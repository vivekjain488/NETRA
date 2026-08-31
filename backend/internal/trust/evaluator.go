// Package trust runs the continuous-trust loop: gather context, score risk,
// decide policy, apply the outcome, and correlate anything that escalates.
//
// This is where NETRA's central idea becomes a single code path (spec §26).
// Risk is not computed once at login; it is recomputed whenever something
// meaningful happens, and the decision that follows is recorded with the exact
// reasons and the exact policy version behind it.
package trust

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netra/backend/internal/behaviour"
	"github.com/netra/backend/internal/incident"
	"github.com/netra/backend/internal/policy"
	"github.com/netra/backend/internal/posture"
	"github.com/netra/backend/internal/risk"
	"github.com/netra/backend/internal/telemetry"
)

// Outcome is the result of one evaluation.
type Outcome struct {
	Assessment risk.Assessment `json:"risk"`
	Decision   policy.Result   `json:"decision"`
	IncidentID *uuid.UUID      `json:"incident_id,omitempty"`
	Applied    string          `json:"session_status"`
}

// Evaluator runs the loop.
type Evaluator struct {
	pool      *pgxpool.Pool
	engine    *risk.Engine
	policies  *policy.Store
	risks     *risk.Store
	baselines *behaviour.Store
	postures  *posture.Store
	incidents *incident.Store
	events    *telemetry.Store
	logger    *slog.Logger
}

// Options are the collaborators the evaluator needs.
type Options struct {
	Pool      *pgxpool.Pool
	Engine    *risk.Engine
	Policies  *policy.Store
	Risks     *risk.Store
	Baselines *behaviour.Store
	Postures  *posture.Store
	Incidents *incident.Store
	Events    *telemetry.Store
	Logger    *slog.Logger
}

// New builds an evaluator.
func New(opts Options) *Evaluator {
	return &Evaluator{
		pool: opts.Pool, engine: opts.Engine, policies: opts.Policies,
		risks: opts.Risks, baselines: opts.Baselines, postures: opts.Postures,
		incidents: opts.Incidents, events: opts.Events, logger: opts.Logger,
	}
}

// sessionContext is what the database knows about a session right now.
type sessionContext struct {
	SessionID   uuid.UUID
	UserID      uuid.UUID
	DeviceID    uuid.UUID
	StartedAt   time.Time
	Status      string
	Attestation string
	SourceIP    string

	DeviceKeyProtection string
	DeviceEnrolledAt    *time.Time
	DeviceHeartbeatAt   *time.Time
}

// Evaluate scores a session and applies the resulting policy decision.
//
// trigger names the event that prompted the evaluation, so an analyst reading
// the risk history can see what moved the score rather than only that it moved.
func (e *Evaluator) Evaluate(ctx context.Context, sessionID uuid.UUID, trigger string) (*Outcome, error) {
	session, err := e.loadSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	inputs, err := e.gather(ctx, session)
	if err != nil {
		return nil, err
	}
	assessment := e.engine.Evaluate(inputs)
	assessment.TriggerEvent = trigger

	riskScoreID, err := e.risks.Record(ctx, session.UserID, session.DeviceID, assessment)
	if err != nil {
		return nil, err
	}

	active, err := e.policies.Active(ctx)
	if err != nil {
		return nil, err
	}
	decision := policy.NewEngine(active).Evaluate(policy.Request{
		Assessment:          assessment,
		ResourceSensitivity: string(inputs.ResourceSensitivity),
	})

	outcome := &Outcome{Assessment: assessment, Decision: decision, Applied: session.Status}

	if decision.CreateIncident {
		created, err := e.incidents.OpenOrEscalate(ctx, sessionID, session.UserID, session.DeviceID,
			string(assessment.Level), assessment.Score,
			fmt.Sprintf("Elevated risk on session for %s", shortID(sessionID)),
			summarise(assessment))
		if err != nil {
			// An incident that cannot be opened must not prevent the decision
			// from being applied; the enforcement matters more than the record.
			e.logger.Error("failed to open incident", slog.String("error", err.Error()))
		} else {
			outcome.IncidentID = &created.ID
		}
	}

	if err := e.policies.RecordDecision(ctx, sessionID, session.UserID, session.DeviceID,
		&riskScoreID, nil, decision, outcome.IncidentID); err != nil {
		return nil, err
	}

	applied, err := e.applyDecision(ctx, sessionID, decision.Decision)
	if err != nil {
		return nil, err
	}
	outcome.Applied = applied

	e.recordDerivedEvents(ctx, session, assessment, decision)

	e.logger.Info("session evaluated",
		slog.String("session_id", sessionID.String()),
		slog.Int("risk", assessment.Score),
		slog.String("level", string(assessment.Level)),
		slog.String("decision", string(decision.Decision)),
		slog.String("trigger", trigger),
		slog.Int64("policy_latency_us", decision.Latency.Microseconds()))

	return outcome, nil
}

// EvaluateDevice re-evaluates whichever session a device currently has.
// Agent telemetry arrives per device; the session is how it reaches a user.
func (e *Evaluator) EvaluateDevice(ctx context.Context, deviceID uuid.UUID, trigger string) (*Outcome, error) {
	var sessionID uuid.UUID
	err := e.pool.QueryRow(ctx, `
		SELECT id FROM sessions WHERE device_id = $1 AND status <> 'ENDED'
		ORDER BY started_at DESC LIMIT 1`, deviceID).Scan(&sessionID)
	if err != nil {
		// No active session is normal: an unattended endpoint still reports
		// telemetry, there is simply no session to score yet.
		return nil, nil
	}
	return e.Evaluate(ctx, sessionID, trigger)
}

func (e *Evaluator) loadSession(ctx context.Context, sessionID uuid.UUID) (*sessionContext, error) {
	var s sessionContext
	err := e.pool.QueryRow(ctx, `
		SELECT s.id, s.user_id, s.device_id, s.started_at, s.status, s.attestation,
		       COALESCE(host(s.source_ip), ''), d.key_protection, d.enrolled_at, d.last_heartbeat_at
		FROM sessions s JOIN devices d ON d.id = s.device_id
		WHERE s.id = $1`, sessionID).Scan(&s.SessionID, &s.UserID, &s.DeviceID,
		&s.StartedAt, &s.Status, &s.Attestation, &s.SourceIP,
		&s.DeviceKeyProtection, &s.DeviceEnrolledAt, &s.DeviceHeartbeatAt)
	if err != nil {
		return nil, fmt.Errorf("load session for evaluation: %w", err)
	}
	return &s, nil
}

// gather assembles the risk inputs. Every value comes from the database, never
// from a client.
func (e *Evaluator) gather(ctx context.Context, session *sessionContext) (risk.Inputs, error) {
	now := time.Now().UTC()
	inputs := risk.Inputs{
		SessionID:           session.SessionID,
		UserID:              session.UserID,
		DeviceID:            session.DeviceID,
		Now:                 now,
		SessionAttested:     session.Attestation != "none",
		DeviceKeyProtection: session.DeviceKeyProtection,
		DeviceEnrolledAt:    session.DeviceEnrolledAt,
		AgentLastHeartbeat:  session.DeviceHeartbeatAt,
		NetworkKnown:        session.SourceIP != "",
		ResourceSensitivity: risk.SensitivityInternal,
	}

	if latest, err := e.postures.Latest(ctx, session.DeviceID); err == nil {
		inputs.DeviceTrustScore = &latest.TrustScore
	}

	// Behavioural context, judged against this user's own history.
	profile, err := e.baselines.Load(ctx, session.UserID)
	if err != nil {
		inputs.LoginHourTypical = true
	} else {
		inputs.BaselineEstablished = profile.Established
		inputs.LoginHourTypical = profile.IsTypicalHour(session.StartedAt)
		inputs.DeviceFirstSeenForUser = profile.Established && !profile.IsKnownDevice(session.DeviceID)
		inputs.NetworkFamiliar = !profile.Established || session.SourceIP == "" ||
			profile.IsKnownNetwork(session.SourceIP)

		if counts, err := e.events.CountByType(ctx, session.SessionID); err == nil {
			total := 0
			for _, count := range counts {
				total += count
			}
			inputs.AccessVolumeZScore = profile.AccessVolumeZScore(total)
		}
	}

	// Sessions before a baseline exists should not be penalised for an
	// unfamiliar network they have no history to compare against.
	if !inputs.BaselineEstablished {
		inputs.NetworkFamiliar = true
	}

	// The highest resource sensitivity this session has actually reached.
	inputs.ResourceSensitivity = e.peakSensitivity(ctx, session.SessionID)

	sinceWeek := now.AddDate(0, 0, -7)
	if count, err := e.risks.CountRecentIncidents(ctx, session.UserID, sinceWeek); err == nil {
		inputs.RecentIncidents = count
	}
	if count, err := e.risks.CountRecentDenials(ctx, session.UserID, sinceWeek); err == nil {
		inputs.RecentDenials = count
	}

	var priorSessions int
	if err := e.pool.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE user_id = $1 AND id <> $2`,
		session.UserID, session.SessionID).Scan(&priorSessions); err == nil {
		inputs.FirstEverSession = priorSessions == 0
	}

	return inputs, nil
}

// peakSensitivity returns the most sensitive resource this session has touched.
// Context is cumulative: reaching a critical resource keeps mattering for the
// rest of the session, not only for the request that reached it.
func (e *Evaluator) peakSensitivity(ctx context.Context, sessionID uuid.UUID) risk.Sensitivity {
	var sensitivity string
	err := e.pool.QueryRow(ctx, `
		SELECT COALESCE(max(
			CASE r.sensitivity
				WHEN 'CRITICAL' THEN 4 WHEN 'SENSITIVE' THEN 3
				WHEN 'INTERNAL' THEN 2 ELSE 1 END), 2)
		FROM events e LEFT JOIN resources r ON r.id = e.resource_id
		WHERE e.session_id = $1`, sessionID).Scan(&sensitivity)
	if err != nil {
		return risk.SensitivityInternal
	}
	switch sensitivity {
	case "4":
		return risk.SensitivityCritical
	case "3":
		return risk.SensitivitySensitive
	case "1":
		return risk.SensitivityPublic
	default:
		return risk.SensitivityInternal
	}
}

// applyDecision enforces the decision on the session.
//
// Only restriction and isolation change session state. A decision to allow
// never re-opens a session an analyst or an earlier decision has closed.
func (e *Evaluator) applyDecision(ctx context.Context, sessionID uuid.UUID, decision policy.Decision) (string, error) {
	var status string
	switch decision {
	case policy.DecisionRestrict:
		status = "RESTRICTED"
	case policy.DecisionIsolate, policy.DecisionDeny:
		status = "ISOLATED"
	default:
		var current string
		if err := e.pool.QueryRow(ctx, `SELECT status FROM sessions WHERE id = $1`, sessionID).
			Scan(&current); err != nil {
			return "", fmt.Errorf("read session status: %w", err)
		}
		return current, nil
	}

	if _, err := e.pool.Exec(ctx,
		`UPDATE sessions SET status = $2, last_seen_at = now() WHERE id = $1 AND status <> 'ENDED'`,
		sessionID, status); err != nil {
		return "", fmt.Errorf("apply session status: %w", err)
	}
	return status, nil
}

// recordDerivedEvents writes the risk update and policy decision back into the
// event stream, so an incident timeline contains the reasoning as well as the
// endpoint activity that triggered it.
func (e *Evaluator) recordDerivedEvents(ctx context.Context, session *sessionContext,
	assessment risk.Assessment, decision policy.Result) {

	severity := telemetry.SeverityInfo
	switch assessment.Level {
	case risk.LevelHigh:
		severity = telemetry.SeverityHigh
	case risk.LevelCritical:
		severity = telemetry.SeverityCritical
	case risk.LevelElevated:
		severity = telemetry.SeverityMedium
	}

	base := telemetry.Event{
		DeviceID: &session.DeviceID, UserID: &session.UserID,
		SessionID: &session.SessionID, Source: telemetry.SourceBackend,
	}

	riskEvent := base
	riskEvent.Type = telemetry.TypeRiskUpdate
	riskEvent.Severity = severity
	riskEvent.Metadata = map[string]string{
		"score":   fmt.Sprint(assessment.Score),
		"level":   string(assessment.Level),
		"factors": strings.Join(assessment.Codes(), ","),
		"trigger": assessment.TriggerEvent,
	}
	if err := e.events.RecordBackendEvent(ctx, riskEvent); err != nil {
		e.logger.Error("failed to record risk event", slog.String("error", err.Error()))
	}

	decisionEvent := base
	decisionEvent.Type = telemetry.TypePolicyDecision
	decisionEvent.Severity = severity
	decisionEvent.Metadata = map[string]string{
		"decision": string(decision.Decision),
		"reason":   decision.Reason,
		"policy":   decision.PolicyID,
	}
	if err := e.events.RecordBackendEvent(ctx, decisionEvent); err != nil {
		e.logger.Error("failed to record policy event", slog.String("error", err.Error()))
	}
}

func summarise(assessment risk.Assessment) string {
	return fmt.Sprintf("Risk %d (%s). Contributing factors: %s.",
		assessment.Score, assessment.Level, strings.Join(assessment.Codes(), ", "))
}

func shortID(id uuid.UUID) string { return id.String()[:8] }
