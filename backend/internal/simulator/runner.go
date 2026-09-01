package simulator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netra/backend/internal/behaviour"
	"github.com/netra/backend/internal/posture"
	"github.com/netra/backend/internal/telemetry"
	"github.com/netra/backend/internal/trust"
)

// Runner executes scenarios against the live platform.
type Runner struct {
	pool      *pgxpool.Pool
	events    *telemetry.Store
	baselines *behaviour.Store
	postures  *posture.Store
	evaluator *trust.Evaluator
	logger    *slog.Logger
}

// NewRunner builds a scenario runner.
func NewRunner(pool *pgxpool.Pool, events *telemetry.Store, baselines *behaviour.Store,
	postures *posture.Store, evaluator *trust.Evaluator, logger *slog.Logger) *Runner {
	return &Runner{pool: pool, events: events, baselines: baselines,
		postures: postures, evaluator: evaluator, logger: logger}
}

// run is the state of one scenario execution.
type run struct {
	ctx    context.Context
	runner *Runner
	now    time.Time
	userID uuid.UUID
	// homeDevice is the user's usual machine; currentDevice is whatever the
	// scenario is presently working from.
	homeDevice    uuid.UUID
	currentDevice uuid.UUID
	sessionID     uuid.UUID
	added         int
}

// Run executes a scenario end to end.
//
// Every step is followed by a real evaluation, so the scores reported back are
// the engine's, not the scenario's.
func (r *Runner) Run(ctx context.Context, scenario Scenario) (*Result, error) {
	state, err := r.prepare(ctx)
	if err != nil {
		return nil, err
	}

	result := &Result{
		Scenario:  scenario.Name,
		StartedAt: state.now,
	}

	for _, s := range scenario.steps {
		state.added = 0
		if err := s.run(state); err != nil {
			return nil, fmt.Errorf("step %q: %w", s.label, err)
		}

		stepResult := StepResult{Step: s.label, At: time.Now().UTC(), EventsAdded: state.added}

		if state.sessionID != uuid.Nil {
			outcome, err := r.evaluator.Evaluate(ctx, state.sessionID, "simulator:"+scenario.Name)
			if err != nil {
				return nil, fmt.Errorf("evaluate after %q: %w", s.label, err)
			}
			score := outcome.Assessment.Score
			stepResult.Score = &score
			stepResult.Level = string(outcome.Assessment.Level)
			stepResult.Decision = string(outcome.Decision.Decision)
			stepResult.Factors = outcome.Assessment.Codes()
			if outcome.IncidentID != nil {
				stepResult.IncidentID = outcome.IncidentID.String()
				result.IncidentID = stepResult.IncidentID
			}
			result.FinalScore = score
			result.FinalLevel = stepResult.Level
			result.Decision = stepResult.Decision
			result.SessionID = state.sessionID.String()
		}

		result.Steps = append(result.Steps, stepResult)
	}

	if err := r.pool.QueryRow(ctx,
		`SELECT u.display_name, d.hostname FROM users u, devices d WHERE u.id = $1 AND d.id = $2`,
		state.userID, state.currentDevice).Scan(&result.UserName, &result.DeviceName); err != nil {
		r.logger.Warn("could not label simulation result", slog.String("error", err.Error()))
	}

	r.logger.Info("scenario complete",
		slog.String("scenario", scenario.Name),
		slog.Int("final_score", result.FinalScore),
		slog.String("decision", result.Decision))

	return result, nil
}

// prepare ensures the simulated user, their usual device and their behavioural
// baseline exist.
func (r *Runner) prepare(ctx context.Context) (*run, error) {
	state := &run{ctx: ctx, runner: r, now: time.Now().UTC()}

	if err := r.pool.QueryRow(ctx, `
		INSERT INTO users (external_subject, email, display_name, department, role)
		VALUES ('sim-alice', 'alice.sharma@example.gov', 'Alice Sharma', 'Operations', 'USER')
		ON CONFLICT (external_subject) DO UPDATE SET updated_at = now()
		RETURNING id`).Scan(&state.userID); err != nil {
		return nil, fmt.Errorf("prepare simulated user: %w", err)
	}

	device, err := r.ensureDevice(ctx, "sim-home", "SIM-LAPTOP-01")
	if err != nil {
		return nil, err
	}
	state.homeDevice = device
	state.currentDevice = device

	if err := r.seedHistory(ctx, state.userID, device); err != nil {
		return nil, err
	}
	return state, nil
}

// seedHistory gives the simulated user a month of ordinary behaviour.
//
// A baseline needs history, and a demonstration lasting twenty minutes has
// none. This is stated openly in the documentation: the baseline is
// simulator-seeded, not learned from a real person.
func (r *Runner) seedHistory(ctx context.Context, userID, deviceID uuid.UUID) error {
	var existing int
	if err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE user_id = $1`, userID).Scan(&existing); err != nil {
		return fmt.Errorf("count seeded sessions: %w", err)
	}
	if existing >= behaviour.MinimumObservations {
		// Already seeded; re-seeding would distort the baseline every run.
		return nil
	}

	now := time.Now().UTC()
	for day := 30; day >= 1; day-- {
		startedAt := time.Date(now.Year(), now.Month(), now.Day(), 9, 12, 0, 0, time.UTC).
			AddDate(0, 0, -day)

		var sessionID uuid.UUID
		if err := r.pool.QueryRow(ctx, `
			INSERT INTO sessions (user_id, device_id, status, auth_method, attestation,
				source_ip, started_at, last_seen_at, ended_at)
			VALUES ($1, $2, 'ENDED', 'oidc', 'device-signature', '10.10.4.21', $3, $3, $3)
			RETURNING id`, userID, deviceID, startedAt).Scan(&sessionID); err != nil {
			return fmt.Errorf("seed session: %w", err)
		}

		// A steady but not identical daily volume, so the standard deviation is
		// usable rather than zero.
		count := 18 + (day % 7)
		for i := 0; i < count; i++ {
			if err := r.events.RecordBackendEvent(ctx, telemetry.Event{
				OccurredAt: startedAt.Add(time.Duration(i) * time.Minute),
				DeviceID:   &deviceID,
				UserID:     &userID,
				SessionID:  &sessionID,
				Type:       telemetry.TypeResourceAccess,
				Severity:   telemetry.SeverityInfo,
				Source:     telemetry.SourceSimulator,
				Metadata:   map[string]string{"application": "mail", "seeded": "true"},
			}); err != nil {
				return fmt.Errorf("seed event: %w", err)
			}
		}
	}

	if _, err := r.baselines.Rebuild(ctx, userID, behaviour.DefaultWindowDays); err != nil {
		return fmt.Errorf("build seeded baseline: %w", err)
	}
	r.logger.Info("seeded simulated behavioural history", slog.String("user_id", userID.String()))
	return nil
}

// ensureDevice creates or returns a simulated device.
//
// Simulated devices carry a real Ed25519 public key so they are indistinguishable
// in shape from an enrolled endpoint — but they are marked in their identifier,
// and their events carry the SIMULATOR source.
func (r *Runner) ensureDevice(ctx context.Context, key, hostname string) (uuid.UUID, error) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return uuid.Nil, fmt.Errorf("generate simulated device key: %w", err)
	}

	var id uuid.UUID
	err = r.pool.QueryRow(ctx, `
		INSERT INTO devices (device_uid, hostname, os_name, os_version, agent_version,
			public_key, key_algorithm, key_protection, state, enrolled_at, last_heartbeat_at)
		VALUES ($1, $2, 'windows', '11', '0.1.0', $3, 'ed25519', 'software', 'ACTIVE', now(), now())
		ON CONFLICT (device_uid) DO UPDATE SET last_heartbeat_at = now()
		RETURNING id`, "netra-sim-"+key, hostname, []byte(publicKey)).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("prepare simulated device: %w", err)
	}

	if err := r.seedPosture(ctx, id); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// seedPosture gives a simulated device a healthy security posture.
//
// Without it every simulated endpoint carries NO_POSTURE, and the
// demonstration would show risk driven by a gap the simulator created rather
// than by the behaviour the scenario is there to show. The posture is scored by
// the same engine as a real device's, from the same shape of signals.
func (r *Runner) seedPosture(ctx context.Context, deviceID uuid.UUID) error {
	var existing int
	if err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM device_posture WHERE device_id = $1`, deviceID).Scan(&existing); err != nil {
		return fmt.Errorf("count simulated posture: %w", err)
	}
	if existing > 0 {
		return nil
	}

	yes := true
	signals := posture.Signals{
		DiskEncryption: &yes, SecureBoot: &yes, Firewall: &yes,
		ScreenLock: &yes, AntiMalware: &yes,
		OSName: "windows", OSVersion: "11",
	}
	now := time.Now().UTC()
	assessment := posture.Evaluate(signals, posture.DeviceContext{
		Active:          true,
		KeyProtection:   "software",
		AgentVersion:    "0.1.0",
		ExpectedAgent:   "0.1.0",
		LastHeartbeatAt: &now,
		Now:             now,
	}, posture.DefaultWeights())

	if _, err := r.postures.Record(ctx, deviceID, signals, assessment); err != nil {
		return fmt.Errorf("record simulated posture: %w", err)
	}
	return nil
}

// ── Step primitives ─────────────────────────────────────────────────────────

// enrolDevice adds a device the user has never worked from.
func (r *run) enrolDevice(hostname string) error {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	device, err := r.runner.ensureDevice(r.ctx, hex.EncodeToString(suffix), hostname)
	if err != nil {
		return err
	}
	r.currentDevice = device

	return r.record(telemetry.TypeDeviceEnrollment, telemetry.SeverityMedium,
		map[string]string{"hostname": hostname, "simulated": "true"})
}

// startSession opens a session on the current device.
func (r *run) startSession(options sessionOptions) error {
	device := r.currentDevice
	if options.Familiar {
		device = r.homeDevice
		r.currentDevice = device
	}

	sourceIP := options.SourceIP
	if sourceIP == "" {
		sourceIP = "10.10.4.21"
	}
	startedAt := options.startedAt(r.now)

	var sessionID uuid.UUID
	if err := r.runner.pool.QueryRow(r.ctx, `
		INSERT INTO sessions (user_id, device_id, status, auth_method, attestation,
			source_ip, started_at, last_seen_at)
		VALUES ($1, $2, 'ACTIVE', 'oidc', 'device-signature', $3, $4, now())
		RETURNING id`, r.userID, device, sourceIP, startedAt).Scan(&sessionID); err != nil {
		return fmt.Errorf("open simulated session: %w", err)
	}
	r.sessionID = sessionID

	return r.record(telemetry.TypeAuthLogin, telemetry.SeverityInfo, map[string]string{
		"source_ip": sourceIP,
		"hour":      fmt.Sprintf("%02d:%02d", startedAt.Hour(), startedAt.Minute()),
	})
}

// accessResource records access to a named resource.
func (r *run) accessResource(applicationKey, resourceKey string) error {
	resourceID, sensitivity, err := r.resolveResource(applicationKey, resourceKey)
	if err != nil {
		return err
	}

	severity := telemetry.SeverityInfo
	if sensitivity == "CRITICAL" {
		severity = telemetry.SeverityMedium
	}

	return r.recordResource(telemetry.TypeResourceAccess, severity, resourceID, map[string]string{
		"application": applicationKey,
		"resource":    resourceKey,
		"sensitivity": sensitivity,
	})
}

// bulkAccess records many reads of one resource, which is what an abnormal
// volume looks like in the event stream.
func (r *run) bulkAccess(applicationKey, resourceKey string, count int) error {
	resourceID, sensitivity, err := r.resolveResource(applicationKey, resourceKey)
	if err != nil {
		return err
	}

	for i := 0; i < count; i++ {
		if err := r.recordResource(telemetry.TypeResourceAccess, telemetry.SeverityInfo,
			resourceID, map[string]string{
				"application": applicationKey,
				"resource":    resourceKey,
				"sensitivity": sensitivity,
				"sequence":    fmt.Sprint(i),
			}); err != nil {
			return err
		}
	}
	return nil
}

// networkEvent records a connection to a destination.
func (r *run) networkEvent(destination string) error {
	return r.record(telemetry.TypeNetworkEvent, telemetry.SeverityLow,
		map[string]string{"destination": destination})
}

func (r *run) resolveResource(applicationKey, resourceKey string) (uuid.UUID, string, error) {
	var (
		id          uuid.UUID
		sensitivity string
	)
	err := r.runner.pool.QueryRow(r.ctx, `
		SELECT r.id, r.sensitivity FROM resources r
		JOIN applications a ON a.id = r.application_id
		WHERE a.key = $1 AND r.key = $2`, applicationKey, resourceKey).Scan(&id, &sensitivity)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("resolve resource %s/%s: %w", applicationKey, resourceKey, err)
	}
	return id, sensitivity, nil
}

func (r *run) record(eventType telemetry.Type, severity telemetry.Severity, metadata map[string]string) error {
	return r.recordResource(eventType, severity, uuid.Nil, metadata)
}

func (r *run) recordResource(eventType telemetry.Type, severity telemetry.Severity,
	resourceID uuid.UUID, metadata map[string]string) error {

	event := eventFor(eventType, severity, metadata)
	event.DeviceID = &r.currentDevice
	event.UserID = &r.userID
	if r.sessionID != uuid.Nil {
		event.SessionID = &r.sessionID
	}

	if err := r.runner.recordWithResource(r.ctx, event, resourceID); err != nil {
		return err
	}
	r.added++
	return nil
}

// recordWithResource stores a simulated event, including its resource link so
// the risk engine can see what sensitivity was reached.
func (r *Runner) recordWithResource(ctx context.Context, event telemetry.Event, resourceID uuid.UUID) error {
	var resource any
	if resourceID != uuid.Nil {
		resource = resourceID
	}
	occurred := event.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}

	metadata, err := marshalMetadata(event.Metadata)
	if err != nil {
		return err
	}

	_, err = r.pool.Exec(ctx, `
		INSERT INTO events (occurred_at, received_at, device_id, user_id, session_id,
			event_type, severity, source, metadata, resource_id)
		VALUES ($1, now(), $2, $3, $4, $5, $6, $7, $8, $9)`,
		occurred, event.DeviceID, event.UserID, event.SessionID,
		string(event.Type), string(event.Severity), string(event.Source), metadata, resource)
	if err != nil {
		return fmt.Errorf("record simulated event: %w", err)
	}
	return nil
}

func marshalMetadata(metadata map[string]string) ([]byte, error) {
	if metadata == nil {
		metadata = map[string]string{}
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("encode simulated metadata: %w", err)
	}
	return encoded, nil
}
