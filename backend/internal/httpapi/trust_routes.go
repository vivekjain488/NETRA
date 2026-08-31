package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/netra/backend/internal/audit"
	"github.com/netra/backend/internal/auth"
	"github.com/netra/backend/internal/behaviour"
	"github.com/netra/backend/internal/device"
	"github.com/netra/backend/internal/incident"
	"github.com/netra/backend/internal/logging"
	"github.com/netra/backend/internal/policy"
	"github.com/netra/backend/internal/reqctx"
	"github.com/netra/backend/internal/risk"
	"github.com/netra/backend/internal/telemetry"
	"github.com/netra/backend/internal/trust"
)

// ── Service contracts ───────────────────────────────────────────────────────

// TelemetryService is the event behaviour the HTTP layer depends on.
type TelemetryService interface {
	Ingest(ctx context.Context, deviceID uuid.UUID, inbound []telemetry.Inbound) (*telemetry.IngestResult, error)
	Query(ctx context.Context, filter telemetry.Filter) ([]telemetry.Event, error)
}

// RiskService reads stored assessments.
type RiskService interface {
	Latest(ctx context.Context, sessionID uuid.UUID) (*risk.Assessment, error)
	History(ctx context.Context, sessionID uuid.UUID, limit int) ([]risk.Assessment, error)
}

// PolicyService reads and writes policies.
type PolicyService interface {
	Active(ctx context.Context) ([]policy.Policy, error)
	All(ctx context.Context) ([]policy.Policy, error)
	Create(ctx context.Context, p policy.Policy, createdBy *uuid.UUID) (*policy.Policy, error)
	Decisions(ctx context.Context, sessionID *uuid.UUID, limit int) ([]policy.DecisionRecord, error)
}

// IncidentService reads and updates incidents.
type IncidentService interface {
	List(ctx context.Context, openOnly bool, limit int) ([]incident.Incident, error)
	ByID(ctx context.Context, id uuid.UUID) (*incident.Incident, error)
	SetStatus(ctx context.Context, id uuid.UUID, status incident.Status) error
	AddNote(ctx context.Context, incidentID, authorID uuid.UUID, body string) error
	Notes(ctx context.Context, incidentID uuid.UUID) ([]incident.Note, error)
	Counts(ctx context.Context) (int, int, error)
}

// BaselineService rebuilds behavioural profiles.
type BaselineService interface {
	Load(ctx context.Context, userID uuid.UUID) (*behaviour.Profile, error)
	Rebuild(ctx context.Context, userID uuid.UUID, windowDays int) (*behaviour.Profile, error)
}

// Evaluator runs the continuous-trust loop.
type Evaluator interface {
	Evaluate(ctx context.Context, sessionID uuid.UUID, trigger string) (*trust.Outcome, error)
	EvaluateDevice(ctx context.Context, deviceID uuid.UUID, trigger string) (*trust.Outcome, error)
}

type trustHandler struct {
	telemetry TelemetryService
	risk      RiskService
	policy    PolicyService
	incidents IncidentService
	baselines BaselineService
	evaluator Evaluator
	stats     StatsService
	recorder  audit.Recorder
}

// StatsService counts fleet state for the overview page.
type StatsService interface {
	FleetSummary(ctx context.Context) (*trust.FleetSummary, error)
}

// ── Agent plane: telemetry ingest ───────────────────────────────────────────

// EventBatch is what an agent submits.
type EventBatch struct {
	Events []telemetry.Inbound `json:"events"`
}

// ingest accepts a batch from an authenticated device and re-evaluates trust.
func (h *trustHandler) ingest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logging.FromContext(ctx)

	reporting, ok := device.FromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Device authentication is required.")
		return
	}

	var batch EventBatch
	if !decodeLargeJSON(w, r, &batch) {
		return
	}
	if len(batch.Events) == 0 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "The batch contains no events.")
		return
	}

	// The device comes from the verified signature, never the payload.
	result, err := h.telemetry.Ingest(ctx, reporting.ID, batch.Events)
	if err != nil {
		if errors.Is(err, telemetry.ErrInvalidEvent) {
			WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error())
			return
		}
		logger.Error("failed to ingest telemetry", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The events could not be stored.")
		return
	}

	// Trust is continuous: new telemetry is exactly the kind of meaningful
	// change that should move a score (spec §26).
	if h.evaluator != nil && result.Accepted > 0 {
		if _, err := h.evaluator.EvaluateDevice(ctx, reporting.ID, "telemetry_batch"); err != nil {
			// Ingest already succeeded; a failed re-evaluation must not make the
			// agent resend events it has correctly delivered.
			logger.Error("re-evaluation after ingest failed", "error", err.Error())
		}
	}

	WriteJSON(w, r, http.StatusAccepted, result)
}

// ── SOC plane: events ───────────────────────────────────────────────────────

func (h *trustHandler) listEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit, err := intQuery(r, "limit", 100)
	if err != nil || limit < 1 || limit > 1000 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "limit must be between 1 and 1000.")
		return
	}

	filter := telemetry.Filter{Limit: limit}
	if raw := r.URL.Query().Get("session_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "session_id must be a UUID.")
			return
		}
		filter.SessionID = &id
	}
	if raw := r.URL.Query().Get("device_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "device_id must be a UUID.")
			return
		}
		filter.DeviceID = &id
	}
	if raw := r.URL.Query().Get("type"); raw != "" {
		for _, value := range strings.Split(raw, ",") {
			filter.Types = append(filter.Types, telemetry.Type(strings.ToUpper(strings.TrimSpace(value))))
		}
	}
	if raw := r.URL.Query().Get("severity"); raw != "" {
		severity := telemetry.Severity(strings.ToUpper(raw))
		filter.Severity = &severity
	}

	events, err := h.telemetry.Query(ctx, filter)
	if err != nil {
		logging.FromContext(ctx).Error("failed to query events", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"Events could not be queried.")
		return
	}
	WriteJSON(w, r, http.StatusOK, map[string]any{"events": nonNilEvents(events)})
}

// ── SOC plane: risk ─────────────────────────────────────────────────────────

func (h *trustHandler) sessionRisk(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sessionID, err := uuid.Parse(chi.URLParam(r, "session_id"))
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "session_id must be a UUID.")
		return
	}

	latest, err := h.risk.Latest(ctx, sessionID)
	if err != nil {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "This session has not been scored yet.")
		return
	}
	history, err := h.risk.History(ctx, sessionID, 200)
	if err != nil {
		logging.FromContext(ctx).Error("failed to load risk history", "error", err.Error())
		history = nil
	}

	trend := make([]map[string]any, 0, len(history))
	for _, point := range history {
		trend = append(trend, map[string]any{
			"computed_at": point.ComputedAt,
			"score":       point.Score,
			"level":       point.Level,
			"trigger":     point.TriggerEvent,
		})
	}

	WriteJSON(w, r, http.StatusOK, map[string]any{
		"session_id": sessionID.String(),
		"current":    latest,
		"history":    trend,
	})
}

// evaluate re-scores a session on demand. Analysts use it to confirm a change;
// the demonstration uses it to show the loop running.
func (h *trustHandler) evaluate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sessionID, err := uuid.Parse(chi.URLParam(r, "session_id"))
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "session_id must be a UUID.")
		return
	}

	outcome, err := h.evaluator.Evaluate(ctx, sessionID, "manual")
	if err != nil {
		logging.FromContext(ctx).Error("manual evaluation failed", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The session could not be evaluated.")
		return
	}
	WriteJSON(w, r, http.StatusOK, outcome)
}

// ── Policy ──────────────────────────────────────────────────────────────────

func (h *trustHandler) listPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policies, err := h.policy.All(ctx)
	if err != nil {
		logging.FromContext(ctx).Error("failed to list policies", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"Policies could not be listed.")
		return
	}
	WriteJSON(w, r, http.StatusOK, map[string]any{"policies": policies})
}

func (h *trustHandler) createPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var candidate policy.Policy
	if !decodeJSON(w, r, &candidate) {
		return
	}
	candidate.Enabled = true

	principal, _ := auth.FromContext(ctx)
	var createdBy *uuid.UUID
	if principal != nil {
		createdBy = &principal.UserID
	}

	created, err := h.policy.Create(ctx, candidate, createdBy)
	if err != nil {
		if errors.Is(err, policy.ErrInvalidPolicy) {
			WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error())
			return
		}
		logging.FromContext(ctx).Error("failed to create policy", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The policy could not be created.")
		return
	}

	// Changing what the system will allow is exactly the kind of privileged
	// action that must be auditable.
	audit.Log(ctx, h.recorder, logging.FromContext(ctx), audit.Entry{
		ActorType:  audit.ActorUser,
		ActorID:    actorID(principal),
		Action:     audit.ActionPolicyCreated,
		TargetType: "policy",
		TargetID:   created.PolicyID,
		Result:     audit.ResultSuccess,
		RequestID:  reqctx.RequestID(ctx),
		Detail: map[string]any{
			"version":  created.Version,
			"decision": string(created.Actions.Decision),
			"name":     created.Name,
		},
	})

	WriteJSON(w, r, http.StatusCreated, created)
}

// evaluatePolicy runs a hypothetical assessment through the live policy set,
// so an administrator can see what a policy will do before relying on it.
func (h *trustHandler) evaluatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var request struct {
		Score               int      `json:"score"`
		Level               string   `json:"level"`
		Factors             []string `json:"factors"`
		ResourceSensitivity string   `json:"resource_sensitivity"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Score < 0 || request.Score > 100 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "score must be 0..100.")
		return
	}

	assessment := risk.Assessment{Score: request.Score, Level: risk.Level(strings.ToUpper(request.Level))}
	if assessment.Level == "" {
		assessment.Level = risk.DefaultThresholds().Level(request.Score)
	}
	for _, code := range request.Factors {
		assessment.Factors = append(assessment.Factors, risk.Factor{Code: strings.ToUpper(code)})
	}

	active, err := h.policy.Active(ctx)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"Policies could not be loaded.")
		return
	}

	result := policy.NewEngine(active).Evaluate(policy.Request{
		Assessment:          assessment,
		ResourceSensitivity: strings.ToUpper(request.ResourceSensitivity),
	})
	WriteJSON(w, r, http.StatusOK, result)
}

func (h *trustHandler) listDecisions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit, err := intQuery(r, "limit", 100)
	if err != nil || limit < 1 || limit > 500 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "limit must be between 1 and 500.")
		return
	}

	var sessionID *uuid.UUID
	if raw := r.URL.Query().Get("session_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "session_id must be a UUID.")
			return
		}
		sessionID = &id
	}

	decisions, err := h.policy.Decisions(ctx, sessionID, limit)
	if err != nil {
		logging.FromContext(ctx).Error("failed to list decisions", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"Decisions could not be listed.")
		return
	}
	WriteJSON(w, r, http.StatusOK, map[string]any{"decisions": decisions})
}

// ── Incidents ───────────────────────────────────────────────────────────────

func (h *trustHandler) listIncidents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit, err := intQuery(r, "limit", 100)
	if err != nil || limit < 1 || limit > 500 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "limit must be between 1 and 500.")
		return
	}

	incidents, err := h.incidents.List(ctx, r.URL.Query().Get("open") == "true", limit)
	if err != nil {
		logging.FromContext(ctx).Error("failed to list incidents", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"Incidents could not be listed.")
		return
	}
	WriteJSON(w, r, http.StatusOK, map[string]any{"incidents": incidents})
}

// getIncident returns an incident with the timeline that explains it: the
// events, the risk trajectory and the decisions, in one response.
func (h *trustHandler) getIncident(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "id must be a UUID.")
		return
	}

	found, err := h.incidents.ByID(ctx, id)
	if errors.Is(err, incident.ErrNotFound) {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "No such incident.")
		return
	}
	if err != nil {
		logging.FromContext(ctx).Error("failed to load incident", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The incident could not be loaded.")
		return
	}

	response := map[string]any{"incident": found}
	if notes, err := h.incidents.Notes(ctx, id); err == nil {
		response["notes"] = notes
	}

	if found.SessionID != nil {
		if events, err := h.telemetry.Query(ctx, telemetry.Filter{SessionID: found.SessionID, Limit: 200}); err == nil {
			response["events"] = nonNilEvents(events)
		}
		if history, err := h.risk.History(ctx, *found.SessionID, 200); err == nil {
			response["risk_history"] = history
		}
		if decisions, err := h.policy.Decisions(ctx, found.SessionID, 100); err == nil {
			response["decisions"] = decisions
		}
	}
	WriteJSON(w, r, http.StatusOK, response)
}

func (h *trustHandler) setIncidentStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "id must be a UUID.")
		return
	}

	var body struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	status, ok := incident.ParseStatus(strings.ToUpper(body.Status))
	if !ok {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request",
			"status must be OPEN, INVESTIGATING, CONTAINED, RESOLVED or FALSE_POSITIVE.")
		return
	}

	if err := h.incidents.SetStatus(ctx, id, status); err != nil {
		if errors.Is(err, incident.ErrNotFound) {
			WriteProblem(w, r, http.StatusNotFound, "Not Found", "No such incident.")
			return
		}
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The incident could not be updated.")
		return
	}

	principal, _ := auth.FromContext(ctx)
	audit.Log(ctx, h.recorder, logging.FromContext(ctx), audit.Entry{
		ActorType:  audit.ActorUser,
		ActorID:    actorID(principal),
		Action:     audit.ActionIncidentUpdated,
		TargetType: "incident",
		TargetID:   id.String(),
		Result:     audit.ResultSuccess,
		RequestID:  reqctx.RequestID(ctx),
		Detail:     map[string]any{"status": string(status)},
	})

	WriteJSON(w, r, http.StatusOK, map[string]any{"id": id.String(), "status": status})
}

func (h *trustHandler) addIncidentNote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "id must be a UUID.")
		return
	}

	var body struct {
		Body string `json:"body"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if trimmed := strings.TrimSpace(body.Body); trimmed == "" || len(trimmed) > 4000 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request",
			"A note must be between 1 and 4000 characters.")
		return
	}

	principal, ok := auth.FromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "A bearer token is required.")
		return
	}

	if err := h.incidents.AddNote(ctx, id, principal.UserID, strings.TrimSpace(body.Body)); err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The note could not be added.")
		return
	}
	WriteJSON(w, r, http.StatusCreated, map[string]any{"status": "added"})
}

// ── Overview ────────────────────────────────────────────────────────────────

// rebuildBaseline recomputes a user's behavioural profile on demand.
func (h *trustHandler) rebuildBaseline(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "id must be a UUID.")
		return
	}

	profile, err := h.baselines.Rebuild(ctx, userID, behaviour.DefaultWindowDays)
	if err != nil {
		logging.FromContext(ctx).Error("failed to rebuild baseline", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The baseline could not be rebuilt.")
		return
	}
	WriteJSON(w, r, http.StatusOK, profile)
}

func (h *trustHandler) getBaseline(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "id must be a UUID.")
		return
	}

	profile, err := h.baselines.Load(ctx, userID)
	if err != nil {
		WriteProblem(w, r, http.StatusNotFound, "Not Found",
			"This user has no behavioural baseline yet.")
		return
	}
	WriteJSON(w, r, http.StatusOK, profile)
}

func decodeLargeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	// Telemetry batches are legitimately larger than other request bodies, but
	// still bounded: the whole body was already buffered for signature
	// verification, so this is a second, explicit limit rather than the only one.
	return decodeJSONWithLimit(w, r, target, 4<<20)
}

func nonNilEvents(events []telemetry.Event) []telemetry.Event {
	if events == nil {
		return []telemetry.Event{}
	}
	return events
}

var _ = time.Now

// OverviewResponse is the SOC landing summary (spec §29).
type OverviewResponse struct {
	Endpoints         int               `json:"endpoints"`
	EndpointsTrusted  int               `json:"endpoints_trusted"`
	EndpointsAtRisk   int               `json:"endpoints_at_risk"`
	ActiveSessions    int               `json:"active_sessions"`
	HighRiskSessions  int               `json:"high_risk_sessions"`
	OpenIncidents     int               `json:"open_incidents"`
	CriticalIncidents int               `json:"critical_incidents"`
	RiskDistribution  map[string]int    `json:"risk_distribution"`
	RecentEvents      []telemetry.Event `json:"recent_events"`
}

// overview summarises fleet state for the SOC landing page.
//
// Every figure is counted from stored data. A counter with nothing to count
// reports zero rather than being omitted, so the page never implies that a
// missing number is a healthy one.
func (h *trustHandler) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logging.FromContext(ctx)

	response := OverviewResponse{RiskDistribution: map[string]int{}, RecentEvents: []telemetry.Event{}}

	if open, critical, err := h.incidents.Counts(ctx); err == nil {
		response.OpenIncidents, response.CriticalIncidents = open, critical
	} else {
		logger.Error("failed to count incidents", "error", err.Error())
	}

	if h.telemetry != nil {
		if events, err := h.telemetry.Query(ctx, telemetry.Filter{Limit: 15}); err == nil {
			response.RecentEvents = nonNilEvents(events)
		}
	}

	if h.stats != nil {
		if fleet, err := h.stats.FleetSummary(ctx); err == nil {
			response.Endpoints = fleet.Endpoints
			response.EndpointsTrusted = fleet.Trusted
			response.EndpointsAtRisk = fleet.AtRisk
			response.ActiveSessions = fleet.ActiveSessions
			response.HighRiskSessions = fleet.HighRiskSessions
			response.RiskDistribution = fleet.RiskDistribution
		} else {
			logger.Error("failed to summarise fleet", "error", err.Error())
		}
	}

	WriteJSON(w, r, http.StatusOK, response)
}
