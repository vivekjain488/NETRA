package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/netra/backend/internal/audit"
	"github.com/netra/backend/internal/device"
	"github.com/netra/backend/internal/logging"
	"github.com/netra/backend/internal/posture"
	"github.com/netra/backend/internal/reqctx"
)

// PostureService is the posture behaviour the HTTP layer depends on.
type PostureService interface {
	Record(ctx context.Context, deviceID uuid.UUID, signals posture.Signals, assessment posture.Assessment) (*posture.Record, error)
	Latest(ctx context.Context, deviceID uuid.UUID) (*posture.Record, error)
	History(ctx context.Context, deviceID uuid.UUID, limit int) ([]posture.Record, error)
	LatestScores(ctx context.Context) (map[uuid.UUID]int, error)
}

type postureHandler struct {
	posture       PostureService
	recorder      audit.Recorder
	weights       posture.Weights
	expectedAgent string
}

// PostureReport is what an agent submits.
type PostureReport struct {
	Signals posture.Signals `json:"signals"`
}

// PostureResponse is the scored assessment.
//
// It is returned to the agent so the endpoint client can show the user their
// own device trust and why — the endpoint learns its score from the backend
// rather than deciding it.
type PostureResponse struct {
	TrustScore   int              `json:"trust_score"`
	Factors      []posture.Factor `json:"factors"`
	Weakest      []posture.Factor `json:"weakest,omitempty"`
	Verified     bool             `json:"verified"`
	ModelVersion string           `json:"model_version"`
	CollectedAt  time.Time        `json:"collected_at"`
}

// submit scores and stores a posture report from an authenticated device.
func (h *postureHandler) submit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logging.FromContext(ctx)

	reporting, ok := device.FromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Device authentication is required.")
		return
	}

	var report PostureReport
	if !decodeJSON(w, r, &report) {
		return
	}
	if err := report.Signals.Validate(); err != nil {
		// A device sending malformed posture is worth recording: it is either
		// a broken agent or something pretending to be one.
		h.auditRejection(ctx, reporting.ID.String(), err.Error())
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	// The device identifier comes from the verified signature, never from the
	// body: an agent must not be able to report posture on another device's
	// behalf.
	assessment := posture.Evaluate(report.Signals, posture.DeviceContext{
		Active:          reporting.State == device.StateActive,
		KeyProtection:   reporting.KeyProtection,
		AgentVersion:    reporting.AgentVersion,
		ExpectedAgent:   h.expectedAgent,
		LastHeartbeatAt: reporting.LastHeartbeatAt,
		Now:             time.Now(),
	}, h.weights)

	stored, err := h.posture.Record(ctx, reporting.ID, report.Signals, assessment)
	if err != nil {
		logger.Error("failed to store posture", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The posture report could not be stored.")
		return
	}

	// Posture reports arrive on a schedule and are not audited individually:
	// they would swamp the log. The history table is the record, and a material
	// drop in trust becomes a risk event in Phase 7.
	logger.Info("posture recorded",
		"trust_score", assessment.Score,
		"verified", assessment.Verified)

	WriteJSON(w, r, http.StatusCreated, PostureResponse{
		TrustScore:   stored.TrustScore,
		Factors:      stored.Factors,
		Weakest:      assessment.Weakest(3),
		Verified:     stored.Verified,
		ModelVersion: stored.ModelVersion,
		CollectedAt:  stored.CollectedAt,
	})
}

// latest returns a device's current posture with its explanation.
func (h *postureHandler) latest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "id must be a UUID.")
		return
	}

	record, err := h.posture.Latest(ctx, id)
	if errors.Is(err, posture.ErrNoPosture) {
		WriteProblem(w, r, http.StatusNotFound, "Not Found",
			"This device has not reported its posture yet.")
		return
	}
	if err != nil {
		logging.FromContext(ctx).Error("failed to load posture", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The posture could not be loaded.")
		return
	}

	WriteJSON(w, r, http.StatusOK, map[string]any{
		"device_id":     record.DeviceID.String(),
		"trust_score":   record.TrustScore,
		"factors":       record.Factors,
		"signals":       record.Signals,
		"verified":      record.Verified,
		"model_version": record.ModelVersion,
		"collected_at":  record.CollectedAt,
	})
}

// history returns recent posture assessments for a device, so an investigator
// can see when a control was turned off rather than only that it is off now.
func (h *postureHandler) history(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "id must be a UUID.")
		return
	}
	limit, err := intQuery(r, "limit", 50)
	if err != nil || limit < 1 || limit > 200 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "limit must be between 1 and 200.")
		return
	}

	records, err := h.posture.History(ctx, id, limit)
	if err != nil {
		logging.FromContext(ctx).Error("failed to load posture history", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The posture history could not be loaded.")
		return
	}

	type point struct {
		CollectedAt time.Time `json:"collected_at"`
		TrustScore  int       `json:"trust_score"`
		Verified    bool      `json:"verified"`
	}
	out := make([]point, 0, len(records))
	for _, record := range records {
		out = append(out, point{record.CollectedAt, record.TrustScore, record.Verified})
	}
	WriteJSON(w, r, http.StatusOK, map[string]any{"device_id": id.String(), "history": out})
}

// auditPostureFailure records a rejected posture submission. Kept separate so
// the reason is consistent wherever it is used.
func (h *postureHandler) auditRejection(ctx context.Context, deviceID, reason string) {
	audit.Log(ctx, h.recorder, logging.FromContext(ctx), audit.Entry{
		ActorType:  audit.ActorDevice,
		ActorID:    deviceID,
		Action:     audit.ActionPostureRejected,
		TargetType: "device",
		TargetID:   deviceID,
		Result:     audit.ResultDenied,
		RequestID:  reqctx.RequestID(ctx),
		Detail:     map[string]any{"reason": reason},
	})
}
