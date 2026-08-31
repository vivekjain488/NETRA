package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/netra/backend/internal/audit"
	"github.com/netra/backend/internal/auth"
	"github.com/netra/backend/internal/device"
	"github.com/netra/backend/internal/logging"
	"github.com/netra/backend/internal/reqctx"
)

// DeviceService is the device behaviour the HTTP layer depends on.
type DeviceService interface {
	device.Repository
	IssueEnrollmentToken(ctx context.Context, createdBy *uuid.UUID, label string, ttl time.Duration) (string, uuid.UUID, error)
	Enroll(ctx context.Context, token string, req device.EnrollRequest) (*device.Device, error)
	List(ctx context.Context, limit int) ([]device.Device, error)
	ByID(ctx context.Context, id uuid.UUID) (*device.Device, error)
	Heartbeat(ctx context.Context, id uuid.UUID, agentVersion string) error
	Revoke(ctx context.Context, id uuid.UUID, reason string) error
}

type deviceHandler struct {
	devices  DeviceService
	recorder audit.Recorder
}

// ── Wire types ──────────────────────────────────────────────────────────────

// EnrollmentTokenRequest asks for a single-use device enrollment token.
type EnrollmentTokenRequest struct {
	Label      string `json:"label"`
	TTLMinutes int    `json:"ttl_minutes"`
}

// EnrollmentTokenResponse carries the token. The plaintext is returned exactly
// once; only its hash is stored.
type EnrollmentTokenResponse struct {
	TokenID   string    `json:"token_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Notice    string    `json:"notice"`
}

// EnrollRequestBody is what an agent submits to enroll.
type EnrollRequestBody struct {
	EnrollmentToken string `json:"enrollment_token"`
	DeviceUID       string `json:"device_uid"`
	Hostname        string `json:"hostname"`
	OSName          string `json:"os_name"`
	OSVersion       string `json:"os_version"`
	AgentVersion    string `json:"agent_version"`
	PublicKey       string `json:"public_key"`
	KeyProtection   string `json:"key_protection"`
}

// DeviceResponse is a device as returned by the API.
type DeviceResponse struct {
	ID              string     `json:"id"`
	DeviceUID       string     `json:"device_uid"`
	Hostname        string     `json:"hostname"`
	OSName          string     `json:"os_name"`
	OSVersion       string     `json:"os_version"`
	AgentVersion    string     `json:"agent_version"`
	KeyAlgorithm    string     `json:"key_algorithm"`
	KeyProtection   string     `json:"key_protection"`
	State           string     `json:"state"`
	EnrolledAt      *time.Time `json:"enrolled_at,omitempty"`
	LastHeartbeatAt *time.Time `json:"last_heartbeat_at,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	RevokedReason   string     `json:"revoked_reason,omitempty"`
}

// HeartbeatRequest is the agent's periodic liveness report.
type HeartbeatRequest struct {
	AgentVersion  string `json:"agent_version"`
	QueuedEvents  int    `json:"queued_events"`
	DroppedEvents int64  `json:"dropped_events"`
}

// HeartbeatResponse tells the agent what the control plane expects next.
type HeartbeatResponse struct {
	ServerTime        time.Time `json:"server_time"`
	HeartbeatInterval int       `json:"heartbeat_interval_seconds"`
	PolicyVersion     int       `json:"policy_version"`
}

// RevokeRequest carries the reason a device is no longer trusted.
type RevokeRequest struct {
	Reason string `json:"reason"`
}

func toDeviceResponse(d *device.Device) DeviceResponse {
	// The public key is deliberately absent: it is not secret, but publishing
	// every device's key on a SOC endpoint serves no operational purpose.
	return DeviceResponse{
		ID:              d.ID.String(),
		DeviceUID:       d.DeviceUID,
		Hostname:        d.Hostname,
		OSName:          d.OSName,
		OSVersion:       d.OSVersion,
		AgentVersion:    d.AgentVersion,
		KeyAlgorithm:    d.KeyAlgorithm,
		KeyProtection:   d.KeyProtection,
		State:           string(d.State),
		EnrolledAt:      d.EnrolledAt,
		LastHeartbeatAt: d.LastHeartbeatAt,
		RevokedAt:       d.RevokedAt,
		RevokedReason:   d.RevokedReason,
	}
}

// ── Admin plane ─────────────────────────────────────────────────────────────

// issueEnrollmentToken creates a single-use token for enrolling one device.
//
// Enrollment is never anonymous: without an administrator-issued token, any
// host that could reach the API could claim a device identity.
func (h *deviceHandler) issueEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req EnrollmentTokenRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.TTLMinutes <= 0 {
		req.TTLMinutes = 60
	}
	if req.TTLMinutes > 60*24*7 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request",
			"ttl_minutes must not exceed one week.")
		return
	}

	principal, _ := auth.FromContext(ctx)
	var createdBy *uuid.UUID
	if principal != nil {
		createdBy = &principal.UserID
	}

	ttl := time.Duration(req.TTLMinutes) * time.Minute
	token, tokenID, err := h.devices.IssueEnrollmentToken(ctx, createdBy, req.Label, ttl)
	if err != nil {
		logging.FromContext(ctx).Error("failed to issue enrollment token", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The enrollment token could not be issued.")
		return
	}

	audit.Log(ctx, h.recorder, logging.FromContext(ctx), audit.Entry{
		ActorType:  audit.ActorUser,
		ActorID:    actorID(principal),
		Action:     audit.ActionEnrollTokenIssue,
		TargetType: "enrollment_token",
		TargetID:   tokenID.String(),
		Result:     audit.ResultSuccess,
		RequestID:  reqctx.RequestID(ctx),
		// The token itself is never audited: an audit reader must not be able
		// to enrol a device from the log.
		Detail: map[string]any{"label": req.Label, "ttl_minutes": req.TTLMinutes},
	})

	WriteJSON(w, r, http.StatusCreated, EnrollmentTokenResponse{
		TokenID:   tokenID.String(),
		Token:     token,
		ExpiresAt: time.Now().Add(ttl).UTC(),
		Notice:    "This token is shown once and can enrol exactly one device.",
	})
}

// listDevices returns the enrolled fleet.
func (h *deviceHandler) listDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit, err := intQuery(r, "limit", 100)
	if err != nil || limit < 1 || limit > 500 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter",
			"limit must be between 1 and 500.")
		return
	}

	devices, err := h.devices.List(ctx, limit)
	if err != nil {
		logging.FromContext(ctx).Error("failed to list devices", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"Devices could not be listed.")
		return
	}

	out := make([]DeviceResponse, 0, len(devices))
	for i := range devices {
		out = append(out, toDeviceResponse(&devices[i]))
	}
	WriteJSON(w, r, http.StatusOK, map[string]any{"devices": out})
}

// getDevice returns one device.
func (h *deviceHandler) getDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "id must be a UUID.")
		return
	}

	found, err := h.devices.ByID(ctx, id)
	if errors.Is(err, device.ErrDeviceNotFound) {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "No such device.")
		return
	}
	if err != nil {
		logging.FromContext(ctx).Error("failed to load device", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The device could not be loaded.")
		return
	}
	WriteJSON(w, r, http.StatusOK, toDeviceResponse(found))
}

// revokeDevice withdraws trust from a device.
func (h *deviceHandler) revokeDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "id must be a UUID.")
		return
	}

	var req RevokeRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	principal, _ := auth.FromContext(ctx)
	err = h.devices.Revoke(ctx, id, req.Reason)
	if errors.Is(err, device.ErrDeviceNotFound) {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "No such device, or it is already revoked.")
		return
	}
	if err != nil {
		logging.FromContext(ctx).Error("failed to revoke device", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The device could not be revoked.")
		return
	}

	audit.Log(ctx, h.recorder, logging.FromContext(ctx), audit.Entry{
		ActorType:  audit.ActorUser,
		ActorID:    actorID(principal),
		Action:     audit.ActionDeviceRevoke,
		TargetType: "device",
		TargetID:   id.String(),
		Result:     audit.ResultSuccess,
		RequestID:  reqctx.RequestID(ctx),
		Detail:     map[string]any{"reason": req.Reason},
	})

	WriteJSON(w, r, http.StatusOK, map[string]any{"status": "revoked", "device_id": id.String()})
}

// ── Agent plane ─────────────────────────────────────────────────────────────

// enroll registers a device against a single-use enrollment token.
//
// This is the one agent-plane route that is not device-signed: the device has
// no identity yet. The enrollment token is what authorises it.
func (h *deviceHandler) enroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logging.FromContext(ctx)

	var body EnrollRequestBody
	if !decodeJSON(w, r, &body) {
		return
	}

	publicKey, err := device.ParsePublicKey(body.PublicKey)
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	req := device.EnrollRequest{
		DeviceUID:     body.DeviceUID,
		Hostname:      body.Hostname,
		OSName:        body.OSName,
		OSVersion:     body.OSVersion,
		AgentVersion:  body.AgentVersion,
		PublicKey:     publicKey,
		KeyProtection: body.KeyProtection,
	}

	enrolled, err := h.devices.Enroll(ctx, body.EnrollmentToken, req)
	switch {
	case errors.Is(err, device.ErrEnrollmentToken):
		// A failed enrollment attempt is audited: it is a bounded event, since
		// it requires presenting a token value, and it is exactly what a SOC
		// wants to see if someone is guessing.
		audit.Log(ctx, h.recorder, logger, audit.Entry{
			ActorType:  audit.ActorDevice,
			ActorID:    body.DeviceUID,
			Action:     audit.ActionDeviceEnroll,
			TargetType: "device",
			TargetID:   body.DeviceUID,
			Result:     audit.ResultDenied,
			RequestID:  reqctx.RequestID(ctx),
			Detail:     map[string]any{"reason": "invalid or spent enrollment token"},
		})
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized",
			"The enrollment token is not valid.")
		return
	case errors.Is(err, device.ErrDeviceExists):
		WriteProblem(w, r, http.StatusConflict, "Conflict",
			"A device with this identifier is already enrolled.")
		return
	case errors.Is(err, device.ErrValidation):
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	case err != nil:
		logger.Error("device enrollment failed", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The device could not be enrolled.")
		return
	}

	audit.Log(ctx, h.recorder, logger, audit.Entry{
		ActorType:  audit.ActorDevice,
		ActorID:    enrolled.ID.String(),
		Action:     audit.ActionDeviceEnroll,
		TargetType: "device",
		TargetID:   enrolled.ID.String(),
		Result:     audit.ResultSuccess,
		RequestID:  reqctx.RequestID(ctx),
		Detail: map[string]any{
			"hostname":          enrolled.Hostname,
			"os":                enrolled.OSName + " " + enrolled.OSVersion,
			"agent_version":     enrolled.AgentVersion,
			"key_protection":    enrolled.KeyProtection,
			"public_key_sha256": publicKeyFingerprint(publicKey),
		},
	})

	WriteJSON(w, r, http.StatusCreated, toDeviceResponse(enrolled))
}

// heartbeat records agent liveness. The request is device-signed.
func (h *deviceHandler) heartbeat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authenticated, ok := device.FromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Device authentication is required.")
		return
	}

	var body HeartbeatRequest
	if !decodeJSON(w, r, &body) {
		return
	}

	if err := h.devices.Heartbeat(ctx, authenticated.ID, body.AgentVersion); err != nil {
		if errors.Is(err, device.ErrDeviceNotActive) {
			WriteProblem(w, r, http.StatusForbidden, "Forbidden", "This device is not active.")
			return
		}
		logging.FromContext(ctx).Error("failed to record heartbeat", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The heartbeat could not be recorded.")
		return
	}

	// A heartbeat is not audited: it happens every thirty seconds per device
	// and would swamp the log. Liveness is visible from last_heartbeat_at, and
	// its absence is what matters.
	if body.DroppedEvents > 0 {
		logging.FromContext(ctx).Warn("endpoint is shedding telemetry",
			"dropped_events", body.DroppedEvents,
			"queued_events", body.QueuedEvents)
	}

	WriteJSON(w, r, http.StatusOK, HeartbeatResponse{
		ServerTime:        time.Now().UTC(),
		HeartbeatInterval: 30,
		PolicyVersion:     0, // Policies arrive in Phase 9.
	})
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	// Unknown fields are refused rather than ignored: silently discarding a
	// misspelled security-relevant field is how misconfigurations hide.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request",
			"The request body is not valid JSON for this endpoint.")
		return false
	}
	return true
}

func actorID(p *auth.Principal) string {
	if p == nil {
		return ""
	}
	return p.UserID.String()
}

func publicKeyFingerprint(key []byte) string {
	return base64.RawStdEncoding.EncodeToString(key)[:16]
}
