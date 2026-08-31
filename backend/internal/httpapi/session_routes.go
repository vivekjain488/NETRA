package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/netra/backend/internal/audit"
	"github.com/netra/backend/internal/auth"
	"github.com/netra/backend/internal/logging"
	"github.com/netra/backend/internal/reqctx"
	"github.com/netra/backend/internal/session"
)

// SessionService is the session behaviour the HTTP layer depends on.
type SessionService interface {
	IssueNonce(ctx context.Context, userID uuid.UUID) (string, time.Time, error)
	Begin(ctx context.Context, req session.BeginRequest) (*session.Session, error)
	End(ctx context.Context, sessionID, userID uuid.UUID) error
	List(ctx context.Context, activeOnly bool, limit int) ([]session.Session, error)
	ByID(ctx context.Context, id uuid.UUID) (*session.Session, error)
}

type sessionHandler struct {
	sessions SessionService
	recorder audit.Recorder
}

// ── Wire types ──────────────────────────────────────────────────────────────

// NonceResponse is the attestation challenge issued to a signing-in client.
type NonceResponse struct {
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
	// Message is exactly what the device must sign. It is returned rather than
	// left for the client to assemble, so a client bug cannot silently produce
	// a signature over the wrong bytes.
	Message string `json:"message"`
}

// BeginSessionRequest carries the device's attestation.
type BeginSessionRequest struct {
	DeviceUID string `json:"device_uid"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// SessionResponse is a session as returned by the API.
type SessionResponse struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	DeviceID    string     `json:"device_id"`
	Status      string     `json:"status"`
	AuthMethod  string     `json:"auth_method"`
	Attestation string     `json:"attestation"`
	SourceIP    string     `json:"source_ip,omitempty"`
	CurrentRisk *int       `json:"current_risk,omitempty"`
	RiskLevel   string     `json:"risk_level,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	LastSeenAt  time.Time  `json:"last_seen_at"`
	EndedAt     *time.Time `json:"ended_at,omitempty"`

	UserDisplayName string `json:"user_display_name,omitempty"`
	UserEmail       string `json:"user_email,omitempty"`
	DeviceHostname  string `json:"device_hostname,omitempty"`
	DeviceUID       string `json:"device_uid,omitempty"`
}

func toSessionResponse(s *session.Session) SessionResponse {
	return SessionResponse{
		ID:              s.ID.String(),
		UserID:          s.UserID.String(),
		DeviceID:        s.DeviceID.String(),
		Status:          string(s.Status),
		AuthMethod:      s.AuthMethod,
		Attestation:     string(s.Attestation),
		SourceIP:        s.SourceIP,
		CurrentRisk:     s.CurrentRisk,
		RiskLevel:       s.CurrentLevel,
		StartedAt:       s.StartedAt,
		LastSeenAt:      s.LastSeenAt,
		EndedAt:         s.EndedAt,
		UserDisplayName: s.UserDisplayName,
		UserEmail:       s.UserEmail,
		DeviceHostname:  s.DeviceHostname,
		DeviceUID:       s.DeviceUID,
	}
}

// ── Client plane ────────────────────────────────────────────────────────────

// issueNonce returns a single-use attestation challenge for the caller.
func (h *sessionHandler) issueNonce(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	principal, ok := auth.FromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "A bearer token is required.")
		return
	}

	nonce, expiresAt, err := h.sessions.IssueNonce(ctx, principal.UserID)
	if err != nil {
		logging.FromContext(ctx).Error("failed to issue attestation nonce", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"An attestation challenge could not be issued.")
		return
	}

	WriteJSON(w, r, http.StatusCreated, NonceResponse{
		Nonce:     nonce,
		ExpiresAt: expiresAt.UTC(),
		Message:   session.AttestationString(nonce, principal.Subject),
	})
}

// begin establishes a session bound to both the user and their device.
//
// This is the route that makes NETRA more than single sign-on: a valid token
// alone does not produce a session.
func (h *sessionHandler) begin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logging.FromContext(ctx)

	principal, ok := auth.FromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "A bearer token is required.")
		return
	}

	var body BeginSessionRequest
	if !decodeJSON(w, r, &body) {
		return
	}

	created, err := h.sessions.Begin(ctx, session.BeginRequest{
		UserID:    principal.UserID,
		Subject:   principal.Subject,
		DeviceUID: body.DeviceUID,
		Nonce:     body.Nonce,
		Signature: body.Signature,
		SourceIP:  clientIP(r),
	})

	if err != nil {
		// A failed attestation with a valid user token is a strong signal: the
		// user is real but the device proof is not. It is always audited.
		denied := func(reason string) {
			audit.Log(ctx, h.recorder, logger, audit.Entry{
				ActorType:  audit.ActorUser,
				ActorID:    principal.UserID.String(),
				Action:     audit.ActionSessionBegin,
				TargetType: "device",
				TargetID:   body.DeviceUID,
				Result:     audit.ResultDenied,
				RequestID:  reqctx.RequestID(ctx),
				SourceIP:   clientIP(r),
				Detail:     map[string]any{"reason": reason},
			})
		}

		switch {
		case errors.Is(err, session.ErrValidation), errors.Is(err, session.ErrNonce):
			denied("invalid or expired attestation challenge")
			WriteProblem(w, r, http.StatusBadRequest, "Invalid Request",
				"The attestation challenge is not valid.")
		case errors.Is(err, session.ErrAttestation):
			denied("device attestation signature did not verify")
			WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized",
				"The device attestation could not be verified.")
		case errors.Is(err, session.ErrDeviceUnusable):
			denied("device is unknown, not active, or has not reported recently")
			WriteProblem(w, r, http.StatusForbidden, "Forbidden",
				"This device may not establish a session.")
		default:
			logger.Error("failed to begin session", "error", err.Error())
			WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
				"The session could not be established.")
		}
		return
	}

	audit.Log(ctx, h.recorder, logger, audit.Entry{
		ActorType:  audit.ActorUser,
		ActorID:    principal.UserID.String(),
		Action:     audit.ActionSessionBegin,
		TargetType: "session",
		TargetID:   created.ID.String(),
		Result:     audit.ResultSuccess,
		RequestID:  reqctx.RequestID(ctx),
		SourceIP:   clientIP(r),
		Detail: map[string]any{
			"device_id":   created.DeviceID.String(),
			"device_uid":  created.DeviceUID,
			"attestation": string(created.Attestation),
		},
	})

	WriteJSON(w, r, http.StatusCreated, toSessionResponse(created))
}

// end closes the caller's own session.
func (h *sessionHandler) end(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	principal, ok := auth.FromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "A bearer token is required.")
		return
	}

	var body struct {
		SessionID string `json:"session_id"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	id, err := uuid.Parse(body.SessionID)
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "session_id must be a UUID.")
		return
	}

	// The user identifier is part of the update predicate, so one user cannot
	// end another's session even by guessing an identifier.
	if err := h.sessions.End(ctx, id, principal.UserID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			WriteProblem(w, r, http.StatusNotFound, "Not Found",
				"No such active session for this user.")
			return
		}
		logging.FromContext(ctx).Error("failed to end session", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The session could not be ended.")
		return
	}

	audit.Log(ctx, h.recorder, logging.FromContext(ctx), audit.Entry{
		ActorType:  audit.ActorUser,
		ActorID:    principal.UserID.String(),
		Action:     audit.ActionSessionEnd,
		TargetType: "session",
		TargetID:   id.String(),
		Result:     audit.ResultSuccess,
		RequestID:  reqctx.RequestID(ctx),
		SourceIP:   clientIP(r),
	})

	WriteJSON(w, r, http.StatusOK, map[string]any{"status": "ended", "session_id": id.String()})
}

// ── SOC plane ───────────────────────────────────────────────────────────────

func (h *sessionHandler) listSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit, err := intQuery(r, "limit", 100)
	if err != nil || limit < 1 || limit > 500 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "limit must be between 1 and 500.")
		return
	}
	activeOnly := r.URL.Query().Get("active") == "true"

	sessions, err := h.sessions.List(ctx, activeOnly, limit)
	if err != nil {
		logging.FromContext(ctx).Error("failed to list sessions", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"Sessions could not be listed.")
		return
	}

	out := make([]SessionResponse, 0, len(sessions))
	for i := range sessions {
		out = append(out, toSessionResponse(&sessions[i]))
	}
	WriteJSON(w, r, http.StatusOK, map[string]any{"sessions": out})
}

func (h *sessionHandler) getSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "id must be a UUID.")
		return
	}

	found, err := h.sessions.ByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			WriteProblem(w, r, http.StatusNotFound, "Not Found", "No such session.")
			return
		}
		logging.FromContext(ctx).Error("failed to load session", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The session could not be loaded.")
		return
	}
	WriteJSON(w, r, http.StatusOK, toSessionResponse(found))
}

// clientIP returns the peer address. Forwarded headers are ignored: they are
// client-controlled, and a recorded address an attacker chose is worse than
// none.
func clientIP(r *http.Request) string {
	host, _, found := cutLast(r.RemoteAddr, ":")
	if !found {
		return r.RemoteAddr
	}
	return host
}

func cutLast(s, sep string) (before, after string, found bool) {
	for i := len(s) - len(sep); i >= 0; i-- {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}
