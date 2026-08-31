package httpapi

import (
	"context"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"

	"github.com/netra/backend/internal/audit"
	"github.com/netra/backend/internal/auth"
	"github.com/netra/backend/internal/logging"
	"github.com/netra/backend/internal/reqctx"
)

// AuditReader is the read side of the audit log.
type AuditReader interface {
	List(ctx context.Context, afterSeq int64, limit int) ([]audit.Record, error)
	Verify(ctx context.Context) error
}

// AuditRecordResponse is one audit record as returned by the API.
type AuditRecordResponse struct {
	Seq        int64          `json:"seq"`
	At         time.Time      `json:"at"`
	ActorType  string         `json:"actor_type"`
	ActorID    string         `json:"actor_id,omitempty"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type,omitempty"`
	TargetID   string         `json:"target_id,omitempty"`
	Result     string         `json:"result"`
	RequestID  string         `json:"request_id,omitempty"`
	SourceIP   string         `json:"source_ip,omitempty"`
	Detail     map[string]any `json:"detail,omitempty"`
	Hash       string         `json:"hash"`
	PrevHash   string         `json:"prev_hash,omitempty"`
}

// AuditListResponse is the audit query result, including chain integrity.
type AuditListResponse struct {
	Records []AuditRecordResponse `json:"records"`
	// ChainVerified reports whether the log's hash chain is intact. An analyst
	// reading the audit log needs to know whether it can be trusted, so the
	// answer travels with the data rather than living on a separate endpoint.
	ChainVerified bool   `json:"chain_verified"`
	ChainError    string `json:"chain_error,omitempty"`
	NextAfter     int64  `json:"next_after,omitempty"`
}

type auditHandler struct {
	reader   AuditReader
	recorder audit.Recorder
}

func (h *auditHandler) list(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := logging.FromContext(ctx)

	afterValue, err := intQuery(r, "after", 0)
	if err != nil || afterValue < 0 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter",
			"after must be a non-negative integer.")
		return
	}
	after := int64(afterValue)
	limit, err := intQuery(r, "limit", 100)
	if err != nil || limit < 1 || limit > 1000 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Parameter", "limit must be between 1 and 1000.")
		return
	}

	records, err := h.reader.List(ctx, after, limit)
	if err != nil {
		logger.Error("failed to read audit log", "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The audit log could not be read.")
		return
	}

	response := AuditListResponse{Records: make([]AuditRecordResponse, 0, len(records))}
	for _, record := range records {
		response.Records = append(response.Records, AuditRecordResponse{
			Seq:        record.Seq,
			At:         record.At,
			ActorType:  string(record.ActorType),
			ActorID:    record.ActorID,
			Action:     record.Action,
			TargetType: record.TargetType,
			TargetID:   record.TargetID,
			Result:     string(record.Result),
			RequestID:  record.RequestID,
			SourceIP:   record.SourceIP,
			Detail:     record.Detail,
			Hash:       hex.EncodeToString(record.Hash),
			PrevHash:   hex.EncodeToString(record.PrevHash),
		})
	}
	if n := len(records); n > 0 {
		response.NextAfter = records[n-1].Seq
	}

	if err := h.reader.Verify(ctx); err != nil {
		response.ChainVerified = false
		response.ChainError = err.Error()
		// A broken chain means someone may have tampered with the evidence.
		logger.Error("audit chain verification failed", "error", err.Error())
	} else {
		response.ChainVerified = true
	}

	// Reading the audit log is itself a privileged action, so it is audited.
	if principal, ok := auth.FromContext(ctx); ok {
		audit.Log(ctx, h.recorder, logger, audit.Entry{
			ActorType: audit.ActorUser,
			ActorID:   principal.UserID.String(),
			Action:    audit.ActionAuditRead,
			Result:    audit.ResultSuccess,
			RequestID: reqctx.RequestID(ctx),
			Detail:    map[string]any{"after": after, "limit": limit},
		})
	}

	WriteJSON(w, r, http.StatusOK, response)
}

func intQuery(r *http.Request, name string, fallback int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	return strconv.Atoi(raw)
}
