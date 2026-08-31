// Package httpapi contains the NETRA REST surface: routing, middleware and
// the shared error representation.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/netra/backend/internal/logging"
)

// Problem is an RFC 7807 problem detail. Every error response in NETRA uses
// this shape so clients — and the SOC dashboard — can handle failures
// uniformly rather than parsing ad-hoc error strings.
type Problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail,omitempty"`
	Instance  string `json:"instance,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// WriteProblem renders an error as application/problem+json.
//
// detail must never contain internal diagnostics: it is returned to a client
// that may be untrusted. Diagnostics belong in the log, correlated by
// request_id.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	p := Problem{
		Type:      "about:blank",
		Title:     title,
		Status:    status,
		Detail:    detail,
		Instance:  r.URL.Path,
		RequestID: RequestIDFromContext(r.Context()),
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(p); err != nil {
		logging.FromContext(r.Context()).Error("failed to encode problem response",
			slog.String("error", err.Error()))
	}
}

// WriteJSON renders v as a JSON response with the given status.
func WriteJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logging.FromContext(r.Context()).Error("failed to encode response body",
			slog.String("error", err.Error()))
	}
}
