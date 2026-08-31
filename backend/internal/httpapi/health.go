package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/netra/backend/internal/version"
)

// Pinger is the health dependency contract. Keeping it an interface lets the
// health endpoint be tested without a live database.
type Pinger interface {
	Ping(ctx context.Context) error
}

// HealthResponse is the payload of the health endpoints.
type HealthResponse struct {
	Status   string            `json:"status"` // ok | degraded
	Build    version.Info      `json:"build"`
	Checks   map[string]string `json:"checks"`
	Time     time.Time         `json:"time"`
	Env      string            `json:"env"`
	Uptime   string            `json:"uptime"`
	Hostname string            `json:"hostname,omitempty"`
}

// healthHandler answers liveness and readiness probes.
type healthHandler struct {
	db      Pinger
	env     string
	started time.Time
}

// Live reports process liveness. It deliberately does not touch the database:
// a database outage must not cause an orchestrator to kill healthy backends.
func (h *healthHandler) Live(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, r, http.StatusOK, HealthResponse{
		Status: "ok",
		Build:  version.Current(),
		Checks: map[string]string{},
		Time:   time.Now().UTC(),
		Env:    h.env,
		Uptime: time.Since(h.started).Round(time.Second).String(),
	})
}

// Ready reports whether the backend can serve traffic, including dependencies.
func (h *healthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	checks := map[string]string{}
	status := "ok"
	code := http.StatusOK

	if h.db != nil {
		if err := h.db.Ping(ctx); err != nil {
			// The error text is logged, not returned: it can contain the DSN.
			checks["database"] = "unavailable"
			status = "degraded"
			code = http.StatusServiceUnavailable
		} else {
			checks["database"] = "ok"
		}
	} else {
		checks["database"] = "not_configured"
	}

	WriteJSON(w, r, code, HealthResponse{
		Status: status,
		Build:  version.Current(),
		Checks: checks,
		Time:   time.Now().UTC(),
		Env:    h.env,
		Uptime: time.Since(h.started).Round(time.Second).String(),
	})
}
