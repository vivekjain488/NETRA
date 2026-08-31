package httpapi

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/netra/backend/internal/config"
)

// Options are the dependencies required to build the API router.
type Options struct {
	Config *config.Config
	Logger *slog.Logger
	DB     Pinger
}

// NewRouter builds the versioned NETRA API.
//
// Routes are grouped by authentication plane (spec §16, §38). Only the health
// plane is unauthenticated; the agent, client, SOC and admin planes each get
// their own middleware chain as they are implemented in later phases.
func NewRouter(opts Options) http.Handler {
	r := chi.NewRouter()

	r.Use(RequestID)
	r.Use(RequestLogger(opts.Logger))
	r.Use(Recoverer)
	r.Use(SecurityHeaders)
	r.Use(CORS(opts.Config.HTTP.AllowedOrigins))

	health := &healthHandler{
		db:      opts.DB,
		env:     string(opts.Config.Env),
		started: time.Now(),
	}

	r.Route("/api/v1", func(v1 chi.Router) {
		// Health plane — unauthenticated by design, exposes no sensitive data.
		v1.Get("/health", health.Live)
		v1.Get("/health/ready", health.Ready)
	})

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "No such endpoint.")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		WriteProblem(w, r, http.StatusMethodNotAllowed, "Method Not Allowed",
			"This method is not supported for this endpoint.")
	})

	return r
}
