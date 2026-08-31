package httpapi

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/netra/backend/internal/audit"
	"github.com/netra/backend/internal/auth"
	"github.com/netra/backend/internal/config"
	"github.com/netra/backend/internal/device"
	"github.com/netra/backend/internal/identity"
	"github.com/netra/backend/internal/posture"
	"github.com/netra/backend/internal/user"
)

// Options are the dependencies required to build the API router.
type Options struct {
	Config *config.Config
	Logger *slog.Logger
	DB     Pinger

	// Verifier validates user identity tokens. Required for every
	// authenticated plane.
	Verifier identity.Verifier
	// Users projects verified claims onto local user records.
	Users user.Resolver
	// Audit records security-relevant actions.
	Audit audit.Recorder
	// AuditReader serves the audit query API.
	AuditReader AuditReader
	// DevVerifier, when non-nil, mounts the development token endpoint.
	// The configuration loader refuses to set this outside development.
	DevVerifier *identity.DevVerifier
	// Devices backs the agent and device-administration planes.
	Devices DeviceService
	// Sessions backs session establishment and the SOC session views.
	Sessions SessionService
	// Posture backs device posture scoring and its SOC views.
	Posture PostureService
	// PostureWeights is the scoring model applied to reported signals.
	PostureWeights posture.Weights
	// ExpectedAgentVersion is the agent build the fleet should be running.
	ExpectedAgentVersion string
}

// NewRouter builds the versioned NETRA API.
//
// Routes are grouped by authentication plane (spec §16, §38). Only the health
// plane is unauthenticated; each other plane gets its own middleware chain, so
// a handler cannot be reached without having passed the checks for its plane.
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

	authDeps := auth.Deps{
		Verifier:     opts.Verifier,
		Users:        opts.Users,
		Audit:        opts.Audit,
		Logger:       opts.Logger,
		WriteProblem: WriteProblem,
	}
	authenticated := auth.RequireAuth(authDeps)

	r.Route("/api/v1", func(v1 chi.Router) {
		// ── Health plane: unauthenticated, exposes no sensitive data ──────
		v1.Get("/health", health.Live)
		v1.Get("/health/ready", health.Ready)

		// ── Development plane: mounted only when explicitly enabled ───────
		if opts.DevVerifier != nil {
			dev := &devHandler{verifier: opts.DevVerifier, recorder: opts.Audit}
			v1.Post("/dev/token", dev.mint)
		}

		// ── Agent plane: authenticated by the device key, not by a user ───
		if opts.Devices != nil {
			deviceAPI := &deviceHandler{
				devices:  opts.Devices,
				recorder: opts.Audit,
				posture:  opts.Posture,
			}

			// Enrollment is the one agent route without device authentication:
			// the device has no identity yet. The single-use enrollment token
			// issued by an administrator is what authorises it.
			v1.Post("/agent/enroll", deviceAPI.enroll)

			v1.Group(func(agent chi.Router) {
				agent.Use(device.RequireDeviceSignature(device.AuthDeps{
					Devices:      opts.Devices,
					Logger:       opts.Logger,
					WriteProblem: WriteProblem,
				}))
				agent.Post("/agent/heartbeat", deviceAPI.heartbeat)

				if opts.Posture != nil {
					postureAPI := &postureHandler{
						posture:       opts.Posture,
						recorder:      opts.Audit,
						weights:       opts.PostureWeights,
						expectedAgent: opts.ExpectedAgentVersion,
					}
					agent.Post("/agent/posture", postureAPI.submit)
				}
			})
		}

		if opts.Verifier == nil || opts.Users == nil {
			// Without a verifier there is nothing to authenticate against, so
			// the authenticated planes are simply not mounted.
			return
		}

		// ── Client plane: any authenticated user, own data only ───────────
		v1.Group(func(client chi.Router) {
			client.Use(authenticated)
			client.Get("/client/me", handleMe)

			if opts.Sessions != nil {
				sessionAPI := &sessionHandler{sessions: opts.Sessions, recorder: opts.Audit}
				client.Post("/client/session/nonce", sessionAPI.issueNonce)
				client.Post("/client/session/begin", sessionAPI.begin)
				client.Post("/client/session/end", sessionAPI.end)
			}
		})

		// ── SOC plane: analysts, auditors and administrators ──────────────
		if opts.AuditReader != nil {
			auditAPI := &auditHandler{reader: opts.AuditReader, recorder: opts.Audit}
			v1.Group(func(soc chi.Router) {
				soc.Use(authenticated)
				soc.Use(auth.RequireRole(authDeps,
					roleSet(identity.RoleAuditor, identity.RoleAdmin, identity.RoleAnalyst)...))
				soc.Get("/audit", auditAPI.list)
			})
		}

		if opts.Sessions != nil {
			sessionAPI := &sessionHandler{sessions: opts.Sessions, recorder: opts.Audit}
			v1.Group(func(soc chi.Router) {
				soc.Use(authenticated)
				soc.Use(auth.RequireRole(authDeps,
					roleSet(identity.RoleAnalyst, identity.RoleAdmin, identity.RoleAuditor)...))
				soc.Get("/sessions", sessionAPI.listSessions)
				soc.Get("/sessions/{id}", sessionAPI.getSession)
			})
		}

		if opts.Devices != nil {
			deviceAPI := &deviceHandler{
				devices:  opts.Devices,
				recorder: opts.Audit,
				posture:  opts.Posture,
			}

			// Reading the fleet is an investigation activity.
			v1.Group(func(soc chi.Router) {
				soc.Use(authenticated)
				soc.Use(auth.RequireRole(authDeps,
					roleSet(identity.RoleAnalyst, identity.RoleAdmin, identity.RoleAuditor)...))
				soc.Get("/devices", deviceAPI.listDevices)
				soc.Get("/devices/{id}", deviceAPI.getDevice)

				if opts.Posture != nil {
					postureAPI := &postureHandler{
						posture:       opts.Posture,
						recorder:      opts.Audit,
						weights:       opts.PostureWeights,
						expectedAgent: opts.ExpectedAgentVersion,
					}
					soc.Get("/devices/{id}/posture", postureAPI.latest)
					soc.Get("/devices/{id}/posture/history", postureAPI.history)
				}
			})

			// Issuing enrollment tokens and revoking devices change what the
			// system trusts, so they are restricted to administrators.
			v1.Group(func(admin chi.Router) {
				admin.Use(authenticated)
				admin.Use(auth.RequireRole(authDeps, roleSet(identity.RoleAdmin)...))
				admin.Post("/enrollment-tokens", deviceAPI.issueEnrollmentToken)
				admin.Post("/devices/{id}/revoke", deviceAPI.revokeDevice)
			})
		}
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
