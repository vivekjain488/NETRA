// Package auth turns a verified identity token into an authorized principal.
//
// Authentication answers "who is this?"; authorization answers "may they do
// this?". Both are enforced here, at the edge, so no handler can be reached
// without having passed them.
package auth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/netra/backend/internal/audit"
	"github.com/netra/backend/internal/identity"
	"github.com/netra/backend/internal/logging"
	"github.com/netra/backend/internal/reqctx"
	"github.com/netra/backend/internal/user"
)

type principalKey struct{}

// Principal is an authenticated caller.
//
// Roles come from the token, not from the database row: the identity provider
// is authoritative, and reading them from the token means a revoked role takes
// effect on the very next request.
type Principal struct {
	UserID      uuid.UUID
	Subject     string
	Email       string
	DisplayName string
	Department  string
	Roles       []identity.Role
}

// HasRole reports whether the principal holds a specific role.
func (p *Principal) HasRole(role identity.Role) bool {
	for _, held := range p.Roles {
		if held == role {
			return true
		}
	}
	return false
}

// HasAnyRole reports whether the principal holds at least one of the roles.
func (p *Principal) HasAnyRole(roles ...identity.Role) bool {
	for _, role := range roles {
		if p.HasRole(role) {
			return true
		}
	}
	return false
}

// FromContext returns the authenticated principal, if any.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok && p != nil
}

// WithPrincipal returns a context carrying the principal.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// ProblemWriter renders an error response. It matches httpapi.WriteProblem and
// is injected so this package does not depend on the HTTP layer's router.
type ProblemWriter func(w http.ResponseWriter, r *http.Request, status int, title, detail string)

// Deps are the collaborators the middleware needs.
type Deps struct {
	Verifier     identity.Verifier
	Users        user.Resolver
	Audit        audit.Recorder
	Logger       *slog.Logger
	WriteProblem ProblemWriter
}

// RequireAuth rejects any request without a valid identity token.
//
// Authentication failures are logged but not written to the audit log:
// anonymous traffic to a public address would otherwise let anyone grow the
// audit table without limit. Authorization denials, which require a valid
// identity, are audited.
func RequireAuth(deps Deps) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			logger := logging.FromContext(ctx)

			raw, ok := bearerToken(r)
			if !ok {
				deps.WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized",
					"A bearer token is required.")
				return
			}

			claims, err := deps.Verifier.Verify(ctx, raw)
			if err != nil {
				logger.Warn("identity token rejected",
					slog.String("issuer", deps.Verifier.Issuer()),
					slog.String("error", err.Error()))
				deps.WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized",
					"The bearer token is not valid.")
				return
			}
			if err := claims.Validate(); err != nil {
				deps.WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized",
					"The bearer token is not valid.")
				return
			}

			record, err := deps.Users.ResolveFromClaims(ctx, claims)
			if err != nil {
				// A disabled account presenting a still-valid token is a
				// security-relevant event and is audited.
				audit.Log(ctx, deps.Audit, logger, audit.Entry{
					ActorType: audit.ActorUser,
					ActorID:   claims.Subject,
					Action:    audit.ActionAuthenticate,
					Result:    audit.ResultDenied,
					RequestID: reqctx.RequestID(ctx),
					SourceIP:  clientIP(r),
					Detail:    map[string]any{"reason": err.Error()},
				})
				logger.Warn("could not resolve authenticated user",
					slog.String("subject", claims.Subject),
					slog.String("error", err.Error()))
				deps.WriteProblem(w, r, http.StatusForbidden, "Forbidden",
					"This account may not access NETRA.")
				return
			}

			principal := &Principal{
				UserID:      record.ID,
				Subject:     claims.Subject,
				Email:       record.Email,
				DisplayName: record.DisplayName,
				Department:  record.Department,
				Roles:       claims.Roles,
			}

			ctx = WithPrincipal(ctx, principal)
			ctx = logging.WithContext(ctx, logger.With(
				slog.String(logging.KeyUserID, principal.UserID.String())))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole rejects a principal that holds none of the given roles.
//
// Every denial is audited: an attempt to reach an administrative endpoint with
// an ordinary account is exactly the kind of event a SOC needs to see.
func RequireRole(deps Deps, roles ...identity.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			principal, ok := FromContext(ctx)
			if !ok {
				// Reaching here means RequireRole was mounted without
				// RequireAuth, which is a wiring bug rather than a client error.
				deps.WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized",
					"A bearer token is required.")
				return
			}

			if !principal.HasAnyRole(roles...) {
				audit.Log(ctx, deps.Audit, logging.FromContext(ctx), audit.Entry{
					ActorType:  audit.ActorUser,
					ActorID:    principal.UserID.String(),
					Action:     audit.ActionAuthorizationDeny,
					TargetType: "endpoint",
					TargetID:   r.Method + " " + r.URL.Path,
					Result:     audit.ResultDenied,
					RequestID:  reqctx.RequestID(ctx),
					SourceIP:   clientIP(r),
					Detail: map[string]any{
						"required_roles": roleNames(roles),
						"held_roles":     roleNames(principal.Roles),
					},
				})
				deps.WriteProblem(w, r, http.StatusForbidden, "Forbidden",
					"Your role does not permit this operation.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

func roleNames(roles []identity.Role) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, string(r))
	}
	return out
}

// clientIP returns the peer address. Forwarded headers are deliberately
// ignored: they are client-controlled, and NETRA would rather record the true
// peer than an address an attacker chose.
func clientIP(r *http.Request) string {
	host, _, found := strings.Cut(r.RemoteAddr, ":")
	if !found {
		return r.RemoteAddr
	}
	return host
}
