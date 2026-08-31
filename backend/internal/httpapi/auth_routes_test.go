package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netra/backend/internal/audit"
	"github.com/netra/backend/internal/config"
	"github.com/netra/backend/internal/identity"
	"github.com/netra/backend/internal/user"
)

// ── Test doubles ────────────────────────────────────────────────────────────

// fakeUsers resolves claims without a database, mapping each subject to a
// stable identifier so tests can assert on it.
type fakeUsers struct {
	ids      map[string]uuid.UUID
	disabled map[string]bool
}

func newFakeUsers() *fakeUsers {
	return &fakeUsers{ids: map[string]uuid.UUID{}, disabled: map[string]bool{}}
}

func (f *fakeUsers) ResolveFromClaims(_ context.Context, claims *identity.Claims) (*user.User, error) {
	if f.disabled[claims.Subject] {
		return nil, user.ErrDisabled
	}
	id, ok := f.ids[claims.Subject]
	if !ok {
		id = uuid.New()
		f.ids[claims.Subject] = id
	}
	return &user.User{
		ID:              id,
		ExternalSubject: claims.Subject,
		Email:           claims.Email,
		DisplayName:     claims.DisplayName,
		Department:      claims.Department,
		Role:            claims.HighestRole(),
	}, nil
}

// fakeAudit captures entries in memory and maintains the same hash chain the
// real store does, so chain behaviour is exercised without PostgreSQL.
type fakeAudit struct {
	records  []audit.Record
	failNext bool
}

func (f *fakeAudit) Record(_ context.Context, entry audit.Entry) error {
	if f.failNext {
		f.failNext = false
		return io.ErrUnexpectedEOF
	}
	if entry.At.IsZero() {
		entry.At = time.Now()
	}
	entry = entry.Normalize()

	var prev []byte
	if n := len(f.records); n > 0 {
		prev = f.records[n-1].Hash
	}
	hash, err := audit.ComputeHash(prev, entry)
	if err != nil {
		return err
	}
	f.records = append(f.records, audit.Record{
		Seq: int64(len(f.records) + 1), Entry: entry, PrevHash: prev, Hash: hash,
	})
	return nil
}

func (f *fakeAudit) List(_ context.Context, afterSeq int64, limit int) ([]audit.Record, error) {
	var out []audit.Record
	for _, record := range f.records {
		if record.Seq > afterSeq && len(out) < limit {
			out = append(out, record)
		}
	}
	return out, nil
}

func (f *fakeAudit) Verify(_ context.Context) error { return audit.VerifyChain(f.records) }

func (f *fakeAudit) actions() []string {
	out := make([]string, 0, len(f.records))
	for _, record := range f.records {
		out = append(out, record.Action)
	}
	return out
}

// testConfig is the configuration shared by the HTTP test harnesses.
func testConfig() *config.Config {
	return &config.Config{
		Env:  config.EnvDevelopment,
		HTTP: config.HTTPConfig{AllowedOrigins: []string{"http://localhost:5173"}},
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// ── Harness ─────────────────────────────────────────────────────────────────

type harness struct {
	router http.Handler
	dev    *identity.DevVerifier
	users  *fakeUsers
	audit  *fakeAudit
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	dev, err := identity.NewDevVerifier("development", time.Hour)
	if err != nil {
		t.Fatalf("NewDevVerifier: %v", err)
	}
	users := newFakeUsers()
	recorder := &fakeAudit{}

	router := NewRouter(Options{
		Config: &config.Config{
			Env:  config.EnvDevelopment,
			HTTP: config.HTTPConfig{AllowedOrigins: []string{"http://localhost:5173"}},
		},
		Logger:      slog.New(slog.NewJSONHandler(io.Discard, nil)),
		DB:          stubPinger{},
		Verifier:    dev,
		Users:       users,
		Audit:       recorder,
		AuditReader: recorder,
		DevVerifier: dev,
	})
	return &harness{router: router, dev: dev, users: users, audit: recorder}
}

func (h *harness) token(t *testing.T, subject string, roles ...identity.Role) string {
	t.Helper()
	token, err := h.dev.Mint(subject, subject+"@example.gov", strings.ToTitle(subject), "Operations", roles)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return token
}

func (h *harness) get(t *testing.T, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

// ── Authentication ──────────────────────────────────────────────────────────

func TestClientMeRequiresAToken(t *testing.T) {
	h := newHarness(t)

	rec := h.get(t, "/api/v1/client/me", "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want problem+json", ct)
	}
}

func TestClientMeRejectsMalformedAuthorizationHeaders(t *testing.T) {
	h := newHarness(t)
	valid := h.token(t, "alice")

	headers := map[string]string{
		"no scheme":     valid,
		"wrong scheme":  "Basic " + valid,
		"empty bearer":  "Bearer ",
		"garbage token": "Bearer not-a-jwt",
	}
	for name, header := range headers {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/client/me", nil)
			req.Header.Set("Authorization", header)
			rec := httptest.NewRecorder()
			h.router.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
		})
	}
}

func TestClientMeReturnsTheCallersOwnIdentity(t *testing.T) {
	h := newHarness(t)

	rec := h.get(t, "/api/v1/client/me", h.token(t, "alice", identity.RoleAnalyst))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var body MeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body.Subject != "alice" || body.Email != "alice@example.gov" {
		t.Errorf("body = %+v, want alice's identity", body)
	}
	if _, err := uuid.Parse(body.UserID); err != nil {
		t.Errorf("user_id = %q, want a UUID", body.UserID)
	}
	if len(body.Roles) != 2 {
		t.Errorf("roles = %v, want USER and SECURITY_ANALYST", body.Roles)
	}
}

func TestDisabledAccountIsRefusedAndAudited(t *testing.T) {
	// Disabling must take effect immediately, not when the token expires.
	h := newHarness(t)
	h.users.disabled["mallory"] = true

	rec := h.get(t, "/api/v1/client/me", h.token(t, "mallory"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := h.audit.actions(); len(got) != 1 || got[0] != audit.ActionAuthenticate {
		t.Errorf("audit actions = %v, want one %q record", got, audit.ActionAuthenticate)
	}
	if h.audit.records[0].Result != audit.ResultDenied {
		t.Errorf("audit result = %q, want DENIED", h.audit.records[0].Result)
	}
}

func TestAnonymousTrafficDoesNotGrowTheAuditLog(t *testing.T) {
	// Auditing every rejected anonymous request would let anyone fill the
	// audit table from an unauthenticated endpoint.
	h := newHarness(t)

	for i := 0; i < 20; i++ {
		h.get(t, "/api/v1/client/me", "")
		h.get(t, "/api/v1/client/me", "Bearer garbage")
	}

	if len(h.audit.records) != 0 {
		t.Errorf("audit records = %d, want 0 for unauthenticated traffic", len(h.audit.records))
	}
}

// ── Authorization ───────────────────────────────────────────────────────────

func TestAuditRequiresAPrivilegedRole(t *testing.T) {
	h := newHarness(t)

	rec := h.get(t, "/api/v1/audit", h.token(t, "bob"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an ordinary user", rec.Code)
	}
}

func TestAuthorizationDenialIsAudited(t *testing.T) {
	h := newHarness(t)

	h.get(t, "/api/v1/audit", h.token(t, "bob"))

	if len(h.audit.records) != 1 {
		t.Fatalf("audit records = %d, want 1", len(h.audit.records))
	}
	record := h.audit.records[0]
	if record.Action != audit.ActionAuthorizationDeny || record.Result != audit.ResultDenied {
		t.Errorf("record = %+v, want an authorization denial", record.Entry)
	}
	if record.TargetID != "GET /api/v1/audit" {
		t.Errorf("target = %q, want the attempted endpoint", record.TargetID)
	}
	if record.RequestID == "" {
		t.Error("audit record has no request_id; it cannot be correlated to the request log")
	}
}

func TestPrivilegedRolesMayReadTheAuditLog(t *testing.T) {
	for _, role := range []identity.Role{identity.RoleAuditor, identity.RoleAdmin, identity.RoleAnalyst} {
		t.Run(string(role), func(t *testing.T) {
			h := newHarness(t)

			rec := h.get(t, "/api/v1/audit", h.token(t, "carol", role))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAuditResponseReportsChainIntegrity(t *testing.T) {
	h := newHarness(t)
	// Generate a denial so the log is not empty.
	h.get(t, "/api/v1/audit", h.token(t, "bob"))

	rec := h.get(t, "/api/v1/audit", h.token(t, "carol", identity.RoleAuditor))

	var body AuditListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if !body.ChainVerified {
		t.Errorf("chain_verified = false, want true (error %q)", body.ChainError)
	}
	if len(body.Records) == 0 {
		t.Fatal("no audit records returned")
	}
	if body.Records[0].Hash == "" {
		t.Error("record hash is empty; integrity cannot be checked by a reader")
	}
}

func TestAuditResponseReportsATamperedChain(t *testing.T) {
	h := newHarness(t)
	h.get(t, "/api/v1/audit", h.token(t, "bob"))
	// Silently rewrite history, as an attacker with database access would.
	h.audit.records[0].Action = "auth.authenticate"

	rec := h.get(t, "/api/v1/audit", h.token(t, "carol", identity.RoleAuditor))

	var body AuditListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body.ChainVerified {
		t.Error("chain_verified = true after the log was tampered with")
	}
	if body.ChainError == "" {
		t.Error("chain_error is empty; an analyst would not know what broke")
	}
}

func TestAuditRejectsInvalidPagination(t *testing.T) {
	h := newHarness(t)
	token := h.token(t, "carol", identity.RoleAuditor)

	for _, query := range []string{"?limit=0", "?limit=5000", "?limit=abc", "?after=-1"} {
		t.Run(query, func(t *testing.T) {
			if rec := h.get(t, "/api/v1/audit"+query, token); rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
		})
	}
}

// ── Development token endpoint ──────────────────────────────────────────────

func TestDevTokenEndpointMintsUsableTokens(t *testing.T) {
	h := newHarness(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dev/token",
		strings.NewReader(`{"subject":"alice","email":"alice@example.gov","roles":["ADMIN"]}`))
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var body DevTokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body.Issuer != identity.DevIssuer {
		t.Errorf("issuer = %q, want %q", body.Issuer, identity.DevIssuer)
	}

	// The minted token must actually work against an authenticated route.
	if rec := h.get(t, "/api/v1/audit", body.AccessToken); rec.Code != http.StatusOK {
		t.Errorf("minted token was rejected by the audit endpoint: %d", rec.Code)
	}
}

func TestDevTokenEndpointValidatesInput(t *testing.T) {
	h := newHarness(t)

	bodies := map[string]string{
		"missing subject": `{"email":"a@b.gov"}`,
		"not json":        `not json`,
		"unknown field":   `{"subject":"alice","is_admin":true}`,
	}
	for name, payload := range bodies {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/dev/token", strings.NewReader(payload))
			rec := httptest.NewRecorder()
			h.router.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestDevTokenRouteAbsentWhenNotConfigured(t *testing.T) {
	// The route is not mounted rather than guarded inside the handler: a route
	// that does not exist cannot be reached by a misconfigured deployment.
	router := NewRouter(Options{
		Config: &config.Config{Env: config.EnvProduction},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		DB:     stubPinger{},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dev/token",
		strings.NewReader(`{"subject":"attacker","roles":["ADMIN"]}`))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when development authentication is off", rec.Code)
	}
}

func TestAuthenticatedRoutesAbsentWithoutAVerifier(t *testing.T) {
	router := NewRouter(Options{
		Config: &config.Config{Env: config.EnvProduction},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		DB:     stubPinger{},
	})

	for _, path := range []string{"/api/v1/client/me", "/api/v1/audit"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404 rather than an unauthenticated handler", path, rec.Code)
		}
	}
}
