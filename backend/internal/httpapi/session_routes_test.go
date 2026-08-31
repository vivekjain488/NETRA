package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/netra/backend/internal/audit"
	"github.com/netra/backend/internal/config"
	"github.com/netra/backend/internal/identity"
	"github.com/netra/backend/internal/session"
)

// fakeSessions records what the handler asked for and returns a programmed
// outcome. Attestation cryptography itself is covered in the session package;
// this double exists to test wiring, authorization and audit behaviour.
type fakeSessions struct {
	beginErr    error
	endErr      error
	lastBegin   session.BeginRequest
	established map[uuid.UUID]*session.Session
	ownerOf     map[uuid.UUID]uuid.UUID
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{
		established: map[uuid.UUID]*session.Session{},
		ownerOf:     map[uuid.UUID]uuid.UUID{},
	}
}

func (f *fakeSessions) IssueNonce(_ context.Context, _ uuid.UUID) (string, time.Time, error) {
	nonce, err := session.GenerateNonce()
	return nonce, time.Now().Add(session.NonceTTL), err
}

func (f *fakeSessions) Begin(_ context.Context, req session.BeginRequest) (*session.Session, error) {
	f.lastBegin = req
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	created := &session.Session{
		ID: uuid.New(), UserID: req.UserID, DeviceID: uuid.New(),
		Status: session.StatusActive, AuthMethod: "oidc",
		Attestation: session.AttestationDeviceSignature,
		DeviceUID:   req.DeviceUID, StartedAt: time.Now().UTC(), LastSeenAt: time.Now().UTC(),
	}
	f.established[created.ID] = created
	f.ownerOf[created.ID] = req.UserID
	return created, nil
}

func (f *fakeSessions) End(_ context.Context, sessionID, userID uuid.UUID) error {
	if f.endErr != nil {
		return f.endErr
	}
	// Mirrors the store's predicate: a session belonging to another user is
	// indistinguishable from one that does not exist.
	if owner, ok := f.ownerOf[sessionID]; !ok || owner != userID {
		return pgx.ErrNoRows
	}
	delete(f.ownerOf, sessionID)
	return nil
}

func (f *fakeSessions) List(_ context.Context, activeOnly bool, limit int) ([]session.Session, error) {
	out := make([]session.Session, 0, len(f.established))
	for _, s := range f.established {
		if activeOnly && s.Status == session.StatusEnded {
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, *s)
	}
	return out, nil
}

func (f *fakeSessions) ByID(_ context.Context, id uuid.UUID) (*session.Session, error) {
	s, ok := f.established[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return s, nil
}

type sessionHarness struct {
	*harness
	sessions *fakeSessions
}

func newSessionHarness(t *testing.T) *sessionHarness {
	t.Helper()

	dev, err := identity.NewDevVerifier("development", time.Hour)
	if err != nil {
		t.Fatalf("NewDevVerifier: %v", err)
	}
	users := newFakeUsers()
	recorder := &fakeAudit{}
	sessions := newFakeSessions()

	router := NewRouter(Options{
		Config:      &config.Config{Env: config.EnvDevelopment},
		Logger:      slog.New(slog.NewJSONHandler(io.Discard, nil)),
		DB:          stubPinger{},
		Verifier:    dev,
		Users:       users,
		Audit:       recorder,
		AuditReader: recorder,
		DevVerifier: dev,
		Sessions:    sessions,
	})
	return &sessionHarness{
		harness:  &harness{router: router, dev: dev, users: users, audit: recorder},
		sessions: sessions,
	}
}

func (h *sessionHarness) post(t *testing.T, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

// ── Nonce issuance ──────────────────────────────────────────────────────────

func TestSessionNonceRequiresAuthentication(t *testing.T) {
	h := newSessionHarness(t)

	if rec := h.post(t, "/api/v1/client/session/nonce", "", `{}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestSessionNonceReturnsTheExactMessageToSign(t *testing.T) {
	// Returning the message rather than letting the client assemble it means a
	// client bug cannot silently sign the wrong bytes.
	h := newSessionHarness(t)

	rec := h.post(t, "/api/v1/client/session/nonce", h.token(t, "alice"), `{}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
	var body NonceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Message != session.AttestationString(body.Nonce, "alice") {
		t.Errorf("message = %q, want the canonical attestation string", body.Message)
	}
	if err := session.ValidateNonceFormat(body.Nonce); err != nil {
		t.Errorf("issued nonce is malformed: %v", err)
	}
	if !body.ExpiresAt.After(time.Now()) {
		t.Error("issued nonce is already expired")
	}
}

func TestSessionNoncesAreUnique(t *testing.T) {
	h := newSessionHarness(t)
	token := h.token(t, "alice")

	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		var body NonceResponse
		rec := h.post(t, "/api/v1/client/session/nonce", token, `{}`)
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if seen[body.Nonce] {
			t.Fatal("the same attestation nonce was issued twice")
		}
		seen[body.Nonce] = true
	}
}

// ── Session establishment ───────────────────────────────────────────────────

func beginBody(deviceUID, nonce, signature string) string {
	return `{"device_uid":"` + deviceUID + `","nonce":"` + nonce + `","signature":"` + signature + `"}`
}

func TestBeginSessionRequiresAuthentication(t *testing.T) {
	h := newSessionHarness(t)

	rec := h.post(t, "/api/v1/client/session/begin", "", beginBody("netra-abc", "n", "s"))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestBeginSessionBindsUserAndDevice(t *testing.T) {
	h := newSessionHarness(t)
	nonce, _ := session.GenerateNonce()

	rec := h.post(t, "/api/v1/client/session/begin", h.token(t, "alice"),
		beginBody("netra-abcdef0123456789", nonce, "c2lnbmF0dXJl"))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
	var body SessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Attestation != string(session.AttestationDeviceSignature) {
		t.Errorf("attestation = %q, want device-signature", body.Attestation)
	}
	if body.Status != string(session.StatusActive) {
		t.Errorf("status = %q, want ACTIVE", body.Status)
	}

	// The subject must reach the store, or the attestation could not be bound
	// to this particular user.
	if h.sessions.lastBegin.Subject != "alice" {
		t.Errorf("subject passed to the store = %q, want alice", h.sessions.lastBegin.Subject)
	}
	if h.sessions.lastBegin.UserID == uuid.Nil {
		t.Error("the authenticated user was not passed to the store")
	}
}

func TestBeginSessionIsAudited(t *testing.T) {
	h := newSessionHarness(t)
	nonce, _ := session.GenerateNonce()

	h.post(t, "/api/v1/client/session/begin", h.token(t, "alice"),
		beginBody("netra-abcdef0123456789", nonce, "c2ln"))

	found := false
	for _, record := range h.audit.records {
		if record.Action == audit.ActionSessionBegin && record.Result == audit.ResultSuccess {
			found = true
			if record.Detail["attestation"] != string(session.AttestationDeviceSignature) {
				t.Errorf("audit detail = %v, want the attestation method recorded", record.Detail)
			}
		}
	}
	if !found {
		t.Error("session establishment was not audited")
	}
}

func TestBeginSessionFailuresAreAuditedAndMapped(t *testing.T) {
	// A valid user token with a failed device proof is a strong signal: the
	// person is real but the device is not vouched for.
	nonce, _ := session.GenerateNonce()

	tests := map[string]struct {
		err      error
		wantCode int
	}{
		"bad attestation": {session.ErrAttestation, http.StatusUnauthorized},
		"unusable device": {session.ErrDeviceUnusable, http.StatusForbidden},
		"spent nonce":     {session.ErrNonce, http.StatusBadRequest},
		"malformed":       {session.ErrValidation, http.StatusBadRequest},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h := newSessionHarness(t)
			h.sessions.beginErr = tt.err

			rec := h.post(t, "/api/v1/client/session/begin", h.token(t, "alice"),
				beginBody("netra-abcdef0123456789", nonce, "c2ln"))

			if rec.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantCode)
			}
			denied := false
			for _, record := range h.audit.records {
				if record.Action == audit.ActionSessionBegin && record.Result == audit.ResultDenied {
					denied = true
				}
			}
			if !denied {
				t.Error("a failed attestation was not audited")
			}
		})
	}
}

func TestBeginSessionRejectsUnknownFields(t *testing.T) {
	h := newSessionHarness(t)
	nonce, _ := session.GenerateNonce()

	rec := h.post(t, "/api/v1/client/session/begin", h.token(t, "alice"),
		`{"device_uid":"netra-abcdef0123456789","nonce":"`+nonce+`","signature":"c2ln","risk_score":0}`)

	// Silently ignoring a field named risk_score would be exactly the kind of
	// client-supplied value the backend must never accept.
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ── Ending sessions ─────────────────────────────────────────────────────────

func TestEndSessionClosesTheCallersOwnSession(t *testing.T) {
	h := newSessionHarness(t)
	token := h.token(t, "alice")
	nonce, _ := session.GenerateNonce()

	rec := h.post(t, "/api/v1/client/session/begin", token,
		beginBody("netra-abcdef0123456789", nonce, "c2ln"))
	var created SessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if rec := h.post(t, "/api/v1/client/session/end", token,
		`{"session_id":"`+created.ID+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}

func TestEndSessionCannotCloseAnotherUsersSession(t *testing.T) {
	h := newSessionHarness(t)
	nonce, _ := session.GenerateNonce()

	rec := h.post(t, "/api/v1/client/session/begin", h.token(t, "alice"),
		beginBody("netra-abcdef0123456789", nonce, "c2ln"))
	var created SessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Mallory guesses a session identifier. It must be indistinguishable from
	// one that does not exist.
	got := h.post(t, "/api/v1/client/session/end", h.token(t, "mallory"),
		`{"session_id":"`+created.ID+`"}`)

	if got.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", got.Code)
	}
}

func TestEndSessionRejectsAMalformedIdentifier(t *testing.T) {
	h := newSessionHarness(t)

	rec := h.post(t, "/api/v1/client/session/end", h.token(t, "alice"), `{"session_id":"not-a-uuid"}`)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ── SOC plane ───────────────────────────────────────────────────────────────

func TestSessionListRequiresAPrivilegedRole(t *testing.T) {
	h := newSessionHarness(t)

	if rec := h.get(t, "/api/v1/sessions", h.token(t, "alice", identity.RoleUser)); rec.Code != http.StatusForbidden {
		t.Errorf("ordinary user status = %d, want 403", rec.Code)
	}
	if rec := h.get(t, "/api/v1/sessions", h.token(t, "ravi", identity.RoleAnalyst)); rec.Code != http.StatusOK {
		t.Errorf("analyst status = %d, want 200", rec.Code)
	}
}

func TestGetSessionReportsMissingSessions(t *testing.T) {
	h := newSessionHarness(t)

	rec := h.get(t, "/api/v1/sessions/"+uuid.NewString(), h.token(t, "ravi", identity.RoleAnalyst))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestSessionRoutesAbsentWithoutASessionService(t *testing.T) {
	router := NewRouter(Options{
		Config: &config.Config{Env: config.EnvProduction},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		DB:     stubPinger{},
	})

	for _, path := range []string{"/api/v1/client/session/begin", "/api/v1/sessions"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, rec.Code)
		}
	}
}

func TestErrorsAreDistinctSentinels(t *testing.T) {
	// The handler maps each failure to a different status, so they must not
	// collapse into one another.
	for _, pair := range [][2]error{
		{session.ErrNonce, session.ErrAttestation},
		{session.ErrAttestation, session.ErrDeviceUnusable},
		{session.ErrNonce, session.ErrDeviceUnusable},
	} {
		if errors.Is(pair[0], pair[1]) {
			t.Errorf("%v and %v are not distinguishable", pair[0], pair[1])
		}
	}
}
