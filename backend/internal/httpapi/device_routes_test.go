package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netra/backend/internal/audit"
	"github.com/netra/backend/internal/config"
	"github.com/netra/backend/internal/device"
	"github.com/netra/backend/internal/identity"
)

// fakeDevices is an in-memory DeviceService that preserves the security
// properties the real store enforces in SQL: single-use enrollment tokens,
// unique device identifiers, and nonce uniqueness per device.
type fakeDevices struct {
	mu       sync.Mutex
	tokens   map[string]*fakeToken
	byUID    map[string]*device.Device
	byID     map[uuid.UUID]*device.Device
	nonces   map[string]bool
	failNext error
}

type fakeToken struct {
	id        uuid.UUID
	expiresAt time.Time
	used      bool
}

func newFakeDevices() *fakeDevices {
	return &fakeDevices{
		tokens: map[string]*fakeToken{},
		byUID:  map[string]*device.Device{},
		byID:   map[uuid.UUID]*device.Device{},
		nonces: map[string]bool{},
	}
}

func (f *fakeDevices) IssueEnrollmentToken(_ context.Context, _ *uuid.UUID, _ string, ttl time.Duration) (string, uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", uuid.Nil, err
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw)
	id := uuid.New()
	f.tokens[hashToken(plaintext)] = &fakeToken{id: id, expiresAt: time.Now().Add(ttl)}
	return plaintext, id, nil
}

func (f *fakeDevices) Enroll(_ context.Context, token string, req device.EnrollRequest) (*device.Device, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	stored, ok := f.tokens[hashToken(token)]
	if !ok || stored.used || time.Now().After(stored.expiresAt) {
		return nil, device.ErrEnrollmentToken
	}
	if _, exists := f.byUID[req.DeviceUID]; exists {
		return nil, device.ErrDeviceExists
	}

	now := time.Now().UTC()
	created := &device.Device{
		ID: uuid.New(), DeviceUID: req.DeviceUID, Hostname: req.Hostname,
		OSName: req.OSName, OSVersion: req.OSVersion, AgentVersion: req.AgentVersion,
		PublicKey: req.PublicKey, KeyAlgorithm: "ed25519", KeyProtection: req.KeyProtection,
		State: device.StateActive, EnrolledAt: &now, CreatedAt: now,
	}
	stored.used = true
	f.byUID[created.DeviceUID] = created
	f.byID[created.ID] = created
	return created, nil
}

func (f *fakeDevices) ByUID(_ context.Context, uid string) (*device.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.byUID[uid]
	if !ok {
		return nil, device.ErrDeviceNotFound
	}
	return d, nil
}

func (f *fakeDevices) ByID(_ context.Context, id uuid.UUID) (*device.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.byID[id]
	if !ok {
		return nil, device.ErrDeviceNotFound
	}
	return d, nil
}

func (f *fakeDevices) List(_ context.Context, limit int) ([]device.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]device.Device, 0, len(f.byID))
	for _, d := range f.byID {
		if len(out) >= limit {
			break
		}
		out = append(out, *d)
	}
	return out, nil
}

func (f *fakeDevices) Heartbeat(_ context.Context, id uuid.UUID, agentVersion string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}
	d, ok := f.byID[id]
	if !ok || d.State != device.StateActive {
		return device.ErrDeviceNotActive
	}
	now := time.Now().UTC()
	d.LastHeartbeatAt = &now
	if agentVersion != "" {
		d.AgentVersion = agentVersion
	}
	return nil
}

func (f *fakeDevices) Revoke(_ context.Context, id uuid.UUID, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.byID[id]
	if !ok || d.State == device.StateRevoked {
		return device.ErrDeviceNotFound
	}
	now := time.Now().UTC()
	d.State = device.StateRevoked
	d.RevokedAt = &now
	d.RevokedReason = reason
	return nil
}

func (f *fakeDevices) ConsumeNonce(_ context.Context, deviceID uuid.UUID, nonce string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := deviceID.String() + ":" + nonce
	if f.nonces[key] {
		return device.ErrReplayedNonce
	}
	f.nonces[key] = true
	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ── Harness ─────────────────────────────────────────────────────────────────

type deviceHarness struct {
	*harness
	devices *fakeDevices
}

func newDeviceHarness(t *testing.T) *deviceHarness {
	t.Helper()

	dev, err := identity.NewDevVerifier("development", time.Hour)
	if err != nil {
		t.Fatalf("NewDevVerifier: %v", err)
	}
	users := newFakeUsers()
	recorder := &fakeAudit{}
	devices := newFakeDevices()

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
		Devices:     devices,
	})
	return &deviceHarness{
		harness: &harness{router: router, dev: dev, users: users, audit: recorder},
		devices: devices,
	}
}

func (h *deviceHarness) post(t *testing.T, path, token, body string) *httptest.ResponseRecorder {
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

// issueToken obtains an enrollment token as an administrator would.
func (h *deviceHarness) issueToken(t *testing.T) string {
	t.Helper()
	rec := h.post(t, "/api/v1/enrollment-tokens",
		h.token(t, "priya", identity.RoleAdmin), `{"label":"test","ttl_minutes":60}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue token: status %d (%s)", rec.Code, rec.Body.String())
	}
	var body EnrollmentTokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return body.Token
}

// enrolledAgent is a device that has completed enrollment and can sign.
type enrolledAgent struct {
	uid        string
	privateKey ed25519.PrivateKey
	response   DeviceResponse
}

func (h *deviceHarness) enroll(t *testing.T, uid string) *enrolledAgent {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	payload := fmt.Sprintf(`{
		"enrollment_token": %q, "device_uid": %q, "hostname": "GOV-LAPTOP-01",
		"os_name": "windows", "os_version": "11", "agent_version": "0.1.0",
		"public_key": %q, "key_protection": "software"}`,
		h.issueToken(t), uid, base64.StdEncoding.EncodeToString(pub))

	rec := h.post(t, "/api/v1/agent/enroll", "", payload)
	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll: status %d (%s)", rec.Code, rec.Body.String())
	}
	var response DeviceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode enroll response: %v", err)
	}
	return &enrolledAgent{uid: uid, privateKey: priv, response: response}
}

// signedRequest builds a device-signed request the way the agent does.
func (a *enrolledAgent) signedRequest(t *testing.T, method, path, body string, opts ...func(*device.SigningInput)) *http.Request {
	t.Helper()

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	in := device.SigningInput{
		Method:    method,
		Path:      path,
		Timestamp: time.Now().UTC(),
		Nonce:     hex.EncodeToString(nonce),
		Body:      []byte(body),
	}
	for _, opt := range opts {
		opt(&in)
	}

	req := httptest.NewRequest(method, path, strings.NewReader(string(in.Body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(device.HeaderDeviceUID, a.uid)
	req.Header.Set(device.HeaderNonce, in.Nonce)
	req.Header.Set(device.HeaderTimestamp, strconv.FormatInt(in.Timestamp.Unix(), 10))
	req.Header.Set(device.HeaderSignature, device.Sign(a.privateKey, in))
	return req
}

func (h *deviceHarness) send(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

// ── Enrollment ──────────────────────────────────────────────────────────────

func TestEnrollmentTokenRequiresAdmin(t *testing.T) {
	h := newDeviceHarness(t)

	for _, role := range []identity.Role{identity.RoleUser, identity.RoleAnalyst, identity.RoleAuditor} {
		t.Run(string(role), func(t *testing.T) {
			rec := h.post(t, "/api/v1/enrollment-tokens", h.token(t, "x", role), `{}`)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403 for %s", rec.Code, role)
			}
		})
	}
}

func TestEnrollmentTokenIsReturnedOnceAndNotAudited(t *testing.T) {
	h := newDeviceHarness(t)

	token := h.issueToken(t)
	if len(token) < 32 {
		t.Errorf("token = %q, want a long random value", token)
	}

	// An audit reader must not be able to enrol a device from the log.
	for _, record := range h.audit.records {
		body, _ := json.Marshal(record.Detail)
		if strings.Contains(string(body), token) {
			t.Fatal("the enrollment token was written to the audit log")
		}
	}
}

func TestEnrollSucceedsWithAValidToken(t *testing.T) {
	h := newDeviceHarness(t)

	agent := h.enroll(t, "device-uid-000001")

	if agent.response.State != string(device.StateActive) {
		t.Errorf("state = %q, want ACTIVE", agent.response.State)
	}
	if agent.response.EnrolledAt == nil {
		t.Error("enrolled_at is not set")
	}
}

func TestEnrollResponseNeverContainsAPrivateKey(t *testing.T) {
	h := newDeviceHarness(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	rec := h.post(t, "/api/v1/agent/enroll", "", fmt.Sprintf(`{
		"enrollment_token": %q, "device_uid": "device-uid-000009", "hostname": "h",
		"os_name": "windows", "os_version": "11", "agent_version": "0.1.0",
		"public_key": %q, "key_protection": "software"}`,
		h.issueToken(t), base64.StdEncoding.EncodeToString(pub)))

	if strings.Contains(rec.Body.String(), "private") {
		t.Errorf("enrollment response mentions a private key: %s", rec.Body.String())
	}
}

func TestEnrollRejectsAnInvalidToken(t *testing.T) {
	h := newDeviceHarness(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	rec := h.post(t, "/api/v1/agent/enroll", "", fmt.Sprintf(`{
		"enrollment_token": "not-a-real-token", "device_uid": "device-uid-000002",
		"hostname": "h", "os_name": "windows", "os_version": "11",
		"agent_version": "0.1.0", "public_key": %q, "key_protection": "software"}`,
		base64.StdEncoding.EncodeToString(pub)))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	// A guessing attempt is exactly what a SOC needs to see.
	found := false
	for _, record := range h.audit.records {
		if record.Action == audit.ActionDeviceEnroll && record.Result == audit.ResultDenied {
			found = true
		}
	}
	if !found {
		t.Error("a failed enrollment attempt was not audited")
	}
}

func TestEnrollmentTokenIsSingleUse(t *testing.T) {
	h := newDeviceHarness(t)
	token := h.issueToken(t)

	enrollWith := func(uid string) int {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		return h.post(t, "/api/v1/agent/enroll", "", fmt.Sprintf(`{
			"enrollment_token": %q, "device_uid": %q, "hostname": "h",
			"os_name": "windows", "os_version": "11", "agent_version": "0.1.0",
			"public_key": %q, "key_protection": "software"}`,
			token, uid, base64.StdEncoding.EncodeToString(pub))).Code
	}

	if got := enrollWith("device-uid-000003"); got != http.StatusCreated {
		t.Fatalf("first enrollment status = %d, want 201", got)
	}
	if got := enrollWith("device-uid-000004"); got != http.StatusUnauthorized {
		t.Errorf("second enrollment with the same token status = %d, want 401", got)
	}
}

func TestEnrollRejectsADuplicateDeviceIdentifier(t *testing.T) {
	// A duplicate means someone is trying to take over an existing record: a
	// genuine reinstall generates a new identifier and a new key pair.
	h := newDeviceHarness(t)
	h.enroll(t, "device-uid-000005")

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	rec := h.post(t, "/api/v1/agent/enroll", "", fmt.Sprintf(`{
		"enrollment_token": %q, "device_uid": "device-uid-000005", "hostname": "h",
		"os_name": "windows", "os_version": "11", "agent_version": "0.1.0",
		"public_key": %q, "key_protection": "software"}`,
		h.issueToken(t), base64.StdEncoding.EncodeToString(pub)))

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestEnrollValidatesItsInput(t *testing.T) {
	h := newDeviceHarness(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	valid := base64.StdEncoding.EncodeToString(pub)

	cases := map[string]string{
		"short device_uid":       fmt.Sprintf(`{"enrollment_token":"t","device_uid":"x","hostname":"h","os_name":"w","os_version":"11","agent_version":"0.1.0","public_key":%q,"key_protection":"software"}`, valid),
		"missing hostname":       fmt.Sprintf(`{"enrollment_token":"t","device_uid":"device-uid-000006","hostname":"","os_name":"w","os_version":"11","agent_version":"0.1.0","public_key":%q,"key_protection":"software"}`, valid),
		"public key not base64":  `{"enrollment_token":"t","device_uid":"device-uid-000006","hostname":"h","os_name":"w","os_version":"11","agent_version":"0.1.0","public_key":"!!!","key_protection":"software"}`,
		"public key wrong size":  `{"enrollment_token":"t","device_uid":"device-uid-000006","hostname":"h","os_name":"w","os_version":"11","agent_version":"0.1.0","public_key":"c2hvcnQ=","key_protection":"software"}`,
		"unknown key protection": fmt.Sprintf(`{"enrollment_token":"t","device_uid":"device-uid-000006","hostname":"h","os_name":"w","os_version":"11","agent_version":"0.1.0","public_key":%q,"key_protection":"magic"}`, valid),
		"unknown field":          fmt.Sprintf(`{"enrollment_token":"t","device_uid":"device-uid-000006","hostname":"h","os_name":"w","os_version":"11","agent_version":"0.1.0","public_key":%q,"key_protection":"software","is_trusted":true}`, valid),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if rec := h.post(t, "/api/v1/agent/enroll", "", payload); rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// ── Device-signed requests ──────────────────────────────────────────────────

func TestHeartbeatAcceptsAValidSignature(t *testing.T) {
	h := newDeviceHarness(t)
	agent := h.enroll(t, "device-uid-000010")

	rec := h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/heartbeat",
		`{"agent_version":"0.1.0","queued_events":3,"dropped_events":0}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var body HeartbeatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.HeartbeatInterval <= 0 {
		t.Error("heartbeat interval is not set; the agent would have no cadence")
	}
}

func TestHeartbeatRejectsAnUnsignedRequest(t *testing.T) {
	h := newDeviceHarness(t)
	h.enroll(t, "device-uid-000011")

	rec := h.post(t, "/api/v1/agent/heartbeat", "", `{"agent_version":"0.1.0"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestHeartbeatRejectsATamperedBody(t *testing.T) {
	// The signature covers a digest of the body, so any edit in transit fails.
	h := newDeviceHarness(t)
	agent := h.enroll(t, "device-uid-000012")

	req := agent.signedRequest(t, http.MethodPost, "/api/v1/agent/heartbeat", `{"queued_events":1}`)
	req.Body = io.NopCloser(strings.NewReader(`{"queued_events":9999}`))

	if rec := h.send(req); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a tampered body", rec.Code)
	}
}

func TestHeartbeatRejectsAReplayedRequest(t *testing.T) {
	h := newDeviceHarness(t)
	agent := h.enroll(t, "device-uid-000013")
	req := agent.signedRequest(t, http.MethodPost, "/api/v1/agent/heartbeat", `{"agent_version":"0.1.0"}`)

	body, _ := io.ReadAll(req.Body)
	replay := func() int {
		clone := httptest.NewRequest(req.Method, req.URL.Path, strings.NewReader(string(body)))
		clone.Header = req.Header.Clone()
		return h.send(clone).Code
	}

	if got := replay(); got != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", got)
	}
	if got := replay(); got != http.StatusUnauthorized {
		t.Errorf("replayed request status = %d, want 401", got)
	}
}

func TestHeartbeatRejectsAStaleTimestamp(t *testing.T) {
	h := newDeviceHarness(t)
	agent := h.enroll(t, "device-uid-000014")

	stale := func(in *device.SigningInput) { in.Timestamp = time.Now().Add(-time.Hour) }
	future := func(in *device.SigningInput) { in.Timestamp = time.Now().Add(time.Hour) }

	for name, opt := range map[string]func(*device.SigningInput){"stale": stale, "future": future} {
		t.Run(name, func(t *testing.T) {
			req := agent.signedRequest(t, http.MethodPost, "/api/v1/agent/heartbeat", `{}`, opt)
			if rec := h.send(req); rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
		})
	}
}

func TestHeartbeatRejectsAnotherDevicesKey(t *testing.T) {
	h := newDeviceHarness(t)
	victim := h.enroll(t, "device-uid-000015")
	attacker := h.enroll(t, "device-uid-000016")

	// Sign with the attacker's key but claim the victim's identity.
	req := attacker.signedRequest(t, http.MethodPost, "/api/v1/agent/heartbeat", `{}`)
	req.Header.Set(device.HeaderDeviceUID, victim.uid)

	if rec := h.send(req); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestHeartbeatRejectsAnUnknownDevice(t *testing.T) {
	h := newDeviceHarness(t)
	agent := h.enroll(t, "device-uid-000017")

	req := agent.signedRequest(t, http.MethodPost, "/api/v1/agent/heartbeat", `{}`)
	req.Header.Set(device.HeaderDeviceUID, "device-uid-999999")

	if rec := h.send(req); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestSignatureFromOneEndpointDoesNotWorkOnAnother(t *testing.T) {
	// The path is part of the signed material, so a captured signature cannot
	// be moved to a different, possibly more sensitive, endpoint.
	h := newDeviceHarness(t)
	agent := h.enroll(t, "device-uid-000018")

	req := agent.signedRequest(t, http.MethodPost, "/api/v1/agent/enroll", `{}`)
	moved := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", strings.NewReader(`{}`))
	moved.Header = req.Header.Clone()

	if rec := h.send(moved); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// ── Revocation ──────────────────────────────────────────────────────────────

func TestRevocationTakesEffectImmediately(t *testing.T) {
	// A revoked device still holds a key that signs correctly; state is what
	// stops it, and it must stop it on the very next request.
	h := newDeviceHarness(t)
	agent := h.enroll(t, "device-uid-000020")

	if rec := h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/heartbeat", `{}`)); rec.Code != http.StatusOK {
		t.Fatalf("pre-revocation heartbeat status = %d, want 200", rec.Code)
	}

	rec := h.post(t, "/api/v1/devices/"+agent.response.ID+"/revoke",
		h.token(t, "priya", identity.RoleAdmin), `{"reason":"suspected compromise"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}

	if rec := h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/heartbeat", `{}`)); rec.Code != http.StatusUnauthorized {
		t.Errorf("post-revocation heartbeat status = %d, want 401", rec.Code)
	}
}

func TestRevocationRequiresAdminAndIsAudited(t *testing.T) {
	h := newDeviceHarness(t)
	agent := h.enroll(t, "device-uid-000021")

	if rec := h.post(t, "/api/v1/devices/"+agent.response.ID+"/revoke",
		h.token(t, "ravi", identity.RoleAnalyst), `{"reason":"x"}`); rec.Code != http.StatusForbidden {
		t.Errorf("analyst revocation status = %d, want 403", rec.Code)
	}

	h.post(t, "/api/v1/devices/"+agent.response.ID+"/revoke",
		h.token(t, "priya", identity.RoleAdmin), `{"reason":"suspected compromise"}`)

	found := false
	for _, record := range h.audit.records {
		if record.Action == audit.ActionDeviceRevoke && record.TargetID == agent.response.ID {
			found = true
		}
	}
	if !found {
		t.Error("device revocation was not audited")
	}
}

// ── SOC plane ───────────────────────────────────────────────────────────────

func TestDeviceListRequiresAPrivilegedRole(t *testing.T) {
	h := newDeviceHarness(t)
	h.enroll(t, "device-uid-000030")

	if rec := h.get(t, "/api/v1/devices", h.token(t, "alice", identity.RoleUser)); rec.Code != http.StatusForbidden {
		t.Errorf("ordinary user status = %d, want 403", rec.Code)
	}
	if rec := h.get(t, "/api/v1/devices", h.token(t, "ravi", identity.RoleAnalyst)); rec.Code != http.StatusOK {
		t.Errorf("analyst status = %d, want 200", rec.Code)
	}
}

func TestDeviceListDoesNotExposePublicKeys(t *testing.T) {
	h := newDeviceHarness(t)
	h.enroll(t, "device-uid-000031")

	rec := h.get(t, "/api/v1/devices", h.token(t, "ravi", identity.RoleAnalyst))

	if strings.Contains(rec.Body.String(), "public_key") {
		t.Errorf("device listing exposes public keys: %s", rec.Body.String())
	}
}

func TestGetDeviceRejectsAMalformedIdentifier(t *testing.T) {
	h := newDeviceHarness(t)

	rec := h.get(t, "/api/v1/devices/not-a-uuid", h.token(t, "ravi", identity.RoleAnalyst))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAgentRoutesAbsentWithoutADeviceService(t *testing.T) {
	router := NewRouter(Options{
		Config: &config.Config{Env: config.EnvProduction},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		DB:     stubPinger{},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}
