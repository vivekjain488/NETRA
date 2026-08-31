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

	"github.com/netra/backend/internal/config"
)

type stubPinger struct{ err error }

func (s stubPinger) Ping(context.Context) error { return s.err }

func testRouter(t *testing.T, db Pinger) http.Handler {
	t.Helper()
	return NewRouter(Options{
		Config: &config.Config{
			Env: config.EnvDevelopment,
			HTTP: config.HTTPConfig{
				AllowedOrigins: []string{"http://localhost:5173"},
			},
		},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		DB:     db,
	})
}

func do(t *testing.T, h http.Handler, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthLiveIsUpWithoutDatabase(t *testing.T) {
	// Liveness must not depend on the database, or an outage would cause
	// healthy backends to be restarted.
	rec := do(t, testRouter(t, stubPinger{err: errors.New("down")}), http.MethodGet, "/api/v1/health", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body HealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want ok", body.Status)
	}
	if body.Build.Version == "" {
		t.Error("build version is empty; health must report build info")
	}
}

func TestHealthReadyReflectsDatabase(t *testing.T) {
	tests := []struct {
		name       string
		pinger     Pinger
		wantCode   int
		wantStatus string
		wantCheck  string
	}{
		{"database up", stubPinger{}, http.StatusOK, "ok", "ok"},
		{"database down", stubPinger{err: errors.New("connection refused")}, http.StatusServiceUnavailable, "degraded", "unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(t, testRouter(t, tt.pinger), http.MethodGet, "/api/v1/health/ready", nil)

			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantCode)
			}
			var body HealthResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("response is not valid JSON: %v", err)
			}
			if body.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", body.Status, tt.wantStatus)
			}
			if body.Checks["database"] != tt.wantCheck {
				t.Errorf("checks[database] = %q, want %q", body.Checks["database"], tt.wantCheck)
			}
		})
	}
}

func TestReadyDoesNotLeakDatabaseError(t *testing.T) {
	// The DSN can appear in driver errors; it must never reach a client.
	secret := "postgres://netra:hunter2@db:5432/netra"
	rec := do(t, testRouter(t, stubPinger{err: errors.New(secret)}), http.MethodGet, "/api/v1/health/ready", nil)

	if got := rec.Body.String(); strings.Contains(got, "hunter2") {
		t.Errorf("response leaked credentials from the database error: %s", got)
	}
}

func TestEveryResponseCarriesRequestID(t *testing.T) {
	h := testRouter(t, stubPinger{})

	for _, path := range []string{"/api/v1/health", "/api/v1/does-not-exist"} {
		rec := do(t, h, http.MethodGet, path, nil)
		if rec.Header().Get(RequestIDHeader) == "" {
			t.Errorf("%s: missing %s header", path, RequestIDHeader)
		}
	}
}

func TestRequestIDIsNotTakenFromClient(t *testing.T) {
	// Trusting a client-supplied ID would let an attacker collide or poison
	// audit correlation.
	rec := do(t, testRouter(t, stubPinger{}), http.MethodGet, "/api/v1/health",
		map[string]string{RequestIDHeader: "attacker-chosen-id"})

	if got := rec.Header().Get(RequestIDHeader); got == "attacker-chosen-id" {
		t.Error("client-supplied request ID was echoed back; it must be server-generated")
	}
}

func TestNotFoundReturnsProblemJSON(t *testing.T) {
	rec := do(t, testRouter(t, stubPinger{}), http.MethodGet, "/api/v1/nope", nil)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if p.Status != http.StatusNotFound || p.RequestID == "" {
		t.Errorf("problem = %+v, want status 404 and a request_id", p)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	rec := do(t, testRouter(t, stubPinger{}), http.MethodDelete, "/api/v1/health", nil)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := do(t, testRouter(t, stubPinger{}), http.MethodGet, "/api/v1/health", nil)

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
}

func TestCORSAllowsOnlyConfiguredOrigins(t *testing.T) {
	h := testRouter(t, stubPinger{})

	allowed := do(t, h, http.MethodGet, "/api/v1/health",
		map[string]string{"Origin": "http://localhost:5173"})
	if got := allowed.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("allowed origin: Access-Control-Allow-Origin = %q, want the origin echoed", got)
	}

	denied := do(t, h, http.MethodGet, "/api/v1/health",
		map[string]string{"Origin": "https://evil.test"})
	if got := denied.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("unconfigured origin was allowed: Access-Control-Allow-Origin = %q", got)
	}
}

func TestRecovererHidesPanicDetail(t *testing.T) {
	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("secret internal detail")
	})
	h := RequestID(RequestLogger(slog.New(slog.NewJSONHandler(io.Discard, nil)))(Recoverer(panicking)))

	rec := do(t, h, http.MethodGet, "/boom", nil)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "secret internal detail") {
		t.Errorf("panic detail leaked to client: %s", rec.Body.String())
	}
}

