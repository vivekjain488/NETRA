package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiterAllowsUpToTheLimit(t *testing.T) {
	l := newLimiter(RateLimit{Requests: 3, Window: time.Minute})
	now := time.Now()

	for i := 1; i <= 3; i++ {
		if allowed, _ := l.allow("caller", now); !allowed {
			t.Fatalf("request %d was refused within the limit", i)
		}
	}
	if allowed, _ := l.allow("caller", now); allowed {
		t.Error("a request beyond the limit was allowed")
	}
}

func TestLimiterIsPerCaller(t *testing.T) {
	// One noisy client must not exhaust everyone else's budget.
	l := newLimiter(RateLimit{Requests: 1, Window: time.Minute})
	now := time.Now()

	l.allow("first", now)
	if allowed, _ := l.allow("second", now); !allowed {
		t.Error("a second caller was refused because the first exhausted its limit")
	}
}

func TestLimiterResetsAfterTheWindow(t *testing.T) {
	l := newLimiter(RateLimit{Requests: 1, Window: time.Minute})
	now := time.Now()

	l.allow("caller", now)
	if allowed, _ := l.allow("caller", now.Add(2*time.Minute)); !allowed {
		t.Error("the window did not reset")
	}
}

func TestPruneBoundsMemory(t *testing.T) {
	// Callers come and go; without pruning the map grows for the life of the
	// process.
	l := newLimiter(RateLimit{Requests: 1, Window: time.Minute})
	now := time.Now()

	for i := 0; i < 100; i++ {
		l.allow(string(rune('a'+i%26))+string(rune('0'+i/26)), now)
	}
	l.prune(now.Add(2 * time.Minute))

	if len(l.buckets) != 0 {
		t.Errorf("%d buckets survived pruning", len(l.buckets))
	}
}

func TestRateLimitedRefusesWithRetryAfter(t *testing.T) {
	handler := RateLimited(RateLimit{Requests: 2, Window: time.Minute}, ByIP)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		req.RemoteAddr = "192.0.2.10:5555"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	send()
	send()
	refused := send()

	if refused.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", refused.Code)
	}
	if refused.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After header; a client cannot know when to try again")
	}
	if ct := refused.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want problem+json", ct)
	}
}

func TestByDeviceKeyPrefersTheDeviceHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/events", nil)
	req.RemoteAddr = "192.0.2.10:5555"
	req.Header.Set("X-NETRA-Device", "netra-abc")

	if got := ByDevice(req); got != "device:netra-abc" {
		t.Errorf("key = %q, want the device identifier", got)
	}
}

func TestByDeviceFallsBackToAddress(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/events", nil)
	req.RemoteAddr = "192.0.2.10:5555"

	if got := ByDevice(req); got != "ip:192.0.2.10" {
		t.Errorf("key = %q, want the peer address", got)
	}
}

func TestRateLimitKeysIgnoreForwardedHeaders(t *testing.T) {
	// Keying on a client-controlled header would let an attacker reset their
	// own limit by changing it.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.RemoteAddr = "192.0.2.10:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")

	if got := ByIP(req); got != "192.0.2.10" {
		t.Errorf("key = %q, want the peer address rather than the forwarded one", got)
	}
}
