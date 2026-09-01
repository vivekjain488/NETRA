package httpapi

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/netra/backend/internal/logging"
)

// RateLimit bounds how often one caller may hit a route group.
//
// It exists for two reasons that matter more than load shedding. Enrollment and
// token endpoints are guessable targets, and an unbounded one lets an attacker
// try as fast as the network allows. Telemetry ingest writes to the database on
// an authenticated but automated path, where a misbehaving agent can fill a
// table faster than an operator will notice.
type RateLimit struct {
	// Requests permitted per Window.
	Requests int
	Window   time.Duration
}

// bucket tracks one caller's usage within the current window.
type bucket struct {
	count   int
	resetAt time.Time
}

// limiter is a fixed-window counter keyed by caller.
//
// A fixed window can permit a burst of up to twice the limit across a boundary.
// That is an accepted trade: the purpose here is to make brute force and runaway
// clients impractical, not to shape traffic precisely, and a simpler limiter is
// one whose behaviour an operator can predict. A distributed limiter arrives
// with horizontal scaling; this one is per-instance and says so.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	limit   RateLimit
}

func newLimiter(limit RateLimit) *limiter {
	return &limiter{buckets: map[string]*bucket{}, limit: limit}
}

// allow reports whether the caller may proceed, and when their window resets.
func (l *limiter) allow(key string, now time.Time) (bool, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.buckets[key]
	if !ok || now.After(entry.resetAt) {
		entry = &bucket{resetAt: now.Add(l.limit.Window)}
		l.buckets[key] = entry
	}

	entry.count++
	return entry.count <= l.limit.Requests, entry.resetAt
}

// prune drops expired buckets so the map cannot grow without bound as callers
// come and go.
func (l *limiter) prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for key, entry := range l.buckets {
		if now.After(entry.resetAt) {
			delete(l.buckets, key)
		}
	}
}

// KeyFunc identifies the caller a limit applies to.
type KeyFunc func(*http.Request) string

// ByIP limits per source address. Forwarded headers are ignored: they are
// client-controlled, so keying on one would let an attacker reset their own
// limit at will.
func ByIP(r *http.Request) string { return clientIP(r) }

// ByDevice limits per claimed device identifier, for the agent plane. The claim
// is unverified at this point in the chain, which is the point: the limit has to
// apply before signature verification does any database work.
func ByDevice(r *http.Request) string {
	if uid := r.Header.Get("X-NETRA-Device"); uid != "" {
		return "device:" + uid
	}
	return "ip:" + clientIP(r)
}

// RateLimited returns middleware enforcing a limit.
func RateLimited(limit RateLimit, key KeyFunc) func(http.Handler) http.Handler {
	l := newLimiter(limit)

	// Housekeeping runs on a ticker rather than on every request, so a burst
	// does not pay for the cleanup of an idle period.
	go func() {
		ticker := time.NewTicker(limit.Window)
		defer ticker.Stop()
		for now := range ticker.C {
			l.prune(now)
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			now := time.Now()
			allowed, resetAt := l.allow(key(r), now)

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Requests))
			if !allowed {
				retryAfter := int(time.Until(resetAt).Seconds()) + 1
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))

				logging.FromContext(r.Context()).Warn("rate limit exceeded",
					"path", r.URL.Path, "retry_after_seconds", retryAfter)

				WriteProblem(w, r, http.StatusTooManyRequests, "Too Many Requests",
					"This client has made too many requests. Retry after the interval in the Retry-After header.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
