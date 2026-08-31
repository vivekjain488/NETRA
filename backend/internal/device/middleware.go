package device

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/netra/backend/internal/logging"
)

// MaxSignedBodyBytes bounds the body a device may submit. The whole body must
// be buffered to verify the signature, so an unbounded limit would be a memory
// exhaustion vector on an unauthenticated code path.
const MaxSignedBodyBytes = 4 << 20 // 4 MiB

type deviceKey struct{}

// FromContext returns the authenticated device, if any.
func FromContext(ctx context.Context) (*Device, bool) {
	d, ok := ctx.Value(deviceKey{}).(*Device)
	return d, ok && d != nil
}

// WithDevice returns a context carrying the authenticated device.
func WithDevice(ctx context.Context, d *Device) context.Context {
	return context.WithValue(ctx, deviceKey{}, d)
}

// BodyFromContext returns the buffered request body read during verification,
// so a handler does not have to read it a second time.
type bodyKey struct{}

func BodyFromContext(ctx context.Context) []byte {
	b, _ := ctx.Value(bodyKey{}).([]byte)
	return b
}

// Repository is the subset of the store the middleware needs.
type Repository interface {
	ByUID(ctx context.Context, deviceUID string) (*Device, error)
	ConsumeNonce(ctx context.Context, deviceID uuid.UUID, nonce string, seenAt time.Time) error
}

// ProblemWriter renders an error response, injected to avoid a dependency on
// the HTTP router package.
type ProblemWriter func(w http.ResponseWriter, r *http.Request, status int, title, detail string)

// AuthDeps are the collaborators the device middleware needs.
type AuthDeps struct {
	Devices      Repository
	Logger       *slog.Logger
	WriteProblem ProblemWriter
}

// RequireDeviceSignature authenticates an agent request by its device key.
//
// The checks are ordered cheapest-first so that a malformed request is
// rejected before any database work is done. Every failure returns the same
// generic 401: an agent-plane endpoint must not tell a caller which part of a
// forged request was wrong.
//
// Failures are logged rather than written to the audit log. A caller who knows
// a device identifier could otherwise grow the audit table at will; the log
// carries the same detail and is the right place for volume-based alerting.
func RequireDeviceSignature(deps AuthDeps) func(http.Handler) http.Handler {
	reject := func(w http.ResponseWriter, r *http.Request) {
		deps.WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized",
			"The request is not a valid signed device request.")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			logger := logging.FromContext(ctx)

			deviceUID := r.Header.Get(HeaderDeviceUID)
			nonce := r.Header.Get(HeaderNonce)
			signature := r.Header.Get(HeaderSignature)
			rawTimestamp := r.Header.Get(HeaderTimestamp)

			if deviceUID == "" || nonce == "" || signature == "" || rawTimestamp == "" {
				logger.Warn("device request is missing signature headers")
				reject(w, r)
				return
			}
			if err := ValidateNonce(nonce); err != nil {
				logger.Warn("device request nonce rejected", slog.String("error", err.Error()))
				reject(w, r)
				return
			}

			seconds, err := strconv.ParseInt(rawTimestamp, 10, 64)
			if err != nil {
				logger.Warn("device request timestamp is not a unix time")
				reject(w, r)
				return
			}
			timestamp := time.Unix(seconds, 0).UTC()
			if err := CheckClockSkew(timestamp, time.Now()); err != nil {
				// Clock skew is usually an operational fault, not an attack, so
				// it is logged distinctly to keep it diagnosable.
				logger.Warn("device request rejected for clock skew",
					slog.String(logging.KeyDeviceID, deviceUID),
					slog.String("error", err.Error()))
				reject(w, r)
				return
			}

			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxSignedBodyBytes))
			if err != nil {
				logger.Warn("device request body could not be read",
					slog.String("error", err.Error()))
				reject(w, r)
				return
			}

			enrolled, err := deps.Devices.ByUID(ctx, deviceUID)
			if err != nil {
				logger.Warn("device request from an unknown device",
					slog.String(logging.KeyDeviceID, deviceUID))
				reject(w, r)
				return
			}
			if enrolled.State != StateActive {
				// Revocation takes effect immediately: a revoked device holds a
				// key that still signs correctly, so state is what stops it.
				logger.Warn("device request from a device that is not active",
					slog.String(logging.KeyDeviceID, enrolled.ID.String()),
					slog.String("state", string(enrolled.State)))
				reject(w, r)
				return
			}

			input := SigningInput{
				Method:    r.Method,
				Path:      r.URL.Path,
				Timestamp: timestamp,
				Nonce:     nonce,
				Body:      body,
			}
			if err := VerifySignature(enrolled.PublicKey, input, signature); err != nil {
				logger.Warn("device request signature verification failed",
					slog.String(logging.KeyDeviceID, enrolled.ID.String()))
				reject(w, r)
				return
			}

			// The nonce is consumed last: a request that was never going to be
			// accepted must not be able to burn nonces on the device's behalf.
			if err := deps.Devices.ConsumeNonce(ctx, enrolled.ID, nonce, timestamp); err != nil {
				if errors.Is(err, ErrReplayedNonce) {
					logger.Warn("replayed device request rejected",
						slog.String(logging.KeyDeviceID, enrolled.ID.String()))
					reject(w, r)
					return
				}
				logger.Error("could not record request nonce",
					slog.String("error", err.Error()))
				deps.WriteProblem(w, r, http.StatusInternalServerError,
					"Internal Server Error", "The request could not be processed.")
				return
			}

			ctx = WithDevice(ctx, enrolled)
			ctx = context.WithValue(ctx, bodyKey{}, body)
			ctx = logging.WithContext(ctx, logger.With(
				slog.String(logging.KeyDeviceID, enrolled.ID.String())))

			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
