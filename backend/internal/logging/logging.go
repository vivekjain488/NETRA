// Package logging provides structured JSON logging for the NETRA backend.
//
// Spec §40 requires every request to carry a request_id and every security
// event, session and device to be identifiable in the logs. This package
// carries a logger on the request context so correlation identifiers are
// attached once at the edge and inherited by everything downstream.
package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

type contextKey struct{}

var loggerKey contextKey

// Attribute keys used across the backend. Investigation depends on these being
// spelled identically everywhere, so they are defined once.
const (
	KeyRequestID = "request_id"
	KeyEventID   = "event_id"
	KeySessionID = "session_id"
	KeyDeviceID  = "device_id"
	KeyUserID    = "user_id"
)

// New builds a logger for the given level and format ("json" or "text").
func New(w io.Writer, level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}

	var handler slog.Handler
	if strings.EqualFold(format, "text") {
		handler = slog.NewTextHandler(w, opts)
	} else {
		handler = slog.NewJSONHandler(w, opts)
	}
	return slog.New(handler)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// WithContext returns a context carrying the logger.
func WithContext(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// FromContext returns the logger carried by ctx, or the default logger.
// It never returns nil, so callers can log unconditionally.
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}
