// Package reqctx carries per-request correlation values.
//
// It exists so that the HTTP layer and the modules it invokes can share the
// request identifier without either importing the other — investigation
// depends on one identifier threading through logs, audit records and error
// responses alike (spec §40).
package reqctx

import "context"

type requestIDKey struct{}

// WithRequestID returns a context carrying the correlation identifier.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the correlation identifier, or "" if unset.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}
