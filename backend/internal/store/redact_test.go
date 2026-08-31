package store

import (
	"errors"
	"strings"
	"testing"
)

func TestRedactRemovesPassword(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"postgres scheme", "failed to connect to postgres://netra:sup3rs3cret@db:5432/netra"},
		{"postgresql scheme", "bad dsn postgresql://netra:sup3rs3cret@localhost:5432/netra?sslmode=disable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redact(errors.New(tt.in)).Error()

			if strings.Contains(got, "sup3rs3cret") {
				t.Errorf("password survived redaction: %s", got)
			}
			if !strings.Contains(got, "REDACTED") {
				t.Errorf("redacted marker missing: %s", got)
			}
		})
	}
}

func TestRedactNilStaysNil(t *testing.T) {
	if redact(nil) != nil {
		t.Error("redact(nil) returned a non-nil error")
	}
}

func TestRedactKeepsUsefulContext(t *testing.T) {
	got := redact(errors.New("connect to postgres://netra:pw@db:5432/netra: connection refused")).Error()

	if !strings.Contains(got, "connection refused") {
		t.Errorf("redaction destroyed the diagnostic: %s", got)
	}
}
