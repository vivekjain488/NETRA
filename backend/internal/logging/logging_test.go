package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestNewEmitsJSON(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, "info", "json").Info("device enrolled", slog.String(KeyDeviceID, "dev-1"))

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("log line is not valid JSON: %v (line=%q)", err, buf.String())
	}
	if entry["msg"] != "device enrolled" {
		t.Errorf("msg = %v, want %q", entry["msg"], "device enrolled")
	}
	if entry[KeyDeviceID] != "dev-1" {
		t.Errorf("%s = %v, want dev-1", KeyDeviceID, entry[KeyDeviceID])
	}
}

func TestNewRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, "warn", "json").Info("should be filtered")

	if buf.Len() != 0 {
		t.Errorf("info line emitted at warn level: %q", buf.String())
	}
}

func TestFromContextRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, "info", "json")

	if got := FromContext(WithContext(context.Background(), l)); got != l {
		t.Error("FromContext did not return the logger stored by WithContext")
	}
}

func TestFromContextNeverReturnsNil(t *testing.T) {
	if FromContext(context.Background()) == nil {
		t.Fatal("FromContext returned nil for a bare context; callers would panic")
	}
}
