// Package telemetry ingests, normalizes and stores endpoint security events.
//
// Two rules shape everything here. First, endpoint-supplied time is untrusted:
// `occurred_at` is what the endpoint claims, and `received_at` is what the
// server observed. Second, an event is attributed to the device that signed
// the request carrying it, never to a device named in the payload.
package telemetry

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Type is a security event type. It is a string rather than a database enum so
// new types can be added without a blocking migration (spec §14).
type Type string

// The event types the platform understands.
const (
	TypeAuthLogin         Type = "AUTH_LOGIN"
	TypeAuthLogout        Type = "AUTH_LOGOUT"
	TypeDeviceEnrollment  Type = "DEVICE_ENROLLMENT"
	TypeDevicePosture     Type = "DEVICE_POSTURE"
	TypeApplicationStart  Type = "APPLICATION_START"
	TypeApplicationAccess Type = "APPLICATION_ACCESS"
	TypeResourceAccess    Type = "RESOURCE_ACCESS"
	TypePrivilegeChange   Type = "PRIVILEGE_CHANGE"
	TypeNetworkEvent      Type = "NETWORK_EVENT"
	TypeSecurityEvent     Type = "SECURITY_EVENT"
	TypePolicyDecision    Type = "POLICY_DECISION"
	TypeRiskUpdate        Type = "RISK_UPDATE"
	TypeSecurityAlert     Type = "SECURITY_ALERT"
)

// knownTypes is the ingest allowlist. It matches the CHECK constraint on the
// events table; an unknown type is rejected at the edge with a clear reason
// rather than failing later as a constraint violation.
var knownTypes = map[Type]bool{
	TypeAuthLogin: true, TypeAuthLogout: true, TypeDeviceEnrollment: true,
	TypeDevicePosture: true, TypeApplicationStart: true, TypeApplicationAccess: true,
	TypeResourceAccess: true, TypePrivilegeChange: true, TypeNetworkEvent: true,
	TypeSecurityEvent: true, TypePolicyDecision: true, TypeRiskUpdate: true,
	TypeSecurityAlert: true,
}

// Severity as assessed at collection time. The backend may revise it.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

var knownSeverities = map[Severity]bool{
	SeverityInfo: true, SeverityLow: true, SeverityMedium: true,
	SeverityHigh: true, SeverityCritical: true,
}

// Source records which part of the system produced an event.
type Source string

const (
	SourceAgent     Source = "AGENT"
	SourceClient    Source = "CLIENT"
	SourceBackend   Source = "BACKEND"
	SourceSimulator Source = "SIMULATOR"
)

// Limits on a submitted batch. They exist so a misbehaving or hostile agent
// cannot exhaust server memory or fill the events table in one request.
const (
	MaxBatchSize        = 500
	MaxMetadataEntries  = 32
	MaxMetadataKeyLen   = 64
	MaxMetadataValueLen = 512
	MaxEventIDLen       = 128
	// MaxClockDrift bounds how far an endpoint's claimed time may sit from the
	// server's. Beyond it the claim is replaced by server time and the original
	// is preserved in metadata, so a wrong endpoint clock cannot rewrite the
	// order of a timeline.
	MaxClockDrift = 24 * time.Hour
)

// ErrInvalidEvent wraps every rejection caused by the event itself.
var ErrInvalidEvent = errors.New("invalid event")

// Inbound is one event as submitted by an agent.
//
// Time arrives as Unix milliseconds rather than a formatted timestamp: the
// agent has a clock but no date library, and an integer cannot be malformed
// by a locale or a timezone abbreviation.
type Inbound struct {
	EventID      string            `json:"event_id"`
	OccurredAtMs int64             `json:"occurred_at_ms"`
	Type         Type              `json:"event_type"`
	Severity     Severity          `json:"severity"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// Event is a normalized, stored security event.
type Event struct {
	ID           uuid.UUID         `json:"id"`
	AgentEventID string            `json:"agent_event_id,omitempty"`
	OccurredAt   time.Time         `json:"occurred_at"`
	ReceivedAt   time.Time         `json:"received_at"`
	DeviceID     *uuid.UUID        `json:"device_id,omitempty"`
	UserID       *uuid.UUID        `json:"user_id,omitempty"`
	SessionID    *uuid.UUID        `json:"session_id,omitempty"`
	Type         Type              `json:"event_type"`
	Severity     Severity          `json:"severity"`
	Source       Source            `json:"source"`
	Metadata     map[string]string `json:"metadata,omitempty"`

	// Joined for the SOC event view.
	DeviceHostname string `json:"device_hostname,omitempty"`
	UserName       string `json:"user_name,omitempty"`
}

// Rejection explains why one event in a batch was not accepted.
//
// A batch is not all-or-nothing: one malformed event must not discard the
// valid telemetry alongside it, but the agent still has to be told what was
// dropped so a broken collector is visible rather than silent.
type Rejection struct {
	EventID string `json:"event_id,omitempty"`
	Index   int    `json:"index"`
	Reason  string `json:"reason"`
}

// Normalize validates an inbound event and returns its stored form.
//
// now is the server's authoritative clock. The device is supplied by the
// caller from the verified request signature and is never read from the body.
func (in Inbound) Normalize(deviceID uuid.UUID, now time.Time) (Event, error) {
	if !knownTypes[in.Type] {
		return Event{}, fmt.Errorf("%w: unknown event_type %q", ErrInvalidEvent, in.Type)
	}

	severity := in.Severity
	if severity == "" {
		severity = SeverityInfo
	}
	if !knownSeverities[severity] {
		return Event{}, fmt.Errorf("%w: unknown severity %q", ErrInvalidEvent, severity)
	}

	if len(in.EventID) > MaxEventIDLen {
		return Event{}, fmt.Errorf("%w: event_id must be at most %d characters",
			ErrInvalidEvent, MaxEventIDLen)
	}
	if len(in.Metadata) > MaxMetadataEntries {
		return Event{}, fmt.Errorf("%w: at most %d metadata entries are accepted",
			ErrInvalidEvent, MaxMetadataEntries)
	}

	metadata := make(map[string]string, len(in.Metadata))
	for key, value := range in.Metadata {
		if len(key) == 0 || len(key) > MaxMetadataKeyLen {
			return Event{}, fmt.Errorf("%w: metadata keys must be 1..%d characters",
				ErrInvalidEvent, MaxMetadataKeyLen)
		}
		if len(value) > MaxMetadataValueLen {
			return Event{}, fmt.Errorf("%w: metadata value for %q exceeds %d characters",
				ErrInvalidEvent, key, MaxMetadataValueLen)
		}
		metadata[key] = value
	}

	occurred := now
	if in.OccurredAtMs > 0 {
		occurred = time.UnixMilli(in.OccurredAtMs).UTC()
	}

	// An endpoint clock that is wrong by more than a day would silently
	// reorder an investigation timeline, so the claim is replaced and the
	// original kept for diagnosis rather than discarded.
	if drift := now.Sub(occurred); drift > MaxClockDrift || drift < -MaxClockDrift {
		metadata["netra.reported_occurred_at"] = occurred.Format(time.RFC3339)
		metadata["netra.clock_drift_seconds"] = fmt.Sprintf("%.0f", drift.Seconds())
		occurred = now
	}

	return Event{
		AgentEventID: strings.TrimSpace(in.EventID),
		OccurredAt:   occurred,
		ReceivedAt:   now,
		DeviceID:     &deviceID,
		Type:         in.Type,
		Severity:     severity,
		Source:       SourceAgent,
		Metadata:     metadata,
	}, nil
}

// Filter narrows an event query.
type Filter struct {
	DeviceID  *uuid.UUID
	UserID    *uuid.UUID
	SessionID *uuid.UUID
	Types     []Type
	Severity  *Severity
	Since     *time.Time
	Limit     int
}

// Normalize clamps a filter to safe bounds.
func (f Filter) Normalize() Filter {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	return f
}
