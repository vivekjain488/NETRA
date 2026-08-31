// Package audit records security-relevant actions in a tamper-evident log.
//
// Spec §33 requires every privileged action to be auditable. For a defence
// system the harder requirement is that the record cannot be quietly edited:
// each entry commits to its predecessor's hash, so removing, reordering or
// altering any row breaks the chain from that point onward and verification
// reports exactly where.
package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// ActorType identifies who performed an action.
type ActorType string

const (
	ActorUser      ActorType = "USER"
	ActorDevice    ActorType = "DEVICE"
	ActorSystem    ActorType = "SYSTEM"
	ActorSimulator ActorType = "SIMULATOR"
)

// Result is the outcome of an audited action.
type Result string

const (
	ResultSuccess Result = "SUCCESS"
	ResultDenied  Result = "DENIED"
	ResultFailure Result = "FAILURE"
)

// Action names the audited operation. Actions are constants rather than free
// text so that queries over the log are reliable.
const (
	ActionAuthenticate      = "auth.authenticate"
	ActionAuthorizationDeny = "auth.authorization_denied"
	ActionDevTokenIssued    = "auth.dev_token_issued"
	ActionDeviceEnroll      = "device.enroll"
	ActionDeviceHeartbeat   = "device.heartbeat"
	ActionDeviceRevoke      = "device.revoke"
	ActionEnrollTokenIssue  = "device.enrollment_token_issued"
	ActionAuditRead         = "audit.read"
	ActionSessionBegin      = "session.begin"
	ActionSessionEnd        = "session.end"
	ActionPostureRejected   = "device.posture_rejected"
)

// Entry is an action to be recorded.
type Entry struct {
	At         time.Time
	ActorType  ActorType
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	Result     Result
	RequestID  string
	SourceIP   string
	Detail     map[string]any
}

// Record is a stored entry, including its position and chain hashes.
type Record struct {
	Seq int64
	Entry
	PrevHash []byte
	Hash     []byte
}

// canonical is the deterministic byte encoding an entry's hash is taken over.
//
// Field order is fixed by the struct, and Go marshals maps with sorted keys, so
// the same entry always produces the same bytes. Timestamps are truncated to
// microseconds because PostgreSQL stores no finer resolution — without this the
// hash computed before insert would not match the hash recomputed after read.
type canonical struct {
	At         string         `json:"at"`
	ActorType  ActorType      `json:"actor_type"`
	ActorID    string         `json:"actor_id"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Result     Result         `json:"result"`
	RequestID  string         `json:"request_id"`
	SourceIP   string         `json:"source_ip"`
	Detail     map[string]any `json:"detail"`
}

// Normalize returns the entry with values coerced to their stored form.
func (e Entry) Normalize() Entry {
	e.At = e.At.UTC().Truncate(time.Microsecond)
	if e.Detail == nil {
		e.Detail = map[string]any{}
	}
	if e.Result == "" {
		e.Result = ResultSuccess
	}
	return e
}

// CanonicalBytes returns the exact bytes hashed for this entry.
func (e Entry) CanonicalBytes() ([]byte, error) {
	n := e.Normalize()
	return json.Marshal(canonical{
		At:         n.At.Format(time.RFC3339Nano),
		ActorType:  n.ActorType,
		ActorID:    n.ActorID,
		Action:     n.Action,
		TargetType: n.TargetType,
		TargetID:   n.TargetID,
		Result:     n.Result,
		RequestID:  n.RequestID,
		SourceIP:   n.SourceIP,
		Detail:     n.Detail,
	})
}

// ComputeHash returns SHA-256 over the previous hash followed by this entry.
// The genesis entry has a nil previous hash.
func ComputeHash(prevHash []byte, e Entry) ([]byte, error) {
	body, err := e.CanonicalBytes()
	if err != nil {
		return nil, fmt.Errorf("encode audit entry: %w", err)
	}

	h := sha256.New()
	h.Write(prevHash)
	h.Write(body)
	return h.Sum(nil), nil
}

// ChainError describes where a chain verification failed.
type ChainError struct {
	Seq    int64
	Reason string
}

func (e *ChainError) Error() string {
	return fmt.Sprintf("audit chain broken at seq %d: %s", e.Seq, e.Reason)
}

// VerifyChain recomputes every hash in sequence order and reports the first
// record that does not match. Records must be ordered by ascending Seq.
func VerifyChain(records []Record) error {
	return VerifyChainFrom(nil, records)
}

// VerifyChainFrom verifies a slice that continues an already-verified chain.
// prev is the hash of the record immediately preceding records[0], or nil when
// records[0] is the genesis entry. This lets a long log be verified page by
// page without loading all of it into memory.
func VerifyChainFrom(prev []byte, records []Record) error {
	for i, record := range records {
		if i > 0 && record.Seq <= records[i-1].Seq {
			return &ChainError{Seq: record.Seq, Reason: "records are not in ascending sequence order"}
		}
		if !equalHash(record.PrevHash, prev) {
			return &ChainError{Seq: record.Seq, Reason: "previous hash does not match the preceding record"}
		}

		want, err := ComputeHash(prev, record.Entry)
		if err != nil {
			return &ChainError{Seq: record.Seq, Reason: err.Error()}
		}
		if !equalHash(record.Hash, want) {
			return &ChainError{Seq: record.Seq, Reason: "record contents do not match its hash"}
		}
		prev = record.Hash
	}
	return nil
}

func equalHash(a, b []byte) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
