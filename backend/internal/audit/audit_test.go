package audit

import (
	"errors"
	"testing"
	"time"
)

func entryAt(seconds int, action string) Entry {
	return Entry{
		At:         time.Date(2026, 8, 31, 10, 0, seconds, 0, time.UTC),
		ActorType:  ActorUser,
		ActorID:    "alice",
		Action:     action,
		TargetType: "device",
		TargetID:   "GOV-LAPTOP-01",
		Result:     ResultSuccess,
		RequestID:  "req-1",
		Detail:     map[string]any{"reason": "test"},
	}
}

// buildChain produces a valid chain of n records, as the store would.
func buildChain(t *testing.T, n int) []Record {
	t.Helper()

	var (
		records []Record
		prev    []byte
	)
	for i := 0; i < n; i++ {
		e := entryAt(i, "test.action").Normalize()
		hash, err := ComputeHash(prev, e)
		if err != nil {
			t.Fatalf("ComputeHash: %v", err)
		}
		records = append(records, Record{
			Seq: int64(i + 1), Entry: e, PrevHash: prev, Hash: hash,
		})
		prev = hash
	}
	return records
}

func TestComputeHashIsDeterministic(t *testing.T) {
	a, err := ComputeHash(nil, entryAt(0, "x"))
	if err != nil {
		t.Fatalf("ComputeHash: %v", err)
	}
	b, err := ComputeHash(nil, entryAt(0, "x"))
	if err != nil {
		t.Fatalf("ComputeHash: %v", err)
	}

	if string(a) != string(b) {
		t.Error("the same entry produced two different hashes")
	}
	if len(a) != 32 {
		t.Errorf("hash length = %d, want 32", len(a))
	}
}

func TestComputeHashDependsOnPredecessor(t *testing.T) {
	// This is the property that makes the log a chain rather than a list.
	withoutPrev, _ := ComputeHash(nil, entryAt(0, "x"))
	withPrev, _ := ComputeHash([]byte("previous"), entryAt(0, "x"))

	if string(withoutPrev) == string(withPrev) {
		t.Error("hash ignored the previous record; the chain would not detect reordering")
	}
}

func TestComputeHashChangesWithEveryField(t *testing.T) {
	base := entryAt(0, "x")
	baseHash, _ := ComputeHash(nil, base)

	mutations := map[string]func(Entry) Entry{
		"action":      func(e Entry) Entry { e.Action = "y"; return e },
		"actor":       func(e Entry) Entry { e.ActorID = "mallory"; return e },
		"actor type":  func(e Entry) Entry { e.ActorType = ActorSystem; return e },
		"result":      func(e Entry) Entry { e.Result = ResultDenied; return e },
		"target":      func(e Entry) Entry { e.TargetID = "OTHER"; return e },
		"target type": func(e Entry) Entry { e.TargetType = "user"; return e },
		"request id":  func(e Entry) Entry { e.RequestID = "req-2"; return e },
		"source ip":   func(e Entry) Entry { e.SourceIP = "10.0.0.1"; return e },
		"timestamp":   func(e Entry) Entry { e.At = e.At.Add(time.Second); return e },
		"detail":      func(e Entry) Entry { e.Detail = map[string]any{"reason": "changed"}; return e },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			got, _ := ComputeHash(nil, mutate(base))
			if string(got) == string(baseHash) {
				t.Errorf("changing %s did not change the hash; that field could be edited undetected", name)
			}
		})
	}
}

func TestNormalizeTruncatesToMicroseconds(t *testing.T) {
	// PostgreSQL stores microseconds. Without truncation the hash computed
	// before insert would not match the hash recomputed after read.
	e := Entry{At: time.Date(2026, 8, 31, 10, 0, 0, 123_456_789, time.UTC)}

	if got := e.Normalize().At.Nanosecond(); got != 123_456_000 {
		t.Errorf("nanoseconds = %d, want 123456000", got)
	}
}

func TestVerifyChainAcceptsAValidChain(t *testing.T) {
	if err := VerifyChain(buildChain(t, 5)); err != nil {
		t.Errorf("VerifyChain rejected a valid chain: %v", err)
	}
}

func TestVerifyChainAcceptsEmpty(t *testing.T) {
	if err := VerifyChain(nil); err != nil {
		t.Errorf("VerifyChain rejected an empty log: %v", err)
	}
}

func TestVerifyChainDetectsEditedRecord(t *testing.T) {
	records := buildChain(t, 5)
	records[2].Action = "auth.authorization_denied" // silently rewritten

	err := VerifyChain(records)
	if err == nil {
		t.Fatal("an edited record passed verification")
	}
	var chainErr *ChainError
	if !errors.As(err, &chainErr) || chainErr.Seq != 3 {
		t.Errorf("error = %v, want a ChainError at seq 3", err)
	}
}

func TestVerifyChainDetectsDeletedRecord(t *testing.T) {
	records := buildChain(t, 5)
	records = append(records[:2], records[3:]...) // remove seq 3

	if err := VerifyChain(records); err == nil {
		t.Fatal("a deleted record passed verification")
	}
}

func TestVerifyChainDetectsReordering(t *testing.T) {
	records := buildChain(t, 5)
	records[1], records[2] = records[2], records[1]

	if err := VerifyChain(records); err == nil {
		t.Fatal("reordered records passed verification")
	}
}

func TestVerifyChainDetectsAppendedForgery(t *testing.T) {
	// An attacker appending a record without the chain hash must be caught.
	records := buildChain(t, 3)
	forged := entryAt(9, "device.revoke").Normalize()
	records = append(records, Record{Seq: 4, Entry: forged, PrevHash: records[2].Hash, Hash: []byte("forged")})

	if err := VerifyChain(records); err == nil {
		t.Fatal("a forged record passed verification")
	}
}

func TestVerifyChainFromContinuesAcrossPages(t *testing.T) {
	all := buildChain(t, 6)
	first, second := all[:3], all[3:]

	if err := VerifyChainFrom(nil, first); err != nil {
		t.Fatalf("first page failed: %v", err)
	}
	if err := VerifyChainFrom(first[len(first)-1].Hash, second); err != nil {
		t.Errorf("second page failed to continue the chain: %v", err)
	}
}

func TestVerifyChainFromRejectsWrongContinuation(t *testing.T) {
	all := buildChain(t, 6)

	if err := VerifyChainFrom([]byte("not the real head"), all[3:]); err == nil {
		t.Error("a page was accepted against the wrong predecessor")
	}
}
