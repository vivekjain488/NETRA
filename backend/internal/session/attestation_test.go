package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func attest(priv ed25519.PrivateKey, nonce, subject string) string {
	return base64.StdEncoding.EncodeToString(
		ed25519.Sign(priv, []byte(AttestationString(nonce, subject))))
}

func TestAttestationStringBindsNonceAndSubject(t *testing.T) {
	base := AttestationString("abc", "alice")

	if base == AttestationString("abd", "alice") {
		t.Error("changing the nonce did not change the attestation message")
	}
	// Without the subject, an attestation produced during one person's sign-in
	// could be lifted into another's on a shared device.
	if base == AttestationString("abc", "bob") {
		t.Error("changing the subject did not change the attestation message")
	}
}

func TestAttestationStringIsDistinctFromRequestSigning(t *testing.T) {
	// A signature made for the agent request plane must never verify as a
	// session attestation, or an intercepted heartbeat could be replayed as a
	// sign-in proof.
	message := AttestationString("abc", "alice")

	if !strings.HasPrefix(message, "NETRA-attest-v1\n") {
		t.Errorf("attestation message = %q, want its own version prefix", message)
	}
	if strings.HasPrefix(message, "NETRA-v1\n") {
		t.Error("attestation message shares the request-signing prefix")
	}
}

func TestVerifyAttestationAcceptsAValidSignature(t *testing.T) {
	pub, priv := keypair(t)

	if err := verifyAttestation(pub, "nonce-value", "alice", attest(priv, "nonce-value", "alice")); err != nil {
		t.Errorf("verifyAttestation rejected a valid attestation: %v", err)
	}
}

func TestVerifyAttestationRejectsSubstitutions(t *testing.T) {
	pub, priv := keypair(t)
	otherPub, _ := keypair(t)
	valid := attest(priv, "nonce-value", "alice")

	tests := map[string]struct {
		key       []byte
		nonce     string
		subject   string
		signature string
	}{
		"another device's key": {otherPub, "nonce-value", "alice", valid},
		"different nonce":      {pub, "other-nonce", "alice", valid},
		"different subject":    {pub, "nonce-value", "bob", valid},
		"not base64":           {pub, "nonce-value", "alice", "!!!"},
		"truncated signature":  {pub, "nonce-value", "alice", "aGVsbG8="},
		"empty signature":      {pub, "nonce-value", "alice", ""},
		"malformed key":        {pub[:8], "nonce-value", "alice", valid},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := verifyAttestation(tt.key, tt.nonce, tt.subject, tt.signature)
			if !errors.Is(err, ErrAttestation) {
				t.Errorf("verifyAttestation accepted %s (err = %v)", name, err)
			}
		})
	}
}

func TestGenerateNonceIsUniqueAndWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		nonce, err := GenerateNonce()
		if err != nil {
			t.Fatalf("GenerateNonce: %v", err)
		}
		if seen[nonce] {
			t.Fatal("GenerateNonce produced a duplicate")
		}
		seen[nonce] = true

		if err := ValidateNonceFormat(nonce); err != nil {
			t.Fatalf("generated nonce failed its own validation: %v", err)
		}
	}
}

func TestValidateNonceFormat(t *testing.T) {
	valid, _ := GenerateNonce()

	tests := map[string]bool{
		valid:                   true,
		"":                      false,
		"abc":                   false,
		strings.Repeat("z", 64): false,
		strings.Repeat("a", 63): false,
		strings.Repeat("A", 64): false, // uppercase is not produced by hex.EncodeToString
		valid + "0":             false,
	}
	for nonce, wantValid := range tests {
		label := nonce
		if len(label) > 12 {
			label = label[:12] + "..."
		}
		t.Run(label, func(t *testing.T) {
			if err := ValidateNonceFormat(nonce); (err == nil) != wantValid {
				t.Errorf("ValidateNonceFormat(%q) error = %v, want valid = %v", label, err, wantValid)
			}
		})
	}
}

func TestBeginRequestValidate(t *testing.T) {
	valid, _ := GenerateNonce()
	base := BeginRequest{DeviceUID: "netra-abcdef0123456789", Nonce: valid, Signature: "c2ln"}

	if err := base.Validate(); err != nil {
		t.Fatalf("Validate rejected a well-formed request: %v", err)
	}

	mutations := map[string]func(BeginRequest) BeginRequest{
		"no device":        func(r BeginRequest) BeginRequest { r.DeviceUID = ""; return r },
		"no signature":     func(r BeginRequest) BeginRequest { r.Signature = ""; return r },
		"bad nonce":        func(r BeginRequest) BeginRequest { r.Nonce = "short"; return r },
		"oversized device": func(r BeginRequest) BeginRequest { r.DeviceUID = strings.Repeat("x", 200); return r },
		"oversized signature": func(r BeginRequest) BeginRequest {
			r.Signature = strings.Repeat("x", 600)
			return r
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := mutate(base).Validate(); err == nil {
				t.Errorf("Validate accepted a request with %s", name)
			}
		})
	}
}
