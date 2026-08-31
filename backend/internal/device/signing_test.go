package device

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func input() SigningInput {
	return SigningInput{
		Method:    "POST",
		Path:      "/api/v1/agent/heartbeat",
		Timestamp: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC),
		Nonce:     "a1b2c3d4e5f60718",
		Body:      []byte(`{"agent_version":"0.1.0"}`),
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	pub, priv := keypair(t)

	if err := VerifySignature(pub, input(), Sign(priv, input())); err != nil {
		t.Errorf("VerifySignature rejected a valid signature: %v", err)
	}
}

func TestVerifyRejectsAnotherKey(t *testing.T) {
	_, priv := keypair(t)
	otherPub, _ := keypair(t)

	if err := VerifySignature(otherPub, input(), Sign(priv, input())); !errors.Is(err, ErrSignature) {
		t.Error("a signature verified against the wrong public key")
	}
}

func TestSignatureCoversEveryPart(t *testing.T) {
	pub, priv := keypair(t)
	signature := Sign(priv, input())

	mutations := map[string]func(SigningInput) SigningInput{
		"method": func(in SigningInput) SigningInput { in.Method = "GET"; return in },
		// Without the path, a signature captured from one endpoint could be
		// replayed against a more sensitive one.
		"path":      func(in SigningInput) SigningInput { in.Path = "/api/v1/agent/enroll"; return in },
		"timestamp": func(in SigningInput) SigningInput { in.Timestamp = in.Timestamp.Add(time.Second); return in },
		"nonce":     func(in SigningInput) SigningInput { in.Nonce = "ffffffffffffffff"; return in },
		"body":      func(in SigningInput) SigningInput { in.Body = []byte(`{"agent_version":"9.9.9"}`); return in },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := VerifySignature(pub, mutate(input()), signature); !errors.Is(err, ErrSignature) {
				t.Errorf("changing the %s did not invalidate the signature", name)
			}
		})
	}
}

func TestVerifyRejectsMalformedInput(t *testing.T) {
	pub, priv := keypair(t)
	valid := Sign(priv, input())

	tests := map[string]struct {
		key       []byte
		signature string
	}{
		"short public key":     {pub[:16], valid},
		"empty public key":     {nil, valid},
		"signature not base64": {pub, "!!!not base64!!!"},
		"signature too short":  {pub, "aGVsbG8="},
		"empty signature":      {pub, ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if err := VerifySignature(tt.key, input(), tt.signature); !errors.Is(err, ErrSignature) {
				t.Errorf("malformed input was accepted: %v", err)
			}
		})
	}
}

func TestCanonicalStringIsVersioned(t *testing.T) {
	// The version prefix lets the scheme change later without a signature
	// produced under the old rules being accepted under the new ones.
	if !strings.HasPrefix(input().CanonicalString(), "NETRA-v1\n") {
		t.Errorf("canonical string is not version-prefixed: %q", input().CanonicalString())
	}
}

func TestCanonicalStringDoesNotEmbedTheBody(t *testing.T) {
	// A large telemetry batch must not make signing cost grow with its size.
	in := input()
	in.Body = []byte(strings.Repeat("x", 100_000))

	if got := len(in.CanonicalString()); got > 200 {
		t.Errorf("canonical string length = %d, want a fixed-size digest of the body", got)
	}
}

func TestCheckClockSkew(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		offset  time.Duration
		wantErr bool
	}{
		{"current", 0, false},
		{"slightly behind", -2 * time.Minute, false},
		{"slightly ahead", 2 * time.Minute, false},
		{"far behind", -10 * time.Minute, true},
		// Future timestamps are rejected as strictly as past ones: otherwise an
		// endpoint could mint requests that stay valid after its key is revoked.
		{"far ahead", 10 * time.Minute, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckClockSkew(now.Add(tt.offset), now)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckClockSkew() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrClockSkew) {
				t.Errorf("error = %v, want ErrClockSkew so operators can diagnose it", err)
			}
		})
	}
}

func TestValidateNonce(t *testing.T) {
	tests := map[string]bool{
		"a1b2c3d4e5f60718":                 true,
		"A1B2C3D4E5F60718":                 true,
		"a1b2-c3d4-e5f6-0718":              true,
		"short":                            false,
		"":                                 false,
		"zzzzzzzzzzzzzzzzzz":               false,
		strings.Repeat("ab", 100):          false,
		"a1b2c3d4e5f60718; DROP TABLE x--": false,
	}
	for nonce, wantValid := range tests {
		t.Run(nonce, func(t *testing.T) {
			err := ValidateNonce(nonce)
			if (err == nil) != wantValid {
				t.Errorf("ValidateNonce(%q) error = %v, want valid = %v", nonce, err, wantValid)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _ := keypair(t)

	valid := base64Encode(pub)
	got, err := ParsePublicKey(valid)
	if err != nil {
		t.Fatalf("ParsePublicKey rejected a valid key: %v", err)
	}
	if string(got) != string(pub) {
		t.Error("decoded key does not match the original")
	}

	for name, encoded := range map[string]string{
		"not base64": "!!!",
		"wrong size": base64Encode([]byte("too short")),
		"empty":      "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePublicKey(encoded); err == nil {
				t.Errorf("ParsePublicKey accepted %s", name)
			}
		})
	}
}

func base64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
