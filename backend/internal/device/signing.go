// Package device owns device identity: enrollment, cryptographic
// authentication of agent requests, heartbeat and revocation.
//
// The device private key never leaves the endpoint (spec §11). NETRA stores
// only the public key, so there is no column anywhere in the schema that could
// leak one.
package device

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Header names carried by every device-signed request.
const (
	HeaderDeviceUID = "X-NETRA-Device"
	HeaderTimestamp = "X-NETRA-Timestamp"
	HeaderNonce     = "X-NETRA-Nonce"
	HeaderSignature = "X-NETRA-Signature"
)

// MaxClockSkew bounds how far an endpoint's clock may differ from the
// server's. A signed request outside this window is rejected, which limits how
// long a captured request stays useful even before the nonce check.
const MaxClockSkew = 5 * time.Minute

// NonceMinLength is the minimum accepted nonce length in characters. A short
// nonce would collide often enough to make replay rejection unreliable.
const NonceMinLength = 16

var (
	// ErrSignature covers every reason a signature is unacceptable. Callers
	// receive one undifferentiated error so the endpoint cannot be used to
	// probe which part of a forged request was wrong.
	ErrSignature = errors.New("device request signature is not valid")
	// ErrClockSkew indicates the timestamp is outside the accepted window.
	// It is separate because it is an operational problem an administrator
	// must be able to diagnose, not an attack signal.
	ErrClockSkew = errors.New("device request timestamp is outside the accepted window")
)

// SigningInput is the material covered by a device signature.
type SigningInput struct {
	Method    string
	Path      string
	Timestamp time.Time
	Nonce     string
	Body      []byte
}

// CanonicalString builds the exact bytes that are signed.
//
// The body is covered by its digest rather than inline, so signing cost does
// not grow with a large telemetry batch. Method and path are included so a
// signature captured from one endpoint cannot be replayed against another.
func (in SigningInput) CanonicalString() string {
	digest := sha256.Sum256(in.Body)
	return strings.Join([]string{
		"NETRA-v1",
		strings.ToUpper(in.Method),
		in.Path,
		fmt.Sprintf("%d", in.Timestamp.UTC().Unix()),
		in.Nonce,
		hex.EncodeToString(digest[:]),
	}, "\n")
}

// Sign produces a base64 signature over the canonical string.
// Used by tests and by the reference client; the agent signs in Rust.
func Sign(key ed25519.PrivateKey, in SigningInput) string {
	sig := ed25519.Sign(key, []byte(in.CanonicalString()))
	return base64.StdEncoding.EncodeToString(sig)
}

// VerifySignature checks a base64 signature against a public key.
func VerifySignature(publicKey []byte, in SigningInput, signature string) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return ErrSignature
	}
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return ErrSignature
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(in.CanonicalString()), raw) {
		return ErrSignature
	}
	return nil
}

// CheckClockSkew reports whether a request timestamp is acceptable.
//
// Future timestamps are rejected as strictly as past ones: allowing them would
// let an endpoint mint requests that stay valid long after a key is revoked.
func CheckClockSkew(timestamp, now time.Time) error {
	drift := now.Sub(timestamp)
	if drift < 0 {
		drift = -drift
	}
	if drift > MaxClockSkew {
		return fmt.Errorf("%w: drift %s exceeds %s", ErrClockSkew,
			drift.Round(time.Second), MaxClockSkew)
	}
	return nil
}

// ValidateNonce checks that a nonce is long enough to be unique in practice.
func ValidateNonce(nonce string) error {
	if len(nonce) < NonceMinLength {
		return fmt.Errorf("%w: nonce must be at least %d characters", ErrSignature, NonceMinLength)
	}
	if len(nonce) > 128 {
		return fmt.Errorf("%w: nonce is too long", ErrSignature)
	}
	for _, r := range nonce {
		// Restricting the alphabet keeps the value safe to store and log.
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == '-') {
			return fmt.Errorf("%w: nonce must be hexadecimal", ErrSignature)
		}
	}
	return nil
}

// ParsePublicKey decodes a base64 Ed25519 public key.
func ParsePublicKey(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("public key is not valid base64")
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return raw, nil
}
