// Package session establishes and tracks NETRA sessions.
//
// A session is the point where NETRA differs most from single sign-on. It is
// not created by a valid token alone: it requires proof, in the same exchange,
// that the request comes from an enrolled device whose private key is present
// on the machine. A stolen token is therefore not enough, and a compromised
// device without a user is not enough either (spec §26).
package session

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
)

// AttestationMethod records how a session's device was proven.
type AttestationMethod string

const (
	// AttestationDeviceSignature is an Ed25519 signature over the issued nonce.
	AttestationDeviceSignature AttestationMethod = "device-signature"
	// AttestationMTLS is reserved for Phase 15, when the agent channel gains
	// mutual TLS and the transport itself carries the proof.
	AttestationMTLS AttestationMethod = "mtls"
	// AttestationNone marks a session established without device proof. It
	// exists so historical rows remain readable, not as a supported path.
	AttestationNone AttestationMethod = "none"
)

// NonceLength is the byte length of a session nonce before hex encoding.
const NonceLength = 32

var (
	// ErrNonce covers every reason an attestation nonce is unacceptable:
	// unknown, expired, already spent, or issued to a different user. They are
	// undifferentiated so the endpoint cannot be used to probe which.
	ErrNonce = errors.New("attestation nonce is not valid")
	// ErrAttestation indicates the device signature did not verify.
	ErrAttestation = errors.New("device attestation is not valid")
	// ErrDeviceUnusable indicates the named device cannot back a session.
	ErrDeviceUnusable = errors.New("device cannot be used for a session")
	// ErrValidation wraps rejections caused by the request itself.
	ErrValidation = errors.New("invalid session request")
)

// AttestationString is the canonical message a device signs to attest a
// session.
//
// It is deliberately a different shape from the agent-plane request signature:
// a signature produced for one purpose must never verify for the other, or an
// intercepted heartbeat signature could be presented as a session attestation.
//
// The subject is bound in so that an attestation produced during one person's
// sign-in cannot be lifted into another's, even on a shared device.
func AttestationString(nonce, subject string) string {
	return strings.Join([]string{"NETRA-attest-v1", nonce, subject}, "\n")
}

// GenerateNonce returns a random hex nonce.
func GenerateNonce() (string, error) {
	raw := make([]byte, NonceLength)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// ValidateNonceFormat checks a nonce before it reaches the database.
func ValidateNonceFormat(nonce string) error {
	if len(nonce) != NonceLength*2 {
		return ErrNonce
	}
	for _, r := range nonce {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return ErrNonce
		}
	}
	return nil
}
