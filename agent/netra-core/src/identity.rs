//! Device cryptographic identity.
//!
//! The agent generates an Ed25519 key pair at enrollment and keeps the private
//! key on the endpoint for its whole life (spec §11). NETRA's schema has no
//! column for a private key, so there is nowhere for one to be sent even by
//! mistake.
//!
//! The signing scheme is deliberately identical to the backend's
//! `device.SigningInput`: the same canonical string, or signatures will not
//! verify. Any change here must be made on both sides together.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Length of an Ed25519 secret key in bytes.
pub const SECRET_KEY_LEN: usize = 32;

/// Errors produced while handling device identity.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("stored key material is {found} bytes, expected {SECRET_KEY_LEN}")]
    KeyLength { found: usize },
    #[error("device identifier is not usable: {0}")]
    DeviceUid(String),
}

/// The endpoint's private signing key.
///
/// The secret bytes are wrapped in `Zeroizing` wherever they are exported, so
/// a copy does not linger in freed memory after use.
pub struct DeviceKey {
    signing: SigningKey,
}

impl DeviceKey {
    /// Generates a fresh key pair from the operating system's CSPRNG.
    pub fn generate() -> Self {
        let mut rng = rand_core::OsRng;
        Self {
            signing: SigningKey::generate(&mut rng),
        }
    }

    /// Restores a key from stored secret bytes.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != SECRET_KEY_LEN {
            return Err(IdentityError::KeyLength { found: bytes.len() });
        }
        let mut fixed = [0u8; SECRET_KEY_LEN];
        fixed.copy_from_slice(bytes);
        Ok(Self {
            signing: SigningKey::from_bytes(&fixed),
        })
    }

    /// Exports the secret bytes for storage by a [`crate::keystore::KeyStore`].
    ///
    /// This is the only path by which the private key leaves this type, and it
    /// exists solely so the key store can persist it locally. It is never sent
    /// anywhere.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_LEN]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// The public key, which is what the backend registers.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// The public key as standard base64, the form the enrollment API expects.
    pub fn public_key_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.verifying_key().to_bytes())
    }

    /// Signs a canonical request string, returning standard base64.
    pub fn sign_base64(&self, message: &str) -> String {
        let signature = self.signing.sign(message.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    }
}

impl std::fmt::Debug for DeviceKey {
    /// Never prints key material, so an accidental `{:?}` cannot leak it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKey")
            .field("public_key", &self.public_key_base64())
            .finish_non_exhaustive()
    }
}

/// The signed material for one request.
///
/// Mirrors `device.SigningInput` in the backend exactly.
pub struct SigningInput<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub timestamp_unix: i64,
    pub nonce: &'a str,
    pub body: &'a [u8],
}

impl SigningInput<'_> {
    /// Builds the canonical string that is signed.
    ///
    /// The body appears as a digest rather than inline so signing cost does not
    /// grow with a large telemetry batch. Method and path are included so a
    /// captured signature cannot be replayed against a different endpoint.
    pub fn canonical_string(&self) -> String {
        let digest = Sha256::digest(self.body);
        format!(
            "NETRA-v1\n{}\n{}\n{}\n{}\n{}",
            self.method.to_ascii_uppercase(),
            self.path,
            self.timestamp_unix,
            self.nonce,
            hex::encode(digest)
        )
    }
}

/// Generates a random device identifier.
///
/// It is random rather than derived from hardware: a hostname or serial number
/// would be guessable, and a guessable identifier lets an attacker address a
/// specific device when probing.
pub fn generate_device_uid() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    format!("netra-{}", hex::encode(bytes))
}

/// Generates a per-request nonce for replay protection.
pub fn generate_nonce() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Validates a device identifier against the backend's accepted range.
pub fn validate_device_uid(uid: &str) -> Result<(), IdentityError> {
    if uid.len() < 8 || uid.len() > 128 {
        return Err(IdentityError::DeviceUid(
            "must be between 8 and 128 characters".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    fn input<'a>(body: &'a [u8]) -> SigningInput<'a> {
        SigningInput {
            method: "POST",
            path: "/api/v1/agent/heartbeat",
            timestamp_unix: 1_788_000_000,
            nonce: "a1b2c3d4e5f60718",
            body,
        }
    }

    #[test]
    fn generated_keys_are_distinct() {
        let a = DeviceKey::generate();
        let b = DeviceKey::generate();
        assert_ne!(a.public_key_base64(), b.public_key_base64());
    }

    #[test]
    fn public_key_is_32_bytes_base64() {
        let encoded = DeviceKey::generate().public_key_base64();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .expect("public key is valid base64");
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn key_round_trips_through_stored_bytes() {
        let original = DeviceKey::generate();
        let restored = DeviceKey::from_secret_bytes(original.secret_bytes().as_slice())
            .expect("restores from its own bytes");

        assert_eq!(original.public_key_base64(), restored.public_key_base64());
    }

    #[test]
    fn rejects_truncated_key_material() {
        // Truncated storage must fail loudly rather than produce a key that
        // silently fails to authenticate later.
        assert!(DeviceKey::from_secret_bytes(&[0u8; 16]).is_err());
        assert!(DeviceKey::from_secret_bytes(&[]).is_err());
    }

    #[test]
    fn signature_verifies_against_the_public_key() {
        let key = DeviceKey::generate();
        let message = input(b"{}").canonical_string();

        let raw = base64::engine::general_purpose::STANDARD
            .decode(key.sign_base64(&message))
            .expect("signature is base64");
        let signature = Signature::from_slice(&raw).expect("signature is well formed");

        key.verifying_key()
            .verify(message.as_bytes(), &signature)
            .expect("signature verifies");
    }

    #[test]
    fn canonical_string_is_version_prefixed() {
        assert!(input(b"{}").canonical_string().starts_with("NETRA-v1\n"));
    }

    #[test]
    fn canonical_string_does_not_grow_with_the_body() {
        // A large telemetry batch must not make signing cost scale with it.
        let large = vec![b'x'; 100_000];
        assert!(input(&large).canonical_string().len() < 200);
    }

    #[test]
    fn canonical_string_changes_with_every_field() {
        let base = input(b"{}").canonical_string();
        let body = input(b"{\"a\":1}").canonical_string();
        assert_ne!(base, body);

        let mut other = input(b"{}");
        other.path = "/api/v1/agent/enroll";
        assert_ne!(base, other.canonical_string());

        let mut other = input(b"{}");
        other.nonce = "ffffffffffffffff";
        assert_ne!(base, other.canonical_string());

        let mut other = input(b"{}");
        other.timestamp_unix += 1;
        assert_ne!(base, other.canonical_string());
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let key = DeviceKey::generate();
        let secret = hex::encode(key.secret_bytes().as_slice());

        let rendered = format!("{key:?}");
        assert!(
            !rendered.contains(&secret),
            "Debug output leaked the private key"
        );
    }

    #[test]
    fn device_uids_are_unique_and_valid() {
        let a = generate_device_uid();
        let b = generate_device_uid();

        assert_ne!(a, b);
        assert!(validate_device_uid(&a).is_ok());
        assert!(a.starts_with("netra-"));
    }

    #[test]
    fn rejects_unusable_device_uids() {
        assert!(validate_device_uid("short").is_err());
        assert!(validate_device_uid(&"x".repeat(200)).is_err());
    }

    #[test]
    fn nonces_are_unique_and_hexadecimal() {
        let a = generate_nonce();
        let b = generate_nonce();

        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
