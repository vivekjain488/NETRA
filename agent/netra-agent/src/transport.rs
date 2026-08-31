//! Authenticated communication with the NETRA control plane.
//!
//! Two request shapes exist. Enrollment is authorised by a single-use token
//! issued by an administrator, because the device has no identity yet.
//! Everything afterwards is signed with the device key, so the backend can
//! verify the sender without any shared secret.

use std::time::Duration;

use netra_core::identity::{generate_nonce, SigningInput};
use netra_core::DeviceKey;
use serde::{Deserialize, Serialize};

/// Header names, matching the backend's `device` package exactly.
const HEADER_DEVICE: &str = "X-NETRA-Device";
const HEADER_TIMESTAMP: &str = "X-NETRA-Timestamp";
const HEADER_NONCE: &str = "X-NETRA-Nonce";
const HEADER_SIGNATURE: &str = "X-NETRA-Signature";

/// Errors produced while talking to the backend.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("network request failed: {0}")]
    Network(String),
    /// The backend rejected this device's identity. The agent must stop
    /// retrying and wait for an operator: a revoked device retrying forever
    /// is noise, not resilience.
    #[error("device authentication was rejected by the backend")]
    Unauthorized,
    #[error("enrollment was refused: {0}")]
    EnrollmentRefused(String),
    #[error("backend returned status {status}")]
    Status { status: u16 },
    #[error("backend response could not be read: {0}")]
    Decode(String),
}

/// What the agent submits to enroll.
#[derive(Debug, Serialize)]
pub struct EnrollRequest {
    pub enrollment_token: String,
    pub device_uid: String,
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub agent_version: String,
    /// Base64 Ed25519 public key. The private key is never included, and the
    /// backend has no field to receive one.
    pub public_key: String,
    pub key_protection: String,
}

/// The device record the backend created.
#[derive(Debug, Deserialize)]
pub struct EnrollResponse {
    pub id: String,
    pub device_uid: String,
    pub state: String,
    pub key_protection: String,
}

/// The agent's periodic liveness report.
#[derive(Debug, Serialize)]
pub struct HeartbeatRequest {
    pub agent_version: String,
    pub queued_events: usize,
    pub dropped_events: u64,
}

/// What the control plane expects next.
#[derive(Debug, Deserialize)]
pub struct HeartbeatResponse {
    pub heartbeat_interval_seconds: u64,
    pub policy_version: i64,
}

/// An RFC 7807 problem document, the shape of every backend error.
#[derive(Debug, Deserialize)]
struct Problem {
    title: Option<String>,
    detail: Option<String>,
}

/// HTTP client for the NETRA backend.
pub struct BackendClient {
    http: reqwest::Client,
    base_url: String,
}

impl BackendClient {
    /// Builds a client for the given backend base URL.
    pub fn new(base_url: impl Into<String>, timeout: Duration) -> Result<Self, TransportError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("netra-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| TransportError::Network(e.to_string()))?;

        Ok(Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        })
    }

    /// Enrolls this device using a single-use enrollment token.
    pub async fn enroll(&self, request: &EnrollRequest) -> Result<EnrollResponse, TransportError> {
        let response = self
            .http
            .post(format!("{}/api/v1/agent/enroll", self.base_url))
            .json(request)
            .send()
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;

        let status = response.status();
        if status.is_success() {
            return response
                .json::<EnrollResponse>()
                .await
                .map_err(|e| TransportError::Decode(e.to_string()));
        }

        let problem = response.json::<Problem>().await.ok();
        let detail = problem
            .and_then(|p| p.detail.or(p.title))
            .unwrap_or_else(|| format!("status {status}"));
        Err(TransportError::EnrollmentRefused(detail))
    }

    /// Sends a device-signed heartbeat.
    pub async fn heartbeat(
        &self,
        key: &DeviceKey,
        device_uid: &str,
        request: &HeartbeatRequest,
    ) -> Result<HeartbeatResponse, TransportError> {
        let body = serde_json::to_vec(request).map_err(|e| TransportError::Decode(e.to_string()))?;
        let response = self
            .signed_post(key, device_uid, "/api/v1/agent/heartbeat", body)
            .await?;

        response
            .json::<HeartbeatResponse>()
            .await
            .map_err(|e| TransportError::Decode(e.to_string()))
    }

    /// Signs and sends a POST request on the agent plane.
    async fn signed_post(
        &self,
        key: &DeviceKey,
        device_uid: &str,
        path: &str,
        body: Vec<u8>,
    ) -> Result<reqwest::Response, TransportError> {
        let nonce = generate_nonce();
        // Endpoint wall-clock time. The backend treats it as untrusted and
        // rejects anything outside its skew window.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let signature = key.sign_base64(
            &SigningInput {
                method: "POST",
                path,
                timestamp_unix: timestamp,
                nonce: &nonce,
                body: &body,
            }
            .canonical_string(),
        );

        let response = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .header("Content-Type", "application/json")
            .header(HEADER_DEVICE, device_uid)
            .header(HEADER_TIMESTAMP, timestamp.to_string())
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, signature)
            .body(body)
            .send()
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;

        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(TransportError::Unauthorized);
        }
        if !status.is_success() {
            return Err(TransportError::Status {
                status: status.as_u16(),
            });
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_trailing_slash_is_normalised() {
        // Otherwise every request path would contain a double slash, which the
        // backend router treats as a different, unmatched route.
        let client = BackendClient::new("http://localhost:8080/", Duration::from_secs(5))
            .expect("client builds");
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn enroll_request_never_serializes_private_key_material() {
        let key = DeviceKey::generate();
        let request = EnrollRequest {
            enrollment_token: "token".to_string(),
            device_uid: "netra-0123456789abcdef".to_string(),
            hostname: "GOV-LAPTOP-01".to_string(),
            os_name: "windows".to_string(),
            os_version: "11".to_string(),
            agent_version: "0.1.0".to_string(),
            public_key: key.public_key_base64(),
            key_protection: "software".to_string(),
        };

        let encoded = serde_json::to_string(&request).expect("serializes");
        let secret = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            key.secret_bytes().as_slice(),
        );

        assert!(!encoded.contains(&secret), "enrollment payload contains the private key");
        assert!(encoded.contains(&key.public_key_base64()));
    }
}
