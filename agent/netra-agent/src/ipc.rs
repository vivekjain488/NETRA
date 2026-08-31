//! Local IPC between the NETRA client and the agent.
//!
//! # Why this exists
//!
//! The Electron client is the user-facing surface; the agent holds the device
//! key. The client needs two things from the agent: the device's current
//! security status, and a signature proving device possession when the user
//! signs in. Nothing else crosses this boundary.
//!
//! # Threat model for this channel
//!
//! Any process running as the same user could connect. Three properties bound
//! what that gains an attacker:
//!
//! 1. **The agent never signs arbitrary bytes.** `attest` takes a nonce and a
//!    subject and builds the attestation message itself, always with the
//!    `NETRA-attest-v1` prefix. There is no code path by which this socket can
//!    produce an agent-plane request signature, so a local process cannot use
//!    the agent as an oracle to forge device telemetry.
//! 2. **A per-boot token is required.** It is written to a file only the agent
//!    user can read, and is regenerated on every start, so it cannot be
//!    harvested once and reused after a restart.
//! 3. **The transport is not network-reachable.** A Unix socket with
//!    owner-only permissions, or a named pipe, rather than a loopback port
//!    that every local process could reach.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use netra_core::identity::generate_nonce;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::status::SharedStatus;
use crate::enrollment::EnrolledIdentity;

/// Maximum accepted request line. A client has no reason to send more, and an
/// unbounded read on a local socket is a trivial memory exhaustion vector.
const MAX_REQUEST_BYTES: u64 = 8 * 1024;

/// Errors produced while serving local IPC.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("ipc i/o failed: {0}")]
    Io(#[from] std::io::Error),
}

/// A request from the client.
#[derive(Debug, Deserialize)]
pub struct Request {
    /// The per-boot token from the agent's token file.
    pub token: String,
    pub method: String,
    #[serde(default)]
    pub params: Params,
}

/// Parameters for the `attest` method. Deliberately narrow: there is no field
/// through which a caller could supply a whole message to sign.
#[derive(Debug, Default, Deserialize)]
pub struct Params {
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub subject: String,
}

/// A response to the client.
#[derive(Debug, Serialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    fn ok(value: serde_json::Value) -> Self {
        Self { ok: true, result: Some(value), error: None }
    }

    fn error(message: impl Into<String>) -> Self {
        Self { ok: false, result: None, error: Some(message.into()) }
    }
}

/// Everything the IPC server needs to answer a request.
pub struct IpcContext {
    pub token: String,
    pub status: SharedStatus,
    pub identity: Mutex<Option<Arc<EnrolledIdentity>>>,
}

/// Generates the per-boot IPC token and writes it where only the agent's own
/// account can read it.
pub fn write_token_file(state_dir: &Path) -> Result<String, IpcError> {
    let token = format!("{}{}", generate_nonce(), generate_nonce());
    let path = token_path(state_dir);

    std::fs::create_dir_all(state_dir)?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(token.as_bytes())?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&path, token.as_bytes())?;
    }

    Ok(token)
}

/// Path of the IPC token file.
pub fn token_path(state_dir: &Path) -> PathBuf {
    state_dir.join("ipc.token")
}

/// Maximum usable Unix socket path length.
///
/// `sockaddr_un.sun_path` is 104 bytes on macOS and 108 on Linux. A path at or
/// beyond that is rejected at bind time with an obscure error, so the limit is
/// checked here and a short fallback used instead.
#[cfg(not(windows))]
const MAX_SOCKET_PATH: usize = 100;

/// Address the client connects to.
///
/// The chosen endpoint is also written to `agent.endpoint` in the state
/// directory, so the client reads it rather than re-deriving this logic.
pub fn endpoint(state_dir: &Path) -> String {
    #[cfg(windows)]
    {
        let _ = state_dir;
        // Per-user, so two accounts on the same machine do not collide.
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".to_string());
        format!(r"\\.\pipe\netra-agent-{user}")
    }
    #[cfg(not(windows))]
    {
        let preferred = state_dir.join("agent.sock");
        if preferred.as_os_str().len() < MAX_SOCKET_PATH {
            return preferred.to_string_lossy().to_string();
        }

        // A deep state directory (a long user name, a nested profile) would
        // overflow sun_path. Fall back to a short name in the temporary
        // directory, derived from the state directory so two agents with
        // different state cannot collide.
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(state_dir.as_os_str().as_encoded_bytes());
        let short = std::env::temp_dir().join(format!("netra-{}.sock", hex::encode(&digest[..8])));
        short.to_string_lossy().to_string()
    }
}

/// Publishes the endpoint so the client does not have to re-derive it.
pub fn write_endpoint_file(state_dir: &Path) -> Result<String, IpcError> {
    let address = endpoint(state_dir);
    std::fs::create_dir_all(state_dir)?;
    std::fs::write(state_dir.join("agent.endpoint"), &address)?;
    Ok(address)
}

/// Handles one request and produces the response.
///
/// Kept free of any i/o so the security-relevant decisions can be tested
/// directly.
pub async fn handle_request(context: &IpcContext, raw: &str) -> Response {
    let request: Request = match serde_json::from_str(raw) {
        Ok(request) => request,
        Err(_) => return Response::error("malformed request"),
    };

    // Constant-time comparison: the token is a secret, and a length- or
    // content-dependent comparison would leak it a byte at a time.
    if !constant_time_eq(request.token.as_bytes(), context.token.as_bytes()) {
        warn!("rejected a local IPC request with an incorrect token");
        return Response::error("unauthorized");
    }

    match request.method.as_str() {
        "status" => Response::ok(context.status.snapshot().await.to_json()),
        "attest" => attest(context, &request.params).await,
        other => {
            debug!(method = other, "unknown local IPC method");
            Response::error("unknown method")
        }
    }
}

/// Produces a device attestation for a sign-in.
///
/// The message is constructed here, never accepted from the caller. This is
/// what stops the socket being used to sign an agent-plane request.
async fn attest(context: &IpcContext, params: &Params) -> Response {
    if params.nonce.len() != 64 || !params.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Response::error("nonce must be 64 hexadecimal characters");
    }
    if params.subject.is_empty() || params.subject.len() > 255 {
        return Response::error("subject must be between 1 and 255 characters");
    }

    let identity = context.identity.lock().await;
    let Some(identity) = identity.as_ref() else {
        return Response::error("this device is not enrolled");
    };

    // Mirrors the backend's session.AttestationString exactly.
    let message = format!("NETRA-attest-v1\n{}\n{}", params.nonce, params.subject);
    let signature = identity.key.sign_base64(&message);

    info!(subject = %params.subject, "produced a device attestation for a sign-in");
    Response::ok(serde_json::json!({
        "device_uid": identity.registration.device_uid,
        "signature": signature,
    }))
}

/// Compares two byte strings without an early return on the first difference.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        difference |= x ^ y;
    }
    difference == 0
}

/// Serves local IPC until the process shuts down.
pub async fn serve(context: Arc<IpcContext>, state_dir: PathBuf) -> Result<(), IpcError> {
    let address = write_endpoint_file(&state_dir)?;
    info!(endpoint = %address, "local IPC listening");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        use tokio::net::UnixListener;

        // A stale socket from a previous run would block binding.
        let _ = std::fs::remove_file(&address);
        let listener = UnixListener::bind(&address)?;
        // Owner-only, so another account on the machine cannot connect at all.
        std::fs::set_permissions(&address, std::fs::Permissions::from_mode(0o600))?;

        loop {
            let (stream, _) = listener.accept().await?;
            let context = Arc::clone(&context);
            tokio::spawn(async move {
                if let Err(err) = serve_connection(context, stream).await {
                    debug!(error = %err, "local IPC connection ended");
                }
            });
        }
    }

    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ServerOptions;

        loop {
            let server = ServerOptions::new().create(&address)?;
            server.connect().await?;

            let context = Arc::clone(&context);
            tokio::spawn(async move {
                if let Err(err) = serve_connection(context, server).await {
                    debug!(error = %err, "local IPC connection ended");
                }
            });
        }
    }
}

/// Reads newline-delimited requests from one connection.
async fn serve_connection<S>(context: Arc<IpcContext>, stream: S) -> Result<(), IpcError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half.take(MAX_REQUEST_BYTES));
    let mut line = String::new();

    loop {
        line.clear();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            return Ok(());
        }

        let response = handle_request(&context, line.trim()).await;
        let mut encoded = serde_json::to_vec(&response)
            .unwrap_or_else(|_| br#"{"ok":false,"error":"internal error"}"#.to_vec());
        encoded.push(b'\n');
        write_half.write_all(&encoded).await?;
        write_half.flush().await?;

        // Reset the budget so a long-lived connection can send more than one
        // request without the cap accumulating across them.
        reader.get_mut().set_limit(MAX_REQUEST_BYTES);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::AgentStatus;
    use netra_core::{DeviceKey, DeviceRegistration};

    fn context(enrolled: bool) -> IpcContext {
        let identity = enrolled.then(|| {
            Arc::new(EnrolledIdentity {
                key: DeviceKey::generate(),
                registration: DeviceRegistration {
                    device_uid: "netra-0123456789abcdef".to_string(),
                    device_id: "d66b2950-6a4c-4189-93cb-73047e0e55a6".to_string(),
                    key_protection: "software".to_string(),
                    enrolled_at: "2026-08-31T12:00:00Z".to_string(),
                    backend_url: "http://localhost:8080".to_string(),
                },
            })
        });

        IpcContext {
            token: "correct-token".to_string(),
            status: SharedStatus::new(AgentStatus::default()),
            identity: Mutex::new(identity),
        }
    }

    fn nonce() -> String {
        format!("{}{}", generate_nonce(), generate_nonce())
    }

    #[tokio::test]
    async fn rejects_a_request_without_the_token() {
        let response = handle_request(&context(true), r#"{"token":"","method":"status"}"#).await;

        assert!(!response.ok);
        assert_eq!(response.error.as_deref(), Some("unauthorized"));
    }

    #[tokio::test]
    async fn rejects_a_request_with_the_wrong_token() {
        let response =
            handle_request(&context(true), r#"{"token":"guessed","method":"status"}"#).await;

        assert!(!response.ok);
    }

    #[tokio::test]
    async fn rejects_malformed_json() {
        let response = handle_request(&context(true), "not json").await;

        assert!(!response.ok);
        assert_eq!(response.error.as_deref(), Some("malformed request"));
    }

    #[tokio::test]
    async fn rejects_an_unknown_method() {
        let response =
            handle_request(&context(true), r#"{"token":"correct-token","method":"exfiltrate"}"#)
                .await;

        assert!(!response.ok);
        assert_eq!(response.error.as_deref(), Some("unknown method"));
    }

    #[tokio::test]
    async fn status_is_available_without_enrollment() {
        let response =
            handle_request(&context(false), r#"{"token":"correct-token","method":"status"}"#).await;

        assert!(response.ok, "status failed: {:?}", response.error);
        let result = response.result.expect("result");
        assert_eq!(result["enrolled"], serde_json::Value::Bool(false));
    }

    #[tokio::test]
    async fn attest_signs_only_the_attestation_message() {
        // The signature must verify against the attestation message and
        // nothing else. If a caller could influence the signed bytes, this
        // socket would be an oracle for forging agent-plane requests.
        use base64::Engine as _;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let context = context(true);
        let nonce = nonce();
        let request = format!(
            r#"{{"token":"correct-token","method":"attest","params":{{"nonce":"{nonce}","subject":"alice"}}}}"#
        );

        let response = handle_request(&context, &request).await;
        assert!(response.ok, "attest failed: {:?}", response.error);

        let result = response.result.expect("result");
        let signature_b64 = result["signature"].as_str().expect("signature");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .expect("signature is base64");
        let signature = Signature::from_slice(&raw).expect("signature is well formed");

        let guard = context.identity.lock().await;
        let key: VerifyingKey = guard.as_ref().unwrap().key.verifying_key();

        let expected = format!("NETRA-attest-v1\n{nonce}\nalice");
        key.verify(expected.as_bytes(), &signature)
            .expect("signature covers the attestation message");

        // The same signature must not verify over an agent-plane request.
        let forged = format!("NETRA-v1\nPOST\n/api/v1/agent/events\n0\n{nonce}\n00");
        assert!(
            key.verify(forged.as_bytes(), &signature).is_err(),
            "an attestation verified as a request signature"
        );
    }

    #[tokio::test]
    async fn attest_rejects_a_malformed_nonce() {
        let context = context(true);

        for bad in ["", "short", &"z".repeat(64), &"a".repeat(63)] {
            let request = format!(
                r#"{{"token":"correct-token","method":"attest","params":{{"nonce":"{bad}","subject":"alice"}}}}"#
            );
            let response = handle_request(&context, &request).await;
            assert!(!response.ok, "nonce {bad:?} was accepted");
        }
    }

    #[tokio::test]
    async fn attest_rejects_a_missing_or_oversized_subject() {
        let context = context(true);
        let nonce = nonce();

        for subject in ["", &"x".repeat(300)] {
            let request = format!(
                r#"{{"token":"correct-token","method":"attest","params":{{"nonce":"{nonce}","subject":"{subject}"}}}}"#
            );
            assert!(!handle_request(&context, &request).await.ok);
        }
    }

    #[tokio::test]
    async fn attest_fails_before_enrollment() {
        let nonce = nonce();
        let request = format!(
            r#"{{"token":"correct-token","method":"attest","params":{{"nonce":"{nonce}","subject":"alice"}}}}"#
        );

        let response = handle_request(&context(false), &request).await;

        assert!(!response.ok);
        assert_eq!(response.error.as_deref(), Some("this device is not enrolled"));
    }

    #[cfg(not(windows))]
    #[test]
    fn endpoint_falls_back_when_the_state_path_is_too_long() {
        use std::path::PathBuf;

        let short = PathBuf::from("/tmp/netra");
        assert!(endpoint(&short).ends_with("agent.sock"));

        // A path this deep would overflow sockaddr_un.sun_path at bind time.
        let long = PathBuf::from(format!("/tmp/{}", "d".repeat(150)));
        let fallback = endpoint(&long);
        assert!(fallback.len() < MAX_SOCKET_PATH, "fallback is still too long: {fallback}");
        assert!(fallback.contains("netra-"), "unexpected fallback: {fallback}");
    }

    #[cfg(not(windows))]
    #[test]
    fn fallback_endpoints_differ_per_state_directory() {
        use std::path::PathBuf;

        let a = endpoint(&PathBuf::from(format!("/tmp/{}/a", "d".repeat(150))));
        let b = endpoint(&PathBuf::from(format!("/tmp/{}/b", "d".repeat(150))));

        assert_ne!(a, b, "two agents with different state would share a socket");
    }

    #[test]
    fn constant_time_eq_matches_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
