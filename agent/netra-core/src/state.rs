//! Non-secret local agent state.
//!
//! The private key lives in the [`crate::keystore`]; everything else the agent
//! must remember across restarts — its device identifier, the identity the
//! backend assigned it, the cached policy version — lives here. Keeping them
//! apart means the key store can be swapped for a TPM without moving the rest.

use std::fs;
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Errors produced while reading or writing agent state.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state i/o failed: {0}")]
    Io(#[from] io::Error),
    #[error("stored state is not readable: {0}")]
    Corrupt(String),
}

/// What the backend returned when this device enrolled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegistration {
    /// The agent-generated identifier presented at enrollment.
    pub device_uid: String,
    /// The identifier the backend assigned.
    pub device_id: String,
    /// How the private key is protected, as reported at enrollment.
    pub key_protection: String,
    /// RFC 3339 timestamp of enrollment, for operator diagnostics.
    pub enrolled_at: String,
    /// The backend this device is enrolled with. Enrolling against one backend
    /// and reporting to another would silently split a fleet's telemetry.
    pub backend_url: String,
}

/// Persisted agent state.
pub struct StateStore {
    path: PathBuf,
    dir: PathBuf,
}

impl StateStore {
    /// Creates a state store rooted at the given directory.
    pub fn new(dir: PathBuf) -> Self {
        Self {
            path: dir.join("registration.json"),
            dir,
        }
    }

    /// Loads the registration, or `None` if this device has not enrolled.
    pub fn load(&self) -> Result<Option<DeviceRegistration>, StateError> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| StateError::Corrupt(e.to_string())),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(StateError::Io(err)),
        }
    }

    /// Persists the registration.
    pub fn save(&self, registration: &DeviceRegistration) -> Result<(), StateError> {
        fs::create_dir_all(&self.dir)?;
        let encoded = serde_json::to_vec_pretty(registration)
            .map_err(|e| StateError::Corrupt(e.to_string()))?;

        // Written through a temporary file and renamed, so a crash mid-write
        // cannot leave a half-written registration that fails to parse on the
        // next start.
        let temporary = self.path.with_extension("json.tmp");
        fs::write(&temporary, encoded)?;
        fs::rename(&temporary, &self.path)?;
        Ok(())
    }

    /// Removes the registration.
    pub fn clear(&self) -> Result<(), StateError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(StateError::Io(err)),
        }
    }
}

/// Resolves the directory where agent state is kept.
///
/// Overridable so tests and a portable development run do not write to a
/// shared machine-wide location.
pub fn default_state_dir() -> PathBuf {
    if let Ok(explicit) = std::env::var("NETRA_AGENT_STATE_DIR") {
        if !explicit.trim().is_empty() {
            return PathBuf::from(explicit);
        }
    }

    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local).join("NETRA");
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("NETRA");
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".netra");
    }
    PathBuf::from(".netra-state")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration() -> DeviceRegistration {
        DeviceRegistration {
            device_uid: "netra-0123456789abcdef".to_string(),
            device_id: "0f5e1e5c-0000-4000-8000-000000000000".to_string(),
            key_protection: "software".to_string(),
            enrolled_at: "2026-08-31T12:00:00Z".to_string(),
            backend_url: "http://localhost:8080".to_string(),
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("netra-state-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn round_trips_registration() {
        let dir = temp_dir("roundtrip");
        let store = StateStore::new(dir.clone());

        assert!(store.load().expect("load").is_none());
        store.save(&registration()).expect("save");
        assert_eq!(store.load().expect("load"), Some(registration()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reports_corrupt_state_rather_than_silently_reenrolling() {
        // Treating unreadable state as "not enrolled" would make the agent
        // enrol again and orphan its existing device record.
        let dir = temp_dir("corrupt");
        fs::create_dir_all(&dir).expect("create dir");
        fs::write(dir.join("registration.json"), b"{ not json").expect("write");

        assert!(StateStore::new(dir.clone()).load().is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_is_idempotent() {
        let dir = temp_dir("clear");
        let store = StateStore::new(dir.clone());
        store.save(&registration()).expect("save");

        store.clear().expect("clear");
        store.clear().expect("clearing twice is not an error");
        assert!(store.load().expect("load").is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_dir_is_overridable() {
        std::env::set_var("NETRA_AGENT_STATE_DIR", "/tmp/netra-explicit");
        assert_eq!(default_state_dir(), PathBuf::from("/tmp/netra-explicit"));
        std::env::remove_var("NETRA_AGENT_STATE_DIR");

        assert!(!default_state_dir().as_os_str().is_empty());
    }
}
