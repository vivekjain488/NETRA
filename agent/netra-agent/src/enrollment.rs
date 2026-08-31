//! Device enrollment.
//!
//! Runs once in a device's life. It generates the key pair, registers the
//! public key with the control plane, and persists both the key and the
//! resulting registration so the agent can authenticate on every later start.

use netra_collect::host::HostInfo;
use netra_core::identity::generate_device_uid;
use netra_core::keystore::KeyStore;
use netra_core::{DeviceKey, DeviceRegistration, StateStore};
use tracing::{info, warn};

use crate::transport::{BackendClient, EnrollRequest, TransportError};

/// Errors produced during enrollment.
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("key store: {0}")]
    KeyStore(#[from] netra_core::keystore::KeyStoreError),
    #[error("state store: {0}")]
    State(#[from] netra_core::state::StateError),
    #[error("device identity: {0}")]
    Identity(#[from] netra_core::identity::IdentityError),
}

/// The identity an enrolled agent operates with.
pub struct EnrolledIdentity {
    pub key: DeviceKey,
    pub registration: DeviceRegistration,
}

/// Loads an existing identity from local storage.
///
/// Both halves must be present. A key without a registration, or the reverse,
/// means enrollment was interrupted; treating that as enrolled would produce an
/// agent that can never authenticate, so it is reported as not enrolled and
/// enrollment starts cleanly.
pub fn load_existing(
    keys: &dyn KeyStore,
    state: &StateStore,
) -> Result<Option<EnrolledIdentity>, EnrollmentError> {
    let stored_key = keys.load()?;
    let registration = state.load()?;

    match (stored_key, registration) {
        (Some(secret), Some(registration)) => {
            let key = DeviceKey::from_secret_bytes(&secret)?;
            Ok(Some(EnrolledIdentity { key, registration }))
        }
        (Some(_), None) => {
            warn!("a device key exists without a registration; enrollment will start again");
            Ok(None)
        }
        (None, Some(_)) => {
            warn!("a registration exists without a device key; enrollment will start again");
            Ok(None)
        }
        (None, None) => Ok(None),
    }
}

/// Enrolls this device with the control plane.
///
/// The key is written to local storage **before** the public half is sent. If
/// the process dies mid-enrollment, the worst case is an unused key on disk;
/// the reverse order could register a public key whose private half was never
/// persisted, leaving a device record that can never authenticate.
pub async fn enroll(
    client: &BackendClient,
    keys: &dyn KeyStore,
    state: &StateStore,
    enrollment_token: &str,
    backend_url: &str,
) -> Result<EnrolledIdentity, EnrollmentError> {
    let host = HostInfo::detect();
    let device_uid = generate_device_uid();
    let key = DeviceKey::generate();

    keys.store(key.secret_bytes().as_slice())?;

    let request = EnrollRequest {
        enrollment_token: enrollment_token.to_string(),
        device_uid: device_uid.clone(),
        hostname: host.hostname.clone(),
        os_name: host.os_name.clone(),
        os_version: host.os_version.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        public_key: key.public_key_base64(),
        key_protection: keys.protection().as_api_value().to_string(),
    };

    info!(
        device_uid = %device_uid,
        hostname = %host.hostname,
        key_protection = keys.protection().as_api_value(),
        "enrolling with the NETRA control plane"
    );

    let response = match client.enroll(&request).await {
        Ok(response) => response,
        Err(err) => {
            // The key is useless without a registration, so it is removed
            // rather than left behind to confuse the next attempt.
            if let Err(cleanup) = keys.clear() {
                warn!(error = %cleanup, "could not remove the unused device key");
            }
            return Err(err.into());
        }
    };

    let registration = DeviceRegistration {
        device_uid: response.device_uid,
        device_id: response.id,
        key_protection: response.key_protection,
        enrolled_at: now_rfc3339(),
        backend_url: backend_url.to_string(),
    };
    state.save(&registration)?;

    info!(
        device_id = %registration.device_id,
        state = %response.state,
        "device enrolled"
    );
    Ok(EnrolledIdentity { key, registration })
}

/// Formats the current time as RFC 3339 without pulling in a date library.
///
/// The value is diagnostic only; the backend records its own authoritative
/// enrollment timestamp.
fn now_rfc3339() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}", UnixTime(seconds))
}

/// Minimal civil-time formatter for a Unix timestamp in UTC.
struct UnixTime(u64);

impl std::fmt::Display for UnixTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let days = self.0 / 86_400;
        let seconds_of_day = self.0 % 86_400;
        let (year, month, day) = civil_from_days(days as i64);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            seconds_of_day / 3600,
            (seconds_of_day % 3600) / 60,
            seconds_of_day % 60
        )
    }
}

/// Howard Hinnant's days-from-civil algorithm, inverted.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_a_known_timestamp() {
        assert_eq!(UnixTime(1_787_299_200).to_string(), "2026-08-21T08:00:00Z");
    }

    #[test]
    fn formats_the_unix_epoch() {
        assert_eq!(UnixTime(0).to_string(), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn handles_a_leap_day() {
        // 2024-02-29T12:34:56Z
        assert_eq!(UnixTime(1_709_209_496).to_string(), "2024-02-29T12:24:56Z");
    }
}
