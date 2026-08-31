//! Basic host identification, used during enrollment and heartbeat.
//!
//! Only fields with a security purpose are collected: hostname and OS build
//! identify the managed endpoint and drive posture. Nothing here describes
//! what the user is doing (spec §34).

use serde::{Deserialize, Serialize};

/// Identifying facts about the endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub architecture: String,
}

impl HostInfo {
    /// Detects host information using the platform backend.
    ///
    /// Detection never fails: a missing value becomes `"unknown"` so that an
    /// endpoint with an unreadable field still enrolls and still reports. The
    /// backend scores `"unknown"` as a posture weakness rather than trusting
    /// it, so degrading here cannot inflate a device's trust score.
    pub fn detect() -> Self {
        Self {
            hostname: crate::platform::hostname().unwrap_or_else(|| "unknown".to_string()),
            os_name: crate::platform::os_name().to_string(),
            os_version: crate::platform::os_version().unwrap_or_else(|| "unknown".to_string()),
            architecture: std::env::consts::ARCH.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_populates_every_field() {
        let info = HostInfo::detect();

        assert!(!info.hostname.is_empty());
        assert!(!info.os_name.is_empty());
        assert!(!info.os_version.is_empty());
        assert!(!info.architecture.is_empty());
    }

    #[test]
    fn detect_reports_a_real_hostname_on_this_host() {
        // On the supported development and target platforms the hostname is
        // always readable; "unknown" here would mean the backend is broken.
        let info = HostInfo::detect();
        assert_ne!(info.hostname, "unknown", "hostname detection failed: {info:?}");
        assert_ne!(info.os_version, "unknown", "os version detection failed: {info:?}");
    }

    #[test]
    fn host_info_round_trips_through_json() {
        let info = HostInfo::detect();
        let json = serde_json::to_string(&info).expect("serializes");
        let decoded: HostInfo = serde_json::from_str(&json).expect("deserializes");

        assert_eq!(info, decoded);
    }
}
