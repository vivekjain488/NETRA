//! The normalized NETRA event model (spec §14).
//!
//! Privacy is enforced by the shape of this type, not by convention: there is
//! no field for keystrokes, screen contents, message bodies or credentials, so
//! a collector cannot report them without changing the schema in review
//! (spec §13, §34).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// The security event types the agent and backend understand.
///
/// Serialized as the SCREAMING_SNAKE_CASE names used by the backend schema.
/// Unknown variants are rejected on both sides rather than silently ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    AuthLogin,
    AuthLogout,
    DeviceEnrollment,
    DevicePosture,
    ApplicationStart,
    ApplicationAccess,
    ResourceAccess,
    PrivilegeChange,
    NetworkEvent,
    SecurityEvent,
    PolicyDecision,
    RiskUpdate,
    SecurityAlert,
}

/// Severity as assessed at collection time. The backend may revise it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A single normalized security event.
///
/// `occurred_at_ms` is endpoint wall-clock time and is therefore untrusted:
/// the backend stamps its own authoritative receipt time on arrival.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub event_id: String,
    pub occurred_at_ms: u64,
    pub event_type: EventType,
    pub severity: Severity,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,

    /// Security-relevant metadata only. BTreeMap keeps serialization stable,
    /// which makes byte-size accounting and test assertions deterministic.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl Event {
    /// Builds an event stamped with the current endpoint time.
    pub fn new(event_type: EventType, severity: Severity) -> Self {
        Self {
            event_id: new_event_id(),
            occurred_at_ms: now_ms(),
            event_type,
            severity,
            device_id: None,
            user_id: None,
            session_id: None,
            application_id: None,
            resource_id: None,
            metadata: BTreeMap::new(),
        }
    }

    /// Attaches a metadata key/value pair.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Attaches the reporting device.
    pub fn with_device(mut self, device_id: impl Into<String>) -> Self {
        self.device_id = Some(device_id.into());
        self
    }

    /// Serialized size in bytes, used for queue accounting.
    pub fn encoded_len(&self) -> usize {
        serde_json::to_vec(self).map(|v| v.len()).unwrap_or(0)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Generates a unique event identifier without pulling in a UUID dependency.
///
/// Uniqueness only has to hold within one endpoint before the backend assigns
/// its own primary key, so a monotonic counter combined with the start
/// timestamp is sufficient and cheap.
fn new_event_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}", now_ms(), n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_ids_are_unique() {
        let a = Event::new(EventType::AuthLogin, Severity::Info);
        let b = Event::new(EventType::AuthLogin, Severity::Info);
        assert_ne!(a.event_id, b.event_id);
    }

    #[test]
    fn serializes_event_type_as_backend_name() {
        let event = Event::new(EventType::ResourceAccess, Severity::High);
        let json = serde_json::to_string(&event).expect("event serializes");

        assert!(json.contains("\"RESOURCE_ACCESS\""), "got {json}");
        assert!(json.contains("\"HIGH\""), "got {json}");
    }

    #[test]
    fn omits_absent_optional_fields() {
        // Sending nulls for every unset correlation field would inflate every
        // batch on a bandwidth-constrained endpoint.
        let json = serde_json::to_string(&Event::new(EventType::AuthLogin, Severity::Info))
            .expect("event serializes");

        assert!(!json.contains("session_id"), "got {json}");
        assert!(!json.contains("null"), "got {json}");
    }

    #[test]
    fn round_trips_through_json() {
        let original = Event::new(EventType::ApplicationStart, Severity::Low)
            .with_device("device-1")
            .with_metadata("application", "operations-portal");

        let json = serde_json::to_string(&original).expect("serializes");
        let decoded: Event = serde_json::from_str(&json).expect("deserializes");

        assert_eq!(original, decoded);
    }

    #[test]
    fn severity_orders_from_info_to_critical() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Info);
    }

    #[test]
    fn encoded_len_is_nonzero() {
        assert!(Event::new(EventType::AuthLogin, Severity::Info).encoded_len() > 0);
    }
}
