//! The agent's current security status, shared with the local client.
//!
//! Only fields the user is entitled to see about their own device appear here.
//! There is no field for anything the client has no need of, which keeps the
//! IPC surface from widening by accident.

use std::sync::Arc;

use tokio::sync::RwLock;

/// A snapshot of what the agent knows about itself.
#[derive(Debug, Clone, Default)]
pub struct AgentStatus {
    pub enrolled: bool,
    pub device_id: Option<String>,
    pub device_uid: Option<String>,
    pub key_protection: String,
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub agent_version: String,
    pub backend_url: String,
    /// Whether the last heartbeat reached the control plane.
    pub connected: bool,
    /// Set when the control plane refused this device's identity, which is
    /// what the user sees if their device has been revoked.
    pub identity_rejected: bool,
    pub last_heartbeat: Option<String>,
    pub queued_events: usize,
    pub dropped_events: u64,
    /// The trust score most recently returned by the control plane.
    ///
    /// It is stored, never computed here: the endpoint learns its score from
    /// the backend rather than deciding it.
    pub trust_score: Option<i32>,
    /// The controls that lost the most points, so the user can see what to fix.
    pub trust_weaknesses: Vec<String>,
}

impl AgentStatus {
    /// Renders the status for the local IPC response.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "enrolled": self.enrolled,
            "device_id": self.device_id,
            "device_uid": self.device_uid,
            "key_protection": self.key_protection,
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "agent_version": self.agent_version,
            "backend_url": self.backend_url,
            "connected": self.connected,
            "identity_rejected": self.identity_rejected,
            "last_heartbeat": self.last_heartbeat,
            "queued_events": self.queued_events,
            "dropped_events": self.dropped_events,
            "trust_score": self.trust_score,
            "trust_weaknesses": self.trust_weaknesses,
        })
    }
}

/// Status shared between the heartbeat loop and the IPC server.
#[derive(Clone)]
pub struct SharedStatus {
    inner: Arc<RwLock<AgentStatus>>,
}

impl SharedStatus {
    /// Creates shared status from an initial value.
    pub fn new(status: AgentStatus) -> Self {
        Self { inner: Arc::new(RwLock::new(status)) }
    }

    /// Returns a copy of the current status.
    pub async fn snapshot(&self) -> AgentStatus {
        self.inner.read().await.clone()
    }

    /// Applies an update under the write lock.
    pub async fn update(&self, apply: impl FnOnce(&mut AgentStatus)) {
        let mut guard = self.inner.write().await;
        apply(&mut guard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn update_is_visible_to_readers() {
        let status = SharedStatus::new(AgentStatus::default());

        status.update(|s| s.queued_events = 7).await;

        assert_eq!(status.snapshot().await.queued_events, 7);
    }

    #[tokio::test]
    async fn clones_share_one_state() {
        let status = SharedStatus::new(AgentStatus::default());
        let clone = status.clone();

        clone.update(|s| s.connected = true).await;

        assert!(status.snapshot().await.connected, "a clone did not share state");
    }

    #[test]
    fn json_never_contains_key_material() {
        // The status is handed to any local process holding the IPC token, so
        // it must carry nothing secret.
        let status = AgentStatus {
            enrolled: true,
            device_uid: Some("netra-abc".to_string()),
            key_protection: "software".to_string(),
            ..Default::default()
        };

        let rendered = status.to_json().to_string();
        for forbidden in ["private", "secret", "token"] {
            assert!(
                !rendered.contains(forbidden),
                "status JSON mentions {forbidden}: {rendered}"
            );
        }
    }
}
