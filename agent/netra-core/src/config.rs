//! Agent configuration, resolved from the environment.
//!
//! Mirrors the backend's rule (spec §39): nothing important is hard-coded, and
//! invalid input fails loudly rather than silently degrading a security
//! control.

use std::time::Duration;

/// Errors produced while resolving configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{key} is not valid: {reason}")]
    Invalid { key: &'static str, reason: String },
}

/// Fully resolved agent configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    /// Base URL of the NETRA backend.
    pub backend_url: String,
    /// Interval between heartbeats.
    pub heartbeat_interval: Duration,
    /// Maximum events retained locally while the backend is unreachable.
    pub queue_max_events: usize,
    /// Maximum bytes retained locally while the backend is unreachable.
    pub queue_max_bytes: usize,
    /// Log verbosity.
    pub log_level: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            backend_url: "http://localhost:8080".to_string(),
            heartbeat_interval: Duration::from_secs(30),
            // Bounded by both count and bytes (spec §15): local storage must
            // never grow without limit on a government endpoint.
            queue_max_events: 10_000,
            queue_max_bytes: 20 * 1024 * 1024,
            log_level: "info".to_string(),
        }
    }
}

impl AgentConfig {
    /// Reads configuration from the process environment, falling back to the
    /// defaults above for anything unset.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut cfg = Self::default();

        if let Some(url) = non_empty("NETRA_BACKEND_URL") {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(ConfigError::Invalid {
                    key: "NETRA_BACKEND_URL",
                    reason: "must start with http:// or https://".to_string(),
                });
            }
            cfg.backend_url = url.trim_end_matches('/').to_string();
        }

        if let Some(raw) = non_empty("NETRA_AGENT_HEARTBEAT_INTERVAL") {
            cfg.heartbeat_interval = parse_duration(&raw).ok_or(ConfigError::Invalid {
                key: "NETRA_AGENT_HEARTBEAT_INTERVAL",
                reason: format!("expected a duration such as 30s, got {raw:?}"),
            })?;
        }

        if let Some(raw) = non_empty("NETRA_AGENT_QUEUE_MAX_EVENTS") {
            cfg.queue_max_events = parse_positive(&raw).ok_or(ConfigError::Invalid {
                key: "NETRA_AGENT_QUEUE_MAX_EVENTS",
                reason: format!("expected a positive integer, got {raw:?}"),
            })?;
        }

        if let Some(raw) = non_empty("NETRA_AGENT_QUEUE_MAX_BYTES") {
            cfg.queue_max_bytes = parse_positive(&raw).ok_or(ConfigError::Invalid {
                key: "NETRA_AGENT_QUEUE_MAX_BYTES",
                reason: format!("expected a positive integer, got {raw:?}"),
            })?;
        }

        if let Some(level) = non_empty("NETRA_LOG_LEVEL") {
            cfg.log_level = level.to_lowercase();
        }

        Ok(cfg)
    }
}

fn non_empty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

fn parse_positive(raw: &str) -> Option<usize> {
    raw.trim().parse::<usize>().ok().filter(|v| *v > 0)
}

/// Parses `30s`, `5m` or `2h`. Deliberately minimal: the agent has no need for
/// a general duration grammar, and a smaller parser is easier to trust.
fn parse_duration(raw: &str) -> Option<Duration> {
    let raw = raw.trim();
    let (value, multiplier) = match raw.chars().last()? {
        's' => (&raw[..raw.len() - 1], 1),
        'm' => (&raw[..raw.len() - 1], 60),
        'h' => (&raw[..raw.len() - 1], 3600),
        _ => (raw, 1),
    };
    let secs = value.trim().parse::<u64>().ok()?;
    if secs == 0 {
        return None;
    }
    Some(Duration::from_secs(secs * multiplier))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_bounded() {
        let cfg = AgentConfig::default();
        assert!(cfg.queue_max_events > 0, "queue must be bounded by count");
        assert!(cfg.queue_max_bytes > 0, "queue must be bounded by size");
        assert!(cfg.heartbeat_interval > Duration::ZERO);
    }

    #[test]
    fn parses_duration_suffixes() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_duration("45"), Some(Duration::from_secs(45)));
    }

    #[test]
    fn rejects_unusable_durations() {
        // A zero interval would spin the heartbeat loop at full CPU.
        assert_eq!(parse_duration("0s"), None);
        assert_eq!(parse_duration("soon"), None);
        assert_eq!(parse_duration(""), None);
    }

    #[test]
    fn rejects_non_positive_sizes() {
        assert_eq!(parse_positive("0"), None);
        assert_eq!(parse_positive("-1"), None);
        assert_eq!(parse_positive("lots"), None);
        assert_eq!(parse_positive("512"), Some(512));
    }
}
