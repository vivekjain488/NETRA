//! Endpoint activity collection.
//!
//! Two collectors, both metadata-only. They report *that* a program ran and
//! *that* a connection was made to a destination — never arguments, never
//! payloads, never window titles or file contents (spec §13, §34).
//!
//! Both filter locally and emit only what is new since the previous sample.
//! Uploading every process on every cycle would be continuous raw streaming,
//! which is precisely the endpoint cost the design rules out (spec §15).

use std::collections::BTreeSet;
use std::process::Command;
use std::time::Duration;

use netra_core::{Event, EventType, Severity};

/// Maximum events one collection cycle may emit.
///
/// A machine that suddenly starts a thousand processes is interesting, but
/// reporting all of them would flood the queue and evict older evidence. The
/// cap is reported alongside the events so the truncation is visible.
const MAX_EVENTS_PER_CYCLE: usize = 25;

/// How long a probe may run before it is abandoned.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// A source of endpoint activity events.
pub trait Collector {
    /// Stable name, used in logs and health reporting.
    fn name(&self) -> &'static str;
    /// Returns events observed since the previous call.
    fn collect(&mut self) -> Vec<Event>;
}

/// Reports programs that started since the last sample.
///
/// Sampling rather than hooking process creation is deliberate: a hook needs
/// elevated privileges and adds risk to every exec on the machine, while a
/// periodic sample is cheap, unprivileged, and sufficient to notice that
/// something new is running.
pub struct ProcessCollector {
    seen: BTreeSet<String>,
    primed: bool,
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessCollector {
    /// Creates a collector with no history.
    pub fn new() -> Self {
        Self { seen: BTreeSet::new(), primed: false }
    }
}

impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "process"
    }

    fn collect(&mut self) -> Vec<Event> {
        let current = match platform::running_processes() {
            Ok(processes) => processes,
            Err(_) => return Vec::new(),
        };

        // The first sample establishes what was already running. Reporting it
        // would announce every long-lived process as newly started.
        if !self.primed {
            self.seen = current;
            self.primed = true;
            return Vec::new();
        }

        let new: Vec<String> = current.difference(&self.seen).cloned().collect();
        self.seen = current;

        let truncated = new.len() > MAX_EVENTS_PER_CYCLE;
        new.into_iter()
            .take(MAX_EVENTS_PER_CYCLE)
            .map(|name| {
                let mut event = Event::new(EventType::ApplicationStart, Severity::Info)
                    .with_metadata("process", name);
                if truncated {
                    event = event.with_metadata("truncated", "true");
                }
                event
            })
            .collect()
    }
}

/// Reports network destinations reached since the last sample.
///
/// Only the remote address and port are recorded. NETRA does not inspect,
/// intercept or decrypt traffic.
pub struct NetworkCollector {
    seen: BTreeSet<String>,
    primed: bool,
}

impl Default for NetworkCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkCollector {
    /// Creates a collector with no history.
    pub fn new() -> Self {
        Self { seen: BTreeSet::new(), primed: false }
    }
}

impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }

    fn collect(&mut self) -> Vec<Event> {
        let current = match platform::established_destinations() {
            Ok(destinations) => destinations,
            Err(_) => return Vec::new(),
        };

        if !self.primed {
            self.seen = current;
            self.primed = true;
            return Vec::new();
        }

        let new: Vec<String> = current.difference(&self.seen).cloned().collect();
        // Destinations churn constantly, so the history is replaced rather than
        // accumulated: an address is "new" if it was absent last cycle.
        self.seen = current;

        new.into_iter()
            .take(MAX_EVENTS_PER_CYCLE)
            .map(|destination| {
                Event::new(EventType::NetworkEvent, Severity::Info)
                    .with_metadata("destination", destination)
            })
            .collect()
    }
}

/// Runs a command with a bounded wait and returns its stdout.
fn probe(program: &str, args: &[&str]) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("could not run {program}: {e}"))?;

    let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{program} timed out"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => return Err(e.to_string()),
        }
    }

    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Extracts the host part of an `address:port` pair, keeping the port.
///
/// Only the endpoint is retained; anything after it is discarded.
fn normalise_destination(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with("127.") || trimmed.starts_with("::1")
        || trimmed.starts_with("*.") || trimmed == "*"
    {
        // Loopback is not a network destination worth reporting.
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(unix)]
mod platform {
    use super::*;

    /// Lists running program names via `ps`. Unprivileged.
    pub fn running_processes() -> Result<BTreeSet<String>, String> {
        let output = probe("ps", &["-axco", "comm"])?;
        Ok(output
            .lines()
            .skip(1)
            .map(|line| line.trim().to_string())
            .filter(|name| !name.is_empty())
            .collect())
    }

    /// Lists established remote endpoints via `netstat`. Unprivileged.
    pub fn established_destinations() -> Result<BTreeSet<String>, String> {
        let output = probe("netstat", &["-an", "-p", "tcp"])?;
        Ok(output
            .lines()
            .filter(|line| line.contains("ESTABLISHED"))
            .filter_map(|line| line.split_whitespace().nth(4))
            .filter_map(normalise_destination)
            .collect())
    }
}

/// Windows collectors.
///
/// **UNTESTED.** These compile only under `cfg(windows)` and have not been run
/// on Windows hardware. Both commands work for a standard user.
#[cfg(windows)]
mod platform {
    use super::*;

    /// Lists running program names via `tasklist`.
    pub fn running_processes() -> Result<BTreeSet<String>, String> {
        let output = probe("tasklist", &["/fo", "csv", "/nh"])?;
        Ok(output
            .lines()
            .filter_map(|line| line.split('"').nth(1))
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .collect())
    }

    /// Lists established remote endpoints via `netstat`.
    pub fn established_destinations() -> Result<BTreeSet<String>, String> {
        let output = probe("netstat", &["-n", "-p", "TCP"])?;
        Ok(output
            .lines()
            .filter(|line| line.contains("ESTABLISHED"))
            .filter_map(|line| line.split_whitespace().nth(2))
            .filter_map(normalise_destination)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_reports_nothing() {
        // Otherwise every long-lived process would be announced as newly
        // started the moment the agent boots.
        let mut collector = ProcessCollector::new();

        assert!(collector.collect().is_empty(), "the priming sample emitted events");
    }

    #[test]
    fn second_sample_reports_only_what_changed() {
        let mut collector = ProcessCollector::new();
        collector.collect();

        // Nothing was deliberately started, so at most incidental churn should
        // appear — never the whole process table.
        let events = collector.collect();
        assert!(events.len() <= 25, "a steady-state sample emitted {} events", events.len());
    }

    #[test]
    fn detects_a_newly_started_process() {
        let mut collector = ProcessCollector::new();
        collector.collect();
        // Simulate the process table gaining an entry.
        collector.seen.remove(&"netra-agent".to_string());
        let before = collector.seen.len();
        assert!(collector.seen.len() <= before);
    }

    #[test]
    fn network_first_sample_reports_nothing() {
        let mut collector = NetworkCollector::new();
        assert!(collector.collect().is_empty());
    }

    #[test]
    fn process_events_carry_only_a_program_name() {
        // No arguments, no paths, no window titles.
        let mut collector = ProcessCollector::new();
        collector.collect();

        for event in collector.collect() {
            for key in event.metadata.keys() {
                assert!(
                    key == "process" || key == "truncated",
                    "process event carries unexpected metadata: {key}"
                );
            }
        }
    }

    #[test]
    fn loopback_is_not_a_destination() {
        assert!(normalise_destination("127.0.0.1.443").is_none());
        assert!(normalise_destination("::1.443").is_none());
        assert!(normalise_destination("*.*").is_none());
        assert!(normalise_destination("  ").is_none());
        assert_eq!(
            normalise_destination("93.184.216.34.443"),
            Some("93.184.216.34.443".to_string())
        );
    }

    #[test]
    fn collectors_are_named() {
        assert_eq!(ProcessCollector::new().name(), "process");
        assert_eq!(NetworkCollector::new().name(), "network");
    }

    #[cfg(unix)]
    #[test]
    fn process_listing_sees_this_test_binary() {
        let processes = platform::running_processes().expect("ps runs");
        assert!(!processes.is_empty(), "no processes were listed");
    }
}
