//! The NETRA endpoint agent.
//!
//! Phase 1 scope: configuration, structured logging, host identification, the
//! bounded local queue and the heartbeat loop with graceful shutdown. Device
//! enrollment and backend transport arrive in Phase 3, real collectors in
//! Phase 6; this binary deliberately does not pretend to do either yet.
//!
//! Runs in the foreground on the development host. The Windows Service wrapper
//! is added in Phase 16 alongside packaging.

use anyhow::Result;
use netra_collect::host::HostInfo;
use netra_core::{AgentConfig, Event, EventQueue, EventType, Severity};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let config = AgentConfig::from_env()?;
    init_logging(&config.log_level);

    let host = HostInfo::detect();
    info!(
        hostname = %host.hostname,
        os_name = %host.os_name,
        os_version = %host.os_version,
        architecture = %host.architecture,
        backend_url = %config.backend_url,
        version = env!("CARGO_PKG_VERSION"),
        "NETRA agent starting"
    );
    warn!("device identity not yet established: enrollment is implemented in Phase 3");

    let mut queue = EventQueue::new(config.queue_max_events, config.queue_max_bytes);
    run(&config, &mut queue).await;

    let stats = queue.stats();
    info!(
        queued = stats.len,
        dropped_total = stats.dropped_total,
        "NETRA agent stopped"
    );
    Ok(())
}

/// Runs the heartbeat loop until a shutdown signal arrives.
async fn run(config: &AgentConfig, queue: &mut EventQueue) {
    let mut ticker = tokio::time::interval(config.heartbeat_interval);
    // Skip missed ticks rather than firing them back to back: after a laptop
    // resumes from sleep, a burst of catch-up heartbeats would be pointless
    // load on both endpoint and backend.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut beats: u64 = 0;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                beats += 1;
                let event = Event::new(EventType::DevicePosture, Severity::Info)
                    .with_metadata("heartbeat", beats.to_string());
                queue.push(event);

                let stats = queue.stats();
                info!(
                    beat = beats,
                    queued = stats.len,
                    queue_bytes = stats.bytes,
                    dropped_total = stats.dropped_total,
                    utilisation = format!("{:.1}%", stats.utilisation() * 100.0),
                    "heartbeat tick (queued locally; transport arrives in Phase 3)"
                );
            }
            _ = shutdown_signal() => {
                info!("shutdown signal received");
                break;
            }
        }
    }
}

/// Resolves when the service is asked to stop.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                ctrl_c.await;
                return;
            }
        };
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }

    #[cfg(not(unix))]
    ctrl_c.await;
}

/// Installs structured JSON logging. The agent's logs are security evidence,
/// so they are machine-parseable by default (spec §40).
fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("netra_agent={level},netra_core={level},netra_collect={level}")));

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .with_target(true)
        .init();
}
