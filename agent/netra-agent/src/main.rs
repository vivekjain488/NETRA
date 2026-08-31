//! The NETRA endpoint agent.
//!
//! Phase 1 scope: configuration, structured logging, host identification, the
//! bounded local queue and the heartbeat loop with graceful shutdown. Device
//! enrollment and backend transport arrive in Phase 3, real collectors in
//! Phase 6; this binary deliberately does not pretend to do either yet.
//!
//! Runs in the foreground on the development host. The Windows Service wrapper
//! is added in Phase 16 alongside packaging.

mod enrollment;
mod ipc;
mod status;
mod transport;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use netra_collect::host::HostInfo;
use netra_core::keystore::default_key_store;
use netra_core::state::default_state_dir;
use netra_core::{AgentConfig, Event, EventQueue, EventType, Severity, StateStore};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::enrollment::EnrolledIdentity;
use crate::status::{AgentStatus, SharedStatus};
use crate::transport::{BackendClient, HeartbeatRequest, PostureReport, TransportError};

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

    let state_dir = default_state_dir();
    let keys = default_key_store(state_dir.clone());
    let state = StateStore::new(state_dir.clone());
    let client = BackendClient::new(&config.backend_url, Duration::from_secs(15))?;

    info!(
        state_dir = %state_dir.display(),
        key_protection = keys.protection().as_api_value(),
        "local state initialised"
    );

    let identity = match enrollment::load_existing(keys.as_ref(), &state)? {
        Some(existing) => {
            info!(device_id = %existing.registration.device_id, "loaded existing device identity");
            verify_backend_matches(&existing, &config.backend_url);
            Some(existing)
        }
        None => match std::env::var("NETRA_ENROLLMENT_TOKEN").ok().filter(|t| !t.trim().is_empty()) {
            Some(token) => Some(
                enrollment::enroll(&client, keys.as_ref(), &state, &token, &config.backend_url).await?,
            ),
            None => {
                warn!(
                    "this device is not enrolled and NETRA_ENROLLMENT_TOKEN is not set; \
                     collecting locally only. Ask an administrator for an enrollment token."
                );
                None
            }
        },
    };

    let identity = identity.map(Arc::new);

    let status = SharedStatus::new(AgentStatus {
        enrolled: identity.is_some(),
        device_id: identity.as_ref().map(|i| i.registration.device_id.clone()),
        device_uid: identity.as_ref().map(|i| i.registration.device_uid.clone()),
        key_protection: keys.protection().as_api_value().to_string(),
        hostname: host.hostname.clone(),
        os_name: host.os_name.clone(),
        os_version: host.os_version.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        backend_url: config.backend_url.clone(),
        ..Default::default()
    });

    // The client needs the agent's status and, at sign-in, a device
    // attestation. Everything else stays inside the agent.
    let ipc_token = ipc::write_token_file(&state_dir)?;
    let ipc_context = Arc::new(ipc::IpcContext {
        token: ipc_token,
        status: status.clone(),
        identity: tokio::sync::Mutex::new(identity.clone()),
    });
    let ipc_dir = state_dir.clone();
    tokio::spawn(async move {
        if let Err(err) = ipc::serve(ipc_context, ipc_dir).await {
            error!(error = %err, "local IPC server stopped");
        }
    });

    let mut queue = EventQueue::new(config.queue_max_events, config.queue_max_bytes);
    run(&config, &client, identity.as_deref(), &status, &mut queue).await;

    let stats = queue.stats();
    info!(
        queued = stats.len,
        dropped_total = stats.dropped_total,
        "NETRA agent stopped"
    );
    Ok(())
}

/// Warns when the stored registration belongs to a different backend.
///
/// Enrolling against one control plane and reporting to another would split a
/// fleet's telemetry silently, which is worse than a loud warning.
fn verify_backend_matches(identity: &EnrolledIdentity, configured: &str) {
    let enrolled = identity.registration.backend_url.trim_end_matches('/');
    if enrolled != configured.trim_end_matches('/') {
        warn!(
            enrolled_with = %enrolled,
            configured = %configured,
            "this device was enrolled with a different backend; its identity will not be recognised"
        );
    }
}

/// Runs the heartbeat loop until a shutdown signal arrives.
async fn run(
    config: &AgentConfig,
    client: &BackendClient,
    identity: Option<&EnrolledIdentity>,
    status: &SharedStatus,
    queue: &mut EventQueue,
) {
    let mut interval = config.heartbeat_interval;
    let mut ticker = tokio::time::interval(interval);
    // Skip missed ticks rather than firing them back to back: after a laptop
    // resumes from sleep, a burst of catch-up heartbeats would be pointless
    // load on both endpoint and backend.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Posture probes spawn system utilities, so they run on their own, much
    // slower schedule than the heartbeat (spec §45). The first tick fires
    // immediately so a device reports its posture as soon as it starts.
    let mut posture_ticker = tokio::time::interval(config.posture_interval);
    posture_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut beats: u64 = 0;
    let mut identity_rejected = false;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                beats += 1;
                queue.push(
                    Event::new(EventType::DevicePosture, Severity::Info)
                        .with_metadata("heartbeat", beats.to_string()),
                );

                let stats = queue.stats();
                status
                    .update(|s| {
                        s.queued_events = stats.len;
                        s.dropped_events = stats.dropped_total;
                    })
                    .await;

                let Some(identity) = identity else {
                    info!(
                        beat = beats,
                        queued = stats.len,
                        "heartbeat tick (not enrolled; events are queued locally)"
                    );
                    continue;
                };
                if identity_rejected {
                    // A revoked device retrying forever is noise, not
                    // resilience. Collection continues; transmission does not.
                    continue;
                }

                let request = HeartbeatRequest {
                    agent_version: env!("CARGO_PKG_VERSION").to_string(),
                    queued_events: stats.len,
                    dropped_events: stats.dropped_total,
                };

                match client
                    .heartbeat(&identity.key, &identity.registration.device_uid, &request)
                    .await
                {
                    Ok(response) => {
                        info!(
                            beat = beats,
                            queued = stats.len,
                            dropped_total = stats.dropped_total,
                            policy_version = response.policy_version,
                            "heartbeat acknowledged"
                        );
                        status.update(|s| s.connected = true).await;
                        // The control plane owns the cadence, so a fleet can be
                        // slowed down centrally without redeploying agents.
                        let requested = Duration::from_secs(response.heartbeat_interval_seconds.clamp(5, 3600));
                        if requested != interval {
                            info!(
                                previous = ?interval,
                                requested = ?requested,
                                "adopting the heartbeat interval requested by the control plane"
                            );
                            interval = requested;
                            // Scheduled one full interval out. `interval()`
                            // fires its first tick immediately, which would
                            // send an extra heartbeat the moment the cadence
                            // changed.
                            ticker = tokio::time::interval_at(
                                tokio::time::Instant::now() + interval,
                                interval,
                            );
                            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                        }
                    }
                    Err(TransportError::Unauthorized) => {
                        error!(
                            device_id = %identity.registration.device_id,
                            "the control plane rejected this device's identity; it may have been \
                             revoked. Telemetry will continue to be collected locally but not sent."
                        );
                        identity_rejected = true;
                        status
                            .update(|s| {
                                s.connected = false;
                                s.identity_rejected = true;
                            })
                            .await;
                    }
                    Err(err) => {
                        // Offline operation is normal (spec §37): keep
                        // collecting and retry on the next tick.
                        warn!(
                            beat = beats,
                            queued = stats.len,
                            error = %err,
                            "heartbeat failed; continuing to queue locally"
                        );
                        status.update(|s| s.connected = false).await;
                    }
                }
            }
            _ = posture_ticker.tick() => {
                let Some(identity) = identity else { continue };
                if identity_rejected {
                    continue;
                }

                // Collection shells out to system utilities, so it runs on the
                // blocking pool rather than stalling the async runtime.
                let signals = match tokio::task::spawn_blocking(netra_collect::posture::collect).await {
                    Ok(signals) => signals,
                    Err(err) => {
                        warn!(error = %err, "posture collection task failed");
                        continue;
                    }
                };

                let determined = signals.determined_count();
                let unknown = signals.collection_errors.len();

                match client
                    .posture(&identity.key, &identity.registration.device_uid, &PostureReport { signals })
                    .await
                {
                    Ok(response) => {
                        let weaknesses: Vec<String> = response
                            .weakest
                            .iter()
                            .map(|f| {
                                format!(
                                    "{} [{}/{}] — {}",
                                    f.label, f.contribution, f.maximum, f.detail
                                )
                            })
                            .collect();

                        info!(
                            trust_score = response.trust_score,
                            model = %response.model_version,
                            signals_determined = determined,
                            signals_unknown = unknown,
                            "posture reported and scored by the control plane"
                        );

                        status
                            .update(|s| {
                                s.trust_score = Some(response.trust_score);
                                s.trust_weaknesses = weaknesses;
                            })
                            .await;
                    }
                    Err(TransportError::Unauthorized) => {
                        error!("the control plane rejected this device while reporting posture");
                        identity_rejected = true;
                        status.update(|s| s.identity_rejected = true).await;
                    }
                    Err(err) => {
                        warn!(error = %err, "posture report failed; will retry on the next cycle");
                    }
                }
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
