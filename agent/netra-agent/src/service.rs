//! Running the agent as an operating-system service.
//!
//! The agent is a background service on a managed endpoint, not something a
//! user starts. On Windows that means the Service Control Manager; on macOS and
//! Linux it means a launchd or systemd unit invoking the same binary in the
//! foreground, which is why the foreground path stays first-class.
//!
//! **The Windows path is UNTESTED.** It compiles only under `cfg(windows)` and
//! has not been run on Windows hardware. It must not be described as working
//! until it has been.
//!
//! # Privileges
//!
//! The agent needs no administrator rights for anything it currently does.
//! Installing it as a service does require them, as installing any service
//! does, but the running service can hold an ordinary account. On Windows,
//! BitLocker status is the one signal that would benefit from elevation; when
//! it is unavailable the signal is reported as unknown rather than guessed.

/// How the agent was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Started directly, logging to stdout. Used in development and by launchd
    /// and systemd units.
    Foreground,
    /// Started by the Windows Service Control Manager.
    WindowsService,
}

/// Decides how this process was launched.
///
/// The `--service` flag is explicit rather than inferred: guessing wrong means
/// either a service that never reports ready, or a foreground run that tries to
/// talk to a service controller that is not there.
pub fn detect_mode() -> Mode {
    if std::env::args().any(|arg| arg == "--service") {
        return Mode::WindowsService;
    }
    Mode::Foreground
}

#[cfg(windows)]
pub mod windows_service_host {
    //! **UNTESTED.** Windows Service Control Manager integration.

    use std::ffi::OsString;
    use std::time::Duration;

    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    /// The name the service is registered under.
    pub const SERVICE_NAME: &str = "NetraAgent";

    windows_service::define_windows_service!(ffi_service_main, service_main);

    /// Entry point invoked by the Service Control Manager.
    pub fn run() -> Result<(), windows_service::Error> {
        windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(err) = run_service() {
            // The service controller has no console, so a failure here is
            // reported through the agent's own log rather than stderr.
            tracing::error!(error = %err, "the NETRA agent service stopped");
        }
    }

    fn run_service() -> Result<(), windows_service::Error> {
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();

        let handler = move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };

        let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;

        let running = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        };
        status_handle.set_service_status(running.clone())?;

        // The agent's own runtime owns the work; this thread only waits for the
        // controller to ask it to stop.
        let worker = std::thread::spawn(crate::run_agent_blocking);
        let _ = shutdown_rx.recv();

        crate::request_shutdown();
        let _ = worker.join();

        status_handle.set_service_status(ServiceStatus {
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            ..running
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreground_is_the_default() {
        // A developer running the binary directly must not end up waiting for a
        // service controller that is not there.
        assert_eq!(detect_mode(), Mode::Foreground);
    }
}
