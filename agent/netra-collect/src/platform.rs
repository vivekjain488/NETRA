//! Platform backends behind the collection seam.
//!
//! Each function has one implementation per supported platform. Adding Linux
//! later means adding a module here, with no change to callers.

/// Returns the OS family name recorded on the device record.
pub fn os_name() -> &'static str {
    std::env::consts::OS
}

#[cfg(target_os = "macos")]
pub use macos::{hostname, os_version};

#[cfg(target_os = "windows")]
pub use windows::{hostname, os_version};

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub use fallback::{hostname, os_version};

/// macOS backend. Implemented and exercised by the crate's tests on the
/// development host.
#[cfg(target_os = "macos")]
mod macos {
    use std::process::Command;

    /// Reads the hostname via `scutil`, which returns the configured name
    /// rather than a transient DHCP name.
    pub fn hostname() -> Option<String> {
        run("scutil", &["--get", "ComputerName"]).or_else(|| run("hostname", &["-s"]))
    }

    /// Reads the macOS product version, e.g. "15.3.1".
    pub fn os_version() -> Option<String> {
        run("sw_vers", &["-productVersion"])
    }

    fn run(program: &str, args: &[&str]) -> Option<String> {
        let output = Command::new(program).args(args).output().ok()?;
        if !output.status.success() {
            return None;
        }
        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    }
}

/// Windows backend.
///
/// **UNTESTED.** This compiles only under `cfg(windows)` and has not been run
/// on Windows hardware. It must not be reported as working until it has been.
#[cfg(target_os = "windows")]
mod windows {
    /// Reads the NetBIOS computer name, which Windows always sets.
    pub fn hostname() -> Option<String> {
        std::env::var("COMPUTERNAME")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    /// Reads the OS build from the registry via `reg query`.
    ///
    /// A future phase should replace this with a direct `RtlGetVersion` call:
    /// spawning a process per lookup is acceptable at enrollment but not on a
    /// hot path.
    pub fn os_version() -> Option<String> {
        let output = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "/v",
                "DisplayVersion",
            ])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        text.lines()
            .find(|line| line.contains("DisplayVersion"))
            .and_then(|line| line.split_whitespace().last())
            .map(|v| v.to_string())
            .filter(|v| !v.is_empty())
    }
}

/// Backend for platforms with no dedicated implementation yet.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod fallback {
    pub fn hostname() -> Option<String> {
        std::env::var("HOSTNAME").ok().filter(|v| !v.is_empty())
    }

    pub fn os_version() -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_name_is_reported() {
        assert!(!os_name().is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_backend_reads_hostname_and_version() {
        assert!(hostname().is_some(), "scutil/hostname lookup failed");

        let version = os_version().expect("sw_vers lookup failed");
        assert!(
            version.chars().next().is_some_and(|c| c.is_ascii_digit()),
            "unexpected macOS version format: {version}"
        );
    }
}
