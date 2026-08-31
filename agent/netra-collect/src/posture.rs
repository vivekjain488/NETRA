//! Endpoint security posture collection.
//!
//! The agent reports what it observed; it does not score itself. An endpoint
//! that computed its own trust score would be asserting its own
//! trustworthiness, and a compromised one would simply report a perfect score.
//! Scoring happens in the control plane (spec §43).
//!
//! Every signal is `Option<bool>`, so "could not determine" stays distinct from
//! "determined to be off". A collector that fails must never look like one that
//! found a control enabled.
//!
//! # Required permissions
//!
//! Collection runs as the agent's own account. Nothing here needs elevation on
//! macOS. On Windows, BitLocker status is the one signal that normally requires
//! administrator rights; when it is unavailable the signal is reported as
//! unknown with the reason attached, rather than guessed.

use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// How long any single probe may take before it is abandoned. A hung system
/// utility must not stall the agent's collection cycle.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Security signals observed on the endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostureSignals {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_encryption: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_boot: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screen_lock: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anti_malware: Option<bool>,

    pub os_name: String,
    pub os_version: String,

    /// Signals that could not be determined, and why. Reporting the failure is
    /// more useful to an operator than silently omitting the field.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub collection_errors: BTreeMap<String, String>,
}

impl PostureSignals {
    /// Number of signals that were successfully determined.
    pub fn determined_count(&self) -> usize {
        [
            self.disk_encryption,
            self.secure_boot,
            self.firewall,
            self.screen_lock,
            self.anti_malware,
        ]
        .iter()
        .filter(|value| value.is_some())
        .count()
    }
}

/// Collects posture for this endpoint.
pub fn collect() -> PostureSignals {
    let host = crate::host::HostInfo::detect();
    let mut signals = PostureSignals {
        os_name: host.os_name,
        os_version: host.os_version,
        ..Default::default()
    };

    platform::collect_into(&mut signals);
    signals
}

/// Runs a command with a bounded wait and returns its stdout.
///
/// The timeout matters: these are system utilities invoked on a user's laptop,
/// and one of them hanging must not stall telemetry collection.
fn probe(program: &str, args: &[&str]) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run {program}: {e}"))?;

    let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{program} did not finish within {PROBE_TIMEOUT:?}"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => return Err(format!("waiting for {program} failed: {e}")),
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("reading {program} output failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} exited with {}",
            output.status.code().unwrap_or(-1)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stdout.is_empty() {
        return Ok(stdout);
    }

    // Several macOS system utilities report their result on stderr while
    // exiting successfully. Treating an empty stdout as failure would leave
    // those signals permanently unknown.
    Ok(String::from_utf8_lossy(&output.stderr).trim().to_string())
}

/// Records a determined signal, or the reason it could not be determined.
fn record(
    signals: &mut PostureSignals,
    name: &str,
    result: Result<bool, String>,
    assign: impl FnOnce(&mut PostureSignals, bool),
) {
    match result {
        Ok(value) => assign(signals, value),
        Err(reason) => {
            signals.collection_errors.insert(name.to_string(), reason);
        }
    }
}

/// macOS collectors. Implemented and exercised on the development host.
#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    pub fn collect_into(signals: &mut PostureSignals) {
        record(signals, "disk_encryption", filevault(), |s, v| s.disk_encryption = Some(v));
        record(signals, "secure_boot", system_integrity_protection(), |s, v| {
            s.secure_boot = Some(v)
        });
        record(signals, "firewall", firewall(), |s, v| s.firewall = Some(v));
        record(signals, "screen_lock", screen_lock(), |s, v| s.screen_lock = Some(v));

        // macOS has no supported way to query XProtect or Gatekeeper state that
        // maps cleanly onto "real-time protection is active". Reporting unknown
        // is more honest than reporting a value that does not mean that.
        signals.collection_errors.insert(
            "anti_malware".to_string(),
            "macOS exposes no equivalent real-time protection status".to_string(),
        );
    }

    /// FileVault full-disk encryption. Readable without elevation.
    fn filevault() -> Result<bool, String> {
        let output = probe("fdesetup", &["status"])?;
        if output.contains("FileVault is On") {
            Ok(true)
        } else if output.contains("FileVault is Off") {
            Ok(false)
        } else {
            Err(format!("unrecognised fdesetup output: {output}"))
        }
    }

    /// System Integrity Protection, the closest macOS analogue to Secure Boot.
    fn system_integrity_protection() -> Result<bool, String> {
        let output = probe("csrutil", &["status"])?;
        let lowered = output.to_lowercase();
        if lowered.contains("enabled") {
            Ok(true)
        } else if lowered.contains("disabled") {
            Ok(false)
        } else {
            Err(format!("unrecognised csrutil output: {output}"))
        }
    }

    /// Application firewall state.
    ///
    /// Read through `socketfilterfw` rather than the `com.apple.alf` preference
    /// domain: that plist no longer exists on current macOS, so reading it left
    /// this signal permanently unknown.
    fn firewall() -> Result<bool, String> {
        let output = probe(
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            &["--getglobalstate"],
        )?;
        let lowered = output.to_lowercase();
        if lowered.contains("enabled") {
            Ok(true)
        } else if lowered.contains("disabled") {
            Ok(false)
        } else {
            Err(format!("unrecognised firewall state: {output}"))
        }
    }

    /// Whether a password is required to unlock after sleep or screensaver.
    ///
    /// `sysadminctl -screenLock status` reports either that the lock is off or
    /// the delay before it applies. The delay itself is a policy question for a
    /// later phase; what matters here is whether a lock is configured at all.
    fn screen_lock() -> Result<bool, String> {
        let output = probe("sysadminctl", &["-screenLock", "status"])?;
        let lowered = output.to_lowercase();
        if lowered.contains("screenlock delay is") {
            Ok(true)
        } else if lowered.contains("off") {
            Ok(false)
        } else {
            Err(format!("unrecognised sysadminctl output: {output}"))
        }
    }
}

/// Windows collectors.
///
/// **UNTESTED.** These compile only under `cfg(windows)` and have not been run
/// on Windows hardware. They must not be described as working until they have.
///
/// Permissions: Secure Boot, firewall, screen lock and Defender status are all
/// readable by a standard user. BitLocker status normally requires
/// administrator rights; when it is unavailable the signal is reported as
/// unknown with the reason, never guessed.
#[cfg(target_os = "windows")]
mod platform {
    use super::*;

    pub fn collect_into(signals: &mut PostureSignals) {
        record(signals, "disk_encryption", bitlocker(), |s, v| s.disk_encryption = Some(v));
        record(signals, "secure_boot", secure_boot(), |s, v| s.secure_boot = Some(v));
        record(signals, "firewall", firewall(), |s, v| s.firewall = Some(v));
        record(signals, "screen_lock", screen_lock(), |s, v| s.screen_lock = Some(v));
        record(signals, "anti_malware", defender(), |s, v| s.anti_malware = Some(v));
    }

    /// Runs a PowerShell expression and returns its trimmed output.
    fn powershell(expression: &str) -> Result<String, String> {
        probe(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", expression],
        )
    }

    fn parse_bool(output: &str, name: &str) -> Result<bool, String> {
        match output.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            other => Err(format!("unrecognised {name} value: {other}")),
        }
    }

    /// BitLocker protection on the system volume. Usually requires elevation.
    fn bitlocker() -> Result<bool, String> {
        let output = powershell(
            "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq 'On'",
        )
        .map_err(|e| format!("{e} (BitLocker status usually requires administrator rights)"))?;
        parse_bool(&output, "BitLocker protection status")
    }

    /// UEFI Secure Boot. Throws on legacy BIOS systems, which is reported as
    /// unknown rather than as disabled.
    fn secure_boot() -> Result<bool, String> {
        let output = powershell(
            "try { [bool](Confirm-SecureBootUEFI) } catch { 'unsupported' }",
        )?;
        if output.trim().eq_ignore_ascii_case("unsupported") {
            return Err("this system does not report Secure Boot state".to_string());
        }
        parse_bool(&output, "Secure Boot state")
    }

    /// Windows Defender Firewall on the current profile.
    fn firewall() -> Result<bool, String> {
        let output = powershell(
            "(Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false } | Measure-Object).Count -eq 0",
        )?;
        parse_bool(&output, "firewall state")
    }

    /// Whether the screensaver requires a password to dismiss.
    fn screen_lock() -> Result<bool, String> {
        let output = powershell(
            "(Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaverIsSecure -ErrorAction Stop).ScreenSaverIsSecure",
        )?;
        parse_bool(&output, "ScreenSaverIsSecure")
    }

    /// Microsoft Defender real-time protection.
    fn defender() -> Result<bool, String> {
        let output = powershell("(Get-MpComputerStatus).RealTimeProtectionEnabled")?;
        parse_bool(&output, "real-time protection state")
    }
}

/// Collectors for platforms with no dedicated implementation yet.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod platform {
    use super::*;

    pub fn collect_into(signals: &mut PostureSignals) {
        signals.collection_errors.insert(
            "platform".to_string(),
            format!("posture collection is not implemented for {}", std::env::consts::OS),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_reports_the_operating_system() {
        let signals = collect();

        assert!(!signals.os_name.is_empty());
        assert!(!signals.os_version.is_empty());
    }

    #[test]
    fn unknown_signals_carry_a_reason() {
        // A collector that failed must explain itself rather than leaving the
        // operator with a silently missing field.
        let signals = collect();

        for name in ["disk_encryption", "secure_boot", "firewall", "screen_lock", "anti_malware"] {
            let determined = match name {
                "disk_encryption" => signals.disk_encryption.is_some(),
                "secure_boot" => signals.secure_boot.is_some(),
                "firewall" => signals.firewall.is_some(),
                "screen_lock" => signals.screen_lock.is_some(),
                _ => signals.anti_malware.is_some(),
            };
            if !determined {
                assert!(
                    signals.collection_errors.contains_key(name),
                    "{name} was not determined and has no recorded reason: {signals:?}"
                );
            }
        }
    }

    #[test]
    fn signals_round_trip_through_json() {
        let signals = collect();
        let encoded = serde_json::to_string(&signals).expect("serializes");
        let decoded: PostureSignals = serde_json::from_str(&encoded).expect("deserializes");

        assert_eq!(signals, decoded);
    }

    #[test]
    fn absent_signals_are_omitted_rather_than_null() {
        // Sending nulls for every undetermined control would inflate every
        // report on a bandwidth-constrained endpoint.
        let signals = PostureSignals {
            os_name: "macos".to_string(),
            os_version: "26".to_string(),
            ..Default::default()
        };

        let encoded = serde_json::to_string(&signals).expect("serializes");
        assert!(!encoded.contains("null"), "got {encoded}");
        assert!(!encoded.contains("disk_encryption"), "got {encoded}");
    }

    #[test]
    fn no_score_is_computed_on_the_endpoint() {
        // The endpoint reports facts; the control plane decides what they are
        // worth. A score field here would be the endpoint asserting its own
        // trustworthiness.
        let encoded = serde_json::to_string(&collect()).expect("serializes");

        for forbidden in ["score", "trust", "verified"] {
            assert!(!encoded.contains(forbidden), "posture report contains {forbidden}: {encoded}");
        }
    }

    #[test]
    fn probe_reports_a_missing_program() {
        assert!(probe("netra-no-such-program", &[]).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_determines_every_signal_it_can() {
        // All four are readable without elevation on a supported macOS, so a
        // failure here means a collector has broken — which is exactly what
        // happened when the com.apple.alf preference domain was removed.
        let signals = collect();

        for (name, determined) in [
            ("disk_encryption (FileVault)", signals.disk_encryption.is_some()),
            ("secure_boot (SIP)", signals.secure_boot.is_some()),
            ("firewall", signals.firewall.is_some()),
            ("screen_lock", signals.screen_lock.is_some()),
        ] {
            assert!(
                determined,
                "{name} was not determined: {:?}",
                signals.collection_errors
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reports_anti_malware_as_unavailable_not_false() {
        // Reporting "no real-time protection" would be wrong: macOS simply has
        // no equivalent status to read.
        let signals = collect();

        assert!(signals.anti_malware.is_none());
        assert!(signals.collection_errors.contains_key("anti_malware"));
    }
}
