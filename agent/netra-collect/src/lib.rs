//! Telemetry collectors for the NETRA endpoint agent.
//!
//! # Platform strategy
//!
//! The specification targets Windows first. Collection is therefore expressed
//! as a [`Collector`] trait with one backend per platform, selected at compile
//! time. This keeps every platform-specific call behind a single seam.
//!
//! **Verification status**, stated honestly:
//!
//! - `platform::macos` — implemented and tested on the development host.
//! - `platform::windows` — compiled only under `cfg(windows)` and **not yet
//!   executed on Windows hardware**. It is marked as such at each definition
//!   and must not be described as working until it has been run there.

pub mod host;
pub mod platform;

use netra_core::Event;

/// A source of security telemetry.
///
/// `collect` is called on the agent's schedule and must be cheap: spec §45
/// requires that no continuous heavy analysis runs on the endpoint.
pub trait Collector {
    /// Stable identifier used in logs and health reporting.
    fn name(&self) -> &'static str;

    /// Returns any events observed since the previous call.
    fn collect(&mut self) -> Vec<Event>;
}
