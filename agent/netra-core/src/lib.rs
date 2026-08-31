//! Core types shared by every part of the NETRA endpoint agent.
//!
//! This crate is deliberately platform-independent and dependency-light: it
//! holds the event model, the agent configuration and the bounded local queue.
//! Platform-specific collection lives in `netra-collect`.

pub mod config;
pub mod event;
pub mod identity;
pub mod keystore;
pub mod queue;
pub mod state;

pub use config::AgentConfig;
pub use event::{Event, EventType, Severity};
pub use identity::{DeviceKey, SigningInput};
pub use keystore::{KeyStore, Protection};
pub use queue::{EventQueue, QueueStats};
pub use state::{DeviceRegistration, StateStore};
