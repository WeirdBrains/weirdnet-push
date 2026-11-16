#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

pub mod api;
#[cfg(feature = "client")]
pub mod client;
mod error;
pub mod handle;
#[cfg(feature = "server")]
pub mod server;
pub mod wake;

#[cfg(feature = "client")]
pub use client::PushClient;
pub use error::{Error, Result};
pub use handle::{ControlSecret, WakeCard, WakeHandle};
pub use wake::{PAYLOAD_LEN, Payload96, PushKey, Reason, ReplayGuard, Wake};
