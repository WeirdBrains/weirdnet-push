//! The push service's HTTP API (JSON).
//!
//! | Method and path | Body | Answer |
//! | --- | --- | --- |
//! | `POST /v1/register` | [`Register`] | [`Registered`] |
//! | `POST /v1/rotate` | [`Control`] | [`Registered`] (the old handle is revoked) |
//! | `POST /v1/unregister` | [`Control`] | 204 |
//! | `POST /v1/wake` | [`WakeRequest`] | 202, or 410 if the handle is unknown or revoked |
//! | `GET /v1/relay/announcements` | bearer relay token | NDJSON stream of [`Announcement`] |
//! | `GET /v1/health` | | 200 `ok` |

use crate::handle::{ControlSecret, WakeHandle};
use crate::wake::Payload96;
use serde::{Deserialize, Serialize};

/// How the service reaches a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Apple Push Notification service (iOS; required for background wake there).
    Apns {
        /// The APNs device token, hex.
        token: String,
        /// The app's bundle id (the APNs topic).
        topic: String,
        /// Use the APNs development environment.
        #[serde(default)]
        sandbox: bool,
    },
    /// Firebase Cloud Messaging (Android Play builds).
    Fcm {
        /// The FCM registration token.
        token: String,
    },
    /// Wake announcements carried by Weirdnet relays (opt-in; F-Droid and builds without
    /// Google services). The device's home relay delivers over the connection it keeps.
    Relay,
}

impl Transport {
    /// "apns", "fcm" or "relay".
    pub fn kind(&self) -> &'static str {
        match self {
            Transport::Apns { .. } => "apns",
            Transport::Fcm { .. } => "fcm",
            Transport::Relay => "relay",
        }
    }
}

/// `POST /v1/register`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Register {
    /// How to reach the device.
    pub transport: Transport,
}

/// A new handle and its control secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registered {
    /// Share (sealed) with the home relay and trusted peers.
    pub handle: WakeHandle,
    /// Keep on the device.
    pub control: ControlSecret,
}

/// `POST /v1/rotate` and `POST /v1/unregister`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Control {
    /// The handle.
    pub handle: WakeHandle,
    /// Its control secret.
    pub control: ControlSecret,
    /// For rotate: a new transport (such as a refreshed APNs token); `None` keeps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
}

/// `POST /v1/wake`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeRequest {
    /// Whom to wake.
    pub handle: WakeHandle,
    /// The sealed payload.
    pub payload: Payload96,
}

/// One line of `GET /v1/relay/announcements`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announcement {
    /// The handle the device told its home relay.
    pub handle: WakeHandle,
    /// The sealed payload to pass on.
    pub payload: Payload96,
}

/// An error body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// What went wrong.
    pub error: String,
}
