/// Errors from this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A wake payload is the wrong size, malformed, or doesn't open with this key and handle.
    #[error("bad wake payload")]
    BadPayload,
    /// A payload was seen before or is too old or too far in the future.
    #[error("replayed or stale wake")]
    Replay,
    /// The handle is unknown or revoked.
    #[error("unknown or revoked wake handle")]
    Gone,
    /// The control secret doesn't match.
    #[error("wrong control secret")]
    Unauthorized,
    /// A request or config is invalid.
    #[error("invalid: {0}")]
    Invalid(String),
    /// Delivery to APNs, FCM or a relay failed.
    #[error("delivery: {0}")]
    Delivery(String),
    /// The server answered with an error.
    #[error("server: {status}: {message}")]
    Server {
        /// HTTP status.
        status: u16,
        /// Its message.
        message: String,
    },
    /// HTTP transport.
    #[cfg(feature = "client")]
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    /// Key material.
    #[error("keys: {0}")]
    Keys(String),
    /// I/O.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<weirdnet_keys::KeysError> for Error {
    fn from(e: weirdnet_keys::KeysError) -> Self {
        Error::Keys(e.to_string())
    }
}

/// `Result` with [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;
