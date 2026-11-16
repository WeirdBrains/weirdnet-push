use crate::api::Announcement;
use crate::error::{Error, Result};
use crate::handle::WakeHandle;
use crate::wake::Payload96;
use axum::body::Body;
use axum::response::Response;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::sync::broadcast;

/// The relay wake path: relays that follow this server get every relay-path wake and pass
/// it on when the device with that handle is connected to them.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// SHA-256 digests (hex) of the relay tokens allowed to follow.
    pub token_digests: Vec<String>,
}

/// Fans relay-path wakes out to the following relays.
#[derive(Debug)]
pub struct RelayHub {
    digests: Vec<String>,
    tx: broadcast::Sender<Announcement>,
}

/// The digest a relay token is listed by.
pub fn token_digest(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

impl RelayHub {
    /// A hub for `config`.
    pub fn new(config: &RelayConfig) -> Result<Self> {
        for d in &config.token_digests {
            if d.len() != 64 || !d.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::Invalid("relay token_digests must be hex SHA-256".into()));
            }
        }
        Ok(Self { digests: config.token_digests.iter().map(|d| d.to_ascii_lowercase()).collect(), tx: broadcast::channel(4096).0 })
    }

    /// True if `token` may follow.
    pub fn allows(&self, token: &str) -> bool {
        use subtle::ConstantTimeEq;
        let d = token_digest(token);
        !token.is_empty() && self.digests.iter().fold(false, |ok, x| ok | bool::from(x.as_bytes().ct_eq(d.as_bytes())))
    }

    /// How many relays follow now.
    pub fn followers(&self) -> usize {
        self.tx.receiver_count()
    }

    pub(crate) fn announce(&self, handle: &WakeHandle, payload: Payload96) {
        let _ = self.tx.send(Announcement { handle: handle.clone(), payload });
    }

    pub(crate) fn stream(&self) -> Response {
        let rx = self.tx.subscribe();
        let s = futures_util::stream::unfold(rx, |mut rx| async move {
            loop {
                match tokio::time::timeout(Duration::from_secs(25), rx.recv()).await {
                    Err(_) => return Some((Ok::<_, std::io::Error>(b"\n".to_vec()), rx)), // keepalive
                    Ok(Ok(a)) => {
                        let mut line = serde_json::to_vec(&a).unwrap();
                        line.push(b'\n');
                        return Some((Ok(line), rx));
                    }
                    Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                        tracing::warn!(dropped = n, "a relay fell behind");
                    }
                    Ok(Err(broadcast::error::RecvError::Closed)) => return None,
                }
            }
        });
        Response::builder().header("content-type", "application/x-ndjson").header("cache-control", "no-store").body(Body::from_stream(s)).unwrap()
    }
}
