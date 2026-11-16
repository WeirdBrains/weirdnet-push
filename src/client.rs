//! A client for the push service: devices register, rotate and revoke handles; senders
//! (relays and peers) wake devices; relays follow announcements.

use crate::api::{Announcement, Control, ErrorBody, Register, Registered, Transport, WakeRequest};
use crate::error::{Error, Result};
use crate::handle::{ControlSecret, WakeCard, WakeHandle};
use crate::wake::{Payload96, Reason};

/// A push service client.
#[derive(Debug, Clone)]
pub struct PushClient {
    base: String,
    http: reqwest::Client,
}

async fn check(r: reqwest::Response) -> Result<reqwest::Response> {
    let s = r.status();
    if s.is_success() {
        return Ok(r);
    }
    if s.as_u16() == 410 {
        return Err(Error::Gone);
    }
    if s.as_u16() == 401 || s.as_u16() == 403 {
        return Err(Error::Unauthorized);
    }
    let message = r.json::<ErrorBody>().await.map(|b| b.error).unwrap_or_default();
    Err(Error::Server { status: s.as_u16(), message })
}

impl PushClient {
    /// A client for the service at `base` (such as `https://push.weirdbrains.com`).
    pub fn new(base: impl Into<String>) -> Self {
        Self::with_client(base, reqwest::Client::builder().timeout(std::time::Duration::from_secs(20)).build().expect("HTTP client"))
    }

    /// With your own HTTP client.
    pub fn with_client(base: impl Into<String>, http: reqwest::Client) -> Self {
        Self { base: base.into().trim_end_matches('/').to_string(), http }
    }

    /// The service base URL.
    pub fn base(&self) -> &str {
        &self.base
    }

    fn url(&self, p: &str) -> String {
        format!("{}{p}", self.base)
    }

    /// Registers a device and gets a new handle.
    pub async fn register(&self, transport: Transport) -> Result<Registered> {
        Ok(check(self.http.post(self.url("/v1/register")).json(&Register { transport }).send().await?).await?.json().await?)
    }

    /// Replaces a handle with a new one (and optionally a new transport); the old one stops
    /// working at once. Tell the home relay and trusted peers the new handle.
    pub async fn rotate(&self, handle: &WakeHandle, control: &ControlSecret, transport: Option<Transport>) -> Result<Registered> {
        let body = Control { handle: handle.clone(), control: control.clone(), transport };
        Ok(check(self.http.post(self.url("/v1/rotate")).json(&body).send().await?).await?.json().await?)
    }

    /// Revokes a handle and forgets the device token (the per-device off switch).
    pub async fn unregister(&self, handle: &WakeHandle, control: &ControlSecret) -> Result<()> {
        let body = Control { handle: handle.clone(), control: control.clone(), transport: None };
        check(self.http.post(self.url("/v1/unregister")).json(&body).send().await?).await?;
        Ok(())
    }

    /// Sends a sealed payload. [`Error::Gone`] means the handle was revoked: forget it.
    pub async fn wake(&self, handle: &WakeHandle, payload: Payload96) -> Result<()> {
        check(self.http.post(self.url("/v1/wake")).json(&WakeRequest { handle: handle.clone(), payload }).send().await?).await?;
        Ok(())
    }

    /// Seals and sends a wake for a card.
    pub async fn wake_card(&self, card: &WakeCard, reason: Reason) -> Result<()> {
        self.wake(&card.handle, card.seal(reason)?).await
    }

    /// Follows wake announcements (relays). Calls `f` for each until the stream ends or `f`
    /// returns false.
    pub async fn announcements(&self, relay_token: &str, mut f: impl FnMut(Announcement) -> bool) -> Result<()> {
        let mut r = check(
            self.http
                .get(self.url("/v1/relay/announcements"))
                .bearer_auth(relay_token)
                .timeout(std::time::Duration::from_secs(365 * 86400))
                .send()
                .await?,
        )
        .await?;
        let mut buf = Vec::new();
        while let Some(chunk) = r.chunk().await? {
            buf.extend_from_slice(&chunk);
            while let Some(i) = buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buf.drain(..=i).collect();
                let line = &line[..line.len() - 1];
                if line.is_empty() {
                    continue; // keepalive
                }
                if let Ok(a) = serde_json::from_slice::<Announcement>(line)
                    && !f(a)
                {
                    return Ok(());
                }
            }
            if buf.len() > 64 << 10 {
                return Err(Error::Invalid("announcement line too long".into()));
            }
        }
        Ok(())
    }
}
