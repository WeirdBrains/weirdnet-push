//! The relay wake path: the wire protocol between a device, its home relay and senders.
//!
//! For builds without APNs or FCM (F-Droid, sideloaded Android), the device opts in to keep
//! a stream of [`PROTOCOL`] open to its home relay (on Android, from a foreground service)
//! and subscribes with its wake handles. Wakes reach the relay in two ways:
//!
//! - a sender (a trusted peer that holds the device's [`crate::WakeCard`]) opens a stream to
//!   the relay and sends [`ToRelay::Deliver`];
//! - the relay follows a push service's announcements
//!   ([`crate::PushClient::announcements`]) for devices that registered
//!   [`crate::api::Transport::Relay`] there, so wakes originating from WeirdBrains reach
//!   devices behind NAT.
//!
//! The relay passes the sealed payload on unchanged ([`FromRelay::Wake`]); only the device
//! can open it. Frames are JSON, each after a 2-byte big-endian length, at most
//! [`MAX_FRAME`] bytes. This module is transport-neutral: it works on any
//! `futures` `AsyncRead + AsyncWrite`, such as a `weirdnet-net` stream.

use crate::error::{Error, Result};
use crate::handle::WakeHandle;
use crate::wake::Payload96;
use futures_util::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde::{Deserialize, Serialize};

/// The stream protocol id.
pub const PROTOCOL: &str = "/weirdnet/wake/1";
/// The largest frame.
pub const MAX_FRAME: usize = 2048;
/// The most handles one subscription may carry.
pub const MAX_HANDLES: usize = 8;

/// From a device or sender to the relay. The first frame of a stream decides its kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "t")]
pub enum ToRelay {
    /// A device: deliver wakes for these handles on this stream while it stays open.
    Subscribe {
        /// At most [`MAX_HANDLES`].
        handles: Vec<WakeHandle>,
    },
    /// A sender: pass this payload on to the device with this handle.
    Deliver {
        /// Whom.
        handle: WakeHandle,
        /// The sealed payload.
        payload: Payload96,
    },
}

/// What happened to a delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    /// Passed to a connected device.
    Delivered,
    /// The device was connected recently; it is held briefly for its reconnect.
    Held,
    /// No device with that handle is connected here.
    Offline,
    /// Too many wakes for this handle just now; dropped.
    TooMany,
}

/// From the relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "t")]
pub enum FromRelay {
    /// The subscription is in place.
    Subscribed {
        /// How many handles.
        handles: usize,
        /// The relay sends [`FromRelay::Keepalive`] at least this often; treat twice this
        /// without a frame as a lost connection and reconnect.
        keepalive_s: u32,
    },
    /// A wake for one of the subscribed handles.
    Wake {
        /// Which handle.
        handle: WakeHandle,
        /// The sealed payload (open it with [`crate::PushKey::open`]).
        payload: Payload96,
    },
    /// Nothing to say.
    Keepalive,
    /// The answer to [`ToRelay::Deliver`].
    Delivered {
        /// What happened.
        status: Delivery,
    },
    /// The request was refused.
    Error {
        /// Why.
        error: String,
    },
}

/// Writes one frame.
pub async fn write<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<()> {
    let body = serde_json::to_vec(msg).map_err(|e| Error::Invalid(e.to_string()))?;
    if body.len() > MAX_FRAME {
        return Err(Error::Invalid("frame too large".into()));
    }
    let mut b = (body.len() as u16).to_be_bytes().to_vec();
    b.extend(body);
    w.write_all(&b).await?;
    w.flush().await?;
    Ok(())
}

/// Reads one frame; `None` at a clean end of stream.
pub async fn read<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(r: &mut R) -> Result<Option<T>> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let n = u16::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(Error::Invalid("bad frame length".into()));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map(Some).map_err(|e| Error::Invalid(format!("bad frame: {e}")))
}

/// A device's open subscription.
pub struct Subscription<S> {
    io: S,
    /// The relay's keepalive interval.
    pub keepalive_s: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Subscription<S> {
    /// Subscribes `handles` on a fresh stream to the home relay.
    pub async fn start(mut io: S, handles: &[WakeHandle]) -> Result<Self> {
        if handles.is_empty() || handles.len() > MAX_HANDLES {
            return Err(Error::Invalid(format!("subscribe 1 to {MAX_HANDLES} handles")));
        }
        write(&mut io, &ToRelay::Subscribe { handles: handles.to_vec() }).await?;
        match read(&mut io).await? {
            Some(FromRelay::Subscribed { keepalive_s, .. }) => Ok(Self { io, keepalive_s }),
            Some(FromRelay::Error { error }) => Err(Error::Delivery(error)),
            _ => Err(Error::Invalid("unexpected answer to subscribe".into())),
        }
    }

    /// The next wake. Keepalives are skipped; `None` when the relay closed the stream. Wrap
    /// it in a timeout of twice [`Subscription::keepalive_s`] to notice a dead connection.
    pub async fn next(&mut self) -> Result<Option<(WakeHandle, Payload96)>> {
        loop {
            match read(&mut self.io).await? {
                None => return Ok(None),
                Some(FromRelay::Wake { handle, payload }) => return Ok(Some((handle, payload))),
                Some(FromRelay::Keepalive) => continue,
                Some(FromRelay::Error { error }) => return Err(Error::Delivery(error)),
                Some(_) => return Err(Error::Invalid("unexpected frame".into())),
            }
        }
    }

    /// The next frame, keepalives included (to reset an idle timer on each).
    pub async fn next_frame(&mut self) -> Result<Option<FromRelay>> {
        read(&mut self.io).await
    }
}

/// A sender: passes a sealed payload to the device's home relay over a fresh stream.
pub async fn deliver<S: AsyncRead + AsyncWrite + Unpin>(mut io: S, handle: &WakeHandle, payload: Payload96) -> Result<Delivery> {
    write(&mut io, &ToRelay::Deliver { handle: handle.clone(), payload }).await?;
    let r = read(&mut io).await?;
    let _ = io.close().await;
    match r {
        Some(FromRelay::Delivered { status }) => Ok(status),
        Some(FromRelay::Error { error }) => Err(Error::Delivery(error)),
        _ => Err(Error::Invalid("unexpected answer to deliver".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_are_bounded() {
        futures_util::FutureExt::now_or_never(async {
            let h = WakeHandle::generate();
            let p = Payload96::from_slice(&[[1u8].as_slice(), &[7u8; 95]].concat()).unwrap();
            let mut buf = Vec::new();
            write(&mut buf, &ToRelay::Deliver { handle: h.clone(), payload: p }).await.unwrap();
            write(&mut buf, &FromRelay::Keepalive).await.unwrap();
            let mut r = futures_util::io::Cursor::new(buf);
            assert_eq!(read::<_, ToRelay>(&mut r).await.unwrap(), Some(ToRelay::Deliver { handle: h, payload: p }));
            assert_eq!(read::<_, FromRelay>(&mut r).await.unwrap(), Some(FromRelay::Keepalive));
            assert_eq!(read::<_, FromRelay>(&mut r).await.unwrap(), None);
            let mut big = futures_util::io::Cursor::new([0xffu8, 0xff].to_vec());
            assert!(read::<_, FromRelay>(&mut big).await.is_err());
            let mut zero = futures_util::io::Cursor::new([0u8, 0].to_vec());
            assert!(read::<_, FromRelay>(&mut zero).await.is_err());
            // A payload must be a valid version-1 payload of the exact size.
            let bad = br#"{"t":"deliver","handle":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","payload":"AA"}"#;
            let mut b = (bad.len() as u16).to_be_bytes().to_vec();
            b.extend(bad);
            assert!(read::<_, ToRelay>(&mut futures_util::io::Cursor::new(b)).await.is_err());
        })
        .unwrap();
    }
}
