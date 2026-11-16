//! Wake payloads: fixed-size ciphertexts sealed to one device's push key.
//!
//! ```text
//! payload    = 0x01 ‖ E (32) ‖ ChaCha20-Poly1305(key, nonce 0, plaintext (47), aad) (63)   = 96 bytes
//! key        = HKDF-SHA256(ikm = X25519(e, D), salt = E ‖ D, info = "weirdnet-push/wake/v1")
//! aad        = "weirdnet-push/wake/v1" ‖ handle
//! plaintext  = reason (1) ‖ random (16) ‖ unix seconds (8, big-endian) ‖ zeros (22)
//! ```
//!
//! `E` is a fresh X25519 key per payload, so the key is never reused and a zero nonce is
//! safe. The payload holds only a reason code, a random value and a time: no content, sender,
//! peer id, address or site name. Everything a push provider, the push service or a relay
//! sees is the handle (or device token), the time, and these 96 bytes.

use crate::error::{Error, Result};
use crate::handle::WakeHandle;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use std::collections::VecDeque;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use weirdnet_keys::exchange::ExchangeSecret;
use zeroize::Zeroizing;

/// The payload size in bytes.
pub const PAYLOAD_LEN: usize = 96;
const VERSION: u8 = 1;
const INFO: &[u8] = b"weirdnet-push/wake/v1";
const PLAIN_LEN: usize = 47;

/// Why a device is woken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// Sealed messages are waiting on the home relay or a desktop.
    MessageWaiting,
    /// A peer asks the device to connect.
    ConnectionRequested,
    /// A code this version doesn't know (newer senders).
    Other(u8),
}

impl Reason {
    /// The wire code.
    pub fn code(self) -> u8 {
        match self {
            Reason::MessageWaiting => 1,
            Reason::ConnectionRequested => 2,
            Reason::Other(c) => c,
        }
    }

    /// From the wire code.
    pub fn from_code(c: u8) -> Self {
        match c {
            1 => Reason::MessageWaiting,
            2 => Reason::ConnectionRequested,
            c => Reason::Other(c),
        }
    }
}

/// An opened wake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wake {
    /// Why.
    pub reason: Reason,
    /// The sender's random value (for replay checks).
    pub nonce: [u8; 16],
    /// When it was sealed (unix seconds, the sender's clock).
    pub at: u64,
}

/// A fixed-size wake payload.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Payload96(pub [u8; PAYLOAD_LEN]);

impl std::fmt::Debug for Payload96 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Payload96({}…)", hex::encode(&self.0[..6]))
    }
}

impl Payload96 {
    /// From bytes; they must be exactly [`PAYLOAD_LEN`] long.
    pub fn from_slice(b: &[u8]) -> Result<Self> {
        let a: [u8; PAYLOAD_LEN] = b.try_into().map_err(|_| Error::BadPayload)?;
        if a[0] != VERSION {
            return Err(Error::BadPayload);
        }
        Ok(Self(a))
    }

    /// Base64url without padding (128 characters), as carried in JSON and push messages.
    pub fn to_b64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }

    /// From [`Payload96::to_b64`].
    pub fn from_b64(s: &str) -> Result<Self> {
        use base64::Engine;
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).map_err(|_| Error::BadPayload)?;
        Self::from_slice(&b)
    }
}

impl serde::Serialize for Payload96 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_b64())
    }
}

impl<'de> serde::Deserialize<'de> for Payload96 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Payload96::from_b64(&s).map_err(serde::de::Error::custom)
    }
}

fn key(shared: &[u8; 32], e: &[u8; 32], d: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let mut k = Zeroizing::new([0u8; 32]);
    weirdnet_keys::kdf::hkdf_expand(shared, Some(&[&e[..], &d[..]].concat()), INFO, &mut k[..])?;
    Ok(k)
}

fn aad(handle: &WakeHandle) -> Vec<u8> {
    [INFO, handle.as_str().as_bytes()].concat()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Seals a wake for the device whose push public key is `device` and whose handle is
/// `handle`.
pub fn seal(device: &[u8; 32], handle: &WakeHandle, reason: Reason) -> Result<Payload96> {
    seal_at(device, handle, reason, now())
}

/// [`seal`] with a given time (tests).
pub fn seal_at(device: &[u8; 32], handle: &WakeHandle, reason: Reason, at: u64) -> Result<Payload96> {
    let e = ExchangeSecret::generate();
    let epub = e.public();
    let shared = e.agree(device).ok_or(Error::BadPayload)?;
    let k = key(&shared, &epub, device)?;
    let mut plain = Zeroizing::new([0u8; PLAIN_LEN]);
    plain[0] = reason.code();
    plain[1..17].copy_from_slice(&weirdnet_keys::random_bytes::<16>()?);
    plain[17..25].copy_from_slice(&at.to_be_bytes());
    let ct = ChaCha20Poly1305::new((&*k).into())
        .encrypt(&Nonce::default(), Payload { msg: &plain[..], aad: &aad(handle) })
        .map_err(|_| Error::BadPayload)?;
    let mut out = [0u8; PAYLOAD_LEN];
    out[0] = VERSION;
    out[1..33].copy_from_slice(&epub);
    out[33..].copy_from_slice(&ct);
    Ok(Payload96(out))
}

/// A device's push key (X25519). Keep the secret on the device; give the public key to the
/// home relay and trusted peers with the handle.
pub struct PushKey(ExchangeSecret);

impl std::fmt::Debug for PushKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PushKey(<redacted>)")
    }
}

impl PushKey {
    /// A new key.
    pub fn generate() -> Self {
        Self(ExchangeSecret::generate())
    }

    /// From stored secret bytes.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(ExchangeSecret::from_bytes(b))
    }

    /// The secret bytes, to store.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.0.to_bytes()
    }

    /// The public key.
    pub fn public(&self) -> [u8; 32] {
        self.0.public()
    }

    /// Opens a payload sent to `handle`.
    pub fn open(&self, handle: &WakeHandle, p: &Payload96) -> Result<Wake> {
        let mut epub = [0u8; 32];
        epub.copy_from_slice(&p.0[1..33]);
        let shared = self.0.agree(&epub).ok_or(Error::BadPayload)?;
        let k = key(&shared, &epub, &self.public())?;
        let plain = Zeroizing::new(
            ChaCha20Poly1305::new((&*k).into())
                .decrypt(&Nonce::default(), Payload { msg: &p.0[33..], aad: &aad(handle) })
                .map_err(|_| Error::BadPayload)?,
        );
        if plain.len() != PLAIN_LEN || plain[25..].iter().any(|&b| b != 0) {
            return Err(Error::BadPayload);
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&plain[1..17]);
        Ok(Wake { reason: Reason::from_code(plain[0]), nonce, at: u64::from_be_bytes(plain[17..25].try_into().unwrap()) })
    }
}

/// Refuses wakes seen before, older than `window`, or more than `window` ahead.
#[derive(Debug)]
pub struct ReplayGuard {
    window: Duration,
    seen: VecDeque<(u64, [u8; 16])>,
    max: usize,
}

impl ReplayGuard {
    /// A guard with a window (10 minutes is a good default) remembering up to `max` wakes.
    pub fn new(window: Duration, max: usize) -> Self {
        Self { window, seen: VecDeque::new(), max: max.max(1) }
    }

    /// Checks and remembers a wake at the device's time `now` (unix seconds).
    pub fn check(&mut self, w: &Wake, now: u64) -> Result<()> {
        let win = self.window.as_secs();
        if w.at + win < now || w.at > now + win {
            return Err(Error::Replay);
        }
        while self.seen.front().is_some_and(|(t, _)| t + win < now) {
            self.seen.pop_front();
        }
        if self.seen.iter().any(|(_, n)| n == &w.nonce) {
            return Err(Error::Replay);
        }
        if self.seen.len() >= self.max {
            self.seen.pop_front();
        }
        self.seen.push_back((w.at, w.nonce));
        Ok(())
    }

    /// [`ReplayGuard::check`] with the system clock.
    pub fn check_now(&mut self, w: &Wake) -> Result<()> {
        self.check(w, now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_fixed_size_and_bound_to_handle_and_key() {
        let k = PushKey::generate();
        let h = WakeHandle::generate();
        let p = seal(&k.public(), &h, Reason::MessageWaiting).unwrap();
        assert_eq!(p.0.len(), PAYLOAD_LEN);
        assert_eq!(p.to_b64().len(), 128);
        let w = k.open(&h, &p).unwrap();
        assert_eq!(w.reason, Reason::MessageWaiting);
        // Two payloads for the same wake differ entirely after the version byte.
        let q = seal(&k.public(), &h, Reason::MessageWaiting).unwrap();
        assert_ne!(p.0[1..], q.0[1..]);
        assert!(matches!(k.open(&WakeHandle::generate(), &p), Err(Error::BadPayload)));
        assert!(matches!(PushKey::generate().open(&h, &p), Err(Error::BadPayload)));
        for i in [0usize, 1, 40, 95] {
            let mut bad = p;
            bad.0[i] ^= 1;
            let r = Payload96::from_slice(&bad.0).and_then(|b| k.open(&h, &b));
            assert!(r.is_err(), "byte {i}");
        }
        assert!(Payload96::from_slice(&p.0[..95]).is_err());
        assert_eq!(Payload96::from_b64(&p.to_b64()).unwrap(), p);
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<Payload96>(&json).unwrap(), p);
        assert_eq!(Reason::from_code(Reason::ConnectionRequested.code()), Reason::ConnectionRequested);
        assert_eq!(Reason::from_code(9), Reason::Other(9));
    }

    #[test]
    fn replays_and_stale_wakes_are_refused() {
        let k = PushKey::generate();
        let h = WakeHandle::generate();
        let mut g = ReplayGuard::new(Duration::from_secs(600), 100);
        let p = seal_at(&k.public(), &h, Reason::ConnectionRequested, 10_000).unwrap();
        let w = k.open(&h, &p).unwrap();
        assert_eq!(w.at, 10_000);
        g.check(&w, 10_010).unwrap();
        assert!(matches!(g.check(&w, 10_011), Err(Error::Replay)));
        let old = k.open(&h, &seal_at(&k.public(), &h, Reason::MessageWaiting, 9_000).unwrap()).unwrap();
        assert!(matches!(g.check(&old, 10_010), Err(Error::Replay)));
        let ahead = k.open(&h, &seal_at(&k.public(), &h, Reason::MessageWaiting, 11_000).unwrap()).unwrap();
        assert!(matches!(g.check(&ahead, 10_010), Err(Error::Replay)));
    }
}
