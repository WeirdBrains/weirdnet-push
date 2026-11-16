//! Wake handles and control secrets.
//!
//! A wake handle is 32 random bytes (base64url): what a sender needs to wake a device, and
//! all it learns. The device shares it, sealed, only with its home relay and trusted peers.
//! The control secret, also 32 random bytes, stays on the device; it is needed to rotate or
//! revoke the handle. The server keeps only SHA-256 hashes of both.

use crate::error::{Error, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn random32() -> String {
    B64.encode(weirdnet_keys::random_bytes::<32>().expect("system randomness"))
}

fn check32(s: &str) -> Result<()> {
    match B64.decode(s) {
        Ok(b) if b.len() == 32 => Ok(()),
        _ => Err(Error::Invalid("expected 32 bytes, base64url".into())),
    }
}

/// An opaque wake handle.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WakeHandle(String);

impl std::fmt::Debug for WakeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WakeHandle({}…)", &self.0[..6])
    }
}

impl WakeHandle {
    /// A new random handle.
    pub fn generate() -> Self {
        Self(random32())
    }

    /// Parses a handle.
    pub fn parse(s: &str) -> Result<Self> {
        check32(s)?;
        Ok(Self(s.to_string()))
    }

    /// The handle text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The server's key for it: hex SHA-256.
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(self.0.as_bytes()))
    }
}

impl TryFrom<String> for WakeHandle {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        check32(&s)?;
        Ok(Self(s))
    }
}

impl From<WakeHandle> for String {
    fn from(h: WakeHandle) -> String {
        h.0
    }
}

/// The secret that controls a handle (rotate, revoke).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ControlSecret(String);

impl std::fmt::Debug for ControlSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ControlSecret(<redacted>)")
    }
}

impl ControlSecret {
    /// A new random secret.
    pub fn generate() -> Self {
        Self(random32())
    }

    /// The secret text (store it on the device).
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Hex SHA-256, as the server keeps it.
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(self.0.as_bytes()))
    }

    /// Constant-time check against a stored digest.
    pub fn matches(&self, digest: &str) -> bool {
        use subtle::ConstantTimeEq;
        self.digest().as_bytes().ct_eq(digest.as_bytes()).into()
    }
}

impl TryFrom<String> for ControlSecret {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        check32(&s)?;
        Ok(Self(s))
    }
}

impl From<ControlSecret> for String {
    fn from(h: ControlSecret) -> String {
        h.0
    }
}

/// What a device gives its home relay and trusted peers (sealed) so they can wake it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeCard {
    /// The push service base URL (`https://push.weirdbrains.com`).
    pub service: String,
    /// The handle.
    pub handle: WakeHandle,
    /// The device's push public key, hex.
    pub key: String,
}

impl WakeCard {
    /// The push public key.
    pub fn public_key(&self) -> Result<[u8; 32]> {
        let b = hex::decode(&self.key).map_err(|_| Error::Invalid("bad push key".into()))?;
        b.try_into().map_err(|_| Error::Invalid("bad push key".into()))
    }

    /// Seals a wake for this card.
    pub fn seal(&self, reason: crate::wake::Reason) -> Result<crate::wake::Payload96> {
        crate::wake::seal(&self.public_key()?, &self.handle, reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_and_secrets() {
        let h = WakeHandle::generate();
        assert_eq!(h.as_str().len(), 43);
        assert_eq!(WakeHandle::parse(h.as_str()).unwrap(), h);
        assert!(WakeHandle::parse("short").is_err());
        assert!(serde_json::from_str::<WakeHandle>("\"nope\"").is_err());
        assert_eq!(h.digest().len(), 64);
        let c = ControlSecret::generate();
        assert!(c.matches(&c.digest()));
        assert!(!ControlSecret::generate().matches(&c.digest()));
        assert!(!format!("{c:?}").contains(c.expose()));
    }
}
