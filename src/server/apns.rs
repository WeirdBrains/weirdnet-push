use crate::error::{Error, Result};
use crate::wake::Payload96;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// APNs with token-based (`.p8`) authentication.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApnsConfig {
    /// The `.p8` signing key from the Apple developer account.
    pub key: PathBuf,
    /// Its key id.
    pub key_id: String,
    /// The team id.
    pub team_id: String,
    /// Bundle ids this server delivers for.
    pub topics: Vec<String>,
    /// Override the production endpoint (tests).
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Override the development endpoint (tests).
    #[serde(default)]
    pub sandbox_endpoint: Option<String>,
}

/// An APNs sender.
pub struct Apns {
    config: ApnsConfig,
    key: jsonwebtoken::EncodingKey,
    http: reqwest::Client,
    jwt: Mutex<Option<(String, Instant)>>,
}

impl std::fmt::Debug for Apns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Apns").field("key_id", &self.config.key_id).field("topics", &self.config.topics).finish()
    }
}

#[derive(serde::Serialize)]
struct Claims<'a> {
    iss: &'a str,
    iat: u64,
}

/// The text shown if the Notification Service Extension can't run; the real alert is made
/// on the device after decrypting.
pub const PLACEHOLDER_TITLE: &str = "Weirdnet";
/// See [`PLACEHOLDER_TITLE`].
pub const PLACEHOLDER_BODY: &str = "New activity";

impl Apns {
    /// Loads the key.
    pub fn new(config: &ApnsConfig) -> Result<Self> {
        let pem = std::fs::read(&config.key)?;
        let key = jsonwebtoken::EncodingKey::from_ec_pem(&pem).map_err(|e| Error::Invalid(format!("APNs key: {e}")))?;
        let plain = |e: &Option<String>| e.as_deref().is_some_and(|u| u.starts_with("http://"));
        let mut b = reqwest::Client::builder().timeout(Duration::from_secs(20)).pool_idle_timeout(Duration::from_secs(3000));
        if plain(&config.endpoint) || plain(&config.sandbox_endpoint) {
            b = b.http2_prior_knowledge(); // h2c for tests
        }
        Ok(Self { config: config.clone(), key, http: b.build()?, jwt: Mutex::new(None) })
    }

    pub(crate) fn allows_topic(&self, t: &str) -> bool {
        self.config.topics.iter().any(|x| x == t)
    }

    fn token(&self) -> Result<String> {
        let mut g = self.jwt.lock().unwrap();
        // Apple: refresh no more than every 20 minutes, and before an hour.
        if let Some((t, at)) = &*g
            && at.elapsed() < Duration::from_secs(40 * 60)
        {
            return Ok(t.clone());
        }
        let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        h.kid = Some(self.config.key_id.clone());
        let iat = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let t = jsonwebtoken::encode(&h, &Claims { iss: &self.config.team_id, iat }, &self.key)
            .map_err(|e| Error::Delivery(format!("APNs token: {e}")))?;
        *g = Some((t.clone(), Instant::now()));
        Ok(t)
    }

    pub(crate) async fn send(&self, device: &str, topic: &str, sandbox: bool, p: &Payload96) -> Result<()> {
        let base = if sandbox {
            self.config.sandbox_endpoint.as_deref().unwrap_or("https://api.sandbox.push.apple.com")
        } else {
            self.config.endpoint.as_deref().unwrap_or("https://api.push.apple.com")
        };
        let exp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600;
        let body = serde_json::json!({
            "aps": { "alert": { "title": PLACEHOLDER_TITLE, "body": PLACEHOLDER_BODY }, "mutable-content": 1 },
            "wn": p.to_b64(),
        });
        let r = self
            .http
            .post(format!("{base}/3/device/{device}"))
            .bearer_auth(self.token()?)
            .header("apns-topic", topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-expiration", exp.to_string())
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Delivery(format!("APNs: {e}")))?;
        let status = r.status().as_u16();
        if status == 200 {
            return Ok(());
        }
        #[derive(Deserialize)]
        struct Reason {
            reason: String,
        }
        let reason = r.json::<Reason>().await.map(|r| r.reason).unwrap_or_default();
        match (status, reason.as_str()) {
            (410, _) | (400, "BadDeviceToken") | (400, "DeviceTokenNotForTopic") => Err(Error::Gone),
            _ => Err(Error::Delivery(format!("APNs {status} {reason}"))),
        }
    }
}
