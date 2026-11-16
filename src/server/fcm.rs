use crate::error::{Error, Result};
use crate::wake::Payload96;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// FCM HTTP v1 with a service account.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FcmConfig {
    /// The service account JSON key file.
    pub service_account: PathBuf,
    /// Override the FCM endpoint (tests).
    #[serde(default)]
    pub endpoint: Option<String>,
}

#[derive(Deserialize)]
struct ServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
    token_uri: String,
}

/// An FCM sender.
pub struct Fcm {
    sa: ServiceAccount,
    key: jsonwebtoken::EncodingKey,
    endpoint: String,
    http: reqwest::Client,
    access: tokio::sync::Mutex<Option<(String, Instant)>>,
}

impl std::fmt::Debug for Fcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fcm").field("project", &self.sa.project_id).finish()
    }
}

#[derive(serde::Serialize)]
struct Claims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

impl Fcm {
    /// Loads the service account.
    pub fn new(config: &FcmConfig) -> Result<Self> {
        let sa: ServiceAccount =
            serde_json::from_slice(&std::fs::read(&config.service_account)?).map_err(|e| Error::Invalid(format!("FCM service account: {e}")))?;
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(sa.private_key.as_bytes()).map_err(|e| Error::Invalid(format!("FCM key: {e}")))?;
        let endpoint = config.endpoint.clone().unwrap_or_else(|| "https://fcm.googleapis.com".into()).trim_end_matches('/').to_string();
        let http = reqwest::Client::builder().timeout(Duration::from_secs(20)).build()?;
        Ok(Self { sa, key, endpoint, http, access: tokio::sync::Mutex::new(None) })
    }

    async fn access_token(&self) -> Result<String> {
        let mut g = self.access.lock().await;
        if let Some((t, until)) = &*g
            && Instant::now() < *until
        {
            return Ok(t.clone());
        }
        let iat = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let claims = Claims { iss: &self.sa.client_email, scope: SCOPE, aud: &self.sa.token_uri, iat, exp: iat + 3600 };
        let jwt = jsonwebtoken::encode(&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256), &claims, &self.key)
            .map_err(|e| Error::Delivery(format!("FCM token: {e}")))?;
        let body = format!("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={jwt}");
        let r = self
            .http
            .post(&self.sa.token_uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| Error::Delivery(format!("FCM token: {e}")))?;
        if !r.status().is_success() {
            return Err(Error::Delivery(format!("FCM token: {}", r.status())));
        }
        #[derive(Deserialize)]
        struct Tok {
            access_token: String,
            expires_in: u64,
        }
        let t: Tok = r.json().await.map_err(|e| Error::Delivery(format!("FCM token: {e}")))?;
        let until = Instant::now() + Duration::from_secs(t.expires_in.saturating_sub(120).max(60));
        *g = Some((t.access_token.clone(), until));
        Ok(t.access_token)
    }

    pub(crate) async fn send(&self, device: &str, p: &Payload96) -> Result<()> {
        let body = serde_json::json!({
            "message": {
                "token": device,
                "data": { "wn": p.to_b64() },
                "android": { "priority": "HIGH", "ttl": "3600s" },
            }
        });
        let r = self
            .http
            .post(format!("{}/v1/projects/{}/messages:send", self.endpoint, self.sa.project_id))
            .bearer_auth(self.access_token().await?)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Delivery(format!("FCM: {e}")))?;
        let status = r.status().as_u16();
        if (200..300).contains(&status) {
            return Ok(());
        }
        if status == 401 {
            *self.access.lock().await = None;
        }
        let text = r.text().await.unwrap_or_default();
        if status == 404 || text.contains("UNREGISTERED") {
            return Err(Error::Gone);
        }
        Err(Error::Delivery(format!("FCM {status}")))
    }
}
