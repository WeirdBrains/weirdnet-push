//! The push server: registrations, wake requests, and delivery through APNs, FCM and relay
//! announcements. Run it with the `weirdnet-push` binary, or embed [`router`].
//!
//! It keeps per registration only: the SHA-256 of the handle (the key), the SHA-256 of the
//! control secret, the transport (the APNs or FCM token, or "relay"), and the creation
//! time. It never sees what a wake is about, and it logs no handles or tokens.

mod apns;
mod fcm;
mod relay;
mod store;

pub use apns::{Apns, ApnsConfig};
pub use fcm::{Fcm, FcmConfig};
pub use relay::{RelayConfig, RelayHub, token_digest};
pub use store::{Registration, Store};

use crate::api::{Control, ErrorBody, Register, Registered, Transport, WakeRequest};
use crate::error::{Error, Result};
use crate::handle::{ControlSecret, WakeHandle};
use axum::Json;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// The server config (TOML).
///
/// ```toml
/// listen = "127.0.0.1:8470"          # put TLS in front (a reverse proxy)
/// store = "/var/lib/weirdnet-push/registrations.json"
///
/// [apns]
/// key = "/etc/weirdnet-push/AuthKey_ABC123DEFG.p8"
/// key_id = "ABC123DEFG"
/// team_id = "TEAM123456"
/// topics = ["com.weirdbrains.morph"]
///
/// [fcm]
/// service_account = "/etc/weirdnet-push/fcm-service-account.json"
///
/// [relay]
/// # `weirdnet-push relay-token` prints a token and its digest; list the digests here.
/// token_digests = ["…"]
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where to listen.
    pub listen: SocketAddr,
    /// The registrations file.
    pub store: PathBuf,
    /// Most registrations kept (default one million).
    #[serde(default = "default_max")]
    pub max_registrations: usize,
    /// APNs, if this server delivers to iOS.
    pub apns: Option<ApnsConfig>,
    /// FCM, if this server delivers to Android Play builds.
    pub fcm: Option<FcmConfig>,
    /// The relay wake path, if relays follow this server.
    pub relay: Option<RelayConfig>,
}

fn default_max() -> usize {
    1_000_000
}

impl Config {
    /// Parses TOML.
    pub fn from_toml(s: &str) -> Result<Self> {
        toml::from_str(s).map_err(|e| Error::Invalid(format!("config: {e}")))
    }
}

/// The running service.
pub struct Service {
    store: Store,
    apns: Option<Apns>,
    fcm: Option<Fcm>,
    relay: Option<RelayHub>,
}

impl Service {
    /// Opens the store and loads the delivery credentials.
    pub fn new(config: &Config) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            store: Store::open(&config.store, config.max_registrations)?,
            apns: config.apns.as_ref().map(Apns::new).transpose()?,
            fcm: config.fcm.as_ref().map(Fcm::new).transpose()?,
            relay: config.relay.as_ref().map(RelayHub::new).transpose()?,
        }))
    }

    /// The store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The relay hub, if the relay path is on.
    pub fn relay(&self) -> Option<&RelayHub> {
        self.relay.as_ref()
    }

    fn check_transport(&self, t: &Transport) -> Result<()> {
        match t {
            Transport::Apns { token, topic, .. } => {
                let a = self.apns.as_ref().ok_or_else(|| Error::Invalid("APNs is not configured on this server".into()))?;
                if token.is_empty() || token.len() > 200 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(Error::Invalid("bad APNs token".into()));
                }
                if !a.allows_topic(topic) {
                    return Err(Error::Invalid("this server does not deliver for that app".into()));
                }
            }
            Transport::Fcm { token } => {
                if self.fcm.is_none() {
                    return Err(Error::Invalid("FCM is not configured on this server".into()));
                }
                if token.is_empty() || token.len() > 4096 || !token.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(Error::Invalid("bad FCM token".into()));
                }
            }
            Transport::Relay => {
                if self.relay.is_none() {
                    return Err(Error::Invalid("the relay wake path is not on for this server".into()));
                }
            }
        }
        Ok(())
    }

    /// Registers a device.
    pub fn register(&self, t: Transport) -> Result<Registered> {
        self.check_transport(&t)?;
        let (handle, control) = (WakeHandle::generate(), ControlSecret::generate());
        self.store.insert(&handle, Registration::new(t, &control))?;
        Ok(Registered { handle, control })
    }

    fn authorize(&self, c: &Control) -> Result<Registration> {
        let r = self.store.get(&c.handle).ok_or(Error::Gone)?;
        if !c.control.matches(&r.control) {
            return Err(Error::Unauthorized);
        }
        Ok(r)
    }

    /// Rotates a handle.
    pub fn rotate(&self, c: Control) -> Result<Registered> {
        let r = self.authorize(&c)?;
        let t = match c.transport {
            Some(t) => {
                self.check_transport(&t)?;
                t
            }
            None => r.transport,
        };
        let (handle, control) = (WakeHandle::generate(), ControlSecret::generate());
        self.store.replace(&c.handle, &handle, Registration::new(t, &control))?;
        Ok(Registered { handle, control })
    }

    /// Revokes a handle.
    pub fn unregister(&self, c: Control) -> Result<()> {
        self.authorize(&c)?;
        self.store.remove(&c.handle)?;
        Ok(())
    }

    /// Delivers a wake.
    pub async fn wake(&self, w: WakeRequest) -> Result<()> {
        let r = self.store.get(&w.handle).ok_or(Error::Gone)?;
        let res = match &r.transport {
            Transport::Apns { token, topic, sandbox } => self.apns.as_ref().ok_or(Error::Gone)?.send(token, topic, *sandbox, &w.payload).await,
            Transport::Fcm { token } => self.fcm.as_ref().ok_or(Error::Gone)?.send(token, &w.payload).await,
            Transport::Relay => {
                self.relay.as_ref().ok_or(Error::Gone)?.announce(&w.handle, w.payload);
                Ok(())
            }
        };
        if let Err(Error::Gone) = res {
            // The provider says the token is dead: revoke the handle.
            tracing::info!(kind = r.transport.kind(), "token rejected by the provider; handle revoked");
            self.store.remove(&w.handle)?;
        }
        res
    }
}

struct ApiError(Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            Error::Gone => StatusCode::GONE,
            Error::Unauthorized => StatusCode::FORBIDDEN,
            Error::Invalid(_) | Error::BadPayload => StatusCode::BAD_REQUEST,
            Error::Delivery(_) | Error::Http(_) => StatusCode::BAD_GATEWAY,
            Error::Server { .. } => StatusCode::BAD_GATEWAY,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status.is_server_error() {
            tracing::warn!("{}", self.0);
        }
        (status, Json(ErrorBody { error: self.0.to_string() })).into_response()
    }
}

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        ApiError(e)
    }
}

type S = State<Arc<Service>>;

async fn register(State(s): S, Json(r): Json<Register>) -> Result<Json<Registered>, ApiError> {
    Ok(Json(s.register(r.transport)?))
}

async fn rotate(State(s): S, Json(c): Json<Control>) -> Result<Json<Registered>, ApiError> {
    Ok(Json(s.rotate(c)?))
}

async fn unregister(State(s): S, Json(c): Json<Control>) -> Result<StatusCode, ApiError> {
    s.unregister(c)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn wake(State(s): S, Json(w): Json<WakeRequest>) -> Result<StatusCode, ApiError> {
    s.wake(w).await?;
    Ok(StatusCode::ACCEPTED)
}

async fn announcements(State(s): S, headers: HeaderMap) -> Result<Response, ApiError> {
    let hub = s.relay.as_ref().ok_or(Error::Gone)?;
    let token = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    if !hub.allows(token) {
        return Err(Error::Unauthorized.into());
    }
    Ok(hub.stream())
}

/// The HTTP routes.
pub fn router(s: Arc<Service>) -> axum::Router {
    axum::Router::new()
        .route("/v1/register", post(register))
        .route("/v1/rotate", post(rotate))
        .route("/v1/unregister", post(unregister))
        .route("/v1/wake", post(wake))
        .route("/v1/relay/announcements", get(announcements))
        .route("/v1/health", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(16 << 10))
        .with_state(s)
}

/// Serves until `shutdown` resolves.
pub async fn serve(config: Config, shutdown: impl std::future::Future<Output = ()> + Send + 'static) -> Result<()> {
    let s = Service::new(&config)?;
    let l = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(listen = %l.local_addr()?, apns = config.apns.is_some(), fcm = config.fcm.is_some(), relay = config.relay.is_some(), "weirdnet-push serving");
    axum::serve(l, router(s)).with_graceful_shutdown(shutdown).await?;
    Ok(())
}
