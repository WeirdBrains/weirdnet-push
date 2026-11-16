//! The push server against mock APNs and FCM.
#![cfg(feature = "server")]

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Version};
use axum::routing::post;
use axum::{Json, Router};
use std::sync::{Arc, Mutex};
use weirdnet_push::api::Transport;
use weirdnet_push::server::{ApnsConfig, Config, FcmConfig, RelayConfig, Service, Store, router, token_digest};
use weirdnet_push::{Error, PushClient, PushKey, Reason, WakeCard, WakeHandle};

#[derive(Default)]
struct Mock {
    apns: Mutex<Vec<(String, HeaderMap, Version, serde_json::Value)>>,
    apns_status: Mutex<(u16, &'static str)>,
    tokens: Mutex<Vec<String>>,
    fcm: Mutex<Vec<(HeaderMap, serde_json::Value)>>,
}

async fn apns(
    State(m): State<Arc<Mock>>,
    Path(device): Path<String>,
    version: Version,
    h: HeaderMap,
    Json(b): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    m.apns.lock().unwrap().push((device, h, version, b));
    let (s, reason) = *m.apns_status.lock().unwrap();
    (StatusCode::from_u16(s).unwrap(), Json(serde_json::json!({ "reason": reason })))
}

async fn token(State(m): State<Arc<Mock>>, body: String) -> Json<serde_json::Value> {
    m.tokens.lock().unwrap().push(body);
    Json(serde_json::json!({ "access_token": "ya29.test", "expires_in": 3600, "token_type": "Bearer" }))
}

async fn fcm(State(m): State<Arc<Mock>>, h: HeaderMap, Json(b): Json<serde_json::Value>) -> (StatusCode, &'static str) {
    let unregistered = b["message"]["token"] == "dead";
    m.fcm.lock().unwrap().push((h, b));
    if unregistered {
        (StatusCode::NOT_FOUND, r#"{"error":{"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}"#)
    } else {
        (StatusCode::OK, "{}")
    }
}

async fn spawn(r: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    format!("http://{a}")
}

struct T {
    _dir: tempfile::TempDir,
    mock: Arc<Mock>,
    service: Arc<Service>,
    client: PushClient,
    ec_public: String,
    rsa_public: String,
    store: std::path::PathBuf,
    relay_token: String,
}

async fn setup() -> T {
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    let dir = tempfile::tempdir().unwrap();
    let mock = Arc::new(Mock { apns_status: Mutex::new((200, "")), ..Default::default() });
    let mock_url = spawn(
        Router::new()
            .route("/3/device/{device}", post(apns))
            .route("/token", post(token))
            .route("/v1/projects/{p}/messages:send", post(fcm))
            .with_state(mock.clone()),
    )
    .await;

    let ec = p256::SecretKey::random(&mut rand_core::OsRng);
    std::fs::write(dir.path().join("AuthKey.p8"), ec.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes()).unwrap();
    let ec_public = ec.public_key().to_public_key_pem(LineEnding::LF).unwrap();

    let rsa = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let rsa_pem = rsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(&rsa, rsa::pkcs8::LineEnding::LF).unwrap();
    let rsa_public = rsa::pkcs8::EncodePublicKey::to_public_key_pem(&rsa.to_public_key(), rsa::pkcs8::LineEnding::LF).unwrap();
    let sa = serde_json::json!({
        "type": "service_account", "project_id": "weirdnet-test", "client_email": "push@weirdnet-test.iam.gserviceaccount.com",
        "private_key": rsa_pem.as_str(), "token_uri": format!("{mock_url}/token"),
    });
    std::fs::write(dir.path().join("sa.json"), sa.to_string()).unwrap();

    let relay_token = WakeHandle::generate().as_str().to_string();
    let store = dir.path().join("registrations.json");
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        store: store.clone(),
        max_registrations: 100,
        apns: Some(ApnsConfig {
            key: dir.path().join("AuthKey.p8"),
            key_id: "KEYID12345".into(),
            team_id: "TEAM123456".into(),
            topics: vec!["com.weirdbrains.morph".into()],
            endpoint: Some(mock_url.clone()),
            sandbox_endpoint: Some(mock_url.clone()),
        }),
        fcm: Some(FcmConfig { service_account: dir.path().join("sa.json"), endpoint: Some(mock_url.clone()) }),
        relay: Some(RelayConfig { token_digests: vec![token_digest(&relay_token)] }),
    };
    let service = Service::new(&config).unwrap();
    let url = spawn(router(service.clone())).await;
    T { _dir: dir, mock, service, client: PushClient::new(url), ec_public, rsa_public, store, relay_token }
}

fn apns_transport(token: &str) -> Transport {
    Transport::Apns { token: token.into(), topic: "com.weirdbrains.morph".into(), sandbox: false }
}

fn card(t: &T, handle: &WakeHandle, key: &PushKey) -> WakeCard {
    WakeCard { service: t.client.base().into(), handle: handle.clone(), key: hex::encode(key.public()) }
}

#[tokio::test]
async fn apns_wakes_carry_only_the_sealed_payload() {
    let t = setup().await;
    let key = PushKey::generate();
    let r = t.client.register(apns_transport("abcdef0123")).await.unwrap();
    t.client.wake_card(&card(&t, &r.handle, &key), Reason::MessageWaiting).await.unwrap();

    let (device, h, version, body) = t.mock.apns.lock().unwrap().pop().unwrap();
    assert_eq!(device, "abcdef0123");
    assert_eq!(version, Version::HTTP_2);
    assert_eq!(h["apns-topic"], "com.weirdbrains.morph");
    assert_eq!(h["apns-push-type"], "alert");
    assert_eq!(h["apns-priority"], "10");
    let jwt = h["authorization"]
        .to_str()
        .unwrap()
        .strip_prefix("bearer ")
        .or_else(|| h["authorization"].to_str().unwrap().strip_prefix("Bearer "))
        .unwrap();
    let header = jsonwebtoken::decode_header(jwt).unwrap();
    assert_eq!((header.alg, header.kid.as_deref()), (jsonwebtoken::Algorithm::ES256, Some("KEYID12345")));
    let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    v.required_spec_claims.clear();
    v.validate_exp = false;
    let claims =
        jsonwebtoken::decode::<serde_json::Value>(jwt, &jsonwebtoken::DecodingKey::from_ec_pem(t.ec_public.as_bytes()).unwrap(), &v).unwrap().claims;
    assert_eq!(claims["iss"], "TEAM123456");

    // Exactly the placeholder alert and the ciphertext.
    let keys: Vec<&String> = body.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["aps", "wn"]);
    assert_eq!(body["aps"]["mutable-content"], 1);
    assert_eq!(body["aps"]["alert"]["body"], "New activity");
    let p = weirdnet_push::Payload96::from_b64(body["wn"].as_str().unwrap()).unwrap();
    assert_eq!(key.open(&r.handle, &p).unwrap().reason, Reason::MessageWaiting);
}

#[tokio::test]
async fn a_dead_apns_token_revokes_the_handle() {
    let t = setup().await;
    let key = PushKey::generate();
    let r = t.client.register(apns_transport("abcdef")).await.unwrap();
    *t.mock.apns_status.lock().unwrap() = (410, "Unregistered");
    let c = card(&t, &r.handle, &key);
    assert!(matches!(t.client.wake_card(&c, Reason::MessageWaiting).await, Err(Error::Gone)));
    assert!(matches!(t.client.wake_card(&c, Reason::MessageWaiting).await, Err(Error::Gone)));
    assert_eq!(t.mock.apns.lock().unwrap().len(), 1, "the second wake never reaches APNs");
    // Other failures don't revoke.
    let r = t.client.register(apns_transport("abcdef")).await.unwrap();
    *t.mock.apns_status.lock().unwrap() = (500, "InternalServerError");
    let c = card(&t, &r.handle, &key);
    assert!(matches!(t.client.wake_card(&c, Reason::MessageWaiting).await, Err(Error::Server { status: 502, .. })));
    assert!(t.service.store().get(&r.handle).is_some());
}

#[tokio::test]
async fn fcm_wakes_with_a_cached_service_account_token() {
    let t = setup().await;
    let key = PushKey::generate();
    let r = t.client.register(Transport::Fcm { token: "fcm-token-1".into() }).await.unwrap();
    let c = card(&t, &r.handle, &key);
    t.client.wake_card(&c, Reason::ConnectionRequested).await.unwrap();
    t.client.wake_card(&c, Reason::MessageWaiting).await.unwrap();
    let tokens = t.mock.tokens.lock().unwrap().clone();
    assert_eq!(tokens.len(), 1);
    let assertion = tokens[0].split("assertion=").nth(1).unwrap();
    assert!(tokens[0].starts_with("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&"));
    let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    v.validate_aud = false;
    let claims = jsonwebtoken::decode::<serde_json::Value>(assertion, &jsonwebtoken::DecodingKey::from_rsa_pem(t.rsa_public.as_bytes()).unwrap(), &v)
        .unwrap()
        .claims;
    assert_eq!(claims["scope"], "https://www.googleapis.com/auth/firebase.messaging");
    let sent = t.mock.fcm.lock().unwrap().clone();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].0["authorization"], "Bearer ya29.test");
    let m = &sent[0].1["message"];
    assert_eq!(m["token"], "fcm-token-1");
    assert_eq!(m["android"]["priority"], "HIGH");
    assert_eq!(m["data"].as_object().unwrap().len(), 1);
    let p = weirdnet_push::Payload96::from_b64(m["data"]["wn"].as_str().unwrap()).unwrap();
    assert_eq!(key.open(&r.handle, &p).unwrap().reason, Reason::ConnectionRequested);

    let dead = t.client.register(Transport::Fcm { token: "dead".into() }).await.unwrap();
    assert!(matches!(t.client.wake_card(&card(&t, &dead.handle, &key), Reason::MessageWaiting).await, Err(Error::Gone)));
    assert!(t.service.store().get(&dead.handle).is_none());
}

#[tokio::test]
async fn rotate_and_unregister_need_the_control_secret() {
    let t = setup().await;
    let key = PushKey::generate();
    let r = t.client.register(apns_transport("abcdef")).await.unwrap();
    let other = t.client.register(apns_transport("abcdef")).await.unwrap();
    assert!(matches!(t.client.rotate(&r.handle, &other.control, None).await, Err(Error::Unauthorized)));
    assert!(matches!(t.client.unregister(&r.handle, &other.control).await, Err(Error::Unauthorized)));
    let n = t.client.rotate(&r.handle, &r.control, Some(apns_transport("0123456789"))).await.unwrap();
    assert_ne!(n.handle, r.handle);
    assert!(matches!(t.client.wake_card(&card(&t, &r.handle, &key), Reason::MessageWaiting).await, Err(Error::Gone)));
    t.client.wake_card(&card(&t, &n.handle, &key), Reason::MessageWaiting).await.unwrap();
    assert_eq!(t.mock.apns.lock().unwrap().last().unwrap().0, "0123456789");
    // The old control secret is spent too.
    assert!(matches!(t.client.unregister(&n.handle, &r.control).await, Err(Error::Unauthorized)));
    t.client.unregister(&n.handle, &n.control).await.unwrap();
    assert!(matches!(t.client.wake_card(&card(&t, &n.handle, &key), Reason::MessageWaiting).await, Err(Error::Gone)));
    assert!(matches!(t.client.unregister(&n.handle, &n.control).await, Err(Error::Gone)));
}

#[tokio::test]
async fn bad_registrations_and_payloads_are_refused() {
    let t = setup().await;
    for bad in [
        Transport::Apns { token: "abc".into(), topic: "com.example.other".into(), sandbox: false },
        Transport::Apns { token: "not hex".into(), topic: "com.weirdbrains.morph".into(), sandbox: false },
        Transport::Fcm { token: String::new() },
    ] {
        assert!(matches!(t.client.register(bad).await, Err(Error::Server { status: 400, .. })));
    }
    let r = t.client.register(apns_transport("abcdef")).await.unwrap();
    let http = reqwest::Client::new();
    let short = serde_json::json!({ "handle": r.handle.as_str(), "payload": "AAAA" });
    let s = http.post(format!("{}/v1/wake", t.client.base())).json(&short).send().await.unwrap().status();
    assert_eq!(s.as_u16(), 422);
    let big = "x".repeat(32 << 10);
    let s = http.post(format!("{}/v1/register", t.client.base())).header("content-type", "application/json").body(big).send().await.unwrap().status();
    assert_eq!(s.as_u16(), 413);
    assert!(t.mock.apns.lock().unwrap().is_empty());
}

#[tokio::test]
async fn relays_follow_wake_announcements() {
    let t = setup().await;
    let key = PushKey::generate();
    let r = t.client.register(Transport::Relay).await.unwrap();
    assert!(matches!(t.client.announcements("wrong", |_| true).await, Err(Error::Unauthorized)));
    let (tx, rx) = tokio::sync::oneshot::channel();
    let follower = t.client.clone();
    let token = t.relay_token.clone();
    let task = tokio::spawn(async move {
        let mut tx = Some(tx);
        follower
            .announcements(&token, move |a| {
                tx.take().unwrap().send(a).unwrap();
                false
            })
            .await
            .unwrap();
    });
    while t.service.relay().unwrap().followers() == 0 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    t.client.wake_card(&card(&t, &r.handle, &key), Reason::ConnectionRequested).await.unwrap();
    let a = rx.await.unwrap();
    assert_eq!(a.handle, r.handle);
    assert_eq!(key.open(&a.handle, &a.payload).unwrap().reason, Reason::ConnectionRequested);
    task.await.unwrap();
}

#[tokio::test]
async fn the_store_keeps_no_handles_or_secrets() {
    let t = setup().await;
    let r = t.client.register(apns_transport("abcdef")).await.unwrap();
    let file = std::fs::read_to_string(&t.store).unwrap();
    assert!(!file.contains(r.handle.as_str()));
    assert!(!file.contains(r.control.expose()));
    assert!(file.contains(&r.handle.digest()));
    let again = Store::open(&t.store, 10).unwrap();
    assert_eq!(again.get(&r.handle).unwrap().transport, apns_transport("abcdef"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&t.store).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
