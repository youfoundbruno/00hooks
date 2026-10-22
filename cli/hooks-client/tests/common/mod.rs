//! A tiny in-process relay implementing just enough of PROTOCOL.md for the client's tests: signed
//! request checks (time window, nonces, signatures), accounts, `/v1/stream` with a backlog and
//! scripted misbehaviour, and `/v1/ack`, which checks that everything acknowledged was recorded in
//! the client's state directory first. Events are kept in the clear in `log` and sealed (and signed
//! with the mock's relay key) at send time for any device that registered a sealing key.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use hooks_client::Event;
use hooks_client::seal::{SealedContent, seal_event, seal_kid};
use hooks_client::signing::canonical_string;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use serde_json::{Value, json};
use tokio::sync::mpsc;

/// How one stream connection behaves, taken in order from `State::script`; `Normal` once it runs out.
#[derive(Debug, Clone)]
pub enum Conn {
    /// `ready`, the backlog, then heartbeats and live events until the client goes away.
    Normal,
    /// `ready`, then `n` events, then half of the next frame, then the connection ends.
    CutAfter(usize),
    /// Start `n` seqs earlier than the protocol says (an at-least-once relay re-sending), then
    /// behave as `Normal`.
    Rewind(u64),
    /// `ready` and `n` events, then `closed {code}`.
    CloseAfter(usize, u16),
    /// `ready` and `n` events, then `resync {after}`.
    ResyncAfter(usize),
    /// `ready`, a `gap` for the given inclusive range, then `Normal`.
    Gap(u64, u64),
    /// `retry` and `ready`, then nothing at all (no heartbeats either).
    Silent,
    /// `ready` and `n` events, then nothing at all.
    SilentAfter(usize),
    /// The response headers never come (until long after any client has given up); the next
    /// connection is taken from the script as usual.
    Stall,
}

#[derive(Default)]
pub struct State {
    pub devices: HashMap<String, VerifyingKey>,
    pub revoked: HashSet<String>,
    nonces: HashSet<(String, String)>,
    /// The account's log: events in seq order.
    pub log: Vec<Value>,
    pub acked: u64,
    pub acks: Vec<u64>,
    /// Problems the relay noticed (bad signatures, acks of unrecorded events…). Tests assert empty.
    pub violations: Vec<String>,
    /// `Last-Event-ID` of each stream request, in order.
    pub stream_requests: Vec<Option<u64>>,
    pub script: VecDeque<Conn>,
    /// The relay's clock minus the real one.
    pub clock_offset_ms: i64,
    /// Refuse every signed request with `clock_skew`.
    pub always_skew: bool,
    /// The client's state directory, read on every ack.
    pub client_home: Option<PathBuf>,
    pub skew_refusals: usize,
    pub hooks: Vec<Value>,
    /// Answer this many acks with `503` before taking them.
    pub fail_acks: usize,
    /// Acks answered with `503`.
    pub failed_acks: usize,
    /// Each ack is answered after this long.
    pub ack_delay: Duration,
    /// Seqs whose `hook` frame is sent garbled (data that isn't an event).
    pub garbled: HashSet<u64>,
    /// `DELETE /v1/devices/<id>`: (the signing device, the revoked id), in order.
    pub revocations: Vec<(String, String)>,
    /// The enrolment code `POST /v1/enrolments/redeem` accepts.
    pub enrolment_code: Option<String>,
    /// Sealing keys by device (raw X25519 public keys).
    pub seal_keys: HashMap<String, [u8; 32]>,
    /// The `X-00h-Protocol` header of each stream request, in order.
    pub stream_protocols: Vec<Option<String>>,
    /// Seqs whose envelope is sent with a broken relay signature (a forgery).
    pub forged: HashSet<u64>,
    /// Seqs sent unsealed even to a device with a sealing key.
    pub unsealed: HashSet<u64>,
    /// Every `POST /v1/hooks` body, in order.
    pub hook_requests: Vec<Value>,
    /// API keys created: (id, name, scopes), and revoked ids.
    pub api_keys: Vec<(String, String, Vec<String>)>,
    pub revoked_keys: Vec<String>,
    /// When set, `POST /v1/accounts` needs `Authorization: Bearer <this>` (`/v1/info` still says
    /// signups are open, as a relay that misreports would).
    pub signup_token: Option<String>,
    /// `hook-change` messages (PROTOCOL §6), in order: each device's stream sends the ones it
    /// hasn't been sent yet after `ready`, then live ones, without an `id:`. Clearing
    /// `hook_changes_sent` sends them all again, as the relay may (delivery is at least once).
    pub hook_changes: Vec<Value>,
    /// How many of `hook_changes` each device has been sent.
    pub hook_changes_sent: HashMap<String, usize>,
    /// Names given with `PATCH /v1/devices/<id>` (a device without one is called "test").
    pub device_names: HashMap<String, String>,
    /// More entries for `GET /v1/devices` (other devices and phones of the account).
    pub other_devices: Vec<Value>,
    /// Every `PATCH /v1/hooks/<id>` body, in order.
    pub hook_patches: Vec<Value>,
    /// What `POST /v1/test/<id>` answers: `(status, body)`; by default `200` with a delivery that
    /// was accepted, and `409` for a strict or `standard-webhooks-ed25519` hook, as the relay does.
    pub test_answer: Option<(u16, Value)>,
    /// Fields `/v1/info` adds or replaces (an object; `null` adds none).
    pub info_extra: Value,
    /// `limit` messages (PROTOCOL §6): sent after `ready` on every connection, without an `id:`.
    pub limits: Vec<Value>,
    /// Raw frames sent after the backlog on every connection (a gap the relay says late, say).
    pub trailing: Vec<String>,
    next_device: usize,
}

/// The mock relay's envelope-signing key (its public half is `/v1/info`'s `relayKey`).
pub fn relay_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

pub fn relay_key_b64() -> String {
    URL_SAFE_NO_PAD.encode(relay_signing_key().verifying_key().as_bytes())
}

/// `e` as `device` receives it: sealed to its key when it has one.
pub fn sealed_for(s: &State, device: &str, e: &Value) -> Value {
    let seq = e["seq"].as_u64().unwrap();
    let Some(pk) = s.seal_keys.get(device) else {
        return e.clone();
    };
    if s.unsealed.contains(&seq) {
        return e.clone();
    }
    let meta: Event = serde_json::from_value(e.clone()).unwrap();
    let content = SealedContent {
        headers: meta.headers.clone(),
        content_type: meta.content_type.clone(),
        url: None,
        notice: false,
        origin: None,
        body: meta.body_bytes().unwrap(),
    };
    let sealed = seal_event(&relay_signing_key(), device, pk, &meta, &content).unwrap();
    let mut v = serde_json::to_value(&sealed).unwrap();
    if s.forged.contains(&seq) {
        // Signed by someone else's key.
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let forged = seal_event(&other, device, pk, &meta, &content).unwrap();
        v = serde_json::to_value(&forged).unwrap();
    }
    v
}

fn seal_key_of(v: &Value) -> Option<[u8; 32]> {
    URL_SAFE_NO_PAD
        .decode(v["sealKey"].as_str()?)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// An event as the relay would send it.
pub fn event(seq: u64) -> Value {
    let body = format!("{{\"n\":{seq}}}");
    json!({
        "seq": seq,
        "id": format!("evt_{seq:04}"),
        "hookId": "hk_1",
        "receivedAt": 1792233600000u64 + seq,
        "verified": true,
        "preset": "github",
        "eventType": "push",
        "contentType": "application/json",
        "headers": { "x-github-event": "push" },
        "body": STANDARD.encode(body),
    })
}

pub struct MockRelay {
    pub url: String,
    pub state: Arc<Mutex<State>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MockRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockRelay {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let st = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let st = st.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| handle(st.clone(), req));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(sock), svc)
                        .await;
                });
            }
        });
        MockRelay { url, state, task }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    pub fn push_events(&self, seqs: impl IntoIterator<Item = u64>) {
        self.with(|s| s.log.extend(seqs.into_iter().map(event)));
    }
}

type Resp = Response<BoxBody<Bytes, Infallible>>;

fn json_resp(status: StatusCode, v: Value) -> Resp {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(v.to_string())).boxed())
        .unwrap()
}

fn unauthorized(error: &str, extra: Option<(&str, Value)>) -> Resp {
    let mut v = json!({ "error": error, "message": "Not allowed." });
    if let Some((k, x)) = extra {
        v[k] = x;
    }
    json_resp(StatusCode::UNAUTHORIZED, v)
}

/// PROTOCOL §1, relay side. Returns the device id, or the refusal to send.
fn check_signed(
    st: &Arc<Mutex<State>>,
    req: &hyper::http::request::Parts,
    body: &[u8],
) -> Result<String, Box<Resp>> {
    let h = |name: &str| {
        req.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let mut s = st.lock().unwrap();
    let server_time = now_ms() + s.clock_offset_ms;
    let (Some(device), Some(time), Some(nonce), Some(sig), Some(host)) = (
        h("x-00h-device"),
        h("x-00h-time"),
        h("x-00h-nonce"),
        h("x-00h-signature"),
        h("host"),
    ) else {
        s.violations
            .push(format!("unsigned request to {}", req.uri.path()));
        return Err(Box::new(unauthorized("unauthorized", None)));
    };
    let time: i64 = time.parse().unwrap_or(0);
    if s.always_skew || (time - server_time).abs() > 300_000 {
        s.skew_refusals += 1;
        return Err(Box::new(unauthorized(
            "clock_skew",
            Some(("serverTime", json!(server_time))),
        )));
    }
    if nonce.len() != 22 || !s.nonces.insert((device.clone(), nonce.clone())) {
        s.violations
            .push(format!("reused or malformed nonce {nonce}"));
        return Err(Box::new(unauthorized("unauthorized", None)));
    }
    let Some(key) = s.devices.get(&device).copied() else {
        return Err(Box::new(unauthorized("unauthorized", None)));
    };
    if s.revoked.contains(&device) {
        return Err(Box::new(unauthorized("unauthorized", None)));
    }
    let path = req
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let canonical = canonical_string(
        &device,
        &host,
        req.method.as_str(),
        &path,
        time,
        &nonce,
        body,
    );
    let ok = URL_SAFE_NO_PAD
        .decode(&sig)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .is_some_and(|sig| key.verify_strict(canonical.as_bytes(), &sig).is_ok());
    if !ok {
        s.violations.push(format!("bad signature on {path}"));
        return Err(Box::new(unauthorized("unauthorized", None)));
    }
    Ok(device)
}

async fn handle(st: Arc<Mutex<State>>, req: Request<Incoming>) -> Result<Resp, Infallible> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let route = (parts.method.as_str(), parts.uri.path());
    if route == ("GET", "/v1/stream") {
        let stall = matches!(st.lock().unwrap().script.front(), Some(Conn::Stall));
        if stall {
            st.lock().unwrap().script.pop_front();
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }
    if route == ("POST", "/v1/ack") {
        let delay = st.lock().unwrap().ack_delay;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
    let resp = match route {
        ("GET", "/v1/info") => {
            let s = st.lock().unwrap();
            let mut info = json!({ "version": "mock", "protocol": 2, "protocols": [2], "signupOpen": true,
                                   "relayKey": relay_key_b64(), "serverTime": now_ms() + s.clock_offset_ms });
            if let (Some(o), Some(extra)) = (info.as_object_mut(), s.info_extra.as_object()) {
                for (k, v) in extra {
                    o.insert(k.clone(), v.clone());
                }
            }
            json_resp(StatusCode::OK, info)
        }
        ("POST", "/v1/accounts")
            if st.lock().unwrap().signup_token.as_ref().is_some_and(|t| {
                parts
                    .headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    != Some(format!("Bearer {t}").as_str())
            }) =>
        {
            unauthorized("unauthorized", None)
        }
        ("POST", "/v1/accounts") => {
            let v: Value = serde_json::from_slice(&body).unwrap_or_default();
            let key = URL_SAFE_NO_PAD
                .decode(v["publicKey"].as_str().unwrap_or(""))
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .and_then(|b| VerifyingKey::from_bytes(&b).ok());
            match key {
                None => json_resp(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"invalid","message":"Bad key.","field":"publicKey"}),
                ),
                Some(key) => {
                    let mut s = st.lock().unwrap();
                    s.next_device += 1;
                    let id = format!("dev_{}", s.next_device);
                    s.devices.insert(id.clone(), key);
                    if let Some(k) = seal_key_of(&v) {
                        s.seal_keys.insert(id.clone(), k);
                    }
                    json_resp(
                        StatusCode::CREATED,
                        json!({ "accountId": "acc_1", "deviceId": id }),
                    )
                }
            }
        }
        ("POST", "/v1/enrolments/redeem") => {
            let v: Value = serde_json::from_slice(&body).unwrap_or_default();
            let key = URL_SAFE_NO_PAD
                .decode(v["publicKey"].as_str().unwrap_or(""))
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .and_then(|b| VerifyingKey::from_bytes(&b).ok());
            let mut s = st.lock().unwrap();
            let right =
                s.enrolment_code.is_some() && v["code"].as_str() == s.enrolment_code.as_deref();
            match key {
                Some(key) if right => {
                    s.enrolment_code = None;
                    s.next_device += 1;
                    let id = format!("dev_{}", s.next_device);
                    s.devices.insert(id.clone(), key);
                    if let Some(k) = seal_key_of(&v) {
                        s.seal_keys.insert(id.clone(), k);
                    }
                    json_resp(
                        StatusCode::OK,
                        json!({ "accountId": "acc_1", "deviceId": id }),
                    )
                }
                _ => unauthorized("unauthorized", None),
            }
        }
        _ => match check_signed(&st, &parts, &body) {
            Err(r) => *r,
            Ok(device) => signed_route(&st, &parts, &body, &device),
        },
    };
    Ok(resp)
}

fn signed_route(
    st: &Arc<Mutex<State>>,
    parts: &hyper::http::request::Parts,
    body: &[u8],
    device: &str,
) -> Resp {
    match (parts.method.as_str(), parts.uri.path()) {
        ("GET", "/v1/devices") => {
            let s = st.lock().unwrap();
            let kid = s.seal_keys.get(device).map(|k| seal_kid(k));
            let name = s
                .device_names
                .get(device)
                .cloned()
                .unwrap_or_else(|| "test".into());
            let mut devices = vec![json!({ "id": device, "name": name, "createdAt": 1,
                                           "lastSeenAt": null, "current": true, "sealKid": kid })];
            devices.extend(s.other_devices.iter().cloned());
            json_resp(StatusCode::OK, json!({ "devices": devices }))
        }
        ("PATCH", path) if path.starts_with("/v1/devices/") => {
            let id = path["/v1/devices/".len()..].to_string();
            let v: Value = serde_json::from_slice(body).unwrap_or_default();
            let name = v["name"].as_str().unwrap_or("").trim().to_string();
            if name.is_empty() || name.chars().count() > 100 {
                return json_resp(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"invalid","message":"A name is 1 to 100 characters.","field":"name"}),
                );
            }
            let mut s = st.lock().unwrap();
            if id == device {
                s.device_names.insert(id.clone(), name.clone());
                let kid = s.seal_keys.get(device).map(|k| seal_kid(k));
                return json_resp(
                    StatusCode::OK,
                    json!({ "device": { "id": id, "name": name, "createdAt": 1, "lastSeenAt": null,
                                        "current": true, "sealKid": kid } }),
                );
            }
            match s.other_devices.iter_mut().find(|d| d["id"] == id.as_str()) {
                Some(d) => {
                    d["name"] = json!(name);
                    let d = d.clone();
                    json_resp(StatusCode::OK, json!({ "device": d }))
                }
                None => json_resp(
                    StatusCode::NOT_FOUND,
                    json!({"error":"not_found","message":"Nothing is here."}),
                ),
            }
        }
        ("PATCH", path) if path.starts_with("/v1/hooks/") => {
            let id = path["/v1/hooks/".len()..].to_string();
            let v: Value = serde_json::from_slice(body).unwrap_or_default();
            let mut s = st.lock().unwrap();
            s.hook_patches.push(v.clone());
            if let Some(to) = v.get("deliverTo").and_then(Value::as_str) {
                let sealed = s.seal_keys.contains_key(to)
                    || s.other_devices
                        .iter()
                        .any(|d| d["id"] == to && d["kind"] != "phone" && !d["sealKid"].is_null());
                if !sealed {
                    return json_resp(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"invalid","message":"Not an active device of this account with a sealing key.","field":"deliverTo"}),
                    );
                }
            }
            if let Some(r) = v.get("response").filter(|r| !r.is_null()) {
                let ok = r["status"]
                    .as_u64()
                    .is_some_and(|n| (200..300).contains(&n));
                if !ok {
                    return json_resp(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"invalid","message":"A success status, 200 to 299.","field":"response.status"}),
                    );
                }
            }
            let Some(h) = s.hooks.iter_mut().find(|h| h["id"] == id.as_str()) else {
                return json_resp(
                    StatusCode::NOT_FOUND,
                    json!({"error":"not_found","message":"Nothing is here."}),
                );
            };
            if let (Some(o), Some(p)) = (h.as_object_mut(), v.as_object()) {
                for (k, x) in p {
                    o.insert(k.clone(), x.clone());
                }
            }
            let h = h.clone();
            json_resp(StatusCode::OK, h)
        }
        ("POST", path) if path.starts_with("/v1/test/") => {
            let id = &path["/v1/test/".len()..];
            let s = st.lock().unwrap();
            let Some(h) = s.hooks.iter().find(|h| h["id"] == id) else {
                return json_resp(
                    StatusCode::NOT_FOUND,
                    json!({"error":"not_found","message":"Nothing is here."}),
                );
            };
            if h["verify"]["strict"] == json!(true) {
                return json_resp(
                    StatusCode::CONFLICT,
                    json!({"error":"conflict","message":"This hook is strict: its secret is on your devices, so the relay can't sign a test event."}),
                );
            }
            if h["verify"]["preset"] == "standard-webhooks-ed25519" {
                return json_resp(
                    StatusCode::CONFLICT,
                    json!({"error":"conflict","message":"The relay holds only this hook's public key, so it can't sign a test event."}),
                );
            }
            let (status, answer) = s.test_answer.clone().unwrap_or((
                200,
                json!({ "status": 200, "answer": { "received": "evt_test1" },
                        "eventType": "00hooks.test" }),
            ));
            json_resp(StatusCode::from_u16(status).unwrap(), answer)
        }
        ("PUT", path) if path.starts_with("/v1/devices/") && path.ends_with("/seal-key") => {
            let v: Value = serde_json::from_slice(body).unwrap_or_default();
            let target = &path["/v1/devices/".len()..path.len() - "/seal-key".len()];
            if target != device {
                return json_resp(
                    StatusCode::FORBIDDEN,
                    json!({"error":"forbidden","message":"Only its own."}),
                );
            }
            match seal_key_of(&v) {
                None => json_resp(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"invalid","message":"Bad key.","field":"sealKey"}),
                ),
                Some(k) => {
                    st.lock().unwrap().seal_keys.insert(device.to_string(), k);
                    json_resp(StatusCode::OK, json!({ "kid": seal_kid(&k) }))
                }
            }
        }
        ("POST", "/v1/keys") => {
            let v: Value = serde_json::from_slice(body).unwrap_or_default();
            let mut s = st.lock().unwrap();
            let id = format!("key_{:026}", s.api_keys.len() + 1);
            let scopes: Vec<String> = v["scopes"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let name = v["name"].as_str().unwrap_or("").to_string();
            s.api_keys.push((id.clone(), name.clone(), scopes.clone()));
            let token = format!("hk_{}_{}", &id[4..], "A".repeat(43));
            json_resp(
                StatusCode::CREATED,
                json!({ "key": { "id": id, "name": name, "scopes": scopes, "createdAt": 1,
                                  "createdBy": device, "expiresAt": now_ms() + 86_400_000,
                                  "lastUsedAt": null },
                        "token": token }),
            )
        }
        ("GET", "/v1/keys") => {
            let s = st.lock().unwrap();
            let keys: Vec<Value> = s
                .api_keys
                .iter()
                .filter(|(id, _, _)| !s.revoked_keys.contains(id))
                .map(|(id, name, scopes)| {
                    json!({ "id": id, "name": name, "scopes": scopes, "createdAt": 1,
                            "createdBy": device, "expiresAt": now_ms() + 86_400_000,
                            "lastUsedAt": null })
                })
                .collect();
            json_resp(StatusCode::OK, json!({ "keys": keys }))
        }
        ("DELETE", path) if path.starts_with("/v1/keys/") => {
            st.lock()
                .unwrap()
                .revoked_keys
                .push(path["/v1/keys/".len()..].to_string());
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::new(Bytes::new()).boxed())
                .unwrap()
        }
        ("GET", "/v1/audit") => json_resp(
            StatusCode::OK,
            json!({ "entries": [
                { "at": 1792233600000u64, "kind": "hook.created", "actor": device,
                  "subject": "hk_1", "name": "ci\u{1b}[2J" },
                { "at": 1792231200000u64, "kind": "verify.failed", "actor": null,
                  "subject": "hk_1", "name": "ci", "count": 3 }
            ] }),
        ),
        ("POST", "/v1/hooks") => {
            let v: Value = serde_json::from_slice(body).unwrap_or_default();
            let mut verify = v["verify"].clone();
            let supplied = verify.get("secret").is_some();
            if let Some(o) = verify.as_object_mut() {
                o.remove("secret");
            }
            let strict = verify["strict"] == json!(true);
            let mut s = st.lock().unwrap();
            s.hook_requests.push(v.clone());
            let id = format!("hk_{}", s.hooks.len() + 1);
            let hook = json!({ "id": id, "name": v["name"], "url": format!("https://relay.example/h/{id}"),
                               "enabled": true, "verify": verify,
                               "maxBodyBytes": 1048576, "createdAt": 1, "lastEventAt": null });
            s.hooks.push(hook.clone());
            let mut out = json!({ "hook": hook, "url": format!("https://relay.example/h/{id}") });
            // Like the relay: a secret only when it generated one.
            if !supplied && !strict {
                out["secret"] = json!("s3cret");
            }
            json_resp(StatusCode::CREATED, out)
        }
        ("GET", path) if path.starts_with("/v1/hooks/") => {
            let id = &path["/v1/hooks/".len()..];
            let hook = st
                .lock()
                .unwrap()
                .hooks
                .iter()
                .find(|h| h["id"] == id)
                .cloned();
            match hook {
                Some(h) => json_resp(StatusCode::OK, h),
                None => json_resp(
                    StatusCode::NOT_FOUND,
                    json!({"error":"not_found","message":"Nothing is here."}),
                ),
            }
        }
        ("GET", "/v1/hooks") => {
            let hooks = st.lock().unwrap().hooks.clone();
            json_resp(StatusCode::OK, json!({ "hooks": hooks }))
        }
        ("POST", "/v1/ack") => {
            let v: Value = serde_json::from_slice(body).unwrap_or_default();
            let through = v["through"].as_u64().unwrap_or(0);
            let mut s = st.lock().unwrap();
            if s.fail_acks > 0 {
                s.fail_acks -= 1;
                s.failed_acks += 1;
                return json_resp(
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({"error":"internal","message":"Try again."}),
                );
            }
            check_recorded(&mut s, through);
            s.acks.push(through);
            s.acked = s.acked.max(through);
            let acked = s.acked;
            json_resp(StatusCode::OK, json!({ "acked": acked }))
        }
        ("DELETE", path) if path.starts_with("/v1/devices/") => {
            let id = path["/v1/devices/".len()..].to_string();
            let mut s = st.lock().unwrap();
            if !s.devices.contains_key(&id) {
                return json_resp(
                    StatusCode::NOT_FOUND,
                    json!({"error":"not_found","message":"Nothing is here."}),
                );
            }
            s.revoked.insert(id.clone());
            s.revocations.push((device.to_string(), id));
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::new(Bytes::new()).boxed())
                .unwrap()
        }
        ("GET", "/v1/stream") => {
            let last: Option<u64> = parts
                .headers
                .get("last-event-id")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok());
            let protocol = parts
                .headers
                .get("x-00h-protocol")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let conn = {
                let mut s = st.lock().unwrap();
                s.stream_requests.push(last);
                s.stream_protocols.push(protocol);
                s.script.pop_front().unwrap_or(Conn::Normal)
            };
            stream_response(st.clone(), last, conn, device.to_string())
        }
        _ => json_resp(
            StatusCode::NOT_FOUND,
            json!({"error":"not_found","message":"No such route."}),
        ),
    }
}

/// The delivery rule, seen from the relay: an ack may only cover events the client has recorded.
fn check_recorded(s: &mut State, through: u64) {
    let Some(home) = s.client_home.clone() else {
        return;
    };
    let mut ids = HashSet::new();
    let mut quarantined = HashSet::new();
    let text = std::fs::read_to_string(home.join("quarantine.jsonl")).unwrap_or_default();
    for line in text.lines() {
        if let Some(seq) = serde_json::from_str::<Value>(line)
            .ok()
            .and_then(|v| v["seq"].as_u64())
        {
            quarantined.insert(seq);
        }
    }
    for name in ["inbox.jsonl", "seen.jsonl"] {
        let text = std::fs::read_to_string(home.join(name)).unwrap_or_default();
        for line in text.lines() {
            if let Some(id) = serde_json::from_str::<Value>(line)
                .ok()
                .and_then(|v| v["id"].as_str().map(str::to_string))
            {
                ids.insert(id);
            }
        }
    }
    for e in &s.log {
        let seq = e["seq"].as_u64().unwrap();
        let id = e["id"].as_str().unwrap();
        if seq <= through && seq > s.acked && !ids.contains(id) && !quarantined.contains(&seq) {
            s.violations
                .push(format!("ack through {through} before {id} was recorded"));
        }
    }
}

struct ChanBody(mpsc::Receiver<Bytes>);

impl Body for ChanBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|o| o.map(|b| Ok(Frame::data(b))))
    }
}

fn frame(e: &Value) -> String {
    format!("id: {}\nevent: hook\ndata: {}\n\n", e["seq"], e)
}

/// The frame for `e` as `device` receives it (sealed when it has a key), garbled when the test
/// asked for its seq to be.
fn frame_for(st: &Arc<Mutex<State>>, device: &str, e: &Value) -> String {
    let seq = e["seq"].as_u64().unwrap();
    let s = st.lock().unwrap();
    if s.garbled.contains(&seq) {
        format!("id: {seq}\nevent: hook\ndata: {{\"seq\":{seq},\"id\":\"evt_garbled\n\n")
    } else {
        frame(&sealed_for(&s, device, e))
    }
}

/// The `hook-change` frames `device` hasn't been sent, marked sent (at most once per device).
fn unsent_hook_changes(st: &Arc<Mutex<State>>, device: &str) -> Vec<String> {
    let mut s = st.lock().unwrap();
    let from = s.hook_changes_sent.get(device).copied().unwrap_or(0);
    let frames: Vec<String> = s.hook_changes[from.min(s.hook_changes.len())..]
        .iter()
        .map(|c| format!("event: hook-change\ndata: {c}\n\n"))
        .collect();
    let total = s.hook_changes.len();
    s.hook_changes_sent.insert(device.to_string(), total);
    frames
}

fn stream_response(st: Arc<Mutex<State>>, last: Option<u64>, conn: Conn, device: String) -> Resp {
    let (tx, rx) = mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        let send = |s: String| {
            let tx = tx.clone();
            async move { tx.send(Bytes::from(s)).await.is_ok() }
        };
        let (acked, head, kid) = {
            let s = st.lock().unwrap();
            let head = s.log.last().and_then(|e| e["seq"].as_u64()).unwrap_or(0);
            (s.acked, head, s.seal_keys.get(&device).map(|k| seal_kid(k)))
        };
        let mut after = last.unwrap_or(0).max(acked);
        if let Conn::Rewind(n) = conn {
            after = after.saturating_sub(n);
        }
        let ready = json!({ "accountId": "acc_1", "deviceId": device, "after": after,
                            "head": head, "protocol": 2, "sealKid": kid });
        if !send(format!("retry: 5000\n\nevent: ready\ndata: {ready}\n\n")).await {
            return;
        }
        if let Conn::Silent = conn {
            tx.closed().await;
            return;
        }
        for f in unsent_hook_changes(&st, &device) {
            if !send(f).await {
                return;
            }
        }
        let limits: Vec<String> = st
            .lock()
            .unwrap()
            .limits
            .iter()
            .map(|l| format!("event: limit\ndata: {l}\n\n"))
            .collect();
        for f in limits {
            if !send(f).await {
                return;
            }
        }
        if let Conn::Gap(from, to) = conn {
            let gap = json!({ "from": from, "to": to, "reason": "retention" });
            if !send(format!("event: gap\ndata: {gap}\n\n")).await {
                return;
            }
        }
        let backlog: Vec<Value> = {
            let s = st.lock().unwrap();
            s.log
                .iter()
                .filter(|e| e["seq"].as_u64().unwrap() > after)
                .cloned()
                .collect()
        };
        let limit = match conn {
            Conn::CutAfter(n)
            | Conn::CloseAfter(n, _)
            | Conn::ResyncAfter(n)
            | Conn::SilentAfter(n) => n,
            _ => usize::MAX,
        };
        let mut sent = after;
        for e in backlog.iter().take(limit) {
            // Several frames per write, split mid-frame, so the client sees odd chunk boundaries.
            let f = frame_for(&st, &device, e);
            let (a, b) = f.split_at(f.len() / 3);
            if !send(a.to_string()).await || !send(b.to_string()).await {
                return;
            }
            sent = e["seq"].as_u64().unwrap();
        }
        match conn {
            Conn::CutAfter(_) => {
                if let Some(next) = backlog.get(limit) {
                    let f = frame_for(&st, &device, next);
                    let _ = send(f[..f.len() / 2].to_string()).await;
                }
                return;
            }
            Conn::CloseAfter(_, code) => {
                let closed = json!({ "code": code, "reason": "test" });
                let _ = send(format!("event: closed\ndata: {closed}\n\n")).await;
                return;
            }
            Conn::ResyncAfter(_) => {
                let _ = send(format!("event: resync\ndata: {{\"after\":{sent}}}\n\n")).await;
                tx.closed().await;
                return;
            }
            Conn::SilentAfter(_) => {
                tx.closed().await;
                return;
            }
            _ => {}
        }
        let trailing: Vec<String> = st.lock().unwrap().trailing.clone();
        for f in trailing {
            if !send(f).await {
                return;
            }
        }
        // Live: heartbeats, and any events appended to the log meanwhile.
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let fresh: Vec<Value> = {
                let s = st.lock().unwrap();
                s.log
                    .iter()
                    .filter(|e| e["seq"].as_u64().unwrap() > sent)
                    .cloned()
                    .collect()
            };
            for e in fresh {
                if !send(frame_for(&st, &device, &e)).await {
                    return;
                }
                sent = e["seq"].as_u64().unwrap();
            }
            for f in unsent_hook_changes(&st, &device) {
                if !send(f).await {
                    return;
                }
            }
            if !send(": hb\n".to_string()).await {
                return;
            }
        }
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache, no-transform")
        .header("x-accel-buffering", "no")
        .body(ChanBody(rx).boxed())
        .unwrap()
}

/// A fresh directory under the OS temp dir, removed when dropped.
pub struct TempHome(pub PathBuf);

impl TempHome {
    pub fn new(tag: &str) -> Self {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let d = std::env::temp_dir().join(format!("hooks-it-{tag}-{hex}"));
        std::fs::create_dir_all(&d).unwrap();
        TempHome(d)
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
