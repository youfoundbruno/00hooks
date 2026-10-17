//! A tiny in-process relay implementing just enough of PROTOCOL.md for the client's tests: signed
//! request checks (time window, nonces, signatures), accounts, `/v1/stream` with a backlog and
//! scripted misbehaviour, and `/v1/ack`, which checks that everything acknowledged was recorded in
//! the client's state directory first.

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
use ed25519_dalek::{Signature, VerifyingKey};
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
    /// Seqs whose `hook` frame is sent garbled (data that isn't an event).
    pub garbled: HashSet<u64>,
    /// `DELETE /v1/devices/<id>`: (the signing device, the revoked id), in order.
    pub revocations: Vec<(String, String)>,
    /// The enrolment code `POST /v1/enrolments/redeem` accepts.
    pub enrolment_code: Option<String>,
    next_device: usize,
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
    let resp = match route {
        ("GET", "/v1/info") => {
            let offset = st.lock().unwrap().clock_offset_ms;
            json_resp(
                StatusCode::OK,
                json!({ "version": "mock", "protocol": 1, "signupOpen": true,
                        "serverTime": now_ms() + offset }),
            )
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
        ("GET", "/v1/devices") => json_resp(
            StatusCode::OK,
            json!({ "devices": [{ "id": device, "name": "test", "createdAt": 1,
                                  "lastSeenAt": null, "current": true }] }),
        ),
        ("POST", "/v1/hooks") => {
            let v: Value = serde_json::from_slice(body).unwrap_or_default();
            let hook = json!({ "id": "hk_1", "name": v["name"], "url": "https://relay.example/h/hk_1",
                               "enabled": true, "verify": { "preset": v["verify"]["preset"] },
                               "maxBodyBytes": 1048576, "createdAt": 1, "lastEventAt": null });
            st.lock().unwrap().hooks.push(hook.clone());
            json_resp(
                StatusCode::CREATED,
                json!({ "hook": hook, "url": "https://relay.example/h/hk_1",
                        "secret": "s3cret" }),
            )
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
            let conn = {
                let mut s = st.lock().unwrap();
                s.stream_requests.push(last);
                s.script.pop_front().unwrap_or(Conn::Normal)
            };
            stream_response(st.clone(), last, conn)
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

/// The frame for `e`, garbled when the test asked for its seq to be.
fn frame_for(st: &Arc<Mutex<State>>, e: &Value) -> String {
    let seq = e["seq"].as_u64().unwrap();
    if st.lock().unwrap().garbled.contains(&seq) {
        format!("id: {seq}\nevent: hook\ndata: {{\"seq\":{seq},\"id\":\"evt_garbled\n\n")
    } else {
        frame(e)
    }
}

fn stream_response(st: Arc<Mutex<State>>, last: Option<u64>, conn: Conn) -> Resp {
    let (tx, rx) = mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        let send = |s: String| {
            let tx = tx.clone();
            async move { tx.send(Bytes::from(s)).await.is_ok() }
        };
        let (acked, head) = {
            let s = st.lock().unwrap();
            let head = s.log.last().and_then(|e| e["seq"].as_u64()).unwrap_or(0);
            (s.acked, head)
        };
        let mut after = last.unwrap_or(0).max(acked);
        if let Conn::Rewind(n) = conn {
            after = after.saturating_sub(n);
        }
        let ready =
            json!({ "accountId": "acc_1", "deviceId": "dev_1", "after": after, "head": head });
        if !send(format!("retry: 5000\n\nevent: ready\ndata: {ready}\n\n")).await {
            return;
        }
        if let Conn::Silent = conn {
            tx.closed().await;
            return;
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
            Conn::CutAfter(n) | Conn::CloseAfter(n, _) | Conn::ResyncAfter(n) => n,
            _ => usize::MAX,
        };
        let mut sent = after;
        for e in backlog.iter().take(limit) {
            // Several frames per write, split mid-frame, so the client sees odd chunk boundaries.
            let f = frame_for(&st, e);
            let (a, b) = f.split_at(f.len() / 3);
            if !send(a.to_string()).await || !send(b.to_string()).await {
                return;
            }
            sent = e["seq"].as_u64().unwrap();
        }
        match conn {
            Conn::CutAfter(_) => {
                if let Some(next) = backlog.get(limit) {
                    let f = frame(next);
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
            _ => {}
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
                if !send(frame_for(&st, &e)).await {
                    return;
                }
                sent = e["seq"].as_u64().unwrap();
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
