//! The relay's HTTP API (PROTOCOL §2, §3, §7), with signed requests and clock-skew correction.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::json;
use url::Url;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::keys::DeviceKey;
use crate::seal::Opener;
use crate::signing::{new_nonce, sign_with};
use crate::types::*;
use crate::{Error, Result};

/// How long an ordinary API call may take.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// The system clock, in Unix milliseconds.
pub fn system_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A client for one relay, optionally acting as one device. Cheap to clone.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

struct Inner {
    http: reqwest::Client,
    base: String,
    device: Option<(String, DeviceKey)>,
    /// Relay time minus our time, learned from a `clock_skew` refusal.
    offset_ms: AtomicI64,
    /// Opens this device's sealed events; a subscription uses it before recording anything.
    opener: RwLock<Option<Arc<Opener>>>,
}

enum Auth<'a> {
    None,
    Signed,
    Bearer(&'a str),
}

/// Check that a relay URL is usable: http(s), and https unless it points at this machine.
pub fn parse_relay_url(relay: &str) -> Result<Url> {
    let url = Url::parse(relay.trim())
        .map_err(|e| Error::Invalid(format!("{relay:?} isn't a URL ({e})")))?;
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&url) => {}
        "http" => {
            return Err(Error::Invalid(format!(
                "{relay} uses plain http; use https (http is allowed only for a relay on this machine)"
            )));
        }
        other => {
            return Err(Error::Invalid(format!(
                "{relay} uses {other}:; the relay URL must start with https://"
            )));
        }
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::Invalid(format!(
            "{relay} has a query or fragment; give just the relay's address"
        )));
    }
    Ok(url)
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d == "localhost" || d.ends_with(".localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Ids go into URL paths, so they are checked first: a prefix and lowercase base32.
pub fn check_id(prefix: &str, id: &str) -> Result<()> {
    let ok = id.len() <= 64
        && id.strip_prefix(prefix).is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
        });
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "{id:?} isn't a valid id (expected {prefix}…)"
        )))
    }
}

impl Client {
    /// A client that can make unsigned calls only (info, account creation, enrolment).
    pub fn new(relay: &str) -> Result<Self> {
        Self::build(relay, None)
    }

    /// A client that signs as `device_id` with `key`.
    pub fn with_device(relay: &str, device_id: &str, key: DeviceKey) -> Result<Self> {
        check_id("dev_", device_id)?;
        Self::build(relay, Some((device_id.to_string(), key)))
    }

    fn build(relay: &str, device: Option<(String, DeviceKey)>) -> Result<Self> {
        let url = parse_relay_url(relay)?;
        // reqwest is built without a bundled crypto provider; install ring once per process.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .user_agent(concat!("00hooks/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(CONNECT_TIMEOUT)
            // A signed request is bound to its host and path; never follow it anywhere else.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Network(e.to_string()))?;
        Ok(Client {
            inner: Arc::new(Inner {
                http,
                base: url.as_str().trim_end_matches('/').to_string(),
                device,
                offset_ms: AtomicI64::new(0),
                opener: RwLock::new(None),
            }),
        })
    }

    /// The relay URL, without a trailing slash.
    pub fn relay(&self) -> &str {
        &self.inner.base
    }

    pub fn device_id(&self) -> Option<&str> {
        self.inner.device.as_ref().map(|(id, _)| id.as_str())
    }

    /// Give the client what opens this device's sealed events (PROTOCOL §5). A [`crate::subscribe`]d
    /// stream then hands over opened events, and refuses unsealed ones.
    pub fn set_opener(&self, opener: Opener) {
        *self.inner.opener.write().expect("opener lock") = Some(Arc::new(opener));
    }

    pub fn opener(&self) -> Option<Arc<Opener>> {
        self.inner.opener.read().expect("opener lock").clone()
    }

    /// Relay time minus this computer's time, as learned from a `clock_skew` refusal (0 until then).
    pub fn clock_offset_ms(&self) -> i64 {
        self.inner.offset_ms.load(Ordering::Relaxed)
    }

    /// Use a known offset (for example from `/v1/info`) for the times we sign.
    pub fn set_clock_offset_ms(&self, offset: i64) {
        self.inner.offset_ms.store(offset, Ordering::Relaxed);
    }

    /// Now, on the relay's clock as far as we know it.
    pub fn now_ms(&self) -> i64 {
        system_now_ms() + self.clock_offset_ms()
    }

    pub(crate) fn url(&self, path: &str) -> Result<Url> {
        Url::parse(&format!("{}{path}", self.inner.base))
            .map_err(|e| Error::Invalid(format!("bad request path {path:?}: {e}")))
    }

    /// Send a request. A signed request refused with `clock_skew` is retried once with the relay's
    /// time; a second refusal is reported as [`Error::ClockSkew`].
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        auth: Auth<'_>,
        extra: &[(&str, String)],
        timeout: Option<Duration>,
    ) -> Result<reqwest::Response> {
        let url = self.url(path)?;
        let mut retried = false;
        loop {
            let mut req = self.inner.http.request(method.clone(), url.clone());
            if let Some(t) = timeout {
                req = req.timeout(t);
            }
            for (k, v) in extra {
                req = req.header(*k, v);
            }
            let bytes = body.clone().unwrap_or_default();
            match auth {
                Auth::None => {}
                Auth::Bearer(token) => req = req.bearer_auth(token),
                Auth::Signed => {
                    let (device_id, key) = self.inner.device.as_ref().ok_or_else(|| {
                        Error::Invalid("this request needs a device; log in first".into())
                    })?;
                    let headers = sign_with(
                        key,
                        device_id,
                        method.as_str(),
                        &url,
                        &bytes,
                        self.now_ms(),
                        &new_nonce()?,
                    )?;
                    for (k, v) in headers.pairs() {
                        req = req.header(k, v);
                    }
                }
            }
            if body.is_some() {
                req = req
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(bytes);
            }
            let resp = req.send().await?;
            if resp.status() != StatusCode::UNAUTHORIZED || !matches!(auth, Auth::Signed) {
                return Ok(resp);
            }
            let status = resp.status().as_u16();
            let local = system_now_ms();
            let err = read_error_body(resp).await;
            match (err.error.as_str(), err.server_time) {
                ("clock_skew", Some(server_time)) => {
                    let skew = server_time - local;
                    self.set_clock_offset_ms(skew);
                    if retried {
                        return Err(Error::ClockSkew { skew_ms: skew });
                    }
                    retried = true;
                }
                _ => return Err(api_error(status, err)),
            }
        }
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
        auth: Auth<'_>,
    ) -> Result<T> {
        let body = body.map(|b| serde_json::to_vec(&b).expect("json"));
        let resp = self
            .send(method, path, body, auth, &[], Some(CALL_TIMEOUT))
            .await?;
        decode(resp).await
    }

    async fn call_empty(&self, method: Method, path: &str) -> Result<()> {
        let resp = self
            .send(method, path, None, Auth::Signed, &[], Some(CALL_TIMEOUT))
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status().as_u16();
            Err(api_error(status, read_error_body(resp).await))
        }
    }

    /// `GET /v1/info` (unsigned).
    pub async fn info(&self) -> Result<Info> {
        self.call(Method::GET, "/v1/info", None, Auth::None).await
    }

    /// `POST /v1/accounts`: a new account whose first device has `public_key` (and, from
    /// protocol 2, the sealing key `seal_key`).
    pub async fn create_account(
        &self,
        device_name: &str,
        public_key: &str,
        seal_key: Option<&str>,
        signup_token: Option<&str>,
    ) -> Result<Joined> {
        let mut body = json!({ "deviceName": device_name, "publicKey": public_key });
        if let Some(k) = seal_key {
            body["sealKey"] = json!(k);
        }
        let auth = match signup_token {
            Some(t) => Auth::Bearer(t),
            None => Auth::None,
        };
        self.call(Method::POST, "/v1/accounts", Some(body), auth)
            .await
    }

    /// `POST /v1/enrolments`: a one-time code for adding another device.
    pub async fn create_enrolment(&self) -> Result<Enrolment> {
        self.call(Method::POST, "/v1/enrolments", None, Auth::Signed)
            .await
    }

    /// `POST /v1/enrolments/redeem`: join the account that issued `code`.
    pub async fn redeem_enrolment(
        &self,
        code: &str,
        device_name: &str,
        public_key: &str,
        seal_key: Option<&str>,
    ) -> Result<Joined> {
        let mut body = json!({ "code": code, "deviceName": device_name, "publicKey": public_key });
        if let Some(k) = seal_key {
            body["sealKey"] = json!(k);
        }
        self.call(
            Method::POST,
            "/v1/enrolments/redeem",
            Some(body),
            Auth::None,
        )
        .await
    }

    /// `GET /v1/devices`.
    pub async fn devices(&self) -> Result<Vec<DeviceInfo>> {
        #[derive(serde::Deserialize)]
        struct R {
            devices: Vec<DeviceInfo>,
        }
        let r: R = self
            .call(Method::GET, "/v1/devices", None, Auth::Signed)
            .await?;
        Ok(r.devices)
    }

    /// `DELETE /v1/devices/<id>`.
    pub async fn revoke_device(&self, id: &str) -> Result<()> {
        check_id("dev_", id)?;
        self.call_empty(Method::DELETE, &format!("/v1/devices/{id}"))
            .await
    }

    /// `PATCH /v1/devices/<id>`: rename a device (1 to 100 characters, trimmed).
    pub async fn rename_device(&self, id: &str, name: &str) -> Result<DeviceInfo> {
        check_id("dev_", id)?;
        #[derive(serde::Deserialize)]
        struct R {
            device: DeviceInfo,
        }
        let r: R = self
            .call(
                Method::PATCH,
                &format!("/v1/devices/{id}"),
                Some(json!({ "name": name.trim() })),
                Auth::Signed,
            )
            .await?;
        Ok(r.device)
    }

    /// `PUT /v1/devices/<id>/seal-key`: this device's sealing key; returns its kid.
    pub async fn set_seal_key(&self, seal_key: &str) -> Result<String> {
        #[derive(serde::Deserialize)]
        struct R {
            kid: String,
        }
        let id = self
            .device_id()
            .ok_or_else(|| Error::Invalid("this request needs a device; log in first".into()))?
            .to_string();
        let r: R = self
            .call(
                Method::PUT,
                &format!("/v1/devices/{id}/seal-key"),
                Some(json!({ "sealKey": seal_key })),
                Auth::Signed,
            )
            .await?;
        Ok(r.kid)
    }

    /// `POST /v1/keys`: an API key; its token is in the answer only.
    pub async fn create_key(
        &self,
        name: &str,
        scopes: &[String],
        expires_in_days: Option<u32>,
    ) -> Result<CreatedKey> {
        let mut body = json!({ "name": name, "scopes": scopes });
        if let Some(d) = expires_in_days {
            body["expiresInDays"] = json!(d);
        }
        self.call(Method::POST, "/v1/keys", Some(body), Auth::Signed)
            .await
    }

    /// `GET /v1/keys`.
    pub async fn keys(&self) -> Result<Vec<ApiKey>> {
        #[derive(serde::Deserialize)]
        struct R {
            keys: Vec<ApiKey>,
        }
        let r: R = self
            .call(Method::GET, "/v1/keys", None, Auth::Signed)
            .await?;
        Ok(r.keys)
    }

    /// `DELETE /v1/keys/<id>`.
    pub async fn revoke_key(&self, id: &str) -> Result<()> {
        check_id("key_", id)?;
        self.call_empty(Method::DELETE, &format!("/v1/keys/{id}"))
            .await
    }

    /// `GET /v1/audit`.
    pub async fn audit(&self, since: Option<i64>, limit: Option<u32>) -> Result<Vec<AuditEntry>> {
        #[derive(serde::Deserialize)]
        struct R {
            entries: Vec<AuditEntry>,
        }
        let mut q = Vec::new();
        if let Some(s) = since {
            q.push(format!("since={s}"));
        }
        if let Some(l) = limit {
            q.push(format!("limit={l}"));
        }
        let path = if q.is_empty() {
            "/v1/audit".to_string()
        } else {
            format!("/v1/audit?{}", q.join("&"))
        };
        let r: R = self.call(Method::GET, &path, None, Auth::Signed).await?;
        Ok(r.entries)
    }

    /// `POST /v1/hooks`. `verify` is `{ "preset": …, …fields }`.
    pub async fn create_hook(&self, name: &str, verify: serde_json::Value) -> Result<CreatedHook> {
        self.create_hook_with(name, verify, None).await
    }

    /// `POST /v1/hooks` with an offline notice (PROTOCOL §4a), for presets that can carry one.
    pub async fn create_hook_with(
        &self,
        name: &str,
        verify: serde_json::Value,
        offline_notice: Option<&OfflineNotice>,
    ) -> Result<CreatedHook> {
        let mut body = json!({ "name": name, "verify": verify });
        if let Some(n) = offline_notice {
            body["offlineNotice"] = serde_json::to_value(n).expect("json");
        }
        self.call(Method::POST, "/v1/hooks", Some(body), Auth::Signed)
            .await
    }

    /// `GET /v1/hooks`.
    pub async fn hooks(&self) -> Result<Vec<Hook>> {
        #[derive(serde::Deserialize)]
        struct R {
            hooks: Vec<Hook>,
        }
        let r: R = self
            .call(Method::GET, "/v1/hooks", None, Auth::Signed)
            .await?;
        Ok(r.hooks)
    }

    /// `GET /v1/hooks/<id>`.
    pub async fn hook(&self, id: &str) -> Result<Hook> {
        check_id("hk_", id)?;
        self.call(Method::GET, &format!("/v1/hooks/{id}"), None, Auth::Signed)
            .await
    }

    /// `PATCH /v1/hooks/<id>`.
    pub async fn patch_hook(&self, id: &str, patch: &HookPatch) -> Result<Hook> {
        check_id("hk_", id)?;
        let body = serde_json::to_value(patch).expect("json");
        self.call(
            Method::PATCH,
            &format!("/v1/hooks/{id}"),
            Some(body),
            Auth::Signed,
        )
        .await
    }

    /// `POST /v1/hooks/<id>/rotate`: a new secret; the old one works for 24 h more.
    pub async fn rotate_hook(&self, id: &str) -> Result<Rotated> {
        check_id("hk_", id)?;
        self.call(
            Method::POST,
            &format!("/v1/hooks/{id}/rotate"),
            None,
            Auth::Signed,
        )
        .await
    }

    /// `POST /v1/test/<hookId>`: the relay sends the hook a signed sample event of kind
    /// `00hooks.test`, and says what the delivery got.
    pub async fn test_hook(&self, id: &str) -> Result<TestSent> {
        check_id("hk_", id)?;
        self.call(Method::POST, &format!("/v1/test/{id}"), None, Auth::Signed)
            .await
    }

    /// `DELETE /v1/hooks/<id>`.
    pub async fn delete_hook(&self, id: &str) -> Result<()> {
        check_id("hk_", id)?;
        self.call_empty(Method::DELETE, &format!("/v1/hooks/{id}"))
            .await
    }

    /// `GET /v1/hooks/<id>/screen` (PROTOCOL §4b): the hook's edge screen, or `None`.
    pub async fn hook_screen(&self, id: &str) -> Result<Option<serde_json::Value>> {
        check_id("hk_", id)?;
        #[derive(serde::Deserialize)]
        struct R {
            screen: Option<serde_json::Value>,
        }
        let r: R = self
            .call(
                Method::GET,
                &format!("/v1/hooks/{id}/screen"),
                None,
                Auth::Signed,
            )
            .await?;
        Ok(r.screen)
    }

    /// `PUT /v1/hooks/<id>/screen`: replace the hook's edge screen (`None` removes it). Returns it as
    /// the relay keeps it.
    pub async fn put_hook_screen(
        &self,
        id: &str,
        screen: Option<&serde_json::Value>,
    ) -> Result<Option<serde_json::Value>> {
        check_id("hk_", id)?;
        #[derive(serde::Deserialize)]
        struct R {
            screen: Option<serde_json::Value>,
        }
        let r: R = self
            .call(
                Method::PUT,
                &format!("/v1/hooks/{id}/screen"),
                Some(json!({ "screen": screen })),
                Auth::Signed,
            )
            .await?;
        Ok(r.screen)
    }

    /// `GET /v1/screen/key`: the account's screen key, which field values are hashed with before
    /// they go to the edge.
    pub async fn screen_key(&self) -> Result<Vec<u8>> {
        #[derive(serde::Deserialize)]
        struct R {
            key: String,
        }
        let r: R = self
            .call(Method::GET, "/v1/screen/key", None, Auth::Signed)
            .await?;
        URL_SAFE_NO_PAD
            .decode(r.key.as_bytes())
            .ok()
            .filter(|k| k.len() == 32)
            .ok_or_else(|| Error::Invalid("the relay's screen key isn't 32 bytes".into()))
    }

    /// `GET /v1/held`: the events the relay's screen holds.
    pub async fn held(&self) -> Result<Vec<HeldEvent>> {
        #[derive(serde::Deserialize)]
        struct R {
            held: Vec<HeldEvent>,
        }
        let r: R = self
            .call(Method::GET, "/v1/held", None, Auth::Signed)
            .await?;
        Ok(r.held)
    }

    /// `POST /v1/held/<id>/release`: the event is streamed now. Returns its seq.
    pub async fn release_held(&self, id: &str) -> Result<u64> {
        check_id("evt_", id)?;
        #[derive(serde::Deserialize)]
        struct R {
            seq: u64,
        }
        let r: R = self
            .call(
                Method::POST,
                &format!("/v1/held/{id}/release"),
                None,
                Auth::Signed,
            )
            .await?;
        Ok(r.seq)
    }

    /// `DELETE /v1/held/<id>`: the event is never streamed.
    pub async fn drop_held(&self, id: &str) -> Result<()> {
        check_id("evt_", id)?;
        self.call_empty(Method::DELETE, &format!("/v1/held/{id}"))
            .await
    }

    /// `POST /v1/ack`: everything through `seq` is recorded locally. Returns the relay's ack.
    pub async fn ack(&self, through: u64) -> Result<u64> {
        #[derive(serde::Deserialize)]
        struct R {
            acked: u64,
        }
        let r: R = self
            .call(
                Method::POST,
                "/v1/ack",
                Some(json!({ "through": through })),
                Auth::Signed,
            )
            .await?;
        Ok(r.acked)
    }

    /// `GET /v1/stream` (or, with `probe`, `?probe=1`): the raw response, after checking it is an
    /// event stream.
    pub(crate) async fn open_stream(
        &self,
        last_event_id: Option<u64>,
        probe: bool,
    ) -> Result<reqwest::Response> {
        let mut extra = vec![
            ("Accept", "text/event-stream".to_string()),
            ("X-00h-Protocol", crate::PROTOCOL_VERSION.to_string()),
        ];
        if let Some(id) = last_event_id {
            extra.push(("Last-Event-ID", id.to_string()));
        }
        let path = if probe {
            "/v1/stream?probe=1"
        } else {
            "/v1/stream"
        };
        let resp = self
            .send(Method::GET, path, None, Auth::Signed, &extra, None)
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(api_error(status.as_u16(), read_error_body(resp).await));
        }
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !ct.starts_with("text/event-stream") {
            return Err(Error::Protocol(format!(
                "the stream answered with {ct:?} instead of text/event-stream"
            )));
        }
        Ok(resp)
    }
}

async fn read_error_body(resp: reqwest::Response) -> ErrorBody {
    let status = resp.status();
    let bytes = resp.bytes().await.unwrap_or_default();
    serde_json::from_slice::<ErrorBody>(&bytes).unwrap_or_else(|_| ErrorBody {
        error: status
            .canonical_reason()
            .unwrap_or("error")
            .to_ascii_lowercase()
            .replace(' ', "_"),
        ..Default::default()
    })
}

fn api_error(status: u16, e: ErrorBody) -> Error {
    Error::Api {
        status,
        code: e.error,
        message: e.message,
        field: e.field,
    }
}

async fn decode<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let status = resp.status();
    if !status.is_success() {
        return Err(api_error(status.as_u16(), read_error_body(resp).await));
    }
    let bytes = resp.bytes().await?;
    serde_json::from_slice(&bytes).map_err(|e| Error::Protocol(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_urls_must_be_https_unless_local() {
        assert!(parse_relay_url("https://relay.example.com").is_ok());
        assert!(parse_relay_url("http://127.0.0.1:8787").is_ok());
        assert!(parse_relay_url("http://localhost:8787").is_ok());
        assert!(parse_relay_url("http://[::1]:8787").is_ok());
        assert!(parse_relay_url("http://relay.example.com").is_err());
        assert!(parse_relay_url("ftp://relay.example.com").is_err());
        assert!(parse_relay_url("https://relay.example.com/?x=1").is_err());
        assert!(parse_relay_url("relay.example.com").is_err());
    }

    #[test]
    fn ids_are_checked_before_going_into_paths() {
        assert!(check_id("hk_", "hk_0abc9").is_ok());
        assert!(check_id("hk_", "hk_").is_err());
        assert!(check_id("hk_", "dev_abc").is_err());
        assert!(check_id("hk_", "hk_../x").is_err());
        assert!(check_id("hk_", "hk_ABC").is_err());
    }

    #[test]
    fn a_path_prefix_in_the_relay_url_is_kept() {
        let c = Client::new("https://relay.example.com/base/").unwrap();
        assert_eq!(
            c.url("/v1/info").unwrap().as_str(),
            "https://relay.example.com/base/v1/info"
        );
    }
}
