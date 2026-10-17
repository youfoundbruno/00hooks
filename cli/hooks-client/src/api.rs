//! The relay's HTTP API (PROTOCOL §2, §3, §7), with signed requests and clock-skew correction.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::json;
use url::Url;

use crate::keys::DeviceKey;
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

    /// `POST /v1/accounts`: a new account whose first device has `public_key`.
    pub async fn create_account(
        &self,
        device_name: &str,
        public_key: &str,
        signup_token: Option<&str>,
    ) -> Result<Joined> {
        let body = json!({ "deviceName": device_name, "publicKey": public_key });
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
    ) -> Result<Joined> {
        let body = json!({ "code": code, "deviceName": device_name, "publicKey": public_key });
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

    /// `POST /v1/hooks`. `verify` is `{ "preset": …, …fields }`.
    pub async fn create_hook(&self, name: &str, verify: serde_json::Value) -> Result<CreatedHook> {
        let body = json!({ "name": name, "verify": verify });
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

    /// `DELETE /v1/hooks/<id>`.
    pub async fn delete_hook(&self, id: &str) -> Result<()> {
        check_id("hk_", id)?;
        self.call_empty(Method::DELETE, &format!("/v1/hooks/{id}"))
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

    /// `GET /v1/stream`: the raw response, after checking it is an event stream.
    pub(crate) async fn open_stream(
        &self,
        last_event_id: Option<u64>,
    ) -> Result<reqwest::Response> {
        let mut extra = vec![("Accept", "text/event-stream".to_string())];
        if let Some(id) = last_event_id {
            extra.push(("Last-Event-ID", id.to_string()));
        }
        let resp = self
            .send(Method::GET, "/v1/stream", None, Auth::Signed, &extra, None)
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
