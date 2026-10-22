//! Call a URL: the host is fixed in the configuration and checked against the automation's
//! allowlist again at send time; template values in the path or query are percent-encoded; secret
//! headers are read from the store just before sending; no redirects are followed (a redirect
//! could leave the allowlist). Every call carries `00hooks-origin`, `00hooks-hop` and an
//! `Idempotency-Key`.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{Map, Value};

use super::{Failure, Outcome};
use crate::config::host_allowed;
use crate::path::Seg;
use crate::secrets::SecretStore;
use crate::template::{JsonTemplate, Template};
use crate::{HOP_HEADER, ORIGIN_HEADER};

/// The largest body a call sends: a batch's events beyond it fail the call (nothing is cut
/// silently; the batch is kept for `00hooks replay`).
pub const MAX_BODY: usize = 10 * 1024 * 1024;

/// An HTTP client for actions: no redirects, a user agent, ring for TLS.
pub fn http_client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .user_agent(concat!("00hooks/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .build()
        .expect("http client")
}

/// Percent-encode everything but RFC 3986's unreserved characters.
pub fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub struct Call<'a> {
    pub method: &'a str,
    pub url: &'a Template,
    pub headers: &'a [(String, Template)],
    pub body: Option<&'a JsonTemplate>,
    pub idempotency_key: &'a Template,
    pub timeout: Duration,
    pub allow_hosts: &'a [String],
    pub origin: &'a str,
    pub hop: u32,
}

pub async fn call(
    http: &reqwest::Client,
    c: &Call<'_>,
    ctx: &Value,
    secrets: &dyn SecretStore,
) -> Outcome {
    let url_text = c.url.render_with(ctx, &encode_component);
    let url = reqwest::Url::parse(&url_text)
        .map_err(|e| Failure::fatal(format!("the URL isn't valid once filled in ({e})")))?;
    let host = url.host_str().unwrap_or_default();
    if !host_allowed(host, c.allow_hosts) || !matches!(url.scheme(), "http" | "https") {
        return Err(Failure::fatal(format!("the host {host} isn't allowed")));
    }

    // Secrets: read only the ones these headers name, now.
    let mut secret_values = Map::new();
    for (_, t) in c.headers {
        for p in t.paths() {
            if let (Some(Seg::Key(root)), Some(Seg::Key(name))) = (p.segs.first(), p.segs.get(1))
                && root == "secret"
                && !secret_values.contains_key(name)
            {
                match secrets.get(name) {
                    Ok(Some(v)) => {
                        secret_values.insert(name.clone(), Value::String(v));
                    }
                    Ok(None) => {
                        return Err(Failure::fatal(format!(
                            "the secret {name} isn't set; run `00hooks secrets set {name}`"
                        )));
                    }
                    Err(e) => {
                        return Err(Failure::retry(format!(
                            "couldn't read the secret {name}: {e}"
                        )));
                    }
                }
            }
        }
    }
    let mut header_ctx = ctx.clone();
    if !secret_values.is_empty()
        && let Value::Object(m) = &mut header_ctx
    {
        m.insert("secret".into(), Value::Object(secret_values));
    }

    let mut headers = HeaderMap::new();
    for (name, t) in c.headers {
        let value = t.render(&header_ctx);
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Failure::fatal(format!("{name:?} isn't a valid header name")))?;
        // Never echo the value: it may hold a secret.
        let value = HeaderValue::from_str(&value).map_err(|_| {
            Failure::fatal(format!(
                "the {name} header's value has characters a header can't carry"
            ))
        })?;
        headers.insert(name, value);
    }
    let set = |h: &mut HeaderMap, n: &'static str, v: &str| {
        if let Ok(v) = HeaderValue::from_str(v) {
            h.insert(HeaderName::from_static(n), v);
        }
    };
    set(&mut headers, ORIGIN_HEADER, c.origin);
    set(&mut headers, HOP_HEADER, &(c.hop + 1).to_string());
    let key = crate::text::sanitize(&c.idempotency_key.render(ctx));
    set(
        &mut headers,
        "idempotency-key",
        &crate::text::cut(&key, 255),
    );

    let method = reqwest::Method::from_bytes(c.method.as_bytes())
        .map_err(|_| Failure::fatal(format!("{} isn't an HTTP method", c.method)))?;
    let body = match c.body {
        Some(t) => Some(t.render(ctx)),
        // A batch's run sends its events, as a JSON array.
        None if matches!(c.method, "POST" | "PUT" | "PATCH") && ctx.get("batch").is_some() => Some(
            ctx.get("events")
                .cloned()
                .unwrap_or(Value::Array(Vec::new())),
        ),
        None if matches!(c.method, "POST" | "PUT" | "PATCH") => Some(serde_json::json!({
            "event": ctx.get("event"),
            "headers": ctx.get("headers"),
            "payload": ctx.get("payload"),
        })),
        None => None,
    };
    let mut req = http
        .request(method, url.clone())
        .headers(headers)
        .timeout(c.timeout);
    if let Some(b) = body {
        let bytes = serde_json::to_vec(&b).expect("json");
        if bytes.len() > MAX_BODY {
            return Err(Failure::fatal(format!(
                "the body would be {} MiB, more than the {} MiB a call sends; nothing was sent \
                 (for a batch, lower max_events, or use run or write)",
                bytes.len().div_ceil(1024 * 1024),
                MAX_BODY / (1024 * 1024)
            )));
        }
        req = req.header("content-type", "application/json").body(bytes);
    }
    let resp = req.send().await.map_err(|e| {
        let what = if e.is_timeout() {
            format!("no answer within {} s", c.timeout.as_secs())
        } else if e.is_connect() {
            "couldn't connect".to_string()
        } else {
            "the request failed".to_string()
        };
        Failure::retry(format!("{what} ({host})"))
    })?;
    let status = resp.status();
    let detail = format!("HTTP {} from {host}", status.as_u16());
    if status.is_success() {
        Ok(detail)
    } else if status.is_server_error() || status.as_u16() == 429 || status.as_u16() == 408 {
        Err(Failure::retry(detail))
    } else if status.is_redirection() {
        Err(Failure::fatal(format!(
            "{detail}: redirects aren't followed"
        )))
    } else {
        Err(Failure::fatal(detail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components_are_fully_encoded() {
        assert_eq!(
            encode_component("a b/c?d#e&f=g"),
            "a%20b%2Fc%3Fd%23e%26f%3Dg"
        );
        assert_eq!(encode_component("ok-._~9"), "ok-._~9");
        assert_eq!(encode_component("é"), "%C3%A9");
        assert_eq!(encode_component("@evil.org"), "%40evil.org");
    }
}
