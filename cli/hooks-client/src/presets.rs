//! Provider signature checks on the device, for strict hooks (PROTOCOL §3): the relay keeps no secret
//! for them, so the device verifies what the provider signed. The same declarative table as the
//! relay's (`relay/src/presets.ts`), held to the same vectors (`fixtures/presets.v1.json`).
//!
//! Everything runs over the raw bytes, every signature comparison is constant-time, and every
//! candidate signature is tried against every secret.

use std::collections::BTreeMap;

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::types::decode_base64_lenient;

/// Event types are labels: anything longer is cut (PROTOCOL §5).
pub const EVENT_TYPE_MAX: usize = 200;

/// One piece of the signed content.
#[derive(Debug, Clone, Copy)]
enum Part {
    Body,
    Text(&'static str),
    Header(&'static str),
    SigParam(&'static str),
    /// Twilio: the URL, then the sorted form parameters (or the URL alone, for JSON).
    Twilio,
}

#[derive(Debug, Clone)]
enum SigFormat {
    Single { prefix: String },
    Versioned { version: &'static str },
    Params { param: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mac_ {
    HmacSha256,
    HmacSha1,
    Ed25519,
    Token,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum KeyForm {
    Utf8,
    Whsec,
    Whpk,
}

#[derive(Debug, Clone, Copy)]
enum Encoding {
    Hex,
    Base64,
}

#[derive(Debug, Clone, Copy)]
enum TsSource {
    Header(&'static str),
    SigParam(&'static str),
    BodyField(&'static str),
}

#[derive(Debug, Clone, Copy)]
struct Timestamp {
    source: TsSource,
    millis: bool,
    tolerance_s: i64,
}

#[derive(Debug, Clone, Copy)]
enum TypeSource {
    Header(&'static str),
    BodyFields(&'static [&'static str]),
}

/// One preset (PROTOCOL §3's table).
#[derive(Debug, Clone)]
struct Spec {
    mac: Mac_,
    key: KeyForm,
    sig: Option<(String, SigFormat, Encoding)>,
    signed: &'static [Part],
    timestamp: Option<Timestamp>,
    event_type: Option<TypeSource>,
}

const BODY: &[Part] = &[Part::Body];
const STANDARD: &[Part] = &[
    Part::Header("webhook-id"),
    Part::Text("."),
    Part::Header("webhook-timestamp"),
    Part::Text("."),
    Part::Body,
];
const STRIPE: &[Part] = &[Part::SigParam("t"), Part::Text("."), Part::Body];
const SLACK: &[Part] = &[
    Part::Text("v0:"),
    Part::Header("x-slack-request-timestamp"),
    Part::Text(":"),
    Part::Body,
];
const TWILIO: &[Part] = &[Part::Twilio];

fn sig(header: &str, f: SigFormat, e: Encoding) -> Option<(String, SigFormat, Encoding)> {
    Some((header.to_string(), f, e))
}

/// The spec of a hook, from its `verify` object (the generic `hmac` preset takes its header,
/// algorithm, encoding and prefix from it). `None` for an unknown preset.
fn spec(verify: &Value) -> Option<Spec> {
    let preset = verify.get("preset")?.as_str()?;
    let field = |k: &str| verify.get(k).and_then(Value::as_str);
    let s = match preset {
        "github" => Spec {
            mac: Mac_::HmacSha256,
            key: KeyForm::Utf8,
            sig: sig(
                "x-hub-signature-256",
                SigFormat::Single {
                    prefix: "sha256=".into(),
                },
                Encoding::Hex,
            ),
            signed: BODY,
            timestamp: None,
            event_type: Some(TypeSource::Header("x-github-event")),
        },
        "standard-webhooks" | "standard-webhooks-ed25519" => {
            let ed = preset == "standard-webhooks-ed25519";
            Spec {
                mac: if ed { Mac_::Ed25519 } else { Mac_::HmacSha256 },
                key: if ed { KeyForm::Whpk } else { KeyForm::Whsec },
                sig: sig(
                    "webhook-signature",
                    SigFormat::Versioned {
                        version: if ed { "v1a" } else { "v1" },
                    },
                    Encoding::Base64,
                ),
                signed: STANDARD,
                timestamp: Some(Timestamp {
                    source: TsSource::Header("webhook-timestamp"),
                    millis: false,
                    tolerance_s: 300,
                }),
                event_type: Some(TypeSource::BodyFields(&["type"])),
            }
        }
        "stripe" => Spec {
            mac: Mac_::HmacSha256,
            key: KeyForm::Utf8,
            sig: sig(
                "stripe-signature",
                SigFormat::Params { param: "v1" },
                Encoding::Hex,
            ),
            signed: STRIPE,
            timestamp: Some(Timestamp {
                source: TsSource::SigParam("t"),
                millis: false,
                tolerance_s: 300,
            }),
            event_type: Some(TypeSource::BodyFields(&["type"])),
        },
        "slack" => Spec {
            mac: Mac_::HmacSha256,
            key: KeyForm::Utf8,
            sig: sig(
                "x-slack-signature",
                SigFormat::Single {
                    prefix: "v0=".into(),
                },
                Encoding::Hex,
            ),
            signed: SLACK,
            timestamp: Some(Timestamp {
                source: TsSource::Header("x-slack-request-timestamp"),
                millis: false,
                tolerance_s: 300,
            }),
            event_type: Some(TypeSource::BodyFields(&["event.type", "type"])),
        },
        "linear" => Spec {
            mac: Mac_::HmacSha256,
            key: KeyForm::Utf8,
            sig: sig(
                "linear-signature",
                SigFormat::Single {
                    prefix: String::new(),
                },
                Encoding::Hex,
            ),
            signed: BODY,
            timestamp: Some(Timestamp {
                source: TsSource::BodyField("webhookTimestamp"),
                millis: true,
                tolerance_s: 60,
            }),
            event_type: Some(TypeSource::BodyFields(&["type"])),
        },
        "shopify" => Spec {
            mac: Mac_::HmacSha256,
            key: KeyForm::Utf8,
            sig: sig(
                "x-shopify-hmac-sha256",
                SigFormat::Single {
                    prefix: String::new(),
                },
                Encoding::Base64,
            ),
            signed: BODY,
            timestamp: None,
            event_type: Some(TypeSource::Header("x-shopify-topic")),
        },
        "twilio" => Spec {
            mac: Mac_::HmacSha1,
            key: KeyForm::Utf8,
            sig: sig(
                "x-twilio-signature",
                SigFormat::Single {
                    prefix: String::new(),
                },
                Encoding::Base64,
            ),
            signed: TWILIO,
            timestamp: None,
            event_type: None,
        },
        "hmac" => Spec {
            mac: if field("algorithm") == Some("sha1") {
                Mac_::HmacSha1
            } else {
                Mac_::HmacSha256
            },
            key: KeyForm::Utf8,
            sig: Some((
                field("header")?.to_ascii_lowercase(),
                SigFormat::Single {
                    prefix: field("prefix").unwrap_or("").to_string(),
                },
                if field("encoding") == Some("base64") {
                    Encoding::Base64
                } else {
                    Encoding::Hex
                },
            )),
            signed: BODY,
            timestamp: None,
            event_type: None,
        },
        "token" => Spec {
            mac: Mac_::Token,
            key: KeyForm::Utf8,
            sig: None,
            signed: &[],
            timestamp: None,
            event_type: None,
        },
        "unverified" => Spec {
            mac: Mac_::None,
            key: KeyForm::Utf8,
            sig: None,
            signed: &[],
            timestamp: None,
            event_type: None,
        },
        _ => return None,
    };
    Some(s)
}

/// One delivery, as the device has it: the headers lowercased.
pub struct Delivery<'a> {
    pub headers: &'a BTreeMap<String, String>,
    pub body: &'a [u8],
    /// Unix ms: the relay's `receivedAt` (signed), so an event read later still verifies.
    pub now_ms: i64,
    /// The public URL the relay was reached at (Twilio signs it).
    pub url: Option<&'a str>,
}

/// The outcome of a check.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub ok: bool,
    /// The provider's event type, when the preset reads one (from a signed body, or a header).
    pub event_type: Option<String>,
}

const REFUSED: Verdict = Verdict {
    ok: false,
    event_type: None,
};

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Constant-time equality (the lengths may leak, as they do everywhere).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Stripe-style `k=v,k=v` parameters; every value of a repeated key is kept.
fn sig_params(value: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for part in value.split(',') {
        if let Some((k, v)) = part.split_once('=')
            && !k.trim().is_empty()
        {
            out.entry(k.trim().to_string())
                .or_default()
                .push(v.trim().to_string());
        }
    }
    out
}

fn candidates(
    spec: &Spec,
    headers: &BTreeMap<String, String>,
) -> (Vec<Vec<u8>>, BTreeMap<String, Vec<String>>) {
    let mut params = BTreeMap::new();
    let Some((header, format, encoding)) = &spec.sig else {
        return (vec![], params);
    };
    let Some(value) = headers.get(header) else {
        return (vec![], params);
    };
    let raw: Vec<String> = match format {
        SigFormat::Single { prefix } => match value.strip_prefix(prefix.as_str()) {
            Some(rest) => vec![rest.trim().to_string()],
            None => return (vec![], params),
        },
        SigFormat::Versioned { version } => value
            .split(' ')
            .filter_map(|s| s.strip_prefix(&format!("{version},")).map(str::to_string))
            .collect(),
        SigFormat::Params { param } => {
            params = sig_params(value);
            params.get(*param).cloned().unwrap_or_default()
        }
    };
    let sigs = raw
        .iter()
        .filter_map(|s| match encoding {
            Encoding::Hex => decode_hex(s),
            Encoding::Base64 => decode_base64_lenient(s).ok(),
        })
        .filter(|b| !b.is_empty())
        .collect();
    (sigs, params)
}

fn body_path(json: &Option<Value>, path: &str) -> Option<String> {
    let mut v = json.as_ref()?;
    for k in path.split('.') {
        v = v.as_object()?.get(k)?;
    }
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn signed_bytes(
    spec: &Spec,
    d: &Delivery,
    params: &BTreeMap<String, Vec<String>>,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for part in spec.signed {
        match part {
            Part::Body => out.extend_from_slice(d.body),
            Part::Text(t) => out.extend_from_slice(t.as_bytes()),
            Part::Header(h) => out.extend_from_slice(d.headers.get(*h)?.as_bytes()),
            Part::SigParam(p) => match params.get(*p).map(Vec::as_slice) {
                Some([one]) => out.extend_from_slice(one.as_bytes()),
                _ => return None,
            },
            Part::Twilio => return None,
        }
    }
    Some(out)
}

/// The strings Twilio may have signed (PROTOCOL §3): the URL as reached, without its port, and with
/// the scheme's default port, each followed (for a form body) by the sorted parameters.
pub fn twilio_signed(d: &Delivery) -> Option<Vec<String>> {
    let raw = d.url?;
    let url = url::Url::parse(raw).ok()?;
    let ct = d
        .headers
        .get("content-type")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let mut suffix = String::new();
    let body_hash = url
        .query_pairs()
        .find(|(k, _)| k == "bodySHA256")
        .map(|(_, v)| v.into_owned());
    if let Some(expected) = body_hash {
        let got = hex(&Sha256::digest(d.body));
        if !ct_eq(expected.to_ascii_lowercase().as_bytes(), got.as_bytes()) {
            return None;
        }
    } else if ct.starts_with("application/x-www-form-urlencoded") {
        let mut by_name: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
        for (k, v) in url::form_urlencoded::parse(d.body) {
            by_name
                .entry(k.into_owned())
                .or_default()
                .insert(v.into_owned());
        }
        // BTreeMap and BTreeSet order strings by bytes: for UTF-8, that is code-point order.
        for (name, values) in by_name {
            for v in values {
                suffix.push_str(&name);
                suffix.push_str(&v);
            }
        }
    } else if !d.body.is_empty() {
        return None;
    }
    let mut without = url.clone();
    let _ = without.set_port(None);
    let host = url.host_str()?;
    let port = url.port_or_known_default()?;
    let query = url.query().map(|q| format!("?{q}")).unwrap_or_default();
    let with = format!("{}://{host}:{port}{}{query}", url.scheme(), url.path());
    let mut variants = vec![raw.to_string()];
    for v in [without.to_string(), with] {
        if !variants.contains(&v) {
            variants.push(v);
        }
    }
    Some(variants.into_iter().map(|u| u + &suffix).collect())
}

fn key_bytes(form: KeyForm, secret: &str) -> Option<Vec<u8>> {
    let decoded = |prefix: &str| {
        secret
            .strip_prefix(prefix)
            .and_then(|b| decode_base64_lenient(b).ok())
    };
    match form {
        KeyForm::Utf8 => Some(secret.as_bytes().to_vec()),
        KeyForm::Whsec => decoded("whsec_").filter(|k| k.len() >= 16),
        KeyForm::Whpk => decoded("whpk_").filter(|k| k.len() == 32),
    }
}

fn mac(alg: Mac_, key: &[u8], msg: &[u8]) -> Vec<u8> {
    match alg {
        Mac_::HmacSha1 => {
            let mut m = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(key).expect("any key size");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key size");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
    }
}

fn any_match(spec: &Spec, keys: &[String], sigs: &[Vec<u8>], signed: &[Vec<u8>]) -> bool {
    let mut ok = false;
    for k in keys {
        let Some(key) = key_bytes(spec.key, k) else {
            continue;
        };
        if spec.mac == Mac_::Ed25519 {
            let Some(pk) = <[u8; 32]>::try_from(key.as_slice())
                .ok()
                .and_then(|b| VerifyingKey::from_bytes(&b).ok())
            else {
                continue;
            };
            for msg in signed {
                for s in sigs {
                    if let Ok(sig) = Signature::from_slice(s) {
                        ok |= pk.verify_strict(msg, &sig).is_ok();
                    }
                }
            }
            continue;
        }
        for msg in signed {
            let expected = mac(spec.mac, &key, msg);
            for s in sigs {
                ok |= ct_eq(&expected, s);
            }
        }
    }
    ok
}

fn timestamp_ms(
    spec: &Spec,
    d: &Delivery,
    params: &BTreeMap<String, Vec<String>>,
    json: &Option<Value>,
) -> Option<Option<i64>> {
    let Some(t) = spec.timestamp else {
        return Some(None);
    };
    let raw = match t.source {
        TsSource::Header(h) => d.headers.get(h).cloned(),
        TsSource::SigParam(p) => match params.get(p).map(Vec::as_slice) {
            Some([one]) => Some(one.clone()),
            _ => None,
        },
        TsSource::BodyField(f) => body_path(json, f),
    }?;
    if raw.is_empty() || raw.len() > 16 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: i64 = raw.parse().ok()?;
    Some(Some(if t.millis { n } else { n.saturating_mul(1000) }))
}

/// Verifies one delivery with the hook's `verify` object and every currently valid secret (for
/// `standard-webhooks-ed25519`, the sender's `whpk_` public key, from `secrets` or `verify`).
pub fn verify(verify: &Value, secrets: &[String], d: &Delivery) -> Verdict {
    let Some(spec) = spec(verify) else {
        return REFUSED;
    };
    match spec.mac {
        Mac_::None => {
            return Verdict {
                ok: true,
                event_type: None,
            };
        }
        Mac_::Token => {
            let header = verify
                .get("header")
                .and_then(Value::as_str)
                .unwrap_or("authorization")
                .to_ascii_lowercase();
            let value = d.headers.get(&header).map(String::as_str).unwrap_or("");
            let presented = if header == "authorization" {
                match value.split_once(' ') {
                    Some((scheme, rest)) if scheme.eq_ignore_ascii_case("bearer") => rest.trim(),
                    _ => return REFUSED,
                }
            } else {
                value
            };
            let mut ok = false;
            for s in secrets {
                ok |= ct_eq(s.as_bytes(), presented.as_bytes());
            }
            return Verdict {
                ok,
                event_type: None,
            };
        }
        _ => {}
    }
    let (sigs, params) = candidates(&spec, d.headers);
    if sigs.is_empty() {
        return REFUSED;
    }
    let signed: Vec<Vec<u8>> = if spec.signed.iter().any(|p| matches!(p, Part::Twilio)) {
        match twilio_signed(d) {
            Some(v) => v.into_iter().map(String::into_bytes).collect(),
            None => return REFUSED,
        }
    } else {
        match signed_bytes(&spec, d, &params) {
            Some(b) => vec![b],
            None => return REFUSED,
        }
    };
    let mut keys: Vec<String> = secrets.to_vec();
    if spec.mac == Mac_::Ed25519
        && let Some(pk) = verify.get("publicKey").and_then(Value::as_str)
    {
        keys.push(pk.to_string());
    }
    if !any_match(&spec, &keys, &sigs, &signed) {
        return REFUSED;
    }
    let json: Option<Value> = serde_json::from_slice(d.body).ok();
    // After the signature, so the timestamp read is a signed one (Linear's is in the body).
    match timestamp_ms(&spec, d, &params, &json) {
        None => return REFUSED,
        Some(Some(ts)) => {
            let tolerance = spec.timestamp.map(|t| t.tolerance_s).unwrap_or(0) * 1000;
            if (d.now_ms - ts).abs() > tolerance {
                return REFUSED;
            }
        }
        Some(None) => {}
    }
    let event_type = match spec.event_type {
        None => None,
        Some(TypeSource::Header(h)) => d.headers.get(h).cloned(),
        // Only strings: a number in `type` isn't a type.
        Some(TypeSource::BodyFields(paths)) => paths.iter().find_map(|p| {
            let mut v = json.as_ref();
            for k in p.split('.') {
                v = v.and_then(Value::as_object).and_then(|o| o.get(k));
            }
            v.and_then(Value::as_str).map(str::to_string)
        }),
    }
    .map(|t| t.chars().take(EVENT_TYPE_MAX).collect());
    Verdict {
        ok: true,
        event_type,
    }
}

/// A strict-mode secret generated on the device for presets whose secret the relay would otherwise
/// generate: 32 random bytes, in the provider's form. `None` for presets whose secret the provider
/// issues (it must be supplied).
pub fn generate_secret(preset: &str) -> crate::Result<Option<String>> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| crate::Error::KeyStore(format!("no randomness: {e}")))?;
    Ok(match preset {
        "standard-webhooks" => Some(format!(
            "whsec_{}",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        )),
        "github" | "hmac" | "token" => {
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `fixtures/presets.v1.json`: the vectors the relay's tests run too.
    const VECTORS: &str = include_str!("../../../fixtures/presets.v1.json");

    #[test]
    fn every_shared_vector_gives_the_expected_verdict() {
        let doc: Value = serde_json::from_str(VECTORS).unwrap();
        let vectors = doc["vectors"].as_array().unwrap();
        assert!(vectors.len() >= 20);
        let mut presets = std::collections::BTreeSet::new();
        for v in vectors {
            let name = v["name"].as_str().unwrap();
            presets.insert(v["verify"]["preset"].as_str().unwrap().to_string());
            let headers: BTreeMap<String, String> = v["headers"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, x)| (k.to_ascii_lowercase(), x.as_str().unwrap().to_string()))
                .collect();
            let secrets: Vec<String> = v["secrets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect();
            let body = v["body"].as_str().unwrap().as_bytes();
            let d = Delivery {
                headers: &headers,
                body,
                now_ms: v["now"].as_i64().unwrap(),
                url: v["url"].as_str(),
            };
            let got = verify(&v["verify"], &secrets, &d);
            assert_eq!(got.ok, v["expect"]["ok"].as_bool().unwrap(), "{name}");
            if got.ok
                && let Some(want) = v["expect"].get("eventType")
            {
                assert_eq!(got.event_type.as_deref(), want.as_str(), "{name}");
            }
        }
        for p in [
            "github",
            "standard-webhooks",
            "standard-webhooks-ed25519",
            "stripe",
            "slack",
            "linear",
            "shopify",
            "twilio",
            "hmac",
            "token",
        ] {
            assert!(presets.contains(p), "no vector for {p}");
        }
    }

    #[test]
    fn unknown_presets_and_missing_headers_refuse() {
        let h = BTreeMap::new();
        let d = Delivery {
            headers: &h,
            body: b"{}",
            now_ms: 0,
            url: None,
        };
        assert!(!verify(&json!({"preset": "nope"}), &["s".into()], &d).ok);
        assert!(!verify(&json!({"preset": "github"}), &["s".into()], &d).ok);
        assert!(!verify(&json!({"preset": "hmac"}), &["s".into()], &d).ok);
        assert!(verify(&json!({"preset": "unverified"}), &[], &d).ok);
    }

    #[test]
    fn generated_secrets_take_the_provider_form() {
        assert!(
            generate_secret("standard-webhooks")
                .unwrap()
                .unwrap()
                .starts_with("whsec_")
        );
        assert_eq!(generate_secret("github").unwrap().unwrap().len(), 43);
        assert!(generate_secret("stripe").unwrap().is_none());
    }
}
