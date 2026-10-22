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
    Single {
        prefix: String,
    },
    Versioned {
        version: &'static str,
    },
    /// `k=v` pairs separated by `sep`: `,` (Stripe) or `;` (Paddle).
    Params {
        param: &'static str,
        sep: char,
    },
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

#[derive(Debug, Clone, Copy, PartialEq)]
enum TsUnit {
    Seconds,
    Millis,
    /// An RFC 3339 date-time (Twitch's).
    Rfc3339,
}

#[derive(Debug, Clone, Copy)]
struct Timestamp {
    source: TsSource,
    unit: TsUnit,
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
const CALENDLY: &[Part] = &[Part::SigParam("t"), Part::Text("."), Part::Body];
const PADDLE: &[Part] = &[Part::SigParam("ts"), Part::Text(":"), Part::Body];
const TWITCH: &[Part] = &[
    Part::Header("twitch-eventsub-message-id"),
    Part::Header("twitch-eventsub-message-timestamp"),
    Part::Body,
];
const ZOOM: &[Part] = &[
    Part::Text("v0:"),
    Part::Header("x-zm-request-timestamp"),
    Part::Text(":"),
    Part::Body,
];

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
                    unit: TsUnit::Seconds,
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
                SigFormat::Params {
                    param: "v1",
                    sep: ',',
                },
                Encoding::Hex,
            ),
            signed: STRIPE,
            timestamp: Some(Timestamp {
                source: TsSource::SigParam("t"),
                unit: TsUnit::Seconds,
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
                unit: TsUnit::Seconds,
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
                unit: TsUnit::Millis,
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
        // Meta (WhatsApp, Messenger, Instagram): GitHub's header and scheme under the app secret,
        // typed by the signed body's `object`.
        "meta" => Spec {
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
            event_type: Some(TypeSource::BodyFields(&["object"])),
        },
        // Calendly: `t=<s>,v1=<hex>` over `t.body`, `t` within 3 minutes.
        "calendly" => Spec {
            mac: Mac_::HmacSha256,
            key: KeyForm::Utf8,
            sig: sig(
                "calendly-webhook-signature",
                SigFormat::Params {
                    param: "v1",
                    sep: ',',
                },
                Encoding::Hex,
            ),
            signed: CALENDLY,
            timestamp: Some(Timestamp {
                source: TsSource::SigParam("t"),
                unit: TsUnit::Seconds,
                tolerance_s: 180,
            }),
            event_type: Some(TypeSource::BodyFields(&["event"])),
        },
        // Typeform: `sha256=<base64 HMAC(body)>`, no timestamp.
        "typeform" => Spec {
            mac: Mac_::HmacSha256,
            key: KeyForm::Utf8,
            sig: sig(
                "typeform-signature",
                SigFormat::Single {
                    prefix: "sha256=".into(),
                },
                Encoding::Base64,
            ),
            signed: BODY,
            timestamp: None,
            event_type: Some(TypeSource::BodyFields(&["event_type"])),
        },
        // Paddle Billing: `ts=<s>;h1=<hex>` over `ts:body`, `ts` within 5 s.
        "paddle" => Spec {
            mac: Mac_::HmacSha256,
            key: KeyForm::Utf8,
            sig: sig(
                "paddle-signature",
                SigFormat::Params {
                    param: "h1",
                    sep: ';',
                },
                Encoding::Hex,
            ),
            signed: PADDLE,
            timestamp: Some(Timestamp {
                source: TsSource::SigParam("ts"),
                unit: TsUnit::Seconds,
                tolerance_s: 5,
            }),
            event_type: Some(TypeSource::BodyFields(&["event_type"])),
        },
        // Twitch EventSub: `sha256=<hex>` over id, timestamp and body; the RFC 3339 timestamp at
        // most 10 minutes off; typed by the signed body's subscription type.
        "twitch" => Spec {
            mac: Mac_::HmacSha256,
            key: KeyForm::Utf8,
            sig: sig(
                "twitch-eventsub-message-signature",
                SigFormat::Single {
                    prefix: "sha256=".into(),
                },
                Encoding::Hex,
            ),
            signed: TWITCH,
            timestamp: Some(Timestamp {
                source: TsSource::Header("twitch-eventsub-message-timestamp"),
                unit: TsUnit::Rfc3339,
                tolerance_s: 600,
            }),
            event_type: Some(TypeSource::BodyFields(&["subscription.type"])),
        },
        // Zoom: `v0=<hex>` over `v0:ts:body`. The timestamp is signed but, with no documented
        // window, not checked (as the relay).
        "zoom" => Spec {
            mac: Mac_::HmacSha256,
            key: KeyForm::Utf8,
            sig: sig(
                "x-zm-signature",
                SigFormat::Single {
                    prefix: "v0=".into(),
                },
                Encoding::Hex,
            ),
            signed: ZOOM,
            timestamp: None,
            event_type: Some(TypeSource::BodyFields(&["event"])),
        },
        // PagerDuty v3: `v1=<hex HMAC(body)>[,v1=…]`, no timestamp.
        "pagerduty" => Spec {
            mac: Mac_::HmacSha256,
            key: KeyForm::Utf8,
            sig: sig(
                "x-pagerduty-signature",
                SigFormat::Params {
                    param: "v1",
                    sep: ',',
                },
                Encoding::Hex,
            ),
            signed: BODY,
            timestamp: None,
            event_type: Some(TypeSource::BodyFields(&["event.event_type"])),
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

/// Stripe-style `k=v,k=v` parameters (Paddle's `k=v;k=v`); every value of a repeated key is kept.
fn sig_params(value: &str, sep: char) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for part in value.split(sep) {
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
        SigFormat::Params { param, sep } => {
            params = sig_params(value, *sep);
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
    if t.unit == TsUnit::Rfc3339 {
        return rfc3339_ms(&raw).map(Some);
    }
    if raw.is_empty() || raw.len() > 16 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: i64 = raw.parse().ok()?;
    Some(Some(if t.unit == TsUnit::Millis {
        n
    } else {
        n.saturating_mul(1000)
    }))
}

/// An RFC 3339 date-time (`2019-11-16T10:11:12.634234626Z`) in Unix ms, the fraction cut to whole
/// ms; `None` unless it is exactly that form, from 1970, with every field in range (no leap second).
/// The relay's `rfc3339Ms` parses it the same way.
pub fn rfc3339_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = b.get(r)?;
        if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(part).ok()?.parse().ok()
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut i = 19;
    let mut ms = 0;
    if b[i] == b'.' {
        let start = i + 1;
        let mut end = start;
        while end < b.len() && b[end].is_ascii_digit() {
            end += 1;
        }
        if end == start || end - start > 9 {
            return None;
        }
        let mut digits = s[start..end.min(start + 3)].to_string();
        while digits.len() < 3 {
            digits.push('0');
        }
        ms = digits.parse::<i64>().ok()?;
        i = end;
    }
    let offset_min = match &b[i..] {
        [b'Z'] => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let (oh, om) = (num(i + 1..i + 3)?, num(i + 4..i + 6)?);
            if oh > 23 || om > 59 {
                return None;
            }
            (if *sign == b'-' { -1 } else { 1 }) * (oh * 60 + om)
        }
        _ => return None,
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days_in = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if y < 1970 || d < 1 || d > days_in || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    // Days from 1970-01-01 (Howard Hinnant's days_from_civil).
    let (yy, m) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = yy / 400;
    let yoe = yy - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 24 + h) * 60 + mi - offset_min) * 60_000 + se * 1000 + ms)
}

/// Whether a preset proves anything in strict mode. `unverified` proves nothing, and a `token`
/// crosses the relay in the clear with every delivery, so a relay that saw one can mint more: in
/// strict mode (the relay is not trusted to vouch) both are refused.
pub fn strict_capable(verify: &Value) -> bool {
    spec(verify).is_some_and(|s| !matches!(s.mac, Mac_::None | Mac_::Token))
}

/// The headers that carry a preset's signature (or token), lowercased: what is dropped from an
/// event once it has been verified, so a stored or forwarded event is never a ready-made replay.
pub fn signature_headers(verify: &Value) -> Vec<String> {
    let Some(spec) = spec(verify) else {
        return Vec::new();
    };
    match (spec.mac, &spec.sig) {
        (Mac_::Token, _) => vec![
            verify
                .get("header")
                .and_then(Value::as_str)
                .unwrap_or("authorization")
                .to_ascii_lowercase(),
        ],
        (_, Some((header, ..))) => vec![header.clone()],
        _ => Vec::new(),
    }
}

/// Verifies one delivery for a strict hook (PROTOCOL §3): as [`verify`], but a preset that isn't
/// [`strict_capable`] is refused whatever the delivery says.
pub fn verify_strict(spec_value: &Value, secrets: &[String], d: &Delivery) -> Verdict {
    if !strict_capable(spec_value) {
        return REFUSED;
    }
    verify(spec_value, secrets, d)
}

/// Verifies one delivery with the hook's `verify` object and every currently valid secret (for
/// `standard-webhooks-ed25519`, the sender's `whpk_` public key, from `secrets` or `verify`). A
/// `verify` object marked `"strict": true` is held to [`verify_strict`].
pub fn verify(verify: &Value, secrets: &[String], d: &Delivery) -> Verdict {
    let Some(spec) = spec(verify) else {
        return REFUSED;
    };
    if verify.get("strict") == Some(&Value::Bool(true))
        && matches!(spec.mac, Mac_::None | Mac_::Token)
    {
        return REFUSED;
    }
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
        "github" | "calendly" | "typeform" | "twitch" | "hmac" | "token" => {
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
            "meta",
            "calendly",
            "typeform",
            "paddle",
            "twitch",
            "zoom",
            "pagerduty",
            "hmac",
            "token",
        ] {
            assert!(presets.contains(p), "no vector for {p}");
        }
    }

    #[test]
    fn rfc3339_is_parsed_exactly_and_nothing_else() {
        // 2019-11-16T10:11:12Z
        let base = 1_573_899_072_000;
        assert_eq!(rfc3339_ms("2019-11-16T10:11:12Z"), Some(base));
        assert_eq!(
            rfc3339_ms("2019-11-16T10:11:12.634234626Z"),
            Some(base + 634)
        );
        assert_eq!(rfc3339_ms("2019-11-16T12:11:12.5+02:00"), Some(base + 500));
        assert_eq!(rfc3339_ms("2019-11-16T05:41:12-04:30"), Some(base));
        assert_eq!(rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_ms("2024-02-29T00:00:00Z"), Some(1_709_164_800_000));
        for bad in [
            "2023-02-29T00:00:00Z",
            "2019-13-01T00:00:00Z",
            "2019-11-16T24:00:00Z",
            "2019-11-16T23:59:60Z",
            "2019-11-16 10:11:12Z",
            "2019-11-16T10:11:12",
            "2019-11-16t10:11:12z",
            "2019-11-16T10:11:12.Z",
            "2019-11-16T10:11:12.1234567890Z",
            "0050-01-01T00:00:00Z",
            "1792233600",
            " 2019-11-16T10:11:12Z",
            "2019-11-16T10:11:12+0200",
            "+019-11-16T10:11:12Z",
        ] {
            assert_eq!(rfc3339_ms(bad), None, "{bad}");
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
    fn strict_mode_refuses_presets_that_prove_nothing_the_relay_could_not_mint() {
        // A relay that rewrote a strict hook's spec to `unverified`, or to a `token` it has seen in
        // the clear, gets nothing past the device.
        let h = BTreeMap::from([("authorization".to_string(), "Bearer tok".to_string())]);
        let d = Delivery {
            headers: &h,
            body: b"{}",
            now_ms: 0,
            url: None,
        };
        let tok = json!({"preset": "token", "header": "Authorization"});
        assert!(
            verify(&tok, &["tok".into()], &d).ok,
            "token still works when the relay verifies"
        );
        assert!(!verify_strict(&tok, &["tok".into()], &d).ok);
        assert!(!verify_strict(&json!({"preset": "unverified"}), &[], &d).ok);
        let marked = json!({"preset": "token", "header": "Authorization", "strict": true});
        assert!(!verify(&marked, &["tok".into()], &d).ok);
        assert!(!verify(&json!({"preset": "unverified", "strict": true}), &[], &d).ok);
        assert!(!strict_capable(&json!({"preset": "nope"})));
        assert!(strict_capable(&json!({"preset": "stripe"})));
    }

    #[test]
    fn signature_headers_name_what_carries_the_proof() {
        assert_eq!(
            signature_headers(&json!({"preset": "stripe"})),
            ["stripe-signature"]
        );
        assert_eq!(
            signature_headers(&json!({"preset": "hmac", "header": "X-Sig"})),
            ["x-sig"]
        );
        assert_eq!(
            signature_headers(&json!({"preset": "token"})),
            ["authorization"]
        );
        assert!(signature_headers(&json!({"preset": "unverified"})).is_empty());
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
        // Twitch takes 10 to 100 ASCII characters; the receiver chooses Calendly's and Typeform's.
        for p in ["calendly", "typeform", "twitch"] {
            assert_eq!(generate_secret(p).unwrap().unwrap().len(), 43, "{p}");
        }
        for p in ["paddle", "zoom", "pagerduty"] {
            assert!(generate_secret(p).unwrap().is_none(), "{p}");
        }
    }
}
