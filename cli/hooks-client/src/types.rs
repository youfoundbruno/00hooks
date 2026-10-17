//! The JSON shapes of PROTOCOL.md, camelCase on the wire. Unknown fields are kept (`extra`) so a newer
//! relay's additions survive a round trip through the local store.

use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::Secret;

/// `GET /v1/info`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Info {
    pub version: String,
    pub protocol: u32,
    pub signup_open: bool,
    pub server_time: i64,
}

/// `POST /v1/accounts` and `POST /v1/enrolments/redeem`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Joined {
    pub account_id: String,
    pub device_id: String,
}

/// `POST /v1/enrolments`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Enrolment {
    pub code: String,
    pub expires_at: i64,
}

/// One entry of `GET /v1/devices`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    #[serde(default)]
    pub last_seen_at: Option<i64>,
    #[serde(default)]
    pub current: bool,
}

/// A hook's verification settings: the preset and its non-secret fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Verify {
    pub preset: String,
    #[serde(flatten)]
    pub fields: Map<String, Value>,
}

/// `Hook` (PROTOCOL §3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Hook {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub verify: Verify,
    pub max_body_bytes: u64,
    pub created_at: i64,
    #[serde(default)]
    pub last_event_at: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `POST /v1/hooks` → `{ hook, url, secret? }`. The secret appears here only.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedHook {
    pub hook: Hook,
    pub url: String,
    #[serde(default)]
    pub secret: Option<Secret>,
}

/// `POST /v1/hooks/<id>/rotate` → `{ secret }`.
#[derive(Debug, Clone, Deserialize)]
pub struct Rotated {
    pub secret: Secret,
}

/// `PATCH /v1/hooks/<id>`: only the fields that are set are sent.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HookPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
}

/// An event (PROTOCOL §5), as delivered in `event: hook`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub seq: u64,
    pub id: String,
    pub hook_id: String,
    pub received_at: i64,
    pub verified: bool,
    pub preset: String,
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Event {
    /// The raw body bytes. The protocol sends padded standard base64 (RFC 4648 §4); URL-safe or
    /// unpadded bodies are accepted too.
    pub fn body_bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        decode_base64_lenient(&self.body)
    }

    /// The decoded body size, computed from the base64 length (without decoding).
    pub fn body_len(&self) -> usize {
        let s = self.body.trim_end_matches('=');
        s.len() * 3 / 4
    }
}

/// Padded standard base64 first (what the protocol sends), then any other common spelling.
pub(crate) fn decode_base64_lenient(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    if let Ok(bytes) = STANDARD.decode(s) {
        return Ok(bytes);
    }
    let cfg = GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
    let alphabet = if s.contains(['-', '_']) {
        &base64::alphabet::URL_SAFE
    } else {
        &base64::alphabet::STANDARD
    };
    GeneralPurpose::new(alphabet, cfg).decode(s)
}

/// `event: ready`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Ready {
    pub account_id: String,
    pub device_id: String,
    pub after: u64,
    pub head: u64,
}

/// `event: gap`: an inclusive range of seqs that retention dropped.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Gap {
    pub from: u64,
    pub to: u64,
    #[serde(default)]
    pub reason: String,
}

/// `event: resync`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Resync {
    pub after: u64,
}

/// `event: closed`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Closed {
    pub code: u16,
    #[serde(default)]
    pub reason: String,
}

/// An error body (PROTOCOL §8).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ErrorBody {
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub server_time: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_round_trips_unknown_fields() {
        let raw = r#"{"seq":42,"id":"evt_1","hookId":"hk_1","receivedAt":1,"verified":true,
            "preset":"github","eventType":"push","contentType":"application/json",
            "headers":{"x-github-event":"push"},"body":"e30=","sealed":{"v":1}}"#;
        let e: Event = serde_json::from_str(raw).unwrap();
        assert_eq!(e.seq, 42);
        assert_eq!(e.body_bytes().unwrap(), b"{}");
        assert_eq!(e.body_len(), 2);
        let back = serde_json::to_value(&e).unwrap();
        assert_eq!(back["sealed"]["v"], 1);
        assert_eq!(back["hookId"], "hk_1");
    }

    #[test]
    fn body_decodes_padded_standard_base64() {
        // Bytes that need `+`, `/` and padding in the standard alphabet.
        assert_eq!(decode_base64_lenient("+/8=").unwrap(), vec![0xfb, 0xff]);
        assert_eq!(decode_base64_lenient("e30=").unwrap(), b"{}");
        assert_eq!(decode_base64_lenient("").unwrap(), b"");
        assert!(decode_base64_lenient("not base64!").is_err());
    }

    #[test]
    fn body_decodes_url_safe_and_unpadded() {
        assert_eq!(decode_base64_lenient("-_8").unwrap(), vec![0xfb, 0xff]);
        assert_eq!(decode_base64_lenient("e30").unwrap(), b"{}");
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new("whsec_abc");
        assert_eq!(format!("{s:?}"), "Secret(…)");
    }

    #[test]
    fn patch_sends_only_set_fields() {
        let p = HookPatch {
            enabled: Some(false),
            ..Default::default()
        };
        assert_eq!(serde_json::to_string(&p).unwrap(), r#"{"enabled":false}"#);
    }
}
