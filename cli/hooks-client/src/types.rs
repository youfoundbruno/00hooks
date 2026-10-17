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
    /// Every stream protocol the relay serves (PROTOCOL §0); `[protocol]` when absent.
    #[serde(default)]
    pub protocols: Vec<u32>,
    pub signup_open: bool,
    /// The relay's Ed25519 envelope-signing key (unpadded base64url), pinned at login.
    #[serde(default)]
    pub relay_key: Option<String>,
    pub server_time: i64,
}

impl Info {
    /// Whether the relay serves stream protocol `v`.
    pub fn serves(&self, v: u32) -> bool {
        if self.protocols.is_empty() {
            self.protocol == v
        } else {
            self.protocols.contains(&v)
        }
    }
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
    /// The kid of the sealing key the relay holds for it; `None` when it has none.
    #[serde(default)]
    pub seal_kid: Option<String>,
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
    /// The offline notice, when one is set (PROTOCOL §4a).
    #[serde(default)]
    pub offline_notice: Option<OfflineNotice>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `POST /v1/hooks` → `{ hook, url, secret?, verifyToken? }`. The secret appears here only.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedHook {
    pub hook: Hook,
    pub url: String,
    #[serde(default)]
    pub secret: Option<Secret>,
    /// Meta's verify token, when the relay generated it: shown here only.
    #[serde(default)]
    pub verify_token: Option<Secret>,
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
    /// `Some(None)` clears the offline notice; `Some(Some(_))` sets it (PROTOCOL §4a).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_notice: Option<Option<OfflineNotice>>,
}

/// A hook's offline notice (PROTOCOL §4a): what the relay answers, at most once a day per sender,
/// while no device stream has been connected for `after_minutes`. Only for presets whose provider
/// takes a reply in the webhook's response (`twilio`, `slack` slash commands).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OfflineNotice {
    pub text: String,
    pub after_minutes: u32,
}

/// `sealed` in an event (PROTOCOL §5): an HPKE envelope for this device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Sealed {
    pub kid: String,
    pub enc: String,
    pub ct: String,
}

/// An event (PROTOCOL §5). As delivered in `event: hook` it is sealed (`sealed` and `sig` set,
/// `headers` and `body` empty); a subscription opens it ([`crate::seal::Opener`]) before recording
/// and handing it over, so consumers see `headers`, `content_type` and `body`, as in protocol 1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub seq: u64,
    pub id: String,
    pub hook_id: String,
    pub received_at: i64,
    /// Verified by the relay or, for a strict hook, by this device after opening.
    pub verified: bool,
    /// A strict hook: the provider's signature is checked on the device (PROTOCOL §3).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub strict: bool,
    pub preset: String,
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
    /// The envelope, until it is opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<Sealed>,
    /// The relay's signature over the envelope, until it is opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    /// The relay answered the sender with the hook's offline notice (PROTOCOL §4a): read from the
    /// sealed content, so only the relay could have said so.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub notice: bool,
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
pub fn decode_base64_lenient(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u32>,
    /// The sealing key the relay holds for this device (PROTOCOL §6); `None` when it has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_kid: Option<String>,
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

/// An API key (PROTOCOL §9). Its token is shown only in [`CreatedKey`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub created_by: String,
    pub expires_at: i64,
    #[serde(default)]
    pub last_used_at: Option<i64>,
}

/// `POST /v1/keys` → `{ key, token }`.
#[derive(Debug, Clone, Deserialize)]
pub struct CreatedKey {
    pub key: ApiKey,
    pub token: Secret,
}

/// One entry of `GET /v1/audit`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEntry {
    pub at: i64,
    pub kind: String,
    #[serde(default)]
    pub actor: Option<String>,
    pub subject: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
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
            "headers":{"x-github-event":"push"},"body":"e30=","future":{"v":1}}"#;
        let e: Event = serde_json::from_str(raw).unwrap();
        assert_eq!(e.seq, 42);
        assert_eq!(e.body_bytes().unwrap(), b"{}");
        assert_eq!(e.body_len(), 2);
        let back = serde_json::to_value(&e).unwrap();
        assert_eq!(back["future"]["v"], 1);
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
