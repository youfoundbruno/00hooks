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
    /// What the relay's screen takes (PROTOCOL §4b), when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screen: Option<ScreenInfo>,
    /// Optional hosted extras the relay announces (PROTOCOL §2): data, shown only when present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extras: Vec<Extra>,
    /// Phone links and push (PROTOCOL §2, §10), when the relay carries them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<PhoneInfo>,
    /// Fields of a newer relay, kept so `00hooks relay status --json` shows them.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `/v1/info`'s `phone`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PhoneInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push: Option<PushInfo>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `/v1/info`'s `phone.push`: whether the relay can wake a phone, and on which platforms.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PushInfo {
    #[serde(default)]
    pub available: bool,
    /// The APNs environment (`sandbox` or `production`), when it can.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Per platform, from relays that announce it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platforms: Option<PushPlatforms>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `phone.push.platforms`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PushPlatforms {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ios: Option<PlatformPush>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub android: Option<PlatformPush>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One platform's push.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PlatformPush {
    #[serde(default)]
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `/v1/info`'s `screen`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScreenInfo {
    pub edge: bool,
    pub max_rules: u32,
    /// How long a held event waits at the relay.
    pub held_days: f64,
}

/// A hosted extra a relay announces (fingerprint sync, reputation lists, a longer hold, evaluator
/// credits): never hard-coded in a client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Extra {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// One event the relay's screen holds (`GET /v1/held`): metadata, never content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HeldEvent {
    pub id: String,
    pub hook_id: String,
    pub received_at: i64,
    pub verified: bool,
    #[serde(default)]
    pub strict: bool,
    pub preset: String,
    #[serde(default)]
    pub event_type: Option<String>,
    /// The edge rule that held it.
    pub rule: String,
    pub size: u64,
    pub expires_at: i64,
}

/// Where a delivery came from, as the relay's edge saw it (sealed with the content, PROTOCOL §4b).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Origin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

impl Origin {
    pub fn is_empty(&self) -> bool {
        self.ip.is_none() && self.asn.is_none() && self.country.is_none()
    }
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
    /// Its labels, which a hook's `recipients` can name (PROTOCOL §2); empty from a relay that
    /// predates tags.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// The longest device tag, in characters.
pub const MAX_TAG_LEN: usize = 32;
/// The most tags one device may carry.
pub const MAX_DEVICE_TAGS: usize = 10;
/// The most devices a hook's `recipients` may list (the device cap).
pub const MAX_TARGET_DEVICES: usize = 10;
/// The most tags a hook's `recipients` may name.
pub const MAX_TARGET_TAGS: usize = 10;

/// Whether `tag` is a valid device tag: 1 to 32 characters of lowercase letters, digits, `.`,
/// `_` and `-`, beginning and ending with a letter or digit (as the relay checks it).
pub fn valid_tag(tag: &str) -> bool {
    let b = tag.as_bytes();
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !b.is_empty()
        && b.len() <= MAX_TAG_LEN
        && edge(b[0])
        && edge(b[b.len() - 1])
        && b.iter()
            .all(|&c| edge(c) || matches!(c, b'.' | b'_' | b'-'))
}

/// A hook's recipients (PROTOCOL §3): the listed devices and every device carrying any of the
/// tags, together.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Recipients {
    #[serde(default)]
    pub devices: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Who gets a hook's events, as [`Hook::target`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryTarget {
    /// Every device with a sealing key.
    All,
    /// Only these devices and tags.
    Only(Recipients),
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
    /// The only device this hook's events are delivered to; `None`: every device (and what an
    /// older relay, which doesn't send the field, does).
    #[serde(default)]
    pub deliver_to: Option<String>,
    /// The static answer the relay sends the provider for each accepted delivery, when set.
    #[serde(default)]
    pub response: Option<HookResponse>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A hook's static answer to the provider (`Hook.response`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HookResponse {
    /// 200 to 299, but not 204 or 205.
    pub status: u16,
    /// `text/plain`, `application/json`, `application/xml` or `text/xml`.
    pub content_type: String,
    /// At most 4096 bytes of UTF-8.
    pub body: String,
}

/// The content types a hook's static answer may have.
pub const RESPONSE_CONTENT_TYPES: &[&str] = &[
    "text/plain",
    "application/json",
    "application/xml",
    "text/xml",
];
/// The longest body a hook's static answer may have, in bytes.
pub const RESPONSE_MAX_BODY: usize = 4096;

/// `POST /v1/test/<hookId>`: what the signed test delivery got.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TestSent {
    /// The HTTP status the delivery was answered with.
    pub status: u16,
    /// The delivery's JSON answer, or `None` when it wasn't JSON.
    #[serde(default)]
    pub answer: Option<Value>,
    pub event_type: String,
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
    /// `Some(None)`: deliver to every device; `Some(Some(id))`: only to that one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deliver_to: Option<Option<String>>,
    /// `Some(None)`: deliver to every device; `Some(Some(_))`: only to those devices and tags.
    /// Never sent together with `deliver_to` (the relay refuses both).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipients: Option<Option<Recipients>>,
    /// `Some(None)` clears the static answer; `Some(Some(_))` sets it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Option<HookResponse>>,
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
    /// Held by the relay's screen and released (PROTOCOL §4b): relay-signed metadata.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub held: bool,
    /// Where it came from, as the edge saw it: read from the sealed content only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
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

/// `event: hook-change` (PROTOCOL §6): a hook of the account was created, had its secret rotated,
/// was renamed or deleted. Sent without an `id:`, at most once per device; it is not an event of
/// the log, so it is never recorded or acknowledged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HookChange {
    /// The account's change number: it only grows. The relay may send a change twice (at least
    /// once), so a client hands over each `n` once; 0 (absent) is never deduplicated.
    #[serde(default)]
    pub n: u64,
    /// `hook.created`, `hook.rotated`, `hook.renamed` or `hook.deleted`; see [`HookChange::change`].
    pub kind: String,
    pub hook_id: String,
    /// The hook's name (its new one for a rename, its last one for a deletion).
    #[serde(default)]
    pub name: Option<String>,
    /// The name before a rename; only for `hook.renamed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_name: Option<String>,
    /// Who did it: a device id (`dev_…`), an API key id (`key_…`), or `None`.
    #[serde(default)]
    pub actor: Option<String>,
    /// When, in Unix milliseconds.
    #[serde(default)]
    pub at: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What a [`HookChange`] says happened. A kind this client doesn't know is [`Other`], never an
/// error.
///
/// [`Other`]: HookChangeKind::Other
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookChangeKind {
    Created,
    Rotated,
    Renamed,
    Deleted,
    Other,
}

impl HookChange {
    pub fn change(&self) -> HookChangeKind {
        match self.kind.as_str() {
            "hook.created" => HookChangeKind::Created,
            "hook.rotated" => HookChangeKind::Rotated,
            "hook.renamed" => HookChangeKind::Renamed,
            "hook.deleted" => HookChangeKind::Deleted,
            _ => HookChangeKind::Other,
        }
    }

    /// The actor in words: "device dev_…", "API key key_…", or "someone unknown". Not sanitised:
    /// the caller does that for its output.
    pub fn actor_words(&self) -> String {
        match self.actor.as_deref() {
            Some(a) if a.starts_with("dev_") => format!("device {a}"),
            Some(a) if a.starts_with("key_") => format!("API key {a}"),
            Some(a) if !a.is_empty() => a.to_string(),
            _ => "someone unknown".to_string(),
        }
    }

    /// Whether `device_id` made the change itself.
    pub fn by_device(&self, device_id: &str) -> bool {
        self.actor.as_deref() == Some(device_id)
    }
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

/// The reasons a `gap` gives (PROTOCOL §6). A reason this client doesn't know is still a gap.
pub mod gap_reason {
    /// Retention dropped the events before this device read them.
    pub const RETENTION: &str = "retention";
    /// The event had no envelope for this device (it had no sealing key then).
    pub const NO_KEY: &str = "no_key";
    /// The event's message was over the relay's internal message limit.
    pub const TOO_LARGE: &str = "too_large";
    /// Deliveries the relay answered `200` and dropped past the account's daily cap, on a hook
    /// whose `onLimit` is `accept_and_drop` (PROTOCOL §4 step 7).
    pub const OVER_LIMIT: &str = "over_limit";
}

impl Gap {
    /// The relay took these deliveries past the daily cap and dropped them (nothing was stored).
    pub fn is_over_limit(&self) -> bool {
        self.reason == gap_reason::OVER_LIMIT
    }
}

/// `event: limit` (PROTOCOL §6): one of the plan's limits is refusing deliveries. Sent without an
/// `id:`, at most once an hour per scope and hook, and again after `ready`; never recorded or
/// acknowledged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Limit {
    /// `hook_rate`, `account_rate`, `daily`, `paused` or `plan_expired`; see [`Limit::kind`].
    pub scope: String,
    /// The hook, for a hook's own scope (`hook_rate`, `paused`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook_id: Option<String>,
    /// Deliveries refused (or, for `daily`, also accepted and dropped) since `since`.
    #[serde(default)]
    pub refused: u64,
    /// When the limit began to bite, in Unix milliseconds.
    #[serde(default)]
    pub since: i64,
    /// When it lifts, in Unix milliseconds; `None` for `plan_expired` (it lifts when renewed).
    #[serde(default)]
    pub until: Option<i64>,
    /// The plan in effect.
    #[serde(default)]
    pub plan: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Which limit a [`Limit`] (or a refusal's `scope`, [`crate::Error::limit_scope`]) names. A scope
/// this client doesn't know is [`Other`], never an error.
///
/// [`Other`]: LimitScope::Other
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitScope {
    /// One hook's token bucket.
    HookRate,
    /// The account's token bucket, across its hooks.
    AccountRate,
    /// The account's deliveries per UTC day.
    Daily,
    /// The hook is paused after a flood of refusals.
    Paused,
    /// The hook is paused because its recipients match no device with a sealing key.
    NoRecipient,
    /// The account's entitled plan ran out (PROTOCOL §2b).
    PlanExpired,
    /// The account's backlog is full (`quota`).
    Account,
    /// The hook's share of the backlog is full (`quota`).
    Hook,
    /// The hook's screen hold is full (`quota`).
    Held,
    /// The plan's hook cap (`409`).
    Hooks,
    /// The plan's hook creations per day.
    HookCreates,
    /// Hook creations per address.
    HookCreateIp,
    Other,
}

impl LimitScope {
    pub fn parse(scope: &str) -> Self {
        match scope {
            "hook_rate" => LimitScope::HookRate,
            "account_rate" => LimitScope::AccountRate,
            "daily" => LimitScope::Daily,
            "paused" => LimitScope::Paused,
            "no_recipient" => LimitScope::NoRecipient,
            "plan_expired" => LimitScope::PlanExpired,
            "account" => LimitScope::Account,
            "hook" => LimitScope::Hook,
            "held" => LimitScope::Held,
            "hooks" => LimitScope::Hooks,
            "hook_creates" => LimitScope::HookCreates,
            "hook_create_ip" => LimitScope::HookCreateIp,
            _ => LimitScope::Other,
        }
    }
}

impl Limit {
    pub fn kind(&self) -> LimitScope {
        LimitScope::parse(&self.scope)
    }
}

/// What a delivery past the account's daily cap gets (PROTOCOL §3, `onLimit`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnLimit {
    /// `429`, so the provider retries later (the default).
    Refuse,
    /// `200`, nothing stored, and the devices get a gap `over_limit`.
    AcceptAndDrop,
}

impl Hook {
    /// The hook's `onLimit` (PROTOCOL §3); `Refuse` from a relay that predates plans.
    pub fn on_limit(&self) -> OnLimit {
        match self.extra.get("onLimit").and_then(Value::as_str) {
            Some("accept_and_drop") => OnLimit::AcceptAndDrop,
            _ => OnLimit::Refuse,
        }
    }

    /// When the hook's pause ends (Unix milliseconds), while it is paused.
    pub fn paused_until(&self) -> Option<i64> {
        self.extra.get("pausedUntil").and_then(Value::as_i64)
    }

    /// Why the relay pauses the hook (`refusals`, `no_recipient`, or a reason this client doesn't
    /// know), while it does.
    pub fn paused_reason(&self) -> Option<&str> {
        self.extra.get("pausedReason").and_then(Value::as_str)
    }

    /// Whether the hook is paused because its recipients match no device (PROTOCOL §3).
    pub fn paused_for_no_recipient(&self) -> bool {
        self.paused_reason() == Some("no_recipient")
    }

    /// The hook's `recipients` (PROTOCOL §3): `None` when the relay doesn't send the field (it
    /// predates lists and tags) or sends a shape this client can't read; `Some(None)`: every
    /// device. Read from `extra`, so no future shape can make a hook unreadable.
    pub fn recipients(&self) -> Option<Option<Recipients>> {
        match self.extra.get("recipients")? {
            Value::Null => Some(None),
            v => serde_json::from_value(v.clone()).ok().map(Some),
        }
    }

    /// Who gets the hook's events: its `recipients`, else its one `deliverTo` device, else all.
    /// A list the relay emptied (its devices were all revoked) is nobody, never every device.
    pub fn target(&self) -> DeliveryTarget {
        match self.recipients() {
            Some(Some(r)) => return DeliveryTarget::Only(r),
            Some(None) => return DeliveryTarget::All,
            None => {}
        }
        match &self.deliver_to {
            Some(id) => DeliveryTarget::Only(Recipients {
                devices: vec![id.clone()],
                tags: vec![],
            }),
            None => DeliveryTarget::All,
        }
    }
}

/// How to get the operator's hosted plan, as `/v1/info` and `GET /v1/account` announce it: data,
/// shown as it is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HostedPlan {
    pub plan: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// What `/v1/info` says about plans (PROTOCOL §2a): read with [`crate::Client::plans_info`].
/// A relay that predates plans says nothing, which reads as `plans: false`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PlansInfo {
    #[serde(default)]
    pub plans: bool,
    /// Whether the relay takes Overblast entitlements (PROTOCOL §2b).
    #[serde(default)]
    pub entitlements: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosted_plan: Option<HostedPlan>,
}

/// A plan's limits (PROTOCOL §2a). `None` is no limit.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PlanLimits {
    #[serde(default)]
    pub hooks: Option<u64>,
    #[serde(default)]
    pub devices: Option<u64>,
    #[serde(default)]
    pub events_per_day: Option<u64>,
    #[serde(default)]
    pub hook_rate_per_min: Option<f64>,
    #[serde(default)]
    pub hook_burst: Option<u64>,
    #[serde(default)]
    pub account_rate_per_min: Option<f64>,
    #[serde(default)]
    pub account_burst: Option<u64>,
    #[serde(default)]
    pub retention_hours: Option<f64>,
    #[serde(default)]
    pub max_body_bytes: Option<u64>,
    #[serde(default)]
    pub backlog_events: Option<u64>,
    #[serde(default)]
    pub backlog_bytes: Option<u64>,
    #[serde(default)]
    pub hook_creates_per_day: Option<u64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Events and bytes waiting for acknowledgement.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Backlog {
    #[serde(default)]
    pub events: u64,
    #[serde(default)]
    pub bytes: u64,
}

/// Today's counts for the account (UTC).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct UsageToday {
    #[serde(default)]
    pub events: u64,
    #[serde(default)]
    pub refused: u64,
    #[serde(default)]
    pub dropped: u64,
}

/// One hook's counts in `GET /v1/account`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HookUsage {
    #[serde(default)]
    pub today: u64,
    #[serde(default)]
    pub refused: u64,
    #[serde(default)]
    pub backlog: Backlog,
    /// Exact (a `Hook`'s `last_event_at` is written at most once a minute).
    #[serde(default)]
    pub last_event_at: Option<i64>,
}

/// `GET /v1/account`'s `usage`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccountUsage {
    /// The UTC day the counts are for (days since the epoch).
    #[serde(default)]
    pub day: u64,
    #[serde(default)]
    pub today: UsageToday,
    #[serde(default)]
    pub per_hook: BTreeMap<String, HookUsage>,
    #[serde(default)]
    pub backlog: Backlog,
    #[serde(default)]
    pub hooks: u64,
    #[serde(default)]
    pub devices: u64,
    #[serde(default)]
    pub hook_creates_today: u64,
}

/// A paused hook in `GET /v1/account`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PausedHook {
    pub hook_id: String,
    pub until: i64,
}

/// `GET /v1/account` (PROTOCOL §2a): the account's plan, its limits and today's usage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub account_id: String,
    pub plan: String,
    /// When the plan ends (an entitlement's `exp`), in Unix milliseconds; `None`: it doesn't.
    #[serde(default)]
    pub plan_until: Option<i64>,
    /// The entitled plan ran out: `plan` is the fallback.
    #[serde(default)]
    pub expired: bool,
    #[serde(default)]
    pub limits: PlanLimits,
    #[serde(default)]
    pub usage: AccountUsage,
    #[serde(default)]
    pub paused: Vec<PausedHook>,
    /// How to get the hosted plan, when the operator offers it to this account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<HostedPlan>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `POST /v1/accounts` with an entitlement (PROTOCOL §2b): the account, on the entitled plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EntitledJoin {
    pub account_id: String,
    pub device_id: String,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub plan_until: Option<i64>,
}

impl EntitledJoin {
    pub fn joined(&self) -> Joined {
        Joined {
            account_id: self.account_id.clone(),
            device_id: self.device_id.clone(),
        }
    }
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
    /// Which limit answered a `429` or a cap's `409` (PROTOCOL §8).
    #[serde(default)]
    pub scope: Option<String>,
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
    fn hook_changes_read_every_kind_and_tolerate_new_ones() {
        let raw = r#"{"n":7,"kind":"hook.renamed","hookId":"hk_1","name":"billing",
            "previousName":"payments","actor":"key_9","at":1760000000000,"future":1}"#;
        let c: HookChange = serde_json::from_str(raw).unwrap();
        assert_eq!(c.change(), HookChangeKind::Renamed);
        assert_eq!(c.n, 7);
        assert_eq!(c.previous_name.as_deref(), Some("payments"));
        assert_eq!(c.actor_words(), "API key key_9");
        assert!(!c.by_device("dev_1"));
        assert_eq!(serde_json::to_value(&c).unwrap()["future"], 1);
        for (kind, want) in [
            ("hook.created", HookChangeKind::Created),
            ("hook.rotated", HookChangeKind::Rotated),
            ("hook.deleted", HookChangeKind::Deleted),
            ("hook.screen", HookChangeKind::Other),
        ] {
            let c: HookChange =
                serde_json::from_value(serde_json::json!({"kind": kind, "hookId": "hk_1"}))
                    .unwrap();
            assert_eq!(c.change(), want);
            assert_eq!(c.actor_words(), "someone unknown");
            assert_eq!(c.name, None);
            assert_eq!(c.n, 0, "no number: never deduplicated");
        }
        let c: HookChange = serde_json::from_str(
            r#"{"kind":"hook.rotated","hookId":"hk_1","name":"x","actor":"dev_1","at":1}"#,
        )
        .unwrap();
        assert!(c.by_device("dev_1"));
        assert_eq!(c.actor_words(), "device dev_1");
        assert!(serde_json::from_str::<HookChange>(r#"{"kind":"hook.created"}"#).is_err());
    }

    #[test]
    fn limits_read_every_scope_and_tolerate_new_ones() {
        let raw = r#"{"scope":"hook_rate","hookId":"hk_1","refused":12,"since":1,"until":2,
            "plan":"overblast","future":true}"#;
        let l: Limit = serde_json::from_str(raw).unwrap();
        assert_eq!(l.kind(), LimitScope::HookRate);
        assert_eq!(l.hook_id.as_deref(), Some("hk_1"));
        assert_eq!((l.refused, l.since, l.until), (12, 1, Some(2)));
        assert_eq!(serde_json::to_value(&l).unwrap()["future"], true);
        let l: Limit = serde_json::from_str(
            r#"{"scope":"plan_expired","refused":1,"since":5,"until":null,"plan":"suspended"}"#,
        )
        .unwrap();
        assert_eq!(l.kind(), LimitScope::PlanExpired);
        assert_eq!(l.until, None);
        assert_eq!(l.hook_id, None);
        for (s, want) in [
            ("account_rate", LimitScope::AccountRate),
            ("daily", LimitScope::Daily),
            ("paused", LimitScope::Paused),
            ("hooks", LimitScope::Hooks),
            ("hook_creates", LimitScope::HookCreates),
            ("someday", LimitScope::Other),
        ] {
            assert_eq!(LimitScope::parse(s), want);
        }
    }

    #[test]
    fn gaps_say_over_limit() {
        let g: Gap = serde_json::from_str(r#"{"from":2,"to":3,"reason":"over_limit"}"#).unwrap();
        assert!(g.is_over_limit());
        let g: Gap = serde_json::from_str(r#"{"from":2,"to":3}"#).unwrap();
        assert!(!g.is_over_limit());
    }

    #[test]
    fn hooks_read_on_limit_and_pauses_from_newer_relays_only() {
        let old: Hook = serde_json::from_value(serde_json::json!({
            "id": "hk_1", "name": "n", "url": "u", "enabled": true, "verify": {"preset": "github"},
            "maxBodyBytes": 1, "createdAt": 0
        }))
        .unwrap();
        assert_eq!(old.on_limit(), OnLimit::Refuse);
        assert_eq!(old.paused_until(), None);
        let new: Hook = serde_json::from_value(serde_json::json!({
            "id": "hk_1", "name": "n", "url": "u", "enabled": true, "verify": {"preset": "github"},
            "maxBodyBytes": 1, "createdAt": 0, "onLimit": "accept_and_drop", "pausedUntil": 99
        }))
        .unwrap();
        assert_eq!(new.on_limit(), OnLimit::AcceptAndDrop);
        assert_eq!(new.paused_until(), Some(99));
        assert_eq!(
            serde_json::to_value(OnLimit::AcceptAndDrop).unwrap(),
            "accept_and_drop"
        );
    }

    #[test]
    fn account_info_reads_the_relay_answer() {
        let raw = r#"{"accountId":"acc_1","plan":"overblast","planUntil":5,"expired":false,
            "limits":{"hooks":50,"devices":10,"eventsPerDay":50000,"hookRatePerMin":120,
              "hookBurst":300,"accountRatePerMin":600,"accountBurst":1200,"retentionHours":168,
              "maxBodyBytes":1048576,"backlogEvents":10000,"backlogBytes":268435456,
              "hookCreatesPerDay":100},
            "usage":{"day":20383,"today":{"events":3,"refused":1,"dropped":0},
              "perHook":{"hk_1":{"today":3,"refused":1,"backlog":{"events":2,"bytes":10},
              "lastEventAt":7}},"backlog":{"events":2,"bytes":10},"hooks":1,"devices":1,
              "hookCreatesToday":1},
            "paused":[{"hookId":"hk_1","until":9}],
            "upgrade":{"plan":"overblast","title":"Overblast Plan","url":"https://x.example"}}"#;
        let a: AccountInfo = serde_json::from_str(raw).unwrap();
        assert_eq!(a.plan, "overblast");
        assert_eq!(a.limits.events_per_day, Some(50_000));
        assert_eq!(a.limits.hook_rate_per_min, Some(120.0));
        assert_eq!(a.usage.per_hook["hk_1"].last_event_at, Some(7));
        assert_eq!(a.paused[0].until, 9);
        assert_eq!(a.upgrade.unwrap().title, "Overblast Plan");
        // The default plan's nulls are no limit.
        let a: AccountInfo = serde_json::from_str(
            r#"{"accountId":"acc_1","plan":"default","planUntil":null,"limits":{"hooks":null}}"#,
        )
        .unwrap();
        assert_eq!(a.limits.hooks, None);
        assert_eq!(a.usage, AccountUsage::default());
        let p: PlansInfo = serde_json::from_str(r#"{"version":"1","protocol":2}"#).unwrap();
        assert!(!p.plans && !p.entitlements && p.hosted_plan.is_none());
    }

    #[test]
    fn patch_sends_only_set_fields() {
        let p = HookPatch {
            enabled: Some(false),
            ..Default::default()
        };
        assert_eq!(serde_json::to_string(&p).unwrap(), r#"{"enabled":false}"#);
        let p = HookPatch {
            deliver_to: Some(None),
            ..Default::default()
        };
        assert_eq!(serde_json::to_string(&p).unwrap(), r#"{"deliverTo":null}"#);
        let p = HookPatch {
            deliver_to: Some(Some("dev_1".into())),
            response: Some(Some(HookResponse {
                status: 200,
                content_type: "text/plain".into(),
                body: "ok".into(),
            })),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&p).unwrap(),
            r#"{"deliverTo":"dev_1","response":{"status":200,"contentType":"text/plain","body":"ok"}}"#
        );
        let p = HookPatch {
            response: Some(None),
            ..Default::default()
        };
        assert_eq!(serde_json::to_string(&p).unwrap(), r#"{"response":null}"#);
    }

    #[test]
    fn hooks_read_deliver_to_and_response_and_tolerate_their_absence() {
        let base = serde_json::json!({
            "id": "hk_1", "name": "n", "url": "https://r.example/h/hk_1", "enabled": true,
            "verify": {"preset": "github"}, "maxBodyBytes": 1, "createdAt": 0
        });
        let old: Hook = serde_json::from_value(base.clone()).unwrap();
        assert!(old.deliver_to.is_none() && old.response.is_none());
        let mut v = base;
        v["deliverTo"] = "dev_9".into();
        v["response"] =
            serde_json::json!({"status": 202, "contentType": "application/json", "body": "{}"});
        let h: Hook = serde_json::from_value(v).unwrap();
        assert_eq!(h.deliver_to.as_deref(), Some("dev_9"));
        assert_eq!(h.response.unwrap().status, 202);
        assert!(h.extra.is_empty());
    }

    #[test]
    fn hooks_read_recipients_and_pause_reasons_and_tolerate_any_shape() {
        let base = serde_json::json!({
            "id": "hk_1", "name": "n", "url": "https://r.example/h/hk_1", "enabled": true,
            "verify": {"preset": "github"}, "maxBodyBytes": 1, "createdAt": 0
        });
        let read = |extra: Value| {
            let mut v = base.clone();
            for (k, x) in extra.as_object().unwrap() {
                v[k] = x.clone();
            }
            serde_json::from_value::<Hook>(v).unwrap()
        };
        // An old relay: no field, every device; or its one device.
        let old = read(serde_json::json!({}));
        assert_eq!(old.recipients(), None);
        assert_eq!(old.paused_reason(), None);
        assert_eq!(old.target(), DeliveryTarget::All);
        let one = read(serde_json::json!({"deliverTo": "dev_1"}));
        assert_eq!(
            one.target(),
            DeliveryTarget::Only(Recipients {
                devices: vec!["dev_1".into()],
                tags: vec![]
            })
        );
        // A new relay: null is every device.
        let all = read(serde_json::json!({"deliverTo": null, "recipients": null}));
        assert_eq!(all.recipients(), Some(None));
        assert_eq!(all.target(), DeliveryTarget::All);
        // A list and tags; a missing array is empty; unknown keys are ignored.
        let many = read(serde_json::json!({
            "deliverTo": null,
            "recipients": {"devices": ["dev_1", "dev_2"], "tags": ["office-macs"], "later": 1},
            "pausedReason": "no_recipient"
        }));
        let want = Recipients {
            devices: vec!["dev_1".into(), "dev_2".into()],
            tags: vec!["office-macs".into()],
        };
        assert_eq!(many.recipients(), Some(Some(want.clone())));
        assert_eq!(many.target(), DeliveryTarget::Only(want));
        assert!(many.paused_for_no_recipient());
        let tags = read(serde_json::json!({"recipients": {"tags": ["a"]}}));
        assert_eq!(
            tags.target(),
            DeliveryTarget::Only(Recipients {
                devices: vec![],
                tags: vec!["a".into()]
            })
        );
        // A list the relay emptied (every listed device revoked) is nobody, not every device.
        let nobody = read(serde_json::json!({
            "deliverTo": null, "recipients": {"devices": [], "tags": []}, "pausedReason": "no_recipient"
        }));
        assert_eq!(nobody.target(), DeliveryTarget::Only(Recipients::default()));
        // A shape this client can't read never makes the hook unreadable.
        let odd = read(serde_json::json!({
            "deliverTo": "dev_3", "recipients": ["dev_3"], "pausedReason": "something_new"
        }));
        assert_eq!(odd.recipients(), None);
        assert_eq!(odd.paused_reason(), Some("something_new"));
        assert!(!odd.paused_for_no_recipient());
        assert!(matches!(odd.target(), DeliveryTarget::Only(r) if r.devices == ["dev_3"]));
        // And it serialises back with the fields it was given.
        let back = serde_json::to_value(&many).unwrap();
        assert_eq!(back["recipients"]["tags"][0], "office-macs");
    }

    #[test]
    fn patches_send_recipients_and_devices_read_tags() {
        let p = HookPatch {
            recipients: Some(Some(Recipients {
                devices: vec!["dev_1".into()],
                tags: vec!["office".into()],
            })),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&p).unwrap(),
            r#"{"recipients":{"devices":["dev_1"],"tags":["office"]}}"#
        );
        let p = HookPatch {
            recipients: Some(None),
            ..Default::default()
        };
        assert_eq!(serde_json::to_string(&p).unwrap(), r#"{"recipients":null}"#);
        let d: DeviceInfo =
            serde_json::from_str(r#"{"id":"dev_1","name":"a","createdAt":0}"#).unwrap();
        assert!(d.tags.is_empty());
        let d: DeviceInfo =
            serde_json::from_str(r#"{"id":"dev_1","name":"a","createdAt":0,"tags":["x"]}"#)
                .unwrap();
        assert_eq!(d.tags, ["x"]);
        assert_eq!(LimitScope::parse("no_recipient"), LimitScope::NoRecipient);
    }

    #[test]
    fn tags_are_short_lowercase_labels() {
        for ok in ["a", "office-macs", "mac.2", "x_y", &"a".repeat(32)] {
            assert!(valid_tag(ok), "{ok}");
        }
        for bad in ["", "Office", "-a", "a-", "a b", "a/b", &"a".repeat(33), "é"] {
            assert!(!valid_tag(bad), "{bad}");
        }
    }

    #[test]
    fn info_reads_push_platforms_and_keeps_new_fields() {
        let v = serde_json::json!({
            "version": "1", "protocol": 2, "protocols": [2], "signupOpen": false,
            "relayKey": "k", "serverTime": 5,
            "phone": {"protocol": 1, "push": {"available": true, "environment": "production",
                      "platforms": {"ios": {"available": true, "environment": "production"},
                                    "android": {"available": false}}}},
            "later": {"x": 1}
        });
        let i: Info = serde_json::from_value(v.clone()).unwrap();
        let push = i.phone.as_ref().unwrap().push.as_ref().unwrap();
        let p = push.platforms.as_ref().unwrap();
        assert!(p.ios.as_ref().unwrap().available && !p.android.as_ref().unwrap().available);
        assert_eq!(serde_json::to_value(&i).unwrap(), v, "nothing lost");
        // An older relay: no phone, no protocols.
        let i: Info = serde_json::from_value(serde_json::json!({
            "version": "0", "protocol": 2, "signupOpen": true, "serverTime": 1
        }))
        .unwrap();
        assert!(i.phone.is_none() && i.serves(2));
    }
}
