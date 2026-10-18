//! `hooks-screen`: the screen, an optional firewall for everything that comes from outside
//! (00hooks PLAN §6a). The harness half: the 00hooks runner and the programs that embed it use it, so a
//! webhook, a message on any channel and what a routine fetches meet the same rules before any
//! automation or agent sees them.
//!
//! - [`rules`]: ordered rules on origin (address, network, country), headers, size, whether the
//!   sender is known, fields of the item ([`fields`]: *is*, *domain is*, *contains*, *pattern*,
//!   *similar text*, *one of*, joined by and/or), and similarity to items you decided on
//!   ([`shape`] and [`minhash`] fingerprints). Learned rules expire unless they keep matching.
//! - [`evaluator`]: the optional AI evaluator, asked bounded questions with typed answers, never
//!   tools; it fails closed to the source's default.
//! - [`screen`]: the decision for an item, the quarantine list (Release, Drop, Always…), the
//!   evaluator's cache, its cost per source and its daily cap.
//! - [`edge`]: the rules that can go to the relay, with field values as keyed hashes.
//!
//! The relay's half (the edge) is `relay/src/screen.ts`; both are held to the vectors in
//! `fixtures/screen.v1.json`.

pub mod edge;
pub mod evaluator;
pub mod fields;
pub mod minhash;
pub mod rules;
pub mod screen;
pub mod shape;
pub mod text;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use evaluator::{Answers, Decider, EvaluatorSettings, Provider, Retention, Thresholds};
pub use rules::{Condition, FieldOp, Rule};
pub use screen::{By, Decision, Held, HeldState, Screen, Settings, SourceSettings};

/// What happens to an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Delivered as usual.
    Pass,
    /// Kept aside, not acted on, until a person releases or drops it.
    Quarantine,
    /// Discarded, with the reason recorded.
    Drop,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Pass => "Pass",
            Verdict::Quarantine => "Quarantine",
            Verdict::Drop => "Drop",
        }
    }
}

/// The kind of source an item came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// A webhook (a 00hooks hook).
    Webhook,
    /// A message on a messaging channel.
    Channel,
    /// Outside content a routine fetched.
    Routine,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Webhook => "webhook",
            SourceKind::Channel => "channel",
            SourceKind::Routine => "routine",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub kind: SourceKind,
    /// The hook id, the channel (`telegram`, `email`…) or the routine's id.
    pub id: String,
    /// Its name, for showing.
    pub name: String,
}

impl Source {
    pub fn describe(&self) -> String {
        match self.kind {
            SourceKind::Webhook => format!("a webhook to {}", self.name),
            SourceKind::Channel => format!("a message on {}", self.name),
            SourceKind::Routine => format!("content the routine {} fetched", self.name),
        }
    }
}

/// Where an item came from, as far as anyone can tell.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Origin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Messages: the sender's handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    /// Messages: whether the sender is a person you know.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<bool>,
}

/// One item to screen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    /// The host's id for it (an event id, a message id).
    pub id: String,
    pub source: Source,
    /// The content as fields read it: a webhook's parsed body; a message as
    /// `{sender, text, subject?, channel}`.
    pub payload: Value,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub origin: Origin,
    /// Bytes.
    #[serde(default)]
    pub size: usize,
    pub received_at: i64,
    /// An agent would read it: the fallback when the evaluator can't answer is quarantine.
    #[serde(default)]
    pub agent_bound: bool,
    /// Something would act on it; when nothing would, the evaluator isn't asked (it would cost
    /// money for nothing).
    #[serde(default = "yes")]
    pub consequential: bool,
    /// What the source is for, in the person's words (an automation's description).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// The item in a few words, for the quarantine list ("pull_request from GitHub").
    #[serde(default)]
    pub summary: String,
    /// What similarity reads, when it isn't every string of the payload: a message's own text,
    /// so the same template from another sender still counts as the same.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

impl Item {
    /// The text its fingerprint is taken from: `text` when set, else every string of the payload.
    pub fn similarity_text(&self) -> String {
        match &self.text {
            Some(t) => t.clone(),
            None => text::item_text(&self.payload),
        }
    }
}

fn yes() -> bool {
    true
}

/// Now, in Unix milliseconds.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The first `max` characters, with `…` when cut.
pub fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
}

/// 16 random hex characters.
pub fn random_hex() -> String {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).expect("randomness");
    r.iter().map(|b| format!("{b:02x}")).collect()
}

/// A body as fields read it: JSON when it parses as JSON, the fields of a form when it is
/// `application/x-www-form-urlencoded` (a repeated name becomes a list), text when it is UTF-8,
/// else `null`. The runner's context and the relay read bodies the same way.
pub fn parse_payload(bytes: &[u8], content_type: Option<&str>) -> Value {
    if bytes.is_empty() {
        return Value::Null;
    }
    if let Ok(v) = serde_json::from_slice::<Value>(bytes) {
        return v;
    }
    let form = content_type.is_some_and(|c| {
        c.to_ascii_lowercase()
            .starts_with("application/x-www-form-urlencoded")
    });
    if form {
        let mut m = serde_json::Map::new();
        for (k, v) in url::form_urlencoded::parse(bytes) {
            let v = Value::String(v.into_owned());
            match m.get_mut(k.as_ref()) {
                Some(Value::Array(a)) => a.push(v),
                Some(prev) => *prev = Value::Array(vec![prev.take(), v]),
                None => {
                    m.insert(k.into_owned(), v);
                }
            }
        }
        return Value::Object(m);
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => Value::String(text.to_string()),
        Err(_) => Value::Null,
    }
}
