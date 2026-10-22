//! Rules (PLAN §6a, "Rules", "Similarity", "Field rules"): ordered, deterministic, explainable.
//! A rule is a list of conditions joined by *and* (or by *or*, `any: true`) and a verdict. The
//! first rule that holds decides, and the reason shown is its name.
//!
//! Learned rules are rules too: made from a decision in the quarantine list (*Always pass similar*,
//! *Always drop similar*, *Block on fields…*), they keep what they came from, count their matches,
//! can be switched off, and expire after a while without a match (90 days by default).

use std::collections::BTreeMap;
use std::net::IpAddr;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fields::{self, compile_pattern, contains_words, domain_is, fold, pattern_matches};
use crate::minhash::{DEFAULT_THRESHOLD, Signature};
use crate::window::Window;
use crate::{Item, Verdict};

pub const MAX_RULES: usize = 500;
pub const MAX_CONDITIONS: usize = 20;
pub const MAX_LIST: usize = 1000;
pub const MAX_NAME: usize = 120;
/// A learned rule expires this long after it last matched (or was made).
pub const DEFAULT_EXPIRY_DAYS: u32 = 90;

/// How a header is compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderOp {
    Present,
    Absent,
    Is,
    Contains,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cmp {
    Gt,
    Lt,
}

/// How a field is compared (see [`crate::fields`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldOp {
    Is,
    DomainIs,
    Contains,
    Pattern,
    SimilarText,
    OneOf,
}

impl FieldOp {
    /// Whether the relay must read the words to check it, so pushing it to the edge asks first.
    pub fn needs_words(self) -> bool {
        matches!(
            self,
            FieldOp::Contains | FieldOp::Pattern | FieldOp::SimilarText
        )
    }

    pub fn label(self) -> &'static str {
        match self {
            FieldOp::Is => "is",
            FieldOp::DomainIs => "domain is",
            FieldOp::Contains => "contains",
            FieldOp::Pattern => "matches",
            FieldOp::SimilarText => "is like",
            FieldOp::OneOf => "is one of",
        }
    }
}

/// One condition. `not` turns a list into an allow list ("not from these networks").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "on", rename_all = "snake_case")]
pub enum Condition {
    /// The sender's address is one of these addresses or networks (CIDR). `preset` names where the
    /// list came from (a provider's published ranges), for showing only.
    Ip {
        #[serde(rename = "in")]
        list: Vec<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        not: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preset: Option<String>,
    },
    Asn {
        #[serde(rename = "in")]
        list: Vec<u32>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        not: bool,
    },
    /// Two-letter country codes.
    Country {
        #[serde(rename = "in")]
        list: Vec<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        not: bool,
    },
    Header {
        name: String,
        op: HeaderOp,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<String>,
    },
    Size {
        op: Cmp,
        bytes: u64,
    },
    /// The sender is a person you know (messages).
    Known {
        value: bool,
    },
    Field {
        path: String,
        op: FieldOp,
        /// `is`, `domain is`, `contains`, `pattern`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        /// `one of`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        values: Vec<String>,
        /// `similar text`: the field's MinHash signature.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        threshold: Option<f64>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        not: bool,
    },
    /// The item arrived within a time window ([`crate::window`]): `from` to `to` (`HH:MM`; past
    /// midnight when `from` is later), on `days` (0 is Sunday; every day when absent), in the IANA
    /// zone `tz` (UTC when absent), by its `received_at`.
    Time {
        from: String,
        to: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        days: Option<Vec<u8>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tz: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        not: bool,
    },
    /// Similar to an item you decided on: the same shape, and text at least this similar. Only the
    /// fingerprint is kept, never the item.
    Similar {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shape: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        threshold: Option<f64>,
    },
}

/// Where a learned rule came from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Learned {
    /// The held item it was made from.
    pub from: String,
    /// What the item was, in words ("a webhook from GitHub", "a message from +1555…").
    pub summary: String,
    pub at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub verdict: Verdict,
    /// Conditions joined by *or* instead of *and*.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub any: bool,
    pub conditions: Vec<Condition>,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Which sources it applies to: `webhook`, `channel`, `routine`, or a source id
    /// (`webhook:hk_…`, `channel:telegram`); empty means every source.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learned: Option<Learned>,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_matched_at: Option<i64>,
    #[serde(default)]
    pub matches: u64,
    /// Push it to the relay (webhooks only).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub edge: bool,
}

fn yes() -> bool {
    true
}

impl Rule {
    /// Whether a learned rule has gone `days` without a match.
    pub fn expired(&self, now: i64, days: u32) -> bool {
        self.learned.is_some()
            && now - self.last_matched_at.unwrap_or(self.created_at) > i64::from(days) * 86_400_000
    }

    /// Whether it applies to a source (`kind`, `kind:id`).
    pub fn applies_to(&self, kind: &str, id: &str) -> bool {
        self.sources.is_empty()
            || self
                .sources
                .iter()
                .any(|s| s == kind || *s == format!("{kind}:{id}"))
    }

    /// Whether any condition needs the relay to read words.
    pub fn needs_words(&self) -> bool {
        self.conditions.iter().any(Condition::needs_words)
    }

    /// The rule in a sentence: "Drop when payload.sender.email domain is deals.example".
    pub fn describe(&self) -> String {
        let join = if self.any { " or " } else { " and " };
        let parts: Vec<String> = self.conditions.iter().map(describe).collect();
        format!("{} when {}", self.verdict.label(), parts.join(join))
    }
}

fn describe(c: &Condition) -> String {
    let neg = |not: bool| if not { "not " } else { "" };
    match c {
        Condition::Ip { list, not, preset } => match preset {
            Some(p) => format!("the address is {}in {p}'s published ranges", neg(*not)),
            None => format!("the address is {}{}", neg(*not), short_list(list)),
        },
        Condition::Asn { list, not } => format!(
            "the network is {}AS{}",
            neg(*not),
            list.iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", AS")
        ),
        Condition::Country { list, not } => {
            format!("the country is {}{}", neg(*not), list.join(", "))
        }
        Condition::Header { name, op, value } => match op {
            HeaderOp::Present => format!("the header {name} is there"),
            HeaderOp::Absent => format!("the header {name} is missing"),
            HeaderOp::Is => format!("the header {name} is {}", value.as_deref().unwrap_or("")),
            HeaderOp::Contains => format!(
                "the header {name} contains {}",
                value.as_deref().unwrap_or("")
            ),
        },
        Condition::Size { op, bytes } => format!(
            "the size is {} {} KB",
            if *op == Cmp::Gt { "over" } else { "under" },
            bytes / 1024
        ),
        Condition::Known { value } => {
            if *value {
                "the sender is someone you know".into()
            } else {
                "the sender is a stranger".into()
            }
        }
        Condition::Field {
            path,
            op,
            value,
            values,
            not,
            ..
        } => {
            let what = match op {
                FieldOp::OneOf => short_list(values),
                FieldOp::SimilarText => "this one".into(),
                _ => value.clone().unwrap_or_default(),
            };
            format!("{path} {}{} {what}", neg(*not), op.label())
        }
        Condition::Time {
            from,
            to,
            days,
            tz,
            not,
        } => {
            const NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
            let on = match days {
                Some(d) => format!(
                    " on {}",
                    d.iter()
                        .map(|&x| NAMES.get(usize::from(x)).copied().unwrap_or("?"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                None => String::new(),
            };
            format!(
                "it arrived {}between {from} and {to}{on} ({})",
                neg(*not),
                tz.as_deref().unwrap_or("UTC")
            )
        }
        Condition::Similar { .. } => "it is similar to the item it was made from".into(),
    }
}

impl Condition {
    /// Whether the relay must read the words to check it (a field's `contains`, `pattern` and
    /// `similar text`, and a header's `contains`), so pushing it to the edge asks first.
    pub fn needs_words(&self) -> bool {
        match self {
            Condition::Field { op, .. } => op.needs_words(),
            Condition::Header { op, .. } => *op == HeaderOp::Contains,
            _ => false,
        }
    }
}

fn short_list(l: &[String]) -> String {
    if l.len() <= 3 {
        l.join(", ")
    } else {
        format!("{}, … ({} in all)", l[..3].join(", "), l.len())
    }
}

/// A rule ready to test: patterns compiled, signatures decoded, networks parsed.
#[derive(Debug, Clone)]
pub struct Compiled {
    pub rule: Rule,
    conds: Vec<Cond>,
}

#[derive(Debug, Clone)]
enum Cond {
    Ip(Vec<Net>, bool),
    Asn(Vec<u32>, bool),
    Country(Vec<String>, bool),
    Header(String, HeaderOp, String),
    Size(Cmp, u64),
    Known(bool),
    Field {
        path: String,
        test: FieldTest,
        not: bool,
    },
    Similar(Option<String>, Option<Box<Signature>>, f64),
    Time(Box<Window>, bool),
}

#[derive(Debug, Clone)]
enum FieldTest {
    Is(String),
    DomainIs(String),
    Contains(String),
    Pattern(Box<Regex>),
    Similar(Box<Signature>, f64),
    OneOf(Vec<String>),
}

/// An address or a network.
#[derive(Debug, Clone, PartialEq)]
pub struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Net {
    pub fn parse(s: &str) -> Option<Net> {
        let s = s.trim();
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = p.unwrap_or(max);
        (prefix <= max).then_some(Net { addr, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        let ip = match (ip, &self.addr) {
            (IpAddr::V6(v6), IpAddr::V4(_)) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => return false,
            },
            _ => *ip,
        };
        match (ip, self.addr) {
            (IpAddr::V4(a), IpAddr::V4(n)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(a) & mask == u32::from(n) & mask
            }
            (IpAddr::V6(a), IpAddr::V6(n)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(a) & mask == u128::from(n) & mask
            }
            _ => false,
        }
    }
}

fn need(v: &Option<String>, what: &str) -> Result<String, String> {
    match v.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() && s.chars().count() <= 1000 => Ok(s.to_string()),
        _ => Err(format!("{what} needs a value of up to 1,000 characters")),
    }
}

fn threshold(t: Option<f64>) -> Result<f64, String> {
    let t = t.unwrap_or(DEFAULT_THRESHOLD);
    if !(0.5..=1.0).contains(&t) {
        return Err("a similarity threshold is from 0.5 to 1".into());
    }
    Ok(t)
}

impl Compiled {
    /// Check a rule and make it ready to test; the error is one sentence.
    pub fn new(rule: Rule) -> Result<Compiled, String> {
        if rule.id.is_empty()
            || rule.id.len() > 64
            || !rule
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err("a rule's id is 1 to 64 letters, digits, - or _".into());
        }
        if rule.name.trim().is_empty() || rule.name.chars().count() > MAX_NAME {
            return Err(format!(
                "a rule needs a name of up to {MAX_NAME} characters"
            ));
        }
        if rule.conditions.is_empty() || rule.conditions.len() > MAX_CONDITIONS {
            return Err(format!("a rule has 1 to {MAX_CONDITIONS} conditions"));
        }
        let mut conds = Vec::new();
        for c in &rule.conditions {
            conds.push(compile(c).map_err(|e| format!("{}: {e}", rule.name.trim()))?);
        }
        Ok(Compiled { rule, conds })
    }

    /// Whether the rule holds for an item.
    pub fn test(&self, item: &Item, view: &mut View) -> bool {
        let mut each = self.conds.iter().map(|c| holds(c, item, view));
        if self.rule.any {
            each.any(|b| b)
        } else {
            each.all(|b| b)
        }
    }
}

fn list_len<T>(l: &[T]) -> Result<(), String> {
    if l.is_empty() || l.len() > MAX_LIST {
        return Err(format!("a list has 1 to {MAX_LIST} entries"));
    }
    Ok(())
}

fn compile(c: &Condition) -> Result<Cond, String> {
    Ok(match c {
        Condition::Ip { list, not, .. } => {
            list_len(list)?;
            let nets = list
                .iter()
                .map(|s| Net::parse(s).ok_or_else(|| format!("{s} isn't an address or a network")))
                .collect::<Result<Vec<_>, _>>()?;
            Cond::Ip(nets, *not)
        }
        Condition::Asn { list, not } => {
            list_len(list)?;
            Cond::Asn(list.clone(), *not)
        }
        Condition::Country { list, not } => {
            list_len(list)?;
            let codes = list
                .iter()
                .map(|c| {
                    let c = c.trim().to_ascii_uppercase();
                    if c.len() == 2 && c.chars().all(|x| x.is_ascii_uppercase()) {
                        Ok(c)
                    } else {
                        Err(format!("{c} isn't a two-letter country code"))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            Cond::Country(codes, *not)
        }
        Condition::Header { name, op, value } => {
            let name = name.trim().to_ascii_lowercase();
            if name.is_empty()
                || name.len() > 100
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err("a header name is letters, digits, - or _".into());
            }
            let v = match op {
                HeaderOp::Is | HeaderOp::Contains => {
                    need(value, "a header condition")?.to_lowercase()
                }
                _ => String::new(),
            };
            Cond::Header(name, *op, v)
        }
        Condition::Size { op, bytes } => Cond::Size(*op, *bytes),
        Condition::Known { value } => Cond::Known(*value),
        Condition::Field {
            path,
            op,
            value,
            values,
            signature,
            threshold: t,
            not,
        } => {
            if !fields::valid_path(path) {
                return Err(format!("{path} isn't a field (payload.… or headers.…)"));
            }
            let test = match op {
                FieldOp::Is => FieldTest::Is(fold(&need(value, "is")?)),
                FieldOp::DomainIs => {
                    FieldTest::DomainIs(fields::domain_of(&need(value, "domain is")?))
                }
                FieldOp::Contains => {
                    let v = need(value, "contains")?;
                    if crate::text::tokens(&v).is_empty() {
                        return Err("contains needs at least one word".into());
                    }
                    FieldTest::Contains(v)
                }
                FieldOp::Pattern => {
                    FieldTest::Pattern(Box::new(compile_pattern(&need(value, "a pattern")?)?))
                }
                FieldOp::SimilarText => {
                    let sig = signature
                        .as_deref()
                        .and_then(Signature::decode)
                        .ok_or("similar text needs the field's signature")?;
                    FieldTest::Similar(Box::new(sig), threshold(*t)?)
                }
                FieldOp::OneOf => {
                    list_len(values)?;
                    FieldTest::OneOf(values.iter().map(|v| fold(v)).collect())
                }
            };
            Cond::Field {
                path: path.clone(),
                test,
                not: *not,
            }
        }
        Condition::Time {
            from,
            to,
            days,
            tz,
            not,
        } => Cond::Time(
            Box::new(Window::new(from, to, days.as_deref(), tz.as_deref())?),
            *not,
        ),
        Condition::Similar {
            shape,
            text,
            threshold: t,
        } => {
            let sig = match text {
                Some(t) => Some(Box::new(
                    Signature::decode(t).ok_or("the text fingerprint is malformed")?,
                )),
                None => None,
            };
            if shape.is_none() && sig.is_none() {
                return Err("a similarity condition needs a shape or a text fingerprint".into());
            }
            if let Some(s) = shape
                && (s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return Err("the shape fingerprint is malformed".into());
            }
            Cond::Similar(shape.clone(), sig, threshold(*t)?)
        }
    })
}

/// What rules read of an item, worked out once and only when a rule needs it.
#[derive(Default)]
pub struct View {
    shape: Option<String>,
    text: Option<Option<Signature>>,
    ip: Option<Option<IpAddr>>,
}

impl View {
    pub fn shape(&mut self, item: &Item) -> &str {
        self.shape
            .get_or_insert_with(|| crate::shape::shape_hash(&item.payload))
    }

    pub fn text(&mut self, item: &Item) -> Option<&Signature> {
        self.text
            .get_or_insert_with(|| Signature::of_text(&item.similarity_text()))
            .as_ref()
    }

    fn ip(&mut self, item: &Item) -> Option<IpAddr> {
        *self.ip.get_or_insert_with(|| {
            item.origin
                .ip
                .as_deref()
                .and_then(|s| s.trim().parse().ok())
        })
    }
}

fn header<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

fn holds(c: &Cond, item: &Item, view: &mut View) -> bool {
    match c {
        Cond::Ip(nets, not) => match view.ip(item) {
            Some(ip) => nets.iter().any(|n| n.contains(&ip)) != *not,
            None => false,
        },
        Cond::Asn(list, not) => match item.origin.asn {
            Some(a) => list.contains(&a) != *not,
            None => false,
        },
        Cond::Country(list, not) => match &item.origin.country {
            Some(c) => list.iter().any(|x| x.eq_ignore_ascii_case(c)) != *not,
            None => false,
        },
        Cond::Header(name, op, v) => {
            let h = header(&item.headers, name);
            match op {
                HeaderOp::Present => h.is_some(),
                HeaderOp::Absent => h.is_none(),
                HeaderOp::Is => h.is_some_and(|h| h.trim().to_lowercase() == *v),
                HeaderOp::Contains => h.is_some_and(|h| h.to_lowercase().contains(v.as_str())),
            }
        }
        Cond::Size(op, n) => match op {
            Cmp::Gt => item.size as u64 > *n,
            Cmp::Lt => (item.size as u64) < *n,
        },
        Cond::Known(want) => item.origin.known == Some(*want),
        // When the item arrived (for a webhook, the relay's signed receivedAt), not now.
        Cond::Time(w, not) => w.holds(item.received_at) != *not,
        Cond::Field { path, test, not } => {
            let values = fields::values_at(&item.payload, &item.headers, path);
            if values.is_empty() {
                return false;
            }
            values.iter().any(|v| field_holds(test, v)) != *not
        }
        Cond::Similar(shape, sig, t) => {
            if let Some(s) = shape
                && view.shape(item) != s
            {
                return false;
            }
            match sig {
                Some(sig) => view
                    .text(item)
                    .is_some_and(|mine| mine.similarity(sig) >= *t),
                None => true,
            }
        }
    }
}

fn field_holds(t: &FieldTest, v: &str) -> bool {
    match t {
        FieldTest::Is(want) => fold(v) == *want,
        FieldTest::DomainIs(d) => domain_is(v, d),
        FieldTest::Contains(phrase) => contains_words(v, phrase),
        FieldTest::Pattern(re) => pattern_matches(re, v),
        FieldTest::Similar(sig, t) => {
            Signature::of_text(v).is_some_and(|s| s.similarity(sig) >= *t)
        }
        FieldTest::OneOf(list) => list.contains(&fold(v)),
    }
}

/// The fingerprint of an item, as a similarity condition: its shape, and its text when it has any.
pub fn fingerprint(item: &Item) -> Condition {
    let text = Signature::of_text(&item.similarity_text()).map(|s| s.encode());
    Condition::Similar {
        shape: Some(crate::shape::shape_hash(&item.payload)),
        text,
        threshold: None,
    }
}

/// A field condition from an item's own value, for *Block on fields…*: `similar text` takes the
/// value's signature; the others take the value as it is.
pub fn field_condition(
    item: &Item,
    path: &str,
    op: FieldOp,
    list: Option<Vec<String>>,
) -> Result<Condition, String> {
    let values = fields::values_at(&item.payload, &item.headers, path);
    let first = values
        .first()
        .cloned()
        .ok_or_else(|| format!("the item has no value at {path}"))?;
    let mut c = Condition::Field {
        path: path.to_string(),
        op,
        value: None,
        values: Vec::new(),
        signature: None,
        threshold: None,
        not: false,
    };
    if let Condition::Field {
        value,
        values: vs,
        signature,
        ..
    } = &mut c
    {
        match op {
            FieldOp::SimilarText => {
                *signature = Some(
                    Signature::of_text(&first)
                        .ok_or("that field has no words to compare")?
                        .encode(),
                )
            }
            FieldOp::OneOf => *vs = list.unwrap_or(values),
            FieldOp::DomainIs => *value = Some(fields::domain_of(&first)),
            _ => *value = Some(first),
        }
    }
    compile(&c)?;
    Ok(c)
}

/// The fields of an item and their values, for the field-rule picker: every scalar path of the
/// payload (catalogue spelling) and every header.
pub fn item_fields(item: &Item) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for path in crate::shape::fields(&item.payload).into_keys() {
        let vals = fields::values_at(&item.payload, &item.headers, &path);
        if let Some(v) = vals.first() {
            out.push((path, crate::cut(v, 200)));
        }
    }
    for (k, v) in &item.headers {
        out.push((
            format!("headers.{}", k.to_ascii_lowercase()),
            crate::cut(v, 200),
        ));
    }
    out
}

/// Parse rules from JSON, keeping the good ones and saying what was wrong with the rest.
pub fn parse_rules(v: &Value) -> (Vec<Rule>, Vec<String>) {
    let mut good = Vec::new();
    let mut bad = Vec::new();
    if let Value::Array(items) = v {
        for (i, r) in items.iter().enumerate() {
            match serde_json::from_value::<Rule>(r.clone()) {
                Ok(rule) => match Compiled::new(rule.clone()) {
                    Ok(_) => good.push(rule),
                    Err(e) => bad.push(format!("rule {}: {e}", i + 1)),
                },
                Err(e) => bad.push(format!("rule {}: {e}", i + 1)),
            }
        }
    }
    (good, bad)
}
