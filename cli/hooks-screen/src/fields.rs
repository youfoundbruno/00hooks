//! Field values and how field rules compare them (PLAN §6a, "Field rules").
//!
//! A field is named by its catalogue path (PLAN §5.0): `payload.sender.email`, `payload.items[].sku`
//! (any item), or `headers.x-github-event`. A path can give several values (one per list item); a
//! condition holds when any of them matches. Only scalars count: strings as they are, numbers and
//! booleans as their JSON text.
//!
//! - **is**: case-folded and trimmed, then equal.
//! - **domain is**: the domain of an address (after the last `@`) or a URL (its host), lower-cased,
//!   without a trailing dot; it matches the domain or any subdomain of it. A domain longer than DNS
//!   allows (253 bytes, 127 labels) never matches.
//! - **contains**: the rule's words appear, in order and next to each other, among the value's
//!   words (case-insensitive; [`crate::text::tokens`]).
//! - **pattern**: a regular expression ([`compile_pattern`]); the regex engine runs in linear time,
//!   and the value it reads is cut at [`MAX_PATTERN_INPUT`] bytes.
//! - **similar text**: a MinHash of that one field ([`crate::minhash`]) at or above a threshold.
//! - **one of**: equal (as for *is*) to any value of a list.
//!
//! For the edge, *is*, *domain is* and *one of* travel as keyed hashes ([`keyed_hash`]): the relay
//! hashes what arrives the same way and compares, and never holds the value. A *pattern* goes only
//! when it is in the subset the relay's linear-time matcher takes ([`edge_pattern_weight`]), which
//! reads the first [`EDGE_PATTERN_INPUT`] characters ([`edge_pattern_matches`]).

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use regex::{Regex, RegexBuilder};
use serde_json::Value;
use sha2::Sha256;

/// The longest pattern a rule may hold.
pub const MAX_PATTERN: usize = 200;
/// What a pattern reads of a value: its first 64 KiB.
pub const MAX_PATTERN_INPUT: usize = 64 * 1024;
const REGEX_SIZE: usize = 256 * 1024;

/// The values at a catalogue path, as text. `item` is `{payload, headers}` as the screen builds it.
pub fn values_at(payload: &Value, headers: &BTreeMap<String, String>, path: &str) -> Vec<String> {
    if let Some(h) = path.strip_prefix("headers.") {
        let h = h.to_ascii_lowercase();
        return headers
            .iter()
            .filter(|(k, _)| k.to_ascii_lowercase() == h)
            .map(|(_, v)| v.clone())
            .collect();
    }
    let Some(rest) = path.strip_prefix("payload") else {
        return Vec::new();
    };
    let mut cur = vec![payload];
    for part in split_path(rest) {
        let mut next = Vec::new();
        for v in cur {
            match (part, v) {
                ("[]", Value::Array(items)) => next.extend(items.iter()),
                (k, Value::Object(m)) if k != "[]" => {
                    if let Some(c) = m.get(k) {
                        next.push(c);
                    }
                }
                _ => {}
            }
        }
        cur = next;
    }
    cur.into_iter().filter_map(scalar_text).collect()
}

fn scalar_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// `.a.b[].c` → `a`, `b`, `[]`, `c` (the catalogue's spelling).
pub fn split_path(rest: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for dotted in rest.split('.').filter(|s| !s.is_empty()) {
        let mut s = dotted;
        while let Some(i) = s.find("[]") {
            if i > 0 {
                out.push(&s[..i]);
            }
            out.push("[]");
            s = &s[i + 2..];
        }
        if !s.is_empty() {
            out.push(s);
        }
    }
    out
}

/// Whether a path is one a field rule may name: `payload…` or `headers.<name>`, at most 300
/// characters, no control characters.
pub fn valid_path(path: &str) -> bool {
    path.len() <= 300
        && !path.chars().any(char::is_control)
        && (path == "payload"
            || path.starts_with("payload.")
            || path.starts_with("payload[]")
            || path.strip_prefix("headers.").is_some_and(|h| {
                !h.is_empty()
                    && h.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            }))
}

/// *is* and *one of* compare this: trimmed and lower-cased.
pub fn fold(v: &str) -> String {
    v.trim().to_lowercase()
}

/// The domain of an address or URL, lower-cased, without a trailing dot: after the last `@`, or
/// the host of `scheme://[user@]host[:port]/…`, or the value itself.
pub fn domain_of(v: &str) -> String {
    let v = v.trim().to_lowercase();
    let host = if let Some(at) = v.rfind('@')
        && !v.contains("://")
    {
        v[at + 1..].to_string()
    } else if let Some(i) = v.find("://") {
        let rest = &v[i + 3..];
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..end];
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        if authority.starts_with('[') {
            match authority.find(']') {
                Some(e) => authority[..=e].to_string(),
                None => authority.to_string(),
            }
        } else {
            match authority.rfind(':') {
                Some(c) => authority[..c].to_string(),
                None => authority.to_string(),
            }
        }
    } else {
        v.clone()
    };
    host.trim_end_matches('.').to_string()
}

/// The longest domain read, in bytes, and its most labels (as DNS has them).
pub const MAX_DOMAIN_BYTES: usize = 253;
pub const MAX_DOMAIN_LABELS: usize = 127;

/// The domain and every parent of it: `a.b.example` → `a.b.example`, `b.example`, `example`. None
/// for a domain longer than [`MAX_DOMAIN_BYTES`] or with more than [`MAX_DOMAIN_LABELS`] labels: it
/// never matches (the relay reads the same).
pub fn domain_suffixes(domain: &str) -> Vec<String> {
    if domain.len() > MAX_DOMAIN_BYTES || domain.split('.').count() > MAX_DOMAIN_LABELS {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut d = domain;
    loop {
        if !d.is_empty() {
            out.push(d.to_string());
        }
        match d.find('.') {
            Some(i) => d = &d[i + 1..],
            None => return out,
        }
    }
}

/// Whether `value`'s domain is `domain` or under it.
pub fn domain_is(value: &str, domain: &str) -> bool {
    let want = domain_of(domain);
    !want.is_empty() && domain_suffixes(&domain_of(value)).contains(&want)
}

/// Whether the words of `phrase` appear in order and adjacent among the words of `value`.
pub fn contains_words(value: &str, phrase: &str) -> bool {
    let want = crate::text::tokens(phrase);
    if want.is_empty() {
        return false;
    }
    let have = crate::text::tokens(value);
    have.windows(want.len()).any(|w| w == want.as_slice())
}

/// Compile a pattern with the size limits. The engine has no backtracking, so its time is linear
/// in what it reads; the limits keep what it compiles small.
pub fn compile_pattern(pattern: &str) -> Result<Regex, String> {
    if pattern.is_empty() {
        return Err("the pattern is empty".into());
    }
    if pattern.chars().count() > MAX_PATTERN {
        return Err(format!(
            "the pattern is longer than {MAX_PATTERN} characters"
        ));
    }
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE)
        .dfa_size_limit(REGEX_SIZE * 4)
        .nest_limit(32)
        .build()
        .map_err(|e| match e {
            regex::Error::CompiledTooBig(_) => {
                "the pattern is too large once compiled; simplify it".into()
            }
            e => format!(
                "this isn't a valid pattern: {}",
                e.to_string().lines().last().unwrap_or("")
            ),
        })
}

/// Whether a compiled pattern matches the first [`MAX_PATTERN_INPUT`] bytes of a value.
pub fn pattern_matches(re: &Regex, value: &str) -> bool {
    let mut end = value.len().min(MAX_PATTERN_INPUT);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    re.is_match(&value[..end])
}

/// What a pattern reads of a value at the edge: its first 2,048 characters.
pub const EDGE_PATTERN_INPUT: usize = 2048;
/// The most a `{n,m}` repeat counts to in an edge pattern.
pub const EDGE_MAX_REPEAT: u32 = 1000;
/// The most an edge pattern weighs once its repeats are counted (see [`edge_pattern_weight`]).
pub const EDGE_MAX_WEIGHT: u32 = 250;
/// The most groups nest in an edge pattern.
pub const EDGE_MAX_GROUP_DEPTH: usize = 8;
/// The most the different patterns of one hook's edge screen weigh together.
pub const EDGE_MAX_SCREEN_WEIGHT: u32 = 4000;

/// Whether a pattern matches a value as the edge reads it: the first [`EDGE_PATTERN_INPUT`]
/// characters. The relay's linear-time matcher gives the same answer for every pattern
/// [`edge_pattern_weight`] takes (`fixtures/screen.v1.json`).
pub fn edge_pattern_matches(re: &Regex, value: &str) -> bool {
    let end = value
        .char_indices()
        .nth(EDGE_PATTERN_INPUT)
        .map_or(value.len(), |(i, _)| i);
    re.is_match(&value[..end])
}

/// Whether a pattern may go to the edge (see [`edge_pattern_weight`]).
pub fn edge_safe_pattern(pattern: &str) -> Result<(), String> {
    edge_pattern_weight(pattern).map(|_| ())
}

/// The weight of a pattern the edge can run, or why it can't. The relay matches patterns in linear
/// time with its own engine (`relay/src/screen-pattern.ts`), which takes a subset of this crate's
/// syntax with the same meaning; this checks the same subset, the same way:
///
/// - 1 to 200 characters; `(?i)` only at the very start; groups `( )`, `(?: )` and `(?i: )`,
///   nested at most 8 deep; `|` (an empty branch matches the empty text);
/// - repeats `*`, `+`, `?`, `{n}`, `{n,}`, `{n,m}` (digits only, at most 1,000, n <= m), each
///   optionally lazy, never on an assertion and never stacked;
/// - escapes `\d \D \w \W \s \S \b \B \n \t \r \f \v` and `\` before ASCII punctuation (not `<` or
///   `>`); any other character but `\ . + * ? ( ) | [ ] { } ^ $` stands for itself; `.`, `^`, `$`;
/// - classes `[…]`/`[^…]` of characters, ranges between two characters, and `\d \D \w \W \s \S`;
///   no nesting, no `&&`, `~~` or `--`, `-` only first or last, never empty;
/// - a weight of at most 250: a character, class or assertion weighs 1, a sequence the sum, an
///   alternation the sum plus one per `|`, `x{n,m}` weight(x)·max(m,1) and `x{n,}` weight(x)·(n+1).
pub fn edge_pattern_weight(pattern: &str) -> Result<u32, String> {
    let cs: Vec<char> = pattern.chars().collect();
    if cs.is_empty() {
        return Err("the pattern is empty".into());
    }
    if cs.len() > MAX_PATTERN {
        return Err(format!(
            "the pattern is longer than {MAX_PATTERN} characters"
        ));
    }
    let mut p = EdgeParser { cs: &cs, pos: 0 };
    if cs.starts_with(&['(', '?', 'i', ')']) {
        p.pos = 4;
    }
    let weight = p.alt(0)?;
    if p.pos < cs.len() {
        return Err("an unmatched )".into());
    }
    if weight > EDGE_MAX_WEIGHT {
        return Err(format!(
            "the pattern is too large once its repeats are counted (at most {EDGE_MAX_WEIGHT})"
        ));
    }
    // The regex crate reads it too (its syntax only: a large compiled size is no error here).
    match RegexBuilder::new(pattern).size_limit(1 << 16).build() {
        Ok(_) | Err(regex::Error::CompiledTooBig(_)) => Ok(weight),
        Err(e) => Err(format!(
            "this isn't a valid pattern: {}",
            e.to_string().lines().last().unwrap_or("")
        )),
    }
}

/// An edge pattern compiled by this crate, to match as the relay does ([`edge_pattern_matches`]).
/// The subset's weight bounds its size, so the limit here is wider than [`compile_pattern`]'s
/// (whose limit `\w`, a large Unicode class, reaches sooner than the weight does).
pub fn edge_regex(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .size_limit(64 * 1024 * 1024)
        .nest_limit(64)
        .build()
        .map_err(|e| {
            format!(
                "this isn't a valid pattern: {}",
                e.to_string().lines().last().unwrap_or("")
            )
        })
}

fn capped(w: u64) -> u32 {
    w.min(u64::from(EDGE_MAX_WEIGHT) + 1) as u32
}

fn edge_punct(c: char) -> bool {
    c.is_ascii_punctuation() && c != '<' && c != '>'
}

const EDGE_NAMED: &str = "dDwWsS";
const EDGE_ESCAPED: &str = "ntrfv";

struct EdgeParser<'a> {
    cs: &'a [char],
    pos: usize,
}

/// One character of a class: a character, or a named class (`\d`…).
enum ClassItem {
    Char(char),
    Named,
}

impl EdgeParser<'_> {
    fn peek(&self, o: usize) -> Option<char> {
        self.cs.get(self.pos + o).copied()
    }

    fn alt(&mut self, depth: usize) -> Result<u32, String> {
        let mut sum = u64::from(self.cat(depth)?);
        let mut bars = 0u64;
        while self.peek(0) == Some('|') {
            self.pos += 1;
            sum += u64::from(self.cat(depth)?);
            bars += 1;
        }
        Ok(capped(sum + bars))
    }

    fn cat(&mut self, depth: usize) -> Result<u32, String> {
        let mut sum = 0u64;
        loop {
            match self.peek(0) {
                None | Some('|' | ')') => break,
                _ => {}
            }
            let (w, assertion) = self.atom(depth)?;
            let w = match self.quant()? {
                Some((min, max)) => {
                    if assertion {
                        return Err("an assertion can't repeat".into());
                    }
                    if self.peek(0) == Some('?') {
                        self.pos += 1;
                    }
                    if matches!(self.peek(0), Some('*' | '+' | '?' | '{')) {
                        return Err("a repeat can't repeat".into());
                    }
                    let times = match max {
                        None => u64::from(min) + 1,
                        Some(m) => u64::from(m.max(1)),
                    };
                    capped(u64::from(w) * times)
                }
                None => w,
            };
            sum += u64::from(w);
        }
        Ok(capped(sum))
    }

    fn quant(&mut self) -> Result<Option<(u32, Option<u32>)>, String> {
        let bad = || "a repeat is {n}, {n,} or {n,m}".to_string();
        match self.peek(0) {
            Some('*') => {
                self.pos += 1;
                return Ok(Some((0, None)));
            }
            Some('+') => {
                self.pos += 1;
                return Ok(Some((1, None)));
            }
            Some('?') => {
                self.pos += 1;
                return Ok(Some((0, Some(1))));
            }
            Some('{') => self.pos += 1,
            _ => return Ok(None),
        }
        let min = self.number()?;
        if self.peek(0) == Some('}') {
            self.pos += 1;
            return Ok(Some((min, Some(min))));
        }
        if self.peek(0) != Some(',') {
            return Err(bad());
        }
        self.pos += 1;
        if self.peek(0) == Some('}') {
            self.pos += 1;
            return Ok(Some((min, None)));
        }
        let max = self.number()?;
        if self.peek(0) != Some('}') {
            return Err(bad());
        }
        self.pos += 1;
        if min > max {
            return Err("a repeat's {n,m} has n above m".into());
        }
        Ok(Some((min, Some(max))))
    }

    fn number(&mut self) -> Result<u32, String> {
        let mut s = String::new();
        while s.len() < 5
            && let Some(c) = self.peek(0).filter(char::is_ascii_digit)
        {
            s.push(c);
            self.pos += 1;
        }
        if s.is_empty() || self.peek(0).is_some_and(|c| c.is_ascii_digit()) {
            return Err("a repeat is {n}, {n,} or {n,m}".into());
        }
        let n: u32 = s.parse().map_err(|_| "a repeat is {n}, {n,} or {n,m}")?;
        if n > EDGE_MAX_REPEAT {
            return Err(format!("a repeat counts to at most {EDGE_MAX_REPEAT}"));
        }
        Ok(n)
    }

    /// An atom's weight, and whether it is an assertion.
    fn atom(&mut self, depth: usize) -> Result<(u32, bool), String> {
        let c = self.cs[self.pos];
        match c {
            '(' => {
                self.pos += 1;
                if self.peek(0) == Some('?') {
                    if self.peek(1) == Some(':') {
                        self.pos += 2;
                    } else if self.peek(1) == Some('i') && self.peek(2) == Some(':') {
                        self.pos += 3;
                    } else {
                        return Err(
                            "the only groups are ( ), (?: ) and (?i: ), and (?i) only at the start"
                                .into(),
                        );
                    }
                }
                if depth + 1 > EDGE_MAX_GROUP_DEPTH {
                    return Err(format!("groups nest at most {EDGE_MAX_GROUP_DEPTH} deep"));
                }
                let w = self.alt(depth + 1)?;
                if self.peek(0) != Some(')') {
                    return Err("an unclosed (".into());
                }
                self.pos += 1;
                Ok((w, false))
            }
            '.' => {
                self.pos += 1;
                Ok((1, false))
            }
            '^' | '$' => {
                self.pos += 1;
                Ok((1, true))
            }
            '[' => {
                self.class()?;
                Ok((1, false))
            }
            '\\' => {
                let e = self.peek(1);
                self.pos += 2;
                match e {
                    None => Err("a pattern can't end in \\".into()),
                    Some('b' | 'B') => Ok((1, true)),
                    Some(e) if EDGE_NAMED.contains(e) || EDGE_ESCAPED.contains(e) => Ok((1, false)),
                    Some(e) if edge_punct(e) => Ok((1, false)),
                    Some(e) => Err(format!("\\{e} isn't in the edge's subset")),
                }
            }
            '*' | '+' | '?' | '{' => Err("a repeat needs something to repeat".into()),
            ')' | '|' | ']' | '}' => Err(format!("{c} needs a \\ before it")),
            _ => {
                self.pos += 1;
                Ok((1, false))
            }
        }
    }

    fn single(&mut self) -> Result<ClassItem, String> {
        let c = self.cs[self.pos];
        if c != '\\' {
            self.pos += 1;
            return Ok(ClassItem::Char(c));
        }
        let e = self.peek(1);
        self.pos += 2;
        match e {
            None => Err("an unclosed [".into()),
            Some(e) if EDGE_NAMED.contains(e) => Ok(ClassItem::Named),
            Some(e) if EDGE_ESCAPED.contains(e) => Ok(ClassItem::Char(match e {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                'f' => '\x0c',
                _ => '\x0b',
            })),
            Some(e) if edge_punct(e) => Ok(ClassItem::Char(e)),
            Some(e) => Err(format!("\\{e} isn't in the edge's subset inside [ ]")),
        }
    }

    fn class(&mut self) -> Result<(), String> {
        self.pos += 1;
        if self.peek(0) == Some('^') {
            self.pos += 1;
        }
        let mut items = 0;
        loop {
            let Some(c) = self.peek(0) else {
                return Err("an unclosed [".into());
            };
            if c == ']' {
                if items == 0 {
                    return Err("a class needs something in it (write \\] for a ])".into());
                }
                self.pos += 1;
                return Ok(());
            }
            if c == '[' {
                return Err("classes don't nest (write \\[ for a [)".into());
            }
            if (c == '&' || c == '~') && self.peek(1) == Some(c) {
                return Err(format!("{c}{c} isn't in the edge's subset"));
            }
            if c == '-' && items > 0 && self.peek(1) != Some(']') {
                return Err("a - in a class goes first or last (or write \\-)".into());
            }
            let lo = if c == '-' {
                self.pos += 1;
                ClassItem::Char('-')
            } else {
                self.single()?
            };
            items += 1;
            let range_follows =
                self.peek(0) == Some('-') && !matches!(self.peek(1), Some(']') | None);
            match lo {
                ClassItem::Named => {
                    if range_follows {
                        return Err("a range goes between two characters".into());
                    }
                }
                ClassItem::Char(lo) => {
                    if c != '-' && range_follows {
                        self.pos += 1;
                        match self.single()? {
                            ClassItem::Named => {
                                return Err("a range goes between two characters".into());
                            }
                            ClassItem::Char(hi) if hi < lo => {
                                return Err("a range goes from low to high".into());
                            }
                            ClassItem::Char(_) => {}
                        }
                    }
                }
            }
        }
    }
}

/// The keyed hash a field value travels to the edge as: HMAC-SHA256 under the account's screen key
/// of `00hooks-screen-field-v1\n<path>\n<normalised value>`, its first 16 bytes in unpadded
/// base64url (22 characters).
pub fn keyed_hash(key: &[u8], path: &str, normalised: &str) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac takes any key");
    mac.update(format!("00hooks-screen-field-v1\n{path}\n{normalised}").as_bytes());
    let out = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(&out[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn paths_reach_nested_fields_lists_and_headers() {
        let p = json!({"sender": {"email": " Promo@Deals.Example "}, "items": [{"sku": "a"}, {"sku": 2}], "ok": true});
        let mut h = BTreeMap::new();
        h.insert("X-Kind".to_string(), "promo".to_string());
        assert_eq!(
            values_at(&p, &h, "payload.sender.email"),
            [" Promo@Deals.Example "]
        );
        assert_eq!(values_at(&p, &h, "payload.items[].sku"), ["a", "2"]);
        assert_eq!(values_at(&p, &h, "payload.ok"), ["true"]);
        assert_eq!(values_at(&p, &h, "headers.x-kind"), ["promo"]);
        assert!(values_at(&p, &h, "payload.sender").is_empty());
        assert!(valid_path("payload.items[].sku") && valid_path("headers.x-kind"));
        assert!(!valid_path("body.x") && !valid_path("headers.a b"));
    }

    #[test]
    fn domains_of_addresses_and_urls() {
        assert_eq!(
            domain_of(" Promo@Mail.Deals.Example. "),
            "mail.deals.example"
        );
        assert_eq!(domain_of("https://user@Bit.ly:443/x?y"), "bit.ly");
        assert!(domain_is("x@mail.deals.example", "deals.example"));
        assert!(domain_is("deals.example", "Deals.Example"));
        assert!(!domain_is("x@nodeals.example", "deals.example"));
        assert!(!domain_is("x@deals.example.com", "deals.example"));
    }

    #[test]
    fn words_and_patterns() {
        assert!(contains_words("Get FREE crypto now!", "free crypto"));
        assert!(!contains_words("freecrypto", "free crypto"));
        assert!(!contains_words("crypto free", "free crypto"));
        let re = compile_pattern(r"bit\.ly/\w+").unwrap();
        assert!(pattern_matches(&re, "see bit.ly/abc"));
        assert!(compile_pattern("(").is_err());
        assert!(compile_pattern(&"a".repeat(201)).is_err());
        // A pattern that blows up a backtracking engine is fine here (linear time)...
        let evil = compile_pattern("(a+)+$").unwrap();
        let t = std::time::Instant::now();
        assert!(!pattern_matches(&evil, &format!("{}!", "a".repeat(60_000))));
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
        // ...and at the edge, whose engine is linear too, within its subset.
        assert!(edge_safe_pattern("(a+)+$").is_ok());
        assert!(edge_safe_pattern(r"(\w)\1").is_err());
        assert!(edge_safe_pattern("(?=a)").is_err());
        assert!(edge_safe_pattern("a*b*c*").is_ok());
        assert!(edge_safe_pattern(r"bit\.ly/\w+").is_ok());
        assert!(edge_safe_pattern("[(*+]x{2,5}").is_ok());
        assert!(edge_safe_pattern(r"\w{251}").is_err());
        assert_eq!(edge_pattern_weight(r"(?i)a{2,3}(b|cd)*"), Ok(3 + 4));
    }

    #[test]
    fn keyed_hashes_depend_on_key_path_and_value() {
        let a = keyed_hash(b"k1", "payload.x", "v");
        assert_eq!(a.len(), 22);
        assert_ne!(a, keyed_hash(b"k2", "payload.x", "v"));
        assert_ne!(a, keyed_hash(b"k1", "payload.y", "v"));
        assert_ne!(a, keyed_hash(b"k1", "payload.x", "w"));
    }
}
