//! Field values and how field rules compare them (PLAN §6a, "Field rules").
//!
//! A field is named by its catalogue path (PLAN §5.0): `payload.sender.email`, `payload.items[].sku`
//! (any item), or `headers.x-github-event`. A path can give several values (one per list item); a
//! condition holds when any of them matches. Only scalars count: strings as they are, numbers and
//! booleans as their JSON text.
//!
//! - **is**: case-folded and trimmed, then equal.
//! - **domain is**: the domain of an address (after the last `@`) or a URL (its host), lower-cased,
//!   without a trailing dot; it matches the domain or any subdomain of it.
//! - **contains**: the rule's words appear, in order and next to each other, among the value's
//!   words (case-insensitive; [`crate::text::tokens`]).
//! - **pattern**: a regular expression ([`compile_pattern`]); the regex engine runs in linear time,
//!   and the value it reads is cut at [`MAX_PATTERN_INPUT`] bytes.
//! - **similar text**: a MinHash of that one field ([`crate::minhash`]) at or above a threshold.
//! - **one of**: equal (as for *is*) to any value of a list.
//!
//! For the edge, *is*, *domain is* and *one of* travel as keyed hashes ([`keyed_hash`]): the relay
//! hashes what arrives the same way and compares, and never holds the value.

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

/// The domain and every parent of it: `a.b.example` → `a.b.example`, `b.example`, `example`.
pub fn domain_suffixes(domain: &str) -> Vec<String> {
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

/// Whether a pattern may go to the edge: the relay's regular expressions backtrack, so it takes only
/// a small, safe subset (no back-references, no look-around, no quantified groups, at most two
/// unbounded repeats), and reads at most 2,048 characters of a value. `relay/src/screen.ts` checks
/// the same.
pub fn edge_safe_pattern(pattern: &str) -> Result<(), String> {
    if pattern.chars().count() > MAX_PATTERN {
        return Err(format!(
            "the pattern is longer than {MAX_PATTERN} characters"
        ));
    }
    let chars: Vec<char> = pattern.chars().collect();
    let mut unbounded = 0;
    let mut i = 0;
    let mut in_class = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            let n = chars.get(i + 1).copied().unwrap_or(' ');
            if n.is_ascii_digit() && n != '0' || n == 'k' {
                return Err("back-references can't go to the edge".into());
            }
            i += 2;
            continue;
        }
        if in_class {
            if c == ']' {
                in_class = false;
            }
            i += 1;
            continue;
        }
        match c {
            '[' => in_class = true,
            '(' if chars.get(i + 1) == Some(&'?') => {
                let n = chars.get(i + 2).copied().unwrap_or(' ');
                if n == '=' || n == '!' || n == '<' {
                    return Err("look-around can't go to the edge".into());
                }
            }
            ')' => {
                if matches!(chars.get(i + 1), Some('*' | '+' | '?' | '{')) {
                    return Err("a repeated group can't go to the edge".into());
                }
            }
            '*' | '+' => unbounded += 1,
            '{' => {
                let close = chars[i..].iter().position(|c| *c == '}');
                if let Some(j) = close {
                    let inner: String = chars[i + 1..i + j].iter().collect();
                    if inner.ends_with(',') {
                        unbounded += 1;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    if unbounded > 2 {
        return Err("more than two unbounded repeats can't go to the edge".into());
    }
    Ok(())
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
        // ...but never goes to the edge, whose engine backtracks.
        assert!(edge_safe_pattern("(a+)+$").is_err());
        assert!(edge_safe_pattern(r"(\w)\1").is_err());
        assert!(edge_safe_pattern("(?=a)").is_err());
        assert!(edge_safe_pattern("a*b*c*").is_err());
        assert!(edge_safe_pattern(r"bit\.ly/\w+").is_ok());
        assert!(edge_safe_pattern("[(*+]x{2,5}").is_ok());
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
