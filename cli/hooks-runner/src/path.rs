//! Field paths: `payload.pull_request.additions`, `payload.labels[0].name`,
//! `headers["x-github-event"]`. Used by filters, templates and the event catalogue.

use std::fmt;

use serde_json::Value;

/// Where a path may start.
pub const ROOTS: &[&str] = &["payload", "headers", "event", "change", "agent"];

/// The fields of `agent.*`: the reply of the last "ask an agent" action before this one.
pub const AGENT_FIELDS: &[&str] = &["reply", "id", "name"];

/// The fields of `event.*`.
pub const EVENT_FIELDS: &[&str] = &[
    "id",
    "seq",
    "hookId",
    "hook",
    "eventType",
    "kind",
    "verified",
    "receivedAt",
    "preset",
    "contentType",
    "replay",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seg {
    Key(String),
    Index(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    pub segs: Vec<Seg>,
}

impl Path {
    pub fn root(&self) -> &str {
        match self.segs.first() {
            Some(Seg::Key(k)) => k,
            _ => "",
        }
    }

    /// Follow the path through `v`. `None` when any step is missing.
    pub fn lookup<'a>(&self, v: &'a Value) -> Option<&'a Value> {
        let mut cur = v;
        for s in &self.segs {
            cur = match (s, cur) {
                (Seg::Key(k), Value::Object(m)) => m.get(k)?,
                (Seg::Index(i), Value::Array(a)) => a.get(*i)?,
                _ => return None,
            };
        }
        Some(cur)
    }

    /// The catalogue's spelling: array indexes become `[]` (`payload.labels[].name`).
    pub fn field_key(&self) -> String {
        let mut out = String::new();
        for (i, s) in self.segs.iter().enumerate() {
            match s {
                Seg::Key(k) => {
                    if i > 0 {
                        out.push('.');
                    }
                    out.push_str(k);
                }
                Seg::Index(_) => out.push_str("[]"),
            }
        }
        out
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, s) in self.segs.iter().enumerate() {
            match s {
                Seg::Key(k) if is_ident(k) => {
                    if i > 0 {
                        f.write_str(".")?;
                    }
                    f.write_str(k)?;
                }
                Seg::Key(k) => write!(f, "[{}]", Value::String(k.clone()))?,
                Seg::Index(n) => write!(f, "[{n}]")?,
            }
        }
        Ok(())
    }
}

pub fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '$'
}

pub fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '$')
}

fn is_ident(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(is_ident_start) && c.all(is_ident_char)
}

/// Parse a path at the start of `s`; returns it and the bytes consumed. Errors are plain sentences.
pub fn parse_prefix(s: &str) -> Result<(Path, usize), String> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut segs = Vec::new();
    let ident = |i: &mut usize| -> Option<String> {
        let start = *i;
        let first = s[*i..].chars().next()?;
        if !is_ident_start(first) {
            return None;
        }
        *i += first.len_utf8();
        while let Some(c) = s[*i..].chars().next() {
            if !is_ident_char(c) {
                break;
            }
            *i += c.len_utf8();
        }
        Some(s[start..*i].to_string())
    };
    match ident(&mut i) {
        Some(k) => segs.push(Seg::Key(k)),
        None => return Err("expected a field path such as payload.action".into()),
    }
    loop {
        match b.get(i) {
            Some(b'.') => {
                i += 1;
                match ident(&mut i) {
                    Some(k) => segs.push(Seg::Key(k)),
                    None => return Err("expected a field name after `.`".into()),
                }
            }
            Some(b'[') => {
                i += 1;
                if let Some(q @ (b'"' | b'\'')) = b.get(i).copied() {
                    let (text, used) = parse_string(&s[i..], q as char)?;
                    segs.push(Seg::Key(text));
                    i += used;
                } else {
                    let start = i;
                    while b.get(i).is_some_and(u8::is_ascii_digit) {
                        i += 1;
                    }
                    let n = s[start..i]
                        .parse::<usize>()
                        .map_err(|_| "expected a number or a quoted name inside `[ ]`")?;
                    segs.push(Seg::Index(n));
                }
                if b.get(i) != Some(&b']') {
                    return Err("expected `]`".into());
                }
                i += 1;
            }
            _ => break,
        }
        if segs.len() > 64 {
            return Err("the path is too long".into());
        }
    }
    Ok((Path { segs }, i))
}

/// A whole string as a path.
pub fn parse(s: &str) -> Result<Path, String> {
    let s = s.trim();
    let (p, used) = parse_prefix(s)?;
    if used != s.len() {
        return Err(format!("unexpected text after the path: {:?}", &s[used..]));
    }
    Ok(p)
}

/// Parse a quoted string starting at `s[0]` (the quote). Returns the text and the bytes consumed.
pub fn parse_string(s: &str, quote: char) -> Result<(String, usize), String> {
    let mut out = String::new();
    let mut chars = s.char_indices();
    chars.next();
    while let Some((i, c)) = chars.next() {
        match c {
            c if c == quote => return Ok((out, i + c.len_utf8())),
            '\\' => match chars.next() {
                Some((_, 'n')) => out.push('\n'),
                Some((_, 't')) => out.push('\t'),
                Some((_, c @ ('\\' | '"' | '\''))) => out.push(c),
                Some((_, c)) => return Err(format!("unknown escape `\\{c}` in a string")),
                None => break,
            },
            c => out.push(c),
        }
    }
    Err("a string isn't closed (missing its closing quote)".into())
}

/// Check a path's root (and, for `event.*`, its field). `secret` is allowed where `secrets` is.
pub fn check_root(p: &Path, secrets: bool) -> Result<(), String> {
    let root = p.root();
    if root == "secret" {
        if !secrets {
            return Err(
                "secrets can only be used in a `call` action's headers, never in a body, URL, \
                 command or file"
                    .into(),
            );
        }
        return match (p.segs.len(), p.segs.get(1)) {
            (2, Some(Seg::Key(name))) if is_secret_name(name) => Ok(()),
            _ => Err("write a secret as secret.NAME (letters, digits and _)".into()),
        };
    }
    if !ROOTS.contains(&root) {
        return Err(format!(
            "`{p}` doesn't start with one of {}; did you mean `payload.{p}`?",
            ROOTS.join(", ")
        ));
    }
    if root == "event"
        && let Some(Seg::Key(f)) = p.segs.get(1)
        && !EVENT_FIELDS.contains(&f.as_str())
    {
        return Err(format!(
            "`{p}`: events have no field `{f}` (they have {})",
            EVENT_FIELDS.join(", ")
        ));
    }
    if root == "agent" {
        match (p.segs.len(), p.segs.get(1)) {
            (2, Some(Seg::Key(f))) if AGENT_FIELDS.contains(&f.as_str()) => {}
            _ => {
                return Err(format!(
                    "`{p}`: an agent's answer has {}",
                    AGENT_FIELDS
                        .iter()
                        .map(|f| format!("agent.{f}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
    }
    Ok(())
}

pub fn is_secret_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.starts_with(|c: char| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_and_looks_up() {
        let p = parse("payload.labels[1].name").unwrap();
        let v = json!({"payload": {"labels": [{"name": "a"}, {"name": "b"}]}});
        assert_eq!(p.lookup(&v), Some(&json!("b")));
        assert_eq!(p.field_key(), "payload.labels[].name");
        assert_eq!(p.to_string(), "payload.labels[1].name");
        let p = parse("headers[\"x-github-event\"]").unwrap();
        assert_eq!(p.segs[1], Seg::Key("x-github-event".into()));
        let p = parse("headers.x-github-event").unwrap();
        assert_eq!(p.segs[1], Seg::Key("x-github-event".into()));
        assert!(parse("payload.").is_err());
        assert!(parse("payload[x]").is_err());
        assert!(parse("1abc").is_err());
        assert!(parse("payload.a b").is_err());
        assert_eq!(parse("payload.missing.deeper").unwrap().lookup(&v), None);
    }

    #[test]
    fn roots_are_checked() {
        assert!(check_root(&parse("payload.x").unwrap(), false).is_ok());
        let e = check_root(&parse("action").unwrap(), false).unwrap_err();
        assert!(e.contains("payload.action"), "{e}");
        assert!(check_root(&parse("event.nope").unwrap(), false).is_err());
        assert!(check_root(&parse("secret.TOKEN").unwrap(), false).is_err());
        assert!(check_root(&parse("secret.TOKEN").unwrap(), true).is_ok());
        assert!(check_root(&parse("secret.TOKEN.x").unwrap(), true).is_err());
    }
}
