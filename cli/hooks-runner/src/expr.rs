//! The filter language of an automation's `only_if`. Small on purpose: it compares fields with
//! values and combines the answers, and it can't call anything, assign anything or loop.
//!
//! ```text
//! payload.action == "opened" and payload.pull_request.additions > 500
//! payload.repository.full_name in ["acme/web", "acme/api"]
//! not payload.pull_request.draft
//! payload.issue.title contains "urgent" or payload.issue.title matches "^\\[P[01]\\]"
//! ```
//!
//! - Values: field paths (rooted at `payload`, `headers`, `event` or `change`), strings in double or
//!   single quotes, numbers, `true`, `false`, `null`, and lists of those (`[1, 2]`).
//! - Comparisons: `==`, `!=`, `>`, `<`, `>=`, `<=`, `in`, `contains`, `matches`.
//! - Logic: `and`, `or`, `not`, parentheses. A value on its own is tested for truth (`true`, a
//!   non-zero number, a non-empty string, list or object).
//! - A missing field is `null`: `payload.x == null` is true when it's missing, and any ordering
//!   comparison with it is false.
//! - `contains` is case-insensitive for text; on a list it tests membership; on an object, a key.
//! - `matches` takes a literal regular expression (Rust `regex` syntax: no look-around or
//!   back-references, so matching always runs in time linear in the input), compiled once when the
//!   file is loaded, with a size limit; it looks at the first 64 KiB of the value.

use std::fmt;

use regex::{Regex, RegexBuilder};
use serde_json::Value;

use crate::path::{self, Path};

/// The longest expression accepted.
pub const MAX_SOURCE: usize = 4096;
/// The deepest nesting of `not` and parentheses.
pub const MAX_DEPTH: usize = 32;
/// The most items in a list literal.
pub const MAX_LIST: usize = 256;
/// The longest regular expression accepted.
pub const MAX_PATTERN: usize = 512;
/// What `matches` reads of a value.
pub const MATCH_INPUT: usize = 64 * 1024;
/// The compiled size limit of one regular expression.
const REGEX_SIZE: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    In,
    Contains,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Lit(Value),
    Path(Path),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Cmp(Op, Box<Expr>, Box<Expr>),
    Matches(Box<Expr>, Regex),
}

/// A parse error and the character column (0-based) where it was noticed.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub at: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at character {})", self.message, self.at + 1)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Path(Path),
    Str(String),
    Num(f64),
    Word(&'static str),
    Sym(&'static str),
}

const WORDS: &[&str] = &[
    "and", "or", "not", "in", "contains", "matches", "true", "false", "null",
];

fn lex(src: &str) -> Result<Vec<(Tok, usize)>, ParseError> {
    let mut out = Vec::new();
    let mut i = 0;
    let b = src.as_bytes();
    let err = |at: usize, m: &str| ParseError {
        at: src[..at].chars().count(),
        message: m.to_string(),
    };
    while i < b.len() {
        let c = src[i..].chars().next().expect("in bounds");
        if c.is_whitespace() {
            i += c.len_utf8();
            continue;
        }
        let start = i;
        let two = src.get(i..i + 2).unwrap_or("");
        if let Some(sym) = ["==", "!=", ">=", "<="].iter().find(|s| **s == two) {
            out.push((Tok::Sym(sym), start));
            i += 2;
            continue;
        }
        match c {
            '>' | '<' | '(' | ')' | '[' | ']' | ',' => {
                let s = match c {
                    '>' => ">",
                    '<' => "<",
                    '(' => "(",
                    ')' => ")",
                    '[' => "[",
                    ']' => "]",
                    _ => ",",
                };
                out.push((Tok::Sym(s), start));
                i += 1;
            }
            '"' | '\'' => {
                let (text, used) = path::parse_string(&src[i..], c).map_err(|m| err(start, &m))?;
                out.push((Tok::Str(text), start));
                i += used;
            }
            '=' => {
                return Err(err(
                    start,
                    "use `==` to compare (a single `=` assigns nothing here)",
                ));
            }
            '!' => return Err(err(start, "use `not` (or `!=` to compare)")),
            '&' | '|' => return Err(err(start, "use `and` and `or`")),
            c if c.is_ascii_digit()
                || (c == '-' && b.get(i + 1).is_some_and(u8::is_ascii_digit)) =>
            {
                let mut j = i + 1;
                while j < b.len() && (b[j].is_ascii_digit() || b[j] == b'.') {
                    j += 1;
                }
                let n: f64 = src[i..j]
                    .parse()
                    .map_err(|_| err(start, "this isn't a number"))?;
                out.push((Tok::Num(n), start));
                i = j;
            }
            c if path::is_ident_start(c) => {
                let (p, used) = path::parse_prefix(&src[i..]).map_err(|m| err(start, &m))?;
                let word = match p.segs.as_slice() {
                    [path::Seg::Key(k)] => WORDS.iter().find(|w| **w == k.as_str()).copied(),
                    _ => None,
                };
                match word {
                    Some(w) => out.push((Tok::Word(w), start)),
                    None => out.push((Tok::Path(p), start)),
                }
                i += used;
            }
            _ => return Err(err(start, &format!("unexpected character {c:?}"))),
        }
    }
    Ok(out)
}

struct Parser<'a> {
    src: &'a str,
    toks: Vec<(Tok, usize)>,
    pos: usize,
    depth: usize,
    /// Every path the expression reads, for checking against the catalogue.
    paths: Vec<Path>,
}

impl Parser<'_> {
    fn at(&self) -> usize {
        let byte = self
            .toks
            .get(self.pos)
            .map(|t| t.1)
            .unwrap_or(self.src.len());
        self.src[..byte].chars().count()
    }

    fn err<T>(&self, m: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError {
            at: self.at(),
            message: m.into(),
        })
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|t| &t.0)
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn deeper(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return self.err("the expression is nested too deeply");
        }
        Ok(())
    }

    fn or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.and()?;
        while self.eat(&Tok::Word("or")) {
            let right = self.and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.not()?;
        while self.eat(&Tok::Word("and")) {
            let right = self.not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn not(&mut self) -> Result<Expr, ParseError> {
        if self.eat(&Tok::Word("not")) {
            self.deeper()?;
            let inner = self.not()?;
            self.depth -= 1;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.cmp()
    }

    fn cmp(&mut self) -> Result<Expr, ParseError> {
        let left = self.value()?;
        let op = match self.peek() {
            Some(Tok::Sym("==")) => Op::Eq,
            Some(Tok::Sym("!=")) => Op::Ne,
            Some(Tok::Sym(">")) => Op::Gt,
            Some(Tok::Sym("<")) => Op::Lt,
            Some(Tok::Sym(">=")) => Op::Ge,
            Some(Tok::Sym("<=")) => Op::Le,
            Some(Tok::Word("in")) => Op::In,
            Some(Tok::Word("contains")) => Op::Contains,
            Some(Tok::Word("matches")) => {
                self.pos += 1;
                let Some(Tok::Str(pattern)) = self.peek().cloned() else {
                    return self.err("`matches` takes a quoted regular expression");
                };
                let re = compile_regex(&pattern).map_err(|m| ParseError {
                    at: self.at(),
                    message: m,
                })?;
                self.pos += 1;
                return Ok(Expr::Matches(Box::new(left), re));
            }
            _ => return Ok(left),
        };
        self.pos += 1;
        let right = self.value()?;
        Ok(Expr::Cmp(op, Box::new(left), Box::new(right)))
    }

    fn value(&mut self) -> Result<Expr, ParseError> {
        let Some(tok) = self.peek().cloned() else {
            return self.err("the expression ends too early");
        };
        self.pos += 1;
        match tok {
            Tok::Path(p) => {
                if let Err(m) = path::check_root(&p, false) {
                    self.pos -= 1;
                    return self.err(m);
                }
                if path::is_batch_root(p.root()) {
                    self.pos -= 1;
                    return self.err(format!(
                        "`{p}`: only_if tests each event before it joins a batch, so it can't \
                         read `batch` or `events` (the actions can)"
                    ));
                }
                self.paths.push(p.clone());
                Ok(Expr::Path(p))
            }
            Tok::Str(s) => Ok(Expr::Lit(Value::String(s))),
            Tok::Num(n) => Ok(Expr::Lit(number(n))),
            Tok::Word("true") => Ok(Expr::Lit(Value::Bool(true))),
            Tok::Word("false") => Ok(Expr::Lit(Value::Bool(false))),
            Tok::Word("null") => Ok(Expr::Lit(Value::Null)),
            Tok::Sym("(") => {
                self.deeper()?;
                let inner = self.or()?;
                self.depth -= 1;
                if !self.eat(&Tok::Sym(")")) {
                    return self.err("expected `)`");
                }
                Ok(inner)
            }
            Tok::Sym("[") => {
                let mut items = Vec::new();
                if !self.eat(&Tok::Sym("]")) {
                    loop {
                        let item = match self.peek().cloned() {
                            Some(Tok::Str(s)) => Value::String(s),
                            Some(Tok::Num(n)) => number(n),
                            Some(Tok::Word("true")) => Value::Bool(true),
                            Some(Tok::Word("false")) => Value::Bool(false),
                            Some(Tok::Word("null")) => Value::Null,
                            _ => {
                                return self.err(
                                    "a list holds only strings, numbers, true, false and null",
                                );
                            }
                        };
                        self.pos += 1;
                        items.push(item);
                        if items.len() > MAX_LIST {
                            return self.err(format!("a list holds at most {MAX_LIST} items"));
                        }
                        if self.eat(&Tok::Sym("]")) {
                            break;
                        }
                        if !self.eat(&Tok::Sym(",")) {
                            return self.err("expected `,` or `]` in the list");
                        }
                    }
                }
                Ok(Expr::Lit(Value::Array(items)))
            }
            Tok::Word(w) => {
                self.pos -= 1;
                self.err(format!("expected a value, found `{w}`"))
            }
            Tok::Sym(s) => {
                self.pos -= 1;
                self.err(format!("expected a value, found `{s}`"))
            }
        }
    }
}

fn number(n: f64) -> Value {
    if n.fract() == 0.0 && n.abs() < 9.0e15 {
        Value::Number((n as i64).into())
    } else {
        serde_json::Number::from_f64(n)
            .map(Value::Number)
            .unwrap_or(Value::Null)
    }
}

/// Compile a regular expression with the size limits.
pub fn compile_regex(pattern: &str) -> Result<Regex, String> {
    if pattern.len() > MAX_PATTERN {
        return Err(format!(
            "the regular expression is longer than {MAX_PATTERN} characters"
        ));
    }
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE)
        .dfa_size_limit(REGEX_SIZE * 4)
        .nest_limit(64)
        .build()
        .map_err(|e| match e {
            regex::Error::CompiledTooBig(_) => {
                "the regular expression is too large once compiled; simplify it".to_string()
            }
            e => format!(
                "this isn't a valid regular expression: {}",
                e.to_string().lines().last().unwrap_or("")
            ),
        })
}

/// A parsed `only_if`.
#[derive(Debug, Clone)]
pub struct Filter {
    pub source: String,
    pub expr: Expr,
    pub paths: Vec<Path>,
}

impl Filter {
    pub fn parse(src: &str) -> Result<Filter, ParseError> {
        if src.len() > MAX_SOURCE {
            return Err(ParseError {
                at: 0,
                message: format!("the expression is longer than {MAX_SOURCE} characters"),
            });
        }
        let toks = lex(src)?;
        let mut p = Parser {
            src,
            toks,
            pos: 0,
            depth: 0,
            paths: Vec::new(),
        };
        if p.toks.is_empty() {
            return p.err("the expression is empty");
        }
        let expr = p.or()?;
        if p.pos != p.toks.len() {
            return p.err("unexpected text here (join conditions with `and` or `or`)");
        }
        Ok(Filter {
            source: src.to_string(),
            expr,
            paths: p.paths,
        })
    }

    /// Whether the event context `ctx` passes.
    pub fn test(&self, ctx: &Value) -> bool {
        truthy(&eval(&self.expr, ctx))
    }
}

pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn eval(e: &Expr, ctx: &Value) -> Value {
    match e {
        Expr::Lit(v) => v.clone(),
        Expr::Path(p) => p.lookup(ctx).cloned().unwrap_or(Value::Null),
        Expr::Not(x) => Value::Bool(!truthy(&eval(x, ctx))),
        Expr::And(a, b) => Value::Bool(truthy(&eval(a, ctx)) && truthy(&eval(b, ctx))),
        Expr::Or(a, b) => Value::Bool(truthy(&eval(a, ctx)) || truthy(&eval(b, ctx))),
        Expr::Matches(x, re) => Value::Bool(match eval(x, ctx) {
            Value::String(s) => re.is_match(head(&s, MATCH_INPUT)),
            _ => false,
        }),
        Expr::Cmp(op, a, b) => Value::Bool(compare(*op, &eval(a, ctx), &eval(b, ctx))),
    }
}

/// The first `max` bytes of `s`, cut on a character boundary.
fn head(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut at = max;
    while !s.is_char_boundary(at) {
        at -= 1;
    }
    &s[..at]
}

/// JSON equality, with numbers compared by value (`1 == 1.0`).
pub fn equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        _ => a == b,
    }
}

fn compare(op: Op, a: &Value, b: &Value) -> bool {
    use std::cmp::Ordering;
    let order = || -> Option<Ordering> {
        match (a, b) {
            (Value::Number(x), Value::Number(y)) => x.as_f64()?.partial_cmp(&y.as_f64()?),
            (Value::String(x), Value::String(y)) => Some(x.cmp(y)),
            _ => None,
        }
    };
    match op {
        Op::Eq => equal(a, b),
        Op::Ne => !equal(a, b),
        Op::Gt => order() == Some(Ordering::Greater),
        Op::Lt => order() == Some(Ordering::Less),
        Op::Ge => matches!(order(), Some(Ordering::Greater | Ordering::Equal)),
        Op::Le => matches!(order(), Some(Ordering::Less | Ordering::Equal)),
        Op::In => match b {
            Value::Array(items) => items.iter().any(|i| equal(a, i)),
            Value::String(hay) => matches!(a, Value::String(n) if hay.contains(n.as_str())),
            Value::Object(m) => matches!(a, Value::String(k) if m.contains_key(k)),
            _ => false,
        },
        Op::Contains => match a {
            Value::String(hay) => match b {
                Value::String(n) => hay.to_lowercase().contains(&n.to_lowercase()),
                _ => false,
            },
            Value::Array(items) => items.iter().any(|i| equal(i, b)),
            Value::Object(m) => matches!(b, Value::String(k) if m.contains_key(k)),
            _ => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{Duration, Instant};

    fn ctx() -> Value {
        json!({
            "payload": {
                "action": "opened",
                "pull_request": {"additions": 600, "draft": false, "title": "[P0] Fix it"},
                "labels": [{"name": "bug"}, {"name": "ui"}],
                "names": ["bug", "ui"],
                "repo": "acme/web",
                "amount": 12.5,
                "empty": "",
                "obj": {"k": 1}
            },
            "headers": {"x-github-event": "pull_request"},
            "event": {"verified": true, "eventType": "pull_request"}
        })
    }

    fn t(src: &str) -> bool {
        Filter::parse(src)
            .unwrap_or_else(|e| panic!("{src}: {e}"))
            .test(&ctx())
    }

    #[test]
    fn comparisons() {
        assert!(t(r#"payload.action == "opened""#));
        assert!(t(r#"payload.action != 'closed'"#));
        assert!(t("payload.pull_request.additions > 500"));
        assert!(!t("payload.pull_request.additions < 500"));
        assert!(t(
            "payload.pull_request.additions >= 600 and payload.pull_request.additions <= 600"
        ));
        assert!(t("payload.amount == 12.5"));
        assert!(t("payload.pull_request.additions == 600.0"));
        assert!(t(r#"payload.repo in ["acme/web", "acme/api"]"#));
        assert!(!t(r#"payload.repo in ["acme/api"]"#));
        assert!(t(r#""bug" in payload.names"#));
        assert!(t(r#"payload.names contains "ui""#));
        assert!(
            t(r#"payload.pull_request.title contains "fix IT""#),
            "case-insensitive"
        );
        assert!(t(r#"payload.obj contains "k""#));
        assert!(t(r#"payload.pull_request.title matches "^\\[P[01]\\]""#));
        assert!(t(r#"headers["x-github-event"] == "pull_request""#));
        assert!(t("headers.x-github-event == event.eventType"));
        assert!(t("payload.labels[1].name == \"ui\""));
    }

    #[test]
    fn logic_and_truth() {
        assert!(t("not payload.pull_request.draft"));
        assert!(t("not not payload.action"));
        assert!(!t("payload.empty"));
        assert!(t(
            r#"payload.action == "x" or (payload.repo == "acme/web" and event.verified)"#
        ));
        assert!(
            !t(r#"payload.action == "x" or payload.repo == "y" and true"#),
            "and binds tighter"
        );
        assert!(t(
            r#"(payload.action == "x" or payload.repo == "acme/web") and true"#
        ));
    }

    #[test]
    fn missing_fields_are_null_and_never_order() {
        assert!(t("payload.nope == null"));
        assert!(!t("payload.nope > 1"));
        assert!(!t("payload.nope < 1"));
        assert!(!t(r#"payload.nope contains "x""#));
        assert!(!t(r#"payload.nope matches ".*""#));
        assert!(
            !t("payload.action > 1"),
            "a string and a number don't order"
        );
        assert!(!t("payload.labels.name == \"bug\""), "a list has no keys");
    }

    #[test]
    fn it_cannot_run_code() {
        for src in [
            "system(\"touch /tmp/x\")",
            "payload.action()",
            "payload.action = 1",
            "$(touch /tmp/x)",
            "`id`",
            "payload.a; payload.b",
            "payload.a && payload.b",
            "!payload.a",
            "import os",
            "payload.a + 1",
            "{{payload.a}}",
            "[payload.a]",
        ] {
            assert!(Filter::parse(src).is_err(), "{src} should not parse");
        }
        // Text that looks like code is only ever data.
        let f = Filter::parse(r#"payload.action == "$(touch /tmp/x); rm -rf /""#).unwrap();
        assert!(!f.test(&ctx()));
    }

    #[test]
    fn errors_say_where_and_what() {
        let e = Filter::parse("action == \"opened\"").unwrap_err();
        assert!(e.message.contains("payload.action"), "{e}");
        let e = Filter::parse("payload.a = 1").unwrap_err();
        assert!(e.message.contains("=="), "{e}");
        assert_eq!(e.at, 10);
        let e = Filter::parse("payload.a == ").unwrap_err();
        assert!(e.message.contains("ends too early"), "{e}");
        let e = Filter::parse("payload.a == 1 payload.b").unwrap_err();
        assert!(e.message.contains("and"), "{e}");
        assert!(Filter::parse("(payload.a").is_err());
        assert!(Filter::parse("\"open").is_err());
        assert!(Filter::parse("").is_err());
        assert!(Filter::parse("event.nope == 1").is_err());
        // A filter tests one event: a batch's fields aren't there yet.
        let e = Filter::parse("batch.count > 3").unwrap_err();
        assert!(
            e.message.contains("each event before it joins a batch"),
            "{e}"
        );
        assert!(Filter::parse("events[0].payload.a == 1").is_err());
    }

    #[test]
    fn limits_hold() {
        let deep = format!("{}payload.a{}", "(".repeat(40), ")".repeat(40));
        assert!(Filter::parse(&deep).unwrap_err().message.contains("deeply"));
        let nots = format!("{}payload.a", "not ".repeat(40));
        assert!(Filter::parse(&nots).is_err());
        assert!(Filter::parse(&"a".repeat(MAX_SOURCE + 1)).is_err());
        let list = format!("payload.a in [{}]", vec!["1"; MAX_LIST + 1].join(","));
        assert!(Filter::parse(&list).is_err());
        let long = format!("payload.a matches \"{}\"", "a".repeat(MAX_PATTERN + 1));
        assert!(Filter::parse(&long).is_err());
        // A pattern that compiles to something huge is refused.
        let huge = r#"payload.a matches "\\w{1000}\\w{1000}\\w{1000}""#;
        let e = Filter::parse(huge).unwrap_err();
        assert!(e.message.contains("too large"), "{e}");
        // Look-around and back-references aren't supported (they need backtracking).
        assert!(Filter::parse(r#"payload.a matches "(a)\\1""#).is_err());
        assert!(Filter::parse(r#"payload.a matches "(?=a)""#).is_err());
        assert!(Filter::parse(r#"payload.a matches "[""#).is_err());
        assert!(
            Filter::parse("payload.a matches payload.b").is_err(),
            "patterns are literals"
        );
    }

    #[test]
    fn catastrophic_patterns_run_in_linear_time() {
        let f = Filter::parse(r#"payload.s matches "^(a+)+$" or payload.s matches "(x+x+)+y""#)
            .unwrap();
        let ctx = json!({"payload": {"s": format!("{}!", "a".repeat(60_000))}});
        let start = Instant::now();
        assert!(!f.test(&ctx));
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
        // Only the first 64 KiB is read.
        let f = Filter::parse(r#"payload.s matches "b$""#).unwrap();
        let ctx = json!({"payload": {"s": format!("{}b", "a".repeat(MATCH_INPUT))}});
        assert!(!f.test(&ctx));
    }

    #[test]
    fn collects_the_paths_it_reads() {
        let f =
            Filter::parse("payload.a.b > 1 and headers.x == \"y\" or not payload.labels[3].name")
                .unwrap();
        let keys: Vec<String> = f.paths.iter().map(Path::field_key).collect();
        assert_eq!(
            keys,
            vec!["payload.a.b", "headers.x", "payload.labels[].name"]
        );
    }
}
