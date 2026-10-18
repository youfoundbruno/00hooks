//! Templates: text with `{{ path | filter }}` slots, and JSON values whose strings are templates.
//!
//! A slot holds a field path and optional filters, nothing else: no expressions, no calls.
//! Filters: `money` (minor units such as cents to `12.34`; `money:EUR` adds the currency),
//! `truncate` (to 80 characters, or `truncate:40`), `json` (the value as JSON), `upper`.
//!
//! Rendering never re-reads its output as a template, so a payload containing `{{…}}` stays text.

use serde_json::Value;

use crate::path::{self, Path};

/// The longest template accepted.
pub const MAX_SOURCE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    Money(Option<String>),
    Truncate(usize),
    Json,
    Upper,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Slot {
    pub path: Path,
    pub filters: Vec<Filter>,
}

#[derive(Debug, Clone, PartialEq)]
enum Part {
    Text(String),
    Slot(Slot),
}

/// A parsed text template.
#[derive(Debug, Clone, PartialEq)]
pub struct Template {
    parts: Vec<Part>,
}

/// Which roots a template may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Event fields only.
    Event,
    /// Event fields and `secret.NAME` (a call's headers).
    WithSecrets,
}

impl Template {
    pub fn parse(src: &str, scope: Scope) -> Result<Template, String> {
        if src.len() > MAX_SOURCE {
            return Err(format!(
                "the template is longer than {} KiB",
                MAX_SOURCE / 1024
            ));
        }
        let mut parts = Vec::new();
        let mut rest = src;
        while let Some(open) = rest.find("{{") {
            if open > 0 {
                parts.push(Part::Text(rest[..open].to_string()));
            }
            let after = &rest[open + 2..];
            let close = after
                .find("}}")
                .ok_or_else(|| "a `{{` isn't closed with `}}`".to_string())?;
            parts.push(Part::Slot(parse_slot(&after[..close], scope)?));
            rest = &after[close + 2..];
        }
        if rest.contains("}}") {
            return Err("a `}}` has no `{{` before it".into());
        }
        if !rest.is_empty() {
            parts.push(Part::Text(rest.to_string()));
        }
        Ok(Template { parts })
    }

    /// The paths this template reads.
    pub fn paths(&self) -> impl Iterator<Item = &Path> {
        self.parts.iter().filter_map(|p| match p {
            Part::Slot(s) => Some(&s.path),
            Part::Text(_) => None,
        })
    }

    /// The template is exactly one slot (`"{{payload.items}}"`): in a JSON template it keeps the
    /// value's type.
    fn single(&self) -> Option<&Slot> {
        match self.parts.as_slice() {
            [Part::Slot(s)] => Some(s),
            _ => None,
        }
    }

    pub fn is_constant(&self) -> bool {
        self.parts.iter().all(|p| matches!(p, Part::Text(_)))
    }

    /// Its first characters come from the event: it starts with a slot (`"{{payload.x}}"`,
    /// `"{{payload.x}}.txt"`), not with text you wrote (`"--title={{payload.x}}"`). A command's
    /// argument like this could be made to start with `-` by whoever sent the event.
    pub fn starts_with_slot(&self) -> bool {
        matches!(self.parts.first(), Some(Part::Slot(_)))
    }

    /// Render to text. `encode` is applied to every value put into a slot (URLs percent-encode).
    pub fn render_with(&self, ctx: &Value, encode: &dyn Fn(&str) -> String) -> String {
        let mut out = String::new();
        for p in &self.parts {
            match p {
                Part::Text(t) => out.push_str(t),
                Part::Slot(s) => out.push_str(&encode(&to_text(&s.apply(ctx)))),
            }
        }
        out
    }

    pub fn render(&self, ctx: &Value) -> String {
        self.render_with(ctx, &|s| s.to_string())
    }
}

impl Slot {
    fn apply(&self, ctx: &Value) -> Value {
        let mut v = self.path.lookup(ctx).cloned().unwrap_or(Value::Null);
        for f in &self.filters {
            v = f.apply(v);
        }
        v
    }
}

fn parse_slot(inner: &str, scope: Scope) -> Result<Slot, String> {
    let mut pieces = inner.split('|');
    let head = pieces.next().unwrap_or("").trim();
    if head.is_empty() {
        return Err("an empty `{{ }}`: put a field path inside, such as {{payload.id}}".into());
    }
    let path = path::parse(head).map_err(|e| format!("in `{{{{{}}}}}`: {e}", inner.trim()))?;
    path::check_root(&path, scope == Scope::WithSecrets)?;
    let mut filters = Vec::new();
    for f in pieces {
        let f = f.trim();
        let (name, arg) = match f.split_once(':') {
            Some((n, a)) => (n.trim(), Some(a.trim())),
            None => (f, None),
        };
        filters.push(match (name, arg) {
            ("money", None) => Filter::Money(None),
            ("money", Some(c))
                if !c.is_empty() && c.len() <= 8 && c.chars().all(|c| c.is_ascii_alphabetic()) =>
            {
                Filter::Money(Some(c.to_ascii_uppercase()))
            }
            ("money", Some(_)) => {
                return Err("`money` takes a currency code, such as money:EUR".into());
            }
            ("truncate", None) => Filter::Truncate(80),
            ("truncate", Some(n)) => Filter::Truncate(
                n.parse::<usize>()
                    .ok()
                    .filter(|n| (1..=100_000).contains(n))
                    .ok_or("`truncate` takes a length, such as truncate:40")?,
            ),
            ("json", None) => Filter::Json,
            ("upper", None) => Filter::Upper,
            ("json" | "upper", Some(_)) => return Err(format!("`{name}` takes no argument")),
            _ => {
                return Err(format!(
                    "unknown filter `{name}` (the filters are money, truncate, json and upper)"
                ));
            }
        });
    }
    if path.root() == "secret" && !filters.is_empty() {
        return Err("a secret can't go through filters".into());
    }
    Ok(Slot { path, filters })
}

impl Filter {
    fn apply(&self, v: Value) -> Value {
        match self {
            Filter::Money(currency) => {
                let minor = match &v {
                    Value::Number(n) => n.as_f64(),
                    Value::String(s) => s.trim().parse::<f64>().ok(),
                    _ => None,
                };
                let Some(minor) = minor else { return v };
                let major = format!("{:.2}", minor / 100.0);
                Value::String(match currency {
                    Some(c) => format!("{major} {c}"),
                    None => major,
                })
            }
            Filter::Truncate(n) => {
                let s = to_text(&v);
                if s.chars().count() <= *n {
                    Value::String(s)
                } else {
                    let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
                    t.push('…');
                    Value::String(t)
                }
            }
            Filter::Json => Value::String(serde_json::to_string(&v).unwrap_or_default()),
            Filter::Upper => Value::String(to_text(&v).to_uppercase()),
        }
    }
}

/// A value as text: strings as they are, `null` as nothing, everything else as JSON.
pub fn to_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// A JSON value whose strings are templates (a call's body, a file's line).
#[derive(Debug, Clone, PartialEq)]
pub enum JsonTemplate {
    Lit(Value),
    Text(Template),
    Array(Vec<JsonTemplate>),
    Object(Vec<(String, JsonTemplate)>),
}

impl JsonTemplate {
    pub fn parse(v: &Value) -> Result<JsonTemplate, String> {
        Ok(match v {
            Value::String(s) => {
                let t = Template::parse(s, Scope::Event)?;
                if t.is_constant() {
                    JsonTemplate::Lit(v.clone())
                } else {
                    JsonTemplate::Text(t)
                }
            }
            Value::Array(a) => JsonTemplate::Array(
                a.iter()
                    .map(JsonTemplate::parse)
                    .collect::<Result<_, _>>()?,
            ),
            Value::Object(m) => JsonTemplate::Object(
                m.iter()
                    .map(|(k, v)| Ok((k.clone(), JsonTemplate::parse(v)?)))
                    .collect::<Result<_, String>>()?,
            ),
            other => JsonTemplate::Lit(other.clone()),
        })
    }

    /// A string that is a single slot keeps the value's JSON type (`"{{payload.items}}"` is the
    /// list); anything else renders as text.
    pub fn render(&self, ctx: &Value) -> Value {
        match self {
            JsonTemplate::Lit(v) => v.clone(),
            JsonTemplate::Text(t) => match t.single() {
                Some(slot) => slot.apply(ctx),
                None => Value::String(t.render(ctx)),
            },
            JsonTemplate::Array(a) => Value::Array(a.iter().map(|t| t.render(ctx)).collect()),
            JsonTemplate::Object(m) => {
                Value::Object(m.iter().map(|(k, t)| (k.clone(), t.render(ctx))).collect())
            }
        }
    }

    pub fn paths(&self) -> Vec<&Path> {
        match self {
            JsonTemplate::Lit(_) => Vec::new(),
            JsonTemplate::Text(t) => t.paths().collect(),
            JsonTemplate::Array(a) => a.iter().flat_map(JsonTemplate::paths).collect(),
            JsonTemplate::Object(m) => m.iter().flat_map(|(_, t)| t.paths()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> Value {
        json!({
            "payload": {
                "id": "ord_1", "amount": 1999, "currency": "eur", "title": "a very long title here",
                "items": [1, 2], "nested": {"a": "b"}, "evil": "{{payload.id}} $(touch /tmp/x)"
            },
            "event": {"id": "evt_1", "verified": true}
        })
    }

    fn r(src: &str) -> String {
        Template::parse(src, Scope::Event).unwrap().render(&ctx())
    }

    #[test]
    fn renders_slots_and_filters() {
        assert_eq!(
            r("New order {{payload.id}} for {{ payload.amount | money }}"),
            "New order ord_1 for 19.99"
        );
        assert_eq!(r("{{payload.amount|money:eur}}"), "19.99 EUR");
        assert_eq!(r("{{payload.title | truncate:10}}"), "a very lo…");
        assert_eq!(
            r("{{payload.title | truncate:100}}"),
            "a very long title here"
        );
        assert_eq!(r("{{payload.title | upper | truncate:6}}"), "A VER…");
        assert_eq!(r("{{payload.nested | json}}"), r#"{"a":"b"}"#);
        assert_eq!(r("{{payload.id | json}}"), r#""ord_1""#);
        assert_eq!(r("{{payload.nested}}"), r#"{"a":"b"}"#);
        assert_eq!(r("[{{payload.missing}}]"), "[]");
        assert_eq!(r("{{event.verified}}"), "true");
        assert_eq!(
            r("{{payload.title | money}}"),
            "a very long title here",
            "not a number"
        );
        assert_eq!(r("no slots"), "no slots");
    }

    #[test]
    fn output_is_never_read_again() {
        assert_eq!(r("{{payload.evil}}"), "{{payload.id}} $(touch /tmp/x)");
    }

    #[test]
    fn refuses_what_it_cannot_do() {
        for (src, want) in [
            ("{{payload.id", "isn't closed"),
            ("payload.id}}", "no `{{`"),
            ("{{ }}", "empty"),
            ("{{payload.id | lower}}", "unknown filter"),
            ("{{payload.id | truncate:x}}", "length"),
            ("{{payload.id | money:12}}", "currency"),
            ("{{id}}", "payload.id"),
            ("{{payload.id + 1}}", "unexpected text"),
            ("{{secret.TOKEN}}", "secrets can only"),
            ("{{exec('id')}}", "unexpected text"),
        ] {
            let e = Template::parse(src, Scope::Event).unwrap_err();
            assert!(e.contains(want), "{src}: {e}");
        }
        assert!(Template::parse("Bearer {{secret.TOKEN}}", Scope::WithSecrets).is_ok());
        assert!(Template::parse("{{secret.TOKEN | upper}}", Scope::WithSecrets).is_err());
    }

    #[test]
    fn json_templates_keep_types() {
        let t = JsonTemplate::parse(&json!({
            "text": "Order {{payload.id}}",
            "items": "{{payload.items}}",
            "amount": "{{payload.amount}}",
            "money": "{{payload.amount | money}}",
            "fixed": [1, true, "x"],
            "missing": "{{payload.nope}}"
        }))
        .unwrap();
        assert_eq!(
            t.render(&ctx()),
            json!({
                "text": "Order ord_1", "items": [1, 2], "amount": 1999, "money": "19.99",
                "fixed": [1, true, "x"], "missing": null
            })
        );
        let paths: Vec<String> = t.paths().iter().map(|p| p.to_string()).collect();
        assert!(paths.contains(&"payload.items".to_string()));
    }
}
