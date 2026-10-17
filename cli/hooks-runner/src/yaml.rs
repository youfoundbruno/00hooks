//! A small YAML document tree that remembers the line of every node, so validation errors can name
//! it. Built from `yaml-rust2`'s event stream. Anchors, aliases and tags are refused: an automation
//! file has no use for them, and aliases are how YAML "billion laughs" documents blow up.

use std::fmt;

use serde_json::{Map, Number, Value};
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};

/// The most nodes a document may have: far more than any real automation file.
const MAX_NODES: usize = 100_000;
/// The deepest nesting allowed.
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Map(Vec<(Node, Node)>),
    Seq(Vec<Node>),
    /// The text, and whether it was quoted (a quoted scalar is always a string).
    Scalar(String, bool),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub kind: Kind,
    /// 1-based.
    pub line: usize,
}

/// A YAML syntax problem, with its line.
#[derive(Debug, Clone, PartialEq)]
pub struct SyntaxError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

struct Builder {
    stack: Vec<(Node, Option<Node>)>,
    root: Option<Node>,
    documents: usize,
    nodes: usize,
    error: Option<SyntaxError>,
}

impl Builder {
    fn fail(&mut self, line: usize, message: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(SyntaxError {
                line,
                message: message.into(),
            });
        }
    }

    fn push_value(&mut self, node: Node) {
        match self.stack.last_mut() {
            None => self.root = Some(node),
            Some((parent, pending_key)) => match &mut parent.kind {
                Kind::Seq(items) => items.push(node),
                Kind::Map(entries) => match pending_key.take() {
                    None => *pending_key = Some(node),
                    Some(key) => entries.push((key, node)),
                },
                Kind::Scalar(..) => unreachable!("scalars have no children"),
            },
        }
    }
}

impl MarkedEventReceiver for Builder {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        if self.error.is_some() {
            return;
        }
        let line = mark.line().max(1);
        let anchored = |anchor: usize| anchor != 0;
        let is_seq = matches!(ev, Event::SequenceStart(..));
        match ev {
            Event::DocumentStart => {
                self.documents += 1;
                if self.documents > 1 {
                    self.fail(
                        line,
                        "only one YAML document is allowed (remove the extra `---`)",
                    );
                }
            }
            Event::Alias(_) => self.fail(line, "anchors and aliases (`&`, `*`) aren't supported"),
            Event::Scalar(text, style, anchor, tag) => {
                if anchored(anchor) {
                    return self.fail(line, "anchors and aliases (`&`, `*`) aren't supported");
                }
                if tag.is_some() {
                    return self.fail(line, "YAML tags (`!…`) aren't supported");
                }
                self.nodes += 1;
                let quoted = !matches!(style, TScalarStyle::Plain);
                self.push_value(Node {
                    kind: Kind::Scalar(text, quoted),
                    line,
                });
            }
            Event::SequenceStart(anchor, tag) | Event::MappingStart(anchor, tag) => {
                if anchored(anchor) {
                    return self.fail(line, "anchors and aliases (`&`, `*`) aren't supported");
                }
                if tag.is_some() {
                    return self.fail(line, "YAML tags (`!…`) aren't supported");
                }
                self.nodes += 1;
                if self.stack.len() >= MAX_DEPTH {
                    return self.fail(line, "the file is nested too deeply");
                }
                let kind = if is_seq {
                    Kind::Seq(Vec::new())
                } else {
                    Kind::Map(Vec::new())
                };
                self.stack.push((Node { kind, line }, None));
            }
            Event::SequenceEnd | Event::MappingEnd => {
                if let Some((node, _)) = self.stack.pop() {
                    self.push_value(node);
                }
            }
            _ => {}
        }
        if self.nodes > MAX_NODES {
            self.fail(line, "the file is too large");
        }
    }
}

/// Parse one YAML document. An empty document is `None`.
pub fn parse(text: &str) -> Result<Option<Node>, SyntaxError> {
    let mut b = Builder {
        stack: Vec::new(),
        root: None,
        documents: 0,
        nodes: 0,
        error: None,
    };
    let mut parser = Parser::new_from_str(text);
    if let Err(e) = parser.load(&mut b, true) {
        return Err(SyntaxError {
            line: e.marker().line().max(1),
            message: format!("this isn't valid YAML: {}", e.info()),
        });
    }
    if let Some(e) = b.error {
        return Err(e);
    }
    Ok(b.root)
}

impl Node {
    pub fn as_str(&self) -> Option<&str> {
        match &self.kind {
            Kind::Scalar(s, _) => Some(s),
            _ => None,
        }
    }

    /// A plain scalar `null`, `~` or empty.
    pub fn is_null(&self) -> bool {
        matches!(&self.kind, Kind::Scalar(s, false) if s.is_empty() || s == "~" || s == "null")
    }

    pub fn describe(&self) -> &'static str {
        match &self.kind {
            Kind::Map(_) => "a mapping",
            Kind::Seq(_) => "a list",
            Kind::Scalar(..) => "a single value",
        }
    }

    /// The value as JSON: plain scalars are typed (`true`, `12`, `1.5`, `null`), quoted ones are
    /// strings, and mapping keys are strings.
    pub fn to_json(&self) -> Value {
        match &self.kind {
            Kind::Scalar(s, true) => Value::String(s.clone()),
            Kind::Scalar(s, false) => plain_scalar(s),
            Kind::Seq(items) => Value::Array(items.iter().map(Node::to_json).collect()),
            Kind::Map(entries) => {
                let mut m = Map::new();
                for (k, v) in entries {
                    m.insert(k.as_str().unwrap_or_default().to_string(), v.to_json());
                }
                Value::Object(m)
            }
        }
    }
}

fn plain_scalar(s: &str) -> Value {
    match s {
        "" | "~" | "null" | "Null" | "NULL" => Value::Null,
        "true" | "True" | "TRUE" => Value::Bool(true),
        "false" | "False" | "FALSE" => Value::Bool(false),
        _ => {
            if let Ok(i) = s.parse::<i64>() {
                return Value::Number(i.into());
            }
            if s.chars().any(|c| c.is_ascii_digit())
                && s.chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '+' | 'e' | 'E'))
                && let Ok(f) = s.parse::<f64>()
                && let Some(n) = Number::from_f64(f)
            {
                return Value::Number(n);
            }
            Value::String(s.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_lines_and_types() {
        let doc = parse("a: 1\nb:\n  - \"2\"\n  - x\nc: true\n")
            .unwrap()
            .unwrap();
        let Kind::Map(entries) = &doc.kind else {
            panic!()
        };
        assert_eq!(entries[0].0.as_str(), Some("a"));
        assert_eq!(entries[0].0.line, 1);
        assert_eq!(entries[1].1.line, 3, "the list starts on line 3");
        let Kind::Seq(items) = &entries[1].1.kind else {
            panic!()
        };
        assert_eq!(items[1].line, 4);
        assert_eq!(
            doc.to_json(),
            serde_json::json!({"a": 1, "b": ["2", "x"], "c": true})
        );
    }

    #[test]
    fn refuses_aliases_tags_and_several_documents() {
        let e = parse("a: &x [1]\nb: *x\n").unwrap_err();
        assert!(e.message.contains("aliases"), "{e}");
        let e = parse("a: !!str 1\n").unwrap_err();
        assert!(e.message.contains("tags"), "{e}");
        let e = parse("a: 1\n---\nb: 2\n").unwrap_err();
        assert!(e.message.contains("one YAML document"), "{e}");
        assert_eq!(e.line, 2);
    }

    #[test]
    fn syntax_errors_name_the_line() {
        let e = parse("a: 1\nb: [1, 2\nc: 3\n").unwrap_err();
        assert!(e.line >= 2, "{e}");
        assert!(e.message.contains("valid YAML"));
        assert_eq!(parse("").unwrap(), None);
    }
}
