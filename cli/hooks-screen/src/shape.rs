//! A payload's shape hash (PLAN §5.0, §6a): its field paths and their types, never its values. The
//! same walk as the runner's event catalogue (`payload.a.b`, `payload.list[].x`; at most 2,000
//! fields, 32 levels and 50 items of each list), each path written `path:type|type`, the lines
//! sorted and joined with `\n`, then SHA-256 in hex. The relay computes the same
//! (`relay/src/screen.ts`).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAX_FIELDS: usize = 2000;
const MAX_DEPTH: usize = 32;
const MAX_ITEMS: usize = 50;

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Every field path of a payload with the types seen there.
pub fn fields(payload: &Value) -> BTreeMap<String, BTreeSet<&'static str>> {
    let mut out = BTreeMap::new();
    visit(payload, "payload".to_string(), 0, &mut out);
    out
}

fn visit(
    v: &Value,
    path: String,
    depth: usize,
    out: &mut BTreeMap<String, BTreeSet<&'static str>>,
) {
    if path != "payload" {
        if !out.contains_key(&path) && out.len() >= MAX_FIELDS {
            return;
        }
        out.entry(path.clone()).or_default().insert(type_name(v));
    }
    if depth >= MAX_DEPTH {
        return;
    }
    match v {
        Value::Object(m) => {
            // Code-point order, whatever order the map keeps, so the 2,000-field cut is the same
            // everywhere.
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for k in keys {
                visit(&m[k], format!("{path}.{k}"), depth + 1, out);
            }
        }
        Value::Array(items) => {
            for item in items.iter().take(MAX_ITEMS) {
                visit(item, format!("{path}[]"), depth + 1, out);
            }
        }
        _ => {}
    }
}

/// The hex SHA-256 of the payload's shape.
pub fn shape_hash(payload: &Value) -> String {
    let mut lines: Vec<String> = fields(payload)
        .into_iter()
        .map(|(p, t)| format!("{p}:{}", t.into_iter().collect::<Vec<_>>().join("|")))
        .collect();
    lines.sort();
    let digest = Sha256::digest(lines.join("\n").as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn same_fields_same_hash_whatever_the_values() {
        let a = shape_hash(&json!({"a": 1, "b": "x", "c": [{"d": true}]}));
        let b = shape_hash(&json!({"c": [{"d": false}], "b": "y", "a": 2}));
        let c = shape_hash(&json!({"a": 1, "b": "x", "c": [{"d": "true"}]}));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
        // Mixed types in a list are both recorded.
        let f = fields(&json!({"l": [1, "x"]}));
        assert_eq!(
            f["payload.l[]"].iter().copied().collect::<Vec<_>>(),
            ["number", "string"]
        );
    }
}
