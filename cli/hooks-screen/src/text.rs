//! An item's text, the way similarity sees it (PLAN §6a, "Similarity"): every string in the
//! payload, keys in code-point order, lower-cased, cut into words (runs of letters and digits), then
//! word 5-grams. The relay does exactly the same in `relay/src/screen.ts`; both are held to
//! `fixtures/screen.v1.json`.

use serde_json::Value;

/// The most words read from one item (or one field): the rest don't count.
pub const MAX_TOKENS: usize = 10_000;
/// Words per shingle.
pub const SHINGLE: usize = 5;
/// How deep the payload walk goes (the catalogue's limit).
pub const MAX_DEPTH: usize = 32;

/// Every string leaf of a payload, joined by spaces: objects in code-point order of their keys,
/// arrays in order, to [`MAX_DEPTH`]. Numbers, booleans and nulls aren't text.
pub fn item_text(payload: &Value) -> String {
    let mut parts = Vec::new();
    collect(payload, 0, &mut parts);
    parts.join(" ")
}

fn collect<'a>(v: &'a Value, depth: usize, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(items) if depth < MAX_DEPTH => {
            for i in items {
                collect(i, depth + 1, out);
            }
        }
        Value::Object(m) if depth < MAX_DEPTH => {
            let mut keys: Vec<&String> = m.keys().collect();
            // Code-point order (Rust's `str` order is byte order of UTF-8, which is the same).
            keys.sort();
            for k in keys {
                collect(&m[k], depth + 1, out);
            }
        }
        _ => {}
    }
}

/// Lower-cased words: maximal runs of alphanumeric characters (Unicode `Alphabetic` or a number),
/// at most [`MAX_TOKENS`].
pub fn tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_alphanumeric() {
            cur.push(c);
        } else if !cur.is_empty() {
            out.push(cur.to_lowercase());
            cur.clear();
            if out.len() >= MAX_TOKENS {
                return out;
            }
        }
    }
    if !cur.is_empty() && out.len() < MAX_TOKENS {
        out.push(cur.to_lowercase());
    }
    out
}

/// Word 5-grams, each its words joined by one space; fewer than five words make one shingle of all
/// of them; none make none.
pub fn shingles(tokens: &[String]) -> Vec<String> {
    if tokens.is_empty() {
        return Vec::new();
    }
    if tokens.len() < SHINGLE {
        return vec![tokens.join(" ")];
    }
    tokens.windows(SHINGLE).map(|w| w.join(" ")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn text_is_the_strings_in_key_order() {
        let v = json!({"b": "two", "a": ["one", 3, {"z": "four", "y": null}], "c": true});
        assert_eq!(item_text(&v), "one four two");
    }

    #[test]
    fn words_are_lowercased_runs_of_letters_and_digits() {
        assert_eq!(
            tokens("Free CRYPTO!! bit.ly/x9 — Ünïcode ΣΑΣ"),
            ["free", "crypto", "bit", "ly", "x9", "ünïcode", "σας"]
        );
        let s: Vec<String> = tokens("a b c d e f");
        assert_eq!(shingles(&s), ["a b c d e", "b c d e f"]);
        assert_eq!(shingles(&tokens("hi there")), ["hi there"]);
        assert!(shingles(&[]).is_empty());
    }
}
