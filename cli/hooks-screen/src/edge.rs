//! What of the screen can go to the relay (PROTOCOL §4b), for one hook: the rules marked `edge`,
//! with field values turned into keyed hashes.
//!
//! - Origin, header and size conditions go as they are; so do fingerprints (a shape hash and a
//!   MinHash signature, which say almost nothing about the text).
//! - `is`, `domain is` and `one of` go as keyed hashes under the account's screen key
//!   ([`crate::fields::keyed_hash`]): the relay hashes what arrives and compares, and never holds the
//!   value.
//! - `contains`, `pattern` and `similar text` need the relay to read the words: they go only when
//!   the person agreed (`words`), and the payload says so (`consent.words`). A pattern must also be
//!   in the subset the relay's linear-time matcher takes ([`crate::fields::edge_pattern_weight`]),
//!   and the different patterns of one hook weigh at most [`crate::fields::EDGE_MAX_SCREEN_WEIGHT`]
//!   together.
//! - Whether the sender is known is the harness's alone: a rule using it stays home.

use serde_json::{Value, json};

use std::collections::BTreeMap;

use crate::fields::{self, EDGE_MAX_SCREEN_WEIGHT, domain_of, fold, keyed_hash};
use crate::rules::{Condition, FieldOp, Rule};
use crate::{SourceKind, now_ms};

/// The most rules the relay takes for one hook.
pub const MAX_EDGE_RULES: usize = 200;

/// The edge screen for one hook, and why each rule that stayed home stayed.
pub struct Export {
    /// `{"rules": [...], "consent": {"words": bool}}`, the body of `PUT /v1/hooks/<id>/screen`.
    pub screen: Value,
    pub skipped: Vec<(String, String)>,
}

fn condition(c: &Condition, key: &[u8], words: bool) -> Result<Value, String> {
    Ok(match c {
        Condition::Known { .. } => {
            return Err("whether a sender is known is only known on this machine".into());
        }
        Condition::Field {
            path,
            op,
            value,
            values,
            signature,
            threshold,
            not,
        } => {
            if op.needs_words() && !words {
                return Err(format!(
                    "\"{}\" needs the relay to read the words; allow that in the screen's settings first",
                    op.label()
                ));
            }
            let mut v = json!({"on": "field", "path": path, "op": op});
            if *not {
                v["not"] = json!(true);
            }
            match op {
                FieldOp::Is => {
                    v["hashes"] =
                        json!([keyed_hash(key, path, &fold(value.as_deref().unwrap_or("")))])
                }
                FieldOp::DomainIs => {
                    v["hashes"] = json!([keyed_hash(
                        key,
                        path,
                        &domain_of(value.as_deref().unwrap_or(""))
                    )])
                }
                FieldOp::OneOf => {
                    v["hashes"] = json!(
                        values
                            .iter()
                            .map(|x| keyed_hash(key, path, &fold(x)))
                            .collect::<Vec<_>>()
                    )
                }
                FieldOp::Contains => v["words"] = json!(value),
                FieldOp::Pattern => {
                    let p = value.as_deref().unwrap_or("");
                    fields::edge_safe_pattern(p)?;
                    v["pattern"] = json!(p);
                }
                FieldOp::SimilarText => {
                    v["signature"] = json!(signature);
                    if let Some(t) = threshold {
                        v["threshold"] = json!(t);
                    }
                }
            }
            v
        }
        other => serde_json::to_value(other).map_err(|e| e.to_string())?,
    })
}

/// The rules for hook `hook_id` that can go to the relay.
pub fn export(rules: &[Rule], hook_id: &str, key: &[u8], words: bool, expiry_days: u32) -> Export {
    let now = now_ms();
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    let mut needs_words = false;
    // The different patterns sent so far, and what they weigh together.
    let mut patterns: BTreeMap<String, u32> = BTreeMap::new();
    for r in rules {
        if !r.edge
            || !r.enabled
            || r.expired(now, expiry_days)
            || !r.applies_to(SourceKind::Webhook.as_str(), hook_id)
        {
            continue;
        }
        if out.len() >= MAX_EDGE_RULES {
            skipped.push((
                r.name.clone(),
                format!("the relay takes at most {MAX_EDGE_RULES} rules a hook"),
            ));
            continue;
        }
        match r
            .conditions
            .iter()
            .map(|c| condition(c, key, words))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(conds) => {
                let mut more = patterns.clone();
                for c in &r.conditions {
                    if let Condition::Field {
                        op: FieldOp::Pattern,
                        value: Some(p),
                        ..
                    } = c
                        && let Ok(w) = fields::edge_pattern_weight(p)
                    {
                        more.insert(p.clone(), w);
                    }
                }
                if more.values().sum::<u32>() > EDGE_MAX_SCREEN_WEIGHT {
                    skipped.push((
                        r.name.clone(),
                        format!(
                            "the relay takes patterns weighing at most {EDGE_MAX_SCREEN_WEIGHT} a hook together"
                        ),
                    ));
                    continue;
                }
                patterns = more;
                needs_words |= r.needs_words();
                let mut v = json!({"id": r.id, "verdict": r.verdict, "conditions": conds});
                if r.any {
                    v["any"] = json!(true);
                }
                out.push(v);
            }
            Err(e) => skipped.push((r.name.clone(), e)),
        }
    }
    Export {
        screen: json!({"rules": out, "consent": {"words": needs_words}}),
        skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(id: &str, conditions: Value) -> Rule {
        serde_json::from_value(json!({
            "id": id, "name": id, "verdict": "drop", "conditions": conditions, "edge": true
        }))
        .unwrap()
    }

    #[test]
    fn patterns_go_within_the_subset_and_the_screens_weight() {
        let key = [7u8; 32];
        let pattern = |id: &str, p: &str| {
            rule(
                id,
                json!([{"on": "field", "path": "payload.t", "op": "pattern", "value": p}]),
            )
        };
        let mut rules: Vec<Rule> = (0..20)
            .map(|i| pattern(&format!("p{i}"), &format!(r"\w{{200}}{i}")))
            .collect();
        // The same pattern again costs nothing more.
        rules.push(pattern("again", r"\w{200}0"));
        rules.push(pattern("backref", r"(\w)\1"));
        let out = export(&rules, "hk_x", &key, true, 90);
        let sent: Vec<&str> = out.screen["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert_eq!(sent.len(), 20);
        assert!(sent.contains(&"again") && !sent.contains(&"p19"));
        let skipped: Vec<&str> = out.skipped.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(skipped, ["p19", "backref"]);
    }
}
