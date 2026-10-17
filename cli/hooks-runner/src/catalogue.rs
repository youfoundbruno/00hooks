//! The event catalogue (PLAN §5.0): for each kind of event seen (a hook plus the provider's event
//! type, or the payload's shape hash when there is none), its field tree with types and presence
//! counts, one sample (the first), up to 20 values of short repeating fields, first and last seen,
//! and a count. It notices new kinds and shape changes.
//!
//! Kept on this machine only, one private file per kind in `<runner>/catalogue/`. Samples and seen
//! values are content: they can be cleared per kind or all at once, and a hook can be set to keep
//! structure only (no sample, no values).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Values longer than this aren't kept as "values seen".
pub const SHORT_VALUE: usize = 64;
/// The most distinct values kept per field; a field with more is "varied" and keeps none.
pub const MAX_VALUES: usize = 20;
/// The most fields recorded per kind.
pub const MAX_FIELDS: usize = 2000;
/// How deep the walk goes.
const MAX_DEPTH: usize = 32;
/// How many items of each list are looked at.
const MAX_ITEMS: usize = 50;
/// Shape changes remembered per kind.
const MAX_CHANGES: usize = 20;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldInfo {
    /// `string`, `number`, `boolean`, `null`, `object`, `array`.
    pub types: BTreeSet<String>,
    /// In how many events it was present.
    pub present: u64,
    /// Distinct short values seen, at most [`MAX_VALUES`]; empty when varied or structure-only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<Value>,
    /// More than [`MAX_VALUES`] distinct values: not a short repeating field.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub varied: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShapeChange {
    pub at: i64,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KindRecord {
    pub hook_id: String,
    pub kind: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub count: u64,
    /// Payload fields by path (`payload.pull_request.additions`, `payload.labels[].name`).
    pub fields: BTreeMap<String, FieldInfo>,
    /// Header names and how often each was present.
    #[serde(default)]
    pub headers: BTreeMap<String, u64>,
    /// The first event's payload and headers, unless structure-only or cleared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample: Option<Sample>,
    /// The latest shape's hash.
    pub shape: String,
    #[serde(default)]
    pub changes: Vec<ShapeChange>,
    /// More than [`MAX_FIELDS`] fields: the rest weren't recorded.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sample {
    pub event_id: String,
    pub payload: Value,
    pub headers: BTreeMap<String, String>,
}

impl KindRecord {
    /// `<hook id>/<kind>`.
    pub fn key(&self) -> String {
        key(&self.hook_id, &self.kind)
    }

    pub fn has_field(&self, field_key: &str) -> bool {
        if let Some(h) = field_key.strip_prefix("headers.") {
            return self.headers.contains_key(h);
        }
        self.fields.contains_key(field_key)
    }

    /// The sample's value at a catalogue path (the first array item stands for `[]`).
    pub fn sample_value(&self, field_key: &str) -> Option<&Value> {
        let sample = self.sample.as_ref()?;
        let rest = field_key.strip_prefix("payload")?;
        let mut cur = &sample.payload;
        for part in split_key(rest) {
            cur = match (part, cur) {
                ("[]", Value::Array(a)) => a.first()?,
                (k, Value::Object(m)) => m.get(k)?,
                _ => return None,
            };
        }
        Some(cur)
    }
}

/// `.a.b[].c` → `a`, `b`, `[]`, `c`.
fn split_key(rest: &str) -> Vec<&str> {
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

pub fn key(hook_id: &str, kind: &str) -> String {
    format!("{hook_id}/{kind}")
}

/// What one event's payload looks like.
#[derive(Debug, Default)]
pub struct Walk {
    pub fields: BTreeMap<String, FieldInfo>,
    /// Lists that were empty, and fields that were `null`: what's under them is unknown, not gone.
    pub hollow: HashSet<String>,
    pub truncated: bool,
}

/// Walk a payload into catalogue paths, each with its type(s) and short values.
pub fn walk(payload: &Value) -> Walk {
    let mut w = Walk::default();
    visit(payload, "payload".to_string(), 0, &mut w);
    w
}

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

fn visit(v: &Value, path: String, depth: usize, w: &mut Walk) {
    if path != "payload" {
        if !w.fields.contains_key(&path) && w.fields.len() >= MAX_FIELDS {
            w.truncated = true;
            return;
        }
        let f = w.fields.entry(path.clone()).or_default();
        f.types.insert(type_name(v).to_string());
        f.present = 1;
        let short = match v {
            Value::String(s) => s.chars().count() <= SHORT_VALUE,
            Value::Number(_) | Value::Bool(_) => true,
            _ => false,
        };
        if short && !f.values.contains(v) {
            f.values.push(v.clone());
        }
    }
    if depth >= MAX_DEPTH {
        return;
    }
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                visit(child, format!("{path}.{k}"), depth + 1, w);
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                w.hollow.insert(path.clone());
            }
            for item in items.iter().take(MAX_ITEMS) {
                visit(item, format!("{path}[]"), depth + 1, w);
            }
        }
        Value::Null => {
            w.hollow.insert(path);
        }
        _ => {}
    }
}

/// The nearest enclosing path: `payload.a.b` → `payload.a`, `payload.a[]` → `payload.a`.
fn parent(p: &str) -> Option<&str> {
    if let Some(s) = p.strip_suffix("[]") {
        return Some(s);
    }
    let dot = p.rfind('.')?;
    let br = p.rfind("[]").map(|i| i + 2).unwrap_or(0);
    Some(&p[..dot.max(br)])
}

/// Drop paths whose parent is in the same list, so a lost object shows once, not once per field.
fn topmost(mut paths: Vec<String>) -> Vec<String> {
    let set: HashSet<String> = paths.iter().cloned().collect();
    paths.retain(|p| {
        let mut cur = p.as_str();
        while let Some(par) = parent(cur) {
            if set.contains(par) {
                return false;
            }
            cur = par;
        }
        true
    });
    paths
}

/// What observing one event found.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub key: String,
    pub new_kind: bool,
    pub change: Option<ShapeChange>,
}

/// The catalogue: every kind seen, loaded from and saved to its directory.
#[derive(Debug)]
pub struct Catalogue {
    dir: PathBuf,
    kinds: BTreeMap<String, KindRecord>,
}

fn file_name(key: &str) -> String {
    let d = Sha256::digest(key.as_bytes());
    let hex: String = d.iter().take(10).map(|b| format!("{b:02x}")).collect();
    format!("{hex}.json")
}

impl Catalogue {
    /// Open (creating, 0700) the catalogue in `dir`. Files that can't be read are skipped.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Catalogue> {
        let dir = dir.into();
        hooks_client::fsutil::create_private_dir(&dir).map_err(Error::from_client)?;
        let mut kinds = BTreeMap::new();
        for entry in std::fs::read_dir(&dir)?.flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|e| e == "json")
                && let Ok(bytes) = std::fs::read(&p)
                && let Ok(k) = serde_json::from_slice::<KindRecord>(&bytes)
            {
                kinds.insert(k.key(), k);
            }
        }
        Ok(Catalogue { dir, kinds })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn kinds(&self) -> impl Iterator<Item = &KindRecord> {
        self.kinds.values()
    }

    pub fn get(&self, hook_id: &str, kind: &str) -> Option<&KindRecord> {
        self.kinds.get(&key(hook_id, kind))
    }

    pub fn by_key(&self, key: &str) -> Option<&KindRecord> {
        self.kinds.get(key)
    }

    /// Re-read one kind from its file (gone when the file is).
    fn refresh(&mut self, key: &str) {
        let path = self.dir.join(file_name(key));
        match std::fs::read(&path) {
            Ok(bytes) => {
                if let Ok(k) = serde_json::from_slice::<KindRecord>(&bytes)
                    && k.key() == key
                {
                    self.kinds.insert(key.to_string(), k);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.kinds.remove(key);
            }
            Err(_) => {}
        }
    }

    fn save(&self, k: &KindRecord) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(k).expect("json");
        hooks_client::fsutil::write_atomic(&self.dir.join(file_name(&k.key())), &bytes, true)
            .map_err(Error::from_client)
    }

    /// Record one event of `kind` on `hook_id`.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        hook_id: &str,
        kind: &str,
        event_id: &str,
        payload: &Value,
        headers: &BTreeMap<String, String>,
        at: i64,
        structure_only: bool,
    ) -> Result<Observation> {
        let key = key(hook_id, kind);
        // The file is the truth: `00hooks kinds clear` may have changed it while we ran.
        self.refresh(&key);
        let w = walk(payload);
        let shape = crate::context::shape_hash(payload);
        let sample = || Sample {
            event_id: event_id.to_string(),
            payload: payload.clone(),
            headers: headers.clone(),
        };
        let Some(rec) = self.kinds.get_mut(&key) else {
            let mut fields = w.fields;
            for f in fields.values_mut() {
                if structure_only {
                    f.values.clear();
                }
                if f.values.len() > MAX_VALUES {
                    f.values.clear();
                    f.varied = true;
                }
            }
            let rec = KindRecord {
                hook_id: hook_id.to_string(),
                kind: kind.to_string(),
                first_seen: at,
                last_seen: at,
                count: 1,
                fields,
                headers: headers.keys().map(|h| (h.clone(), 1)).collect(),
                sample: (!structure_only).then(sample),
                shape,
                changes: Vec::new(),
                truncated: w.truncated,
            };
            self.save(&rec)?;
            self.kinds.insert(key.clone(), rec);
            return Ok(Observation {
                key,
                new_kind: true,
                change: None,
            });
        };

        // Gained: paths never seen before. Lost: paths present in every event so far, missing now,
        // whose parent is still here as an object (under an empty list or a null, it's unknown).
        let added: Vec<String> = w
            .fields
            .keys()
            .filter(|p| !rec.fields.contains_key(*p))
            .cloned()
            .collect();
        let removed: Vec<String> = rec
            .fields
            .iter()
            .filter(|(p, f)| f.present >= rec.count && !w.fields.contains_key(*p))
            .filter(|(p, _)| {
                let mut cur = p.as_str();
                while let Some(par) = parent(cur) {
                    if w.hollow.contains(par) {
                        return false;
                    }
                    cur = par;
                }
                true
            })
            .map(|(p, _)| p.clone())
            .collect();
        let (added, removed) = (topmost(added), topmost(removed));
        let change = (!added.is_empty() || !removed.is_empty()).then_some(ShapeChange {
            at,
            added,
            removed,
        });
        if let Some(c) = &change {
            rec.changes.push(c.clone());
            if rec.changes.len() > MAX_CHANGES {
                rec.changes.remove(0);
            }
        }

        for (p, seen) in w.fields {
            if !rec.fields.contains_key(&p) && rec.fields.len() >= MAX_FIELDS {
                rec.truncated = true;
                continue;
            }
            let f = rec.fields.entry(p).or_default();
            f.types.extend(seen.types);
            f.present += 1;
            if structure_only || f.varied {
                f.values.clear();
                continue;
            }
            for v in seen.values {
                if !f.values.contains(&v) {
                    f.values.push(v);
                }
            }
            if f.values.len() > MAX_VALUES {
                f.values.clear();
                f.varied = true;
            }
        }
        for h in headers.keys() {
            *rec.headers.entry(h.clone()).or_default() += 1;
        }
        rec.count += 1;
        rec.last_seen = rec.last_seen.max(at);
        rec.shape = shape;
        rec.truncated |= w.truncated;
        if structure_only {
            rec.sample = None;
        } else if rec.sample.is_none() {
            rec.sample = Some(sample());
        }
        let rec = rec.clone();
        self.save(&rec)?;
        Ok(Observation {
            key,
            new_kind: false,
            change,
        })
    }

    /// Clear one kind's sample and values seen (its structure stays).
    pub fn clear_sample(&mut self, key: &str) -> Result<bool> {
        let Some(rec) = self.kinds.get_mut(key) else {
            return Ok(false);
        };
        rec.sample = None;
        for f in rec.fields.values_mut() {
            f.values.clear();
        }
        let rec = rec.clone();
        self.save(&rec)?;
        Ok(true)
    }

    /// Forget one kind entirely.
    pub fn forget(&mut self, key: &str) -> Result<bool> {
        if self.kinds.remove(key).is_none() {
            return Ok(false);
        }
        match std::fs::remove_file(self.dir.join(file_name(key))) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(true),
        }
    }

    /// Forget every kind.
    pub fn clear_all(&mut self) -> Result<usize> {
        let keys: Vec<String> = self.kinds.keys().cloned().collect();
        for k in &keys {
            self.forget(k)?;
        }
        Ok(keys.len())
    }

    /// Drop samples and values of every kind from these hooks (they were set to structure only).
    pub fn enforce_structure_only(&mut self, hook_ids: &HashSet<String>) -> Result<()> {
        let keys: Vec<String> = self
            .kinds
            .values()
            .filter(|k| {
                hook_ids.contains(&k.hook_id)
                    && (k.sample.is_some() || k.fields.values().any(|f| !f.values.is_empty()))
            })
            .map(KindRecord::key)
            .collect();
        for k in keys {
            self.clear_sample(&k)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use serde_json::json;

    fn obs(c: &mut Catalogue, kind: &str, id: &str, p: Value, so: bool) -> Observation {
        let headers = BTreeMap::from([("x-github-event".to_string(), kind.to_string())]);
        c.observe("hk_1", kind, id, &p, &headers, 1000, so).unwrap()
    }

    #[test]
    fn a_new_kind_keeps_its_tree_sample_and_values() {
        let dir = temp_dir("cat-new");
        let mut c = Catalogue::open(&dir).unwrap();
        let o = obs(
            &mut c,
            "issues",
            "evt_1",
            json!({"action": "opened", "issue": {"number": 7, "labels": [{"name": "bug"}]}}),
            false,
        );
        assert!(o.new_kind && o.change.is_none());
        let k = c.get("hk_1", "issues").unwrap();
        assert_eq!(k.count, 1);
        assert_eq!(
            k.fields["payload.issue.number"].types,
            BTreeSet::from(["number".to_string()])
        );
        assert_eq!(
            k.fields["payload.issue.labels"].types,
            BTreeSet::from(["array".to_string()])
        );
        assert_eq!(
            k.fields["payload.issue.labels[].name"].values,
            vec![json!("bug")]
        );
        assert_eq!(k.sample.as_ref().unwrap().event_id, "evt_1");
        assert_eq!(
            k.sample_value("payload.issue.labels[].name"),
            Some(&json!("bug"))
        );
        assert!(k.has_field("headers.x-github-event"));

        // The second event: counted, values gathered, the sample stays the first.
        let o = obs(
            &mut c,
            "issues",
            "evt_2",
            json!({"action": "closed", "issue": {"number": 8, "labels": []}}),
            false,
        );
        assert!(!o.new_kind);
        assert!(
            o.change.is_none(),
            "an empty list hides its items; that's no shape change: {o:?}"
        );
        let k = c.get("hk_1", "issues").unwrap();
        assert_eq!(k.count, 2);
        assert_eq!(
            k.fields["payload.action"].values,
            vec![json!("opened"), json!("closed")]
        );
        assert_eq!(k.fields["payload.issue.labels[].name"].present, 1);
        assert_eq!(k.sample.as_ref().unwrap().event_id, "evt_1");

        // It's all on disk.
        drop(c);
        let c = Catalogue::open(&dir).unwrap();
        assert_eq!(c.get("hk_1", "issues").unwrap().count, 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn varied_fields_keep_no_values() {
        let dir = temp_dir("cat-varied");
        let mut c = Catalogue::open(&dir).unwrap();
        for i in 0..25 {
            obs(
                &mut c,
                "k",
                &format!("evt_{i}"),
                json!({"id": i, "status": "ok", "long": "x".repeat(100)}),
                false,
            );
        }
        let k = c.get("hk_1", "k").unwrap();
        assert!(k.fields["payload.id"].varied && k.fields["payload.id"].values.is_empty());
        assert_eq!(k.fields["payload.status"].values, vec![json!("ok")]);
        assert!(
            k.fields["payload.long"].values.is_empty(),
            "long values aren't kept"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn shape_changes_are_noticed() {
        let dir = temp_dir("cat-shape");
        let mut c = Catalogue::open(&dir).unwrap();
        obs(
            &mut c,
            "pr",
            "e1",
            json!({"pr": {"title": "a", "auto_merge": {"by": "x", "at": 1}}}),
            false,
        );
        obs(
            &mut c,
            "pr",
            "e2",
            json!({"pr": {"title": "b", "auto_merge": {"by": "y", "at": 2}}}),
            false,
        );
        let o = obs(
            &mut c,
            "pr",
            "e3",
            json!({"pr": {"title": "c", "draft": false}}),
            false,
        );
        let ch = o.change.unwrap();
        assert_eq!(ch.added, vec!["payload.pr.draft"]);
        assert_eq!(
            ch.removed,
            vec!["payload.pr.auto_merge"],
            "the lost object shows once"
        );
        // A null where an object was isn't a loss of its fields.
        let o = obs(
            &mut c,
            "pr",
            "e4",
            json!({"pr": {"title": "d", "draft": null}}),
            false,
        );
        assert!(o.change.is_none(), "{o:?}");
        // A field present in only some events is optional; its absence is no change.
        let o = obs(&mut c, "pr", "e5", json!({"pr": {"title": "e"}}), false);
        assert!(o.change.is_none(), "{o:?}");
        assert_eq!(c.get("hk_1", "pr").unwrap().changes.len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn structure_only_keeps_no_content() {
        let dir = temp_dir("cat-structure");
        let mut c = Catalogue::open(&dir).unwrap();
        obs(
            &mut c,
            "k",
            "e1",
            json!({"email": "a@example.com", "plan": "pro"}),
            true,
        );
        obs(
            &mut c,
            "k",
            "e2",
            json!({"email": "b@example.com", "plan": "pro"}),
            true,
        );
        let k = c.get("hk_1", "k").unwrap();
        assert!(k.sample.is_none());
        assert!(k.fields.values().all(|f| f.values.is_empty()));
        assert_eq!(k.fields["payload.email"].present, 2);
        let raw: String = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
            .collect();
        assert!(
            !raw.contains("example.com") && !raw.contains("pro\""),
            "{raw}"
        );

        // Switching a hook to structure only purges what it had.
        obs(&mut c, "other", "e3", json!({"secret": "s3"}), false);
        assert!(c.get("hk_1", "other").unwrap().sample.is_some());
        c.enforce_structure_only(&HashSet::from(["hk_1".to_string()]))
            .unwrap();
        assert!(c.get("hk_1", "other").unwrap().sample.is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn clearing_per_kind_and_all() {
        let dir = temp_dir("cat-clear");
        let mut c = Catalogue::open(&dir).unwrap();
        obs(&mut c, "a", "e1", json!({"s": "v"}), false);
        obs(&mut c, "b", "e2", json!({"s": "v"}), false);
        assert!(c.clear_sample("hk_1/a").unwrap());
        let a = c.get("hk_1", "a").unwrap();
        assert!(a.sample.is_none() && a.fields["payload.s"].values.is_empty());
        assert!(a.fields.contains_key("payload.s"), "the structure stays");
        assert!(!c.clear_sample("hk_1/nope").unwrap());
        assert!(c.forget("hk_1/a").unwrap());
        assert!(c.get("hk_1", "a").is_none());
        assert_eq!(c.clear_all().unwrap(), 1);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn clearing_from_another_process_sticks() {
        let dir = temp_dir("cat-other");
        let mut running = Catalogue::open(&dir).unwrap();
        obs(&mut running, "a", "e1", json!({"s": "secret value"}), false);
        let mut cli = Catalogue::open(&dir).unwrap();
        cli.clear_sample("hk_1/a").unwrap();
        obs(&mut running, "a", "e2", json!({"s": "other"}), false);
        let k = Catalogue::open(&dir)
            .unwrap()
            .get("hk_1", "a")
            .unwrap()
            .clone();
        assert_eq!(k.count, 2);
        assert_eq!(
            k.sample.unwrap().event_id,
            "e2",
            "the cleared sample didn't come back"
        );
        assert_eq!(k.fields["payload.s"].values, vec![json!("other")]);
        cli.clear_all().unwrap();
        let o = obs(&mut running, "a", "e3", json!({"s": "x"}), false);
        assert!(o.new_kind, "a forgotten kind starts again");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn paths_split_and_nest() {
        assert_eq!(split_key(".a.b[].c"), vec!["a", "b", "[]", "c"]);
        assert_eq!(split_key(".m[][]"), vec!["m", "[]", "[]"]);
        assert_eq!(parent("payload.a[].b"), Some("payload.a[]"));
        assert_eq!(parent("payload.a[]"), Some("payload.a"));
        assert_eq!(parent("payload"), None);
        assert_eq!(
            topmost(vec![
                "payload.a".into(),
                "payload.a.b".into(),
                "payload.a[].c".into(),
                "payload.d".into()
            ]),
            vec!["payload.a", "payload.d"]
        );
    }
}
