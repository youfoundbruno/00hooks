//! The content-hash dedupe (PROTOCOL §3): the runner's own memory of what content it has already
//! taken, for the presets whose provider signs no timestamp.
//!
//! For those presets a captured genuine delivery verifies forever. The relay refuses one whose body
//! it has seen in the last `REPLAY_MARK_DAYS` (180 days by default); past that it accepts the
//! replay as a new event with a new `evt_` id, which the runner's dedupe by event id can't catch.
//! So the runner keeps its own marks: SHA-256 of the hook id and the body bytes (never the headers:
//! a replay's delivery id differs), with the id and arrival time of the event that first carried
//! them, so the person is told which event it repeats.
//!
//! Only hashes are kept (`content-marks.jsonl`, 0600, in the runner's folder), each fsynced
//! **before** the run's start record: a crash between the two leaves a mark naming this very event,
//! so when the relay hands it over again it still runs (the mark names it), while a copy under
//! another id is refused. Bounded: at most [`KEEP_MARKS`] marks, the oldest dropped first, and none
//! older than [`KEEP_DAYS`].

use std::collections::{HashMap, VecDeque};
use std::path::Path;

use hooks_client::Event;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Result;
use crate::jsonl::Jsonl;

/// The presets whose relay replay marks rest on the body's hash because the provider signs no
/// timestamp (PROTOCOL §3, "replay marks"). Keep this list in step with that table: a preset added
/// there that signs no timestamp belongs here too. Never `token` or `unverified` (the relay doesn't
/// dedupe them, and identical bodies are legitimate there), nor a preset that signs a timestamp
/// (the timestamp already refuses old replays, and identical bodies can be legitimate).
pub const BODY_HASH_PRESETS: &[&str] = &["github", "shopify", "twilio", "meta", "hmac"];

/// The most marks kept; the oldest go first.
pub const KEEP_MARKS: usize = 100_000;
/// How long a mark is kept, in days: well past the relay's `REPLAY_MARK_DAYS` default (180), since
/// the runner's marks matter exactly once the relay's have expired.
pub const KEEP_DAYS: i64 = 400;

const DAY_MS: i64 = 86_400_000;

/// Whether an event's content is deduped: verified (by the relay, or by this device for a strict
/// hook) and of a preset that signs no timestamp.
pub fn applies(e: &Event) -> bool {
    e.verified && BODY_HASH_PRESETS.contains(&e.preset.as_str())
}

/// The content's hash: SHA-256 over a label, the hook id and the body bytes.
pub fn content_hash(e: &Event) -> String {
    let body = e
        .body_bytes()
        .unwrap_or_else(|_| e.body.as_bytes().to_vec());
    let mut h = Sha256::new();
    h.update(b"00hooks-content-v1\0");
    h.update(e.hook_id.as_bytes());
    h.update(b"\0");
    h.update(&body);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// One mark.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mark {
    /// The content's hash.
    pub h: String,
    /// The event that first carried it.
    pub e: String,
    /// When that event reached the relay.
    pub r: i64,
    /// When the mark was written (its age counts from here).
    pub at: i64,
}

#[derive(Debug)]
pub struct ContentMarks {
    file: Jsonl,
    by_hash: HashMap<String, Mark>,
    /// Hashes, oldest first.
    order: VecDeque<String>,
    /// Lines in the file (compacted when it holds twice what is kept).
    lines: usize,
    keep: usize,
    keep_ms: i64,
}

impl ContentMarks {
    pub fn open(dir: &Path) -> Result<ContentMarks> {
        Self::open_with(dir, KEEP_MARKS, KEEP_DAYS * DAY_MS, crate::now_ms())
    }

    /// With other bounds (tests).
    pub fn open_with(dir: &Path, keep: usize, keep_ms: i64, now: i64) -> Result<ContentMarks> {
        let (file, marks, rec) = Jsonl::open::<Mark>(dir.join("content-marks.jsonl"))?;
        let read = marks.len();
        let mut m = ContentMarks {
            file,
            by_hash: HashMap::new(),
            order: VecDeque::new(),
            lines: read,
            keep,
            keep_ms,
        };
        for mark in marks {
            if now - mark.at < keep_ms && !m.by_hash.contains_key(&mark.h) {
                m.order.push_back(mark.h.clone());
                m.by_hash.insert(mark.h.clone(), mark);
            }
        }
        m.evict();
        if m.order.len() != read || rec.damaged > 0 {
            m.compact()?;
        }
        Ok(m)
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// The mark for this content, if it is kept and not too old.
    pub fn get(&self, hash: &str, now: i64) -> Option<&Mark> {
        self.by_hash.get(hash).filter(|m| now - m.at < self.keep_ms)
    }

    /// Record that `e` carried this content, durably (fsynced before it returns).
    pub fn record(&mut self, hash: &str, e: &Event, now: i64) -> Result<()> {
        let mark = Mark {
            h: hash.to_string(),
            e: e.id.clone(),
            r: e.received_at,
            at: now,
        };
        self.file.append(&mark)?;
        self.lines += 1;
        if self.by_hash.insert(hash.to_string(), mark).is_some() {
            // An expired mark written again: it moves to the newest end.
            self.order.retain(|h| h != hash);
        }
        self.order.push_back(hash.to_string());
        self.evict();
        if self.lines > self.keep.saturating_mul(2).max(16) {
            self.compact()?;
        }
        Ok(())
    }

    fn evict(&mut self) {
        while self.order.len() > self.keep {
            if let Some(h) = self.order.pop_front() {
                self.by_hash.remove(&h);
            }
        }
    }

    fn compact(&mut self) -> Result<()> {
        let keep: Vec<&Mark> = self.order.iter().map(|h| &self.by_hash[h]).collect();
        self.lines = keep.len();
        self.file.compact(keep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::test_event;
    use crate::testutil::temp_dir;
    use serde_json::json;

    #[test]
    fn the_hash_covers_the_hook_and_the_body_not_the_headers() {
        let a = test_event(1, Some("push"), &json!({"a": 1}));
        let mut b = test_event(2, Some("push"), &json!({"a": 1}));
        b.headers.insert("x-github-delivery".into(), "other".into());
        assert_eq!(content_hash(&a), content_hash(&b));
        let mut c = b.clone();
        c.hook_id = "hk_2".into();
        assert_ne!(content_hash(&a), content_hash(&c));
        let d = test_event(3, Some("push"), &json!({"a": 2}));
        assert_ne!(content_hash(&a), content_hash(&d));
        assert_eq!(content_hash(&a).len(), 64);
    }

    #[test]
    fn only_verified_events_of_untimestamped_presets() {
        let mut e = test_event(1, Some("push"), &json!({}));
        for p in ["github", "shopify", "twilio", "meta", "hmac"] {
            e.preset = p.into();
            assert!(applies(&e), "{p}");
        }
        for p in [
            "unverified",
            "token",
            "stripe",
            "slack",
            "linear",
            "standard-webhooks",
            "standard-webhooks-ed25519",
        ] {
            e.preset = p.into();
            assert!(!applies(&e), "{p}");
        }
        e.preset = "github".into();
        e.verified = false;
        assert!(!applies(&e), "an unverified event proves nothing");
    }

    #[test]
    fn marks_survive_a_restart_and_are_private() {
        let dir = temp_dir("marks");
        let e = test_event(1, Some("push"), &json!({"a": 1}));
        let h = content_hash(&e);
        {
            let mut m = ContentMarks::open(&dir).unwrap();
            assert!(m.get(&h, 10).is_none());
            m.record(&h, &e, 10).unwrap();
        }
        let m = ContentMarks::open_with(&dir, KEEP_MARKS, KEEP_DAYS * DAY_MS, 20).unwrap();
        let mark = m.get(&h, 20).unwrap();
        assert_eq!((mark.e.as_str(), mark.r), ("evt_1", e.received_at));
        let text = std::fs::read_to_string(dir.join("content-marks.jsonl")).unwrap();
        assert!(!text.contains("\"a\""), "hashes only: {text}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("content-marks.jsonl"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn marks_are_bounded_by_count_and_age() {
        let dir = temp_dir("marks-bounds");
        let events: Vec<Event> = (0..40)
            .map(|i| test_event(i, Some("push"), &json!({ "n": i })))
            .collect();
        let hashes: Vec<String> = events.iter().map(content_hash).collect();
        {
            let mut m = ContentMarks::open_with(&dir, 10, 1000, 0).unwrap();
            for (i, e) in events.iter().enumerate() {
                m.record(&hashes[i], e, i as i64).unwrap();
            }
            assert_eq!(m.len(), 10, "the oldest go first");
            assert!(m.get(&hashes[29], 40).is_none());
            assert!(m.get(&hashes[30], 40).is_some());
            // Too old to count, even while still in memory.
            assert!(m.get(&hashes[30], 2000).is_none());
        }
        let lines = std::fs::read_to_string(dir.join("content-marks.jsonl"))
            .unwrap()
            .lines()
            .count();
        assert!(lines <= 20, "the file is compacted: {lines}");
        // Reopened later: the old marks are gone from the file too.
        let m = ContentMarks::open_with(&dir, 10, 1000, 1034).unwrap();
        assert_eq!(m.len(), 5, "only marks younger than the age bound");
        assert!(m.get(&hashes[39], 1034).is_some());
        drop(m);
        let lines = std::fs::read_to_string(dir.join("content-marks.jsonl"))
            .unwrap()
            .lines()
            .count();
        assert_eq!(lines, 5);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
