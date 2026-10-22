//! Batches (`batch:` on an automation): matching events are held on disk, and the automation's
//! actions run once for all of them when the batch is cut.
//!
//! Everything is under the runner's folder, private like the rest of it (0700 folders, 0600 files):
//! - `batches/open.json`: the open batches, at most one per automation (written atomically);
//! - `batches/open/<id>.jsonl`: an open batch's events, one per line, each line fsynced as the event
//!   joins. A line is what a command gets for a single event today (`payload`, `headers`, `event`).
//! - `batches/done/<id>.jsonl` and `<id>.json`: a batch that was cut, and what it was, kept so
//!   `00hooks replay <id>` can run it again: the newest [`KEEP_DONE`], at most [`KEEP_DONE_BYTES`]
//!   in all, like the event archive keeps the newest events.
//!
//! A restart loses nothing: the open batches and their first-event times are read back, a line a
//! crash tore is cut off, and a batch already due runs at the runner's next tick. Cutting is ordered
//! so a batch runs at most once: the batch is marked as being cut, its run's start is recorded
//! (fsynced) under the batch's id, and only then is its file moved to `done`. A crash after the
//! start finds the run already begun and closes it as interrupted; a crash before it leaves the
//! batch open, to run at the next tick.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jsonl::{self, Jsonl};
use crate::{Error, Result};

/// How many cut batches are kept for replay.
pub const KEEP_DONE: usize = 200;
/// The most bytes the cut batches kept for replay take in all.
pub const KEEP_DONE_BYTES: u64 = 256 * 1024 * 1024;

/// Why a batch was cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// No new event came for `idle`.
    Idle,
    /// `max_wait` passed since its first event.
    MaxWait,
    /// It held `max_events`.
    MaxEvents,
    /// The next event would have taken it over the most a batch holds on disk.
    MaxBytes,
    /// `00hooks batches flush` (or a host's flush).
    Flush,
    /// Its automation no longer batches (`batch:` was removed): what it held runs now.
    Unbatched,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Idle => "idle",
            Reason::MaxWait => "max_wait",
            Reason::MaxEvents => "max_events",
            Reason::MaxBytes => "max_bytes",
            Reason::Flush => "flush",
            Reason::Unbatched => "unbatched",
        }
    }
}

/// An open batch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenBatch {
    pub id: String,
    pub automation: String,
    /// When its first event joined (Unix ms, the runner's clock): `max_wait` counts from here.
    pub first_at: i64,
    /// When its latest event joined: `idle` counts from here.
    pub last_at: i64,
    pub count: u32,
    /// Its file's size.
    pub bytes: u64,
    /// Events not held because it was full while its automation couldn't run (paused or over its
    /// rate limit). Each is in its own run record, and `00hooks replay` runs it.
    #[serde(default)]
    pub refused: u32,
    /// Being cut, for this reason: set just before its run's start is recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cutting: Option<Reason>,
}

/// A batch that was cut.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DoneBatch {
    pub id: String,
    pub automation: String,
    pub count: u32,
    pub first_at: i64,
    pub last_at: i64,
    pub reason: Reason,
    #[serde(default)]
    pub refused: u32,
    pub cut_at: i64,
}

/// Whether `s` is a batch id (`bat_` and 16 hex characters): only those name a file.
pub fn is_batch_id(s: &str) -> bool {
    s.strip_prefix("bat_")
        .is_some_and(|h| h.len() == 16 && h.chars().all(|c| c.is_ascii_hexdigit()))
}

fn batches_dir(runner_dir: &Path) -> PathBuf {
    runner_dir.join("batches")
}

fn index_path(runner_dir: &Path) -> PathBuf {
    batches_dir(runner_dir).join("open.json")
}

/// The open batches, without opening the store (for `00hooks batches` while the runner runs).
pub fn read_open(runner_dir: &Path) -> Result<Vec<OpenBatch>> {
    match std::fs::read(index_path(runner_dir)) {
        Ok(b) => {
            let map: BTreeMap<String, OpenBatch> = serde_json::from_slice(&b)
                .map_err(|e| Error::Store(format!("the open batches can't be read: {e}")))?;
            Ok(map.into_values().collect())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

/// A cut batch that is still kept, without opening the store.
pub fn read_done(runner_dir: &Path, id: &str) -> Result<Option<DoneBatch>> {
    if !is_batch_id(id) {
        return Ok(None);
    }
    let p = batches_dir(runner_dir)
        .join("done")
        .join(format!("{id}.json"));
    match std::fs::read(&p) {
        Ok(b) => Ok(serde_json::from_slice(&b).ok()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn open_append(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    opts.open(path)
}

/// The batches on disk.
#[derive(Debug)]
pub struct BatchStore {
    dir: PathBuf,
    open: BTreeMap<String, OpenBatch>,
}

impl BatchStore {
    /// Open (creating the folders privately), reading back the open batches: each one's count and
    /// size come from its file, with a line a crash tore cut off. A batch whose file is gone is
    /// forgotten.
    pub fn open(runner_dir: &Path) -> Result<BatchStore> {
        let dir = batches_dir(runner_dir);
        for d in [dir.clone(), dir.join("open"), dir.join("done")] {
            hooks_client::fsutil::create_private_dir(&d).map_err(Error::from_client)?;
        }
        let mut open: BTreeMap<String, OpenBatch> = BTreeMap::new();
        for mut b in read_open(runner_dir)? {
            if !is_batch_id(&b.id) {
                continue;
            }
            let path = dir.join("open").join(format!("{}.jsonl", b.id));
            if !path.exists() {
                // Moved to `done` by a cut a crash interrupted: the runner settles it.
                if b.cutting.is_some() {
                    open.insert(b.automation.clone(), b);
                }
                continue;
            }
            let (_, items, _) = Jsonl::open::<Value>(&path)?;
            b.count = items.len() as u32;
            b.bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            open.insert(b.automation.clone(), b);
        }
        let store = BatchStore { dir, open };
        store.save()?;
        Ok(store)
    }

    fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.open).expect("json");
        hooks_client::fsutil::write_atomic(&self.dir.join("open.json"), &bytes, true)
            .map_err(Error::from_client)
    }

    fn open_path(&self, id: &str) -> PathBuf {
        self.dir.join("open").join(format!("{id}.jsonl"))
    }

    /// Where a cut batch's events are kept (for `replay`, and for a host's agent).
    pub fn done_path(&self, id: &str) -> PathBuf {
        self.dir.join("done").join(format!("{id}.jsonl"))
    }

    pub fn get(&self, automation: &str) -> Option<&OpenBatch> {
        self.open.get(automation)
    }

    pub fn all(&self) -> impl Iterator<Item = &OpenBatch> {
        self.open.values()
    }

    /// Add one event (a JSON line, without its newline) to `automation`'s batch, opening one if
    /// it has none. The line is fsynced before this returns.
    pub fn hold(&mut self, automation: &str, line: &[u8], now: i64) -> Result<OpenBatch> {
        if !self.open.contains_key(automation) {
            let b = OpenBatch {
                id: format!("bat_{}", crate::random_hex()),
                automation: automation.to_string(),
                first_at: now,
                last_at: now,
                count: 0,
                bytes: 0,
                refused: 0,
                cutting: None,
            };
            self.open.insert(automation.to_string(), b);
            // On record before its file exists: a crash in between leaves an empty batch.
            self.save()?;
        }
        let id = self.open[automation].id.clone();
        let mut f = open_append(&self.open_path(&id))?;
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line);
        buf.push(b'\n');
        f.write_all(&buf)?;
        f.sync_data()?;
        let b = self.open.get_mut(automation).expect("present");
        b.count += 1;
        b.bytes += buf.len() as u64;
        b.last_at = now;
        let out = b.clone();
        self.save()?;
        Ok(out)
    }

    /// Count an event `automation`'s full batch couldn't take.
    pub fn refuse(&mut self, automation: &str) -> Result<()> {
        if let Some(b) = self.open.get_mut(automation) {
            b.refused += 1;
            self.save()?;
        }
        Ok(())
    }

    /// The events an open batch holds, oldest first.
    pub fn events(&self, automation: &str) -> Result<Vec<Value>> {
        let Some(b) = self.open.get(automation) else {
            return Ok(Vec::new());
        };
        let path = if self.open_path(&b.id).exists() {
            self.open_path(&b.id)
        } else {
            self.done_path(&b.id)
        };
        Ok(jsonl::read_all::<Value>(&path)?.0)
    }

    /// Mark a batch as being cut (saved), before its run's start is recorded.
    pub fn mark_cutting(&mut self, automation: &str, reason: Reason) -> Result<()> {
        if let Some(b) = self.open.get_mut(automation) {
            b.cutting = Some(reason);
            self.save()?;
        }
        Ok(())
    }

    /// Leave a batch open after all (its run's start couldn't be recorded).
    pub fn unmark_cutting(&mut self, automation: &str) -> Result<()> {
        if let Some(b) = self.open.get_mut(automation) {
            b.cutting = None;
            self.save()?;
        }
        Ok(())
    }

    /// Close a batch: its file moves to `done` with a note of what it was, and older cut batches
    /// beyond what's kept are removed.
    pub fn finish(&mut self, automation: &str, reason: Reason, now: i64) -> Result<DoneBatch> {
        let b = self
            .open
            .get(automation)
            .cloned()
            .ok_or_else(|| Error::Other(format!("{automation:?} has no open batch")))?;
        let from = self.open_path(&b.id);
        let to = self.done_path(&b.id);
        if from.exists() {
            std::fs::rename(&from, &to)?;
        } else if !to.exists() {
            // An empty batch (a crash between opening it and its first line).
            open_append(&to)?;
        }
        let done = DoneBatch {
            id: b.id.clone(),
            automation: b.automation.clone(),
            count: b.count,
            first_at: b.first_at,
            last_at: b.last_at,
            reason,
            refused: b.refused,
            cut_at: now,
        };
        let meta = serde_json::to_vec_pretty(&done).expect("json");
        hooks_client::fsutil::write_atomic(
            &self.dir.join("done").join(format!("{}.json", b.id)),
            &meta,
            true,
        )
        .map_err(Error::from_client)?;
        self.open.remove(automation);
        self.save()?;
        self.prune();
        Ok(done)
    }

    /// Throw an open batch away, with its events.
    pub fn discard(&mut self, automation: &str) -> Result<Option<OpenBatch>> {
        let Some(b) = self.open.remove(automation) else {
            return Ok(None);
        };
        let _ = std::fs::remove_file(self.open_path(&b.id));
        self.save()?;
        Ok(Some(b))
    }

    /// A cut batch that is still kept: what it was, and its events.
    pub fn done(&self, id: &str) -> Result<Option<(DoneBatch, Vec<Value>)>> {
        let Some(meta) = read_done(self.dir.parent().unwrap_or(Path::new(".")), id)? else {
            return Ok(None);
        };
        let path = self.done_path(id);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some((meta, jsonl::read_all::<Value>(&path)?.0)))
    }

    /// Keep the newest [`KEEP_DONE`] cut batches, at most [`KEEP_DONE_BYTES`] in all.
    fn prune(&self) {
        let Ok(entries) = std::fs::read_dir(self.dir.join("done")) else {
            return;
        };
        let mut done: Vec<(i64, String, u64)> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let id = name.strip_suffix(".json")?.to_string();
                if !is_batch_id(&id) {
                    return None;
                }
                let meta: DoneBatch =
                    serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok()?;
                let size = std::fs::metadata(self.done_path(&id))
                    .map(|m| m.len())
                    .unwrap_or(0);
                Some((meta.cut_at, id, size))
            })
            .collect();
        done.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
        let mut total = 0u64;
        for (i, (_, id, size)) in done.iter().enumerate() {
            total += size;
            if i >= KEEP_DONE || (i > 0 && total > KEEP_DONE_BYTES) {
                let _ = std::fs::remove_file(self.done_path(id));
                let _ = std::fs::remove_file(self.dir.join("done").join(format!("{id}.json")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;

    #[test]
    fn held_events_survive_a_restart_and_a_torn_line() {
        let dir = temp_dir("batch-store");
        let mut s = BatchStore::open(&dir).unwrap();
        let b = s.hold("a", br#"{"n":1}"#, 1000).unwrap();
        assert!(is_batch_id(&b.id));
        s.hold("a", br#"{"n":2}"#, 2000).unwrap();
        s.hold("other", br#"{"n":9}"#, 1500).unwrap();
        // A crash mid-append.
        let mut f = open_append(&s.open_path(&b.id)).unwrap();
        f.write_all(b"{\"n\":").unwrap();
        drop((f, s));

        let mut s = BatchStore::open(&dir).unwrap();
        let a = s.get("a").unwrap().clone();
        assert_eq!(
            (a.id.clone(), a.count, a.first_at, a.last_at),
            (b.id.clone(), 2, 1000, 2000)
        );
        assert_eq!(a.bytes, 16, "the torn line is cut off");
        assert_eq!(
            s.events("a").unwrap(),
            vec![serde_json::json!({"n": 1}), serde_json::json!({"n": 2})]
        );
        let done = s.finish("a", Reason::Idle, 5000).unwrap();
        assert_eq!(
            (done.count, done.reason, done.cut_at),
            (2, Reason::Idle, 5000)
        );
        assert!(s.get("a").is_none());
        let (meta, events) = s.done(&b.id).unwrap().unwrap();
        assert_eq!((meta, events.len()), (done, 2));
        // The next event opens a new batch.
        let b2 = s.hold("a", br#"{"n":3}"#, 6000).unwrap();
        assert_ne!(b2.id, b.id);
        assert_eq!(read_open(&dir).unwrap().len(), 2);
        assert!(s.discard("other").unwrap().is_some());
        assert!(s.discard("other").unwrap().is_none());
        assert_eq!(read_open(&dir).unwrap().len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn batch_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("batch-perms");
        let mut s = BatchStore::open(&dir).unwrap();
        let b = s.hold("a", b"{}", 1).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.join("batches")), 0o700);
        assert_eq!(mode(&dir.join("batches/open")), 0o700);
        assert_eq!(mode(&s.open_path(&b.id)), 0o600);
        assert_eq!(mode(&dir.join("batches/open.json")), 0o600);
        s.finish("a", Reason::Flush, 2).unwrap();
        assert_eq!(mode(&s.done_path(&b.id)), 0o600);
        assert_eq!(mode(&dir.join("batches/done")), 0o700);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn only_the_newest_cut_batches_are_kept() {
        let dir = temp_dir("batch-prune");
        let mut s = BatchStore::open(&dir).unwrap();
        let mut ids = Vec::new();
        for i in 0..(KEEP_DONE as i64 + 3) {
            ids.push(s.hold("a", b"{}", i).unwrap().id);
            s.finish("a", Reason::MaxEvents, i).unwrap();
        }
        assert!(s.done(&ids[0]).unwrap().is_none(), "the oldest went");
        assert!(s.done(&ids[2]).unwrap().is_none());
        assert!(s.done(&ids[3]).unwrap().is_some());
        assert!(s.done(ids.last().unwrap()).unwrap().is_some());
        // Ids from outside never name a file.
        assert!(!is_batch_id("bat_../../x"));
        assert!(s.done("bat_../../etc/passwd").unwrap().is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
