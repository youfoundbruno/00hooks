//! The local state directory: the config, the stream cursor, the events recorded but not yet handed
//! over (the inbox), the ids already handed over (the seen set), and the quarantine: `hook` messages
//! that couldn't be read, kept raw so nothing the relay sent is silently lost.
//!
//! Every file is either replaced atomically (config, cursor) or appended and fsynced (inbox, seen).
//! A crash can leave a torn last line in an append-only file; it is skipped on the next start, when
//! both files are compacted.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::keys::FileKeyStore;
use crate::types::Event;
use crate::{Error, Result, fsutil};

/// How many handed-over ids are remembered. The relay never replays below the cursor, so old ids
/// only matter if the cursor is lost; 100k is months of traffic for most people.
pub const SEEN_CAP: usize = 100_000;

const CONFIG: &str = "config.json";
const CURSOR: &str = "cursor.json";
const INBOX: &str = "inbox.jsonl";
const SEEN: &str = "seen.jsonl";
/// Raw `hook` messages that couldn't be read. Append-only; never compacted or reset.
pub const QUARANTINE: &str = "quarantine.jsonl";
const LOCK: &str = "listen.lock";
const KEYS: &str = "keys";

/// What `00hooks login` saves.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub relay: String,
    pub account_id: String,
    pub device_id: String,
    pub device_name: String,
    /// `keychain` or `file`.
    pub key_store: String,
    /// The key's name in that store.
    pub key_name: String,
    /// The relay's envelope-signing key (`relayKey`), pinned at login (PROTOCOL §2). `None` for a
    /// login from before protocol 2, until `00hooks devices seal-key` pins it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_key: Option<String>,
    /// The kids of this device's sealing keys, oldest first; each private key is in the key store
    /// as `seal-<kid>`. The last is the one the relay seals new events to; older ones open events
    /// sealed before a replacement.
    #[serde(default)]
    pub seal_kids: Vec<String>,
}

/// The state directory.
#[derive(Debug, Clone)]
pub struct StateDir {
    dir: PathBuf,
}

impl StateDir {
    /// `$HOOKS_HOME`, or the platform's data directory: `~/Library/Application Support/00hooks` on
    /// macOS, `$XDG_DATA_HOME/00hooks` (`~/.local/share/00hooks`) on Linux.
    pub fn default_path() -> Result<PathBuf> {
        if let Some(home) = std::env::var_os("HOOKS_HOME").filter(|v| !v.is_empty()) {
            return Ok(PathBuf::from(home));
        }
        dirs::data_dir().map(|d| d.join("00hooks")).ok_or_else(|| {
            Error::Store(
                "can't find a data directory for this user; set HOOKS_HOME to a folder".into(),
            )
        })
    }

    pub fn open_default() -> Result<Self> {
        Self::open(Self::default_path()?)
    }

    /// Open (creating, 0700) a state directory.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fsutil::create_private_dir(&dir)
            .map_err(|e| Error::Store(format!("can't create {}: {e}", dir.display())))?;
        Ok(StateDir { dir })
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    pub fn load_config(&self) -> Result<Option<Config>> {
        let path = self.dir.join(CONFIG);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| {
                Error::Store(format!(
                    "{} is damaged ({e}); log in again with --force",
                    path.display()
                ))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save_config(&self, config: &Config) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(config).expect("json");
        fsutil::write_atomic(&self.dir.join(CONFIG), &bytes, true)
    }

    /// Forget the device and everything recorded (used when logging in again).
    pub fn reset(&self) -> Result<()> {
        for name in [CONFIG, CURSOR, INBOX, SEEN] {
            match std::fs::remove_file(self.dir.join(name)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
        }
        fsutil::sync_dir(&self.dir);
        Ok(())
    }

    /// The fallback key store, `<dir>/keys`.
    pub fn file_keys(&self) -> FileKeyStore {
        FileKeyStore::new(self.dir.join(KEYS))
    }

    /// Take the listener lock: only one process streams for this state directory at a time.
    /// `None` when another process holds it.
    pub fn lock_listener(&self) -> Result<Option<ListenerLock>> {
        let file = fsutil::open_append(&self.dir.join(LOCK))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(ListenerLock { _file: file })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
        }
    }

    /// Open the event store (compacting it). Hold the listener lock while it is open.
    pub fn open_events(&self) -> Result<EventStore> {
        EventStore::open(&self.dir)
    }
}

/// Held while a process listens; released when dropped.
#[derive(Debug)]
pub struct ListenerLock {
    _file: File,
}

#[derive(Serialize, Deserialize)]
struct CursorFile {
    seq: u64,
}

#[derive(Serialize, Deserialize)]
struct SeenLine {
    id: String,
}

/// One quarantined message: what the relay sent, exactly, and why it couldn't be read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Quarantined {
    /// When it was quarantined, Unix ms.
    pub at: i64,
    /// The SSE `id` (the event's seq) when it was a number.
    pub seq: Option<u64>,
    /// The SSE `id` as sent, when it wasn't a number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>,
    /// The SSE event type, `hook`.
    pub event: String,
    /// The `data:` field, exactly as sent.
    pub data: String,
    /// Why it couldn't be read.
    pub error: String,
}

/// The cursor, the inbox and the seen set.
#[derive(Debug)]
pub struct EventStore {
    dir: PathBuf,
    cursor: u64,
    seen: HashSet<String>,
    inbox: BTreeMap<u64, Event>,
    inbox_ids: HashSet<String>,
    inbox_file: File,
    seen_file: File,
}

/// Read a JSONL file, skipping lines that don't parse (a torn write at the end, after a crash).
fn read_lines<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Vec<T>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for line in BufReader::new(file).split(b'\n') {
        let line = line?;
        if let Ok(v) = serde_json::from_slice::<T>(&line) {
            out.push(v);
        }
    }
    Ok(out)
}

fn to_lines<T: Serialize>(items: impl IntoIterator<Item = T>) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        serde_json::to_writer(&mut out, &item).expect("json");
        out.push(b'\n');
    }
    out
}

/// Remove temporary files an atomic write left behind when the process died mid-write (their names
/// are random, so nothing else would ever reuse them). Only the store's own files, best effort.
fn sweep_temp_files(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let ours = [CURSOR, INBOX, SEEN]
            .iter()
            .any(|f| name.starts_with(&format!(".{f}.")) && name.ends_with(".tmp"));
        if ours && entry.file_type().is_ok_and(|t| t.is_file()) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

impl EventStore {
    fn open(dir: &Path) -> Result<Self> {
        sweep_temp_files(dir);
        // Seen set: keep the newest SEEN_CAP distinct ids, in order.
        let mut order: VecDeque<String> = VecDeque::new();
        let mut seen = HashSet::new();
        for line in read_lines::<SeenLine>(&dir.join(SEEN))? {
            if seen.insert(line.id.clone()) {
                order.push_back(line.id);
            }
        }
        while order.len() > SEEN_CAP {
            if let Some(old) = order.pop_front() {
                seen.remove(&old);
            }
        }
        fsutil::write_atomic(
            &dir.join(SEEN),
            &to_lines(order.iter().map(|id| SeenLine { id: id.clone() })),
            true,
        )?;

        // Inbox: recorded events not yet handed over, once each, in seq order.
        let mut inbox = BTreeMap::new();
        let mut inbox_ids = HashSet::new();
        for event in read_lines::<Event>(&dir.join(INBOX))? {
            if !seen.contains(&event.id) && inbox_ids.insert(event.id.clone()) {
                inbox.insert(event.seq, event);
            }
        }
        fsutil::write_atomic(&dir.join(INBOX), &to_lines(inbox.values()), true)?;

        let cursor_from_file = match std::fs::read(dir.join(CURSOR)) {
            Ok(b) => serde_json::from_slice::<CursorFile>(&b)
                .map(|c| c.seq)
                .unwrap_or(0),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e.into()),
        };
        let cursor = cursor_from_file.max(inbox.keys().next_back().copied().unwrap_or(0));

        Ok(EventStore {
            dir: dir.to_path_buf(),
            cursor,
            seen,
            inbox,
            inbox_ids,
            inbox_file: fsutil::open_append(&dir.join(INBOX))?,
            seen_file: fsutil::open_append(&dir.join(SEEN))?,
        })
    }

    /// The highest seq recorded (or skipped by a gap): what `Last-Event-ID` resumes from.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Move the cursor forward (never back), atomically.
    pub fn advance_cursor(&mut self, seq: u64) -> Result<()> {
        if seq <= self.cursor {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&CursorFile { seq }).expect("json");
        fsutil::write_atomic(&self.dir.join(CURSOR), &bytes, true)?;
        self.cursor = seq;
        Ok(())
    }

    /// Already handed over to the consumer.
    pub fn is_seen(&self, id: &str) -> bool {
        self.seen.contains(id)
    }

    /// Recorded and waiting to be handed over.
    pub fn is_recorded(&self, id: &str) -> bool {
        self.inbox_ids.contains(id)
    }

    /// Record a batch durably: append the events that are new (neither handed over nor already
    /// recorded), fsync, then move the cursor past the whole batch. Returns the new events.
    pub fn record(&mut self, events: &[Event]) -> Result<Vec<Event>> {
        let mut fresh = Vec::new();
        let mut buf = Vec::new();
        for e in events {
            if self.is_seen(&e.id) || self.is_recorded(&e.id) {
                continue;
            }
            serde_json::to_writer(&mut buf, e).expect("json");
            buf.push(b'\n');
            self.inbox_ids.insert(e.id.clone());
            self.inbox.insert(e.seq, e.clone());
            fresh.push(e.clone());
        }
        if !buf.is_empty() {
            self.inbox_file.write_all(&buf)?;
            self.inbox_file.sync_data()?;
        }
        if let Some(max) = events.iter().map(|e| e.seq).max() {
            self.advance_cursor(max)?;
        }
        Ok(fresh)
    }

    /// Note that `id` has been handed to the consumer (durably, before it is).
    pub fn mark_delivered(&mut self, id: &str) -> Result<()> {
        if !self.seen.insert(id.to_string()) {
            return Ok(());
        }
        let mut line = serde_json::to_vec(&SeenLine { id: id.to_string() }).expect("json");
        line.push(b'\n');
        self.seen_file.write_all(&line)?;
        self.seen_file.sync_data()?;
        if self.inbox_ids.remove(id) {
            self.inbox.retain(|_, e| e.id != id);
        }
        Ok(())
    }

    /// Keep an unreadable message raw in `quarantine.jsonl` (appended and fsynced), so that
    /// acknowledging past it loses nothing. Returns the file's path.
    pub fn quarantine(&mut self, q: &Quarantined) -> Result<PathBuf> {
        let path = self.dir.join(QUARANTINE);
        let mut line = serde_json::to_vec(q).expect("json");
        line.push(b'\n');
        let mut f = fsutil::open_append(&path)?;
        f.write_all(&line)?;
        f.sync_data()?;
        fsutil::sync_dir(&self.dir);
        Ok(path)
    }

    /// Everything quarantined so far, oldest first.
    pub fn quarantined(&self) -> Result<Vec<Quarantined>> {
        read_lines(&self.dir.join(QUARANTINE))
    }

    /// Recorded events not yet handed over, oldest first.
    pub fn pending(&self) -> Vec<Event> {
        self.inbox.values().cloned().collect()
    }

    /// The highest seq waiting in the inbox.
    pub fn pending_through(&self) -> Option<u64> {
        self.inbox.keys().next_back().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::temp_dir;

    pub(crate) fn event(seq: u64) -> Event {
        serde_json::from_value(serde_json::json!({
            "seq": seq, "id": format!("evt_{seq}"), "hookId": "hk_1", "receivedAt": 1,
            "verified": true, "preset": "github", "body": "e30="
        }))
        .unwrap()
    }

    #[test]
    fn config_round_trips_and_is_private() {
        let dir = temp_dir("cfg");
        let s = StateDir::open(dir.join("home")).unwrap();
        assert!(s.load_config().unwrap().is_none());
        let c = Config {
            relay: "https://relay.example.com".into(),
            account_id: "acc_1".into(),
            device_id: "dev_1".into(),
            device_name: "laptop".into(),
            key_store: "file".into(),
            key_name: "key_1".into(),
            relay_key: Some("A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".into()),
            seal_kids: vec!["QjSYPjQbvjPuXDfQbGtuAQ".into()],
        };
        s.save_config(&c).unwrap();
        assert_eq!(s.load_config().unwrap(), Some(c));
        // A login from before protocol 2 still loads, with nothing pinned and no sealing key.
        let old = r#"{"relay":"https://r.example","accountId":"acc_1","deviceId":"dev_1",
            "deviceName":"x","keyStore":"file","keyName":"k"}"#;
        std::fs::write(s.path().join(CONFIG), old).unwrap();
        let back = s.load_config().unwrap().unwrap();
        assert!(back.relay_key.is_none() && back.seal_kids.is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(s.path().join(CONFIG)).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn record_dedupes_and_moves_the_cursor() {
        let dir = temp_dir("rec");
        let s = StateDir::open(&dir).unwrap();
        let mut ev = s.open_events().unwrap();
        let fresh = ev.record(&[event(1), event(2), event(2)]).unwrap();
        assert_eq!(fresh.len(), 2);
        assert_eq!(ev.cursor(), 2);
        // Recorded but not delivered: recording again adds nothing.
        assert!(ev.record(&[event(2)]).unwrap().is_empty());
        ev.mark_delivered("evt_1").unwrap();
        // Delivered: recording again adds nothing either.
        assert!(ev.record(&[event(1)]).unwrap().is_empty());
        assert_eq!(ev.pending(), vec![event(2)]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn state_survives_a_crash_with_torn_writes() {
        let dir = temp_dir("crash");
        let s = StateDir::open(&dir).unwrap();
        {
            let mut ev = s.open_events().unwrap();
            ev.record(&[event(1), event(2), event(3)]).unwrap();
            ev.mark_delivered("evt_1").unwrap();
            ev.mark_delivered("evt_2").unwrap();
            // The process dies here: no clean shutdown.
            std::mem::forget(ev);
        }
        // A crash mid-append leaves half a line in each file, and an atomic write left its temp.
        for name in [INBOX, SEEN] {
            let mut f = fsutil::open_append(&dir.join(name)).unwrap();
            f.write_all(b"{\"seq\":4,\"id\":\"evt_").unwrap();
        }
        std::fs::write(dir.join(".cursor.json.tmp"), b"{\"seq\":99").unwrap();
        std::fs::write(dir.join(".cursor.json.0123456789abcdef.tmp"), b"{\"seq\":9").unwrap();

        let mut ev = s.open_events().unwrap();
        assert_eq!(ev.cursor(), 3);
        assert!(
            !dir.join(".cursor.json.0123456789abcdef.tmp").exists(),
            "leftover temporary files are swept"
        );
        assert!(ev.is_seen("evt_1") && ev.is_seen("evt_2"));
        assert!(!ev.is_seen("evt_3"));
        assert_eq!(ev.pending(), vec![event(3)], "recorded, not delivered");
        // Compaction rewrote both files cleanly: appending after it yields parseable lines.
        ev.record(&[event(4)]).unwrap();
        ev.mark_delivered("evt_3").unwrap();
        drop(ev);
        let ev = s.open_events().unwrap();
        assert_eq!(ev.pending(), vec![event(4)]);
        assert_eq!(ev.cursor(), 4);
        assert_eq!(read_lines::<SeenLine>(&dir.join(SEEN)).unwrap().len(), 3);
        let raw = std::fs::read_to_string(dir.join(INBOX)).unwrap();
        assert!(
            raw.lines()
                .all(|l| serde_json::from_str::<Event>(l).is_ok())
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cursor_never_goes_back_and_covers_the_inbox() {
        let dir = temp_dir("cur");
        let s = StateDir::open(&dir).unwrap();
        let mut ev = s.open_events().unwrap();
        ev.advance_cursor(10).unwrap();
        ev.advance_cursor(5).unwrap();
        assert_eq!(ev.cursor(), 10);
        drop(ev);
        // A lost cursor file is rebuilt from the inbox.
        let mut ev = s.open_events().unwrap();
        ev.record(&[event(12)]).unwrap();
        drop(ev);
        std::fs::remove_file(dir.join(CURSOR)).unwrap();
        assert_eq!(s.open_events().unwrap().cursor(), 12);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn seen_set_is_compacted_on_start() {
        let dir = temp_dir("seen");
        let s = StateDir::open(&dir).unwrap();
        let mut lines = Vec::new();
        for i in 0..(SEEN_CAP + 10) {
            lines.extend_from_slice(format!("{{\"id\":\"evt_{i}\"}}\n").as_bytes());
        }
        lines.extend_from_slice(b"{\"id\":\"evt_5\"}\n");
        std::fs::write(dir.join(SEEN), lines).unwrap();
        let ev = s.open_events().unwrap();
        assert!(
            !ev.is_seen("evt_0"),
            "the oldest ids are dropped past the cap"
        );
        assert!(ev.is_seen(&format!("evt_{}", SEEN_CAP + 9)));
        assert_eq!(
            read_lines::<SeenLine>(&dir.join(SEEN)).unwrap().len(),
            SEEN_CAP
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn quarantine_keeps_the_raw_message_durably() {
        let dir = temp_dir("quarantine");
        let s = StateDir::open(&dir).unwrap();
        let mut ev = s.open_events().unwrap();
        let q = Quarantined {
            at: 1,
            seq: Some(7),
            raw_id: None,
            event: "hook".into(),
            data: "{\"seq\":7,\"broken".into(),
            error: "EOF while parsing".into(),
        };
        let path = ev.quarantine(&q).unwrap();
        assert_eq!(path, dir.join(QUARANTINE));
        drop(ev);
        // Survives a restart and isn't compacted away.
        let ev = s.open_events().unwrap();
        assert_eq!(ev.quarantined().unwrap(), vec![q]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o600);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn only_one_listener_holds_the_lock() {
        let dir = temp_dir("lock");
        let s = StateDir::open(&dir).unwrap();
        let first = s.lock_listener().unwrap();
        assert!(first.is_some());
        assert!(s.lock_listener().unwrap().is_none());
        drop(first);
        assert!(s.lock_listener().unwrap().is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
