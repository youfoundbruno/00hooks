//! Run records (PLAN §5.3): one per event, saying which automations matched, what each action
//! did, how long it took and what went wrong. Kept in `runs.jsonl`, append-only:
//!
//! - a `start` line, fsynced **before** any action runs;
//! - an `end` line with the whole record once it's done.
//!
//! A `start` with no `end` is a run a crash interrupted. It is closed as `interrupted` on the next
//! start and never run again by itself (its actions may have happened already: at most once wins
//! over at least once). `00hooks replay` runs it again on purpose.
//!
//! The events themselves are kept in `events.jsonl` (the newest [`KEEP_EVENTS`]) so they can be
//! replayed.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use hooks_client::Event;
use serde::{Deserialize, Serialize};

use crate::catalogue::ShapeChange;
use crate::jsonl::{self, Jsonl};
use crate::{Result, now_ms};

/// How many runs `runs.jsonl` keeps.
pub const KEEP_RUNS: usize = 5000;
/// How many events `events.jsonl` keeps for replay.
pub const KEEP_EVENTS: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Every automation that ran succeeded (or none matched).
    Ok,
    /// At least one action failed.
    Failed,
    /// Not acted on: our own echo, a loop, an event seen before.
    Dropped,
    /// A crash stopped it part-way.
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionResult {
    pub action: String,
    pub ok: bool,
    pub attempts: u32,
    pub ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// What an "ask an agent" action got back: the agent's reply (cut to `MAX_OUTPUT` characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

/// The most of an agent's reply a run record keeps.
pub const MAX_OUTPUT: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutomationRun {
    pub name: String,
    /// `kind`, `new_kind` or `shape_changed`.
    pub trigger: String,
    /// Why it didn't run, when it didn't.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    #[serde(default)]
    pub actions: Vec<ActionResult>,
}

impl AutomationRun {
    pub fn failed(&self) -> bool {
        self.actions.iter().any(|a| !a.ok)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunRecord {
    pub run: String,
    pub event_id: String,
    pub seq: u64,
    pub hook_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook: Option<String>,
    pub kind: String,
    pub verified: bool,
    pub started_at: i64,
    pub finished_at: i64,
    #[serde(default)]
    pub replay: bool,
    pub status: RunStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default)]
    pub new_kind: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape_change: Option<ShapeChange>,
    #[serde(default)]
    pub automations: Vec<AutomationRun>,
}

impl RunRecord {
    pub fn ran(&self) -> usize {
        self.automations
            .iter()
            .filter(|a| a.skipped.is_none())
            .count()
    }

    pub fn failed(&self) -> usize {
        self.automations.iter().filter(|a| a.failed()).count()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "camelCase")]
enum Line {
    #[serde(rename_all = "camelCase")]
    Start {
        run: String,
        event_id: String,
        seq: u64,
        hook_id: String,
        kind: String,
        verified: bool,
        at: i64,
        #[serde(default)]
        replay: bool,
    },
    End {
        record: RunRecord,
    },
}

/// The run log and the event archive.
#[derive(Debug)]
pub struct RunLog {
    runs_file: Jsonl,
    events_path: PathBuf,
    events_file: Jsonl,
    /// Finished runs, oldest first.
    runs: VecDeque<RunRecord>,
    /// Events that started a (non-replay) run: never run twice.
    seen: HashSet<String>,
    archived: HashSet<String>,
    /// Runs closed as interrupted while opening.
    pub interrupted: Vec<RunRecord>,
}

impl RunLog {
    pub fn open(dir: &Path) -> Result<RunLog> {
        hooks_client::fsutil::create_private_dir(dir).map_err(crate::Error::from_client)?;
        let (mut runs_file, lines, _) = Jsonl::open::<Line>(dir.join("runs.jsonl"))?;
        let mut open: HashMap<String, Line> = HashMap::new();
        let mut order: Vec<String> = Vec::new();
        let mut done: HashMap<String, RunRecord> = HashMap::new();
        let mut seen = HashSet::new();
        for l in lines {
            match l {
                Line::Start {
                    ref run,
                    ref event_id,
                    replay,
                    ..
                } => {
                    if !replay {
                        seen.insert(event_id.clone());
                    }
                    order.push(run.clone());
                    open.insert(run.clone(), l.clone());
                }
                Line::End { record } => {
                    if !record.replay && record.status != RunStatus::Dropped {
                        seen.insert(record.event_id.clone());
                    }
                    if open.remove(&record.run).is_none() {
                        order.push(record.run.clone());
                    }
                    done.insert(record.run.clone(), record);
                }
            }
        }
        // Close what a crash left open.
        let mut interrupted = Vec::new();
        for run in &order {
            if let Some(Line::Start {
                run,
                event_id,
                seq,
                hook_id,
                kind,
                verified,
                at,
                replay,
            }) = open.remove(run)
            {
                let rec = RunRecord {
                    run: run.clone(),
                    event_id,
                    seq,
                    hook_id,
                    hook: None,
                    kind,
                    verified,
                    started_at: at,
                    finished_at: now_ms(),
                    replay,
                    status: RunStatus::Interrupted,
                    note: Some(
                        "the runner stopped while this ran; it wasn't run again (replay it if \
                         needed)"
                            .into(),
                    ),
                    new_kind: false,
                    shape_change: None,
                    automations: Vec::new(),
                };
                runs_file.append(&Line::End {
                    record: rec.clone(),
                })?;
                interrupted.push(rec.clone());
                done.insert(run, rec);
            }
        }
        let mut runs: VecDeque<RunRecord> = order.iter().filter_map(|r| done.remove(r)).collect();
        if runs.len() > KEEP_RUNS {
            runs.drain(..runs.len() - KEEP_RUNS);
            runs_file.compact(runs.iter().map(|r| Line::End { record: r.clone() }))?;
        }

        // The archive: the newest KEEP_EVENTS events, each once.
        let events_path = dir.join("events.jsonl");
        let (mut events_file, events, _) = Jsonl::open::<Event>(&events_path)?;
        let mut archived = HashSet::new();
        if events.len() > KEEP_EVENTS {
            let keep: Vec<Event> = events[events.len() - KEEP_EVENTS..].to_vec();
            archived.extend(keep.iter().map(|e| e.id.clone()));
            events_file.compact(keep)?;
        } else {
            archived.extend(events.iter().map(|e| e.id.clone()));
        }
        Ok(RunLog {
            runs_file,
            events_path,
            events_file,
            runs,
            seen,
            archived,
            interrupted,
        })
    }

    /// An event that already started a run (and so will never run again by itself).
    pub fn seen(&self, event_id: &str) -> bool {
        self.seen.contains(event_id)
    }

    /// Archive the event and record the run's start, durably. Returns the run id.
    pub fn begin(&mut self, e: &Event, kind: &str, replay: bool) -> Result<String> {
        if self.archived.insert(e.id.clone()) {
            self.events_file.append(e)?;
        }
        let run = format!("run_{}", crate::random_hex());
        self.runs_file.append(&Line::Start {
            run: run.clone(),
            event_id: e.id.clone(),
            seq: e.seq,
            hook_id: e.hook_id.clone(),
            kind: kind.to_string(),
            verified: e.verified,
            at: now_ms(),
            replay,
        })?;
        if !replay {
            self.seen.insert(e.id.clone());
        }
        Ok(run)
    }

    /// Record a finished run.
    pub fn finish(&mut self, record: RunRecord) -> Result<()> {
        self.runs_file.append(&Line::End {
            record: record.clone(),
        })?;
        if !record.replay && record.status != RunStatus::Dropped {
            self.seen.insert(record.event_id.clone());
        }
        self.runs.push_back(record);
        if self.runs.len() > KEEP_RUNS * 2 {
            self.runs.drain(..self.runs.len() - KEEP_RUNS);
            let keep: Vec<Line> = self
                .runs
                .iter()
                .map(|r| Line::End { record: r.clone() })
                .collect();
            self.runs_file.compact(keep)?;
        }
        Ok(())
    }

    /// The newest `n` runs, newest first.
    pub fn recent(&self, n: usize) -> Vec<&RunRecord> {
        self.runs.iter().rev().take(n).collect()
    }

    /// Finished runs of one event, oldest first.
    pub fn of_event(&self, event_id: &str) -> Vec<&RunRecord> {
        self.runs
            .iter()
            .filter(|r| r.event_id == event_id)
            .collect()
    }

    /// The newest `n` archived events, newest first (for previews against real events).
    pub fn recent_events(&self, n: usize) -> Result<Vec<Event>> {
        let (events, _) = jsonl::read_all::<Event>(&self.events_path)?;
        Ok(events.into_iter().rev().take(n).collect())
    }

    /// An archived event, by id (or by seq, written as a number).
    pub fn event(&self, id: &str) -> Result<Option<Event>> {
        let (events, _) = jsonl::read_all::<Event>(&self.events_path)?;
        let seq = id.parse::<u64>().ok();
        Ok(events
            .into_iter()
            .rev()
            .find(|e| e.id == id || Some(e.seq) == seq))
    }
}

/// Read the finished runs without opening the log for writing (for `00hooks runs` while the
/// runner is running).
pub fn read_runs(dir: &Path) -> Result<Vec<RunRecord>> {
    let (lines, _) = jsonl::read_all::<Line>(&dir.join("runs.jsonl"))?;
    Ok(lines
        .into_iter()
        .filter_map(|l| match l {
            Line::End { record } => Some(record),
            Line::Start { .. } => None,
        })
        .collect())
}

/// Read an archived event without opening the log for writing.
pub fn read_event(dir: &Path, id: &str) -> Result<Option<Event>> {
    let (events, _) = jsonl::read_all::<Event>(&dir.join("events.jsonl"))?;
    let seq = id.parse::<u64>().ok();
    Ok(events
        .into_iter()
        .rev()
        .find(|e| e.id == id || Some(e.seq) == seq))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::test_event;
    use crate::testutil::temp_dir;
    use serde_json::json;

    fn record(run: &str, e: &Event) -> RunRecord {
        RunRecord {
            run: run.into(),
            event_id: e.id.clone(),
            seq: e.seq,
            hook_id: e.hook_id.clone(),
            hook: None,
            kind: "k".into(),
            verified: true,
            started_at: 1,
            finished_at: 2,
            replay: false,
            status: RunStatus::Ok,
            note: None,
            new_kind: false,
            shape_change: None,
            automations: vec![],
        }
    }

    #[test]
    fn runs_survive_restarts_and_crashes_close_as_interrupted() {
        let dir = temp_dir("runs");
        let e1 = test_event(1, Some("k"), &json!({"a": 1}));
        let e2 = test_event(2, Some("k"), &json!({"a": 2}));
        {
            let mut log = RunLog::open(&dir).unwrap();
            let r1 = log.begin(&e1, "k", false).unwrap();
            log.finish(record(&r1, &e1)).unwrap();
            // Crash while e2 runs: a start, no end, and a torn line after it.
            log.begin(&e2, "k", false).unwrap();
        }
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("runs.jsonl"))
            .unwrap();
        std::io::Write::write_all(&mut f, b"{\"t\":\"end\",\"rec").unwrap();
        drop(f);

        let log = RunLog::open(&dir).unwrap();
        assert!(
            log.seen("evt_1") && log.seen("evt_2"),
            "neither runs again by itself"
        );
        assert_eq!(log.interrupted.len(), 1);
        assert_eq!(log.interrupted[0].event_id, "evt_2");
        let recent = log.recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].status, RunStatus::Interrupted);
        assert_eq!(recent[1].status, RunStatus::Ok);
        assert_eq!(log.event("evt_2").unwrap().unwrap(), e2, "kept for replay");
        assert_eq!(log.event("1").unwrap().unwrap(), e1, "by seq too");
        drop(log);
        // Closing it is recorded, so it isn't reported twice.
        let log = RunLog::open(&dir).unwrap();
        assert!(log.interrupted.is_empty());
        assert_eq!(read_runs(&dir).unwrap().len(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replays_and_drops_dont_mark_events_seen() {
        let dir = temp_dir("runs-replay");
        let e = test_event(5, Some("k"), &json!({}));
        let mut log = RunLog::open(&dir).unwrap();
        let r = log.begin(&e, "k", true).unwrap();
        let mut rec = record(&r, &e);
        rec.replay = true;
        log.finish(rec).unwrap();
        assert!(!log.seen("evt_5"));
        let mut rec = record("run_x", &e);
        rec.status = RunStatus::Dropped;
        log.finish(rec).unwrap();
        assert!(!log.seen("evt_5"));
        assert_eq!(log.of_event("evt_5").len(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
