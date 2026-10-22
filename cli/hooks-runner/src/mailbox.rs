//! One runner per state directory, and a mailbox for asking it to replay an event (or flush or drop
//! a batch) while it runs.
//!
//! `00hooks run` holds `<runner>/runner.lock`. `00hooks replay` (and `00hooks batches flush|drop`)
//! takes the lock and does the work in its own process when no runner is running; otherwise it
//! drops a request into `<runner>/replay/` and waits for the running runner's answer beside it.

use std::fs::File;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::runs::RunRecord;
use crate::{Error, Result};

/// Held while a runner runs; released when dropped.
#[derive(Debug)]
pub struct RunnerLock {
    _file: File,
}

/// Take the runner lock. `None` when another process holds it.
pub fn lock(runner_dir: &Path) -> Result<Option<RunnerLock>> {
    hooks_client::fsutil::create_private_dir(runner_dir).map_err(Error::from_client)?;
    let file = hooks_client::fsutil::open_append(&runner_dir.join("runner.lock"))
        .map_err(Error::from_client)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(RunnerLock { _file: file })),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    #[serde(default)]
    event: String,
    /// Run this automation's open batch now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    flush: Option<String>,
    /// Throw this automation's open batch away.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    drop: Option<String>,
}

/// What a request asks the running runner.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ask {
    /// Replay an event, or a kept batch, by id.
    Replay(String),
    /// Run an automation's open batch now.
    Flush(String),
    /// Throw an automation's open batch away.
    Drop(String),
}

/// The running runner's answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Answer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<RunRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// What was done, in a sentence (a dropped batch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

fn dir(runner_dir: &Path) -> PathBuf {
    runner_dir.join("replay")
}

/// Ask the running runner to replay `event`. Returns where its answer will appear.
pub fn submit(runner_dir: &Path, event: &str) -> Result<PathBuf> {
    submit_ask(runner_dir, &Ask::Replay(event.to_string()))
}

/// Ask the running runner something. Returns where its answer will appear.
pub fn submit_ask(runner_dir: &Path, ask: &Ask) -> Result<PathBuf> {
    let d = dir(runner_dir);
    hooks_client::fsutil::create_private_dir(&d).map_err(Error::from_client)?;
    let id = crate::random_hex();
    let req = match ask {
        Ask::Replay(e) => Request {
            event: e.clone(),
            flush: None,
            drop: None,
        },
        Ask::Flush(a) => Request {
            event: String::new(),
            flush: Some(a.clone()),
            drop: None,
        },
        Ask::Drop(a) => Request {
            event: String::new(),
            flush: None,
            drop: Some(a.clone()),
        },
    };
    let bytes = serde_json::to_vec(&req).expect("json");
    hooks_client::fsutil::write_atomic(&d.join(format!("{id}.request.json")), &bytes, true)
        .map_err(Error::from_client)?;
    Ok(d.join(format!("{id}.answer.json")))
}

/// Requests waiting: (the answer's path, what is asked).
pub fn pending(runner_dir: &Path) -> Vec<(PathBuf, Ask)> {
    let d = dir(runner_dir);
    let Ok(entries) = std::fs::read_dir(&d) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(id) = name.strip_suffix(".request.json") else {
            continue;
        };
        if !id.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let req = std::fs::read(e.path())
            .ok()
            .and_then(|b| serde_json::from_slice::<Request>(&b).ok());
        let _ = std::fs::remove_file(e.path());
        let ask = match req {
            Some(Request { flush: Some(a), .. }) => Ask::Flush(a),
            Some(Request { drop: Some(a), .. }) => Ask::Drop(a),
            Some(r) => Ask::Replay(r.event),
            None => continue,
        };
        out.push((d.join(format!("{id}.answer.json")), ask));
    }
    out
}

/// Answer a request.
pub fn answer(path: &Path, a: &Answer) -> Result<()> {
    let bytes = serde_json::to_vec(a).expect("json");
    hooks_client::fsutil::write_atomic(path, &bytes, true).map_err(Error::from_client)
}

/// The answer, once it's there (and removed).
pub fn take_answer(path: &Path) -> Option<Answer> {
    let bytes = std::fs::read(path).ok()?;
    let a = serde_json::from_slice(&bytes).ok()?;
    let _ = std::fs::remove_file(path);
    Some(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;

    #[test]
    fn one_runner_and_a_mailbox() {
        let d = temp_dir("mailbox");
        let first = lock(&d).unwrap();
        assert!(first.is_some());
        assert!(lock(&d).unwrap().is_none());
        let at = submit(&d, "evt_1").unwrap();
        let reqs = pending(&d);
        assert_eq!(reqs, vec![(at.clone(), Ask::Replay("evt_1".to_string()))]);
        assert!(pending(&d).is_empty(), "taken once");
        let f = submit_ask(&d, &Ask::Flush("Readings".into())).unwrap();
        let g = submit_ask(&d, &Ask::Drop("Other".into())).unwrap();
        let mut reqs = pending(&d);
        reqs.sort();
        let mut want = vec![
            (f, Ask::Flush("Readings".into())),
            (g, Ask::Drop("Other".into())),
        ];
        want.sort();
        assert_eq!(reqs, want);
        answer(
            &at,
            &Answer {
                record: None,
                error: Some("no".into()),
                note: None,
            },
        )
        .unwrap();
        assert_eq!(take_answer(&at).unwrap().error.as_deref(), Some("no"));
        assert!(take_answer(&at).is_none());
        drop(first);
        assert!(lock(&d).unwrap().is_some());
        std::fs::remove_dir_all(d).unwrap();
    }
}
