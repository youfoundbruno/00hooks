//! Append-only JSON-lines files with torn-tail recovery: a crash mid-append leaves a last line
//! without its newline; opening the file cuts it off, so the next append starts on a clean line.
//! Lines in the middle that don't parse are skipped and counted.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::Result;

/// An open append-only file.
#[derive(Debug)]
pub struct Jsonl {
    path: PathBuf,
    file: File,
}

/// What opening found.
#[derive(Debug, Default, PartialEq)]
pub struct Recovery {
    /// Bytes of a torn last line that were cut off.
    pub torn_bytes: u64,
    /// Complete lines that didn't parse (skipped).
    pub damaged: usize,
}

fn open_append(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.append(true).create(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    Ok(opts.open(path)?)
}

/// Cut a torn last line off `path` (anything after its last newline).
fn cut_torn_tail(path: &Path) -> Result<u64> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let keep = bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let torn = (bytes.len() - keep) as u64;
    if torn > 0 {
        let f = OpenOptions::new().write(true).open(path)?;
        f.set_len(keep as u64)?;
        f.sync_all()?;
    }
    Ok(torn)
}

/// Read every line that parses as `T`.
pub fn read_all<T: DeserializeOwned>(path: &Path) -> Result<(Vec<T>, usize)> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    let mut damaged = 0;
    for line in BufReader::new(file).split(b'\n') {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        match serde_json::from_slice::<T>(&line) {
            Ok(v) => out.push(v),
            Err(_) => damaged += 1,
        }
    }
    Ok((out, damaged))
}

/// Replace `path` with these items, atomically.
pub fn rewrite<T: Serialize>(path: &Path, items: impl IntoIterator<Item = T>) -> Result<()> {
    let mut buf = Vec::new();
    for item in items {
        serde_json::to_writer(&mut buf, &item).expect("json");
        buf.push(b'\n');
    }
    hooks_client::fsutil::write_atomic(path, &buf, true).map_err(crate::Error::from_client)
}

impl Jsonl {
    /// Open for appending, cutting a torn tail first. Returns the lines that parse.
    pub fn open<T: DeserializeOwned>(
        path: impl Into<PathBuf>,
    ) -> Result<(Jsonl, Vec<T>, Recovery)> {
        let path = path.into();
        let torn_bytes = cut_torn_tail(&path)?;
        let (items, damaged) = read_all(&path)?;
        let file = open_append(&path)?;
        Ok((
            Jsonl { path, file },
            items,
            Recovery {
                torn_bytes,
                damaged,
            },
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one line and fsync it.
    pub fn append<T: Serialize>(&mut self, item: &T) -> Result<()> {
        let mut line = serde_json::to_vec(item).expect("json");
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.sync_data()?;
        Ok(())
    }

    /// Replace the file's contents (compaction) and keep appending to the new file.
    pub fn compact<T: Serialize>(&mut self, items: impl IntoIterator<Item = T>) -> Result<()> {
        rewrite(&self.path, items)?;
        self.file = open_append(&self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use serde_json::{Value, json};

    #[test]
    fn a_torn_tail_is_cut_and_appends_stay_clean() {
        let dir = temp_dir("jsonl");
        let p = dir.join("log.jsonl");
        {
            let (mut j, items, rec) = Jsonl::open::<Value>(&p).unwrap();
            assert!(items.is_empty() && rec == Recovery::default());
            j.append(&json!({"n": 1})).unwrap();
            j.append(&json!({"n": 2})).unwrap();
        }
        // A crash mid-append, and a damaged line in the middle.
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"not json\n{\"n\": 3}\n{\"n\":").unwrap();
        drop(f);
        let (mut j, items, rec) = Jsonl::open::<Value>(&p).unwrap();
        assert_eq!(
            items,
            vec![json!({"n": 1}), json!({"n": 2}), json!({"n": 3})]
        );
        assert_eq!(
            rec,
            Recovery {
                torn_bytes: 5,
                damaged: 1
            }
        );
        j.append(&json!({"n": 4})).unwrap();
        drop(j);
        let (items, damaged) = read_all::<Value>(&p).unwrap();
        assert_eq!(items.len(), 4);
        assert_eq!(damaged, 1);
        assert!(
            std::fs::read_to_string(&p)
                .unwrap()
                .ends_with("{\"n\":4}\n")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn compaction_replaces_the_file() {
        let dir = temp_dir("jsonl-compact");
        let p = dir.join("log.jsonl");
        let (mut j, _, _) = Jsonl::open::<Value>(&p).unwrap();
        for n in 0..10 {
            j.append(&json!({ "n": n })).unwrap();
        }
        j.compact([json!({"n": 9})]).unwrap();
        j.append(&json!({"n": 10})).unwrap();
        let (items, _) = read_all::<Value>(&p).unwrap();
        assert_eq!(items, vec![json!({"n": 9}), json!({"n": 10})]);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
