//! Write a file: append a JSON line onto a file, or write one file per event into a folder. The
//! file or folder is fixed in the configuration; only a file's *name* comes from a template, and it
//! is sanitised to letters, digits, `.`, `_` and `-`, so it can never leave the folder.

use std::io::Write;
use std::path::Path;

use serde_json::Value;

use super::{Failure, Outcome};

/// A file name from untrusted text: letters, digits, `.`, `_` and `-`; anything else becomes `_`;
/// no leading dot; at most 128 characters. `None` when nothing usable is left.
pub fn safe_name(s: &str) -> Option<String> {
    let mapped: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = mapped.trim_start_matches('.');
    let name: String = trimmed.chars().take(128).collect();
    let meaningful = name.chars().any(|c| c.is_ascii_alphanumeric());
    meaningful.then_some(name)
}

fn open_append(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        // A symlink planted at the path is never followed.
        opts.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    opts.open(path)
}

/// Append one JSON line to `path` (creating it, and its folder, privately).
pub fn append(path: &Path, line: &Value) -> Outcome {
    if let Some(dir) = path.parent() {
        hooks_client::fsutil::create_private_dir(dir)
            .map_err(|e| Failure::fatal(format!("couldn't create {}: {e}", dir.display())))?;
    }
    let mut bytes = serde_json::to_vec(line).expect("json");
    bytes.push(b'\n');
    let mut f = open_append(path)
        .map_err(|e| Failure::fatal(format!("couldn't open {}: {e}", path.display())))?;
    f.write_all(&bytes)
        .and_then(|_| f.sync_data())
        .map_err(|e| Failure::fatal(format!("couldn't append to {}: {e}", path.display())))?;
    Ok(format!("appended a line to {}", path.display()))
}

/// Write `content` (text as it is, anything else as JSON) to `folder/<safe name>`, atomically.
pub fn write_file(folder: &Path, name: &str, content: &Value) -> Outcome {
    let Some(name) = safe_name(name) else {
        return Err(Failure::fatal(format!(
            "the file name {:?} has nothing usable once cleaned",
            crate::text::cut(&crate::text::sanitize(name), 60)
        )));
    };
    hooks_client::fsutil::create_private_dir(folder)
        .map_err(|e| Failure::fatal(format!("couldn't create {}: {e}", folder.display())))?;
    let bytes = match content {
        Value::String(s) => s.clone().into_bytes(),
        other => {
            let mut b = serde_json::to_vec_pretty(other).expect("json");
            b.push(b'\n');
            b
        }
    };
    let path = folder.join(&name);
    hooks_client::fsutil::write_atomic(&path, &bytes, true)
        .map_err(|e| Failure::retry(format!("couldn't write {}: {e}", path.display())))?;
    Ok(format!("wrote {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use serde_json::json;

    #[test]
    fn names_are_sanitised() {
        assert_eq!(safe_name("issue-42.json").as_deref(), Some("issue-42.json"));
        assert_eq!(
            safe_name("../../etc/passwd").as_deref(),
            Some("_.._etc_passwd")
        );
        assert_eq!(safe_name("/abs/path").as_deref(), Some("_abs_path"));
        assert_eq!(safe_name(".hidden").as_deref(), Some("hidden"));
        assert_eq!(
            safe_name("$(touch /tmp/x);").as_deref(),
            Some("__touch__tmp_x__")
        );
        assert_eq!(safe_name("a\0b\nc").as_deref(), Some("a_b_c"));
        assert_eq!(safe_name("..."), None);
        assert_eq!(safe_name("___"), None);
        assert_eq!(safe_name(""), None);
        assert_eq!(safe_name(&"x".repeat(300)).unwrap().len(), 128);
    }

    #[test]
    fn files_stay_in_their_folder() {
        let dir = temp_dir("write");
        let folder = dir.join("out");
        write_file(&folder, "../escape.json", &json!({"a": 1})).unwrap();
        assert!(!dir.join("escape.json").exists());
        assert!(folder.join("_escape.json").exists());
        write_file(&folder, "note.txt", &json!("plain text")).unwrap();
        assert_eq!(
            std::fs::read_to_string(folder.join("note.txt")).unwrap(),
            "plain text"
        );
        assert!(write_file(&folder, "///", &json!(1)).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn appends_lines() {
        let dir = temp_dir("append");
        let p = dir.join("sub/log.jsonl");
        append(&p, &json!({"n": 1})).unwrap();
        append(&p, &json!({"n": "two\nlines"})).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(
            text.lines().count(),
            2,
            "a newline in a value stays escaped"
        );
        #[cfg(unix)]
        {
            let link = dir.join("link.jsonl");
            std::os::unix::fs::symlink(&p, &link).unwrap();
            assert!(
                append(&link, &json!({})).is_err(),
                "symlinks aren't followed"
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
