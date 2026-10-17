//! Helpers for the crate's own tests.

use std::path::PathBuf;

/// A fresh directory under the OS temp dir.
pub fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hooks-runner-{tag}-{}", crate::random_hex()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
