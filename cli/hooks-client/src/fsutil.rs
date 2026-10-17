//! Crash-safe file primitives: private directories, atomic replace, durable append.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::Result;

/// Create `dir` (and parents) readable only by the owner.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let mode = std::fs::metadata(dir)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)?;
    Ok(())
}

/// Create a fresh file at `path` for writing: never an existing file (`O_EXCL`), never through a
/// symlink (`O_NOFOLLOW`), and, when `private`, 0600 from the start and again on the open file (so
/// a umask or an odd filesystem can't leave it wider).
fn create_fresh(path: &Path, private: bool) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        if private {
            opts.mode(0o600);
        }
    }
    let f = opts.open(path)?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = private;
    Ok(f)
}

/// A temporary name beside `path` that nobody can guess: `.<name>.<16 random hex>.tmp`.
fn temp_name(dir: &Path, name: &str) -> Result<std::path::PathBuf> {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).map_err(|e| crate::Error::Store(format!("no randomness: {e}")))?;
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    Ok(dir.join(format!(".{name}.{hex}.tmp")))
}

/// Replace `path` with `bytes` so that a crash leaves either the old file or the new one: write a
/// fresh temporary file beside it (random name, created exclusively, no symlinks followed), fsync
/// it, rename it over, then fsync the directory. The temporary file is removed on any failure.
pub fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = temp_name(dir, &name)?;
    let written = (|| -> std::io::Result<()> {
        let mut f = create_fresh(&tmp, private)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    sync_dir(dir);
    Ok(())
}

/// Fsync a directory so a rename or a new file in it survives a crash. Best effort: not every
/// platform can open a directory.
pub fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Open `path` for appending (creating it 0600).
pub fn open_append(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    Ok(opts.open(path)?)
}

#[cfg(test)]
pub(crate) fn temp_dir(tag: &str) -> std::path::PathBuf {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    let d = std::env::temp_dir().join(format!("hooks-client-{tag}-{hex}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
        let dir = temp_dir("atomic");
        let p = dir.join("f.json");
        write_atomic(&p, b"one", false).unwrap();
        write_atomic(&p, b"two", false).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn temp_names_are_random_and_created_exclusively() {
        let dir = temp_dir("tmpname");
        let a = temp_name(&dir, "f.json").unwrap();
        let b = temp_name(&dir, "f.json").unwrap();
        assert_ne!(a, b);
        let n = a.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            n.starts_with(".f.json.") && n.ends_with(".tmp") && n.len() == ".f.json.".len() + 20
        );
        // An existing file at the temporary name is never opened or truncated.
        std::fs::write(&a, b"someone else's").unwrap();
        assert!(create_fresh(&a, true).is_err());
        assert_eq!(std::fs::read(&a).unwrap(), b"someone else's");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_is_never_followed() {
        let dir = temp_dir("symlink");
        let target = dir.join("target");
        std::fs::write(&target, b"keep").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(create_fresh(&link, true).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_files_are_0600_whatever_the_umask_allows() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        let p = dir.join("secret");
        write_atomic(&p, b"x", true).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
