//! Secrets that a `call` action's headers name (`{{secret.GITHUB_TOKEN}}`), read at send time from
//! the OS keychain (service `00hooks-secrets`), or from 0600 files in `<runner>/secrets` when
//! `HOOKS_KEYSTORE=file`. A secret's value never goes into a run record, a log line or an error.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::path::is_secret_name;
use crate::{Error, Result};

const SERVICE: &str = "00hooks-secrets";

pub trait SecretStore: Send + Sync {
    fn describe(&self) -> String;
    fn get(&self, name: &str) -> Result<Option<String>>;
    fn set(&self, name: &str, value: &str) -> Result<()>;
    fn delete(&self, name: &str) -> Result<bool>;
}

fn check(name: &str) -> Result<()> {
    if is_secret_name(name) {
        Ok(())
    } else {
        Err(Error::Other(format!(
            "{name:?} isn't a secret name: use letters, digits and _, not starting with a digit"
        )))
    }
}

/// The OS keychain.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeychainSecrets;

fn keychain_error(e: keyring::Error) -> Error {
    Error::Other(format!("the keychain refused: {e}"))
}

impl SecretStore for KeychainSecrets {
    fn describe(&self) -> String {
        "the keychain".into()
    }

    fn get(&self, name: &str) -> Result<Option<String>> {
        check(name)?;
        let entry = keyring::Entry::new(SERVICE, name).map_err(keychain_error)?;
        match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(keychain_error(e)),
        }
    }

    fn set(&self, name: &str, value: &str) -> Result<()> {
        check(name)?;
        keyring::Entry::new(SERVICE, name)
            .and_then(|e| e.set_password(value))
            .map_err(keychain_error)
    }

    fn delete(&self, name: &str) -> Result<bool> {
        check(name)?;
        let entry = keyring::Entry::new(SERVICE, name).map_err(keychain_error)?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(keychain_error(e)),
        }
    }
}

/// One 0600 file per secret in a 0700 directory.
#[derive(Debug, Clone)]
pub struct FileSecrets {
    dir: PathBuf,
}

impl FileSecrets {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        FileSecrets { dir: dir.into() }
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        check(name)?;
        Ok(self.dir.join(name))
    }
}

#[cfg(unix)]
fn check_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_file()
        || meta.uid() != rustix::process::getuid().as_raw()
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err(Error::Other(format!(
            "refusing to read {}: it must be a regular file of yours that only you can read (chmod 600)",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_: &Path) -> Result<()> {
    Ok(())
}

impl SecretStore for FileSecrets {
    fn describe(&self) -> String {
        format!("private files in {}", self.dir.display())
    }

    fn get(&self, name: &str) -> Result<Option<String>> {
        let p = self.path(name)?;
        if std::fs::symlink_metadata(&p).is_err() {
            return Ok(None);
        }
        check_private(&p)?;
        Ok(Some(
            std::fs::read_to_string(&p)?
                .trim_end_matches(['\n', '\r'])
                .to_string(),
        ))
    }

    fn set(&self, name: &str, value: &str) -> Result<()> {
        let p = self.path(name)?;
        hooks_client::fsutil::create_private_dir(&self.dir).map_err(Error::from_client)?;
        hooks_client::fsutil::write_atomic(&p, value.as_bytes(), true).map_err(Error::from_client)
    }

    fn delete(&self, name: &str) -> Result<bool> {
        match std::fs::remove_file(self.path(name)?) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

/// In memory, for tests and embedding.
#[derive(Debug, Default)]
pub struct MemorySecrets(Mutex<HashMap<String, String>>);

impl SecretStore for MemorySecrets {
    fn describe(&self) -> String {
        "memory".into()
    }

    fn get(&self, name: &str) -> Result<Option<String>> {
        Ok(self.0.lock().expect("lock").get(name).cloned())
    }

    fn set(&self, name: &str, value: &str) -> Result<()> {
        check(name)?;
        self.0
            .lock()
            .expect("lock")
            .insert(name.into(), value.into());
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<bool> {
        Ok(self.0.lock().expect("lock").remove(name).is_some())
    }
}

/// `HOOKS_KEYSTORE=file` (or no keychain) → files in `<runner_dir>/secrets`; else the keychain.
pub fn default_store(runner_dir: &Path) -> Box<dyn SecretStore> {
    let file = match std::env::var("HOOKS_KEYSTORE").as_deref() {
        Ok("file") => true,
        Ok("keychain") => false,
        _ => keyring::Entry::store_status().is_err(),
    };
    if file {
        Box::new(FileSecrets::new(runner_dir.join("secrets")))
    } else {
        Box::new(KeychainSecrets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;

    #[test]
    fn file_secrets_are_private() {
        let dir = temp_dir("secrets");
        let s = FileSecrets::new(dir.join("secrets"));
        assert_eq!(s.get("TOKEN").unwrap(), None);
        s.set("TOKEN", "abc").unwrap();
        assert_eq!(s.get("TOKEN").unwrap().as_deref(), Some("abc"));
        assert!(s.set("../x", "y").is_err());
        assert!(s.get("a/b").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let p = dir.join("secrets/TOKEN");
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(s.get("TOKEN").is_err(), "a readable secret file is refused");
        }
        assert!(s.delete("TOKEN").unwrap());
        assert!(!s.delete("TOKEN").unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
