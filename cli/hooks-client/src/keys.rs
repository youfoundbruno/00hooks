//! Device keys: an Ed25519 key pair per device, whose private half never leaves the machine.
//!
//! The 32-byte seed is kept in a [`KeyStore`]: the OS keychain ([`KeychainStore`]), a 0600 file
//! ([`FileKeyStore`]) when there is no keychain, or memory ([`MemoryKeyStore`]) in tests.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};

use crate::{Error, Result, fsutil};

/// The keychain service name entries are filed under.
pub const KEYCHAIN_SERVICE: &str = "00hooks";

/// A device's Ed25519 signing key.
pub struct DeviceKey {
    signing: SigningKey,
}

impl DeviceKey {
    /// A new random key.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::KeyStore(format!("no randomness: {e}")))?;
        let key = Self::from_seed(&seed);
        seed.fill(0);
        Ok(key)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        DeviceKey {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The public key, base64url without padding (43 characters), as `publicKey` in PROTOCOL §2.
    pub fn public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing.verifying_key().as_bytes())
    }

    /// The 64-byte Ed25519 signature of `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Load the key named `name` from `store`; `None` when there is none.
    pub fn load(store: &dyn KeyStore, name: &str) -> Result<Option<Self>> {
        Ok(store.load(name)?.map(|mut seed| {
            let key = Self::from_seed(&seed);
            seed.fill(0);
            key
        }))
    }

    /// Save this key in `store` as `name`.
    pub fn save(&self, store: &dyn KeyStore, name: &str) -> Result<()> {
        let mut seed = self.seed();
        let r = store.save(name, &seed);
        seed.fill(0);
        r
    }
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeviceKey({})", self.public_key())
    }
}

/// Where device keys (the signing seed, the sealing keys) and strict hooks' secrets are kept.
pub trait KeyStore: Send + Sync {
    /// A short name for messages: "the keychain", "a file".
    fn describe(&self) -> String;
    fn load_bytes(&self, name: &str) -> Result<Option<Vec<u8>>>;
    fn save_bytes(&self, name: &str, bytes: &[u8]) -> Result<()>;
    fn delete(&self, name: &str) -> Result<()>;

    /// A 32-byte key.
    fn load(&self, name: &str) -> Result<Option<[u8; 32]>> {
        match self.load_bytes(name)? {
            None => Ok(None),
            Some(mut b) => {
                let key = <[u8; 32]>::try_from(b.as_slice()).map_err(|_| {
                    Error::KeyStore(format!("the key {name} in {} is damaged", self.describe()))
                });
                b.fill(0);
                key.map(Some)
            }
        }
    }

    fn save(&self, name: &str, seed: &[u8; 32]) -> Result<()> {
        self.save_bytes(name, seed)
    }
}

/// Key names become keychain accounts and file names, so they are kept to a safe alphabet.
pub fn check_key_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(format!("invalid key name {name:?}")))
    }
}

// Every entry is base64url text, so a device seed reads the same as before (32 bytes) and other
// entries (strict hooks' secrets) fit the keychain's text values.
fn encode_bytes(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_bytes(text: &str, where_: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text.trim())
        .map_err(|_| Error::KeyStore(format!("a key in {where_} is damaged")))
}

/// The OS keychain: macOS Keychain, the Secret Service on Linux, Credential Manager on Windows.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeychainStore;

impl KeychainStore {
    /// Whether this platform's keychain can be opened at all.
    pub fn available() -> bool {
        keyring::Entry::store_status().is_ok()
    }

    fn entry(name: &str) -> Result<keyring::Entry> {
        check_key_name(name)?;
        keyring::Entry::new(KEYCHAIN_SERVICE, name).map_err(keychain_error)
    }
}

fn keychain_error(e: keyring::Error) -> Error {
    Error::KeyStore(format!("the keychain refused: {e}"))
}

impl KeyStore for KeychainStore {
    fn describe(&self) -> String {
        "the keychain".into()
    }

    fn load_bytes(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match Self::entry(name)?.get_password() {
            Ok(text) => decode_bytes(&text, "the keychain").map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(keychain_error(e)),
        }
    }

    fn save_bytes(&self, name: &str, bytes: &[u8]) -> Result<()> {
        Self::entry(name)?
            .set_password(&encode_bytes(bytes))
            .map_err(keychain_error)
    }

    fn delete(&self, name: &str) -> Result<()> {
        match Self::entry(name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(keychain_error(e)),
        }
    }
}

/// A file per key in a directory, mode 0600 inside a 0700 directory. Reading refuses a file whose
/// permissions let anyone else read or write it.
#[derive(Debug, Clone)]
pub struct FileKeyStore {
    dir: PathBuf,
}

impl FileKeyStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        FileKeyStore { dir: dir.into() }
    }

    pub fn path(&self, name: &str) -> Result<PathBuf> {
        check_key_name(name)?;
        Ok(self.dir.join(format!("{name}.key")))
    }
}

/// Refuse a key file that isn't a regular file, that another user owns, or that group or others can
/// read or write.
#[cfg(unix)]
fn check_private(path: &Path) -> Result<()> {
    check_private_for(path, rustix::process::getuid().as_raw())
}

#[cfg(unix)]
fn check_private_for(path: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(Error::KeyStore(format!(
            "refusing to read {}: it isn't a regular file",
            path.display()
        )));
    }
    if meta.uid() != uid {
        return Err(Error::KeyStore(format!(
            "refusing to read {}: it belongs to another user (uid {}), so it may not be the key \
             this computer saved. Log in again and revoke this device from another one",
            path.display(),
            meta.uid()
        )));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::KeyStore(format!(
            "refusing to read {}: its permissions are {mode:o}, so other users may have read it. \
             If only you can log in to this computer, run `chmod 600 {}`; otherwise log in again \
             and revoke this device from another one",
            path.display(),
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(Error::KeyStore(format!(
            "refusing to read {}: it isn't a regular file",
            path.display()
        )));
    }
    // The folder's access list is owner-only (narrowed now if it was made before that, or
    // widened since), and the key file grants no one else anything of its own.
    #[cfg(windows)]
    {
        if let Some(dir) = path.parent() {
            fsutil::ensure_private_dir(dir)?;
        }
        if !fsutil::owner_only(path)? {
            return Err(Error::KeyStore(format!(
                "refusing to read {}: its access list lets other users read it. Log in again and \
                 revoke this device from another one",
                path.display()
            )));
        }
    }
    Ok(())
}

impl KeyStore for FileKeyStore {
    fn describe(&self) -> String {
        format!("a private file in {}", self.dir.display())
    }

    fn load_bytes(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path(name)?;
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }
        check_private(&path)?;
        let text = std::fs::read_to_string(&path)?;
        decode_bytes(&text, &path.display().to_string()).map(Some)
    }

    fn save_bytes(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let path = self.path(name)?;
        fsutil::create_private_dir(&self.dir)?;
        fsutil::write_atomic(&path, encode_bytes(bytes).as_bytes(), true)
    }

    fn delete(&self, name: &str) -> Result<()> {
        match std::fs::remove_file(self.path(name)?) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }
}

/// Keys in memory only, for tests.
#[derive(Debug, Default)]
pub struct MemoryKeyStore {
    keys: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryKeyStore {
    fn describe(&self) -> String {
        "memory".into()
    }

    fn load_bytes(&self, name: &str) -> Result<Option<Vec<u8>>> {
        check_key_name(name)?;
        Ok(self.keys.lock().expect("key map").get(name).cloned())
    }

    fn save_bytes(&self, name: &str, bytes: &[u8]) -> Result<()> {
        check_key_name(name)?;
        self.keys
            .lock()
            .expect("key map")
            .insert(name.to_string(), bytes.to_vec());
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<()> {
        self.keys.lock().expect("key map").remove(name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::temp_dir;

    #[test]
    fn memory_store_round_trips() {
        let store = MemoryKeyStore::new();
        let key = DeviceKey::generate().unwrap();
        key.save(&store, "dev").unwrap();
        let back = DeviceKey::load(&store, "dev").unwrap().unwrap();
        assert_eq!(back.public_key(), key.public_key());
        assert_eq!(key.public_key().len(), 43);
        store.delete("dev").unwrap();
        assert!(DeviceKey::load(&store, "dev").unwrap().is_none());
    }

    #[test]
    fn key_names_cannot_escape_the_directory() {
        let store = FileKeyStore::new(std::env::temp_dir());
        assert!(store.path("../etc/passwd").is_err());
        assert!(store.path("").is_err());
        assert!(store.path("key_ok-1").is_ok());
    }

    #[test]
    fn file_store_round_trips_with_0600() {
        let dir = temp_dir("rt");
        let store = FileKeyStore::new(dir.join("keys"));
        assert!(DeviceKey::load(&store, "k").unwrap().is_none());
        let key = DeviceKey::generate().unwrap();
        key.save(&store, "k").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.path("k").unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
            let dmode = std::fs::metadata(dir.join("keys"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(dmode & 0o777, 0o700);
        }
        let back = DeviceKey::load(&store, "k").unwrap().unwrap();
        assert_eq!(back.public_key(), key.public_key());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_store_refuses_a_key_others_can_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perm");
        let store = FileKeyStore::new(dir.join("keys"));
        DeviceKey::generate().unwrap().save(&store, "k").unwrap();
        let path = store.path("k").unwrap();
        for mode in [0o644, 0o640, 0o604, 0o660, 0o606] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = DeviceKey::load(&store, "k").unwrap_err().to_string();
            assert!(err.contains("refusing to read"), "{mode:o}: {err}");
            assert!(err.contains("chmod 600"), "{err}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(DeviceKey::load(&store, "k").unwrap().is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_store_refuses_a_key_another_user_owns() {
        use std::os::unix::fs::MetadataExt;
        let dir = temp_dir("owner");
        let store = FileKeyStore::new(dir.join("keys"));
        DeviceKey::generate().unwrap().save(&store, "k").unwrap();
        let path = store.path("k").unwrap();
        let mine = std::fs::metadata(&path).unwrap().uid();
        assert_eq!(mine, rustix::process::getuid().as_raw());
        check_private_for(&path, mine).unwrap();
        // The same file, checked as if this process ran as someone else.
        let err = check_private_for(&path, mine.wrapping_add(1))
            .unwrap_err()
            .to_string();
        assert!(err.contains("belongs to another user"), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_store_refuses_a_symlink() {
        let dir = temp_dir("link");
        let store = FileKeyStore::new(dir.join("keys"));
        DeviceKey::generate().unwrap().save(&store, "real").unwrap();
        std::os::unix::fs::symlink(store.path("real").unwrap(), store.path("link").unwrap())
            .unwrap();
        let err = DeviceKey::load(&store, "link").unwrap_err().to_string();
        assert!(err.contains("isn't a regular file"), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
