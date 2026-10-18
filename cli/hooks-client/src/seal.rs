//! Sealed events (PROTOCOL §5): the device's X25519 sealing key, opening HPKE envelopes (RFC 9180:
//! DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode; the `hpke` crate), checking
//! the relay's Ed25519 signature over each envelope with the key pinned at login, and, for strict
//! hooks, verifying the provider's own signature ([`crate::presets`]).
//!
//! [`Opener::open`] turns an envelope back into an [`Event`] with `headers`, `contentType` and
//! `body` restored, so whatever consumes the stream (the CLI's `listen`, an automation runner)
//! never sees an envelope. [`seal_event`] is the relay's side, for tests and tools.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::keys::KeyStore;
use crate::presets;
use crate::types::{Event, Sealed, decode_base64_lenient};
use crate::{Error, Result};

type Kem = X25519HkdfSha256;

/// HPKE `info`.
pub const SEAL_INFO: &[u8] = b"00hooks seal v1";
/// The first line of the relay's envelope signature.
pub const ENVELOPE_SIG_VERSION: &str = "00hooks-envelope-v1";

/// A sealing key's id: the first 16 bytes of `SHA-256("00hooks-seal-kid-v1\n" ‖ key)`, base64url.
pub fn seal_kid(public_key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"00hooks-seal-kid-v1\n");
    h.update(public_key);
    URL_SAFE_NO_PAD.encode(&h.finalize()[..16])
}

/// HPKE associated data: the hook, the seq and the event id.
pub fn seal_aad(hook_id: &str, seq: u64, id: &str) -> Vec<u8> {
    format!("00hooks-seal-v1\n{hook_id}\n{seq}\n{id}").into_bytes()
}

/// A device's X25519 sealing key. The private half never leaves the machine.
pub struct SealKey {
    secret: <Kem as hpke::Kem>::PrivateKey,
    public: [u8; 32],
}

impl SealKey {
    /// A new random key.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::KeyStore(format!("no randomness: {e}")))?;
        // DeriveKeyPair (RFC 9180 §7.1.3) from 32 random bytes: a uniformly random X25519 key.
        let (secret, public) = Kem::derive_keypair(&seed);
        seed.fill(0);
        Ok(SealKey {
            public: public.to_bytes().into(),
            secret,
        })
    }

    /// The key from its 32 private bytes (as stored).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let secret = <Kem as hpke::Kem>::PrivateKey::from_bytes(bytes)
            .map_err(|_| Error::KeyStore("the sealing key is damaged".into()))?;
        let public = Kem::sk_to_pk(&secret).to_bytes().into();
        Ok(SealKey { secret, public })
    }

    fn private_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes().into()
    }

    /// The public key, unpadded base64url (43 characters): `sealKey` in PROTOCOL §2.
    pub fn public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public)
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public
    }

    pub fn kid(&self) -> String {
        seal_kid(&self.public)
    }

    /// The key-store name it is kept under.
    pub fn store_name(kid: &str) -> String {
        format!("seal-{kid}")
    }

    pub fn save(&self, store: &dyn KeyStore) -> Result<()> {
        let mut bytes = self.private_bytes();
        let r = store.save(&Self::store_name(&self.kid()), &bytes);
        bytes.fill(0);
        r
    }

    pub fn load(store: &dyn KeyStore, kid: &str) -> Result<Option<Self>> {
        match store.load(&Self::store_name(kid))? {
            None => Ok(None),
            Some(mut bytes) => {
                let key = Self::from_bytes(&bytes);
                bytes.fill(0);
                let key = key?;
                if key.kid() != kid {
                    return Err(Error::KeyStore(format!(
                        "the sealing key stored as {kid} has another id"
                    )));
                }
                Ok(Some(key))
            }
        }
    }
}

impl fmt::Debug for SealKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealKey({})", self.kid())
    }
}

/// What is sealed (PROTOCOL §5): the content of a delivery.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SealedContent {
    pub headers: BTreeMap<String, String>,
    pub content_type: Option<String>,
    /// Strict hooks only: the public URL the relay was reached at.
    pub url: Option<String>,
    /// The relay answered this delivery with the hook's offline notice (PROTOCOL §4a).
    pub notice: bool,
    /// Where it came from, as the edge saw it (PROTOCOL §4b).
    pub origin: Option<crate::types::Origin>,
    pub body: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContentMeta {
    headers: BTreeMap<String, String>,
    content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    notice: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin: Option<crate::types::Origin>,
}

/// The plaintext: the JSON of everything but the body, `\n`, then the body's raw bytes.
pub fn encode_content(c: &SealedContent) -> Vec<u8> {
    let meta = ContentMeta {
        headers: c.headers.clone(),
        content_type: c.content_type.clone(),
        url: c.url.clone(),
        notice: c.notice,
        origin: c.origin.clone().filter(|o| !o.is_empty()),
    };
    let mut out = serde_json::to_vec(&meta).expect("json");
    out.push(b'\n');
    out.extend_from_slice(&c.body);
    out
}

pub fn decode_content(pt: &[u8]) -> std::result::Result<SealedContent, String> {
    let nl = pt
        .iter()
        .position(|&b| b == b'\n')
        .ok_or("the sealed content has no boundary")?;
    let meta: ContentMeta = serde_json::from_slice(&pt[..nl])
        .map_err(|e| format!("the sealed content's header isn't readable: {e}"))?;
    Ok(SealedContent {
        headers: meta.headers,
        content_type: meta.content_type,
        url: meta.url,
        notice: meta.notice,
        origin: meta.origin,
        body: pt[nl + 1..].to_vec(),
    })
}

/// The string the relay signs for one envelope (PROTOCOL §5).
pub fn envelope_sig_string(device_id: &str, e: &Event, kid: &str, enc: &str, ct: &[u8]) -> String {
    let event_type = match &e.event_type {
        None => "-".to_string(),
        Some(t) => URL_SAFE_NO_PAD.encode(t.as_bytes()),
    };
    let ct_hash: String = Sha256::digest(ct)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut lines = vec![
        ENVELOPE_SIG_VERSION.to_string(),
        device_id.to_string(),
        e.seq.to_string(),
        e.id.clone(),
        e.hook_id.clone(),
        e.received_at.to_string(),
        if e.verified { "1" } else { "0" }.into(),
        if e.strict { "1" } else { "0" }.into(),
        e.preset.clone(),
        event_type,
        kid.to_string(),
        enc.to_string(),
        ct_hash,
    ];
    // A released event (PROTOCOL §4b) says so, signed.
    if e.held {
        lines.push("held".into());
    }
    lines.join("\n")
}

/// The associated data of an event the relay's screen held (PROTOCOL §4b): `held` stands where the
/// seq would be, since it had none when it was sealed.
pub fn held_aad(hook_id: &str, id: &str) -> Vec<u8> {
    format!("00hooks-seal-v1\n{hook_id}\nheld\n{id}").into_bytes()
}

/// The associated data an event was sealed with: held, or at its seq.
pub fn event_aad(e: &Event) -> Vec<u8> {
    if e.held {
        held_aad(&e.hook_id, &e.id)
    } else {
        seal_aad(&e.hook_id, e.seq, &e.id)
    }
}

/// A strict hook's verification, as this device keeps it (in the key store, beside the device keys).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StrictHook {
    /// The hook's `verify` object (preset and non-secret fields; `publicKey` for Ed25519).
    pub verify: Value,
    /// Every secret that verifies, newest first.
    pub secrets: Vec<String>,
}

impl StrictHook {
    pub fn store_name(hook_id: &str) -> String {
        format!("strict-{hook_id}")
    }

    pub fn load(store: &dyn KeyStore, hook_id: &str) -> Result<Option<Self>> {
        match store.load_bytes(&Self::store_name(hook_id))? {
            None => Ok(None),
            Some(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| {
                Error::KeyStore(format!("the strict-mode secret for {hook_id} is damaged"))
            }),
        }
    }

    pub fn save(&self, store: &dyn KeyStore, hook_id: &str) -> Result<()> {
        store.save_bytes(
            &Self::store_name(hook_id),
            &serde_json::to_vec(self).expect("json"),
        )
    }
}

impl fmt::Display for StrictHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StrictHook({} secrets)", self.secrets.len())
    }
}

/// Why an event didn't open, and whether trying again later can help.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFailure {
    /// It is forged, changed, replayed, unreadable or doesn't verify: it never will.
    Refused,
    /// This device lacks what opens it (the sealing key it names, a strict hook's secret): it
    /// opens once that is added (`00hooks hooks secret`, a restored key store).
    Missing,
    /// The key store (or the replay cache) couldn't be read or written just now, a locked keychain
    /// say: it opens when that works again.
    Unavailable,
}

/// An event that didn't open: a plain sentence (never payload content) and its [`OpenFailure`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenError {
    pub failure: OpenFailure,
    pub message: String,
    /// It failed as a strict hook's delivery (verified, or meant to be, on this device).
    pub strict: bool,
}

impl OpenError {
    pub fn refused(m: impl Into<String>) -> Self {
        OpenError {
            failure: OpenFailure::Refused,
            message: m.into(),
            strict: false,
        }
    }

    pub fn missing(m: impl Into<String>) -> Self {
        OpenError {
            failure: OpenFailure::Missing,
            message: m.into(),
            strict: false,
        }
    }

    pub fn unavailable(m: impl Into<String>) -> Self {
        OpenError {
            failure: OpenFailure::Unavailable,
            message: m.into(),
            strict: false,
        }
    }

    /// Whether the event may open later, so it must be kept whole rather than refused.
    pub fn recoverable(&self) -> bool {
        self.failure != OpenFailure::Refused
    }
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OpenError {}

impl From<&str> for OpenError {
    fn from(m: &str) -> Self {
        OpenError::refused(m)
    }
}

impl From<String> for OpenError {
    fn from(m: String) -> Self {
        OpenError::refused(m)
    }
}

/// Where an [`Opener`] finds strict hooks' secrets.
pub trait StrictSecrets: Send + Sync {
    fn get(&self, hook_id: &str) -> Result<Option<StrictHook>>;

    /// Whether this device keeps a strict secret for `hook_id`, asked for **every** event: when it
    /// does, the event is verified here whatever the relay's metadata says, so a relay can't switch
    /// strict mode off. The default reads the secret; an index can answer without touching the
    /// key store ([`IndexedStrictSecrets`]).
    fn holds(&self, hook_id: &str) -> Result<bool> {
        Ok(self.get(hook_id)?.is_some())
    }
}

/// Strict secrets in a key store. [`StrictSecrets::holds`] reads the key store for every event;
/// [`IndexedStrictSecrets`] doesn't.
pub struct StoreStrictSecrets(pub std::sync::Arc<dyn KeyStore>);

impl StrictSecrets for StoreStrictSecrets {
    fn get(&self, hook_id: &str) -> Result<Option<StrictHook>> {
        StrictHook::load(self.0.as_ref(), hook_id)
    }
}

/// The ids of the hooks this device keeps strict secrets for, in a private file beside the state
/// (no secret in it). Written when a secret is kept (`hooks create --strict`, `hooks secret`), and
/// by [`IndexedStrictSecrets`] when it finds one the index lacks (a secret kept before the index).
#[derive(Debug, Clone)]
pub struct StrictIndex {
    path: PathBuf,
}

#[derive(Serialize, Deserialize, Default)]
struct StrictIndexFile {
    hooks: BTreeSet<String>,
}

impl StrictIndex {
    /// The file name inside a state directory.
    pub const FILE: &'static str = "strict-hooks.json";

    pub fn new(path: impl Into<PathBuf>) -> Self {
        StrictIndex { path: path.into() }
    }

    fn read(&self) -> Result<StrictIndexFile> {
        match std::fs::read(&self.path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|_| {
                Error::Store(format!(
                    "{} is damaged; strict hooks can't be told apart until it's fixed",
                    self.path.display()
                ))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StrictIndexFile::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn contains(&self, hook_id: &str) -> Result<bool> {
        Ok(self.read()?.hooks.contains(hook_id))
    }

    pub fn add(&self, hook_id: &str) -> Result<()> {
        let mut f = self.read()?;
        if f.hooks.insert(hook_id.to_string()) {
            crate::fsutil::write_atomic(&self.path, &serde_json::to_vec(&f).expect("json"), true)?;
        }
        Ok(())
    }
}

/// Strict secrets in a key store, with a [`StrictIndex`] saying which hooks have one, so an event of
/// an ordinary hook never touches the key store, and one of a strict hook is verified here even
/// when the relay's metadata claims it isn't strict.
pub struct IndexedStrictSecrets {
    pub store: std::sync::Arc<dyn KeyStore>,
    pub index: StrictIndex,
}

impl StrictSecrets for IndexedStrictSecrets {
    fn get(&self, hook_id: &str) -> Result<Option<StrictHook>> {
        let found = StrictHook::load(self.store.as_ref(), hook_id)?;
        if found.is_some() {
            // Heals an index that predates the secret (or was lost).
            self.index.add(hook_id)?;
        }
        Ok(found)
    }

    fn holds(&self, hook_id: &str) -> Result<bool> {
        self.index.contains(hook_id)
    }
}

/// How long a strict event's replay mark is kept: the relay's retention (7 days) and a margin. A
/// strict event received longer ago than this is refused, since its mark may be gone.
pub const REPLAY_WINDOW_MS: i64 = 8 * 86_400_000;
/// The most replay marks kept; the oldest go first.
pub const REPLAY_MAX: usize = 200_000;
/// How far in the future (by this device's clock) a strict event's `receivedAt` may be.
pub const FUTURE_SKEW_MS: i64 = 10 * 60_000;

#[derive(Serialize, Deserialize)]
struct ReplayLine {
    k: String,
    id: String,
    at: i64,
}

/// The device's own replay marks for strict events (PROTOCOL §3): one per verified delivery, the
/// hash of its hook and body, with the event id it arrived as. The same body again under another
/// id within [`REPLAY_WINDOW_MS`] is a replay, whoever sends it: the relay's dedupe can't be relied
/// on in strict mode, where the relay isn't trusted. Kept in memory, or durably in a private JSONL
/// file ([`ReplayCache::at`], read when first needed, by the one process that streams).
pub struct ReplayCache {
    path: Option<PathBuf>,
    file: Option<std::fs::File>,
    loaded: bool,
    by_key: HashMap<String, (String, i64)>,
    order: VecDeque<String>,
}

impl fmt::Debug for ReplayCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReplayCache({} marks)", self.by_key.len())
    }
}

impl ReplayCache {
    /// The file name inside a state directory.
    pub const FILE: &'static str = "strict-replay.jsonl";

    /// Marks in memory only: forgotten on restart.
    pub fn memory() -> Self {
        ReplayCache {
            path: None,
            file: None,
            loaded: true,
            by_key: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Marks kept in `path`, read (and compacted) when the first strict event needs them, so a
    /// command that never opens one never touches the file.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        ReplayCache {
            path: Some(path.into()),
            loaded: false,
            ..ReplayCache::memory()
        }
    }

    /// Marks kept in `path`, read now.
    pub fn open(path: impl Into<PathBuf>, now_ms: i64) -> Result<Self> {
        let mut c = ReplayCache::at(path);
        c.load(now_ms)?;
        Ok(c)
    }

    /// Read the file (dropping marks past the window and torn lines), rewrite it with what is
    /// left, then keep it open for appending.
    fn load(&mut self, now_ms: i64) -> Result<()> {
        let Some(path) = self.path.clone() else {
            self.loaded = true;
            return Ok(());
        };
        if let Ok(f) = std::fs::File::open(&path) {
            use std::io::BufRead;
            for line in std::io::BufReader::new(f).split(b'\n') {
                if let Ok(l) = serde_json::from_slice::<ReplayLine>(&line?)
                    && l.at >= now_ms - REPLAY_WINDOW_MS
                {
                    self.insert(l.k, l.id, l.at);
                }
            }
        }
        let mut out = Vec::new();
        for k in &self.order {
            let (id, at) = &self.by_key[k];
            serde_json::to_writer(
                &mut out,
                &ReplayLine {
                    k: k.clone(),
                    id: id.clone(),
                    at: *at,
                },
            )
            .expect("json");
            out.push(b'\n');
        }
        crate::fsutil::write_atomic(&path, &out, true)?;
        self.file = Some(crate::fsutil::open_append(&path)?);
        self.loaded = true;
        Ok(())
    }

    /// The mark of a delivery: its hook and the hash of its body. The body is what the provider
    /// signed (with any signed timestamp or id), so nobody can change it without the signature
    /// failing, and a provider's retry of the same delivery has the same mark.
    pub fn mark(hook_id: &str, body: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(b"00hooks-replay-v1\n");
        h.update(hook_id.as_bytes());
        h.update(b"\n");
        h.update(Sha256::digest(body));
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn insert(&mut self, k: String, id: String, at: i64) {
        if self.by_key.insert(k.clone(), (id, at)).is_none() {
            self.order.push_back(k);
        }
        while self.order.len() > REPLAY_MAX {
            if let Some(old) = self.order.pop_front() {
                self.by_key.remove(&old);
            }
        }
    }

    /// Notes event `id`, received at `at`, under `mark` (`now_ms` ages the file's marks when it is
    /// first read). `Ok(false)` when another event id already carried the same mark within the
    /// window: a replay. The same id again (a redelivery after a lost acknowledgement, a release)
    /// is not one.
    pub fn note(&mut self, mark: &str, id: &str, at: i64, now_ms: i64) -> Result<bool> {
        if !self.loaded {
            self.load(now_ms)?;
        }
        if let Some((seen_id, seen_at)) = self.by_key.get(mark)
            && (at - seen_at).abs() <= REPLAY_WINDOW_MS
        {
            return Ok(seen_id == id);
        }
        if let Some(f) = &mut self.file {
            use std::io::Write;
            let mut line = serde_json::to_vec(&ReplayLine {
                k: mark.to_string(),
                id: id.to_string(),
                at,
            })
            .expect("json");
            line.push(b'\n');
            f.write_all(&line)?;
            f.sync_data()?;
        }
        self.insert(mark.to_string(), id.to_string(), at);
        Ok(true)
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

/// Opens this device's envelopes: its sealing keys by kid, the relay key pinned at login, and the
/// strict hooks' secrets.
pub struct Opener {
    device_id: String,
    relay_key: Option<VerifyingKey>,
    keys: HashMap<String, SealKey>,
    strict: Option<Box<dyn StrictSecrets>>,
    replay: Mutex<ReplayCache>,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl fmt::Debug for Opener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut kids: Vec<_> = self.keys.keys().collect();
        kids.sort();
        write!(
            f,
            "Opener({}, relay key pinned: {}, kids: {kids:?})",
            self.device_id,
            self.relay_key.is_some()
        )
    }
}

/// Parses a relay key (unpadded base64url Ed25519 public key).
pub fn parse_relay_key(key: &str) -> Result<VerifyingKey> {
    URL_SAFE_NO_PAD
        .decode(key.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .ok_or_else(|| Error::Protocol("the relay's key (relayKey) isn't an Ed25519 key".into()))
}

impl Opener {
    /// `relay_key` is the pinned `relayKey`; without one, nothing opens (a pre-protocol-2 login).
    pub fn new(device_id: &str, relay_key: Option<&str>) -> Result<Self> {
        Ok(Opener {
            device_id: device_id.to_string(),
            relay_key: relay_key.map(parse_relay_key).transpose()?,
            keys: HashMap::new(),
            strict: None,
            replay: Mutex::new(ReplayCache::memory()),
            now: Arc::new(crate::api::system_now_ms),
        })
    }

    pub fn add_key(&mut self, key: SealKey) {
        self.keys.insert(key.kid(), key);
    }

    pub fn with_strict(mut self, strict: Box<dyn StrictSecrets>) -> Self {
        self.strict = Some(strict);
        self
    }

    /// Keep strict events' replay marks here (durable when opened from a file); the default is in
    /// memory, forgotten on restart.
    pub fn with_replay_cache(mut self, cache: ReplayCache) -> Self {
        self.replay = Mutex::new(cache);
        self
    }

    /// The clock strict events' `receivedAt` is checked against (Unix ms); the system's by default.
    pub fn with_clock(mut self, now: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.now = Arc::new(now);
        self
    }

    /// Whether this device holds the sealing key `kid`.
    pub fn holds(&self, kid: &str) -> bool {
        self.keys.contains_key(kid)
    }

    pub fn has_relay_key(&self) -> bool {
        self.relay_key.is_some()
    }

    /// Opens one event: checks the relay's signature, opens the envelope, and verifies a strict
    /// hook's provider signature. The error is a plain sentence (never payload content) for the
    /// quarantine record, and says whether the event may open later ([`OpenError::recoverable`]).
    pub fn open(&self, mut e: Event) -> std::result::Result<Event, OpenError> {
        let sealed = e.sealed.take().ok_or(
            "the event arrived unsealed; a protocol 2 relay seals every event, so it was refused",
        )?;
        let relay_key = self.relay_key.as_ref().ok_or_else(|| {
            OpenError::missing(
                "no relay key is pinned for this login, so envelopes can't be checked; run \
                 `00hooks devices seal-key`",
            )
        })?;
        let ct = decode_base64_lenient(&sealed.ct).map_err(|_| "the ciphertext isn't base64")?;
        let sig = e
            .sig
            .take()
            .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
            .and_then(|b| Signature::from_slice(&b).ok())
            .ok_or("the envelope has no readable relay signature")?;
        let signed = envelope_sig_string(&self.device_id, &e, &sealed.kid, &sealed.enc, &ct);
        relay_key
            .verify_strict(signed.as_bytes(), &sig)
            .map_err(|_| "the relay's signature doesn't verify: it wasn't sealed by the relay this device logged in to, or it was changed")?;
        let key = self.keys.get(&sealed.kid).ok_or_else(|| {
            OpenError::missing(format!(
                "it is sealed to key {}, which this device doesn't hold",
                sealed.kid
            ))
        })?;
        let enc = URL_SAFE_NO_PAD
            .decode(&sealed.enc)
            .ok()
            .and_then(|b| <Kem as hpke::Kem>::EncappedKey::from_bytes(&b).ok())
            .ok_or("the envelope's encapsulated key isn't readable")?;
        let pt = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Base,
            &key.secret,
            &enc,
            SEAL_INFO,
            &ct,
            &event_aad(&e),
        )
        .map_err(|_| "the envelope doesn't open with this device's key")?;
        let mut content = decode_content(&pt)?;
        // Strict whenever this device keeps a strict secret for the hook, whatever the relay's
        // (signed, but relay-written) metadata says: a relay can't switch strict mode off.
        let strict_here = e.strict
            || match &self.strict {
                None => false,
                Some(s) => s.holds(&e.hook_id).map_err(|err| {
                    OpenError::unavailable(format!(
                        "couldn't tell whether {} is a strict hook ({err})",
                        e.hook_id
                    ))
                })?,
            };
        if strict_here {
            self.verify_strict(&mut e, &mut content)
                .map_err(|err| OpenError {
                    strict: true,
                    ..err
                })?;
        }
        e.headers = content.headers;
        e.content_type = content.content_type;
        e.notice = content.notice;
        // Only the sealed content says where it came from.
        e.origin = content.origin;
        e.body = STANDARD.encode(&content.body);
        Ok(e)
    }

    fn verify_strict(
        &self,
        e: &mut Event,
        content: &mut SealedContent,
    ) -> std::result::Result<(), OpenError> {
        let hook = match &self.strict {
            None => None,
            Some(s) => s.get(&e.hook_id).map_err(|err| {
                OpenError::unavailable(format!(
                    "couldn't read the strict-mode secret for {} ({err})",
                    e.hook_id
                ))
            })?,
        }
        .ok_or_else(|| {
            OpenError::missing(format!(
                "{} is a strict hook and this device has no secret for it; add it with \
                 `00hooks hooks secret {}`",
                e.hook_id, e.hook_id
            ))
        })?;
        // The preset this device verifies with is its own, kept when the secret was; the relay's
        // (signed) preset must agree, or the relay is describing some other hook.
        let preset = hook
            .verify
            .get("preset")
            .and_then(Value::as_str)
            .unwrap_or("");
        if preset != e.preset {
            return Err(OpenError::refused(format!(
                "the relay calls strict hook {} a {:?} hook, but this device verifies it as {:?}",
                e.hook_id, e.preset, preset
            )));
        }
        let verdict = presets::verify_strict(
            &hook.verify,
            &hook.secrets,
            &presets::Delivery {
                headers: &content.headers,
                body: &content.body,
                now_ms: e.received_at,
                url: content.url.as_deref(),
            },
        );
        if !verdict.ok {
            return Err(OpenError::refused(format!(
                "the provider's signature doesn't verify for strict hook {} (forged, replayed \
                 late, or the secret on this device is wrong)",
                e.hook_id
            )));
        }
        // `receivedAt` dates the signature check; it is the relay's word, so it must be plausible
        // by this device's clock, and recent enough that its replay mark is still kept.
        let now = (self.now)();
        if e.received_at > now + FUTURE_SKEW_MS {
            return Err(OpenError::refused(format!(
                "strict event {} says it was received in the future, by this computer's clock",
                e.id
            )));
        }
        if e.received_at < now - REPLAY_WINDOW_MS {
            return Err(OpenError::refused(format!(
                "strict event {} was received more than 8 days ago, too long to check it isn't a \
                 replay",
                e.id
            )));
        }
        let mark = ReplayCache::mark(&e.hook_id, &content.body);
        let fresh = self
            .replay
            .lock()
            .expect("replay cache")
            .note(&mark, &e.id, e.received_at, now)
            .map_err(|err| {
                OpenError::unavailable(format!("couldn't keep the replay mark ({err})"))
            })?;
        if !fresh {
            return Err(OpenError::refused(format!(
                "strict event {} repeats a delivery this device already took under another id: a \
                 replay",
                e.id
            )));
        }
        // Verified: the signature has done its job, and kept beside its body it would be a
        // ready-made replay wherever the event goes next (the store, a call's body).
        for h in presets::signature_headers(&hook.verify) {
            content.headers.remove(&h);
        }
        e.verified = true;
        e.strict = true;
        if verdict.event_type.is_some() {
            e.event_type = verdict.event_type;
        }
        Ok(())
    }
}

/// The relay's side (PROTOCOL §5): seals `content` to one device's key and signs the envelope. The
/// relay itself is TypeScript; this is for tests and tools. `meta` gives the routing fields.
pub fn seal_event(
    relay: &SigningKey,
    device_id: &str,
    recipient: &[u8; 32],
    meta: &Event,
    content: &SealedContent,
) -> Result<Event> {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(recipient)
        .map_err(|_| Error::Invalid("not an X25519 public key".into()))?;
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeS::Base,
        &pk,
        SEAL_INFO,
        &encode_content(content),
        &event_aad(meta),
    )
    .map_err(|e| Error::Invalid(format!("sealing failed: {e:?}")))?;
    let kid = seal_kid(recipient);
    let enc = URL_SAFE_NO_PAD.encode(enc.to_bytes());
    let mut e = meta.clone();
    e.headers = BTreeMap::new();
    e.content_type = None;
    e.body = String::new();
    let sig = relay.sign(envelope_sig_string(device_id, &e, &kid, &enc, &ct).as_bytes());
    e.sealed = Some(Sealed {
        kid,
        enc,
        ct: STANDARD.encode(&ct),
    });
    e.sig = Some(URL_SAFE_NO_PAD.encode(sig.to_bytes()));
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MemoryKeyStore;
    use serde_json::json;

    const RFC: &str = include_str!("../../../fixtures/hpke-rfc9180-a2.json");
    const INTEROP: &str = include_str!("../../../fixtures/seal-interop.v1.json");

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc9180_a2_derives_the_keys_and_opens_the_published_ciphertexts() {
        let v: Value = serde_json::from_str(RFC).unwrap();
        let s = |k: &str| unhex(v[k].as_str().unwrap());
        let (sk, pk) = Kem::derive_keypair(&s("ikmR"));
        assert_eq!(sk.to_bytes().to_vec(), s("skRm"));
        assert_eq!(pk.to_bytes().to_vec(), s("pkRm"));
        let (_, pk_e) = Kem::derive_keypair(&s("ikmE"));
        assert_eq!(pk_e.to_bytes().to_vec(), s("pkEm"));
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&s("enc")).unwrap();
        let mut ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Base,
            &sk,
            &enc,
            &s("info"),
        )
        .unwrap();
        // Sequence numbers 0, 1, 2 in order: the context's nonce counter advances with each open.
        for x in v["encryptions"].as_array().unwrap() {
            let pt = ctx
                .open(
                    &unhex(x["ct"].as_str().unwrap()),
                    &unhex(x["aad"].as_str().unwrap()),
                )
                .unwrap();
            assert_eq!(pt, unhex(x["pt"].as_str().unwrap()), "seq {}", x["seq"]);
        }
    }

    fn interop() -> (Value, Opener) {
        let v: Value = serde_json::from_str(INTEROP).unwrap();
        let sk: [u8; 32] = URL_SAFE_NO_PAD
            .decode(v["devicePrivateKey"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let key = SealKey::from_bytes(&sk).unwrap();
        assert_eq!(key.public_key(), v["devicePublicKey"].as_str().unwrap());
        assert_eq!(key.kid(), v["kid"].as_str().unwrap());
        let mut opener = Opener::new(
            v["deviceId"].as_str().unwrap(),
            Some(v["relayKey"].as_str().unwrap()),
        )
        .unwrap();
        opener.add_key(key);
        (v, opener)
    }

    /// One strict hook's secret (`hk_000000000000000000000000h3` for the interop sample, `hk_x` in
    /// the other tests).
    struct Fixed(&'static str, StrictHook);
    impl StrictSecrets for Fixed {
        fn get(&self, hook_id: &str) -> Result<Option<StrictHook>> {
            Ok((hook_id == self.0).then(|| self.1.clone()))
        }
    }

    /// A key store that is locked: every read fails.
    struct Locked;
    impl StrictSecrets for Locked {
        fn get(&self, _: &str) -> Result<Option<StrictHook>> {
            Err(Error::KeyStore("the keychain is locked".into()))
        }
    }

    const T: i64 = 1_792_233_600;
    const SECRET: &str = "whsec_device_only_secret";

    fn stripe_sig(t: i64, body: &[u8]) -> String {
        let mut mac =
            <hmac::Hmac<Sha256> as hmac::KeyInit>::new_from_slice(SECRET.as_bytes()).unwrap();
        hmac::Mac::update(&mut mac, format!("{t}.").as_bytes());
        hmac::Mac::update(&mut mac, body);
        hmac::Mac::finalize(mac)
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// A relay, a device whose opener keeps `hk_x`'s strict Stripe secret (with its clock at `T`
    /// plus a minute), and a genuine Stripe delivery for it.
    fn strict_setup() -> (SigningKey, [u8; 32], Opener, Event, SealedContent) {
        let relay = SigningKey::from_bytes(&[3; 32]);
        let key = SealKey::generate().unwrap();
        let mut opener = Opener::new(
            "dev_1",
            Some(&URL_SAFE_NO_PAD.encode(relay.verifying_key().as_bytes())),
        )
        .unwrap();
        let pk = key.public_bytes();
        opener.add_key(key);
        let opener = opener
            .with_strict(Box::new(Fixed(
                "hk_x",
                StrictHook {
                    verify: json!({"preset": "stripe", "strict": true}),
                    secrets: vec![SECRET.into()],
                },
            )))
            .with_clock(|| T * 1000 + 60_000);
        let body = br#"{"id":"evt_1","type":"invoice.paid"}"#;
        let meta = Event {
            seq: 7,
            id: "evt_x".into(),
            hook_id: "hk_x".into(),
            received_at: T * 1000 + 30_000,
            verified: false,
            strict: true,
            preset: "stripe".into(),
            ..Event::default()
        };
        let content = SealedContent {
            headers: BTreeMap::from([
                (
                    "stripe-signature".into(),
                    format!("t={T},v1={}", stripe_sig(T, body)),
                ),
                ("user-agent".into(), "Stripe/1.0".into()),
            ]),
            content_type: Some("application/json".into()),
            url: Some("https://relay.example/h/hk_x".into()),
            notice: false,
            origin: None,
            body: body.to_vec(),
        };
        (relay, pk, opener, meta, content)
    }

    #[test]
    fn opens_every_event_the_relays_own_code_sealed_under_node() {
        let (v, opener) = interop();
        // The strict sample's signature header is a placeholder: without a matching secret it is
        // refused, which is the point of strict mode.
        let opener = opener.with_strict(Box::new(Fixed(
            "hk_000000000000000000000000h3",
            StrictHook {
                verify: json!({"preset": "stripe"}),
                secrets: vec!["whsec_not_the_one".into()],
            },
        )));
        for item in v["events"].as_array().unwrap() {
            let e: Event = serde_json::from_value(item["message"].clone()).unwrap();
            let want = &item["expect"];
            if e.strict {
                let err = opener.open(e).unwrap_err();
                assert!(err.message.contains("doesn't verify"), "{err}");
                continue;
            }
            let opened = opener.open(e.clone()).unwrap();
            assert!(opened.sealed.is_none() && opened.sig.is_none());
            assert_eq!(
                serde_json::to_value(&opened.headers).unwrap(),
                want["headers"]
            );
            assert_eq!(opened.content_type.as_deref(), want["contentType"].as_str());
            assert_eq!(opened.body, want["body"].as_str().unwrap());
            assert_eq!(opened.seq, e.seq);
            assert_eq!(opened.event_type, e.event_type);
        }
    }

    #[test]
    fn refuses_changed_metadata_another_device_and_unsealed_events() {
        let (v, opener) = interop();
        let e: Event = serde_json::from_value(v["events"][0]["message"].clone()).unwrap();
        let mut forged = e.clone();
        forged.verified = !forged.verified;
        assert!(
            opener
                .open(forged)
                .unwrap_err()
                .message
                .contains("signature")
        );
        let mut moved = e.clone();
        moved.seq += 1;
        assert!(
            opener
                .open(moved)
                .unwrap_err()
                .message
                .contains("signature")
        );
        let mut typed = e.clone();
        typed.event_type = Some("forged".into());
        assert!(
            opener
                .open(typed)
                .unwrap_err()
                .message
                .contains("signature")
        );
        // The same envelope presented to another device id: the signature names the device.
        let mut other =
            Opener::new("dev_someoneelse", Some(v["relayKey"].as_str().unwrap())).unwrap();
        other.add_key(SealKey::generate().unwrap());
        assert!(
            other
                .open(e.clone())
                .unwrap_err()
                .message
                .contains("signature")
        );
        // Signed by another relay key.
        let mut wrong_relay = Opener::new(
            v["deviceId"].as_str().unwrap(),
            Some(
                &URL_SAFE_NO_PAD
                    .encode(SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes()),
            ),
        )
        .unwrap();
        wrong_relay.add_key(interop().1.keys.into_values().next().unwrap());
        assert!(
            wrong_relay
                .open(e.clone())
                .unwrap_err()
                .message
                .contains("signature")
        );
        let mut plain = e.clone();
        plain.sealed = None;
        assert!(opener.open(plain).unwrap_err().message.contains("unsealed"));
        let no_relay = Opener::new(v["deviceId"].as_str().unwrap(), None).unwrap();
        assert!(
            no_relay
                .open(e)
                .unwrap_err()
                .message
                .contains("devices seal-key")
        );
    }

    #[test]
    fn a_released_event_opens_with_the_held_aad_and_its_held_flag_is_signed() {
        let relay = SigningKey::from_bytes(&[5; 32]);
        let key = SealKey::generate().unwrap();
        let mut opener = Opener::new(
            "dev_1",
            Some(&URL_SAFE_NO_PAD.encode(relay.verifying_key().as_bytes())),
        )
        .unwrap();
        let pk = key.public_bytes();
        opener.add_key(key);
        let meta = Event {
            seq: 9,
            id: "evt_h".into(),
            hook_id: "hk_h".into(),
            received_at: 1,
            verified: true,
            preset: "github".into(),
            held: true,
            ..Event::default()
        };
        let content = SealedContent {
            body: b"{\"a\":1}".to_vec(),
            origin: Some(crate::types::Origin {
                ip: Some("203.0.113.4".into()),
                asn: Some(64500),
                country: Some("PT".into()),
            }),
            ..SealedContent::default()
        };
        let sealed = seal_event(&relay, "dev_1", &pk, &meta, &content).unwrap();
        let opened = opener.open(sealed.clone()).unwrap();
        assert!(opened.held);
        assert_eq!(opened.origin.unwrap().asn, Some(64500));
        // Claiming it wasn't held breaks the relay's signature; so does claiming an ordinary one was.
        let mut unflagged = sealed.clone();
        unflagged.held = false;
        assert!(
            opener
                .open(unflagged)
                .unwrap_err()
                .message
                .contains("signature")
        );
        // The origin comes from the sealed content only, never the clear metadata.
        let mut plain_meta = meta.clone();
        plain_meta.held = false;
        let mut claimed =
            seal_event(&relay, "dev_1", &pk, &plain_meta, &SealedContent::default()).unwrap();
        claimed.origin = Some(crate::types::Origin {
            ip: Some("1.2.3.4".into()),
            ..Default::default()
        });
        assert_eq!(opener.open(claimed).unwrap().origin, None);
    }

    #[test]
    fn the_offline_notice_flag_is_read_from_the_sealed_content_only() {
        let relay = SigningKey::from_bytes(&[4; 32]);
        let key = SealKey::generate().unwrap();
        let mut opener = Opener::new(
            "dev_1",
            Some(&URL_SAFE_NO_PAD.encode(relay.verifying_key().as_bytes())),
        )
        .unwrap();
        let pk = key.public_bytes();
        opener.add_key(key);
        let meta = Event {
            seq: 3,
            id: "evt_n".into(),
            hook_id: "hk_n".into(),
            received_at: 1,
            verified: true,
            preset: "twilio".into(),
            ..Event::default()
        };
        let mut content = SealedContent {
            content_type: Some("application/x-www-form-urlencoded".into()),
            notice: true,
            origin: None,
            body: b"From=%2B15005550001&Body=hi".to_vec(),
            ..SealedContent::default()
        };
        let opened = opener
            .open(seal_event(&relay, "dev_1", &pk, &meta, &content).unwrap())
            .unwrap();
        assert!(opened.notice);
        content.notice = false;
        let plain = opener
            .open(seal_event(&relay, "dev_1", &pk, &meta, &content).unwrap())
            .unwrap();
        assert!(!plain.notice);
        // A flag beside the envelope (not sealed) is the sender's word, and is replaced on open.
        let mut claimed = seal_event(&relay, "dev_1", &pk, &meta, &content).unwrap();
        claimed.notice = true;
        assert!(!opener.open(claimed).unwrap().notice);
    }

    #[test]
    fn seals_and_opens_a_strict_event_verifying_the_provider_signature_at_received_at() {
        let (relay, pk, opener, meta, mut content) = strict_setup();
        let body = content.body.clone();
        let opened = opener
            .open(seal_event(&relay, "dev_1", &pk, &meta, &content).unwrap())
            .unwrap();
        assert!(opened.verified && opened.strict);
        assert_eq!(opened.event_type.as_deref(), Some("invoice.paid"));
        assert_eq!(STANDARD.decode(&opened.body).unwrap(), body);

        // A forged signature is refused; so is a genuine one six minutes before it arrived.
        content.headers.insert(
            "stripe-signature".into(),
            format!("t={T},v1={}", "0".repeat(64)),
        );
        let forged = Event {
            id: "evt_y".into(),
            ..meta.clone()
        };
        let err = opener
            .open(seal_event(&relay, "dev_1", &pk, &forged, &content).unwrap())
            .unwrap_err();
        assert!(err.message.contains("doesn't verify") && !err.recoverable());
        let late = Event {
            id: "evt_z".into(),
            received_at: (T + 360) * 1000,
            ..meta.clone()
        };
        content.headers.insert(
            "stripe-signature".into(),
            format!("t={T},v1={}", stripe_sig(T, &body)),
        );
        assert!(
            opener
                .open(seal_event(&relay, "dev_1", &pk, &late, &content).unwrap())
                .is_err()
        );
    }

    #[test]
    fn a_relay_cannot_switch_strict_mode_off_for_a_hook_this_device_keeps_a_secret_for() {
        let (relay, pk, opener, meta, mut content) = strict_setup();
        // The relay claims the hook isn't strict and that it verified a body it made up.
        content.body = br#"{"id":"evt_forged","type":"invoice.paid"}"#.to_vec();
        let downgraded = Event {
            strict: false,
            verified: true,
            ..meta.clone()
        };
        let err = opener
            .open(seal_event(&relay, "dev_1", &pk, &downgraded, &content).unwrap())
            .unwrap_err();
        assert!(err.message.contains("doesn't verify"), "{err}");
        // Nor can it relabel the hook's preset to one that proves nothing.
        let (relay, pk, opener, meta, content) = strict_setup();
        for preset in ["unverified", "token", "github"] {
            let relabelled = Event {
                preset: preset.into(),
                ..meta.clone()
            };
            let err = opener
                .open(seal_event(&relay, "dev_1", &pk, &relabelled, &content).unwrap())
                .unwrap_err();
            assert!(err.message.contains("verifies it as"), "{preset}: {err}");
        }
        // A genuine delivery marked not strict is still verified here, and handed over verified.
        let unmarked = Event {
            strict: false,
            ..meta.clone()
        };
        let opened = opener
            .open(seal_event(&relay, "dev_1", &pk, &unmarked, &content).unwrap())
            .unwrap();
        assert!(opened.verified && opened.strict);
    }

    #[test]
    fn a_strict_spec_this_device_kept_as_unverified_or_token_verifies_nothing() {
        let (relay, pk, opener, meta, content) = strict_setup();
        let _ = opener;
        for spec in [
            json!({"preset": "unverified", "strict": true}),
            json!({"preset": "token", "header": "Authorization", "strict": true}),
        ] {
            let preset = spec["preset"].as_str().unwrap().to_string();
            let mut o = Opener::new(
                "dev_1",
                Some(&URL_SAFE_NO_PAD.encode(relay.verifying_key().as_bytes())),
            )
            .unwrap()
            .with_strict(Box::new(Fixed(
                "hk_x",
                StrictHook {
                    verify: spec,
                    secrets: vec!["tok".into()],
                },
            )))
            .with_clock(|| T * 1000);
            let k = SealKey::generate().unwrap();
            let pk2 = k.public_bytes();
            o.add_key(k);
            let mut c = content.clone();
            c.headers
                .insert("authorization".into(), "Bearer tok".into());
            let e = Event {
                preset: preset.clone(),
                ..meta.clone()
            };
            let err = o
                .open(seal_event(&relay, "dev_1", &pk2, &e, &c).unwrap())
                .unwrap_err();
            assert!(err.message.contains("doesn't verify"), "{preset}: {err}");
        }
        let _ = pk;
    }

    #[test]
    fn a_strict_delivery_under_a_new_id_is_a_replay_and_the_same_id_is_not() {
        let (relay, pk, opener, meta, content) = strict_setup();
        let first = seal_event(&relay, "dev_1", &pk, &meta, &content).unwrap();
        opener.open(first.clone()).unwrap();
        // Redelivered as itself (a lost ack, a release): fine.
        opener.open(first).unwrap();
        // The same signed delivery under a new id and seq: a replay, whoever sends it.
        let again = Event {
            seq: 8,
            id: "evt_again".into(),
            ..meta.clone()
        };
        let err = opener
            .open(seal_event(&relay, "dev_1", &pk, &again, &content).unwrap())
            .unwrap_err();
        assert!(
            err.message.contains("replay") && !err.recoverable(),
            "{err}"
        );
    }

    #[test]
    fn received_at_must_be_plausible_by_the_device_clock() {
        let (relay, pk, opener, meta, content) = strict_setup();
        let opener = opener.with_clock(|| T * 1000 - 3_600_000);
        let err = opener
            .open(seal_event(&relay, "dev_1", &pk, &meta, &content).unwrap())
            .unwrap_err();
        assert!(err.message.contains("future"), "{err}");
        let opener = opener.with_clock(|| T * 1000 + REPLAY_WINDOW_MS + 60_000);
        let err = opener
            .open(seal_event(&relay, "dev_1", &pk, &meta, &content).unwrap())
            .unwrap_err();
        assert!(err.message.contains("8 days"), "{err}");
    }

    #[test]
    fn signature_headers_are_dropped_once_verified() {
        let (relay, pk, opener, meta, content) = strict_setup();
        let opened = opener
            .open(seal_event(&relay, "dev_1", &pk, &meta, &content).unwrap())
            .unwrap();
        assert!(!opened.headers.contains_key("stripe-signature"));
        assert_eq!(opened.headers["user-agent"], "Stripe/1.0");
    }

    #[test]
    fn a_missing_secret_or_a_locked_store_is_recoverable_and_says_so() {
        let (relay, pk, opener, meta, content) = strict_setup();
        let _ = opener;
        let mut bare = Opener::new(
            "dev_1",
            Some(&URL_SAFE_NO_PAD.encode(relay.verifying_key().as_bytes())),
        )
        .unwrap();
        let k = SealKey::generate().unwrap();
        let pk2 = k.public_bytes();
        bare.add_key(k);
        let sealed = seal_event(&relay, "dev_1", &pk2, &meta, &content).unwrap();
        let err = bare.open(sealed.clone()).unwrap_err();
        assert_eq!(err.failure, OpenFailure::Missing, "{err}");
        let locked = bare.with_strict(Box::new(Locked));
        let err = locked.open(sealed).unwrap_err();
        assert_eq!(err.failure, OpenFailure::Unavailable, "{err}");
        // An ordinary hook asks the store too (it may be strict here): locked is recoverable.
        let plain = Event {
            strict: false,
            verified: true,
            preset: "github".into(),
            ..meta.clone()
        };
        let err = locked
            .open(seal_event(&relay, "dev_1", &pk2, &plain, &content).unwrap())
            .unwrap_err();
        assert!(err.recoverable(), "{err}");
        // A sealing key this device doesn't hold is missing, not refused.
        let other = SealKey::generate().unwrap();
        let err = Opener::new(
            "dev_1",
            Some(&URL_SAFE_NO_PAD.encode(relay.verifying_key().as_bytes())),
        )
        .unwrap()
        .open(seal_event(&relay, "dev_1", &other.public_bytes(), &plain, &content).unwrap())
        .unwrap_err();
        assert_eq!(err.failure, OpenFailure::Missing);
        let _ = pk;
    }

    #[test]
    fn the_strict_index_answers_without_the_store_and_heals_itself() {
        let dir = crate::fsutil::temp_dir("strict-index");
        let store: std::sync::Arc<dyn KeyStore> = std::sync::Arc::new(MemoryKeyStore::new());
        let s = IndexedStrictSecrets {
            store: store.clone(),
            index: StrictIndex::new(dir.join(StrictIndex::FILE)),
        };
        assert!(!s.holds("hk_1").unwrap());
        StrictHook {
            verify: json!({"preset": "github", "strict": true}),
            secrets: vec!["s".into()],
        }
        .save(store.as_ref(), "hk_1")
        .unwrap();
        // Kept before the index knew: the first strict event's lookup adds it.
        assert!(!s.holds("hk_1").unwrap());
        assert!(s.get("hk_1").unwrap().is_some());
        assert!(s.holds("hk_1").unwrap());
        assert!(
            StrictIndex::new(dir.join(StrictIndex::FILE))
                .contains("hk_1")
                .unwrap()
        );
        std::fs::write(dir.join(StrictIndex::FILE), b"{broken").unwrap();
        assert!(
            s.holds("hk_1").is_err(),
            "a damaged index fails, never says no"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replay_marks_survive_a_restart_and_age_out() {
        let dir = crate::fsutil::temp_dir("replay");
        let path = dir.join(ReplayCache::FILE);
        let now = T * 1000;
        let mut c = ReplayCache::open(&path, now).unwrap();
        let m = ReplayCache::mark("hk_1", b"body");
        assert!(c.note(&m, "evt_1", now, now).unwrap());
        assert!(c.note(&m, "evt_1", now, now).unwrap());
        drop(c);
        // Read lazily, on the first note.
        let mut c = ReplayCache::at(&path);
        assert!(!c.note(&m, "evt_2", now + 1000, now + 1000).unwrap());
        assert_ne!(m, ReplayCache::mark("hk_2", b"body"));
        drop(c);
        // Past the window it is forgotten (and such an old event is refused before it gets here).
        let c = ReplayCache::open(&path, now + REPLAY_WINDOW_MS + 1).unwrap();
        assert!(c.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn keys_round_trip_through_a_store_by_kid() {
        let store = MemoryKeyStore::new();
        let key = SealKey::generate().unwrap();
        key.save(&store).unwrap();
        let back = SealKey::load(&store, &key.kid()).unwrap().unwrap();
        assert_eq!(back.public_key(), key.public_key());
        assert_eq!(key.kid().len(), 22);
        assert!(SealKey::load(&store, "unknownkid").unwrap().is_none());
        let strict = StrictHook {
            verify: json!({"preset": "github"}),
            secrets: vec!["s".into()],
        };
        strict.save(&store, "hk_1").unwrap();
        assert_eq!(StrictHook::load(&store, "hk_1").unwrap(), Some(strict));
    }
}
