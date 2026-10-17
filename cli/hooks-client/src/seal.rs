//! Sealed events (PROTOCOL §5): the device's X25519 sealing key, opening HPKE envelopes (RFC 9180:
//! DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode; the `hpke` crate), checking
//! the relay's Ed25519 signature over each envelope with the key pinned at login, and, for strict
//! hooks, verifying the provider's own signature ([`crate::presets`]).
//!
//! [`Opener::open`] turns an envelope back into an [`Event`] with `headers`, `contentType` and
//! `body` restored, so whatever consumes the stream (the CLI's `listen`, an automation runner)
//! never sees an envelope. [`seal_event`] is the relay's side, for tests and tools.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

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
}

/// The plaintext: the JSON of everything but the body, `\n`, then the body's raw bytes.
pub fn encode_content(c: &SealedContent) -> Vec<u8> {
    let meta = ContentMeta {
        headers: c.headers.clone(),
        content_type: c.content_type.clone(),
        url: c.url.clone(),
        notice: c.notice,
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
    [
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
    ]
    .join("\n")
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

/// Where an [`Opener`] finds strict hooks' secrets.
pub trait StrictSecrets: Send + Sync {
    fn get(&self, hook_id: &str) -> Result<Option<StrictHook>>;
}

/// Strict secrets in a key store.
pub struct StoreStrictSecrets(pub std::sync::Arc<dyn KeyStore>);

impl StrictSecrets for StoreStrictSecrets {
    fn get(&self, hook_id: &str) -> Result<Option<StrictHook>> {
        StrictHook::load(self.0.as_ref(), hook_id)
    }
}

/// Opens this device's envelopes: its sealing keys by kid, the relay key pinned at login, and the
/// strict hooks' secrets.
pub struct Opener {
    device_id: String,
    relay_key: Option<VerifyingKey>,
    keys: HashMap<String, SealKey>,
    strict: Option<Box<dyn StrictSecrets>>,
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
        })
    }

    pub fn add_key(&mut self, key: SealKey) {
        self.keys.insert(key.kid(), key);
    }

    pub fn with_strict(mut self, strict: Box<dyn StrictSecrets>) -> Self {
        self.strict = Some(strict);
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
    /// quarantine record.
    pub fn open(&self, mut e: Event) -> std::result::Result<Event, String> {
        let sealed = e.sealed.take().ok_or(
            "the event arrived unsealed; a protocol 2 relay seals every event, so it was refused",
        )?;
        let relay_key = self.relay_key.as_ref().ok_or(
            "no relay key is pinned for this login, so envelopes can't be checked; run \
             `00hooks devices seal-key`",
        )?;
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
            format!(
                "it is sealed to key {}, which this device doesn't hold",
                sealed.kid
            )
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
            &seal_aad(&e.hook_id, e.seq, &e.id),
        )
        .map_err(|_| "the envelope doesn't open with this device's key")?;
        let content = decode_content(&pt)?;
        if e.strict {
            self.verify_strict(&mut e, &content)?;
        }
        e.headers = content.headers;
        e.content_type = content.content_type;
        e.notice = content.notice;
        e.body = STANDARD.encode(&content.body);
        Ok(e)
    }

    fn verify_strict(
        &self,
        e: &mut Event,
        content: &SealedContent,
    ) -> std::result::Result<(), String> {
        let hook = match &self.strict {
            None => None,
            Some(s) => s.get(&e.hook_id).map_err(|err| err.to_string())?,
        }
        .ok_or_else(|| {
            format!(
                "{} is a strict hook and this device has no secret for it; add it with \
                 `00hooks hooks secret {}`",
                e.hook_id, e.hook_id
            )
        })?;
        let verdict = presets::verify(
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
            return Err(format!(
                "the provider's signature doesn't verify for strict hook {} (forged, replayed \
                 late, or the secret on this device is wrong)",
                e.hook_id
            ));
        }
        e.verified = true;
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
        &seal_aad(&meta.hook_id, meta.seq, &meta.id),
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

    struct Fixed(StrictHook);
    impl StrictSecrets for Fixed {
        fn get(&self, _: &str) -> Result<Option<StrictHook>> {
            Ok(Some(self.0.clone()))
        }
    }

    #[test]
    fn opens_every_event_the_relays_own_code_sealed_under_node() {
        let (v, opener) = interop();
        // The strict sample's signature header is a placeholder: without a matching secret it is
        // refused, which is the point of strict mode.
        let opener = opener.with_strict(Box::new(Fixed(StrictHook {
            verify: json!({"preset": "stripe"}),
            secrets: vec!["whsec_not_the_one".into()],
        })));
        for item in v["events"].as_array().unwrap() {
            let e: Event = serde_json::from_value(item["message"].clone()).unwrap();
            let want = &item["expect"];
            if e.strict {
                let err = opener.open(e).unwrap_err();
                assert!(err.contains("doesn't verify"), "{err}");
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
        assert!(opener.open(forged).unwrap_err().contains("signature"));
        let mut moved = e.clone();
        moved.seq += 1;
        assert!(opener.open(moved).unwrap_err().contains("signature"));
        let mut typed = e.clone();
        typed.event_type = Some("forged".into());
        assert!(opener.open(typed).unwrap_err().contains("signature"));
        // The same envelope presented to another device id: the signature names the device.
        let mut other =
            Opener::new("dev_someoneelse", Some(v["relayKey"].as_str().unwrap())).unwrap();
        other.add_key(SealKey::generate().unwrap());
        assert!(other.open(e.clone()).unwrap_err().contains("signature"));
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
                .contains("signature")
        );
        let mut plain = e.clone();
        plain.sealed = None;
        assert!(opener.open(plain).unwrap_err().contains("unsealed"));
        let no_relay = Opener::new(v["deviceId"].as_str().unwrap(), None).unwrap();
        assert!(no_relay.open(e).unwrap_err().contains("devices seal-key"));
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
        let relay = SigningKey::from_bytes(&[3; 32]);
        let key = SealKey::generate().unwrap();
        let mut opener = Opener::new(
            "dev_1",
            Some(&URL_SAFE_NO_PAD.encode(relay.verifying_key().as_bytes())),
        )
        .unwrap();
        let pk = key.public_bytes();
        opener.add_key(key);
        let secret = "whsec_device_only_secret";
        let opener = opener.with_strict(Box::new(Fixed(StrictHook {
            verify: json!({"preset": "stripe", "strict": true}),
            secrets: vec![secret.into()],
        })));
        let t = 1_792_233_600i64;
        let body = br#"{"id":"evt_1","type":"invoice.paid"}"#;
        let mut mac =
            <hmac::Hmac<Sha256> as hmac::KeyInit>::new_from_slice(secret.as_bytes()).unwrap();
        hmac::Mac::update(&mut mac, format!("{t}.").as_bytes());
        hmac::Mac::update(&mut mac, body);
        let sig: String = hmac::Mac::finalize(mac)
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let meta = Event {
            seq: 7,
            id: "evt_x".into(),
            hook_id: "hk_x".into(),
            // Read long after it arrived: the timestamp is checked against receivedAt.
            received_at: t * 1000 + 30_000,
            verified: false,
            strict: true,
            preset: "stripe".into(),
            ..Event::default()
        };
        let mut content = SealedContent {
            headers: BTreeMap::from([("stripe-signature".into(), format!("t={t},v1={sig}"))]),
            content_type: Some("application/json".into()),
            url: Some("https://relay.example/h/hk_x".into()),
            notice: false,
            body: body.to_vec(),
        };
        let opened = opener
            .open(seal_event(&relay, "dev_1", &pk, &meta, &content).unwrap())
            .unwrap();
        assert!(opened.verified);
        assert_eq!(opened.event_type.as_deref(), Some("invoice.paid"));
        assert_eq!(STANDARD.decode(&opened.body).unwrap(), body);

        // A forged signature is refused; so is a genuine one six minutes before it arrived.
        content.headers.insert(
            "stripe-signature".into(),
            format!("t={t},v1={}", "0".repeat(64)),
        );
        let forged = seal_event(&relay, "dev_1", &pk, &meta, &content).unwrap();
        assert!(opener.open(forged).unwrap_err().contains("doesn't verify"));
        let late = Event {
            received_at: (t + 360) * 1000,
            ..meta.clone()
        };
        content
            .headers
            .insert("stripe-signature".into(), format!("t={t},v1={sig}"));
        assert!(
            opener
                .open(seal_event(&relay, "dev_1", &pk, &late, &content).unwrap())
                .is_err()
        );
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
