//! Request signing, PROTOCOL §1.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use url::Url;

use crate::keys::DeviceKey;
use crate::{Error, Result};

pub const HEADER_DEVICE: &str = "X-00h-Device";
pub const HEADER_TIME: &str = "X-00h-Time";
pub const HEADER_NONCE: &str = "X-00h-Nonce";
pub const HEADER_SIGNATURE: &str = "X-00h-Signature";

/// The first line of every canonical string.
pub const CANONICAL_VERSION: &str = "00hooks-v1";

/// Lowercase hex SHA-256 of `body` (of the empty string when there is no body).
pub fn body_hash(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let mut out = String::with_capacity(64);
    for b in digest.iter() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The canonical string of PROTOCOL §1: seven lines joined with `\n`, no trailing newline.
pub fn canonical_string(
    host: &str,
    method: &str,
    path_and_query: &str,
    time_ms: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    [
        CANONICAL_VERSION,
        &host.to_ascii_lowercase(),
        &method.to_ascii_uppercase(),
        path_and_query,
        &time_ms.to_string(),
        nonce,
        &body_hash(body),
    ]
    .join("\n")
}

/// The host line: lowercase, with `:port` only when the URL names a port that isn't its scheme's
/// default (exactly what an HTTP client puts in the `Host` header).
pub fn signing_host(url: &Url) -> Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::Invalid(format!("the relay URL {url} has no host")))?
        .to_ascii_lowercase();
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

/// The path and query, exactly as they will be sent.
pub fn path_and_query(url: &Url) -> String {
    match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    }
}

/// 128 random bits as 22 base64url characters.
pub fn new_nonce() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| Error::KeyStore(format!("no randomness: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(b))
}

/// The four headers of a signed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    pub device: String,
    pub time: i64,
    pub nonce: String,
    pub signature: String,
}

impl SignedHeaders {
    pub fn pairs(&self) -> [(&'static str, String); 4] {
        [
            (HEADER_DEVICE, self.device.clone()),
            (HEADER_TIME, self.time.to_string()),
            (HEADER_NONCE, self.nonce.clone()),
            (HEADER_SIGNATURE, self.signature.clone()),
        ]
    }
}

/// Sign a request with a given time and nonce (pure: the same inputs give the same headers).
pub fn sign_with(
    key: &DeviceKey,
    device_id: &str,
    method: &str,
    url: &Url,
    body: &[u8],
    time_ms: i64,
    nonce: &str,
) -> Result<SignedHeaders> {
    let canonical = canonical_string(
        &signing_host(url)?,
        method,
        &path_and_query(url),
        time_ms,
        nonce,
        body,
    );
    Ok(SignedHeaders {
        device: device_id.to_string(),
        time: time_ms,
        nonce: nonce.to_string(),
        signature: URL_SAFE_NO_PAD.encode(key.sign(canonical.as_bytes())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The vector in PROTOCOL.md §1 ("Example"). The relay tests against the same values; change
    // them only together with the document.
    pub const SEED: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    const URL: &str = "https://relay.example.com/v1/hooks?limit=10";
    const TIME: i64 = 1792233600000;
    const NONCE: &str = "AAECAwQFBgcICQoLDA0ODw";
    const BODY: &str = r#"{"name":"ci","verify":{"preset":"github"}}"#;
    const PUBLIC_KEY: &str = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
    const BODY_HASH: &str = "871ec9aaacf62bacee0fb97ada9c29fed342cd0d7a3a07731570385a03c17a4c";
    const SIGNATURE: &str =
        "OlQhu7X6asl-UprVxIhRjftd-Hl-KN6hOcQdDgiJlLacZL6pbTwK3-E-TOtNaqW7wOTr2QkRirJfp0O8hDOaAQ";

    #[test]
    fn canonical_string_matches_the_protocol_vector() {
        let url = Url::parse(URL).unwrap();
        let s = canonical_string(
            &signing_host(&url).unwrap(),
            "post",
            &path_and_query(&url),
            TIME,
            NONCE,
            BODY.as_bytes(),
        );
        let expected = format!(
            "00hooks-v1\nrelay.example.com\nPOST\n/v1/hooks?limit=10\n1792233600000\nAAECAwQFBgcICQoLDA0ODw\n{BODY_HASH}"
        );
        assert_eq!(s, expected);
        assert_eq!(body_hash(BODY.as_bytes()), BODY_HASH);
    }

    #[test]
    fn signature_matches_the_protocol_vector() {
        let key = DeviceKey::from_seed(&SEED);
        assert_eq!(key.public_key(), PUBLIC_KEY);
        let url = Url::parse(URL).unwrap();
        let h = sign_with(&key, "dev_0", "POST", &url, BODY.as_bytes(), TIME, NONCE).unwrap();
        assert_eq!(h.signature, SIGNATURE);
        assert_eq!(h.signature.len(), 86);
    }

    #[test]
    fn the_protocol_document_carries_the_same_vector() {
        let doc = include_str!("../../../docs/PROTOCOL.md");
        for value in [
            PUBLIC_KEY,
            BODY_HASH,
            SIGNATURE,
            NONCE,
            BODY,
            "1792233600000",
        ] {
            assert!(doc.contains(value), "PROTOCOL.md §1 lacks {value}");
        }
        let seed_hex: String = SEED.iter().map(|b| format!("{b:02x}")).collect();
        assert!(doc.contains(&seed_hex));
    }

    #[test]
    fn empty_body_hashes_the_empty_string() {
        assert_eq!(
            body_hash(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn host_keeps_only_non_default_ports() {
        let h = |u: &str| signing_host(&Url::parse(u).unwrap()).unwrap();
        assert_eq!(h("https://Relay.Example.COM/"), "relay.example.com");
        assert_eq!(h("https://relay.example.com:443/"), "relay.example.com");
        assert_eq!(h("http://relay.example.com:80/"), "relay.example.com");
        assert_eq!(h("http://127.0.0.1:8787/"), "127.0.0.1:8787");
        assert_eq!(
            h("https://relay.example.com:8443/"),
            "relay.example.com:8443"
        );
    }

    #[test]
    fn path_keeps_the_query_as_sent() {
        let p = |u: &str| path_and_query(&Url::parse(u).unwrap());
        assert_eq!(p("https://r.example/v1/stream"), "/v1/stream");
        assert_eq!(
            p("https://r.example/v1/hooks?a=1&b=%20"),
            "/v1/hooks?a=1&b=%20"
        );
        assert_eq!(p("https://r.example"), "/");
    }

    #[test]
    fn nonces_are_22_chars_and_differ() {
        let a = new_nonce().unwrap();
        let b = new_nonce().unwrap();
        assert_eq!(a.len(), 22);
        assert_ne!(a, b);
    }
}
