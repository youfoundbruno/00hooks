use std::fmt;

/// Everything that can go wrong in the client. Messages are plain sentences and never carry secrets,
/// signatures or payload content.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The relay could not be reached, or the connection broke.
    #[error("could not reach the relay: {0}")]
    Network(String),

    /// The relay answered with an error body (`{ "error", "message" }`, PROTOCOL §8).
    #[error("{}", api_message(.status, .code, .message))]
    Api {
        status: u16,
        code: String,
        message: String,
        field: Option<String>,
    },

    /// The relay refused our time even after one retry with its clock (PROTOCOL §1).
    #[error("this computer's clock is {} off the relay's, even after correcting for it once", describe_skew(*.skew_ms))]
    ClockSkew { skew_ms: i64 },

    /// The stream closed with a terminal code (`4401` or `4409`, PROTOCOL §6), or the relay refused
    /// the stream in a way that retrying cannot fix.
    #[error("{}", closed_message(*.code, .reason))]
    Closed { code: u16, reason: String },

    /// The key store failed or refused.
    #[error("{0}")]
    KeyStore(String),

    /// The local state directory failed.
    #[error("local state: {0}")]
    Store(String),

    /// The relay sent something that doesn't match the protocol.
    #[error("unexpected answer from the relay: {0}")]
    Protocol(String),

    /// A value given by the caller is malformed.
    #[error("{0}")]
    Invalid(String),

    #[error("{0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    /// The relay no longer accepts this device (revoked, unknown, or a key mismatch).
    pub fn is_unauthorized(&self) -> bool {
        match self {
            Error::Api { status, code, .. } => *status == 401 && code != "clock_skew",
            Error::Closed { code, .. } => *code == 4401,
            _ => false,
        }
    }

    /// Which of the relay's limits refused the request (PROTOCOL §8): a `429` or a cap's `409`
    /// that names its `scope`. `None` for any other error, or a scope this client doesn't know.
    pub fn limit_scope(&self) -> Option<crate::types::LimitScope> {
        match self {
            Error::Api {
                status: 429 | 409,
                field: Some(f),
                ..
            } => match crate::types::LimitScope::parse(f) {
                crate::types::LimitScope::Other => None,
                s => Some(s),
            },
            _ => None,
        }
    }

    /// The machine is offline or the relay is down: worth retrying later.
    pub fn is_transient(&self) -> bool {
        match self {
            Error::Network(_) => true,
            Error::Api { status, .. } => *status >= 500 || *status == 429 || *status == 408,
            _ => false,
        }
    }
}

fn api_message(status: &u16, code: &str, message: &str) -> String {
    if message.is_empty() {
        format!("the relay refused the request ({status} {code})")
    } else {
        format!("the relay refused the request ({status} {code}): {message}")
    }
}

fn closed_message(code: u16, reason: &str) -> String {
    let what = match code {
        4401 => "the relay no longer accepts this device (revoked, or its key doesn't match)",
        4409 => "another process started listening as this device",
        _ => "the relay closed the stream",
    };
    if reason.is_empty() {
        format!("{what} ({code})")
    } else {
        format!("{what} ({code}: {reason})")
    }
}

/// `1.2 s`, `7 min 3 s`: how far off a clock is, without a sign.
pub fn describe_skew(skew_ms: i64) -> String {
    let ms = skew_ms.unsigned_abs();
    if ms < 1000 {
        format!("{ms} ms")
    } else if ms < 60_000 {
        format!("{:.1} s", ms as f64 / 1000.0)
    } else {
        format!("{} min {} s", ms / 60_000, (ms % 60_000) / 1000)
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        // Callers already say which relay; drop the URL so messages stay short.
        Error::Network(flatten(&e.without_url()))
    }
}

fn flatten(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        let text = s.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = s.source();
    }
    out
}

/// A secret value (a hook signing secret). `Debug` never prints it.
#[derive(Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }
    /// The secret itself. Call this only to show it to the person once, or to hand it to the relay.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(…)")
    }
}
