//! What every command needs: the state directory, the saved login, a signing client, and errors
//! that say what to do next.

use std::fmt;

use hooks_client::{
    Client, Config, DeviceKey, Error, KeyStore, KeychainStore, StateDir, describe_skew,
};

use crate::output::sanitize;

/// A failure to show the person: what happened, then what to do about it.
#[derive(Debug)]
pub struct Failure {
    pub message: String,
    pub code: i32,
}

impl Failure {
    pub fn new(message: impl Into<String>) -> Self {
        Failure {
            message: message.into(),
            code: 1,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

pub type CliResult<T = ()> = Result<T, Failure>;

/// Turn a library error into a sentence that ends with the next step.
pub fn explain(e: Error, relay: &str) -> Failure {
    let message = match &e {
        Error::Network(detail) => format!(
            "Couldn't reach the relay at {relay} ({detail}). Check your connection, or run \
             `00hooks doctor`."
        ),
        Error::ClockSkew { skew_ms } => format!(
            "This computer's clock is {} off the relay's. Turn on automatic date and time in \
             your system settings, then try again.",
            describe_skew(*skew_ms)
        ),
        e if e.is_unauthorized() => "The relay no longer accepts this device: it was revoked, or \
             its key doesn't match. Run `00hooks login --force` to log in again."
            .to_string(),
        Error::Api {
            code,
            message,
            field,
            ..
        } => {
            let mut m = if message.is_empty() {
                format!("The relay refused the request ({code}).")
            } else {
                format!("The relay refused the request: {}", sentence(message))
            };
            if let Some(f) = field {
                m.push_str(&format!(" (field: {f})"));
            }
            m
        }
        Error::Closed { .. } => sentence(&e.to_string()),
        other => sentence(&other.to_string()),
    };
    // The relay's message, a close reason and network details are text from elsewhere: nothing in
    // them may drive the terminal.
    Failure::new(sanitize(&message, false))
}

/// Capitalise and end with a full stop.
pub fn sentence(s: &str) -> String {
    let s = s.trim();
    let mut c = s.chars();
    let mut out = match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => return String::new(),
    };
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

/// The key store a config names.
pub fn key_store(kind: &str, state: &StateDir) -> Box<dyn KeyStore> {
    match kind {
        "file" => Box::new(state.file_keys()),
        _ => Box::new(KeychainStore),
    }
}

/// The key store to create a new key in: `HOOKS_KEYSTORE=file|keychain`, else the keychain when
/// there is one.
pub fn preferred_key_store() -> &'static str {
    match std::env::var("HOOKS_KEYSTORE").as_deref() {
        Ok("file") => "file",
        Ok("keychain") => "keychain",
        _ if KeychainStore::available() => "keychain",
        _ => "file",
    }
}

pub fn open_state() -> CliResult<StateDir> {
    StateDir::open_default().map_err(|e| Failure::new(sentence(&e.to_string())))
}

/// A logged-in context.
pub struct Ctx {
    pub state: StateDir,
    pub config: Config,
    pub client: Client,
}

impl Ctx {
    pub fn load() -> CliResult<Ctx> {
        let state = open_state()?;
        let config = state
            .load_config()
            .map_err(|e| Failure::new(sentence(&e.to_string())))?
            .ok_or_else(|| {
                Failure::new(
                    "This computer isn't logged in. Run `00hooks login --relay <URL>` first.",
                )
            })?;
        let store = key_store(&config.key_store, &state);
        let key = DeviceKey::load(store.as_ref(), &config.key_name)
            .map_err(|e| Failure::new(sentence(&e.to_string())))?
            .ok_or_else(|| {
                Failure::new(format!(
                    "The key for this device ({}) is missing from {}. Run `00hooks login --force` \
                     to log in again.",
                    config.device_id,
                    store.describe()
                ))
            })?;
        let client = Client::with_device(&config.relay, &config.device_id, key)
            .map_err(|e| Failure::new(sentence(&e.to_string())))?;
        Ok(Ctx {
            state,
            config,
            client,
        })
    }

    pub fn explain(&self, e: Error) -> Failure {
        explain(e, &self.config.relay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_end_with_what_to_do() {
        let f = explain(
            Error::Network("connection refused".into()),
            "https://r.example",
        );
        assert!(f.message.contains("00hooks doctor"), "{f}");
        let f = explain(
            Error::Api {
                status: 401,
                code: "unauthorized".into(),
                message: String::new(),
                field: None,
            },
            "https://r.example",
        );
        assert!(f.message.contains("00hooks login --force"), "{f}");
        let f = explain(Error::ClockSkew { skew_ms: 420_000 }, "x");
        assert!(f.message.contains("7 min 0 s"), "{f}");
        let f = explain(
            Error::Api {
                status: 400,
                code: "invalid".into(),
                message: "name is too long".into(),
                field: Some("name".into()),
            },
            "x",
        );
        assert_eq!(
            f.message,
            "The relay refused the request: Name is too long. (field: name)"
        );
    }

    #[test]
    fn relay_text_is_sanitised() {
        let f = explain(
            Error::Api {
                status: 400,
                code: "invalid".into(),
                message: "bad\u{1b}]0;pwned\u{7}\u{9b}2J\u{202e}name".into(),
                field: Some("na\u{1b}[2Jme".into()),
            },
            "x",
        );
        for c in ['\u{1b}', '\u{7}', '\u{9b}', '\u{202e}'] {
            assert!(!f.message.contains(c), "{:?}", f.message);
        }
        let f = explain(
            Error::Closed {
                code: 4409,
                reason: "replaced\u{1b}[31m\u{2066}".into(),
            },
            "x",
        );
        assert!(!f.message.contains('\u{1b}') && !f.message.contains('\u{2066}'));
        assert!(f.message.contains("replaced"), "{}", f.message);
    }

    #[test]
    fn sentence_capitalises_and_ends() {
        assert_eq!(sentence("local state: oops"), "Local state: oops.");
        assert_eq!(sentence("done."), "done.".replacen('d', "D", 1));
    }
}
