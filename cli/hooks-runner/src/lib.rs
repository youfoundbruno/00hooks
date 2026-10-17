//! `hooks-runner`: the 00hooks automation runner (PLAN §5).
//!
//! It consumes events through `hooks-client`'s public API and, for each one:
//! 1. drops our own echoes and runaway loops (`00hooks-origin`, `00hooks-hop`);
//! 2. records the event and the start of its run, durably, before acting;
//! 3. adds it to the [`catalogue`] (field tree, sample, values seen), noticing new kinds and
//!    shape changes;
//! 4. matches the automations of `automations.yaml` ([`config`]) on kinds, the catalogue's own
//!    triggers, an [`expr`] filter and the verified flag;
//! 5. runs their plain [`actions`] (notify, call a URL, run an allowed command, write a file), with
//!    retries for what's safe to repeat, per-automation rate limits and a circuit breaker;
//! 6. records the result ([`runs`]), so any event can be replayed.
//!
//! Webhook content is data: no payload value is ever interpolated into a shell, a file path (a
//! file name is sanitised; folders are fixed in the configuration) or a URL's host.

pub mod actions;
pub mod catalogue;
pub mod check;
pub mod config;
pub mod context;
pub mod expr;
pub mod jsonl;
pub mod mailbox;
pub mod path;
pub mod runner;
pub mod runs;
pub mod secrets;
pub mod service;
pub mod state;
pub mod template;
pub mod text;
pub mod yaml;

#[cfg(test)]
pub(crate) mod testutil;

use std::fmt;

pub use catalogue::{Catalogue, KindRecord};
pub use config::{Automations, Problem};
pub use runner::{Runner, RunnerOptions};
pub use runs::{RunLog, RunRecord};

/// The header that marks a call as ours, and the one that counts hops.
pub const ORIGIN_HEADER: &str = "00hooks-origin";
pub const HOP_HEADER: &str = "00hooks-hop";

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// Something in the runner's own files.
    Store(String),
    /// `automations.yaml` has problems.
    Config(Vec<Problem>),
    /// Anything else, as a plain sentence.
    Other(String),
}

impl Error {
    pub fn from_client(e: hooks_client::Error) -> Error {
        Error::Store(e.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Store(m) | Error::Other(m) => f.write_str(m),
            Error::Config(problems) => {
                for (i, p) in problems.iter().enumerate() {
                    if i > 0 {
                        f.write_str("\n")?;
                    }
                    write!(f, "{p}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Now, in Unix milliseconds.
pub fn now_ms() -> i64 {
    hooks_client::api::system_now_ms()
}

/// 16 random hex characters.
pub fn random_hex() -> String {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).expect("randomness");
    r.iter().map(|b| format!("{b:02x}")).collect()
}
