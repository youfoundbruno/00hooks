//! The plain actions (PLAN §5.2): notify, call a URL, run an allowed command, write a file.
//! Each returns a short detail on success, or a [`Failure`] that says whether trying again is
//! safe and useful.

pub mod call;
pub mod command;
pub mod notify;
pub mod write;

pub use notify::{Notifier, NullNotifier, RecordingNotifier, SystemNotifier};

/// Why an action failed, and whether to try again.
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    pub message: String,
    /// A transient failure (a network error, a 5xx): worth retrying when the action is safe to
    /// repeat.
    pub retryable: bool,
}

impl Failure {
    pub fn retry(m: impl Into<String>) -> Failure {
        Failure {
            message: m.into(),
            retryable: true,
        }
    }

    pub fn fatal(m: impl Into<String>) -> Failure {
        Failure {
            message: m.into(),
            retryable: false,
        }
    }
}

pub type Outcome = Result<String, Failure>;
