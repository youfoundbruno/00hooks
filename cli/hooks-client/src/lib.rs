//! `hooks-client`: the 00hooks client library.
//!
//! - [`keys`]: device keys and where they are kept (keychain, a 0600 file, or memory).
//! - [`signing`]: the canonical string and signed headers of PROTOCOL §1.
//! - [`api`]: the relay's HTTP API, with clock-skew correction.
//! - [`sse`]: a hand-written Server-Sent Events parser.
//! - [`stream`]: the resilient subscription (resume, backoff, record → ack → hand over, dedupe).
//! - [`store`]: the crash-safe local state directory.
//! - [`seal`]: sealing keys, opening sealed events and checking the relay's signature (PROTOCOL §5).
//! - [`presets`]: provider signature checks for strict hooks (PROTOCOL §3).
//!
//! The library does no terminal I/O; the `00hooks` CLI and the 00next node both embed it.

pub mod api;
pub mod backoff;
mod error;
pub mod fsutil;
pub mod keys;
pub mod presets;
pub mod seal;
pub mod signing;
pub mod sse;
pub mod store;
pub mod stream;
pub mod types;

pub use api::Client;
pub use error::{Error, Result, Secret, describe_skew};
pub use keys::{DeviceKey, FileKeyStore, KeyStore, KeychainStore, MemoryKeyStore};
pub use seal::{Opener, SealKey, StrictHook};
pub use store::{Config, EventStore, Quarantined, StateDir};
pub use stream::{StreamEvent, SubscribeOptions, Subscription, subscribe};
pub use types::*;

/// The stream protocol this client speaks (PROTOCOL §0): sent as `X-00h-Protocol`, and looked for
/// in `/v1/info`'s `protocols`.
pub const PROTOCOL_VERSION: u32 = 2;
