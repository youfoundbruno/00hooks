//! The resilient event stream (PROTOCOL §6 and §7).
//!
//! [`subscribe`] returns a [`Subscription`] whose [`Subscription::next`] yields typed events. Behind
//! it, every connection attempt is freshly signed and resumes from the durable cursor; a dead or
//! dropped connection is retried with jittered backoff; and each `hook` event goes through the
//! delivery rule: **record** it in the local store, **acknowledge** it to the relay, then **hand it
//! over**, skipping any id that was handed over before.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use crate::api::Client;
use crate::backoff::{Backoff, Clock, CloseAction, Jitter, TokioClock, close_action};
use crate::sse::{SseItem, SseParser};
use crate::store::EventStore;
use crate::types::{Closed, Event, Gap, Ready, Resync};
use crate::{Error, Result};

/// Tuning for [`subscribe`]. The defaults are the protocol's.
#[derive(Clone)]
pub struct SubscribeOptions {
    /// No byte (heartbeats included) for this long means the connection is dead. 70 s.
    pub idle_timeout: Duration,
    /// The shortest wait before reconnecting. 1 s.
    pub min_backoff: Duration,
    /// The longest wait before reconnecting. 30 s.
    pub max_backoff: Duration,
    /// Sleeping; replaced by a fake clock in tests.
    pub clock: Arc<dyn Clock>,
    pub jitter: Jitter,
}

impl Default for SubscribeOptions {
    fn default() -> Self {
        SubscribeOptions {
            idle_timeout: Duration::from_secs(70),
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            clock: Arc::new(TokioClock),
            jitter: Jitter::from_entropy(),
        }
    }
}

/// What the stream yields.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamEvent {
    /// Connected: the relay resumes after `after`; `head` is its newest seq.
    Ready(Ready),
    /// A webhook event, recorded and acknowledged, handed over exactly once.
    Hook(Event),
    /// Retention dropped these seqs before this device could read them.
    Gap(Gap),
    /// The relay asked the client to catch up from its cursor; it is reconnecting.
    Resync(Resync),
    /// The connection dropped; the next attempt is in `delay`.
    Reconnecting {
        attempt: u32,
        delay: Duration,
        reason: String,
    },
    /// Something worth telling the person that doesn't stop the stream.
    Warning(String),
}

/// What to do once the current batch has been handed over.
#[derive(Debug)]
enum Then {
    Reconnect { immediate: bool, reason: String },
    Stop(Closed),
}

/// A live subscription. Call [`Subscription::next`] in a loop; `None` means it ended (after an
/// `Err` for a terminal close).
pub struct Subscription {
    client: Client,
    store: EventStore,
    opts: SubscribeOptions,
    backoff: Backoff,
    parser: SseParser,
    conn: Option<reqwest::Response>,
    /// Wait this long before the next connection attempt.
    delay: Option<Duration>,
    /// Ready to hand over, in order.
    out: VecDeque<StreamEvent>,
    /// Recorded, waiting for the acknowledgement of `ack_through` before being handed over.
    awaiting_ack: Vec<StreamEvent>,
    ack_through: Option<u64>,
    /// The highest seq the relay has confirmed.
    acked: u64,
    then: Option<Then>,
    finished: bool,
}

/// Start streaming events for the client's device into `store`. Events recorded by an earlier run
/// but not handed over (a crash between the two) come first.
pub fn subscribe(client: Client, store: EventStore, opts: SubscribeOptions) -> Subscription {
    let backoff = Backoff::new(opts.min_backoff, opts.max_backoff, opts.jitter.clone());
    let pending: Vec<StreamEvent> = store.pending().into_iter().map(StreamEvent::Hook).collect();
    let ack_through = store.pending_through();
    Subscription {
        client,
        store,
        opts,
        backoff,
        parser: SseParser::default(),
        conn: None,
        delay: None,
        out: VecDeque::new(),
        awaiting_ack: pending,
        ack_through,
        acked: 0,
        then: None,
        finished: false,
    }
}

/// Whether a failure to open the stream is worth retrying.
fn is_retryable(e: &Error) -> bool {
    match e {
        Error::Network(_) | Error::Protocol(_) | Error::ClockSkew { .. } => true,
        Error::Api { status, .. } => *status >= 500 || *status == 408 || *status == 429,
        _ => false,
    }
}

impl Subscription {
    pub fn store(&self) -> &EventStore {
        &self.store
    }

    pub fn into_store(self) -> EventStore {
        self.store
    }

    fn fail(&mut self, e: Error) -> Option<Result<StreamEvent>> {
        self.finished = true;
        self.conn = None;
        Some(Err(e))
    }

    fn schedule_reconnect(&mut self, immediate: bool, reason: String) {
        self.conn = None;
        let first = self.backoff.attempt() == 0;
        let wait = self.backoff.next_delay();
        let delay = if immediate && first {
            Duration::ZERO
        } else {
            wait
        };
        self.delay = Some(delay);
        self.out.push_back(StreamEvent::Reconnecting {
            attempt: self.backoff.attempt(),
            delay,
            reason,
        });
    }

    /// The next event. Cancel-safe at the level of the delivery rule: a recorded event is never
    /// lost, and an event is marked handed-over only as this function returns it.
    pub async fn next(&mut self) -> Option<Result<StreamEvent>> {
        loop {
            // 1. Hand over what is ready, skipping ids handed over before.
            if let Some(ev) = self.out.pop_front() {
                if let StreamEvent::Hook(e) = &ev {
                    if self.store.is_seen(&e.id) {
                        continue;
                    }
                    if let Err(err) = self.store.mark_delivered(&e.id) {
                        return self.fail(err);
                    }
                }
                return Some(Ok(ev));
            }
            if self.finished {
                return None;
            }

            // 2. Acknowledge what was recorded, then release it.
            if let Some(through) = self.ack_through {
                match self.client.ack(through).await {
                    Ok(acked) => self.acked = self.acked.max(acked),
                    Err(e) if e.is_unauthorized() => return self.fail(e),
                    Err(e) => self.out.push_back(StreamEvent::Warning(format!(
                        "couldn't acknowledge events through {through} ({e}); they are recorded \
                         here and will be acknowledged later"
                    ))),
                }
                self.ack_through = None;
                self.out.extend(self.awaiting_ack.drain(..));
                continue;
            }

            // 3. Act on a `resync` or `closed` once everything before it is handed over.
            match self.then.take() {
                Some(Then::Stop(closed)) => {
                    return self.fail(Error::Closed {
                        code: closed.code,
                        reason: closed.reason,
                    });
                }
                Some(Then::Reconnect { immediate, reason }) => {
                    self.schedule_reconnect(immediate, reason);
                    continue;
                }
                None => {}
            }

            // 4. Connect: signed afresh, resuming from the durable cursor.
            if self.conn.is_none() {
                if let Some(d) = self.delay {
                    if !d.is_zero() {
                        self.opts.clock.sleep(d).await;
                    }
                    self.delay = None;
                }
                let cursor = self.store.cursor();
                let last = (cursor > 0).then_some(cursor);
                match self.client.open_stream(last).await {
                    Ok(resp) => {
                        self.conn = Some(resp);
                        self.parser = SseParser::default();
                    }
                    Err(e) if is_retryable(&e) => {
                        self.schedule_reconnect(false, e.to_string());
                        continue;
                    }
                    Err(e) => return self.fail(e),
                }
            }

            // 5. Read, treating a silent connection as dead.
            let idle = self.opts.clock.sleep(self.opts.idle_timeout);
            let conn = self.conn.as_mut().expect("connected");
            let read = tokio::select! {
                biased;
                chunk = conn.chunk() => Some(chunk),
                _ = idle => None,
            };
            match read {
                None => {
                    let secs = self.opts.idle_timeout.as_secs_f64();
                    self.schedule_reconnect(false, format!("no data for {secs:.0} s"));
                }
                Some(Ok(None)) => {
                    self.schedule_reconnect(false, "the relay closed the connection".into());
                }
                Some(Err(e)) => self.schedule_reconnect(false, Error::from(e).to_string()),
                Some(Ok(Some(bytes))) => {
                    if let Err(e) = self.process(&bytes) {
                        return self.fail(e);
                    }
                }
            }
        }
    }

    /// Parse a chunk, record its `hook` events, and queue everything for the ack and the handover.
    fn process(&mut self, bytes: &[u8]) -> Result<()> {
        let items = match self.parser.push(bytes) {
            Ok(items) => items,
            Err(e) => {
                self.schedule_reconnect(false, e.to_string());
                return Ok(());
            }
        };
        let mut batch: Vec<StreamEvent> = Vec::new();
        let mut hooks: Vec<Event> = Vec::new();
        let mut gaps_to = 0u64;
        for item in items {
            let ev = match item {
                SseItem::Retry(ms) => {
                    self.backoff.set_base(Duration::from_millis(ms));
                    continue;
                }
                SseItem::Comment(_) => continue,
                SseItem::Event(ev) => ev,
            };
            let kind = ev.event.as_deref().unwrap_or("message");
            match kind {
                "ready" => match serde_json::from_str::<Ready>(&ev.data) {
                    Ok(r) => {
                        self.backoff.reset();
                        batch.push(StreamEvent::Ready(r));
                    }
                    Err(e) => batch.push(warn_unreadable("ready", ev.id.as_deref(), &e)),
                },
                "hook" => match serde_json::from_str::<Event>(&ev.data) {
                    Ok(e) => {
                        hooks.push(e.clone());
                        batch.push(StreamEvent::Hook(e));
                    }
                    Err(e) => batch.push(warn_unreadable("hook", ev.id.as_deref(), &e)),
                },
                "gap" => match serde_json::from_str::<Gap>(&ev.data) {
                    Ok(g) => {
                        gaps_to = gaps_to.max(g.to);
                        batch.push(StreamEvent::Gap(g));
                    }
                    Err(e) => batch.push(warn_unreadable("gap", ev.id.as_deref(), &e)),
                },
                "resync" => {
                    match serde_json::from_str::<Resync>(&ev.data) {
                        Ok(r) => batch.push(StreamEvent::Resync(r)),
                        Err(e) => batch.push(warn_unreadable("resync", ev.id.as_deref(), &e)),
                    }
                    // Catch up from our own cursor: it is what we have recorded.
                    self.then = Some(Then::Reconnect {
                        immediate: true,
                        reason: "the relay asked to resync".into(),
                    });
                    break;
                }
                "closed" => {
                    let closed = serde_json::from_str::<Closed>(&ev.data).unwrap_or(Closed {
                        code: 1000,
                        reason: String::new(),
                    });
                    self.then = Some(match close_action(closed.code) {
                        CloseAction::Stop => Then::Stop(closed),
                        CloseAction::ReconnectNow => Then::Reconnect {
                            immediate: true,
                            reason: describe_close(&closed),
                        },
                        CloseAction::Reconnect => Then::Reconnect {
                            immediate: false,
                            reason: describe_close(&closed),
                        },
                    });
                    break;
                }
                _ => {}
            }
        }

        // Record first (durably), then queue the ack; the handover waits for both.
        let fresh = self.store.record(&hooks)?;
        if gaps_to > 0 {
            self.store.advance_cursor(gaps_to)?;
        }
        let mut fresh_ids: HashSet<String> = fresh.into_iter().map(|e| e.id).collect();
        batch.retain(|ev| match ev {
            StreamEvent::Hook(e) => fresh_ids.remove(&e.id),
            _ => true,
        });
        let through = hooks.iter().map(|e| e.seq).max().unwrap_or(0);
        if through > self.acked {
            self.ack_through = Some(through);
            self.awaiting_ack.extend(batch);
        } else {
            self.out.extend(batch);
        }
        Ok(())
    }
}

fn warn_unreadable(kind: &str, id: Option<&str>, e: &serde_json::Error) -> StreamEvent {
    let at = id.map(|i| format!(" (id {i})")).unwrap_or_default();
    StreamEvent::Warning(format!(
        "skipped a `{kind}` message{at} that couldn't be read: {e}"
    ))
}

fn describe_close(c: &Closed) -> String {
    let what = match c.code {
        4408 => "the relay closed the stream because it was read too slowly",
        1012 => "the relay is restarting",
        _ => "the relay closed the stream",
    };
    if c.reason.is_empty() {
        format!("{what} ({})", c.code)
    } else {
        format!("{what} ({}: {})", c.code, c.reason)
    }
}

/// Open the stream, wait for `ready`, and close it, recording nothing (for `00hooks doctor`).
///
/// Opening a stream replaces any other stream of the same device (PROTOCOL §6, `4409`), so callers
/// should not probe while a listener for this device is running.
pub async fn probe(client: &Client, timeout: Duration) -> Result<Ready> {
    let attempt = async {
        let mut resp = client.open_stream(None).await?;
        let mut parser = SseParser::default();
        while let Some(chunk) = resp.chunk().await? {
            let items = parser
                .push(&chunk)
                .map_err(|e| Error::Protocol(e.to_string()))?;
            for item in items {
                if let SseItem::Event(ev) = item {
                    match ev.event.as_deref() {
                        Some("ready") => {
                            return serde_json::from_str::<Ready>(&ev.data)
                                .map_err(|e| Error::Protocol(format!("unreadable ready: {e}")));
                        }
                        Some("closed") => {
                            let c: Closed = serde_json::from_str(&ev.data).unwrap_or(Closed {
                                code: 1000,
                                reason: String::new(),
                            });
                            return Err(Error::Closed {
                                code: c.code,
                                reason: c.reason,
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
        Err(Error::Protocol(
            "the stream ended before saying ready".into(),
        ))
    };
    tokio::time::timeout(timeout, attempt)
        .await
        .map_err(|_| Error::Network(format!("no ready event within {} s", timeout.as_secs())))?
}
