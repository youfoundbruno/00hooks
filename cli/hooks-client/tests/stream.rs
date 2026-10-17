//! End-to-end tests of the client against the in-process mock relay in `common`.

mod common;

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use common::{Conn, MockRelay, TempHome};
use hooks_client::backoff::{Clock, Jitter};
use hooks_client::{
    Client, DeviceKey, Error, StateDir, StreamEvent, SubscribeOptions, Subscription, subscribe,
};

/// A device on the mock relay, with a state directory the relay can inspect on ack.
async fn device(relay: &MockRelay, tag: &str) -> (Client, StateDir, TempHome) {
    let key = DeviceKey::generate().unwrap();
    let joined = Client::new(&relay.url)
        .unwrap()
        .create_account("test", &key.public_key(), None)
        .await
        .unwrap();
    assert_eq!(joined.account_id, "acc_1");
    let client = Client::with_device(&relay.url, &joined.device_id, key).unwrap();
    let home = TempHome::new(tag);
    let state = StateDir::open(&home.0).unwrap();
    relay.with(|s| s.client_home = Some(home.0.clone()));
    (client, state, home)
}

fn fast() -> SubscribeOptions {
    SubscribeOptions {
        idle_timeout: Duration::from_secs(5),
        min_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(50),
        jitter: Jitter::new(42),
        ..Default::default()
    }
}

/// Read until `hooks` hook events have been handed over; returns everything yielded.
async fn read_hooks(sub: &mut Subscription, hooks: usize) -> Vec<StreamEvent> {
    let mut all = Vec::new();
    let mut n = 0;
    let fut = async {
        while n < hooks {
            let ev = sub
                .next()
                .await
                .expect("stream ended")
                .expect("stream failed");
            if matches!(ev, StreamEvent::Hook(_)) {
                n += 1;
            }
            all.push(ev);
        }
    };
    tokio::time::timeout(Duration::from_secs(20), fut)
        .await
        .expect("timed out waiting for events");
    all
}

fn hook_seqs(evs: &[StreamEvent]) -> Vec<u64> {
    evs.iter()
        .filter_map(|e| match e {
            StreamEvent::Hook(h) => Some(h.seq),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn no_event_is_lost_or_handed_over_twice_across_drops_and_replays() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=30);
    relay.with(|s| {
        s.script.extend([
            // Drops mid-frame after 10 events.
            Conn::CutAfter(10),
            // Resumes 3 seqs early (an at-least-once relay re-sending 8–10), then stays live.
            Conn::Rewind(3),
        ]);
    });
    let (client, state, _home) = device(&relay, "e2e").await;
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());

    let evs = read_hooks(&mut sub, 30).await;
    assert_eq!(hook_seqs(&evs), (1..=30).collect::<Vec<_>>());
    let reconnects = evs
        .iter()
        .filter(|e| matches!(e, StreamEvent::Reconnecting { .. }))
        .count();
    assert_eq!(reconnects, 1, "{evs:#?}");

    relay.with(|s| {
        assert!(s.violations.is_empty(), "{:?}", s.violations);
        assert_eq!(s.stream_requests[0], None);
        assert_eq!(
            s.stream_requests[1],
            Some(10),
            "resumes from the durable cursor"
        );
        assert!(
            s.acks.windows(2).all(|w| w[0] < w[1]),
            "acks only move forward: {:?}",
            s.acks
        );
        assert_eq!(s.acked, 30);
    });
    assert_eq!(sub.store().cursor(), 30);

    // Push more while connected: live events arrive too, and nothing old comes back.
    relay.push_events(31..=33);
    let evs = read_hooks(&mut sub, 3).await;
    assert_eq!(hook_seqs(&evs), vec![31, 32, 33]);
}

#[tokio::test]
async fn duplicates_from_a_replaying_relay_are_never_handed_over() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=8);
    relay.with(|s| {
        s.script
            .extend([Conn::CloseAfter(5, 1012), Conn::Rewind(5)]);
    });
    let (client, state, _home) = device(&relay, "dupes").await;
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    let evs = read_hooks(&mut sub, 8).await;
    assert_eq!(hook_seqs(&evs), (1..=8).collect::<Vec<_>>());
    // The 1012 close reconnected with backoff (not at once), and the relay re-sent old seqs.
    assert!(evs.iter().any(|e| matches!(e,
        StreamEvent::Reconnecting { delay, reason, .. }
            if !delay.is_zero() && reason.contains("restarting"))));
    relay.with(|s| assert!(s.violations.is_empty(), "{:?}", s.violations));

    // The live connection keeps sending heartbeats; nothing more is handed over.
    let more = tokio::time::timeout(Duration::from_millis(400), sub.next()).await;
    if let Ok(Some(Ok(StreamEvent::Hook(h)))) = more {
        panic!("handed over {} twice", h.id);
    }
}

#[tokio::test]
async fn a_crash_between_record_and_handover_hands_over_after_restart() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=5);
    let (client, state, _home) = device(&relay, "crash").await;
    {
        // The earlier run recorded 1–3 and handed over only 1, then died before acking.
        let mut events = state.open_events().unwrap();
        let recorded: Vec<_> = (1..=3)
            .map(|n| serde_json::from_value(common::event(n)).unwrap())
            .collect();
        events.record(&recorded).unwrap();
        events.mark_delivered("evt_0001").unwrap();
    }
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    let evs = read_hooks(&mut sub, 4).await;
    assert_eq!(hook_seqs(&evs), vec![2, 3, 4, 5]);
    relay.with(|s| {
        assert_eq!(
            s.acks[0], 3,
            "the recorded events are acknowledged before the handover"
        );
        assert_eq!(s.stream_requests[0], Some(3));
        assert!(s.violations.is_empty(), "{:?}", s.violations);
    });
}

#[tokio::test]
async fn too_slow_reconnects_at_once_and_replaced_stops() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=4);
    relay.with(|s| {
        s.script
            .extend([Conn::CloseAfter(2, 4408), Conn::CloseAfter(2, 4409)])
    });
    let (client, state, _home) = device(&relay, "codes").await;
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    let evs = read_hooks(&mut sub, 4).await;
    assert!(evs.iter().any(|e| matches!(e,
        StreamEvent::Reconnecting { delay, .. } if delay.is_zero())));
    match sub.next().await {
        Some(Err(Error::Closed { code: 4409, .. })) => {}
        other => panic!("expected a terminal 4409, got {other:?}"),
    }
    assert!(sub.next().await.is_none());
    relay.with(|s| assert_eq!(s.stream_requests.len(), 2));
}

#[tokio::test]
async fn resync_reconnects_from_the_cursor() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=6);
    relay.with(|s| s.script.push_back(Conn::ResyncAfter(4)));
    let (client, state, _home) = device(&relay, "resync").await;
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    let evs = read_hooks(&mut sub, 6).await;
    assert_eq!(hook_seqs(&evs), (1..=6).collect::<Vec<_>>());
    assert!(
        evs.iter()
            .any(|e| matches!(e, StreamEvent::Resync(r) if r.after == 4))
    );
    relay.with(|s| assert_eq!(s.stream_requests, vec![None, Some(4)]));
}

#[tokio::test]
async fn gaps_are_reported_before_the_next_event_and_skip_the_cursor() {
    let relay = MockRelay::start().await;
    relay.push_events(4..=5);
    relay.with(|s| s.script.push_back(Conn::Gap(1, 3)));
    let (client, state, _home) = device(&relay, "gap").await;
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    let evs = read_hooks(&mut sub, 2).await;
    let kinds: Vec<_> = evs
        .iter()
        .map(|e| match e {
            StreamEvent::Ready(_) => "ready".to_string(),
            StreamEvent::Gap(g) => format!("gap {}-{}", g.from, g.to),
            StreamEvent::Hook(h) => format!("hook {}", h.seq),
            other => format!("{other:?}"),
        })
        .collect();
    assert_eq!(kinds, vec!["ready", "gap 1-3", "hook 4", "hook 5"]);
    assert_eq!(sub.store().cursor(), 5);
}

#[tokio::test]
async fn a_revoked_device_stops_instead_of_retrying() {
    let relay = MockRelay::start().await;
    let (client, state, _home) = device(&relay, "revoked").await;
    relay.with(|s| {
        let ids: Vec<_> = s.devices.keys().cloned().collect();
        s.revoked.extend(ids);
    });
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    match sub.next().await {
        Some(Err(e)) => assert!(e.is_unauthorized(), "{e}"),
        other => panic!("expected unauthorized, got {other:?}"),
    }
    assert!(sub.next().await.is_none());
}

/// A fake clock for [`Clock`]: sleeps wait on virtual time, which only moves when the test says.
#[derive(Clone, Default)]
struct ManualClock {
    inner: Arc<Mutex<Virtual>>,
}

/// Virtual now, and each sleeper's deadline.
#[derive(Default)]
struct Virtual(Duration, Vec<(Duration, oneshot::Sender<()>)>);

impl Clock for ManualClock {
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let (tx, rx) = oneshot::channel();
        let mut g = self.inner.lock().unwrap();
        let at = g.0 + d;
        g.1.push((at, tx));
        Box::pin(async move {
            let _ = rx.await;
        })
    }
}

impl ManualClock {
    /// Jump to the earliest pending deadline and wake everything due. Returns virtual now.
    fn advance(&self) -> Duration {
        let mut g = self.inner.lock().unwrap();
        g.1.retain(|(_, tx)| !tx.is_closed());
        let next =
            g.1.iter()
                .map(|(at, _)| *at)
                .min()
                .expect("nothing is sleeping");
        g.0 = next;
        let (due, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut g.1)
            .into_iter()
            .partition(|(at, _)| *at <= next);
        g.1 = rest;
        for (_, tx) in due {
            let _ = tx.send(());
        }
        next
    }
}

#[tokio::test]
async fn a_silent_connection_counts_as_dead_after_70_seconds() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=2);
    relay.with(|s| s.script.extend([Conn::Silent, Conn::Silent]));
    let (client, state, _home) = device(&relay, "idle").await;
    let clock = ManualClock::default();
    let opts = SubscribeOptions {
        jitter: Jitter::new(3),
        clock: Arc::new(clock.clone()),
        ..Default::default()
    };
    let mut sub = subscribe(client, state.open_events().unwrap(), opts);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let reader = tokio::spawn(async move {
        while let Some(r) = sub.next().await {
            if tx.send(r).is_err() {
                return;
            }
        }
    });

    // Whenever the subscription has been quiet for a while (real time), move the fake clock to
    // its next deadline: the 70 s idle timer, or a backoff wait.
    let mut delays = Vec::new();
    let mut seqs = Vec::new();
    let mut virtual_now = Duration::ZERO;
    while seqs.len() < 2 {
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Err(_) => virtual_now = clock.advance(),
            Ok(Some(Ok(StreamEvent::Reconnecting { delay, reason, .. }))) => {
                assert_eq!(reason, "no data for 70 s");
                delays.push(delay);
            }
            Ok(Some(Ok(StreamEvent::Hook(h)))) => seqs.push(h.seq),
            Ok(Some(Ok(_))) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    reader.abort();
    assert_eq!(seqs, vec![1, 2]);
    assert_eq!(delays.len(), 2);
    // `retry: 5000` sets the base, and each silent connection did say `ready` (which resets the
    // sequence), so both waits are in 2.5–5 s.
    for d in &delays {
        assert!(
            *d >= Duration::from_millis(2500) && *d <= Duration::from_secs(5),
            "{d:?}"
        );
    }
    assert_eq!(
        virtual_now,
        Duration::from_secs(140) + delays[0] + delays[1]
    );
    relay.with(|s| assert_eq!(s.stream_requests.len(), 3));
}

#[tokio::test]
async fn clock_skew_is_corrected_once_then_reported() {
    let relay = MockRelay::start().await;
    let (client, _state, _home) = device(&relay, "skew").await;
    relay.with(|s| s.clock_offset_ms = 10 * 60 * 1000);
    let devices = client.devices().await.unwrap();
    assert!(devices[0].current);
    let offset = client.clock_offset_ms();
    assert!((offset - 600_000).abs() < 5_000, "{offset}");
    relay.with(|s| assert_eq!(s.skew_refusals, 1));
    // Already corrected: the next call goes straight through.
    client.devices().await.unwrap();
    relay.with(|s| assert_eq!(s.skew_refusals, 1));

    relay.with(|s| s.always_skew = true);
    match client.devices().await {
        Err(Error::ClockSkew { .. }) => {}
        other => panic!("expected ClockSkew, got {other:?}"),
    }
    relay.with(|s| {
        assert_eq!(s.skew_refusals, 3, "one retry, not more");
        assert!(s.violations.is_empty(), "{:?}", s.violations);
    });
}

#[tokio::test]
async fn hook_secrets_come_back_once_and_never_print() {
    let relay = MockRelay::start().await;
    let (client, _state, _home) = device(&relay, "hooks").await;
    let created = client
        .create_hook("ci", serde_json::json!({ "preset": "github" }))
        .await
        .unwrap();
    assert_eq!(created.hook.verify.preset, "github");
    let secret = created.secret.as_ref().expect("secret");
    assert_eq!(secret.expose(), "s3cret");
    assert!(!format!("{created:?}").contains("s3cret"));
    assert!(!format!("{secret:?}").contains("s3cret"));
}

#[tokio::test]
async fn the_mock_notices_an_ack_of_events_that_were_never_recorded() {
    // Proves the ack-after-record check above is live: acking without recording is caught.
    let relay = MockRelay::start().await;
    relay.push_events(1..=3);
    let (client, _state, _home) = device(&relay, "ackcheck").await;
    client.ack(3).await.unwrap();
    relay.with(|s| assert_eq!(s.violations.len(), 3, "{:?}", s.violations));
}
