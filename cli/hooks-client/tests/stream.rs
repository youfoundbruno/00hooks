//! End-to-end tests of the client against the in-process mock relay in `common`.

mod common;

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use base64::Engine;
use common::{Conn, MockRelay, TempHome};
use hooks_client::backoff::{Clock, Jitter};
use hooks_client::seal::StrictSecrets;
use hooks_client::store::QuarantineKind;
use hooks_client::{
    Client, DeviceKey, Error, Opener, SealKey, StateDir, StreamEvent, StrictHook, SubscribeOptions,
    Subscription, subscribe,
};

/// A device on the mock relay, with a state directory the relay can inspect on ack. Every device
/// seals: a subscription without an opener refuses to start.
async fn device(relay: &MockRelay, tag: &str) -> (Client, StateDir, TempHome) {
    let (client, state, home, _) = sealed_device(relay, tag).await;
    (client, state, home)
}

/// A protocol 2 device: it registered a sealing key, and its client opens what is sealed to it
/// (checking the mock relay's signature with the key pinned from `/v1/info`).
async fn sealed_device(relay: &MockRelay, tag: &str) -> (Client, StateDir, TempHome, String) {
    let key = DeviceKey::generate().unwrap();
    let seal = SealKey::generate().unwrap();
    let anon = Client::new(&relay.url).unwrap();
    let info = anon.info().await.unwrap();
    assert!(info.serves(2));
    let joined = anon
        .create_account("test", &key.public_key(), Some(&seal.public_key()), None)
        .await
        .unwrap();
    let client = Client::with_device(&relay.url, &joined.device_id, key).unwrap();
    let kid = seal.kid();
    let mut opener = Opener::new(&joined.device_id, info.relay_key.as_deref()).unwrap();
    opener.add_key(seal);
    client.set_opener(opener);
    let home = TempHome::new(tag);
    let state = StateDir::open(&home.0).unwrap();
    relay.with(|s| s.client_home = Some(home.0.clone()));
    (client, state, home, kid)
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

#[tokio::test]
async fn probe_reads_ready_and_records_nothing() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=4);
    let (client, state, _home) = device(&relay, "probe").await;
    let ready = hooks_client::stream::probe(&client, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!((ready.after, ready.head), (0, 4));
    assert_eq!(state.open_events().unwrap().cursor(), 0);
    relay.with(|s| assert!(s.acks.is_empty()));
}

#[tokio::test]
async fn a_failed_ack_is_retried_while_newer_events_keep_flowing_in_order() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=3);
    relay.with(|s| s.fail_acks = 1_000);
    let (client, state, _home) = device(&relay, "ackretry").await;
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());

    // Handed over even though the relay refuses every acknowledgement.
    let evs = read_hooks(&mut sub, 3).await;
    assert_eq!(hook_seqs(&evs), vec![1, 2, 3]);
    // Newer events keep arriving, in order, while the ack is refused and retried.
    relay.push_events(4..=5);
    let more = read_hooks(&mut sub, 2).await;
    assert_eq!(hook_seqs(&more), vec![4, 5]);
    let warnings = evs
        .iter()
        .chain(more.iter())
        .filter(|e| matches!(e, StreamEvent::Warning(w) if w.contains("retried")))
        .count();
    assert_eq!(warnings, 1, "one warning per streak, not one per attempt");

    // No new event comes now: only the retry can get the ack through once the relay takes acks.
    relay.with(|s| s.fail_acks = 0);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while relay.with(|s| s.acked) < 5 {
        assert!(
            std::time::Instant::now() < deadline,
            "the ack was never retried"
        );
        let _ = tokio::time::timeout(Duration::from_millis(100), sub.next()).await;
    }
    relay.with(|s| {
        assert!(s.failed_acks >= 2, "{}", s.failed_acks);
        assert!(s.violations.is_empty(), "{:?}", s.violations);
        assert_eq!(
            s.acks,
            vec![5],
            "only the successful ack is recorded, covering everything"
        );
    });
}

#[tokio::test]
async fn an_unreadable_hook_frame_is_quarantined_not_skipped() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=4);
    relay.with(|s| {
        s.garbled.insert(2);
    });
    let (client, state, home) = device(&relay, "quarantine").await;
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    let evs = read_hooks(&mut sub, 3).await;
    let kinds: Vec<String> = evs
        .iter()
        .filter_map(|e| match e {
            StreamEvent::Hook(h) => Some(format!("hook {}", h.seq)),
            StreamEvent::Quarantined { seq, .. } => Some(format!("quarantined {seq:?}")),
            _ => None,
        })
        .collect();
    assert_eq!(
        kinds,
        vec!["hook 1", "quarantined Some(2)", "hook 3", "hook 4"]
    );
    let path = evs
        .iter()
        .find_map(|e| match e {
            StreamEvent::Quarantined { path, .. } => Some(path.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(path, home.0.join("quarantine.jsonl"));

    // The raw message is on disk, and the ack past it only came after it was.
    let q = sub.store().quarantined().unwrap();
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].seq, Some(2));
    assert_eq!(q[0].data, "{\"seq\":2,\"id\":\"evt_garbled");
    assert_eq!(sub.store().cursor(), 4);
    relay.with(|s| {
        assert!(s.violations.is_empty(), "{:?}", s.violations);
        assert_eq!(s.acked, 4);
    });
}

#[tokio::test]
async fn an_unreadable_last_frame_is_recorded_before_it_is_acknowledged() {
    // Nothing readable after it: the ack still covers it, because the quarantine recorded it.
    let relay = MockRelay::start().await;
    relay.push_events(1..=2);
    relay.with(|s| {
        s.garbled.insert(2);
    });
    let (client, state, _home) = device(&relay, "quarantine-last").await;
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    let evs = read_hooks(&mut sub, 1).await;
    assert_eq!(hook_seqs(&evs), vec![1]);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while relay.with(|s| s.acked) < 2 {
        assert!(std::time::Instant::now() < deadline, "never acknowledged");
        let _ = tokio::time::timeout(Duration::from_millis(100), sub.next()).await;
    }
    relay.with(|s| assert!(s.violations.is_empty(), "{:?}", s.violations));
    assert_eq!(sub.store().quarantined().unwrap().len(), 1);
}

#[tokio::test]
async fn sealed_events_are_opened_before_they_are_recorded_or_handed_over() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=5);
    relay.with(|s| s.script.push_back(Conn::CutAfter(2)));
    let (client, state, home, _) = sealed_device(&relay, "sealed").await;
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    let evs = read_hooks(&mut sub, 5).await;
    assert_eq!(hook_seqs(&evs), (1..=5).collect::<Vec<_>>());
    for ev in &evs {
        if let StreamEvent::Hook(h) = ev {
            // Opened: the content is back, the envelope gone, as in protocol 1.
            assert!(h.sealed.is_none() && h.sig.is_none());
            assert_eq!(
                h.body_bytes().unwrap(),
                format!("{{\"n\":{}}}", h.seq).as_bytes()
            );
            assert_eq!(h.headers["x-github-event"], "push");
            assert_eq!(h.content_type.as_deref(), Some("application/json"));
        }
    }
    // Every stream request asked for protocol 2.
    relay.with(|s| {
        assert!(!s.stream_protocols.is_empty());
        assert!(s.stream_protocols.iter().all(|p| p.as_deref() == Some("2")));
        assert!(s.violations.is_empty(), "{:?}", s.violations);
    });
    // What the store kept is the opened event, never an envelope.
    let inbox = std::fs::read_to_string(home.0.join("inbox.jsonl")).unwrap_or_default();
    assert!(!inbox.contains("\"sealed\""), "{inbox}");
}

#[tokio::test]
async fn a_forged_or_unsealed_event_is_quarantined_and_never_handed_over() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=4);
    relay.with(|s| {
        s.forged.insert(2);
        s.unsealed.insert(3);
    });
    let (client, state, _home, _) = sealed_device(&relay, "forged").await;
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    let evs = read_hooks(&mut sub, 2).await;
    let kinds: Vec<String> = evs
        .iter()
        .filter_map(|e| match e {
            StreamEvent::Hook(h) => Some(format!("hook {}", h.seq)),
            StreamEvent::Quarantined { seq, error, .. } => {
                Some(format!("quarantined {} {}", seq.unwrap(), error))
            }
            _ => None,
        })
        .collect();
    assert_eq!(kinds.len(), 4, "{kinds:?}");
    assert_eq!(kinds[0], "hook 1");
    assert!(
        kinds[1].starts_with("quarantined 2") && kinds[1].contains("signature"),
        "{kinds:?}"
    );
    assert!(
        kinds[2].starts_with("quarantined 3") && kinds[2].contains("unsealed"),
        "{kinds:?}"
    );
    assert_eq!(kinds[3], "hook 4");
    // Kept raw and acknowledged past: nothing silently skipped.
    assert_eq!(sub.store().quarantined().unwrap().len(), 2);
    relay.with(|s| {
        assert!(s.violations.is_empty(), "{:?}", s.violations);
        assert_eq!(s.acked, 4);
    });
}

#[tokio::test]
async fn ready_says_so_when_the_relay_seals_to_a_key_this_computer_lacks() {
    let relay = MockRelay::start().await;
    let (client, state, _home, _) = sealed_device(&relay, "otherkey").await;
    // Another sealing key set for this device (by a newer login elsewhere, say).
    let other = SealKey::generate().unwrap();
    let kid = client.set_seal_key(&other.public_key()).await.unwrap();
    assert_eq!(kid, other.kid());
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    let first = tokio::time::timeout(Duration::from_secs(5), sub.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    match first {
        StreamEvent::Warning(w) => assert!(w.contains(&kid) && w.contains("seal-key"), "{w}"),
        other => panic!("expected a warning first, got {other:?}"),
    }
}

#[tokio::test]
async fn confirm_mode_hands_over_again_after_a_restart_until_confirmed() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=3);
    let (client, state, _home, _) = sealed_device(&relay, "confirm").await;
    let opts = SubscribeOptions {
        confirm: true,
        ..fast()
    };
    {
        let mut sub = subscribe(client.clone(), state.open_events().unwrap(), opts.clone());
        let evs = read_hooks(&mut sub, 3).await;
        assert_eq!(hook_seqs(&evs), vec![1, 2, 3]);
        // The consumer recorded 1 and 2, then died before recording 3.
        sub.confirm("evt_0001").unwrap();
        sub.confirm("evt_0002").unwrap();
    }
    relay.with(|s| assert_eq!(s.acked, 3, "acknowledged once recorded here"));
    let mut sub = subscribe(client, state.open_events().unwrap(), opts);
    let evs = read_hooks(&mut sub, 1).await;
    let again: Vec<String> = evs
        .iter()
        .filter_map(|e| match e {
            StreamEvent::Hook(h) => Some(h.id.clone()),
            _ => None,
        })
        .collect();
    // Same id, opened content, handed over again; the confirmed ones never come back.
    assert_eq!(again, vec!["evt_0003"]);
    sub.confirm("evt_0003").unwrap();
    relay.push_events(4..=4);
    let evs = read_hooks(&mut sub, 1).await;
    assert_eq!(hook_seqs(&evs), vec![4]);
    assert!(sub.store().pending().iter().all(|e| e.id == "evt_0004"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_next_cancelled_during_an_ack_loses_neither_the_ack_nor_the_events() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=2);
    relay.with(|s| s.ack_delay = Duration::from_millis(300));
    let (client, state, _home) = device(&relay, "cancel").await;
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    // Read until a batch is recorded and its ack is in flight, then give up on it (as a select!
    // does), a few times over.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut cancelled = 0;
    while sub.store().cursor() < 1 || cancelled < 3 {
        if sub.store().cursor() >= 1 {
            cancelled += 1;
        }
        assert!(std::time::Instant::now() < deadline, "never recorded");
        let r = tokio::time::timeout(Duration::from_millis(50), sub.next()).await;
        assert!(
            !matches!(r, Ok(Some(Ok(StreamEvent::Hook(_))))),
            "handed over before the ack"
        );
    }
    relay.with(|s| s.ack_delay = Duration::ZERO);
    let evs = read_hooks(&mut sub, 2).await;
    assert_eq!(hook_seqs(&evs), vec![1, 2]);
    relay.with(|s| {
        assert_eq!(s.acked, 2);
        assert!(s.violations.is_empty(), "{:?}", s.violations);
    });
}

/// The strict hook of the tests below, and its secret.
const STRICT_HOOK: &str = "hk_strict";
const GH_SECRET: &str = "gh-device-secret";

/// The strict secrets a device holds, changed by the test as it goes.
#[derive(Clone, Default)]
struct Secrets(Arc<Mutex<Option<StrictHook>>>);

impl StrictSecrets for Secrets {
    fn get(&self, hook_id: &str) -> hooks_client::Result<Option<StrictHook>> {
        Ok(if hook_id == STRICT_HOOK {
            self.0.lock().unwrap().clone()
        } else {
            None
        })
    }
}

impl Secrets {
    fn add(&self) {
        *self.0.lock().unwrap() = Some(StrictHook {
            verify: serde_json::json!({"preset": "github", "strict": true}),
            secrets: vec![GH_SECRET.into()],
        });
    }
}

/// A sealed device whose opener asks `secrets` about strict hooks.
async fn strict_device(
    relay: &MockRelay,
    tag: &str,
    secrets: Secrets,
) -> (Client, StateDir, TempHome) {
    let key = DeviceKey::generate().unwrap();
    let seal = SealKey::generate().unwrap();
    let anon = Client::new(&relay.url).unwrap();
    let info = anon.info().await.unwrap();
    let joined = anon
        .create_account("test", &key.public_key(), Some(&seal.public_key()), None)
        .await
        .unwrap();
    let client = Client::with_device(&relay.url, &joined.device_id, key).unwrap();
    let mut opener = Opener::new(&joined.device_id, info.relay_key.as_deref()).unwrap();
    opener.add_key(seal);
    client.set_opener(opener.with_strict(Box::new(secrets)));
    let home = TempHome::new(tag);
    let state = StateDir::open(&home.0).unwrap();
    relay.with(|s| s.client_home = Some(home.0.clone()));
    (client, state, home)
}

/// A genuine GitHub delivery to the strict hook, as the relay stores it (`verified: false`).
fn strict_event(seq: u64) -> serde_json::Value {
    use hmac::{KeyInit, Mac};
    let body = format!("{{\"strict\":{seq}}}");
    let mut m = <hmac::Hmac<sha2::Sha256>>::new_from_slice(GH_SECRET.as_bytes()).unwrap();
    m.update(body.as_bytes());
    let sig: String = m
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut e = common::event(seq);
    e["hookId"] = serde_json::json!(STRICT_HOOK);
    e["verified"] = serde_json::json!(false);
    e["strict"] = serde_json::json!(true);
    e["receivedAt"] = serde_json::json!(common::now_ms());
    e["headers"] = serde_json::json!({ "x-hub-signature-256": format!("sha256={sig}") });
    e["body"] = serde_json::json!(base64::engine::general_purpose::STANDARD.encode(body));
    e
}

fn describe(ev: &StreamEvent) -> String {
    match ev {
        StreamEvent::Ready(_) => "ready".into(),
        StreamEvent::Hook(h) => format!("hook {}", h.seq),
        StreamEvent::Gap(g) => format!("gap {}-{}", g.from, g.to),
        StreamEvent::Quarantined { seq, error, .. } => format!("quarantined {seq:?}: {error}"),
        StreamEvent::Reconnecting { reason, .. } => format!("reconnecting: {reason}"),
        StreamEvent::Warning(w) => format!("warning: {w}"),
        StreamEvent::Resync(_) => "resync".into(),
    }
}

/// Read until `pred` holds for an event; returns everything read, described.
async fn read_until(sub: &mut Subscription, pred: impl Fn(&StreamEvent) -> bool) -> Vec<String> {
    let mut seen = Vec::new();
    let fut = async {
        loop {
            let ev = sub.next().await.expect("ended").expect("failed");
            seen.push(describe(&ev));
            if pred(&ev) {
                return;
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .is_err()
    {
        panic!("timed out; read {seen:#?}");
    }
    seen
}

#[tokio::test]
async fn a_subscription_without_an_opener_refuses_to_start() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=1);
    let key = DeviceKey::generate().unwrap();
    let joined = Client::new(&relay.url)
        .unwrap()
        .create_account("test", &key.public_key(), None, None)
        .await
        .unwrap();
    let client = Client::with_device(&relay.url, &joined.device_id, key).unwrap();
    let home = TempHome::new("noopener");
    let state = StateDir::open(&home.0).unwrap();
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    match sub.next().await {
        Some(Err(Error::Invalid(m))) => assert!(m.contains("Opener"), "{m}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(sub.next().await.is_none());
    assert!(
        relay.with(|s| s.stream_requests.is_empty()),
        "never connected"
    );
}

#[tokio::test]
async fn a_strict_event_without_its_secret_is_held_unacknowledged_until_the_secret_arrives() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=1);
    relay.with(|s| s.log.push(strict_event(2)));
    relay.push_events(3..=3);
    let secrets = Secrets::default();
    let (client, state, _home) = strict_device(&relay, "hold", secrets.clone()).await;
    let opts = SubscribeOptions {
        hold_attempts: 1000,
        ..fast()
    };
    let mut sub = subscribe(client, state.open_events().unwrap(), opts);
    let seen = read_until(&mut sub, |e| matches!(e, StreamEvent::Reconnecting { .. })).await;
    assert!(seen.contains(&"hook 1".to_string()), "{seen:?}");
    assert!(
        seen.iter().any(|l| l.contains("event 2 is held")),
        "{seen:?}"
    );
    // Not acknowledged: the relay keeps it (and everything after it).
    assert_eq!(relay.with(|s| s.acked), 1);
    secrets.add();
    let seen = read_until(
        &mut sub,
        |e| matches!(e, StreamEvent::Hook(h) if h.seq == 3),
    )
    .await;
    assert!(seen.contains(&"hook 2".to_string()), "{seen:?}");
    assert!(
        !seen.iter().any(|l| l.starts_with("quarantined")),
        "{seen:?}"
    );
    assert!(sub.store().quarantined().unwrap().is_empty());
    assert!(relay.with(|s| s.violations.is_empty()));
}

#[tokio::test]
async fn a_strict_event_held_too_long_is_kept_whole_and_opens_on_a_later_reconnect() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=1);
    relay.with(|s| s.log.push(strict_event(2)));
    relay.push_events(3..=3);
    let secrets = Secrets::default();
    let (client, state, _home) = strict_device(&relay, "holdq", secrets.clone()).await;
    let opts = SubscribeOptions {
        hold_attempts: 2,
        ..fast()
    };
    let mut sub = subscribe(client.clone(), state.open_events().unwrap(), opts.clone());
    let seen = read_until(
        &mut sub,
        |e| matches!(e, StreamEvent::Hook(h) if h.seq == 3),
    )
    .await;
    assert_eq!(
        seen.iter()
            .filter(|l| l.starts_with("reconnecting: event 2 is held"))
            .count(),
        2,
        "{seen:?}"
    );
    assert!(
        seen.iter().any(|l| l.starts_with("quarantined Some(2)")),
        "{seen:?}"
    );
    let q = sub.store().quarantined().unwrap();
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].kind, QuarantineKind::Recoverable);
    assert!(!q[0].data.is_empty(), "kept whole");
    drop(sub);
    // The secret is added; the next connection's `ready` opens it from the quarantine.
    secrets.add();
    let mut sub = subscribe(client, state.open_events().unwrap(), opts);
    let seen = read_until(&mut sub, |e| matches!(e, StreamEvent::Hook(_))).await;
    assert!(seen.contains(&"hook 2".to_string()), "{seen:?}");
    assert!(sub.store().quarantined().unwrap().is_empty());
    assert!(relay.with(|s| s.violations.is_empty()));
}

#[tokio::test]
async fn an_old_seq_sent_again_under_a_new_id_is_quarantined_not_run() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=3);
    let (client, state, _home) = device(&relay, "stale").await;
    let mut sub = subscribe(client.clone(), state.open_events().unwrap(), fast());
    read_hooks(&mut sub, 3).await;
    drop(sub);
    // A relay that resends seq 2 (as a new event: its id has long left the seen set, say).
    relay.with(|s| {
        s.log[1]["id"] = serde_json::json!("evt_resent");
        s.script.push_back(Conn::Rewind(2));
    });
    relay.push_events(4..=4);
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    let seen = read_until(
        &mut sub,
        |e| matches!(e, StreamEvent::Hook(h) if h.seq == 4),
    )
    .await;
    assert!(
        seen.iter()
            .any(|l| l.starts_with("quarantined Some(2)") && l.contains("cursor")),
        "{seen:?}"
    );
    assert!(!seen.contains(&"hook 2".to_string()), "{seen:?}");
    let q = sub.store().quarantined().unwrap();
    assert_eq!(q[0].kind, QuarantineKind::Stale);
    assert!(q[0].data.is_empty());
}

#[tokio::test]
async fn a_gap_past_the_relays_head_never_moves_the_cursor_there() {
    let relay = MockRelay::start().await;
    relay.push_events(4..=5);
    relay.with(|s| {
        s.script.push_back(Conn::Gap(1, 1_000_000));
        s.script.push_back(Conn::Gap(900, 1_000_000));
    });
    let (client, state, _home) = device(&relay, "gapclamp").await;
    let mut sub = subscribe(client.clone(), state.open_events().unwrap(), fast());
    let seen = read_until(&mut sub, |e| matches!(e, StreamEvent::Gap(_))).await;
    assert_eq!(seen.last().unwrap(), "gap 1-5", "clamped to the head");
    drop(sub);
    assert_eq!(state.open_events().unwrap().cursor(), 5);
    // A gap that starts past the head is ignored outright, and what comes next still arrives.
    relay.push_events(6..=6);
    let mut sub = subscribe(client, state.open_events().unwrap(), fast());
    let seen = read_until(
        &mut sub,
        |e| matches!(e, StreamEvent::Hook(h) if h.seq == 6),
    )
    .await;
    assert!(
        seen.iter()
            .any(|l| l.contains("ignored a gap (900 to 1000000)")),
        "{seen:?}"
    );
    assert_eq!(sub.store().cursor(), 6);
}

#[tokio::test]
async fn an_event_too_large_for_the_stream_is_skipped_after_a_few_tries() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=1);
    relay.with(|s| {
        let mut big = common::event(2);
        big["body"] =
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode("x".repeat(20_000)));
        s.log.push(big);
    });
    relay.push_events(3..=3);
    let (client, state, _home) = device(&relay, "oversize").await;
    let opts = SubscribeOptions {
        max_event_bytes: 4096,
        ..fast()
    };
    let mut sub = subscribe(client, state.open_events().unwrap(), opts);
    let seen = read_until(
        &mut sub,
        |e| matches!(e, StreamEvent::Hook(h) if h.seq == 3),
    )
    .await;
    assert_eq!(
        seen.iter()
            .filter(|l| l.contains("larger than 4096"))
            .count(),
        4,
        "three reconnects and one quarantine: {seen:?}"
    );
    let q = sub.store().quarantined().unwrap();
    assert_eq!(q.len(), 1);
    assert_eq!((q[0].kind, q[0].seq), (QuarantineKind::Oversize, Some(2)));
}

#[tokio::test]
async fn a_stream_that_never_opens_is_given_up_on_and_retried() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=1);
    relay.with(|s| s.script.push_back(Conn::Stall));
    let (client, state, _home) = device(&relay, "stall").await;
    let opts = SubscribeOptions {
        open_timeout: Duration::from_millis(300),
        ..fast()
    };
    let mut sub = subscribe(client, state.open_events().unwrap(), opts);
    let seen = read_until(&mut sub, |e| matches!(e, StreamEvent::Hook(_))).await;
    assert!(
        seen[0].contains("didn't open the stream within"),
        "{seen:?}"
    );
}

#[tokio::test]
async fn failing_acks_do_not_keep_a_silent_connection_alive() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=1);
    relay.with(|s| {
        s.script.push_back(Conn::SilentAfter(1));
        s.fail_acks = usize::MAX;
    });
    let (client, state, _home) = device(&relay, "idleack").await;
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
    let mut virtual_now = Duration::ZERO;
    loop {
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Err(_) => virtual_now = clock.advance(),
            Ok(Some(Ok(StreamEvent::Reconnecting { reason, .. }))) => {
                assert_eq!(reason, "no data for 70 s");
                break;
            }
            Ok(Some(Ok(_))) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    reader.abort();
    // Ack retries fired at 1, 3, 7, 15, 31 and 61 s; none of them moved the deadline.
    assert_eq!(virtual_now, Duration::from_secs(70));
    assert!(relay.with(|s| s.failed_acks) >= 6);
}
