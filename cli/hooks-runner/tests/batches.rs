//! Batched automations (`batch:`) end to end, in process, with a clock the tests move by hand:
//! events are held on disk and the actions run once for all of them, cut by idle, max_wait,
//! max_events or the size cap; a restart resumes the timers; filters apply per event; rate limits
//! and pauses count batch runs; and every action gets the whole batch.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use hooks_client::Event;
use hooks_runner::actions::RecordingNotifier;
use hooks_runner::batch::Reason;
use hooks_runner::runs::{RunRecord, RunStatus};
use hooks_runner::secrets::MemorySecrets;
use hooks_runner::{Runner, RunnerOptions};
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};

const T0: i64 = 1_792_233_600_000;
const SEC: i64 = 1000;
const MIN: i64 = 60 * SEC;

struct Temp(PathBuf);

impl Temp {
    fn new(tag: &str) -> Temp {
        let d = std::env::temp_dir().join(format!(
            "hooks-runner-batch-{tag}-{}",
            hooks_runner::random_hex()
        ));
        std::fs::create_dir_all(&d).unwrap();
        Temp(d)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn event_with(seq: u64, body: &Value, verified: bool) -> Event {
    let mut bytes = serde_json::to_vec(body).unwrap();
    bytes.extend(std::iter::repeat_n(b' ', seq as usize));
    serde_json::from_value(json!({
        "seq": seq, "id": format!("evt_{seq:04}"), "hookId": "hk_s", "receivedAt": T0 + seq as i64,
        "verified": verified, "preset": "github", "eventType": "reading",
        "contentType": "application/json", "headers": {"x-github-event": "reading"},
        "body": base64::engine::general_purpose::STANDARD.encode(bytes)
    }))
    .unwrap()
}

fn event(seq: u64) -> Event {
    event_with(seq, &json!({"n": seq}), true)
}

struct Setup {
    dir: Temp,
    clock: Arc<AtomicI64>,
    notifier: Arc<RecordingNotifier>,
    runner: Runner,
}

impl Setup {
    fn at(&self, ms: i64) {
        self.clock.store(ms, Ordering::SeqCst);
    }

    fn path(&self, p: &str) -> PathBuf {
        self.dir.0.join(p)
    }

    fn reopen(&mut self) {
        // Drop the old runner first, as a restart would.
        let fresh = open(&self.dir.0, self.clock.clone(), self.notifier.clone());
        self.runner = fresh;
    }
}

fn open(dir: &Path, clock: Arc<AtomicI64>, notifier: Arc<RecordingNotifier>) -> Runner {
    let mut opts = RunnerOptions::new(dir.join("runner"), dir.join("automations.yaml"), "dev_me");
    opts.notifier = Some(notifier);
    opts.secrets = Arc::new(MemorySecrets::default());
    opts.retry_base = Duration::from_millis(5);
    opts.clock = Arc::new(move || clock.load(Ordering::SeqCst));
    let mut r = Runner::open(opts).unwrap();
    r.set_hook_names(BTreeMap::from([(
        "hk_s".to_string(),
        "sensors".to_string(),
    )]))
    .unwrap();
    r
}

fn setup(tag: &str, yaml: &str) -> Setup {
    let dir = Temp::new(tag);
    let yaml = yaml.replace("$DIR", &dir.0.display().to_string());
    std::fs::write(dir.0.join("automations.yaml"), yaml).unwrap();
    let clock = Arc::new(AtomicI64::new(T0));
    let notifier = Arc::new(RecordingNotifier::default());
    let runner = open(&dir.0, clock.clone(), notifier.clone());
    Setup {
        dir,
        clock,
        notifier,
        runner,
    }
}

fn read_lines(p: &Path) -> Vec<Value> {
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn ns(lines: &[Value]) -> Vec<i64> {
    lines
        .iter()
        .map(|l| l["payload"]["n"].as_i64().unwrap())
        .collect()
}

fn reason(r: &RunRecord) -> Reason {
    r.batch.as_ref().expect("a batch run").reason
}

/// A command that keeps what it got: stdin, both event files and the batch's variables.
const KEEPER: &str = r#"
automations:
  - name: Readings
    when: { hook: sensors, kinds: any }
    batch: { idle: 1m, max_wait: 3m, max_events: 50 }
    allow_commands: [/bin/sh]
    then:
      - run:
          command: sh
          args: [-c, 'cat >> $DIR/stdin.jsonl; cp "$HOOKS_EVENTS_FILE" $DIR/events.jsonl; cp "$HOOKS_EVENT_FILE" $DIR/last.json; env | grep HOOKS_BATCH_ | sort > $DIR/env.txt']
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_batch_runs_once_with_every_event() {
    let mut s = setup("idle", KEEPER);
    let rec = s.runner.handle(&event(1)).await;
    assert_eq!(rec.status, RunStatus::Ok, "{rec:?}");
    let held_in = rec.automations[0].batch.clone().expect("held");
    assert_eq!((rec.ran(), rec.batched()), (0, 1));
    assert!(rec.automations[0].actions.is_empty(), "nothing ran yet");
    s.at(T0 + 30 * SEC);
    let rec = s.runner.handle(&event(2)).await;
    assert_eq!(rec.automations[0].batch.as_deref(), Some(held_in.as_str()));
    let open = s.runner.open_batches();
    assert_eq!((open.len(), open[0].count), (1, 2));
    assert_eq!(
        s.runner.next_batch_due(),
        Some(T0 + 90 * SEC),
        "1m after the last"
    );

    s.at(T0 + 89 * SEC);
    assert!(s.runner.tick().await.is_empty(), "not idle long enough");
    assert!(!s.path("stdin.jsonl").exists());
    s.at(T0 + 90 * SEC);
    let runs = s.runner.tick().await;
    assert_eq!(runs.len(), 1);
    let r = &runs[0];
    assert_eq!(r.status, RunStatus::Ok, "{r:?}");
    assert_eq!(r.event_id, held_in);
    assert_eq!(reason(r), Reason::Idle);
    assert_eq!(r.batch.as_ref().unwrap().count, 2);
    assert_eq!(r.automations[0].trigger, "batch");
    assert_eq!(r.ran(), 1);
    assert!(s.runner.open_batches().is_empty());
    assert!(s.runner.tick().await.is_empty(), "once");

    // stdin and HOOKS_EVENTS_FILE: every event as a JSON line; HOOKS_EVENT_FILE: the last one.
    let stdin = read_lines(&s.path("stdin.jsonl"));
    assert_eq!(ns(&stdin), [1, 2]);
    assert_eq!(stdin[0]["event"]["id"], "evt_0001");
    assert_eq!(read_lines(&s.path("events.jsonl")), stdin);
    let last: Value =
        serde_json::from_str(&std::fs::read_to_string(s.path("last.json")).unwrap()).unwrap();
    assert_eq!(last["payload"]["n"], 2);
    assert!(
        last.get("batch").is_none(),
        "the last event as a single event's file has it"
    );
    let env = std::fs::read_to_string(s.path("env.txt")).unwrap();
    assert_eq!(
        env,
        format!(
            "HOOKS_BATCH_COUNT=2\nHOOKS_BATCH_FIRST=2026-10-17T10:40:00.000Z\nHOOKS_BATCH_ID={held_in}\nHOOKS_BATCH_LAST=2026-10-17T10:40:30.000Z\nHOOKS_BATCH_REASON=idle\n"
        )
    );

    // The next event opens a new batch.
    s.at(T0 + 10 * MIN);
    let rec = s.runner.handle(&event(3)).await;
    assert_ne!(rec.automations[0].batch.as_deref(), Some(held_in.as_str()));
    // The run log keeps the batch run with its count and reason.
    let all = hooks_runner::runs::read_runs(&s.path("runner")).unwrap();
    let b: Vec<&RunRecord> = all.iter().filter(|r| r.batch.is_some()).collect();
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].batch.as_ref().unwrap().reason, Reason::Idle);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_wait_cuts_a_batch_even_while_events_keep_coming() {
    let mut s = setup("max-wait", KEEPER);
    for i in 0..6 {
        s.at(T0 + i * 30 * SEC);
        s.runner.handle(&event(i as u64 + 1)).await;
        assert!(s.runner.tick().await.is_empty(), "never idle at {i}");
    }
    assert_eq!(s.runner.next_batch_due(), Some(T0 + 3 * MIN));
    s.at(T0 + 3 * MIN);
    let runs = s.runner.tick().await;
    assert_eq!(runs.len(), 1);
    assert_eq!(reason(&runs[0]), Reason::MaxWait);
    assert_eq!(ns(&read_lines(&s.path("stdin.jsonl"))), [1, 2, 3, 4, 5, 6]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_events_and_the_size_cap_cut_a_batch_at_once() {
    let mut s = setup(
        "max-events",
        r#"
automations:
  - name: Readings
    when: { hook: sensors, kinds: any }
    batch: { idle: 1h, max_events: 3 }
    then:
      - write: { append: $DIR/out.jsonl }
"#,
    );
    for i in 1..=2 {
        s.runner.handle(&event(i)).await;
        assert!(s.runner.take_batch_runs().is_empty());
    }
    let rec = s.runner.handle(&event(3)).await;
    assert!(
        rec.automations[0].batch.is_some(),
        "the third joins, then it's cut"
    );
    let runs = s.runner.take_batch_runs();
    assert_eq!(runs.len(), 1);
    assert_eq!(reason(&runs[0]), Reason::MaxEvents);
    // `write` appends every event, a line each.
    assert_eq!(ns(&read_lines(&s.path("out.jsonl"))), [1, 2, 3]);
    assert_eq!(
        runs[0].automations[0].actions[0].detail.as_deref(),
        Some(format!("appended 3 lines to {}", s.path("out.jsonl").display()).as_str())
    );
    s.runner.handle(&event(4)).await;
    assert_eq!(s.runner.open_batches()[0].count, 1, "a new batch");

    // The size cap: 3 MiB events, so the third would pass 8 MiB.
    let mut s = setup(
        "max-bytes",
        r#"
automations:
  - name: Big
    when: { hook: sensors, kinds: any }
    batch: { idle: 1h }
    then:
      - write: { append: $DIR/big.jsonl, line: { n: "{{payload.n}}" } }
"#,
    );
    let big = "x".repeat(3 * 1024 * 1024);
    for i in 1..=3u64 {
        s.runner
            .handle(&event_with(i, &json!({"n": i, "big": big}), true))
            .await;
    }
    let runs = s.runner.take_batch_runs();
    assert_eq!(runs.len(), 1);
    assert_eq!(reason(&runs[0]), Reason::MaxBytes);
    assert_eq!(runs[0].batch.as_ref().unwrap().count, 2);
    assert_eq!(
        read_lines(&s.path("big.jsonl")),
        [json!({"n": 1}), json!({"n": 2})]
    );
    assert_eq!(
        s.runner.open_batches()[0].count,
        1,
        "the third starts the next"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_keeps_the_batch_and_its_timers() {
    let mut s = setup("restart", KEEPER);
    s.runner.handle(&event(1)).await;
    s.at(T0 + 20 * SEC);
    s.runner.handle(&event(2)).await;
    let id = s.runner.open_batches()[0].id.clone();

    // Restarted before it's due: the timers resume from the stored times.
    s.at(T0 + 40 * SEC);
    s.reopen();
    let open = s.runner.open_batches();
    assert_eq!(
        (open[0].id.clone(), open[0].count, open[0].first_at),
        (id.clone(), 2, T0)
    );
    assert_eq!(s.runner.next_batch_due(), Some(T0 + 80 * SEC));
    assert!(s.runner.tick().await.is_empty());

    // Stopped for an hour: overdue, so it runs at the first tick, by the earlier deadline.
    s.at(T0 + 60 * MIN);
    s.reopen();
    let runs = s.runner.tick().await;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].event_id, id);
    assert_eq!(reason(&runs[0]), Reason::Idle);
    assert_eq!(ns(&read_lines(&s.path("stdin.jsonl"))), [1, 2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_while_cutting_runs_a_batch_at_most_once() {
    let mut s = setup("crash", KEEPER);
    s.runner.handle(&event(1)).await;
    let id = s.runner.open_batches()[0].id.clone();
    let index = s.path("runner/batches/open.json");
    let mark = |reason: &str| {
        let mut v: Value = serde_json::from_slice(&std::fs::read(&index).unwrap()).unwrap();
        v["Readings"]["cutting"] = json!(reason);
        std::fs::write(&index, serde_json::to_vec(&v).unwrap()).unwrap();
    };

    // Marked, but its run never began: it stays open and runs at the next tick.
    mark("idle");
    s.reopen();
    assert_eq!(s.runner.open_batches()[0].cutting, None);
    s.at(T0 + 2 * MIN);
    assert_eq!(s.runner.tick().await.len(), 1);

    // Marked and its run began (the start line is on disk): never run again by itself.
    s.runner.handle(&event(2)).await;
    let id2 = s.runner.open_batches()[0].id.clone();
    assert_ne!(id, id2);
    mark("max_wait");
    let start = json!({"t": "start", "run": "run_crashed", "eventId": id2, "seq": 2, "hookId": "hk_s",
        "kind": "reading", "verified": true, "at": T0});
    let mut runs = std::fs::read_to_string(s.path("runner/runs.jsonl")).unwrap();
    runs.push_str(&format!("{start}\n"));
    std::fs::write(s.path("runner/runs.jsonl"), runs).unwrap();
    s.reopen();
    assert!(s.runner.open_batches().is_empty());
    let said = s.runner.take_log().join("\n");
    assert!(
        said.contains(&format!("`00hooks replay {id2}` runs it")),
        "{said}"
    );
    s.at(T0 + 30 * MIN);
    assert!(s.runner.tick().await.is_empty());
    assert_eq!(ns(&read_lines(&s.path("stdin.jsonl"))), [1]);
    // The batch is kept: replay runs it.
    let r = s.runner.replay(&id2).await.unwrap();
    assert!(r.replay);
    assert_eq!(ns(&read_lines(&s.path("stdin.jsonl"))), [1, 2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filters_and_verified_only_apply_to_each_event() {
    let mut s = setup(
        "filters",
        r#"
automations:
  - name: Big readings
    when: { hook: sensors, kinds: any }
    only_if: payload.n > 10
    batch: { idle: 1m }
    then:
      - write: { append: $DIR/out.jsonl }
"#,
    );
    let rec = s
        .runner
        .handle(&event_with(1, &json!({"n": 5}), true))
        .await;
    assert_eq!(
        rec.automations[0].skipped.as_deref(),
        Some("only_if is false")
    );
    assert!(rec.automations[0].batch.is_none());
    let rec = s
        .runner
        .handle(&event_with(2, &json!({"n": 50}), false))
        .await;
    assert!(
        rec.automations[0]
            .skipped
            .as_deref()
            .unwrap()
            .contains("isn't verified")
    );
    assert!(s.runner.open_batches().is_empty(), "neither joined");
    s.runner
        .handle(&event_with(3, &json!({"n": 30}), true))
        .await;
    s.runner
        .handle(&event_with(4, &json!({"n": 3}), true))
        .await;
    s.at(T0 + 2 * MIN);
    let runs = s.runner.tick().await;
    assert_eq!(runs[0].batch.as_ref().unwrap().count, 1);
    assert_eq!(ns(&read_lines(&s.path("out.jsonl"))), [30]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limits_and_pauses_count_batch_runs_and_hold_events_up_to_the_cap() {
    let mut s = setup(
        "rate",
        r#"
automations:
  - name: Readings
    when: { hook: sensors, kinds: any }
    batch: { idle: 10s, max_events: 2 }
    rate_limit: 1/hour
    then:
      - write: { append: $DIR/out.jsonl }
"#,
    );
    // Ten events, one batch run: the rate limit counts the run, not the events.
    s.runner.handle(&event(1)).await;
    let runs = {
        s.runner.handle(&event(2)).await;
        s.runner.take_batch_runs()
    };
    assert_eq!((runs.len(), runs[0].status), (1, RunStatus::Ok));
    assert_eq!(s.runner.states().map["Readings"].runs.len(), 1);

    // Over its limit: the next batch is due but waits, holding up to max_events.
    s.runner.handle(&event(3)).await;
    s.at(T0 + MIN);
    assert!(
        s.runner.tick().await.is_empty(),
        "waiting for the rate limit"
    );
    let said = s.runner.take_log().join("\n");
    assert!(
        said.contains("can't run now (over its rate limit (1/hour))"),
        "{said}"
    );
    let rec = s.runner.handle(&event(4)).await;
    assert!(
        rec.automations[0].batch.is_some(),
        "held, not cut: it can't run"
    );
    assert!(s.runner.take_batch_runs().is_empty());
    // Full while it can't run: a new event isn't held, and the record says so and how to run it.
    let rec = s.runner.handle(&event(5)).await;
    let skipped = rec.automations[0].skipped.clone().unwrap();
    assert!(skipped.contains("is full (2 events"), "{skipped}");
    assert!(
        skipped.contains("`00hooks replay evt_0005` runs it later"),
        "{skipped}"
    );
    assert_eq!(s.runner.open_batches()[0].refused, 1);
    // An hour on, it runs, and says what it couldn't take.
    s.at(T0 + 61 * MIN);
    let runs = s.runner.tick().await;
    assert_eq!(runs.len(), 1);
    let b = runs[0].batch.clone().unwrap();
    assert_eq!((b.count, b.refused), (2, 1));
    assert_eq!(ns(&read_lines(&s.path("out.jsonl"))), [1, 2, 3, 4]);

    // Failures pause it after pause_after batch runs; held events wait for `resume`.
    let mut s = setup(
        "pause",
        r#"
automations:
  - name: Failing
    when: { hook: sensors, kinds: any }
    batch: { idle: 10s }
    rate_limit: none
    pause_after: 1
    allow_commands: [/bin/sh]
    then:
      - run: { command: sh, args: [-c, 'test -e $DIR/ok'] }
"#,
    );
    s.runner.handle(&event(1)).await;
    s.at(T0 + 20 * SEC);
    let runs = s.runner.tick().await;
    assert_eq!(runs[0].status, RunStatus::Failed);
    assert!(s.runner.states().map["Failing"].paused_until.is_some());
    s.runner.handle(&event(2)).await;
    let said = s.runner.take_log().join("\n");
    assert!(said.contains("its events are held in batch"), "{said}");
    s.at(T0 + MIN);
    assert!(s.runner.tick().await.is_empty(), "paused");
    let e = s
        .runner
        .flush_batch("Failing")
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("can't run now (paused"), "{e}");
    std::fs::write(s.path("ok"), "").unwrap();
    assert!(s.runner.resume("Failing").unwrap());
    let runs = s.runner.tick().await;
    assert_eq!((runs.len(), runs[0].status), (1, RunStatus::Ok));
}

/// Each request's headers and body.
type Seen = Arc<Mutex<Vec<(BTreeMap<String, String>, String)>>>;

struct Server {
    url: String,
    seen: Seen,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn server() -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen: Seen = Arc::default();
    let st = seen.clone();
    let task = tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let st = st.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let st = st.clone();
                        async move {
                            let (parts, body) = req.into_parts();
                            let body = body.collect().await.unwrap().to_bytes();
                            let headers = parts
                                .headers
                                .iter()
                                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").into()))
                                .collect();
                            st.lock()
                                .unwrap()
                                .push((headers, String::from_utf8_lossy(&body).into_owned()));
                            Ok::<_, Infallible>(hyper::Response::new(Full::new(
                                Bytes::from_static(b"{}"),
                            )))
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(sock), svc)
                    .await;
            });
        }
    });
    Server { url, seen, task }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn call_notify_and_files_get_the_whole_batch() {
    let srv = server().await;
    let yaml = format!(
        r#"
automations:
  - name: Readings
    when: {{ hook: sensors, kinds: any }}
    batch: {{ max_wait: 1m }}
    allow_hosts: [127.0.0.1]
    then:
      - notify: "{{{{batch.count}}}} readings ({{{{batch.reason}}}}) from {{{{batch.first}}}}: {{{{events | json | truncate:500}}}}"
      - call: {{ url: "{}/batch" }}
      - call: {{ url: "{}/summary", body: {{ count: "{{{{batch.count}}}}", ns: "{{{{events}}}}", last: "{{{{payload.n}}}}" }} }}
      - write: {{ folder: $DIR/files }}
"#,
        srv.url, srv.url
    );
    let mut s = setup("call", &yaml);
    s.runner.handle(&event(1)).await;
    s.runner.handle(&event(2)).await;
    s.at(T0 + MIN);
    let runs = s.runner.tick().await;
    assert_eq!(runs[0].status, RunStatus::Ok, "{:?}", runs[0]);
    let id = runs[0].event_id.clone();

    let shown = s.notifier.shown.lock().unwrap().clone();
    assert!(
        shown[0]
            .1
            .starts_with("2 readings (max_wait) from 2026-10-17T10:40:00.000Z: [{"),
        "{shown:?}"
    );
    let seen = srv.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    // The default body is the events, as a JSON array; the batch's id keys the call.
    let body: Value = serde_json::from_str(&seen[0].1).unwrap();
    assert_eq!(ns(body.as_array().unwrap()), [1, 2]);
    assert_eq!(seen[0].0["idempotency-key"], id);
    assert_eq!(seen[0].0["00hooks-hop"], "1");
    let body: Value = serde_json::from_str(&seen[1].1).unwrap();
    assert_eq!(body["count"], 2);
    assert_eq!(body["last"], 2, "payload is the last event's");
    assert_eq!(ns(body["ns"].as_array().unwrap()), [1, 2]);
    // A file per batch run: the batch and its events.
    let file: Value = serde_json::from_str(
        &std::fs::read_to_string(s.path(&format!("files/{id}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(file["batch"]["count"], 2);
    assert_eq!(file["batch"]["id"], id.as_str());
    assert_eq!(ns(file["events"].as_array().unwrap()), [1, 2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batches_can_be_flushed_dropped_and_replayed() {
    let mut s = setup("flush", KEEPER);
    let e = s
        .runner
        .flush_batch("Readings")
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("has no open batch"), "{e}");
    s.runner.handle(&event(1)).await;
    s.runner.handle(&event(2)).await;
    let r = s.runner.flush_batch("Readings").await.unwrap();
    assert_eq!(reason(&r), Reason::Flush);
    let id = r.event_id.clone();
    assert_eq!(ns(&read_lines(&s.path("stdin.jsonl"))), [1, 2]);
    // The cut batch is kept, privately, and replays as it was.
    let kept = s.path(&format!("runner/batches/done/{id}.jsonl"));
    assert_eq!(read_lines(&kept).len(), 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&kept).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let again = s.runner.replay(&id).await.unwrap();
    assert!(again.replay);
    assert_eq!(again.event_id, id);
    assert_eq!(again.batch.as_ref().unwrap().reason, Reason::Flush);
    assert_eq!(ns(&read_lines(&s.path("stdin.jsonl"))), [1, 2, 1, 2]);
    // A replay of a batch that isn't kept, or of an id that isn't one, says so.
    let e = s.runner.replay("bat_0000000000000000").await.unwrap_err();
    assert!(e.to_string().contains("isn't kept"), "{e}");

    // Dropped: gone, never run.
    s.runner.handle(&event(3)).await;
    let open_id = s.runner.open_batches()[0].id.clone();
    let e = s.runner.replay(&open_id).await.unwrap_err();
    assert!(e.to_string().contains("still open"), "{e}");
    let b = s.runner.drop_batch("Readings").unwrap();
    assert_eq!(b.count, 1);
    assert!(s.runner.open_batches().is_empty());
    assert!(
        !s.path(&format!("runner/batches/open/{open_id}.jsonl"))
            .exists()
    );
    s.at(T0 + 60 * MIN);
    assert!(s.runner.tick().await.is_empty());
    assert!(s.runner.drop_batch("Readings").is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hosts_agent_gets_the_batch_file() {
    #[derive(Default)]
    struct Agents(Mutex<Vec<hooks_runner::AskRequest>>);
    impl hooks_runner::Asker for Agents {
        fn ask(&self, req: hooks_runner::AskRequest) -> hooks_runner::ask::AskFuture<'_> {
            Box::pin(async move {
                self.0.lock().unwrap().push(req);
                Ok(hooks_runner::AskReply {
                    agent_id: "ag_1".into(),
                    agent_name: "Reader".into(),
                    reply: "Read them.".into(),
                })
            })
        }
    }
    let dir = Temp::new("ask");
    let yaml = "automations:\n  - name: au_batch\n    when: { hook: hk_s, kinds: any }\n    batch: { idle: 30s }\n    then:\n      - notify: \"{{agent.reply}} ({{batch.count}})\"\n";
    let mut given = hooks_runner::config::parse(yaml, &dir.0.join("x.yaml")).unwrap();
    given.automations[0].actions.insert(
        0,
        hooks_runner::config::Action {
            kind: hooks_runner::config::ActionKind::Ask {
                agent: "new".into(),
                instructions: "Summarise the readings.".into(),
                profile: "read_only".into(),
                timeout: Duration::from_secs(5),
            },
            retries: 0,
            line: 0,
        },
    );
    let clock = Arc::new(AtomicI64::new(T0));
    let agents = Arc::new(Agents::default());
    let notifier = Arc::new(RecordingNotifier::default());
    let mut opts = RunnerOptions::new(dir.0.join("runner"), dir.0.join("x.yaml"), "dev_me");
    opts.asker = Some(agents.clone());
    opts.notifier = Some(notifier.clone());
    let c = clock.clone();
    opts.clock = Arc::new(move || c.load(Ordering::SeqCst));
    let mut runner = Runner::open_with(opts, given).unwrap();
    runner.handle(&event(1)).await;
    runner.handle(&event(2)).await;
    clock.store(T0 + MIN, Ordering::SeqCst);
    let runs = runner.tick().await;
    assert_eq!(runs[0].status, RunStatus::Ok, "{:?}", runs[0]);
    let req = agents.0.lock().unwrap()[0].clone();
    let b = req.batch.clone().expect("a batch");
    assert_eq!((b.count, b.reason.as_str()), (2, "idle"));
    assert_eq!(req.event.id, "evt_0002", "the last event");
    assert_eq!(ns(&read_lines(&b.file)), [1, 2]);
    let note = hooks_runner::ask::describe_batch(&b);
    assert!(
        note.contains("a batch of 2 events") && note.contains("untrusted"),
        "{note}"
    );
    assert_eq!(notifier.shown.lock().unwrap()[0].1, "Read them. (2)");
}
