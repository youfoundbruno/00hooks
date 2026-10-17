//! The runner end to end, in process: real actions against a local HTTP server, temporary folders
//! and real programs, with a recording notifier and in-memory secrets.

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use hooks_client::Event;
use hooks_runner::actions::RecordingNotifier;
use hooks_runner::runs::RunStatus;
use hooks_runner::secrets::{MemorySecrets, SecretStore};
use hooks_runner::{Runner, RunnerOptions};
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};

struct Temp(PathBuf);

impl Temp {
    fn new(tag: &str) -> Temp {
        let d = std::env::temp_dir().join(format!(
            "hooks-runner-it-{tag}-{}",
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

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: String,
}

#[derive(Default)]
struct ServerState {
    requests: Vec<Seen>,
    /// Status codes to answer with, in order; 200 once they run out.
    script: VecDeque<u16>,
}

struct Server {
    url: String,
    state: Arc<Mutex<ServerState>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start() -> Server {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(ServerState::default()));
        let st = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let st = st.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let st = st.clone();
                            async move {
                                let (parts, body) = req.into_parts();
                                let body = body.collect().await.unwrap().to_bytes();
                                let mut s = st.lock().unwrap();
                                s.requests.push(Seen {
                                    method: parts.method.to_string(),
                                    path: parts.uri.to_string(),
                                    headers: parts
                                        .headers
                                        .iter()
                                        .map(|(k, v)| {
                                            (k.to_string(), v.to_str().unwrap_or("").to_string())
                                        })
                                        .collect(),
                                    body: String::from_utf8_lossy(&body).into_owned(),
                                });
                                let status = s.script.pop_front().unwrap_or(200);
                                Ok::<_, Infallible>(
                                    hyper::Response::builder()
                                        .status(status)
                                        .body(Full::new(Bytes::from_static(b"{}")))
                                        .unwrap(),
                                )
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(sock), svc)
                        .await;
                });
            }
        });
        Server { url, state, task }
    }

    fn requests(&self) -> Vec<Seen> {
        self.state.lock().unwrap().requests.clone()
    }
}

fn event(seq: u64, event_type: &str, body: &Value) -> Event {
    event_with(seq, event_type, body, true, &[])
}

fn event_with(
    seq: u64,
    event_type: &str,
    body: &Value,
    verified: bool,
    headers: &[(&str, &str)],
) -> Event {
    let mut h: BTreeMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    h.insert("x-github-event".into(), event_type.into());
    serde_json::from_value(json!({
        "seq": seq, "id": format!("evt_{seq:04}"), "hookId": "hk_gh", "receivedAt": 1792233600000u64 + seq,
        "verified": verified, "preset": "github", "eventType": event_type,
        "contentType": "application/json", "headers": h,
        "body": base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(body).unwrap())
    }))
    .unwrap()
}

struct Setup {
    dir: Temp,
    notifier: Arc<RecordingNotifier>,
    runner: Runner,
}

impl Setup {
    fn automations(&self) -> PathBuf {
        self.dir.0.join("automations.yaml")
    }

    fn shown(&self) -> Vec<(String, String)> {
        self.notifier.shown.lock().unwrap().clone()
    }
}

fn setup(tag: &str, yaml: &str) -> Setup {
    let dir = Temp::new(tag);
    let yaml = yaml.replace("$DIR", &dir.0.display().to_string());
    std::fs::write(dir.0.join("automations.yaml"), yaml).unwrap();
    let notifier = Arc::new(RecordingNotifier::default());
    let secrets = Arc::new(MemorySecrets::default());
    secrets.set("TOKEN", "s3cr3t-value").unwrap();
    let mut opts = RunnerOptions::new(
        dir.0.join("runner"),
        dir.0.join("automations.yaml"),
        "dev_me",
    );
    opts.notifier = Some(notifier.clone());
    opts.secrets = secrets;
    opts.retry_base = Duration::from_millis(5);
    let mut runner = Runner::open(opts).unwrap();
    runner
        .set_hook_names(BTreeMap::from([(
            "hk_gh".to_string(),
            "github".to_string(),
        )]))
        .unwrap();
    Setup {
        dir,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_issue_writes_a_file_calls_a_url_and_runs_a_command() {
    let server = Server::start().await;
    let yaml = format!(
        r##"
automations:
  - name: Opened issues
    when: {{ hook: github, kinds: [issues] }}
    only_if: payload.action == "opened" and payload.issue.number > 10
    allow_hosts: [127.0.0.1]
    allow_commands: [/bin/echo]
    then:
      - notify: "Issue #{{{{payload.issue.number}}}}: {{{{payload.issue.title | truncate:10}}}}"
      - write: {{ append: $DIR/out/issues.jsonl, line: {{ n: "{{{{payload.issue.number}}}}", t: "{{{{payload.issue.title}}}}" }} }}
      - write: {{ folder: $DIR/files, name: "issue-{{{{payload.issue.number}}}}.json" }}
      - call:
          url: {}/hook/{{{{payload.issue.number}}}}?title={{{{payload.issue.title}}}}
          headers: {{ Authorization: "Bearer {{{{secret.TOKEN}}}}", X-Kind: "{{{{event.kind}}}}" }}
          body: {{ number: "{{{{payload.issue.number}}}}", labels: "{{{{payload.issue.labels}}}}" }}
      - run: {{ command: echo, args: ["#{{{{payload.issue.number}}}}"] }}
"##,
        server.url
    );
    let mut s = setup("issue", &yaml);
    let body = json!({"action": "opened", "issue": {"number": 42, "title": "Crash on start / & ?", "labels": ["bug"]}});
    let rec = s.runner.handle(&event(1, "issues", &body)).await;
    assert_eq!(rec.status, RunStatus::Ok, "{rec:#?}");
    assert_eq!(rec.kind, "issues");
    assert!(rec.new_kind);
    let actions = &rec.automations[0].actions;
    assert_eq!(actions.len(), 5);
    assert!(
        actions.iter().all(|a| a.ok && a.attempts == 1),
        "{actions:#?}"
    );
    assert_eq!(actions[4].detail.as_deref(), Some("echo exited 0: #42"));

    assert_eq!(
        s.shown(),
        vec![("00hooks".into(), "Issue #42: Crash on …".into())]
    );
    let lines = read_lines(&s.dir.0.join("out/issues.jsonl"));
    assert_eq!(lines, vec![json!({"n": 42, "t": "Crash on start / & ?"})]);
    let file: Value = serde_json::from_str(
        &std::fs::read_to_string(s.dir.0.join("files/issue-42.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(file["payload"]["issue"]["number"], 42);
    assert_eq!(file["event"]["id"], "evt_0001");

    let reqs = server.requests();
    assert_eq!(reqs.len(), 1);
    let r = &reqs[0];
    assert_eq!(r.method, "POST");
    assert_eq!(
        r.path, "/hook/42?title=Crash%20on%20start%20%2F%20%26%20%3F",
        "values are percent-encoded"
    );
    assert_eq!(r.headers["authorization"], "Bearer s3cr3t-value");
    assert_eq!(r.headers["x-kind"], "issues");
    assert_eq!(r.headers["00hooks-origin"], "dev_me");
    assert_eq!(r.headers["00hooks-hop"], "1");
    assert_eq!(r.headers["idempotency-key"], "evt_0001");
    assert_eq!(
        serde_json::from_str::<Value>(&r.body).unwrap(),
        json!({"number": 42, "labels": ["bug"]})
    );

    // The secret's value is in no record.
    let runs = std::fs::read_to_string(s.dir.0.join("runner/runs.jsonl")).unwrap();
    assert!(!runs.contains("s3cr3t-value"));

    // The filter: a closed issue, or a small number, runs nothing.
    let rec = s
        .runner
        .handle(&event(
            2,
            "issues",
            &json!({"action": "closed", "issue": {"number": 50}}),
        ))
        .await;
    assert_eq!(
        rec.automations[0].skipped.as_deref(),
        Some("only_if is false")
    );
    let rec = s
        .runner
        .handle(&event(3, "issue_comment", &json!({"action": "opened"})))
        .await;
    assert!(rec.automations.is_empty(), "another kind");
    assert_eq!(server.requests().len(), 1);

    // The catalogue knows the kind, its fields and a sample.
    let k = s.runner.catalogue().get("hk_gh", "issues").unwrap();
    assert_eq!(k.count, 2);
    assert!(k.fields.contains_key("payload.issue.labels[]"));
    assert_eq!(
        k.fields["payload.action"].values,
        vec![json!("opened"), json!("closed")]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn payload_text_never_reaches_a_shell() {
    let s0 = Temp::new("marker");
    let marker = s0.0.join("pwned");
    let marker2 = s0.0.join("pwned2");
    let evil = format!(
        "$(touch {m}); touch {m2} && `touch {m}` | touch {m} > {m} \"'",
        m = marker.display(),
        m2 = marker2.display()
    );
    let yaml = r#"
automations:
  - name: Evil
    when: { hook: github, kinds: [push] }
    allow_commands: [/bin/echo, /bin/cat]
    then:
      - run: { command: echo, args: ["{{payload.text}}", "x{{payload.text}}"], env: { TEXT: "{{payload.text}}" } }
      - run: { command: cat }
      - run: { command: cat, args: ["{{payload.text}}"], event: none }
      - notify: "never reached"
  - name: Env
    when: { hook: github, kinds: [push] }
    allow_commands: [/usr/bin/printenv]
    then:
      - run: { command: printenv, args: [TEXT], env: { TEXT: "{{payload.text}}" } }
  - name: Inherited
    when: { hook: github, kinds: [push] }
    allow_commands: [/usr/bin/printenv]
    then:
      - run: { command: printenv, args: [CARGO_PKG_NAME] }
"#;
    let mut s = setup("evil", yaml);
    assert!(
        std::env::var("CARGO_PKG_NAME").is_ok(),
        "cargo sets it for tests"
    );
    let rec = s
        .runner
        .handle(&event(1, "push", &json!({"text": evil})))
        .await;
    let a = &rec.automations[0].actions;
    // echo printed the text as it is: one argument, untouched.
    assert!(a[0].ok, "{a:#?}");
    let printed = a[0].detail.as_deref().unwrap();
    assert!(
        printed.contains("$(touch") && printed.contains("; touch"),
        "{printed}"
    );
    // cat got the event on stdin.
    assert!(
        a[1].ok && a[1].detail.as_deref().unwrap().contains("$(touch"),
        "{a:#?}"
    );
    // cat with the text as a file name fails (no such file): it was one argument, not a command.
    assert!(!a[2].ok, "{a:#?}");
    assert_eq!(a.len(), 3, "the automation stops at the first failure");
    // The environment variable holds the raw text.
    let env = &rec.automations[1].actions[0];
    assert!(
        env.ok && env.detail.as_deref().unwrap().contains("exited 0: $(touch"),
        "{env:#?}"
    );
    // The runner's own environment isn't passed on.
    let inherited = &rec.automations[2].actions[0];
    assert!(
        !inherited.ok,
        "CARGO_PKG_NAME leaked into the command: {inherited:#?}"
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !marker.exists() && !marker2.exists(),
        "a payload ran a command"
    );

    // A file name from the payload stays a file in its folder.
    let yaml = r#"
automations:
  - name: Files
    when: { hook: github, kinds: [push] }
    then:
      - write: { folder: $DIR/files, name: "{{payload.text}}" }
"#;
    let mut s2 = setup("evil-files", yaml);
    let rec = s2
        .runner
        .handle(&event(1, "push", &json!({"text": "../../../tmp/x; $(id)"})))
        .await;
    assert_eq!(rec.status, RunStatus::Ok, "{rec:#?}");
    let names: Vec<String> = std::fs::read_dir(s2.dir.0.join("files"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["_.._.._tmp_x____id_"]);
    assert!(!marker.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commands_get_the_event_in_a_file_and_are_stopped_at_their_limit() {
    let dir = Temp::new("script");
    let script = dir.0.join("tool.sh");
    std::fs::write(&script, "#!/bin/sh\ncat \"$HOOKS_EVENT_FILE\"\n").unwrap();
    let sleeper = dir.0.join("sleep.sh");
    std::fs::write(&sleeper, "#!/bin/sh\nsleep 30 &\nsleep 30\n").unwrap();
    #[cfg(unix)]
    for p in [&script, &sleeper] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let yaml = format!(
        r#"
automations:
  - name: Tool
    when: {{ hook: github, kinds: [push] }}
    allow_commands: [{}, {}]
    then:
      - run: {{ command: tool.sh, event: file }}
      - run: {{ command: sleep.sh, timeout: 500ms }}
"#,
        script.display(),
        sleeper.display()
    );
    let mut s = setup("file", &yaml);
    let started = std::time::Instant::now();
    let rec = s
        .runner
        .handle(&event(1, "push", &json!({"ref": "main"})))
        .await;
    let a = &rec.automations[0].actions;
    assert!(
        a[0].ok && a[0].detail.as_deref().unwrap().contains("\"ref\":\"main\""),
        "{a:#?}"
    );
    assert!(
        !a[1].ok && a[1].error.as_deref().unwrap().contains("time limit"),
        "{a:#?}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    // The event file is gone afterwards.
    let left: Vec<_> = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("00hooks-event-")
        })
        .collect();
    assert!(
        left.is_empty()
            || left.iter().all(|e| e
                .metadata()
                .map(|m| m.modified().unwrap().elapsed().unwrap() > Duration::from_secs(60))
                .unwrap_or(true))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn safe_actions_are_retried_and_commands_are_not() {
    let server = Server::start().await;
    server.state.lock().unwrap().script = VecDeque::from([503, 503]);
    let yaml = format!(
        r#"
automations:
  - name: Retry
    when: {{ hook: github, kinds: [push] }}
    allow_hosts: [127.0.0.1]
    allow_commands: [/usr/bin/false]
    then:
      - notify: "hi"
      - call: {{ url: {}/x }}
      - run: {{ command: false }}
"#,
        server.url
    );
    let mut s = setup("retry", &yaml);
    *s.notifier.fail.lock().unwrap() = 1;
    let rec = s.runner.handle(&event(1, "push", &json!({}))).await;
    let a = &rec.automations[0].actions;
    assert_eq!((a[0].ok, a[0].attempts), (true, 2), "notify retried once");
    assert_eq!(
        (a[1].ok, a[1].attempts),
        (true, 3),
        "the call retried after two 503s"
    );
    assert_eq!(
        (a[2].ok, a[2].attempts),
        (false, 1),
        "a command isn't retried"
    );
    assert_eq!(rec.status, RunStatus::Failed);
    let keys: Vec<String> = server
        .requests()
        .iter()
        .map(|r| r.headers["idempotency-key"].clone())
        .collect();
    assert_eq!(
        keys,
        vec!["evt_0001"; 3],
        "every attempt carries the same idempotency key"
    );

    // A 4xx isn't retried.
    server.state.lock().unwrap().script = VecDeque::from([404]);
    let rec = s.runner.handle(&event(2, "push", &json!({}))).await;
    let a = &rec.automations[0].actions;
    assert_eq!((a[1].ok, a[1].attempts), (false, 1));
    assert_eq!(a[1].error.as_deref(), Some("HTTP 404 from 127.0.0.1"));

    // A command marked idempotent is retried.
    let yaml = r#"
automations:
  - name: Idem
    when: { hook: github, kinds: [push] }
    allow_commands: [/usr/bin/false]
    then:
      - run: { command: false, idempotent: true, retries: 2 }
"#;
    let mut s = setup("retry-idem", yaml);
    let rec = s.runner.handle(&event(1, "push", &json!({}))).await;
    assert_eq!(rec.automations[0].actions[0].attempts, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limits_and_the_circuit_breaker() {
    let server = Server::start().await;
    let yaml = format!(
        r#"
automations:
  - name: Limited
    when: {{ hook: github, kinds: [push] }}
    rate_limit: 2/hour
    then:
      - notify: "push"
  - name: Flaky
    when: {{ hook: github, kinds: [deploy] }}
    pause_after: 2
    pause_for: 1h
    allow_hosts: [127.0.0.1]
    then:
      - call: {{ url: {}/x, retries: 0 }}
"#,
        server.url
    );
    let mut s = setup("limits", &yaml);
    for seq in 1..=3 {
        s.runner.handle(&event(seq, "push", &json!({}))).await;
    }
    let rec = s.runner.handle(&event(4, "push", &json!({}))).await;
    assert!(
        rec.automations[0]
            .skipped
            .as_deref()
            .unwrap()
            .contains("rate limit (2/hour)"),
        "{rec:#?}"
    );
    let shown = s.shown();
    assert_eq!(shown.iter().filter(|(_, b)| b == "push").count(), 2);
    assert_eq!(
        shown
            .iter()
            .filter(|(t, _)| t.contains("rate limit"))
            .count(),
        1,
        "said once: {shown:?}"
    );

    server.state.lock().unwrap().script = VecDeque::from([400, 400]);
    for seq in 10..=11 {
        let rec = s.runner.handle(&event(seq, "deploy", &json!({}))).await;
        assert_eq!(rec.status, RunStatus::Failed);
    }
    let rec = s.runner.handle(&event(12, "deploy", &json!({}))).await;
    assert!(
        rec.automations[0]
            .skipped
            .as_deref()
            .unwrap()
            .contains("paused"),
        "{rec:#?}"
    );
    assert_eq!(
        server.requests().len(),
        2,
        "a paused automation calls nothing"
    );
    assert!(
        s.shown()
            .iter()
            .any(|(t, b)| t.contains("paused") && b.contains("\"Flaky\" failed 2 times"))
    );
    // Resuming lifts the pause.
    assert!(s.runner.resume("Flaky").unwrap());
    let rec = s.runner.handle(&event(13, "deploy", &json!({}))).await;
    assert_eq!(rec.status, RunStatus::Ok, "{rec:#?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loops_and_duplicates_are_dropped() {
    let server = Server::start().await;
    let yaml = format!(
        r#"
automations:
  - name: Forward
    when: {{ hook: github, kinds: [push] }}
    allow_hosts: [127.0.0.1]
    then:
      - call: {{ url: {}/x }}
"#,
        server.url
    );
    let mut s = setup("loops", &yaml);
    let echo = event_with(
        1,
        "push",
        &json!({}),
        true,
        &[("00hooks-origin", "dev_me"), ("00hooks-hop", "1")],
    );
    let rec = s.runner.handle(&echo).await;
    assert_eq!(rec.status, RunStatus::Dropped);
    assert!(rec.note.unwrap().contains("our own call"));
    let far = event_with(
        2,
        "push",
        &json!({}),
        true,
        &[("00hooks-origin", "dev_other"), ("00hooks-hop", "4")],
    );
    assert_eq!(s.runner.handle(&far).await.status, RunStatus::Dropped);
    let near = event_with(
        3,
        "push",
        &json!({}),
        true,
        &[("00hooks-origin", "dev_other"), ("00hooks-hop", "2")],
    );
    assert_eq!(s.runner.handle(&near).await.status, RunStatus::Ok);
    assert_eq!(
        server.requests()[0].headers["00hooks-hop"],
        "3",
        "the hop count goes up by one"
    );

    // The same event twice (the relay delivers at least once) runs once.
    let e = event(5, "push", &json!({}));
    assert_eq!(s.runner.handle(&e).await.status, RunStatus::Ok);
    let again = s.runner.handle(&e).await;
    assert_eq!(again.status, RunStatus::Dropped);
    assert_eq!(server.requests().len(), 2);
    assert!(
        s.runner.catalogue().get("hk_gh", "push").unwrap().count == 2,
        "echoes aren't catalogued"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_runs_a_recorded_event_again_even_after_a_restart() {
    let yaml = r#"
automations:
  - name: Log
    when: { hook: github, kinds: [push] }
    then:
      - write: { append: $DIR/log.jsonl, line: { id: "{{event.id}}", replay: "{{event.replay}}" } }
"#;
    let s = setup("replay", yaml);
    let dir = s.dir.0.clone();
    let mut runner = s.runner;
    runner.handle(&event(7, "push", &json!({"a": 1}))).await;
    drop(runner);
    let mut opts = RunnerOptions::new(dir.join("runner"), dir.join("automations.yaml"), "dev_me");
    opts.notifier = Some(s.notifier.clone());
    let mut runner = Runner::open(opts).unwrap();
    let rec = runner.replay("evt_0007").await.unwrap();
    assert!(rec.replay);
    assert_eq!(rec.status, RunStatus::Ok);
    assert_eq!(
        read_lines(&dir.join("log.jsonl")),
        vec![
            json!({"id": "evt_0007", "replay": false}),
            json!({"id": "evt_0007", "replay": true})
        ]
    );
    assert_eq!(
        runner.catalogue().get("hk_gh", "push").unwrap().count,
        1,
        "a replay isn't a new sighting"
    );
    assert!(runner.replay("evt_nope").await.is_err());
    // The relay sending it again still doesn't run it a third time.
    assert_eq!(
        runner
            .handle(&event(7, "push", &json!({"a": 1})))
            .await
            .status,
        RunStatus::Dropped
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_catalogue_triggers_new_kinds_and_shape_changes() {
    let yaml = r#"
automations:
  - name: New
    when: { new_kind: true, hook: github }
    then:
      - notify: { title: "New kind", body: "{{event.hook}} sent {{event.kind}}" }
  - name: Shape
    when: { shape_changed: true, kinds: [pull_request] }
    then:
      - notify: { title: "Shape", body: "added {{change.added | json}} removed {{change.removed | json}}" }
"#;
    let mut s = setup("meta", yaml);
    let r = s
        .runner
        .handle(&event(
            1,
            "pull_request",
            &json!({"pr": {"title": "a", "auto_merge": {"x": 1}}}),
        ))
        .await;
    assert_eq!(r.automations.len(), 1);
    assert_eq!(r.automations[0].trigger, "new_kind");
    s.runner
        .handle(&event(
            2,
            "pull_request",
            &json!({"pr": {"title": "b", "auto_merge": {"x": 2}}}),
        ))
        .await;
    let r = s
        .runner
        .handle(&event(
            3,
            "pull_request",
            &json!({"pr": {"title": "c", "draft": true}}),
        ))
        .await;
    assert_eq!(r.automations[0].trigger, "shape_changed");
    assert_eq!(
        s.shown(),
        vec![
            ("New kind".into(), "github sent pull_request".into()),
            (
                "Shape".into(),
                "added [\"payload.pr.draft\"] removed [\"payload.pr.auto_merge\"]".into()
            ),
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unverified_events_are_refused_unless_allowed() {
    let yaml = r#"
automations:
  - name: Strict
    when: { hook: github, kinds: [push] }
    then: [{ notify: strict }]
  - name: Lax
    when: { hook: github, kinds: [push] }
    verified_only: false
    then: [{ notify: lax }]
"#;
    let mut s = setup("verified", yaml);
    let rec = s
        .runner
        .handle(&event_with(1, "push", &json!({}), false, &[]))
        .await;
    assert!(
        rec.automations[0]
            .skipped
            .as_deref()
            .unwrap()
            .contains("isn't verified")
    );
    assert!(rec.automations[1].skipped.is_none());
    assert_eq!(s.shown(), vec![("00hooks".into(), "lax".into())]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_catch_up_ends_with_a_summary_and_runs_oldest_first() {
    let yaml = r#"
automations:
  - name: Log
    when: { hook: github, kinds: [push] }
    then:
      - write: { append: $DIR/log.jsonl, line: { seq: "{{event.seq}}" } }
"#;
    let mut s = setup("catchup", yaml);
    s.runner.on_ready(10, 16);
    for seq in 11..=16 {
        s.runner.handle(&event(seq, "push", &json!({}))).await;
    }
    let seqs: Vec<i64> = read_lines(&s.dir.0.join("log.jsonl"))
        .iter()
        .map(|v| v["seq"].as_i64().unwrap())
        .collect();
    assert_eq!(seqs, vec![11, 12, 13, 14, 15, 16]);
    let shown = s.shown();
    assert_eq!(shown.len(), 1, "{shown:?}");
    assert!(
        shown[0]
            .1
            .contains("Ran 6 events that arrived while this computer was offline"),
        "{shown:?}"
    );
    // A short catch-up says nothing.
    s.runner.on_ready(16, 18);
    for seq in 17..=18 {
        s.runner.handle(&event(seq, "push", &json!({}))).await;
    }
    assert_eq!(s.shown().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn structure_only_hooks_and_reloading_the_file() {
    let yaml = r#"
hooks:
  github: { structure_only: true }
automations: []
"#;
    let mut s = setup("structure", yaml);
    s.runner
        .handle(&event(1, "push", &json!({"email": "a@example.com"})))
        .await;
    let k = s.runner.catalogue().get("hk_gh", "push").unwrap();
    assert!(k.sample.is_none() && k.fields["payload.email"].values.is_empty());

    // Change the file: the next event uses the new automations.
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(
        s.automations(),
        "automations:\n  - name: Now\n    when: { hook: github, kinds: [push] }\n    then: [{ notify: now }]\n",
    )
    .unwrap();
    let rec = s
        .runner
        .handle(&event(2, "push", &json!({"email": "b@example.com"})))
        .await;
    assert_eq!(rec.automations.len(), 1);
    assert!(
        s.runner
            .take_log()
            .iter()
            .any(|l| l.starts_with("Reloaded"))
    );
    // Without structure_only, a sample is kept again.
    assert!(
        s.runner
            .catalogue()
            .get("hk_gh", "push")
            .unwrap()
            .sample
            .is_some()
    );

    // A broken file keeps the previous automations.
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(
        s.automations(),
        "automations:\n  - name: Broken\n    when: {}\n",
    )
    .unwrap();
    let rec = s.runner.handle(&event(3, "push", &json!({}))).await;
    assert_eq!(rec.automations[0].name, "Now");
    assert!(
        s.runner
            .take_log()
            .iter()
            .any(|l| l.contains("previous automations stay in force"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_are_confirmed_after_their_start_is_on_disk_and_replays_never() {
    let yaml = r#"
automations:
  - name: Log
    when: { hook: github, kinds: [push] }
    then:
      - write: { append: $DIR/log.jsonl, line: { id: "{{event.id}}" } }
"#;
    let mut s = setup("confirm", yaml);
    let runs = s.dir.0.join("runner/runs.jsonl");
    let log = s.dir.0.join("log.jsonl");
    let e = event(1, "push", &json!({}));
    let mut confirmed: Vec<(String, bool, usize)> = Vec::new();
    let rec = s
        .runner
        .handle_confirming(&e, &mut |id| {
            // At the confirm, the run's start is already in the run log and nothing has run yet.
            let started = read_lines(&runs)
                .iter()
                .any(|l| l["t"] == "start" && l["eventId"] == id);
            confirmed.push((id.to_string(), started, read_lines(&log).len()));
        })
        .await;
    assert_eq!(rec.status, RunStatus::Ok);
    assert_eq!(confirmed, vec![("evt_0001".to_string(), true, 0)]);
    assert_eq!(read_lines(&log).len(), 1);

    // Handed over again (a crash before the stream heard the confirm): confirmed, not run.
    let mut again = Vec::new();
    let rec = s
        .runner
        .handle_confirming(&e, &mut |id| again.push(id.to_string()))
        .await;
    assert_eq!(rec.status, RunStatus::Dropped);
    assert_eq!(again, vec!["evt_0001"]);
    assert_eq!(read_lines(&log).len(), 1);

    // A loop is settled too: dropped, and confirmed so it isn't handed over again.
    let echo = event_with(2, "push", &json!({}), true, &[("00hooks-origin", "dev_me")]);
    let mut looped = Vec::new();
    let rec = s
        .runner
        .handle_confirming(&echo, &mut |id| looped.push(id.to_string()))
        .await;
    assert_eq!(rec.status, RunStatus::Dropped);
    assert_eq!(looped, vec!["evt_0002"]);

    // A replay runs from the archive and confirms nothing.
    let rec = s.runner.replay("evt_0001").await.unwrap();
    assert!(rec.replay);
    assert_eq!(read_lines(&log).len(), 2);
}
