//! `00hooks run` and the commands around it, end to end against the in-process mock relay.
//! Every run uses a temporary HOOKS_HOME, the file key store and `notify: none`.

#[path = "../../hooks-client/tests/common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use common::{MockRelay, TempHome};

fn cmd(home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_00hooks"));
    c.env("HOOKS_HOME", home)
        .env("HOOKS_KEYSTORE", "file")
        .env("HOOKS_AUTOMATIONS", home.join("automations.yaml"))
        .env_remove("HOOKS_RELAY")
        .stdin(Stdio::null());
    c
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

async fn run(home: &Path, args: &[&str]) -> Output {
    let home = home.to_path_buf();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || cmd(&home).args(&args).output().unwrap())
        .await
        .unwrap()
}

fn spawn_runner(home: &Path) -> Child {
    cmd(home)
        .arg("run")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn stop(mut child: Child) -> String {
    let _ = child.kill();
    text(&child.wait_with_output().unwrap().stderr)
}

fn lines(p: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

async fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ok() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn ns(p: &Path) -> Vec<i64> {
    lines(p).iter().map(|v| v["n"].as_i64().unwrap()).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_acts_once_per_event_and_the_commands_around_it_work() {
    let relay = MockRelay::start().await;
    let home = TempHome::new("cli-run");
    let dir: PathBuf = home.0.clone();
    relay.with(|s| s.client_home = Some(dir.clone()));
    let out = run(&dir, &["login", "--relay", &relay.url]).await;
    assert!(out.status.success(), "{}", text(&out.stderr));

    let log = dir.join("out/pushes.jsonl");
    std::fs::write(
        dir.join("automations.yaml"),
        format!(
            r#"version: 1
notify: none
automations:
  - name: Big pushes
    when: {{ hook: hk_1, kinds: [push] }}
    only_if: payload.n > 1
    then:
      - write: {{ append: {}, line: {{ n: "{{{{payload.n}}}}", id: "{{{{event.id}}}}" }} }}
"#,
            log.display()
        ),
    )
    .unwrap();

    let out = run(&dir, &["automations", "check"]).await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("1 automation, valid."),
        "{}",
        text(&out.stdout)
    );
    assert!(
        text(&out.stdout).contains("the kind \"push\" hasn't been seen yet"),
        "{}",
        text(&out.stdout)
    );

    // Three events waiting: the filter lets two through, each runs once.
    relay.push_events(1..=3);
    let child = spawn_runner(&dir);
    wait_for("two lines", || ns(&log).len() >= 2).await;
    // Stopped with a kill below: wait for the three runs to be closed, not just acted on.
    let finished = |dir: &Path| {
        lines(&dir.join("runner/runs.jsonl"))
            .iter()
            .filter(|l| l["t"] == "end")
            .count()
    };
    wait_for("three finished runs", || finished(&dir) >= 3).await;
    // A second runner for the same state folder is refused.
    let out = run(&dir, &["run"]).await;
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("already running"),
        "{}",
        text(&out.stderr)
    );
    let stderr = stop(child);
    assert_eq!(ns(&log), vec![2, 3], "{stderr}");
    assert!(
        stderr.contains("Connected. 3 events are waiting"),
        "{stderr}"
    );
    assert!(stderr.contains("New kind: hk_1/push"), "{stderr}");
    assert!(stderr.contains("hk_1/push  evt_0002  1 ran"), "{stderr}");
    assert!(
        stderr.contains("Big pushes\" skipped: only_if is false"),
        "{stderr}"
    );
    relay.with(|s| {
        assert!(s.violations.is_empty(), "{:?}", s.violations);
        assert_eq!(s.acked, 3);
    });

    // Restarting doesn't run anything twice; a new event runs.
    relay.push_events(4..=4);
    let child = spawn_runner(&dir);
    wait_for("the fourth line", || ns(&log).len() >= 3).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop(child);
    assert_eq!(ns(&log), vec![2, 3, 4]);

    // The catalogue.
    let out = run(&dir, &["kinds"]).await;
    let t = text(&out.stdout);
    assert!(
        t.contains("KIND") && t.contains("hk_1/push") && t.contains("  4  "),
        "{t}"
    );
    let out = run(&dir, &["kinds", "show", "push"]).await;
    let t = text(&out.stdout);
    assert!(
        t.contains("payload.n") && t.contains("number") && t.contains("4/4"),
        "{t}"
    );
    assert!(t.contains("headers.x-github-event"), "{t}");
    assert!(t.contains("1, 2, 3, 4"), "values seen: {t}");
    let out = run(&dir, &["kinds", "show", "nope"]).await;
    assert_eq!(out.status.code(), Some(1));

    // Now the check knows the kind, and flags a field it doesn't have.
    let yaml = std::fs::read_to_string(dir.join("automations.yaml")).unwrap();
    std::fs::write(
        dir.join("automations.yaml"),
        yaml.replace("payload.n > 1", "payload.n > 1 and payload.size > 2"),
    )
    .unwrap();
    let out = run(&dir, &["automations", "check", "--strict"]).await;
    assert_eq!(out.status.code(), Some(1));
    let t = text(&out.stdout);
    assert!(
        t.contains("line 6:") && t.contains("`payload.size` isn't a field of hk_1/push"),
        "{t}"
    );
    assert!(!t.contains("hasn't been seen yet"), "{t}");
    std::fs::write(dir.join("automations.yaml"), &yaml).unwrap();

    // Runs, and a replay in this process (no runner is running).
    let out = run(&dir, &["runs", "--event", "evt_0003"]).await;
    let t = text(&out.stdout);
    assert!(
        t.contains("evt_0003  1 ran") && t.contains("write ok"),
        "{t}"
    );
    let out = run(&dir, &["replay", "evt_0003"]).await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("evt_0003 (replay)  1 ran"),
        "{}",
        text(&out.stdout)
    );
    assert_eq!(ns(&log), vec![2, 3, 4, 3]);

    // A replay asked of a running runner goes through it.
    let child = spawn_runner(&dir);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let out = run(&dir, &["replay", "2"]).await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("Asked the running runner"),
        "{}",
        text(&out.stderr)
    );
    let stderr = stop(child);
    assert_eq!(ns(&log), vec![2, 3, 4, 3, 2], "{stderr}");
    let out = run(&dir, &["replay", "evt_nope"]).await;
    assert!(
        text(&out.stderr).contains("No recorded event"),
        "{}",
        text(&out.stderr)
    );

    // Clearing a kind's sample keeps its structure.
    let out = run(&dir, &["kinds", "clear", "hk_1/push"]).await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = run(&dir, &["kinds", "show", "push", "--json"]).await;
    let k: serde_json::Value = serde_json::from_str(text(&out.stdout).trim()).unwrap();
    assert!(
        k.get("sample").is_none() && k["fields"]["payload.n"].get("values").is_none(),
        "{k}"
    );
    let out = run(&dir, &["kinds", "clear", "--all"]).await;
    assert!(text(&out.stdout).contains("Forgot 1 kind"));
}

/// Run until the process stops by itself (a test crash point), and return its stderr.
async fn run_until_crash(home: &Path, point: &str) -> Output {
    let home = home.to_path_buf();
    let point = point.to_string();
    tokio::task::spawn_blocking(move || {
        cmd(&home)
            .arg("run")
            .env("HOOKS_TEST_CRASH", point)
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_around_the_start_record_neither_loses_nor_repeats_an_event() {
    let relay = MockRelay::start().await;
    let home = TempHome::new("cli-crash");
    let dir: PathBuf = home.0.clone();
    relay.with(|s| s.client_home = Some(dir.clone()));
    let out = run(&dir, &["login", "--relay", &relay.url]).await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let log = dir.join("out/pushes.jsonl");
    std::fs::write(
        dir.join("automations.yaml"),
        format!(
            r#"version: 1
notify: none
automations:
  - name: Every push
    when: {{ hook: hk_1, kinds: [push] }}
    then:
      - write: {{ append: {}, line: {{ n: "{{{{payload.n}}}}" }} }}
"#,
            log.display()
        ),
    )
    .unwrap();

    // 1. A crash after the stream handed the event over, before the runner recorded its start.
    //    Without the confirmed handover the stream had already marked it handed over, so it was
    //    never run: the at-most-once gap.
    relay.push_events(1..=1);
    let out = run_until_crash(&dir, "after-handover").await;
    assert_eq!(out.status.code(), Some(86), "{}", text(&out.stderr));
    assert!(ns(&log).is_empty());
    relay.with(|s| assert_eq!(s.acked, 1, "recorded locally, so acknowledged"));
    // Restarted, it is handed over again and runs, once.
    let child = spawn_runner(&dir);
    wait_for("event 1 to run", || ns(&log) == vec![1]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let stderr = stop(child);
    assert_eq!(ns(&log), vec![1], "{stderr}");

    // 2. A crash after the start record, before the action ran and before the confirm.
    relay.push_events(2..=2);
    let out = run_until_crash(&dir, "after-start").await;
    assert_eq!(out.status.code(), Some(86), "{}", text(&out.stderr));
    // Restarted, it is handed over again, found already handled, and not run twice: the run is
    // closed as interrupted and can be replayed by hand.
    relay.push_events(3..=3);
    let child = spawn_runner(&dir);
    wait_for("event 3 to run", || ns(&log) == vec![1, 3]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let stderr = stop(child);
    assert_eq!(ns(&log), vec![1, 3], "{stderr}");
    assert!(stderr.contains("was interrupted"), "{stderr}");
    assert!(stderr.contains("already handled"), "{stderr}");

    // 3. Nothing is handed over a third time: the confirms made it to the inbox.
    let child = spawn_runner(&dir);
    tokio::time::sleep(Duration::from_millis(800)).await;
    let stderr = stop(child);
    assert!(!stderr.contains("already handled"), "{stderr}");
    assert_eq!(ns(&log), vec![1, 3]);
    relay.with(|s| assert!(s.violations.is_empty(), "{:?}", s.violations));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_broken_file_stops_the_runner_with_its_lines() {
    let relay = MockRelay::start().await;
    let home = TempHome::new("cli-broken");
    let dir = home.0.clone();
    run(&dir, &["login", "--relay", &relay.url]).await;
    std::fs::write(
        dir.join("automations.yaml"),
        "automations:\n  - name: x\n    when: { kinds: [push] }\n    then:\n      - notfy: hi\n",
    )
    .unwrap();
    for args in [&["run"][..], &["automations", "check"][..]] {
        let out = run(&dir, args).await;
        assert_eq!(out.status.code(), Some(1));
        let e = text(&out.stderr);
        assert!(
            e.contains("has 1 problem")
                && e.contains("line 5:")
                && e.contains("did you mean `notify`"),
            "{e}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_files_and_secrets() {
    let home = TempHome::new("cli-service");
    let dir = home.0.clone();
    let out = run(&dir, &["service", "install", "--print"]).await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let t = text(&out.stdout);
    let home_s = dir.display().to_string();
    if cfg!(target_os = "macos") {
        assert!(
            t.contains("<string>run</string>") && t.contains("<key>RunAtLoad</key>"),
            "{t}"
        );
        assert!(
            t.contains(&format!("<string>{home_s}/logs/runner.log</string>")),
            "{t}"
        );
    } else {
        assert!(
            t.contains(" run\n") && t.contains("WantedBy=default.target"),
            "{t}"
        );
        assert!(
            t.contains(&format!("append:{home_s}/logs/runner.log")),
            "{t}"
        );
    }
    assert!(t.contains(&home_s), "HOOKS_HOME is passed on: {t}");

    // Secrets come from stdin and land in a private file with HOOKS_KEYSTORE=file.
    let mut child = cmd(&dir)
        .args(["secrets", "set", "API_TOKEN"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(b"tok-123\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        !text(&out.stdout).contains("tok-123"),
        "the value is never echoed"
    );
    let file = dir.join("runner/secrets/API_TOKEN");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "tok-123");
    let out = run(&dir, &["secrets", "delete", "API_TOKEN"]).await;
    assert!(out.status.success());
    assert!(!file.exists());
    let out = run(&dir, &["secrets", "set", "bad name"]).await;
    assert_eq!(out.status.code(), Some(1));
}

fn hook(id: &str, name: &str) -> serde_json::Value {
    serde_json::json!({ "id": id, "name": name, "url": format!("https://relay.example/h/{id}"),
        "enabled": true, "verify": { "preset": "github" }, "maxBodyBytes": 1048576,
        "createdAt": 1, "lastEventAt": null })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hook_names_are_pinned_to_ids_and_hook_changes_are_told() {
    let relay = MockRelay::start().await;
    let home = TempHome::new("cli-pins");
    let dir: PathBuf = home.0.clone();
    relay.with(|s| {
        s.client_home = Some(dir.clone());
        s.hooks = vec![hook("hk_1", "ci")];
    });
    let out = run(&dir, &["login", "--relay", &relay.url]).await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let log = dir.join("out/pushes.jsonl");
    std::fs::write(
        dir.join("automations.yaml"),
        format!(
            r#"version: 1
notify: none
automations:
  - name: Pushes
    when: {{ hook: ci, kinds: [push] }}
    then:
      - write: {{ append: {}, line: {{ n: "{{{{payload.n}}}}" }} }}
"#,
            log.display()
        ),
    )
    .unwrap();

    // The runner resolves the name, pins it, and says a secret rotated by an API key.
    relay.with(|s| {
        s.hook_changes.push(serde_json::json!({
            "n": 1, "kind": "hook.rotated", "hookId": "hk_1", "name": "ci", "actor": "key_1",
            "at": 1792233600000i64
        }))
    });
    relay.push_events(1..=1);
    let child = spawn_runner(&dir);
    wait_for("event 1", || ns(&log) == vec![1]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let stderr = stop(child);
    assert!(
        stderr.contains("Pinned the hook name \"ci\" to hk_1"),
        "{stderr}"
    );
    assert!(
        stderr.contains("Hook ci (hk_1) had its secret rotated by API key key_1."),
        "{stderr}"
    );
    let out = run(&dir, &["automations", "check"]).await;
    let t = text(&out.stdout);
    assert!(t.contains("hook \"ci\" is hk_1 (pinned "), "{t}");

    // Renamed, and a new hook takes the name: after a restart the pin holds and says so.
    relay.with(|s| s.hooks = vec![hook("hk_1", "old-ci"), hook("hk_2", "ci")]);
    relay.push_events(2..=2);
    let child = spawn_runner(&dir);
    wait_for("event 2", || ns(&log) == vec![1, 2]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let stderr = stop(child);
    assert!(
        stderr.contains("now belongs to hk_2, not to hk_1"),
        "{stderr}"
    );
    let out = run(&dir, &["automations", "check", "--strict"]).await;
    assert_eq!(out.status.code(), Some(1));
    let t = text(&out.stdout);
    assert!(
        t.contains("line 5:") && t.contains("now belongs to hk_2"),
        "{t}"
    );
    relay.with(|s| assert!(s.violations.is_empty(), "{:?}", s.violations));
}
