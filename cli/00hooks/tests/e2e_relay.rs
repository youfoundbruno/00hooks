//! The real CLI against a real local relay: GitHub `issues` deliveries, signed, go through the
//! relay to `00hooks run`, which writes a line and calls a local URL for each opened issue,
//! exactly once, and catalogues the kind.
//!
//! Runs only when `HOOKS_E2E_RELAY` names a relay started with
//! `pnpm --filter ./relay dev --port 8813` (so `HOOKS_E2E_RELAY=http://127.0.0.1:8813`).

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hmac::{KeyInit, Mac};
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};

struct Home(PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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

fn numbers(p: &Path) -> Vec<i64> {
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["number"]
                .as_i64()
                .unwrap()
        })
        .collect()
}

async fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ok() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A local server that records the paths it's called on.
async fn receiver() -> (String, Arc<Mutex<Vec<(String, String)>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let s = s.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let s = s.clone();
                        async move {
                            let path = req.uri().to_string();
                            let origin = req
                                .headers()
                                .get("00hooks-origin")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let _ = req.into_body().collect().await;
                            s.lock().unwrap().push((path, origin));
                            Ok::<_, Infallible>(hyper::Response::new(Full::new(
                                Bytes::from_static(b"ok"),
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
    (url, seen)
}

/// Deliver a GitHub event the way GitHub does: signed body, event and delivery headers.
async fn deliver(
    http: &reqwest::Client,
    hook_url: &str,
    secret: &str,
    delivery: &str,
    body: &Value,
) -> Value {
    let bytes = serde_json::to_vec(body).unwrap();
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(&bytes);
    let sig: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let resp = http
        .post(hook_url)
        .header("content-type", "application/json")
        .header("user-agent", "GitHub-Hookshot/e2e")
        .header("x-github-event", "issues")
        .header("x-github-delivery", delivery)
        .header("x-hub-signature-256", format!("sha256={sig}"))
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap()
}

fn issue(action: &str, number: i64) -> Value {
    json!({
        "action": action,
        "issue": {"number": number, "title": format!("Issue {number}"), "labels": [{"name": "bug"}]},
        "repository": {"full_name": "acme/web"},
        "sender": {"login": "someone"}
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_issues_through_a_real_relay_run_exactly_once() {
    let Ok(relay) = std::env::var("HOOKS_E2E_RELAY") else {
        eprintln!(
            "skipped: set HOOKS_E2E_RELAY to a relay from `pnpm --filter ./relay dev --port 8813`"
        );
        return;
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let http = reqwest::Client::new();
    let home = Home(std::env::temp_dir().join(format!("hooks-e2e-{}", std::process::id())));
    std::fs::create_dir_all(&home.0).unwrap();
    let dir = home.0.clone();

    let out = run(&dir, &["login", "--relay", &relay, "--name", "e2e"]).await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = run(
        &dir,
        &[
            "hooks", "create", "--name", "gh", "--preset", "github", "--json",
        ],
    )
    .await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let created: Value = serde_json::from_str(text(&out.stdout).trim()).unwrap();
    let hook_url = created["url"].as_str().unwrap().to_string();
    // The relay's public URL may name another host; deliver to the local relay itself.
    let hook_path = &hook_url[hook_url.find("/h/").unwrap()..];
    let hook_url = format!("{relay}{hook_path}");
    let secret = created["secret"].as_str().unwrap().to_string();

    // A second hook on the same relay, which an automation calls: its own call coming back
    // through the relay must be dropped, not run.
    let out = run(
        &dir,
        &[
            "hooks",
            "create",
            "--name",
            "loop",
            "--preset",
            "token",
            "--header",
            "x-hook-token",
            "--json",
        ],
    )
    .await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let looped: Value = serde_json::from_str(text(&out.stdout).trim()).unwrap();
    let loop_url = looped["url"].as_str().unwrap();
    let loop_url = format!("{relay}{}", &loop_url[loop_url.find("/h/").unwrap()..]);
    let loop_token = looped["secret"].as_str().unwrap().to_string();
    let mut child = cmd(&dir)
        .args(["secrets", "set", "LOOP_TOKEN"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    std::io::Write::write_all(
        &mut child.stdin.take().unwrap(),
        format!("{loop_token}\n").as_bytes(),
    )
    .unwrap();
    assert!(child.wait().unwrap().success());

    let (receiver_url, calls) = receiver().await;
    let log = dir.join("issues.jsonl");
    std::fs::write(
        dir.join("automations.yaml"),
        format!(
            r#"version: 1
notify: none
automations:
  - name: Opened issues
    when: {{ hook: gh, kinds: [issues] }}
    only_if: payload.action == "opened" and payload.repository.full_name in ["acme/web"]
    allow_hosts: [127.0.0.1]
    then:
      - write: {{ append: {log}, line: {{ number: "{{{{payload.issue.number}}}}", title: "{{{{payload.issue.title}}}}" }} }}
      - call: {{ url: "{receiver_url}/issues/{{{{payload.issue.number}}}}", body: {{ n: "{{{{payload.issue.number}}}}" }} }}
      - call: {{ url: "{loop_url}", headers: {{ x-hook-token: "{{{{secret.LOOP_TOKEN}}}}" }} }}
  - name: Echo
    when: {{ hook: loop, kinds: any }}
    then:
      - write: {{ append: {echo} }}
"#,
            log = log.display(),
            echo = dir.join("echo.jsonl").display()
        ),
    )
    .unwrap();

    // Two deliveries while the runner is offline (one filtered out), and GitHub's retry of the
    // first, which the relay answers as a duplicate.
    let r = deliver(&http, &hook_url, &secret, "d-1", &issue("opened", 1)).await;
    assert!(r["received"].as_str().unwrap().starts_with("evt_"), "{r}");
    deliver(&http, &hook_url, &secret, "d-2", &issue("closed", 2)).await;
    let r = deliver(&http, &hook_url, &secret, "d-1", &issue("opened", 1)).await;
    assert_eq!(r["duplicate"], true, "{r}");

    let child = spawn_runner(&dir);
    wait_for("issue 1", || numbers(&log) == vec![1]).await;
    // One more while it runs.
    deliver(&http, &hook_url, &secret, "d-3", &issue("opened", 3)).await;
    wait_for("issue 3", || numbers(&log) == vec![1, 3]).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let stderr = stop(child);
    assert!(stderr.contains("New kind: gh/issues"), "{stderr}");

    // Restarted, it runs nothing again.
    let child = spawn_runner(&dir);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let stderr2 = stop(child);
    assert!(stderr2.contains("Connected."), "{stderr2}");
    assert_eq!(
        numbers(&log),
        vec![1, 3],
        "exactly once per event\n{stderr}\n{stderr2}"
    );
    let calls = calls.lock().unwrap().clone();
    let paths: Vec<&str> = calls.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(paths, vec!["/issues/1", "/issues/3"]);
    assert!(
        calls.iter().all(|(_, o)| o.starts_with("dev_")),
        "{calls:?}"
    );

    assert!(
        !dir.join("echo.jsonl").exists(),
        "our own call ran an automation"
    );

    // The catalogue shows the kind, with its fields and the action values seen.
    let out = run(&dir, &["kinds"]).await;
    let t = text(&out.stdout);
    assert!(t.contains("gh/issues") && t.contains("  3  "), "{t}");
    let out = run(&dir, &["kinds", "show", "gh/issues"]).await;
    let t = text(&out.stdout);
    for want in [
        "payload.issue.number",
        "payload.issue.labels[].name",
        "\"opened\", \"closed\"",
        "headers.x-github-delivery",
    ] {
        assert!(t.contains(want), "{want} missing:\n{t}");
    }
    let out = run(&dir, &["automations", "check", "--strict"]).await;
    assert!(
        out.status.success(),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    let out = run(&dir, &["runs"]).await;
    let t = text(&out.stdout);
    assert_eq!(t.matches("gh/issues").count(), 3, "{t}");
    assert_eq!(t.matches(" 1 ran").count(), 2, "{t}");
    assert!(t.contains("only_if is false"), "{t}");
    assert_eq!(
        t.matches("dropped: our own call coming back").count(),
        2,
        "{t}"
    );
    eprintln!("{t}");
}
