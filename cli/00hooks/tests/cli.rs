//! The `00hooks` binary end to end, against the in-process mock relay of the library's tests.
//! Every run uses a temporary HOOKS_HOME and the file key store: the real keychain is never touched.

#[path = "../../hooks-client/tests/common/mod.rs"]
mod common;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use common::{MockRelay, TempHome};

fn cmd(home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_00hooks"));
    c.env("HOOKS_HOME", home)
        .env("HOOKS_KEYSTORE", "file")
        .env_remove("HOOKS_RELAY")
        .env_remove("HOOKS_SIGNUP_TOKEN")
        .stdin(Stdio::null());
    c
}

fn run(home: &Path, args: &[&str]) -> Output {
    cmd(home).args(args).output().unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn commands_say_what_to_do_when_not_logged_in() {
    let home = TempHome::new("cli-nologin");
    let out = run(&home.0, &["hooks", "list"]);
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(
        err.contains("isn't logged in") && err.contains("00hooks login"),
        "{err}"
    );

    let out = run(&home.0, &["login"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("--relay"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn plain_http_is_refused_for_remote_relays() {
    let home = TempHome::new("cli-http");
    let out = run(&home.0, &["login", "--relay", "http://relay.example.com"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("https"), "{}", text(&out.stderr));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_create_a_hook_listen_and_doctor() {
    let relay = MockRelay::start().await;
    relay.push_events(1..=3);
    let home = TempHome::new("cli-e2e");
    relay.with(|s| s.client_home = Some(home.0.clone()));
    let dir: PathBuf = home.0.clone();

    // Each run of the binary blocks, so it goes on a blocking thread while the relay keeps serving.
    let blocking = |args: Vec<String>| {
        let dir = dir.clone();
        tokio::task::spawn_blocking(move || {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            run(&dir, &args)
        })
    };
    let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    let out = blocking(argv(&[
        "login", "--relay", &relay.url, "--name", "test box",
    ]))
    .await
    .unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("Created account acc_1"),
        "{}",
        text(&out.stdout)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let keys: Vec<_> = std::fs::read_dir(dir.join("keys"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        // The signing key and the sealing key, both private.
        assert_eq!(keys.len(), 2);
        assert!(
            keys.iter().any(|k| k
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("seal-")),
            "{keys:?}"
        );
        for k in &keys {
            let mode = std::fs::metadata(k).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
    // The relay key is pinned, and the relay holds the sealing key.
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("config.json")).unwrap()).unwrap();
    assert_eq!(config["relayKey"], common::relay_key_b64());
    assert_eq!(config["sealKids"].as_array().unwrap().len(), 1);
    relay.with(|s| assert!(s.seal_keys.contains_key("dev_1")));

    // A second login without --force is refused.
    let out = blocking(argv(&["login", "--relay", "http://127.0.0.1:1"]))
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("--force"));

    let out = blocking(argv(&[
        "hooks", "create", "--name", "ci", "--preset", "github",
    ]))
    .await
    .unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("URL     https://relay.example/h/hk_1"),
        "{stdout}"
    );
    assert!(stdout.contains("Secret  s3cret"), "{stdout}");
    assert!(text(&out.stderr).contains("Save this secret now"));

    let out = blocking(argv(&["hooks", "list"])).await.unwrap();
    assert!(text(&out.stdout).contains("ci"), "{}", text(&out.stdout));

    let out = blocking(argv(&["doctor"])).await.unwrap();
    let report = text(&out.stdout);
    assert!(out.status.success(), "{report}{}", text(&out.stderr));
    assert!(
        report.contains("Stream opens (3 events waiting)"),
        "{report}"
    );

    // Listen with --json: three JSON lines on stdout, human lines on stderr.
    let lines = tokio::task::spawn_blocking({
        let dir = dir.clone();
        move || {
            let mut child = cmd(&dir)
                .args(["listen", "--json"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut reader = BufReader::new(child.stdout.take().unwrap());
            let mut lines = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(20);
            while lines.len() < 3 && Instant::now() < deadline {
                let mut l = String::new();
                if reader.read_line(&mut l).unwrap() == 0 {
                    break;
                }
                lines.push(l);
            }
            let _ = child.kill();
            let _ = child.wait();
            lines
        }
    })
    .await
    .unwrap();
    let seqs: Vec<u64> = lines
        .iter()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["seq"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(seqs, vec![1, 2, 3]);
    relay.with(|s| {
        assert!(s.violations.is_empty(), "{:?}", s.violations);
        assert_eq!(s.acked, 3);
    });

    // Human mode: a summary line per event on stderr, the pretty body on stdout, nothing replayed.
    relay.push_events(4..=5);
    // Read stdout until the last body; its summary line is queued before it, so stderr is
    // complete by then.
    let (stdout, all) = tokio::task::spawn_blocking({
        let dir = dir.clone();
        move || {
            let mut child = cmd(&dir)
                .arg("listen")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut reader = BufReader::new(child.stdout.take().unwrap());
            let mut stdout = String::new();
            let deadline = Instant::now() + Duration::from_secs(20);
            while !stdout.contains("\"n\": 5") && Instant::now() < deadline {
                if reader.read_line(&mut stdout).unwrap() == 0 {
                    break;
                }
            }
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            (stdout, text(&out.stderr))
        }
    })
    .await
    .unwrap();
    assert!(all.contains("Connected. 2 events are waiting."), "{all}");
    assert!(all.contains("push  ci  verified  7 B  evt_0004"), "{all}");
    assert!(!all.contains("evt_0003"), "already handed over: {all}");
    assert!(
        stdout.contains("\"n\": 4") && stdout.contains("\"n\": 5"),
        "{stdout}"
    );
}

fn run_with_stdin(home: &Path, args: &[&str], input: &str) -> Output {
    use std::io::Write;
    let mut child = cmd(home)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_reads_the_code_from_stdin_and_force_revokes_the_previous_device() {
    let relay = MockRelay::start().await;
    let home = TempHome::new("cli-relogin");
    let dir = home.0.clone();
    let url = relay.url.clone();
    let blocking = |args: Vec<String>, input: Option<String>| {
        let dir = dir.clone();
        tokio::task::spawn_blocking(move || {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            match input {
                Some(i) => run_with_stdin(&dir, &args, &i),
                None => run(&dir, &args),
            }
        })
    };
    let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    let out = blocking(argv(&["login", "--relay", &url]), None)
        .await
        .unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("device dev_1"));

    // A code after --code is refused without being echoed.
    let out = blocking(
        argv(&["login", "--force", "--code", "ABCD-EFGH-JKMN"]),
        None,
    )
    .await
    .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(
        err.contains("--code-stdin") && !err.contains("ABCD"),
        "{err}"
    );

    // --code-stdin joins with the piped code, and --force revokes the previous device.
    relay.with(|s| s.enrolment_code = Some("ABCD-EFGH-JKMN".into()));
    let out = blocking(
        argv(&["login", "--force", "--code-stdin"]),
        Some("ABCD-EFGH-JKMN\n".into()),
    )
    .await
    .unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("Joined account acc_1"));
    assert!(text(&out.stdout).contains("device dev_2"));
    assert!(
        text(&out.stderr).contains("Revoked this computer's previous device dev_1"),
        "{}",
        text(&out.stderr)
    );
    relay.with(|s| {
        assert_eq!(
            s.revocations,
            vec![("dev_1".to_string(), "dev_1".to_string())]
        );
    });
    // Only the new device's keys are left (signing and sealing).
    assert_eq!(std::fs::read_dir(dir.join("keys")).unwrap().count(), 2);

    // --code reads stdin too when it isn't a terminal. When the previous device can't be revoked,
    // the login still goes through and says so plainly.
    relay.with(|s| {
        s.enrolment_code = Some("MNPQ-RSTV-WXYZ".into());
        s.revoked.insert("dev_2".into());
    });
    let out = blocking(
        argv(&["login", "--force", "--code"]),
        Some("mnpq-rstv-wxyz\n".to_uppercase()),
    )
    .await
    .unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    let err = text(&out.stderr);
    assert!(
        err.contains("Couldn't revoke this computer's previous device dev_2")
            && err.contains("already refuses it")
            && err.contains("00hooks devices revoke dev_2"),
        "{err}"
    );
    relay.with(|s| assert_eq!(s.revocations.len(), 1));

    // No code at all is refused.
    let out = blocking(
        argv(&["login", "--force", "--code-stdin"]),
        Some(String::new()),
    )
    .await
    .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("No enrolment code"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_signup_or_code_is_explained_as_such() {
    let relay = MockRelay::start().await;
    relay.with(|s| s.signup_token = Some("right".into()));
    let home = TempHome::new("cli-refused");
    let dir = home.0.clone();
    let url = relay.url.clone();
    let out = tokio::task::spawn_blocking(move || {
        run(&dir, &["login", "--relay", &url, "--signup-token", "wrong"])
    })
    .await
    .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(err.contains("needs a signup token"), "{err}");
    assert!(
        !err.contains("--force") && !err.contains("revoked"),
        "{err}"
    );
    // Nothing was kept: no login, no key.
    assert!(!home.0.join("config.json").exists());

    let dir = home.0.clone();
    let url = relay.url.clone();
    let out = tokio::task::spawn_blocking(move || {
        run_with_stdin(
            &dir,
            &["login", "--relay", &url, "--code-stdin"],
            "ZZZZ-ZZZZ-ZZZZ\n",
        )
    })
    .await
    .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(err.contains("code is wrong, used or expired"), "{err}");
    assert!(!err.contains("--force"), "{err}");
}

/// `00hooks screen`: off until switched on; a held item is dropped with --always, which learns a
/// rule kept as a fingerprint; ids are checked before anything is asked of the relay.
#[test]
fn the_screen_commands_work_on_this_computer() {
    use hooks_runner::hooks_screen::{Decision, Item, Screen, Source, SourceKind};
    let home = TempHome::new("cli-screen");
    let out = run(&home.0, &["screen"]);
    assert!(
        text(&out.stdout).contains("The screen is off for webhooks."),
        "{}",
        text(&out.stderr)
    );
    let out = run(&home.0, &["screen", "on"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = run(&home.0, &["screen", "status", "--json"]);
    assert!(
        text(&out.stdout).contains("\"on\":true"),
        "{}",
        text(&out.stdout)
    );
    // Something the runner held (made here directly, as the runner would).
    let dir = home.0.join("runner").join("screen");
    let s = Screen::open(&dir).unwrap();
    let item = Item {
        id: "evt_1".into(),
        source: Source {
            kind: SourceKind::Webhook,
            id: "hk_1".into(),
            name: "shop".into(),
        },
        payload: serde_json::json!({"text": "Win a free crypto wallet today, click the link and claim your prize now"}),
        headers: Default::default(),
        origin: Default::default(),
        size: 10,
        received_at: 1,
        agent_bound: true,
        consequential: true,
        purpose: None,
        summary: "order from shop".into(),
    };
    let d: Decision = serde_json::from_value(
        serde_json::json!({"verdict": "quarantine", "by": "rule", "reason": "doubtful"}),
    )
    .unwrap();
    let h = s.hold(&item, &d, serde_json::Value::Null).unwrap();
    let out = run(&home.0, &["screen", "drop", &h.id, "--always"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("Learned: Drop items like order from shop"),
        "{}",
        text(&out.stdout)
    );
    let out = run(&home.0, &["screen", "rules"]);
    assert!(
        text(&out.stdout).contains("always"),
        "{}",
        text(&out.stdout)
    );
    let out = run(&home.0, &["screen", "release", "nonsense"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("starts with hld_"),
        "{}",
        text(&out.stderr)
    );
}
