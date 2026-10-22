//! Phase 1 in the CLI, against the mock relay: strict hooks keep their secret here, provider presets
//! need theirs, an older login gets a sealing key, API keys and the audit log.

#[path = "../../hooks-client/tests/common/mod.rs"]
mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::{MockRelay, TempHome};
use serde_json::{Value, json};

fn cmd(home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_00hooks"));
    c.env("HOOKS_HOME", home)
        .env("HOOKS_KEYSTORE", "file")
        .env_remove("HOOKS_RELAY")
        .env_remove("HOOKS_SIGNUP_TOKEN")
        .stdin(Stdio::null());
    c
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Runs the binary on a blocking thread (the mock relay serves on this runtime meanwhile).
async fn run(home: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let home: PathBuf = home.to_path_buf();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let stdin = stdin.map(str::to_string);
    tokio::task::spawn_blocking(move || {
        let mut c = cmd(&home);
        c.args(&args);
        match stdin {
            None => c.output().unwrap(),
            Some(input) => {
                let mut child = c
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
        }
    })
    .await
    .unwrap()
}

async fn logged_in(relay: &MockRelay, tag: &str) -> TempHome {
    let home = TempHome::new(tag);
    let out = run(
        &home.0,
        &["login", "--relay", &relay.url, "--name", "box"],
        None,
    )
    .await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    home
}

fn key_files(home: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(home.join("keys"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_strict_hook_keeps_its_secret_here_and_never_sends_it() {
    let relay = MockRelay::start().await;
    let home = logged_in(&relay, "p1-strict").await;

    // A preset whose secret the relay would make: made here instead, shown once, kept here.
    let out = run(
        &home.0,
        &[
            "hooks", "create", "--name", "gh", "--preset", "github", "--strict",
        ],
        None,
    )
    .await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let shown = text(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("Secret  ").map(str::to_string))
        .expect("the secret is shown once");
    assert!(text(&out.stderr).contains("never has this hook's secret"));
    let sent = relay.with(|s| s.hook_requests[0].clone());
    assert_eq!(sent["verify"], json!({"preset": "github", "strict": true}));
    assert!(!sent.to_string().contains(&shown));
    assert!(key_files(&home.0).contains(&"strict-hk_1.key".to_string()));

    // A provider-issued secret comes from stdin; it never goes to the relay either.
    let out = run(
        &home.0,
        &[
            "hooks",
            "create",
            "--name",
            "pay",
            "--preset",
            "stripe",
            "--strict",
            "--secret-stdin",
        ],
        Some("whsec_from_stripe_dashboard\n"),
    )
    .await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(!text(&out.stdout).contains("whsec_from_stripe"));
    let sent = relay.with(|s| s.hook_requests[1].clone());
    assert_eq!(sent["verify"], json!({"preset": "stripe", "strict": true}));

    // Rotation of a strict hook happens on the devices.
    let out = run(&home.0, &["hooks", "rotate", "hk_2"], None).await;
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("hooks secret"),
        "{}",
        text(&out.stderr)
    );

    // Both are in this computer's index of strict hooks, so the relay can't switch them off.
    let index = std::fs::read_to_string(home.0.join("strict-hooks.json")).unwrap();
    assert!(index.contains("hk_1") && index.contains("hk_2"), "{index}");

    // Another computer (here, the same one again) can take the secret over; the previous one stays.
    // How the hook is signed comes from the person, not the relay: without --preset the relay's
    // description has to be confirmed, which a script does with --yes.
    let out = run(
        &home.0,
        &["hooks", "secret", "hk_2", "--secret-stdin"],
        Some("whsec_new_one\n"),
    )
    .await;
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("--yes"), "{}", text(&out.stderr));
    let out = run(
        &home.0,
        &[
            "hooks",
            "secret",
            "hk_2",
            "--secret-stdin",
            "--preset",
            "github",
        ],
        Some("whsec_new_one\n"),
    )
    .await;
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("you said github"),
        "{}",
        text(&out.stderr)
    );
    let out = run(
        &home.0,
        &[
            "hooks",
            "secret",
            "hk_2",
            "--secret-stdin",
            "--preset",
            "stripe",
        ],
        Some("whsec_new_one\n"),
    )
    .await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("previous one keeps working"),
        "{}",
        text(&out.stdout)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_presets_need_their_secret_and_ed25519_its_public_key() {
    let relay = MockRelay::start().await;
    let home = logged_in(&relay, "p1-presets").await;
    for preset in [
        "stripe",
        "slack",
        "linear",
        "shopify",
        "twilio",
        "paddle",
        "zoom",
        "pagerduty",
    ] {
        let out = run(
            &home.0,
            &["hooks", "create", "--name", preset, "--preset", preset],
            None,
        )
        .await;
        assert_eq!(out.status.code(), Some(1), "{preset}");
        assert!(
            text(&out.stderr).contains("--secret-stdin"),
            "{}",
            text(&out.stderr)
        );
    }
    let out = run(
        &home.0,
        &[
            "hooks",
            "create",
            "--name",
            "slack",
            "--preset",
            "slack",
            "--secret-stdin",
        ],
        Some("slack-signing-secret\n"),
    )
    .await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        relay.with(|s| s.hook_requests[0]["verify"].clone()),
        json!({"preset": "slack", "secret": "slack-signing-secret"})
    );

    let out = run(
        &home.0,
        &[
            "hooks",
            "create",
            "--name",
            "svix",
            "--preset",
            "standard-webhooks-ed25519",
        ],
        None,
    )
    .await;
    assert!(
        text(&out.stderr).contains("--public-key"),
        "{}",
        text(&out.stderr)
    );
    let pk = "whpk_11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    let out = run(
        &home.0,
        &[
            "hooks",
            "create",
            "--name",
            "svix",
            "--preset",
            "standard-webhooks-ed25519",
            "--public-key",
            pk,
        ],
        None,
    )
    .await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        relay.with(|s| s.hook_requests[1]["verify"].clone()),
        json!({"preset": "standard-webhooks-ed25519", "publicKey": pk})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_login_from_before_sealing_gets_a_key_and_pins_the_relay() {
    let relay = MockRelay::start().await;
    let home = logged_in(&relay, "p1-upgrade").await;
    // Make it look like a protocol 1 login: no pinned key, no sealing key.
    let path = home.0.join("config.json");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let old_kid = config["sealKids"][0].as_str().unwrap().to_string();
    let o = config.as_object_mut().unwrap();
    o.remove("relayKey");
    o.remove("sealKids");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();

    let out = run(&home.0, &["devices"], None).await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("not on this computer"),
        "{}",
        text(&out.stdout)
    );

    let out = run(&home.0, &["devices", "seal-key"], None).await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains(&common::relay_key_b64()),
        "{}",
        text(&out.stderr)
    );
    let config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(config["relayKey"], common::relay_key_b64());
    let new_kid = config["sealKids"][0].as_str().unwrap().to_string();
    assert_ne!(new_kid, old_kid);
    assert!(text(&out.stdout).contains(&new_kid));

    // And events sealed to the new key open: listen shows one.
    relay.push_events(1..=1);
    let out = tokio::task::spawn_blocking({
        let home = home.0.clone();
        move || {
            let mut child = cmd(&home)
                .args(["listen", "--json"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1500));
            let _ = child.kill();
            child.wait_with_output().unwrap()
        }
    })
    .await
    .unwrap();
    let line = text(&out.stdout);
    assert!(
        line.contains("\"id\":\"evt_0001\""),
        "{line}\n{}",
        text(&out.stderr)
    );
    assert!(!line.contains("\"sealed\""), "{line}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_keys_are_created_listed_and_revoked_and_the_audit_reads_safely() {
    let relay = MockRelay::start().await;
    let home = logged_in(&relay, "p1-keys").await;
    let out = run(
        &home.0,
        &[
            "keys",
            "create",
            "--name",
            "ci",
            "--scope",
            "hooks:read",
            "--scope",
            "events:read",
        ],
        None,
    )
    .await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let token = text(&out.stdout).trim().to_string();
    assert!(token.starts_with("hk_"), "{token}");
    assert!(text(&out.stderr).contains("won't be shown again"));
    assert_eq!(
        relay.with(|s| s.api_keys[0].2.clone()),
        vec!["hooks:read".to_string(), "events:read".to_string()]
    );

    let out = run(
        &home.0,
        &["keys", "create", "--name", "x", "--scope", "stream"],
        None,
    )
    .await;
    assert_eq!(
        out.status.code(),
        Some(2),
        "an unknown scope is a usage error"
    );

    let out = run(&home.0, &["keys", "list"], None).await;
    let listed = text(&out.stdout);
    assert!(
        listed.contains("hooks:read events:read") && !listed.contains(&token),
        "{listed}"
    );

    let id = relay.with(|s| s.api_keys[0].0.clone());
    let out = run(&home.0, &["keys", "revoke", &id], None).await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(relay.with(|s| s.revoked_keys.clone()), vec![id]);

    let out = run(&home.0, &["audit"], None).await;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let shown = text(&out.stdout);
    assert!(
        shown.contains("hook created") && shown.contains("signature refused ×3"),
        "{shown}"
    );
    assert!(shown.contains("the relay"), "{shown}");
    // Relay text never drives the terminal.
    assert!(!shown.contains('\u{1b}'), "{shown:?}");
}
