//! Device renames, delivering a hook to one device, a hook's static answer, test events and
//! `relay status`, against the mock relay.

#[path = "../../hooks-client/tests/common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::{MockRelay, TempHome};
use serde_json::{Value, json};

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Runs the binary on a blocking thread (the mock relay serves on this runtime meanwhile).
async fn run(home: &Path, args: &[&str]) -> Output {
    let home: PathBuf = home.to_path_buf();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_00hooks"))
            .env("HOOKS_HOME", &home)
            .env("HOOKS_KEYSTORE", "file")
            .env_remove("HOOKS_RELAY")
            .env_remove("HOOKS_SIGNUP_TOKEN")
            .stdin(Stdio::null())
            .args(&args)
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

async fn ok(home: &Path, args: &[&str]) -> String {
    let out = run(home, args).await;
    assert!(
        out.status.success(),
        "{args:?}: {}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    text(&out.stdout)
}

async fn fails(home: &Path, args: &[&str]) -> String {
    let out = run(home, args).await;
    assert_eq!(
        out.status.code(),
        Some(1),
        "{args:?}: {}",
        text(&out.stdout)
    );
    format!("{}{}", text(&out.stdout), text(&out.stderr))
}

async fn logged_in(relay: &MockRelay, tag: &str) -> TempHome {
    let home = TempHome::new(tag);
    ok(&home.0, &["login", "--relay", &relay.url, "--name", "box"]).await;
    home
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn devices_are_renamed_by_id_or_name() {
    let relay = MockRelay::start().await;
    let home = logged_in(&relay, "rename").await;
    relay.with(|s| {
        s.other_devices
            .push(json!({ "id": "dev_9", "name": "old laptop", "createdAt": 1,
                                     "lastSeenAt": null, "current": false, "sealKid": "k" }))
    });
    let out = ok(&home.0, &["devices", "rename", "old laptop", "  attic  "]).await;
    assert_eq!(out.trim(), "Renamed old laptop (dev_9) to attic.");
    let devices = ok(&home.0, &["devices"]).await;
    assert!(devices.contains("attic"), "{devices}");

    // This computer, by id: its login's record follows.
    ok(&home.0, &["devices", "rename", "dev_1", "desk"]).await;
    let config = std::fs::read_to_string(home.0.join("config.json")).unwrap();
    assert!(config.contains("\"desk\""), "{config}");

    assert!(
        fails(&home.0, &["devices", "rename", "nobody", "x"])
            .await
            .contains("No device named nobody")
    );
    assert!(
        fails(&home.0, &["devices", "rename", "desk", &"x".repeat(101)])
            .await
            .contains("1 to 100 characters")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hook_delivers_to_one_device_and_answers_with_a_static_response() {
    let relay = MockRelay::start().await;
    let home = logged_in(&relay, "deliver").await;
    ok(
        &home.0,
        &["hooks", "create", "--name", "sms", "--preset", "github"],
    )
    .await;
    relay.with(|s| {
        s.other_devices
            .push(json!({ "id": "dev_9", "name": "server", "createdAt": 1,
                                     "lastSeenAt": null, "current": false, "sealKid": "k" }))
    });

    let out = ok(&home.0, &["hooks", "deliver-to", "sms", "server"]).await;
    assert!(out.contains("only to server (dev_9)"), "{out}");
    assert_eq!(
        relay.with(|s| s.hook_patches.last().cloned()),
        Some(json!({"deliverTo": "dev_9"}))
    );
    let shown = ok(&home.0, &["hooks", "show", "sms"]).await;
    assert!(shown.contains("dev_9"), "{shown}");
    let list = ok(&home.0, &["hooks", "list"]).await;
    assert!(
        list.contains("DELIVERED TO") && list.contains("dev_9"),
        "{list}"
    );
    ok(&home.0, &["hooks", "deliver-to", "hk_1", "--all"]).await;
    assert_eq!(
        relay.with(|s| s.hook_patches.last().cloned()),
        Some(json!({"deliverTo": null}))
    );
    // The relay's refusal is said with its field.
    relay.with(|s| {
        s.other_devices
            .push(json!({ "id": "dev_8", "name": "nokey", "createdAt": 1,
                                     "lastSeenAt": null, "current": false, "sealKid": null }))
    });
    let err = fails(&home.0, &["hooks", "deliver-to", "sms", "dev_8"]).await;
    assert!(err.contains("(field: deliverTo)"), "{err}");

    // A static answer, from the command line or a file.
    let out = ok(
        &home.0,
        &[
            "hooks",
            "response",
            "sms",
            "--status",
            "200",
            "--content-type",
            "text/xml",
            "--body",
            "<Response/>",
        ],
    )
    .await;
    assert!(out.contains("200 text/xml, 11 B"), "{out}");
    assert_eq!(
        relay.with(|s| s.hook_patches.last().cloned()),
        Some(
            json!({"response": {"status": 200, "contentType": "text/xml", "body": "<Response/>"}})
        )
    );
    let file = home.0.join("answer.json");
    std::fs::write(&file, "{\"ok\":true}").unwrap();
    ok(
        &home.0,
        &[
            "hooks",
            "response",
            "sms",
            "--status",
            "202",
            "--content-type",
            "application/json",
            "--body-file",
            file.to_str().unwrap(),
        ],
    )
    .await;
    assert_eq!(
        relay.with(|s| s.hook_patches.last().unwrap()["response"]["body"].clone()),
        json!("{\"ok\":true}")
    );
    let shown: Value =
        serde_json::from_str(&ok(&home.0, &["hooks", "show", "sms", "--json"]).await).unwrap();
    assert_eq!(shown["response"]["status"], 202);
    // Checked here before anything is sent.
    let before = relay.with(|s| s.hook_patches.len());
    let err = fails(
        &home.0,
        &[
            "hooks",
            "response",
            "sms",
            "--status",
            "500",
            "--content-type",
            "text/plain",
            "--body",
            "",
        ],
    )
    .await;
    assert!(err.contains("200 to 299"), "{err}");
    assert!(
        fails(
            &home.0,
            &[
                "hooks",
                "response",
                "sms",
                "--status",
                "200",
                "--content-type",
                "text/plain"
            ],
        )
        .await
        .contains("--body")
    );
    assert_eq!(relay.with(|s| s.hook_patches.len()), before);
    // Usage errors (clap) for mixing --clear with an answer.
    let out = run(
        &home.0,
        &["hooks", "response", "sms", "--clear", "--status", "200"],
    )
    .await;
    assert!(!out.status.success());

    ok(&home.0, &["hooks", "response", "sms", "--clear"]).await;
    assert_eq!(
        relay.with(|s| s.hook_patches.last().cloned()),
        Some(json!({"response": null}))
    );
    let shown = ok(&home.0, &["hooks", "show", "sms"]).await;
    assert!(shown.contains("the default"), "{shown}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_test_event_says_what_the_delivery_got() {
    let relay = MockRelay::start().await;
    let home = logged_in(&relay, "test-event").await;
    ok(
        &home.0,
        &["hooks", "create", "--name", "ci", "--preset", "github"],
    )
    .await;
    let out = ok(&home.0, &["test", "ci"]).await;
    assert_eq!(
        out.trim(),
        "Sent a signed test event to ci: accepted as evt_test1 (status 200). It runs only \
         automations that list the kind 00hooks.test."
    );
    let j: Value = serde_json::from_str(&ok(&home.0, &["test", "hk_1", "--json"]).await).unwrap();
    assert_eq!(j["eventType"], "00hooks.test");

    relay.with(|s| {
        s.test_answer = Some((
            200,
            json!({"status": 200, "answer": {"duplicate": true}, "eventType": "00hooks.test"}),
        ))
    });
    assert!(ok(&home.0, &["test", "ci"]).await.contains("duplicate"));
    relay.with(|s| {
        s.test_answer = Some((
            200,
            json!({"status": 429, "answer": {"error": "quota"}, "eventType": "00hooks.test"}),
        ))
    });
    let out = fails(&home.0, &["test", "ci"]).await;
    assert!(out.contains("refused with status 429: quota"), "{out}");

    // A strict hook: the relay can't sign for it, and says so.
    ok(
        &home.0,
        &[
            "hooks", "create", "--name", "strict", "--preset", "github", "--strict",
        ],
    )
    .await;
    let out = fails(&home.0, &["test", "strict"]).await;
    assert!(
        out.contains("secret is on your devices") && out.contains("provider's dashboard"),
        "{out}"
    );
    assert!(
        fails(&home.0, &["test", "nope"])
            .await
            .contains("No hook named")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_status_reads_info_and_checks_the_pinned_key() {
    let relay = MockRelay::start().await;
    let home = logged_in(&relay, "relay-status").await;
    relay.with(|s| {
        s.info_extra = json!({
            "screen": {"edge": true, "maxRules": 200, "heldDays": 7},
            "phone": {"protocol": 1, "push": {"available": true, "environment": "sandbox",
                      "platforms": {"ios": {"available": true, "environment": "sandbox"},
                                    "android": {"available": false}}}},
            "later": 1
        })
    });
    let out = ok(&home.0, &["relay", "status"]).await;
    for want in [
        "Version     mock",
        "2 (this 00hooks speaks 2)",
        "matches the key pinned at login",
        "open to anyone",
        "iOS (sandbox), not Android",
        "up to 200 rules",
    ] {
        assert!(out.contains(want), "{want:?} in:\n{out}");
    }
    let j: Value =
        serde_json::from_str(&ok(&home.0, &["relay", "status", "--json"]).await).unwrap();
    assert_eq!(j["later"], 1, "a newer relay's fields are kept");
    assert_eq!(
        j["phone"]["push"]["platforms"]["android"]["available"],
        false
    );

    // Another relay, without logging in to it.
    let fresh = TempHome::new("relay-status-anon");
    let out = ok(&fresh.0, &["relay", "status", "--relay", &relay.url]).await;
    assert!(!out.contains("pinned"), "{out}");
    assert!(
        fails(&fresh.0, &["relay", "status"])
            .await
            .contains("--relay")
    );

    // A protocol this 00hooks doesn't speak, and a key that isn't the pinned one.
    relay.with(|s| s.info_extra = json!({"protocol": 9, "protocols": [9]}));
    let out = fails(&home.0, &["relay", "status"]).await;
    assert!(
        out.contains("NOT SERVED") && out.contains("protocol 2"),
        "{out}"
    );
    relay.with(|s| s.info_extra = json!({"relayKey": "B".repeat(43)}));
    let out = fails(&home.0, &["relay", "status"]).await;
    assert!(
        out.contains("DIFFERS") && out.contains("login --force"),
        "{out}"
    );

    // Unreachable.
    drop(relay);
    let out = fails(&home.0, &["relay", "status"]).await;
    assert!(out.contains("Couldn't reach the relay"), "{out}");
}
