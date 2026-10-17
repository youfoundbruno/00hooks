//! Cross-implementation round trip (PROTOCOL §5): a key made here, events sealed to it by the
//! relay's own code (`relay/src/envelope.ts`, run under Node by `relay/scripts/seal-interop.ts`),
//! opened here. The committed fixture (`fixtures/seal-interop.v1.json`) is checked by the unit
//! tests without Node; this test makes fresh keys and needs Node 22.18+ and the relay's
//! dependencies (`pnpm install`). Without them it says so and passes, unless `HOOKS_REQUIRE_NODE`
//! is set (as `pnpm check` sets it).

use std::path::PathBuf;
use std::process::Command;

use base64::Engine;
use hooks_client::{Event, Opener, SealKey};
use serde_json::Value;

#[test]
fn events_sealed_by_the_relays_code_under_node_open_here() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = root.join("relay/scripts/seal-interop.ts");
    let deps = root.join("relay/node_modules/@hpke/core");
    let required = std::env::var_os("HOOKS_REQUIRE_NODE").is_some();
    let node_ok = Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !node_ok || !deps.exists() {
        assert!(
            !required,
            "HOOKS_REQUIRE_NODE is set, but node or relay/node_modules is missing"
        );
        eprintln!("skipped: needs node and `pnpm install` for the relay");
        return;
    }

    let key = SealKey::generate().unwrap();
    let device = "dev_0123456789abcdefghjkmnpq";
    let out = Command::new("node")
        .arg(&script)
        .args(["--live", &key.public_key(), device])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["kid"].as_str().unwrap(), key.kid());
    let mut opener = Opener::new(device, Some(doc["relayKey"].as_str().unwrap())).unwrap();
    opener.add_key(key);
    let events = doc["events"].as_array().unwrap();
    assert_eq!(events.len(), 4);
    let mut opened = 0;
    for item in events {
        let e: Event = serde_json::from_value(item["message"].clone()).unwrap();
        if e.strict {
            // Its provider signature is a placeholder: with no secret here it is refused, as it must be.
            assert!(opener.open(e).unwrap_err().contains("strict hook"));
            continue;
        }
        let o = opener.open(e).unwrap();
        let want = &item["expect"];
        assert_eq!(serde_json::to_value(&o.headers).unwrap(), want["headers"]);
        assert_eq!(o.content_type.as_deref(), want["contentType"].as_str());
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&o.body)
                .unwrap(),
            base64::engine::general_purpose::STANDARD
                .decode(want["body"].as_str().unwrap())
                .unwrap()
        );
        opened += 1;
    }
    assert_eq!(opened, 3);
}
