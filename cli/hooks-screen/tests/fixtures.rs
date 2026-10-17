//! The vectors the relay is held to as well (`fixtures/screen.v1.json`): words, shapes, MinHash
//! signatures, domains, keyed field hashes and which patterns may go to the edge. Run with
//! `HOOKS_WRITE_SCREEN_FIXTURES=1` to write the file after a deliberate change.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hooks_screen::fields::{domain_of, domain_suffixes, edge_safe_pattern, fold, keyed_hash};
use hooks_screen::minhash::{Signature, murmur3_32};
use hooks_screen::{parse_payload, shape, text};
use serde_json::{Value, json};

fn path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/screen.v1.json")
}

fn bodies() -> Vec<(&'static str, Option<&'static str>, String)> {
    let junk = "Congratulations! You have won a FREE crypto wallet worth 5000 dollars. Click bit.ly/claim-now to claim your prize before midnight, only for today.";
    vec![
        ("json", Some("application/json"), json!({"b": "two", "a": ["One", 3, {"z": "Four", "y": null}], "c": true}).to_string()),
        ("junk", Some("application/json"), json!({"message": {"text": junk, "from": "promo@mail.deals.example"}, "id": 1}).to_string()),
        ("junk-2", Some("application/json"), json!({"message": {"text": junk.replace("5000", "7000"), "from": "promo@deals.example"}, "id": 2}).to_string()),
        ("form", Some("application/x-www-form-urlencoded"), "From=%2B15550001111&Body=Hello+there%2C+friend&Body=again&MessageSid=SM1".to_string()),
        ("text", Some("text/plain"), "Plain ÜNÏCODE text — ΣΑΣ, numbers 42 and_snake".to_string()),
        ("unicode-keys", Some("application/json"), json!({"é": "acute", "z": "zed", "Z": "big zed", "日本": "kanji", "a.b": "dotted"}).to_string()),
        ("empty", None, String::new()),
    ]
}

fn build() -> Value {
    let key = [7u8; 32];
    let items: Vec<Value> = bodies()
        .into_iter()
        .map(|(name, ct, body)| {
            let payload = parse_payload(body.as_bytes(), ct);
            let t = text::item_text(&payload);
            json!({
                "name": name,
                "contentType": ct,
                "body": body,
                "text": t,
                "tokens": text::tokens(&t),
                "shape": shape::shape_hash(&payload),
                "signature": Signature::of_text(&t).map(|s| s.encode()),
            })
        })
        .collect();
    let sig = |i: usize| Signature::decode(items[i]["signature"].as_str().unwrap()).unwrap();
    let similar = json!([
        {"a": "junk", "b": "junk-2", "similarity": sig(1).similarity(&sig(2))},
        {"a": "junk", "b": "json", "similarity": sig(1).similarity(&sig(0))},
    ]);
    let murmur: Vec<Value> = ["", "a", "ab", "abc", "abcd", "hello world", "ünïcode σας"]
        .iter()
        .map(|s| json!({"text": s, "hash": murmur3_32(s.as_bytes(), 0)}))
        .collect();
    let domains: Vec<Value> = [
        "Promo@Mail.Deals.Example.",
        "https://user@Bit.ly:443/x?y",
        "deals.example",
        "http://[::1]:80/",
    ]
    .iter()
    .map(
        |v| json!({"value": v, "domain": domain_of(v), "suffixes": domain_suffixes(&domain_of(v))}),
    )
    .collect();
    let hashes: Vec<Value> = [
        ("payload.message.from", "is", "  PROMO@deals.example "),
        ("payload.message.from", "domain_is", "deals.example"),
        ("payload.id", "one_of", "2"),
        ("headers.x-kind", "is", "Promo"),
    ]
    .iter()
    .map(|(p, op, v)| {
        let n = if *op == "domain_is" {
            domain_of(v)
        } else {
            fold(v)
        };
        json!({"path": p, "op": op, "value": v, "normalised": n, "hash": keyed_hash(&key, p, &n)})
    })
    .collect();
    let patterns: Vec<Value> = [
        r"bit\.ly/\w+",
        "(a+)+$",
        r"(\w)\1",
        "(?=x)",
        "a*b*c*",
        "[(*+]x{2,5}",
        "a{2,}b+",
    ]
    .iter()
    .map(|p| json!({"pattern": p, "edge": edge_safe_pattern(p).is_ok()}))
    .collect();
    json!({
        "version": 1,
        "about": "Screen vectors (PROTOCOL §4b): the Rust harness (cli/hooks-screen) and the relay (relay/src/screen.ts) compute these alike.",
        "screenKey": URL_SAFE_NO_PAD.encode(key),
        "murmur": murmur,
        "items": items,
        "similar": similar,
        "domains": domains,
        "fieldHashes": hashes,
        "edgePatterns": patterns,
    })
}

#[test]
fn the_shared_vectors_hold() {
    let built = build();
    if std::env::var_os("HOOKS_WRITE_SCREEN_FIXTURES").is_some() {
        std::fs::write(path(), serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    let on_disk: Value =
        serde_json::from_slice(&std::fs::read(path()).expect("fixtures/screen.v1.json")).unwrap();
    assert_eq!(
        built, on_disk,
        "the screen's vectors changed; regenerate them deliberately"
    );
    // The near-identical pair is similar enough to drop at the default threshold; the other isn't.
    assert!(on_disk["similar"][0]["similarity"].as_f64().unwrap() >= 0.5);
    assert!(on_disk["similar"][1]["similarity"].as_f64().unwrap() < 0.2);
}
