//! The vectors the relay is held to as well (`fixtures/screen.v1.json`): words, shapes, MinHash
//! signatures, domains, keyed field hashes, which patterns may go to the edge (and their weight),
//! what edge patterns match, and when time windows hold. Run with `HOOKS_WRITE_SCREEN_FIXTURES=1` to write the file after a
//! deliberate change.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hooks_screen::fields::{
    domain_of, domain_suffixes, edge_pattern_matches, edge_pattern_weight, edge_regex, fold,
    keyed_hash,
};
use hooks_screen::minhash::{Signature, murmur3_32};
use hooks_screen::rules::{Compiled, Rule, View};
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

/// An item received at `at` (Unix milliseconds), for time windows.
fn item_at(at: i64) -> hooks_screen::Item {
    serde_json::from_value(json!({
        "id": "evt_t",
        "source": {"kind": "webhook", "id": "hk_t", "name": "t"},
        "payload": {},
        "receivedAt": at,
    }))
    .unwrap()
}

fn time_rule(condition: &Value) -> Result<Compiled, String> {
    let rule: Rule = serde_json::from_value(
        json!({"id": "t", "name": "t", "verdict": "drop", "conditions": [condition]}),
    )
    .map_err(|e| e.to_string())?;
    Compiled::new(rule)
}

/// When time windows hold, each answer written here by hand (not taken from either half), and the
/// windows both halves refuse, with the field the relay names.
fn time_windows() -> Value {
    let at = |s: &str| s.parse::<jiff::Timestamp>().unwrap().as_millisecond();
    let nights = json!({"on": "time", "from": "22:00", "to": "06:00", "tz": "Europe/Lisbon"});
    let friday_nights = json!({"on": "time", "days": [5], "from": "22:00", "to": "06:00"});
    let weekends = json!({"on": "time", "days": [0, 6], "from": "00:00", "to": "24:00"});
    let office_ny = json!({"on": "time", "days": [1, 2, 3, 4, 5], "from": "09:00", "to": "17:00", "tz": "America/New_York"});
    let gap_ny = json!({"on": "time", "from": "02:00", "to": "03:00", "tz": "America/New_York"});
    let twice_ny = json!({"on": "time", "from": "01:00", "to": "02:00", "tz": "America/New_York"});
    let outside_office = json!({"on": "time", "from": "09:00", "to": "17:00", "not": true});
    let kolkata = json!({"on": "time", "from": "09:00", "to": "17:00", "tz": "Asia/Kolkata"});
    let auckland_friday = json!({"on": "time", "days": [5], "from": "09:00", "to": "10:00", "tz": "Pacific/Auckland"});
    let to_midnight = json!({"on": "time", "days": [4], "from": "22:00", "to": "00:00"});
    let friday_nights_not =
        json!({"on": "time", "days": [5], "from": "22:00", "to": "06:00", "not": true});
    // 2026-10-23 is a Friday. Lisbon is UTC+0 in winter and UTC+1 in summer (from 29 March 2026);
    // New York springs forward on 8 March 2026 (02:00 EST to 03:00 EDT) and falls back on
    // 1 November 2026 (02:00 EDT to 01:00 EST).
    let cases: Vec<(&Value, &str, bool)> = vec![
        (&nights, "2026-01-15T23:30:00Z", true),
        (&nights, "2026-01-15T22:00:00Z", true),
        (&nights, "2026-01-15T05:59:59Z", true),
        (&nights, "2026-01-15T06:00:00Z", false),
        (&nights, "2026-01-15T12:00:00Z", false),
        (&nights, "2026-07-15T21:30:00Z", true),
        (&nights, "2026-07-15T05:30:00Z", false),
        (&nights, "2026-03-29T00:59:59Z", true),
        (&nights, "2026-03-29T05:00:00Z", false),
        (&friday_nights, "2026-10-23T23:00:00Z", true),
        (&friday_nights, "2026-10-24T03:00:00Z", true),
        (&friday_nights, "2026-10-24T23:00:00Z", false),
        (&friday_nights, "2026-10-23T03:00:00Z", false),
        (&friday_nights_not, "2026-10-24T03:00:00Z", false),
        (&friday_nights_not, "2026-10-23T03:00:00Z", true),
        (&weekends, "2026-10-24T12:00:00Z", true),
        (&weekends, "2026-10-25T23:59:59Z", true),
        (&weekends, "2026-10-26T00:00:00Z", false),
        (&weekends, "2026-10-23T23:59:59Z", false),
        (&office_ny, "2026-03-06T13:30:00Z", false),
        (&office_ny, "2026-03-09T13:30:00Z", true),
        (&office_ny, "2026-03-09T21:00:00Z", false),
        (&office_ny, "2026-03-07T15:00:00Z", false),
        (&gap_ny, "2026-03-08T06:59:59Z", false),
        (&gap_ny, "2026-03-08T07:00:00Z", false),
        (&gap_ny, "2026-03-09T06:30:00Z", true),
        (&twice_ny, "2026-11-01T05:30:00Z", true),
        (&twice_ny, "2026-11-01T06:30:00Z", true),
        (&twice_ny, "2026-11-01T07:00:00Z", false),
        (&outside_office, "2026-10-22T12:00:00Z", false),
        (&outside_office, "2026-10-22T18:00:00Z", true),
        (&outside_office, "2026-10-22T08:59:59Z", true),
        (&kolkata, "2026-01-15T03:30:00Z", true),
        (&kolkata, "2026-01-15T03:29:59Z", false),
        (&auckland_friday, "2026-01-15T20:30:00Z", true),
        (&auckland_friday, "2026-07-16T21:30:00Z", true),
        (&auckland_friday, "2026-07-16T20:30:00Z", false),
        (&to_midnight, "2026-10-22T23:59:59Z", true),
        (&to_midnight, "2026-10-23T00:00:00Z", false),
    ];
    let cases: Vec<Value> = cases
        .into_iter()
        .map(|(c, when, want)| {
            let rule = time_rule(c).unwrap_or_else(|e| panic!("{c}: {e}"));
            let holds = rule.test(&item_at(at(when)), &mut View::default());
            assert_eq!(holds, want, "{c} at {when}");
            json!({"condition": c, "utc": when, "at": at(when), "holds": holds})
        })
        .collect();
    let w = |extra: Value| {
        let mut c = json!({"on": "time", "from": "09:00", "to": "17:00"});
        for (k, v) in extra.as_object().unwrap() {
            c[k] = v.clone();
        }
        c
    };
    let refused: Vec<Value> = [
        (w(json!({"tz": "Mars/Olympus"})), "tz"),
        (w(json!({"tz": "+01:00"})), "tz"),
        (w(json!({"tz": "Etc/Unknown"})), "tz"),
        (w(json!({"tz": "Factory"})), "tz"),
        (w(json!({"tz": ""})), "tz"),
        (w(json!({"tz": "../zoneinfo/UTC"})), "tz"),
        (w(json!({"tz": format!("Europe/{}", "L".repeat(60))})), "tz"),
        (w(json!({"tz": 1})), "tz"),
        (w(json!({"from": "24:00"})), "from"),
        (w(json!({"from": "9:00"})), "from"),
        (w(json!({"from": "09:60"})), "from"),
        (w(json!({"to": "24:01"})), "to"),
        (w(json!({"to": "09:00"})), "to"),
        (w(json!({"days": [7]})), "days"),
        (w(json!({"days": []})), "days"),
        (w(json!({"days": [1, 1]})), "days"),
        (w(json!({"days": ["1"]})), "days"),
        (w(json!({"days": [1.5]})), "days"),
        (w(json!({"not": "yes"})), "not"),
    ]
    .into_iter()
    .map(|(c, field)| {
        assert!(time_rule(&c).is_err(), "{c} is refused");
        json!({"condition": c, "field": field})
    })
    .collect();
    // Zones as both halves name them: case doesn't matter, and old names still work.
    let accepted: Vec<Value> = [
        "UTC",
        "Europe/Lisbon",
        "europe/lisbon",
        "US/Eastern",
        "Asia/Calcutta",
        "Europe/Kyiv",
        "Etc/GMT+5",
        "America/Argentina/Buenos_Aires",
        "America/Port-au-Prince",
    ]
    .iter()
    .map(|tz| {
        let c = w(json!({"tz": tz}));
        assert!(time_rule(&c).is_ok(), "{tz} is a zone");
        c
    })
    .collect();
    json!({"cases": cases, "refused": refused, "accepted": accepted})
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
    let long_labels = format!("x@{}a", "a.".repeat(127));
    let long_name = format!("x@{}", "x".repeat(254));
    let long_bytes = format!("x@{}", "é".repeat(127));
    let most_labels = format!("x@{}a.", "a.".repeat(126));
    let domains: Vec<Value> = [
        "Promo@Mail.Deals.Example.",
        "https://user@Bit.ly:443/x?y",
        "deals.example",
        "http://[::1]:80/",
        long_labels.as_str(),
        long_name.as_str(),
        long_bytes.as_str(),
        most_labels.as_str(),
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
    let too_long = "a".repeat(201);
    let too_deep = format!("{}a{}", "(".repeat(9), ")".repeat(9));
    let deepest = format!("{}a{}", "(".repeat(8), ")".repeat(8));
    let patterns: Vec<Value> = [
        r"bit\.ly/\w+",
        "(a+)+$",
        r"(\w)\1",
        "(?=x)",
        "a*b*c*",
        "[(*+]x{2,5}",
        "a{2,}b+",
        r"(?i)free (crypto|bitcoin)",
        r"^\d{3}-\d{4}$",
        "colou?r",
        r"\bcat\b",
        "[^a-z0-9_-]",
        "a|",
        "()",
        "x{0}y",
        "a{2,3}?",
        r"\.\*\+\?\(\)\|\[\]\{\}\^\$\-\/\#\&\~\!\%",
        r"[\]\-]",
        "[-a]",
        "[a-]",
        "(?i:abc)d",
        "^.$",
        r"\s\S\d\D\w\W\B",
        r"[\d\s\n]",
        "ş+",
        "a b#c",
        r"\w{250}",
        r"(\w{0,50}){4}x",
        deepest.as_str(),
        "(?<n>a)",
        "(?s).",
        "a(?i)b",
        "(?-i)a",
        "a**",
        "a+*",
        "^*",
        r"\b+",
        "{2}",
        "x}",
        "x]",
        "[]a]",
        "[]",
        "[^]",
        "[[]",
        "[a-c-e]",
        "[a&&b]",
        "[a~~b]",
        r"[\d-z]",
        "[z-a]",
        "a{3,2}",
        "a{1001}",
        "a{,3}",
        "a{2, 5}",
        r"\w{251}",
        r"(\w{100}){3}",
        too_deep.as_str(),
        r"\x41",
        r"\pL",
        r"\<",
        r"\A",
        r"\z",
        r"\0",
        r"a\",
        "(",
        ")",
        "",
        too_long.as_str(),
    ]
    .iter()
    .map(|p| {
        let w = edge_pattern_weight(p).ok();
        json!({"pattern": p, "edge": w.is_some(), "weight": w})
    })
    .collect();
    let a3000 = format!("{}!", "a".repeat(3000));
    let at3000 = "@".repeat(3000);
    let opt = format!("^{}{}$", "a?".repeat(28), "a".repeat(28));
    let a28 = "a".repeat(28);
    let a27 = "a".repeat(27);
    let w100 = format!("{}!", "a".repeat(100));
    let matches: Vec<Value> = [
        (r"bit\.ly/\w+", "see bit.ly/abc"),
        (r"bit\.ly/\w+", "see bit.ly/"),
        ("(a+)+$", a3000.as_str()),
        ("(a+)+$", "aaab"),
        ("^a*$", a3000.as_str()),
        ("!$", a3000.as_str()),
        (r".*@.*\.ru", at3000.as_str()),
        (r".*@.*\.ru", "x@y.ru"),
        (opt.as_str(), a28.as_str()),
        (opt.as_str(), a27.as_str()),
        (r"\w{0,60}\w{0,60}\w{0,60}!", a3000.as_str()),
        (r"\w{0,60}\w{0,60}\w{0,60}!", w100.as_str()),
        (r"(?i)free (crypto|bitcoin)", "Get FREE Bitcoin"),
        (r"(?i)free (crypto|bitcoin)", "free coins"),
        ("(?i)s", "ſ"),
        ("(?i)σ", "ς"),
        ("(?i)[^k]", "\u{212A}"),
        ("(?i)[^k]", "K"),
        ("(?i)[^k]", "x"),
        ("(?i)[a-z]+", "\u{212A}"),
        (r"\bcat\b", "a cat!"),
        (r"\bcat\b", "concat"),
        (r"\bcat\b", "é cat"),
        (r"\bcat\b", "écat"),
        (r"\Bcat", "concat"),
        (r"\Bcat", "cat"),
        ("^.$", "\r"),
        ("^.$", "\n"),
        ("^.$", "\u{2028}"),
        ("^.$", "😀"),
        (r"^\w$", "é"),
        (r"^\w$", "٣"),
        (r"^\w$", "‿"),
        (r"^\w$", "-"),
        (r"^\d+$", "٣٤"),
        (r"^\d+$", "12a"),
        (r"\s", "a\u{a0}b"),
        (r"\s", "ab"),
        (r"\W", "abc"),
        (r"\W", "a-b"),
        ("colou?r", "color"),
        ("colou?r", "colr"),
        ("a{2,3}b", "aab"),
        ("a{2,3}b", "ab"),
        ("x{0}y", "y"),
        ("a|", "zzz"),
        (r"[\]\-]", "]"),
        (r"[\]\-]", "-"),
        (r"[\]\-]", "a"),
        ("^ş+$", "şş"),
        ("^$", ""),
        ("(?i:abc)d", "ABCd"),
        ("(?i:abc)d", "ABCD"),
        (r"\.\*\+", ".*+"),
        ("[^a-z0-9_-]", "abc-_"),
        ("[^a-z0-9_-]", "abc!"),
        ("(a*)*b", "aaaa"),
        ("()", "x"),
    ]
    .iter()
    .map(|(p, v)| {
        assert!(edge_pattern_weight(p).is_ok(), "{p} is an edge pattern");
        let re = edge_regex(p).unwrap();
        json!({"pattern": p, "value": v, "matches": edge_pattern_matches(&re, v)})
    })
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
        "edgeMatches": matches,
        "timeWindows": time_windows(),
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
