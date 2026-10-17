//! What filters and templates see of an event: `payload` (the body, parsed), `headers` (the ones
//! the relay kept), `event` (id, hook, kind, verified…) and, for the catalogue's own triggers,
//! `change` (the fields a kind gained or lost).

use hooks_client::Event;
use serde_json::{Value, json};

use crate::text::sanitize;

/// The body as a value: JSON when it parses as JSON, the fields of a form when it's
/// `application/x-www-form-urlencoded`, text when it's UTF-8, else `null` (the screen reads bodies
/// the same way: `hooks_screen::parse_payload`).
pub fn payload(e: &Event) -> Value {
    match e.body_bytes() {
        Ok(bytes) => hooks_screen::parse_payload(&bytes, e.content_type.as_deref()),
        Err(_) => Value::Null,
    }
}

/// The hash of a payload's shape: its field paths and types, never its values (the screen's
/// fingerprints use the same hash).
pub fn shape_hash(payload: &Value) -> String {
    hooks_screen::shape::shape_hash(payload)
}

/// A kind's name: the provider's event type, or `shape:<12 hex>` when there is none.
pub fn kind_name(e: &Event, payload: &Value) -> String {
    match e.event_type.as_deref().map(|t| sanitize(t.trim())) {
        Some(t) if !t.is_empty() => t,
        _ => format!("shape:{}", &shape_hash(payload)[..12]),
    }
}

/// The value filters and templates read.
pub fn build(
    e: &Event,
    payload: Value,
    hook_name: Option<&str>,
    kind: &str,
    replay: bool,
) -> Value {
    json!({
        "payload": payload,
        "headers": e.headers,
        "event": {
            "id": e.id,
            "seq": e.seq,
            "hookId": e.hook_id,
            "hook": hook_name.unwrap_or(&e.hook_id),
            "eventType": e.event_type,
            "kind": kind,
            "verified": e.verified,
            "receivedAt": e.received_at,
            "preset": e.preset,
            "contentType": e.content_type,
            "replay": replay,
        },
    })
}

#[cfg(test)]
pub(crate) fn test_event(seq: u64, event_type: Option<&str>, body: &Value) -> Event {
    use base64::Engine;
    serde_json::from_value(json!({
        "seq": seq, "id": format!("evt_{seq}"), "hookId": "hk_1", "receivedAt": 1792233600000u64,
        "verified": true, "preset": "github", "eventType": event_type,
        "contentType": "application/json",
        "headers": {"x-github-event": event_type.unwrap_or("")},
        "body": base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(body).unwrap())
    }))
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn payloads_parse_json_forms_and_text() {
        let e = test_event(1, Some("push"), &json!({"a": 1}));
        assert_eq!(payload(&e), json!({"a": 1}));
        let mut e = test_event(1, None, &json!(null));
        e.content_type = Some("application/x-www-form-urlencoded".into());
        e.body = base64::engine::general_purpose::STANDARD.encode("a=1&b=x+y&a=2");
        assert_eq!(payload(&e), json!({"a": ["1", "2"], "b": "x y"}));
        e.content_type = Some("text/plain".into());
        e.body = base64::engine::general_purpose::STANDARD.encode("hello");
        assert_eq!(payload(&e), json!("hello"));
        e.body = base64::engine::general_purpose::STANDARD.encode([0xff, 0xfe]);
        assert_eq!(payload(&e), Value::Null);
    }

    #[test]
    fn kinds_use_the_event_type_or_the_shape() {
        let e = test_event(1, Some("issues"), &json!({"a": 1}));
        assert_eq!(kind_name(&e, &payload(&e)), "issues");
        let a = test_event(1, None, &json!({"a": 1, "b": "x"}));
        let b = test_event(2, None, &json!({"a": 2, "b": "y"}));
        let c = test_event(3, None, &json!({"a": 2, "c": "y"}));
        let ka = kind_name(&a, &payload(&a));
        assert!(ka.starts_with("shape:") && ka.len() == 18, "{ka}");
        assert_eq!(
            ka,
            kind_name(&b, &payload(&b)),
            "same shape, different values"
        );
        assert_ne!(ka, kind_name(&c, &payload(&c)));
        let evil = test_event(1, Some("x\u{1b}[2J"), &json!({}));
        assert_eq!(kind_name(&evil, &json!({})), "x[2J");
    }
}
