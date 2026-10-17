//! `00hooks listen`: stream events to the terminal.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use hooks_client::{Event, StreamEvent, SubscribeOptions, describe_skew, subscribe};

use crate::ctx::{CliResult, Ctx, Failure, sentence};
use crate::output::{Line, Output, clock, duration, sanitize, size};

/// Bodies longer than this are cut in human mode (`--json` always has the whole event).
const SHOW_BODY: usize = 64 * 1024;

/// One human line about an event: time, type, hook, verified, size, id.
pub fn summary(e: &Event, hook_name: Option<&str>) -> String {
    let kind = e.event_type.as_deref().unwrap_or("event");
    let hook = hook_name.unwrap_or(&e.hook_id);
    format!(
        "{}  {}  {}  {}  {}  {}",
        clock(e.received_at),
        sanitize(kind, false),
        sanitize(hook, false),
        if e.verified { "verified" } else { "UNVERIFIED" },
        size(e.body_len()),
        sanitize(&e.id, false),
    )
}

/// The body for a person to read: pretty JSON, or text, with control characters removed.
pub fn render_body(e: &Event) -> Option<String> {
    let bytes = match e.body_bytes() {
        Ok(b) => b,
        Err(_) => return Some("(the body isn't valid base64)".into()),
    };
    if bytes.is_empty() {
        return None;
    }
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        let pretty = serde_json::to_string_pretty(&v).unwrap_or_default();
        return Some(cut(sanitize(&pretty, true)));
    }
    match std::str::from_utf8(&bytes) {
        Ok(text) => Some(cut(sanitize(text, true))),
        Err(_) => Some(format!("({} of binary data)", size(bytes.len()))),
    }
}

fn cut(mut s: String) -> String {
    if s.len() > SHOW_BODY {
        let mut at = SHOW_BODY;
        while !s.is_char_boundary(at) {
            at -= 1;
        }
        s.truncate(at);
        s.push_str("\n… (cut here; `00hooks listen --json` shows whole events)");
    }
    s
}

/// Hook names by id, refreshed at most every 30 s when an unknown id shows up.
struct Names {
    map: HashMap<String, String>,
    fetched: Option<Instant>,
}

impl Names {
    async fn refresh(&mut self, ctx: &Ctx) -> Result<(), hooks_client::Error> {
        let hooks = ctx.client.hooks().await?;
        self.map = hooks.into_iter().map(|h| (h.id, h.name)).collect();
        self.fetched = Some(Instant::now());
        Ok(())
    }

    async fn get(&mut self, ctx: &Ctx, id: &str) -> Option<String> {
        if !self.map.contains_key(id)
            && self
                .fetched
                .is_none_or(|t| t.elapsed() > Duration::from_secs(30))
        {
            let _ = self.refresh(ctx).await;
        }
        self.map.get(id).cloned()
    }
}

pub async fn run(as_json: bool, filters: Vec<String>) -> CliResult {
    let ctx = Ctx::load()?;
    let _lock = ctx
        .state
        .lock_listener()
        .map_err(|e| Failure::new(sentence(&e.to_string())))?
        .ok_or_else(|| {
            Failure::new(format!(
                "Another `00hooks listen` is already running for {}. Stop it first; one device \
                 has one stream.",
                ctx.state.path().display()
            ))
        })?;

    let mut names = Names {
        map: HashMap::new(),
        fetched: None,
    };
    // Offline is fine (the stream waits for the relay); a refused device is not.
    if let Err(e) = names.refresh(&ctx).await
        && e.is_unauthorized()
    {
        return Err(ctx.explain(e));
    }
    let mut only: HashSet<String> = HashSet::new();
    for f in &filters {
        if f.starts_with("hk_") {
            only.insert(f.clone());
        } else if let Some((id, _)) = names.map.iter().find(|(_, n)| *n == f) {
            only.insert(id.clone());
        } else {
            return Err(Failure::new(format!(
                "No hook named {}. Run `00hooks hooks list` to see them.",
                sanitize(f, false)
            )));
        }
    }

    let events = ctx
        .state
        .open_events()
        .map_err(|e| Failure::new(sentence(&e.to_string())))?;
    let mut out = Output::spawn(256);
    out.err(format!(
        "Listening as {} on {}. Times are UTC. Press Ctrl-C to stop.",
        sanitize(&ctx.config.device_name, false),
        ctx.config.relay
    ))
    .await;
    if !only.is_empty() {
        out.err("Showing only the chosen hooks; events for the others are still received and acknowledged.")
            .await;
    }

    let mut sub = subscribe(ctx.client.clone(), events, SubscribeOptions::default());
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut connected_before = false;
    let mut skew_told = false;
    let result = loop {
        let next = tokio::select! {
            _ = &mut ctrl_c => break Ok(()),
            next = sub.next() => next,
        };
        let ev = match next {
            None => break Ok(()),
            Some(Err(e)) => break Err(ctx.explain(e)),
            Some(Ok(ev)) => ev,
        };
        let lines: Vec<Line> = match ev {
            StreamEvent::Ready(r) => {
                let mut l = Vec::new();
                let waiting = r.head.saturating_sub(r.after);
                let what = if connected_before {
                    "Reconnected"
                } else {
                    "Connected"
                };
                connected_before = true;
                l.push(Line::Err(match waiting {
                    0 => format!("{what}."),
                    1 => format!("{what}. 1 event is waiting."),
                    n => format!("{what}. {n} events are waiting."),
                }));
                let offset = ctx.client.clock_offset_ms();
                if offset.abs() > 30_000 && !skew_told {
                    skew_told = true;
                    l.push(Line::Err(format!(
                        "This computer's clock is {} off the relay's; requests correct for it, but \
                         consider turning on automatic date and time.",
                        describe_skew(offset)
                    )));
                }
                l
            }
            StreamEvent::Hook(e) => {
                if !only.is_empty() && !only.contains(&e.hook_id) {
                    continue;
                }
                let name = names.get(&ctx, &e.hook_id).await;
                let mut l = vec![Line::Err(summary(&e, name.as_deref()))];
                if as_json {
                    l.push(Line::Out(serde_json::to_string(&e).unwrap_or_default()));
                } else if let Some(body) = render_body(&e) {
                    l.push(Line::Out(body));
                }
                l
            }
            StreamEvent::Gap(g) => vec![Line::Err(format!(
                "Missed events {} to {}: the relay dropped them ({}) before this device read them.",
                g.from,
                g.to,
                sanitize(
                    if g.reason.is_empty() {
                        "retention"
                    } else {
                        &g.reason
                    },
                    false
                )
            ))],
            StreamEvent::Resync(r) => vec![Line::Err(format!(
                "The relay asked to catch up (it had sent up to event {}); reconnecting.",
                r.after
            ))],
            StreamEvent::Reconnecting { delay, reason, .. } => {
                let when = if delay.is_zero() {
                    "now".to_string()
                } else {
                    format!("in {}", duration(delay))
                };
                vec![Line::Err(format!(
                    "Connection lost: {}. Reconnecting {when}.",
                    sanitize(&reason, false)
                ))]
            }
            StreamEvent::Warning(w) => vec![Line::Err(sentence(&sanitize(&w, false)))],
        };
        let mut open = true;
        for line in lines {
            open &= out.send(line).await;
        }
        if !open {
            break Ok(());
        }
    };
    if result.is_ok() && !out.is_broken() {
        out.err("Stopped.").await;
    }
    out.finish().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn event(body: &[u8], event_type: Option<&str>, verified: bool) -> Event {
        serde_json::from_value(serde_json::json!({
            "seq": 1, "id": "evt_1", "hookId": "hk_1", "receivedAt": 1792233600000u64,
            "verified": verified, "preset": "github", "eventType": event_type,
            "body": base64::engine::general_purpose::STANDARD.encode(body)
        }))
        .unwrap()
    }

    #[test]
    fn summary_shows_type_hook_verified_size_and_time() {
        let e = event(b"{\"a\":1}", Some("push"), true);
        assert_eq!(
            summary(&e, Some("ci")),
            "10:40:00  push  ci  verified  7 B  evt_1"
        );
        let e = event(b"x", Some("evil\u{1b}]0;title\u{7}"), false);
        let s = summary(&e, None);
        assert!(s.contains("UNVERIFIED") && s.contains("hk_1"));
        assert!(!s.contains('\u{1b}') && !s.contains('\u{7}'));
    }

    #[test]
    fn bodies_are_pretty_and_harmless() {
        let e = event(b"{\"msg\":\"hi\\u001b[2J\",\"n\":[1,2]}", None, true);
        let body = render_body(&e).unwrap();
        assert!(body.contains("\"msg\""), "{body}");
        assert!(body.contains('\n'), "pretty-printed");
        // serde escapes C0 controls inside strings; the output never carries a raw ESC.
        assert!(!body.contains('\u{1b}'));
        let e = event("plain\u{9b}text\n".as_bytes(), None, true);
        assert_eq!(render_body(&e).unwrap(), "plaintext\n");
        let e = event(&[0xff, 0xfe, 0x00], None, true);
        assert_eq!(render_body(&e).unwrap(), "(3 B of binary data)");
        assert_eq!(render_body(&event(b"", None, true)), None);
    }

    #[test]
    fn long_bodies_are_cut_on_a_char_boundary() {
        let text = "é".repeat(SHOW_BODY);
        let e = event(text.as_bytes(), None, true);
        let body = render_body(&e).unwrap();
        assert!(body.len() < SHOW_BODY + 100);
        assert!(body.ends_with("shows whole events)"));
    }
}
