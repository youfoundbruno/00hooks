//! `00hooks listen`: stream events to the terminal.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use hooks_client::{
    Event, HookChange, HookChangeKind, StreamEvent, SubscribeOptions, describe_skew, subscribe,
};

use crate::ctx::{CliResult, Ctx, Failure, sentence};
use crate::output::{Line, Output, clock, duration, json_line, sanitize, size};

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

/// One human line about a hook change (`event: hook-change`): what happened to which hook, and who
/// did it. `known` is the name this computer knew the hook by, if any.
pub fn describe_change(c: &HookChange, known: Option<&str>) -> String {
    let id = sanitize(&c.hook_id, false);
    let name = c
        .name
        .as_deref()
        .or(known)
        .map(|n| format!("{} ({id})", sanitize(n, false)))
        .unwrap_or_else(|| id.clone());
    let who = sanitize(&c.actor_words(), false);
    let what = match c.change() {
        HookChangeKind::Created => format!("Hook {name} was created by {who}."),
        HookChangeKind::Rotated => format!("Hook {name} had its secret rotated by {who}."),
        HookChangeKind::Renamed => match c.previous_name.as_deref().or(known) {
            Some(prev) => format!(
                "Hook {id} was renamed from {} to {} by {who}.",
                sanitize(prev, false),
                sanitize(c.name.as_deref().unwrap_or("?"), false)
            ),
            None => format!("Hook {name} was renamed by {who}."),
        },
        HookChangeKind::Deleted => format!("Hook {name} was deleted by {who}."),
        HookChangeKind::Other => format!(
            "Hook {name} changed ({}) by {who}.",
            sanitize(&c.kind, false)
        ),
    };
    if c.at > 0 {
        format!("{}  {what}", clock(c.at))
    } else {
        what
    }
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

    /// Keep the map current from a hook change, so the next event shows the hook's new name.
    fn apply(&mut self, c: &HookChange) {
        match c.change() {
            HookChangeKind::Created | HookChangeKind::Renamed | HookChangeKind::Rotated => {
                if let Some(n) = &c.name {
                    self.map.insert(c.hook_id.clone(), n.clone());
                }
            }
            HookChangeKind::Deleted => {
                self.map.remove(&c.hook_id);
            }
            HookChangeKind::Other => {}
        }
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
                    // C1 controls and bidi characters as `\u` escapes: the line is for programs,
                    // but it is often read in a terminal too.
                    l.push(Line::Out(json_line(&e)));
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
            StreamEvent::Quarantined { seq, path, error } => {
                let which = seq.map(|n| format!(" {n}")).unwrap_or_default();
                vec![Line::Err(format!(
                    "Event{which} arrived but couldn't be read ({}). Its raw message is kept in {}, \
                     and it was acknowledged, so the relay won't send it again.",
                    sanitize(&error, false),
                    path.display()
                ))]
            }
            StreamEvent::Warning(w) => vec![Line::Err(sentence(&sanitize(&w, false)))],
            StreamEvent::HookChange(c) => {
                let line = describe_change(&c, names.map.get(&c.hook_id).map(String::as_str));
                names.apply(&c);
                vec![Line::Err(line)]
            }
            // A kind of message this version doesn't know (the stream grows additively).
            _ => continue,
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
    fn json_mode_escapes_c1_and_bidi_in_events() {
        let e = event(b"{}", Some("push\u{9b}2J\u{202e}gnp.exe"), true);
        let line = json_line(&e);
        assert!(
            !line.contains('\u{9b}') && !line.contains('\u{202e}'),
            "{line:?}"
        );
        let back: Event = serde_json::from_str(&line).unwrap();
        assert_eq!(back.event_type, e.event_type);
    }

    fn change(v: serde_json::Value) -> HookChange {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn hook_changes_say_what_happened_and_who_did_it() {
        let at = 1792233600000i64;
        let c = change(serde_json::json!({"kind": "hook.rotated", "hookId": "hk_1",
            "name": "payments", "actor": "key_7", "at": at}));
        assert_eq!(
            describe_change(&c, None),
            "10:40:00  Hook payments (hk_1) had its secret rotated by API key key_7."
        );
        let c = change(serde_json::json!({"kind": "hook.renamed", "hookId": "hk_1",
            "name": "billing", "previousName": "payments", "actor": "dev_2"}));
        assert_eq!(
            describe_change(&c, Some("old")),
            "Hook hk_1 was renamed from payments to billing by device dev_2."
        );
        let c = change(serde_json::json!({"kind": "hook.created", "hookId": "hk_3",
            "name": "pay\u{1b}]0;x\u{7}ments", "actor": null}));
        let line = describe_change(&c, None);
        assert_eq!(
            line,
            "Hook pay]0;xments (hk_3) was created by someone unknown."
        );
        let c = change(serde_json::json!({"kind": "hook.deleted", "hookId": "hk_3"}));
        assert_eq!(
            describe_change(&c, Some("ci")),
            "Hook ci (hk_3) was deleted by someone unknown."
        );
        let c = change(serde_json::json!({"kind": "hook.paused", "hookId": "hk_3"}));
        assert_eq!(
            describe_change(&c, None),
            "Hook hk_3 changed (hook.paused) by someone unknown."
        );
    }

    #[test]
    fn hook_changes_keep_the_names_current() {
        let mut names = Names {
            map: HashMap::from([("hk_1".to_string(), "payments".to_string())]),
            fetched: None,
        };
        names.apply(&change(
            serde_json::json!({"kind": "hook.renamed", "hookId": "hk_1",
            "name": "billing", "previousName": "payments"}),
        ));
        names.apply(&change(
            serde_json::json!({"kind": "hook.created", "hookId": "hk_2",
            "name": "payments"}),
        ));
        assert_eq!(names.map["hk_1"], "billing");
        assert_eq!(names.map["hk_2"], "payments");
        names.apply(&change(
            serde_json::json!({"kind": "hook.deleted", "hookId": "hk_1",
            "name": "billing"}),
        ));
        assert!(!names.map.contains_key("hk_1"));
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
