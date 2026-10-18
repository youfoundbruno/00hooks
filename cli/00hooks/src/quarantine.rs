//! `00hooks quarantine …`: events that arrived but couldn't be read or opened.

use hooks_client::store::{QuarantineKind, Quarantined};
use serde_json::json;

use crate::ctx::{CliResult, Ctx, Failure, open_state, sentence};
use crate::output::{date_time, json_line, sanitize, table};

fn kind(k: QuarantineKind) -> &'static str {
    match k {
        QuarantineKind::Refused => "refused",
        QuarantineKind::StrictRefused => "refused (strict)",
        QuarantineKind::Recoverable => "waiting",
        QuarantineKind::Oversize => "too large",
        QuarantineKind::Stale => "stale",
    }
}

/// The first `max` characters, with `…` when cut.
fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max - 1).collect();
    t.push('…');
    t
}

/// The rows `list` prints: when, the seq, what kind, and why (sanitised: the reason may name text
/// from the relay).
pub fn rows(items: &[Quarantined]) -> Vec<Vec<String>> {
    let mut rows = vec![vec![
        "WHEN".to_string(),
        "SEQ".into(),
        "KIND".into(),
        "WHY".into(),
    ]];
    for q in items {
        rows.push(vec![
            date_time(q.at),
            q.seq.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
            kind(q.kind).into(),
            sanitize(&cut(&q.error, 120), false),
        ]);
    }
    rows
}

pub fn list(as_json: bool) -> CliResult {
    let state = open_state()?;
    let items = state
        .quarantined()
        .map_err(|e| Failure::new(sentence(&e.to_string())))?;
    if as_json {
        for q in &items {
            let mut v = json!(q);
            // The raw message stays in the file; the list says how big it was.
            v.as_object_mut().map(|o| o.remove("data"));
            println!("{}", json_line(&v));
        }
        return Ok(());
    }
    if items.is_empty() {
        eprintln!("Nothing is quarantined.");
        return Ok(());
    }
    print!("{}", table(&rows(&items)));
    let waiting = items
        .iter()
        .filter(|q| q.kind == QuarantineKind::Recoverable)
        .count();
    if waiting > 0 {
        eprintln!(
            "{waiting} waiting for something this computer lacks; once it's there, a running \
             listener opens them on its next reconnect, or run `00hooks quarantine retry`."
        );
    }
    Ok(())
}

pub fn retry() -> CliResult {
    let ctx = Ctx::load()?;
    let Some(_lock) = ctx
        .state
        .lock_listener()
        .map_err(|e| Failure::new(sentence(&e.to_string())))?
    else {
        return Err(Failure::new(
            "A listener is running for this computer (`00hooks run`, the service, or `00hooks \
             listen`). It opens waiting events itself each time it reconnects; stop it and run \
             this again to retry now.",
        ));
    };
    let opener = ctx
        .client
        .opener()
        .ok_or_else(|| Failure::new("This login can't open events."))?;
    let mut events = ctx
        .state
        .open_events()
        .map_err(|e| Failure::new(sentence(&e.to_string())))?;
    let r = events
        .retry_quarantined(&opener)
        .map_err(|e| Failure::new(sentence(&e.to_string())))?;
    println!(
        "Opened {}; {} still waiting; {} refused now.",
        r.opened.len(),
        r.waiting,
        r.refused
    );
    if !r.opened.is_empty() {
        eprintln!(
            "They are recorded here and handed over, once, when `00hooks run` (or `listen`) \
             next starts."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_say_what_kind_and_strip_controls() {
        let q = Quarantined::new(
            QuarantineKind::Recoverable,
            0,
            Some("4"),
            "{}",
            "no secret\u{1b}[2J here",
        );
        let r = rows(&[q]);
        assert_eq!(r[1][1], "4");
        assert_eq!(r[1][2], "waiting");
        assert!(!r[1][3].contains('\u{1b}'));
    }
}
