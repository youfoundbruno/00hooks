//! `00hooks screen`: the screen (PLAN §6a) on this computer: switch it on, list and decide what it
//! held (here, and at the relay), list its rules, and push the rules that can go to the relay.
//!
//! The screen's files live in `<runner>/screen/`; a running `00hooks run` reads changes made here.
//! Releasing a held event runs it, so it goes through the runner (the running one, through its
//! mailbox, or one started for the purpose).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hooks_runner::hooks_screen::{Screen, SourceSettings, Verdict, edge};
use hooks_runner::runner::{load_names, runner_dir};
use hooks_runner::{Runner, RunnerOptions, mailbox};
use serde_json::json;

use crate::automate::automations_path;
use crate::ctx::{CliResult, Ctx, Failure, open_state, sentence};
use crate::output::{date_time, json_line, sanitize, table};

/// The screen's folder for a state directory.
pub fn screen_dir(runner: &std::path::Path) -> PathBuf {
    runner.join("screen")
}

/// The screen this computer's runner uses.
pub fn open(runner: &std::path::Path) -> CliResult<Arc<Screen>> {
    Screen::open(screen_dir(runner))
        .map(Arc::new)
        .map_err(|e| Failure::new(sentence(&e)))
}

fn local() -> CliResult<(PathBuf, Arc<Screen>)> {
    let state = open_state()?;
    let rdir = runner_dir(state.path());
    let s = open(&rdir)?;
    Ok((rdir, s))
}

/// `00hooks screen status`.
pub fn status(json: bool) -> CliResult {
    let (_, s) = local()?;
    let set = s.settings();
    let w = set.source(hooks_runner::hooks_screen::SourceKind::Webhook, "");
    let rules = s.rules();
    let learned = rules.iter().filter(|r| r.learned.is_some()).count();
    let held = s.held().len();
    let broken = s.rule_errors();
    if json {
        println!(
            "{}",
            json_line(
                &json!({"on": w.enabled, "evaluate": w.evaluate, "rules": rules.len() - learned, "learned": learned, "held": held, "broken": broken.len()})
            )
        );
        return Ok(());
    }
    println!(
        "The screen is {} for webhooks{}.",
        if w.enabled { "on" } else { "off" },
        if w.enabled && w.evaluate {
            ", with the evaluator"
        } else {
            ""
        }
    );
    println!(
        "{} rules of yours, {learned} learned; {held} held.",
        rules.len() - learned
    );
    for l in broken_lines(&broken) {
        eprintln!("{l}");
    }
    Ok(())
}

/// What to say about rules that don't compile: each holds what it applies to until it's fixed.
pub fn broken_lines(errors: &[hooks_runner::hooks_screen::RuleError]) -> Vec<String> {
    errors
        .iter()
        .map(|e| {
            format!(
                "Rule {} ({}) doesn't work: {}. Until it's fixed or switched off, what it applies \
                 to is held.",
                e.id,
                sanitize(&e.name, false),
                sanitize(&e.error, false)
            )
        })
        .collect()
}

/// `00hooks screen on|off`.
pub fn set_on(on: bool, evaluate: bool) -> CliResult {
    let (_, s) = local()?;
    let mut set = s.settings();
    let mut w = set
        .sources
        .get("webhook")
        .cloned()
        .unwrap_or_else(SourceSettings::default);
    w.enabled = on;
    w.evaluate = on && evaluate;
    set.sources.insert("webhook".into(), w);
    s.set_settings(set)
        .map_err(|e| Failure::new(sentence(&e)))?;
    println!(
        "The screen is {} for webhooks. A running `00hooks run` picks it up with the next event.",
        if on { "on" } else { "off" }
    );
    Ok(())
}

/// `00hooks screen held`: what this computer's screen holds, then what the relay holds.
pub async fn held(json: bool) -> CliResult {
    let (_, s) = local()?;
    let mine = s.held();
    let relay = match Ctx::load() {
        Ok(ctx) => match ctx.client.held().await {
            Ok(h) => h,
            Err(e) => return Err(ctx.explain(e)),
        },
        Err(_) => Vec::new(),
    };
    if json {
        for h in &mine {
            println!(
                "{}",
                json_line(
                    &json!({"where": "here", "id": h.id, "heldAt": h.held_at, "summary": h.item.summary, "reason": h.decision.reason})
                )
            );
        }
        for h in &relay {
            println!(
                "{}",
                json_line(
                    &json!({"where": "relay", "id": h.id, "heldAt": h.received_at, "hook": h.hook_id, "rule": h.rule})
                )
            );
        }
        return Ok(());
    }
    if mine.is_empty() && relay.is_empty() {
        println!("Nothing is held.");
        return Ok(());
    }
    let mut rows = vec![vec![
        "ID".into(),
        "WHERE".into(),
        "HELD".into(),
        "WHAT".into(),
        "WHY".into(),
    ]];
    for h in &mine {
        rows.push(vec![
            h.id.clone(),
            "here".into(),
            date_time(h.held_at),
            sanitize(&h.item.summary, false),
            sanitize(&h.decision.reason, false),
        ]);
    }
    for h in &relay {
        rows.push(vec![
            h.id.clone(),
            "relay".into(),
            date_time(h.received_at),
            sanitize(
                &format!(
                    "{} on {}",
                    h.event_type.as_deref().unwrap_or("an event"),
                    h.hook_id
                ),
                false,
            ),
            sanitize(&format!("edge rule {}", h.rule), false),
        ]);
    }
    print!("{}", table(&rows));
    println!("`00hooks screen release <id>` runs one; `00hooks screen drop <id>` drops it.");
    Ok(())
}

/// `00hooks screen release <id>`: a held event runs now (here), or is streamed (at the relay).
pub async fn release(id: String, file: Option<PathBuf>) -> CliResult {
    if id.starts_with("evt_") {
        let ctx = Ctx::load()?;
        let seq = ctx
            .client
            .release_held(&id)
            .await
            .map_err(|e| ctx.explain(e))?;
        println!("Released {id} at the relay: it streams as event {seq}.");
        return Ok(());
    }
    if !id.starts_with("hld_") {
        return Err(Failure::new(
            "A held item's id starts with hld_ (here) or evt_ (at the relay); `00hooks screen held` lists them.",
        ));
    }
    let state = open_state()?;
    let rdir = runner_dir(state.path());
    let record = match mailbox::lock(&rdir).map_err(|e| Failure::new(sentence(&e.to_string())))? {
        Some(_lock) => {
            let path = automations_path(file)?;
            let origin = state
                .load_config()
                .ok()
                .flatten()
                .map(|c| c.device_id)
                .unwrap_or_else(|| "dev_local".into());
            let mut opts = RunnerOptions::new(&rdir, &path, &origin);
            opts.screen = Some(open(&rdir)?);
            let mut runner =
                Runner::open(opts).map_err(|e| Failure::new(sentence(&e.to_string())))?;
            runner
                .release(&id)
                .await
                .map_err(|e| Failure::new(sentence(&e.to_string())))?
        }
        None => {
            let at =
                mailbox::submit(&rdir, &id).map_err(|e| Failure::new(sentence(&e.to_string())))?;
            eprintln!("Asked the running runner to release it…");
            let deadline = Instant::now() + Duration::from_secs(120);
            loop {
                if let Some(a) = mailbox::take_answer(&at) {
                    match (a.record, a.error) {
                        (Some(r), _) => break r,
                        (None, e) => return Err(Failure::new(sentence(&e.unwrap_or_default()))),
                    }
                }
                if Instant::now() > deadline {
                    return Err(Failure::new(
                        "The running runner didn't answer within 2 minutes.",
                    ));
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    };
    println!(
        "Released {id}: {} automation run{}.",
        record.ran(),
        if record.ran() == 1 { "" } else { "s" }
    );
    Ok(())
}

/// `00hooks screen drop <id> [--always]`.
pub async fn drop(id: String, always: bool) -> CliResult {
    if id.starts_with("evt_") {
        if always {
            return Err(Failure::new(
                "The relay keeps no content, so --always works on items held here (hld_…).",
            ));
        }
        let ctx = Ctx::load()?;
        ctx.client
            .drop_held(&id)
            .await
            .map_err(|e| ctx.explain(e))?;
        println!("Dropped {id} at the relay.");
        return Ok(());
    }
    let (_, s) = local()?;
    s.drop_held(&id).map_err(|e| Failure::new(sentence(&e)))?;
    println!("Dropped {id}.");
    if always {
        let r = s
            .always(&id, Verdict::Drop)
            .map_err(|e| Failure::new(sentence(&e)))?;
        println!(
            "Learned: {} (expires after {} days without a match; `00hooks screen sync` sends it to the relay).",
            sanitize(&r.name, false),
            s.settings().expiry_days
        );
    }
    Ok(())
}

/// `00hooks screen rules`.
pub fn rules(json: bool) -> CliResult {
    let (_, s) = local()?;
    let rules = s.rules();
    if json {
        for r in &rules {
            println!("{}", json_line(r));
        }
        return Ok(());
    }
    if rules.is_empty() {
        println!("No rules yet.");
        return Ok(());
    }
    let mut rows = vec![vec![
        "ID".into(),
        "RULE".into(),
        "ON".into(),
        "MATCHED".into(),
    ]];
    for r in &rules {
        rows.push(vec![
            r.id.clone(),
            sanitize(&r.describe(), false),
            if r.enabled { "always" } else { "off" }.into(),
            match r.last_matched_at {
                Some(t) => format!("{} times, last {}", r.matches, date_time(t)),
                None => "never".into(),
            },
        ]);
    }
    print!("{}", table(&rows));
    for l in broken_lines(&s.rule_errors()) {
        eprintln!("{l}");
    }
    Ok(())
}

/// `00hooks screen sync`: push each hook's edge rules to the relay (field values as keyed hashes).
pub async fn sync() -> CliResult {
    let ctx = Ctx::load()?;
    let rdir = runner_dir(ctx.state.path());
    let s = open(&rdir)?;
    let set = s.settings();
    let key = ctx.client.screen_key().await.map_err(|e| ctx.explain(e))?;
    let hooks = ctx.client.hooks().await.map_err(|e| ctx.explain(e))?;
    let names = load_names(&rdir);
    for h in hooks {
        let out = edge::export(&s.rules(), &h.id, &key, set.edge.words, set.expiry_days);
        let n = out.screen["rules"].as_array().map(Vec::len).unwrap_or(0);
        let body = (n > 0).then_some(&out.screen);
        ctx.client
            .put_hook_screen(&h.id, body)
            .await
            .map_err(|e| ctx.explain(e))?;
        let name = names.get(&h.id).cloned().unwrap_or(h.name.clone());
        println!(
            "{}: {n} rule{} at the relay.",
            sanitize(&name, false),
            if n == 1 { "" } else { "s" }
        );
        for (rule, why) in out.skipped {
            println!(
                "  stays here: {} ({})",
                sanitize(&rule, false),
                sanitize(&why, false)
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broken_rules_are_named_and_said_to_hold() {
        let lines = broken_lines(&[hooks_runner::hooks_screen::RuleError {
            id: "rul_1".into(),
            name: "bad\u{1b}[2J".into(),
            error: "the pattern is empty".into(),
        }]);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("rul_1") && lines[0].contains("held"));
        assert!(!lines[0].contains('\u{1b}'));
    }
}
