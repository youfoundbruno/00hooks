//! `00hooks audit` (PROTOCOL §9): what happened on the account. Names and ids only.

use serde_json::json;

use crate::ctx::{CliResult, Ctx};
use crate::output::{date_time, json_line, sanitize, table};

/// One line's "what" column: the kind in words.
fn what(kind: &str, count: Option<u64>) -> String {
    let base = match kind {
        "hook.created" => "hook created",
        "hook.rotated" => "hook secret rotated",
        "hook.deleted" => "hook deleted",
        "device.added" => "device added",
        "device.revoked" => "device revoked",
        "device.seal_key" => "sealing key set",
        "key.created" => "API key created",
        "key.revoked" => "API key revoked",
        "key.used" => "API key used",
        "verify.failed" => "signature refused",
        other => return sanitize(other, false),
    };
    match count {
        Some(n) => format!("{base} ×{n} (that hour)"),
        None => base.to_string(),
    }
}

pub async fn run(limit: Option<u32>, as_json: bool) -> CliResult {
    let ctx = Ctx::load()?;
    let entries = ctx
        .client
        .audit(None, limit)
        .await
        .map_err(|e| ctx.explain(e))?;
    if as_json {
        println!("{}", json_line(&json!({ "entries": entries })));
        return Ok(());
    }
    if entries.is_empty() {
        eprintln!("Nothing recorded yet.");
        return Ok(());
    }
    let mut rows = vec![vec![
        "WHEN (UTC)".to_string(),
        "WHAT".into(),
        "SUBJECT".into(),
        "NAME".into(),
        "BY".into(),
    ]];
    for e in entries {
        rows.push(vec![
            date_time(e.at),
            what(&e.kind, e.count),
            sanitize(&e.subject, false),
            e.name
                .as_deref()
                .map(|n| sanitize(n, false))
                .unwrap_or_default(),
            e.actor
                .as_deref()
                .map(|a| sanitize(a, false))
                .unwrap_or_else(|| "the relay".into()),
        ]);
    }
    print!("{}", table(&rows));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_read_as_words_and_unknown_ones_are_sanitised() {
        assert_eq!(
            what("verify.failed", Some(3)),
            "signature refused ×3 (that hour)"
        );
        assert_eq!(what("hook.created", None), "hook created");
        assert!(!what("new.kind\u{1b}[2J", None).contains('\u{1b}'));
    }
}
