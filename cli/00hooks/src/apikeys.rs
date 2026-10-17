//! `00hooks keys …` (PROTOCOL §9): API keys for management and CI. A key is shown once; it can
//! never open the stream, enrol a device or make more keys.

use clap::ValueEnum;
use hooks_client::api::check_id;
use serde_json::json;

use crate::ctx::{CliResult, Ctx, Failure};
use crate::output::{date_time, json_line, sanitize, table};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Scope {
    #[value(name = "hooks:read")]
    HooksRead,
    #[value(name = "hooks:write")]
    HooksWrite,
    #[value(name = "events:read")]
    EventsRead,
    #[value(name = "devices:write")]
    DevicesWrite,
    #[value(name = "audit:read")]
    AuditRead,
}

impl Scope {
    pub fn wire(self) -> &'static str {
        match self {
            Scope::HooksRead => "hooks:read",
            Scope::HooksWrite => "hooks:write",
            Scope::EventsRead => "events:read",
            Scope::DevicesWrite => "devices:write",
            Scope::AuditRead => "audit:read",
        }
    }
}

pub async fn create(
    name: String,
    scopes: Vec<Scope>,
    days: Option<u32>,
    as_json: bool,
) -> CliResult {
    if scopes.is_empty() {
        return Err(Failure::new(
            "Give the key at least one --scope (hooks:read, hooks:write, events:read, \
             devices:write, audit:read).",
        ));
    }
    let ctx = Ctx::load()?;
    let mut wire: Vec<String> = scopes.iter().map(|s| s.wire().to_string()).collect();
    wire.dedup();
    let created = ctx
        .client
        .create_key(&name, &wire, days)
        .await
        .map_err(|e| ctx.explain(e))?;
    if as_json {
        println!(
            "{}",
            json_line(&json!({ "key": created.key, "token": created.token.expose() }))
        );
    } else {
        eprintln!(
            "Created key {} ({}), valid until {}, for: {}.",
            sanitize(&created.key.name, false),
            sanitize(&created.key.id, false),
            date_time(created.key.expires_at),
            sanitize(&created.key.scopes.join(", "), false)
        );
        println!("{}", sanitize(created.token.expose(), false));
    }
    eprintln!(
        "Save this token now: it won't be shown again. Use it as `Authorization: Bearer <token>`; \
         it can't open the stream."
    );
    Ok(())
}

pub async fn list(as_json: bool) -> CliResult {
    let ctx = Ctx::load()?;
    let keys = ctx.client.keys().await.map_err(|e| ctx.explain(e))?;
    if as_json {
        println!("{}", json_line(&json!({ "keys": keys })));
        return Ok(());
    }
    if keys.is_empty() {
        eprintln!(
            "No API keys. Create one with `00hooks keys create --name ci --scope hooks:read`."
        );
        return Ok(());
    }
    let now = hooks_client::api::system_now_ms();
    let mut rows = vec![vec![
        "NAME".to_string(),
        "ID".into(),
        "SCOPES".into(),
        "EXPIRES".into(),
        "LAST USED".into(),
    ]];
    for k in keys {
        rows.push(vec![
            sanitize(&k.name, false),
            sanitize(&k.id, false),
            sanitize(&k.scopes.join(" "), false),
            if k.expires_at <= now {
                format!("expired {}", date_time(k.expires_at))
            } else {
                date_time(k.expires_at)
            },
            k.last_used_at
                .map(date_time)
                .unwrap_or_else(|| "never".into()),
        ]);
    }
    print!("{}", table(&rows));
    Ok(())
}

pub async fn revoke(id: String) -> CliResult {
    check_id("key_", &id)
        .map_err(|e| Failure::new(format!("{e}. Run `00hooks keys list` to see ids.")))?;
    let ctx = Ctx::load()?;
    ctx.client
        .revoke_key(&id)
        .await
        .map_err(|e| ctx.explain(e))?;
    println!("Revoked {id}. It stops working at once.");
    Ok(())
}
