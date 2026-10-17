//! `00hooks hooks …`.

use std::io::BufRead;

use clap::ValueEnum;
use hooks_client::{Hook, HookPatch, StrictHook};
use serde_json::{Map, Value, json};

use crate::account::confirm;
use crate::ctx::{CliResult, Ctx, Failure, key_store, sentence};
use crate::output::{date_time, json_line, sanitize, size, table};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Preset {
    Github,
    StandardWebhooks,
    StandardWebhooksEd25519,
    Stripe,
    Slack,
    Linear,
    Shopify,
    Twilio,
    Hmac,
    Token,
    Unverified,
}

impl Preset {
    fn wire(self) -> &'static str {
        match self {
            Preset::Github => "github",
            Preset::StandardWebhooks => "standard-webhooks",
            Preset::StandardWebhooksEd25519 => "standard-webhooks-ed25519",
            Preset::Stripe => "stripe",
            Preset::Slack => "slack",
            Preset::Linear => "linear",
            Preset::Shopify => "shopify",
            Preset::Twilio => "twilio",
            Preset::Hmac => "hmac",
            Preset::Token => "token",
            Preset::Unverified => "unverified",
        }
    }

    /// The provider issues the secret: it has to be given (`--secret-stdin`).
    fn provider_issued(self) -> bool {
        matches!(
            self,
            Preset::Stripe | Preset::Slack | Preset::Linear | Preset::Shopify | Preset::Twilio
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Algorithm {
    Sha256,
    Sha1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Encoding {
    Hex,
    Base64,
}

#[derive(Debug, Clone, Default)]
pub struct VerifyArgs {
    pub header: Option<String>,
    pub algorithm: Option<Algorithm>,
    pub encoding: Option<Encoding>,
    pub prefix: Option<String>,
    pub secret: Option<String>,
    /// standard-webhooks-ed25519: the sender's `whpk_` public key.
    pub public_key: Option<String>,
    /// Verify on this device (PROTOCOL §3): the secret never goes to the relay.
    pub strict: bool,
}

/// The `verify` object of PROTOCOL §3 for a preset and its flags, refusing flags that don't apply.
pub fn verify_spec(preset: Preset, a: &VerifyArgs) -> CliResult<Value> {
    let mut v = Map::new();
    v.insert("preset".into(), json!(preset.wire()));
    let only = |flag: &str, set: bool, allowed: &[Preset]| -> CliResult {
        if set && !allowed.contains(&preset) {
            let names: Vec<_> = allowed.iter().map(|p| p.wire()).collect();
            return Err(Failure::new(format!(
                "--{flag} applies only to --preset {}.",
                names.join(" or ")
            )));
        }
        Ok(())
    };
    only("header", a.header.is_some(), &[Preset::Hmac, Preset::Token])?;
    only("algorithm", a.algorithm.is_some(), &[Preset::Hmac])?;
    only("encoding", a.encoding.is_some(), &[Preset::Hmac])?;
    only("prefix", a.prefix.is_some(), &[Preset::Hmac])?;
    only(
        "public-key",
        a.public_key.is_some(),
        &[Preset::StandardWebhooksEd25519],
    )?;
    if preset == Preset::Unverified && a.secret.is_some() {
        return Err(Failure::new(
            "An unverified hook has no secret; drop --secret-stdin.",
        ));
    }
    if preset == Preset::Unverified && a.strict {
        return Err(Failure::new(
            "An unverified hook has nothing to verify; drop --strict.",
        ));
    }
    if preset == Preset::StandardWebhooksEd25519 {
        if a.secret.is_some() {
            return Err(Failure::new(
                "--preset standard-webhooks-ed25519 takes the sender's public key \
                 (--public-key whpk_…), not a secret.",
            ));
        }
        if a.public_key.is_none() {
            return Err(Failure::new(
                "--preset standard-webhooks-ed25519 needs --public-key: the sender's whpk_ key.",
            ));
        }
    }
    if preset.provider_issued() && a.secret.is_none() {
        return Err(Failure::new(format!(
            "--preset {} needs the signing secret {} gives you, on stdin: for example \
             `pbpaste | 00hooks hooks create … --secret-stdin`.",
            preset.wire(),
            preset.wire()
        )));
    }
    match preset {
        Preset::Hmac => {
            let header = a.header.clone().ok_or_else(|| {
                Failure::new(
                    "--preset hmac needs --header: the header the sender puts its signature in.",
                )
            })?;
            v.insert("header".into(), json!(header));
            let alg = match a.algorithm.unwrap_or(Algorithm::Sha256) {
                Algorithm::Sha256 => "sha256",
                Algorithm::Sha1 => "sha1",
            };
            v.insert("algorithm".into(), json!(alg));
            let enc = match a.encoding.unwrap_or(Encoding::Hex) {
                Encoding::Hex => "hex",
                Encoding::Base64 => "base64",
            };
            v.insert("encoding".into(), json!(enc));
            if let Some(p) = &a.prefix {
                v.insert("prefix".into(), json!(p));
            }
        }
        Preset::Token => {
            v.insert(
                "header".into(),
                json!(a.header.clone().unwrap_or_else(|| "Authorization".into())),
            );
        }
        _ => {}
    }
    if a.strict {
        // A strict hook's secret and key stay here: the relay gets neither.
        v.insert("strict".into(), json!(true));
    } else {
        if let Some(s) = &a.secret {
            v.insert("secret".into(), json!(s));
        }
        if let Some(k) = &a.public_key {
            v.insert("publicKey".into(), json!(k));
        }
    }
    Ok(Value::Object(v))
}

/// What a strict hook keeps on this device: its `verify` (from the relay, plus the public key for
/// Ed25519) and its secrets.
fn strict_entry(
    hook: &Hook,
    secret: String,
    public_key: Option<&str>,
    previous: Option<StrictHook>,
) -> StrictHook {
    let mut verify = serde_json::to_value(&hook.verify).expect("json");
    if let Some(k) = public_key {
        verify["publicKey"] = json!(k);
    }
    let mut secrets = vec![secret];
    // The previous secret keeps verifying (one), so a sender can switch over without losing events.
    if let Some(p) = previous
        && let Some(old) = p.secrets.into_iter().next()
        && !secrets.contains(&old)
    {
        secrets.push(old);
    }
    StrictHook { verify, secrets }
}

fn is_strict(h: &Hook) -> bool {
    h.verify.fields.get("strict") == Some(&Value::Bool(true))
}

/// Read a secret from stdin (one line), so it never appears in the process list or shell history.
pub fn read_secret_stdin() -> CliResult<String> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| Failure::new(format!("Couldn't read the secret from stdin: {e}.")))?;
    let s = line.trim_end_matches(['\r', '\n']).to_string();
    if s.is_empty() {
        return Err(Failure::new(
            "No secret on stdin. Pipe it in, for example `pbpaste | 00hooks hooks create … --secret-stdin`.",
        ));
    }
    Ok(s)
}

const SAVE_NOW: &str = "Save this secret now: it won't be shown again.";

pub async fn create(
    name: String,
    preset: Preset,
    mut args: VerifyArgs,
    as_json: bool,
) -> CliResult {
    // A strict hook whose secret the relay would have made gets one made here instead.
    let mut generated_here = None;
    if args.strict && args.secret.is_none() && preset != Preset::StandardWebhooksEd25519 {
        generated_here = hooks_client::presets::generate_secret(preset.wire())
            .map_err(|e| Failure::new(e.to_string()))?;
        args.secret = generated_here.clone();
    }
    let verify = verify_spec(preset, &args)?;
    let ctx = Ctx::load()?;
    let mut created = ctx
        .client
        .create_hook(&name, verify)
        .await
        .map_err(|e| ctx.explain(e))?;
    if args.strict {
        let store = key_store(&ctx.config.key_store, &ctx.state);
        let secret = args
            .secret
            .clone()
            .or_else(|| args.public_key.clone())
            .expect("checked");
        let entry = strict_entry(&created.hook, secret, args.public_key.as_deref(), None);
        if let Err(e) = entry.save(store.as_ref(), &created.hook.id) {
            // A strict hook nobody can verify is no use: take it back.
            let _ = ctx.client.delete_hook(&created.hook.id).await;
            return Err(Failure::new(format!(
                "Couldn't keep the hook's secret in {} ({e}), so the hook was deleted again.",
                store.describe()
            )));
        }
        // Shown once, like a relay-generated secret: the sender needs it.
        created.secret = generated_here.map(hooks_client::Secret::new);
    }
    if as_json {
        let mut v = json!({ "hook": created.hook, "url": created.url });
        if let Some(s) = &created.secret {
            v["secret"] = json!(s.expose());
        }
        println!("{}", json_line(&v));
    } else {
        eprintln!(
            "Created hook {} ({}).",
            sanitize(&created.hook.name, false),
            created.hook.id
        );
        println!("URL     {}", sanitize(&created.url, false));
        if let Some(s) = &created.secret {
            println!("Secret  {}", sanitize(s.expose(), false));
        }
    }
    if created.secret.is_some() {
        eprintln!("{SAVE_NOW} Paste it into the sender's webhook settings.");
    } else if args.secret.is_some() {
        eprintln!("The hook uses the secret you gave.");
    }
    if args.strict {
        eprintln!(
            "Strict: the relay never has this hook's secret; this computer verifies every event \
             itself. On your other computers, run `00hooks hooks secret {}` with the same secret.",
            created.hook.id
        );
    }
    if preset == Preset::Unverified {
        eprintln!(
            "Anyone who learns this URL can send events to it; they arrive marked unverified."
        );
    }
    Ok(())
}

/// A hook by id (`hk_…`) or by exact name.
async fn resolve(ctx: &Ctx, which: &str) -> CliResult<Hook> {
    if which.starts_with("hk_") {
        return ctx.client.hook(which).await.map_err(|e| ctx.explain(e));
    }
    let hooks = ctx.client.hooks().await.map_err(|e| ctx.explain(e))?;
    let mut matches: Vec<Hook> = hooks.into_iter().filter(|h| h.name == which).collect();
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(Failure::new(format!(
            "No hook named {}. Run `00hooks hooks list` to see them.",
            sanitize(which, false)
        ))),
        _ => Err(Failure::new(format!(
            "More than one hook is named {}; use its id (`00hooks hooks list`).",
            sanitize(which, false)
        ))),
    }
}

fn state(h: &Hook) -> &'static str {
    if h.enabled { "active" } else { "paused" }
}

pub async fn list(as_json: bool) -> CliResult {
    let ctx = Ctx::load()?;
    let hooks = ctx.client.hooks().await.map_err(|e| ctx.explain(e))?;
    if as_json {
        println!("{}", json_line(&json!({ "hooks": hooks })));
        return Ok(());
    }
    if hooks.is_empty() {
        eprintln!(
            "No hooks yet. Create one with `00hooks hooks create --name NAME --preset github`."
        );
        return Ok(());
    }
    let mut rows = vec![vec![
        "NAME".to_string(),
        "ID".into(),
        "PRESET".into(),
        "STATE".into(),
        "LAST EVENT".into(),
    ]];
    for h in &hooks {
        rows.push(vec![
            sanitize(&h.name, false),
            h.id.clone(),
            sanitize(&h.verify.preset, false),
            state(h).into(),
            h.last_event_at
                .map(date_time)
                .unwrap_or_else(|| "never".into()),
        ]);
    }
    print!("{}", table(&rows));
    Ok(())
}

pub fn describe(h: &Hook) -> String {
    let mut rows = vec![
        vec!["Name".to_string(), sanitize(&h.name, false)],
        vec!["ID".into(), h.id.clone()],
        vec!["URL".into(), sanitize(&h.url, false)],
        vec!["Preset".into(), sanitize(&h.verify.preset, false)],
    ];
    for (k, v) in &h.verify.fields {
        let v = match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        rows.push(vec![
            format!("  {}", sanitize(k, false)),
            sanitize(&v, false),
        ]);
    }
    rows.extend([
        vec!["State".into(), state(h).into()],
        vec!["Max body".into(), size(h.max_body_bytes as usize)],
        vec!["Created".into(), date_time(h.created_at)],
        vec![
            "Last event".into(),
            h.last_event_at
                .map(date_time)
                .unwrap_or_else(|| "never".into()),
        ],
    ]);
    table(&rows)
}

pub async fn show(which: String, as_json: bool) -> CliResult {
    let ctx = Ctx::load()?;
    let h = resolve(&ctx, &which).await?;
    if as_json {
        println!("{}", json_line(&json!(h)));
    } else {
        print!("{}", describe(&h));
    }
    Ok(())
}

pub async fn rotate(which: String) -> CliResult {
    let ctx = Ctx::load()?;
    let h = resolve(&ctx, &which).await?;
    if is_strict(&h) {
        return Err(Failure::new(format!(
            "{} is strict: its secret lives on your computers, not the relay. Change it at the \
             sender, then run `00hooks hooks secret {} --secret-stdin` on each computer.",
            sanitize(&h.name, false),
            h.id
        )));
    }
    let r = ctx
        .client
        .rotate_hook(&h.id)
        .await
        .map_err(|e| ctx.explain(e))?;
    eprintln!("New secret for {} ({}):", sanitize(&h.name, false), h.id);
    println!("Secret  {}", sanitize(r.secret.expose(), false));
    eprintln!("{SAVE_NOW} The previous secret keeps working for 24 hours.");
    Ok(())
}

/// `00hooks hooks secret`: keep a strict hook's secret (or Ed25519 public key) on this computer.
/// The previous one keeps verifying alongside it, for a switch-over.
pub async fn secret(
    which: String,
    secret: Option<String>,
    public_key: Option<String>,
) -> CliResult {
    let ctx = Ctx::load()?;
    let h = resolve(&ctx, &which).await?;
    if !is_strict(&h) {
        return Err(Failure::new(format!(
            "{} isn't strict: the relay verifies it, and holds its secret.",
            sanitize(&h.name, false)
        )));
    }
    let ed = h.verify.preset == "standard-webhooks-ed25519";
    let value = match (ed, secret, public_key) {
        (true, None, Some(k)) => k,
        (false, Some(s), None) => s,
        (true, ..) => {
            return Err(Failure::new(
                "This hook is standard-webhooks-ed25519: give the sender's key with --public-key.",
            ));
        }
        (false, ..) => {
            return Err(Failure::new(
                "Pipe the hook's secret in with --secret-stdin.",
            ));
        }
    };
    let store = key_store(&ctx.config.key_store, &ctx.state);
    let previous = StrictHook::load(store.as_ref(), &h.id)
        .map_err(|e| Failure::new(sentence(&e.to_string())))?;
    let entry = strict_entry(&h, value.clone(), ed.then_some(value.as_str()), previous);
    entry
        .save(store.as_ref(), &h.id)
        .map_err(|e| Failure::new(format!("Couldn't keep the secret: {e}.")))?;
    println!(
        "Kept the secret for {} in {}; events for it are verified here.{}",
        sanitize(&h.name, false),
        store.describe(),
        if entry.secrets.len() > 1 {
            " The previous one keeps working too, until the next change."
        } else {
            ""
        }
    );
    Ok(())
}

pub async fn set_enabled(which: String, enabled: bool) -> CliResult {
    let ctx = Ctx::load()?;
    let h = resolve(&ctx, &which).await?;
    let patch = HookPatch {
        enabled: Some(enabled),
        ..Default::default()
    };
    let h = ctx
        .client
        .patch_hook(&h.id, &patch)
        .await
        .map_err(|e| ctx.explain(e))?;
    let name = sanitize(&h.name, false);
    if enabled {
        println!("Resumed {name}. Its URL accepts events again.");
    } else {
        println!("Paused {name}. Its URL answers 404 until you resume it.");
    }
    Ok(())
}

pub async fn delete(which: String, yes: bool) -> CliResult {
    let ctx = Ctx::load()?;
    let h = resolve(&ctx, &which).await?;
    let name = sanitize(&h.name, false);
    if !yes
        && !confirm(&format!(
            "Delete hook {name} ({})? Senders using its URL will get 404.",
            h.id
        ))?
    {
        eprintln!("Nothing deleted.");
        return Ok(());
    }
    ctx.client
        .delete_hook(&h.id)
        .await
        .map_err(|e| ctx.explain(e))?;
    println!(
        "Deleted {name}. Events it already received stay until every device acknowledges them."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_build_the_protocol_verify_object() {
        let none = VerifyArgs::default();
        assert_eq!(
            verify_spec(Preset::Github, &none).unwrap(),
            json!({"preset":"github"})
        );
        assert_eq!(
            verify_spec(Preset::StandardWebhooks, &none).unwrap(),
            json!({"preset":"standard-webhooks"})
        );
        assert_eq!(
            verify_spec(Preset::Token, &none).unwrap(),
            json!({"preset":"token","header":"Authorization"})
        );
        let hmac = VerifyArgs {
            header: Some("X-Signature".into()),
            prefix: Some("sha256=".into()),
            secret: Some("s".into()),
            ..Default::default()
        };
        assert_eq!(
            verify_spec(Preset::Hmac, &hmac).unwrap(),
            json!({"preset":"hmac","header":"X-Signature","algorithm":"sha256",
                   "encoding":"hex","prefix":"sha256=","secret":"s"})
        );
    }

    #[test]
    fn strict_hooks_send_neither_secret_nor_key_to_the_relay() {
        let a = VerifyArgs {
            secret: Some("whsec_from_stripe".into()),
            strict: true,
            ..Default::default()
        };
        assert_eq!(
            verify_spec(Preset::Stripe, &a).unwrap(),
            json!({"preset":"stripe","strict":true})
        );
        let ed = VerifyArgs {
            public_key: Some("whpk_x".into()),
            strict: true,
            ..Default::default()
        };
        assert_eq!(
            verify_spec(Preset::StandardWebhooksEd25519, &ed).unwrap(),
            json!({"preset":"standard-webhooks-ed25519","strict":true})
        );
        let relay = VerifyArgs {
            public_key: Some("whpk_x".into()),
            ..Default::default()
        };
        assert_eq!(
            verify_spec(Preset::StandardWebhooksEd25519, &relay).unwrap(),
            json!({"preset":"standard-webhooks-ed25519","publicKey":"whpk_x"})
        );
        let none = VerifyArgs {
            strict: true,
            ..Default::default()
        };
        assert!(verify_spec(Preset::Unverified, &none).is_err());
        assert!(verify_spec(Preset::Twilio, &none).is_err());
        assert!(
            verify_spec(Preset::Github, &relay)
                .unwrap_err()
                .message
                .contains("--public-key")
        );
    }

    #[test]
    fn flags_that_do_not_apply_are_refused() {
        assert!(
            verify_spec(Preset::Hmac, &VerifyArgs::default())
                .unwrap_err()
                .message
                .contains("--header")
        );
        let header = VerifyArgs {
            header: Some("X".into()),
            ..Default::default()
        };
        assert!(verify_spec(Preset::Github, &header).is_err());
        let secret = VerifyArgs {
            secret: Some("s".into()),
            ..Default::default()
        };
        assert!(verify_spec(Preset::Unverified, &secret).is_err());
        let alg = VerifyArgs {
            algorithm: Some(Algorithm::Sha1),
            ..Default::default()
        };
        assert!(verify_spec(Preset::Token, &alg).is_err());
    }

    #[test]
    fn describe_strips_controls_from_names() {
        let h: Hook = serde_json::from_value(json!({
            "id": "hk_1", "name": "evil\u{1b}[2J", "url": "https://r.example/h/hk_1",
            "enabled": false, "verify": {"preset": "hmac", "header": "X-Sig"},
            "maxBodyBytes": 1048576, "createdAt": 0, "lastEventAt": null
        }))
        .unwrap();
        let text = describe(&h);
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("paused"));
        assert!(text.contains("1.0 MB"));
        assert!(text.contains("header") && text.contains("X-Sig"));
    }
}
