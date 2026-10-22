//! `00hooks hooks …`.

use std::io::BufRead;

use clap::ValueEnum;
use hooks_client::{
    Error, Hook, HookPatch, HookResponse, RESPONSE_CONTENT_TYPES, RESPONSE_MAX_BODY, StrictHook,
    TestSent,
};
use serde_json::{Map, Value, json};

use crate::account::confirm;
use crate::ctx::{CliResult, Ctx, Failure, key_store, sentence, strict_index};
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
    /// Meta: WhatsApp Cloud API, Messenger and Instagram webhooks.
    Meta,
    Calendly,
    Typeform,
    /// Paddle Billing.
    Paddle,
    /// Twitch EventSub.
    Twitch,
    Zoom,
    /// PagerDuty (v3 webhooks).
    Pagerduty,
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
            Preset::Meta => "meta",
            Preset::Calendly => "calendly",
            Preset::Typeform => "typeform",
            Preset::Paddle => "paddle",
            Preset::Twitch => "twitch",
            Preset::Zoom => "zoom",
            Preset::Pagerduty => "pagerduty",
            Preset::Hmac => "hmac",
            Preset::Token => "token",
            Preset::Unverified => "unverified",
        }
    }

    /// The provider issues the secret: it has to be given (`--secret-stdin`).
    fn provider_issued(self) -> bool {
        matches!(
            self,
            Preset::Stripe
                | Preset::Slack
                | Preset::Linear
                | Preset::Shopify
                | Preset::Twilio
                | Preset::Meta
                | Preset::Paddle
                | Preset::Zoom
                | Preset::Pagerduty
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
    if preset == Preset::Token && a.strict {
        return Err(Failure::new(
            "A token hook can't be strict: the token reaches the relay in the clear with every \
             delivery, so the relay could mint events with it. Use a signing preset (hmac, say), \
             or drop --strict.",
        ));
    }
    if preset == Preset::Zoom && a.strict {
        return Err(Failure::new(
            "A zoom hook can't be strict: Zoom checks the endpoint every 72 hours with a token the \
             relay must sign with the secret. Drop --strict.",
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

/// What a strict hook keeps on this device: its `verify`, built here from what the person said
/// (never taken from the relay: a relay that could rewrite it could make the device verify
/// nothing), plus the public key for Ed25519, and its secrets.
fn strict_entry(
    mut verify: Value,
    secret: String,
    public_key: Option<&str>,
    previous: Option<StrictHook>,
) -> StrictHook {
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
        .create_hook(&name, verify.clone())
        .await
        .map_err(|e| ctx.explain(e))?;
    if args.strict {
        let store = key_store(&ctx.config.key_store, &ctx.state);
        let secret = args
            .secret
            .clone()
            .or_else(|| args.public_key.clone())
            .expect("checked");
        let entry = strict_entry(verify.clone(), secret, args.public_key.as_deref(), None);
        let kept = entry
            .save(store.as_ref(), &created.hook.id)
            .and_then(|()| strict_index(&ctx.state).add(&created.hook.id));
        if let Err(e) = kept {
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
        if let Some(t) = &created.verify_token {
            v["verifyToken"] = json!(t.expose());
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
        if let Some(t) = &created.verify_token {
            println!("Verify token  {}", sanitize(t.expose(), false));
        }
    }
    if created.verify_token.is_some() {
        eprintln!("{SAVE_NOW} Meta asks for the verify token when you add the callback URL.");
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
        "DELIVERED TO".into(),
        "LAST EVENT".into(),
    ]];
    for h in &hooks {
        rows.push(vec![
            sanitize(&h.name, false),
            h.id.clone(),
            sanitize(&h.verify.preset, false),
            state(h).into(),
            delivered_to(h),
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
        vec!["Delivered to".into(), delivered_to(h)],
        vec!["Answers".into(), answers(h)],
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

/// Which devices get a hook's events.
fn delivered_to(h: &Hook) -> String {
    match &h.deliver_to {
        Some(id) => sanitize(id, false),
        None => "every device".into(),
    }
}

/// What the relay answers the provider for an accepted delivery.
fn answers(h: &Hook) -> String {
    match &h.response {
        Some(r) => format!(
            "{} {}, {}",
            r.status,
            sanitize(&r.content_type, false),
            size(r.body.len())
        ),
        None => "the default ({\"received\": …})".into(),
    }
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

/// The verify settings `hooks secret` is given: the preset and its fields, as the person says them.
/// With no preset, the relay's description is shown and confirmed instead.
#[derive(Debug, Clone, Default)]
pub struct SecretArgs {
    pub preset: Option<Preset>,
    pub header: Option<String>,
    pub algorithm: Option<Algorithm>,
    pub encoding: Option<Encoding>,
    pub prefix: Option<String>,
    /// Accept the relay's description without asking (scripts).
    pub yes: bool,
}

fn parse_preset(wire: &str) -> Option<Preset> {
    Preset::value_variants()
        .iter()
        .copied()
        .find(|p| p.wire() == wire)
}

/// The verify object to keep for strict hook `h`, from what the person said (`a.preset` and its
/// fields), or else from the relay's description, rebuilt through the same checks (only the
/// preset's own non-secret fields survive) and shown for confirmation.
pub fn strict_spec(
    h: &Hook,
    a: &SecretArgs,
    secret: Option<String>,
    public_key: Option<String>,
) -> CliResult<(Value, bool)> {
    let relay = h.verify.preset.as_str();
    let (preset, from_relay) = match a.preset {
        Some(p) => (p, false),
        None => (
            parse_preset(relay).ok_or_else(|| {
                Failure::new(format!(
                    "The relay calls this hook a {} hook, which this version doesn't know; say \
                     which with --preset.",
                    sanitize(relay, false)
                ))
            })?,
            true,
        ),
    };
    if preset.wire() != relay {
        return Err(Failure::new(format!(
            "The relay says this hook is a {} hook, but you said {}. Its events are signed as {} \
             hooks, so they wouldn't verify: check the hook, or recreate it.",
            sanitize(relay, false),
            preset.wire(),
            sanitize(relay, false)
        )));
    }
    let field = |k: &str| {
        from_relay
            .then(|| {
                h.verify
                    .fields
                    .get(k)
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .flatten()
    };
    let args = VerifyArgs {
        header: a.header.clone().or_else(|| field("header")),
        algorithm: a.algorithm.or_else(|| match field("algorithm").as_deref() {
            Some("sha1") => Some(Algorithm::Sha1),
            Some(_) => Some(Algorithm::Sha256),
            None => None,
        }),
        encoding: a.encoding.or_else(|| match field("encoding").as_deref() {
            Some("base64") => Some(Encoding::Base64),
            Some(_) => Some(Encoding::Hex),
            None => None,
        }),
        prefix: a.prefix.clone().or_else(|| field("prefix")),
        secret,
        public_key,
        strict: true,
    };
    // A relay's description may carry fields of other presets; they would be refused below, so
    // keep only what this preset takes.
    let args = if from_relay && preset != Preset::Hmac {
        VerifyArgs {
            header: None,
            algorithm: None,
            encoding: None,
            prefix: None,
            ..args
        }
    } else {
        args
    };
    Ok((verify_spec(preset, &args)?, from_relay))
}

/// How a verify object reads, one line per setting.
fn describe_spec(v: &Value) -> String {
    let mut out = Vec::new();
    if let Some(o) = v.as_object() {
        for (k, x) in o {
            if k == "strict" {
                continue;
            }
            let x = match x {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            out.push(format!("  {}: {}", sanitize(k, false), sanitize(&x, false)));
        }
    }
    out.join("\n")
}

/// `00hooks hooks secret`: keep a strict hook's secret (or Ed25519 public key) on this computer.
/// The previous one keeps verifying alongside it, for a switch-over.
pub async fn secret(
    which: String,
    secret: Option<String>,
    public_key: Option<String>,
    a: SecretArgs,
) -> CliResult {
    let ctx = Ctx::load()?;
    let h = resolve(&ctx, &which).await?;
    if !is_strict(&h) {
        return Err(Failure::new(format!(
            "{} isn't strict: the relay verifies it, and holds its secret.",
            sanitize(&h.name, false)
        )));
    }
    let ed = a
        .preset
        .map(Preset::wire)
        .unwrap_or(h.verify.preset.as_str())
        == "standard-webhooks-ed25519";
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
    let (verify, from_relay) = if ed {
        strict_spec(&h, &a, None, Some(value.clone()))?
    } else {
        strict_spec(&h, &a, Some(value.clone()), None)?
    };
    if from_relay {
        eprintln!(
            "This computer will verify {} ({}) with these settings, as the relay describes it:\n{}",
            sanitize(&h.name, false),
            h.id,
            describe_spec(&verify)
        );
        if !a.yes
            && !confirm(
                "Check them against the sender's webhook settings: a wrong preset or header \
                 means nothing verifies. Keep the secret with these settings? (Say them yourself \
                 with --preset and its options, or pass --yes in a script.)",
            )?
        {
            eprintln!("Nothing kept.");
            return Ok(());
        }
    }
    let store = key_store(&ctx.config.key_store, &ctx.state);
    let previous = StrictHook::load(store.as_ref(), &h.id)
        .map_err(|e| Failure::new(sentence(&e.to_string())))?;
    let entry = strict_entry(
        verify,
        value.clone(),
        ed.then_some(value.as_str()),
        previous,
    );
    entry
        .save(store.as_ref(), &h.id)
        .and_then(|()| strict_index(&ctx.state).add(&h.id))
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

/// `hooks deliver-to`: deliver a hook's events only to one device (`Some`), or to all (`None`).
pub async fn deliver_to(which: String, device: Option<String>) -> CliResult {
    let ctx = Ctx::load()?;
    let h = resolve(&ctx, &which).await?;
    let target = match &device {
        Some(d) => Some(crate::account::resolve_device(&ctx, d).await?),
        None => None,
    };
    let patch = HookPatch {
        deliver_to: Some(target.as_ref().map(|d| d.id.clone())),
        ..Default::default()
    };
    let h = ctx
        .client
        .patch_hook(&h.id, &patch)
        .await
        .map_err(|e| ctx.explain(e))?;
    let name = sanitize(&h.name, false);
    match target {
        Some(d) => println!(
            "{name}'s events now go only to {} ({}): its automations run on that computer \
             alone. `00hooks hooks deliver-to {} --all` sends them to every device again.",
            sanitize(&d.name, false),
            d.id,
            h.id
        ),
        None => println!("{name}'s events now go to every device."),
    }
    Ok(())
}

/// A static answer, checked as the relay checks it, so a mistake is said before the call.
pub fn response_spec(status: u16, content_type: &str, body: String) -> CliResult<HookResponse> {
    if !(200..=299).contains(&status) {
        return Err(Failure::new(
            "--status must be a success status, 200 to 299 (the provider would retry anything else).",
        ));
    }
    if !RESPONSE_CONTENT_TYPES.contains(&content_type) {
        return Err(Failure::new(format!(
            "--content-type must be one of {}.",
            RESPONSE_CONTENT_TYPES.join(", ")
        )));
    }
    if body.len() > RESPONSE_MAX_BODY {
        return Err(Failure::new(format!(
            "The body is {}; an answer's body is at most {}.",
            size(body.len()),
            size(RESPONSE_MAX_BODY)
        )));
    }
    Ok(HookResponse {
        status,
        content_type: content_type.to_string(),
        body,
    })
}

/// `hooks response`: set (`Some`) or clear (`None`) the static answer the relay gives the provider.
pub async fn set_response(which: String, response: Option<HookResponse>) -> CliResult {
    let ctx = Ctx::load()?;
    let h = resolve(&ctx, &which).await?;
    let patch = HookPatch {
        response: Some(response),
        ..Default::default()
    };
    let h = ctx
        .client
        .patch_hook(&h.id, &patch)
        .await
        .map_err(|e| ctx.explain(e))?;
    let name = sanitize(&h.name, false);
    match &h.response {
        Some(_) => println!(
            "{name} now answers each accepted delivery with {}.",
            answers(&h)
        ),
        None => println!("{name} answers deliveries with the default again."),
    }
    Ok(())
}

/// `00hooks test`: have the relay send a hook a signed test event, and say what it got.
pub async fn test(which: String, as_json: bool) -> CliResult {
    let ctx = Ctx::load()?;
    let h = resolve(&ctx, &which).await?;
    let name = sanitize(&h.name, false);
    let sent = match ctx.client.test_hook(&h.id).await {
        Ok(s) => s,
        Err(Error::Api {
            status: 409,
            message,
            ..
        }) => {
            let why = if message.is_empty() {
                "The relay can't sign a test event for this hook.".to_string()
            } else {
                sentence(&sanitize(&message, false))
            };
            return Err(Failure::new(format!(
                "{why} Send a test from the provider's dashboard instead (most have a \"send test \
                 webhook\" or \"redeliver\" button); `00hooks listen` shows it arrive."
            )));
        }
        Err(e) => return Err(ctx.explain(e)),
    };
    if as_json {
        println!("{}", json_line(&sent));
    } else {
        println!("{}", describe_test(&name, &sent));
    }
    if (200..300).contains(&sent.status) {
        Ok(())
    } else {
        Err(Failure {
            message: String::new(),
            code: 1,
        })
    }
}

/// What a test delivery got, in a sentence.
pub fn describe_test(name: &str, t: &TestSent) -> String {
    let head = format!("Sent a signed test event to {name}");
    let answer = t.answer.as_ref();
    let field = |k: &str| answer.and_then(|a| a.get(k));
    let says = |k: &str| field(k) == Some(&Value::Bool(true));
    let status = t.status;
    if !(200..300).contains(&status) {
        let why = field("message")
            .or_else(|| field("error"))
            .and_then(Value::as_str)
            .map(|m| format!(": {}", sanitize(m, false)))
            .unwrap_or_default();
        return format!("{head}: refused with status {status}{why}.");
    }
    if says("duplicate") {
        return format!(
            "{head}: the relay took it for a duplicate (status {status}), so it wasn't stored again."
        );
    }
    if says("held") {
        return format!(
            "{head}: held by the screen (status {status}). `00hooks screen held` lists it."
        );
    }
    if says("dropped") {
        return format!("{head}: dropped by the screen (status {status}).");
    }
    let tail = format!(
        "It runs only automations that list the kind {}.",
        hooks_runner::TEST_KIND
    );
    match field("received").and_then(Value::as_str) {
        Some(id) => format!(
            "{head}: accepted as {} (status {status}). {tail}",
            sanitize(id, false)
        ),
        None => format!("{head}: accepted (status {status}). {tail}"),
    }
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
    fn the_documented_hmac_presets_take_the_right_secret() {
        let none = VerifyArgs::default();
        for p in [Preset::Calendly, Preset::Typeform, Preset::Twitch] {
            // The receiver chooses these secrets: the relay generates one when none is given.
            assert_eq!(
                verify_spec(p, &none).unwrap(),
                json!({ "preset": p.wire() })
            );
            assert_eq!(parse_preset(p.wire()), Some(p));
        }
        let given = VerifyArgs {
            secret: Some("s".into()),
            ..Default::default()
        };
        for p in [Preset::Paddle, Preset::Zoom, Preset::Pagerduty] {
            assert!(
                verify_spec(p, &none)
                    .unwrap_err()
                    .message
                    .contains("--secret-stdin")
            );
            assert_eq!(
                verify_spec(p, &given).unwrap(),
                json!({ "preset": p.wire(), "secret": "s" })
            );
            assert_eq!(parse_preset(p.wire()), Some(p));
        }
        let strict = VerifyArgs {
            secret: Some("s".into()),
            strict: true,
            ..Default::default()
        };
        assert_eq!(
            verify_spec(Preset::Paddle, &strict).unwrap(),
            json!({"preset":"paddle","strict":true})
        );
        // Zoom's endpoint check needs the secret at the relay.
        assert!(
            verify_spec(Preset::Zoom, &strict)
                .unwrap_err()
                .message
                .contains("can't be strict")
        );
    }

    #[test]
    fn a_token_hook_cannot_be_strict() {
        let a = VerifyArgs {
            secret: Some("tok".into()),
            strict: true,
            ..Default::default()
        };
        assert!(
            verify_spec(Preset::Token, &a)
                .unwrap_err()
                .message
                .contains("can't be strict")
        );
    }

    fn hook(verify: Value) -> Hook {
        serde_json::from_value(json!({
            "id": "hk_1", "name": "n", "url": "https://r.example/h/hk_1", "enabled": true,
            "verify": verify, "maxBodyBytes": 1, "createdAt": 0, "lastEventAt": null
        }))
        .unwrap()
    }

    #[test]
    fn the_strict_spec_kept_is_built_here_never_copied_from_the_relay() {
        // What the person says wins, and must agree with the relay's preset.
        let h = hook(json!({"preset": "hmac", "header": "X-Relay", "strict": true}));
        let said = SecretArgs {
            preset: Some(Preset::Hmac),
            header: Some("X-Sig".into()),
            ..Default::default()
        };
        let (v, from_relay) = strict_spec(&h, &said, Some("s".into()), None).unwrap();
        assert!(!from_relay);
        assert_eq!(v["header"], "X-Sig");
        assert!(v.get("secret").is_none());
        let wrong = SecretArgs {
            preset: Some(Preset::Github),
            ..Default::default()
        };
        assert!(
            strict_spec(&h, &wrong, Some("s".into()), None)
                .unwrap_err()
                .message
                .contains("you said github")
        );
        // From the relay's description: rebuilt through the same checks, its other fields
        // (a planted public key, say) dropped, and flagged for confirmation.
        let h = hook(json!({"preset": "github", "strict": true,
                            "publicKey": "whpk_planted", "header": "X"}));
        let (v, from_relay) =
            strict_spec(&h, &SecretArgs::default(), Some("s".into()), None).unwrap();
        assert!(from_relay);
        assert_eq!(v, json!({"preset": "github", "strict": true}));
        // A relay that says the hook is unverified or token gets nothing kept.
        for p in ["unverified", "token"] {
            let h = hook(json!({"preset": p, "strict": true}));
            assert!(strict_spec(&h, &SecretArgs::default(), Some("s".into()), None).is_err());
        }
        // The Ed25519 key is the person's, never the relay's.
        let h = hook(
            json!({"preset": "standard-webhooks-ed25519", "strict": true,
                            "publicKey": "whpk_relay"}),
        );
        let (v, _) =
            strict_spec(&h, &SecretArgs::default(), None, Some("whpk_mine".into())).unwrap();
        let e = strict_entry(v, "whpk_mine".into(), Some("whpk_mine"), None);
        assert_eq!(e.verify["publicKey"], "whpk_mine");
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
    fn a_static_answer_is_checked_before_it_is_sent() {
        assert!(response_spec(200, "text/plain", "ok".into()).is_ok());
        assert!(response_spec(299, "text/xml", "<x/>".into()).is_ok());
        assert!(
            response_spec(302, "text/plain", "".into())
                .unwrap_err()
                .message
                .contains("200 to 299")
        );
        assert!(
            response_spec(200, "text/html", "".into())
                .unwrap_err()
                .message
                .contains("application/json")
        );
        assert!(response_spec(200, "text/plain", "x".repeat(4096)).is_ok());
        assert!(response_spec(200, "text/plain", "x".repeat(4097)).is_err());
    }

    #[test]
    fn a_test_delivery_is_described() {
        let t = |status: u16, answer: Value| TestSent {
            status,
            answer: (!answer.is_null()).then_some(answer),
            event_type: "00hooks.test".into(),
        };
        assert_eq!(
            describe_test("ci", &t(200, json!({"received": "evt_1"}))),
            "Sent a signed test event to ci: accepted as evt_1 (status 200). It runs only \
             automations that list the kind 00hooks.test."
        );
        assert!(describe_test("ci", &t(200, json!({"duplicate": true}))).contains("duplicate"));
        assert!(describe_test("ci", &t(200, json!({"held": true}))).contains("held by the screen"));
        assert!(describe_test("ci", &t(200, json!({"dropped": true}))).contains("dropped"));
        assert!(describe_test("ci", &t(202, Value::Null)).contains("accepted (status 202)"));
        assert_eq!(
            describe_test(
                "ci",
                &t(429, json!({"error": "quota", "message": "full\u{1b}[2J"}))
            ),
            "Sent a signed test event to ci: refused with status 429: full[2J."
        );
    }

    #[test]
    fn hooks_show_where_they_deliver_and_what_they_answer() {
        let mut h = hook(json!({"preset": "github"}));
        let text = describe(&h);
        assert!(text.contains("every device") && text.contains("the default"));
        h.deliver_to = Some("dev_2".into());
        h.response = Some(HookResponse {
            status: 200,
            content_type: "text/xml".into(),
            body: "<Response/>".into(),
        });
        let text = describe(&h);
        assert!(
            text.contains("dev_2") && text.contains("200 text/xml, 11 B"),
            "{text}"
        );
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
