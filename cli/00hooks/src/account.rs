//! `00hooks login` and `00hooks devices`.

use std::io::{BufRead, IsTerminal};

use hooks_client::api::{check_id, system_now_ms};
use hooks_client::{
    Client, Config, DeviceInfo, DeviceKey, Error, KeychainStore, PROTOCOL_VERSION, SealKey,
    StateDir,
};

use crate::ctx::{
    CliResult, Ctx, Failure, explain, key_store, open_state, preferred_key_store, sentence,
};
use crate::output::{date_time, sanitize, table};

/// Where an enrolment code comes from: never the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeSource {
    /// Not joining: create an account.
    None,
    /// Ask on the terminal, or read stdin when it isn't one.
    Ask,
    /// Read stdin.
    Stdin,
}

pub struct Login {
    pub relay: Option<String>,
    pub name: Option<String>,
    pub signup_token: Option<String>,
    pub code: CodeSource,
    pub force: bool,
}

/// Read one line: the enrolment code.
fn read_code(source: CodeSource) -> CliResult<String> {
    let stdin = std::io::stdin();
    if source == CodeSource::Ask && stdin.is_terminal() {
        eprint!("Enrolment code (from `00hooks devices add` on the other computer): ");
    }
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .map_err(|e| Failure::new(format!("Couldn't read the enrolment code: {e}.")))?;
    let code = line.trim().to_string();
    if code.is_empty() {
        return Err(Failure::new(
            "No enrolment code given. Run `00hooks devices add` on a computer that's logged in, \
             then type the code when asked, or pipe it in with --code-stdin.",
        ));
    }
    Ok(code)
}

/// Revoke the device a previous login on this computer used, signed with its own key. Best effort:
/// the reason it couldn't, in plain words, otherwise.
async fn revoke_previous(old: &Config, state: &StateDir) -> Result<(), String> {
    let store = key_store(&old.key_store, state);
    let key = match DeviceKey::load(store.as_ref(), &old.key_name) {
        Ok(Some(k)) => k,
        Ok(None) => return Err(format!("its key is no longer in {}", store.describe())),
        Err(e) => return Err(format!("its key couldn't be read ({e})")),
    };
    let client = Client::with_device(&old.relay, &old.device_id, key).map_err(|e| e.to_string())?;
    match client.revoke_device(&old.device_id).await {
        Ok(()) => Ok(()),
        Err(e) if e.is_unauthorized() => {
            Err("the relay already refuses it (it was revoked, or its key doesn't match)".into())
        }
        Err(Error::Network(detail)) => Err(format!(
            "the relay at {} can't be reached ({detail})",
            old.relay
        )),
        Err(e) => Err(e.to_string()),
    }
}

/// This computer's name, for the device list.
fn default_device_name() -> String {
    let from_cmd = std::process::Command::new("hostname")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let name = from_cmd
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_default();
    let name = sanitize(name.trim_end_matches(".local"), false);
    if name.is_empty() {
        "this computer".into()
    } else {
        name
    }
}

fn random_key_name() -> CliResult<String> {
    let nonce = hooks_client::signing::new_nonce().map_err(|e| Failure::new(e.to_string()))?;
    let safe: String = nonce
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { 'x' })
        .collect();
    Ok(format!("device-{safe}"))
}

/// A refused account creation or redemption. A `401` there is never about this device (it doesn't
/// exist yet): it is the signup token, or the enrolment code.
fn explain_join(e: Error, relay: &str, joining: bool) -> Failure {
    match &e {
        Error::Api {
            status: 401, code, ..
        } if code != "clock_skew" => Failure::new(if joining {
            "That enrolment code is wrong, used or expired. Run `00hooks devices add` on a \
             computer that's logged in for a new one."
        } else {
            "This relay needs a signup token to create an account. Pass --signup-token or set \
             HOOKS_SIGNUP_TOKEN."
        }),
        _ => explain(e, relay),
    }
}

pub async fn login(args: Login) -> CliResult {
    let state = open_state()?;
    let existing = state
        .load_config()
        .map_err(|e| Failure::new(e.to_string()))?;
    if let (Some(c), false) = (&existing, args.force) {
        return Err(Failure::new(format!(
            "This computer is already logged in as {} ({}) on {}. Run `00hooks login --force` \
             to replace that login.",
            sanitize(&c.device_name, false),
            c.device_id,
            c.relay
        )));
    }
    let relay = args
        .relay
        .clone()
        .or_else(|| existing.as_ref().map(|c| c.relay.clone()))
        .ok_or_else(|| {
            Failure::new(
                "Pass --relay with your relay's address, for example \
                 `00hooks login --relay https://relay.example.com`.",
            )
        })?;
    let anon = Client::new(&relay).map_err(|e| Failure::new(e.to_string()))?;
    let info = anon.info().await.map_err(|e| explain(e, &relay))?;
    if !info.serves(PROTOCOL_VERSION) {
        return Err(Failure::new(format!(
            "The relay at {relay} speaks protocol {}, and this 00hooks speaks {PROTOCOL_VERSION}. \
             Update {}.",
            info.protocol,
            if info.protocol > PROTOCOL_VERSION {
                "00hooks"
            } else {
                "the relay"
            }
        )));
    }
    // Every envelope is checked against this key from now on (PROTOCOL §2, §5).
    let relay_key = pinnable_relay_key(&info, &relay)?;
    let joining = args.code != CodeSource::None;
    if !joining && args.signup_token.is_none() && !info.signup_open {
        return Err(Failure::new(
            "This relay needs a signup token to create an account. Pass --signup-token (or set \
             HOOKS_SIGNUP_TOKEN), or join an existing account with --code from \
             `00hooks devices add` on a computer that's already logged in.",
        ));
    }

    let code = if joining {
        Some(read_code(args.code)?)
    } else {
        None
    };

    let name = args.name.clone().unwrap_or_else(default_device_name);
    let key = DeviceKey::generate().map_err(|e| Failure::new(e.to_string()))?;
    let seal = SealKey::generate().map_err(|e| Failure::new(e.to_string()))?;
    let key_name = random_key_name()?;

    // Keep the key before telling the relay about it, so a device never exists without its key.
    let mut kind = preferred_key_store();
    let mut store = key_store(kind, &state);
    if let Err(e) = key.save(store.as_ref(), &key_name) {
        if kind != "keychain" || std::env::var("HOOKS_KEYSTORE").as_deref() == Ok("keychain") {
            return Err(Failure::new(format!("Couldn't save the device key: {e}.")));
        }
        eprintln!("The keychain isn't available ({e}); keeping the device key in a private file.");
        kind = "file";
        store = key_store(kind, &state);
        key.save(store.as_ref(), &key_name)
            .map_err(|e| Failure::new(format!("Couldn't save the device key: {e}.")))?;
    }
    if let Err(e) = seal.save(store.as_ref()) {
        let _ = store.delete(&key_name);
        return Err(Failure::new(format!("Couldn't save the sealing key: {e}.")));
    }

    let joined = match &code {
        Some(code) => {
            anon.redeem_enrolment(
                code.trim(),
                &name,
                &key.public_key(),
                Some(&seal.public_key()),
            )
            .await
        }
        None => {
            anon.create_account(
                &name,
                &key.public_key(),
                Some(&seal.public_key()),
                args.signup_token.as_deref(),
            )
            .await
        }
    };
    let joined = match joined {
        Ok(j) => j,
        Err(e) => {
            let _ = store.delete(&key_name);
            let _ = store.delete(&SealKey::store_name(&seal.kid()));
            return Err(explain_join(e, &relay, joining));
        }
    };
    check_id("dev_", &joined.device_id).map_err(|e| Failure::new(e.to_string()))?;

    if let Some(old) = &existing {
        // The previous device is abandoned: revoke it (signed with its own key) so it holds no
        // events back and its key is worth nothing, then forget the key here.
        match revoke_previous(old, &state).await {
            Ok(()) => eprintln!("Revoked this computer's previous device {}.", old.device_id),
            Err(why) => eprintln!(
                "Couldn't revoke this computer's previous device {}: {}. Revoke it from a \
                 computer logged in to that account: `00hooks devices revoke {}`.",
                old.device_id,
                sanitize(&why, false),
                old.device_id
            ),
        }
        let old_store = key_store(&old.key_store, &state);
        let _ = old_store.delete(&old.key_name);
        for kid in &old.seal_kids {
            let _ = old_store.delete(&SealKey::store_name(kid));
        }
    }
    state.reset().map_err(|e| Failure::new(e.to_string()))?;
    let config = Config {
        relay: anon.relay().to_string(),
        account_id: joined.account_id.clone(),
        device_id: joined.device_id.clone(),
        device_name: name.clone(),
        key_store: kind.to_string(),
        key_name,
        relay_key: Some(relay_key.clone()),
        seal_kids: vec![seal.kid()],
    };
    state
        .save_config(&config)
        .map_err(|e| Failure::new(e.to_string()))?;

    let how = if joining {
        "Joined account"
    } else {
        "Created account"
    };
    println!(
        "{how} {}. This computer is device {} ({}).",
        sanitize(&joined.account_id, false),
        joined.device_id,
        sanitize(&name, false)
    );
    eprintln!(
        "The device keys are kept in {}. Events are sealed to this computer's key {}, and \
         checked against the relay's key {relay_key}.",
        store.describe(),
        seal.kid()
    );
    if info.signup_open && !joining && args.signup_token.is_none() {
        eprintln!("Note: this relay lets anyone sign up; that's meant for development only.");
    }
    Ok(())
}

/// The relay key to pin from `/v1/info`; refuses a relay that can't sign envelopes.
fn pinnable_relay_key(info: &hooks_client::Info, relay: &str) -> CliResult<String> {
    let key = info.relay_key.clone().ok_or_else(|| {
        Failure::new(format!(
            "The relay at {relay} publishes no envelope-signing key (relayKey), so it can't \
             seal events. Its operator needs to set RELAY_SIGNING_KEY."
        ))
    })?;
    hooks_client::seal::parse_relay_key(&key)
        .map_err(|e| Failure::new(sentence(&e.to_string())))?;
    Ok(key)
}

/// `00hooks devices seal-key`: a new sealing key for this device (a login from before protocol 2
/// has none), registered with the relay. Older keys stay, so events sealed to them still open.
pub async fn devices_seal_key() -> CliResult {
    let mut ctx = Ctx::load()?;
    if ctx.config.relay_key.is_none() {
        let info = ctx.client.info().await.map_err(|e| ctx.explain(e))?;
        let key = pinnable_relay_key(&info, &ctx.config.relay)?;
        eprintln!(
            "This login predates sealing, so the relay's key is pinned now, as the relay \
             reports it: {key}. Compare it with what your relay's operator publishes."
        );
        ctx.config.relay_key = Some(key);
    }
    let store = key_store(&ctx.config.key_store, &ctx.state);
    let seal = SealKey::generate().map_err(|e| Failure::new(e.to_string()))?;
    seal.save(store.as_ref())
        .map_err(|e| Failure::new(format!("Couldn't save the sealing key: {e}.")))?;
    let kid = match ctx.client.set_seal_key(&seal.public_key()).await {
        Ok(kid) => kid,
        Err(e) => {
            let _ = store.delete(&SealKey::store_name(&seal.kid()));
            return Err(ctx.explain(e));
        }
    };
    if kid != seal.kid() {
        return Err(Failure::new(
            "The relay named the new sealing key differently than this computer does; not using it.",
        ));
    }
    ctx.config.seal_kids.push(kid.clone());
    ctx.state
        .save_config(&ctx.config)
        .map_err(|e| Failure::new(e.to_string()))?;
    println!("New events are sealed to this computer's key {kid}.");
    Ok(())
}

pub async fn devices_list() -> CliResult {
    let ctx = Ctx::load()?;
    let devices = ctx.client.devices().await.map_err(|e| ctx.explain(e))?;
    let mut rows = vec![vec![
        "NAME".to_string(),
        "ID".into(),
        "ADDED".into(),
        "LAST SEEN".into(),
        "SEALING KEY".into(),
    ]];
    for d in devices {
        let mut name = sanitize(&d.name, false);
        if d.current {
            name.push_str(" (this computer)");
        }
        rows.push(vec![
            name,
            sanitize(&d.id, false),
            date_time(d.created_at),
            d.last_seen_at
                .map(date_time)
                .unwrap_or_else(|| "never".into()),
            match &d.seal_kid {
                None if d.current => "none: run `00hooks devices seal-key`".into(),
                None => "none (gets gaps)".into(),
                Some(k) if d.current && !ctx.config.seal_kids.contains(k) => {
                    format!("{} (not on this computer)", sanitize(k, false))
                }
                Some(k) => sanitize(k, false),
            },
        ]);
    }
    print!("{}", table(&rows));
    Ok(())
}

pub async fn devices_add() -> CliResult {
    let ctx = Ctx::load()?;
    let e = ctx
        .client
        .create_enrolment()
        .await
        .map_err(|e| ctx.explain(e))?;
    let minutes = ((e.expires_at - system_now_ms()).max(0) + 30_000) / 60_000;
    let code = sanitize(&e.code, false);
    eprintln!(
        "One-time code, valid until {} (about {minutes} min):",
        date_time(e.expires_at)
    );
    println!("{code}");
    eprintln!(
        "On the other computer, run this and type the code when asked:\n  00hooks login --relay {} --code",
        ctx.config.relay
    );
    Ok(())
}

/// A device by id (`dev_…`) or by its exact current name.
pub async fn resolve_device(ctx: &Ctx, which: &str) -> CliResult<DeviceInfo> {
    let devices = ctx.client.devices().await.map_err(|e| ctx.explain(e))?;
    if which.starts_with("dev_") {
        return devices.into_iter().find(|d| d.id == which).ok_or_else(|| {
            Failure::new(format!(
                "No device {} on this account. Run `00hooks devices` to see them.",
                sanitize(which, false)
            ))
        });
    }
    let mut matches: Vec<DeviceInfo> = devices.into_iter().filter(|d| d.name == which).collect();
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(Failure::new(format!(
            "No device named {}. Run `00hooks devices` to see them.",
            sanitize(which, false)
        ))),
        _ => Err(Failure::new(format!(
            "More than one device is named {}; use its id (`00hooks devices`).",
            sanitize(which, false)
        ))),
    }
}

/// The longest device name, in characters (PROTOCOL §2).
const MAX_DEVICE_NAME: usize = 100;

pub async fn devices_rename(which: String, name: String) -> CliResult {
    let name = name.trim().to_string();
    let chars = name.chars().count();
    if chars == 0 || chars > MAX_DEVICE_NAME {
        return Err(Failure::new(format!(
            "A device name is 1 to {MAX_DEVICE_NAME} characters."
        )));
    }
    let ctx = Ctx::load()?;
    let d = resolve_device(&ctx, &which).await?;
    let old = sanitize(&d.name, false);
    let d = ctx
        .client
        .rename_device(&d.id, &name)
        .await
        .map_err(|e| ctx.explain(e))?;
    if d.id == ctx.config.device_id {
        // Keep the login's own record of its name in step.
        let mut config = ctx.config.clone();
        config.device_name = d.name.clone();
        ctx.state
            .save_config(&config)
            .map_err(|e| Failure::new(sentence(&e.to_string())))?;
    }
    println!("Renamed {old} ({}) to {}.", d.id, sanitize(&d.name, false));
    Ok(())
}

pub async fn devices_revoke(id: String, yes: bool) -> CliResult {
    let ctx = Ctx::load()?;
    check_id("dev_", &id)
        .map_err(|e| Failure::new(format!("{e}. Run `00hooks devices` to see ids.")))?;
    if id == ctx.config.device_id && !yes {
        return Err(Failure::new(
            "That's this computer's own device; revoking it logs this computer out. Pass --yes \
             if that's what you want.",
        ));
    }
    ctx.client
        .revoke_device(&id)
        .await
        .map_err(|e| ctx.explain(e))?;
    println!("Revoked {id}. Its stream closes now, and it can't sign requests any more.");
    Ok(())
}

/// Ask a yes/no question on the terminal. Refuses to guess when there is no terminal.
pub fn confirm(question: &str) -> CliResult<bool> {
    if !std::io::stdin().is_terminal() {
        return Err(Failure::new(
            "Not asking for confirmation without a terminal. Pass --yes to go ahead.",
        ));
    }
    eprint!("{question} Type yes to confirm: ");
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|e| Failure::new(e.to_string()))?;
    Ok(answer.trim().eq_ignore_ascii_case("yes"))
}

/// Whether this platform has a usable keychain (for `doctor`).
pub fn keychain_available() -> bool {
    KeychainStore::available()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(status: u16, code: &str) -> Error {
        Error::Api {
            status,
            code: code.into(),
            message: "Signing up on this relay needs its signup token.".into(),
            field: None,
        }
    }

    #[test]
    fn a_refused_signup_asks_for_the_token_not_a_new_login() {
        let f = explain_join(refused(401, "unauthorized"), "https://r.example", false);
        assert!(f.message.contains("signup token"), "{f}");
        assert!(f.message.contains("HOOKS_SIGNUP_TOKEN"), "{f}");
        assert!(!f.message.contains("--force"), "{f}");
        assert!(!f.message.contains("revoked"), "{f}");
    }

    #[test]
    fn a_refused_redemption_says_the_code_is_wrong() {
        let f = explain_join(refused(401, "unauthorized"), "https://r.example", true);
        assert!(f.message.contains("code is wrong, used or expired"), "{f}");
        assert!(!f.message.contains("--force"), "{f}");
    }

    #[test]
    fn other_refusals_keep_their_explanation() {
        let f = explain_join(refused(429, "rate_limited"), "https://r.example", true);
        assert!(f.message.contains("refused the request"), "{f}");
        let f = explain_join(Error::Network("down".into()), "https://r.example", false);
        assert!(f.message.contains("Couldn't reach"), "{f}");
    }
}
