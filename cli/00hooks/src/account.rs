//! `00hooks login` and `00hooks devices`.

use std::io::IsTerminal;

use hooks_client::api::{check_id, system_now_ms};
use hooks_client::{Client, Config, DeviceKey, KeychainStore, PROTOCOL_VERSION};

use crate::ctx::{CliResult, Ctx, Failure, explain, key_store, open_state, preferred_key_store};
use crate::output::{date_time, sanitize, table};

pub struct Login {
    pub relay: Option<String>,
    pub name: Option<String>,
    pub signup_token: Option<String>,
    pub code: Option<String>,
    pub force: bool,
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
    if info.protocol != PROTOCOL_VERSION {
        return Err(Failure::new(format!(
            "The relay at {relay} speaks protocol {}, and this 00hooks speaks {PROTOCOL_VERSION}. \
             Update 00hooks.",
            info.protocol
        )));
    }
    if args.code.is_none() && args.signup_token.is_none() && !info.signup_open {
        return Err(Failure::new(
            "This relay needs a signup token to create an account. Pass --signup-token (or set \
             HOOKS_SIGNUP_TOKEN), or join an existing account with --code from \
             `00hooks devices add` on a computer that's already logged in.",
        ));
    }

    let name = args.name.clone().unwrap_or_else(default_device_name);
    let key = DeviceKey::generate().map_err(|e| Failure::new(e.to_string()))?;
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

    let joined = match &args.code {
        Some(code) => {
            anon.redeem_enrolment(code.trim(), &name, &key.public_key())
                .await
        }
        None => {
            anon.create_account(&name, &key.public_key(), args.signup_token.as_deref())
                .await
        }
    };
    let joined = match joined {
        Ok(j) => j,
        Err(e) => {
            let _ = store.delete(&key_name);
            return Err(explain(e, &relay));
        }
    };
    check_id("dev_", &joined.device_id).map_err(|e| Failure::new(e.to_string()))?;

    if let Some(old) = &existing {
        // The old device's key is no longer needed here.
        let _ = key_store(&old.key_store, &state).delete(&old.key_name);
    }
    state.reset().map_err(|e| Failure::new(e.to_string()))?;
    let config = Config {
        relay: anon.relay().to_string(),
        account_id: joined.account_id.clone(),
        device_id: joined.device_id.clone(),
        device_name: name.clone(),
        key_store: kind.to_string(),
        key_name,
    };
    state
        .save_config(&config)
        .map_err(|e| Failure::new(e.to_string()))?;

    let how = if args.code.is_some() {
        "Joined account"
    } else {
        "Created account"
    };
    println!(
        "{how} {}. This computer is device {} ({}).",
        joined.account_id,
        joined.device_id,
        sanitize(&name, false)
    );
    eprintln!("The device key is kept in {}.", store.describe());
    if info.signup_open && args.code.is_none() && args.signup_token.is_none() {
        eprintln!("Note: this relay lets anyone sign up; that's meant for development only.");
    }
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
    ]];
    for d in devices {
        let mut name = sanitize(&d.name, false);
        if d.current {
            name.push_str(" (this computer)");
        }
        rows.push(vec![
            name,
            d.id,
            date_time(d.created_at),
            d.last_seen_at
                .map(date_time)
                .unwrap_or_else(|| "never".into()),
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
        "On the other computer, run:\n  00hooks login --relay {} --code {code}",
        ctx.config.relay
    );
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
