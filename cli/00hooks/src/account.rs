//! `00hooks login` and `00hooks devices`.

use std::io::{BufRead, IsTerminal};

use hooks_client::api::{check_id, system_now_ms};
use hooks_client::{Client, Config, DeviceKey, Error, KeychainStore, PROTOCOL_VERSION, StateDir};

use crate::ctx::{CliResult, Ctx, Failure, explain, key_store, open_state, preferred_key_store};
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

    let joined = match &code {
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
    eprintln!("The device key is kept in {}.", store.describe());
    if info.signup_open && !joining && args.signup_token.is_none() {
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
            sanitize(&d.id, false),
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
        "On the other computer, run this and type the code when asked:\n  00hooks login --relay {} --code",
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
