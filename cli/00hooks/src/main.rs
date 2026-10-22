//! `00hooks`: webhooks from anywhere, delivered to this computer.

mod account;
mod apikeys;
mod audit;
mod automate;
mod ctx;
mod doctor;
mod hooks;
mod listen;
mod output;
mod quarantine;
mod relay;
mod screen;
mod service;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::ctx::CliResult;
use crate::hooks::{Algorithm, Encoding, Preset, VerifyArgs};

#[derive(Parser)]
#[command(
    name = "00hooks",
    version,
    about = "Webhooks from anywhere, delivered to this computer in real time.",
    after_help = "State lives in HOOKS_HOME (default: your user data folder). \
                  HOOKS_KEYSTORE=file keeps the device key in a private file instead of the keychain."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Log this computer in: create an account, or join one with a code.
    Login {
        /// The relay's address, for example https://relay.example.com.
        #[arg(long, env = "HOOKS_RELAY")]
        relay: Option<String>,
        /// A name for this computer in the device list (default: its hostname).
        #[arg(long)]
        name: Option<String>,
        /// The relay's signup token, when it requires one.
        #[arg(
            long,
            env = "HOOKS_SIGNUP_TOKEN",
            hide_env_values = true,
            conflicts_with_all = ["code", "code_stdin"]
        )]
        signup_token: Option<String>,
        /// Join an existing account with a code from `00hooks devices add`. You're asked for the
        /// code (it's read from stdin when that isn't a terminal); it's never taken from the
        /// command line, where shell history and the process list would keep it.
        #[arg(long, conflicts_with = "code_stdin")]
        code: bool,
        /// Join an existing account with a code read from stdin.
        #[arg(long)]
        code_stdin: bool,
        /// Replace an existing login on this computer (and revoke its old device when it can).
        #[arg(long)]
        force: bool,
        /// Anything else: a code typed after --code lands here, and is refused with the reason.
        #[arg(hide = true)]
        stray: Vec<String>,
    },
    /// List, add or revoke the devices on this account.
    Devices {
        #[command(subcommand)]
        cmd: Option<DevicesCmd>,
    },
    /// Create and manage hooks.
    Hooks {
        #[command(subcommand)]
        cmd: HooksCmd,
    },
    /// Create, list or revoke API keys (for management and CI; never the stream).
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// What happened on the account: hooks, devices and keys changed, keys used, signatures
    /// refused. Names and ids only.
    Audit {
        /// At most this many entries (newest first; default 100).
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        json: bool,
    },
    /// Stream events to the terminal.
    Listen {
        /// Print each event as a JSON line on stdout (human lines stay on stderr).
        #[arg(long)]
        json: bool,
        /// Show only this hook (id or name); repeat for several.
        #[arg(long = "hook", value_name = "HOOK")]
        hooks: Vec<String>,
    },
    /// Check the key, the clock, the relay and the stream.
    Doctor,
    /// What the relay says about itself: version, protocols, key, signup, clock, push, screen.
    Relay {
        #[command(subcommand)]
        cmd: RelayCmd,
    },
    /// Have the relay send a hook a signed test event (kind 00hooks.test), and say what it got.
    /// Only automations that list the kind 00hooks.test run on it.
    Test {
        /// The hook (id or name).
        hook: String,
        #[arg(long)]
        json: bool,
    },
    /// Listen and run automations from automations.yaml, until stopped.
    Run {
        /// The automations file (default: ~/.config/00hooks/automations.yaml).
        #[arg(long, env = "HOOKS_AUTOMATIONS", value_name = "FILE")]
        automations: Option<PathBuf>,
    },
    /// Check automations.yaml, or resume an automation the circuit breaker paused.
    Automations {
        #[command(subcommand)]
        cmd: AutomationsCmd,
    },
    /// The event catalogue: every kind of event seen, with its fields.
    Kinds {
        #[command(subcommand)]
        cmd: Option<KindsCmd>,
        /// One JSON line per kind.
        #[arg(long)]
        json: bool,
    },
    /// Recent automation runs.
    Runs {
        /// How many (the newest).
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Only the runs of this event (id or seq), with every action's result.
        #[arg(long)]
        event: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Run a recorded event again (by id or seq), against the current automations.
    Replay {
        event: String,
        #[arg(long, env = "HOOKS_AUTOMATIONS", value_name = "FILE")]
        automations: Option<PathBuf>,
    },
    /// Open batches (automations with `batch:`): how many events each holds and when it runs.
    Batches {
        #[command(subcommand)]
        cmd: Option<BatchesCmd>,
        /// One JSON line per open batch.
        #[arg(long)]
        json: bool,
        #[arg(long, env = "HOOKS_AUTOMATIONS", value_name = "FILE", global = true)]
        automations: Option<PathBuf>,
    },
    /// Run `00hooks run` at login (launchd on macOS, systemd --user on Linux).
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Secrets that a call's headers use as {{secret.NAME}}, kept in the keychain.
    Secrets {
        #[command(subcommand)]
        cmd: SecretsCmd,
    },
    /// The screen: a firewall that decides what happens to each event before any automation sees
    /// it (pass, hold for you, or drop), here and at the relay.
    Screen {
        #[command(subcommand)]
        cmd: Option<ScreenCmd>,
    },
    /// Events that arrived but couldn't be read or opened.
    Quarantine {
        #[command(subcommand)]
        cmd: Option<QuarantineCmd>,
    },
}

#[derive(Subcommand)]
enum RelayCmd {
    /// GET /v1/info of the relay this computer is logged in to (or --relay), and what it means here.
    Status {
        /// Another relay's address.
        #[arg(long)]
        relay: Option<String>,
        /// Print the relay's answer as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum QuarantineCmd {
    /// What is in the quarantine, and why (the default).
    List {
        #[arg(long)]
        json: bool,
    },
    /// Open again the events that waited for something this computer lacked (a strict hook's
    /// secret, a sealing key, a locked keychain); those that open now run on the next start.
    Retry,
}

#[derive(Subcommand)]
enum ScreenCmd {
    /// Whether it's on, and how many rules and held items there are.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Screen every webhook before automations run.
    On {
        /// Also ask the AI evaluator (set it up in the screen's settings.json) about what rules
        /// don't settle.
        #[arg(long)]
        evaluate: bool,
    },
    /// Stop screening.
    Off,
    /// What is held, here and at the relay.
    Held {
        #[arg(long)]
        json: bool,
    },
    /// Run a held event now (hld_…), or have the relay stream one it held (evt_…).
    Release {
        id: String,
        #[arg(long, env = "HOOKS_AUTOMATIONS", value_name = "FILE")]
        automations: Option<PathBuf>,
    },
    /// Drop a held event.
    Drop {
        id: String,
        /// Also drop everything similar from now on (a learned rule, kept as a fingerprint).
        #[arg(long)]
        always: bool,
    },
    /// The rules, with what they matched and when.
    Rules {
        #[arg(long)]
        json: bool,
    },
    /// Send the rules marked for the edge to the relay (field values as keyed hashes).
    Sync,
}

#[derive(Subcommand)]
enum AutomationsCmd {
    /// Validate the file, and check its kinds and fields against the event catalogue.
    Check {
        #[arg(long, env = "HOOKS_AUTOMATIONS", value_name = "FILE")]
        automations: Option<PathBuf>,
        /// Fail on warnings too.
        #[arg(long)]
        strict: bool,
    },
    /// Lift the pause the circuit breaker put on an automation.
    Resume { name: String },
}

#[derive(Subcommand)]
enum BatchesCmd {
    /// List the open batches (the default).
    List,
    /// Run an automation's open batch now.
    Flush { automation: String },
    /// Throw an automation's open batch away; its events don't run.
    Drop {
        automation: String,
        /// Don't ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum KindsCmd {
    /// List the kinds (the default).
    List,
    /// One kind's field tree, with sample values and the values seen.
    Show {
        /// hook/kind (hook name or id), or a kind only one hook has.
        kind: String,
        #[arg(long)]
        json: bool,
    },
    /// Clear one kind's sample and values seen, or forget every kind.
    Clear {
        kind: Option<String>,
        /// Forget every kind: structure, samples and values.
        #[arg(long, conflicts_with = "kind")]
        all: bool,
        /// Forget this kind entirely instead of only its sample and values.
        #[arg(long, requires = "kind")]
        forget: bool,
    },
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Install and start the service.
    Install {
        #[arg(long, env = "HOOKS_AUTOMATIONS", value_name = "FILE")]
        automations: Option<PathBuf>,
        /// Print the service file instead of installing it.
        #[arg(long)]
        print: bool,
    },
    /// Stop and remove the service.
    Uninstall,
    /// Whether it's installed and running.
    Status,
}

#[derive(Subcommand)]
enum SecretsCmd {
    /// Save a secret; the value is read from stdin (pipe it in).
    Set { name: String },
    /// Delete a secret.
    Delete { name: String },
}

#[derive(Subcommand)]
enum DevicesCmd {
    /// List the devices (the default).
    List,
    /// Print a one-time code for adding another computer.
    Add,
    /// Revoke a device: its stream closes and its key stops working.
    Revoke {
        id: String,
        /// Don't refuse when it's this computer's own device.
        #[arg(long)]
        yes: bool,
    },
    /// Give this computer a new sealing key (a login from before sealing has none).
    SealKey,
    /// Rename a device (by id or current name).
    Rename {
        device: String,
        /// The new name (1 to 100 characters).
        name: String,
    },
    /// Add tags to a device, so hooks delivered to a tag (`hooks deliver-to --tag`) reach it.
    Tag {
        device: String,
        /// Short labels: lowercase letters, digits, '.', '_' and '-'.
        #[arg(required = true)]
        tags: Vec<String>,
    },
    /// Remove tags from a device (or --all of them).
    Untag {
        device: String,
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        tags: Vec<String>,
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Create a key; prints its token once.
    Create {
        #[arg(long)]
        name: String,
        /// What the key may do; repeat for several.
        #[arg(long = "scope", value_enum, required = true)]
        scopes: Vec<apikeys::Scope>,
        /// Days until it expires (1 to 365; default 90).
        #[arg(long)]
        expires_in_days: Option<u32>,
        #[arg(long)]
        json: bool,
    },
    /// List the keys (never their tokens).
    List {
        #[arg(long)]
        json: bool,
    },
    /// Revoke a key: it stops working at once.
    Revoke { id: String },
}

#[derive(Subcommand)]
enum HooksCmd {
    /// Create a hook; prints its URL and, once, its secret.
    Create {
        #[arg(long)]
        name: String,
        /// How the relay checks that events are genuine.
        #[arg(long, value_enum)]
        preset: Preset,
        /// hmac: the signature header. token: the header carrying the token (default Authorization).
        #[arg(long)]
        header: Option<String>,
        /// hmac: the HMAC hash (default sha256).
        #[arg(long, value_enum)]
        algorithm: Option<Algorithm>,
        /// hmac: how the signature is written (default hex).
        #[arg(long, value_enum)]
        encoding: Option<Encoding>,
        /// hmac: text before the signature, such as `sha256=`.
        #[arg(long)]
        prefix: Option<String>,
        /// Read the sender's existing secret from stdin instead of letting the relay generate one.
        /// Required for stripe, slack, linear, shopify, twilio, meta (the app secret), paddle, zoom
        /// and pagerduty, which issue their own.
        #[arg(long)]
        secret_stdin: bool,
        /// standard-webhooks-ed25519: the sender's public key (whpk_…). Not a secret.
        #[arg(long)]
        public_key: Option<String>,
        /// Verify on this computer: the secret never goes to the relay, which checks only the
        /// signature header's shape and timestamp. Other computers need the secret too
        /// (`00hooks hooks secret`).
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        json: bool,
    },
    /// Keep a strict hook's secret on this computer (from stdin), so it can verify its events.
    /// Say how it's signed with --preset (and its options), as at create; without it, the relay's
    /// description is shown and has to be confirmed.
    Secret {
        hook: String,
        #[arg(long, conflicts_with = "public_key")]
        secret_stdin: bool,
        /// standard-webhooks-ed25519: the sender's public key.
        #[arg(long)]
        public_key: Option<String>,
        /// How the sender signs: the preset the hook was created with.
        #[arg(long, value_enum)]
        preset: Option<Preset>,
        /// hmac: the signature header.
        #[arg(long, requires = "preset")]
        header: Option<String>,
        /// hmac: the HMAC hash (default sha256).
        #[arg(long, value_enum, requires = "preset")]
        algorithm: Option<Algorithm>,
        /// hmac: how the signature is written (default hex).
        #[arg(long, value_enum, requires = "preset")]
        encoding: Option<Encoding>,
        /// hmac: text before the signature, such as `sha256=`.
        #[arg(long, requires = "preset")]
        prefix: Option<String>,
        /// Without --preset: accept the relay's description of the hook without asking.
        #[arg(long)]
        yes: bool,
    },
    /// List hooks.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show one hook (by id or name).
    Show {
        hook: String,
        #[arg(long)]
        json: bool,
    },
    /// Make a new secret; the old one keeps working for 24 hours.
    Rotate { hook: String },
    /// Stop accepting events (the URL answers 404).
    Pause { hook: String },
    /// Accept events again.
    Resume { hook: String },
    /// Deliver a hook's events only to some devices (by id or name) and/or the devices carrying a
    /// tag, so its automations run on those computers alone; --all delivers them to every device
    /// again.
    DeliverTo {
        hook: String,
        /// Devices, by id or name (up to 10).
        #[arg(conflicts_with = "all")]
        devices: Vec<String>,
        /// Devices carrying this tag (`00hooks devices tag`); repeat for several.
        #[arg(long = "tag", value_name = "TAG", conflicts_with = "all")]
        tags: Vec<String>,
        #[arg(long)]
        all: bool,
    },
    /// Set the static answer the relay gives the provider for each accepted delivery, or --clear it.
    Response {
        hook: String,
        /// 200 to 299, but not 204 or 205.
        #[arg(long, required_unless_present = "clear", conflicts_with = "clear")]
        status: Option<u16>,
        /// text/plain, application/json, application/xml or text/xml.
        #[arg(long, required_unless_present = "clear", conflicts_with = "clear")]
        content_type: Option<String>,
        /// The body (at most 4096 bytes).
        #[arg(long, conflicts_with_all = ["body_file", "clear"])]
        body: Option<String>,
        /// Read the body from this file.
        #[arg(long, value_name = "PATH", conflicts_with = "clear")]
        body_file: Option<PathBuf>,
        /// Answer with the default again.
        #[arg(long)]
        clear: bool,
    },
    /// Delete a hook.
    Delete {
        hook: String,
        /// Don't ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

async fn dispatch(cmd: Cmd) -> CliResult {
    match cmd {
        Cmd::Login {
            relay,
            name,
            signup_token,
            code,
            code_stdin,
            force,
            stray,
        } => {
            if !stray.is_empty() {
                // Never echo it: it may be an enrolment code.
                return Err(ctx::Failure::new(
                    "`00hooks login` takes no values without an option, and the enrolment code \
                     never goes on the command line: shell history and the process list would \
                     keep it. Run `00hooks login --relay <URL> --code` and type it when asked, or \
                     pipe it in with --code-stdin.",
                ));
            }
            let code = match (code, code_stdin) {
                (true, _) => account::CodeSource::Ask,
                (false, true) => account::CodeSource::Stdin,
                (false, false) => account::CodeSource::None,
            };
            account::login(account::Login {
                relay,
                name,
                signup_token,
                code,
                force,
            })
            .await
        }
        Cmd::Devices { cmd } => match cmd.unwrap_or(DevicesCmd::List) {
            DevicesCmd::List => account::devices_list().await,
            DevicesCmd::Add => account::devices_add().await,
            DevicesCmd::Revoke { id, yes } => account::devices_revoke(id, yes).await,
            DevicesCmd::SealKey => account::devices_seal_key().await,
            DevicesCmd::Rename { device, name } => account::devices_rename(device, name).await,
            DevicesCmd::Tag { device, tags } => account::devices_tag(device, tags).await,
            DevicesCmd::Untag { device, tags, all } => {
                account::devices_untag(device, tags, all).await
            }
        },
        Cmd::Keys { cmd } => match cmd {
            KeysCmd::Create {
                name,
                scopes,
                expires_in_days,
                json,
            } => apikeys::create(name, scopes, expires_in_days, json).await,
            KeysCmd::List { json } => apikeys::list(json).await,
            KeysCmd::Revoke { id } => apikeys::revoke(id).await,
        },
        Cmd::Audit { limit, json } => audit::run(limit, json).await,
        Cmd::Hooks { cmd } => match cmd {
            HooksCmd::Create {
                name,
                preset,
                header,
                algorithm,
                encoding,
                prefix,
                secret_stdin,
                public_key,
                strict,
                json,
            } => {
                let secret = if secret_stdin {
                    Some(hooks::read_secret_stdin()?)
                } else {
                    None
                };
                let args = VerifyArgs {
                    header,
                    algorithm,
                    encoding,
                    prefix,
                    secret,
                    public_key,
                    strict,
                };
                hooks::create(name, preset, args, json).await
            }
            HooksCmd::Secret {
                hook,
                secret_stdin,
                public_key,
                preset,
                header,
                algorithm,
                encoding,
                prefix,
                yes,
            } => {
                let secret = if secret_stdin {
                    Some(hooks::read_secret_stdin()?)
                } else {
                    None
                };
                let args = hooks::SecretArgs {
                    preset,
                    header,
                    algorithm,
                    encoding,
                    prefix,
                    yes,
                };
                hooks::secret(hook, secret, public_key, args).await
            }
            HooksCmd::List { json } => hooks::list(json).await,
            HooksCmd::Show { hook, json } => hooks::show(hook, json).await,
            HooksCmd::Rotate { hook } => hooks::rotate(hook).await,
            HooksCmd::Pause { hook } => hooks::set_enabled(hook, false).await,
            HooksCmd::Resume { hook } => hooks::set_enabled(hook, true).await,
            HooksCmd::Delete { hook, yes } => hooks::delete(hook, yes).await,
            HooksCmd::DeliverTo {
                hook,
                devices,
                tags,
                all,
            } => hooks::deliver_to(hook, devices, tags, all).await,
            HooksCmd::Response {
                hook,
                status,
                content_type,
                body,
                body_file,
                clear,
            } => {
                if clear {
                    return hooks::set_response(hook, None).await;
                }
                let body = match (body, body_file) {
                    (Some(b), None) => b,
                    (None, Some(p)) => std::fs::read_to_string(&p).map_err(|e| {
                        ctx::Failure::new(format!(
                            "Couldn't read {} as UTF-8 text: {e}.",
                            p.display()
                        ))
                    })?,
                    _ => {
                        return Err(ctx::Failure::new(
                            "Give the answer's body with --body TEXT or --body-file PATH \
                             (--body \"\" for an empty one).",
                        ));
                    }
                };
                let r = hooks::response_spec(
                    status.unwrap_or_default(),
                    content_type.as_deref().unwrap_or_default(),
                    body,
                )?;
                hooks::set_response(hook, Some(r)).await
            }
        },
        Cmd::Listen { json, hooks } => listen::run(json, hooks).await,
        Cmd::Doctor => doctor::run().await,
        Cmd::Relay { cmd } => match cmd {
            RelayCmd::Status { relay: r, json } => relay::status(r, json).await,
        },
        Cmd::Test { hook, json } => hooks::test(hook, json).await,
        Cmd::Run { automations } => automate::run(automations).await,
        Cmd::Automations { cmd } => match cmd {
            AutomationsCmd::Check {
                automations,
                strict,
            } => automate::check(automations, strict),
            AutomationsCmd::Resume { name } => automate::resume(name),
        },
        Cmd::Kinds { cmd, json } => match cmd.unwrap_or(KindsCmd::List) {
            KindsCmd::List => automate::kinds(json),
            KindsCmd::Show { kind, json: j } => automate::kinds_show(kind, json || j),
            KindsCmd::Clear { kind, all, forget } => automate::kinds_clear(kind, all, forget),
        },
        Cmd::Runs { limit, event, json } => automate::runs(limit, event, json),
        Cmd::Replay { event, automations } => automate::replay(event, automations).await,
        Cmd::Batches {
            cmd,
            json,
            automations,
        } => match cmd.unwrap_or(BatchesCmd::List) {
            BatchesCmd::List => automate::batches(automations, json),
            BatchesCmd::Flush { automation } => {
                automate::batches_flush(automation, automations).await
            }
            BatchesCmd::Drop { automation, yes } => {
                automate::batches_drop(automation, yes, automations).await
            }
        },
        Cmd::Service { cmd } => match cmd {
            ServiceCmd::Install { automations, print } => service::install(automations, print),
            ServiceCmd::Uninstall => service::uninstall(),
            ServiceCmd::Status => service::status(),
        },
        Cmd::Screen { cmd } => match cmd.unwrap_or(ScreenCmd::Status { json: false }) {
            ScreenCmd::Status { json } => screen::status(json),
            ScreenCmd::On { evaluate } => screen::set_on(true, evaluate),
            ScreenCmd::Off => screen::set_on(false, false),
            ScreenCmd::Held { json } => screen::held(json).await,
            ScreenCmd::Release { id, automations } => screen::release(id, automations).await,
            ScreenCmd::Drop { id, always } => screen::drop(id, always).await,
            ScreenCmd::Rules { json } => screen::rules(json),
            ScreenCmd::Sync => screen::sync().await,
        },
        Cmd::Quarantine { cmd } => match cmd.unwrap_or(QuarantineCmd::List { json: false }) {
            QuarantineCmd::List { json } => quarantine::list(json),
            QuarantineCmd::Retry => quarantine::retry(),
        },
        Cmd::Secrets { cmd } => match cmd {
            SecretsCmd::Set { name } => automate::secrets_set(name),
            SecretsCmd::Delete { name } => automate::secrets_delete(name),
        },
    }
}

fn main() {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(f) = runtime.block_on(dispatch(cli.cmd)) {
        if !f.message.is_empty() {
            // Every failure is printed through `sanitize`: some carry text from the relay.
            eprintln!("{}", output::sanitize(&f.message, true));
        }
        std::process::exit(f.code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn signup_token_and_code_are_exclusive() {
        let r = Cli::try_parse_from(["00hooks", "login", "--signup-token", "t", "--code"]);
        assert!(r.is_err());
        let r = Cli::try_parse_from(["00hooks", "login", "--signup-token", "t", "--code-stdin"]);
        assert!(r.is_err());
        let r = Cli::try_parse_from(["00hooks", "login", "--code", "--code-stdin"]);
        assert!(r.is_err());
    }

    #[test]
    fn code_is_a_flag_and_a_value_is_refused() {
        let cli = Cli::try_parse_from(["00hooks", "login", "--code"]).unwrap();
        match cli.cmd {
            Cmd::Login { code, stray, .. } => assert!(code && stray.is_empty()),
            _ => panic!(),
        }
        // A value still parses, so dispatch can say why it's refused instead of a usage error.
        let cli = Cli::try_parse_from(["00hooks", "login", "--code", "ABCD-EFGH-JKMN"]).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = runtime.block_on(dispatch(cli.cmd)).unwrap_err();
        assert!(err.message.contains("--code-stdin"), "{}", err.message);
        assert!(!err.message.contains("ABCD"), "{}", err.message);
    }

    #[test]
    fn listen_takes_several_hooks() {
        let cli =
            Cli::try_parse_from(["00hooks", "listen", "--json", "--hook", "a", "--hook", "b"])
                .unwrap();
        match cli.cmd {
            Cmd::Listen { json, hooks } => {
                assert!(json);
                assert_eq!(hooks, vec!["a", "b"]);
            }
            _ => panic!(),
        }
    }
}
