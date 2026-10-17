//! `00hooks`: webhooks from anywhere, delivered to this computer.

mod account;
mod ctx;
mod doctor;
mod hooks;
mod listen;
mod output;

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
        #[arg(long)]
        secret_stdin: bool,
        #[arg(long)]
        json: bool,
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
        },
        Cmd::Hooks { cmd } => match cmd {
            HooksCmd::Create {
                name,
                preset,
                header,
                algorithm,
                encoding,
                prefix,
                secret_stdin,
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
                };
                hooks::create(name, preset, args, json).await
            }
            HooksCmd::List { json } => hooks::list(json).await,
            HooksCmd::Show { hook, json } => hooks::show(hook, json).await,
            HooksCmd::Rotate { hook } => hooks::rotate(hook).await,
            HooksCmd::Pause { hook } => hooks::set_enabled(hook, false).await,
            HooksCmd::Resume { hook } => hooks::set_enabled(hook, true).await,
            HooksCmd::Delete { hook, yes } => hooks::delete(hook, yes).await,
        },
        Cmd::Listen { json, hooks } => listen::run(json, hooks).await,
        Cmd::Doctor => doctor::run().await,
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
