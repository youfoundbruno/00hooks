//! `00hooks doctor`: keys, clock, relay, signed requests, stream.

use std::time::Duration;

use hooks_client::api::system_now_ms;
use hooks_client::{DeviceKey, PROTOCOL_VERSION, describe_skew};

use crate::account::keychain_available;
use crate::ctx::{CliResult, Ctx, Failure, key_store, open_state, sentence};
use crate::output::sanitize;

struct Report {
    failed: bool,
}

impl Report {
    fn ok(&self, s: &str) {
        println!("ok    {s}");
    }
    fn warn(&self, s: &str) {
        println!("warn  {s}");
    }
    fn fail(&mut self, s: &str) {
        self.failed = true;
        println!("fail  {s}");
    }
}

pub async fn run() -> CliResult {
    let mut r = Report { failed: false };
    let state = open_state()?;
    r.ok(&format!("State directory: {}", state.path().display()));
    let config = match state.load_config() {
        Ok(Some(c)) => c,
        Ok(None) => {
            r.fail("Not logged in. Run `00hooks login --relay <URL>`.");
            return Err(Failure {
                message: String::new(),
                code: 1,
            });
        }
        Err(e) => {
            r.fail(&sentence(&e.to_string()));
            return Err(Failure {
                message: String::new(),
                code: 1,
            });
        }
    };
    r.ok(&format!(
        "Logged in as {} ({}) on {}.",
        sanitize(&config.device_name, false),
        config.device_id,
        config.relay
    ));

    // Keys.
    let store = key_store(&config.key_store, &state);
    match DeviceKey::load(store.as_ref(), &config.key_name) {
        Ok(Some(_)) => r.ok(&format!("Device key found in {}.", store.describe())),
        Ok(None) => r.fail(&format!(
            "The device key is missing from {}. Run `00hooks login --force`.",
            store.describe()
        )),
        Err(e) => r.fail(&sentence(&e.to_string())),
    }
    let forced_file = std::env::var("HOOKS_KEYSTORE").as_deref() == Ok("file");
    if config.key_store == "file" && !forced_file && keychain_available() {
        r.warn("The key is in a file although this computer has a keychain; `00hooks login --force` would move it there.");
    }

    // Relay and clock (unsigned, so this works even when the key doesn't).
    let ctx = Ctx::load();
    let anon = match hooks_client::Client::new(&config.relay) {
        Ok(c) => c,
        Err(e) => {
            r.fail(&sentence(&e.to_string()));
            return finish(r);
        }
    };
    let t0 = system_now_ms();
    match anon.info().await {
        Ok(info) => {
            let t1 = system_now_ms();
            r.ok(&format!(
                "Relay reachable: version {}, protocol {} (`00hooks relay status` says more).",
                sanitize(&info.version, false),
                info.protocol
            ));
            if !crate::relay::speaks(&info) {
                r.fail(&format!(
                    "This 00hooks speaks protocol {PROTOCOL_VERSION}; update it to match the relay."
                ));
            }
            let skew = crate::relay::skew_ms(&info, t0, t1);
            let text = format!("Clock: {} off the relay's.", describe_skew(skew));
            if skew.abs() < 5_000 {
                r.ok(&text);
            } else if skew.abs() < 300_000 {
                r.warn(&format!(
                    "{text} Requests still work; turning on automatic date and time fixes it."
                ));
            } else {
                r.warn(&format!(
                    "{text} Requests are corrected for it, but turn on automatic date and time."
                ));
            }
            if info.signup_open {
                r.warn("This relay lets anyone sign up (development only).");
            }
        }
        Err(e) => {
            r.fail(&format!(
                "Can't reach the relay: {}",
                sentence(&e.to_string())
            ));
            return finish(r);
        }
    }

    // Signed requests and the stream.
    let ctx = match ctx {
        Ok(c) => c,
        Err(e) => {
            r.fail(&e.message);
            return finish(r);
        }
    };
    match ctx.client.devices().await {
        Ok(d) => r.ok(&format!(
            "Signed requests accepted ({} device{} on this account).",
            d.len(),
            if d.len() == 1 { "" } else { "s" }
        )),
        Err(e) => {
            r.fail(&ctx.explain(e).message);
            return finish(r);
        }
    }
    match ctx.state.lock_listener() {
        Ok(None) => r.ok(
            "Stream: `00hooks listen` is running here, so it wasn't opened again (that would replace it).",
        ),
        Ok(Some(_lock)) => {
            match hooks_client::stream::probe(&ctx.client, Duration::from_secs(20)).await {
                Ok(ready) => {
                    let waiting = ready.head.saturating_sub(ready.after);
                    r.ok(&format!(
                        "Stream opens ({waiting} event{} waiting).",
                        if waiting == 1 { "" } else { "s" }
                    ));
                }
                Err(e) => r.fail(&format!("Stream: {}", ctx.explain(e).message)),
            }
        }
        Err(e) => r.fail(&sentence(&e.to_string())),
    }
    finish(r)
}

fn finish(r: Report) -> CliResult {
    if r.failed {
        Err(Failure {
            message: String::new(),
            code: 1,
        })
    } else {
        Ok(())
    }
}
