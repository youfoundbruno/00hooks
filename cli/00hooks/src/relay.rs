//! `00hooks relay status`: what a relay says about itself (`GET /v1/info`, unsigned).

use hooks_client::api::system_now_ms;
use hooks_client::{Client, Info, PROTOCOL_VERSION, PlatformPush, describe_skew};

use crate::ctx::{CliResult, Failure, explain, open_state, sentence};
use crate::output::{json_line, sanitize, table};

/// Whether this 00hooks speaks a stream protocol the relay serves.
pub fn speaks(info: &Info) -> bool {
    info.serves(PROTOCOL_VERSION)
}

/// The relay's clock minus ours, from an answer that took from `t0` to `t1`.
pub fn skew_ms(info: &Info, t0: i64, t1: i64) -> i64 {
    info.server_time - (t0 + t1) / 2
}

/// How the relay's key compares with the one pinned at login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pin {
    /// Not logged in to this relay: nothing to compare with.
    None,
    Matches,
    Differs,
}

pub async fn status(relay: Option<String>, as_json: bool) -> CliResult {
    let state = open_state()?;
    let config = state
        .load_config()
        .map_err(|e| Failure::new(sentence(&e.to_string())))?;
    let url = match (&relay, &config) {
        (Some(r), _) => r.trim().trim_end_matches('/').to_string(),
        (None, Some(c)) => c.relay.clone(),
        (None, None) => {
            return Err(Failure::new(
                "This computer isn't logged in; give the relay with --relay <URL>.",
            ));
        }
    };
    let client = Client::new(&url).map_err(|e| Failure::new(sentence(&e.to_string())))?;
    let t0 = system_now_ms();
    let info = client.info().await.map_err(|e| explain(e, &url))?;
    let t1 = system_now_ms();
    // The pinned key only means something for the relay this computer is logged in to.
    let pinned = config
        .as_ref()
        .filter(|c| Client::new(&c.relay).is_ok_and(|x| x.relay() == client.relay()))
        .and_then(|c| c.relay_key.clone());
    let pin = match (&pinned, &info.relay_key) {
        (None, _) => Pin::None,
        (Some(p), Some(k)) if p == k => Pin::Matches,
        (Some(_), _) => Pin::Differs,
    };
    if as_json {
        println!("{}", json_line(&info));
    } else {
        print!(
            "{}",
            describe(client.relay(), &info, pin, skew_ms(&info, t0, t1))
        );
    }
    if !speaks(&info) {
        return Err(Failure::new(format!(
            "This 00hooks speaks protocol {PROTOCOL_VERSION}, which the relay doesn't serve; \
             update whichever is older."
        )));
    }
    if pin == Pin::Differs {
        return Err(Failure::new(
            "The relay's key isn't the one pinned at login, so this computer refuses its events. \
             If the operator replaced the key on purpose, log in again with `00hooks login \
             --force`; otherwise something is answering in the relay's place.",
        ));
    }
    Ok(())
}

fn platform(name: &str, p: &PlatformPush) -> String {
    match (&p.available, &p.environment) {
        (true, Some(env)) => format!("{name} ({})", sanitize(env, false)),
        (true, None) => name.to_string(),
        (false, _) => format!("not {name}"),
    }
}

/// The human view of `/v1/info`.
pub fn describe(relay: &str, info: &Info, pin: Pin, skew: i64) -> String {
    let protocols: Vec<String> = if info.protocols.is_empty() {
        vec![info.protocol.to_string()]
    } else {
        info.protocols.iter().map(u32::to_string).collect()
    };
    let speaks = if speaks(info) {
        format!("this 00hooks speaks {PROTOCOL_VERSION}")
    } else {
        format!("this 00hooks speaks {PROTOCOL_VERSION}: NOT SERVED")
    };
    let key = match (&info.relay_key, pin) {
        (None, _) => "none (this relay takes no deliveries)".to_string(),
        (Some(k), Pin::Matches) => {
            format!("{} (matches the key pinned at login)", sanitize(k, false))
        }
        (Some(k), Pin::Differs) => format!(
            "{} (DIFFERS from the key pinned at login)",
            sanitize(k, false)
        ),
        (Some(k), Pin::None) => sanitize(k, false),
    };
    let push = match info.phone.as_ref().and_then(|p| p.push.as_ref()) {
        None => "no (no phone links)".to_string(),
        Some(p) => match &p.platforms {
            Some(pl) => {
                let mut parts = Vec::new();
                if let Some(i) = &pl.ios {
                    parts.push(platform("iOS", i));
                }
                if let Some(a) = &pl.android {
                    parts.push(platform("Android", a));
                }
                if parts.is_empty() {
                    "no".to_string()
                } else {
                    parts.join(", ")
                }
            }
            None => match (p.available, &p.environment) {
                (true, Some(env)) => format!("yes ({})", sanitize(env, false)),
                (true, None) => "yes".into(),
                (false, _) => "no".into(),
            },
        },
    };
    let screen = match &info.screen {
        Some(s) if s.edge => format!(
            "at the edge: up to {} rules a hook, held events kept {} days",
            s.max_rules, s.held_days
        ),
        _ => "no edge screen".to_string(),
    };
    let rows = vec![
        vec!["Relay".to_string(), sanitize(relay, false)],
        vec!["Version".into(), sanitize(&info.version, false)],
        vec![
            "Protocols".into(),
            format!("{} ({speaks})", protocols.join(", ")),
        ],
        vec!["Relay key".into(), key],
        vec![
            "Signup".into(),
            if info.signup_open {
                "open to anyone".into()
            } else {
                "needs a token, or closed".into()
            },
        ],
        vec![
            "Clock".into(),
            format!("{} off this computer's", describe_skew(skew)),
        ],
        vec!["Phone push".into(), push],
        vec!["Screen".into(), screen],
    ];
    table(&rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn info(v: serde_json::Value) -> Info {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn status_says_protocol_key_push_and_screen() {
        let i = info(json!({
            "version": "1.2", "protocol": 2, "protocols": [2, 3], "signupOpen": false,
            "relayKey": "KEY", "serverTime": 0,
            "screen": {"edge": true, "maxRules": 200, "heldDays": 7},
            "phone": {"protocol": 1, "push": {"available": true, "environment": "production",
                "platforms": {"ios": {"available": true, "environment": "production"},
                              "android": {"available": false}}}}
        }));
        let t = describe("https://r.example", &i, Pin::Matches, 0);
        assert!(t.contains("2, 3 (this 00hooks speaks 2)"), "{t}");
        assert!(t.contains("KEY (matches the key pinned at login)"), "{t}");
        assert!(t.contains("needs a token"), "{t}");
        assert!(t.contains("iOS (production), not Android"), "{t}");
        assert!(t.contains("up to 200 rules"), "{t}");
        assert!(speaks(&i));

        let i = info(json!({
            "version": "0\u{1b}[2J", "protocol": 1, "signupOpen": true, "relayKey": "OTHER",
            "serverTime": 0,
            "phone": {"protocol": 1, "push": {"available": true, "environment": "sandbox"}}
        }));
        let t = describe("https://r.example", &i, Pin::Differs, 0);
        assert!(!t.contains('\u{1b}'));
        assert!(t.contains("NOT SERVED") && t.contains("DIFFERS"), "{t}");
        assert!(
            t.contains("yes (sandbox)") && t.contains("open to anyone"),
            "{t}"
        );
        assert!(t.contains("no edge screen"), "{t}");
        assert!(!speaks(&i));
    }
}
