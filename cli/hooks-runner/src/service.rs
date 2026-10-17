//! `00hooks service`: run `00hooks run` at login. macOS: a launchd user agent
//! (`~/Library/LaunchAgents/<LABEL>.plist`). Linux: a systemd user unit
//! (`~/.config/systemd/user/00hooks.service`). Logs go to `<state dir>/logs/runner.log`.

use std::path::PathBuf;
use std::process::Command;

use crate::{Error, Result};

/// The launchd label.
pub const LABEL: &str = "io.github.youfoundbruno.00hooks";
/// The systemd unit's name.
pub const UNIT: &str = "00hooks.service";

/// What the service runs and with which settings.
#[derive(Debug, Clone, PartialEq)]
pub struct Spec {
    /// The `00hooks` binary.
    pub exe: PathBuf,
    /// The state directory (`HOOKS_HOME`).
    pub state_dir: PathBuf,
    /// `HOOKS_KEYSTORE`, when set.
    pub keystore: Option<String>,
    /// The automations file.
    pub automations: PathBuf,
    /// `PATH` for the runner and its commands.
    pub path: String,
}

impl Spec {
    pub fn log(&self) -> PathBuf {
        self.state_dir.join("logs").join("runner.log")
    }

    fn env(&self) -> Vec<(&'static str, String)> {
        let mut v = vec![
            ("HOOKS_HOME", self.state_dir.display().to_string()),
            ("HOOKS_AUTOMATIONS", self.automations.display().to_string()),
            ("PATH", self.path.clone()),
        ];
        if let Some(k) = &self.keystore {
            v.push(("HOOKS_KEYSTORE", k.clone()));
        }
        v
    }
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The launchd agent.
pub fn launchd_plist(spec: &Spec) -> String {
    let log = xml(&spec.log().display().to_string());
    let mut env = String::new();
    for (k, v) in spec.env() {
        env.push_str(&format!(
            "        <key>{k}</key>\n        <string>{}</string>\n",
            xml(&v)
        ));
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>run</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
{env}    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>30</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#,
        exe = xml(&spec.exe.display().to_string()),
    )
}

/// Quote a value for a systemd unit file: in double quotes, with `\`, `"` escaped and `%` doubled
/// (systemd's specifier character).
fn systemd_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            '\n' | '\r' => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The systemd user unit.
pub fn systemd_unit(spec: &Spec) -> String {
    let mut env = String::new();
    for (k, v) in spec.env() {
        env.push_str(&format!(
            "Environment={}\n",
            systemd_quote(&format!("{k}={v}"))
        ));
    }
    let log = spec.log().display().to_string().replace('%', "%%");
    format!(
        "[Unit]\n\
         Description=00hooks automation runner\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={} run\n\
         {env}\
         Restart=on-failure\n\
         RestartSec=30\n\
         StandardOutput=append:{log}\n\
         StandardError=append:{log}\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        systemd_quote(&spec.exe.display().to_string()),
    )
}

/// Where the service file goes on this system.
pub fn service_file() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| Error::Other("can't find the home folder".into()))?;
    if cfg!(target_os = "macos") {
        Ok(home
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist")))
    } else if cfg!(target_os = "linux") {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".config"));
        Ok(base.join("systemd/user").join(UNIT))
    } else {
        Err(Error::Other(
            "services are supported on macOS (launchd) and Linux (systemd); run `00hooks run` \
             another way here"
                .into(),
        ))
    }
}

/// The service file's contents for this system.
pub fn contents(spec: &Spec) -> String {
    if cfg!(target_os = "macos") {
        launchd_plist(spec)
    } else {
        systemd_unit(spec)
    }
}

fn run(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| Error::Other(format!("couldn't run {program}: {e}")))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(text)
    } else {
        Err(Error::Other(format!(
            "`{program} {}` failed: {}",
            args.join(" "),
            text.trim()
        )))
    }
}

#[cfg(unix)]
fn gui_domain() -> String {
    format!("gui/{}", rustix::process::getuid().as_raw())
}

#[cfg(not(unix))]
fn gui_domain() -> String {
    String::new()
}

/// Write the service file and start it. Returns what happened, as sentences.
pub fn install(spec: &Spec) -> Result<Vec<String>> {
    let file = service_file()?;
    let mut said = Vec::new();
    hooks_client::fsutil::create_private_dir(spec.log().parent().expect("logs dir"))
        .map_err(Error::from_client)?;
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    hooks_client::fsutil::write_atomic(&file, contents(spec).as_bytes(), false)
        .map_err(Error::from_client)?;
    said.push(format!("Wrote {}.", file.display()));
    if cfg!(target_os = "macos") {
        let domain = gui_domain();
        // Replace a loaded copy, if any.
        let _ = run("launchctl", &["bootout", &format!("{domain}/{LABEL}")]);
        run(
            "launchctl",
            &["bootstrap", &domain, &file.display().to_string()],
        )?;
        said.push(format!(
            "Loaded it with launchctl ({domain}/{LABEL}); it starts at every login."
        ));
    } else {
        run("systemctl", &["--user", "daemon-reload"])?;
        run("systemctl", &["--user", "enable", "--now", UNIT])?;
        said.push(format!("Enabled and started {UNIT} (systemctl --user)."));
    }
    said.push(format!("Logs: {}", spec.log().display()));
    Ok(said)
}

/// Stop the service and remove its file.
pub fn uninstall() -> Result<Vec<String>> {
    let file = service_file()?;
    let mut said = Vec::new();
    if cfg!(target_os = "macos") {
        if run(
            "launchctl",
            &["bootout", &format!("{}/{LABEL}", gui_domain())],
        )
        .is_ok()
        {
            said.push("Stopped the runner.".into());
        }
    } else if run("systemctl", &["--user", "disable", "--now", UNIT]).is_ok() {
        said.push("Stopped and disabled the runner.".into());
    }
    match std::fs::remove_file(&file) {
        Ok(()) => said.push(format!("Removed {}.", file.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            said.push("No service was installed.".into())
        }
        Err(e) => return Err(e.into()),
    }
    if !cfg!(target_os = "macos") {
        let _ = run("systemctl", &["--user", "daemon-reload"]);
    }
    Ok(said)
}

/// Whether the service is installed and running, in sentences.
pub fn status() -> Result<Vec<String>> {
    let file = service_file()?;
    let mut said = Vec::new();
    if !file.exists() {
        said.push("Not installed. Run `00hooks service install`.".into());
        return Ok(said);
    }
    said.push(format!("Installed: {}", file.display()));
    if cfg!(target_os = "macos") {
        match run(
            "launchctl",
            &["print", &format!("{}/{LABEL}", gui_domain())],
        ) {
            Ok(text) => {
                let state = text
                    .lines()
                    .find_map(|l| l.trim().strip_prefix("state = "))
                    .unwrap_or("unknown");
                let pid = text.lines().find_map(|l| l.trim().strip_prefix("pid = "));
                said.push(match pid {
                    Some(p) => format!("Loaded: {state}, pid {p}."),
                    None => format!("Loaded: {state}."),
                });
            }
            Err(_) => said.push("Not loaded. Run `00hooks service install` again.".into()),
        }
    } else {
        let active =
            run("systemctl", &["--user", "is-active", UNIT]).unwrap_or_else(|e| e.to_string());
        said.push(format!("systemd says: {}", active.trim()));
    }
    Ok(said)
}

/// The installed file, if any (for `status --show`).
pub fn installed_contents() -> Option<String> {
    std::fs::read_to_string(service_file().ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> Spec {
        Spec {
            exe: PathBuf::from("/opt/00 hooks/bin/00hooks"),
            state_dir: PathBuf::from("/home/me/.local/share/00hooks"),
            keystore: Some("file".into()),
            automations: PathBuf::from("/home/me/.config/00hooks/a&b%.yaml"),
            path: "/usr/local/bin:/usr/bin:/bin".into(),
        }
    }

    #[test]
    fn the_launchd_agent_runs_the_runner_at_login() {
        let p = launchd_plist(&spec());
        assert!(p.contains(&format!("<string>{LABEL}</string>")));
        assert!(
            p.contains("<string>/opt/00 hooks/bin/00hooks</string>\n        <string>run</string>")
        );
        assert!(p.contains("<key>RunAtLoad</key>\n    <true/>"));
        assert!(p.contains("<key>SuccessfulExit</key>\n        <false/>"));
        assert!(p.contains(
            "<key>StandardOutPath</key>\n    <string>/home/me/.local/share/00hooks/logs/runner.log</string>"
        ));
        assert!(p.contains(
            "<key>HOOKS_HOME</key>\n        <string>/home/me/.local/share/00hooks</string>"
        ));
        assert!(p.contains("<key>HOOKS_KEYSTORE</key>\n        <string>file</string>"));
        assert!(p.contains("a&amp;b%.yaml"), "XML is escaped");
        assert!(!p.contains("a&b"));
    }

    #[test]
    fn the_systemd_unit_runs_the_runner_at_login() {
        let u = systemd_unit(&spec());
        assert!(u.contains("ExecStart=\"/opt/00 hooks/bin/00hooks\" run\n"));
        assert!(u.contains("Environment=\"HOOKS_HOME=/home/me/.local/share/00hooks\"\n"));
        assert!(
            u.contains("Environment=\"HOOKS_AUTOMATIONS=/home/me/.config/00hooks/a&b%%.yaml\"\n")
        );
        assert!(u.contains("Restart=on-failure"));
        assert!(u.contains("StandardOutput=append:/home/me/.local/share/00hooks/logs/runner.log"));
        assert!(u.contains("[Install]\nWantedBy=default.target\n"));
        assert_eq!(systemd_quote("a\"b\\c\nd"), "\"a\\\"b\\\\cd\"");
    }
}
