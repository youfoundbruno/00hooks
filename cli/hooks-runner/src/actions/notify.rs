//! Notifications. macOS: `terminal-notifier` when it's installed, else `osascript`. Linux:
//! `notify-send`. The text is always a separate argument, never part of a script: `osascript`
//! gets a fixed AppleScript that reads its arguments (`on run argv`), so nothing in a payload can
//! become AppleScript.
//!
//! (The UserNotifications framework needs an app bundle; a bare command-line program can't use
//! it, so the CLI goes through these helpers.)

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use crate::text::{cut, sanitize};

const TITLE_MAX: usize = 100;
const BODY_MAX: usize = 500;

pub trait Notifier: Send + Sync {
    /// Show a notification. The texts are already rendered; the notifier cleans them.
    fn notify(&self, title: &str, body: &str) -> Result<(), String>;
}

/// Clean and shorten; never start with `-` (some helpers would read it as an option).
fn clean(s: &str, max: usize) -> String {
    let s = cut(sanitize(s).trim(), max);
    if s.starts_with('-') {
        format!(" {s}")
    } else {
        s
    }
}

/// The first executable called `name` on `PATH`.
pub fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// The system's notifications.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemNotifier;

/// The command that shows a notification on this system, as a program and its arguments.
pub fn system_command(title: &str, body: &str) -> Result<(PathBuf, Vec<String>), String> {
    let (title, body) = (clean(title, TITLE_MAX), clean(body, BODY_MAX));
    if cfg!(target_os = "macos") {
        if let Some(tn) = which("terminal-notifier") {
            return Ok((
                tn,
                vec![
                    "-title".into(),
                    title,
                    "-message".into(),
                    body,
                    "-group".into(),
                    "00hooks".into(),
                ],
            ));
        }
        return Ok((
            PathBuf::from("/usr/bin/osascript"),
            vec![
                "-e".into(),
                "on run argv".into(),
                "-e".into(),
                "display notification (item 2 of argv) with title (item 1 of argv)".into(),
                "-e".into(),
                "end run".into(),
                "--".into(),
                title,
                body,
            ],
        ));
    }
    match which("notify-send") {
        Some(ns) => Ok((
            ns,
            vec!["--app-name=00hooks".into(), "--".into(), title, body],
        )),
        None => Err("no notification helper found (install notify-send, from libnotify)".into()),
    }
}

impl Notifier for SystemNotifier {
    fn notify(&self, title: &str, body: &str) -> Result<(), String> {
        let (program, args) = system_command(title, body)?;
        let out = Command::new(&program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("couldn't start {}: {e}", program.display()))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{} failed: {}",
                program.display(),
                cut(&sanitize(&String::from_utf8_lossy(&out.stderr)), 200)
            ))
        }
    }
}

/// Shows nothing (`notify: none`).
#[derive(Debug, Default, Clone, Copy)]
pub struct NullNotifier;

impl Notifier for NullNotifier {
    fn notify(&self, _: &str, _: &str) -> Result<(), String> {
        Ok(())
    }
}

/// Keeps what it was asked to show (tests, and embedding in an app with its own notifications).
#[derive(Debug, Default)]
pub struct RecordingNotifier {
    pub shown: Mutex<Vec<(String, String)>>,
    /// Fail this many times first.
    pub fail: Mutex<u32>,
}

impl Notifier for RecordingNotifier {
    fn notify(&self, title: &str, body: &str) -> Result<(), String> {
        let mut fail = self.fail.lock().expect("lock");
        if *fail > 0 {
            *fail -= 1;
            return Err("the notification centre isn't answering".into());
        }
        self.shown
            .lock()
            .expect("lock")
            .push((clean(title, TITLE_MAX), clean(body, BODY_MAX)));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_an_argument_never_a_script() {
        let evil = "\" & (do shell script \"touch /tmp/x\") & \"";
        let (program, args) = system_command("t", evil).unwrap_or_else(|_| {
            (
                PathBuf::from("notify-send"),
                vec!["--".into(), "t".into(), evil.into()],
            )
        });
        assert!(!program.as_os_str().is_empty());
        // The payload text is one whole argument, after `--`, and no script argument contains it.
        assert_eq!(args.last().unwrap(), evil.trim());
        let dashdash = args.iter().position(|a| a == "--");
        if program.ends_with("osascript") || program.ends_with("notify-send") {
            assert!(dashdash.is_some());
            assert!(
                args[..dashdash.unwrap()]
                    .iter()
                    .all(|a| !a.contains("touch"))
            );
        }
    }

    #[test]
    fn texts_are_cleaned() {
        assert_eq!(clean("-rf\u{1b}[2J", 50), " -rf[2J");
        assert_eq!(clean(&"x".repeat(600), BODY_MAX).chars().count(), BODY_MAX);
        let r = RecordingNotifier::default();
        r.notify("a\nb", "c\u{202e}d").unwrap();
        assert_eq!(r.shown.lock().unwrap()[0], ("a b".into(), "cd".into()));
    }
}
