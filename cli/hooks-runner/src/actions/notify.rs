//! Notifications. macOS: `terminal-notifier` when it's installed, else `osascript`. Linux:
//! `notify-send`. The text is always a separate argument, never part of a script: `osascript`
//! gets a fixed AppleScript that reads its arguments (`on run argv`), so nothing in a payload can
//! become AppleScript.
//!
//! `notify-send` renders a little markup in the body, so `&`, `<`, `>` and quotes in it are
//! escaped. A helper gets [`HELPER_LIMIT`] to finish and is killed after it. Helpers are looked
//! up only in absolute `PATH` entries.
//!
//! (The UserNotifications framework needs an app bundle; a bare command-line program can't use
//! it, so the CLI goes through these helpers.)

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::text::{cut, sanitize};

const TITLE_MAX: usize = 100;
const BODY_MAX: usize = 500;
/// How long a notification helper may take before it is killed.
pub const HELPER_LIMIT: Duration = Duration::from_secs(10);

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
    which_in(name, &std::env::var_os("PATH")?)
}

/// The first file called `name` in these `PATH` entries. A relative entry (`.`, `bin`, an empty
/// one) is skipped: it would find whatever is in the current folder.
pub fn which_in(name: &str, path: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// `notify-send`'s body is markup: what would be read as a tag or an entity is escaped.
fn escape_markup(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// `notify-send`'s arguments: the texts after `--`, the body escaped.
fn notify_send_args(title: String, body: &str) -> Vec<String> {
    vec![
        "--app-name=00hooks".into(),
        "--".into(),
        title,
        escape_markup(body),
    ]
}

/// Run a helper, waiting at most `limit` for it; it is killed after that. Its error output (the
/// first 4 KiB) is the error.
pub fn run_helper(program: &Path, args: &[String], limit: Duration) -> Result<(), String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("couldn't start {}: {e}", program.display()))?;
    let (tx, rx) = std::sync::mpsc::channel();
    if let Some(mut err) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut keep = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = err.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if keep.len() < 4096 {
                    keep.extend_from_slice(&buf[..n.min(4096 - keep.len())]);
                }
            }
            let _ = tx.send(keep);
        });
    }
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{} didn't finish within {} s and was stopped",
                    program.display(),
                    limit.as_secs_f32()
                ));
            }
            Err(e) => return Err(format!("{}: {e}", program.display())),
        }
    };
    if status.success() {
        return Ok(());
    }
    let stderr = rx
        .recv_timeout(Duration::from_millis(200))
        .unwrap_or_default();
    Err(format!(
        "{} failed: {}",
        program.display(),
        cut(&sanitize(&String::from_utf8_lossy(&stderr)), 200)
    ))
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
        Some(ns) => Ok((ns, notify_send_args(title, &body))),
        None => Err("no notification helper found (install notify-send, from libnotify)".into()),
    }
}

impl Notifier for SystemNotifier {
    fn notify(&self, title: &str, body: &str) -> Result<(), String> {
        let (program, args) = system_command(title, body)?;
        run_helper(&program, &args, HELPER_LIMIT)
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
                notify_send_args("t".into(), evil),
            )
        });
        assert!(!program.as_os_str().is_empty());
        // The payload text is one whole argument, after `--`, and no script argument contains it
        // (notify-send's escaped, as it reads markup).
        let want = if program.ends_with("notify-send") {
            escape_markup(evil.trim())
        } else {
            evil.trim().to_string()
        };
        assert_eq!(args.last().unwrap(), &want);
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
    fn notify_send_gets_no_markup() {
        let args = notify_send_args("a <b>".into(), "<a href=\"x\">click</a> & 'so' >");
        assert_eq!(
            args,
            [
                "--app-name=00hooks",
                "--",
                "a <b>",
                "&lt;a href=&quot;x&quot;&gt;click&lt;/a&gt; &amp; &#39;so&#39; &gt;"
            ]
        );
    }

    #[test]
    fn relative_path_entries_are_never_searched() {
        let dir = crate::testutil::temp_dir("which");
        std::fs::write(dir.join("notify-send"), "").unwrap();
        let abs = dir.display().to_string();
        let joined = |entries: &[&str]| std::env::join_paths(entries).unwrap();
        assert_eq!(
            which_in("notify-send", &joined(&[&abs])),
            Some(dir.join("notify-send"))
        );
        // The same folder named relatively (as `.` would be, from inside it) is skipped.
        // `../../…/<temp>/which-…`: relative, and it does lead there from the current folder.
        let cwd = std::env::current_dir().unwrap();
        let ups = cwd.components().count().saturating_sub(1);
        let rel = format!(
            "{}{}",
            "../".repeat(ups),
            dir.strip_prefix("/").unwrap().display()
        );
        assert!(!Path::new(&rel).is_absolute());
        assert!(Path::new(&rel).join("notify-send").is_file());
        assert_eq!(which_in("notify-send", &joined(&[".", "", &rel])), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_slow_helper_is_stopped() {
        let started = Instant::now();
        let e = run_helper(
            Path::new("/bin/sh"),
            &["-c".into(), "sleep 30".into()],
            Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(e.contains("didn't finish"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            run_helper(
                Path::new("/bin/sh"),
                &["-c".into(), "exit 0".into()],
                HELPER_LIMIT
            )
            .is_ok()
        );
        let e = run_helper(
            Path::new("/bin/sh"),
            &["-c".into(), "echo nope >&2; exit 3".into()],
            HELPER_LIMIT,
        )
        .unwrap_err();
        assert!(e.contains("failed: nope"), "{e}");
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
