//! Run an allowed command: the program from the automation's `allow_commands`, an argument list
//! (each template renders to exactly one argument), never a shell. An argument that starts with
//! an event value may not render to `-…` (an option the sender chose) unless the action says
//! `options_end` or `raw` ([`render_args`]). The environment is empty but
//! for `PATH`, `HOME` and `LANG` and the automation's own `env`. The event goes on stdin as JSON,
//! or into a private file named by `HOOKS_EVENT_FILE`. Each run gets its own private folder
//! ([`RunDir`]: random name, 0700, removed afterwards) as its working directory, with the event
//! file in it. The command runs in its own process group; the group is killed (with everything the
//! command started) when the command exits, at its time limit, or when the run is dropped, so a
//! background child holding the output open can't keep the runner waiting.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::{Failure, Outcome};
use crate::config::EventInput;
use crate::template::Template;
use crate::text::{cut, sanitize};

/// How much of stdout and stderr is kept.
const KEEP_OUTPUT: usize = 16 * 1024;
/// After the command exits, how long what's left in its output is read (at most what remains of
/// its time limit, at least [`MIN_OUTPUT_GRACE`]).
const OUTPUT_GRACE: Duration = Duration::from_secs(2);
const MIN_OUTPUT_GRACE: Duration = Duration::from_millis(100);

pub struct Run<'a> {
    pub program: &'a Path,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub event: EventInput,
    pub timeout: Duration,
}

/// A NUL can't be passed to a program; drop it rather than fail.
fn no_nul(s: String) -> String {
    if s.contains('\0') {
        s.replace('\0', "")
    } else {
        s
    }
}

/// Render a command's arguments. An argument whose first characters come from the event
/// ([`Template::starts_with_slot`]) and render to `-…` would let whoever sent the event pass the
/// program an option of their choosing (`--upload-pack=…`, `-oProxyCommand=…`), so it is refused,
/// naming the argument and never its value. `options_end` (usually `--`) goes right before the
/// first such argument, and lets those after it start with `-`: the program reads them as
/// operands. `raw` allows them as they are. Arguments you wrote (`--title={{payload.x}}`, `-v`)
/// are never refused.
pub fn render_args(
    args: &[Template],
    ctx: &Value,
    raw: bool,
    options_end: Option<&str>,
) -> Result<Vec<String>, Failure> {
    let mut out = Vec::with_capacity(args.len() + 1);
    let mut ended = false;
    for (i, t) in args.iter().enumerate() {
        let from_event = t.starts_with_slot();
        if from_event
            && !ended
            && let Some(marker) = options_end
        {
            out.push(no_nul(marker.to_string()));
            ended = true;
        }
        let v = no_nul(t.render(ctx));
        if from_event && !raw && !ended && v.starts_with('-') {
            return Err(Failure::fatal(format!(
                "argument {} of args starts with `-` from the event, so the program could read \
                 it as an option; refused (set `options_end: \"--\"` on the action when the \
                 program takes `--`, or `raw: true` to allow it)",
                i + 1
            )));
        }
        out.push(v);
    }
    Ok(out)
}

/// A private folder for one run: a random name under the OS temp folder, created exclusively
/// (never an existing folder or a symlink), 0700. The command runs in it, the event file goes in
/// it, and it is removed with everything in it when dropped.
pub struct RunDir(PathBuf);

impl RunDir {
    pub fn create() -> std::io::Result<RunDir> {
        let path = std::env::temp_dir().join(format!("00hooks-run-{}", crate::random_hex()));
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // A umask can only narrow it, but make sure.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(RunDir(path))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// A private file in the folder: created exclusively, never through a symlink, 0600.
    fn write_file(&self, name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
        use std::io::Write;
        let path = self.0.join(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
            opts.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        let mut f = opts.open(&path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(path)
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The command's process group (Unix): killed, with everything the command started in it, when
/// this is dropped, so a run future dropped mid-run (a signal, a host shutting down) leaves
/// nothing running.
struct Group(Option<u32>);

impl Group {
    fn kill(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self
            .0
            .take()
            .and_then(|p| rustix::process::Pid::from_raw(p as i32))
        {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        #[cfg(not(unix))]
        {
            self.0 = None;
        }
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Read until the end, keeping the first [`KEEP_OUTPUT`] bytes where the caller can take them even
/// when the reading is cut short.
async fn read_into<R: AsyncRead + Unpin>(mut r: R, keep: Arc<Mutex<Vec<u8>>>) {
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                let mut out = keep.lock().unwrap_or_else(|p| p.into_inner());
                if out.len() < KEEP_OUTPUT {
                    let take = n.min(KEEP_OUTPUT - out.len());
                    out.extend_from_slice(&buf[..take]);
                }
            }
        }
    }
}

pub async fn run(r: Run<'_>, ctx: &Value) -> Outcome {
    let event_json = serde_json::to_vec(ctx).expect("json");
    // Removed at the end, or when the run is dropped, after the process group is killed.
    let dir = RunDir::create()
        .map_err(|e| Failure::fatal(format!("couldn't make the run's private folder: {e}")))?;
    let mut cmd = tokio::process::Command::new(r.program);
    cmd.args(r.args.into_iter().map(no_nul))
        .env_clear()
        .current_dir(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for k in ["PATH", "HOME", "LANG"] {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    for (k, v) in r.env {
        cmd.env(k, no_nul(v));
    }
    #[cfg(unix)]
    cmd.process_group(0);
    match r.event {
        EventInput::File => {
            let f = dir
                .write_file("event.json", &event_json)
                .map_err(|e| Failure::fatal(format!("couldn't write the event file: {e}")))?;
            cmd.env("HOOKS_EVENT_FILE", f);
            cmd.stdin(Stdio::null());
        }
        EventInput::Stdin => {
            cmd.stdin(Stdio::piped());
        }
        EventInput::None => {
            cmd.stdin(Stdio::null());
        }
    }
    let name = r
        .program
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let deadline = tokio::time::Instant::now() + r.timeout;
    let mut child = cmd
        .spawn()
        .map_err(|e| Failure::fatal(format!("couldn't start {}: {e}", r.program.display())))?;
    let mut group = Group(child.id());
    let feed = child.stdin.take().map(|mut stdin| {
        tokio::spawn(async move {
            // A program that doesn't read its input is fine.
            let _ = stdin.write_all(&event_json).await;
            let _ = stdin.shutdown().await;
        })
    });
    let (stdout, stderr) = (Arc::default(), Arc::default());
    let readers = [
        tokio::spawn(read_into(
            child.stdout.take().expect("piped"),
            Arc::clone(&stdout),
        )),
        tokio::spawn(read_into(
            child.stderr.take().expect("piped"),
            Arc::clone(&stderr),
        )),
    ];
    let waited = tokio::time::timeout_at(deadline, child.wait()).await;
    // Whatever the command left running in its group (`sleep 30 &`) goes with it: it would hold
    // the output open and keep the runner waiting.
    group.kill();
    let status = match waited {
        Ok(s) => s.map_err(|e| Failure::fatal(format!("{name}: {e}"))),
        Err(_) => {
            let _ = child.kill().await;
            Err(Failure::fatal(format!(
                "{name} was stopped after {} s, its time limit",
                r.timeout.as_secs()
            )))
        }
    };
    // What's still in the pipes is read for a moment; something that left the group and still
    // holds them open doesn't keep the run waiting.
    let grace = OUTPUT_GRACE
        .min(deadline.saturating_duration_since(tokio::time::Instant::now()))
        .max(MIN_OUTPUT_GRACE);
    let mut readers = readers;
    let _ = tokio::time::timeout(grace, async {
        for r in readers.iter_mut() {
            let _ = r.await;
        }
    })
    .await;
    for r in readers.iter().chain(feed.iter()) {
        r.abort();
    }
    let status = status?;
    let take = |b: &Arc<Mutex<Vec<u8>>>| b.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let (stdout, stderr) = (take(&stdout), take(&stderr));
    drop(dir);
    let show = |b: &[u8]| cut(&sanitize(String::from_utf8_lossy(b).trim()), 300);
    if status.success() {
        let o = show(&stdout);
        Ok(if o.is_empty() {
            format!("{name} exited 0")
        } else {
            format!("{name} exited 0: {o}")
        })
    } else {
        let code = status
            .code()
            .map(|c| format!("exited {c}"))
            .unwrap_or_else(|| "was killed by a signal".into());
        let e = show(&stderr);
        Err(Failure::retry(if e.is_empty() {
            format!("{name} {code}")
        } else {
            format!("{name} {code}: {e}")
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::Scope;
    use serde_json::json;

    fn args(list: &[&str]) -> Vec<Template> {
        list.iter()
            .map(|a| Template::parse(a, Scope::Event).unwrap())
            .collect()
    }

    #[test]
    fn an_event_value_can_not_become_an_option() {
        let ctx = json!({"payload": {"repo": "--upload-pack=touch /tmp/pwned", "name": "fine"}});
        let a = args(&["fetch", "{{payload.repo}}"]);
        let e = render_args(&a, &ctx, false, None).unwrap_err();
        assert!(!e.retryable);
        assert!(e.message.contains("argument 2"), "{}", e.message);
        assert!(!e.message.contains("upload-pack"), "never echoes the value");
        // A NUL in front doesn't hide the dash.
        let ctx2 = json!({"payload": {"repo": "\u{0}-oProxyCommand=x"}});
        assert!(render_args(&a, &ctx2, false, None).is_err());
        // Values that don't start with `-` pass; so do arguments you wrote, `-` and all.
        let ok = args(&["-v", "--name={{payload.repo}}", "{{payload.name}}"]);
        assert_eq!(
            render_args(&ok, &ctx, false, None).unwrap(),
            ["-v", "--name=--upload-pack=touch /tmp/pwned", "fine"]
        );
        // `raw: true` allows it.
        assert_eq!(
            render_args(&a, &ctx, true, None).unwrap(),
            ["fetch", "--upload-pack=touch /tmp/pwned"]
        );
    }

    #[test]
    fn options_end_goes_before_the_first_event_value() {
        let ctx = json!({"payload": {"a": "-rf", "b": "--x"}});
        let a = args(&["-n", "{{payload.a}}", "lit", "{{payload.b}}"]);
        assert_eq!(
            render_args(&a, &ctx, false, Some("--")).unwrap(),
            ["-n", "--", "-rf", "lit", "--x"]
        );
        // No event values: no marker.
        assert_eq!(
            render_args(&args(&["-n", "x"]), &ctx, false, Some("--")).unwrap(),
            ["-n", "x"]
        );
    }
}
