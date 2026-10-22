//! The automation commands: `run`, `automations check|resume`, `kinds`, `runs`, `replay` and
//! `secrets`. The work is done by the `hooks-runner` crate; this file is the terminal around it.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hooks_client::{StateDir, StreamEvent, SubscribeOptions, subscribe};
use hooks_runner::catalogue::{Catalogue, KindRecord};
use hooks_runner::config::{self, Automations, Problem};
use hooks_runner::hookrefs;
use hooks_runner::runner::{load_names, runner_dir};
use hooks_runner::runs::{RunRecord, RunStatus, read_runs};
use hooks_runner::{Runner, RunnerOptions, mailbox};

use crate::ctx::{CliResult, Ctx, Failure, open_state, sentence};
use crate::output::{clock, date_time, duration, json_line, sanitize, table};

/// The automations file: `--automations`, else `HOOKS_AUTOMATIONS`, else
/// `~/.config/00hooks/automations.yaml`.
pub fn automations_path(given: Option<PathBuf>) -> CliResult<PathBuf> {
    given
        .or_else(config::default_path)
        .ok_or_else(|| Failure::new("Can't find the home folder; pass --automations <file>."))
}

fn problems(path: &Path, ps: &[Problem]) -> String {
    let mut m = format!(
        "{} has {} problem{}:",
        path.display(),
        ps.len(),
        if ps.len() == 1 { "" } else { "s" }
    );
    for p in ps {
        if p.line > 0 {
            m.push_str(&format!("\n  line {}: {}", p.line, p.message));
        } else {
            m.push_str(&format!("\n  {}", p.message));
        }
    }
    m
}

fn fail(e: hooks_runner::Error, path: &Path) -> Failure {
    match e {
        hooks_runner::Error::Config(ps) => Failure::new(problems(path, &ps)),
        e => Failure::new(sentence(&e.to_string())),
    }
}

fn err(m: impl Into<String>) {
    eprintln!("{}", sanitize(&m.into(), true));
}

/// One line per run, and one per failed action.
fn describe_run(r: &RunRecord) -> Vec<String> {
    let hook = r.hook.as_deref().unwrap_or(&r.hook_id);
    let what = if r.kind.is_empty() {
        hook.to_string()
    } else {
        format!("{hook}/{}", r.kind)
    };
    let replay = if r.replay { " (replay)" } else { "" };
    let mut head = format!(
        "{}  {}  {}{replay}  ",
        clock(r.started_at),
        sanitize(&what, false),
        r.event_id
    );
    match r.status {
        RunStatus::Dropped | RunStatus::Interrupted | RunStatus::Skipped => {
            head.push_str(&format!(
                "{}: {}",
                status_word(r.status),
                r.note.as_deref().unwrap_or("")
            ))
        }
        _ => {
            let ran = r.ran();
            let skipped = r.automations.len() - ran;
            if r.automations.is_empty() {
                head.push_str("no automation matched");
            } else {
                head.push_str(&format!("{ran} ran"));
                if r.failed() > 0 {
                    head.push_str(&format!(" ({} failed)", r.failed()));
                }
                if skipped > 0 {
                    head.push_str(&format!(", {skipped} skipped"));
                }
            }
        }
    }
    let mut lines = vec![head];
    for a in &r.automations {
        if let Some(s) = &a.skipped {
            lines.push(format!("  {:?} skipped: {}", a.name, sanitize(s, false)));
        }
        for x in a.actions.iter().filter(|x| !x.ok) {
            let tries = if x.attempts > 1 {
                format!(" after {} attempts", x.attempts)
            } else {
                String::new()
            };
            lines.push(format!(
                "  {:?}: {} failed{tries}: {}",
                a.name,
                x.action,
                sanitize(x.error.as_deref().unwrap_or(""), false)
            ));
        }
    }
    lines
}

fn status_word(s: RunStatus) -> &'static str {
    match s {
        RunStatus::Ok => "ok",
        RunStatus::Failed => "failed",
        RunStatus::Dropped => "dropped",
        RunStatus::Interrupted => "interrupted",
        RunStatus::Held => "held",
        RunStatus::Skipped => "skipped",
    }
}

fn flush(runner: &mut Runner) {
    for line in runner.take_log() {
        err(line);
    }
}

/// Tests only (debug builds): stop the process dead at a named point, as a crash would, to prove
/// what a crash there leaves behind: `HOOKS_TEST_CRASH=after-handover` or `after-start`. It exits
/// at once, without running destructors or finishing anything in flight (not `abort`, so the OS
/// files no crash report for each test run).
fn crash_point(name: &str) {
    if cfg!(debug_assertions) && std::env::var("HOOKS_TEST_CRASH").is_ok_and(|v| v == name) {
        std::process::exit(86);
    }
}

/// `00hooks run`: listen and act, until stopped.
pub async fn run(file: Option<PathBuf>) -> CliResult {
    let ctx = Ctx::load()?;
    let path = automations_path(file)?;
    let _listener = ctx
        .state
        .lock_listener()
        .map_err(|e| Failure::new(sentence(&e.to_string())))?
        .ok_or_else(|| {
            Failure::new(format!(
                "Another `00hooks run` or `00hooks listen` is already running for {}. Stop it \
                 first: one device has one stream (`00hooks service status` shows the service).",
                ctx.state.path().display()
            ))
        })?;
    let rdir = runner_dir(ctx.state.path());
    let _lock = mailbox::lock(&rdir)
        .map_err(|e| Failure::new(sentence(&e.to_string())))?
        .ok_or_else(|| Failure::new("Another runner is running for this state folder."))?;
    let mut opts = RunnerOptions::new(&rdir, &path, &ctx.config.device_id);
    opts.screen = Some(crate::screen::open(&rdir)?);
    let mut runner = Runner::open(opts).map_err(|e| fail(e, &path))?;
    match ctx.client.hooks().await {
        Ok(hooks) => {
            let names: BTreeMap<String, String> =
                hooks.into_iter().map(|h| (h.id, h.name)).collect();
            if let Err(e) = runner.set_hook_names(names) {
                err(format!("Couldn't save the hook names: {e}"));
            }
        }
        Err(e) if e.is_unauthorized() => return Err(ctx.explain(e)),
        Err(_) => {}
    }
    let n = runner.config().automations.len();
    err(format!(
        "Running {n} automation{} from {} as {} on {}. Times are UTC. Press Ctrl-C to stop.",
        if n == 1 { "" } else { "s" },
        path.display(),
        sanitize(&ctx.config.device_name, false),
        ctx.config.relay
    ));
    if !path.exists() {
        err(format!(
            "{} doesn't exist yet: events are recorded and catalogued, and nothing runs.",
            path.display()
        ));
    }
    flush(&mut runner);

    // Replay requests from `00hooks replay`, checked every second.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(PathBuf, String)>(16);
    let watch_dir = rdir.clone();
    let watcher = tokio::spawn(async move {
        loop {
            for req in mailbox::pending(&watch_dir) {
                if tx.send(req).await.is_err() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    let events = ctx
        .state
        .open_events()
        .map_err(|e| Failure::new(sentence(&e.to_string())))?;
    // Confirmed handover: an event counts as handed over only once the runner has recorded its
    // start, so a crash in between hands it over again on the next start instead of losing it.
    let mut sub = subscribe(
        ctx.client.clone(),
        events,
        SubscribeOptions {
            confirm: true,
            ..SubscribeOptions::default()
        },
    );
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    #[cfg(unix)]
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| Failure::new(format!("Couldn't listen for SIGTERM: {e}.")))?;
    // SIGTERM (Unix); never elsewhere.
    #[cfg(unix)]
    macro_rules! terminated {
        () => {
            term.recv()
        };
    }
    #[cfg(not(unix))]
    macro_rules! terminated {
        () => {
            std::future::pending::<Option<()>>()
        };
    }
    let mut connected_before = false;
    let result = loop {
        let next = tokio::select! {
            _ = &mut ctrl_c => break Ok(()),
            _ = terminated!() => break Ok(()),
            Some((answer_at, event)) = rx.recv() => {
                // A signal stops a replay half-way too: its command is killed with the run, and
                // the run is reported as interrupted on the next start.
                let replayed = tokio::select! {
                    r = runner.replay(&event) => r,
                    _ = &mut ctrl_c => break Ok(()),
                    _ = terminated!() => break Ok(()),
                };
                let answer = match replayed {
                    Ok(record) => {
                        for l in describe_run(&record) { err(l); }
                        mailbox::Answer { record: Some(record), error: None }
                    }
                    Err(e) => mailbox::Answer { record: None, error: Some(e.to_string()) },
                };
                if let Err(e) = mailbox::answer(&answer_at, &answer) {
                    err(format!("Couldn't answer a replay request: {e}"));
                }
                flush(&mut runner);
                continue;
            }
            next = sub.next() => next,
        };
        let ev = match next {
            None => break Ok(()),
            Some(Err(e)) => break Err(ctx.explain(e)),
            Some(Ok(ev)) => ev,
        };
        match ev {
            StreamEvent::Ready(r) => {
                let waiting = r.head.saturating_sub(r.after);
                let what = if connected_before {
                    "Reconnected"
                } else {
                    "Connected"
                };
                connected_before = true;
                runner.on_ready(r.after, r.head);
                err(match waiting {
                    0 => format!("{what}."),
                    1 => format!("{what}. 1 event is waiting."),
                    n => format!("{what}. {n} events are waiting; running them oldest first."),
                });
            }
            StreamEvent::Hook(e) => {
                crash_point("after-handover");
                let mut unconfirmed = None;
                // A signal stops a run half-way: what it started is killed with it (the
                // runner's commands die with their run), and the next start reports the run as
                // interrupted (`00hooks replay` runs it again).
                let mut confirm = |id: &str| {
                    crash_point("after-start");
                    if let Err(e) = sub.confirm(id) {
                        unconfirmed = Some(e.to_string());
                    }
                };
                let record = tokio::select! {
                    r = runner.handle_confirming(&e, &mut confirm) => r,
                    _ = &mut ctrl_c => break Ok(()),
                    _ = terminated!() => break Ok(()),
                };
                if let Some(why) = unconfirmed {
                    err(format!(
                        "Couldn't mark event {} as handled in the stream's inbox ({}); if this \
                         runner restarts it is handed over again and found already handled.",
                        e.id,
                        sanitize(&why, false)
                    ));
                }
                flush(&mut runner);
                for l in describe_run(&record) {
                    err(l);
                }
            }
            StreamEvent::Gap(g) => err(format!(
                "Missed events {} to {}: the relay dropped them ({}) before this device read them.",
                g.from,
                g.to,
                sanitize(
                    if g.reason.is_empty() {
                        "retention"
                    } else {
                        &g.reason
                    },
                    false
                )
            )),
            StreamEvent::Resync(r) => err(format!(
                "The relay asked to catch up from event {}; reconnecting.",
                r.after
            )),
            StreamEvent::Reconnecting { delay, reason, .. } => {
                let when = if delay.is_zero() {
                    "now".to_string()
                } else {
                    format!("in {}", duration(delay))
                };
                err(format!(
                    "Connection lost: {}. Reconnecting {when}.",
                    sanitize(&reason, false)
                ));
            }
            StreamEvent::Quarantined { seq, path, error } => err(format!(
                "Event{} arrived but couldn't be read ({}); it is noted in {} (`00hooks quarantine \
                 list`).",
                seq.map(|n| format!(" {n}")).unwrap_or_default(),
                sanitize(&error, false),
                path.display()
            )),
            StreamEvent::Warning(w) => err(sentence(&sanitize(&w, false))),
            StreamEvent::Limit(l) => err(crate::listen::describe_limit(&l)),
            // The runner says what changed, warns the person when it matters (a secret rotated by
            // someone else, a name the automations use taken), and keeps the names current.
            StreamEvent::HookChange(c) => {
                runner.on_hook_change(&c).await;
                flush(&mut runner);
            }
            // A kind of message this version doesn't know (the stream grows additively).
            _ => {}
        }
    };
    watcher.abort();
    if result.is_ok() {
        err("Stopped.");
    }
    result
}

/// `00hooks automations check`.
pub fn check(file: Option<PathBuf>, strict: bool) -> CliResult {
    let path = automations_path(file)?;
    if !path.exists() {
        return Err(Failure::new(format!(
            "{} doesn't exist. Create it (the README's Automations section has an example), or pass --automations.",
            path.display()
        )));
    }
    let config = Automations::load(&path).map_err(|ps| Failure::new(problems(&path, &ps)))?;
    let state = open_state()?;
    let rdir = runner_dir(state.path());
    let cat = Catalogue::open(rdir.join("catalogue"))
        .map_err(|e| Failure::new(sentence(&e.to_string())))?;
    let names = load_names(&rdir);
    let pins = hookrefs::load_pins(&rdir).map_err(|e| Failure::new(sentence(&e.to_string())))?;
    let warnings = hooks_runner::check::check(&config, &cat, &names, &pins);
    let n = config.automations.len();
    println!(
        "{}: {n} automation{}, valid.",
        path.display(),
        if n == 1 { "" } else { "s" }
    );
    // How each hook named in the file resolves: matching is by id only.
    for r in hooks_runner::check::resolution(&config, &names, &pins).resolved {
        println!("  {}", sanitize(&hookrefs::describe(&r), false));
    }
    for w in &warnings {
        println!("  line {}: {}", w.line, sanitize(&w.message, false));
    }
    if strict && !warnings.is_empty() {
        return Err(Failure::new(format!(
            "{} warning{} (--strict).",
            warnings.len(),
            if warnings.len() == 1 { "" } else { "s" }
        )));
    }
    Ok(())
}

/// `00hooks automations resume <name>`.
pub fn resume(name: String) -> CliResult {
    let state = open_state()?;
    let rdir = runner_dir(state.path());
    let mut s = hooks_runner::state::States::open(&rdir)
        .map_err(|e| Failure::new(sentence(&e.to_string())))?;
    if s.resume(&name) {
        s.save()
            .map_err(|e| Failure::new(sentence(&e.to_string())))?;
        println!("{name:?} is no longer paused.");
        Ok(())
    } else {
        Err(Failure::new(format!("{name:?} isn't paused.")))
    }
}

fn kind_label(k: &KindRecord, names: &BTreeMap<String, String>) -> String {
    sanitize(
        &format!("{}/{}", names.get(&k.hook_id).unwrap_or(&k.hook_id), k.kind),
        false,
    )
}

/// Find a kind by `hook/kind` (hook name or id) or a bare kind when only one hook has it.
fn find_kind<'a>(
    cat: &'a Catalogue,
    names: &BTreeMap<String, String>,
    want: &str,
) -> CliResult<&'a KindRecord> {
    let matches: Vec<&KindRecord> = cat
        .kinds()
        .filter(|k| {
            let name = names.get(&k.hook_id);
            want == k.kind
                || want == format!("{}/{}", k.hook_id, k.kind)
                || name.is_some_and(|n| want == format!("{n}/{}", k.kind))
        })
        .collect();
    match matches.as_slice() {
        [one] => Ok(one),
        [] => Err(Failure::new(format!(
            "No kind {}. `00hooks kinds` lists them.",
            sanitize(want, false)
        ))),
        many => Err(Failure::new(format!(
            "{} could be {}; write it as hook/kind.",
            sanitize(want, false),
            many.iter()
                .map(|k| kind_label(k, names))
                .collect::<Vec<_>>()
                .join(" or ")
        ))),
    }
}

fn open_catalogue() -> CliResult<(Catalogue, BTreeMap<String, String>)> {
    let state = open_state()?;
    let rdir = runner_dir(state.path());
    let cat = Catalogue::open(rdir.join("catalogue"))
        .map_err(|e| Failure::new(sentence(&e.to_string())))?;
    Ok((cat, load_names(&rdir)))
}

/// `00hooks kinds`.
pub fn kinds(as_json: bool) -> CliResult {
    let (cat, names) = open_catalogue()?;
    if as_json {
        for k in cat.kinds() {
            println!("{}", json_line(k));
        }
        return Ok(());
    }
    if cat.kinds().next().is_none() {
        println!("No events catalogued yet. `00hooks run` adds each kind as it arrives.");
        return Ok(());
    }
    let mut rows = vec![vec![
        "KIND".into(),
        "COUNT".into(),
        "FIRST SEEN".into(),
        "LAST SEEN".into(),
        "FIELDS".into(),
        "NOTE".into(),
    ]];
    for k in cat.kinds() {
        let note = match k.changes.last() {
            Some(c) => format!("shape changed {}", &date_time(c.at)[..10]),
            None if k.sample.is_none() => "no sample".into(),
            None => String::new(),
        };
        rows.push(vec![
            kind_label(k, &names),
            k.count.to_string(),
            date_time(k.first_seen),
            date_time(k.last_seen),
            k.fields.len().to_string(),
            note,
        ]);
    }
    print!("{}", table(&rows));
    Ok(())
}

fn short(v: &serde_json::Value) -> String {
    let s = match v {
        serde_json::Value::String(s) => format!("{s:?}"),
        other => other.to_string(),
    };
    let s = sanitize(&s, false);
    if s.chars().count() > 40 {
        format!("{}…", s.chars().take(39).collect::<String>())
    } else {
        s
    }
}

/// `00hooks kinds show <kind>`.
pub fn kinds_show(want: String, as_json: bool) -> CliResult {
    let (cat, names) = open_catalogue()?;
    let k = find_kind(&cat, &names, &want)?;
    if as_json {
        println!("{}", json_line(k));
        return Ok(());
    }
    println!("Kind       {}", kind_label(k, &names));
    println!("Hook       {}", k.hook_id);
    println!(
        "Seen       {} times, first {}, last {}",
        k.count,
        date_time(k.first_seen),
        date_time(k.last_seen)
    );
    match &k.sample {
        Some(s) => println!("Sample     event {}", sanitize(&s.event_id, false)),
        None => println!("Sample     none (cleared, or the hook keeps structure only)"),
    }
    for c in &k.changes {
        println!(
            "Changed    {}: added {}; removed {}",
            date_time(c.at),
            if c.added.is_empty() {
                "nothing".into()
            } else {
                sanitize(&c.added.join(", "), false)
            },
            if c.removed.is_empty() {
                "nothing".into()
            } else {
                sanitize(&c.removed.join(", "), false)
            }
        );
    }
    if k.truncated {
        println!(
            "Note       more than {} fields; the rest weren't recorded",
            hooks_runner::catalogue::MAX_FIELDS
        );
    }
    println!();
    let mut rows = vec![vec![
        "FIELD".into(),
        "TYPE".into(),
        "PRESENT".into(),
        "SAMPLE".into(),
        "VALUES SEEN".into(),
    ]];
    for (path, f) in &k.fields {
        let sample = match k.sample_value(path) {
            Some(serde_json::Value::Object(_)) | Some(serde_json::Value::Array(_)) => String::new(),
            Some(v) => short(v),
            None => String::new(),
        };
        let values = if f.varied {
            "(many)".to_string()
        } else {
            f.values.iter().map(short).collect::<Vec<_>>().join(", ")
        };
        rows.push(vec![
            sanitize(path, false),
            f.types.iter().cloned().collect::<Vec<_>>().join("|"),
            format!("{}/{}", f.present, k.count),
            sample,
            values,
        ]);
    }
    for (h, n) in &k.headers {
        rows.push(vec![
            sanitize(&format!("headers.{h}"), false),
            "string".into(),
            format!("{n}/{}", k.count),
            String::new(),
            String::new(),
        ]);
    }
    print!("{}", table(&rows));
    Ok(())
}

/// `00hooks kinds clear`.
pub fn kinds_clear(want: Option<String>, all: bool, forget: bool) -> CliResult {
    let (mut cat, names) = open_catalogue()?;
    let e = |e: hooks_runner::Error| Failure::new(sentence(&e.to_string()));
    match (want, all) {
        (None, true) => {
            let n = cat.clear_all().map_err(e)?;
            println!(
                "Forgot {n} kind{} (structure, samples and values).",
                if n == 1 { "" } else { "s" }
            );
        }
        (Some(w), false) => {
            let key = find_kind(&cat, &names, &w)?.key();
            let label = kind_label(cat.by_key(&key).expect("found"), &names);
            if forget {
                cat.forget(&key).map_err(e)?;
                println!("Forgot {label}.");
            } else {
                cat.clear_sample(&key).map_err(e)?;
                println!("Cleared the sample and values seen of {label}; its structure stays.");
            }
        }
        _ => {
            return Err(Failure::new(
                "Name a kind to clear, or pass --all to forget every kind.",
            ));
        }
    }
    Ok(())
}

/// `00hooks runs`.
pub fn runs(limit: usize, event: Option<String>, as_json: bool) -> CliResult {
    let state = open_state()?;
    let rdir = runner_dir(state.path());
    let all = read_runs(&rdir).map_err(|e| Failure::new(sentence(&e.to_string())))?;
    let mut picked: Vec<&RunRecord> = all
        .iter()
        .rev()
        .filter(|r| {
            event
                .as_ref()
                .is_none_or(|id| &r.event_id == id || r.seq.to_string() == *id)
        })
        .take(limit)
        .collect();
    picked.reverse();
    if as_json {
        for r in picked {
            println!("{}", json_line(r));
        }
        return Ok(());
    }
    if picked.is_empty() {
        println!("No runs yet.");
        return Ok(());
    }
    for r in picked {
        for l in describe_run(r) {
            println!("{l}");
        }
        if event.is_some() {
            for a in &r.automations {
                for x in a.actions.iter().filter(|x| x.ok) {
                    println!(
                        "  {:?}: {} ok in {} ms: {}",
                        a.name,
                        x.action,
                        x.ms,
                        sanitize(x.detail.as_deref().unwrap_or(""), false)
                    );
                }
            }
        }
    }
    Ok(())
}

/// `00hooks replay <event>`.
pub async fn replay(event: String, file: Option<PathBuf>) -> CliResult {
    let state = open_state()?;
    let rdir = runner_dir(state.path());
    if hooks_runner::runs::read_event(&rdir, &event)
        .map_err(|e| Failure::new(sentence(&e.to_string())))?
        .is_none()
    {
        return Err(Failure::new(format!(
            "No recorded event {}. `00hooks runs` lists recent ones (the newest {} are kept).",
            sanitize(&event, false),
            hooks_runner::runs::KEEP_EVENTS
        )));
    }
    let record = match mailbox::lock(&rdir).map_err(|e| Failure::new(sentence(&e.to_string())))? {
        Some(_lock) => {
            let path = automations_path(file)?;
            let origin = origin(&state)?;
            let mut runner = Runner::open(RunnerOptions::new(&rdir, &path, &origin))
                .map_err(|e| fail(e, &path))?;
            let r = runner
                .replay(&event)
                .await
                .map_err(|e| Failure::new(sentence(&e.to_string())))?;
            flush(&mut runner);
            r
        }
        None => {
            // A runner is running: ask it, so its rate limits and state stay its own.
            let at = mailbox::submit(&rdir, &event)
                .map_err(|e| Failure::new(sentence(&e.to_string())))?;
            eprintln!("Asked the running runner to replay it…");
            let deadline = Instant::now() + Duration::from_secs(120);
            loop {
                if let Some(a) = mailbox::take_answer(&at) {
                    match (a.record, a.error) {
                        (Some(r), _) => break r,
                        (None, e) => return Err(Failure::new(sentence(&e.unwrap_or_default()))),
                    }
                }
                if Instant::now() > deadline {
                    return Err(Failure::new(
                        "The running runner didn't answer within 2 minutes; it may be busy. Check `00hooks runs` later.",
                    ));
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    };
    for l in describe_run(&record) {
        println!("{l}");
    }
    if record.status == RunStatus::Failed {
        return Err(Failure {
            message: String::new(),
            code: 1,
        });
    }
    Ok(())
}

/// This machine's origin on outbound calls: the device id.
fn origin(state: &StateDir) -> CliResult<String> {
    Ok(state
        .load_config()
        .map_err(|e| Failure::new(sentence(&e.to_string())))?
        .map(|c| c.device_id)
        .unwrap_or_else(|| "dev_local".into()))
}

/// `00hooks secrets set <NAME>`: the value comes from stdin, never the command line.
pub fn secrets_set(name: String) -> CliResult {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(Failure::new(format!(
            "Pipe the value in, so it never shows on screen or in your shell history: for example \
             `pbpaste | 00hooks secrets set {name}`."
        )));
    }
    let mut line = String::new();
    std::io::BufRead::read_line(&mut stdin.lock(), &mut line)
        .map_err(|e| Failure::new(format!("Couldn't read the value from stdin: {e}.")))?;
    let value = line.trim_end_matches(['\r', '\n']);
    if value.is_empty() {
        return Err(Failure::new("No value on stdin."));
    }
    let state = open_state()?;
    let store = hooks_runner::secrets::default_store(&runner_dir(state.path()));
    store
        .set(&name, value)
        .map_err(|e| Failure::new(sentence(&e.to_string())))?;
    println!(
        "Saved {name} in {}. Use it in a call's headers as {{{{secret.{name}}}}}.",
        store.describe()
    );
    Ok(())
}

/// `00hooks secrets delete <NAME>`.
pub fn secrets_delete(name: String) -> CliResult {
    let state = open_state()?;
    let store = hooks_runner::secrets::default_store(&runner_dir(state.path()));
    if store
        .delete(&name)
        .map_err(|e| Failure::new(sentence(&e.to_string())))?
    {
        println!("Deleted {name}.");
        Ok(())
    } else {
        Err(Failure::new(format!(
            "No secret {name} in {}.",
            store.describe()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hooks_runner::runs::{ActionResult, AutomationRun};

    #[test]
    fn runs_read_as_sentences() {
        let r = RunRecord {
            run: "run_1".into(),
            event_id: "evt_1".into(),
            seq: 1,
            hook_id: "hk_1".into(),
            hook: Some("github".into()),
            kind: "issues".into(),
            verified: true,
            started_at: 1792233600000,
            finished_at: 1792233600000,
            replay: false,
            status: RunStatus::Failed,
            note: None,
            new_kind: false,
            shape_change: None,
            automations: vec![
                AutomationRun {
                    name: "A".into(),
                    trigger: "kind".into(),
                    skipped: None,
                    actions: vec![ActionResult {
                        action: "call".into(),
                        ok: false,
                        attempts: 3,
                        ms: 10,
                        error: Some("HTTP 503 from x\u{1b}[2J".into()),
                        detail: None,
                        output: None,
                    }],
                    batch: None,
                },
                AutomationRun {
                    name: "B".into(),
                    trigger: "kind".into(),
                    skipped: Some("only_if is false".into()),
                    actions: vec![],
                    batch: None,
                },
            ],
            held: None,
            batch: None,
        };
        let lines = describe_run(&r);
        assert_eq!(
            lines[0],
            "10:40:00  github/issues  evt_1  1 ran (1 failed), 1 skipped"
        );
        assert_eq!(
            lines[1],
            "  \"A\": call failed after 3 attempts: HTTP 503 from x[2J"
        );
        assert_eq!(lines[2], "  \"B\" skipped: only_if is false");
    }
}
