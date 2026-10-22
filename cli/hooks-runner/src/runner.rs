//! The runner: one event in, a run record out. See the crate docs for the steps.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use hooks_client::{Event, HookChange, HookChangeKind};
use hooks_screen::{Screen, SourceKind, Verdict};
use serde_json::{Value, json};

use crate::actions::{self, Failure, Notifier, NullNotifier, SystemNotifier};
use crate::ask::{AskBatch, AskRequest, Asker};
use crate::batch::{BatchStore, OpenBatch, Reason};
use crate::catalogue::{Catalogue, Observation};
use crate::config::{
    Action, ActionKind, Automation, Automations, Batch, MAX_BATCH_BYTES, NotifyMode, Trigger,
    describe_rate,
};
use crate::contentmarks::{self, ContentMarks};
use crate::hookrefs::{self, HookRefs, Pin, Pins};
use crate::runs::{ActionResult, AutomationRun, BatchSummary, RunLog, RunRecord, RunStatus};
use crate::secrets::SecretStore;
use crate::state::{Admit, Breaker, States};
use crate::text::sanitize;
use crate::{Error, HOP_HEADER, ORIGIN_HEADER, Result, TEST_KIND, context, is_test_event, now_ms};

/// Events beyond this many hops are dropped as a loop.
pub const HOP_LIMIT: u32 = 3;
/// A catch-up of at least this many events ends with a summary notification.
pub const SUMMARY_AFTER: u64 = 5;

pub struct RunnerOptions {
    /// The runner's own folder (`<state dir>/runner`).
    pub dir: PathBuf,
    pub automations: PathBuf,
    /// This machine's identity on outbound calls (the device id).
    pub origin: String,
    /// `None`: the system's notifications, or none, as the file says.
    pub notifier: Option<Arc<dyn Notifier>>,
    pub secrets: Arc<dyn SecretStore>,
    /// The first retry's wait; doubles each time, at most 30 s.
    pub retry_base: Duration,
    /// Runs "ask an agent" actions; `None` (the CLI) makes them fail, saying why.
    pub asker: Option<Arc<dyn Asker>>,
    /// The screen (PLAN §6a): every event meets it before any automation runs. A host shares one
    /// screen across its sources; `None` runs without one.
    pub screen: Option<Arc<Screen>>,
    /// Now, in Unix milliseconds: batches' timers and the rate limits read it. The system's clock
    /// by default; tests set their own.
    pub clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl RunnerOptions {
    pub fn new(dir: impl Into<PathBuf>, automations: impl Into<PathBuf>, origin: &str) -> Self {
        let dir = dir.into();
        let secrets: Arc<dyn SecretStore> = Arc::from(crate::secrets::default_store(&dir));
        RunnerOptions {
            dir,
            automations: automations.into(),
            origin: origin.to_string(),
            notifier: None,
            secrets,
            retry_base: Duration::from_secs(1),
            asker: None,
            screen: None,
            clock: Arc::new(now_ms),
        }
    }
}

struct CatchUp {
    until: u64,
    events: u64,
    ran: u64,
    failed: u64,
}

pub struct Runner {
    opts: RunnerOptions,
    config: Automations,
    config_stamp: Option<SystemTime>,
    /// The host gave the automations (`open_with`): the file is never read.
    given: bool,
    catalogue: Catalogue,
    runs: RunLog,
    /// The content-hash dedupe: what content was already taken, for presets that sign no timestamp.
    marks: ContentMarks,
    states: States,
    http: reqwest::Client,
    /// Hook names by id, from the relay (cached in `hooks.json`).
    names: BTreeMap<String, String>,
    /// The automations' hook references, resolved to ids: matching is by id only.
    refs: HookRefs,
    /// Names pinned to ids (`hook-pins.json`).
    pins: Pins,
    /// What resolving the references last reported, so each problem is said once.
    told: BTreeSet<String>,
    catch_up: Option<CatchUp>,
    log: Vec<String>,
    /// Hooks whose kinds reached the catalogue's cap, already said.
    capped_hooks: HashSet<String>,
    /// The open batches (`batch:`), on disk.
    batches: BatchStore,
    /// Batch runs that happened while an event was handled, for the caller (`take_batch_runs`).
    batch_runs: Vec<RunRecord>,
    /// Batches whose automation can't run now, already said.
    waiting_told: HashSet<String>,
}

/// A batch's events and what they were, for its run.
struct BatchInput {
    id: String,
    count: u32,
    first_at: i64,
    last_at: i64,
    reason: Reason,
    refused: u32,
    events: Vec<Value>,
    file: PathBuf,
}

impl BatchInput {
    fn summary(&self, automation: &str) -> BatchSummary {
        BatchSummary {
            id: self.id.clone(),
            automation: automation.to_string(),
            count: self.count,
            first_at: self.first_at,
            last_at: self.last_at,
            reason: self.reason,
            refused: self.refused,
        }
    }

    /// `batch` as templates read it.
    fn fields(&self) -> Value {
        json!({
            "id": self.id,
            "count": self.count,
            "first": rfc3339(self.first_at),
            "last": rfc3339(self.last_at),
            "reason": self.reason.as_str(),
            "refused": self.refused,
        })
    }

    /// What a batch's actions read: its last event (`payload`, `headers`, `event`), `batch` and
    /// `events`.
    fn context(&self) -> Value {
        let mut ctx = self.events.last().cloned().unwrap_or_else(|| json!({}));
        if let Value::Object(m) = &mut ctx {
            m.insert("batch".into(), self.fields());
            m.insert("events".into(), Value::Array(self.events.clone()));
        }
        ctx
    }

    /// One event of the batch with `batch` beside it (an appended line).
    fn context_of(&self, event: &Value) -> Value {
        let mut ctx = event.clone();
        if let Value::Object(m) = &mut ctx {
            m.insert("batch".into(), self.fields());
        }
        ctx
    }

    /// The most hops any of its events had come through.
    fn hop(&self) -> u32 {
        self.events
            .iter()
            .filter_map(|e| e["headers"].as_object())
            .filter_map(|h| {
                h.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(HOP_HEADER))
                    .and_then(|(_, v)| v.as_str()?.trim().parse::<u32>().ok())
            })
            .max()
            .unwrap_or(0)
    }
}

/// When an open batch is due, and why: `idle` after its last event or `max_wait` after its first,
/// whichever comes first.
pub fn batch_due(b: &OpenBatch, cfg: &Batch) -> (i64, Reason) {
    let ms = |d: Duration| d.as_millis() as i64;
    let idle = cfg.idle.map(|d| b.last_at + ms(d));
    let max = cfg.max_wait.map(|d| b.first_at + ms(d));
    match (idle, max) {
        (Some(i), Some(m)) if m < i => (m, Reason::MaxWait),
        (Some(i), _) => (i, Reason::Idle),
        (None, Some(m)) => (m, Reason::MaxWait),
        (None, None) => (b.first_at, Reason::MaxWait),
    }
}

fn stamp(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// The runner's folder inside a state directory.
pub fn runner_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("runner")
}

/// Hook names by id, cached for when the relay can't be asked.
pub fn load_names(dir: &Path) -> BTreeMap<String, String> {
    std::fs::read(dir.join("hooks.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

impl Runner {
    /// Open the runner's store and read the automations. A file with problems is an error: the
    /// runner doesn't start on a configuration it can't fully understand.
    pub fn open(opts: RunnerOptions) -> Result<Runner> {
        hooks_client::fsutil::create_private_dir(&opts.dir).map_err(Error::from_client)?;
        let config = Automations::load(&opts.automations).map_err(Error::Config)?;
        Self::start(opts, config, false)
    }

    /// Open the runner's store with automations the host keeps as data (a program that embeds the runner), instead of
    /// `automations.yaml`. `set_automations` replaces them; the file is never read.
    pub fn open_with(opts: RunnerOptions, automations: Automations) -> Result<Runner> {
        hooks_client::fsutil::create_private_dir(&opts.dir).map_err(Error::from_client)?;
        Self::start(opts, automations, true)
    }

    fn start(opts: RunnerOptions, config: Automations, given: bool) -> Result<Runner> {
        let mut r = Runner {
            given,
            config_stamp: if given {
                None
            } else {
                stamp(&opts.automations)
            },
            catalogue: Catalogue::open(opts.dir.join("catalogue"))?,
            runs: RunLog::open(&opts.dir)?,
            marks: ContentMarks::open(&opts.dir)?,
            states: States::open(&opts.dir)?,
            http: actions::call::http_client(),
            names: load_names(&opts.dir),
            refs: HookRefs::default(),
            pins: Pins::new(),
            told: BTreeSet::new(),
            catch_up: None,
            log: Vec::new(),
            capped_hooks: HashSet::new(),
            batches: BatchStore::open(&opts.dir)?,
            batch_runs: Vec::new(),
            waiting_told: HashSet::new(),
            config,
            opts,
        };
        r.settle_batches();
        for rec in r.runs.interrupted.clone() {
            r.say(format!(
                "Run {} of event {} was interrupted when the runner last stopped; it wasn't run \
                 again. `00hooks replay {}` runs it.",
                rec.run, rec.event_id, rec.event_id
            ));
        }
        r.resolve_hooks();
        r.apply_structure_only()?;
        Ok(r)
    }

    pub fn config(&self) -> &Automations {
        &self.config
    }

    /// Now, by the runner's clock.
    fn now(&self) -> i64 {
        (self.opts.clock)()
    }

    /// Batches a crash stopped while they were being cut: one whose run had begun is closed (the
    /// run log reports that run as interrupted, and `00hooks replay <batch>` runs it again); one
    /// whose run hadn't begun stays open, to run at the next tick.
    fn settle_batches(&mut self) {
        let cutting: Vec<OpenBatch> = self
            .batches
            .all()
            .filter(|b| b.cutting.is_some())
            .cloned()
            .collect();
        for b in cutting {
            let reason = b.cutting.expect("filtered");
            let done = if self.runs.seen(&b.id) {
                let now = self.now();
                self.batches.finish(&b.automation, reason, now).map(|_| {
                    format!(
                        "Batch {} of {:?} was being run when the runner last stopped; it wasn't \
                         run again. `00hooks replay {}` runs it.",
                        b.id, b.automation, b.id
                    )
                })
            } else {
                self.batches
                    .unmark_cutting(&b.automation)
                    .map(|_| String::new())
            };
            match done {
                Ok(m) if m.is_empty() => {}
                Ok(m) => self.say(m),
                Err(e) => self.say(format!("Couldn't settle batch {}: {e}", b.id)),
            }
        }
    }

    /// The open batches (`batch:`), one per automation at most.
    pub fn open_batches(&self) -> Vec<OpenBatch> {
        self.batches.all().cloned().collect()
    }

    /// When the next open batch is due (Unix ms), by the current automations. A host sleeps until
    /// then (or ticks every second or so) and calls [`Runner::tick`].
    pub fn next_batch_due(&self) -> Option<i64> {
        self.batches
            .all()
            .filter_map(|b| {
                let a = self
                    .config
                    .automations
                    .iter()
                    .find(|a| a.name == b.automation && a.enabled)?;
                Some(match &a.batch {
                    Some(cfg) => batch_due(b, cfg).0,
                    None => b.last_at,
                })
            })
            .min()
    }

    /// Batch runs that happened while an event was handled (a batch cut by `max_events` or
    /// `max_bytes`), oldest first. They're in the run log too; [`Runner::tick`] returns them as well.
    pub fn take_batch_runs(&mut self) -> Vec<RunRecord> {
        std::mem::take(&mut self.batch_runs)
    }

    /// Why `a` couldn't run now, if it couldn't: paused, or over its rate limit.
    fn blocked(&self, a: &Automation, now: i64) -> Option<String> {
        match self.states.peek(&a.name, a.rate_limit, now) {
            Admit::Run => None,
            Admit::Paused { until } => Some(format!(
                "paused after repeated failures until {}",
                crate::text::sanitize(&clock(until))
            )),
            Admit::RateLimited { .. } => Some(format!(
                "over its rate limit ({})",
                describe_rate(a.rate_limit)
            )),
        }
    }

    /// Run the batches that are due: `idle` or `max_wait` passed (a batch already overdue after a
    /// restart runs now). A batch whose automation can't run now (paused, over its rate limit) stays
    /// open and keeps holding events until it can. Returns the batch runs, with any that happened
    /// while events were handled since the last call.
    pub async fn tick(&mut self) -> Vec<RunRecord> {
        self.reload_if_changed();
        if self.batches.all().next().is_none() {
            return self.take_batch_runs();
        }
        if let Err(err) = self.states.reload() {
            self.say(format!("Couldn't read the automations' state: {err}"));
        }
        let now = self.now();
        let open: Vec<OpenBatch> = self.batches.all().cloned().collect();
        for b in open {
            let Some(a) = self
                .config
                .automations
                .iter()
                .find(|a| a.name == b.automation)
                .cloned()
            else {
                continue;
            };
            if !a.enabled {
                continue;
            }
            if b.count == 0 {
                // A crash between opening it and its first event: nothing to run.
                let _ = self.batches.discard(&b.automation);
                continue;
            }
            let (due, reason) = match &a.batch {
                Some(cfg) => batch_due(&b, cfg),
                None => (now, Reason::Unbatched),
            };
            if now < due {
                continue;
            }
            if let Some(why) = self.blocked(&a, now) {
                if self.waiting_told.insert(b.id.clone()) {
                    self.say(format!(
                        "Batch {} of {:?} is due, but the automation can't run now ({why}); it \
                         stays open and keeps holding events (up to its max_events or {} MiB; \
                         past that, new events aren't held and are counted).",
                        b.id,
                        a.name,
                        MAX_BATCH_BYTES / (1024 * 1024)
                    ));
                }
                continue;
            }
            let rec = self.cut(&a, reason).await;
            self.batch_runs.push(rec);
        }
        if let Err(err) = self.states.save() {
            self.say(format!("Couldn't save the automations' state: {err}"));
        }
        self.take_batch_runs()
    }

    /// Run an automation's open batch now (`00hooks batches flush`). Refused while the automation
    /// can't run (paused, over its rate limit): the batch stays open.
    pub async fn flush_batch(&mut self, automation: &str) -> Result<RunRecord> {
        self.reload_if_changed();
        let a = self
            .config
            .automations
            .iter()
            .find(|a| a.name == automation)
            .cloned()
            .ok_or_else(|| {
                Error::Other(format!(
                    "no automation is named {automation:?} in the automations; `00hooks batches \
                     drop` discards its batch"
                ))
            })?;
        match self.batches.get(automation) {
            Some(b) if b.count > 0 => {}
            _ => return Err(Error::Other(format!("{automation:?} has no open batch"))),
        }
        self.states.reload()?;
        if let Some(why) = self.blocked(&a, self.now()) {
            return Err(Error::Other(format!(
                "{automation:?} can't run now ({why}), so its batch stays open; `00hooks \
                 automations resume` lifts a pause"
            )));
        }
        let rec = self.cut(&a, Reason::Flush).await;
        self.states.save()?;
        Ok(rec)
    }

    /// Throw an automation's open batch away, with its events (`00hooks batches drop`). The events
    /// stay in the event archive, so `00hooks replay <event>` can still run one.
    pub fn drop_batch(&mut self, automation: &str) -> Result<OpenBatch> {
        let b = self
            .batches
            .discard(automation)?
            .ok_or_else(|| Error::Other(format!("{automation:?} has no open batch")))?;
        self.waiting_told.remove(&b.id);
        self.say(format!(
            "Dropped batch {} of {automation:?}: {} events weren't run.",
            b.id, b.count
        ));
        Ok(b)
    }

    /// Hold one event in `a`'s batch. A full batch is cut first (`max_events`, `max_bytes`), unless
    /// the automation can't run now: then the event isn't held, and is counted, with a note in its
    /// record saying how to run it later. Nothing is ever dropped silently.
    async fn hold(
        &mut self,
        a: &Automation,
        cfg: &Batch,
        ctx: &Value,
        e: &Event,
        mut run: AutomationRun,
    ) -> AutomationRun {
        let now = self.now();
        let line = serde_json::to_vec(ctx).expect("json");
        let size = line.len() as u64 + 1;
        let blocked = self.blocked(a, now);
        if let Some(open) = self.batches.get(&a.name).cloned() {
            let full = if open.count >= cfg.max_events {
                Some(Reason::MaxEvents)
            } else if open.bytes + size > MAX_BATCH_BYTES {
                Some(Reason::MaxBytes)
            } else {
                None
            };
            match (full, &blocked) {
                (None, _) => {}
                (Some(_), Some(why)) => {
                    if let Err(err) = self.batches.refuse(&a.name) {
                        self.say(format!("Couldn't count a refused event: {err}"));
                    }
                    run.skipped = Some(format!(
                        "its batch {} is full ({} events, {} KiB) and it can't run now ({why}), \
                         so this event wasn't held; `00hooks replay {}` runs it later",
                        open.id,
                        open.count,
                        open.bytes.div_ceil(1024),
                        e.id
                    ));
                    return run;
                }
                (Some(reason), None) => {
                    let rec = self.cut(a, reason).await;
                    self.batch_runs.push(rec);
                }
            }
        }
        if size > MAX_BATCH_BYTES {
            run.skipped = Some(format!(
                "the event alone is more than a batch holds ({} MiB), so it wasn't held; \
                 `00hooks replay {}` runs it",
                MAX_BATCH_BYTES / (1024 * 1024),
                e.id
            ));
            return run;
        }
        match self.batches.hold(&a.name, &line, now) {
            Ok(open) => {
                run.batch = Some(open.id.clone());
                if let Some(why) = &blocked
                    && self.waiting_told.insert(open.id.clone())
                {
                    self.say(format!(
                        "{:?} can't run now ({why}); its events are held in batch {} until it \
                         can (up to {} events or {} MiB; past that, new events aren't held and \
                         are counted).",
                        a.name,
                        open.id,
                        cfg.max_events,
                        MAX_BATCH_BYTES / (1024 * 1024)
                    ));
                }
                if open.count >= cfg.max_events && blocked.is_none() {
                    let rec = self.cut(a, Reason::MaxEvents).await;
                    self.batch_runs.push(rec);
                }
            }
            Err(err) => run.actions.push(ActionResult {
                action: "batch".into(),
                ok: false,
                attempts: 1,
                ms: 0,
                error: Some(format!("couldn't hold the event in its batch: {err}")),
                detail: None,
                output: None,
            }),
        }
        run
    }

    /// Cut `a`'s open batch and run its actions once, for all its events. At most once: the batch
    /// is marked, its run's start recorded (fsynced), and only then moved to `done`.
    async fn cut(&mut self, a: &Automation, reason: Reason) -> RunRecord {
        let now = self.now();
        let open = self.batches.get(&a.name).cloned().expect("an open batch");
        let failed = |this: &mut Runner, note: String| {
            this.say(format!("Batch {} of {:?}: {note}", open.id, a.name));
            let at = now_ms();
            RunRecord {
                run: format!("run_{}", crate::random_hex()),
                event_id: open.id.clone(),
                seq: 0,
                hook_id: String::new(),
                hook: None,
                kind: String::new(),
                verified: false,
                started_at: at,
                finished_at: at,
                replay: false,
                status: RunStatus::Failed,
                note: Some(note),
                new_kind: false,
                shape_change: None,
                automations: Vec::new(),
                held: None,
                batch: Some(BatchSummary {
                    id: open.id.clone(),
                    automation: a.name.clone(),
                    count: open.count,
                    first_at: open.first_at,
                    last_at: open.last_at,
                    reason,
                    refused: open.refused,
                }),
            }
        };
        let events = match self.batches.events(&a.name) {
            Ok(v) => v,
            Err(err) => {
                return failed(
                    self,
                    format!("couldn't read its events, so nothing ran; it stays open: {err}"),
                );
            }
        };
        if let Err(err) = self.batches.mark_cutting(&a.name, reason) {
            return failed(
                self,
                format!("couldn't record the cut, so nothing ran; it stays open: {err}"),
            );
        }
        let last = events.last().cloned().unwrap_or_else(|| json!({}));
        let ev = &last["event"];
        let run_id = match self.runs.begin_batch(
            &open.id,
            ev["seq"].as_u64().unwrap_or(0),
            ev["hookId"].as_str().unwrap_or_default(),
            ev["kind"].as_str().unwrap_or_default(),
            ev["verified"].as_bool().unwrap_or(false),
            false,
        ) {
            Ok(r) => r,
            Err(err) => {
                let _ = self.batches.unmark_cutting(&a.name);
                return failed(
                    self,
                    format!("couldn't record its run, so nothing ran; it stays open: {err}"),
                );
            }
        };
        if let Err(err) = self.batches.finish(&a.name, reason, now) {
            self.say(format!(
                "Couldn't move batch {} to the kept batches: {err}",
                open.id
            ));
        }
        self.waiting_told.remove(&open.id);
        let input = BatchInput {
            id: open.id.clone(),
            count: events.len() as u32,
            first_at: open.first_at,
            last_at: open.last_at,
            reason,
            refused: open.refused,
            file: self.batches.done_path(&open.id),
            events,
        };
        self.run_batch(a, input, run_id, false).await
    }

    /// Run a batch's actions and record the run.
    async fn run_batch(
        &mut self,
        a: &Automation,
        input: BatchInput,
        run_id: String,
        replay: bool,
    ) -> RunRecord {
        let started_at = now_ms();
        let ctx = input.context();
        let ev = ctx["event"].clone();
        let e = self.last_event(&ctx);
        let run = AutomationRun {
            name: a.name.clone(),
            trigger: "batch".into(),
            skipped: None,
            actions: Vec::new(),
            batch: None,
        };
        let hop = input.hop();
        let run = self.run_actions(a, &ctx, &e, Some(&input), hop, run).await;
        let status = if run.failed() {
            RunStatus::Failed
        } else {
            RunStatus::Ok
        };
        let rec = RunRecord {
            run: run_id,
            event_id: input.id.clone(),
            seq: ev["seq"].as_u64().unwrap_or(0),
            hook_id: ev["hookId"].as_str().unwrap_or_default().to_string(),
            hook: ev["hook"].as_str().map(str::to_string),
            kind: ev["kind"].as_str().unwrap_or_default().to_string(),
            verified: ev["verified"].as_bool().unwrap_or(false),
            started_at,
            finished_at: now_ms(),
            replay,
            status,
            note: Some(format!(
                "a batch of {} event{} ({})",
                input.count,
                if input.count == 1 { "" } else { "s" },
                input.reason.as_str()
            )),
            new_kind: false,
            shape_change: None,
            automations: vec![run],
            held: None,
            batch: Some(input.summary(&a.name)),
        };
        self.finish(rec)
    }

    /// The batch's last event, for an agent: from the event archive, else rebuilt from what the
    /// batch kept of it.
    fn last_event(&self, ctx: &Value) -> Event {
        let ev = &ctx["event"];
        if let Some(id) = ev["id"].as_str()
            && let Ok(Some(e)) = self.runs.event(id)
        {
            return e;
        }
        use base64::Engine;
        let body = match &ctx["payload"] {
            Value::String(s) => s.clone().into_bytes(),
            Value::Null => Vec::new(),
            v => serde_json::to_vec(v).expect("json"),
        };
        serde_json::from_value(json!({
            "seq": ev["seq"].as_u64().unwrap_or(0),
            "id": ev["id"].as_str().unwrap_or_default(),
            "hookId": ev["hookId"].as_str().unwrap_or_default(),
            "receivedAt": ev["receivedAt"].as_i64().unwrap_or(0),
            "verified": ev["verified"].as_bool().unwrap_or(false),
            "preset": ev["preset"].as_str().unwrap_or_default(),
            "eventType": ev["eventType"],
            "contentType": ev["contentType"],
            "headers": ctx["headers"].as_object().cloned().unwrap_or_default(),
            "body": base64::engine::general_purpose::STANDARD.encode(body),
        }))
        .expect("an event")
    }

    /// Run a kept batch again (`00hooks replay <batch id>`), against the current automations.
    async fn replay_batch(&mut self, id: &str) -> Result<RunRecord> {
        self.reload_if_changed();
        let Some((meta, events)) = self.batches.done(id)? else {
            if self.batches.all().any(|b| b.id == id) {
                return Err(Error::Other(format!(
                    "batch {id} is still open; `00hooks batches flush` runs it now"
                )));
            }
            return Err(Error::Other(format!(
                "batch {id} isn't kept any more (the newest {} batches that ran are)",
                crate::batch::KEEP_DONE
            )));
        };
        let a = self
            .config
            .automations
            .iter()
            .find(|a| a.name == meta.automation)
            .cloned()
            .ok_or_else(|| {
                Error::Other(format!(
                    "batch {id} belongs to {:?}, which isn't in the automations now",
                    meta.automation
                ))
            })?;
        self.states.reload()?;
        let last = events.last().cloned().unwrap_or_else(|| json!({}));
        let ev = &last["event"];
        let run_id = self.runs.begin_batch(
            id,
            ev["seq"].as_u64().unwrap_or(0),
            ev["hookId"].as_str().unwrap_or_default(),
            ev["kind"].as_str().unwrap_or_default(),
            ev["verified"].as_bool().unwrap_or(false),
            true,
        )?;
        let input = BatchInput {
            id: id.to_string(),
            count: events.len() as u32,
            first_at: meta.first_at,
            last_at: meta.last_at,
            reason: meta.reason,
            refused: meta.refused,
            file: self.batches.done_path(id),
            events,
        };
        let rec = self.run_batch(&a, input, run_id, true).await;
        self.states.save()?;
        Ok(rec)
    }

    /// Replace the automations (a host that keeps them as data).
    pub fn set_automations(&mut self, automations: Automations) {
        self.config = automations;
        self.resolve_hooks();
        if let Err(e) = self.apply_structure_only() {
            self.say(format!("Couldn't apply structure_only: {e}"));
        }
    }

    pub fn catalogue(&self) -> &Catalogue {
        &self.catalogue
    }

    /// To clear a kind's sample, forget a kind, or clear the whole catalogue.
    pub fn catalogue_mut(&mut self) -> &mut Catalogue {
        &mut self.catalogue
    }

    /// Each automation's rate-limit and circuit-breaker state, by name.
    pub fn states(&self) -> &States {
        &self.states
    }

    pub fn runs(&self) -> &RunLog {
        &self.runs
    }

    pub fn states_mut(&mut self) -> &mut States {
        &mut self.states
    }

    /// Lines for the person (the CLI prints them), oldest first.
    pub fn take_log(&mut self) -> Vec<String> {
        std::mem::take(&mut self.log)
    }

    fn say(&mut self, m: impl Into<String>) {
        self.log.push(m.into());
    }

    fn notifier(&self) -> Arc<dyn Notifier> {
        match (&self.opts.notifier, self.config.notify) {
            (Some(n), NotifyMode::System) => n.clone(),
            (None, NotifyMode::System) => Arc::new(SystemNotifier),
            (_, NotifyMode::None) => Arc::new(NullNotifier),
        }
    }

    /// Tell the person something about the runner itself (a pause, a catch-up).
    async fn tell(&mut self, title: &str, body: String) {
        self.say(body.clone());
        let n = self.notifier();
        let title = title.to_string();
        let _ = tokio::task::spawn_blocking(move || n.notify(&title, &body)).await;
    }

    /// Hook names by id (from the relay); cached on disk. The automations' hook names are resolved
    /// again: a name not pinned yet may resolve now; a pinned one keeps its id ([`hookrefs`]).
    pub fn set_hook_names(&mut self, names: BTreeMap<String, String>) -> Result<()> {
        if names != self.names {
            let bytes = serde_json::to_vec_pretty(&names).expect("json");
            hooks_client::fsutil::write_atomic(&self.opts.dir.join("hooks.json"), &bytes, true)
                .map_err(Error::from_client)?;
            self.names = names;
            self.resolve_hooks();
            self.apply_structure_only()?;
        }
        Ok(())
    }

    pub fn hook_names(&self) -> &BTreeMap<String, String> {
        &self.names
    }

    /// The automations' hook references, resolved to ids.
    pub fn hook_refs(&self) -> &HookRefs {
        &self.refs
    }

    /// Resolve the automations' hook references against the names and the pins, pin the names
    /// resolved for the first time, and say what doesn't resolve (once each).
    fn resolve_hooks(&mut self) {
        let mut messages: Vec<String> = Vec::new();
        let pins_ok = match hookrefs::load_pins(&self.opts.dir) {
            Ok(p) => {
                self.pins = p;
                true
            }
            Err(e) => {
                messages.push(format!(
                    "{e}. Until it is fixed or removed, hook names in the automations resolve \
                     only to the ids pinned before, and nothing new is pinned (ids still match)."
                ));
                false
            }
        };
        let mut r = hookrefs::resolve(&self.config, &self.names, &self.pins);
        if pins_ok && !r.new_pins.is_empty() {
            let at = now_ms();
            for (name, id) in &r.new_pins {
                self.pins.insert(name.clone(), Pin { id: id.clone(), at });
            }
            match hookrefs::save_pins(&self.opts.dir, &self.pins) {
                Ok(()) => {
                    for (name, id) in &r.new_pins {
                        self.say(format!(
                            "Pinned the hook name {:?} to {id}: the automations follow this hook \
                             by its id, whatever it is called later.",
                            sanitize(name)
                        ));
                    }
                }
                Err(e) => messages.push(format!(
                    "Couldn't record the hook names' ids ({e}); they are used for now and \
                     resolved again on the next start."
                )),
            }
        } else if !pins_ok {
            // Fail closed: a name the pins can't vouch for doesn't resolve.
            for (name, _) in &r.new_pins {
                r.refs.remove(name);
            }
        }
        let path = self.config.path.display().to_string();
        for p in r.problems.iter().chain(&r.warnings) {
            messages.push(format!("{path}: line {}: {}", p.line, sanitize(&p.message)));
        }
        let now: BTreeSet<String> = messages.iter().cloned().collect();
        for m in messages {
            if !self.told.contains(&m) {
                self.say(m);
            }
        }
        self.told = now;
        self.refs = r.refs;
    }

    fn apply_structure_only(&mut self) -> Result<()> {
        let ids: HashSet<String> = self
            .catalogue
            .kinds()
            .map(|k| k.hook_id.clone())
            .filter(|id| self.config.structure_only(id, &self.refs))
            .collect();
        if !ids.is_empty() {
            self.catalogue.enforce_structure_only(&ids)?;
        }
        Ok(())
    }

    /// Re-read `automations.yaml` when it changed. A file with problems is reported and the
    /// previous automations stay in force.
    pub fn reload_if_changed(&mut self) {
        if self.given {
            return;
        }
        let now = stamp(&self.opts.automations);
        if now == self.config_stamp {
            return;
        }
        self.config_stamp = now;
        match Automations::load(&self.opts.automations) {
            Ok(c) => {
                self.say(format!(
                    "Reloaded {} ({} automations).",
                    self.opts.automations.display(),
                    c.automations.len()
                ));
                self.config = c;
                self.resolve_hooks();
                if let Err(e) = self.apply_structure_only() {
                    self.say(format!("Couldn't apply structure_only: {e}"));
                }
            }
            Err(problems) => {
                let mut m = format!(
                    "{} changed but has problems, so the previous automations stay in force:",
                    self.opts.automations.display()
                );
                for p in problems {
                    m.push_str(&format!("\n  {p}"));
                }
                self.say(m);
            }
        }
    }

    /// The stream (re)connected: `head - after` events were waiting.
    pub fn on_ready(&mut self, after: u64, head: u64) {
        if head > after {
            match &mut self.catch_up {
                Some(c) => c.until = c.until.max(head),
                None => {
                    self.catch_up = Some(CatchUp {
                        until: head,
                        events: 0,
                        ran: 0,
                        failed: 0,
                    })
                }
            }
        }
    }

    async fn count_catch_up(&mut self, rec: &RunRecord) {
        let Some(c) = &mut self.catch_up else { return };
        if rec.seq <= c.until {
            c.events += 1;
            c.ran += rec.ran() as u64;
            c.failed += rec.failed() as u64;
        }
        if rec.seq >= c.until {
            let c = self.catch_up.take().expect("present");
            if c.events >= SUMMARY_AFTER {
                let failed = match c.failed {
                    0 => String::new(),
                    1 => ", 1 failed".into(),
                    n => format!(", {n} failed"),
                };
                self.tell(
                    "00hooks caught up",
                    format!(
                        "Ran {} events that arrived while this computer was offline, oldest \
                         first: {} automation runs{failed}.",
                        c.events, c.ran
                    ),
                )
                .await;
            }
        }
    }

    /// Handle one event from the stream. Never fails: what went wrong is in the record.
    pub async fn handle(&mut self, e: &Event) -> RunRecord {
        self.handle_confirming(e, &mut |_| {}).await
    }

    /// Handle one event from a stream subscribed with `SubscribeOptions { confirm: true }`.
    /// `confirm` is called with the event's id once it is settled here: its run's start is
    /// recorded (fsynced), or it was dropped as a duplicate or a loop. The caller passes it on to
    /// `Subscription::confirm`. It isn't called when the start couldn't be recorded, so the event
    /// stays in the stream's inbox and comes back after a restart instead of being lost.
    ///
    /// Together with the run log's own memory of every event that started a run, an event is run
    /// at most once and, short of a disk that refuses writes, at least once: a crash before the
    /// start record hands it over again; a crash after it finds it already handled.
    pub async fn handle_confirming(
        &mut self,
        e: &Event,
        confirm: &mut (dyn FnMut(&str) + Send),
    ) -> RunRecord {
        self.reload_if_changed();
        let rec = self.process(e, false, false, confirm).await;
        if !rec.replay {
            self.count_catch_up(&rec).await;
        }
        rec
    }

    /// Run a recorded event again, now, against the current automations.
    pub async fn replay(&mut self, event_id: &str) -> Result<RunRecord> {
        // `00hooks screen release` asks a running runner through the same mailbox.
        if event_id.starts_with("hld_") {
            return self.release(event_id).await;
        }
        if crate::batch::is_batch_id(event_id) {
            return self.replay_batch(event_id).await;
        }
        self.reload_if_changed();
        let e = self.runs.event(event_id)?.ok_or_else(|| {
            Error::Other(format!(
                "no recorded event {event_id}; `00hooks runs` lists the ones that can be replayed"
            ))
        })?;
        Ok(self.process(&e, true, false, &mut |_| {}).await)
    }

    /// The screen this runner checks events with, if any.
    pub fn screen(&self) -> Option<&Arc<Screen>> {
        self.opts.screen.as_ref()
    }

    /// Release an event the screen held: it runs now, once, against the current automations.
    pub async fn release(&mut self, held_id: &str) -> Result<RunRecord> {
        self.reload_if_changed();
        let screen = self
            .opts
            .screen
            .clone()
            .ok_or_else(|| Error::Other("this runner has no screen".into()))?;
        let h = screen.release(held_id).map_err(Error::Other)?;
        let e: Event = serde_json::from_value(h.host["event"].clone())
            .map_err(|_| Error::Other("the held item carries no event to run".into()))?;
        Ok(self.process(&e, true, true, &mut |_| {}).await)
    }

    /// The screen's view of an event (PLAN §6a): its payload and headers, where the edge saw it come
    /// from, whether anything beyond a notification would act on it (`agent_bound`) and whether
    /// anything would at all (`consequential`).
    fn screen_item(
        &self,
        e: &Event,
        payload: &Value,
        kind: &str,
        triggered: &[&Automation],
    ) -> hooks_screen::Item {
        let hook = self
            .names
            .get(&e.hook_id)
            .cloned()
            .unwrap_or_else(|| e.hook_id.clone());
        let origin = e.origin.clone().unwrap_or_default();
        let names: Vec<String> = triggered.iter().map(|a| a.name.clone()).collect();
        hooks_screen::Item {
            id: e.id.clone(),
            source: hooks_screen::Source {
                kind: SourceKind::Webhook,
                id: e.hook_id.clone(),
                name: hook.clone(),
            },
            payload: payload.clone(),
            headers: e.headers.clone(),
            origin: hooks_screen::Origin {
                ip: origin.ip,
                asn: origin.asn,
                country: origin.country,
                sender: None,
                known: None,
            },
            size: e.body_len(),
            received_at: e.received_at,
            // Anything beyond a notification (an agent, a command, a call, a file) would act on
            // it: when the evaluator can't answer, it is held rather than passed, so exhausting
            // the daily cap or forcing a time-out doesn't let it through.
            agent_bound: acts_beyond_notifying(triggered),
            consequential: !triggered.is_empty(),
            purpose: (!names.is_empty())
                .then(|| format!("events for these automations: {}", names.join("; "))),
            summary: crate::text::cut(&crate::text::sanitize(&format!("{kind} from {hook}")), 120),
            text: None,
        }
    }

    fn dropped(&self, e: &Event, note: String) -> RunRecord {
        let at = now_ms();
        RunRecord {
            run: format!("run_{}", crate::random_hex()),
            event_id: e.id.clone(),
            seq: e.seq,
            hook_id: e.hook_id.clone(),
            hook: self.names.get(&e.hook_id).cloned(),
            kind: String::new(),
            verified: e.verified,
            started_at: at,
            finished_at: at,
            replay: false,
            status: RunStatus::Dropped,
            note: Some(note),
            new_kind: false,
            shape_change: None,
            automations: Vec::new(),
            held: None,
            batch: None,
        }
    }

    fn finish(&mut self, rec: RunRecord) -> RunRecord {
        if let Err(err) = self.runs.finish(rec.clone()) {
            self.say(format!("Couldn't record run {}: {err}", rec.run));
        }
        rec
    }

    async fn process(
        &mut self,
        e: &Event,
        replay: bool,
        released: bool,
        confirm: &mut (dyn FnMut(&str) + Send),
    ) -> RunRecord {
        // At least once from the relay, at most once here.
        if !replay && self.runs.seen(&e.id) {
            confirm(&e.id);
            let rec = self.dropped(e, "already handled; not run twice".into());
            return self.finish(rec);
        }
        // Loops: our own call coming back, or a chain of 00hooks forwarding to each other.
        let header = |name: &str| {
            e.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        let hop: u32 = header(HOP_HEADER)
            .and_then(|h| h.trim().parse().ok())
            .unwrap_or(0);
        if header(ORIGIN_HEADER) == Some(self.opts.origin.as_str()) {
            confirm(&e.id);
            let rec = self.dropped(
                e,
                "our own call coming back (00hooks-origin); dropped to prevent a loop".into(),
            );
            return self.finish(rec);
        }
        if hop > HOP_LIMIT {
            confirm(&e.id);
            let rec = self.dropped(e, format!("it has passed through {hop} automations (more than {HOP_LIMIT}); dropped as a loop"));
            return self.finish(rec);
        }

        // A replay under a new id of content already taken (PROTOCOL §3). The mark is written before
        // the run's start: a crash between the two leaves a mark naming this very event, so it
        // still runs when the relay hands it over again, and a copy under another id never does.
        if !replay && contentmarks::applies(e) {
            let hash = contentmarks::content_hash(e);
            let now = now_ms();
            match self.marks.get(&hash, now) {
                Some(m) if m.e != e.id => {
                    let note = format!(
                        "same content as event {} received {}: a replay",
                        m.e,
                        clock(m.r)
                    );
                    confirm(&e.id);
                    let rec = self.dropped(e, note);
                    return self.finish(rec);
                }
                Some(_) => {}
                None => {
                    if let Err(err) = self.marks.record(&hash, e, now) {
                        // Without the mark a replay of it could run later: don't act yet. It isn't
                        // confirmed, so it comes back after a restart.
                        let mut rec = self.dropped(
                            e,
                            format!(
                                "couldn't record the event's content mark, so nothing ran: {err}"
                            ),
                        );
                        rec.status = RunStatus::Failed;
                        self.say(format!("Couldn't record event {}: {err}", e.id));
                        return rec;
                    }
                }
            }
        }

        let payload = context::payload(e);
        let kind = context::kind_name(e, &payload);
        let test = is_test_event(e);
        let hook_name = self.names.get(&e.hook_id).cloned();
        let started_at = now_ms();
        let run = match self.runs.begin(e, &kind, replay) {
            Ok(r) => {
                // The start is on disk: from here a crash finds it handled, never runs it twice.
                if !replay {
                    confirm(&e.id);
                }
                r
            }
            Err(err) => {
                // Without a durable start we can't promise at most once: don't act.
                let mut rec =
                    self.dropped(e, format!("couldn't record the run, so nothing ran: {err}"));
                rec.status = RunStatus::Failed;
                self.say(format!("Couldn't record event {}: {err}", e.id));
                return rec;
            }
        };

        // A test event isn't a kind the hook sends: it stays out of the catalogue.
        let observation = if replay || test {
            Observation {
                key: crate::catalogue::key(&e.hook_id, &kind),
                new_kind: false,
                change: None,
                capped: false,
            }
        } else {
            let so = self.config.structure_only(&e.hook_id, &self.refs);
            match self.catalogue.observe(
                &e.hook_id,
                &kind,
                &e.id,
                &payload,
                &e.headers,
                e.received_at,
                so,
            ) {
                Ok(o) => o,
                Err(err) => {
                    self.say(format!("Couldn't update the event catalogue: {err}"));
                    Observation {
                        key: crate::catalogue::key(&e.hook_id, &kind),
                        new_kind: false,
                        change: None,
                        capped: false,
                    }
                }
            }
        };
        let label = format!("{}/{}", hook_name.as_deref().unwrap_or(&e.hook_id), kind);
        if observation.new_kind {
            self.say(format!("New kind: {label}"));
        }
        let capped = observation.capped.then(|| {
            format!(
                "the catalogue already keeps {} kinds for this hook, so this kind wasn't recorded",
                crate::catalogue::MAX_KINDS_PER_HOOK
            )
        });
        if let Some(c) = &capped
            && self.capped_hooks.insert(e.hook_id.clone())
        {
            self.say(format!(
                "{label}: {c} (said once per hook while the runner runs)."
            ));
        }
        if let Some(c) = &observation.change {
            self.say(format!(
                "{label} changed shape: added {}; removed {}",
                list_or_none(&c.added),
                list_or_none(&c.removed)
            ));
        }

        let mut ctx = context::build(e, payload, hook_name.as_deref(), &kind, replay);
        if let (Some(c), Value::Object(m)) = (&observation.change, &mut ctx) {
            m.insert(
                "change".into(),
                json!({"added": c.added, "removed": c.removed}),
            );
        }

        // The screen (PLAN §6a), before any automation: not for a replay or a release (the person
        // asked for those), nor for an event the person already released at the relay.
        if !replay
            && !e.held
            && let Some(screen) = self.opts.screen.clone()
        {
            let triggered: Vec<&Automation> = self
                .config
                .automations
                .iter()
                .filter(|a| self.triggered(a, e, &kind, &observation).is_some())
                .collect();
            let item = self.screen_item(e, &ctx["payload"], &kind, &triggered);
            let decision = screen.check(&item).await;
            let screened = |status: RunStatus, note: String, held: Option<String>| RunRecord {
                run: run.clone(),
                event_id: e.id.clone(),
                seq: e.seq,
                hook_id: e.hook_id.clone(),
                hook: hook_name.clone(),
                kind: kind.clone(),
                verified: e.verified,
                started_at,
                finished_at: now_ms(),
                replay,
                status,
                note: Some(note),
                new_kind: observation.new_kind,
                shape_change: observation.change.clone(),
                automations: Vec::new(),
                held,
                batch: None,
            };
            match decision.verdict {
                Verdict::Pass => {}
                Verdict::Drop => {
                    let reason = crate::text::sanitize(&decision.reason);
                    self.say(format!("Dropped {label} by the screen: {reason}"));
                    let rec = screened(
                        RunStatus::Dropped,
                        format!("dropped by the screen: {reason}"),
                        None,
                    );
                    return self.finish(rec);
                }
                Verdict::Quarantine => {
                    let reason = crate::text::sanitize(&decision.reason);
                    let rec = match screen.hold(&item, &decision, json!({ "event": e })) {
                        Ok(h) => {
                            self.say(format!("Held {label} by the screen: {reason}. `00hooks screen held` lists it."));
                            screened(
                                RunStatus::Held,
                                format!("held by the screen: {reason}"),
                                Some(h.id),
                            )
                        }
                        Err(err) => screened(
                            RunStatus::Held,
                            format!(
                                "held by the screen ({reason}), but the quarantine list couldn't keep it: {err}; `00hooks replay {}` runs it",
                                e.id
                            ),
                            None,
                        ),
                    };
                    return self.finish(rec);
                }
            }
        }

        let mut autos = Vec::new();
        if let Err(err) = self.states.reload() {
            self.say(format!("Couldn't read the automations' state: {err}"));
        }
        let automations = self.config.automations.clone();
        for a in &automations {
            let Some(trigger) = self.triggered(a, e, &kind, &observation) else {
                continue;
            };
            autos.push(self.run_automation(a, trigger, e, &ctx, hop).await);
        }
        if let Err(err) = self.states.save() {
            self.say(format!("Couldn't save the automations' state: {err}"));
        }
        let status = if autos.iter().any(AutomationRun::failed) {
            RunStatus::Failed
        } else if test && autos.is_empty() {
            RunStatus::Skipped
        } else {
            RunStatus::Ok
        };
        let capped = if status == RunStatus::Skipped {
            Some(format!(
                "a test event (00hooks test); automations that list the kind {TEST_KIND} run on it"
            ))
        } else {
            capped
        };
        let rec = RunRecord {
            run,
            event_id: e.id.clone(),
            seq: e.seq,
            hook_id: e.hook_id.clone(),
            hook: hook_name,
            kind,
            verified: e.verified,
            started_at,
            finished_at: now_ms(),
            replay,
            status,
            note: match (released, capped) {
                (true, Some(c)) => Some(format!("released from the screen's quarantine list; {c}")),
                (true, None) => Some("released from the screen's quarantine list".to_string()),
                (false, c) => c,
            },
            new_kind: observation.new_kind,
            shape_change: observation.change,
            automations: autos,
            held: None,
            batch: None,
        };
        self.finish(rec)
    }

    /// Whether `a` fires for this event, and by which trigger.
    fn triggered(
        &self,
        a: &Automation,
        e: &Event,
        kind: &str,
        o: &Observation,
    ) -> Option<&'static str> {
        if !a.enabled {
            return None;
        }
        // By id only: a name was resolved to its id (and pinned) when the file was read.
        if let Some(h) = &a.when.hook
            && !self.refs.matches(h, &e.hook_id)
        {
            return None;
        }
        // A test event runs only what names its kind: not "any kind", nor the catalogue's triggers.
        if is_test_event(e) {
            return match &a.when.trigger {
                Trigger::Kinds(k) => k.iter().any(|k| k == TEST_KIND).then_some("kind"),
                _ => None,
            };
        }
        match &a.when.trigger {
            Trigger::Kinds(k) => (k.is_empty() || k.iter().any(|k| k == kind)).then_some("kind"),
            Trigger::NewKind => o.new_kind.then_some("new_kind"),
            Trigger::ShapeChanged(k) => (o.change.is_some()
                && (k.is_empty() || k.iter().any(|k| k == kind)))
            .then_some("shape_changed"),
        }
    }

    async fn run_automation(
        &mut self,
        a: &Automation,
        trigger: &str,
        e: &Event,
        ctx: &Value,
        hop: u32,
    ) -> AutomationRun {
        let mut run = AutomationRun {
            name: a.name.clone(),
            trigger: trigger.to_string(),
            skipped: None,
            actions: Vec::new(),
            batch: None,
        };
        if a.verified_only && !e.verified {
            run.skipped =
                Some("the event isn't verified (set verified_only: false to allow it)".into());
            return run;
        }
        if let Some(f) = &a.only_if
            && !f.test(ctx)
        {
            run.skipped = Some("only_if is false".into());
            return run;
        }
        // Batched: the filters passed, so it joins the batch; the actions run when it's cut.
        if let Some(cfg) = &a.batch {
            return self.hold(a, cfg, ctx, e, run).await;
        }
        self.run_actions(a, ctx, e, None, hop, run).await
    }

    /// Admit a run (rate limit, pause) and run the actions, recording the result for the circuit
    /// breaker. A batch's run counts once.
    async fn run_actions(
        &mut self,
        a: &Automation,
        ctx: &Value,
        e: &Event,
        batch: Option<&BatchInput>,
        hop: u32,
        mut run: AutomationRun,
    ) -> AutomationRun {
        let now = self.now();
        match self.states.admit(&a.name, a.rate_limit, now) {
            Admit::Run => {}
            Admit::RateLimited { tell } => {
                let rate = describe_rate(a.rate_limit);
                run.skipped = Some(format!("its rate limit ({rate}) is reached"));
                if tell {
                    self.tell(
                        "00hooks: rate limit",
                        if a.batch.is_some() {
                            format!("{:?} reached its rate limit ({rate}); its batches wait until it frees up.", a.name)
                        } else {
                            format!("{:?} reached its rate limit ({rate}); matching events are skipped until it frees up.", a.name)
                        },
                    )
                    .await;
                }
                return run;
            }
            Admit::Paused { until } => {
                run.skipped = Some(format!(
                    "paused after repeated failures, until {} (`00hooks automations resume` lifts it)",
                    crate::text::sanitize(&clock(until))
                ));
                return run;
            }
        }
        // Each automation reads the event, plus what its own "ask an agent" actions answered.
        let mut ctx = ctx.clone();
        for action in &a.actions {
            let (result, answer) = self.run_action(a, action, &ctx, e, batch, hop).await;
            let ok = result.ok;
            run.actions.push(result);
            if !ok {
                break;
            }
            if let (Some(answer), Value::Object(m)) = (answer, &mut ctx) {
                m.insert("agent".into(), answer);
            }
        }
        let ok = !run.failed();
        let now = self.now();
        match self
            .states
            .record(&a.name, ok, a.pause_after, a.pause_for, now)
        {
            Breaker::Paused { failures, until } => {
                self.tell(
                    "00hooks: automation paused",
                    format!(
                        "{:?} failed {failures} times in a row, so it's paused until {}. `00hooks automations resume {:?}` restarts it now.",
                        a.name,
                        clock(until),
                        a.name
                    ),
                )
                .await;
            }
            Breaker::Recovered => self.say(format!(
                "{:?} ran fine again; it's no longer paused.",
                a.name
            )),
            Breaker::Unchanged => {}
        }
        run
    }

    /// Run one action (with its retries). An "ask an agent" action also returns its answer, as
    /// `agent` reads it in the templates after it.
    async fn run_action(
        &mut self,
        a: &Automation,
        action: &Action,
        ctx: &Value,
        e: &Event,
        batch: Option<&BatchInput>,
        hop: u32,
    ) -> (ActionResult, Option<Value>) {
        let started = Instant::now();
        if let ActionKind::Ask {
            agent,
            instructions,
            profile,
            timeout,
        } = &action.kind
        {
            let req = AskRequest {
                automation: a.name.clone(),
                agent: agent.clone(),
                instructions: instructions.clone(),
                profile: profile.clone(),
                timeout: *timeout,
                event: e.clone(),
                hook: self.names.get(&e.hook_id).cloned(),
                kind: ctx["event"]["kind"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                payload: ctx["payload"].clone(),
                batch: batch.map(|b| AskBatch {
                    id: b.id.clone(),
                    count: b.count,
                    first_at: b.first_at,
                    last_at: b.last_at,
                    reason: b.reason.as_str().to_string(),
                    file: b.file.clone(),
                }),
            };
            let outcome = self.ask(req).await;
            let ms = started.elapsed().as_millis() as u64;
            return match outcome {
                Ok(r) => {
                    let output: String = r.reply.chars().take(crate::runs::MAX_OUTPUT).collect();
                    let answer = json!({"reply": r.reply, "id": r.agent_id, "name": r.agent_name});
                    (
                        ActionResult {
                            action: action.kind.label().into(),
                            ok: true,
                            attempts: 1,
                            ms,
                            error: None,
                            detail: Some(format!("answered by {}", r.agent_name)),
                            output: Some(output),
                        },
                        Some(answer),
                    )
                }
                Err(f) => (
                    ActionResult {
                        action: action.kind.label().into(),
                        ok: false,
                        attempts: 1,
                        ms,
                        error: Some(f.message),
                        detail: None,
                        output: None,
                    },
                    None,
                ),
            };
        }
        let mut attempts = 0;
        loop {
            attempts += 1;
            let outcome = self.exec(a, action, ctx, batch, hop).await;
            match outcome {
                Ok(detail) => {
                    return (
                        ActionResult {
                            action: action.kind.label().into(),
                            ok: true,
                            attempts,
                            ms: started.elapsed().as_millis() as u64,
                            error: None,
                            detail: Some(detail),
                            output: None,
                        },
                        None,
                    );
                }
                Err(Failure { message, retryable }) => {
                    if retryable && attempts <= action.retries {
                        let factor = 1u32 << (attempts - 1).min(10);
                        let wait = self
                            .opts
                            .retry_base
                            .saturating_mul(factor)
                            .min(Duration::from_secs(30));
                        tokio::time::sleep(wait).await;
                        continue;
                    }
                    return (
                        ActionResult {
                            action: action.kind.label().into(),
                            ok: false,
                            attempts,
                            ms: started.elapsed().as_millis() as u64,
                            error: Some(message),
                            detail: None,
                            output: None,
                        },
                        None,
                    );
                }
            }
        }
    }

    /// Ask the host's agent, within the action's time limit. Never retried: an agent's turn isn't
    /// safe to repeat.
    async fn ask(&self, req: AskRequest) -> Result<crate::ask::AskReply, Failure> {
        let Some(asker) = self.opts.asker.clone() else {
            return Err(Failure::fatal(
                "asking an agent needs a host that runs agents (a program that embeds the runner); the 00hooks CLI \
                 runs plain actions only",
            ));
        };
        let limit = req.timeout;
        match tokio::time::timeout(limit, asker.ask(req)).await {
            Ok(r) => r,
            Err(_) => Err(Failure::fatal(format!(
                "the agent didn't answer within {} minutes",
                limit.as_secs().div_ceil(60)
            ))),
        }
    }

    async fn exec(
        &mut self,
        a: &Automation,
        action: &Action,
        ctx: &Value,
        batch: Option<&BatchInput>,
        hop: u32,
    ) -> actions::Outcome {
        match &action.kind {
            ActionKind::Notify { title, body } => {
                if self.config.notify == NotifyMode::None {
                    return Ok("not shown (notify: none)".into());
                }
                let (t, b) = (title.render(ctx), body.render(ctx));
                let n = self.notifier();
                tokio::task::spawn_blocking(move || n.notify(&t, &b))
                    .await
                    .map_err(|e| Failure::retry(e.to_string()))?
                    .map_err(Failure::retry)?;
                Ok("shown".into())
            }
            ActionKind::Call {
                method,
                url,
                headers,
                body,
                idempotency_key,
                timeout,
            } => {
                let call = actions::call::Call {
                    method,
                    url,
                    headers,
                    body: body.as_ref(),
                    idempotency_key,
                    timeout: *timeout,
                    allow_hosts: &a.allow_hosts,
                    origin: &self.opts.origin,
                    hop,
                };
                actions::call::call(&self.http, &call, ctx, self.opts.secrets.as_ref()).await
            }
            ActionKind::Run {
                command,
                args,
                env,
                event,
                timeout,
                raw,
                options_end,
                ..
            } => {
                // Checked when the file was read; checked again here, where it matters.
                if !a.allow_commands.iter().any(|c| c == command) {
                    return Err(Failure::fatal(format!(
                        "{} isn't in allow_commands",
                        command.display()
                    )));
                }
                let args = actions::command::render_args(args, ctx, *raw, options_end.as_deref())?;
                let run = actions::command::Run {
                    program: command,
                    args,
                    env: env
                        .iter()
                        .map(|(k, t)| (k.clone(), t.render(ctx)))
                        .collect(),
                    event: *event,
                    timeout: *timeout,
                    batch: batch.map(|b| {
                        let mut jsonl = Vec::new();
                        for ev in &b.events {
                            serde_json::to_writer(&mut jsonl, ev).expect("json");
                            jsonl.push(b'\n');
                        }
                        actions::command::BatchFiles {
                            jsonl,
                            last: b.events.last().cloned().unwrap_or(Value::Null),
                            env: vec![
                                ("HOOKS_BATCH_ID".into(), b.id.clone()),
                                ("HOOKS_BATCH_COUNT".into(), b.count.to_string()),
                                ("HOOKS_BATCH_FIRST".into(), rfc3339(b.first_at)),
                                ("HOOKS_BATCH_LAST".into(), rfc3339(b.last_at)),
                                ("HOOKS_BATCH_REASON".into(), b.reason.as_str().into()),
                            ],
                        }
                    }),
                };
                actions::command::run(run, ctx).await
            }
            // A batch appends a line per event, in one write.
            ActionKind::Append { path, line } => match batch {
                Some(b) => {
                    let lines: Vec<Value> = b
                        .events
                        .iter()
                        .map(|ev| line.render(&b.context_of(ev)))
                        .collect();
                    actions::write::append_lines(path, &lines)
                }
                None => actions::write::append(path, &line.render(ctx)),
            },
            ActionKind::WriteFile {
                folder,
                name,
                content,
            } => actions::write::write_file(folder, &name.render(ctx), &content.render(ctx)),
            // Handled before the retry loop (`run_action`).
            ActionKind::Ask { .. } => Err(Failure::fatal("an ask action can't run here")),
        }
    }

    /// A hook changed (the stream's `hook-change`, PROTOCOL §6). Tells the person when a hook's
    /// secret was rotated by anyone but this device, or when a hook is created or renamed to a name
    /// the automations use; then keeps the hook names current (a pinned name keeps its id).
    pub async fn on_hook_change(&mut self, c: &HookChange) {
        let id = sanitize(&c.hook_id);
        let known = self.names.get(&c.hook_id).cloned();
        let label = match c.name.as_deref().or(known.as_deref()) {
            Some(n) => format!("{} ({id})", sanitize(n)),
            None => id.clone(),
        };
        let who = sanitize(&c.actor_words());
        let aliases = hookrefs::aliases(&self.config, &self.names);
        let taken = c
            .name
            .as_deref()
            .filter(|n| aliases.contains(*n))
            .map(str::to_string);
        match (c.change(), taken) {
            (HookChangeKind::Rotated, _) if c.by_device(&self.opts.origin) => {
                self.say(format!(
                    "Hook {label} had its secret rotated by this device."
                ));
            }
            (HookChangeKind::Rotated, _) => {
                self.tell(
                    "00hooks: a hook's secret was rotated",
                    format!(
                        "Hook {label} had its secret rotated by {who}. If that wasn't you, revoke \
                         it (`00hooks keys list`, `00hooks devices list`) and rotate the secret \
                         again."
                    ),
                )
                .await;
            }
            (kind @ (HookChangeKind::Created | HookChangeKind::Renamed), Some(name)) => {
                let shown = sanitize(&name);
                let what = match (kind, c.previous_name.as_deref()) {
                    (HookChangeKind::Created, _) => format!("Hook {id} was created as {shown:?}"),
                    (_, Some(prev)) => format!(
                        "Hook {id} was renamed from {:?} to {shown:?}",
                        sanitize(prev)
                    ),
                    _ => format!("Hook {id} was renamed to {shown:?}"),
                };
                let then = match self.pins.get(&name) {
                    Some(p) if p.id != c.hook_id => format!(
                        "The automations that use the name {shown:?} keep using {}, the hook it \
                         was pinned to; if {id} is the one you mean, write its id in the \
                         automations file.",
                        sanitize(&p.id)
                    ),
                    Some(_) => format!(
                        "It is the hook the automations that use the name {shown:?} already use."
                    ),
                    None => format!("The automations that use the name {shown:?} now use it."),
                };
                self.tell(
                    "00hooks: a hook took a name your automations use",
                    format!("{what} by {who}. {then}"),
                )
                .await;
            }
            (HookChangeKind::Created, None) => {
                self.say(format!("Hook {label} was created by {who}."))
            }
            (HookChangeKind::Renamed, None) => self.say(format!(
                "Hook {id} was renamed from {:?} to {:?} by {who}.",
                sanitize(
                    c.previous_name
                        .as_deref()
                        .or(known.as_deref())
                        .unwrap_or("?")
                ),
                sanitize(c.name.as_deref().unwrap_or("?"))
            )),
            (HookChangeKind::Deleted, _) => self.say(format!("Hook {label} was deleted by {who}.")),
            (HookChangeKind::Other, _) => self.say(format!(
                "Hook {label} changed ({}) by {who}.",
                sanitize(&c.kind)
            )),
        }
        let mut names = self.names.clone();
        match c.change() {
            HookChangeKind::Created | HookChangeKind::Renamed | HookChangeKind::Rotated => {
                if let Some(n) = &c.name {
                    names.insert(c.hook_id.clone(), n.clone());
                }
            }
            HookChangeKind::Deleted => {
                names.remove(&c.hook_id);
            }
            HookChangeKind::Other => {}
        }
        if let Err(e) = self.set_hook_names(names) {
            self.say(format!("Couldn't save the hook names: {e}"));
        }
    }

    /// Lift a pause on an automation.
    pub fn resume(&mut self, name: &str) -> Result<bool> {
        let r = self.states.resume(name);
        self.states.save()?;
        Ok(r)
    }
}

/// Whether any action of these automations does more than show a notification.
fn acts_beyond_notifying(triggered: &[&Automation]) -> bool {
    triggered.iter().any(|a| {
        a.actions
            .iter()
            .any(|x| !matches!(x.kind, ActionKind::Notify { .. }))
    })
}

fn list_or_none(v: &[String]) -> String {
    if v.is_empty() {
        "nothing".into()
    } else {
        v.join(", ")
    }
}

/// `2026-10-17 10:40 UTC`.
pub fn clock(ms: i64) -> String {
    let (y, m, d, h, min, _) = civil(ms);
    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02} UTC")
}

/// `2026-10-17T10:40:05.123Z` (RFC 3339, UTC): a batch's first and last times.
pub fn rfc3339(ms: i64) -> String {
    let (y, m, d, h, min, s) = civil(ms);
    format!(
        "{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{s:02}.{:03}Z",
        ms.rem_euclid(1000)
    )
}

/// Year, month, day, hour, minute, second (UTC).
fn civil(ms: i64) -> (i64, i64, i64, i64, i64, i64) {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // H. Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}
