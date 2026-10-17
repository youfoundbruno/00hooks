//! The runner: one event in, a run record out. See the crate docs for the steps.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use hooks_client::Event;
use hooks_screen::{Screen, SourceKind, Verdict};
use serde_json::{Value, json};

use crate::actions::{self, Failure, Notifier, NullNotifier, SystemNotifier};
use crate::ask::{AskRequest, Asker};
use crate::catalogue::{Catalogue, Observation};
use crate::config::{
    Action, ActionKind, Automation, Automations, NotifyMode, Trigger, describe_rate, hook_matches,
};
use crate::runs::{ActionResult, AutomationRun, RunLog, RunRecord, RunStatus};
use crate::secrets::SecretStore;
use crate::state::{Admit, Breaker, States};
use crate::{Error, HOP_HEADER, ORIGIN_HEADER, Result, context, now_ms};

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
    states: States,
    http: reqwest::Client,
    names: BTreeMap<String, String>,
    catch_up: Option<CatchUp>,
    log: Vec<String>,
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

    /// Open the runner's store with automations the host keeps as data (00next), instead of
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
            states: States::open(&opts.dir)?,
            http: actions::call::http_client(),
            names: load_names(&opts.dir),
            catch_up: None,
            log: Vec::new(),
            config,
            opts,
        };
        for rec in r.runs.interrupted.clone() {
            r.say(format!(
                "Run {} of event {} was interrupted when the runner last stopped; it wasn't run \
                 again. `00hooks replay {}` runs it.",
                rec.run, rec.event_id, rec.event_id
            ));
        }
        r.apply_structure_only()?;
        Ok(r)
    }

    pub fn config(&self) -> &Automations {
        &self.config
    }

    /// Replace the automations (a host that keeps them as data).
    pub fn set_automations(&mut self, automations: Automations) {
        self.config = automations;
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

    /// Hook names by id (from the relay); cached on disk.
    pub fn set_hook_names(&mut self, names: BTreeMap<String, String>) -> Result<()> {
        if names != self.names {
            let bytes = serde_json::to_vec_pretty(&names).expect("json");
            hooks_client::fsutil::write_atomic(&self.opts.dir.join("hooks.json"), &bytes, true)
                .map_err(Error::from_client)?;
            self.names = names;
            self.apply_structure_only()?;
        }
        Ok(())
    }

    pub fn hook_names(&self) -> &BTreeMap<String, String> {
        &self.names
    }

    fn apply_structure_only(&mut self) -> Result<()> {
        let ids: HashSet<String> = self
            .catalogue
            .kinds()
            .map(|k| k.hook_id.clone())
            .filter(|id| self.config.structure_only(id, &self.names))
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
    /// from, and whether an agent (or anything) would act on it.
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
            agent_bound: triggered.iter().any(|a| {
                a.actions
                    .iter()
                    .any(|x| matches!(x.kind, ActionKind::Ask { .. }))
            }),
            consequential: !triggered.is_empty(),
            purpose: (!names.is_empty())
                .then(|| format!("events for these automations: {}", names.join("; "))),
            summary: crate::text::cut(&crate::text::sanitize(&format!("{kind} from {hook}")), 120),
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

        let payload = context::payload(e);
        let kind = context::kind_name(e, &payload);
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

        let observation = if replay {
            Observation {
                key: crate::catalogue::key(&e.hook_id, &kind),
                new_kind: false,
                change: None,
            }
        } else {
            let so = self.config.structure_only(&e.hook_id, &self.names);
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
                    }
                }
            }
        };
        let label = format!("{}/{}", hook_name.as_deref().unwrap_or(&e.hook_id), kind);
        if observation.new_kind {
            self.say(format!("New kind: {label}"));
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
        } else {
            RunStatus::Ok
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
            note: released.then(|| "released from the screen's quarantine list".to_string()),
            new_kind: observation.new_kind,
            shape_change: observation.change,
            automations: autos,
            held: None,
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
        if let Some(h) = &a.when.hook
            && !hook_matches(h, &e.hook_id, &self.names)
        {
            return None;
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
        let now = now_ms();
        match self.states.admit(&a.name, a.rate_limit, now) {
            Admit::Run => {}
            Admit::RateLimited { tell } => {
                let rate = describe_rate(a.rate_limit);
                run.skipped = Some(format!("its rate limit ({rate}) is reached"));
                if tell {
                    self.tell(
                        "00hooks: rate limit",
                        format!("{:?} reached its rate limit ({rate}); matching events are skipped until it frees up.", a.name),
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
            let (result, answer) = self.run_action(a, action, &ctx, e, hop).await;
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
        match self
            .states
            .record(&a.name, ok, a.pause_after, a.pause_for, now_ms())
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
            let outcome = self.exec(a, action, ctx, hop).await;
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
                "asking an agent needs a host that runs agents, such as 00next; the 00hooks CLI \
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
                ..
            } => {
                // Checked when the file was read; checked again here, where it matters.
                if !a.allow_commands.iter().any(|c| c == command) {
                    return Err(Failure::fatal(format!(
                        "{} isn't in allow_commands",
                        command.display()
                    )));
                }
                let run = actions::command::Run {
                    program: command,
                    args: args.iter().map(|t| t.render(ctx)).collect(),
                    env: env
                        .iter()
                        .map(|(k, t)| (k.clone(), t.render(ctx)))
                        .collect(),
                    event: *event,
                    timeout: *timeout,
                };
                actions::command::run(run, ctx).await
            }
            ActionKind::Append { path, line } => actions::write::append(path, &line.render(ctx)),
            ActionKind::WriteFile {
                folder,
                name,
                content,
            } => actions::write::write_file(folder, &name.render(ctx), &content.render(ctx)),
            // Handled before the retry loop (`run_action`).
            ActionKind::Ask { .. } => Err(Failure::fatal("an ask action can't run here")),
        }
    }

    /// Lift a pause on an automation.
    pub fn resume(&mut self, name: &str) -> Result<bool> {
        let r = self.states.resume(name);
        self.states.save()?;
        Ok(r)
    }
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
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60
    )
}
