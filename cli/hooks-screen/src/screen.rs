//! The screen itself: one decision per item, the quarantine list, and what the evaluator costs.
//!
//! The order (PLAN §6a): the source must have the screen on; then the rules you wrote, in order;
//! then learned rules, newest first; then, only for an item something would act on, the evaluator
//! (from its cache when the same item was evaluated before, within the source's daily cap, never for
//! a sensitive source with a decider that can't promise zero retention). When the evaluator fails,
//! times out or is over its cap, the item gets the source's fallback: **quarantine** when anything
//! beyond a notification would act on it (`Item::agent_bound`: an agent, a command, a call, a
//! file), **pass** only when nothing but a notification would; never a silent pass for an action.
//!
//! Kept in a private folder: `settings.json`, `rules.json` (rules and learned rules: field values
//! you chose, fingerprints, never an item), `held.json` (the quarantine list: held items with their
//! content until you decide, then only what was decided), `cache.json` (verdicts by fingerprint) and
//! `usage.json` (evaluations and cost per source, today).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::evaluator::{Answers, Decider, EvaluatorSettings, Request, Retention};
use crate::rules::{self, Compiled, Condition, FieldOp, Rule, View};
use crate::{Item, SourceKind, Verdict, now_ms, random_hex};

/// Held items wait this long by default, then are dropped.
pub const DEFAULT_HELD_DAYS: u32 = 30;
/// The evaluator's default daily cap per source.
pub const DEFAULT_DAILY_CAP: u32 = 100;
/// Decided items remembered (without their content).
const KEEP_DECIDED: usize = 200;
const MAX_HELD: usize = 1000;
const CACHE_MAX: usize = 2000;
const CACHE_TTL_MS: i64 = 30 * 86_400_000;
/// Match counts are written at most this often during a flood.
const SAVE_EVERY: Duration = Duration::from_secs(5);

/// One source type's (or one source's) screen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SourceSettings {
    pub enabled: bool,
    /// Ask the evaluator about what rules didn't settle.
    pub evaluate: bool,
    /// What an item gets when the evaluator can't answer; `None`: quarantine when anything beyond
    /// a notification would act on it (`Item::agent_bound`), pass when only a notification would.
    pub fallback: Option<Verdict>,
    /// Its content may only go to a decider that keeps nothing (local, or zero retention).
    pub sensitive: bool,
    /// Evaluations a day; past it, items get the fallback.
    pub daily_cap: u32,
}

impl Default for SourceSettings {
    fn default() -> Self {
        SourceSettings {
            enabled: false,
            evaluate: false,
            fallback: None,
            sensitive: false,
            daily_cap: DEFAULT_DAILY_CAP,
        }
    }
}

/// Pushing rules and fingerprints to the relay (optional, webhooks only).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EdgeSync {
    pub enabled: bool,
    /// The person agreed that `contains`, `pattern` and `similar text` rules go to the relay, which
    /// then reads those words.
    pub words: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// By `webhook`, `channel`, `routine`, or one source: `channel:telegram`, `webhook:hk_…`.
    pub sources: BTreeMap<String, SourceSettings>,
    pub evaluator: EvaluatorSettings,
    /// The similarity at or above which an item counts as the same (Jaccard, 0.5–1).
    pub similarity: f64,
    /// Learned rules expire after this many days without a match.
    pub expiry_days: u32,
    /// Held items are dropped after this many days.
    pub held_days: u32,
    pub edge: EdgeSync,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            sources: BTreeMap::new(),
            evaluator: EvaluatorSettings::default(),
            similarity: crate::minhash::DEFAULT_THRESHOLD,
            expiry_days: rules::DEFAULT_EXPIRY_DAYS,
            held_days: DEFAULT_HELD_DAYS,
            edge: EdgeSync::default(),
        }
    }
}

impl Settings {
    /// The settings for one source: its own, else its kind's, else off.
    pub fn source(&self, kind: SourceKind, id: &str) -> SourceSettings {
        self.sources
            .get(&format!("{}:{id}", kind.as_str()))
            .or_else(|| self.sources.get(kind.as_str()))
            .cloned()
            .unwrap_or_default()
    }

    pub fn check(&self) -> Result<(), String> {
        self.evaluator.check()?;
        if !(0.5..=1.0).contains(&self.similarity) {
            return Err("the similarity threshold is from 0.5 to 1".into());
        }
        if !(1..=3650).contains(&self.expiry_days) {
            return Err("learned rules expire after 1 to 3,650 days".into());
        }
        if !(1..=365).contains(&self.held_days) {
            return Err("held items wait 1 to 365 days".into());
        }
        for (k, s) in &self.sources {
            let kind = k.split(':').next().unwrap_or("");
            if !matches!(kind, "webhook" | "channel" | "routine") || k.len() > 100 {
                return Err(format!("{k} isn't a source"));
            }
            if s.daily_cap > 100_000 {
                return Err("a daily cap is at most 100,000 evaluations".into());
            }
        }
        Ok(())
    }
}

/// What settled an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum By {
    /// The screen is off for this source.
    Off,
    /// A rule you wrote.
    Rule,
    /// A learned rule (Always…, Block on fields…).
    Learned,
    /// The evaluator.
    Evaluator,
    /// The evaluator, earlier, for the same item.
    Cache,
    /// The evaluator couldn't answer (failed, timed out, over its cap, refused for privacy).
    Fallback,
    /// Nothing matched and the evaluator wasn't asked.
    Default,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub verdict: Verdict,
    pub by: By,
    /// One sentence: the rule's name, the evaluator's reason, why it fell back.
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answers: Option<Answers>,
}

impl Decision {
    fn new(verdict: Verdict, by: By, reason: impl Into<String>) -> Decision {
        Decision {
            verdict,
            by,
            reason: reason.into(),
            rule: None,
            answers: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldState {
    Held,
    Released,
    Dropped,
    /// Waited past `held_days`: dropped without a decision.
    Expired,
}

/// One field of a held item, for the field-rule picker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldValue {
    pub path: String,
    pub value: String,
}

/// An item in the quarantine list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Held {
    pub id: String,
    /// The item; its content is cleared once it is decided.
    pub item: Item,
    pub decision: Decision,
    pub held_at: i64,
    pub state: HeldState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<i64>,
    /// What the host needs to deliver it on release (an event id, a thread and message).
    #[serde(default)]
    pub host: Value,
    /// Its fingerprint, kept after the content goes, for *Always … similar*.
    pub fingerprint: Condition,
    /// Its fields and values while it is held, for *Block on fields…*.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldValue>,
}

/// A field to block (or pass) on, as picked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldPick {
    pub path: String,
    pub op: FieldOp,
    /// For `one of`: the list (the item's own value when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceUsage {
    pub evaluations: u32,
    /// What they cost, as the providers reported it (USD).
    pub cost: f64,
    /// Items that got the fallback.
    pub fallbacks: u32,
    pub cached: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Usage {
    /// Days since the epoch (UTC).
    day: i64,
    sources: BTreeMap<String, SourceUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Cached {
    verdict: Verdict,
    reason: String,
    answers: Option<Answers>,
    at: i64,
}

struct State {
    settings: Settings,
    rules: Vec<Rule>,
    compiled: Vec<Compiled>,
    held: Vec<Held>,
    cache: BTreeMap<String, Cached>,
    usage: Usage,
    rules_saved: Instant,
    rules_dirty: bool,
}

/// The screen: shared by every source of a host (wrap it in an `Arc`).
pub struct Screen {
    dir: PathBuf,
    state: Mutex<State>,
    decider: Mutex<Option<Arc<dyn Decider>>>,
    /// When this screen last wrote (or read) each file: another process's change is read again.
    stamps: Mutex<BTreeMap<&'static str, Option<std::time::SystemTime>>>,
}

fn stamp(p: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

fn read<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T, String> {
    match std::fs::read(path) {
        Ok(b) => {
            serde_json::from_slice(&b).map_err(|e| format!("{} is damaged: {e}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("couldn't read {}: {e}", path.display())),
    }
}

fn day(ms: i64) -> i64 {
    ms.div_euclid(86_400_000)
}

fn compile_all(rules: &[Rule]) -> Vec<Compiled> {
    rules
        .iter()
        .filter_map(|r| Compiled::new(r.clone()).ok())
        .collect()
}

/// The cache key of an item: its source and what similarity sees of it, hashed.
pub fn cache_key(item: &Item) -> String {
    let mut h = Sha256::new();
    h.update(item.source.kind.as_str());
    h.update([0]);
    h.update(&item.source.id);
    h.update([0]);
    h.update(crate::shape::shape_hash(&item.payload));
    h.update([0]);
    h.update(item.similarity_text());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

impl Screen {
    /// Open (or start) a screen kept in `dir`. A damaged file is an error rather than a screen that
    /// silently forgot its rules.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Screen, String> {
        let dir = dir.into();
        hooks_client::fsutil::create_private_dir(&dir).map_err(|e| e.to_string())?;
        let settings: Settings = read(&dir.join("settings.json"))?;
        let rules: Vec<Rule> = read(&dir.join("rules.json"))?;
        let held: Vec<Held> = read(&dir.join("held.json"))?;
        // A damaged cache or usage file costs nothing to forget.
        let cache = read(&dir.join("cache.json")).unwrap_or_default();
        let usage = read(&dir.join("usage.json")).unwrap_or_default();
        let compiled = compile_all(&rules);
        let s = Screen {
            dir,
            state: Mutex::new(State {
                settings,
                compiled,
                rules,
                held,
                cache,
                usage,
                rules_saved: Instant::now(),
                rules_dirty: false,
            }),
            decider: Mutex::new(None),
            stamps: Mutex::new(BTreeMap::new()),
        };
        s.note_stamps();
        s.prune(now_ms());
        Ok(s)
    }

    fn note_stamps(&self) {
        let mut st = self.stamps.lock().unwrap_or_else(|p| p.into_inner());
        for f in ["settings.json", "rules.json", "held.json"] {
            st.insert(f, stamp(&self.dir.join(f)));
        }
    }

    /// Read again what another process (the CLI, while a runner runs) changed on disk.
    pub fn refresh(&self) {
        let changed: Vec<&'static str> = {
            let st = self.stamps.lock().unwrap_or_else(|p| p.into_inner());
            ["settings.json", "rules.json", "held.json"]
                .into_iter()
                .filter(|f| st.get(f).copied().flatten() != stamp(&self.dir.join(f)))
                .collect()
        };
        if changed.is_empty() {
            return;
        }
        let mut state = self.lock();
        for f in &changed {
            let path = self.dir.join(f);
            match *f {
                "settings.json" => {
                    if let Ok(v) = read::<Settings>(&path) {
                        state.settings = v;
                    }
                }
                "rules.json" => {
                    if let Ok(v) = read::<Vec<Rule>>(&path) {
                        state.compiled = compile_all(&v);
                        state.rules = v;
                        state.rules_dirty = false;
                    }
                }
                _ => {
                    if let Ok(v) = read::<Vec<Held>>(&path) {
                        state.held = v;
                    }
                }
            }
        }
        drop(state);
        self.note_stamps();
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn write<T: Serialize>(&self, name: &'static str, v: &T) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?;
        let path = self.dir.join(name);
        hooks_client::fsutil::write_atomic(&path, &bytes, true).map_err(|e| e.to_string())?;
        self.stamps
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(name, stamp(&path));
        Ok(())
    }

    fn save_rules(&self, st: &mut State) -> Result<(), String> {
        st.rules_saved = Instant::now();
        st.rules_dirty = false;
        self.write("rules.json", &st.rules)
    }

    /// Write what's waiting (match counts kept back during a flood).
    pub fn flush(&self) -> Result<(), String> {
        let mut st = self.lock();
        if st.rules_dirty {
            self.save_rules(&mut st)?;
        }
        Ok(())
    }

    /// The decider the evaluator settings name; the host builds it (it holds the key).
    pub fn set_decider(&self, d: Option<Arc<dyn Decider>>) {
        *self.decider.lock().unwrap_or_else(|p| p.into_inner()) = d;
    }

    pub fn decider(&self) -> Option<Arc<dyn Decider>> {
        self.decider
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn settings(&self) -> Settings {
        self.lock().settings.clone()
    }

    pub fn set_settings(&self, s: Settings) -> Result<(), String> {
        s.check()?;
        let mut st = self.lock();
        self.write("settings.json", &s)?;
        st.settings = s;
        Ok(())
    }

    pub fn rules(&self) -> Vec<Rule> {
        self.lock().rules.clone()
    }

    /// Add a rule, or replace the one with its id (keeping its match history).
    pub fn put_rule(&self, mut rule: Rule) -> Result<Rule, String> {
        Compiled::new(rule.clone())?;
        let mut st = self.lock();
        let now = now_ms();
        match st.rules.iter_mut().find(|r| r.id == rule.id) {
            Some(old) => {
                rule.created_at = old.created_at;
                rule.matches = old.matches;
                rule.last_matched_at = old.last_matched_at;
                rule.learned = rule.learned.or_else(|| old.learned.clone());
                *old = rule.clone();
            }
            None => {
                if st.rules.len() >= rules::MAX_RULES {
                    return Err(format!(
                        "the screen holds at most {} rules",
                        rules::MAX_RULES
                    ));
                }
                if rule.created_at == 0 {
                    rule.created_at = now;
                }
                st.rules.push(rule.clone());
            }
        }
        st.compiled = compile_all(&st.rules);
        self.save_rules(&mut st)?;
        Ok(rule)
    }

    pub fn remove_rule(&self, id: &str) -> Result<bool, String> {
        let mut st = self.lock();
        let before = st.rules.len();
        st.rules.retain(|r| r.id != id);
        if st.rules.len() == before {
            return Ok(false);
        }
        st.compiled = compile_all(&st.rules);
        self.save_rules(&mut st)?;
        Ok(true)
    }

    /// Switch a rule on (*Always*) or *Off*. Switching a learned rule on again starts its expiry
    /// afresh.
    pub fn set_rule_enabled(&self, id: &str, on: bool) -> Result<Rule, String> {
        let mut st = self.lock();
        let now = now_ms();
        let r = st
            .rules
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or("there's no such rule")?;
        r.enabled = on;
        if on && r.learned.is_some() {
            r.last_matched_at = Some(now);
        }
        let out = r.clone();
        st.compiled = compile_all(&st.rules);
        self.save_rules(&mut st)?;
        Ok(out)
    }

    /// The first rule that holds: your rules in order, then learned rules, newest first.
    fn match_rule(&self, item: &Item) -> Option<Decision> {
        let mut st = self.lock();
        let now = now_ms();
        let days = st.settings.expiry_days;
        let kind = item.source.kind.as_str();
        let mut view = View::default();
        let mut order: Vec<usize> = (0..st.compiled.len())
            .filter(|i| st.compiled[*i].rule.learned.is_none())
            .collect();
        let mut learned: Vec<usize> = (0..st.compiled.len())
            .filter(|i| st.compiled[*i].rule.learned.is_some())
            .collect();
        learned.sort_by_key(|i| std::cmp::Reverse(st.compiled[*i].rule.created_at));
        order.extend(learned);
        let hit = order.into_iter().find(|i| {
            let c = &st.compiled[*i];
            c.rule.enabled
                && !c.rule.expired(now, days)
                && c.rule.applies_to(kind, &item.source.id)
                && c.test(item, &mut view)
        })?;
        let rule = st.compiled[hit].rule.clone();
        if let Some(r) = st.rules.iter_mut().find(|r| r.id == rule.id) {
            r.matches += 1;
            r.last_matched_at = Some(now);
        }
        if let Some(c) = st.compiled.get_mut(hit) {
            c.rule.last_matched_at = Some(now);
        }
        st.rules_dirty = true;
        if st.rules_saved.elapsed() >= SAVE_EVERY {
            let _ = self.save_rules(&mut st);
        }
        let mut d = Decision::new(
            rule.verdict,
            if rule.learned.is_some() {
                By::Learned
            } else {
                By::Rule
            },
            match &rule.learned {
                Some(l) => format!(
                    "{} (learned from {} on {})",
                    rule.name,
                    l.summary,
                    date(l.at)
                ),
                None => rule.name.clone(),
            },
        );
        d.rule = Some(rule.id);
        Some(d)
    }

    fn count(&self, item: &Item, f: impl FnOnce(&mut SourceUsage)) -> SourceUsage {
        let mut st = self.lock();
        let today = day(now_ms());
        if st.usage.day != today {
            st.usage = Usage {
                day: today,
                sources: BTreeMap::new(),
            };
        }
        let key = format!("{}:{}", item.source.kind.as_str(), item.source.id);
        let u = st.usage.sources.entry(key).or_default();
        f(u);
        let out = u.clone();
        let usage = st.usage.clone();
        drop(st);
        let _ = self.write("usage.json", &usage);
        out
    }

    /// Evaluations and cost per source today (`webhook:hk_…`, `channel:telegram`).
    pub fn usage(&self) -> BTreeMap<String, SourceUsage> {
        let st = self.lock();
        if st.usage.day == day(now_ms()) {
            st.usage.sources.clone()
        } else {
            BTreeMap::new()
        }
    }

    /// Decide what happens to an item. Never fails: what went wrong is the reason of a fallback.
    pub async fn check(&self, item: &Item) -> Decision {
        self.refresh();
        let (settings, evaluator) = {
            let st = self.lock();
            (
                st.settings.source(item.source.kind, &item.source.id),
                st.settings.evaluator.clone(),
            )
        };
        if !settings.enabled {
            return Decision::new(Verdict::Pass, By::Off, "the screen is off for this source");
        }
        if let Some(d) = self.match_rule(item) {
            return d;
        }
        let decider = self.decider();
        let Some(decider) = decider.filter(|_| settings.evaluate) else {
            return Decision::new(Verdict::Pass, By::Default, "no rule matched");
        };
        if !item.consequential {
            return Decision::new(
                Verdict::Pass,
                By::Default,
                "no rule matched, and nothing would act on it",
            );
        }
        let fallback = |why: String| {
            let v = settings.fallback.unwrap_or(if item.agent_bound {
                Verdict::Quarantine
            } else {
                Verdict::Pass
            });
            Decision::new(v, By::Fallback, why)
        };
        let key = cache_key(item);
        let cached = {
            let st = self.lock();
            st.cache
                .get(&key)
                .filter(|c| now_ms() - c.at < CACHE_TTL_MS)
                .cloned()
        };
        if let Some(c) = cached {
            self.count(item, |u| u.cached += 1);
            let mut d = Decision::new(
                c.verdict,
                By::Cache,
                format!("{} (an earlier evaluation of the same item)", c.reason),
            );
            d.answers = c.answers;
            return d;
        }
        if settings.sensitive && decider.retention() == Retention::Unknown {
            self.count(item, |u| u.fallbacks += 1);
            return fallback(format!(
                "this source is sensitive and {} can't promise to keep nothing, so it wasn't asked",
                decider.name()
            ));
        }
        let used = self
            .usage()
            .get(&format!("{}:{}", item.source.kind.as_str(), item.source.id))
            .cloned()
            .unwrap_or_default();
        if used.evaluations >= settings.daily_cap {
            self.count(item, |u| u.fallbacks += 1);
            return fallback(format!(
                "the evaluator's daily cap ({}) for this source is reached",
                settings.daily_cap
            ));
        }
        let req = Request::for_item(item);
        let limit = Duration::from_millis(evaluator.timeout_ms.max(1000));
        let answered = tokio::time::timeout(limit, decider.decide(&req)).await;
        let answers = match answered {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => {
                self.count(item, |u| {
                    u.evaluations += 1;
                    u.fallbacks += 1;
                });
                return fallback(format!("the evaluator failed ({e})"));
            }
            Err(_) => {
                self.count(item, |u| {
                    u.evaluations += 1;
                    u.fallbacks += 1;
                });
                return fallback(format!(
                    "the evaluator didn't answer within {} s",
                    limit.as_secs()
                ));
            }
        };
        let cost = answers.cost.unwrap_or(0.0);
        self.count(item, |u| {
            u.evaluations += 1;
            u.cost += cost;
        });
        let (verdict, reason) = evaluator.thresholds.verdict(&answers);
        {
            let mut st = self.lock();
            st.cache.insert(
                key,
                Cached {
                    verdict,
                    reason: reason.clone(),
                    answers: Some(answers.clone()),
                    at: now_ms(),
                },
            );
            if st.cache.len() > CACHE_MAX {
                let mut by_age: Vec<(String, i64)> =
                    st.cache.iter().map(|(k, c)| (k.clone(), c.at)).collect();
                by_age.sort_by_key(|(_, at)| *at);
                for (k, _) in by_age.into_iter().take(st.cache.len() - CACHE_MAX) {
                    st.cache.remove(&k);
                }
            }
            let cache = st.cache.clone();
            drop(st);
            let _ = self.write("cache.json", &cache);
        }
        let mut d = Decision::new(verdict, By::Evaluator, reason);
        d.answers = Some(answers);
        d
    }

    /// Put an item in the quarantine list. `host` is what the host needs to deliver it on release.
    pub fn hold(&self, item: &Item, decision: &Decision, host: Value) -> Result<Held, String> {
        let similarity = self.lock().settings.similarity;
        let mut fingerprint = rules::fingerprint(item);
        if let Condition::Similar { threshold, .. } = &mut fingerprint {
            *threshold = Some(similarity);
        }
        let h = Held {
            id: format!("hld_{}", random_hex()),
            item: item.clone(),
            decision: decision.clone(),
            held_at: now_ms(),
            state: HeldState::Held,
            decided_at: None,
            host,
            fingerprint,
            fields: rules::item_fields(item)
                .into_iter()
                .map(|(path, value)| FieldValue { path, value })
                .collect(),
        };
        let mut st = self.lock();
        let waiting = st
            .held
            .iter()
            .filter(|h| h.state == HeldState::Held)
            .count();
        if waiting >= MAX_HELD {
            return Err(format!(
                "the quarantine list is full ({MAX_HELD} items wait); release or drop some"
            ));
        }
        st.held.push(h.clone());
        let held = st.held.clone();
        drop(st);
        self.write("held.json", &held)?;
        Ok(h)
    }

    /// Items waiting, newest first.
    pub fn held(&self) -> Vec<Held> {
        self.refresh();
        let st = self.lock();
        let mut v: Vec<Held> = st
            .held
            .iter()
            .filter(|h| h.state == HeldState::Held)
            .cloned()
            .collect();
        v.sort_by_key(|h| std::cmp::Reverse(h.held_at));
        v
    }

    /// Items decided recently (without their content), newest first.
    pub fn decided(&self) -> Vec<Held> {
        let st = self.lock();
        let mut v: Vec<Held> = st
            .held
            .iter()
            .filter(|h| h.state != HeldState::Held)
            .cloned()
            .collect();
        v.sort_by_key(|h| std::cmp::Reverse(h.decided_at.unwrap_or(h.held_at)));
        v
    }

    pub fn get(&self, id: &str) -> Option<Held> {
        self.lock().held.iter().find(|h| h.id == id).cloned()
    }

    /// Settle a held item once. Returns it as it was held (content and `host` included), so the
    /// host can deliver a released one; what stays in the list keeps no content.
    fn decide(&self, id: &str, to: HeldState) -> Result<Held, String> {
        self.refresh();
        let mut st = self.lock();
        let h = st
            .held
            .iter_mut()
            .find(|h| h.id == id)
            .ok_or("there's no such held item")?;
        if h.state != HeldState::Held {
            return Err(match h.state {
                HeldState::Released => "it was already released".into(),
                HeldState::Dropped => "it was already dropped".into(),
                _ => "it waited too long and was dropped".to_string(),
            });
        }
        let out = h.clone();
        h.state = to;
        h.decided_at = Some(now_ms());
        h.host = Value::Null;
        h.item.payload = Value::Null;
        h.item.headers.clear();
        h.fields.clear();
        let mut held = st.held.clone();
        drop(st);
        trim_decided(&mut held);
        self.write("held.json", &held)?;
        self.lock().held = held;
        Ok(out)
    }

    /// Release a held item: it is delivered now, by the host, once.
    pub fn release(&self, id: &str) -> Result<Held, String> {
        self.decide(id, HeldState::Released)
    }

    pub fn drop_held(&self, id: &str) -> Result<Held, String> {
        self.decide(id, HeldState::Dropped)
    }

    /// *Always pass/quarantine/drop similar*: a learned rule from a held item's fingerprint, for its
    /// source.
    pub fn always(&self, id: &str, verdict: Verdict) -> Result<Rule, String> {
        let h = self.get(id).ok_or("there's no such held item")?;
        let rule = Rule {
            id: format!("lr_{}", random_hex()),
            name: format!(
                "{} items like {}",
                verdict.label(),
                crate::cut(&h.item.summary, 60)
            ),
            verdict,
            any: false,
            conditions: vec![h.fingerprint.clone()],
            enabled: true,
            sources: vec![format!(
                "{}:{}",
                h.item.source.kind.as_str(),
                h.item.source.id
            )],
            learned: Some(rules::Learned {
                from: h.id.clone(),
                summary: crate::cut(&h.item.summary, 80),
                at: now_ms(),
            }),
            created_at: now_ms(),
            last_matched_at: None,
            matches: 0,
            edge: h.item.source.kind == SourceKind::Webhook && self.settings().edge.enabled,
        };
        self.put_rule(rule)
    }

    /// *Block on fields…*: a learned rule from fields of a held item, joined by and (`any: false`)
    /// or or.
    pub fn rule_from_fields(
        &self,
        id: &str,
        picks: &[FieldPick],
        any: bool,
        verdict: Verdict,
    ) -> Result<Rule, String> {
        let h = self.get(id).ok_or("there's no such held item")?;
        if h.state != HeldState::Held {
            return Err(
                "its content is gone once it is decided; pick fields while it is held".into(),
            );
        }
        if picks.is_empty() {
            return Err("pick at least one field".into());
        }
        let conditions = picks
            .iter()
            .map(|p| rules::field_condition(&h.item, &p.path, p.op, p.values.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let names: Vec<String> = picks
            .iter()
            .map(|p| format!("{} {}", p.path, p.op.label()))
            .collect();
        let rule = Rule {
            id: format!("lr_{}", random_hex()),
            name: crate::cut(
                &format!(
                    "{} when {}",
                    verdict.label(),
                    names.join(if any { " or " } else { " and " })
                ),
                rules::MAX_NAME,
            ),
            verdict,
            any,
            conditions,
            enabled: true,
            sources: vec![format!(
                "{}:{}",
                h.item.source.kind.as_str(),
                h.item.source.id
            )],
            learned: Some(rules::Learned {
                from: h.id.clone(),
                summary: crate::cut(&h.item.summary, 80),
                at: now_ms(),
            }),
            created_at: now_ms(),
            last_matched_at: None,
            matches: 0,
            edge: false,
        };
        self.put_rule(rule)
    }

    /// Forget expired learned rules, drop held items past their wait, trim the cache.
    pub fn prune(&self, now: i64) {
        let mut st = self.lock();
        let days = st.settings.expiry_days;
        let before = st.rules.len();
        st.rules.retain(|r| !r.expired(now, days));
        if st.rules.len() != before {
            st.compiled = compile_all(&st.rules);
            let _ = self.save_rules(&mut st);
        }
        let wait = i64::from(st.settings.held_days) * 86_400_000;
        let mut changed = false;
        for h in st.held.iter_mut() {
            if h.state == HeldState::Held && now - h.held_at > wait {
                h.state = HeldState::Expired;
                h.decided_at = Some(now);
                h.host = Value::Null;
                h.item.payload = Value::Null;
                h.item.headers.clear();
                h.fields.clear();
                changed = true;
            }
        }
        if changed {
            let mut held = st.held.clone();
            trim_decided(&mut held);
            st.held = held.clone();
            let _ = self.write("held.json", &held);
        }
        st.cache.retain(|_, c| now - c.at < CACHE_TTL_MS);
    }
}

fn trim_decided(held: &mut Vec<Held>) {
    let decided = held.iter().filter(|h| h.state != HeldState::Held).count();
    if decided <= KEEP_DECIDED {
        return;
    }
    let mut extra = decided - KEEP_DECIDED;
    held.sort_by_key(|h| h.decided_at.unwrap_or(h.held_at));
    held.retain(|h| {
        if extra > 0 && h.state != HeldState::Held {
            extra -= 1;
            false
        } else {
            true
        }
    });
}

/// `12 October 2026`.
pub fn date(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    format!("{d} {} {y}", MONTHS[(m - 1) as usize])
}
