//! `automations.yaml`: what to do when events arrive. Parsed into typed automations with every
//! problem reported at once, each naming its line, in plain words.
//!
//! ```yaml
//! version: 1
//! notify: system              # or `none`: notifications are only recorded in the run log
//! hooks:                      # optional per-hook settings, by name or id
//!   payments:
//!     structure_only: true    # the catalogue keeps no sample and no values for this hook
//! automations:
//!   - name: Triage new issues
//!     when:
//!       hook: github          # a hook's name or id
//!       kinds: [issues]       # or `any`; or `new_kind: true` / `shape_changed: true`
//!     only_if: payload.action == "opened" and payload.issue.comments < 5
//!     verified_only: true     # the default
//!     rate_limit: 30/hour     # the default
//!     allow_hosts: [api.example.com]
//!     allow_commands: [/usr/bin/say]
//!     then:
//!       - notify: "#{{payload.issue.number}} {{payload.issue.title | truncate:60}}"
//!       - call:
//!           url: https://api.example.com/triage
//!           headers: { Authorization: "Bearer {{secret.TRIAGE_TOKEN}}" }
//!           body: { number: "{{payload.issue.number}}" }
//!       - run: { command: /usr/bin/say, args: ["New issue {{payload.issue.number}}"] }
//!       - write: { append: ~/hooks/issues.jsonl }
//! ```

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::expr::Filter;
use crate::path::{self as fpath};
use crate::template::{JsonTemplate, Scope, Template};
use crate::yaml::{self, Kind, Node};

/// The default `rate_limit`: 30 runs an hour.
pub const DEFAULT_RATE: RateLimit = RateLimit {
    max: 30,
    per: Duration::from_secs(3600),
};
/// Failed runs in a row before an automation is paused.
pub const DEFAULT_PAUSE_AFTER: u32 = 5;
/// How long a paused automation waits before trying again.
pub const DEFAULT_PAUSE_FOR: Duration = Duration::from_secs(15 * 60);
const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_RUN_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_TIMEOUT: Duration = Duration::from_secs(3600);
const MAX_RETRIES: u32 = 10;

/// One problem in the file.
#[derive(Debug, Clone, PartialEq)]
pub struct Problem {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyMode {
    System,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub max: u32,
    pub per: Duration,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Trigger {
    /// These kinds (any kind when empty).
    Kinds(Vec<String>),
    /// A kind seen for the first time.
    NewKind,
    /// A known kind gained or lost fields (these kinds; any when empty).
    ShapeChanged(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct When {
    /// A hook's name or id; `None` for any hook.
    pub hook: Option<String>,
    pub trigger: Trigger,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventInput {
    Stdin,
    File,
    None,
}

#[derive(Debug, Clone)]
pub enum ActionKind {
    Notify {
        title: Template,
        body: Template,
    },
    Call {
        method: String,
        url: Template,
        headers: Vec<(String, Template)>,
        body: Option<JsonTemplate>,
        idempotency_key: Template,
        timeout: Duration,
    },
    Run {
        command: PathBuf,
        args: Vec<Template>,
        env: Vec<(String, Template)>,
        event: EventInput,
        timeout: Duration,
        idempotent: bool,
    },
    Append {
        path: PathBuf,
        line: JsonTemplate,
    },
    WriteFile {
        folder: PathBuf,
        name: Template,
        content: JsonTemplate,
    },
}

impl ActionKind {
    pub fn label(&self) -> &'static str {
        match self {
            ActionKind::Notify { .. } => "notify",
            ActionKind::Call { .. } => "call",
            ActionKind::Run { .. } => "run",
            ActionKind::Append { .. } | ActionKind::WriteFile { .. } => "write",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Action {
    pub kind: ActionKind,
    /// Extra attempts after a failure, for actions that are safe to repeat.
    pub retries: u32,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct Automation {
    pub name: String,
    pub line: usize,
    pub enabled: bool,
    pub when: When,
    pub only_if: Option<Filter>,
    pub only_if_line: usize,
    pub verified_only: bool,
    pub rate_limit: Option<RateLimit>,
    pub pause_after: u32,
    pub pause_for: Duration,
    pub allow_hosts: Vec<String>,
    pub allow_commands: Vec<PathBuf>,
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone)]
pub struct HookSettings {
    pub hook: String,
    pub structure_only: bool,
    pub line: usize,
}

/// A whole, valid automations file.
#[derive(Debug, Clone)]
pub struct Automations {
    pub path: PathBuf,
    pub notify: NotifyMode,
    pub hooks: Vec<HookSettings>,
    pub automations: Vec<Automation>,
}

impl Automations {
    pub fn empty(path: impl Into<PathBuf>) -> Automations {
        Automations {
            path: path.into(),
            notify: NotifyMode::System,
            hooks: Vec::new(),
            automations: Vec::new(),
        }
    }

    /// Read and parse a file. A missing file is an empty configuration.
    pub fn load(path: &Path) -> Result<Automations, Vec<Problem>> {
        match std::fs::read_to_string(path) {
            Ok(text) => parse(&text, path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Automations::empty(path)),
            Err(e) => Err(vec![Problem {
                line: 0,
                message: format!("can't read {}: {e}", path.display()),
            }]),
        }
    }

    pub fn structure_only(&self, hook_id: &str, names: &BTreeMap<String, String>) -> bool {
        self.hooks
            .iter()
            .any(|h| h.structure_only && hook_matches(&h.hook, hook_id, names))
    }
}

/// Whether `want` (a name or id) is the hook `hook_id`.
pub fn hook_matches(want: &str, hook_id: &str, names: &BTreeMap<String, String>) -> bool {
    want == hook_id || names.get(hook_id).is_some_and(|n| n == want)
}

/// The default file: `$XDG_CONFIG_HOME/00hooks/automations.yaml`, else
/// `~/.config/00hooks/automations.yaml` (on macOS too). `HOOKS_AUTOMATIONS` overrides it.
pub fn default_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("HOOKS_AUTOMATIONS").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(p));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))?;
    Some(base.join("00hooks").join("automations.yaml"))
}

/// Problems found while reading.
struct Ctx {
    problems: Vec<Problem>,
}

impl Ctx {
    fn err(&mut self, line: usize, m: impl Into<String>) {
        self.problems.push(Problem {
            line,
            message: m.into(),
        });
    }
}

/// A mapping's entries, tracking which keys were read so the rest can be reported as unknown.
struct Fields<'a> {
    entries: Vec<(&'a str, &'a Node, usize)>,
    used: HashSet<&'a str>,
    line: usize,
}

impl<'a> Fields<'a> {
    fn of(node: &'a Node, what: &str, cx: &mut Ctx) -> Option<Fields<'a>> {
        let Kind::Map(entries) = &node.kind else {
            cx.err(
                node.line,
                format!(
                    "{what} should be a mapping (`key: value` lines), not {}",
                    node.describe()
                ),
            );
            return None;
        };
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (k, v) in entries {
            let Some(key) = k.as_str() else {
                cx.err(k.line, "keys must be plain names");
                continue;
            };
            if !seen.insert(key) {
                cx.err(k.line, format!("`{key}` is given twice"));
                continue;
            }
            out.push((key, v, k.line));
        }
        Some(Fields {
            entries: out,
            used: HashSet::new(),
            line: node.line,
        })
    }

    fn get(&mut self, key: &'a str) -> Option<&'a Node> {
        let found = self.entries.iter().find(|(k, _, _)| *k == key).map(|e| e.1);
        if found.is_some() {
            self.used.insert(key);
        }
        found
    }

    /// Report keys nobody asked for, suggesting the closest known one.
    fn finish(self, known: &[&str], what: &str, cx: &mut Ctx) {
        for (k, _, line) in &self.entries {
            if !self.used.contains(k) && !known.contains(k) {
                let hint = closest(k, known)
                    .map(|s| format!("; did you mean `{s}`?"))
                    .unwrap_or_else(|| format!(" (known: {})", known.join(", ")));
                cx.err(*line, format!("{what}: unknown key `{k}`{hint}"));
            }
        }
    }
}

fn closest<'b>(word: &str, known: &[&'b str]) -> Option<&'b str> {
    known
        .iter()
        .map(|k| (distance(word, k), *k))
        .filter(|(d, k)| *d <= 2.max(k.len() / 4))
        .min_by_key(|(d, _)| *d)
        .map(|(_, k)| k)
}

fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(ca != *cb);
            cur.push(sub.min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

fn string(node: &Node, what: &str, cx: &mut Ctx) -> Option<String> {
    match &node.kind {
        Kind::Scalar(s, _) => Some(s.clone()),
        _ => {
            cx.err(
                node.line,
                format!("{what} should be text, not {}", node.describe()),
            );
            None
        }
    }
}

fn boolean(node: &Node, what: &str, cx: &mut Ctx) -> Option<bool> {
    match &node.kind {
        Kind::Scalar(s, false) if s == "true" => Some(true),
        Kind::Scalar(s, false) if s == "false" => Some(false),
        _ => {
            cx.err(node.line, format!("{what} should be true or false"));
            None
        }
    }
}

fn list<'a>(node: &'a Node, what: &str, cx: &mut Ctx) -> Option<Vec<&'a Node>> {
    match &node.kind {
        Kind::Seq(items) => Some(items.iter().collect()),
        Kind::Scalar(..) => Some(vec![node]),
        Kind::Map(_) => {
            cx.err(node.line, format!("{what} should be a list"));
            None
        }
    }
}

fn strings(node: &Node, what: &str, cx: &mut Ctx) -> Vec<String> {
    list(node, what, cx)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|n| string(n, what, cx))
        .collect()
}

/// `500ms`, `10s`, `5m`, `1h`.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit())?;
    let n: u64 = s[..split].parse().ok()?;
    let ms = match s[split..].trim() {
        "ms" => n,
        "s" | "sec" | "second" | "seconds" => n.checked_mul(1000)?,
        "m" | "min" | "minute" | "minutes" => n.checked_mul(60_000)?,
        "h" | "hour" | "hours" => n.checked_mul(3_600_000)?,
        _ => return None,
    };
    Some(Duration::from_millis(ms))
}

fn duration(node: &Node, what: &str, max: Duration, cx: &mut Ctx) -> Option<Duration> {
    let s = string(node, what, cx)?;
    match parse_duration(&s) {
        Some(d) if !d.is_zero() && d <= max => Some(d),
        Some(_) => {
            cx.err(
                node.line,
                format!("{what} must be more than 0 and at most {} s", max.as_secs()),
            );
            None
        }
        None => {
            cx.err(
                node.line,
                format!("{what}: write a duration such as 10s, 5m or 1h (not {s:?})"),
            );
            None
        }
    }
}

fn count(node: &Node, what: &str, max: u32, cx: &mut Ctx) -> Option<u32> {
    match string(node, what, cx)?.parse::<u32>() {
        Ok(n) if n <= max => Some(n),
        _ => {
            cx.err(
                node.line,
                format!("{what} should be a whole number from 0 to {max}"),
            );
            None
        }
    }
}

/// `30/hour`, `5/minute`, `100/day`, or `none`.
pub fn parse_rate(s: &str) -> Result<Option<RateLimit>, String> {
    let s = s.trim();
    if matches!(s, "none" | "off" | "unlimited") {
        return Ok(None);
    }
    let bad =
        || format!("write a rate such as 30/hour, 5/minute or 100/day, or `none` (not {s:?})");
    let (n, per) = s.split_once('/').ok_or_else(bad)?;
    let max: u32 = n.trim().parse().map_err(|_| bad())?;
    let per = match per.trim() {
        "second" | "s" => Duration::from_secs(1),
        "minute" | "min" | "m" => Duration::from_secs(60),
        "hour" | "h" => Duration::from_secs(3600),
        "day" | "d" => Duration::from_secs(86_400),
        _ => return Err(bad()),
    };
    if max == 0 {
        return Err("a rate of 0 would never run; set `enabled: false` instead".into());
    }
    Ok(Some(RateLimit { max, per }))
}

/// Expand `~/` and require an absolute path.
fn local_path(node: &Node, what: &str, cx: &mut Ctx) -> Option<PathBuf> {
    let s = string(node, what, cx)?;
    if s.contains("{{") {
        cx.err(
            node.line,
            format!("{what} can't contain a template: payload values never choose a path"),
        );
        return None;
    }
    let p = if let Some(rest) = s.strip_prefix("~/") {
        match dirs::home_dir() {
            Some(h) => h.join(rest),
            None => {
                cx.err(
                    node.line,
                    format!("{what}: can't find the home folder to expand `~`"),
                );
                return None;
            }
        }
    } else {
        PathBuf::from(&s)
    };
    if !p.is_absolute() {
        cx.err(
            node.line,
            format!("{what} must be an absolute path (or start with ~/), not {s:?}"),
        );
        return None;
    }
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        cx.err(node.line, format!("{what} can't contain `..`"));
        return None;
    }
    Some(p)
}

fn template(node: &Node, what: &str, scope: Scope, cx: &mut Ctx) -> Option<Template> {
    let s = string(node, what, cx)?;
    Template::parse(&s, scope)
        .map_err(|e| cx.err(node.line, format!("{what}: {e}")))
        .ok()
}

fn json_template(node: &Node, what: &str, cx: &mut Ctx) -> Option<JsonTemplate> {
    JsonTemplate::parse(&node.to_json())
        .map_err(|e| cx.err(node.line, format!("{what}: {e}")))
        .ok()
}

/// Parse the text of an automations file.
pub fn parse(text: &str, path: &Path) -> Result<Automations, Vec<Problem>> {
    let root = match yaml::parse(text) {
        Ok(Some(n)) => n,
        Ok(None) => return Ok(Automations::empty(path)),
        Err(e) => {
            return Err(vec![Problem {
                line: e.line,
                message: e.message,
            }]);
        }
    };
    let mut cx = Ctx {
        problems: Vec::new(),
    };
    let mut out = Automations::empty(path);
    if let Some(mut f) = Fields::of(&root, "the file", &mut cx) {
        if let Some(v) = f.get("version")
            && v.as_str() != Some("1")
        {
            cx.err(v.line, "this version of 00hooks reads `version: 1` files");
        }
        if let Some(n) = f.get("notify") {
            match n.as_str() {
                Some("system") => out.notify = NotifyMode::System,
                Some("none") => out.notify = NotifyMode::None,
                _ => cx.err(n.line, "notify should be `system` or `none`"),
            }
        }
        if let Some(h) = f.get("hooks") {
            out.hooks = parse_hooks(h, &mut cx);
        }
        match f.get("automations") {
            Some(a) if a.is_null() => {}
            Some(a) => {
                if let Some(items) = list(a, "automations", &mut cx) {
                    let mut names = HashSet::new();
                    for item in items {
                        if let Some(auto) = parse_automation(item, &mut cx) {
                            if !names.insert(auto.name.clone()) {
                                cx.err(
                                    auto.line,
                                    format!(
                                        "two automations are named {:?}; names must be unique",
                                        auto.name
                                    ),
                                );
                            }
                            out.automations.push(auto);
                        }
                    }
                }
            }
            None => {}
        }
        f.finish(
            &["version", "notify", "hooks", "automations"],
            "the file",
            &mut cx,
        );
    }
    if cx.problems.is_empty() {
        Ok(out)
    } else {
        cx.problems.sort_by_key(|p| p.line);
        Err(cx.problems)
    }
}

fn parse_hooks(node: &Node, cx: &mut Ctx) -> Vec<HookSettings> {
    let mut out = Vec::new();
    let Kind::Map(entries) = &node.kind else {
        cx.err(
            node.line,
            "hooks should map each hook's name or id to its settings",
        );
        return out;
    };
    for (k, v) in entries {
        let Some(hook) = k.as_str() else { continue };
        let Some(mut f) = Fields::of(v, &format!("hook {hook:?}"), cx) else {
            continue;
        };
        let structure_only = f
            .get("structure_only")
            .and_then(|n| boolean(n, "structure_only", cx))
            .unwrap_or(false);
        f.finish(&["structure_only"], &format!("hook {hook:?}"), cx);
        out.push(HookSettings {
            hook: hook.to_string(),
            structure_only,
            line: k.line,
        });
    }
    out
}

const AUTOMATION_KEYS: &[&str] = &[
    "name",
    "enabled",
    "when",
    "only_if",
    "verified_only",
    "rate_limit",
    "pause_after",
    "pause_for",
    "allow_hosts",
    "allow_commands",
    "then",
];

fn parse_automation(node: &Node, cx: &mut Ctx) -> Option<Automation> {
    let before = cx.problems.len();
    let mut f = Fields::of(node, "each automation", cx)?;
    let name = match f.get("name").and_then(|n| string(n, "name", cx)) {
        Some(n)
            if !n.trim().is_empty()
                && n.chars().count() <= 100
                && !n.chars().any(char::is_control) =>
        {
            n.trim().to_string()
        }
        Some(_) => {
            cx.err(
                node.line,
                "an automation's name must be 1 to 100 characters, on one line",
            );
            String::new()
        }
        None => {
            cx.err(node.line, "this automation has no `name`");
            String::new()
        }
    };
    let what = |k: &str| format!("{name:?}: {k}");
    let enabled = f
        .get("enabled")
        .and_then(|n| boolean(n, &what("enabled"), cx))
        .unwrap_or(true);
    let when = match f.get("when") {
        Some(w) => parse_when(w, &name, cx),
        None => {
            cx.err(
                node.line,
                format!("{name:?} has no `when`: say which events start it"),
            );
            None
        }
    };
    let (only_if, only_if_line) = match f.get("only_if") {
        Some(n) => {
            let filter = string(n, &what("only_if"), cx).and_then(|s| {
                Filter::parse(&s)
                    .map_err(|e| cx.err(n.line, format!("{name:?}: only_if: {e}")))
                    .ok()
            });
            (filter, n.line)
        }
        None => (None, 0),
    };
    let verified_only = f
        .get("verified_only")
        .and_then(|n| boolean(n, &what("verified_only"), cx))
        .unwrap_or(true);
    let rate_limit = match f.get("rate_limit") {
        Some(n) => match string(n, &what("rate_limit"), cx).map(|s| parse_rate(&s)) {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
                cx.err(n.line, format!("{name:?}: rate_limit: {e}"));
                None
            }
            None => None,
        },
        None => Some(DEFAULT_RATE),
    };
    let pause_after = f
        .get("pause_after")
        .and_then(|n| count(n, &what("pause_after"), 1000, cx))
        .unwrap_or(DEFAULT_PAUSE_AFTER);
    let pause_for = f
        .get("pause_for")
        .and_then(|n| duration(n, &what("pause_for"), Duration::from_secs(7 * 86_400), cx))
        .unwrap_or(DEFAULT_PAUSE_FOR);
    let allow_hosts: Vec<String> = match f.get("allow_hosts") {
        Some(n) => strings(n, &what("allow_hosts"), cx)
            .into_iter()
            .filter_map(|h| match check_host_entry(&h) {
                Ok(h) => Some(h),
                Err(e) => {
                    cx.err(n.line, format!("{name:?}: allow_hosts: {e}"));
                    None
                }
            })
            .collect(),
        None => Vec::new(),
    };
    let allow_commands: Vec<PathBuf> = match f.get("allow_commands") {
        Some(n) => list(n, &what("allow_commands"), cx)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|c| local_path(c, &what("allow_commands"), cx))
            .collect(),
        None => Vec::new(),
    };
    let mut actions = Vec::new();
    match f.get("then") {
        Some(t) => {
            for item in list(t, &what("then"), cx).unwrap_or_default() {
                if let Some(a) = parse_action(item, &name, &allow_hosts, &allow_commands, cx) {
                    actions.push(a);
                }
            }
            if actions.is_empty() && cx.problems.len() == before {
                cx.err(t.line, format!("{name:?}: `then` has no actions"));
            }
        }
        None => cx.err(node.line, format!("{name:?} has no `then`: say what to do")),
    }
    let line = f.line;
    f.finish(AUTOMATION_KEYS, &format!("automation {name:?}"), cx);
    if cx.problems.len() > before {
        return None;
    }
    Some(Automation {
        name,
        line,
        enabled,
        when: when?,
        only_if,
        only_if_line,
        verified_only,
        rate_limit,
        pause_after,
        pause_for,
        allow_hosts,
        allow_commands,
        actions,
    })
}

fn parse_when(node: &Node, name: &str, cx: &mut Ctx) -> Option<When> {
    let what = format!("{name:?}: when");
    let mut f = Fields::of(node, &what, cx)?;
    let hook = f
        .get("hook")
        .and_then(|n| string(n, &format!("{what}: hook"), cx));
    let kinds_node = f.get("kinds");
    let kinds: Option<Vec<String>> = kinds_node.map(|n| {
        if n.as_str() == Some("any") {
            Vec::new()
        } else {
            strings(n, &format!("{what}: kinds"), cx)
                .into_iter()
                .map(|k| k.trim().to_string())
                .collect()
        }
    });
    let new_kind = f
        .get("new_kind")
        .and_then(|n| boolean(n, &format!("{what}: new_kind"), cx))
        .unwrap_or(false);
    let shape_changed = f
        .get("shape_changed")
        .and_then(|n| boolean(n, &format!("{what}: shape_changed"), cx))
        .unwrap_or(false);
    f.finish(&["hook", "kinds", "new_kind", "shape_changed"], &what, cx);
    if let Some(k) = &kinds
        && k.iter().any(String::is_empty)
    {
        cx.err(node.line, format!("{what}: a kind can't be empty"));
    }
    let trigger = match (new_kind, shape_changed, kinds) {
        (true, true, _) => {
            cx.err(
                node.line,
                format!("{what}: choose one of new_kind and shape_changed"),
            );
            return None;
        }
        (true, false, Some(_)) => {
            cx.err(
                node.line,
                format!("{what}: new_kind fires for kinds not seen before, so it takes no `kinds`"),
            );
            return None;
        }
        (true, false, None) => Trigger::NewKind,
        (false, true, k) => Trigger::ShapeChanged(k.unwrap_or_default()),
        (false, false, Some(k)) => {
            if k.is_empty() && hook.is_none() {
                cx.err(
                    node.line,
                    format!("{what}: `kinds: any` needs a `hook` (any kind from which hook?)"),
                );
                return None;
            }
            Trigger::Kinds(k)
        }
        (false, false, None) => {
            cx.err(node.line, format!("{what}: give `kinds` (a list, or `any` with a `hook`), `new_kind: true` or `shape_changed: true`"));
            return None;
        }
    };
    Some(When {
        hook,
        trigger,
        line: node.line,
    })
}

/// An `allow_hosts` entry: a host name, an IP address, or `*.domain`. Lowercased.
fn check_host_entry(h: &str) -> Result<String, String> {
    let h = h.trim().to_ascii_lowercase();
    let bare = h.strip_prefix("*.").unwrap_or(&h);
    let ok = !bare.is_empty()
        && bare.len() <= 253
        && bare
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        && !bare.contains("..");
    if !ok || h.contains("://") || h.contains('/') {
        return Err(format!(
            "{h:?} isn't a host; write just the host, such as api.example.com or *.example.com"
        ));
    }
    if bare.contains(':') && !bare.starts_with('[') && bare.matches(':').count() == 1 {
        return Err(format!("{h:?}: write the host without a port"));
    }
    Ok(h)
}

/// Whether `host` is allowed by one of `allow`.
pub fn host_allowed(host: &str, allow: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    allow.iter().any(|a| {
        let a = a.trim_start_matches('[').trim_end_matches(']');
        match a.strip_prefix("*.") {
            Some(domain) => host.ends_with(&format!(".{domain}")),
            None => host == a,
        }
    })
}

const ACTIONS: &[&str] = &["notify", "call", "run", "write"];

fn parse_action(
    node: &Node,
    name: &str,
    hosts: &[String],
    commands: &[PathBuf],
    cx: &mut Ctx,
) -> Option<Action> {
    let Kind::Map(entries) = &node.kind else {
        cx.err(
            node.line,
            format!(
                "{name:?}: each action is one of {}, such as `- notify: \"text\"`",
                ACTIONS.join(", ")
            ),
        );
        return None;
    };
    if entries.len() != 1 {
        cx.err(node.line, format!("{name:?}: each item under `then` is one action (one of {}); put the action's settings under it", ACTIONS.join(", ")));
        return None;
    }
    let (k, body) = &entries[0];
    let kind = k.as_str().unwrap_or("");
    let what = format!("{name:?}: {kind}");
    let line = k.line;
    match kind {
        "notify" => parse_notify(body, &what, cx).map(|kind| Action {
            kind,
            retries: 2,
            line,
        }),
        "call" => parse_call(body, &what, hosts, cx),
        "run" => parse_run(body, &what, commands, cx),
        "write" => parse_write(body, &what, cx),
        other => {
            let hint = closest(other, ACTIONS)
                .map(|s| format!("; did you mean `{s}`?"))
                .unwrap_or_default();
            cx.err(
                line,
                format!(
                    "{name:?}: unknown action `{other}` (the actions are {}){hint}",
                    ACTIONS.join(", ")
                ),
            );
            None
        }
    }
    .map(|mut a| {
        a.line = line;
        a
    })
}

fn parse_notify(node: &Node, what: &str, cx: &mut Ctx) -> Option<ActionKind> {
    if let Kind::Scalar(..) = node.kind {
        let body = template(node, what, Scope::Event, cx)?;
        let title = Template::parse("00hooks", Scope::Event).expect("constant");
        return Some(ActionKind::Notify { title, body });
    }
    let mut f = Fields::of(node, what, cx)?;
    let title = match f.get("title") {
        Some(n) => template(n, &format!("{what}: title"), Scope::Event, cx),
        None => Template::parse("00hooks", Scope::Event).ok(),
    };
    let body = match f.get("body") {
        Some(n) => template(n, &format!("{what}: body"), Scope::Event, cx),
        None => {
            cx.err(node.line, format!("{what} needs a `body`"));
            None
        }
    };
    f.finish(&["title", "body"], what, cx);
    Some(ActionKind::Notify {
        title: title?,
        body: body?,
    })
}

const METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "idempotency-key",
    "00hooks-origin",
    "00hooks-hop",
];

/// The text of a URL template up to its first slot must hold the whole scheme and host, so a
/// payload value can never change where the call goes.
fn check_url(raw: &str, hosts: &[String]) -> Result<(), String> {
    let literal = raw.split("{{").next().unwrap_or("");
    let probe = raw.replace("{{", "x").replace("}}", "x");
    let url = url::Url::parse(&probe).map_err(|e| format!("{raw:?} isn't a URL ({e})"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("the URL must start with https:// (or http://)".into());
    }
    let Some(host) = url.host_str() else {
        return Err("the URL has no host".into());
    };
    let lit = url::Url::parse(literal).ok();
    let host_fixed = lit.as_ref().and_then(|u| u.host_str()) == Some(host)
        && (raw.len() == literal.len() || {
            let after = &literal[literal.find("://").map(|i| i + 3).unwrap_or(0)..];
            after.contains(['/', '?', '#'])
        });
    if !host_fixed || url.username() != "" || url.password().is_some() {
        return Err("the URL's scheme and host must be written out, with templates only in its path or query".into());
    }
    if !host_allowed(host, hosts) {
        return Err(format!(
            "the host {host} isn't in this automation's allow_hosts{}",
            if hosts.is_empty() {
                " (it has none)"
            } else {
                ""
            }
        ));
    }
    Ok(())
}

fn parse_call(node: &Node, what: &str, hosts: &[String], cx: &mut Ctx) -> Option<Action> {
    let mut f = Fields::of(node, what, cx)?;
    let url = f.get("url").and_then(|n| {
        let raw = string(n, &format!("{what}: url"), cx)?;
        if let Err(e) = check_url(&raw, hosts) {
            cx.err(n.line, format!("{what}: {e}"));
            return None;
        }
        template(n, &format!("{what}: url"), Scope::Event, cx)
    });
    if f.get("url").is_none() {
        cx.err(node.line, format!("{what} needs a `url`"));
    }
    let method = match f.get("method") {
        Some(n) => string(n, &format!("{what}: method"), cx).and_then(|m| {
            let m = m.to_ascii_uppercase();
            if METHODS.contains(&m.as_str()) {
                Some(m)
            } else {
                cx.err(
                    n.line,
                    format!("{what}: method should be one of {}", METHODS.join(", ")),
                );
                None
            }
        }),
        None => Some("POST".to_string()),
    };
    let mut headers = Vec::new();
    if let Some(h) = f.get("headers")
        && let Some(mut hf) = Fields::of(h, &format!("{what}: headers"), cx)
    {
        let names: Vec<&str> = hf.entries.iter().map(|e| e.0).collect();
        for name in names {
            let lower = name.to_ascii_lowercase();
            let node = hf.get(name).expect("listed");
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
            {
                cx.err(
                    node.line,
                    format!("{what}: {name:?} isn't a valid header name"),
                );
            } else if RESERVED_HEADERS.contains(&lower.as_str()) {
                cx.err(
                    node.line,
                    format!("{what}: the {name} header is set by 00hooks"),
                );
            } else if let Some(t) = template(
                node,
                &format!("{what}: header {name}"),
                Scope::WithSecrets,
                cx,
            ) {
                headers.push((name.to_string(), t));
            }
        }
    }
    let body = f
        .get("body")
        .and_then(|n| json_template(n, &format!("{what}: body"), cx));
    let idempotency_key = match f.get("idempotency_key") {
        Some(n) => template(n, &format!("{what}: idempotency_key"), Scope::Event, cx),
        None => Template::parse("{{event.id}}", Scope::Event).ok(),
    };
    let timeout = f
        .get("timeout")
        .and_then(|n| duration(n, &format!("{what}: timeout"), MAX_TIMEOUT, cx))
        .unwrap_or(DEFAULT_CALL_TIMEOUT);
    let retries = f
        .get("retries")
        .and_then(|n| count(n, &format!("{what}: retries"), MAX_RETRIES, cx))
        .unwrap_or(3);
    f.finish(
        &[
            "url",
            "method",
            "headers",
            "body",
            "idempotency_key",
            "timeout",
            "retries",
        ],
        what,
        cx,
    );
    Some(Action {
        kind: ActionKind::Call {
            method: method?,
            url: url?,
            headers,
            body,
            idempotency_key: idempotency_key?,
            timeout,
        },
        retries,
        line: node.line,
    })
}

fn env_name_ok(n: &str) -> Result<(), String> {
    let valid = !n.is_empty()
        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !n.starts_with(|c: char| c.is_ascii_digit());
    if !valid {
        return Err(format!("{n:?} isn't a valid environment variable name"));
    }
    let upper = n.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "PATH" | "HOME" | "LANG" | "HOOKS_EVENT_FILE"
    ) || upper.starts_with("LD_")
        || upper.starts_with("DYLD_")
    {
        return Err(format!(
            "{n} is set by 00hooks (or would change how programs load) and can't be set here"
        ));
    }
    Ok(())
}

fn parse_run(node: &Node, what: &str, commands: &[PathBuf], cx: &mut Ctx) -> Option<Action> {
    let mut f = Fields::of(node, what, cx)?;
    let command = match f.get("command") {
        Some(n) => string(n, &format!("{what}: command"), cx).and_then(|c| {
            let chosen: Vec<&PathBuf> = if c.contains('/') || c.starts_with('~') {
                let p = local_path(n, &format!("{what}: command"), cx)?;
                commands.iter().filter(|a| **a == p).collect()
            } else {
                commands
                    .iter()
                    .filter(|a| a.file_name().is_some_and(|f| f == c.as_str()))
                    .collect()
            };
            match chosen.as_slice() {
                [one] => Some((*one).clone()),
                [] => {
                    cx.err(
                        n.line,
                        format!(
                            "{what}: {c:?} isn't in this automation's allow_commands{}",
                            if commands.is_empty() {
                                " (it has none; list the program's full path there)"
                            } else {
                                ""
                            }
                        ),
                    );
                    None
                }
                _ => {
                    cx.err(
                        n.line,
                        format!(
                            "{what}: {c:?} matches several allow_commands; write its full path"
                        ),
                    );
                    None
                }
            }
        }),
        None => {
            cx.err(node.line, format!("{what} needs a `command`"));
            None
        }
    };
    let args = match f.get("args") {
        Some(n) => list(n, &format!("{what}: args"), cx)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|a| template(a, &format!("{what}: args"), Scope::Event, cx))
            .collect(),
        None => Vec::new(),
    };
    let mut env = Vec::new();
    if let Some(e) = f.get("env")
        && let Some(mut ef) = Fields::of(e, &format!("{what}: env"), cx)
    {
        let names: Vec<&str> = ef.entries.iter().map(|e| e.0).collect();
        for name in names {
            let node = ef.get(name).expect("listed");
            match env_name_ok(name) {
                Err(m) => cx.err(node.line, format!("{what}: env: {m}")),
                Ok(()) => {
                    if let Some(t) =
                        template(node, &format!("{what}: env {name}"), Scope::Event, cx)
                    {
                        env.push((name.to_string(), t));
                    }
                }
            }
        }
    }
    let event = match f.get("event") {
        Some(n) => match n.as_str() {
            Some("stdin") => EventInput::Stdin,
            Some("file") => EventInput::File,
            Some("none") => EventInput::None,
            _ => {
                cx.err(
                    n.line,
                    format!("{what}: event should be `stdin`, `file` or `none`"),
                );
                EventInput::None
            }
        },
        None => EventInput::Stdin,
    };
    let timeout = f
        .get("timeout")
        .and_then(|n| duration(n, &format!("{what}: timeout"), MAX_TIMEOUT, cx))
        .unwrap_or(DEFAULT_RUN_TIMEOUT);
    let idempotent = f
        .get("idempotent")
        .and_then(|n| boolean(n, &format!("{what}: idempotent"), cx))
        .unwrap_or(false);
    let retries = match f.get("retries") {
        Some(n) => {
            let r = count(n, &format!("{what}: retries"), MAX_RETRIES, cx).unwrap_or(0);
            if r > 0 && !idempotent {
                cx.err(n.line, format!("{what}: a command is retried only when it's marked `idempotent: true` (safe to run twice)"));
            }
            r
        }
        None if idempotent => 2,
        None => 0,
    };
    f.finish(
        &[
            "command",
            "args",
            "env",
            "event",
            "timeout",
            "idempotent",
            "retries",
        ],
        what,
        cx,
    );
    Some(Action {
        kind: ActionKind::Run {
            command: command?,
            args,
            env,
            event,
            timeout,
            idempotent,
        },
        retries,
        line: node.line,
    })
}

fn parse_write(node: &Node, what: &str, cx: &mut Ctx) -> Option<Action> {
    let mut f = Fields::of(node, what, cx)?;
    let default_content = || {
        JsonTemplate::parse(&serde_json::json!({
            "event": "{{event}}",
            "headers": "{{headers}}",
            "payload": "{{payload}}"
        }))
        .expect("constant")
    };
    let retries_node = f.get("retries");
    let (kind, retries) = match (f.get("append"), f.get("folder")) {
        (Some(a), None) => {
            let path = local_path(a, &format!("{what}: append"), cx);
            let line = match f.get("line") {
                Some(n) => json_template(n, &format!("{what}: line"), cx),
                None => Some(default_content()),
            };
            if let Some(r) = retries_node {
                cx.err(
                    r.line,
                    format!(
                        "{what}: appending isn't retried (a second try could write the line twice)"
                    ),
                );
            }
            f.finish(&["append", "line"], what, cx);
            (
                ActionKind::Append {
                    path: path?,
                    line: line?,
                },
                0,
            )
        }
        (None, Some(d)) => {
            let folder = local_path(d, &format!("{what}: folder"), cx);
            let name = match f.get("name") {
                Some(n) => template(n, &format!("{what}: name"), Scope::Event, cx),
                None => Template::parse("{{event.id}}.json", Scope::Event).ok(),
            };
            let content = match f.get("content") {
                Some(n) => json_template(n, &format!("{what}: content"), cx),
                None => Some(default_content()),
            };
            let retries = retries_node
                .and_then(|n| count(n, &format!("{what}: retries"), MAX_RETRIES, cx))
                .unwrap_or(2);
            f.finish(&["folder", "name", "content", "retries"], what, cx);
            (
                ActionKind::WriteFile {
                    folder: folder?,
                    name: name?,
                    content: content?,
                },
                retries,
            )
        }
        (Some(_), Some(_)) => {
            cx.err(node.line, format!("{what}: choose `append` (a JSON line onto a file) or `folder` (a file per event), not both"));
            return None;
        }
        (None, None) => {
            cx.err(
                node.line,
                format!("{what} needs `append: <file>` or `folder: <folder>`"),
            );
            return None;
        }
    };
    Some(Action {
        kind,
        retries,
        line: node.line,
    })
}

/// Field references to check against the catalogue: (line, path).
pub fn field_refs(a: &Automation) -> Vec<(usize, fpath::Path)> {
    let mut out = Vec::new();
    if let Some(f) = &a.only_if {
        out.extend(f.paths.iter().map(|p| (a.only_if_line, p.clone())));
    }
    for act in &a.actions {
        let mut add =
            |ps: Vec<&fpath::Path>| out.extend(ps.into_iter().map(|p| (act.line, p.clone())));
        match &act.kind {
            ActionKind::Notify { title, body } => {
                add(title.paths().chain(body.paths()).collect());
            }
            ActionKind::Call {
                url,
                headers,
                body,
                idempotency_key,
                ..
            } => {
                add(url.paths().chain(idempotency_key.paths()).collect());
                add(headers.iter().flat_map(|(_, t)| t.paths()).collect());
                if let Some(b) = body {
                    add(b.paths());
                }
            }
            ActionKind::Run { args, env, .. } => {
                add(args.iter().flat_map(Template::paths).collect());
                add(env.iter().flat_map(|(_, t)| t.paths()).collect());
            }
            ActionKind::Append { line, .. } => add(line.paths()),
            ActionKind::WriteFile { name, content, .. } => {
                add(name.paths().collect());
                add(content.paths());
            }
        }
    }
    out
}

/// What the default values look like, for messages.
pub fn describe_rate(r: Option<RateLimit>) -> String {
    match r {
        None => "no limit".into(),
        Some(r) => {
            let per = match r.per.as_secs() {
                1 => "second",
                60 => "minute",
                3600 => "hour",
                _ => "day",
            };
            format!("{}/{per}", r.max)
        }
    }
}

/// Render a JSON value for a message.
pub fn short_json(v: &Value) -> String {
    crate::text::cut(&crate::text::sanitize(&crate::template::to_text(v)), 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> Result<Automations, Vec<Problem>> {
        parse(text, Path::new("/tmp/automations.yaml"))
    }

    fn errs(text: &str) -> Vec<String> {
        p(text)
            .unwrap_err()
            .into_iter()
            .map(|p| p.to_string())
            .collect()
    }

    const GOOD: &str = r##"
version: 1
notify: none
hooks:
  payments:
    structure_only: true
automations:
  - name: Triage
    when:
      hook: github
      kinds: [issues, issue_comment]
    only_if: payload.action == "opened" and payload.issue.comments < 5
    rate_limit: 10/minute
    allow_hosts: [127.0.0.1, "*.example.com"]
    allow_commands: [/usr/bin/say]
    then:
      - notify: "#{{payload.issue.number}} {{payload.issue.title | truncate:60}}"
      - call:
          url: http://127.0.0.1:9/issues/{{payload.issue.number}}?x={{payload.action}}
          headers: { Authorization: "Bearer {{secret.TOKEN}}" }
          body: { number: "{{payload.issue.number}}" }
      - run: { command: say, args: ["Issue {{payload.issue.number}}"], env: { TITLE: "{{payload.issue.title}}" } }
      - write: { append: /tmp/issues.jsonl }
      - write: { folder: /tmp/out, name: "{{payload.issue.number}}.json" }
  - name: New kinds
    when: { new_kind: true }
    then:
      - notify: { title: "New kind", body: "{{event.kind}} on {{event.hook}}" }
"##;

    #[test]
    fn a_good_file_parses() {
        let a = p(GOOD).unwrap();
        assert_eq!(a.notify, NotifyMode::None);
        assert!(a.hooks[0].structure_only && a.hooks[0].hook == "payments");
        assert_eq!(a.automations.len(), 2);
        let t = &a.automations[0];
        assert_eq!(t.when.hook.as_deref(), Some("github"));
        assert_eq!(
            t.when.trigger,
            Trigger::Kinds(vec!["issues".into(), "issue_comment".into()])
        );
        assert!(t.verified_only, "the default");
        assert_eq!(
            t.rate_limit,
            Some(RateLimit {
                max: 10,
                per: Duration::from_secs(60)
            })
        );
        assert_eq!(t.actions.len(), 5);
        assert_eq!(t.actions[0].line, 17);
        match &t.actions[2].kind {
            ActionKind::Run {
                command,
                event,
                idempotent,
                ..
            } => {
                assert_eq!(command, Path::new("/usr/bin/say"));
                assert_eq!(*event, EventInput::Stdin);
                assert!(!idempotent);
            }
            _ => panic!(),
        }
        assert_eq!(
            t.actions[2].retries, 0,
            "commands aren't retried by default"
        );
        assert_eq!(t.actions[1].retries, 3);
        assert_eq!(a.automations[1].when.trigger, Trigger::NewKind);
        assert_eq!(a.automations[1].rate_limit, Some(DEFAULT_RATE));
        let refs: Vec<String> = field_refs(t).iter().map(|(_, p)| p.field_key()).collect();
        assert!(refs.contains(&"payload.issue.comments".to_string()));
        assert!(refs.contains(&"payload.issue.title".to_string()));
        assert!(refs.contains(&"secret.TOKEN".to_string()));
    }

    #[test]
    fn errors_name_their_lines_and_say_what_to_do() {
        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    then:\n      - notfy: hi\n",
        );
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(
            e[0].starts_with("line 5:") && e[0].contains("did you mean `notify`"),
            "{e:?}"
        );

        let e = errs("automations:\n  - name: x\n    when: { kinds: [a] }\n    thne: []\n");
        assert!(
            e.iter()
                .any(|m| m.contains("line 4") && m.contains("did you mean `then`")),
            "{e:?}"
        );
        assert!(e.iter().any(|m| m.contains("has no `then`")), "{e:?}");

        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    only_if: action == 1\n    then: [{notify: hi}]\n",
        );
        assert!(
            e[0].starts_with("line 4:") && e[0].contains("payload.action"),
            "{e:?}"
        );

        let e = errs("automations: [\n");
        assert!(e[0].contains("valid YAML"), "{e:?}");

        let e = errs(
            "automations:\n  - name: a\n    when: { kinds: [k] }\n    then: [{notify: x}]\n  - name: a\n    when: { kinds: [k] }\n    then: [{notify: x}]\n",
        );
        assert!(e[0].contains("line 5") && e[0].contains("unique"), "{e:?}");
    }

    #[test]
    fn hosts_and_commands_must_be_allowed() {
        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    then:\n      - call: { url: https://evil.example.org/x }\n",
        );
        assert!(
            e[0].contains("isn't in this automation's allow_hosts (it has none)"),
            "{e:?}"
        );

        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    allow_hosts: [api.example.com]\n    then:\n      - call: { url: \"https://{{payload.host}}/x\" }\n",
        );
        assert!(e[0].contains("written out"), "{e:?}");
        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    allow_hosts: [api.example.com]\n    then:\n      - call: { url: \"https://api.example.com{{payload.rest}}\" }\n",
        );
        assert!(e[0].contains("written out"), "{e:?}");
        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    allow_hosts: [api.example.com]\n    then:\n      - call: { url: \"https://api.example.com@evil.org/\" }\n",
        );
        assert!(!e.is_empty(), "userinfo tricks are refused");
        assert!(p("automations:\n  - name: x\n    when: { kinds: [a] }\n    allow_hosts: [\"*.example.com\"]\n    then:\n      - call: { url: \"https://api.example.com/{{payload.rest}}\" }\n").is_ok());
        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    allow_hosts: [\"https://api.example.com/\"]\n    then: [{notify: x}]\n",
        );
        assert!(e[0].contains("isn't a host"), "{e:?}");

        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    then:\n      - run: { command: /bin/sh, args: [-c, \"{{payload.x}}\"] }\n",
        );
        assert!(e[0].contains("allow_commands (it has none"), "{e:?}");
        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    allow_commands: [bin/tool]\n    then: [{notify: x}]\n",
        );
        assert!(e[0].contains("absolute"), "{e:?}");
        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    allow_commands: [/bin/echo]\n    then:\n      - run: { command: echo, retries: 2 }\n",
        );
        assert!(e[0].contains("idempotent"), "{e:?}");
        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    allow_commands: [/bin/echo]\n    then:\n      - run: { command: echo, env: { PATH: x, LD_PRELOAD: y } }\n",
        );
        assert_eq!(e.len(), 2, "{e:?}");
    }

    #[test]
    fn paths_and_secrets_stay_where_they_belong() {
        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    then:\n      - write: { append: \"/tmp/{{payload.name}}.jsonl\" }\n",
        );
        assert!(e[0].contains("never choose a path"), "{e:?}");
        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    then:\n      - write: { append: relative.jsonl }\n",
        );
        assert!(e[0].contains("absolute"), "{e:?}");
        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    then:\n      - write: { append: /tmp/../etc/x }\n",
        );
        assert!(e[0].contains(".."), "{e:?}");
        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    then:\n      - notify: \"{{secret.TOKEN}}\"\n",
        );
        assert!(e[0].contains("secrets can only"), "{e:?}");
        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    allow_hosts: [a.example]\n    then:\n      - call: { url: \"https://a.example/\", body: { t: \"{{secret.TOKEN}}\" } }\n",
        );
        assert!(e[0].contains("secrets can only"), "{e:?}");
        let e = errs(
            "automations:\n  - name: x\n    when: { kinds: [a] }\n    allow_hosts: [a.example]\n    then:\n      - call: { url: \"https://a.example/\", headers: { 00hooks-origin: x } }\n",
        );
        assert!(e[0].contains("set by 00hooks"), "{e:?}");
    }

    #[test]
    fn triggers() {
        let e =
            errs("automations:\n  - name: x\n    when: { kinds: any }\n    then: [{notify: x}]\n");
        assert!(e[0].contains("needs a `hook`"), "{e:?}");
        let a = p("automations:\n  - name: x\n    when: { hook: gh, kinds: any }\n    then: [{notify: x}]\n").unwrap();
        assert_eq!(a.automations[0].when.trigger, Trigger::Kinds(vec![]));
        let a = p("automations:\n  - name: x\n    when: { shape_changed: true, kinds: pull_request }\n    then: [{notify: x}]\n").unwrap();
        assert_eq!(
            a.automations[0].when.trigger,
            Trigger::ShapeChanged(vec!["pull_request".into()])
        );
        let e = errs(
            "automations:\n  - name: x\n    when: { new_kind: true, shape_changed: true }\n    then: [{notify: x}]\n",
        );
        assert!(e[0].contains("choose one"), "{e:?}");
        let e =
            errs("automations:\n  - name: x\n    when: { hook: gh }\n    then: [{notify: x}]\n");
        assert!(e[0].contains("give `kinds`"), "{e:?}");
    }

    #[test]
    fn rates_and_durations() {
        assert_eq!(parse_rate("none").unwrap(), None);
        assert_eq!(parse_rate("100/day").unwrap().unwrap().max, 100);
        assert!(parse_rate("0/hour").is_err());
        assert!(parse_rate("lots").is_err());
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("5 x"), None);
        assert_eq!(describe_rate(Some(DEFAULT_RATE)), "30/hour");
        assert!(host_allowed("API.example.com", &["*.example.com".into()]));
        assert!(!host_allowed("example.com", &["*.example.com".into()]));
        assert!(!host_allowed("evilexample.com", &["*.example.com".into()]));
        assert!(host_allowed("::1", &["[::1]".into()]));
    }

    #[test]
    fn an_empty_or_missing_file_has_no_automations() {
        assert!(p("").unwrap().automations.is_empty());
        assert!(p("automations:\n").unwrap().automations.is_empty());
        let a = Automations::load(Path::new("/nonexistent/00hooks/automations.yaml")).unwrap();
        assert!(a.automations.is_empty());
    }
}
