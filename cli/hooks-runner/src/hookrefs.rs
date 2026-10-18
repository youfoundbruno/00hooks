//! Hook references: how the automations name their hooks, and how those names become ids.
//!
//! A hook is named in the automations (`when.hook`, the `hooks:` settings) by its id or by its
//! name, but **matching is by id only**. A name is an alias, resolved to an id against the relay's
//! hook list (id → name) when the configuration is loaded or the list changes, and the first
//! resolution is **pinned** in the runner's folder ([`PINS_FILE`]), name → id.
//!
//! Why: whoever can create or rename hooks (a leaked API key with `hooks:write`, say) could
//! otherwise give a hook of theirs the name an automation uses and drive it. So:
//!
//! - a reference that looks like an id (`hk_…`), or is the id of a known hook, is an id and never a
//!   name, so no hook can be *named* into one;
//! - a name that resolves to no hook, or to more than one, is a problem: the automations that use
//!   it don't run until it resolves (or the person writes the id);
//! - once pinned, a name keeps its id. If the name later points at a different hook (a rename, a
//!   new hook taking it, across a restart too), the pin holds and the person is warned; writing the
//!   id in the file is how they say the other hook is the one they mean.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{Automations, Problem};
use crate::runner::clock;
use crate::{Error, Result};

/// The pin file in the runner's folder: `{"<name>": {"id": "hk_…", "at": <ms>}}`.
pub const PINS_FILE: &str = "hook-pins.json";

/// A name's id, as first resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    pub id: String,
    /// When it was pinned, in Unix milliseconds.
    pub at: i64,
}

/// Pins by name.
pub type Pins = BTreeMap<String, Pin>;

/// Read the pins. A missing file is no pins; one that can't be read is an error (never "no pins":
/// that would let every name re-resolve).
pub fn load_pins(dir: &Path) -> Result<Pins> {
    let path = dir.join(PINS_FILE);
    match std::fs::read(&path) {
        Ok(b) => serde_json::from_slice(&b)
            .map_err(|e| Error::Store(format!("{} can't be read: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Pins::new()),
        Err(e) => Err(Error::Store(format!("can't read {}: {e}", path.display()))),
    }
}

pub fn save_pins(dir: &Path, pins: &Pins) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(pins).expect("json");
    hooks_client::fsutil::write_atomic(&dir.join(PINS_FILE), &bytes, true)
        .map_err(Error::from_client)
}

/// Whether a reference is an id: it has a hook id's prefix, or it is the id of a known hook.
pub fn is_id(reference: &str, names: &BTreeMap<String, String>) -> bool {
    reference.starts_with("hk_") || names.contains_key(reference)
}

/// The resolved references: each reference, as written, to the one hook id it means.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookRefs {
    ids: BTreeMap<String, String>,
}

impl HookRefs {
    /// The id `reference` resolved to; `None` when it didn't resolve.
    pub fn id(&self, reference: &str) -> Option<&str> {
        self.ids.get(reference).map(String::as_str)
    }

    /// Whether `reference` means the hook `hook_id`.
    pub fn matches(&self, reference: &str, hook_id: &str) -> bool {
        self.id(reference) == Some(hook_id)
    }

    /// Forget a reference: it matches nothing.
    pub(crate) fn remove(&mut self, reference: &str) {
        self.ids.remove(reference);
    }

    /// Every resolved reference, with its id.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.ids.iter().map(|(r, i)| (r.as_str(), i.as_str()))
    }
}

/// How a reference resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum How {
    /// It is an id.
    Id,
    /// A name, pinned to this id at `at`.
    Pinned { at: i64 },
    /// A name resolved for the first time: pinned now.
    New,
}

/// One reference that resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub reference: String,
    pub id: String,
    pub how: How,
}

/// What resolving a configuration found.
#[derive(Debug, Clone, Default)]
pub struct Resolution {
    pub refs: HookRefs,
    /// Each distinct reference that resolved, in the file's order.
    pub resolved: Vec<Resolved>,
    /// References that resolved to no hook or to several, one per use: what uses them doesn't run.
    pub problems: Vec<Problem>,
    /// Pinned names whose hook list has changed under them, one per use: the pin holds.
    pub warnings: Vec<Problem>,
    /// Names resolved for the first time, to be pinned: (name, id).
    pub new_pins: Vec<(String, String)>,
}

/// Every place the configuration names a hook: (reference, line, what uses it).
fn uses(config: &Automations) -> Vec<(String, usize, String)> {
    let mut out = Vec::new();
    for h in &config.hooks {
        out.push((h.hook.clone(), h.line, format!("hooks: {:?}", h.hook)));
    }
    for a in &config.automations {
        if let Some(h) = &a.when.hook {
            out.push((h.clone(), a.when.line, format!("{:?}: when: hook", a.name)));
        }
    }
    out
}

/// The names (not ids) the configuration uses for hooks.
pub fn aliases(
    config: &Automations,
    names: &BTreeMap<String, String>,
) -> std::collections::BTreeSet<String> {
    uses(config)
        .into_iter()
        .map(|(r, _, _)| r)
        .filter(|r| !is_id(r, names))
        .collect()
}

/// The outcome for one name.
enum Outcome {
    Ok {
        id: String,
        how: How,
        warning: Option<String>,
    },
    Unresolved(String),
}

fn resolve_name(name: &str, names: &BTreeMap<String, String>, pins: &Pins) -> Outcome {
    let holders: Vec<&str> = names
        .iter()
        .filter(|(_, n)| n.as_str() == name)
        .map(|(id, _)| id.as_str())
        .collect();
    if let Some(pin) = pins.get(name) {
        let since = clock(pin.at);
        let others: Vec<&str> = holders.iter().copied().filter(|id| *id != pin.id).collect();
        let warning = if !others.is_empty() {
            Some(format!(
                "the name {name:?} now belongs to {}, not to {}, the hook it named when first read \
                 ({since}); the automations keep using {}. If {} is the hook you mean, write its \
                 id in the file instead of the name",
                others.join(" and "),
                pin.id,
                pin.id,
                others.join(" or ")
            ))
        } else if names.is_empty() || holders.contains(&pin.id.as_str()) {
            None
        } else {
            match names.get(&pin.id) {
                Some(now) => Some(format!(
                    "hook {}, which the name {name:?} named when first read ({since}), is now \
                     named {now:?}; the automations keep using it. Write its id in the file to \
                     say so",
                    pin.id
                )),
                None => Some(format!(
                    "hook {}, which the name {name:?} named when first read ({since}), no longer \
                     exists, so nothing matches; if another hook is meant, write its id in the file",
                    pin.id
                )),
            }
        };
        return Outcome::Ok {
            id: pin.id.clone(),
            how: How::Pinned { at: pin.at },
            warning,
        };
    }
    match holders.as_slice() {
        [one] => Outcome::Ok {
            id: one.to_string(),
            how: How::New,
            warning: None,
        },
        [] if names.is_empty() => Outcome::Unresolved(format!(
            "the hook named {name:?} can't be found yet: the hook list comes from the relay when \
             `00hooks run` starts. It doesn't run until then, or write the hook's id"
        )),
        [] => Outcome::Unresolved(format!(
            "no hook is named {name:?} (`00hooks hooks list` shows them), so it doesn't run; check \
             the name, or write the hook's id"
        )),
        many => Outcome::Unresolved(format!(
            "{} hooks are named {name:?} ({}), so it doesn't run; write the id of the one you mean",
            many.len(),
            many.join(", ")
        )),
    }
}

/// Resolve every hook reference of `config` against the relay's hook list (`names`, id → name)
/// and the pins. Pure: the caller records `new_pins`.
pub fn resolve(config: &Automations, names: &BTreeMap<String, String>, pins: &Pins) -> Resolution {
    let mut r = Resolution::default();
    let mut outcomes: BTreeMap<String, Outcome> = BTreeMap::new();
    for (reference, line, who) in uses(config) {
        if is_id(&reference, names) {
            if !r.refs.ids.contains_key(&reference) {
                r.refs.ids.insert(reference.clone(), reference.clone());
                r.resolved.push(Resolved {
                    reference: reference.clone(),
                    id: reference,
                    how: How::Id,
                });
            }
            continue;
        }
        let outcome = outcomes
            .entry(reference.clone())
            .or_insert_with(|| resolve_name(&reference, names, pins));
        match outcome {
            Outcome::Ok { id, how, warning } => {
                if let Some(w) = warning {
                    r.warnings.push(Problem {
                        line,
                        message: format!("{who}: {w}"),
                    });
                }
                if !r.refs.ids.contains_key(&reference) {
                    r.refs.ids.insert(reference.clone(), id.clone());
                    if *how == How::New {
                        r.new_pins.push((reference.clone(), id.clone()));
                    }
                    r.resolved.push(Resolved {
                        reference,
                        id: id.clone(),
                        how: how.clone(),
                    });
                }
            }
            Outcome::Unresolved(m) => r.problems.push(Problem {
                line,
                message: format!("{who}: {m}"),
            }),
        }
    }
    r
}

/// One line about how a reference resolved, for `00hooks automations check`.
pub fn describe(r: &Resolved) -> String {
    match &r.how {
        How::Id => format!("hook {} is matched by its id", r.id),
        How::Pinned { at } => format!("hook {:?} is {} (pinned {})", r.reference, r.id, clock(*at)),
        How::New => format!(
            "hook {:?} is {} (pinned to it when the runner next reads the file)",
            r.reference, r.id
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn config(yaml: &str) -> Automations {
        crate::config::parse(yaml, Path::new("a.yaml")).unwrap()
    }

    fn names(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(i, n)| (i.to_string(), n.to_string()))
            .collect()
    }

    const YAML: &str = r#"
hooks:
  payments: { structure_only: true }
automations:
  - name: Pay
    when: { hook: payments, kinds: any }
    then: [{ notify: x }]
  - name: Ci
    when: { hook: hk_ci, kinds: [push] }
    then: [{ notify: x }]
"#;

    #[test]
    fn names_resolve_to_one_id_and_are_pinned_ids_stay_ids() {
        let c = config(YAML);
        let r = resolve(
            &c,
            &names(&[("hk_pay", "payments"), ("hk_ci", "ci")]),
            &Pins::new(),
        );
        assert!(r.problems.is_empty() && r.warnings.is_empty(), "{r:?}");
        assert!(r.refs.matches("payments", "hk_pay"));
        assert!(!r.refs.matches("payments", "hk_ci"));
        assert!(r.refs.matches("hk_ci", "hk_ci"));
        assert_eq!(
            r.new_pins,
            vec![("payments".to_string(), "hk_pay".to_string())]
        );
        // Once per reference, though the file names it twice.
        assert_eq!(r.resolved.len(), 2);
        assert!(describe(&r.resolved[0]).contains("when the runner next reads the file"));
        assert_eq!(describe(&r.resolved[1]), "hook hk_ci is matched by its id");
    }

    #[test]
    fn a_name_that_resolves_to_no_hook_or_to_several_is_a_problem_and_matches_nothing() {
        let c = config(YAML);
        let r = resolve(&c, &names(&[("hk_ci", "ci")]), &Pins::new());
        assert_eq!(r.problems.len(), 2, "{r:?}");
        assert_eq!(r.problems[0].line, 3);
        assert!(
            r.problems[0]
                .message
                .starts_with("hooks: \"payments\": no hook is named")
        );
        assert!(
            r.problems[1]
                .message
                .starts_with("\"Pay\": when: hook: no hook is named")
        );
        assert_eq!(r.refs.id("payments"), None);
        assert!(r.new_pins.is_empty());

        let r = resolve(
            &c,
            &names(&[("hk_a", "payments"), ("hk_b", "payments")]),
            &Pins::new(),
        );
        assert!(
            r.problems[0]
                .message
                .contains("2 hooks are named \"payments\" (hk_a, hk_b)"),
            "{r:?}"
        );
        assert_eq!(r.refs.id("payments"), None);

        // No list at all yet (offline, nothing cached): it says so.
        let r = resolve(&c, &BTreeMap::new(), &Pins::new());
        assert!(
            r.problems[0].message.contains("can't be found yet"),
            "{r:?}"
        );
        // Ids need no list.
        assert!(r.refs.matches("hk_ci", "hk_ci"));
    }

    #[test]
    fn a_pin_holds_when_the_name_moves_and_says_so() {
        let c = config(YAML);
        let pins = Pins::from([(
            "payments".to_string(),
            Pin {
                id: "hk_pay".into(),
                at: 1792233600000,
            },
        )]);
        // The person's hook was renamed and another took the name (a leaked key, say).
        let list = names(&[("hk_pay", "billing"), ("hk_evil", "payments")]);
        let r = resolve(&c, &list, &pins);
        assert!(r.problems.is_empty(), "{r:?}");
        assert!(r.refs.matches("payments", "hk_pay"));
        assert!(!r.refs.matches("payments", "hk_evil"));
        assert!(r.new_pins.is_empty());
        assert_eq!(r.warnings.len(), 2, "one per use: {r:?}");
        let w = &r.warnings[0].message;
        assert!(
            w.contains("now belongs to hk_evil, not to hk_pay")
                && w.contains("keep using hk_pay")
                && w.contains("2026-10-17 10:40 UTC")
                && w.contains("write its id"),
            "{w}"
        );
        assert_eq!(
            describe(&r.resolved[0]),
            "hook \"payments\" is hk_pay (pinned 2026-10-17 10:40 UTC)"
        );

        // Renamed, nobody took the name: still the pinned hook, with a word.
        let r = resolve(&c, &names(&[("hk_pay", "billing")]), &pins);
        assert!(r.refs.matches("payments", "hk_pay"));
        assert!(
            r.warnings[0].message.contains("is now named \"billing\""),
            "{r:?}"
        );
        // Deleted: nothing matches, and the name doesn't move.
        let r = resolve(&c, &names(&[("hk_ci", "ci")]), &pins);
        assert!(r.refs.matches("payments", "hk_pay"));
        assert!(r.warnings[0].message.contains("no longer exists"), "{r:?}");
        // Unchanged, or no list to compare with: no warning.
        let r = resolve(&c, &names(&[("hk_pay", "payments")]), &pins);
        assert!(r.warnings.is_empty() && r.problems.is_empty(), "{r:?}");
        let r = resolve(&c, &BTreeMap::new(), &pins);
        assert!(r.warnings.is_empty() && r.problems.is_empty(), "{r:?}");
        assert!(r.refs.matches("payments", "hk_pay"));
    }

    #[test]
    fn aliases_are_the_names_not_the_ids() {
        let c = config(YAML);
        let a = aliases(&c, &names(&[("hk_ci", "ci")]));
        assert_eq!(a.into_iter().collect::<Vec<_>>(), vec!["payments"]);
    }

    #[test]
    fn a_hook_named_like_an_id_is_never_matched_by_name() {
        let c = config(
            "automations:\n  - name: A\n    when: { hook: hk_victim, kinds: any }\n    then: [{notify: x}]\n",
        );
        // Someone names a hook of theirs after the id an automation uses.
        let r = resolve(&c, &names(&[("hk_evil", "hk_victim")]), &Pins::new());
        assert!(r.refs.matches("hk_victim", "hk_victim"));
        assert!(!r.refs.matches("hk_victim", "hk_evil"));
        assert!(r.new_pins.is_empty());
    }

    #[test]
    fn pins_round_trip_and_a_broken_file_is_an_error() {
        let dir = crate::testutil::temp_dir("pins");
        assert!(load_pins(&dir).unwrap().is_empty());
        let pins = Pins::from([(
            "payments".to_string(),
            Pin {
                id: "hk_pay".into(),
                at: 1,
            },
        )]);
        save_pins(&dir, &pins).unwrap();
        assert_eq!(load_pins(&dir).unwrap(), pins);
        std::fs::write(dir.join(PINS_FILE), b"{not json").unwrap();
        assert!(load_pins(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
