//! `00hooks automations check`: a valid file checked against what has actually arrived. Unknown
//! hooks, kinds not seen yet, fields a kind doesn't have and fields a kind lost are flagged, so a
//! filter doesn't silently never match.

use std::collections::BTreeMap;

use crate::catalogue::{Catalogue, KindRecord};
use crate::config::{Automations, Problem, Trigger, field_refs};
use crate::hookrefs::{self, Pins, Resolution};
use crate::runner::clock;

fn label(k: &KindRecord, names: &BTreeMap<String, String>) -> String {
    format!("{}/{}", names.get(&k.hook_id).unwrap_or(&k.hook_id), k.kind)
}

/// How the file's hook references resolve against the cached hook list and the runner's pins
/// ([`hookrefs`]), without pinning anything.
pub fn resolution(
    config: &Automations,
    names: &BTreeMap<String, String>,
    pins: &Pins,
) -> Resolution {
    hookrefs::resolve(config, names, pins)
}

/// Warnings, each naming its line: hook references that don't resolve (or whose pin no longer
/// matches the hook list), then what the catalogue says about kinds and fields.
pub fn check(
    config: &Automations,
    cat: &Catalogue,
    names: &BTreeMap<String, String>,
    pins: &Pins,
) -> Vec<Problem> {
    let res = resolution(config, names, pins);
    let mut out: Vec<Problem> = res.problems.iter().chain(&res.warnings).cloned().collect();
    let mut warn = |line: usize, message: String| out.push(Problem { line, message });
    // An id the relay's list doesn't have and that never sent an event.
    let unknown_id = |id: &str| !names.contains_key(id) && !cat.kinds().any(|k| k.hook_id == id);
    for r in &res.resolved {
        if r.how == hookrefs::How::Id && unknown_id(&r.id) {
            for (line, who) in config
                .hooks
                .iter()
                .filter(|h| h.hook == r.reference)
                .map(|h| (h.line, "hooks".to_string()))
                .chain(
                    config
                        .automations
                        .iter()
                        .filter(|a| a.when.hook.as_deref() == Some(r.reference.as_str()))
                        .map(|a| (a.when.line, format!("{:?}", a.name))),
                )
            {
                warn(
                    line,
                    format!(
                        "{who}: no hook {} is known yet: check the id, or run `00hooks hooks list`",
                        r.id
                    ),
                );
            }
        }
    }
    for a in &config.automations {
        let who = format!("{:?}", a.name);
        // A hook that didn't resolve is reported above; its kinds can't be checked.
        if a.when
            .hook
            .as_ref()
            .is_some_and(|h| res.refs.id(h).is_none())
        {
            continue;
        }
        let on_hook = |k: &&KindRecord| {
            a.when
                .hook
                .as_ref()
                .is_none_or(|h| res.refs.matches(h, &k.hook_id))
        };
        let (kinds, any): (&[String], bool) = match &a.when.trigger {
            Trigger::Kinds(k) => (k, k.is_empty()),
            // The payload of a kind not seen yet is unknown, and a shape change is about fields.
            Trigger::NewKind | Trigger::ShapeChanged(_) => continue,
        };
        let records: Vec<&KindRecord> = if any {
            cat.kinds().filter(on_hook).collect()
        } else {
            let mut v = Vec::new();
            for kind in kinds {
                let found: Vec<&KindRecord> = cat
                    .kinds()
                    .filter(on_hook)
                    .filter(|k| &k.kind == kind)
                    .collect();
                if found.is_empty() {
                    let on = a
                        .when
                        .hook
                        .as_deref()
                        .map(|h| format!(" on {h}"))
                        .unwrap_or_default();
                    warn(
                        a.when.line,
                        format!(
                            "{who}: the kind {kind:?} hasn't been seen yet{on} (fine if you're setting the service up now)"
                        ),
                    );
                }
                v.extend(found);
            }
            v
        };
        if records.is_empty() {
            continue;
        }
        for (line, path) in field_refs(a) {
            let key = path.field_key();
            if !matches!(path.root(), "payload" | "headers") || path.segs.len() < 2 {
                continue;
            }
            let have: Vec<&&KindRecord> = records.iter().filter(|k| k.has_field(&key)).collect();
            if have.is_empty() {
                let which: Vec<String> = records.iter().map(|k| label(k, names)).collect();
                warn(
                    line,
                    format!(
                        "{who}: `{path}` isn't a field of {} as seen so far; it would never match",
                        which.join(", ")
                    ),
                );
                continue;
            }
            // Present in some kinds; lost in the latest shape of any?
            for k in &records {
                if let Some(c) = k.changes.last()
                    && c.removed.iter().any(|r| {
                        key == *r
                            || key.starts_with(&format!("{r}."))
                            || key.starts_with(&format!("{r}[]"))
                    })
                {
                    warn(
                        line,
                        format!(
                            "{who}: {} lost `{path}` on {}",
                            label(k, names),
                            clock(c.at)
                        ),
                    );
                }
            }
        }
    }
    out.sort_by_key(|p| p.line);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use serde_json::json;
    use std::path::Path;

    #[test]
    fn flags_unknown_kinds_fields_and_lost_fields() {
        let dir = temp_dir("check");
        let mut cat = Catalogue::open(&dir).unwrap();
        let h = BTreeMap::new();
        let names = BTreeMap::from([("hk_1".to_string(), "github".to_string())]);
        for (i, p) in [
            json!({"action": "opened", "pr": {"auto": 1, "n": 1}}),
            json!({"action": "x", "pr": {"auto": 2, "n": 2}}),
            json!({"action": "y", "pr": {"n": 3}}),
        ]
        .iter()
        .enumerate()
        {
            cat.observe(
                "hk_1",
                "pull_request",
                &format!("e{i}"),
                p,
                &h,
                1792233600000,
                false,
            )
            .unwrap();
        }
        let yaml = r#"
automations:
  - name: A
    when: { hook: github, kinds: [pull_request, issues] }
    only_if: payload.action == "opened" and payload.nope > 1 and payload.pr.auto == 1
    then:
      - notify: "{{payload.pr.n}} {{headers.x-missing}} {{event.id}}"
  - name: B
    when: { hook: gitlab, kinds: any }
    then: [{ notify: x }]
  - name: C
    when: { new_kind: true }
    then: [{ notify: "{{payload.anything}}" }]
"#;
        let config = crate::config::parse(yaml, Path::new("a.yaml")).unwrap();
        let w: Vec<String> = check(&config, &cat, &names, &Pins::new())
            .iter()
            .map(|p| p.to_string())
            .collect();
        assert!(
            w.iter().any(|m| m.starts_with("line 4:")
                && m.contains("\"issues\" hasn't been seen yet on github")),
            "{w:#?}"
        );
        assert!(
            w.iter().any(|m| m.starts_with("line 5:")
                && m.contains("`payload.nope` isn't a field of github/pull_request")),
            "{w:#?}"
        );
        assert!(
            w.iter()
                .any(|m| m.starts_with("line 5:") && m.contains("lost `payload.pr.auto`")),
            "{w:#?}"
        );
        assert!(
            w.iter()
                .any(|m| m.starts_with("line 7:") && m.contains("headers.x-missing")),
            "{w:#?}"
        );
        assert!(
            w.iter()
                .any(|m| m.starts_with("line 9:") && m.contains("no hook is named \"gitlab\"")),
            "{w:#?}"
        );
        assert!(
            !w.iter().any(|m| m.contains("payload.action")
                || m.contains("payload.pr.n`")
                || m.contains("anything")),
            "{w:#?}"
        );
        assert_eq!(w.len(), 5, "{w:#?}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn hook_references_are_checked_by_id_with_the_pins() {
        let dir = temp_dir("check-pins");
        let mut cat = Catalogue::open(&dir).unwrap();
        cat.observe(
            "hk_gh",
            "push",
            "e1",
            &json!({"n": 1}),
            &BTreeMap::new(),
            1792233600000,
            false,
        )
        .unwrap();
        let yaml = r#"
automations:
  - name: A
    when: { hook: github, kinds: [push] }
    then: [{ notify: "{{payload.n}}" }]
  - name: B
    when: { hook: hk_gone, kinds: any }
    then: [{ notify: x }]
"#;
        let config = crate::config::parse(yaml, Path::new("a.yaml")).unwrap();
        // The pinned hook was renamed and another took its name: the check follows the pin, so
        // the kinds it reports are the pinned hook's, and it says the name moved.
        let names = BTreeMap::from([
            ("hk_gh".to_string(), "old-github".to_string()),
            ("hk_new".to_string(), "github".to_string()),
        ]);
        let pins = Pins::from([(
            "github".to_string(),
            crate::hookrefs::Pin {
                id: "hk_gh".into(),
                at: 1792233600000,
            },
        )]);
        let w: Vec<String> = check(&config, &cat, &names, &pins)
            .iter()
            .map(|p| p.to_string())
            .collect();
        assert!(
            w.iter()
                .any(|m| m.starts_with("line 4:")
                    && m.contains("now belongs to hk_new, not to hk_gh")),
            "{w:#?}"
        );
        assert!(
            w.iter()
                .any(|m| m.starts_with("line 7:") && m.contains("no hook hk_gone is known yet")),
            "{w:#?}"
        );
        assert_eq!(w.len(), 2, "push is known on the pinned hook: {w:#?}");
        let r = resolution(&config, &names, &pins);
        assert!(r.refs.matches("github", "hk_gh"));
        assert!(r.new_pins.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
