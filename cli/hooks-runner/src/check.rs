//! `00hooks automations check`: a valid file checked against what has actually arrived. Unknown
//! hooks, kinds not seen yet, fields a kind doesn't have and fields a kind lost are flagged, so a
//! filter doesn't silently never match.

use std::collections::BTreeMap;

use crate::catalogue::{Catalogue, KindRecord};
use crate::config::{Automations, Problem, Trigger, field_refs, hook_matches};
use crate::runner::clock;

fn label(k: &KindRecord, names: &BTreeMap<String, String>) -> String {
    format!("{}/{}", names.get(&k.hook_id).unwrap_or(&k.hook_id), k.kind)
}

/// Warnings, each naming its line.
pub fn check(
    config: &Automations,
    cat: &Catalogue,
    names: &BTreeMap<String, String>,
) -> Vec<Problem> {
    let mut out = Vec::new();
    let mut warn = |line: usize, message: String| out.push(Problem { line, message });
    let known_hook = |h: &str| {
        names.contains_key(h)
            || names.values().any(|n| n == h)
            || cat.kinds().any(|k| k.hook_id == h)
    };
    for h in &config.hooks {
        if !known_hook(&h.hook) {
            warn(
                h.line,
                format!(
                    "hooks: no hook {:?} is known yet (names come from the relay when `00hooks run` starts)",
                    h.hook
                ),
            );
        }
    }
    for a in &config.automations {
        let who = format!("{:?}", a.name);
        if let Some(h) = &a.when.hook
            && !known_hook(h)
        {
            warn(
                a.when.line,
                format!(
                    "{who}: no hook {h:?} is known yet: check the name, or run `00hooks hooks list`"
                ),
            );
        }
        let on_hook = |k: &&KindRecord| {
            a.when
                .hook
                .as_ref()
                .is_none_or(|h| hook_matches(h, &k.hook_id, names))
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
        let w: Vec<String> = check(&config, &cat, &names)
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
        assert!(w.iter().any(|m| m.contains("no hook \"gitlab\"")), "{w:#?}");
        assert!(
            !w.iter().any(|m| m.contains("payload.action")
                || m.contains("payload.pr.n`")
                || m.contains("anything")),
            "{w:#?}"
        );
        assert_eq!(w.len(), 5, "{w:#?}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
