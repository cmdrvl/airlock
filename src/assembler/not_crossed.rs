//! The negative inventory of an assembly: every input field that did not cross the boundary.
//!
//! `assemble` emits exactly the allowed-key paths it finds in the inputs. Everything else in
//! the inputs stays behind, and this module records what, so a manifest can answer "what did
//! NOT cross" as well as "what did". Values are never stored: an entry carries the path, the
//! input artifact it came from, a hash of the value and the reason it stayed behind.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use cmdrvl_core::jcs;

use super::{InputArtifact, join_array_path, join_object_path, value_at_path};
use crate::hash::blake3_hash;
use crate::types::BoundaryMode;

pub const NOT_CROSSED_VERSION: &str = "airlock.not_crossed.v1";

/// Why a field stayed behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NotCrossedReason {
    /// No allowed key admits this path.
    NotAllowed,
    /// The path is, or contains, an object key the policy lists in `forbidden_keys`.
    ForbiddenKey,
    /// An allowed derived-text path, withheld because the mode is TELEMETRY_ONLY.
    DerivedTextExcluded,
    /// An allowed path that an earlier input already supplied; assemble takes the first.
    ShadowedByEarlierInput,
}

/// One withheld field. The value itself is never stored, only its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotCrossedEntry {
    /// Where the field sat in its input: dotted object keys with `[i]` array indexes, the
    /// notation of the policy's allowed keys and of provenance source paths.
    pub path: String,
    /// Content hash of the input artifact the field came from.
    pub source_artifact_hash: String,
    /// `blake3(RFC 8785 JCS(value))`; integers beyond 2^53, which JCS refuses, hash as exact
    /// decimal digits since nothing downstream recomputes a value that never crossed.
    pub value_hash: String,
    pub reason: NotCrossedReason,
}

/// The sidecar `assemble --not-crossed-out` writes and `verify --not-crossed` reads. It names
/// the policy and prompt payload it belongs to, so verify can refuse one from another run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotCrossedInventory {
    pub version: String,
    pub policy_hash: String,
    pub prompt_payload_hash: String,
    pub boundary_mode: BoundaryMode,
    pub entries: Vec<NotCrossedEntry>,
}

impl NotCrossedInventory {
    pub fn new(
        policy_hash: impl Into<String>,
        prompt_payload_hash: impl Into<String>,
        boundary_mode: BoundaryMode,
        entries: Vec<NotCrossedEntry>,
    ) -> Self {
        Self {
            version: NOT_CROSSED_VERSION.to_string(),
            policy_hash: policy_hash.into(),
            prompt_payload_hash: prompt_payload_hash.into(),
            boundary_mode,
            entries,
        }
    }

    pub fn to_canonical_json(&self) -> String {
        let value = serde_json::to_value(self).expect("not-crossed inventory serializes to JSON");
        crate::output::canonical_json(&value)
    }
}

/// One allowed-key rule as `assemble` applied it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CrossingRule {
    pub key_path: String,
    /// True when the rule is withheld in this mode (a derived-text path in TELEMETRY_ONLY).
    pub excluded: bool,
}

/// Every field of `inputs` that `assemble` leaves out, in a deterministic order: by input,
/// then by path. Entries are the maximal withheld subtrees that hold no forbidden key, plus
/// each forbidden-key subtree on its own, so a forbidden key buried in an unlisted object is
/// still reported as one.
pub(super) fn inventory(
    inputs: &[InputArtifact],
    rules: &[CrossingRule],
    forbidden_keys: &[String],
) -> Vec<NotCrossedEntry> {
    // assemble takes the first input that holds an allowed path; later ones are shadowed.
    let selected: Vec<(&str, Option<usize>)> = rules
        .iter()
        .filter(|rule| !rule.excluded)
        .map(|rule| {
            let first = inputs
                .iter()
                .position(|input| value_at_path(&input.data, &rule.key_path).is_some());
            (rule.key_path.as_str(), first)
        })
        .collect();

    let mut found: Vec<(usize, NotCrossedEntry)> = Vec::new();
    for (index, input) in inputs.iter().enumerate() {
        let Some(object) = input.data.as_object() else {
            continue;
        };
        let mut walk = Walk {
            input,
            index,
            rules,
            selected: &selected,
            forbidden_keys,
            found: &mut found,
        };
        walk.object(object, None);
    }
    found.sort_by(|(left_index, left), (right_index, right)| {
        (left_index, &left.path).cmp(&(right_index, &right.path))
    });
    found.into_iter().map(|(_, entry)| entry).collect()
}

struct Walk<'a> {
    input: &'a InputArtifact,
    index: usize,
    rules: &'a [CrossingRule],
    selected: &'a [(&'a str, Option<usize>)],
    forbidden_keys: &'a [String],
    found: &'a mut Vec<(usize, NotCrossedEntry)>,
}

impl Walk<'_> {
    fn object(&mut self, object: &Map<String, Value>, prefix: Option<&str>) {
        for (key, child) in object {
            let path = join_object_path(prefix, key);
            if let Some((_, first)) = self.selected.iter().find(|(rule, _)| *rule == path) {
                // An allowed path: it crossed unless an earlier input supplied it.
                if *first != Some(self.index) {
                    self.record(&path, child, NotCrossedReason::ShadowedByEarlierInput);
                }
            } else if self
                .rules
                .iter()
                .any(|rule| rule.excluded && rule.key_path == path)
            {
                self.record(&path, child, NotCrossedReason::DerivedTextExcluded);
            } else if let (true, Some(nested)) = (self.leads_to_a_rule(&path), child.as_object()) {
                self.object(nested, Some(&path));
            } else if self.is_forbidden(key) {
                self.record(&path, child, NotCrossedReason::ForbiddenKey);
            } else {
                self.withhold(child, &path);
            }
        }
    }

    /// True when some rule's path lies strictly below `path`, so an object there may hold a
    /// crossing field and has to be searched rather than withheld whole.
    fn leads_to_a_rule(&self, path: &str) -> bool {
        self.rules.iter().any(|rule| {
            rule.key_path
                .strip_prefix(path)
                .is_some_and(|rest| rest.starts_with('.'))
        })
    }

    fn is_forbidden(&self, key: &str) -> bool {
        self.forbidden_keys.iter().any(|forbidden| forbidden == key)
    }

    /// Record a withheld subtree, splitting it where a forbidden key hides inside.
    fn withhold(&mut self, value: &Value, path: &str) {
        if !self.holds_forbidden_key(value) {
            self.record(path, value, NotCrossedReason::NotAllowed);
            return;
        }
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    let child_path = join_object_path(Some(path), key);
                    if self.is_forbidden(key) {
                        self.record(&child_path, child, NotCrossedReason::ForbiddenKey);
                    } else {
                        self.withhold(child, &child_path);
                    }
                }
            }
            Value::Array(items) => {
                for (position, child) in items.iter().enumerate() {
                    self.withhold(child, &join_array_path(Some(path), position));
                }
            }
            _ => self.record(path, value, NotCrossedReason::NotAllowed),
        }
    }

    fn holds_forbidden_key(&self, value: &Value) -> bool {
        match value {
            Value::Object(object) => object
                .iter()
                .any(|(key, child)| self.is_forbidden(key) || self.holds_forbidden_key(child)),
            Value::Array(items) => items.iter().any(|child| self.holds_forbidden_key(child)),
            _ => false,
        }
    }

    fn record(&mut self, path: &str, value: &Value, reason: NotCrossedReason) {
        self.found.push((
            self.index,
            NotCrossedEntry {
                path: path.to_string(),
                source_artifact_hash: self.input.content_hash.clone(),
                value_hash: value_hash(value),
                reason,
            },
        ));
    }
}

fn value_hash(value: &Value) -> String {
    let canonical = jcs::to_string(value).unwrap_or_else(|_| jcs::to_string_exact_integers(value));
    blake3_hash(canonical.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use super::*;

    const SOURCE: &str = "blake3:0000000000000000000000000000000000000000000000000000000000000001";
    const SECOND: &str = "blake3:0000000000000000000000000000000000000000000000000000000000000002";

    fn input(content_hash: &str, data: Value) -> InputArtifact {
        InputArtifact {
            path: PathBuf::from("input.json"),
            content_hash: content_hash.to_string(),
            data,
        }
    }

    fn rule(key_path: &str, excluded: bool) -> CrossingRule {
        CrossingRule {
            key_path: key_path.to_string(),
            excluded,
        }
    }

    fn forbidden() -> Vec<String> {
        vec!["html_path".to_string()]
    }

    fn hash_of(canonical: &str) -> String {
        blake3_hash(canonical.as_bytes())
    }

    fn summary(entries: &[NotCrossedEntry]) -> Vec<(&str, NotCrossedReason)> {
        entries
            .iter()
            .map(|entry| (entry.path.as_str(), entry.reason))
            .collect()
    }

    #[test]
    fn unlisted_fields_are_recorded_and_allowed_ones_are_not() {
        let inputs = [input(
            SOURCE,
            json!({"family_id": "f", "extra": {"a": 1}, "count": 3}),
        )];

        let entries = inventory(&inputs, &[rule("family_id", false)], &forbidden());

        assert_eq!(
            summary(&entries),
            [
                ("count", NotCrossedReason::NotAllowed),
                ("extra", NotCrossedReason::NotAllowed)
            ]
        );
        assert_eq!(entries[0].value_hash, hash_of("3"));
        assert_eq!(entries[1].value_hash, hash_of(r#"{"a":1}"#));
        assert!(
            entries
                .iter()
                .all(|entry| entry.source_artifact_hash == SOURCE)
        );
    }

    #[test]
    fn a_field_inside_a_partly_allowed_object_is_found_below_the_allowed_path() {
        let inputs = [input(SOURCE, json!({"a": {"b": 1, "c": 2}}))];

        let entries = inventory(&inputs, &[rule("a.b", false)], &forbidden());

        assert_eq!(summary(&entries), [("a.c", NotCrossedReason::NotAllowed)]);
    }

    #[test]
    fn a_scalar_where_an_allowed_path_needs_an_object_is_withheld_whole() {
        let inputs = [input(SOURCE, json!({"a": 5}))];

        let entries = inventory(&inputs, &[rule("a.b", false)], &forbidden());

        assert_eq!(summary(&entries), [("a", NotCrossedReason::NotAllowed)]);
    }

    #[test]
    fn a_derived_text_path_is_withheld_only_when_the_mode_excludes_it() {
        let inputs = [input(SOURCE, json!({"note": "text", "n": 1}))];

        let excluded = inventory(
            &inputs,
            &[rule("n", false), rule("note", true)],
            &forbidden(),
        );
        let admitted = inventory(
            &inputs,
            &[rule("n", false), rule("note", false)],
            &forbidden(),
        );

        assert_eq!(
            summary(&excluded),
            [("note", NotCrossedReason::DerivedTextExcluded)]
        );
        assert_eq!(excluded[0].value_hash, hash_of(r#""text""#));
        assert!(admitted.is_empty());
    }

    #[test]
    fn a_forbidden_key_is_reported_at_any_depth_and_splits_its_neighbours() {
        let inputs = [input(
            SOURCE,
            json!({
                "html_path": "/a.html",
                "wrapper": {"keep": 1, "html_path": "/b.html", "items": [{"x": 1}, {"html_path": "c"}]}
            }),
        )];

        let entries = inventory(&inputs, &[], &forbidden());

        assert_eq!(
            summary(&entries),
            [
                ("html_path", NotCrossedReason::ForbiddenKey),
                ("wrapper.html_path", NotCrossedReason::ForbiddenKey),
                ("wrapper.items[0]", NotCrossedReason::NotAllowed),
                ("wrapper.items[1].html_path", NotCrossedReason::ForbiddenKey),
                ("wrapper.keep", NotCrossedReason::NotAllowed),
            ]
        );
        assert_eq!(entries[0].value_hash, hash_of(r#""/a.html""#));
    }

    #[test]
    fn an_allowed_path_supplied_by_an_earlier_input_shadows_later_ones() {
        let inputs = [
            input(SOURCE, json!({"family_id": "first"})),
            input(SECOND, json!({"family_id": "second", "other": 1})),
        ];

        let entries = inventory(&inputs, &[rule("family_id", false)], &forbidden());

        assert_eq!(
            summary(&entries),
            [
                ("family_id", NotCrossedReason::ShadowedByEarlierInput),
                ("other", NotCrossedReason::NotAllowed)
            ]
        );
        assert!(
            entries
                .iter()
                .all(|entry| entry.source_artifact_hash == SECOND)
        );
        assert_eq!(entries[0].value_hash, hash_of(r#""second""#));
    }

    #[test]
    fn a_value_beyond_the_jcs_integer_range_still_hashes_exactly() {
        let inputs = [input(SOURCE, json!({"big": 12345678901234567890u64}))];

        let entries = inventory(&inputs, &[], &forbidden());

        assert_eq!(entries[0].value_hash, hash_of("12345678901234567890"));
    }

    #[test]
    fn the_inventory_holds_hashes_and_paths_but_never_a_withheld_value() {
        let inputs = [input(
            SOURCE,
            json!({"secret_note": "do-not-leak-this-value", "html_path": "/private/page.html"}),
        )];
        let entries = inventory(&inputs, &[], &forbidden());
        let sidecar = NotCrossedInventory::new(SOURCE, SECOND, BoundaryMode::Annotated, entries);

        let text = sidecar.to_canonical_json();

        assert!(!text.contains("do-not-leak-this-value"));
        assert!(!text.contains("/private/page.html"));
        assert!(text.contains("secret_note"), "paths are recorded");
    }

    #[test]
    fn order_follows_the_input_then_the_path_whatever_the_object_key_order() {
        let first = input(SOURCE, json!({"z": 1, "a": 2}));
        let second = input(SECOND, json!({"m": 3}));

        let entries = inventory(&[first, second], &[], &forbidden());

        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            ["a", "z", "m"]
        );
    }

    #[test]
    fn the_sidecar_refuses_unknown_fields_so_a_value_cannot_ride_along() {
        let mut value = serde_json::to_value(NotCrossedInventory::new(
            SOURCE,
            SECOND,
            BoundaryMode::Annotated,
            Vec::new(),
        ))
        .unwrap();
        value["raw_value"] = json!("smuggled");

        assert!(serde_json::from_value::<NotCrossedInventory>(value).is_err());
    }
}
