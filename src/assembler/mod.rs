pub mod provenance;

pub use provenance::{BoundaryClass, PromptProvenance, ProvenanceRecord, TransformationKind};

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::{json, Map, Value};

use crate::hash::blake3_hash;
use crate::output::{canonical_json_bytes, sort_value};
use crate::policy::AirlockPolicy;
use crate::refusal::RefusalEnvelope;
use crate::types::BoundaryMode;

#[derive(Debug, Clone, PartialEq)]
pub struct InputArtifact {
    pub path: PathBuf,
    pub content_hash: String,
    pub data: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssemblyResult {
    pub prompt_payload: Value,
    pub prompt_provenance: PromptProvenance,
    pub prompt_payload_hash: String,
    pub system_prompt_hash: String,
}

pub fn assemble(
    policy: &AirlockPolicy,
    inputs: &[InputArtifact],
    system_prompt: &str,
    boundary_mode: BoundaryMode,
) -> Result<AssemblyResult, RefusalEnvelope> {
    validate_inputs(inputs)?;

    let system_prompt_hash = blake3_hash(system_prompt.as_bytes());
    let policy_hash = hash_policy_content(policy)?;
    let mut user_content = Value::Object(Map::new());
    let mut records = vec![
        synthetic_record(
            "messages[0].role",
            "system",
            "template.messages[0].role",
            "message_template.system_role",
        ),
        synthetic_record(
            "messages[0].content",
            system_prompt,
            "system_prompt",
            "system_prompt",
        ),
        synthetic_record(
            "messages[1].role",
            "user",
            "template.messages[1].role",
            "message_template.user_role",
        ),
    ];

    for (rule_index, rule) in policy.allowed_keys.iter().enumerate() {
        let boundary_class = classify_rule(policy, &rule.key_path, rule.boundary_class)?;
        if boundary_mode == BoundaryMode::TelemetryOnly
            && matches!(boundary_class, BoundaryClass::DerivedText)
        {
            continue;
        }

        if let Some((artifact, value)) = find_first_matching_input(inputs, &rule.key_path) {
            insert_value_at_path(&mut user_content, &rule.key_path, value.clone()).map_err(
                |detail| {
                    RefusalEnvelope::internal(
                        "failed to assemble prompt payload from allowed key",
                        detail,
                    )
                },
            )?;

            let rule_id = format!("allowed_keys[{rule_index}]");
            record_value_fragments(
                &mut records,
                &format!("messages[1].content.{}", rule.key_path),
                &rule.key_path,
                value,
                &artifact.content_hash,
                &rule_id,
                boundary_class,
            );
        }
    }

    let user_content = sort_value(user_content);
    if user_content.as_object().is_some_and(Map::is_empty) {
        records.push(synthetic_record(
            "messages[1].content",
            "{}",
            "template.messages[1].content",
            "message_template.user_content",
        ));
    }

    let prompt_payload = sort_value(json!({
        "messages": [
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": user_content,
            }
        ]
    }));
    let prompt_payload_hash = blake3_hash(&canonical_json_bytes(&prompt_payload));
    let prompt_provenance = PromptProvenance::new(
        policy_hash,
        prompt_payload_hash.clone(),
        boundary_mode,
        records,
    );

    ensure_provenance_coverage(&prompt_payload, &prompt_provenance)?;

    Ok(AssemblyResult {
        prompt_payload,
        prompt_provenance,
        prompt_payload_hash,
        system_prompt_hash,
    })
}

fn validate_inputs(inputs: &[InputArtifact]) -> Result<(), RefusalEnvelope> {
    for input in inputs {
        if !input.data.is_object() {
            return Err(RefusalEnvelope::bad_input(
                "input artifact root must be a JSON object",
                json!({
                    "actual_type": json_type_name(&input.data),
                    "path": input.path.display().to_string(),
                }),
            ));
        }
    }

    Ok(())
}

fn hash_policy_content(policy: &AirlockPolicy) -> Result<String, RefusalEnvelope> {
    let value = serde_json::to_value(policy).map_err(|error| {
        RefusalEnvelope::internal(
            "failed to serialize policy for deterministic hashing",
            json!({ "error": error.to_string() }),
        )
    })?;

    Ok(blake3_hash(&canonical_json_bytes(&sort_value(value))))
}

fn classify_rule(
    policy: &AirlockPolicy,
    key_path: &str,
    override_class: Option<BoundaryClass>,
) -> Result<BoundaryClass, RefusalEnvelope> {
    if matches!(override_class, Some(BoundaryClass::Forbidden)) {
        return Err(RefusalEnvelope::internal(
            "allow rule cannot emit FORBIDDEN boundary class",
            json!({ "key_path": key_path }),
        ));
    }

    if policy
        .derived_text_paths
        .iter()
        .any(|path| path == key_path)
    {
        Ok(BoundaryClass::DerivedText)
    } else if let Some(boundary_class) = override_class {
        Ok(boundary_class)
    } else {
        Ok(BoundaryClass::Telemetry)
    }
}

fn synthetic_record(
    prompt_path: &str,
    value: &str,
    source_path: &str,
    policy_rule_id: &str,
) -> ProvenanceRecord {
    let emitted_value = Value::String(value.to_string());
    ProvenanceRecord {
        prompt_path: prompt_path.to_string(),
        emitted_value_hash: blake3_hash(&canonical_json_bytes(&emitted_value)),
        source_artifact_hash: blake3_hash(value.as_bytes()),
        source_path: source_path.to_string(),
        transformation_kind: TransformationKind::Template,
        policy_rule_id: policy_rule_id.to_string(),
        boundary_class: BoundaryClass::Telemetry,
        admitted_boundary_modes: vec![BoundaryMode::Annotated, BoundaryMode::TelemetryOnly],
    }
}

fn find_first_matching_input<'a>(
    inputs: &'a [InputArtifact],
    key_path: &str,
) -> Option<(&'a InputArtifact, &'a Value)> {
    inputs
        .iter()
        .find_map(|input| value_at_path(&input.data, key_path).map(|value| (input, value)))
}

fn value_at_path<'a>(value: &'a Value, key_path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in key_path.split('.') {
        current = current.as_object()?.get(segment)?;
    }

    Some(current)
}

fn insert_value_at_path(target: &mut Value, key_path: &str, value: Value) -> Result<(), Value> {
    let mut current = target;
    let segments: Vec<&str> = key_path.split('.').collect();

    for (index, segment) in segments.iter().enumerate() {
        let is_last = index == segments.len() - 1;
        let object = current
            .as_object_mut()
            .ok_or_else(|| json!({ "key_path": key_path, "segment": segment }))?;

        if is_last {
            object.insert((*segment).to_string(), value);
            return Ok(());
        }

        current = object
            .entry((*segment).to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }

    Ok(())
}

fn record_value_fragments(
    records: &mut Vec<ProvenanceRecord>,
    prompt_path: &str,
    source_path: &str,
    value: &Value,
    source_artifact_hash: &str,
    policy_rule_id: &str,
    boundary_class: BoundaryClass,
) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            for key in keys {
                let child = &map[&key];
                record_value_fragments(
                    records,
                    &format!("{prompt_path}.{key}"),
                    &format!("{source_path}.{key}"),
                    child,
                    source_artifact_hash,
                    policy_rule_id,
                    boundary_class,
                );
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for (index, item) in items.iter().enumerate() {
                record_value_fragments(
                    records,
                    &format!("{prompt_path}[{index}]"),
                    &format!("{source_path}[{index}]"),
                    item,
                    source_artifact_hash,
                    policy_rule_id,
                    boundary_class,
                );
            }
        }
        _ => records.push(ProvenanceRecord {
            prompt_path: prompt_path.to_string(),
            emitted_value_hash: blake3_hash(&canonical_json_bytes(value)),
            source_artifact_hash: source_artifact_hash.to_string(),
            source_path: source_path.to_string(),
            transformation_kind: if matches!(boundary_class, BoundaryClass::DerivedText) {
                TransformationKind::DerivedAnnotation
            } else {
                TransformationKind::Copy
            },
            policy_rule_id: policy_rule_id.to_string(),
            boundary_class,
            admitted_boundary_modes: match boundary_class {
                BoundaryClass::Telemetry => {
                    vec![BoundaryMode::Annotated, BoundaryMode::TelemetryOnly]
                }
                BoundaryClass::DerivedText => vec![BoundaryMode::Annotated],
                BoundaryClass::Forbidden => Vec::new(),
            },
        }),
    }
}

fn ensure_provenance_coverage(
    prompt_payload: &Value,
    prompt_provenance: &PromptProvenance,
) -> Result<(), RefusalEnvelope> {
    let prompt_paths = collect_fragment_paths(prompt_payload, None);
    let provenance_paths: BTreeSet<String> = prompt_provenance
        .records
        .iter()
        .map(|record| record.prompt_path.clone())
        .collect();

    let missing: Vec<String> = prompt_paths
        .difference(&provenance_paths)
        .cloned()
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(RefusalEnvelope::internal(
            "assembled prompt contains bytes without provenance coverage",
            json!({ "missing_paths": missing }),
        ))
    }
}

fn collect_fragment_paths(value: &Value, path: Option<&str>) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    match value {
        Value::Object(map) if !map.is_empty() => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            for key in keys {
                let next_path = join_object_path(path, &key);
                paths.extend(collect_fragment_paths(&map[&key], Some(&next_path)));
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for (index, item) in items.iter().enumerate() {
                let next_path = join_array_path(path, index);
                paths.extend(collect_fragment_paths(item, Some(&next_path)));
            }
        }
        _ => {
            if let Some(path) = path {
                paths.insert(path.to_string());
            }
        }
    }

    paths
}

fn join_object_path(base: Option<&str>, key: &str) -> String {
    match base {
        Some(base) => format!("{base}.{key}"),
        None => key.to_string(),
    }
}

fn join_array_path(base: Option<&str>, index: usize) -> String {
    match base {
        Some(base) => format!("{base}[{index}]"),
        None => format!("[{index}]"),
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AllowRule, ForbiddenPattern};
    use crate::types::ClaimLevel;
    use std::path::Path;

    fn sample_policy() -> AirlockPolicy {
        AirlockPolicy {
            policy_id: "tournament_baseline".to_string(),
            version: "airlock.v0".to_string(),
            allowed_keys: vec![
                AllowRule {
                    key_path: "family_id".to_string(),
                    description: None,
                    boundary_class: None,
                },
                AllowRule {
                    key_path: "benchmark_summary.score".to_string(),
                    description: None,
                    boundary_class: Some(BoundaryClass::Telemetry),
                },
                AllowRule {
                    key_path: "mutator_context.challenge_observation".to_string(),
                    description: None,
                    boundary_class: None,
                },
            ],
            forbidden_keys: vec!["html_path".to_string()],
            forbidden_patterns: vec![ForbiddenPattern {
                pattern: "<[a-z][^>]*>".to_string(),
                description: None,
                artifact_class: Some("raw_html".to_string()),
            }],
            derived_text_paths: vec!["mutator_context.challenge_observation".to_string()],
            claim_levels: vec![
                ClaimLevel::BoundaryFailed,
                ClaimLevel::RawDocumentAbsent,
                ClaimLevel::StrictTelemetryOnly,
            ],
        }
    }

    fn sample_inputs() -> Vec<InputArtifact> {
        vec![
            InputArtifact {
                path: Path::new("strategy_space.json").to_path_buf(),
                content_hash: blake3_hash(
                    br#"{"benchmark_summary":{"score":97},"family_id":"family-001","mutator_context":{"challenge_observation":"Dense footnotes in note disclosures."}}"#,
                ),
                data: json!({
                    "family_id": "family-001",
                    "benchmark_summary": {
                        "score": 97
                    },
                    "mutator_context": {
                        "challenge_observation": "Dense footnotes in note disclosures."
                    }
                }),
            },
            InputArtifact {
                path: Path::new("heuristic.json").to_path_buf(),
                content_hash: blake3_hash(br#"{"unused":"ignored"}"#),
                data: json!({
                    "unused": "ignored"
                }),
            },
        ]
    }

    #[test]
    fn assemble_is_deterministic_for_same_inputs() {
        let policy = sample_policy();
        let inputs = sample_inputs();

        let first = assemble(&policy, &inputs, "System prompt", BoundaryMode::Annotated).unwrap();
        let second = assemble(&policy, &inputs, "System prompt", BoundaryMode::Annotated).unwrap();

        assert_eq!(first.prompt_payload, second.prompt_payload);
        assert_eq!(first.prompt_payload_hash, second.prompt_payload_hash);
        assert_eq!(
            first.prompt_provenance.hash(),
            second.prompt_provenance.hash()
        );
    }

    #[test]
    fn telemetry_only_strips_derived_text_fields() {
        let policy = sample_policy();
        let inputs = sample_inputs();

        let annotated = assemble(&policy, &inputs, "System prompt", BoundaryMode::Annotated)
            .unwrap()
            .prompt_payload;
        let telemetry_only = assemble(
            &policy,
            &inputs,
            "System prompt",
            BoundaryMode::TelemetryOnly,
        )
        .unwrap()
        .prompt_payload;

        assert_eq!(
            annotated["messages"][1]["content"]["mutator_context"]["challenge_observation"],
            "Dense footnotes in note disclosures."
        );
        assert!(telemetry_only["messages"][1]["content"]["mutator_context"]
            ["challenge_observation"]
            .is_null());
    }

    #[test]
    fn every_prompt_fragment_has_provenance() {
        let policy = sample_policy();
        let inputs = sample_inputs();
        let result = assemble(&policy, &inputs, "System prompt", BoundaryMode::Annotated).unwrap();

        let prompt_paths = collect_fragment_paths(&result.prompt_payload, None);
        let record_paths: BTreeSet<String> = result
            .prompt_provenance
            .records
            .iter()
            .map(|record| record.prompt_path.clone())
            .collect();

        assert_eq!(prompt_paths, record_paths);
    }

    #[test]
    fn invalid_input_json_returns_refusal() {
        let policy = sample_policy();
        let invalid_inputs = vec![InputArtifact {
            path: Path::new("bad.json").to_path_buf(),
            content_hash: blake3_hash(br#"["not","an","object"]"#),
            data: json!(["not", "an", "object"]),
        }];

        let refusal = assemble(
            &policy,
            &invalid_inputs,
            "System prompt",
            BoundaryMode::Annotated,
        )
        .unwrap_err();

        assert_eq!(refusal.refusal.code.as_str(), "E_BAD_INPUT");
    }

    #[test]
    fn system_prompt_hash_uses_raw_string_bytes() {
        let policy = sample_policy();
        let inputs = sample_inputs();
        let result = assemble(&policy, &inputs, "System prompt", BoundaryMode::Annotated).unwrap();

        assert_eq!(result.system_prompt_hash, blake3_hash(b"System prompt"));
    }
}
