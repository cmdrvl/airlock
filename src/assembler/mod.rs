pub mod not_crossed;
pub mod provenance;

pub use not_crossed::{
    NOT_CROSSED_VERSION, NotCrossedEntry, NotCrossedInventory, NotCrossedReason,
};
pub use provenance::{BoundaryClass, PromptProvenance, ProvenanceRecord, TransformationKind};

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::{Map, Value, json};

use crate::adapter::ResponsePart;
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
    /// Every input field that did not cross the boundary, with the reason. See
    /// [`not_crossed`].
    pub not_crossed: Vec<NotCrossedEntry>,
}

/// The key under the user message's content that carries an earlier turn's material. Reserved:
/// no policy rule may allow a path that starts with it, and `verify` treats any message whose
/// content object has this key as carrying model output.
pub const PRIOR_TURN_KEY: &str = "prior_turn";

/// The key under [`PRIOR_TURN_KEY`] that carries tool results, beside `model_output`.
pub const TOOL_RESULTS_KEY: &str = "tool_results";

/// `policy_rule_id` on every provenance record copied from an earlier response.
pub const MODEL_OUTPUT_RULE_ID: &str = "chain.model_output";

/// `policy_rule_id` on the content record of a tool result whose hash the policy declares.
pub const TOOL_RESULT_RULE_ID: &str = "chain.tool_result";

/// `policy_rule_id` on the content record of a tool result whose hash the policy does not
/// declare. Such a result is recorded as DERIVED_TEXT and caps the claim in `verify`.
pub const TOOL_RESULT_UNDECLARED_RULE_ID: &str = "chain.tool_result.undeclared";

/// A tool result an earlier tool call produced, as the exact text of a local artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResultArtifact {
    /// The `tool_use` id in the response that this result answers.
    pub tool_use_id: String,
    /// The artifact's bytes, which must be UTF-8 text, embedded verbatim. So
    /// `blake3_hash(content.as_bytes())` is the artifact's hash and `verify` can recompute it
    /// from the prompt alone.
    pub content: String,
}

/// An earlier turn's model output, ready to enter the prompt, with any tool results that
/// answered its tool calls. The caller has already checked `response_hash` against a gate
/// receipt; the assembler does not look at receipts.
#[derive(Debug, Clone, PartialEq)]
pub struct PriorTurn<'a> {
    /// `blake3:` hash of the response bytes the parts were read from.
    pub response_hash: &'a str,
    pub parts: &'a [ResponsePart],
    pub tool_results: &'a [ToolResultArtifact],
}

pub fn assemble(
    policy: &AirlockPolicy,
    inputs: &[InputArtifact],
    system_prompt: &str,
    boundary_mode: BoundaryMode,
) -> Result<AssemblyResult, RefusalEnvelope> {
    assemble_with_prior_turn(policy, inputs, system_prompt, boundary_mode, None)
}

/// [`assemble`], plus an earlier turn's model output under [`PRIOR_TURN_KEY`]. With `None` the
/// result is byte-for-byte what `assemble` has always produced.
pub fn assemble_with_prior_turn(
    policy: &AirlockPolicy,
    inputs: &[InputArtifact],
    system_prompt: &str,
    boundary_mode: BoundaryMode,
    prior_turn: Option<&PriorTurn<'_>>,
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

    let mut crossing_rules = Vec::with_capacity(policy.allowed_keys.len());
    for (rule_index, rule) in policy.allowed_keys.iter().enumerate() {
        if rule.key_path.split('.').next() == Some(PRIOR_TURN_KEY) {
            return Err(RefusalEnvelope::bad_policy(
                format!("allowed key cannot start with the reserved name {PRIOR_TURN_KEY}"),
                json!({ "key_path": rule.key_path, "reserved": PRIOR_TURN_KEY }),
            ));
        }
        let boundary_class = classify_rule(policy, &rule.key_path, rule.boundary_class)?;
        let excluded = boundary_mode == BoundaryMode::TelemetryOnly
            && matches!(boundary_class, BoundaryClass::DerivedText);
        crossing_rules.push(not_crossed::CrossingRule {
            key_path: rule.key_path.clone(),
            excluded,
        });
        if excluded {
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

    if let Some(turn) = prior_turn {
        admit_prior_turn(&mut user_content, &mut records, turn, policy)?;
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

    let not_crossed = not_crossed::inventory(inputs, &crossing_rules, &policy.forbidden_keys);

    Ok(AssemblyResult {
        prompt_payload,
        prompt_provenance,
        prompt_payload_hash,
        system_prompt_hash,
        not_crossed,
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
    Ok(crate::policy::resolved_policy_hash(policy))
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

    // MODEL_OUTPUT is assigned only by the chain path, after a response hash was checked against
    // a gate receipt, and TOOL_RESULT only for an artifact the policy declares by hash. A policy
    // rule that could name either would let any input field carry the label.
    if let Some(chain_class @ (BoundaryClass::ModelOutput | BoundaryClass::ToolResult)) =
        override_class
    {
        let name = if chain_class == BoundaryClass::ModelOutput {
            "MODEL_OUTPUT"
        } else {
            "TOOL_RESULT"
        };
        return Err(RefusalEnvelope::bad_policy(
            format!("allow rule cannot assign the {name} boundary class"),
            json!({ "key_path": key_path, "boundary_class": name }),
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
                BoundaryClass::ModelOutput | BoundaryClass::ToolResult => {
                    vec![BoundaryMode::Annotated, BoundaryMode::TelemetryOnly]
                }
                BoundaryClass::Forbidden => Vec::new(),
            },
        }),
    }
}

/// Put an earlier turn's model output into the user message under [`PRIOR_TURN_KEY`] and record
/// every leaf copied from the response as MODEL_OUTPUT. The `kind` tags are airlock's own
/// template text, so they are recorded as template records like the roles. Tool results go in
/// beside it under [`TOOL_RESULTS_KEY`], only when there are any, so a turn without them is
/// byte-identical to what it was before tool results existed.
fn admit_prior_turn(
    user_content: &mut Value,
    records: &mut Vec<ProvenanceRecord>,
    turn: &PriorTurn<'_>,
    policy: &AirlockPolicy,
) -> Result<(), RefusalEnvelope> {
    let base_path = format!("messages[1].content.{PRIOR_TURN_KEY}.model_output");
    let mut blocks = Vec::with_capacity(turn.parts.len());
    for (index, part) in turn.parts.iter().enumerate() {
        let block_path = format!("{base_path}[{index}]");
        let leaf =
            |records: &mut Vec<ProvenanceRecord>, field: &str, source_path: &str, value: &Value| {
                record_value_fragments(
                    records,
                    &format!("{block_path}.{field}"),
                    source_path,
                    value,
                    turn.response_hash,
                    MODEL_OUTPUT_RULE_ID,
                    BoundaryClass::ModelOutput,
                );
            };
        match part {
            ResponsePart::Text { source_path, text } => {
                records.push(synthetic_record(
                    &format!("{block_path}.kind"),
                    "text",
                    &format!("template.{PRIOR_TURN_KEY}.kind"),
                    "chain.kind",
                ));
                leaf(
                    records,
                    "text",
                    &format!("{source_path}.text"),
                    &Value::String(text.clone()),
                );
                blocks.push(json!({ "kind": "text", "text": text }));
            }
            ResponsePart::ToolUse {
                source_path,
                id,
                id_source_path,
                name,
                input,
                input_source_path,
            } => {
                records.push(synthetic_record(
                    &format!("{block_path}.kind"),
                    "tool_use",
                    &format!("template.{PRIOR_TURN_KEY}.kind"),
                    "chain.kind",
                ));
                let mut block = Map::new();
                block.insert("kind".to_string(), json!("tool_use"));
                if let Some(id) = id {
                    let id_value = Value::String(id.clone());
                    leaf(records, "id", id_source_path, &id_value);
                    block.insert("id".to_string(), id_value);
                }
                let name_value = Value::String(name.clone());
                leaf(records, "name", &format!("{source_path}.name"), &name_value);
                block.insert("name".to_string(), name_value);
                leaf(records, "input", input_source_path, input);
                block.insert("input".to_string(), input.clone());
                blocks.push(Value::Object(block));
            }
        }
    }

    let tool_results = admit_tool_results(records, turn, policy)?;

    let object = user_content.as_object_mut().ok_or_else(|| {
        RefusalEnvelope::internal(
            "user content must be an object to carry a prior turn",
            json!({ "key": PRIOR_TURN_KEY }),
        )
    })?;
    let mut prior_turn = Map::new();
    prior_turn.insert("model_output".to_string(), Value::Array(blocks));
    if !tool_results.is_empty() {
        prior_turn.insert(TOOL_RESULTS_KEY.to_string(), Value::Array(tool_results));
    }
    object.insert(PRIOR_TURN_KEY.to_string(), Value::Object(prior_turn));
    Ok(())
}

/// Admit the tool results that answer the response's tool calls, in the response's order (never
/// the order they were supplied in, so the prompt's bytes do not depend on flag order).
///
/// Every supplied result must answer a `tool_use` id the response contains, once. For each, the
/// `tool_use_id` is a copy from the response (MODEL_OUTPUT) and the `content` is the artifact's
/// exact text: TOOL_RESULT when the policy declares its blake3 hash, DERIVED_TEXT when it does not.
/// That label is a record of what happened here. `verify` decides the claim from the prompt and
/// the policy, never from these labels.
fn admit_tool_results(
    records: &mut Vec<ProvenanceRecord>,
    turn: &PriorTurn<'_>,
    policy: &AirlockPolicy,
) -> Result<Vec<Value>, RefusalEnvelope> {
    if turn.tool_results.is_empty() {
        return Ok(Vec::new());
    }

    // The tool_use ids the response holds, in response order, each with where its id was read.
    let mut known: Vec<(&str, &str)> = Vec::new();
    for part in turn.parts {
        if let ResponsePart::ToolUse {
            id: Some(id),
            id_source_path,
            ..
        } = part
            && !known.iter().any(|(seen, _)| seen == id)
        {
            known.push((id.as_str(), id_source_path.as_str()));
        }
    }

    let mut supplied: BTreeMap<&str, &ToolResultArtifact> = BTreeMap::new();
    for result in turn.tool_results {
        let id = result.tool_use_id.as_str();
        if !known.iter().any(|(known_id, _)| *known_id == id) {
            return Err(RefusalEnvelope::bad_input(
                "tool result names a tool_use id that the response does not contain",
                json!({
                    "field": "tool_result.tool_use_id",
                    "tool_use_id": id,
                    "known_tool_use_ids": known.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
                }),
            ));
        }
        if supplied.insert(id, result).is_some() {
            return Err(RefusalEnvelope::bad_input(
                "two tool results answer the same tool_use id",
                json!({ "field": "tool_result.tool_use_id", "tool_use_id": id }),
            ));
        }
    }

    let base_path = format!("messages[1].content.{PRIOR_TURN_KEY}.{TOOL_RESULTS_KEY}");
    let mut blocks = Vec::with_capacity(supplied.len());
    for (id, id_source_path) in known {
        let Some(result) = supplied.get(id) else {
            continue;
        };
        let block_path = format!("{base_path}[{}]", blocks.len());
        records.push(synthetic_record(
            &format!("{block_path}.kind"),
            "tool_result",
            &format!("template.{PRIOR_TURN_KEY}.kind"),
            "chain.kind",
        ));
        record_value_fragments(
            records,
            &format!("{block_path}.tool_use_id"),
            id_source_path,
            &Value::String(id.to_string()),
            turn.response_hash,
            MODEL_OUTPUT_RULE_ID,
            BoundaryClass::ModelOutput,
        );
        records.push(tool_result_content_record(
            format!("{block_path}.content"),
            id,
            &result.content,
            policy,
        ));
        blocks.push(json!({
            "kind": "tool_result",
            "tool_use_id": id,
            "content": result.content,
        }));
    }
    Ok(blocks)
}

fn tool_result_content_record(
    prompt_path: String,
    tool_use_id: &str,
    content: &str,
    policy: &AirlockPolicy,
) -> ProvenanceRecord {
    let artifact_hash = blake3_hash(content.as_bytes());
    let declared = policy.declares_tool_result(&artifact_hash);
    ProvenanceRecord {
        prompt_path,
        emitted_value_hash: blake3_hash(&canonical_json_bytes(&Value::String(content.to_string()))),
        source_artifact_hash: artifact_hash,
        source_path: format!("tool_result.{tool_use_id}"),
        transformation_kind: TransformationKind::Copy,
        policy_rule_id: if declared {
            TOOL_RESULT_RULE_ID
        } else {
            TOOL_RESULT_UNDECLARED_RULE_ID
        }
        .to_string(),
        boundary_class: if declared {
            BoundaryClass::ToolResult
        } else {
            BoundaryClass::DerivedText
        },
        // The chain path admits the content in both modes; what an undeclared result costs is the
        // claim, which `verify` caps.
        admitted_boundary_modes: vec![BoundaryMode::Annotated, BoundaryMode::TelemetryOnly],
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
            detectors: Vec::new(),
            detectors_warn_only: Vec::new(),
            protected_bloom_min_hits: None,
            tabular_min_rows: None,
            allow_multimodal: None,
            declared_tool_results: Vec::new(),
            extends: Vec::new(),
            source_chain: Vec::new(),
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
        assert!(
            telemetry_only["messages"][1]["content"]["mutator_context"]["challenge_observation"]
                .is_null()
        );
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
