pub mod detectors;
pub mod egress;

use std::collections::HashSet;

use regex::Regex;
use serde_json::Value;

use crate::adapter::Adapter;
use crate::assembler::{PRIOR_TURN_KEY, PromptProvenance};
use crate::output::canonical_json;
use crate::policy::AirlockPolicy;
use crate::refusal::RefusalEnvelope;
use crate::types::{BindingStatus, BlockedReason, BoundaryMode, ClaimLevel, Finding};

/// Verification result for one prompt/request boundary check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub achieved_claim: ClaimLevel,
    pub binding_status: BindingStatus,
    pub raw_document_present: bool,
    pub filing_derived_text_present: bool,
    pub findings: Vec<Finding>,
    pub blocked_reasons: Vec<BlockedReason>,
}

/// Verify the prompt and request boundary against policy.
pub fn verify(
    policy: &AirlockPolicy,
    prompt_payload: &Value,
    prompt_provenance: &PromptProvenance,
    request_payload: &Value,
    boundary_mode: BoundaryMode,
    adapter: &dyn Adapter,
) -> Result<VerifyResult, RefusalEnvelope> {
    verify_with_adapter(
        policy,
        prompt_payload,
        prompt_provenance,
        request_payload,
        boundary_mode,
        Some(adapter),
    )
}

/// Verify policy constraints and bind the request to the assembled prompt using
/// the selected vendor adapter. A `None` adapter is reserved for scanner unit
/// tests that exercise policy scanning independently of transport binding.
fn verify_with_adapter(
    policy: &AirlockPolicy,
    prompt_payload: &Value,
    prompt_provenance: &PromptProvenance,
    request_payload: &Value,
    boundary_mode: BoundaryMode,
    adapter: Option<&dyn Adapter>,
) -> Result<VerifyResult, RefusalEnvelope> {
    let mut findings = Vec::new();
    let mut forbidden_paths = Vec::new();
    let mut detector_blocking_paths = Vec::new();
    let mut derived_text_paths = Vec::new();
    let mut binding_paths = Vec::new();

    scan_forbidden_keys(
        prompt_payload,
        &policy.forbidden_keys,
        &mut findings,
        &mut forbidden_paths,
    );
    scan_forbidden_keys(
        request_payload,
        &policy.forbidden_keys,
        &mut findings,
        &mut forbidden_paths,
    );

    let compiled_patterns = compile_patterns(policy);
    scan_forbidden_patterns(
        prompt_payload,
        &compiled_patterns,
        &mut findings,
        &mut forbidden_paths,
    );
    scan_forbidden_patterns(
        request_payload,
        &compiled_patterns,
        &mut findings,
        &mut forbidden_paths,
    );

    // Model output is found from the prompt's structure, never from provenance labels: a
    // provenance gap is advisory, so labels an attacker deleted must not lift the claim cap.
    let model_output_paths = model_output_paths(prompt_payload);
    let mut model_output_dirty = false;
    for (payload, root_path) in [(prompt_payload, "prompt"), (request_payload, "request")] {
        let detector_scan = detectors::scan_payload(policy, payload, root_path);
        if root_path == "prompt" {
            model_output_dirty = detector_scan.findings.iter().any(|finding| {
                finding
                    .key_path
                    .strip_prefix("prompt.")
                    .is_some_and(|path| path_is_under_any(path, &model_output_paths))
            });
        }
        findings.extend(detector_scan.findings);
        for path in detector_scan.blocking_paths {
            if !detector_blocking_paths.contains(&path) {
                detector_blocking_paths.push(path);
            }
        }
    }

    scan_derived_text_fields(
        prompt_payload,
        &policy.derived_text_paths,
        &mut findings,
        &mut derived_text_paths,
    );

    scan_provenance_gaps(prompt_payload, prompt_provenance, &mut findings);

    if let Some(adapter) = adapter {
        scan_request_binding(
            prompt_payload,
            request_payload,
            adapter,
            &mut findings,
            &mut binding_paths,
        )?;
    }

    let raw_document_present = !forbidden_paths.is_empty();
    let filing_derived_text_present = !derived_text_paths.is_empty();
    let binding_status = if binding_paths.is_empty() {
        BindingStatus::Bound
    } else {
        BindingStatus::Unbound
    };
    let model_output = model_output_screen(policy, &model_output_paths, model_output_dirty);
    let unscreened_model_output_paths = if model_output == ModelOutputScreen::Unscreened {
        model_output_paths
    } else {
        Vec::new()
    };
    let achieved_claim = derive_claim(
        raw_document_present,
        filing_derived_text_present,
        binding_status,
        boundary_mode,
        !detector_blocking_paths.is_empty(),
        model_output,
    );
    let blocked_reasons = derive_blocked_reasons(
        achieved_claim,
        boundary_mode,
        &forbidden_paths,
        &detector_blocking_paths,
        &derived_text_paths,
        &binding_paths,
        &unscreened_model_output_paths,
    );

    Ok(VerifyResult {
        achieved_claim,
        binding_status,
        raw_document_present,
        filing_derived_text_present,
        findings,
        blocked_reasons,
    })
}

#[cfg(test)]
fn verify_policy_only(
    policy: &AirlockPolicy,
    prompt_payload: &Value,
    prompt_provenance: &PromptProvenance,
    request_payload: &Value,
    boundary_mode: BoundaryMode,
) -> VerifyResult {
    verify_with_adapter(
        policy,
        prompt_payload,
        prompt_provenance,
        request_payload,
        boundary_mode,
        None,
    )
    .expect("policy-only scanning does not inspect adapter messages")
}

fn scan_request_binding(
    prompt_payload: &Value,
    request_payload: &Value,
    adapter: &dyn Adapter,
    findings: &mut Vec<Finding>,
    binding_paths: &mut Vec<String>,
) -> Result<(), RefusalEnvelope> {
    if let Some(request) = request_payload.as_object() {
        for key in request.keys() {
            if !adapter.transport_keys().contains(&key.as_str()) {
                let path = key.clone();
                binding_paths.push(path.clone());
                findings.push(Finding {
                    key_path: path,
                    sample_value: None,
                    artifact_class: "REQUEST_UNBOUND".to_string(),
                    matched_rule: "adapter.transport_keys".to_string(),
                    span_hash: None,
                });
            }
        }
    }

    let expected_messages = prompt_payload
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            RefusalEnvelope::bad_prompt(
                "prompt payload must contain a messages array",
                serde_json::json!({ "field": "messages" }),
            )
        })?;
    let unwrapped = adapter.unwrap(request_payload)?;
    let actual_messages = unwrapped
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            RefusalEnvelope::bad_request(
                "adapter did not expose a messages array",
                serde_json::json!({ "field": "messages" }),
            )
        })?;

    for index in 0..expected_messages.len().max(actual_messages.len()) {
        match (expected_messages.get(index), actual_messages.get(index)) {
            (Some(expected), Some(actual)) => {
                if canonical_json(expected) != canonical_json(actual) {
                    let path = format!("messages[{index}]");
                    binding_paths.push(path.clone());
                    findings.push(Finding {
                        key_path: path,
                        sample_value: None,
                        artifact_class: "REQUEST_UNBOUND".to_string(),
                        matched_rule: "prompt.messages_match_unwrapped_request".to_string(),
                        span_hash: None,
                    });
                }
            }
            (Some(_), None) => {
                let path = format!("messages[{index}]");
                binding_paths.push(path.clone());
                findings.push(Finding {
                    key_path: path,
                    sample_value: None,
                    artifact_class: "REQUEST_UNBOUND".to_string(),
                    matched_rule: "prompt.message_missing_from_request".to_string(),
                    span_hash: None,
                });
            }
            (None, Some(_)) => {
                let path = format!("messages[{index}]");
                binding_paths.push(path.clone());
                findings.push(Finding {
                    key_path: path,
                    sample_value: None,
                    artifact_class: "REQUEST_UNBOUND".to_string(),
                    matched_rule: "request.message_not_in_prompt".to_string(),
                    span_hash: None,
                });
            }
            (None, None) => continue,
        }
    }

    Ok(())
}

fn scan_forbidden_keys(
    value: &Value,
    forbidden_keys: &[String],
    findings: &mut Vec<Finding>,
    forbidden_paths: &mut Vec<String>,
) {
    walk_key_paths(value, String::new(), &mut |path, _| {
        for (index, forbidden_key) in forbidden_keys.iter().enumerate() {
            if path_matches_rule(&path, forbidden_key) {
                forbidden_paths.push(path.clone());
                findings.push(Finding {
                    key_path: path.clone(),
                    sample_value: None,
                    artifact_class: "forbidden_key".to_string(),
                    matched_rule: format!("forbidden_keys[{index}]"),
                    span_hash: None,
                });
            }
        }
    });
}

fn scan_forbidden_patterns(
    value: &Value,
    patterns: &[(usize, Regex, String)],
    findings: &mut Vec<Finding>,
    forbidden_paths: &mut Vec<String>,
) {
    walk_leaf_values(value, String::new(), &mut |path, leaf| {
        let Some(text) = leaf.as_str() else {
            return;
        };

        for (index, pattern, artifact_class) in patterns {
            if pattern.is_match(text) {
                forbidden_paths.push(path.clone());
                findings.push(Finding {
                    key_path: path.clone(),
                    sample_value: Some(truncate_sample(text)),
                    artifact_class: artifact_class.clone(),
                    matched_rule: format!("forbidden_patterns[{index}]"),
                    span_hash: None,
                });
            }
        }
    });
}

fn scan_derived_text_fields(
    prompt_payload: &Value,
    derived_text_rules: &[String],
    findings: &mut Vec<Finding>,
    derived_text_paths: &mut Vec<String>,
) {
    walk_leaf_values(prompt_payload, String::new(), &mut |path, leaf| {
        for (index, rule) in derived_text_rules.iter().enumerate() {
            if path_matches_rule(&path, rule) {
                derived_text_paths.push(path.clone());
                findings.push(Finding {
                    key_path: path.clone(),
                    sample_value: Some(truncate_sample(&render_value(leaf))),
                    artifact_class: "derived_text_field_hit".to_string(),
                    matched_rule: format!("derived_text_paths[{index}]"),
                    span_hash: None,
                });
            }
        }
    });
}

fn scan_provenance_gaps(
    prompt_payload: &Value,
    prompt_provenance: &PromptProvenance,
    findings: &mut Vec<Finding>,
) {
    let covered_paths: HashSet<&str> = prompt_provenance
        .records
        .iter()
        .map(|record| record.prompt_path.as_str())
        .collect();

    walk_leaf_values(prompt_payload, String::new(), &mut |path, _| {
        if !covered_paths.contains(path.as_str()) {
            findings.push(Finding {
                key_path: path.clone(),
                sample_value: None,
                artifact_class: "provenance_gap".to_string(),
                matched_rule: "prompt_provenance".to_string(),
                span_hash: None,
            });
        }
    });
}

/// Where the model output in a prompt stands against the policy's screen (al-210 ruling D2(b)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelOutputScreen {
    /// The prompt carries no `prior_turn`.
    Absent,
    /// The policy has a blocking detector pack and no detector found anything under `prior_turn`.
    ScreenedClean,
    /// Model output crossed without that screen: the policy has no blocking detector pack, or a
    /// detector reported a hit under `prior_turn`. A blocking hit also fails the boundary; a
    /// warn-only hit lands here and caps the claim.
    Unscreened,
}

/// Where the prompt's `messages[i].content` objects carry [`PRIOR_TURN_KEY`], as bare paths
/// (`messages[1].content.prior_turn`).
fn model_output_paths(prompt_payload: &Value) -> Vec<String> {
    prompt_payload
        .get("messages")
        .and_then(Value::as_array)
        .map(|messages| {
            messages
                .iter()
                .enumerate()
                .filter(|(_, message)| {
                    message
                        .get("content")
                        .and_then(Value::as_object)
                        .is_some_and(|content| content.contains_key(PRIOR_TURN_KEY))
                })
                .map(|(index, _)| format!("messages[{index}].content.{PRIOR_TURN_KEY}"))
                .collect()
        })
        .unwrap_or_default()
}

/// True when `path` is one of `roots` or lies beneath one (`root.x` or `root[0]`).
fn path_is_under_any(path: &str, roots: &[String]) -> bool {
    roots.iter().any(|root| {
        path == root
            || path
                .strip_prefix(root.as_str())
                .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('['))
    })
}

/// Model output is screened clean only if some enabled detector pack blocks (is not warn-only)
/// and none reported a hit beneath `prior_turn`. Forbidden keys and patterns apply to model output
/// like any other text and fail the boundary on their own; they are not what "screened" means here,
/// because a policy without detector packs would otherwise let free-form model text earn STRICT.
fn model_output_screen(
    policy: &AirlockPolicy,
    model_output_paths: &[String],
    detector_hit_under_it: bool,
) -> ModelOutputScreen {
    if model_output_paths.is_empty() {
        return ModelOutputScreen::Absent;
    }
    let blocking_pack_enabled = policy
        .detectors
        .iter()
        .any(|pack| !policy.detectors_warn_only.contains(pack));
    if blocking_pack_enabled && !detector_hit_under_it {
        ModelOutputScreen::ScreenedClean
    } else {
        ModelOutputScreen::Unscreened
    }
}

fn derive_claim(
    raw_document_present: bool,
    filing_derived_text_present: bool,
    binding_status: BindingStatus,
    boundary_mode: BoundaryMode,
    detector_blocked: bool,
    model_output: ModelOutputScreen,
) -> ClaimLevel {
    if raw_document_present || binding_status == BindingStatus::Unbound || detector_blocked {
        return ClaimLevel::BoundaryFailed;
    }

    if filing_derived_text_present || model_output == ModelOutputScreen::Unscreened {
        return ClaimLevel::RawDocumentAbsent;
    }

    match boundary_mode {
        BoundaryMode::Annotated => ClaimLevel::RawDocumentAbsent,
        BoundaryMode::TelemetryOnly => ClaimLevel::StrictTelemetryOnly,
    }
}

fn derive_blocked_reasons(
    achieved_claim: ClaimLevel,
    boundary_mode: BoundaryMode,
    forbidden_paths: &[String],
    detector_paths: &[String],
    derived_text_paths: &[String],
    binding_paths: &[String],
    unscreened_model_output_paths: &[String],
) -> Vec<BlockedReason> {
    let mut blocked_reasons = Vec::new();
    let mut sensitive_paths = forbidden_paths.to_vec();
    for path in detector_paths {
        if !sensitive_paths.contains(path) {
            sensitive_paths.push(path.clone());
        }
    }
    let boundary_paths = unique_paths(&sensitive_paths, binding_paths);
    let boundary_reason = if !detector_paths.is_empty() {
        "an enabled sensitive-content detector matched a boundary value"
    } else {
        match (forbidden_paths.is_empty(), binding_paths.is_empty()) {
            (false, false) => {
                "forbidden material was detected and the request does not match the assembled prompt"
            }
            (false, true) => "forbidden material detected in the request boundary",
            (true, false) => {
                "request does not match the assembled prompt or adapter transport keys"
            }
            (true, true) => "no boundary failure detected",
        }
    };

    if achieved_claim < ClaimLevel::RawDocumentAbsent {
        blocked_reasons.push(BlockedReason {
            claim_attempted: ClaimLevel::RawDocumentAbsent,
            reason: boundary_reason.to_string(),
            offending_paths: boundary_paths.clone(),
        });
    }

    if achieved_claim < ClaimLevel::StrictTelemetryOnly {
        let (reason, offending_paths) = if !boundary_paths.is_empty() {
            (boundary_reason.to_string(), boundary_paths)
        } else {
            strict_telemetry_block(
                boundary_mode,
                forbidden_paths,
                derived_text_paths,
                unscreened_model_output_paths,
            )
        };
        blocked_reasons.push(BlockedReason {
            claim_attempted: ClaimLevel::StrictTelemetryOnly,
            reason,
            offending_paths,
        });
    }

    blocked_reasons
}

fn unique_paths(first: &[String], second: &[String]) -> Vec<String> {
    let mut paths = Vec::with_capacity(first.len() + second.len());
    for path in first.iter().chain(second) {
        if !paths.contains(path) {
            paths.push(path.clone());
        }
    }
    paths
}

fn strict_telemetry_block(
    boundary_mode: BoundaryMode,
    forbidden_paths: &[String],
    derived_text_paths: &[String],
    unscreened_model_output_paths: &[String],
) -> (String, Vec<String>) {
    if !forbidden_paths.is_empty() {
        return (
            "forbidden material detected in the request boundary".to_string(),
            forbidden_paths.to_vec(),
        );
    }

    if !derived_text_paths.is_empty() {
        return (
            "filing-derived text crossed the boundary".to_string(),
            derived_text_paths.to_vec(),
        );
    }

    if !unscreened_model_output_paths.is_empty() {
        return (
            "model output from an earlier turn crossed without a clean screen: the policy needs a blocking detector pack and no detector may report a hit in it".to_string(),
            unscreened_model_output_paths.to_vec(),
        );
    }

    match boundary_mode {
        BoundaryMode::Annotated => (
            "boundary mode ANNOTATED caps the claim ceiling at RAW_DOCUMENT_ABSENT".to_string(),
            Vec::new(),
        ),
        BoundaryMode::TelemetryOnly => (
            "strict telemetry-only claim was not earned".to_string(),
            Vec::new(),
        ),
    }
}

fn compile_patterns(policy: &AirlockPolicy) -> Vec<(usize, Regex, String)> {
    policy
        .forbidden_patterns
        .iter()
        .enumerate()
        .filter_map(|(index, pattern)| {
            Regex::new(&pattern.pattern).ok().map(|regex| {
                (
                    index,
                    regex,
                    pattern
                        .artifact_class
                        .clone()
                        .unwrap_or_else(|| "forbidden_pattern".to_string()),
                )
            })
        })
        .collect()
}

fn walk_key_paths(value: &Value, current_path: String, visitor: &mut impl FnMut(String, &Value)) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let next_path = join_object_path(&current_path, key);
                visitor(next_path.clone(), child);
                walk_key_paths(child, next_path, visitor);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let next_path = join_array_path(&current_path, index);
                walk_key_paths(child, next_path, visitor);
            }
        }
        _ => {}
    }
}

fn walk_leaf_values(value: &Value, current_path: String, visitor: &mut impl FnMut(String, &Value)) {
    match value {
        Value::Object(map) => {
            if map.is_empty() && !current_path.is_empty() {
                visitor(current_path, value);
                return;
            }

            for (key, child) in map {
                let next_path = join_object_path(&current_path, key);
                walk_leaf_values(child, next_path, visitor);
            }
        }
        Value::Array(items) => {
            if items.is_empty() && !current_path.is_empty() {
                visitor(current_path, value);
                return;
            }

            for (index, child) in items.iter().enumerate() {
                let next_path = join_array_path(&current_path, index);
                walk_leaf_values(child, next_path, visitor);
            }
        }
        _ => visitor(current_path, value),
    }
}

fn join_object_path(base: &str, key: &str) -> String {
    if base.is_empty() {
        key.to_string()
    } else {
        format!("{base}.{key}")
    }
}

fn join_array_path(base: &str, index: usize) -> String {
    if base.is_empty() {
        format!("[{index}]")
    } else {
        format!("{base}[{index}]")
    }
}

fn path_matches_rule(path: &str, rule: &str) -> bool {
    let path_segments = normalized_segments(path);
    let rule_segments = normalized_segments(rule);

    if rule_segments.is_empty() || path_segments.len() < rule_segments.len() {
        return false;
    }

    path_segments[path_segments.len() - rule_segments.len()..] == rule_segments
}

fn normalized_segments(path: &str) -> Vec<String> {
    path.split('.')
        .filter_map(|segment| {
            let normalized = segment.split('[').next().unwrap_or_default().trim();
            if normalized.is_empty() {
                None
            } else {
                Some(normalized.to_string())
            }
        })
        .collect()
}

fn render_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "<unrenderable>".to_string()),
    }
}

fn truncate_sample(text: &str) -> String {
    text.chars().take(100).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::{BoundaryClass, PromptProvenance, ProvenanceRecord, TransformationKind};
    use crate::hash::blake3_hash;
    use crate::policy::{AllowRule, ForbiddenPattern};

    fn sample_policy() -> AirlockPolicy {
        AirlockPolicy {
            policy_id: "tournament_baseline".to_string(),
            version: "airlock.v0".to_string(),
            allowed_keys: vec![
                AllowRule {
                    key_path: "system_prompt".to_string(),
                    description: None,
                    boundary_class: Some(BoundaryClass::Telemetry),
                },
                AllowRule {
                    key_path: "input.family_id".to_string(),
                    description: None,
                    boundary_class: Some(BoundaryClass::Telemetry),
                },
                AllowRule {
                    key_path: "input.benchmark_summary.score".to_string(),
                    description: None,
                    boundary_class: Some(BoundaryClass::Telemetry),
                },
                AllowRule {
                    key_path: "input.mutator_context.challenge_observation".to_string(),
                    description: None,
                    boundary_class: Some(BoundaryClass::DerivedText),
                },
            ],
            forbidden_keys: vec![
                "html_path".to_string(),
                "section_html".to_string(),
                "pdf_path".to_string(),
            ],
            forbidden_patterns: vec![
                ForbiddenPattern {
                    pattern: "<[a-z][^>]*>".to_string(),
                    description: Some("Raw HTML".to_string()),
                    artifact_class: Some("raw_html".to_string()),
                },
                ForbiddenPattern {
                    pattern: "sec\\.gov/Archives".to_string(),
                    description: Some("SEC archive URLs".to_string()),
                    artifact_class: Some("sec_archive_url".to_string()),
                },
            ],
            derived_text_paths: vec![
                "input.mutator_context.challenge_observation".to_string(),
                "input.mutator_context.challenge_profile.layout_notes".to_string(),
            ],
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
            extends: Vec::new(),
            source_chain: Vec::new(),
        }
    }

    fn clean_prompt_payload() -> Value {
        serde_json::json!({
            "system_prompt": "Use structured telemetry only.",
            "input": {
                "family_id": "bdc_schedule_of_investments",
                "benchmark_summary": {
                    "score": 0.97
                },
                "challenge_profile": {
                    "page_count": 12
                }
            }
        })
    }

    fn request_payload() -> Value {
        serde_json::json!({
            "model": "gpt-5",
            "temperature": 0,
            "messages": [
                {
                    "role": "system",
                    "content": "Use structured telemetry only."
                }
            ]
        })
    }

    fn build_provenance(
        prompt_payload: &Value,
        boundary_mode: BoundaryMode,
        missing_paths: &[&str],
    ) -> PromptProvenance {
        let mut paths = Vec::new();
        walk_leaf_values(prompt_payload, String::new(), &mut |path, value| {
            paths.push((path, value.clone()));
        });

        let missing: HashSet<&str> = missing_paths.iter().copied().collect();
        let records: Vec<ProvenanceRecord> = paths
            .into_iter()
            .filter(|(path, _)| !missing.contains(path.as_str()))
            .map(|(path, value)| {
                let boundary_class =
                    if path.contains("challenge_observation") || path.contains("layout_notes") {
                        BoundaryClass::DerivedText
                    } else {
                        BoundaryClass::Telemetry
                    };

                ProvenanceRecord {
                    prompt_path: path.clone(),
                    emitted_value_hash: blake3_hash(
                        serde_json::to_string(&value).unwrap().as_bytes(),
                    ),
                    source_artifact_hash: blake3_hash(b"strategy_space.json"),
                    source_path: path.clone(),
                    transformation_kind: match boundary_class {
                        BoundaryClass::DerivedText => TransformationKind::DerivedAnnotation,
                        _ => TransformationKind::Copy,
                    },
                    policy_rule_id: format!("allow.{path}"),
                    boundary_class,
                    admitted_boundary_modes: match boundary_class {
                        BoundaryClass::DerivedText => vec![BoundaryMode::Annotated],
                        _ => vec![BoundaryMode::Annotated, BoundaryMode::TelemetryOnly],
                    },
                }
            })
            .collect();

        PromptProvenance::new(
            "blake3:policyhash".to_string(),
            blake3_hash(serde_json::to_string(prompt_payload).unwrap().as_bytes()),
            boundary_mode,
            records,
        )
    }

    #[test]
    fn clean_payload_in_telemetry_only_earns_strict_telemetry_only() {
        let prompt_payload = clean_prompt_payload();
        let result = verify_policy_only(
            &sample_policy(),
            &prompt_payload,
            &build_provenance(&prompt_payload, BoundaryMode::TelemetryOnly, &[]),
            &request_payload(),
            BoundaryMode::TelemetryOnly,
        );

        assert_eq!(result.achieved_claim, ClaimLevel::StrictTelemetryOnly);
        assert!(!result.raw_document_present);
        assert!(!result.filing_derived_text_present);
        assert!(result.blocked_reasons.is_empty());
    }

    #[test]
    fn enabled_pii_detector_fails_the_claim_unless_marked_warn_only() {
        let prompt_payload = clean_prompt_payload();
        let provenance = build_provenance(&prompt_payload, BoundaryMode::TelemetryOnly, &[]);
        let mut request = request_payload();
        request["messages"][0]["content"] = serde_json::json!("SSN 123-45-6789");

        let mut enforcing_policy = sample_policy();
        enforcing_policy
            .detectors
            .push(crate::policy::DetectorPack::Pii);
        let enforced = verify_policy_only(
            &enforcing_policy,
            &prompt_payload,
            &provenance,
            &request,
            BoundaryMode::TelemetryOnly,
        );
        assert_eq!(enforced.achieved_claim, ClaimLevel::BoundaryFailed);
        let detector_finding = enforced
            .findings
            .iter()
            .find(|finding| finding.artifact_class == "DETECTED_SENSITIVE")
            .expect("PII should create a detector finding");
        assert_eq!(detector_finding.key_path, "request.messages[0].content");
        assert_eq!(detector_finding.matched_rule, "PII_US_SSN");
        assert!(detector_finding.sample_value.is_none());
        assert!(
            detector_finding
                .span_hash
                .as_deref()
                .unwrap()
                .starts_with("blake3:")
        );

        let mut warn_only_policy = enforcing_policy;
        warn_only_policy
            .detectors_warn_only
            .push(crate::policy::DetectorPack::Pii);
        let warn_only = verify_policy_only(
            &warn_only_policy,
            &prompt_payload,
            &provenance,
            &request,
            BoundaryMode::TelemetryOnly,
        );
        assert_eq!(warn_only.achieved_claim, ClaimLevel::StrictTelemetryOnly);
        assert!(warn_only.blocked_reasons.is_empty());
        assert!(
            warn_only
                .findings
                .iter()
                .any(|finding| finding.artifact_class == "DETECTED_SENSITIVE")
        );
    }

    #[test]
    fn clean_payload_in_annotated_mode_is_capped_at_raw_document_absent() {
        let prompt_payload = clean_prompt_payload();
        let result = verify_policy_only(
            &sample_policy(),
            &prompt_payload,
            &build_provenance(&prompt_payload, BoundaryMode::Annotated, &[]),
            &request_payload(),
            BoundaryMode::Annotated,
        );

        assert_eq!(result.achieved_claim, ClaimLevel::RawDocumentAbsent);
        assert_eq!(result.blocked_reasons.len(), 1);
        assert_eq!(
            result.blocked_reasons[0].claim_attempted,
            ClaimLevel::StrictTelemetryOnly
        );
        assert!(
            result.blocked_reasons[0]
                .reason
                .contains("boundary mode ANNOTATED")
        );
    }

    #[test]
    fn derived_text_in_annotated_mode_is_detected_and_caps_claim() {
        let prompt_payload = serde_json::json!({
            "system_prompt": "Use annotations when necessary.",
            "input": {
                "family_id": "bdc_schedule_of_investments",
                "mutator_context": {
                    "challenge_observation": "Dense two-column layout with footnotes."
                }
            }
        });

        let result = verify_policy_only(
            &sample_policy(),
            &prompt_payload,
            &build_provenance(&prompt_payload, BoundaryMode::Annotated, &[]),
            &request_payload(),
            BoundaryMode::Annotated,
        );

        assert_eq!(result.achieved_claim, ClaimLevel::RawDocumentAbsent);
        assert!(result.filing_derived_text_present);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.artifact_class == "derived_text_field_hit")
        );
        assert_eq!(result.blocked_reasons.len(), 1);
        assert!(
            result.blocked_reasons[0]
                .reason
                .contains("filing-derived text")
        );
    }

    #[test]
    fn forbidden_key_causes_boundary_failed() {
        let prompt_payload = clean_prompt_payload();
        let request_payload = serde_json::json!({
            "model": "gpt-5",
            "html_path": "/tmp/filing.html"
        });

        let result = verify_policy_only(
            &sample_policy(),
            &prompt_payload,
            &build_provenance(&prompt_payload, BoundaryMode::TelemetryOnly, &[]),
            &request_payload,
            BoundaryMode::TelemetryOnly,
        );

        assert_eq!(result.achieved_claim, ClaimLevel::BoundaryFailed);
        assert!(result.raw_document_present);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.key_path == "html_path"
                    && finding.artifact_class == "forbidden_key")
        );
    }

    #[test]
    fn forbidden_pattern_causes_boundary_failed_and_truncates_sample() {
        let prompt_payload = clean_prompt_payload();
        let request_payload = serde_json::json!({
            "model": "gpt-5",
            "messages": [
                {
                    "role": "user",
                    "content": format!("<table>{}</table>", "x".repeat(200))
                }
            ]
        });

        let result = verify_policy_only(
            &sample_policy(),
            &prompt_payload,
            &build_provenance(&prompt_payload, BoundaryMode::TelemetryOnly, &[]),
            &request_payload,
            BoundaryMode::TelemetryOnly,
        );

        let finding = result
            .findings
            .iter()
            .find(|finding| finding.artifact_class == "raw_html")
            .unwrap();

        assert_eq!(result.achieved_claim, ClaimLevel::BoundaryFailed);
        assert!(finding.sample_value.as_ref().unwrap().len() <= 100);
    }

    #[test]
    fn provenance_gap_is_recorded_without_degrading_claim() {
        let prompt_payload = clean_prompt_payload();
        let result = verify_policy_only(
            &sample_policy(),
            &prompt_payload,
            &build_provenance(
                &prompt_payload,
                BoundaryMode::TelemetryOnly,
                &["input.benchmark_summary.score"],
            ),
            &request_payload(),
            BoundaryMode::TelemetryOnly,
        );

        assert_eq!(result.achieved_claim, ClaimLevel::StrictTelemetryOnly);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.artifact_class == "provenance_gap"
                    && finding.key_path == "input.benchmark_summary.score")
        );
    }
}
