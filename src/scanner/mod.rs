use std::collections::HashSet;

use regex::Regex;
use serde_json::Value;

use crate::assembler::PromptProvenance;
use crate::policy::AirlockPolicy;
use crate::types::{BlockedReason, BoundaryMode, ClaimLevel, Finding};

/// Verification result for one prompt/request boundary check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub achieved_claim: ClaimLevel,
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
) -> VerifyResult {
    let mut findings = Vec::new();
    let mut forbidden_paths = Vec::new();
    let mut derived_text_paths = Vec::new();

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

    scan_derived_text_fields(
        prompt_payload,
        &policy.derived_text_paths,
        &mut findings,
        &mut derived_text_paths,
    );

    scan_provenance_gaps(prompt_payload, prompt_provenance, &mut findings);

    let raw_document_present = !forbidden_paths.is_empty();
    let filing_derived_text_present = !derived_text_paths.is_empty();
    let achieved_claim = derive_claim(
        raw_document_present,
        filing_derived_text_present,
        boundary_mode,
    );
    let blocked_reasons = derive_blocked_reasons(
        achieved_claim,
        boundary_mode,
        &forbidden_paths,
        &derived_text_paths,
    );

    VerifyResult {
        achieved_claim,
        raw_document_present,
        filing_derived_text_present,
        findings,
        blocked_reasons,
    }
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
            });
        }
    });
}

fn derive_claim(
    raw_document_present: bool,
    filing_derived_text_present: bool,
    boundary_mode: BoundaryMode,
) -> ClaimLevel {
    if raw_document_present {
        return ClaimLevel::BoundaryFailed;
    }

    if filing_derived_text_present {
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
    derived_text_paths: &[String],
) -> Vec<BlockedReason> {
    let mut blocked_reasons = Vec::new();

    if achieved_claim < ClaimLevel::RawDocumentAbsent {
        blocked_reasons.push(BlockedReason {
            claim_attempted: ClaimLevel::RawDocumentAbsent,
            reason: "forbidden material detected in the request boundary".to_string(),
            offending_paths: forbidden_paths.to_vec(),
        });
    }

    if achieved_claim < ClaimLevel::StrictTelemetryOnly {
        let (reason, offending_paths) =
            strict_telemetry_block(boundary_mode, forbidden_paths, derived_text_paths);
        blocked_reasons.push(BlockedReason {
            claim_attempted: ClaimLevel::StrictTelemetryOnly,
            reason,
            offending_paths,
        });
    }

    blocked_reasons
}

fn strict_telemetry_block(
    boundary_mode: BoundaryMode,
    forbidden_paths: &[String],
    derived_text_paths: &[String],
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
        let result = verify(
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
    fn clean_payload_in_annotated_mode_is_capped_at_raw_document_absent() {
        let prompt_payload = clean_prompt_payload();
        let result = verify(
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
        assert!(result.blocked_reasons[0]
            .reason
            .contains("boundary mode ANNOTATED"));
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

        let result = verify(
            &sample_policy(),
            &prompt_payload,
            &build_provenance(&prompt_payload, BoundaryMode::Annotated, &[]),
            &request_payload(),
            BoundaryMode::Annotated,
        );

        assert_eq!(result.achieved_claim, ClaimLevel::RawDocumentAbsent);
        assert!(result.filing_derived_text_present);
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.artifact_class == "derived_text_field_hit"));
        assert_eq!(result.blocked_reasons.len(), 1);
        assert!(result.blocked_reasons[0]
            .reason
            .contains("filing-derived text"));
    }

    #[test]
    fn forbidden_key_causes_boundary_failed() {
        let prompt_payload = clean_prompt_payload();
        let request_payload = serde_json::json!({
            "model": "gpt-5",
            "html_path": "/tmp/filing.html"
        });

        let result = verify(
            &sample_policy(),
            &prompt_payload,
            &build_provenance(&prompt_payload, BoundaryMode::TelemetryOnly, &[]),
            &request_payload,
            BoundaryMode::TelemetryOnly,
        );

        assert_eq!(result.achieved_claim, ClaimLevel::BoundaryFailed);
        assert!(result.raw_document_present);
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.key_path == "html_path"
                && finding.artifact_class == "forbidden_key"));
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

        let result = verify(
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
        let result = verify(
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
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.artifact_class == "provenance_gap"
                && finding.key_path == "input.benchmark_summary.score"));
    }
}
