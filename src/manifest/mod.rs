use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::assembler::{BoundaryClass, PromptProvenance};
use crate::hash::blake3_hash;
use crate::output::{canonical_json, canonical_json_bytes};
use crate::types::{BlockedReason, BoundaryMode, ClaimLevel, Finding, UpstreamArtifact};

pub const AIRLOCK_MANIFEST_VERSION: &str = "airlock.v0";

/// Aggregate provenance counts used by explain output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceSummary {
    pub total_fragments: usize,
    pub by_boundary_class: BTreeMap<String, usize>,
}

impl ProvenanceSummary {
    pub fn from_prompt_provenance(prompt_provenance: &PromptProvenance) -> Self {
        let mut by_boundary_class = BTreeMap::new();

        for record in &prompt_provenance.records {
            let key = boundary_class_name(record.boundary_class).to_string();
            *by_boundary_class.entry(key).or_insert(0) += 1;
        }

        Self {
            total_fragments: prompt_provenance.records.len(),
            by_boundary_class,
        }
    }
}

/// Primary proof artifact for an Airlock verification run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirlockManifest {
    pub manifest_version: String,
    pub boundary_mode: BoundaryMode,
    pub policy_id: String,
    pub policy_hash: String,
    pub claim_levels_evaluated: Vec<ClaimLevel>,
    pub achieved_claim: ClaimLevel,
    pub upstream_artifact_inventory: Vec<UpstreamArtifact>,
    pub system_prompt_hash: String,
    pub prompt_payload_hash: String,
    pub prompt_provenance_hash: String,
    pub prompt_provenance_ref: String,
    pub request_payload_hash: String,
    pub replay_ref: String,
    pub model_id: String,
    pub adapter: String,
    pub raw_document_present: bool,
    pub filing_derived_text_present: bool,
    pub findings: Vec<Finding>,
    pub blocked_reasons: Vec<BlockedReason>,
    pub provenance_summary: ProvenanceSummary,
    pub timestamp: String,
}

impl AirlockManifest {
    pub fn to_canonical_json(&self) -> String {
        canonical_json(&self.as_json_value())
    }

    pub fn hash(&self) -> String {
        blake3_hash(&canonical_json_bytes(&self.as_json_value()))
    }

    pub fn write_to(&self, path: &Path) -> Result<(), std::io::Error> {
        let json = self.to_canonical_json();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("airlock_manifest.json");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_path = parent.join(format!(".{filename}.{}.tmp", nonce));

        std::fs::write(&temp_path, json.as_bytes())?;
        std::fs::rename(&temp_path, path)?;
        Ok(())
    }

    fn as_json_value(&self) -> Value {
        serde_json::to_value(self).expect("airlock manifest should serialize to JSON")
    }
}

#[derive(Debug, Default)]
pub struct ManifestBuilder {
    boundary_mode: Option<BoundaryMode>,
    policy_id: Option<String>,
    policy_hash: Option<String>,
    claim_levels_evaluated: Option<Vec<ClaimLevel>>,
    achieved_claim: Option<ClaimLevel>,
    upstream_artifact_inventory: Option<Vec<UpstreamArtifact>>,
    system_prompt_hash: Option<String>,
    prompt_payload_hash: Option<String>,
    prompt_provenance: Option<PromptProvenanceSnapshot>,
    request_payload_hash: Option<String>,
    replay_ref: Option<String>,
    model_id: Option<String>,
    adapter: Option<String>,
    raw_document_present: Option<bool>,
    filing_derived_text_present: Option<bool>,
    findings: Option<Vec<Finding>>,
    blocked_reasons: Option<Vec<BlockedReason>>,
    timestamp: Option<String>,
}

impl ManifestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn boundary_mode(mut self, boundary_mode: BoundaryMode) -> Self {
        self.boundary_mode = Some(boundary_mode);
        self
    }

    pub fn policy_id(mut self, policy_id: impl Into<String>) -> Self {
        self.policy_id = Some(policy_id.into());
        self
    }

    pub fn policy_hash(mut self, policy_hash: impl Into<String>) -> Self {
        self.policy_hash = Some(policy_hash.into());
        self
    }

    pub fn claim_levels_evaluated(mut self, claim_levels_evaluated: Vec<ClaimLevel>) -> Self {
        self.claim_levels_evaluated = Some(claim_levels_evaluated);
        self
    }

    pub fn achieved_claim(mut self, achieved_claim: ClaimLevel) -> Self {
        self.achieved_claim = Some(achieved_claim);
        self
    }

    pub fn upstream_artifact_inventory(
        mut self,
        upstream_artifact_inventory: Vec<UpstreamArtifact>,
    ) -> Self {
        self.upstream_artifact_inventory = Some(upstream_artifact_inventory);
        self
    }

    pub fn system_prompt_hash(mut self, system_prompt_hash: impl Into<String>) -> Self {
        self.system_prompt_hash = Some(system_prompt_hash.into());
        self
    }

    pub fn prompt_payload_hash(mut self, prompt_payload_hash: impl Into<String>) -> Self {
        self.prompt_payload_hash = Some(prompt_payload_hash.into());
        self
    }

    pub fn prompt_provenance(
        mut self,
        prompt_provenance_ref: impl Into<String>,
        prompt_provenance: &PromptProvenance,
    ) -> Self {
        self.prompt_provenance = Some(PromptProvenanceSnapshot::new(
            prompt_provenance_ref.into(),
            prompt_provenance,
        ));
        self
    }

    pub fn request_payload_hash(mut self, request_payload_hash: impl Into<String>) -> Self {
        self.request_payload_hash = Some(request_payload_hash.into());
        self
    }

    pub fn replay_ref(mut self, replay_ref: impl Into<String>) -> Self {
        self.replay_ref = Some(replay_ref.into());
        self
    }

    pub fn model_id(mut self, model_id: impl Into<String>) -> Self {
        self.model_id = Some(model_id.into());
        self
    }

    pub fn adapter(mut self, adapter: impl Into<String>) -> Self {
        self.adapter = Some(adapter.into());
        self
    }

    pub fn raw_document_present(mut self, raw_document_present: bool) -> Self {
        self.raw_document_present = Some(raw_document_present);
        self
    }

    pub fn filing_derived_text_present(mut self, filing_derived_text_present: bool) -> Self {
        self.filing_derived_text_present = Some(filing_derived_text_present);
        self
    }

    pub fn findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = Some(findings);
        self
    }

    pub fn blocked_reasons(mut self, blocked_reasons: Vec<BlockedReason>) -> Self {
        self.blocked_reasons = Some(blocked_reasons);
        self
    }

    pub fn timestamp(mut self, timestamp: impl Into<String>) -> Self {
        self.timestamp = Some(timestamp.into());
        self
    }

    pub fn timestamp_now(mut self) -> Self {
        self.timestamp = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
        self
    }

    pub fn build(self) -> Result<AirlockManifest, ManifestBuildError> {
        let boundary_mode = require(self.boundary_mode, "boundary_mode")?;
        let policy_id = require_non_empty(self.policy_id, "policy_id")?;
        let policy_hash = require_non_empty(self.policy_hash, "policy_hash")?;
        validate_blake3_hash("policy_hash", &policy_hash)?;

        let claim_levels_evaluated =
            require(self.claim_levels_evaluated, "claim_levels_evaluated")?;
        if claim_levels_evaluated.is_empty() {
            return Err(ManifestBuildError::invalid(
                "claim_levels_evaluated",
                "must contain at least one claim level",
            ));
        }

        let achieved_claim = require(self.achieved_claim, "achieved_claim")?;
        let upstream_artifact_inventory = require(
            self.upstream_artifact_inventory,
            "upstream_artifact_inventory",
        )?;
        for artifact in &upstream_artifact_inventory {
            validate_non_empty_field("upstream_artifact_inventory.path", &artifact.path)?;
            validate_blake3_hash(
                "upstream_artifact_inventory.content_hash",
                &artifact.content_hash,
            )?;
            validate_non_empty_field(
                "upstream_artifact_inventory.artifact_class",
                &artifact.artifact_class,
            )?;
        }

        let system_prompt_hash = require_non_empty(self.system_prompt_hash, "system_prompt_hash")?;
        validate_blake3_hash("system_prompt_hash", &system_prompt_hash)?;

        let prompt_payload_hash =
            require_non_empty(self.prompt_payload_hash, "prompt_payload_hash")?;
        validate_blake3_hash("prompt_payload_hash", &prompt_payload_hash)?;

        let prompt_provenance = require(self.prompt_provenance, "prompt_provenance")?;
        validate_non_empty_field("prompt_provenance_ref", &prompt_provenance.reference)?;
        validate_blake3_hash("prompt_provenance_hash", &prompt_provenance.hash)?;
        if prompt_provenance.policy_hash != policy_hash {
            return Err(ManifestBuildError::invalid(
                "prompt_provenance.policy_hash",
                "does not match manifest policy_hash",
            ));
        }
        if prompt_provenance.prompt_payload_hash != prompt_payload_hash {
            return Err(ManifestBuildError::invalid(
                "prompt_provenance.prompt_payload_hash",
                "does not match manifest prompt_payload_hash",
            ));
        }
        if prompt_provenance.boundary_mode != boundary_mode {
            return Err(ManifestBuildError::invalid(
                "prompt_provenance.boundary_mode",
                "does not match manifest boundary_mode",
            ));
        }

        let request_payload_hash =
            require_non_empty(self.request_payload_hash, "request_payload_hash")?;
        validate_blake3_hash("request_payload_hash", &request_payload_hash)?;

        let replay_ref = require_non_empty(self.replay_ref, "replay_ref")?;
        let model_id = require_non_empty(self.model_id, "model_id")?;
        let adapter = require_non_empty(self.adapter, "adapter")?;
        let raw_document_present = require(self.raw_document_present, "raw_document_present")?;
        let filing_derived_text_present = require(
            self.filing_derived_text_present,
            "filing_derived_text_present",
        )?;
        let findings = require(self.findings, "findings")?;
        let blocked_reasons = require(self.blocked_reasons, "blocked_reasons")?;
        let timestamp = require_non_empty(self.timestamp, "timestamp")?;
        validate_rfc3339_timestamp(&timestamp)?;

        Ok(AirlockManifest {
            manifest_version: AIRLOCK_MANIFEST_VERSION.to_string(),
            boundary_mode,
            policy_id,
            policy_hash,
            claim_levels_evaluated,
            achieved_claim,
            upstream_artifact_inventory,
            system_prompt_hash,
            prompt_payload_hash,
            prompt_provenance_hash: prompt_provenance.hash,
            prompt_provenance_ref: prompt_provenance.reference,
            request_payload_hash,
            replay_ref,
            model_id,
            adapter,
            raw_document_present,
            filing_derived_text_present,
            findings,
            blocked_reasons,
            provenance_summary: prompt_provenance.summary,
            timestamp,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestBuildError {
    message: String,
}

impl ManifestBuildError {
    fn missing(field: &'static str) -> Self {
        Self {
            message: format!("missing required field: {field}"),
        }
    }

    fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self {
            message: format!("invalid field {field}: {}", reason.into()),
        }
    }
}

impl fmt::Display for ManifestBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ManifestBuildError {}

#[derive(Debug)]
struct PromptProvenanceSnapshot {
    hash: String,
    reference: String,
    summary: ProvenanceSummary,
    policy_hash: String,
    prompt_payload_hash: String,
    boundary_mode: BoundaryMode,
}

impl PromptProvenanceSnapshot {
    fn new(reference: String, prompt_provenance: &PromptProvenance) -> Self {
        Self {
            hash: prompt_provenance.hash(),
            reference,
            summary: ProvenanceSummary::from_prompt_provenance(prompt_provenance),
            policy_hash: prompt_provenance.policy_hash.clone(),
            prompt_payload_hash: prompt_provenance.prompt_payload_hash.clone(),
            boundary_mode: prompt_provenance.boundary_mode,
        }
    }
}

fn require<T>(value: Option<T>, field: &'static str) -> Result<T, ManifestBuildError> {
    value.ok_or_else(|| ManifestBuildError::missing(field))
}

fn require_non_empty(
    value: Option<String>,
    field: &'static str,
) -> Result<String, ManifestBuildError> {
    let value = require(value, field)?;
    validate_non_empty_field(field, &value)?;
    Ok(value)
}

fn validate_non_empty_field(field: &'static str, value: &str) -> Result<(), ManifestBuildError> {
    if value.trim().is_empty() {
        return Err(ManifestBuildError::invalid(field, "must not be empty"));
    }
    Ok(())
}

fn validate_blake3_hash(field: &'static str, value: &str) -> Result<(), ManifestBuildError> {
    let Some(hex) = value.strip_prefix("blake3:") else {
        return Err(ManifestBuildError::invalid(
            field,
            "must use blake3:{64 hex} format",
        ));
    };

    if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ManifestBuildError::invalid(
            field,
            "must use blake3:{64 hex} format",
        ));
    }

    Ok(())
}

fn validate_rfc3339_timestamp(timestamp: &str) -> Result<(), ManifestBuildError> {
    DateTime::parse_from_rfc3339(timestamp)
        .map(|_| ())
        .map_err(|_| ManifestBuildError::invalid("timestamp", "must be a valid RFC3339 timestamp"))
}

fn boundary_class_name(boundary_class: BoundaryClass) -> &'static str {
    match boundary_class {
        BoundaryClass::Telemetry => "TELEMETRY",
        BoundaryClass::DerivedText => "DERIVED_TEXT",
        BoundaryClass::Forbidden => "FORBIDDEN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::{ProvenanceRecord, TransformationKind};
    use crate::hash::blake3_hash;

    fn sample_hash(label: &str) -> String {
        blake3_hash(label.as_bytes())
    }

    fn sample_provenance(
        policy_hash: &str,
        prompt_payload_hash: &str,
        boundary_mode: BoundaryMode,
    ) -> PromptProvenance {
        PromptProvenance::new(
            policy_hash.to_string(),
            prompt_payload_hash.to_string(),
            boundary_mode,
            vec![
                ProvenanceRecord {
                    prompt_path: "messages[1].content.challenge_profile.page_count".to_string(),
                    emitted_value_hash: sample_hash("page_count"),
                    source_artifact_hash: sample_hash("strategy_space"),
                    source_path: "challenge_profile.page_count".to_string(),
                    transformation_kind: TransformationKind::Copy,
                    policy_rule_id: "allow.challenge_profile.page_count".to_string(),
                    boundary_class: BoundaryClass::Telemetry,
                    admitted_boundary_modes: vec![
                        BoundaryMode::Annotated,
                        BoundaryMode::TelemetryOnly,
                    ],
                },
                ProvenanceRecord {
                    prompt_path: "messages[1].content.challenge_observation".to_string(),
                    emitted_value_hash: sample_hash("challenge_observation"),
                    source_artifact_hash: sample_hash("strategy_space"),
                    source_path: "mutator_context.challenge_observation".to_string(),
                    transformation_kind: TransformationKind::DerivedAnnotation,
                    policy_rule_id: "derived.challenge_observation".to_string(),
                    boundary_class: BoundaryClass::DerivedText,
                    admitted_boundary_modes: vec![BoundaryMode::Annotated],
                },
                ProvenanceRecord {
                    prompt_path: "messages[1].content.section_html".to_string(),
                    emitted_value_hash: sample_hash("section_html"),
                    source_artifact_hash: sample_hash("forbidden_input"),
                    source_path: "section_html".to_string(),
                    transformation_kind: TransformationKind::Copy,
                    policy_rule_id: "deny.section_html".to_string(),
                    boundary_class: BoundaryClass::Forbidden,
                    admitted_boundary_modes: vec![BoundaryMode::Annotated],
                },
            ],
        )
    }

    fn sample_builder() -> ManifestBuilder {
        let policy_hash = sample_hash("policy");
        let prompt_payload_hash = sample_hash("prompt-payload");
        let prompt_provenance =
            sample_provenance(&policy_hash, &prompt_payload_hash, BoundaryMode::Annotated);

        ManifestBuilder::new()
            .boundary_mode(BoundaryMode::Annotated)
            .policy_id("tournament_baseline")
            .policy_hash(policy_hash)
            .claim_levels_evaluated(vec![
                ClaimLevel::BoundaryFailed,
                ClaimLevel::RawDocumentAbsent,
                ClaimLevel::StrictTelemetryOnly,
            ])
            .achieved_claim(ClaimLevel::RawDocumentAbsent)
            .upstream_artifact_inventory(vec![UpstreamArtifact {
                path: "strategy_space.json".to_string(),
                content_hash: sample_hash("strategy_space"),
                artifact_class: "strategy_space".to_string(),
            }])
            .system_prompt_hash(sample_hash("system-prompt"))
            .prompt_payload_hash(prompt_payload_hash)
            .prompt_provenance("prompt_provenance.json", &prompt_provenance)
            .request_payload_hash(sample_hash("request-payload"))
            .replay_ref("request.json")
            .model_id("gpt-5")
            .adapter("openai_chat_completions")
            .raw_document_present(false)
            .filing_derived_text_present(true)
            .findings(vec![Finding {
                key_path: "mutator_context.challenge_observation".to_string(),
                sample_value: Some("Dense footnote section".to_string()),
                artifact_class: "derived_text".to_string(),
                matched_rule: "derived.challenge_observation".to_string(),
            }])
            .blocked_reasons(vec![BlockedReason {
                claim_attempted: ClaimLevel::StrictTelemetryOnly,
                reason: "derived text present".to_string(),
                offending_paths: vec!["mutator_context.challenge_observation".to_string()],
            }])
            .timestamp("2026-03-26T14:28:00Z")
    }

    fn sample_manifest() -> AirlockManifest {
        sample_builder()
            .build()
            .expect("sample manifest should build")
    }

    #[test]
    fn provenance_summary_counts_boundary_classes() {
        let manifest = sample_manifest();

        assert_eq!(manifest.provenance_summary.total_fragments, 3);
        assert_eq!(
            manifest
                .provenance_summary
                .by_boundary_class
                .get("TELEMETRY"),
            Some(&1)
        );
        assert_eq!(
            manifest
                .provenance_summary
                .by_boundary_class
                .get("DERIVED_TEXT"),
            Some(&1)
        );
        assert_eq!(
            manifest
                .provenance_summary
                .by_boundary_class
                .get("FORBIDDEN"),
            Some(&1)
        );
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let manifest = sample_manifest();

        assert_eq!(manifest.to_canonical_json(), manifest.to_canonical_json());
        assert!(manifest
            .to_canonical_json()
            .contains("\"manifest_version\":\"airlock.v0\""));
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let manifest = sample_manifest();

        assert_eq!(manifest.hash(), manifest.hash());
        assert!(manifest.hash().starts_with("blake3:"));
    }

    #[test]
    fn write_to_persists_canonical_json() {
        let manifest = sample_manifest();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("airlock_manifest.json");

        manifest.write_to(&path).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written, manifest.to_canonical_json());
    }

    #[test]
    fn builder_rejects_missing_required_fields() {
        let err = sample_builder()
            .timestamp("")
            .build()
            .expect_err("empty timestamp should fail");

        assert_eq!(
            err.to_string(),
            "invalid field timestamp: must not be empty"
        );
    }

    #[test]
    fn builder_rejects_invalid_hashes_and_timestamps() {
        let bad_hash_err = sample_builder()
            .policy_hash("sha256:not-a-blake3-hash")
            .build()
            .expect_err("bad policy hash should fail");
        assert_eq!(
            bad_hash_err.to_string(),
            "invalid field policy_hash: must use blake3:{64 hex} format"
        );

        let bad_timestamp_err = sample_builder()
            .timestamp("not-a-timestamp")
            .build()
            .expect_err("bad timestamp should fail");
        assert_eq!(
            bad_timestamp_err.to_string(),
            "invalid field timestamp: must be a valid RFC3339 timestamp"
        );
    }

    #[test]
    fn builder_rejects_prompt_provenance_mismatches() {
        let policy_hash = sample_hash("policy");
        let prompt_payload_hash = sample_hash("prompt-payload");
        let mismatched = sample_provenance(
            &policy_hash,
            &sample_hash("different-prompt-payload"),
            BoundaryMode::Annotated,
        );

        let err = ManifestBuilder::new()
            .boundary_mode(BoundaryMode::Annotated)
            .policy_id("tournament_baseline")
            .policy_hash(policy_hash)
            .claim_levels_evaluated(vec![
                ClaimLevel::BoundaryFailed,
                ClaimLevel::RawDocumentAbsent,
                ClaimLevel::StrictTelemetryOnly,
            ])
            .achieved_claim(ClaimLevel::RawDocumentAbsent)
            .upstream_artifact_inventory(vec![UpstreamArtifact {
                path: "strategy_space.json".to_string(),
                content_hash: sample_hash("strategy_space"),
                artifact_class: "strategy_space".to_string(),
            }])
            .system_prompt_hash(sample_hash("system-prompt"))
            .prompt_payload_hash(prompt_payload_hash)
            .prompt_provenance("prompt_provenance.json", &mismatched)
            .request_payload_hash(sample_hash("request-payload"))
            .replay_ref("request.json")
            .model_id("gpt-5")
            .adapter("openai_chat_completions")
            .raw_document_present(false)
            .filing_derived_text_present(true)
            .findings(vec![])
            .blocked_reasons(vec![])
            .timestamp("2026-03-26T14:28:00Z")
            .build()
            .expect_err("mismatched prompt payload hash should fail");

        assert_eq!(
            err.to_string(),
            "invalid field prompt_provenance.prompt_payload_hash: does not match manifest prompt_payload_hash"
        );
    }

    #[test]
    fn timestamp_now_sets_rfc3339_value() {
        let manifest = sample_builder()
            .timestamp_now()
            .build()
            .expect("timestamp_now should produce a valid manifest");

        assert!(DateTime::parse_from_rfc3339(&manifest.timestamp).is_ok());
    }
}
