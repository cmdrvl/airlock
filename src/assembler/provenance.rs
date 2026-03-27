use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hash::blake3_hash;
use crate::output::{canonical_json, canonical_json_bytes};
use crate::types::BoundaryMode;

pub const PROMPT_PROVENANCE_VERSION: &str = "airlock.v0";

/// Records how one emitted prompt field or fragment crossed the boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub prompt_path: String,
    pub emitted_value_hash: String,
    pub source_artifact_hash: String,
    pub source_path: String,
    pub transformation_kind: TransformationKind,
    pub policy_rule_id: String,
    pub boundary_class: BoundaryClass,
    pub admitted_boundary_modes: Vec<BoundaryMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransformationKind {
    Copy,
    Normalize,
    Aggregate,
    Template,
    DerivedAnnotation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryClass {
    Telemetry,
    DerivedText,
    Forbidden,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptProvenance {
    pub version: String,
    pub policy_hash: String,
    pub prompt_payload_hash: String,
    pub boundary_mode: BoundaryMode,
    pub records: Vec<ProvenanceRecord>,
}

impl PromptProvenance {
    pub fn new(
        policy_hash: impl Into<String>,
        prompt_payload_hash: impl Into<String>,
        boundary_mode: BoundaryMode,
        records: Vec<ProvenanceRecord>,
    ) -> Self {
        Self {
            version: PROMPT_PROVENANCE_VERSION.to_string(),
            policy_hash: policy_hash.into(),
            prompt_payload_hash: prompt_payload_hash.into(),
            boundary_mode,
            records,
        }
    }

    /// Serialize this artifact as canonical JSON with recursively sorted keys.
    pub fn to_canonical_json(&self) -> String {
        canonical_json(&self.as_json_value())
    }

    /// Hash the canonical JSON bytes for deterministic replay and sealing.
    pub fn hash(&self) -> String {
        blake3_hash(&canonical_json_bytes(&self.as_json_value()))
    }

    fn as_json_value(&self) -> Value {
        serde_json::to_value(self).expect("prompt provenance should serialize to JSON")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::blake3_hash;

    fn sample_record(boundary_class: BoundaryClass) -> ProvenanceRecord {
        ProvenanceRecord {
            prompt_path: "messages[1].content.challenge_profile.page_count".to_string(),
            emitted_value_hash: blake3_hash(br#"{"page_count":12}"#),
            source_artifact_hash: blake3_hash(br#"{"challenge_profile":{"page_count":12}}"#),
            source_path: "challenge_profile.page_count".to_string(),
            transformation_kind: TransformationKind::Copy,
            policy_rule_id: "allow.challenge_profile.page_count".to_string(),
            boundary_class,
            admitted_boundary_modes: vec![BoundaryMode::Annotated, BoundaryMode::TelemetryOnly],
        }
    }

    fn sample_provenance() -> PromptProvenance {
        PromptProvenance::new(
            blake3_hash(br#"{"policy_id":"tournament_baseline"}"#),
            blake3_hash(
                br#"{"messages":[{"content":"system prompt","role":"system"},{"content":{"challenge_profile":{"layout_notes":["Dense footnote section"],"page_count":12}},"role":"user"}]}"#,
            ),
            BoundaryMode::Annotated,
            vec![
                sample_record(BoundaryClass::Telemetry),
                ProvenanceRecord {
                    prompt_path: "messages[1].content.challenge_profile.layout_notes[0]".to_string(),
                    emitted_value_hash: blake3_hash(b"\"Dense footnote section\""),
                    source_artifact_hash: blake3_hash(
                        br#"{"challenge_profile":{"layout_notes":["Dense footnote section"]}}"#,
                    ),
                    source_path: "challenge_profile.layout_notes[0]".to_string(),
                    transformation_kind: TransformationKind::DerivedAnnotation,
                    policy_rule_id: "derived.challenge_profile.layout_notes".to_string(),
                    boundary_class: BoundaryClass::DerivedText,
                    admitted_boundary_modes: vec![BoundaryMode::Annotated],
                },
                ProvenanceRecord {
                    prompt_path: "messages[1].content.section_html".to_string(),
                    emitted_value_hash: blake3_hash(b"\"<table>forbidden</table>\""),
                    source_artifact_hash: blake3_hash(
                        br#"{"section_html":"<table>forbidden</table>"}"#,
                    ),
                    source_path: "section_html".to_string(),
                    transformation_kind: TransformationKind::Copy,
                    policy_rule_id: "deny.section_html".to_string(),
                    boundary_class: BoundaryClass::Forbidden,
                    admitted_boundary_modes: vec![BoundaryMode::Annotated],
                },
            ],
        )
    }

    #[test]
    fn transformation_kind_serializes_as_expected() {
        assert_eq!(
            serde_json::to_string(&TransformationKind::Copy).unwrap(),
            "\"COPY\""
        );
        assert_eq!(
            serde_json::to_string(&TransformationKind::Normalize).unwrap(),
            "\"NORMALIZE\""
        );
        assert_eq!(
            serde_json::to_string(&TransformationKind::Aggregate).unwrap(),
            "\"AGGREGATE\""
        );
        assert_eq!(
            serde_json::to_string(&TransformationKind::Template).unwrap(),
            "\"TEMPLATE\""
        );
        assert_eq!(
            serde_json::to_string(&TransformationKind::DerivedAnnotation).unwrap(),
            "\"DERIVED_ANNOTATION\""
        );
    }

    #[test]
    fn boundary_class_serializes_as_expected() {
        assert_eq!(
            serde_json::to_string(&BoundaryClass::Telemetry).unwrap(),
            "\"TELEMETRY\""
        );
        assert_eq!(
            serde_json::to_string(&BoundaryClass::DerivedText).unwrap(),
            "\"DERIVED_TEXT\""
        );
        assert_eq!(
            serde_json::to_string(&BoundaryClass::Forbidden).unwrap(),
            "\"FORBIDDEN\""
        );
    }

    #[test]
    fn provenance_record_round_trips_through_serde() {
        let record = sample_record(BoundaryClass::Telemetry);
        let json = serde_json::to_string(&record).unwrap();
        let decoded: ProvenanceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn prompt_provenance_round_trips_through_serde() {
        let provenance = sample_provenance();
        let json = serde_json::to_string(&provenance).unwrap();
        let decoded: PromptProvenance = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, provenance);
    }

    #[test]
    fn prompt_provenance_canonical_json_is_deterministic() {
        let provenance = sample_provenance();
        let json_once = provenance.to_canonical_json();
        let json_twice = provenance.to_canonical_json();

        assert_eq!(json_once, json_twice);
        assert!(json_once.starts_with("{\"boundary_mode\":\"ANNOTATED\""));
        assert!(json_once.contains("\"boundary_class\":\"TELEMETRY\""));
        assert!(json_once.contains("\"boundary_class\":\"DERIVED_TEXT\""));
        assert!(json_once.contains("\"boundary_class\":\"FORBIDDEN\""));
    }

    #[test]
    fn prompt_provenance_hash_is_deterministic() {
        let provenance = sample_provenance();
        assert_eq!(provenance.hash(), provenance.hash());
    }

    #[test]
    fn admitted_boundary_modes_use_boundary_mode_enum_strings() {
        let record = sample_record(BoundaryClass::Telemetry);
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(
            json["admitted_boundary_modes"],
            serde_json::json!(["ANNOTATED", "TELEMETRY_ONLY"])
        );
    }

    #[test]
    fn new_sets_airlock_version() {
        let provenance = PromptProvenance::new(
            "blake3:policy",
            "blake3:prompt",
            BoundaryMode::TelemetryOnly,
            vec![],
        );

        assert_eq!(provenance.version, PROMPT_PROVENANCE_VERSION);
    }
}
