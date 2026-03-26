use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// BoundaryMode
// ---------------------------------------------------------------------------

/// Declares how much filing-derived prose is allowed to cross the boundary.
///
/// - `Annotated`: structured telemetry plus bounded derived prose.
///   Claim ceiling: `RawDocumentAbsent`.
/// - `TelemetryOnly`: structured telemetry only. No filing-derived prose crosses.
///   Claim ceiling: `StrictTelemetryOnly`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryMode {
    Annotated,
    TelemetryOnly,
}

impl fmt::Display for BoundaryMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Annotated => write!(f, "ANNOTATED"),
            Self::TelemetryOnly => write!(f, "TELEMETRY_ONLY"),
        }
    }
}

// ---------------------------------------------------------------------------
// ClaimLevel
// ---------------------------------------------------------------------------

/// The strict claim hierarchy for boundary attestation.
///
/// `BoundaryFailed < RawDocumentAbsent < StrictTelemetryOnly`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimLevel {
    BoundaryFailed,
    RawDocumentAbsent,
    StrictTelemetryOnly,
}

impl ClaimLevel {
    /// Numeric rank for ordering. Higher = stronger claim.
    fn rank(self) -> u8 {
        match self {
            Self::BoundaryFailed => 0,
            Self::RawDocumentAbsent => 1,
            Self::StrictTelemetryOnly => 2,
        }
    }
}

impl Ord for ClaimLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for ClaimLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for ClaimLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundaryFailed => write!(f, "BOUNDARY_FAILED"),
            Self::RawDocumentAbsent => write!(f, "RAW_DOCUMENT_ABSENT"),
            Self::StrictTelemetryOnly => write!(f, "STRICT_TELEMETRY_ONLY"),
        }
    }
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

/// An offending item detected during boundary scanning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// JSON key path where the violation was found (e.g. "html_path").
    pub key_path: String,

    /// Truncated sample of the offending value (max 100 chars).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_value: Option<String>,

    /// Classification of the artifact (e.g. "forbidden_key", "forbidden_pattern").
    pub artifact_class: String,

    /// The policy rule that matched.
    pub matched_rule: String,
}

// ---------------------------------------------------------------------------
// BlockedReason
// ---------------------------------------------------------------------------

/// Explains why a stronger claim level was not earned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedReason {
    /// The claim level that was attempted but not achieved.
    pub claim_attempted: ClaimLevel,

    /// Human-readable explanation.
    pub reason: String,

    /// Key paths that blocked the claim.
    pub offending_paths: Vec<String>,
}

// ---------------------------------------------------------------------------
// UpstreamArtifact
// ---------------------------------------------------------------------------

/// An input artifact that influenced the boundary crossing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamArtifact {
    /// File path or identifier of the upstream artifact.
    pub path: String,

    /// Content hash in `blake3:{hex}` format.
    pub content_hash: String,

    /// Classification (e.g. "strategy_space", "heuristic", "system_prompt").
    pub artifact_class: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_level_ordering() {
        assert!(ClaimLevel::BoundaryFailed < ClaimLevel::RawDocumentAbsent);
        assert!(ClaimLevel::RawDocumentAbsent < ClaimLevel::StrictTelemetryOnly);
        assert!(ClaimLevel::BoundaryFailed < ClaimLevel::StrictTelemetryOnly);
    }

    #[test]
    fn boundary_mode_serde_roundtrip() {
        for mode in [BoundaryMode::Annotated, BoundaryMode::TelemetryOnly] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: BoundaryMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
        // Verify SCREAMING_SNAKE_CASE serialization
        assert_eq!(
            serde_json::to_string(&BoundaryMode::Annotated).unwrap(),
            "\"ANNOTATED\""
        );
        assert_eq!(
            serde_json::to_string(&BoundaryMode::TelemetryOnly).unwrap(),
            "\"TELEMETRY_ONLY\""
        );
    }

    #[test]
    fn claim_level_serde_roundtrip() {
        for level in [
            ClaimLevel::BoundaryFailed,
            ClaimLevel::RawDocumentAbsent,
            ClaimLevel::StrictTelemetryOnly,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: ClaimLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
        assert_eq!(
            serde_json::to_string(&ClaimLevel::BoundaryFailed).unwrap(),
            "\"BOUNDARY_FAILED\""
        );
        assert_eq!(
            serde_json::to_string(&ClaimLevel::RawDocumentAbsent).unwrap(),
            "\"RAW_DOCUMENT_ABSENT\""
        );
        assert_eq!(
            serde_json::to_string(&ClaimLevel::StrictTelemetryOnly).unwrap(),
            "\"STRICT_TELEMETRY_ONLY\""
        );
    }

    #[test]
    fn finding_serde_roundtrip() {
        let finding = Finding {
            key_path: "html_path".to_string(),
            sample_value: Some("/filings/abc.html".to_string()),
            artifact_class: "forbidden_key".to_string(),
            matched_rule: "forbidden_keys[0]".to_string(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, back);
    }

    #[test]
    fn finding_skips_none_sample_value() {
        let finding = Finding {
            key_path: "pdf_path".to_string(),
            sample_value: None,
            artifact_class: "forbidden_key".to_string(),
            matched_rule: "forbidden_keys[2]".to_string(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(!json.contains("sample_value"));
    }

    #[test]
    fn blocked_reason_serde_roundtrip() {
        let reason = BlockedReason {
            claim_attempted: ClaimLevel::StrictTelemetryOnly,
            reason: "derived text present".to_string(),
            offending_paths: vec!["mutator_context.challenge_observation".to_string()],
        };
        let json = serde_json::to_string(&reason).unwrap();
        let back: BlockedReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, back);
    }

    #[test]
    fn upstream_artifact_serde_roundtrip() {
        let artifact = UpstreamArtifact {
            path: "strategy_space.json".to_string(),
            content_hash: "blake3:abc123".to_string(),
            artifact_class: "strategy_space".to_string(),
        };
        let json = serde_json::to_string(&artifact).unwrap();
        let back: UpstreamArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }
}
