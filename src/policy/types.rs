use serde::{Deserialize, Serialize};

use crate::assembler::BoundaryClass;
use crate::types::ClaimLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorPack {
    Secrets,
    Pii,
    Tabular,
    Blobs,
    Paths,
}

impl DetectorPack {
    pub(crate) fn boundary_pack(self) -> boundary_detectors::Pack {
        match self {
            Self::Secrets => boundary_detectors::Pack::Secrets,
            Self::Pii => boundary_detectors::Pack::Pii,
            Self::Tabular => boundary_detectors::Pack::Tabular,
            Self::Blobs => boundary_detectors::Pack::Blobs,
            Self::Paths => boundary_detectors::Pack::Paths,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirlockPolicy {
    pub policy_id: String,
    pub version: String,
    pub allowed_keys: Vec<AllowRule>,
    pub forbidden_keys: Vec<String>,
    pub forbidden_patterns: Vec<ForbiddenPattern>,
    pub derived_text_paths: Vec<String>,
    pub claim_levels: Vec<ClaimLevel>,
    #[serde(default)]
    pub detectors: Vec<DetectorPack>,
    #[serde(default)]
    pub detectors_warn_only: Vec<DetectorPack>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_bloom_min_hits: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tabular_min_rows: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_multimodal: Option<bool>,
    /// Local artifacts whose bytes the operator vouches for as tool results (al-210 ruling D3).
    /// A tool result in a chained prompt is TOOL_RESULT, and keeps the strict claim reachable,
    /// only if the blake3 hash of its content is listed here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_tool_results: Vec<DeclaredToolResult>,
    #[serde(skip)]
    pub extends: Vec<String>,
    #[serde(skip)]
    pub source_chain: Vec<PolicySource>,
}

impl AirlockPolicy {
    /// True when `artifact_hash` (as `blake3_hash` writes it) is listed in
    /// `declared_tool_results`. The assembler's label and `verify`'s claim both ask this one
    /// question, so they cannot disagree about what "declared" means.
    pub fn declares_tool_result(&self, artifact_hash: &str) -> bool {
        self.declared_tool_results
            .iter()
            .any(|declared| declared.artifact_hash == artifact_hash)
    }
}

/// One file in a resolved policy's depth-first inheritance chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySource {
    pub source_ref: String,
    pub extends: Vec<String>,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowRule {
    pub key_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary_class: Option<BoundaryClass>,
}

/// One declared tool-result artifact: the hash of its exact bytes, as `blake3_hash` writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredToolResult {
    pub artifact_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForbiddenPattern {
    pub pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_class: Option<String>,
}
