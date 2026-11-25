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
    #[serde(skip)]
    pub extends: Vec<String>,
    #[serde(skip)]
    pub source_chain: Vec<PolicySource>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForbiddenPattern {
    pub pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_class: Option<String>,
}
