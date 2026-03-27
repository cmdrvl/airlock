use serde::{Deserialize, Serialize};

use crate::assembler::BoundaryClass;
use crate::types::ClaimLevel;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirlockPolicy {
    pub policy_id: String,
    pub version: String,
    pub allowed_keys: Vec<AllowRule>,
    pub forbidden_keys: Vec<String>,
    pub forbidden_patterns: Vec<ForbiddenPattern>,
    pub derived_text_paths: Vec<String>,
    pub claim_levels: Vec<ClaimLevel>,
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
