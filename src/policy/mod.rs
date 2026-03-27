pub mod types;

pub use types::{AirlockPolicy, AllowRule, ForbiddenPattern};

use std::path::Path;

use regex::Regex;
use serde_json::json;

use crate::hash::blake3_hash;
use crate::refusal::RefusalEnvelope;

pub fn load_policy(path: &Path) -> Result<AirlockPolicy, RefusalEnvelope> {
    let raw = std::fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            RefusalEnvelope::missing_file(path.display().to_string())
        } else {
            RefusalEnvelope::bad_policy(
                "failed to read policy file",
                json!({
                    "error": error.to_string(),
                    "path": path.display().to_string(),
                }),
            )
        }
    })?;

    let yaml_value: serde_yaml::Value = serde_yaml::from_slice(&raw).map_err(|error| {
        RefusalEnvelope::bad_policy(
            "policy file failed YAML parsing",
            json!({
                "error": error.to_string(),
                "path": path.display().to_string(),
            }),
        )
    })?;

    ensure_required_top_level_fields(&yaml_value, path)?;

    let policy: AirlockPolicy = serde_yaml::from_value(yaml_value).map_err(|error| {
        RefusalEnvelope::bad_policy(
            "policy file failed schema validation",
            json!({
                "error": error.to_string(),
                "path": path.display().to_string(),
            }),
        )
    })?;

    validate_policy(&policy, path)?;
    Ok(policy)
}

pub fn hash_policy(path: &Path) -> Result<String, RefusalEnvelope> {
    let raw = std::fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            RefusalEnvelope::missing_file(path.display().to_string())
        } else {
            RefusalEnvelope::bad_policy(
                "failed to read policy file",
                json!({
                    "error": error.to_string(),
                    "path": path.display().to_string(),
                }),
            )
        }
    })?;

    Ok(blake3_hash(&raw))
}

pub fn validate_policy(policy: &AirlockPolicy, path: &Path) -> Result<(), RefusalEnvelope> {
    if policy.policy_id.trim().is_empty() {
        return Err(policy_validation_error(
            path,
            "policy_id must not be empty",
            json!({ "field": "policy_id" }),
        ));
    }

    if policy.version.trim().is_empty() {
        return Err(policy_validation_error(
            path,
            "version must not be empty",
            json!({ "field": "version" }),
        ));
    }

    if policy.allowed_keys.is_empty() {
        return Err(policy_validation_error(
            path,
            "allowed_keys must contain at least one rule",
            json!({ "field": "allowed_keys" }),
        ));
    }

    if let Some((index, _)) = policy
        .allowed_keys
        .iter()
        .enumerate()
        .find(|(_, rule)| rule.key_path.trim().is_empty())
    {
        return Err(policy_validation_error(
            path,
            "allow rule key_path must not be empty",
            json!({
                "field": "allowed_keys",
                "index": index,
            }),
        ));
    }

    if policy.claim_levels.is_empty() {
        return Err(policy_validation_error(
            path,
            "claim_levels must contain at least one value",
            json!({ "field": "claim_levels" }),
        ));
    }

    if let Some((index, _)) = policy
        .forbidden_patterns
        .iter()
        .enumerate()
        .find(|(_, pattern)| pattern.pattern.trim().is_empty())
    {
        return Err(policy_validation_error(
            path,
            "forbidden pattern must not be empty",
            json!({
                "field": "forbidden_patterns",
                "index": index,
            }),
        ));
    }

    for (index, pattern) in policy.forbidden_patterns.iter().enumerate() {
        Regex::new(&pattern.pattern).map_err(|error| {
            policy_validation_error(
                path,
                "forbidden pattern failed regex compilation",
                json!({
                    "error": error.to_string(),
                    "field": "forbidden_patterns",
                    "index": index,
                    "pattern": pattern.pattern,
                }),
            )
        })?;
    }

    Ok(())
}

fn policy_validation_error(
    path: &Path,
    message: impl Into<String>,
    detail: serde_json::Value,
) -> RefusalEnvelope {
    let mut detail = detail;
    if let Some(object) = detail.as_object_mut() {
        object.insert(
            "path".to_string(),
            serde_json::Value::String(path.display().to_string()),
        );
    }

    RefusalEnvelope::bad_policy(message, detail)
}

fn ensure_required_top_level_fields(
    yaml_value: &serde_yaml::Value,
    path: &Path,
) -> Result<(), RefusalEnvelope> {
    let mapping = yaml_value.as_mapping().ok_or_else(|| {
        policy_validation_error(
            path,
            "policy file must be a YAML mapping",
            json!({ "field": "root" }),
        )
    })?;

    for field in [
        "policy_id",
        "version",
        "allowed_keys",
        "forbidden_keys",
        "forbidden_patterns",
        "derived_text_paths",
        "claim_levels",
    ] {
        let key = serde_yaml::Value::String(field.to_string());
        if !mapping.contains_key(&key) {
            return Err(policy_validation_error(
                path,
                format!("{field} is required"),
                json!({ "field": field }),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::BoundaryClass;
    use crate::types::ClaimLevel;
    use tempfile::tempdir;

    fn sample_policy() -> AirlockPolicy {
        AirlockPolicy {
            policy_id: "tournament_baseline".to_string(),
            version: "airlock.v0".to_string(),
            allowed_keys: vec![
                AllowRule {
                    key_path: "family_id".to_string(),
                    description: Some("Filing family identifier".to_string()),
                    boundary_class: Some(BoundaryClass::Telemetry),
                },
                AllowRule {
                    key_path: "mutator_context.challenge_observation".to_string(),
                    description: Some("Derived structural notes".to_string()),
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
                    description: Some("Raw HTML markup".to_string()),
                    artifact_class: Some("raw_html".to_string()),
                },
                ForbiddenPattern {
                    pattern: "sec\\.gov/Archives".to_string(),
                    description: Some("SEC archive URLs".to_string()),
                    artifact_class: Some("sec_archive_url".to_string()),
                },
            ],
            derived_text_paths: vec![
                "mutator_context.challenge_observation".to_string(),
                "mutator_context.challenge_profile.header_surfaces".to_string(),
            ],
            claim_levels: vec![
                ClaimLevel::BoundaryFailed,
                ClaimLevel::RawDocumentAbsent,
                ClaimLevel::StrictTelemetryOnly,
            ],
        }
    }

    #[test]
    fn policy_yaml_round_trip_is_deterministic() {
        let yaml_once = serde_yaml::to_string(&sample_policy()).unwrap();
        let parsed: AirlockPolicy = serde_yaml::from_str(&yaml_once).unwrap();
        let yaml_twice = serde_yaml::to_string(&parsed).unwrap();

        assert_eq!(yaml_once, yaml_twice);
    }

    #[test]
    fn hash_policy_is_deterministic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, serde_yaml::to_string(&sample_policy()).unwrap()).unwrap();

        let first = hash_policy(&path).unwrap();
        let second = hash_policy(&path).unwrap();

        assert_eq!(first, second);
        assert!(first.starts_with("blake3:"));
    }

    #[test]
    fn load_policy_returns_bad_policy_for_invalid_yaml() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("broken.yaml");
        std::fs::write(&path, "policy_id: [unterminated").unwrap();

        let refusal = load_policy(&path).unwrap_err();

        assert_eq!(refusal.refusal.code.as_str(), "E_BAD_POLICY");
        assert!(refusal.refusal.message.contains("YAML parsing"));
    }

    #[test]
    fn load_policy_rejects_missing_policy_id() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing-policy-id.yaml");
        std::fs::write(
            &path,
            r#"
version: airlock.v0
allowed_keys:
  - key_path: family_id
forbidden_keys: []
forbidden_patterns: []
derived_text_paths: []
claim_levels:
  - BOUNDARY_FAILED
"#,
        )
        .unwrap();

        let refusal = load_policy(&path).unwrap_err();

        assert_eq!(refusal.refusal.code.as_str(), "E_BAD_POLICY");
        assert!(refusal.refusal.message.contains("policy_id"));
    }

    #[test]
    fn load_policy_rejects_invalid_regex_pattern() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("invalid-regex.yaml");
        std::fs::write(
            &path,
            r#"
policy_id: tournament_baseline
version: airlock.v0
allowed_keys:
  - key_path: family_id
forbidden_keys: []
forbidden_patterns:
  - pattern: "["
derived_text_paths: []
claim_levels:
  - BOUNDARY_FAILED
"#,
        )
        .unwrap();

        let refusal = load_policy(&path).unwrap_err();

        assert_eq!(refusal.refusal.code.as_str(), "E_BAD_POLICY");
        assert!(refusal.refusal.message.contains("regex compilation"));
    }

    #[test]
    fn load_policy_rejects_empty_allowed_keys() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty-allowed.yaml");
        std::fs::write(
            &path,
            r#"
policy_id: tournament_baseline
version: airlock.v0
allowed_keys: []
forbidden_keys: []
forbidden_patterns: []
derived_text_paths: []
claim_levels:
  - BOUNDARY_FAILED
"#,
        )
        .unwrap();

        let refusal = load_policy(&path).unwrap_err();

        assert_eq!(refusal.refusal.code.as_str(), "E_BAD_POLICY");
        assert!(refusal.refusal.message.contains("allowed_keys"));
    }

    #[test]
    fn rules_tournament_baseline_loads_successfully() {
        let path = Path::new("rules/tournament_baseline.yaml");
        let policy = load_policy(path).unwrap();

        assert_eq!(policy.policy_id, "tournament_baseline");
        assert!(!policy.allowed_keys.is_empty());
        assert!(!policy.claim_levels.is_empty());
    }

    #[test]
    fn sec_archive_pattern_matches_real_url_in_sample_and_baseline_policies() {
        let sample_policy = sample_policy();
        let sample_pattern = sample_policy
            .forbidden_patterns
            .iter()
            .find(|pattern| pattern.artifact_class.as_deref() == Some("sec_archive_url"))
            .unwrap();
        let baseline_policy = load_policy(Path::new("rules/tournament_baseline.yaml")).unwrap();
        let baseline_pattern = baseline_policy
            .forbidden_patterns
            .iter()
            .find(|pattern| pattern.artifact_class.as_deref() == Some("sec_archive_url"))
            .unwrap();
        let url = "https://www.sec.gov/Archives/edgar/data/0000000000/000000000026000001/index.htm";

        assert!(Regex::new(&sample_pattern.pattern).unwrap().is_match(url));
        assert!(Regex::new(&baseline_pattern.pattern).unwrap().is_match(url));
    }
}
