pub mod types;

pub use types::{AirlockPolicy, AllowRule, ForbiddenPattern, PolicySource};

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::hash::blake3_hash;
use crate::refusal::RefusalEnvelope;

pub fn load_policy(path: &Path) -> Result<AirlockPolicy, RefusalEnvelope> {
    let mut policy = AirlockPolicy::default();
    let mut stack = Vec::new();
    let mut visited = BTreeSet::new();
    let mut source_chain = Vec::new();
    let mut has_extends = false;
    let mut root_extends = Vec::new();
    resolve_policy_file(
        path,
        &mut stack,
        &mut visited,
        &mut policy,
        &mut source_chain,
        &mut has_extends,
        &mut root_extends,
    )?;

    policy.extends = root_extends;
    if has_extends {
        policy.source_chain = source_chain;
    }
    validate_policy(&policy, path)?;
    Ok(policy)
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialPolicy {
    policy_id: Option<String>,
    version: Option<String>,
    allowed_keys: Option<Vec<AllowRule>>,
    forbidden_keys: Option<Vec<String>>,
    forbidden_patterns: Option<Vec<ForbiddenPattern>>,
    derived_text_paths: Option<Vec<String>>,
    claim_levels: Option<Vec<crate::types::ClaimLevel>>,
    protected_bloom_min_hits: Option<usize>,
    allow_multimodal: Option<bool>,
    extends: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct PolicyContent<'a> {
    policy_id: &'a str,
    version: &'a str,
    allowed_keys: &'a [AllowRule],
    forbidden_keys: &'a [String],
    forbidden_patterns: &'a [ForbiddenPattern],
    derived_text_paths: &'a [String],
    claim_levels: &'a [crate::types::ClaimLevel],
    #[serde(skip_serializing_if = "Option::is_none")]
    protected_bloom_min_hits: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_multimodal: Option<bool>,
}

fn resolve_policy_file(
    path: &Path,
    stack: &mut Vec<PathBuf>,
    visited: &mut BTreeSet<PathBuf>,
    resolved: &mut AirlockPolicy,
    source_chain: &mut Vec<PolicySource>,
    has_extends: &mut bool,
    root_extends: &mut Vec<String>,
) -> Result<(), RefusalEnvelope> {
    let canonical_path = path.canonicalize().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound && stack.is_empty() {
            RefusalEnvelope::missing_file(path.display().to_string())
        } else {
            RefusalEnvelope::bad_policy(
                "extended policy source could not be resolved",
                json!({
                    "error": error.to_string(),
                    "path": path.display().to_string(),
                }),
            )
        }
    })?;

    if stack.contains(&canonical_path) {
        let mut cycle = stack
            .iter()
            .map(|item| item.display().to_string())
            .collect::<Vec<_>>();
        cycle.push(canonical_path.display().to_string());
        return Err(RefusalEnvelope::bad_policy(
            "policy extends cycle detected",
            json!({ "cycle": cycle }),
        ));
    }
    if visited.contains(&canonical_path) {
        return Ok(());
    }

    let raw = std::fs::read(&canonical_path).map_err(|error| {
        RefusalEnvelope::bad_policy(
            "failed to read policy file",
            json!({
                "error": error.to_string(),
                "path": canonical_path.display().to_string(),
            }),
        )
    })?;
    let yaml_value: serde_yaml::Value = serde_yaml::from_slice(&raw).map_err(|error| {
        RefusalEnvelope::bad_policy(
            "policy file failed YAML parsing",
            json!({
                "error": error.to_string(),
                "path": canonical_path.display().to_string(),
            }),
        )
    })?;
    ensure_non_null_fields(&yaml_value, &canonical_path)?;
    let extends_key = serde_yaml::Value::String("extends".to_string());
    let has_parent_refs = yaml_value
        .as_mapping()
        .and_then(|mapping| mapping.get(&extends_key))
        .and_then(serde_yaml::Value::as_sequence)
        .is_some_and(|refs| !refs.is_empty());
    if stack.is_empty() && !has_parent_refs {
        ensure_required_top_level_fields(&yaml_value, &canonical_path)?;
    }
    let partial: PartialPolicy = serde_yaml::from_value(yaml_value).map_err(|error| {
        RefusalEnvelope::bad_policy(
            "policy file failed schema validation",
            json!({
                "error": error.to_string(),
                "path": canonical_path.display().to_string(),
            }),
        )
    })?;

    let mut refs = partial.extends.clone().unwrap_or_default();
    refs.sort();
    refs.dedup();
    if !refs.is_empty() {
        *has_extends = true;
    }
    if stack.is_empty() {
        *root_extends = partial.extends.clone().unwrap_or_default();
    }

    stack.push(canonical_path.clone());
    for source_ref in &refs {
        let source_path =
            resolve_policy_reference(&canonical_path, source_ref).ok_or_else(|| {
                RefusalEnvelope::bad_policy(
                    "extended policy source does not exist",
                    json!({
                        "extends": source_ref,
                        "path": canonical_path.display().to_string(),
                    }),
                )
            })?;
        resolve_policy_file(
            &source_path,
            stack,
            visited,
            resolved,
            source_chain,
            has_extends,
            root_extends,
        )?;
    }
    stack.pop();

    merge_partial_policy(resolved, partial);
    source_chain.push(PolicySource {
        source_ref: canonical_path.display().to_string(),
        extends: refs,
        content_hash: blake3_hash(&raw),
    });
    visited.insert(canonical_path);
    Ok(())
}

fn resolve_policy_reference(parent: &Path, source_ref: &str) -> Option<PathBuf> {
    let source = Path::new(source_ref);
    let parent_dir = parent.parent().unwrap_or_else(|| Path::new("."));
    let requested = if source.is_absolute() {
        source.to_path_buf()
    } else {
        parent_dir.join(source)
    };
    let mut candidates = vec![requested.clone()];
    if source.extension().is_none() {
        candidates.push(requested.with_extension("yaml"));
        candidates.push(requested.with_extension("yml"));
        if source.components().count() <= 1 {
            candidates.push(parent_dir.join("rules").join(format!("{source_ref}.yaml")));
            candidates.push(parent_dir.join("rules").join(format!("{source_ref}.yml")));
        }
    }
    candidates.into_iter().find(|candidate| candidate.is_file())
}

fn ensure_non_null_fields(
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
        "protected_bloom_min_hits",
        "allow_multimodal",
        "extends",
    ] {
        let key = serde_yaml::Value::String(field.to_string());
        if mapping.get(&key).is_some_and(serde_yaml::Value::is_null) {
            return Err(policy_validation_error(
                path,
                format!("{field} must not be null"),
                json!({ "field": field }),
            ));
        }
    }
    Ok(())
}

fn merge_partial_policy(resolved: &mut AirlockPolicy, partial: PartialPolicy) {
    if let Some(policy_id) = partial.policy_id {
        resolved.policy_id = policy_id;
    }
    if let Some(version) = partial.version {
        resolved.version = version;
    }
    if let Some(min_hits) = partial.protected_bloom_min_hits {
        resolved.protected_bloom_min_hits = Some(min_hits);
    }
    if let Some(allow_multimodal) = partial.allow_multimodal {
        resolved.allow_multimodal = Some(allow_multimodal);
    }
    if let Some(allowed_keys) = partial.allowed_keys {
        for rule in allowed_keys {
            if let Some(existing) = resolved
                .allowed_keys
                .iter_mut()
                .find(|existing| existing.key_path == rule.key_path)
            {
                *existing = rule;
            } else {
                resolved.allowed_keys.push(rule);
            }
        }
    }
    if let Some(forbidden_keys) = partial.forbidden_keys {
        for key in forbidden_keys {
            if !resolved.forbidden_keys.contains(&key) {
                resolved.forbidden_keys.push(key);
            }
        }
    }
    if let Some(forbidden_patterns) = partial.forbidden_patterns {
        for pattern in forbidden_patterns {
            if let Some(existing) = resolved
                .forbidden_patterns
                .iter_mut()
                .find(|existing| existing.pattern == pattern.pattern)
            {
                *existing = pattern;
            } else {
                resolved.forbidden_patterns.push(pattern);
            }
        }
    }
    if let Some(paths) = partial.derived_text_paths {
        for path in paths {
            if !resolved.derived_text_paths.contains(&path) {
                resolved.derived_text_paths.push(path);
            }
        }
    }
    if let Some(claim_levels) = partial.claim_levels {
        for level in claim_levels {
            if !resolved.claim_levels.contains(&level) {
                resolved.claim_levels.push(level);
            }
        }
    }
}

pub fn resolved_policy_hash(policy: &AirlockPolicy) -> String {
    let content = PolicyContent {
        policy_id: &policy.policy_id,
        version: &policy.version,
        allowed_keys: &policy.allowed_keys,
        forbidden_keys: &policy.forbidden_keys,
        forbidden_patterns: &policy.forbidden_patterns,
        derived_text_paths: &policy.derived_text_paths,
        claim_levels: &policy.claim_levels,
        protected_bloom_min_hits: policy.protected_bloom_min_hits,
        allow_multimodal: policy.allow_multimodal,
    };
    let value = serde_json::to_value(content).expect("resolved policy should serialize");
    blake3_hash(&crate::output::canonical_json_bytes(
        &crate::output::sort_value(value),
    ))
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

    if policy.protected_bloom_min_hits == Some(0) {
        return Err(policy_validation_error(
            path,
            "protected_bloom_min_hits must be greater than zero",
            json!({ "field": "protected_bloom_min_hits" }),
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
            protected_bloom_min_hits: None,
            allow_multimodal: None,
            extends: Vec::new(),
            source_chain: Vec::new(),
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
    fn policy_proxy_options_are_hashed_and_zero_bloom_threshold_is_rejected() {
        let mut base = sample_policy();
        let original_hash = resolved_policy_hash(&base);
        base.protected_bloom_min_hits = Some(8);
        base.allow_multimodal = Some(true);
        assert_ne!(resolved_policy_hash(&base), original_hash);

        base.protected_bloom_min_hits = Some(0);
        let refusal = validate_policy(&base, Path::new("policy.yaml")).unwrap_err();
        assert!(refusal.refusal.message.contains("protected_bloom_min_hits"));
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
