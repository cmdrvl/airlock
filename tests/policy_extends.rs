use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::tempdir;

use airlock::policy::{self, AirlockPolicy};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> PathBuf {
    repo_root().join("fixtures/policy_extends").join(name)
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

#[test]
fn resolves_child_overrides_and_records_policy_sources_in_manifest() {
    let policy_path = fixture("child.yaml");
    let policy = policy::load_policy(&policy_path).unwrap();

    assert_eq!(policy.policy_id, "inherited_child");
    assert_eq!(
        policy
            .allowed_keys
            .iter()
            .map(|rule| rule.key_path.as_str())
            .collect::<Vec<_>>(),
        ["family_id", "benchmark_summary.score"]
    );
    assert_eq!(policy.forbidden_keys, ["html_path"]);
    assert_eq!(policy.forbidden_patterns[0].pattern, "<script");
    assert_eq!(policy.derived_text_paths, ["benchmark_summary.description"]);
    assert_eq!(policy.claim_levels.len(), 3);
    assert_eq!(policy.source_chain.len(), 2);
    assert!(
        policy
            .source_chain
            .iter()
            .all(|source| source.content_hash.starts_with("blake3:"))
    );

    let dir = tempdir().unwrap();
    let policy_copy = dir.path().join("child.yaml");
    let base_copy = dir.path().join("base.yaml");
    fs::copy(&policy_path, &policy_copy).unwrap();
    fs::copy(fixture("base.yaml"), &base_copy).unwrap();
    let copied_policy = policy::load_policy(&policy_copy).unwrap();
    let input = dir.path().join("input.json");
    write_json(&input, &json!({"family_id": "sample-family"}));
    let prompt = dir.path().join("prompt.json");
    let provenance = dir.path().join("provenance.json");
    let assemble = Command::cargo_bin("airlock")
        .unwrap()
        .current_dir(&dir)
        .args([
            "assemble",
            "--policy",
            policy_copy.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--out",
            prompt.to_str().unwrap(),
            "--provenance-out",
            provenance.to_str().unwrap(),
            "--no-witness",
        ])
        .assert()
        .success();
    assert!(!assemble.get_output().stdout.is_empty());

    let prompt_value: Value = serde_json::from_slice(&fs::read(&prompt).unwrap()).unwrap();
    let request = dir.path().join("request.json");
    write_json(
        &request,
        &json!({
            "model": "gpt-5",
            "messages": prompt_value["messages"],
            "temperature": 0
        }),
    );
    let manifest_path = dir.path().join("manifest.json");
    let verify = Command::cargo_bin("airlock")
        .unwrap()
        .current_dir(&dir)
        .args([
            "verify",
            "--policy",
            policy_copy.to_str().unwrap(),
            "--prompt",
            prompt.to_str().unwrap(),
            "--provenance",
            provenance.to_str().unwrap(),
            "--request",
            request.to_str().unwrap(),
            "--out",
            manifest_path.to_str().unwrap(),
            "--no-witness",
        ])
        .assert()
        .success();
    let manifest: Value = serde_json::from_slice(&verify.get_output().stdout).unwrap();
    let policy_sources = manifest["upstream_artifact_inventory"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|artifact| artifact["artifact_class"] == "policy_source")
        .collect::<Vec<_>>();
    assert_eq!(policy_sources.len(), 2);
    for source in &copied_policy.source_chain {
        assert!(policy_sources.iter().any(|artifact| {
            artifact["content_hash"] == source.content_hash
                && artifact["path"] == source.source_ref
                && artifact["extends"] == serde_json::to_value(&source.extends).unwrap()
        }));
    }
}

#[test]
fn resolved_hash_and_list_order_do_not_depend_on_include_order() {
    let order_ab = policy::load_policy(&fixture("order_ab.yaml")).unwrap();
    let order_ba = policy::load_policy(&fixture("order_ba.yaml")).unwrap();

    assert_eq!(
        policy::resolved_policy_hash(&order_ab),
        policy::resolved_policy_hash(&order_ba)
    );
    assert_eq!(
        order_ab
            .allowed_keys
            .iter()
            .map(|rule| rule.key_path.as_str())
            .collect::<Vec<_>>(),
        order_ba
            .allowed_keys
            .iter()
            .map(|rule| rule.key_path.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(order_ab.forbidden_keys, ["html_path", "pdf_path"]);
}

#[test]
fn cycle_refuses_with_bad_policy() {
    let refusal = policy::load_policy(&fixture("cycle_a.yaml")).unwrap_err();

    assert_eq!(refusal.refusal.code.as_str(), "E_BAD_POLICY");
    assert!(refusal.refusal.message.contains("cycle"));
}

#[test]
fn policy_can_be_loaded_as_the_typed_resolved_contract() {
    let policy: AirlockPolicy = policy::load_policy(&fixture("child.yaml")).unwrap();

    assert_eq!(policy.policy_id, "inherited_child");
    assert_eq!(policy.extends, ["base.yaml"]);
    assert_eq!(policy.source_chain.len(), 2);
}

#[test]
fn extending_policy_fixture_is_allowed_by_policy_schema() {
    let schema: Value = serde_json::from_slice(
        &fs::read(repo_root().join("schemas/airlock_policy.schema.json")).unwrap(),
    )
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let child: Value = serde_yaml::from_slice(&fs::read(fixture("child.yaml")).unwrap()).unwrap();

    assert!(validator.is_valid(&child));
}
