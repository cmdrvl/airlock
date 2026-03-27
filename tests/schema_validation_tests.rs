use std::path::{Path, PathBuf};

use jsonschema::validator_for;
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn compile_schema(path: &str) -> jsonschema::Validator {
    validator_for(&read_json(&repo_root().join(path))).unwrap()
}

#[test]
fn test_manifest_validates_against_schema() {
    let schema = compile_schema("schemas/airlock.v0.schema.json");

    for path in [
        "fixtures/clean_telemetry_only/expected_manifest.json",
        "fixtures/annotated_mode/expected_manifest.json",
        "fixtures/boundary_failed/expected_manifest.json",
    ] {
        schema
            .validate(&read_json(&repo_root().join(path)))
            .unwrap();
    }
}

#[test]
fn test_provenance_validates_against_schema() {
    let schema = compile_schema("schemas/prompt_provenance.schema.json");

    for path in [
        "fixtures/clean_telemetry_only/expected_prompt_provenance.json",
        "fixtures/annotated_mode/expected_prompt_provenance.json",
        "fixtures/boundary_failed/prompt_provenance.json",
    ] {
        schema
            .validate(&read_json(&repo_root().join(path)))
            .unwrap();
    }
}

#[test]
fn test_refusal_validates_against_schema() {
    let schema = compile_schema("schemas/refusal.schema.json");
    let refusal = read_json(&repo_root().join("fixtures/refusal/expected_refusal_bad_policy.json"));

    schema.validate(&refusal).unwrap();
}

#[test]
fn test_bad_manifest_fails_schema() {
    let schema = compile_schema("schemas/airlock.v0.schema.json");
    let mut manifest =
        read_json(&repo_root().join("fixtures/clean_telemetry_only/expected_manifest.json"));
    manifest["policy_hash"] = Value::String("sha256:not-a-blake3-hash".to_string());

    assert!(schema.validate(&manifest).is_err());
}
