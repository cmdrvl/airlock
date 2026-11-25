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

const GOLDEN_V0_3: [&str; 3] = [
    "fixtures/clean_telemetry_only/expected_manifest_v0_3.json",
    "fixtures/annotated_mode/expected_manifest_v0_3.json",
    "fixtures/boundary_failed/expected_manifest_v0_3.json",
];

#[test]
fn test_v0_3_manifests_validate_against_schema() {
    let schema = compile_schema("schemas/airlock.v0.schema.json");

    for path in GOLDEN_V0_3 {
        let manifest = read_json(&repo_root().join(path));
        assert_eq!(manifest["manifest_version"], "airlock.v0.3", "{path}");
        assert!(
            schema.is_valid(&manifest),
            "{path} does not validate: {:?}",
            schema
                .validate(&manifest)
                .err()
                .map(|error| error.to_string())
        );
    }
}

#[test]
fn test_v0_3_manifest_requires_bytes_crossed_and_attestation() {
    let schema = compile_schema("schemas/airlock.v0.schema.json");

    for field in ["bytes_crossed", "attestation"] {
        let mut manifest = read_json(&repo_root().join(GOLDEN_V0_3[0]));
        manifest.as_object_mut().unwrap().remove(field);
        assert!(
            schema.validate(&manifest).is_err(),
            "a v0.3 manifest without {field} must not validate"
        );
    }
}

#[test]
fn test_v0_2_manifest_may_not_carry_v0_3_fields() {
    let schema = compile_schema("schemas/airlock.v0.schema.json");

    for (field, value) in [
        ("bytes_crossed", Value::from(632)),
        ("attestation", Value::from("self_attested")),
    ] {
        let mut manifest =
            read_json(&repo_root().join("fixtures/clean_telemetry_only/expected_manifest.json"));
        assert_eq!(manifest["manifest_version"], "airlock.v0.2");
        manifest[field] = value;
        assert!(
            schema.validate(&manifest).is_err(),
            "a v0.2 manifest carrying {field} must not validate"
        );
    }
}

#[test]
fn test_unknown_version_and_bad_v0_3_field_values_fail_schema() {
    let schema = compile_schema("schemas/airlock.v0.schema.json");
    let valid = read_json(&repo_root().join(GOLDEN_V0_3[0]));
    assert!(schema.validate(&valid).is_ok());

    for (field, value) in [
        ("manifest_version", Value::from("airlock.v0.4")),
        ("manifest_version", Value::from("airlock.v0")),
        ("bytes_crossed", Value::from(-1)),
        ("bytes_crossed", Value::from("632")),
        ("attestation", Value::from("trusted")),
    ] {
        let mut manifest = valid.clone();
        manifest[field] = value.clone();
        assert!(
            schema.validate(&manifest).is_err(),
            "{field}={value} must not validate"
        );
    }
}
