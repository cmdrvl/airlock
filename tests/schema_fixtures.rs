use std::path::{Path, PathBuf};

use jsonschema::validator_for;
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn all_exist(paths: &[PathBuf]) -> bool {
    paths.iter().all(|path| path.exists())
}

fn load_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn load_yaml_as_json(path: &Path) -> Value {
    serde_yaml::from_slice::<Value>(&std::fs::read(path).unwrap()).unwrap()
}

fn compile_schema(path: &Path) -> jsonschema::Validator {
    let schema = load_json(path);
    validator_for(&schema).unwrap()
}

fn skip_until_present(paths: &[PathBuf]) -> bool {
    if all_exist(paths) {
        true
    } else {
        if let Some(missing) = paths.iter().find(|path| !path.exists()) {
            eprintln!(
                "skipping schema fixture validation until {} exists",
                missing.display()
            );
        }
        false
    }
}

#[test]
fn schema_files_are_valid_when_present() {
    let root = repo_root();
    let schema_paths = vec![
        root.join("schemas/airlock.v0.schema.json"),
        root.join("schemas/airlock_policy.schema.json"),
        root.join("schemas/prompt_provenance.schema.json"),
        root.join("schemas/refusal.schema.json"),
    ];

    if !skip_until_present(&schema_paths) {
        return;
    }

    for path in &schema_paths {
        compile_schema(path);
    }
}

#[test]
fn clean_telemetry_only_fixture_set_validates_when_present() {
    let root = repo_root();
    let paths = vec![
        root.join("schemas/airlock_policy.schema.json"),
        root.join("schemas/prompt_provenance.schema.json"),
        root.join("schemas/airlock.v0.schema.json"),
        root.join("fixtures/clean_telemetry_only/policy.yaml"),
        root.join("fixtures/clean_telemetry_only/expected_prompt_provenance.json"),
        root.join("fixtures/clean_telemetry_only/expected_manifest.json"),
    ];

    if !skip_until_present(&paths) {
        return;
    }

    let policy_schema = compile_schema(&root.join("schemas/airlock_policy.schema.json"));
    let provenance_schema = compile_schema(&root.join("schemas/prompt_provenance.schema.json"));
    let manifest_schema = compile_schema(&root.join("schemas/airlock.v0.schema.json"));

    policy_schema
        .validate(&load_yaml_as_json(
            &root.join("fixtures/clean_telemetry_only/policy.yaml"),
        ))
        .unwrap();
    provenance_schema
        .validate(&load_json(&root.join(
            "fixtures/clean_telemetry_only/expected_prompt_provenance.json",
        )))
        .unwrap();
    manifest_schema
        .validate(&load_json(
            &root.join("fixtures/clean_telemetry_only/expected_manifest.json"),
        ))
        .unwrap();
}

#[test]
fn annotated_mode_fixture_set_validates_when_present() {
    let root = repo_root();
    let paths = vec![
        root.join("schemas/airlock_policy.schema.json"),
        root.join("schemas/prompt_provenance.schema.json"),
        root.join("schemas/airlock.v0.schema.json"),
        root.join("fixtures/annotated_mode/policy.yaml"),
        root.join("fixtures/annotated_mode/expected_prompt_provenance.json"),
        root.join("fixtures/annotated_mode/expected_manifest.json"),
    ];

    if !skip_until_present(&paths) {
        return;
    }

    let policy_schema = compile_schema(&root.join("schemas/airlock_policy.schema.json"));
    let provenance_schema = compile_schema(&root.join("schemas/prompt_provenance.schema.json"));
    let manifest_schema = compile_schema(&root.join("schemas/airlock.v0.schema.json"));

    policy_schema
        .validate(&load_yaml_as_json(
            &root.join("fixtures/annotated_mode/policy.yaml"),
        ))
        .unwrap();
    provenance_schema
        .validate(&load_json(
            &root.join("fixtures/annotated_mode/expected_prompt_provenance.json"),
        ))
        .unwrap();
    manifest_schema
        .validate(&load_json(
            &root.join("fixtures/annotated_mode/expected_manifest.json"),
        ))
        .unwrap();
}

#[test]
fn boundary_failed_fixture_set_validates_when_present() {
    let root = repo_root();
    let paths = vec![
        root.join("schemas/airlock_policy.schema.json"),
        root.join("schemas/airlock.v0.schema.json"),
        root.join("fixtures/boundary_failed/policy.yaml"),
        root.join("fixtures/boundary_failed/expected_manifest.json"),
    ];

    if !skip_until_present(&paths) {
        return;
    }

    let policy_schema = compile_schema(&root.join("schemas/airlock_policy.schema.json"));
    let manifest_schema = compile_schema(&root.join("schemas/airlock.v0.schema.json"));

    policy_schema
        .validate(&load_yaml_as_json(
            &root.join("fixtures/boundary_failed/policy.yaml"),
        ))
        .unwrap();
    manifest_schema
        .validate(&load_json(
            &root.join("fixtures/boundary_failed/expected_manifest.json"),
        ))
        .unwrap();
}

#[test]
fn refusal_fixture_set_validates_when_present() {
    let root = repo_root();
    let paths = vec![
        root.join("schemas/refusal.schema.json"),
        root.join("schemas/airlock_policy.schema.json"),
        root.join("fixtures/refusal/missing_fields_policy.yaml"),
        root.join("fixtures/refusal/expected_refusal_bad_policy.json"),
        root.join("rules/tournament_baseline.yaml"),
    ];

    if !skip_until_present(&paths) {
        return;
    }

    let refusal_schema = compile_schema(&root.join("schemas/refusal.schema.json"));
    let policy_schema = compile_schema(&root.join("schemas/airlock_policy.schema.json"));

    refusal_schema
        .validate(&load_json(
            &root.join("fixtures/refusal/expected_refusal_bad_policy.json"),
        ))
        .unwrap();
    policy_schema
        .validate(&load_yaml_as_json(
            &root.join("rules/tournament_baseline.yaml"),
        ))
        .unwrap();

    let missing_fields_policy =
        load_yaml_as_json(&root.join("fixtures/refusal/missing_fields_policy.yaml"));
    assert!(policy_schema.validate(&missing_fields_policy).is_err());
}
