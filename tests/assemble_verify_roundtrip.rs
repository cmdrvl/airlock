use std::fs;
use std::path::Path;

use assert_cmd::Command;
use serde_json::{json, Value};
use tempfile::tempdir;

fn write_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
}

fn sample_policy_yaml() -> &'static str {
    r#"policy_id: clean_telemetry_only
version: airlock.v0
allowed_keys:
  - key_path: family_id
    description: Filing family identifier
    boundary_class: TELEMETRY
  - key_path: benchmark_summary
    description: Deterministic benchmark summary
    boundary_class: TELEMETRY
forbidden_keys:
  - html_path
  - section_html
forbidden_patterns:
  - pattern: "<[a-z][^>]*>"
    description: Raw HTML markup
    artifact_class: raw_html
  - pattern: sec\\.gov/Archives
    description: SEC archive URLs
    artifact_class: sec_archive_url
derived_text_paths: []
claim_levels:
  - BOUNDARY_FAILED
  - RAW_DOCUMENT_ABSENT
  - STRICT_TELEMETRY_ONLY
"#
}

#[test]
fn assemble_output_round_trips_through_verify() {
    let dir = tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    let strategy_path = dir.path().join("strategy_space.json");
    let system_prompt_path = dir.path().join("system_prompt.txt");
    let prompt_path = dir.path().join("prompt_payload.json");
    let provenance_path = dir.path().join("prompt_provenance.json");
    let request_path = dir.path().join("request.json");
    let manifest_path = dir.path().join("airlock_manifest.json");
    let witness_path = dir.path().join("witness.jsonl");

    write_file(&policy_path, sample_policy_yaml().as_bytes());
    write_file(
        &strategy_path,
        br#"{"family_id":"bdc_schedule_of_investments","benchmark_summary":{"score":97}}"#,
    );
    write_file(&system_prompt_path, b"You are a careful boundary verifier.");

    Command::cargo_bin("airlock")
        .unwrap()
        .env("EPISTEMIC_WITNESS", &witness_path)
        .args([
            "assemble",
            "--policy",
            policy_path.to_str().unwrap(),
            "--input",
            strategy_path.to_str().unwrap(),
            "--system-prompt",
            system_prompt_path.to_str().unwrap(),
            "--boundary-mode",
            "TELEMETRY_ONLY",
            "--out",
            prompt_path.to_str().unwrap(),
            "--provenance-out",
            provenance_path.to_str().unwrap(),
            "--no-witness",
        ])
        .assert()
        .success();

    let prompt_payload: Value = serde_json::from_slice(&fs::read(&prompt_path).unwrap()).unwrap();
    write_file(
        &request_path,
        serde_json::to_vec(&json!({
            "model": "gpt-5",
            "messages": prompt_payload["messages"].clone(),
        }))
        .unwrap()
        .as_slice(),
    );

    let verify_output = Command::cargo_bin("airlock")
        .unwrap()
        .env("EPISTEMIC_WITNESS", &witness_path)
        .args([
            "verify",
            "--policy",
            policy_path.to_str().unwrap(),
            "--prompt",
            prompt_path.to_str().unwrap(),
            "--provenance",
            provenance_path.to_str().unwrap(),
            "--request",
            request_path.to_str().unwrap(),
            "--out",
            manifest_path.to_str().unwrap(),
            "--no-witness",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let manifest: Value = serde_json::from_slice(&verify_output).unwrap();
    assert_eq!(manifest["achieved_claim"], "STRICT_TELEMETRY_ONLY");
    assert_eq!(manifest["boundary_mode"], "TELEMETRY_ONLY");
    assert_eq!(
        fs::read_to_string(&manifest_path).unwrap(),
        String::from_utf8(verify_output).unwrap()
    );
}
