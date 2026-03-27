use std::fs;
use std::path::{Path, PathBuf};

use airlock::witness::WitnessRecord;
use assert_cmd::Command;
use jsonschema::validator_for;
use serde_json::{json, Value};
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(path: &str) -> PathBuf {
    repo_root().join(path)
}

fn airlock_cmd() -> Command {
    let mut cmd = Command::cargo_bin("airlock").unwrap();
    cmd.current_dir(repo_root());
    cmd
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn read_json_output(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

fn normalized_manifest(mut actual: Value, expected: &Value) -> Value {
    actual["timestamp"] = expected["timestamp"].clone();
    actual
}

fn assert_refusal_code(bytes: &[u8], code: &str) {
    let refusal = read_json_output(bytes);
    assert_eq!(refusal["outcome"], "REFUSAL");
    assert_eq!(refusal["refusal"]["code"], code);
}

fn sample_witness_record(
    command: &str,
    outcome: &str,
    timestamp: &str,
    input_hash: &str,
) -> WitnessRecord {
    WitnessRecord::with_timestamp(
        command,
        outcome,
        if outcome == "VERIFY_PARTIAL" { 1 } else { 0 },
        vec![WitnessRecord::input("policy.yaml", input_hash)],
        json!({"boundary_mode": "ANNOTATED"}),
        "blake3:stdout",
        128,
        timestamp,
    )
}

fn write_witness_ledger(path: &Path, records: &[WitnessRecord]) {
    let contents = records
        .iter()
        .map(|record| record.to_jsonl_line())
        .collect::<String>();
    fs::write(path, contents).unwrap();
}

#[test]
fn test_describe_emits_operator_json() {
    let output = airlock_cmd()
        .arg("--describe")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let describe = read_json_output(&output);

    assert_eq!(describe["name"], "airlock");
    assert_eq!(describe["output_schema"], "airlock.v0.schema.json");
    assert!(describe["subcommands"]["assemble"]["usage"]
        .as_str()
        .unwrap()
        .contains("airlock assemble"));
}

#[test]
fn test_schema_emits_json_schema() {
    let output = airlock_cmd()
        .arg("--schema")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let schema = read_json_output(&output);

    assert_eq!(schema["title"], "airlock manifest schema");
    validator_for(&schema).unwrap();
}

#[test]
fn test_version_emits_semver() {
    let output = airlock_cmd()
        .arg("--version")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(
        String::from_utf8(output).unwrap(),
        format!("airlock {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn test_describe_takes_precedence() {
    let output = airlock_cmd()
        .args(["--describe", "--schema", "verify"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let describe = read_json_output(&output);

    assert_eq!(describe["name"], "airlock");
    assert!(describe.get("$schema").is_none());
}

#[test]
fn test_schema_takes_precedence_over_version() {
    let output = airlock_cmd()
        .args(["--schema", "--version"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let schema = read_json_output(&output);

    assert_eq!(schema["title"], "airlock manifest schema");
}

#[test]
fn test_assemble_clean_telemetry() {
    let dir = tempdir().unwrap();
    let prompt_path = dir.path().join("prompt.json");
    let provenance_path = dir.path().join("provenance.json");

    let output = airlock_cmd()
        .args([
            "assemble",
            "--policy",
            "fixtures/clean_telemetry_only/policy.yaml",
            "--input",
            "fixtures/clean_telemetry_only/strategy_space.json",
            "--system-prompt",
            "fixtures/clean_telemetry_only/system_prompt.txt",
            "--boundary-mode",
            "TELEMETRY_ONLY",
            "--out",
            prompt_path.to_str().unwrap(),
            "--provenance-out",
            provenance_path.to_str().unwrap(),
            "--no-witness",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(output, fs::read(&prompt_path).unwrap());
    assert_eq!(
        fs::read(&prompt_path).unwrap(),
        fs::read(fixture(
            "fixtures/clean_telemetry_only/expected_prompt_payload.json"
        ))
        .unwrap()
    );
    assert_eq!(
        fs::read(&provenance_path).unwrap(),
        fs::read(fixture(
            "fixtures/clean_telemetry_only/expected_prompt_provenance.json"
        ))
        .unwrap()
    );
}

#[test]
fn test_assemble_annotated_mode() {
    let dir = tempdir().unwrap();
    let prompt_path = dir.path().join("prompt.json");
    let provenance_path = dir.path().join("provenance.json");

    let output = airlock_cmd()
        .args([
            "assemble",
            "--policy",
            "fixtures/annotated_mode/policy.yaml",
            "--input",
            "fixtures/annotated_mode/strategy_space.json",
            "--system-prompt",
            "fixtures/annotated_mode/system_prompt.txt",
            "--boundary-mode",
            "ANNOTATED",
            "--out",
            prompt_path.to_str().unwrap(),
            "--provenance-out",
            provenance_path.to_str().unwrap(),
            "--no-witness",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(output, fs::read(&prompt_path).unwrap());
    assert_eq!(
        fs::read(&prompt_path).unwrap(),
        fs::read(fixture(
            "fixtures/annotated_mode/expected_prompt_payload.json"
        ))
        .unwrap()
    );
    assert_eq!(
        fs::read(&provenance_path).unwrap(),
        fs::read(fixture(
            "fixtures/annotated_mode/expected_prompt_provenance.json"
        ))
        .unwrap()
    );
}

#[test]
fn test_assemble_telemetry_only_strips_derived() {
    let dir = tempdir().unwrap();
    let prompt_path = dir.path().join("prompt.json");
    let provenance_path = dir.path().join("provenance.json");

    airlock_cmd()
        .args([
            "assemble",
            "--policy",
            "fixtures/annotated_mode/policy.yaml",
            "--input",
            "fixtures/annotated_mode/strategy_space.json",
            "--system-prompt",
            "fixtures/annotated_mode/system_prompt.txt",
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

    let prompt = read_json(&prompt_path);
    let provenance = read_json(&provenance_path);
    assert!(prompt["messages"][1]["content"]
        .as_object()
        .unwrap()
        .get("mutator_context")
        .is_none());
    assert_eq!(provenance["boundary_mode"], "TELEMETRY_ONLY");
    assert!(provenance["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|record| record["boundary_class"] != "DERIVED_TEXT"));
}

#[test]
fn test_assemble_missing_policy() {
    let dir = tempdir().unwrap();
    let output = airlock_cmd()
        .args([
            "assemble",
            "--policy",
            dir.path().join("missing.yaml").to_str().unwrap(),
            "--input",
            "fixtures/clean_telemetry_only/strategy_space.json",
            "--system-prompt",
            "fixtures/clean_telemetry_only/system_prompt.txt",
            "--out",
            dir.path().join("prompt.json").to_str().unwrap(),
            "--provenance-out",
            dir.path().join("provenance.json").to_str().unwrap(),
            "--no-witness",
        ])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    assert_refusal_code(&output, "E_BAD_POLICY");
}

#[test]
fn test_assemble_missing_input() {
    let dir = tempdir().unwrap();
    let output = airlock_cmd()
        .args([
            "assemble",
            "--policy",
            "fixtures/clean_telemetry_only/policy.yaml",
            "--input",
            dir.path().join("missing.json").to_str().unwrap(),
            "--system-prompt",
            "fixtures/clean_telemetry_only/system_prompt.txt",
            "--out",
            dir.path().join("prompt.json").to_str().unwrap(),
            "--provenance-out",
            dir.path().join("provenance.json").to_str().unwrap(),
            "--no-witness",
        ])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    assert_refusal_code(&output, "E_MISSING_FILE");
}

#[test]
fn test_assemble_multiple_inputs() {
    let dir = tempdir().unwrap();
    let input_a = dir.path().join("a.json");
    let input_b = dir.path().join("b.json");
    let prompt_path = dir.path().join("prompt.json");
    let provenance_path = dir.path().join("provenance.json");

    fs::write(
        &input_a,
        r#"{"family_id":"bdc_schedule_of_investments","benchmark_summary":{"score":97}}"#,
    )
    .unwrap();
    fs::write(
        &input_b,
        r#"{"allowed_toggles":["layout_retry"],"current_strategy":"table_merge_v2","max_proposals":3}"#,
    )
    .unwrap();

    airlock_cmd()
        .args([
            "assemble",
            "--policy",
            "fixtures/clean_telemetry_only/policy.yaml",
            "--input",
            input_a.to_str().unwrap(),
            "--input",
            input_b.to_str().unwrap(),
            "--system-prompt",
            "fixtures/clean_telemetry_only/system_prompt.txt",
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

    let prompt = read_json(&prompt_path);
    assert_eq!(
        prompt["messages"][1]["content"]["family_id"],
        json!("bdc_schedule_of_investments")
    );
    assert_eq!(
        prompt["messages"][1]["content"]["allowed_toggles"][0],
        json!("layout_retry")
    );
    assert_eq!(
        prompt["messages"][1]["content"]["current_strategy"],
        json!("table_merge_v2")
    );
    assert_eq!(prompt["messages"][1]["content"]["max_proposals"], json!(3));
}

#[test]
fn test_verify_strict_telemetry() {
    let dir = tempdir().unwrap();
    let manifest_path = dir.path().join("manifest.json");
    let output = airlock_cmd()
        .args([
            "verify",
            "--policy",
            "fixtures/clean_telemetry_only/policy.yaml",
            "--prompt",
            "fixtures/clean_telemetry_only/expected_prompt_payload.json",
            "--provenance",
            "fixtures/clean_telemetry_only/expected_prompt_provenance.json",
            "--request",
            "fixtures/clean_telemetry_only/request.json",
            "--out",
            manifest_path.to_str().unwrap(),
            "--no-witness",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let actual = read_json_output(&output);
    let expected = read_json(&fixture(
        "fixtures/clean_telemetry_only/expected_manifest.json",
    ));
    assert_eq!(actual["achieved_claim"], "STRICT_TELEMETRY_ONLY");
    assert_eq!(actual["boundary_mode"], "TELEMETRY_ONLY");
    assert_eq!(normalized_manifest(actual, &expected), expected);
    assert_eq!(
        normalized_manifest(read_json(&manifest_path), &expected),
        expected
    );
}

#[test]
fn test_verify_annotated() {
    let dir = tempdir().unwrap();
    let manifest_path = dir.path().join("manifest.json");
    let output = airlock_cmd()
        .args([
            "verify",
            "--policy",
            "fixtures/annotated_mode/policy.yaml",
            "--prompt",
            "fixtures/annotated_mode/expected_prompt_payload.json",
            "--provenance",
            "fixtures/annotated_mode/expected_prompt_provenance.json",
            "--request",
            "fixtures/annotated_mode/request.json",
            "--out",
            manifest_path.to_str().unwrap(),
            "--no-witness",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let actual = read_json_output(&output);
    let expected = read_json(&fixture("fixtures/annotated_mode/expected_manifest.json"));
    assert_eq!(actual["achieved_claim"], "RAW_DOCUMENT_ABSENT");
    assert_eq!(actual["boundary_mode"], "ANNOTATED");
    assert_eq!(normalized_manifest(actual, &expected), expected);
}

#[test]
fn test_verify_boundary_failed() {
    let dir = tempdir().unwrap();
    let manifest_path = dir.path().join("manifest.json");
    let output = airlock_cmd()
        .args([
            "verify",
            "--policy",
            "fixtures/boundary_failed/policy.yaml",
            "--prompt",
            "fixtures/boundary_failed/prompt_payload.json",
            "--provenance",
            "fixtures/boundary_failed/prompt_provenance.json",
            "--request",
            "fixtures/boundary_failed/request.json",
            "--out",
            manifest_path.to_str().unwrap(),
            "--no-witness",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let actual = read_json_output(&output);
    let expected = read_json(&fixture("fixtures/boundary_failed/expected_manifest.json"));
    assert_eq!(actual["achieved_claim"], "BOUNDARY_FAILED");
    assert_eq!(normalized_manifest(actual, &expected), expected);
    assert!(read_json(&manifest_path)["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["artifact_class"] == "sec_archive_url"));
}

#[test]
fn test_verify_require_claim_met() {
    let dir = tempdir().unwrap();
    let manifest_path = dir.path().join("manifest.json");

    airlock_cmd()
        .args([
            "verify",
            "--policy",
            "fixtures/annotated_mode/policy.yaml",
            "--prompt",
            "fixtures/annotated_mode/expected_prompt_payload.json",
            "--provenance",
            "fixtures/annotated_mode/expected_prompt_provenance.json",
            "--request",
            "fixtures/annotated_mode/request.json",
            "--out",
            manifest_path.to_str().unwrap(),
            "--require-claim",
            "RAW_DOCUMENT_ABSENT",
            "--no-witness",
        ])
        .assert()
        .success();
}

#[test]
fn test_verify_require_claim_not_met() {
    let dir = tempdir().unwrap();
    let manifest_path = dir.path().join("manifest.json");
    let output = airlock_cmd()
        .args([
            "verify",
            "--policy",
            "fixtures/annotated_mode/policy.yaml",
            "--prompt",
            "fixtures/annotated_mode/expected_prompt_payload.json",
            "--provenance",
            "fixtures/annotated_mode/expected_prompt_provenance.json",
            "--request",
            "fixtures/annotated_mode/request.json",
            "--out",
            manifest_path.to_str().unwrap(),
            "--require-claim",
            "STRICT_TELEMETRY_ONLY",
            "--no-witness",
        ])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let manifest = read_json_output(&output);
    assert_eq!(manifest["achieved_claim"], "RAW_DOCUMENT_ABSENT");
    assert!(manifest_path.exists());
}

#[test]
fn test_verify_always_emits_manifest() {
    let dir = tempdir().unwrap();
    let manifest_path = dir.path().join("manifest.json");

    airlock_cmd()
        .args([
            "verify",
            "--policy",
            "fixtures/boundary_failed/policy.yaml",
            "--prompt",
            "fixtures/boundary_failed/prompt_payload.json",
            "--provenance",
            "fixtures/boundary_failed/prompt_provenance.json",
            "--request",
            "fixtures/boundary_failed/request.json",
            "--out",
            manifest_path.to_str().unwrap(),
            "--no-witness",
        ])
        .assert()
        .success();

    assert!(manifest_path.exists());
}

#[test]
fn test_explain_strict_telemetry() {
    let output = airlock_cmd()
        .args([
            "explain",
            "--manifest",
            "fixtures/clean_telemetry_only/expected_manifest.json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).unwrap();

    assert!(rendered.contains("Claim achieved: STRICT_TELEMETRY_ONLY"));
    assert!(!rendered.contains("Why strict telemetry-only was not earned:"));
}

#[test]
fn test_explain_annotated() {
    let output = airlock_cmd()
        .args([
            "explain",
            "--manifest",
            "fixtures/annotated_mode/expected_manifest.json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).unwrap();

    assert!(rendered.contains("Claim achieved: RAW_DOCUMENT_ABSENT"));
    assert!(rendered.contains("Why strict telemetry-only was not earned:"));
    assert!(rendered.contains("messages[1].content.mutator_context.challenge_observation"));
}

#[test]
fn test_explain_boundary_failed() {
    let output = airlock_cmd()
        .args([
            "explain",
            "--manifest",
            "fixtures/boundary_failed/expected_manifest.json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).unwrap();

    assert!(rendered.contains("Claim achieved: BOUNDARY_FAILED"));
    assert!(rendered.contains("Boundary violation detected:"));
    assert!(rendered.contains("sec_archive_url"));
}

#[test]
fn test_explain_missing_manifest() {
    let dir = tempdir().unwrap();
    let output = airlock_cmd()
        .args([
            "explain",
            "--manifest",
            dir.path().join("missing.json").to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    assert_refusal_code(&output, "E_MISSING_FILE");
}

#[test]
fn test_witness_append_on_assemble() {
    let dir = tempdir().unwrap();
    let ledger_path = dir.path().join("witness.jsonl");
    let prompt_path = dir.path().join("prompt.json");
    let provenance_path = dir.path().join("provenance.json");

    airlock_cmd()
        .env("EPISTEMIC_WITNESS", &ledger_path)
        .args([
            "assemble",
            "--policy",
            "fixtures/clean_telemetry_only/policy.yaml",
            "--input",
            "fixtures/clean_telemetry_only/strategy_space.json",
            "--system-prompt",
            "fixtures/clean_telemetry_only/system_prompt.txt",
            "--boundary-mode",
            "TELEMETRY_ONLY",
            "--out",
            prompt_path.to_str().unwrap(),
            "--provenance-out",
            provenance_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let line = fs::read_to_string(&ledger_path).unwrap();
    let record = read_json_output(line.trim_end().as_bytes());
    assert_eq!(record["command"], "assemble");
    assert_eq!(record["outcome"], "ASSEMBLED");
}

#[test]
fn test_witness_append_on_verify() {
    let dir = tempdir().unwrap();
    let ledger_path = dir.path().join("witness.jsonl");
    let manifest_path = dir.path().join("manifest.json");

    airlock_cmd()
        .env("EPISTEMIC_WITNESS", &ledger_path)
        .args([
            "verify",
            "--policy",
            "fixtures/clean_telemetry_only/policy.yaml",
            "--prompt",
            "fixtures/clean_telemetry_only/expected_prompt_payload.json",
            "--provenance",
            "fixtures/clean_telemetry_only/expected_prompt_provenance.json",
            "--request",
            "fixtures/clean_telemetry_only/request.json",
            "--out",
            manifest_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let line = fs::read_to_string(&ledger_path).unwrap();
    let record = read_json_output(line.trim_end().as_bytes());
    assert_eq!(record["command"], "verify");
    assert_eq!(record["outcome"], "VERIFIED");
}

#[test]
fn test_witness_no_witness_flag() {
    let dir = tempdir().unwrap();
    let ledger_path = dir.path().join("witness.jsonl");
    let prompt_path = dir.path().join("prompt.json");
    let provenance_path = dir.path().join("provenance.json");

    airlock_cmd()
        .env("EPISTEMIC_WITNESS", &ledger_path)
        .args([
            "assemble",
            "--policy",
            "fixtures/clean_telemetry_only/policy.yaml",
            "--input",
            "fixtures/clean_telemetry_only/strategy_space.json",
            "--system-prompt",
            "fixtures/clean_telemetry_only/system_prompt.txt",
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

    assert!(!ledger_path.exists());
}

#[test]
fn test_witness_query_filters() {
    let dir = tempdir().unwrap();
    let ledger_path = dir.path().join("witness.jsonl");
    write_witness_ledger(
        &ledger_path,
        &[
            sample_witness_record(
                "verify",
                "VERIFIED",
                "2024-01-15T10:30:00Z",
                "blake3:aaa111",
            ),
            sample_witness_record(
                "verify",
                "VERIFY_PARTIAL",
                "2024-01-16T10:30:00Z",
                "blake3:bbb222",
            ),
            sample_witness_record(
                "assemble",
                "ASSEMBLED",
                "2024-01-17T10:30:00Z",
                "blake3:ccc333",
            ),
        ],
    );

    let output = airlock_cmd()
        .env("EPISTEMIC_WITNESS", &ledger_path)
        .args([
            "witness",
            "query",
            "--since",
            "2024-01-16T00:00:00Z",
            "--until",
            "2024-01-16T23:59:59Z",
            "--outcome",
            "VERIFY_PARTIAL",
            "--input-hash",
            "bbb",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value = read_json_output(&output);
    assert_eq!(value.as_array().unwrap().len(), 1);
    assert_eq!(value[0]["outcome"], "VERIFY_PARTIAL");
}

#[test]
fn test_witness_last() {
    let dir = tempdir().unwrap();
    let ledger_path = dir.path().join("witness.jsonl");
    write_witness_ledger(
        &ledger_path,
        &[
            sample_witness_record(
                "assemble",
                "ASSEMBLED",
                "2024-01-15T10:29:00Z",
                "blake3:aaa111",
            ),
            sample_witness_record(
                "verify",
                "VERIFIED",
                "2024-01-15T10:30:00Z",
                "blake3:bbb222",
            ),
        ],
    );

    let output = airlock_cmd()
        .env("EPISTEMIC_WITNESS", &ledger_path)
        .args(["witness", "last", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value = read_json_output(&output);
    assert_eq!(value["command"], "verify");
    assert_eq!(value["outcome"], "VERIFIED");
}

#[test]
fn test_witness_count() {
    let dir = tempdir().unwrap();
    let ledger_path = dir.path().join("witness.jsonl");
    write_witness_ledger(
        &ledger_path,
        &[
            sample_witness_record(
                "assemble",
                "ASSEMBLED",
                "2024-01-15T10:29:00Z",
                "blake3:aaa111",
            ),
            sample_witness_record(
                "verify",
                "VERIFIED",
                "2024-01-15T10:30:00Z",
                "blake3:bbb222",
            ),
        ],
    );

    let output = airlock_cmd()
        .env("EPISTEMIC_WITNESS", &ledger_path)
        .args(["witness", "count", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value = read_json_output(&output);
    assert_eq!(value["count"], 2);
}

#[test]
fn test_witness_append_failure_preserves_exit() {
    let dir = tempdir().unwrap();
    let manifest_path = dir.path().join("manifest.json");
    let assert = airlock_cmd()
        .env("EPISTEMIC_WITNESS", dir.path())
        .args([
            "verify",
            "--policy",
            "fixtures/annotated_mode/policy.yaml",
            "--prompt",
            "fixtures/annotated_mode/expected_prompt_payload.json",
            "--provenance",
            "fixtures/annotated_mode/expected_prompt_provenance.json",
            "--request",
            "fixtures/annotated_mode/request.json",
            "--out",
            manifest_path.to_str().unwrap(),
            "--require-claim",
            "STRICT_TELEMETRY_ONLY",
        ])
        .assert();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert.code(1);
    assert!(stderr.contains("witness append failed"));
    assert!(manifest_path.exists());
}
