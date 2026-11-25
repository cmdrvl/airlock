use std::fs;
use std::path::{Path, PathBuf};

use airlock::witness::WitnessRecord;
use assert_cmd::Command;
use jsonschema::validator_for;
use serde_json::{Value, json};
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

fn airlock_cmd_in(dir: &Path, witness_path: &Path) -> Command {
    let mut cmd = Command::cargo_bin("airlock").unwrap();
    cmd.current_dir(dir);
    cmd.env("EPISTEMIC_WITNESS", witness_path);
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

fn assert_doctor_side_effects_absent(dir: &Path, witness_path: &Path) {
    assert!(!witness_path.exists());
    if let Some(parent) = witness_path.parent() {
        assert!(!parent.exists());
    }
    assert!(!dir.join(".doctor").exists());
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

    assert_eq!(describe["schema_version"], "operator.v1");
    assert_eq!(describe["name"], "airlock");
    assert_eq!(describe["tool_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        describe["invocation"]["output_schema"],
        "airlock.v0.schema.json"
    );
    // Legacy operator.v0 spellings must be gone.
    assert!(describe.get("version").is_none());
    assert!(describe.get("subcommands").is_none());
    assert!(describe.get("pipeline_position").is_none());

    let names: Vec<&str> = describe["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|command| command["name"].as_str().unwrap())
        .collect();
    for required in [
        "assemble",
        "verify",
        "explain",
        "witness",
        "capabilities",
        "robot-docs",
        "doctor",
    ] {
        assert!(names.contains(&required), "missing command {required}");
    }
    assert!(
        describe["invocation"]["usage"]
            .as_array()
            .unwrap()
            .iter()
            .any(|usage| usage.as_str().unwrap().contains("airlock assemble"))
    );
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
fn test_bare_invocation_prints_agent_entrypoints() {
    let output = airlock_cmd().assert().success().get_output().stdout.clone();

    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.contains("Usage: airlock"));
    assert!(stdout.contains("airlock doctor triage --json"));
    assert!(stdout.contains("airlock capabilities --json"));
    assert!(stdout.contains("airlock robot-docs guide"));
}

#[test]
fn test_top_level_robot_triage_alias_is_the_triage_report() {
    let alias = airlock_cmd()
        .arg("--robot-triage")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let canonical = airlock_cmd()
        .args(["doctor", "triage", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(alias, canonical);
    let value = read_json_output(&alias);
    assert_eq!(value["schema_version"], "cmdrvl.doctor.v1");
    assert_eq!(value["mode"], "triage");
    assert_eq!(value["healthy"], true);
    assert_eq!(
        value["summary"]["capabilities"],
        "airlock capabilities --json"
    );
    assert_eq!(value["side_effects"]["reads_manifest_files"], false);
}

#[test]
fn test_top_level_capabilities_json_is_the_describe_contract() {
    let capabilities = airlock_cmd()
        .args(["capabilities", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let describe = airlock_cmd()
        .arg("--describe")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(capabilities, describe);
    let value = read_json_output(&capabilities);
    assert_eq!(value["schema_version"], "operator.v1");
    assert!(
        value["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|command| command["name"] == "explain")
    );
    assert_eq!(value["exit_codes"]["0"]["domain"], "positive");
    assert_eq!(value["exit_codes"]["1"]["domain"], "negative");
    assert_eq!(value["exit_codes"]["2"]["domain"], "error");
    let refusals: Vec<&str> = value["refusals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|refusal| refusal["code"].as_str().unwrap())
        .collect();
    assert_eq!(refusals.len(), 9);
    assert!(refusals.iter().all(|code| code.starts_with("E_")));
}

#[test]
fn test_capabilities_without_json_is_human_text() {
    let output = airlock_cmd()
        .arg("capabilities")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.starts_with("airlock capabilities"));
    assert!(serde_json::from_str::<Value>(&stdout).is_err());
}

#[test]
fn test_top_level_robot_docs_guide_alias() {
    let output = airlock_cmd()
        .args(["robot-docs", "guide"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.contains("airlock doctor robot docs"));
    assert!(stdout.contains("airlock --robot-triage"));
    assert!(stdout.contains("airlock explain --manifest <MANIFEST> --json"));
    assert!(stdout.contains("Composition:"));
    assert!(stdout.contains("airlock assemble --policy <POLICY>"));
    assert!(stdout.contains("pack seal airlock_manifest.json prompt_provenance.json"));
}

#[test]
fn test_json_typo_has_agent_hint() {
    let output = airlock_cmd()
        .arg("--jsno")
        .assert()
        .code(2)
        .get_output()
        .stderr
        .clone();

    let stderr = String::from_utf8(output).unwrap();
    assert!(stderr.contains("did you mean `--json`"));
    assert!(stderr.contains("airlock doctor triage --json"));
}

#[test]
fn test_doctor_health_json_is_read_only() {
    let dir = tempdir().unwrap();
    let witness_path = dir.path().join("witness").join("ledger.jsonl");

    let output = airlock_cmd_in(dir.path(), &witness_path)
        .args(["doctor", "health", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_doctor_side_effects_absent(dir.path(), &witness_path);
    let payload = read_json_output(&output);
    assert_eq!(payload["schema_version"], "cmdrvl.doctor.v1");
    assert_eq!(payload["mode"], "health");
    assert_eq!(payload["tool"], "airlock");
    assert_eq!(payload["tool_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(payload["healthy"], true);
    assert!(
        payload["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["severity"] == "info")
    );
    // Additive pre-v1 detail fields stay.
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["read_only"], true);
    assert_eq!(payload["read_only_contract"], "cmdrvl.read_only_doctor.v1");
    assert!(payload["contract"].is_null());
    assert_eq!(payload["witness"]["opened"], false);
    assert_eq!(payload["witness"]["appended"], false);
    assert_eq!(payload["witness"]["directory_created"], false);
    assert_eq!(
        payload["config_footprint"]["managed_state_paths"][0],
        "~/.cmdrvl/state/witness/witness.jsonl"
    );
    assert_eq!(
        payload["config_footprint"]["legacy_migration_required"],
        true
    );
    assert_eq!(payload["side_effects"]["appends_witness_ledger"], false);
    assert_eq!(payload["side_effects"]["writes_migration_logs"], false);
    assert_eq!(payload["side_effects"]["writes_deprecation_notices"], false);
}

#[test]
fn test_doctor_capabilities_json_has_no_fixers_or_side_effects() {
    let dir = tempdir().unwrap();
    let witness_path = dir.path().join("witness").join("ledger.jsonl");

    let output = airlock_cmd_in(dir.path(), &witness_path)
        .args(["doctor", "capabilities", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_doctor_side_effects_absent(dir.path(), &witness_path);
    let payload = read_json_output(&output);
    assert_eq!(payload["schema_version"], "cmdrvl.doctor.v1");
    assert_eq!(payload["mode"], "capabilities");
    assert_eq!(payload["healthy"], true);
    assert_eq!(payload["fixers"].as_array().map(Vec::len), Some(0));
    assert_eq!(payload["config_footprint"]["self_contained"], true);

    let side_effects = payload["side_effects"].as_object().unwrap();
    assert!(
        side_effects
            .values()
            .all(|enabled| enabled.as_bool() == Some(false))
    );

    // `contract` is exactly the `capabilities --json` document.
    let capabilities = airlock_cmd_in(dir.path(), &witness_path)
        .args(["capabilities", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(payload["contract"], read_json_output(&capabilities));

    assert_eq!(
        payload["agent_entrypoints"]["robot_docs"],
        "airlock robot-docs guide"
    );
    assert_eq!(
        payload["agent_entrypoints"]["triage_json"],
        "airlock doctor triage --json"
    );
    assert_eq!(
        payload["composition"]["family"]["name"],
        "cmdrvl-boundary-attestation"
    );
    assert_eq!(
        payload["composition"]["role"],
        "boundary attestation primitive between deterministic evidence and model execution"
    );
    assert!(
        payload["composition"]["canonical_chain"][0]
            .as_str()
            .is_some_and(|command| command.contains("airlock assemble --policy <POLICY>"))
    );
    assert!(
        payload["composition"]["canonical_chain"][2]
            .as_str()
            .is_some_and(|command| command.contains("pack seal airlock_manifest.json"))
    );
    assert_doctor_side_effects_absent(dir.path(), &witness_path);
}

#[test]
fn test_doctor_health_alias_matches_doctor_json() {
    let dir = tempdir().unwrap();
    let witness_path = dir.path().join("witness").join("ledger.jsonl");

    let canonical = airlock_cmd_in(dir.path(), &witness_path)
        .args(["doctor", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let alias = airlock_cmd_in(dir.path(), &witness_path)
        .args(["doctor", "health", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(canonical, alias);
    assert_eq!(read_json_output(&canonical)["mode"], "health");
    assert_doctor_side_effects_absent(dir.path(), &witness_path);
}

#[test]
fn test_doctor_robot_triage_json_is_machine_readable() {
    let dir = tempdir().unwrap();
    let witness_path = dir.path().join("witness").join("ledger.jsonl");

    let output = airlock_cmd_in(dir.path(), &witness_path)
        .args(["doctor", "triage", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let alias = airlock_cmd_in(dir.path(), &witness_path)
        .args(["doctor", "--robot-triage"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_doctor_side_effects_absent(dir.path(), &witness_path);
    assert_eq!(output, alias);
    let payload = read_json_output(&output);
    assert_eq!(payload["schema_version"], "cmdrvl.doctor.v1");
    assert_eq!(payload["mode"], "triage");
    assert_eq!(payload["healthy"], true);
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["summary"]["failed_checks"], 0);
    assert_eq!(payload["next_actions"].as_array().map(Vec::len), Some(0));
    assert!(
        payload["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["severity"] == "info")
    );
    assert_eq!(
        payload["config_footprint"]["deprecation_notices"],
        "~/.cmdrvl/notices/deprecated-paths.jsonl"
    );
}

#[test]
fn test_doctor_triage_without_json_is_human_text() {
    let output = airlock_cmd()
        .args(["doctor", "triage"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.starts_with("airlock doctor triage: healthy"));
    assert!(serde_json::from_str::<Value>(&stdout).is_err());
}

#[test]
fn test_doctor_robot_docs_is_plain_text_and_read_only() {
    let dir = tempdir().unwrap();
    let witness_path = dir.path().join("witness").join("ledger.jsonl");

    let output = airlock_cmd_in(dir.path(), &witness_path)
        .args(["doctor", "robot-docs"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_doctor_side_effects_absent(dir.path(), &witness_path);
    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.contains("airlock doctor robot docs"));
    assert!(stdout.contains("airlock doctor health [--json]"));
    assert!(stdout.contains("~/.cmdrvl/state/witness/witness.jsonl"));
    assert!(stdout.contains("No `doctor --fix` mode exists"));
}

#[test]
fn test_doctor_help_is_available() {
    let output = airlock_cmd()
        .args(["doctor", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.contains("health"));
    assert!(stdout.contains("capabilities"));
    assert!(stdout.contains("triage"));
    assert!(stdout.contains("robot-docs"));
}

#[test]
fn test_doctor_fix_is_not_available() {
    let dir = tempdir().unwrap();
    let witness_path = dir.path().join("witness").join("ledger.jsonl");

    let output = airlock_cmd_in(dir.path(), &witness_path)
        .args(["doctor", "--fix"])
        .assert()
        .code(2)
        .get_output()
        .clone();

    assert!(output.stdout.is_empty());
    assert_doctor_side_effects_absent(dir.path(), &witness_path);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--fix"));
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
    assert!(
        prompt["messages"][1]["content"]
            .as_object()
            .unwrap()
            .get("mutator_context")
            .is_none()
    );
    assert_eq!(provenance["boundary_mode"], "TELEMETRY_ONLY");
    assert!(
        provenance["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record["boundary_class"] != "DERIVED_TEXT")
    );
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
    assert!(
        read_json(&manifest_path)["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["artifact_class"] == "sec_archive_url")
    );
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
fn test_explain_json_output() {
    let output = airlock_cmd()
        .args([
            "explain",
            "--manifest",
            "fixtures/annotated_mode/expected_manifest.json",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value = read_json_output(&output);

    assert_eq!(value["schema"], "airlock.explain.v1");
    assert_eq!(value["claim"]["achieved"], "RAW_DOCUMENT_ABSENT");
    assert_eq!(value["proof"]["policy_id"], "annotated_mode");
    assert!(
        value["blocked_paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|path| path == "messages[1].content.mutator_context.challenge_observation")
    );
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
fn test_witness_bad_timestamp_names_corrected_command() {
    let output = airlock_cmd()
        .args(["witness", "query", "--since", "yesterday", "--json"])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    let refusal = read_json_output(&output);
    assert_eq!(refusal["refusal"]["code"], "E_BAD_INPUT");
    assert_eq!(
        refusal["refusal"]["next_command"],
        "airlock witness query --since 2026-01-15T00:00:00Z --json"
    );
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

const FIXED_EPOCH: &str = "1700000000";

fn assemble_with_out_flag(out_flag: &str, dir: &Path, label: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let prompt_path = dir.join(format!("{label}-prompt.json"));
    let provenance_path = dir.join(format!("{label}-provenance.json"));
    let stdout = airlock_cmd()
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
            out_flag,
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
    (
        stdout,
        fs::read(prompt_path).unwrap(),
        fs::read(provenance_path).unwrap(),
    )
}

#[test]
fn test_assemble_output_alias_matches_out() {
    let dir = tempdir().unwrap();

    let canonical = assemble_with_out_flag("--out", dir.path(), "canonical");
    let alias = assemble_with_out_flag("--output", dir.path(), "alias");

    assert_eq!(canonical, alias);
    assert_eq!(
        alias.1,
        fs::read(fixture(
            "fixtures/clean_telemetry_only/expected_prompt_payload.json"
        ))
        .unwrap()
    );
}

#[test]
fn test_verify_output_alias_matches_out() {
    let dir = tempdir().unwrap();
    let run = |out_flag: &str, label: &str| {
        let manifest_path = dir.path().join(format!("{label}.json"));
        let stdout = airlock_cmd()
            .env("SOURCE_DATE_EPOCH", FIXED_EPOCH)
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
                out_flag,
                manifest_path.to_str().unwrap(),
                "--no-witness",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        (stdout, fs::read(manifest_path).unwrap())
    };

    assert_eq!(run("--out", "canonical"), run("--output", "alias"));
}

#[test]
fn test_help_documents_the_output_alias() {
    for command in ["assemble", "verify"] {
        let output = airlock_cmd()
            .args([command, "--help"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let help = String::from_utf8(output).unwrap();
        assert!(help.contains("--out"), "{command} help lists --out");
        assert!(help.contains("--output"), "{command} help lists --output");
    }
}

#[test]
fn test_operator_json_declares_output_only_as_an_alias_of_out() {
    let describe = read_json_output(
        &airlock_cmd()
            .arg("--describe")
            .assert()
            .success()
            .get_output()
            .stdout,
    );

    let mut out_options = 0;
    for command in describe["commands"].as_array().unwrap() {
        for option in command["options"].as_array().into_iter().flatten() {
            let flag = option["flag"].as_str().unwrap();
            let aliases: Vec<&str> = option["aliases"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|alias| alias.as_str().unwrap())
                .collect();
            assert_ne!(flag, "--output", "--output must not be a primary flag");
            if flag == "--out" {
                out_options += 1;
                assert!(
                    aliases.contains(&"--output"),
                    "{} --out must declare --output as an alias",
                    command["name"]
                );
            } else {
                assert!(
                    !aliases.contains(&"--output"),
                    "{} {flag} must not claim the --output alias",
                    command["name"]
                );
            }
        }
    }
    assert_eq!(out_options, 2, "assemble and verify both take --out");
}

fn contains_escape(bytes: &[u8]) -> bool {
    bytes.contains(&0x1b)
}

/// Every human and machine surface, run piped (non-TTY) under the color-related
/// environment a caller might have, must contain no ANSI escape byte at all.
#[test]
fn test_no_ansi_on_any_surface_under_color_environment() {
    let dir = tempdir().unwrap();
    let witness_path = dir.path().join("witness.jsonl");

    let surfaces: &[&[&str]] = &[
        &[],
        &["--help"],
        &["assemble", "--help"],
        &["verify", "--help"],
        &["doctor", "--help"],
        &["--bogus"],
        &["assemble"],
        &["doctor"],
        &["doctor", "--json"],
        &["doctor", "triage"],
        &["doctor", "capabilities"],
        &["doctor", "robot-docs"],
        &["capabilities"],
        &["capabilities", "--json"],
        &["robot-docs", "guide"],
        &["--describe"],
        &["--schema"],
        &["--version"],
        &[
            "explain",
            "--manifest",
            "fixtures/clean_telemetry_only/expected_manifest.json",
        ],
        &["explain", "--manifest", "does-not-exist/manifest.json"],
        &["witness", "last"],
        &["witness", "count", "--json"],
    ];
    // (label, NO_COLOR, TERM, CLICOLOR_FORCE)
    let environments: &[(&str, Option<&str>, Option<&str>, Option<&str>)] = &[
        ("NO_COLOR=1 TERM=dumb", Some("1"), Some("dumb"), None),
        ("neither NO_COLOR nor TERM", None, None, None),
        (
            "NO_COLOR=1 beats CLICOLOR_FORCE=1",
            Some("1"),
            None,
            Some("1"),
        ),
    ];

    for (label, no_color, term, force) in environments {
        for args in surfaces {
            let mut cmd = airlock_cmd();
            cmd.env("EPISTEMIC_WITNESS", &witness_path)
                .env_remove("NO_COLOR")
                .env_remove("TERM")
                .env_remove("CLICOLOR_FORCE");
            if let Some(value) = no_color {
                cmd.env("NO_COLOR", value);
            }
            if let Some(value) = term {
                cmd.env("TERM", value);
            }
            if let Some(value) = force {
                cmd.env("CLICOLOR_FORCE", value);
            }
            let output = cmd.args(*args).output().unwrap();

            assert!(
                !output.stdout.is_empty() || !output.stderr.is_empty(),
                "`airlock {}` produced no output ({label}); the check would be vacuous",
                args.join(" ")
            );
            assert!(
                !contains_escape(&output.stdout) && !contains_escape(&output.stderr),
                "`airlock {}` emitted an ANSI escape byte ({label})",
                args.join(" ")
            );
        }
    }
    assert!(
        !witness_path.exists(),
        "read-only surfaces must not create the ledger"
    );
}
