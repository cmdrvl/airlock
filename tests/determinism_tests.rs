use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use airlock::assembler::PromptProvenance;
use airlock::hash::blake3_hash;
use airlock::output::{canonical_json, canonical_json_bytes};
use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn airlock_cmd() -> Command {
    let mut cmd = Command::cargo_bin("airlock").unwrap();
    cmd.current_dir(repo_root());
    cmd
}

fn run_clean_assemble(dir: &Path, suffix: usize) -> (Vec<u8>, Vec<u8>) {
    let prompt_path = dir.join(format!("prompt-{suffix}.json"));
    let provenance_path = dir.join(format!("provenance-{suffix}.json"));

    airlock_cmd()
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

    (
        fs::read(prompt_path).unwrap(),
        fs::read(provenance_path).unwrap(),
    )
}

fn normalized_manifest_hash(mut manifest: Value) -> String {
    manifest["timestamp"] = json!("1970-01-01T00:00:00Z");
    blake3_hash(&canonical_json_bytes(&manifest))
}

#[test]
fn test_assemble_deterministic() {
    let dir = tempdir().unwrap();
    let mut prompt_hashes = BTreeSet::new();
    let mut baseline_prompt = None;

    for run in 0..10 {
        let (prompt_bytes, provenance_bytes) = run_clean_assemble(dir.path(), run);
        let provenance: Value = serde_json::from_slice(&provenance_bytes).unwrap();
        prompt_hashes.insert(
            provenance["prompt_payload_hash"]
                .as_str()
                .unwrap()
                .to_string(),
        );

        if let Some(expected) = &baseline_prompt {
            assert_eq!(&prompt_bytes, expected);
        } else {
            baseline_prompt = Some(prompt_bytes);
        }
    }

    assert_eq!(prompt_hashes.len(), 1);
}

#[test]
fn test_manifest_deterministic() {
    let dir = tempdir().unwrap();
    let mut manifest_hashes = BTreeSet::new();
    let mut baseline_manifest = None;

    for run in 0..10 {
        let manifest_path = dir.path().join(format!("manifest-{run}.json"));
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
        let manifest: Value = serde_json::from_slice(&output).unwrap();
        let hash = normalized_manifest_hash(manifest.clone());
        manifest_hashes.insert(hash);

        let normalized = {
            let mut value = manifest;
            value["timestamp"] = json!("1970-01-01T00:00:00Z");
            value
        };

        if let Some(expected) = &baseline_manifest {
            assert_eq!(&normalized, expected);
        } else {
            baseline_manifest = Some(normalized);
        }
    }

    assert_eq!(manifest_hashes.len(), 1);
}

/// 2023-11-14T22:13:20Z
const FIXED_EPOCH: &str = "1700000000";
const FIXED_EPOCH_RFC3339: &str = "2023-11-14T22:13:20+00:00";

fn verify_command(manifest_path: &Path, source_date_epoch: Option<&str>) -> Command {
    let mut cmd = airlock_cmd();
    cmd.args([
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
    ]);
    match source_date_epoch {
        Some(value) => cmd.env("SOURCE_DATE_EPOCH", value),
        None => cmd.env_remove("SOURCE_DATE_EPOCH"),
    };
    cmd
}

fn verify_stdout(manifest_path: &Path, source_date_epoch: Option<&str>) -> Vec<u8> {
    verify_command(manifest_path, source_date_epoch)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone()
}

#[test]
fn test_verify_manifest_is_byte_identical_under_source_date_epoch() {
    let dir = tempdir().unwrap();
    let first_path = dir.path().join("first.json");
    let second_path = dir.path().join("second.json");

    let first_stdout = verify_stdout(&first_path, Some(FIXED_EPOCH));
    // Let the wall clock move past a whole second so any clock leak shows up.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let second_stdout = verify_stdout(&second_path, Some(FIXED_EPOCH));

    assert_eq!(first_stdout, second_stdout);
    assert_eq!(
        fs::read(&first_path).unwrap(),
        fs::read(&second_path).unwrap()
    );

    let manifest: Value = serde_json::from_slice(&first_stdout).unwrap();
    assert_eq!(manifest["timestamp"], FIXED_EPOCH_RFC3339);
    let written: Value = serde_json::from_slice(&fs::read(&first_path).unwrap()).unwrap();
    assert_eq!(written["timestamp"], FIXED_EPOCH_RFC3339);
}

#[test]
fn test_verify_timestamp_follows_the_source_date_epoch_value() {
    let dir = tempdir().unwrap();

    let epoch_zero: Value =
        serde_json::from_slice(&verify_stdout(&dir.path().join("zero.json"), Some("0"))).unwrap();
    let fixed: Value = serde_json::from_slice(&verify_stdout(
        &dir.path().join("fixed.json"),
        Some(FIXED_EPOCH),
    ))
    .unwrap();

    assert_eq!(epoch_zero["timestamp"], "1970-01-01T00:00:00+00:00");
    assert_eq!(fixed["timestamp"], FIXED_EPOCH_RFC3339);
    // Only the timestamp differs between the two instants.
    let mut normalized = epoch_zero.clone();
    normalized["timestamp"] = fixed["timestamp"].clone();
    assert_eq!(normalized, fixed);
}

#[test]
fn test_verify_without_source_date_epoch_uses_the_wall_clock() {
    let dir = tempdir().unwrap();
    let before = chrono::Utc::now();
    let manifest: Value =
        serde_json::from_slice(&verify_stdout(&dir.path().join("now.json"), None)).unwrap();
    let after = chrono::Utc::now();

    let stamped = chrono::DateTime::parse_from_rfc3339(manifest["timestamp"].as_str().unwrap())
        .unwrap()
        .with_timezone(&chrono::Utc);
    assert!(
        stamped >= before - chrono::Duration::seconds(1)
            && stamped <= after + chrono::Duration::seconds(1),
        "timestamp {stamped} should be between {before} and {after}"
    );
}

#[test]
fn test_verify_refuses_an_invalid_source_date_epoch() {
    let dir = tempdir().unwrap();

    for (index, bad) in [
        "",
        "yesterday",
        "1.5",
        " 1700000000",
        "99999999999999999999",
        "9223372036854775807",
    ]
    .into_iter()
    .enumerate()
    {
        let manifest_path = dir.path().join(format!("never-{index}.json"));
        let output = verify_command(&manifest_path, Some(bad))
            .assert()
            .code(2)
            .get_output()
            .clone();

        let refusal: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(refusal["outcome"], "REFUSAL", "value {bad:?}");
        assert_eq!(refusal["refusal"]["code"], "E_BAD_INPUT", "value {bad:?}");
        assert_eq!(refusal["refusal"]["detail"]["env"], "SOURCE_DATE_EPOCH");
        assert_eq!(refusal["refusal"]["detail"]["value"], bad);
        assert_eq!(refusal["refusal"]["detail"]["expected"], "Unix seconds");
        assert!(
            !manifest_path.exists(),
            "no manifest may be written for value {bad:?}"
        );
    }
}

#[test]
fn test_provenance_deterministic() {
    let dir = tempdir().unwrap();
    let mut provenance_hashes = BTreeSet::new();
    let mut baseline_provenance = None;

    for run in 0..10 {
        let (_, provenance_bytes) = run_clean_assemble(dir.path(), run);
        let provenance: PromptProvenance = serde_json::from_slice(&provenance_bytes).unwrap();
        provenance_hashes.insert(provenance.hash());

        if let Some(expected) = &baseline_provenance {
            assert_eq!(&provenance.to_canonical_json(), expected);
        } else {
            baseline_provenance = Some(provenance.to_canonical_json());
        }
    }

    assert_eq!(provenance_hashes.len(), 1);
}

#[test]
fn test_canonical_json_key_order() {
    let values = [
        json!({"z": 1, "a": 2, "m": {"y": 4, "b": 3}}),
        json!({"m": {"b": 3, "y": 4}, "a": 2, "z": 1}),
        json!({"a": 2, "z": 1, "m": {"y": 4, "b": 3}}),
    ];

    let canonical_forms: BTreeSet<String> = values.iter().map(canonical_json).collect();

    assert_eq!(canonical_forms.len(), 1);
    assert_eq!(
        canonical_forms.into_iter().next().unwrap(),
        r#"{"a":2,"m":{"b":3,"y":4},"z":1}"#
    );
}
