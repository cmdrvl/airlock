use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use airlock::assembler::PromptProvenance;
use airlock::hash::blake3_hash;
use airlock::output::{canonical_json, canonical_json_bytes};
use assert_cmd::Command;
use serde_json::{json, Value};
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
