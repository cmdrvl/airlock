//! Witness recording is on by default for `assemble` and `verify`, and `--no-witness` turns it
//! off, through the real `airlock` binary (al-2gz). The README says both; the unit tests in
//! `assemble.rs` and `verify.rs` cover the flag on `run_with_writers`, not the command line.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/clean_telemetry_only")
        .join(name)
}

/// The real `airlock assemble` over the clean fixture, recording to `ledger` unless `no_witness`.
fn assemble(dir: &Path, ledger: &Path, no_witness: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .args(["assemble", "--policy"])
        .arg(fixture("policy.yaml"))
        .arg("--input")
        .arg(fixture("strategy_space.json"))
        .arg("--system-prompt")
        .arg(fixture("system_prompt.txt"))
        .args(["--boundary-mode", "TELEMETRY_ONLY", "--out"])
        .arg(dir.join("prompt.json"))
        .arg("--provenance-out")
        .arg(dir.join("provenance.json"))
        .env("EPISTEMIC_WITNESS", ledger);
    if no_witness {
        command.arg("--no-witness");
    }
    command.output().unwrap()
}

/// The real `airlock verify` over the clean fixture, recording to `ledger` unless `no_witness`.
fn verify(dir: &Path, ledger: &Path, no_witness: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .args(["verify", "--no-sign", "--policy"])
        .arg(fixture("policy.yaml"))
        .arg("--prompt")
        .arg(fixture("expected_prompt_payload.json"))
        .arg("--provenance")
        .arg(fixture("expected_prompt_provenance.json"))
        .arg("--request")
        .arg(fixture("request.json"))
        .arg("--out")
        .arg(dir.join("manifest.json"))
        .env("EPISTEMIC_WITNESS", ledger);
    if no_witness {
        command.arg("--no-witness");
    }
    command.output().unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "exit {:?}: {}{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The `command` of every airlock line in the ledger, in file order.
fn recorded_commands(ledger: &Path) -> Vec<String> {
    fs::read_to_string(ledger)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|record| record["tool"] == "airlock")
        .map(|record| record["command"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn assemble_records_to_the_witness_ledger_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");

    let output = assemble(dir.path(), &ledger, false);

    assert_success(&output);
    assert_eq!(recorded_commands(&ledger), ["assemble"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("witness"), "{stderr}");
}

#[test]
fn verify_records_to_the_witness_ledger_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");

    let output = verify(dir.path(), &ledger, false);

    assert_success(&output);
    assert_eq!(recorded_commands(&ledger), ["verify"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("witness"), "{stderr}");
}

#[test]
fn assemble_with_no_witness_leaves_no_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");

    let output = assemble(dir.path(), &ledger, true);

    assert_success(&output);
    assert!(!ledger.exists(), "--no-witness still wrote {ledger:?}");
}

#[test]
fn verify_with_no_witness_leaves_no_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");

    let output = verify(dir.path(), &ledger, true);

    assert_success(&output);
    assert!(!ledger.exists(), "--no-witness still wrote {ledger:?}");
}
