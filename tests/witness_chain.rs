//! The witness ledger's `prev_hash` chain, through the real `airlock` binary. The chain check
//! here is written from the definition (blake3 of the exact bytes of the previous airlock
//! line) and shares no code with the writer.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use serde_json::Value;

const GENESIS: &str = "blake3:0000000000000000000000000000000000000000000000000000000000000000";

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/clean_telemetry_only")
}

/// `airlock verify` over the clean fixture, appending one airlock entry to `ledger`.
fn verify_command(ledger: &Path, out: &Path) -> Command {
    let root = fixture_root();
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .args(["verify", "--no-sign", "--policy"])
        .arg(root.join("policy.yaml"))
        .arg("--prompt")
        .arg(root.join("expected_prompt_payload.json"))
        .arg("--provenance")
        .arg(root.join("expected_prompt_provenance.json"))
        .arg("--request")
        .arg(root.join("request.json"))
        .arg("--out")
        .arg(out)
        .env("EPISTEMIC_WITNESS", ledger)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

fn run_verify(ledger: &Path, out: &Path) {
    let output = verify_command(ledger, out).output().unwrap();
    assert!(
        output.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("witness"),
        "a witness warning was printed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn hash_of(line: &str) -> String {
    format!("blake3:{}", blake3::hash(line.as_bytes()).to_hex())
}

/// Every line of the ledger that is a JSON object whose `tool` is "airlock", in file order.
fn airlock_lines(ledger: &Path) -> Vec<String> {
    fs::read_to_string(ledger)
        .unwrap()
        .split('\n')
        .filter(|line| {
            serde_json::from_str::<Value>(line)
                .is_ok_and(|value| value.get("tool").and_then(Value::as_str) == Some("airlock"))
        })
        .map(str::to_owned)
        .collect()
}

fn prev_hash_of(line: &str) -> Option<String> {
    let value: Value = serde_json::from_str(line).unwrap();
    value
        .get("prev_hash")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The first entry links to genesis and every other to the exact bytes of the one before it.
fn assert_unbroken_chain(lines: &[String]) {
    assert!(!lines.is_empty());
    assert_eq!(prev_hash_of(&lines[0]).as_deref(), Some(GENESIS));
    for (index, pair) in lines.windows(2).enumerate() {
        assert_eq!(
            prev_hash_of(&pair[1]),
            Some(hash_of(&pair[0])),
            "entry {} does not link to entry {index}",
            index + 1
        );
    }
}

#[test]
fn concurrent_airlock_processes_write_one_unbroken_chain() {
    const WAVES: usize = 3;
    const PER_WAVE: usize = 8;
    let temp = tempfile::tempdir().unwrap();
    let ledger = temp.path().join("witness.jsonl");

    for wave in 0..WAVES {
        let children: Vec<Child> = (0..PER_WAVE)
            .map(|n| {
                verify_command(
                    &ledger,
                    &temp.path().join(format!("manifest-{wave}-{n}.json")),
                )
                .spawn()
                .unwrap()
            })
            .collect();
        for child in children {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "verify failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                !String::from_utf8_lossy(&output.stderr).contains("witness"),
                "a witness warning was printed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    let lines = airlock_lines(&ledger);
    assert_eq!(lines.len(), WAVES * PER_WAVE, "every run left one entry");
    assert_unbroken_chain(&lines);
}

#[test]
fn another_tools_lines_between_real_runs_are_not_links() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = temp.path().join("witness.jsonl");
    run_verify(&ledger, &temp.path().join("one.json"));
    let first = airlock_lines(&ledger).remove(0);
    let mut contents = fs::read_to_string(&ledger).unwrap();
    contents.push_str("{\"tool\":\"rvl\",\"outcome\":\"ok\"}\nnot json\n");
    fs::write(&ledger, contents).unwrap();

    run_verify(&ledger, &temp.path().join("two.json"));

    let lines = airlock_lines(&ledger);
    assert_eq!(lines.len(), 2);
    assert_eq!(prev_hash_of(&lines[1]), Some(hash_of(&first)));
}

#[test]
fn a_ledger_from_before_the_chain_is_extended_not_restarted() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = temp.path().join("witness.jsonl");
    run_verify(&ledger, &temp.path().join("one.json"));
    // Turn that entry into what an older airlock wrote: no prev_hash member.
    let mut legacy: Value = serde_json::from_str(&airlock_lines(&ledger)[0]).unwrap();
    legacy.as_object_mut().unwrap().remove("prev_hash").unwrap();
    let legacy_line = serde_json::to_string(&legacy).unwrap();
    fs::write(&ledger, format!("{legacy_line}\n")).unwrap();

    run_verify(&ledger, &temp.path().join("two.json"));

    let lines = airlock_lines(&ledger);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], legacy_line, "the old entry is left byte for byte");
    assert_eq!(prev_hash_of(&lines[1]), Some(hash_of(&legacy_line)));
}

#[test]
fn witness_last_json_shows_the_chain_link() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = temp.path().join("witness.jsonl");
    run_verify(&ledger, &temp.path().join("one.json"));

    let output = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(["witness", "last", "--json"])
        .env("EPISTEMIC_WITNESS", &ledger)
        .output()
        .unwrap();

    assert!(output.status.success());
    let record: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["prev_hash"], GENESIS);
}
