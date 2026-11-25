//! `airlock witness verify`: what the `prev_hash` chain catches and, pinned on purpose, what it
//! does not. Every ledger here is written by real `airlock verify` runs; the expected hashes are
//! computed by this file's own code (blake3 of the exact bytes of the previous airlock line),
//! not by the code under test.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

const GENESIS: &str = "blake3:0000000000000000000000000000000000000000000000000000000000000000";
const ENTRIES: usize = 5;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/clean_telemetry_only")
}

/// One real `airlock verify` run, which appends one airlock entry to `ledger`.
fn run_verify(ledger: &Path, out: &Path) {
    let root = fixture_root();
    let output = Command::new(env!("CARGO_BIN_EXE_airlock"))
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
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A ledger of `count` real, chained airlock entries.
fn real_ledger(dir: &Path, count: usize) -> PathBuf {
    let ledger = dir.join("witness.jsonl");
    for n in 0..count {
        run_verify(&ledger, &dir.join(format!("manifest-{n}.json")));
    }
    ledger
}

fn hash_of(line: &str) -> String {
    format!("blake3:{}", blake3::hash(line.as_bytes()).to_hex())
}

fn lines_of(ledger: &Path) -> Vec<String> {
    fs::read_to_string(ledger)
        .unwrap()
        .split('\n')
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn write_lines(ledger: &Path, lines: &[String]) {
    fs::write(ledger, format!("{}\n", lines.join("\n"))).unwrap();
}

fn witness_verify(ledger: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(["witness", "verify"])
        .args(extra)
        .env("EPISTEMIC_WITNESS", ledger)
        .output()
        .unwrap()
}

/// `airlock witness verify --json`: the exit code and the parsed stdout.
fn verify_json(ledger: &Path, extra: &[&str]) -> (i32, Value) {
    let mut args = vec!["--json"];
    args.extend_from_slice(extra);
    let output = witness_verify(ledger, &args);
    let parsed = serde_json::from_slice::<Value>(&output.stdout);
    assert!(
        parsed.is_ok(),
        "stdout is not JSON: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    (output.status.code().unwrap(), parsed.unwrap_or(Value::Null))
}

fn break_lines(report: &Value) -> Vec<u64> {
    report["breaks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["line"].as_u64().unwrap())
        .collect()
}

fn break_reasons(report: &Value) -> Vec<String> {
    report["breaks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["reason"].as_str().unwrap().to_owned())
        .collect()
}

/// The ledger as written by someone who can write the whole file: `edit_index` is changed and
/// every `prev_hash` is recomputed so each link holds.
fn rewrite_with_recomputed_links(lines: &[String], edit_index: usize) -> Vec<String> {
    let mut rewritten: Vec<String> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let mut value: Value = serde_json::from_str(line).unwrap();
        if index == edit_index {
            value["exit_code"] = json!(1);
        }
        value["prev_hash"] = json!(match rewritten.last() {
            Some(previous) => hash_of(previous),
            None => GENESIS.to_string(),
        });
        rewritten.push(serde_json::to_string(&value).unwrap());
    }
    rewritten
}

/// An airlock entry as an older airlock (no chain) wrote it: `line` without `prev_hash`.
fn without_prev_hash(line: &str) -> String {
    let mut value: Value = serde_json::from_str(line).unwrap();
    value.as_object_mut().unwrap().remove("prev_hash").unwrap();
    serde_json::to_string(&value).unwrap()
}

#[test]
fn an_untouched_chain_verifies_and_reports_its_head() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), ENTRIES);
    let lines = lines_of(&ledger);
    assert_eq!(lines.len(), ENTRIES);

    let (code, report) = verify_json(&ledger, &[]);

    assert_eq!(code, 0);
    assert_eq!(report["status"], "CHAIN_OK");
    assert_eq!(report["airlock_entries"], ENTRIES);
    assert_eq!(report["chained"], ENTRIES);
    assert_eq!(report["unchained"], 0);
    assert_eq!(report["breaks"], json!([]));
    assert_eq!(report["warnings"], json!([]));
    assert_eq!(report["expected_head"], Value::Null);
    assert_eq!(report["head"], hash_of(lines.last().unwrap()));
    assert_eq!(report["ledger"], ledger.display().to_string());
}

#[test]
fn the_entries_a_real_run_wrote_are_linked_by_this_files_own_hash() {
    // Guards the tests below against passing for the wrong reason: the links in a real ledger
    // are exactly the blake3 of the previous line's bytes, computed here independently.
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), 3);
    let lines = lines_of(&ledger);

    let prev: Vec<String> = lines
        .iter()
        .map(|line| {
            let value: Value = serde_json::from_str(line).unwrap();
            value["prev_hash"].as_str().unwrap().to_owned()
        })
        .collect();

    assert_eq!(
        prev,
        [GENESIS.to_string(), hash_of(&lines[0]), hash_of(&lines[1])]
    );
}

#[test]
fn editing_a_middle_entry_is_caught_at_the_entry_after_it() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), ENTRIES);
    let original = lines_of(&ledger);
    let mut lines = original.clone();
    lines[2] = lines[2].replace("\"exit_code\":0", "\"exit_code\":1");
    assert_ne!(lines[2], original[2], "the edit must change the line");
    write_lines(&ledger, &lines);

    let (code, report) = verify_json(&ledger, &[]);

    assert_eq!(code, 1);
    assert_eq!(report["status"], "CHAIN_BROKEN");
    // Line 4 is the entry after the edited line 3: it still carries the hash of the line as it
    // was, while the line now in the file hashes differently.
    assert_eq!(break_lines(&report), [4]);
    assert_eq!(break_reasons(&report), ["PREV_HASH_MISMATCH"]);
    assert_eq!(report["breaks"][0]["expected"], hash_of(&lines[2]));
    assert_eq!(report["breaks"][0]["found"], hash_of(&original[2]));
}

#[test]
fn deleting_a_middle_entry_is_caught_at_the_entry_after_it() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), ENTRIES);
    let original = lines_of(&ledger);
    let mut lines = original.clone();
    lines.remove(2);
    write_lines(&ledger, &lines);

    let (code, report) = verify_json(&ledger, &[]);

    assert_eq!(code, 1);
    // The old fourth entry is now line 3; it links to the deleted entry, not to the one before.
    assert_eq!(break_lines(&report), [3]);
    assert_eq!(break_reasons(&report), ["PREV_HASH_MISMATCH"]);
    assert_eq!(report["breaks"][0]["expected"], hash_of(&original[1]));
    assert_eq!(report["breaks"][0]["found"], hash_of(&original[2]));
}

#[test]
fn inserting_a_forged_entry_is_caught_at_the_forgery_and_at_the_entry_after_it() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), ENTRIES);
    let original = lines_of(&ledger);
    let mut forged: Value = serde_json::from_str(&original[1]).unwrap();
    forged["exit_code"] = json!(1);
    let forged = serde_json::to_string(&forged).unwrap();
    let mut lines = original.clone();
    lines.insert(2, forged.clone());
    write_lines(&ledger, &lines);

    let (code, report) = verify_json(&ledger, &[]);

    assert_eq!(code, 1);
    // The forgery (line 3) copies line 2's link, which is not the hash of line 2; and the entry
    // after it (line 4) links to line 2, not to the forgery.
    assert_eq!(break_lines(&report), [3, 4]);
    assert_eq!(
        break_reasons(&report),
        ["PREV_HASH_MISMATCH", "PREV_HASH_MISMATCH"]
    );
    assert_eq!(report["breaks"][0]["expected"], hash_of(&original[1]));
    assert_eq!(report["breaks"][1]["expected"], hash_of(&forged));
    assert_eq!(report["breaks"][1]["found"], hash_of(&original[1]));
}

#[test]
fn swapping_two_entries_is_caught() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), ENTRIES);
    let original = lines_of(&ledger);
    let mut lines = original.clone();
    lines.swap(1, 2);
    write_lines(&ledger, &lines);

    let (code, report) = verify_json(&ledger, &[]);

    assert_eq!(code, 1);
    assert_eq!(break_lines(&report), [2, 3, 4]);
    assert_eq!(
        break_reasons(&report),
        [
            "PREV_HASH_MISMATCH",
            "PREV_HASH_MISMATCH",
            "PREV_HASH_MISMATCH"
        ]
    );
}

#[test]
fn cutting_entries_off_the_head_of_the_ledger_is_caught() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), ENTRIES);
    let original = lines_of(&ledger);
    write_lines(&ledger, &original[1..]);

    let (code, report) = verify_json(&ledger, &[]);

    assert_eq!(code, 1);
    assert_eq!(break_lines(&report), [1]);
    assert_eq!(break_reasons(&report), ["FIRST_ENTRY_HAS_PREDECESSOR"]);
    assert_eq!(report["breaks"][0]["expected"], GENESIS);
    assert_eq!(report["breaks"][0]["found"], hash_of(&original[0]));
}

#[test]
fn a_prev_hash_that_is_not_a_string_is_reported_as_malformed() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), 3);
    let mut lines = lines_of(&ledger);
    let mut value: Value = serde_json::from_str(&lines[1]).unwrap();
    value["prev_hash"] = json!(7);
    lines[1] = serde_json::to_string(&value).unwrap();
    write_lines(&ledger, &lines);

    let (code, report) = verify_json(&ledger, &[]);

    assert_eq!(code, 1);
    // The malformed entry itself (line 2), and the entry after it, whose link no longer matches
    // the rewritten line 2.
    assert_eq!(break_lines(&report), [2, 3]);
    assert_eq!(
        break_reasons(&report),
        ["PREV_HASH_MALFORMED", "PREV_HASH_MISMATCH"]
    );
}

// What the chain does NOT detect, pinned so a later change cannot start claiming it does. Both
// are the reason `--expect-head` exists: a head kept off the ledger's writers' reach.

#[test]
fn removing_the_newest_entries_is_not_detected_without_an_expected_head() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), ENTRIES);
    let original = lines_of(&ledger);
    let head_before = hash_of(original.last().unwrap());
    write_lines(&ledger, &original[..3]);

    let (code, report) = verify_json(&ledger, &[]);
    assert_eq!(code, 0, "tail truncation leaves a valid shorter chain");
    assert_eq!(report["status"], "CHAIN_OK");
    assert_eq!(report["airlock_entries"], 3);

    let (code, report) = verify_json(&ledger, &["--expect-head", &head_before]);
    assert_eq!(code, 1);
    assert_eq!(report["status"], "HEAD_MISMATCH");
    assert_eq!(report["breaks"], json!([]));
    assert_eq!(report["expected_head"], head_before);
    assert_eq!(report["head"], hash_of(&original[2]));
}

#[test]
fn a_whole_ledger_rewritten_with_recomputed_links_is_not_detected_without_an_expected_head() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), ENTRIES);
    let original = lines_of(&ledger);
    let head_before = hash_of(original.last().unwrap());
    let rewritten = rewrite_with_recomputed_links(&original, 2);
    assert_ne!(
        rewritten[2], original[2],
        "the rewrite must change an entry"
    );
    write_lines(&ledger, &rewritten);

    let (code, report) = verify_json(&ledger, &[]);
    assert_eq!(code, 0, "a rewrite that recomputes every hash verifies");
    assert_eq!(report["status"], "CHAIN_OK");
    assert_eq!(report["breaks"], json!([]));

    let (code, report) = verify_json(&ledger, &["--expect-head", &head_before]);
    assert_eq!(code, 1);
    assert_eq!(report["status"], "HEAD_MISMATCH");
}

#[test]
fn a_matching_expected_head_passes() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), ENTRIES);
    let (_, first) = verify_json(&ledger, &[]);
    let head = first["head"].as_str().unwrap().to_owned();

    let (code, report) = verify_json(&ledger, &["--expect-head", &head]);

    assert_eq!(code, 0);
    assert_eq!(report["status"], "CHAIN_OK");
    assert_eq!(report["expected_head"], head);
}

#[test]
fn a_broken_chain_is_reported_as_broken_even_when_the_head_also_differs() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), ENTRIES);
    let mut lines = lines_of(&ledger);
    lines[1] = lines[1].replace("\"exit_code\":0", "\"exit_code\":1");
    write_lines(&ledger, &lines);

    let (code, report) = verify_json(&ledger, &["--expect-head", GENESIS]);

    assert_eq!(code, 1);
    assert_eq!(report["status"], "CHAIN_BROKEN");
}

#[test]
fn another_tools_lines_are_neither_links_nor_covered() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), 3);
    let mut lines = lines_of(&ledger);
    let other = json!({"tool": "shape", "outcome": "COMPATIBLE", "note": "original"}).to_string();
    lines.insert(2, other.clone());
    write_lines(&ledger, &lines);

    let (code, report) = verify_json(&ledger, &[]);
    assert_eq!(code, 0);
    assert_eq!(report["airlock_entries"], 3);

    // Editing the other tool's entry is not detected: the chain covers airlock entries only.
    lines[2] = other.replace("original", "edited");
    write_lines(&ledger, &lines);
    let (code, report) = verify_json(&ledger, &[]);
    assert_eq!(code, 0);
    assert_eq!(report["status"], "CHAIN_OK");
}

#[test]
fn an_entry_an_older_airlock_wrote_is_a_warning_and_the_next_entry_links_over_it() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), 2);
    let mut lines = lines_of(&ledger);
    let unchained = without_prev_hash(&lines[0]);
    lines.push(unchained.clone());
    write_lines(&ledger, &lines);
    // A real run appends after the unchained line and must link to its exact bytes.
    run_verify(&ledger, &temp.path().join("manifest-late.json"));

    let (code, report) = verify_json(&ledger, &[]);

    assert_eq!(code, 0, "{report}");
    assert_eq!(report["status"], "CHAIN_OK");
    assert_eq!(report["airlock_entries"], 4);
    assert_eq!(report["chained"], 3);
    assert_eq!(report["unchained"], 1);
    assert_eq!(report["warnings"].as_array().unwrap().len(), 1);
    assert_eq!(report["warnings"][0]["line"], 3);
    assert_eq!(
        report["warnings"][0]["reason"],
        "UNCHAINED_AFTER_CHAIN_START"
    );
    assert_eq!(
        lines_of(&ledger)[3]
            .split("\"prev_hash\":\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap(),
        hash_of(&unchained)
    );
}

#[test]
fn a_ledger_from_before_the_chain_verifies_without_warnings_once_extended() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), 2);
    // Turn the two real entries into what an older airlock wrote: no prev_hash.
    let legacy: Vec<String> = lines_of(&ledger)
        .iter()
        .map(|line| without_prev_hash(line))
        .collect();
    write_lines(&ledger, &legacy);
    run_verify(&ledger, &temp.path().join("manifest-new-0.json"));
    run_verify(&ledger, &temp.path().join("manifest-new-1.json"));

    let (code, report) = verify_json(&ledger, &[]);

    assert_eq!(code, 0, "{report}");
    assert_eq!(report["airlock_entries"], 4);
    assert_eq!(report["chained"], 2);
    assert_eq!(report["unchained"], 2);
    assert_eq!(
        report["warnings"],
        json!([]),
        "entries before the chain began are not warnings"
    );
    // The first chained entry links to the last legacy line, not to the genesis value.
    let first_chained: Value = serde_json::from_str(&lines_of(&ledger)[2]).unwrap();
    assert_eq!(first_chained["prev_hash"], hash_of(&legacy[1]));
}

#[test]
fn a_ledger_with_no_airlock_entries_or_no_ledger_at_all_is_intact() {
    let temp = tempfile::tempdir().unwrap();

    let (code, report) = verify_json(&temp.path().join("missing.jsonl"), &[]);
    assert_eq!(code, 0);
    assert_eq!(report["status"], "CHAIN_OK");
    assert_eq!(report["airlock_entries"], 0);
    assert_eq!(report["head"], Value::Null);

    let only_others = temp.path().join("others.jsonl");
    fs::write(
        &only_others,
        format!("{}\n", json!({"tool": "rvl", "outcome": "REAL_CHANGE"})),
    )
    .unwrap();
    let (code, report) = verify_json(&only_others, &[]);
    assert_eq!(code, 0);
    assert_eq!(report["airlock_entries"], 0);
    assert_eq!(report["head"], Value::Null);
}

#[test]
fn an_unreadable_ledger_is_a_refusal_not_a_verdict() {
    let temp = tempfile::tempdir().unwrap();
    // A directory where the ledger should be: it exists but cannot be read as a file.
    let (code, report) = verify_json(temp.path(), &[]);

    assert_eq!(code, 2);
    assert_eq!(report["outcome"], "REFUSAL");
    assert_eq!(report["refusal"]["code"], "E_WITNESS_ERROR");
}

#[test]
fn a_malformed_expected_head_is_a_refusal_before_the_ledger_is_read() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), 2);
    let uppercase = format!("blake3:{}", "A".repeat(64));
    let short = format!("blake3:{}", "a".repeat(63));
    let wrong_prefix = format!("sha256:{}", "a".repeat(64));

    for bad in [
        "abc",
        "blake3:",
        uppercase.as_str(),
        short.as_str(),
        wrong_prefix.as_str(),
    ] {
        let (code, report) = verify_json(&ledger, &["--expect-head", bad]);
        assert_eq!(code, 2, "{bad}");
        assert_eq!(report["outcome"], "REFUSAL", "{bad}");
        assert_eq!(report["refusal"]["code"], "E_BAD_INPUT", "{bad}");
        assert_eq!(report["refusal"]["detail"]["flag"], "--expect-head");
    }
}

#[test]
fn the_text_report_names_the_break_and_states_the_limit() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = real_ledger(temp.path(), ENTRIES);

    let ok = witness_verify(&ledger, &[]);
    let ok_text = String::from_utf8_lossy(&ok.stdout);
    assert_eq!(ok.status.code(), Some(0));
    assert!(
        ok_text.starts_with("WITNESS CHAIN: CHAIN_OK\n"),
        "{ok_text}"
    );
    assert!(ok_text.contains("Airlock entries: 5 (5 chained, 0 without prev_hash)"));
    assert!(ok_text.contains("tamper hint, not a proof"));
    assert!(ok_text.contains("--expect-head"));

    let mut lines = lines_of(&ledger);
    lines[2] = lines[2].replace("\"exit_code\":0", "\"exit_code\":1");
    write_lines(&ledger, &lines);
    let broken = witness_verify(&ledger, &[]);
    let broken_text = String::from_utf8_lossy(&broken.stdout);
    assert_eq!(broken.status.code(), Some(1));
    assert!(
        broken_text.starts_with("WITNESS CHAIN: CHAIN_BROKEN\n"),
        "{broken_text}"
    );
    assert!(
        broken_text.contains("BREAK at line 4: PREV_HASH_MISMATCH"),
        "the text report uses the JSON reason name: {broken_text}"
    );
}
