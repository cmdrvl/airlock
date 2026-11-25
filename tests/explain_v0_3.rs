//! `airlock explain` on airlock.v0.3 manifests, through the real binary: the request size, the
//! attestation, the signer's fingerprint and the not-crossed inventory, with an airlock.v0.2
//! manifest explained exactly as it always was.
//!
//! `fixtures/explain/*_v0_2.{txt,json}` are the output of the binary built from commit 88e5510,
//! before `explain` knew any v0.3 member, for the two v0.2 golden manifests named in
//! `V0_2_GOLDENS`. They were captured once and are not regenerated.
//!
//! The withheld-value hashes below were computed with Python's `blake3` over the canonical JSON
//! of ASCII values (the same constants `tests/not_crossed.rs` uses), and the signed golden's
//! fingerprint comes from `tests/signing.rs`'s RFC 8032 key; none of them come from this crate.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use tempfile::tempdir;

const OPERATOR_NOTE: &str = "internal note: do not send";
const OPERATOR_NOTE_HASH: &str =
    "blake3:e492e079dfe5a48a0b35ecfe64592fdde152b4d1a00f577e649d06a47a80bf24";
const HTML_PATH: &str = "/srv/filings/page.html";
const HTML_PATH_HASH: &str =
    "blake3:9451fdbc050c92f3b1a85eeff05008d21842ec179d2e02eaefe355f1b0c226de";
const GOLDEN_FINGERPRINT: &str =
    "blake3:6c31041268f471609c79f5f2dbcc38e4a4ab2f4d416109a4e09fcf50fd0f0062";

/// (manifest, captured human output, captured --json output), paths relative to the crate root.
const V0_2_GOLDENS: [(&str, &str, &str); 2] = [
    (
        "fixtures/clean_telemetry_only/expected_manifest.json",
        "fixtures/explain/clean_telemetry_only_v0_2.txt",
        "fixtures/explain/clean_telemetry_only_v0_2.json",
    ),
    (
        "fixtures/boundary_failed/expected_manifest.json",
        "fixtures/explain/boundary_failed_v0_2.txt",
        "fixtures/explain/boundary_failed_v0_2.json",
    ),
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn airlock(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .current_dir(root())
        .env("HOME", home)
        .env_remove("USERPROFILE");
    command
}

fn explain(home: &Path, manifest: &Path, json: bool) -> Output {
    let mut command = airlock(home);
    command.args(["explain", "--manifest"]).arg(manifest);
    if json {
        command.arg("--json");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "explain failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    output
}

fn text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn a_v0_2_manifest_explains_byte_for_byte_as_it_did_before_v0_3() {
    let home = tempdir().unwrap();

    for (manifest, human, machine) in V0_2_GOLDENS {
        assert_eq!(
            explain(home.path(), Path::new(manifest), false).stdout,
            fs::read(root().join(human)).unwrap(),
            "human output for {manifest}"
        );
        assert_eq!(
            explain(home.path(), Path::new(manifest), true).stdout,
            fs::read(root().join(machine)).unwrap(),
            "--json output for {manifest}"
        );
    }
}

#[test]
fn the_signed_golden_explains_with_its_signer_and_says_no_inventory_was_given() {
    let home = tempdir().unwrap();
    let manifest = Path::new("fixtures/clean_telemetry_only/expected_manifest_v0_3_signed.json");
    let on_disk = read_json(&root().join(manifest));
    let bytes_crossed = on_disk["bytes_crossed"].as_u64().unwrap();

    let human = text(&explain(home.path(), manifest, false));
    let machine = stdout_json(&explain(home.path(), manifest, true));

    assert!(
        human.contains(&format!("Bytes crossed: {bytes_crossed}\n")),
        "{human}"
    );
    assert!(
        human.contains(&format!(
            "Signature: ed25519 by {GOLDEN_FINGERPRINT} (explain does not check it; run airlock verify-manifest)\n"
        )),
        "{human}"
    );
    assert!(
        human.contains(
            "Left out of the request: not recorded (verify was not given a not-crossed inventory)\n"
        ),
        "{human}"
    );
    assert_eq!(machine["bytes_crossed"], bytes_crossed);
    assert_eq!(machine["attestation"], "self_attested");
    assert_eq!(machine["not_crossed"], Value::Null);
    assert_eq!(
        machine["signature"],
        json!({
            "algorithm": "ed25519",
            "public_key_fingerprint": GOLDEN_FINGERPRINT,
            "checked": false
        })
    );
    // The signature bytes themselves are not repeated.
    assert!(
        !machine
            .to_string()
            .contains(on_disk["signature"]["value"].as_str().unwrap())
    );
}

#[test]
fn an_unsigned_v0_3_manifest_explains_as_unsigned() {
    let home = tempdir().unwrap();
    let manifest = Path::new("fixtures/clean_telemetry_only/expected_manifest_v0_3.json");

    let human = text(&explain(home.path(), manifest, false));
    let machine = stdout_json(&explain(home.path(), manifest, true));

    assert!(
        human.contains("Signature: none (unsigned manifest)\n"),
        "{human}"
    );
    assert_eq!(machine["signature"], Value::Null);
}

/// Real keygen, real assemble over an input with two withheld fields, a signing verify that is
/// given the inventory, then explain.
#[test]
fn explain_after_a_real_signed_verify_names_the_signer_and_what_was_left_out() {
    let home = tempdir().unwrap();
    let work = tempdir().unwrap();
    let annotated = root().join("fixtures/annotated_mode");

    let keygen = airlock(home.path()).arg("keygen").output().unwrap();
    assert!(keygen.status.success());
    let fingerprint = stdout_json(&keygen)["public_key_fingerprint"]
        .as_str()
        .unwrap()
        .to_string();

    let mut space = read_json(&annotated.join("strategy_space.json"));
    space["operator_note"] = json!(OPERATOR_NOTE);
    space["html_path"] = json!(HTML_PATH);
    let input = work.path().join("strategy_space_extended.json");
    fs::write(&input, serde_json::to_vec(&space).unwrap()).unwrap();

    let prompt = work.path().join("prompt.json");
    let provenance = work.path().join("provenance.json");
    let inventory = work.path().join("not_crossed.json");
    let assemble = airlock(home.path())
        .args(["assemble", "--policy"])
        .arg(annotated.join("policy.yaml"))
        .arg("--input")
        .arg(&input)
        .arg("--system-prompt")
        .arg(annotated.join("system_prompt.txt"))
        .args(["--boundary-mode", "ANNOTATED", "--out"])
        .arg(&prompt)
        .arg("--provenance-out")
        .arg(&provenance)
        .arg("--not-crossed-out")
        .arg(&inventory)
        .arg("--no-witness")
        .output()
        .unwrap();
    assert!(assemble.status.success(), "{}", text(&assemble));

    let manifest = work.path().join("manifest.json");
    let verify = airlock(home.path())
        .args(["verify", "--policy"])
        .arg(annotated.join("policy.yaml"))
        .arg("--prompt")
        .arg(&prompt)
        .arg("--provenance")
        .arg(&provenance)
        .arg("--request")
        .arg(annotated.join("request.json"))
        .arg("--not-crossed")
        .arg(&inventory)
        .arg("--out")
        .arg(&manifest)
        .arg("--no-witness")
        .output()
        .unwrap();
    assert!(verify.status.success(), "{}", text(&verify));
    let written = read_json(&manifest);
    assert!(
        written.get("signature").is_some(),
        "verify must have signed"
    );

    let human_output = explain(home.path(), &manifest, false);
    let machine_output = explain(home.path(), &manifest, true);
    let human = text(&human_output);
    let machine = stdout_json(&machine_output);

    assert!(
        human.contains(&format!(
            "Bytes crossed: {}\n",
            written["bytes_crossed"].as_u64().unwrap()
        )),
        "{human}"
    );
    assert!(
        human.contains(&format!(
            "Signature: ed25519 by {fingerprint} (explain does not check it; run airlock verify-manifest)\n"
        )),
        "{human}"
    );
    assert!(
        human.contains(&format!(
            "Left out of the request: 2 fields (values are never stored):\n  - html_path [FORBIDDEN_KEY] {HTML_PATH_HASH}\n  - operator_note [NOT_ALLOWED] {OPERATOR_NOTE_HASH}\n"
        )),
        "{human}"
    );
    assert_eq!(machine["signature"]["public_key_fingerprint"], fingerprint);
    assert_eq!(machine["bytes_crossed"], written["bytes_crossed"]);
    assert_eq!(machine["not_crossed"], written["not_crossed"]);
    let reasons: Vec<(&str, &str, &str)> = machine["not_crossed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["path"].as_str().unwrap(),
                entry["reason"].as_str().unwrap(),
                entry["value_hash"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        reasons,
        [
            ("html_path", "FORBIDDEN_KEY", HTML_PATH_HASH),
            ("operator_note", "NOT_ALLOWED", OPERATOR_NOTE_HASH),
        ]
    );

    // The withheld values reach neither rendering.
    for output in [&human_output, &machine_output] {
        let all = text(output);
        assert!(!all.contains(OPERATOR_NOTE), "{all}");
        assert!(!all.contains(HTML_PATH), "{all}");
    }
}
