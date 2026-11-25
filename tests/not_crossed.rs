//! The negative inventory, end to end through the real binary: `assemble --not-crossed-out`
//! writes what stayed behind, `verify --not-crossed` copies it into a v0.3 manifest, and
//! neither ever stores a withheld value.
//!
//! Expected hashes here were computed with Python's `blake3` and `json.dumps(sort_keys=True,
//! separators=(",", ":"))`, not with this crate, over ASCII values whose canonical form is
//! the same under RFC 8785.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use jsonschema::validator_for;
use serde_json::{Value, json};

const OPERATOR_NOTE: &str = "internal note: do not send";
const OPERATOR_NOTE_HASH: &str =
    "blake3:e492e079dfe5a48a0b35ecfe64592fdde152b4d1a00f577e649d06a47a80bf24";
const HTML_PATH: &str = "/srv/filings/page.html";
const HTML_PATH_HASH: &str =
    "blake3:9451fdbc050c92f3b1a85eeff05008d21842ec179d2e02eaefe355f1b0c226de";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> PathBuf {
    root().join("fixtures/annotated_mode").join(name)
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn schema(name: &str) -> jsonschema::Validator {
    validator_for(&read_json(&root().join("schemas").join(name))).unwrap()
}

struct Assembled {
    dir: tempfile::TempDir,
    prompt: PathBuf,
    provenance: PathBuf,
    not_crossed: PathBuf,
    stdout: Vec<u8>,
}

/// Assemble the annotated fixture's policy over `input` with an inventory sidecar.
fn assemble(input: &Path, mode: &str) -> Assembled {
    let dir = tempfile::tempdir().unwrap();
    let prompt = dir.path().join("prompt.json");
    let provenance = dir.path().join("provenance.json");
    let not_crossed = dir.path().join("not_crossed.json");
    let output = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(["assemble", "--policy"])
        .arg(fixture("policy.yaml"))
        .arg("--input")
        .arg(input)
        .arg("--system-prompt")
        .arg(fixture("system_prompt.txt"))
        .args(["--boundary-mode", mode, "--out"])
        .arg(&prompt)
        .arg("--provenance-out")
        .arg(&provenance)
        .arg("--not-crossed-out")
        .arg(&not_crossed)
        .arg("--no-witness")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "assemble failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    Assembled {
        dir,
        prompt,
        provenance,
        not_crossed,
        stdout: output.stdout,
    }
}

/// The fixture's strategy space with two extra fields: one nothing allows and one the policy
/// forbids by name.
fn extended_input(dir: &Path) -> PathBuf {
    let mut space = read_json(&fixture("strategy_space.json"));
    space["operator_note"] = json!(OPERATOR_NOTE);
    space["html_path"] = json!(HTML_PATH);
    let path = dir.join("strategy_space_extended.json");
    std::fs::write(&path, serde_json::to_vec(&space).unwrap()).unwrap();
    path
}

fn verify(assembled: &Assembled, not_crossed: Option<&Path>, out: &Path) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .args(["verify", "--no-sign", "--policy"])
        .arg(fixture("policy.yaml"))
        .arg("--prompt")
        .arg(&assembled.prompt)
        .arg("--provenance")
        .arg(&assembled.provenance)
        .arg("--request")
        .arg(fixture("request.json"))
        .arg("--out")
        .arg(out)
        .arg("--no-witness");
    if let Some(path) = not_crossed {
        command.arg("--not-crossed").arg(path);
    }
    command.output().unwrap()
}

#[test]
fn telemetry_only_assembly_records_the_derived_text_it_withheld() {
    let assembled = assemble(&fixture("strategy_space.json"), "TELEMETRY_ONLY");

    let inventory = read_json(&assembled.not_crossed);

    assert_eq!(inventory["version"], "airlock.not_crossed.v1");
    assert_eq!(inventory["boundary_mode"], "TELEMETRY_ONLY");
    assert_eq!(
        inventory["entries"],
        read_json(&fixture("expected_not_crossed_telemetry_only.json"))
    );
    // It names the policy and the payload it belongs to.
    assert_eq!(
        inventory["policy_hash"],
        read_json(&fixture("expected_manifest.json"))["policy_hash"]
    );
    assert_eq!(
        inventory["prompt_payload_hash"],
        airlock::hash::blake3_hash(&assembled.stdout)
    );
    assert!(
        schema("airlock_not_crossed.v1.schema.json").is_valid(&inventory),
        "the inventory must validate against its schema"
    );
}

#[test]
fn an_assembly_that_leaves_nothing_out_records_an_empty_inventory_not_a_missing_one() {
    let assembled = assemble(&fixture("strategy_space.json"), "ANNOTATED");

    let inventory = read_json(&assembled.not_crossed);

    assert_eq!(inventory["entries"], json!([]));
    assert!(schema("airlock_not_crossed.v1.schema.json").is_valid(&inventory));
}

#[test]
fn assemble_writes_no_inventory_unless_asked() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(["assemble", "--policy"])
        .arg(fixture("policy.yaml"))
        .arg("--input")
        .arg(fixture("strategy_space.json"))
        .arg("--out")
        .arg(dir.path().join("prompt.json"))
        .arg("--provenance-out")
        .arg(dir.path().join("provenance.json"))
        .arg("--no-witness")
        .output()
        .unwrap();
    assert!(output.status.success());

    let mut written: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    written.sort();
    assert_eq!(written, ["prompt.json", "provenance.json"]);
}

#[test]
fn verify_copies_the_inventory_into_a_v0_3_manifest_that_validates() {
    let scratch = tempfile::tempdir().unwrap();
    let assembled = assemble(&extended_input(scratch.path()), "ANNOTATED");
    let out = assembled.dir.path().join("manifest.json");

    let output = verify(&assembled, Some(&assembled.not_crossed), &out);

    assert!(
        output.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let manifest = read_json(&out);
    let inventory = read_json(&assembled.not_crossed);
    assert_eq!(manifest["manifest_version"], "airlock.v0.3");
    assert_eq!(manifest["not_crossed"], inventory["entries"]);

    // html_path is forbidden by name, operator_note is simply not allowed; sorted by path.
    let source = inventory["entries"][0]["source_artifact_hash"].clone();
    assert_eq!(
        manifest["not_crossed"],
        json!([
            {
                "path": "html_path",
                "reason": "FORBIDDEN_KEY",
                "source_artifact_hash": source,
                "value_hash": HTML_PATH_HASH,
            },
            {
                "path": "operator_note",
                "reason": "NOT_ALLOWED",
                "source_artifact_hash": source,
                "value_hash": OPERATOR_NOTE_HASH,
            },
        ])
    );
    assert!(
        schema("airlock.v0.schema.json").is_valid(&manifest),
        "the manifest must validate against the manifest schema"
    );
}

#[test]
fn no_withheld_value_is_stored_in_the_inventory_or_the_manifest() {
    let scratch = tempfile::tempdir().unwrap();
    let assembled = assemble(&extended_input(scratch.path()), "TELEMETRY_ONLY");
    let sidecar = std::fs::read_to_string(&assembled.not_crossed).unwrap();
    let observation =
        read_json(&fixture("strategy_space.json"))["mutator_context"]["challenge_observation"]
            .as_str()
            .unwrap()
            .to_owned();
    assert!(!observation.is_empty());

    for value in [OPERATOR_NOTE, HTML_PATH, observation.as_str()] {
        assert!(
            !sidecar.contains(value),
            "{value:?} leaked into the sidecar"
        );
    }
}

#[test]
fn verify_without_an_inventory_records_none() {
    let assembled = assemble(&fixture("strategy_space.json"), "ANNOTATED");
    let out = assembled.dir.path().join("manifest.json");

    let output = verify(&assembled, None, &out);

    assert!(output.status.success());
    let manifest = read_json(&out);
    assert!(
        manifest.get("not_crossed").is_none(),
        "no inventory was supplied, so none may be claimed, not even an empty one"
    );
    assert!(schema("airlock.v0.schema.json").is_valid(&manifest));
}

fn refusal_code(output: &Output) -> (Option<i32>, String) {
    let refusal: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    (
        output.status.code(),
        refusal["refusal"]["code"].as_str().unwrap_or("").to_owned(),
    )
}

#[test]
fn verify_refuses_an_inventory_that_does_not_belong_to_the_run_or_is_malformed() {
    let assembled = assemble(&fixture("strategy_space.json"), "TELEMETRY_ONLY");
    let valid = read_json(&assembled.not_crossed);
    let entry_hash = "blake3:0000000000000000000000000000000000000000000000000000000000000001";

    let mut cases: Vec<(&str, Value)> = Vec::new();
    for (label, field, value) in [
        ("other policy", "policy_hash", json!(entry_hash)),
        ("other payload", "prompt_payload_hash", json!(entry_hash)),
        ("other mode", "boundary_mode", json!("ANNOTATED")),
        ("other version", "version", json!("airlock.not_crossed.v2")),
        ("smuggled field", "raw_value", json!("a withheld value")),
    ] {
        let mut changed = valid.clone();
        changed[field] = value;
        cases.push((label, changed));
    }
    let mut bad_hash = valid.clone();
    bad_hash["entries"][0]["value_hash"] = json!("sha256:abc");
    cases.push(("malformed value hash", bad_hash));
    let mut empty_path = valid.clone();
    empty_path["entries"][0]["path"] = json!("");
    cases.push(("empty path", empty_path));
    let mut bad_reason = valid.clone();
    bad_reason["entries"][0]["reason"] = json!("BECAUSE");
    cases.push(("unknown reason", bad_reason));

    for (label, inventory) in cases {
        let path = assembled.dir.path().join("tampered.json");
        std::fs::write(&path, serde_json::to_vec(&inventory).unwrap()).unwrap();
        let out = assembled
            .dir
            .path()
            .join(format!("{}.json", label.replace(' ', "_")));

        let output = verify(&assembled, Some(&path), &out);

        assert_eq!(
            refusal_code(&output),
            (Some(2), "E_BAD_PROVENANCE".to_owned()),
            "{label}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            !out.exists(),
            "{label}: a refused run must not write a manifest"
        );
    }

    let not_json = assembled.dir.path().join("not_json.json");
    std::fs::write(&not_json, b"{not json").unwrap();
    let output = verify(
        &assembled,
        Some(&not_json),
        &assembled.dir.path().join("m.json"),
    );
    assert_eq!(
        refusal_code(&output),
        (Some(2), "E_BAD_PROVENANCE".to_owned())
    );

    let missing = assembled.dir.path().join("absent.json");
    let output = verify(
        &assembled,
        Some(&missing),
        &assembled.dir.path().join("m.json"),
    );
    assert_eq!(
        refusal_code(&output),
        (Some(2), "E_MISSING_FILE".to_owned())
    );
}

#[test]
fn the_inventory_schema_rejects_extra_fields_and_unknown_reasons() {
    let assembled = assemble(&fixture("strategy_space.json"), "TELEMETRY_ONLY");
    let validator = schema("airlock_not_crossed.v1.schema.json");
    let valid = read_json(&assembled.not_crossed);
    assert!(validator.is_valid(&valid));

    let mut extra = valid.clone();
    extra["raw_value"] = json!("x");
    assert!(!validator.is_valid(&extra));
    let mut entry_extra = valid.clone();
    entry_extra["entries"][0]["value"] = json!("x");
    assert!(!validator.is_valid(&entry_extra));
    let mut reason = valid.clone();
    reason["entries"][0]["reason"] = json!("BECAUSE");
    assert!(!validator.is_valid(&reason));
}
