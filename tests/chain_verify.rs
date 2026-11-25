//! `airlock chain verify`, end to end through the real binary.
//!
//! Every chain here is built by the real `assemble` and `verify`: turn 0 has no chain, each
//! later turn follows the one before with `--prior-manifest`. The receipts are hand-built in
//! the shape `airlock gate` writes (the gate's receipt is unsigned); the chain of receipts a real
//! gate wrote is checked in `a_three_turn_chain_runs_through_the_real_gate_with_v0_4_manifests`
//! in `tests/chain_model_output.rs`, which ends by running `chain verify` over it.
//!
//! Each turn gets its own reply text, so each response hash is different and a receipt for the
//! wrong response is distinguishable from the right one.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use airlock::assembler::PromptProvenance;
use airlock::hash::blake3_hash;
use airlock::manifest::AirlockManifest;
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

const GOLDEN_SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const GOLDEN_PUBLIC_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const ZERO_HASH: &str = "blake3:0000000000000000000000000000000000000000000000000000000000000000";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

/// The hash the gate computes for the manifest at `path`.
fn gate_hash(path: &Path) -> String {
    serde_json::from_slice::<AirlockManifest>(&fs::read(path).unwrap())
        .unwrap()
        .hash()
}

fn provenance_hash(value: &Value) -> String {
    serde_json::from_value::<PromptProvenance>(value.clone())
        .unwrap()
        .hash()
}

fn home_with_golden_key() -> TempDir {
    let home = tempdir().unwrap();
    let dir = home.path().join(".cmdrvl/secrets/airlock");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("ed25519.key"), format!("{GOLDEN_SEED_HEX}\n")).unwrap();
    fs::write(dir.join("ed25519.pub"), format!("{GOLDEN_PUBLIC_HEX}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join("ed25519.key"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    home
}

fn public_key_of(home: &Path) -> PathBuf {
    home.join(".cmdrvl/secrets/airlock/ed25519.pub")
}

fn airlock(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .current_dir(root())
        .env("HOME", home)
        .env_remove("USERPROFILE");
    command
}

fn succeeded(output: &Output, what: &str) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{what}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The reply a model gave to turn `turn`, as the bytes a gate would hash.
fn reply_bytes(turn: usize) -> Vec<u8> {
    let mut reply = read_json(&root().join("fixtures/chain/anthropic_messages_reply.json"));
    reply["content"][1]["text"] = json!(format!("This is the reply to turn {turn}."));
    serde_json::to_vec(&reply).unwrap()
}

fn receipt(response: &[u8], matched_manifest_hash: &str) -> Value {
    json!({
        "gate_version": "airlock.gate.v1",
        "mode": "strict-manifest",
        "achieved_claim": "STRICT_TELEMETRY_ONLY",
        "request_hash": blake3_hash(b"fixture request"),
        "response_hash": blake3_hash(response),
        "upstream_status": 200,
        "blocked": false,
        "findings": [],
        "timestamp": "2026-11-25T00:00:00Z",
        "matched_manifest_hash": matched_manifest_hash,
    })
}

/// A conversation on disk: the manifest library (manifests and provenance files, as
/// `--manifest-dir` wants them) and a directory of receipts.
struct World {
    dir: TempDir,
    home: TempDir,
    lib: PathBuf,
    receipts: PathBuf,
    turns: usize,
}

impl World {
    /// `turns` turns, numbered from 0; `signed` signs every manifest with the golden key.
    fn build(turns: usize, signed: bool) -> World {
        let dir = tempdir().unwrap();
        let lib = dir.path().join("lib");
        let receipts = dir.path().join("receipts");
        fs::create_dir(&lib).unwrap();
        fs::create_dir(&receipts).unwrap();
        let world = World {
            dir,
            home: home_with_golden_key(),
            lib,
            receipts,
            turns,
        };
        for turn in 0..turns {
            world.add_turn(turn, signed);
        }
        world
    }

    fn manifest(&self, turn: usize) -> PathBuf {
        self.lib.join(format!("turn{turn}.manifest.json"))
    }

    fn provenance(&self, turn: usize) -> PathBuf {
        self.lib.join(format!("turn{turn}.provenance.json"))
    }

    /// The receipt that vouches for the response turn `turn` follows (it names manifest
    /// `turn - 1`).
    fn receipt(&self, turn: usize) -> PathBuf {
        self.receipts.join(format!("turn{turn}.receipt.json"))
    }

    fn add_turn(&self, turn: usize, signed: bool) {
        let stem = format!("turn{turn}");
        let prompt = self.dir.path().join(format!("{stem}.prompt.json"));
        let provenance = self.provenance(turn);
        let mut assemble = airlock(self.home.path());
        assemble
            .args(["assemble", "--policy"])
            .arg(root().join("fixtures/chain/policy.yaml"))
            .arg("--input")
            .arg(root().join("fixtures/annotated_mode/strategy_space.json"))
            .arg("--system-prompt")
            .arg(root().join("fixtures/annotated_mode/system_prompt.txt"))
            .args(["--boundary-mode", "TELEMETRY_ONLY", "--out"])
            .arg(&prompt)
            .arg("--provenance-out")
            .arg(&provenance)
            .arg("--no-witness");
        if turn > 0 {
            let reply = reply_bytes(turn - 1);
            let reply_path = self.dir.path().join(format!("{stem}.reply.json"));
            fs::write(&reply_path, &reply).unwrap();
            write_json(
                &self.receipt(turn),
                &receipt(&reply, &gate_hash(&self.manifest(turn - 1))),
            );
            assemble
                .arg("--prior-receipt")
                .arg(self.receipt(turn))
                .arg("--response")
                .arg(&reply_path)
                .args(["--response-adapter", "anthropic_messages"])
                .arg("--prior-manifest")
                .arg(self.manifest(turn - 1));
        }
        succeeded(&assemble.output().unwrap(), &format!("assemble {stem}"));

        let request = json!({
            "model": "gpt-5",
            "messages": read_json(&prompt)["messages"].clone(),
        });
        let request_path = self.dir.path().join(format!("{stem}.request.json"));
        write_json(&request_path, &request);
        let mut verify = airlock(self.home.path());
        verify
            .args(["verify", "--policy"])
            .arg(root().join("fixtures/chain/policy.yaml"))
            .arg("--prompt")
            .arg(&prompt)
            .arg("--provenance")
            .arg(&provenance)
            .arg("--request")
            .arg(&request_path)
            .arg("--out")
            .arg(self.manifest(turn))
            .arg("--no-witness");
        if !signed {
            verify.arg("--no-sign");
        }
        succeeded(&verify.output().unwrap(), &format!("verify {stem}"));
    }

    fn last(&self) -> PathBuf {
        self.manifest(self.turns - 1)
    }

    /// `chain verify ENTRY` over this world, with the receipts and the golden key when asked.
    fn chain_verify(
        &self,
        entry: &Path,
        receipts: bool,
        pubkey: Option<&Path>,
    ) -> (Option<i32>, Value) {
        let mut command = airlock(self.home.path());
        command
            .args(["chain", "verify"])
            .arg(entry)
            .arg("--manifest-dir")
            .arg(&self.lib);
        if receipts {
            command.arg("--receipt-dir").arg(&self.receipts);
        }
        if let Some(key) = pubkey {
            command.arg("--pubkey").arg(key);
        }
        let output = command.output().unwrap();
        let body = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "stdout is not one JSON document ({error}): {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code(), body)
    }

    fn key(&self) -> PathBuf {
        public_key_of(self.home.path())
    }

    /// Refuse expected: the `detail` of the refusal, after checking the exit code and wire code.
    fn refusal(&self, entry: &Path, receipts: bool, pubkey: Option<&Path>, reason: &str) -> Value {
        let (code, body) = self.chain_verify(entry, receipts, pubkey);
        assert_eq!(code, Some(2), "{reason}: {body}");
        assert_eq!(
            body["refusal"]["code"], "E_BAD_MANIFEST",
            "{reason}: {body}"
        );
        assert_eq!(body["refusal"]["detail"]["reason"], reason, "{body}");
        body["refusal"]["detail"].clone()
    }
}

#[test]
fn a_three_turn_chain_verifies_with_its_receipts_and_signatures() {
    let world = World::build(3, true);
    let key = world.key();
    let (code, report) = world.chain_verify(&world.last(), true, Some(&key));
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["command"], "chain verify");
    assert_eq!(report["verified"], true);
    assert_eq!(report["turn_index"], 2);
    assert_eq!(report["receipts_checked"], true);
    assert_eq!(report["signatures_checked"], true);

    let links = report["links"].as_array().unwrap();
    assert_eq!(links.len(), 2, "turn 2 and turn 1 each carry a link");
    for (position, expected_turn) in [2usize, 1].into_iter().enumerate() {
        let link = &links[position];
        assert_eq!(link["turn_index"], expected_turn, "{link}");
        assert_eq!(
            link["manifest_hash"],
            gate_hash(&world.manifest(expected_turn)).as_str()
        );
        assert_eq!(
            link["prior_manifest_hash"],
            gate_hash(&world.manifest(expected_turn - 1)).as_str()
        );
        assert_eq!(
            link["response_hash"],
            blake3_hash(&reply_bytes(expected_turn - 1)).as_str(),
            "the response the turn admitted is the one the receipt records"
        );
        assert_eq!(
            link["receipt_file"],
            format!("turn{expected_turn}.receipt.json")
        );
        for check in [
            "prior_manifest",
            "turn_index",
            "provenance",
            "receipt",
            "signature",
        ] {
            assert_eq!(
                link["checks"][check], "ok",
                "{expected_turn} {check}: {link}"
            );
        }
    }
    assert_eq!(
        report["root"]["manifest_hash"],
        gate_hash(&world.manifest(0)).as_str()
    );
    assert_eq!(report["root"]["manifest_version"], "airlock.v0.3");
    assert_eq!(report["root"]["signature"], "ok");
    assert!(
        report["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|note| note.as_str().unwrap().contains("unsigned")),
        "every report says the gate receipt is unsigned: {report}"
    );
}

#[test]
fn what_was_not_checked_is_said_and_not_implied() {
    let world = World::build(3, false);
    let (code, report) = world.chain_verify(&world.last(), false, None);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["receipts_checked"], false);
    assert_eq!(report["signatures_checked"], false);
    for link in report["links"].as_array().unwrap() {
        assert_eq!(link["checks"]["receipt"], "not_checked", "{link}");
        assert_eq!(link["checks"]["signature"], "not_checked", "{link}");
        assert_eq!(link["receipt_file"], Value::Null);
        assert_eq!(link["checks"]["prior_manifest"], "ok");
        assert_eq!(link["checks"]["provenance"], "ok");
    }
    let notes = report["notes"].to_string();
    assert!(
        notes.contains("--receipt-dir") && notes.contains("--pubkey"),
        "{notes}"
    );
}

#[test]
fn an_unsigned_manifest_is_reported_unsigned_not_refused() {
    let world = World::build(2, false);
    let key = world.key();
    let (code, report) = world.chain_verify(&world.last(), true, Some(&key));
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["signatures_checked"], true);
    assert_eq!(report["links"][0]["checks"]["signature"], "unsigned");
    assert_eq!(report["root"]["signature"], "unsigned");
}

#[test]
fn a_turn_zero_manifest_verifies_with_nothing_to_walk() {
    let world = World::build(1, false);
    let (code, report) = world.chain_verify(&world.manifest(0), true, None);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["turn_index"], 0);
    assert_eq!(report["links"], json!([]));
    assert_eq!(
        report["root"]["manifest_hash"],
        gate_hash(&world.manifest(0)).as_str()
    );
}

#[test]
fn files_are_found_by_content_so_their_names_do_not_matter() {
    let world = World::build(3, false);
    // Every library file and receipt gets a name that says nothing.
    for (index, (from, to_dir)) in (0..3)
        .flat_map(|turn| {
            [
                (world.manifest(turn), &world.lib),
                (world.provenance(turn), &world.lib),
            ]
        })
        .chain((1..3).map(|turn| (world.receipt(turn), &world.receipts)))
        .enumerate()
    {
        if from == world.last() {
            continue; // the entry manifest is named on the command line
        }
        fs::rename(&from, to_dir.join(format!("{index:02}-anonymous.json"))).unwrap();
    }
    let (code, report) = world.chain_verify(&world.last(), true, None);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["links"].as_array().unwrap().len(), 2);
}

#[test]
fn a_manifests_own_provenance_ref_is_not_trusted() {
    let world = World::build(2, false);
    let mut entry = read_json(&world.last());
    entry["prompt_provenance_ref"] = json!("a/path/that/does/not/exist.json");
    write_json(&world.last(), &entry);
    let (code, report) = world.chain_verify(&world.last(), true, None);
    assert_eq!(
        code,
        Some(0),
        "the provenance is found by its hash, not by the ref: {report}"
    );
}

#[test]
fn a_legacy_manifest_can_be_the_root_of_a_chain() {
    let world = World::build(1, false);
    // A v0.2 manifest the old verify wrote, as the library's turn 0.
    let legacy = root().join("fixtures/clean_telemetry_only/expected_manifest.json");
    fs::copy(&legacy, world.manifest(0)).unwrap();
    world.add_turn(1, false);
    let (code, report) = world.chain_verify(&world.manifest(1), true, None);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["root"]["manifest_version"], "airlock.v0.2");
    assert_eq!(report["links"].as_array().unwrap().len(), 1);
}

#[test]
fn a_missing_prior_manifest_is_refused_with_the_hash_that_was_wanted() {
    let world = World::build(3, false);
    let wanted = gate_hash(&world.manifest(1));
    fs::rename(world.manifest(1), world.dir.path().join("elsewhere.json")).unwrap();
    let detail = world.refusal(&world.last(), true, None, "prior_manifest_not_found");
    assert_eq!(detail["turn_index"], 2);
    assert_eq!(detail["prior_manifest_hash"], wanted.as_str());
    assert_eq!(detail["manifest_hash"], gate_hash(&world.last()).as_str());
}

#[test]
fn a_link_whose_index_does_not_follow_its_prior_is_refused() {
    let world = World::build(3, false);
    let mut entry = read_json(&world.last());
    entry["chain"]["turn_index"] = json!(5);
    write_json(&world.last(), &entry);
    let detail = world.refusal(&world.last(), true, None, "turn_index_mismatch");
    assert_eq!(detail["turn_index"], 5);
    assert_eq!(detail["expected_turn_index"], 2);
}

#[test]
fn a_manifest_that_breaks_the_chain_member_rule_is_refused() {
    let world = World::build(2, false);
    // v0.4 without its chain member: it would read as a root.
    let mut entry = read_json(&world.last());
    entry.as_object_mut().unwrap().remove("chain");
    write_json(&world.last(), &entry);
    let detail = world.refusal(&world.last(), true, None, "chain_shape");
    assert_eq!(detail["manifest_version"], "airlock.v0.4");

    // The same manifest as v0.3 with a chain member.
    let mut v0_3_with = read_json(&world.manifest(0));
    v0_3_with["chain"] = json!({"prior_manifest_hash": ZERO_HASH, "turn_index": 1});
    write_json(&world.last(), &v0_3_with);
    world.refusal(&world.last(), true, None, "chain_shape");
}

#[test]
fn a_provenance_that_cannot_be_found_is_refused() {
    let world = World::build(2, false);
    let wanted = read_json(&world.last())["prompt_provenance_hash"].clone();
    fs::rename(world.provenance(1), world.dir.path().join("elsewhere.json")).unwrap();
    let detail = world.refusal(&world.last(), true, None, "provenance_not_found");
    assert_eq!(detail["prompt_provenance_hash"], wanted);
}

/// Replace turn `turn`'s provenance with `edit` of it and point the manifest at the new one, so
/// the manifest and its provenance still agree about the hash: only what is inside differs.
fn edit_provenance(world: &World, turn: usize, edit: impl FnOnce(&mut Value)) {
    let mut provenance = read_json(&world.provenance(turn));
    edit(&mut provenance);
    write_json(&world.provenance(turn), &provenance);
    let mut manifest = read_json(&world.manifest(turn));
    manifest["prompt_provenance_hash"] = json!(provenance_hash(&provenance));
    write_json(&world.manifest(turn), &manifest);
}

#[test]
fn a_provenance_with_a_different_link_than_its_manifest_is_refused() {
    let world = World::build(2, false);
    edit_provenance(&world, 1, |provenance| {
        provenance["chain"]["turn_index"] = json!(9);
    });
    let detail = world.refusal(&world.last(), true, None, "provenance_chain_mismatch");
    assert_eq!(detail["manifest_chain"]["turn_index"], 1);
    assert_eq!(detail["provenance_chain"]["turn_index"], 9);
}

#[test]
fn a_turn_whose_provenance_names_no_response_or_two_is_refused() {
    let world = World::build(2, false);
    edit_provenance(&world, 1, |provenance| {
        let records = provenance["records"].as_array_mut().unwrap();
        records.retain(|record| record["policy_rule_id"] != "chain.model_output");
    });
    world.refusal(&world.last(), true, None, "model_output_hash_missing");

    let world = World::build(2, false);
    edit_provenance(&world, 1, |provenance| {
        let record = provenance["records"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|record| record["policy_rule_id"] == "chain.model_output")
            .unwrap();
        record["source_artifact_hash"] = json!(ZERO_HASH);
    });
    let detail = world.refusal(&world.last(), true, None, "model_output_hash_ambiguous");
    assert!(detail["response_hashes"].as_array().unwrap().len() >= 2);
}

#[test]
fn a_link_with_no_receipt_naming_its_prior_manifest_is_refused() {
    let world = World::build(3, false);
    fs::rename(world.receipt(2), world.dir.path().join("elsewhere.json")).unwrap();
    let detail = world.refusal(&world.last(), true, None, "receipt_not_found");
    assert_eq!(
        detail["prior_manifest_hash"],
        gate_hash(&world.manifest(1)).as_str()
    );
    assert_eq!(detail["turn_index"], 2);
}

#[test]
fn a_receipt_for_a_different_response_is_refused_with_the_hashes_it_does_record() {
    let world = World::build(3, false);
    let other = blake3_hash(&reply_bytes(99));
    write_json(
        &world.receipt(2),
        &receipt(&reply_bytes(99), &gate_hash(&world.manifest(1))),
    );
    let detail = world.refusal(&world.last(), true, None, "receipt_response_mismatch");
    assert_eq!(detail["receipt_response_hashes"], json!([other]));
    assert_eq!(
        detail["response_hash"],
        blake3_hash(&reply_bytes(1)).as_str(),
        "the hash the turn admitted"
    );
}

#[test]
fn a_receipt_for_the_right_response_that_names_another_manifest_does_not_count() {
    let world = World::build(3, false);
    // Turn 2 admitted the reply to turn 1; this receipt records exactly that reply but says the
    // gate matched manifest 0, not manifest 1, so it vouches for a different request.
    write_json(
        &world.receipt(2),
        &receipt(&reply_bytes(1), &gate_hash(&world.manifest(0))),
    );
    let detail = world.refusal(&world.last(), true, None, "receipt_not_found");
    assert_eq!(
        detail["prior_manifest_hash"],
        gate_hash(&world.manifest(1)).as_str()
    );
    assert_eq!(
        detail["response_hash"],
        blake3_hash(&reply_bytes(1)).as_str()
    );
}

#[test]
fn a_receipt_that_is_not_an_admitted_success_does_not_count() {
    for (label, edit) in [
        (
            "blocked",
            (|r: &mut Value| r["blocked"] = json!(true)) as fn(&mut Value),
        ),
        ("upstream 500", |r| r["upstream_status"] = json!(500)),
        ("wrong version", |r| {
            r["gate_version"] = json!("airlock.gate.v0")
        }),
        ("no matched manifest", |r| {
            r.as_object_mut().unwrap().remove("matched_manifest_hash");
        }),
    ] {
        let world = World::build(2, false);
        let mut found = read_json(&world.receipt(1));
        edit(&mut found);
        write_json(&world.receipt(1), &found);
        let (code, body) = world.chain_verify(&world.last(), true, None);
        assert_eq!(code, Some(2), "{label}: {body}");
        assert_eq!(
            body["refusal"]["detail"]["reason"], "receipt_not_found",
            "{label}"
        );
    }
}

#[test]
fn among_several_receipts_for_one_manifest_the_one_for_the_admitted_response_is_found() {
    let world = World::build(2, false);
    // The gate forwarded the same request twice and the origin answered differently the first time.
    write_json(
        &world.receipts.join("a-earlier-different-answer.json"),
        &receipt(&reply_bytes(77), &gate_hash(&world.manifest(0))),
    );
    let (code, report) = world.chain_verify(&world.last(), true, None);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["links"][0]["receipt_file"], "turn1.receipt.json");
}

#[test]
fn a_signature_that_does_not_verify_is_refused_and_a_wrong_key_says_so() {
    let world = World::build(3, true);
    let key = world.key();

    // Tampered after signing, at the entry manifest and at the root.
    let mut entry = read_json(&world.last());
    entry["model_id"] = json!("a-different-model");
    write_json(&world.last(), &entry);
    let detail = world.refusal(&world.last(), true, Some(&key), "signature_invalid");
    assert_eq!(detail["signature_reason"], "signature_mismatch");
    assert_eq!(detail["turn_index"], 2);

    let world = World::build(1, true);
    let mut root_manifest = read_json(&world.manifest(0));
    root_manifest["model_id"] = json!("a-different-model");
    write_json(&world.manifest(0), &root_manifest);
    let detail = world.refusal(
        &world.manifest(0),
        true,
        Some(&world.key()),
        "signature_invalid",
    );
    assert_eq!(detail["turn_index"], 0);

    // Someone else's key.
    let world = World::build(2, true);
    let stranger = tempdir().unwrap();
    succeeded(
        &airlock(stranger.path()).arg("keygen").output().unwrap(),
        "keygen",
    );
    let detail = world.refusal(
        &world.last(),
        true,
        Some(&public_key_of(stranger.path())),
        "signature_invalid",
    );
    assert_eq!(detail["signature_reason"], "fingerprint_mismatch");

    // Without a key the same tampering is not looked for, and the report says so.
    let world = World::build(2, true);
    let mut entry = read_json(&world.last());
    entry["model_id"] = json!("a-different-model");
    write_json(&world.last(), &entry);
    let (code, report) = world.chain_verify(&world.last(), true, None);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["signatures_checked"], false);
}

#[test]
fn a_manifest_that_cannot_start_a_walk_is_refused_by_what_is_wrong_with_it() {
    let world = World::build(2, false);
    let bad = world.dir.path().join("bad.json");

    fs::write(&bad, b"not json").unwrap();
    let (code, body) = world.chain_verify(&bad, true, None);
    assert_eq!(
        (code, body["refusal"]["code"].as_str()),
        (Some(2), Some("E_BAD_MANIFEST"))
    );

    fs::write(&bad, b"{}").unwrap();
    world.refusal(&bad, true, None, "not_a_manifest");

    let mut future = read_json(&world.last());
    future["manifest_version"] = json!("airlock.v0.5");
    write_json(&bad, &future);
    world.refusal(&bad, true, None, "unsupported_manifest_version");

    let (code, body) = world.chain_verify(&world.dir.path().join("no-such.json"), true, None);
    assert_eq!(
        (code, body["refusal"]["code"].as_str()),
        (Some(2), Some("E_MISSING_FILE"))
    );
}

#[test]
fn directories_that_are_missing_or_not_directories_are_refused() {
    let world = World::build(2, false);
    let run = |manifest_dir: &Path, receipt_dir: Option<&Path>| {
        let mut command = airlock(world.home.path());
        command
            .args(["chain", "verify"])
            .arg(world.last())
            .arg("--manifest-dir")
            .arg(manifest_dir);
        if let Some(dir) = receipt_dir {
            command.arg("--receipt-dir").arg(dir);
        }
        let output = command.output().unwrap();
        let body: Value = serde_json::from_slice(&output.stdout).unwrap();
        (
            output.status.code(),
            body["refusal"]["code"].as_str().unwrap_or("").to_owned(),
        )
    };
    let missing = world.dir.path().join("no-such-dir");
    assert_eq!(run(&missing, None), (Some(2), "E_MISSING_FILE".to_owned()));
    assert_eq!(
        run(&world.lib, Some(&missing)),
        (Some(2), "E_MISSING_FILE".to_owned())
    );
    assert_eq!(
        run(&world.last(), None),
        (Some(2), "E_BAD_INPUT".to_owned()),
        "a file is not a directory"
    );
}

#[test]
fn chain_verify_writes_nothing_and_leaves_every_file_as_it_was() {
    let world = World::build(3, true);
    let snapshot = |dir: &Path| {
        let mut files: Vec<(String, Vec<u8>)> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (path.display().to_string(), fs::read(&path).unwrap())
            })
            .collect();
        files.sort();
        files
    };
    let before = (snapshot(&world.lib), snapshot(&world.receipts));
    let key = world.key();
    let (code, _) = world.chain_verify(&world.last(), true, Some(&key));
    assert_eq!(code, Some(0));
    assert_eq!(before, (snapshot(&world.lib), snapshot(&world.receipts)));
}
