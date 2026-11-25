//! The airlock.v0.4 goldens: a two-turn run through the real binary, compared byte for byte with
//! the manifests committed in `fixtures/chain/`.
//!
//! How the goldens were made, and what was checked without this crate (al-210 D-c):
//!
//! * Both turns ran in a fresh directory with relative file names and `SOURCE_DATE_EPOCH`
//!   1700000000, so the refs in the manifest (`turn1.provenance.json`, `turn1.request.json`) and
//!   the timestamp are fixed. Turn 0 has no chain member (airlock.v0.3). Turn 1 follows it with
//!   `--prior-manifest turn0.manifest.json`, the committed reply
//!   `fixtures/chain/anthropic_messages_reply.json` and a receipt.
//! * That receipt is hand-built in the shape `airlock gate` writes (the gate's receipt is
//!   unsigned). The real gate's receipt anchoring a chain is exercised by
//!   `a_three_turn_chain_runs_through_the_real_gate_with_v0_4_manifests` in
//!   `tests/chain_model_output.rs`; this file does not claim it.
//! * Recomputed in Python with `blake3`, `cryptography` and `json.dumps(sort_keys=True,
//!   separators=(",", ":"))` (the manifest is pure ASCII, so that is the RFC 8785 form):
//!   `chain.prior_manifest_hash` is the blake3 of the canonical turn-0 manifest;
//!   `prompt_provenance_hash` is the blake3 of the canonical turn-1 provenance with its chain
//!   member in it (and differs from the hash without it); and the signed golden is the unsigned
//!   one plus an Ed25519 signature over the canonical manifest without `signature`, made with the
//!   RFC 8032 section 7.1 test-1 seed. The signed manifest derived in Python equals the one
//!   `airlock verify` wrote, byte for byte. The gate's hash of each golden (the value a receipt's
//!   `matched_manifest_hash` and the next link's `prior_manifest_hash` carry) was computed the
//!   same way and is pinned below.
//!
//! Every test points HOME at a temp directory, so the real `~/.cmdrvl/secrets` is never read.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use airlock::hash::blake3_hash;
use airlock::manifest::AirlockManifest;
use jsonschema::validator_for;
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

const FIXED_EPOCH: &str = "1700000000";
const GOLDEN_SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const GOLDEN_PUBLIC_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> PathBuf {
    root().join("fixtures/chain").join(name)
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A home that already holds the RFC 8032 test-1 key pair.
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

fn airlock(cwd: &Path, home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .current_dir(cwd)
        .env("HOME", home)
        .env_remove("USERPROFILE")
        .env("SOURCE_DATE_EPOCH", FIXED_EPOCH);
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

fn assemble(cwd: &Path, home: &Path, stem: &str, chain: &[String]) {
    let output = airlock(cwd, home)
        .args(["assemble", "--policy"])
        .arg(fixture("policy.yaml"))
        .arg("--input")
        .arg(root().join("fixtures/annotated_mode/strategy_space.json"))
        .arg("--system-prompt")
        .arg(root().join("fixtures/annotated_mode/system_prompt.txt"))
        .args(["--boundary-mode", "TELEMETRY_ONLY", "--out"])
        .arg(format!("{stem}.prompt.json"))
        .arg("--provenance-out")
        .arg(format!("{stem}.provenance.json"))
        .arg("--no-witness")
        .args(chain)
        .output()
        .unwrap();
    succeeded(&output, &format!("assemble {stem}"));
}

/// `verify` the assembled `stem`; `signed` signs with the key in `home`, otherwise `--no-sign`.
fn verify(cwd: &Path, home: &Path, stem: &str, out: &str, signed: bool) {
    let prompt: Value = read_json(&cwd.join(format!("{stem}.prompt.json")));
    let request = json!({"model": "gpt-5", "messages": prompt["messages"].clone()});
    fs::write(
        cwd.join(format!("{stem}.request.json")),
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    let mut command = airlock(cwd, home);
    command
        .args(["verify", "--policy"])
        .arg(fixture("policy.yaml"))
        .args(["--prompt", &format!("{stem}.prompt.json")])
        .args(["--provenance", &format!("{stem}.provenance.json")])
        .args(["--request", &format!("{stem}.request.json")])
        .args(["--out", out, "--no-witness"]);
    if !signed {
        command.arg("--no-sign");
    }
    succeeded(&command.output().unwrap(), &format!("verify {stem}"));
}

/// Turn 0, then turn 1 following it. Returns the directory and the bytes of turn 1's manifest
/// (signed with the golden key when `signed`).
fn two_turns(signed: bool) -> (TempDir, Vec<u8>) {
    let dir = tempdir().unwrap();
    let home = home_with_golden_key();
    assemble(dir.path(), home.path(), "turn0", &[]);
    verify(
        dir.path(),
        home.path(),
        "turn0",
        "turn0.manifest.json",
        false,
    );

    let reply = fixture("anthropic_messages_reply.json");
    let turn0_hash = serde_json::from_slice::<AirlockManifest>(
        &fs::read(dir.path().join("turn0.manifest.json")).unwrap(),
    )
    .unwrap()
    .hash();
    let receipt = json!({
        "gate_version": "airlock.gate.v1",
        "mode": "strict-manifest",
        "achieved_claim": "STRICT_TELEMETRY_ONLY",
        "request_hash": blake3_hash(b"fixture request"),
        "response_hash": blake3_hash(&fs::read(&reply).unwrap()),
        "upstream_status": 200,
        "blocked": false,
        "findings": [],
        "timestamp": "2026-11-25T00:00:00Z",
        "matched_manifest_hash": turn0_hash,
    });
    fs::write(
        dir.path().join("turn1.receipt.json"),
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();

    assemble(
        dir.path(),
        home.path(),
        "turn1",
        &[
            "--prior-receipt".to_string(),
            "turn1.receipt.json".to_string(),
            "--response".to_string(),
            reply.display().to_string(),
            "--response-adapter".to_string(),
            "anthropic_messages".to_string(),
            "--prior-manifest".to_string(),
            "turn0.manifest.json".to_string(),
        ],
    );
    verify(
        dir.path(),
        home.path(),
        "turn1",
        "turn1.manifest.json",
        signed,
    );
    let bytes = fs::read(dir.path().join("turn1.manifest.json")).unwrap();
    (dir, bytes)
}

#[test]
fn the_unsigned_turn_one_manifest_is_byte_identical_to_the_golden() {
    let (dir, bytes) = two_turns(false);
    let golden = fs::read(fixture("expected_manifest_v0_4.json")).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&bytes),
        String::from_utf8_lossy(&golden),
        "turn 1 no longer matches fixtures/chain/expected_manifest_v0_4.json"
    );

    // Turn 0, which the golden follows, is the v0.3 manifest verify has always written.
    let turn0 = read_json(&dir.path().join("turn0.manifest.json"));
    assert_eq!(turn0["manifest_version"], "airlock.v0.3");
    assert!(turn0.get("chain").is_none());
    let golden = read_json(&fixture("expected_manifest_v0_4.json"));
    assert_eq!(golden["manifest_version"], "airlock.v0.4");
    assert_eq!(golden["chain"]["turn_index"], 1);
    assert_eq!(
        golden["chain"]["prior_manifest_hash"],
        serde_json::from_value::<AirlockManifest>(turn0)
            .unwrap()
            .hash()
            .as_str()
    );
}

#[test]
fn the_signed_turn_one_manifest_is_byte_identical_to_the_golden_and_verifies() {
    let (_dir, bytes) = two_turns(true);
    let golden = fs::read(fixture("expected_manifest_v0_4_signed.json")).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&bytes),
        String::from_utf8_lossy(&golden),
        "turn 1 no longer matches fixtures/chain/expected_manifest_v0_4_signed.json"
    );

    // The committed signed golden verifies against the golden public key.
    let home = home_with_golden_key();
    let output = airlock(&root(), home.path())
        .arg("verify-manifest")
        .arg(fixture("expected_manifest_v0_4_signed.json"))
        .arg("--pubkey")
        .arg(home.path().join(".cmdrvl/secrets/airlock/ed25519.pub"))
        .output()
        .unwrap();
    succeeded(&output, "verify-manifest on the signed v0.4 golden");
}

#[test]
fn the_signed_golden_is_the_unsigned_golden_plus_a_signature_and_nothing_else() {
    let unsigned = read_json(&fixture("expected_manifest_v0_4.json"));
    let mut signed = read_json(&fixture("expected_manifest_v0_4_signed.json"));
    let signature = signed
        .as_object_mut()
        .unwrap()
        .remove("signature")
        .expect("a signature");
    assert_eq!(signature["algorithm"], "ed25519");
    assert_eq!(
        signature["public_key_fingerprint"],
        "blake3:6c31041268f471609c79f5f2dbcc38e4a4ab2f4d416109a4e09fcf50fd0f0062"
    );
    assert_eq!(signed, unsigned, "the chain member is covered, not added");
}

/// The gate stamps `AirlockManifest::hash()` into receipts, and a chain link names it. These
/// literals were computed in Python, not by this crate (see the header): the blake3 of the
/// canonical JSON of each golden, signature included for the signed one. They are what makes
/// "the hash covers the chain member" an independently anchored fact. The gate and the library
/// share one hash function, so a test that only compared them with each other could not notice
/// both ignoring the member.
#[test]
fn the_gate_hash_of_each_golden_is_the_one_computed_without_this_crate() {
    // (golden, its hash, the hash the same manifest would have with the chain member removed)
    let expected = [
        (
            "expected_manifest_v0_4.json",
            "blake3:9c62263bc9f5cf3d05967382b4676721b60cdb0a6db416d7442d9de5cb20ce9d",
            "blake3:8d05a802dc858b3c61f6a00e6660f7e440150b56c0d899fd68e9193f991f489e",
        ),
        (
            "expected_manifest_v0_4_signed.json",
            "blake3:a6aa783f79934068a51103d601fd43257e4f6f477b72a17937fcb675f486e201",
            "blake3:7dac0dad727392cffd55ca34989c42ea20e577a0de416e4c9b89b1a5a52fa96a",
        ),
    ];
    for (name, with_chain, without_chain) in expected {
        let manifest: AirlockManifest =
            serde_json::from_slice(&fs::read(fixture(name)).unwrap()).unwrap();
        assert_eq!(manifest.hash(), with_chain, "{name}");
        assert_ne!(
            manifest.hash(),
            without_chain,
            "{name}: the hash must not be the one the manifest has without its chain member"
        );
    }
}

#[test]
fn both_goldens_validate_against_the_manifest_schema() {
    let schema = validator_for(&read_json(&root().join("schemas/airlock.v0.schema.json"))).unwrap();
    for name in [
        "expected_manifest_v0_4.json",
        "expected_manifest_v0_4_signed.json",
    ] {
        let manifest = read_json(&fixture(name));
        schema
            .validate(&manifest)
            .unwrap_or_else(|error| panic!("{name} fails its schema: {error}"));
    }
}

/// The control: input with no prior turn still yields the airlock.v0.3 manifest, with no chain
/// member, exactly as before this change. The golden is compared without its timestamp, which
/// it does not pin.
#[test]
fn a_run_with_no_prior_turn_still_matches_the_v0_3_golden() {
    let home = tempdir().unwrap();
    let fixtures = "fixtures/clean_telemetry_only";
    let out = tempdir().unwrap();
    let manifest_path = out.path().join("manifest.json");
    let output = airlock(&root(), home.path())
        .args([
            "verify",
            "--no-sign",
            "--no-witness",
            "--policy",
            &format!("{fixtures}/policy.yaml"),
            "--prompt",
            &format!("{fixtures}/expected_prompt_payload.json"),
            "--provenance",
            &format!("{fixtures}/expected_prompt_provenance.json"),
            "--request",
            &format!("{fixtures}/request.json"),
            "--out",
        ])
        .arg(&manifest_path)
        .output()
        .unwrap();
    succeeded(&output, "verify of the clean_telemetry_only fixture");
    let mut produced = read_json(&manifest_path);
    let mut golden = read_json(&root().join(fixtures).join("expected_manifest_v0_3.json"));
    for manifest in [&mut produced, &mut golden] {
        manifest.as_object_mut().unwrap().remove("timestamp");
    }
    assert_eq!(produced, golden);
    assert_eq!(produced["manifest_version"], "airlock.v0.3");
    assert!(produced.get("chain").is_none());
}
