//! Manifest signing, end to end through the real binary: `airlock keygen`, a signing
//! `airlock verify`, and `airlock verify-manifest`.
//!
//! Every test points HOME at a temp directory (and removes USERPROFILE), so the real
//! `~/.cmdrvl/secrets` is never read or written.
//!
//! `fixtures/clean_telemetry_only/expected_manifest_v0_3_signed.json` was not produced by this
//! crate. It was derived with Python's `cryptography` (Ed25519), `blake3` and
//! `json.dumps(sort_keys=True, separators=(",", ":"))` from the unsigned v0.3 golden, with its
//! timestamp set to 2023-11-14T22:13:20+00:00 (SOURCE_DATE_EPOCH 1700000000) and signed with the
//! RFC 8032 section 7.1 test-1 seed. The golden manifest is pure ASCII, so that canonical form is
//! the RFC 8785 form.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use jsonschema::validator_for;
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

const FIXED_EPOCH: &str = "1700000000";
const GOLDEN_SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const GOLDEN_PUBLIC_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const GOLDEN_FINGERPRINT: &str =
    "blake3:6c31041268f471609c79f5f2dbcc38e4a4ab2f4d416109a4e09fcf50fd0f0062";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn golden(name: &str) -> Value {
    read_json(&root().join("fixtures/clean_telemetry_only").join(name))
}

fn manifest_schema() -> jsonschema::Validator {
    validator_for(&read_json(&root().join("schemas/airlock.v0.schema.json"))).unwrap()
}

fn airlock(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .current_dir(root())
        .env("HOME", home)
        .env_remove("USERPROFILE")
        .env("SOURCE_DATE_EPOCH", FIXED_EPOCH);
    command
}

fn keys_dir(home: &Path) -> PathBuf {
    home.join(".cmdrvl").join("secrets").join("airlock")
}

fn keygen(home: &Path) -> Output {
    airlock(home).arg("keygen").output().unwrap()
}

fn verify(home: &Path, out: &Path, extra: &[&str]) -> Output {
    let fixtures = "fixtures/clean_telemetry_only";
    airlock(home)
        .args([
            "verify",
            "--policy",
            &format!("{fixtures}/policy.yaml"),
            "--prompt",
            &format!("{fixtures}/expected_prompt_payload.json"),
            "--provenance",
            &format!("{fixtures}/expected_prompt_provenance.json"),
            "--request",
            &format!("{fixtures}/request.json"),
            "--no-witness",
            "--out",
        ])
        .arg(out)
        .args(extra)
        .output()
        .unwrap()
}

fn verify_manifest(home: &Path, manifest: &Path, pubkey: Option<&Path>) -> Output {
    let mut command = airlock(home);
    command.arg("verify-manifest").arg(manifest);
    if let Some(pubkey) = pubkey {
        command.arg("--pubkey").arg(pubkey);
    }
    command.output().unwrap()
}

fn stdout_json(output: &Output) -> Value {
    let parsed = serde_json::from_slice(&output.stdout);
    assert!(
        parsed.is_ok(),
        "stdout is not JSON: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    parsed.unwrap()
}

/// (exit code, refusal code, detail.reason)
fn refusal(output: &Output) -> (Option<i32>, String, String) {
    let body = stdout_json(output);
    (
        output.status.code(),
        body["refusal"]["code"].as_str().unwrap_or("").to_owned(),
        body["refusal"]["detail"]["reason"]
            .as_str()
            .unwrap_or("")
            .to_owned(),
    )
}

/// A home directory that already holds the RFC 8032 test-1 key pair.
fn home_with_golden_key() -> TempDir {
    let home = tempdir().unwrap();
    let dir = keys_dir(home.path());
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("ed25519.key"), format!("{GOLDEN_SEED_HEX}\n")).unwrap();
    fs::write(dir.join("ed25519.pub"), format!("{GOLDEN_PUBLIC_HEX}\n")).unwrap();
    restrict(&dir.join("ed25519.key"), 0o600);
    home
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) {}

/// A signed manifest made with a freshly generated key in its own home.
struct Signed {
    home: TempDir,
    manifest: PathBuf,
    fingerprint: String,
}

fn signed_with_a_fresh_key() -> Signed {
    let home = tempdir().unwrap();
    let generated = keygen(home.path());
    assert!(generated.status.success(), "{generated:?}");
    let fingerprint = stdout_json(&generated)["public_key_fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    let manifest = home.path().join("manifest.json");
    let output = verify(home.path(), &manifest, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    Signed {
        home,
        manifest,
        fingerprint,
    }
}

#[test]
fn keygen_writes_an_owner_only_pair_under_home_and_never_prints_the_secret() {
    let home = tempdir().unwrap();

    let output = keygen(home.path());

    assert!(output.status.success(), "{output:?}");
    let report = stdout_json(&output);
    let dir = keys_dir(home.path());
    let secret = fs::read_to_string(dir.join("ed25519.key")).unwrap();
    let public = fs::read_to_string(dir.join("ed25519.pub")).unwrap();
    assert_eq!(secret.trim().len(), 64);
    assert_eq!(report["public_key"], public.trim());
    assert_eq!(
        report["secret_key_path"],
        dir.join("ed25519.key").display().to_string()
    );
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains(secret.trim()),
            "the secret key must not appear in stdout or stderr"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.join("ed25519.key")), 0o600);
        assert_eq!(mode(&dir), 0o700);
    }
}

#[test]
fn keygen_never_overwrites_an_existing_key() {
    let home = tempdir().unwrap();
    assert!(keygen(home.path()).status.success());
    let dir = keys_dir(home.path());
    let before = (
        fs::read(dir.join("ed25519.key")).unwrap(),
        fs::read(dir.join("ed25519.pub")).unwrap(),
    );

    let output = keygen(home.path());

    assert_eq!(refusal(&output).0, Some(2));
    assert_eq!(refusal(&output).1, "E_BAD_INPUT");
    assert!(
        stdout_json(&output)["refusal"]["message"]
            .as_str()
            .unwrap()
            .contains("refusing to overwrite")
    );
    assert_eq!(fs::read(dir.join("ed25519.key")).unwrap(), before.0);
    assert_eq!(fs::read(dir.join("ed25519.pub")).unwrap(), before.1);
}

#[test]
fn keygen_without_a_home_directory_refuses_and_writes_nothing_to_the_working_directory() {
    let work = tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .current_dir(work.path())
        .env_remove("HOME")
        .env_remove("USERPROFILE")
        .arg("keygen")
        .output()
        .unwrap();

    assert_eq!(refusal(&output).0, Some(2));
    assert_eq!(refusal(&output).1, "E_BAD_INPUT");
    assert_eq!(fs::read_dir(work.path()).unwrap().count(), 0);
}

#[test]
fn verify_signs_by_default_and_verify_manifest_accepts_the_result() {
    let signed = signed_with_a_fresh_key();

    let manifest = read_json(&signed.manifest);
    assert_eq!(manifest["manifest_version"], "airlock.v0.3");
    assert_eq!(manifest["signature"]["algorithm"], "ed25519");
    assert_eq!(
        manifest["signature"]["public_key_fingerprint"],
        signed.fingerprint.as_str()
    );
    assert_eq!(
        manifest["signature"]["value"].as_str().unwrap().len(),
        128,
        "an Ed25519 signature is 64 bytes"
    );
    assert!(
        manifest_schema().is_valid(&manifest),
        "a signed manifest must validate against the manifest schema"
    );

    // The default public key is the one keygen wrote under HOME.
    let output = verify_manifest(signed.home.path(), &signed.manifest, None);
    assert!(output.status.success(), "{output:?}");
    let report = stdout_json(&output);
    assert_eq!(report["verified"], true);
    assert_eq!(
        report["public_key_fingerprint"],
        signed.fingerprint.as_str()
    );
}

#[test]
fn signing_adds_only_the_signature_member() {
    let signed = signed_with_a_fresh_key();
    let unsigned_path = signed.home.path().join("unsigned.json");
    let output = verify(signed.home.path(), &unsigned_path, &["--no-sign"]);
    assert!(output.status.success());

    let mut with_signature = read_json(&signed.manifest);
    with_signature.as_object_mut().unwrap().remove("signature");

    assert_eq!(with_signature, read_json(&unsigned_path));
}

#[test]
fn a_signed_manifest_matches_the_independently_derived_golden() {
    let home = home_with_golden_key();
    let out = home.path().join("manifest.json");

    let output = verify(home.path(), &out, &[]);

    assert!(output.status.success(), "{output:?}");
    let expected = golden("expected_manifest_v0_3_signed.json");
    assert_eq!(read_json(&out), expected);
    assert_eq!(stdout_json(&output), expected);
    assert_eq!(
        expected["signature"]["public_key_fingerprint"],
        GOLDEN_FINGERPRINT
    );

    // The golden verifies with the matching public key through the CLI.
    let ok = verify_manifest(home.path(), &out, None);
    assert!(ok.status.success(), "{ok:?}");
}

#[test]
fn no_sign_writes_an_unsigned_manifest_even_when_a_key_exists() {
    let home = home_with_golden_key();
    let out = home.path().join("manifest.json");

    let output = verify(home.path(), &out, &["--no-sign"]);

    assert!(output.status.success());
    let manifest = read_json(&out);
    assert!(manifest.get("signature").is_none());
    assert!(manifest_schema().is_valid(&manifest));
    // An unsigned manifest is refused by verify-manifest, never passed.
    let check = verify_manifest(home.path(), &out, None);
    assert_eq!(
        refusal(&check),
        (Some(2), "E_BAD_MANIFEST".to_owned(), "unsigned".to_owned())
    );
}

#[test]
fn no_sign_needs_no_key_at_all_and_creates_none() {
    let home = tempdir().unwrap();
    let out = home.path().join("manifest.json");

    let output = verify(home.path(), &out, &["--no-sign"]);

    assert!(output.status.success(), "{output:?}");
    assert!(manifest_schema().is_valid(&read_json(&out)));
    assert!(!home.path().join(".cmdrvl").exists());
}

#[test]
fn verify_without_a_key_refuses_before_writing_anything_and_does_not_make_one() {
    let home = tempdir().unwrap();
    let out = home.path().join("manifest.json");

    let output = verify(home.path(), &out, &[]);

    assert_eq!(refusal(&output).0, Some(2));
    assert_eq!(refusal(&output).1, "E_BAD_INPUT");
    let body = stdout_json(&output);
    assert_eq!(body["refusal"]["next_command"], "airlock keygen");
    assert!(
        body["refusal"]["message"]
            .as_str()
            .unwrap()
            .contains("--no-sign")
    );
    assert!(!out.exists(), "a refused run must not write a manifest");
    assert!(
        !home.path().join(".cmdrvl").exists(),
        "verify must never create a key on its own"
    );
}

#[cfg(unix)]
#[test]
fn verify_refuses_a_key_that_group_or_others_can_read() {
    let home = home_with_golden_key();
    restrict(&keys_dir(home.path()).join("ed25519.key"), 0o644);
    let out = home.path().join("manifest.json");

    let output = verify(home.path(), &out, &[]);

    assert_eq!(refusal(&output).0, Some(2));
    assert_eq!(refusal(&output).1, "E_BAD_INPUT");
    assert_eq!(stdout_json(&output)["refusal"]["detail"]["mode"], "0644");
    assert!(!out.exists());
}

#[test]
fn verify_refuses_a_malformed_key_file() {
    let home = tempdir().unwrap();
    let dir = keys_dir(home.path());
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("ed25519.key"), "not a key\n").unwrap();
    restrict(&dir.join("ed25519.key"), 0o600);
    let out = home.path().join("manifest.json");

    let output = verify(home.path(), &out, &[]);

    assert_eq!(refusal(&output).0, Some(2));
    assert_eq!(refusal(&output).1, "E_BAD_INPUT");
    assert!(!out.exists());
}

fn tamper(manifest: &Path, change: impl FnOnce(&mut Value)) {
    let mut value = read_json(manifest);
    change(&mut value);
    fs::write(manifest, serde_json::to_vec(&value).unwrap()).unwrap();
}

#[test]
fn any_change_to_a_signed_manifest_is_refused_with_the_reason() {
    type Change = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, Change, &str)> = vec![
        (
            "changed claim",
            Box::new(|m| m["achieved_claim"] = json!("BOUNDARY_FAILED")),
            "signature_mismatch",
        ),
        (
            "changed byte count",
            Box::new(|m| m["bytes_crossed"] = json!(1)),
            "signature_mismatch",
        ),
        (
            "added member",
            Box::new(|m| m["not_crossed"] = json!([])),
            "signature_mismatch",
        ),
        (
            "removed member",
            Box::new(|m| {
                m.as_object_mut().unwrap().remove("bytes_crossed");
            }),
            "signature_mismatch",
        ),
        (
            "flipped signature digit",
            Box::new(|m| {
                let value = m["signature"]["value"].as_str().unwrap().to_owned();
                let flipped = if value.starts_with('0') { "1" } else { "0" };
                m["signature"]["value"] = json!(format!("{flipped}{}", &value[1..]));
            }),
            "signature_mismatch",
        ),
        (
            "signature removed",
            Box::new(|m| {
                m.as_object_mut().unwrap().remove("signature");
            }),
            "unsigned",
        ),
        (
            "other signer named",
            Box::new(|m| m["signature"]["public_key_fingerprint"] = json!(GOLDEN_FINGERPRINT)),
            "fingerprint_mismatch",
        ),
        (
            "other algorithm",
            Box::new(|m| m["signature"]["algorithm"] = json!("ed448")),
            "unsupported_algorithm",
        ),
        (
            "short signature",
            Box::new(|m| m["signature"]["value"] = json!("abcd")),
            "malformed_signature",
        ),
        (
            "downgraded to v0.2",
            Box::new(|m| m["manifest_version"] = json!("airlock.v0.2")),
            "unsupported_manifest_version",
        ),
    ];

    for (label, change, reason) in cases {
        let signed = signed_with_a_fresh_key();
        tamper(&signed.manifest, change);

        let output = verify_manifest(signed.home.path(), &signed.manifest, None);

        assert_eq!(
            refusal(&output),
            (Some(2), "E_BAD_MANIFEST".to_owned(), reason.to_owned()),
            "{label}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn a_manifest_signed_by_another_key_is_refused_and_the_right_key_still_passes() {
    let signed = signed_with_a_fresh_key();
    let other = tempdir().unwrap();
    assert!(keygen(other.path()).status.success());
    let other_public = keys_dir(other.path()).join("ed25519.pub");
    let own_public = keys_dir(signed.home.path()).join("ed25519.pub");

    let wrong = verify_manifest(signed.home.path(), &signed.manifest, Some(&other_public));
    let right = verify_manifest(other.path(), &signed.manifest, Some(&own_public));

    assert_eq!(
        refusal(&wrong),
        (
            Some(2),
            "E_BAD_MANIFEST".to_owned(),
            "fingerprint_mismatch".to_owned()
        )
    );
    // --pubkey on its own is enough: the verifier needs no key of its own under HOME.
    assert!(right.status.success(), "{right:?}");
}

#[test]
fn reformatting_a_signed_manifest_keeps_it_valid_because_the_signature_covers_the_content() {
    let signed = signed_with_a_fresh_key();
    let value = read_json(&signed.manifest);
    fs::write(&signed.manifest, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    let output = verify_manifest(signed.home.path(), &signed.manifest, None);

    assert!(output.status.success(), "{output:?}");
}

#[test]
fn verify_manifest_refuses_a_v0_2_manifest_whatever_the_key() {
    let home = home_with_golden_key();
    let v0_2 = root().join("fixtures/clean_telemetry_only/expected_manifest.json");

    let output = verify_manifest(home.path(), &v0_2, None);

    assert_eq!(
        refusal(&output),
        (
            Some(2),
            "E_BAD_MANIFEST".to_owned(),
            "unsupported_manifest_version".to_owned()
        )
    );
}

#[test]
fn verify_manifest_reports_a_missing_manifest_or_key_as_a_missing_file() {
    let home = tempdir().unwrap();
    let signed = home_with_golden_key();
    let golden_signed =
        root().join("fixtures/clean_telemetry_only/expected_manifest_v0_3_signed.json");

    // No manifest.
    let absent = home.path().join("absent.json");
    let output = verify_manifest(signed.path(), &absent, None);
    assert_eq!(refusal(&output).1, "E_MISSING_FILE");

    // No public key under this empty HOME.
    let output = verify_manifest(home.path(), &golden_signed, None);
    assert_eq!(refusal(&output).1, "E_MISSING_FILE");

    // With the matching public key supplied, the same file verifies.
    let public = keys_dir(signed.path()).join("ed25519.pub");
    let output = verify_manifest(home.path(), &golden_signed, Some(&public));
    assert!(output.status.success(), "{output:?}");
}
