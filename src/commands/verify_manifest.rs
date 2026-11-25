use std::io::{self, Write};

use serde_json::{Value, json};

use crate::cli::{VERIFY_PASS, VerifyManifestArgs};
use crate::output::canonical_json;
use crate::refusal::RefusalEnvelope;
use crate::signing;

/// `airlock verify-manifest`: check the Ed25519 signature on a manifest.
///
/// Exit 0 and a short report when the signature is valid; otherwise a refusal (exit 2) with a
/// `reason` in its detail: `unsigned`, `signature_mismatch`, `fingerprint_mismatch`,
/// `unsupported_manifest_version`, `unsupported_algorithm`, `malformed_signature` or
/// `not_an_object`. Read-only: it records nothing in the witness ledger.
pub fn run(args: VerifyManifestArgs) -> u8 {
    run_with_writer(args, &mut io::stdout())
}

fn run_with_writer(args: VerifyManifestArgs, stdout: &mut impl Write) -> u8 {
    let manifest_path = args.manifest.display().to_string();
    let bytes = match std::fs::read(&args.manifest) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return RefusalEnvelope::missing_file(manifest_path).write_to(stdout);
        }
        Err(error) => {
            return RefusalEnvelope::bad_input(
                "failed to read manifest",
                json!({ "path": manifest_path, "error": error.to_string() }),
            )
            .write_to(stdout);
        }
    };
    let manifest: Value = match serde_json::from_slice(&bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            return RefusalEnvelope::bad_manifest(
                "manifest is not valid JSON",
                json!({ "path": manifest_path, "error": error.to_string() }),
            )
            .write_to(stdout);
        }
    };

    let public_key_path = match args.pubkey {
        Some(path) => path,
        None => match signing::secrets_dir() {
            Ok(dir) => dir.join(signing::PUBLIC_KEY_FILE),
            Err(error) => return error.refusal().write_to(stdout),
        },
    };
    let key = match signing::load_verifying_key(&public_key_path) {
        Ok(key) => key,
        Err(error) => return error.refusal().write_to(stdout),
    };

    match signing::verify_value(&manifest, &key) {
        Ok(verified) => {
            let report = json!({
                "command": "verify-manifest",
                "verified": true,
                "manifest": manifest_path,
                "manifest_version": manifest["manifest_version"],
                "algorithm": verified.algorithm,
                "public_key_fingerprint": verified.public_key_fingerprint,
            });
            let _ = writeln!(stdout, "{}", canonical_json(&report));
            VERIFY_PASS
        }
        Err(failure) => RefusalEnvelope::bad_manifest(
            failure.to_string(),
            json!({
                "reason": failure.reason(),
                "path": manifest_path,
                "public_key": public_key_path.display().to_string(),
            }),
        )
        .write_to(stdout),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use tempfile::{TempDir, tempdir};

    struct Signed {
        dir: TempDir,
        manifest: PathBuf,
        public_key: PathBuf,
    }

    fn signed_manifest() -> Signed {
        let dir = tempdir().unwrap();
        let keys = dir.path().join("keys");
        let generated = signing::generate_keypair(&keys).unwrap();
        let key = signing::load_signing_key(&keys).unwrap();
        let mut manifest = json!({
            "manifest_version": "airlock.v0.3",
            "achieved_claim": "STRICT_TELEMETRY_ONLY",
            "bytes_crossed": 632,
        });
        manifest["signature"] = serde_json::to_value(signing::sign_value(&manifest, &key)).unwrap();
        let path = dir.path().join("manifest.json");
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        Signed {
            manifest: path,
            public_key: generated.public_key_path,
            dir,
        }
    }

    fn check(manifest: &Path, pubkey: &Path) -> (u8, Value) {
        let mut out = Vec::new();
        let code = run_with_writer(
            VerifyManifestArgs {
                manifest: manifest.to_path_buf(),
                pubkey: Some(pubkey.to_path_buf()),
            },
            &mut out,
        );
        (code, serde_json::from_slice(&out).unwrap())
    }

    #[test]
    fn a_valid_signature_exits_zero_with_the_signer_fingerprint() {
        let signed = signed_manifest();

        let (code, report) = check(&signed.manifest, &signed.public_key);

        assert_eq!(code, VERIFY_PASS);
        assert_eq!(report["verified"], true);
        assert_eq!(report["algorithm"], "ed25519");
        let key = signing::load_verifying_key(&signed.public_key).unwrap();
        assert_eq!(report["public_key_fingerprint"], signing::fingerprint(&key));
    }

    #[test]
    fn an_altered_manifest_is_refused_with_signature_mismatch() {
        let signed = signed_manifest();
        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(&signed.manifest).unwrap()).unwrap();
        manifest["achieved_claim"] = json!("BOUNDARY_FAILED");
        std::fs::write(&signed.manifest, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let (code, refusal) = check(&signed.manifest, &signed.public_key);

        assert_eq!(code, 2);
        assert_eq!(refusal["refusal"]["code"], "E_BAD_MANIFEST");
        assert_eq!(refusal["refusal"]["detail"]["reason"], "signature_mismatch");
    }

    #[test]
    fn an_unsigned_manifest_is_refused() {
        let signed = signed_manifest();
        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(&signed.manifest).unwrap()).unwrap();
        manifest.as_object_mut().unwrap().remove("signature");
        std::fs::write(&signed.manifest, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let (code, refusal) = check(&signed.manifest, &signed.public_key);

        assert_eq!(code, 2);
        assert_eq!(refusal["refusal"]["detail"]["reason"], "unsigned");
    }

    #[test]
    fn a_key_that_did_not_sign_is_refused_with_fingerprint_mismatch() {
        let signed = signed_manifest();
        let other = signing::generate_keypair(&signed.dir.path().join("other")).unwrap();

        let (code, refusal) = check(&signed.manifest, &other.public_key_path);

        assert_eq!(code, 2);
        assert_eq!(
            refusal["refusal"]["detail"]["reason"],
            "fingerprint_mismatch"
        );
    }

    #[test]
    fn missing_files_and_bad_json_are_refused_with_their_own_codes() {
        let signed = signed_manifest();
        let absent = signed.dir.path().join("absent");

        let (code, refusal) = check(&absent, &signed.public_key);
        assert_eq!(
            (code, refusal["refusal"]["code"].as_str()),
            (2, Some("E_MISSING_FILE"))
        );

        let (code, refusal) = check(&signed.manifest, &absent);
        assert_eq!(
            (code, refusal["refusal"]["code"].as_str()),
            (2, Some("E_MISSING_FILE"))
        );

        let garbage = signed.dir.path().join("garbage.json");
        std::fs::write(&garbage, b"{nope").unwrap();
        let (code, refusal) = check(&garbage, &signed.public_key);
        assert_eq!(
            (code, refusal["refusal"]["code"].as_str()),
            (2, Some("E_BAD_MANIFEST"))
        );
    }
}
