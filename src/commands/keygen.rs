use std::io::{self, Write};
use std::path::PathBuf;

use serde_json::json;

use crate::cli::{KeygenArgs, VERIFY_PASS};
use crate::output::canonical_json;
use crate::signing::{self, SigningError};

/// `airlock keygen`: write a new Ed25519 key pair under `~/.cmdrvl/secrets/airlock/`.
///
/// Prints the public key and its fingerprint. The secret never reaches stdout, and an
/// existing key is never overwritten.
pub fn run(_args: KeygenArgs) -> u8 {
    run_in(signing::secrets_dir(), &mut io::stdout())
}

fn run_in(dir: Result<PathBuf, SigningError>, stdout: &mut impl Write) -> u8 {
    let generated = match dir.and_then(|dir| signing::generate_keypair(&dir)) {
        Ok(generated) => generated,
        Err(error) => return error.refusal().write_to(stdout),
    };
    let report = json!({
        "command": "keygen",
        "algorithm": signing::SIGNATURE_ALGORITHM,
        "public_key": generated.public_key_hex,
        "public_key_fingerprint": generated.fingerprint,
        "public_key_path": generated.public_key_path.display().to_string(),
        "secret_key_path": generated.secret_key_path.display().to_string(),
    });
    let _ = writeln!(stdout, "{}", canonical_json(&report));
    VERIFY_PASS
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use tempfile::tempdir;

    fn run_to_value(dir: Result<PathBuf, SigningError>) -> (u8, Value, String) {
        let mut out = Vec::new();
        let code = run_in(dir, &mut out);
        let text = String::from_utf8(out).unwrap();
        (code, serde_json::from_str(&text).unwrap(), text)
    }

    #[test]
    fn keygen_reports_the_public_key_and_never_the_secret() {
        let dir = tempdir().unwrap();
        let keys = dir.path().join("airlock");

        let (code, report, text) = run_to_value(Ok(keys.clone()));

        assert_eq!(code, VERIFY_PASS);
        assert_eq!(report["command"], "keygen");
        assert_eq!(report["algorithm"], "ed25519");
        let secret = std::fs::read_to_string(keys.join(signing::SECRET_KEY_FILE)).unwrap();
        assert!(!secret.trim().is_empty());
        assert!(
            !text.contains(secret.trim()),
            "the secret key must never be printed"
        );
        let public = std::fs::read_to_string(keys.join(signing::PUBLIC_KEY_FILE)).unwrap();
        assert_eq!(report["public_key"], public.trim());
        assert_eq!(
            report["secret_key_path"],
            keys.join(signing::SECRET_KEY_FILE).display().to_string()
        );
    }

    #[test]
    fn keygen_refuses_to_overwrite_an_existing_key() {
        let dir = tempdir().unwrap();
        let keys = dir.path().join("airlock");
        assert_eq!(run_to_value(Ok(keys.clone())).0, VERIFY_PASS);
        let before = std::fs::read(keys.join(signing::SECRET_KEY_FILE)).unwrap();

        let (code, refusal, _) = run_to_value(Ok(keys.clone()));

        assert_eq!(code, 2);
        assert_eq!(refusal["refusal"]["code"], "E_BAD_INPUT");
        assert!(
            refusal["refusal"]["message"]
                .as_str()
                .unwrap()
                .contains("refusing to overwrite")
        );
        assert_eq!(
            std::fs::read(keys.join(signing::SECRET_KEY_FILE)).unwrap(),
            before
        );
    }

    #[test]
    fn keygen_refuses_when_there_is_no_home_directory() {
        let (code, refusal, _) = run_to_value(Err(SigningError::NoHome));

        assert_eq!(code, 2);
        assert_eq!(refusal["refusal"]["code"], "E_BAD_INPUT");
        assert_eq!(
            refusal["refusal"]["detail"]["env"],
            serde_json::json!(["HOME", "USERPROFILE"])
        );
    }
}
