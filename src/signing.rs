//! Ed25519 signatures on airlock manifests (`airlock.v0.3`).
//!
//! The signature covers the canonical JSON of the manifest with its `signature` member
//! removed: the same canonical form `verify` writes the manifest in (RFC 8785 for every
//! number a manifest carries). The manifest does not embed the public key, only a
//! fingerprint (`blake3:` of the 32 raw key bytes) that says which key signed. The verifier
//! supplies the key, so a manifest cannot vouch for itself.
//!
//! The key pair lives in `~/.cmdrvl/secrets/airlock/`: `ed25519.key` (the 32-byte seed as hex,
//! mode 0600 on Unix) and `ed25519.pub` (the public key as hex).

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{Value, json};

use crate::hash::blake3_hash;
use crate::manifest::{AIRLOCK_MANIFEST_VERSION, AirlockManifest, ManifestSignature};
use crate::output::canonical_json_bytes;
use crate::paths;
use crate::refusal::RefusalEnvelope;

pub const SIGNATURE_ALGORITHM: &str = "ed25519";
pub const SECRET_KEY_FILE: &str = "ed25519.key";
pub const PUBLIC_KEY_FILE: &str = "ed25519.pub";

#[derive(Debug)]
pub enum SigningError {
    NoHome,
    KeyMissing(PathBuf),
    PublicKeyMissing(PathBuf),
    KeyUnreadable { path: PathBuf, error: String },
    KeyMalformed { path: PathBuf, reason: &'static str },
    KeyTooPermissive { path: PathBuf, mode: u32 },
    KeyExists(PathBuf),
    Io { path: PathBuf, error: String },
    Random(String),
    Serialize(String),
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHome => write!(
                f,
                "cannot locate the home directory (HOME and USERPROFILE are unset), so there is no place for the signing key"
            ),
            Self::KeyMissing(path) => write!(
                f,
                "no signing key at {}: run `airlock keygen`, or pass --no-sign to write an unsigned manifest",
                path.display()
            ),
            Self::PublicKeyMissing(path) => {
                write!(f, "no public key at {}", path.display())
            }
            Self::KeyUnreadable { path, error } => {
                write!(f, "cannot read {}: {error}", path.display())
            }
            Self::KeyMalformed { path, reason } => {
                write!(f, "{} is not a valid key file: {reason}", path.display())
            }
            Self::KeyTooPermissive { path, mode } => write!(
                f,
                "{} is accessible by group or others (mode {mode:o}); restrict it to the owner (0600) before signing",
                path.display()
            ),
            Self::KeyExists(path) => write!(
                f,
                "a key already exists at {}; refusing to overwrite it",
                path.display()
            ),
            Self::Io { path, error } => write!(f, "{}: {error}", path.display()),
            Self::Random(error) => write!(f, "the operating system gave no randomness: {error}"),
            Self::Serialize(error) => write!(f, "manifest could not be serialized: {error}"),
        }
    }
}

impl std::error::Error for SigningError {}

impl SigningError {
    /// The structured refusal for this error. Nothing here carries key material.
    pub fn refusal(&self) -> RefusalEnvelope {
        match self {
            Self::KeyMissing(path) => RefusalEnvelope::bad_input_with_next_command(
                self.to_string(),
                json!({ "path": path.display().to_string() }),
                "airlock keygen",
            ),
            Self::PublicKeyMissing(path) => {
                RefusalEnvelope::missing_file(path.display().to_string())
            }
            Self::KeyTooPermissive { path, mode } => RefusalEnvelope::bad_input(
                self.to_string(),
                json!({
                    "path": path.display().to_string(),
                    "mode": format!("{mode:04o}"),
                    "required": "0600",
                }),
            ),
            Self::KeyExists(path)
            | Self::KeyMalformed { path, .. }
            | Self::KeyUnreadable { path, .. }
            | Self::Io { path, .. } => RefusalEnvelope::bad_input(
                self.to_string(),
                json!({ "path": path.display().to_string() }),
            ),
            Self::NoHome => RefusalEnvelope::bad_input(
                self.to_string(),
                json!({ "env": ["HOME", "USERPROFILE"] }),
            ),
            Self::Random(_) | Self::Serialize(_) => {
                RefusalEnvelope::internal(self.to_string(), json!({}))
            }
        }
    }
}

/// `~/.cmdrvl/secrets/airlock`, or an error when there is no home directory.
pub fn secrets_dir() -> Result<PathBuf, SigningError> {
    paths::airlock_secrets_dir().ok_or(SigningError::NoHome)
}

pub struct GeneratedKey {
    pub secret_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub public_key_hex: String,
    pub fingerprint: String,
}

/// Write a new key pair into `dir`. Refuses, touching nothing, when either file exists: a
/// key is never overwritten, because replacing it would silently orphan every manifest it
/// signed.
pub fn generate_keypair(dir: &Path) -> Result<GeneratedKey, SigningError> {
    let secret_key_path = dir.join(SECRET_KEY_FILE);
    let public_key_path = dir.join(PUBLIC_KEY_FILE);
    for path in [&secret_key_path, &public_key_path] {
        if path.exists() {
            return Err(SigningError::KeyExists(path.clone()));
        }
    }

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|error| SigningError::Random(error.to_string()))?;
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);

    fs::create_dir_all(dir).map_err(|error| io_error(dir, &error))?;
    restrict_directory(dir).map_err(|error| io_error(dir, &error))?;

    let public_key = key.verifying_key();
    let public_key_hex = hex_encode(&public_key.to_bytes());
    // create_new makes a concurrent keygen lose cleanly instead of overwriting.
    write_new_file(&secret_key_path, &key_file_contents(&key), true)?;
    write_new_file(&public_key_path, &format!("{public_key_hex}\n"), false)?;

    Ok(GeneratedKey {
        secret_key_path,
        public_key_path,
        public_key_hex,
        fingerprint: fingerprint(&public_key),
    })
}

fn key_file_contents(key: &SigningKey) -> String {
    format!("{}\n", hex_encode(&key.to_bytes()))
}

fn write_new_file(path: &Path, contents: &str, secret: bool) -> Result<(), SigningError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if secret { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            SigningError::KeyExists(path.to_path_buf())
        } else {
            io_error(path, &error)
        }
    })?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(path, &error))
}

fn io_error(path: &Path, error: &io::Error) -> SigningError {
    SigningError::Io {
        path: path.to_path_buf(),
        error: error.to_string(),
    }
}

#[cfg(unix)]
fn restrict_directory(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn restrict_directory(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// Load the signing key from `dir`. Refuses a key file that group or others can read.
pub fn load_signing_key(dir: &Path) -> Result<SigningKey, SigningError> {
    let path = dir.join(SECRET_KEY_FILE);
    let text = fs::read_to_string(&path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            SigningError::KeyMissing(path.clone())
        } else {
            SigningError::KeyUnreadable {
                path: path.clone(),
                error: error.to_string(),
            }
        }
    })?;
    check_secret_permissions(&path)?;
    let bytes = decode_key(&path, &text)?;
    Ok(SigningKey::from_bytes(&bytes))
}

#[cfg(unix)]
fn check_secret_permissions(path: &Path) -> Result<(), SigningError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|error| io_error(path, &error))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(SigningError::KeyTooPermissive {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_secret_permissions(_path: &Path) -> Result<(), SigningError> {
    Ok(())
}

/// Load a public key file: 32 bytes as hex, as `airlock keygen` writes it.
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey, SigningError> {
    let text = fs::read_to_string(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            SigningError::PublicKeyMissing(path.to_path_buf())
        } else {
            SigningError::KeyUnreadable {
                path: path.to_path_buf(),
                error: error.to_string(),
            }
        }
    })?;
    let bytes = decode_key(path, &text)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| SigningError::KeyMalformed {
        path: path.to_path_buf(),
        reason: "not a valid Ed25519 public key",
    })
}

fn decode_key(path: &Path, text: &str) -> Result<[u8; 32], SigningError> {
    let malformed = |reason| SigningError::KeyMalformed {
        path: path.to_path_buf(),
        reason,
    };
    let bytes = hex_decode(text.trim()).ok_or_else(|| malformed("expected 64 hex characters"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| malformed("expected 32 bytes"))
}

/// `blake3:{64 hex}` of the 32 raw bytes of the public key.
pub fn fingerprint(key: &VerifyingKey) -> String {
    blake3_hash(&key.to_bytes())
}

/// The bytes a signature covers: the canonical JSON of `manifest` without its `signature`
/// member. Every other member, including any this version does not know, is covered.
pub fn signing_payload(manifest: &Value) -> Vec<u8> {
    let mut unsigned = manifest.clone();
    if let Some(object) = unsigned.as_object_mut() {
        object.remove("signature");
    }
    canonical_json_bytes(&unsigned)
}

/// Sign any manifest-shaped JSON value.
pub fn sign_value(manifest: &Value, key: &SigningKey) -> ManifestSignature {
    let signature = key.sign(&signing_payload(manifest));
    ManifestSignature {
        algorithm: SIGNATURE_ALGORITHM.to_string(),
        public_key_fingerprint: fingerprint(&key.verifying_key()),
        value: hex_encode(&signature.to_bytes()),
    }
}

/// Sign `manifest` in place, replacing any signature it already carries.
pub fn sign(manifest: &mut AirlockManifest, key: &SigningKey) -> Result<(), SigningError> {
    manifest.signature = None;
    let value = serde_json::to_value(&*manifest)
        .map_err(|error| SigningError::Serialize(error.to_string()))?;
    manifest.signature = Some(sign_value(&value, key));
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureFailure {
    NotAnObject,
    UnsupportedVersion(String),
    Unsigned,
    Malformed(&'static str),
    UnsupportedAlgorithm(String),
    FingerprintMismatch { recorded: String, supplied: String },
    Mismatch,
}

impl SignatureFailure {
    /// Stable machine-readable reason, for refusal detail.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotAnObject => "not_an_object",
            Self::UnsupportedVersion(_) => "unsupported_manifest_version",
            Self::Unsigned => "unsigned",
            Self::Malformed(_) => "malformed_signature",
            Self::UnsupportedAlgorithm(_) => "unsupported_algorithm",
            Self::FingerprintMismatch { .. } => "fingerprint_mismatch",
            Self::Mismatch => "signature_mismatch",
        }
    }
}

impl fmt::Display for SignatureFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnObject => write!(f, "the manifest is not a JSON object"),
            Self::UnsupportedVersion(version) => write!(
                f,
                "only {AIRLOCK_MANIFEST_VERSION} manifests carry a signature; this one is {version}"
            ),
            Self::Unsigned => write!(f, "the manifest carries no signature"),
            Self::Malformed(why) => write!(f, "the manifest signature is malformed: {why}"),
            Self::UnsupportedAlgorithm(algorithm) => write!(
                f,
                "unsupported signature algorithm {algorithm:?}; expected {SIGNATURE_ALGORITHM:?}"
            ),
            Self::FingerprintMismatch { recorded, supplied } => write!(
                f,
                "the manifest was signed by a different key ({recorded}); the supplied key is {supplied}"
            ),
            Self::Mismatch => write!(
                f,
                "the signature does not match the manifest contents: it was altered after signing, or signed by another key"
            ),
        }
    }
}

pub struct VerifiedSignature {
    pub algorithm: &'static str,
    pub public_key_fingerprint: String,
}

/// Check the signature in `manifest` against `key`. Works on the parsed JSON, not on a
/// re-serialized struct, so a member this build does not know is still covered.
pub fn verify_value(
    manifest: &Value,
    key: &VerifyingKey,
) -> Result<VerifiedSignature, SignatureFailure> {
    let object = manifest.as_object().ok_or(SignatureFailure::NotAnObject)?;
    match object.get("manifest_version").and_then(Value::as_str) {
        Some(AIRLOCK_MANIFEST_VERSION) => {}
        other => {
            return Err(SignatureFailure::UnsupportedVersion(
                other.unwrap_or("(missing)").to_string(),
            ));
        }
    }
    let signature = object.get("signature").ok_or(SignatureFailure::Unsigned)?;
    let signature: ManifestSignature = serde_json::from_value(signature.clone()).map_err(|_| {
        SignatureFailure::Malformed("expected algorithm, public_key_fingerprint and value")
    })?;
    if signature.algorithm != SIGNATURE_ALGORITHM {
        return Err(SignatureFailure::UnsupportedAlgorithm(signature.algorithm));
    }
    let supplied = fingerprint(key);
    if signature.public_key_fingerprint != supplied {
        return Err(SignatureFailure::FingerprintMismatch {
            recorded: signature.public_key_fingerprint,
            supplied,
        });
    }
    let bytes = hex_decode(&signature.value)
        .and_then(|bytes| <[u8; 64]>::try_from(bytes.as_slice()).ok())
        .ok_or(SignatureFailure::Malformed(
            "value must be 128 hex characters",
        ))?;
    key.verify_strict(&signing_payload(manifest), &Signature::from_bytes(&bytes))
        .map_err(|_| SignatureFailure::Mismatch)?;
    Ok(VerifiedSignature {
        algorithm: SIGNATURE_ALGORITHM,
        public_key_fingerprint: supplied,
    })
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Lowercase or uppercase hex to bytes; `None` on odd length or a non-hex character.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    // RFC 8032 section 7.1, test 1: the standard Ed25519 known-answer vector.
    const RFC8032_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const RFC8032_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const RFC8032_EMPTY_SIGNATURE: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    fn key(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }

    fn manifest() -> Value {
        json!({
            "manifest_version": "airlock.v0.3",
            "achieved_claim": "STRICT_TELEMETRY_ONLY",
            "bytes_crossed": 632,
            "attestation": "self_attested",
        })
    }

    fn signed(key: &SigningKey) -> Value {
        let mut value = manifest();
        value["signature"] = serde_json::to_value(sign_value(&value, key)).unwrap();
        value
    }

    #[test]
    fn matches_the_rfc_8032_known_answer_vector() {
        let seed: [u8; 32] = hex_decode(RFC8032_SEED).unwrap().try_into().unwrap();
        let key = SigningKey::from_bytes(&seed);

        assert_eq!(hex_encode(&key.verifying_key().to_bytes()), RFC8032_PUBLIC);
        assert_eq!(
            hex_encode(&key.sign(b"").to_bytes()),
            RFC8032_EMPTY_SIGNATURE
        );
    }

    #[test]
    fn fingerprint_is_the_blake3_of_the_raw_public_key() {
        let public: [u8; 32] = hex_decode(RFC8032_PUBLIC).unwrap().try_into().unwrap();
        let key = VerifyingKey::from_bytes(&public).unwrap();

        // Independently computed with Python's blake3 over bytes.fromhex(RFC8032_PUBLIC).
        assert_eq!(
            fingerprint(&key),
            "blake3:6c31041268f471609c79f5f2dbcc38e4a4ab2f4d416109a4e09fcf50fd0f0062"
        );
    }

    #[test]
    fn hex_round_trips_and_rejects_malformed_text() {
        assert_eq!(hex_encode(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(hex_decode("00ABff"), Some(vec![0x00, 0xab, 0xff]));
        assert_eq!(hex_decode("abc"), None, "odd length");
        assert_eq!(hex_decode("zz"), None, "not hex");
        assert_eq!(hex_decode("é1"), None, "non-ASCII");
        assert_eq!(hex_decode(""), Some(Vec::new()));
    }

    #[test]
    fn payload_drops_only_the_signature_and_is_independent_of_member_order() {
        let a = json!({ "b": 1, "a": [2, "x"], "signature": { "value": "ignored" } });
        let b = json!({ "a": [2, "x"], "b": 1 });

        assert_eq!(signing_payload(&a), br#"{"a":[2,"x"],"b":1}"#.to_vec());
        assert_eq!(signing_payload(&a), signing_payload(&b));
    }

    #[test]
    fn a_signed_manifest_verifies_with_its_key_and_reports_the_fingerprint() {
        let signer = key(7);

        let verified = verify_value(&signed(&signer), &signer.verifying_key()).unwrap();

        assert_eq!(verified.algorithm, "ed25519");
        assert_eq!(
            verified.public_key_fingerprint,
            fingerprint(&signer.verifying_key())
        );
    }

    #[test]
    fn signing_is_deterministic() {
        let signer = key(7);

        assert_eq!(
            sign_value(&manifest(), &signer),
            sign_value(&manifest(), &signer)
        );
    }

    #[test]
    fn any_change_after_signing_is_refused() {
        let signer = key(7);
        let verifier = signer.verifying_key();

        let mut changed = signed(&signer);
        changed["achieved_claim"] = json!("BOUNDARY_FAILED");
        let mut extra = signed(&signer);
        extra["not_crossed"] = json!([]);
        let mut removed = signed(&signer);
        removed.as_object_mut().unwrap().remove("bytes_crossed");

        for (label, tampered) in [
            ("changed value", changed),
            ("added member", extra),
            ("removed member", removed),
        ] {
            assert_eq!(
                verify_value(&tampered, &verifier).err(),
                Some(SignatureFailure::Mismatch),
                "{label}"
            );
        }
    }

    #[test]
    fn a_flipped_signature_bit_is_refused() {
        let signer = key(7);
        let mut value = signed(&signer);
        let original = value["signature"]["value"].as_str().unwrap().to_string();
        let mut bytes = hex_decode(&original).unwrap();
        bytes[10] ^= 0x01;
        value["signature"]["value"] = json!(hex_encode(&bytes));

        assert_eq!(
            verify_value(&value, &signer.verifying_key()).err(),
            Some(SignatureFailure::Mismatch)
        );
    }

    #[test]
    fn a_manifest_signed_by_another_key_is_refused_as_a_fingerprint_mismatch() {
        let signer = key(7);
        let other = key(8);

        let failure = verify_value(&signed(&signer), &other.verifying_key()).err();

        assert_eq!(
            failure,
            Some(SignatureFailure::FingerprintMismatch {
                recorded: fingerprint(&signer.verifying_key()),
                supplied: fingerprint(&other.verifying_key()),
            })
        );
    }

    #[test]
    fn a_relabelled_fingerprint_does_not_help_a_forger() {
        // Signed by 8, claims to be 7: the fingerprint matches the supplied key, so only the
        // signature check stands between the forger and acceptance.
        let victim = key(7);
        let forger = key(8);
        let mut forged = manifest();
        let mut signature = sign_value(&forged, &forger);
        signature.public_key_fingerprint = fingerprint(&victim.verifying_key());
        forged["signature"] = serde_json::to_value(signature).unwrap();

        assert_eq!(
            verify_value(&forged, &victim.verifying_key()).err(),
            Some(SignatureFailure::Mismatch)
        );
    }

    #[test]
    fn a_weak_public_key_cannot_be_used_to_forge_a_signature() {
        // The identity point is a valid-looking public key. Under it, the signature
        // (R = identity, S = 0) passes plain Ed25519 verification for ANY message, so anyone
        // could "sign" a manifest. verify_strict rejects small-order keys; this test is what
        // keeps verify_value on verify_strict.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let weak = VerifyingKey::from_bytes(&identity).expect("the identity is a curve point");
        let mut forged_signature = [0u8; 64];
        forged_signature[0] = 1;
        let mut forged = manifest();
        forged["signature"] = json!({
            "algorithm": "ed25519",
            "public_key_fingerprint": fingerprint(&weak),
            "value": hex_encode(&forged_signature),
        });

        assert_eq!(
            verify_value(&forged, &weak).err(),
            Some(SignatureFailure::Mismatch)
        );
    }

    #[test]
    fn unsigned_v0_2_non_object_and_malformed_signatures_are_refused_with_a_reason() {
        let verifier = key(7).verifying_key();
        let signed_manifest = signed(&key(7));

        let mut v0_2 = signed_manifest.clone();
        v0_2["manifest_version"] = json!("airlock.v0.2");
        let mut algorithm = signed_manifest.clone();
        algorithm["signature"]["algorithm"] = json!("rsa");
        let mut short = signed_manifest.clone();
        short["signature"]["value"] = json!("abcd");
        let mut not_hex = signed_manifest.clone();
        not_hex["signature"]["value"] = json!("zz".repeat(64));
        let mut extra_member = signed_manifest.clone();
        extra_member["signature"]["note"] = json!("x");

        let cases = [
            (manifest(), "unsigned"),
            (json!([1]), "not_an_object"),
            (v0_2, "unsupported_manifest_version"),
            (algorithm, "unsupported_algorithm"),
            (short, "malformed_signature"),
            (not_hex, "malformed_signature"),
            (extra_member, "malformed_signature"),
        ];
        for (value, reason) in cases {
            let failure = verify_value(&value, &verifier).err().unwrap();
            assert_eq!(failure.reason(), reason, "{failure}");
        }
    }

    #[test]
    fn generate_writes_a_matching_pair_and_never_overwrites_it() {
        let dir = tempdir().unwrap();
        let keys = dir.path().join("secrets").join("airlock");

        let generated = generate_keypair(&keys).unwrap();

        let secret = fs::read_to_string(&generated.secret_key_path).unwrap();
        let public = fs::read_to_string(&generated.public_key_path).unwrap();
        assert_eq!(secret.trim().len(), 64);
        assert_eq!(public.trim(), generated.public_key_hex);
        let loaded = load_signing_key(&keys).unwrap();
        assert_eq!(
            hex_encode(&loaded.verifying_key().to_bytes()),
            generated.public_key_hex
        );
        assert_eq!(generated.fingerprint, fingerprint(&loaded.verifying_key()));
        assert_eq!(
            load_verifying_key(&generated.public_key_path).unwrap(),
            loaded.verifying_key()
        );

        let again = generate_keypair(&keys).err().unwrap();
        assert!(matches!(again, SigningError::KeyExists(_)), "{again}");
        assert_eq!(
            fs::read_to_string(&generated.secret_key_path).unwrap(),
            secret
        );
        assert_eq!(
            fs::read_to_string(&generated.public_key_path).unwrap(),
            public
        );
    }

    #[test]
    fn generate_refuses_when_only_the_public_half_exists_and_writes_nothing() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(PUBLIC_KEY_FILE), "stale\n").unwrap();

        let error = generate_keypair(dir.path()).err().unwrap();

        assert!(matches!(error, SigningError::KeyExists(_)));
        assert!(!dir.path().join(SECRET_KEY_FILE).exists());
    }

    #[test]
    fn two_generated_keys_differ() {
        let one = tempdir().unwrap();
        let two = tempdir().unwrap();

        let a = generate_keypair(one.path()).unwrap();
        let b = generate_keypair(two.path()).unwrap();

        assert_ne!(a.public_key_hex, b.public_key_hex);
    }

    #[cfg(unix)]
    #[test]
    fn the_secret_is_owner_only_and_a_looser_one_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let keys = dir.path().join("airlock");
        let generated = generate_keypair(&keys).unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&generated.secret_key_path), 0o600);
        assert_eq!(mode(&keys), 0o700);
        assert!(load_signing_key(&keys).is_ok());

        fs::set_permissions(
            &generated.secret_key_path,
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        let error = load_signing_key(&keys).err().unwrap();
        assert!(
            matches!(error, SigningError::KeyTooPermissive { mode: 0o640, .. }),
            "{error}"
        );
    }

    #[test]
    fn loading_refuses_a_missing_or_malformed_key() {
        let dir = tempdir().unwrap();
        assert!(matches!(
            load_signing_key(dir.path()).err().unwrap(),
            SigningError::KeyMissing(_)
        ));

        for (contents, label) in [
            ("not hex\n", "not hex"),
            ("abcd\n", "too short"),
            (&"ab".repeat(33), "too long"),
        ] {
            let path = dir.path().join(SECRET_KEY_FILE);
            fs::write(&path, contents).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            assert!(
                matches!(
                    load_signing_key(dir.path()).err().unwrap(),
                    SigningError::KeyMalformed { .. }
                ),
                "{label}"
            );
        }
    }

    #[test]
    fn a_public_key_file_that_is_not_a_curve_point_is_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(PUBLIC_KEY_FILE);
        // y = 2 is not on the curve.
        fs::write(&path, format!("02{}\n", "00".repeat(31))).unwrap();

        let error = load_verifying_key(&path).err().unwrap();

        assert!(
            matches!(error, SigningError::KeyMalformed { .. }),
            "{error}"
        );
    }

    #[test]
    fn sign_replaces_an_existing_signature_and_the_result_verifies() {
        let signer = key(7);
        let mut manifest: AirlockManifest = serde_json::from_str(include_str!(
            "../fixtures/clean_telemetry_only/expected_manifest_v0_3.json"
        ))
        .unwrap();
        assert!(manifest.signature.is_none());
        sign(&mut manifest, &key(9)).unwrap();
        let first = manifest.signature.clone().unwrap();

        sign(&mut manifest, &signer).unwrap();

        let second = manifest.signature.clone().unwrap();
        assert_ne!(first, second);
        let value = serde_json::to_value(&manifest).unwrap();
        assert!(verify_value(&value, &signer.verifying_key()).is_ok());
    }
}
