pub mod jcs;

use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

use self::jcs::JcsError;

/// Hash a JSON value as `blake3(JCS(value))` with RFC 8785 canonicalization.
///
/// This is the computation a third party reproduces with any conforming JCS library:
/// canonicalize, then BLAKE3 the UTF-8 bytes. Integers outside ±2^53, which RFC 8785 cannot
/// represent interoperably, are refused instead of hashed (see [`jcs::canonicalize`]).
pub fn jcs_blake3_hash(value: &Value) -> Result<String, JcsError> {
    Ok(blake3_hash(jcs::canonicalize(value)?.as_bytes()))
}

/// Compute a BLAKE3 hash of the given bytes.
///
/// Returns the spine-standard format: `blake3:{hex}`.
pub fn blake3_hash(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    format!("blake3:{}", hash.to_hex())
}

/// True for exactly what [`blake3_hash`] emits: `blake3:` followed by 64 lowercase hex digits.
///
/// Stricter than a bare hex check on purpose. Hashes are compared as strings, so an uppercase
/// spelling of a real hash would never match and would be treated as a different hash.
pub fn is_canonical_blake3_hash(text: &str) -> bool {
    text.strip_prefix("blake3:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// Compute a SHA-256 hash of the given bytes.
///
/// Returns the format: `sha256:{hex}`.
pub fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("sha256:{:x}", result)
}

/// Read a file and return its BLAKE3 content hash.
///
/// Returns the spine-standard format: `blake3:{hex}`.
pub fn hash_file(path: &Path) -> Result<String, std::io::Error> {
    let data = std::fs::read(path)?;
    Ok(blake3_hash(&data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_hash_format() {
        let hash = blake3_hash(b"hello world");
        assert!(hash.starts_with("blake3:"));
        // blake3 hex is 64 chars
        assert_eq!(hash.len(), 7 + 64); // "blake3:" + 64 hex chars
    }

    #[test]
    fn blake3_hash_deterministic() {
        let a = blake3_hash(b"test data");
        let b = blake3_hash(b"test data");
        assert_eq!(a, b);
    }

    #[test]
    fn blake3_hash_differs_for_different_input() {
        let a = blake3_hash(b"input one");
        let b = blake3_hash(b"input two");
        assert_ne!(a, b);
    }

    #[test]
    fn the_canonical_hash_check_accepts_what_blake3_hash_emits_and_nothing_looser() {
        assert!(is_canonical_blake3_hash(&blake3_hash(b"anything")));
        let good = blake3_hash(b"anything");
        let hex = good.strip_prefix("blake3:").unwrap();
        for bad in [
            String::new(),
            "blake3:".to_string(),
            format!("blake3:{}", &hex[..63]),
            format!("blake3:{hex}0"),
            format!("blake3:{}", hex.to_uppercase()),
            format!("BLAKE3:{hex}"),
            format!("sha256:{hex}"),
            format!("blake3:{}g", &hex[..63]),
            format!(" blake3:{hex}"),
        ] {
            assert!(!is_canonical_blake3_hash(&bad), "{bad:?}");
        }
    }

    #[test]
    fn sha256_hash_format() {
        let hash = sha256_hash(b"hello world");
        assert!(hash.starts_with("sha256:"));
        // sha256 hex is 64 chars
        assert_eq!(hash.len(), 7 + 64);
    }

    #[test]
    fn sha256_hash_deterministic() {
        let a = sha256_hash(b"test data");
        let b = sha256_hash(b"test data");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_file_reads_and_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, b"file content").unwrap();

        let hash = hash_file(&path).unwrap();
        assert!(hash.starts_with("blake3:"));
        assert_eq!(hash, blake3_hash(b"file content"));
    }

    #[test]
    fn hash_file_missing_returns_error() {
        let result = hash_file(Path::new("/nonexistent/path/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn jcs_blake3_hashes_the_canonical_utf8_bytes() {
        let value: Value = serde_json::from_str(r#"{ "b": [1.0, 2], "a": "é" }"#).unwrap();
        assert_eq!(
            jcs_blake3_hash(&value).unwrap(),
            blake3_hash(r#"{"a":"é","b":[1,2]}"#.as_bytes())
        );
    }

    #[test]
    fn jcs_blake3_refuses_what_jcs_cannot_represent() {
        let value: Value = serde_json::from_str(r#"{"id": 9007199254740993}"#).unwrap();
        let error = jcs_blake3_hash(&value).unwrap_err();
        assert_eq!(error.pointer, "/id");
    }
}
