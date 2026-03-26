use std::path::Path;

use sha2::{Digest, Sha256};

/// Compute a BLAKE3 hash of the given bytes.
///
/// Returns the spine-standard format: `blake3:{hex}`.
pub fn blake3_hash(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    format!("blake3:{}", hash.to_hex())
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
}
