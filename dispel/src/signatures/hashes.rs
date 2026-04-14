/// SHA-256 hashes of known Realm C2 / imix agent binaries.
///
/// To add a hash, compute the SHA-256 of a confirmed imix binary and add an entry:
///   ("abcdef0123456789...", "imix v0.1.0 linux x86_64 - from lab range X"),
///
/// The first element is the lowercase hex SHA-256 hash.
/// The second element is a human-readable description (version, platform, source).
pub const KNOWN_HASHES: &[(&str, &str)] = &[
    // Example (commented out):
    // ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty file - placeholder"),
];

/// Check whether a SHA-256 hash matches a known imix binary.
/// Returns a description string if the hash is recognized, None otherwise.
pub fn check_hash(sha256: &str) -> Option<&'static str> {
    let lower = sha256.to_lowercase();
    for &(hash, description) in KNOWN_HASHES {
        if hash == lower {
            return Some(description);
        }
    }
    None
}

/// Compute the SHA-256 hash of a file, returning the lowercase hex string.
/// Returns None if the file cannot be read.
pub fn sha256_file(path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::fs;

    let contents = fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&contents);
    Some(format!("{:x}", hasher.finalize()))
}
