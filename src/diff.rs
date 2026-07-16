//! Diff engine: compares two CBOM JSON files and reports newly
//! introduced cryptographic assets.
//!
//! This is the core of the "PLG" (Policy Gate) engine — designed to be
//! wired into CI pipelines so that Pull Requests introducing new
//! cryptography can be flagged or blocked automatically.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::models::CryptoAsset;

/// The result of comparing two CBOM files.
pub struct DiffResult {
    /// Crypto assets present in `head` but absent from `base`.
    pub added: Vec<CryptoAsset>,
    /// Crypto assets present in `base` but absent from `head`.
    pub removed: Vec<CryptoAsset>,
}

/// Load a CBOM JSON file from disk and deserialize it into a `Vec<CryptoAsset>`.
///
/// Returns a descriptive error message on failure (file not found,
/// invalid JSON, schema mismatch, etc.).
pub fn load_cbom(path: &str) -> Result<Vec<CryptoAsset>, String> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(format!("File not found: {}", path));
    }

    let contents = fs::read_to_string(p)
        .map_err(|e| format!("Failed to read '{}': {}", path, e))?;

    let assets: Vec<CryptoAsset> = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse '{}' as CBOM JSON: {}", path, e))?;

    Ok(assets)
}

/// Compare a **base** CBOM against a **head** CBOM and return the delta.
///
/// - `added`: items in `head` that do **not** appear in `base` (new crypto).
/// - `removed`: items in `base` that do **not** appear in `head` (removed crypto).
///
/// Comparison uses the full `CryptoAsset` equality (algorithm + file_path +
/// line_number + library_source), leveraging the `Hash` + `Eq` derives.
pub fn diff_cbom(base: &[CryptoAsset], head: &[CryptoAsset]) -> DiffResult {
    let base_set: HashSet<&CryptoAsset> = base.iter().collect();
    let head_set: HashSet<&CryptoAsset> = head.iter().collect();

    let added: Vec<CryptoAsset> = head
        .iter()
        .filter(|asset| !base_set.contains(asset))
        .cloned()
        .collect();

    let removed: Vec<CryptoAsset> = base
        .iter()
        .filter(|asset| !head_set.contains(asset))
        .cloned()
        .collect();

    DiffResult { added, removed }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CryptoAsset;

    fn asset(algo: &str, file: &str, line: usize, lib: &str) -> CryptoAsset {
        CryptoAsset {
            algorithm: algo.to_string(),
            file_path: file.to_string(),
            line_number: line,
            library_source: lib.to_string(),
        }
    }

    #[test]
    fn test_no_changes() {
        let base = vec![asset("SHA256", "a.py", 1, "hashlib")];
        let head = vec![asset("SHA256", "a.py", 1, "hashlib")];
        let result = diff_cbom(&base, &head);
        assert!(result.added.is_empty());
        assert!(result.removed.is_empty());
    }

    #[test]
    fn test_new_crypto_added() {
        let base = vec![asset("SHA256", "a.py", 1, "hashlib")];
        let head = vec![
            asset("SHA256", "a.py", 1, "hashlib"),
            asset("AES", "b.py", 5, "Crypto"),
        ];
        let result = diff_cbom(&base, &head);
        assert_eq!(result.added.len(), 1);
        assert_eq!(result.added[0].algorithm, "AES");
        assert!(result.removed.is_empty());
    }

    #[test]
    fn test_crypto_removed() {
        let base = vec![
            asset("SHA256", "a.py", 1, "hashlib"),
            asset("MD5", "c.py", 10, "hashlib"),
        ];
        let head = vec![asset("SHA256", "a.py", 1, "hashlib")];
        let result = diff_cbom(&base, &head);
        assert!(result.added.is_empty());
        assert_eq!(result.removed.len(), 1);
        assert_eq!(result.removed[0].algorithm, "MD5");
    }

    #[test]
    fn test_both_added_and_removed() {
        let base = vec![asset("MD5", "old.py", 3, "hashlib")];
        let head = vec![asset("SHA256", "new.py", 7, "hashlib")];
        let result = diff_cbom(&base, &head);
        assert_eq!(result.added.len(), 1);
        assert_eq!(result.added[0].algorithm, "SHA256");
        assert_eq!(result.removed.len(), 1);
        assert_eq!(result.removed[0].algorithm, "MD5");
    }

    #[test]
    fn test_empty_base() {
        let base: Vec<CryptoAsset> = vec![];
        let head = vec![asset("AES", "x.js", 1, "node:crypto")];
        let result = diff_cbom(&base, &head);
        assert_eq!(result.added.len(), 1);
        assert!(result.removed.is_empty());
    }

    #[test]
    fn test_both_empty() {
        let base: Vec<CryptoAsset> = vec![];
        let head: Vec<CryptoAsset> = vec![];
        let result = diff_cbom(&base, &head);
        assert!(result.added.is_empty());
        assert!(result.removed.is_empty());
    }
}
