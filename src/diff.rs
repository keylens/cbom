//! Diff engine: compares two CBOM JSON files and reports newly
//! introduced cryptographic assets.
//!
//! This is the core of the "PLG" (Policy Gate) engine — designed to be
//! wired into CI pipelines so that Pull Requests introducing new
//! cryptography can be flagged or blocked automatically.
//!
//! Enhanced with `--strict` mode to enforce policy violations.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::models::CryptoAsset;
use crate::policy;

/// The result of comparing two CBOM files.
pub struct DiffResult {
    /// Crypto assets present in `head` but absent from `base`.
    pub added: Vec<CryptoAsset>,
    /// Crypto assets present in `base` but absent from `head`.
    pub removed: Vec<CryptoAsset>,
    /// Whether any added asset violates strict policy (deprecated algo, etc.).
    pub has_violations: bool,
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

    let contents =
        fs::read_to_string(p).map_err(|e| format!("Failed to read '{}': {}", path, e))?;

    let assets: Vec<CryptoAsset> = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse '{}' as CBOM JSON: {}", path, e))?;

    Ok(assets)
}

/// Compare a **base** CBOM against a **head** CBOM and return the delta.
///
/// - `added`: items in `head` that do **not** appear in `base` (new crypto).
/// - `removed`: items in `base` that do **not** appear in `head` (removed crypto).
/// - `has_violations`: `true` if any added asset is deprecated.
///
/// Comparison uses algorithm + file_path + line_number + library_source
/// for identity (the `Hash` + `Eq` derives on `CryptoAsset`).
///
/// If `strict` is true, added assets are evaluated through the policy engine
/// and `has_violations` is set accordingly.
pub fn diff_cbom(base: &[CryptoAsset], head: &[CryptoAsset], strict: bool) -> DiffResult {
    let base_set: HashSet<CryptoFingerprint> = base.iter().map(fingerprint).collect();
    let head_set: HashSet<CryptoFingerprint> = head.iter().map(fingerprint).collect();

    let mut added: Vec<CryptoAsset> = head
        .iter()
        .filter(|asset| !base_set.contains(&fingerprint(asset)))
        .cloned()
        .collect();

    let removed: Vec<CryptoAsset> = base
        .iter()
        .filter(|asset| !head_set.contains(&fingerprint(asset)))
        .cloned()
        .collect();

    // Evaluate added assets through the policy engine
    policy::evaluate_all(&mut added);

    let has_violations = if strict {
        policy::has_deprecated(&added) || policy::has_critical(&added)
    } else {
        false
    };

    DiffResult {
        added,
        removed,
        has_violations,
    }
}

// ---------------------------------------------------------------------------
// Fingerprinting
// ---------------------------------------------------------------------------

/// A fingerprint used to compare two `CryptoAsset` instances for diff purposes.
/// We compare on algorithm + file_path + line_number + library_source, ignoring
/// the richer context fields that may differ between runs.
#[derive(Hash, PartialEq, Eq)]
struct CryptoFingerprint {
    algorithm: String,
    file_path: String,
    line_number: usize,
    library_source: String,
}

fn fingerprint(asset: &CryptoAsset) -> CryptoFingerprint {
    CryptoFingerprint {
        algorithm: asset.algorithm.clone(),
        file_path: asset.file_path.clone(),
        line_number: asset.line_number,
        library_source: asset.library_source.clone(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CryptoAsset, DetectionSource, QuantumSafe, Severity};

    fn asset(algo: &str, file: &str, line: usize, lib: &str) -> CryptoAsset {
        CryptoAsset {
            algorithm: algo.to_string(),
            file_path: file.to_string(),
            line_number: line,
            library_source: lib.to_string(),
            key_size: None,
            mode: None,
            padding: None,
            curve: None,
            quantum_safe: QuantumSafe::Unknown,
            severity: Severity::Unknown,
            detection_source: DetectionSource::SourceCode,
            findings: Vec::new(),
            cert_subject: None,
            cert_issuer: None,
            cert_expiry: None,
            cert_serial: None,
            protocol_version: None,
            cipher_suites: Vec::new(),
            dependency_path: None,
            remediation: None,
        }
    }

    #[test]
    fn test_no_changes() {
        let base = vec![asset("SHA256", "a.py", 1, "hashlib")];
        let head = vec![asset("SHA256", "a.py", 1, "hashlib")];
        let result = diff_cbom(&base, &head, false);
        assert!(result.added.is_empty());
        assert!(result.removed.is_empty());
        assert!(!result.has_violations);
    }

    #[test]
    fn test_new_crypto_added() {
        let base = vec![asset("SHA256", "a.py", 1, "hashlib")];
        let head = vec![
            asset("SHA256", "a.py", 1, "hashlib"),
            asset("AES", "b.py", 5, "Crypto"),
        ];
        let result = diff_cbom(&base, &head, false);
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
        let result = diff_cbom(&base, &head, false);
        assert!(result.added.is_empty());
        assert_eq!(result.removed.len(), 1);
        assert_eq!(result.removed[0].algorithm, "MD5");
    }

    #[test]
    fn test_both_added_and_removed() {
        let base = vec![asset("MD5", "old.py", 3, "hashlib")];
        let head = vec![asset("SHA256", "new.py", 7, "hashlib")];
        let result = diff_cbom(&base, &head, false);
        assert_eq!(result.added.len(), 1);
        assert_eq!(result.added[0].algorithm, "SHA256");
        assert_eq!(result.removed.len(), 1);
        assert_eq!(result.removed[0].algorithm, "MD5");
    }

    #[test]
    fn test_empty_base() {
        let base: Vec<CryptoAsset> = vec![];
        let head = vec![asset("AES", "x.js", 1, "node:crypto")];
        let result = diff_cbom(&base, &head, false);
        assert_eq!(result.added.len(), 1);
        assert!(result.removed.is_empty());
    }

    #[test]
    fn test_both_empty() {
        let base: Vec<CryptoAsset> = vec![];
        let head: Vec<CryptoAsset> = vec![];
        let result = diff_cbom(&base, &head, false);
        assert!(result.added.is_empty());
        assert!(result.removed.is_empty());
    }

    #[test]
    fn test_strict_mode_flags_deprecated() {
        let base: Vec<CryptoAsset> = vec![];
        let head = vec![asset("MD5", "bad.py", 1, "hashlib")];
        let result = diff_cbom(&base, &head, true);
        assert!(result.has_violations);
    }

    #[test]
    fn test_strict_mode_passes_for_safe() {
        let base: Vec<CryptoAsset> = vec![];
        let head = vec![asset("AES", "good.py", 1, "Crypto")];
        let result = diff_cbom(&base, &head, true);
        assert!(!result.has_violations);
    }

    #[test]
    fn test_non_strict_mode_no_violations() {
        let base: Vec<CryptoAsset> = vec![];
        let head = vec![asset("MD5", "bad.py", 1, "hashlib")];
        let result = diff_cbom(&base, &head, false);
        // Even with deprecated algo, has_violations is false without strict
        assert!(!result.has_violations);
    }
}
