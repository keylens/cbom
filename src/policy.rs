//! Policy engine: evaluates cryptographic assets and assigns severity levels,
//! quantum-safety status, and human-readable findings.
//!
//! This module is the "brain" that turns a raw inventory into actionable
//! security intelligence. It classifies every detected algorithm against
//! current best practices and post-quantum readiness.

use crate::models::{CryptoAsset, QuantumSafe, Severity};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Evaluate a single `CryptoAsset` and populate its policy fields
/// (`severity`, `quantum_safe`, `findings`).
pub fn evaluate(asset: &mut CryptoAsset) {
    let algo = asset.algorithm.to_uppercase();

    // --- Quantum safety ---
    asset.quantum_safe = classify_quantum_safety(&algo);

    // --- Severity + findings ---
    let (severity, mut findings) = classify_severity(&algo, asset);

    // Mode-specific checks
    if let Some(ref mode) = asset.mode {
        let mode_upper = mode.to_uppercase();
        if mode_upper == "ECB" {
            severity_upgrade(&mut findings, "ECB mode is insecure: it leaks patterns in ciphertext.");
            // ECB is always critical
            asset.severity = Severity::Critical;
            asset.findings = findings;
            return;
        } else if mode_upper == "CBC" {
            findings.push(
                "CBC mode lacks built-in authentication; prefer GCM or use HMAC alongside."
                    .to_string(),
            );
        }
    }

    // Key-size checks
    if let Some(key_size) = asset.key_size {
        if algo.contains("RSA") && key_size < 2048 {
            severity_upgrade(
                &mut findings,
                &format!("RSA key size {} bits is below the 2048-bit minimum.", key_size),
            );
        }
        if algo.contains("AES") && key_size < 128 {
            severity_upgrade(
                &mut findings,
                &format!("AES key size {} bits is non-standard and insecure.", key_size),
            );
        }
    }

    // Quantum-safety finding
    if asset.quantum_safe == QuantumSafe::Vulnerable {
        findings.push(
            "Algorithm is vulnerable to quantum computing attacks (Shor's/Grover's algorithm)."
                .to_string(),
        );
    }

    asset.severity = severity;
    asset.findings = findings;
}

/// Evaluate a batch of `CryptoAsset`s in place.
pub fn evaluate_all(assets: &mut [CryptoAsset]) {
    for asset in assets.iter_mut() {
        evaluate(asset);
    }
}

/// Returns `true` if any asset in the list has `Severity::Critical`.
pub fn has_critical(assets: &[CryptoAsset]) -> bool {
    assets.iter().any(|a| a.severity == Severity::Critical)
}

/// Returns `true` if any asset is flagged as a deprecated algorithm
/// (MD5, SHA-1, DES, RC4, etc.).
pub fn has_deprecated(assets: &[CryptoAsset]) -> bool {
    assets.iter().any(|a| {
        let algo = a.algorithm.to_uppercase();
        is_deprecated(&algo)
    })
}

// ---------------------------------------------------------------------------
// Classification logic
// ---------------------------------------------------------------------------

/// Classify the quantum-safety posture of an algorithm.
fn classify_quantum_safety(algo: &str) -> QuantumSafe {
    // Post-quantum safe algorithms
    if algo.contains("KYBER") || algo.contains("DILITHIUM") || algo.contains("SPHINCS")
        || algo.contains("FALCON") || algo.contains("NTRU")
    {
        return QuantumSafe::Safe;
    }

    // Symmetric algorithms: Grover's halves the key size but ≥128 bit is still OK
    if algo.contains("AES") || algo.contains("CHACHA") || algo.contains("CAMELLIA") {
        return QuantumSafe::Safe;
    }

    // Hash functions are weakened by Grover's but still considered safe enough
    if algo.contains("SHA") || algo.contains("BLAKE") || algo.contains("HMAC") {
        return QuantumSafe::Safe;
    }

    // Asymmetric / public-key: broken by Shor's algorithm
    if algo.contains("RSA") || algo.contains("ECDSA") || algo.contains("ECDH")
        || algo.contains("DSA") || algo.contains("ECC") || algo.contains("ED25519")
        || algo.contains("X25519") || algo.contains("EDDSA") || algo.contains("DH")
        || algo.contains("ELGAMAL")
    {
        return QuantumSafe::Vulnerable;
    }

    QuantumSafe::Unknown
}

/// Classify severity and generate findings for an algorithm.
fn classify_severity(algo: &str, asset: &CryptoAsset) -> (Severity, Vec<String>) {
    let mut findings = Vec::new();

    // --- Critical: fully deprecated / broken ---
    if is_deprecated(algo) {
        let reason = match algo {
            a if a.contains("MD5") => "MD5 is cryptographically broken; collisions are trivial to produce.",
            a if a.contains("MD4") => "MD4 is cryptographically broken and should never be used.",
            a if a.contains("SHA1") || a == "SHA-1" => "SHA-1 is deprecated; practical collision attacks exist (SHAttered).",
            a if a == "DES" => "DES uses a 56-bit key and is trivially brute-forced.",
            a if a.contains("RC4") => "RC4 has multiple known biases and is prohibited in TLS.",
            a if a.contains("RC2") => "RC2 is an obsolete cipher with known weaknesses.",
            _ => "This algorithm is deprecated and should not be used.",
        };
        findings.push(reason.to_string());
        return (Severity::Critical, findings);
    }

    // --- Warning: weak or risky usage patterns ---
    if algo.contains("3DES") || algo.contains("TRIPLE") || algo.contains("TRIPLEDES") {
        findings.push("3DES (Triple DES) has a 64-bit block size vulnerable to Sweet32 attacks; migrate to AES.".to_string());
        return (Severity::Warning, findings);
    }

    // Insecure PRNG
    if algo == "INSECURE_PRNG" || algo == "WEAK_RANDOM" {
        findings.push("Non-cryptographically secure PRNG detected; use secrets/os.urandom (Python) or crypto.randomBytes (Node.js).".to_string());
        return (Severity::Critical, findings);
    }

    // Hardcoded secrets
    if algo == "HARDCODED_IV" || algo == "HARDCODED_SALT" || algo == "HARDCODED_KEY" {
        findings.push("Hardcoded cryptographic material detected; use secure random generation.".to_string());
        return (Severity::Critical, findings);
    }

    // --- Info: quantum-vulnerable but currently acceptable ---
    if asset.quantum_safe == QuantumSafe::Vulnerable {
        return (Severity::Info, findings);
    }

    // --- Safe ---
    (Severity::Safe, findings)
}

/// Check if an algorithm is considered fully deprecated / broken.
fn is_deprecated(algo: &str) -> bool {
    let checks = ["MD5", "MD4", "SHA1", "RC4", "RC2"];
    if checks.iter().any(|&c| algo.contains(c)) {
        return true;
    }
    // Exact match for DES (avoid matching 3DES / TRIPLEDES)
    if algo == "DES" {
        return true;
    }
    // SHA-1 variant
    if algo == "SHA-1" {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn severity_upgrade(findings: &mut Vec<String>, message: &str) {
    findings.push(message.to_string());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CryptoAsset, DetectionSource};

    fn make_asset(algo: &str) -> CryptoAsset {
        CryptoAsset {
            algorithm: algo.to_string(),
            file_path: "test.py".to_string(),
            line_number: 1,
            library_source: "test".to_string(),
            key_size: None,
            mode: None,
            padding: None,
            curve: None,
            quantum_safe: QuantumSafe::Unknown,
            severity: Severity::Unknown,
            detection_source: DetectionSource::SourceCode,
            findings: Vec::new(),
        }
    }

    #[test]
    fn test_md5_is_critical() {
        let mut asset = make_asset("MD5");
        evaluate(&mut asset);
        assert_eq!(asset.severity, Severity::Critical);
        assert!(!asset.findings.is_empty());
    }

    #[test]
    fn test_sha1_is_critical() {
        let mut asset = make_asset("SHA1");
        evaluate(&mut asset);
        assert_eq!(asset.severity, Severity::Critical);
    }

    #[test]
    fn test_des_is_critical() {
        let mut asset = make_asset("DES");
        evaluate(&mut asset);
        assert_eq!(asset.severity, Severity::Critical);
    }

    #[test]
    fn test_aes_is_safe() {
        let mut asset = make_asset("AES");
        evaluate(&mut asset);
        assert_eq!(asset.severity, Severity::Safe);
        assert_eq!(asset.quantum_safe, QuantumSafe::Safe);
    }

    #[test]
    fn test_rsa_is_quantum_vulnerable() {
        let mut asset = make_asset("RSA");
        evaluate(&mut asset);
        assert_eq!(asset.quantum_safe, QuantumSafe::Vulnerable);
        assert_eq!(asset.severity, Severity::Info);
    }

    #[test]
    fn test_ecb_mode_is_critical() {
        let mut asset = make_asset("AES");
        asset.mode = Some("ECB".to_string());
        evaluate(&mut asset);
        assert_eq!(asset.severity, Severity::Critical);
    }

    #[test]
    fn test_cbc_mode_has_warning() {
        let mut asset = make_asset("AES");
        asset.mode = Some("CBC".to_string());
        evaluate(&mut asset);
        assert!(asset.findings.iter().any(|f| f.contains("CBC")));
    }

    #[test]
    fn test_small_rsa_key() {
        let mut asset = make_asset("RSA");
        asset.key_size = Some(1024);
        evaluate(&mut asset);
        assert!(asset.findings.iter().any(|f| f.contains("below the 2048-bit minimum")));
    }

    #[test]
    fn test_kyber_is_quantum_safe() {
        let mut asset = make_asset("KYBER");
        evaluate(&mut asset);
        assert_eq!(asset.quantum_safe, QuantumSafe::Safe);
    }

    #[test]
    fn test_hardcoded_iv_is_critical() {
        let mut asset = make_asset("HARDCODED_IV");
        evaluate(&mut asset);
        assert_eq!(asset.severity, Severity::Critical);
    }

    #[test]
    fn test_insecure_prng_is_critical() {
        let mut asset = make_asset("INSECURE_PRNG");
        evaluate(&mut asset);
        assert_eq!(asset.severity, Severity::Critical);
    }

    #[test]
    fn test_3des_is_warning() {
        let mut asset = make_asset("3DES");
        evaluate(&mut asset);
        assert_eq!(asset.severity, Severity::Warning);
    }

    #[test]
    fn test_has_deprecated() {
        let assets = vec![make_asset("AES"), make_asset("MD5")];
        assert!(has_deprecated(&assets));
    }

    #[test]
    fn test_no_deprecated() {
        let assets = vec![make_asset("AES"), make_asset("SHA256")];
        assert!(!has_deprecated(&assets));
    }
}
