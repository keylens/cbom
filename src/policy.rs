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
/// (`severity`, `quantum_safe`, `findings`, `remediation`).
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
            severity_upgrade(
                &mut findings,
                "ECB mode is insecure: it leaks patterns in ciphertext.",
            );
            asset.remediation = Some(
                "Replace ECB mode with GCM (authenticated encryption). \
                 Example: use AES-256-GCM instead of AES-ECB."
                    .to_string(),
            );
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
                &format!(
                    "RSA key size {} bits is below the 2048-bit minimum.",
                    key_size
                ),
            );
        }
        if algo.contains("AES") && key_size < 128 {
            severity_upgrade(
                &mut findings,
                &format!(
                    "AES key size {} bits is non-standard and insecure.",
                    key_size
                ),
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

    // --- Remediation advice ---
    asset.remediation = generate_remediation(&algo, &asset.library_source);

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
    if algo.contains("KYBER")
        || algo.contains("DILITHIUM")
        || algo.contains("SPHINCS")
        || algo.contains("FALCON")
        || algo.contains("NTRU")
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
    if algo.contains("RSA")
        || algo.contains("ECDSA")
        || algo.contains("ECDH")
        || algo.contains("DSA")
        || algo.contains("ECC")
        || algo.contains("ED25519")
        || algo.contains("X25519")
        || algo.contains("EDDSA")
        || algo.contains("DH")
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
            a if a.contains("MD5") => {
                "MD5 is cryptographically broken; collisions are trivial to produce."
            }
            a if a.contains("MD4") => "MD4 is cryptographically broken and should never be used.",
            a if a.contains("SHA1") || a == "SHA-1" => {
                "SHA-1 is deprecated; practical collision attacks exist (SHAttered)."
            }
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
        findings.push(
            "Hardcoded cryptographic material detected; use secure random generation.".to_string(),
        );
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
// Remediation advice
// ---------------------------------------------------------------------------

/// Generate code-level remediation advice for a given algorithm and library.
///
/// Returns `None` if the algorithm is considered safe and no action is needed.
fn generate_remediation(algo: &str, library_source: &str) -> Option<String> {
    let lib = library_source.to_lowercase();

    // --- MD5 ---
    if algo.contains("MD5") {
        if lib.contains("hashlib") || lib.contains("python") {
            return Some(
                "Replace MD5 with SHA-256.\n\
                 Before: hashlib.md5(data).hexdigest()\n\
                 After:  hashlib.sha256(data).hexdigest()"
                    .to_string(),
            );
        }
        if lib.contains("crypto") || lib.contains("node") {
            return Some(
                "Replace MD5 with SHA-256.\n\
                 Before: crypto.createHash('md5').update(data).digest('hex')\n\
                 After:  crypto.createHash('sha256').update(data).digest('hex')"
                    .to_string(),
            );
        }
        if lib.contains("java") || lib.contains("messagedigest") {
            return Some(
                "Replace MD5 with SHA-256.\n\
                 Before: MessageDigest.getInstance(\"MD5\")\n\
                 After:  MessageDigest.getInstance(\"SHA-256\")"
                    .to_string(),
            );
        }
        return Some(
            "Replace MD5 with SHA-256 or SHA-3. MD5 is cryptographically broken.".to_string(),
        );
    }

    // --- SHA-1 ---
    if algo.contains("SHA1") || algo == "SHA-1" {
        if lib.contains("hashlib") || lib.contains("python") {
            return Some(
                "Replace SHA-1 with SHA-256.\n\
                 Before: hashlib.sha1(data).hexdigest()\n\
                 After:  hashlib.sha256(data).hexdigest()"
                    .to_string(),
            );
        }
        if lib.contains("crypto") || lib.contains("node") {
            return Some(
                "Replace SHA-1 with SHA-256.\n\
                 Before: crypto.createHash('sha1').update(data).digest('hex')\n\
                 After:  crypto.createHash('sha256').update(data).digest('hex')"
                    .to_string(),
            );
        }
        return Some(
            "Replace SHA-1 with SHA-256 or SHA-3. SHA-1 has known collision attacks.".to_string(),
        );
    }

    // --- DES ---
    if algo == "DES" {
        // Java check first because "javax.crypto" contains "crypto"
        if lib.contains("javax") || lib.contains("cipher") || lib.contains("java") {
            return Some(
                "Replace DES with AES/GCM.\n\
                 Before: Cipher.getInstance(\"DES\")\n\
                 After:  Cipher.getInstance(\"AES/GCM/NoPadding\")"
                    .to_string(),
            );
        }
        if lib.contains("crypto") || lib.contains("node") {
            return Some(
                "Replace DES with AES-256-GCM.\n\
                 Before: crypto.createCipheriv('des-ecb', key, '')\n\
                 After:  crypto.createCipheriv('aes-256-gcm', key, iv)"
                    .to_string(),
            );
        }
        return Some(
            "Replace DES (56-bit key) with AES-256-GCM. DES is trivially brute-forced.".to_string(),
        );
    }

    // --- RC4 ---
    if algo.contains("RC4") {
        return Some(
            "Replace RC4 with AES-256-GCM or ChaCha20-Poly1305. RC4 is prohibited in TLS."
                .to_string(),
        );
    }

    // --- 3DES ---
    if algo.contains("3DES") || algo.contains("TRIPLE") || algo.contains("TRIPLEDES") {
        return Some(
            "Migrate from 3DES to AES-256-GCM. 3DES has a 64-bit block size \
             vulnerable to Sweet32 birthday attacks."
                .to_string(),
        );
    }

    // --- Insecure PRNG ---
    if algo == "INSECURE_PRNG" || algo == "WEAK_RANDOM" {
        if lib.contains("python") || lib.contains("random") {
            return Some(
                "Use a cryptographically secure PRNG.\n\
                 Before: random.randint(0, 255)\n\
                 After:  secrets.token_bytes(32) or os.urandom(32)"
                    .to_string(),
            );
        }
        if lib.contains("math") || lib.contains("node") || lib.contains("javascript") {
            return Some(
                "Use a cryptographically secure PRNG.\n\
                 Before: Math.random()\n\
                 After:  crypto.randomBytes(32) or crypto.getRandomValues(new Uint8Array(32))"
                    .to_string(),
            );
        }
        return Some("Replace with a cryptographically secure PRNG (CSPRNG).".to_string());
    }

    // --- Hardcoded secrets ---
    if algo == "HARDCODED_IV" || algo == "HARDCODED_SALT" || algo == "HARDCODED_KEY" {
        let material = match algo {
            "HARDCODED_IV" => "IV (Initialization Vector)",
            "HARDCODED_SALT" => "salt",
            _ => "key",
        };
        return Some(format!(
            "Do not hardcode the {}. Generate it randomly at runtime.\n\
             Example (Python): os.urandom(16)\n\
             Example (Node.js): crypto.randomBytes(16)\n\
             Example (Java): SecureRandom().nextBytes(new byte[16])",
            material
        ));
    }

    // --- RSA with small key ---
    if algo.contains("RSA") {
        return Some(
            "If using RSA, ensure a minimum key size of 2048 bits (preferably 4096). \
             Consider migrating to Ed25519 for signing or ECDH for key exchange. \
             For post-quantum readiness, evaluate ML-KEM (Kyber)."
                .to_string(),
        );
    }

    // No remediation needed for safe algorithms
    None
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
        assert!(asset
            .findings
            .iter()
            .any(|f| f.contains("below the 2048-bit minimum")));
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

    #[test]
    fn test_md5_remediation_python() {
        let mut asset = make_asset("MD5");
        asset.library_source = "hashlib".to_string();
        evaluate(&mut asset);
        assert!(asset.remediation.is_some());
        let rem = asset.remediation.unwrap();
        assert!(rem.contains("SHA-256"));
        assert!(rem.contains("hashlib.sha256"));
    }

    #[test]
    fn test_md5_remediation_node() {
        let mut asset = make_asset("MD5");
        asset.library_source = "node:crypto".to_string();
        evaluate(&mut asset);
        assert!(asset.remediation.is_some());
        let rem = asset.remediation.unwrap();
        assert!(rem.contains("sha256"));
        assert!(rem.contains("createHash"));
    }

    #[test]
    fn test_des_remediation() {
        let mut asset = make_asset("DES");
        asset.library_source = "javax.crypto.Cipher".to_string();
        evaluate(&mut asset);
        assert!(asset.remediation.is_some());
        assert!(asset.remediation.unwrap().contains("AES/GCM"));
    }

    #[test]
    fn test_aes_safe_no_remediation() {
        let mut asset = make_asset("AES");
        evaluate(&mut asset);
        assert!(asset.remediation.is_none());
    }

    #[test]
    fn test_hardcoded_key_remediation() {
        let mut asset = make_asset("HARDCODED_KEY");
        evaluate(&mut asset);
        assert!(asset.remediation.is_some());
        assert!(asset.remediation.unwrap().contains("randomly at runtime"));
    }

    #[test]
    fn test_rsa_remediation() {
        let mut asset = make_asset("RSA");
        evaluate(&mut asset);
        assert!(asset.remediation.is_some());
        assert!(asset.remediation.unwrap().contains("2048"));
    }
}
