//! Dependency scanner: parses lockfiles to detect cryptographic libraries
//! introduced transitively through third-party dependencies.
//!
//! This module complements the Tree-sitter AST scanner by catching
//! cryptography that is inherited via `package-lock.json`, `requirements.txt`,
//! and `Cargo.lock` — packages that perform crypto internally even if the
//! first-party code never directly imports crypto primitives.

use std::path::Path;

use crate::models::{CryptoAsset, DetectionSource, QuantumSafe, Severity};

// ---------------------------------------------------------------------------
// Known crypto-heavy libraries
// ---------------------------------------------------------------------------

/// Python packages known to use or provide cryptographic functionality.
const PYTHON_CRYPTO_PACKAGES: &[(&str, &str)] = &[
    (
        "cryptography",
        "General-purpose cryptographic library (hazmat primitives, X.509, etc.)",
    ),
    (
        "pycryptodome",
        "PyCryptodome: AES, RSA, DES, hashing, and more",
    ),
    ("pycryptodomex", "PyCryptodome (alternative namespace)"),
    (
        "pynacl",
        "Python binding to libsodium (Curve25519, Ed25519, ChaCha20)",
    ),
    ("pyopenssl", "Python wrapper around OpenSSL (TLS, X.509)"),
    ("pyjwt", "JSON Web Token library (HMAC, RSA, ECDSA signing)"),
    (
        "python-jose",
        "JavaScript Object Signing and Encryption for Python",
    ),
    ("jwcrypto", "JWK, JWS, JWE implementations"),
    (
        "paramiko",
        "SSH2 protocol library (RSA, ECDSA, AES, ChaCha20)",
    ),
    ("bcrypt", "bcrypt password hashing"),
    (
        "passlib",
        "Password hashing framework (bcrypt, scrypt, argon2, etc.)",
    ),
    ("argon2-cffi", "Argon2 password hashing"),
    (
        "itsdangerous",
        "Data signing with HMAC (Flask sessions, etc.)",
    ),
    ("certifi", "Mozilla CA certificate bundle"),
    ("pysftp", "SFTP client built on paramiko (SSH/crypto)"),
    ("fabric", "SSH-based remote execution (uses paramiko)"),
    ("scrypt", "scrypt key derivation function"),
    ("tls", "TLS protocol library"),
    ("requests", "HTTP library (uses TLS via urllib3/OpenSSL)"),
    ("urllib3", "HTTP client with TLS support"),
    ("hashlib", "Standard library hashing (MD5, SHA, BLAKE2)"),
    ("hmac", "Standard library HMAC"),
    ("ssl", "Standard library TLS/SSL"),
    ("gnupg", "GnuPG/GPG interface"),
    ("pgpy", "OpenPGP implementation"),
];

/// Node.js packages known to use or provide cryptographic functionality.
const NPM_CRYPTO_PACKAGES: &[(&str, &str)] = &[
    (
        "jsonwebtoken",
        "JWT signing/verification (HMAC, RSA, ECDSA)",
    ),
    ("bcrypt", "bcrypt password hashing"),
    ("bcryptjs", "Pure-JS bcrypt implementation"),
    (
        "crypto-js",
        "JavaScript cryptographic library (AES, DES, SHA, HMAC)",
    ),
    ("node-forge", "TLS, PKI, X.509, AES, DES, RSA, and more"),
    ("tweetnacl", "TweetNaCl.js (Curve25519, Ed25519, XSalsa20)"),
    ("libsodium-wrappers", "libsodium bindings for JS"),
    ("sodium-native", "Native libsodium bindings"),
    ("jose", "JOSE (JWS, JWE, JWT, JWK) library"),
    ("passport-jwt", "Passport.js JWT authentication strategy"),
    ("helmet", "Express security headers (HSTS, CSP)"),
    (
        "express-session",
        "Session management (may use crypto for session IDs)",
    ),
    ("cookie-signature", "Cookie signing with HMAC"),
    ("ssh2", "SSH2 client/server (RSA, ECDSA, AES, ChaCha20)"),
    ("tls", "Node.js TLS module"),
    ("https", "Node.js HTTPS module"),
    ("argon2", "Argon2 password hashing"),
    ("scrypt-js", "scrypt key derivation"),
    ("openpgp", "OpenPGP.js (RSA, ECC, AES, compression)"),
    (
        "elliptic",
        "Elliptic curve cryptography (secp256k1, P-256, etc.)",
    ),
    ("ethereumjs-util", "Ethereum utilities (secp256k1, keccak)"),
    ("web3", "Ethereum Web3.js (signing, hashing)"),
    ("ethers", "Ethereum library (signing, keccak, AES)"),
];

/// Rust crates known to use or provide cryptographic functionality.
const CARGO_CRYPTO_PACKAGES: &[(&str, &str)] = &[
    ("rustls", "TLS library in pure Rust"),
    (
        "ring",
        "Cryptographic primitives (AES, SHA, RSA, ECDSA, Ed25519)",
    ),
    ("openssl", "OpenSSL bindings for Rust"),
    ("openssl-sys", "Raw OpenSSL FFI bindings"),
    ("native-tls", "Platform TLS abstraction"),
    ("aes", "AES block cipher"),
    ("aes-gcm", "AES-GCM authenticated encryption"),
    ("chacha20poly1305", "ChaCha20-Poly1305 AEAD"),
    ("sha2", "SHA-2 hash functions"),
    ("sha3", "SHA-3 / Keccak hash functions"),
    ("blake2", "BLAKE2 hash function"),
    ("blake3", "BLAKE3 hash function"),
    ("md-5", "MD5 hash function"),
    ("hmac", "HMAC message authentication"),
    ("rsa", "RSA encryption/signing"),
    ("ed25519-dalek", "Ed25519 signing"),
    ("x25519-dalek", "X25519 Diffie-Hellman"),
    ("curve25519-dalek", "Curve25519 elliptic curve"),
    ("p256", "NIST P-256 elliptic curve"),
    ("p384", "NIST P-384 elliptic curve"),
    ("k256", "secp256k1 elliptic curve"),
    ("ecdsa", "ECDSA signature algorithm"),
    ("jsonwebtoken", "JWT encoding/decoding"),
    ("argon2", "Argon2 password hashing"),
    ("bcrypt", "bcrypt password hashing"),
    ("scrypt", "scrypt key derivation"),
    ("pbkdf2", "PBKDF2 key derivation"),
    ("hkdf", "HKDF key derivation"),
    ("digest", "Cryptographic digest traits"),
    ("cipher", "Symmetric cipher traits"),
    ("pqcrypto", "Post-quantum cryptography"),
    ("kyber", "CRYSTALS-Kyber key encapsulation"),
    ("dilithium", "CRYSTALS-Dilithium signatures"),
    ("snow", "Noise protocol framework"),
    ("sodiumoxide", "libsodium bindings for Rust"),
    ("sequoia-openpgp", "OpenPGP implementation"),
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan a directory tree for dependency lockfiles and extract cryptographic
/// dependencies from them.
pub fn scan_dependencies(root: &str) -> Vec<CryptoAsset> {
    let mut findings = Vec::new();
    let root_path = Path::new(root);

    // Scan for each lockfile type
    scan_for_lockfile(root_path, "requirements.txt", &mut findings);
    scan_for_lockfile(root_path, "Pipfile.lock", &mut findings);
    scan_for_lockfile(root_path, "package-lock.json", &mut findings);
    scan_for_lockfile(root_path, "yarn.lock", &mut findings);
    scan_for_lockfile(root_path, "Cargo.lock", &mut findings);

    findings
}

// ---------------------------------------------------------------------------
// Lockfile scanning
// ---------------------------------------------------------------------------

fn scan_for_lockfile(root: &Path, filename: &str, findings: &mut Vec<CryptoAsset>) {
    let lockfile_path = root.join(filename);
    if !lockfile_path.exists() {
        return;
    }

    let contents = match std::fs::read_to_string(&lockfile_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let path_str = lockfile_path.to_string_lossy().to_string();

    match filename {
        "requirements.txt" => parse_requirements(&contents, &path_str, findings),
        "Pipfile.lock" => parse_pipfile_lock(&contents, &path_str, findings),
        "package-lock.json" => parse_package_lock_json(&contents, &path_str, findings),
        "yarn.lock" => parse_yarn_lock(&contents, &path_str, findings),
        "Cargo.lock" => parse_cargo_lock(&contents, &path_str, findings),
        _ => {}
    }
}

/// Parse `requirements.txt` for known crypto packages.
fn parse_requirements(contents: &str, file_path: &str, findings: &mut Vec<CryptoAsset>) {
    for (line_num, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        // Extract package name (before ==, >=, <=, ~=, !=, etc.)
        let pkg_name = extract_python_package_name(line);
        if let Some((_, description)) = PYTHON_CRYPTO_PACKAGES
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(&pkg_name))
        {
            let mut asset = CryptoAsset::new(
                format!("DEPENDENCY:{}", pkg_name.to_uppercase()),
                file_path.to_string(),
                line_num + 1,
                pkg_name.to_string(),
            );
            asset.detection_source = DetectionSource::Dependency;
            asset.findings.push(description.to_string());
            findings.push(asset);
        }
    }
}

/// Parse `Pipfile.lock` (JSON) for known crypto packages.
fn parse_pipfile_lock(contents: &str, file_path: &str, findings: &mut Vec<CryptoAsset>) {
    // Pipfile.lock is JSON; extract package names from "default" and "develop" sections
    let parsed: serde_json::Value = match serde_json::from_str(contents) {
        Ok(v) => v,
        Err(_) => return,
    };

    for section in &["default", "develop"] {
        if let Some(packages) = parsed.get(section).and_then(|s| s.as_object()) {
            for (pkg_name, _) in packages {
                let normalized = pkg_name.to_lowercase().replace('-', "_");
                if let Some((_, description)) = PYTHON_CRYPTO_PACKAGES
                    .iter()
                    .find(|(name, _)| name.to_lowercase().replace('-', "_") == normalized)
                {
                    let mut asset = CryptoAsset::new(
                        format!("DEPENDENCY:{}", pkg_name.to_uppercase()),
                        file_path.to_string(),
                        0,
                        pkg_name.to_string(),
                    );
                    asset.detection_source = DetectionSource::Dependency;
                    asset.findings.push(description.to_string());
                    findings.push(asset);
                }
            }
        }
    }
}

/// Parse `package-lock.json` for known crypto npm packages with dependency path tracing.
fn parse_package_lock_json(contents: &str, file_path: &str, findings: &mut Vec<CryptoAsset>) {
    let parsed: serde_json::Value = match serde_json::from_str(contents) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Build a map of package -> list of its direct dependencies
    let mut pkg_deps: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    // package-lock.json v2/v3: "packages" key
    if let Some(packages) = parsed.get("packages").and_then(|p| p.as_object()) {
        for (pkg_path, pkg_info) in packages {
            let pkg_name = pkg_path.rsplit('/').next().unwrap_or(pkg_path).to_string();

            // Collect this package's own dependencies
            let mut deps = Vec::new();
            if let Some(dep_obj) = pkg_info.get("dependencies").and_then(|d| d.as_object()) {
                for (dep_name, _) in dep_obj {
                    deps.push(dep_name.clone());
                }
            }
            if let Some(dep_obj) = pkg_info.get("devDependencies").and_then(|d| d.as_object()) {
                for (dep_name, _) in dep_obj {
                    deps.push(dep_name.clone());
                }
            }
            if !deps.is_empty() {
                pkg_deps.insert(pkg_name.clone(), deps);
            }

            check_npm_package_with_path(&pkg_name, file_path, &pkg_deps, findings);
        }
    }

    // package-lock.json v1: "dependencies" key
    if let Some(deps) = parsed.get("dependencies").and_then(|d| d.as_object()) {
        for (pkg_name, pkg_info) in deps {
            // v1 nests transitive deps; collect them
            if let Some(sub_deps) = pkg_info.get("requires").and_then(|r| r.as_object()) {
                let dep_list: Vec<String> = sub_deps.keys().cloned().collect();
                pkg_deps.insert(pkg_name.clone(), dep_list);
            }
            check_npm_package_with_path(pkg_name, file_path, &pkg_deps, findings);
        }
    }
}

fn check_npm_package_with_path(
    pkg_name: &str,
    file_path: &str,
    pkg_deps: &std::collections::HashMap<String, Vec<String>>,
    findings: &mut Vec<CryptoAsset>,
) {
    if let Some((_, description)) = NPM_CRYPTO_PACKAGES
        .iter()
        .find(|(name, _)| *name == pkg_name)
    {
        // Avoid duplicates
        if findings
            .iter()
            .any(|f| f.library_source == pkg_name && f.file_path == file_path)
        {
            return;
        }
        let mut asset = CryptoAsset::new(
            format!("DEPENDENCY:{}", pkg_name.to_uppercase()),
            file_path.to_string(),
            0,
            pkg_name.to_string(),
        );
        asset.detection_source = DetectionSource::Dependency;
        asset.findings.push(description.to_string());

        // Find which packages depend on this crypto package
        let parents: Vec<&String> = pkg_deps
            .iter()
            .filter(|(_, deps)| deps.iter().any(|d| d == pkg_name))
            .map(|(parent, _)| parent)
            .collect();

        if !parents.is_empty() {
            // Pick the first non-crypto parent as the most useful trace
            let best_parent = parents
                .iter()
                .find(|p| {
                    !NPM_CRYPTO_PACKAGES
                        .iter()
                        .any(|(name, _)| *name == p.as_str())
                })
                .unwrap_or(&&parents[0]);
            asset.dependency_path = Some(format!("{} -> {}", best_parent, pkg_name));
        }

        findings.push(asset);
    }
}

fn check_npm_package(pkg_name: &str, file_path: &str, findings: &mut Vec<CryptoAsset>) {
    if let Some((_, description)) = NPM_CRYPTO_PACKAGES
        .iter()
        .find(|(name, _)| *name == pkg_name)
    {
        // Avoid duplicates
        if findings
            .iter()
            .any(|f| f.library_source == pkg_name && f.file_path == file_path)
        {
            return;
        }
        let mut asset = CryptoAsset::new(
            format!("DEPENDENCY:{}", pkg_name.to_uppercase()),
            file_path.to_string(),
            0,
            pkg_name.to_string(),
        );
        asset.detection_source = DetectionSource::Dependency;
        asset.findings.push(description.to_string());
        findings.push(asset);
    }
}

/// Parse `yarn.lock` for known crypto npm packages.
fn parse_yarn_lock(contents: &str, file_path: &str, findings: &mut Vec<CryptoAsset>) {
    // yarn.lock uses a custom format; package names appear at the start of lines
    // like: `jsonwebtoken@^9.0.0:`
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Package lines don't start with whitespace and contain '@'
        if !line.starts_with(char::is_whitespace) && line.contains('@') {
            let pkg_name = line.split('@').next().unwrap_or("").trim_matches('"');
            check_npm_package(pkg_name, file_path, findings);
        }
    }
}

/// Parse `Cargo.lock` for known crypto Rust crates and trace transitive dependency paths.
///
/// Builds a lightweight dependency graph from `Cargo.lock` and, for each
/// crypto crate found, traces the path from the project root to the crypto
/// crate through intermediate dependencies.
fn parse_cargo_lock(contents: &str, file_path: &str, findings: &mut Vec<CryptoAsset>) {
    // Phase 1: Parse all packages and their dependencies from Cargo.lock
    let mut packages: Vec<CargoPackage> = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_deps: Vec<String> = Vec::new();

    for line in contents.lines() {
        let line = line.trim();

        if line == "[[package]]" {
            // Flush previous package
            if let Some(name) = current_name.take() {
                packages.push(CargoPackage {
                    name,
                    dependencies: std::mem::take(&mut current_deps),
                });
            }
            current_deps.clear();
        }

        if line.starts_with("name = ") {
            let name = line
                .trim_start_matches("name = ")
                .trim_matches('"')
                .to_string();
            current_name = Some(name);
        }

        // Parse dependencies array entries like:  "ring",  "rustls 0.21.0",
        if line.starts_with('"') && current_name.is_some() {
            let dep_name = line
                .trim_matches('"')
                .trim_end_matches(',')
                .trim_matches('"')
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            if !dep_name.is_empty() {
                current_deps.push(dep_name);
            }
        }
    }

    // Flush last package
    if let Some(name) = current_name.take() {
        packages.push(CargoPackage {
            name,
            dependencies: current_deps,
        });
    }

    // Phase 2: Build reverse dependency map (child -> list of parents)
    let mut reverse_deps: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for pkg in &packages {
        for dep in &pkg.dependencies {
            reverse_deps
                .entry(dep.clone())
                .or_default()
                .push(pkg.name.clone());
        }
    }

    // Phase 3: Find crypto packages and trace paths
    for pkg in &packages {
        if let Some((_, description)) = CARGO_CRYPTO_PACKAGES
            .iter()
            .find(|(name, _)| *name == pkg.name.as_str())
        {
            let mut asset = CryptoAsset::new(
                format!("DEPENDENCY:{}", pkg.name.to_uppercase()),
                file_path.to_string(),
                0,
                pkg.name.to_string(),
            );
            asset.detection_source = DetectionSource::Dependency;
            asset.findings.push(description.to_string());

            // Trace dependency path
            let path = trace_dependency_path(&pkg.name, &reverse_deps);
            if !path.is_empty() {
                asset.dependency_path = Some(path);
            }

            findings.push(asset);
        }
    }
}

/// A parsed package from Cargo.lock.
struct CargoPackage {
    name: String,
    dependencies: Vec<String>,
}

/// Trace the reverse dependency path from a crypto crate back to the project root.
///
/// Returns a string like `"axum -> hyper -> rustls -> ring"` or an empty string
/// if the crate appears to be a direct dependency (no parent chain).
fn trace_dependency_path(
    target: &str,
    reverse_deps: &std::collections::HashMap<String, Vec<String>>,
) -> String {
    let mut path = vec![target.to_string()];
    let mut current = target.to_string();
    let mut visited = std::collections::HashSet::new();
    visited.insert(current.clone());

    // Walk up the reverse dependency tree, preferring non-crypto parents
    loop {
        if let Some(parents) = reverse_deps.get(&current) {
            // Pick the first parent that we haven't visited yet, preferring non-crypto ones
            let next = parents
                .iter()
                .filter(|p| !visited.contains(*p))
                .find(|p| {
                    !CARGO_CRYPTO_PACKAGES
                        .iter()
                        .any(|(name, _)| *name == p.as_str())
                })
                .or_else(|| parents.iter().find(|p| !visited.contains(*p)));

            if let Some(parent) = next {
                path.push(parent.clone());
                visited.insert(parent.clone());
                current = parent.clone();
            } else {
                break;
            }
        } else {
            break;
        }
    }

    if path.len() <= 1 {
        return String::new();
    }

    path.reverse();
    path.join(" -> ")
}

fn check_cargo_package(pkg_name: &str, file_path: &str, findings: &mut Vec<CryptoAsset>) {
    if let Some((_, description)) = CARGO_CRYPTO_PACKAGES
        .iter()
        .find(|(name, _)| *name == pkg_name)
    {
        let mut asset = CryptoAsset::new(
            format!("DEPENDENCY:{}", pkg_name.to_uppercase()),
            file_path.to_string(),
            0,
            pkg_name.to_string(),
        );
        asset.detection_source = DetectionSource::Dependency;
        asset.findings.push(description.to_string());
        findings.push(asset);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the package name from a requirements.txt line.
/// Handles formats like: `cryptography==41.0.0`, `requests>=2.28`, `bcrypt`, `package[extra]`.
fn extract_python_package_name(line: &str) -> String {
    let line = line.split('#').next().unwrap_or(line).trim();
    let line = line.split(';').next().unwrap_or(line).trim();

    // Split on version specifiers
    let name = line
        .split(&['=', '>', '<', '!', '~', '['][..])
        .next()
        .unwrap_or(line)
        .trim();

    // Normalize: PEP 503 says hyphens and underscores are equivalent
    name.to_lowercase().replace('-', "_")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_python_package_name() {
        assert_eq!(
            extract_python_package_name("cryptography==41.0.0"),
            "cryptography"
        );
        assert_eq!(extract_python_package_name("requests>=2.28.1"), "requests");
        assert_eq!(extract_python_package_name("bcrypt"), "bcrypt");
        assert_eq!(extract_python_package_name("PyJWT>=2.0"), "pyjwt");
        assert_eq!(
            extract_python_package_name("argon2-cffi[dev]"),
            "argon2_cffi"
        );
        assert_eq!(extract_python_package_name("  passlib  "), "passlib");
        assert_eq!(extract_python_package_name("flask  # not crypto"), "flask");
    }

    #[test]
    fn test_parse_requirements() {
        let contents = "\
# Python deps
cryptography==41.0.0
requests>=2.28
flask==2.3.0
PyJWT>=2.0
bcrypt
";
        let mut findings = Vec::new();
        parse_requirements(contents, "requirements.txt", &mut findings);

        let names: Vec<&str> = findings.iter().map(|f| f.library_source.as_str()).collect();
        assert!(names.contains(&"cryptography"));
        assert!(names.contains(&"pyjwt"));
        assert!(names.contains(&"bcrypt"));
        assert!(names.contains(&"requests"));
        // flask is not a crypto package
        assert!(!names.iter().any(|n| n.contains("flask")));
    }

    #[test]
    fn test_parse_cargo_lock() {
        let contents = r#"
[[package]]
name = "ring"
version = "0.17.0"

[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "rustls"
version = "0.21.0"
"#;
        let mut findings = Vec::new();
        parse_cargo_lock(contents, "Cargo.lock", &mut findings);

        let names: Vec<&str> = findings.iter().map(|f| f.library_source.as_str()).collect();
        assert!(names.contains(&"ring"));
        assert!(names.contains(&"rustls"));
        assert!(!names.contains(&"serde"));
    }

    #[test]
    fn test_parse_package_lock_json() {
        let contents = r#"{
  "name": "my-app",
  "packages": {
    "": {},
    "node_modules/jsonwebtoken": {
      "version": "9.0.0"
    },
    "node_modules/express": {
      "version": "4.18.0"
    },
    "node_modules/bcrypt": {
      "version": "5.1.0"
    }
  }
}"#;
        let mut findings = Vec::new();
        parse_package_lock_json(contents, "package-lock.json", &mut findings);

        let names: Vec<&str> = findings.iter().map(|f| f.library_source.as_str()).collect();
        assert!(names.contains(&"jsonwebtoken"));
        assert!(names.contains(&"bcrypt"));
        assert!(!names.contains(&"express"));
    }

    #[test]
    fn test_dependency_assets_have_correct_source() {
        let contents = "bcrypt==4.0.0\n";
        let mut findings = Vec::new();
        parse_requirements(contents, "requirements.txt", &mut findings);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].detection_source, DetectionSource::Dependency);
    }
}
