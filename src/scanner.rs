//! Scanner module: walks a directory tree and detects cryptographic usage
//! in Python, JavaScript, Java, C, C++, C#, and Go source files using
//! Tree-sitter AST parsing.
//!
//! Also scans for X.509 certificate files (.pem, .crt, .cer, .der) and
//! TLS/SSL protocol configurations in code.
//!
//! Uses the `ignore` crate (from the ripgrep team) for fast, .gitignore-aware
//! file walking, and Tree-sitter queries for reliable AST-based detection
//! without requiring compilation.
//!
//! Enhanced to extract deep cryptographic context: key sizes, modes of
//! operation, padding schemes, elliptic curves, hardcoded IVs/salts,
//! and insecure PRNG usage.

use ignore::WalkBuilder;
use std::path::Path;
use tree_sitter::{Parser, Query, QueryCursor};

use crate::models::{CryptoAsset, DetectionSource, QuantumSafe, Severity};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Known Python modules that provide cryptographic functionality.
const PYTHON_CRYPTO_MODULES: &[&str] = &[
    "hashlib",
    "hmac",
    "ssl",
    "cryptography",
    "Crypto",
    "Cryptodome",
];

/// Known algorithm names that appear as method calls on `hashlib`.
const HASHLIB_ALGORITHMS: &[&str] = &[
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s", "sha3_224",
    "sha3_256", "sha3_384", "sha3_512",
];

/// Directories to always skip during scanning (in addition to .gitignore rules).
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "tests",
    ".git",
    "bin",
    "obj",
    "vendor",
    "build",
    "out",
    "target",
];

/// Known Java classes/packages that provide cryptographic functionality.
const JAVA_CRYPTO_PACKAGES: &[&str] = &["javax.crypto", "java.security", "org.bouncycastle"];

/// Known C/C++ crypto function prefixes (OpenSSL, libsodium).
const C_CRYPTO_FUNCTIONS: &[&str] = &[
    "EVP_",
    "EVP_MD_",
    "EVP_CIPHER_",
    "EVP_PKEY_",
    "SSL_",
    "SSL_CTX_",
    "crypto_secretbox",
    "crypto_box",
    "crypto_sign",
    "crypto_aead",
    "crypto_hash",
    "crypto_auth",
    "crypto_pwhash",
    "crypto_kx",
    "crypto_kdf",
    "randombytes",
];

/// Known C# cryptographic namespaces.
const CSHARP_CRYPTO_NAMESPACES: &[&str] = &["System.Security.Cryptography"];

/// Known Go crypto import paths.
const GO_CRYPTO_PACKAGES: &[&str] = &[
    "crypto/aes",
    "crypto/des",
    "crypto/hmac",
    "crypto/md5",
    "crypto/sha1",
    "crypto/sha256",
    "crypto/sha512",
    "crypto/rsa",
    "crypto/ecdsa",
    "crypto/ed25519",
    "crypto/elliptic",
    "crypto/rand",
    "crypto/tls",
    "crypto/x509",
    "crypto/cipher",
    "golang.org/x/crypto",
];

/// Certificate file extensions to scan.
const CERT_EXTENSIONS: &[&str] = &["pem", "crt", "cer", "der"];

/// Known elliptic curves for detection.
const KNOWN_CURVES: &[&str] = &[
    "P-256",
    "P-384",
    "P-521",
    "prime256v1",
    "secp256r1",
    "secp384r1",
    "secp521r1",
    "secp256k1",
    "Curve25519",
    "Ed25519",
    "X25519",
    "curve25519",
    "ed25519",
    "x25519",
];

/// Known padding schemes for detection.
const KNOWN_PADDINGS: &[&str] = &[
    "PKCS7", "PKCS1v15", "OAEP", "PSS", "ANSIX923", "ISO10126", "pkcs7", "pkcs1", "oaep", "pss",
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan a directory for cryptographic usage in source files and certificates.
///
/// Supports: Python, JavaScript, Java, C, C++, C#, Go, and X.509 certificate files.
///
/// Uses the `ignore` crate to walk the directory tree, automatically
/// respecting `.gitignore` rules and skipping hidden files. Additionally
/// skips well-known non-source directories like `node_modules` and `venv`.
pub fn scan_directory(root: &str) -> Vec<CryptoAsset> {
    let mut findings = Vec::new();

    let walker = WalkBuilder::new(root)
        .standard_filters(true) // respect .gitignore, skip hidden
        .build();

    for result in walker {
        let entry = match result {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();

        // Skip directories themselves (we only process files)
        if path.is_dir() {
            continue;
        }

        // Skip hardcoded directories that might not be in .gitignore
        if should_skip_path(path) {
            continue;
        }

        let ext = match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => ext.to_owned(),
            None => continue,
        };

        let file_path_str = path.to_string_lossy().to_string();

        // Certificate files are binary — handle them separately
        if CERT_EXTENSIONS.contains(&ext.as_str()) {
            findings.extend(scan_certificate_file(path, &file_path_str));
            continue;
        }

        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue, // skip binary files or permission errors
        };

        match ext.as_str() {
            "py" => findings.extend(scan_python(&source, &file_path_str)),
            "js" | "mjs" | "cjs" => findings.extend(scan_javascript(&source, &file_path_str)),
            "java" => findings.extend(scan_java(&source, &file_path_str)),
            "c" | "h" => findings.extend(scan_c(&source, &file_path_str)),
            "cpp" | "cc" | "cxx" | "hpp" | "hxx" => {
                findings.extend(scan_cpp(&source, &file_path_str))
            }
            "cs" => findings.extend(scan_csharp(&source, &file_path_str)),
            "go" => findings.extend(scan_go(&source, &file_path_str)),
            _ => {}
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Path filtering
// ---------------------------------------------------------------------------

/// Returns `true` if the path contains any directory component we should skip.
fn should_skip_path(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_str().unwrap_or("");
        SKIP_DIRS.contains(&s)
    })
}

// ---------------------------------------------------------------------------
// Algorithm string parser
// ---------------------------------------------------------------------------

/// Parse a compound algorithm string like `"aes-256-cbc"` or `"aes-128-gcm"`
/// into its component parts: (base_algorithm, key_size, mode).
///
/// Also handles formats like `"sha256"`, `"des-ede3-cbc"`, etc.
fn parse_algorithm_string(algo_str: &str) -> (String, Option<u32>, Option<String>) {
    let lower = algo_str.to_lowercase();
    let parts: Vec<&str> = lower.split('-').collect();

    let mut base_algo = String::new();
    let mut key_size: Option<u32> = None;
    let mut mode: Option<String> = None;

    for part in &parts {
        // Check if it's a key size
        if let Ok(size) = part.parse::<u32>() {
            if size >= 64 && size <= 4096 {
                key_size = Some(size);
                continue;
            }
        }

        // Check if it's a mode
        let upper = part.to_uppercase();
        if matches!(
            upper.as_str(),
            "CBC" | "GCM" | "ECB" | "CTR" | "CFB" | "OFB" | "CCM" | "XTS" | "WRAP"
        ) {
            mode = Some(upper);
            continue;
        }

        // Otherwise it's part of the algorithm name
        if !base_algo.is_empty() {
            base_algo.push('-');
        }
        base_algo.push_str(&part.to_uppercase());
    }

    if base_algo.is_empty() {
        base_algo = algo_str.to_uppercase();
    }

    (base_algo, key_size, mode)
}

// ---------------------------------------------------------------------------
// Python scanner
// ---------------------------------------------------------------------------

/// Scan a Python source file for cryptographic imports and method calls.
///
/// Detects:
/// - `import hashlib` / `import hmac` / `import ssl`
/// - `from cryptography.hazmat.primitives.hashes import SHA256`
/// - `from Crypto.Cipher import AES`
/// - `hashlib.sha256()` / `hashlib.new('sha256')` method calls
/// - `hmac.new(...)` calls
/// - `import random` (insecure PRNG warning)
/// - Hardcoded IVs/salts/keys as byte literals
fn scan_python(source: &str, file_path: &str) -> Vec<CryptoAsset> {
    let mut findings = Vec::new();
    let language = tree_sitter_python::language();

    let mut parser = Parser::new();
    parser
        .set_language(language)
        .expect("Failed to load Python grammar");

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return findings,
    };
    let root = tree.root_node();
    let src = source.as_bytes();

    // --- Query 1: `import <module>` statements ---
    scan_python_imports(&mut findings, language, root, src, file_path);

    // --- Query 2: `from <module> import <names>` statements ---
    scan_python_from_imports(&mut findings, language, root, src, file_path);

    // --- Query 3: method calls like `hashlib.sha256()` ---
    scan_python_calls(&mut findings, language, root, src, file_path);

    // --- Query 4: insecure PRNG (`import random`) ---
    scan_python_insecure_random(&mut findings, language, root, src, file_path);

    // --- Query 5: hardcoded IVs/salts ---
    scan_python_hardcoded_secrets(&mut findings, source, file_path);

    findings
}

/// Detect `import hashlib`, `import hmac`, etc.
fn scan_python_imports(
    findings: &mut Vec<CryptoAsset>,
    language: tree_sitter::Language,
    root: tree_sitter::Node,
    src: &[u8],
    file_path: &str,
) {
    let query_str = "(import_statement) @stmt";
    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return,
    };

    let mut cursor = QueryCursor::new();
    for qm in cursor.matches(&query, root, src) {
        for capture in qm.captures {
            let text = capture.node.utf8_text(src).unwrap_or("");
            let line = capture.node.start_position().row + 1;

            // Parse "import hashlib" or "import hashlib, hmac, os"
            for module in extract_import_modules(text) {
                let base = module.split('.').next().unwrap_or(&module);
                if PYTHON_CRYPTO_MODULES.contains(&base) {
                    findings.push(CryptoAsset::new(
                        algorithm_from_python_module(base),
                        file_path.to_string(),
                        line,
                        base.to_string(),
                    ));
                }
            }
        }
    }
}

/// Detect `from cryptography.hazmat... import SHA256` style imports.
fn scan_python_from_imports(
    findings: &mut Vec<CryptoAsset>,
    language: tree_sitter::Language,
    root: tree_sitter::Node,
    src: &[u8],
    file_path: &str,
) {
    let query_str = "(import_from_statement) @stmt";
    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return,
    };

    let mut cursor = QueryCursor::new();
    for qm in cursor.matches(&query, root, src) {
        for capture in qm.captures {
            let text = capture.node.utf8_text(src).unwrap_or("");
            let line = capture.node.start_position().row + 1;

            if let Some((module, names)) = parse_from_import(text) {
                let base = module.split('.').next().unwrap_or(&module);
                if PYTHON_CRYPTO_MODULES.contains(&base) {
                    for name in &names {
                        let mut asset = CryptoAsset::new(
                            algorithm_from_python_import(base, name, &module),
                            file_path.to_string(),
                            line,
                            base.to_string(),
                        );

                        // Enrich with context from the import path
                        enrich_python_import_context(&mut asset, &module, name);

                        findings.push(asset);
                    }
                }
            }
        }
    }
}

/// Detect method calls like `hashlib.sha256()`, `hashlib.new('sha256')`, `hmac.new(...)`.
fn scan_python_calls(
    findings: &mut Vec<CryptoAsset>,
    language: tree_sitter::Language,
    root: tree_sitter::Node,
    src: &[u8],
    file_path: &str,
) {
    let query_str = r#"
        (call
          function: (attribute
            object: (identifier) @obj
            attribute: (identifier) @method))
    "#;

    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return,
    };

    let obj_idx = query.capture_index_for_name("obj").unwrap();
    let method_idx = query.capture_index_for_name("method").unwrap();

    let mut cursor = QueryCursor::new();
    for qm in cursor.matches(&query, root, src) {
        let obj_text = capture_text(qm.captures, obj_idx, src);
        let method_text = capture_text(qm.captures, method_idx, src);
        let line = capture_line(qm.captures, obj_idx);

        if obj_text == "hashlib" {
            if HASHLIB_ALGORITHMS.contains(&method_text.as_str()) {
                findings.push(CryptoAsset::new(
                    method_text.to_uppercase(),
                    file_path.to_string(),
                    line,
                    "hashlib".to_string(),
                ));
            } else if method_text == "new" {
                // Generic constructor: hashlib.new('sha256')
                // Navigate: @obj (identifier) → parent (attribute) → parent (call)
                if let Some(call_node) = capture_node(qm.captures, obj_idx)
                    .and_then(|n| n.parent())
                    .and_then(|n| n.parent())
                {
                    if let Some(algo) = extract_first_string_arg(call_node, src) {
                        findings.push(CryptoAsset::new(
                            algo.to_uppercase(),
                            file_path.to_string(),
                            line,
                            "hashlib".to_string(),
                        ));
                    }
                }
            }
        } else if obj_text == "hmac" && method_text == "new" {
            findings.push(CryptoAsset::new(
                "HMAC".to_string(),
                file_path.to_string(),
                line,
                "hmac".to_string(),
            ));
        }
    }
}

/// Detect `import random` — flags insecure PRNG usage.
fn scan_python_insecure_random(
    findings: &mut Vec<CryptoAsset>,
    language: tree_sitter::Language,
    root: tree_sitter::Node,
    src: &[u8],
    file_path: &str,
) {
    let query_str = "(import_statement) @stmt";
    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return,
    };

    let mut cursor = QueryCursor::new();
    for qm in cursor.matches(&query, root, src) {
        for capture in qm.captures {
            let text = capture.node.utf8_text(src).unwrap_or("");
            let line = capture.node.start_position().row + 1;

            for module in extract_import_modules(text) {
                if module == "random" {
                    let mut asset = CryptoAsset::new(
                        "INSECURE_PRNG".to_string(),
                        file_path.to_string(),
                        line,
                        "random".to_string(),
                    );
                    asset.severity = Severity::Critical;
                    asset.findings.push(
                        "Python's `random` module is NOT cryptographically secure. Use `secrets` or `os.urandom()` instead.".to_string(),
                    );
                    findings.push(asset);
                }
            }
        }
    }

    // Also check `from random import ...`
    let query_str2 = "(import_from_statement) @stmt";
    let query2 = match Query::new(language, query_str2) {
        Ok(q) => q,
        Err(_) => return,
    };

    let mut cursor2 = QueryCursor::new();
    for qm in cursor2.matches(&query2, root, src) {
        for capture in qm.captures {
            let text = capture.node.utf8_text(src).unwrap_or("");
            let line = capture.node.start_position().row + 1;

            if let Some((module, _)) = parse_from_import(text) {
                if module == "random" {
                    let mut asset = CryptoAsset::new(
                        "INSECURE_PRNG".to_string(),
                        file_path.to_string(),
                        line,
                        "random".to_string(),
                    );
                    asset.severity = Severity::Critical;
                    asset.findings.push(
                        "Python's `random` module is NOT cryptographically secure. Use `secrets` or `os.urandom()` instead.".to_string(),
                    );
                    findings.push(asset);
                }
            }
        }
    }
}

/// Detect hardcoded IVs, salts, and keys in Python source.
/// Looks for patterns like `iv = b'...'` or `salt = b'...'`.
fn scan_python_hardcoded_secrets(findings: &mut Vec<CryptoAsset>, source: &str, file_path: &str) {
    let secret_patterns = &[
        ("iv", "HARDCODED_IV"),
        ("salt", "HARDCODED_SALT"),
        ("key", "HARDCODED_KEY"),
        ("secret", "HARDCODED_KEY"),
        ("nonce", "HARDCODED_IV"),
    ];

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim().to_lowercase();

        for (pattern, algo_name) in secret_patterns {
            // Match patterns like: iv = b'...', iv = b"...", IV = bytes.fromhex("...")
            let is_assignment = trimmed.starts_with(&format!("{} =", pattern))
                || trimmed.starts_with(&format!("{}=", pattern));

            if is_assignment {
                let rhs = trimmed.split('=').nth(1).unwrap_or("").trim();
                let is_hardcoded = rhs.starts_with("b'")
                    || rhs.starts_with("b\"")
                    || rhs.starts_with("bytes")
                    || rhs.starts_with("bytearray");

                if is_hardcoded {
                    let mut asset = CryptoAsset::new(
                        algo_name.to_string(),
                        file_path.to_string(),
                        line_num + 1,
                        "hardcoded".to_string(),
                    );
                    asset.severity = Severity::Critical;
                    asset.findings.push(format!(
                        "Hardcoded {} detected. Use secure random generation instead.",
                        pattern.to_uppercase()
                    ));
                    findings.push(asset);
                }
            }
        }
    }
}

/// Enrich a Python `from ... import ...` CryptoAsset with context.
fn enrich_python_import_context(asset: &mut CryptoAsset, module: &str, name: &str) {
    let module_lower = module.to_lowercase();
    let name_upper = name.to_uppercase();

    // Detect curves from import path
    if module_lower.contains("ec") || module_lower.contains("curve") {
        for curve in KNOWN_CURVES {
            if name_upper.contains(&curve.to_uppercase()) || name == *curve {
                asset.curve = Some(curve.to_string());
            }
        }
        // Common curve imports from `cryptography` library
        if name == "SECP256R1" || name == "secp256r1" {
            asset.curve = Some("P-256".to_string());
        } else if name == "SECP384R1" || name == "secp384r1" {
            asset.curve = Some("P-384".to_string());
        } else if name == "SECP521R1" || name == "secp521r1" {
            asset.curve = Some("P-521".to_string());
        }
    }

    // Detect padding from import path
    if module_lower.contains("padding") || module_lower.contains("asymmetric") {
        for padding in KNOWN_PADDINGS {
            if name_upper.contains(&padding.to_uppercase()) {
                asset.padding = Some(padding.to_string());
            }
        }
    }

    // Detect modes from import path
    if module_lower.contains("modes") || module_lower.contains("cipher") {
        let mode_checks = ["GCM", "CBC", "ECB", "CTR", "CFB", "OFB", "CCM", "XTS"];
        for mode in mode_checks {
            if name_upper == mode {
                asset.mode = Some(mode.to_string());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JavaScript scanner
// ---------------------------------------------------------------------------

/// Scan a JavaScript source file for cryptographic require/import calls
/// and `crypto.*` method calls.
///
/// Detects:
/// - `require('crypto')` / `require('node:crypto')`
/// - `import crypto from 'crypto'`
/// - `crypto.createHash('sha256')` / `crypto.createHmac(...)` / etc.
/// - `crypto.randomBytes(...)` / `crypto.generateKeyPairSync(...)`
/// - Hardcoded IVs/salts/keys
/// - `Math.random()` insecure PRNG usage
fn scan_javascript(source: &str, file_path: &str) -> Vec<CryptoAsset> {
    let mut findings = Vec::new();
    let language = tree_sitter_javascript::language();

    let mut parser = Parser::new();
    parser
        .set_language(language)
        .expect("Failed to load JavaScript grammar");

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return findings,
    };
    let root = tree.root_node();
    let src = source.as_bytes();

    // --- Query 1: require('crypto') calls ---
    scan_js_require(&mut findings, language, root, src, file_path);

    // --- Query 2: crypto.createHash('sha256') style calls ---
    scan_js_crypto_calls(&mut findings, language, root, src, file_path);

    // --- Query 3: crypto.randomBytes() style utility calls ---
    scan_js_crypto_utility(&mut findings, language, root, src, file_path);

    // --- Query 4: import ... from 'crypto' ---
    scan_js_imports(&mut findings, language, root, src, file_path);

    // --- Query 5: Math.random() insecure PRNG ---
    scan_js_math_random(&mut findings, language, root, src, file_path);

    // --- Query 6: hardcoded IVs/salts ---
    scan_js_hardcoded_secrets(&mut findings, source, file_path);

    findings
}

/// Detect `require('crypto')` / `require('node:crypto')` calls.
fn scan_js_require(
    findings: &mut Vec<CryptoAsset>,
    language: tree_sitter::Language,
    root: tree_sitter::Node,
    src: &[u8],
    file_path: &str,
) {
    let query_str = r#"
        (call_expression
          function: (identifier) @func
          arguments: (arguments (string) @arg))
    "#;

    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return,
    };

    let func_idx = query.capture_index_for_name("func").unwrap();
    let arg_idx = query.capture_index_for_name("arg").unwrap();

    let mut cursor = QueryCursor::new();
    for qm in cursor.matches(&query, root, src) {
        let func_text = capture_text(qm.captures, func_idx, src);
        let arg_text = capture_text(qm.captures, arg_idx, src);
        let line = capture_line(qm.captures, func_idx);

        let module = strip_quotes(&arg_text);
        if func_text == "require" && (module == "crypto" || module == "node:crypto") {
            findings.push(CryptoAsset::new(
                "CRYPTO_MODULE_IMPORT".to_string(),
                file_path.to_string(),
                line,
                "node:crypto".to_string(),
            ));
        }
    }
}

/// Detect `crypto.createHash('sha256')`, `crypto.createCipheriv('aes-256-cbc', ...)`, etc.
/// Enhanced to parse compound algorithm strings for deep context.
fn scan_js_crypto_calls(
    findings: &mut Vec<CryptoAsset>,
    language: tree_sitter::Language,
    root: tree_sitter::Node,
    src: &[u8],
    file_path: &str,
) {
    let query_str = r#"
        (call_expression
          function: (member_expression
            object: (identifier) @obj
            property: (property_identifier) @method)
          arguments: (arguments (string) @arg))
    "#;

    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return,
    };

    let obj_idx = query.capture_index_for_name("obj").unwrap();
    let method_idx = query.capture_index_for_name("method").unwrap();
    let arg_idx = query.capture_index_for_name("arg").unwrap();

    let mut cursor = QueryCursor::new();
    for qm in cursor.matches(&query, root, src) {
        let obj_text = capture_text(qm.captures, obj_idx, src);
        let method_text = capture_text(qm.captures, method_idx, src);
        let arg_text = capture_text(qm.captures, arg_idx, src);
        let line = capture_line(qm.captures, obj_idx);

        if obj_text == "crypto" {
            let raw_algo = strip_quotes(&arg_text);
            match method_text.as_str() {
                "createHash" | "createHmac" | "createCipheriv" | "createDecipheriv"
                | "createSign" | "createVerify" => {
                    let (base_algo, key_size, mode) = parse_algorithm_string(&raw_algo);
                    let mut asset = CryptoAsset::new(
                        base_algo,
                        file_path.to_string(),
                        line,
                        "node:crypto".to_string(),
                    );
                    asset.key_size = key_size;
                    asset.mode = mode;
                    findings.push(asset);
                }
                _ => {}
            }
        }
    }
}

/// Detect `crypto.randomBytes(...)`, `crypto.generateKeyPairSync(...)`, etc.
fn scan_js_crypto_utility(
    findings: &mut Vec<CryptoAsset>,
    language: tree_sitter::Language,
    root: tree_sitter::Node,
    src: &[u8],
    file_path: &str,
) {
    let query_str = r#"
        (call_expression
          function: (member_expression
            object: (identifier) @obj
            property: (property_identifier) @method))
    "#;

    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return,
    };

    let obj_idx = query.capture_index_for_name("obj").unwrap();
    let method_idx = query.capture_index_for_name("method").unwrap();

    let mut cursor = QueryCursor::new();
    for qm in cursor.matches(&query, root, src) {
        let obj_text = capture_text(qm.captures, obj_idx, src);
        let method_text = capture_text(qm.captures, method_idx, src);
        let line = capture_line(qm.captures, obj_idx);

        if obj_text == "crypto" {
            let algo = match method_text.as_str() {
                "randomBytes" | "randomFillSync" | "randomFill" => "CSPRNG",
                "generateKeyPairSync" | "generateKeyPair" => "KEY_GENERATION",
                _ => continue,
            };
            findings.push(CryptoAsset::new(
                algo.to_string(),
                file_path.to_string(),
                line,
                "node:crypto".to_string(),
            ));
        }
    }
}

/// Detect `import crypto from 'crypto'` / `import { createHash } from 'crypto'`.
fn scan_js_imports(
    findings: &mut Vec<CryptoAsset>,
    language: tree_sitter::Language,
    root: tree_sitter::Node,
    src: &[u8],
    file_path: &str,
) {
    let query_str = r#"(import_statement source: (string) @source)"#;

    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return,
    };

    let source_idx = query.capture_index_for_name("source").unwrap();

    let mut cursor = QueryCursor::new();
    for qm in cursor.matches(&query, root, src) {
        let source_text = capture_text(qm.captures, source_idx, src);
        let line = capture_line(qm.captures, source_idx);

        let module = strip_quotes(&source_text);
        if module == "crypto" || module == "node:crypto" {
            findings.push(CryptoAsset::new(
                "CRYPTO_MODULE_IMPORT".to_string(),
                file_path.to_string(),
                line,
                "node:crypto".to_string(),
            ));
        }
    }
}

/// Detect `Math.random()` — insecure PRNG in JavaScript.
fn scan_js_math_random(
    findings: &mut Vec<CryptoAsset>,
    language: tree_sitter::Language,
    root: tree_sitter::Node,
    src: &[u8],
    file_path: &str,
) {
    let query_str = r#"
        (call_expression
          function: (member_expression
            object: (identifier) @obj
            property: (property_identifier) @method))
    "#;

    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return,
    };

    let obj_idx = query.capture_index_for_name("obj").unwrap();
    let method_idx = query.capture_index_for_name("method").unwrap();

    let mut cursor = QueryCursor::new();
    for qm in cursor.matches(&query, root, src) {
        let obj_text = capture_text(qm.captures, obj_idx, src);
        let method_text = capture_text(qm.captures, method_idx, src);
        let line = capture_line(qm.captures, obj_idx);

        if obj_text == "Math" && method_text == "random" {
            let mut asset = CryptoAsset::new(
                "INSECURE_PRNG".to_string(),
                file_path.to_string(),
                line,
                "Math.random".to_string(),
            );
            asset.severity = Severity::Critical;
            asset.findings.push(
                "Math.random() is NOT cryptographically secure. Use crypto.randomBytes() instead."
                    .to_string(),
            );
            findings.push(asset);
        }
    }
}

/// Detect hardcoded IVs, salts, and keys in JavaScript source.
fn scan_js_hardcoded_secrets(findings: &mut Vec<CryptoAsset>, source: &str, file_path: &str) {
    let secret_patterns = &[
        ("iv", "HARDCODED_IV"),
        ("salt", "HARDCODED_SALT"),
        ("key", "HARDCODED_KEY"),
        ("secret", "HARDCODED_KEY"),
        ("nonce", "HARDCODED_IV"),
    ];

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();

        for (pattern, algo_name) in secret_patterns {
            // Match patterns like:
            //   const iv = Buffer.from('...')
            //   let key = '...'
            //   var salt = Buffer.alloc(...)
            let is_const = lower.contains(&format!("const {} =", pattern))
                || lower.contains(&format!("let {} =", pattern))
                || lower.contains(&format!("var {} =", pattern));

            if is_const {
                let rhs = lower.split('=').nth(1).unwrap_or("").trim();
                let is_hardcoded = rhs.starts_with("buffer.from")
                    || rhs.starts_with("buffer.alloc")
                    || rhs.starts_with("'")
                    || rhs.starts_with("\"")
                    || rhs.starts_with("new uint8array");

                if is_hardcoded {
                    let mut asset = CryptoAsset::new(
                        algo_name.to_string(),
                        file_path.to_string(),
                        line_num + 1,
                        "hardcoded".to_string(),
                    );
                    asset.severity = Severity::Critical;
                    asset.findings.push(format!(
                        "Hardcoded {} detected. Use crypto.randomBytes() instead.",
                        pattern.to_uppercase()
                    ));
                    findings.push(asset);
                }
            }
        }
    }
}
// ---------------------------------------------------------------------------
// Java scanner
// ---------------------------------------------------------------------------

/// Scan a Java source file for cryptographic usage.
///
/// Detects:
/// - `import javax.crypto.*` / `import java.security.*`
/// - `import org.bouncycastle.*`
/// - `Cipher.getInstance("AES/CBC/PKCS5Padding")` and similar factory calls
/// - `MessageDigest.getInstance("SHA-256")`
/// - `KeyGenerator.getInstance("AES")`
/// - `SecureRandom` / `java.util.Random` usage
fn scan_java(source: &str, file_path: &str) -> Vec<CryptoAsset> {
    let mut findings = Vec::new();
    let language = tree_sitter_java::language();

    let mut parser = Parser::new();
    parser
        .set_language(language)
        .expect("Failed to load Java grammar");

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return findings,
    };
    let root = tree.root_node();
    let src = source.as_bytes();

    // --- Detect import statements ---
    scan_java_imports(&mut findings, language, root, src, file_path);

    // --- Detect getInstance() factory calls ---
    scan_java_get_instance(&mut findings, language, root, src, file_path);

    // --- Detect insecure java.util.Random ---
    scan_java_insecure_random(&mut findings, source, file_path);

    findings
}

/// Detect Java crypto imports: `import javax.crypto.*`, etc.
fn scan_java_imports(
    findings: &mut Vec<CryptoAsset>,
    language: tree_sitter::Language,
    root: tree_sitter::Node,
    src: &[u8],
    file_path: &str,
) {
    let query_str = "(import_declaration) @import";
    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return,
    };

    let mut cursor = QueryCursor::new();
    for qm in cursor.matches(&query, root, src) {
        for capture in qm.captures {
            let text = capture.node.utf8_text(src).unwrap_or("");
            let line = capture.node.start_position().row + 1;

            let import_path = text
                .trim()
                .trim_start_matches("import")
                .trim_end_matches(';')
                .trim();

            for pkg in JAVA_CRYPTO_PACKAGES {
                if import_path.starts_with(pkg) {
                    let algo = algorithm_from_java_import(import_path);
                    findings.push(CryptoAsset::new(
                        algo,
                        file_path.to_string(),
                        line,
                        pkg.to_string(),
                    ));
                }
            }
        }
    }
}

/// Detect `Cipher.getInstance("AES/CBC/PKCS5Padding")`, `MessageDigest.getInstance("SHA-256")`, etc.
fn scan_java_get_instance(
    findings: &mut Vec<CryptoAsset>,
    language: tree_sitter::Language,
    root: tree_sitter::Node,
    src: &[u8],
    file_path: &str,
) {
    let query_str = r#"
        (method_invocation
          object: (identifier) @obj
          name: (identifier) @method
          arguments: (argument_list (string_literal) @arg))
    "#;

    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return,
    };

    let obj_idx = query.capture_index_for_name("obj").unwrap();
    let method_idx = query.capture_index_for_name("method").unwrap();
    let arg_idx = query.capture_index_for_name("arg").unwrap();

    let mut cursor = QueryCursor::new();
    for qm in cursor.matches(&query, root, src) {
        let obj_text = capture_text(qm.captures, obj_idx, src);
        let method_text = capture_text(qm.captures, method_idx, src);
        let arg_text = capture_text(qm.captures, arg_idx, src);
        let line = capture_line(qm.captures, obj_idx);

        if method_text == "getInstance" {
            let raw = strip_quotes(&arg_text);
            let lib = match obj_text.as_str() {
                "Cipher" => "javax.crypto.Cipher",
                "MessageDigest" => "java.security.MessageDigest",
                "KeyGenerator" => "javax.crypto.KeyGenerator",
                "KeyPairGenerator" => "java.security.KeyPairGenerator",
                "Signature" => "java.security.Signature",
                "Mac" => "javax.crypto.Mac",
                "SecretKeyFactory" => "javax.crypto.SecretKeyFactory",
                "KeyAgreement" => "javax.crypto.KeyAgreement",
                _ => continue,
            };

            // Parse Java algorithm strings like "AES/CBC/PKCS5Padding"
            let parts: Vec<&str> = raw.split('/').collect();
            let base_algo = parts.first().unwrap_or(&"UNKNOWN").to_uppercase();
            let mode = parts.get(1).map(|m| m.to_uppercase());
            let padding = parts.get(2).map(|p| p.to_string());

            let mut asset =
                CryptoAsset::new(base_algo, file_path.to_string(), line, lib.to_string());
            asset.mode = mode;
            asset.padding = padding;
            findings.push(asset);
        }
    }
}

/// Detect `java.util.Random` usage (insecure PRNG).
fn scan_java_insecure_random(findings: &mut Vec<CryptoAsset>, source: &str, file_path: &str) {
    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("java.util.Random")
            || (trimmed.contains("new Random(") && !trimmed.contains("SecureRandom"))
        {
            let mut asset = CryptoAsset::new(
                "INSECURE_PRNG".to_string(),
                file_path.to_string(),
                line_num + 1,
                "java.util.Random".to_string(),
            );
            asset.severity = Severity::Critical;
            asset.findings.push(
                "java.util.Random is NOT cryptographically secure. Use java.security.SecureRandom instead.".to_string(),
            );
            findings.push(asset);
        }
    }
}

/// Map a Java import path to an algorithm label.
fn algorithm_from_java_import(import_path: &str) -> String {
    let last = import_path.rsplit('.').next().unwrap_or("UNKNOWN");
    match last {
        "*" => {
            if import_path.contains("javax.crypto") {
                "JAVAX_CRYPTO (see usage)".to_string()
            } else if import_path.contains("java.security") {
                "JAVA_SECURITY (see usage)".to_string()
            } else {
                "BOUNCYCASTLE (see usage)".to_string()
            }
        }
        "Cipher" => "AES (see usage)".to_string(),
        "MessageDigest" => "HASHING (see usage)".to_string(),
        "SecureRandom" => "CSPRNG".to_string(),
        "KeyGenerator" | "KeyPairGenerator" => "KEY_GENERATION".to_string(),
        "Signature" => "DIGITAL_SIGNATURE".to_string(),
        "Mac" => "HMAC".to_string(),
        "KeyAgreement" => "KEY_AGREEMENT".to_string(),
        _ => last.to_uppercase(),
    }
}

// ---------------------------------------------------------------------------
// C scanner
// ---------------------------------------------------------------------------

/// Scan a C source file for cryptographic usage.
///
/// Detects:
/// - `#include <openssl/...>` headers
/// - `EVP_*` function calls (OpenSSL)
/// - `crypto_secretbox*` / `crypto_box*` (libsodium)
/// - `SSL_*` / `SSL_CTX_*` function calls
fn scan_c(source: &str, file_path: &str) -> Vec<CryptoAsset> {
    let mut findings = Vec::new();
    let language = tree_sitter_c::language();

    let mut parser = Parser::new();
    parser
        .set_language(language)
        .expect("Failed to load C grammar");

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return findings,
    };
    let root = tree.root_node();
    let src = source.as_bytes();

    // --- Detect #include directives for crypto headers ---
    scan_c_includes(&mut findings, source, file_path);

    // --- Detect crypto function calls ---
    scan_c_crypto_calls(&mut findings, language, root, src, file_path);

    findings
}

/// Detect `#include <openssl/...>` and `#include <sodium.h>` preprocessor directives.
fn scan_c_includes(findings: &mut Vec<CryptoAsset>, source: &str, file_path: &str) {
    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("#include") {
            let header = trimmed
                .trim_start_matches("#include")
                .trim()
                .trim_matches(|c: char| c == '<' || c == '>' || c == '"');

            if header.starts_with("openssl/") {
                let algo = match header {
                    "openssl/evp.h" => "EVP (see usage)",
                    "openssl/aes.h" => "AES",
                    "openssl/des.h" => "DES",
                    "openssl/sha.h" => "SHA",
                    "openssl/md5.h" => "MD5",
                    "openssl/rsa.h" => "RSA",
                    "openssl/ec.h" => "ECC",
                    "openssl/hmac.h" => "HMAC",
                    "openssl/ssl.h" => "TLS",
                    "openssl/rand.h" => "CSPRNG",
                    _ => "OPENSSL (see usage)",
                };
                findings.push(CryptoAsset::new(
                    algo.to_string(),
                    file_path.to_string(),
                    line_num + 1,
                    "openssl".to_string(),
                ));
            } else if header == "sodium.h" || header.starts_with("sodium/") {
                findings.push(CryptoAsset::new(
                    "LIBSODIUM (see usage)".to_string(),
                    file_path.to_string(),
                    line_num + 1,
                    "libsodium".to_string(),
                ));
            }
        }
    }
}

/// Detect cryptographic function calls in C: `EVP_*`, `SSL_*`, `crypto_*`.
fn scan_c_crypto_calls(
    findings: &mut Vec<CryptoAsset>,
    language: tree_sitter::Language,
    root: tree_sitter::Node,
    src: &[u8],
    file_path: &str,
) {
    let query_str = r#"
        (call_expression
          function: (identifier) @func)
    "#;

    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return,
    };

    let func_idx = query.capture_index_for_name("func").unwrap();

    let mut cursor = QueryCursor::new();
    for qm in cursor.matches(&query, root, src) {
        let func_text = capture_text(qm.captures, func_idx, src);
        let line = capture_line(qm.captures, func_idx);

        let crypto_match = C_CRYPTO_FUNCTIONS
            .iter()
            .find(|prefix| func_text.starts_with(*prefix));

        if let Some(prefix) = crypto_match {
            let (algo, lib) = classify_c_function(&func_text, prefix);
            findings.push(CryptoAsset::new(algo, file_path.to_string(), line, lib));
        }
    }
}

/// Classify a C crypto function call into algorithm and library.
fn classify_c_function(func_name: &str, prefix: &str) -> (String, String) {
    match prefix {
        "EVP_" | "EVP_MD_" | "EVP_CIPHER_" | "EVP_PKEY_" => {
            let algo = if func_name.contains("sha")
                || func_name.contains("SHA")
                || func_name.contains("md")
                || func_name.contains("Digest")
            {
                "HASHING (see usage)"
            } else if func_name.contains("Encrypt") || func_name.contains("Cipher") {
                "ENCRYPTION (see usage)"
            } else if func_name.contains("Sign") {
                "DIGITAL_SIGNATURE"
            } else {
                "EVP (see usage)"
            };
            (algo.to_string(), "openssl".to_string())
        }
        "SSL_" | "SSL_CTX_" => ("TLS".to_string(), "openssl".to_string()),
        "crypto_secretbox" => ("XSALSA20-POLY1305".to_string(), "libsodium".to_string()),
        "crypto_box" => (
            "X25519-XSALSA20-POLY1305".to_string(),
            "libsodium".to_string(),
        ),
        "crypto_sign" => ("ED25519".to_string(), "libsodium".to_string()),
        "crypto_aead" => ("AEAD (see usage)".to_string(), "libsodium".to_string()),
        "crypto_hash" => ("SHA512".to_string(), "libsodium".to_string()),
        "crypto_auth" => ("HMAC-SHA512-256".to_string(), "libsodium".to_string()),
        "crypto_pwhash" => ("ARGON2".to_string(), "libsodium".to_string()),
        "crypto_kx" => ("KEY_EXCHANGE".to_string(), "libsodium".to_string()),
        "crypto_kdf" => ("KEY_DERIVATION".to_string(), "libsodium".to_string()),
        "randombytes" => ("CSPRNG".to_string(), "libsodium".to_string()),
        _ => ("UNKNOWN".to_string(), "unknown".to_string()),
    }
}

// ---------------------------------------------------------------------------
// C++ scanner
// ---------------------------------------------------------------------------

/// Scan a C++ source file for cryptographic usage.
///
/// Reuses C scanning logic (OpenSSL/libsodium are identical in C++)
/// and additionally detects C++-specific patterns.
fn scan_cpp(source: &str, file_path: &str) -> Vec<CryptoAsset> {
    // C++ shares all of C's crypto patterns
    scan_c(source, file_path)
}

// ---------------------------------------------------------------------------
// C# scanner
// ---------------------------------------------------------------------------

/// Scan a C# source file for cryptographic usage.
///
/// Detects:
/// - `using System.Security.Cryptography;`
/// - `Aes.Create()`, `SHA256.Create()`, etc.
/// - `RNGCryptoServiceProvider` / `RandomNumberGenerator`
/// - `new Random()` (insecure PRNG)
fn scan_csharp(source: &str, file_path: &str) -> Vec<CryptoAsset> {
    let mut findings = Vec::new();
    let language = tree_sitter_c_sharp::language();

    let mut parser = Parser::new();
    parser
        .set_language(language)
        .expect("Failed to load C# grammar");

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return findings,
    };
    let root = tree.root_node();
    let src = source.as_bytes();

    // --- Detect using directives ---
    scan_csharp_usings(&mut findings, source, file_path);

    // --- Detect .Create() factory calls ---
    scan_csharp_create_calls(&mut findings, language, root, src, file_path);

    // --- Detect insecure Random ---
    scan_csharp_insecure_random(&mut findings, source, file_path);

    findings
}

/// Detect `using System.Security.Cryptography;` directives.
fn scan_csharp_usings(findings: &mut Vec<CryptoAsset>, source: &str, file_path: &str) {
    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("using") {
            let ns = trimmed
                .trim_start_matches("using")
                .trim_end_matches(';')
                .trim();

            for crypto_ns in CSHARP_CRYPTO_NAMESPACES {
                if ns.starts_with(crypto_ns) {
                    findings.push(CryptoAsset::new(
                        "SYSTEM_CRYPTO (see usage)".to_string(),
                        file_path.to_string(),
                        line_num + 1,
                        crypto_ns.to_string(),
                    ));
                }
            }
        }
    }
}

/// Detect C# crypto factory calls: `Aes.Create()`, `SHA256.Create()`, etc.
fn scan_csharp_create_calls(
    findings: &mut Vec<CryptoAsset>,
    language: tree_sitter::Language,
    root: tree_sitter::Node,
    src: &[u8],
    file_path: &str,
) {
    let query_str = r#"
        (invocation_expression
          function: (member_access_expression
            expression: (identifier) @obj
            name: (identifier) @method))
    "#;

    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return,
    };

    let obj_idx = query.capture_index_for_name("obj").unwrap();
    let method_idx = query.capture_index_for_name("method").unwrap();

    let mut cursor = QueryCursor::new();
    for qm in cursor.matches(&query, root, src) {
        let obj_text = capture_text(qm.captures, obj_idx, src);
        let method_text = capture_text(qm.captures, method_idx, src);
        let line = capture_line(qm.captures, obj_idx);

        if method_text == "Create" {
            let algo = match obj_text.as_str() {
                "Aes" => "AES",
                "DES" | "TripleDES" => "DES",
                "SHA1" => "SHA1",
                "SHA256" => "SHA256",
                "SHA384" => "SHA384",
                "SHA512" => "SHA512",
                "MD5" => "MD5",
                "RSA" => "RSA",
                "ECDsa" => "ECDSA",
                "ECDiffieHellman" => "ECDH",
                "HMACSHA256" | "HMACSHA512" | "HMACSHA1" => "HMAC",
                "RandomNumberGenerator" => "CSPRNG",
                _ => continue,
            };
            findings.push(CryptoAsset::new(
                algo.to_string(),
                file_path.to_string(),
                line,
                "System.Security.Cryptography".to_string(),
            ));
        }
    }
}

/// Detect `new Random()` in C# (insecure PRNG).
fn scan_csharp_insecure_random(findings: &mut Vec<CryptoAsset>, source: &str, file_path: &str) {
    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("new Random(")
            && !trimmed.contains("SecureRandom")
            && !trimmed.contains("RandomNumberGenerator")
        {
            let mut asset = CryptoAsset::new(
                "INSECURE_PRNG".to_string(),
                file_path.to_string(),
                line_num + 1,
                "System.Random".to_string(),
            );
            asset.severity = Severity::Critical;
            asset.findings.push(
                "System.Random is NOT cryptographically secure. Use RandomNumberGenerator instead."
                    .to_string(),
            );
            findings.push(asset);
        }
    }
}

// ---------------------------------------------------------------------------
// Go scanner
// ---------------------------------------------------------------------------

/// Scan a Go source file for cryptographic usage.
///
/// Detects:
/// - `import "crypto/aes"`, `import "crypto/sha256"`, etc.
/// - `import "golang.org/x/crypto/..."`
/// - `math/rand` usage (insecure PRNG)
/// - `tls.Config` and cipher suite configurations
fn scan_go(source: &str, file_path: &str) -> Vec<CryptoAsset> {
    let mut findings = Vec::new();
    let language = tree_sitter_go::language();

    let mut parser = Parser::new();
    parser
        .set_language(language)
        .expect("Failed to load Go grammar");

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return findings,
    };
    let root = tree.root_node();
    let src = source.as_bytes();

    // --- Detect import declarations ---
    scan_go_imports(&mut findings, language, root, src, file_path);

    // --- Detect TLS config patterns ---
    scan_go_tls_config(&mut findings, source, file_path);

    findings
}

/// Detect Go crypto imports: `"crypto/aes"`, `"crypto/tls"`, etc.
fn scan_go_imports(
    findings: &mut Vec<CryptoAsset>,
    language: tree_sitter::Language,
    root: tree_sitter::Node,
    src: &[u8],
    file_path: &str,
) {
    let query_str = "(import_spec path: (interpreted_string_literal) @path)";
    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return,
    };

    let path_idx = query.capture_index_for_name("path").unwrap();

    let mut cursor = QueryCursor::new();
    for qm in cursor.matches(&query, root, src) {
        let path_text = capture_text(qm.captures, path_idx, src);
        let line = capture_line(qm.captures, path_idx);

        let import_path = strip_quotes(&path_text);

        // Check for crypto packages
        for pkg in GO_CRYPTO_PACKAGES {
            if import_path == *pkg || import_path.starts_with(pkg) {
                let algo = algorithm_from_go_import(&import_path);
                findings.push(CryptoAsset::new(
                    algo,
                    file_path.to_string(),
                    line,
                    import_path.clone(),
                ));
                break;
            }
        }

        // Detect insecure math/rand
        if import_path == "math/rand" {
            let mut asset = CryptoAsset::new(
                "INSECURE_PRNG".to_string(),
                file_path.to_string(),
                line,
                "math/rand".to_string(),
            );
            asset.severity = Severity::Critical;
            asset.findings.push(
                "math/rand is NOT cryptographically secure. Use crypto/rand instead.".to_string(),
            );
            findings.push(asset);
        }
    }
}

/// Detect `tls.Config` patterns and cipher suite references in Go.
fn scan_go_tls_config(findings: &mut Vec<CryptoAsset>, source: &str, file_path: &str) {
    let tls_cipher_suites = [
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
    ];

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        // Detect explicit TLS version settings
        if trimmed.contains("tls.VersionTLS10") || trimmed.contains("VersionTLS10") {
            let mut asset = CryptoAsset::new(
                "TLS".to_string(),
                file_path.to_string(),
                line_num + 1,
                "crypto/tls".to_string(),
            );
            asset.protocol_version = Some("TLSv1.0".to_string());
            asset.severity = Severity::Critical;
            asset
                .findings
                .push("TLS 1.0 is deprecated and insecure.".to_string());
            findings.push(asset);
        } else if trimmed.contains("tls.VersionTLS11") || trimmed.contains("VersionTLS11") {
            let mut asset = CryptoAsset::new(
                "TLS".to_string(),
                file_path.to_string(),
                line_num + 1,
                "crypto/tls".to_string(),
            );
            asset.protocol_version = Some("TLSv1.1".to_string());
            asset.severity = Severity::Warning;
            asset.findings.push("TLS 1.1 is deprecated.".to_string());
            findings.push(asset);
        } else if trimmed.contains("tls.VersionTLS12") || trimmed.contains("VersionTLS12") {
            let mut asset = CryptoAsset::new(
                "TLS".to_string(),
                file_path.to_string(),
                line_num + 1,
                "crypto/tls".to_string(),
            );
            asset.protocol_version = Some("TLSv1.2".to_string());
            findings.push(asset);
        } else if trimmed.contains("tls.VersionTLS13") || trimmed.contains("VersionTLS13") {
            let mut asset = CryptoAsset::new(
                "TLS".to_string(),
                file_path.to_string(),
                line_num + 1,
                "crypto/tls".to_string(),
            );
            asset.protocol_version = Some("TLSv1.3".to_string());
            findings.push(asset);
        }

        // Detect cipher suite references
        for suite in &tls_cipher_suites {
            if trimmed.contains(suite) {
                let mut asset = CryptoAsset::new(
                    "TLS".to_string(),
                    file_path.to_string(),
                    line_num + 1,
                    "crypto/tls".to_string(),
                );
                asset.cipher_suites.push(suite.to_string());
                findings.push(asset);
            }
        }
    }
}

/// Map a Go import path to an algorithm label.
fn algorithm_from_go_import(import_path: &str) -> String {
    match import_path {
        "crypto/aes" => "AES".to_string(),
        "crypto/des" => "DES".to_string(),
        "crypto/hmac" => "HMAC".to_string(),
        "crypto/md5" => "MD5".to_string(),
        "crypto/sha1" => "SHA1".to_string(),
        "crypto/sha256" => "SHA256".to_string(),
        "crypto/sha512" => "SHA512".to_string(),
        "crypto/rsa" => "RSA".to_string(),
        "crypto/ecdsa" => "ECDSA".to_string(),
        "crypto/ed25519" => "ED25519".to_string(),
        "crypto/elliptic" => "ECC".to_string(),
        "crypto/rand" => "CSPRNG".to_string(),
        "crypto/tls" => "TLS".to_string(),
        "crypto/x509" => "X509".to_string(),
        "crypto/cipher" => "CIPHER (see usage)".to_string(),
        _ if import_path.starts_with("golang.org/x/crypto") => {
            let sub = import_path.trim_start_matches("golang.org/x/crypto/");
            match sub {
                "chacha20poly1305" => "CHACHA20-POLY1305".to_string(),
                "curve25519" => "X25519".to_string(),
                "nacl" | "nacl/box" | "nacl/secretbox" => "NACL".to_string(),
                "argon2" => "ARGON2".to_string(),
                "bcrypt" => "BCRYPT".to_string(),
                "scrypt" => "SCRYPT".to_string(),
                "ssh" => "SSH".to_string(),
                "blake2b" => "BLAKE2B".to_string(),
                "blake2s" => "BLAKE2S".to_string(),
                _ => format!("X_CRYPTO/{}", sub.to_uppercase()),
            }
        }
        _ => "CRYPTO (see usage)".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Certificate file scanner
// ---------------------------------------------------------------------------

/// Scan a certificate file (.pem, .crt, .cer, .der) for X.509 metadata.
///
/// Extracts: subject, issuer, expiry date, serial number, and public key algorithm.
fn scan_certificate_file(path: &Path, file_path: &str) -> Vec<CryptoAsset> {
    let mut findings = Vec::new();

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return findings,
    };

    // Try PEM first, then DER
    let certs = parse_pem_certs(&data).or_else(|| parse_der_cert(&data));

    if let Some(cert_list) = certs {
        for (subject, issuer, not_after, serial, pub_key_algo) in cert_list {
            let mut asset = CryptoAsset::new(
                pub_key_algo.clone(),
                file_path.to_string(),
                1,
                "x509-certificate".to_string(),
            );
            asset.cert_subject = Some(subject);
            asset.cert_issuer = Some(issuer);
            asset.cert_expiry = Some(not_after);
            asset.cert_serial = Some(serial);
            asset.detection_source = DetectionSource::SourceCode;
            findings.push(asset);
        }
    }

    findings
}

/// Try to parse PEM-encoded certificates from raw bytes.
fn parse_pem_certs(data: &[u8]) -> Option<Vec<(String, String, String, String, String)>> {
    // Look for PEM markers
    let text = std::str::from_utf8(data).ok()?;
    if !text.contains("-----BEGIN CERTIFICATE-----") {
        return None;
    }

    let mut results = Vec::new();

    // Parse each PEM block
    for pem in pem_blocks(text) {
        let der_bytes = match base64_decode_pem(&pem) {
            Some(b) => b,
            None => continue,
        };

        if let Some(info) = extract_cert_info_from_der(&der_bytes) {
            results.push(info);
        }
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// Try to parse a single DER-encoded certificate.
fn parse_der_cert(data: &[u8]) -> Option<Vec<(String, String, String, String, String)>> {
    extract_cert_info_from_der(data).map(|info| vec![info])
}

/// Extract certificate info from DER-encoded bytes.
/// Returns (subject, issuer, not_after, serial, pub_key_algo).
fn extract_cert_info_from_der(der_data: &[u8]) -> Option<(String, String, String, String, String)> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der_data).ok()?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let not_after = cert.validity().not_after.to_rfc2822().unwrap_or_else(|_| "Unknown".to_string());
    let serial = cert.serial.to_str_radix(16);
    let pub_key_algo = format!("{:?}", cert.public_key().algorithm.algorithm);

    Some((subject, issuer, not_after, serial, pub_key_algo))
}

/// Extract PEM blocks (base64 content between markers) from text.
fn pem_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut in_block = false;
    let mut current = String::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN CERTIFICATE-----" {
            in_block = true;
            current.clear();
        } else if trimmed == "-----END CERTIFICATE-----" {
            if in_block && !current.is_empty() {
                blocks.push(current.clone());
            }
            in_block = false;
        } else if in_block {
            current.push_str(trimmed);
        }
    }

    blocks
}

/// Decode base64 PEM content to raw DER bytes.
/// Uses a simple decoder without pulling in a base64 crate.
fn base64_decode_pem(b64: &str) -> Option<Vec<u8>> {
    // Simple base64 decoder
    let table: Vec<u8> = (0..256u16)
        .map(|i| {
            let c = i as u8 as char;
            match c {
                'A'..='Z' => (c as u8) - b'A',
                'a'..='z' => (c as u8) - b'a' + 26,
                '0'..='9' => (c as u8) - b'0' + 52,
                '+' => 62,
                '/' => 63,
                _ => 255,
            }
        })
        .collect();

    let bytes: Vec<u8> = b64.bytes().filter(|b| table[*b as usize] != 255).collect();
    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);

    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let a = table[chunk[0] as usize] as u32;
        let b = table[chunk[1] as usize] as u32;
        let c = if chunk.len() > 2 {
            table[chunk[2] as usize] as u32
        } else {
            0
        };
        let d = if chunk.len() > 3 {
            table[chunk[3] as usize] as u32
        } else {
            0
        };

        let triple = (a << 18) | (b << 12) | (c << 6) | d;
        result.push((triple >> 16) as u8);
        if chunk.len() > 2 {
            result.push((triple >> 8) as u8);
        }
        if chunk.len() > 3 {
            result.push(triple as u8);
        }
    }

    Some(result)
}

// ---------------------------------------------------------------------------
// Tree-sitter query helpers
// ---------------------------------------------------------------------------

/// Extract the text content of a named capture from a query match.
fn capture_text(captures: &[tree_sitter::QueryCapture], idx: u32, src: &[u8]) -> String {
    captures
        .iter()
        .find(|c| c.index == idx)
        .and_then(|c| c.node.utf8_text(src).ok())
        .unwrap_or("")
        .to_string()
}

/// Extract the 1-indexed line number of a named capture from a query match.
fn capture_line(captures: &[tree_sitter::QueryCapture], idx: u32) -> usize {
    captures
        .iter()
        .find(|c| c.index == idx)
        .map(|c| c.node.start_position().row + 1)
        .unwrap_or(0)
}

/// Get the raw AST node for a named capture (used for parent navigation).
fn capture_node<'tree>(
    captures: &[tree_sitter::QueryCapture<'tree>],
    idx: u32,
) -> Option<tree_sitter::Node<'tree>> {
    captures.iter().find(|c| c.index == idx).map(|c| c.node)
}

// ---------------------------------------------------------------------------
// Python text-parsing helpers
// ---------------------------------------------------------------------------

/// Extract module names from `import hashlib, hmac` → `["hashlib", "hmac"]`.
fn extract_import_modules(text: &str) -> Vec<String> {
    let text = text.trim();
    match text.strip_prefix("import") {
        Some(rest) => rest
            .split(',')
            .map(|s| {
                let s = s.trim();
                // Handle aliased imports: `import hashlib as hl`
                s.split_whitespace().next().unwrap_or(s).to_string()
            })
            .filter(|s| !s.is_empty())
            .collect(),
        None => vec![],
    }
}

/// Parse `from X import Y, Z` → `Some(("X", ["Y", "Z"]))`.
/// Handles multiline and parenthesized imports.
fn parse_from_import(text: &str) -> Option<(String, Vec<String>)> {
    let text = text.trim();
    let rest = text.strip_prefix("from")?;

    let parts: Vec<&str> = rest.splitn(2, "import").collect();
    if parts.len() != 2 {
        return None;
    }

    let module = parts[0].trim().to_string();
    let names: Vec<String> = parts[1]
        .trim()
        .trim_matches(|c: char| c == '(' || c == ')')
        .split(',')
        .map(|s| {
            let s = s.trim();
            // Handle aliased: `SHA256 as sha`
            s.split_whitespace().next().unwrap_or(s).to_string()
        })
        .filter(|s| !s.is_empty())
        .collect();

    Some((module, names))
}

/// Map a bare Python crypto module import to a human-readable algorithm label.
fn algorithm_from_python_module(module: &str) -> String {
    match module {
        "hashlib" => "HASHING (see usage)".to_string(),
        "hmac" => "HMAC".to_string(),
        "ssl" => "TLS".to_string(),
        "cryptography" => "CRYPTOGRAPHY (see usage)".to_string(),
        "Crypto" | "Cryptodome" => "PYCRYPTODOME (see usage)".to_string(),
        _ => "UNKNOWN".to_string(),
    }
}

/// Determine the specific algorithm from a `from X import Y` statement.
fn algorithm_from_python_import(base_module: &str, name: &str, full_module: &str) -> String {
    match base_module {
        "hashlib" => {
            if HASHLIB_ALGORITHMS.contains(&name.to_lowercase().as_str()) {
                name.to_uppercase()
            } else {
                format!("hashlib.{}", name)
            }
        }
        "cryptography" => {
            // e.g., from cryptography.hazmat.primitives.hashes import SHA256
            // e.g., from cryptography.hazmat.primitives.ciphers.algorithms import AES
            name.to_uppercase()
        }
        "Crypto" | "Cryptodome" => {
            // e.g., from Crypto.Cipher import AES
            if full_module.contains("Cipher")
                || full_module.contains("Hash")
                || full_module.contains("PublicKey")
                || full_module.contains("Signature")
            {
                name.to_uppercase()
            } else {
                format!("{}.{}", base_module, name)
            }
        }
        "hmac" => "HMAC".to_string(),
        "ssl" => "TLS".to_string(),
        _ => name.to_string(),
    }
}

// ---------------------------------------------------------------------------
// General helpers
// ---------------------------------------------------------------------------

/// Strip surrounding quotes from a string literal (`'sha256'` → `sha256`).
fn strip_quotes(s: &str) -> String {
    s.trim_matches(|c| c == '\'' || c == '"' || c == '`')
        .to_string()
}

/// Navigate into a `call` node's `arguments` and return the text of the
/// first string literal argument (with quotes stripped).
fn extract_first_string_arg(call_node: tree_sitter::Node, src: &[u8]) -> Option<String> {
    let args = call_node.child_by_field_name("arguments")?;
    for i in 0..args.named_child_count() {
        if let Some(child) = args.named_child(i) {
            if child.kind() == "string" {
                let text = child.utf8_text(src).ok()?;
                return Some(strip_quotes(text));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_import_modules() {
        assert_eq!(extract_import_modules("import hashlib"), vec!["hashlib"]);
        assert_eq!(
            extract_import_modules("import hashlib, hmac, os"),
            vec!["hashlib", "hmac", "os"]
        );
        assert_eq!(
            extract_import_modules("import hashlib as hl"),
            vec!["hashlib"]
        );
    }

    #[test]
    fn test_parse_from_import() {
        let (module, names) = parse_from_import("from hashlib import sha256, md5").unwrap();
        assert_eq!(module, "hashlib");
        assert_eq!(names, vec!["sha256", "md5"]);

        let (module, names) =
            parse_from_import("from cryptography.hazmat.primitives.hashes import SHA256").unwrap();
        assert_eq!(module, "cryptography.hazmat.primitives.hashes");
        assert_eq!(names, vec!["SHA256"]);
    }

    #[test]
    fn test_strip_quotes() {
        assert_eq!(strip_quotes("'sha256'"), "sha256");
        assert_eq!(strip_quotes("\"sha256\""), "sha256");
        assert_eq!(strip_quotes("`sha256`"), "sha256");
    }

    #[test]
    fn test_algorithm_from_python_module() {
        assert_eq!(
            algorithm_from_python_module("hashlib"),
            "HASHING (see usage)"
        );
        assert_eq!(algorithm_from_python_module("hmac"), "HMAC");
        assert_eq!(algorithm_from_python_module("ssl"), "TLS");
    }

    #[test]
    fn test_algorithm_from_python_import() {
        assert_eq!(
            algorithm_from_python_import("hashlib", "sha256", "hashlib"),
            "SHA256"
        );
        assert_eq!(
            algorithm_from_python_import("cryptography", "AES", "cryptography.hazmat"),
            "AES"
        );
        assert_eq!(
            algorithm_from_python_import("Crypto", "AES", "Crypto.Cipher"),
            "AES"
        );
    }

    #[test]
    fn test_parse_algorithm_string() {
        let (algo, key_size, mode) = parse_algorithm_string("aes-256-cbc");
        assert_eq!(algo, "AES");
        assert_eq!(key_size, Some(256));
        assert_eq!(mode, Some("CBC".to_string()));

        let (algo, key_size, mode) = parse_algorithm_string("aes-128-gcm");
        assert_eq!(algo, "AES");
        assert_eq!(key_size, Some(128));
        assert_eq!(mode, Some("GCM".to_string()));

        let (algo, key_size, mode) = parse_algorithm_string("sha256");
        assert_eq!(algo, "SHA256");
        assert_eq!(key_size, None);
        assert_eq!(mode, None);

        let (algo, key_size, mode) = parse_algorithm_string("des-ede3-cbc");
        assert_eq!(algo, "DES-EDE3");
        assert_eq!(key_size, None);
        assert_eq!(mode, Some("CBC".to_string()));
    }

    #[test]
    fn test_scan_python_insecure_random() {
        let source = "import random\nx = random.randint(1, 100)\n";
        let findings = scan_python(source, "test.py");
        assert!(findings.iter().any(|f| f.algorithm == "INSECURE_PRNG"));
    }

    #[test]
    fn test_scan_python_hardcoded_iv() {
        let source = "iv = b'\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07'\n";
        let findings = scan_python(source, "test.py");
        assert!(findings.iter().any(|f| f.algorithm == "HARDCODED_IV"));
    }

    #[test]
    fn test_scan_python_hardcoded_salt() {
        let source = "salt = b'my_fixed_salt_value'\n";
        let findings = scan_python(source, "test.py");
        assert!(findings.iter().any(|f| f.algorithm == "HARDCODED_SALT"));
    }

    #[test]
    fn test_scan_js_algorithm_parsing() {
        let source = r#"
const crypto = require('crypto');
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
"#;
        let findings = scan_javascript(source, "test.js");
        let cipher_finding = findings.iter().find(|f| f.algorithm == "AES");
        assert!(cipher_finding.is_some());
        let cf = cipher_finding.unwrap();
        assert_eq!(cf.key_size, Some(256));
        assert_eq!(cf.mode, Some("CBC".to_string()));
    }

    #[test]
    fn test_scan_js_math_random() {
        let source = "const x = Math.random();\n";
        let findings = scan_javascript(source, "test.js");
        assert!(findings.iter().any(|f| f.algorithm == "INSECURE_PRNG"));
    }

    #[test]
    fn test_scan_js_hardcoded_key() {
        let source = "const key = Buffer.from('my-secret-key-1234567890abcdef');\n";
        let findings = scan_javascript(source, "test.js");
        assert!(findings.iter().any(|f| f.algorithm == "HARDCODED_KEY"));
    }
}
