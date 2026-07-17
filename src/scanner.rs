//! Scanner module: walks a directory tree and detects cryptographic usage
//! in Python and JavaScript source files using Tree-sitter AST parsing.
//!
//! Uses the `ignore` crate (from the ripgrep team) for fast, .gitignore-aware
//! file walking, and Tree-sitter queries for reliable AST-based detection
//! without requiring compilation.
//!
//! Enhanced to extract deep cryptographic context: key sizes, modes of
//! operation, padding schemes, elliptic curves, hardcoded IVs/salts,
//! and insecure PRNG usage.

use std::path::Path;
use ignore::WalkBuilder;
use tree_sitter::{Parser, Query, QueryCursor};

use crate::models::{CryptoAsset, DetectionSource, QuantumSafe, Severity};



// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Known Python modules that provide cryptographic functionality.
const PYTHON_CRYPTO_MODULES: &[&str] = &[
    "hashlib", "hmac", "ssl", "cryptography", "Crypto", "Cryptodome",
];

/// Known algorithm names that appear as method calls on `hashlib`.
const HASHLIB_ALGORITHMS: &[&str] = &[
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "blake2b", "blake2s", "sha3_224", "sha3_256", "sha3_384", "sha3_512",
];

/// Directories to always skip during scanning (in addition to .gitignore rules).
const SKIP_DIRS: &[&str] = &[
    "node_modules", "venv", ".venv", "__pycache__", "tests", ".git",
];

/// Known elliptic curves for detection.
const KNOWN_CURVES: &[&str] = &[
    "P-256", "P-384", "P-521", "prime256v1", "secp256r1", "secp384r1",
    "secp521r1", "secp256k1", "Curve25519", "Ed25519", "X25519",
    "curve25519", "ed25519", "x25519",
];

/// Known padding schemes for detection.
const KNOWN_PADDINGS: &[&str] = &[
    "PKCS7", "PKCS1v15", "OAEP", "PSS", "ANSIX923", "ISO10126",
    "pkcs7", "pkcs1", "oaep", "pss",
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan a directory for cryptographic usage in Python and JavaScript files.
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

        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue, // skip binary files or permission errors
        };

        let file_path_str = path.to_string_lossy().to_string();

        match ext.as_str() {
            "py" => findings.extend(scan_python(&source, &file_path_str)),
            "js" | "mjs" | "cjs" => findings.extend(scan_javascript(&source, &file_path_str)),
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
fn scan_python_hardcoded_secrets(
    findings: &mut Vec<CryptoAsset>,
    source: &str,
    file_path: &str,
) {
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
fn scan_js_hardcoded_secrets(
    findings: &mut Vec<CryptoAsset>,
    source: &str,
    file_path: &str,
) {
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
        assert_eq!(
            extract_import_modules("import hashlib"),
            vec!["hashlib"]
        );
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
        let (module, names) =
            parse_from_import("from hashlib import sha256, md5").unwrap();
        assert_eq!(module, "hashlib");
        assert_eq!(names, vec!["sha256", "md5"]);

        let (module, names) =
            parse_from_import("from cryptography.hazmat.primitives.hashes import SHA256")
                .unwrap();
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
        assert_eq!(algorithm_from_python_module("hashlib"), "HASHING (see usage)");
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
