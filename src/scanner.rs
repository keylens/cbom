//! Scanner module: walks a directory tree and detects cryptographic usage
//! in Python and JavaScript source files using Tree-sitter AST parsing.
//!
//! Uses the `ignore` crate (from the ripgrep team) for fast, .gitignore-aware
//! file walking, and Tree-sitter queries for reliable AST-based detection
//! without requiring compilation.

use std::path::Path;
use ignore::WalkBuilder;
use tree_sitter::{Parser, Query, QueryCursor};

use crate::models::CryptoAsset;



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
                    findings.push(CryptoAsset {
                        algorithm: algorithm_from_python_module(base),
                        file_path: file_path.to_string(),
                        line_number: line,
                        library_source: base.to_string(),
                    });
                }
            }
        }
    }
}

/// Detect `from cryptography.hazmat... import SHA256` style imports.
fn scan_python_from_imports(
    findings: &mut Vec<CryptoFinding>,
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
                        findings.push(CryptoAsset {
                            algorithm: algorithm_from_python_import(base, name, &module),
                            file_path: file_path.to_string(),
                            line_number: line,
                            library_source: base.to_string(),
                        });
                    }
                }
            }
        }
    }
}

/// Detect method calls like `hashlib.sha256()`, `hashlib.new('sha256')`, `hmac.new(...)`.
fn scan_python_calls(
    findings: &mut Vec<CryptoFinding>,
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
                // Direct algorithm call: hashlib.sha256()
                findings.push(CryptoAsset {
                    algorithm: method_text.to_uppercase(),
                    file_path: file_path.to_string(),
                    line_number: line,
                    library_source: "hashlib".to_string(),
                });
            } else if method_text == "new" {
                // Generic constructor: hashlib.new('sha256')
                // Navigate: @obj (identifier) → parent (attribute) → parent (call)
                if let Some(call_node) = capture_node(qm.captures, obj_idx)
                    .and_then(|n| n.parent())
                    .and_then(|n| n.parent())
                {
                    if let Some(algo) = extract_first_string_arg(call_node, src) {
                        findings.push(CryptoAsset {
                            algorithm: algo.to_uppercase(),
                            file_path: file_path.to_string(),
                            line_number: line,
                            library_source: "hashlib".to_string(),
                        });
                    }
                }
            }
        } else if obj_text == "hmac" && method_text == "new" {
            findings.push(CryptoAsset {
                algorithm: "HMAC".to_string(),
                file_path: file_path.to_string(),
                line_number: line,
                library_source: "hmac".to_string(),
            });
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

    findings
}

/// Detect `require('crypto')` / `require('node:crypto')` calls.
fn scan_js_require(
    findings: &mut Vec<CryptoFinding>,
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
            findings.push(CryptoAsset {
                algorithm: "CRYPTO_MODULE_IMPORT".to_string(),
                file_path: file_path.to_string(),
                line_number: line,
                library_source: "node:crypto".to_string(),
            });
        }
    }
}

/// Detect `crypto.createHash('sha256')`, `crypto.createCipheriv('aes-256-cbc', ...)`, etc.
fn scan_js_crypto_calls(
    findings: &mut Vec<CryptoFinding>,
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
            let algo = strip_quotes(&arg_text).to_uppercase();
            match method_text.as_str() {
                "createHash" | "createHmac" | "createCipheriv" | "createDecipheriv"
                | "createSign" | "createVerify" => {
                    findings.push(CryptoAsset {
                        algorithm: algo,
                        file_path: file_path.to_string(),
                        line_number: line,
                        library_source: "node:crypto".to_string(),
                    });
                }
                _ => {}
            }
        }
    }
}

/// Detect `crypto.randomBytes(...)`, `crypto.generateKeyPairSync(...)`, etc.
fn scan_js_crypto_utility(
    findings: &mut Vec<CryptoFinding>,
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
            findings.push(CryptoAsset {
                algorithm: algo.to_string(),
                file_path: file_path.to_string(),
                line_number: line,
                library_source: "node:crypto".to_string(),
            });
        }
    }
}

/// Detect `import crypto from 'crypto'` / `import { createHash } from 'crypto'`.
fn scan_js_imports(
    findings: &mut Vec<CryptoFinding>,
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
            findings.push(CryptoAsset {
                algorithm: "CRYPTO_MODULE_IMPORT".to_string(),
                file_path: file_path.to_string(),
                line_number: line,
                library_source: "node:crypto".to_string(),
            });
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
}
