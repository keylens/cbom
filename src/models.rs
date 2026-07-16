//! Data models for the CBOM (Cryptographic Bill of Materials) schema.
//!
//! All types derive `Serialize` and `Deserialize` so they can be
//! round-tripped through JSON for the `scan` and `diff` commands.

use serde::{Deserialize, Serialize};

/// A single cryptographic asset detected in source code.
///
/// This is the core unit of the CBOM output. Each instance represents
/// one usage of cryptography at a specific location in the codebase.
///
/// # JSON Example
/// ```json
/// {
///   "algorithm": "SHA256",
///   "file_path": "src/auth/hash.py",
///   "line_number": 12,
///   "library_source": "hashlib"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CryptoAsset {
    /// The cryptographic algorithm or primitive detected
    /// (e.g., `"SHA256"`, `"AES-256-CBC"`, `"HMAC"`, `"CSPRNG"`).
    pub algorithm: String,

    /// Path to the source file where the usage was found.
    pub file_path: String,

    /// 1-indexed line number of the detection.
    pub line_number: usize,

    /// The library or module that provides the cryptography
    /// (e.g., `"hashlib"`, `"node:crypto"`, `"cryptography"`).
    pub library_source: String,
}
