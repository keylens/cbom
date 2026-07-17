//! Data models for the CBOM (Cryptographic Bill of Materials) schema.
//!
//! All types derive `Serialize` and `Deserialize` so they can be
//! round-tripped through JSON for the `scan` and `diff` commands.
//!
//! Includes CycloneDX v1.5 output structures for standardized CBOM output.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Core detection model
// ---------------------------------------------------------------------------

/// Quantum-safety classification for a cryptographic algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuantumSafe {
    /// Algorithm is considered quantum-safe (e.g., Kyber, Dilithium).
    Safe,
    /// Algorithm is vulnerable to quantum attacks (e.g., RSA, ECC).
    Vulnerable,
    /// Quantum safety is unknown or not applicable.
    Unknown,
}

/// Severity level assigned by the policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Critical: algorithm is broken or fully deprecated (e.g., MD5, DES, RC4).
    Critical,
    /// Warning: algorithm has known weaknesses or missing authentication (e.g., SHA-1, CBC without HMAC).
    Warning,
    /// Info: algorithm is acceptable but worth noting (e.g., quantum-vulnerable RSA-2048).
    Info,
    /// Safe: algorithm meets current best practices.
    Safe,
    /// Not yet evaluated.
    Unknown,
}

/// The source of a cryptographic finding — first-party code or a dependency.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetectionSource {
    /// Detected via AST analysis of first-party source code.
    SourceCode,
    /// Inferred from a third-party dependency in a lockfile.
    Dependency,
}

/// A single cryptographic asset detected in the codebase.
///
/// This is the core unit of the CBOM output. Each instance represents
/// one usage of cryptography at a specific location in the codebase,
/// enriched with deep context and posture assessment.
///
/// # JSON Example
/// ```json
/// {
///   "algorithm": "AES",
///   "file_path": "src/auth/encrypt.js",
///   "line_number": 42,
///   "library_source": "node:crypto",
///   "key_size": 256,
///   "mode": "CBC",
///   "padding": null,
///   "curve": null,
///   "quantum_safe": "vulnerable",
///   "severity": "warning",
///   "detection_source": "source-code",
///   "findings": ["Mode CBC lacks built-in authentication; prefer GCM."]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CryptoAsset {
    /// The cryptographic algorithm or primitive detected
    /// (e.g., `"SHA256"`, `"AES"`, `"HMAC"`, `"CSPRNG"`).
    pub algorithm: String,

    /// Path to the source file where the usage was found.
    pub file_path: String,

    /// 1-indexed line number of the detection.
    pub line_number: usize,

    /// The library or module that provides the cryptography
    /// (e.g., `"hashlib"`, `"node:crypto"`, `"cryptography"`).
    pub library_source: String,

    /// Key size in bits, if detected (e.g., `128`, `256`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<u32>,

    /// Mode of operation, if detected (e.g., `"GCM"`, `"CBC"`, `"ECB"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// Padding scheme, if detected (e.g., `"PKCS7"`, `"OAEP"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding: Option<String>,

    /// Elliptic curve, if detected (e.g., `"P-256"`, `"Curve25519"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,

    /// Quantum safety posture of the algorithm.
    pub quantum_safe: QuantumSafe,

    /// Severity assigned by the policy engine.
    pub severity: Severity,

    /// How this asset was detected.
    pub detection_source: DetectionSource,

    /// Human-readable policy findings/warnings for this asset.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<String>,
}

impl CryptoAsset {
    /// Create a new CryptoAsset with minimal required fields.
    /// Policy fields are set to defaults and should be populated by the policy engine.
    pub fn new(
        algorithm: String,
        file_path: String,
        line_number: usize,
        library_source: String,
    ) -> Self {
        Self {
            algorithm,
            file_path,
            line_number,
            library_source,
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
}

// ---------------------------------------------------------------------------
// CycloneDX v1.5 output structures
// ---------------------------------------------------------------------------

/// Top-level CycloneDX BOM document.
///
/// Conforms to the CycloneDX v1.5 specification with crypto-asset extensions.
/// See: <https://cyclonedx.org/docs/1.5/json/>
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxBom {
    /// Fixed: `"CycloneDX"`.
    pub bom_format: String,
    /// Specification version: `"1.5"`.
    pub spec_version: String,
    /// Unique serial number for this BOM (URN UUID).
    pub serial_number: String,
    /// BOM version (incremented for updates).
    pub version: u32,
    /// Components discovered in the scan.
    pub components: Vec<CycloneDxComponent>,
}

/// A CycloneDX component representing a cryptographic asset.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxComponent {
    /// Component type — `"crypto-asset"` for cryptographic findings.
    #[serde(rename = "type")]
    pub component_type: String,
    /// Human-readable name of the component (e.g., `"AES-256-GCM"`).
    pub name: String,
    /// Cryptographic properties specific to this asset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_properties: Option<CycloneDxCryptoProperties>,
    /// Evidence of where this component was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<CycloneDxEvidence>,
}

/// CycloneDX crypto-properties node (v1.5 extension).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxCryptoProperties {
    /// Asset type: `"algorithm"`, `"certificate"`, `"protocol"`, `"related-crypto-material"`.
    pub asset_type: String,
    /// Algorithm properties, if asset_type is `"algorithm"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm_properties: Option<CycloneDxAlgorithmProperties>,
    /// OID (Object Identifier) for the algorithm, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
}

/// Algorithm-specific properties in CycloneDX format.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxAlgorithmProperties {
    /// Primitive (e.g., `"block-cipher"`, `"hash"`, `"mac"`, `"signature"`, `"key-agree"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primitive: Option<String>,
    /// Parameter set length / key size in bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_set_identifier: Option<String>,
    /// Mode of operation (e.g., `"gcm"`, `"cbc"`, `"ecb"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Padding scheme (e.g., `"pkcs7"`, `"oaep"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding: Option<String>,
    /// Curve name for elliptic curve algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    /// Certification level, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certification_level: Option<Vec<String>>,
    /// Quantum computing vulnerability level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_functions: Option<Vec<String>>,
}

/// Evidence of where a component was found.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxEvidence {
    /// Occurrences — where in the code or dependencies this was found.
    pub occurrences: Vec<CycloneDxOccurrence>,
}

/// A single occurrence / location of a cryptographic asset.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxOccurrence {
    /// File path where the asset was detected.
    pub location: String,
    /// Line number within the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// Additional context about the detection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

// ---------------------------------------------------------------------------
// Conversion: CryptoAsset → CycloneDX Component
// ---------------------------------------------------------------------------

impl CryptoAsset {
    /// Convert this `CryptoAsset` into a CycloneDX component.
    pub fn to_cyclonedx_component(&self) -> CycloneDxComponent {
        let name = self.build_display_name();
        let primitive = classify_primitive(&self.algorithm);
        let oid = lookup_oid(&self.algorithm);

        CycloneDxComponent {
            component_type: "crypto-asset".to_string(),
            name,
            crypto_properties: Some(CycloneDxCryptoProperties {
                asset_type: "algorithm".to_string(),
                algorithm_properties: Some(CycloneDxAlgorithmProperties {
                    primitive,
                    parameter_set_identifier: self.key_size.map(|k| k.to_string()),
                    mode: self.mode.as_ref().map(|m| m.to_lowercase()),
                    padding: self.padding.as_ref().map(|p| p.to_lowercase()),
                    curve: self.curve.clone(),
                    certification_level: None,
                    crypto_functions: None,
                }),
                oid,
            }),
            evidence: Some(CycloneDxEvidence {
                occurrences: vec![CycloneDxOccurrence {
                    location: self.file_path.clone(),
                    line: Some(self.line_number),
                    additional_context: Some(format!(
                        "library={}, detection={:?}",
                        self.library_source, self.detection_source
                    )),
                }],
            }),
        }
    }

    /// Build a human-readable display name like `"AES-256-GCM"`.
    fn build_display_name(&self) -> String {
        let mut parts = vec![self.algorithm.clone()];
        if let Some(ref ks) = self.key_size {
            parts.push(ks.to_string());
        }
        if let Some(ref m) = self.mode {
            parts.push(m.clone());
        }
        parts.join("-")
    }
}

/// Convert a full list of `CryptoAsset`s into a CycloneDX BOM document.
pub fn to_cyclonedx_bom(assets: &[CryptoAsset]) -> CycloneDxBom {
    let components: Vec<CycloneDxComponent> = assets
        .iter()
        .map(|a| a.to_cyclonedx_component())
        .collect();

    CycloneDxBom {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.5".to_string(),
        serial_number: format!("urn:uuid:{}", simple_uuid()),
        version: 1,
        components,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Classify an algorithm into a CycloneDX primitive type.
fn classify_primitive(algorithm: &str) -> Option<String> {
    let algo = algorithm.to_uppercase();
    if algo.contains("AES") || algo.contains("DES") || algo.contains("BLOWFISH")
        || algo.contains("CHACHA") || algo.contains("RC4") || algo.contains("CAMELLIA")
    {
        Some("block-cipher".to_string())
    } else if algo.contains("SHA") || algo.contains("MD5") || algo.contains("MD4")
        || algo.contains("BLAKE") || algo.contains("RIPEMD") || algo == "HASHING (SEE USAGE)"
    {
        Some("hash".to_string())
    } else if algo.contains("HMAC") {
        Some("mac".to_string())
    } else if algo.contains("RSA") || algo.contains("DSA") || algo.contains("ECDSA")
        || algo.contains("EDDSA") || algo.contains("ED25519")
    {
        Some("signature".to_string())
    } else if algo.contains("ECDH") || algo.contains("DH") || algo.contains("X25519")
        || algo.contains("KYBER") || algo.contains("KEY_GENERATION")
    {
        Some("key-agree".to_string())
    } else if algo.contains("CSPRNG") || algo.contains("RANDOM") {
        Some("random-number-generator".to_string())
    } else if algo == "TLS" || algo == "SSL" {
        Some("protocol".to_string())
    } else {
        None
    }
}

/// Look up the OID (Object Identifier) for well-known algorithms.
fn lookup_oid(algorithm: &str) -> Option<String> {
    match algorithm.to_uppercase().as_str() {
        "AES" => Some("2.16.840.1.101.3.4.1".to_string()),
        "SHA256" | "SHA-256" => Some("2.16.840.1.101.3.4.2.1".to_string()),
        "SHA384" | "SHA-384" => Some("2.16.840.1.101.3.4.2.2".to_string()),
        "SHA512" | "SHA-512" => Some("2.16.840.1.101.3.4.2.3".to_string()),
        "SHA1" | "SHA-1" => Some("1.3.14.3.2.26".to_string()),
        "MD5" => Some("1.2.840.113549.2.5".to_string()),
        "RSA" => Some("1.2.840.113549.1.1.1".to_string()),
        "ECDSA" => Some("1.2.840.10045.4.3".to_string()),
        "DES" => Some("1.3.14.3.2.7".to_string()),
        "3DES" | "TRIPLE-DES" | "TRIPLEDES" => Some("1.2.840.113549.3.7".to_string()),
        "HMAC" => Some("1.2.840.113549.2.9".to_string()),
        _ => None,
    }
}

/// Generate a simple pseudo-UUID for the BOM serial number.
/// Uses a hash of the current timestamp for uniqueness without pulling in `uuid` crate.
fn simple_uuid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seed = now.as_nanos();
    // Format as a UUID-like string from the timestamp hash
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (seed & 0xFFFF_FFFF) as u32,
        ((seed >> 32) & 0xFFFF) as u16,
        ((seed >> 48) & 0x0FFF) as u16 | 0x4000, // version 4
        ((seed >> 60) & 0x3FFF) as u16 | 0x8000,  // variant
        (seed >> 74) & 0xFFFF_FFFF_FFFF
    )
}
