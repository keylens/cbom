
### Default JSON Format

The enriched CBOM is a JSON array of `CryptoAsset` objects with full context:

```json
[
  {
    "algorithm": "AES",
    "file_path": "src/server.js",
    "line_number": 45,
    "library_source": "node:crypto",
    "key_size": 256,
    "mode": "CBC",
    "quantum_safe": "safe",
    "severity": "safe",
    "detection_source": "source-code",
    "findings": ["CBC mode lacks built-in authentication; prefer GCM or use HMAC alongside."]
  },
  {
    "algorithm": "MD5",
    "file_path": "src/legacy.py",
    "line_number": 3,
    "library_source": "hashlib",
    "quantum_safe": "safe",
    "severity": "critical",
    "detection_source": "source-code",
    "findings": ["MD5 is cryptographically broken; collisions are trivial to produce."]
  },
  {
    "algorithm": "DEPENDENCY:PYJWT",
    "file_path": "requirements.txt",
    "line_number": 4,
    "library_source": "pyjwt",
    "quantum_safe": "unknown",
    "severity": "unknown",
    "detection_source": "dependency",
    "findings": ["JSON Web Token library (HMAC, RSA, ECDSA signing)"]
  }
]
```

| Field | Type | Description |
|-------|------|-------------|
| `algorithm` | string | Detected algorithm or crypto primitive |
| `file_path` | string | Relative path to the source file |
| `line_number` | integer | 1-indexed line number |
| `library_source` | string | The library providing the crypto |
| `key_size` | integer? | Key size in bits (e.g., 128, 256) — omitted if unknown |
| `mode` | string? | Mode of operation (e.g., GCM, CBC, ECB) — omitted if unknown |
| `padding` | string? | Padding scheme (e.g., PKCS7, OAEP) — omitted if unknown |
| `curve` | string? | Elliptic curve (e.g., P-256, Curve25519) — omitted if unknown |
| `quantum_safe` | string | `"safe"`, `"vulnerable"`, or `"unknown"` |
| `severity` | string | `"critical"`, `"warning"`, `"info"`, `"safe"`, or `"unknown"` |
| `detection_source` | string | `"source-code"` or `"dependency"` |
| `findings` | string[] | Human-readable policy findings/warnings |

### CycloneDX v1.5 Format

Use `--format cyclonedx` to output in the CycloneDX v1.5 standard:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3e671687-4000-8000-0000-000000000000",
  "version": 1,
  "components": [
    {
      "type": "crypto-asset",
      "name": "AES-256-CBC",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "block-cipher",
          "parameterSetIdentifier": "256",
          "mode": "cbc",
          "padding": null,
          "curve": null
        },
        "oid": "2.16.840.1.101.3.4.1"
      },
      "evidence": {
        "occurrences": [
          {
            "location": "src/server.js",
            "line": 45,
            "additionalContext": "library=node:crypto, detection=SourceCode"
          }
        ]
      }
    }
  ]
}
```

This format is compatible with enterprise SBOM/CBOM platforms like **Dependency-Track**, **Grype**, and **Syft**.

---
