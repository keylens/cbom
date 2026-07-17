# 🔐 cbom — Cryptographic Bill of Materials

A lightning-fast CLI tool that scans codebases to generate a **Cryptographic Bill of Materials (CBOM)**. Built in Rust with Tree-sitter AST parsing for accurate, compilation-free detection of cryptographic usage across Python and JavaScript projects.

Outputs in the **CycloneDX v1.5** standard format, provides **policy-based severity assessment**, **quantum-safety classification**, and scans **both source code and dependencies**.

---

## Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Testing Guide](#-testing-guide)
  - [Unit Tests](#1-unit-tests)
  - [Manual Testing with Sample Files](#2-manual-testing-with-sample-files)
  - [Testing the Diff Engine](#3-testing-the-diff-engine)
  - [Testing Strict Mode](#4-testing-strict-mode)
  - [Docker Testing](#5-docker-testing)
- [CLI Reference](#-cli-reference)
- [Output Formats](#-output-formats)
  - [Default JSON](#default-json-format)
  - [CycloneDX v1.5](#cyclonedx-v15-format)
- [Policy Engine](#-policy-engine)
  - [Severity Levels](#severity-levels)
  - [Quantum Safety](#quantum-safety-classification)
  - [Strict Mode](#strict-mode)
- [Dependency Scanning](#-dependency-scanning)
- [Deep Cryptographic Context](#-deep-cryptographic-context)
- [Security Detections](#-security-detections)
- [CI/CD Integration](#-cicd-integration)
- [Architecture](#-architecture)
- [Future Scope](#-future-scope)

---

## ✨ Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **AST-based scanning** | Uses Tree-sitter for reliable detection — no regex, no compilation required |
| **CycloneDX v1.5 output** | Standard CBOM format with `crypto-asset` nodes, OIDs, and algorithm properties |
| **Policy engine** | Automatic severity tagging, deprecation detection, and quantum-safety classification |
| **Deep crypto context** | Extracts key sizes, modes of operation, padding schemes, and elliptic curves |
| **Dependency scanning** | Parses `Cargo.lock`, `package-lock.json`, `requirements.txt`, `yarn.lock`, `Pipfile.lock` |
| **Security detections** | Flags hardcoded IVs/salts/keys and insecure PRNGs (`random`, `Math.random()`) |
| **Diff engine with `--strict`** | Compare CBOM snapshots; fail CI if deprecated or critically insecure crypto is introduced |
| **Python support** | Detects `hashlib`, `hmac`, `ssl`, `cryptography`, `pycryptodome` usage |
| **JavaScript support** | Detects `node:crypto` module usage (`createHash`, `createCipheriv`, `randomBytes`, etc.) |
| **Smart file walking** | Powered by the `ignore` crate (from ripgrep) — respects `.gitignore` automatically |
| **CI-native exit codes** | Exit `0` (safe) / Exit `1` (new crypto / violations) — plug directly into CI gates |
| **Docker packaging** | Multi-stage Dockerfile for lightweight containerized execution |
| **GitHub Action** | Ready-made `action.yml` for drop-in GitHub Actions integration |

### Detection Coverage

#### Python — Source Code
| Pattern | Example |
|---------|---------|
| Bare imports | `import hashlib`, `import hmac`, `import ssl` |
| Targeted imports | `from cryptography.hazmat.primitives.hashes import SHA256` |
| pycryptodome imports | `from Crypto.Cipher import AES` |
| Direct method calls | `hashlib.sha256()`, `hashlib.md5()` |
| Generic constructors | `hashlib.new('sha256')` |
| HMAC construction | `hmac.new(key, msg, digestmod)` |
| Modes from imports | `from cryptography.hazmat.primitives.ciphers.modes import GCM` |
| Curves from imports | `from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1` |
| Padding from imports | `from cryptography.hazmat.primitives.asymmetric.padding import OAEP` |
| **Insecure PRNG** ⚠️ | `import random` — flagged as critical |
| **Hardcoded secrets** ⚠️ | `iv = b'\x00\x01\x02...'`, `salt = b'fixed'` |

#### JavaScript — Source Code
| Pattern | Example |
|---------|---------|
| CommonJS require | `require('crypto')`, `require('node:crypto')` |
| ES module import | `import crypto from 'crypto'` |
| Hash creation | `crypto.createHash('sha256')` |
| HMAC creation | `crypto.createHmac('sha256', key)` |
| Cipher creation | `crypto.createCipheriv('aes-256-cbc', key, iv)` → extracts AES, 256-bit, CBC |
| Signing | `crypto.createSign('RSA-SHA256')` |
| Random generation | `crypto.randomBytes(32)` |
| Key generation | `crypto.generateKeyPairSync('rsa', options)` |
| **Insecure PRNG** ⚠️ | `Math.random()` — flagged as critical |
| **Hardcoded secrets** ⚠️ | `const key = Buffer.from('...')`, `const iv = '...'` |

#### Dependency Lockfiles
| Lockfile | Ecosystem | Example Detections |
|----------|-----------|-------------------|
| `requirements.txt` | Python | `cryptography`, `PyJWT`, `bcrypt`, `paramiko` |
| `Pipfile.lock` | Python | Same as above, parsed from JSON |
| `package-lock.json` | Node.js | `jsonwebtoken`, `bcrypt`, `crypto-js`, `node-forge` |
| `yarn.lock` | Node.js | Same as above, parsed from yarn format |
| `Cargo.lock` | Rust | `ring`, `rustls`, `aes-gcm`, `ed25519-dalek` |

---

## 📦 Installation

### From source (requires Rust 1.70+)

```bash
# Clone the repository
git clone https://github.com/your-org/cbom.git
cd cbom

# Build in release mode
cargo build --release

# The binary is at ./target/release/cbom
# Optionally, install it system-wide:
cargo install --path .
```

### Via Docker

```bash
docker build -t cbom .
docker run --rm -v $(pwd):/repo cbom scan --path /repo
```

---

## 🚀 Quick Start

```bash
# Scan the current directory (default JSON format)
cbom scan

# Scan a specific project
cbom scan --path /path/to/project

# Output in CycloneDX v1.5 format
cbom scan --path ./my-app --format cyclonedx > cbom-cyclonedx.json

# Save default CBOM to a file
cbom scan --path ./my-app > cbom.json

# Compare two CBOM snapshots
cbom diff --base main-cbom.json --head pr-cbom.json

# Strict mode: fail if deprecated crypto (MD5, SHA-1, DES) is introduced
cbom diff --base main-cbom.json --head pr-cbom.json --strict
```

---

## 🧪 Testing Guide

### 1. Unit Tests

Run the built-in test suite:

```bash
cargo test
```

This runs tests across all modules:

- **`scanner.rs`** — Import parsing, algorithm string parsing (`aes-256-cbc` → AES + 256 + CBC), hardcoded secret detection, insecure PRNG detection
- **`diff.rs`** — Set comparison logic, strict mode violation detection
- **`policy.rs`** — Severity classification, quantum-safety assessment, deprecation detection
- **`dependencies.rs`** — Lockfile parsing for `requirements.txt`, `package-lock.json`, `Cargo.lock`
- **`models.rs`** — CycloneDX conversion and OID lookup

Expected output:
```
running 40+ tests
test diff::tests::test_no_changes ... ok
test diff::tests::test_new_crypto_added ... ok
test diff::tests::test_strict_mode_flags_deprecated ... ok
test diff::tests::test_strict_mode_passes_for_safe ... ok
test policy::tests::test_md5_is_critical ... ok
test policy::tests::test_aes_is_safe ... ok
test policy::tests::test_rsa_is_quantum_vulnerable ... ok
test policy::tests::test_ecb_mode_is_critical ... ok
test policy::tests::test_kyber_is_quantum_safe ... ok
test dependencies::tests::test_parse_requirements ... ok
test dependencies::tests::test_parse_cargo_lock ... ok
test dependencies::tests::test_parse_package_lock_json ... ok
test scanner::tests::test_parse_algorithm_string ... ok
test scanner::tests::test_scan_python_insecure_random ... ok
test scanner::tests::test_scan_python_hardcoded_iv ... ok
test scanner::tests::test_scan_js_algorithm_parsing ... ok
test scanner::tests::test_scan_js_math_random ... ok
...

test result: ok. 40+ passed; 0 failed
```

---

### 2. Manual Testing with Sample Files

Create test fixture files to verify detection against real code patterns.

#### Step 1: Create a test directory

```bash
mkdir -p test-fixtures
```

#### Step 2: Create a Python test file

Create `test-fixtures/crypto_sample.py`:

```python
import hashlib
import hmac
import ssl
import random  # ⚠️ Should be flagged as INSECURE_PRNG
from cryptography.hazmat.primitives.hashes import SHA256, SHA512
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC, GCM
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.asymmetric.padding import OAEP
from Crypto.Cipher import DES3
from Crypto.Hash import MD5

# Direct hashlib usage
digest = hashlib.sha256(b"hello").hexdigest()
digest2 = hashlib.new('sha3_256', b"hello").hexdigest()

# HMAC usage
mac = hmac.new(b"secret", b"message", digestmod=hashlib.sha256)

# ⚠️ Hardcoded IV — should be flagged as HARDCODED_IV
iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

# ⚠️ Hardcoded salt — should be flagged as HARDCODED_SALT
salt = b'my_fixed_salt_value'

# Non-crypto import (should NOT be detected)
import os
import json
from collections import defaultdict
```

#### Step 3: Create a JavaScript test file

Create `test-fixtures/crypto_sample.js`:

```javascript
const crypto = require('crypto');

// Hash
const hash = crypto.createHash('sha256');
hash.update('hello');
console.log(hash.digest('hex'));

// HMAC
const hmac = crypto.createHmac('sha512', 'secret-key');

// Cipher — should extract: AES, 256-bit, CBC mode
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

// GCM cipher — should extract: AES, 128-bit, GCM mode
const gcmCipher = crypto.createCipheriv('aes-128-gcm', key, iv);

// Random bytes
const token = crypto.randomBytes(32);

// Key generation
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

// ⚠️ Insecure PRNG — should be flagged
const badRandom = Math.random();

// ⚠️ Hardcoded key — should be flagged
const key = Buffer.from('my-secret-key-1234567890abcdef');

// Non-crypto code (should NOT be detected)
const fs = require('fs');
console.log("hello world");
```

#### Step 4: Add a requirements.txt

Create `test-fixtures/requirements.txt`:

```
flask==2.3.0
cryptography==41.0.0
PyJWT>=2.0
bcrypt
requests>=2.28
```

#### Step 5: Run the scan

```bash
# Default JSON output
cbom scan --path ./test-fixtures

# CycloneDX output
cbom scan --path ./test-fixtures --format cyclonedx
```

#### Step 6: Verify expected output

You should see findings that include:

- **Source code crypto**: SHA256, AES, HMAC, etc. with deep context (key sizes, modes)
- **Insecure PRNGs**: `INSECURE_PRNG` for `import random` and `Math.random()`
- **Hardcoded secrets**: `HARDCODED_IV`, `HARDCODED_SALT`, `HARDCODED_KEY`
- **Dependencies**: `DEPENDENCY:CRYPTOGRAPHY`, `DEPENDENCY:PYJWT`, `DEPENDENCY:BCRYPT`
- **Severity levels**: `critical` for MD5/hardcoded secrets, `safe` for AES/SHA256
- **Quantum safety**: `vulnerable` for RSA/ECC, `safe` for AES/SHA

> **Verify**: `os`, `json`, `fs`, `flask`, and `console.log` should **NOT** appear in the output.

---

### 3. Testing the Diff Engine

#### Step 1: Create a baseline CBOM

```bash
cbom scan --path ./test-fixtures > base.json
```

#### Step 2: Add new crypto to the test fixtures

Append to `test-fixtures/crypto_sample.py`:

```python
# Newly added crypto
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
```

#### Step 3: Generate the new CBOM

```bash
cbom scan --path ./test-fixtures > head.json
```

#### Step 4: Run the diff

```bash
cbom diff --base base.json --head head.json
```

#### Step 5: Verify behavior

- **stdout** should contain a JSON array with the new `ChaCha20` asset, including `severity` and `quantum_safe` fields
- **stderr** should print `⚠️ 1 NEW cryptographic asset(s) detected!`
- **Exit code** should be `1` (verify with `echo $?` on Linux/Mac or `$LASTEXITCODE` on PowerShell)

---

### 4. Testing Strict Mode

Strict mode causes the diff to fail if any **deprecated or critically insecure** algorithm is introduced.

```bash
# Add MD5 to the head CBOM:
echo 'import hashlib; hashlib.md5(b"test")' >> test-fixtures/bad_crypto.py
cbom scan --path ./test-fixtures > head-strict.json

# Run strict diff — should exit 1 with violation message
cbom diff --base base.json --head head-strict.json --strict
```

Expected stderr output:
```
🔒 Strict mode enabled: deprecated/critical algorithms will cause failure.
🚨 STRICT MODE VIOLATION: Deprecated or critically insecure cryptography detected!
   ❌ MD5 in test-fixtures/bad_crypto.py (line 1): ["MD5 is cryptographically broken..."]
```

---

### 5. Docker Testing

```bash
# Build the image
docker build -t cbom .

# Run a scan (default JSON)
docker run --rm -v $(pwd)/test-fixtures:/repo cbom scan --path /repo

# Run a scan (CycloneDX format)
docker run --rm -v $(pwd)/test-fixtures:/repo cbom scan --path /repo --format cyclonedx

# Run a diff
docker run --rm -v $(pwd):/workspace cbom diff --base /workspace/base.json --head /workspace/head.json

# Run a strict diff
docker run --rm -v $(pwd):/workspace cbom diff --base /workspace/base.json --head /workspace/head.json --strict
```

---

## 📖 CLI Reference

### `cbom scan`

Scan a directory and output a CBOM. Scans both source code (via AST) and dependency lockfiles.

```
USAGE:
    cbom scan [OPTIONS]

OPTIONS:
    -p, --path <PATH>       Path to scan [default: .]
    -f, --format <FORMAT>   Output format: "json" or "cyclonedx" [default: json]
```

**Output formats:**
- `json` — Enriched JSON array with severity, quantum safety, and deep context
- `cyclonedx` — CycloneDX v1.5 BOM with `crypto-asset` components

### `cbom diff`

Compare two CBOM files and detect newly introduced cryptography.

```
USAGE:
    cbom diff --base <BASE> --head <HEAD> [OPTIONS]

OPTIONS:
    --base <BASE>    Path to the base CBOM JSON file
    --head <HEAD>    Path to the head CBOM JSON file
    --strict         Fail if any deprecated or critical algorithm is introduced

EXIT CODES:
    0    No new cryptography introduced
    1    New cryptographic assets detected (delta printed to stdout)
    2    Error (file not found, invalid JSON, etc.)
```

---

## 📄 Output Formats

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

## 🛡 Policy Engine

### Severity Levels

Every detected cryptographic asset is automatically evaluated and assigned a severity:

| Severity | Meaning | Examples |
|----------|---------|----------|
| 🔴 **Critical** | Broken, deprecated, or dangerously misconfigured | MD5, SHA-1, DES, RC4, ECB mode, hardcoded IVs/keys, insecure PRNGs |
| 🟡 **Warning** | Known weaknesses; migration recommended | 3DES (Sweet32), CBC without authentication |
| 🔵 **Info** | Acceptable but notable (e.g., quantum-vulnerable) | RSA-2048, ECDSA, Ed25519 |
| 🟢 **Safe** | Meets current best practices | AES-256-GCM, SHA-256, ChaCha20-Poly1305 |

### Quantum Safety Classification

Each algorithm is classified for post-quantum readiness:

| Classification | Algorithms | Rationale |
|---------------|-----------|-----------|
| ✅ **Safe** | AES, ChaCha20, SHA-2/3, BLAKE2/3, Kyber, Dilithium, SPHINCS+ | Symmetric/hash functions survive Grover's; PQC algorithms are quantum-resistant |
| ⚠️ **Vulnerable** | RSA, ECDSA, ECDH, DSA, Ed25519, X25519, DH, ElGamal | Broken by Shor's algorithm on a quantum computer |
| ❓ **Unknown** | Custom/unrecognized algorithms | Cannot be automatically classified |

### Strict Mode

Use `--strict` with `cbom diff` to enforce cryptographic policy in CI:

```bash
cbom diff --base main.json --head pr.json --strict
```

In strict mode, the diff will **exit 1** if any newly introduced asset:
- Uses a **deprecated** algorithm (MD5, SHA-1, DES, RC4)
- Has **critical** severity (hardcoded secrets, insecure PRNGs, ECB mode)

This enables a "crypto gate" in your CI pipeline that blocks insecure cryptography from being merged.

---

## 📦 Dependency Scanning

cbom scans dependency lockfiles alongside source code to detect **transitive cryptography** — crypto usage inherited through third-party packages.

### Supported Lockfiles

| File | Ecosystem | What's Checked |
|------|-----------|---------------|
| `requirements.txt` | Python (pip) | Package names against known crypto library database |
| `Pipfile.lock` | Python (pipenv) | `default` and `develop` sections |
| `package-lock.json` | Node.js (npm) | `packages` (v2/v3) and `dependencies` (v1) |
| `yarn.lock` | Node.js (yarn) | Package declarations |
| `Cargo.lock` | Rust (cargo) | `[[package]]` entries |

### Known Crypto Libraries

The tool maintains a curated database of **80+ crypto-heavy libraries** across Python, Node.js, and Rust. Examples:

- **Python**: `cryptography`, `PyJWT`, `bcrypt`, `paramiko`, `passlib`, `argon2-cffi`
- **Node.js**: `jsonwebtoken`, `bcrypt`, `crypto-js`, `node-forge`, `openpgp`, `elliptic`
- **Rust**: `ring`, `rustls`, `aes-gcm`, `ed25519-dalek`, `sha2`, `argon2`

Dependency findings are tagged with `detection_source: "dependency"` and include a description of the library's crypto capabilities.

---

## 🔬 Deep Cryptographic Context

cbom extracts detailed cryptographic parameters, not just algorithm names:

### Algorithm String Parsing

Compound algorithm strings like `aes-256-cbc` are parsed into components:

| Input | Algorithm | Key Size | Mode |
|-------|-----------|----------|------|
| `aes-256-cbc` | AES | 256 | CBC |
| `aes-128-gcm` | AES | 128 | GCM |
| `des-ede3-cbc` | DES-EDE3 | — | CBC |
| `sha256` | SHA256 | — | — |

### Context from Python Imports

Import paths are analyzed to extract additional context:

| Import | Extracted Context |
|--------|-------------------|
| `from cryptography...modes import GCM` | `mode: "GCM"` |
| `from cryptography...modes import ECB` | `mode: "ECB"` → severity: critical |
| `from cryptography...ec import SECP256R1` | `curve: "P-256"` |
| `from cryptography...padding import OAEP` | `padding: "OAEP"` |

---

## 🚨 Security Detections

Beyond algorithm detection, cbom flags common cryptographic anti-patterns:

### Hardcoded Cryptographic Material

| Pattern | Language | Severity |
|---------|----------|----------|
| `iv = b'\x00\x01...'` | Python | 🔴 Critical |
| `salt = b'fixed_salt'` | Python | 🔴 Critical |
| `key = b'my_secret_key'` | Python | 🔴 Critical |
| `const iv = Buffer.from('...')` | JavaScript | 🔴 Critical |
| `const key = '...'` | JavaScript | 🔴 Critical |

### Insecure Pseudo-Random Number Generators

| Pattern | Language | Severity | Recommendation |
|---------|----------|----------|----------------|
| `import random` | Python | 🔴 Critical | Use `secrets` or `os.urandom()` |
| `from random import randint` | Python | 🔴 Critical | Use `secrets.randbelow()` |
| `Math.random()` | JavaScript | 🔴 Critical | Use `crypto.randomBytes()` |

---

## 🔁 CI/CD Integration

### GitHub Actions (with Strict Mode)

```yaml
name: Crypto Gate
on:
  pull_request:
    branches: [main]

jobs:
  cbom-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Install cbom
        run: cargo install --path .

      - name: Scan codebase
        run: cbom scan > head-cbom.json

      - name: Diff against baseline (strict mode)
        run: cbom diff --base baseline-cbom.json --head head-cbom.json --strict
```

> **Tip**: Commit a `baseline-cbom.json` to your repo and update it whenever new crypto is intentionally approved.

### GitHub Actions (CycloneDX for Dependency-Track)

```yaml
- name: Generate CycloneDX CBOM
  run: cbom scan --format cyclonedx > cbom-cyclonedx.json

- name: Upload to Dependency-Track
  run: |
    curl -X POST "$DTRACK_URL/api/v1/bom" \
      -H "X-Api-Key: $DTRACK_API_KEY" \
      -F "bom=@cbom-cyclonedx.json" \
      -F "projectName=my-app" \
      -F "projectVersion=${{ github.sha }}"
```

### GitHub Actions (Docker-based)

```yaml
- name: Build cbom image
  run: docker build -t cbom .

- name: Scan with cbom
  run: docker run --rm -v ${{ github.workspace }}:/repo cbom scan --path /repo --format cyclonedx > cbom.json
```

---

## 🏗 Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                           main.rs                                  │
│                     (CLI routing via clap)                          │
│                                                                    │
│  cbom scan --path ./src --format cyclonedx                         │
│  cbom diff --base a --head b --strict                              │
│       │                           │                                │
│       ▼                           ▼                                │
│  ┌──────────┐  ┌───────────────┐  ┌──────────┐                    │
│  │scanner.rs│  │dependencies.rs│  │  diff.rs  │                    │
│  │          │  │               │  │           │                    │
│  │ ignore   │  │ Cargo.lock    │  │ HashSet   │                    │
│  │ (walk)   │  │ package-lock  │  │ (delta)   │                    │
│  │          │  │ requirements  │  │           │                    │
│  │tree-sitter│ │ yarn.lock     │  │ policy    │                    │
│  │ (AST)    │  │ Pipfile.lock  │  │ (strict)  │                    │
│  └────┬─────┘  └──────┬────────┘  └─────┬────┘                    │
│       │               │                 │                          │
│       ▼               ▼                 ▼                          │
│  ┌──────────────────────────────────────────┐                      │
│  │              policy.rs                   │                      │
│  │  severity · quantum safety · findings    │                      │
│  └────────────────────┬─────────────────────┘                      │
│                       │                                            │
│                       ▼                                            │
│  ┌──────────────────────────────────────────┐                      │
│  │              models.rs                   │                      │
│  │  CryptoAsset · CycloneDX structs · OIDs  │                      │
│  └────────────────────┬─────────────────────┘                      │
│                       │                                            │
│              ┌────────┴────────┐                                   │
│              ▼                 ▼                                   │
│     JSON stdout      CycloneDX stdout                              │
└────────────────────────────────────────────────────────────────────┘
```

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| `main.rs` | CLI entry point, argument parsing, output routing |
| `scanner.rs` | Tree-sitter AST scanning for Python & JS; hardcoded secret detection; insecure PRNG detection |
| `dependencies.rs` | Lockfile parsing and cross-referencing against known crypto library database |
| `policy.rs` | Severity classification, quantum-safety assessment, deprecation detection |
| `diff.rs` | CBOM comparison engine with `--strict` mode |
| `models.rs` | Core `CryptoAsset` type + CycloneDX v1.5 output structures + OID mapping |

---

## 🔮 Future Scope

### Near-term Enhancements

| Feature | Description | Priority |
|---------|-------------|----------|
| **TypeScript support** | Add `tree-sitter-typescript` for `.ts`/`.tsx` files | 🔴 High |
| **Java support** | Detect `javax.crypto`, `java.security`, BouncyCastle | 🔴 High |
| **Go support** | Detect `crypto/*` stdlib and `golang.org/x/crypto` | 🔴 High |
| **C/C++ support** | Detect OpenSSL, libsodium, wolfSSL API calls | 🟡 Medium |
| **Rust support** | Detect `ring`, `rustcrypto`, `openssl` crate usage | 🟡 Medium |
| **SARIF output** | Output in SARIF format for GitHub Code Scanning integration | 🔴 High |
| **Configurable ignore** | `.cbomignore` file or `--exclude` flag for custom directory exclusion | 🟡 Medium |

### Medium-term Goals

| Feature | Description |
|---------|-------------|
| **Compliance mapping** | Map detected algorithms to compliance frameworks (FIPS 140-3, NIST SP 800-131A, PCI DSS) |
| **Policy-as-code** | Define custom crypto policies in YAML (e.g., "ban all symmetric < 256-bit") |
| **Interactive TUI** | Rich terminal UI with `ratatui` for browsing findings interactively |
| **GitHub PR comments** | Post diff results as PR review comments with inline annotations |
| **VS Code extension** | Real-time crypto detection with inline diagnostics as you code |

### Long-term Vision

| Feature | Description |
|---------|-------------|
| **Crypto flow analysis** | Track how keys, ciphers, and hashes flow through the codebase (taint analysis) |
| **Auto-remediation** | Suggest and apply fixes for weak crypto (e.g., replace MD5 → SHA256) |
| **SBOM integration** | Embed CBOM data into existing CycloneDX/SPDX SBOMs |
| **Multi-repo dashboard** | Aggregate CBOM data across an entire organization |
| **Historical tracking** | Track crypto posture over time with trend graphs |

---

## 📜 License

MIT

---

## 🤝 Contributing

Contributions are welcome! Key areas where help is needed:

1. **New language grammars** — Add Tree-sitter queries for Java, Go, C/C++, Rust, TypeScript
2. **Detection patterns** — Improve algorithm extraction for edge cases
3. **Crypto library database** — Expand the known crypto libraries list in `dependencies.rs`
4. **Output formats** — SARIF, CSV, table output
5. **Policy rules** — Add compliance framework mappings
6. **Tests** — Integration tests with real-world crypto codebases
