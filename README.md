# 🔐 cbom — Cryptographic Bill of Materials

A lightning-fast CLI tool that scans codebases to generate a **Cryptographic Bill of Materials (CBOM)**. Built in Rust with Tree-sitter AST parsing for accurate, compilation-free detection of cryptographic usage across Python and JavaScript projects.

---

## Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Testing Guide](#-testing-guide)
  - [Unit Tests](#1-unit-tests)
  - [Manual Testing with Sample Files](#2-manual-testing-with-sample-files)
  - [Testing the Diff Engine](#3-testing-the-diff-engine)
  - [Docker Testing](#4-docker-testing)
- [CLI Reference](#-cli-reference)
- [Output Format](#-output-format)
- [CI/CD Integration](#-cicd-integration)
- [Architecture](#-architecture)
- [Future Scope](#-future-scope)

---

## ✨ Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **AST-based scanning** | Uses Tree-sitter for reliable detection — no regex, no compilation required |
| **Python support** | Detects `hashlib`, `hmac`, `ssl`, `cryptography`, `pycryptodome` usage |
| **JavaScript support** | Detects `node:crypto` module usage (`createHash`, `createCipheriv`, `randomBytes`, etc.) |
| **Smart file walking** | Powered by the `ignore` crate (from ripgrep) — respects `.gitignore` automatically |
| **JSON CBOM output** | Structured, machine-readable output with algorithm, file path, line number, and library source |
| **Diff engine** | Compare two CBOM snapshots to detect **newly introduced** cryptography |
| **CI-native exit codes** | Exit `0` (no new crypto) / Exit `1` (new crypto found) — plug directly into CI gates |
| **Docker packaging** | Multi-stage Dockerfile for lightweight containerized execution |
| **GitHub Action** | Ready-made `action.yml` for drop-in GitHub Actions integration |

### Detection Coverage

#### Python
| Pattern | Example |
|---------|---------|
| Bare imports | `import hashlib`, `import hmac`, `import ssl` |
| Targeted imports | `from cryptography.hazmat.primitives.hashes import SHA256` |
| pycryptodome imports | `from Crypto.Cipher import AES` |
| Direct method calls | `hashlib.sha256()`, `hashlib.md5()` |
| Generic constructors | `hashlib.new('sha256')` |
| HMAC construction | `hmac.new(key, msg, digestmod)` |

#### JavaScript
| Pattern | Example |
|---------|---------|
| CommonJS require | `require('crypto')`, `require('node:crypto')` |
| ES module import | `import crypto from 'crypto'` |
| Hash creation | `crypto.createHash('sha256')` |
| HMAC creation | `crypto.createHmac('sha256', key)` |
| Cipher creation | `crypto.createCipheriv('aes-256-cbc', key, iv)` |
| Signing | `crypto.createSign('RSA-SHA256')` |
| Random generation | `crypto.randomBytes(32)` |
| Key generation | `crypto.generateKeyPairSync('rsa', options)` |

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
# Scan the current directory
cbom scan

# Scan a specific project
cbom scan --path /path/to/project

# Save CBOM to a file
cbom scan --path ./my-app > cbom.json

# Compare two CBOM snapshots
cbom diff --base main-cbom.json --head pr-cbom.json
```

---

## 🧪 Testing Guide

### 1. Unit Tests

Run the built-in test suite:

```bash
cargo test
```

This runs tests across all modules:

- **`scanner.rs`** — Tests for import parsing, quote stripping, and algorithm detection helpers
- **`diff.rs`** — Tests for set comparison logic (added, removed, both, empty cases)

Expected output:
```
running 10 tests
test diff::tests::test_no_changes ... ok
test diff::tests::test_new_crypto_added ... ok
test diff::tests::test_crypto_removed ... ok
test diff::tests::test_both_added_and_removed ... ok
test diff::tests::test_empty_base ... ok
test diff::tests::test_both_empty ... ok
test scanner::tests::test_extract_import_modules ... ok
test scanner::tests::test_parse_from_import ... ok
test scanner::tests::test_strip_quotes ... ok
test scanner::tests::test_algorithm_from_python_module ... ok
test scanner::tests::test_algorithm_from_python_import ... ok

test result: ok. 10 passed; 0 failed
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
from cryptography.hazmat.primitives.hashes import SHA256, SHA512
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from Crypto.Cipher import DES3
from Crypto.Hash import MD5

# Direct hashlib usage
digest = hashlib.sha256(b"hello").hexdigest()
digest2 = hashlib.new('sha3_256', b"hello").hexdigest()

# HMAC usage
mac = hmac.new(b"secret", b"message", digestmod=hashlib.sha256)

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

// Cipher
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

// Random bytes
const token = crypto.randomBytes(32);

// Key generation
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

// Non-crypto code (should NOT be detected)
const fs = require('fs');
console.log("hello world");
```

#### Step 4: Run the scan

```bash
cbom scan --path ./test-fixtures
```

#### Step 5: Verify expected output

You should see a JSON array with entries like:

```json
[
  {
    "algorithm": "HASHING (see usage)",
    "file_path": "test-fixtures/crypto_sample.py",
    "line_number": 1,
    "library_source": "hashlib"
  },
  {
    "algorithm": "HMAC",
    "file_path": "test-fixtures/crypto_sample.py",
    "line_number": 2,
    "library_source": "hmac"
  },
  {
    "algorithm": "SHA256",
    "file_path": "test-fixtures/crypto_sample.py",
    "line_number": 4,
    "library_source": "cryptography"
  },
  {
    "algorithm": "SHA256",
    "file_path": "test-fixtures/crypto_sample.py",
    "line_number": 10,
    "library_source": "hashlib"
  },
  {
    "algorithm": "SHA256",
    "file_path": "test-fixtures/crypto_sample.js",
    "line_number": 4,
    "library_source": "node:crypto"
  }
]
```

> **Verify**: `os`, `json`, `fs`, and `console.log` should **NOT** appear in the output.

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

- **stdout** should contain a JSON array with the new `ChaCha20` asset
- **stderr** should print `⚠️ 1 NEW cryptographic asset(s) detected!`
- **Exit code** should be `1` (verify with `echo $?` on Linux/Mac or `$LASTEXITCODE` on PowerShell)

#### Step 6: Test the "no changes" case

```bash
cbom diff --base base.json --base base.json
# Should exit with code 0
# stdout: []
# stderr: ✅ No new cryptographic assets introduced.
```

---

### 4. Docker Testing

```bash
# Build the image
docker build -t cbom .

# Run a scan
docker run --rm -v $(pwd)/test-fixtures:/repo cbom scan --path /repo

# Run a diff
docker run --rm -v $(pwd):/workspace cbom diff --base /workspace/base.json --head /workspace/head.json
```

---

## 📖 CLI Reference

### `cbom scan`

Scan a directory and output a CBOM as JSON.

```
USAGE:
    cbom scan [OPTIONS]

OPTIONS:
    -p, --path <PATH>       Path to scan [default: .]
    -f, --format <FORMAT>   Output format [default: json]
```

### `cbom diff`

Compare two CBOM files and detect newly introduced cryptography.

```
USAGE:
    cbom diff --base <BASE> --head <HEAD>

OPTIONS:
    --base <BASE>    Path to the base CBOM JSON file
    --head <HEAD>    Path to the head CBOM JSON file

EXIT CODES:
    0    No new cryptography introduced
    1    New cryptographic assets detected (delta printed to stdout)
    2    Error (file not found, invalid JSON, etc.)
```

---

## 📄 Output Format

The CBOM is a JSON array of `CryptoAsset` objects:

```json
[
  {
    "algorithm": "SHA256",
    "file_path": "src/auth/hash.py",
    "line_number": 12,
    "library_source": "hashlib"
  },
  {
    "algorithm": "AES-256-CBC",
    "file_path": "src/server.js",
    "line_number": 45,
    "library_source": "node:crypto"
  }
]
```

| Field | Type | Description |
|-------|------|-------------|
| `algorithm` | string | Detected algorithm or crypto primitive |
| `file_path` | string | Relative path to the source file |
| `line_number` | integer | 1-indexed line number |
| `library_source` | string | The library providing the crypto |

---

## 🔁 CI/CD Integration

### GitHub Actions (using the built-in Action)

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

      - name: Install cbom
        run: cargo install --path .

      - name: Scan codebase
        run: cbom scan > head-cbom.json

      - name: Diff against baseline
        run: cbom diff --base baseline-cbom.json --head head-cbom.json
```

> **Tip**: Commit a `baseline-cbom.json` to your repo and update it whenever new crypto is intentionally approved.

---

## 🏗 Architecture

```
┌──────────────────────────────────────────────────────────┐
│                        main.rs                           │
│                    (CLI routing via clap)                 │
│                                                          │
│   cbom scan --path ./src    cbom diff --base a --head b  │
│         │                           │                    │
│         ▼                           ▼                    │
│   ┌──────────┐                ┌──────────┐               │
│   │scanner.rs│                │  diff.rs │               │
│   │          │                │          │               │
│   │ ignore   │                │ HashSet  │               │
│   │ (walk)   │                │ (delta)  │               │
│   │          │                │          │               │
│   │tree-sitter│               │serde_json│               │
│   │ (AST)    │                │ (deser.) │               │
│   └────┬─────┘                └────┬─────┘               │
│        │                           │                     │
│        ▼                           ▼                     │
│   ┌──────────────────────────────────┐                   │
│   │         models.rs                │                   │
│   │    CryptoAsset (serde)           │                   │
│   └──────────────────────────────────┘                   │
│                        │                                 │
│                        ▼                                 │
│                   JSON stdout                            │
└──────────────────────────────────────────────────────────┘
```

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
| **CycloneDX CBOM** | Output in the official CycloneDX CBOM standard format | 🔴 High |
| **Configurable ignore** | `.cbomignore` file or `--exclude` flag for custom directory exclusion | 🟡 Medium |
| **Severity levels** | Flag weak algorithms (MD5, SHA1, DES) as `high` severity | 🟡 Medium |

### Medium-term Goals

| Feature | Description |
|---------|-------------|
| **PQC readiness scoring** | Flag algorithms vulnerable to quantum computing (RSA, ECDSA, classic DH) and suggest post-quantum alternatives |
| **Compliance mapping** | Map detected algorithms to compliance frameworks (FIPS 140-3, NIST SP 800-131A, PCI DSS) |
| **Dependency scanning** | Scan `requirements.txt`, `package.json`, `go.mod` for transitive crypto dependencies |
| **Interactive TUI** | Rich terminal UI with `ratatui` for browsing findings interactively |
| **GitHub PR comments** | Post diff results as PR review comments with inline annotations |
| **VS Code extension** | Real-time crypto detection with inline diagnostics as you code |

### Long-term Vision

| Feature | Description |
|---------|-------------|
| **Crypto flow analysis** | Track how keys, ciphers, and hashes flow through the codebase (taint analysis) |
| **Auto-remediation** | Suggest and apply fixes for weak crypto (e.g., replace MD5 → SHA256) |
| **Policy-as-code** | Define custom crypto policies in YAML (e.g., "ban all symmetric < 256-bit") |
| **SBOM integration** | Embed CBOM data into existing CycloneDX/SPDX SBOMs |
| **Multi-repo dashboard** | Aggregate CBOM data across an entire organization |
| **Historical tracking** | Track crypto posture over time with trend graphs |

---

## 📜 License

MIT

---

## 🤝 Contributing

Contributions are welcome! Key areas where help is needed:

1. **New language grammars** — Add Tree-sitter queries for Java, Go, C/C++, Rust
2. **Detection patterns** — Improve algorithm extraction for edge cases
3. **Output formats** — SARIF, CycloneDX, CSV, table output
4. **Tests** — Integration tests with real-world crypto codebases
