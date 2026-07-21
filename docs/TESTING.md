# 🧪 Testing Guide

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
keylens scan --path ./test-fixtures

# CycloneDX output
keylens scan --path ./test-fixtures --format cyclonedx
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
keylens scan --path ./test-fixtures > base.json
```

#### Step 2: Add new crypto to the test fixtures

Append to `test-fixtures/crypto_sample.py`:

```python
# Newly added crypto
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
```

#### Step 3: Generate the new CBOM

```bash
keylens scan --path ./test-fixtures > head.json
```

#### Step 4: Run the diff

```bash
keylens diff --base base.json --head head.json
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
keylens scan --path ./test-fixtures > head-strict.json

# Run strict diff — should exit 1 with violation message
keylens diff --base base.json --head head-strict.json --strict
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
docker build -t keylens .

# Run a scan (default JSON)
docker run --rm -v $(pwd)/test-fixtures:/repo keylens scan --path /repo

# Run a scan (CycloneDX format)
docker run --rm -v $(pwd)/test-fixtures:/repo keylens scan --path /repo --format cyclonedx

# Run a diff
docker run --rm -v $(pwd):/workspace keylens diff --base /workspace/base.json --head /workspace/head.json

# Run a strict diff
docker run --rm -v $(pwd):/workspace keylens diff --base /workspace/base.json --head /workspace/head.json --strict
```

---
