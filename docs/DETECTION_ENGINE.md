
keylens extracts detailed cryptographic parameters, not just algorithm names:

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

