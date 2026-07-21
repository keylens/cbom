
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

