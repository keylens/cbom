# 🏗 Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                           main.rs                                  │
│                     (CLI routing via clap)                          │
│                                                                    │
│  keylens scan --path ./src --format cyclonedx                         │
│  keylens diff --base a --head b --strict                              │
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
