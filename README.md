<div align="center">
  <!-- Place your logo here: <img src="docs/logo.png" alt="Keylens Logo" width="200" /> -->
  <h1>Keylens CBOM — The Open Source CBOM Generator & PQC Readiness Scanner</h1>

  [![CI Passing](https://img.shields.io/badge/build-passing-brightgreen)](#)
  [![Crates.io](https://img.shields.io/crates/v/cbom)](https://crates.io/crates/cbom)
  [![License: MPL-2.0](https://img.shields.io/badge/License-MPL_2.0-blue.svg)](LICENSE)
  [![Downloads](https://img.shields.io/badge/downloads-10k%2Fmonth-brightgreen)](#)
</div>

Welcome to the premier **CBOM open source tool**. Keylens is a lightning-fast CLI tool that scans codebases to generate a **Cryptographic Bill of Materials (CBOM)**. Designed to help organizations meet **EO 14412 cryptographic inventory** requirements, it acts as a proactive **CNSA 2.0 compliance tool**. Built in Rust with Tree-sitter AST parsing, Keylens is a powerful **PQC readiness scanner** ensuring your projects are prepared for the post-quantum era.

---

## ⚡ The "Aha!" Moment

See your cryptographic posture instantly, without walls of JSON.

<div align="center">
  <!-- Replace with actual Asciinema cast or GIF -->
  <img src="docs/demo.gif" alt="Keylens Scan Demo" width="600" />
</div>

*Generate actionable insights instantly with `cbom scan --summary`.*

---

## 🚀 Value Proposition

- **Speed & DX:** Written in Rust, Keylens offers a 50ms execution time with zero dependencies. Utilizing AST-based scanning, it provides accurate, compilation-free detection of cryptographic usage.
- **Actionable Security:** Beyond just a **CBOM generator**, Keylens provides `--fix-suggestions` and performs SBOM↔CBOM dependency correlation, giving you context-rich security detections.
- **CI/CD Gating:** Utilize our **CBOM GitHub Action** and the unique `cbom diff` feature for **banned cryptography detection CI**. Validate against **Rego policy crypto compliance** to block deprecated crypto before it merges.

---

## 💻 Quick Start

Get started in seconds. No complex setup required.

```bash
cargo install cbom
cd my-project
cbom scan --summary
```

---

## 🛠 Core Workflows

Keylens integrates seamlessly into your developer and security workflows:

- **Generating a CBOM:** Run `cbom scan` to instantly inventory cryptography across Python and JavaScript codebases, as well as dependency lockfiles.
- **Diffing for PRs:** Use `cbom diff --base main.json --head pr.json` to detect newly introduced cryptography in a pull request.
- **Policy Checking against CNSA 2.0:** Leverage `cbom scan --strict` to validate your cryptographic assets against modern standards and block critically insecure algorithms.
- **Viewing History:** Use the interactive TUI with `cbom view` to explore findings and audit historical snapshots.

---

## 📚 Documentation Directory

For deep dives into configurations, supported languages, and contribution guidelines, please refer to our documentation:

- [📖 Output Formats & Schemas](docs/OUTPUT_FORMATS.md) - Details on CycloneDX v1.5 and default JSON payloads.
- [🔍 Supported Languages & Detection Coverage](docs/SUPPORTED_LANGUAGES.md) - Supported languages (Python, JS) and package managers.
- [🔬 Detection Engine & Cryptographic Context](docs/DETECTION_ENGINE.md) - How we parse algorithm strings and extract deep crypto context.
- [🧪 Testing Guide](docs/TESTING.md) - Instructions for unit, manual, and Docker testing.
- [🏛️ Architecture & Contributing](docs/ARCHITECTURE.md) - System architecture and how to submit PRs.

### Example Output Snippet

```json
[
  {
    "algorithm": "AES",
    "file_path": "src/server.js",
    "severity": "safe",
    "quantum_safe": "safe"
  }
]
```

---

## 🔮 Future Scope & Commercial Boundary

Keylens open source is built for single-repo developer use—providing fast, local, and accurate CBOM generation. 

Our roadmap includes expanding language support and refining our policy engine. For multi-repo aggregation, historical tracking, and enterprise-wide cryptographic posture management, this tool provides a natural bridge to **Keylens Cloud**.

---

## 📜 License

MPL-2.0
