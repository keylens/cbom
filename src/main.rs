use std::process;

use clap::{Parser, Subcommand};

mod dependencies;
mod diff;
mod models;
mod policy;
mod scanner;

#[derive(Parser)]
#[command(name = "cbom")]
#[command(author, version, about = "A lightning-fast CLI tool that scans codebases to generate a Cryptographic Bill of Materials (CBOM)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a codebase to generate a CBOM
    Scan {
        /// Path to scan
        #[arg(short, long, default_value = ".")]
        path: String,

        /// Output format: "json" (default) or "cyclonedx"
        #[arg(short, long, default_value = "json")]
        format: String,
    },
    /// Compare two CBOM outputs to find newly introduced cryptography
    Diff {
        /// Base CBOM file or git ref
        #[arg(long)]
        base: String,

        /// Head CBOM file or git ref
        #[arg(long)]
        head: String,

        /// Strict mode: exit 1 if any deprecated or critical algorithm is detected
        #[arg(long, default_value_t = false)]
        strict: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan { path, format } => {
            handle_scan(path, format);
        }
        Commands::Diff { base, head, strict } => {
            handle_diff(base, head, *strict);
        }
    }
}

/// Execute the `scan` subcommand: walk the directory, detect crypto in
/// source code and dependencies, evaluate policy, and output findings.
fn handle_scan(path: &str, format: &str) {
    eprintln!("🔍 Scanning: {}\n", path);

    // Phase 1: Scan first-party source code
    let mut findings = scanner::scan_directory(path);

    // Phase 2: Scan dependency lockfiles
    let dep_findings = dependencies::scan_dependencies(path);
    if !dep_findings.is_empty() {
        eprintln!(
            "📦 Found {} cryptographic dependenc{} in lockfiles.",
            dep_findings.len(),
            if dep_findings.len() == 1 { "y" } else { "ies" }
        );
    }
    findings.extend(dep_findings);

    // Phase 3: Evaluate all findings through the policy engine
    policy::evaluate_all(&mut findings);

    if findings.is_empty() {
        eprintln!("✅ No cryptographic usage detected.");
    } else {
        // Report summary by severity
        let critical = findings.iter().filter(|f| f.severity == models::Severity::Critical).count();
        let warnings = findings.iter().filter(|f| f.severity == models::Severity::Warning).count();
        let info = findings.iter().filter(|f| f.severity == models::Severity::Info).count();
        let safe = findings.iter().filter(|f| f.severity == models::Severity::Safe).count();

        eprintln!(
            "⚠️  Found {} cryptographic asset(s): {} critical, {} warning, {} info, {} safe.\n",
            findings.len(), critical, warnings, info, safe
        );

        if critical > 0 {
            eprintln!("🚨 CRITICAL issues detected! Review findings below.\n");
        }
    }

    // Output based on format
    match format {
        "cyclonedx" => {
            let bom = models::to_cyclonedx_bom(&findings);
            let json = serde_json::to_string_pretty(&bom)
                .expect("Failed to serialize CycloneDX BOM to JSON");
            println!("{}", json);
        }
        _ => {
            // Default: pretty-printed JSON array
            let json = serde_json::to_string_pretty(&findings)
                .expect("Failed to serialize CBOM to JSON");
            println!("{}", json);
        }
    }
}

/// Execute the `diff` subcommand: load two CBOM JSON files, compute the
/// delta, and exit with an appropriate code for CI integration.
///
/// - Exit **0**: no new cryptography introduced (pipeline passes).
/// - Exit **1**: new cryptographic assets found (pipeline should fail/flag).
/// - Exit **2**: error loading files.
///
/// With `--strict`: exit **1** if any added asset uses a deprecated or
/// critically insecure algorithm, even if it's just one finding.
fn handle_diff(base_path: &str, head_path: &str, strict: bool) {
    eprintln!("🔍 Comparing CBOMs:\\n   base: {}\\n   head: {}\\n", base_path, head_path);

    if strict {
        eprintln!("🔒 Strict mode enabled: deprecated/critical algorithms will cause failure.\n");
    }

    let base = match diff::load_cbom(base_path) {
        Ok(assets) => assets,
        Err(e) => {
            eprintln!("❌ Error loading base CBOM: {}", e);
            process::exit(2);
        }
    };

    let head = match diff::load_cbom(head_path) {
        Ok(assets) => assets,
        Err(e) => {
            eprintln!("❌ Error loading head CBOM: {}", e);
            process::exit(2);
        }
    };

    let result = diff::diff_cbom(&base, &head, strict);

    // Report removed assets (informational)
    if !result.removed.is_empty() {
        eprintln!(
            "ℹ️  {} cryptographic asset(s) removed (no longer detected).",
            result.removed.len()
        );
    }

    if result.added.is_empty() {
        eprintln!("✅ No new cryptographic assets introduced.");
        // Output empty delta to stdout
        println!("[]");
        process::exit(0);
    } else {
        eprintln!(
            "⚠️  {} NEW cryptographic asset(s) detected!\n",
            result.added.len()
        );

        // Report policy violations
        if strict && result.has_violations {
            eprintln!("🚨 STRICT MODE VIOLATION: Deprecated or critically insecure cryptography detected in new assets!\n");
            for asset in &result.added {
                if asset.severity == models::Severity::Critical {
                    eprintln!(
                        "   ❌ {} in {} (line {}): {:?}",
                        asset.algorithm, asset.file_path, asset.line_number, asset.findings
                    );
                }
            }
            eprintln!();
        }

        // Pretty-print the delta to stdout
        let json = serde_json::to_string_pretty(&result.added)
            .expect("Failed to serialize diff delta to JSON");
        println!("{}", json);

        // Exit with code 1 to signal CI that new crypto was found
        // (or strict violations detected)
        process::exit(1);
    }
}
