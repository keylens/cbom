use std::process;

use clap::{Parser, Subcommand};

mod diff;
mod models;
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

        /// Output format
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
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan { path, format } => {
            handle_scan(path, format);
        }
        Commands::Diff { base, head } => {
            handle_diff(base, head);
        }
    }
}

/// Execute the `scan` subcommand: walk the directory, detect crypto,
/// and output findings as pretty-printed JSON to stdout.
fn handle_scan(path: &str, _format: &str) {
    eprintln!("🔍 Scanning: {}\n", path);
    let findings = scanner::scan_directory(path);

    if findings.is_empty() {
        eprintln!("✅ No cryptographic usage detected.");
    } else {
        eprintln!(
            "⚠️  Found {} cryptographic asset(s). Writing CBOM to stdout.\n",
            findings.len()
        );
    }

    // Serialize to pretty-printed JSON and write to stdout.
    // Output goes to stdout even when empty (valid JSON: []).
    let json = serde_json::to_string_pretty(&findings)
        .expect("Failed to serialize CBOM to JSON");
    println!("{}", json);
}

/// Execute the `diff` subcommand: load two CBOM JSON files, compute the
/// delta, and exit with an appropriate code for CI integration.
///
/// - Exit **0**: no new cryptography introduced (pipeline passes).
/// - Exit **1**: new cryptographic assets found (pipeline should fail/flag).
fn handle_diff(base_path: &str, head_path: &str) {
    eprintln!("🔍 Comparing CBOMs:\n   base: {}\n   head: {}\n", base_path, head_path);

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

    let result = diff::diff_cbom(&base, &head);

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

        // Pretty-print the delta to stdout
        let json = serde_json::to_string_pretty(&result.added)
            .expect("Failed to serialize diff delta to JSON");
        println!("{}", json);

        // Exit with code 1 to signal CI that new crypto was found
        process::exit(1);
    }
}
