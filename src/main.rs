use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process;

use clap::{Parser, Subcommand};

mod dependencies;
mod diff;
mod history;
mod models;
mod policy;
mod scanner;
mod tui;

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

        /// Print a human-readable summary instead of raw JSON
        #[arg(long, default_value_t = false)]
        summary: bool,

        /// Include remediation advice (fix suggestions) in output
        #[arg(long, default_value_t = false)]
        fix_suggestions: bool,
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
    /// Initialize a new CBOM configuration (zero-friction setup)
    Init,
    /// Interactively browse cryptographic assets in a Terminal UI
    View {
        /// Path to a CBOM JSON file (if omitted, runs a live scan of ".")
        #[arg(short, long)]
        file: Option<String>,
    },
    /// Show a timeline of cryptographic changes across recent git commits
    History {
        /// Number of recent commits to analyze
        #[arg(short = 'n', long, default_value = "5")]
        commits: usize,

        /// Path to the git repository
        #[arg(short, long, default_value = ".")]
        path: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan {
            path,
            format,
            summary,
            fix_suggestions,
        } => {
            handle_scan(path, format, *summary, *fix_suggestions);
        }
        Commands::Diff { base, head, strict } => {
            handle_diff(base, head, *strict);
        }
        Commands::Init => {
            handle_init();
        }
        Commands::View { file } => {
            handle_view(file.as_deref());
        }
        Commands::History { commits, path } => {
            handle_history(path, *commits);
        }
    }
}

/// Execute the `init` subcommand: scaffold setup files.
fn handle_init() {
    eprintln!("✨ Initializing CBOM workspace...");

    // 1. Create .cbomignore
    if !Path::new(".cbomignore").exists() {
        let ignore_content = "node_modules/\ntarget/\nbuild/\n.git/\n";
        fs::write(".cbomignore", ignore_content).expect("Failed to write .cbomignore");
        eprintln!("✅ Created .cbomignore");
    } else {
        eprintln!("ℹ️  .cbomignore already exists, skipping.");
    }

    // 2. Create cbom.yml policy pack (default)
    if !Path::new("cbom.yml").exists() {
        let policy_content = "version: 1.0\npolicies:\n  strict_mode: true\n  banned_algorithms:\n    - MD5\n    - SHA1\n";
        fs::write("cbom.yml", policy_content).expect("Failed to write cbom.yml");
        eprintln!("✅ Created cbom.yml policy pack");
    } else {
        eprintln!("ℹ️  cbom.yml already exists, skipping.");
    }

    // 3. Prompt for GitHub Action
    let workflows_dir = Path::new(".github/workflows");
    let action_file = workflows_dir.join("cbom.yml");

    if !action_file.exists() {
        print!("🚀 Scaffold GitHub Action for CI/CD integration? [Y/n]: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim().to_lowercase();

        if input.is_empty() || input == "y" || input == "yes" {
            fs::create_dir_all(workflows_dir)
                .expect("Failed to create .github/workflows directory");
            let action_content = "name: CBOM Security Scan\non:\n  pull_request:\n    branches: [ main ]\njobs:\n  cbom-diff:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Checkout base branch\n        uses: actions/checkout@v4\n        with:\n          ref: ${{ github.base_ref }}\n      - name: Scan base branch\n        uses: cbom/cbom-action@v1\n        with:\n          mode: 'scan'\n      - name: Rename base output\n        run: mv cbom.json base-cbom.json || true\n\n      - name: Checkout head branch\n        uses: actions/checkout@v4\n      - name: Scan head branch\n        uses: cbom/cbom-action@v1\n        with:\n          mode: 'scan'\n      - name: Rename head output\n        run: mv cbom.json head-cbom.json || true\n\n      - name: Compare CBOMs\n        uses: cbom/cbom-action@v1\n        with:\n          mode: 'diff'\n          base: 'base-cbom.json'\n          head: 'head-cbom.json'\n          strict: 'true'\n";
            fs::write(&action_file, action_content)
                .expect("Failed to write GitHub action workflow");
            eprintln!("✅ Created .github/workflows/cbom.yml");
        } else {
            eprintln!("ℹ️  Skipped GitHub Action scaffolding.");
        }
    } else {
        eprintln!("ℹ️  GitHub Action workflow already exists, skipping.");
    }
}

/// Execute the `scan` subcommand: walk the directory, detect crypto in
/// source code and dependencies, evaluate policy, and output findings.
fn handle_scan(path: &str, format: &str, summary: bool, _fix_suggestions: bool) {
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
        return;
    }

    // Report summary by severity
    let critical = findings
        .iter()
        .filter(|f| f.severity == models::Severity::Critical)
        .count();
    let warnings = findings
        .iter()
        .filter(|f| f.severity == models::Severity::Warning)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == models::Severity::Info)
        .count();
    let safe = findings
        .iter()
        .filter(|f| f.severity == models::Severity::Safe)
        .count();

    eprintln!(
        "⚠️  Found {} cryptographic asset(s): {} critical, {} warning, {} info, {} safe.\n",
        findings.len(),
        critical,
        warnings,
        info,
        safe
    );

    if critical > 0 {
        eprintln!("🚨 CRITICAL issues detected! Review findings below.\n");
    }

    if summary {
        // Human-readable summary mode
        print_summary(&findings);
        return;
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
            let json =
                serde_json::to_string_pretty(&findings).expect("Failed to serialize CBOM to JSON");
            println!("{}", json);
        }
    }
}

/// Print a human-readable summary table to stdout.
fn print_summary(findings: &[models::CryptoAsset]) {
    use models::{DetectionSource, Severity};

    println!("┌─────────────────────────────────────────────────────────────────────────────────────────────┐");
    println!("│  🔐 KeyLens CBOM Summary                                                                  │");
    println!("├──────────────────┬──────────┬──────────┬────────┬─────────────────────┬─────────────────────┤");
    println!("│ Algorithm        │ Severity │ Quantum  │ Source │ Library             │ Location            │");
    println!("├──────────────────┼──────────┼──────────┼────────┼─────────────────────┼─────────────────────┤");

    for asset in findings {
        let severity_icon = match asset.severity {
            Severity::Critical => "🚨 CRIT",
            Severity::Warning => "⚠  WARN",
            Severity::Info => "ℹ  INFO",
            Severity::Safe => "✅ SAFE",
            Severity::Unknown => "?  N/A ",
        };

        let quantum = match asset.quantum_safe {
            models::QuantumSafe::Safe => "✅ Safe",
            models::QuantumSafe::Vulnerable => "⚠ Vuln",
            models::QuantumSafe::Unknown => "— N/A ",
        };

        let source = match asset.detection_source {
            DetectionSource::SourceCode => "Code",
            DetectionSource::Dependency => "Dep ",
        };

        let location = if asset.line_number > 0 {
            format!("{}:{}", short_path(&asset.file_path, 18), asset.line_number)
        } else {
            short_path(&asset.file_path, 18)
        };

        println!(
            "│ {:<16} │ {:<8} │ {:<8} │ {:<6} │ {:<19} │ {:<19} │",
            truncate(&asset.algorithm, 16),
            severity_icon,
            quantum,
            source,
            truncate(&asset.library_source, 19),
            truncate(&location, 19),
        );
    }

    println!("└──────────────────┴──────────┴──────────┴────────┴─────────────────────┴─────────────────────┘");

    // Print findings and remediations for critical/warning items
    let actionable: Vec<&models::CryptoAsset> = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical || f.severity == Severity::Warning)
        .collect();

    if !actionable.is_empty() {
        println!();
        println!("🔧 Actionable Findings:");
        println!();

        for asset in &actionable {
            let icon = if asset.severity == Severity::Critical {
                "🚨"
            } else {
                "⚠️"
            };
            println!("  {} {} in {}", icon, asset.algorithm, asset.file_path);
            for finding in &asset.findings {
                println!("     └─ {}", finding);
            }
            if let Some(ref rem) = asset.remediation {
                println!("     🔧 Fix: {}", rem.lines().next().unwrap_or(""));
                for line in rem.lines().skip(1) {
                    println!("              {}", line);
                }
            }
            if let Some(ref dep) = asset.dependency_path {
                println!("     📦 Dependency path: {}", dep);
            }
            println!();
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…", &s[..max - 1])
    } else {
        s.to_string()
    }
}

fn short_path(path: &str, max: usize) -> String {
    let parts: Vec<&str> = path.split(['/', '\\']).collect();
    let short = if parts.len() <= 2 {
        path.to_string()
    } else {
        format!("…/{}", parts[parts.len() - 2..].join("/"))
    };
    truncate(&short, max)
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
    eprintln!(
        "🔍 Comparing CBOMs:\\n   base: {}\\n   head: {}\\n",
        base_path, head_path
    );

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

        // Post GitHub Actions PR annotations
        if std::env::var("GITHUB_ACTIONS").is_ok() {
            for asset in &result.added {
                if asset.severity == models::Severity::Critical
                    || (strict && asset.severity == models::Severity::Warning)
                {
                    let msg = asset.findings.join("; ");
                    println!(
                        "::error file={},line={}::Banned cryptography introduced: {} - {}",
                        asset.file_path, asset.line_number, asset.algorithm, msg
                    );
                }
            }
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

/// Execute the `view` subcommand: launch the interactive TUI.
fn handle_view(file: Option<&str>) {
    let findings = if let Some(path) = file {
        // Load from JSON file
        match diff::load_cbom(path) {
            Ok(mut assets) => {
                policy::evaluate_all(&mut assets);
                assets
            }
            Err(e) => {
                eprintln!("❌ Error loading CBOM: {}", e);
                process::exit(2);
            }
        }
    } else {
        // Live scan of current directory
        eprintln!("🔍 Scanning current directory for TUI...\n");
        let mut findings = scanner::scan_directory(".");
        let dep_findings = dependencies::scan_dependencies(".");
        findings.extend(dep_findings);
        policy::evaluate_all(&mut findings);
        findings
    };

    if findings.is_empty() {
        eprintln!("✅ No cryptographic assets found. Nothing to display.");
        return;
    }

    eprintln!(
        "🖥️  Launching interactive viewer with {} assets...\n",
        findings.len()
    );

    if let Err(e) = tui::run(findings) {
        eprintln!("❌ TUI error: {}", e);
        process::exit(1);
    }
}

/// Execute the `history` subcommand: scan recent git commits for crypto changes.
fn handle_history(path: &str, commits: usize) {
    eprintln!(
        "🔍 Analyzing cryptographic history ({} commits)...\n",
        commits
    );

    match history::scan_history(path, commits) {
        Ok(timeline) => {
            history::print_timeline(&timeline);
        }
        Err(e) => {
            eprintln!("❌ History scan failed: {}", e);
            process::exit(1);
        }
    }
}
