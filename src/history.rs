//! Git history scanner: analyzes the last N commits to build a timeline
//! of cryptographic changes in the repository.
//!
//! This enables developers to see patterns like "Added 3 RSA usages this
//! week" or "Removed MD5 last commit" — creating immediate visibility into
//! how the project's crypto posture is evolving over time.

use std::process::Command;

use crate::models::{CryptoAsset, Severity};
use crate::{dependencies, policy, scanner};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// A single commit's crypto snapshot and delta from the previous commit.
pub struct CommitCryptoSnapshot {
    /// Short commit hash (7 chars).
    pub hash: String,
    /// Commit subject line.
    pub subject: String,
    /// Author date (YYYY-MM-DD).
    pub date: String,
    /// All crypto assets detected in this commit's tree.
    pub total_assets: usize,
    /// Crypto assets newly added compared to the previous commit.
    pub added: Vec<CryptoAsset>,
    /// Crypto assets removed compared to the previous commit.
    pub removed: Vec<CryptoAsset>,
}

/// Scan the last `n` commits in the current git repository and return
/// a timeline of cryptographic changes.
///
/// Falls back gracefully if git is not available or the directory is not
/// a git repository.
pub fn scan_history(repo_path: &str, n: usize) -> Result<Vec<CommitCryptoSnapshot>, String> {
    // Verify we're in a git repo
    let status = Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to run git: {}", e))?;

    if !status.status.success() {
        return Err("Not a git repository. Run this command from a git repo.".to_string());
    }

    // Get the last N commit hashes, subjects, and dates
    let log_output = Command::new("git")
        .args([
            "log",
            &format!("-n {}", n),
            "--format=%H|%s|%as",
            "--no-merges",
        ])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to run git log: {}", e))?;

    if !log_output.status.success() {
        return Err(format!(
            "git log failed: {}",
            String::from_utf8_lossy(&log_output.stderr)
        ));
    }

    let log_str = String::from_utf8_lossy(&log_output.stdout);
    let commits: Vec<(String, String, String)> = log_str
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(3, '|').collect();
            if parts.len() == 3 {
                Some((
                    parts[0].to_string(),
                    parts[1].to_string(),
                    parts[2].to_string(),
                ))
            } else {
                None
            }
        })
        .collect();

    if commits.is_empty() {
        return Err("No commits found in git history.".to_string());
    }

    let mut timeline = Vec::new();
    let mut prev_assets: Vec<CryptoAsset> = Vec::new();

    // Process commits from oldest to newest for proper diffing
    for (hash, subject, date) in commits.iter().rev() {
        let assets = scan_commit(repo_path, hash)?;
        let total = assets.len();

        // Diff against previous commit
        let (added, removed) = diff_assets(&prev_assets, &assets);

        timeline.push(CommitCryptoSnapshot {
            hash: hash[..7.min(hash.len())].to_string(),
            subject: subject.clone(),
            date: date.clone(),
            total_assets: total,
            added,
            removed,
        });

        prev_assets = assets;
    }

    // Reverse so newest is first (matches `git log` order)
    timeline.reverse();

    Ok(timeline)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Scan a specific commit's file tree for crypto assets.
///
/// Uses `git show <hash>:<file>` to read files at a specific commit
/// without checking out the entire tree.
fn scan_commit(repo_path: &str, hash: &str) -> Result<Vec<CryptoAsset>, String> {
    // Get list of files in this commit's tree
    let ls_output = Command::new("git")
        .args(["ls-tree", "-r", "--name-only", hash])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to run git ls-tree: {}", e))?;

    if !ls_output.status.success() {
        return Ok(Vec::new()); // Gracefully handle missing commits
    }

    // Create a temp directory and extract the commit's tree into it
    let tmp_dir =
        tempfile::tempdir().map_err(|e| format!("Failed to create temp directory: {}", e))?;

    // Use git archive to extract files
    let archive_output = Command::new("git")
        .args(["archive", hash])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to run git archive: {}", e))?;

    if !archive_output.status.success() {
        return Ok(Vec::new());
    }

    // Extract tar archive (cross-platform: use tar command)
    let tar_result = extract_tar_archive(&archive_output.stdout, tmp_dir.path());
    if tar_result.is_err() {
        // Fallback: try scanning via git show for key files
        return scan_commit_via_show(repo_path, hash);
    }

    let tmp_path = tmp_dir.path().to_string_lossy().to_string();
    let mut findings = scanner::scan_directory(&tmp_path);
    let dep_findings = dependencies::scan_dependencies(&tmp_path);
    findings.extend(dep_findings);
    policy::evaluate_all(&mut findings);

    Ok(findings)
}

/// Extract a tar archive from raw bytes into a target directory.
fn extract_tar_archive(tar_data: &[u8], target: &std::path::Path) -> Result<(), String> {
    use std::io::Write;

    // Write tar data to a temp file, then extract
    let tar_path = target.join("__archive.tar");
    let mut tar_file = std::fs::File::create(&tar_path)
        .map_err(|e| format!("Failed to create tar file: {}", e))?;
    tar_file
        .write_all(tar_data)
        .map_err(|e| format!("Failed to write tar data: {}", e))?;
    drop(tar_file);

    let output = Command::new("tar")
        .args([
            "xf",
            &tar_path.to_string_lossy(),
            "-C",
            &target.to_string_lossy(),
        ])
        .output()
        .map_err(|e| format!("tar extraction failed: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "tar extraction failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Clean up the tar file
    let _ = std::fs::remove_file(&tar_path);

    Ok(())
}

/// Fallback: scan a commit by reading individual files via `git show`.
/// This is slower but doesn't require `tar` to be installed.
fn scan_commit_via_show(repo_path: &str, hash: &str) -> Result<Vec<CryptoAsset>, String> {
    let ls_output = Command::new("git")
        .args(["ls-tree", "-r", "--name-only", hash])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to list files: {}", e))?;

    if !ls_output.status.success() {
        return Ok(Vec::new());
    }

    let tmp_dir =
        tempfile::tempdir().map_err(|e| format!("Failed to create temp directory: {}", e))?;

    let file_list = String::from_utf8_lossy(&ls_output.stdout);

    // Only extract scannable files (source code and lockfiles)
    let scannable_extensions = [
        ".py", ".js", ".ts", ".java", ".go", ".rs", ".cs", ".c", ".cpp", ".h", ".pem", ".crt",
        ".cer", ".der",
    ];
    let scannable_names = [
        "requirements.txt",
        "Pipfile.lock",
        "package-lock.json",
        "yarn.lock",
        "Cargo.lock",
    ];

    for file_path in file_list.lines() {
        let file_path = file_path.trim();
        if file_path.is_empty() {
            continue;
        }

        let is_scannable = scannable_extensions
            .iter()
            .any(|ext| file_path.ends_with(ext))
            || scannable_names.iter().any(|name| file_path.ends_with(name));

        if !is_scannable {
            continue;
        }

        // git show hash:path
        let show_output = Command::new("git")
            .args(["show", &format!("{}:{}", hash, file_path)])
            .current_dir(repo_path)
            .output();

        if let Ok(output) = show_output {
            if output.status.success() {
                let dest = tmp_dir.path().join(file_path);
                if let Some(parent) = dest.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(&dest, &output.stdout);
            }
        }
    }

    let tmp_path = tmp_dir.path().to_string_lossy().to_string();
    let mut findings = scanner::scan_directory(&tmp_path);
    let dep_findings = dependencies::scan_dependencies(&tmp_path);
    findings.extend(dep_findings);
    policy::evaluate_all(&mut findings);

    Ok(findings)
}

/// Compute the diff between two sets of crypto assets.
fn diff_assets(
    prev: &[CryptoAsset],
    current: &[CryptoAsset],
) -> (Vec<CryptoAsset>, Vec<CryptoAsset>) {
    use std::collections::HashSet;

    let prev_fingerprints: HashSet<(String, String)> = prev
        .iter()
        .map(|a| (a.algorithm.clone(), a.library_source.clone()))
        .collect();

    let curr_fingerprints: HashSet<(String, String)> = current
        .iter()
        .map(|a| (a.algorithm.clone(), a.library_source.clone()))
        .collect();

    let added: Vec<CryptoAsset> = current
        .iter()
        .filter(|a| !prev_fingerprints.contains(&(a.algorithm.clone(), a.library_source.clone())))
        .cloned()
        .collect();

    let removed: Vec<CryptoAsset> = prev
        .iter()
        .filter(|a| !curr_fingerprints.contains(&(a.algorithm.clone(), a.library_source.clone())))
        .cloned()
        .collect();

    (added, removed)
}

/// Print a formatted timeline of cryptographic changes to stderr.
pub fn print_timeline(snapshots: &[CommitCryptoSnapshot]) {
    if snapshots.is_empty() {
        eprintln!("  No commits to display.");
        return;
    }

    eprintln!("┌─────────────────────────────────────────────────────────────────────┐");
    eprintln!("│  📊 Cryptographic History Timeline                                 │");
    eprintln!("├─────────────────────────────────────────────────────────────────────┤");

    for (i, snap) in snapshots.iter().enumerate() {
        let subject = if snap.subject.len() > 40 {
            format!("{}…", &snap.subject[..39])
        } else {
            snap.subject.clone()
        };

        eprintln!("│                                                                     │");
        eprintln!("│  {} ({})  {}", snap.date, snap.hash, subject);
        eprintln!("│  Total crypto assets: {}", snap.total_assets);

        if !snap.added.is_empty() {
            let critical_count = snap
                .added
                .iter()
                .filter(|a| a.severity == Severity::Critical)
                .count();
            let added_algos: Vec<String> = snap.added.iter().map(|a| a.algorithm.clone()).collect();
            // Deduplicate and count
            let mut algo_counts: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for algo in &added_algos {
                *algo_counts.entry(algo.clone()).or_insert(0) += 1;
            }
            let summary: Vec<String> = algo_counts
                .iter()
                .map(|(algo, count)| {
                    if *count > 1 {
                        format!("{} (×{})", algo, count)
                    } else {
                        algo.clone()
                    }
                })
                .collect();

            eprintln!(
                "│  ✅ Added {} asset(s): {}",
                snap.added.len(),
                summary.join(", ")
            );
            if critical_count > 0 {
                eprintln!("│  🚨 {} critical issue(s) introduced!", critical_count);
            }
        }

        if !snap.removed.is_empty() {
            let removed_algos: Vec<String> =
                snap.removed.iter().map(|a| a.algorithm.clone()).collect();
            eprintln!(
                "│  🗑️  Removed {} asset(s): {}",
                snap.removed.len(),
                removed_algos.join(", ")
            );
        }

        if snap.added.is_empty() && snap.removed.is_empty() && i > 0 {
            eprintln!("│  — No cryptographic changes");
        }

        if i < snapshots.len() - 1 {
            eprintln!("│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ");
        }
    }

    eprintln!("│                                                                     │");
    eprintln!("└─────────────────────────────────────────────────────────────────────┘");

    // Print aggregate summary
    let total_added: usize = snapshots.iter().map(|s| s.added.len()).sum();
    let total_removed: usize = snapshots.iter().map(|s| s.removed.len()).sum();
    let total_critical: usize = snapshots
        .iter()
        .flat_map(|s| s.added.iter())
        .filter(|a| a.severity == Severity::Critical)
        .count();

    eprintln!();
    eprintln!("📈 Summary across {} commit(s):", snapshots.len());
    eprintln!("   + {} crypto asset(s) added", total_added);
    eprintln!("   - {} crypto asset(s) removed", total_removed);
    if total_critical > 0 {
        eprintln!("   🚨 {} critical issue(s) introduced", total_critical);
    }
}
