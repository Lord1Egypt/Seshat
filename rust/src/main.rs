//! `seshat-rs` — the Rust scanning CLI.
//!
//! Usage:
//!   seshat-rs scan <file-or-dir> --patterns <catalog-dir> [--min-confidence X]
//!                                [--json] [--normalized]
//!
//! Scans Solidity sources (a file, or a directory walked in parallel) and prints
//! findings. Output matches the Python engine's findings exactly.

use std::path::{Path, PathBuf};
use std::process::exit;

use rayon::prelude::*;
use serde::Serialize;
use walkdir::WalkDir;

use seshat_rs::{engine, normalize, pattern};

const SKIP_DIRS: &[&str] = &["node_modules", "lib", "out", "cache", "artifacts", "build", ".git"];

#[derive(Serialize)]
struct Out {
    file: String,
    pattern_id: String,
    line: usize,
    severity: String,
    confidence: f64,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args[1] != "scan" {
        eprintln!("usage: seshat-rs scan <file-or-dir> --patterns <dir> [--min-confidence X] [--json] [--normalized]");
        exit(2);
    }
    let target = PathBuf::from(&args[2]);

    let mut patterns_dir = std::env::var("SESHAT_PATTERNS").ok();
    let mut min_conf = 0.0f64;
    let mut json = false;
    let mut normalized = false;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--patterns" => {
                i += 1;
                patterns_dir = args.get(i).cloned();
            }
            "--min-confidence" => {
                i += 1;
                min_conf = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0.0);
            }
            "--json" => json = true,
            "--normalized" => normalized = true,
            other => {
                eprintln!("unknown arg: {other}");
                exit(2);
            }
        }
        i += 1;
    }

    let pdir = match patterns_dir {
        Some(d) => PathBuf::from(d),
        None => {
            eprintln!("error: --patterns <dir> (or $SESHAT_PATTERNS) is required");
            exit(2);
        }
    };
    let patterns = match pattern::load_dir(&pdir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error loading patterns: {e}");
            exit(1);
        }
    };

    let files: Vec<PathBuf> = if target.is_dir() {
        WalkDir::new(&target)
            .into_iter()
            .filter_entry(|e| {
                !e.file_type().is_dir()
                    || !SKIP_DIRS.contains(&e.file_name().to_string_lossy().as_ref())
            })
            .filter_map(|e| e.ok())
            .map(|e| e.into_path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("sol"))
            .collect()
    } else {
        vec![target.clone()]
    };

    let results: Vec<Out> = files
        .par_iter()
        .flat_map(|f| scan_file(f, &patterns, min_conf, normalized))
        .collect();

    if json {
        println!("{}", serde_json::to_string(&results).unwrap_or_else(|_| "[]".into()));
    } else {
        for r in &results {
            println!("{:<8} {} {}:{}", r.severity, r.pattern_id, r.file, r.line);
        }
        eprintln!(
            "scanned {} file(s) with {} patterns → {} findings",
            files.len(),
            patterns.len(),
            results.len()
        );
    }
}

fn scan_file(path: &Path, patterns: &[pattern::Pattern], min_conf: f64, normalized: bool) -> Vec<Out> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let text = if normalized {
        raw
    } else {
        normalize::strip_comments_and_strings(&raw)
    };
    engine::scan_source(&text, patterns, min_conf)
        .into_iter()
        .map(|f| Out {
            file: path.display().to_string(),
            pattern_id: f.pattern_id,
            line: f.line,
            severity: f.severity,
            confidence: f.confidence,
        })
        .collect()
}
