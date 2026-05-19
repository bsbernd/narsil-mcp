//! `narsil-mcp stats` CLI subcommand.
//!
//! Reads persistent metrics from `~/.cache/narsil-mcp/stats/` without
//! starting an engine, and prints either aggregate or per-`index_path`
//! views. Designed so users can check "how much has narsil helped me?"
//! from a plain shell.

use crate::metrics::{
    global_stats_dir, index_path_hash, list_stats_files, render_aggregate_json,
    render_aggregate_markdown, render_list_markdown, stats_file_for, PersistedMetrics,
};
use anyhow::{Context, Result};
use std::path::PathBuf;

/// Output format for `stats` subcommands.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum StatsFormat {
    Markdown,
    Json,
}

#[derive(Debug, clap::Args)]
pub struct StatsArgs {
    /// Show one row per index_path instead of aggregating.
    #[arg(long)]
    pub list: bool,

    /// Restrict the report to one specific index_path (canonical path, the
    /// same value you'd pass to `--index-path` when starting the server).
    #[arg(long)]
    pub index_path: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = StatsFormat::Markdown)]
    pub format: StatsFormat,

    /// Show where stats are stored and exit.
    #[arg(long)]
    pub show_path: bool,
}

pub fn handle_stats_command(args: StatsArgs) -> Result<()> {
    if args.show_path {
        println!("{}", global_stats_dir().display());
        return Ok(());
    }

    if let Some(index_path) = args.index_path.as_ref() {
        return handle_single(index_path, args.format);
    }

    if args.list {
        return handle_list(args.format);
    }

    handle_aggregate(args.format)
}

fn handle_single(index_path: &std::path::Path, format: StatsFormat) -> Result<()> {
    let file = stats_file_for(index_path);
    if !file.exists() {
        anyhow::bail!(
            "No stats found for index path {:?} (looked for {:?}). \
             Has narsil-mcp ever been started with --index-path {:?}?",
            index_path,
            file,
            index_path,
        );
    }
    let snapshot = PersistedMetrics::load(&file)
        .with_context(|| format!("Failed to read stats file {:?}", file))?;
    emit(&[snapshot], format)
}

fn handle_aggregate(format: StatsFormat) -> Result<()> {
    let snapshots = collect_all()?;
    emit(&snapshots, format)
}

fn handle_list(format: StatsFormat) -> Result<()> {
    let files = list_stats_files()?;
    let mut pairs: Vec<(PathBuf, PersistedMetrics)> = Vec::with_capacity(files.len());
    for file in files {
        match PersistedMetrics::load(&file) {
            Ok(snap) => pairs.push((file, snap)),
            Err(e) => eprintln!("warning: skipping unreadable stats file {:?}: {}", file, e),
        }
    }
    // Most-recently-updated first.
    pairs.sort_by(|a, b| b.1.saved_at.cmp(&a.1.saved_at));

    match format {
        StatsFormat::Markdown => {
            print!("{}", render_list_markdown(&pairs));
        }
        StatsFormat::Json => {
            let json: Vec<serde_json::Value> = pairs
                .iter()
                .map(|(path, snap)| {
                    serde_json::json!({
                        "stats_file": path.to_string_lossy(),
                        "index_path": snap.index_path,
                        "index_path_hash": index_path_hash(std::path::Path::new(&snap.index_path)),
                        "first_started_at": snap.first_started_at,
                        "saved_at": snap.saved_at,
                        "total_uptime_seconds": snap.total_uptime_seconds,
                        "total_requests": snap.total_requests(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
    }
    Ok(())
}

fn collect_all() -> Result<Vec<PersistedMetrics>> {
    let files = list_stats_files()?;
    let mut out = Vec::with_capacity(files.len());
    for file in files {
        match PersistedMetrics::load(&file) {
            Ok(snap) => out.push(snap),
            Err(e) => eprintln!("warning: skipping unreadable stats file {:?}: {}", file, e),
        }
    }
    Ok(out)
}

fn emit(snapshots: &[PersistedMetrics], format: StatsFormat) -> Result<()> {
    match format {
        StatsFormat::Markdown => {
            print!("{}", render_aggregate_markdown(snapshots)?);
        }
        StatsFormat::Json => {
            let json = render_aggregate_json(snapshots)?;
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
    }
    Ok(())
}
