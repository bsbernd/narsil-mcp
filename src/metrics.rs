//! Performance metrics tracking for tool operations.
//!
//! Tracks per-tool timings, repo indexing, and file parsing. Counters are kept
//! in two parallel sets: a session view (reset on process start, useful for
//! "this run") and a lifetime view that is persisted to disk and resumed on the
//! next start (ccache-style accumulation across restarts).
//!
//! Percentiles are computed from an HDR histogram so the percentile state is
//! bounded in memory and survives serialisation.

use anyhow::{Context, Result};
use hdrhistogram::serialization::{Deserializer, Serializer, V2Serializer};
use hdrhistogram::Histogram;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Notify;
use tracing::{debug, warn};

/// HDR histogram significant figures — 3 gives ~0.1% precision, plenty for
/// tool latencies in the µs–s range.
const HISTOGRAM_SIGFIG: u8 = 3;

/// Default flush cadence when no override is provided.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(180);

/// Statistics for a single metric stream (one tool, or file parsing).
///
/// Units of `total`/`min`/`max` are determined by the caller: tool times are
/// recorded in milliseconds, file-parse times in microseconds. Field names
/// keep the historical `_ms` suffix even though the data may be µs — callers
/// know which is which by context.
#[derive(Clone)]
pub struct MetricStats {
    pub count: u64,
    pub total_ms: u64,
    pub min_ms: u64,
    pub max_ms: u64,
    histogram: Histogram<u64>,
}

impl Default for MetricStats {
    fn default() -> Self {
        let mut histogram =
            Histogram::<u64>::new(HISTOGRAM_SIGFIG).expect("sigfig=3 is always valid");
        histogram.auto(true);
        Self {
            count: 0,
            total_ms: 0,
            min_ms: u64::MAX,
            max_ms: 0,
            histogram,
        }
    }
}

impl std::fmt::Debug for MetricStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricStats")
            .field("count", &self.count)
            .field("total_ms", &self.total_ms)
            .field("min_ms", &self.min_ms)
            .field("max_ms", &self.max_ms)
            .finish()
    }
}

impl MetricStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, duration_units: u64) {
        self.count += 1;
        self.total_ms += duration_units;
        self.min_ms = self.min_ms.min(duration_units);
        self.max_ms = self.max_ms.max(duration_units);
        // HDR histograms reject 0; bump to 1 so the percentile is still meaningful
        // for sub-resolution samples without skewing the distribution materially.
        let value = duration_units.max(1);
        if let Err(e) = self.histogram.record(value) {
            debug!("HDR histogram record failed for value {}: {}", value, e);
        }
    }

    pub fn avg_ms(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.total_ms as f64 / self.count as f64
        }
    }

    pub fn percentile(&self, p: f64) -> u64 {
        if self.histogram.is_empty() {
            return 0;
        }
        self.histogram.value_at_quantile(p / 100.0)
    }

    pub fn p50(&self) -> u64 {
        self.percentile(50.0)
    }

    pub fn p95(&self) -> u64 {
        self.percentile(95.0)
    }

    pub fn p99(&self) -> u64 {
        self.percentile(99.0)
    }

    /// Merge another stats stream into this one. Used when loading persisted
    /// lifetime counters from disk.
    pub fn merge_from(&mut self, other: &MetricStats) {
        self.count += other.count;
        self.total_ms += other.total_ms;
        if other.count > 0 {
            self.min_ms = self.min_ms.min(other.min_ms);
            self.max_ms = self.max_ms.max(other.max_ms);
        }
        if let Err(e) = self.histogram.add(&other.histogram) {
            warn!("HDR histogram merge failed: {}", e);
        }
    }

    fn to_persisted(&self) -> Result<PersistedCounter> {
        let mut buf = Vec::new();
        let mut serializer = V2Serializer::new();
        serializer
            .serialize(&self.histogram, &mut buf)
            .context("Failed to serialise HDR histogram")?;
        Ok(PersistedCounter {
            count: self.count,
            total_ms: self.total_ms,
            min_ms: if self.count == 0 { 0 } else { self.min_ms },
            max_ms: self.max_ms,
            histogram_bytes: buf,
        })
    }

    fn from_persisted(p: &PersistedCounter) -> Result<Self> {
        let mut deserializer = Deserializer::new();
        let histogram = deserializer
            .deserialize::<u64, _>(&mut p.histogram_bytes.as_slice())
            .context("Failed to deserialise HDR histogram")?;
        Ok(Self {
            count: p.count,
            total_ms: p.total_ms,
            min_ms: if p.count == 0 { u64::MAX } else { p.min_ms },
            max_ms: p.max_ms,
            histogram,
        })
    }
}

/// Repository indexing metrics (session-only, not persisted).
#[derive(Debug, Clone)]
pub struct RepoIndexMetrics {
    pub repo_name: String,
    pub index_time_ms: u64,
    pub file_count: usize,
    pub symbol_count: usize,
    pub indexed_at: Instant,
}

/// On-disk metric counter, one per tool (plus one for file parsing).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedCounter {
    count: u64,
    total_ms: u64,
    min_ms: u64,
    max_ms: u64,
    histogram_bytes: Vec<u8>,
}

/// On-disk metric snapshot. Loaded on startup, written periodically and on
/// shutdown so accumulated counters survive process restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedMetrics {
    version: u32,
    /// Unix seconds when this metrics file was first created.
    first_started_at: u64,
    /// Unix seconds when the snapshot was last written.
    saved_at: u64,
    /// Cumulative server uptime across all runs, in seconds.
    total_uptime_seconds: u64,
    tools: HashMap<String, PersistedCounter>,
    file_parse: PersistedCounter,
}

impl PersistedMetrics {
    const CURRENT_VERSION: u32 = 1;

    fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).context("Failed to read metrics file")?;
        let snapshot: Self =
            postcard::from_bytes(&data).context("Failed to deserialise metrics file")?;
        if snapshot.version != Self::CURRENT_VERSION {
            return Err(anyhow::anyhow!(
                "Metrics file version mismatch: {} != {}",
                snapshot.version,
                Self::CURRENT_VERSION
            ));
        }
        Ok(snapshot)
    }

    fn save(&self, path: &Path) -> Result<()> {
        let data = postcard::to_stdvec(self).context("Failed to serialise metrics")?;
        let temp_path = path.with_extension("tmp");
        std::fs::write(&temp_path, &data).context("Failed to write temp metrics file")?;
        std::fs::rename(&temp_path, path).context("Failed to rename metrics file into place")?;
        Ok(())
    }
}

/// Lifetime accumulators, kept separately from the session counters so the
/// report can show both views.
struct LifetimeCounters {
    tools: HashMap<String, MetricStats>,
    file_parse: MetricStats,
    /// Cumulative uptime across all runs, in seconds. Updated on each save.
    persisted_uptime_seconds: u64,
    /// Unix seconds of the first time the persistent file was created.
    first_started_at: u64,
}

impl Default for LifetimeCounters {
    fn default() -> Self {
        Self {
            tools: HashMap::new(),
            file_parse: MetricStats::new(),
            persisted_uptime_seconds: 0,
            first_started_at: now_unix_seconds(),
        }
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Global metrics collection.
pub struct Metrics {
    start_time: Instant,
    /// Session-only counters (reset on process start).
    tool_metrics: RwLock<HashMap<String, MetricStats>>,
    repo_index_metrics: RwLock<Vec<RepoIndexMetrics>>,
    file_parse_metrics: RwLock<MetricStats>,
    /// Lifetime counters, loaded from disk at startup and updated on every
    /// `record_*` call. Saved back to disk periodically and on shutdown.
    lifetime: RwLock<LifetimeCounters>,
    /// Persistence target. `None` means metrics are session-only.
    persist_path: Option<PathBuf>,
    /// Set whenever lifetime counters change; cleared by the flush task.
    dirty: AtomicBool,
    /// Notifies the flush task to wake up (used for shutdown).
    flush_notify: Arc<Notify>,
}

impl Metrics {
    /// In-memory only — no persistence. Used in tests and when persistence is
    /// explicitly disabled.
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            tool_metrics: RwLock::new(HashMap::new()),
            repo_index_metrics: RwLock::new(Vec::new()),
            file_parse_metrics: RwLock::new(MetricStats::new()),
            lifetime: RwLock::new(LifetimeCounters::default()),
            persist_path: None,
            dirty: AtomicBool::new(false),
            flush_notify: Arc::new(Notify::new()),
        }
    }

    /// Create a Metrics instance backed by an on-disk file. If the file exists
    /// and parses, lifetime counters are seeded from it; otherwise a fresh
    /// lifetime state is created.
    pub fn with_persistence(path: PathBuf) -> Self {
        let mut lifetime = LifetimeCounters::default();
        if path.exists() {
            match PersistedMetrics::load(&path) {
                Ok(snapshot) => {
                    lifetime.first_started_at = snapshot.first_started_at;
                    lifetime.persisted_uptime_seconds = snapshot.total_uptime_seconds;
                    match MetricStats::from_persisted(&snapshot.file_parse) {
                        Ok(stats) => lifetime.file_parse = stats,
                        Err(e) => warn!("Failed to load persisted file_parse stats: {}", e),
                    }
                    for (name, persisted) in snapshot.tools.iter() {
                        match MetricStats::from_persisted(persisted) {
                            Ok(stats) => {
                                lifetime.tools.insert(name.clone(), stats);
                            }
                            Err(e) => warn!("Failed to load persisted tool '{}': {}", name, e),
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to load metrics file at {:?}: {} — starting fresh",
                        path, e
                    );
                }
            }
        }

        Self {
            start_time: Instant::now(),
            tool_metrics: RwLock::new(HashMap::new()),
            repo_index_metrics: RwLock::new(Vec::new()),
            file_parse_metrics: RwLock::new(MetricStats::new()),
            lifetime: RwLock::new(lifetime),
            persist_path: Some(path),
            dirty: AtomicBool::new(false),
            flush_notify: Arc::new(Notify::new()),
        }
    }

    fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Record a tool execution time (milliseconds).
    pub fn record_tool(&self, tool_name: &str, duration: Duration) {
        let duration_ms = duration.as_millis() as u64;
        {
            let mut session = self.tool_metrics.write();
            session
                .entry(tool_name.to_string())
                .or_default()
                .record(duration_ms);
        }
        {
            let mut lifetime = self.lifetime.write();
            lifetime
                .tools
                .entry(tool_name.to_string())
                .or_default()
                .record(duration_ms);
        }
        self.mark_dirty();
    }

    /// Record a repository indexing run (session-only — not persisted).
    pub fn record_repo_index(
        &self,
        repo_name: String,
        duration: Duration,
        file_count: usize,
        symbol_count: usize,
    ) {
        let metric = RepoIndexMetrics {
            repo_name,
            index_time_ms: duration.as_millis() as u64,
            file_count,
            symbol_count,
            indexed_at: Instant::now(),
        };
        self.repo_index_metrics.write().push(metric);
    }

    /// Record a single file parsing time (microseconds).
    pub fn record_file_parse(&self, duration: Duration) {
        let duration_us = duration.as_micros() as u64;
        self.file_parse_metrics.write().record(duration_us);
        self.lifetime.write().file_parse.record(duration_us);
        self.mark_dirty();
    }

    pub fn get_tool_stats(&self, tool_name: &str) -> Option<MetricStats> {
        self.tool_metrics.read().get(tool_name).cloned()
    }

    pub fn get_all_tool_stats(&self) -> HashMap<String, MetricStats> {
        self.tool_metrics.read().clone()
    }

    pub fn get_repo_index_metrics(&self) -> Vec<RepoIndexMetrics> {
        self.repo_index_metrics.read().clone()
    }

    pub fn get_file_parse_stats(&self) -> MetricStats {
        self.file_parse_metrics.read().clone()
    }

    pub fn total_requests(&self) -> u64 {
        self.tool_metrics.read().values().map(|s| s.count).sum()
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn uptime_string(&self) -> String {
        format_duration_seconds(self.uptime_seconds())
    }

    /// Snapshot of lifetime counters: tool name → cumulative stats.
    pub fn get_lifetime_tool_stats(&self) -> HashMap<String, MetricStats> {
        self.lifetime.read().tools.clone()
    }

    pub fn get_lifetime_file_parse_stats(&self) -> MetricStats {
        self.lifetime.read().file_parse.clone()
    }

    /// Cumulative uptime across all runs (including the current session).
    pub fn lifetime_uptime_seconds(&self) -> u64 {
        self.lifetime.read().persisted_uptime_seconds + self.uptime_seconds()
    }

    /// Unix seconds of the first recorded run.
    pub fn first_started_at(&self) -> u64 {
        self.lifetime.read().first_started_at
    }

    /// Total requests across the lifetime view.
    pub fn lifetime_total_requests(&self) -> u64 {
        self.lifetime.read().tools.values().map(|s| s.count).sum()
    }

    /// Take and clear the dirty flag.
    fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Ordering::Relaxed)
    }

    fn snapshot_for_persistence(&self) -> Result<PersistedMetrics> {
        let lifetime = self.lifetime.read();
        let mut tools = HashMap::with_capacity(lifetime.tools.len());
        for (name, stats) in lifetime.tools.iter() {
            tools.insert(name.clone(), stats.to_persisted()?);
        }
        let file_parse = lifetime.file_parse.to_persisted()?;
        Ok(PersistedMetrics {
            version: PersistedMetrics::CURRENT_VERSION,
            first_started_at: lifetime.first_started_at,
            saved_at: now_unix_seconds(),
            total_uptime_seconds: lifetime.persisted_uptime_seconds + self.uptime_seconds(),
            tools,
            file_parse,
        })
    }

    /// Force-write lifetime counters to disk if persistence is configured.
    /// Called by the flush task and on shutdown.
    pub fn flush(&self) -> Result<()> {
        let Some(path) = self.persist_path.as_ref() else {
            return Ok(());
        };
        let snapshot = self.snapshot_for_persistence()?;
        snapshot.save(path)?;
        debug!("Flushed metrics snapshot to {:?}", path);
        Ok(())
    }

    /// Returns true if persistence is enabled.
    pub fn is_persistent(&self) -> bool {
        self.persist_path.is_some()
    }

    /// Path being written to, for diagnostics.
    pub fn persist_path(&self) -> Option<&Path> {
        self.persist_path.as_deref()
    }

    /// Used by the flush task to be woken up on shutdown so it can exit
    /// promptly rather than waiting out the interval.
    pub fn shutdown_notifier(&self) -> Arc<Notify> {
        self.flush_notify.clone()
    }

    /// Signals the flush task to wake up immediately (used during shutdown).
    pub fn notify_shutdown(&self) {
        self.flush_notify.notify_waiters();
    }

    /// Generate a formatted Markdown metrics report.
    pub fn report(&self) -> String {
        let mut output = String::new();

        output.push_str("# Performance Metrics\n\n");
        output.push_str(&format!("**Session Uptime**: {}\n", self.uptime_string()));
        output.push_str(&format!(
            "**Lifetime Uptime**: {} (tracking since {})\n",
            format_duration_seconds(self.lifetime_uptime_seconds()),
            format_unix_timestamp(self.first_started_at())
        ));
        output.push_str(&format!(
            "**Session Requests**: {}\n",
            self.total_requests()
        ));
        output.push_str(&format!(
            "**Lifetime Requests**: {}\n\n",
            self.lifetime_total_requests()
        ));

        // Repository indexing — session-only by design.
        output.push_str("## Repository Indexing (this session)\n\n");
        let repo_metrics = self.get_repo_index_metrics();
        if !repo_metrics.is_empty() {
            output.push_str("| Repository | Index Time | Files | Symbols | Files/sec |\n");
            output.push_str("|------------|------------|-------|---------|----------|\n");
            for metric in &repo_metrics {
                let files_per_sec = if metric.index_time_ms > 0 {
                    (metric.file_count as f64 / (metric.index_time_ms as f64 / 1000.0)).round()
                        as u64
                } else {
                    0
                };
                output.push_str(&format!(
                    "| {} | {}ms | {} | {} | {} |\n",
                    metric.repo_name,
                    metric.index_time_ms,
                    metric.file_count,
                    metric.symbol_count,
                    files_per_sec
                ));
            }
            output.push('\n');
        } else {
            output.push_str("*No repositories indexed yet.*\n\n");
        }

        // File parsing — show both views.
        let session_parse = self.get_file_parse_stats();
        let lifetime_parse = self.get_lifetime_file_parse_stats();
        if session_parse.count > 0 || lifetime_parse.count > 0 {
            output.push_str("## File Parsing\n\n");
            output.push_str("| Scope | Files Parsed | Avg | Min | Max | P50 | P95 | P99 |\n");
            output.push_str("|-------|--------------|-----|-----|-----|-----|-----|-----|\n");
            if session_parse.count > 0 {
                push_parse_row(&mut output, "Session", &session_parse);
            }
            if lifetime_parse.count > 0 {
                push_parse_row(&mut output, "Lifetime", &lifetime_parse);
            }
            output.push('\n');
        }

        // Tool execution — Lifetime first (the durable view), then session.
        let lifetime_tools = self.get_lifetime_tool_stats();
        let session_tools = self.get_all_tool_stats();

        output.push_str("## Tool Execution Times (Lifetime)\n\n");
        if !lifetime_tools.is_empty() {
            push_tool_table(&mut output, &lifetime_tools);
        } else {
            output.push_str("*No tool calls recorded yet.*\n");
        }
        output.push('\n');

        output.push_str("## Tool Execution Times (This Session)\n\n");
        if !session_tools.is_empty() {
            push_tool_table(&mut output, &session_tools);
        } else {
            output.push_str("*No tool calls recorded this session.*\n");
        }

        output
    }

    /// Generate a JSON report of all metrics.
    pub fn report_json(&self) -> serde_json::Value {
        use serde_json::json;

        let session_tools_json = tool_stats_to_json(&self.get_all_tool_stats());
        let lifetime_tools_json = tool_stats_to_json(&self.get_lifetime_tool_stats());

        let repo_metrics = self.get_repo_index_metrics();
        let repo_json: Vec<serde_json::Value> = repo_metrics
            .iter()
            .map(|metric| {
                json!({
                    "repo_name": metric.repo_name,
                    "index_time_ms": metric.index_time_ms,
                    "file_count": metric.file_count,
                    "symbol_count": metric.symbol_count
                })
            })
            .collect();

        let session_parse = self.get_file_parse_stats();
        let lifetime_parse = self.get_lifetime_file_parse_stats();

        json!({
            "session": {
                "uptime_seconds": self.uptime_seconds(),
                "uptime_string": self.uptime_string(),
                "total_requests": self.total_requests(),
                "file_parsing": parse_stats_to_json(&session_parse),
                "tools": session_tools_json,
            },
            "lifetime": {
                "first_started_at": self.first_started_at(),
                "uptime_seconds": self.lifetime_uptime_seconds(),
                "uptime_string": format_duration_seconds(self.lifetime_uptime_seconds()),
                "total_requests": self.lifetime_total_requests(),
                "file_parsing": parse_stats_to_json(&lifetime_parse),
                "tools": lifetime_tools_json,
                "persistent": self.is_persistent(),
            },
            "repository_indexing": repo_json,
        })
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Metrics {
    /// Best-effort sync flush so metrics aren't lost if the engine is dropped
    /// without an explicit shutdown call. Errors are logged, not propagated —
    /// Drop must not panic.
    fn drop(&mut self) {
        if !self.dirty.load(Ordering::Relaxed) {
            return;
        }
        if self.persist_path.is_none() {
            return;
        }
        if let Err(e) = self.flush() {
            warn!("Metrics flush on drop failed: {}", e);
        }
    }
}

fn push_parse_row(output: &mut String, scope: &str, stats: &MetricStats) {
    output.push_str(&format!(
        "| {} | {} | {:.2}µs | {}µs | {}µs | {}µs | {}µs | {}µs |\n",
        scope,
        stats.count,
        stats.avg_ms(),
        stats.min_ms,
        stats.max_ms,
        stats.p50(),
        stats.p95(),
        stats.p99()
    ));
}

fn push_tool_table(output: &mut String, tools: &HashMap<String, MetricStats>) {
    output.push_str(
        "| Tool | Calls | Avg (ms) | P50 (ms) | P95 (ms) | P99 (ms) | Min (ms) | Max (ms) |\n",
    );
    output.push_str(
        "|------|-------|----------|----------|----------|----------|----------|----------|\n",
    );
    let mut sorted: Vec<_> = tools.iter().collect();
    sorted.sort_by_key(|(name, _)| name.as_str().to_owned());
    for (tool_name, stats) in sorted {
        output.push_str(&format!(
            "| {} | {} | {:.2} | {} | {} | {} | {} | {} |\n",
            tool_name,
            stats.count,
            stats.avg_ms(),
            stats.p50(),
            stats.p95(),
            stats.p99(),
            stats.min_ms,
            stats.max_ms
        ));
    }
}

fn tool_stats_to_json(tools: &HashMap<String, MetricStats>) -> serde_json::Value {
    use serde_json::json;
    tools
        .iter()
        .map(|(name, stats)| {
            (
                name.clone(),
                json!({
                    "count": stats.count,
                    "avg_ms": stats.avg_ms(),
                    "p50_ms": stats.p50(),
                    "p95_ms": stats.p95(),
                    "p99_ms": stats.p99(),
                    "min_ms": stats.min_ms,
                    "max_ms": stats.max_ms,
                    "total_ms": stats.total_ms,
                }),
            )
        })
        .collect()
}

fn parse_stats_to_json(stats: &MetricStats) -> serde_json::Value {
    use serde_json::json;
    json!({
        "count": stats.count,
        "avg_us": stats.avg_ms(),
        "p50_us": stats.p50(),
        "p95_us": stats.p95(),
        "p99_us": stats.p99(),
        "min_us": stats.min_ms,
        "max_us": stats.max_ms,
    })
}

fn format_duration_seconds(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, secs)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

fn format_unix_timestamp(seconds: u64) -> String {
    use chrono::DateTime;
    DateTime::from_timestamp(seconds as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("{}", seconds))
}

/// Spawn a background task that flushes lifetime counters to disk every
/// `interval`. The task exits when the metrics shutdown notifier fires (and
/// performs one last flush before returning).
pub fn spawn_flush_task(metrics: Arc<Metrics>, interval: Duration) -> tokio::task::JoinHandle<()> {
    let notify = metrics.shutdown_notifier();
    tokio::spawn(async move {
        if !metrics.is_persistent() {
            debug!("Metrics flush task: persistence disabled, exiting");
            return;
        }
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Discard the immediate first tick — we just loaded; nothing to write.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if metrics.take_dirty() {
                        if let Err(e) = metrics.flush() {
                            warn!("Periodic metrics flush failed: {}", e);
                        }
                    }
                }
                _ = notify.notified() => {
                    debug!("Metrics flush task received shutdown signal");
                    if let Err(e) = metrics.flush() {
                        warn!("Final metrics flush on shutdown failed: {}", e);
                    }
                    break;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use tempfile::TempDir;

    #[test]
    fn test_metric_stats_basic() {
        let mut stats = MetricStats::new();
        assert_eq!(stats.count, 0);
        assert_eq!(stats.avg_ms(), 0.0);

        stats.record(100);
        assert_eq!(stats.count, 1);
        assert_eq!(stats.avg_ms(), 100.0);
        assert_eq!(stats.min_ms, 100);
        assert_eq!(stats.max_ms, 100);
    }

    #[test]
    fn test_metric_stats_percentiles() {
        let mut stats = MetricStats::new();
        for i in 1..=100 {
            stats.record(i);
        }
        assert_eq!(stats.count, 100);
        assert_eq!(stats.avg_ms(), 50.5);
        // HDR histogram is approximate; allow a small bucket-rounding window.
        let p50 = stats.p50();
        let p95 = stats.p95();
        let p99 = stats.p99();
        assert!(
            (49..=51).contains(&p50),
            "p50 was {}, expected near 50",
            p50
        );
        assert!(
            (94..=96).contains(&p95),
            "p95 was {}, expected near 95",
            p95
        );
        assert!(
            (98..=100).contains(&p99),
            "p99 was {}, expected near 99",
            p99
        );
    }

    #[test]
    fn test_metrics_tool_recording() {
        let metrics = Metrics::new();
        metrics.record_tool("list_repos", Duration::from_millis(50));
        metrics.record_tool("list_repos", Duration::from_millis(100));
        metrics.record_tool("find_symbols", Duration::from_millis(200));

        let stats = metrics.get_tool_stats("list_repos").unwrap();
        assert_eq!(stats.count, 2);
        assert_eq!(stats.avg_ms(), 75.0);
        assert_eq!(stats.min_ms, 50);
        assert_eq!(stats.max_ms, 100);

        let stats = metrics.get_tool_stats("find_symbols").unwrap();
        assert_eq!(stats.count, 1);
        assert_eq!(stats.avg_ms(), 200.0);
        assert_eq!(metrics.total_requests(), 3);
    }

    #[test]
    fn test_metrics_repo_indexing() {
        let metrics = Metrics::new();
        metrics.record_repo_index(
            "test-repo".to_string(),
            Duration::from_millis(5000),
            100,
            500,
        );
        let repo_metrics = metrics.get_repo_index_metrics();
        assert_eq!(repo_metrics.len(), 1);
        assert_eq!(repo_metrics[0].repo_name, "test-repo");
        assert_eq!(repo_metrics[0].index_time_ms, 5000);
        assert_eq!(repo_metrics[0].file_count, 100);
        assert_eq!(repo_metrics[0].symbol_count, 500);
    }

    #[test]
    fn test_metrics_file_parsing() {
        let metrics = Metrics::new();
        metrics.record_file_parse(Duration::from_micros(100));
        metrics.record_file_parse(Duration::from_micros(200));
        metrics.record_file_parse(Duration::from_micros(150));
        let parse_stats = metrics.get_file_parse_stats();
        assert_eq!(parse_stats.count, 3);
        assert_eq!(parse_stats.avg_ms(), 150.0);
        assert_eq!(parse_stats.min_ms, 100);
        assert_eq!(parse_stats.max_ms, 200);
    }

    #[test]
    fn test_uptime() {
        let metrics = Metrics::new();
        thread::sleep(Duration::from_millis(100));
        let uptime = metrics.uptime_seconds();
        assert!(uptime < 10, "Uptime should be reasonable for a test");
        let uptime_str = metrics.uptime_string();
        assert!(uptime_str.contains('s'));
    }

    #[test]
    fn test_metrics_report() {
        let metrics = Metrics::new();
        metrics.record_tool("test_tool", Duration::from_millis(100));
        metrics.record_repo_index("test-repo".to_string(), Duration::from_secs(1), 50, 250);
        let report = metrics.report();
        assert!(report.contains("Performance Metrics"));
        assert!(report.contains("test_tool"));
        assert!(report.contains("test-repo"));
        assert!(report.contains("Lifetime"));
    }

    #[test]
    fn test_metrics_json_report() {
        let metrics = Metrics::new();
        metrics.record_tool("test_tool", Duration::from_millis(100));
        metrics.record_file_parse(Duration::from_micros(500));
        let json = metrics.report_json();
        assert!(json["session"]["total_requests"].as_u64().unwrap() > 0);
        assert!(
            json["session"]["tools"]["test_tool"]["count"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert!(json["session"]["file_parsing"]["count"].as_u64().unwrap() > 0);
        assert!(
            json["lifetime"]["tools"]["test_tool"]["count"]
                .as_u64()
                .unwrap()
                > 0
        );
    }

    #[test]
    fn test_empty_percentiles() {
        let stats = MetricStats::new();
        assert_eq!(stats.p50(), 0);
        assert_eq!(stats.p95(), 0);
        assert_eq!(stats.p99(), 0);
    }

    #[test]
    fn test_single_value_percentiles() {
        let mut stats = MetricStats::new();
        stats.record(42);
        assert_eq!(stats.p50(), 42);
        assert_eq!(stats.p95(), 42);
        assert_eq!(stats.p99(), 42);
    }

    #[test]
    fn test_persistence_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("metrics.bin");

        {
            let metrics = Metrics::with_persistence(path.clone());
            for _ in 0..10 {
                metrics.record_tool("alpha", Duration::from_millis(50));
            }
            metrics.record_file_parse(Duration::from_micros(120));
            metrics.flush().unwrap();
        }

        let metrics = Metrics::with_persistence(path.clone());
        let tools = metrics.get_lifetime_tool_stats();
        let alpha = tools.get("alpha").expect("alpha tool should be loaded");
        assert_eq!(alpha.count, 10);
        assert_eq!(alpha.min_ms, 50);
        assert_eq!(alpha.max_ms, 50);

        let parse = metrics.get_lifetime_file_parse_stats();
        assert_eq!(parse.count, 1);
        assert_eq!(parse.min_ms, 120);
    }

    #[test]
    fn test_persistence_accumulates_across_instances() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("metrics.bin");

        {
            let m = Metrics::with_persistence(path.clone());
            m.record_tool("alpha", Duration::from_millis(10));
            m.record_tool("alpha", Duration::from_millis(20));
            m.flush().unwrap();
        }
        {
            let m = Metrics::with_persistence(path.clone());
            // Session view is empty; lifetime view has the prior 2 records.
            assert_eq!(m.total_requests(), 0);
            assert_eq!(m.lifetime_total_requests(), 2);
            m.record_tool("alpha", Duration::from_millis(30));
            m.flush().unwrap();
            assert_eq!(m.lifetime_total_requests(), 3);
        }
        {
            let m = Metrics::with_persistence(path.clone());
            let tools = m.get_lifetime_tool_stats();
            let alpha = tools.get("alpha").unwrap();
            assert_eq!(alpha.count, 3);
            assert_eq!(alpha.min_ms, 10);
            assert_eq!(alpha.max_ms, 30);
            assert_eq!(alpha.total_ms, 60);
        }
    }

    #[test]
    fn test_persistence_missing_file_starts_fresh() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.bin");
        let m = Metrics::with_persistence(path);
        assert_eq!(m.lifetime_total_requests(), 0);
        assert!(m.first_started_at() > 0);
    }

    #[test]
    fn test_persistence_corrupt_file_starts_fresh() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("corrupt.bin");
        std::fs::write(&path, b"not a valid postcard payload").unwrap();
        let m = Metrics::with_persistence(path);
        assert_eq!(m.lifetime_total_requests(), 0);
    }

    #[test]
    fn test_dirty_flag_lifecycle() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("metrics.bin");
        let m = Metrics::with_persistence(path);
        assert!(!m.take_dirty(), "fresh instance is clean");
        m.record_tool("alpha", Duration::from_millis(1));
        assert!(m.take_dirty(), "record_tool marks dirty");
        assert!(!m.take_dirty(), "take_dirty clears the flag");
    }

    #[test]
    fn test_in_memory_metrics_not_persistent() {
        let m = Metrics::new();
        assert!(!m.is_persistent());
        // Calling flush() on a non-persistent Metrics should be a no-op success.
        m.flush().unwrap();
    }
}
