//! Performance metrics tracking for tool operations.
//!
//! Counters are stored ccache-style in a global per-`index_path` file under
//! `~/.cache/narsil-mcp/stats/<hash>.bin`. The same file is shared by every
//! narsil-mcp instance that uses the same `--index-path`; concurrent writers
//! coordinate via an advisory file lock and a delta-based merge so that no
//! instance's contribution is clobbered.
//!
//! Each process keeps three views:
//!   - **session**: counters since process start (reset on every restart).
//!   - **baseline**: shared state loaded from disk; refreshed at every flush.
//!   - **delta**: counters accumulated since the last successful flush.
//!
//! The displayed *lifetime* view is `baseline + delta`. On flush we re-read
//! the shared file (it may have advanced because of other processes), merge
//! our delta in, write atomically, and reset `baseline = merged` / `delta = 0`.

use anyhow::{Context, Result};
use directories::ProjectDirs;
use fs4::fs_std::FileExt;
use hdrhistogram::serialization::{Deserializer, Serializer, V2Serializer};
use hdrhistogram::Histogram;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
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

/// Length of the hex-encoded SHA-256 prefix used as the on-disk filename.
const PATH_HASH_LEN: usize = 16;

// ---------- MetricStats ------------------------------------------------------

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

    /// Merge another stats stream into this one.
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
        let mut histogram = deserializer
            .deserialize::<u64, _>(&mut p.histogram_bytes.as_slice())
            .context("Failed to deserialise HDR histogram")?;
        // V2Deserializer doesn't preserve the auto-resize flag, but we always
        // want it on so future merges can grow the histogram if a process
        // contributes values above the previously-seen range.
        histogram.auto(true);
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

// ---------- Persistence types -----------------------------------------------

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
pub struct PersistedMetrics {
    pub version: u32,
    /// Canonical filesystem path of the index this stats file describes —
    /// kept readable for `narsil-mcp stats --list` output.
    pub index_path: String,
    /// Unix seconds when this metrics file was first created.
    pub first_started_at: u64,
    /// Unix seconds when the snapshot was last written.
    pub saved_at: u64,
    /// Cumulative server uptime across all runs that share this file, in seconds.
    pub total_uptime_seconds: u64,
    tools: HashMap<String, PersistedCounter>,
    file_parse: PersistedCounter,
}

impl PersistedMetrics {
    const CURRENT_VERSION: u32 = 1;

    fn empty(index_path: String) -> Self {
        let now = now_unix_seconds();
        Self {
            version: Self::CURRENT_VERSION,
            index_path,
            first_started_at: now,
            saved_at: now,
            total_uptime_seconds: 0,
            tools: HashMap::new(),
            file_parse: empty_persisted_counter(),
        }
    }

    /// Read and decode a stats file. Returns an error for any failure
    /// (missing file, bad version, deserialisation failure).
    pub fn load(path: &Path) -> Result<Self> {
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
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create stats directory")?;
        }
        let data = postcard::to_stdvec(self).context("Failed to serialise metrics")?;
        let temp_path = path.with_extension("tmp");
        std::fs::write(&temp_path, &data).context("Failed to write temp metrics file")?;
        std::fs::rename(&temp_path, path).context("Failed to rename metrics file into place")?;
        Ok(())
    }

    /// Total recorded requests across all tools in this snapshot.
    pub fn total_requests(&self) -> u64 {
        self.tools.values().map(|t| t.count).sum()
    }
}

fn empty_persisted_counter() -> PersistedCounter {
    MetricStats::new()
        .to_persisted()
        .expect("empty histogram always serialises")
}

// ---------- Path resolution --------------------------------------------------

/// Hex-encoded SHA-256 prefix of a canonical filesystem path. Used as the
/// filename for the per-`index_path` stats file. Stable across runs and OS-
/// safe.
pub fn index_path_hash(canonical_path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_path.as_os_str().to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    hex[..PATH_HASH_LEN].to_string()
}

/// Directory holding all per-`index_path` stats files. Created on demand.
pub fn global_stats_dir() -> PathBuf {
    if let Some(dirs) = ProjectDirs::from("", "", "narsil-mcp") {
        dirs.cache_dir().join("stats")
    } else {
        // Fallback: $HOME/.cache/narsil-mcp/stats. ProjectDirs only fails when
        // the platform has no notion of a home directory, which is rare.
        PathBuf::from("/tmp/narsil-mcp/stats")
    }
}

/// Resolve the stats file path for a given index_path. The directory is
/// created if it doesn't yet exist.
pub fn stats_file_for(index_path: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(index_path).unwrap_or_else(|_| index_path.to_path_buf());
    let hash = index_path_hash(&canonical);
    global_stats_dir().join(format!("{}.bin", hash))
}

/// Lock file accompanying a stats file. Holding an exclusive lock on this
/// file guards the read-merge-write cycle against concurrent writers.
fn lock_file_for(stats_path: &Path) -> PathBuf {
    stats_path.with_extension("lock")
}

fn acquire_exclusive_lock(stats_path: &Path) -> Result<File> {
    let lock_path = lock_file_for(stats_path);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create stats directory for lock")?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("Failed to open lock file at {:?}", lock_path))?;
    file.lock_exclusive()
        .context("Failed to acquire exclusive lock on stats file")?;
    Ok(file)
}

// ---------- LifetimeCounters / Metrics --------------------------------------

#[derive(Default)]
struct CounterSet {
    tools: HashMap<String, MetricStats>,
    file_parse: MetricStats,
}

impl CounterSet {
    fn record_tool(&mut self, name: &str, duration_units: u64) {
        self.tools
            .entry(name.to_string())
            .or_default()
            .record(duration_units);
    }

    fn merge_from(&mut self, other: &CounterSet) {
        for (name, stats) in &other.tools {
            self.tools
                .entry(name.clone())
                .or_default()
                .merge_from(stats);
        }
        self.file_parse.merge_from(&other.file_parse);
    }

    fn from_persisted(p: &PersistedMetrics) -> Result<Self> {
        let mut tools = HashMap::with_capacity(p.tools.len());
        for (name, pc) in &p.tools {
            tools.insert(name.clone(), MetricStats::from_persisted(pc)?);
        }
        Ok(Self {
            tools,
            file_parse: MetricStats::from_persisted(&p.file_parse)?,
        })
    }

    fn write_into_persisted(&self, target: &mut PersistedMetrics) -> Result<()> {
        let mut tools = HashMap::with_capacity(self.tools.len());
        for (name, stats) in &self.tools {
            tools.insert(name.clone(), stats.to_persisted()?);
        }
        target.tools = tools;
        target.file_parse = self.file_parse.to_persisted()?;
        Ok(())
    }
}

struct LifetimeState {
    /// Baseline = last shared state read from disk (loaded at startup, refreshed
    /// after every successful flush). Other concurrent processes' contributions
    /// land here when we re-read at flush time.
    baseline: CounterSet,
    /// Counters accumulated since the baseline was set. Merged into the shared
    /// file at flush time, then cleared.
    deltas: CounterSet,
    /// Total uptime persisted in the shared file the last time we read it.
    persisted_uptime_seconds: u64,
    /// Unix seconds of the first ever invocation that wrote to this file.
    first_started_at: u64,
    /// Canonical index path this lifetime view describes.
    index_path: String,
    /// Session seconds we've already attributed to the lifetime uptime in a
    /// previous flush; used to compute the next increment without double-counting.
    uptime_credited: u64,
}

impl LifetimeState {
    fn fresh(index_path: String) -> Self {
        Self {
            baseline: CounterSet::default(),
            deltas: CounterSet::default(),
            persisted_uptime_seconds: 0,
            first_started_at: now_unix_seconds(),
            index_path,
            uptime_credited: 0,
        }
    }

    fn from_persisted(p: PersistedMetrics) -> Result<Self> {
        Ok(Self {
            baseline: CounterSet::from_persisted(&p)?,
            deltas: CounterSet::default(),
            persisted_uptime_seconds: p.total_uptime_seconds,
            first_started_at: p.first_started_at,
            index_path: p.index_path,
            uptime_credited: 0,
        })
    }

    /// View shown to callers: baseline + pending deltas.
    fn snapshot(&self) -> CounterSet {
        let mut combined = CounterSet::default();
        combined.merge_from(&self.baseline);
        combined.merge_from(&self.deltas);
        combined
    }
}

/// Global metrics collection.
pub struct Metrics {
    start_time: Instant,
    /// Session-only counters (reset on process start).
    tool_metrics: RwLock<HashMap<String, MetricStats>>,
    repo_index_metrics: RwLock<Vec<RepoIndexMetrics>>,
    file_parse_metrics: RwLock<MetricStats>,
    /// Lifetime counters split into baseline + deltas. See module docs.
    lifetime: RwLock<LifetimeState>,
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
            lifetime: RwLock::new(LifetimeState::fresh(String::new())),
            persist_path: None,
            dirty: AtomicBool::new(false),
            flush_notify: Arc::new(Notify::new()),
        }
    }

    /// Create a Metrics instance backed by the global per-`index_path` stats
    /// file. The actual file is `~/.cache/narsil-mcp/stats/<hash>.bin`.
    pub fn with_persistence(index_path: PathBuf) -> Self {
        let stats_path = stats_file_for(&index_path);
        let canonical_str = std::fs::canonicalize(&index_path)
            .unwrap_or(index_path)
            .to_string_lossy()
            .to_string();

        let lifetime = if stats_path.exists() {
            match PersistedMetrics::load(&stats_path) {
                Ok(snapshot) => LifetimeState::from_persisted(snapshot).unwrap_or_else(|e| {
                    warn!(
                        "Stats file at {:?} parsed but decode failed: {} — starting fresh",
                        stats_path, e
                    );
                    LifetimeState::fresh(canonical_str.clone())
                }),
                Err(e) => {
                    warn!(
                        "Failed to load stats file at {:?}: {} — starting fresh",
                        stats_path, e
                    );
                    LifetimeState::fresh(canonical_str.clone())
                }
            }
        } else {
            LifetimeState::fresh(canonical_str.clone())
        };

        Self {
            start_time: Instant::now(),
            tool_metrics: RwLock::new(HashMap::new()),
            repo_index_metrics: RwLock::new(Vec::new()),
            file_parse_metrics: RwLock::new(MetricStats::new()),
            lifetime: RwLock::new(lifetime),
            persist_path: Some(stats_path),
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
        self.tool_metrics
            .write()
            .entry(tool_name.to_string())
            .or_default()
            .record(duration_ms);
        self.lifetime
            .write()
            .deltas
            .record_tool(tool_name, duration_ms);
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
        self.lifetime.write().deltas.file_parse.record(duration_us);
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

    /// Lifetime view: baseline (last loaded shared state) merged with our
    /// deltas since the last flush.
    pub fn get_lifetime_tool_stats(&self) -> HashMap<String, MetricStats> {
        self.lifetime.read().snapshot().tools
    }

    pub fn get_lifetime_file_parse_stats(&self) -> MetricStats {
        self.lifetime.read().snapshot().file_parse
    }

    /// Cumulative uptime across all runs that share this stats file.
    pub fn lifetime_uptime_seconds(&self) -> u64 {
        let state = self.lifetime.read();
        // Uncredited portion of this session's uptime — what would be added
        // on the next flush. Showing it live keeps the lifetime number from
        // appearing to "freeze" between flushes.
        let uncredited = self.uptime_seconds().saturating_sub(state.uptime_credited);
        state.persisted_uptime_seconds + uncredited
    }

    pub fn first_started_at(&self) -> u64 {
        self.lifetime.read().first_started_at
    }

    pub fn lifetime_total_requests(&self) -> u64 {
        let state = self.lifetime.read();
        let baseline: u64 = state.baseline.tools.values().map(|s| s.count).sum();
        let deltas: u64 = state.deltas.tools.values().map(|s| s.count).sum();
        baseline + deltas
    }

    fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Ordering::Relaxed)
    }

    /// Force-write lifetime counters to disk. Re-reads the shared file under
    /// an exclusive lock so concurrent writers' contributions are preserved.
    pub fn flush(&self) -> Result<()> {
        let Some(path) = self.persist_path.as_ref() else {
            return Ok(());
        };

        // Lock first — everything between here and unlock is the critical
        // section. The lock is held across the read-merge-write cycle so two
        // processes can't both read-then-overwrite the same shared state.
        let _lock = acquire_exclusive_lock(path)?;

        // Re-read what's on disk *now* (may have advanced past our baseline
        // because of other concurrent processes).
        let mut current = if path.exists() {
            match PersistedMetrics::load(path) {
                Ok(snapshot) => snapshot,
                Err(e) => {
                    warn!(
                        "Stats file at {:?} unreadable during flush ({}); rewriting from scratch",
                        path, e
                    );
                    PersistedMetrics::empty(self.lifetime.read().index_path.clone())
                }
            }
        } else {
            PersistedMetrics::empty(self.lifetime.read().index_path.clone())
        };

        // Decode current shared state, merge our deltas into it.
        let mut merged = CounterSet::from_persisted(&current).unwrap_or_default();
        {
            let state = self.lifetime.read();
            merged.merge_from(&state.deltas);
        }

        // Compute uptime delta to add to the shared total.
        let session_uptime = self.uptime_seconds();
        let uptime_delta = {
            let state = self.lifetime.read();
            session_uptime.saturating_sub(state.uptime_credited)
        };

        // Write merged counters into the persisted struct.
        merged.write_into_persisted(&mut current)?;
        current.saved_at = now_unix_seconds();
        current.total_uptime_seconds = current.total_uptime_seconds.saturating_add(uptime_delta);
        // Preserve the earliest first_started_at across concurrent writers.
        {
            let state = self.lifetime.read();
            if state.first_started_at != 0 && state.first_started_at < current.first_started_at {
                current.first_started_at = state.first_started_at;
            }
            current.index_path = state.index_path.clone();
        }

        current.save(path)?;

        // Update our local baseline to match what we just wrote; clear deltas
        // and bump the uptime-credited bookkeeping.
        {
            let mut state = self.lifetime.write();
            state.baseline = merged;
            state.deltas = CounterSet::default();
            state.persisted_uptime_seconds = current.total_uptime_seconds;
            state.uptime_credited = session_uptime;
            state.first_started_at = current.first_started_at;
        }

        debug!("Flushed metrics to {:?}", path);
        // `_lock` is dropped here, releasing the advisory lock.
        Ok(())
    }

    pub fn is_persistent(&self) -> bool {
        self.persist_path.is_some()
    }

    pub fn persist_path(&self) -> Option<&Path> {
        self.persist_path.as_deref()
    }

    pub fn shutdown_notifier(&self) -> Arc<Notify> {
        self.flush_notify.clone()
    }

    pub fn notify_shutdown(&self) {
        self.flush_notify.notify_waiters();
    }

    /// Generate a formatted Markdown metrics report.
    pub fn report(&self) -> String {
        let mut output = String::new();
        let lifetime_snapshot = self.lifetime.read().snapshot();
        let index_path = self.lifetime.read().index_path.clone();

        output.push_str("# Performance Metrics\n\n");
        if !index_path.is_empty() {
            output.push_str(&format!("**Index path**: {}\n", index_path));
        }
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

        let session_parse = self.get_file_parse_stats();
        let lifetime_parse = &lifetime_snapshot.file_parse;
        if session_parse.count > 0 || lifetime_parse.count > 0 {
            output.push_str("## File Parsing\n\n");
            let mut parse_rows: Vec<(&str, &MetricStats)> = Vec::new();
            if session_parse.count > 0 {
                parse_rows.push(("Session", &session_parse));
            }
            if lifetime_parse.count > 0 {
                parse_rows.push(("Lifetime", lifetime_parse));
            }
            push_parse_table(&mut output, &parse_rows);
        }

        let lifetime_tools = &lifetime_snapshot.tools;
        let session_tools = self.get_all_tool_stats();

        output.push_str("## Tool Execution Times (Lifetime)\n\n");
        if !lifetime_tools.is_empty() {
            push_tool_table(&mut output, lifetime_tools);
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

        let lifetime_snapshot = self.lifetime.read().snapshot();
        let session_tools_json = tool_stats_to_json(&self.get_all_tool_stats());
        let lifetime_tools_json = tool_stats_to_json(&lifetime_snapshot.tools);

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

        json!({
            "session": {
                "uptime_seconds": self.uptime_seconds(),
                "uptime_string": self.uptime_string(),
                "total_requests": self.total_requests(),
                "file_parsing": parse_stats_to_json(&self.get_file_parse_stats()),
                "tools": session_tools_json,
            },
            "lifetime": {
                "index_path": self.lifetime.read().index_path,
                "first_started_at": self.first_started_at(),
                "uptime_seconds": self.lifetime_uptime_seconds(),
                "uptime_string": format_duration_seconds(self.lifetime_uptime_seconds()),
                "total_requests": self.lifetime_total_requests(),
                "file_parsing": parse_stats_to_json(&lifetime_snapshot.file_parse),
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

// ---------- Helpers / rendering ---------------------------------------------

fn push_md_row<'a>(output: &mut String, cells: impl Iterator<Item = &'a str>, widths: &[usize]) {
    output.push('|');
    for (cell, w) in cells.zip(widths.iter()) {
        output.push_str(&format!(" {:<width$} |", cell, width = w));
    }
    output.push('\n');
}

fn push_md_sep(output: &mut String, widths: &[usize]) {
    output.push('|');
    for w in widths {
        output.push_str(&"-".repeat(w + 2));
        output.push('|');
    }
    output.push('\n');
}

fn push_parse_table(output: &mut String, rows: &[(&str, &MetricStats)]) {
    let headers = ["Scope", "Files Parsed", "Avg", "Min", "Max"];
    let data: Vec<[String; 5]> = rows
        .iter()
        .map(|(scope, stats)| {
            [
                scope.to_string(),
                stats.count.to_string(),
                format!("{:.2}µs", stats.avg_ms()),
                format!("{}µs", stats.min_ms),
                format!("{}µs", stats.max_ms),
            ]
        })
        .collect();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &data {
        for (col, cell) in row.iter().enumerate() {
            widths[col] = widths[col].max(cell.len());
        }
    }
    push_md_row(output, headers.iter().copied(), &widths);
    push_md_sep(output, &widths);
    for row in &data {
        push_md_row(output, row.iter().map(|s| s.as_str()), &widths);
    }
    output.push('\n');
}

fn push_tool_table(output: &mut String, tools: &HashMap<String, MetricStats>) {
    let headers = ["Tool", "Calls", "Avg (ms)", "Min (ms)", "Max (ms)"];
    let mut sorted: Vec<_> = tools.iter().collect();
    sorted.sort_by_key(|(name, _)| name.as_str().to_owned());
    let data: Vec<[String; 5]> = sorted
        .iter()
        .map(|(name, stats)| {
            [
                name.to_string(),
                stats.count.to_string(),
                format!("{:.2}", stats.avg_ms()),
                stats.min_ms.to_string(),
                stats.max_ms.to_string(),
            ]
        })
        .collect();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &data {
        for (col, cell) in row.iter().enumerate() {
            widths[col] = widths[col].max(cell.len());
        }
    }
    push_md_row(output, headers.iter().copied(), &widths);
    push_md_sep(output, &widths);
    for row in &data {
        push_md_row(output, row.iter().map(|s| s.as_str()), &widths);
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

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------- CLI helpers ------------------------------------------------------

/// List every per-`index_path` stats file under the global stats directory.
/// Returns an empty vec if the dir doesn't exist yet.
pub fn list_stats_files() -> Result<Vec<PathBuf>> {
    let dir = global_stats_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .with_context(|| format!("Failed to read stats directory {:?}", dir))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("bin") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Aggregate counters across many persisted snapshots and render them as a
/// markdown report. Used by `narsil-mcp stats`.
pub fn render_aggregate_markdown(snapshots: &[PersistedMetrics]) -> Result<String> {
    let mut merged = CounterSet::default();
    let mut total_uptime: u64 = 0;
    let mut earliest = u64::MAX;
    let mut latest = 0u64;
    let mut total_requests: u64 = 0;
    for snap in snapshots {
        let set = CounterSet::from_persisted(snap)?;
        merged.merge_from(&set);
        total_uptime = total_uptime.saturating_add(snap.total_uptime_seconds);
        earliest = earliest.min(snap.first_started_at);
        latest = latest.max(snap.saved_at);
        total_requests = total_requests.saturating_add(snap.total_requests());
    }
    if snapshots.is_empty() {
        earliest = 0;
    }

    let mut output = String::new();
    output.push_str("# narsil-mcp Lifetime Stats\n\n");
    output.push_str(&format!("**Index paths covered**: {}\n", snapshots.len()));
    output.push_str(&format!("**Total Requests**: {}\n", total_requests));
    output.push_str(&format!(
        "**Total Uptime**: {}\n",
        format_duration_seconds(total_uptime)
    ));
    if !snapshots.is_empty() {
        output.push_str(&format!(
            "**Tracking Since**: {}\n",
            format_unix_timestamp(earliest)
        ));
        output.push_str(&format!(
            "**Last Update**: {}\n\n",
            format_unix_timestamp(latest)
        ));
    } else {
        output.push('\n');
    }

    if merged.file_parse.count > 0 {
        output.push_str("## File Parsing\n\n");
        output.push_str("| Files Parsed | Avg | Min | Max | P50 | P95 | P99 |\n");
        output.push_str("|--------------|-----|-----|-----|-----|-----|-----|\n");
        let stats = &merged.file_parse;
        output.push_str(&format!(
            "| {} | {:.2}µs | {}µs | {}µs | {}µs | {}µs | {}µs |\n\n",
            stats.count,
            stats.avg_ms(),
            stats.min_ms,
            stats.max_ms,
            stats.p50(),
            stats.p95(),
            stats.p99()
        ));
    }

    output.push_str("## Tool Execution Times\n\n");
    if merged.tools.is_empty() {
        output.push_str("*No tool calls recorded.*\n");
    } else {
        push_tool_table(&mut output, &merged.tools);
    }

    Ok(output)
}

/// One-row-per-stats-file summary for `narsil-mcp stats --list`.
pub fn render_list_markdown(snapshots: &[(PathBuf, PersistedMetrics)]) -> String {
    let mut output = String::new();
    output.push_str("# narsil-mcp Stats Files\n\n");
    if snapshots.is_empty() {
        output.push_str("*No stats files found.*\n");
        return output;
    }
    output.push_str("| Index Path | Requests | Tracking Since | Last Update | Total Uptime |\n");
    output.push_str("|------------|----------|----------------|-------------|--------------|\n");
    for (_path, snap) in snapshots {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            snap.index_path,
            snap.total_requests(),
            format_unix_timestamp(snap.first_started_at),
            format_unix_timestamp(snap.saved_at),
            format_duration_seconds(snap.total_uptime_seconds)
        ));
    }
    output
}

/// Render the aggregate as JSON for scripts.
pub fn render_aggregate_json(snapshots: &[PersistedMetrics]) -> Result<serde_json::Value> {
    use serde_json::json;
    let mut merged = CounterSet::default();
    let mut total_uptime: u64 = 0;
    let mut earliest = u64::MAX;
    let mut latest = 0u64;
    let mut total_requests: u64 = 0;
    for snap in snapshots {
        let set = CounterSet::from_persisted(snap)?;
        merged.merge_from(&set);
        total_uptime = total_uptime.saturating_add(snap.total_uptime_seconds);
        earliest = earliest.min(snap.first_started_at);
        latest = latest.max(snap.saved_at);
        total_requests = total_requests.saturating_add(snap.total_requests());
    }
    if snapshots.is_empty() {
        earliest = 0;
    }
    Ok(json!({
        "index_paths_covered": snapshots.len(),
        "total_requests": total_requests,
        "total_uptime_seconds": total_uptime,
        "first_started_at": earliest,
        "last_update_at": latest,
        "file_parsing": parse_stats_to_json(&merged.file_parse),
        "tools": tool_stats_to_json(&merged.tools),
    }))
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

    // Override the global stats dir for tests so we don't touch the real
    // ~/.cache/narsil-mcp. We do this by giving each test a temp directory
    // and feeding it as the `index_path` — the stats file lands under the
    // global cache regardless, but with a unique hash it won't collide.
    // For tests that need exact path control we use Metrics with
    // `persist_path` set directly via the helper below.

    fn make_persisted_metrics(path: PathBuf) -> Metrics {
        // Build a Metrics that writes to a known path (bypassing the global
        // cache dir resolution) so tests can isolate their files.
        let mut m = Metrics::new();
        m.persist_path = Some(path);
        m.lifetime.write().index_path = "test/path".to_string();
        m
    }

    #[test]
    fn test_metric_stats_basic() {
        let mut stats = MetricStats::new();
        assert_eq!(stats.count, 0);
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
        let p50 = stats.p50();
        let p95 = stats.p95();
        let p99 = stats.p99();
        assert!((49..=51).contains(&p50), "p50 was {}", p50);
        assert!((94..=96).contains(&p95), "p95 was {}", p95);
        assert!((98..=100).contains(&p99), "p99 was {}", p99);
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
        assert_eq!(metrics.total_requests(), 3);
    }

    #[test]
    fn test_index_path_hash_stable() {
        let path = Path::new("/home/foo/.cache/narsil-mcp");
        let a = index_path_hash(path);
        let b = index_path_hash(path);
        assert_eq!(a, b);
        assert_eq!(a.len(), PATH_HASH_LEN);
        let other = index_path_hash(Path::new("/home/foo/.cache/narsil-other"));
        assert_ne!(a, other);
    }

    #[test]
    fn test_persistence_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("metrics.bin");

        {
            let metrics = make_persisted_metrics(path.clone());
            for _ in 0..10 {
                metrics.record_tool("alpha", Duration::from_millis(50));
            }
            metrics.record_file_parse(Duration::from_micros(120));
            metrics.flush().unwrap();
        }

        let metrics = make_persisted_metrics(path.clone());
        let snap = PersistedMetrics::load(&path).unwrap();
        // Adopt the loaded snapshot into the freshly-built Metrics so the
        // assertions exercise the post-startup baseline path.
        *metrics.lifetime.write() = LifetimeState::from_persisted(snap).unwrap();

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
    fn test_concurrent_writers_accumulate_without_loss() {
        // Two Metrics instances sharing the same file — both flush in turn,
        // each preserving the other's contributions.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("shared.bin");

        let m1 = make_persisted_metrics(path.clone());
        let m2 = make_persisted_metrics(path.clone());

        m1.record_tool("alpha", Duration::from_millis(10));
        m1.record_tool("alpha", Duration::from_millis(20));
        m1.flush().unwrap();

        m2.record_tool("alpha", Duration::from_millis(30));
        m2.record_tool("beta", Duration::from_millis(5));
        m2.flush().unwrap();

        // After m2 flushed, the shared file should contain m1's + m2's data.
        m1.flush().unwrap(); // re-read the shared file
        let tools = m1.get_lifetime_tool_stats();
        assert_eq!(tools.get("alpha").unwrap().count, 3, "alpha = 2 + 1");
        assert_eq!(
            tools.get("alpha").unwrap().total_ms,
            10 + 20 + 30,
            "alpha total"
        );
        assert_eq!(tools.get("beta").unwrap().count, 1);
        assert_eq!(tools.get("beta").unwrap().min_ms, 5);
    }

    #[test]
    fn test_flush_reread_picks_up_other_writers() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("shared.bin");

        let m1 = make_persisted_metrics(path.clone());
        let m2 = make_persisted_metrics(path.clone());

        // m2 writes first.
        m2.record_tool("alpha", Duration::from_millis(100));
        m2.flush().unwrap();

        // m1 records, flushes — should preserve m2's contribution.
        m1.record_tool("alpha", Duration::from_millis(50));
        m1.flush().unwrap();

        let snap = PersistedMetrics::load(&path).unwrap();
        assert_eq!(snap.tools.get("alpha").unwrap().count, 2);
        assert_eq!(snap.tools.get("alpha").unwrap().total_ms, 150);
    }

    #[test]
    fn test_persistence_corrupt_file_starts_fresh() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("corrupt.bin");
        std::fs::write(&path, b"not a valid postcard payload").unwrap();
        // Corrupt content is treated as "no baseline" by from_persisted; the
        // flush should overwrite it cleanly.
        let m = make_persisted_metrics(path.clone());
        m.record_tool("alpha", Duration::from_millis(1));
        m.flush().unwrap();
        let snap = PersistedMetrics::load(&path).unwrap();
        assert_eq!(snap.tools.get("alpha").unwrap().count, 1);
    }

    #[test]
    fn test_dirty_flag_lifecycle() {
        let m = Metrics::new();
        assert!(!m.take_dirty(), "fresh instance is clean");
        m.record_tool("alpha", Duration::from_millis(1));
        assert!(m.take_dirty(), "record_tool marks dirty");
        assert!(!m.take_dirty(), "take_dirty clears the flag");
    }

    #[test]
    fn test_in_memory_metrics_not_persistent() {
        let m = Metrics::new();
        assert!(!m.is_persistent());
        m.flush().unwrap();
    }

    #[test]
    fn test_render_aggregate_markdown_empty() {
        let out = render_aggregate_markdown(&[]).unwrap();
        assert!(out.contains("narsil-mcp Lifetime Stats"));
        assert!(out.contains("No tool calls recorded"));
    }

    #[test]
    fn test_render_aggregate_markdown_merges_multiple() {
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("a.bin");
        let b = dir.path().join("b.bin");

        let m1 = make_persisted_metrics(a.clone());
        m1.lifetime.write().index_path = "/path/a".to_string();
        m1.record_tool("alpha", Duration::from_millis(10));
        m1.flush().unwrap();

        let m2 = make_persisted_metrics(b.clone());
        m2.lifetime.write().index_path = "/path/b".to_string();
        m2.record_tool("alpha", Duration::from_millis(20));
        m2.record_tool("beta", Duration::from_millis(7));
        m2.flush().unwrap();

        let snaps = vec![
            PersistedMetrics::load(&a).unwrap(),
            PersistedMetrics::load(&b).unwrap(),
        ];
        let out = render_aggregate_markdown(&snaps).unwrap();
        assert!(out.contains("Total Requests**: 3"));
        assert!(out.contains("alpha"));
        assert!(out.contains("beta"));
    }

    #[test]
    fn test_render_list_markdown() {
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("a.bin");
        let m1 = make_persisted_metrics(a.clone());
        m1.lifetime.write().index_path = "/proj/foo".to_string();
        m1.record_tool("alpha", Duration::from_millis(10));
        m1.flush().unwrap();
        let snaps = vec![(a.clone(), PersistedMetrics::load(&a).unwrap())];
        let out = render_list_markdown(&snaps);
        assert!(out.contains("/proj/foo"));
        assert!(out.contains("| 1 |")); // request count
    }

    #[test]
    fn test_uptime_format() {
        assert_eq!(format_duration_seconds(0), "0s");
        assert_eq!(format_duration_seconds(75), "1m 15s");
        assert_eq!(format_duration_seconds(3661), "1h 1m 1s");
        assert_eq!(format_duration_seconds(90_061), "1d 1h 1m 1s");
    }

    #[test]
    fn test_uptime_seconds_grows() {
        let metrics = Metrics::new();
        thread::sleep(Duration::from_millis(100));
        assert!(metrics.uptime_seconds() < 10);
    }
}
