//! Auto-discovery of running SSE narsil-mcp servers.
//!
//! When an editor spawns narsil-mcp in stdio mode and another long-running
//! SSE narsil-mcp already covers the requested repositories, the stdio
//! process delegates to it instead of building a duplicate index. This
//! module owns the on-disk registry that lets stdio find SSE.
//!
//! The registry is a JSON array of [`SseServerRecord`] under either
//! `$XDG_RUNTIME_DIR/narsil-mcp/servers.json` (Linux, tmpfs, per-user) or
//! `<cache_dir>/narsil-mcp/servers.json` (macOS / unset XDG). The
//! directory is chmod'd to `0700` on Unix so other users on a shared host
//! cannot read URLs or repo paths.
//!
//! Liveness is checked solely by sending an MCP `ping` POST to each
//! candidate's URL. PID-based checks were considered and rejected — they
//! add OS-specific code while the HTTP probe is authoritative (a localhost
//! connection refused is microseconds, same order as `kill(pid, 0)`).
//!
//! Reads that prune stale entries hold an advisory exclusive lock on the
//! discovery file so two concurrent stdio starts cannot corrupt it.

use anyhow::{Context, Result};
use fs4::fs_std::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, info, warn};

/// On-disk record of a running SSE narsil-mcp.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SseServerRecord {
    /// Base URL with no trailing slash, e.g. `http://127.0.0.1:7557`.
    pub url: String,
    /// Canonical absolute paths of repositories the server indexes.
    pub repos: Vec<PathBuf>,
}

/// RAII guard that removes this process's entry from the discovery file
/// when dropped. The entry is identified by URL — while a server is alive
/// it holds the listen socket for its URL, so no other process on the same
/// host can register the same URL concurrently.
pub struct DiscoveryEntry {
    path: PathBuf,
    url: String,
}

impl DiscoveryEntry {
    /// Path of the file this entry was written to. Exposed for tests.
    pub fn file_path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DiscoveryEntry {
    fn drop(&mut self) {
        match remove_entry(&self.path, &self.url) {
            Ok(()) => info!("SSE discovery: removed entry url={}", self.url),
            Err(e) => warn!(
                "SSE discovery: failed to remove entry url={}: {}",
                self.url, e
            ),
        }
    }
}

/// Resolve the path of the discovery registry file.
///
/// Linux/BSD: `$XDG_RUNTIME_DIR/narsil-mcp/servers.json` when XDG is set
/// to an absolute path (tmpfs, per-user, cleaned on logout).
///
/// Fallback (macOS, Windows, or unset XDG): the user's cache directory
/// joined with `narsil-mcp/servers.json`. Both locations are already
/// user-scoped — no shared `/tmp` involved.
pub fn discovery_file_path() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(dir);
        if dir.is_absolute() {
            return Ok(dir.join("narsil-mcp").join("servers.json"));
        }
    }
    let base = directories::BaseDirs::new()
        .context("Cannot determine a per-user cache directory for the SSE discovery file")?;
    Ok(base.cache_dir().join("narsil-mcp").join("servers.json"))
}

/// Write (or refresh) a record for the SSE server running on `url`.
/// Returns a guard that removes the entry on drop. The parent directory
/// is created if missing and chmod'd to `0700` on Unix.
pub fn register_server(url: &str, repos: &[PathBuf]) -> Result<DiscoveryEntry> {
    let path = discovery_file_path()?;
    register_at(&path, url, repos)
}

/// Same as [`register_server`] but writes to an explicit path; used by
/// tests to avoid touching the real per-user registry.
pub fn register_at(path: &Path, url: &str, repos: &[PathBuf]) -> Result<DiscoveryEntry> {
    ensure_parent_dir(path)?;
    let normalized = url.trim_end_matches('/').to_string();
    let record = SseServerRecord {
        url: normalized.clone(),
        repos: repos.to_vec(),
    };

    {
        let mut file = open_locked(path)?;
        let mut records = read_records(&mut file).unwrap_or_default();
        // Replace any prior record with the same URL — that record's
        // owner can no longer be alive, since we just bound the socket.
        records.retain(|r| r.url != normalized);
        records.push(record);
        atomic_write(path, &records)?;
    }
    info!(
        "SSE discovery: registered url={} repos={} → {}",
        normalized,
        repos.len(),
        path.display()
    );

    Ok(DiscoveryEntry {
        path: path.to_path_buf(),
        url: normalized,
    })
}

/// Return the base URL of the first record whose repo list is a superset
/// of `repos` AND which answers an MCP `ping` POST. Removes records that
/// fail the probe with a transport-level error as a side effect.
pub fn find_server_for_repos(repos: &[PathBuf]) -> Option<String> {
    let path = discovery_file_path().ok()?;
    find_at(&path, repos)
}

/// Same as [`find_server_for_repos`] but reads from an explicit path;
/// used by tests.
pub fn find_at(path: &Path, repos: &[PathBuf]) -> Option<String> {
    info!("SSE discovery: checking {}", path.display());
    if !path.exists() {
        info!("SSE discovery: no registry file yet");
        return None;
    }

    let mut file = open_locked(path).ok()?;
    let records = read_records(&mut file).unwrap_or_default();

    let mut surviving: Vec<SseServerRecord> = Vec::with_capacity(records.len());
    let mut matched: Option<String> = None;

    for record in records {
        debug!(
            "SSE discovery: candidate url={} repos={:?}",
            record.url, record.repos
        );

        if matched.is_some() {
            // Already picked a winner — keep this record but do not probe.
            surviving.push(record);
            continue;
        }

        match superset_check(&record.repos, repos) {
            Ok(()) => debug!("SSE discovery: repo superset check: match"),
            Err(missing) => {
                debug!(
                    "SSE discovery: repo superset check: miss (missing {})",
                    missing.display()
                );
                surviving.push(record);
                continue;
            }
        }

        match http_probe(&record.url) {
            ProbeResult::Ok => {
                debug!("SSE discovery: ping {}/mcp → 200", record.url);
                matched = Some(record.url.clone());
                surviving.push(record);
            }
            ProbeResult::HttpError(status) => {
                debug!("SSE discovery: ping {}/mcp → http {}", record.url, status);
                // Server is bound but unhappy with the probe; keep the
                // entry for a future call to retry, but do not delegate.
                surviving.push(record);
            }
            ProbeResult::Transport(err) => {
                debug!(
                    "SSE discovery: removed stale entry url={} reason=probe_failed ({})",
                    record.url, err
                );
            }
        }
    }

    if let Err(e) = atomic_write(path, &surviving) {
        warn!("SSE discovery: failed to rewrite registry: {}", e);
    }

    matched
}

// ── internals ────────────────────────────────────────────────────────────

fn ensure_parent_dir(file: &Path) -> Result<()> {
    let dir = file
        .parent()
        .context("Discovery file path has no parent directory")?;
    if !dir.exists() {
        fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create discovery directory: {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(dir)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(dir, perms).with_context(|| {
                format!("Failed to chmod discovery directory: {}", dir.display())
            })?;
        }
    }
    Ok(())
}

/// Open the discovery file (creating an empty one if missing) and take an
/// advisory exclusive lock. The lock is released when the file is closed.
fn open_locked(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("Failed to open {}", path.display()))?;
    file.lock_exclusive()
        .with_context(|| format!("Failed to lock {}", path.display()))?;
    Ok(file)
}

fn read_records(file: &mut File) -> Result<Vec<SseServerRecord>> {
    file.seek(SeekFrom::Start(0))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    if buf.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&buf).context("Failed to parse discovery file as JSON")
}

/// Write `records` atomically: serialise to `.servers.json.tmp-<pid>`,
/// fsync, rename into place. If the rename fails, the partial tmp file is
/// removed. PID in the tmp name is only for collision avoidance between
/// concurrent writers, not for liveness — see module docs.
fn atomic_write(path: &Path, records: &[SseServerRecord]) -> Result<()> {
    let dir = path
        .parent()
        .context("Discovery file path has no parent directory")?;
    let tmp = dir.join(format!(".servers.json.tmp-{}", std::process::id()));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .with_context(|| format!("Failed to create {}", tmp.display()))?;
        let bytes = serde_json::to_vec_pretty(records)?;
        file.write_all(&bytes)?;
        let _ = file.sync_all();
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow::Error::new(e).context(format!(
            "Failed to rename {} → {}",
            tmp.display(),
            path.display()
        )));
    }
    Ok(())
}

fn remove_entry(path: &Path, url: &str) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let mut file = open_locked(path)?;
    let mut records = read_records(&mut file).unwrap_or_default();
    let before = records.len();
    records.retain(|r| r.url != url);
    if records.len() == before {
        return Ok(());
    }
    atomic_write(path, &records)
}

/// Verify that every path in `requested` is present in `available`.
/// Returns the first missing path so the caller can log a precise reason.
fn superset_check(
    available: &[PathBuf],
    requested: &[PathBuf],
) -> std::result::Result<(), PathBuf> {
    for path in requested {
        if !available.iter().any(|p| p == path) {
            return Err(path.clone());
        }
    }
    Ok(())
}

enum ProbeResult {
    /// 2xx response — server is alive and accepting MCP traffic.
    Ok,
    /// Non-2xx response — server is bound but rejected the ping. Entry
    /// is kept for future probes but we will not delegate now.
    HttpError(u16),
    /// Connection refused / timeout / DNS — server is gone, drop entry.
    Transport(String),
}

fn http_probe(url: &str) -> ProbeResult {
    let body = r#"{"jsonrpc":"2.0","id":0,"method":"ping"}"#;
    let endpoint = format!("{}/mcp", url.trim_end_matches('/'));
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
    {
        Ok(c) => c,
        Err(e) => return ProbeResult::Transport(e.to_string()),
    };
    match client
        .post(&endpoint)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .body(body)
        .send()
    {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                ProbeResult::Ok
            } else {
                ProbeResult::HttpError(status.as_u16())
            }
        }
        Err(e) => ProbeResult::Transport(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    /// A URL that reliably refuses connections in the test environment.
    /// Port 1 is the well-known TCPMUX port; nothing listens on it on
    /// developer machines or CI runners, so localhost yields *connection
    /// refused* in microseconds.
    const UNREACHABLE_URL: &str = "http://127.0.0.1:1";

    fn record(url: &str, repos: &[&str]) -> SseServerRecord {
        SseServerRecord {
            url: url.to_string(),
            repos: repos.iter().map(PathBuf::from).collect(),
        }
    }

    fn write_records(path: &Path, records: &[SseServerRecord]) {
        let _ = std::fs::create_dir_all(path.parent().unwrap());
        let bytes = serde_json::to_vec_pretty(records).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn read_back(path: &Path) -> Vec<SseServerRecord> {
        let bytes = std::fs::read(path).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn atomic_write_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("servers.json");

        atomic_write(&path, &[record("http://127.0.0.1:7557", &["/a"])]).unwrap();
        assert_eq!(
            read_back(&path),
            vec![record("http://127.0.0.1:7557", &["/a"])]
        );

        // Rewriting overwrites cleanly with no leftover tmp file.
        atomic_write(&path, &[record("http://127.0.0.1:7558", &["/b"])]).unwrap();
        assert_eq!(
            read_back(&path),
            vec![record("http://127.0.0.1:7558", &["/b"])]
        );

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".servers.json.tmp")
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "tmp files left behind: {:?}",
            leftovers
        );
    }

    #[test]
    fn superset_match_and_miss() {
        let available: Vec<PathBuf> = ["/repo/a", "/repo/b"].iter().map(PathBuf::from).collect();
        let requested_subset: Vec<PathBuf> = ["/repo/a"].iter().map(PathBuf::from).collect();
        let requested_extra: Vec<PathBuf> =
            ["/repo/a", "/repo/c"].iter().map(PathBuf::from).collect();

        assert!(superset_check(&available, &requested_subset).is_ok());
        let miss = superset_check(&available, &requested_extra).unwrap_err();
        assert_eq!(miss, PathBuf::from("/repo/c"));
    }

    #[test]
    fn unreachable_entry_is_pruned_by_find_at() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("servers.json");
        write_records(&path, &[record(UNREACHABLE_URL, &["/r"])]);

        let result = find_at(&path, &[PathBuf::from("/r")]);
        assert!(result.is_none(), "should not match an unreachable URL");

        let surviving = read_back(&path);
        assert!(
            surviving.is_empty(),
            "unreachable entry should be pruned, got {:?}",
            surviving
        );
    }

    #[test]
    fn drop_removes_only_own_entry() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("servers.json");

        // Seed the file with a foreign entry first.
        let foreign = record("http://127.0.0.1:7600", &["/elsewhere"]);
        write_records(&path, std::slice::from_ref(&foreign));

        // Register our own; let the guard drop at the end of the block.
        let our_url = "http://127.0.0.1:7557";
        {
            let _entry = register_at(&path, our_url, &[PathBuf::from("/r")]).unwrap();
            let mid = read_back(&path);
            assert!(mid.iter().any(|r| r.url == our_url));
            assert!(mid.iter().any(|r| r == &foreign));
        }

        let after = read_back(&path);
        assert!(
            !after.iter().any(|r| r.url == our_url),
            "our entry should be gone after drop, got {:?}",
            after
        );
        assert!(
            after.iter().any(|r| r == &foreign),
            "foreign entry should be untouched, got {:?}",
            after
        );
    }

    #[test]
    fn concurrent_find_at_does_not_lose_or_duplicate_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("servers.json");

        // Two unreachable entries plus one live-but-irrelevant entry whose
        // URL also refuses (so we don't accidentally probe a real server
        // during tests). The non-matching repo set prevents the probe from
        // running at all on that record.
        let irrelevant = SseServerRecord {
            url: "http://127.0.0.1:2".to_string(),
            repos: vec![PathBuf::from("/elsewhere")],
        };
        write_records(
            &path,
            &[
                record(UNREACHABLE_URL, &["/r"]),
                record("http://127.0.0.1:3", &["/r"]),
                irrelevant.clone(),
            ],
        );

        let path_arc = Arc::new(path.clone());
        let mut handles = Vec::new();
        for _ in 0..4 {
            let cloned_path = Arc::clone(&path_arc);
            handles.push(std::thread::spawn(move || {
                find_at(&cloned_path, &[PathBuf::from("/r")]);
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        let surviving = read_back(&path);
        // Unreachable matching entries must be gone; the non-matching
        // entry must remain exactly once.
        let irrelevant_count = surviving.iter().filter(|r| **r == irrelevant).count();
        assert_eq!(
            irrelevant_count, 1,
            "non-matching entry should appear exactly once, got {:?}",
            surviving
        );
        assert!(
            !surviving
                .iter()
                .any(|r| r.url == UNREACHABLE_URL || r.url == "http://127.0.0.1:3"),
            "matching-but-unreachable entries should be pruned, got {:?}",
            surviving
        );
    }
}
