//! Persistent index storage and watch mode for incremental updates
//!
//! Saves index to disk and watches for file changes to update incrementally.

use anyhow::{Context, Result};
#[cfg(feature = "native")]
use notify::{Config, Event, EventKind, RecursiveMode, Watcher};

// On Linux use the kernel's inotify backend (event-driven, ~0% idle CPU).
// On other platforms fall back to PollWatcher at compile time; pruning
// build/.git noise from the watched tree is left as a follow-up.
use dashmap::DashMap;
#[cfg(all(feature = "native", target_os = "linux"))]
use notify::INotifyWatcher as PlatformWatcher;
#[cfg(all(feature = "native", not(target_os = "linux")))]
use notify::PollWatcher as PlatformWatcher;
use parking_lot::RwLock;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::symbols::Symbol;

/// File metadata for change detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub path: PathBuf,
    pub content_hash: String,
    pub modified_time: u64,
    pub size: u64,
    pub symbols: Vec<Symbol>,
}

/// Persisted index structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedIndex {
    pub version: u32,
    pub created_at: u64,
    pub updated_at: u64,
    pub repo_root: PathBuf,
    pub files: HashMap<PathBuf, FileMetadata>,
    /// git HEAD commit hash at index time, when the repo is a git checkout.
    /// Compared on startup to rebuild symbols after a checkout/pull.
    pub head_hash: Option<String>,
    /// sha256 of the resolved compile_commands.json at index time, when
    /// compile_commands filtering is on. Detects a CDB regen with no commit.
    pub cdb_hash: Option<String>,
}

impl PersistedIndex {
    // v5: redb RepoMeta header gained head_hash/cdb_hash so the fingerprint
    // round-trips through the per-file store (postcard layout change).
    // v4: added head_hash/cdb_hash fingerprint fields (postcard layout change).
    // v3: Symbol gained confirmed_by/line_conflicts provenance fields, which
    // changes the postcard layout — older indexes must be rebuilt, not misread.
    const CURRENT_VERSION: u32 = 5;

    pub fn new(repo_root: PathBuf) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            version: Self::CURRENT_VERSION,
            created_at: now,
            updated_at: now,
            repo_root,
            files: HashMap::new(),
            head_hash: None,
            cdb_hash: None,
        }
    }

    /// Load index from disk
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).context("Failed to read index file")?;
        let index: Self = postcard::from_bytes(&data).context("Failed to deserialize index")?;

        if index.version != Self::CURRENT_VERSION {
            return Err(anyhow::anyhow!(
                "Index version mismatch: {} != {}",
                index.version,
                Self::CURRENT_VERSION
            ));
        }

        Ok(index)
    }

    /// Save index to disk
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = postcard::to_stdvec(self).context("Failed to serialize index")?;

        // Write to temp file then rename for atomicity
        let temp_path = path.with_extension("tmp");
        std::fs::write(&temp_path, &data).context("Failed to write temp index")?;
        std::fs::rename(&temp_path, path).context("Failed to rename index file")?;

        Ok(())
    }

    /// Check if a file needs re-indexing
    pub fn needs_reindex(&self, path: &Path) -> Result<bool> {
        let metadata = std::fs::metadata(path)?;
        let modified = metadata
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        let size = metadata.len();

        if let Some(cached) = self.files.get(path) {
            // Quick check: size and mtime
            if cached.size == size && cached.modified_time == modified {
                return Ok(false);
            }

            // Slower check: content hash
            let hash = hash_file(path)?;
            Ok(hash != cached.content_hash)
        } else {
            Ok(true)
        }
    }

    /// Update file in index
    pub fn update_file(&mut self, path: PathBuf, symbols: Vec<Symbol>) -> Result<()> {
        let metadata = std::fs::metadata(&path)?;
        let hash = hash_file(&path)?;

        self.files.insert(
            path.clone(),
            FileMetadata {
                path,
                content_hash: hash,
                modified_time: metadata
                    .modified()?
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs(),
                size: metadata.len(),
                symbols,
            },
        );

        self.updated_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(())
    }

    /// Remove file from index
    pub fn remove_file(&mut self, path: &Path) {
        self.files.remove(path);
        self.updated_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Get all symbols across all files
    pub fn all_symbols(&self) -> Vec<&Symbol> {
        self.files.values().flat_map(|f| f.symbols.iter()).collect()
    }

    /// Get symbols for a specific file
    pub fn file_symbols(&self, path: &Path) -> Option<&[Symbol]> {
        self.files.get(path).map(|f| f.symbols.as_slice())
    }
}

/// Compute SHA256 hash of file content
fn hash_file(path: &Path) -> Result<String> {
    let content = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    Ok(format!("{:x}", hasher.finalize()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// redb table: file key (absolute path string) -> postcard(FileMetadata).
const FILES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("files");
/// redb table: the single key "repo" -> postcard(RepoMeta).
const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

/// Repo-level header stored alongside the per-file records.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepoMeta {
    version: u32,
    repo_root: PathBuf,
    created_at: u64,
    updated_at: u64,
    /// Mirrors PersistedIndex::head_hash so the freshness fingerprint survives
    /// the redb round-trip; without it every repo rebuilds on every startup.
    head_hash: Option<String>,
    /// Mirrors PersistedIndex::cdb_hash for the same reason.
    cdb_hash: Option<String>,
}

/// Index storage manager.
///
/// Each repo's index is a redb key-value store (`<hash16>.redb`), one record
/// per file, so an edit updates a single record instead of rewriting the whole
/// repo. The legacy single-blob `.idx` format is migrated on first load.
pub struct IndexStore {
    index_dir: PathBuf,
    /// Open redb handles per repo DB file. These are file handles, not the
    /// index data — record bytes stay on disk and are read on demand.
    dbs: DashMap<PathBuf, Arc<Database>>,
}

impl IndexStore {
    pub fn new(index_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&index_dir)?;
        Ok(Self {
            index_dir,
            dbs: DashMap::new(),
        })
    }

    /// Hash of the canonical absolute repo path, so the same repo reached via a
    /// symlink or relative form maps to the same on-disk filename. Falls back to
    /// the input path when canonicalize fails (e.g. the path no longer exists).
    fn repo_hash(&self, repo_root: &Path) -> String {
        let canonical = repo_root
            .canonicalize()
            .unwrap_or_else(|_| repo_root.to_path_buf());
        let mut hasher = Sha256::new();
        hasher.update(canonical.to_string_lossy().as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Legacy single-blob index path (`.idx`). Retained for migration.
    pub fn index_path(&self, repo_root: &Path) -> PathBuf {
        self.index_dir
            .join(format!("{}.idx", &self.repo_hash(repo_root)[..16]))
    }

    /// redb store path for a repository (`.redb`).
    fn db_path(&self, repo_root: &Path) -> PathBuf {
        self.index_dir
            .join(format!("{}.redb", &self.repo_hash(repo_root)[..16]))
    }

    /// On-disk path of a repo's persisted store, for status/size reporting.
    pub fn store_path(&self, repo_root: &Path) -> PathBuf {
        self.db_path(repo_root)
    }

    /// Open-or-return the cached redb handle for a repo.
    fn db(&self, repo_root: &Path) -> Result<Arc<Database>> {
        use dashmap::mapref::entry::Entry;
        let path = self.db_path(repo_root);
        match self.dbs.entry(path.clone()) {
            Entry::Occupied(e) => Ok(Arc::clone(e.get())),
            Entry::Vacant(e) => {
                let db = Arc::new(
                    Database::create(&path)
                        .with_context(|| format!("Failed to open redb store {:?}", path))?,
                );
                e.insert(Arc::clone(&db));
                Ok(db)
            }
        }
    }

    /// Load or create index for a repository.
    ///
    /// Looks up by canonical-path hash. If no canonical-keyed .idx exists, scans
    /// the index dir for a legacy .idx whose stored repo_root canonicalizes to
    /// the same target — and if found, migrates it to the canonical filename
    /// and updates its repo_root field. The legacy file is removed after a
    /// successful migration.
    pub fn load_or_create(&self, repo_root: &Path) -> Result<PersistedIndex> {
        let canonical_root = repo_root
            .canonicalize()
            .unwrap_or_else(|_| repo_root.to_path_buf());
        let index_path = self.index_path(&canonical_root);

        if index_path.exists() {
            match PersistedIndex::load(&index_path) {
                Ok(index) => {
                    info!("Loaded existing index from {:?}", index_path);
                    return Ok(index);
                }
                Err(e) => {
                    warn!("Failed to load index, creating new: {}", e);
                }
            }
        }

        if let Some(legacy_path) = self.find_legacy_index_for(&canonical_root) {
            match self.migrate_legacy_index(&legacy_path, &index_path, &canonical_root) {
                Ok(index) => return Ok(index),
                Err(e) => warn!(
                    "Failed to migrate legacy index {:?}: {}; creating new",
                    legacy_path, e
                ),
            }
        }

        info!("Creating new index for {:?}", canonical_root);
        Ok(PersistedIndex::new(canonical_root))
    }

    /// Find an existing .idx whose stored repo_root canonicalizes to the
    /// target. Used to migrate indexes saved before path canonicalization.
    fn find_legacy_index_for(&self, canonical_root: &Path) -> Option<PathBuf> {
        let entries = std::fs::read_dir(&self.index_dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("idx") {
                continue;
            }
            let Ok(index) = PersistedIndex::load(&path) else {
                continue;
            };
            let Ok(stored_canonical) = index.repo_root.canonicalize() else {
                continue;
            };
            if stored_canonical == canonical_root {
                return Some(path);
            }
        }
        None
    }

    fn migrate_legacy_index(
        &self,
        legacy_path: &Path,
        canonical_path: &Path,
        canonical_root: &Path,
    ) -> Result<PersistedIndex> {
        let mut index = PersistedIndex::load(legacy_path)?;
        index.repo_root = canonical_root.to_path_buf();
        index.save(canonical_path)?;
        std::fs::remove_file(legacy_path)
            .with_context(|| format!("Failed to remove legacy index {:?}", legacy_path))?;
        info!(
            "Migrated legacy index {:?} -> {:?}",
            legacy_path, canonical_path
        );
        Ok(index)
    }

    /// Save index for a repository (legacy single-blob `.idx`; used by tests and
    /// the unused `IncrementalIndexer`). New code uses [`save_full`].
    pub fn save(&self, index: &PersistedIndex) -> Result<()> {
        let index_path = self.index_path(&index.repo_root);
        index.save(&index_path)?;
        debug!("Saved index to {:?}", index_path);
        Ok(())
    }

    /// Locate and load an old single-blob `.idx` for this repo (canonical-keyed
    /// first, then a pre-canonicalization legacy file) for one-time migration.
    fn find_legacy_blob(&self, canonical_root: &Path) -> Option<(PathBuf, PersistedIndex)> {
        let canonical_path = self.index_path(canonical_root);
        let blob_path = if canonical_path.exists() {
            canonical_path
        } else {
            self.find_legacy_index_for(canonical_root)?
        };
        match PersistedIndex::load(&blob_path) {
            Ok(index) => Some((blob_path, index)),
            Err(e) => {
                warn!(
                    "Failed to load legacy index {:?} for migration: {}",
                    blob_path, e
                );
                None
            }
        }
    }

    /// Load a repo's index from its redb store, reconstructing a `PersistedIndex`.
    ///
    /// On first use, migrates an old single-blob `.idx` into redb and removes it.
    /// A repo with neither store returns an empty index (no file is created
    /// until the first save).
    pub fn load_repo(&self, repo_root: &Path) -> Result<PersistedIndex> {
        let canonical_root = repo_root
            .canonicalize()
            .unwrap_or_else(|_| repo_root.to_path_buf());
        let db_path = self.db_path(&canonical_root);

        if !db_path.exists() {
            if let Some((blob_path, mut index)) = self.find_legacy_blob(&canonical_root) {
                index.repo_root = canonical_root.clone();
                self.save_full(&index)?;
                let _ = std::fs::remove_file(&blob_path);
                info!("Migrated legacy index {:?} -> {:?}", blob_path, db_path);
                return Ok(index);
            }
            return Ok(PersistedIndex::new(canonical_root));
        }

        let db = self.db(&canonical_root)?;
        let read_txn = db.begin_read()?;

        let mut index = PersistedIndex::new(canonical_root);
        if let Ok(meta_table) = read_txn.open_table(META_TABLE) {
            if let Some(guard) = meta_table.get("repo")? {
                if let Ok(meta) = postcard::from_bytes::<RepoMeta>(guard.value()) {
                    index.version = meta.version;
                    index.created_at = meta.created_at;
                    index.updated_at = meta.updated_at;
                    index.repo_root = meta.repo_root;
                    index.head_hash = meta.head_hash;
                    index.cdb_hash = meta.cdb_hash;
                }
            }
        }
        if let Ok(files_table) = read_txn.open_table(FILES_TABLE) {
            for entry in files_table.iter()? {
                let (_key, value) = entry?;
                if let Ok(file_meta) = postcard::from_bytes::<FileMetadata>(value.value()) {
                    index.files.insert(file_meta.path.clone(), file_meta);
                }
            }
        }
        info!(
            "Loaded {} file record(s) from {:?}",
            index.files.len(),
            db_path
        );
        Ok(index)
    }

    /// Rewrite a repo's entire redb store from an in-memory index. Clears stale
    /// records so files deleted since the last full save do not linger. Used for
    /// the initial save after a fresh index, the explicit save_index tool, and
    /// legacy-blob migration.
    pub fn save_full(&self, index: &PersistedIndex) -> Result<()> {
        let db = self.db(&index.repo_root)?;
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.delete_table(FILES_TABLE);
            let mut files_table = write_txn.open_table(FILES_TABLE)?;
            for file_meta in index.files.values() {
                let key = file_meta.path.to_string_lossy();
                let bytes = postcard::to_stdvec(file_meta).context("serialize FileMetadata")?;
                files_table.insert(key.as_ref(), bytes.as_slice())?;
            }
            let mut meta_table = write_txn.open_table(META_TABLE)?;
            let meta = RepoMeta {
                version: PersistedIndex::CURRENT_VERSION,
                repo_root: index.repo_root.clone(),
                created_at: index.created_at,
                updated_at: now_secs(),
                head_hash: index.head_hash.clone(),
                cdb_hash: index.cdb_hash.clone(),
            };
            meta_table.insert("repo", postcard::to_stdvec(&meta)?.as_slice())?;
        }
        write_txn.commit()?;
        debug!(
            "Saved {} file record(s) for {:?}",
            index.files.len(),
            index.repo_root
        );
        Ok(())
    }

    /// Apply a batch of per-file changes to a repo's redb store in one write
    /// transaction. O(changed files) — untouched records are left in place.
    pub fn apply_file_changes(
        &self,
        repo_root: &Path,
        upserts: &[FileMetadata],
        deletes: &[PathBuf],
    ) -> Result<()> {
        if upserts.is_empty() && deletes.is_empty() {
            return Ok(());
        }
        let db = self.db(repo_root)?;
        let write_txn = db.begin_write()?;
        {
            let mut files_table = write_txn.open_table(FILES_TABLE)?;
            for file_meta in upserts {
                let key = file_meta.path.to_string_lossy();
                let bytes = postcard::to_stdvec(file_meta).context("serialize FileMetadata")?;
                files_table.insert(key.as_ref(), bytes.as_slice())?;
            }
            for path in deletes {
                let key = path.to_string_lossy();
                files_table.remove(key.as_ref())?;
            }

            let mut meta_table = write_txn.open_table(META_TABLE)?;
            let existing: Option<RepoMeta> = match meta_table.get("repo")? {
                Some(guard) => postcard::from_bytes::<RepoMeta>(guard.value()).ok(),
                None => None,
            };
            // The existing branch preserves head_hash/cdb_hash (only updated_at
            // is touched below); the fallback runs only before any full save, so
            // the fingerprint is filled in by the next save_full.
            let mut meta = existing.unwrap_or_else(|| RepoMeta {
                version: PersistedIndex::CURRENT_VERSION,
                repo_root: repo_root.to_path_buf(),
                created_at: now_secs(),
                updated_at: 0,
                head_hash: None,
                cdb_hash: None,
            });
            meta.updated_at = now_secs();
            meta_table.insert("repo", postcard::to_stdvec(&meta)?.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// List all cached repositories
    pub fn list_cached(&self) -> Result<Vec<PathBuf>> {
        let mut repos = Vec::new();

        for entry in std::fs::read_dir(&self.index_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map(|e| e == "idx").unwrap_or(false) {
                if let Ok(index) = PersistedIndex::load(&path) {
                    repos.push(index.repo_root);
                }
            }
        }

        Ok(repos)
    }
}

/// File watcher for incremental updates (legacy, sync-based drain).
///
/// Backed by inotify on Linux and PollWatcher elsewhere — see `PlatformWatcher`.
#[cfg(feature = "native")]
pub struct FileWatcher {
    watcher: PlatformWatcher,
    rx: std::sync::mpsc::Receiver<Result<Event, notify::Error>>,
    watched_paths: Vec<PathBuf>,
}

#[cfg(feature = "native")]
impl FileWatcher {
    pub fn new() -> Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel();

        let watcher = PlatformWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            Config::default().with_poll_interval(Duration::from_millis(500)),
        )?;

        Ok(Self {
            watcher,
            rx,
            watched_paths: Vec::new(),
        })
    }

    /// Start watching a directory
    pub fn watch(&mut self, path: &Path) -> Result<()> {
        self.watcher.watch(path, RecursiveMode::Recursive)?;
        self.watched_paths.push(path.to_path_buf());
        info!("Watching for changes: {:?}", path);
        Ok(())
    }

    /// Stop watching a directory
    pub fn unwatch(&mut self, path: &Path) -> Result<()> {
        self.watcher.unwatch(path)?;
        self.watched_paths.retain(|p| p != path);
        Ok(())
    }

    /// Poll for file changes (non-blocking)
    pub fn poll_changes(&self) -> Vec<FileChange> {
        let mut changes = Vec::new();

        while let Ok(result) = self.rx.try_recv() {
            if let Ok(event) = result {
                for path in event.paths {
                    let change_type = match event.kind {
                        EventKind::Create(_) => ChangeType::Created,
                        EventKind::Modify(_) => ChangeType::Modified,
                        EventKind::Remove(_) => ChangeType::Deleted,
                        _ => continue,
                    };

                    changes.extend(source_changes_for_path(&path, change_type));
                }
            }
        }

        // Deduplicate
        changes.sort_by(|a, b| a.path.cmp(&b.path));
        changes.dedup_by(|a, b| a.path == b.path);

        changes
    }

    /// Block until changes occur
    pub fn wait_for_changes(&self, timeout: Duration) -> Vec<FileChange> {
        let mut changes = Vec::new();

        if let Ok(Ok(event)) = self.rx.recv_timeout(timeout) {
            for path in event.paths {
                let change_type = match event.kind {
                    EventKind::Create(_) => ChangeType::Created,
                    EventKind::Modify(_) => ChangeType::Modified,
                    EventKind::Remove(_) => ChangeType::Deleted,
                    _ => continue,
                };

                changes.extend(source_changes_for_path(&path, change_type));
            }
        }

        // Drain any additional events
        changes.extend(self.poll_changes());

        changes
    }
}

/// Async file watcher for event-driven incremental updates.
///
/// Backed by inotify on Linux and PollWatcher elsewhere — see `PlatformWatcher`.
#[cfg(feature = "native")]
pub struct AsyncFileWatcher {
    _watcher: PlatformWatcher,
    watched_paths: Vec<PathBuf>,
}

#[cfg(feature = "native")]
impl AsyncFileWatcher {
    /// Create a new async file watcher and return a channel receiver for events
    pub fn new() -> Result<(Self, mpsc::Receiver<Vec<FileChange>>)> {
        let (tx, rx) = mpsc::channel(100);

        // Create a channel for the notify watcher
        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();

        let watcher = PlatformWatcher::new(
            move |res| {
                let _ = notify_tx.send(res);
            },
            Config::default().with_poll_interval(Duration::from_millis(500)),
        )?;

        // Spawn a task to process notify events and send batched changes
        tokio::spawn(async move {
            let mut debounce_buffer: HashMap<PathBuf, FileChange> = HashMap::new();
            let debounce_duration = Duration::from_millis(300);
            let mut debounce_timer = tokio::time::interval(debounce_duration);
            debounce_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    // Receive events from notify
                    Some(result) = notify_rx.recv() => {
                        if let Ok(event) = result {
                            for path in event.paths {
                                let change_type = match event.kind {
                                    EventKind::Create(_) => ChangeType::Created,
                                    EventKind::Modify(_) => ChangeType::Modified,
                                    EventKind::Remove(_) => ChangeType::Deleted,
                                    _ => continue,
                                };

                                for change in source_changes_for_path(&path, change_type.clone()) {
                                    // Add to debounce buffer (overwrites previous events for same file)
                                    debounce_buffer.insert(change.path.clone(), change);
                                }
                            }
                        }
                    }
                    // Debounce timer tick - flush buffered changes
                    _ = debounce_timer.tick() => {
                        if !debounce_buffer.is_empty() {
                            let changes: Vec<FileChange> = debounce_buffer.drain().map(|(_, v)| v).collect();
                            if tx.send(changes).await.is_err() {
                                // Receiver dropped, exit task
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok((
            Self {
                _watcher: watcher,
                watched_paths: Vec::new(),
            },
            rx,
        ))
    }

    /// Watch a directory for changes
    pub fn watch(&mut self, path: &Path) -> Result<()> {
        self._watcher.watch(path, RecursiveMode::Recursive)?;
        self.watched_paths.push(path.to_path_buf());
        info!("Async watching for changes: {:?}", path);
        Ok(())
    }

    /// Stop watching a directory
    pub fn unwatch(&mut self, path: &Path) -> Result<()> {
        self._watcher.unwatch(path)?;
        self.watched_paths.retain(|p| p != path);
        Ok(())
    }

    /// Get the list of watched paths
    pub fn watched_paths(&self) -> &[PathBuf] {
        &self.watched_paths
    }
}

/// A detected file change
#[derive(Debug, Clone)]
pub struct FileChange {
    pub path: PathBuf,
    pub change_type: ChangeType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
}

/// Check if a path is a source file we care about
fn is_source_file(path: &Path) -> bool {
    let extensions = [
        "rs", "py", "js", "jsx", "ts", "tsx", "go", "java", "c", "h", "cpp", "hpp", "cc", "cxx",
        "hxx", "swift", "v", "vh", "sv", "svh",
    ];

    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| extensions.contains(&e))
        .unwrap_or(false)
}

/// A compile_commands.json change must restart clangd, so it has to survive the
/// source-extension filter that would otherwise drop the .json file.
fn is_compile_commands_file(path: &Path) -> bool {
    path.file_name()
        .map(|n| n == "compile_commands.json")
        .unwrap_or(false)
}

/// Convert a notify path into source-file changes.
///
/// Some platforms, especially macOS FSEvents and network/container mounts,
/// can report a directory as modified instead of the exact file. When that
/// happens, scan the reported directory for source files so watch mode does
/// not silently miss the change.
fn source_changes_for_path(path: &Path, change_type: ChangeType) -> Vec<FileChange> {
    if is_source_file(path) || is_compile_commands_file(path) {
        return vec![FileChange {
            path: path.to_path_buf(),
            change_type,
        }];
    }

    if change_type == ChangeType::Deleted || !path.is_dir() {
        return Vec::new();
    }

    let mut changes = Vec::new();
    collect_source_files(path, change_type, &mut changes);
    changes
}

fn collect_source_files(path: &Path, change_type: ChangeType, changes: &mut Vec<FileChange>) {
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };

    for entry in entries.flatten() {
        let entry_path = entry.path();
        if is_source_file(&entry_path) {
            changes.push(FileChange {
                path: entry_path,
                change_type: change_type.clone(),
            });
        } else if entry_path.is_dir() {
            collect_source_files(&entry_path, change_type.clone(), changes);
        }
    }
}

/// Incremental indexer that combines persistence and watching
#[cfg(feature = "native")]
pub struct IncrementalIndexer {
    store: IndexStore,
    index: Arc<RwLock<PersistedIndex>>,
    watcher: Option<FileWatcher>,
}

#[cfg(feature = "native")]
impl IncrementalIndexer {
    pub fn new(index_dir: PathBuf, repo_root: &Path) -> Result<Self> {
        let store = IndexStore::new(index_dir)?;
        let index = store.load_or_create(repo_root)?;

        Ok(Self {
            store,
            index: Arc::new(RwLock::new(index)),
            watcher: None,
        })
    }

    /// Enable watch mode
    pub fn enable_watch(&mut self, repo_root: &Path) -> Result<()> {
        let mut watcher = FileWatcher::new()?;
        watcher.watch(repo_root)?;
        self.watcher = Some(watcher);
        Ok(())
    }

    /// Check for and process file changes
    pub fn process_changes<F>(&self, mut reindex_fn: F) -> Result<usize>
    where
        F: FnMut(&Path) -> Result<Vec<Symbol>>,
    {
        let changes = match &self.watcher {
            Some(w) => w.poll_changes(),
            None => return Ok(0),
        };

        if changes.is_empty() {
            return Ok(0);
        }

        let mut index = self.index.write();
        let mut count = 0;

        for change in changes {
            match change.change_type {
                ChangeType::Created | ChangeType::Modified => {
                    debug!("Re-indexing: {:?}", change.path);
                    match reindex_fn(&change.path) {
                        Ok(symbols) => {
                            index.update_file(change.path, symbols)?;
                            count += 1;
                        }
                        Err(e) => {
                            warn!("Failed to index {:?}: {}", change.path, e);
                        }
                    }
                }
                ChangeType::Deleted => {
                    debug!("Removing from index: {:?}", change.path);
                    index.remove_file(&change.path);
                    count += 1;
                }
            }
        }

        if count > 0 {
            self.store.save(&index)?;
        }

        Ok(count)
    }

    /// Get a read reference to the index
    pub fn index(&self) -> Arc<RwLock<PersistedIndex>> {
        Arc::clone(&self.index)
    }

    /// Force save the current index
    pub fn save(&self) -> Result<()> {
        let index = self.index.read();
        self.store.save(&index)
    }

    /// Get files that need re-indexing
    pub fn files_needing_reindex(&self) -> Result<Vec<PathBuf>> {
        let index = self.index.read();
        let mut needs_reindex = Vec::new();

        for path in index.files.keys() {
            if !path.exists() || index.needs_reindex(path)? {
                needs_reindex.push(path.clone());
            }
        }

        Ok(needs_reindex)
    }
}

/// Run the file watcher in background using an async event-driven loop.
///
/// The function exits cleanly when:
/// * The shutdown channel's only `Sender` is dropped (`recv()` returns
///   `Err(Closed)`), or
/// * A `()` value is sent on the shutdown channel.
///
/// **Bug history (issue #26):** the spawn site in `main.rs` used to drop the
/// shutdown sender immediately after creating it, so the receiver here saw
/// `Closed` on the first poll and the watcher exited milliseconds after
/// startup — silently disabling `--watch`. Use `spawn_watch_mode` (below)
/// from new call sites; it returns the sender so the caller cannot forget to
/// keep it alive.
pub async fn run_watch_mode(
    engine: Arc<crate::index::CodeIntelEngine>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    info!("Starting async watch mode background task");

    let (_watcher, mut rx) = match engine.create_async_file_watcher() {
        Some((w, r)) => (w, r),
        None => {
            warn!("Failed to create async file watcher, watch mode disabled");
            return;
        }
    };

    loop {
        tokio::select! {
            // Receive batched file change events
            Some(changes) = rx.recv() => {
                if !changes.is_empty() {
                    debug!("Detected {} file change(s)", changes.len());
                    match engine.process_file_changes(&changes).await {
                        Ok(count) => {
                            if count > 0 {
                                debug!("Re-indexed {} file(s)", count);
                            }
                        }
                        Err(e) => {
                            warn!("Error processing file changes: {}", e);
                        }
                    }
                }
            }
            // Handle shutdown signal (or all senders dropped)
            _ = shutdown.recv() => {
                info!("Watch mode shutting down");
                break;
            }
        }
    }
}

/// Spawn the watch-mode background task and return the shutdown `Sender`.
///
/// **Callers must hold the returned `Sender` for as long as the watcher
/// should keep running.** Dropping it makes the watcher loop exit on its
/// next poll (this is the cause of issue #26 — the original wiring dropped
/// the sender immediately).
///
/// The spawned task is detached; the returned `Sender` is the only handle
/// needed to keep the watcher alive.
#[must_use = "the returned Sender must be held until the watcher should stop; \
              dropping it immediately exits the watcher (issue #26)"]
pub fn spawn_watch_mode(
    engine: Arc<crate::index::CodeIntelEngine>,
) -> tokio::sync::broadcast::Sender<()> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    tokio::spawn(async move {
        run_watch_mode(engine, shutdown_rx).await;
    });
    shutdown_tx
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_hash_consistency() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "hello world").unwrap();

        let hash1 = hash_file(&file).unwrap();
        let hash2 = hash_file(&file).unwrap();
        assert_eq!(hash1, hash2);

        std::fs::write(&file, "hello world!").unwrap();
        let hash3 = hash_file(&file).unwrap();
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_is_source_file() {
        assert!(is_source_file(Path::new("foo.rs")));
        assert!(is_source_file(Path::new("bar.py")));
        assert!(is_source_file(Path::new("src/index.ts")));
        assert!(!is_source_file(Path::new("README.md")));
        assert!(!is_source_file(Path::new("data.json")));
    }

    #[test]
    fn test_index_store() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();

        let repo = tempdir().unwrap();
        let index = PersistedIndex::new(repo.path().to_path_buf());

        store.save(&index).unwrap();

        let loaded = store.load_or_create(repo.path()).unwrap();
        assert_eq!(loaded.version, PersistedIndex::CURRENT_VERSION);
    }

    fn meta(path: PathBuf, hash: &str) -> FileMetadata {
        FileMetadata {
            path,
            content_hash: hash.to_string(),
            modified_time: 0,
            size: 0,
            symbols: Vec::new(),
        }
    }

    #[test]
    fn test_redb_incremental_upsert_and_delete() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();
        let repo = tempdir().unwrap();
        let root = repo.path().to_path_buf();

        // A repo with no store loads as empty and creates no file.
        assert!(store.load_repo(&root).unwrap().files.is_empty());

        // Upsert two records.
        let upserts = [meta(root.join("a.rs"), "h1"), meta(root.join("b.rs"), "h2")];
        store.apply_file_changes(&root, &upserts, &[]).unwrap();
        assert_eq!(store.load_repo(&root).unwrap().files.len(), 2);

        // Re-upserting a.rs replaces the record rather than duplicating it.
        store
            .apply_file_changes(&root, &[meta(root.join("a.rs"), "h1b")], &[])
            .unwrap();
        let loaded = store.load_repo(&root).unwrap();
        assert_eq!(loaded.files.len(), 2);
        assert_eq!(
            loaded.files.get(&root.join("a.rs")).unwrap().content_hash,
            "h1b"
        );

        // Deleting b.rs leaves a.rs untouched.
        store
            .apply_file_changes(&root, &[], &[root.join("b.rs")])
            .unwrap();
        let loaded = store.load_repo(&root).unwrap();
        assert_eq!(loaded.files.len(), 1);
        assert!(loaded.files.contains_key(&root.join("a.rs")));
    }

    #[test]
    fn test_redb_save_full_replaces_stale_records() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();
        let repo = tempdir().unwrap();
        let root = repo.path().to_path_buf();

        // Populate an existing files table incrementally.
        store
            .apply_file_changes(
                &root,
                &[meta(root.join("a.rs"), "h1"), meta(root.join("b.rs"), "h2")],
                &[],
            )
            .unwrap();
        assert_eq!(store.load_repo(&root).unwrap().files.len(), 2);

        // A full save with a different set clears stale records (exercises
        // delete_table + reopen on an already-populated table).
        let mut idx = PersistedIndex::new(root.clone());
        idx.files
            .insert(root.join("c.rs"), meta(root.join("c.rs"), "h3"));
        store.save_full(&idx).unwrap();

        let loaded = store.load_repo(&root).unwrap();
        assert_eq!(loaded.files.len(), 1);
        assert!(loaded.files.contains_key(&root.join("c.rs")));
    }

    // Regression: the freshness fingerprint must survive the redb round-trip.
    // When it was dropped, fingerprint_matches always saw None and every repo
    // rebuilt on every startup.
    #[test]
    fn test_redb_round_trips_fingerprint() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();
        let repo = tempdir().unwrap();
        let root = repo.path().to_path_buf();

        let mut idx = PersistedIndex::new(root.clone());
        idx.head_hash = Some("deadbeef".to_string());
        idx.cdb_hash = Some("cafef00d".to_string());
        idx.files
            .insert(root.join("a.rs"), meta(root.join("a.rs"), "h1"));
        store.save_full(&idx).unwrap();

        let loaded = store.load_repo(&root).unwrap();
        assert_eq!(loaded.head_hash.as_deref(), Some("deadbeef"));
        assert_eq!(loaded.cdb_hash.as_deref(), Some("cafef00d"));

        // An incremental edit preserves the fingerprint (only updated_at moves).
        store
            .apply_file_changes(&root, &[meta(root.join("a.rs"), "h1b")], &[])
            .unwrap();
        let loaded = store.load_repo(&root).unwrap();
        assert_eq!(loaded.head_hash.as_deref(), Some("deadbeef"));
        assert_eq!(loaded.cdb_hash.as_deref(), Some("cafef00d"));
    }

    #[test]
    fn test_redb_migrates_legacy_blob() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();
        let repo = tempdir().unwrap();
        let root = repo.path().to_path_buf();

        // Seed a legacy single-blob .idx.
        let mut blob = PersistedIndex::new(root.clone());
        blob.files
            .insert(root.join("x.rs"), meta(root.join("x.rs"), "hx"));
        store.save(&blob).unwrap();
        let blob_path = store.index_path(&root);
        assert!(blob_path.exists());

        // First load migrates it into redb and removes the blob.
        let loaded = store.load_repo(&root).unwrap();
        assert!(loaded.files.contains_key(&root.join("x.rs")));
        assert!(
            !blob_path.exists(),
            "blob should be removed after migration"
        );
        assert!(store.db_path(&root).exists(), "redb store should exist");

        // The migrated data survives a fresh store. redb holds an exclusive file
        // lock, so the first store must be dropped before reopening the same DB.
        drop(store);
        let store2 = IndexStore::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(store2.load_repo(&root).unwrap().files.len(), 1);
    }
}
