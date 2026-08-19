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
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::callgraph::CallEdge;
use crate::symbols::{Symbol, SymbolKind};

/// A persisted call-graph augmentation edge: the resolved caller key paired with
/// the outgoing edge that a non-tree-sitter backend confirmed. Stored on the
/// caller's file record so an unchanged repo can replay augmentation on restart
/// instead of re-querying clangd/ccls/gtags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedCallEdge {
    pub caller_key: String,
    pub edge: CallEdge,
}

/// File metadata for change detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub path: PathBuf,
    pub content_hash: String,
    pub modified_time: u64,
    pub size: u64,
    pub symbols: Vec<Symbol>,
    /// Augmentation edges whose caller lives in this file. Empty for files with
    /// no cross-validated calls and for watch-path upserts (those drop the
    /// edges; a fingerprint mismatch or reindex rebuilds them).
    #[serde(default)]
    pub call_edges: Vec<PersistedCallEdge>,
}

/// Extraction-logic version of the indexer. Distinct from
/// [`PersistedIndex::CURRENT_VERSION`], which tracks the on-disk *serialization*
/// layout: this tracks the *content* the indexer produces (symbol extraction,
/// call-graph construction). Bump it whenever a code change means an unchanged
/// source file would now index differently — e.g. recognising a new definition
/// form — so an already-indexed repo rebuilds on next load even though its git
/// HEAD, compile_commands.json, and serialization layout are all unchanged. The
/// value is persisted in the redb header and compared at load time.
pub const INDEX_LOGIC_VERSION: u32 = 3;

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
    /// git HEAD when compile_commands.json was last applied as the index
    /// filter. The diff base for sources the manifest cannot describe: a
    /// checkout does not regenerate it, so everything changed since is unlisted.
    pub cdb_head_hash: Option<String>,
    /// [`INDEX_LOGIC_VERSION`] the records were produced under. A mismatch with
    /// the running binary's value forces a rebuild, independent of the fingerprint.
    pub logic_version: u32,
}

impl PersistedIndex {
    // v8: PersistedIndex/RepoMeta gained cdb_head_hash (postcard layout change);
    // older records fail to decode and rebuild, which is what gives the new
    // field its first value.
    // v7: PersistedIndex/RepoMeta gained logic_version (postcard layout change);
    // older records fail to decode and rebuild.
    // v6: FileMetadata gained call_edges (persisted call-graph augmentation), a
    // postcard layout change — older records fail to decode and rebuild.
    // v5: redb RepoMeta header gained head_hash/cdb_hash so the fingerprint
    // round-trips through the per-file store (postcard layout change).
    // v4: added head_hash/cdb_hash fingerprint fields (postcard layout change).
    // v3: Symbol gained confirmed_by/line_conflicts provenance fields, which
    // changes the postcard layout — older indexes must be rebuilt, not misread.
    const CURRENT_VERSION: u32 = 8;

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
            cdb_head_hash: None,
            logic_version: INDEX_LOGIC_VERSION,
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
                call_edges: Vec::new(),
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
/// redb table: `"<symbol name>\0<repo-relative file>"` -> postcard(SymbolKind).
/// A symbol name cannot contain NUL, so all definitions of one name form a
/// contiguous key range a prefix scan can read.
const DEFS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("definitions");
/// redb table: repo-relative file -> postcard(Vec<String>) of the names it
/// defines. Read only to retract a file's rows when it changes or goes away.
const DEF_FILES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("definition_files");
/// [`META_TABLE`] key holding the definition map's own header.
const DEFINITION_META_KEY: &str = "definitions";

/// What the definition map stores. Distinct from [`INDEX_LOGIC_VERSION`], which
/// covers symbol extraction for the index proper: this tracks the map's own
/// content rules, so narrowing or widening the kinds it keeps rebuilds the map
/// without invalidating every repo's symbols. Bump it whenever an unchanged
/// source file would now contribute different rows.
const DEFINITION_MAP_VERSION: u32 = 1;
/// Rows buffered before the definition map commits a write transaction. Keeps
/// a whole-repo build's memory flat without paying a transaction per file.
const DEFINITION_FLUSH_ROWS: usize = 50_000;

fn definition_key(name: &str, file: &str) -> String {
    format!("{name}\0{file}")
}

/// One row per distinct name in a file: the key is (name, file), so two
/// symbols sharing a name in one file collapse into a single row carrying
/// whichever kind was parsed first.
///
/// Functions and methods only. The map exists to answer the callee half of the
/// `--index-filter` pull-in, and a macro or type a scoped file uses arrives with
/// the header that defines it, which the include half already pulls in — so
/// storing those kinds would multiply the map without pulling in anything the
/// include rule does not.
fn distinct_definitions(symbols: &[Symbol]) -> Vec<(String, SymbolKind)> {
    let mut seen: BTreeMap<&str, &SymbolKind> = BTreeMap::new();
    for symbol in symbols {
        if symbol.name.is_empty()
            || !matches!(symbol.kind, SymbolKind::Function | SymbolKind::Method)
        {
            continue;
        }
        seen.entry(symbol.name.as_str()).or_insert(&symbol.kind);
    }
    seen.into_iter()
        .map(|(name, kind)| (name.to_string(), kind.clone()))
        .collect()
}

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
    /// Mirrors PersistedIndex::cdb_head_hash so the manifest's diff base
    /// survives a restart; without it every restart re-widens from nothing.
    cdb_head_hash: Option<String>,
    /// [`INDEX_LOGIC_VERSION`] these records were produced under; a mismatch with
    /// the running binary forces a rebuild even when head/cdb are unchanged.
    logic_version: u32,
}

/// Header of a repo's definition map: what it was built from, so one built
/// against a different tree or a different indexer is rejected rather than
/// answered from.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DefinitionMeta {
    head_hash: Option<String>,
    logic_version: u32,
    /// [`DEFINITION_MAP_VERSION`] these rows were produced under. A header
    /// written before this field existed fails to decode, which reads as "no
    /// map" and rebuilds — the same way the index handles a layout change.
    map_version: u32,
    files: u64,
    definitions: u64,
    built_at: u64,
}

/// Size of a repo's definition map as built. Incremental per-file updates do
/// not adjust these, so they describe the build, not the current row count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DefinitionStats {
    pub files: u64,
    pub definitions: u64,
}

/// One definition the map holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinitionHit {
    pub name: String,
    pub kind: SymbolKind,
    /// Repo-relative path of the defining file.
    pub file: String,
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

    /// The stored repo header — fingerprint and timestamps, no per-file records.
    /// A caller that only needs the fingerprint must not pay `load_repo`'s scan
    /// of every record. Returns a fresh empty header when nothing is stored yet;
    /// unlike `load_repo` it does not migrate a legacy blob.
    pub fn load_repo_header(&self, repo_root: &Path) -> Result<PersistedIndex> {
        let canonical_root = repo_root
            .canonicalize()
            .unwrap_or_else(|_| repo_root.to_path_buf());

        let mut index = PersistedIndex::new(canonical_root.clone());
        if !self.db_path(&canonical_root).exists() {
            return Ok(index);
        }

        let db = self.db(&canonical_root)?;
        let read_txn = db.begin_read()?;
        if let Ok(meta_table) = read_txn.open_table(META_TABLE) {
            if let Some(guard) = meta_table.get("repo")? {
                if let Ok(meta) = postcard::from_bytes::<RepoMeta>(guard.value()) {
                    index.version = meta.version;
                    index.created_at = meta.created_at;
                    index.updated_at = meta.updated_at;
                    index.repo_root = meta.repo_root;
                    index.head_hash = meta.head_hash;
                    index.cdb_hash = meta.cdb_hash;
                    index.cdb_head_hash = meta.cdb_head_hash;
                    index.logic_version = meta.logic_version;
                }
            }
        }
        Ok(index)
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

        let mut index = self.load_repo_header(&canonical_root)?;

        let db = self.db(&canonical_root)?;
        let read_txn = db.begin_read()?;
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
                cdb_head_hash: index.cdb_head_hash.clone(),
                logic_version: index.logic_version,
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
                cdb_head_hash: None,
                logic_version: INDEX_LOGIC_VERSION,
            });
            meta.updated_at = now_secs();
            meta_table.insert("repo", postcard::to_stdvec(&meta)?.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// The definition map's header, whatever it was built from. `None` when the
    /// repo has no map — which is also what a build that died before committing
    /// leaves behind, since the header is written last.
    fn definition_meta(&self, repo_root: &Path) -> Option<DefinitionMeta> {
        if !self.db_path(repo_root).exists() {
            return None;
        }
        let db = self.db(repo_root).ok()?;
        let read_txn = db.begin_read().ok()?;
        let meta_table = read_txn.open_table(META_TABLE).ok()?;
        let guard = meta_table.get(DEFINITION_META_KEY).ok()??;
        postcard::from_bytes(guard.value()).ok()
    }

    /// Size of the repo's definition map, or `None` when it is absent or was
    /// built from a different HEAD or by a different indexer.
    pub fn definition_stats(
        &self,
        repo_root: &Path,
        head_hash: Option<&str>,
    ) -> Option<DefinitionStats> {
        let meta = self.definition_meta(repo_root)?;
        if meta.map_version != DEFINITION_MAP_VERSION
            || meta.logic_version != INDEX_LOGIC_VERSION
            || meta.head_hash.as_deref() != head_hash
        {
            return None;
        }
        Some(DefinitionStats {
            files: meta.files,
            definitions: meta.definitions,
        })
    }

    /// Start replacing a repo's definition map.
    ///
    /// Drops the previous map and its header first, so from here until
    /// [`DefinitionWriter::commit`] the repo reads as having no map at all — a
    /// build that is cancelled or dies is never queried as though complete.
    pub fn begin_definitions(&self, repo_root: &Path) -> Result<DefinitionWriter> {
        let db = self.db(repo_root)?;
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.delete_table(DEFS_TABLE);
            let _ = write_txn.delete_table(DEF_FILES_TABLE);
            let mut meta_table = write_txn.open_table(META_TABLE)?;
            meta_table.remove(DEFINITION_META_KEY)?;
        }
        write_txn.commit()?;
        Ok(DefinitionWriter {
            db,
            rows: Vec::new(),
            file_names: Vec::new(),
            stats: DefinitionStats::default(),
        })
    }

    /// Every definition of any of `names`, from the whole repo rather than only
    /// the files the index kept. Paths are repo-relative, as gtags reports them.
    pub fn definitions_of(&self, repo_root: &Path, names: &[String]) -> Result<Vec<DefinitionHit>> {
        let mut hits = Vec::new();
        if !self.db_path(repo_root).exists() {
            return Ok(hits);
        }
        let db = self.db(repo_root)?;
        let read_txn = db.begin_read()?;
        let Ok(table) = read_txn.open_table(DEFS_TABLE) else {
            return Ok(hits);
        };
        for name in names {
            if name.is_empty() {
                continue;
            }
            // NUL sorts below every other byte, so the range from "name\0" up
            // to "name\u{1}" covers this name's rows and no longer name's.
            let start = definition_key(name, "");
            let end = format!("{name}\u{1}");
            for entry in table.range::<&str>(start.as_str()..end.as_str())? {
                let (key, value) = entry?;
                let Some((_, file)) = key.value().split_once('\0') else {
                    continue;
                };
                let Ok(kind) = postcard::from_bytes::<SymbolKind>(value.value()) else {
                    continue;
                };
                hits.push(DefinitionHit {
                    name: name.clone(),
                    kind,
                    file: file.to_string(),
                });
            }
        }
        Ok(hits)
    }

    /// Replace one file's rows in the definition map, so an edited file's
    /// definitions do not stay as they were when the map was built. A no-op on
    /// a repo with no map: an incremental update must not conjure a partial one.
    pub fn update_file_definitions(
        &self,
        repo_root: &Path,
        file: &str,
        symbols: &[Symbol],
    ) -> Result<()> {
        self.replace_file_definitions(repo_root, file, symbols)
    }

    /// Drop a deleted file's rows from the definition map.
    pub fn remove_file_definitions(&self, repo_root: &Path, file: &str) -> Result<()> {
        self.replace_file_definitions(repo_root, file, &[])
    }

    fn replace_file_definitions(
        &self,
        repo_root: &Path,
        file: &str,
        symbols: &[Symbol],
    ) -> Result<()> {
        if self.definition_meta(repo_root).is_none() {
            return Ok(());
        }
        let definitions = distinct_definitions(symbols);
        let db = self.db(repo_root)?;
        let write_txn = db.begin_write()?;
        {
            let mut defs = write_txn.open_table(DEFS_TABLE)?;
            let mut files = write_txn.open_table(DEF_FILES_TABLE)?;

            let previous: Vec<String> = match files.get(file)? {
                Some(guard) => postcard::from_bytes(guard.value()).unwrap_or_default(),
                None => Vec::new(),
            };
            for name in &previous {
                defs.remove(definition_key(name, file).as_str())?;
            }

            let names: Vec<&String> = definitions.iter().map(|(name, _)| name).collect();
            for (name, kind) in &definitions {
                defs.insert(
                    definition_key(name, file).as_str(),
                    postcard::to_stdvec(kind)?.as_slice(),
                )?;
            }
            if names.is_empty() {
                files.remove(file)?;
            } else {
                files.insert(file, postcard::to_stdvec(&names)?.as_slice())?;
            }
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

/// Builds a repo's definition map in bounded batches.
///
/// The map only becomes readable when [`DefinitionWriter::commit`] writes its
/// header, so an abandoned build leaves the repo with no map rather than with
/// half of one.
pub struct DefinitionWriter {
    db: Arc<Database>,
    rows: Vec<(String, SymbolKind, String)>,
    file_names: Vec<(String, Vec<String>)>,
    stats: DefinitionStats,
}

impl DefinitionWriter {
    /// Record what one file defines. Buffered; written once the batch fills.
    pub fn add_file(&mut self, file: &str, symbols: &[Symbol]) -> Result<()> {
        let definitions = distinct_definitions(symbols);
        let names: Vec<String> = definitions.iter().map(|(name, _)| name.clone()).collect();
        for (name, kind) in definitions {
            self.rows.push((name, kind, file.to_string()));
        }
        self.stats.files += 1;
        self.stats.definitions += names.len() as u64;
        self.file_names.push((file.to_string(), names));

        if self.rows.len() >= DEFINITION_FLUSH_ROWS {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.rows.is_empty() && self.file_names.is_empty() {
            return Ok(());
        }
        let write_txn = self.db.begin_write()?;
        {
            let mut defs = write_txn.open_table(DEFS_TABLE)?;
            for (name, kind, file) in self.rows.drain(..) {
                defs.insert(
                    definition_key(&name, &file).as_str(),
                    postcard::to_stdvec(&kind)?.as_slice(),
                )?;
            }
            let mut files = write_txn.open_table(DEF_FILES_TABLE)?;
            for (file, names) in self.file_names.drain(..) {
                if names.is_empty() {
                    continue;
                }
                files.insert(file.as_str(), postcard::to_stdvec(&names)?.as_slice())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Publish the map. `head_hash` is the repo fingerprint it was built from;
    /// a later lookup against a different one rejects it as stale.
    pub fn commit(mut self, head_hash: Option<&str>) -> Result<DefinitionStats> {
        self.flush()?;
        let write_txn = self.db.begin_write()?;
        {
            let mut meta_table = write_txn.open_table(META_TABLE)?;
            let meta = DefinitionMeta {
                head_hash: head_hash.map(str::to_string),
                logic_version: INDEX_LOGIC_VERSION,
                map_version: DEFINITION_MAP_VERSION,
                files: self.stats.files,
                definitions: self.stats.definitions,
                built_at: now_secs(),
            };
            meta_table.insert(DEFINITION_META_KEY, postcard::to_stdvec(&meta)?.as_slice())?;
        }
        write_txn.commit()?;
        Ok(self.stats)
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

/// A branch switch rewrites the worktree, and the `.git/HEAD` write precedes
/// it — the earliest signal that a burst of file changes is coming. It has to
/// survive the source-extension filter, like compile_commands.json.
///
/// A linked worktree keeps its HEAD in `<main>/.git/worktrees/<name>/HEAD`,
/// outside the watched root, so a switch there is not seen here.
fn is_git_head_file(path: &Path) -> bool {
    path.file_name().map(|n| n == "HEAD").unwrap_or(false)
        && path
            .parent()
            .and_then(|parent| parent.file_name())
            .map(|n| n == ".git")
            .unwrap_or(false)
}

/// Convert a notify path into source-file changes.
///
/// Some platforms, especially macOS FSEvents and network/container mounts,
/// can report a directory as modified instead of the exact file. When that
/// happens, scan the reported directory for source files so watch mode does
/// not silently miss the change.
fn source_changes_for_path(path: &Path, change_type: ChangeType) -> Vec<FileChange> {
    if is_source_file(path) || is_compile_commands_file(path) || is_git_head_file(path) {
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
/// How long the worktree must be quiet before a branch-switch update window is
/// closed. `git checkout` writes files in bursts with gaps far below this.
const BRANCH_SWITCH_SETTLE: Duration = Duration::from_secs(2);

/// Apply one watch batch to the index. The caller holds the update leases for
/// the repos involved.
async fn apply_changes(engine: &crate::index::CodeIntelEngine, changes: &[FileChange]) {
    match engine.process_file_changes(changes).await {
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
                    // Hold the update leases for every repo this batch touches,
                    // so a query sees the index either before the batch or
                    // after it, never mid-apply.
                    let window = engine
                        .index_update_leases(&engine.repos_for_changes(&changes))
                        .await;
                    let switched = changes.iter().any(|change| is_git_head_file(&change.path));
                    apply_changes(&engine, &changes).await;
                    // HEAD moved: the checkout that follows rewrites many files
                    // across several debounced batches. Keep this one window
                    // open until the worktree goes quiet, so a query sees the
                    // old branch or the new one, never a mixture.
                    if switched {
                        info!("Branch switch detected; holding the index update window");
                        while let Ok(Some(more)) =
                            tokio::time::timeout(BRANCH_SWITCH_SETTLE, rx.recv()).await
                        {
                            for repo in engine.repos_for_changes(&more) {
                                if !window.covers(&repo) {
                                    debug!(
                                        "Changes in {} applied outside the branch-switch window",
                                        repo
                                    );
                                }
                            }
                            apply_changes(&engine, &more).await;
                        }
                        info!("Worktree settled; index update window closed");
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

    /// `.git/HEAD` is the only non-source path the watcher keeps besides
    /// compile_commands.json: it is what opens the branch-switch window. The
    /// rest of `.git` must stay out — an index write on every command would
    /// reopen the window continuously.
    #[test]
    fn git_head_reaches_the_watcher_and_the_rest_of_git_does_not() {
        let head = Path::new("/repo/.git/HEAD");
        assert_eq!(source_changes_for_path(head, ChangeType::Modified).len(), 1);

        for ignored in ["/repo/.git/index", "/repo/.git/ORIG_HEAD", "/repo/HEAD"] {
            assert!(
                source_changes_for_path(Path::new(ignored), ChangeType::Modified).is_empty(),
                "{} must not reach the watcher",
                ignored
            );
        }
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
            call_edges: Vec::new(),
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

    // The indexer logic-version must survive the redb round-trip so a load can
    // detect an index built by an older indexer and force a rebuild.
    #[test]
    fn test_redb_round_trips_logic_version() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();
        let repo = tempdir().unwrap();
        let root = repo.path().to_path_buf();

        // A fresh index carries the running binary's logic version.
        let mut idx = PersistedIndex::new(root.clone());
        assert_eq!(idx.logic_version, INDEX_LOGIC_VERSION);

        // Simulate an index produced by an older indexer.
        idx.logic_version = INDEX_LOGIC_VERSION - 1;
        idx.files
            .insert(root.join("a.rs"), meta(root.join("a.rs"), "h1"));
        store.save_full(&idx).unwrap();

        let loaded = store.load_repo(&root).unwrap();
        assert_eq!(loaded.logic_version, INDEX_LOGIC_VERSION - 1);
    }

    // Persisted call-graph augmentation edges must survive the redb round-trip,
    // else a cache-loaded repo has nothing to replay and re-queries the backends.
    #[test]
    fn test_redb_round_trips_call_edges() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();
        let repo = tempdir().unwrap();
        let root = repo.path().to_path_buf();

        let mut file_meta = meta(root.join("a.c"), "h1");
        file_meta.call_edges.push(PersistedCallEdge {
            caller_key: "a.c::caller".to_string(),
            edge: CallEdge {
                target: "a.c::callee".to_string(),
                file_path: "a.c".to_string(),
                line: 12,
                column: 3,
                call_type: crate::callgraph::CallType::Unknown,
                scope_hint: None,
                confirmed_by: crate::symbols::SourceSet::CCLS,
                line_conflicts: Vec::new(),
            },
        });

        let mut idx = PersistedIndex::new(root.clone());
        idx.files.insert(root.join("a.c"), file_meta);
        store.save_full(&idx).unwrap();

        let loaded = store.load_repo(&root).unwrap();
        let edges = &loaded.files.get(&root.join("a.c")).unwrap().call_edges;
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].caller_key, "a.c::caller");
        assert_eq!(edges[0].edge.target, "a.c::callee");
        assert_eq!(edges[0].edge.line, 12);
        assert!(edges[0]
            .edge
            .confirmed_by
            .contains(crate::symbols::SourceSet::CCLS));
    }

    fn symbol(name: &str, kind: SymbolKind) -> Symbol {
        Symbol {
            name: name.to_string(),
            kind,
            file_path: String::new(),
            start_line: 1,
            end_line: 1,
            signature: None,
            qualified_name: None,
            doc_comment: None,
            confirmed_by: crate::symbols::SourceSet::TREE_SITTER,
            line_conflicts: Vec::new(),
        }
    }

    fn files_defining(store: &IndexStore, root: &Path, name: &str) -> Vec<String> {
        let mut files: Vec<String> = store
            .definitions_of(root, &[name.to_string()])
            .unwrap()
            .into_iter()
            .map(|hit| hit.file)
            .collect();
        files.sort();
        files
    }

    #[test]
    fn definition_map_answers_which_file_defines_a_name() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();
        let repo = tempdir().unwrap();
        let root = repo.path().to_path_buf();

        // No map yet: no stats, and a lookup answers nothing rather than failing.
        assert_eq!(store.definition_stats(&root, None), None);
        assert!(files_defining(&store, &root, "handle").is_empty());

        let mut writer = store.begin_definitions(&root).unwrap();
        writer
            .add_file(
                "src/net.c",
                &[
                    symbol("handle", SymbolKind::Function),
                    symbol("MAX_CONN", SymbolKind::Macro),
                    symbol("conn", SymbolKind::Struct),
                ],
            )
            .unwrap();
        writer
            .add_file("src/util.c", &[symbol("handle", SymbolKind::Method)])
            .unwrap();
        let stats = writer.commit(Some("head1")).unwrap();
        assert_eq!(stats.files, 2);
        assert_eq!(stats.definitions, 2);

        assert_eq!(
            files_defining(&store, &root, "handle"),
            vec!["src/net.c".to_string(), "src/util.c".to_string()]
        );
        // The kind round-trips, so a caller can tell a method from a function.
        let hits = store
            .definitions_of(&root, &["handle".to_string()])
            .unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().any(|hit| hit.kind == SymbolKind::Method));

        // Kinds the include half already covers are not stored: they would
        // multiply the map without pulling anything in.
        assert!(files_defining(&store, &root, "MAX_CONN").is_empty());
        assert!(files_defining(&store, &root, "conn").is_empty());
    }

    /// The (name, file) key is one string, so a shorter name must not pick up
    /// the rows of a longer one that starts with it.
    #[test]
    fn definition_lookup_does_not_leak_across_name_prefixes() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();
        let repo = tempdir().unwrap();
        let root = repo.path().to_path_buf();

        let mut writer = store.begin_definitions(&root).unwrap();
        writer
            .add_file("a.c", &[symbol("read", SymbolKind::Function)])
            .unwrap();
        writer
            .add_file("b.c", &[symbol("read_buffer", SymbolKind::Function)])
            .unwrap();
        writer.commit(None).unwrap();

        assert_eq!(files_defining(&store, &root, "read"), vec!["a.c"]);
        assert_eq!(files_defining(&store, &root, "read_buffer"), vec!["b.c"]);
    }

    /// A map built against one HEAD must not answer for another, and a rebuild
    /// must not leave the previous build's rows behind.
    #[test]
    fn definition_map_is_rejected_when_stale_and_cleared_on_rebuild() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();
        let repo = tempdir().unwrap();
        let root = repo.path().to_path_buf();

        let mut writer = store.begin_definitions(&root).unwrap();
        writer
            .add_file("old.c", &[symbol("gone", SymbolKind::Function)])
            .unwrap();
        writer.commit(Some("head1")).unwrap();

        assert!(store.definition_stats(&root, Some("head1")).is_some());
        assert_eq!(store.definition_stats(&root, Some("head2")), None);
        assert_eq!(store.definition_stats(&root, None), None);

        // A rebuild drops the map until it commits, then answers only for the
        // new content.
        let mut writer = store.begin_definitions(&root).unwrap();
        assert_eq!(store.definition_stats(&root, Some("head1")), None);
        writer
            .add_file("new.c", &[symbol("fresh", SymbolKind::Function)])
            .unwrap();
        writer.commit(Some("head2")).unwrap();

        assert!(files_defining(&store, &root, "gone").is_empty());
        assert_eq!(files_defining(&store, &root, "fresh"), vec!["new.c"]);
    }

    /// A map whose rows were produced under different content rules must be
    /// rebuilt, not answered from — otherwise narrowing what the map stores
    /// leaves every already-built map holding the old set forever.
    #[test]
    fn definition_map_from_another_content_version_is_rejected() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();
        let repo = tempdir().unwrap();
        let root = repo.path().to_path_buf();

        let mut writer = store.begin_definitions(&root).unwrap();
        writer
            .add_file("a.c", &[symbol("handle", SymbolKind::Function)])
            .unwrap();
        writer.commit(None).unwrap();
        assert!(store.definition_stats(&root, None).is_some());

        // Rewrite the header as an older binary's content rules would have.
        let db = store.db(&root).unwrap();
        let write_txn = db.begin_write().unwrap();
        {
            let mut meta_table = write_txn.open_table(META_TABLE).unwrap();
            let mut meta: DefinitionMeta = {
                let guard = meta_table.get(DEFINITION_META_KEY).unwrap().unwrap();
                postcard::from_bytes(guard.value()).unwrap()
            };
            meta.map_version += 1;
            meta_table
                .insert(
                    DEFINITION_META_KEY,
                    postcard::to_stdvec(&meta).unwrap().as_slice(),
                )
                .unwrap();
        }
        write_txn.commit().unwrap();

        assert_eq!(store.definition_stats(&root, None), None);
    }

    #[test]
    fn editing_a_file_retracts_the_definitions_it_no_longer_has() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();
        let repo = tempdir().unwrap();
        let root = repo.path().to_path_buf();

        let mut writer = store.begin_definitions(&root).unwrap();
        writer
            .add_file(
                "a.c",
                &[
                    symbol("kept", SymbolKind::Function),
                    symbol("dropped", SymbolKind::Function),
                ],
            )
            .unwrap();
        writer.commit(None).unwrap();

        store
            .update_file_definitions(
                &root,
                "a.c",
                &[
                    symbol("kept", SymbolKind::Function),
                    symbol("added", SymbolKind::Function),
                ],
            )
            .unwrap();

        assert_eq!(files_defining(&store, &root, "kept"), vec!["a.c"]);
        assert_eq!(files_defining(&store, &root, "added"), vec!["a.c"]);
        assert!(files_defining(&store, &root, "dropped").is_empty());

        store.remove_file_definitions(&root, "a.c").unwrap();
        assert!(files_defining(&store, &root, "kept").is_empty());
    }

    /// A repo with no definition map must not gain a partial one through the
    /// watch path — a map without a header would be invisible to every reader.
    #[test]
    fn per_file_update_is_a_noop_without_a_map() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();
        let repo = tempdir().unwrap();
        let root = repo.path().to_path_buf();

        // Give the repo a normal index, but no definition map.
        store
            .apply_file_changes(&root, &[meta(root.join("a.rs"), "h1")], &[])
            .unwrap();

        store
            .update_file_definitions(&root, "a.rs", &[symbol("thing", SymbolKind::Function)])
            .unwrap();

        assert_eq!(store.definition_stats(&root, None), None);
        assert!(files_defining(&store, &root, "thing").is_empty());
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
