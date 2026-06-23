//! Code Intelligence Engine - main indexing and query implementation
//!
//! This is the core engine that powers all MCP tool operations.

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, info, warn};

use crate::cache::query_cache::{QueryCache, QueryCacheKey, QueryCacheStats, SearchOptions};
use crate::cache::{AnalysisCache, AnalysisCacheKey, CacheStats};
use crate::callgraph::{CallEdge, CallGraph, CallType};
use crate::cfg;
use crate::dfg;
use crate::embeddings::EmbeddingEngine;
use crate::git::GitRepo;
use crate::gtags::GtagsManager;
use crate::lsp::{LspConfig, LspManager};
use crate::metrics::{spawn_flush_task, MemoryReport, Metrics, DEFAULT_FLUSH_INTERVAL};
use crate::neural::{NeuralConfig, NeuralEngine};
use crate::parser::LanguageParser;
use crate::persist::{IndexStore, PersistedIndex};
use crate::remote::RemoteRepoManager;
use crate::search::{build_file_doc, generate_snippet, ConcurrentSearchIndex, SearchDocument};
use crate::streaming::StreamingConfig;
use crate::symbols::{SourceLine, SourceSet, Symbol, SymbolKind};
use crate::type_inference::{TypeError, TypeInferencer};

/// Metadata about an indexed repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoMetadata {
    pub name: String,
    pub path: PathBuf,
    pub file_count: usize,
    pub total_lines: usize,
    pub languages: HashMap<String, LanguageStats>,
    pub last_indexed: SystemTime,
    /// git HEAD and compile_commands.json fingerprint this index was built
    /// against; a mismatch on startup means the cached symbols are stale.
    pub head_hash: Option<String>,
    pub cdb_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LanguageStats {
    pub file_count: usize,
    pub line_count: usize,
    pub byte_count: usize,
}

/// A code excerpt with context
#[derive(Debug, Clone, Serialize)]
pub struct CodeExcerpt {
    pub file_path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub content: String,
    pub language: String,
    pub relevance_score: f32,
}

/// Options for security scanning operations
///
/// Consolidates parameters for `scan_security` to avoid too-many-arguments.
#[derive(Debug, Clone, Default)]
pub struct SecurityScanOptions<'a> {
    /// Optional path filter to scan only matching files
    pub path: Option<&'a str>,
    /// Minimum severity threshold (critical, high, medium, low, info)
    pub severity_threshold: Option<&'a str>,
    /// Comma-separated ruleset tags to filter by
    pub ruleset: Option<&'a str>,
    /// Whether to exclude test files from scanning
    pub exclude_tests: Option<bool>,
    /// Maximum number of findings to return (for pagination)
    pub max_findings: Option<usize>,
    /// Number of findings to skip (for pagination)
    pub offset: Option<usize>,
}

/// Header inserted at the top of every report whose findings come from
/// the pattern-rule engine (scan_security, check_owasp_top10,
/// check_cwe_top25). Most rules are regex token matches and flag *call
/// sites of potentially dangerous patterns*, not verified vulnerabilities.
/// The hint directs the consuming LLM to verify heuristic findings in
/// security-sensitive code in this pass, not defer them — earlier framings
/// that said "site inventory" caused the consumer to dismiss/defer rather
/// than investigate.
const SECURITY_REPORT_HEURISTIC_HINT: &str = r#"> **Heuristic severities — verify before dismissing.**
>
> Most rules in this report (CWE-787-001, CWE-119-001, CWE-125-001, CWE-89-001, ...) are regex token matches: they identify *call sites of dangerous patterns*, not verified vulnerabilities. A smaller set (e.g. CWE-476-002) are analytically verified via tree-sitter dataflow; the rule ID and message indicate which is which.
>
> **For every heuristic finding in security-sensitive code** — setuid/setgid binaries, parsers of untrusted input, IPC handlers, network protocols, anything with attacker-controllable input — verification MUST happen IN THIS PASS, not in a "follow-up" or "separate review":
>
> 1. Locate the destination buffer's allocation site (may be cross-file). Use `get_callers`, `find_call_path`, and `go_to_definition`.
> 2. Compare the allocated size to the actual write width. Format-string expansion counts: `sprintf(buf, "%s#%s", a, b)` writes `strlen(a) + 1 + strlen(b) + 1` bytes, not `strlen(a) + 1`.
> 3. Conclude only after the trace. State explicitly which size each side resolves to.
>
> **Writing "warrants further review" or "recommend a separate pass" for a finding in privileged code is incomplete work — the audit IS the review.** Heuristic findings in clearly non-privileged code (examples, unit tests, fixtures) may be dismissed at scale.
>
> Absent or omitted fields mean narsil could not determine the value, NOT that the value is benign.

"#;

/// Per-backend enable intent recorded at startup. `Auto` defers the decision to
/// each repository — LSP on a `compile_commands.json`, gtags on a GTAGS db — so
/// a multi-repo session can enable a backend for the repos that warrant it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendIntent {
    /// Forced on (`--lsp` / `--gtags`): augment every C/C++ repo.
    On,
    /// Forced off (`--no-lsp` / `--no-gtags`).
    Off,
    /// Decide per repo from what it ships.
    #[default]
    Auto,
}

/// Upper bound on file count for `--gtags-generate`: building a GTAGS database
/// on a very large tree (e.g. the kernel) is slow and writes into the repo, so
/// auto-generation is skipped above this size.
const GTAGS_GENERATE_MAX_FILES: usize = 50_000;

/// Options for configuring the CodeIntelEngine
#[derive(Debug, Clone)]
pub struct EngineOptions {
    /// Enable git integration (blame, history, etc.)
    pub git_enabled: bool,
    /// Enable call graph analysis
    pub call_graph_enabled: bool,
    /// Enable index persistence to disk
    pub persist_enabled: bool,
    /// Enable file watching for incremental updates
    pub watch_enabled: bool,
    /// Enable remote GitHub repository support (gates Remote-category tools).
    /// Mirrors `--remote` so `ToolFilter::convert_engine_options` can surface
    /// `FeatureFlag::Remote` and the Remote tools become visible in
    /// `tools/list`.
    pub remote_enabled: bool,
    /// Streaming configuration
    pub streaming_config: StreamingConfig,
    /// LSP configuration
    pub lsp_config: LspConfig,
    /// Neural embedding configuration
    pub neural_config: NeuralConfig,
    /// Enable analysis caching for expensive operations
    pub cache_enabled: bool,
    /// Cache TTL in seconds (default: 1800 = 30 minutes)
    pub cache_ttl_seconds: u64,
    /// TF-IDF embedding vocabulary size / vector dimension (default: 1000)
    pub embedding_dim: usize,
    /// When true, restrict C/C++ source indexing to files in compile_commands.json
    pub use_compile_commands: bool,
    /// Path to compile_commands.json, relative to the repo root (default: "compile_commands.json")
    pub compile_commands_path: Option<PathBuf>,
    /// Glob patterns (relative to repo root) for files to always index
    pub include: Vec<String>,
    /// Paths/globs (relative to repo root) that additionally get the clangd/ccls
    /// pass. Empty means the whole repo. tree-sitter and gtags are unaffected;
    /// this only bounds the secondary LSP augmentation.
    pub lsp_scope: Vec<String>,
    /// Paths/globs that restrict the base (tree-sitter) index: when set, a repo
    /// with any matching file indexes only matching files (plus --include).
    /// A repo with no match is indexed in full. Empty means the whole repo.
    pub index_filter: Vec<String>,
    /// Per-repo overrides (from a `--profile` config). A repo listed here uses
    /// its own index_filter/lsp_scope/background_index; `lsp_scope`/`index_filter`
    /// above remain the defaults for any repo without an entry.
    pub repo_settings: Vec<crate::config::schema::RepoEntrySettings>,
    /// Enable GNU Global (gtags) as an additional C/C++ reference backend
    pub gtags_enabled: bool,
    /// Per-repo intent for LSP index-time augmentation (On/Off/Auto).
    pub lsp_intent: BackendIntent,
    /// Per-repo intent for gtags index-time augmentation (On/Off/Auto).
    pub gtags_intent: BackendIntent,
    /// Build a GTAGS database (via the `gtags` binary) for C/C++ repos that lack
    /// one. Writes into the repo, so opt-in; size-gated by GTAGS_GENERATE_MAX_FILES.
    pub gtags_generate: bool,
    /// Enable RDF knowledge graph storage (requires graph feature)
    #[cfg(feature = "graph")]
    pub graph_enabled: bool,
    /// Path for knowledge graph storage (defaults to index_path/graph if not set)
    #[cfg(feature = "graph")]
    pub graph_path: Option<std::path::PathBuf>,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            git_enabled: false,
            call_graph_enabled: false,
            persist_enabled: false,
            watch_enabled: false,
            remote_enabled: false,
            streaming_config: StreamingConfig::default(),
            lsp_config: LspConfig::default(),
            neural_config: NeuralConfig::default(),
            cache_enabled: true,
            cache_ttl_seconds: 1800,
            embedding_dim: 1000,
            use_compile_commands: false,
            compile_commands_path: None,
            include: Vec::new(),
            lsp_scope: Vec::new(),
            index_filter: Vec::new(),
            repo_settings: Vec::new(),
            gtags_enabled: false,
            lsp_intent: BackendIntent::default(),
            gtags_intent: BackendIntent::default(),
            gtags_generate: false,
            #[cfg(feature = "graph")]
            graph_enabled: false,
            #[cfg(feature = "graph")]
            graph_path: None,
        }
    }
}

/// One compiled scope entry (`--lsp-scope` / `--index-filter`). A plain path is a
/// recursive directory prefix; an entry with glob metacharacters is matched with
/// `glob`. Matched against both the repo-relative and the absolute path.
#[derive(Clone)]
enum ScopeRule {
    Prefix(String),
    Glob(glob::Pattern),
}

/// Per-repo compiled scope rules and gtags overrides. Built once per repo in
/// `with_options` from the profile entry (falling back to the global
/// `--index-filter`/`--lsp-scope`/`--gtags*` defaults when the entry omits them).
struct CompiledRepoSettings {
    /// Effective `--index-filter` rules for this repo (empty = whole repo).
    index_filter: Vec<ScopeRule>,
    /// Effective `--lsp-scope` rules for this repo (empty = whole repo).
    lsp_scope: Vec<ScopeRule>,
    /// Per-repo gtags enable override (`gtags: { enabled }`). None = global intent.
    gtags_enabled: Option<bool>,
    /// Per-repo gtags auto-generate override (`gtags: { generate }`). None = global flag.
    gtags_generate: Option<bool>,
    /// Per-repo compile_commands coverage threshold (percent). None = global default.
    compile_commands_min_coverage_pct: Option<usize>,
}

/// Compile raw scope entries (paths or globs) into matchers. Invalid globs are
/// downgraded to a literal prefix with a warning.
fn compile_scope(entries: &[String]) -> Vec<ScopeRule> {
    entries
        .iter()
        .filter_map(|entry| {
            let trimmed = entry.trim().trim_end_matches('/');
            if trimmed.is_empty() {
                return None;
            }
            if trimmed.contains(['*', '?', '[']) {
                match glob::Pattern::new(trimmed) {
                    Ok(pattern) => Some(ScopeRule::Glob(pattern)),
                    Err(e) => {
                        warn!("scope: ignoring invalid glob {:?}: {}", trimmed, e);
                        Some(ScopeRule::Prefix(trimmed.to_string()))
                    }
                }
            } else {
                Some(ScopeRule::Prefix(trimmed.to_string()))
            }
        })
        .collect()
}

/// Whether a file (`rel` repo-relative, `abs` absolute) is under any of `rules`.
/// Empty `rules` never matches — callers treat empty as "no scoping".
fn scope_matches(rules: &[ScopeRule], rel: &str, abs: &str) -> bool {
    let under =
        |path: &str, prefix: &str| path == prefix || path.starts_with(&format!("{prefix}/"));
    rules.iter().any(|rule| match rule {
        ScopeRule::Prefix(prefix) => under(rel, prefix) || under(abs, prefix),
        ScopeRule::Glob(pattern) => pattern.matches(rel) || pattern.matches(abs),
    })
}

/// The main code intelligence engine
pub struct CodeIntelEngine {
    /// Base path for index storage (stored for potential future use)
    _index_path: PathBuf,
    /// Registered repository paths
    repo_paths: Vec<PathBuf>,
    /// Cached repo metadata
    repos: DashMap<String, RepoMetadata>,
    /// Symbol index: repo -> symbols
    symbols: DashMap<String, Vec<Symbol>>,
    /// File content cache (path -> content)
    file_cache: DashMap<PathBuf, Arc<String>>,
    /// Language parser
    parser: Arc<LanguageParser>,
    /// Git repository handles (when git is enabled)
    git_repos: DashMap<String, GitRepo>,
    /// Call graphs per repository (when call_graph is enabled)
    call_graphs: DashMap<String, CallGraph>,
    /// Semantic search index
    search_index: Arc<ConcurrentSearchIndex>,
    /// Embedding engine for semantic similarity (TF-IDF)
    embedding_engine: Arc<EmbeddingEngine>,
    /// Neural embedding engine for semantic search (when neural is enabled)
    neural_engine: Option<Arc<NeuralEngine>>,
    /// Engine options (feature flags)
    options: EngineOptions,
    /// Index store for persistence (when persist is enabled)
    /// Performance metrics
    pub metrics: Arc<Metrics>,
    index_store: Option<IndexStore>,
    /// LSP manager for enhanced code analysis (when lsp is enabled)
    lsp_manager: Option<Arc<LspManager>>,
    /// GNU Global manager for C/C++ reference queries (when gtags is enabled)
    gtags_manager: Option<Arc<GtagsManager>>,
    /// Remote repository manager for GitHub integration
    remote_manager: Option<Arc<tokio::sync::Mutex<RemoteRepoManager>>>,
    /// Cached security rules engine (avoids reloading rules on each scan)
    security_engine: Arc<crate::security_rules::SecurityRulesEngine>,
    /// Analysis cache for expensive operations (security scans, call graphs, etc.)
    analysis_cache: Arc<AnalysisCache<AnalysisCacheKey, String>>,
    /// Query result cache for symbol lookups and search operations
    query_cache: Arc<QueryCache>,
    /// Tracks whether background initialization has completed
    initialization_complete: AtomicBool,
    /// Number of repositories that have been fully indexed
    indexed_repos_count: AtomicUsize,
    /// Total number of repositories to index
    total_repos_count: AtomicUsize,
    /// RDF knowledge graph for persistent code intelligence data (when graph is enabled)
    #[cfg(feature = "graph")]
    knowledge_graph: Option<Arc<crate::persistence::KnowledgeGraph>>,
    /// Background task that periodically flushes lifetime metrics to disk.
    /// Aborted on shutdown after a final synchronous flush.
    metrics_flush_task: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Per-repo cached `.gitignore` matcher, so the watch path rejects the same
    /// paths the index-time WalkBuilder would (built lazily on first use).
    gitignore_matchers: DashMap<PathBuf, Arc<ignore::gitignore::Gitignore>>,
    /// Last time a `global -u` ran per repo, to debounce gtags refreshes under
    /// a burst of file events.
    gtags_last_refresh: DashMap<PathBuf, std::time::Instant>,
    /// Global `--lsp-scope` rules, used as the default for any repo without a
    /// per-repo override; empty means the clangd/ccls pass runs repo-wide.
    default_lsp_scope: Vec<ScopeRule>,
    /// Global `--index-filter` rules, used as the default for any repo without a
    /// per-repo override; empty means the whole repo is indexed.
    default_index_filter: Vec<ScopeRule>,
    /// Per-repo compiled scope rules and flags, keyed by canonical repo path.
    /// A repo absent here falls back to the global defaults above.
    repo_settings: std::collections::HashMap<String, CompiledRepoSettings>,
    /// Per-repo memo: true when the repo had >=1 file under `--index-filter`, so
    /// the watch path can drop changes to out-of-scope files. Absent = not
    /// scoped (full index), which keeps unrelated repos untouched.
    index_filtered_repos: DashMap<String, bool>,
}

impl CodeIntelEngine {
    /// Create a new engine with default options (no git, no call graphs, no persistence)
    ///
    /// # Arguments
    /// * `index_path` - Directory path for storing index data
    /// * `repo_paths` - List of repository paths to index
    pub async fn new(index_path: PathBuf, repo_paths: Vec<PathBuf>) -> Result<Self> {
        Self::with_options(index_path, repo_paths, EngineOptions::default()).await
    }

    /// Create a new engine with the specified options
    pub async fn with_options(
        index_path: PathBuf,
        repo_paths: Vec<PathBuf>,
        mut options: EngineOptions,
    ) -> Result<Self> {
        let expanded_index = expand_path(&index_path)?;
        std::fs::create_dir_all(&expanded_index)?;

        let expanded_repos: Vec<PathBuf> = repo_paths
            .iter()
            .map(|p| expand_path(p).unwrap_or_else(|_| p.clone()))
            .collect();

        // Initialize index store for persistence if enabled
        let index_store = if options.persist_enabled {
            match IndexStore::new(expanded_index.clone()) {
                Ok(store) => {
                    info!("Index persistence enabled, storing in {:?}", expanded_index);
                    Some(store)
                }
                Err(e) => {
                    warn!("Failed to initialize index store: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Initialize LSP manager if enabled
        let lsp_manager = if options.lsp_config.enabled {
            info!("LSP integration enabled");
            // Per-repo clangd/ccls tuning, keyed by canonical repo root so it
            // matches the repo encoded in server keys. A field left unset on the
            // config block keeps the RepoLspTuning default (backend on, no dial).
            let mut tuning_map = std::collections::HashMap::new();
            for entry in &options.repo_settings {
                if entry.clangd.is_none() && entry.ccls.is_none() {
                    continue;
                }
                let key = match expand_path(&entry.path).and_then(|p| canonical_repo_key(&p)) {
                    Ok(key) => PathBuf::from(key),
                    Err(e) => {
                        warn!("per-repo LSP tuning ignored for {:?}: {}", entry.path, e);
                        continue;
                    }
                };
                let clangd = entry.clangd.as_ref();
                let ccls = entry.ccls.as_ref();
                tuning_map.insert(
                    key,
                    crate::lsp::RepoLspTuning {
                        clangd_enabled: clangd.and_then(|c| c.enabled).unwrap_or(true),
                        clangd_jobs: clangd.and_then(|c| c.jobs),
                        clangd_background_index: clangd
                            .and_then(|c| c.background_index)
                            .unwrap_or(true),
                        ccls_enabled: ccls.and_then(|c| c.enabled).unwrap_or(true),
                        ccls_threads: ccls.and_then(|c| c.threads),
                        ccls_retain_in_memory: ccls.and_then(|c| c.retain_in_memory),
                        ccls_background_index: ccls
                            .and_then(|c| c.background_index)
                            .unwrap_or(true),
                    },
                );
            }
            if !tuning_map.is_empty() {
                info!(
                    "per-repo clangd/ccls tuning for {} repo(s)",
                    tuning_map.len()
                );
            }
            options.lsp_config.lsp_tuning = tuning_map;
            Some(Arc::new(LspManager::new(
                options.lsp_config.clone(),
                expanded_repos.clone(),
            )))
        } else {
            None
        };

        // Initialize GNU Global manager if enabled
        let gtags_manager = if options.gtags_enabled {
            info!("GNU Global (gtags) integration enabled");
            Some(Arc::new(GtagsManager::new(expanded_repos.clone())))
        } else {
            None
        };

        // Initialize neural engine if enabled
        let neural_engine = if options.neural_config.enabled {
            match NeuralEngine::new(options.neural_config.clone()) {
                Ok(engine) => {
                    info!(
                        "Neural embedding engine initialized (backend={}, model={:?})",
                        options.neural_config.backend, options.neural_config.model_name
                    );
                    Some(Arc::new(engine))
                }
                Err(e) => {
                    warn!(
                        "Failed to initialize neural engine: {}. Run 'narsil-mcp config init --neural' to set up your API key.",
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        // Pre-initialize security rules engine (caches compiled patterns)
        let security_engine = Arc::new(crate::security_rules::SecurityRulesEngine::new());

        // Initialize analysis cache for expensive operations
        let analysis_cache = if options.cache_enabled {
            let ttl = std::time::Duration::from_secs(options.cache_ttl_seconds);
            info!(
                "Analysis cache enabled (TTL: {}s, capacity: 1000)",
                options.cache_ttl_seconds
            );
            Arc::new(AnalysisCache::new(1000, ttl))
        } else {
            // Create a minimal cache even when disabled (0 TTL means immediate expiry)
            Arc::new(AnalysisCache::new(1, std::time::Duration::from_secs(0)))
        };

        // Initialize query cache for symbol lookups and search operations
        let query_cache = if options.cache_enabled {
            let ttl = std::time::Duration::from_secs(options.cache_ttl_seconds);
            info!(
                "Query cache enabled (TTL: {}s, capacity: 2000)",
                options.cache_ttl_seconds
            );
            Arc::new(QueryCache::new(2000, ttl))
        } else {
            // Create a minimal cache even when disabled (0 TTL means immediate expiry)
            Arc::new(QueryCache::new(1, std::time::Duration::from_secs(0)))
        };

        // Initialize knowledge graph if graph feature is enabled
        #[cfg(feature = "graph")]
        let knowledge_graph = if options.graph_enabled {
            let graph_path = options
                .graph_path
                .clone()
                .unwrap_or_else(|| expanded_index.join("graph"));
            match crate::persistence::KnowledgeGraph::open(&graph_path) {
                Ok(graph) => {
                    info!("Knowledge graph opened at {:?}", graph_path);
                    // Load ontology if the graph is new/empty
                    if graph.is_empty() {
                        if let Err(e) = graph.load_ontology() {
                            warn!("Failed to load ontology into knowledge graph: {}", e);
                        } else {
                            info!("Loaded narsil ontology into knowledge graph");
                        }
                    }
                    Some(Arc::new(graph))
                }
                Err(e) => {
                    warn!("Failed to open knowledge graph at {:?}: {}", graph_path, e);
                    None
                }
            }
        } else {
            None
        };

        let total_repos = expanded_repos.len();

        // Lifetime metrics are persisted globally under the user's cache
        // directory, keyed by the canonical index_path so multiple invocations
        // for the same index share a single stats file (ccache-style). This is
        // independent of `--persist`: the file is tiny and the user wants
        // accumulation regardless.
        let metrics = Arc::new(Metrics::with_persistence(expanded_index.clone()));
        let flush_task = spawn_flush_task(Arc::clone(&metrics), DEFAULT_FLUSH_INTERVAL);

        // Compile the global path-scope flags once; these are the defaults for
        // any repo without a per-repo override.
        let default_lsp_scope = compile_scope(&options.lsp_scope);
        let default_index_filter = compile_scope(&options.index_filter);

        // Compile per-repo overrides, keyed by canonical repo path so lookups
        // match canonical_repo_key(repo_path). A repo entry that omits a scope
        // list inherits the corresponding global default.
        let mut repo_settings: std::collections::HashMap<String, CompiledRepoSettings> =
            std::collections::HashMap::new();
        for entry in &options.repo_settings {
            let key = match expand_path(&entry.path).and_then(|p| canonical_repo_key(&p)) {
                Ok(key) => key,
                Err(e) => {
                    warn!(
                        "per-repo config ignored for {:?}: {}",
                        entry.path, e
                    );
                    continue;
                }
            };
            repo_settings.insert(
                key,
                CompiledRepoSettings {
                    index_filter: if entry.index_filter.is_empty() {
                        default_index_filter.clone()
                    } else {
                        compile_scope(&entry.index_filter)
                    },
                    lsp_scope: if entry.lsp_scope.is_empty() {
                        default_lsp_scope.clone()
                    } else {
                        compile_scope(&entry.lsp_scope)
                    },
                    gtags_enabled: entry.gtags.as_ref().and_then(|g| g.enabled),
                    gtags_generate: entry.gtags.as_ref().and_then(|g| g.generate),
                    compile_commands_min_coverage_pct: entry.compile_commands_min_coverage_pct,
                },
            );
        }

        let engine = Self {
            _index_path: expanded_index,
            repo_paths: expanded_repos.clone(),
            repos: DashMap::new(),
            symbols: DashMap::new(),
            file_cache: DashMap::new(),
            parser: Arc::new(LanguageParser::new()?),
            git_repos: DashMap::new(),
            call_graphs: DashMap::new(),
            search_index: Arc::new(ConcurrentSearchIndex::new()),
            embedding_engine: Arc::new(EmbeddingEngine::new(options.embedding_dim)),
            neural_engine,
            options: options.clone(),
            index_store,
            metrics,
            lsp_manager,
            gtags_manager,
            remote_manager: None,
            security_engine,
            analysis_cache,
            query_cache,
            initialization_complete: AtomicBool::new(false),
            indexed_repos_count: AtomicUsize::new(0),
            total_repos_count: AtomicUsize::new(total_repos),
            #[cfg(feature = "graph")]
            knowledge_graph,
            metrics_flush_task: parking_lot::Mutex::new(Some(flush_task)),
            gitignore_matchers: DashMap::new(),
            gtags_last_refresh: DashMap::new(),
            default_lsp_scope,
            default_index_filter,
            repo_settings,
            index_filtered_repos: DashMap::new(),
        };

        // Try to load persisted indexes first if persistence is enabled
        let mut loaded_repos: Vec<String> = Vec::new();
        if options.persist_enabled {
            if let Some(ref store) = engine.index_store {
                for repo_path in &expanded_repos {
                    if let Ok(persisted) = store.load_repo(repo_path) {
                        if !persisted.files.is_empty() {
                            let repo_name = match canonical_repo_key(repo_path) {
                                Ok(k) => k,
                                Err(e) => {
                                    warn!("Skipping cached repo {:?}: {}", repo_path, e);
                                    continue;
                                }
                            };

                            // Load symbols from persisted index
                            let symbols: Vec<Symbol> = persisted
                                .files
                                .values()
                                .flat_map(|f| f.symbols.clone())
                                .collect();

                            info!(
                                "Loaded {} symbols from persisted index for {}",
                                symbols.len(),
                                repo_name
                            );

                            // Calculate metadata from persisted data
                            let mut languages: HashMap<String, LanguageStats> = HashMap::new();
                            let mut total_lines = 0;

                            for file_meta in persisted.files.values() {
                                let ext = file_meta
                                    .path
                                    .extension()
                                    .and_then(|e| e.to_str())
                                    .unwrap_or("unknown");
                                let lang = ext_to_language(ext);
                                let stats = languages.entry(lang).or_default();
                                stats.file_count += 1;
                                stats.byte_count += file_meta.size as usize;
                                // Estimate lines from symbols
                                let max_line = file_meta
                                    .symbols
                                    .iter()
                                    .map(|s| s.end_line)
                                    .max()
                                    .unwrap_or(0);
                                stats.line_count += max_line;
                                total_lines += max_line;
                            }

                            let metadata = RepoMetadata {
                                name: repo_name.clone(),
                                path: repo_path.clone(),
                                file_count: persisted.files.len(),
                                total_lines,
                                languages,
                                last_indexed: SystemTime::UNIX_EPOCH
                                    + std::time::Duration::from_secs(persisted.updated_at),
                                head_hash: persisted.head_hash.clone(),
                                cdb_hash: persisted.cdb_hash.clone(),
                            };

                            engine.repos.insert(repo_name.clone(), metadata);
                            engine.symbols.insert(repo_name.clone(), symbols);
                            loaded_repos.push(repo_name);
                        }
                    }
                }
            }
        }

        // Initialize call graphs BEFORE indexing (must exist for index_repo to populate them)
        if options.call_graph_enabled {
            for repo_path in &expanded_repos {
                if repo_path.exists() {
                    let repo_name = match canonical_repo_key(repo_path) {
                        Ok(k) => k,
                        Err(e) => {
                            warn!("Skipping call graph init for {:?}: {}", repo_path, e);
                            continue;
                        }
                    };
                    let call_graph = CallGraph::new();
                    info!("Call graph initialized for repository: {}", repo_name);
                    engine.call_graphs.insert(repo_name, call_graph);
                }
            }
        }

        // Initialize watch mode if enabled
        if options.watch_enabled {
            info!("Watch mode enabled - monitoring for file changes");
            // Note: Watch mode runs asynchronously. Use process_watch_events() to handle changes.
        }

        // NOTE: We now return the engine IMMEDIATELY without blocking on indexing.
        // This allows the MCP server to respond to initialize requests quickly.
        // Call complete_initialization() to finish indexing in the background.
        info!(
            "Engine created (initialization deferred for {} repos)",
            total_repos
        );

        Ok(engine)
    }

    /// Gracefully stop the metrics flush task and write a final snapshot.
    ///
    /// Should be called before the process exits so the last few minutes of
    /// metrics activity aren't lost. The background flush task is signalled,
    /// performs a final write, then exits; this function awaits it.
    pub async fn shutdown(&self) {
        // Wake the flush task so it writes immediately rather than waiting for
        // the next tick.
        self.metrics.notify_shutdown();
        let handle = self.metrics_flush_task.lock().take();
        if let Some(handle) = handle {
            if let Err(e) = handle.await {
                if !e.is_cancelled() {
                    warn!("Metrics flush task ended abnormally: {}", e);
                }
            }
        }
        // Belt-and-braces: also do an explicit flush in case the task already
        // exited or never started.
        if let Err(e) = self.metrics.flush() {
            warn!("Final metrics flush failed: {}", e);
        }
    }

    /// Complete the deferred initialization by indexing all repositories
    /// and initializing git. This should be called in the background after
    /// the engine is created to allow the MCP server to respond quickly.
    pub async fn complete_initialization(&self) -> Result<()> {
        if self.initialization_complete.load(Ordering::Acquire) {
            info!("Initialization already complete, skipping");
            return Ok(());
        }

        info!("Starting background initialization");

        // For repos loaded from persistence: index_repo still runs to rebuild the
        // BM25 search index and call graph (which are not persisted), but it
        // skips the expensive embedding indexing since symbols are already cached.
        // For repos not in the cache: do a full fresh index and save afterwards.
        let mut any_freshly_indexed = false;

        let total_repos = self.repo_paths.len();
        let mut done_repos = 0;
        for repo_path in &self.repo_paths {
            let repo_name = match canonical_repo_key(repo_path) {
                Ok(k) => k,
                Err(e) => {
                    warn!("Skipping indexing of {:?}: {}", repo_path, e);
                    continue;
                }
            };

            let from_cache = self.repos.contains_key(&repo_name);
            if from_cache {
                info!(
                    "Repository {} loaded from cache; rebuilding search index and call graph",
                    repo_name
                );
            } else {
                info!("Indexing repository: {:?}", repo_path);
            }

            if repo_path.exists() {
                if let Err(e) = self.index_repo(repo_path).await {
                    warn!("Failed to index {:?}: {}", repo_path, e);
                } else {
                    self.indexed_repos_count.fetch_add(1, Ordering::Release);
                    if !from_cache {
                        any_freshly_indexed = true;
                    }
                }
            } else {
                warn!("Repository path does not exist: {:?}", repo_path);
            }
            done_repos += 1;
            info!("Indexed {}/{} repositories: {}", done_repos, total_repos, repo_name);
        }

        // Persist the freshly-built index so subsequent startups skip embedding
        // re-indexing (the expensive serial part).
        if self.options.persist_enabled && any_freshly_indexed {
            if let Err(e) = self.save_index().await {
                warn!("Failed to save index to disk: {}", e);
            }
        }

        // Initialize git repos if enabled
        if self.options.git_enabled {
            for repo_path in &self.repo_paths {
                if repo_path.exists() {
                    let repo_name = match canonical_repo_key(repo_path) {
                        Ok(k) => k,
                        Err(e) => {
                            warn!("Skipping git init for {:?}: {}", repo_path, e);
                            continue;
                        }
                    };

                    match GitRepo::new(repo_path) {
                        Ok(git_repo) => {
                            info!("Git enabled for repository: {}", repo_name);
                            self.git_repos.insert(repo_name, git_repo);
                        }
                        Err(e) => {
                            warn!("Failed to initialize git for {}: {}", repo_name, e);
                        }
                    }
                }
            }
        }

        // Warm clangd now so the cross-validation path is ready before the
        // first C/C++ query, rather than racing a cold preamble/index build.
        if let Some(lsp) = &self.lsp_manager {
            // Servers are per repo, so warm each repo's C/C++ backends rooted at
            // that repo rather than starting a single shared server.
            for repo in self.repos.iter() {
                // gtags-only repos never start a language server.
                if self.lsp_augment_disabled(repo.key()) {
                    continue;
                }
                let mut has_c = false;
                let mut has_cpp = false;
                for lang in repo.value().languages.keys() {
                    match lang.as_str() {
                        "c" | "C" => has_c = true,
                        "cpp" | "C++" => has_cpp = true,
                        _ => {}
                    }
                }
                if !has_c && !has_cpp {
                    continue;
                }
                let repo_path = PathBuf::from(repo.key());
                if has_c {
                    lsp.warm_up(&repo_path, "c").await;
                }
                if has_cpp {
                    lsp.warm_up(&repo_path, "cpp").await;
                }
            }
        }

        self.initialization_complete.store(true, Ordering::Release);
        info!("Background initialization complete");
        // The initial build's transient buffers (parse trees, cleared content
        // strings) are the bulk of glibc's retained high-water mark — trim
        // before measuring so the startup RSS reflects the live working set.
        Self::return_freed_heap_to_os();
        let memory = self.memory_report();
        info!("{}", memory.summary_line());
        // Persist the snapshot so the offline `narsil-mcp stats` command can
        // report it; written by the next periodic/shutdown/Drop flush.
        self.metrics.set_memory_report(memory);

        Ok(())
    }

    /// Check if background initialization has completed
    pub fn is_fully_initialized(&self) -> bool {
        self.initialization_complete.load(Ordering::Acquire)
    }

    /// Get detailed initialization status
    pub fn get_initialization_status(&self) -> HashMap<String, serde_json::Value> {
        let mut status = HashMap::new();
        status.insert(
            "is_initialized".to_string(),
            serde_json::Value::Bool(self.is_fully_initialized()),
        );
        status.insert(
            "indexed_repos".to_string(),
            serde_json::Value::Number(self.indexed_repos_count.load(Ordering::Acquire).into()),
        );
        status.insert(
            "total_repos".to_string(),
            serde_json::Value::Number(self.total_repos_count.load(Ordering::Acquire).into()),
        );
        status.insert(
            "progress_percentage".to_string(),
            serde_json::Value::Number(
                if self.total_repos_count.load(Ordering::Acquire) > 0 {
                    ((self.indexed_repos_count.load(Ordering::Acquire) as f64
                        / self.total_repos_count.load(Ordering::Acquire) as f64)
                        * 100.0) as i64
                } else {
                    100
                }
                .into(),
            ),
        );
        status
    }

    /// Index one symbol's signature into the embedding engine and, when neural
    /// search is enabled, queue it for batch neural indexing. Skips symbols
    /// without a signature (nothing to embed). `symbol.file_path` must already
    /// be the repo-relative path.
    fn index_symbol_embeddings(
        &self,
        symbol: &Symbol,
        neural_docs: &mut Vec<crate::neural::NeuralDocument>,
    ) {
        let sig = match symbol.signature {
            Some(ref sig) => sig,
            None => return,
        };
        let symbol_id = format!("{}::{}", symbol.file_path, symbol.name);
        self.embedding_engine.index_snippet(
            symbol_id.clone(),
            symbol.file_path.clone(),
            sig.clone(),
            symbol.start_line,
            symbol.end_line,
        );
        if self.neural_engine.is_some() {
            neural_docs.push(crate::neural::NeuralDocument {
                id: symbol_id,
                file_path: symbol.file_path.clone(),
                content: sig.clone(),
                start_line: symbol.start_line,
                end_line: symbol.end_line,
                symbol_name: Some(symbol.name.clone()),
            });
        }
    }

    /// Does `repo_path` ship a compile_commands.json clangd can read? Honors an
    /// explicit `--compile-commands-path`, else the conventional locations.
    fn compile_commands_present(&self, repo_path: &Path) -> bool {
        if let Some(rel) = &self.options.compile_commands_path {
            return repo_path.join(rel).exists();
        }
        repo_path.join("compile_commands.json").exists()
            || repo_path.join("build/compile_commands.json").exists()
    }

    /// Candidate compile_commands.json paths for `repo_path`, mirroring the
    /// resolution in `load_compile_commands_filter`.
    fn compile_commands_candidate_paths(&self, repo_path: &Path) -> Vec<PathBuf> {
        match &self.options.compile_commands_path {
            Some(explicit) if explicit.is_absolute() => vec![explicit.clone()],
            Some(explicit) => vec![repo_path.join(explicit)],
            None => vec![
                repo_path.join("compile_commands.json"),
                repo_path.join("build/compile_commands.json"),
            ],
        }
    }

    /// sha256 over the resolved compile_commands.json content, or None when CDB
    /// filtering is off or no CDB is present. Folds candidate files in a fixed
    /// order for determinism; part of the index freshness fingerprint.
    fn compile_commands_hash(&self, repo_path: &Path) -> Option<String> {
        if !self.options.use_compile_commands {
            return None;
        }
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let mut any = false;
        for cdb in self.compile_commands_candidate_paths(repo_path) {
            if let Ok(bytes) = std::fs::read(&cdb) {
                hasher.update(&bytes);
                any = true;
            }
        }
        any.then(|| format!("{:x}", hasher.finalize()))
    }

    /// git HEAD commit hash for `repo_path`, or None when it is not a git
    /// checkout; part of the index freshness fingerprint.
    fn git_head_hash(&self, repo_path: &Path) -> Option<String> {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(repo_path)
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let hash = String::from_utf8(output.stdout).ok()?.trim().to_string();
        (!hash.is_empty()).then_some(hash)
    }

    /// True when the in-memory repo metadata's recorded fingerprint still matches
    /// the repo's current git HEAD and compile_commands.json. A false result
    /// means the cached symbols are stale and must be rebuilt.
    fn fingerprint_matches(&self, repo_name: &str, repo_path: &Path) -> bool {
        let (prior_head, prior_cdb) = match self.repos.get(repo_name) {
            Some(meta) => (meta.head_hash.clone(), meta.cdb_hash.clone()),
            None => return false,
        };
        let head = self.git_head_hash(repo_path);
        let cdb = self.compile_commands_hash(repo_path);
        // With neither a git HEAD nor a compile_commands.json there is no fingerprint
        // to prove freshness, so an in-place edit between restarts would go undetected
        // and stale symbols would be served. Treat the cache as invalid and rebuild.
        if head.is_none() && cdb.is_none() {
            return false;
        }
        prior_head == head && prior_cdb == cdb
    }

    /// Persisted per-file `(content_hash, symbols)` for a repo, keyed by the
    /// repo-relative path, so a fingerprint-triggered rebuild can reuse unchanged
    /// files' symbols instead of re-augmenting them. None when persistence is off
    /// or no prior index exists. Files are persisted only when they have at least
    /// one symbol, whose `file_path` is the repo-relative path.
    fn load_prior_file_symbols(
        &self,
        repo_path: &Path,
    ) -> Option<HashMap<String, (String, Vec<Symbol>)>> {
        let store = self.index_store.as_ref()?;
        let persisted = store.load_repo(repo_path).ok()?;
        let mut by_rel: HashMap<String, (String, Vec<Symbol>)> = HashMap::new();
        for file_meta in persisted.files.into_values() {
            if let Some(rel) = file_meta.symbols.first().map(|s| s.file_path.clone()) {
                by_rel.insert(rel, (file_meta.content_hash, file_meta.symbols));
            }
        }
        Some(by_rel)
    }

    /// Whether LSP augmentation applies to `repo_path` given the recorded intent
    /// and what the repo ships. Does not test for C/C++ presence — callers gate
    /// that per file/symbol.
    fn lsp_repo_enabled(&self, repo_path: &Path) -> bool {
        self.lsp_manager.as_ref().is_some_and(|l| l.is_enabled())
            && match self.options.lsp_intent {
                BackendIntent::On => true,
                BackendIntent::Off => false,
                BackendIntent::Auto => self.compile_commands_present(repo_path),
            }
    }

    /// Per-repo compiled settings for `repo_path`, looked up by canonical key
    /// (matching how `repo_settings` was built). None = no profile entry, so the
    /// global defaults apply.
    fn repo_settings_for_path(&self, repo_path: &Path) -> Option<&CompiledRepoSettings> {
        canonical_repo_key(repo_path)
            .ok()
            .and_then(|key| self.repo_settings.get(&key))
    }

    /// Effective compile_commands coverage threshold (percent) for `repo_path`:
    /// the per-repo `compile_commands_min_coverage_pct` override wins over the
    /// global default.
    fn compile_commands_min_coverage_pct(&self, repo_path: &Path) -> usize {
        self.repo_settings_for_path(repo_path)
            .and_then(|s| s.compile_commands_min_coverage_pct)
            .unwrap_or(COMPILE_COMMANDS_DEFAULT_MIN_COVERAGE_PCT)
    }

    /// Whether gtags is intended for `repo_path`, ignoring whether a GTAGS db
    /// exists yet (used by the auto-generate gate, which runs before the db is
    /// built). The per-repo `gtags: { enabled }` override wins over the global
    /// `--gtags`/`--no-gtags` intent.
    fn gtags_repo_intended(&self, repo_path: &Path) -> bool {
        match self
            .repo_settings_for_path(repo_path)
            .and_then(|s| s.gtags_enabled)
        {
            Some(enabled) => enabled,
            None => self.options.gtags_intent != BackendIntent::Off,
        }
    }

    /// Whether GTAGS should be auto-generated/refreshed for `repo_path`: the
    /// per-repo `gtags: { generate }` override wins over the global
    /// `--gtags-generate` flag.
    fn gtags_generate_for_repo(&self, repo_path: &Path) -> bool {
        self.repo_settings_for_path(repo_path)
            .and_then(|s| s.gtags_generate)
            .unwrap_or(self.options.gtags_generate)
    }

    /// Whether gtags augmentation applies to `repo_path`. A GTAGS database is
    /// required even when intent is `On` (global cannot query without one);
    /// `On` only forces the manager to exist at startup. The per-repo enable
    /// override is folded in via `gtags_repo_intended`.
    fn gtags_repo_enabled(&self, repo_path: &Path) -> bool {
        self.gtags_manager.is_some()
            && self.gtags_repo_intended(repo_path)
            && repo_path.join("GTAGS").exists()
    }

    /// Effective `--index-filter` rules for a repo: its per-repo override if it
    /// has one, else the global default.
    fn repo_index_filter_rules(&self, repo_name: &str) -> &[ScopeRule] {
        self.repo_settings
            .get(repo_name)
            .map(|s| s.index_filter.as_slice())
            .unwrap_or(&self.default_index_filter)
    }

    /// Effective `--lsp-scope` rules for a repo: its per-repo override if it has
    /// one, else the global default.
    fn repo_lsp_scope_rules(&self, repo_name: &str) -> &[ScopeRule] {
        self.repo_settings
            .get(repo_name)
            .map(|s| s.lsp_scope.as_slice())
            .unwrap_or(&self.default_lsp_scope)
    }

    /// Whether `--lsp-scope` applies to this repo (empty = LSP pass runs
    /// repo-wide).
    fn lsp_scope_active(&self, repo_name: &str) -> bool {
        !self.repo_lsp_scope_rules(repo_name).is_empty()
    }

    /// Whether a file is under any `--lsp-scope` entry for this repo. Each entry
    /// is matched against both the repo-relative path and the absolute path, so
    /// a relative entry (e.g. `fs/fuse`) matches that path in any repo, while an
    /// absolute entry (e.g. `/home/u/src/linux.git/fs`) scopes one repo
    /// precisely and never matches another.
    fn lsp_scope_matches(&self, repo_name: &str, rel: &str, abs: &str) -> bool {
        scope_matches(self.repo_lsp_scope_rules(repo_name), rel, abs)
    }

    /// Whether the clangd/ccls augment passes are off for this repo: true when
    /// it enables no C/C++ backend (clangd and ccls both disabled), so it is
    /// indexed with tree-sitter + gtags only.
    fn lsp_augment_disabled(&self, repo_name: &str) -> bool {
        self.lsp_manager
            .as_ref()
            .map(|lsp| lsp.active_cxx_backends_for(Path::new(repo_name)).is_empty())
            .unwrap_or(true)
    }

    /// Whether `--index-filter` restricted this repo's base index (memoized at
    /// index time). Absent = not restricted, so unrelated repos stay full.
    fn repo_index_filtered(&self, repo_name: &str) -> bool {
        self.index_filtered_repos
            .get(repo_name)
            .map(|v| *v)
            .unwrap_or(false)
    }

    /// Whether the additional clangd/ccls pass should run for `rel`. tree-sitter
    /// and gtags always run; this only bounds the LSP layer. `repo_scoped` is true
    /// when the repo has at least one file under `--lsp-scope` (so an unrelated
    /// repo is never silently dropped). In a scoped repo the pass is limited to
    /// matching files that are real C/C++ source TUs — honoring compile_commands
    /// (headers / non-built files are excluded; the `.c` files reaching
    /// augmentation are already compile_commands-filtered, so an extension check
    /// suffices).
    fn lsp_augment_allows(&self, repo_name: &str, repo_scoped: bool, rel: &str, abs: &str) -> bool {
        if self.lsp_augment_disabled(repo_name) {
            return false;
        }
        if !repo_scoped {
            return true;
        }
        let ext = Path::new(rel)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        self.lsp_scope_matches(repo_name, rel, abs) && is_c_source_ext(ext)
    }

    /// Per-repo `.gitignore` matcher (repo `.gitignore` + `.git/info/exclude`),
    /// built once and cached. Mirrors the `git_ignore`/`git_exclude` flags the
    /// index-time `ignore::WalkBuilder` uses so the watch path can reject the
    /// same paths the indexer would.
    fn gitignore_for(&self, repo_path: &Path) -> Arc<ignore::gitignore::Gitignore> {
        if let Some(matcher) = self.gitignore_matchers.get(repo_path) {
            return matcher.clone();
        }
        let mut builder = ignore::gitignore::GitignoreBuilder::new(repo_path);
        builder.add(repo_path.join(".gitignore"));
        builder.add(repo_path.join(".git/info/exclude"));
        let matcher = Arc::new(
            builder
                .build()
                .unwrap_or_else(|_| ignore::gitignore::Gitignore::empty()),
        );
        self.gitignore_matchers
            .insert(repo_path.to_path_buf(), matcher.clone());
        matcher
    }

    /// True when the indexer would never have indexed `abs_path` under
    /// `repo_path` — a dotfile/dir or a `.gitignore`d path — mirroring the
    /// index-time `WalkBuilder` (`hidden(true)` + git ignores). The watch path
    /// consults this so build output written into a watched tree never triggers
    /// a re-index or a gtags refresh (an in-tree kernel build emits `*.o`,
    /// `*.o.d`, `include/generated/*.h`, `*.mod.c`, …).
    fn is_ignored_for_index(&self, repo_path: &Path, abs_path: &Path) -> bool {
        let rel = abs_path.strip_prefix(repo_path).unwrap_or(abs_path);
        // hidden(true): the indexer skips any entry whose name starts with '.'.
        // Covers .git, .ccls-cache, .cache/clangd and hidden Kbuild deps such as
        // arch/x86/boot/.early_serial_console.o.d.
        if rel
            .components()
            .any(|c| c.as_os_str().to_str().is_some_and(|s| s.starts_with('.')))
        {
            return true;
        }
        self.gitignore_for(repo_path)
            .matched_path_or_any_parents(rel, false)
            .is_ignore()
    }

    /// Refresh the GTAGS database for `repo_path` when gtags is the active C/C++
    /// backend, mirroring index_repo's refresh gating. The watch path calls this
    /// wherever it brings clangd back in sync (compile_commands change, source edit)
    /// so the gtags peer backend does not silently drift its line numbers.
    async fn refresh_gtags_if_active(&self, repo_path: &Path) {
        // gtags_repo_enabled == gtags is genuinely active here (manager present,
        // intent not Off, a GTAGS db exists) — i.e. "if gtags is used".
        if !self.gtags_repo_enabled(repo_path) {
            return;
        }
        // Debounce: a burst of edits (e.g. a branch switch touching many files)
        // must not spawn back-to-back full-tree `global -u` passes, each of which
        // re-stats the whole repo. Skip when one ran for this repo recently.
        const GTAGS_REFRESH_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(5);
        if let Some(last) = self.gtags_last_refresh.get(repo_path) {
            if last.elapsed() < GTAGS_REFRESH_DEBOUNCE {
                debug!(
                    "gtags: refresh for {:?} debounced ({:?} since last)",
                    repo_path,
                    last.elapsed()
                );
                return;
            }
        }
        if self.gtags_generate_for_repo(repo_path) && crate::gtags::gtags_binary_present() {
            if let Some(gtags) = &self.gtags_manager {
                self.gtags_last_refresh
                    .insert(repo_path.to_path_buf(), std::time::Instant::now());
                gtags.update_database(repo_path).await; // global -u, incremental
            }
        } else {
            warn!(
                "gtags: {:?} changed under watch but GTAGS was not refreshed (pass \
                 --gtags-generate to refresh automatically); cross-validation degraded.",
                repo_path
            );
        }
    }

    /// Backends enabled for cross-validation on `repo_path`. tree-sitter is
    /// always present; the C/C++ LSP backends and gtags count only for C/C++
    /// data (`is_cxx`) and only when this repo actually enabled them. Gates
    /// provenance annotations — a divergence is only meaningful when at least
    /// two backends were enabled.
    fn enabled_backends_for_repo(&self, repo_path: &Path, is_cxx: bool) -> SourceSet {
        let mut set = SourceSet::TREE_SITTER;
        if is_cxx {
            if self.lsp_repo_enabled(repo_path) {
                if let Some(lsp) = &self.lsp_manager {
                    for backend in lsp.active_cxx_backends_for(repo_path) {
                        set.insert(backend);
                    }
                }
            }
            if self.gtags_repo_enabled(repo_path) {
                set.insert(SourceSet::GTAGS);
            }
        }
        set
    }

    async fn index_repos(&self) -> Result<()> {
        for repo_path in &self.repo_paths {
            if repo_path.exists() {
                info!("Indexing repository: {:?}", repo_path);
                if let Err(e) = self.index_repo(repo_path).await {
                    warn!("Failed to index {:?}: {}", repo_path, e);
                }
            } else {
                warn!("Repository path does not exist: {:?}", repo_path);
            }
        }
        Ok(())
    }

    async fn index_repo(&self, path: &Path) -> Result<()> {
        let start_time = std::time::Instant::now();
        let repo_name = canonical_repo_key(path)?;

        // If symbols are already loaded from the persistence cache, skip the
        // expensive per-symbol embedding indexing — BM25 and call graph still
        // get rebuilt from the parsed files below.
        // A cached repo whose fingerprint still matches needs no symbol work. A
        // mismatch (git HEAD moved or compile_commands.json changed since the
        // index was built) forces a rebuild that reuses unchanged files' persisted
        // symbols. A never-indexed repo is a full build.
        let was_cached = self.symbols.contains_key(&repo_name);
        let symbols_cached = was_cached && self.fingerprint_matches(&repo_name, path);
        let prior_symbols = if was_cached && !symbols_cached {
            info!(
                "index fingerprint changed (HEAD or compile_commands.json) — rebuilding symbols for {}",
                repo_name
            );
            self.load_prior_file_symbols(path)
        } else {
            None
        };

        // C/C++ symbol augmentation (Phases 2/3): clangd/ccls documentSymbol and
        // gtags definitions are folded into the tree-sitter baseline. Whether a
        // backend actually runs is decided per repo *after* parsing (it needs the
        // repo's language set and its compile_commands.json / GTAGS db); here we
        // only decide whether to defer C/C++ symbols for that later pass. Cached
        // repos skip it with the rest of the re-index work.
        let lsp_candidate = self.lsp_manager.as_ref().is_some_and(|l| l.is_enabled())
            && self.options.lsp_intent != BackendIntent::Off;
        let gtags_candidate =
            self.gtags_manager.is_some() && self.options.gtags_intent != BackendIntent::Off;
        let cxx_augment = !symbols_cached && (lsp_candidate || gtags_candidate);
        let mut cxx_groups: Vec<CxxFileSymbols> = Vec::new();

        let mut languages: HashMap<String, LanguageStats> = HashMap::new();
        let mut symbols_vec: Vec<Symbol> = Vec::new();
        let mut neural_docs: Vec<crate::neural::NeuralDocument> = Vec::new();
        let mut file_count = 0;
        let mut total_lines = 0;

        // Use ignore crate to respect .gitignore
        let walker = ignore::WalkBuilder::new(path)
            .hidden(true)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .require_git(false)
            .build();

        let mut files: Vec<PathBuf> = walker
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .map(|e| e.path().to_path_buf())
            .collect();

        // --index-filter: restrict the base index to matching files, but only for
        // a repo that actually contains a match — a repo with none is indexed in
        // full, so unrelated repos are never touched. Files named by --include are
        // force-kept. The decision is memoized for the watch path.
        let index_filter_rules = self.repo_index_filter_rules(&repo_name);
        let repo_index_filtered = !index_filter_rules.is_empty()
            && files.iter().any(|f| {
                let rel = f.strip_prefix(path).unwrap_or(f).to_string_lossy().into_owned();
                scope_matches(index_filter_rules, &rel, &f.to_string_lossy())
            });
        if repo_index_filtered {
            let before = files.len();
            let include = compile_scope(&self.options.include);
            files.retain(|f| {
                let rel = f.strip_prefix(path).unwrap_or(f).to_string_lossy().into_owned();
                let abs = f.to_string_lossy();
                scope_matches(index_filter_rules, &rel, &abs)
                    || scope_matches(&include, &rel, &abs)
            });
            info!(
                "--index-filter: {} → {} files ({} filtered out) in {}",
                before,
                files.len(),
                before - files.len(),
                repo_name
            );
        }
        self.index_filtered_repos
            .insert(repo_name.clone(), repo_index_filtered);

        // A handful of C/C++ files usually means a plain-Makefile project that
        // ships no compile_commands.json; applying the filter there would drop
        // those sources from indexing and warn pointlessly. Engage it only for
        // repos with a real C/C++ build.
        let cxx_source_count = files
            .iter()
            .filter(|f| {
                let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
                is_c_source_ext(ext)
            })
            .count();
        if self.options.use_compile_commands && cxx_source_count >= COMPILE_COMMANDS_MIN_CXX_SOURCES
        {
            let explicit: Option<&Path> = self.options.compile_commands_path.as_deref();
            let compiled = if let Some(p) = explicit {
                load_compile_commands_filter(path, &[p])
            } else {
                load_compile_commands_filter(
                    path,
                    &[
                        Path::new("compile_commands.json"),
                        Path::new("build/compile_commands.json"),
                    ],
                )
            };
            let patterns = compile_include_patterns(&self.options.include);

            // A manifest covering only a sliver of the repo's C sources is
            // stale/partial (e.g. an incremental `bear -- make` that recompiled
            // one TU); honouring it would silently drop nearly every source, so
            // fall back to indexing all sources. clangd still gets the manifest.
            let min_coverage_pct = self.compile_commands_min_coverage_pct(path);
            let covered = files
                .iter()
                .filter(|abs_path| {
                    let ext = abs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    is_c_source_ext(ext) && compiled.contains(abs_path.as_path())
                })
                .count();

            if covered * 100 < cxx_source_count * min_coverage_pct {
                warn!(
                    "compile_commands.json covers only {}/{} C sources (<{}%) for {} — \
                     treating as stale; indexing all sources",
                    covered, cxx_source_count, min_coverage_pct, repo_name
                );
            } else {
                let before = files.len();
                files.retain(|abs_path| {
                    let ext = abs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if is_c_header_ext(ext) {
                        return true;
                    }
                    if !is_c_source_ext(ext) {
                        return true;
                    }
                    if compiled.contains(abs_path.as_path()) {
                        return true;
                    }
                    let rel = abs_path.strip_prefix(path).unwrap_or(abs_path);
                    patterns.iter().any(|p| p.matches_path(rel))
                });
                info!(
                    "compile_commands filter: {} → {} files ({} filtered out)",
                    before,
                    files.len(),
                    before - files.len()
                );
            }
        }

        // Parse files in parallel
        let parse_phase_start = std::time::Instant::now();
        let metrics = Arc::clone(&self.metrics);
        let parsed_results: Vec<_> = files
            .par_iter()
            .filter_map(|file_path| {
                let parse_start = std::time::Instant::now();
                let content = std::fs::read_to_string(file_path).ok()?;
                let parsed = self.parser.parse_file(file_path, &content).ok()?;
                metrics.record_file_parse(parse_start.elapsed());
                Some((file_path.clone(), content, parsed))
            })
            .collect();

        // Tokenize all files in parallel and build SearchDocuments.
        // tokenize_code is the dominant cost of the old serial index_file loop;
        // doing it here with par_iter avoids one write-lock acquisition per file.
        let search_docs: Vec<SearchDocument> = parsed_results
            .par_iter()
            .map(|(file_path, content, _)| {
                let relative_path = file_path
                    .strip_prefix(path)
                    .unwrap_or(file_path)
                    .to_string_lossy()
                    .to_string();
                build_file_doc(&relative_path, content)
            })
            .collect();

        // Collect parsed trees for call graph construction
        let mut trees_for_callgraph: Vec<(String, String, tree_sitter::Tree)> = Vec::new();

        for (file_path, content, parsed) in parsed_results {
            file_count += 1;
            let lines = content.lines().count();
            total_lines += lines;

            // Update language stats
            let lang_stats = languages.entry(parsed.language.clone()).or_default();
            lang_stats.file_count += 1;
            lang_stats.line_count += lines;
            lang_stats.byte_count += content.len();

            // Collect symbols with file path and index for embeddings
            let relative_path = file_path
                .strip_prefix(path)
                .unwrap_or(&file_path)
                .to_string_lossy()
                .to_string();

            if !symbols_cached {
                let is_cxx = is_cxx_language(parsed.language.as_str());
                // On a fingerprint rebuild, an unchanged C/C++ file reuses its
                // persisted (already-augmented) symbols, skipping the costly
                // clangd/gtags round-trip below.
                let reused = if cxx_augment && is_cxx {
                    prior_symbols
                        .as_ref()
                        .and_then(|prior| prior.get(&relative_path))
                        .filter(|(hash, _)| *hash == content_sha256(content.as_bytes()))
                        .map(|(_, symbols)| symbols.clone())
                } else {
                    None
                };

                if let Some(symbols) = reused {
                    for symbol in &symbols {
                        self.index_symbol_embeddings(symbol, &mut neural_docs);
                    }
                    symbols_vec.extend(symbols);
                } else if cxx_augment && is_cxx {
                    // Queue the tree-sitter baseline for the async LSP/gtags pass
                    // below; embeddings happen there once the symbols are merged.
                    let mut symbols = parsed.symbols;
                    for symbol in &mut symbols {
                        symbol.file_path = relative_path.clone();
                    }
                    cxx_groups.push(CxxFileSymbols {
                        abs_path: file_path.clone(),
                        relative_path: relative_path.clone(),
                        symbols,
                    });
                } else {
                    for mut symbol in parsed.symbols {
                        symbol.file_path = relative_path.clone();
                        self.index_symbol_embeddings(&symbol, &mut neural_docs);
                        symbols_vec.push(symbol);
                    }
                }
            }

            // Cache file content
            self.file_cache
                .insert(file_path.clone(), Arc::new(content.clone()));

            // Collect tree for call graph if enabled and tree exists
            if self.options.call_graph_enabled {
                if let Some(tree) = parsed.tree {
                    trees_for_callgraph.push((relative_path, content, tree));
                }
            }
        }

        info!(
            "timing: parsed {} files in {:?} for {}",
            file_count,
            parse_phase_start.elapsed(),
            repo_name
        );

        // Now that parsing has revealed the language set, decide per repo which
        // backends actually run (Auto needs compile_commands.json / a GTAGS db).
        // gtags can build its database on demand first, size-gated, since it
        // writes into the repo tree.
        let cxx_present = languages.keys().any(|lang| is_cxx_language(lang));
        if cxx_present
            && self.gtags_generate_for_repo(path)
            && self.gtags_repo_intended(path)
            && !path.join("GTAGS").exists()
        {
            if file_count > GTAGS_GENERATE_MAX_FILES {
                info!(
                    "gtags: skip auto-generate for {} ({} files > {} limit)",
                    repo_name, file_count, GTAGS_GENERATE_MAX_FILES
                );
            } else if crate::gtags::gtags_binary_present() {
                if let Some(gtags) = &self.gtags_manager {
                    gtags.ensure_database(path).await;
                }
            }
        }
        // An existing GTAGS predating the current sources drifts its line numbers,
        // which the line-window symbol merge cannot pair — silently degrading gtags
        // cross-validation. Refresh it (writes into the repo, so opt-in via
        // --gtags-generate) before the augment runs, else warn.
        if cxx_present
            && self.gtags_repo_intended(path)
            && path.join("GTAGS").exists()
            && gtags_database_stale(path, &files)
        {
            if self.gtags_generate_for_repo(path) && crate::gtags::gtags_binary_present() {
                if let Some(gtags) = &self.gtags_manager {
                    gtags.update_database(path).await;
                }
            } else {
                warn!(
                    "gtags: GTAGS in {:?} is older than indexed sources; symbol \
                     cross-validation will be degraded. Run `global -u` (or pass \
                     --gtags-generate to refresh automatically).",
                    path
                );
            }
        }
        let lsp_for_repo = (cxx_present && self.lsp_repo_enabled(path))
            .then(|| self.lsp_manager.clone())
            .flatten();
        let gtags_for_repo = (cxx_present && self.gtags_repo_enabled(path))
            .then(|| self.gtags_manager.clone())
            .flatten();

        // Phases 2/3: augment the queued C/C++ files with clangd/ccls
        // documentSymbol and gtags definitions. The LSP/gtags calls are async and
        // cannot run inside the rayon parse closure, so they run here, after it.
        // A small semaphore bounds in-flight files to overlap the servers and
        // subprocesses without flooding a single LSP process. Runs before
        // embedding finalisation so the merged symbols are embedded.
        if !cxx_groups.is_empty() && lsp_for_repo.is_none() && gtags_for_repo.is_none() {
            // C/C++ files were deferred but this repo enabled no backend (no
            // compile_commands.json / GTAGS db, or intent Off): embed and store
            // the tree-sitter baseline unchanged.
            for group in cxx_groups {
                for symbol in &group.symbols {
                    self.index_symbol_embeddings(symbol, &mut neural_docs);
                }
                symbols_vec.extend(group.symbols);
            }
        } else if !cxx_groups.is_empty() {
            let doc_sym_start = std::time::Instant::now();
            let doc_sym_files = cxx_groups.len();
            let semaphore = Arc::new(tokio::sync::Semaphore::new(CXX_AUGMENT_CONCURRENCY));
            // When --lsp-scope is given, gate the LSP pass to files under it (only
            // for repos that actually contain a matching file). gtags is unaffected.
            let repo_scoped = self.lsp_scope_active(&repo_name)
                && cxx_groups.iter().any(|g| {
                    self.lsp_scope_matches(
                        &repo_name,
                        &g.relative_path,
                        &g.abs_path.to_string_lossy(),
                    )
                });
            // The repo's enabled C/C++ backends, resolved once; each
            // documentSymbol task filters its calls to these.
            let active_backends = lsp_for_repo
                .as_ref()
                .map(|lsp| lsp.active_cxx_backends_for(Path::new(&repo_name)))
                .unwrap_or_default();
            let mut tasks = tokio::task::JoinSet::new();
            for group in cxx_groups {
                let permit = semaphore.clone().acquire_owned().await?;
                let lsp = if self.lsp_augment_allows(
                    &repo_name,
                    repo_scoped,
                    &group.relative_path,
                    &group.abs_path.to_string_lossy(),
                ) {
                    lsp_for_repo.clone()
                } else {
                    None
                };
                let gtags = gtags_for_repo.clone();
                let repo_path = path.to_path_buf();
                let active_backends = active_backends.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let CxxFileSymbols {
                        abs_path,
                        relative_path,
                        mut symbols,
                    } = group;
                    let lang = get_language_from_path(&abs_path.to_string_lossy());

                    if let Some(lsp) = &lsp {
                        for &backend in &active_backends {
                            match lsp.get_document_symbols(backend, &abs_path, &lang).await {
                                Ok(mut lsp_symbols) => {
                                    for symbol in &mut lsp_symbols {
                                        symbol.file_path = relative_path.clone();
                                    }
                                    merge_symbols(&mut symbols, lsp_symbols, backend);
                                }
                                Err(e) => {
                                    debug!("LSP documentSymbol failed for {:?}: {}", abs_path, e)
                                }
                            }
                        }
                    }

                    if let Some(gtags) = &gtags {
                        let gtags_symbols: Vec<Symbol> = gtags
                            .list_file_symbols(&abs_path, &repo_path)
                            .await
                            .into_iter()
                            .map(|(name, line)| Symbol {
                                name,
                                kind: SymbolKind::Unknown,
                                file_path: relative_path.clone(),
                                start_line: line,
                                end_line: line,
                                signature: None,
                                qualified_name: None,
                                doc_comment: None,
                                confirmed_by: SourceSet::GTAGS,
                                line_conflicts: Vec::new(),
                            })
                            .collect();
                        merge_symbols(&mut symbols, gtags_symbols, SourceSet::GTAGS);
                    }

                    symbols
                });
            }

            while let Some(joined) = tasks.join_next().await {
                match joined {
                    Ok(file_symbols) => {
                        for symbol in &file_symbols {
                            self.index_symbol_embeddings(symbol, &mut neural_docs);
                        }
                        symbols_vec.extend(file_symbols);
                    }
                    Err(e) => warn!("C/C++ symbol augmentation task failed: {}", e),
                }
            }
            info!(
                "timing: cxx documentSymbol+gtags: {} files in {:?} for {}",
                doc_sym_files,
                doc_sym_start.elapsed(),
                repo_name
            );
        }

        // Batch-insert all pre-tokenized search documents under a single write lock.
        self.search_index.batch_add_documents(search_docs);

        // TF-IDF vocabulary finalisation — skip when symbols came from the
        // persistence cache (embedding_engine was not populated this run).
        if !symbols_cached {
            // Build vocabulary and re-embed all snippets with final IDF values.
            // Must happen after the per-file loop so all document frequencies are
            // accumulated before the single O(V log V) sort.
            self.embedding_engine.finalize();
        }

        let symbol_count = if symbols_cached {
            self.symbols.get(&repo_name).map(|s| s.len()).unwrap_or(0)
        } else {
            symbols_vec.len()
        };

        let metadata = RepoMetadata {
            name: repo_name.clone(),
            path: path.to_path_buf(),
            file_count,
            total_lines,
            languages,
            last_indexed: SystemTime::now(),
            head_hash: self.git_head_hash(path),
            cdb_hash: self.compile_commands_hash(path),
        };

        info!(
            "Indexed {} files, {} symbols in {}",
            file_count, symbol_count, repo_name
        );

        // Batch index neural embeddings if enabled (skipped for cached repos)
        if !symbols_cached {
            if let Some(ref neural) = self.neural_engine {
                if !neural_docs.is_empty() {
                    info!(
                        "Generating neural embeddings for {} symbols...",
                        neural_docs.len()
                    );
                    let items: Vec<(crate::neural::NeuralDocument,)> =
                        neural_docs.into_iter().map(|d| (d,)).collect();
                    if let Err(e) = neural.index_batch(&items) {
                        warn!("Failed to batch index neural embeddings: {}", e);
                    } else {
                        info!("Neural embeddings indexed successfully");
                    }
                }
            }
        }

        // Record indexing metrics
        let elapsed = start_time.elapsed();
        self.metrics
            .record_repo_index(repo_name.clone(), elapsed, file_count, symbol_count);

        if !symbols_cached {
            self.repos.insert(repo_name.clone(), metadata);
            self.symbols.insert(repo_name.clone(), symbols_vec);
        }

        // Build call graph if enabled
        if self.options.call_graph_enabled && !trees_for_callgraph.is_empty() {
            if let Some(call_graph) = self.call_graphs.get(&repo_name) {
                let call_graph_start = std::time::Instant::now();
                if let Err(e) = call_graph.build_from_files(&trees_for_callgraph) {
                    warn!("Failed to build call graph for {}: {}", repo_name, e);
                } else {
                    info!(
                        "Built call graph for {} with {} files in {:?}",
                        repo_name,
                        trees_for_callgraph.len(),
                        call_graph_start.elapsed()
                    );
                }
            }
        }

        // Phases 5/6: augment the C/C++ call graph from LSP callHierarchy and
        // gtags references. Same enable gate as the symbol pass; the baseline
        // graph built above provides the nodes merge_edges folds edges onto.
        if self.options.call_graph_enabled
            && (lsp_for_repo.is_some() || gtags_for_repo.is_some())
            && self.call_graphs.contains_key(&repo_name)
        {
            let call_hierarchy_start = std::time::Instant::now();
            self.augment_call_graph_cxx(&repo_name, path, &lsp_for_repo, &gtags_for_repo)
                .await;
            info!(
                "timing: cxx callHierarchy augmentation in {:?} for {}",
                call_hierarchy_start.elapsed(),
                repo_name
            );
        }

        // Transform symbols to RDF knowledge graph if enabled
        #[cfg(feature = "graph")]
        if let Some(ref graph) = self.knowledge_graph {
            use crate::persistence::{RepositoryTransformer, SymbolTransformer};

            // Get the symbols we just indexed
            if let Some(symbols) = self.symbols.get(&repo_name) {
                let symbol_count = symbols.len();
                if let Err(e) = SymbolTransformer::transform_many(graph, &repo_name, symbols.iter())
                {
                    warn!(
                        "Failed to transform symbols to RDF for {}: {}",
                        repo_name, e
                    );
                } else {
                    // Also add repository metadata
                    let file_paths: Vec<String> = symbols
                        .iter()
                        .map(|s| s.file_path.clone())
                        .collect::<std::collections::HashSet<_>>()
                        .into_iter()
                        .collect();
                    if let Err(e) = RepositoryTransformer::transform(
                        graph,
                        &repo_name,
                        file_paths.iter().map(|s| s.as_str()),
                    ) {
                        warn!(
                            "Failed to transform repository metadata to RDF for {}: {}",
                            repo_name, e
                        );
                    } else {
                        info!(
                            "Transformed {} symbols to RDF knowledge graph for {}",
                            symbol_count, repo_name
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Phases 5/6 (C/C++ call-graph augmentation): after the tree-sitter
    /// baseline graph is built, fold in clangd/ccls `callHierarchy` outgoing
    /// calls and gtags reverse references. The LSP/gtags queries are async and
    /// the dominant indexing cost, so they fan out with bounded concurrency;
    /// `merge_edges` is applied serially afterwards (the call graph is not
    /// shared across tasks). Only existing tree-sitter caller/callee nodes are
    /// touched — edges to functions the baseline never saw are dropped.
    async fn augment_call_graph_cxx(
        &self,
        repo_name: &str,
        repo_path: &Path,
        lsp: &Option<Arc<LspManager>>,
        gtags: &Option<Arc<GtagsManager>>,
    ) {
        // C/C++ function/method definitions from the merged symbols: (name,
        // relative file, 1-based definition line).
        let functions: Vec<(String, String, usize)> = match self.symbols.get(repo_name) {
            Some(symbols) => symbols
                .iter()
                .filter(|sym| {
                    matches!(sym.kind, SymbolKind::Function | SymbolKind::Method)
                        && matches!(get_language_from_path(&sym.file_path).as_str(), "c" | "cpp")
                })
                .map(|sym| (sym.name.clone(), sym.file_path.clone(), sym.start_line))
                .collect(),
            None => return,
        };
        if functions.is_empty() {
            return;
        }

        // Phase 5: one task per (function, backend) querying callHierarchy
        // outgoing calls. Each returns its backend bit and the resolved edges;
        // the graph mutation happens serially below.
        let lsp_phase_start = std::time::Instant::now();
        let mut lsp_edges: Vec<(SourceSet, Vec<(String, CallEdge)>)> = Vec::new();
        // gtags-only repos skip the callHierarchy pass entirely: with the
        // background index off it re-parses every TU cold to resolve callees,
        // which is ruinous on a huge tree. Phase 6 (gtags) below still runs.
        // The same cold-reparse bars clangd/ccls without a compile_commands.json:
        // every call then reparses its TU cold, so the pass costs ~one request
        // timeout per function (136s on a 22-file repo) yet every call times out
        // → zero edges. gtags + tree-sitter still build the graph.
        let lsp = lsp.as_ref().filter(|_| {
            !self.lsp_augment_disabled(repo_name) && self.compile_commands_present(repo_path)
        });
        if let Some(lsp) = lsp {
            let backends = lsp.active_cxx_backends_for(Path::new(repo_name));
            // Same --lsp-scope gate as the documentSymbol pass: skip callHierarchy
            // for functions outside the scoped paths in a scoped repo.
            let repo_scoped = self.lsp_scope_active(repo_name)
                && functions.iter().any(|(_, rel, _)| {
                    self.lsp_scope_matches(repo_name, rel, &repo_path.join(rel).to_string_lossy())
                });
            // Group functions by file so each translation unit is opened once and
            // all its functions are queried against that single open document,
            // rather than reopening (and rebuilding the preamble) per function.
            let mut by_file: std::collections::HashMap<String, Vec<(String, u32)>> =
                std::collections::HashMap::new();
            for (name, rel_path, line) in &functions {
                by_file
                    .entry(rel_path.clone())
                    .or_default()
                    .push((name.clone(), *line as u32));
            }
            if !backends.is_empty() {
                let semaphore = Arc::new(tokio::sync::Semaphore::new(CXX_AUGMENT_CONCURRENCY));
                let mut tasks = tokio::task::JoinSet::new();
                // Files skipped because the wall-clock budget elapsed before
                // they could be queried; reported so the truncation is visible.
                let mut budget_skipped: usize = 0;
                // One task per (file, backend); the semaphore runs files in
                // parallel up to CXX_AUGMENT_CONCURRENCY.
                for (rel_path, file_funcs) in by_file {
                    if !self.lsp_augment_allows(
                        repo_name,
                        repo_scoped,
                        &rel_path,
                        &repo_path.join(&rel_path).to_string_lossy(),
                    ) {
                        continue;
                    }
                    let abs_path = match validate_path(repo_path, &rel_path) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    // Stop launching new files once the phase budget is spent;
                    // in-flight tasks drain below. Granularity is one file, so a
                    // file with many functions may overhang the budget slightly.
                    if lsp_phase_start.elapsed() > CXX_CALLHIERARCHY_BUDGET {
                        budget_skipped += 1;
                        continue;
                    }
                    for backend in &backends {
                        let permit = match semaphore.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => break,
                        };
                        let lsp = lsp.clone();
                        let backend = *backend;
                        let rel_path = rel_path.clone();
                        let abs_path = abs_path.clone();
                        let file_funcs = file_funcs.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            let per_func = lsp
                                .call_hierarchy_outgoing_batch(backend, &abs_path, &file_funcs)
                                .await;
                            // per_func is aligned with file_funcs; map each
                            // function's outgoing calls onto its caller edges.
                            let mut edges: Vec<(String, CallEdge)> = Vec::new();
                            for ((name, _line), calls) in file_funcs.iter().zip(per_func) {
                                let caller_key = CallGraph::qualified_key(&rel_path, name);
                                for (callee_name, _callee_file, call_line) in calls {
                                    edges.push((
                                        caller_key.clone(),
                                        CallEdge {
                                            target: callee_name,
                                            file_path: rel_path.clone(),
                                            line: call_line as usize,
                                            column: 0,
                                            call_type: CallType::Unknown,
                                            scope_hint: None,
                                            confirmed_by: backend,
                                            line_conflicts: Vec::new(),
                                        },
                                    ));
                                }
                            }
                            (backend, edges)
                        });
                    }
                }
                while let Some(joined) = tasks.join_next().await {
                    match joined {
                        Ok((backend, edges)) if !edges.is_empty() => {
                            lsp_edges.push((backend, edges))
                        }
                        Ok(_) => {}
                        Err(e) => warn!("LSP callHierarchy task failed: {}", e),
                    }
                }
                if budget_skipped > 0 {
                    warn!(
                        "callHierarchy (LSP) budget {:?} exceeded for {}: {} file(s) \
                         skipped; tree-sitter/gtags edges retained",
                        CXX_CALLHIERARCHY_BUDGET, repo_name, budget_skipped
                    );
                }
            }
        }
        info!(
            "timing: callHierarchy (LSP) in {:?} for {}",
            lsp_phase_start.elapsed(),
            repo_name
        );

        // Phase 6: one task per function fetching gtags reverse references.
        // `global -rx` returns *uses* (which include address-of and
        // declarations, not only resolved calls), so these edges are weaker —
        // recorded via the GTAGS bit so the consumer can tell them apart.
        let gtags_phase_start = std::time::Instant::now();
        let mut gtags_refs: Vec<(String, Vec<(String, usize, String)>)> = Vec::new();
        if let Some(gtags) = gtags {
            let semaphore = Arc::new(tokio::sync::Semaphore::new(CXX_AUGMENT_CONCURRENCY));
            let mut tasks = tokio::task::JoinSet::new();
            for (name, _rel_path, _line) in &functions {
                let permit = match semaphore.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let gtags = gtags.clone();
                let name = name.clone();
                let repo_path = repo_path.to_path_buf();
                tasks.spawn(async move {
                    let _permit = permit;
                    let refs = gtags.find_references(&name, &repo_path).await;
                    (name, refs)
                });
            }
            while let Some(joined) = tasks.join_next().await {
                match joined {
                    Ok((name, refs)) if !refs.is_empty() => gtags_refs.push((name, refs)),
                    Ok(_) => {}
                    Err(e) => warn!("gtags reference task failed: {}", e),
                }
            }
        }
        info!(
            "timing: gtags references in {:?} for {}",
            gtags_phase_start.elapsed(),
            repo_name
        );

        if lsp_edges.is_empty() && gtags_refs.is_empty() {
            return;
        }

        // Serial merge — the call graph is not shared with the async tasks.
        let call_graph = match self.call_graphs.get(repo_name) {
            Some(cg) => cg,
            None => return,
        };

        for (backend, edges) in lsp_edges {
            call_graph.merge_edges(edges, backend);
        }

        // Map each gtags reference site back to its enclosing function (the
        // caller); the queried function is the callee.
        if !gtags_refs.is_empty() {
            if let Some(symbols) = self.symbols.get(repo_name) {
                // enclosing_function_at scans every symbol; calling it per gtags
                // reference is O(refs × symbols) and dominates indexing on large
                // trees. Group function/method symbols by file once so each
                // reference scans only its own file's functions.
                let mut funcs_by_file: std::collections::HashMap<&str, Vec<&Symbol>> =
                    std::collections::HashMap::new();
                for sym in symbols.value() {
                    if matches!(sym.kind, SymbolKind::Function | SymbolKind::Method) {
                        funcs_by_file
                            .entry(sym.file_path.as_str())
                            .or_default()
                            .push(sym);
                    }
                }
                for (callee_name, refs) in gtags_refs {
                    let edges: Vec<(String, CallEdge)> = refs
                        .into_iter()
                        .filter_map(|(rel_file, line, _text)| {
                            let caller = funcs_by_file
                                .get(rel_file.as_str())?
                                .iter()
                                .find(|sym| sym.start_line <= line && line <= sym.end_line)?;
                            Some((
                                CallGraph::qualified_key(&caller.file_path, &caller.name),
                                CallEdge {
                                    target: callee_name.clone(),
                                    file_path: rel_file,
                                    line,
                                    column: 0,
                                    call_type: CallType::Unknown,
                                    scope_hint: None,
                                    confirmed_by: SourceSet::GTAGS,
                                    line_conflicts: Vec::new(),
                                },
                            ))
                        })
                        .collect();
                    if !edges.is_empty() {
                        call_graph.merge_edges(edges, SourceSet::GTAGS);
                    }
                }
            }
        }
    }

    pub async fn reindex_all(&self) -> Result<()> {
        self.repos.clear();
        self.symbols.clear();
        self.file_cache.clear();
        self.search_index.clear();
        self.embedding_engine.clear();
        // Clear all caches on full reindex
        self.analysis_cache.clear();
        self.query_cache.clear();
        let result = self.index_repos().await;
        self.refresh_memory_snapshot();
        result
    }

    pub async fn reindex(&self, repo: Option<&str>) -> Result<String> {
        match repo {
            Some(name) => {
                let repo_key = self.resolve_repo(name)?;
                let path = PathBuf::from(&repo_key);
                self.repos.remove(&repo_key);
                self.symbols.remove(&repo_key);
                // Reset call graph so stale nodes from a branch switch don't linger.
                // build_from_files only inserts/overwrites — it never removes — so
                // functions deleted on the new branch would otherwise persist.
                if self.options.call_graph_enabled {
                    self.call_graphs.insert(repo_key.clone(), CallGraph::new());
                }
                // Invalidate all caches for this repo so stale analysis results
                // (callers, callees, paths) are not served after the rebuild.
                self.query_cache.invalidate_for_repo(&repo_key);
                self.analysis_cache.invalidate_where(|k| k.repo == repo_key);
                self.index_repo(&path).await?;
                self.refresh_memory_snapshot();
                Ok(format!("Re-indexed repository: {}", repo_key))
            }
            None => {
                self.reindex_all().await?;
                Ok("Re-indexed all repositories".to_string())
            }
        }
    }

    /// Resolve a user-supplied repo argument to the canonical absolute path of
    /// an indexed repository.
    ///
    /// Accepts `"."`, a relative path, or an absolute path. The input is
    /// canonicalized (resolving `..`, symlinks, and the current directory) and
    /// then matched against indexed repositories: an exact match returns the
    /// repo root, and any subdirectory of an indexed repo also resolves to
    /// that repo's root (so `"."` from inside a repo subdirectory works).
    ///
    /// Bare short names (e.g. `"linux.git"`) are rejected with an error that
    /// points the caller at `list_repos`: short names cannot disambiguate
    /// between multiple indexed repos that share the same basename, so the
    /// caller must pass a path.
    ///
    /// The returned string is the canonical absolute path as stored in the
    /// engine's repository maps — use it directly as the lookup key.
    fn resolve_repo(&self, input: &str) -> Result<String> {
        if input.is_empty() {
            return Err(self.repo_not_found_error(input));
        }

        // Reject anything that isn't a path-like input. Bare short names are
        // ambiguous (two repos can share a basename), so require an explicit
        // path or ".".
        let looks_like_path = input == "." || input.contains('/') || input.contains('\\');
        if !looks_like_path {
            let repo_paths: Vec<_> = self
                .repos
                .iter()
                .map(|r| r.value().path.display().to_string())
                .collect();
            return Err(anyhow!(
                "Repository '{}' must be passed as an absolute path, relative path, or '.'. \
                 Indexed repositories: {}. \
                 Use list_repos to see all indexed repositories.",
                input,
                repo_paths.join(", ")
            ));
        }

        // Resolve the input to an absolute canonical path on disk.
        let as_path = if input == "." {
            std::env::current_dir().context("Failed to read current directory")?
        } else {
            PathBuf::from(input)
        };
        let canonical_input = as_path
            .canonicalize()
            .with_context(|| format!("Failed to canonicalize repo path '{}'", input))?;

        // Match against indexed repos: exact, or a subdirectory of one.
        for entry in self.repos.iter() {
            let stored = &entry.value().path;
            let stored_canonical = match stored.canonicalize() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if canonical_input == stored_canonical || canonical_input.starts_with(&stored_canonical)
            {
                return Ok(stored_canonical.to_string_lossy().into_owned());
            }
        }

        Err(self.repo_not_found_error(input))
    }

    /// Get a reference to the engine options
    pub fn options(&self) -> &EngineOptions {
        &self.options
    }

    /// Get a reference to the knowledge graph (if enabled).
    ///
    /// Returns `None` if the graph feature is disabled or if graph initialization failed.
    #[cfg(feature = "graph")]
    #[must_use]
    pub fn knowledge_graph(&self) -> Option<Arc<crate::persistence::KnowledgeGraph>> {
        self.knowledge_graph.clone()
    }

    /// Get cache statistics for metrics reporting
    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        self.analysis_cache.stats()
    }

    /// Get query cache statistics for metrics reporting
    #[must_use]
    pub fn query_cache_stats(&self) -> QueryCacheStats {
        self.query_cache.stats()
    }

    /// Check if analysis caching is enabled
    #[must_use]
    pub fn is_cache_enabled(&self) -> bool {
        self.options.cache_enabled
    }

    /// Compute a hash of the repository's file modification times for cache invalidation.
    /// This hash changes when any file in the repo is modified, added, or deleted.
    ///
    /// `repo_key` must be the canonical absolute path string returned by
    /// `resolve_repo`.
    fn compute_repo_hash(&self, repo_key: &str) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        let repo_path = PathBuf::from(repo_key);

        // Collect all file mtimes from this repo
        let mut file_info: Vec<(PathBuf, SystemTime)> = self
            .file_cache
            .iter()
            .filter(|entry| entry.key().starts_with(&repo_path))
            .filter_map(|entry| {
                let path = entry.key().clone();
                std::fs::metadata(&path)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .map(|mtime| (path, mtime))
            })
            .collect();

        // Sort for deterministic ordering
        file_info.sort_by(|a, b| a.0.cmp(&b.0));

        for (path, mtime) in file_info {
            hasher.update(path.to_string_lossy().as_bytes());
            if let Ok(duration) = mtime.duration_since(std::time::UNIX_EPOCH) {
                hasher.update(duration.as_secs().to_le_bytes());
            }
        }

        format!("{:x}", hasher.finalize())
    }

    /// Clear cache entries for a specific repository (e.g., after reindexing)
    pub fn invalidate_cache_for_repo(&self, repo_name: &str) {
        let repo_prefix = repo_name.to_string();
        self.analysis_cache
            .invalidate_where(|key| key.repo == repo_prefix);
    }

    /// Helper to create a helpful error message for missing/invalid repo parameter
    fn repo_not_found_error(&self, repo: &str) -> anyhow::Error {
        if repo.is_empty() {
            let repo_names: Vec<_> = self.repos.iter().map(|r| r.key().clone()).collect();
            if repo_names.is_empty() {
                anyhow!(
                    "Missing required 'repo' parameter. No repositories are indexed yet. \
                     Use --repos flag when starting the server."
                )
            } else {
                anyhow!(
                    "Missing required 'repo' parameter. Available repositories: {}. \
                     Use list_repos to see all indexed repositories.",
                    repo_names.join(", ")
                )
            }
        } else {
            let repo_names: Vec<_> = self.repos.iter().map(|r| r.key().clone()).collect();
            anyhow!(
                "Repository '{}' not found. Available repositories: {}. \
                 Use list_repos to see all indexed repositories.",
                repo,
                repo_names.join(", ")
            )
        }
    }

    pub async fn list_repos(&self) -> Result<String> {
        // Back-compat: the bare form keeps the full per-language detail for all repos.
        self.list_repos_scoped(None, true).await
    }

    /// List indexed repositories, optionally scoped to one and/or with the
    /// per-language breakdown.
    ///
    /// @param[in] repo    Show only this repo (resolved like any `repo` arg); all if None.
    /// @param[in] detail  Emit the per-language file/line table; compact summary if false.
    pub async fn list_repos_scoped(&self, repo: Option<&str>, detail: bool) -> Result<String> {
        let only: Option<String> = match repo {
            Some(r) => Some(self.resolve_repo(r)?),
            None => None,
        };

        let mut output = String::new();
        output.push_str("# Indexed Repositories\n\n");
        output.push_str(
            "Pass the **Repo** value below as the `repo` argument to any tool.\n\
             It is the canonical absolute path of the repository on disk; \
             relative paths and `.` (current directory) are also accepted.\n\n",
        );

        let mut shown = 0usize;
        for entry in self.repos.iter() {
            if only.as_deref().is_some_and(|key| entry.key() != key) {
                continue;
            }
            let repo = entry.value();
            // The map key is the canonical absolute path string; the basename
            // is shown as a friendly label only.
            output.push_str(&format!("## {}\n", repo.name));
            output.push_str(&format!("- **Repo**: `{}`\n", entry.key()));

            if detail {
                output.push_str(&format!("- **Files**: {}\n", repo.file_count));
                output.push_str(&format!("- **Total Lines**: {}\n", repo.total_lines));
                output.push_str("- **Languages**:\n");

                let mut langs: Vec<_> = repo.languages.iter().collect();
                langs.sort_by_key(|(_, stats)| std::cmp::Reverse(stats.line_count));

                for (lang, stats) in langs {
                    output.push_str(&format!(
                        "  - {}: {} files, {} lines\n",
                        lang, stats.file_count, stats.line_count
                    ));
                }
            } else {
                // Compact default: one summary line, no per-language table.
                output.push_str(&format!(
                    "- **Files**: {}, **Lines**: {} (pass `detail=true` for languages)\n",
                    repo.file_count, repo.total_lines
                ));
            }
            output.push('\n');
            shown += 1;
        }

        if self.repos.is_empty() {
            output.push_str("*No repositories indexed yet.*\n");
        } else if shown == 0 {
            output.push_str("*No matching repository.*\n");
        }

        Ok(output)
    }

    pub async fn get_project_structure(&self, repo: &str, max_depth: usize) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let path = PathBuf::from(&repo_key);
        let mut output = String::new();
        output.push_str(&format!("# Project Structure: {}\n\n```\n", repo_key));

        self.build_tree(&path, 0, max_depth, &mut output)?;

        output.push_str("```\n");
        Ok(output)
    }

    fn build_tree(
        &self,
        current: &Path,
        depth: usize,
        max_depth: usize,
        output: &mut String,
    ) -> Result<()> {
        if depth > max_depth {
            return Ok(());
        }

        let indent = "  ".repeat(depth);
        let name = current.file_name().and_then(|n| n.to_str()).unwrap_or(".");

        if current.is_dir() {
            // Skip hidden and common non-essential directories (but not at root level,
            // since the repo itself might be in a hidden directory like ~/.dotfiles)
            if depth > 0
                && (name.starts_with('.')
                    || name == "node_modules"
                    || name == "target"
                    || name == "__pycache__"
                    || name == "venv")
            {
                return Ok(());
            }

            output.push_str(&format!("{}{} {}/\n", indent, "\u{1f4c1}", name));

            let mut entries: Vec<_> = std::fs::read_dir(current)?.filter_map(|e| e.ok()).collect();
            entries.sort_by_key(|e| (!e.path().is_dir(), e.file_name()));

            for entry in entries {
                self.build_tree(&entry.path(), depth + 1, max_depth, output)?;
            }
        } else {
            let size = std::fs::metadata(current).map(|m| m.len()).unwrap_or(0);
            let size_str = format_size(size);
            let icon = get_file_icon(name);
            output.push_str(&format!("{}{} {} ({})\n", indent, icon, name, size_str));
        }

        Ok(())
    }

    pub async fn find_symbols(
        &self,
        repo: &str,
        symbol_type: Option<&str>,
        pattern: Option<&str>,
        file_pattern: Option<&str>,
        exclude_tests: Option<bool>,
        limit: usize,
    ) -> Result<String> {
        use crate::security_rules::is_test_file;

        let repo = self.resolve_repo(repo)?;

        // A missing name filter must not silently dump every symbol in the repo: a
        // misnamed argument (e.g. `query=` before it was aliased, or a typo) lands here
        // with no filter and would return the first `limit` symbols of the whole repo.
        // Refuse with guidance; an explicit `pattern="*"` is the way to list everything.
        if pattern.is_none() && file_pattern.is_none() && symbol_type.is_none() {
            return Ok(format!(
                "# Symbols in {}\n\nNo `pattern` (or `query`) given — refusing to list \
                 every symbol.\nPass a name pattern, e.g. `pattern=\"next_mount_opt\"` or \
                 `pattern=\"fuse_*\"`; use `pattern=\"*\"` to list all.\n",
                repo
            ));
        }

        // Build cache key from query parameters
        let cache_key = {
            let options = SearchOptions {
                file_pattern: file_pattern.map(String::from),
                max_results: Some(limit),
                exclude_tests,
            };
            let query = format!(
                "{}|{}",
                pattern.unwrap_or("*"),
                symbol_type.unwrap_or("all")
            );
            QueryCacheKey::code_search_with_options(Some(repo.as_str()), query, &options)
        };

        // Check cache first
        if self.options.cache_enabled {
            if let Some(cached) = self.query_cache.get(&cache_key) {
                return Ok(cached);
            }
        }

        let symbols = self
            .symbols
            .get(&repo)
            .ok_or_else(|| self.repo_not_found_error(&repo))?;

        let exclude_tests = exclude_tests.unwrap_or(false);

        let type_filter: Option<SymbolKind> = symbol_type.and_then(|t| match t {
            "struct" => Some(SymbolKind::Struct),
            "class" => Some(SymbolKind::Class),
            "enum" => Some(SymbolKind::Enum),
            "interface" => Some(SymbolKind::Interface),
            "function" => Some(SymbolKind::Function),
            "method" => Some(SymbolKind::Method),
            "trait" => Some(SymbolKind::Trait),
            "type" => Some(SymbolKind::TypeAlias),
            _ => None,
        });

        // Compile name pattern: glob when wildcards present, substring otherwise.
        let name_glob: Option<glob::Pattern> = pattern
            .filter(|p| p.contains('*') || p.contains('?'))
            .and_then(|p| glob::Pattern::new(p).ok());
        let glob_opts = glob::MatchOptions {
            case_sensitive: false,
            require_literal_separator: false,
            require_literal_leading_dot: false,
        };

        let file_glob = file_pattern.and_then(|p| glob::Pattern::new(p).ok());

        let mut filtered: Vec<_> = symbols
            .iter()
            .filter(|s| {
                if exclude_tests && is_test_file(&s.file_path) {
                    return false;
                }
                if let Some(ref kind) = type_filter {
                    if &s.kind != kind {
                        return false;
                    }
                }
                // Glob match when wildcards present, substring match otherwise.
                if let Some(ref glob) = name_glob {
                    if !glob.matches_with(&s.name, glob_opts) {
                        return false;
                    }
                } else if let Some(pat) = pattern {
                    if !s.name.to_lowercase().contains(&pat.to_lowercase()) {
                        return false;
                    }
                }
                if let Some(ref glob) = file_glob {
                    if !glob.matches(&s.file_path) {
                        return false;
                    }
                }
                true
            })
            .collect();

        // Surface the most relevant matches within `limit`: exact name (case-insensitive)
        // first, then prefix, then substring/other. Stable sort keeps insertion order on
        // ties, so a specific pattern lands its intended symbol at the top of the window.
        if let Some(pat) = pattern {
            let pat_lc = pat.to_lowercase();
            filtered.sort_by_key(|s| {
                let name_lc = s.name.to_lowercase();
                if name_lc == pat_lc {
                    0u8
                } else if name_lc.starts_with(&pat_lc) {
                    1
                } else {
                    2
                }
            });
        }

        let total = filtered.len();

        // Collect dependent files for smart invalidation (from displayed results only).
        let dependent_files: Vec<String> = filtered
            .iter()
            .take(limit)
            .map(|s| s.file_path.clone())
            .collect();

        let mut output = String::new();
        output.push_str(&format!("# Symbols in {}\n\n", repo));
        if total > limit {
            output.push_str(&format!(
                "Found {} symbols (showing first {}; increase `limit` to see more)\n\n",
                total, limit
            ));
        } else {
            output.push_str(&format!("Found {} symbols\n\n", total));
        }

        // Group displayed results by kind.
        let mut by_kind: HashMap<SymbolKind, Vec<&Symbol>> = HashMap::new();
        for symbol in filtered.iter().copied().take(limit) {
            by_kind.entry(symbol.kind.clone()).or_default().push(symbol);
        }

        let repo_path = PathBuf::from(&repo);
        for (kind, syms) in by_kind {
            output.push_str(&format!("## {:?}s\n\n", kind));
            for sym in syms {
                let is_cxx = matches!(get_language_from_path(&sym.file_path).as_str(), "c" | "cpp");
                let provenance = render_provenance(
                    ProvenanceSubject::Symbol,
                    self.enabled_backends_for_repo(&repo_path, is_cxx),
                    sym.confirmed_by,
                    sym.start_line,
                    &sym.line_conflicts,
                )
                .map(|annotation| format!(" _({})_", annotation))
                .unwrap_or_default();
                output.push_str(&format!(
                    "- **{}** (`{}:{}`) {}{}\n",
                    sym.name,
                    sym.file_path,
                    sym.start_line,
                    sym.signature.as_deref().unwrap_or(""),
                    provenance
                ));
            }
            output.push('\n');
        }

        // Cache the result with file dependencies for smart invalidation.
        if self.options.cache_enabled {
            self.query_cache
                .insert_with_files(cache_key, output.clone(), dependent_files);
        }

        Ok(output)
    }

    /// Render a definition located via gtags when the AST symbol table missed it
    /// (e.g. a file-local static the C parser dropped). gtags yields only the start
    /// line, not an AST end line, so a bounded window after it is shown and the
    /// provenance is flagged as approximate.
    fn render_gtags_definition(
        &self,
        repo_path: &Path,
        symbol_name: &str,
        rel_file: &str,
        start_line: usize,
        context_lines: usize,
    ) -> Result<String> {
        // Number of body lines shown after the definition site, since gtags gives no
        // end line; enough to reveal a typical signature and the start of the body.
        const GTAGS_DEF_WINDOW: usize = 40;

        let file_path = validate_path(repo_path, rel_file)?;
        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;
        let lines: Vec<&str> = content.lines().collect();
        // end is bounded by the file; clamp start so a line number past EOF
        // yields an empty window instead of a slice-index panic.
        let end = (start_line + GTAGS_DEF_WINDOW).min(lines.len());
        let start = start_line.saturating_sub(context_lines + 1).min(end);

        let mut output = String::new();
        output.push_str(&format!("# {}\n\n", symbol_name));
        output.push_str(&format!("**File**: `{}`\n", rel_file));
        output.push_str(&format!("**Line**: {}\n", start_line));
        output.push_str(
            "**Provenance**: located via gtags (GNU Global); the AST symbol table \
             missed it, so the shown body window is approximate\n\n",
        );
        output.push_str("```");
        output.push_str(get_language_id(rel_file));
        output.push('\n');
        for (offset, line) in lines[start..end].iter().enumerate() {
            let line_num = start + offset + 1;
            let marker = if line_num == start_line { "→" } else { " " };
            output.push_str(&format!("{} {:4} │ {}\n", marker, line_num, line));
        }
        output.push_str("```\n");
        Ok(output)
    }

    pub async fn get_symbol_definition(
        &self,
        repo: &str,
        symbol_name: &str,
        context_lines: usize,
    ) -> Result<String> {
        let repo = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo);
        let symbols = self
            .symbols
            .get(&repo)
            .ok_or_else(|| self.repo_not_found_error(&repo))?;

        // Find matching symbol
        let symbol = match symbols
            .iter()
            .find(|s| s.name == symbol_name || s.qualified_name.as_deref() == Some(symbol_name))
        {
            Some(s) => s,
            None => {
                // AST miss (e.g. a file-local static the C parser dropped): consult
                // gtags, which indexes definitions independently of the AST pass.
                if self.gtags_repo_enabled(&repo_path) {
                    if let Some(gtags) = &self.gtags_manager {
                        if let Some((file, line, _)) = gtags
                            .find_definitions(symbol_name, &repo_path)
                            .await
                            .into_iter()
                            .next()
                        {
                            return self.render_gtags_definition(
                                &repo_path,
                                symbol_name,
                                &file,
                                line,
                                context_lines,
                            );
                        }
                    }
                }
                // Still nothing: offer near-miss candidates rather than a bare error,
                // so the caller can re-query instead of falling back to grep.
                let mut hints: Vec<&str> = symbols
                    .iter()
                    .filter(|s| s.name.to_lowercase().contains(&symbol_name.to_lowercase()))
                    .map(|s| s.name.as_str())
                    .collect();
                hints.sort_unstable();
                hints.dedup();
                hints.truncate(10);
                return Err(anyhow!(
                    "Symbol '{}' not found in repository '{}'.{}",
                    symbol_name,
                    repo,
                    if hints.is_empty() {
                        String::new()
                    } else {
                        format!(" Did you mean: {}", hints.join(", "))
                    }
                ));
            }
        };

        let file_path = validate_path(&repo_path, &symbol.file_path)?;
        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let lines: Vec<&str> = content.lines().collect();
        // end is bounded by the file; clamp start so a stale line number past
        // EOF yields an empty window instead of a slice-index panic.
        let end = (symbol.end_line + context_lines).min(lines.len());
        let start = symbol.start_line.saturating_sub(context_lines + 1).min(end);

        let mut output = String::new();
        output.push_str(&format!("# {}\n\n", symbol.name));
        output.push_str(&format!("**File**: `{}`\n", symbol.file_path));
        output.push_str(&format!(
            "**Lines**: {}-{}\n",
            symbol.start_line, symbol.end_line
        ));
        output.push_str(&format!("**Kind**: {:?}\n\n", symbol.kind));
        let is_cxx = matches!(
            get_language_from_path(&symbol.file_path).as_str(),
            "c" | "cpp"
        );
        if let Some(provenance) = render_provenance(
            ProvenanceSubject::Symbol,
            self.enabled_backends_for_repo(&repo_path, is_cxx),
            symbol.confirmed_by,
            symbol.start_line,
            &symbol.line_conflicts,
        ) {
            output.push_str(&format!("**Provenance**: {}\n\n", provenance));
        }

        output.push_str("```");
        output.push_str(get_language_id(&symbol.file_path));
        output.push('\n');

        // Try to get LSP hover info for enhanced information
        if let Some(ref lsp) = self.lsp_manager {
            let language = get_language_from_path(&symbol.file_path);
            if let Ok(Some(hover)) = lsp
                .get_hover(&language, &file_path, symbol.start_line as u32, 0)
                .await
            {
                output.push_str("\n## Type Information (LSP enhanced)\n\n");
                output.push_str(&crate::lsp::hover_to_markdown(&hover));
                output.push('\n');
            }
        }
        for (i, line) in lines[start..end].iter().enumerate() {
            let line_num = start + i + 1;
            let marker = if line_num >= symbol.start_line && line_num <= symbol.end_line {
                "â†’"
            } else {
                " "
            };
            output.push_str(&format!("{} {:4} â”‚ {}\n", marker, line_num, line));
        }

        output.push_str("```\n");

        Ok(output)
    }

    pub async fn search_code(
        &self,
        repo: Option<&str>,
        query: &str,
        file_pattern: Option<&str>,
        max_results: usize,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::security_rules::is_test_file;

        // Build cache key from query parameters
        let cache_key = {
            let options = SearchOptions {
                file_pattern: file_pattern.map(String::from),
                max_results: Some(max_results),
                exclude_tests,
            };
            QueryCacheKey::code_search_with_options(repo, query, &options)
        };

        // Check cache first
        if self.options.cache_enabled {
            if let Some(cached) = self.query_cache.get(&cache_key) {
                return Ok(cached);
            }
        }

        let query_lower = query.to_lowercase();
        let exclude_tests = exclude_tests.unwrap_or(false); // Default false for search
        let mut results: Vec<CodeExcerpt> = Vec::new();

        let repos_to_search: Vec<String> = match repo {
            Some(r) => vec![self.resolve_repo(r)?],
            None => self.repos.iter().map(|r| r.key().clone()).collect(),
        };

        let glob = file_pattern.and_then(|p| glob::Pattern::new(p).ok());

        for repo_name in repos_to_search {
            // After resolve_repo / iteration of self.repos, repo_name is the
            // canonical absolute path used as both the engine's map key and
            // the on-disk repository root.
            let repo_path = PathBuf::from(&repo_name);

            // Search through cached files
            for entry in self.file_cache.iter() {
                let file_path = entry.key();

                // Check if file is in this repo
                if !file_path.starts_with(&repo_path) {
                    continue;
                }

                let rel_path = file_path
                    .strip_prefix(&repo_path)
                    .unwrap_or(file_path)
                    .to_string_lossy();

                // Skip test files if exclude_tests is enabled
                if exclude_tests && is_test_file(&rel_path) {
                    continue;
                }

                // Apply file pattern filter
                if let Some(ref g) = glob {
                    if !g.matches(&rel_path) {
                        continue;
                    }
                }

                let content = entry.value();
                let lines: Vec<&str> = content.lines().collect();

                // Simple text search with scoring
                for (line_num, line) in lines.iter().enumerate() {
                    if line.to_lowercase().contains(&query_lower) {
                        let start = line_num.saturating_sub(3);
                        let end = (line_num + 4).min(lines.len());

                        let excerpt_content: String = lines[start..end]
                            .iter()
                            .enumerate()
                            .map(|(i, l)| format!("{:4} | {}", start + i + 1, l))
                            .collect::<Vec<_>>()
                            .join("\n");

                        // Calculate relevance score
                        let score = calculate_relevance(line, &query_lower);

                        results.push(CodeExcerpt {
                            file_path: rel_path.to_string(),
                            start_line: start + 1,
                            end_line: end,
                            content: excerpt_content,
                            language: get_language_id(&rel_path).to_string(),
                            relevance_score: score,
                        });
                    }
                }
            }
        }

        // Sort by relevance and take top results
        results.sort_by(|a, b| {
            b.relevance_score
                .partial_cmp(&a.relevance_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results.truncate(max_results);

        // Collect dependent files for smart invalidation
        let dependent_files: Vec<String> = results.iter().map(|r| r.file_path.clone()).collect();

        let mut output = String::new();
        output.push_str(&format!("# Search Results for: `{}`\n\n", query));
        output.push_str(&format!("Found {} results\n\n", results.len()));

        for (i, result) in results.iter().enumerate() {
            output.push_str(&format!("## {}. `{}`\n", i + 1, result.file_path));
            output.push_str(&format!(
                "Lines {}-{} | Score: {:.2}\n\n",
                result.start_line, result.end_line, result.relevance_score
            ));
            output.push_str("```");
            output.push_str(&result.language);
            output.push('\n');
            output.push_str(&result.content);
            output.push_str("\n```\n\n");
        }

        // Cache the result with file dependencies for smart invalidation
        if self.options.cache_enabled {
            self.query_cache
                .insert_with_files(cache_key, output.clone(), dependent_files);
        }

        Ok(output)
    }

    pub async fn get_file(
        &self,
        repo: &str,
        path: &str,
        start_line: Option<usize>,
        end_line: Option<usize>,
    ) -> Result<String> {
        let repo_path = PathBuf::from(self.resolve_repo(repo)?);
        let file_path = validate_path(&repo_path, path)?;

        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let lines: Vec<&str> = content.lines().collect();
        let start = start_line.unwrap_or(1).saturating_sub(1);
        let end = end_line.unwrap_or(lines.len()).min(lines.len());

        let mut output = String::new();
        output.push_str(&format!("# {}\n\n", path));
        output.push_str(&format!(
            "Lines {}-{} of {}\n\n",
            start + 1,
            end,
            lines.len()
        ));

        output.push_str("```");
        output.push_str(get_language_id(path));
        output.push('\n');

        for (i, line) in lines[start..end].iter().enumerate() {
            output.push_str(&format!("{:4} â”‚ {}\n", start + i + 1, line));
        }

        output.push_str("```\n");

        Ok(output)
    }

    pub async fn find_references(
        &self,
        repo: &str,
        symbol: &str,
        _include_definition: bool,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::security_rules::is_test_file;

        let repo = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo);
        let exclude_tests = exclude_tests.unwrap_or(false); // Default false for symbol search

        // Phase B3: Run text search and LSP search in parallel
        // Text search is fast (synchronous), LSP can be slow
        // Use tokio::select! to avoid blocking on LSP timeout

        // Check if LSP is enabled before spawning async work
        let lsp_enabled = self
            .lsp_manager
            .as_ref()
            .map(|lsp| lsp.is_enabled())
            .unwrap_or(false);

        // Helper to filter test files from references
        let filter_tests = |refs: Vec<(String, usize, String)>| -> Vec<(String, usize, String)> {
            if exclude_tests {
                refs.into_iter()
                    .filter(|(path, _, _)| !is_test_file(path))
                    .collect()
            } else {
                refs
            }
        };

        if !lsp_enabled {
            // Fast path: no LSP, just do text search
            let text_refs = filter_tests(self.text_search_references(&repo_path, symbol));
            return Ok(self.format_references(&text_refs, false, symbol));
        }

        // LSP is enabled - race text search against LSP with a grace period
        // 1. Do text search immediately (it's fast)
        let text_refs = filter_tests(self.text_search_references(&repo_path, symbol));

        // 2. Try LSP with a short additional timeout (500ms grace period)
        // This way we don't block the full LSP timeout (1.5s) if text search is ready
        let lsp_result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            self.lsp_search_references(&repo, symbol, &repo_path),
        )
        .await;

        // 3. Use LSP results if available and non-empty, otherwise text search
        if let Ok(Some(lsp_refs)) = lsp_result {
            let lsp_refs = filter_tests(lsp_refs);
            if !lsp_refs.is_empty() {
                return Ok(self.format_references(&lsp_refs, true, symbol));
            }
        }

        Ok(self.format_references(&text_refs, false, symbol))
    }

    /// Text-based reference search (fast, synchronous)
    fn text_search_references(
        &self,
        repo_path: &Path,
        symbol: &str,
    ) -> Vec<(String, usize, String)> {
        let mut references = Vec::new();

        for entry in self.file_cache.iter() {
            let file_path = entry.key();
            if !file_path.starts_with(repo_path) {
                continue;
            }

            let rel_path = file_path
                .strip_prefix(repo_path)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            let content = entry.value();
            for (line_num, line) in content.lines().enumerate() {
                if line.contains(symbol) {
                    references.push((rel_path.clone(), line_num + 1, line.trim().to_string()));
                }
            }
        }

        references
    }

    /// 0-based (line, UTF-16 column) of `name` as a whole-word token, scanning
    /// from the definition's start line.
    ///
    /// clangd resolves a symbol from the identifier under the cursor, so a
    /// reference query must anchor on the name token — column 0 sits on the
    /// return type or a leading keyword. The name is usually on the start line
    /// but a return type on its own line pushes it down, so a few lines are
    /// scanned, never past the definition body.
    fn locate_name_anchor(
        content: &str,
        name: &str,
        start_line: usize,
        end_line: usize,
    ) -> Option<(u32, u32)> {
        if name.is_empty() {
            return None;
        }
        let lines: Vec<&str> = content.lines().collect();
        let first = start_line.saturating_sub(1);
        let window_end = (first + 8).min(end_line).min(lines.len());

        for line_idx in first..window_end {
            let line = lines[line_idx];
            let mut search_from = 0;
            while let Some(rel) = line[search_from..].find(name) {
                let byte_idx = search_from + rel;
                let before_ok = line[..byte_idx]
                    .chars()
                    .next_back()
                    .map(|c| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(true);
                let after_idx = byte_idx + name.len();
                let after_ok = line[after_idx..]
                    .chars()
                    .next()
                    .map(|c| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(true);
                if before_ok && after_ok {
                    let col = line[..byte_idx].encode_utf16().count() as u32;
                    return Some((line_idx as u32, col));
                }
                search_from = after_idx;
            }
        }
        None
    }

    /// LSP-based reference search (can be slow, async)
    async fn lsp_search_references(
        &self,
        repo: &str,
        symbol: &str,
        repo_path: &Path,
    ) -> Option<Vec<(String, usize, String)>> {
        let lsp = self.lsp_manager.as_ref()?;
        let symbol_entry = self.symbols.get(repo)?;

        for sym in symbol_entry.iter() {
            if sym.name == symbol || sym.qualified_name.as_deref() == Some(symbol) {
                let file_path = match validate_path(repo_path, &sym.file_path) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let language = get_language_from_path(&sym.file_path);

                // Anchor on the name token (0-based); fall back to the start of
                // the definition line when it cannot be located.
                let (anchor_line, anchor_col) = std::fs::read_to_string(&file_path)
                    .ok()
                    .and_then(|content| {
                        Self::locate_name_anchor(&content, &sym.name, sym.start_line, sym.end_line)
                    })
                    .unwrap_or_else(|| (sym.start_line.saturating_sub(1) as u32, 0));

                let lsp_map = lsp
                    .find_references_parallel(&language, &file_path, anchor_line, anchor_col, true)
                    .await;
                if !lsp_map.is_empty() {
                    let mut seen = std::collections::HashSet::new();
                    let mut references = Vec::new();
                    for locations in lsp_map.into_values() {
                        for loc in locations {
                            if let Ok(path) = loc.uri.to_file_path() {
                                let line_idx = loc.range.start.line as usize;
                                if seen.insert((path.clone(), line_idx)) {
                                    if let Ok(content) = std::fs::read_to_string(&path) {
                                        let lines: Vec<&str> = content.lines().collect();
                                        if line_idx < lines.len() {
                                            let rel = path
                                                .strip_prefix(repo_path)
                                                .unwrap_or(&path)
                                                .to_string_lossy()
                                                .to_string();
                                            references.push((
                                                rel,
                                                line_idx + 1,
                                                lines[line_idx].trim().to_string(),
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !references.is_empty() {
                        return Some(references);
                    }
                }
                break;
            }
        }

        None
    }

    /// Query all enabled reference backends for `symbol` and return per-backend
    /// hit sets. Returns `None` when no backend applies (none enabled, or the
    /// symbol's language has no LSP server and gtags does not apply).
    ///
    /// LSP backends apply to any configured language; gtags (GNU Global) is
    /// C/C++ only. Backend labels: the LSP backend or language id (`"clangd"`,
    /// `"ccls"`, `"rust"`, ...) and `"gtags"`.
    async fn refs_for_symbol(
        &self,
        repo: &str,
        symbol: &str,
        repo_path: &Path,
        symbols: &[Symbol],
    ) -> Option<HashMap<String, Vec<(String, usize, String)>>> {
        // gtags indexes C/C++ only; used to gate the gtags backend below.
        let is_cxx = symbols.iter().any(|s| {
            s.name == symbol && matches!(get_language_from_path(&s.file_path).as_str(), "c" | "cpp")
        });

        let lsp_enabled = self.lsp_manager.as_ref().is_some_and(|l| l.is_enabled());
        let gtags_enabled = self.gtags_manager.is_some();

        if !lsp_enabled && !gtags_enabled {
            return None;
        }

        let mut all: HashMap<String, Vec<(String, usize, String)>> = HashMap::new();

        // LSP backends: find the anchor position then query all backends in parallel
        if lsp_enabled {
            if let Some(lsp) = &self.lsp_manager {
                let symbol_entry = self.symbols.get(repo);
                if let Some(entry) = symbol_entry {
                    for sym in entry.iter() {
                        if sym.name != symbol && sym.qualified_name.as_deref() != Some(symbol) {
                            continue;
                        }
                        let language = get_language_from_path(&sym.file_path);
                        let file_path = match crate::index::validate_path(repo_path, &sym.file_path)
                        {
                            Ok(p) => p,
                            Err(_) => continue,
                        };
                        let (anchor_line, anchor_col) = std::fs::read_to_string(&file_path)
                            .ok()
                            .and_then(|content| {
                                Self::locate_name_anchor(
                                    &content,
                                    &sym.name,
                                    sym.start_line,
                                    sym.end_line,
                                )
                            })
                            .unwrap_or_else(|| (sym.start_line.saturating_sub(1) as u32, 0));

                        let lsp_map = lsp
                            .find_references_parallel(
                                &language,
                                &file_path,
                                anchor_line,
                                anchor_col,
                                true,
                            )
                            .await;

                        for (label, locations) in lsp_map {
                            self.metrics.record_backend_call(&label);
                            let mut refs: Vec<(String, usize, String)> = Vec::new();
                            for loc in locations {
                                if let Ok(path) = loc.uri.to_file_path() {
                                    if let Ok(content) = std::fs::read_to_string(&path) {
                                        let lines: Vec<&str> = content.lines().collect();
                                        let line_idx = loc.range.start.line as usize;
                                        if line_idx < lines.len() {
                                            let rel = path
                                                .strip_prefix(repo_path)
                                                .unwrap_or(&path)
                                                .to_string_lossy()
                                                .to_string();
                                            refs.push((
                                                rel,
                                                line_idx + 1,
                                                lines[line_idx].trim().to_string(),
                                            ));
                                        }
                                    }
                                }
                            }
                            if !refs.is_empty() {
                                all.insert(label, refs);
                            }
                        }
                        break;
                    }
                }
            }
        }

        // gtags backend (C/C++ only)
        if is_cxx {
            if let Some(gtags) = &self.gtags_manager {
                let gtags_refs = gtags.find_references(symbol, repo_path).await;
                self.metrics.record_backend_call("gtags");
                if !gtags_refs.is_empty() {
                    all.insert("gtags".to_string(), gtags_refs);
                }
            }
        }

        if all.is_empty() {
            None
        } else {
            Some(all)
        }
    }

    /// Format references into output string
    fn format_references(
        &self,
        references: &[(String, usize, String)],
        lsp_enhanced: bool,
        symbol: &str,
    ) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "# References to `{}`{}\n\n",
            symbol,
            if lsp_enhanced { " (LSP enhanced)" } else { "" }
        ));
        output.push_str(&format!("Found {} references\n\n", references.len()));

        for (path, line, content) in references {
            output.push_str(&format!(
                "- `{}:{}` - `{}`\n",
                path,
                line,
                if content.len() > 80 {
                    &content[..80]
                } else {
                    content
                }
            ));
        }

        output
    }

    pub async fn get_dependencies(
        &self,
        repo: &str,
        path: &str,
        direction: &str,
    ) -> Result<String> {
        let repo_path = PathBuf::from(self.resolve_repo(repo)?);
        let file_path = validate_path(&repo_path, path)?;

        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let mut output = String::new();
        output.push_str(&format!("# Dependencies for `{}`\n\n", path));

        // Extract imports based on language
        let imports = extract_imports(&content, path);

        if direction == "imports" || direction == "both" {
            output.push_str("## Imports\n\n");
            for import in &imports {
                output.push_str(&format!("- `{}`\n", import));
            }
            output.push('\n');
        }

        if direction == "imported_by" || direction == "both" {
            output.push_str("## Imported By\n\n");

            // Search for files that import this module
            let module_name = Path::new(path)
                .file_stem()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            for entry in self.file_cache.iter() {
                let fp = entry.key();
                if !fp.starts_with(&repo_path) || fp == &file_path {
                    continue;
                }

                let content = entry.value();
                if content.contains(module_name) {
                    let rel_path = fp.strip_prefix(&repo_path).unwrap_or(fp).to_string_lossy();
                    output.push_str(&format!("- `{}`\n", rel_path));
                }
            }
        }

        Ok(output)
    }

    pub async fn read_resource(&self, uri: &str) -> Result<String> {
        // Parse URI like "file:///path/to/file"
        let path_str = uri.strip_prefix("file://").unwrap_or(uri);
        let requested_path = Path::new(path_str);

        // Security: Validate the path is within one of the indexed repositories
        // Try to canonicalize the requested path first
        let canonical_requested = requested_path
            .canonicalize()
            .context("Path does not exist or cannot be accessed")?;

        // Check if the path is within any indexed repository
        for repo_entry in self.repos.iter() {
            let repo_meta = repo_entry.value();
            if let Ok(canonical_root) = repo_meta.path.canonicalize() {
                if canonical_requested.starts_with(&canonical_root) {
                    // Path is within this repository, safe to read
                    return std::fs::read_to_string(&canonical_requested)
                        .context("Failed to read resource");
                }
            }
        }

        // Path is not within any indexed repository - reject the request
        Err(anyhow!(
            "Access denied: path '{}' is outside all indexed repositories",
            path_str
        ))
    }

    // === Persistence Methods ===

    /// Save the current index to disk
    pub async fn save_index(&self) -> Result<String> {
        if !self.options.persist_enabled {
            return Ok(
                "Persistence is not enabled. Start with --persist flag to enable.".to_string(),
            );
        }

        let store = match &self.index_store {
            Some(s) => s,
            None => return Err(anyhow!("Index store not initialized")),
        };

        let mut saved_count = 0;
        for repo_path in &self.repo_paths {
            let repo_name = match canonical_repo_key(repo_path) {
                Ok(k) => k,
                Err(e) => {
                    warn!("Skipping save_index for {:?}: {}", repo_path, e);
                    continue;
                }
            };

            // Create a persisted index from current state. The repo_root field
            // is stored as the canonical absolute path so future loads route
            // through the canonical-keyed index file.
            let mut persisted = PersistedIndex::new(PathBuf::from(&repo_name));
            persisted.head_hash = self.git_head_hash(repo_path);
            persisted.cdb_hash = self.compile_commands_hash(repo_path);

            // Populate with current symbols
            if let Some(symbols) = self.symbols.get(&repo_name) {
                // Group symbols by file path
                let mut by_file: HashMap<String, Vec<Symbol>> = HashMap::new();
                for sym in symbols.iter() {
                    by_file
                        .entry(sym.file_path.clone())
                        .or_default()
                        .push(sym.clone());
                }

                // Create file metadata for each file
                for (file_path, file_symbols) in by_file {
                    let full_path = repo_path.join(&file_path);
                    if let Ok(metadata) = std::fs::metadata(&full_path) {
                        let modified = metadata
                            .modified()
                            .ok()
                            .and_then(|m| m.duration_since(SystemTime::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);

                        let content_hash = if let Ok(content) = std::fs::read(&full_path) {
                            use sha2::{Digest, Sha256};
                            let mut hasher = Sha256::new();
                            hasher.update(&content);
                            format!("{:x}", hasher.finalize())
                        } else {
                            String::new()
                        };

                        persisted.files.insert(
                            full_path.clone(),
                            crate::persist::FileMetadata {
                                path: full_path,
                                content_hash,
                                modified_time: modified,
                                size: metadata.len(),
                                symbols: file_symbols,
                            },
                        );
                    }
                }
            }

            // Save the index (full rewrite — one-time after a fresh index and
            // for the explicit save_index tool; the watch path is incremental).
            // A per-repo failure (e.g. redb lock held by another process) must
            // not abort saving the remaining repos.
            match store.save_full(&persisted) {
                Ok(()) => saved_count += 1,
                Err(e) => warn!("Failed to save index for {}: {}", repo_name, e),
            }
        }

        Ok(format!(
            "Saved {} repository index(es) to disk successfully.",
            saved_count
        ))
    }

    /// Resolved compile_commands.json paths that watch mode must cover, mirroring
    /// the resolution in `index_repo` so the watch set and the load set agree.
    /// Empty when compile_commands filtering is disabled.
    #[cfg(feature = "native")]
    fn compile_commands_watch_paths(&self) -> Vec<PathBuf> {
        if !self.options.use_compile_commands {
            return Vec::new();
        }
        let mut paths = Vec::new();
        match &self.options.compile_commands_path {
            Some(explicit) if explicit.is_absolute() => paths.push(explicit.clone()),
            Some(explicit) => {
                for repo in &self.repo_paths {
                    paths.push(repo.join(explicit));
                }
            }
            None => {
                for repo in &self.repo_paths {
                    paths.push(repo.join("compile_commands.json"));
                    paths.push(repo.join("build/compile_commands.json"));
                }
            }
        }
        paths
    }

    /// Parent directories of out-of-tree compile_commands paths that the watcher
    /// must cover. Watch the directory, not the file: an atomic write-and-rename
    /// replaces the inode and would break a file-level watch. Sibling files that
    /// leak through are dropped later by the repo lookup in `process_file_changes`.
    #[cfg(feature = "native")]
    fn compile_commands_watch_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        for cc_path in self.compile_commands_watch_paths() {
            if let Some(dir) = cc_path.parent() {
                let already_watched = self.repo_paths.iter().any(|r| dir.starts_with(r));
                if dir.exists() && !already_watched && !dirs.contains(&dir.to_path_buf()) {
                    dirs.push(dir.to_path_buf());
                }
            }
        }
        dirs
    }

    /// Create a file watcher for the indexed repositories.
    /// The caller is responsible for managing the watcher lifecycle.
    /// Returns None if watch mode is not enabled.
    #[cfg(feature = "native")]
    pub fn create_file_watcher(&self) -> Option<crate::persist::FileWatcher> {
        if !self.options.watch_enabled {
            return None;
        }

        match crate::persist::FileWatcher::new() {
            Ok(mut watcher) => {
                for repo_path in &self.repo_paths {
                    if repo_path.exists() {
                        if let Err(e) = watcher.watch(repo_path) {
                            warn!("Failed to watch {:?}: {}", repo_path, e);
                        }
                    }
                }
                for dir in self.compile_commands_watch_dirs() {
                    if let Err(e) = watcher.watch(&dir) {
                        warn!("Failed to watch compile_commands dir {:?}: {}", dir, e);
                    }
                }
                Some(watcher)
            }
            Err(e) => {
                warn!("Failed to create file watcher: {}", e);
                None
            }
        }
    }

    /// Create an async file watcher for the indexed repositories.
    /// Returns the watcher and a receiver for batched file change events.
    /// Returns None if watch mode is not enabled.
    #[cfg(feature = "native")]
    pub fn create_async_file_watcher(
        &self,
    ) -> Option<(
        crate::persist::AsyncFileWatcher,
        tokio::sync::mpsc::Receiver<Vec<crate::persist::FileChange>>,
    )> {
        if !self.options.watch_enabled {
            return None;
        }

        match crate::persist::AsyncFileWatcher::new() {
            Ok((mut watcher, rx)) => {
                for repo_path in &self.repo_paths {
                    if repo_path.exists() {
                        if let Err(e) = watcher.watch(repo_path) {
                            warn!("Failed to watch {:?}: {}", repo_path, e);
                        }
                    }
                }
                for dir in self.compile_commands_watch_dirs() {
                    if let Err(e) = watcher.watch(&dir) {
                        warn!("Failed to watch compile_commands dir {:?}: {}", dir, e);
                    }
                }
                Some((watcher, rx))
            }
            Err(e) => {
                warn!("Failed to create async file watcher: {}", e);
                None
            }
        }
    }

    /// The indexed repo a changed compile_commands.json belongs to, matching the
    /// repo's resolved CDB candidate paths (covers out-of-tree build dirs) and
    /// falling back to tree containment.
    fn repo_for_compile_commands(&self, cdb_path: &Path) -> Option<PathBuf> {
        let canon = cdb_path.canonicalize().ok();
        for repo in &self.repo_paths {
            for candidate in self.compile_commands_candidate_paths(repo) {
                if candidate == cdb_path
                    || (canon.is_some() && candidate.canonicalize().ok() == canon)
                {
                    return Some(repo.clone());
                }
            }
            if path_is_within_repo(cdb_path, repo) {
                return Some(repo.clone());
            }
        }
        None
    }

    /// Augment a C/C++ file's tree-sitter `symbols` with clangd/ccls
    /// documentSymbol and gtags definitions, honoring this repo's enabled
    /// backends. The per-file analogue of the index-time augment pass, for the
    /// incremental watch path.
    async fn augment_cxx_symbols(
        &self,
        repo_name: &str,
        abs_path: &Path,
        relative_path: &str,
        repo_path: &Path,
        repo_scoped: bool,
        mut symbols: Vec<Symbol>,
    ) -> Vec<Symbol> {
        if self.lsp_augment_allows(repo_name, repo_scoped, relative_path, &abs_path.to_string_lossy())
            && self.lsp_repo_enabled(repo_path)
        {
            if let Some(lsp) = &self.lsp_manager {
                let lang = get_language_from_path(&abs_path.to_string_lossy());
                for backend in lsp.active_cxx_backends_for(Path::new(repo_name)) {
                    match lsp.get_document_symbols(backend, abs_path, &lang).await {
                        Ok(mut lsp_symbols) => {
                            for symbol in &mut lsp_symbols {
                                symbol.file_path = relative_path.to_string();
                            }
                            merge_symbols(&mut symbols, lsp_symbols, backend);
                        }
                        Err(e) => debug!("LSP documentSymbol failed for {:?}: {}", abs_path, e),
                    }
                }
            }
        }
        if self.gtags_repo_enabled(repo_path) {
            if let Some(gtags) = &self.gtags_manager {
                let gtags_symbols: Vec<Symbol> = gtags
                    .list_file_symbols(abs_path, repo_path)
                    .await
                    .into_iter()
                    .map(|(name, line)| Symbol {
                        name,
                        kind: SymbolKind::Unknown,
                        file_path: relative_path.to_string(),
                        start_line: line,
                        end_line: line,
                        signature: None,
                        qualified_name: None,
                        doc_comment: None,
                        confirmed_by: SourceSet::GTAGS,
                        line_conflicts: Vec::new(),
                    })
                    .collect();
                merge_symbols(&mut symbols, gtags_symbols, SourceSet::GTAGS);
            }
        }
        symbols
    }

    /// Re-index the C/C++ sources a compile_commands.json change adds to or
    /// removes from `repo_path`'s included set: newly-included files are parsed
    /// and augmented (clangd/gtags), dropped files are removed. Headers and
    /// non-C/C++ files are unaffected (never filtered). Returns files changed.
    async fn reindex_compile_commands_delta(&self, repo_path: &Path) -> usize {
        use crate::persist::FileMetadata;
        let repo_name = match canonical_repo_key(repo_path) {
            Ok(k) => k,
            Err(e) => {
                warn!(
                    "compile_commands re-index skipped for {:?}: {}",
                    repo_path, e
                );
                return 0;
            }
        };
        let canon_repo = repo_path
            .canonicalize()
            .unwrap_or_else(|_| repo_path.to_path_buf());

        // Source files clangd now knows about (canonical absolute paths).
        let compiled = if let Some(p) = self.options.compile_commands_path.as_deref() {
            load_compile_commands_filter(repo_path, &[p])
        } else {
            load_compile_commands_filter(
                repo_path,
                &[
                    Path::new("compile_commands.json"),
                    Path::new("build/compile_commands.json"),
                ],
            )
        };

        // C/C++ source files already carrying symbols, by repo-relative path.
        let indexed: std::collections::HashSet<String> = self
            .symbols
            .get(&repo_name)
            .map(|syms| {
                syms.iter()
                    .map(|s| s.file_path.clone())
                    .filter(|p| {
                        Path::new(p)
                            .extension()
                            .and_then(|e| e.to_str())
                            .is_some_and(is_c_source_ext)
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut upserts: Vec<FileMetadata> = Vec::new();
        let mut deletes: Vec<PathBuf> = Vec::new();

        // --lsp-scope gate for this repo: scoped only when some compiled TU lies
        // under a scope entry (else this repo is unaffected).
        let repo_scoped = self.lsp_scope_active(&repo_name)
            && compiled.iter().any(|abs| {
                abs.strip_prefix(&canon_repo)
                    .ok()
                    .map(|rel| {
                        self.lsp_scope_matches(
                            &repo_name,
                            &rel.to_string_lossy(),
                            &abs.to_string_lossy(),
                        )
                    })
                    .unwrap_or(false)
            });

        // Newly-included sources: parse, augment, insert.
        for abs_path in &compiled {
            let relative_path = match abs_path.strip_prefix(&canon_repo) {
                Ok(rel) => rel.to_string_lossy().to_string(),
                Err(_) => continue,
            };
            if indexed.contains(&relative_path) {
                continue;
            }
            // Honor --index-filter on the compile_commands delta too.
            if self.repo_index_filtered(&repo_name)
                && !scope_matches(
                    self.repo_index_filter_rules(&repo_name),
                    &relative_path,
                    &abs_path.to_string_lossy(),
                )
            {
                continue;
            }
            let content = match std::fs::read_to_string(abs_path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let parsed = match self.parser.parse_file(abs_path, &content) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let mut symbols = parsed.symbols;
            for symbol in &mut symbols {
                symbol.file_path = relative_path.clone();
            }
            let symbols = self
                .augment_cxx_symbols(
                    &repo_name,
                    abs_path,
                    &relative_path,
                    repo_path,
                    repo_scoped,
                    symbols,
                )
                .await;

            if let Some(mut entry) = self.symbols.get_mut(&repo_name) {
                entry.retain(|s| s.file_path != relative_path);
                entry.extend(symbols.iter().cloned());
            }
            self.file_cache
                .insert(abs_path.clone(), Arc::new(content.clone()));
            self.search_index.index_file(&relative_path, &content);
            self.query_cache.invalidate_for_file(&relative_path);

            let content_hash = content_sha256(content.as_bytes());
            let (modified_time, size) = std::fs::metadata(abs_path)
                .ok()
                .map(|meta| {
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    (mtime, meta.len())
                })
                .unwrap_or((0, 0));
            upserts.push(FileMetadata {
                path: abs_path.clone(),
                content_hash,
                modified_time,
                size,
                symbols,
            });
        }

        // Sources dropped from the CDB: remove their symbols.
        for relative_path in &indexed {
            let abs = canon_repo.join(relative_path);
            let still_included = abs
                .canonicalize()
                .ok()
                .map(|c| compiled.contains(&c))
                .unwrap_or(false);
            if still_included {
                continue;
            }
            if let Some(mut entry) = self.symbols.get_mut(&repo_name) {
                entry.retain(|s| s.file_path != *relative_path);
            }
            self.file_cache.remove(&abs);
            self.query_cache.invalidate_for_file(relative_path);
            deletes.push(abs);
        }

        let changed = upserts.len() + deletes.len();
        if changed > 0 && self.options.persist_enabled {
            if let Some(store) = &self.index_store {
                if let Err(e) =
                    store.apply_file_changes(&PathBuf::from(&repo_name), &upserts, &deletes)
                {
                    warn!(
                        "Failed to persist compile_commands delta for {}: {}",
                        repo_name, e
                    );
                }
            }
        }
        if changed > 0 {
            info!(
                "compile_commands change: re-indexed {} source file(s) in {}",
                changed, repo_name
            );
        }
        changed
    }

    /// Process file changes detected by the watcher.
    /// Returns the number of files re-indexed.
    pub async fn process_file_changes(
        &self,
        changes: &[crate::persist::FileChange],
    ) -> Result<usize> {
        use crate::persist::{ChangeType, FileMetadata};

        // Per-repo batches so each repo's redb store is updated in one write
        // transaction, touching only changed records — never the whole repo.
        #[derive(Default)]
        struct RepoPending {
            upserts: Vec<FileMetadata>,
            deletes: Vec<PathBuf>,
        }
        let mut pending: HashMap<String, RepoPending> = HashMap::new();

        let mut count = 0;
        // Repos whose C/C++ sources changed this batch, mapped to the changed
        // source paths: their GTAGS db drifts on every edit, so refresh it once
        // per repo after the loop (not per file), and only when actually stale.
        let mut gtags_dirty: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();

        for change in changes {
            // compile_commands.json regenerated → clangd holds stale flags. Restart
            // the C/C++ servers and skip normal re-indexing (it is not a source
            // file). Checked before the repo lookup so an out-of-tree build dir is
            // also handled. Deliberately does not bump `count` or add to
            // `pending`, so it does not trigger a persist on its own.
            if change
                .path
                .file_name()
                .is_some_and(|n| n == "compile_commands.json")
            {
                let cc_repo = self.repo_for_compile_commands(&change.path);
                if let Some(lsp) = &self.lsp_manager {
                    match &cc_repo {
                        Some(repo_path) => {
                            for lang in ["c", "cpp"] {
                                lsp.restart_server(repo_path, lang).await;
                            }
                        }
                        // Out-of-tree build dir we could not map to a repo:
                        // restart every repo's C/C++ servers so none keeps stale
                        // flags. A repo with no running server is a no-op.
                        None => {
                            for repo in &self.repo_paths {
                                for lang in ["c", "cpp"] {
                                    lsp.restart_server(repo, lang).await;
                                }
                            }
                        }
                    }
                }
                // The included C/C++ source set changed: bring symbols in line by
                // indexing newly-added sources (augmented) and dropping removed
                // ones. LSP is restarted first so the augment sees fresh flags.
                if let Some(repo_path) = cc_repo {
                    count += self.reindex_compile_commands_delta(&repo_path).await;
                    // gtags is the peer C/C++ backend: keep its database in sync with
                    // the changed source set, just as clangd was restarted above.
                    self.refresh_gtags_if_active(&repo_path).await;
                }
                continue;
            }

            // Find which repo this file belongs to. Notify may emit canonical
            // paths even when the user supplied a symlinked path (for example
            // `/private/var/...` vs `/var/...` on macOS), so compare both raw
            // and canonical forms.
            let repo_path = self
                .repo_paths
                .iter()
                .find(|p| path_is_within_repo(&change.path, p));

            let repo_path = match repo_path {
                Some(p) => p,
                None => continue,
            };

            // Build artifacts written into a watched tree (e.g. an in-tree kernel
            // build) must never trigger a re-index or a gtags refresh. Mirror the
            // index-time WalkBuilder(hidden + git_ignore) filter so the watch path
            // tracks exactly the files the indexer would.
            if self.is_ignored_for_index(repo_path, &change.path) {
                continue;
            }

            let repo_name = match canonical_repo_key(repo_path) {
                Ok(k) => k,
                Err(e) => {
                    warn!("Skipping re-index of {:?}: {}", change.path, e);
                    continue;
                }
            };

            // --index-filter: in a repo whose base index is restricted, never
            // (re)index a file outside the scope. Repos not restricted are
            // untouched, so this changes nothing for them.
            if self.repo_index_filtered(&repo_name) {
                let rel = change
                    .path
                    .strip_prefix(repo_path)
                    .unwrap_or(&change.path)
                    .to_string_lossy()
                    .into_owned();
                if !scope_matches(
                    self.repo_index_filter_rules(&repo_name),
                    &rel,
                    &change.path.to_string_lossy(),
                ) {
                    continue;
                }
            }

            // A C/C++ source changed (created/modified/deleted): flag the repo so its
            // GTAGS database is refreshed below, keeping the gtags backend in sync.
            if matches!(
                get_language_from_path(&change.path.to_string_lossy()).as_str(),
                "c" | "cpp"
            ) {
                gtags_dirty
                    .entry(repo_path.to_path_buf())
                    .or_default()
                    .push(change.path.clone());
            }

            match change.change_type {
                ChangeType::Created | ChangeType::Modified => {
                    // Re-index the changed file
                    if let Ok(content) = std::fs::read_to_string(&change.path) {
                        if let Ok(parsed) = self.parser.parse_file(&change.path, &content) {
                            let rel_path = change
                                .path
                                .strip_prefix(repo_path)
                                .unwrap_or(&change.path)
                                .to_string_lossy()
                                .to_string();

                            // Build this file's symbols once and reuse them for
                            // both the in-memory index and the persisted record.
                            let mut file_symbols: Vec<_> = parsed
                                .symbols
                                .into_iter()
                                .map(|mut symbol| {
                                    symbol.file_path = rel_path.clone();
                                    symbol
                                })
                                .collect();

                            // Augment with LSP for C/C++ files, mirroring index_repo
                            // phase 2. LSP servers are always current; gtags
                            // augmentation happens after GTAGS is refreshed below.
                            let lang = get_language_from_path(&change.path.to_string_lossy());
                            if matches!(lang.as_str(), "c" | "cpp") {
                                if let Some(lsp) = &self.lsp_manager {
                                    let abs_str = change.path.to_string_lossy();
                                    let repo_scoped = self.lsp_scope_active(&repo_name);
                                    if self.lsp_augment_allows(
                                        &repo_name,
                                        repo_scoped,
                                        &rel_path,
                                        &abs_str,
                                    ) {
                                        let active_backends =
                                            lsp.active_cxx_backends_for(repo_path);
                                        for &backend in &active_backends {
                                            match lsp
                                                .get_document_symbols(
                                                    backend,
                                                    &change.path,
                                                    &lang,
                                                )
                                                .await
                                            {
                                                Ok(mut lsp_syms) => {
                                                    for s in &mut lsp_syms {
                                                        s.file_path = rel_path.clone();
                                                    }
                                                    merge_symbols(
                                                        &mut file_symbols,
                                                        lsp_syms,
                                                        backend,
                                                    );
                                                }
                                                Err(e) => debug!(
                                                    "LSP documentSymbol failed for {:?}: {}",
                                                    change.path, e
                                                ),
                                            }
                                        }
                                    }
                                }
                            }

                            // Update symbols for this file
                            if let Some(mut symbols) = self.symbols.get_mut(&repo_name) {
                                symbols.retain(|s| s.file_path != rel_path);
                                symbols.extend(file_symbols.iter().cloned());
                            }

                            // Update file cache
                            self.file_cache
                                .insert(change.path.clone(), Arc::new(content.clone()));

                            // Update search index
                            self.search_index.index_file(&rel_path, &content);

                            // Smart cache invalidation - only invalidate entries that depend on this file
                            self.query_cache.invalidate_for_file(&rel_path);

                            // Persisted per-file record: hash the content already
                            // read (no second disk read), stat for mtime/size.
                            let content_hash = {
                                use sha2::{Digest, Sha256};
                                let mut hasher = Sha256::new();
                                hasher.update(content.as_bytes());
                                format!("{:x}", hasher.finalize())
                            };
                            let (modified_time, size) = std::fs::metadata(&change.path)
                                .ok()
                                .map(|meta| {
                                    let mtime = meta
                                        .modified()
                                        .ok()
                                        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                                        .map(|d| d.as_secs())
                                        .unwrap_or(0);
                                    (mtime, meta.len())
                                })
                                .unwrap_or((0, 0));
                            pending.entry(repo_name.clone()).or_default().upserts.push(
                                FileMetadata {
                                    path: change.path.clone(),
                                    content_hash,
                                    modified_time,
                                    size,
                                    symbols: file_symbols,
                                },
                            );

                            debug!("Re-indexed file: {}", rel_path);
                            count += 1;
                        }
                    }
                }
                ChangeType::Deleted => {
                    let rel_path = change
                        .path
                        .strip_prefix(repo_path)
                        .unwrap_or(&change.path)
                        .to_string_lossy()
                        .to_string();

                    // Remove symbols for this file
                    if let Some(mut symbols) = self.symbols.get_mut(&repo_name) {
                        symbols.retain(|s| s.file_path != rel_path);
                    }

                    // Remove from file cache
                    self.file_cache.remove(&change.path);

                    // Smart cache invalidation - only invalidate entries that depend on this file
                    self.query_cache.invalidate_for_file(&rel_path);

                    info!("Removed file from index: {}", rel_path);
                    pending
                        .entry(repo_name.clone())
                        .or_default()
                        .deletes
                        .push(change.path.clone());
                    count += 1;
                }
            }
        }

        // Persist only the repos that changed, each in a single redb write
        // transaction. Untouched repos (e.g. the kernel tree) are never opened.
        if self.options.persist_enabled {
            if let Some(store) = &self.index_store {
                for (repo_name, repo_pending) in &pending {
                    if let Err(e) = store.apply_file_changes(
                        &PathBuf::from(repo_name),
                        &repo_pending.upserts,
                        &repo_pending.deletes,
                    ) {
                        warn!("Failed to persist index changes for {}: {}", repo_name, e);
                    }
                }
            }
        }

        // Bring the gtags peer backend in sync for every repo whose C/C++ sources
        // changed — once per repo, since the watcher already debounces/batches.
        // Only pay for a full-tree `global -u` when the DB is actually behind the
        // changed sources (or one was deleted); the refresh itself is debounced.
        for (repo_path, changed) in &gtags_dirty {
            let any_deleted = changed.iter().any(|p| !p.exists());
            if any_deleted || gtags_database_stale(repo_path, changed) {
                self.refresh_gtags_if_active(repo_path).await;
            } else {
                debug!(
                    "gtags: {:?} already current vs {} changed source(s); skip global -u",
                    repo_path,
                    changed.len()
                );
            }
        }

        // Augment changed C/C++ file symbols from gtags, now that global -u has
        // run and the GTAGS database reflects the current sources. Mirrors
        // index_repo phase 3 for the incremental path.
        if let Some(gtags) = &self.gtags_manager {
            for (repo_path, changed) in &gtags_dirty {
                if !self.gtags_repo_enabled(repo_path) {
                    continue;
                }
                let repo_name = match canonical_repo_key(repo_path) {
                    Ok(k) => k,
                    Err(_) => continue,
                };
                for abs_path in changed {
                    if !abs_path.exists() {
                        continue; // deleted — symbols already removed above
                    }
                    let rel_path = abs_path
                        .strip_prefix(repo_path)
                        .unwrap_or(abs_path)
                        .to_string_lossy()
                        .to_string();
                    let gtags_syms: Vec<Symbol> = gtags
                        .list_file_symbols(abs_path, repo_path)
                        .await
                        .into_iter()
                        .map(|(name, line)| Symbol {
                            name,
                            kind: SymbolKind::Unknown,
                            file_path: rel_path.clone(),
                            start_line: line,
                            end_line: line,
                            signature: None,
                            qualified_name: None,
                            doc_comment: None,
                            confirmed_by: SourceSet::GTAGS,
                            line_conflicts: Vec::new(),
                        })
                        .collect();
                    if gtags_syms.is_empty() {
                        continue;
                    }
                    if let Some(mut symbols) = self.symbols.get_mut(&repo_name) {
                        // Extract the file's current symbols (tree-sitter + LSP),
                        // merge gtags in, then put the merged set back.
                        let mut file_syms: Vec<Symbol> = symbols
                            .iter()
                            .filter(|s| s.file_path == rel_path)
                            .cloned()
                            .collect();
                        merge_symbols(&mut file_syms, gtags_syms, SourceSet::GTAGS);
                        symbols.retain(|s| s.file_path != rel_path);
                        symbols.extend(file_syms);
                    }
                }
            }
        }

        // Re-measure only when something was actually re-indexed (a lone
        // compile_commands.json restart that touches no sources leaves count 0).
        if count > 0 {
            self.refresh_memory_snapshot();
        }

        Ok(count)
    }

    // === Git Integration Methods ===

    /// Get git blame for a file
    pub async fn get_blame(
        &self,
        repo: &str,
        path: &str,
        start_line: Option<usize>,
        end_line: Option<usize>,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo_key);
        // Validate path to prevent traversal attacks
        validate_path(&repo_path, path)?;

        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let blame = match (start_line, end_line) {
            (Some(start), Some(end)) => git_repo.blame_range(path, start, end)?,
            _ => git_repo.blame(path)?,
        };

        Ok(git_repo.blame_markdown(&blame))
    }

    /// Get git history for a file
    pub async fn get_file_history(
        &self,
        repo: &str,
        path: &str,
        max_commits: usize,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo_key);
        // Validate path to prevent traversal attacks
        validate_path(&repo_path, path)?;

        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let history = git_repo.file_history(path, max_commits)?;
        Ok(git_repo.history_markdown(&history))
    }

    /// Get commits that modified a specific symbol/function
    pub async fn get_symbol_history(
        &self,
        repo: &str,
        path: &str,
        symbol: &str,
        max_commits: usize,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo_key);
        // Validate path to prevent traversal attacks
        validate_path(&repo_path, path)?;

        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let history = git_repo.symbol_history(path, symbol, max_commits)?;
        Ok(git_repo.history_markdown(&history))
    }

    /// Get the diff for a specific commit
    pub async fn get_commit_diff(
        &self,
        repo: &str,
        commit: &str,
        path: Option<&str>,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo_key);
        // Validate path to prevent traversal attacks
        if let Some(p) = path {
            validate_path(&repo_path, p)?;
        }

        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let diff = git_repo.commit_diff(commit, path)?;

        let mut output = String::new();
        output.push_str(&format!("# Commit Diff: `{}`\n\n", commit));
        if let Some(p) = path {
            output.push_str(&format!("**File**: `{}`\n\n", p));
        }
        output.push_str("```diff\n");
        output.push_str(&diff);
        output.push_str("\n```\n");

        Ok(output)
    }

    /// Get current branch and repository status
    pub async fn get_branch_info(&self, repo: &str) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let branch = git_repo.current_branch()?;
        let modified = git_repo.modified_files()?;

        let mut output = String::new();
        output.push_str(&format!("# Git Status: {}\n\n", repo_key));
        output.push_str(&format!("**Current Branch**: `{}`\n", branch));
        output.push_str(&format!("**Modified Files**: {}\n\n", modified.len()));

        if !modified.is_empty() {
            output.push_str("## Working Tree Changes\n\n");
            for file in &modified {
                output.push_str(&format!("- `{}`\n", file));
            }
        } else {
            output.push_str("*No changes in working tree*\n");
        }

        Ok(output)
    }

    /// Get list of modified files in working tree
    pub async fn get_modified_files(&self, repo: &str) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let modified = git_repo.modified_files()?;

        let mut output = String::new();
        output.push_str(&format!("# Modified Files in {}\n\n", repo_key));
        output.push_str(&format!("Found {} modified files\n\n", modified.len()));

        if !modified.is_empty() {
            for file in &modified {
                output.push_str(&format!("- `{}`\n", file));
            }
        } else {
            output.push_str("*No changes in working tree*\n");
        }

        Ok(output)
    }

    /// Get recent changes across the repository
    pub async fn get_recent_changes(&self, repo: &str, days: u32) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let changes = git_repo.recent_changes(days)?;

        let mut output = String::new();
        output.push_str(&format!("# Recent Changes (last {} days)\n\n", days));
        output.push_str(&format!("Found {} commits\n\n", changes.len()));

        for commit in changes.iter().take(20) {
            output.push_str(&format!(
                "- `{}` {} - {} (+{} -{})\n",
                commit.short_hash,
                commit.subject,
                commit.author,
                commit.insertions,
                commit.deletions
            ));
        }

        Ok(output)
    }

    /// Get code hotspots (complex + frequently changed)
    pub async fn get_hotspots(
        &self,
        repo: &str,
        days: u32,
        _min_complexity: Option<usize>,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let freq = git_repo.change_frequency(days)?;

        let mut output = String::new();
        output.push_str(&format!("# Code Hotspots (last {} days)\n\n", days));
        output.push_str("Files with high change frequency (potential maintenance burden):\n\n");

        output.push_str("| File | Commits | Authors | Churn Score |\n");
        output.push_str("|------|---------|---------|-------------|\n");

        for item in freq.iter().take(20) {
            output.push_str(&format!(
                "| `{}` | {} | {} | {:.2} |\n",
                item.file_path, item.total_commits, item.unique_authors, item.churn_score
            ));
        }

        Ok(output)
    }

    /// Get contributors to a file or repository
    pub async fn get_contributors(&self, repo: &str, path: Option<&str>) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo_key);
        // Validate path to prevent traversal attacks
        if let Some(p) = path {
            validate_path(&repo_path, p)?;
        }

        let git_repo = self.git_repos.get(&repo_key).ok_or_else(|| {
            anyhow!(
                "Git not available for {}. Enable with --git flag.",
                repo_key
            )
        })?;

        let mut output = String::new();

        match path {
            Some(p) => {
                output.push_str(&format!("# Contributors to `{}`\n\n", p));
                let contributors = git_repo.file_contributors(p)?;

                if contributors.is_empty() {
                    output.push_str("*No contributors found for this file.*\n");
                } else {
                    for (name, count) in contributors {
                        output.push_str(&format!("- {} ({} commits)\n", name, count));
                    }
                }
            }
            None => {
                output.push_str(&format!("# Repository Contributors: {}\n\n", repo));
                let contributors = git_repo.repo_contributors()?;

                if contributors.is_empty() {
                    output.push_str("*No contributors found.*\n");
                } else {
                    output.push_str(&format!(
                        "**Total contributors**: {}\n\n",
                        contributors.len()
                    ));
                    for (name, count) in contributors {
                        output.push_str(&format!("- {} ({} commits)\n", name, count));
                    }
                }
            }
        }

        Ok(output)
    }

    // === Repository Discovery ===

    /// Discover repositories in a directory
    pub async fn discover_repos(&self, base_path: &str, max_depth: usize) -> Result<String> {
        let path = std::path::Path::new(base_path);
        let repos = crate::repo::discover_repos(path, max_depth)?;

        let mut output = String::new();
        output.push_str(&format!("# Discovered Repositories in `{}`\n\n", base_path));
        output.push_str(&format!(
            "Found {} repositories (max depth: {})\n\n",
            repos.len(),
            max_depth
        ));

        for repo_path in &repos {
            let name = crate::repo::repo_name_from_path(repo_path);
            output.push_str(&format!("- **{}** - `{}`\n", name, repo_path.display()));
        }

        if repos.is_empty() {
            output.push_str("*No repositories found.*\n");
        }

        Ok(output)
    }

    /// Validate a repository path
    pub async fn validate_repo(&self, path: &str) -> Result<String> {
        let repo_path = std::path::Path::new(path);

        match crate::repo::validate_repo_path(repo_path) {
            Ok(_) => {
                let is_repo = crate::repo::is_repository(repo_path);
                let name = crate::repo::repo_name_from_path(repo_path);

                let mut output = String::new();
                output.push_str(&format!("# Repository Validation: `{}`\n\n", path));
                output.push_str(&format!("**Name**: {}\n", name));
                output.push_str(&format!("**Path**: {}\n", repo_path.display()));
                output.push_str(&format!(
                    "**Is Repository**: {}\n",
                    if is_repo {
                        "Yes"
                    } else {
                        "No (no VCS or project markers detected)"
                    }
                ));
                output.push_str("**Readable**: Yes\n");

                if is_repo {
                    output.push_str("\nThis path can be indexed with `--repos` flag.\n");
                } else {
                    output.push_str("\nWarning: No VCS (.git) or project markers detected. It may still be indexable but might not be a proper repository.\n");
                }

                Ok(output)
            }
            Err(e) => {
                let mut output = String::new();
                output.push_str(&format!("# Repository Validation: `{}`\n\n", path));
                output.push_str("**Status**: Invalid\n\n");
                output.push_str(&format!("**Error**: {}\n", e));
                Ok(output)
            }
        }
    }

    /// Walk every in-memory subsystem and return a heap breakdown. Sizes the
    /// engine-owned collections (symbols, file_cache, repos, git_repos) here and
    /// delegates to each subsystem's `heap_bytes()` for the rest. Sizes are
    /// estimates from container capacities and owned allocations — see
    /// [`MemoryReport`].
    pub fn memory_report(&self) -> MemoryReport {
        use crate::metrics::hashmap_table_bytes;

        // symbols: DashMap<String, Vec<Symbol>>
        let symbols = hashmap_table_bytes::<String, Vec<Symbol>>(self.symbols.len())
            + self
                .symbols
                .iter()
                .map(|entry| {
                    entry.key().capacity()
                        + entry.value().capacity() * std::mem::size_of::<Symbol>()
                        + entry.value().iter().map(Symbol::heap_bytes).sum::<usize>()
                })
                .sum::<usize>();

        // file_cache: DashMap<PathBuf, Arc<String>> — content is shared via Arc
        // but each entry holds a distinct file, so count each once.
        let file_cache = hashmap_table_bytes::<PathBuf, Arc<String>>(self.file_cache.len())
            + self
                .file_cache
                .iter()
                .map(|entry| entry.key().capacity() + entry.value().capacity())
                .sum::<usize>();

        // repos: DashMap<String, RepoMetadata>
        let repos = hashmap_table_bytes::<String, RepoMetadata>(self.repos.len())
            + self
                .repos
                .iter()
                .map(|entry| {
                    let meta = entry.value();
                    entry.key().capacity()
                        + meta.name.capacity()
                        + meta.path.capacity()
                        + hashmap_table_bytes::<String, LanguageStats>(meta.languages.capacity())
                        + meta.languages.keys().map(String::capacity).sum::<usize>()
                        + meta.head_hash.as_ref().map_or(0, String::capacity)
                        + meta.cdb_hash.as_ref().map_or(0, String::capacity)
                })
                .sum::<usize>();

        // git_repos: DashMap<String, GitRepo> — only the keys are tracked;
        // libgit2 keeps its own buffers that are invisible here.
        let git_repos = hashmap_table_bytes::<String, GitRepo>(self.git_repos.len())
            + self
                .git_repos
                .iter()
                .map(|entry| entry.key().capacity())
                .sum::<usize>();

        // call_graphs: DashMap<String, CallGraph>
        let call_graphs = hashmap_table_bytes::<String, CallGraph>(self.call_graphs.len())
            + self
                .call_graphs
                .iter()
                .map(|entry| entry.key().capacity() + entry.value().heap_bytes())
                .sum::<usize>();

        MemoryReport {
            symbols,
            search_index: self.search_index.inner.read().heap_bytes(),
            embeddings: self.embedding_engine.heap_bytes(),
            file_cache,
            call_graphs,
            repos,
            git_repos,
            neural: 0,
            process_rss: Self::process_rss_bytes(),
        }
    }

    /// Resident set size in bytes from the `VmRSS:` line of /proc/self/status
    /// (already in kB, so no page-size lookup is needed). None when the file is
    /// unavailable (non-Linux).
    fn process_rss_bytes() -> Option<usize> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb: usize = rest.split_whitespace().next()?.parse().ok()?;
                return Some(kb * 1024);
            }
        }
        None
    }

    /// Release freed heap back to the kernel. glibc keeps the indexing
    /// high-water mark in its arenas; malloc_trim(0) returns the unused top so
    /// RSS tracks the live working set. glibc/Linux only — a no-op on
    /// musl/macOS/wasm, which lack malloc_trim.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn return_freed_heap_to_os() {
        extern "C" {
            fn malloc_trim(pad: usize) -> std::os::raw::c_int;
        }
        // SAFETY: malloc_trim is safe to call at any point; it only walks the
        // allocator's free lists and may madvise unused pages away.
        unsafe {
            malloc_trim(0);
        }
    }

    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    fn return_freed_heap_to_os() {}

    /// Re-measure the live heap and hand it to metrics so the next flush
    /// persists an up-to-date snapshot. Called after a runtime re-index changes
    /// the in-memory subsystems. `memory_report()` walks every DashMap, so this
    /// is only invoked on actual re-index events, never on a timer. Trims first
    /// so the persisted RSS reflects the reclaimed working set.
    fn refresh_memory_snapshot(&self) {
        Self::return_freed_heap_to_os();
        self.metrics.set_memory_report(self.memory_report());
    }

    /// Get status of the search index
    pub async fn get_index_status(&self, repo: Option<&str>) -> Result<String> {
        // Resolve the optional repo filter to a canonical path; an unknown or
        // empty value is treated as "no filter" rather than an error so the
        // overall status is always retrievable.
        let repo_filter: Option<String> = match repo {
            Some(r) if !r.is_empty() => self.resolve_repo(r).ok(),
            _ => None,
        };

        let mut output = String::new();
        output.push_str("# Index Status\n\n");

        // Initialization status (critical for editors like Zed)
        let init_status = self.get_initialization_status();
        let is_initialized = init_status
            .get("is_initialized")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let indexed_repos = init_status
            .get("indexed_repos")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let total_repos = init_status
            .get("total_repos")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let progress = init_status
            .get("progress_percentage")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        output.push_str("## Initialization Status\n\n");
        output.push_str(&format!(
            "- **Status**: {}\n",
            if is_initialized {
                "✓ Complete"
            } else {
                "⏳ In Progress"
            }
        ));
        output.push_str(&format!(
            "- **Progress**: {}/{} repositories ({}%)\n\n",
            indexed_repos, total_repos, progress
        ));

        let stats = self.search_index.stats();
        output.push_str(&format!("**Total Documents**: {}\n", stats.total_documents));
        output.push_str(&format!("**Total Terms**: {}\n", stats.total_terms));
        output.push_str(&format!(
            "**Avg Document Length**: {:.1} tokens\n\n",
            stats.avg_doc_length
        ));

        // Feature flags section
        output.push_str("## Enabled Features\n\n");
        output.push_str(&format!(
            "- **Git integration**: {}\n",
            if self.options.git_enabled {
                "enabled"
            } else {
                "disabled"
            }
        ));
        output.push_str(&format!(
            "- **Call graph analysis**: {}\n",
            if self.options.call_graph_enabled {
                "enabled"
            } else {
                "disabled"
            }
        ));
        output.push_str(&format!(
            "- **Index persistence**: {}\n",
            if self.options.persist_enabled {
                "enabled"
            } else {
                "disabled"
            }
        ));
        output.push_str(&format!(
            "- **Watch mode**: {}\n",
            if self.options.watch_enabled {
                "enabled"
            } else {
                "disabled"
            }
        ));
        output.push_str(&format!(
            "- **Neural embeddings**: {}\n\n",
            if self.neural_engine.is_some() {
                format!(
                    "enabled (backend={}, model={:?})",
                    self.options.neural_config.backend, self.options.neural_config.model_name
                )
            } else {
                "disabled".to_string()
            }
        ));

        output.push_str("## Document Types\n\n");
        for (doc_type, count) in &stats.doc_types {
            output.push_str(&format!("- {:?}: {}\n", doc_type, count));
        }

        output.push_str("\n## Repositories\n\n");
        for entry in self.repos.iter() {
            let meta = entry.value();
            let key = entry.key();
            if repo_filter.as_deref().is_none_or(|f| f == key) {
                output.push_str(&format!("### {}\n", meta.name));
                output.push_str(&format!("- Repo: `{}`\n", key));
                output.push_str(&format!("- Files: {}\n", meta.file_count));
                output.push_str(&format!(
                    "- Symbols: {}\n",
                    self.symbols.get(key).map(|s| s.len()).unwrap_or(0)
                ));
                output.push_str(&format!(
                    "- Git: {}\n\n",
                    if self.git_repos.contains_key(key) {
                        "enabled"
                    } else {
                        "disabled"
                    }
                ));
            }
        }

        output.push_str(&self.memory_report().render_markdown());

        Ok(output)
    }

    // === Semantic Search ===

    /// Perform semantic code search using BM25 ranking
    pub async fn semantic_search(
        &self,
        repo: Option<&str>,
        query: &str,
        max_results: usize,
        _doc_type: Option<&str>,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::security_rules::is_test_file;

        // Build cache key from query parameters
        let cache_key = {
            let options = SearchOptions {
                file_pattern: None,
                max_results: Some(max_results),
                exclude_tests,
            };
            QueryCacheKey::code_search_with_options(repo, format!("semantic:{}", query), &options)
        };

        // Check cache first
        if self.options.cache_enabled {
            if let Some(cached) = self.query_cache.get(&cache_key) {
                return Ok(cached);
            }
        }

        let exclude_tests = exclude_tests.unwrap_or(false); // Default false for search

        // Validate repo if specified
        let repo_key = if let Some(r) = repo {
            if !r.is_empty() {
                Some(self.resolve_repo(r)?)
            } else {
                None
            }
        } else {
            None
        };
        let repo_name = repo_key.as_deref();

        let results: Vec<_> = self
            .search_index
            .search(query, max_results * 2) // Get more results to filter
            .into_iter()
            .filter(|r| !exclude_tests || !is_test_file(&r.document.file_path))
            .take(max_results)
            .collect();

        // Collect dependent files for smart invalidation
        let dependent_files: Vec<String> = results
            .iter()
            .map(|r| r.document.file_path.clone())
            .collect();

        let mut output = String::new();
        output.push_str(&format!("# Semantic Search: `{}`\n\n", query));
        if let Some(r) = repo_name {
            output.push_str(&format!("Repository: {}\n", r));
        }
        output.push_str(&format!("Found {} results\n\n", results.len()));

        for (i, result) in results.iter().enumerate() {
            output.push_str(&format!(
                "## {}. {} (score: {:.2})\n",
                i + 1,
                result.document.file_path,
                result.score
            ));
            output.push_str(&format!(
                "Lines {}-{}\n\n",
                result.document.start_line, result.document.end_line
            ));
            // snippet is empty for the persistent index (content is None there);
            // regenerate from file_cache — O(num_repos) lookup per top-N result
            let snippet = if result.snippet.is_empty() {
                self.repo_paths
                    .iter()
                    .find_map(|rp| {
                        self.file_cache
                            .get(&rp.join(&result.document.file_path))
                            .map(|entry| generate_snippet(entry.value(), &result.matched_terms))
                    })
                    .unwrap_or_default()
            } else {
                result.snippet.clone()
            };
            output.push_str("```\n");
            output.push_str(&snippet);
            output.push_str("\n```\n\n");
        }

        if results.is_empty() {
            output.push_str("*No results found.*\n");
        }

        // Cache the result with file dependencies for smart invalidation
        if self.options.cache_enabled {
            self.query_cache
                .insert_with_files(cache_key, output.clone(), dependent_files);
        }

        Ok(output)
    }

    // === Similarity Search Methods ===

    /// Find code similar to a given code snippet using embeddings
    pub async fn find_similar_code(
        &self,
        repo: Option<&str>,
        query: &str,
        max_results: usize,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::security_rules::is_test_file;

        let exclude_tests = exclude_tests.unwrap_or(false); // Default false for search

        // Validate repo if specified
        let repo_key = if let Some(r) = repo {
            if !r.is_empty() {
                Some(self.resolve_repo(r)?)
            } else {
                None
            }
        } else {
            None
        };
        let repo_name = repo_key.as_deref();

        let results: Vec<_> = self
            .embedding_engine
            .find_similar_code(query, max_results * 2) // Get more to filter
            .into_iter()
            .filter(|r| !exclude_tests || !is_test_file(&r.document.file_path))
            .take(max_results)
            .collect();

        let mut output = String::new();
        output.push_str(&format!("# Similar Code Search: `{}`\n\n", query));
        if let Some(r) = repo_name {
            output.push_str(&format!("Repository: {}\n", r));
        }
        output.push_str(&format!(
            "Found {} similar code snippets\n\n",
            results.len()
        ));

        for (i, result) in results.iter().enumerate() {
            output.push_str(&format!(
                "## {}. {} (similarity: {:.3})\n",
                i + 1,
                result.document.file_path,
                result.similarity
            ));
            output.push_str(&format!(
                "Lines {}-{}\n\n",
                result.document.start_line, result.document.end_line
            ));
            output.push_str("```\n");
            output.push_str(&result.document.content);
            output.push_str("\n```\n\n");
        }

        if results.is_empty() {
            output.push_str("*No similar code found.*\n");
        }

        Ok(output)
    }

    /// Find code similar to a specific symbol
    pub async fn find_similar_to_symbol(
        &self,
        repo: &str,
        symbol_name: &str,
        max_results: usize,
    ) -> Result<String> {
        // First find the symbol to get its ID
        let symbols = self
            .symbols
            .get(repo)
            .ok_or_else(|| self.repo_not_found_error(repo))?;

        let symbol = symbols
            .iter()
            .find(|s| s.name == symbol_name || s.qualified_name.as_deref() == Some(symbol_name))
            .ok_or_else(|| {
                anyhow!(
                    "Symbol '{}' not found in repository '{}'",
                    symbol_name,
                    repo
                )
            })?;

        // Create symbol ID
        let symbol_id = format!("{}::{}", symbol.file_path, symbol.name);

        // Find similar code to this symbol
        let results = self
            .embedding_engine
            .find_similar_to_doc(&symbol_id, max_results);

        let mut output = String::new();
        output.push_str(&format!("# Code Similar to Symbol: `{}`\n\n", symbol_name));
        output.push_str(&format!(
            "Reference: `{}:{}` ({:?})\n\n",
            symbol.file_path, symbol.start_line, symbol.kind
        ));
        output.push_str(&format!("Found {} similar snippets\n\n", results.len()));

        for (i, result) in results.iter().enumerate() {
            // Skip the symbol itself
            if result.document.id == symbol_id {
                continue;
            }

            output.push_str(&format!(
                "## {}. {} (similarity: {:.3})\n",
                i + 1,
                result.document.file_path,
                result.similarity
            ));
            output.push_str(&format!(
                "Lines {}-{}\n\n",
                result.document.start_line, result.document.end_line
            ));
            output.push_str("```\n");
            output.push_str(&result.document.content);
            output.push_str("\n```\n\n");
        }

        if results.len() <= 1 {
            output.push_str("*No similar code found.*\n");
        }

        Ok(output)
    }

    // === Call Graph Methods ===

    /// Get the call graph for a function
    ///
    /// Results are cached for performance. Cache is invalidated when files change.
    pub async fn get_call_graph(
        &self,
        repo: &str,
        function: &str,
        _depth: usize,
        _exclude_tests: Option<bool>,
    ) -> Result<String> {
        // Note: exclude_tests filtering would require call graph regeneration
        // For now, the parameter is accepted but filtering happens at source

        let repo = self.resolve_repo(repo)?;

        if !self.is_fully_initialized() {
            return Err(anyhow!(
                "Call graph not yet available — initialization in progress. \
                 Please retry in a moment."
            ));
        }

        // Build cache key with function as discriminator
        let cache_key = AnalysisCacheKey::with_discriminator(&repo, "call_graph", function);

        // Compute repo hash for invalidation
        let repo_hash = self.compute_repo_hash(&repo);

        // Check cache first
        if self.options.cache_enabled {
            if let Some(cached) = self
                .analysis_cache
                .get_if_hash_matches(&cache_key, &repo_hash)
            {
                return Ok(cached);
            }
        }

        let call_graph = self.call_graphs.get(&repo).ok_or_else(|| {
            anyhow!(
                "Call graph not found for '{}'. Is --call-graph enabled?",
                repo
            )
        })?;

        // Empty string means show summary (None), otherwise look up specific function
        let func_option = if function.is_empty() {
            None
        } else {
            Some(function)
        };
        let result = call_graph.to_markdown(func_option);

        // Cache the result
        if self.options.cache_enabled {
            self.analysis_cache
                .insert_with_hash(cache_key, result.clone(), Some(repo_hash));
        }

        Ok(result)
    }

    /// Find the symbol (function/method) in `repo` whose body contains `file:line`.
    /// Used to map an LSP reference location back to a caller name.
    fn enclosing_function_at<'a>(
        symbols: &'a [Symbol],
        file: &str,
        line: usize,
    ) -> Option<&'a Symbol> {
        symbols.iter().find(|sym| {
            matches!(sym.kind, SymbolKind::Function | SymbolKind::Method)
                && sym.file_path == file
                && sym.start_line <= line
                && line <= sym.end_line
        })
    }

    /// Get callers of a function.
    ///
    /// When LSP is enabled and the queried function lives in a C/C++ file, LSP
    /// `textDocument/references` results are merged with the AST-based call graph
    /// to produce the most complete caller list. Each edge is tagged with its
    /// source (`[LSP]`, `[ast]`, or confirmed by both).
    pub async fn get_callers(
        &self,
        repo: &str,
        function: &str,
        transitive: bool,
        max_depth: usize,
        _exclude_tests: Option<bool>,
    ) -> Result<String> {
        let repo = self.resolve_repo(repo)?;

        if !self.is_fully_initialized() {
            return Err(anyhow!(
                "Call graph not yet available — initialization in progress. \
                 Please retry in a moment."
            ));
        }

        let cache_key = AnalysisCacheKey::with_discriminator(&repo, "callers_hybrid", function);
        let repo_hash = self.compute_repo_hash(&repo);
        if self.options.cache_enabled {
            if let Some(cached) = self
                .analysis_cache
                .get_if_hash_matches(&cache_key, &repo_hash)
            {
                return Ok(cached);
            }
        }

        let call_graph = self.call_graphs.get(&repo).ok_or_else(|| {
            anyhow!(
                "Call graph not found for '{}'. Is --call-graph enabled?",
                repo
            )
        })?;

        let mut output = String::new();
        output.push_str(&format!("# Callers of `{}`\n\n", function));

        if transitive {
            let callers = call_graph.get_transitive_callers(function, max_depth);
            output.push_str(&format!(
                "Found {} transitive callers (max depth: {})\n\n",
                callers.len(),
                max_depth
            ));
            for (name, depth) in &callers {
                output.push_str(&format!("- `{}` (depth: {})\n", name, depth));
            }
        } else {
            // Collect AST-derived callers.
            let mut callers: Vec<CallEdge> = call_graph.get_callers(function);

            // LSP augmentation for C/C++ when a language server is available.
            // `repo` here is already the canonical absolute path.
            let repo_path = PathBuf::from(&repo);
            if let (Some(lsp), false) = (&self.lsp_manager, transitive) {
                if lsp.is_enabled() {
                    if let Some(sym_list) = self.symbols.get(&repo) {
                        // Find the definition of the queried function to know its file/language.
                        let def_sym = sym_list.iter().find(|s| {
                            s.name == function || s.qualified_name.as_deref() == Some(function)
                        });
                        if let Some(def) = def_sym {
                            let lang = get_language_from_path(&def.file_path);
                            if lang == "c" || lang == "cpp" {
                                if let Some(lsp_refs) = self
                                    .lsp_search_references(&repo, function, &repo_path)
                                    .await
                                {
                                    let sym_slice: Vec<Symbol> = sym_list.iter().cloned().collect();
                                    let ast_keys: std::collections::HashSet<(String, usize)> =
                                        callers
                                            .iter()
                                            .map(|e| (e.file_path.clone(), e.line))
                                            .collect();

                                    // lsp_search_references merges all configured
                                    // C/C++ backends; tag agreement with the primary
                                    // backend's bit as a coarse "LSP-confirmed" marker.
                                    let lsp_bit = lsp
                                        .active_cxx_backends_for(&repo_path)
                                        .first()
                                        .copied()
                                        .unwrap_or(SourceSet::CLANGD);

                                    for (rel_path, ref_line, _content) in &lsp_refs {
                                        let key = (rel_path.clone(), *ref_line);
                                        if ast_keys.contains(&key) {
                                            // Both sources agree — record the LSP confirmer.
                                            for edge in callers.iter_mut() {
                                                if edge.file_path == *rel_path
                                                    && edge.line == *ref_line
                                                {
                                                    edge.confirmed_by.insert(lsp_bit);
                                                }
                                            }
                                        } else {
                                            // LSP-only edge: resolve enclosing function.
                                            let caller_name = Self::enclosing_function_at(
                                                &sym_slice, rel_path, *ref_line,
                                            )
                                            .map(|s| s.name.clone())
                                            .unwrap_or_else(|| format!("<unknown>@{}", ref_line));

                                            callers.push(CallEdge {
                                                target: caller_name,
                                                file_path: rel_path.clone(),
                                                line: *ref_line,
                                                column: 0,
                                                call_type: CallType::Unknown,
                                                scope_hint: None,
                                                confirmed_by: lsp_bit,
                                                line_conflicts: Vec::new(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            output.push_str(&format!("Found {} direct callers\n\n", callers.len()));
            for caller in &callers {
                let is_cxx = matches!(
                    get_language_from_path(&caller.file_path).as_str(),
                    "c" | "cpp"
                );
                let provenance = render_provenance(
                    ProvenanceSubject::CallEdge,
                    self.enabled_backends_for_repo(&repo_path, is_cxx),
                    caller.confirmed_by,
                    caller.line,
                    &caller.line_conflicts,
                )
                .map(|annotation| format!(" — {}", annotation))
                .unwrap_or_default();
                output.push_str(&format!(
                    "- `{}` at `{}:{}`{} ({:?})\n",
                    caller.target, caller.file_path, caller.line, provenance, caller.call_type
                ));
            }
        }

        if output.ends_with("\n\n") {
            output.push_str("*No callers found.*\n");
        }

        if self.options.cache_enabled {
            self.analysis_cache
                .insert_with_hash(cache_key, output.clone(), Some(repo_hash));
        }

        Ok(output)
    }

    /// Get callees of a function.
    pub async fn get_callees(
        &self,
        repo: &str,
        function: &str,
        transitive: bool,
        max_depth: usize,
        _exclude_tests: Option<bool>,
    ) -> Result<String> {
        let repo = self.resolve_repo(repo)?;

        if !self.is_fully_initialized() {
            return Err(anyhow!(
                "Call graph not yet available — initialization in progress. \
                 Please retry in a moment."
            ));
        }

        let cache_key = AnalysisCacheKey::with_discriminator(&repo, "callees_hybrid", function);
        let repo_hash = self.compute_repo_hash(&repo);
        if self.options.cache_enabled {
            if let Some(cached) = self
                .analysis_cache
                .get_if_hash_matches(&cache_key, &repo_hash)
            {
                return Ok(cached);
            }
        }

        let call_graph = self.call_graphs.get(&repo).ok_or_else(|| {
            anyhow!(
                "Call graph not found for '{}'. Is --call-graph enabled?",
                repo
            )
        })?;

        let mut output = String::new();
        output.push_str(&format!("# Callees of `{}`\n\n", function));

        if transitive {
            let callees = call_graph.get_transitive_callees(function, max_depth);
            output.push_str(&format!(
                "Found {} transitive callees (max depth: {})\n\n",
                callees.len(),
                max_depth
            ));
            for (name, depth) in &callees {
                output.push_str(&format!("- `{}` (depth: {})\n", name, depth));
            }
        } else {
            let callees = call_graph.get_callees(function);
            output.push_str(&format!("Found {} direct callees\n\n", callees.len()));
            for callee in &callees {
                output.push_str(&format!(
                    "- `{}` at `{}:{}` ({:?})\n",
                    callee.target, callee.file_path, callee.line, callee.call_type
                ));
            }
        }

        if output.ends_with("\n\n") {
            output.push_str("*No callees found.*\n");
        }

        if self.options.cache_enabled {
            self.analysis_cache
                .insert_with_hash(cache_key, output.clone(), Some(repo_hash));
        }

        Ok(output)
    }

    /// Find the call path between two functions
    pub async fn find_call_path(&self, repo: &str, from: &str, to: &str) -> Result<String> {
        let repo = self.resolve_repo(repo)?;

        if !self.is_fully_initialized() {
            return Err(anyhow!(
                "Call graph not yet available — initialization in progress. \
                 Please retry in a moment."
            ));
        }

        let call_graph = self.call_graphs.get(&repo).ok_or_else(|| {
            anyhow!(
                "Call graph not found for '{}'. Is --call-graph enabled?",
                repo
            )
        })?;

        let mut output = String::new();
        output.push_str(&format!("# Call Path: `{}` â†’ `{}`\n\n", from, to));

        match call_graph.find_call_path(from, to) {
            Some(path) => {
                output.push_str(&format!("Found path with {} steps:\n\n", path.len() - 1));
                for (i, func) in path.iter().enumerate() {
                    if i > 0 {
                        output.push_str("  â†“\n");
                    }
                    output.push_str(&format!("{}. `{}`\n", i + 1, func));
                }
            }
            None => {
                output.push_str("*No path found between these functions.*\n");
            }
        }

        Ok(output)
    }

    /// Get complexity metrics for a function
    pub async fn get_complexity(&self, repo: &str, function: &str) -> Result<String> {
        let repo = self.resolve_repo(repo)?;

        if !self.is_fully_initialized() {
            return Err(anyhow!(
                "Call graph not yet available — initialization in progress. \
                 Please retry in a moment."
            ));
        }

        let call_graph = self.call_graphs.get(&repo).ok_or_else(|| {
            anyhow!(
                "Call graph not found for '{}'. Is --call-graph enabled?",
                repo
            )
        })?;

        let mut output = String::new();
        output.push_str(&format!("# Complexity Metrics: `{}`\n\n", function));

        match call_graph.get_metrics(function) {
            Some(metrics) => {
                output.push_str("| Metric | Value |\n");
                output.push_str("|--------|-------|\n");
                output.push_str(&format!("| Lines of Code | {} |\n", metrics.loc));
                output.push_str(&format!(
                    "| Cyclomatic Complexity | {} |\n",
                    metrics.cyclomatic
                ));
                output.push_str(&format!("| Max Nesting Depth | {} |\n", metrics.max_depth));
                output.push_str(&format!("| Parameters | {} |\n", metrics.params));
                output.push_str(&format!("| Return Points | {} |\n", metrics.returns));
                output.push_str(&format!(
                    "| Cognitive Complexity | {} |\n",
                    metrics.cognitive
                ));

                // Add health assessment
                output.push_str("\n## Health Assessment\n\n");
                if metrics.cyclomatic > 10 {
                    output.push_str("âš ï¸ **High cyclomatic complexity** - Consider refactoring into smaller functions.\n");
                } else if metrics.cyclomatic > 5 {
                    output.push_str("âš¡ **Moderate complexity** - Function is manageable but could be simplified.\n");
                } else {
                    output.push_str("âœ… **Low complexity** - Function is well-structured.\n");
                }

                if metrics.max_depth > 4 {
                    output.push_str("âš ï¸ **Deep nesting** - Consider early returns or extracting nested logic.\n");
                }
            }
            None => {
                output.push_str("*Function not found in call graph.*\n");
            }
        }

        Ok(output)
    }

    /// Get function hotspots (highly connected functions)
    pub async fn get_function_hotspots(
        &self,
        repo: &str,
        min_connections: usize,
        _exclude_tests: Option<bool>,
    ) -> Result<String> {
        // Note: exclude_tests filtering would require call graph regeneration
        let repo = self.resolve_repo(repo)?;

        if !self.is_fully_initialized() {
            return Err(anyhow!(
                "Call graph not yet available — initialization in progress. \
                 Please retry in a moment."
            ));
        }

        let call_graph = self.call_graphs.get(&repo).ok_or_else(|| {
            anyhow!(
                "Call graph not found for '{}'. Is --call-graph enabled?",
                repo
            )
        })?;

        let default_limit = 50;
        let hotspots = call_graph.get_hotspots_limited(min_connections, default_limit);
        let total_count = call_graph.get_hotspots(min_connections).len();

        let mut output = String::new();
        output.push_str(&format!(
            "# Function Hotspots in {} (min {} connections)\n\n",
            repo, min_connections
        ));

        if hotspots.is_empty() {
            output.push_str("*No hotspots found matching the criteria.*\n");
        } else {
            if total_count > hotspots.len() {
                output.push_str(&format!(
                    "Showing top {} of {} highly connected functions (generic trait methods filtered):\n\n",
                    hotspots.len(),
                    total_count
                ));
            } else {
                output.push_str(&format!(
                    "Found {} highly connected functions (generic trait methods filtered):\n\n",
                    hotspots.len()
                ));
            }
            output.push_str("| Function | Incoming | Outgoing | Total |\n");
            output.push_str("|----------|----------|----------|-------|\n");

            for (name, incoming, outgoing) in &hotspots {
                output.push_str(&format!(
                    "| `{}` | {} | {} | {} |\n",
                    name,
                    incoming,
                    outgoing,
                    incoming + outgoing
                ));
            }

            output.push_str("\n## Analysis\n\n");
            output.push_str(
                "Functions with many connections are potential refactoring candidates:\n",
            );
            output.push_str("- **High incoming**: Widely used, changes have broad impact\n");
            output.push_str("- **High outgoing**: Complex, depends on many other functions\n");
            output
                .push_str("- **High both**: Central to the codebase, requires careful attention\n");
        }

        Ok(output)
    }

    // === Excerpt Extraction ===

    /// Get an intelligent code excerpt with context
    pub async fn get_excerpt(
        &self,
        repo: &str,
        path: &str,
        match_lines: &[usize],
        config: crate::extract::ExcerptConfig,
    ) -> Result<String> {
        let repo_path = PathBuf::from(self.resolve_repo(repo)?);
        let file_path = validate_path(&repo_path, path)?;

        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let excerpts = crate::extract::extract_excerpts(&content, match_lines, &config);
        let best = crate::extract::select_best_excerpt(&excerpts, 3);

        let mut output = String::new();
        output.push_str(&format!("# Code Excerpt: `{}`\n\n", path));
        output.push_str(&format!(
            "Extracted {} excerpt(s) from {} match line(s)\n\n",
            best.len(),
            match_lines.len()
        ));

        for (i, excerpt) in best.iter().enumerate() {
            output.push_str(&format!("## Excerpt {}\n", i + 1));
            output.push_str(&format!(
                "Lines {}-{} | Relevance: {:.2}\n\n",
                excerpt.start_line, excerpt.end_line, excerpt.relevance
            ));
            output.push_str("```");
            output.push_str(get_language_id(path));
            output.push('\n');
            output.push_str(&excerpt.content);
            output.push_str("\n```\n\n");
        }

        if best.is_empty() {
            output.push_str("*No excerpts could be extracted.*\n");
        }

        Ok(output)
    }

    // === Performance Metrics Methods ===

    /// Get performance metrics report including cache statistics
    pub async fn get_metrics(&self, format: &str) -> Result<String> {
        let cache_stats = self.cache_stats();

        if format == "json" {
            let mut json = self.metrics.report_json();
            // Add cache statistics to JSON
            json["cache"] = serde_json::json!({
                "enabled": self.options.cache_enabled,
                "ttl_seconds": self.options.cache_ttl_seconds,
                "hits": cache_stats.hits,
                "misses": cache_stats.misses,
                "hit_rate_percent": cache_stats.hit_rate(),
                "evictions": cache_stats.evictions,
                "expirations": cache_stats.expirations,
                "size": cache_stats.size,
                "capacity": cache_stats.capacity,
            });
            Ok(json.to_string())
        } else {
            let mut output = self.metrics.report();

            // Add cache statistics section
            output.push_str("\n## Analysis Cache\n\n");
            output.push_str(&format!(
                "**Status**: {}\n",
                if self.options.cache_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ));
            output.push_str(&format!(
                "**TTL**: {} seconds\n\n",
                self.options.cache_ttl_seconds
            ));

            output.push_str("| Metric | Value |\n");
            output.push_str("|--------|-------|\n");
            output.push_str(&format!("| Hits | {} |\n", cache_stats.hits));
            output.push_str(&format!("| Misses | {} |\n", cache_stats.misses));
            output.push_str(&format!("| Hit Rate | {:.2}% |\n", cache_stats.hit_rate()));
            output.push_str(&format!("| Evictions | {} |\n", cache_stats.evictions));
            output.push_str(&format!("| Expirations | {} |\n", cache_stats.expirations));
            output.push_str(&format!(
                "| Size | {} / {} |\n",
                cache_stats.size, cache_stats.capacity
            ));

            Ok(output)
        }
    }

    // === LSP Integration Methods ===

    /// Get hover information from LSP (type info, documentation, etc.)
    pub async fn get_hover_info(
        &self,
        repo: &str,
        path: &str,
        line: usize,
        character: usize,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo_key);
        let file_path = validate_path(&repo_path, path)?;

        // Detect language from file extension
        let language = get_language_from_path(path);

        let mut output = String::new();
        output.push_str(&format!("# Hover Info: `{}`\n\n", path));
        output.push_str(&format!("**Position**: {}:{}\n\n", line, character));

        // Try LSP first if available
        if let Some(ref lsp) = self.lsp_manager {
            match lsp
                .get_hover(&language, &file_path, line as u32, character as u32)
                .await
            {
                Ok(Some(hover)) => {
                    output.push_str("## LSP Hover Information (LSP enhanced)\n\n");
                    output.push_str(&crate::lsp::hover_to_markdown(&hover));
                    output.push_str("\n\n");
                    return Ok(output);
                }
                Ok(None) => {
                    output.push_str("*No hover information available from LSP*\n\n");
                }
                Err(e) => {
                    output.push_str(&format!("*LSP error: {}*\n\n", e));
                }
            }
        }

        // Fallback to tree-sitter symbols
        output.push_str("## Symbol Information (tree-sitter)\n\n");
        let symbols = self
            .symbols
            .get(&repo_key)
            .ok_or_else(|| self.repo_not_found_error(&repo_key))?;

        // Find symbol at this location
        for symbol in symbols.iter() {
            if symbol.file_path == path && line >= symbol.start_line && line <= symbol.end_line {
                output.push_str(&format!("**Symbol**: {}\n", symbol.name));
                output.push_str(&format!("**Kind**: {:?}\n", symbol.kind));
                if let Some(sig) = &symbol.signature {
                    output.push_str(&format!("**Signature**: `{}`\n", sig));
                }
                if let Some(doc) = &symbol.doc_comment {
                    output.push_str(&format!("\n{}\n", doc));
                }
                break;
            }
        }

        Ok(output)
    }

    /// Get type information for a symbol (requires LSP)
    pub async fn get_type_info(
        &self,
        repo: &str,
        path: &str,
        line: usize,
        character: usize,
    ) -> Result<String> {
        let repo_path = PathBuf::from(self.resolve_repo(repo)?);
        let file_path = validate_path(&repo_path, path)?;
        let language = get_language_from_path(path);

        let mut output = String::new();
        output.push_str(&format!("# Type Information: `{}`\n\n", path));
        output.push_str(&format!("**Position**: {}:{}\n\n", line, character));

        if let Some(ref lsp) = self.lsp_manager {
            match lsp
                .get_hover(&language, &file_path, line as u32, character as u32)
                .await
            {
                Ok(Some(hover)) => {
                    output.push_str("## Type Information (LSP enhanced)\n\n");
                    output.push_str(&crate::lsp::hover_to_markdown(&hover));
                    return Ok(output);
                }
                Ok(None) => {
                    output.push_str("*No type information available from LSP*\n");
                }
                Err(e) => {
                    output.push_str(&format!("*LSP error: {}*\n", e));
                }
            }
        } else {
            output.push_str("*LSP not enabled. Use --lsp flag to enable type information.*\n");
        }

        Ok(output)
    }

    // === Go to Definition (LSP) ===

    /// Get definition location using LSP
    pub async fn go_to_definition(
        &self,
        repo: &str,
        path: &str,
        line: usize,
        character: usize,
    ) -> Result<String> {
        let repo_key = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo_key);
        let file_path = validate_path(&repo_path, path)?;
        let language = get_language_from_path(path);

        let mut output = String::new();
        output.push_str(&format!("# Go to Definition: `{}`\n\n", path));
        output.push_str(&format!("**Position**: {}:{}\n\n", line, character));

        if let Some(ref lsp) = self.lsp_manager {
            match lsp
                .get_definition(&language, &file_path, line as u32, character as u32)
                .await
            {
                Ok(Some(locations)) => {
                    if locations.is_empty() {
                        output.push_str("*No definition found*\n");
                    } else {
                        output.push_str(&format!("Found {} definition(s):\n\n", locations.len()));
                        for loc in locations {
                            if let Ok(def_path) = loc.uri.to_file_path() {
                                let rel_path = def_path
                                    .strip_prefix(&repo_path)
                                    .unwrap_or(&def_path)
                                    .to_string_lossy();
                                output.push_str(&format!(
                                    "- `{}:{}:{}`\n",
                                    rel_path,
                                    loc.range.start.line + 1,
                                    loc.range.start.character
                                ));
                            } else {
                                output.push_str(&format!(
                                    "- `{}:{}:{}`\n",
                                    loc.uri,
                                    loc.range.start.line + 1,
                                    loc.range.start.character
                                ));
                            }
                        }
                    }
                    return Ok(output);
                }
                Ok(None) => {
                    output.push_str("*No definition found from LSP*\n");
                }
                Err(e) => {
                    output.push_str(&format!("*LSP error: {}*\n", e));
                }
            }
        } else {
            output.push_str("*LSP not enabled. Use --lsp flag to enable go-to-definition.*\n");
        }

        // Fallback: try to find in our symbol index
        output.push_str("\n## Symbol Index Fallback\n\n");

        // Read the file to find what symbol is at this position
        let content = std::fs::read_to_string(&file_path)?;
        let lines: Vec<&str> = content.lines().collect();

        if line > 0 && line <= lines.len() {
            let source_line = lines[line - 1];
            // Try to find a symbol at or near the character position
            if let Some(symbols) = self.symbols.get(&repo_key) {
                for symbol in symbols.iter() {
                    if source_line.contains(&symbol.name) {
                        output.push_str(&format!(
                            "Possible match: **{}** at `{}:{}` ({:?})\n",
                            symbol.name, symbol.file_path, symbol.start_line, symbol.kind
                        ));
                    }
                }
            }
        }

        Ok(output)
    }

    // === Remote Repository Methods ===

    /// Initialize the remote repository manager
    pub fn init_remote_manager(&mut self) -> Result<()> {
        if self.remote_manager.is_none() {
            let manager = RemoteRepoManager::new()?;
            self.remote_manager = Some(Arc::new(tokio::sync::Mutex::new(manager)));
            info!("Remote repository manager initialized");
        }
        Ok(())
    }

    /// Add a remote GitHub repository for indexing
    pub async fn add_remote_repo(
        &self,
        url: &str,
        sparse_paths: Option<&[String]>,
    ) -> Result<String> {
        // Initialize manager if needed
        let manager = match &self.remote_manager {
            Some(m) => m.clone(),
            None => {
                return Err(anyhow!(
                    "Remote repository support not initialized. Use init_remote_manager() first."
                ));
            }
        };

        let remote = crate::remote::RemoteRepo::from_url(url)?;

        let mut output = String::new();
        output.push_str(&format!(
            "# Adding Remote Repository: {}\n\n",
            remote.identifier()
        ));
        output.push_str(&format!("**URL**: {}\n", remote.url));
        if let Some(branch) = &remote.branch {
            output.push_str(&format!("**Branch**: {}\n", branch));
        }
        output.push('\n');

        let local_path = {
            let mut mgr = manager.lock().await;
            if let Some(paths) = sparse_paths {
                let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
                output.push_str(&format!(
                    "Performing sparse checkout of {} paths...\n\n",
                    paths.len()
                ));
                mgr.sparse_checkout(&remote, &path_refs).await?
            } else {
                output.push_str("Cloning repository...\n\n");
                mgr.clone_repo(&remote).await?
            }
        };

        output.push_str(&format!("**Local Path**: `{}`\n\n", local_path.display()));
        output.push_str("Repository cloned successfully. You can now index it with `reindex`.\n");

        // Note: Full indexing would require adding this path to repo_paths and calling index_repo
        // For now we just clone and return the path

        Ok(output)
    }

    /// List files in a remote GitHub repository via API
    pub async fn list_remote_files(&self, url: &str, path: Option<&str>) -> Result<String> {
        let manager = match &self.remote_manager {
            Some(m) => m.clone(),
            None => {
                // Try to create a temporary manager for API-only operation
                let mgr = RemoteRepoManager::new()?;
                let remote = crate::remote::RemoteRepo::from_url(url)?;
                let files = mgr.list_files(&remote, path).await?;

                let mut output = String::new();
                output.push_str(&format!("# Files in {}\n\n", remote.identifier()));
                if let Some(p) = path {
                    output.push_str(&format!("**Path**: `{}`\n\n", p));
                }
                output.push_str(&format!("Found {} files:\n\n", files.len()));
                for file in files {
                    output.push_str(&format!("- `{}`\n", file));
                }
                return Ok(output);
            }
        };

        let remote = crate::remote::RemoteRepo::from_url(url)?;

        let files = {
            let mgr = manager.lock().await;
            mgr.list_files(&remote, path).await?
        };

        let mut output = String::new();
        output.push_str(&format!("# Files in {}\n\n", remote.identifier()));
        if let Some(p) = path {
            output.push_str(&format!("**Path**: `{}`\n\n", p));
        }
        output.push_str(&format!("Found {} files:\n\n", files.len()));
        for file in &files {
            output.push_str(&format!("- `{}`\n", file));
        }

        if files.is_empty() {
            output.push_str("*No files found (directory may be empty or not exist)*\n");
        }

        Ok(output)
    }

    /// Fetch a specific file from a remote GitHub repository
    pub async fn get_remote_file(&self, url: &str, path: &str) -> Result<String> {
        let manager = match &self.remote_manager {
            Some(m) => m.clone(),
            None => {
                // Try to create a temporary manager for API-only operation
                let mgr = RemoteRepoManager::new()?;
                let remote = crate::remote::RemoteRepo::from_url(url)?;
                let content = mgr.get_file(&remote, path).await?;

                let mut output = String::new();
                output.push_str(&format!("# {} from {}\n\n", path, remote.identifier()));
                output.push_str("```");
                output.push_str(get_language_id(path));
                output.push('\n');
                output.push_str(&content);
                output.push_str("\n```\n");
                return Ok(output);
            }
        };

        let remote = crate::remote::RemoteRepo::from_url(url)?;

        let content = {
            let mgr = manager.lock().await;
            mgr.get_file(&remote, path).await?
        };

        let mut output = String::new();
        output.push_str(&format!("# {} from {}\n\n", path, remote.identifier()));

        let lines: Vec<&str> = content.lines().collect();
        output.push_str(&format!("**Lines**: {}\n\n", lines.len()));

        output.push_str("```");
        output.push_str(get_language_id(path));
        output.push('\n');
        output.push_str(&content);
        output.push_str("\n```\n");

        Ok(output)
    }

    // ==================== Control Flow Graph (CFG) Tools ====================

    /// Get control flow graph for a specific function
    pub async fn get_control_flow(&self, repo: &str, path: &str, function: &str) -> Result<String> {
        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;

        // Parse the file
        let parsed = self.parser.parse_file(&full_path, &content)?;

        // Get the tree (required for CFG analysis)
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;

        // Build CFGs for all functions
        let cfgs = cfg::analyze_function(tree, &content, path)?;

        // Find the requested function
        let cfg = cfgs
            .iter()
            .find(|c| c.function_name == function)
            .ok_or_else(|| anyhow!("Function '{}' not found in {}", function, path))?;

        Ok(cfg.to_markdown())
    }

    /// Find dead code including unreachable blocks, dead stores, and unused imports
    ///
    /// # Arguments
    /// * `repo` - Repository name
    /// * `path` - File path relative to repository root
    /// * `function` - Optional function name to focus analysis on
    /// * `exclude_tests` - Whether to skip test files (default: true)
    ///
    /// # Returns
    /// Markdown-formatted dead code analysis report
    ///
    /// # Errors
    /// Returns an error if the repository or file is not found, or if parsing fails
    pub async fn find_dead_code(
        &self,
        repo: &str,
        path: &str,
        function: Option<&str>,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::dead_code;
        use crate::security_rules::is_test_file;

        let exclude_tests = exclude_tests.unwrap_or(true);
        if exclude_tests && is_test_file(path) {
            return Ok(format!("# Dead Code Analysis: `{}`\n\nSkipped: test file (use exclude_tests=false to include)", path));
        }

        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;

        let parsed = self.parser.parse_file(&full_path, &content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;

        // Use the comprehensive dead code analysis
        let mut report = dead_code::analyze_dead_code(tree, &content, path)?;

        // Filter by function if specified
        if let Some(func_name) = function {
            report
                .unreachable_blocks
                .retain(|b| b.function_name == func_name);
            report.dead_stores.retain(|d| d.function_name == func_name);
            // Note: unused_imports are file-level, not function-level
        }

        Ok(report.to_markdown())
    }

    // ==================== Data Flow Graph (DFG) Tools ====================

    /// Get data flow analysis for a specific function
    pub async fn get_data_flow(&self, repo: &str, path: &str, function: &str) -> Result<String> {
        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;

        let parsed = self.parser.parse_file(&full_path, &content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;
        let analyses = dfg::analyze_file(tree, &content, path)?;

        // Find the requested function
        let analysis = analyses
            .iter()
            .find(|a| a.function_name == function)
            .ok_or_else(|| anyhow!("Function '{}' not found in {}", function, path))?;

        Ok(analysis.to_markdown())
    }

    /// Get reaching definitions analysis for a function
    pub async fn get_reaching_definitions(
        &self,
        repo: &str,
        path: &str,
        function: &str,
    ) -> Result<String> {
        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;

        let parsed = self.parser.parse_file(&full_path, &content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;
        let cfgs = cfg::analyze_function(tree, &content, path)?;

        let cfg = cfgs
            .iter()
            .find(|c| c.function_name == function)
            .ok_or_else(|| anyhow!("Function '{}' not found in {}", function, path))?;

        let mut analyzer = dfg::DfgAnalyzer::new(cfg);
        let analysis = analyzer.analyze();

        let mut output = String::new();
        output.push_str(&format!("# Reaching Definitions: `{}`\n\n", function));
        output.push_str(&format!("**File**: `{}`\n\n", path));

        output.push_str("## Def-Use Chains\n\n");
        for chain in &analysis.def_use_chains {
            output.push_str(&format!(
                "### `{}` (line {})\n\n",
                chain.definition.variable, chain.definition.line
            ));

            if chain.uses.is_empty() {
                output.push_str("*No uses found (dead store)*\n\n");
            } else {
                output.push_str("**Reaches**:\n");
                for use_ in &chain.uses {
                    output.push_str(&format!("- Line {}: {:?}\n", use_.line, use_.kind));
                }
                output.push('\n');
            }
        }

        Ok(output)
    }

    /// Find variables that may be used before initialization
    pub async fn find_uninitialized(
        &self,
        repo: &str,
        path: &str,
        function: Option<&str>,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::security_rules::is_test_file;

        let exclude_tests = exclude_tests.unwrap_or(true);
        if exclude_tests && is_test_file(path) {
            return Ok(format!("# Uninitialized Variable Analysis: `{}`\n\nSkipped: test file (use exclude_tests=false to include)", path));
        }

        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;

        let parsed = self.parser.parse_file(&full_path, &content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;
        let analyses = dfg::analyze_file(tree, &content, path)?;

        let mut output = String::new();
        output.push_str(&format!(
            "# Uninitialized Variable Analysis: `{}`\n\n",
            path
        ));

        let mut total_issues = 0;

        for analysis in &analyses {
            if let Some(func_name) = function {
                if analysis.function_name != func_name {
                    continue;
                }
            }

            if !analysis.uninitialized_uses.is_empty() {
                output.push_str(&format!("## Function: `{}`\n\n", analysis.function_name));
                output.push_str("⚠️ **Potentially uninitialized variables:**\n\n");

                for use_ in &analysis.uninitialized_uses {
                    output.push_str(&format!(
                        "- `{}` at line {} ({:?})\n",
                        use_.variable, use_.line, use_.kind
                    ));
                    total_issues += 1;
                }
                output.push('\n');
            }
        }

        if total_issues == 0 {
            output.push_str("✅ No potentially uninitialized variables detected.\n");
        } else {
            output.push_str(&format!(
                "\n**Total**: {} potential issue(s) found.\n",
                total_issues
            ));
        }

        Ok(output)
    }

    /// Find dead stores (assignments that are never read)
    pub async fn find_dead_stores(
        &self,
        repo: &str,
        path: &str,
        function: Option<&str>,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::security_rules::is_test_file;

        let exclude_tests = exclude_tests.unwrap_or(true);
        if exclude_tests && is_test_file(path) {
            return Ok(format!("# Dead Store Analysis: `{}`\n\nSkipped: test file (use exclude_tests=false to include)", path));
        }

        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;

        let parsed = self.parser.parse_file(&full_path, &content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;
        let analyses = dfg::analyze_file(tree, &content, path)?;

        let mut output = String::new();
        output.push_str(&format!("# Dead Store Analysis: `{}`\n\n", path));

        let mut total_dead = 0;

        for analysis in &analyses {
            if let Some(func_name) = function {
                if analysis.function_name != func_name {
                    continue;
                }
            }

            if !analysis.dead_stores.is_empty() {
                output.push_str(&format!("## Function: `{}`\n\n", analysis.function_name));
                output.push_str("⚠️ **Dead stores (assignments never read):**\n\n");

                for def in &analysis.dead_stores {
                    output.push_str(&format!(
                        "- `{}` at line {} (block {})\n",
                        def.variable, def.line, def.block
                    ));
                    total_dead += 1;
                }
                output.push('\n');
            }
        }

        if total_dead == 0 {
            output.push_str("✅ No dead stores detected.\n");
        } else {
            output.push_str(&format!(
                "\n**Total**: {} dead store(s) found.\n",
                total_dead
            ));
        }

        Ok(output)
    }

    // Phase 2: Enhanced Search & Embeddings

    /// Perform hybrid search combining BM25 and TF-IDF
    pub async fn hybrid_search(
        &self,
        query: &str,
        repo: Option<&str>,
        max_results: usize,
        mode: &str,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::chunking::AstChunker;
        use crate::embeddings::EmbeddingEngine;
        use crate::hybrid_search::create_hybrid_engine;
        use crate::search::ConcurrentSearchIndex;
        use crate::security_rules::is_test_file;
        use std::sync::Arc;

        let exclude_tests = exclude_tests.unwrap_or(false); // Default false for search

        // Create search engines
        let bm25_index = Arc::new(ConcurrentSearchIndex::new());
        let tfidf_engine = Arc::new(EmbeddingEngine::new(self.options.embedding_dim));
        let hybrid_engine = create_hybrid_engine(bm25_index.clone(), tfidf_engine.clone());
        let chunker = AstChunker::new();

        // Index all files from relevant repos
        for repo_entry in self.repos.iter() {
            let repo_name = repo_entry.key();
            let repo_meta = repo_entry.value();

            // Filter by repo if specified
            if let Some(target_repo) = repo {
                if repo_name != target_repo && !repo_meta.path.ends_with(target_repo) {
                    continue;
                }
            }

            let repo_path = &repo_meta.path;

            for file_entry in self.file_cache.iter() {
                let file_path = file_entry.key();
                if !file_path.starts_with(repo_path) {
                    continue;
                }
                // Skip test files if exclude_tests is enabled
                if exclude_tests && is_test_file(&file_path.to_string_lossy()) {
                    continue;
                }

                let content = file_entry.value();
                let file_path_str = file_path.to_string_lossy().to_string();

                // Chunk the file (catch panics from malformed UTF-8 boundaries)
                let chunks = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    chunker.chunk_file(content, &file_path_str)
                })) {
                    Ok(chunks) => chunks,
                    Err(_) => {
                        tracing::warn!("Skipping file due to chunking error: {}", file_path_str);
                        continue;
                    }
                };

                // Index each chunk
                for chunk in chunks {
                    hybrid_engine.index_chunk(&chunk);
                }
            }
        }

        // Perform search based on mode
        let results = match mode {
            "bm25" => hybrid_engine.search_bm25(query, max_results),
            "tfidf" => hybrid_engine.search_tfidf(query, max_results),
            _ => hybrid_engine.search(query, max_results),
        };

        // Format results
        let mut output = String::new();
        output.push_str(&format!("# Hybrid Search Results for: `{}`\n\n", query));
        output.push_str(&format!("**Mode**: {}\n", mode));
        output.push_str(&format!("**Results**: {}\n\n", results.len()));

        for (i, result) in results.iter().enumerate() {
            output.push_str(&format!("## {}. {}\n", i + 1, result.file_path));
            output.push_str(&format!("- **Score**: {:.4}\n", result.score));
            output.push_str(&format!(
                "- **Lines**: {}-{}\n",
                result.start_line, result.end_line
            ));

            if let Some(bm25) = result.bm25_rank {
                output.push_str(&format!("- **BM25 rank**: {}\n", bm25 + 1));
            }
            if let Some(tfidf) = result.tfidf_rank {
                output.push_str(&format!("- **TF-IDF rank**: {}\n", tfidf + 1));
            }

            if !result.matched_terms.is_empty() {
                output.push_str(&format!(
                    "- **Matched terms**: {}\n",
                    result.matched_terms.join(", ")
                ));
            }

            // Show snippet
            output.push_str("\n```\n");
            let snippet_lines: Vec<&str> = result.content.lines().take(10).collect();
            output.push_str(&snippet_lines.join("\n"));
            if result.content.lines().count() > 10 {
                output.push_str("\n... (truncated)");
            }
            output.push_str("\n```\n\n");
        }

        if results.is_empty() {
            output.push_str("No results found.\n");
        }

        Ok(output)
    }

    /// Search over AST-aware code chunks
    pub async fn search_chunks(
        &self,
        query: &str,
        repo: Option<&str>,
        chunk_type: Option<&str>,
        max_results: usize,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::chunking::{AstChunker, ChunkType};
        use crate::search::tokenize_code;
        use crate::security_rules::is_test_file;

        let exclude_tests = exclude_tests.unwrap_or(false); // Default false for search
        let chunker = AstChunker::new();
        let query_tokens: std::collections::HashSet<_> = tokenize_code(query).into_iter().collect();
        let mut all_chunks = Vec::new();

        let target_type = chunk_type.and_then(|t| match t {
            "function" => Some(ChunkType::Function),
            "method" => Some(ChunkType::Method),
            "class" => Some(ChunkType::Class),
            "trait" => Some(ChunkType::Trait),
            "module" => Some(ChunkType::Module),
            _ => None,
        });

        // Collect chunks from relevant repos
        for repo_entry in self.repos.iter() {
            let repo_name = repo_entry.key();
            let repo_meta = repo_entry.value();

            // Filter by repo if specified
            if let Some(target_repo) = repo {
                if repo_name != target_repo && !repo_meta.path.ends_with(target_repo) {
                    continue;
                }
            }

            let repo_path = &repo_meta.path;

            for file_entry in self.file_cache.iter() {
                // Skip test files if exclude_tests is enabled
                if exclude_tests && is_test_file(&file_entry.key().to_string_lossy()) {
                    continue;
                }
                let file_path = file_entry.key();
                if !file_path.starts_with(repo_path) {
                    continue;
                }

                let content = file_entry.value();
                let file_path_str = file_path.to_string_lossy().to_string();

                let chunks = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    chunker.chunk_file(content, &file_path_str)
                })) {
                    Ok(chunks) => chunks,
                    Err(_) => {
                        tracing::warn!("Skipping file due to chunking error: {}", file_path_str);
                        continue;
                    }
                };

                for chunk in chunks {
                    // Filter by type if specified
                    if let Some(ref target) = target_type {
                        if chunk.chunk_type != *target {
                            continue;
                        }
                    }

                    // Score the chunk
                    let chunk_tokens: std::collections::HashSet<_> =
                        tokenize_code(&chunk.content).into_iter().collect();
                    let common = query_tokens.intersection(&chunk_tokens).count();
                    let score = if query_tokens.is_empty() {
                        0.0
                    } else {
                        common as f64 / query_tokens.len() as f64
                    };

                    if score > 0.0 {
                        all_chunks.push((chunk, score));
                    }
                }
            }
        }

        // Sort by score
        all_chunks.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        all_chunks.truncate(max_results);

        // Format results
        let mut output = String::new();
        output.push_str(&format!("# Chunk Search Results for: `{}`\n\n", query));
        if let Some(ct) = chunk_type {
            output.push_str(&format!("**Filter**: {} chunks only\n", ct));
        }
        output.push_str(&format!("**Results**: {}\n\n", all_chunks.len()));

        for (i, (chunk, score)) in all_chunks.iter().enumerate() {
            output.push_str(&format!("## {}. {}\n", i + 1, chunk.id));
            output.push_str(&format!("- **File**: {}\n", chunk.file_path));
            output.push_str(&format!(
                "- **Lines**: {}-{}\n",
                chunk.start_line, chunk.end_line
            ));
            output.push_str(&format!("- **Type**: {}\n", chunk.chunk_type));
            output.push_str(&format!("- **Score**: {:.2}\n", score));

            if let Some(ref ctx) = chunk.symbol_context {
                output.push_str(&format!("- **Symbol**: `{}` ({:?})\n", ctx.name, ctx.kind));
                if let Some(ref sig) = ctx.signature {
                    output.push_str(&format!(
                        "- **Signature**: `{}`\n",
                        sig.chars().take(100).collect::<String>()
                    ));
                }
            }

            if let Some(ref doc) = chunk.doc_comment {
                let doc_preview: String = doc.lines().take(2).collect::<Vec<_>>().join(" ");
                output.push_str(&format!(
                    "- **Doc**: {}\n",
                    doc_preview.chars().take(80).collect::<String>()
                ));
            }

            output.push_str("\n```\n");
            let snippet_lines: Vec<&str> = chunk.content.lines().take(15).collect();
            output.push_str(&snippet_lines.join("\n"));
            if chunk.content.lines().count() > 15 {
                output.push_str("\n... (truncated)");
            }
            output.push_str("\n```\n\n");
        }

        if all_chunks.is_empty() {
            output.push_str("No matching chunks found.\n");
        }

        Ok(output)
    }

    /// Get AST-aware chunks for a file
    pub async fn get_chunks(
        &self,
        repo: &str,
        path: &str,
        include_imports: bool,
    ) -> Result<String> {
        use crate::chunking::{AstChunker, ChunkerConfig, ChunkingStats};

        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;

        let config = ChunkerConfig {
            include_context: include_imports,
            ..Default::default()
        };
        let chunker = AstChunker::with_config(config);
        let chunks = chunker.chunk_file(&content, path);
        let stats = ChunkingStats::from_chunks(&chunks);

        let mut output = String::new();
        output.push_str(&format!("# Code Chunks: `{}`\n\n", path));
        output.push_str(&format!("**Total chunks**: {}\n", stats.total_chunks));
        output.push_str(&format!(
            "**Avg lines/chunk**: {:.1}\n",
            stats.avg_chunk_lines
        ));
        output.push_str(&format!("**Max chunk lines**: {}\n", stats.max_chunk_lines));
        output.push_str(&format!(
            "**Min chunk lines**: {}\n\n",
            stats.min_chunk_lines
        ));

        output.push_str("## Chunk Types:\n");
        for (chunk_type, count) in &stats.by_type {
            output.push_str(&format!("- {}: {}\n", chunk_type, count));
        }
        output.push('\n');

        for (i, chunk) in chunks.iter().enumerate() {
            output.push_str(&format!(
                "---\n\n## Chunk {} ({})\n",
                i + 1,
                chunk.chunk_type
            ));
            output.push_str(&format!(
                "**Lines**: {}-{}\n",
                chunk.start_line, chunk.end_line
            ));

            if let Some(ref ctx) = chunk.symbol_context {
                output.push_str(&format!("**Symbol**: `{}` ({:?})\n", ctx.name, ctx.kind));
            }

            if !chunk.imports.is_empty() && include_imports {
                output.push_str(&format!(
                    "**Imports**: {} statements\n",
                    chunk.imports.len()
                ));
            }

            output.push_str("\n```\n");
            output.push_str(&chunk.content);
            output.push_str("\n```\n\n");
        }

        Ok(output)
    }

    /// Get statistics about code chunks in a repository
    pub async fn get_chunk_stats(&self, repo: &str) -> Result<String> {
        use crate::chunking::{AstChunker, ChunkingStats};

        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let repo_path = repo_meta.path.clone();
        drop(repo_meta); // Release the lock

        let chunker = AstChunker::new();
        let mut all_chunks = Vec::new();
        let mut file_count = 0;

        for file_entry in self.file_cache.iter() {
            let file_path = file_entry.key();
            if !file_path.starts_with(&repo_path) {
                continue;
            }

            file_count += 1;
            let content = file_entry.value();
            let file_path_str = file_path.to_string_lossy().to_string();

            let chunks = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                chunker.chunk_file(content, &file_path_str)
            })) {
                Ok(chunks) => chunks,
                Err(_) => {
                    tracing::warn!("Skipping file due to chunking error: {}", file_path_str);
                    continue;
                }
            };
            all_chunks.extend(chunks);
        }

        let stats = ChunkingStats::from_chunks(&all_chunks);

        let mut output = String::new();
        output.push_str(&format!("# Chunk Statistics: `{}`\n\n", repo));
        output.push_str(&format!("**Files processed**: {}\n", file_count));
        output.push_str(&format!("**Total chunks**: {}\n", stats.total_chunks));
        output.push_str(&format!(
            "**Avg lines/chunk**: {:.1}\n",
            stats.avg_chunk_lines
        ));
        output.push_str(&format!("**Max chunk lines**: {}\n", stats.max_chunk_lines));
        output.push_str(&format!(
            "**Min chunk lines**: {}\n\n",
            stats.min_chunk_lines
        ));

        output.push_str("## Chunks by Type:\n\n");
        output.push_str("| Type | Count | Percentage |\n");
        output.push_str("|------|-------|------------|\n");

        let mut types: Vec<_> = stats.by_type.into_iter().collect();
        types.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

        for (chunk_type, count) in types {
            let pct = if stats.total_chunks > 0 {
                count as f64 / stats.total_chunks as f64 * 100.0
            } else {
                0.0
            };
            output.push_str(&format!("| {} | {} | {:.1}% |\n", chunk_type, count, pct));
        }

        Ok(output)
    }

    /// Get statistics about the embedding index
    pub async fn get_embedding_stats(&self) -> Result<String> {
        let (tfidf_stats, doc_count) = self.embedding_engine.stats();
        let search_stats = self.search_index.stats();

        let mut output = String::new();
        output.push_str("# Embedding & Search Index Statistics\n\n");

        output.push_str("## TF-IDF Embeddings\n\n");
        output.push_str(&format!("- **Documents indexed**: {}\n", doc_count));
        output.push_str(&format!(
            "- **Total docs in IDF**: {}\n",
            tfidf_stats.total_docs
        ));
        output.push_str(&format!(
            "- **Vocabulary size**: {}\n",
            tfidf_stats.vocab_size
        ));
        output.push_str(&format!(
            "- **Embedding dimension**: {}\n",
            tfidf_stats.dimension
        ));

        output.push_str("\n## BM25 Search Index\n\n");
        output.push_str(&format!(
            "- **Documents indexed**: {}\n",
            search_stats.total_documents
        ));
        output.push_str(&format!(
            "- **Total terms**: {}\n",
            search_stats.total_terms
        ));
        output.push_str(&format!(
            "- **Avg doc length**: {:.1} tokens\n",
            search_stats.avg_doc_length
        ));

        output.push_str("\n## Document Types:\n\n");
        output.push_str("| Type | Count |\n");
        output.push_str("|------|-------|\n");
        for (doc_type, count) in &search_stats.doc_types {
            output.push_str(&format!("| {:?} | {} |\n", doc_type, count));
        }

        Ok(output)
    }

    // Phase 3: Taint Analysis & Security Tools

    /// Find injection vulnerabilities using taint analysis
    pub async fn find_injection_vulnerabilities(
        &self,
        repo_name: &str,
        path: Option<&str>,
        exclude_tests: Option<bool>,
        vuln_types: &[String],
    ) -> Result<String> {
        use crate::security_rules::{
            is_security_exemplar_file, is_test_file, strip_inline_test_code,
        };

        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);
        let exclude_tests = exclude_tests.unwrap_or(true);

        let mut all_results: Vec<crate::taint::TaintAnalysisResult> = Vec::new();
        let include_all = vuln_types.contains(&"all".to_string()) || vuln_types.is_empty();

        // Get files to analyze - supports both file and directory paths
        // Always exclude security exemplar files (rule definitions) to avoid false positives
        let files_to_analyze: Vec<std::path::PathBuf> = self
            .file_cache
            .iter()
            .filter(|entry| entry.key().starts_with(&repo_path))
            .filter(|entry| {
                if let Some(specific_path) = path {
                    // Support both file and directory paths by checking if path matches
                    let entry_path = entry.key().to_string_lossy();
                    entry_path.contains(specific_path)
                } else {
                    true
                }
            })
            .filter(|entry| !exclude_tests || !is_test_file(&entry.key().to_string_lossy()))
            .filter(|entry| !is_security_exemplar_file(&entry.key().to_string_lossy()))
            .filter(|entry| {
                let path_str = entry.key().to_string_lossy();
                path_str.ends_with(".py")
                    || path_str.ends_with(".js")
                    || path_str.ends_with(".ts")
                    || path_str.ends_with(".tsx")
                    || path_str.ends_with(".go")
                    || path_str.ends_with(".rs")
                    || path_str.ends_with(".php")
                    || path_str.ends_with(".java")
                    || path_str.ends_with(".rb")
                    || path_str.ends_with(".c")
                    || path_str.ends_with(".cpp")
                    || path_str.ends_with(".cs")
                    || path_str.ends_with(".kt")
            })
            .map(|entry| entry.key().clone())
            .collect();

        for file_path in &files_to_analyze {
            if let Some(content_entry) = self.file_cache.get(file_path) {
                let content = content_entry.value();
                let file_str = file_path.to_string_lossy();
                let scan_content = if exclude_tests {
                    strip_inline_test_code(&file_str, content)
                } else {
                    std::borrow::Cow::Borrowed(content.as_str())
                };
                let result = crate::taint::analyze_code(scan_content.as_ref(), &file_str);
                all_results.push(result);
            }
        }

        // Filter and aggregate results
        let mut output = String::new();
        output.push_str(&format!(
            "# Injection Vulnerability Analysis: {}\n\n",
            repo_name
        ));

        // Collect all vulnerabilities first
        let mut all_vulns: Vec<crate::taint::TaintFlow> = Vec::new();

        for result in &all_results {
            for vuln in &result.vulnerabilities {
                if let Some(ref vuln_kind) = vuln.vulnerability {
                    let type_key = match vuln_kind {
                        crate::taint::VulnerabilityKind::SqlInjection => "sql",
                        crate::taint::VulnerabilityKind::Xss => "xss",
                        crate::taint::VulnerabilityKind::CommandInjection => "command",
                        crate::taint::VulnerabilityKind::PathTraversal => "path",
                        _ => "other",
                    };

                    if include_all || vuln_types.iter().any(|t| t == type_key) {
                        all_vulns.push(vuln.clone());
                    }
                }
            }
        }

        // Sort by severity (highest first) then by confidence
        all_vulns.sort_by(|a, b| {
            let sev_a = a.severity.unwrap_or(crate::taint::Severity::Low);
            let sev_b = b.severity.unwrap_or(crate::taint::Severity::Low);
            sev_b
                .cmp(&sev_a)
                .then_with(|| b.confidence.cmp(&a.confidence))
        });

        let total_vulns = all_vulns.len();

        // Apply pagination to prevent overwhelming responses
        const MAX_FINDINGS_PER_REQUEST: usize = 50;
        let findings_to_show = if total_vulns > MAX_FINDINGS_PER_REQUEST {
            info!(
                "Limiting output to top {} of {} findings (sorted by severity)",
                MAX_FINDINGS_PER_REQUEST, total_vulns
            );
            &all_vulns[..MAX_FINDINGS_PER_REQUEST]
        } else {
            &all_vulns[..]
        };

        // Aggregate by type
        let mut by_type: std::collections::HashMap<String, Vec<crate::taint::TaintFlow>> =
            std::collections::HashMap::new();

        for vuln in findings_to_show {
            if let Some(ref vuln_kind) = vuln.vulnerability {
                let type_name = vuln_kind.display_name().to_string();
                by_type.entry(type_name).or_default().push(vuln.clone());
            }
        }

        // Summary
        output.push_str("## Summary\n\n");
        output.push_str(&format!(
            "- **Files Analyzed**: {}\n",
            files_to_analyze.len()
        ));
        output.push_str(&format!("- **Vulnerabilities Found**: {}\n", total_vulns));

        if total_vulns > MAX_FINDINGS_PER_REQUEST {
            output.push_str(&format!(
                "- **⚠️ Results Truncated**: Showing top {} most severe findings (sorted by severity and confidence)\n",
                MAX_FINDINGS_PER_REQUEST
            ));
            output.push_str("- **Note**: Many findings may be false positives. Focus on high-severity issues first.\n");
        }
        output.push('\n');

        if total_vulns == 0 {
            output.push_str("No injection vulnerabilities detected.\n");
            return Ok(output);
        }

        // By type breakdown
        output.push_str("## Vulnerabilities by Type\n\n");
        for (type_name, vulns) in &by_type {
            output.push_str(&format!("### {} ({})\n\n", type_name, vulns.len()));

            for vuln in vulns {
                let severity_icon = match vuln.severity {
                    Some(crate::taint::Severity::Critical) => "🔴",
                    Some(crate::taint::Severity::High) => "🟠",
                    Some(crate::taint::Severity::Medium) => "🟡",
                    Some(crate::taint::Severity::Low) => "🔵",
                    _ => "⚪",
                };

                output.push_str(&format!(
                    "{} **{}:{} → {}:{}**\n",
                    severity_icon,
                    vuln.source.file_path,
                    vuln.source.line,
                    vuln.sink.file_path,
                    vuln.sink.line
                ));
                output.push_str(&format!("  - Source: `{}`\n", vuln.source.code));
                output.push_str(&format!("  - Sink: `{}`\n", vuln.sink.code));

                if let Some(ref vk) = vuln.vulnerability {
                    if let Some(cwe) = vk.cwe_id() {
                        output.push_str(&format!("  - CWE: {}\n", cwe));
                    }
                }
                output.push('\n');
            }
        }

        Ok(output)
    }

    /// Trace taint flow from a specific source location
    pub async fn trace_taint(&self, repo_name: &str, path: &str, line: usize) -> Result<String> {
        let repo_path = PathBuf::from(self.resolve_repo(repo_name)?);
        let full_path = validate_path(&repo_path, path)?;

        let content = self
            .file_cache
            .get(&full_path)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| anyhow!("File not found: {}", path))?;

        let result = crate::taint::analyze_code(&content, path);

        let mut output = String::new();
        output.push_str(&format!("# Taint Trace: {}:{}\n\n", path, line));

        // Find flows that start near this line
        let relevant_flows: Vec<_> = result
            .flows
            .iter()
            .filter(|f| f.source.line == line || (f.source.line as i64 - line as i64).abs() <= 3)
            .collect();

        if relevant_flows.is_empty() {
            output.push_str(&format!(
                "No taint sources found at or near line {}.\n\n",
                line
            ));

            // Show nearby sources
            if !result.sources.is_empty() {
                output.push_str("## Nearby Taint Sources\n\n");
                for source in result.sources.iter().take(5) {
                    output.push_str(&format!(
                        "- Line {}: `{}` ({})\n",
                        source.line,
                        source.variable,
                        source.kind.display_name()
                    ));
                }
            }
            return Ok(output);
        }

        output.push_str(&format!(
            "Found {} taint flows from this location:\n\n",
            relevant_flows.len()
        ));

        for (i, flow) in relevant_flows.iter().enumerate() {
            output.push_str(&format!("## Flow {}\n\n", i + 1));
            output.push_str(&flow.to_markdown());
            output.push_str("\n---\n\n");
        }

        Ok(output)
    }

    /// Get all taint sources in a repository or file
    pub async fn get_taint_sources(
        &self,
        repo_name: &str,
        path: Option<&str>,
        exclude_tests: Option<bool>,
        source_types: &[String],
    ) -> Result<String> {
        use crate::security_rules::{
            is_security_exemplar_file, is_test_file, strip_inline_test_code,
        };

        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);
        let exclude_tests = exclude_tests.unwrap_or(true);
        let include_all = source_types.contains(&"all".to_string()) || source_types.is_empty();

        let mut all_sources: Vec<crate::taint::TaintSource> = Vec::new();

        // Get files to analyze - supports both file and directory paths
        // Always exclude security exemplar files (rule definitions) to avoid false positives
        let files_to_analyze: Vec<std::path::PathBuf> = self
            .file_cache
            .iter()
            .filter(|entry| entry.key().starts_with(&repo_path))
            .filter(|entry| {
                if let Some(specific_path) = path {
                    // Support both file and directory paths by checking if path matches
                    let entry_path = entry.key().to_string_lossy();
                    entry_path.contains(specific_path)
                } else {
                    true
                }
            })
            .filter(|entry| !exclude_tests || !is_test_file(&entry.key().to_string_lossy()))
            .filter(|entry| !is_security_exemplar_file(&entry.key().to_string_lossy()))
            .filter(|entry| {
                let path_str = entry.key().to_string_lossy();
                path_str.ends_with(".py")
                    || path_str.ends_with(".js")
                    || path_str.ends_with(".ts")
                    || path_str.ends_with(".tsx")
                    || path_str.ends_with(".go")
                    || path_str.ends_with(".rs")
                    || path_str.ends_with(".php")
                    || path_str.ends_with(".java")
                    || path_str.ends_with(".rb")
                    || path_str.ends_with(".c")
                    || path_str.ends_with(".cpp")
                    || path_str.ends_with(".cs")
                    || path_str.ends_with(".kt")
            })
            .map(|entry| entry.key().clone())
            .collect();

        for file_path in &files_to_analyze {
            if let Some(content_entry) = self.file_cache.get(file_path) {
                let content = content_entry.value();
                let file_str = file_path.to_string_lossy();
                let scan_content = if exclude_tests {
                    strip_inline_test_code(&file_str, content)
                } else {
                    std::borrow::Cow::Borrowed(content.as_str())
                };
                let result = crate::taint::analyze_code(scan_content.as_ref(), &file_str);

                for source in result.sources {
                    // Filter by type
                    let type_match = match &source.kind {
                        crate::taint::SourceKind::UserInput { .. } => {
                            source_types.contains(&"user_input".to_string())
                        }
                        crate::taint::SourceKind::FileRead => {
                            source_types.contains(&"file_read".to_string())
                        }
                        crate::taint::SourceKind::DatabaseQuery => {
                            source_types.contains(&"database".to_string())
                        }
                        crate::taint::SourceKind::Environment => {
                            source_types.contains(&"environment".to_string())
                        }
                        crate::taint::SourceKind::Network => {
                            source_types.contains(&"network".to_string())
                        }
                        _ => true,
                    };

                    if include_all || type_match {
                        all_sources.push(source);
                    }
                }
            }
        }

        let mut output = String::new();
        output.push_str(&format!("# Taint Sources: {}\n\n", repo_name));
        output.push_str(&format!(
            "**Total sources found**: {}\n\n",
            all_sources.len()
        ));

        if all_sources.is_empty() {
            output.push_str("No taint sources found matching the criteria.\n");
            return Ok(output);
        }

        // Group by type
        let mut by_type: std::collections::HashMap<String, Vec<&crate::taint::TaintSource>> =
            std::collections::HashMap::new();
        for source in &all_sources {
            let type_name = source.kind.display_name();
            by_type.entry(type_name).or_default().push(source);
        }

        for (type_name, sources) in &by_type {
            output.push_str(&format!("## {} ({})\n\n", type_name, sources.len()));
            output.push_str("| File | Line | Variable | Code |\n");
            output.push_str("|------|------|----------|------|\n");

            for source in sources {
                let code_preview: String = source.code.chars().take(50).collect();
                output.push_str(&format!(
                    "| `{}` | {} | `{}` | `{}` |\n",
                    source.file_path, source.line, source.variable, code_preview
                ));
            }
            output.push('\n');
        }

        Ok(output)
    }

    /// Get a comprehensive security summary for a repository
    ///
    /// Results are cached for performance. Cache is invalidated when files change.
    pub async fn get_security_summary(
        &self,
        repo_name: &str,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::security_rules::{
            is_security_exemplar_file, is_test_file, strip_inline_test_code,
        };

        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);
        let exclude_tests = exclude_tests.unwrap_or(true);

        // Build cache key with discriminator for exclude_tests option
        let cache_key = AnalysisCacheKey::with_discriminator(
            &repo_name,
            "security_summary",
            format!("exclude_tests={}", exclude_tests),
        );

        // Compute repo hash for invalidation
        let repo_hash = self.compute_repo_hash(&repo_name);

        // Check cache first
        if self.options.cache_enabled {
            if let Some(cached) = self
                .analysis_cache
                .get_if_hash_matches(&cache_key, &repo_hash)
            {
                return Ok(cached);
            }
        }

        let mut total_files = 0;
        let mut total_sources = 0;
        let mut total_sinks = 0;
        let mut total_vulns = 0;
        let mut total_sanitized = 0;

        let mut vuln_by_severity: std::collections::HashMap<crate::taint::Severity, usize> =
            std::collections::HashMap::new();
        let mut vuln_by_type: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        // Analyze all supported files
        // Always exclude security exemplar files (rule definitions) to avoid false positives
        let files: Vec<(std::path::PathBuf, Arc<String>)> = self
            .file_cache
            .iter()
            .filter(|entry| entry.key().starts_with(&repo_path))
            .filter(|entry| !exclude_tests || !is_test_file(&entry.key().to_string_lossy()))
            .filter(|entry| !is_security_exemplar_file(&entry.key().to_string_lossy()))
            .filter(|entry| {
                let path_str = entry.key().to_string_lossy();
                path_str.ends_with(".py")
                    || path_str.ends_with(".js")
                    || path_str.ends_with(".ts")
                    || path_str.ends_with(".tsx")
                    || path_str.ends_with(".go")
                    || path_str.ends_with(".rs")
            })
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        for (file_path, content) in &files {
            total_files += 1;
            let file_str = file_path.to_string_lossy();
            let scan_content = if exclude_tests {
                strip_inline_test_code(&file_str, content)
            } else {
                std::borrow::Cow::Borrowed(content.as_str())
            };
            let result = crate::taint::analyze_code(scan_content.as_ref(), &file_str);

            total_sources += result.sources.len();
            total_sinks += result.sinks.len();

            for flow in &result.flows {
                if flow.is_sanitized {
                    total_sanitized += 1;
                } else if flow.vulnerability.is_some() {
                    total_vulns += 1;

                    if let Some(sev) = flow.severity {
                        *vuln_by_severity.entry(sev).or_insert(0) += 1;
                    }

                    if let Some(ref vuln_kind) = flow.vulnerability {
                        *vuln_by_type
                            .entry(vuln_kind.display_name().to_string())
                            .or_insert(0) += 1;
                    }
                }
            }
        }

        let mut output = String::new();
        output.push_str(&format!("# Security Summary: {}\n\n", repo_name));

        // Risk assessment
        let risk_level = if vuln_by_severity
            .get(&crate::taint::Severity::Critical)
            .unwrap_or(&0)
            > &0
        {
            "🔴 CRITICAL"
        } else if vuln_by_severity
            .get(&crate::taint::Severity::High)
            .unwrap_or(&0)
            > &0
        {
            "🟠 HIGH"
        } else if total_vulns > 0 {
            "🟡 MEDIUM"
        } else {
            "🟢 LOW"
        };

        output.push_str(&format!("## Risk Level: {}\n\n", risk_level));

        // Statistics
        output.push_str("## Analysis Statistics\n\n");
        output.push_str(&format!("- **Files Analyzed**: {}\n", total_files));
        output.push_str(&format!("- **Taint Sources**: {}\n", total_sources));
        output.push_str(&format!("- **Taint Sinks**: {}\n", total_sinks));
        output.push_str(&format!("- **Vulnerabilities Found**: {}\n", total_vulns));
        output.push_str(&format!("- **Sanitized Flows**: {}\n\n", total_sanitized));

        // Vulnerability breakdown by severity
        if total_vulns > 0 {
            output.push_str("## Vulnerabilities by Severity\n\n");
            for sev in [
                crate::taint::Severity::Critical,
                crate::taint::Severity::High,
                crate::taint::Severity::Medium,
                crate::taint::Severity::Low,
            ] {
                let count = vuln_by_severity.get(&sev).unwrap_or(&0);
                if *count > 0 {
                    let icon = match sev {
                        crate::taint::Severity::Critical => "🔴",
                        crate::taint::Severity::High => "🟠",
                        crate::taint::Severity::Medium => "🟡",
                        crate::taint::Severity::Low => "🔵",
                        crate::taint::Severity::Info => "⚪",
                    };
                    output.push_str(&format!("- {} {:?}: {}\n", icon, sev, count));
                }
            }
            output.push('\n');

            // Vulnerability breakdown by type
            output.push_str("## Vulnerabilities by Type\n\n");
            output.push_str("| Type | Count |\n");
            output.push_str("|------|-------|\n");
            for (vuln_type, count) in &vuln_by_type {
                output.push_str(&format!("| {} | {} |\n", vuln_type, count));
            }
            output.push('\n');

            // Recommendations
            output.push_str("## Recommendations\n\n");
            if vuln_by_type.contains_key("SQL Injection") {
                output.push_str(
                    "- **SQL Injection**: Use parameterized queries or prepared statements\n",
                );
            }
            if vuln_by_type.contains_key("Cross-Site Scripting (XSS)") {
                output.push_str(
                    "- **XSS**: Sanitize user input and use proper encoding for HTML output\n",
                );
            }
            if vuln_by_type.contains_key("Command Injection") {
                output.push_str("- **Command Injection**: Avoid shell execution or use strict input validation\n");
            }
            if vuln_by_type.contains_key("Path Traversal") {
                output.push_str("- **Path Traversal**: Validate file paths and use basename/realpath functions\n");
            }
        } else {
            output.push_str("## No vulnerabilities detected\n\n");
            output.push_str("The codebase appears secure based on the taint analysis.\n");
        }

        // Cache the result for future requests
        if self.options.cache_enabled {
            self.analysis_cache
                .insert_with_hash(cache_key, output.clone(), Some(repo_hash));
        }

        Ok(output)
    }

    // ========================================================================
    // Phase 4: Security Rules Engine
    // ========================================================================

    /// Run every security pass the engine supports and assemble a
    /// single audit report. The aggregator is a thin wrapper: it
    /// delegates the heavy lifting to `scan_security` (which already
    /// folds pattern matches, the symbolic CWE-122 heap-overflow
    /// pass, and unsanitised taint flows into one severity-ordered
    /// list) and prefixes the result with a summary panel built from
    /// `get_security_summary`.
    ///
    /// Callers were previously expected to chain those tools by
    /// hand. Having a single audit entry point makes the
    /// "is this codebase healthy?" question one round trip and
    /// guarantees the aggregated findings are deduplicated against
    /// each other rather than against whatever the user happens to
    /// have called.
    pub async fn security_audit(
        &self,
        repo_name: &str,
        path: Option<&str>,
        severity_threshold: Option<&str>,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        let scan_output = self
            .scan_security(
                repo_name,
                SecurityScanOptions {
                    path,
                    severity_threshold,
                    ruleset: None,
                    exclude_tests,
                    max_findings: None,
                    offset: None,
                },
            )
            .await?;

        let summary_output = self
            .get_security_summary(repo_name, exclude_tests)
            .await
            .ok();

        let mut output = String::from("# Security Audit\n\n");
        output.push_str("Aggregated report from every security pass the engine supports:\n\n");
        output.push_str("- Pattern rules (CWE Top 25 + OWASP Top 10 + custom rulesets)\n");
        output.push_str("- Symbolic heap-overflow detection (CWE-122)\n");
        output.push_str("- Taint-flow analysis (sources → sinks, unsanitised only)\n\n");

        if let Some(summary) = summary_output {
            output.push_str("## At a Glance\n\n");
            output.push_str(&summary);
            if !summary.ends_with('\n') {
                output.push('\n');
            }
            output.push('\n');
        }

        output.push_str("## Detailed Findings\n\n");
        output.push_str(&scan_output);

        Ok(output)
    }

    /// Scan repository for security issues using the security rules engine
    ///
    /// Phase C2: Added `max_findings` and `offset` parameters for pagination.
    /// This helps bound output size for large codebases.
    ///
    /// Results are cached when no pagination is used (offset=None, max_findings=None).
    pub async fn scan_security(
        &self,
        repo_name: &str,
        opts: SecurityScanOptions<'_>,
    ) -> Result<String> {
        use crate::heap_size;
        use crate::security_rules::{
            is_security_exemplar_file, is_test_file, strip_inline_test_code, CallGraphContext,
            FileCacheContext, SecurityRulesEngine,
        };

        let path = opts.path;
        let severity_threshold = opts.severity_threshold;
        let ruleset = opts.ruleset;
        let max_findings = opts.max_findings;
        let offset = opts.offset;

        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);
        let exclude_tests = opts.exclude_tests.unwrap_or(true);
        let min_severity = parse_severity_threshold(severity_threshold);

        // Only cache when no pagination is used
        let use_cache = self.options.cache_enabled && offset.is_none() && max_findings.is_none();

        // Build cache key with all parameters that affect output
        let cache_key = if use_cache {
            Some(AnalysisCacheKey::with_discriminator(
                &repo_name,
                "scan_security",
                format!(
                    "path={:?},severity={:?},ruleset={:?},exclude_tests={}",
                    path, severity_threshold, ruleset, exclude_tests
                ),
            ))
        } else {
            None
        };

        // Compute repo hash for invalidation
        let repo_hash = if use_cache {
            Some(self.compute_repo_hash(&repo_name))
        } else {
            None
        };

        // Check cache first (only for non-paginated requests)
        if let (Some(ref key), Some(ref hash)) = (&cache_key, &repo_hash) {
            if let Some(cached) = self.analysis_cache.get_if_hash_matches(key, hash) {
                return Ok(cached);
            }
        }

        let engine = SecurityRulesEngine::new();

        // Collect files to scan with combined filters
        // Always exclude security exemplar files (rule definitions) to avoid false positives
        let files: Vec<_> = self
            .file_cache
            .iter()
            .filter(|e| e.key().starts_with(&repo_path))
            .filter(|e| path.is_none_or(|p| e.key().to_string_lossy().contains(p)))
            .filter(|e| !exclude_tests || !is_test_file(&e.key().to_string_lossy()))
            .filter(|e| !is_security_exemplar_file(&e.key().to_string_lossy()))
            .filter(|e| is_security_scannable(&e.key().to_string_lossy()))
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();

        // Parse ruleset tags
        let ruleset_tags: Option<Vec<&str>> =
            ruleset.map(|r| r.split(',').map(str::trim).collect());

        // Build a cross-file context so the symbolic heap-overflow pass
        // can resolve allocator helpers defined in a different
        // translation unit from their write site. Prefer the project
        // call graph when available; otherwise fall back to a
        // file_cache-backed context so cross-TU resolution still works
        // when the user runs scan_security without --call-graph (which
        // is the default). Without this fallback every CWE-122 finding
        // that requires a cross-TU helper would silently disappear.
        let graph_ref_opt = self.call_graphs.get(&repo_name);
        let cg_ctx = graph_ref_opt
            .as_ref()
            .map(|g| CallGraphContext::new(g.value(), &self.file_cache, &repo_path));
        let fc_ctx = if cg_ctx.is_none() {
            Some(FileCacheContext::new(&self.file_cache, &repo_path))
        } else {
            None
        };
        let cross_file_ctx: &dyn heap_size::CrossFileContext = match (&cg_ctx, &fc_ctx) {
            (Some(c), _) => c,
            (None, Some(c)) => c,
            (None, None) => unreachable!("fc_ctx is set whenever cg_ctx is None"),
        };

        // Scan all files and filter by severity
        let mut findings: Vec<_> = files
            .iter()
            .flat_map(|(file_path, content)| {
                let file_str = file_path.to_string_lossy();
                let lang = detect_language_from_path(&file_str);
                let scan_content = if exclude_tests {
                    strip_inline_test_code(&file_str, content)
                } else {
                    std::borrow::Cow::Borrowed(content.as_str())
                };
                match &ruleset_tags {
                    Some(tags) => {
                        engine.scan_with_tags(scan_content.as_ref(), &file_str, &lang, tags)
                    }
                    None => engine.scan_with_context(
                        scan_content.as_ref(),
                        &file_str,
                        &lang,
                        cross_file_ctx,
                    ),
                }
            })
            .filter(|f| f.severity >= min_severity)
            .collect();

        // Fold in the taint analyser's output so the caller does not
        // need a separate trace_taint / get_taint_sources pass: every
        // unsanitised flow becomes a TAINT-* finding alongside the
        // pattern matches. Skip when a tag-filtered ruleset is in
        // effect — the caller asked for a specific tag set, and
        // taint flows are not currently tagged.
        if ruleset_tags.is_none() {
            for (file_path, content) in &files {
                let file_str = file_path.to_string_lossy();
                let scan_content = if exclude_tests {
                    strip_inline_test_code(&file_str, content)
                } else {
                    std::borrow::Cow::Borrowed(content.as_str())
                };
                let analysis = crate::taint::analyze_code(scan_content.as_ref(), &file_str);
                for flow in &analysis.vulnerabilities {
                    if let Some(finding) =
                        crate::security_rules::taint_flow_to_security_finding(flow)
                    {
                        if finding.severity >= min_severity {
                            findings.push(finding);
                        }
                    }
                }
            }
            crate::security_rules::dedupe_findings(&mut findings);
        }

        findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

        // Phase C2: Apply pagination (offset and limit)
        let total_findings = findings.len();
        let offset = offset.unwrap_or(0);
        let findings = if offset > 0 || max_findings.is_some() {
            let start = offset.min(findings.len());
            let end = match max_findings {
                Some(limit) => (start + limit).min(findings.len()),
                None => findings.len(),
            };
            findings[start..end].to_vec()
        } else {
            findings
        };
        let truncated = findings.len() < total_findings;

        // Build output
        let mut output = format!("# Security Scan: {}\n\n", repo_name);
        output.push_str(SECURITY_REPORT_HEURISTIC_HINT);
        output.push_str(&format!("**Files Scanned**: {}\n", files.len()));
        output.push_str(&format!(
            "**Test Files**: {}\n",
            if exclude_tests {
                "excluded"
            } else {
                "included"
            }
        ));
        if let Some(ref tags) = ruleset_tags {
            output.push_str(&format!("**Ruleset Filter**: {}\n", tags.join(", ")));
        }

        // Phase C2: Show pagination info
        if truncated {
            output.push_str(&format!(
                "**Findings**: {} (showing {} of {}, offset: {})\n\n",
                findings.len(),
                findings.len(),
                total_findings,
                offset
            ));
        } else {
            output.push_str(&format!("**Findings**: {}\n\n", findings.len()));
        }

        if findings.is_empty() {
            if truncated && offset >= total_findings {
                output.push_str(&format!(
                    "Offset {} exceeds total findings {}. Try a smaller offset.\n",
                    offset, total_findings
                ));
            } else {
                output.push_str("No security issues found above the severity threshold.\n");
            }
        } else {
            output.push_str(&format_findings_by_severity(&findings));

            // Phase C2: Add pagination hint
            if truncated {
                output.push_str(&format!(
                    "\n---\n*Results truncated. Use `offset: {}` to see more findings.*\n",
                    offset + findings.len()
                ));
            }
        }

        // Cache the result (only for non-paginated requests)
        if let (Some(key), Some(hash)) = (cache_key, repo_hash) {
            self.analysis_cache
                .insert_with_hash(key, output.clone(), Some(hash));
        }

        Ok(output)
    }

    /// Scan for OWASP Top 10 vulnerabilities
    pub async fn check_owasp_top10(
        &self,
        repo_name: &str,
        path: Option<&str>,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::security_rules::{
            is_security_exemplar_file, is_test_file, strip_inline_test_code, SecurityRulesEngine,
        };

        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);
        let engine = SecurityRulesEngine::new();
        let exclude_tests = exclude_tests.unwrap_or(true);

        // Always exclude security exemplar files (rule definitions) to avoid false positives
        let files: Vec<_> = self
            .file_cache
            .iter()
            .filter(|e| e.key().starts_with(&repo_path))
            .filter(|e| path.is_none_or(|p| e.key().to_string_lossy().contains(p)))
            .filter(|e| !exclude_tests || !is_test_file(&e.key().to_string_lossy()))
            .filter(|e| !is_security_exemplar_file(&e.key().to_string_lossy()))
            .filter(|e| is_security_scannable(&e.key().to_string_lossy()))
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();

        let mut findings: Vec<_> = files
            .iter()
            .flat_map(|(file_path, content)| {
                let file_str = file_path.to_string_lossy();
                let scan_content = if exclude_tests {
                    strip_inline_test_code(&file_str, content)
                } else {
                    std::borrow::Cow::Borrowed(content.as_str())
                };
                engine.scan_owasp_top10(
                    scan_content.as_ref(),
                    &file_str,
                    &detect_language_from_path(&file_str),
                )
            })
            .collect();

        findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

        let mut output = format!("# OWASP Top 10 2021 Scan: {}\n\n", repo_name);
        output.push_str(SECURITY_REPORT_HEURISTIC_HINT);
        output.push_str(&format!("**Files Scanned**: {}\n", files.len()));
        output.push_str(&format!("**Findings**: {}\n\n", findings.len()));

        if findings.is_empty() {
            output.push_str("No OWASP Top 10 issues detected.\n");
        } else {
            output.push_str(&format_findings_by_category(
                &findings,
                OWASP_TOP10_CATEGORIES,
                |f| &f.owasp,
            ));
        }

        Ok(output)
    }

    /// Scan for CWE Top 25 vulnerabilities
    pub async fn check_cwe_top25(
        &self,
        repo_name: &str,
        path: Option<&str>,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::security_rules::{
            is_security_exemplar_file, is_test_file, strip_inline_test_code, SecurityRulesEngine,
        };

        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);
        let engine = SecurityRulesEngine::new();
        let exclude_tests = exclude_tests.unwrap_or(true);

        // Always exclude security exemplar files (rule definitions) to avoid false positives
        let files: Vec<_> = self
            .file_cache
            .iter()
            .filter(|e| e.key().starts_with(&repo_path))
            .filter(|e| path.is_none_or(|p| e.key().to_string_lossy().contains(p)))
            .filter(|e| !exclude_tests || !is_test_file(&e.key().to_string_lossy()))
            .filter(|e| !is_security_exemplar_file(&e.key().to_string_lossy()))
            .filter(|e| is_security_scannable(&e.key().to_string_lossy()))
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();

        let mut findings: Vec<_> = files
            .iter()
            .flat_map(|(file_path, content)| {
                let file_str = file_path.to_string_lossy();
                let scan_content = if exclude_tests {
                    strip_inline_test_code(&file_str, content)
                } else {
                    std::borrow::Cow::Borrowed(content.as_str())
                };
                engine.scan_cwe_top25(
                    scan_content.as_ref(),
                    &file_str,
                    &detect_language_from_path(&file_str),
                )
            })
            .collect();

        findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

        let mut output = format!("# CWE Top 25 Scan: {}\n\n", repo_name);
        output.push_str(SECURITY_REPORT_HEURISTIC_HINT);
        output.push_str(&format!("**Files Scanned**: {}\n", files.len()));
        output.push_str(&format!("**Findings**: {}\n\n", findings.len()));

        if findings.is_empty() {
            output.push_str("No CWE Top 25 issues detected.\n");
        } else {
            output.push_str(&format_findings_by_category(
                &findings,
                CWE_TOP25_TYPES,
                |f| &f.cwe,
            ));
        }

        Ok(output)
    }

    /// Get explanation of a vulnerability type
    pub async fn explain_vulnerability(
        &self,
        rule_id: Option<&str>,
        cwe: Option<&str>,
    ) -> Result<String> {
        use crate::security_rules::SecurityRulesEngine;

        let engine = SecurityRulesEngine::new();
        let mut output = String::new();

        // Look up by rule ID first
        if let Some(id) = rule_id {
            if let Some(explanation) = engine.explain_vulnerability(id) {
                output.push_str(&format!("# {}\n\n", explanation.name));
                output.push_str(&format!("**Rule ID**: {}\n", explanation.rule_id));
                output.push_str(&format!("**Severity**: {:?}\n\n", explanation.severity));

                if !explanation.cwe.is_empty() {
                    output.push_str("**CWE IDs**: ");
                    output.push_str(&explanation.cwe.join(", "));
                    output.push_str("\n\n");
                }

                if !explanation.owasp.is_empty() {
                    output.push_str("**OWASP Categories**: ");
                    output.push_str(&explanation.owasp.join(", "));
                    output.push_str("\n\n");
                }

                output.push_str("## Description\n\n");
                output.push_str(&explanation.description);
                output.push_str("\n\n");

                output.push_str("## Remediation\n\n");
                output.push_str(&explanation.remediation);
                output.push_str("\n\n");

                if !explanation.examples.is_empty() {
                    output.push_str("## Examples\n\n");
                    for example in &explanation.examples {
                        output.push_str(&format!("### {} Example\n\n", example.language));
                        output.push_str("**Vulnerable Code:**\n```\n");
                        output.push_str(&example.vulnerable);
                        output.push_str("\n```\n\n**Fixed Code:**\n```\n");
                        output.push_str(&example.fixed);
                        output.push_str("\n```\n\n");
                        output.push_str(&example.explanation);
                        output.push_str("\n\n");
                    }
                }

                if !explanation.references.is_empty() {
                    output.push_str("## References\n\n");
                    for ref_url in &explanation.references {
                        output.push_str(&format!("- {}\n", ref_url));
                    }
                }

                return Ok(output);
            }
        }

        // Look up by CWE
        if let Some(cwe_id) = cwe {
            // Find rules that match this CWE
            let matching_rules: Vec<_> = engine
                .get_rules()
                .into_iter()
                .filter(|r| r.cwe.iter().any(|c| c.contains(cwe_id)))
                .collect();

            if !matching_rules.is_empty() {
                output.push_str(&format!("# {} Vulnerabilities\n\n", cwe_id));

                // Add CWE reference
                let cwe_num = cwe_id.trim_start_matches("CWE-");
                output.push_str(&format!(
                    "**Reference**: https://cwe.mitre.org/data/definitions/{}.html\n\n",
                    cwe_num
                ));

                output.push_str("## Related Rules\n\n");
                for rule in &matching_rules {
                    output.push_str(&format!("### {} - {}\n\n", rule.id, rule.name));
                    output.push_str(&format!("**Severity**: {:?}\n\n", rule.severity));
                    output.push_str(&format!("{}\n\n", rule.message));
                    output.push_str(&format!("**Remediation**: {}\n\n", rule.remediation));
                }

                return Ok(output);
            }
        }

        output.push_str("# Vulnerability Not Found\n\n");
        output.push_str("The specified vulnerability type was not found in the rules engine.\n\n");
        output.push_str("Try one of these common rule IDs:\n");
        output.push_str("- OWASP-A03-001 (SQL Injection)\n");
        output.push_str("- OWASP-A03-003 (XSS)\n");
        output.push_str("- OWASP-A07-001 (Hardcoded Credentials)\n");
        output.push_str("- CWE-787-001 (Buffer Overflow)\n\n");
        output.push_str("Or search by CWE ID (e.g., CWE-89, CWE-79).\n");

        Ok(output)
    }

    /// Suggest fixes for a security finding
    pub async fn suggest_fix(
        &self,
        repo_name: &str,
        path: &str,
        line: usize,
        rule_id: Option<&str>,
    ) -> Result<String> {
        use crate::security_rules::SecurityRulesEngine;

        let repo_path = PathBuf::from(self.resolve_repo(repo_name)?);
        let full_path = validate_path(&repo_path, path)?;
        let engine = SecurityRulesEngine::new();

        // Get file content
        let content = self
            .file_cache
            .get(&full_path)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| anyhow!("File not found: {}", path))?;

        let file_str = full_path.to_string_lossy();
        let lang = detect_language_from_path(&file_str);

        // Scan the file
        let findings = engine.scan(&content, &file_str, &lang);

        // Find the finding at or near the specified line
        let finding = findings.iter().find(|f| {
            if let Some(rid) = rule_id {
                f.rule_id == rid && (f.line == line || (f.line <= line && f.end_line >= line))
            } else {
                f.line == line || (f.line <= line && f.end_line >= line)
            }
        });

        let mut output = String::new();

        if let Some(f) = finding {
            output.push_str(&format!("# Fix Suggestions for {}\n\n", f.rule_name));
            output.push_str(&format!("**Location**: {}:{}\n", path, f.line));
            output.push_str(&format!("**Rule**: {} - {}\n", f.rule_id, f.rule_name));
            output.push_str(&format!("**Severity**: {:?}\n\n", f.severity));

            output.push_str("## Issue\n\n");
            output.push_str(&f.message);
            output.push_str("\n\n");

            output.push_str("## Affected Code\n\n```\n");
            output.push_str(&f.snippet);
            output.push_str("\n```\n\n");

            // Get suggested fixes
            let fixes = engine.suggest_fix(f, &content);

            output.push_str("## Suggested Fixes\n\n");

            if fixes.is_empty() {
                output.push_str(&format!("**General Guidance**: {}\n", f.remediation));
            } else {
                for (i, fix) in fixes.iter().enumerate() {
                    output.push_str(&format!(
                        "### Option {} (Confidence: {:?})\n\n",
                        i + 1,
                        fix.confidence
                    ));
                    output.push_str(&fix.description);
                    output.push_str("\n\n");

                    if !fix.diff.is_empty() {
                        output.push_str("```diff\n");
                        output.push_str(&fix.diff);
                        output.push_str("\n```\n\n");
                    }
                }
            }

            // Add references
            if !f.cwe.is_empty() || !f.owasp.is_empty() {
                output.push_str("## References\n\n");
                for cwe in &f.cwe {
                    let cwe_num = cwe.trim_start_matches("CWE-");
                    output.push_str(&format!(
                        "- {}: https://cwe.mitre.org/data/definitions/{}.html\n",
                        cwe, cwe_num
                    ));
                }
                for owasp in &f.owasp {
                    output.push_str(&format!(
                        "- {}: https://owasp.org/Top10/{}\n",
                        owasp,
                        owasp.replace(":", "_")
                    ));
                }
            }
        } else {
            output.push_str("# No Finding at Specified Location\n\n");
            output.push_str(&format!(
                "No security finding found at {}:{}.\n\n",
                path, line
            ));

            if !findings.is_empty() {
                output.push_str("## Other findings in this file\n\n");
                for f in findings.iter().take(5) {
                    output.push_str(&format!(
                        "- Line {}: {} ({})\n",
                        f.line, f.rule_name, f.rule_id
                    ));
                }
            }
        }

        Ok(output)
    }

    // ========================================================================
    // Phase 5: Supply Chain Security
    // ========================================================================

    /// Generate Software Bill of Materials (SBOM) in CycloneDX or SPDX format
    ///
    /// Phase C1: Added `compact` parameter to output minified JSON (~25% smaller).
    pub async fn generate_sbom(
        &self,
        repo_name: &str,
        format: &str,
        compact: bool,
    ) -> Result<String> {
        use crate::supply_chain::{SbomFormat, SupplyChainAnalyzer};

        let repo_path = PathBuf::from(self.resolve_repo(repo_name)?);
        let analyzer = SupplyChainAnalyzer::new();

        // Get project name and version from manifest if available
        let (project_name, project_version) = self.get_project_info(&repo_path);

        let sbom_format = match format.to_lowercase().as_str() {
            "spdx" => SbomFormat::Spdx,
            "json" => SbomFormat::Json,
            _ => SbomFormat::CycloneDX,
        };

        match analyzer.generate_sbom(
            &repo_path,
            &project_name,
            &project_version,
            sbom_format,
            compact,
        ) {
            Ok(sbom) => {
                let mut output = String::new();
                output.push_str(&format!("# Software Bill of Materials: {}\n\n", repo_name));
                output.push_str(&format!("**Format**: {:?}\n", sbom_format));
                output.push_str(&format!(
                    "**Project**: {} v{}\n\n",
                    project_name, project_version
                ));
                if compact {
                    output.push_str("**Output**: Compact (minified)\n\n");
                }
                output.push_str("```json\n");
                output.push_str(&sbom);
                output.push_str("\n```\n");
                Ok(output)
            }
            Err(e) => Err(anyhow!("Failed to generate SBOM: {}", e)),
        }
    }

    /// Check dependencies for known vulnerabilities
    pub async fn check_dependencies(
        &self,
        repo_name: &str,
        severity_threshold: Option<&str>,
        include_dev: bool,
    ) -> Result<String> {
        use crate::supply_chain::{SupplyChainAnalyzer, VulnSeverity};

        let repo_path = PathBuf::from(self.resolve_repo(repo_name)?);
        let analyzer = SupplyChainAnalyzer::new();

        let min_severity = match severity_threshold {
            Some("critical") => VulnSeverity::Critical,
            Some("high") => VulnSeverity::High,
            Some("medium") => VulnSeverity::Medium,
            _ => VulnSeverity::Low,
        };

        let deps = match analyzer.parse_dependencies(&repo_path) {
            Ok(d) => d,
            Err(e) => return Err(anyhow!("Failed to parse dependencies: {}", e)),
        };

        // Filter dev dependencies if needed
        let deps: Vec<_> = if include_dev {
            deps
        } else {
            deps.into_iter().filter(|d| !d.dev_dependency).collect()
        };

        let vulns = analyzer.check_vulnerabilities(&deps);

        // Filter by severity
        let vulns: Vec<_> = vulns
            .into_iter()
            .filter(|v| v.risk_level >= min_severity)
            .collect();

        let mut output = String::new();
        output.push_str(&format!(
            "# Dependency Vulnerability Scan: {}\n\n",
            repo_name
        ));
        output.push_str(&format!("**Dependencies Scanned**: {}\n", deps.len()));
        output.push_str(&format!("**Vulnerable Dependencies**: {}\n", vulns.len()));
        output.push_str(&format!("**Severity Threshold**: {:?}\n\n", min_severity));

        if vulns.is_empty() {
            output.push_str("No vulnerable dependencies found above the severity threshold.\n");
        } else {
            // Group by severity
            let critical: Vec<_> = vulns
                .iter()
                .filter(|v| v.risk_level == VulnSeverity::Critical)
                .collect();
            let high: Vec<_> = vulns
                .iter()
                .filter(|v| v.risk_level == VulnSeverity::High)
                .collect();
            let medium: Vec<_> = vulns
                .iter()
                .filter(|v| v.risk_level == VulnSeverity::Medium)
                .collect();
            let low: Vec<_> = vulns
                .iter()
                .filter(|v| v.risk_level == VulnSeverity::Low)
                .collect();

            if !critical.is_empty() {
                output.push_str(&format!("## 🔴 Critical ({})\n\n", critical.len()));
                for v in &critical {
                    output.push_str(&format_vuln_finding(v));
                }
            }

            if !high.is_empty() {
                output.push_str(&format!("## 🟠 High ({})\n\n", high.len()));
                for v in &high {
                    output.push_str(&format_vuln_finding(v));
                }
            }

            if !medium.is_empty() {
                output.push_str(&format!("## 🟡 Medium ({})\n\n", medium.len()));
                for v in &medium {
                    output.push_str(&format_vuln_finding(v));
                }
            }

            if !low.is_empty() {
                output.push_str(&format!("## 🔵 Low ({})\n\n", low.len()));
                for v in &low {
                    output.push_str(&format_vuln_finding(v));
                }
            }
        }

        Ok(output)
    }

    /// Check license compliance for dependencies
    pub async fn check_licenses(
        &self,
        repo_name: &str,
        project_license: Option<&str>,
        fail_on_copyleft: bool,
    ) -> Result<String> {
        use crate::supply_chain::SupplyChainAnalyzer;

        let repo_path = PathBuf::from(self.resolve_repo(repo_name)?);
        let analyzer = SupplyChainAnalyzer::new();

        let deps = match analyzer.parse_dependencies(&repo_path) {
            Ok(d) => d,
            Err(e) => return Err(anyhow!("Failed to parse dependencies: {}", e)),
        };

        let report = analyzer.check_licenses(&deps, project_license);

        let mut output = String::new();
        output.push_str(&format!("# License Compliance Report: {}\n\n", repo_name));

        if let Some(lic) = project_license {
            output.push_str(&format!("**Project License**: {}\n", lic));
        }
        output.push_str(&format!("**Dependencies Analyzed**: {}\n\n", deps.len()));
        output.push_str(&format!("{}\n\n", report.summary));

        // License distribution
        output.push_str("## License Distribution\n\n");
        output.push_str("| License | Count | Dependencies |\n");
        output.push_str("|---------|-------|-------------|\n");

        let mut sorted_licenses: Vec<_> = report.dependencies_by_license.iter().collect();
        sorted_licenses.sort_by_key(|(_, dep_list)| std::cmp::Reverse(dep_list.len()));

        for (license, dep_list) in sorted_licenses.iter().take(15) {
            let deps_preview: String = dep_list
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let suffix = if dep_list.len() > 3 {
                format!(" +{} more", dep_list.len() - 3)
            } else {
                String::new()
            };
            output.push_str(&format!(
                "| {} | {} | {}{} |\n",
                license,
                dep_list.len(),
                deps_preview,
                suffix
            ));
        }
        output.push('\n');

        // Categorization
        output.push_str("## License Categories\n\n");
        output.push_str(&format!(
            "- **Permissive**: {} packages\n",
            report.permissive_deps.len()
        ));
        output.push_str(&format!(
            "- **Copyleft**: {} packages\n",
            report.copyleft_deps.len()
        ));
        output.push_str(&format!(
            "- **Unknown**: {} packages\n\n",
            report.unknown_license_deps.len()
        ));

        // Issues
        if !report.issues.is_empty() {
            output.push_str("## License Issues\n\n");

            let copyleft_issues: Vec<_> = report
                .issues
                .iter()
                .filter(|i| i.issue_type == crate::supply_chain::LicenseIssueType::Copyleft)
                .collect();
            let unknown_issues: Vec<_> = report
                .issues
                .iter()
                .filter(|i| {
                    i.issue_type == crate::supply_chain::LicenseIssueType::Unknown
                        || i.issue_type == crate::supply_chain::LicenseIssueType::NoLicense
                })
                .collect();

            if !copyleft_issues.is_empty() && fail_on_copyleft {
                output.push_str("### ⚠️ Copyleft License Warnings\n\n");
                for issue in &copyleft_issues {
                    output.push_str(&format!(
                        "- **{}**: {} ({})\n",
                        issue.dependency, issue.license, issue.message
                    ));
                    output.push_str(&format!("  - *Recommendation*: {}\n", issue.recommendation));
                }
                output.push('\n');
            }

            if !unknown_issues.is_empty() {
                output.push_str("### ⚠️ Unknown/Missing Licenses\n\n");
                for issue in &unknown_issues {
                    output.push_str(&format!("- **{}**: {}\n", issue.dependency, issue.message));
                }
                output.push('\n');
            }
        } else {
            output.push_str("No license compliance issues detected.\n");
        }

        // Copyleft dependencies list
        if !report.copyleft_deps.is_empty() {
            output.push_str("## Copyleft Dependencies\n\n");
            output.push_str("These dependencies may have viral licensing requirements:\n\n");
            for dep in &report.copyleft_deps {
                output.push_str(&format!("- {}\n", dep));
            }
            output.push('\n');
        }

        Ok(output)
    }

    /// Find safe upgrade paths for vulnerable dependencies
    pub async fn find_upgrade_path(
        &self,
        repo_name: &str,
        dependency: Option<&str>,
    ) -> Result<String> {
        use crate::supply_chain::SupplyChainAnalyzer;

        let repo_path = PathBuf::from(self.resolve_repo(repo_name)?);
        let analyzer = SupplyChainAnalyzer::new();

        let deps = match analyzer.parse_dependencies(&repo_path) {
            Ok(d) => d,
            Err(e) => return Err(anyhow!("Failed to parse dependencies: {}", e)),
        };

        // Filter to specific dependency if requested
        let deps: Vec<_> = if let Some(dep_name) = dependency {
            deps.into_iter().filter(|d| d.name == dep_name).collect()
        } else {
            deps
        };

        let vulns = analyzer.check_vulnerabilities(&deps);
        let upgrades = analyzer.find_upgrade_path(&vulns);

        let mut output = String::new();
        output.push_str(&format!("# Upgrade Recommendations: {}\n\n", repo_name));

        if let Some(dep) = dependency {
            output.push_str(&format!("**Dependency**: {}\n\n", dep));
        }

        if upgrades.is_empty() {
            if dependency.is_some() {
                output.push_str("No vulnerable versions found for this dependency.\n");
            } else {
                output.push_str("No vulnerable dependencies require upgrading.\n");
            }
        } else {
            output.push_str(&format!("**Upgrades Recommended**: {}\n\n", upgrades.len()));

            output.push_str(
                "| Dependency | Current | Recommended | Breaking | Vulnerabilities Fixed |\n",
            );
            output.push_str(
                "|------------|---------|-------------|----------|----------------------|\n",
            );

            for upgrade in &upgrades {
                let breaking = if upgrade.breaking_changes {
                    "⚠️ Yes"
                } else {
                    "No"
                };
                let fixed = upgrade.vulnerabilities_fixed.join(", ");
                output.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    upgrade.dependency,
                    upgrade.current_version,
                    upgrade.recommended_version,
                    breaking,
                    fixed
                ));
            }
            output.push('\n');

            // Detailed recommendations
            output.push_str("## Detailed Recommendations\n\n");
            for upgrade in &upgrades {
                output.push_str(&format!("### {}\n\n", upgrade.dependency));
                output.push_str(&format!("- **Current**: {}\n", upgrade.current_version));
                output.push_str(&format!(
                    "- **Recommended**: {}\n",
                    upgrade.recommended_version
                ));
                output.push_str(&format!("- **Reason**: {:?}\n", upgrade.reason));

                if upgrade.breaking_changes {
                    output.push_str(
                        "- **⚠️ Breaking Changes Expected**: Review changelog before upgrading\n",
                    );
                }

                if !upgrade.vulnerabilities_fixed.is_empty() {
                    output.push_str("- **Fixes**:\n");
                    for vuln_id in &upgrade.vulnerabilities_fixed {
                        output.push_str(&format!("  - {}\n", vuln_id));
                    }
                }
                output.push('\n');
            }
        }

        Ok(output)
    }

    /// Helper: Get project name and version from manifest files
    fn get_project_info(&self, repo_path: &std::path::Path) -> (String, String) {
        // Try Cargo.toml
        let cargo_toml = repo_path.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                if let Ok(parsed) = toml::from_str::<toml::Value>(&content) {
                    let name = parsed
                        .get("package")
                        .and_then(|p| p.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let version = parsed
                        .get("package")
                        .and_then(|p| p.get("version"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("0.0.0")
                        .to_string();
                    return (name, version);
                }
            }
        }

        // Try package.json
        let package_json = repo_path.join("package.json");
        if package_json.exists() {
            if let Ok(content) = std::fs::read_to_string(&package_json) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                    let name = parsed
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let version = parsed
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0.0.0")
                        .to_string();
                    return (name, version);
                }
            }
        }

        // Fallback to directory name
        let name = repo_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        (name, "0.0.0".to_string())
    }

    // =========================================================================
    // Phase 6: Advanced Features
    // =========================================================================

    /// Get import graph for a file or repository
    pub async fn get_import_graph(
        &self,
        repo_name: &str,
        file: Option<&str>,
        direction: &str,
    ) -> Result<String> {
        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);
        let symbols = self
            .symbols
            .get(&repo_name)
            .map(|s| s.clone())
            .unwrap_or_default();

        let mut resolver = crate::incremental::SymbolResolver::new();

        // Deduplicate file paths to avoid parsing the same file multiple times
        let unique_files: std::collections::HashSet<_> =
            symbols.iter().map(|s| s.file_path.clone()).collect();

        // Parse imports from unique files only
        for rel_path in unique_files {
            let file_path = repo_path.join(&rel_path);
            if file_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&file_path) {
                    let imports = parse_imports_from_content(&content, &rel_path);
                    resolver.register_imports(&file_path, imports);
                }
            }
        }

        let graph = resolver.build_import_graph(&repo_path);

        let mut output = String::new();
        output.push_str("# Import Graph\n\n");

        if let Some(target_file) = file {
            let target_path = repo_path.join(target_file);

            match direction {
                "imports" | "both" => {
                    output.push_str(&format!("## Files imported by `{}`\n\n", target_file));
                    let deps = graph.dependencies(&target_path);
                    if deps.is_empty() {
                        output.push_str("No imports found.\n\n");
                    } else {
                        for dep in deps {
                            let rel_path = dep
                                .strip_prefix(&repo_path)
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_else(|_| dep.to_string_lossy().to_string());
                            output.push_str(&format!("- `{}`\n", rel_path));
                        }
                        output.push('\n');
                    }
                }
                _ => {}
            }

            match direction {
                "importers" | "both" => {
                    output.push_str(&format!("## Files that import `{}`\n\n", target_file));
                    let dependents = graph.dependents(&target_path);
                    if dependents.is_empty() {
                        output.push_str("No importers found.\n\n");
                    } else {
                        for dep in dependents {
                            let rel_path = dep
                                .strip_prefix(&repo_path)
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_else(|_| dep.to_string_lossy().to_string());
                            output.push_str(&format!("- `{}`\n", rel_path));
                        }
                        output.push('\n');
                    }
                }
                _ => {}
            }

            let depth = graph.depth(&target_path);
            output.push_str(&format!("**Import depth**: {}\n", depth));
        } else {
            // Show summary for whole repo
            output.push_str("## Repository Import Summary\n\n");
            output.push_str("| File | Dependencies | Dependents |\n");
            output.push_str("|------|--------------|------------|\n");

            let mut file_stats: Vec<_> = symbols
                .iter()
                .map(|s| {
                    let path = repo_path.join(&s.file_path);
                    let deps = graph.dependencies(&path).len();
                    let dependents = graph.dependents(&path).len();
                    (s.file_path.clone(), deps, dependents)
                })
                .collect();

            file_stats.sort_by_key(|(_, deps, dependents)| std::cmp::Reverse(deps + dependents));
            file_stats.truncate(20);

            for (file, deps, dependents) in file_stats {
                output.push_str(&format!("| {} | {} | {} |\n", file, deps, dependents));
            }
        }

        Ok(output)
    }

    /// Find circular import dependencies
    pub async fn find_circular_imports(
        &self,
        repo_name: &str,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::security_rules::is_test_file;

        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);
        let exclude_tests = exclude_tests.unwrap_or(true);
        let symbols = self
            .symbols
            .get(&repo_name)
            .map(|s| s.clone())
            .unwrap_or_default();

        let mut resolver = crate::incremental::SymbolResolver::new();

        // Parse imports from all files
        for symbol in &symbols {
            // Skip test files if exclude_tests is enabled
            if exclude_tests && is_test_file(&symbol.file_path) {
                continue;
            }
            let file_path = repo_path.join(&symbol.file_path);
            if file_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&file_path) {
                    let imports = parse_imports_from_content(&content, &symbol.file_path);
                    resolver.register_imports(&file_path, imports);
                }
            }
        }

        let graph = resolver.build_import_graph(&repo_path);
        let cycles = graph.find_cycles();

        let mut output = String::new();
        output.push_str("# Circular Import Analysis\n\n");

        if cycles.is_empty() {
            output.push_str("No circular imports detected.\n");
        } else {
            output.push_str(&format!(
                "**Found {} circular import chain(s)**\n\n",
                cycles.len()
            ));

            for (i, cycle) in cycles.iter().enumerate() {
                output.push_str(&format!("## Cycle {}\n\n", i + 1));
                output.push_str("```\n");
                for (j, path) in cycle.iter().enumerate() {
                    let rel_path = path
                        .strip_prefix(&repo_path)
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|_| path.to_string_lossy().to_string());
                    output.push_str(&rel_path.to_string());
                    if j < cycle.len() - 1 {
                        output.push_str(" -> ");
                    }
                }
                output.push_str(&format!(
                    " -> {} (cycle)\n",
                    cycle
                        .first()
                        .map(|p| p
                            .strip_prefix(&repo_path)
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|_| p.to_string_lossy().to_string()))
                        .unwrap_or_default()
                ));
                output.push_str("```\n\n");
            }

            output.push_str("## Recommendations\n\n");
            output.push_str("- Extract shared code to a separate module\n");
            output.push_str("- Use dependency injection to break cycles\n");
            output.push_str("- Consider lazy imports or dynamic imports\n");
        }

        Ok(output)
    }

    /// Find exported symbols that are never imported by other files
    ///
    /// # Arguments
    /// * `repo_name` - Repository name
    /// * `exclude_entry_points` - Whether to exclude entry point files (lib.rs, main.rs, index.js, etc.)
    /// * `exclude_patterns` - Glob patterns for files to exclude from analysis
    ///
    /// # Returns
    /// Markdown report of unused exports
    ///
    /// # Errors
    /// Returns error if repository not found
    pub async fn find_unused_exports(
        &self,
        repo_name: &str,
        exclude_entry_points: bool,
        exclude_patterns: Vec<String>,
    ) -> Result<String> {
        use crate::dead_code::{find_unused_exports, UnusedExportConfig};
        use crate::incremental::ExportedSymbol;

        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);
        let symbols = self
            .symbols
            .get(&repo_name)
            .map(|s| s.clone())
            .unwrap_or_default();

        let mut resolver = crate::incremental::SymbolResolver::new();

        // Track which files we've processed
        let mut processed_files = std::collections::HashSet::new();

        // Parse exports and imports from all files
        for symbol in &symbols {
            let file_path = repo_path.join(&symbol.file_path);

            // Skip if already processed this file
            if processed_files.contains(&file_path) {
                continue;
            }

            if file_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&file_path) {
                    // Parse imports
                    let imports = parse_imports_from_content(&content, &symbol.file_path);
                    resolver.register_imports(&file_path, imports);

                    // Extract exports from symbols in this file
                    let file_symbols: Vec<_> = symbols
                        .iter()
                        .filter(|s| s.file_path == symbol.file_path)
                        .collect();

                    let exports: Vec<ExportedSymbol> = file_symbols
                        .into_iter()
                        .filter_map(|s| {
                            // Determine if symbol is public from signature
                            let is_public = s
                                .signature
                                .as_ref()
                                .map(|sig| {
                                    sig.trim_start().starts_with("pub ") || sig.contains("export ")
                                })
                                .unwrap_or(false);

                            // Only track public symbols
                            if is_public {
                                Some(ExportedSymbol {
                                    name: s.name.clone(),
                                    symbol: s.clone(),
                                    is_default: false,
                                    is_public: true,
                                })
                            } else {
                                None
                            }
                        })
                        .collect();

                    resolver.index_file(&file_path, &[], exports);
                    processed_files.insert(file_path);
                }
            }
        }

        // Configure analysis
        let config = UnusedExportConfig {
            exclude_entry_points,
            exclude_patterns,
            include_reexports: false,
        };

        // Run unused export detection
        let report = find_unused_exports(
            resolver.get_exports(),
            resolver.get_imports(),
            &repo_path,
            &config,
        );

        Ok(report.to_markdown())
    }

    /// Fuzzy workspace symbol search
    pub async fn workspace_symbol_search(
        &self,
        query: &str,
        kind: Option<&str>,
        limit: usize,
    ) -> Result<String> {
        let mut index = crate::incremental::WorkspaceSymbolIndex::new();

        // Index all symbols from all repos
        for entry in self.symbols.iter() {
            let repo_name = entry.key();
            for symbol in entry.value().iter() {
                let file_path =
                    std::path::PathBuf::from(format!("{}/{}", repo_name, symbol.file_path));
                index.add_symbol(symbol.clone(), file_path);
            }
        }

        // Filter by kind if specified
        let results = if let Some(kind_filter) = kind {
            if kind_filter == "all" {
                index.search(query, limit)
            } else {
                let target_kind = match kind_filter {
                    "function" => Some(crate::symbols::SymbolKind::Function),
                    "class" => Some(crate::symbols::SymbolKind::Class),
                    "struct" => Some(crate::symbols::SymbolKind::Struct),
                    "interface" => Some(crate::symbols::SymbolKind::Interface),
                    "enum" => Some(crate::symbols::SymbolKind::Enum),
                    "variable" => Some(crate::symbols::SymbolKind::Variable),
                    _ => None,
                };

                if let Some(kind) = target_kind {
                    index
                        .search(query, limit * 2)
                        .into_iter()
                        .filter(|r| r.symbol.kind == kind)
                        .take(limit)
                        .collect()
                } else {
                    index.search(query, limit)
                }
            }
        } else {
            index.search(query, limit)
        };

        let mut output = String::new();
        output.push_str(&format!("# Symbol Search: '{}'\n\n", query));

        if results.is_empty() {
            output.push_str("No symbols found.\n");
        } else {
            output.push_str(&format!("Found {} results:\n\n", results.len()));
            output.push_str("| Symbol | Kind | File | Line | Score |\n");
            output.push_str("|--------|------|------|------|-------|\n");

            for result in results {
                output.push_str(&format!(
                    "| `{}` | {:?} | {} | {} | {:.2} |\n",
                    result.symbol.name,
                    result.symbol.kind,
                    result.file_path.display(),
                    result.symbol.start_line,
                    result.score
                ));
            }
        }

        Ok(output)
    }

    /// Get incremental indexing status
    pub async fn get_incremental_status(&self, repo_name: &str) -> Result<String> {
        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);

        let mut output = String::new();
        output.push_str(&format!("# Incremental Index Status: {}\n\n", repo_name));

        // Count files and symbols
        let symbol_count = self.symbols.get(&repo_name).map(|s| s.len()).unwrap_or(0);

        let file_count = self.file_cache.len();

        output.push_str("## Index Statistics\n\n");
        output.push_str(&format!("- **Repository**: {}\n", repo_path.display()));
        output.push_str(&format!("- **Indexed Symbols**: {}\n", symbol_count));
        output.push_str(&format!("- **Cached Files**: {}\n", file_count));

        // Check for persisted index
        if let Some(ref store) = self.index_store {
            let index_file = store.store_path(&repo_path);
            if index_file.exists() {
                if let Ok(metadata) = std::fs::metadata(&index_file) {
                    output.push_str(&format!(
                        "- **Index File Size**: {}\n",
                        format_size(metadata.len())
                    ));
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(duration) = modified.elapsed() {
                            let mins = duration.as_secs() / 60;
                            output.push_str(&format!("- **Last Updated**: {} minutes ago\n", mins));
                        }
                    }
                }
            } else {
                output.push_str("- **Index File**: Not persisted\n");
            }
        }

        // Symbol breakdown by kind
        if let Some(symbols) = self.symbols.get(&repo_name) {
            output.push_str("\n## Symbol Breakdown\n\n");
            let mut by_kind: std::collections::HashMap<crate::symbols::SymbolKind, usize> =
                std::collections::HashMap::new();
            for s in symbols.iter() {
                *by_kind.entry(s.kind.clone()).or_insert(0) += 1;
            }

            let mut counts: Vec<_> = by_kind.into_iter().collect();
            counts.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

            for (kind, count) in counts {
                output.push_str(&format!("- {:?}: {}\n", kind, count));
            }
        }

        Ok(output)
    }

    /// Find all usages of a symbol
    pub async fn find_symbol_usages(
        &self,
        repo_name: &str,
        symbol_name: &str,
        include_imports: bool,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::security_rules::is_test_file;

        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);
        let exclude_tests = exclude_tests.unwrap_or(false); // Default false for symbol search
        let symbols = self
            .symbols
            .get(&repo_name)
            .map(|s| s.clone())
            .unwrap_or_default();

        let mut usages: Vec<(String, usize, String)> = Vec::new();
        let mut definitions: Vec<(String, usize, String)> = Vec::new();

        // Find definitions
        for symbol in &symbols {
            if symbol.name == symbol_name {
                if exclude_tests && is_test_file(&symbol.file_path) {
                    continue;
                }
                definitions.push((
                    symbol.file_path.clone(),
                    symbol.start_line,
                    format!("{:?} definition", symbol.kind),
                ));
            }
        }

        // Search for usages in files
        for entry in self.file_cache.iter() {
            let path = entry.key();
            let content = entry.value();

            if !path.starts_with(&repo_path) {
                continue;
            }

            let rel_path = path
                .strip_prefix(&repo_path)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| path.to_string_lossy().to_string());

            // Skip test files if exclude_tests is enabled
            if exclude_tests && is_test_file(&rel_path) {
                continue;
            }

            for (line_num, line) in content.lines().enumerate() {
                let is_import = line.contains("import ")
                    || line.contains("use ")
                    || line.contains("from ")
                    || line.contains("require(");

                if !include_imports && is_import {
                    continue;
                }

                if line.contains(symbol_name) {
                    let context = if is_import { "import" } else { "usage" };
                    usages.push((rel_path.clone(), line_num + 1, context.to_string()));
                }
            }
        }

        // Query all enabled semantic backends to cross-validate textual hits.
        // Neither source alone is trusted (grep over-reports, a cold backend
        // under-reports), so results are labelled, not replaced.
        let backend_refs = self
            .refs_for_symbol(&repo_name, symbol_name, &repo_path, &symbols)
            .await;

        let mut output = String::new();
        output.push_str(&format!("# Symbol Usages: '{}'\n\n", symbol_name));

        if !definitions.is_empty() {
            output.push_str("## Definitions\n\n");
            for (file, line, kind) in &definitions {
                output.push_str(&format!("- `{}:{}` ({})\n", file, line, kind));
            }
            output.push('\n');
        }

        if let Some(backends) = &backend_refs {
            // Build a per-backend key set for fast membership tests
            let mut backend_keys: HashMap<String, std::collections::HashSet<(String, usize)>> =
                HashMap::new();
            for (label, refs) in backends {
                let keys = refs.iter().map(|(f, l, _)| (f.clone(), *l)).collect();
                backend_keys.insert(label.clone(), keys);
            }

            let grep_keys: std::collections::HashSet<(String, usize)> = usages
                .iter()
                .map(|(file, line, _)| (file.clone(), *line))
                .collect();

            // Union of all backend key sets — any semantic backend confirming a
            // textual hit marks it "confirmed"
            let all_semantic_keys: std::collections::HashSet<(String, usize)> = backend_keys
                .values()
                .flat_map(|s| s.iter().cloned())
                .collect();

            let mut rows: Vec<(String, usize, String)> = Vec::new();
            for (file, line, _) in &usages {
                let label = if all_semantic_keys.contains(&(file.clone(), *line)) {
                    "confirmed".to_string()
                } else {
                    "syntactic-only".to_string()
                };
                rows.push((file.clone(), *line, label));
            }

            // Hits found by a backend but not by text search
            for (blabel, refs) in backends {
                for (file, line, _) in refs {
                    if !grep_keys.contains(&(file.clone(), *line)) {
                        rows.push((file.clone(), *line, format!("{}-only", blabel)));
                    }
                }
            }

            rows.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
            rows.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

            if rows.is_empty() {
                output.push_str("## Usages\n\nNo usages found.\n");
            } else {
                let confirmed = rows.iter().filter(|r| r.2 == "confirmed").count();
                let syntactic = rows.iter().filter(|r| r.2 == "syntactic-only").count();
                let backend_only = rows.len() - confirmed - syntactic;

                // Build a sorted, deduplicated list of active backend labels
                let mut active: Vec<&str> = backends.keys().map(String::as_str).collect();
                active.sort_unstable();
                let active_str = active.join(", ");

                output.push_str(&format!(
                    "## Usages ({} total — cross-validated by: {})\n\n",
                    rows.len(),
                    active_str
                ));
                output.push_str(&format!(
                    "*{} confirmed, {} syntactic-only (no backend confirmed — possible \
                     false match or unindexed TU), {} backend-only (backend found, \
                     text search missed)*\n\n",
                    confirmed, syntactic, backend_only
                ));
                output.push_str("| File | Line | Source |\n");
                output.push_str("|------|------|--------|\n");
                for (file, line, label) in rows.iter().take(50) {
                    output.push_str(&format!("| {} | {} | {} |\n", file, line, label));
                }
                if rows.len() > 50 {
                    output.push_str(&format!("\n*... and {} more*\n", rows.len() - 50));
                }
            }
        } else if usages.is_empty() {
            output.push_str("## Usages\n\nNo usages found.\n");
        } else {
            output.push_str(&format!("## Usages ({} found)\n\n", usages.len()));
            output.push_str("| File | Line | Context |\n");
            output.push_str("|------|------|--------|\n");

            for (file, line, context) in usages.iter().take(50) {
                output.push_str(&format!("| {} | {} | {} |\n", file, line, context));
            }

            if usages.len() > 50 {
                output.push_str(&format!("\n*... and {} more*\n", usages.len() - 50));
            }
        }

        Ok(output)
    }

    /// Get export map for a file
    pub async fn get_export_map(&self, repo_name: &str, path: &str) -> Result<String> {
        let repo_name = self.resolve_repo(repo_name)?;
        let repo_path = PathBuf::from(&repo_name);
        let file_path = validate_path(&repo_path, path)?;

        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let symbols = self
            .symbols
            .get(&repo_name)
            .map(|s| s.clone())
            .unwrap_or_default();

        // Find symbols defined in this file
        let file_symbols: Vec<_> = symbols.iter().filter(|s| s.file_path == path).collect();

        let mut output = String::new();
        output.push_str(&format!("# Export Map: {}\n\n", path));

        if file_symbols.is_empty() {
            output.push_str("No exported symbols found.\n");
        } else {
            // Get all symbols - we can't determine visibility without AST info
            let mut public_symbols: Vec<_> = file_symbols.iter().collect();
            public_symbols.sort_by_key(|symbol| symbol.start_line);

            output.push_str("## Exported Symbols\n\n");
            output.push_str("| Name | Kind | Line | Signature |\n");
            output.push_str("|------|------|------|----------|\n");

            for symbol in public_symbols {
                let sig = symbol.signature.as_deref().unwrap_or("-");
                output.push_str(&format!(
                    "| `{}` | {:?} | {} | {} |\n",
                    symbol.name,
                    symbol.kind,
                    symbol.start_line,
                    if sig.len() > 50 { &sig[..50] } else { sig }
                ));
            }

            // Detect export statements in the file
            let export_lines: Vec<_> = content
                .lines()
                .enumerate()
                .filter(|(_, line)| {
                    let trimmed = line.trim();
                    trimmed.starts_with("export ")
                        || trimmed.starts_with("pub ")
                        || trimmed.starts_with("module.exports")
                        || trimmed.starts_with("__all__")
                })
                .collect();

            if !export_lines.is_empty() {
                output.push_str("\n## Export Statements\n\n");
                for (line_num, line) in export_lines {
                    output.push_str(&format!(
                        "- Line {}: `{}`\n",
                        line_num + 1,
                        line.trim().chars().take(80).collect::<String>()
                    ));
                }
            }
        }

        Ok(output)
    }

    // === Neural Search Methods ===

    /// Perform neural semantic search
    pub async fn neural_search(
        &self,
        repo: Option<&str>,
        query: &str,
        max_results: usize,
    ) -> Result<String> {
        let neural = self.neural_engine.as_ref().ok_or_else(|| {
            anyhow!(
                "Neural search not available. Enable with --neural flag and set EMBEDDING_API_KEY."
            )
        })?;

        let results = neural.search(query, max_results)?;

        let mut output = String::new();
        output.push_str(&format!("# Neural Search Results for: `{}`\n\n", query));

        // Filter by repo if specified
        let filtered_results: Vec<_> = if let Some(repo_name) = repo {
            results
                .into_iter()
                .filter(|r| r.document.file_path.contains(repo_name))
                .collect()
        } else {
            results
        };

        if filtered_results.is_empty() {
            output.push_str("No results found.\n");
        } else {
            output.push_str(&format!(
                "Found {} semantically similar results:\n\n",
                filtered_results.len()
            ));

            for (i, result) in filtered_results.iter().enumerate() {
                output.push_str(&format!(
                    "## {}. {} (similarity: {:.3})\n",
                    i + 1,
                    result.document.file_path,
                    result.similarity
                ));
                output.push_str(&format!(
                    "Lines {}-{}\n\n",
                    result.document.start_line, result.document.end_line
                ));

                if let Some(ref symbol) = result.document.symbol_name {
                    output.push_str(&format!("**Symbol**: `{}`\n\n", symbol));
                }

                // Show snippet (truncated if long)
                let content = &result.document.content;
                let snippet = if content.len() > 500 {
                    format!("{}...", &content[..500])
                } else {
                    content.clone()
                };
                output.push_str("```\n");
                output.push_str(&snippet);
                output.push_str("\n```\n\n");
            }
        }

        Ok(output)
    }

    /// Find code semantically similar to a symbol
    pub async fn find_semantic_clones(
        &self,
        repo: &str,
        path: &str,
        function: &str,
        threshold: f32,
    ) -> Result<String> {
        let neural = self
            .neural_engine
            .as_ref()
            .ok_or_else(|| anyhow!("Neural search not available. Enable with --neural flag."))?;

        // Get the symbol's code
        let repo_key = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo_key);
        let file_path = validate_path(&repo_path, path)?;
        let content = std::fs::read_to_string(&file_path)?;

        // Find the symbol in our index
        let symbols = self
            .symbols
            .get(&repo_key)
            .ok_or_else(|| anyhow!("Repository not indexed"))?;
        let symbol = symbols
            .iter()
            .find(|s| s.name == function && s.file_path == path)
            .ok_or_else(|| anyhow!("Symbol not found: {}", function))?;

        // Extract the symbol's code
        let lines: Vec<&str> = content.lines().collect();
        let start = symbol.start_line.saturating_sub(1);
        let end = symbol.end_line.min(lines.len());
        let symbol_code = lines[start..end].join("\n");

        // Search for similar code
        let results = neural.search(&symbol_code, 20)?;

        let mut output = String::new();
        output.push_str(&format!("# Semantic Clones of `{}`\n\n", function));
        output.push_str(&format!("Threshold: {:.2}\n\n", threshold));

        let filtered: Vec<_> = results
            .into_iter()
            .filter(|r| {
                r.similarity >= threshold && r.document.symbol_name.as_deref() != Some(function)
            })
            .collect();

        if filtered.is_empty() {
            output.push_str("No semantic clones found above threshold.\n");
        } else {
            output.push_str(&format!("Found {} potential clones:\n\n", filtered.len()));

            for (i, result) in filtered.iter().enumerate() {
                output.push_str(&format!(
                    "## {}. {} (similarity: {:.3})\n",
                    i + 1,
                    result
                        .document
                        .symbol_name
                        .as_deref()
                        .unwrap_or(&result.document.file_path),
                    result.similarity
                ));
                output.push_str(&format!(
                    "File: {}:{}-{}\n\n",
                    result.document.file_path, result.document.start_line, result.document.end_line
                ));

                let content = &result.document.content;
                let snippet = if content.len() > 300 {
                    format!("{}...", &content[..300])
                } else {
                    content.clone()
                };
                output.push_str("```\n");
                output.push_str(&snippet);
                output.push_str("\n```\n\n");
            }
        }

        Ok(output)
    }

    /// Get neural engine statistics
    pub async fn get_neural_stats(&self) -> Result<String> {
        let neural = self
            .neural_engine
            .as_ref()
            .ok_or_else(|| anyhow!("Neural search not available. Enable with --neural flag."))?;

        let stats = neural.stats();

        let mut output = String::new();
        output.push_str("# Neural Embedding Statistics\n\n");
        output.push_str(&format!("**Backend**: {}\n", stats.backend));
        if let Some(model) = &stats.model {
            output.push_str(&format!("**Model**: {}\n", model));
        }
        output.push_str(&format!("**Dimension**: {}\n", stats.dimension));
        output.push_str(&format!("**Indexed Documents**: {}\n", stats.indexed_count));

        Ok(output)
    }

    /// Check if neural search is available
    pub fn is_neural_enabled(&self) -> bool {
        self.neural_engine.is_some()
    }

    // ========== Phase 8: Type Inference ==========

    /// Infer types for a Python/JavaScript function
    pub async fn infer_types(&self, repo: &str, path: &str, function: &str) -> Result<String> {
        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;
        let language = detect_language_from_path(path);

        // Check if it's a dynamic language
        if !matches!(language.as_str(), "python" | "javascript" | "typescript") {
            return Err(anyhow!(
                "Type inference is only available for Python and JavaScript/TypeScript. Found: {}",
                language
            ));
        }

        // Parse the file
        let parsed = self.parser.parse_file(&full_path, &content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;

        // Find the function
        let mut found_cfg = None;
        let cfgs = cfg::analyze_function(tree, &content, path)?;

        for cfg_item in cfgs {
            if cfg_item.function_name == function {
                found_cfg = Some(cfg_item);
                break;
            }
        }

        let cfg_ref = found_cfg.as_ref();

        // Create inferencer and run
        let mut inferencer = TypeInferencer::new(&content, cfg_ref, &language);
        let result = inferencer.infer_from_cfg(&[]);

        Ok(result.to_markdown())
    }

    /// Check for type errors in a file without running external type checkers
    pub async fn check_type_errors(
        &self,
        repo: &str,
        path: &str,
        exclude_tests: Option<bool>,
    ) -> Result<String> {
        use crate::security_rules::is_test_file;

        let exclude_tests = exclude_tests.unwrap_or(true);
        if exclude_tests && is_test_file(path) {
            return Ok(format!("# Type Error Analysis: `{}`\n\nSkipped: test file (use exclude_tests=false to include)", path));
        }

        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;

        if full_path.is_dir() {
            let mut files: Vec<(PathBuf, String, String, Arc<String>)> = self
                .file_cache
                .iter()
                .filter(|entry| path_is_within_repo(entry.key(), &full_path))
                .filter_map(|entry| {
                    let display_path = entry
                        .key()
                        .strip_prefix(&repo_meta.path)
                        .unwrap_or(entry.key())
                        .to_string_lossy()
                        .replace('\\', "/");
                    if exclude_tests && is_test_file(&display_path) {
                        return None;
                    }

                    let language = detect_language_from_path(&display_path);
                    if !is_type_checkable_language(&language) {
                        return None;
                    }

                    Some((
                        entry.key().clone(),
                        display_path,
                        language,
                        entry.value().clone(),
                    ))
                })
                .collect();
            files.sort_by(|left, right| left.1.cmp(&right.1));

            let mut function_count = 0usize;
            let mut all_errors: Vec<(String, String, TypeError)> = Vec::new();

            for (file_path, display_path, language, content) in &files {
                let (file_function_count, errors) =
                    self.collect_type_errors_for_file(file_path, display_path, content, language)?;
                function_count += file_function_count;

                for (function_name, error) in errors {
                    all_errors.push((display_path.clone(), function_name, error));
                }
            }

            let mut output = String::new();
            output.push_str(&format!("# Type Check Results: `{}`\n\n", path));
            output.push_str(&format!("**Files analyzed**: {}\n", files.len()));
            output.push_str(&format!("**Functions analyzed**: {}\n\n", function_count));

            if files.is_empty() {
                output.push_str("No supported Python or JavaScript/TypeScript files found.\n");
            } else if all_errors.is_empty() {
                output.push_str("✅ No type errors found!\n");
            } else {
                output.push_str(&format!(
                    "⚠️ **{} potential issues found**\n\n",
                    all_errors.len()
                ));

                for (file_path, func_name, error) in &all_errors {
                    output.push_str(&format!(
                        "- **{}::{}** (line {}:{}): {:?} - {}\n",
                        file_path, func_name, error.line, error.column, error.kind, error.message
                    ));
                }
            }

            return Ok(output);
        }

        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;
        let language = detect_language_from_path(path);

        // Check if it's a dynamic language
        if !is_type_checkable_language(&language) {
            return Err(anyhow!(
                "Type checking is only available for Python and JavaScript/TypeScript. Found: {}",
                language
            ));
        }

        let (function_count, all_errors) =
            self.collect_type_errors_for_file(&full_path, path, &content, &language)?;

        // Format output
        let mut output = String::new();
        output.push_str(&format!("# Type Check Results: `{}`\n\n", path));
        output.push_str(&format!("**Functions analyzed**: {}\n\n", function_count));

        if all_errors.is_empty() {
            output.push_str("✅ No type errors found!\n");
        } else {
            output.push_str(&format!(
                "⚠️ **{} potential issues found**\n\n",
                all_errors.len()
            ));

            for (func_name, error) in &all_errors {
                output.push_str(&format!(
                    "- **{}** (line {}:{}): {:?} - {}\n",
                    func_name, error.line, error.column, error.kind, error.message
                ));
            }
        }

        Ok(output)
    }

    fn collect_type_errors_for_file(
        &self,
        full_path: &Path,
        display_path: &str,
        content: &str,
        language: &str,
    ) -> Result<(usize, Vec<(String, TypeError)>)> {
        let parsed = self.parser.parse_file(full_path, content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;
        let cfgs = cfg::analyze_function(tree, content, display_path)?;

        let mut all_errors: Vec<(String, TypeError)> = Vec::new();

        for cfg_item in &cfgs {
            let mut inferencer = TypeInferencer::new(content, Some(cfg_item), language);
            let result = inferencer.infer_from_cfg(&[]);

            for error in result.errors {
                all_errors.push((cfg_item.function_name.clone(), error));
            }

            let check_errors = inferencer.check_type_errors();
            for error in check_errors {
                all_errors.push((cfg_item.function_name.clone(), error));
            }
        }

        Ok((cfgs.len(), all_errors))
    }

    /// Enhanced taint analysis with type information
    pub async fn get_typed_taint_flow(
        &self,
        repo: &str,
        path: &str,
        source_line: usize,
    ) -> Result<String> {
        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        let full_path = validate_path(&repo_meta.path, path)?;
        let content = std::fs::read_to_string(&full_path).context("Failed to read file")?;
        let language = detect_language_from_path(path);

        // Parse the file
        let parsed = self.parser.parse_file(&full_path, &content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;
        let cfgs = cfg::analyze_function(tree, &content, path)?;

        let mut output = String::new();
        output.push_str(&format!(
            "# Typed Taint Flow: `{}` (line {})\n\n",
            path, source_line
        ));

        // Find which function contains this line
        let mut containing_cfg = None;
        for cfg_item in &cfgs {
            for block in cfg_item.blocks.values() {
                if block.start_line <= source_line && source_line <= block.end_line {
                    containing_cfg = Some(cfg_item);
                    break;
                }
            }
            if containing_cfg.is_some() {
                break;
            }
        }

        if let Some(cfg_item) = containing_cfg {
            output.push_str(&format!("**Function**: `{}`\n\n", cfg_item.function_name));

            // Get type information
            let mut inferencer = TypeInferencer::new(&content, Some(cfg_item), &language);
            let types = inferencer.infer_from_cfg(&[]);

            // Get taint information using the existing analyzer
            let taint_result = crate::taint::analyze_code(&content, path);

            // Combine type and taint info
            output.push_str("## Type Information at Source\n\n");
            if let Some(line_types) = types.variable_types.get(&source_line) {
                for (var, ty) in line_types {
                    let ty_ref: &crate::type_inference::Type = ty;
                    output.push_str(&format!("- `{}`: `{}`\n", var, ty_ref.display_name()));
                }
            } else {
                output.push_str("*No type information available at this line*\n");
            }
            output.push('\n');

            output.push_str("## Taint Sources Near Line\n\n");
            let nearby_sources: Vec<_> = taint_result
                .sources
                .iter()
                .filter(|s| s.line >= source_line.saturating_sub(5) && s.line <= source_line + 5)
                .collect();

            if nearby_sources.is_empty() {
                output.push_str("*No taint sources near this line*\n");
            } else {
                for source in nearby_sources {
                    let type_info = types
                        .variable_types
                        .get(&source.line)
                        .and_then(|vars: &HashMap<String, crate::type_inference::Type>| {
                            vars.get(&source.variable)
                        })
                        .map(|t: &crate::type_inference::Type| t.display_name())
                        .unwrap_or_else(|| "unknown".to_string());

                    output.push_str(&format!(
                        "- Line {}: `{}` ({}) - type: `{}`\n",
                        source.line,
                        source.variable,
                        source.kind.display_name(),
                        type_info
                    ));
                }
            }
            output.push('\n');

            output.push_str("## Taint Flows\n\n");
            if taint_result.flows.is_empty() {
                output.push_str("*No complete taint flows detected*\n");
            } else {
                for flow in &taint_result.flows {
                    if !flow.is_sanitized {
                        output.push_str(&format!(
                            "⚠️ {} flow: {} -> {} ({:?})\n",
                            flow.vulnerability
                                .as_ref()
                                .map(|v| v.display_name())
                                .unwrap_or("Unknown"),
                            flow.source.variable,
                            flow.sink.function,
                            flow.severity.unwrap_or(crate::taint::Severity::Medium)
                        ));

                        // Add type info for flow steps
                        for step in &flow.path {
                            let type_info = types
                                .variable_types
                                .get(&step.line)
                                .and_then(|vars: &HashMap<String, crate::type_inference::Type>| {
                                    vars.get(&step.variable)
                                })
                                .map(|t: &crate::type_inference::Type| t.display_name())
                                .unwrap_or_else(|| "unknown".to_string());

                            output.push_str(&format!(
                                "  - Line {}: `{}` - type: `{}`\n",
                                step.line, step.variable, type_info
                            ));
                        }
                    }
                }
            }

            // Add security notes based on types
            output.push_str("\n## Security Notes\n\n");
            let mut has_notes = false;

            for line_types in types.variable_types.values() {
                for (var, ty) in line_types {
                    let ty_ref: &crate::type_inference::Type = ty;
                    let type_name = ty_ref.display_name();
                    if type_name.contains("str") || type_name.contains("String") {
                        // Check if this variable appears in any unsanitized flow
                        for flow in &taint_result.flows {
                            if !flow.is_sanitized && flow.source.variable == *var {
                                output.push_str(&format!(
                                    "⚠️ String variable `{}` may flow to dangerous sink\n",
                                    var
                                ));
                                has_notes = true;
                            }
                        }
                    }
                }
            }

            if !has_notes {
                output.push_str("*No immediate security concerns detected*\n");
            }
        } else {
            output.push_str(&format!(
                "*Line {} is not within a function body*\n",
                source_line
            ));
        }

        Ok(output)
    }

    // ========================================================================
    // Graph Visualization Helper Methods
    // ========================================================================

    /// Get call graph data for visualization
    /// Returns a reference to the call graph for the given repository
    pub fn get_call_graph_for_viz(
        &self,
        repo: &str,
    ) -> Result<dashmap::mapref::one::Ref<'_, String, CallGraph>> {
        if !self.options.call_graph_enabled {
            return Err(anyhow!(
                "Call graph not enabled. Start with --call-graph flag."
            ));
        }

        // Find the repo
        let repo_name = if repo.is_empty() {
            // Use first available repo
            self.call_graphs
                .iter()
                .next()
                .map(|e| e.key().clone())
                .ok_or_else(|| anyhow!("No repositories indexed with call graphs"))?
        } else {
            repo.to_string()
        };

        self.call_graphs
            .get(&repo_name)
            .ok_or_else(|| anyhow!("Call graph not found for repository: {}", repo_name))
    }

    /// Get a code excerpt for visualization (simplified version for graph tooltips)
    pub async fn get_excerpt_for_viz(
        &self,
        repo: &str,
        path: &str,
        center_line: usize,
        context: usize,
    ) -> Result<String> {
        let repo_path = PathBuf::from(self.resolve_repo(repo)?);
        let file_path = validate_path(&repo_path, path)?;

        let content = std::fs::read_to_string(&file_path).context("Failed to read file")?;

        let lines: Vec<&str> = content.lines().collect();
        let start = center_line.saturating_sub(context + 1);
        let end = (center_line + context).min(lines.len());

        let excerpt: String = lines[start..end]
            .iter()
            .enumerate()
            .map(|(i, line)| format!("{:4} | {}", start + i + 1, line))
            .collect::<Vec<_>>()
            .join("\n");

        Ok(excerpt)
    }

    /// Get import graph data for visualization
    ///
    /// Uses the cached symbol and file data instead of re-walking the filesystem.
    ///
    /// # Arguments
    /// * `repo` - Repository name
    /// * `max_nodes` - Maximum number of file nodes to include (early exit)
    ///
    /// # Errors
    /// Returns an error if the repository is not indexed
    pub async fn get_import_graph_for_viz(
        &self,
        repo: &str,
        max_nodes: usize,
    ) -> Result<crate::tool_handlers::graph::ImportGraphData> {
        use std::collections::HashMap;

        let repo = self.resolve_repo(repo)?;
        let repo_path = PathBuf::from(&repo);

        // Use cached symbols to get unique file paths (same approach as get_import_graph)
        let symbols = self
            .symbols
            .get(&repo)
            .map(|s| s.clone())
            .unwrap_or_default();

        let unique_files: std::collections::HashSet<_> =
            symbols.iter().map(|s| s.file_path.clone()).collect();

        let mut files: HashMap<String, Vec<String>> = HashMap::new();
        let mut node_count = 0;

        for rel_path in unique_files {
            if node_count >= max_nodes {
                break;
            }

            // Try the file_cache first, fall back to disk read
            let abs_path = repo_path.join(&rel_path);
            let content = if let Some(cached) = self.file_cache.get(&abs_path) {
                cached.clone()
            } else if let Ok(content) = std::fs::read_to_string(&abs_path) {
                std::sync::Arc::new(content)
            } else {
                continue;
            };

            let imports = parse_imports_from_content(&content, &rel_path);
            let import_paths: Vec<String> = imports.iter().map(|i| i.import_path.clone()).collect();

            if !import_paths.is_empty() {
                node_count += 1 + import_paths.len(); // source file + targets
                files.insert(rel_path, import_paths);
            }
        }

        let cycles: Vec<Vec<String>> = Vec::new();

        Ok(crate::tool_handlers::graph::ImportGraphData { files, cycles })
    }

    /// Get symbol graph data for visualization
    ///
    /// Iterates the file cache directly to find references instead of round-tripping
    /// through the markdown-formatted `find_references` output.
    ///
    /// # Arguments
    /// * `repo` - Repository name
    /// * `symbol_name` - Symbol to find references for
    /// * `max_nodes` - Maximum number of reference nodes to include
    ///
    /// # Errors
    /// Returns an error if the repository is not indexed or the symbol is not found
    pub async fn get_symbol_graph_for_viz(
        &self,
        repo: &str,
        symbol_name: &str,
        max_nodes: usize,
    ) -> Result<crate::tool_handlers::graph::SymbolGraphData> {
        let repo = self.resolve_repo(repo)?;
        // Find the symbol definition
        let symbols = self
            .symbols
            .get(&repo)
            .ok_or_else(|| anyhow!("Repository not indexed: {}", repo))?;

        let target_symbol = symbols
            .iter()
            .find(|s| s.name == symbol_name || s.name.ends_with(&format!("::{}", symbol_name)))
            .ok_or_else(|| anyhow!("Symbol not found: {}", symbol_name))?;

        let definition = crate::tool_handlers::graph::SymbolDefinition {
            id: target_symbol.name.clone(),
            kind: format!("{:?}", target_symbol.kind).to_lowercase(),
            file_path: target_symbol.file_path.clone(),
            line: target_symbol.start_line,
        };

        // Iterate file_cache directly to find references (same logic as text_search_references)
        let repo_path = PathBuf::from(&repo);
        let mut references = Vec::new();

        // Reserve one node for the definition itself
        let max_refs = max_nodes.saturating_sub(1);

        for entry in self.file_cache.iter() {
            if references.len() >= max_refs {
                break;
            }

            let file_path = entry.key();
            if !file_path.starts_with(&repo_path) {
                continue;
            }

            let rel_path = file_path
                .strip_prefix(&repo_path)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            let content = entry.value();
            for (line_num, line) in content.lines().enumerate() {
                if references.len() >= max_refs {
                    break;
                }
                if line.contains(symbol_name) {
                    references.push(crate::tool_handlers::graph::SymbolReference {
                        file_path: rel_path.clone(),
                        line: line_num + 1,
                    });
                }
            }
        }

        Ok(crate::tool_handlers::graph::SymbolGraphData {
            definition,
            references,
        })
    }

    /// Get control flow graph data for visualization
    ///
    /// Uses the real `cfg::analyze_function` builder to produce actual basic blocks
    /// and control flow edges instead of a single-block stub.
    ///
    /// # Arguments
    /// * `repo` - Repository name
    /// * `function` - Function name to analyze
    ///
    /// # Errors
    /// Returns an error if the repository, function, or file is not found, or if parsing fails
    pub async fn get_cfg_for_viz(
        &self,
        repo: &str,
        function: &str,
    ) -> Result<crate::tool_handlers::graph::CfgData> {
        let repo = self.resolve_repo(repo)?;
        let repo_meta = self
            .repos
            .get(&repo)
            .ok_or_else(|| anyhow!("Repository '{}' not found", repo))?;

        // Find the function in symbols
        let symbols = self
            .symbols
            .get(&repo)
            .ok_or_else(|| anyhow!("No symbols for repository: {}", repo))?;

        let func_symbol = symbols
            .iter()
            .find(|s| s.name == function || s.name.ends_with(&format!("::{}", function)))
            .ok_or_else(|| anyhow!("Function not found: {}", function))?;

        let full_path = validate_path(&repo_meta.path, &func_symbol.file_path)?;
        let content = std::fs::read_to_string(&full_path)?;

        // Parse the file with tree-sitter (same approach as get_control_flow)
        let parsed = self.parser.parse_file(&full_path, &content)?;
        let tree = parsed
            .tree
            .as_ref()
            .ok_or_else(|| anyhow!("Failed to parse file"))?;

        // Build CFGs for all functions in the file
        let cfgs = cfg::analyze_function(tree, &content, &func_symbol.file_path)?;

        // Find the requested function's CFG
        let cfg_result = cfgs
            .iter()
            .find(|c| c.function_name == function || c.function_name == func_symbol.name);

        let cfg_result = match cfg_result {
            Some(c) => c,
            None => {
                // Fallback: try partial match
                cfgs.iter()
                    .find(|c| {
                        c.function_name.ends_with(&format!("::{}", function))
                            || function.ends_with(&format!("::{}", c.function_name))
                            || c.function_name.contains(function)
                    })
                    .ok_or_else(|| {
                        let available: Vec<_> =
                            cfgs.iter().map(|c| c.function_name.as_str()).collect();
                        anyhow!(
                            "Function '{}' not found in CFG analysis. Available: {:?}",
                            function,
                            available
                        )
                    })?
            }
        };

        // Convert cfg::BasicBlock → graph::CfgBlock
        let source_lines: Vec<&str> = content.lines().collect();
        let mut blocks = Vec::new();
        for (id, block) in &cfg_result.blocks {
            let block_type = if block.is_entry {
                "entry"
            } else if block.is_exit {
                "exit"
            } else {
                match &block.terminator {
                    cfg::Terminator::Branch { .. } => "branch",
                    cfg::Terminator::Loop => "loop",
                    cfg::Terminator::Return => "return",
                    cfg::Terminator::Unreachable => "unreachable",
                    _ => "basic",
                }
            };

            // Extract code from source lines
            let start_idx = block.start_line.saturating_sub(1);
            let end_idx = block.end_line.min(source_lines.len());
            let code = if start_idx < end_idx {
                source_lines[start_idx..end_idx].join("\n")
            } else {
                block.label.clone()
            };

            blocks.push(crate::tool_handlers::graph::CfgBlock {
                id: format!("block_{}", id),
                label: block.label.clone(),
                block_type: block_type.to_string(),
                start_line: block.start_line,
                code,
            });
        }

        // Convert cfg::CfgEdge → graph::CfgEdge
        let mut edges = Vec::new();
        for edge in &cfg_result.edges {
            let (edge_type, condition, is_back_edge) = match &edge.kind {
                cfg::EdgeKind::TrueBranch => ("branch", Some("true".to_string()), None),
                cfg::EdgeKind::FalseBranch => ("branch", Some("false".to_string()), None),
                cfg::EdgeKind::LoopBack => ("loop_back", None, Some(true)),
                cfg::EdgeKind::LoopExit => ("loop_exit", None, None),
                cfg::EdgeKind::FallThrough => ("fallthrough", None, None),
                cfg::EdgeKind::Jump => ("jump", None, None),
                cfg::EdgeKind::Exception => ("exception", None, None),
            };

            edges.push(crate::tool_handlers::graph::CfgEdge {
                from: format!("block_{}", edge.from),
                to: format!("block_{}", edge.to),
                edge_type: edge_type.to_string(),
                condition,
                is_back_edge,
            });
        }

        Ok(crate::tool_handlers::graph::CfgData {
            file_path: func_symbol.file_path.clone(),
            blocks,
            edges,
        })
    }

    /// Get security data for visualization overlay
    /// Only scans the specified file paths (from graph nodes) for efficiency
    pub async fn get_security_for_viz(
        &self,
        repo: &str,
        file_paths: &[String],
    ) -> Result<crate::tool_handlers::graph::SecurityVizData> {
        let repo_path = PathBuf::from(self.resolve_repo(repo)?);

        // Use cached security rules engine (already has compiled patterns)
        let engine = &self.security_engine;

        // Collect valid file paths first
        let valid_files: Vec<(std::path::PathBuf, String)> = file_paths
            .iter()
            .filter_map(|file_path| {
                let full_path = if std::path::Path::new(file_path).is_absolute() {
                    std::path::PathBuf::from(file_path)
                } else {
                    repo_path.join(file_path)
                };

                if !full_path.is_file() {
                    return None;
                }

                let path_str = full_path.to_string_lossy().to_string();
                if !is_security_scannable(&path_str) {
                    return None;
                }

                Some((full_path, path_str))
            })
            .collect();

        // Scan files in parallel using rayon
        let all_findings: Vec<_> = valid_files
            .par_iter()
            .filter_map(|(full_path, path_str)| {
                std::fs::read_to_string(full_path).ok().map(|content| {
                    let language = detect_language_from_path(path_str);
                    engine.scan(&content, path_str, &language)
                })
            })
            .flatten()
            .collect();

        // Get taint sources and sinks
        let mut taint_sources = Vec::new();
        let mut taint_sinks = Vec::new();

        // Simplified: extract from findings
        for finding in &all_findings {
            if finding.message.to_lowercase().contains("source")
                || finding.message.to_lowercase().contains("input")
            {
                taint_sources.push(format!("{}:{}", finding.file_path, finding.line));
            }
            if finding.message.to_lowercase().contains("sink")
                || finding.message.to_lowercase().contains("dangerous")
            {
                taint_sinks.push(format!("{}:{}", finding.file_path, finding.line));
            }
        }

        // Convert findings to visualization format
        let vulnerabilities: Vec<crate::tool_handlers::graph::VulnInfo> = all_findings
            .iter()
            .map(|f| crate::tool_handlers::graph::VulnInfo {
                file_path: f.file_path.clone(),
                line: f.line,
                severity: format!("{:?}", f.severity).to_lowercase(),
                function: None, // Would need to resolve from symbols
            })
            .collect();

        Ok(crate::tool_handlers::graph::SecurityVizData {
            vulnerabilities,
            taint_sources,
            taint_sinks,
        })
    }

    // ========================================================================
    // SPARQL Query Methods
    // ========================================================================

    /// Execute a SPARQL query against the knowledge graph.
    ///
    /// # Arguments
    ///
    /// * `query` - The SPARQL query to execute
    /// * `timeout_ms` - Optional timeout in milliseconds (default: 30000)
    /// * `limit` - Optional maximum number of results (default: 1000)
    /// * `offset` - Optional offset for pagination (default: 0)
    /// * `format` - Output format: json, markdown, or csv (default: json)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The graph feature is not enabled
    /// - No knowledge graph is available
    /// - The query is invalid
    /// - The query times out
    #[cfg(feature = "graph")]
    pub async fn sparql_query(
        &self,
        query: &str,
        timeout_ms: Option<u64>,
        limit: Option<usize>,
        offset: Option<usize>,
        format: Option<&str>,
    ) -> Result<String> {
        use crate::persistence::sparql::{OutputFormat, QueryOptions, SparqlEngine};
        use std::str::FromStr;

        let graph = self
            .knowledge_graph
            .as_ref()
            .ok_or_else(|| anyhow!("Knowledge graph not enabled. Start with --graph flag."))?;

        let output_format = format
            .map(OutputFormat::from_str)
            .transpose()?
            .unwrap_or_default();

        let options = QueryOptions::default()
            .with_timeout_ms(timeout_ms.unwrap_or(30_000))
            .with_limit(limit.unwrap_or(1000))
            .with_offset(offset.unwrap_or(0))
            .with_format(output_format);

        let engine = SparqlEngine::new(graph);

        // Determine query type and execute
        let query_trimmed = query.trim().to_uppercase();
        if query_trimmed.starts_with("ASK") {
            let result = engine.query_ask(query, &options)?;
            let output = format!(
                "# SPARQL ASK Query Result\n\n**Result**: {}\n\n*Executed in {}ms*",
                if result.result { "true" } else { "false" },
                result.execution_time_ms
            );
            Ok(output)
        } else {
            let result = engine.query_select(query, &options)?;
            SparqlEngine::format_result(&result, output_format)
        }
    }

    /// List available SPARQL query templates.
    ///
    /// # Errors
    ///
    /// Returns an error if the graph feature is not enabled.
    #[cfg(feature = "graph")]
    pub async fn list_sparql_templates(&self) -> Result<String> {
        use crate::persistence::sparql::templates;

        let all_templates = templates::all();

        let mut output = String::new();
        output.push_str("# SPARQL Query Templates\n\n");
        output.push_str(&format!(
            "**{} templates available**\n\n",
            all_templates.len()
        ));

        for template in all_templates {
            output.push_str(&format!("## `{}`\n\n", template.name));
            output.push_str(&format!("{}\n\n", template.description));

            if !template.parameters.is_empty() {
                output.push_str("**Parameters:**\n");
                for param in template.parameters {
                    output.push_str(&format!("- `${}`\n", param));
                }
                output.push('\n');
            } else {
                output.push_str("*No parameters required*\n\n");
            }
        }

        Ok(output)
    }

    /// Execute a SPARQL query template with parameters.
    ///
    /// # Arguments
    ///
    /// * `template_name` - Name of the template to execute
    /// * `params` - JSON object with parameter values
    /// * `timeout_ms` - Optional timeout in milliseconds
    /// * `limit` - Optional maximum number of results
    /// * `format` - Output format: json, markdown, or csv
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The template is not found
    /// - Required parameters are missing
    /// - The query fails
    #[cfg(feature = "graph")]
    pub async fn run_sparql_template(
        &self,
        template_name: &str,
        params: std::collections::HashMap<String, String>,
        timeout_ms: Option<u64>,
        limit: Option<usize>,
        format: Option<&str>,
    ) -> Result<String> {
        use crate::persistence::sparql::{templates, OutputFormat, QueryOptions, SparqlEngine};
        use std::str::FromStr;

        let graph = self
            .knowledge_graph
            .as_ref()
            .ok_or_else(|| anyhow!("Knowledge graph not enabled. Start with --graph flag."))?;

        let template = templates::get(template_name)
            .ok_or_else(|| anyhow!("Template not found: {}", template_name))?;

        let output_format = format
            .map(OutputFormat::from_str)
            .transpose()?
            .unwrap_or_default();

        let options = QueryOptions::default()
            .with_timeout_ms(timeout_ms.unwrap_or(30_000))
            .with_limit(limit.unwrap_or(1000))
            .with_format(output_format);

        let engine = SparqlEngine::new(graph);
        let result = engine.query_template(template, &params, &options)?;

        let mut output = String::new();
        output.push_str(&format!("# Template: `{}`\n\n", template_name));
        output.push_str(&format!("{}\n\n", template.description));
        output.push_str("---\n\n");
        output.push_str(&SparqlEngine::format_result(&result, output_format)?);

        Ok(output)
    }

    // ========================================================================
    // Code Context Graph (CCG) Methods
    // ========================================================================

    /// Get CCG manifest (Layer 0) for a repository.
    ///
    /// Returns a JSON-LD manifest with repository identity, symbol counts,
    /// security summary, and layer URIs.
    ///
    /// # Arguments
    ///
    /// * `repo` - Repository name
    /// * `include_security` - Whether to include security summary
    /// * `base_url` - Base URL for layer URIs
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The repository is not found
    /// - The graph feature is not enabled
    #[cfg(feature = "graph")]
    pub async fn get_ccg_manifest(
        &self,
        repo: &str,
        include_security: bool,
        base_url: Option<&str>,
    ) -> Result<String> {
        use crate::ccg::{CcgGenerator, CcgOptions, Layer};

        let input = self.build_ccg_input(repo).await?;

        let mut options = CcgOptions::default();
        if !include_security {
            options = options.without_security_summary();
        }
        if let Some(url) = base_url {
            options = options.with_base_url(url);
        }

        let generator = CcgGenerator::new();
        let output = generator.generate_layer(Layer::Manifest, &input, &options)?;

        Ok(output.content)
    }

    /// Export CCG manifest (Layer 0) to a file.
    ///
    /// # Arguments
    ///
    /// * `repo` - Repository name
    /// * `include_security` - Whether to include security summary
    /// * `base_url` - Base URL for layer URIs
    /// * `output_path` - Optional output file path
    ///
    /// # Errors
    ///
    /// Returns an error if file writing fails.
    #[cfg(feature = "graph")]
    pub async fn export_ccg_manifest(
        &self,
        repo: &str,
        include_security: bool,
        base_url: Option<&str>,
        output_path: Option<&str>,
    ) -> Result<String> {
        let content = self
            .get_ccg_manifest(repo, include_security, base_url)
            .await?;

        if let Some(path) = output_path {
            std::fs::write(path, &content)?;
            Ok(format!(
                "Manifest exported to: {}\nSize: {} bytes",
                path,
                content.len()
            ))
        } else {
            Ok(content)
        }
    }

    /// Export CCG architecture (Layer 1) for a repository.
    #[cfg(feature = "graph")]
    pub async fn export_ccg_architecture(
        &self,
        repo: &str,
        output_path: Option<&str>,
    ) -> Result<String> {
        use crate::ccg::{CcgGenerator, CcgOptions, Layer};

        let input = self.build_ccg_input(repo).await?;
        let options = CcgOptions::default();

        let generator = CcgGenerator::new();
        let output = generator.generate_layer(Layer::Architecture, &input, &options)?;

        if let Some(path) = output_path {
            std::fs::write(path, &output.content)?;
            Ok(format!(
                "Architecture exported to: {}\nSize: {} bytes",
                path, output.size_bytes
            ))
        } else {
            Ok(output.content)
        }
    }

    /// Export CCG symbol index (Layer 2) for a repository.
    #[cfg(feature = "graph")]
    pub async fn export_ccg_index(&self, repo: &str, output_path: Option<&str>) -> Result<String> {
        use crate::ccg::{CcgGenerator, CcgOptions, Layer};

        let input = self.build_ccg_input(repo).await?;
        let options = CcgOptions::default();

        let generator = CcgGenerator::new();
        let output = generator.generate_layer(Layer::SymbolIndex, &input, &options)?;

        if let Some(path) = output_path {
            // Write base64-encoded gzipped content
            std::fs::write(path, &output.content)?;
            Ok(format!(
                "Symbol index exported to: {}\nCompressed size: {} bytes\nSymbol count: {}",
                path,
                output.size_bytes,
                output
                    .metadata
                    .get("symbol_count")
                    .unwrap_or(&serde_json::json!(0))
            ))
        } else {
            // Return metadata summary since content is binary
            Ok(format!(
                "# CCG Symbol Index (Layer 2)\n\nCompressed size: {} bytes\nSymbol count: {}\nCall edges: {}\n\n*Content is gzip-compressed and base64-encoded*",
                output.size_bytes,
                output.metadata.get("symbol_count").unwrap_or(&serde_json::json!(0)),
                output.metadata.get("call_edge_count").unwrap_or(&serde_json::json!(0))
            ))
        }
    }

    /// Export CCG full detail (Layer 3) for a repository.
    #[cfg(feature = "graph")]
    pub async fn export_ccg_full(&self, repo: &str, output_path: Option<&str>) -> Result<String> {
        use crate::ccg::{CcgGenerator, CcgOptions, Layer};

        let input = self.build_ccg_input(repo).await?;
        let options = CcgOptions::default();

        let generator = CcgGenerator::new();
        let output = generator.generate_layer(Layer::FullDetail, &input, &options)?;

        if let Some(path) = output_path {
            std::fs::write(path, &output.content)?;
            Ok(format!(
                "Full detail exported to: {}\nCompressed size: {} bytes",
                path, output.size_bytes
            ))
        } else {
            Ok(format!(
                "# CCG Full Detail (Layer 3)\n\nCompressed size: {} bytes\nSymbol count: {}\nCall edges: {}\nImport edges: {}\nFindings: {}\n\n*Content is gzip-compressed and base64-encoded*",
                output.size_bytes,
                output.metadata.get("symbol_count").unwrap_or(&serde_json::json!(0)),
                output.metadata.get("call_edge_count").unwrap_or(&serde_json::json!(0)),
                output.metadata.get("import_edge_count").unwrap_or(&serde_json::json!(0)),
                output.metadata.get("finding_count").unwrap_or(&serde_json::json!(0))
            ))
        }
    }

    /// Export all CCG layers bundled to a directory.
    #[cfg(feature = "graph")]
    pub async fn export_ccg(
        &self,
        repo: &str,
        output_dir: Option<&str>,
        base_url: Option<&str>,
        include_security: bool,
    ) -> Result<String> {
        use crate::ccg::{CcgGenerator, CcgOptions};

        let input = self.build_ccg_input(repo).await?;

        let mut options = CcgOptions::default();
        if !include_security {
            options = options.without_security_summary();
        }
        if let Some(url) = base_url {
            options = options.with_base_url(url);
        }

        let generator = CcgGenerator::new();
        let bundle = generator.generate_bundle(&input, &options)?;

        if let Some(dir) = output_dir {
            std::fs::create_dir_all(dir)?;

            // Write each layer
            for (layer, output) in &bundle.layers {
                let filename = match layer {
                    crate::ccg::Layer::Manifest => "manifest.json",
                    crate::ccg::Layer::Architecture => "architecture.json",
                    crate::ccg::Layer::SymbolIndex => "symbol-index.nq.gz.b64",
                    crate::ccg::Layer::FullDetail => "full-detail.nq.gz.b64",
                };
                let path = format!("{}/{}", dir, filename);
                std::fs::write(&path, &output.content)?;
            }

            Ok(format!(
                "# CCG Bundle Exported\n\nDirectory: {}\nTotal size: {} bytes\nLayers: {}\nL0+L1 within budget: {}",
                dir,
                bundle.total_size_bytes,
                bundle.layers.len(),
                bundle.manifest_layers_within_budget()
            ))
        } else {
            Ok(format!(
                "# CCG Bundle Summary\n\nRepository: {}\nTotal size: {} bytes\nLayers: {}\nL0+L1 within budget: {}\nGenerated at: {}",
                bundle.repo,
                bundle.total_size_bytes,
                bundle.layers.len(),
                bundle.manifest_layers_within_budget(),
                bundle.generated_at
            ))
        }
    }

    /// Query CCG Layer 3 using SPARQL.
    ///
    /// # Arguments
    ///
    /// * `repo` - Repository name (reserved for repo-specific CCG querying)
    /// * `query` - SPARQL query string
    /// * `timeout_ms` - Optional query timeout in milliseconds
    /// * `limit` - Optional result limit
    ///
    /// # Errors
    ///
    /// Returns an error if the SPARQL query fails.
    #[cfg(feature = "graph")]
    pub async fn query_ccg(
        &self,
        _repo: &str,
        query: &str,
        timeout_ms: Option<u64>,
        limit: Option<usize>,
    ) -> Result<String> {
        // For now, delegate to sparql_query since L3 is stored in the knowledge graph.
        // The _repo parameter is reserved for repo-specific CCG querying in the future.
        self.sparql_query(query, timeout_ms, limit, None, Some("markdown"))
            .await
    }

    /// Build CCG input from repository data.
    #[cfg(feature = "graph")]
    async fn build_ccg_input(&self, repo: &str) -> Result<crate::ccg::CcgInput> {
        use crate::ccg::{
            CallEdgeInfo, CcgInput, FileInfo, ImportEdgeInfo, SecurityFindingInfo, SymbolInfo,
        };

        // Get repo metadata
        let repo_meta = self
            .repos
            .get(repo)
            .ok_or_else(|| anyhow!("Repository not found: {}", repo))?;

        // Build file info from file cache, filtered by repo path
        let repo_path = repo_meta.path.clone();
        drop(repo_meta); // Release the borrow before iterating file_cache

        let files: Vec<FileInfo> = self
            .file_cache
            .iter()
            .filter(|entry| entry.key().starts_with(&repo_path))
            .map(|entry| {
                let path = entry.key();
                let path_str = path.to_string_lossy().to_string();
                let relative_path = path
                    .strip_prefix(&repo_path)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| path_str.clone());
                let language = detect_language_from_path(&path_str);
                let size_bytes = entry.value().len();
                FileInfo {
                    path: relative_path,
                    language,
                    size_bytes,
                }
            })
            .collect();

        // Build symbol info
        let symbols: Vec<SymbolInfo> = self
            .symbols
            .get(repo)
            .map(|s| {
                s.iter()
                    .map(|sym| SymbolInfo {
                        name: sym.name.clone(),
                        kind: format!("{:?}", sym.kind),
                        file: sym.file_path.clone(),
                        start_line: sym.start_line,
                        end_line: sym.end_line,
                        signature: sym.signature.clone(),
                        doc_comment: sym.doc_comment.clone(),
                        is_public: true, // Would need visibility analysis
                        complexity: None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Build call edges from call graph (if available)
        let call_edges: Vec<CallEdgeInfo> = self
            .call_graphs
            .get(repo)
            .map(|cg| {
                cg.iter_nodes()
                    .flat_map(|node| {
                        let node = node.value();
                        node.calls
                            .iter()
                            .map(|edge| CallEdgeInfo {
                                caller: node.name.clone(),
                                caller_file: node.file_path.clone(),
                                callee: edge.target.clone(),
                                callee_file: edge.file_path.clone(),
                                line: edge.line,
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Build import edges - for now empty, would need import graph
        let import_edges: Vec<ImportEdgeInfo> = Vec::new();

        // Get security findings
        let security_findings: Vec<SecurityFindingInfo> = Vec::new();
        // Would need to run security scan and cache results

        Ok(CcgInput {
            repo_name: repo.to_string(),
            repo_url: None,
            files,
            symbols,
            call_edges,
            import_edges,
            security_findings,
        })
    }
}

/// Minimum C/C++ source files for a repo to be treated as a compile-commands
/// build. Below this, a missing compile_commands.json is assumed intentional
/// (e.g. a plain-Makefile project) rather than an error worth filtering or
/// warning for.
const COMPILE_COMMANDS_MIN_CXX_SOURCES: usize = 5;

/// Default minimum percent of a repo's C sources that compile_commands.json must
/// cover to be trusted as the index filter (per-repo overridable via
/// `compile_commands_min_coverage_pct`). Below this the manifest is treated as
/// stale/partial and ignored so a one-off `bear` capture of a single TU cannot
/// silently gut the index.
const COMPILE_COMMANDS_DEFAULT_MIN_COVERAGE_PCT: usize = 25;

fn is_c_source_ext(ext: &str) -> bool {
    matches!(ext, "c" | "cpp" | "cc" | "cxx" | "S" | "s")
}

/// True when `repo_path`'s GTAGS database is older than the newest indexed
/// C/C++ source. A stale database reports drifted line numbers that the
/// line-window symbol merge cannot pair, silently dropping gtags confirmation.
fn gtags_database_stale(repo_path: &Path, files: &[PathBuf]) -> bool {
    let gtags_mtime = match std::fs::metadata(repo_path.join("GTAGS")).and_then(|m| m.modified()) {
        Ok(mtime) => mtime,
        Err(_) => return false,
    };
    files.iter().any(|file| {
        let is_cxx = file
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| is_c_source_ext(e) || is_c_header_ext(e));
        is_cxx
            && std::fs::metadata(file)
                .and_then(|m| m.modified())
                .map(|mtime| mtime > gtags_mtime)
                .unwrap_or(false)
    })
}

/// sha256 hex of file content, matching the `content_hash` persisted in
/// `FileMetadata`, so a rebuild can tell whether a file changed since last index.
fn content_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn is_c_header_ext(ext: &str) -> bool {
    matches!(ext, "h" | "hpp" | "hh" | "hxx" | "h++")
}

fn load_compile_commands_filter(
    repo_root: &Path,
    json_paths: &[&Path],
) -> std::collections::HashSet<PathBuf> {
    let mut result = std::collections::HashSet::new();
    let mut any_loaded = false;

    for json_path in json_paths {
        let full_path = if json_path.is_absolute() {
            json_path.to_path_buf()
        } else {
            repo_root.join(json_path)
        };

        let content = match std::fs::read_to_string(&full_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let entries: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Failed to parse compile_commands.json at {:?}: {}",
                    full_path, e
                );
                continue;
            }
        };

        let arr = match entries.as_array() {
            Some(a) => a,
            None => {
                warn!(
                    "compile_commands.json at {:?} is not a JSON array",
                    full_path
                );
                continue;
            }
        };

        // A present-but-empty compile_commands.json (e.g. `[]`) parses fine yet,
        // under --use-compile-commands, silently filters out every C/C++ source
        // file, leaving only headers indexed. Surface it loudly.
        if arr.is_empty() {
            warn!(
                "compile_commands.json at {:?} exists but has 0 entries ({} bytes); \
                 with --use-compile-commands all C/C++ source files will be skipped \
                 (headers still indexed). Regenerate it or drop --use-compile-commands.",
                full_path,
                content.len()
            );
        }

        let json_parent = full_path.parent().map(Path::to_path_buf);
        let count_before = result.len();
        let mut unresolved = 0usize;
        for entry in arr.iter() {
            let file_str = match entry.get("file").and_then(|f| f.as_str()) {
                Some(s) => s,
                None => continue,
            };
            let directory: Option<&Path> = entry
                .get("directory")
                .and_then(|d| d.as_str())
                .map(Path::new);
            match resolve_compile_command_file(file_str, directory, json_parent.as_deref()) {
                Some(canonical) => {
                    result.insert(canonical);
                }
                None => {
                    unresolved += 1;
                }
            }
        }
        if unresolved > 0 {
            warn!(
                "compile_commands.json at {:?}: {} entries with unresolvable paths",
                full_path, unresolved
            );
        }
        info!(
            "Loaded {} compiled files from {:?}",
            result.len() - count_before,
            full_path
        );
        any_loaded = true;
    }

    if !any_loaded {
        warn!(
            "No compile_commands.json found in {:?} (tried: {:?})",
            repo_root, json_paths
        );
    }

    result
}

/// Resolve a compile_commands.json `file` field to a canonical absolute path.
///
/// Per the clang spec, when `file` is relative it must be resolved against
/// the entry's `directory` field. We also fall back to resolving against
/// the JSON's containing directory, which lets us tolerate JSONs generated
/// on another machine where `directory` points at a path that doesn't exist
/// on this filesystem.
fn resolve_compile_command_file(
    file: &str,
    directory: Option<&Path>,
    json_parent: Option<&Path>,
) -> Option<PathBuf> {
    let file_path = Path::new(file);
    if file_path.is_absolute() {
        return file_path.canonicalize().ok();
    }
    if let Some(dir) = directory {
        if let Ok(canonical) = dir.join(file_path).canonicalize() {
            return Some(canonical);
        }
    }
    if let Some(parent) = json_parent {
        if let Ok(canonical) = parent.join(file_path).canonicalize() {
            return Some(canonical);
        }
    }
    None
}

fn compile_include_patterns(patterns: &[String]) -> Vec<glob::Pattern> {
    patterns
        .iter()
        .filter_map(|p| match glob::Pattern::new(p) {
            Ok(pattern) => Some(pattern),
            Err(e) => {
                warn!("Invalid include pattern '{}': {}", p, e);
                None
            }
        })
        .collect()
}

/// Parse imports from file content
fn parse_imports_from_content(content: &str, file_path: &str) -> Vec<crate::incremental::Import> {
    let mut imports = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // JavaScript/TypeScript ES imports
        if trimmed.starts_with("import ") {
            if let Some(from_idx) = trimmed.find(" from ") {
                let path_part = &trimmed[from_idx + 7..];
                let import_path = path_part
                    .trim_matches(|c| c == '\'' || c == '"' || c == ';')
                    .to_string();

                imports.push(crate::incremental::Import {
                    source_file: std::path::PathBuf::from(file_path),
                    import_path,
                    imported_symbols: vec![],
                    import_type: crate::incremental::ImportType::EsModule,
                    line: line_num + 1,
                });
            }
        }
        // CommonJS require
        else if trimmed.contains("require(") {
            if let Some(start) = trimmed.find("require(") {
                let after = &trimmed[start + 8..];
                if let Some(end) = after.find(')') {
                    let import_path = after[..end]
                        .trim_matches(|c| c == '\'' || c == '"')
                        .to_string();

                    imports.push(crate::incremental::Import {
                        source_file: std::path::PathBuf::from(file_path),
                        import_path,
                        imported_symbols: vec![],
                        import_type: crate::incremental::ImportType::CommonJs,
                        line: line_num + 1,
                    });
                }
            }
        }
        // Python imports
        else if let Some(stripped) = trimmed.strip_prefix("from ") {
            let import_path = stripped.split_whitespace().next().unwrap_or("").to_string();
            if !import_path.is_empty() {
                imports.push(crate::incremental::Import {
                    source_file: std::path::PathBuf::from(file_path),
                    import_path,
                    imported_symbols: vec![],
                    import_type: crate::incremental::ImportType::Python,
                    line: line_num + 1,
                });
            }
        } else if let Some(stripped) = trimmed.strip_prefix("import ") {
            // Handle Go imports separately from Python
            if file_path.ends_with(".go") {
                let import_path = stripped
                    .trim_matches(|c| c == '"' || c == '(' || c == ')')
                    .to_string();

                if !import_path.is_empty() {
                    imports.push(crate::incremental::Import {
                        source_file: std::path::PathBuf::from(file_path),
                        import_path,
                        imported_symbols: vec![],
                        import_type: crate::incremental::ImportType::Go,
                        line: line_num + 1,
                    });
                }
            } else {
                // Python import
                let import_path = stripped.split_whitespace().next().unwrap_or("").to_string();
                if !import_path.is_empty() {
                    imports.push(crate::incremental::Import {
                        source_file: std::path::PathBuf::from(file_path),
                        import_path,
                        imported_symbols: vec![],
                        import_type: crate::incremental::ImportType::Python,
                        line: line_num + 1,
                    });
                }
            }
        }
        // Rust use statements
        else if let Some(stripped) = trimmed.strip_prefix("use ") {
            // Extract the full module path, removing the item/group at the end
            // e.g., "use crate::api::client::Client;" → "crate::api::client"
            // e.g., "use crate::api::{foo, bar};" → "crate::api"
            let cleaned = stripped.trim_end_matches(';').trim();

            let import_path = if let Some(brace_idx) = cleaned.find('{') {
                // Group import: take everything before the brace
                cleaned[..brace_idx].trim_end_matches("::").to_string()
            } else {
                // Single import: take all segments (resolver will try
                // progressively shorter paths)
                cleaned.to_string()
            };

            if !import_path.is_empty() {
                imports.push(crate::incremental::Import {
                    source_file: std::path::PathBuf::from(file_path),
                    import_path,
                    imported_symbols: vec![],
                    import_type: crate::incremental::ImportType::Rust,
                    line: line_num + 1,
                });
            }
        }
        // C/C++ includes
        else if let Some(stripped) = trimmed.strip_prefix("#include") {
            let import_path = stripped
                .trim()
                .trim_matches(|c| c == '"' || c == '<' || c == '>')
                .to_string();

            imports.push(crate::incremental::Import {
                source_file: std::path::PathBuf::from(file_path),
                import_path,
                imported_symbols: vec![],
                import_type: crate::incremental::ImportType::CppInclude,
                line: line_num + 1,
            });
        }
    }

    imports
}

/// Format a vulnerability finding for output
fn format_vuln_finding(v: &crate::supply_chain::DependencyVuln) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "### {} @ {}\n\n",
        v.dependency.name, v.dependency.version
    ));
    s.push_str(&format!("**Ecosystem**: {:?}\n", v.dependency.ecosystem));

    if let Some(ref upgrade) = v.upgrade_to {
        s.push_str(&format!("**Upgrade to**: {}\n\n", upgrade));
    }

    s.push_str("**Vulnerabilities**:\n\n");
    for vuln in &v.vulnerabilities {
        s.push_str(&format!("- **{}**: {}\n", vuln.id, vuln.summary));
        if !vuln.aliases.is_empty() {
            s.push_str(&format!("  - Aliases: {}\n", vuln.aliases.join(", ")));
        }
        if let Some(score) = vuln.cvss_score {
            s.push_str(&format!("  - CVSS: {:.1}\n", score));
        }
        if !vuln.fixed_versions.is_empty() {
            s.push_str(&format!(
                "  - Fixed in: {}\n",
                vuln.fixed_versions.join(", ")
            ));
        }
    }
    s.push('\n');
    s
}

/// Format a security finding for output
fn format_finding(f: &crate::security_rules::SecurityFinding) -> String {
    let mut s = String::new();
    s.push_str(&format!("### {} - {}\n\n", f.rule_id, f.rule_name));
    s.push_str(&format!("**File**: {}:{}\n", f.file_path, f.line));
    s.push_str(&format!("**Message**: {}\n", f.message));
    if !f.cwe.is_empty() {
        s.push_str(&format!("**CWE**: {}\n", f.cwe.join(", ")));
    }
    s.push_str(&format!("**Remediation**: {}\n\n", f.remediation));
    if !f.snippet.is_empty() {
        s.push_str("```\n");
        s.push_str(&f.snippet);
        s.push_str("\n```\n\n");
    }
    s
}

/// File extensions supported for security scanning
const SECURITY_SCAN_EXTENSIONS: &[&str] = &[
    ".py", ".js", ".ts", ".tsx", ".go", ".rs", ".c", ".cpp", ".h", ".java", ".rb", ".php",
];

/// Parse severity threshold from string
fn parse_severity_threshold(threshold: Option<&str>) -> crate::taint::Severity {
    use crate::taint::Severity;
    match threshold {
        Some("critical") => Severity::Critical,
        Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        Some("info") => Severity::Info,
        _ => Severity::Low,
    }
}

/// Check if file extension is supported for security scanning
fn is_security_scannable(path: &str) -> bool {
    SECURITY_SCAN_EXTENSIONS
        .iter()
        .any(|ext| path.ends_with(ext))
}

/// OWASP Top 10 2021 categories
const OWASP_TOP10_CATEGORIES: &[(&str, &str)] = &[
    ("A01:2021", "Broken Access Control"),
    ("A02:2021", "Cryptographic Failures"),
    ("A03:2021", "Injection"),
    ("A04:2021", "Insecure Design"),
    ("A05:2021", "Security Misconfiguration"),
    ("A06:2021", "Vulnerable Components"),
    ("A07:2021", "Authentication Failures"),
    ("A08:2021", "Software Integrity Failures"),
    ("A09:2021", "Logging Failures"),
    ("A10:2021", "SSRF"),
];

/// CWE Top 25 vulnerability types
const CWE_TOP25_TYPES: &[(&str, &str)] = &[
    ("CWE-787", "Out-of-bounds Write"),
    ("CWE-79", "Cross-site Scripting (XSS)"),
    ("CWE-89", "SQL Injection"),
    ("CWE-416", "Use After Free"),
    ("CWE-78", "OS Command Injection"),
    ("CWE-20", "Improper Input Validation"),
    ("CWE-125", "Out-of-bounds Read"),
    ("CWE-22", "Path Traversal"),
    ("CWE-352", "Cross-Site Request Forgery"),
    ("CWE-434", "Unrestricted File Upload"),
    ("CWE-862", "Missing Authorization"),
    ("CWE-476", "NULL Pointer Dereference"),
    ("CWE-287", "Improper Authentication"),
    ("CWE-190", "Integer Overflow"),
    ("CWE-502", "Insecure Deserialization"),
    ("CWE-798", "Hardcoded Credentials"),
    ("CWE-918", "Server-Side Request Forgery"),
];

/// Format findings grouped by category (OWASP or CWE)
fn format_findings_by_category<'a, F>(
    findings: &'a [crate::security_rules::SecurityFinding],
    categories: &[(&str, &str)],
    get_cats: F,
) -> String
where
    F: Fn(&'a crate::security_rules::SecurityFinding) -> &'a Vec<String>,
{
    use std::collections::HashMap;

    let mut by_category: HashMap<String, Vec<_>> = HashMap::new();
    for f in findings {
        for cat in get_cats(f) {
            by_category.entry(cat.clone()).or_default().push(f);
        }
    }

    let mut output = String::new();
    for (cat_id, cat_name) in categories {
        if let Some(cat_findings) = by_category.get(*cat_id) {
            output.push_str(&format!(
                "## {} - {} ({})\n\n",
                cat_id,
                cat_name,
                cat_findings.len()
            ));
            for f in cat_findings {
                output.push_str(&format_finding(f));
            }
        }
    }
    output
}

/// Format findings grouped by severity level
fn format_findings_by_severity(findings: &[crate::security_rules::SecurityFinding]) -> String {
    use crate::taint::Severity;

    let mut output = String::new();

    let severity_groups = [
        (Severity::Critical, "🔴 Critical"),
        (Severity::High, "🟠 High"),
        (Severity::Medium, "🟡 Medium"),
        (Severity::Low, "🔵 Low"),
    ];

    for (severity, label) in severity_groups {
        let group: Vec<_> = findings.iter().filter(|f| f.severity == severity).collect();
        if !group.is_empty() {
            output.push_str(&format!("## {} ({})\n\n", label, group.len()));
            for f in group {
                output.push_str(&format_finding(f));
            }
        }
    }

    output
}

/// Detect language from file path
fn detect_language_from_path(path: &str) -> String {
    if path.ends_with(".py") {
        "python".to_string()
    } else if path.ends_with(".js") {
        "javascript".to_string()
    } else if path.ends_with(".ts") || path.ends_with(".tsx") {
        "typescript".to_string()
    } else if path.ends_with(".rs") {
        "rust".to_string()
    } else if path.ends_with(".go") {
        "go".to_string()
    } else if path.ends_with(".c") || path.ends_with(".h") {
        "c".to_string()
    } else if path.ends_with(".cpp")
        || path.ends_with(".cc")
        || path.ends_with(".cxx")
        || path.ends_with(".hpp")
    {
        "cpp".to_string()
    } else if path.ends_with(".java") {
        "java".to_string()
    } else if path.ends_with(".rb") {
        "ruby".to_string()
    } else if path.ends_with(".php") {
        "php".to_string()
    } else if path.ends_with(".cs") {
        "csharp".to_string()
    } else if path.ends_with(".swift") {
        "swift".to_string()
    } else if path.ends_with(".v")
        || path.ends_with(".vh")
        || path.ends_with(".sv")
        || path.ends_with(".svh")
    {
        "verilog".to_string()
    } else {
        "unknown".to_string()
    }
}

fn is_type_checkable_language(language: &str) -> bool {
    matches!(language, "python" | "javascript" | "typescript")
}

// Helper functions

/// Derive the canonical absolute path string used as the engine's repository
/// key. All repository-keyed maps (`repos`, `symbols`, `git_repos`,
/// `call_graphs`) share this single key derivation so that two repositories
/// with the same basename (e.g. two `linux.git` clones) do not collide.
fn canonical_repo_key(path: &Path) -> Result<String> {
    Ok(path
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize repo path {:?}", path))?
        .to_string_lossy()
        .into_owned())
}

fn expand_path(path: &Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if let Some(stripped) = path_str.strip_prefix("~") {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("Cannot find home directory"))?;
        Ok(home.join(path_str.strip_prefix("~/").unwrap_or(stripped)))
    } else {
        Ok(path.to_path_buf())
    }
}

fn path_is_within_repo(path: &Path, repo: &Path) -> bool {
    if path.starts_with(repo) {
        return true;
    }

    let Ok(repo_canonical) = repo.canonicalize() else {
        return false;
    };

    if let Ok(path_canonical) = path.canonicalize() {
        return path_canonical.starts_with(&repo_canonical);
    }

    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(parent_canonical) = parent.canonicalize() else {
        return false;
    };

    parent_canonical.starts_with(repo_canonical)
}

/// Validate that a requested path is within the repository root to prevent path traversal attacks
fn validate_path(repo_root: &Path, requested: &str) -> Result<PathBuf> {
    // Don't allow paths starting with /
    if requested.starts_with('/') {
        return Err(anyhow!("Absolute paths not allowed"));
    }

    // Build and canonicalize the full path
    let full_path = repo_root.join(requested);

    // Canonicalize both paths for comparison (handles ../ etc)
    let canonical_root = repo_root
        .canonicalize()
        .context("Failed to canonicalize repo root")?;
    let canonical_path = full_path
        .canonicalize()
        .context("Path does not exist or cannot be accessed")?;

    // Verify the requested path is within the repo root
    if !canonical_path.starts_with(&canonical_root) {
        return Err(anyhow!(
            "Path traversal attempt blocked: path is outside repository"
        ));
    }

    Ok(canonical_path)
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;

    if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

fn get_file_icon(name: &str) -> &'static str {
    match name.rsplit('.').next() {
        // Rust Crab (\u{1f980})
        Some("rs") => "\u{1f980}",
        // Python Snake (\u{1f40d})
        Some("py") => "\u{1f40d}",
        // Lua Moon (\u{1f319})
        Some("lua") => "\u{1f319}",
        // Scroll (\u{1f4dc})
        Some("js" | "jsx") => "\u{1f4dc}",
        // Blue Book (\u{1f4d8})
        Some("ts" | "tsx") => "\u{1f4d8}",
        // Hamster Face (\u{1f439})
        Some("go") => "\u{1f439}",
        // Hot Beverage (\u{2615})
        Some("java") => "\u{2615}",
        // Gear (\u{2699}\u{fe0f})
        Some("c" | "h" | "cpp" | "hpp" | "cc") => "\u{2699}\u{fe0f}",
        // Memo (\u{1f4dd})
        Some("md") => "\u{1f4dd}",
        // Clipboard (\u{1f4cb})
        Some("json") => "\u{1f4cb}",
        // Gear (\u{2699}\u{fe0f})
        Some("toml" | "yaml" | "yml") => "\u{2699}\u{fe0f}",
        // Globe with Meridians (\u{1f310})
        Some("html") => "\u{1f310}",
        // Artist Palette (\u{1f3a8})
        Some("css" | "scss") => "\u{1f3a8}",
        // Page Facing Up (\u{1f4c4})
        _ => "\u{1f4c4}",
    }
}

fn get_language_id(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("rs") => "rust",
        Some("py") => "python",
        Some("js") => "javascript",
        Some("jsx") => "jsx",
        Some("ts") => "typescript",
        Some("tsx") => "tsx",
        Some("go") => "go",
        Some("java") => "java",
        Some("c" | "h") => "c",
        Some("cpp" | "hpp" | "cc") => "cpp",
        Some("md") => "markdown",
        Some("json") => "json",
        Some("toml") => "toml",
        Some("yaml" | "yml") => "yaml",
        Some("html") => "html",
        Some("css") => "css",
        Some("scss") => "scss",
        Some("sh" | "bash") => "bash",
        _ => "",
    }
}

fn calculate_relevance(line: &str, query: &str) -> f32 {
    let mut score = 1.0;

    // Exact match bonus
    if line.contains(query) {
        score += 2.0;
    }

    // Word boundary bonus
    let words: Vec<&str> = line.split_whitespace().collect();
    for word in &words {
        if word.to_lowercase() == query {
            score += 3.0;
        }
    }

    // Definition-like patterns get bonus
    if line.contains("fn ")
        || line.contains("def ")
        || line.contains("func ")
        || line.contains("class ")
        || line.contains("struct ")
    {
        score += 1.5;
    }

    // Shorter lines with match are more relevant
    score += (100.0 / line.len() as f32).min(1.0);

    score
}

/// True for the tree-sitter language names of C and C++ sources. Accepts both
/// the parser's lowercase config names ("c"/"cpp") and the capitalized display
/// names from `ext_to_language` ("C"/"C++"), since the fresh-index and
/// persisted-load paths key the languages map with different conventions.
fn is_cxx_language(name: &str) -> bool {
    matches!(name, "c" | "cpp" | "C" | "C++")
}

fn ext_to_language(ext: &str) -> String {
    match ext {
        "rs" => "Rust",
        "py" => "Python",
        "js" | "jsx" => "JavaScript",
        "ts" | "tsx" => "TypeScript",
        "go" => "Go",
        "java" => "Java",
        "c" | "h" => "C",
        "cpp" | "hpp" | "cc" | "cxx" => "C++",
        "cs" => "C#",
        _ => ext,
    }
    .to_string()
}

fn extract_imports(content: &str, _path: &str) -> Vec<String> {
    let mut imports = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Detect imports across languages:
        // - Rust: use
        // - Python: import, from
        // - JavaScript/TypeScript: import, require()
        // - Go: import
        // - C/C++: #include
        let is_import = trimmed.starts_with("use ")
            || trimmed.starts_with("import ")
            || trimmed.starts_with("from ")
            || trimmed.contains("require(")
            || trimmed.starts_with("#include");

        if is_import {
            imports.push(trimmed.to_string());
        }
    }

    imports
}

mod dirs {
    use std::path::PathBuf;

    pub fn home_dir() -> Option<PathBuf> {
        directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
    }
}

/// Maximum line distance at which same-name symbols from different backends are
/// treated as the same definition. Backends report different rows for one
/// definition (tree-sitter = definition node, LSP = name token, gtags = tag
/// line); a small window pairs them while leaving genuine overloads — which sit
/// further apart — as separate symbols. Too wide merges adjacent overloads, too
/// narrow duplicates one symbol.
const SYMBOL_MATCH_WINDOW: usize = 3;

/// Concurrent in-flight C/C++ files during the LSP/gtags augmentation pass.
/// Kept small to overlap subprocesses and server round-trips without flooding a
/// single clangd/ccls process.
const CXX_AUGMENT_CONCURRENCY: usize = 6;

/// Wall-clock cap on the per-repo callHierarchy (LSP) augment phase. clangd/ccls
/// answer cold first-opens slowly; on a large tree the per-function round-trips
/// can otherwise run for minutes. Once exceeded, remaining files are skipped and
/// the graph keeps its tree-sitter/gtags edges plus whatever callHierarchy
/// already completed.
const CXX_CALLHIERARCHY_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// One C/C++ file's tree-sitter baseline symbols, queued for the async LSP/gtags
/// augmentation pass that cannot run inside the rayon parse closure.
struct CxxFileSymbols {
    abs_path: PathBuf,
    relative_path: String,
    symbols: Vec<Symbol>,
}

/// What a provenance annotation describes. Only the gtags-only wording differs:
/// gtags reports references, not resolved calls.
#[derive(Clone, Copy)]
enum ProvenanceSubject {
    Symbol,
    CallEdge,
}

/// All known backends, highest priority first — iterated to list which *enabled*
/// backends failed to confirm a datum.
const PROVENANCE_BACKENDS: [SourceSet; 4] = [
    SourceSet::CLANGD,
    SourceSet::CCLS,
    SourceSet::TREE_SITTER,
    SourceSet::GTAGS,
];

/// Render a backend-provenance annotation, or `None` when nothing is worth
/// surfacing. Annotates only on divergence: returns `None` when fewer than two
/// backends were enabled for the repo (no cross-validation possible) or when
/// every enabled backend confirmed the datum with no line conflict. Otherwise
/// it names the disagreement so the consumer reasons about it instead of
/// trusting one backend blindly.
fn render_provenance(
    subject: ProvenanceSubject,
    enabled: SourceSet,
    confirmed: SourceSet,
    canonical_line: usize,
    conflicts: &[SourceLine],
) -> Option<String> {
    if enabled.count() < 2 {
        return None;
    }

    // Enabled backends that did not confirm this datum.
    let mut missing = SourceSet::empty();
    for backend in PROVENANCE_BACKENDS {
        if enabled.contains(backend) && !confirmed.contains(backend) {
            missing.insert(backend);
        }
    }
    if missing.is_empty() && conflicts.is_empty() {
        return None; // full agreement, no dissent — silent
    }

    let mut parts: Vec<String> = Vec::new();

    if matches!(subject, ProvenanceSubject::CallEdge) && confirmed == SourceSet::GTAGS {
        // global -rx reports references, not resolved calls.
        parts.push("reference-derived (gtags) — unverified call".to_string());
    } else if missing.is_empty() {
        parts.push(format!("confirmed by {}", confirmed.labels().join(", ")));
    } else {
        parts.push(format!(
            "confirmed by {}; not by {}",
            confirmed.labels().join(", "),
            missing.labels().join(", ")
        ));
    }

    if !conflicts.is_empty() {
        let label = |source: SourceSet| source.labels().first().copied().unwrap_or("?");
        let mut entries = vec![format!("{} {}", label(confirmed.highest()), canonical_line)];
        for conflict in conflicts {
            entries.push(format!("{} {}", label(conflict.source), conflict.line));
        }
        parts.push(format!("WARNING line disagreement: {}", entries.join(", ")));
    }

    Some(parts.join("; "))
}

/// Merge one backend's `incoming` symbols into `existing`, keyed by (name, file)
/// with nearest-line matching inside [`SYMBOL_MATCH_WINDOW`]. Mirrors
/// `callgraph::CallGraph::fold_edge`: `confirmed_by` accumulates, priority
/// ([`SourceSet::rank`]) wins the canonical location and metadata, and divergent
/// lines are retained in `line_conflicts`. A symbol no prior backend saw is
/// inserted standalone (genuine overloads stay separate).
fn merge_symbols(existing: &mut Vec<Symbol>, incoming: Vec<Symbol>, source: SourceSet) {
    for inc in incoming {
        let best = existing
            .iter_mut()
            .filter(|sym| sym.name == inc.name && sym.file_path == inc.file_path)
            .filter(|sym| sym.start_line.abs_diff(inc.start_line) <= SYMBOL_MATCH_WINDOW)
            .min_by_key(|sym| sym.start_line.abs_diff(inc.start_line));

        match best {
            Some(sym) => fold_symbol(sym, inc, source),
            None => {
                let mut sym = inc;
                sym.confirmed_by = source;
                sym.line_conflicts = Vec::new();
                existing.push(sym);
            }
        }
    }
}

/// Fold a `source` confirmation into an existing symbol. Priority decides the
/// canonical location and which source's metadata is kept; the loser's line is
/// retained in `line_conflicts`. A lower-priority source never erases richer
/// metadata (e.g. gtags supplies only name+line), so its fields are taken only
/// when it outranks the current confirmer and actually carries them.
fn fold_symbol(existing: &mut Symbol, incoming: Symbol, source: SourceSet) {
    let old_canonical = existing.confirmed_by.highest();
    existing.confirmed_by.insert(source);

    if source.rank() > old_canonical.rank() {
        if existing.start_line != incoming.start_line {
            existing.line_conflicts.push(SourceLine {
                source: old_canonical,
                line: existing.start_line,
            });
        }
        existing.start_line = incoming.start_line;
        existing.end_line = incoming.end_line;

        // Metadata follows the highest-priority source that supplies it.
        if incoming.kind != SymbolKind::Unknown {
            existing.kind = incoming.kind;
        }
        if incoming.signature.is_some() {
            existing.signature = incoming.signature;
        }
        if incoming.qualified_name.is_some() {
            existing.qualified_name = incoming.qualified_name;
        }
        if incoming.doc_comment.is_some() {
            existing.doc_comment = incoming.doc_comment;
        }
    } else if incoming.start_line != existing.start_line {
        existing.line_conflicts.push(SourceLine {
            source,
            line: incoming.start_line,
        });
    }
}

fn get_language_from_path(path: &str) -> String {
    match path.rsplit('.').next() {
        Some("rs") => "rust",
        Some("py") => "python",
        Some("js") | Some("jsx") => "javascript",
        Some("ts") | Some("tsx") => "typescript",
        Some("go") => "go",
        Some("java") => "java",
        Some("c") | Some("h") => "c",
        Some("cpp") | Some("hpp") | Some("cc") | Some("cxx") => "cpp",
        Some("cs") => "csharp",
        _ => "unknown",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn cxx_parser_language_names_drive_augmentation_gate() {
        // Regression: index_repo gates the clangd/ccls/gtags augmentation pass on
        // is_cxx_language(parsed.language). The parser names C "c" and C++ "cpp"
        // (lowercase); a stale uppercase "C"/"C++" comparison made the gate always
        // false, so no C/C++ symbol was ever cross-validated. Couple the two so
        // they cannot drift apart again.
        let parser = crate::parser::LanguageParser::new().unwrap();
        for (path, src) in [
            ("a.c", "int f(void) { return 0; }\n"),
            ("a.cpp", "int g() { return 0; }\n"),
        ] {
            let parsed = parser.parse_file(Path::new(path), src).unwrap();
            assert!(
                is_cxx_language(&parsed.language),
                "parser language {:?} for {} is not recognized by is_cxx_language",
                parsed.language,
                path
            );
        }
    }

    fn sym(name: &str, line: usize, source: SourceSet) -> Symbol {
        Symbol {
            name: name.to_string(),
            kind: if source == SourceSet::GTAGS {
                SymbolKind::Unknown
            } else {
                SymbolKind::Function
            },
            file_path: "a.c".to_string(),
            start_line: line,
            end_line: line,
            signature: (source != SourceSet::GTAGS).then(|| format!("sig@{}", line)),
            qualified_name: None,
            doc_comment: None,
            confirmed_by: source,
            line_conflicts: Vec::new(),
        }
    }

    #[test]
    fn merge_higher_priority_wins_line_and_records_conflict() {
        // tree-sitter at 10, clangd at 11 within the window: clangd wins the
        // canonical line, tree-sitter's line is retained as a conflict.
        let mut existing = vec![sym("foo", 10, SourceSet::TREE_SITTER)];
        merge_symbols(
            &mut existing,
            vec![sym("foo", 11, SourceSet::CLANGD)],
            SourceSet::CLANGD,
        );

        assert_eq!(existing.len(), 1);
        let foo = &existing[0];
        assert_eq!(foo.start_line, 11);
        assert!(foo.confirmed_by.contains(SourceSet::TREE_SITTER));
        assert!(foo.confirmed_by.contains(SourceSet::CLANGD));
        assert_eq!(foo.line_conflicts.len(), 1);
        assert_eq!(foo.line_conflicts[0].source, SourceSet::TREE_SITTER);
        assert_eq!(foo.line_conflicts[0].line, 10);
    }

    #[test]
    fn merge_lower_priority_keeps_line_but_adds_confirmer() {
        // gtags ranks below tree-sitter: it confirms existence and records its
        // divergent line, but never wins the canonical line or erases metadata.
        let mut existing = vec![sym("foo", 10, SourceSet::TREE_SITTER)];
        merge_symbols(
            &mut existing,
            vec![sym("foo", 9, SourceSet::GTAGS)],
            SourceSet::GTAGS,
        );

        let foo = &existing[0];
        assert_eq!(foo.start_line, 10);
        assert_eq!(foo.kind, SymbolKind::Function);
        assert_eq!(foo.signature.as_deref(), Some("sig@10"));
        assert!(foo.confirmed_by.contains(SourceSet::GTAGS));
        assert_eq!(
            foo.line_conflicts,
            vec![SourceLine {
                source: SourceSet::GTAGS,
                line: 9
            }]
        );
    }

    #[test]
    fn merge_beyond_window_keeps_overloads_separate() {
        // Two same-name definitions far apart are distinct overloads, not a
        // single symbol two backends disagree about.
        let mut existing = vec![sym("foo", 10, SourceSet::TREE_SITTER)];
        merge_symbols(
            &mut existing,
            vec![sym("foo", 40, SourceSet::CLANGD)],
            SourceSet::CLANGD,
        );

        assert_eq!(existing.len(), 2);
    }

    #[test]
    fn merge_inserts_symbol_no_prior_backend_saw() {
        // A macro-defined symbol only gtags found is added standalone.
        let mut existing = vec![sym("foo", 10, SourceSet::TREE_SITTER)];
        merge_symbols(
            &mut existing,
            vec![sym("BAR", 5, SourceSet::GTAGS)],
            SourceSet::GTAGS,
        );

        assert_eq!(existing.len(), 2);
        let bar = existing.iter().find(|s| s.name == "BAR").unwrap();
        assert_eq!(bar.confirmed_by, SourceSet::GTAGS);
    }

    fn source_set(bits: &[SourceSet]) -> SourceSet {
        let mut set = SourceSet::empty();
        for bit in bits {
            set.insert(*bit);
        }
        set
    }

    #[test]
    fn provenance_silent_without_cross_validation() {
        // Only one backend enabled — nothing to cross-validate against.
        let out = render_provenance(
            ProvenanceSubject::Symbol,
            SourceSet::TREE_SITTER,
            SourceSet::TREE_SITTER,
            10,
            &[],
        );
        assert!(out.is_none());
    }

    #[test]
    fn provenance_silent_on_full_agreement() {
        let enabled = source_set(&[SourceSet::TREE_SITTER, SourceSet::CLANGD]);
        assert!(render_provenance(ProvenanceSubject::Symbol, enabled, enabled, 10, &[]).is_none());
    }

    #[test]
    fn provenance_reports_existence_disagreement() {
        let enabled = source_set(&[SourceSet::TREE_SITTER, SourceSet::CLANGD, SourceSet::CCLS]);
        let msg = render_provenance(
            ProvenanceSubject::Symbol,
            enabled,
            SourceSet::CLANGD,
            10,
            &[],
        )
        .unwrap();
        assert!(msg.contains("confirmed by clangd"));
        assert!(msg.contains("not by"));
        assert!(msg.contains("ccls") && msg.contains("tree-sitter"));
    }

    #[test]
    fn provenance_flags_gtags_only_edge_as_unverified() {
        let enabled = source_set(&[SourceSet::TREE_SITTER, SourceSet::CLANGD, SourceSet::GTAGS]);
        let msg = render_provenance(
            ProvenanceSubject::CallEdge,
            enabled,
            SourceSet::GTAGS,
            10,
            &[],
        )
        .unwrap();
        assert!(msg.contains("reference-derived (gtags)"));
    }

    #[test]
    fn provenance_reports_line_disagreement() {
        let enabled = source_set(&[SourceSet::TREE_SITTER, SourceSet::CLANGD]);
        let conflicts = vec![SourceLine {
            source: SourceSet::TREE_SITTER,
            line: 9,
        }];
        let msg =
            render_provenance(ProvenanceSubject::Symbol, enabled, enabled, 10, &conflicts).unwrap();
        assert!(msg.contains("WARNING line disagreement"));
        assert!(msg.contains("clangd 10"));
        assert!(msg.contains("tree-sitter 9"));
    }

    #[test]
    fn anchor_lands_on_name_not_return_type() {
        // `foo` starts at column 4, past the `int ` return type.
        let src = "int foo(void) { return 0; }\n";
        let pos = CodeIntelEngine::locate_name_anchor(src, "foo", 1, 1);
        assert_eq!(pos, Some((0, 4)));
    }

    #[test]
    fn anchor_follows_name_onto_a_later_line() {
        // Return type on its own line pushes the name down one line.
        let src = "static int\nfoo(void)\n{\n}\n";
        let pos = CodeIntelEngine::locate_name_anchor(src, "foo", 1, 4);
        assert_eq!(pos, Some((1, 0)));
    }

    #[test]
    fn anchor_requires_whole_word_match() {
        // `foo` must not match inside `foobar`; the real definition is line 2.
        let src = "int foobar(void);\nint foo(void) { return 0; }\n";
        let pos = CodeIntelEngine::locate_name_anchor(src, "foo", 1, 2);
        assert_eq!(pos, Some((1, 4)));
    }

    #[test]
    fn anchor_returns_none_when_name_absent() {
        let src = "int bar(void) { return 0; }\n";
        assert_eq!(CodeIntelEngine::locate_name_anchor(src, "foo", 1, 1), None);
    }

    #[test]
    fn resolve_relative_file_via_directory_field() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        let src = repo.join("src/foo.c");
        write_file(&src, "int foo(void) { return 0; }\n");
        let build = repo.join("build");
        std::fs::create_dir_all(&build).unwrap();

        let resolved = resolve_compile_command_file("../src/foo.c", Some(&build), None)
            .expect("relative file with valid directory must resolve");

        assert_eq!(resolved, src.canonicalize().unwrap());
    }

    #[test]
    fn resolve_absolute_file_is_used_as_is() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        let src = repo.join("src/foo.c");
        write_file(&src, "");

        let abs = src.canonicalize().unwrap();
        let abs_str = abs.to_string_lossy();

        let resolved =
            resolve_compile_command_file(&abs_str, Some(Path::new("/nonexistent/build")), None)
                .expect("absolute file path must resolve regardless of directory");

        assert_eq!(resolved, abs);
    }

    #[test]
    fn resolve_falls_back_to_json_parent_when_directory_is_stale() {
        // Simulates a compile_commands.json generated on another machine:
        // `directory` points at a path that does not exist on this
        // filesystem, but the JSON itself sits in the real build dir, so
        // resolving against the JSON's parent yields the correct file.
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        let src = repo.join("src/foo.c");
        write_file(&src, "");
        let build = repo.join("build");
        std::fs::create_dir_all(&build).unwrap();

        let stale = Path::new("/this/path/does/not/exist/build");
        let resolved = resolve_compile_command_file("../src/foo.c", Some(stale), Some(&build))
            .expect("json-parent fallback must resolve when directory is stale");

        assert_eq!(resolved, src.canonicalize().unwrap());
    }

    #[test]
    fn resolve_returns_none_when_no_strategy_succeeds() {
        let tmp = TempDir::new().unwrap();
        let build = tmp.path().join("build");
        std::fs::create_dir_all(&build).unwrap();

        let resolved = resolve_compile_command_file(
            "no_such_file.c",
            Some(Path::new("/nonexistent/build")),
            Some(&build),
        );

        assert!(
            resolved.is_none(),
            "must return None when neither directory nor json-parent resolves"
        );
    }

    #[test]
    fn load_filter_resolves_meson_style_relative_paths() {
        // End-to-end: a meson-shaped compile_commands.json with `directory`
        // pointing at <repo>/build and `file` as `../lib/foo.c`. Confirms
        // that load_compile_commands_filter populates the set with the
        // canonical path that the walker would also emit — closing the
        // empty-set failure mode that drops every C source at the retain
        // filter.
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        let foo = repo.join("lib/foo.c");
        write_file(&foo, "");
        let build = repo.join("build");
        std::fs::create_dir_all(&build).unwrap();
        let json_path = build.join("compile_commands.json");
        let json = format!(
            r#"[{{"directory": "{}", "command": "cc -c ../lib/foo.c", "file": "../lib/foo.c"}}]"#,
            build.canonicalize().unwrap().display()
        );
        std::fs::write(&json_path, json).unwrap();

        let set = load_compile_commands_filter(repo, &[Path::new("build/compile_commands.json")]);

        assert_eq!(set.len(), 1, "must load exactly one entry");
        assert!(
            set.contains(&foo.canonicalize().unwrap()),
            "set must contain canonical path to lib/foo.c, got: {:?}",
            set
        );
    }
}
