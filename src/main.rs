#![recursion_limit = "256"]

use anyhow::{bail, Context, Result};
use clap::{Parser as ClapParser, Subcommand, ValueEnum};
use narsil_mcp::lsp::CxxLspBackend;
use narsil_mcp::{
    config, http_server, index, lsp, mcp, neural, persist, pid_status, repo, sse_discovery,
    stats_cli, stdio_proxy, streaming,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

/// Transport for the MCP server.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum Transport {
    /// Read JSON-RPC from stdin, write responses to stdout. The
    /// historical narsil-mcp transport; suitable when an editor spawns a
    /// fresh subprocess per session.
    #[default]
    Stdio,
    /// MCP HTTP+SSE transport (spec 2024-11-05). Serves one persistent
    /// narsil-mcp to many editor sessions over a shared HTTP listener.
    Sse,
}

#[derive(ClapParser, Debug)]
#[command(name = "narsil-mcp")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Blazingly fast MCP server for code intelligence")]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Configuration management commands
    #[command(subcommand)]
    Config(config::ConfigCommand),

    /// Tool listing and information commands
    #[command(subcommand)]
    Tools(config::ToolsCommand),

    /// Show accumulated performance stats (without starting the server).
    Stats(stats_cli::StatsArgs),
}

#[derive(ClapParser, Debug)]
struct ServerArgs {
    /// Paths to repositories or directories to index.
    /// Comma-separated when set via `NARSIL_REPOS`
    /// (e.g. `NARSIL_REPOS=/path/a,/path/b`).
    #[arg(short, long, env = "NARSIL_REPOS", value_delimiter = ',')]
    repos: Vec<PathBuf>,

    /// Named repository profile from config.yaml / .narsil.yaml
    #[arg(long, env = "NARSIL_PROFILE")]
    profile: Option<String>,

    /// Path to persistent index storage
    #[arg(
        short,
        long,
        env = "NARSIL_INDEX_PATH",
        default_value = "~/.cache/narsil-mcp"
    )]
    index_path: PathBuf,

    /// Enable verbose logging (to stderr)
    #[arg(short, long, env = "NARSIL_VERBOSE")]
    verbose: bool,

    /// Re-index all repositories on startup
    #[arg(long, env = "NARSIL_REINDEX")]
    reindex: bool,

    /// Enable watch mode for incremental updates
    #[arg(short, long, env = "NARSIL_WATCH")]
    watch: bool,

    /// Enable call graph analysis (slower initial index)
    #[arg(long, env = "NARSIL_CALL_GRAPH")]
    call_graph: bool,

    /// Enable git integration
    #[arg(long, env = "NARSIL_GIT")]
    git: bool,

    /// Auto-discover repositories in a directory
    #[arg(long, env = "NARSIL_DISCOVER")]
    discover: Option<PathBuf>,

    /// Enable index persistence (save/load index to/from disk)
    #[arg(short, long, env = "NARSIL_PERSIST")]
    persist: bool,

    /// Enable LSP integration for enhanced code intelligence (requires language servers installed)
    #[arg(long, env = "NARSIL_LSP")]
    lsp: bool,

    /// Force-disable LSP even when a C/C++ language server is present on PATH.
    /// Without this, LSP is auto-enabled for C/C++ repos that ship a
    /// compile_commands.json whenever clangd or ccls is installed.
    #[arg(long, env = "NARSIL_NO_LSP")]
    no_lsp: bool,

    /// C/C++ LSP backends to start: "auto" probes PATH for clangd and ccls and
    /// starts whichever are installed; a comma-separated subset (e.g. "clangd",
    /// "ccls", "clangd,ccls") pins specific backends. Only takes effect with --lsp.
    #[arg(long, env = "NARSIL_LSP_CXX_BACKENDS", default_value = "auto")]
    lsp_cxx_backends: String,

    /// Per-request timeout (ms) for the index-time C/C++ documentSymbol augment.
    /// clangd/ccls parse a translation unit on first open, which for large files
    /// exceeds the interactive timeout; raise this if augmentation is missing on
    /// big sources. Only takes effect with --lsp.
    #[arg(long, env = "NARSIL_LSP_INDEX_TIMEOUT_MS", default_value = "60000")]
    lsp_index_timeout_ms: u64,

    /// Force-enable GNU Global (gtags) as a C/C++ reference backend, even when
    /// global(1) is not detected. By default gtags is auto-enabled whenever
    /// global(1) is found on PATH. Returning results still needs a GTAGS database.
    #[arg(long, env = "NARSIL_GTAGS")]
    gtags: bool,

    /// Force-disable gtags even when global(1) is present on PATH.
    #[arg(long, env = "NARSIL_NO_GTAGS")]
    no_gtags: bool,

    /// Build a GTAGS database (via the `gtags` binary) for C/C++ repos that lack
    /// one, so index-time gtags augmentation has data. Writes GTAGS/GRTAGS/GPATH
    /// into the repo and is skipped on very large trees.
    #[arg(long, env = "NARSIL_GTAGS_GENERATE")]
    gtags_generate: bool,

    /// Enable streaming responses for large result sets
    #[arg(long, env = "NARSIL_STREAMING")]
    streaming: bool,

    /// Enable remote GitHub repository support (uses GITHUB_TOKEN env var for auth)
    #[arg(long, env = "NARSIL_REMOTE")]
    remote: bool,

    /// Enable neural embeddings for semantic search (requires EMBEDDING_API_KEY, VOYAGE_API_KEY, or OPENAI_API_KEY)
    #[arg(long, env = "NARSIL_NEURAL")]
    neural: bool,

    /// Neural embedding backend: "api" (default) or "onnx"
    #[arg(long, env = "NARSIL_NEURAL_BACKEND", default_value = "api")]
    neural_backend: String,

    /// Neural embedding model name (e.g., "voyage-code-2", "text-embedding-3-small")
    #[arg(long, env = "NARSIL_NEURAL_MODEL")]
    neural_model: Option<String>,

    /// Neural embedding dimension (auto-detected from model if not specified)
    #[arg(long, env = "NARSIL_NEURAL_DIMENSION")]
    neural_dimension: Option<usize>,

    /// Enable HTTP server for visualization frontend
    #[arg(long, env = "NARSIL_HTTP")]
    http: bool,

    /// HTTP server port (default: 3000)
    #[arg(long, env = "NARSIL_HTTP_PORT", default_value = "3000")]
    http_port: u16,

    /// MCP transport to expose: `stdio` (default) or `sse`.
    /// SSE binds an HTTP listener (see --sse-host / --sse-port) and lets
    /// multiple editor sessions share one persistent narsil-mcp process.
    #[arg(long, env = "NARSIL_TRANSPORT", value_enum, default_value = "stdio")]
    transport: Transport,

    /// Bind address for the SSE transport. Only loopback addresses are
    /// accepted today — exposing on a network requires a future
    /// --allow-remote flag plus authentication.
    /// Setting this flag implicitly selects --transport sse.
    #[arg(long, env = "NARSIL_SSE_HOST")]
    sse_host: Option<String>,

    /// TCP port for the SSE transport.
    /// Setting this flag implicitly selects --transport sse.
    #[arg(long, env = "NARSIL_SSE_PORT")]
    sse_port: Option<u16>,

    /// SSE keep-alive interval in seconds. Comments are emitted on the
    /// stream to keep proxies / NATs from dropping idle connections.
    #[arg(long, env = "NARSIL_SSE_KEEPALIVE_SECS", default_value = "15")]
    sse_keepalive_secs: u64,

    /// Tool preset (minimal, balanced, full, security-focused)
    /// Overrides the preset from config file
    #[arg(long, env = "NARSIL_PRESET")]
    preset: Option<String>,

    /// Expose only these tool groups in tools/list. Example: --expose code,git
    ///
    /// Comma-separated and composable; repo-addressing tools are always
    /// present. Empty falls back to --preset. Tool schemas are re-sent on
    /// every request, so an unused group costs context all session.
    ///
    ///   code          symbols, references, search, file text; call and
    ///                 import graphs; complexity, hotspots, cycles; CFG views
    ///   git           blame, history, commit diffs, branch state
    ///   analysis      complexity, hotspots, import graphs, cycles, per-
    ///                 function control and data flow -- derived from source
    ///                 you can already read, so off by default
    ///   lint          uninitialized reads, dead stores, dead code, type
    ///                 errors -- your compiler already reports these, with
    ///                 type information narsil does not have. Enable only
    ///                 where no compiler covers the source.
    ///   security      vulnerability scanning and taint tracking
    ///   supply-chain  SBOM, licences, dependency and upgrade checks
    ///   retrieval     chunk/embedding retrieval and similarity search
    #[arg(
        long,
        env = "NARSIL_EXPOSE",
        value_delimiter = ',',
        verbatim_doc_comment
    )]
    expose: Vec<String>,

    /// TF-IDF embedding dimension (default: 512).
    /// Lower values reduce memory usage; higher values improve find_similar_code accuracy.
    #[arg(long, env = "NARSIL_EMBEDDING_DIM")]
    embedding_dim: Option<usize>,

    /// Disable analysis caching (caching is enabled by default)
    #[arg(long, env = "NARSIL_NO_CACHE")]
    no_cache: bool,

    /// Cache TTL in seconds (default: 1800 = 30 minutes)
    #[arg(long, env = "NARSIL_CACHE_TTL", default_value = "1800")]
    cache_ttl: u64,

    /// Enable RDF knowledge graph storage for SPARQL queries and CCG export.
    /// NOTE: Binary must be built with --features graph for this to work.
    /// If unsure, check the startup log for warnings.
    #[arg(long, env = "NARSIL_GRAPH")]
    graph: bool,

    /// Path for knowledge graph storage (default: <index_path>/graph).
    /// Only used when --graph is enabled and the graph feature is compiled in.
    #[arg(long, env = "NARSIL_GRAPH_PATH")]
    graph_path: Option<PathBuf>,

    /// Use compile_commands.json to restrict which C/C++ source files are indexed.
    /// Headers are always indexed regardless.
    #[arg(long, env = "NARSIL_USE_COMPILE_COMMANDS")]
    use_compile_commands: bool,

    /// Path to compile_commands.json, relative to the repo root (default: compile_commands.json).
    #[arg(long, env = "NARSIL_COMPILE_COMMANDS_PATH")]
    compile_commands_path: Option<PathBuf>,

    /// Glob patterns (relative to repo root) for files to always index.
    /// Comma-separated (e.g. "tools/perf/**/*.c,scripts/**/*.py").
    #[arg(long, env = "NARSIL_INCLUDE", value_delimiter = ',')]
    include: Vec<String>,

    /// Paths that additionally get the clangd/ccls pass; a plain dir matches it
    /// and all subdirs, globs (*, **) are supported. Each entry is matched
    /// against both the repo-relative and the absolute path: a relative entry
    /// (e.g. "fs/fuse") applies in every repo that has it, while an absolute
    /// entry (e.g. "$HOME/src/linux.git/fs") scopes one repo precisely and never
    /// matches another — use absolute paths to scope a single repo in a
    /// multi-repo server. tree-sitter and gtags still cover every file. Within a
    /// repo where any file matches, only compile_commands.json TUs under these
    /// paths are queried via LSP. Comma-separated. Empty = whole repo (default).
    #[arg(long, env = "NARSIL_LSP_SCOPE", value_delimiter = ',')]
    lsp_scope: Vec<String>,

    /// Restrict the base (tree-sitter) index to these paths: in a repo with any
    /// matching file, only matching files (plus --include) are indexed at all —
    /// nothing else exists in narsil for that repo. Same matching as --lsp-scope
    /// (relative or absolute, recursive dirs, globs); use absolute paths to scope
    /// one repo in a multi-repo server. A repo with no match is indexed in full,
    /// so unrelated repos are untouched. Trade-off: out-of-scope files (incl.
    /// headers) are absent, so narsil's symbols/call graph won't resolve into
    /// them (a whole-repo GTAGS db still answers gtags reference queries).
    /// Comma-separated. Empty = whole repo (the default).
    #[arg(long, env = "NARSIL_INDEX_FILTER", value_delimiter = ',')]
    index_filter: Vec<String>,

    /// Per-repo overrides sourced from a `--profile` config entry. Not a CLI
    /// flag; populated by `apply_named_profile`.
    #[arg(skip)]
    repo_settings: Vec<config::schema::RepoEntrySettings>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle subcommands (config, tools)
    if let Some(command) = args.command {
        // For subcommands, we don't need logging to stderr
        return match command {
            Commands::Config(config_cmd) => config::handle_config_command(config_cmd).await,
            Commands::Tools(tools_cmd) => config::handle_tools_command(tools_cmd),
            Commands::Stats(stats_args) => stats_cli::handle_stats_command(stats_args),
        };
    }

    // Default: run MCP server
    let mut server_args = args.server;

    // Initialize logging to stderr (stdout is for MCP protocol)
    let level = if server_args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting narsil-mcp v{}", env!("CARGO_PKG_VERSION"));

    apply_named_profile(&mut server_args)?;

    // --sse-host / --sse-port are SSE-specific flags; passing either one
    // implicitly activates SSE transport so `narsil-mcp --sse-host localhost`
    // does the right thing without also requiring --transport sse.
    if matches!(server_args.transport, Transport::Stdio)
        && (server_args.sse_host.is_some() || server_args.sse_port.is_some())
    {
        info!(
            "--sse-host/--sse-port specified without --transport sse; \
             activating SSE transport implicitly"
        );
        server_args.transport = Transport::Sse;
    }

    // Resolve the final list of repository paths from CLI args, env, and
    // discovery. For stdio transport, fall back to cwd when nothing is
    // specified so bare `narsil-mcp` "just works" inside a project.
    // SSE transport requires explicit --repos to avoid silently indexing
    // whatever directory the server process was started in.
    let cwd_fallback = matches!(server_args.transport, Transport::Stdio);
    let repos = resolve_repo_paths(
        server_args.repos.clone(),
        server_args.discover.clone(),
        cwd_fallback,
    )?;

    info!("Repos to index: {:?}", repos);

    // Resolve before the discovery probe below: a typo must fail the process
    // whether or not this invocation ends up delegating.
    let expose = parse_expose_groups(&server_args.expose)?;

    // Stdio auto-discovery: if a long-running SSE narsil-mcp is already
    // indexing a superset of these repos, delegate to it and skip local
    // engine construction entirely. The probe is a single MCP `ping`;
    // anything that fails (no registry file, no matching repos, transport
    // error) falls through to the normal local-index path.
    if matches!(server_args.transport, Transport::Stdio) {
        // The discovery probe uses a blocking HTTP client whose own runtime is
        // dropped when the call returns; run it via spawn_blocking so that drop
        // does not happen inside this async context (which would panic).
        let probe_repos = repos.clone();
        let discovered =
            tokio::task::spawn_blocking(move || sse_discovery::find_server_for_repos(&probe_repos))
                .await
                .ok()
                .flatten();
        if let Some(proxy_url) = discovered {
            info!("SSE discovery: delegating stdio to {}", proxy_url);
            // The upstream daemon decides its own tool list; nothing on this
            // side can narrow it, so say so rather than appear to have applied it.
            if !expose.is_empty() {
                warn!(
                    "--expose is ignored when delegating to {}: the upstream server's \
                     own --expose/--preset decides the tool list",
                    proxy_url
                );
            }
            // Record this delegating process so `narsil-mcp stats` can show the
            // stdio→SSE link; the guard removes the file on a clean return.
            let _pid_status_entry = pid_status::write_status(&pid_status::PidStatus::new(
                "stdio",
                pid_status::ProcessRole::StdioProxy {
                    upstream_url: proxy_url.clone(),
                },
                &repos,
            ))
            .map_err(|e| warn!("pid status: could not write: {}", e))
            .ok();
            return stdio_proxy::run_stdio_proxy_with_shutdown(&proxy_url, &repos).await;
        }
        info!("SSE discovery: no matching server, building local index");
    }

    // Check if --graph flag is used but feature isn't compiled
    #[cfg(not(feature = "graph"))]
    if server_args.graph {
        warn!(
            "--graph flag was passed but the binary was built without the 'graph' feature. \
             SPARQL and CCG tools will not be available. \
             Rebuild with: cargo build --release --features graph"
        );
    }

    // Determine actual graph availability
    #[cfg(feature = "graph")]
    let graph_available = server_args.graph;
    #[cfg(not(feature = "graph"))]
    let graph_available = false;

    // gtags intent: --gtags forces on, --no-gtags forces off, else Auto
    // (auto-detect global(1)). The manager exists whenever intent ≠ Off and a
    // backend is available; per-repo gating happens in index_repo.
    let gtags_intent = if server_args.no_gtags {
        index::BackendIntent::Off
    } else if server_args.gtags {
        index::BackendIntent::On
    } else {
        index::BackendIntent::Auto
    };
    let gtags_enabled = match gtags_intent {
        index::BackendIntent::Off => false,
        index::BackendIntent::On => true,
        index::BackendIntent::Auto => narsil_mcp::gtags::gtags_available(),
    };

    // LSP intent: --lsp forces on, --no-lsp forces off, else Auto (enable when a
    // C/C++ language server is on PATH). Per-repo gating (compile_commands.json)
    // happens in index_repo.
    let lsp_intent = if server_args.no_lsp {
        index::BackendIntent::Off
    } else if server_args.lsp {
        index::BackendIntent::On
    } else {
        index::BackendIntent::Auto
    };

    info!(
        "Features: call_graph={}, git={}, watch={}, persist={}, lsp_intent={:?}, gtags={}, streaming={}, remote={}, neural={}, cache={}, graph={}",
        server_args.call_graph, server_args.git, server_args.watch, server_args.persist,
        lsp_intent, gtags_enabled, server_args.streaming, server_args.remote,
        server_args.neural, !server_args.no_cache, graph_available
    );

    // Build LSP config. Resolve C/C++ backends first so Auto can enable LSP when
    // a server is available.
    let mut lsp_config = lsp::LspConfig::default();
    let cxx_backends_auto = server_args
        .lsp_cxx_backends
        .trim()
        .eq_ignore_ascii_case("auto");
    let cxx_backends: Vec<CxxLspBackend> = if cxx_backends_auto {
        CxxLspBackend::detect_available()
    } else {
        server_args
            .lsp_cxx_backends
            .split(',')
            .filter_map(|s| match s.trim() {
                "clangd" => Some(CxxLspBackend::Clangd),
                "ccls" => Some(CxxLspBackend::Ccls),
                other => {
                    warn!(
                        "Unknown --lsp-cxx-backends value '{}'; ignoring (valid: clangd, ccls, auto)",
                        other
                    );
                    None
                }
            })
            .collect()
    };
    let lsp_enabled = match lsp_intent {
        index::BackendIntent::Off => false,
        index::BackendIntent::On => true,
        index::BackendIntent::Auto => !cxx_backends.is_empty(),
    };
    if lsp_enabled {
        lsp_config.enabled = true;
        lsp_config.index_timeout_ms = server_args.lsp_index_timeout_ms;
        // Enable LSP for common languages
        for lang in [
            "rust",
            "python",
            "typescript",
            "javascript",
            "go",
            "c",
            "cpp",
            "java",
        ] {
            lsp_config.enabled_languages.insert(lang.to_string(), true);
        }

        // "auto" adopts whatever was detected (possibly empty -> C/C++ LSP off);
        // an explicit list overrides only when it yields at least one backend.
        if cxx_backends_auto {
            if cxx_backends.is_empty() {
                warn!("No C/C++ LSP backend found on PATH (clangd, ccls); C/C++ LSP disabled");
            }
            lsp_config.cxx_lsp_backends = cxx_backends;
        } else if !cxx_backends.is_empty() {
            lsp_config.cxx_lsp_backends = cxx_backends;
        }

        info!(
            "LSP integration enabled for: {:?}; C/C++ backends: {:?}",
            lsp_config.enabled_languages.keys().collect::<Vec<_>>(),
            lsp_config
                .cxx_lsp_backends
                .iter()
                .map(|b| b.label())
                .collect::<Vec<_>>()
        );
    }

    // Build streaming config
    let streaming_config = streaming::StreamingConfig {
        enabled: server_args.streaming,
        ..Default::default()
    };
    if server_args.streaming {
        info!(
            "Streaming responses enabled (threshold: {} items)",
            streaming_config.auto_stream_threshold
        );
    }

    // Build neural config
    let neural_dimension = server_args.neural_dimension.unwrap_or_else(|| {
        neural::default_dimension_for_model(server_args.neural_model.as_deref())
    });
    let neural_config = neural::NeuralConfig {
        enabled: server_args.neural,
        backend: server_args.neural_backend.clone(),
        model_name: server_args.neural_model.clone(),
        dimension: neural_dimension,
        ..Default::default()
    };
    if server_args.neural {
        info!(
            "Neural embeddings requested (backend={}, model={:?}, dimension={})",
            server_args.neural_backend, server_args.neural_model, neural_dimension
        );
    }

    // Initialize the code intelligence engine with options
    let options = index::EngineOptions {
        git_enabled: server_args.git,
        call_graph_enabled: server_args.call_graph,
        persist_enabled: server_args.persist,
        watch_enabled: server_args.watch,
        remote_enabled: server_args.remote,
        streaming_config,
        lsp_config,
        neural_config,
        cache_enabled: !server_args.no_cache,
        cache_ttl_seconds: server_args.cache_ttl,
        embedding_dim: server_args.embedding_dim.unwrap_or(1000),
        use_compile_commands: server_args.use_compile_commands,
        compile_commands_path: server_args.compile_commands_path,
        include: server_args.include,
        lsp_scope: server_args.lsp_scope,
        index_filter: server_args.index_filter,
        repo_settings: server_args.repo_settings,
        gtags_enabled,
        lsp_intent,
        gtags_intent,
        gtags_generate: server_args.gtags_generate,
        #[cfg(feature = "graph")]
        graph_enabled: server_args.graph,
        #[cfg(feature = "graph")]
        graph_path: server_args.graph_path,
    };

    // NOTE: Engine creation is now fast and returns immediately.
    // Indexing happens in background to allow quick MCP server startup.
    let mut engine =
        index::CodeIntelEngine::with_options(server_args.index_path, repos.clone(), options)
            .await?;

    // Initialize remote repository support if enabled
    if server_args.remote {
        match engine.init_remote_manager() {
            Ok(()) => info!("Remote repository support enabled"),
            Err(e) => warn!("Failed to initialize remote repository support: {}", e),
        }
    }

    let engine = Arc::new(engine);

    // Publish this process's status so `narsil-mcp stats` (and a human
    // diagnosing the stdio↔SSE path) can see its role, URL, and repos. The
    // guard removes the file on a clean return; the background task below
    // refreshes it with real symbol counts once indexing finishes.
    let pid_status_role = match server_args.transport {
        Transport::Stdio => pid_status::ProcessRole::StdioLocal,
        Transport::Sse => {
            let host = server_args
                .sse_host
                .clone()
                .unwrap_or_else(|| "127.0.0.1".to_string());
            let port = server_args.sse_port.unwrap_or(7557);
            pid_status::ProcessRole::Sse {
                url: format_discovery_url(&host, port),
            }
        }
    };
    let pid_status_transport = match server_args.transport {
        Transport::Stdio => "stdio",
        Transport::Sse => "sse",
    };
    let base_pid_status = pid_status::PidStatus::new(pid_status_transport, pid_status_role, &repos);
    let _pid_status_entry = pid_status::write_status(&base_pid_status)
        .map_err(|e| warn!("pid status: could not write: {}", e))
        .ok();

    // Start background initialization task (indexing repos, git init)
    let init_engine = Arc::clone(&engine);
    let reindex_flag = server_args.reindex;
    let refresh_pid_status = base_pid_status.clone();
    tokio::spawn(async move {
        if reindex_flag {
            info!("Re-indexing all repositories...");
            if let Err(e) = init_engine.reindex_all().await {
                warn!("Error during re-indexing: {}", e);
            }
        } else {
            // Complete deferred initialization
            if let Err(e) = init_engine.complete_initialization().await {
                warn!("Error during background initialization: {}", e);
            }
        }
        // Rewrite the status with post-indexing symbol counts. update_status
        // overwrites in place so the main-scope guard still owns removal.
        let updated = refresh_pid_status.with_repo_counts(init_engine.repo_status_snapshot());
        if let Err(e) = pid_status::update_status(&updated) {
            warn!("pid status: could not refresh counts: {}", e);
        }
    });

    // Start watch mode in background if enabled.
    //
    // The returned `Sender` MUST live until `main` returns — dropping it
    // immediately makes the watcher loop see `Closed` on its first poll and
    // exit milliseconds after spawn (issue #26). Binding the value to
    // `_watch_shutdown_tx` here keeps it alive for the rest of `main`; the
    // tokio runtime tears the detached task down when `main` returns.
    let _watch_shutdown_tx = if server_args.watch {
        Some(persist::spawn_watch_mode(Arc::clone(&engine)))
    } else {
        None
    };

    // The chosen transport is raced against Ctrl-C (and SIGTERM on Unix)
    // so that, when the user terminates the process, we get a chance to
    // flush accumulated metrics to disk before exiting. Without this, the
    // periodic flush could miss the last few minutes of activity.
    let shutdown_engine = Arc::clone(&engine);

    let server_result = match server_args.transport {
        Transport::Stdio => {
            // Start HTTP server in background if enabled (visualization
            // frontend only); MCP runs on stdio for editor communication.
            if server_args.http {
                info!("Starting HTTP server on port {}", server_args.http_port);
                let http_engine = Arc::clone(&engine);
                let http_port = server_args.http_port;
                tokio::spawn(async move {
                    let http_server = http_server::HttpServer::new(http_engine, http_port);
                    if let Err(e) = http_server.run().await {
                        warn!("HTTP server error: {}", e);
                    }
                });
            }

            let server = mcp::McpServer::from_arc(Arc::clone(&engine), server_args.preset, expose);
            run_stdio_with_shutdown(server).await
        }
        Transport::Sse => {
            let sse_host = server_args
                .sse_host
                .unwrap_or_else(|| "127.0.0.1".to_string());
            let sse_port = server_args.sse_port.unwrap_or(7557);

            // Refuse non-loopback bind. A network-exposed MCP transport
            // without authentication would let any host on the LAN drive
            // tool calls and read source. Adding network exposure must go
            // through a future --allow-remote flag plus auth.
            if !is_loopback_bind_addr(&sse_host) {
                bail!(
                    "--sse-host {} is not a loopback address. Refusing to bind: \
                     the SSE transport has no authentication. Use 127.0.0.1, \
                     ::1, or localhost.",
                    sse_host
                );
            }
            if server_args.http {
                info!(
                    "--http is implicit when --transport sse is set; --http-port {} ignored, \
                     frontend routes are mounted on the SSE listener",
                    server_args.http_port
                );
            }
            let keepalive = Duration::from_secs(server_args.sse_keepalive_secs);
            let mcp_server = Arc::new(mcp::McpServer::from_arc(
                Arc::clone(&engine),
                server_args.preset,
                expose,
            ));
            info!(
                "Starting MCP SSE transport on http://{}:{}/mcp/sse",
                sse_host, sse_port
            );
            let http_server = http_server::HttpServer::new(Arc::clone(&engine), sse_port)
                .with_mcp_routes(mcp_server, sse_host.clone(), sse_port, keepalive);

            // Advertise this listener for stdio auto-discovery. The guard
            // is bound in match-arm scope so it drops (and removes the
            // entry) when the arm returns, whether normally or on error.
            let discovery_url = format_discovery_url(&sse_host, sse_port);
            let _discovery_entry = sse_discovery::register_server(&discovery_url, &repos)
                .map_err(|e| warn!("SSE discovery: could not register: {}", e))
                .ok();

            run_http_with_shutdown(http_server).await
        }
    };

    shutdown_engine.shutdown().await;

    server_result?;
    Ok(())
}

/// Format the canonical base URL for the SSE listener, suitable for
/// publishing in the discovery file. Wraps bare IPv6 addresses in
/// brackets so the result parses as a valid URL.
fn format_discovery_url(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("http://[{}]:{}", host, port)
    } else {
        format!("http://{}:{}", host, port)
    }
}

/// True if `host` names a loopback bind target. Network-facing binds
/// (e.g. `0.0.0.0`, LAN IPs) are explicitly rejected for the unauthenticated
/// SSE transport.
fn is_loopback_bind_addr(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

#[cfg(unix)]
async fn wait_for_terminate_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            term.recv().await;
        }
        Err(e) => {
            warn!("Failed to install SIGTERM handler: {}", e);
            // Park forever so the tokio::select! below doesn't pick this arm.
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_terminate_signal() {
    std::future::pending::<()>().await;
}

async fn run_stdio_with_shutdown(server: mcp::McpServer) -> Result<()> {
    tokio::select! {
        result = server.run() => result,
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl-C, shutting down");
            Ok(())
        }
        _ = wait_for_terminate_signal() => {
            info!("Received SIGTERM, shutting down");
            Ok(())
        }
    }
}

async fn run_http_with_shutdown(server: http_server::HttpServer) -> Result<()> {
    tokio::select! {
        result = server.run() => result,
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl-C, shutting down");
            Ok(())
        }
        _ = wait_for_terminate_signal() => {
            info!("Received SIGTERM, shutting down");
            Ok(())
        }
    }
}

/// Resolve `--expose` group names. Rejected here rather than by clap's value
/// parser so the error can name the valid groups; a typo must fail the process
/// instead of quietly exposing a different tool set.
fn parse_expose_groups(names: &[String]) -> Result<Vec<config::ExposeGroup>> {
    names
        .iter()
        .map(|name| {
            config::ExposeGroup::parse(name).ok_or_else(|| {
                let valid: Vec<&str> = config::ExposeGroup::ALL.iter().map(|g| g.name()).collect();
                anyhow::anyhow!(
                    "Unknown --expose group '{}'. Valid groups: {}",
                    name,
                    valid.join(", ")
                )
            })
        })
        .collect()
}

/// Apply a named repository profile from the loaded configuration.
///
/// Explicit CLI/env values remain authoritative. Profiles provide defaults for
/// repos, discovery, preset, and feature booleans.
fn apply_named_profile(server_args: &mut ServerArgs) -> Result<()> {
    let Some(profile_name) = server_args.profile.as_deref() else {
        return Ok(());
    };

    let config = config::ConfigLoader::new()
        .load()
        .context("Failed to load configuration for --profile")?;
    let profile = config.profiles.get(profile_name).ok_or_else(|| {
        let mut names: Vec<_> = config.profiles.keys().cloned().collect();
        names.sort();
        anyhow::anyhow!(
            "Unknown profile '{}'. Available profiles: {}",
            profile_name,
            if names.is_empty() {
                "<none>".to_string()
            } else {
                names.join(", ")
            }
        )
    })?;

    if server_args.repos.is_empty() {
        server_args.repos = profile
            .repos
            .iter()
            .map(|e| e.path().to_path_buf())
            .collect();
        // Carry per-repo overrides alongside the flat path list so the path code
        // below stays untouched; the engine keys these by canonical repo path.
        // Fold the profile-group backend defaults into each entry's unset fields.
        server_args.repo_settings = profile
            .repos
            .iter()
            .map(|e| {
                e.settings().with_group_defaults(
                    profile.clangd.as_ref(),
                    profile.ccls.as_ref(),
                    profile.gtags.as_ref(),
                )
            })
            .collect();
    }
    if server_args.discover.is_none() {
        server_args.discover = profile.discover.clone();
    }
    if server_args.preset.is_none() {
        server_args.preset = profile.preset.clone();
    }
    if server_args.expose.is_empty() {
        server_args.expose = profile.expose.clone();
    }

    apply_bool_default(&mut server_args.git, profile.git);
    apply_bool_default(&mut server_args.call_graph, profile.call_graph);
    apply_bool_default(&mut server_args.persist, profile.persist);
    apply_bool_default(&mut server_args.watch, profile.watch);
    apply_bool_default(&mut server_args.lsp, profile.lsp);
    apply_bool_default(&mut server_args.remote, profile.remote);
    apply_bool_default(&mut server_args.neural, profile.neural);
    apply_bool_default(&mut server_args.graph, profile.graph);
    if server_args.embedding_dim.is_none() {
        server_args.embedding_dim = profile.embedding_dim;
    }
    apply_bool_default(
        &mut server_args.use_compile_commands,
        profile.use_compile_commands,
    );
    if server_args.compile_commands_path.is_none() {
        server_args.compile_commands_path = profile.compile_commands_path.clone();
    }
    if server_args.include.is_empty() {
        server_args.include = profile.include.clone();
    }

    info!("Applied repository profile '{}'", profile_name);
    Ok(())
}

fn apply_bool_default(target: &mut bool, profile_value: Option<bool>) {
    if !*target {
        if let Some(value) = profile_value {
            *target = value;
        }
    }
}

/// Resolve the final set of repository paths to index from CLI input.
///
/// Order of operations:
/// 1. Start with `cli_repos` (populated from `--repos` or `NARSIL_REPOS`).
/// 2. If `discover` is set, walk that directory and append discovered repos.
/// 3. Expand `~`, relative paths, and symlinks into canonical absolute paths.
/// 4. If the list is still empty, default to `[cwd]` so a bare invocation
///    indexes the project the user is sitting in (issue #22).
/// 5. Drop paths that do not exist on disk, logging each at WARN. If all
///    explicit paths were invalid, return a clear error.
fn resolve_repo_paths(
    cli_repos: Vec<PathBuf>,
    discover: Option<PathBuf>,
    cwd_fallback: bool,
) -> Result<Vec<PathBuf>> {
    let mut repos = cli_repos;
    let had_explicit_input = !repos.is_empty() || discover.is_some();

    if let Some(discover_path) = discover {
        let discover_path = normalize_existing_path(&discover_path)
            .with_context(|| format!("Invalid --discover path: {}", discover_path.display()))?;
        info!("Discovering repositories in: {:?}", discover_path);
        let discovered = repo::discover_repos(&discover_path, 3)?;
        info!("Found {} repositories via discovery", discovered.len());
        repos.extend(discovered);
    }

    // Fall back to the current working directory when no repos are specified
    // anywhere — bare `narsil-mcp` should "just work" inside a project.
    // This fallback is intentionally disabled for SSE transport, where the
    // server is a persistent process not tied to any project directory.
    if repos.is_empty() {
        if !cwd_fallback {
            bail!(
                "No repositories specified. Pass --repos <path> (or set NARSIL_REPOS) \
                 to tell the SSE server which repositories to index."
            );
        }
        let cwd = std::env::current_dir().context(
            "--repos was not specified and the current working directory is unavailable",
        )?;
        info!(
            "No --repos / NARSIL_REPOS / --discover specified; defaulting to cwd: {:?}",
            cwd
        );
        repos.push(cwd);
    }

    let mut validated = Vec::new();
    for path in repos {
        match normalize_existing_path(&path) {
            Ok(path) => {
                if !validated.contains(&path) {
                    validated.push(path);
                }
            }
            Err(_) => warn!("Repository path does not exist, skipping: {:?}", path),
        }
    }

    if validated.is_empty() {
        if had_explicit_input {
            bail!("No valid repository paths remain after validation");
        }
        bail!("Current working directory could not be resolved as a repository path");
    }

    Ok(validated)
}

fn normalize_existing_path(path: &Path) -> Result<PathBuf> {
    let expanded = expand_tilde(path)?;
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir()?.join(expanded)
    };

    let canonical = absolute
        .canonicalize()
        .with_context(|| format!("Path does not exist: {}", path.display()))?;
    Ok(normalize_canonical_path(canonical))
}

fn normalize_canonical_path(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let path_str = path.to_string_lossy();
        if let Some(rest) = path_str.strip_prefix("\\\\?\\UNC\\") {
            return PathBuf::from(format!("\\\\{rest}"));
        }
        if let Some(rest) = path_str.strip_prefix("\\\\?\\") {
            return PathBuf::from(rest);
        }
    }

    path
}

fn expand_tilde(path: &Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    let Some(stripped) = path_str.strip_prefix('~') else {
        return Ok(path.to_path_buf());
    };

    let home = directories::BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .context("Cannot expand '~': home directory not found")?;
    if stripped.is_empty() {
        Ok(home)
    } else if let Some(rest) = stripped.strip_prefix('/') {
        Ok(home.join(rest))
    } else {
        Ok(path.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests that mutate `NARSIL_*` env vars share process-wide state and
    /// must run sequentially. Without this lock, parallel test execution
    /// races between `set_var` and `Args::try_parse_from`.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn parse_with_env<F: FnOnce()>(setup: F) -> Args {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Ensure no NARSIL_* leak in from outside the test:
        for var in [
            "NARSIL_REPOS",
            "NARSIL_PROFILE",
            "NARSIL_CONFIG_PATH",
            "NARSIL_INDEX_PATH",
            "NARSIL_VERBOSE",
            "NARSIL_REINDEX",
            "NARSIL_WATCH",
            "NARSIL_CALL_GRAPH",
            "NARSIL_GIT",
            "NARSIL_DISCOVER",
            "NARSIL_PERSIST",
            "NARSIL_LSP",
            "NARSIL_LSP_CXX_BACKENDS",
            "NARSIL_GTAGS",
            "NARSIL_STREAMING",
            "NARSIL_REMOTE",
            "NARSIL_NEURAL",
            "NARSIL_NEURAL_BACKEND",
            "NARSIL_NEURAL_MODEL",
            "NARSIL_NEURAL_DIMENSION",
            "NARSIL_HTTP",
            "NARSIL_HTTP_PORT",
            "NARSIL_PRESET",
            "NARSIL_NO_CACHE",
            "NARSIL_CACHE_TTL",
            "NARSIL_GRAPH",
            "NARSIL_GRAPH_PATH",
        ] {
            std::env::remove_var(var);
        }
        setup();
        Args::try_parse_from(["narsil-mcp"]).expect("CLI parse should succeed")
    }

    #[test]
    fn neural_model_is_settable_via_env() {
        let args = parse_with_env(|| {
            std::env::set_var("NARSIL_NEURAL_MODEL", "voyage-code-2");
        });
        std::env::remove_var("NARSIL_NEURAL_MODEL");
        assert_eq!(args.server.neural_model.as_deref(), Some("voyage-code-2"));
    }

    #[test]
    fn neural_dimension_is_settable_via_env() {
        let args = parse_with_env(|| {
            std::env::set_var("NARSIL_NEURAL_DIMENSION", "1024");
        });
        std::env::remove_var("NARSIL_NEURAL_DIMENSION");
        assert_eq!(args.server.neural_dimension, Some(1024));
    }

    #[test]
    fn boolean_flags_are_settable_via_env() {
        let args = parse_with_env(|| {
            std::env::set_var("NARSIL_GIT", "true");
            std::env::set_var("NARSIL_CALL_GRAPH", "true");
            std::env::set_var("NARSIL_REMOTE", "true");
            std::env::set_var("NARSIL_NEURAL", "true");
        });
        for var in [
            "NARSIL_GIT",
            "NARSIL_CALL_GRAPH",
            "NARSIL_REMOTE",
            "NARSIL_NEURAL",
        ] {
            std::env::remove_var(var);
        }
        assert!(args.server.git);
        assert!(args.server.call_graph);
        assert!(args.server.remote);
        assert!(args.server.neural);
    }

    #[test]
    fn repos_are_settable_via_env_comma_separated() {
        let args = parse_with_env(|| {
            std::env::set_var("NARSIL_REPOS", "/tmp/a,/tmp/b,/tmp/c");
        });
        std::env::remove_var("NARSIL_REPOS");
        assert_eq!(
            args.server.repos,
            vec![
                PathBuf::from("/tmp/a"),
                PathBuf::from("/tmp/b"),
                PathBuf::from("/tmp/c"),
            ]
        );
    }

    #[test]
    fn http_port_is_settable_via_env() {
        let args = parse_with_env(|| {
            std::env::set_var("NARSIL_HTTP_PORT", "4444");
        });
        std::env::remove_var("NARSIL_HTTP_PORT");
        assert_eq!(args.server.http_port, 4444);
    }

    #[test]
    fn profile_and_reindex_are_settable_via_env() {
        let args = parse_with_env(|| {
            std::env::set_var("NARSIL_PROFILE", "work");
            std::env::set_var("NARSIL_REINDEX", "true");
        });
        std::env::remove_var("NARSIL_PROFILE");
        std::env::remove_var("NARSIL_REINDEX");
        assert_eq!(args.server.profile.as_deref(), Some("work"));
        assert!(args.server.reindex);
    }

    #[test]
    fn cli_args_override_env_vars() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NARSIL_NEURAL_MODEL", "from-env");
        let args = Args::try_parse_from(["narsil-mcp", "--neural-model", "from-cli"]).unwrap();
        std::env::remove_var("NARSIL_NEURAL_MODEL");
        assert_eq!(args.server.neural_model.as_deref(), Some("from-cli"));
    }

    #[test]
    fn resolve_repo_paths_falls_back_to_cwd_when_empty() {
        let resolved = resolve_repo_paths(vec![], None, true).unwrap();
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(resolved, vec![cwd]);
    }

    #[test]
    fn resolve_repo_paths_no_cwd_fallback_errors_when_empty() {
        let err = resolve_repo_paths(vec![], None, false).unwrap_err();
        assert!(err.to_string().contains("No repositories specified"));
    }

    #[test]
    fn resolve_repo_paths_filters_missing_paths() {
        let cwd = std::env::current_dir().unwrap();
        let nonexistent = PathBuf::from("/this/path/definitely/does/not/exist/narsil-test-zzz");
        assert!(!nonexistent.exists());

        let resolved = resolve_repo_paths(vec![cwd.clone(), nonexistent], None, false).unwrap();
        // The missing path is dropped; the existing one survives.
        assert_eq!(resolved, vec![cwd]);
    }

    #[test]
    fn resolve_repo_paths_errors_when_all_explicit_paths_are_missing() {
        let nonexistent = PathBuf::from("/this/path/definitely/does/not/exist/narsil-test-zzz");
        let err = resolve_repo_paths(vec![nonexistent], None, false).unwrap_err();
        assert!(err.to_string().contains("No valid repository paths"));
    }

    #[test]
    fn resolve_repo_paths_expands_dot_to_cwd() {
        let resolved = resolve_repo_paths(vec![PathBuf::from(".")], None, false).unwrap();
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(resolved, vec![cwd]);
    }

    #[test]
    fn resolve_repo_paths_keeps_explicit_paths() {
        let cwd = std::env::current_dir().unwrap();
        let resolved = resolve_repo_paths(vec![cwd.clone()], None, false).unwrap();
        assert_eq!(resolved, vec![cwd]);
    }

    #[test]
    fn named_profile_supplies_repos_and_flags() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            format!(
                r#"version: "1.0"
profiles:
  work:
    repos:
      - {}
    git: true
    call_graph: true
    preset: balanced
"#,
                repo.display()
            ),
        )
        .unwrap();

        std::env::set_var("NARSIL_CONFIG_PATH", &config_path);
        let mut args = Args::try_parse_from(["narsil-mcp", "--profile", "work"]).unwrap();
        apply_named_profile(&mut args.server).unwrap();
        std::env::remove_var("NARSIL_CONFIG_PATH");

        assert_eq!(args.server.repos, vec![repo]);
        assert!(args.server.git);
        assert!(args.server.call_graph);
        assert_eq!(args.server.preset.as_deref(), Some("balanced"));
    }
}
