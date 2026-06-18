//! LSP integration for enhanced code intelligence
//!
//! This module provides integration with Language Server Protocol servers for
//! richer type information, hover docs, and go-to-definition capabilities.

use crate::symbols::{SourceSet, Symbol, SymbolKind as NarsilSymbolKind};
use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use lsp_types::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// C/C++ LSP backend selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CxxLspBackend {
    Clangd,
    Ccls,
}

impl CxxLspBackend {
    /// Short label used in server map keys and output strings.
    pub fn label(self) -> &'static str {
        match self {
            CxxLspBackend::Clangd => "clangd",
            CxxLspBackend::Ccls => "ccls",
        }
    }

    /// Backends whose binary is installed on `$PATH`, in preference order
    /// (clangd before ccls). Empty when neither is found.
    pub fn detect_available() -> Vec<CxxLspBackend> {
        [
            (CxxLspBackend::Clangd, "clangd"),
            (CxxLspBackend::Ccls, "ccls"),
        ]
        .into_iter()
        .filter(|(_, binary)| crate::validation::binary_on_path(binary))
        .map(|(backend, _)| backend)
        .collect()
    }
}

/// Configuration for LSP integration
#[derive(Debug, Clone)]
pub struct LspConfig {
    /// Enable/disable LSP per language
    pub enabled_languages: HashMap<String, bool>,
    /// Custom LSP server paths
    pub server_paths: HashMap<String, PathBuf>,
    /// Request timeout in milliseconds (interactive requests)
    pub timeout_ms: u64,
    /// Request timeout for the index-time documentSymbol augment. clangd/ccls
    /// must parse a translation unit on first open, which for a large C/C++
    /// file far exceeds the interactive bound; this batch step can afford to
    /// wait.
    pub index_timeout_ms: u64,
    /// Enable LSP globally
    pub enabled: bool,
    /// Which C/C++ LSP backends to start (defaults to clangd only)
    pub cxx_lsp_backends: Vec<CxxLspBackend>,
}

impl Default for LspConfig {
    fn default() -> Self {
        Self {
            enabled_languages: HashMap::new(),
            server_paths: HashMap::new(),
            // Phase B1: Reduced from 5000ms to 1500ms for better responsiveness
            // LSP requests that don't complete within 1.5s are unlikely to complete usefully
            timeout_ms: 1500,
            index_timeout_ms: 60000,
            enabled: false,
            cxx_lsp_backends: vec![CxxLspBackend::Clangd],
        }
    }
}

/// LSP JSON-RPC message
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LspMessage {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<LspError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LspError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

/// A running LSP server process
struct LspProcess {
    _child: Child,
    stdin: Arc<Mutex<ChildStdin>>,
    pending_requests: Arc<DashMap<i64, tokio::sync::oneshot::Sender<Result<Value, LspError>>>>,
    next_id: Arc<AtomicI64>,
    capabilities: Arc<RwLock<Option<ServerCapabilities>>>,
}

/// Manager for LSP clients per language
pub struct LspManager {
    config: LspConfig,
    servers: DashMap<String, Arc<LspProcess>>,
    workspace_roots: Vec<PathBuf>,
}

impl LspManager {
    /// Create a new LSP manager
    pub fn new(config: LspConfig, workspace_roots: Vec<PathBuf>) -> Self {
        Self {
            config,
            servers: DashMap::new(),
            workspace_roots,
        }
    }

    /// Check if LSP is globally enabled
    ///
    /// Phase B2: Callers can use this to avoid async overhead when LSP is disabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if LSP is enabled for a language
    pub fn is_enabled_for_language(&self, language: &str) -> bool {
        if !self.config.enabled {
            return false;
        }
        self.config
            .enabled_languages
            .get(language)
            .copied()
            .unwrap_or(false)
    }

    /// DashMap key for a C/C++ server entry: `"<lang>:<backend>"`.
    /// Non-C/C++ languages use just the language name.
    fn server_key(language: &str, backend: CxxLspBackend) -> String {
        format!("{}:{}", language, backend.label())
    }

    /// Key to look up the primary (first-configured) server for `language`.
    fn primary_server_key(&self, language: &str) -> String {
        if matches!(language, "c" | "cpp") {
            let backend = self
                .config
                .cxx_lsp_backends
                .first()
                .copied()
                .unwrap_or(CxxLspBackend::Clangd);
            Self::server_key(language, backend)
        } else {
            language.to_string()
        }
    }

    /// Get or start the primary server for `language`.
    async fn get_or_start_server(&self, language: &str) -> Result<Arc<LspProcess>> {
        let key = self.primary_server_key(language);
        self.get_or_start_server_for_key(&key).await
    }

    /// Get or start the server identified by `key`.
    async fn get_or_start_server_for_key(&self, key: &str) -> Result<Arc<LspProcess>> {
        if let Some(server) = self.servers.get(key) {
            return Ok(server.clone());
        }
        let server = self.start_server(key).await?;
        let server_arc = Arc::new(server);
        self.servers.insert(key.to_string(), server_arc.clone());
        Ok(server_arc)
    }

    /// Start an LSP server process for `server_key`.
    /// For C/C++ the key is `"<lang>:<backend>"`; for other languages it is just the language.
    async fn start_server(&self, server_key: &str) -> Result<LspProcess> {
        let language = server_key.split(':').next().unwrap_or(server_key);
        let (command, args) = self.get_server_command_for_key(server_key)?;

        info!(
            "Starting LSP server for {}: {} {:?}",
            server_key,
            command.display(),
            args
        );

        let mut child = tokio::process::Command::new(command.as_os_str())
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn LSP server")?;

        let stdin = child.stdin.take().ok_or_else(|| anyhow!("No stdin"))?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("No stdout"))?;

        let pending_requests = Arc::new(DashMap::new());
        let next_id = Arc::new(AtomicI64::new(1));
        let capabilities = Arc::new(RwLock::new(None));

        // Spawn response handler task
        let pending_clone = pending_requests.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::handle_responses(stdout, pending_clone).await {
                warn!("LSP response handler error: {}", e);
            }
        });

        let process = LspProcess {
            _child: child,
            stdin: Arc::new(Mutex::new(stdin)),
            pending_requests,
            next_id,
            capabilities,
        };

        // Initialize the server (use the language part of the key for LSP protocol)
        self.initialize_server(&process, language).await?;

        Ok(process)
    }

    /// Handle responses from LSP server
    async fn handle_responses(
        stdout: ChildStdout,
        pending_requests: Arc<DashMap<i64, tokio::sync::oneshot::Sender<Result<Value, LspError>>>>,
    ) -> Result<()> {
        let mut reader = BufReader::new(stdout);
        let mut content_length = 0;

        loop {
            let mut header_line = String::new();
            reader.read_line(&mut header_line).await?;

            if header_line.is_empty() {
                break;
            }

            let header_line = header_line.trim();

            if header_line.starts_with("Content-Length:") {
                content_length = header_line
                    .strip_prefix("Content-Length:")
                    .unwrap()
                    .trim()
                    .parse::<usize>()?;
            } else if header_line.is_empty() && content_length > 0 {
                // Read the JSON content
                let mut buffer = vec![0u8; content_length];
                tokio::io::AsyncReadExt::read_exact(&mut reader, &mut buffer).await?;

                let message: LspMessage = serde_json::from_slice(&buffer)?;
                debug!("Received LSP message: {:?}", message);

                // Handle response
                if let Some(id) = message.id {
                    if let Some((_, tx)) = pending_requests.remove(&id) {
                        if let Some(error) = message.error {
                            let _ = tx.send(Err(error));
                        } else {
                            // No error => a result is present; a null result is a
                            // valid "no data" answer that callers handle.
                            let _ = tx.send(Ok(message.result.unwrap_or(Value::Null)));
                        }
                    }
                }

                content_length = 0;
            }
        }

        Ok(())
    }

    /// Send a request to the LSP server
    async fn send_request(
        &self,
        process: &LspProcess,
        method: &str,
        params: Value,
    ) -> Result<Value> {
        self.send_request_with_timeout(process, method, params, self.config.timeout_ms)
            .await
    }

    /// Like `send_request` but with an explicit timeout, for the index-time
    /// documentSymbol augment whose first-open TU parse far exceeds the
    /// interactive bound.
    async fn send_request_with_timeout(
        &self,
        process: &LspProcess,
        method: &str,
        params: Value,
        timeout_ms: u64,
    ) -> Result<Value> {
        let id = process.next_id.fetch_add(1, Ordering::SeqCst);

        let message = LspMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(id),
            method: Some(method.to_string()),
            params: Some(params),
            result: None,
            error: None,
        };

        let json = serde_json::to_string(&message)?;
        let content = format!("Content-Length: {}\r\n\r\n{}", json.len(), json);

        let (tx, rx) = tokio::sync::oneshot::channel();
        process.pending_requests.insert(id, tx);

        // Send request
        {
            let mut stdin = process.stdin.lock().await;
            stdin.write_all(content.as_bytes()).await?;
            stdin.flush().await?;
        }

        // Wait for response with timeout
        let response = timeout(Duration::from_millis(timeout_ms), rx)
            .await
            .context("LSP request timeout")?
            .context("Response channel closed")?
            .map_err(|e| anyhow!("LSP error {}: {}", e.code, e.message))?;

        Ok(response)
    }

    /// Send a notification (no response expected) to the LSP server.
    async fn send_notification(
        &self,
        process: &LspProcess,
        method: &str,
        params: Value,
    ) -> Result<()> {
        let message = LspMessage {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: Some(method.to_string()),
            // exit carries no params; a null value is dropped from the wire so
            // the framing matches a parameterless notification.
            params: if params.is_null() { None } else { Some(params) },
            result: None,
            error: None,
        };

        let json = serde_json::to_string(&message)?;
        let content = format!("Content-Length: {}\r\n\r\n{}", json.len(), json);

        let mut stdin = process.stdin.lock().await;
        stdin.write_all(content.as_bytes()).await?;
        stdin.flush().await?;
        Ok(())
    }

    /// Send a notification without borrowing `self` — accepts an `Arc<LspProcess>`
    /// so callers can move it into a `JoinSet` task.
    async fn do_send_notification(
        process: Arc<LspProcess>,
        method: &'static str,
        params: Value,
    ) -> Result<()> {
        let message = LspMessage {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: Some(method.to_string()),
            params: if params.is_null() { None } else { Some(params) },
            result: None,
            error: None,
        };
        let json = serde_json::to_string(&message)?;
        let content = format!("Content-Length: {}\r\n\r\n{}", json.len(), json);
        let mut stdin = process.stdin.lock().await;
        stdin.write_all(content.as_bytes()).await?;
        stdin.flush().await?;
        Ok(())
    }

    /// Send a request without borrowing `self`.
    async fn do_send_request(
        process: Arc<LspProcess>,
        timeout_ms: u64,
        method: &'static str,
        params: Value,
    ) -> Result<Value> {
        let id = process.next_id.fetch_add(1, Ordering::SeqCst);
        let message = LspMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(id),
            method: Some(method.to_string()),
            params: Some(params),
            result: None,
            error: None,
        };
        let json = serde_json::to_string(&message)?;
        let content = format!("Content-Length: {}\r\n\r\n{}", json.len(), json);

        let (tx, rx) = tokio::sync::oneshot::channel();
        process.pending_requests.insert(id, tx);

        {
            let mut stdin = process.stdin.lock().await;
            stdin.write_all(content.as_bytes()).await?;
            stdin.flush().await?;
        }

        let response = timeout(Duration::from_millis(timeout_ms), rx)
            .await
            .context("LSP request timeout")?
            .context("Response channel closed")?
            .map_err(|e| anyhow!("LSP error {}: {}", e.code, e.message))?;

        Ok(response)
    }

    /// Query a single LSP process for references. Takes owned values so it
    /// can be dispatched inside a `tokio::task::JoinSet` task.
    async fn query_references_on_process(
        process: Arc<LspProcess>,
        timeout_ms: u64,
        language: String,
        file_path: PathBuf,
        line: u32,
        character: u32,
        include_declaration: bool,
    ) -> Result<Option<Vec<Location>>> {
        let uri = Url::from_file_path(&file_path).map_err(|_| anyhow!("Invalid file path"))?;
        let text = std::fs::read_to_string(&file_path)?;

        Self::do_send_notification(
            Arc::clone(&process),
            "textDocument/didOpen",
            serde_json::json!({
                "textDocument": {
                    "uri": &uri,
                    "languageId": language,
                    "version": 1,
                    "text": text,
                }
            }),
        )
        .await
        .ok();

        let params = ReferenceParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position { line, character },
            },
            context: ReferenceContext {
                include_declaration,
            },
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        };
        let params_value = serde_json::to_value(&params)?;

        let response = Self::do_send_request(
            Arc::clone(&process),
            timeout_ms,
            "textDocument/references",
            params_value,
        )
        .await;

        Self::do_send_notification(
            Arc::clone(&process),
            "textDocument/didClose",
            serde_json::json!({ "textDocument": {
                "uri": Url::from_file_path(&file_path).unwrap()
            }}),
        )
        .await
        .ok();

        let response = response?;
        if response.is_null() {
            return Ok(None);
        }
        let locations: Vec<Location> = serde_json::from_value(response)?;
        Ok(Some(locations))
    }

    /// Query all configured backends for `language` in parallel and return per-backend results.
    ///
    /// For C/C++, fans out across all configured backends (clangd, ccls). For all
    /// other languages, queries the single configured server. Returns a map from
    /// backend label to the locations that backend found; backends that fail or
    /// return nothing are omitted.
    pub async fn find_references_parallel(
        &self,
        language: &str,
        file_path: &Path,
        line: u32,
        character: u32,
        include_declaration: bool,
    ) -> HashMap<String, Vec<Location>> {
        let timeout_ms = self.config.timeout_ms;
        let file_path_buf = file_path.to_path_buf();
        let language_owned = language.to_string();

        let mut servers: Vec<(String, Arc<LspProcess>)> = Vec::new();
        if matches!(language, "c" | "cpp") {
            for &backend in &self.config.cxx_lsp_backends {
                let key = Self::server_key(language, backend);
                match self.get_or_start_server_for_key(&key).await {
                    Ok(s) => servers.push((backend.label().to_string(), s)),
                    Err(e) => debug!(
                        "Could not start {} for {}: {}",
                        backend.label(),
                        language,
                        e
                    ),
                }
            }
        } else {
            match self.get_or_start_server(language).await {
                Ok(s) => servers.push((language.to_string(), s)),
                Err(e) => debug!("Could not start LSP server for {}: {}", language, e),
            }
        }

        let mut set = tokio::task::JoinSet::new();
        for (label, server) in servers {
            let fp = file_path_buf.clone();
            let lang = language_owned.clone();
            set.spawn(async move {
                let result = Self::query_references_on_process(
                    server,
                    timeout_ms,
                    lang,
                    fp,
                    line,
                    character,
                    include_declaration,
                )
                .await;
                (label, result)
            });
        }

        let mut results = HashMap::new();
        while let Some(task_result) = set.join_next().await {
            if let Ok((label, Ok(Some(locations)))) = task_result {
                results.insert(label, locations);
            }
        }
        results
    }

    /// Open `file_path` so the server can resolve positions within it.
    ///
    /// Uses on-disk content because narsil indexes saved state — editor
    /// buffers are irrelevant. clangd answers textDocument/* only for open
    /// documents, so this must precede any position query.
    async fn did_open(&self, process: &LspProcess, language: &str, file_path: &Path) -> Result<()> {
        let uri = Url::from_file_path(file_path).map_err(|_| anyhow!("Invalid file path"))?;
        let text = std::fs::read_to_string(file_path)?;
        self.send_notification(
            process,
            "textDocument/didOpen",
            serde_json::json!({
                "textDocument": {
                    "uri": uri,
                    "languageId": language,
                    "version": 1,
                    "text": text,
                }
            }),
        )
        .await
    }

    /// Close a document previously opened with `did_open`.
    async fn did_close(&self, process: &LspProcess, file_path: &Path) -> Result<()> {
        let uri = Url::from_file_path(file_path).map_err(|_| anyhow!("Invalid file path"))?;
        self.send_notification(
            process,
            "textDocument/didClose",
            serde_json::json!({ "textDocument": { "uri": uri } }),
        )
        .await
    }

    /// Initialize the LSP server
    async fn initialize_server(&self, process: &LspProcess, language: &str) -> Result<()> {
        let workspace_root = self
            .workspace_roots
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("."));

        let workspace_folder = WorkspaceFolder {
            uri: Url::from_file_path(&workspace_root).unwrap(),
            name: workspace_root
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("workspace")
                .to_string(),
        };

        // root_uri is deprecated in the LSP spec, but ccls rejects initialize
        // without it (-32600 "expected rootUri"). Set it from the workspace
        // root; clangd and the other servers accept it too.
        #[allow(deprecated)]
        let init_params = InitializeParams {
            process_id: Some(std::process::id()),
            root_uri: Some(Url::from_file_path(&workspace_root).unwrap()),
            // Advertise hierarchical document symbols, else clangd/ccls reply with
            // the legacy flat SymbolInformation[] that document_symbols_raw drops.
            capabilities: ClientCapabilities {
                text_document: Some(TextDocumentClientCapabilities {
                    document_symbol: Some(DocumentSymbolClientCapabilities {
                        hierarchical_document_symbol_support: Some(true),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            trace: Some(TraceValue::Off),
            workspace_folders: Some(vec![workspace_folder]),
            client_info: Some(ClientInfo {
                name: "narsil-mcp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
            ..Default::default()
        };

        let params_value = serde_json::to_value(&init_params)?;
        let response = self
            .send_request(process, "initialize", params_value)
            .await?;

        let init_result: InitializeResult = serde_json::from_value(response)?;
        *process.capabilities.write().await = Some(init_result.capabilities);

        info!("LSP server initialized for {}", language);

        // Send initialized notification
        self.send_notification(process, "initialized", serde_json::json!({}))
            .await?;

        Ok(())
    }

    /// Get the command and args to start the server identified by `server_key`.
    /// For C/C++ the key is `"<lang>:<backend>"`; for other languages it is the language name.
    fn get_server_command_for_key(&self, server_key: &str) -> Result<(PathBuf, Vec<String>)> {
        // Custom path lookup uses the language part of the key
        let language = server_key.split(':').next().unwrap_or(server_key);
        if let Some(path) = self.config.server_paths.get(language) {
            let path_str = path.to_string_lossy().to_string();
            crate::validation::validate_lsp_server_path(&path_str)
                .map_err(|e| anyhow!("Invalid LSP server path for {}: {}", language, e))?;
            return Ok((path.clone(), vec![]));
        }

        match server_key {
            "rust" => Ok((PathBuf::from("rust-analyzer"), vec![])),
            "python" => Ok((
                PathBuf::from("pyright-langserver"),
                vec!["--stdio".to_string()],
            )),
            "javascript" | "typescript" => Ok((
                PathBuf::from("typescript-language-server"),
                vec!["--stdio".to_string()],
            )),
            "go" => Ok((PathBuf::from("gopls"), vec![])),
            "c:clangd" | "cpp:clangd" => Ok((PathBuf::from("clangd"), vec![])),
            "c:ccls" | "cpp:ccls" => Ok((PathBuf::from("ccls"), vec![])),
            "java" => Ok((
                PathBuf::from("jdtls"),
                vec!["-data".to_string(), "/tmp/jdtls-workspace".to_string()],
            )),
            _ => Err(anyhow!("No LSP server configured for {}", server_key)),
        }
    }

    /// Get hover information
    pub async fn get_hover(
        &self,
        language: &str,
        file_path: &Path,
        line: u32,
        character: u32,
    ) -> Result<Option<Hover>> {
        if !self.is_enabled_for_language(language) {
            return Ok(None);
        }

        let server = match self.get_or_start_server(language).await {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to start LSP server for {}: {}", language, e);
                return Ok(None);
            }
        };

        let uri = Url::from_file_path(file_path).map_err(|_| anyhow!("Invalid file path"))?;

        let params = HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position { line, character },
            },
            work_done_progress_params: WorkDoneProgressParams::default(),
        };

        let params_value = serde_json::to_value(&params)?;
        self.did_open(&server, language, file_path).await.ok();
        let result = self
            .send_request(&server, "textDocument/hover", params_value)
            .await;
        self.did_close(&server, file_path).await.ok();
        let response = result?;

        if response.is_null() {
            return Ok(None);
        }

        let hover: Hover = serde_json::from_value(response)?;
        Ok(Some(hover))
    }

    /// Get definition location
    pub async fn get_definition(
        &self,
        language: &str,
        file_path: &Path,
        line: u32,
        character: u32,
    ) -> Result<Option<Vec<Location>>> {
        if !self.is_enabled_for_language(language) {
            return Ok(None);
        }

        let server = match self.get_or_start_server(language).await {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to start LSP server for {}: {}", language, e);
                return Ok(None);
            }
        };

        let uri = Url::from_file_path(file_path).map_err(|_| anyhow!("Invalid file path"))?;

        let params = GotoDefinitionParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position { line, character },
            },
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        };

        let params_value = serde_json::to_value(&params)?;
        self.did_open(&server, language, file_path).await.ok();
        let response = self
            .send_request(&server, "textDocument/definition", params_value)
            .await;
        self.did_close(&server, file_path).await.ok();
        let response = response?;

        if response.is_null() {
            return Ok(None);
        }

        let result: GotoDefinitionResponse = serde_json::from_value(response)?;

        let locations = match result {
            GotoDefinitionResponse::Scalar(loc) => vec![loc],
            GotoDefinitionResponse::Array(locs) => locs,
            GotoDefinitionResponse::Link(_) => return Ok(None),
        };

        Ok(Some(locations))
    }

    /// Single-bit `SourceSet` for each configured C/C++ LSP backend
    /// (`SourceSet::CLANGD` and/or `SourceSet::CCLS`). Empty when LSP is
    /// disabled. Drives the per-backend documentSymbol (Phase 2) and
    /// callHierarchy (Phase 5) index passes; results from each are merged, not
    /// stored separately.
    pub fn active_cxx_backends(&self) -> Vec<SourceSet> {
        if !self.config.enabled {
            return Vec::new();
        }
        self.config
            .cxx_lsp_backends
            .iter()
            .map(|backend| match backend {
                CxxLspBackend::Clangd => SourceSet::CLANGD,
                CxxLspBackend::Ccls => SourceSet::CCLS,
            })
            .collect()
    }

    /// Map a single-bit C/C++ `SourceSet` back to its `CxxLspBackend`.
    fn cxx_backend_for_source(source: SourceSet) -> Option<CxxLspBackend> {
        if source == SourceSet::CLANGD {
            Some(CxxLspBackend::Clangd)
        } else if source == SourceSet::CCLS {
            Some(CxxLspBackend::Ccls)
        } else {
            None
        }
    }

    /// documentSymbol against the server identified by `server_key`, returning
    /// the raw nested LSP symbols (or `None` when the server is unavailable,
    /// returns nothing, or returns the deprecated flat shape).
    async fn document_symbols_raw(
        &self,
        server_key: &str,
        language: &str,
        file_path: &Path,
    ) -> Result<Option<Vec<DocumentSymbol>>> {
        let server = match self.get_or_start_server_for_key(server_key).await {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to start LSP server {}: {}", server_key, e);
                return Ok(None);
            }
        };

        let uri = Url::from_file_path(file_path).map_err(|_| anyhow!("Invalid file path"))?;

        let params = DocumentSymbolParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        };

        let params_value = serde_json::to_value(&params)?;
        self.did_open(&server, language, file_path).await.ok();
        let response = self
            .send_request_with_timeout(
                &server,
                "textDocument/documentSymbol",
                params_value,
                self.config.index_timeout_ms,
            )
            .await;
        self.did_close(&server, file_path).await.ok();
        let response = response?;

        if response.is_null() {
            return Ok(None);
        }

        let result: DocumentSymbolResponse = serde_json::from_value(response)?;

        match result {
            DocumentSymbolResponse::Flat(_) => Ok(None),
            DocumentSymbolResponse::Nested(symbols) => Ok(Some(symbols)),
        }
    }

    /// documentSymbol against one C/C++ `backend`, flattened into narsil
    /// `Symbol`s tagged with that backend's `confirmed_by` bit. Nested members
    /// (methods inside a class) become separate symbols. `start_line` is the
    /// name-token row (selectionRange) to match the dedup convention; the
    /// returned symbols carry an empty `file_path` — the caller assigns the
    /// repo-relative path.
    pub async fn get_document_symbols(
        &self,
        backend: SourceSet,
        file_path: &Path,
        language: &str,
    ) -> Result<Vec<Symbol>> {
        let cxx = match Self::cxx_backend_for_source(backend) {
            Some(b) => b,
            None => return Ok(Vec::new()),
        };
        let server_key = Self::server_key(language, cxx);
        let nested = match self
            .document_symbols_raw(&server_key, language, file_path)
            .await?
        {
            Some(n) => n,
            None => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        flatten_document_symbols(&nested, backend, &mut out);
        Ok(out)
    }

    /// Prepare a `CallHierarchyItem` for `symbol_name` (anchored on its name
    /// token at/after the 1-based `line`) on one `backend`, then fetch its
    /// outgoing calls. Returns (callee_name, callee_def_file, call_site_line):
    /// `callee_def_file` is the callee's absolute definition path and
    /// `call_site_line` is the 1-based line *in this caller* where the call
    /// occurs (from `from_ranges`) — a `CallEdge`'s line is the call site, not
    /// the callee's definition. Empty when the backend has no callHierarchy
    /// support, the position cannot be anchored, or there are no outgoing calls.
    pub async fn call_hierarchy_outgoing(
        &self,
        backend: SourceSet,
        file_path: &Path,
        symbol_name: &str,
        line: u32,
    ) -> Result<Vec<(String, String, u32)>> {
        let cxx = match Self::cxx_backend_for_source(backend) {
            Some(b) => b,
            None => return Ok(Vec::new()),
        };
        let language = cxx_language_id(file_path);
        let server_key = Self::server_key(language, cxx);
        let server = match self.get_or_start_server_for_key(&server_key).await {
            Ok(s) => s,
            Err(_) => return Ok(Vec::new()),
        };

        // prepareCallHierarchy must sit on the identifier; anchor on the name
        // token. `line` is the symbol's 1-based definition row.
        let content = std::fs::read_to_string(file_path).unwrap_or_default();
        let (anchor_line, anchor_col) =
            name_anchor(&content, symbol_name, (line.max(1) - 1) as usize)
                .unwrap_or((line.max(1) - 1, 0));

        let uri = Url::from_file_path(file_path).map_err(|_| anyhow!("Invalid file path"))?;
        self.did_open(&server, language, file_path).await.ok();

        let prepare_params = CallHierarchyPrepareParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position {
                    line: anchor_line,
                    character: anchor_col,
                },
            },
            work_done_progress_params: WorkDoneProgressParams::default(),
        };
        let prepare_value = serde_json::to_value(&prepare_params)?;
        let prepare_resp = self
            .send_request(&server, "textDocument/prepareCallHierarchy", prepare_value)
            .await;

        let item = match prepare_resp {
            Ok(v) if !v.is_null() => serde_json::from_value::<Vec<CallHierarchyItem>>(v)
                .ok()
                .and_then(|items| items.into_iter().next()),
            _ => None,
        };
        let item = match item {
            Some(i) => i,
            None => {
                self.did_close(&server, file_path).await.ok();
                return Ok(Vec::new());
            }
        };

        let out_params = CallHierarchyOutgoingCallsParams {
            item,
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        };
        let out_value = serde_json::to_value(&out_params)?;
        let out_resp = self
            .send_request(&server, "callHierarchy/outgoingCalls", out_value)
            .await;
        self.did_close(&server, file_path).await.ok();

        let calls: Vec<CallHierarchyOutgoingCall> = match out_resp {
            Ok(v) if !v.is_null() => serde_json::from_value(v).unwrap_or_default(),
            _ => return Ok(Vec::new()),
        };

        let mut result = Vec::new();
        for call in calls {
            let callee_file = call
                .to
                .uri
                .to_file_path()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            // A CallEdge's line is the call site in this caller; outgoingCalls
            // reports those in `from_ranges`. Fall back to the callee's name row
            // only when a backend omits them.
            let call_site_line = call
                .from_ranges
                .first()
                .map(|range| range.start.line + 1)
                .unwrap_or_else(|| call.to.selection_range.start.line + 1);
            result.push((call.to.name, callee_file, call_site_line));
        }
        Ok(result)
    }

    /// Gracefully stop one server: shutdown request followed by exit notification.
    async fn shutdown_one_server(&self, language: &str, process: &LspProcess) {
        info!("Shutting down LSP server for {}", language);

        let _ = self
            .send_request(process, "shutdown", serde_json::json!({}))
            .await;

        let _ = self.send_notification(process, "exit", Value::Null).await;
    }

    /// Shutdown all LSP servers
    pub async fn shutdown_all(&self) -> Result<()> {
        for entry in self.servers.iter() {
            self.shutdown_one_server(entry.key(), entry.value()).await;
        }

        self.servers.clear();
        Ok(())
    }

    /// Restart all LSP servers for `language`: evict and gracefully shut down
    /// each process, then immediately spawn fresh ones so they read the new
    /// compile_commands.json. For C/C++ every configured backend is restarted.
    /// Called when compile_commands.json changes.
    pub async fn restart_server(&self, language: &str) {
        if matches!(language, "c" | "cpp") {
            for &backend in &self.config.cxx_lsp_backends {
                let key = Self::server_key(language, backend);
                if let Some((_, process)) = self.servers.remove(&key) {
                    info!(
                        "Restarting {} LSP server for {} (compile_commands.json changed)",
                        backend.label(),
                        language
                    );
                    self.shutdown_one_server(&key, &process).await;
                    if let Err(e) = self.get_or_start_server_for_key(&key).await {
                        warn!(
                            "Failed to respawn {} LSP server for {}: {}",
                            backend.label(),
                            language,
                            e
                        );
                    }
                }
            }
        } else if let Some((_, process)) = self.servers.remove(language) {
            info!(
                "Restarting LSP server for {} (compile_commands.json changed)",
                language
            );
            self.shutdown_one_server(language, &process).await;
            if let Err(e) = self.get_or_start_server(language).await {
                warn!("Failed to respawn LSP server for {}: {}", language, e);
            }
        }
    }

    /// Eagerly start all servers for `language` so they are warm before the
    /// first query. For C/C++ this starts every configured backend. Best-effort:
    /// a missing binary or spawn failure is logged, not fatal. No-op when LSP
    /// is not enabled for the language.
    pub async fn warm_up(&self, language: &str) {
        if !self.is_enabled_for_language(language) {
            return;
        }
        if matches!(language, "c" | "cpp") {
            for &backend in &self.config.cxx_lsp_backends {
                let key = Self::server_key(language, backend);
                if let Err(e) = self.get_or_start_server_for_key(&key).await {
                    warn!(
                        "Failed to warm up {} LSP server for {}: {}",
                        backend.label(),
                        language,
                        e
                    );
                }
            }
        } else if let Err(e) = self.get_or_start_server(language).await {
            warn!("Failed to warm up LSP server for {}: {}", language, e);
        }
    }
}

impl Drop for LspManager {
    fn drop(&mut self) {
        // Best effort cleanup - spawn a blocking task
        let servers = std::mem::take(&mut self.servers);
        std::thread::spawn(move || {
            for entry in servers.iter() {
                let process = entry.value();
                // Kill process on drop
                let _ = process;
            }
        });
    }
}

/// LSP languageId for a C/C++ file, by extension. Defaults to "c" for plain
/// `.h` and anything unrecognised; clangd/ccls still resolve via
/// compile_commands.json regardless.
fn cxx_language_id(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "cpp" | "cxx" | "cc" | "c++" | "hpp" | "hxx" | "hh" | "h++" | "ipp" | "tpp" => "cpp",
        _ => "c",
    }
}

/// Map an LSP `SymbolKind` to a narsil [`NarsilSymbolKind`].
fn lsp_kind_to_narsil(kind: SymbolKind) -> NarsilSymbolKind {
    match kind {
        SymbolKind::FUNCTION => NarsilSymbolKind::Function,
        SymbolKind::METHOD => NarsilSymbolKind::Method,
        SymbolKind::CONSTRUCTOR => NarsilSymbolKind::Constructor,
        SymbolKind::STRUCT => NarsilSymbolKind::Struct,
        SymbolKind::CLASS => NarsilSymbolKind::Class,
        SymbolKind::ENUM => NarsilSymbolKind::Enum,
        SymbolKind::ENUM_MEMBER => NarsilSymbolKind::Constant,
        SymbolKind::INTERFACE => NarsilSymbolKind::Interface,
        SymbolKind::NAMESPACE => NarsilSymbolKind::Namespace,
        SymbolKind::MODULE | SymbolKind::PACKAGE => NarsilSymbolKind::Module,
        SymbolKind::CONSTANT => NarsilSymbolKind::Constant,
        SymbolKind::VARIABLE => NarsilSymbolKind::Variable,
        SymbolKind::FIELD | SymbolKind::PROPERTY => NarsilSymbolKind::Field,
        SymbolKind::TYPE_PARAMETER => NarsilSymbolKind::TypeAlias,
        _ => NarsilSymbolKind::Unknown,
    }
}

/// Flatten the nested documentSymbol tree into narsil `Symbol`s, recursing into
/// children so class members become separate symbols. Each carries `backend` as
/// its sole confirmer; `file_path` is left empty for the caller to fill.
fn flatten_document_symbols(symbols: &[DocumentSymbol], backend: SourceSet, out: &mut Vec<Symbol>) {
    for ds in symbols {
        #[allow(deprecated)]
        out.push(Symbol {
            name: ds.name.clone(),
            kind: lsp_kind_to_narsil(ds.kind),
            file_path: String::new(),
            start_line: ds.selection_range.start.line as usize + 1,
            end_line: ds.range.end.line as usize + 1,
            signature: ds.detail.clone(),
            qualified_name: None,
            doc_comment: None,
            confirmed_by: backend,
            line_conflicts: Vec::new(),
        });
        if let Some(children) = &ds.children {
            flatten_document_symbols(children, backend, out);
        }
    }
}

/// 0-based (line, UTF-16 column) of `name` as a whole-word token, scanning a
/// few lines from `start_line` (0-based). A leading return type can push the
/// name token below the definition's first line, so a short window is scanned.
fn name_anchor(content: &str, name: &str, start_line: usize) -> Option<(u32, u32)> {
    if name.is_empty() {
        return None;
    }
    let lines: Vec<&str> = content.lines().collect();
    let end = (start_line + 8).min(lines.len());
    for line_idx in start_line..end {
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

/// Convert LSP hover to markdown string
pub fn hover_to_markdown(hover: &Hover) -> String {
    match &hover.contents {
        HoverContents::Scalar(content) => marked_string_to_markdown(content),
        HoverContents::Array(contents) => contents
            .iter()
            .map(marked_string_to_markdown)
            .collect::<Vec<_>>()
            .join("\n\n"),
        HoverContents::Markup(markup) => match markup.kind {
            MarkupKind::PlainText => markup.value.clone(),
            MarkupKind::Markdown => markup.value.clone(),
        },
    }
}

fn marked_string_to_markdown(marked: &MarkedString) -> String {
    match marked {
        MarkedString::String(s) => s.clone(),
        MarkedString::LanguageString(ls) => {
            format!("```{}\n{}\n```", ls.language, ls.value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsp_config_default() {
        let config = LspConfig::default();
        assert!(!config.enabled);
        // B1: Reduced timeout from 5000ms to 1500ms for better responsiveness
        assert!(
            config.timeout_ms <= 2000,
            "LSP timeout should be <= 2000ms, got {}",
            config.timeout_ms
        );
    }

    #[test]
    fn test_lsp_config_default_timeout_reduced() {
        // Phase B1: Verify timeout is reduced to 1500ms
        let config = LspConfig::default();
        assert_eq!(config.timeout_ms, 1500, "Default timeout should be 1500ms");
    }

    #[test]
    fn test_server_detection() {
        let config = LspConfig::default();
        let manager = LspManager::new(config, vec![]);

        let (cmd, _) = manager.get_server_command_for_key("rust").unwrap();
        assert_eq!(cmd, PathBuf::from("rust-analyzer"));

        let (cmd, _) = manager.get_server_command_for_key("python").unwrap();
        assert_eq!(cmd, PathBuf::from("pyright-langserver"));

        let (cmd, _) = manager.get_server_command_for_key("c:clangd").unwrap();
        assert_eq!(cmd, PathBuf::from("clangd"));

        let (cmd, _) = manager.get_server_command_for_key("c:ccls").unwrap();
        assert_eq!(cmd, PathBuf::from("ccls"));
    }

    #[test]
    fn test_is_enabled_returns_false_by_default() {
        // Phase B2: Callers can check if LSP is globally enabled before making async calls
        let config = LspConfig::default();
        let manager = LspManager::new(config, vec![]);
        assert!(!manager.is_enabled(), "LSP should be disabled by default");
    }

    #[test]
    fn test_is_enabled_returns_true_when_enabled() {
        let config = LspConfig {
            enabled: true,
            ..Default::default()
        };
        let manager = LspManager::new(config, vec![]);
        assert!(
            manager.is_enabled(),
            "LSP should be enabled when config says so"
        );
    }

    #[tokio::test]
    async fn test_lsp_early_exit_when_disabled() {
        // Phase B2: LSP methods should return immediately when disabled
        use std::time::Instant;

        let config = LspConfig {
            enabled: false,
            ..Default::default()
        };
        let manager = LspManager::new(config, vec![]);

        let start = Instant::now();
        let result = manager
            .get_hover("rust", std::path::Path::new("test.rs"), 1, 0)
            .await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert!(
            elapsed.as_millis() < 100,
            "LSP call when disabled should complete in <100ms, took {}ms",
            elapsed.as_millis()
        );
    }

    #[test]
    fn test_hover_to_markdown() {
        let hover = Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: "# Test\n\nSome content".to_string(),
            }),
            range: None,
        };

        let markdown = hover_to_markdown(&hover);
        assert_eq!(markdown, "# Test\n\nSome content");
    }

    #[test]
    fn test_lsp_rejects_malicious_server_path() {
        let mut paths = HashMap::new();
        paths.insert("rust".to_string(), PathBuf::from(";whoami"));
        let config = LspConfig {
            server_paths: paths,
            ..Default::default()
        };
        let manager = LspManager::new(config, vec![]);
        let result = manager.get_server_command_for_key("rust");
        assert!(result.is_err(), "Should reject malicious server path");
    }

    #[test]
    fn test_lsp_rejects_relative_traversal_path() {
        let mut paths = HashMap::new();
        paths.insert("rust".to_string(), PathBuf::from("../../bin/evil"));
        let config = LspConfig {
            server_paths: paths,
            ..Default::default()
        };
        let manager = LspManager::new(config, vec![]);
        let result = manager.get_server_command_for_key("rust");
        assert!(result.is_err(), "Should reject relative traversal path");
    }
}
