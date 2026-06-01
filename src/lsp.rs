//! LSP integration for enhanced code intelligence
//!
//! This module provides integration with Language Server Protocol servers for
//! richer type information, hover docs, and go-to-definition capabilities.

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
}

/// Configuration for LSP integration
#[derive(Debug, Clone)]
pub struct LspConfig {
    /// Enable/disable LSP per language
    pub enabled_languages: HashMap<String, bool>,
    /// Custom LSP server paths
    pub server_paths: HashMap<String, PathBuf>,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
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
        let response = timeout(Duration::from_millis(self.config.timeout_ms), rx)
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

    /// Query all configured C/C++ backends in parallel and return per-backend results.
    ///
    /// Returns a map from backend label (`"clangd"`, `"ccls"`) to the locations
    /// that backend found. Backends that fail or return nothing are omitted.
    pub async fn find_cxx_references_parallel(
        &self,
        language: &str,
        file_path: &Path,
        line: u32,
        character: u32,
        include_declaration: bool,
    ) -> HashMap<&'static str, Vec<Location>> {
        let timeout_ms = self.config.timeout_ms;
        let file_path_buf = file_path.to_path_buf();
        let language_owned = language.to_string();

        // Start all backends first (fast once servers are already warm)
        let mut servers: Vec<(&'static str, Arc<LspProcess>)> = Vec::new();
        for &backend in &self.config.cxx_lsp_backends {
            let key = Self::server_key(language, backend);
            match self.get_or_start_server_for_key(&key).await {
                Ok(s) => servers.push((backend.label(), s)),
                Err(e) => debug!(
                    "Could not start {} for {}: {}",
                    backend.label(),
                    language,
                    e
                ),
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
            capabilities: ClientCapabilities::default(),
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

    /// Find references
    pub async fn find_references(
        &self,
        language: &str,
        file_path: &Path,
        line: u32,
        character: u32,
        include_declaration: bool,
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
        self.did_open(&server, language, file_path).await.ok();
        let response = self
            .send_request(&server, "textDocument/references", params_value)
            .await;
        self.did_close(&server, file_path).await.ok();
        let response = response?;

        if response.is_null() {
            return Ok(None);
        }

        let locations: Vec<Location> = serde_json::from_value(response)?;
        Ok(Some(locations))
    }

    /// Get document symbols
    pub async fn get_document_symbols(
        &self,
        language: &str,
        file_path: &Path,
    ) -> Result<Option<Vec<DocumentSymbol>>> {
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

        let params = DocumentSymbolParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        };

        let params_value = serde_json::to_value(&params)?;
        self.did_open(&server, language, file_path).await.ok();
        let response = self
            .send_request(&server, "textDocument/documentSymbol", params_value)
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
