//! Stdio ↔ HTTP proxy for the SSE auto-discovery feature.
//!
//! When the stdio entry-point finds a running SSE narsil-mcp that already
//! covers the requested repositories, it skips engine construction and
//! runs this proxy instead. The proxy is byte-level: it reads
//! newline-delimited JSON-RPC from stdin, forwards each line as a POST to
//! the streamable HTTP `/mcp` endpoint, captures the `Mcp-Session-Id`
//! header from the first response, and writes successful response bodies
//! back to stdout as new lines.
//!
//! Requests are serialised — one stdin line, one POST, one response
//! written, repeat. The MCP stdio framing technically allows pipelining
//! but the editors that drive narsil-mcp do not exercise it, and
//! localhost RTT keeps the latency cost bounded. If a real workload
//! regresses, revisit.

use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info, warn};

// `tokio::io::stdin()` is backed by a blocking thread parked in `read(2)`.
// On shutdown signal, dropping the proxy_loop future cannot unblock that
// thread (only fresh stdin input would, which never arrives once the editor
// has disconnected), so the runtime hangs forever waiting for it. Skip the
// hung shutdown by exiting directly after flushing stdout.
async fn exit_after_flush(code: i32) -> ! {
    let mut stdout = tokio::io::stdout();
    let _ = stdout.flush().await;
    std::process::exit(code);
}

const MCP_SESSION_HEADER: &str = "mcp-session-id";

/// Upper bound on how long a reconnect keeps trying to reach a restarted
/// server before giving up and letting the editor respawn us.
const RECONNECT_WINDOW: Duration = Duration::from_secs(30);
/// Backoff cap between rediscovery attempts during a reconnect.
const RECONNECT_BACKOFF_CAP: Duration = Duration::from_secs(2);
/// Per-line reconnect budget: a server that keeps rejecting one request
/// terminates the proxy (editor respawns it) rather than looping forever.
const MAX_RECONNECTS: u32 = 5;

/// State for one stdio↔SSE proxy session: the upstream endpoint, the captured
/// `Mcp-Session-Id`, and the cached MCP handshake so a server restart can be
/// papered over by re-establishing a fresh session and replaying the request.
struct ProxySession {
    client: reqwest::Client,
    /// `<base_url>/mcp`; updated if rediscovery finds the server on a new URL.
    endpoint: String,
    /// Repos this stdio process serves; used to rediscover the restarted
    /// server, which may have rebound an ephemeral port.
    repos: Vec<PathBuf>,
    session_header_name: HeaderName,
    /// Session id captured from the first response; cleared on reconnect.
    session_id: Option<HeaderValue>,
    /// The `initialize` request line, replayed verbatim to mint a session on
    /// a new server. Cached as it passes through on the way out.
    init_request: Option<String>,
    /// The `notifications/initialized` line, replayed after `initialize`.
    initialized_notification: Option<String>,
}

/// Result of forwarding one stdin line upstream.
enum Forward {
    /// Response body to write back to stdout.
    Body(Vec<u8>),
    /// 202 Accepted — a notification with no response to forward.
    Accepted,
}

impl ProxySession {
    fn new(base_url: &str, repos: &[PathBuf]) -> Result<Self> {
        let endpoint = format!("{}/mcp", base_url.trim_end_matches('/'));
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .context("Building reqwest client for stdio proxy")?;
        Ok(Self {
            client,
            endpoint,
            repos: repos.to_vec(),
            session_header_name: HeaderName::from_static(MCP_SESSION_HEADER),
            session_id: None,
            init_request: None,
            initialized_notification: None,
        })
    }

    fn request_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        if let Some(captured) = &self.session_id {
            headers.insert(self.session_header_name.clone(), captured.clone());
        }
        headers
    }

    /// Remember the handshake lines so a reconnect can replay them. Parses
    /// only until both are cached, so the steady-state cost is one comparison.
    fn observe_handshake(&mut self, line: &str) {
        if self.init_request.is_some() && self.initialized_notification.is_some() {
            return;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => return,
        };
        match value.get("method").and_then(|method| method.as_str()) {
            Some("initialize") => self.init_request = Some(line.to_string()),
            Some("notifications/initialized") => {
                self.initialized_notification = Some(line.to_string())
            }
            _ => {}
        }
    }

    /// POST one line to the current endpoint, capturing `Mcp-Session-Id` from
    /// the response while we do not yet hold one.
    async fn post_once(&mut self, line: &str) -> reqwest::Result<reqwest::Response> {
        let response = self
            .client
            .post(&self.endpoint)
            .headers(self.request_headers())
            .body(line.to_string())
            .send()
            .await?;
        if self.session_id.is_none() {
            if let Some(value) = response.headers().get(&self.session_header_name).cloned() {
                if let Ok(text) = value.to_str() {
                    info!("Proxy session established (Mcp-Session-Id={})", text);
                }
                self.session_id = Some(value);
            }
        }
        Ok(response)
    }

    /// Forward one line, retrying transparently across a server restart. A
    /// reconnect is triggered by a transport error (failed send or dropped
    /// response body) or by a 404/503 from the upstream — the streamable
    /// handler returns 404 when it no longer knows our session id and 503
    /// while it is bound but not yet serving, both of which happen when the
    /// server rebinds the same port on restart. Any other non-2xx terminates.
    async fn forward(&mut self, line: &str) -> Result<Forward> {
        let mut reconnects: u32 = 0;
        loop {
            let response = match self.post_once(line).await {
                Ok(response) => response,
                Err(e) => {
                    self.reconnect_or_bail(line, &mut reconnects, &format!("send failed: {e}"))
                        .await?;
                    continue;
                }
            };

            let status = response.status();
            let code = status.as_u16();
            if code == 202 {
                return Ok(Forward::Accepted);
            }
            if code == 404 || code == 503 {
                self.reconnect_or_bail(line, &mut reconnects, &format!("HTTP {code}"))
                    .await?;
                continue;
            }
            if !status.is_success() {
                return Err(anyhow!("upstream returned HTTP {}", code));
            }

            match response.bytes().await {
                Ok(body) => return Ok(Forward::Body(body.to_vec())),
                Err(e) => {
                    self.reconnect_or_bail(
                        line,
                        &mut reconnects,
                        &format!("body read failed: {e}"),
                    )
                    .await?;
                    continue;
                }
            }
        }
    }

    /// Run one reconnect cycle for the in-flight `line`, bailing once the
    /// per-line reconnect budget ([`MAX_RECONNECTS`]) is spent.
    async fn reconnect_or_bail(
        &mut self,
        line: &str,
        attempts: &mut u32,
        reason: &str,
    ) -> Result<()> {
        *attempts += 1;
        if *attempts > MAX_RECONNECTS {
            return Err(anyhow!(
                "giving up after {} reconnect attempts (last reason: {})",
                MAX_RECONNECTS,
                reason
            ));
        }
        warn!(
            "Proxy upstream {}; reconnecting (attempt {}/{})",
            reason, attempts, MAX_RECONNECTS
        );
        self.reconnect(line)
            .await
            .context("reconnecting to SSE server")
    }

    /// Re-establish a session against the restarted (possibly moved) server.
    /// Rediscovers via the registry with bounded backoff, then replays the
    /// cached handshake — unless `in_flight` is itself the `initialize`
    /// request, whose replay by the caller re-establishes the session anyway.
    /// Errors once [`RECONNECT_WINDOW`] is exhausted so the caller exits and
    /// the editor respawns us.
    async fn reconnect(&mut self, in_flight: &str) -> Result<()> {
        let start = Instant::now();
        let mut backoff = Duration::from_millis(100);
        loop {
            let repos = self.repos.clone();
            // find_server_for_repos uses a blocking HTTP probe; keep it off the
            // async worker so the shutdown-signal select stays responsive.
            let found = tokio::task::spawn_blocking(move || {
                crate::sse_discovery::find_server_for_repos(&repos)
            })
            .await
            .ok()
            .flatten();

            if let Some(url) = found {
                self.endpoint = format!("{}/mcp", url.trim_end_matches('/'));
                self.session_id = None;
                if self.init_request.as_deref() == Some(in_flight) {
                    info!(
                        "Proxy reconnected to {} (in-flight initialize re-establishes session)",
                        url
                    );
                    return Ok(());
                }
                match self.replay_handshake().await {
                    Ok(()) => {
                        info!("Proxy reconnected to {}", url);
                        return Ok(());
                    }
                    Err(e) => warn!("Proxy reconnect: handshake replay failed: {}", e),
                }
            }

            if start.elapsed() >= RECONNECT_WINDOW {
                return Err(anyhow!(
                    "no SSE server reachable within {:?} of restart",
                    RECONNECT_WINDOW
                ));
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(RECONNECT_BACKOFF_CAP);
        }
    }

    /// Replay the cached `initialize` (and the `initialized` notification) to
    /// mint a fresh `Mcp-Session-Id`. The replayed responses are drained, not
    /// forwarded — the editor already saw them on the original handshake.
    async fn replay_handshake(&mut self) -> Result<()> {
        let init = self
            .init_request
            .clone()
            .ok_or_else(|| anyhow!("no cached initialize request to replay"))?;
        let response = self
            .post_once(&init)
            .await
            .context("replaying initialize after reconnect")?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "initialize replay returned HTTP {}",
                response.status().as_u16()
            ));
        }
        let _ = response.bytes().await;
        if self.session_id.is_none() {
            return Err(anyhow!("server returned no session id on reconnect"));
        }
        if let Some(note) = self.initialized_notification.clone() {
            let response = self
                .post_once(&note)
                .await
                .context("replaying initialized notification after reconnect")?;
            let _ = response.bytes().await;
        }
        Ok(())
    }
}

/// Run the proxy loop against `base_url` until stdin closes, the upstream
/// returns an unrecoverable error, or a shutdown signal arrives. `repos` is
/// the set this process serves, used to rediscover the server if it restarts.
pub async fn run_stdio_proxy_with_shutdown(base_url: &str, repos: &[PathBuf]) -> Result<()> {
    let mut session = ProxySession::new(base_url, repos)?;

    tokio::select! {
        result = proxy_loop(&mut session) => result,
        _ = tokio::signal::ctrl_c() => {
            info!("Proxy session terminating: shutdown signal (Ctrl-C)");
            exit_after_flush(0).await
        }
        _ = wait_for_terminate_signal() => {
            info!("Proxy session terminating: shutdown signal (SIGTERM)");
            exit_after_flush(0).await
        }
    }
}

async fn proxy_loop(session: &mut ProxySession) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader
            .read_line(&mut line)
            .await
            .context("Reading stdin for proxy")?;
        if bytes_read == 0 {
            info!("Proxy session terminating: stdin closed");
            return Ok(());
        }

        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed.is_empty() {
            continue;
        }
        debug!("proxy → {} bytes", trimmed.len());

        // Cache the handshake before sending so a reconnect can replay it even
        // if this very request is the one that hits a restarted server.
        session.observe_handshake(trimmed);

        match session.forward(trimmed).await? {
            Forward::Accepted => {
                debug!("proxy ← 202 Accepted (notification)");
                continue;
            }
            Forward::Body(body) => {
                debug!("proxy ← bytes={}", body.len());
                stdout.write_all(&body).await?;
                // The streamable HTTP transport returns a single JSON object
                // per POST; stdio framing requires a trailing newline that the
                // HTTP body does not always carry.
                if !body.ends_with(b"\n") {
                    stdout.write_all(b"\n").await?;
                }
                stdout.flush().await?;
            }
        }
    }
}

#[cfg(unix)]
async fn wait_for_terminate_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            term.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
}

#[cfg(not(unix))]
async fn wait_for_terminate_signal() {
    std::future::pending::<()>().await;
}
