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
use std::time::Duration;
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

/// Run the proxy loop against `base_url` until stdin closes, the upstream
/// returns an error, or a shutdown signal arrives.
pub async fn run_stdio_proxy_with_shutdown(base_url: &str) -> Result<()> {
    let endpoint = format!("{}/mcp", base_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .context("Building reqwest client for stdio proxy")?;

    tokio::select! {
        result = proxy_loop(&client, &endpoint) => result,
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

async fn proxy_loop(client: &reqwest::Client, endpoint: &str) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();

    let session_header_name: HeaderName = HeaderName::from_static(MCP_SESSION_HEADER);
    let mut session_id: Option<HeaderValue> = None;
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

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        if let Some(captured) = &session_id {
            headers.insert(session_header_name.clone(), captured.clone());
        }

        let response = match client
            .post(endpoint)
            .headers(headers)
            .body(trimmed.to_string())
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) => {
                warn!("Proxy session terminating: transport error: {}", e);
                return Err(anyhow!("upstream transport error: {}", e));
            }
        };

        let status = response.status();
        if session_id.is_none() {
            if let Some(value) = response.headers().get(&session_header_name).cloned() {
                if let Ok(text) = value.to_str() {
                    info!("Proxy session established (Mcp-Session-Id={})", text);
                }
                session_id = Some(value);
            }
        }

        if status.as_u16() == 202 {
            debug!("proxy ← 202 Accepted (notification)");
            continue;
        }

        if !status.is_success() {
            let code = status.as_u16();
            warn!("Proxy session terminating: http error: {}", code);
            return Err(anyhow!("upstream returned HTTP {}", code));
        }

        let body = response
            .bytes()
            .await
            .context("Reading proxy response body")?;
        debug!("proxy ← status={} bytes={}", status.as_u16(), body.len());

        stdout.write_all(&body).await?;
        // The streamable HTTP transport returns a single JSON object per
        // POST; stdio framing requires a trailing newline that the HTTP
        // body does not always carry.
        if !body.ends_with(b"\n") {
            stdout.write_all(b"\n").await?;
        }
        stdout.flush().await?;
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
