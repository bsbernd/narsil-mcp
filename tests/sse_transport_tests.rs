//! Integration tests for the MCP HTTP+SSE transport.
//!
//! These tests spawn the narsil-mcp binary with `--transport sse`, drive
//! the JSON-RPC protocol over HTTP, and observe responses on the SSE
//! stream. The smoke test covers the spec-required `endpoint` event and
//! one full request/response cycle. The isolation test exercises the
//! per-session `client_info` flow — guarding against a regression where
//! one session's `initialize` could overwrite another's editor identity.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

fn binary_path() -> PathBuf {
    let name = if cfg!(debug_assertions) {
        "target/debug/narsil-mcp"
    } else {
        "target/release/narsil-mcp"
    };
    PathBuf::from(name)
}

/// Bind ephemeral port and immediately release it. The subprocess that
/// comes up next is racing with anything else on the host; for a test
/// machine this is acceptable.
fn ephemeral_port() -> Result<u16> {
    let sock = TcpListener::bind("127.0.0.1:0")?;
    let port = sock.local_addr()?.port();
    drop(sock);
    Ok(port)
}

/// A spawned narsil-mcp subprocess in SSE mode. The temp directory is
/// kept alive for the process lifetime; both are dropped together.
struct SseServer {
    process: Child,
    port: u16,
    _repo: TempDir,
}

impl SseServer {
    fn spawn() -> Result<Self> {
        let port = ephemeral_port()?;
        let repo = TempDir::new()?;
        let process = Command::new(binary_path())
            .args([
                "--transport",
                "sse",
                "--sse-host",
                "127.0.0.1",
                "--sse-port",
                &port.to_string(),
                "--repos",
                repo.path().to_str().expect("temp path is utf-8"),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn narsil-mcp; run `cargo build` first")?;

        let server = Self {
            process,
            port,
            _repo: repo,
        };
        server.wait_until_ready()?;
        Ok(server)
    }

    fn wait_until_ready(&self) -> Result<()> {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()?;
        let url = format!("http://127.0.0.1:{}/health", self.port);
        while Instant::now() < deadline {
            if let Ok(resp) = client.get(&url).send() {
                if resp.status().is_success() {
                    return Ok(());
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
        bail!("server did not become ready within {:?}", STARTUP_TIMEOUT);
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for SseServer {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

#[derive(Debug, Clone)]
struct SseEvent {
    event: Option<String>,
    data: String,
}

/// One SSE session against the server. Opens GET /mcp/sse, parses the
/// initial `endpoint` event to learn the session id, then forwards every
/// subsequent event to a channel for the test to consume.
struct SseClient {
    base_url: String,
    session_id: String,
    rx: Receiver<SseEvent>,
    _reader: thread::JoinHandle<()>,
}

impl SseClient {
    fn open(base_url: &str) -> Result<Self> {
        let url = format!("{}/mcp/sse", base_url);
        let resp = reqwest::blocking::Client::builder()
            // No timeout — the SSE stream is long-lived. The test owns
            // termination by dropping the client.
            .timeout(None)
            .build()?
            .get(&url)
            .send()
            .context("GET /mcp/sse")?;

        let mut reader = BufReader::new(EventReadAdapter::new(resp));

        // The first event must be `endpoint`. Read frames synchronously
        // until we see it.
        let mut endpoint_event: Option<SseEvent> = None;
        for _ in 0..16 {
            match read_one_event(&mut reader)? {
                Some(ev) if ev.event.as_deref() == Some("endpoint") => {
                    endpoint_event = Some(ev);
                    break;
                }
                Some(_) => continue, // keep-alive comment or unrelated
                None => bail!("server closed before sending endpoint event"),
            }
        }
        let endpoint_event =
            endpoint_event.ok_or_else(|| anyhow!("did not see endpoint event in first frames"))?;

        let session_id = parse_session_id(&endpoint_event.data)?;

        // Spawn a thread to drain subsequent events into a channel.
        let (tx, rx) = mpsc::channel();
        let reader_handle = thread::spawn(move || loop {
            match read_one_event(&mut reader) {
                Ok(Some(ev)) => {
                    if tx.send(ev).is_err() {
                        return;
                    }
                }
                Ok(None) => return, // server closed
                Err(_) => return,
            }
        });

        Ok(Self {
            base_url: base_url.to_string(),
            session_id,
            rx,
            _reader: reader_handle,
        })
    }

    fn post(&self, body: &Value) -> Result<u16> {
        let url = format!(
            "{}/mcp/message?sessionId={}",
            self.base_url, self.session_id
        );
        let resp = reqwest::blocking::Client::new()
            .post(&url)
            .json(body)
            .send()
            .context("POST /mcp/message")?;
        Ok(resp.status().as_u16())
    }

    fn next_event(&self, timeout: Duration) -> Result<SseEvent> {
        match self.rx.recv_timeout(timeout) {
            Ok(ev) => Ok(ev),
            Err(RecvTimeoutError::Timeout) => bail!("timeout waiting for SSE event"),
            Err(RecvTimeoutError::Disconnected) => bail!("SSE stream closed"),
        }
    }

    fn try_next_event(&self, timeout: Duration) -> Option<SseEvent> {
        self.rx.recv_timeout(timeout).ok()
    }
}

/// Wraps a reqwest blocking Response so BufReader can pull bytes. The
/// blocking response already implements `Read`; this newtype just lets us
/// move it across threads.
struct EventReadAdapter {
    inner: reqwest::blocking::Response,
}

impl EventReadAdapter {
    fn new(inner: reqwest::blocking::Response) -> Self {
        Self { inner }
    }
}

impl Read for EventReadAdapter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

/// Read one SSE frame. Returns `Ok(None)` on EOF, `Ok(Some(ev))` once a
/// blank line terminates the frame, or an error.
///
/// SSE frame syntax (subset we need): each non-blank line is `field:
/// value` or starts with `:` (comment). Blank line ends the frame. We
/// only recognise `event:` and `data:`; comment lines are ignored.
fn read_one_event<R: BufRead>(reader: &mut R) -> Result<Option<SseEvent>> {
    let mut event = None;
    let mut data: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut got_any_field = false;
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        // Normalize CRLF / LF
        let line = buf.trim_end_matches('\n').trim_end_matches('\r');
        if line.is_empty() {
            if got_any_field {
                return Ok(Some(SseEvent {
                    event,
                    data: data.join("\n"),
                }));
            }
            // Blank line with no fields = keep-alive separator before
            // anything happened; keep reading.
            continue;
        }
        if line.starts_with(':') {
            // Comment / keep-alive; ignore but record we saw activity
            got_any_field = true;
            continue;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => continue,
        };
        match field {
            "event" => event = Some(value.to_string()),
            "data" => data.push(value.to_string()),
            _ => {}
        }
        got_any_field = true;
    }
}

fn parse_session_id(endpoint_data: &str) -> Result<String> {
    // Expected: "/mcp/message?sessionId=<uuid>"
    let prefix = "/mcp/message?sessionId=";
    endpoint_data
        .strip_prefix(prefix)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("malformed endpoint event data: {:?}", endpoint_data))
}

fn initialize(id: i64, client_name: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": client_name, "version": "1.0" }
        }
    })
}

fn tools_list(id: i64) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {} })
}

fn tools_count(response_data: &str) -> Result<usize> {
    let v: Value = serde_json::from_str(response_data)?;
    let tools = v
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .ok_or_else(|| anyhow!("response did not contain result.tools array"))?;
    Ok(tools.len())
}

fn response_id(response_data: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(response_data)?;
    Ok(v.get("id").cloned().unwrap_or(Value::Null))
}

/// Spec smoke test: open SSE, observe `endpoint` event, drive
/// initialize → tools/list → list_repos, assert each response arrives
/// with the matching JSON-RPC id.
#[test]
fn test_sse_smoke_flow() -> Result<()> {
    let server = SseServer::spawn()?;
    let client = SseClient::open(&server.base_url())?;

    assert!(!client.session_id.is_empty(), "session id must be set");

    assert_eq!(client.post(&initialize(1, "test-client"))?, 202);
    let ev = client.next_event(EVENT_TIMEOUT)?;
    assert_eq!(response_id(&ev.data)?, json!(1));

    assert_eq!(client.post(&tools_list(2))?, 202);
    let ev = client.next_event(EVENT_TIMEOUT)?;
    assert_eq!(response_id(&ev.data)?, json!(2));
    assert!(tools_count(&ev.data)? > 0, "tools/list should return tools");

    let call = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": { "name": "list_repos", "arguments": {} }
    });
    assert_eq!(client.post(&call)?, 202);
    let ev = client.next_event(EVENT_TIMEOUT)?;
    assert_eq!(response_id(&ev.data)?, json!(3));

    Ok(())
}

/// Per-session isolation: two concurrent SSE sessions get distinct
/// session ids and their responses route back to the originating SSE
/// stream. A previous design with a shared `McpServer.client_info`
/// mutex risked cross-session contamination; the SessionState refactor
/// guards against that.
///
/// We assert the strongest property we can observe from outside the
/// process today: each session's POST yields a response with the
/// matching JSON-RPC id, delivered on that session's own SSE channel.
/// Asserting that `tools/list` returns different tool counts per
/// editor would also probe per-session client_info — but the
/// editor-preset mapping is currently broken (tracked separately in
/// the `integration_editor_tests` suite), so doing so would conflate
/// regressions.
#[test]
fn test_sse_per_session_isolation() -> Result<()> {
    let server = SseServer::spawn()?;
    let client_a = SseClient::open(&server.base_url())?;
    let client_b = SseClient::open(&server.base_url())?;

    assert_ne!(
        client_a.session_id, client_b.session_id,
        "each SSE connection must get its own session id"
    );

    // Initialize each with a different editor identity. Interleave the
    // POSTs to maximise the chance a shared-mutex bug would surface.
    assert_eq!(client_a.post(&initialize(101, "claude-desktop"))?, 202);
    assert_eq!(client_b.post(&initialize(202, "zed"))?, 202);

    let ev_a = client_a.next_event(EVENT_TIMEOUT)?;
    let ev_b = client_b.next_event(EVENT_TIMEOUT)?;

    // Each session's initialize response must land on its own SSE
    // stream with its own id.
    assert_eq!(response_id(&ev_a.data)?, json!(101));
    assert_eq!(response_id(&ev_b.data)?, json!(202));

    // tools/list interleaved across both sessions; both must succeed
    // and the responses must route back correctly.
    assert_eq!(client_a.post(&tools_list(102))?, 202);
    assert_eq!(client_b.post(&tools_list(203))?, 202);
    let ev_a = client_a.next_event(EVENT_TIMEOUT)?;
    let ev_b = client_b.next_event(EVENT_TIMEOUT)?;

    assert_eq!(response_id(&ev_a.data)?, json!(102));
    assert_eq!(response_id(&ev_b.data)?, json!(203));
    assert!(tools_count(&ev_a.data)? > 0);
    assert!(tools_count(&ev_b.data)? > 0);

    Ok(())
}

/// POST to a fabricated `sessionId` (i.e., the SSE never opened) must
/// reject with `410 Gone`. This is what the client uses to learn it
/// should reconnect on `/mcp/sse`.
#[test]
fn test_sse_post_to_unknown_session_returns_410() -> Result<()> {
    let server = SseServer::spawn()?;
    let url = format!(
        "{}/mcp/message?sessionId=00000000-0000-0000-0000-000000000000",
        server.base_url()
    );
    let resp = reqwest::blocking::Client::new()
        .post(&url)
        .json(&initialize(1, "test-client"))
        .send()?;
    assert_eq!(resp.status().as_u16(), 410);
    Ok(())
}

/// JSON-RPC notifications (no `id`) must not produce an SSE response.
/// `initialized` is the canonical client-to-server notification in the
/// MCP handshake.
#[test]
fn test_sse_notification_produces_no_response() -> Result<()> {
    let server = SseServer::spawn()?;
    let client = SseClient::open(&server.base_url())?;
    assert_eq!(client.post(&initialize(1, "test-client"))?, 202);
    let _ = client.next_event(EVENT_TIMEOUT)?;

    let notification = json!({
        "jsonrpc": "2.0",
        "method": "initialized",
        "params": {}
    });
    assert_eq!(client.post(&notification)?, 202);

    // Wait briefly; no SSE event should arrive.
    assert!(
        client.try_next_event(Duration::from_millis(500)).is_none(),
        "notification must not generate an SSE response"
    );
    Ok(())
}

/// Non-loopback `Host` headers must be rejected on `/mcp/*` to mitigate
/// DNS rebinding attacks against the local server.
#[test]
fn test_sse_rejects_non_loopback_host_header() -> Result<()> {
    let server = SseServer::spawn()?;
    let url = format!("{}/mcp/sse", server.base_url());
    let resp = reqwest::blocking::Client::new()
        .get(&url)
        .header("Host", "evil.example")
        .send()?;
    assert_eq!(resp.status().as_u16(), 403);
    Ok(())
}
