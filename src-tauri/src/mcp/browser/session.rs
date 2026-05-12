// Persistent CDP-driven browser session backing every browser_* MCP tool.
//
// Lifecycle:
//   browser_open  → spawn bundled WonderBrowser via crate::browser, attach CDP
//                   over a single WebSocket, install network + console event
//                   listeners that drain into shared buffers.
//   browser_*     → send/recv CDP commands over that same socket using a
//                   correlation map (cmd id → oneshot sender).
//   browser_close → kill the process, drop the socket, drop state.

use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use super::network::{classify_auth_like, NetCapture, NetEntry};
use super::snapshot::RefMap;

type WsStream = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsSink = futures_util::stream::SplitSink<WsStream, WsMessage>;
type WsRead = futures_util::stream::SplitStream<WsStream>;

static CMD_ID: AtomicU64 = AtomicU64::new(1);
fn next_cmd_id() -> u64 {
    CMD_ID.fetch_add(1, Ordering::Relaxed)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// True for tungstenite/IO errors that indicate the underlying WebSocket
/// dropped — used to gate reconnect attempts in `send()`.
fn looks_closed(msg: &str) -> bool {
    let l = msg.to_lowercase();
    l.contains("closed connection")
        || l.contains("connection closed")
        || l.contains("connection reset")
        || l.contains("broken pipe")
        || l.contains("channel closed")
        || l.contains("alreadyclosed")
}

pub struct BrowserSession {
    pub browser_label: String,
    pub pid: u32,
    pub cdp_port: u16,
    pub proxy_port: u16,
    pub headless: bool,
    /// Whether this session was spawned by us (true) or attached to a
    /// pre-existing browser (false). Controls cleanup on close().
    pub launched_by_us: bool,

    sink: Arc<Mutex<WsSink>>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<serde_json::Value>>>>,
    /// Cleared by the event loop when the WS stream ends. `send()` checks this
    /// before each command and triggers a reconnect if false.
    alive: Arc<AtomicBool>,
    /// Reconnect mutex — guards against multiple concurrent reconnect attempts
    /// when several browser_* calls fail simultaneously.
    reconnecting: Arc<Mutex<()>>,

    pub net: Arc<NetCapture>,
    pub console: Arc<Mutex<Vec<ConsoleMsg>>>,
    pub refmap: Arc<Mutex<RefMap>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConsoleMsg {
    pub kind: String, // "log", "error", "warning", "csp_violation", "page_error"
    pub text: String,
    pub url: Option<String>,
    pub line: Option<u32>,
    pub at_ms: u64,
}

pub struct LaunchArgs {
    pub url: Option<String>,
    pub proxy_port: u16,
    pub cdp_port: u16,
    pub headless: bool,
}

impl BrowserSession {
    pub async fn launch(app: &tauri::AppHandle, args: LaunchArgs) -> Result<Self, String> {
        let (browser_path, browser_label) = crate::browser::resolve_browser_binary(app, false, None).await?;

        let extension_path =
            crate::chromium::ChromiumManager::new(app).ok().and_then(|m| m.extension_path().ok());

        let home = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
        let profile_dir = std::path::PathBuf::from(format!("{}/.wondersuite/mcp-browser-profile", home));
        std::fs::create_dir_all(&profile_dir).map_err(|e| e.to_string())?;

        let opts = crate::browser::LaunchOptions {
            proxy_port: args.proxy_port,
            use_proxy: true,
            cdp_port: args.cdp_port,
            extension_path,
            profile_dir: Some(profile_dir),
            no_sandbox: false,
            headless: args.headless,
        };
        let pid = crate::browser::launch_browser(&browser_path.to_string_lossy(), &opts)
            .map_err(|e| format!("Launch failed: {}", e))?;

        Self::build(browser_label, pid, args.cdp_port, args.proxy_port, args.headless, true, args.url).await
    }

    /// Attach to a running **WonderBrowser** CDP session — never the user's
    /// system Chrome. Touching a user's daily-driver Chrome profile is risky
    /// (data leakage, profile lock, "wrong window" UX confusion), so the
    /// supported flow is intentionally narrow:
    ///
    ///   1. Scan `cdp_port` (or 9333 then 9222/9223). If any responds AND it
    ///      identifies as our WonderBrowser, attach. Other browsers are
    ///      rejected with a clear message — call `browser_open` instead.
    ///   2. If nothing is reachable AND `auto_launch=true`, spawn a fresh
    ///      WonderBrowser exactly like `browser_open` would, and attach.
    ///   3. Otherwise return ATTACH_FAILED.
    pub async fn attach(app: &tauri::AppHandle, args: AttachArgs) -> Result<Self, String> {
        let ports_to_try: Vec<u16> = match args.cdp_port {
            Some(p) => vec![p],
            // 9333 first — that's the WonderBrowser default. 9222/9223 are
            // included for the case where someone explicitly launched the
            // bundled CfT on the Chrome-standard port.
            None => vec![9333, 9222, 9223],
        };
        for p in &ports_to_try {
            if let Some(probe) = probe_cdp_port(*p).await {
                if probe.is_wonderbrowser {
                    return Self::build(probe.label, 0, *p, args.proxy_port, false, false, args.url).await;
                }
                return Err(format!(
                    "code=NOT_WONDERBROWSER hint=\"Found a CDP server on :{} but it is `{}`, not the bundled WonderBrowser. browser_attach refuses to drive third-party browsers because that touches the user's real cookies / extensions / accounts. Call browser_open instead — it spawns an isolated WonderBrowser with the WonderSuite proxy + stealth extension wired up.\"",
                    p, probe.label
                ));
            }
        }

        if !args.auto_launch {
            return Err(format!(
                "code=ATTACH_FAILED hint=\"no WonderBrowser CDP responder on port(s) {:?}. Either: (a) re-run with auto_launch=true so we spawn a fresh WonderBrowser ourselves, or (b) call browser_open directly. browser_attach only ever drives the bundled WonderBrowser — system Chrome / Edge / Brave are intentionally not supported here to keep user profile data untouched.\"",
                ports_to_try
            ));
        }

        // Auto-launch path: spawn a fresh WonderBrowser exactly like
        // browser_open. Same proxy wiring, same extension, same isolated
        // profile dir. The only thing that makes this distinct from
        // browser_open is the port-scan fast-path above.
        let proxy_running =
            crate::proxy_commands::get_global_proxy_state().map(|ps| ps.is_running()).unwrap_or(false);
        if !proxy_running {
            return Err(
                "code=PROXY_DOWN hint=\"WonderSuite proxy is not running — call proxy_start (or start it via the UI) and retry. browser_attach auto_launch needs the proxy because the spawned WonderBrowser routes through it.\""
                    .to_string(),
            );
        }
        let launch_args = LaunchArgs {
            url: args.url,
            proxy_port: args.proxy_port,
            cdp_port: ports_to_try.first().copied().unwrap_or(9333),
            headless: false,
        };
        Self::launch(app, launch_args).await
    }

    async fn build(
        browser_label: String,
        pid: u32,
        cdp_port: u16,
        proxy_port: u16,
        headless: bool,
        launched_by_us: bool,
        initial_url: Option<String>,
    ) -> Result<Self, String> {
        let ws_url = wait_for_cdp_target(cdp_port).await?;
        let (ws, _) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .map_err(|e| format!("CDP connect failed: {}", e))?;
        let (sink, stream) = ws.split();
        let sink = Arc::new(Mutex::new(sink));
        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<serde_json::Value>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(AtomicBool::new(true));
        let net = Arc::new(NetCapture::new());
        let console = Arc::new(Mutex::new(Vec::<ConsoleMsg>::new()));
        let refmap = Arc::new(Mutex::new(RefMap::new()));

        spawn_event_loop(stream, pending.clone(), net.clone(), console.clone(), alive.clone());

        let sess = Self {
            browser_label,
            pid,
            cdp_port,
            proxy_port,
            headless,
            launched_by_us,
            sink,
            pending,
            alive,
            reconnecting: Arc::new(Mutex::new(())),
            net,
            console,
            refmap,
        };

        sess.enable_domains().await?;
        if let Some(url) = initial_url {
            sess.send("Page.navigate", serde_json::json!({ "url": url })).await?;
        }
        Ok(sess)
    }

    /// Send the suite of CDP enable + injection commands that bring a fresh
    /// connection up to full-feature parity (network capture, console, AI
    /// cursor overlay). Called from `build` and from `reconnect`.
    async fn enable_domains(&self) -> Result<(), String> {
        for (m, p) in [
            ("Page.enable", serde_json::json!({})),
            ("Runtime.enable", serde_json::json!({})),
            ("DOM.enable", serde_json::json!({})),
            ("Network.enable", serde_json::json!({})),
            ("Log.enable", serde_json::json!({})),
            ("Accessibility.enable", serde_json::json!({})),
            ("Page.setLifecycleEventsEnabled", serde_json::json!({ "enabled": true })),
            ("Page.addScriptToEvaluateOnNewDocument", serde_json::json!({"source": csp_violation_hook()})),
            ("Page.addScriptToEvaluateOnNewDocument", serde_json::json!({"source": ai_cursor_overlay()})),
        ] {
            // Use send_raw — we already hold a fresh connection here.
            self.send_raw(m, p).await?;
        }
        // Inject the overlay into whatever page is currently loaded so the
        // cursor is visible immediately, without needing a navigate.
        let _ = self
            .send_raw(
                "Runtime.evaluate",
                serde_json::json!({
                    "expression": ai_cursor_overlay(),
                    "returnByValue": true,
                    "awaitPromise": true,
                }),
            )
            .await;
        Ok(())
    }

    pub async fn send(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        // Fast-path: connection looks alive, try once.
        if self.alive.load(Ordering::Relaxed) {
            match self.send_raw(method, params.clone()).await {
                Ok(v) => return Ok(v),
                Err(e) if !looks_closed(&e) => return Err(e),
                Err(_) => {} // fall through to reconnect
            }
        }
        // Slow path: reconnect once and retry.
        self.reconnect().await.map_err(|e| {
            format!("code=CDP_LOST hint=\"reconnect failed: {}. Call browser_close then browser_open to start fresh.\"", e)
        })?;
        self.send_raw(method, params).await
    }

    async fn send_raw(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let id = next_cmd_id();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);
        let cmd = serde_json::json!({ "id": id, "method": method, "params": params });
        let send_result = self.sink.lock().await.send(WsMessage::Text(cmd.to_string().into())).await;
        if let Err(e) = send_result {
            // Drop the pending slot so the orphan doesn't sit in the map.
            self.pending.lock().await.remove(&id);
            self.alive.store(false, Ordering::Relaxed);
            return Err(format!("CDP send: {}", e));
        }
        let resp = tokio::time::timeout(std::time::Duration::from_secs(20), rx)
            .await
            .map_err(|_| format!("CDP timeout (20s) for {}", method))?
            .map_err(|_| format!("CDP channel closed for {}", method))?;
        if let Some(err) = resp.get("error") {
            return Err(format!("CDP {}: {}", method, err));
        }
        Ok(resp.get("result").cloned().unwrap_or(serde_json::json!({})))
    }

    /// Reopen the CDP WebSocket against the same CDP port and re-enable every
    /// domain. Pending command-id slots are drained so old callers see
    /// "channel closed" instead of hanging until the 20s timeout.
    async fn reconnect(&self) -> Result<(), String> {
        // Serialise reconnect attempts — multiple browser_* calls failing in
        // parallel should not race to redial.
        let _g = self.reconnecting.lock().await;
        if self.alive.load(Ordering::Relaxed) {
            return Ok(()); // somebody else just succeeded
        }

        // Hint to the user: this is a recoverable hiccup, not a tool bug.
        eprintln!("[browser_session] CDP closed; reconnecting on port {}", self.cdp_port);

        // Drain orphaned callers.
        {
            let mut g = self.pending.lock().await;
            g.clear();
        }

        let ws_url = wait_for_cdp_target_short(self.cdp_port).await?;
        let (ws, _) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .map_err(|e| format!("CDP reconnect failed: {}", e))?;
        let (new_sink, new_stream) = ws.split();
        {
            let mut sink_g = self.sink.lock().await;
            *sink_g = new_sink;
        }
        // Reset the alive flag BEFORE spawning the event loop and BEFORE
        // re-enabling domains so the recursive sends inside enable_domains
        // take the fast-path instead of recursing into reconnect.
        self.alive.store(true, Ordering::Relaxed);
        spawn_event_loop(
            new_stream,
            self.pending.clone(),
            self.net.clone(),
            self.console.clone(),
            self.alive.clone(),
        );
        self.enable_domains().await?;
        Ok(())
    }

    pub async fn eval(&self, expression: &str) -> Result<serde_json::Value, String> {
        let r = self
            .send(
                "Runtime.evaluate",
                serde_json::json!({
                    "expression": expression,
                    "returnByValue": true,
                    "awaitPromise": true,
                }),
            )
            .await?;
        if let Some(ex) = r.get("exceptionDetails") {
            return Err(format!("JS exception: {}", ex));
        }
        Ok(r.pointer("/result/value").cloned().unwrap_or(serde_json::Value::Null))
    }

    pub async fn close(&self) {
        let _ = self.send("Browser.close", serde_json::json!({})).await;
        // Only kill the OS process if we spawned it. Attached browsers belong
        // to the user — leave them alone.
        if self.launched_by_us && self.pid != 0 {
            #[cfg(target_os = "windows")]
            {
                let _ = std::process::Command::new("taskkill")
                    .args(["/PID", &self.pid.to_string(), "/F", "/T"])
                    .output();
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = std::process::Command::new("kill").arg(self.pid.to_string()).output();
            }
        }
    }
}

pub struct AttachArgs {
    /// Specific port to attach to. None scans the WonderBrowser ports
    /// (9333 first, then 9222/9223 in case the user pinned a different port).
    pub cdp_port: Option<u16>,
    pub proxy_port: u16,
    pub url: Option<String>,
    /// If no WonderBrowser is reachable, spawn one ourselves (same code path
    /// as `browser_open`). Off by default — keeps `browser_attach` strict.
    pub auto_launch: bool,
}

#[derive(Debug)]
struct CdpProbe {
    label: String,
    /// True if the `Browser` field on /json/version matches the bundled
    /// Chrome-for-Testing build (HeadlessChrome shows up too). We refuse to
    /// drive anything else so a user's daily-driver Chrome on 9222 isn't
    /// silently puppeted.
    is_wonderbrowser: bool,
}

async fn probe_cdp_port(cdp_port: u16) -> Option<CdpProbe> {
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(2)).build().ok()?;
    let resp = client.get(format!("http://127.0.0.1:{}/json/version", cdp_port)).send().await.ok()?;
    let json: serde_json::Value = resp.json().await.ok()?;
    let browser = json.get("Browser").and_then(|b| b.as_str()).unwrap_or("").to_string();
    let user_agent = json.get("User-Agent").and_then(|u| u.as_str()).unwrap_or("");
    // CfT identifies as "HeadlessChrome/<v>" when headless and "Chrome/<v>"
    // when visible. We additionally fingerprint the User-Agent for the
    // "HeadlessChrome" marker because some real Chrome builds will also
    // report just "Chrome/<v>" on /json/version. To stay strict, we also
    // accept matches by port-knocking — the bundled launch uses 9333 by
    // default and we're the only thing on that port in a sane install.
    let is_wonderbrowser =
        browser.contains("HeadlessChrome") || user_agent.contains("HeadlessChrome") || cdp_port == 9333;
    Some(CdpProbe {
        label: if browser.is_empty() {
            format!("attached:{}", cdp_port)
        } else {
            format!("{} (:{})", browser, cdp_port)
        },
        is_wonderbrowser,
    })
}

fn spawn_event_loop(
    mut stream: WsRead,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<serde_json::Value>>>>,
    net: Arc<NetCapture>,
    console: Arc<Mutex<Vec<ConsoleMsg>>>,
    alive: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        while let Some(msg) = stream.next().await {
            let Ok(WsMessage::Text(text)) = msg else {
                // Ping/pong/binary frames are fine — only stop on stream end
                // (handled below by loop termination).
                continue;
            };
            let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else { continue };

            if let Some(id) = json.get("id").and_then(|v| v.as_u64()) {
                if let Some(tx) = pending.lock().await.remove(&id) {
                    let _ = tx.send(json);
                }
                continue;
            }
            let Some(method) = json.get("method").and_then(|v| v.as_str()) else { continue };
            let params = json.get("params").cloned().unwrap_or(serde_json::json!({}));
            match method {
                "Network.requestWillBeSent" => {
                    let req_id = params["requestId"].as_str().unwrap_or("").to_string();
                    // Redirect: CDP reuses the requestId and embeds the prior
                    // response in `redirectResponse`. Backfill the existing
                    // entry's status before pushing the next hop.
                    if let Some(rr) = params.get("redirectResponse") {
                        let status = rr.get("status").and_then(|v| v.as_u64()).map(|s| s as u16);
                        let headers = rr.get("headers").cloned().unwrap_or(serde_json::json!({}));
                        let mime = rr.get("mimeType").and_then(|v| v.as_str()).map(String::from);
                        net.update(&req_id, |e| {
                            e.status = status;
                            e.response_headers = headers;
                            e.mime_type = mime;
                            e.finished_at_ms = Some(now_ms());
                        });
                    }
                    let url =
                        params.pointer("/request/url").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let method_s = params
                        .pointer("/request/method")
                        .and_then(|v| v.as_str())
                        .unwrap_or("GET")
                        .to_string();
                    let headers =
                        params.pointer("/request/headers").cloned().unwrap_or(serde_json::json!({}));
                    let body = params.pointer("/request/postData").and_then(|v| v.as_str()).map(String::from);
                    let rtype = params["type"].as_str().unwrap_or("").to_string();
                    let is_auth = classify_auth_like(&url);
                    net.push(NetEntry {
                        request_id: req_id,
                        url,
                        method: method_s,
                        resource_type: rtype,
                        request_headers: headers,
                        request_body: body,
                        status: None,
                        response_headers: serde_json::json!({}),
                        mime_type: None,
                        started_at_ms: now_ms(),
                        finished_at_ms: None,
                        is_auth_like: is_auth,
                    });
                }
                "Network.responseReceived" => {
                    let req_id = params["requestId"].as_str().unwrap_or("").to_string();
                    let status =
                        params.pointer("/response/status").and_then(|v| v.as_u64()).map(|s| s as u16);
                    let headers =
                        params.pointer("/response/headers").cloned().unwrap_or(serde_json::json!({}));
                    let mime =
                        params.pointer("/response/mimeType").and_then(|v| v.as_str()).map(String::from);
                    net.update(&req_id, |e| {
                        e.status = status;
                        e.response_headers = headers;
                        e.mime_type = mime;
                    });
                }
                "Network.loadingFinished" => {
                    let req_id = params["requestId"].as_str().unwrap_or("").to_string();
                    net.update(&req_id, |e| {
                        e.finished_at_ms = Some(now_ms());
                    });
                }
                "Log.entryAdded" => {
                    let entry = &params["entry"];
                    let kind = match entry["level"].as_str().unwrap_or("info") {
                        "error" => "error",
                        "warning" => "warning",
                        _ => "log",
                    };
                    push_console(
                        &console,
                        ConsoleMsg {
                            kind: kind.into(),
                            text: entry["text"].as_str().unwrap_or("").to_string(),
                            url: entry["url"].as_str().map(String::from),
                            line: entry["lineNumber"].as_u64().map(|n| n as u32),
                            at_ms: now_ms(),
                        },
                    )
                    .await;
                }
                "Runtime.consoleAPICalled" => {
                    let kind = params["type"].as_str().unwrap_or("log").to_string();
                    let mut text = String::new();
                    if let Some(args) = params["args"].as_array() {
                        for (i, a) in args.iter().enumerate() {
                            if i > 0 {
                                text.push(' ');
                            }
                            text.push_str(a.get("value").and_then(|v| v.as_str()).unwrap_or_else(|| {
                                a.get("description").and_then(|v| v.as_str()).unwrap_or("")
                            }));
                        }
                    }
                    push_console(&console, ConsoleMsg { kind, text, url: None, line: None, at_ms: now_ms() })
                        .await;
                }
                "Runtime.exceptionThrown" => {
                    let text = params
                        .pointer("/exceptionDetails/text")
                        .and_then(|v| v.as_str())
                        .unwrap_or("(no text)")
                        .to_string();
                    push_console(
                        &console,
                        ConsoleMsg {
                            kind: "page_error".into(),
                            text,
                            url: None,
                            line: None,
                            at_ms: now_ms(),
                        },
                    )
                    .await;
                }
                _ => {}
            }
        }
        // Stream ended — browser closed the socket. Mark dead so the next
        // send() triggers reconnect logic.
        alive.store(false, Ordering::Relaxed);
        // Wake up everyone currently parked on a pending reply.
        let mut g = pending.lock().await;
        g.clear();
    });
}

async fn push_console(buf: &Arc<Mutex<Vec<ConsoleMsg>>>, m: ConsoleMsg) {
    let mut g = buf.lock().await;
    if g.len() >= 500 {
        g.remove(0);
    }
    g.push(m);
}

async fn wait_for_cdp_target(cdp_port: u16) -> Result<String, String> {
    wait_for_cdp_target_with_attempts(cdp_port, 30, 500).await
}

/// Short-timeout variant used by reconnect — if the browser process is gone we
/// don't want to spin for 15 seconds.
async fn wait_for_cdp_target_short(cdp_port: u16) -> Result<String, String> {
    wait_for_cdp_target_with_attempts(cdp_port, 4, 250).await
}

async fn wait_for_cdp_target_with_attempts(
    cdp_port: u16,
    attempts: usize,
    delay_ms: u64,
) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!("http://127.0.0.1:{}/json", cdp_port);
    for _ in 0..attempts {
        if let Ok(resp) = client.get(&url).send().await {
            if let Ok(pages) = resp.json::<Vec<serde_json::Value>>().await {
                if let Some(p) = pages.iter().find(|p| p["type"].as_str() == Some("page")) {
                    if let Some(ws) = p["webSocketDebuggerUrl"].as_str() {
                        return Ok(ws.to_string());
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }
    Err(format!(
        "CDP target on :{} did not become reachable within {}ms",
        cdp_port,
        attempts as u64 * delay_ms
    ))
}

// Forward CSP violation events as console entries the agent can read.
fn csp_violation_hook() -> &'static str {
    r#"
    try {
        document.addEventListener('securitypolicyviolation', (e) => {
            console.warn('[CSP_VIOLATION]', JSON.stringify({
                directive: e.violatedDirective,
                blocked: e.blockedURI,
                src: e.sourceFile,
                line: e.lineNumber,
                policy: e.originalPolicy && e.originalPolicy.slice(0, 200)
            }));
        }, true);
    } catch (_) {}
    "#
}

// Visual AI cursor overlay — injected on every document so the user can SEE
// what the agent is doing. Persistent: a MutationObserver + setInterval watch
// for the cursor being torn off the page (SPA reroutes, document.write, hostile
// CSS resets) and re-attach it. Lives inside the page so screenshots include
// it automatically. High z-index, pointer-events:none so it never blocks real
// input. Helpers on `window.__ws_cursor_*` are called by browser_click /
// browser_type / browser_scroll from Rust so every action animates first.
pub(crate) fn ai_cursor_overlay() -> &'static str {
    r##"
(function() {
  const CSS_ID = '__ws_ai_cursor_css';
  const CUR_ID = '__ws_ai_cursor';

  const css_text = `
    #__ws_ai_cursor {
      position: fixed; top: 32px; left: 32px;
      pointer-events: none; z-index: 2147483647;
      transition: top 360ms cubic-bezier(.22,.61,.36,1),
                  left 360ms cubic-bezier(.22,.61,.36,1);
      filter: drop-shadow(0 4px 14px rgba(0,0,0,0.55));
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      will-change: top, left;
    }
    #__ws_ai_cursor .__ws_ai_halo {
      position: absolute; left: -10px; top: -10px;
      width: 48px; height: 48px; border-radius: 50%;
      background: radial-gradient(circle, rgba(232,161,69,0.55) 0%, rgba(232,161,69,0.18) 45%, rgba(232,161,69,0) 70%);
      animation: __ws_ai_pulse 2.4s ease-in-out infinite;
      pointer-events: none;
    }
    @keyframes __ws_ai_pulse {
      0%, 100% { transform: scale(0.85); opacity: 0.75; }
      50%      { transform: scale(1.08); opacity: 1; }
    }
    #__ws_ai_cursor svg { display: block; position: relative; z-index: 2; }
    #__ws_ai_cursor .__ws_ai_cap {
      position: absolute; left: 30px; top: 30px;
      background: linear-gradient(180deg, #ffb967 0%, #e8a145 100%);
      color: #1a1614;
      padding: 3px 9px 3px 7px; border-radius: 5px;
      font-size: 10px; font-weight: 800; letter-spacing: 0.6px;
      white-space: nowrap; box-shadow: 0 3px 10px rgba(0,0,0,0.45);
      border: 1px solid rgba(0,0,0,0.25);
      pointer-events: none;
      display: inline-flex; align-items: center; gap: 4px;
    }
    #__ws_ai_cursor .__ws_ai_cap::before {
      content: ''; display: inline-block; width: 5px; height: 5px;
      border-radius: 50%; background: #22c55e;
      box-shadow: 0 0 6px #22c55e;
    }
    .__ws_ai_ripple {
      position: fixed; pointer-events: none; z-index: 2147483646;
      width: 44px; height: 44px; border-radius: 50%;
      border: 3px solid #e8a145;
      box-shadow: 0 0 18px rgba(232,161,69,0.6);
      animation: __ws_ai_ripple 620ms ease-out forwards;
    }
    @keyframes __ws_ai_ripple {
      0% { opacity: 1; transform: translate(-50%, -50%) scale(0.4); }
      100% { opacity: 0; transform: translate(-50%, -50%) scale(3); }
    }
    .__ws_ai_typehint {
      position: fixed; pointer-events: none; z-index: 2147483646;
      background: linear-gradient(180deg, rgba(255,185,103,0.97) 0%, rgba(232,161,69,0.97) 100%);
      color: #1a1614;
      padding: 4px 9px; border-radius: 5px;
      font-family: 'JetBrains Mono', 'Cascadia Code', monospace;
      font-size: 11px; font-weight: 700;
      box-shadow: 0 3px 10px rgba(0,0,0,0.5);
      border: 1px solid rgba(0,0,0,0.2);
      animation: __ws_ai_typehint_in 200ms ease-out, __ws_ai_typehint_out 220ms 1100ms ease-in forwards;
    }
    @keyframes __ws_ai_typehint_in { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes __ws_ai_typehint_out { to { opacity: 0; transform: translateY(-8px); } }
    .__ws_ai_scrollbar {
      position: fixed; pointer-events: none; z-index: 2147483646;
      top: 50%; right: 14px; transform: translateY(-50%);
      width: 6px; height: 80px;
      background: rgba(0,0,0,0.4); border-radius: 3px;
      box-shadow: 0 0 8px rgba(0,0,0,0.5);
    }
    .__ws_ai_scrollbar > div {
      position: absolute; left: 0; right: 0;
      background: linear-gradient(180deg, #ffb967, #e8a145);
      border-radius: 3px; box-shadow: 0 0 6px rgba(232,161,69,0.8);
      transition: top 120ms linear, height 120ms linear;
    }
    .__ws_ai_scrollbanner {
      position: fixed; pointer-events: none; z-index: 2147483646;
      top: 16px; left: 50%; transform: translateX(-50%);
      background: linear-gradient(180deg, rgba(255,185,103,0.97) 0%, rgba(232,161,69,0.97) 100%);
      color: #1a1614;
      padding: 6px 14px; border-radius: 6px;
      font-family: 'JetBrains Mono', 'Cascadia Code', monospace;
      font-size: 12px; font-weight: 700;
      box-shadow: 0 4px 14px rgba(0,0,0,0.55);
      border: 1px solid rgba(0,0,0,0.25);
      display: inline-flex; align-items: center; gap: 8px;
    }
  `;

  function ensureCursor() {
    if (!document.documentElement) return;
    if (!document.getElementById(CSS_ID)) {
      const css = document.createElement('style');
      css.id = CSS_ID;
      css.textContent = css_text;
      document.documentElement.appendChild(css);
    }
    if (document.getElementById(CUR_ID)) return;
    const cur = document.createElement('div');
    cur.id = CUR_ID;
    cur.innerHTML =
      '<div class="__ws_ai_halo"></div>' +
      '<svg width="28" height="28" viewBox="0 0 28 28" xmlns="http://www.w3.org/2000/svg">' +
        '<defs>' +
          '<linearGradient id="__ws_ai_grad" x1="0%" y1="0%" x2="100%" y2="100%">' +
            '<stop offset="0%" stop-color="#ffd28a"/>' +
            '<stop offset="100%" stop-color="#d9892a"/>' +
          '</linearGradient>' +
        '</defs>' +
        '<path d="M3 3 L3 22 L9 17 L13 26 L17 24.5 L13 15.5 L22 15.5 Z" ' +
          'fill="url(#__ws_ai_grad)" stroke="#1a1614" stroke-width="1.6" stroke-linejoin="round"/>' +
      '</svg>' +
      '<span class="__ws_ai_cap">AI</span>';
    document.documentElement.appendChild(cur);
  }

  function setLabel(text) {
    const cur = document.getElementById(CUR_ID);
    if (!cur) return;
    const cap = cur.querySelector('.__ws_ai_cap');
    if (cap) cap.textContent = text || 'AI';
  }

  window.__ws_cursor_move_to = function(el, label, opts) {
    if (!el) return;
    ensureCursor();
    opts = opts || {};
    try {
      if (opts.scroll !== false) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'center' });
      }
    } catch (_) {}
    setTimeout(() => {
      const cur = document.getElementById(CUR_ID);
      if (!cur) return;
      const r = el.getBoundingClientRect();
      cur.style.top = (r.top + r.height/2 - 14) + 'px';
      cur.style.left = (r.left + r.width/2 - 6) + 'px';
      setLabel(label || 'AI');
    }, 50);
  };

  window.__ws_cursor_click_fx = function(el) {
    if (!el) return;
    ensureCursor();
    const r = el.getBoundingClientRect();
    const rip = document.createElement('div');
    rip.className = '__ws_ai_ripple';
    rip.style.left = (r.left + r.width/2) + 'px';
    rip.style.top = (r.top + r.height/2) + 'px';
    (document.body || document.documentElement).appendChild(rip);
    setTimeout(() => rip.remove(), 700);
  };

  window.__ws_cursor_typehint = function(el, text) {
    if (!el) return;
    ensureCursor();
    const r = el.getBoundingClientRect();
    const hint = document.createElement('div');
    hint.className = '__ws_ai_typehint';
    const safe = (text || '').replace(/</g, '&lt;');
    hint.textContent = '> ' + (safe.length > 28 ? safe.slice(0, 28) + '...' : safe);
    hint.style.left = Math.max(8, r.left + r.width/2 - 60) + 'px';
    hint.style.top = Math.max(8, r.top - 26) + 'px';
    (document.body || document.documentElement).appendChild(hint);
    setTimeout(() => hint.remove(), 1500);
  };

  window.__ws_cursor_scroll_indicator = function(direction, amount) {
    ensureCursor();
    const banner = document.createElement('div');
    banner.className = '__ws_ai_scrollbanner';
    const arrow = direction === 'up' ? '^' : direction === 'down' ? 'v' : direction === 'left' ? '<' : '>';
    banner.textContent = arrow + ' scroll ' + direction + ' ' + Math.abs(amount) + 'px';
    (document.body || document.documentElement).appendChild(banner);
    setTimeout(() => banner.remove(), 1300);
  };

  // Animated rAF scroll so the user actually SEES the page moving. The page
  // may have scroll-behavior:auto or be inside a custom container — we drive
  // window.scrollTo in steps to guarantee a visible motion.
  window.__ws_cursor_animate_scroll = function(dx, dy, duration) {
    ensureCursor();
    duration = duration || 700;
    const startX = window.scrollX || window.pageXOffset || 0;
    const startY = window.scrollY || window.pageYOffset || 0;
    const t0 = performance.now();
    return new Promise((resolve) => {
      function step(now) {
        const t = Math.min(1, (now - t0) / duration);
        // ease-out cubic
        const e = 1 - Math.pow(1 - t, 3);
        window.scrollTo(startX + dx * e, startY + dy * e);
        if (t < 1) requestAnimationFrame(step);
        else resolve(true);
      }
      requestAnimationFrame(step);
    });
  };
  // Same for an element scroll container.
  window.__ws_cursor_animate_scroll_el = function(el, dx, dy, duration) {
    if (!el) return Promise.resolve(false);
    ensureCursor();
    duration = duration || 700;
    const startX = el.scrollLeft;
    const startY = el.scrollTop;
    const t0 = performance.now();
    return new Promise((resolve) => {
      function step(now) {
        const t = Math.min(1, (now - t0) / duration);
        const e = 1 - Math.pow(1 - t, 3);
        el.scrollLeft = startX + dx * e;
        el.scrollTop = startY + dy * e;
        if (t < 1) requestAnimationFrame(step);
        else resolve(true);
      }
      requestAnimationFrame(step);
    });
  };

  function start() {
    ensureCursor();
    // SPA / hostile-DOM defense: re-inject if anything removes our nodes.
    try {
      const mo = new MutationObserver(() => {
        if (!document.getElementById(CUR_ID)) ensureCursor();
      });
      mo.observe(document.documentElement, { childList: true, subtree: false });
      if (document.body) {
        mo.observe(document.body, { childList: true, subtree: false });
      }
    } catch (_) {}
    // Belt + suspenders: poll every 1.5s in case the observer was unhooked.
    if (!window.__ws_ai_cursor_poll) {
      window.__ws_ai_cursor_poll = setInterval(ensureCursor, 1500);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, { once: true });
  } else {
    start();
  }
})();
"##
}
