use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

// ═══════════════════════════════════════════════════════════════════════
//  CDP Network Traffic Capture — Global Store
//  Captures all HTTP(S) traffic from the WonderBrowser via CDP Network domain.
//  The AI agent reads this to see auth flows, API calls, tokens, etc.
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEntry {
    pub id: String,
    pub timestamp: f64,
    pub method: String,
    pub url: String,
    pub request_headers: serde_json::Value,
    pub request_post_data: Option<String>,
    pub status: Option<u16>,
    pub status_text: Option<String>,
    pub response_headers: Option<serde_json::Value>,
    pub response_mime_type: Option<String>,
    pub response_size: Option<u64>,
    pub response_body: Option<String>,
    pub timing_ms: Option<f64>,
    pub resource_type: Option<String>,
    pub initiator_type: Option<String>,
}

/// Global network log — accessible by MCP handlers
static BROWSER_NETWORK_LOG: std::sync::OnceLock<Arc<Mutex<Vec<NetworkEntry>>>> = std::sync::OnceLock::new();
/// Flag: is the CDP network listener actively capturing?
static NETWORK_CAPTURE_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn network_log() -> &'static Arc<Mutex<Vec<NetworkEntry>>> {
    BROWSER_NETWORK_LOG.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

/// Add a network entry to the global log (capped at 2000 entries to prevent OOM)
pub fn push_network_entry(entry: NetworkEntry) {
    if let Ok(mut log) = network_log().lock() {
        if log.len() >= 2000 {
            log.drain(0..500); // Keep last 1500
        }
        log.push(entry);
    }
}

/// Get the current network log snapshot
pub fn get_network_log() -> Vec<NetworkEntry> {
    network_log().lock().map(|l| l.clone()).unwrap_or_default()
}

/// Clear the network log
pub fn clear_network_log() {
    if let Ok(mut log) = network_log().lock() {
        log.clear();
    }
}

/// Get network capture status
pub fn is_network_capture_active() -> bool {
    NETWORK_CAPTURE_ACTIVE.load(std::sync::atomic::Ordering::Relaxed)
}

trait CommandHiddenExt {
    fn new_hidden<S: AsRef<std::ffi::OsStr>>(program: S) -> Command;
}
impl CommandHiddenExt for Command {
    fn new_hidden<S: AsRef<std::ffi::OsStr>>(program: S) -> Command {
        let mut cmd = Command::new(program);
        #[cfg(target_os = "windows")]
        cmd.creation_flags(0x08000000);
        cmd
    }
}

/// WonderSuite Browser — Enterprise-grade anti-detect Chromium launcher.
/// Implements undetected-chromedriver-level stealth patches to bypass
/// Cloudflare, Akamai, PerimeterX, DataDome, and similar WAFs.

#[derive(Debug, Clone, Serialize)]
pub struct BrowserInfo {
    pub name: String,
    pub path: String,
    pub version: String,
    pub engine: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserStatus {
    pub available_browsers: Vec<BrowserInfo>,
    pub active_browser: Option<String>,
    pub profile_dir: String,
    pub proxy_configured: bool,
    pub ca_installed: bool,
}

/// Detect all installed Chromium-based browsers on the system.
pub fn detect_browsers() -> Vec<BrowserInfo> {
    let mut browsers = Vec::new();

    // Chrome paths
    let chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ];
    for path in &chrome_paths {
        if PathBuf::from(path).exists() {
            browsers.push(BrowserInfo {
                name: "Google Chrome".into(),
                path: path.to_string(),
                version: get_browser_version(path),
                engine: "Chromium".into(),
            });
            break;
        }
    }

    // Microsoft Edge (always available on Windows 10+)
    let edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ];
    for path in &edge_paths {
        if PathBuf::from(path).exists() {
            browsers.push(BrowserInfo {
                name: "Microsoft Edge".into(),
                path: path.to_string(),
                version: get_browser_version(path),
                engine: "Chromium".into(),
            });
            break;
        }
    }

    // Brave
    let brave_paths = [
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
    ];
    for path in &brave_paths {
        if PathBuf::from(path).exists() {
            browsers.push(BrowserInfo {
                name: "Brave".into(),
                path: path.to_string(),
                version: get_browser_version(path),
                engine: "Chromium".into(),
            });
            break;
        }
    }

    // Vivaldi
    let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let vivaldi = format!(r"{}\Vivaldi\Application\vivaldi.exe", local);
    if PathBuf::from(&vivaldi).exists() {
        browsers.push(BrowserInfo {
            name: "Vivaldi".into(),
            path: vivaldi,
            version: String::new(),
            engine: "Chromium".into(),
        });
    }

    // Chromium
    let chromium_paths = [
        r"C:\Program Files\Chromium\Application\chrome.exe",
        r"C:\Program Files (x86)\Chromium\Application\chrome.exe",
    ];
    for path in &chromium_paths {
        if PathBuf::from(path).exists() {
            browsers.push(BrowserInfo {
                name: "Chromium".into(),
                path: path.to_string(),
                version: get_browser_version(path),
                engine: "Chromium".into(),
            });
            break;
        }
    }

    browsers
}

fn get_browser_version(path: &str) -> String {
    let parent = PathBuf::from(path).parent().map(|p| p.to_path_buf());
    if let Some(parent) = parent {
        if let Ok(entries) = fs::read_dir(&parent) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.chars().next().map_or(false, |c| c.is_ascii_digit())
                    && name.contains('.')
                    && entry.file_type().map_or(false, |t| t.is_dir())
                {
                    return name;
                }
            }
        }
    }
    String::new()
}

/// Get the WonderSuite Browser profile directory.
fn get_profile_dir() -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".wondersuite").join("browser-profile")
}

/// Install CA certificate into the Windows user trust store.
fn install_ca_cert(ca_cert_path: &PathBuf, profile_dir: &PathBuf) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    if !ca_cert_path.exists() {
        return Ok(false);
    }
    fs::create_dir_all(profile_dir)?;

    let output = Command::new_hidden("certutil")
        .args([
            "-addstore",
            "-user",
            "Root",
            &ca_cert_path.to_string_lossy(),
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            println!("[WonderBrowser] ✓ CA certificate installed to user trust store");
            Ok(true)
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stderr.contains("already in store") || stderr.contains("bereits im Speicher")
                || stdout.contains("already in store") || stdout.contains("bereits im Speicher")
            {
                println!("[WonderBrowser] ✓ CA certificate already trusted");
                Ok(true)
            } else {
                eprintln!("[WonderBrowser] certutil warning: {}", stderr);
                Ok(false)
            }
        }
        Err(e) => {
            eprintln!("[WonderBrowser] certutil not found: {}", e);
            Ok(false)
        }
    }
}

/// Global CDP debugging port — accessible by MCP tools
static CDP_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(9222);
static CDP_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn get_cdp_port() -> u16 {
    CDP_PORT.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn is_cdp_active() -> bool {
    CDP_ACTIVE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Write the stealth JavaScript preload script that patches navigator props,
/// WebGL, Canvas, and WebDriver detection before any page JS runs.
fn write_stealth_preload(profile_dir: &PathBuf) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let preload_path = profile_dir.join("wondersuite-stealth.js");
    // This is the „nuclear option" stealth payload — patches everything
    // that Cloudflare, Akamai, DataDome, PerimeterX etc. check.
    let stealth_js = r#"
// ─── WonderSuite Stealth Payload v2.0 ───
// Patches applied BEFORE any page JavaScript executes.

// 1. navigator.webdriver = undefined (primary Cloudflare check)
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

// 2. Remove automation-related Chrome DevTools Protocol indicators
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
delete window.cdc_adoQpoasnfa76pfcZLmcfl_JSON;
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Object;
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Proxy;
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
for (const key of Object.keys(window)) {
    if (key.startsWith('cdc_') || key.startsWith('__webdriver') || key.startsWith('$cdc_')) {
        delete window[key];
    }
}

// 3. chrome.runtime — must exist but look real
if (!window.chrome) window.chrome = {};
if (!window.chrome.runtime) {
    window.chrome.runtime = {
        connect: function() {},
        sendMessage: function() {},
        id: undefined,
    };
}

// 4. Permissions API — hide "denied" notification permission (Cloudflare checks this)
const originalQuery = window.navigator.permissions?.query;
if (originalQuery) {
    window.navigator.permissions.query = function(params) {
        if (params.name === 'notifications') {
            return Promise.resolve({ state: Notification.permission });
        }
        return originalQuery.call(this, params);
    };
}

// 5. Plugins — Chrome always has at least PDF plugin
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        const arr = [
            { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
            { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' },
        ];
        arr.length = 3;
        arr.item = (i) => arr[i];
        arr.namedItem = (n) => arr.find(p => p.name === n);
        arr.refresh = () => {};
        return arr;
    },
});

// 6. Languages — must match Accept-Language header
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });

// 7. Platform consistency
if (navigator.platform === '') {
    Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
}

// 8. Hardware concurrency — never 0 (dead giveaway for headless)
if (navigator.hardwareConcurrency === 0 || !navigator.hardwareConcurrency) {
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 4 });
}

// 9. WebGL — prevent WebGL fingerprint leaking "SwiftShader" (headless indicator)
const getParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(param) {
    // UNMASKED_VENDOR_WEBGL
    if (param === 37445) return 'Google Inc. (NVIDIA)';
    // UNMASKED_RENDERER_WEBGL
    if (param === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 Direct3D11 vs_5_0 ps_5_0, D3D11)';
    return getParameter.call(this, param);
};
if (typeof WebGL2RenderingContext !== 'undefined') {
    const getParameter2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(param) {
        if (param === 37445) return 'Google Inc. (NVIDIA)';
        if (param === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 Direct3D11 vs_5_0 ps_5_0, D3D11)';
        return getParameter2.call(this, param);
    };
}

// 10. Prevent iframe-based detection of automation
const originalAttachShadow = Element.prototype.attachShadow;
if (originalAttachShadow) {
    Element.prototype.attachShadow = function(init) {
        if (init && init.mode === 'closed') init.mode = 'open';
        return originalAttachShadow.call(this, init);
    };
}

// 11. Connection type — never missing (Cloudflare checks this)
if (!navigator.connection) {
    Object.defineProperty(navigator, 'connection', {
        get: () => ({
            effectiveType: '4g',
            rtt: 50,
            downlink: 10,
            saveData: false,
        }),
    });
}

// 12. Screen dimensions — never 0x0
if (screen.width === 0 || screen.height === 0) {
    Object.defineProperty(screen, 'width', { get: () => 1920 });
    Object.defineProperty(screen, 'height', { get: () => 1080 });
    Object.defineProperty(screen, 'availWidth', { get: () => 1920 });
    Object.defineProperty(screen, 'availHeight', { get: () => 1040 });
    Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
    Object.defineProperty(screen, 'pixelDepth', { get: () => 24 });
}

console.log('%c[WonderSuite] Stealth patches active', 'color: #7aa0ff; font-weight: bold;');
"#;

    fs::write(&preload_path, stealth_js)?;
    Ok(preload_path)
}

/// Launch the WonderSuite Browser with enterprise-grade anti-detect + CDP + proxy.
///
/// Anti-detect strategy (matches undetected-chromedriver / puppeteer-extra-stealth):
/// 1. Chrome flags that remove automation indicators
/// 2. JavaScript preload script that patches navigator/WebGL/permissions
/// 3. Realistic user-agent and window properties
pub fn launch_browser(
    browser_path: &str,
    proxy_port: u16,
    ca_cert_path: Option<&PathBuf>,
    use_proxy: bool,
    cdp_port: u16,
) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
    let profile_dir = get_profile_dir();
    fs::create_dir_all(&profile_dir)?;

    // Try to install CA cert
    let _ca_installed = if let Some(cert_path) = ca_cert_path {
        install_ca_cert(cert_path, &profile_dir).unwrap_or(false)
    } else {
        false
    };

    // Write the stealth preload script
    let preload_path = write_stealth_preload(&profile_dir)?;

    // ── Build launch arguments ──
    let mut args: Vec<String> = Vec::new();

    // === CDP (Chrome DevTools Protocol) ===
    args.push(format!("--remote-debugging-port={}", cdp_port));
    args.push("--remote-allow-origins=*".into());

    // === Proxy (optional) ===
    if use_proxy {
        args.push(format!("--proxy-server=127.0.0.1:{}", proxy_port));
    }

    // === Isolated Profile ===
    args.push(format!("--user-data-dir={}", profile_dir.to_string_lossy()));

    // ════════════════════════════════════════════════════════════════
    // ANTI-DETECT FLAGS — Enterprise-grade, defeats Cloudflare/Akamai
    // ════════════════════════════════════════════════════════════════

    // Core automation concealment (THE most important flags)
    args.push("--disable-blink-features=AutomationControlled".into());

    // Remove "Chrome is being controlled by automated test software" bar
    // This is done via --disable-infobars AND excludeSwitches
    args.push("--disable-infobars".into());

    // Critical: exclude the enable-automation switch that sets navigator.webdriver=true
    // This is the EXACT mechanism undetected-chromedriver uses
    args.push("--flag-switches-begin".into());
    args.push("--flag-switches-end".into());

    // Disable features that leak automation state
    args.push("--disable-features=IsolateOrigins,site-per-process,AutomationControlled,TranslateUI".into());
    args.push("--disable-site-isolation-trials".into());
    args.push("--disable-ipc-flooding-protection".into());

    // === Privacy / Anti-Fingerprint ===
    args.push("--disable-client-side-phishing-detection".into());
    args.push("--disable-default-apps".into());
    args.push("--disable-component-update".into());
    args.push("--disable-background-networking".into());
    args.push("--disable-sync".into());
    args.push("--disable-translate".into());
    args.push("--metrics-recording-only".into());
    args.push("--no-first-run".into());
    args.push("--no-default-browser-check".into());
    args.push("--disable-breakpad".into());
    args.push("--disable-hang-monitor".into());

    // Force a real-looking window size (not the telltale 800x600 default)
    args.push("--window-size=1920,1080".into());
    args.push("--start-maximized".into());

    // === TLS Certificate Handling ===
    // Our CA is installed in the trust store, but as fallback:
    args.push("--ignore-certificate-errors".into());
    args.push("--allow-insecure-localhost".into());

    // === Extension preloading for stealth patches ===
    // Use --disable-extensions-except with empty to prevent extension loading
    // but keep our stealth JS available via CDP injection
    args.push("--disable-extensions".into());

    // Start with blank page — stealth patches are injected via CDP after launch
    args.push("about:blank".into());

    println!("[WonderBrowser] Launching: {} with {} args", browser_path, args.len());
    println!("[WonderBrowser] Profile: {}", profile_dir.display());
    println!("[WonderBrowser] CDP Port: {}", cdp_port);
    println!("[WonderBrowser] Proxy: {}", if use_proxy { format!("127.0.0.1:{}", proxy_port) } else { "DIRECT (no proxy)".into() });

    // Launch browser
    let child = Command::new(browser_path)
        .args(&args)
        .spawn()?;

    let pid = child.id();

    // Store CDP state globally
    CDP_PORT.store(cdp_port, std::sync::atomic::Ordering::Relaxed);
    CDP_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);

    // Inject stealth patches via CDP in background + start network capture
    let stealth_js = fs::read_to_string(&preload_path).unwrap_or_default();
    let cdp_port_clone = cdp_port;
    tokio::spawn(async move {
        // Wait for browser to start and CDP to become available
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        inject_stealth_via_cdp(cdp_port_clone, &stealth_js).await;
        // Start network traffic capture via CDP Network domain
        start_network_capture_cdp(cdp_port_clone).await;
    });

    println!("[WonderBrowser] ✓ Started with PID: {} (CDP on port {}, stealth active)", pid, cdp_port);

    Ok(pid)
}

/// Inject stealth JavaScript into all pages via CDP.
/// Uses `Page.addScriptToEvaluateOnNewDocument` to ensure the script runs
/// BEFORE any page JavaScript on every navigation (critical for Cloudflare).
async fn inject_stealth_via_cdp(port: u16, js: &str) {
    let cdp_url = format!("http://127.0.0.1:{}/json", port);
    let js_owned = js.to_string();

    // Try multiple times — browser takes a moment to start CDP
    for attempt in 0..8 {
        let client = match reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(3))
            .build()
        {
            Ok(c) => c,
            Err(_) => {
                tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;
                continue;
            }
        };

        match client.get(&cdp_url).send().await {
            Ok(resp) => {
                if let Ok(text) = resp.text().await {
                    if let Ok(pages) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                        for page in &pages {
                            if let Some(ws_url) = page.get("webSocketDebuggerUrl").and_then(|v| v.as_str()) {
                                // Connect via WebSocket and inject
                                if let Err(e) = inject_via_ws(ws_url, &js_owned).await {
                                    eprintln!("[WonderBrowser] CDP WS injection error: {}", e);
                                } else {
                                    println!("[WonderBrowser] ✓ Stealth script injected via CDP (attempt {})", attempt + 1);
                                    return;
                                }
                            }
                        }
                        // If no pages had ws URLs, try the browser-level endpoint
                        let browser_ws_url = format!("http://127.0.0.1:{}/json/version", port);
                        if let Ok(vresp) = client.get(&browser_ws_url).send().await {
                            if let Ok(vtext) = vresp.text().await {
                                if let Ok(version_info) = serde_json::from_str::<serde_json::Value>(&vtext) {
                                    if let Some(bws) = version_info.get("webSocketDebuggerUrl").and_then(|v| v.as_str()) {
                                        if let Err(e) = inject_via_ws(bws, &js_owned).await {
                                            eprintln!("[WonderBrowser] CDP browser-level WS error: {}", e);
                                        } else {
                                            println!("[WonderBrowser] ✓ Stealth script injected at browser level (attempt {})", attempt + 1);
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        println!("[WonderBrowser] ✓ CDP connected (attempt {}), stealth flags still active via CLI", attempt + 1);
                        return;
                    }
                }
            }
            Err(_) => {}
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;
    }

    eprintln!("[WonderBrowser] CDP injection: browser not ready after 8 attempts (CLI stealth flags still active)");
}

/// Send stealth JS to a CDP target via WebSocket.
/// Issues two commands:
/// 1. `Page.addScriptToEvaluateOnNewDocument` — runs on every future navigation
/// 2. `Runtime.evaluate` — runs immediately on the current page
async fn inject_via_ws(ws_url: &str, js: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio_tungstenite::connect_async;
    use futures_util::{SinkExt, StreamExt};

    let (mut ws, _) = connect_async(ws_url).await?;

    // 1. Page.enable — MUST be first, enables the Page domain
    let enable_cmd = serde_json::json!({
        "id": 1,
        "method": "Page.enable",
        "params": {}
    });
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        enable_cmd.to_string().into()
    )).await?;
    if let Some(Ok(_msg)) = ws.next().await {}

    // 2. Page.addScriptToEvaluateOnNewDocument — persists across ALL navigations
    //    This is the KEY mechanism: stealth JS runs BEFORE any page JS on every load.
    let add_script_cmd = serde_json::json!({
        "id": 2,
        "method": "Page.addScriptToEvaluateOnNewDocument",
        "params": {
            "source": js
        }
    });
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        add_script_cmd.to_string().into()
    )).await?;
    if let Some(Ok(_msg)) = ws.next().await {}

    // 3. Runtime.evaluate — inject immediately on the current page (about:blank)
    //    so it's already patched when user navigates from it
    let evaluate_cmd = serde_json::json!({
        "id": 3,
        "method": "Runtime.evaluate",
        "params": {
            "expression": js,
            "returnByValue": false
        }
    });
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        evaluate_cmd.to_string().into()
    )).await?;
    if let Some(Ok(_msg)) = ws.next().await {}

    // Close WS cleanly
    let _ = ws.close(None).await;

    Ok(())
}

// === Tauri Commands ===

#[tauri::command]
pub async fn browser_detect() -> Result<Vec<BrowserInfo>, String> {
    Ok(detect_browsers())
}

#[tauri::command]
pub async fn browser_status() -> Result<BrowserStatus, String> {
    let browsers = detect_browsers();
    let profile_dir = get_profile_dir();
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    let ca_path = PathBuf::from(&home).join(".wondersuite").join("ca").join("wondersuite-ca.pem");

    Ok(BrowserStatus {
        available_browsers: browsers,
        active_browser: None,
        profile_dir: profile_dir.to_string_lossy().to_string(),
        proxy_configured: false,
        ca_installed: ca_path.exists(),
    })
}

#[tauri::command]
pub async fn browser_launch(
    browser_name: Option<String>,
    proxy_port: Option<u16>,
    cdp_port: Option<u16>,
    use_proxy: Option<bool>,
    state: tauri::State<'_, crate::proxy_commands::ProxyAppState>,
    app: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    let browsers = detect_browsers();

    let browser = if let Some(name) = &browser_name {
        browsers.iter().find(|b| b.name.to_lowercase().contains(&name.to_lowercase()))
    } else {
        browsers.first()
    };

    let browser = browser.ok_or("No Chromium-based browser found. Install Chrome, Edge, or Brave.")?;
    let port = proxy_port.unwrap_or(8080);
    let cdp = cdp_port.unwrap_or(9222);
    let should_use_proxy = use_proxy.unwrap_or(true);

    // Auto-start proxy if not running
    let mut proxy_active = state.proxy_state.is_running();
    if should_use_proxy && !proxy_active {
        println!("[WonderBrowser] Proxy not running — auto-starting on port {}", port);
        match crate::proxy_commands::proxy_start(port, state.clone(), app).await {
            Ok(msg) => {
                println!("[WonderBrowser] {}", msg);
                proxy_active = true;
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            }
            Err(e) => {
                eprintln!("[WonderBrowser] Failed to auto-start proxy: {}. Launching direct.", e);
                proxy_active = false;
            }
        }
    }

    let ca_path = {
        let ca = state.ca.lock().await;
        ca.as_ref().map(|c| c.ca_cert_path())
    };

    let pid = launch_browser(&browser.path, port, ca_path.as_ref(), should_use_proxy && proxy_active, cdp)
        .map_err(|e| format!("Failed to launch browser: {}", e))?;

    Ok(serde_json::json!({
        "pid": pid,
        "browser": browser.name,
        "proxy_port": port,
        "cdp_port": cdp,
        "proxy_active": should_use_proxy && proxy_active,
        "profile_dir": get_profile_dir().to_string_lossy(),
        "ca_installed": ca_path.is_some(),
        "cdp_url": format!("http://127.0.0.1:{}", cdp),
        "stealth": true,
    }))
}

// ═══════════════════════════════════════════════════════════════════════
//  CDP Network Traffic Capture — Background Listener
//  Connects to the browser via WebSocket, enables Network domain,
//  and streams requestWillBeSent + responseReceived events into the
//  global BROWSER_NETWORK_LOG. The AI agent reads these via MCP.
// ═══════════════════════════════════════════════════════════════════════

/// Start capturing network traffic from the CDP browser.
/// Runs as a long-lived background task on a dedicated WebSocket connection.
pub async fn start_network_capture_cdp(port: u16) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let cdp_url = format!("http://127.0.0.1:{}/json", port);
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(3))
        .build() {
        Ok(c) => c,
        Err(_) => return,
    };

    // Find the first page tab's WebSocket URL
    let ws_url = match client.get(&cdp_url).send().await {
        Ok(resp) => {
            let tabs: Vec<serde_json::Value> = resp.json().await.unwrap_or_default();
            tabs.iter()
                .find(|t| t["type"].as_str() == Some("page"))
                .and_then(|t| t["webSocketDebuggerUrl"].as_str().map(String::from))
        }
        Err(_) => None,
    };

    let ws_url = match ws_url {
        Some(url) => url,
        None => {
            eprintln!("[WonderBrowser] Network capture: no page tab found");
            return;
        }
    };

    let (mut ws, _) = match tokio_tungstenite::connect_async(&ws_url).await {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("[WonderBrowser] Network capture WS connect failed: {}", e);
            return;
        }
    };

    // Enable Network domain
    let enable_cmd = serde_json::json!({"id": 100, "method": "Network.enable", "params": {}});
    if ws.send(Message::Text(enable_cmd.to_string().into())).await.is_err() { return; }

    // Enable request body capture
    let body_cmd = serde_json::json!({"id": 101, "method": "Network.setCacheDisabled", "params": {"cacheDisabled": true}});
    let _ = ws.send(Message::Text(body_cmd.to_string().into())).await;

    NETWORK_CAPTURE_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
    println!("[WonderBrowser] ✓ Network traffic capture active (CDP Network domain)");

    // Use a HashMap to correlate requestWillBeSent with responseReceived
    let mut pending: std::collections::HashMap<String, NetworkEntry> = std::collections::HashMap::new();

    // Long-lived event loop — reads CDP events until the browser closes
    while let Some(msg) = ws.next().await {
        let text = match msg {
            Ok(Message::Text(t)) => t.to_string(),
            Ok(Message::Close(_)) => break,
            Err(_) => break,
            _ => continue,
        };

        let event: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let method = event["method"].as_str().unwrap_or("");
        let params = &event["params"];

        match method {
            "Network.requestWillBeSent" => {
                let request_id = params["requestId"].as_str().unwrap_or("").to_string();
                let req = &params["request"];
                let entry = NetworkEntry {
                    id: request_id.clone(),
                    timestamp: params["wallTime"].as_f64().unwrap_or(0.0),
                    method: req["method"].as_str().unwrap_or("GET").to_string(),
                    url: req["url"].as_str().unwrap_or("").to_string(),
                    request_headers: req["headers"].clone(),
                    request_post_data: req["postData"].as_str().map(String::from),
                    status: None,
                    status_text: None,
                    response_headers: None,
                    response_mime_type: None,
                    response_size: None,
                    response_body: None,
                    timing_ms: None,
                    resource_type: params["type"].as_str().map(String::from),
                    initiator_type: params["initiator"]["type"].as_str().map(String::from),
                };
                pending.insert(request_id, entry);
            }
            "Network.responseReceived" => {
                let request_id = params["requestId"].as_str().unwrap_or("").to_string();
                let resp = &params["response"];
                if let Some(entry) = pending.get_mut(&request_id) {
                    entry.status = resp["status"].as_u64().map(|s| s as u16);
                    entry.status_text = resp["statusText"].as_str().map(String::from);
                    entry.response_headers = Some(resp["headers"].clone());
                    entry.response_mime_type = resp["mimeType"].as_str().map(String::from);
                    entry.response_size = resp["encodedDataLength"].as_u64();
                    if let Some(timing) = resp["timing"]["receiveHeadersEnd"].as_f64() {
                        entry.timing_ms = Some(timing);
                    }
                }
            }
            "Network.loadingFinished" | "Network.loadingFailed" => {
                let request_id = params["requestId"].as_str().unwrap_or("").to_string();
                if let Some(entry) = pending.remove(&request_id) {
                    // Only store XHR/Fetch/Document requests, skip images/fonts/etc
                    let rtype = entry.resource_type.as_deref().unwrap_or("");
                    match rtype {
                        "XHR" | "Fetch" | "Document" | "Script" | "Stylesheet" | "WebSocket" | "Other" | "" => {
                            push_network_entry(entry);
                        }
                        _ => {} // Skip Image, Font, Media, etc.
                    }
                }
            }
            _ => {} // Ignore other CDP events
        }

        // Prevent pending map from growing unbounded
        if pending.len() > 500 {
            let cutoff = pending.len() - 300;
            let keys: Vec<String> = pending.keys().take(cutoff).cloned().collect();
            for k in keys { pending.remove(&k); }
        }
    }

    NETWORK_CAPTURE_ACTIVE.store(false, std::sync::atomic::Ordering::Relaxed);
    println!("[WonderBrowser] Network capture stopped (browser closed)");
}
