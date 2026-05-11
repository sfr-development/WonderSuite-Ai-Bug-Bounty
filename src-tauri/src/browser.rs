use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

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
/// PIDs of browser processes we spawned — used to clean up on app exit.
static LAUNCHED_PIDS: std::sync::OnceLock<Mutex<Vec<u32>>> = std::sync::OnceLock::new();

fn launched_pids() -> &'static Mutex<Vec<u32>> {
    LAUNCHED_PIDS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn track_launched_pid(pid: u32) {
    if let Ok(mut v) = launched_pids().lock() {
        v.push(pid);
    }
}

pub fn kill_all_launched() {
    let pids: Vec<u32> = launched_pids().lock().map(|v| v.clone()).unwrap_or_default();
    if pids.is_empty() {
        return;
    }
    println!("[WonderBrowser] Cleaning up {} spawned browser process(es) on shutdown", pids.len());
    for pid in pids {
        #[cfg(target_os = "windows")]
        {
            let _ = Command::new_hidden("taskkill").args(["/F", "/T", "/PID", &pid.to_string()]).output();
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).output();
        }
    }
    if let Ok(mut v) = launched_pids().lock() {
        v.clear();
    }
}

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
    let home =
        std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".wondersuite").join("browser-profile")
}

/// Install CA certificate into the Windows user trust store.
fn install_ca_cert(
    ca_cert_path: &PathBuf,
    profile_dir: &PathBuf,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    if !ca_cert_path.exists() {
        return Ok(false);
    }
    fs::create_dir_all(profile_dir)?;

    let output = Command::new_hidden("certutil")
        .args(["-addstore", "-user", "Root", &ca_cert_path.to_string_lossy()])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            println!("[WonderBrowser] ✓ CA certificate installed to user trust store");
            Ok(true)
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stderr.contains("already in store")
                || stderr.contains("bereits im Speicher")
                || stdout.contains("already in store")
                || stdout.contains("bereits im Speicher")
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
    let stealth_js = r#"

Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

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

if (!window.chrome) window.chrome = {};
if (!window.chrome.runtime) {
    window.chrome.runtime = {
        connect: function() {},
        sendMessage: function() {},
        id: undefined,
    };
}

const originalQuery = window.navigator.permissions?.query;
if (originalQuery) {
    window.navigator.permissions.query = function(params) {
        if (params.name === 'notifications') {
            return Promise.resolve({ state: Notification.permission });
        }
        return originalQuery.call(this, params);
    };
}

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

Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });

if (navigator.platform === '') {
    Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
}

if (navigator.hardwareConcurrency === 0 || !navigator.hardwareConcurrency) {
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 4 });
}

const getParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(param) {
    if (param === 37445) return 'Google Inc. (NVIDIA)';
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

const originalAttachShadow = Element.prototype.attachShadow;
if (originalAttachShadow) {
    Element.prototype.attachShadow = function(init) {
        if (init && init.mode === 'closed') init.mode = 'open';
        return originalAttachShadow.call(this, init);
    };
}

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

    let _ca_installed = if let Some(cert_path) = ca_cert_path {
        install_ca_cert(cert_path, &profile_dir).unwrap_or(false)
    } else {
        false
    };

    let preload_path = write_stealth_preload(&profile_dir)?;

    let mut args: Vec<String> = Vec::new();

    args.push(format!("--remote-debugging-port={}", cdp_port));
    args.push("--remote-allow-origins=*".into());

    if use_proxy {
        args.push(format!("--proxy-server=127.0.0.1:{}", proxy_port));
    }

    args.push(format!("--user-data-dir={}", profile_dir.to_string_lossy()));

    args.push("--disable-blink-features=AutomationControlled".into());

    args.push("--disable-infobars".into());

    args.push("--flag-switches-begin".into());
    args.push("--flag-switches-end".into());

    args.push("--disable-features=IsolateOrigins,site-per-process,AutomationControlled,TranslateUI".into());
    args.push("--enable-features=NetworkService,NetworkServiceInProcess".into());

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

    args.push("--window-size=1920,1080".into());
    args.push("--start-maximized".into());

    args.push("--allow-insecure-localhost".into());

    args.push("--disable-component-extensions-with-background-pages".into());

    let browser_ver = get_browser_version(browser_path);
    let chrome_ver = if browser_ver.is_empty() { "136.0.7103.93".to_string() } else { browser_ver };
    args.push(format!(
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{} Safari/537.36",
        chrome_ver
    ));

    args.push("data:text/html,<title>New Tab</title>".into());

    println!("[WonderBrowser] Launching: {} with {} args", browser_path, args.len());
    println!("[WonderBrowser] Profile: {}", profile_dir.display());
    println!("[WonderBrowser] CDP Port: {}", cdp_port);
    println!(
        "[WonderBrowser] Proxy: {}",
        if use_proxy { format!("127.0.0.1:{}", proxy_port) } else { "DIRECT (no proxy)".into() }
    );

    let child = Command::new(browser_path).args(&args).spawn()?;

    let pid = child.id();
    track_launched_pid(pid);

    CDP_PORT.store(cdp_port, std::sync::atomic::Ordering::Relaxed);
    CDP_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);

    let stealth_js = fs::read_to_string(&preload_path).unwrap_or_default();
    let cdp_port_clone = cdp_port;
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        inject_stealth_via_cdp(cdp_port_clone, &stealth_js).await;
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
                                match inject_via_ws(ws_url, &js_owned).await {
                                    Err(e) => {
                                        eprintln!("[WonderBrowser] CDP WS injection error: {}", e);
                                    }
                                    _ => {
                                        println!(
                                            "[WonderBrowser] ✓ Stealth script injected via CDP (attempt {})",
                                            attempt + 1
                                        );
                                        return;
                                    }
                                }
                            }
                        }
                        let browser_ws_url = format!("http://127.0.0.1:{}/json/version", port);
                        if let Ok(vresp) = client.get(&browser_ws_url).send().await {
                            if let Ok(vtext) = vresp.text().await {
                                if let Ok(version_info) = serde_json::from_str::<serde_json::Value>(&vtext) {
                                    if let Some(bws) =
                                        version_info.get("webSocketDebuggerUrl").and_then(|v| v.as_str())
                                    {
                                        match inject_via_ws(bws, &js_owned).await {
                                            Err(e) => {
                                                eprintln!(
                                                    "[WonderBrowser] CDP browser-level WS error: {}",
                                                    e
                                                );
                                            }
                                            _ => {
                                                println!("[WonderBrowser] ✓ Stealth script injected at browser level (attempt {})", attempt + 1);
                                                return;
                                            }
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

    eprintln!(
        "[WonderBrowser] CDP injection: browser not ready after 8 attempts (CLI stealth flags still active)"
    );
}

/// Send stealth JS to a CDP target via WebSocket.
/// Issues two commands:
/// 1. `Page.addScriptToEvaluateOnNewDocument` — runs on every future navigation
/// 2. `Runtime.evaluate` — runs immediately on the current page
async fn inject_via_ws(ws_url: &str, js: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::connect_async;

    let (mut ws, _) = connect_async(ws_url).await?;

    let enable_cmd = serde_json::json!({
        "id": 1,
        "method": "Page.enable",
        "params": {}
    });
    ws.send(tokio_tungstenite::tungstenite::Message::Text(enable_cmd.to_string().into())).await?;
    if let Some(Ok(_msg)) = ws.next().await {}

    let add_script_cmd = serde_json::json!({
        "id": 2,
        "method": "Page.addScriptToEvaluateOnNewDocument",
        "params": {
            "source": js
        }
    });
    ws.send(tokio_tungstenite::tungstenite::Message::Text(add_script_cmd.to_string().into())).await?;
    if let Some(Ok(_msg)) = ws.next().await {}

    let evaluate_cmd = serde_json::json!({
        "id": 3,
        "method": "Runtime.evaluate",
        "params": {
            "expression": js,
            "returnByValue": false
        }
    });
    ws.send(tokio_tungstenite::tungstenite::Message::Text(evaluate_cmd.to_string().into())).await?;
    if let Some(Ok(_msg)) = ws.next().await {}

    let _ = ws.close(None).await;

    Ok(())
}

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

    // If the user pinned a specific port and it is in use, return a structured
    // error so the frontend can show a kill-the-process modal.
    if let Some(p) = proxy_port {
        let s = crate::port_commands::port_status(p);
        if s.in_use {
            return Err(serde_json::to_string(&serde_json::json!({
                "kind": "port_in_use",
                "role": "proxy",
                "port": p,
                "holders": s.holders,
            }))
            .unwrap_or_else(|_| format!("Proxy port {} is in use", p)));
        }
    }
    if let Some(p) = cdp_port {
        let s = crate::port_commands::port_status(p);
        if s.in_use {
            return Err(serde_json::to_string(&serde_json::json!({
                "kind": "port_in_use",
                "role": "cdp",
                "port": p,
                "holders": s.holders,
            }))
            .unwrap_or_else(|_| format!("CDP port {} is in use", p)));
        }
    }

    let port = if let Some(p) = proxy_port {
        p
    } else {
        match find_available_port(8080, 8090) {
            Some(p) => p,
            None => {
                let s = crate::port_commands::port_status(8080);
                return Err(serde_json::to_string(&serde_json::json!({
                    "kind": "port_in_use",
                    "role": "proxy",
                    "port": 8080,
                    "holders": s.holders,
                }))
                .unwrap_or_else(|_| "All proxy ports 8080-8090 are in use".into()));
            }
        }
    };

    let cdp = if let Some(p) = cdp_port {
        p
    } else {
        match find_available_port(9222, 9232) {
            Some(p) => p,
            None => {
                let s = crate::port_commands::port_status(9222);
                return Err(serde_json::to_string(&serde_json::json!({
                    "kind": "port_in_use",
                    "role": "cdp",
                    "port": 9222,
                    "holders": s.holders,
                }))
                .unwrap_or_else(|_| "All CDP ports 9222-9232 are in use".into()));
            }
        }
    };

    let should_use_proxy = use_proxy.unwrap_or(true);

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

/// Try to find an available TCP port in the given range.
fn find_available_port(start: u16, end: u16) -> Option<u16> {
    for port in start..=end {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Some(port);
        }
    }
    None
}

/// Start capturing network traffic from the CDP browser.
/// Runs as a long-lived background task on a dedicated WebSocket connection.
pub async fn start_network_capture_cdp(port: u16) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let cdp_url = format!("http://127.0.0.1:{}/json", port);
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

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

    let enable_cmd = serde_json::json!({"id": 100, "method": "Network.enable", "params": {}});
    if ws.send(Message::Text(enable_cmd.to_string().into())).await.is_err() {
        return;
    }

    let body_cmd = serde_json::json!({"id": 101, "method": "Network.setCacheDisabled", "params": {"cacheDisabled": true}});
    let _ = ws.send(Message::Text(body_cmd.to_string().into())).await;

    NETWORK_CAPTURE_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
    println!("[WonderBrowser] ✓ Network traffic capture active (CDP Network domain)");

    let mut pending: std::collections::HashMap<String, NetworkEntry> = std::collections::HashMap::new();

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
                    let rtype = entry.resource_type.as_deref().unwrap_or("");
                    match rtype {
                        "XHR" | "Fetch" | "Document" | "Script" | "Stylesheet" | "WebSocket" | "Other"
                        | "" => {
                            push_network_entry(entry);
                        }
                        _ => {} // Skip Image, Font, Media, etc.
                    }
                }
            }
            _ => {} // Ignore other CDP events
        }

        if pending.len() > 500 {
            let cutoff = pending.len() - 300;
            let keys: Vec<String> = pending.keys().take(cutoff).cloned().collect();
            for k in keys {
                pending.remove(&k);
            }
        }
    }

    NETWORK_CAPTURE_ACTIVE.store(false, std::sync::atomic::Ordering::Relaxed);
    println!("[WonderBrowser] Network capture stopped (browser closed)");
}
