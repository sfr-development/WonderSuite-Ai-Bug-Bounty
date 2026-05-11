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
/// Note: kept for legacy paths but no longer called — we now use Burp-style
/// `--ignore-certificate-errors` on the isolated browser profile instead.
#[allow(dead_code)]
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
/// Options controlling how `launch_browser` builds its command line.
#[derive(Debug, Clone)]
pub struct LaunchOptions {
    pub proxy_port: u16,
    pub use_proxy: bool,
    pub cdp_port: u16,
    /// Path to an unpacked Chrome extension dir. None disables `--load-extension`.
    pub extension_path: Option<PathBuf>,
    /// Per-session profile dir override. None falls back to the legacy
    /// `~/.wondersuite/browser-profile` path used by v0.1.x.
    pub profile_dir: Option<PathBuf>,
    /// Disable the Linux sandbox. Should only be set when the user explicitly
    /// opts in via Settings. Matches Burp's "Allow Burp's browser to run
    /// without a sandbox" toggle.
    pub no_sandbox: bool,
    /// Run with --headless=new for the CDP crawl pass.
    pub headless: bool,
}

impl Default for LaunchOptions {
    fn default() -> Self {
        Self {
            proxy_port: 8080,
            use_proxy: true,
            cdp_port: 9222,
            extension_path: None,
            profile_dir: None,
            no_sandbox: false,
            headless: false,
        }
    }
}

pub fn launch_browser(
    browser_path: &str,
    opts: &LaunchOptions,
) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
    let proxy_port = opts.proxy_port;
    let cdp_port = opts.cdp_port;
    let use_proxy = opts.use_proxy;

    // Per-launch profile dir keeps Chromium isolated from the user's system Chrome
    // (cookies, history, extensions, autofill). Same pattern Burp / Caido / ZAP use.
    let profile_dir = opts.profile_dir.clone().unwrap_or_else(get_profile_dir);
    fs::create_dir_all(&profile_dir)?;

    // Stealth used to be injected via CDP (Page.addScriptToEvaluateOnNewDocument).
    // v0.2.0 moved it into the bundled WonderSuite Chrome extension, which runs the
    // same patches in the page's MAIN world at document_start — strictly better
    // because it doesn't leave CDP runtime fingerprint markers (window.cdc_*,
    // Runtime.evaluate execution-context anomalies, the /json/version endpoint
    // probe). We only fall back to CDP injection if the extension isn't loaded.
    let cdp_stealth_fallback = opts.extension_path.is_none();
    let preload_path = if cdp_stealth_fallback { Some(write_stealth_preload(&profile_dir)?) } else { None };

    let mut args: Vec<String> = Vec::new();

    // ── Proxy wiring (Burp-style) ────────────────────────────────────────
    if use_proxy {
        args.push(format!("--proxy-server=127.0.0.1:{}", proxy_port));
        // CRITICAL: Chrome 72+ silently bypasses the proxy for localhost / 127.0.0.1
        // unless we explicitly negate that. Without this, anyone testing a local app
        // sees empty proxy logs — same gotcha Burp's launcher solves.
        args.push("--proxy-bypass-list=<-loopback>".into());
    }
    // Trust the MITM cert without touching the OS trust store. Burp does the same:
    // an isolated profile + this flag avoids the certutil dance, UAC prompts, and
    // the risk of leaving a MITM root trusted system-wide after uninstall.
    args.push("--ignore-certificate-errors".into());
    args.push("--allow-insecure-localhost".into());
    args.push("--test-type".into()); // suppresses the "you are using an unsupported flag" infobar

    // ── Profile / first-run noise ────────────────────────────────────────
    args.push(format!("--user-data-dir={}", profile_dir.to_string_lossy()));
    args.push("--no-first-run".into());
    args.push("--no-default-browser-check".into());
    args.push("--no-pings".into());
    args.push("--no-service-autorun".into());
    args.push("--no-experiments".into());
    args.push("--disable-default-apps".into());
    args.push("--disable-sync".into());
    args.push("--disable-component-update".into());
    args.push("--disable-background-networking".into());
    args.push("--disable-breakpad".into());
    args.push("--disable-crash-reporter".into());
    args.push("--disable-hang-monitor".into());
    args.push("--disable-notifications".into());
    args.push("--disable-translate".into());
    args.push("--disable-client-side-phishing-detection".into());
    args.push("--disable-domain-reliability".into());
    args.push("--disable-ipc-flooding-protection".into());
    args.push("--disable-infobars".into());
    args.push("--disable-component-extensions-with-background-pages".into());
    args.push("--metrics-recording-only".into());

    // Force every request through the wire so the proxy captures them all.
    args.push("--disk-cache-size=0".into());
    args.push("--media-cache-size=0".into());

    // ── Feature flags ─────────────────────────────────────────────────────
    // HttpsUpgrades silently rewrites http:// → https:// and can route around the
    // proxy on edge cases. ChromeWhatsNewUI is the first-run promo page.
    args.push("--disable-features=HttpsUpgrades,ChromeWhatsNewUI,IsolateOrigins,site-per-process,AutomationControlled,TranslateUI,OptimizationHints,MediaRouter,DialMediaRouteProvider".into());
    args.push("--enable-features=NetworkService,NetworkServiceInProcess".into());
    args.push("--disable-blink-features=AutomationControlled".into());

    // ── CDP for automation hooks (agent_browser + crawler JS-render) ─────
    // CDP increases fingerprint surface (window.cdc_*, /json/version probes).
    // Only enable when the caller asks for it — set `cdp_port` to 0 to skip.
    if cdp_port != 0 {
        args.push(format!("--remote-debugging-port={}", cdp_port));
        args.push("--remote-allow-origins=*".into());
    }

    // ── WonderSuite extension (stealth + endpoint hooks) ─────────────────
    if let Some(ext) = &opts.extension_path {
        args.push(format!("--load-extension={}", ext.to_string_lossy()));
        args.push(format!("--disable-extensions-except={}", ext.to_string_lossy()));
    }

    // ── Optional headless mode (used by the crawler's JS-render pass) ────
    if opts.headless {
        args.push("--headless=new".into());
        args.push("--hide-scrollbars".into());
        args.push("--mute-audio".into());
    }

    // ── Optional sandbox-off toggle (Linux root, hardened-kernel users) ──
    if opts.no_sandbox {
        args.push("--no-sandbox".into());
    }

    // ── Window ────────────────────────────────────────────────────────────
    args.push("--window-size=1920,1080".into());
    if !opts.headless {
        args.push("--start-maximized".into());
    }

    // Intentionally NOT setting --user-agent. Hardcoding a stale UA string
    // (we previously claimed Chrome 136) created a glaring mismatch against
    // the real underlying Chromium build (148.x) — every bot detector picks
    // up the inconsistency. Let CfT's native UA stand. Callers who really
    // want to spoof can set it after attach via CDP Network.setUserAgentOverride.

    args.push("about:blank".into());

    // Hard pre-flight check: refuse to spawn if the binary or the extension
    // dir is missing. Without these checks the user sees a silent failure
    // (chrome.exe exits ms after launch) and has no idea what went wrong.
    let bin_path_buf = PathBuf::from(browser_path);
    if !bin_path_buf.exists() {
        return Err(format!(
            "browser binary not found at {} (did the Chromium download finish? — check Settings -> Browser)",
            browser_path
        )
        .into());
    }
    if let Some(ext) = &opts.extension_path {
        if !ext.exists() {
            return Err(format!(
                "extension dir not found at {} — reinstall via Settings -> Browser, or disable extension loading by reinstalling without --load-extension",
                ext.display()
            )
            .into());
        }
        if !ext.join("manifest.json").exists() {
            return Err(format!(
                "extension manifest missing at {} — the bundled wondersuite-extension didn't get copied",
                ext.join("manifest.json").display()
            )
            .into());
        }
    }

    println!("[WonderBrowser] Launching: {} with {} args", browser_path, args.len());
    println!("[WonderBrowser] Profile: {} (isolated, Burp-style)", profile_dir.display());
    println!("[WonderBrowser] CDP Port: {}", cdp_port);
    if let Some(ext) = &opts.extension_path {
        println!("[WonderBrowser] Extension: {}", ext.display());
    }
    println!(
        "[WonderBrowser] Proxy: {} (--proxy-bypass-list=<-loopback>, --ignore-certificate-errors)",
        if use_proxy { format!("127.0.0.1:{}", proxy_port) } else { "DIRECT (no proxy)".into() }
    );

    let child = Command::new(browser_path)
        .args(&args)
        .spawn()
        .map_err(|e| format!("Failed to spawn browser process: {} (path: {})", e, browser_path))?;

    let pid = child.id();
    track_launched_pid(pid);

    if cdp_port != 0 {
        CDP_PORT.store(cdp_port, std::sync::atomic::Ordering::Relaxed);
        CDP_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);

        // Fallback CDP stealth injection — only runs when the extension is NOT
        // loaded (e.g. system browser fallback after bundled-Chromium download
        // failed). Skipping this when the extension is loaded avoids running
        // the same patches twice and leaves no CDP runtime trace.
        if cdp_stealth_fallback {
            if let Some(path) = preload_path {
                let stealth_js = fs::read_to_string(&path).unwrap_or_default();
                let cdp_port_clone = cdp_port;
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    inject_stealth_via_cdp(cdp_port_clone, &stealth_js).await;
                    start_network_capture_cdp(cdp_port_clone).await;
                });
            }
        } else {
            // Extension handles stealth; we only need CDP for network capture.
            let cdp_port_clone = cdp_port;
            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                start_network_capture_cdp(cdp_port_clone).await;
            });
        }
    }

    println!(
        "[WonderBrowser] ✓ Started with PID: {} (CDP={}, stealth={})",
        pid,
        if cdp_port != 0 { format!("port {}", cdp_port) } else { "off".into() },
        if cdp_stealth_fallback { "CDP-fallback" } else { "extension" }
    );

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

/// Resolve which Chromium binary to launch. Tries the bundled WonderBrowser
/// (ChromiumManager) first; falls back to a detected system browser only when
/// the user opted in via Settings (or when bundled download failed and the
/// fallback flag was set explicitly via `prefer_system`).
pub async fn resolve_browser_binary(
    app: &tauri::AppHandle,
    prefer_system: bool,
    system_name_hint: Option<&str>,
) -> Result<(PathBuf, String), String> {
    if !prefer_system {
        match crate::chromium::ChromiumManager::new(app) {
            Ok(mgr) => {
                let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                match mgr.ensure(cancel).await {
                    Ok(p) => {
                        return Ok((p, format!("WonderBrowser (Chromium {})", mgr.pinned_version())));
                    }
                    Err(e) => {
                        eprintln!(
                            "[WonderBrowser] Bundled Chromium unavailable: {}. Falling back to system browser detection.",
                            e
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("[WonderBrowser] ChromiumManager init failed: {}", e);
            }
        }
    }
    let browsers = detect_browsers();
    let chosen = if let Some(name) = system_name_hint {
        browsers.iter().find(|b| b.name.to_lowercase().contains(&name.to_lowercase()))
    } else {
        browsers.first()
    };
    let chosen = chosen.ok_or_else(|| {
        "No browser available. The bundled Chromium failed to download and no system Chrome/Edge/Brave was found."
            .to_string()
    })?;
    Ok((PathBuf::from(&chosen.path), chosen.name.clone()))
}

#[tauri::command]
pub async fn browser_launch(
    browser_name: Option<String>,
    proxy_port: Option<u16>,
    cdp_port: Option<u16>,
    use_proxy: Option<bool>,
    prefer_system_browser: Option<bool>,
    no_sandbox: Option<bool>,
    state: tauri::State<'_, crate::proxy_commands::ProxyAppState>,
    app: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    let prefer_system = prefer_system_browser.unwrap_or(false);
    let no_sandbox = no_sandbox.unwrap_or(false);
    let (browser_path, browser_label) =
        resolve_browser_binary(&app, prefer_system, browser_name.as_deref()).await?;

    let our_pid = std::process::id();
    let proxy_already_ours = if state.proxy_state.is_running() {
        if let Some(p) = proxy_port {
            *state.proxy_state.proxy_port.lock().await == p
        } else {
            false
        }
    } else {
        false
    };

    if let Some(p) = proxy_port {
        if !proxy_already_ours {
            let s = crate::port_commands::port_status(p);
            let foreign_holders: Vec<_> = s.holders.into_iter().filter(|h| h.pid != our_pid).collect();
            if s.in_use && !foreign_holders.is_empty() {
                return Err(serde_json::to_string(&serde_json::json!({
                    "kind": "port_in_use",
                    "role": "proxy",
                    "port": p,
                    "holders": foreign_holders,
                }))
                .unwrap_or_else(|_| format!("Proxy port {} is in use", p)));
            }
        }
    }
    if let Some(p) = cdp_port {
        let s = crate::port_commands::port_status(p);
        let foreign_holders: Vec<_> = s.holders.into_iter().filter(|h| h.pid != our_pid).collect();
        if s.in_use && !foreign_holders.is_empty() {
            return Err(serde_json::to_string(&serde_json::json!({
                "kind": "port_in_use",
                "role": "cdp",
                "port": p,
                "holders": foreign_holders,
            }))
            .unwrap_or_else(|_| format!("CDP port {} is in use", p)));
        }
    }

    let port = if let Some(p) = proxy_port {
        p
    } else if proxy_already_ours {
        *state.proxy_state.proxy_port.lock().await
    } else {
        match find_available_port(8080, 8090) {
            Some(p) => p,
            None => {
                let s = crate::port_commands::port_status(8080);
                let foreign: Vec<_> = s.holders.into_iter().filter(|h| h.pid != our_pid).collect();
                return Err(serde_json::to_string(&serde_json::json!({
                    "kind": "port_in_use",
                    "role": "proxy",
                    "port": 8080,
                    "holders": foreign,
                }))
                .unwrap_or_else(|_| "All proxy ports 8080-8090 are in use".into()));
            }
        }
    };

    // CDP defaults OFF for user-launched browser sessions. The flag
    // --remote-debugging-port=N causes Chromium 148+ to set
    // navigator.webdriver=true internally (the previous workaround
    // --disable-blink-features=AutomationControlled no longer fully
    // suppresses it). Off-by-default keeps the fingerprint clean.
    // Callers that need CDP (agent_browser, crawler JS-render pass) pass
    // an explicit cdp_port; pass 0 to keep CDP off.
    let cdp = cdp_port.unwrap_or(0);

    let should_use_proxy = use_proxy.unwrap_or(true);

    let mut proxy_active = state.proxy_state.is_running();
    if should_use_proxy && !proxy_active {
        println!("[WonderBrowser] Proxy not running — auto-starting on port {}", port);
        match crate::proxy_commands::proxy_start(port, state.clone(), app.clone()).await {
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

    let extension_path = match crate::chromium::ChromiumManager::new(&app) {
        Ok(mgr) => mgr.extension_path().ok(),
        Err(_) => None,
    };

    let profile_dir = get_profile_dir();
    let opts = LaunchOptions {
        proxy_port: port,
        use_proxy: should_use_proxy && proxy_active,
        cdp_port: cdp,
        extension_path: extension_path.clone(),
        profile_dir: Some(profile_dir.clone()),
        no_sandbox,
        headless: false,
    };

    let pid = launch_browser(&browser_path.to_string_lossy(), &opts)
        .map_err(|e| format!("Failed to launch browser: {}", e))?;

    Ok(serde_json::json!({
        "pid": pid,
        "browser": browser_label,
        "proxy_port": port,
        "cdp_port": cdp,
        "proxy_active": should_use_proxy && proxy_active,
        "profile_dir": profile_dir.to_string_lossy(),
        "extension_loaded": extension_path.is_some(),
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
