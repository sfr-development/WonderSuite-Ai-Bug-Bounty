use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// WonderSuite Browser — Anti-detect Chromium launcher with auto proxy + CA cert.
/// Detects installed Chromium-based browsers (Chrome, Edge, Brave, Chromium)
/// and launches with isolated profile, proxy pre-configured, CA cert trusted.

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

    // Architecture-aware paths
    let arch = std::env::consts::ARCH;
    let is_arm = arch.contains("aarch64") || arch.contains("arm");

    // Chrome paths
    let chrome_paths: Vec<&str> = if is_arm {
        vec![
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ]
    } else {
        vec![
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ]
    };

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
    // Try to get version from the binary's directory version folder
    let parent = PathBuf::from(path).parent().map(|p| p.to_path_buf());
    if let Some(parent) = parent {
        if let Ok(entries) = fs::read_dir(&parent) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                // Version folders look like "131.0.6778.109"
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

/// Install CA certificate into the WonderSuite Browser profile.
fn install_ca_cert(ca_cert_path: &PathBuf, profile_dir: &PathBuf) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    if !ca_cert_path.exists() {
        return Ok(false);
    }

    // Create profile dir
    fs::create_dir_all(profile_dir)?;

    // For Chromium on Windows, we install the CA into the Windows certificate store
    // This makes it trusted by all Chromium browsers using this profile
    let output = Command::new("certutil")
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
            // If already installed, that's fine
            if stderr.contains("already in store") || stderr.contains("bereits im Speicher") {
                println!("[WonderBrowser] ✓ CA certificate already trusted");
                Ok(true)
            } else {
                eprintln!("[WonderBrowser] certutil warning: {}", stderr);
                // Fallback: use Chrome's --ignore-certificate-errors flag
                Ok(false)
            }
        }
        Err(e) => {
            eprintln!("[WonderBrowser] certutil not found: {}", e);
            Ok(false)
        }
    }
}

/// Global CDP debugging port — accessible by MCP tools (browser_execute_js, session_from_browser)
static CDP_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(9222);
static CDP_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Get the current CDP port for external tools.
pub fn get_cdp_port() -> u16 {
    CDP_PORT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Check if a CDP browser is active.
pub fn is_cdp_active() -> bool {
    CDP_ACTIVE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Launch the WonderSuite Browser with full anti-detect + CDP + optional proxy.
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
    let ca_installed = if let Some(cert_path) = ca_cert_path {
        install_ca_cert(cert_path, &profile_dir).unwrap_or(false)
    } else {
        false
    };

    // Build launch arguments
    let mut args: Vec<String> = vec![
        // === CDP — Chrome DevTools Protocol ===
        format!("--remote-debugging-port={}", cdp_port),
        "--remote-allow-origins=*".into(),

        // === Proxy Configuration (only if proxy is running) ===
        // Proxy is OPTIONAL — without it, browser connects directly
    ];

    if use_proxy {
        args.push(format!("--proxy-server=127.0.0.1:{}", proxy_port));
    }

    args.extend([
        // === Isolated Profile ===
        format!("--user-data-dir={}", profile_dir.to_string_lossy()),

        // === Anti-Detect / Stealth (undetected-chromedriver level) ===
        "--disable-blink-features=AutomationControlled".into(),
        "--disable-features=IsolateOrigins,site-per-process".into(),
        "--disable-site-isolation-trials".into(),
        "--disable-web-security".into(),
        "--disable-features=CrossSiteDocumentBlockingIfIsolating".into(),
        "--excludeSwitches=enable-automation".into(),
        "--disable-ipc-flooding-protection".into(),

        // === Privacy / Anti-Fingerprint ===
        "--disable-client-side-phishing-detection".into(),
        "--disable-default-apps".into(),
        "--disable-extensions-except=".into(),
        "--disable-component-update".into(),
        "--disable-background-networking".into(),
        "--disable-sync".into(),
        "--disable-translate".into(),
        "--disable-features=TranslateUI".into(),
        "--metrics-recording-only".into(),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),

        // === Navigator overrides (anti-bot) ===
        "--disable-features=AutomationControlled".into(),

        // === Performance ===
        "--disable-gpu-sandbox".into(),
        "--disable-breakpad".into(),
        "--disable-hang-monitor".into(),

        // === WonderSuite Identity ===
        "--window-name=WonderSuite Browser".into(),
        "--app-name=WonderSuite".into(),
    ]);

    // If CA cert was NOT installed via certutil, use fallback flags
    if !ca_installed {
        args.push("--ignore-certificate-errors".into());
        args.push("--allow-insecure-localhost".into());
    }

    // Launch with blank page
    args.push("about:blank".into());

    println!("[WonderBrowser] Launching: {} with {} args", browser_path, args.len());
    println!("[WonderBrowser] Profile: {}", profile_dir.display());
    println!("[WonderBrowser] CDP Port: {}", cdp_port);
    println!("[WonderBrowser] Proxy: {}", if use_proxy { format!("127.0.0.1:{}", proxy_port) } else { "DIRECT (no proxy)".into() });
    println!("[WonderBrowser] CA installed: {}", ca_installed);

    let child = Command::new(browser_path)
        .args(&args)
        .spawn()?;

    let pid = child.id();

    // Store CDP state globally so MCP tools can discover it
    CDP_PORT.store(cdp_port, std::sync::atomic::Ordering::Relaxed);
    CDP_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);

    println!("[WonderBrowser] ✓ Started with PID: {} (CDP on port {})", pid, cdp_port);

    Ok(pid)
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
) -> Result<serde_json::Value, String> {
    let browsers = detect_browsers();

    // Find requested browser or use first available
    let browser = if let Some(name) = &browser_name {
        browsers.iter().find(|b| b.name.to_lowercase().contains(&name.to_lowercase()))
    } else {
        browsers.first()
    };

    let browser = browser.ok_or("No Chromium-based browser found. Install Chrome, Edge, or Brave.")?;
    let port = proxy_port.unwrap_or(8080);
    let cdp = cdp_port.unwrap_or(9222);

    // Auto-detect if proxy should be used
    let proxy_running = state.proxy_state.is_running();
    let should_use_proxy = use_proxy.unwrap_or(proxy_running);

    if !proxy_running && should_use_proxy {
        println!("[WonderBrowser] Warning: Proxy requested but not running. Launching direct.");
    }

    // Get CA cert path
    let ca_path = {
        let ca = state.ca.lock().await;
        ca.as_ref().map(|c| c.ca_cert_path())
    };

    let pid = launch_browser(&browser.path, port, ca_path.as_ref(), should_use_proxy && proxy_running, cdp)
        .map_err(|e| format!("Failed to launch browser: {}", e))?;

    Ok(serde_json::json!({
        "pid": pid,
        "browser": browser.name,
        "proxy_port": port,
        "cdp_port": cdp,
        "proxy_active": should_use_proxy && proxy_running,
        "profile_dir": get_profile_dir().to_string_lossy(),
        "ca_installed": ca_path.is_some(),
        "cdp_url": format!("http://127.0.0.1:{}", cdp),
    }))
}
