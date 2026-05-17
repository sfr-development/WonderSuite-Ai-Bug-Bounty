use crate::mcp::McpState;
use serde::Serialize;
use std::time::Instant;

/// v0.3.12: GitHub releases proxy for the Changelog tab. The webview's CSP
/// blocks cross-origin fetch() to api.github.com, so we relay the request
/// through reqwest on the Rust side and pass the raw JSON string back.
///
/// 10-second timeout, unauthenticated (60 req/h per IP is plenty for a per-
/// user changelog refresh). Returns the body verbatim — the frontend parses.
#[tauri::command]
pub async fn fetch_github_releases() -> Result<String, String> {
    let url = "https://api.github.com/repos/sfr-development/WonderSuite-Ai-Bug-Bounty/releases?per_page=20";
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("WonderSuite-Changelog/0.3.13")
        .build()
        .map_err(|e| format!("client: {}", e))?;
    let resp = client
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("fetch: {}", e))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("read body: {}", e))?;
    if !status.is_success() {
        return Err(format!("GitHub API {}: {}", status, text.chars().take(200).collect::<String>()));
    }
    Ok(text)
}

#[derive(Serialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: String,
    pub body: String,
    pub time_ms: u64,
    pub size: usize,
}

#[tauri::command]
pub async fn send_http_request(
    method: String,
    url: String,
    headers: Option<std::collections::HashMap<String, String>>,
    body: Option<String>,
) -> Result<HttpResponse, String> {
    let start = Instant::now();

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let mut req = match method.to_uppercase().as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "PATCH" => client.patch(&url),
        "HEAD" => client.head(&url),
        "OPTIONS" => client.request(reqwest::Method::OPTIONS, &url),
        _ => return Err(format!("Unsupported method: {}", method)),
    };

    if let Some(hdrs) = headers {
        for (key, value) in hdrs {
            if let (Ok(name), Ok(val)) = (
                reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                reqwest::header::HeaderValue::from_str(&value),
            ) {
                req = req.header(name, val);
            }
        }
    }

    if let Some(b) = body {
        if !b.is_empty() {
            req = req.body(b);
        }
    }

    let response = req.send().await.map_err(|e| e.to_string())?;
    let status = response.status().as_u16();

    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
        .collect::<Vec<_>>()
        .join("\n");

    let body = response.text().await.map_err(|e| e.to_string())?;
    let time_ms = start.elapsed().as_millis() as u64;
    let size = body.len();

    Ok(HttpResponse { status, headers, body, time_ms, size })
}

#[tauri::command]
pub async fn mcp_start(state: tauri::State<'_, McpState>, port: u16) -> Result<String, String> {
    let mut server = state.lock().await;
    server.start(port).await?;
    Ok(format!("MCP server started on port {}", port))
}

#[tauri::command]
pub async fn mcp_stop(state: tauri::State<'_, McpState>) -> Result<String, String> {
    let mut server = state.lock().await;
    server.stop()?;
    Ok("MCP server stopped".into())
}

#[tauri::command]
pub async fn mcp_status(state: tauri::State<'_, McpState>) -> Result<bool, String> {
    let server = state.lock().await;
    Ok(server.is_running())
}

/// Check if a file or directory exists on disk
#[tauri::command]
pub async fn check_path_exists(path: String) -> Result<bool, String> {
    Ok(std::path::Path::new(&path).exists())
}

/// Read file content as a string — restricted to safe paths
#[tauri::command]
pub async fn read_file_content(path: String) -> Result<String, String> {
    validate_path(&path)?;
    std::fs::read_to_string(&path).map_err(|e| format!("Cannot read file {}: {}", path, e))
}

/// Write MCP config JSON to a target path (for IDE integration)
#[tauri::command]
pub async fn write_mcp_config(path: String, content: String) -> Result<String, String> {
    let p = std::path::Path::new(&path);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Cannot create directory: {}", e))?;
    }

    if p.exists() {
        let existing_raw = std::fs::read_to_string(p).unwrap_or_default();
        let existing_clean = strip_json_comments(&existing_raw);

        if !existing_clean.trim().is_empty() {
            if let (Ok(mut existing_json), Ok(new_json)) = (
                serde_json::from_str::<serde_json::Value>(&existing_clean),
                serde_json::from_str::<serde_json::Value>(&content),
            ) {
                if let Some(new_servers) = new_json.get("mcpServers") {
                    if let Some(existing_servers) = existing_json.get_mut("mcpServers") {
                        if let (Some(es), Some(ns)) =
                            (existing_servers.as_object_mut(), new_servers.as_object())
                        {
                            for (k, v) in ns {
                                es.insert(k.clone(), v.clone());
                            }
                        }
                    } else {
                        existing_json
                            .as_object_mut()
                            .map(|o| o.insert("mcpServers".into(), new_servers.clone()));
                    }
                }
                if let Some(new_mcp) = new_json.get("mcp") {
                    if let Some(existing_mcp) = existing_json.get_mut("mcp") {
                        if let Some(new_s) = new_mcp.get("servers") {
                            if let Some(existing_s) = existing_mcp.get_mut("servers") {
                                if let (Some(es), Some(ns)) = (existing_s.as_object_mut(), new_s.as_object())
                                {
                                    for (k, v) in ns {
                                        es.insert(k.clone(), v.clone());
                                    }
                                }
                            } else {
                                existing_mcp
                                    .as_object_mut()
                                    .map(|o| o.insert("servers".into(), new_s.clone()));
                            }
                        }
                    } else {
                        existing_json.as_object_mut().map(|o| o.insert("mcp".into(), new_mcp.clone()));
                    }
                }
                let merged = serde_json::to_string_pretty(&existing_json).map_err(|e| e.to_string())?;
                std::fs::write(p, &merged).map_err(|e| format!("Cannot write file: {}", e))?;
                return Ok(format!("Merged WonderSuite MCP config into {}", path));
            }
        }
    }

    std::fs::write(p, &content).map_err(|e| format!("Cannot write file: {}", e))?;
    Ok(format!("WonderSuite MCP config written to {}", path))
}

/// Strip single-line comments (// ...) from JSON-with-comments content
fn strip_json_comments(input: &str) -> String {
    let s = input.trim_start_matches('\u{feff}');
    let mut result = String::with_capacity(s.len());
    let mut in_string = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if in_string {
            result.push(c);
            if c == '\\' {
                if let Some(next) = chars.next() {
                    result.push(next);
                }
            } else if c == '"' {
                in_string = false;
            }
        } else {
            if c == '"' {
                in_string = true;
                result.push(c);
            } else if c == '/' {
                if chars.peek() == Some(&'/') {
                    for nc in chars.by_ref() {
                        if nc == '\n' {
                            result.push('\n');
                            break;
                        }
                    }
                } else {
                    result.push(c);
                }
            } else {
                result.push(c);
            }
        }
    }
    result
}

#[tauri::command]
pub async fn get_mcp_activity(since_id: Option<u64>) -> Result<Vec<crate::mcp::ActivityEntry>, String> {
    Ok(crate::mcp::get_activity_log(since_id.unwrap_or(0)))
}

#[tauri::command]
pub async fn get_mcp_activity_stats() -> Result<serde_json::Value, String> {
    Ok(crate::mcp::get_activity_stats())
}

#[tauri::command]
pub async fn get_mcp_traffic(since_id: Option<u64>) -> Result<Vec<crate::mcp::McpTrafficEntry>, String> {
    Ok(crate::mcp::get_mcp_traffic(since_id.unwrap_or(0)))
}

#[tauri::command]
pub fn mcp_list_tools() -> Vec<crate::mcp::ToolDef> {
    crate::mcp::tool_definitions()
}

/// Bridge command: lets the WonderSuite UI execute any MCP tool by name +
/// params. Used by Recon/OSINT/Tools panels that don't have a dedicated
/// `#[tauri::command]` wrapper.
///
/// v0.3.10 security hardening: a small set of high-privilege MCP tools that
/// could be abused from a compromised webview (proxy routing, certificate
/// pass-through, raw socket, browser code execution, OAST listener exposure)
/// is denied by default. Pass `WS_MCP_DEV_MODE=1` in the environment, or
/// call the dedicated `#[tauri::command]` (e.g. `proxy_set_upstream`)
/// directly, to use those. The hot loop for daily-use tools (encode, decode,
/// scan, fingerprint, recon) is unchanged.
#[tauri::command]
pub async fn mcp_execute_tool(name: String, params: serde_json::Value) -> Result<serde_json::Value, String> {
    if !is_dev_mode() && is_high_risk_tool(&name) {
        return Err(format!(
            "Tool '{}' is high-privilege and not callable via the IPC bridge by default. \
             Use the dedicated Tauri command (e.g. `proxy_set_upstream`, `browser_evaluate`) \
             or set the env var `WS_MCP_DEV_MODE=1` before launching WonderSuite to allow it.",
            name
        ));
    }
    crate::mcp::handle_tool_call(&name, &params).await
}

/// High-risk MCP tools. Compromising the webview should not give an attacker
/// the ability to: re-route the user's traffic through their proxy, plant a
/// permanent match-replace rule, open a public SMTP/DNS listener, run
/// arbitrary JS in the user's bundled Chromium session, fire raw bytes at
/// arbitrary destinations. Each of these has a dedicated `#[tauri::command]`
/// entry point that the legitimate UI already uses.
fn is_high_risk_tool(name: &str) -> bool {
    matches!(
        name,
        "proxy_set_upstream"
            | "proxy_add_match_replace"
            | "proxy_remove_match_replace"
            | "proxy_add_interception_rule"
            | "proxy_remove_interception_rule"
            | "proxy_add_tls_passthrough"
            | "browser_evaluate"
            | "browser_dom_sinks"
            | "oast_start_smtp_server"
            | "oast_start_dns_server"
            | "mtls_send_request"
            | "raw_tcp_send"
    )
}

fn is_dev_mode() -> bool {
    std::env::var("WS_MCP_DEV_MODE").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false)
}

/// Settings → MCP browser default-headless toggle. The UI flips this; the next
/// `browser_open` MCP call uses it as the default when `headless` isn't given.
#[tauri::command]
pub fn mcp_browser_get_headless() -> bool {
    crate::mcp::browser::default_headless()
}

#[tauri::command]
pub fn mcp_browser_set_headless(headless: bool) {
    crate::mcp::browser::set_default_headless(headless);
}

/// Get the active human-emulation stealth profile name ("fast" / "human" / "paranoid").
#[tauri::command]
pub fn mcp_browser_get_stealth_profile() -> String {
    crate::mcp::browser::stealth_profile().as_str().to_string()
}

/// Set the human-emulation stealth profile. Unknown values fall back to "human".
#[tauri::command]
pub fn mcp_browser_set_stealth_profile(profile: String) {
    let p = crate::mcp::browser::input::StealthProfile::from_str(&profile);
    crate::mcp::browser::set_stealth_profile(p);
}

/// Write text content to a file path — restricted to safe paths
#[tauri::command]
pub async fn save_file_text(path: String, content: String) -> Result<(), String> {
    validate_path(&path)?;
    std::fs::write(&path, content).map_err(|e| format!("Failed to save file: {}", e))
}

/// Return the bundled wondersuite.md Claude skill as a string. Bundled via
/// include_str! so it ships inside the binary and works offline. The Settings
/// → AI Skill panel uses this to populate a save-as dialog for the user.
#[tauri::command]
pub fn skill_content() -> &'static str {
    include_str!("../../.claude/skills/wondersuite.md")
}

/// Write the bundled skill into a user-chosen directory. Creates
/// `<dir>/.claude/skills/wondersuite.md` (path-traversal-safe).
#[tauri::command]
pub async fn install_skill(directory: String) -> Result<String, String> {
    if directory.contains("..") {
        return Err("Path traversal not allowed".into());
    }
    let dir = std::path::PathBuf::from(&directory);
    if !dir.exists() {
        return Err(format!("Directory does not exist: {}", directory));
    }
    if !dir.is_dir() {
        return Err(format!("Not a directory: {}", directory));
    }
    let skills_dir = dir.join(".claude").join("skills");
    std::fs::create_dir_all(&skills_dir).map_err(|e| format!("Failed to create .claude/skills: {}", e))?;
    let target = skills_dir.join("wondersuite.md");
    std::fs::write(&target, skill_content()).map_err(|e| format!("Failed to write skill: {}", e))?;
    Ok(target.to_string_lossy().to_string())
}

/// Write binary content (base64 encoded) to a file path — restricted to safe paths
#[tauri::command]
pub async fn save_file_bytes(path: String, data_base64: String) -> Result<(), String> {
    validate_path(&path)?;
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&data_base64)
        .map_err(|e| format!("Invalid base64: {}", e))?;
    std::fs::write(&path, bytes).map_err(|e| format!("Failed to save file: {}", e))
}

/// Validate that a file path is within allowed directories.
/// Prevents path traversal and arbitrary file access via the Tauri IPC.
///
/// v0.3.10: previously this function silently fell through to `Ok(())` after
/// the allowed-prefix loop — any code with IPC reach (compromised webview,
/// rogue extension) could read `~/.ssh/id_rsa` or write `.bat` files into the
/// Startup folder. Now the fall-through is an explicit `Err`. The IDE config
/// allowlist is also tightened — it requires the IDE directory to be a path
/// SEGMENT (e.g. `.../\.cursor/...`), not just contain the substring anywhere
/// in the path. `C:\evil\.cursor.malicious.json` no longer slips through.
fn validate_path(path: &str) -> Result<(), String> {
    let canonical = std::path::Path::new(path);

    if path.contains("..") {
        return Err("Path traversal not allowed".into());
    }

    let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_default();

    let allowed_prefixes = [
        format!("{}/.wondersuite", home),
        format!("{}/.wondersuite", home).replace('/', "\\"),
        format!("{}\\.wondersuite", home),
        "./wondersuite_memory".to_string(),
        std::env::temp_dir().to_string_lossy().to_string(),
    ];

    let path_str = canonical.to_string_lossy().to_string();

    for prefix in &allowed_prefixes {
        if path_str.starts_with(prefix) {
            return Ok(());
        }
    }

    // IDE / MCP-client config writes — `Settings → MCP Server → One-click
    // install` writes config files into a user's editor config dir. We allow
    // a JSON write only when the path contains a recognized IDE directory
    // as an actual path SEGMENT (delimited by separator on both sides) and
    // ends with `.json`. This rejects `C:\evil\.cursor.evil.json` while
    // still allowing `C:\Users\u\.cursor\mcp.json`.
    let ide_dirs = [".cursor", ".vscode", ".claude", ".continue", ".windsurf"];
    if path_str.ends_with(".json") {
        for dir in &ide_dirs {
            let win_seg = format!("\\{}\\", dir);
            let unix_seg = format!("/{}/", dir);
            if path_str.contains(&win_seg) || path_str.contains(&unix_seg) {
                return Ok(());
            }
        }
    }

    Err(format!(
        "Path '{}' is outside allowed directories. Allowed: {}/.wondersuite/, system temp dir, IDE config dirs (.cursor / .vscode / .claude / .continue / .windsurf) for .json files.",
        path_str, home
    ))
}
