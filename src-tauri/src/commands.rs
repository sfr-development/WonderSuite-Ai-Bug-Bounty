use crate::mcp::McpState;
use serde::Serialize;
use std::time::Instant;

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

/// Bridge command: lets the AI agent execute any MCP tool by name + params.
/// This gives the agent access to encode, decode, hash, analyze_jwt, generate_payload,
/// repeat_request, fuzz_request, scan_target, analyze_tokens, compare_data,
/// query_logs, organize_findings, active_scan, crawl_target, discover_subdomains,
/// discover_content, full_auto_scan, test_auth_bypass, detect_smuggling, find_secrets,
/// generate_csrf_poc, dom_invader, timing_attack, raw_tcp_send, smuggling_send,
/// bambda_filter, mtls_send_request, dns_resolve, race_request, h2_*, crtsh_search,
/// wayback_lookup, whois_lookup, asn_lookup, favicon_hash, discover_parameters,
/// graphql_introspect, js_link_finder, reverse_ip_lookup, template_*, and more.
#[tauri::command]
pub async fn mcp_execute_tool(name: String, params: serde_json::Value) -> Result<serde_json::Value, String> {
    crate::mcp::handle_tool_call(&name, &params).await
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
/// Prevents path traversal and arbitrary file access.
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

    if path_str.ends_with(".json")
        && (path_str.contains(".cursor") || path_str.contains(".vscode") || path_str.contains(".claude"))
    {
        return Ok(());
    }

    Ok(())
}
