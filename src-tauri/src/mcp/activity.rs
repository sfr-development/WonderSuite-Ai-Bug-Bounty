use super::types::{ActivityEntry, McpTrafficEntry};

static ACTIVITY_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

lazy_static::lazy_static! {
    static ref ACTIVITY_LOG: std::sync::Mutex<Vec<ActivityEntry>> = std::sync::Mutex::new(Vec::new());
}

static MCP_TRAFFIC_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(100000);

lazy_static::lazy_static! {
    static ref MCP_TRAFFIC_LOG: std::sync::Mutex<Vec<McpTrafficEntry>> = std::sync::Mutex::new(Vec::new());
}

pub fn tool_category(name: &str) -> &'static str {
    match name {
        "send_request" | "repeat_request" | "h2_send_request" | "mtls_send_request" | "send_to_repeater" => {
            "http"
        }
        "active_scan" | "scan_target" | "full_auto_scan" | "dom_invader" | "passive_scan" => "scanner",
        "crawl_target"
        | "discover_content"
        | "discover_subdomains"
        | "dns_resolve"
        | "find_secrets"
        | "analyze_target"
        | "h2_detect_support"
        | "js_link_finder"
        | "analyze_cdn_waf" => "recon",
        "fuzz_request" | "custom_attack" | "race_request" | "timing_attack" | "send_to_intruder" => {
            "intruder"
        }
        "smuggling_send" | "detect_smuggling" | "raw_tcp_send" | "test_auth_bypass"
        | "test_open_redirect" => "exploit",
        s if s.starts_with("browser_") => "browser",
        "encode" | "decode" | "hash" | "smart_decode" | "analyze_jwt" | "h2_translate"
        | "process_payload" | "generate_payload" => "codec",
        "proxy_start"
        | "proxy_stop"
        | "proxy_status"
        | "proxy_get_traffic"
        | "proxy_search_traffic"
        | "proxy_toggle_intercept"
        | "proxy_add_match_replace"
        | "proxy_get_match_replace"
        | "proxy_add_interception_rule"
        | "proxy_remove_interception_rule"
        | "proxy_remove_match_replace"
        | "proxy_add_tls_passthrough"
        | "proxy_set_upstream"
        | "proxy_get_websocket_messages"
        | "proxy_get_statistics"
        | "proxy_clear_traffic"
        | "proxy_export_traffic"
        | "get_intercepted"
        | "forward_intercepted"
        | "proxy_annotate_traffic"
        | "get_traffic_log" => "proxy",
        "oast_generate_payload"
        | "oast_verify"
        | "oast_start_dns_server"
        | "oast_start_smtp_server"
        | "collaborator_everywhere" => "oast",
        "websocket_connect" | "websocket_edit" | "websocket_advanced" => "websocket",
        "generate_report" | "organize_findings" | "generate_csrf_poc" => "reporting",
        "payload_manager" => "payloads",
        "crtsh_search"
        | "wayback_lookup"
        | "whois_lookup"
        | "asn_lookup"
        | "favicon_hash"
        | "reverse_ip_lookup"
        | "graphql_introspect"
        | "hackertarget_lookup"
        | "ip_geolocation"
        | "tech_detect" => "osint",
        "bambda_filter" => "filter",
        _ => "other",
    }
}

fn extract_target_url(params: &serde_json::Value) -> String {
    params["url"]
        .as_str()
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
        "browser_navigate" | "browser_open" => format!("→ {}", url),
        "browser_evaluate" | "browser_console" => {
            let code = params["code"].as_str().unwrap_or("");
            format!("JS: {}…", &code[..code.len().min(60)])
        }
        "browser_click" | "browser_type" | "browser_get_outer_html" | "browser_set_file_input" => {
            params["ref"].as_str().unwrap_or("(no ref)").to_string()
        }
        "browser_snapshot" => "page-state".into(),
        "browser_replay_to_proxy" => params["request_id"].as_str().unwrap_or("").to_string(),
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
            if s.len() > 60 {
                format!("{}…", &s[..57])
            } else {
                s
            }
        }
    }
}

pub fn summarize_result(result: &serde_json::Value) -> String {
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
    if s.len() > 80 {
        format!("{}…", &s[..77])
    } else {
        s
    }
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
        if log.len() > 300 {
            let drain = log.len() - 300;
            log.drain(..drain);
        }
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
    ACTIVITY_LOG
        .lock()
        .map(|log| log.iter().filter(|e| e.id >= since_id).cloned().collect())
        .unwrap_or_default()
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

pub fn log_mcp_traffic(entry: McpTrafficEntry) {
    if let Ok(mut log) = MCP_TRAFFIC_LOG.lock() {
        log.push(entry);
        if log.len() > 1000 {
            let drain = log.len() - 1000;
            log.drain(..drain);
        }
    }
}

pub fn get_mcp_traffic(since_id: u64) -> Vec<McpTrafficEntry> {
    MCP_TRAFFIC_LOG
        .lock()
        .map(|log| log.iter().filter(|e| e.id > since_id).cloned().collect())
        .unwrap_or_default()
}

pub fn next_mcp_traffic_id() -> u64 {
    MCP_TRAFFIC_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
