use crate::mcp::types::HandlerResult;
use crate::proxy::state::*;
use crate::proxy_commands::get_global_proxy_state;
use std::sync::Arc;

/// Helper: get the proxy state or return an error
fn proxy() -> Result<Arc<ProxyState>, String> {
    get_global_proxy_state().ok_or_else(|| "Proxy not initialized — proxy state is unavailable".to_string())
}

/// Parsed view of a raw HTTP/1.1 request string. Used by the bridge between
/// intercept and attack tools so a still-on-hold intercept item can be fed
/// straight into send_to_intruder / passive_scan / active_scan without a
/// roundtrip through forward_intercepted (which previously was the *only*
/// path to a numeric traffic_id and broke whenever the upstream took >5s).
pub(crate) struct ParsedRawRequest {
    pub method: String,
    pub url: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: String,
}

/// Parse `raw_request` (the on-hold InterceptedItem.raw_request string) into
/// method / url / headers map / body. `host_hint` is taken from the intercept
/// item; we use it to resolve the request-line's path into a full URL.
/// `https_hint` decides http vs https when the request-line has only a path.
pub(crate) fn parse_raw_request(raw: &str, host_hint: &str, https_hint: bool) -> ParsedRawRequest {
    let mut method = String::new();
    let mut path = String::new();
    let mut headers: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut in_body = false;
    let mut body_lines: Vec<&str> = Vec::new();

    for (i, line) in raw.lines().enumerate() {
        if i == 0 {
            // Request line: METHOD PATH HTTP/x.y
            let mut parts = line.splitn(3, ' ');
            method = parts.next().unwrap_or("").to_string();
            path = parts.next().unwrap_or("").to_string();
            continue;
        }
        if in_body {
            body_lines.push(line);
        } else if line.trim().is_empty() {
            in_body = true;
        } else if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    let scheme = if https_hint { "https" } else { "http" };
    let url = if path.starts_with("http://") || path.starts_with("https://") {
        path.clone()
    } else if !host_hint.is_empty() {
        format!("{}://{}{}", scheme, host_hint, path)
    } else {
        path.clone()
    };

    ParsedRawRequest { method, url, headers, body: body_lines.join("\n") }
}

/// v0.3.10: recursively descend a JSON value and emit every scalar leaf as
/// `(json_pointer_path, value)`. Used by `send_to_intruder` to mark only
/// fuzzable scalar leaves instead of replacing whole nested objects with
/// string payloads (which breaks JSON shape on the wire).
///
/// Depth-limited (16) to defeat malicious or pathological inputs. Arrays
/// produce paths like `key[0]`, `key[1]`. Objects produce dotted paths.
pub(crate) fn collect_scalar_leaves(
    v: &serde_json::Value,
    prefix: &str,
    out: &mut Vec<(String, serde_json::Value)>,
    depth: usize,
) {
    if depth > 16 {
        return;
    }
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                let path = if prefix.is_empty() { k.clone() } else { format!("{}.{}", prefix, k) };
                collect_scalar_leaves(val, &path, out, depth + 1);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let path = format!("{}[{}]", prefix, i);
                collect_scalar_leaves(val, &path, out, depth + 1);
            }
        }
        serde_json::Value::String(_) | serde_json::Value::Number(_) | serde_json::Value::Bool(_) => {
            // Scalar leaves get a path even if prefix is empty (caller used
            // empty prefix → root scalar, very rare for real bodies).
            let path = if prefix.is_empty() { "root".to_string() } else { prefix.to_string() };
            out.push((path, v.clone()));
        }
        serde_json::Value::Null => {
            // Skip nulls — not a fuzz-able value, but the path can still be
            // referenced by an agent if it wants to populate.
        }
    }
}

/// Look up a still-pending intercept by UUID and return its parsed request.
/// Used by handlers that accept `intercept_id` as an alternative to
/// `traffic_id` — bridging the on-hold-intercept world to the attack tools.
pub(crate) async fn fetch_intercepted(
    ps: &Arc<ProxyState>,
    intercept_id: &str,
) -> Result<ParsedRawRequest, String> {
    let pending = ps.pending_intercepts.lock().await;
    let p = pending
        .get(intercept_id)
        .ok_or_else(|| format!("Intercept '{}' not found (already forwarded/dropped?)", intercept_id))?;
    let https_hint = p.item.url.starts_with("https://");
    Ok(parse_raw_request(&p.item.raw_request, &p.item.host, https_hint))
}

pub async fn handle_proxy_start(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let port = params["port"].as_u64().unwrap_or(8080) as u16;

    if ps.is_running() {
        let current_port = *ps.proxy_port.lock().await;
        return Ok(serde_json::json!({
            "status": "already_running",
            "port": current_port,
            "message": format!("Proxy is already running on port {}", current_port)
        }));
    }

    let ca = crate::proxy_commands::get_global_ca()
        .ok_or_else(|| "CA not initialized — proxy cannot start without CA".to_string())?;

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .map_err(|e| format!("Port {} is blocked or already in use: {}", port, e))?;

    *ps.proxy_port.lock().await = port;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<crate::proxy::state::ProxyEvent>();
    *ps.event_tx.lock().await = Some(tx);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });

    let cancel = tokio_util::sync::CancellationToken::new();
    let engine = Arc::new(crate::proxy::engine::ProxyEngine::new(ca, ps.clone(), cancel.clone()));
    let ps_err = ps.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = engine.run(listener).await {
            eprintln!("[Proxy/MCP] Engine error: {}", e);
            ps_err.running.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let shutdown = crate::proxy_commands::get_or_init_global_shutdown().await;
    *shutdown.lock().await = Some((handle, cancel));

    Ok(serde_json::json!({
        "status": "running",
        "port": port,
        "message": format!("Proxy engine started on 127.0.0.1:{}", port)
    }))
}

pub async fn handle_proxy_stop(_params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;

    if !ps.is_running() {
        return Ok(serde_json::json!({
            "status": "not_running",
            "message": "Proxy is not running"
        }));
    }

    ps.drain_pending_intercepts().await;
    ps.set_intercept(false);
    ps.set_response_intercept(false);

    let shutdown = crate::proxy_commands::get_or_init_global_shutdown().await;
    if let Some((handle, cancel)) = shutdown.lock().await.take() {
        cancel.cancel();
        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(5), handle).await;
    }

    ps.running.store(false, std::sync::atomic::Ordering::SeqCst);
    *ps.event_tx.lock().await = None;

    Ok(serde_json::json!({
        "status": "stopped",
        "message": "Proxy engine stopped successfully"
    }))
}

pub async fn handle_proxy_status(_params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;

    let running = ps.is_running();
    let port = *ps.proxy_port.lock().await;
    let traffic_count = ps.traffic.lock().await.len();
    let intercept_enabled = ps.is_intercept_enabled();
    let response_intercept = ps.is_response_intercept_enabled();
    let pending_count = ps.pending_intercepts.lock().await.len();
    let mr_count = ps.match_replace_rules.read().await.len();
    let ir_count = ps.interception_rules.read().await.len();
    let tls_count = ps.tls_passthrough.read().await.len();
    let upstream = ps.upstream_proxy.read().await.clone();
    let ws_count = ps.websocket_messages.lock().await.len();

    Ok(serde_json::json!({
        "running": running,
        "port": port,
        "total_requests": traffic_count,
        "intercept_enabled": intercept_enabled,
        "response_intercept_enabled": response_intercept,
        "pending_intercepts": pending_count,
        "match_replace_rules": mr_count,
        "interception_rules": ir_count,
        "tls_passthrough_entries": tls_count,
        "upstream_proxy_enabled": upstream.enabled,
        "websocket_messages": ws_count,
    }))
}

pub async fn handle_proxy_toggle_intercept(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let enabled = params["enabled"].as_bool().unwrap_or(false);
    let response_intercept = params["response_intercept"].as_bool();

    ps.set_intercept(enabled);

    if let Some(resp_int) = response_intercept {
        ps.set_response_intercept(resp_int);
    }

    if !enabled {
        ps.drain_pending_intercepts().await;
    }

    Ok(serde_json::json!({
        "intercept_enabled": enabled,
        "response_intercept_enabled": response_intercept.unwrap_or(ps.is_response_intercept_enabled()),
        "pending_drained": !enabled
    }))
}

pub async fn handle_proxy_get_traffic(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let limit = params["limit"].as_u64().unwrap_or(100) as usize;

    // v0.3.10: structured filters + summary/detail modes. Without filters a
    // single call could blow >30 KB on 5 entries when the bodies are huge
    // (YouTube telemetry, GraphQL mutations) — useless for an LLM agent
    // working a token budget. Filters apply BEFORE the body is serialized.
    let host_filter = params["host"].as_str();
    let method_filter = params["method"].as_str().map(|s| s.to_ascii_uppercase());
    let mime_filter = params["mime"].as_str().map(|s| s.to_ascii_lowercase());
    let exclude_static = params["exclude_static"].as_bool().unwrap_or(false);
    let exclude_third_party = params["exclude_third_party"].as_bool().unwrap_or(false);
    let status_min = params["status_min"].as_u64().unwrap_or(0) as u16;
    let status_max = params["status_max"].as_u64().unwrap_or(999) as u16;
    let mode = params["mode"].as_str().unwrap_or("detail"); // "summary" | "detail"
    let body_preview_bytes = params["body_preview_bytes"].as_u64().unwrap_or(4096) as usize;
    let primary_host = params["primary_host"].as_str(); // for exclude_third_party

    // Static-resource extension check.
    fn is_static_ext(path: &str) -> bool {
        let p = path.to_ascii_lowercase();
        const EXTS: &[&str] = &[
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".css", ".js", ".woff", ".woff2",
            ".ttf", ".eot", ".map", ".mp4", ".webm",
        ];
        EXTS.iter().any(|e| p.ends_with(e))
    }

    let traffic = ps.get_traffic().await;
    let total = traffic.len();

    let filtered: Vec<&TrafficEntry> = traffic
        .iter()
        .rev()
        .filter(|e| {
            if let Some(h) = host_filter {
                if !e.host.contains(h) {
                    return false;
                }
            }
            if let Some(m) = &method_filter {
                if &e.method.to_ascii_uppercase() != m {
                    return false;
                }
            }
            if let Some(mt) = &mime_filter {
                if !e.mime_type.to_ascii_lowercase().contains(mt) {
                    return false;
                }
            }
            if e.status < status_min || e.status > status_max {
                return false;
            }
            if exclude_static && is_static_ext(&e.path) {
                return false;
            }
            if exclude_third_party {
                if let Some(ph) = primary_host {
                    if !e.host.contains(ph) {
                        return false;
                    }
                }
            }
            true
        })
        .take(limit)
        .collect();

    let entries_json: Vec<serde_json::Value> = filtered
        .iter()
        .map(|e| {
            if mode == "summary" {
                // Metadata-only. ~30x smaller than detail mode for an agent
                // that just wants to know "what's interesting in here".
                serde_json::json!({
                    "id": e.id,
                    "timestamp": e.timestamp,
                    "method": e.method,
                    "url": e.url,
                    "host": e.host,
                    "path": e.path,
                    "status": e.status,
                    "mime_type": e.mime_type,
                    "response_length": e.response_length,
                    "response_time_ms": e.response_time_ms,
                    "request_body_size": e.request_body.len(),
                    "tls": e.tls,
                    "source": e.source,
                    "notes": e.notes,
                    "color": e.color,
                })
            } else {
                serde_json::json!({
                    "id": e.id, "timestamp": e.timestamp, "method": e.method,
                    "url": e.url, "host": e.host, "path": e.path, "port": e.port,
                    "tls": e.tls, "status": e.status,
                    "response_length": e.response_length,
                    "response_time_ms": e.response_time_ms,
                    "mime_type": e.mime_type,
                    "request_headers": e.request_headers,
                    "request_body": truncate_utf8(&e.request_body, body_preview_bytes),
                    "response_headers": e.response_headers,
                    "response_body": truncate_utf8(&e.response_body, body_preview_bytes),
                    "source": e.source, "notes": e.notes, "color": e.color
                })
            }
        })
        .collect();

    Ok(serde_json::json!({
        "total": total,
        "filtered": filtered.len(),
        "returned": entries_json.len(),
        "mode": mode,
        "entries": entries_json
    }))
}

pub async fn handle_proxy_search_traffic(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let query = params["query"].as_str().ok_or("Missing query")?;

    let results = ps.search_traffic(query).await;
    let entries_json: Vec<serde_json::Value> = results
        .iter()
        .take(200)
        .map(|e| {
            serde_json::json!({
                "id": e.id, "method": e.method, "url": e.url, "host": e.host,
                "status": e.status, "response_length": e.response_length,
                "response_time_ms": e.response_time_ms, "mime_type": e.mime_type,
                "tls": e.tls, "source": e.source
            })
        })
        .collect();

    Ok(serde_json::json!({
        "query": query,
        "total_matches": results.len(),
        "returned": entries_json.len(),
        "results": entries_json
    }))
}

pub async fn handle_proxy_add_match_replace(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let name = params["name"].as_str().ok_or("Missing name")?;
    let target = params["target"].as_str().ok_or(
        "Missing target (request_header, request_body, response_header, response_body, request_url)",
    )?;
    let match_pattern = params["match_pattern"].as_str().ok_or("Missing match_pattern")?;
    let replace_value = params["replace_value"].as_str().ok_or("Missing replace_value")?;
    let is_regex = params["is_regex"].as_bool().unwrap_or(false);
    let direction = params["direction"].as_str().unwrap_or("both");
    let id = uuid::Uuid::new_v4().to_string();

    if is_regex {
        regex::Regex::new(match_pattern).map_err(|e| format!("Invalid regex pattern: {}", e))?;
    }

    let rule = MatchReplaceRule {
        id: id.clone(),
        enabled: true,
        name: name.to_string(),
        target: target.to_string(),
        match_pattern: match_pattern.to_string(),
        replace_value: replace_value.to_string(),
        is_regex,
        direction: direction.to_string(),
    };

    ps.match_replace_rules.write().await.push(rule);

    Ok(serde_json::json!({
        "status": "added",
        "rule_id": id,
        "name": name,
        "target": target,
        "match_pattern": match_pattern,
        "replace_value": replace_value,
        "is_regex": is_regex,
        "direction": direction
    }))
}

pub async fn handle_proxy_get_match_replace(_params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let rules = ps.match_replace_rules.read().await;

    let rules_json: Vec<serde_json::Value> = rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id, "enabled": r.enabled, "name": r.name,
                "target": r.target, "match_pattern": r.match_pattern,
                "replace_value": r.replace_value, "is_regex": r.is_regex,
                "direction": r.direction
            })
        })
        .collect();

    Ok(serde_json::json!({
        "total": rules_json.len(),
        "rules": rules_json
    }))
}

pub async fn handle_proxy_add_tls_passthrough(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let host = params["host"].as_str().ok_or("Missing host")?;
    let port = params["port"].as_u64().map(|p| p as u16);
    let id = uuid::Uuid::new_v4().to_string();

    let entry = TlsPassThroughEntry {
        id: id.clone(),
        enabled: true,
        host: host.to_string(),
        port,
        notes: params["notes"].as_str().unwrap_or("").to_string(),
    };

    ps.tls_passthrough.write().await.push(entry);

    Ok(serde_json::json!({
        "status": "added",
        "entry_id": id,
        "host": host,
        "port": port,
        "message": format!("TLS passthrough added for {}{}", host, port.map(|p| format!(":{}", p)).unwrap_or_default())
    }))
}

pub async fn handle_proxy_set_upstream(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let host = params["host"].as_str().ok_or("Missing host")?;
    let port = params["port"].as_u64().ok_or("Missing port")? as u16;
    let enabled = params["enabled"].as_bool().unwrap_or(true);
    let proxy_type = params["proxy_type"].as_str().unwrap_or("http");

    let config = UpstreamProxyConfig {
        enabled,
        proxy_type: proxy_type.to_string(),
        host: host.to_string(),
        port,
        username: params["username"].as_str().map(|s| s.to_string()),
        password: params["password"].as_str().map(|s| s.to_string()),
        bypass_patterns: params["bypass_patterns"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default(),
    };

    *ps.upstream_proxy.write().await = config;

    Ok(serde_json::json!({
        "status": "configured",
        "enabled": enabled,
        "proxy_type": proxy_type,
        "host": host,
        "port": port,
        "message": if enabled {
            format!("Upstream proxy set to {}://{}:{}", proxy_type, host, port)
        } else {
            "Upstream proxy disabled".to_string()
        }
    }))
}

pub async fn handle_proxy_get_websocket_messages(_params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let messages = ps.get_websocket_messages().await;

    let msgs_json: Vec<serde_json::Value> = messages
        .iter()
        .rev()
        .take(200)
        .map(|m| {
            serde_json::json!({
                "id": m.id, "connection_id": m.connection_id,
                "direction": m.direction, "opcode": m.opcode,
                "data": truncate_utf8(&m.data, 2048),
                "length": m.length, "timestamp": m.timestamp,
                "host": m.host, "url": m.url
            })
        })
        .collect();

    Ok(serde_json::json!({
        "total": messages.len(),
        "returned": msgs_json.len(),
        "messages": msgs_json
    }))
}

pub async fn handle_proxy_add_interception_rule(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let name = params["name"].as_str().ok_or("Missing name")?;
    let rule_type_str = params["rule_type"].as_str().ok_or("Missing rule_type")?;
    let pattern = params["pattern"].as_str().ok_or("Missing pattern")?;
    let action = params["action"].as_str().unwrap_or("intercept");
    let target_str = params["target"].as_str().unwrap_or("both");
    let id = uuid::Uuid::new_v4().to_string();

    let rule_type = match rule_type_str {
        "url_contains" => InterceptionRuleType::UrlContains { pattern: pattern.to_string() },
        "url_regex" => {
            regex::Regex::new(pattern).map_err(|e| format!("Invalid regex: {}", e))?;
            InterceptionRuleType::UrlRegex { pattern: pattern.to_string() }
        }
        "host_equals" => InterceptionRuleType::HostEquals { host: pattern.to_string() },
        "method_equals" => InterceptionRuleType::MethodEquals { method: pattern.to_string() },
        "file_extension" => InterceptionRuleType::FileExtension {
            extensions: pattern.split(',').map(|s| s.trim().to_string()).collect(),
        },
        _ => return Err(format!("Unknown rule_type: {}. Valid: url_contains, url_regex, host_equals, method_equals, file_extension", rule_type_str)),
    };

    let target = match target_str {
        "request" => InterceptionTarget::Request,
        "response" => InterceptionTarget::Response,
        _ => InterceptionTarget::Both,
    };

    let rule = InterceptionRule {
        id: id.clone(),
        enabled: true,
        name: name.to_string(),
        rule_type,
        target,
        action: action.to_string(),
    };

    ps.interception_rules.write().await.push(rule);

    Ok(serde_json::json!({
        "status": "added",
        "rule_id": id,
        "name": name,
        "rule_type": rule_type_str,
        "pattern": pattern,
        "action": action,
        "target": target_str
    }))
}

pub async fn handle_proxy_get_statistics(_params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;

    let traffic = ps.traffic.lock().await;
    let ws = ps.websocket_messages.lock().await;
    let pending = ps.pending_intercepts.lock().await;
    let mr = ps.match_replace_rules.read().await;
    let ir = ps.interception_rules.read().await;
    let tls = ps.tls_passthrough.read().await;

    let total = traffic.len();
    let tls_count = traffic.iter().filter(|t| t.tls).count();

    let methods: std::collections::HashMap<String, usize> = {
        let mut m = std::collections::HashMap::new();
        for t in traffic.iter() {
            *m.entry(t.method.clone()).or_insert(0) += 1;
        }
        m
    };

    let status_groups: std::collections::HashMap<String, usize> = {
        let mut s = std::collections::HashMap::new();
        for t in traffic.iter() {
            let group = match t.status {
                st if st < 200 => "1xx",
                st if st < 300 => "2xx",
                st if st < 400 => "3xx",
                st if st < 500 => "4xx",
                _ => "5xx",
            };
            *s.entry(group.to_string()).or_insert(0) += 1;
        }
        s
    };

    let total_bytes: usize = traffic.iter().map(|t| t.response_length).sum();
    let avg_response_time =
        if total > 0 { traffic.iter().map(|t| t.response_time_ms).sum::<u64>() / total as u64 } else { 0 };

    Ok(serde_json::json!({
        "running": ps.is_running(),
        "total_requests": total,
        "tls_requests": tls_count,
        "plain_requests": total - tls_count,
        "methods": methods,
        "status_groups": status_groups,
        "total_response_bytes": total_bytes,
        "avg_response_time_ms": avg_response_time,
        "websocket_messages": ws.len(),
        "pending_intercepts": pending.len(),
        "match_replace_rules": mr.len(),
        "interception_rules": ir.len(),
        "tls_passthrough_entries": tls.len(),
    }))
}

pub async fn handle_proxy_clear_traffic(_params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    ps.clear_traffic().await;

    Ok(serde_json::json!({
        "status": "cleared",
        "message": "All proxy traffic cleared"
    }))
}

pub async fn handle_proxy_export_traffic(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let format = params["format"].as_str().unwrap_or("json");

    let traffic = ps.get_traffic().await;

    match format {
        "json" => {
            let json_str = serde_json::to_string_pretty(&traffic).map_err(|e| e.to_string())?;
            Ok(serde_json::json!({
                "format": "json",
                "total_entries": traffic.len(),
                "data": json_str,
                "size_bytes": json_str.len()
            }))
        }
        "har" => {
            let entries: Vec<serde_json::Value> = traffic
                .iter()
                .map(|t| {
                    let req_headers = parse_raw_headers_har(&t.request_headers);
                    let resp_headers = parse_raw_headers_har(&t.response_headers);
                    let qs = parse_query_string_har(&t.url);
                    serde_json::json!({
                        "startedDateTime": t.timestamp,
                        "time": t.response_time_ms,
                        "request": {
                            "method": t.method,
                            "url": t.url,
                            "httpVersion": "HTTP/1.1",
                            "headers": req_headers,
                            "queryString": qs,
                            "cookies": [],
                            "headersSize": t.request_headers.len(),
                            "bodySize": t.request_body.len(),
                            "postData": if t.request_body.is_empty() {
                                serde_json::Value::Null
                            } else {
                                serde_json::json!({
                                    "mimeType": header_value(&t.request_headers, "content-type").unwrap_or_else(|| "application/octet-stream".into()),
                                    "text": t.request_body,
                                })
                            }
                        },
                        "response": {
                            "status": t.status,
                            "statusText": http_status_text(t.status),
                            "httpVersion": "HTTP/1.1",
                            "headers": resp_headers,
                            "cookies": [],
                            "content": {
                                "size": t.response_length,
                                "mimeType": t.mime_type
                            },
                            "redirectURL": header_value(&t.response_headers, "location").unwrap_or_default(),
                            "headersSize": t.response_headers.len(),
                            "bodySize": t.response_length
                        },
                        "cache": {},
                        "timings": {
                            "send": 0,
                            "wait": t.response_time_ms,
                            "receive": 0
                        }
                    })
                })
                .collect();

            let har = serde_json::json!({
                "log": {
                    "version": "1.2",
                    "creator": { "name": "WonderSuite", "version": "1.0" },
                    "entries": entries
                }
            });

            let har_str = serde_json::to_string_pretty(&har).map_err(|e| e.to_string())?;
            Ok(serde_json::json!({
                "format": "har",
                "total_entries": traffic.len(),
                "data": har_str,
                "size_bytes": har_str.len()
            }))
        }
        _ => Err(format!("Unknown format: {}. Use 'json' or 'har'", format)),
    }
}

/// Remove or toggle an interception rule by ID.
pub async fn handle_proxy_remove_interception_rule(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let id = params["id"].as_str().ok_or("Missing rule id")?;
    let action = params["action"].as_str().unwrap_or("remove"); // "remove" or "toggle"

    let mut rules = ps.interception_rules.write().await;

    match action {
        "toggle" => {
            if let Some(rule) = rules.iter_mut().find(|r| r.id == id) {
                rule.enabled = !rule.enabled;
                Ok(serde_json::json!({
                    "action": "toggled",
                    "id": id,
                    "enabled": rule.enabled,
                    "name": rule.name,
                }))
            } else {
                Err(format!("Rule '{}' not found", id))
            }
        }
        _ => {
            let before = rules.len();
            rules.retain(|r| r.id != id);
            if rules.len() < before {
                Ok(serde_json::json!({
                    "action": "removed",
                    "id": id,
                    "remaining_rules": rules.len(),
                }))
            } else {
                Err(format!("Rule '{}' not found", id))
            }
        }
    }
}

/// Remove or toggle a match/replace rule by ID.
pub async fn handle_proxy_remove_match_replace(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let id = params["id"].as_str().ok_or("Missing rule id")?;
    let action = params["action"].as_str().unwrap_or("remove");

    let mut rules = ps.match_replace_rules.write().await;

    match action {
        "toggle" => {
            if let Some(rule) = rules.iter_mut().find(|r| r.id == id) {
                rule.enabled = !rule.enabled;
                Ok(serde_json::json!({
                    "action": "toggled",
                    "id": id,
                    "enabled": rule.enabled,
                    "name": rule.name,
                }))
            } else {
                Err(format!("Rule '{}' not found", id))
            }
        }
        _ => {
            let before = rules.len();
            rules.retain(|r| r.id != id);
            if rules.len() < before {
                Ok(serde_json::json!({
                    "action": "removed",
                    "id": id,
                    "remaining_rules": rules.len(),
                }))
            } else {
                Err(format!("Rule '{}' not found", id))
            }
        }
    }
}

/// Annotate a traffic entry — add notes, color highlighting, like Burp's highlighting.
pub async fn handle_proxy_annotate_traffic(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let traffic_id = params["traffic_id"].as_u64().ok_or("Missing traffic_id")?;

    let mut traffic = ps.traffic.lock().await;
    let entry = traffic
        .iter_mut()
        .find(|e| e.id == traffic_id)
        .ok_or(format!("Traffic entry {} not found", traffic_id))?;

    if let Some(notes) = params["notes"].as_str() {
        entry.notes = notes.to_string();
    }
    if let Some(color) = params["color"].as_str() {
        entry.color = color.to_string();
    }

    Ok(serde_json::json!({
        "traffic_id": traffic_id,
        "notes": entry.notes,
        "color": entry.color,
        "url": entry.url,
    }))
}

/// Send to Repeater — Take a traffic entry (by ID) or raw request,
/// optionally modify it, and replay it. Returns full response.
pub async fn handle_send_to_repeater(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;

    let (method, url, headers, body) = if let Some(traffic_id) = params["traffic_id"].as_u64() {
        let traffic = ps.traffic.lock().await;
        let entry = traffic
            .iter()
            .find(|e| e.id == traffic_id)
            .ok_or(format!("Traffic entry {} not found", traffic_id))?;

        let method = params["method"].as_str().unwrap_or(&entry.method).to_string();
        let url = params["url"].as_str().unwrap_or(&entry.url).to_string();
        let headers_str = params["raw_headers"].as_str().unwrap_or(&entry.request_headers).to_string();
        let body = params["body"].as_str().unwrap_or(&entry.request_body).to_string();

        let parsed_headers = parse_raw_headers(&headers_str);

        let mut final_headers = parsed_headers;
        if let Some(h_obj) = params["headers"].as_object() {
            for (k, v) in h_obj {
                if let Some(val) = v.as_str() {
                    final_headers.insert(k.to_lowercase(), val.to_string());
                }
            }
        }

        (method, url, final_headers, body)
    } else if let Some(url) = params["url"].as_str() {
        let method = params["method"].as_str().unwrap_or("GET").to_string();
        let body = params["body"].as_str().unwrap_or("").to_string();
        let mut headers = std::collections::HashMap::new();
        if let Some(h_obj) = params["headers"].as_object() {
            for (k, v) in h_obj {
                if let Some(val) = v.as_str() {
                    headers.insert(k.to_lowercase(), val.to_string());
                }
            }
        }
        (method, url.to_string(), headers, body)
    } else {
        return Err("Either traffic_id or url is required".into());
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("Client error: {}", e))?;

    let mut req = match method.to_uppercase().as_str() {
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "PATCH" => client.patch(&url),
        "HEAD" => client.head(&url),
        "OPTIONS" => client.request(reqwest::Method::OPTIONS, &url),
        _ => client.get(&url),
    };

    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if !body.is_empty() {
        req = req.body(body.clone());
    }

    let start = std::time::Instant::now();
    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let resp_headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let resp_body = resp.text().await.unwrap_or_default();
            let elapsed = start.elapsed().as_millis() as u64;

            let entry = TrafficEntry {
                id: ps.next_id(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                method: method.clone(),
                url: url.clone(),
                host: url::Url::parse(&url)
                    .map(|u| u.host_str().unwrap_or("").to_string())
                    .unwrap_or_default(),
                path: url::Url::parse(&url).map(|u| u.path().to_string()).unwrap_or_default(),
                port: url::Url::parse(&url).map(|u| u.port_or_known_default().unwrap_or(80)).unwrap_or(80),
                tls: url.starts_with("https"),
                status,
                response_length: resp_body.len(),
                response_time_ms: elapsed,
                mime_type: resp_headers
                    .iter()
                    .find(|(k, _)| k == "content-type")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default(),
                request_headers: headers
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect::<Vec<_>>()
                    .join("\r\n"),
                request_body: body.clone(),
                response_headers: resp_headers
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect::<Vec<_>>()
                    .join("\r\n"),
                response_body: resp_body.clone(),
                source: "repeater".into(),
                notes: String::new(),
                color: String::new(),
            };
            let entry_id = entry.id;
            ps.traffic.lock().await.push(entry);

            Ok(serde_json::json!({
                "status": status,
                "response_time_ms": elapsed,
                "response_length": resp_body.len(),
                "response_headers": resp_headers,
                "response_body": truncate_utf8(&resp_body, 8192),
                "traffic_id": entry_id,
                "source": "repeater",
            }))
        }
        Err(e) => Err(format!("Request failed: {}", e)),
    }
}

/// Send to Intruder — Take a traffic entry OR a still-pending intercept and
/// convert it to a fuzz_request config with auto-detected injection points
/// for query, body (JSON / form-urlencoded), and Cookie header values.
///
/// Accepts either `traffic_id` (numeric, from the traffic log) or
/// `intercept_id` (UUID, from get_intercepted) — bridges the on-hold-intercept
/// path into the attack chain without forcing the agent to forward first.
pub async fn handle_send_to_intruder(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;

    // Source resolution: prefer explicit intercept_id when present, otherwise
    // fall back to traffic_id. One of the two is mandatory.
    let intercept_id = params["intercept_id"].as_str();
    let traffic_id = params["traffic_id"].as_u64();

    let (method, url, request_body, headers, source_id, source_kind): (
        String,
        String,
        String,
        std::collections::HashMap<String, String>,
        String,
        &'static str,
    ) = if let Some(iid) = intercept_id {
        let parsed = fetch_intercepted(&ps, iid).await?;
        (parsed.method, parsed.url, parsed.body, parsed.headers, iid.to_string(), "intercept")
    } else if let Some(tid) = traffic_id {
        let traffic = ps.traffic.lock().await;
        let entry =
            traffic.iter().find(|e| e.id == tid).ok_or_else(|| format!("Traffic entry {} not found", tid))?;
        let hdrs: std::collections::HashMap<String, String> = entry
            .request_headers
            .lines()
            .filter_map(|line| {
                line.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            })
            .collect();
        (
            entry.method.clone(),
            entry.url.clone(),
            entry.request_body.clone(),
            hdrs,
            tid.to_string(),
            "traffic",
        )
    } else {
        return Err(
            "Either `traffic_id` (from proxy_get_traffic) or `intercept_id` (from get_intercepted) is required.".into(),
        );
    };

    let query_params: Vec<(String, String)> = url::Url::parse(&url)
        .map(|parsed| parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect())
        .unwrap_or_default();

    let mut suggested_url = url.clone();
    let mut suggested_body = request_body.clone();
    let mut positions = Vec::new();
    let override_category = params["category"].as_str();

    for (key, value) in query_params.iter() {
        let marker = format!("§{}§", key);
        suggested_url = suggested_url.replace(&format!("{}={}", key, value), &format!("{}={}", key, marker));
        let category = override_category.unwrap_or_else(|| infer_payload_category(key));
        positions.push(serde_json::json!({
            "marker": marker,
            "original_value": value,
            "parameter": key,
            "location": "query",
            "source": "file",
            "file_category": category,
            "limit": 200
        }));
    }

    // Body injection — accept POST/PUT/PATCH/DELETE (anything that typically
    // carries a body) and probe BOTH JSON-object AND form-urlencoded layouts.
    // Previously this was POST-only and JSON-only → form-encoded bodies
    // (`a=1&b=2`) and PUT/PATCH APIs produced zero body markers.
    let method_upper = method.to_ascii_uppercase();
    let body_method = matches!(method_upper.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
    if body_method && !request_body.is_empty() {
        let ctype = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.to_ascii_lowercase())
            .unwrap_or_default();

        let mut body_keys_added: std::collections::HashSet<String> = std::collections::HashSet::new();

        // 1. JSON body — recursive descent into nested objects + arrays.
        //
        // v0.3.10: previously we only marked top-level object keys, which
        // produced two broken results: (a) for nested objects like
        // `{ variables: { settingsId: "..." } }`, replacing `variables` with
        // a string payload broke JSON shape → upstream returned 400 every
        // probe → zero signal. (b) for GraphQL we'd mark the `query` field
        // (the GraphQL mutation source, structural) as XSS-categorized →
        // 400. The fix: descend into objects, collect every SCALAR LEAF as
        // an injection point, name it by its JSON pointer (`settingsId`,
        // `variables.settingsId`, `variables.targets[0]`), and GraphQL-aware
        // skip the `query`/`operationName` keys (structural), focusing on
        // `variables.*` instead.
        let looks_json = ctype.contains("json")
            || request_body.trim_start().starts_with('{')
            || request_body.trim_start().starts_with('[');
        if looks_json {
            if let Ok(body_json) = serde_json::from_str::<serde_json::Value>(&request_body) {
                // GraphQL heuristic: top-level keys `query`/`operationName`
                // are structural, `variables` is the data surface. When we
                // see that exact shape, descend only into `variables`.
                let is_graphql = body_json
                    .get("query")
                    .and_then(|v| v.as_str())
                    .map(|s| s.contains("query") || s.contains("mutation") || s.contains("subscription"))
                    .unwrap_or(false)
                    && body_json.get("variables").is_some();

                let mut leaves: Vec<(String, serde_json::Value)> = Vec::new();
                if is_graphql {
                    if let Some(vars) = body_json.get("variables") {
                        collect_scalar_leaves(vars, "variables", &mut leaves, 0);
                    }
                } else {
                    collect_scalar_leaves(&body_json, "", &mut leaves, 0);
                }

                // Hard cap so a 50-element array doesn't blow up the
                // intruder config. Caller can re-issue with more after
                // pruning.
                const MAX_BODY_LEAVES: usize = 40;
                let trimmed = leaves.len() > MAX_BODY_LEAVES;
                let leaves_iter = leaves.into_iter().take(MAX_BODY_LEAVES);

                for (path, value) in leaves_iter {
                    // Marker name is derived from the path (preserve dot/[i]
                    // notation so the agent can see exactly what's being
                    // fuzzed).
                    let marker = format!("§{}§", path);
                    // Use the LAST segment for category inference (e.g.
                    // `variables.targets[3]` -> `targets`).
                    let cat_key = path.rsplit_once('.').map(|(_, k)| k).unwrap_or(&path);
                    let cat_key = cat_key.split('[').next().unwrap_or(cat_key);
                    let category = override_category.unwrap_or_else(|| infer_payload_category(cat_key));

                    // Replace literal value in the raw body. We render the
                    // original value as JSON, replace with quoted marker.
                    // Best-effort; non-unique scalars may co-replace with
                    // others but the markers + path metadata still let the
                    // agent pick which to target.
                    let value_str = match &value {
                        serde_json::Value::String(s) => format!("\"{}\"", s),
                        _ => value.to_string(),
                    };
                    let value_with_marker = format!("\"{}\"", marker);
                    suggested_body = suggested_body.replace(&value_str, &value_with_marker);

                    positions.push(serde_json::json!({
                        "marker": marker,
                        "original_value": value,
                        "parameter": path,
                        "location": "body_json",
                        "source": "file",
                        "file_category": category,
                        "limit": 200,
                        "graphql": is_graphql,
                    }));
                    body_keys_added.insert(path);
                }

                if trimmed {
                    positions.push(serde_json::json!({
                        "note": format!(
                            "Body has more than {} scalar leaves — only first {} marked. Use `category` override or filter on `parameter` path to focus.",
                            MAX_BODY_LEAVES, MAX_BODY_LEAVES
                        ),
                        "location": "meta",
                    }));
                }
            }
        }

        // 2. Form-urlencoded body — `a=1&b=2`. Detected by content-type OR by
        // the absence of `{`/`[` and the presence of `=`.
        let looks_form = ctype.contains("x-www-form-urlencoded")
            || (!looks_json && request_body.contains('=') && !request_body.contains('\n'));
        if looks_form {
            for pair in request_body.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    let key = key.trim();
                    if key.is_empty() || body_keys_added.contains(key) {
                        continue;
                    }
                    let marker = format!("§{}§", key);
                    let category = override_category.unwrap_or_else(|| infer_payload_category(key));
                    suggested_body =
                        suggested_body.replace(&format!("{}={}", key, value), &format!("{}={}", key, marker));
                    positions.push(serde_json::json!({
                        "marker": marker,
                        "original_value": value,
                        "parameter": key,
                        "location": "body_form",
                        "source": "file",
                        "file_category": category,
                        "limit": 200
                    }));
                    body_keys_added.insert(key.to_string());
                }
            }
        }

        // 3. Multipart — detected by content-type. Mark each form-data part by
        // its `name="..."` attribute. We don't rewrite the body; the agent gets
        // pointers it can target with body_regex match rules.
        if ctype.starts_with("multipart/form-data") {
            let part_re = regex::Regex::new("name=\"([^\"]+)\"").ok();
            if let Some(re) = part_re {
                for cap in re.captures_iter(&request_body) {
                    if let Some(name) = cap.get(1) {
                        let key = name.as_str();
                        if body_keys_added.contains(key) {
                            continue;
                        }
                        let category = override_category.unwrap_or_else(|| infer_payload_category(key));
                        positions.push(serde_json::json!({
                            "marker": format!("§{}§", key),
                            "original_value": serde_json::Value::Null,
                            "parameter": key,
                            "location": "body_multipart",
                            "source": "file",
                            "file_category": category,
                            "limit": 200,
                            "note": "multipart name — replace the value of this form-data part manually before fuzzing",
                        }));
                        body_keys_added.insert(key.to_string());
                    }
                }
            }
        }
    }

    // 4. Cookie header — each cookie name is a parameter. Cookies are a *very*
    // common SQLi / XSS vector that gets missed when scanners only look at
    // query strings. We mark each Cookie name with a §§ marker that fuzz_request
    // can substitute.
    if let Some(cookie_header) =
        headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("cookie")).map(|(_, v)| v.clone())
    {
        for pair in cookie_header.split(';') {
            if let Some((name, value)) = pair.split_once('=') {
                let name = name.trim();
                if name.is_empty() {
                    continue;
                }
                let category = override_category.unwrap_or_else(|| infer_payload_category(name));
                positions.push(serde_json::json!({
                    "marker": format!("§cookie_{}§", name),
                    "original_value": value.trim(),
                    "parameter": name,
                    "location": "cookie",
                    "source": "file",
                    "file_category": category,
                    "limit": 200,
                    "note": "Cookie value — substitute via match_rules / Header injection in fuzz_request",
                }));
            }
        }
    }

    let intruder_config = serde_json::json!({
        "attack_type": "sniper",
        "base_request": {
            "method": method,
            "url": suggested_url,
            "headers": headers,
            "body": suggested_body,
        },
        "positions": positions,
        "match_rules": [
            { "type": "status_diff" },
            { "type": "length_diff", "threshold": 200 },
            { "type": "timing", "threshold_ms": 5000 },
        ],
        "max_concurrent": 10,
        "delay_ms": 0,
    });

    Ok(serde_json::json!({
        "source": source_kind,
        "source_id": source_id,
        "traffic_id": traffic_id,
        "intercept_id": intercept_id,
        "original_request": {
            "method": method,
            "url": url,
            "headers": headers,
            "body": request_body,
        },
        "injection_points": positions.len(),
        "intruder_config": intruder_config,
        "next_step": "Pass intruder_config straight to fuzz_request — payloads are auto-selected per parameter name. Override with the top-level `category` argument if the heuristic guesses wrong.",
    }))
}

/// Map a parameter name to the PayloadManager category that's most likely
/// to surface a vulnerability there. Used by send_to_intruder so the agent
/// gets a runnable config without having to know payload categories.
fn infer_payload_category(param: &str) -> &'static str {
    let p = param.to_ascii_lowercase();
    if p.ends_with("_id") || p == "id" || p == "uid" || p == "pid" || p == "uuid" {
        "sqli"
    } else if p.contains("redirect")
        || p.contains("return")
        || p == "next"
        || p == "url"
        || p == "dest"
        || p == "callback"
    {
        "open_redirect"
    } else if p.contains("path") || p.contains("file") || p == "include" || p == "template" {
        "lfi"
    } else if p.contains("cmd") || p.contains("exec") || p == "command" || p == "shell" {
        "cmdi"
    } else if p == "q"
        || p.contains("search")
        || p == "s"
        || p.contains("query")
        || p == "comment"
        || p == "message"
        || p == "text"
    {
        "xss"
    } else if p.contains("xml") || p == "data" {
        "xxe"
    } else if p == "user" || p == "username" || p == "login" || p == "password" || p == "pass" {
        "auth"
    } else if p == "filter" || p == "where" {
        "nosql"
    } else if p.contains("ssrf") || p == "host" {
        "ssrf"
    } else {
        "fuzzing"
    }
}

/// Get intercepted requests/responses waiting for decision.
/// Returns raw + structured parsed data — the agent decides what to do.
pub async fn handle_get_intercepted(_params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let pending = ps.pending_intercepts.lock().await;

    let items: Vec<serde_json::Value> = pending
        .values()
        .map(|p| {
            let mut parsed_headers: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
            let mut content_type = String::new();

            let lines: Vec<&str> = p.item.raw_request.lines().collect();
            let mut in_body = false;
            let mut body_lines = Vec::new();

            for (i, line) in lines.iter().enumerate() {
                if i == 0 {
                    continue;
                }
                if in_body {
                    body_lines.push(*line);
                } else if line.trim().is_empty() {
                    in_body = true;
                } else if let Some((k, v)) = line.split_once(':') {
                    let key = k.trim().to_string();
                    let val = v.trim().to_string();
                    if key.to_lowercase() == "content-type" {
                        content_type = val.clone();
                    }
                    parsed_headers.insert(key, serde_json::Value::String(val));
                }
            }
            let parsed_body = body_lines.join("\n");

            let mut query_params: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
            if let Some(q) = p.item.url.split('?').nth(1) {
                for pair in q.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        query_params.insert(
                            k.to_string(),
                            serde_json::Value::String(
                                v.replace("%20", " ")
                                    .replace("%3D", "=")
                                    .replace("%26", "&")
                                    .replace("%3F", "?")
                                    .replace("%2F", "/")
                                    .replace("%3A", ":")
                                    .replace("+", " "),
                            ),
                        );
                    }
                }
            }

            let path = p
                .item
                .url
                .split('?')
                .next()
                .unwrap_or(&p.item.url)
                .replace(&format!("https://{}", p.item.host), "")
                .replace(&format!("http://{}", p.item.host), "");

            serde_json::json!({
                "id": p.item.id,
                "type": if p.item.is_response { "response" } else { "request" },
                "method": p.item.method,
                "url": p.item.url,
                "host": p.item.host,
                "path": path,
                "timestamp": p.item.timestamp,
                "raw_request": p.item.raw_request,
                "raw_response": p.item.raw_response,
                "status": p.item.status,
                "parsed": {
                    "headers": serde_json::Value::Object(parsed_headers),
                    "body": parsed_body,
                    "body_size": parsed_body.len(),
                    "content_type": content_type,
                    "query_params": serde_json::Value::Object(query_params),
                },
            })
        })
        .collect();

    Ok(serde_json::json!({
        "pending_count": items.len(),
        "intercept_enabled": ps.is_intercept_enabled(),
        "response_intercept_enabled": ps.is_response_intercept_enabled(),
        "items": items,
    }))
}

/// Forward or drop an intercepted request. Supports three editing modes:
/// 1. No modification: forward_intercepted({id, action: "forward"})
/// 2. Raw edit: forward_intercepted({id, action: "forward", modified_raw: "GET /path HTTP/1.1\r\n..."})
/// 3. Structured edit: forward_intercepted({id, action: "forward", modify: {method, path, headers, body, add_headers, remove_headers}})
pub async fn handle_forward_intercepted(params: &serde_json::Value) -> HandlerResult {
    let ps = proxy()?;
    let id = params["id"].as_str().ok_or("Intercepted item id is required")?;
    let action = params["action"].as_str().unwrap_or("forward");

    let mut pending = ps.pending_intercepts.lock().await;
    let item = pending
        .remove(id)
        .ok_or(format!("No pending intercept with id '{}'. Use get_intercepted to list pending.", id))?;

    let original_method = item.item.method.clone();
    let original_url = item.item.url.clone();

    match action {
        "forward" => {
            if let Some(raw) = params["modified_raw"].as_str() {
                if !raw.is_empty() {
                    let _ = item.sender.send(InterceptDecision::Forward(raw.to_string()));
                    drop(pending);
                    ps.emit(ProxyEvent::InterceptResolved {
                        id: id.to_string(),
                        action: "forward_modified_raw".to_string(),
                    })
                    .await;
                    return Ok(serde_json::json!({
                        "id": id, "action": "forward", "mode": "raw_edit", "status": "resolved"
                    }));
                }
            }

            if let Some(modify) = params.get("modify") {
                let raw = &item.item.raw_request;
                let mut lines: Vec<String> = raw.lines().map(|l| l.to_string()).collect();

                if lines.is_empty() {
                    let _ = item.sender.send(InterceptDecision::Forward(String::new()));
                } else {
                    let req_parts: Vec<&str> = lines[0].split_whitespace().collect();
                    let mut method = req_parts.get(0).unwrap_or(&"GET").to_string();
                    let mut path = req_parts.get(1).unwrap_or(&"/").to_string();
                    let http_ver = req_parts.get(2).unwrap_or(&"HTTP/1.1").to_string();

                    if let Some(m) = modify["method"].as_str() {
                        method = m.to_uppercase();
                    }
                    if let Some(p) = modify["path"].as_str() {
                        path = p.to_string();
                    }

                    let mut header_map: Vec<(String, String)> = Vec::new();
                    let mut body_start = lines.len();
                    for (i, line) in lines.iter().enumerate().skip(1) {
                        if line.trim().is_empty() {
                            body_start = i + 1;
                            break;
                        }
                        if let Some((k, v)) = line.split_once(':') {
                            header_map.push((k.trim().to_string(), v.trim().to_string()));
                        }
                    }

                    let mut body =
                        if body_start < lines.len() { lines[body_start..].join("\n") } else { String::new() };

                    if let Some(hdrs) = modify["headers"].as_object() {
                        header_map.clear();
                        for (k, v) in hdrs {
                            if let Some(val) = v.as_str() {
                                header_map.push((k.clone(), val.to_string()));
                            }
                        }
                    }

                    if let Some(add) = modify["add_headers"].as_object() {
                        for (k, v) in add {
                            if let Some(val) = v.as_str() {
                                header_map.retain(|(hk, _)| !hk.eq_ignore_ascii_case(k));
                                header_map.push((k.clone(), val.to_string()));
                            }
                        }
                    }

                    if let Some(remove) = modify["remove_headers"].as_array() {
                        for r in remove {
                            if let Some(name) = r.as_str() {
                                header_map.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
                            }
                        }
                    }

                    if let Some(b) = modify["body"].as_str() {
                        body = b.to_string();
                        header_map.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
                        if !body.is_empty() {
                            header_map.push(("Content-Length".to_string(), body.len().to_string()));
                        }
                    }

                    let mut rebuilt = format!("{} {} {}\r\n", method, path, http_ver);
                    for (k, v) in &header_map {
                        rebuilt.push_str(&format!("{}: {}\r\n", k, v));
                    }
                    rebuilt.push_str("\r\n");
                    if !body.is_empty() {
                        rebuilt.push_str(&body);
                    }

                    let _ = item.sender.send(InterceptDecision::Forward(rebuilt));
                }
                drop(pending);
                ps.emit(ProxyEvent::InterceptResolved {
                    id: id.to_string(),
                    action: "forward_modified_json".to_string(),
                })
                .await;
                return Ok(serde_json::json!({
                    "id": id, "action": "forward", "mode": "structured_edit", "status": "resolved"
                }));
            }

            let _ = item.sender.send(InterceptDecision::Forward(String::new()));
        }
        "drop" => {
            let _ = item.sender.send(InterceptDecision::Drop);
        }
        _ => {
            pending.insert(id.to_string(), item);
            return Err(format!("Unknown action '{}'. Use 'forward' or 'drop'.", action));
        }
    }

    drop(pending);

    ps.emit(ProxyEvent::InterceptResolved { id: id.to_string(), action: action.to_string() }).await;

    if action == "forward" {
        // Poll the traffic log for an entry matching the forwarded request.
        // Correlate by URL + method + "after this point in time"; never
        // assume traffic.last() is ours (races with concurrent flows).
        let started_at = chrono::Utc::now();
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(5000);
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
            let traffic = ps.traffic.lock().await;
            let hit = traffic.iter().rev().find(|t| {
                t.url == original_url
                    && t.method.eq_ignore_ascii_case(&original_method)
                    && chrono::DateTime::parse_from_rfc3339(&t.timestamp)
                        .map(|ts| ts >= started_at)
                        .unwrap_or(false)
            });
            if let Some(t) = hit {
                return Ok(serde_json::json!({
                    "id": id, "action": action, "status": "resolved",
                    "response": {
                        "traffic_id": t.id,
                        "status_code": t.status,
                        "url": t.url,
                        "method": t.method,
                        "response_headers": t.response_headers,
                        "response_body": t.response_body,
                        "response_length": t.response_length,
                        "response_time_ms": t.response_time_ms,
                        "mime_type": t.mime_type,
                    },
                }));
            }
            drop(traffic);
            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }
        return Ok(serde_json::json!({
            "id": id, "action": action, "status": "resolved_no_response_yet",
            "hint": format!("Forwarded — no matching response within 5s. Poll proxy_search_traffic with query={:?} for the {} response.", original_url, original_method),
        }));
    }

    Ok(serde_json::json!({
        "id": id,
        "action": action,
        "status": "resolved",
    }))
}

// ── HAR-export helpers ───────────────────────────────────────────────────────

fn parse_raw_headers_har(raw: &str) -> Vec<serde_json::Value> {
    raw.lines()
        .filter_map(|line| {
            let idx = line.find(':')?;
            let name = line[..idx].trim();
            let value = line[idx + 1..].trim();
            if name.is_empty() {
                return None;
            }
            Some(serde_json::json!({ "name": name, "value": value }))
        })
        .collect()
}

fn parse_query_string_har(url: &str) -> Vec<serde_json::Value> {
    let Some(q) = url.split_once('?').map(|(_, q)| q) else { return Vec::new() };
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            serde_json::json!({
                "name": urlencoding::decode(k).map(|s| s.into_owned()).unwrap_or_else(|_| k.to_string()),
                "value": urlencoding::decode(v).map(|s| s.into_owned()).unwrap_or_else(|_| v.to_string()),
            })
        })
        .collect()
}

fn header_value(raw: &str, want: &str) -> Option<String> {
    raw.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(want) {
            Some(v.trim().to_string())
        } else {
            None
        }
    })
}

fn http_status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

/// Truncate a UTF-8 string at byte index, snapping to the previous char
/// boundary so non-ASCII bodies don't panic. Appends a `[truncated, N bytes total]`
/// suffix when truncation occurs. Binary responses are still readable enough
/// for the agent to spot magic bytes (GIF89a, PNG header, ELF, etc.).
pub fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut cut = max_bytes;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}... [truncated, {} bytes total]", &s[..cut], s.len())
}

fn parse_raw_headers(raw: &str) -> std::collections::HashMap<String, String> {
    let mut headers = std::collections::HashMap::new();
    for line in raw.lines() {
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_lowercase();
            let value = line[colon_pos + 1..].trim().to_string();
            if !key.is_empty() {
                headers.insert(key, value);
            }
        }
    }
    headers
}
