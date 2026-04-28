// ═══════════════════════════════════════════════════════════════════════
//  HTTP Handler — universal send_request (the AI's primary HTTP tool)
// ═══════════════════════════════════════════════════════════════════════

use crate::mcp::types::HandlerResult;
use crate::mcp::activity::{log_mcp_traffic, next_mcp_traffic_id};
use crate::mcp::types::McpTrafficEntry;
use crate::mcp::client::HttpClientFactory;

pub async fn handle_send_request(params: &serde_json::Value) -> HandlerResult {
    let method = params["method"].as_str().unwrap_or("GET");
    let url = params["url"].as_str().ok_or("Missing url")?;

    let client = HttpClientFactory::default_client()?;

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
