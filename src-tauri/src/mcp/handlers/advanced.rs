// ═══════════════════════════════════════════════════════════════════════
//  Advanced Handlers — raw TCP, mTLS, race conditions, H2, Bambda filter
// ═══════════════════════════════════════════════════════════════════════

use std::sync::Arc;
use crate::mcp::types::HandlerResult;

pub async fn handle_raw_tcp_send(params: &serde_json::Value) -> HandlerResult {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let host = params["host"].as_str().ok_or("Missing host")?;
    let use_tls = params["tls"].as_bool().unwrap_or(false);
    let port = params["port"].as_u64().unwrap_or(if use_tls { 443 } else { 80 }) as u16;
    let read_timeout = params["read_timeout_ms"].as_u64().unwrap_or(5000);
    let read_size = params["read_size"].as_u64().unwrap_or(65536) as usize;

    let start = std::time::Instant::now();
    let addr = format!("{}:{}", host, port);
    let tcp_stream = tokio::net::TcpStream::connect(&addr).await.map_err(|e| format!("TCP connect failed: {}", e))?;
    let connect_ms = start.elapsed().as_millis();

    let raw = if let Some(hex) = params["data_hex"].as_str() {
        hex.split_whitespace().filter_map(|h| u8::from_str_radix(h.trim(), 16).ok()).collect::<Vec<u8>>()
    } else {
        let data_str = params["data"].as_str().unwrap_or("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")
            .replace("{host}", host).replace("\\r\\n", "\r\n").replace("\\n", "\n").replace("\\0", "\0");
        data_str.into_bytes()
    };

    if use_tls {
        let cx = native_tls::TlsConnector::builder().danger_accept_invalid_certs(true).build().map_err(|e| format!("TLS: {}", e))?;
        let cx = tokio_native_tls::TlsConnector::from(cx);
        let mut tls_stream = cx.connect(host, tcp_stream).await.map_err(|e| format!("TLS handshake: {}", e))?;
        tls_stream.write_all(&raw).await.map_err(|e| format!("Write: {}", e))?;
        tls_stream.flush().await.ok();
        let mut buf = vec![0u8; read_size];
        let n = tokio::time::timeout(std::time::Duration::from_millis(read_timeout), tls_stream.read(&mut buf)).await.unwrap_or(Ok(0)).unwrap_or(0);
        Ok(serde_json::json!({"bytes_sent": raw.len(), "bytes_received": n, "connect_ms": connect_ms, "total_ms": start.elapsed().as_millis(), "tls": true, "response": String::from_utf8_lossy(&buf[..n]), "response_hex": buf[..n].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")}))
    } else {
        let mut stream = tcp_stream;
        stream.write_all(&raw).await.map_err(|e| format!("Write: {}", e))?;
        stream.flush().await.ok();
        let mut buf = vec![0u8; read_size];
        let n = tokio::time::timeout(std::time::Duration::from_millis(read_timeout), stream.read(&mut buf)).await.unwrap_or(Ok(0)).unwrap_or(0);
        Ok(serde_json::json!({"bytes_sent": raw.len(), "bytes_received": n, "connect_ms": connect_ms, "total_ms": start.elapsed().as_millis(), "tls": false, "response": String::from_utf8_lossy(&buf[..n]), "response_hex": buf[..n].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")}))
    }
}

pub async fn handle_mtls_send_request(params: &serde_json::Value) -> HandlerResult {
    let method = params["method"].as_str().unwrap_or("GET");
    let url_str = params["url"].as_str().ok_or("Missing url")?;
    let pkcs12_base64 = params["client_pkcs12_base64"].as_str();
    let pkcs12_password = params["pkcs12_password"].as_str().unwrap_or("");

    let client = if let Some(p12_b64) = pkcs12_base64 {
        let p12_bytes = crate::mcp::utils::base64_decode_bytes(p12_b64);
        let native_identity = native_tls::Identity::from_pkcs12(&p12_bytes, pkcs12_password).map_err(|e| format!("Invalid PKCS12: {}", e))?;
        let tls_connector = native_tls::TlsConnector::builder().identity(native_identity).danger_accept_invalid_certs(true).build().map_err(|e| format!("TLS build: {}", e))?;
        reqwest::Client::builder().use_preconfigured_tls(tls_connector).build().map_err(|e: reqwest::Error| e.to_string())?
    } else { reqwest::Client::builder().danger_accept_invalid_certs(true).build().map_err(|e: reqwest::Error| e.to_string())? };

    let start = std::time::Instant::now();
    let mut req = match method.to_uppercase().as_str() { "POST" => client.post(url_str), "PUT" => client.put(url_str), "DELETE" => client.delete(url_str), "PATCH" => client.patch(url_str), "HEAD" => client.head(url_str), _ => client.get(url_str) };
    if let Some(headers) = params["headers"].as_object() { for (k, v) in headers { if let Some(val) = v.as_str() { req = req.header(k.as_str(), val); } } }
    if let Some(body) = params["body"].as_str() { req = req.body(body.to_string()); }
    let resp = req.send().await.map_err(|e: reqwest::Error| e.to_string())?;
    let elapsed = start.elapsed().as_millis();
    let status = resp.status().as_u16();
    let resp_headers: std::collections::HashMap<String, String> = resp.headers().iter().map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string())).collect();
    let body: String = resp.text().await.unwrap_or_default();
    Ok(serde_json::json!({"status": status, "headers": resp_headers, "body_preview": body.chars().take(2000).collect::<String>(), "body_size": body.len(), "elapsed_ms": elapsed, "mtls": true}))
}

pub async fn handle_race_request(params: &serde_json::Value) -> HandlerResult {
    let gate_timeout = params["gate_timeout_ms"].as_u64().unwrap_or(5000);

    // ── Build request list ──
    let mut requests: Vec<serde_json::Value> = Vec::new();

    // Option 1: explicit array
    if let Some(arr) = params["requests"].as_array() {
        requests = arr.clone();
    }

    // Option 2: repeat_count + template_request
    if requests.is_empty() {
        let count = params["repeat_count"].as_u64().unwrap_or(0).min(50);
        let template = params["template_request"].as_object();
        if count > 0 {
            if let Some(tmpl) = template {
                for _ in 0..count {
                    requests.push(serde_json::Value::Object(tmpl.clone()));
                }
            }
        }
    }

    if requests.is_empty() {
        return Ok(serde_json::json!({
            "error": "No requests to fire. Provide 'requests' array or 'repeat_count' + 'template_request'.",
            "received_params": {
                "has_requests": params["requests"].is_array(),
                "repeat_count": params["repeat_count"].as_u64(),
                "has_template": params["template_request"].is_object(),
            }
        }));
    }

    let n = requests.len();
    let requests_clone = requests.clone();

    // ── Run all race requests in an ISOLATED thread+runtime ──
    // This prevents any panic or deadlock from crashing the MCP server
    let (result_tx, result_rx) = std::sync::mpsc::channel::<serde_json::Value>();

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = result_tx.send(serde_json::json!({
                    "error": format!("Failed to create race runtime: {}", e),
                    "total_requests": n,
                }));
                return;
            }
        };

        let result = rt.block_on(async move {
            let start_time = std::time::Instant::now();
            let go_signal = std::sync::Arc::new(tokio::sync::Notify::new());
            let per_req_timeout = std::time::Duration::from_millis(gate_timeout);

            let mut handles = Vec::new();
            for (idx, req) in requests_clone.into_iter().enumerate() {
                let go = go_signal.clone();
                let method = req["method"].as_str().unwrap_or("GET").to_uppercase();
                let url_str = req["url"].as_str().unwrap_or("").to_string();
                let body = req["body"].as_str().unwrap_or("").to_string();
                let custom_headers: Vec<(String, String)> = req["headers"]
                    .as_object()
                    .map(|h| h.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
                    .unwrap_or_default();

                handles.push(tokio::spawn(async move {
                    let client = reqwest::Client::builder()
                        .danger_accept_invalid_certs(true)
                        .timeout(per_req_timeout)
                        .pool_max_idle_per_host(0)
                        .no_proxy()
                        .build()
                        .map_err(|e| e.to_string())?;

                    let m = match method.as_str() {
                        "POST" => reqwest::Method::POST, "PUT" => reqwest::Method::PUT,
                        "DELETE" => reqwest::Method::DELETE, "PATCH" => reqwest::Method::PATCH,
                        _ => reqwest::Method::GET,
                    };
                    let mut rb = client.request(m, &url_str);
                    for (k, v) in &custom_headers { rb = rb.header(k.as_str(), v.as_str()); }
                    if !body.is_empty() { rb = rb.body(body); }

                    // Wait for go signal (with 2s timeout to prevent deadlock)
                    let pre_wait = std::time::Instant::now();
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), go.notified()).await;
                    let wait_us = pre_wait.elapsed().as_micros();

                    // Fire!
                    let fire_time = std::time::Instant::now();
                    let result = rb.send().await;
                    let response_ms = fire_time.elapsed().as_millis();

                    match result {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let body_text = resp.text().await.unwrap_or_default();
                            let preview_len = body_text.len().min(500);
                            Ok::<serde_json::Value, String>(serde_json::json!({
                                "index": idx, "status": status,
                                "response_ms": response_ms, "barrier_wait_us": wait_us,
                                "body_length": body_text.len(),
                                "body_preview": &body_text[..preview_len]
                            }))
                        }
                        Err(e) => Ok(serde_json::json!({
                            "index": idx, "error": e.to_string(),
                            "response_ms": response_ms, "barrier_wait_us": wait_us
                        }))
                    }
                }));
            }

            // Small delay to let all tasks reach the wait point, then fire all at once
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            go_signal.notify_waiters();

            // Collect results with hard timeout
            let mut race_results: Vec<serde_json::Value> = Vec::new();
            for handle in handles {
                match tokio::time::timeout(std::time::Duration::from_secs(10), handle).await {
                    Ok(Ok(Ok(v))) => race_results.push(v),
                    Ok(Ok(Err(e))) => race_results.push(serde_json::json!({"error": e})),
                    Ok(Err(e)) => race_results.push(serde_json::json!({"error": e.to_string()})),
                    Err(_) => race_results.push(serde_json::json!({"error": "timed out"})),
                }
            }

            let response_times: Vec<u64> = race_results.iter().filter_map(|r| r["response_ms"].as_u64()).collect();
            let statuses: Vec<u64> = race_results.iter().filter_map(|r| r["status"].as_u64()).collect();
            let min_ms = response_times.iter().copied().min().unwrap_or(0);
            let max_ms = response_times.iter().copied().max().unwrap_or(0);
            let all_same = statuses.windows(2).all(|w| w[0] == w[1]);

            serde_json::json!({
                "total_requests": n,
                "total_ms": start_time.elapsed().as_millis(),
                "timing_spread_ms": max_ms.saturating_sub(min_ms),
                "fastest_ms": min_ms,
                "slowest_ms": max_ms,
                "all_same_status": all_same,
                "status_codes": statuses,
                "results": race_results,
                "race_condition_indicators": {
                    "timing_spread_low": (max_ms - min_ms) < 50,
                    "mixed_statuses": !all_same,
                }
            })
        });

        let _ = result_tx.send(result);
    });

    // Wait for result from isolated thread (max 15s)
    match result_rx.recv_timeout(std::time::Duration::from_secs(15)) {
        Ok(result) => Ok(result),
        Err(_) => Ok(serde_json::json!({
            "error": "Race request timed out after 15s",
            "total_requests": n,
        })),
    }
}


pub async fn handle_h2_send_request(params: &serde_json::Value) -> HandlerResult {
    let url = params["url"].as_str().ok_or("Missing url")?;
    let method_str = params["method"].as_str().unwrap_or("GET").to_uppercase();
    let body = params["body"].as_str().unwrap_or("");
    let client = reqwest::Client::builder().danger_accept_invalid_certs(true).timeout(std::time::Duration::from_secs(15)).build().map_err(|e| e.to_string())?;
    let m = match method_str.as_str() { "POST" => reqwest::Method::POST, "PUT" => reqwest::Method::PUT, "DELETE" => reqwest::Method::DELETE, "PATCH" => reqwest::Method::PATCH, _ => reqwest::Method::GET };
    let mut req = client.request(m, url);
    if let Some(headers) = params["headers"].as_object() { for (k, v) in headers { if let Some(val) = v.as_str() { req = req.header(k.as_str(), val); } } }
    if !body.is_empty() { req = req.body(body.to_string()); }
    let start = std::time::Instant::now();
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let elapsed = start.elapsed().as_millis();
    let status = resp.status().as_u16();
    let version = format!("{:?}", resp.version());
    let headers: std::collections::HashMap<String, String> = resp.headers().iter().map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string())).collect();
    let resp_body = resp.text().await.unwrap_or_default();
    Ok(serde_json::json!({"status": status, "protocol": version, "headers": headers, "body_preview": resp_body.chars().take(2000).collect::<String>(), "body_size": resp_body.len(), "elapsed_ms": elapsed}))
}

pub async fn handle_bambda_filter(params: &serde_json::Value) -> HandlerResult {
    let expression = params["expression"].as_str().ok_or("Missing expression")?;
    let traffic_json = params["traffic"].as_array();
    let conditions = crate::mcp::utils::parse_bambda_expression(expression)?;
    if let Some(traffic) = traffic_json {
        let filtered: Vec<&serde_json::Value> = traffic.iter().filter(|item| crate::mcp::utils::evaluate_bambda_conditions(item, &conditions)).collect();
        Ok(serde_json::json!({"expression": expression, "total_items": traffic.len(), "matched_items": filtered.len(), "filtered": filtered, "conditions_parsed": conditions.len()}))
    } else {
        Ok(serde_json::json!({"expression": expression, "valid": true, "conditions_parsed": conditions.len(), "conditions": conditions.iter().map(|c| serde_json::json!({"field": c.field, "operator": c.operator, "value": c.value})).collect::<Vec<_>>(), "note": "Expression parsed successfully. Provide 'traffic' array to apply the filter."}))
    }
}
