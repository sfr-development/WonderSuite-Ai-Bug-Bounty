use crate::mcp::client::HttpClientFactory;
use crate::mcp::types::HandlerResult;
use crate::mcp::utils::extract_html_title;

pub async fn handle_browser_navigate(params: &serde_json::Value) -> HandlerResult {
    let action = params["action"].as_str().ok_or("Missing action")?;
    match action {
        "open" | "navigate" => {
            let url = params["url"].as_str().ok_or("Missing url")?;
            let wait_ms = params["wait_ms"].as_u64().unwrap_or(2000);
            let cdp_port = crate::browser::get_cdp_port();
            let cdp_active = crate::browser::is_cdp_active();

            if !cdp_active {
                let browsers = crate::browser::detect_browsers();
                let browser = browsers.first().ok_or("No Chromium browser found")?;
                let profile_dir = format!(
                    "{}/.wondersuite/browser-profile",
                    std::env::var("USERPROFILE")
                        .unwrap_or_else(|_| std::env::var("HOME").unwrap_or_default())
                );

                let args: Vec<String> = vec![
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

                let child = std::process::Command::new(&browser.path)
                    .args(&args)
                    .spawn()
                    .map_err(|e| format!("Failed to launch browser: {}", e))?;
                if wait_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await;
                }

                let cdp_url = format!("http://127.0.0.1:{}/json", cdp_port);
                let client = HttpClientFactory::default_client()?;

                let mut tabs_info = serde_json::json!(null);
                for _ in 0..3 {
                    if let Ok(resp) = client.get(&cdp_url).send().await {
                        if let Ok(tabs) = resp.json::<Vec<serde_json::Value>>().await {
                            tabs_info = serde_json::json!(tabs);
                            break;
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }

                let capture_port = cdp_port;
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    crate::browser::start_network_capture_cdp(capture_port).await;
                });

                Ok(serde_json::json!({
                    "action": action, "url": url, "browser": browser.name,
                    "pid": child.id(), "cdp_port": cdp_port,
                    "cdp_url": format!("http://127.0.0.1:{}", cdp_port),
                    "tabs": tabs_info,
                    "proxy": "direct (no proxy)",
                    "network_capture": "auto-started — use browser_network_traffic to read captured requests",
                    "tip": "All HTTP traffic is being captured. Login or browse, then use browser_network_traffic to see all requests/responses."
                }))
            } else {
                let cdp_url = format!("http://127.0.0.1:{}/json", cdp_port);
                let client = HttpClientFactory::default_client()?;
                let tabs_resp = client.get(&cdp_url).send().await.map_err(|e| {
                    format!("CDP not reachable: {} — launch browser first with 'open' action", e)
                })?;
                let tabs: Vec<serde_json::Value> = tabs_resp.json().await.map_err(|e| e.to_string())?;

                if let Some(tab) = tabs.iter().find(|t| t["type"].as_str() == Some("page")) {
                    if let Some(ws_url) = tab["webSocketDebuggerUrl"].as_str() {
                        let (mut ws, _) = tokio_tungstenite::connect_async(ws_url)
                            .await
                            .map_err(|e| format!("CDP WS connect: {}", e))?;
                        use futures_util::SinkExt;
                        use tokio_tungstenite::tungstenite::Message;
                        let nav_cmd =
                            serde_json::json!({"id":1,"method":"Page.navigate","params":{"url":url}});
                        ws.send(Message::Text(nav_cmd.to_string().into()))
                            .await
                            .map_err(|e| e.to_string())?;
                        if wait_ms > 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await;
                        }
                    }
                }

                let page_info = match client.get(url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        serde_json::json!({"status": status, "title": extract_html_title(&body), "body_length": body.len()})
                    }
                    _ => {
                        serde_json::json!({"note": "Browser navigated via CDP"})
                    }
                };

                Ok(serde_json::json!({
                    "action": "navigate (CDP)", "url": url,
                    "cdp_port": cdp_port, "page_info": page_info,
                }))
            }
        }
        "get_page" => {
            let url = params["url"].as_str().ok_or("Missing url")?;
            let client = HttpClientFactory::default_client()?;
            let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let hdrs: Vec<String> =
                resp.headers().iter().map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or(""))).collect();
            let body = resp.text().await.unwrap_or_default();
            Ok(serde_json::json!({"url": url, "status": status, "title": extract_html_title(&body),
                "headers": hdrs, "body_length": body.len(), "body_preview": &body[..body.len().min(5000)],
                "links": crate::mcp::utils::extract_links(&body, url), "forms": crate::mcp::utils::extract_forms(&body)}))
        }
        _ => Ok(serde_json::json!({"action": action, "instruction": "Browser action dispatched"})),
    }
}

pub async fn handle_browser_execute_js(params: &serde_json::Value) -> HandlerResult {
    let code = params["code"].as_str().ok_or("Missing code")?;
    let await_promise = params["await_promise"].as_bool().unwrap_or(true);
    let timeout_ms = params["timeout_ms"].as_u64().unwrap_or(10000);

    let cdp_port = crate::browser::get_cdp_port();
    let cdp_url = format!("http://127.0.0.1:{}/json", cdp_port);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .connect_timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(|e| e.to_string())?;
    let tabs_resp = client.get(&cdp_url).send().await
        .map_err(|_| format!("No browser with CDP debugging on port {}. Use browser_navigate with action:'open' to launch one first.", cdp_port))?;
    let tabs: Vec<serde_json::Value> =
        tabs_resp.json().await.map_err(|e| format!("Failed to parse CDP tabs: {}", e))?;

    let tab_id = params["tab_id"].as_u64();
    let target_tab = if let Some(tid) = tab_id {
        tabs.get(tid as usize).ok_or("Tab ID out of range")?
    } else {
        tabs.iter().find(|t| t["type"].as_str() == Some("page")).ok_or("No page tab found")?
    };

    let ws_url = target_tab["webSocketDebuggerUrl"].as_str().ok_or("No WebSocket debugger URL for tab")?;
    let tab_url = target_tab["url"].as_str().unwrap_or("unknown");
    let tab_title = target_tab["title"].as_str().unwrap_or("unknown");

    let (mut ws_stream, _) = tokio_tungstenite::connect_async(ws_url)
        .await
        .map_err(|e| format!("CDP WebSocket connect failed: {}", e))?;

    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let eval_msg = serde_json::json!({
        "id": 1, "method": "Runtime.evaluate",
        "params": {
            "expression": code, "awaitPromise": await_promise,
            "returnByValue": true, "timeout": timeout_ms, "userGesture": true,
        }
    });

    ws_stream
        .send(Message::Text(eval_msg.to_string().into()))
        .await
        .map_err(|e| format!("CDP send failed: {}", e))?;

    let result = tokio::time::timeout(std::time::Duration::from_millis(timeout_ms + 2000), async {
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
    })
    .await
    .map_err(|_| "CDP evaluation timed out".to_string())??;

    let _ = ws_stream.close(None).await;

    let cdp_result = &result["result"]["result"];
    let exception = &result["result"]["exceptionDetails"];

    if exception.is_object() {
        Ok(serde_json::json!({
            "success": false, "error": exception["text"].as_str().unwrap_or("JavaScript error"),
            "exception": exception, "tab_url": tab_url, "tab_title": tab_title,
        }))
    } else {
        Ok(serde_json::json!({
            "success": true, "type": cdp_result["type"].as_str().unwrap_or("undefined"),
            "value": cdp_result["value"], "description": cdp_result["description"],
            "tab_url": tab_url, "tab_title": tab_title,
        }))
    }
}

pub async fn handle_session_from_browser(params: &serde_json::Value) -> HandlerResult {
    let domain = params["domain"].as_str();
    let include_ls = params["include_local_storage"].as_bool().unwrap_or(true);
    let include_ss = params["include_session_storage"].as_bool().unwrap_or(true);

    let cdp_port = crate::browser::get_cdp_port();
    let cdp_url = format!("http://127.0.0.1:{}/json", cdp_port);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .connect_timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(|e| e.to_string())?;
    let tabs: Vec<serde_json::Value> = client.get(&cdp_url).send().await
        .map_err(|_| format!("No browser with CDP debugging on port {}. Use browser_navigate with action:'open' to launch one first.", cdp_port))?
        .json().await.map_err(|e| format!("Parse CDP tabs: {}", e))?;

    let target_tab = tabs.iter().find(|t| t["type"].as_str() == Some("page")).ok_or("No page tab found")?;
    let ws_url = target_tab["webSocketDebuggerUrl"].as_str().ok_or("No WS debugger URL")?;
    let tab_url = target_tab["url"].as_str().unwrap_or("unknown");

    let (mut ws, _) =
        tokio_tungstenite::connect_async(ws_url).await.map_err(|e| format!("CDP connect: {}", e))?;

    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let mut msg_id = 1u64;

    async fn cdp_call(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        id: u64,
        method: &str,
        cdp_params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let msg = serde_json::json!({"id": id, "method": method, "params": cdp_params});
        ws.send(Message::Text(msg.to_string().into())).await.map_err(|e| e.to_string())?;
        let timeout = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while let Some(Ok(Message::Text(ref text))) = ws.next().await {
                if let Ok(r) = serde_json::from_str::<serde_json::Value>(&text) {
                    if r["id"].as_u64() == Some(id) {
                        return Ok(r);
                    }
                }
            }
            Err("Connection closed".to_string())
        })
        .await
        .map_err(|_| "CDP timeout".to_string())?;
        timeout
    }

    let cookie_result = cdp_call(&mut ws, msg_id, "Network.getAllCookies", serde_json::json!({})).await?;
    msg_id += 1;
    let all_cookies = cookie_result["result"]["cookies"].as_array().cloned().unwrap_or_default();

    let filtered_cookies: Vec<&serde_json::Value> = if let Some(d) = domain {
        all_cookies
            .iter()
            .filter(|c| {
                c["domain"]
                    .as_str()
                    .map_or(false, |cd| cd.contains(d) || d.contains(cd.trim_start_matches('.')))
            })
            .collect()
    } else {
        all_cookies.iter().collect()
    };

    let cookie_header: String = filtered_cookies
        .iter()
        .filter_map(|c| Some(format!("{}={}", c["name"].as_str()?, c["value"].as_str()?)))
        .collect::<Vec<_>>()
        .join("; ");

    let mut local_storage = serde_json::json!(null);
    if include_ls {
        let ls_result = cdp_call(&mut ws, msg_id, "Runtime.evaluate", serde_json::json!({
            "expression": "JSON.stringify(Object.fromEntries(Object.entries(localStorage)))", "returnByValue": true
        })).await?;
        msg_id += 1;
        if let Some(val) = ls_result["result"]["result"]["value"].as_str() {
            local_storage = serde_json::from_str(val).unwrap_or(serde_json::json!({}));
        }
    }

    let mut session_storage = serde_json::json!(null);
    if include_ss {
        let ss_result = cdp_call(&mut ws, msg_id, "Runtime.evaluate", serde_json::json!({
            "expression": "JSON.stringify(Object.fromEntries(Object.entries(sessionStorage)))", "returnByValue": true
        })).await?;
        let _ = msg_id; // suppress unused warning
        if let Some(val) = ss_result["result"]["result"]["value"].as_str() {
            session_storage = serde_json::from_str(val).unwrap_or(serde_json::json!({}));
        }
    }

    let _ = ws.close(None).await;
    let auto_apply = params["auto_apply"].as_bool().unwrap_or(true);

    Ok(serde_json::json!({
        "tab_url": tab_url, "domain_filter": domain,
        "cookies": filtered_cookies, "cookie_count": filtered_cookies.len(),
        "cookie_header": cookie_header, "local_storage": local_storage,
        "session_storage": session_storage, "auto_applied": auto_apply,
        "usage": "Use the 'cookie_header' value in your request headers: Cookie: <value>",
    }))
}

pub async fn handle_browser_network_traffic(params: &serde_json::Value) -> HandlerResult {
    let action = params["action"].as_str().unwrap_or("get");
    let cdp_active = crate::browser::is_cdp_active();
    let capture_active = crate::browser::is_network_capture_active();

    match action {
        "status" => {
            let log = crate::browser::get_network_log();
            Ok(serde_json::json!({
                "browser_running": cdp_active,
                "network_capture_active": capture_active,
                "total_entries": log.len(),
                "cdp_port": crate::browser::get_cdp_port(),
                "hint": if !cdp_active {
                    "No browser is running. Use browser_navigate with action:'open' to launch the WonderBrowser, then navigate to the target site and login. All network traffic will be automatically captured."
                } else if !capture_active {
                    "Browser is running but network capture is not active. This may happen if the browser was launched externally. Try restarting the browser via browser_navigate."
                } else {
                    "Network capture is active. Browse the target site and all HTTP traffic (XHR, Fetch, Document) will be captured here."
                }
            }))
        }
        "clear" => {
            crate::browser::clear_network_log();
            Ok(serde_json::json!({"action": "cleared", "message": "Network traffic log cleared"}))
        }
        "get" | "filter" => {
            if !cdp_active {
                return Ok(serde_json::json!({
                    "entries": [],
                    "total": 0,
                    "hint": "⚠️ No browser is running! Please use browser_navigate with action:'open' to launch the WonderBrowser first. Navigate to the target site (e.g. a login page) and interact with it. All network requests will be automatically captured and visible here.",
                    "suggested_action": "browser_navigate",
                    "suggested_params": {"action": "open", "url": "https://cloud.renostar.app/identity/auth"}
                }));
            }

            let all_entries = crate::browser::get_network_log();

            if all_entries.is_empty() && capture_active {
                return Ok(serde_json::json!({
                    "entries": [],
                    "total": 0,
                    "hint": "Network capture is active but no traffic has been recorded yet. Please navigate to a page or login in the WonderBrowser. Tip: The capture only records XHR, Fetch, Document, Script, and Stylesheet requests (images/fonts are filtered out).",
                    "capture_active": true
                }));
            }

            let limit = params["limit"].as_u64().unwrap_or(100) as usize;
            let url_filter = params["url_contains"].as_str();
            let method_filter = params["method"].as_str();
            let status_filter = params["status"].as_u64().map(|s| s as u16);
            let type_filter = params["resource_type"].as_str();
            let exclude_static = params["exclude_static"].as_bool().unwrap_or(true);

            let filtered: Vec<&crate::browser::NetworkEntry> = all_entries
                .iter()
                .filter(|e| {
                    if let Some(f) = url_filter {
                        if !e.url.to_lowercase().contains(&f.to_lowercase()) {
                            return false;
                        }
                    }
                    if let Some(m) = method_filter {
                        if !e.method.eq_ignore_ascii_case(m) {
                            return false;
                        }
                    }
                    if let Some(s) = status_filter {
                        if e.status != Some(s) {
                            return false;
                        }
                    }
                    if let Some(t) = type_filter {
                        if e.resource_type.as_deref() != Some(t) {
                            return false;
                        }
                    }
                    if exclude_static {
                        let rtype = e.resource_type.as_deref().unwrap_or("");
                        if matches!(rtype, "Image" | "Font" | "Media") {
                            return false;
                        }
                        if e.url.starts_with("data:") || e.url.starts_with("chrome-extension:") {
                            return false;
                        }
                    }
                    true
                })
                .rev() // Most recent first
                .take(limit)
                .collect();

            let mut auth_requests: Vec<&crate::browser::NetworkEntry> = Vec::new();
            let mut api_requests: Vec<&crate::browser::NetworkEntry> = Vec::new();
            for e in &filtered {
                let url_lower = e.url.to_lowercase();
                if url_lower.contains("auth")
                    || url_lower.contains("login")
                    || url_lower.contains("token")
                    || url_lower.contains("session")
                    || url_lower.contains("identity")
                    || url_lower.contains("oauth")
                {
                    auth_requests.push(e);
                }
                if url_lower.contains("/api/") || url_lower.contains("graphql") {
                    api_requests.push(e);
                }
            }

            Ok(serde_json::json!({
                "entries": filtered,
                "total": all_entries.len(),
                "filtered_count": filtered.len(),
                "capture_active": capture_active,
                "auth_requests_found": auth_requests.len(),
                "api_requests_found": api_requests.len(),
                "hint": if !auth_requests.is_empty() {
                    format!("🔐 Found {} authentication-related requests! Check these for tokens, credentials, and session info.", auth_requests.len())
                } else if !api_requests.is_empty() {
                    format!("🌐 Found {} API requests. Analyze these for IDOR, authorization bypass, and data exposure.", api_requests.len())
                } else if filtered.is_empty() {
                    "No matching traffic found. Try adjusting your filters or interact with the browser.".to_string()
                } else {
                    format!("Showing {} of {} total captured entries.", filtered.len(), all_entries.len())
                }
            }))
        }
        "start_capture" => {
            if !cdp_active {
                return Err("No browser running. Use browser_navigate with action:'open' first.".into());
            }
            let cdp_port = crate::browser::get_cdp_port();
            tokio::spawn(async move {
                crate::browser::start_network_capture_cdp(cdp_port).await;
            });
            Ok(serde_json::json!({"action": "capture_started", "cdp_port": cdp_port}))
        }
        _ => Err(format!("Unknown action '{}'. Use: get, filter, clear, status, start_capture", action)),
    }
}
