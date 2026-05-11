// CDP-driven JS-render pass.
//
// When the crawler's SPA detector flags a page as JS-heavy, the URL is
// re-fetched through the already-launched WonderBrowser over the Chrome
// DevTools Protocol. The browser executes the page JS, then we:
//   1. Wait for network idle (or a 5 s ceiling).
//   2. Pull every <a href>, <form action>, and dynamically added route.
//   3. Drain the extension's `window.__wsRoutes` buffer for fetch/XHR/WS
//      endpoints observed at runtime.
//   4. Close the tab.
//
// The browser must already be running with --remote-debugging-port=N for
// this to work. browser.rs starts it that way unconditionally.

use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Default, Serialize)]
pub struct RenderResult {
    pub final_url: String,
    pub title: String,
    pub anchors: Vec<String>,
    pub form_actions: Vec<String>,
    pub spa_routes: Vec<String>,
    pub runtime_endpoints: Vec<RuntimeEndpoint>,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct RuntimeEndpoint {
    pub kind: String,
    pub method: String,
    pub url: String,
}

/// Drive a single URL through CDP. Returns extracted links + runtime endpoints.
///
/// `cdp_port` is the `--remote-debugging-port` the browser is listening on.
/// `url` is the URL to navigate to. `timeout` is the max wall-clock budget.
pub async fn render_via_cdp(cdp_port: u16, url: &str, timeout: Duration) -> RenderResult {
    let started = std::time::Instant::now();
    let mut result = RenderResult::default();
    let r = tokio::time::timeout(timeout, render_inner(cdp_port, url, &mut result)).await;
    result.elapsed_ms = started.elapsed().as_millis() as u64;
    match r {
        Err(_) => {
            result.error = Some(format!("render timed out after {}ms", result.elapsed_ms));
        }
        Ok(Err(e)) => {
            result.error = Some(e);
        }
        Ok(Ok(())) => {}
    }
    result
}

async fn render_inner(cdp_port: u16, url: &str, result: &mut RenderResult) -> Result<(), String> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    // 1. Find the browser's debugger WebSocket
    let client =
        reqwest::Client::builder().timeout(Duration::from_secs(5)).build().map_err(|e| e.to_string())?;
    let version_url = format!("http://127.0.0.1:{}/json/version", cdp_port);
    let v: serde_json::Value = client
        .get(&version_url)
        .send()
        .await
        .map_err(|e| format!("CDP /json/version: {}", e))?
        .json()
        .await
        .map_err(|e| format!("CDP /json/version parse: {}", e))?;
    let ws_url = v["webSocketDebuggerUrl"].as_str().ok_or("no webSocketDebuggerUrl")?.to_string();

    let (mut ws, _) =
        tokio_tungstenite::connect_async(&ws_url).await.map_err(|e| format!("CDP connect_async: {}", e))?;

    let mut next_id: i64 = 1;

    // 2. Create a new target (tab) for our URL
    let create = serde_json::json!({
        "id": next_id, "method": "Target.createTarget",
        "params": { "url": url, "newWindow": false }
    });
    next_id += 1;
    ws.send(Message::Text(create.to_string().into())).await.map_err(|e| format!("createTarget: {}", e))?;

    let mut target_id: Option<String> = None;
    let mut session_id: Option<String> = None;
    let mut last_loaded: bool = false;
    let mut idle_count = 0usize;
    let mut tick = 0;

    while let Some(Ok(msg)) = ws.next().await {
        tick += 1;
        if tick > 600 {
            break; // safety: 600 messages without resolution = bail
        }
        let Message::Text(text) = msg else { continue };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };

        // Pull target id from createTarget result
        if target_id.is_none() {
            if let Some(t) = v["result"]["targetId"].as_str() {
                target_id = Some(t.to_string());
                // Attach
                let attach = serde_json::json!({
                    "id": next_id, "method": "Target.attachToTarget",
                    "params": { "targetId": t, "flatten": true }
                });
                next_id += 1;
                ws.send(Message::Text(attach.to_string().into()))
                    .await
                    .map_err(|e| format!("attachToTarget: {}", e))?;
                continue;
            }
        }

        // Capture session id from attachedToTarget event
        if session_id.is_none() {
            if let Some(sid) = v["params"]["sessionId"].as_str() {
                if v["method"].as_str() == Some("Target.attachedToTarget") {
                    session_id = Some(sid.to_string());
                    // Enable Page + Network domains in this session
                    for method in &["Page.enable", "Network.enable", "Runtime.enable"] {
                        let cmd = serde_json::json!({
                            "id": next_id, "sessionId": sid, "method": method, "params": {}
                        });
                        next_id += 1;
                        ws.send(Message::Text(cmd.to_string().into())).await.ok();
                    }
                    continue;
                }
            }
        }

        // Page lifecycle events
        let method = v["method"].as_str().unwrap_or("");
        match method {
            "Page.loadEventFired" => last_loaded = true,
            "Page.lifecycleEvent" => {
                let name = v["params"]["name"].as_str().unwrap_or("");
                if name == "networkIdle" && last_loaded {
                    // Give the page another 500 ms of JS time, then break.
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    idle_count += 1;
                    if idle_count >= 1 {
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    // 3. Extract anchors, forms, routes, and drain extension routes
    if let Some(sid) = session_id.clone() {
        let script = r#"
            (() => {
                const anchors = Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href).filter(h => !!h);
                const forms = Array.from(document.querySelectorAll('form[action]'))
                    .map(f => new URL(f.getAttribute('action'), document.baseURI).toString());
                const routes = (window.__wsRoutes || []).slice();
                if (window.__wsDrainRoutes) { try { window.__wsDrainRoutes(); } catch (e) {} }
                return JSON.stringify({
                    url: location.href,
                    title: document.title || '',
                    anchors, forms, routes,
                });
            })();
        "#;
        let eval_cmd = serde_json::json!({
            "id": next_id, "sessionId": sid, "method": "Runtime.evaluate",
            "params": { "expression": script, "returnByValue": true, "awaitPromise": false }
        });
        next_id += 1;
        ws.send(Message::Text(eval_cmd.to_string().into()))
            .await
            .map_err(|e| format!("Runtime.evaluate: {}", e))?;

        // Wait for the result
        while let Some(Ok(msg)) = ws.next().await {
            let Message::Text(text) = msg else { continue };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
            if v["result"]["result"]["value"].is_string() {
                let json = v["result"]["result"]["value"].as_str().unwrap_or("");
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json) {
                    result.final_url = parsed["url"].as_str().unwrap_or("").into();
                    result.title = parsed["title"].as_str().unwrap_or("").into();
                    if let Some(a) = parsed["anchors"].as_array() {
                        result.anchors = a.iter().filter_map(|x| x.as_str().map(String::from)).collect();
                    }
                    if let Some(f) = parsed["forms"].as_array() {
                        result.form_actions = f.iter().filter_map(|x| x.as_str().map(String::from)).collect();
                    }
                    if let Some(r) = parsed["routes"].as_array() {
                        for entry in r {
                            let kind = entry["kind"].as_str().unwrap_or("").to_string();
                            let url_v = entry["url"].as_str().unwrap_or("").to_string();
                            let method_v = entry["method"].as_str().unwrap_or("GET").to_string();
                            if !url_v.is_empty() {
                                if kind == "pushstate" || kind == "replacestate" {
                                    result.spa_routes.push(url_v);
                                } else {
                                    result.runtime_endpoints.push(RuntimeEndpoint {
                                        kind,
                                        method: method_v,
                                        url: url_v,
                                    });
                                }
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    // 4. Close the tab
    if let Some(tid) = target_id {
        let close = serde_json::json!({
            "id": next_id, "method": "Target.closeTarget",
            "params": { "targetId": tid }
        });
        ws.send(Message::Text(close.to_string().into())).await.ok();
    }
    let _ = ws.close(None).await;
    Ok(())
}
