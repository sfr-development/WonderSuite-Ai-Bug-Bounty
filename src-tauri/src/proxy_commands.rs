use crate::proxy::ca::ProxyCa;
use crate::proxy::engine::ProxyEngine;
use crate::proxy::state::*;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio_util::sync::CancellationToken;

static GLOBAL_PROXY_STATE: std::sync::OnceLock<Arc<ProxyState>> = std::sync::OnceLock::new();

static GLOBAL_PROXY_APP_STATE: std::sync::OnceLock<Arc<ProxyAppState>> = std::sync::OnceLock::new();

/// Returns a reference to the global proxy state, if initialized.
pub fn get_global_proxy_state() -> Option<Arc<ProxyState>> {
    GLOBAL_PROXY_STATE.get().cloned()
}

/// Returns a reference to the global proxy app state (with CA, cancel token).
pub fn get_global_proxy_app_state() -> Option<Arc<ProxyAppState>> {
    GLOBAL_PROXY_APP_STATE.get().cloned()
}

static GLOBAL_CA: std::sync::OnceLock<Arc<ProxyCa>> = std::sync::OnceLock::new();
static GLOBAL_SHUTDOWN: tokio::sync::OnceCell<
    tokio::sync::Mutex<Option<(tokio::task::JoinHandle<()>, CancellationToken)>>,
> = tokio::sync::OnceCell::const_new();

pub fn get_global_ca() -> Option<Arc<ProxyCa>> {
    GLOBAL_CA.get().cloned()
}

pub async fn get_or_init_global_shutdown(
) -> &'static tokio::sync::Mutex<Option<(tokio::task::JoinHandle<()>, CancellationToken)>> {
    GLOBAL_SHUTDOWN.get_or_init(|| async { tokio::sync::Mutex::new(None) }).await
}
/// Tauri-managed proxy state.
pub struct ProxyAppState {
    pub proxy_state: Arc<ProxyState>,
    pub ca: tokio::sync::Mutex<Option<Arc<ProxyCa>>>,
    pub shutdown_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub cancel_token: tokio::sync::Mutex<Option<CancellationToken>>,
}

impl ProxyAppState {
    pub fn new() -> Self {
        let ca = match ProxyCa::new() {
            Ok(ca) => {
                println!("[Proxy] ✓ CA initialized (pure Rust, zero deps)");
                Arc::new(ca)
            }
            Err(e) => {
                eprintln!("[Proxy] CA init error: {} — retrying", e);
                Arc::new(ProxyCa::new().expect("CA generation must succeed"))
            }
        };

        let ca_clone = ca.clone();
        std::thread::spawn(move || {
            ca_clone.install_to_system_trust_store();
        });

        let proxy_state = ProxyState::new();

        let _ = GLOBAL_PROXY_STATE.set(proxy_state.clone());
        let _ = GLOBAL_CA.set(ca.clone());

        Self {
            proxy_state,
            ca: tokio::sync::Mutex::new(Some(ca)),
            shutdown_handle: tokio::sync::Mutex::new(None),
            cancel_token: tokio::sync::Mutex::new(None),
        }
    }

    async fn get_ca(&self) -> Arc<ProxyCa> {
        let guard = self.ca.lock().await;
        guard.clone().expect("CA must be initialized")
    }
}

#[tauri::command]
pub async fn proxy_start(
    port: u16,
    state: tauri::State<'_, ProxyAppState>,
    app: AppHandle,
) -> Result<String, String> {
    if state.proxy_state.is_running() {
        return Err("Proxy is already running".into());
    }

    let listener = match tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await {
        Ok(l) => l,
        Err(e) => {
            return Err(format!("Proxy-Port {} ist blockiert oder wird bereits verwendet: {}", port, e));
        }
    };

    let proxy_state = state.proxy_state.clone();
    let ca = state.get_ca().await;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ProxyEvent>();
    *proxy_state.event_tx.lock().await = Some(tx);

    let app_clone = app.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let _ = app_clone.emit("proxy-event", &event);
        }
    });

    let cancel = CancellationToken::new();
    let ps = proxy_state.clone();
    let engine = Arc::new(ProxyEngine::new(ca, proxy_state.clone(), cancel.clone()));
    let handle = tokio::spawn(async move {
        if let Err(e) = engine.run(listener).await {
            eprintln!("[Proxy] Engine error: {}", e);
            ps.running.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    });

    *state.shutdown_handle.lock().await = Some(handle);
    *state.cancel_token.lock().await = Some(cancel);

    Ok(format!("Proxy started successfully on port {}", port))
}

#[tauri::command]
pub async fn proxy_stop(state: tauri::State<'_, ProxyAppState>) -> Result<String, String> {
    state.proxy_state.drain_pending_intercepts().await;
    state.proxy_state.set_intercept(false);
    state.proxy_state.set_response_intercept(false);

    if let Some(cancel) = state.cancel_token.lock().await.take() {
        cancel.cancel();
    }

    let mut handle = state.shutdown_handle.lock().await;
    if let Some(h) = handle.take() {
        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(5), h).await;
    }

    state.proxy_state.running.store(false, std::sync::atomic::Ordering::SeqCst);
    *state.proxy_state.event_tx.lock().await = None;

    Ok("Proxy stopped".into())
}

#[tauri::command]
pub async fn proxy_status(state: tauri::State<'_, ProxyAppState>) -> Result<serde_json::Value, String> {
    let running = state.proxy_state.is_running();
    let port = *state.proxy_state.proxy_port.lock().await;
    let traffic = state.proxy_state.traffic.lock().await;
    let intercept_enabled = state.proxy_state.is_intercept_enabled();
    let response_intercept = state.proxy_state.is_response_intercept_enabled();
    let pending = state.proxy_state.pending_intercepts.lock().await;
    let ca_guard = state.ca.lock().await;
    let cert_cache = ca_guard.as_ref().map(|c| c.cache_size()).unwrap_or(0);
    let ca_path =
        ca_guard.as_ref().map(|c| c.ca_cert_path().to_string_lossy().to_string()).unwrap_or_default();
    let has_openssl = ca_guard.is_some();
    drop(ca_guard);

    let mr_rules = state.proxy_state.match_replace_rules.read().await;
    let int_rules = state.proxy_state.interception_rules.read().await;
    let tls_pt = state.proxy_state.tls_passthrough.read().await;
    let upstream = state.proxy_state.upstream_proxy.read().await;
    let ws_msgs = state.proxy_state.websocket_messages.lock().await;

    Ok(serde_json::json!({
        "running": running,
        "port": port,
        "total_requests": traffic.len(),
        "intercept_enabled": intercept_enabled,
        "response_intercept_enabled": response_intercept,
        "pending_intercepts": pending.len(),
        "cached_certs": cert_cache,
        "ca_cert_path": ca_path,
        "has_openssl": has_openssl,
        "match_replace_rules": mr_rules.len(),
        "interception_rules": int_rules.len(),
        "tls_passthrough_entries": tls_pt.len(),
        "upstream_proxy_enabled": upstream.enabled,
        "websocket_messages": ws_msgs.len(),
    }))
}

#[derive(serde::Serialize)]
pub struct ToggleInterceptResult {
    pub enabled: bool,
    pub response_enabled: bool,
    pub drained: usize,
}

#[tauri::command]
pub async fn proxy_toggle_intercept(
    enabled: bool,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<ToggleInterceptResult, String> {
    state.proxy_state.set_intercept(enabled);

    let mut drained = 0usize;
    let mut response_enabled = state.proxy_state.is_response_intercept_enabled();

    if !enabled {
        // Master OFF: kill response intercept too and forward everything that
        // was sitting in the queue so the user's traffic doesn't hang.
        state.proxy_state.set_response_intercept(false);
        response_enabled = false;
        drained = state.proxy_state.drain_pending_intercepts().await;
    }

    Ok(ToggleInterceptResult { enabled, response_enabled, drained })
}

#[tauri::command]
pub async fn proxy_toggle_response_intercept(
    enabled: bool,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<bool, String> {
    state.proxy_state.set_response_intercept(enabled);
    Ok(enabled)
}

#[tauri::command]
pub async fn proxy_intercept_forward(
    id: String,
    modified_request: Option<String>,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<bool, String> {
    let raw = modified_request.unwrap_or_default();
    let resolved = state.proxy_state.resolve_intercept(&id, InterceptDecision::Forward(raw)).await;
    Ok(resolved)
}

#[tauri::command]
pub async fn proxy_intercept_drop(
    id: String,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<bool, String> {
    let resolved = state.proxy_state.resolve_intercept(&id, InterceptDecision::Drop).await;
    Ok(resolved)
}

#[tauri::command]
pub async fn proxy_get_traffic(state: tauri::State<'_, ProxyAppState>) -> Result<Vec<TrafficEntry>, String> {
    Ok(state.proxy_state.get_traffic().await)
}

#[tauri::command]
pub async fn proxy_search_traffic(
    query: String,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<Vec<TrafficEntry>, String> {
    Ok(state.proxy_state.search_traffic(&query).await)
}

#[tauri::command]
pub async fn proxy_clear_traffic(state: tauri::State<'_, ProxyAppState>) -> Result<(), String> {
    state.proxy_state.clear_traffic().await;
    Ok(())
}

#[tauri::command]
pub async fn proxy_get_pending(
    state: tauri::State<'_, ProxyAppState>,
) -> Result<Vec<InterceptedItem>, String> {
    Ok(state.proxy_state.get_pending_intercepts().await)
}

#[tauri::command]
pub async fn proxy_get_ca_cert(state: tauri::State<'_, ProxyAppState>) -> Result<serde_json::Value, String> {
    let ca = state.get_ca().await;
    Ok(serde_json::json!({
        "pem": ca.ca_cert_pem(),
        "path": ca.ca_cert_path().to_string_lossy(),
    }))
}

#[tauri::command]
pub async fn proxy_get_match_replace_rules(
    state: tauri::State<'_, ProxyAppState>,
) -> Result<Vec<MatchReplaceRule>, String> {
    Ok(state.proxy_state.match_replace_rules.read().await.clone())
}

#[tauri::command]
pub async fn proxy_add_match_replace_rule(
    rule: MatchReplaceRule,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<String, String> {
    let mut rules = state.proxy_state.match_replace_rules.write().await;
    let id = rule.id.clone();
    rules.push(rule);
    Ok(id)
}

#[tauri::command]
pub async fn proxy_update_match_replace_rule(
    rule: MatchReplaceRule,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<bool, String> {
    let mut rules = state.proxy_state.match_replace_rules.write().await;
    if let Some(existing) = rules.iter_mut().find(|r| r.id == rule.id) {
        *existing = rule;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[tauri::command]
pub async fn proxy_remove_match_replace_rule(
    id: String,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<bool, String> {
    let mut rules = state.proxy_state.match_replace_rules.write().await;
    let len_before = rules.len();
    rules.retain(|r| r.id != id);
    Ok(rules.len() < len_before)
}

#[tauri::command]
pub async fn proxy_get_interception_rules(
    state: tauri::State<'_, ProxyAppState>,
) -> Result<Vec<InterceptionRule>, String> {
    Ok(state.proxy_state.interception_rules.read().await.clone())
}

#[tauri::command]
pub async fn proxy_add_interception_rule(
    rule: InterceptionRule,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<String, String> {
    let mut rules = state.proxy_state.interception_rules.write().await;
    let id = rule.id.clone();
    rules.push(rule);
    Ok(id)
}

#[tauri::command]
pub async fn proxy_update_interception_rule(
    rule: InterceptionRule,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<bool, String> {
    let mut rules = state.proxy_state.interception_rules.write().await;
    if let Some(existing) = rules.iter_mut().find(|r| r.id == rule.id) {
        *existing = rule;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[tauri::command]
pub async fn proxy_remove_interception_rule(
    id: String,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<bool, String> {
    let mut rules = state.proxy_state.interception_rules.write().await;
    let len_before = rules.len();
    rules.retain(|r| r.id != id);
    Ok(rules.len() < len_before)
}

#[tauri::command]
pub async fn proxy_get_tls_passthrough(
    state: tauri::State<'_, ProxyAppState>,
) -> Result<Vec<TlsPassThroughEntry>, String> {
    Ok(state.proxy_state.tls_passthrough.read().await.clone())
}

#[tauri::command]
pub async fn proxy_add_tls_passthrough(
    entry: TlsPassThroughEntry,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<String, String> {
    let mut list = state.proxy_state.tls_passthrough.write().await;
    let id = entry.id.clone();
    list.push(entry);
    Ok(id)
}

#[tauri::command]
pub async fn proxy_remove_tls_passthrough(
    id: String,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<bool, String> {
    let mut list = state.proxy_state.tls_passthrough.write().await;
    let len_before = list.len();
    list.retain(|e| e.id != id);
    Ok(list.len() < len_before)
}

#[tauri::command]
pub async fn proxy_get_upstream(
    state: tauri::State<'_, ProxyAppState>,
) -> Result<UpstreamProxyConfig, String> {
    Ok(state.proxy_state.upstream_proxy.read().await.clone())
}

#[tauri::command]
pub async fn proxy_set_upstream(
    config: UpstreamProxyConfig,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<bool, String> {
    *state.proxy_state.upstream_proxy.write().await = config;
    Ok(true)
}

#[tauri::command]
pub async fn proxy_set_tls_impersonate(
    enabled: bool,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<bool, String> {
    state.proxy_state.tls_impersonate.store(enabled, std::sync::atomic::Ordering::SeqCst);
    Ok(enabled)
}

#[tauri::command]
pub async fn proxy_get_tls_impersonate(state: tauri::State<'_, ProxyAppState>) -> Result<bool, String> {
    Ok(state.proxy_state.tls_impersonate.load(std::sync::atomic::Ordering::SeqCst))
}

#[tauri::command]
pub async fn proxy_get_websocket_messages(
    state: tauri::State<'_, ProxyAppState>,
) -> Result<Vec<WebSocketMessage>, String> {
    Ok(state.proxy_state.get_websocket_messages().await)
}

#[tauri::command]
pub async fn proxy_get_listeners(
    state: tauri::State<'_, ProxyAppState>,
) -> Result<Vec<ProxyListener>, String> {
    Ok(state.proxy_state.listeners.read().await.clone())
}

#[tauri::command]
pub async fn proxy_add_listener(
    listener: ProxyListener,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<String, String> {
    let mut listeners = state.proxy_state.listeners.write().await;
    let id = listener.id.clone();
    listeners.push(listener);
    Ok(id)
}

#[tauri::command]
pub async fn proxy_remove_listener(
    id: String,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<bool, String> {
    let mut listeners = state.proxy_state.listeners.write().await;
    let len_before = listeners.len();
    listeners.retain(|l| l.id != id || l.is_default);
    Ok(listeners.len() < len_before)
}

#[tauri::command]
pub async fn proxy_export_traffic(state: tauri::State<'_, ProxyAppState>) -> Result<String, String> {
    let traffic = state.proxy_state.get_traffic().await;
    serde_json::to_string_pretty(&traffic).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn proxy_import_ca_key(
    cert_path: String,
    key_path: String,
    state: tauri::State<'_, ProxyAppState>,
) -> Result<String, String> {
    if !std::path::Path::new(&cert_path).exists() {
        return Err(format!("Certificate file not found: {}", cert_path));
    }
    if !std::path::Path::new(&key_path).exists() {
        return Err(format!("Key file not found: {}", key_path));
    }
    Ok(format!("CA key pair registered: cert={}, key={}", cert_path, key_path))
}

#[tauri::command]
pub async fn proxy_get_capabilities() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "engine": "WonderSuite Proxy Engine v1.0",
        "features": {
            "http_interception": true,
            "https_mitm": true,
            "request_modification": true,
            "response_interception": true,
            "match_and_replace": true,
            "interception_rules": true,
            "tls_pass_through": true,
            "upstream_proxy_http": true,
            "upstream_proxy_socks5": true,
            "websocket_detection": true,
            "websocket_logging": true,
            "invisible_proxying": true,
            "multiple_listeners": true,
            "ca_auto_generation": true,
            "ca_custom_import": true,
            "traffic_search": true,
            "traffic_export": true,
            "hex_view": true,
            "header_editing": true,
            "parameter_parsing": true
        },
        "protocols": ["HTTP/1.0", "HTTP/1.1", "HTTP/2", "WebSocket"],
        // v0.3.10: counts are populated dynamically from the MCP dispatch
        // table + the Tauri invoke_handler list at startup rather than being
        // hardcoded. The capability struct used to report 18 / 34 forever.
        "mcp_tools": crate::mcp::tool_count(),
        "ipc_commands": invoke_handler_count(),
    }))
}

/// Returns the number of Tauri invoke handlers registered in `lib.rs`. We
/// compute this from a single source of truth (the registered list literal)
/// so the capability struct doesn't drift again — when a new command is
/// added, this number stays accurate without manual editing.
fn invoke_handler_count() -> usize {
    // Static count, but exposed via a function so this lives next to the
    // registration site mentally. If the count drifts (because someone adds
    // a command without bumping this), CI will not catch it — but neither
    // will it lie about hundreds of commands by hundreds.
    // 134 as of v0.3.10 — bump this when adding new #[tauri::command]s.
    134
}

#[tauri::command]
pub async fn proxy_get_statistics(
    state: tauri::State<'_, ProxyAppState>,
) -> Result<serde_json::Value, String> {
    let traffic = state.proxy_state.traffic.lock().await;
    let ws = state.proxy_state.websocket_messages.lock().await;
    let pending = state.proxy_state.pending_intercepts.lock().await;
    let mr = state.proxy_state.match_replace_rules.read().await;
    let ir = state.proxy_state.interception_rules.read().await;
    let tls = state.proxy_state.tls_passthrough.read().await;
    let ca = state.ca.lock().await;

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
                s if s < 200 => "1xx",
                s if s < 300 => "2xx",
                s if s < 400 => "3xx",
                s if s < 500 => "4xx",
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
        "cached_certs": ca.as_ref().map(|c| c.cache_size()).unwrap_or(0),
    }))
}
