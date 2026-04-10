use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// ── WebSocket State ─────────────────────────────────────────────────────────

pub type WsState = Arc<Mutex<WsManager>>;

pub fn create_ws_state() -> WsState {
    Arc::new(Mutex::new(WsManager::new()))
}

pub struct WsManager {
    pub connections: HashMap<String, WsConnection>,
    pub match_replace_rules: Vec<WsMatchReplace>,
    next_msg_id: u64,
}

impl WsManager {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            match_replace_rules: Vec::new(),
            next_msg_id: 1,
        }
    }
    pub fn next_id(&mut self) -> u64 {
        let id = self.next_msg_id;
        self.next_msg_id += 1;
        id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsConnection {
    pub id: String,
    pub url: String,
    pub status: String,  // "connecting", "open", "closed", "error"
    pub messages: Vec<WsMessage>,
    pub connected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    pub id: u64,
    pub direction: String,  // "sent" or "received"
    pub data: String,
    pub msg_type: String,  // "text", "binary", "ping", "pong", "close"
    pub size: usize,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMatchReplace {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub direction: String,  // "sent", "received", "both"
    pub match_pattern: String,
    pub replace_value: String,
    pub is_regex: bool,
}

// ── Tauri Commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub async fn ws_connect(
    state: tauri::State<'_, WsState>,
    url: String,
    headers: Option<HashMap<String, String>>,
) -> Result<String, String> {
    let conn_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let cid = conn_id.clone();

    // Create connection entry
    {
        let mut mgr = state.lock().await;
        mgr.connections.insert(cid.clone(), WsConnection {
            id: cid.clone(),
            url: url.clone(),
            status: "connecting".into(),
            messages: Vec::new(),
            connected_at: chrono_now(),
        });
    }

    let state_clone = state.inner().clone();

    // Spawn WebSocket connection
    tokio::spawn(async move {
        use tokio_tungstenite::connect_async;

        let ws_url = if url.starts_with("ws://") || url.starts_with("wss://") {
            url.clone()
        } else {
            format!("wss://{}", url)
        };

        match connect_async(&ws_url).await {
            Ok((ws_stream, _response)) => {
                use futures_util::{SinkExt, StreamExt};
                let (mut write, mut read) = ws_stream.split();

                // Mark as open
                {
                    let mut mgr = state_clone.lock().await;
                    if let Some(conn) = mgr.connections.get_mut(&cid) {
                        conn.status = "open".into();
                    }
                }

                // Read messages
                while let Some(msg) = read.next().await {
                    match msg {
                        Ok(msg) => {
                            let (data, msg_type) = match &msg {
                                tokio_tungstenite::tungstenite::Message::Text(t) => (t.to_string(), "text"),
                                tokio_tungstenite::tungstenite::Message::Binary(b) => {
                                    (format!("[binary: {} bytes]", b.len()), "binary")
                                }
                                tokio_tungstenite::tungstenite::Message::Ping(_) => ("ping".into(), "ping"),
                                tokio_tungstenite::tungstenite::Message::Pong(_) => ("pong".into(), "pong"),
                                tokio_tungstenite::tungstenite::Message::Close(_) => ("close".into(), "close"),
                                _ => continue,
                            };
                            let size = data.len();
                            let mut mgr = state_clone.lock().await;
                            let mid = mgr.next_id();
                            if let Some(conn) = mgr.connections.get_mut(&cid) {
                                conn.messages.push(WsMessage {
                                    id: mid,
                                    direction: "received".into(),
                                    data,
                                    msg_type: msg_type.into(),
                                    size,
                                    timestamp: chrono_now(),
                                });
                                // Keep only last 1000 messages
                                if conn.messages.len() > 1000 {
                                    conn.messages.drain(0..100);
                                }
                            }
                            if msg_type == "close" { break; }
                        }
                        Err(_) => break,
                    }
                }

                // Mark as closed
                let mut mgr = state_clone.lock().await;
                if let Some(conn) = mgr.connections.get_mut(&cid) {
                    conn.status = "closed".into();
                }
            }
            Err(e) => {
                let mut mgr = state_clone.lock().await;
                if let Some(conn) = mgr.connections.get_mut(&cid) {
                    conn.status = format!("error: {}", e);
                }
            }
        }
    });

    Ok(conn_id)
}

#[tauri::command]
pub async fn ws_send_frame(
    state: tauri::State<'_, WsState>,
    connection_id: String,
    message: String,
    msg_type: Option<String>,
) -> Result<String, String> {
    let mut mgr = state.lock().await;
    let mid = mgr.next_id();

    // Apply match & replace rules
    let mut final_msg = message.clone();
    for rule in &mgr.match_replace_rules {
        if !rule.enabled { continue; }
        if rule.direction != "sent" && rule.direction != "both" { continue; }
        if rule.is_regex {
            if let Ok(re) = regex::Regex::new(&rule.match_pattern) {
                final_msg = re.replace_all(&final_msg, rule.replace_value.as_str()).to_string();
            }
        } else {
            final_msg = final_msg.replace(&rule.match_pattern, &rule.replace_value);
        }
    }

    let size = final_msg.len();
    if let Some(conn) = mgr.connections.get_mut(&connection_id) {
        conn.messages.push(WsMessage {
            id: mid,
            direction: "sent".into(),
            data: final_msg,
            msg_type: msg_type.unwrap_or_else(|| "text".into()),
            size,
            timestamp: chrono_now(),
        });
        Ok("Frame queued".into())
    } else {
        Err("Connection not found".into())
    }
}

#[tauri::command]
pub async fn ws_get_messages(
    state: tauri::State<'_, WsState>,
    connection_id: String,
    since_id: Option<u64>,
) -> Result<Vec<WsMessage>, String> {
    let mgr = state.lock().await;
    let conn = mgr.connections.get(&connection_id).ok_or("Connection not found")?;
    let from = since_id.unwrap_or(0);
    Ok(conn.messages.iter().filter(|m| m.id > from).cloned().collect())
}

#[tauri::command]
pub async fn ws_list_connections(
    state: tauri::State<'_, WsState>,
) -> Result<Vec<serde_json::Value>, String> {
    let mgr = state.lock().await;
    Ok(mgr.connections.values().map(|c| serde_json::json!({
        "id": c.id,
        "url": c.url,
        "status": c.status,
        "message_count": c.messages.len(),
        "connected_at": c.connected_at,
    })).collect())
}

#[tauri::command]
pub async fn ws_close_connection(
    state: tauri::State<'_, WsState>,
    connection_id: String,
) -> Result<String, String> {
    let mut mgr = state.lock().await;
    if let Some(conn) = mgr.connections.get_mut(&connection_id) {
        conn.status = "closed".into();
        Ok("Connection closed".into())
    } else {
        Err("Connection not found".into())
    }
}

#[tauri::command]
pub async fn ws_add_match_replace(
    state: tauri::State<'_, WsState>,
    name: String,
    direction: String,
    match_pattern: String,
    replace_value: String,
    is_regex: Option<bool>,
) -> Result<String, String> {
    let id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let mut mgr = state.lock().await;
    mgr.match_replace_rules.push(WsMatchReplace {
        id: id.clone(),
        name,
        enabled: true,
        direction,
        match_pattern,
        replace_value,
        is_regex: is_regex.unwrap_or(false),
    });
    Ok(id)
}

#[tauri::command]
pub async fn ws_get_match_replace(
    state: tauri::State<'_, WsState>,
) -> Result<Vec<WsMatchReplace>, String> {
    let mgr = state.lock().await;
    Ok(mgr.match_replace_rules.clone())
}

#[tauri::command]
pub async fn ws_remove_match_replace(
    state: tauri::State<'_, WsState>,
    rule_id: String,
) -> Result<String, String> {
    let mut mgr = state.lock().await;
    mgr.match_replace_rules.retain(|r| r.id != rule_id);
    Ok("Rule removed".into())
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", now.as_secs())
}
