use crate::mcp::types::HandlerResult;

pub async fn handle_websocket_connect(params: &serde_json::Value) -> HandlerResult {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let action = params["action"].as_str().unwrap_or("list");
    static WS_CONNECTIONS: std::sync::LazyLock<
        tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::mpsc::Sender<String>>>,
    > = std::sync::LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashMap::new()));
    static WS_MESSAGES: std::sync::LazyLock<
        tokio::sync::Mutex<std::collections::HashMap<String, Vec<String>>>,
    > = std::sync::LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashMap::new()));

    match action {
        "connect" => {
            let url = params["url"].as_str().ok_or("Missing url for connect")?;
            let conn_id = format!("ws_{}", chrono::Utc::now().timestamp_millis());
            let (ws_stream, resp) = tokio_tungstenite::connect_async(url)
                .await
                .map_err(|e| format!("WebSocket connect failed: {}", e))?;
            let (mut write, mut read) = ws_stream.split();
            let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(100);
            tokio::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    if msg == "__CLOSE__" {
                        let _ = write.close().await;
                        break;
                    }
                    let _ = write.send(Message::Text(msg.into())).await;
                }
            });
            let cid2 = conn_id.clone();
            tokio::spawn(async move {
                while let Some(Ok(msg)) = read.next().await {
                    let text = match &msg {
                        Message::Text(t) => t.to_string(),
                        Message::Binary(b) => format!("[binary {} bytes]", b.len()),
                        Message::Ping(_) => "[ping]".into(),
                        Message::Pong(_) => "[pong]".into(),
                        Message::Close(_) => {
                            break;
                        }
                        _ => continue,
                    };
                    WS_MESSAGES.lock().await.entry(cid2.clone()).or_insert_with(Vec::new).push(text);
                }
            });
            WS_CONNECTIONS.lock().await.insert(conn_id.clone(), tx);
            WS_MESSAGES.lock().await.insert(conn_id.clone(), Vec::new());
            Ok(
                serde_json::json!({"action": "connected", "connection_id": conn_id, "url": url, "status": resp.status().as_u16()}),
            )
        }
        "send" => {
            let conn_id = params["connection_id"].as_str().ok_or("Missing connection_id")?;
            let message = params["message"].as_str().ok_or("Missing message")?;
            let conns = WS_CONNECTIONS.lock().await;
            let tx = conns.get(conn_id).ok_or("Connection not found")?;
            tx.send(message.to_string()).await.map_err(|e| format!("Send failed: {}", e))?;
            Ok(serde_json::json!({"action": "sent", "connection_id": conn_id, "bytes": message.len()}))
        }
        "receive" => {
            let conn_id = params["connection_id"].as_str().ok_or("Missing connection_id")?;
            let timeout = params["receive_timeout_ms"].as_u64().unwrap_or(5000);
            let max_msgs = params["max_messages"].as_u64().unwrap_or(10) as usize;
            tokio::time::sleep(std::time::Duration::from_millis(timeout.min(5000))).await;
            let mut msgs = WS_MESSAGES.lock().await;
            let messages = msgs.get_mut(conn_id).ok_or("Connection not found")?;
            let drained: Vec<String> = messages.drain(..).take(max_msgs).collect();
            Ok(
                serde_json::json!({"action": "received", "connection_id": conn_id, "count": drained.len(), "messages": drained}),
            )
        }
        "close" => {
            let conn_id = params["connection_id"].as_str().ok_or("Missing connection_id")?;
            let mut conns = WS_CONNECTIONS.lock().await;
            if let Some(tx) = conns.remove(conn_id) {
                let _ = tx.send("__CLOSE__".into()).await;
            }
            WS_MESSAGES.lock().await.remove(conn_id);
            Ok(serde_json::json!({"action": "closed", "connection_id": conn_id}))
        }
        "list" => {
            let conns = WS_CONNECTIONS.lock().await;
            let ids: Vec<&String> = conns.keys().collect();
            Ok(serde_json::json!({"action": "list", "connections": ids, "count": ids.len()}))
        }
        _ => Err(format!("Unknown websocket_connect action: {}", action)),
    }
}
