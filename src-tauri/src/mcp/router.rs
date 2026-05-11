use axum::extract::Json;
use axum::http::StatusCode;

use super::activity::{log_activity_finish, log_activity_start, summarize_result};
use super::types::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};

/// POST handler — processes JSON-RPC requests for MCP Streamable HTTP
pub async fn handle_rpc(req_body: axum::body::Bytes) -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;

    let req: JsonRpcRequest = match serde_json::from_slice(&req_body) {
        Ok(r) => r,
        Err(e) => {
            let err_resp = JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: None,
                result: None,
                error: Some(JsonRpcError { code: -32700, message: format!("Parse error: {}", e) }),
            };
            return (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], Json(err_resp))
                .into_response();
        }
    };

    if req.id.is_none() {
        println!("[MCP] Notification received: {}", req.method);
        return (StatusCode::ACCEPTED, "").into_response();
    }

    let response = match req.method.as_str() {
        "initialize" => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: req.id,
            result: Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "wondersuite", "version": "1.0.0" }
            })),
            error: None,
        },
        "ping" => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: req.id,
            result: Some(serde_json::json!({})),
            error: None,
        },
        "tools/list" => {
            let tools = super::tool_definitions();
            JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: req.id,
                result: Some(serde_json::json!({ "tools": tools })),
                error: None,
            }
        }
        "tools/call" => {
            let name = req.params["name"].as_str().unwrap_or("");
            let args = &req.params["arguments"];

            let activity_id = log_activity_start(name, args);
            let start_time = std::time::Instant::now();

            match super::handle_tool_call(name, args).await {
                Ok(result) => {
                    let elapsed = start_time.elapsed().as_millis() as u64;
                    let summary = summarize_result(&result);
                    log_activity_finish(activity_id, "success", summary, elapsed);

                    JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id: req.id,
                        result: Some(serde_json::json!({
                            "content": [{ "type": "text", "text": serde_json::to_string_pretty(&result).unwrap_or_default() }]
                        })),
                        error: None,
                    }
                }
                Err(e) => {
                    let elapsed = start_time.elapsed().as_millis() as u64;
                    log_activity_finish(activity_id, "error", e.clone(), elapsed);

                    JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id: req.id,
                        result: Some(serde_json::json!({
                            "content": [{ "type": "text", "text": e }],
                            "isError": true
                        })),
                        error: None,
                    }
                }
            }
        }
        _ => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: req.id,
            result: None,
            error: Some(JsonRpcError { code: -32601, message: format!("Method not found: {}", req.method) }),
        },
    };

    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], Json(response)).into_response()
}

/// GET handler for MCP Streamable HTTP — returns server info
pub async fn handle_mcp_get() -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        Json(serde_json::json!({
            "name": "wondersuite",
            "version": "1.0.0",
            "protocolVersion": "2024-11-05",
        })),
    )
        .into_response()
}
