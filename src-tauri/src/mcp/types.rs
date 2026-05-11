use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub id: u64,
    pub timestamp: String,
    pub tool_name: String,
    pub category: String,
    pub params_summary: String,
    pub status: String, // "running", "success", "error"
    pub result_summary: String,
    pub duration_ms: u64,
    pub target_url: String, // extracted URL if present
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTrafficEntry {
    pub id: u64,
    pub timestamp: String,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub tls: bool,
    pub status: u16,
    pub response_length: usize,
    pub response_time_ms: u64,
    pub mime_type: String,
    pub request_headers: String,
    pub request_body: String,
    pub response_headers: String,
    pub response_body: String,
    pub source: String,
    pub notes: String,
    pub color: String,
}

#[derive(Debug, Clone, Default)]
pub struct WebSocketState {
    pub match_replace_rules: Vec<WsMatchReplace>,
}

#[derive(Debug, Clone)]
pub struct WsMatchReplace {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub direction: String, // "client_to_server", "server_to_client", "both"
    pub match_pattern: String,
    pub replace_value: String,
    pub is_regex: bool,
    pub match_type: String, // "text", "binary", "json"
}

#[derive(Debug, Clone)]
pub struct BambdaCondition {
    pub field: String,
    pub operator: String,
    pub value: String,
}

pub type HandlerResult = Result<serde_json::Value, String>;
