pub mod activity;
pub mod client;
pub mod router;
pub mod state;
pub mod types;
pub mod utils;

pub use activity::{
    get_activity_log, get_activity_stats, get_mcp_traffic, log_activity_finish, log_activity_start,
    log_mcp_traffic, next_mcp_traffic_id,
};
pub use types::{ActivityEntry, McpTrafficEntry, ToolDef};

use axum::routing::post;
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod handlers;

pub async fn handle_tool_call(name: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
    handlers::dispatch(name, params).await
}

pub fn tool_definitions() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "send_request".into(),
            description: "Send any HTTP request. The primary tool for all HTTP interaction — use this for testing, fuzzing, exploit chains, and general web requests.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "method": { "type": "string", "description": "HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)", "default": "GET" },
                    "url": { "type": "string", "description": "Full target URL" },
                    "headers": { "type": "object", "description": "Key-value map of request headers", "additionalProperties": { "type": "string" } },
                    "body": { "type": "string", "description": "Request body content" }
                },
                "required": ["url"]
            }),
        },
        ToolDef {
            name: "encode".into(),
            description: "Encode data in base64, URL, or hex format.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "data": { "type": "string", "description": "Data to encode" },
                    "format": { "type": "string", "enum": ["base64", "url", "hex"], "description": "Encoding format" }
                },
                "required": ["data", "format"]
            }),
        },
        ToolDef {
            name: "decode".into(),
            description: "Decode data from base64, URL, or hex format.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "data": { "type": "string", "description": "Encoded data to decode" },
                    "format": { "type": "string", "enum": ["base64", "url", "hex"], "description": "Encoding format" }
                },
                "required": ["data", "format"]
            }),
        },
        ToolDef {
            name: "hash".into(),
            description: "Compute hash of data using MD5, SHA-1, SHA-256, or SHA-512.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "data": { "type": "string", "description": "Data to hash" },
                    "algorithm": { "type": "string", "description": "Hash algorithm (md5, sha1, sha256, sha512)" }
                },
                "required": ["data", "algorithm"]
            }),
        },
        ToolDef {
            name: "analyze_jwt".into(),
            description: "Decode and analyze a JWT token — extracts header, payload, and signature.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "token": { "type": "string", "description": "JWT token string" }
                },
                "required": ["token"]
            }),
        },
        ToolDef {
            name: "smart_decode".into(),
            description: "Auto-detect and recursively decode multi-layered encoding (base64→URL→hex→JWT). Useful for analyzing obfuscated tokens and values.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "data": { "type": "string", "description": "Data to analyze and decode" },
                    "max_depth": { "type": "integer", "description": "Max decode iterations", "default": 5 }
                },
                "required": ["data"]
            }),
        },
        ToolDef {
            name: "proxy_start".into(),
            description: "Start the proxy listener on a given port.".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": { "port": { "type": "integer", "default": 8080 } } }),
        },
        ToolDef {
            name: "proxy_stop".into(),
            description: "Stop the proxy listener.".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "proxy_status".into(),
            description: "Get current proxy status including running state and capabilities.".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "proxy_toggle_intercept".into(),
            description: "Enable or disable request interception.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" },
                    "response_intercept": { "type": "boolean", "description": "Also toggle response interception" }
                },
                "required": ["enabled"]
            }),
        },
        ToolDef {
            name: "proxy_get_traffic".into(),
            description: "Retrieve captured proxy traffic entries.".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": { "limit": { "type": "integer", "default": 50 } } }),
        },
        ToolDef {
            name: "proxy_search_traffic".into(),
            description: "Search through captured traffic by URL, host, headers, or response body.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "query": { "type": "string", "description": "Search query" } },
                "required": ["query"]
            }),
        },
        ToolDef {
            name: "proxy_add_match_replace".into(),
            description: "Add a match-and-replace rule for proxied traffic. Supports regex and directional filtering.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" }, "target": { "type": "string", "description": "header, body, url" },
                    "match_pattern": { "type": "string" }, "replace_value": { "type": "string" },
                    "is_regex": { "type": "boolean", "default": false },
                    "direction": { "type": "string", "enum": ["request", "response", "both"], "default": "both" }
                },
                "required": ["name", "target", "match_pattern", "replace_value"]
            }),
        },
        ToolDef {
            name: "proxy_get_match_replace".into(),
            description: "List all match-and-replace rules.".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "proxy_add_tls_passthrough".into(),
            description: "Add a host to TLS passthrough list — traffic to this host will not be intercepted/decrypted.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "host": { "type": "string" }, "port": { "type": "integer" } },
                "required": ["host"]
            }),
        },
        ToolDef {
            name: "proxy_set_upstream".into(),
            description: "Configure an upstream (chained) proxy for all outgoing proxy traffic.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" }, "proxy_type": { "type": "string", "enum": ["http", "socks5"] },
                    "host": { "type": "string" }, "port": { "type": "integer" },
                    "username": { "type": "string" }, "password": { "type": "string" }
                },
                "required": ["host", "port"]
            }),
        },
        ToolDef {
            name: "proxy_get_websocket_messages".into(),
            description: "Retrieve captured WebSocket messages from proxy traffic.".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "proxy_add_interception_rule".into(),
            description: "Add a selective interception rule (intercept only matching traffic).".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "rule_type": { "type": "string", "enum": ["url_contains", "url_regex", "host_equals", "method_equals", "file_extension"] },
                    "pattern": { "type": "string" },
                    "action": { "type": "string", "enum": ["intercept", "drop", "forward"], "default": "intercept" },
                    "target": { "type": "string", "enum": ["request", "response", "both"], "default": "both" }
                },
                "required": ["name", "rule_type", "pattern"]
            }),
        },
        ToolDef {
            name: "proxy_get_capabilities".into(),
            description: "List all proxy capabilities and supported features.".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "proxy_get_statistics".into(),
            description: "Get proxy runtime statistics (requests, bytes, connections, uptime).".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "proxy_clear_traffic".into(),
            description: "Clear all captured proxy traffic.".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        ToolDef {
            name: "proxy_export_traffic".into(),
            description: "Export proxy traffic in JSON or HAR format.".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": { "format": { "type": "string", "enum": ["json", "har"], "default": "json" } } }),
        },
        ToolDef {
            name: "browser_navigate".into(),
            description: "Launch or navigate the Chromium browser via CDP. Actions: 'open' (launch+navigate), 'navigate' (CDP navigate), 'get_page' (fetch+parse HTML).".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["open", "navigate", "get_page"] },
                    "url": { "type": "string" },
                    "wait_ms": { "type": "integer", "default": 2000 }
                },
                "required": ["action", "url"]
            }),
        },
        ToolDef {
            name: "browser_execute_js".into(),
            description: "Execute JavaScript in the browser via CDP Runtime.evaluate. Supports async/await. Use for DOM manipulation, data extraction, XSS testing.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "code": { "type": "string", "description": "JavaScript code to execute" },
                    "await_promise": { "type": "boolean", "default": true },
                    "timeout_ms": { "type": "integer", "default": 10000 },
                    "tab_id": { "type": "integer", "description": "Target tab index (default: first page tab)" }
                },
                "required": ["code"]
            }),
        },
        ToolDef {
            name: "session_from_browser".into(),
            description: "Extract cookies, localStorage, and sessionStorage from the running browser via CDP. Returns a ready-to-use Cookie header.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Filter cookies by domain" },
                    "include_local_storage": { "type": "boolean", "default": true },
                    "include_session_storage": { "type": "boolean", "default": true },
                    "auto_apply": { "type": "boolean", "default": true }
                }
            }),
        },
        ToolDef {
            name: "browser_network_traffic".into(),
            description: "Read captured network traffic from the WonderBrowser via CDP. Automatically captures all HTTP requests/responses when the browser is running. Use this to see login flows, API calls, tokens, and more. Actions: get (list traffic with filters), clear, status, start_capture.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["get", "filter", "clear", "status", "start_capture"], "default": "get", "description": "Action: get/filter (read traffic), clear (reset log), status (check capture state), start_capture (manual start)" },
                    "limit": { "type": "integer", "default": 100, "description": "Max entries to return" },
                    "url_contains": { "type": "string", "description": "Filter by URL substring (e.g. 'api/identity')" },
                    "method": { "type": "string", "description": "Filter by HTTP method (GET, POST, etc.)" },
                    "status": { "type": "integer", "description": "Filter by HTTP status code" },
                    "resource_type": { "type": "string", "description": "Filter by type: XHR, Fetch, Document, Script, etc." },
                    "exclude_static": { "type": "boolean", "default": true, "description": "Exclude Image/Font/Media resources" }
                }
            }),
        },
        ToolDef {
            name: "session_manage".into(),
            description: "Manage session state: cookies, macros. Actions: get_cookies, set_cookie, clear_cookies, remove_cookie, create_macro, run_macro, list_macros.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["get_cookies", "set_cookie", "clear_cookies", "remove_cookie", "create_macro", "run_macro", "list_macros"] },
                    "domain": { "type": "string" }, "cookie_name": { "type": "string" }, "cookie_value": { "type": "string" },
                    "cookie_path": { "type": "string", "default": "/" },
                    "macro_name": { "type": "string" }, "macro_id": { "type": "string" },
                    "macro_steps": { "type": "array", "items": { "type": "object" } }
                },
                "required": ["action"]
            }),
        },
        ToolDef {
            name: "websocket_connect".into(),
            description: "Raw WebSocket operations: connect, send, receive, close, list. Use for WS-based testing, socket hijacking, real-time protocol analysis.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["connect", "send", "receive", "close", "list"] },
                    "url": { "type": "string", "description": "WebSocket URL (for connect)" },
                    "connection_id": { "type": "string", "description": "Connection ID (for send/receive/close)" },
                    "message": { "type": "string", "description": "Message to send" },
                    "receive_timeout_ms": { "type": "integer", "default": 5000 },
                    "max_messages": { "type": "integer", "default": 10 }
                },
                "required": ["action"]
            }),
        },
        ToolDef {
            name: "crawl_target".into(),
            description: "Crawl a web target — discovers pages, forms, scripts, comments, emails, and API endpoints via BFS traversal.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string" }, "max_depth": { "type": "integer", "default": 5 },
                    "max_pages": { "type": "integer", "default": 200 },
                    "extract_forms": { "type": "boolean", "default": true },
                    "extract_comments": { "type": "boolean", "default": true },
                    "extract_emails": { "type": "boolean", "default": true },
                    "timeout_ms": { "type": "integer", "default": 10000 }
                },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "discover_subdomains".into(),
            description: "Discover subdomains via DNS bruteforce + crt.sh certificate transparency. Optionally checks HTTP status of found subdomains.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string" }, "wordlist": { "type": "string", "enum": ["small", "medium", "large"], "default": "medium" },
                    "use_crt_sh": { "type": "boolean", "default": true }, "check_http": { "type": "boolean", "default": true },
                    "timeout_ms": { "type": "integer", "default": 5000 }
                },
                "required": ["domain"]
            }),
        },
        ToolDef {
            name: "discover_content".into(),
            description: "Directory/file bruteforce (dirbusting). Wordlists: common, admin, api, backup, medium. Concurrent with semaphore.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string" }, "wordlist": { "type": "string", "enum": ["common", "admin", "api", "backup", "medium"], "default": "common" },
                    "extensions": { "type": "array", "items": { "type": "string" }, "description": "File extensions to append" },
                    "follow_redirects": { "type": "boolean", "default": false },
                    "max_concurrent": { "type": "integer", "default": 20 },
                    "timeout_ms": { "type": "integer", "default": 5000 }
                },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "find_secrets".into(),
            description: "Scan text or a URL response for leaked secrets: AWS keys, API keys, JWTs, passwords, database URLs, internal IPs, and more (17 pattern types).".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "Text to scan for secrets" },
                    "target": { "type": "string", "description": "URL to fetch and scan (alternative to text)" }
                }
            }),
        },
        ToolDef {
            name: "dns_resolve".into(),
            description: "DNS resolution with CDN detection and origin subdomain probing. Checks for CloudFront, Cloudflare, Akamai indicators.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string" } },
                "required": ["domain"]
            }),
        },
        ToolDef {
            name: "oast_generate_payload".into(),
            description: "Generate OAST callback payloads for blind vulnerability detection. Supports blind_sqli, blind_ssrf, blind_xxe, blind_cmdi, blind_xss, blind_ssti.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "description": { "type": "string", "description": "What this payload tests" },
                    "vuln_type": { "type": "string", "enum": ["generic", "blind_sqli", "blind_ssrf", "blind_xxe", "blind_cmdi", "blind_xss", "blind_ssti"], "default": "generic" }
                }
            }),
        },
        ToolDef {
            name: "oast_poll_interactions".into(),
            description: "Poll for OAST callback interactions. Filter by correlation_id.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "correlation_id": { "type": "string" } }
            }),
        },
        ToolDef {
            name: "oast_start_server".into(),
            description: "Start OAST HTTP callback server.".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": { "http_port": { "type": "integer", "default": 8888 } } }),
        },
        ToolDef {
            name: "oast_start_dns_server".into(),
            description: "Start OAST DNS callback server for detecting blind DNS exfiltration.".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": { "port": { "type": "integer", "default": 8853 } } }),
        },
        ToolDef {
            name: "oast_start_smtp_server".into(),
            description: "Start OAST SMTP callback server for detecting blind email-based exfiltration.".into(),
            input_schema: serde_json::json!({ "type": "object", "properties": { "port": { "type": "integer", "default": 2525 } } }),
        },
        ToolDef {
            name: "oast_verify".into(),
            description: "OAST server management: start_server, self_test (verify callback chain), get_interactions, clear.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["start_server", "self_test", "get_interactions", "clear"], "default": "self_test" },
                    "port": { "type": "integer", "default": 8888 },
                    "correlation_id": { "type": "string" }
                }
            }),
        },
        ToolDef {
            name: "crtsh_search".into(),
            description: "Search crt.sh Certificate Transparency logs for subdomains and certificates.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string" }, "include_expired": { "type": "boolean", "default": false } },
                "required": ["domain"]
            }),
        },
        ToolDef {
            name: "wayback_lookup".into(),
            description: "Search Wayback Machine for historical URLs, API endpoints, and interesting files.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string" }, "match_type": { "type": "string", "default": "domain" }, "limit": { "type": "integer", "default": 500 } },
                "required": ["domain"]
            }),
        },
        ToolDef {
            name: "whois_lookup".into(),
            description: "RDAP/WHOIS lookup for domain or IP — registrar, nameservers, dates, contacts.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "target": { "type": "string", "description": "Domain or IP address" } },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "asn_lookup".into(),
            description: "ASN lookup for IP or AS number — identifies network owner, prefix, country via Team Cymru + RDAP.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "target": { "type": "string", "description": "IP address or AS number (e.g., AS13335)" } },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "favicon_hash".into(),
            description: "Compute MurmurHash3 of a favicon for Shodan/FOFA/ZoomEye searches. Returns search query strings.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "target": { "type": "string", "description": "URL or domain to fetch favicon from" } },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "reverse_ip_lookup".into(),
            description: "PTR record lookup — find hostnames associated with an IP address.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "ip": { "type": "string" } },
                "required": ["ip"]
            }),
        },
        ToolDef {
            name: "js_link_finder".into(),
            description: "Analyze JavaScript files linked from a page — extracts API endpoints, paths, and hardcoded secrets.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "target": { "type": "string" }, "max_js_files": { "type": "integer", "default": 20 } },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "graphql_introspect".into(),
            description: "GraphQL introspection — discovers queries, mutations, types, and fields. Works with authenticated endpoints.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "GraphQL endpoint URL" },
                    "headers": { "type": "object", "description": "Auth/custom headers", "additionalProperties": { "type": "string" } }
                },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "raw_tcp_send".into(),
            description: "Send raw bytes over TCP/TLS. Use for HTTP smuggling (CL.TE/TE.CL), custom protocol testing, banner grabbing, and crafted malformed requests.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "host": { "type": "string" }, "port": { "type": "integer" },
                    "tls": { "type": "boolean", "default": false },
                    "data": { "type": "string", "description": "Raw string data (supports \\r\\n escape, {host} template)" },
                    "data_hex": { "type": "string", "description": "Alternative: hex-encoded bytes" },
                    "read_timeout_ms": { "type": "integer", "default": 5000 },
                    "read_size": { "type": "integer", "default": 65536 }
                },
                "required": ["host"]
            }),
        },
        ToolDef {
            name: "mtls_send_request".into(),
            description: "Send HTTP request with mutual TLS (client certificate). Provide PKCS12 client cert for mTLS-protected endpoints.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string" }, "method": { "type": "string", "default": "GET" },
                    "headers": { "type": "object", "additionalProperties": { "type": "string" } },
                    "body": { "type": "string" },
                    "client_pkcs12_base64": { "type": "string", "description": "Base64-encoded PKCS12 client certificate" },
                    "pkcs12_password": { "type": "string", "default": "" }
                },
                "required": ["url"]
            }),
        },
        ToolDef {
            name: "race_request".into(),
            description: "Fire N requests simultaneously using a barrier sync — detects race conditions (TOCTOU). All requests release at the same microsecond.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "requests": { "type": "array", "items": { "type": "object" }, "description": "Array of {method, url, headers, body}" },
                    "repeat_count": { "type": "integer", "description": "Repeat a single template N times" },
                    "template_request": { "type": "object", "description": "Template request to repeat" },
                    "gate_timeout_ms": { "type": "integer", "default": 5000 }
                }
            }),
        },
        ToolDef {
            name: "h2_send_request".into(),
            description: "Send HTTP/2 request — test H2-specific behaviors, multiplexing, protocol downgrade.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string" }, "method": { "type": "string", "default": "GET" },
                    "headers": { "type": "object", "additionalProperties": { "type": "string" } },
                    "body": { "type": "string" }
                },
                "required": ["url"]
            }),
        },
        ToolDef {
            name: "bambda_filter".into(),
            description: "Apply Bambda-style filter expressions to traffic data. Syntax: 'field operator value' (e.g., 'status >= 400 AND url contains /api').".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "expression": { "type": "string", "description": "Bambda filter expression" },
                    "traffic": { "type": "array", "description": "Traffic entries to filter (optional, omit to just validate expression)" }
                },
                "required": ["expression"]
            }),
        },
        ToolDef {
            name: "payload_manager".into(),
            description: "Manage attack payload wordlists. Download from SecLists/PayloadsAllTheThings, search, list categories. Actions: download, list, search, info, load.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["download", "list", "search", "info", "load"], "description": "Action to perform", "default": "list" },
                    "category": { "type": "string", "description": "Payload category: sqli, xss, cmdi, ssti, lfi, ssrf, xxe, ldap, nosql, open_redirect, auth, fuzzing, traversal, all" },
                    "source": { "type": "string", "description": "Source filter: seclists, payloadsallthethings, all", "default": "all" },
                    "query": { "type": "string", "description": "Search query (for action=search)" },
                    "limit": { "type": "integer", "description": "Max payloads to return (for action=load)", "default": 100 },
                    "offset": { "type": "integer", "description": "Offset for pagination (for action=load)", "default": 0 }
                }
            }),
        },
        ToolDef {
            name: "passive_scan".into(),
            description: "Passive security scan — analyzes response for security headers, cookie flags, CORS misconfig, info disclosure. No extra attack requests sent.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target URL to analyze" },
                    "checks": { "type": "array", "items": { "type": "string" }, "description": "Check categories: all, headers, cookies, cors, info_disclosure", "default": ["all"] }
                },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "fuzz_request".into(),
            description: "Multi-mode request fuzzer (Intruder). Supports Sniper, Battering Ram, Pitchfork, Cluster Bomb attack types. Can load payloads from downloaded wordlists.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "attack_type": { "type": "string", "enum": ["sniper", "battering_ram", "pitchfork", "cluster_bomb"], "default": "sniper", "description": "Attack mode" },
                    "base_request": {
                        "type": "object",
                        "description": "Base request template with §marker§ placeholders",
                        "properties": {
                            "method": { "type": "string", "default": "GET" },
                            "url": { "type": "string" },
                            "headers": { "type": "object" },
                            "body": { "type": "string" }
                        },
                        "required": ["url"]
                    },
                    "positions": {
                        "type": "array",
                        "description": "Payload positions",
                        "items": {
                            "type": "object",
                            "properties": {
                                "marker": { "type": "string", "default": "§payload§" },
                                "source": { "type": "string", "enum": ["inline", "file", "range"], "default": "inline" },
                                "payloads": { "description": "Payloads for source=inline (array or newline-separated string)" },
                                "file_category": { "type": "string", "description": "Category for source=file (e.g., sqli, xss)" },
                                "limit": { "type": "integer", "default": 1000 },
                                "start": { "type": "integer" }, "end": { "type": "integer" }, "step": { "type": "integer" }
                            }
                        }
                    },
                    "match_rules": {
                        "type": "array",
                        "description": "Match rules for anomaly detection",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string", "enum": ["status_code", "length_diff", "body_contains", "body_regex", "timing", "status_diff"] },
                                "values": { "type": "array", "items": { "type": "integer" } },
                                "value": { "type": "string" },
                                "pattern": { "type": "string" },
                                "threshold": { "type": "integer" },
                                "threshold_ms": { "type": "integer" }
                            }
                        }
                    },
                    "max_concurrent": { "type": "integer", "default": 10 },
                    "delay_ms": { "type": "integer", "default": 0 },
                    "max_requests": { "type": "integer", "default": 10000 },
                    "stop_on_match": { "type": "boolean", "default": false }
                },
                "required": ["base_request", "positions"]
            }),
        },
        ToolDef {
            name: "active_scan".into(),
            description: "Active vulnerability scanner — probes for SQLi (error + time-based blind), XSS (reflected), SSTI (7 engines), LFI (7 techniques), Open Redirect, CRLF/Header Injection. Uses downloaded payloads.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target URL with query parameters to test" },
                    "scan_types": { "type": "array", "items": { "type": "string" }, "description": "Scan types: all, sqli, xss, ssti, lfi, open_redirect, header_injection", "default": ["all"] },
                    "max_payloads_per_type": { "type": "integer", "default": 25, "description": "Max payloads per vulnerability type" },
                    "max_concurrent": { "type": "integer", "default": 5 },
                    "timeout_secs": { "type": "integer", "default": 15 }
                },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "generate_report".into(),
            description: "Generate security report from scan findings. Formats: markdown (full report), json (structured data), summary (overview only).".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "findings": { "type": "array", "description": "Array of finding objects from scan results" },
                    "format": { "type": "string", "enum": ["markdown", "json", "summary"], "default": "markdown" },
                    "title": { "type": "string", "default": "WonderSuite Security Report" },
                    "target": { "type": "string", "description": "Target that was scanned" }
                },
                "required": ["findings"]
            }),
        },
        ToolDef {
            name: "send_to_repeater".into(),
            description: "Replay a request from proxy traffic (by traffic_id) or send a raw request. Allows modifying method, URL, headers, body before resending. Response logged as 'repeater' source.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "traffic_id": { "type": "integer", "description": "Traffic entry ID to replay (from proxy_get_traffic)" },
                    "url": { "type": "string", "description": "URL (required if no traffic_id)" },
                    "method": { "type": "string", "description": "Override HTTP method" },
                    "headers": { "type": "object", "description": "Override/add headers" },
                    "raw_headers": { "type": "string", "description": "Raw header string override" },
                    "body": { "type": "string", "description": "Override request body" }
                }
            }),
        },
        ToolDef {
            name: "send_to_intruder".into(),
            description: "Convert a proxy traffic entry into a fuzz_request config with auto-detected injection points. Returns a ready-to-use intruder config.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "traffic_id": { "type": "integer", "description": "Traffic entry ID to convert" }
                },
                "required": ["traffic_id"]
            }),
        },
        ToolDef {
            name: "get_intercepted".into(),
            description: "List all intercepted requests/responses waiting for a decision. Use with forward_intercepted to modify and forward.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        },
        ToolDef {
            name: "forward_intercepted".into(),
            description: "Forward or drop an intercepted request. Optionally modify the raw request before forwarding. This enables real-time MITM attack testing.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "description": "Intercepted item ID" },
                    "action": { "type": "string", "enum": ["forward", "drop"], "default": "forward" },
                    "modified_raw": { "type": "string", "description": "Modified raw request/response to forward instead of original" },
                    "modify": {
                        "type": "object",
                        "description": "Structured request modification (alternative to modified_raw). Surgically edit individual fields.",
                        "properties": {
                            "method": { "type": "string", "description": "Override HTTP method (e.g. GET→POST, PUT, DELETE, PATCH)" },
                            "path": { "type": "string", "description": "Override request path" },
                            "headers": { "type": "object", "description": "Replace ALL headers with this map" },
                            "body": { "type": "string", "description": "Override request body. Content-Length auto-updated." },
                            "add_headers": { "type": "object", "description": "Add/replace specific headers without touching others" },
                            "remove_headers": { "type": "array", "items": { "type": "string" }, "description": "Remove specific headers by name" }
                        }
                    }
                },
                "required": ["id"]
            }),
        },
        ToolDef {
            name: "proxy_remove_interception_rule".into(),
            description: "Remove or toggle an interception rule by ID.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "description": "Rule ID to remove/toggle" },
                    "action": { "type": "string", "enum": ["remove", "toggle"], "default": "remove" }
                },
                "required": ["id"]
            }),
        },
        ToolDef {
            name: "proxy_remove_match_replace".into(),
            description: "Remove or toggle a match/replace rule by ID.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "description": "Rule ID to remove/toggle" },
                    "action": { "type": "string", "enum": ["remove", "toggle"], "default": "remove" }
                },
                "required": ["id"]
            }),
        },
        ToolDef {
            name: "proxy_annotate_traffic".into(),
            description: "Annotate a traffic entry with notes and color highlighting (like Burp highlighting). Colors: red, orange, yellow, green, blue, purple, gray.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "traffic_id": { "type": "integer", "description": "Traffic entry ID" },
                    "notes": { "type": "string", "description": "Notes to attach" },
                    "color": { "type": "string", "description": "Highlight color" }
                },
                "required": ["traffic_id"]
            }),
        },
        ToolDef {
            name: "hackertarget_lookup".into(),
            description: "Query HackerTarget OSINT API (no API key). Bundles 7 tools: hostsearch, reversedns, dnslookup, httpheaders, pagelinks, geoip, aslookup. Run all or select specific ones.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Domain or IP to query" },
                    "tools": { "type": "array", "items": { "type": "string" }, "description": "Which tools to run: hostsearch, reversedns, dnslookup, httpheaders, pagelinks, geoip, aslookup. Default: all", "default": ["hostsearch", "reversedns", "dnslookup", "httpheaders", "pagelinks", "geoip", "aslookup"] }
                },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "ip_geolocation".into(),
            description: "Full IP geolocation via ip-api.com + country.is (no API key). Returns country, city, ISP, ASN, reverse DNS, proxy/mobile/hosting detection.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "ip": { "type": "string", "description": "IP address to geolocate" }
                },
                "required": ["ip"]
            }),
        },
        ToolDef {
            name: "tech_detect".into(),
            description: "Technology fingerprinting — detects web server, framework, CMS, CDN, analytics, libraries via HTTP headers and HTML body analysis. No API key needed.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "URL or domain to fingerprint" }
                },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "analyze_cdn_waf".into(),
            description: "Detect CDN (Cloudflare, BunnyCDN, CloudFront, Akamai, Fastly, Sucuri, Imperva) and WAF presence on a target. Returns fingerprints, bypass strategies, origin discovery hints, and evasion techniques. ALWAYS run this first on new targets to understand protections before attacking.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target URL or domain to analyze for CDN/WAF presence" }
                },
                "required": ["target"]
            }),
        },
        ToolDef {
            name: "get_traffic_log".into(),
            description: "Read the full traffic log from all MCP HTTP requests. Returns complete request/response data (headers + bodies) with auto-detected CDN presence and security findings. Use this instead of browser_network_traffic — it captures ALL requests made via send_request with full detail. Filter by URL, method, status code range.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "since_id": { "type": "integer", "description": "Only return entries with ID greater than this (for polling)", "default": 0 },
                    "limit": { "type": "integer", "description": "Max entries to return (newest first)", "default": 100 },
                    "url_contains": { "type": "string", "description": "Filter by URL substring (case insensitive)" },
                    "method": { "type": "string", "description": "Filter by HTTP method (GET, POST, etc.)" },
                    "status": { "type": "integer", "description": "Filter by exact status code" },
                    "min_status": { "type": "integer", "description": "Filter by minimum status code (e.g. 400 for errors)" },
                    "max_status": { "type": "integer", "description": "Filter by maximum status code" }
                }
            }),
        },
    ]
}

pub struct McpServer {
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
    pub bound_port: u16,
}

impl McpServer {
    pub fn new() -> Self {
        Self { shutdown_tx: None, thread_handle: None, bound_port: 0 }
    }

    /// Start the MCP HTTP server on a dedicated thread with its own tokio runtime.
    /// This avoids any interference with Tauri's async runtime.
    pub fn start_sync(&mut self, port: u16) -> Result<(), String> {
        if self.shutdown_tx.is_some() {
            return Err("Server already running".into());
        }

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<u16, String>>();

        let handle = std::thread::Builder::new()
            .name("mcp-server".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(4)
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("Failed to create runtime: {}", e)));
                        return;
                    }
                };

                rt.block_on(async move {
                    let app = Router::new().route(
                        "/mcp",
                        post(|body: axum::body::Bytes| async move { router::handle_rpc(body).await })
                            .get(router::handle_mcp_get),
                    );

                    let ports = [port, port + 1, port + 2];
                    let mut listener_opt = None;
                    let mut bound = port;

                    for &p in &ports {
                        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], p));
                        match tokio::net::TcpListener::bind(addr).await {
                            Ok(l) => {
                                listener_opt = Some(l);
                                bound = p;
                                break;
                            }
                            Err(e) => {
                                println!("[MCP] Port {} unavailable: {}", p, e);
                            }
                        }
                    }

                    let listener = match listener_opt {
                        Some(l) => l,
                        None => {
                            let _ = ready_tx.send(Err("Could not bind to any port".into()));
                            return;
                        }
                    };

                    println!("[MCP] Server listening on 127.0.0.1:{}", bound);
                    let _ = ready_tx.send(Ok(bound));

                    axum::serve(listener, app)
                        .with_graceful_shutdown(async {
                            let _ = rx.await;
                        })
                        .await
                        .ok();

                    println!("[MCP] Server shut down");
                });
            })
            .map_err(|e| format!("Failed to spawn MCP thread: {}", e))?;

        match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(bound_port)) => {
                self.shutdown_tx = Some(tx);
                self.thread_handle = Some(handle);
                self.bound_port = bound_port;
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err("MCP server startup timed out".into()),
        }
    }

    /// Async wrapper for Tauri commands
    pub async fn start(&mut self, port: u16) -> Result<(), String> {
        self.start_sync(port)
    }

    pub fn stop(&mut self) -> Result<(), String> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
        self.bound_port = 0;
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.shutdown_tx.is_some()
    }
}

pub type McpState = Arc<Mutex<McpServer>>;

pub fn create_mcp_state() -> McpState {
    Arc::new(Mutex::new(McpServer::new()))
}
