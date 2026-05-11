use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

/// A captured HTTP request/response pair for the traffic log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEntry {
    pub id: u64,
    pub timestamp: String,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub port: u16,
    pub tls: bool,
    pub status: u16,
    pub response_length: usize,
    pub response_time_ms: u64,
    pub mime_type: String,
    pub request_headers: String,
    pub request_body: String,
    pub response_headers: String,
    pub response_body: String,
    pub source: String, // "proxy", "repeater", "scanner", etc.
    pub notes: String,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketMessage {
    pub id: u64,
    pub connection_id: String,
    pub direction: String, // "client_to_server" or "server_to_client"
    pub opcode: String,    // "text", "binary", "ping", "pong", "close"
    pub data: String,
    pub length: usize,
    pub timestamp: String,
    pub host: String,
    pub url: String,
}

/// A request waiting for intercept decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptedItem {
    pub id: String,
    pub method: String,
    pub url: String,
    pub host: String,
    pub raw_request: String,
    pub timestamp: String,
    pub is_response: bool,
    pub status: Option<u16>,
    pub raw_response: Option<String>,
}

/// Decision for an intercepted request.
pub enum InterceptDecision {
    Forward(String), // possibly modified raw request/response
    Drop,
}

/// Pending intercept with its resolution channel.
pub struct PendingIntercept {
    pub item: InterceptedItem,
    pub sender: oneshot::Sender<InterceptDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptionRule {
    pub id: String,
    pub enabled: bool,
    pub name: String,
    pub rule_type: InterceptionRuleType,
    pub target: InterceptionTarget,
    /// "intercept" or "passthrough"
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum InterceptionRuleType {
    #[serde(rename = "url_contains")]
    UrlContains { pattern: String },
    #[serde(rename = "url_regex")]
    UrlRegex { pattern: String },
    #[serde(rename = "host_equals")]
    HostEquals { host: String },
    #[serde(rename = "method_equals")]
    MethodEquals { method: String },
    #[serde(rename = "header_contains")]
    HeaderContains { header: String, value: String },
    #[serde(rename = "mime_type")]
    MimeType { pattern: String },
    #[serde(rename = "status_code")]
    StatusCode { min: u16, max: u16 },
    #[serde(rename = "file_extension")]
    FileExtension { extensions: Vec<String> },
}

/// Whether rule applies to requests, responses, or both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InterceptionTarget {
    #[serde(rename = "request")]
    Request,
    #[serde(rename = "response")]
    Response,
    #[serde(rename = "both")]
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchReplaceRule {
    pub id: String,
    pub enabled: bool,
    pub name: String,
    /// Where to apply: "request_header", "request_body", "response_header", "response_body", "request_url", "request_param"
    pub target: String,
    pub match_pattern: String,
    pub replace_value: String,
    pub is_regex: bool,
    /// "request", "response", "both"
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsPassThroughEntry {
    pub id: String,
    pub enabled: bool,
    pub host: String,
    pub port: Option<u16>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamProxyConfig {
    pub enabled: bool,
    pub proxy_type: String, // "http", "socks5"
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Host patterns that bypass the upstream proxy ("*.internal.com")
    pub bypass_patterns: Vec<String>,
}

impl Default for UpstreamProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy_type: "http".into(),
            host: String::new(),
            port: 0,
            username: None,
            password: None,
            bypass_patterns: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyListener {
    pub id: String,
    pub enabled: bool,
    pub address: String,
    pub port: u16,
    pub is_default: bool,
    /// "all", "loopback", "specific"
    pub bind_type: String,
    pub running: bool,
}

/// Events emitted by the proxy for the frontend.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum ProxyEvent {
    #[serde(rename = "traffic")]
    Traffic { entry: TrafficEntry },
    #[serde(rename = "intercept")]
    Intercept { item: InterceptedItem },
    #[serde(rename = "intercept_resolved")]
    InterceptResolved { id: String, action: String },
    #[serde(rename = "websocket")]
    WebSocket { message: WebSocketMessage },
    #[serde(rename = "status")]
    Status { running: bool, port: u16, total_requests: usize },
}

/// Central proxy state shared across all tasks.
pub struct ProxyState {
    pub intercept_enabled: AtomicBool,
    pub response_intercept_enabled: AtomicBool,
    pub running: AtomicBool,
    id_counter: AtomicU64,
    pub traffic: Mutex<Vec<TrafficEntry>>,
    pub websocket_messages: Mutex<Vec<WebSocketMessage>>,
    pub pending_intercepts: Mutex<HashMap<String, PendingIntercept>>,
    pub event_tx: Mutex<Option<mpsc::UnboundedSender<ProxyEvent>>>,
    pub proxy_port: Mutex<u16>,
    pub interception_rules: RwLock<Vec<InterceptionRule>>,
    pub match_replace_rules: RwLock<Vec<MatchReplaceRule>>,
    pub tls_passthrough: RwLock<Vec<TlsPassThroughEntry>>,
    pub upstream_proxy: RwLock<UpstreamProxyConfig>,
    pub listeners: RwLock<Vec<ProxyListener>>,
    pub max_traffic_entries: AtomicU64,
    pub max_response_size: AtomicU64,
}

impl ProxyState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            intercept_enabled: AtomicBool::new(false),
            response_intercept_enabled: AtomicBool::new(false),
            running: AtomicBool::new(false),
            id_counter: AtomicU64::new(1),
            traffic: Mutex::new(Vec::new()),
            websocket_messages: Mutex::new(Vec::new()),
            pending_intercepts: Mutex::new(HashMap::new()),
            event_tx: Mutex::new(None),
            proxy_port: Mutex::new(8080),
            interception_rules: RwLock::new(Self::default_interception_rules()),
            match_replace_rules: RwLock::new(Vec::new()),
            tls_passthrough: RwLock::new(Vec::new()),
            upstream_proxy: RwLock::new(UpstreamProxyConfig::default()),
            listeners: RwLock::new(vec![ProxyListener {
                id: "default".into(),
                enabled: true,
                address: "127.0.0.1".into(),
                port: 8080,
                is_default: true,
                bind_type: "loopback".into(),
                running: false,
            }]),
            max_traffic_entries: AtomicU64::new(5000),
            max_response_size: AtomicU64::new(10 * 1024 * 1024), // 10MB
        })
    }

    fn default_interception_rules() -> Vec<InterceptionRule> {
        vec![
            InterceptionRule {
                id: "skip-images".into(),
                enabled: true,
                name: "Skip images".into(),
                rule_type: InterceptionRuleType::FileExtension {
                    extensions: vec![
                        "png".into(),
                        "jpg".into(),
                        "jpeg".into(),
                        "gif".into(),
                        "svg".into(),
                        "ico".into(),
                        "webp".into(),
                    ],
                },
                target: InterceptionTarget::Both,
                action: "passthrough".into(),
            },
            InterceptionRule {
                id: "skip-css-js".into(),
                enabled: true,
                name: "Skip CSS/JS".into(),
                rule_type: InterceptionRuleType::FileExtension {
                    extensions: vec![
                        "css".into(),
                        "js".into(),
                        "woff".into(),
                        "woff2".into(),
                        "ttf".into(),
                        "eot".into(),
                    ],
                },
                target: InterceptionTarget::Both,
                action: "passthrough".into(),
            },
        ]
    }

    pub fn next_id(&self) -> u64 {
        self.id_counter.fetch_add(1, Ordering::SeqCst)
    }

    pub fn is_intercept_enabled(&self) -> bool {
        self.intercept_enabled.load(Ordering::SeqCst)
    }

    pub fn is_response_intercept_enabled(&self) -> bool {
        self.response_intercept_enabled.load(Ordering::SeqCst)
    }

    pub fn set_intercept(&self, enabled: bool) {
        self.intercept_enabled.store(enabled, Ordering::SeqCst);
    }

    pub fn set_response_intercept(&self, enabled: bool) {
        self.response_intercept_enabled.store(enabled, Ordering::SeqCst);
    }

    /// Drain all pending intercepts by auto-forwarding them with their original
    /// payload. Called when intercept is toggled OFF so requests don't hang.
    /// Returns the number of intercepts that were drained.
    pub async fn drain_pending_intercepts(&self) -> usize {
        let mut intercepts = self.pending_intercepts.lock().await;
        let ids: Vec<String> = intercepts.keys().cloned().collect();
        let count = ids.len();
        for id in ids {
            if let Some(pending) = intercepts.remove(&id) {
                let _ = pending.sender.send(InterceptDecision::Forward(String::new()));
                self.emit(ProxyEvent::InterceptResolved { id, action: "forward".to_string() }).await;
            }
        }
        if count > 0 {
            println!("[Proxy] Drained {} pending intercepts (toggle off)", count);
        }
        count
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Check if a request should be intercepted based on interception rules.
    pub async fn should_intercept_request(&self, method: &str, url: &str, host: &str, headers: &str) -> bool {
        if !self.is_intercept_enabled() {
            return false;
        }

        let rules = self.interception_rules.read().await;
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }
            if !matches!(rule.target, InterceptionTarget::Request | InterceptionTarget::Both) {
                continue;
            }

            let matches = self.rule_matches(&rule.rule_type, method, url, host, headers, None);
            if matches {
                return rule.action == "intercept";
            }
        }
        true
    }

    /// Check if a response should be intercepted.
    pub async fn should_intercept_response(&self, url: &str, host: &str, status: u16, headers: &str) -> bool {
        if !self.is_response_intercept_enabled() {
            return false;
        }

        let rules = self.interception_rules.read().await;
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }
            if !matches!(rule.target, InterceptionTarget::Response | InterceptionTarget::Both) {
                continue;
            }

            let matches = self.rule_matches(&rule.rule_type, "", url, host, headers, Some(status));
            if matches {
                return rule.action == "intercept";
            }
        }
        true
    }

    fn rule_matches(
        &self,
        rule_type: &InterceptionRuleType,
        method: &str,
        url: &str,
        host: &str,
        headers: &str,
        status: Option<u16>,
    ) -> bool {
        match rule_type {
            InterceptionRuleType::UrlContains { pattern } => url.contains(pattern.as_str()),
            InterceptionRuleType::UrlRegex { pattern } => {
                regex::Regex::new(pattern).map(|r| r.is_match(url)).unwrap_or(false)
            }
            InterceptionRuleType::HostEquals { host: h } => host.eq_ignore_ascii_case(h),
            InterceptionRuleType::MethodEquals { method: m } => method.eq_ignore_ascii_case(m),
            InterceptionRuleType::HeaderContains { header, value } => headers.lines().any(|l| {
                if let Some((k, v)) = l.split_once(':') {
                    k.trim().eq_ignore_ascii_case(header) && v.trim().contains(value.as_str())
                } else {
                    false
                }
            }),
            InterceptionRuleType::MimeType { pattern } => headers.lines().any(|l| {
                if let Some((k, v)) = l.split_once(':') {
                    k.trim().eq_ignore_ascii_case("content-type") && v.trim().contains(pattern.as_str())
                } else {
                    false
                }
            }),
            InterceptionRuleType::StatusCode { min, max } => {
                status.map(|s| s >= *min && s <= *max).unwrap_or(false)
            }
            InterceptionRuleType::FileExtension { extensions } => {
                let path = url.split('?').next().unwrap_or(url);
                if let Some(ext) = path.rsplit('.').next() {
                    extensions.iter().any(|e| e.eq_ignore_ascii_case(ext))
                } else {
                    false
                }
            }
        }
    }

    /// Apply match & replace rules to a request.
    pub async fn apply_match_replace_request(
        &self,
        headers: &mut String,
        body: &mut String,
        url: &mut String,
    ) {
        let rules = self.match_replace_rules.read().await;
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }
            if rule.direction != "request" && rule.direction != "both" {
                continue;
            }

            match rule.target.as_str() {
                "request_header" => {
                    *headers = self.apply_replacement(
                        headers,
                        &rule.match_pattern,
                        &rule.replace_value,
                        rule.is_regex,
                    );
                }
                "request_body" => {
                    *body =
                        self.apply_replacement(body, &rule.match_pattern, &rule.replace_value, rule.is_regex);
                }
                "request_url" => {
                    *url =
                        self.apply_replacement(url, &rule.match_pattern, &rule.replace_value, rule.is_regex);
                }
                _ => {}
            }
        }
    }

    /// Apply match & replace rules to a response.
    pub async fn apply_match_replace_response(&self, headers: &mut String, body: &mut Vec<u8>) {
        let rules = self.match_replace_rules.read().await;
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }
            if rule.direction != "response" && rule.direction != "both" {
                continue;
            }

            match rule.target.as_str() {
                "response_header" => {
                    *headers = self.apply_replacement(
                        headers,
                        &rule.match_pattern,
                        &rule.replace_value,
                        rule.is_regex,
                    );
                }
                "response_body" => {
                    let body_str = String::from_utf8_lossy(body).to_string();
                    let new_body = self.apply_replacement(
                        &body_str,
                        &rule.match_pattern,
                        &rule.replace_value,
                        rule.is_regex,
                    );
                    *body = new_body.into_bytes();
                }
                _ => {}
            }
        }
    }

    fn apply_replacement(&self, input: &str, pattern: &str, replacement: &str, is_regex: bool) -> String {
        if is_regex {
            match regex::Regex::new(pattern) {
                Ok(re) => re.replace_all(input, replacement).to_string(),
                Err(_) => input.to_string(),
            }
        } else {
            input.replace(pattern, replacement)
        }
    }

    /// Check if a host is in the TLS pass-through list.
    pub async fn is_tls_passthrough(&self, host: &str, port: u16) -> bool {
        let list = self.tls_passthrough.read().await;
        list.iter().any(|entry| {
            if !entry.enabled {
                return false;
            }
            let host_match = if entry.host.starts_with('*') {
                host.ends_with(&entry.host[1..])
            } else {
                host.eq_ignore_ascii_case(&entry.host)
            };
            let port_match = entry.port.map(|p| p == port).unwrap_or(true);
            host_match && port_match
        })
    }

    pub async fn add_traffic(&self, entry: TrafficEntry) {
        let max = self.max_traffic_entries.load(Ordering::SeqCst) as usize;
        let mut traffic = self.traffic.lock().await;
        traffic.push(entry.clone());

        if traffic.len() > max {
            let drain = traffic.len() - max;
            traffic.drain(0..drain);
        }

        self.emit(ProxyEvent::Traffic { entry }).await;
    }

    pub async fn add_websocket_message(&self, msg: WebSocketMessage) {
        let mut messages = self.websocket_messages.lock().await;
        messages.push(msg.clone());
        if messages.len() > 5000 {
            messages.drain(0..500);
        }
        self.emit(ProxyEvent::WebSocket { message: msg }).await;
    }

    pub async fn add_intercept(&self, pending: PendingIntercept) {
        let item = pending.item.clone();
        let id = item.id.clone();
        let mut intercepts = self.pending_intercepts.lock().await;
        intercepts.insert(id, pending);
        self.emit(ProxyEvent::Intercept { item }).await;
    }

    pub async fn resolve_intercept(&self, id: &str, decision: InterceptDecision) -> bool {
        let mut intercepts = self.pending_intercepts.lock().await;
        match intercepts.remove(id) {
            Some(pending) => {
                let action = match &decision {
                    InterceptDecision::Forward(_) => "forward",
                    InterceptDecision::Drop => "drop",
                };
                self.emit(ProxyEvent::InterceptResolved { id: id.to_string(), action: action.to_string() })
                    .await;
                let _ = pending.sender.send(decision);
                true
            }
            _ => false,
        }
    }

    pub async fn get_traffic(&self) -> Vec<TrafficEntry> {
        self.traffic.lock().await.clone()
    }

    pub async fn search_traffic(&self, query: &str) -> Vec<TrafficEntry> {
        let traffic = self.traffic.lock().await;
        traffic
            .iter()
            .filter(|t| {
                t.url.contains(query)
                    || t.host.contains(query)
                    || t.path.contains(query)
                    || t.request_headers.contains(query)
                    || t.response_body.contains(query)
            })
            .cloned()
            .collect()
    }

    pub async fn get_pending_intercepts(&self) -> Vec<InterceptedItem> {
        let intercepts = self.pending_intercepts.lock().await;
        intercepts.values().map(|p| p.item.clone()).collect()
    }

    pub async fn clear_traffic(&self) {
        self.traffic.lock().await.clear();
    }

    pub async fn get_websocket_messages(&self) -> Vec<WebSocketMessage> {
        self.websocket_messages.lock().await.clone()
    }

    pub async fn emit(&self, event: ProxyEvent) {
        if let Some(tx) = self.event_tx.lock().await.as_ref() {
            let _ = tx.send(event);
        }
    }
}
