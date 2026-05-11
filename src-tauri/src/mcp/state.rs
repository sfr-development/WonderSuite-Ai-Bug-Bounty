use std::collections::{HashMap, VecDeque};

/// Global pentest session state — shared across ALL tool calls.
/// Enables the AI to build exploit chains without losing context.
#[derive(Debug, Clone, Default)]
pub struct SharedPentestState {
    /// Discovered endpoints from crawling/content discovery
    pub discovered_endpoints: Vec<DiscoveredEndpoint>,

    /// Active session tokens/cookies per domain
    pub session_store: HashMap<String, SessionData>,

    /// OAST correlation tracking — payload_id → callback mapping
    pub oast_correlations: HashMap<String, OastCorrelation>,

    /// Vulnerability findings from ALL tools (accumulative)
    pub findings: Vec<Finding>,

    /// Technology fingerprints per target
    pub tech_fingerprints: HashMap<String, Vec<String>>,

    /// Request/Response history for differential analysis (last 200)
    pub request_history: VecDeque<RequestRecord>,

    /// AI-assigned tags and notes per target
    pub target_notes: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub method: String,
    pub source: String, // "crawl", "content_discovery", "js_link_finder", etc.
    pub status_code: Option<u16>,
    pub content_type: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct SessionData {
    pub cookies: HashMap<String, String>,
    pub auth_header: Option<String>,
    pub csrf_token: Option<String>,
    pub last_updated: String,
}

#[derive(Debug, Clone)]
pub struct OastCorrelation {
    pub payload_id: String,
    pub injected_at: String,     // URL where payload was injected
    pub injection_point: String, // parameter name, header, etc.
    pub tool_name: String,       // which tool injected it
    pub callback_received: bool,
    pub callback_details: Option<serde_json::Value>,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: String,   // "critical", "high", "medium", "low", "info"
    pub confidence: String, // "certain", "firm", "tentative"
    pub url: String,
    pub evidence: serde_json::Value,
    pub tool_source: String, // which MCP tool found it
    pub timestamp: String,
    pub oast_confirmed: bool, // true if confirmed via out-of-band callback
}

#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub tool_name: String,
    pub url: String,
    pub method: String,
    pub status_code: u16,
    pub response_size: usize,
    pub response_time_ms: u64,
    pub timestamp: String,
}

/// Compact summary of current pentest state for AI decision-making
#[derive(Debug, Clone, serde::Serialize)]
pub struct PentestContext {
    pub total_endpoints: usize,
    pub total_findings: usize,
    pub active_sessions: Vec<String>,
    pub pending_oast: usize,
    pub confirmed_oast: usize,
    pub severity_summary: HashMap<String, usize>,
    pub technologies: HashMap<String, Vec<String>>,
    pub recent_requests: usize,
}

impl SharedPentestState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Auto-ingest results from any tool call into the shared state.
    /// Called after every successful tool execution.
    pub fn ingest_result(&mut self, tool_name: &str, result: &serde_json::Value) {
        let now = chrono::Utc::now().to_rfc3339();

        if let Some(url) = result["url"].as_str().or(result["target"].as_str()) {
            let record = RequestRecord {
                tool_name: tool_name.to_string(),
                url: url.to_string(),
                method: result["method"].as_str().unwrap_or("GET").to_string(),
                status_code: result["status"].as_u64().unwrap_or(0) as u16,
                response_size: result["body_length"].as_u64().unwrap_or(0) as usize,
                response_time_ms: result["response_ms"].as_u64().unwrap_or(0),
                timestamp: now.clone(),
            };
            self.request_history.push_back(record);
            if self.request_history.len() > 200 {
                self.request_history.pop_front();
            }
        }

        match tool_name {
            "crawl_target" | "discover_content" | "js_link_finder" => {
                if let Some(urls) = result["urls"]
                    .as_array()
                    .or(result["endpoints"].as_array())
                    .or(result["discovered_paths"].as_array())
                {
                    for url_val in urls {
                        if let Some(url_str) = url_val.as_str().or(url_val["url"].as_str()) {
                            self.discovered_endpoints.push(DiscoveredEndpoint {
                                url: url_str.to_string(),
                                method: "GET".to_string(),
                                source: tool_name.to_string(),
                                status_code: url_val["status"].as_u64().map(|s| s as u16),
                                content_type: url_val["content_type"].as_str().map(|s| s.to_string()),
                                timestamp: now.clone(),
                            });
                        }
                    }
                }
            }
            "discover_subdomains" | "crtsh_search" => {
                if let Some(subs) = result["subdomains"].as_array() {
                    for sub in subs {
                        if let Some(s) = sub.as_str() {
                            self.discovered_endpoints.push(DiscoveredEndpoint {
                                url: format!("https://{}", s),
                                method: "GET".to_string(),
                                source: tool_name.to_string(),
                                status_code: None,
                                content_type: None,
                                timestamp: now.clone(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        if let Some(findings_arr) = result["findings"].as_array() {
            for f in findings_arr {
                self.findings.push(Finding {
                    id: format!("{}_{}", tool_name, self.findings.len()),
                    title: f["title"]
                        .as_str()
                        .or(f["template_name"].as_str())
                        .unwrap_or("Unknown")
                        .to_string(),
                    severity: f["severity"].as_str().unwrap_or("info").to_string(),
                    confidence: f["confidence"].as_str().unwrap_or("tentative").to_string(),
                    url: f["url"].as_str().unwrap_or("").to_string(),
                    evidence: f.clone(),
                    tool_source: tool_name.to_string(),
                    timestamp: now.clone(),
                    oast_confirmed: false,
                });
            }
        }

        if let Some(techs) = result["technologies"].as_array() {
            let target = result["url"].as_str().or(result["target"].as_str()).unwrap_or("unknown");
            let entry = self.tech_fingerprints.entry(target.to_string()).or_insert_with(Vec::new);
            for tech in techs {
                if let Some(t) = tech.as_str() {
                    if !entry.contains(&t.to_string()) {
                        entry.push(t.to_string());
                    }
                }
            }
        }
    }

    /// Returns a compact context summary for AI decision-making
    pub fn get_context(&self) -> PentestContext {
        let mut severity_summary = HashMap::new();
        for f in &self.findings {
            *severity_summary.entry(f.severity.clone()).or_insert(0) += 1;
        }

        PentestContext {
            total_endpoints: self.discovered_endpoints.len(),
            total_findings: self.findings.len(),
            active_sessions: self.session_store.keys().cloned().collect(),
            pending_oast: self.oast_correlations.values().filter(|c| !c.callback_received).count(),
            confirmed_oast: self.oast_correlations.values().filter(|c| c.callback_received).count(),
            severity_summary,
            technologies: self.tech_fingerprints.clone(),
            recent_requests: self.request_history.len(),
        }
    }

    /// Register an OAST payload for correlation tracking
    pub fn register_oast_payload(
        &mut self,
        payload_id: &str,
        injected_at: &str,
        injection_point: &str,
        tool_name: &str,
    ) {
        self.oast_correlations.insert(
            payload_id.to_string(),
            OastCorrelation {
                payload_id: payload_id.to_string(),
                injected_at: injected_at.to_string(),
                injection_point: injection_point.to_string(),
                tool_name: tool_name.to_string(),
                callback_received: false,
                callback_details: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
        );
    }

    /// Mark an OAST correlation as confirmed (callback received)
    pub fn confirm_oast_callback(&mut self, payload_id: &str, details: serde_json::Value) {
        if let Some(corr) = self.oast_correlations.get_mut(payload_id) {
            corr.callback_received = true;
            corr.callback_details = Some(details);

            for finding in &mut self.findings {
                if finding.url == corr.injected_at {
                    finding.oast_confirmed = true;
                    finding.confidence = "certain".to_string();
                }
            }
        }
    }
}
