pub mod active;
pub mod fuzzer;
pub mod passive;
pub mod reporting;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub finding_type: String,
    pub name: String,
    pub severity: String,
    pub confidence: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    pub evidence: String,
    pub detail: String,
    pub remediation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_info: Option<RequestInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestInfo {
    pub method: String,
    pub url: String,
    pub request_headers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    pub response_status: u16,
    pub response_headers: Vec<String>,
    pub response_body_preview: String,
    pub response_time_ms: u64,
    pub response_size: usize,
}

/// Simple ID generator for findings
static FINDING_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub fn next_finding_id() -> String {
    let id = FINDING_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("finding-{}", id)
}
