use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    Connect,
    Syn,
    Udp,
}

impl Default for ScanMode {
    fn default() -> Self {
        ScanMode::Connect
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TimingTemplate {
    T0,
    T1,
    T2,
    T3,
    T4,
    T5,
    T6,
}

impl Default for TimingTemplate {
    fn default() -> Self {
        TimingTemplate::T3
    }
}

impl TimingTemplate {
    /// (initial_permits, connect_timeout_ms, max_retries, target_pps)
    pub fn defaults(&self) -> (usize, u64, u8, u32) {
        match self {
            TimingTemplate::T0 => (1, 300_000, 10, 1),
            TimingTemplate::T1 => (4, 15_000, 10, 5),
            TimingTemplate::T2 => (16, 10_000, 8, 50),
            TimingTemplate::T3 => (256, 3_000, 6, 1_000),
            TimingTemplate::T4 => (1024, 1_250, 4, 5_000),
            TimingTemplate::T5 => (4096, 300, 2, 20_000),
            TimingTemplate::T6 => (16384, 150, 1, 65_000),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub targets: Vec<String>,
    pub ports: String,
    #[serde(default)]
    pub mode: ScanMode,
    #[serde(default)]
    pub timing: TimingTemplate,
    #[serde(default = "default_true")]
    pub service_detect: bool,
    #[serde(default = "default_intensity")]
    pub probe_intensity: u8,
    #[serde(default)]
    pub exclude_cdn: bool,
    #[serde(default = "default_true")]
    pub adaptive: bool,
    #[serde(default)]
    pub idle_mode: bool,
    #[serde(default)]
    pub max_hosts: Option<usize>,
    // v0.3.20: when false the orchestrator drops Closed / Filtered /
    // OpenFiltered results before persisting + emitting. Frontend wires
    // this to the "Show closed/filtered" toggle so the user can opt out
    // of the noise at-source instead of just hiding it in the UI.
    // Default true keeps backward compat with older callers / MCP clients.
    #[serde(default = "default_true")]
    pub emit_closed_filtered: bool,
}

fn default_true() -> bool {
    true
}
fn default_intensity() -> u8 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cn: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls_san: Vec<String>,
    #[serde(default)]
    pub tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub host: String,
    pub ip: IpAddr,
    pub port: u16,
    pub proto: String,
    pub state: PortState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceInfo>,
    pub rtt_ms: u32,
    pub ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub status: String,
    pub total_probes: usize,
    pub completed: usize,
    pub open_count: usize,
    pub filtered_count: usize,
    pub pps: f64,
    pub rtt_p50_ms: u32,
    pub permits: usize,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scan_id: String,
    pub status: String,
    pub total_open: usize,
    pub total_filtered: usize,
    pub total_probed: usize,
    pub elapsed_ms: u64,
    pub by_service: std::collections::HashMap<String, usize>,
    pub sample: Vec<ScanResult>,
}
