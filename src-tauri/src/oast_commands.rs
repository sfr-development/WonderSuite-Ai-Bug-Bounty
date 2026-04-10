use serde::Serialize;
use std::sync::OnceLock;
use tokio::sync::Mutex;

use crate::oast::{self, OastPayload, OastInteraction};

/// Global payload store (payloads generated via GUI)
static PAYLOADS: OnceLock<Mutex<Vec<OastPayload>>> = OnceLock::new();

fn get_payloads() -> &'static Mutex<Vec<OastPayload>> {
    PAYLOADS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Server status tracking
static SERVER_STATUS: OnceLock<Mutex<OastServerStatus>> = OnceLock::new();

#[derive(Debug, Clone, Serialize)]
pub struct OastServerStatus {
    pub http_running: bool,
    pub http_port: u16,
    pub dns_running: bool,
    pub dns_port: u16,
    pub smtp_running: bool,
    pub smtp_port: u16,
}

impl Default for OastServerStatus {
    fn default() -> Self {
        Self {
            http_running: false, http_port: 8888,
            dns_running: false, dns_port: 8853,
            smtp_running: false, smtp_port: 2525,
        }
    }
}

fn get_server_status() -> &'static Mutex<OastServerStatus> {
    SERVER_STATUS.get_or_init(|| Mutex::new(OastServerStatus::default()))
}

// ─── Tauri Commands ─────────────────────────────────────────────────────

/// Start the OAST HTTP callback server
#[tauri::command]
pub async fn oast_start_http(port: Option<u16>) -> Result<String, String> {
    let p = port.unwrap_or(8888);
    oast::start_http_callback_server(p).await?;
    let mut status = get_server_status().lock().await;
    status.http_running = true;
    status.http_port = p;
    Ok(format!("OAST HTTP callback server started on port {}", p))
}

/// Start the OAST DNS callback server
#[tauri::command]
pub async fn oast_start_dns(port: Option<u16>) -> Result<String, String> {
    let p = port.unwrap_or(8853);
    oast::start_dns_server(p).await?;
    let mut status = get_server_status().lock().await;
    status.dns_running = true;
    status.dns_port = p;
    Ok(format!("OAST DNS callback server started on port {}", p))
}

/// Start the OAST SMTP callback server
#[tauri::command]
pub async fn oast_start_smtp(port: Option<u16>) -> Result<String, String> {
    let p = port.unwrap_or(2525);
    oast::start_smtp_server(p).await?;
    let mut status = get_server_status().lock().await;
    status.smtp_running = true;
    status.smtp_port = p;
    Ok(format!("OAST SMTP callback server started on port {}", p))
}

/// Get OAST server status
#[tauri::command]
pub async fn oast_status() -> Result<OastServerStatus, String> {
    let status = get_server_status().lock().await;
    Ok(status.clone())
}

/// Generate a new OAST payload
#[tauri::command]
pub async fn oast_generate(
    description: String,
    vuln_type: Option<String>,
    server_domain: Option<String>,
) -> Result<OastPayload, String> {
    let domain = server_domain.unwrap_or_else(|| "oast.wondersuite.local".to_string());
    let desc = if let Some(vt) = &vuln_type {
        format!("[{}] {}", vt, description)
    } else {
        description
    };
    let payload = oast::generate_oast_payload(&desc, &domain);
    get_payloads().lock().await.push(payload.clone());
    Ok(payload)
}

/// Generate scan-specific OAST payloads (SQLi, SSRF, XXE, CmdInj)
#[tauri::command]
pub async fn oast_generate_scan_payloads(
    target: String,
    server_domain: Option<String>,
) -> Result<Vec<serde_json::Value>, String> {
    let domain = server_domain.unwrap_or_else(|| "oast.wondersuite.local".to_string());
    let result = oast::generate_oast_payloads_for_scan(&target, &domain);
    let mut store = get_payloads().lock().await;
    let mut out = Vec::new();
    for (vuln_type, inject_payload, oast_payload) in result {
        store.push(oast_payload.clone());
        out.push(serde_json::json!({
            "vuln_type": vuln_type,
            "inject_payload": inject_payload,
            "oast_payload": oast_payload,
        }));
    }
    Ok(out)
}

/// Get all generated payloads
#[tauri::command]
pub async fn oast_get_payloads() -> Result<Vec<OastPayload>, String> {
    let store = get_payloads().lock().await;
    Ok(store.clone())
}

/// Poll for OAST interactions (callbacks received)
#[tauri::command]
pub async fn oast_poll_interactions(
    correlation_id: Option<String>,
) -> Result<Vec<OastInteraction>, String> {
    let store = oast::get_interactions().lock().await;
    let filtered: Vec<OastInteraction> = if let Some(cid) = correlation_id {
        store.iter().filter(|i| i.correlation_id == cid).cloned().collect()
    } else {
        store.clone()
    };
    Ok(filtered)
}

/// Clear all OAST data (payloads + interactions)
#[tauri::command]
pub async fn oast_clear() -> Result<String, String> {
    get_payloads().lock().await.clear();
    oast::get_interactions().lock().await.clear();
    Ok("OAST data cleared".into())
}

/// Generate Collaborator Everywhere headers for a target
#[tauri::command]
pub async fn oast_collaborator_everywhere(
    server_domain: Option<String>,
) -> Result<Vec<serde_json::Value>, String> {
    let domain = server_domain.unwrap_or_else(|| "oast.wondersuite.local".to_string());
    let headers = oast::collaborator_everywhere_headers(&domain);
    let mut store = get_payloads().lock().await;
    let out: Vec<serde_json::Value> = headers.into_iter().map(|(header, value, oast_payload)| {
        store.push(oast_payload.clone());
        serde_json::json!({
            "header": header,
            "value": value,
            "oast_payload": oast_payload,
        })
    }).collect();
    Ok(out)
}
