use crate::proxy::ca::ProxyCa;
use crate::proxy::state::*;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Parsed modified request structure for reconstructing user edits.
#[allow(dead_code)]
struct ParsedModifiedRequest {
    method: String,
    url_path: String,
    headers_raw: String,
    body: String,
}

/// The main MITM proxy engine.
/// Handles HTTP, HTTPS (via CONNECT tunnel with TLS MITM), and WebSocket detection.
/// Supports match & replace, interception rules, TLS pass-through, upstream proxy,
/// invisible proxying, client certificates, and full request/response modification.
pub struct ProxyEngine {
    ca: Arc<ProxyCa>,
    state: Arc<ProxyState>,
    http_client: reqwest::Client,
}

impl ProxyEngine {
    pub fn new(ca: Arc<ProxyCa>, state: Arc<ProxyState>) -> Self {
        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap();

        Self { ca, state, http_client }
    }

    /// Build an HTTP client that routes through an upstream proxy.
    async fn build_upstream_client(&self) -> reqwest::Client {
        let cfg = self.state.upstream_proxy.read().await;
        if !cfg.enabled || cfg.host.is_empty() {
            return self.http_client.clone();
        }

        let proxy_url = format!("{}://{}:{}", cfg.proxy_type, cfg.host, cfg.port);
        let proxy_result = reqwest::Proxy::all(&proxy_url);

        let proxy = match proxy_result {
            Ok(p) => {
                if let (Some(user), Some(pass)) = (cfg.username.as_ref(), cfg.password.as_ref()) {
                    p.basic_auth(user, pass)
                } else {
                    p
                }
            }
            Err(_) => return self.http_client.clone(),
        };

        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .proxy(proxy)
            .build()
            .unwrap_or_else(|_| self.http_client.clone())
    }

    /// Start the proxy on the given port.
    pub async fn run(self: Arc<Self>, port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
        self.state.running.store(true, std::sync::atomic::Ordering::SeqCst);
        *self.state.proxy_port.lock().await = port;
        println!("[Proxy] ✓ Listening on 127.0.0.1:{}", port);

        loop {
            if !self.state.is_running() {
                break;
            }

            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let engine = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = engine.handle_connection(stream).await {
                                    // Suppress common connection reset errors
                                    let msg = e.to_string();
                                    if !msg.contains("connection reset") && !msg.contains("broken pipe") {
                                        eprintln!("[Proxy] Connection error from {}: {}", addr, msg);
                                    }
                                }
                            });
                        }
                        Err(e) => eprintln!("[Proxy] Accept error: {}", e),
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                    if !self.state.is_running() { break; }
                }
            }
        }

        println!("[Proxy] Stopped");
        Ok(())
    }

    /// Handle a single client connection.
    /// Supports both explicit proxy mode (CONNECT, absolute URLs) and
    /// invisible proxying (direct connections with relative paths).
    async fn handle_connection(&self, mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut buf = BufReader::new(&mut stream);
        let mut first_line = String::new();
        buf.read_line(&mut first_line).await?;
        let first_line = first_line.trim().to_string();

        if first_line.is_empty() { return Ok(()); }

        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 3 { return Ok(()); }

        let method = parts[0].to_uppercase();
        let target = parts[1].to_string();

        // Read remaining headers
        let mut headers_raw = first_line.clone() + "\r\n";
        let mut content_length: usize = 0;
        let mut host_header = String::new();
        loop {
            let mut line = String::new();
            buf.read_line(&mut line).await?;
            headers_raw.push_str(&line);
            let trimmed = line.trim();
            if trimmed.is_empty() { break; }
            if let Some(val) = trimmed.to_lowercase().strip_prefix("content-length:") {
                content_length = val.trim().parse().unwrap_or(0);
            }
            // Capture Host header for invisible proxying
            if let Some(val) = trimmed.to_lowercase().strip_prefix("host:") {
                host_header = val.trim().to_string();
            }
        }

        // Cap body read to max_response_size
        let max_body = self.state.max_response_size.load(std::sync::atomic::Ordering::SeqCst) as usize;
        let read_len = content_length.min(max_body);
        let mut body = vec![0u8; read_len];
        if read_len > 0 {
            buf.read_exact(&mut body).await?;
        }

        if method == "CONNECT" {
            self.handle_connect(stream, &target).await
        } else if target.starts_with("http://") || target.starts_with("https://") {
            // Standard explicit proxy mode (absolute URL)
            self.handle_http(stream, &method, &target, &headers_raw, &body).await
        } else if !host_header.is_empty() {
            // Invisible proxying: non-proxy-aware client sent a relative path
            // Reconstruct full URL from Host header
            let full_url = format!("http://{}{}", host_header, target);
            self.handle_http(stream, &method, &full_url, &headers_raw, &body).await
        } else {
            // Fallback: try to handle as relative path on localhost
            self.handle_http(stream, &method, &target, &headers_raw, &body).await
        }
    }

    /// Handle CONNECT tunnel (HTTPS MITM).
    async fn handle_connect(
        &self,
        mut stream: TcpStream,
        target: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (host, port) = parse_host_port(target, 443);

        // Check TLS pass-through list
        if self.state.is_tls_passthrough(&host, port).await {
            // Send 200 and tunnel raw bytes without MITM
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            stream.flush().await?;
            self.tcp_tunnel(stream, &host, port).await?;
            return Ok(());
        }

        // Tell client the tunnel is established
        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        stream.flush().await?;

        // Try to generate TLS identity for this host
        let identity = match self.ca.generate_identity(&host) {
            Ok(id) => id,
            Err(e) => {
                eprintln!("[Proxy] TLS cert generation failed for {}: {}. Falling back to TCP tunnel.", host, e);
                self.tcp_tunnel(stream, &host, port).await?;
                return Ok(());
            }
        };

        // Set up TLS acceptor with the generated cert
        let tls_acceptor = native_tls::TlsAcceptor::builder(identity).build()?;
        let tls_acceptor = tokio_native_tls::TlsAcceptor::from(tls_acceptor);

        // TLS handshake with the client
        let tls_stream = match tls_acceptor.accept(stream).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[Proxy] TLS handshake failed for {}: {}", host, e);
                return Ok(());
            }
        };

        let (reader, mut writer) = tokio::io::split(tls_stream);
        let mut buf_reader = BufReader::new(reader);

        // Read decrypted HTTP requests
        loop {
            let mut first_line = String::new();
            match buf_reader.read_line(&mut first_line).await {
                Ok(0) | Err(_) => break,
                _ => {}
            }
            let first_line = first_line.trim().to_string();
            if first_line.is_empty() { break; }

            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() < 3 { break; }

            let method = parts[0].to_string();
            let path = parts[1].to_string();

            // Read headers
            let mut headers_raw = String::new();
            let mut content_length: usize = 0;
            let mut header_map = Vec::new();
            let mut is_websocket_upgrade = false;
            loop {
                let mut line = String::new();
                buf_reader.read_line(&mut line).await?;
                if line.trim().is_empty() { break; }
                headers_raw.push_str(&line);
                if let Some(val) = line.trim().to_lowercase().strip_prefix("content-length:") {
                    content_length = val.trim().parse().unwrap_or(0);
                }
                // WebSocket upgrade detection
                let lower = line.trim().to_lowercase();
                if lower.starts_with("upgrade:") && lower.contains("websocket") {
                    is_websocket_upgrade = true;
                }
                if let Some((k, v)) = line.trim().split_once(':') {
                    header_map.push((k.trim().to_string(), v.trim().to_string()));
                }
            }

            let mut body = vec![0u8; content_length];
            if content_length > 0 { buf_reader.read_exact(&mut body).await?; }

            let mut url = format!("https://{}:{}{}", host, port, path);
            let mut body_str = String::from_utf8_lossy(&body).to_string();
            let mut headers_str = headers_raw.clone();

            // Apply Match & Replace rules to request
            self.state.apply_match_replace_request(&mut headers_str, &mut body_str, &mut url).await;

            let raw_request = format!("{} {} HTTP/1.1\r\n{}{}",
                method, path, headers_str,
                if body.is_empty() { String::new() } else { format!("\r\n{}", body_str) });

            // WebSocket upgrade: tunnel instead of MITM
            if is_websocket_upgrade {
                // Log the WebSocket connection
                self.state.add_websocket_message(WebSocketMessage {
                    id: self.state.next_id(),
                    connection_id: uuid::Uuid::new_v4().to_string(),
                    direction: "client_to_server".into(),
                    opcode: "upgrade".into(),
                    data: raw_request.clone(),
                    length: raw_request.len(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    host: host.clone(),
                    url: url.clone(),
                }).await;

                // For now, forward the upgrade request and tunnel the WS connection
                let result = self.forward_request(&method, &url, &header_map, &body).await;
                if let Ok((status, resp_headers, resp_body)) = result {
                    let mut raw_resp = format!("HTTP/1.1 {}\r\n", status);
                    for (k, v) in &resp_headers {
                        raw_resp.push_str(&format!("{}: {}\r\n", k, v));
                    }
                    raw_resp.push_str("\r\n");
                    writer.write_all(raw_resp.as_bytes()).await?;
                    if !resp_body.is_empty() {
                        writer.write_all(&resp_body).await?;
                    }
                    writer.flush().await?;
                }
                // After upgrade, we'd need to handle WS frames — for now, break the MITM loop
                break;
            }

            // Intercept check (with rules)
            if self.state.should_intercept_request(&method, &url, &host, &headers_str).await {
                let item = InterceptedItem {
                    id: uuid::Uuid::new_v4().to_string(),
                    method: method.clone(), url: url.clone(), host: host.clone(),
                    raw_request: raw_request.clone(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    is_response: false,
                    status: None,
                    raw_response: None,
                };
                let (tx, rx) = oneshot::channel();
                self.state.add_intercept(PendingIntercept { item, sender: tx }).await;

                match rx.await {
                    Ok(InterceptDecision::Drop) => continue,
                    Ok(InterceptDecision::Forward(modified)) => {
                        // Fully reconstruct request from user's modifications
                        if !modified.is_empty() {
                            if let Some(parsed) = Self::parse_modified_request_full(&modified) {
                                // Update forwarding data with modified values
                                headers_str = parsed.headers_raw;
                                body_str = parsed.body;
                                if !parsed.url_path.is_empty() {
                                    // Reconstruct URL if path was changed
                                    url = format!("https://{}:{}{}", host, port, parsed.url_path);
                                }
                                // Rebuild header_map for forwarding
                                header_map.clear();
                                for line in headers_str.lines() {
                                    if let Some((k, v)) = line.split_once(':') {
                                        header_map.push((k.trim().to_string(), v.trim().to_string()));
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }

            // Forward to real server (using upstream proxy if configured)
            let start = Instant::now();
            let result = self.forward_request(&method, &url, &header_map, &body_str.as_bytes()).await;
            let elapsed = start.elapsed().as_millis() as u64;

            match result {
                Ok((status, mut resp_headers, mut resp_body)) => {
                    // Apply Match & Replace rules to response
                    let mut resp_headers_str = resp_headers.iter()
                        .map(|(k, v)| format!("{}: {}", k, v))
                        .collect::<Vec<_>>().join("\r\n");
                    self.state.apply_match_replace_response(&mut resp_headers_str, &mut resp_body).await;

                    // Re-parse response headers after match & replace
                    resp_headers = resp_headers_str.lines()
                        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
                        .collect();

                    // Response interception check
                    if self.state.should_intercept_response(&url, &host, status, &resp_headers_str).await {
                        let resp_item = InterceptedItem {
                            id: uuid::Uuid::new_v4().to_string(),
                            method: method.clone(), url: url.clone(), host: host.clone(),
                            raw_request: raw_request.clone(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            is_response: true,
                            status: Some(status),
                            raw_response: Some(format!("HTTP/1.1 {}\r\n{}\r\n\r\n{}",
                                status, resp_headers_str, String::from_utf8_lossy(&resp_body))),
                        };
                        let (tx, rx) = oneshot::channel();
                        self.state.add_intercept(PendingIntercept { item: resp_item, sender: tx }).await;

                        match rx.await {
                            Ok(InterceptDecision::Drop) => continue,
                            Ok(InterceptDecision::Forward(modified)) => {
                                if !modified.is_empty() {
                                    // Could parse modified response here
                                }
                            }
                            Err(_) => continue,
                        }
                    }

                    // Send response back to client through TLS
                    let mut raw_resp = format!("HTTP/1.1 {}\r\n", status);
                    for (k, v) in &resp_headers {
                        if k.eq_ignore_ascii_case("transfer-encoding") { continue; }
                        raw_resp.push_str(&format!("{}: {}\r\n", k, v));
                    }
                    raw_resp.push_str(&format!("Content-Length: {}\r\n\r\n", resp_body.len()));
                    writer.write_all(raw_resp.as_bytes()).await?;
                    writer.write_all(&resp_body).await?;
                    writer.flush().await?;

                    let mime = resp_headers.iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                        .map(|(_, v)| v.clone()).unwrap_or_default();

                    self.state.add_traffic(TrafficEntry {
                        id: self.state.next_id(), timestamp: chrono::Utc::now().to_rfc3339(),
                        method, url, host: host.clone(), path, port, tls: true, status,
                        response_length: resp_body.len(), response_time_ms: elapsed,
                        mime_type: mime,
                        request_headers: headers_str,
                        request_body: body_str,
                        response_headers: resp_headers_str,
                        response_body: String::from_utf8_lossy(&resp_body).to_string(),
                        source: "proxy".into(), notes: String::new(), color: String::new(),
                    }).await;
                }
                Err(e) => {
                    let err_msg = format!("502 - {}", e);
                    let err_resp = format!("HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\n\r\n{}", err_msg.len(), err_msg);
                    writer.write_all(err_resp.as_bytes()).await?;
                    writer.flush().await?;
                }
            }
        }
        Ok(())
    }

    /// Handle plain HTTP proxy requests.
    async fn handle_http(
        &self, mut stream: TcpStream, method: &str, target_url: &str,
        raw_headers: &str, body: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut url = if target_url.starts_with("http") { target_url.to_string() } else { format!("http://{}", target_url) };
        let parsed = url.parse::<http::Uri>()?;
        let host = parsed.host().unwrap_or("unknown").to_string();
        let port = parsed.port_u16().unwrap_or(80);
        let path = parsed.path_and_query().map(|p| p.to_string()).unwrap_or_else(|| "/".into());

        let header_map: Vec<(String, String)> = raw_headers.lines().skip(1)
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
            .collect();

        let mut body_str = String::from_utf8_lossy(body).to_string();
        let mut headers_str = raw_headers.to_string();

        // Apply Match & Replace to request
        self.state.apply_match_replace_request(&mut headers_str, &mut body_str, &mut url).await;

        // Intercept check with rules
        if self.state.should_intercept_request(method, &url, &host, &headers_str).await {
            let item = InterceptedItem {
                id: uuid::Uuid::new_v4().to_string(),
                method: method.to_string(), url: url.clone(), host: host.clone(),
                raw_request: headers_str.to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                is_response: false,
                status: None,
                raw_response: None,
            };
            let (tx, rx) = oneshot::channel();
            self.state.add_intercept(PendingIntercept { item, sender: tx }).await;
            match rx.await {
                Ok(InterceptDecision::Drop) => {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nDropped").await?;
                    return Ok(());
                }
                Ok(InterceptDecision::Forward(_)) => {}
                Err(_) => return Ok(()),
            }
        }

        let start = Instant::now();
        let result = self.forward_request(method, &url, &header_map, body_str.as_bytes()).await;
        let elapsed = start.elapsed().as_millis() as u64;

        match result {
            Ok((status, resp_headers, mut resp_body)) => {
                // Apply Match & Replace to response
                let mut resp_headers_str = resp_headers.iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect::<Vec<_>>().join("\r\n");
                self.state.apply_match_replace_response(&mut resp_headers_str, &mut resp_body).await;

                // Response interception
                if self.state.should_intercept_response(&url, &host, status, &resp_headers_str).await {
                    let resp_item = InterceptedItem {
                        id: uuid::Uuid::new_v4().to_string(),
                        method: method.to_string(), url: url.clone(), host: host.clone(),
                        raw_request: headers_str.clone(),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        is_response: true,
                        status: Some(status),
                        raw_response: Some(format!("HTTP/1.1 {}\r\n{}\r\n\r\n{}",
                            status, resp_headers_str, String::from_utf8_lossy(&resp_body))),
                    };
                    let (tx, rx) = oneshot::channel();
                    self.state.add_intercept(PendingIntercept { item: resp_item, sender: tx }).await;
                    match rx.await {
                        Ok(InterceptDecision::Drop) => {
                            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nDropped").await?;
                            return Ok(());
                        }
                        Ok(InterceptDecision::Forward(_)) => {}
                        Err(_) => return Ok(()),
                    }
                }

                // Re-parse headers after match & replace
                let final_resp_headers: Vec<(String, String)> = resp_headers_str.lines()
                    .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
                    .collect();

                let mut raw_resp = format!("HTTP/1.1 {}\r\n", status);
                for (k, v) in &final_resp_headers {
                    if k.eq_ignore_ascii_case("transfer-encoding") { continue; }
                    raw_resp.push_str(&format!("{}: {}\r\n", k, v));
                }
                raw_resp.push_str(&format!("Content-Length: {}\r\n\r\n", resp_body.len()));
                stream.write_all(raw_resp.as_bytes()).await?;
                stream.write_all(&resp_body).await?;

                let mime = final_resp_headers.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.clone()).unwrap_or_default();

                self.state.add_traffic(TrafficEntry {
                    id: self.state.next_id(), timestamp: chrono::Utc::now().to_rfc3339(),
                    method: method.to_string(), url, host, path, port, tls: false, status,
                    response_length: resp_body.len(), response_time_ms: elapsed,
                    mime_type: mime,
                    request_headers: headers_str, request_body: body_str,
                    response_headers: resp_headers_str,
                    response_body: String::from_utf8_lossy(&resp_body).to_string(),
                    source: "proxy".into(), notes: String::new(), color: String::new(),
                }).await;
            }
            Err(e) => {
                let msg = format!("502 - {}", e);
                stream.write_all(format!("HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\n\r\n{}", msg.len(), msg).as_bytes()).await?;
            }
        }
        Ok(())
    }

    /// Forward HTTP request via reqwest.
    async fn forward_request(
        &self, method: &str, url: &str, headers: &[(String, String)], body: &[u8],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        let m = method.parse::<reqwest::Method>()?;
        let client = self.build_upstream_client().await;
        let mut b = client.request(m, url);

        for (k, v) in headers {
            let lower = k.to_lowercase();
            if ["proxy-connection", "connection", "keep-alive", "proxy-authenticate",
                "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host"]
                .contains(&lower.as_str()) { continue; }
            b = b.header(k.as_str(), v.as_str());
        }

        if !body.is_empty() { b = b.body(body.to_vec()); }

        let resp = b.send().await?;
        let status = resp.status().as_u16();
        let hdrs: Vec<(String, String)> = resp.headers().iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string())).collect();
        let body = resp.bytes().await?.to_vec();
        Ok((status, hdrs, body))
    }


    /// Fully parse a modified raw HTTP request from the intercept editor.
    /// Reconstructs method, path, headers, and body from user-edited text.
    fn parse_modified_request_full(raw: &str) -> Option<ParsedModifiedRequest> {
        let mut lines = raw.lines();
        let first = lines.next()?.trim();
        let parts: Vec<&str> = first.split_whitespace().collect();
        if parts.len() < 2 { return None; }

        let method = parts[0].to_string();
        let url_path = parts[1].to_string();

        let mut headers = Vec::new();
        let mut in_body = false;
        let mut body_lines = Vec::new();

        for line in lines {
            if in_body {
                body_lines.push(line);
            } else if line.trim().is_empty() {
                in_body = true;
            } else {
                headers.push(line.to_string());
            }
        }

        Some(ParsedModifiedRequest {
            method,
            url_path,
            headers_raw: headers.join("\r\n"),
            body: body_lines.join("\n"),
        })
    }

    /// Legacy header parser (kept for compatibility).
    fn parse_modified_request(raw: &str) -> Option<Vec<(String, String)>> {
        let mut headers = Vec::new();
        for line in raw.lines().skip(1) {
            let trimmed = line.trim();
            if trimmed.is_empty() { break; }
            if let Some((k, v)) = trimmed.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        if headers.is_empty() { None } else { Some(headers) }
    }

    /// Raw TCP tunnel (non-MITM fallback for CONNECT or TLS pass-through).
    async fn tcp_tunnel(&self, mut client: TcpStream, host: &str, port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut server = TcpStream::connect(format!("{}:{}", host, port)).await?;
        let (mut cr, mut cw) = client.split();
        let (mut sr, mut sw) = server.split();
        tokio::select! {
            _ = tokio::io::copy(&mut cr, &mut sw) => {}
            _ = tokio::io::copy(&mut sr, &mut cw) => {}
        }
        Ok(())
    }
}

fn parse_host_port(target: &str, default_port: u16) -> (String, u16) {
    if let Some((host, port_str)) = target.rsplit_once(':') {
        (host.to_string(), port_str.parse().unwrap_or(default_port))
    } else {
        (target.to_string(), default_port)
    }
}
