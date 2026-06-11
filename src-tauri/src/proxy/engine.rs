use crate::proxy::ca::ProxyCa;
use crate::proxy::state::*;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// Maximum size of HTTP headers (64 KB)
const MAX_HEADER_SIZE: usize = 65_536;

/// Idle timeout for keep-alive connections (seconds)
const KEEPALIVE_IDLE_TIMEOUT_SECS: u64 = 120;

/// Timeout for reading the initial request line (seconds)
const INITIAL_READ_TIMEOUT_SECS: u64 = 30;

/// Maximum body size for chunked reads (32 MB)
const MAX_CHUNKED_BODY: usize = 32 * 1024 * 1024;

/// A parsed HTTP request read off the wire.
struct WireRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    headers_raw: String,
    body: Vec<u8>,
    is_websocket_upgrade: bool,
}

/// Parsed modified request from the intercept editor.
struct ParsedModifiedRequest {
    method: String,
    url_path: String,
    headers: Vec<(String, String)>,
    headers_raw: String,
    body: Vec<u8>,
}

/// The main MITM proxy engine.
///
/// Handles:
/// - HTTP proxy (explicit, with absolute URLs)
/// - HTTPS MITM (via CONNECT tunnel + TLS interception with per-host RSA certs)
/// - Invisible proxying (relative paths + Host header reconstruction)
/// - HTTP/1.1 keep-alive (persistent connections inside TLS tunnels)
/// - Chunked transfer encoding
/// - WebSocket upgrade detection and tunneling
/// - Request/response interception with modification
/// - Match & Replace rules
/// - TLS pass-through (bypass MITM for configured hosts)
/// - Upstream proxy support (HTTP/SOCKS5)
pub struct ProxyEngine {
    ca: Arc<ProxyCa>,
    state: Arc<ProxyState>,
    http_client: reqwest::Client,
    /// Chrome-fingerprint-spoofing client. Used when `state.tls_impersonate`
    /// is true so the upstream JA3/JA4 + HTTP/2 frame signature looks like
    /// real Chrome instead of native-tls / SChannel. Linux falls back to
    /// reqwest because boring-sys2 collides with system OpenSSL at link time.
    #[cfg(not(target_os = "linux"))]
    impersonate_client: crate::tls_impersonate::ImpersonateClient,
    cancel: CancellationToken,
}

impl ProxyEngine {
    pub fn new(ca: Arc<ProxyCa>, state: Arc<ProxyState>, cancel: CancellationToken) -> Self {
        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("Failed to build HTTP client");

        #[cfg(not(target_os = "linux"))]
        let impersonate_client = crate::tls_impersonate::ImpersonateClient::new(
            crate::tls_impersonate::ImpersonateProfile::Chrome137,
        )
        .unwrap_or_else(|e| {
            eprintln!(
                "[Proxy] TLS impersonation client init failed: {} — falling back to native TLS only",
                e
            );
            crate::tls_impersonate::ImpersonateClient::new(
                crate::tls_impersonate::ImpersonateProfile::Chrome137,
            )
            .expect("impersonate client second build")
        });

        #[cfg(not(target_os = "linux"))]
        let s = Self { ca, state, http_client, impersonate_client, cancel };
        #[cfg(target_os = "linux")]
        let s = Self { ca, state, http_client, cancel };
        s
    }

    /// Build an HTTP client that routes through an upstream proxy.
    async fn build_upstream_client(&self) -> reqwest::Client {
        let cfg = self.state.upstream_proxy.read().await;
        if !cfg.enabled || cfg.host.is_empty() {
            return self.http_client.clone();
        }

        let proxy_url = format!("{}://{}:{}", cfg.proxy_type, cfg.host, cfg.port);
        let proxy = match reqwest::Proxy::all(&proxy_url) {
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

    /// Start the proxy on the given listener.
    pub async fn run(
        self: Arc<Self>,
        listener: TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let port = listener.local_addr()?.port();
        self.state.running.store(true, std::sync::atomic::Ordering::SeqCst);
        *self.state.proxy_port.lock().await = port;
        println!("[Proxy] ✓ Listening on 127.0.0.1:{}", port);

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    println!("[Proxy] Shutdown signal received");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let engine = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = engine.handle_connection(stream).await {
                                    let msg = e.to_string();
                                    if !is_benign_error(&msg) {
                                        eprintln!("[Proxy] Connection error from {}: {}", addr, msg);
                                    }
                                }
                            });
                        }
                        Err(e) => eprintln!("[Proxy] Accept error: {}", e),
                    }
                }
            }
        }

        self.state.running.store(false, std::sync::atomic::Ordering::SeqCst);
        println!("[Proxy] Stopped cleanly, port released");
        Ok(())
    }

    /// Handle a single incoming client connection.
    async fn handle_connection(
        &self,
        stream: TcpStream,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _ = stream.set_nodelay(true);

        let mut buf = BufReader::with_capacity(8192, stream);

        let mut first_line = String::new();
        let n = tokio::time::timeout(
            tokio::time::Duration::from_secs(INITIAL_READ_TIMEOUT_SECS),
            buf.read_line(&mut first_line),
        )
        .await
        .map_err(|_| "Initial read timeout")??;

        if n == 0 || first_line.trim().is_empty() {
            return Ok(());
        }

        let first_line = first_line.trim().to_string();
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Ok(());
        }

        let method = parts[0].to_uppercase();
        let target = parts[1].to_string();

        let mut content_length: usize = 0;
        let mut host_header = String::new();
        let mut is_chunked = false;
        let mut total_header_bytes = first_line.len();
        let mut header_pairs: Vec<(String, String)> = Vec::new();
        let mut headers_raw = String::new();

        loop {
            let mut line = String::new();
            buf.read_line(&mut line).await?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }

            total_header_bytes += line.len();
            if total_header_bytes > MAX_HEADER_SIZE {
                return Err("Headers too large".into());
            }

            headers_raw.push_str(trimmed);
            headers_raw.push_str("\r\n");

            if let Some((key, value)) = trimmed.split_once(':') {
                let k = key.trim().to_string();
                let v = value.trim().to_string();
                let lower = k.to_lowercase();

                if lower == "content-length" {
                    content_length = v.parse().unwrap_or(0);
                }
                if lower == "host" {
                    host_header = v.clone();
                }
                if lower == "transfer-encoding" && v.to_lowercase().contains("chunked") {
                    is_chunked = true;
                }

                header_pairs.push((k, v));
            }
        }

        if method == "CONNECT" {
            let stream = buf.into_inner();
            self.handle_connect(stream, &target).await
        } else {
            let max_body = self.state.max_response_size.load(std::sync::atomic::Ordering::SeqCst) as usize;
            let body = if is_chunked {
                read_chunked_body(&mut buf, max_body).await?
            } else if content_length > 0 {
                let read_len = content_length.min(max_body);
                let mut body = vec![0u8; read_len];
                buf.read_exact(&mut body).await?;
                body
            } else {
                Vec::new()
            };

            let mut stream = buf.into_inner();

            let full_url = if target.starts_with("http://") || target.starts_with("https://") {
                target.clone()
            } else if !host_header.is_empty() {
                format!("http://{}{}", host_header, target)
            } else {
                target.clone()
            };

            self.handle_http_request(
                &mut stream,
                &method,
                &full_url,
                &headers_raw,
                &header_pairs,
                &body,
                false,
            )
            .await
        }
    }

    /// Handle CONNECT tunnel — either TLS pass-through or full MITM.
    async fn handle_connect(
        &self,
        mut stream: TcpStream,
        target: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (host, port) = parse_host_port(target, 443);

        if self.state.is_tls_passthrough(&host, port).await {
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            stream.flush().await?;
            return self.tcp_tunnel(stream, &host, port).await;
        }

        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        stream.flush().await?;

        let identity = match self.ca.generate_identity(&host) {
            Ok(id) => id,
            Err(e) => {
                eprintln!(
                    "[Proxy] TLS cert generation failed for {}: {}. Falling back to TCP tunnel.",
                    host, e
                );
                return self.tcp_tunnel(stream, &host, port).await;
            }
        };

        let tls_acceptor = match native_tls::TlsAcceptor::builder(identity).build() {
            Ok(a) => tokio_native_tls::TlsAcceptor::from(a),
            Err(e) => {
                eprintln!("[Proxy] TLS acceptor build failed for {}: {}", host, e);
                return self.tcp_tunnel(stream, &host, port).await;
            }
        };

        let tls_stream = match tls_acceptor.accept(stream).await {
            Ok(s) => s,
            Err(e) => {
                let msg = e.to_string();
                if !is_benign_error(&msg) {
                    eprintln!("[Proxy] TLS handshake failed for {}: {}", host, msg);
                }
                return Ok(());
            }
        };

        let (reader, mut writer) = tokio::io::split(tls_stream);
        let mut buf_reader = BufReader::with_capacity(8192, reader);

        loop {
            let request = tokio::time::timeout(
                tokio::time::Duration::from_secs(KEEPALIVE_IDLE_TIMEOUT_SECS),
                read_wire_request(&mut buf_reader),
            )
            .await;

            let request = match request {
                Ok(Ok(Some(req))) => req,
                Ok(Ok(None)) => break, // Connection closed
                Ok(Err(_)) => break,   // Parse error
                Err(_) => break,       // Idle timeout
            };

            // v0.3.35: a WebSocket upgrade takes over the whole connection. Hand
            // BOTH halves to the relay (which holds it open and captures every
            // frame) instead of the old detection-only stub that forwarded the
            // handshake and then dropped all frames.
            if request.is_websocket_upgrade {
                if let Err(e) = self.relay_websocket(buf_reader, writer, &host, port, request).await {
                    let msg = e.to_string();
                    if !is_benign_error(&msg) {
                        eprintln!("[Proxy] WebSocket relay error for {}: {}", host, msg);
                    }
                }
                return Ok(());
            }

            let should_continue = self.process_tunneled_request(&mut writer, &host, port, request).await;

            match should_continue {
                Ok(true) => continue,
                Ok(false) => break,
                Err(e) => {
                    let msg = e.to_string();
                    if !is_benign_error(&msg) {
                        eprintln!("[Proxy] MITM request error for {}: {}", host, msg);
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    /// Process a single request inside a TLS tunnel.
    /// Returns `true` if the keep-alive loop should continue.
    async fn process_tunneled_request<W: AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
        host: &str,
        port: u16,
        request: WireRequest,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let method = request.method.clone();
        let path = request.path.clone();
        let headers = request.headers.clone();
        let mut headers_raw = request.headers_raw.clone();
        let mut body = request.body.clone();
        let mut body_str = String::from_utf8_lossy(&body).to_string();

        let mut url = if port == 443 {
            format!("https://{}{}", host, path)
        } else {
            format!("https://{}:{}{}", host, port, path)
        };

        self.state.apply_match_replace_request(&mut headers_raw, &mut body_str, &mut url).await;

        if body_str != String::from_utf8_lossy(&body) {
            body = body_str.as_bytes().to_vec();
        }

        let raw_request = format!(
            "{} {} HTTP/1.1\r\n{}{}",
            method,
            path,
            headers_raw,
            if body.is_empty() { String::new() } else { format!("\r\n{}", body_str) }
        );

        // NOTE: WebSocket upgrades are intercepted earlier, in `handle_connect`,
        // which hands both stream halves to `relay_websocket`. They never reach
        // this point.

        let mut final_method = method.clone();
        let mut final_url = url.clone();
        let mut final_headers_raw = headers_raw.clone();
        let mut final_body_str = body_str.clone();
        let mut final_headers = headers.clone();
        let mut final_body = body.clone();

        if self.state.should_intercept_request(&method, &url, host, &headers_raw).await {
            let item = InterceptedItem {
                id: uuid::Uuid::new_v4().to_string(),
                method: method.clone(),
                url: url.clone(),
                host: host.to_string(),
                raw_request: raw_request.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                is_response: false,
                status: None,
                raw_response: None,
            };
            let (tx, rx) = oneshot::channel();
            self.state.add_intercept(PendingIntercept { item, sender: tx }).await;

            match rx.await {
                Ok(InterceptDecision::Drop) => return Ok(true),
                Ok(InterceptDecision::Forward(modified)) => {
                    if !modified.is_empty() {
                        if let Some(parsed) = parse_modified_request(&modified) {
                            final_method = parsed.method;
                            final_headers_raw = parsed.headers_raw;
                            final_body_str = String::from_utf8_lossy(&parsed.body).to_string();
                            final_body = parsed.body;
                            final_headers = parsed.headers;
                            if !parsed.url_path.is_empty() {
                                let port_str = if port == 443 { String::new() } else { format!(":{}", port) };
                                final_url = format!("https://{}{}{}", host, port_str, parsed.url_path);
                            }
                        }
                    }
                }
                Err(_) => return Ok(true),
            }
        }

        let start = Instant::now();
        let result = self.forward_request(&final_method, &final_url, &final_headers, &final_body).await;
        let elapsed = start.elapsed().as_millis() as u64;

        match result {
            Ok((status, resp_headers, resp_body)) => {
                self.process_response(
                    writer,
                    status,
                    resp_headers,
                    resp_body,
                    &final_method,
                    &final_url,
                    host,
                    &path,
                    port,
                    true,
                    elapsed,
                    &final_headers_raw,
                    &final_body_str,
                    &raw_request,
                )
                .await?;
            }
            Err(e) => {
                let err_msg = format!("502 - {}", e);
                let err_resp = format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\n\r\n{}",
                    err_msg.len(),
                    err_msg
                );
                writer.write_all(err_resp.as_bytes()).await?;
                writer.flush().await?;
            }
        }

        let conn_close = request
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"));

        Ok(!conn_close)
    }

    /// Handle a plain HTTP proxy request.
    async fn handle_http_request(
        &self,
        stream: &mut TcpStream,
        method: &str,
        target_url: &str,
        headers_raw: &str,
        _header_pairs: &[(String, String)],
        body: &[u8],
        is_tls: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut url = if target_url.starts_with("http") {
            target_url.to_string()
        } else {
            format!("http://{}", target_url)
        };

        let parsed = url.parse::<http::Uri>()?;
        let host = parsed.host().unwrap_or("unknown").to_string();
        let port = parsed.port_u16().unwrap_or(if is_tls { 443 } else { 80 });
        let path = parsed.path_and_query().map(|p| p.to_string()).unwrap_or_else(|| "/".into());

        let mut body_str = String::from_utf8_lossy(body).to_string();
        let mut headers_str = headers_raw.to_string();
        let mut method = method.to_string();

        self.state.apply_match_replace_request(&mut headers_str, &mut body_str, &mut url).await;

        if self.state.should_intercept_request(&method, &url, &host, &headers_str).await {
            let raw_request = format!(
                "{} {} HTTP/1.1\r\n{}{}\r\n",
                method,
                path,
                headers_str.lines().collect::<Vec<_>>().join("\r\n"),
                if body_str.is_empty() { String::new() } else { format!("\r\n{}", body_str) }
            );

            let item = InterceptedItem {
                id: uuid::Uuid::new_v4().to_string(),
                method: method.clone(),
                url: url.clone(),
                host: host.clone(),
                raw_request,
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
                Ok(InterceptDecision::Forward(modified)) => {
                    if !modified.is_empty() {
                        if let Some(parsed) = parse_modified_request(&modified) {
                            method = parsed.method;
                            headers_str = parsed.headers_raw;
                            body_str = String::from_utf8_lossy(&parsed.body).to_string();
                            if !parsed.url_path.is_empty() {
                                let port_str = if port == 80 { String::new() } else { format!(":{}", port) };
                                url = format!("http://{}{}{}", host, port_str, parsed.url_path);
                            }
                        }
                    }
                }
                Err(_) => return Ok(()),
            }
        }

        let header_map: Vec<(String, String)> = headers_str
            .lines()
            .filter(|l| !l.trim().is_empty() && l.contains(':'))
            .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
            .collect();

        let start = Instant::now();
        let result = self.forward_request(&method, &url, &header_map, body_str.as_bytes()).await;
        let elapsed = start.elapsed().as_millis() as u64;

        let raw_request_log = format!("{} {} HTTP/1.1\r\n{}", method, path, headers_str);

        match result {
            Ok((status, resp_headers, resp_body)) => {
                self.process_response(
                    stream,
                    status,
                    resp_headers,
                    resp_body,
                    &method,
                    &url,
                    &host,
                    &path,
                    port,
                    is_tls,
                    elapsed,
                    &headers_str,
                    &body_str,
                    &raw_request_log,
                )
                .await?;
            }
            Err(e) => {
                let msg = format!("502 - {}", e);
                stream
                    .write_all(
                        format!("HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\n\r\n{}", msg.len(), msg)
                            .as_bytes(),
                    )
                    .await?;
            }
        }

        Ok(())
    }

    /// Process response: Match & Replace → Intercept → Write → Log
    async fn process_response<W: AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
        status: u16,
        resp_headers: Vec<(String, String)>,
        mut resp_body: Vec<u8>,
        method: &str,
        url: &str,
        host: &str,
        path: &str,
        port: u16,
        tls: bool,
        elapsed_ms: u64,
        request_headers: &str,
        request_body: &str,
        raw_request: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut resp_headers_str =
            resp_headers.iter().map(|(k, v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join("\r\n");
        self.state.apply_match_replace_response(&mut resp_headers_str, &mut resp_body).await;

        let mut final_headers: Vec<(String, String)> = resp_headers_str
            .lines()
            .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
            .collect();

        if self.state.should_intercept_response(url, host, status, &resp_headers_str).await {
            let resp_item = InterceptedItem {
                id: uuid::Uuid::new_v4().to_string(),
                method: method.to_string(),
                url: url.to_string(),
                host: host.to_string(),
                raw_request: raw_request.to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                is_response: true,
                status: Some(status),
                raw_response: Some(format!(
                    "HTTP/1.1 {}\r\n{}\r\n\r\n{}",
                    status,
                    resp_headers_str,
                    String::from_utf8_lossy(&resp_body)
                )),
            };
            let (tx, rx) = oneshot::channel();
            self.state.add_intercept(PendingIntercept { item: resp_item, sender: tx }).await;

            match rx.await {
                Ok(InterceptDecision::Drop) => {
                    writer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nDropped").await?;
                    writer.flush().await?;
                    return Ok(());
                }
                Ok(InterceptDecision::Forward(modified)) => {
                    if !modified.is_empty() {
                        if let Some((_s, new_headers, new_body)) = parse_modified_response(&modified) {
                            final_headers = new_headers;
                            resp_body = new_body.into_bytes();
                            resp_headers_str = final_headers
                                .iter()
                                .map(|(k, v)| format!("{}: {}", k, v))
                                .collect::<Vec<_>>()
                                .join("\r\n");
                        }
                    }
                }
                Err(_) => {} // forward original
            }
        }

        let mut raw_resp = format!("HTTP/1.1 {}\r\n", status);
        for (k, v) in &final_headers {
            let lower = k.to_lowercase();
            if lower == "transfer-encoding" || lower == "content-encoding" || lower == "content-length" {
                continue;
            }
            raw_resp.push_str(&format!("{}: {}\r\n", k, v));
        }
        raw_resp.push_str(&format!("Content-Length: {}\r\n\r\n", resp_body.len()));

        writer.write_all(raw_resp.as_bytes()).await?;
        writer.write_all(&resp_body).await?;
        writer.flush().await?;

        let mime = final_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        const MAX_STORED_BODY: usize = 65_536; // 64KB
        let stored_body = if resp_body.len() > MAX_STORED_BODY {
            let truncated = String::from_utf8_lossy(&resp_body[..MAX_STORED_BODY]);
            format!("{}… [truncated, {} bytes total]", truncated, resp_body.len())
        } else {
            String::from_utf8_lossy(&resp_body).to_string()
        };

        self.state
            .add_traffic(TrafficEntry {
                id: self.state.next_id(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                method: method.to_string(),
                url: url.to_string(),
                host: host.to_string(),
                path: path.to_string(),
                port,
                tls,
                status,
                response_length: resp_body.len(),
                response_time_ms: elapsed_ms,
                mime_type: mime,
                request_headers: request_headers.to_string(),
                request_body: request_body.to_string(),
                response_headers: resp_headers_str,
                response_body: stored_body,
                source: "proxy".into(),
                notes: String::new(),
                color: String::new(),
            })
            .await;

        Ok(())
    }

    /// Forward request to real server via reqwest.
    async fn forward_request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        // Branch on the impersonation toggle. wreq matches Chrome's JA3/JA4
        // + HTTP/2 fingerprint; reqwest leaks the platform native-tls one.
        // Linux falls back to reqwest because boring-sys2 collides with the
        // system OpenSSL link.
        #[cfg(not(target_os = "linux"))]
        {
            let use_impersonate = self.state.tls_impersonate.load(std::sync::atomic::Ordering::Relaxed);
            if use_impersonate {
                let upstream_for_wreq = {
                    let cfg = self.state.upstream_proxy.read().await;
                    if cfg.enabled && !cfg.host.is_empty() {
                        Some(crate::tls_impersonate::ImpersonateUpstreamProxy {
                            scheme: cfg.proxy_type.clone(),
                            host: cfg.host.clone(),
                            port: cfg.port,
                            username: cfg.username.clone(),
                            password: cfg.password.clone(),
                        })
                    } else {
                        None
                    }
                };
                if let Err(e) = self.impersonate_client.set_upstream(upstream_for_wreq).await {
                    eprintln!("[Proxy] wreq upstream proxy update failed: {} — falling through", e);
                } else {
                    return self.forward_via_impersonate(method, url, headers, body).await;
                }
            }
        }

        let m = method
            .parse::<reqwest::Method>()
            .map_err(|e| format!("Invalid HTTP method '{}': {}", method, e))?;

        let client = self.build_upstream_client().await;
        let mut builder = client.request(m, url);

        for (k, v) in headers {
            let lower = k.to_lowercase();
            if HOP_BY_HOP_HEADERS.contains(&lower.as_str()) {
                continue;
            }
            builder = builder.header(k.as_str(), v.as_str());
        }

        if !body.is_empty() {
            builder = builder.body(body.to_vec());
        }

        let resp = builder.send().await?;
        let status = resp.status().as_u16();
        let hdrs: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let resp_body = resp.bytes().await?.to_vec();

        Ok((status, hdrs, resp_body))
    }

    /// Same as `forward_request` but uses wreq with the Chrome JA3/JA4
    /// emulation profile. Not compiled on Linux (boring-sys2 collides with
    /// system OpenSSL there).
    #[cfg(not(target_os = "linux"))]
    async fn forward_via_impersonate(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        let m =
            method.parse::<wreq::Method>().map_err(|e| format!("Invalid HTTP method '{}': {}", method, e))?;

        // App-level retry-once on transient h2 errors. wreq has its own
        // `http2_max_retry_count(2)` but doesn't retry every variant of
        // "stream error received: unspecific protocol error" we see in the
        // wild — particularly after a server-initiated GOAWAY mid-handshake.
        // A second attempt almost always succeeds because the stale pooled
        // connection got evicted by the first failure.
        let attempts = 2;
        let mut last_err: Option<wreq::Error> = None;
        for attempt in 0..attempts {
            let client = self.impersonate_client.client().await;
            let mut builder = client.request(m.clone(), url);

            for (k, v) in headers {
                let lower = k.to_lowercase();
                if HOP_BY_HOP_HEADERS.contains(&lower.as_str()) {
                    continue;
                }
                builder = builder.header(k.as_str(), v.as_str());
            }

            if !body.is_empty() {
                builder = builder.body(body.to_vec());
            }

            match builder.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let hdrs: Vec<(String, String)> = resp
                        .headers()
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect();
                    return match resp.bytes().await {
                        Ok(b) => Ok((status, hdrs, b.to_vec())),
                        Err(e) => Err(wreq_err_chain("body", &e).into()),
                    };
                }
                Err(e) => {
                    let chain = wreq_err_chain("send", &e);
                    let is_h2_transient = is_h2_transient_error(&chain);
                    if is_h2_transient && attempt + 1 < attempts {
                        // Pause briefly so the next request doesn't race the
                        // pool eviction triggered by this failure.
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        last_err = Some(e);
                        continue;
                    }
                    return Err(chain.into());
                }
            }
        }

        // Unreachable in practice — the loop either returns Ok or Err on the
        // final iteration. Surface the last error just in case.
        Err(last_err
            .map(|e| wreq_err_chain("send", &e))
            .unwrap_or_else(|| "forward_via_impersonate: exhausted retries".into())
            .into())
    }

    /// v0.3.35: full WebSocket frame relay for the MITM proxy.
    ///
    /// Replaces the old detection-only stub (which forwarded the handshake via a
    /// one-shot HTTP call and then dropped every frame). After the client's
    /// upgrade request we open a real upstream TLS connection, replay the
    /// handshake, forward the `101 Switching Protocols` response to the client,
    /// then relay every frame in both directions *byte-for-byte* — sniffing a
    /// copy of each direction to log frames (opcode + direction + unmasked text)
    /// into the proxy's WebSocket pool. Forwarding is verbatim, so the tunnel is
    /// never corrupted; parsing is best-effort, for visibility only. Scope for
    /// 0.3.35 is capture/observe (no frame editing / hold / match-replace).
    async fn relay_websocket<R, W>(
        &self,
        mut client_reader: R,
        mut client_writer: W,
        host: &str,
        port: u16,
        request: WireRequest,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        let connection_id = uuid::Uuid::new_v4().to_string();
        let url = if port == 443 {
            format!("wss://{}{}", host, request.path)
        } else {
            format!("wss://{}:{}{}", host, port, request.path)
        };

        // Reconstruct the verbatim upgrade request: request line + headers + the
        // blank-line terminator. `headers_raw` already ends each header with CRLF
        // but omits the final blank line.
        let upgrade_req =
            format!("{} {} HTTP/1.1\r\n{}\r\n", request.method, request.path, request.headers_raw);

        self.state
            .add_websocket_message(WebSocketMessage {
                id: self.state.next_id(),
                connection_id: connection_id.clone(),
                direction: "client_to_server".into(),
                opcode: "upgrade".into(),
                data: upgrade_req.clone(),
                length: upgrade_req.len(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                host: host.to_string(),
                url: url.clone(),
            })
            .await;

        // Open the upstream TLS connection (this is the CONNECT / HTTPS path).
        let tcp = TcpStream::connect((host, port)).await?;
        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()?;
        let connector = tokio_native_tls::TlsConnector::from(connector);
        let upstream = connector.connect(host, tcp).await?;
        let (mut up_read, mut up_write) = tokio::io::split(upstream);

        // Replay the handshake upstream.
        up_write.write_all(upgrade_req.as_bytes()).await?;
        up_write.flush().await?;

        // Read the upstream response head (up to CRLF CRLF) and forward it to the
        // client so the browser sees a real 101 Switching Protocols.
        let mut resp_head = Vec::new();
        let mut one = [0u8; 1];
        loop {
            let n = up_read.read(&mut one).await?;
            if n == 0 {
                break;
            }
            resp_head.push(one[0]);
            if resp_head.ends_with(b"\r\n\r\n") {
                break;
            }
            if resp_head.len() > MAX_HEADER_SIZE {
                return Err("WebSocket upstream response headers too large".into());
            }
        }
        client_writer.write_all(&resp_head).await?;
        client_writer.flush().await?;

        let resp_head_str = String::from_utf8_lossy(&resp_head).to_string();
        self.state
            .add_websocket_message(WebSocketMessage {
                id: self.state.next_id(),
                connection_id: connection_id.clone(),
                direction: "server_to_client".into(),
                opcode: "upgrade".into(),
                data: resp_head_str.clone(),
                length: resp_head_str.len(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                host: host.to_string(),
                url: url.clone(),
            })
            .await;

        // Relay both directions until either side closes.
        let c2s = self.relay_ws_direction(
            &mut client_reader,
            &mut up_write,
            "client_to_server",
            &connection_id,
            host,
            &url,
        );
        let s2c = self.relay_ws_direction(
            &mut up_read,
            &mut client_writer,
            "server_to_client",
            &connection_id,
            host,
            &url,
        );
        tokio::select! {
            _ = c2s => {}
            _ = s2c => {}
        }

        Ok(())
    }

    /// Relay one direction of a WebSocket stream: forward bytes verbatim, then
    /// sniff a copy to log each complete frame it can parse.
    async fn relay_ws_direction<R, W>(
        &self,
        from: &mut R,
        to: &mut W,
        direction: &str,
        connection_id: &str,
        host: &str,
        url: &str,
    ) -> std::io::Result<()>
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        let mut sniff: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = from.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            // Forward verbatim FIRST — the tunnel must never depend on our
            // ability to parse a frame.
            to.write_all(&chunk[..n]).await?;
            to.flush().await?;

            sniff.extend_from_slice(&chunk[..n]);
            let (frames, consumed) = parse_ws_frames(&sniff);
            for f in frames {
                let (data, length) = render_ws_frame(&f);
                self.state
                    .add_websocket_message(WebSocketMessage {
                        id: self.state.next_id(),
                        connection_id: connection_id.to_string(),
                        direction: direction.to_string(),
                        opcode: ws_opcode_name(f.opcode).to_string(),
                        data,
                        length,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        host: host.to_string(),
                        url: url.to_string(),
                    })
                    .await;
            }
            if consumed > 0 {
                sniff.drain(0..consumed);
            }
            // Bound memory if we're mid-way through an implausibly large frame.
            if sniff.len() > 1_048_576 {
                sniff.clear();
            }
        }
        Ok(())
    }

    async fn tcp_tunnel(
        &self,
        mut client: TcpStream,
        host: &str,
        port: u16,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut server = TcpStream::connect(format!("{}:{}", host, port)).await?;
        let (mut cr, mut cw) = client.split();
        let (mut sr, mut sw) = server.split();

        tokio::select! {
            r = tokio::io::copy(&mut cr, &mut sw) => {
                if let Err(e) = r { if !is_benign_error(&e.to_string()) { eprintln!("[Proxy] Tunnel C→S: {}", e); } }
            }
            r = tokio::io::copy(&mut sr, &mut cw) => {
                if let Err(e) = r { if !is_benign_error(&e.to_string()) { eprintln!("[Proxy] Tunnel S→C: {}", e); } }
            }
        }

        Ok(())
    }
}

// ── WebSocket frame sniffing (v0.3.35) ──────────────────────────────────────
//
// These parse RFC 6455 frames purely for logging. The proxy forwards the raw
// bytes verbatim, so a parse failure can never corrupt the tunnel.

/// A WebSocket frame with its payload already unmasked, captured for display.
struct ParsedWsFrame {
    opcode: u8,
    payload: Vec<u8>,
}

fn ws_opcode_name(op: u8) -> &'static str {
    match op {
        0x0 => "continuation",
        0x1 => "text",
        0x2 => "binary",
        0x8 => "close",
        0x9 => "ping",
        0xA => "pong",
        _ => "unknown",
    }
}

/// Turn a parsed frame into a `(display_string, byte_length)` pair for the UI.
fn render_ws_frame(f: &ParsedWsFrame) -> (String, usize) {
    let len = f.payload.len();
    match f.opcode {
        0x1 => {
            let s = String::from_utf8_lossy(&f.payload);
            (s.chars().take(4096).collect(), len)
        }
        0x8 => {
            if f.payload.len() >= 2 {
                let code = u16::from_be_bytes([f.payload[0], f.payload[1]]);
                let reason = String::from_utf8_lossy(&f.payload[2..]);
                (format!("close code={} reason={}", code, reason), len)
            } else {
                ("close".to_string(), len)
            }
        }
        _ => {
            let preview: String = f.payload.iter().take(32).map(|b| format!("{:02x}", b)).collect();
            (format!("[{} bytes] {}", len, preview), len)
        }
    }
}

/// Parse as many complete WebSocket frames as possible from the front of `buf`.
/// Returns the parsed frames (payloads unmasked) and the number of bytes
/// consumed; an incomplete trailing frame is left for the next read.
fn parse_ws_frames(buf: &[u8]) -> (Vec<ParsedWsFrame>, usize) {
    let mut frames = Vec::new();
    let mut pos = 0;
    while buf.len() - pos >= 2 {
        let rest = &buf[pos..];
        let b0 = rest[0];
        let b1 = rest[1];
        let opcode = b0 & 0x0F;
        let masked = (b1 & 0x80) != 0;
        let len7 = (b1 & 0x7F) as usize;

        let (mut header, payload_len) = if len7 == 126 {
            if rest.len() < 4 {
                break;
            }
            (4usize, u16::from_be_bytes([rest[2], rest[3]]) as usize)
        } else if len7 == 127 {
            if rest.len() < 10 {
                break;
            }
            (
                10usize,
                u64::from_be_bytes([rest[2], rest[3], rest[4], rest[5], rest[6], rest[7], rest[8], rest[9]])
                    as usize,
            )
        } else {
            (2usize, len7)
        };

        let mask_offset = header;
        if masked {
            header += 4;
        }
        let total = header + payload_len;
        if rest.len() < total {
            break;
        }

        let mut payload = rest[header..total].to_vec();
        if masked {
            let key =
                [rest[mask_offset], rest[mask_offset + 1], rest[mask_offset + 2], rest[mask_offset + 3]];
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[i % 4];
            }
        }

        frames.push(ParsedWsFrame { opcode, payload });
        pos += total;
    }
    (frames, pos)
}

#[cfg(test)]
mod ws_frame_tests {
    use super::*;

    #[test]
    fn parses_unmasked_text_frame() {
        // FIN + text(0x1), len 2, "Hi"
        let buf = [0x81u8, 0x02, b'H', b'i'];
        let (frames, consumed) = parse_ws_frames(&buf);
        assert_eq!(consumed, 4);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].opcode, 0x1);
        assert_eq!(frames[0].payload, b"Hi");
    }

    #[test]
    fn parses_masked_client_frame() {
        // FIN + text, masked, len 2, key 01020304, "Hi" XOR key
        let key = [0x01u8, 0x02, 0x03, 0x04];
        let masked = [b'H' ^ key[0], b'i' ^ key[1]];
        let buf = [0x81u8, 0x82, key[0], key[1], key[2], key[3], masked[0], masked[1]];
        let (frames, consumed) = parse_ws_frames(&buf);
        assert_eq!(consumed, 8);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"Hi"); // unmasked back to plaintext
    }

    #[test]
    fn leaves_incomplete_frame_unconsumed() {
        // Header claims a masked 2-byte payload but only part is present.
        let buf = [0x81u8, 0x82, 0x01, 0x02];
        let (frames, consumed) = parse_ws_frames(&buf);
        assert_eq!(consumed, 0);
        assert!(frames.is_empty());
    }

    #[test]
    fn parses_two_back_to_back_frames() {
        let buf = [0x81u8, 0x01, b'A', 0x8A, 0x00]; // text "A" then a pong (0xA)
        let (frames, consumed) = parse_ws_frames(&buf);
        assert_eq!(consumed, 5);
        assert_eq!(frames.len(), 2);
        assert_eq!(ws_opcode_name(frames[1].opcode), "pong");
    }

    #[test]
    fn renders_close_frame_code() {
        let f = ParsedWsFrame { opcode: 0x8, payload: vec![0x03, 0xE8] }; // 1000
        let (data, _) = render_ws_frame(&f);
        assert!(data.contains("code=1000"));
    }
}

/// Read a single HTTP request from a buffered reader.
/// Returns `None` if the connection was closed.
async fn read_wire_request<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<WireRequest>, Box<dyn std::error::Error + Send + Sync>> {
    let mut request_line = String::new();
    let n = reader.read_line(&mut request_line).await?;
    if n == 0 {
        return Ok(None);
    }

    let request_line = request_line.trim().to_string();
    if request_line.is_empty() {
        return Ok(None);
    }

    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(format!("Invalid request line: {}", request_line).into());
    }

    let method = parts[0].to_string();
    let path = parts[1].to_string();

    let mut headers = Vec::new();
    let mut headers_raw = String::new();
    let mut content_length: usize = 0;
    let mut is_chunked = false;
    let mut is_websocket_upgrade = false;
    let mut total_bytes = request_line.len();

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }

        total_bytes += line.len();
        if total_bytes > MAX_HEADER_SIZE {
            return Err("Headers too large".into());
        }

        headers_raw.push_str(trimmed);
        headers_raw.push_str("\r\n");

        if let Some((key, value)) = trimmed.split_once(':') {
            let k = key.trim().to_string();
            let v = value.trim().to_string();
            let lower = k.to_lowercase();

            if lower == "content-length" {
                content_length = v.parse().unwrap_or(0);
            }
            if lower == "transfer-encoding" && v.to_lowercase().contains("chunked") {
                is_chunked = true;
            }
            if lower == "upgrade" && v.to_lowercase().contains("websocket") {
                is_websocket_upgrade = true;
            }

            headers.push((k, v));
        }
    }

    let body = if is_chunked {
        read_chunked_body(reader, MAX_CHUNKED_BODY).await?
    } else if content_length > 0 {
        let mut body = vec![0u8; content_length.min(MAX_CHUNKED_BODY)];
        reader.read_exact(&mut body).await?;
        body
    } else {
        Vec::new()
    };

    Ok(Some(WireRequest { method, path, headers, headers_raw, body, is_websocket_upgrade }))
}

/// Read a chunked transfer-encoded body.
async fn read_chunked_body<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_size: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        reader.read_line(&mut size_line).await?;
        let size_hex = size_line.trim().split(';').next().unwrap_or("0").trim();
        let chunk_size =
            usize::from_str_radix(size_hex, 16).map_err(|_| format!("Invalid chunk size: {}", size_hex))?;

        if chunk_size == 0 {
            let mut trailing = String::new();
            let _ = reader.read_line(&mut trailing).await;
            break;
        }

        if body.len() + chunk_size > max_size {
            return Err("Chunked body exceeds maximum size".into());
        }

        let mut chunk = vec![0u8; chunk_size];
        reader.read_exact(&mut chunk).await?;
        body.extend_from_slice(&chunk);

        let mut trailing = String::new();
        let _ = reader.read_line(&mut trailing).await;
    }
    Ok(body)
}

fn parse_modified_request(raw: &str) -> Option<ParsedModifiedRequest> {
    let mut lines = raw.lines();
    let first = lines.next()?.trim();
    let parts: Vec<&str> = first.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let method = parts[0].to_string();
    let url_path = parts[1].to_string();

    let mut header_lines = Vec::new();
    let mut header_pairs = Vec::new();
    let mut in_body = false;
    let mut body_lines = Vec::new();

    for line in lines {
        if in_body {
            body_lines.push(line);
        } else if line.trim().is_empty() {
            in_body = true;
        } else {
            header_lines.push(line.to_string());
            if let Some((k, v)) = line.split_once(':') {
                header_pairs.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
    }

    Some(ParsedModifiedRequest {
        method,
        url_path,
        headers: header_pairs,
        headers_raw: header_lines.join("\r\n"),
        body: body_lines.join("\n").into_bytes(),
    })
}

fn parse_modified_response(raw: &str) -> Option<(u16, Vec<(String, String)>, String)> {
    let mut lines = raw.lines();
    let first = lines.next()?.trim();
    let status = first
        .split_whitespace()
        .find(|s| s.parse::<u16>().is_ok())
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(200);

    let mut headers = Vec::new();
    let mut in_body = false;
    let mut body_lines = Vec::new();

    for line in lines {
        if in_body {
            body_lines.push(line);
        } else if line.trim().is_empty() {
            in_body = true;
        } else if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    Some((status, headers, body_lines.join("\n")))
}

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "proxy-connection",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "accept-encoding", // MUST strip: reqwest disables auto-decompress when set explicitly
];

fn parse_host_port(target: &str, default_port: u16) -> (String, u16) {
    if target.starts_with('[') {
        if let Some((bracket_end, rest)) = target[1..].split_once(']') {
            let host = bracket_end.to_string();
            let port = rest.strip_prefix(':').and_then(|p| p.parse().ok()).unwrap_or(default_port);
            return (host, port);
        }
    }
    if let Some((host, port_str)) = target.rsplit_once(':') {
        (host.to_string(), port_str.parse().unwrap_or(default_port))
    } else {
        (target.to_string(), default_port)
    }
}

fn is_benign_error(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    lower.contains("connection reset")
        || lower.contains("broken pipe")
        || lower.contains("eof")
        || lower.contains("connection abort")
        || lower.contains("forcibly closed")
        || lower.contains("timed out")
        || lower.contains("unexpected eof")
        || lower.contains("peer not authenticated")
        || lower.contains("received fatal alert")
        || lower.contains("channel closed")
}

#[cfg(not(target_os = "linux"))]
fn wreq_err_chain(stage: &str, e: &wreq::Error) -> String {
    use std::error::Error;
    let mut out = format!("wreq {}: {}", stage, e);
    let mut src: Option<&dyn Error> = e.source();
    let mut depth = 0;
    while let Some(s) = src {
        out.push_str(&format!(" -> {}", s));
        src = s.source();
        depth += 1;
        if depth > 8 {
            break;
        }
    }
    out
}

/// Best-effort string match for transient HTTP/2 errors that benefit from
/// a one-shot retry on a fresh pooled connection. wreq's typed error tree
/// hides h2's internal error codes behind `SendRequest`/`Body` variants, so
/// we sniff the formatted chain. Patterns are matched case-insensitively
/// because some error sources camel-case their text.
#[cfg(not(target_os = "linux"))]
fn is_h2_transient_error(chain: &str) -> bool {
    let lower = chain.to_ascii_lowercase();
    // "stream error received: unspecific protocol error detected" (h2 lib),
    // "REFUSED_STREAM" / "PROTOCOL_ERROR" (h2 typed errors), "go away" after
    // server-initiated shutdown, "broken pipe" / "connection reset" / "eof"
    // on a pooled socket the peer already closed.
    lower.contains("unspecific protocol error")
        || lower.contains("protocol_error")
        || lower.contains("refused_stream")
        || lower.contains("refused stream")
        || lower.contains("go away")
        || lower.contains("goaway")
        || lower.contains("http2 error")
        || lower.contains("connection reset")
        || lower.contains("broken pipe")
        || lower.contains("unexpected eof")
}
