use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// WonderSuite HTTP/2 Translation Layer
/// 
/// Provides binary ↔ human-readable translation for HTTP/2 traffic.
/// Handles pseudo-headers, frame types, HPACK compression, and
/// transparent protocol negotiation.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Frame {
    pub frame_type: Http2FrameType,
    pub stream_id: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
    pub length: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Http2FrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
    Unknown(u8),
}

impl Http2FrameType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Data,
            1 => Self::Headers,
            2 => Self::Priority,
            3 => Self::RstStream,
            4 => Self::Settings,
            5 => Self::PushPromise,
            6 => Self::Ping,
            7 => Self::GoAway,
            8 => Self::WindowUpdate,
            9 => Self::Continuation,
            v => Self::Unknown(v),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Headers => 1,
            Self::Priority => 2,
            Self::RstStream => 3,
            Self::Settings => 4,
            Self::PushPromise => 5,
            Self::Ping => 6,
            Self::GoAway => 7,
            Self::WindowUpdate => 8,
            Self::Continuation => 9,
            Self::Unknown(v) => *v,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Data => "DATA",
            Self::Headers => "HEADERS",
            Self::Priority => "PRIORITY",
            Self::RstStream => "RST_STREAM",
            Self::Settings => "SETTINGS",
            Self::PushPromise => "PUSH_PROMISE",
            Self::Ping => "PING",
            Self::GoAway => "GOAWAY",
            Self::WindowUpdate => "WINDOW_UPDATE",
            Self::Continuation => "CONTINUATION",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

/// Human-readable representation of an HTTP/2 request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Request {
    pub method: String,
    pub path: String,
    pub authority: String,
    pub scheme: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub stream_id: u32,
    pub protocol_version: String,
}

/// Human-readable representation of an HTTP/2 response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub stream_id: u32,
    pub protocol_version: String,
}

/// HTTP/2 Settings parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
}

impl Default for Http2Settings {
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: 100,
            initial_window_size: 65535,
            max_frame_size: 16384,
            max_header_list_size: 8192,
        }
    }
}

/// Translate an HTTP/1.1 request to HTTP/2 format
pub fn http1_to_http2(method: &str, url: &str, headers: &HashMap<String, String>, body: Option<&str>) -> Http2Request {
    let parsed = url::Url::parse(url).unwrap_or_else(|_| url::Url::parse("http://localhost").unwrap());
    let authority = parsed.host_str().unwrap_or("localhost").to_string();
    let path = parsed.path().to_string();
    let scheme = parsed.scheme().to_string();
    
    // Filter out HTTP/1.1 specific headers that become pseudo-headers in H2
    let mut h2_headers = HashMap::new();
    for (k, v) in headers {
        let lower = k.to_lowercase();
        // Skip headers that become pseudo-headers
        if lower == "host" || lower == "connection" || lower == "transfer-encoding" 
            || lower == "keep-alive" || lower == "upgrade" {
            continue;
        }
        h2_headers.insert(lower, v.clone());
    }
    
    Http2Request {
        method: method.to_uppercase(),
        path,
        authority: format!("{}:{}", authority, parsed.port_or_known_default().unwrap_or(443)),
        scheme,
        headers: h2_headers,
        body: body.map(|b| b.to_string()),
        stream_id: 1, // Default stream
        protocol_version: "h2".into(),
    }
}

/// Translate an HTTP/2 request back to HTTP/1.1 human-readable format
pub fn http2_to_http1(req: &Http2Request) -> String {
    let mut lines = Vec::new();
    lines.push(format!("{} {} HTTP/2", req.method, req.path));
    lines.push(format!(":method: {}", req.method));
    lines.push(format!(":path: {}", req.path));
    lines.push(format!(":authority: {}", req.authority));
    lines.push(format!(":scheme: {}", req.scheme));
    
    for (k, v) in &req.headers {
        lines.push(format!("{}: {}", k, v));
    }
    
    if let Some(body) = &req.body {
        lines.push(String::new());
        lines.push(body.clone());
    }
    
    lines.join("\r\n")
}

/// Translate HTTP/2 response to human-readable format
pub fn http2_response_to_readable(resp: &Http2Response) -> String {
    let mut lines = Vec::new();
    lines.push(format!("HTTP/2 {}", resp.status));
    lines.push(format!(":status: {}", resp.status));
    
    for (k, v) in &resp.headers {
        lines.push(format!("{}: {}", k, v));
    }
    
    if let Some(body) = &resp.body {
        lines.push(String::new());
        lines.push(body.clone());
    }
    
    lines.join("\r\n")
}

/// Parse HTTP/2 pseudo-headers from a raw header block
pub fn parse_pseudo_headers(raw: &str) -> (HashMap<String, String>, HashMap<String, String>) {
    let mut pseudo = HashMap::new();
    let mut regular = HashMap::new();
    
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();
            
            if key.starts_with(':') {
                pseudo.insert(key, value);
            } else {
                regular.insert(key, value);
            }
        }
    }
    
    (pseudo, regular)
}

/// Send an HTTP/2 request using reqwest
pub async fn send_h2_request(req: &Http2Request) -> Result<Http2Response, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e: reqwest::Error| e.to_string())?;
    
    let url = format!("{}://{}{}", req.scheme, req.authority, req.path);
    
    let mut builder = match req.method.as_str() {
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "PATCH" => client.patch(&url),
        "HEAD" => client.head(&url),
        _ => client.get(&url),
    };
    
    for (k, v) in &req.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    
    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }
    
    let resp = builder.send().await.map_err(|e: reqwest::Error| e.to_string())?;
    
    let status = resp.status().as_u16();
    let headers: HashMap<String, String> = resp.headers().iter()
        .map(|(k, v): (&reqwest::header::HeaderName, &reqwest::header::HeaderValue)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body: Option<String> = resp.text().await.ok();
    
    Ok(Http2Response {
        status,
        headers,
        body,
        stream_id: req.stream_id,
        protocol_version: "h2".into(),
    })
}

/// Describe HTTP/2 frame flags
pub fn describe_flags(frame_type: &Http2FrameType, flags: u8) -> Vec<String> {
    let mut flag_names = Vec::new();
    
    match frame_type {
        Http2FrameType::Data => {
            if flags & 0x01 != 0 { flag_names.push("END_STREAM".into()); }
            if flags & 0x08 != 0 { flag_names.push("PADDED".into()); }
        }
        Http2FrameType::Headers => {
            if flags & 0x01 != 0 { flag_names.push("END_STREAM".into()); }
            if flags & 0x04 != 0 { flag_names.push("END_HEADERS".into()); }
            if flags & 0x08 != 0 { flag_names.push("PADDED".into()); }
            if flags & 0x20 != 0 { flag_names.push("PRIORITY".into()); }
        }
        Http2FrameType::Settings => {
            if flags & 0x01 != 0 { flag_names.push("ACK".into()); }
        }
        Http2FrameType::Ping => {
            if flags & 0x01 != 0 { flag_names.push("ACK".into()); }
        }
        Http2FrameType::PushPromise => {
            if flags & 0x04 != 0 { flag_names.push("END_HEADERS".into()); }
            if flags & 0x08 != 0 { flag_names.push("PADDED".into()); }
        }
        _ => {}
    }
    
    flag_names
}

/// Generate a human-readable frame dump
pub fn frame_to_string(frame: &Http2Frame) -> String {
    let flags = describe_flags(&frame.frame_type, frame.flags);
    let flag_str = if flags.is_empty() { String::new() } else { format!(" [{}]", flags.join(", ")) };
    
    format!(
        "Frame: {} | Stream: {} | Length: {} | Flags: 0x{:02X}{}",
        frame.frame_type.name(),
        frame.stream_id,
        frame.length,
        frame.flags,
        flag_str,
    )
}

/// Detect if a server supports HTTP/2
pub async fn detect_h2_support(url: &str) -> Result<bool, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| e.to_string())?;
    
    if let Ok(resp) = client.get(url).send().await {
        let version = resp.version();
        Ok(format!("{:?}", version).contains("HTTP/2"))
    } else {
        Ok(false)
    }
}
