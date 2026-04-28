// ═══════════════════════════════════════════════════════════════════════
//  Codec Primitives — encode, decode, hash, JWT analysis, smart_decode
//  Raw data transformation tools. The AI chains these however it wants.
// ═══════════════════════════════════════════════════════════════════════

use crate::mcp::types::HandlerResult;
use crate::mcp::utils::*;

pub async fn handle_encode(params: &serde_json::Value) -> HandlerResult {
    let data = params["data"].as_str().ok_or("Missing data")?;
    let format = params["format"].as_str().ok_or("Missing format")?;
    let result = match format {
        "base64" => Ok(base64_encode(data.as_bytes())),
        "url" => Ok(urlencoding_encode(data)),
        "hex" => Ok(data.as_bytes().iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")),
        _ => Err(format!("Unknown format: {}", format)),
    }?;
    Ok(serde_json::json!({ "result": result }))
}

pub async fn handle_decode(params: &serde_json::Value) -> HandlerResult {
    let data = params["data"].as_str().ok_or("Missing data")?;
    let format = params["format"].as_str().ok_or("Missing format")?;
    let result = match format {
        "base64" => base64_decode(data).map_err(|e| e.to_string()),
        "url" => Ok(urlencoding_decode(data)),
        "hex" => {
            let bytes: Result<Vec<u8>, _> = data.split_whitespace()
                .map(|h| u8::from_str_radix(h, 16))
                .collect();
            bytes.map(|b| String::from_utf8_lossy(&b).to_string()).map_err(|e| e.to_string())
        }
        _ => Err(format!("Unknown format: {}", format)),
    }?;
    Ok(serde_json::json!({ "result": result }))
}

pub async fn handle_hash(params: &serde_json::Value) -> HandlerResult {
    let data = params["data"].as_str().ok_or("Missing data")?;
    let algo = params["algorithm"].as_str().ok_or("Missing algorithm")?;
    let hash = compute_hash(algo, data.as_bytes());
    Ok(serde_json::json!({ "algorithm": algo, "hash": hash }))
}

pub async fn handle_analyze_jwt(params: &serde_json::Value) -> HandlerResult {
    let token = params["token"].as_str().ok_or("Missing token")?;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 { return Err("Invalid JWT".into()); }

    let header = base64_decode(parts[0]).unwrap_or_else(|_| "invalid".into());
    let payload = base64_decode(parts[1]).unwrap_or_else(|_| "invalid".into());

    Ok(serde_json::json!({
        "header": serde_json::from_str::<serde_json::Value>(&header).unwrap_or(serde_json::Value::String(header)),
        "payload": serde_json::from_str::<serde_json::Value>(&payload).unwrap_or(serde_json::Value::String(payload)),
        "signature": parts.get(2).unwrap_or(&""),
    }))
}

pub async fn handle_smart_decode(params: &serde_json::Value) -> HandlerResult {
    let data = params["data"].as_str().ok_or("Missing data")?;
    let max_depth = params["max_depth"].as_u64().unwrap_or(5) as usize;

    let mut current = data.to_string();
    let mut chain: Vec<serde_json::Value> = Vec::new();
    chain.push(serde_json::json!({"step": 0, "encoding": "input", "value": &current}));

    for step in 1..=max_depth {
        let trimmed = current.trim().to_string();
        // JWT detection
        if trimmed.matches('.').count() == 2 && trimmed.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '=' || c == '+' || c == '/') {
            let parts: Vec<&str> = trimmed.split('.').collect();
            if let Ok(header) = base64_decode(parts[0]) {
                if header.starts_with('{') {
                    let payload = base64_decode(parts[1]).unwrap_or_default();
                    chain.push(serde_json::json!({"step": step, "encoding": "JWT", "header": header, "payload": payload}));
                    break;
                }
            }
        }
        // Base64
        if trimmed.len() > 3 && trimmed.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=') {
            if let Ok(decoded) = base64_decode(&trimmed) {
                if decoded.chars().all(|c| c.is_ascii() && !c.is_control()) && !decoded.is_empty() {
                    chain.push(serde_json::json!({"step": step, "encoding": "base64", "value": &decoded}));
                    current = decoded;
                    continue;
                }
            }
        }
        // URL decode
        if trimmed.contains('%') {
            let decoded = urlencoding_decode(&trimmed);
            if decoded != trimmed {
                chain.push(serde_json::json!({"step": step, "encoding": "url", "value": &decoded}));
                current = decoded;
                continue;
            }
        }
        // Hex
        if trimmed.len() > 4 && trimmed.len() % 2 == 0 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let bytes: Result<Vec<u8>, _> = (0..trimmed.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&trimmed[i..i+2], 16))
                .collect();
            if let Ok(bytes) = bytes {
                let decoded = String::from_utf8_lossy(&bytes).to_string();
                if decoded.chars().all(|c| c.is_ascii() && !c.is_control()) {
                    chain.push(serde_json::json!({"step": step, "encoding": "hex", "value": &decoded}));
                    current = decoded;
                    continue;
                }
            }
        }
        break;
    }

    Ok(serde_json::json!({
        "input": data,
        "final_decoded": current,
        "decoding_chain": chain,
        "total_steps": chain.len() - 1,
    }))
}
