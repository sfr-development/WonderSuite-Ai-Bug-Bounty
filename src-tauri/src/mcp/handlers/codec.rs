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
            let bytes: Result<Vec<u8>, _> =
                data.split_whitespace().map(|h| u8::from_str_radix(h, 16)).collect();
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
    if parts.len() < 2 {
        return Err("Invalid JWT (need at least header.payload)".into());
    }

    let header_raw = base64_decode(parts[0]).map_err(|e| format!("Header b64 decode: {}", e))?;
    let payload_raw = base64_decode(parts[1]).map_err(|e| format!("Payload b64 decode: {}", e))?;
    let header_json: serde_json::Value =
        serde_json::from_str(&header_raw).unwrap_or(serde_json::Value::String(header_raw.clone()));
    let payload_json: serde_json::Value =
        serde_json::from_str(&payload_raw).unwrap_or(serde_json::Value::String(payload_raw.clone()));

    let mut vulnerabilities = Vec::<serde_json::Value>::new();
    let alg = header_json.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    let alg_lower = alg.to_ascii_lowercase();
    if alg_lower == "none" {
        vulnerabilities.push(serde_json::json!({
            "id": "JWT_ALG_NONE",
            "severity": "critical",
            "evidence": format!("alg = {:?}", alg),
            "hint": "Re-sign the token with alg=none and an empty signature — many libraries accept it. Test by sending header.payload. (one trailing dot, no sig).",
        }));
    }
    if matches!(alg_lower.as_str(), "hs256" | "hs384" | "hs512") {
        vulnerabilities.push(serde_json::json!({
            "id": "JWT_HS_KEY_CONFUSION",
            "severity": "high",
            "evidence": format!("alg = {} (HMAC)", alg),
            "hint": "If the server has the RSA public key available, you may be able to re-sign with HS256 using the public key as the secret (key-confusion). Try a known-public-key attack.",
        }));
    }
    if let Some(kid) = header_json.get("kid").and_then(|v| v.as_str()) {
        if kid.contains('\'') || kid.contains('"') || kid.contains("../") || kid.contains("..\\") {
            vulnerabilities.push(serde_json::json!({
                "id": "JWT_KID_SUSPICIOUS",
                "severity": "high",
                "evidence": format!("kid = {:?}", kid),
                "hint": "kid value contains quote / path-traversal chars — server may be doing SQL lookup or file load on kid. Try kid=' UNION SELECT 'secret'-- or kid=/dev/null with empty signature.",
            }));
        } else {
            vulnerabilities.push(serde_json::json!({
                "id": "JWT_KID_INJECTABLE",
                "severity": "info",
                "evidence": format!("kid = {:?}", kid),
                "hint": "kid is a likely SQLi / path-traversal sink. Try replacing with quote-injection or directory-traversal payloads.",
            }));
        }
    }
    if let Some(jku) = header_json.get("jku").and_then(|v| v.as_str()) {
        vulnerabilities.push(serde_json::json!({
            "id": "JWT_JKU_SSRF",
            "severity": "high",
            "evidence": format!("jku = {:?}", jku),
            "hint": "jku points the server at an external JWK Set URL — try jku=https://attacker/jwks.json with a self-signed RSA pair.",
        }));
    }
    if header_json.get("x5u").is_some() {
        vulnerabilities.push(serde_json::json!({
            "id": "JWT_X5U_SSRF",
            "severity": "high",
            "evidence": "x5u header present",
            "hint": "x5u fetches an X.509 cert chain — same SSRF / self-signed-pair attack as jku.",
        }));
    }
    let sig = parts.get(2).copied().unwrap_or("");
    if sig.is_empty() && alg_lower != "none" {
        vulnerabilities.push(serde_json::json!({
            "id": "JWT_EMPTY_SIG",
            "severity": "info",
            "evidence": "no signature segment",
            "hint": "Empty signature with non-none alg — may still verify on careless servers.",
        }));
    }
    if let Some(exp) = payload_json.get("exp").and_then(|v| v.as_i64()) {
        let now = chrono::Utc::now().timestamp();
        if exp < now {
            vulnerabilities.push(serde_json::json!({
                "id": "JWT_EXPIRED",
                "severity": "info",
                "evidence": format!("exp = {} ({}s ago)", exp, now - exp),
                "hint": "Token already expired — useful for testing whether the server enforces exp.",
            }));
        }
    }

    Ok(serde_json::json!({
        "header": header_json,
        "payload": payload_json,
        "signature": sig,
        "alg": alg,
        "vulnerabilities": vulnerabilities,
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
        if trimmed.matches('.').count() == 2
            && trimmed.chars().all(|c| {
                c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '=' || c == '+' || c == '/'
            })
        {
            let parts: Vec<&str> = trimmed.split('.').collect();
            if let Ok(header) = base64_decode(parts[0]) {
                if header.starts_with('{') {
                    let payload = base64_decode(parts[1]).unwrap_or_default();
                    chain.push(serde_json::json!({"step": step, "encoding": "JWT", "header": header, "payload": payload}));
                    break;
                }
            }
        }
        if trimmed.len() > 3
            && trimmed.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            if let Ok(decoded) = base64_decode(&trimmed) {
                if decoded.chars().all(|c| c.is_ascii() && !c.is_control()) && !decoded.is_empty() {
                    chain.push(serde_json::json!({"step": step, "encoding": "base64", "value": &decoded}));
                    current = decoded;
                    continue;
                }
            }
        }
        if trimmed.contains('%') {
            let decoded = urlencoding_decode(&trimmed);
            if decoded != trimmed {
                chain.push(serde_json::json!({"step": step, "encoding": "url", "value": &decoded}));
                current = decoded;
                continue;
            }
        }
        if trimmed.len() > 4 && trimmed.len() % 2 == 0 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let bytes: Result<Vec<u8>, _> =
                (0..trimmed.len()).step_by(2).map(|i| u8::from_str_radix(&trimmed[i..i + 2], 16)).collect();
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
