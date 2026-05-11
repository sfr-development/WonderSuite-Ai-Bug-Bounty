use super::types::BambdaCondition;

pub fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

pub fn base64_decode(input: &str) -> Result<String, String> {
    let bytes = base64_decode_bytes(input);
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

pub fn base64_decode_bytes(input: &str) -> Vec<u8> {
    let input = input.replace('-', "+").replace('_', "/");
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input,
    };
    const TABLE: [i8; 128] = {
        let mut t = [-1i8; 128];
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < 64 {
            t[chars[i] as usize] = i as i8;
            i += 1;
        }
        t
    };
    let mut bytes = Vec::new();
    let chars: Vec<u8> = padded.bytes().filter(|&b| b != b'\n' && b != b'\r' && b != b' ').collect();
    for chunk in chars.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        let vals: Vec<i8> = chunk
            .iter()
            .map(|&b| {
                if b == b'=' {
                    0
                } else if (b as usize) < 128 {
                    TABLE[b as usize]
                } else {
                    -1
                }
            })
            .collect();
        if vals.iter().any(|&v| v == -1) {
            break;
        }
        let triple =
            ((vals[0] as u32) << 18) | ((vals[1] as u32) << 12) | ((vals[2] as u32) << 6) | (vals[3] as u32);
        bytes.push(((triple >> 16) & 0xFF) as u8);
        if chunk[2] != b'=' {
            bytes.push(((triple >> 8) & 0xFF) as u8);
        }
        if chunk[3] != b'=' {
            bytes.push((triple & 0xFF) as u8);
        }
    }
    bytes
}

pub fn urlencoding_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{:02X}", b),
        })
        .collect()
}

pub fn urlencoding_decode(s: &str) -> String {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(val) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16) {
                result.push(val);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).to_string()
}

pub fn compute_hash(algo: &str, data: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    algo.hash(&mut hasher);
    data.hash(&mut hasher);
    format!(
        "{:016x}{:016x}{:016x}{:016x}",
        hasher.finish(),
        data.len(),
        hasher.finish().wrapping_mul(0x517cc1b727220a95),
        hasher.finish().wrapping_add(0x6c62272e07bb0142)
    )
}

pub fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    let c1: u32 = 0xcc9e2d51;
    let c2: u32 = 0x1b873593;
    let mut h1 = seed;
    let len = data.len();

    let nblocks = len / 4;
    for i in 0..nblocks {
        let mut k1 = u32::from_le_bytes([data[i * 4], data[i * 4 + 1], data[i * 4 + 2], data[i * 4 + 3]]);
        k1 = k1.wrapping_mul(c1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(c2);
        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);
    }

    let tail = &data[nblocks * 4..];
    let mut k1: u32 = 0;
    match tail.len() {
        3 => {
            k1 ^= (tail[2] as u32) << 16;
            k1 ^= (tail[1] as u32) << 8;
            k1 ^= tail[0] as u32;
            k1 = k1.wrapping_mul(c1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(c2);
            h1 ^= k1;
        }
        2 => {
            k1 ^= (tail[1] as u32) << 8;
            k1 ^= tail[0] as u32;
            k1 = k1.wrapping_mul(c1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(c2);
            h1 ^= k1;
        }
        1 => {
            k1 ^= tail[0] as u32;
            k1 = k1.wrapping_mul(c1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(c2);
            h1 ^= k1;
        }
        _ => {}
    }

    h1 ^= len as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85ebca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2ae35);
    h1 ^= h1 >> 16;
    h1
}

pub fn extract_html_title(html: &str) -> String {
    let re = regex::Regex::new(r"(?i)<title[^>]*>(.*?)</title>").ok();
    re.and_then(|r| r.captures(html).and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string())))
        .unwrap_or_else(|| String::new())
}

pub fn extract_links(html: &str, base_url: &str) -> Vec<String> {
    let re = regex::Regex::new(r#"(?i)href=["']([^"']+)["']"#).ok();
    let base = url::Url::parse(base_url).ok();
    re.map(|r| {
        r.captures_iter(html)
            .filter_map(|c| {
                let href = c.get(1)?.as_str();
                if href.starts_with("javascript:") || href.starts_with("#") || href.starts_with("mailto:") {
                    return None;
                }
                if href.starts_with("http") {
                    return Some(href.to_string());
                }
                base.as_ref().and_then(|b| b.join(href).ok().map(|u| u.to_string()))
            })
            .take(50)
            .collect()
    })
    .unwrap_or_default()
}

pub fn extract_forms(html: &str) -> Vec<serde_json::Value> {
    let form_re = regex::Regex::new(r"(?is)<form([^>]*)>(.*?)</form>").ok();
    let action_re = regex::Regex::new(r#"(?i)action=["']([^"']*)["']"#).ok();
    let method_re = regex::Regex::new(r#"(?i)method=["']([^"']*)["']"#).ok();
    let input_re = regex::Regex::new(r#"(?i)<input([^>]*)>"#).ok();
    let name_re = regex::Regex::new(r#"(?i)name=["']([^"']*)["']"#).ok();
    let type_re = regex::Regex::new(r#"(?i)type=["']([^"']*)["']"#).ok();

    form_re
        .map(|fr| {
            fr.captures_iter(html)
                .take(10)
                .map(|fc| {
                    let attrs = fc.get(1).map(|m| m.as_str()).unwrap_or("");
                    let body = fc.get(2).map(|m| m.as_str()).unwrap_or("");
                    let action = action_re
                        .as_ref()
                        .and_then(|r| {
                            r.captures(attrs).and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
                        })
                        .unwrap_or_default();
                    let method = method_re
                        .as_ref()
                        .and_then(|r| {
                            r.captures(attrs).and_then(|c| c.get(1).map(|m| m.as_str().to_uppercase()))
                        })
                        .unwrap_or_else(|| "GET".into());
                    let inputs: Vec<serde_json::Value> = input_re
                        .as_ref()
                        .map(|ir| {
                            ir.captures_iter(body)
                                .filter_map(|ic| {
                                    let ia = ic.get(1).map(|m| m.as_str()).unwrap_or("");
                                    let name = name_re.as_ref().and_then(|r| {
                                        r.captures(ia).and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
                                    })?;
                                    let itype = type_re
                                        .as_ref()
                                        .and_then(|r| {
                                            r.captures(ia)
                                                .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
                                        })
                                        .unwrap_or_else(|| "text".into());
                                    Some(serde_json::json!({"name": name, "type": itype}))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    serde_json::json!({"action": action, "method": method, "inputs": inputs})
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn parse_bambda_expression(expr: &str) -> Result<Vec<BambdaCondition>, String> {
    let mut conditions = Vec::new();
    let parts: Vec<&str> = expr.split("&&").map(|s| s.trim()).collect();

    for part in parts {
        if part.is_empty() {
            continue;
        }
        let operators = vec![
            "contains",
            "not_contains",
            "matches",
            "==",
            "!=",
            ">=",
            "<=",
            ">",
            "<",
            "starts_with",
            "ends_with",
        ];
        let mut found = false;

        for op in &operators {
            if let Some(idx) = part.find(op) {
                let field = part[..idx].trim().to_string();
                let value = part[idx + op.len()..].trim().trim_matches('\'').trim_matches('"').to_string();
                conditions.push(BambdaCondition { field, operator: op.to_string(), value });
                found = true;
                break;
            }
        }

        if !found {
            conditions.push(BambdaCondition {
                field: part.trim().to_string(),
                operator: "exists".to_string(),
                value: String::new(),
            });
        }
    }

    if conditions.is_empty() {
        Err("No valid conditions parsed from expression".into())
    } else {
        Ok(conditions)
    }
}

pub fn evaluate_bambda_conditions(item: &serde_json::Value, conditions: &[BambdaCondition]) -> bool {
    conditions.iter().all(|cond| {
        let field_value = get_nested_field(item, &cond.field);
        let field_str = match &field_value {
            Some(v) => match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => v.to_string(),
            },
            None => return cond.operator == "not_contains",
        };

        match cond.operator.as_str() {
            "==" => field_str == cond.value,
            "!=" => field_str != cond.value,
            "contains" => field_str.contains(&cond.value),
            "not_contains" => !field_str.contains(&cond.value),
            "starts_with" => field_str.starts_with(&cond.value),
            "ends_with" => field_str.ends_with(&cond.value),
            ">" => field_str.parse::<f64>().unwrap_or(0.0) > cond.value.parse::<f64>().unwrap_or(0.0),
            ">=" => field_str.parse::<f64>().unwrap_or(0.0) >= cond.value.parse::<f64>().unwrap_or(0.0),
            "<" => field_str.parse::<f64>().unwrap_or(0.0) < cond.value.parse::<f64>().unwrap_or(0.0),
            "<=" => field_str.parse::<f64>().unwrap_or(0.0) <= cond.value.parse::<f64>().unwrap_or(0.0),
            "matches" => regex::Regex::new(&cond.value).map(|r| r.is_match(&field_str)).unwrap_or(false),
            "exists" => true,
            _ => false,
        }
    })
}

pub fn get_nested_field<'a>(item: &'a serde_json::Value, field: &str) -> Option<&'a serde_json::Value> {
    let parts: Vec<&str> = field.split('.').collect();
    let mut current = item;
    for part in parts {
        current = current.get(part)?;
    }
    Some(current)
}
