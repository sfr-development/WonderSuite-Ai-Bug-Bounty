use crate::mcp::types::HandlerResult;
use std::collections::HashMap;

pub async fn handle_fuzz_request(params: &serde_json::Value) -> HandlerResult {
    let attack_type = params["attack_type"].as_str().unwrap_or("sniper");
    let max_concurrent = params["max_concurrent"].as_u64().unwrap_or(10) as usize;
    let delay_ms = params["delay_ms"].as_u64().unwrap_or(0);
    let max_requests = params["max_requests"].as_u64().unwrap_or(10000) as usize;
    let stop_on_match = params["stop_on_match"].as_bool().unwrap_or(false);

    let base = &params["base_request"];
    let method = base["method"].as_str().unwrap_or("GET").to_string();
    let url_template = base["url"].as_str().ok_or("base_request.url is required")?;
    let body_template = base["body"].as_str().unwrap_or("").to_string();
    let base_headers: HashMap<String, String> = base["headers"]
        .as_object()
        .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
        .unwrap_or_default();

    let positions = params["positions"].as_array().ok_or("positions array is required")?;

    let mut position_data: Vec<PositionInfo> = Vec::new();
    for pos in positions {
        let marker = pos["marker"].as_str().unwrap_or("§payload§").to_string();
        let payloads = resolve_payloads(pos)?;
        position_data.push(PositionInfo { marker, payloads });
    }

    if position_data.is_empty() {
        return Err("At least one position with payloads is required".into());
    }

    let match_rules = parse_match_rules(&params["match_rules"]);

    let combinations = generate_combinations(attack_type, &position_data, max_requests)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| format!("Client error: {}", e))?;

    let baseline_url = strip_markers(url_template, &position_data);
    let baseline_body = strip_markers(&body_template, &position_data);
    let baseline = send_one(&client, &method, &baseline_url, &base_headers, &baseline_body).await;

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent));
    let results_lock = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<FuzzResult>::new()));
    let total = combinations.len();

    let mut handles = Vec::new();
    for (idx, combo) in combinations.into_iter().enumerate() {
        let sem = semaphore.clone();
        let res = results_lock.clone();
        let client = client.clone();
        let method = method.clone();
        let url_tpl = url_template.to_string();
        let body_tpl = body_template.clone();
        let hdrs = base_headers.clone();
        let rules = match_rules.clone();
        let bl = baseline.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let mut url = url_tpl;
            let mut body = body_tpl;
            for (marker, payload) in &combo {
                url = url.replace(marker, payload);
                body = body.replace(marker, payload);
            }

            let start = std::time::Instant::now();
            let result = send_one(&client, &method, &url, &hdrs, &body).await;
            let elapsed = start.elapsed().as_millis() as u64;

            let length_diff = (result.length as i64 - bl.length as i64).unsigned_abs() as usize;
            let time_diff = if elapsed > bl.time_ms { elapsed - bl.time_ms } else { bl.time_ms - elapsed };

            let matched_rules = check_matches(&result, &bl, &rules, length_diff, elapsed);
            let is_anomaly = !matched_rules.is_empty();

            let fuzz_result = FuzzResult {
                index: idx,
                payload: combo.iter().map(|(_, p)| p.clone()).collect::<Vec<_>>().join(" | "),
                position: combo.first().map(|(m, _)| m.clone()).unwrap_or_default(),
                status: result.status,
                length: result.length,
                time_ms: elapsed,
                length_diff,
                matched_rules,
                body_preview: result.body[..result.body.len().min(200)].to_string(),
                is_anomaly,
            };

            let mut results = res.lock().await;
            results.push(fuzz_result);
        });

        handles.push(handle);

        if delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
    }

    for h in handles {
        let _ = h.await;
    }

    let mut results = results_lock.lock().await;
    results.sort_by_key(|r| r.index);

    let anomalies: Vec<&FuzzResult> = results.iter().filter(|r| r.is_anomaly).collect();
    let error_count = results.iter().filter(|r| r.status == 0).count();
    let elapsed_total = results.iter().map(|r| r.time_ms).max().unwrap_or(0);

    Ok(serde_json::json!({
        "attack_type": attack_type,
        "total_requests": total,
        "completed": results.len(),
        "matches": anomalies.len(),
        "errors": error_count,
        "elapsed_ms": elapsed_total,
        "baseline": {
            "status": baseline.status,
            "length": baseline.length,
            "time_ms": baseline.time_ms,
        },
        "results": results.iter().collect::<Vec<_>>(),
        "anomalies": anomalies,
    }))
}

struct PositionInfo {
    marker: String,
    payloads: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct FuzzResult {
    index: usize,
    payload: String,
    position: String,
    status: u16,
    length: usize,
    time_ms: u64,
    length_diff: usize,
    matched_rules: Vec<String>,
    body_preview: String,
    is_anomaly: bool,
}

#[derive(Debug, Clone)]
struct ResponseInfo {
    status: u16,
    length: usize,
    body: String,
    time_ms: u64,
}

#[derive(Debug, Clone)]
enum MatchRule {
    StatusCode(Vec<u16>),
    LengthDiff(usize),
    BodyContains(String),
    BodyRegex(String),
    Timing(u64),
    StatusDiff,
}

fn resolve_payloads(pos: &serde_json::Value) -> Result<Vec<String>, String> {
    let source = pos["source"].as_str().unwrap_or("inline");
    match source {
        "inline" => {
            if let Some(arr) = pos["payloads"].as_array() {
                Ok(arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            } else if let Some(s) = pos["payloads"].as_str() {
                Ok(s.lines().filter(|l| !l.trim().is_empty()).map(String::from).collect())
            } else {
                Err("Inline payloads required (array or newline-separated string)".into())
            }
        }
        "file" => {
            let category =
                pos["file_category"].as_str().ok_or("file_category is required for source=file")?;
            let mut mgr = crate::mcp::handlers::payloads::manager();
            let all = mgr.load(category)?;
            let limit = pos["limit"].as_u64().unwrap_or(1000) as usize;
            Ok(all.into_iter().take(limit).collect())
        }
        "range" => {
            let start = pos["start"].as_i64().unwrap_or(0);
            let end = pos["end"].as_i64().unwrap_or(100);
            let step = pos["step"].as_i64().unwrap_or(1).max(1);
            Ok((start..=end).step_by(step as usize).map(|n| n.to_string()).collect())
        }
        _ => Err(format!("Unknown payload source: {}", source)),
    }
}

fn generate_combinations(
    attack_type: &str,
    positions: &[PositionInfo],
    max_requests: usize,
) -> Result<Vec<Vec<(String, String)>>, String> {
    let mut combos: Vec<Vec<(String, String)>> = Vec::new();

    match attack_type {
        "sniper" => {
            for (i, pos) in positions.iter().enumerate() {
                for payload in &pos.payloads {
                    let mut combo: Vec<(String, String)> = Vec::new();
                    for (j, p) in positions.iter().enumerate() {
                        if i == j {
                            combo.push((p.marker.clone(), payload.clone()));
                        } else {
                            combo.push((p.marker.clone(), String::new()));
                        }
                    }
                    combos.push(combo);
                    if combos.len() >= max_requests {
                        return Ok(combos);
                    }
                }
            }
        }
        "battering_ram" | "batteringram" => {
            if let Some(first) = positions.first() {
                for payload in &first.payloads {
                    let combo: Vec<(String, String)> =
                        positions.iter().map(|p| (p.marker.clone(), payload.clone())).collect();
                    combos.push(combo);
                    if combos.len() >= max_requests {
                        return Ok(combos);
                    }
                }
            }
        }
        "pitchfork" => {
            let min_len = positions.iter().map(|p| p.payloads.len()).min().unwrap_or(0);
            for i in 0..min_len {
                let combo: Vec<(String, String)> =
                    positions.iter().map(|p| (p.marker.clone(), p.payloads[i].clone())).collect();
                combos.push(combo);
                if combos.len() >= max_requests {
                    return Ok(combos);
                }
            }
        }
        "cluster_bomb" | "clusterbomb" => {
            let mut indices = vec![0usize; positions.len()];
            loop {
                let combo: Vec<(String, String)> = positions
                    .iter()
                    .enumerate()
                    .map(|(i, p)| (p.marker.clone(), p.payloads[indices[i]].clone()))
                    .collect();
                combos.push(combo);
                if combos.len() >= max_requests {
                    return Ok(combos);
                }

                let mut carry = true;
                for i in (0..positions.len()).rev() {
                    if carry {
                        indices[i] += 1;
                        if indices[i] >= positions[i].payloads.len() {
                            indices[i] = 0;
                        } else {
                            carry = false;
                        }
                    }
                }
                if carry {
                    break;
                } // All combinations exhausted
            }
        }
        _ => {
            return Err(format!(
                "Unknown attack type: {}. Use: sniper, battering_ram, pitchfork, cluster_bomb",
                attack_type
            ))
        }
    }

    Ok(combos)
}

fn strip_markers(template: &str, positions: &[PositionInfo]) -> String {
    let mut result = template.to_string();
    for pos in positions {
        result = result.replace(&pos.marker, "");
    }
    result
}

fn parse_match_rules(rules_val: &serde_json::Value) -> Vec<MatchRule> {
    let mut rules = Vec::new();
    if let Some(arr) = rules_val.as_array() {
        for rule in arr {
            let rule_type = rule["type"].as_str().unwrap_or("");
            match rule_type {
                "status_code" => {
                    if let Some(vals) = rule["values"].as_array() {
                        let codes: Vec<u16> =
                            vals.iter().filter_map(|v| v.as_u64().map(|n| n as u16)).collect();
                        rules.push(MatchRule::StatusCode(codes));
                    }
                }
                "length_diff" => {
                    let threshold = rule["threshold"].as_u64().unwrap_or(100) as usize;
                    rules.push(MatchRule::LengthDiff(threshold));
                }
                "body_contains" => {
                    if let Some(val) = rule["value"].as_str() {
                        rules.push(MatchRule::BodyContains(val.to_string()));
                    }
                }
                "body_regex" => {
                    if let Some(pat) = rule["pattern"].as_str() {
                        rules.push(MatchRule::BodyRegex(pat.to_string()));
                    }
                }
                "timing" => {
                    let threshold = rule["threshold_ms"].as_u64().unwrap_or(3000);
                    rules.push(MatchRule::Timing(threshold));
                }
                "status_diff" => {
                    rules.push(MatchRule::StatusDiff);
                }
                _ => {}
            }
        }
    }
    if rules.is_empty() {
        rules.push(MatchRule::LengthDiff(200));
        rules.push(MatchRule::StatusDiff);
        rules.push(MatchRule::Timing(5000));
    }
    rules
}

fn check_matches(
    result: &ResponseInfo,
    baseline: &ResponseInfo,
    rules: &[MatchRule],
    length_diff: usize,
    time_ms: u64,
) -> Vec<String> {
    let mut matched = Vec::new();
    for rule in rules {
        match rule {
            MatchRule::StatusCode(codes) => {
                if codes.contains(&result.status) {
                    matched.push(format!("status_code:{}", result.status));
                }
            }
            MatchRule::LengthDiff(threshold) => {
                if length_diff >= *threshold {
                    matched.push(format!("length_diff:{}", length_diff));
                }
            }
            MatchRule::BodyContains(val) => {
                if result.body.contains(val.as_str()) {
                    matched.push(format!("body_contains:{}", val));
                }
            }
            MatchRule::BodyRegex(pat) => {
                if let Ok(re) = regex::Regex::new(pat) {
                    if re.is_match(&result.body) {
                        matched.push(format!("body_regex:{}", pat));
                    }
                }
            }
            MatchRule::Timing(threshold) => {
                if time_ms >= *threshold {
                    matched.push(format!("timing:{}ms", time_ms));
                }
            }
            MatchRule::StatusDiff => {
                if result.status != baseline.status {
                    matched.push(format!("status_diff:{}→{}", baseline.status, result.status));
                }
            }
        }
    }
    matched
}

async fn send_one(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: &str,
) -> ResponseInfo {
    let mut req = match method.to_uppercase().as_str() {
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        "HEAD" => client.head(url),
        _ => client.get(url),
    };
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if !body.is_empty() {
        req = req.body(body.to_string());
    }

    let start = std::time::Instant::now();
    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body_text = resp.text().await.unwrap_or_default();
            let length = body_text.len();
            let time_ms = start.elapsed().as_millis() as u64;
            ResponseInfo { status, length, body: body_text, time_ms }
        }
        Err(_) => ResponseInfo {
            status: 0,
            length: 0,
            body: String::new(),
            time_ms: start.elapsed().as_millis() as u64,
        },
    }
}
