use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub type IntruderState = Arc<Mutex<IntruderManager>>;

// v0.3.10: global accessor so MCP handlers can drive the Intruder engine
// without a Tauri State<'_, _> wrapper. Populated at app startup mirroring
// the same OnceLock pattern used for proxy_commands::GLOBAL_PROXY_STATE.
static GLOBAL_INTRUDER_STATE: std::sync::OnceLock<IntruderState> = std::sync::OnceLock::new();

pub fn create_intruder_state() -> IntruderState {
    let s: IntruderState = Arc::new(Mutex::new(IntruderManager::new()));
    let _ = GLOBAL_INTRUDER_STATE.set(s.clone());
    s
}

pub fn intruder_state() -> Option<IntruderState> {
    GLOBAL_INTRUDER_STATE.get().cloned()
}

pub struct IntruderManager {
    pub attacks: HashMap<String, AttackState>,
}

impl IntruderManager {
    pub fn new() -> Self {
        Self { attacks: HashMap::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackState {
    pub id: String,
    pub status: String, // "running", "paused", "completed", "stopped"
    pub attack_type: String,
    pub request_template: String,
    pub results: Vec<AttackResult>,
    pub total_payloads: usize,
    pub completed_payloads: usize,
    pub started_at: String,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    pub id: usize,
    pub position: usize,
    pub payload: String,
    pub status: u16,
    pub length: usize,
    pub time_ms: u64,
    pub error: String,
    pub grep_match: bool,
    pub grep_extracts: HashMap<String, String>,
    pub response_headers: String,
    pub response_body_preview: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayloadSet {
    pub payload_type: String, // "simple_list", "numbers", "bruteforce", "null_payloads", "dates"
    pub values: Vec<String>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub step: Option<i64>,
    pub charset: Option<String>,
    pub min_len: Option<usize>,
    pub max_len: Option<usize>,
    pub count: Option<usize>,
    pub processors: Vec<PayloadProcessor>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayloadProcessor {
    pub processor_type: String, // url_encode, base64_encode, md5, sha1, sha256, prefix, suffix, match_replace, uppercase, lowercase, reverse
    pub value: Option<String>,
    pub replace_with: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GrepRule {
    pub rule_type: String, // "match" or "extract"
    pub pattern: String,
    pub name: Option<String>, // for extract
    pub group: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IntruderConfig {
    pub attack_type: String, // sniper, battering_ram, pitchfork, cluster_bomb
    pub request_template: String,
    pub payload_sets: Vec<PayloadSet>,
    pub grep_rules: Vec<GrepRule>,
    pub threads: usize,
    pub throttle_ms: u64,
    pub follow_redirects: bool,
}

fn generate_payloads(set: &PayloadSet) -> Vec<String> {
    let mut raw = match set.payload_type.as_str() {
        "numbers" => {
            let from = set.from.unwrap_or(0);
            let to = set.to.unwrap_or(100);
            let step = set.step.unwrap_or(1);
            let mut v = Vec::new();
            let mut i = from;
            while i <= to {
                v.push(i.to_string());
                i += step;
            }
            v
        }
        "null_payloads" => {
            vec!["".to_string(); set.count.unwrap_or(10)]
        }
        "bruteforce" => {
            let charset = set.charset.as_deref().unwrap_or("abcdefghijklmnopqrstuvwxyz0123456789");
            let min = set.min_len.unwrap_or(1);
            let max = set.max_len.unwrap_or(3);
            let chars: Vec<char> = charset.chars().collect();
            let mut results = Vec::new();
            for len in min..=max {
                generate_combinations(&chars, len, &mut String::new(), &mut results);
                if results.len() > 10000 {
                    break;
                } // Safety limit
            }
            results
        }
        _ => set.values.clone(), // simple_list
    };

    for proc in &set.processors {
        raw = raw.into_iter().map(|p| apply_processor(&p, proc)).collect();
    }

    raw
}

fn generate_combinations(chars: &[char], len: usize, current: &mut String, results: &mut Vec<String>) {
    if current.len() == len {
        results.push(current.clone());
        return;
    }
    if results.len() > 10000 {
        return;
    }
    for &c in chars {
        current.push(c);
        generate_combinations(chars, len, current, results);
        current.pop();
    }
}

fn apply_processor(payload: &str, proc: &PayloadProcessor) -> String {
    match proc.processor_type.as_str() {
        "url_encode" => urlencoding::encode(payload).to_string(),
        "url_decode" => urlencoding::decode(payload).unwrap_or_else(|_| payload.into()).to_string(),
        "base64_encode" => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(payload.as_bytes())
        }
        "base64_decode" => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(payload)
                .map(|b| String::from_utf8_lossy(&b).to_string())
                .unwrap_or_else(|_| payload.to_string())
        }
        "md5" => format!("{:x}", md5::compute(payload.as_bytes())),
        "sha256" => {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(payload.as_bytes());
            format!("{:x}", hash)
        }
        "sha1" => {
            use sha1::Digest;
            let hash = sha1::Sha1::digest(payload.as_bytes());
            format!("{:x}", hash)
        }
        "prefix" => format!("{}{}", proc.value.as_deref().unwrap_or(""), payload),
        "suffix" => format!("{}{}", payload, proc.value.as_deref().unwrap_or("")),
        "match_replace" => {
            if let (Some(pattern), Some(replacement)) = (&proc.value, &proc.replace_with) {
                payload.replace(pattern.as_str(), replacement)
            } else {
                payload.to_string()
            }
        }
        "uppercase" => payload.to_uppercase(),
        "lowercase" => payload.to_lowercase(),
        "reverse" => payload.chars().rev().collect(),
        "hex_encode" => payload.as_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
        "html_encode" => {
            payload.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
        }
        _ => payload.to_string(),
    }
}

fn extract_positions(template: &str) -> Vec<(usize, usize, String)> {
    let mut positions = Vec::new();
    let bytes = template.as_bytes();
    let marker = b'\xc2'; // § first byte in UTF-8
    let marker2 = b'\xa7'; // § second byte
    let mut i = 0;
    while i < bytes.len().saturating_sub(1) {
        if bytes[i] == marker && bytes[i + 1] == marker2 {
            let start = i;
            i += 2;
            let content_start = i;
            while i < bytes.len().saturating_sub(1) {
                if bytes[i] == marker && bytes[i + 1] == marker2 {
                    let content = String::from_utf8_lossy(&bytes[content_start..i]).to_string();
                    positions.push((start, i + 2, content));
                    i += 2;
                    break;
                }
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    positions
}

fn inject_payload(template: &str, positions: &[(usize, usize, String)], payloads: &[&str]) -> String {
    let mut result = String::new();
    let mut last_end = 0;
    for (i, (start, end, _)) in positions.iter().enumerate() {
        result.push_str(&template[last_end..*start]);
        if i < payloads.len() {
            result.push_str(payloads[i]);
        }
        last_end = *end;
    }
    result.push_str(&template[last_end..]);
    result
}

fn parse_request_template(raw: &str) -> (String, String, Vec<(String, String)>, Option<String>) {
    let parts: Vec<&str> = raw.splitn(2, "\n\n").collect();
    let header_section = parts[0];
    let body = parts.get(1).map(|b| b.to_string());

    let lines: Vec<&str> = header_section.lines().collect();
    let first = lines.first().unwrap_or(&"GET / HTTP/1.1");
    let first_parts: Vec<&str> = first.split_whitespace().collect();
    let method = first_parts.first().unwrap_or(&"GET").to_string();
    let path = first_parts.get(1).unwrap_or(&"/").to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut host = String::new();
    for line in &lines[1..] {
        if let Some(idx) = line.find(':') {
            let key = line[..idx].trim().to_string();
            let val = line[idx + 1..].trim().to_string();
            if key.to_lowercase() == "host" {
                host = val.clone();
            }
            headers.push((key, val));
        }
    }

    let url = if path.starts_with("http") { path } else { format!("https://{}{}", host, path) };

    (method, url, headers, body)
}

#[tauri::command]
pub async fn intruder_start(
    state: tauri::State<'_, IntruderState>,
    config: IntruderConfig,
) -> Result<String, String> {
    let state_clone = state.inner().clone();
    start_attack_from_state(state_clone, config).await
}

/// v0.3.10: reusable engine entry that doesn't require a Tauri `State` —
/// used by the MCP `intruder_start` handler so the AI agent can drive the
/// Intruder without going through Tauri IPC.
pub async fn start_attack_from_state(state: IntruderState, config: IntruderConfig) -> Result<String, String> {
    let attack_id = uuid::Uuid::new_v4().to_string();
    let aid = attack_id.clone();

    let payload_sets: Vec<Vec<String>> = config.payload_sets.iter().map(|s| generate_payloads(s)).collect();

    let positions = extract_positions(&config.request_template);
    if positions.is_empty() {
        return Err("No injection positions found (mark with §)".into());
    }

    let payload_matrix: Vec<Vec<String>> = match config.attack_type.as_str() {
        "battering_ram" => {
            let set = payload_sets.first().cloned().unwrap_or_default();
            set.into_iter().map(|p| vec![p; positions.len()]).collect()
        }
        "pitchfork" => {
            let max_len = payload_sets.iter().map(|s| s.len()).min().unwrap_or(0);
            (0..max_len)
                .map(|i| payload_sets.iter().map(|s| s.get(i).cloned().unwrap_or_default()).collect())
                .collect()
        }
        "cluster_bomb" => {
            let mut combos: Vec<Vec<String>> = vec![vec![]];
            for set in &payload_sets {
                let mut new_combos = Vec::new();
                for combo in &combos {
                    for payload in set {
                        let mut new = combo.clone();
                        new.push(payload.clone());
                        new_combos.push(new);
                    }
                }
                combos = new_combos;
                if combos.len() > 100000 {
                    break;
                } // Safety
            }
            combos
        }
        _ => {
            // sniper
            let set = payload_sets.first().cloned().unwrap_or_default();
            let mut all = Vec::new();
            for pos_idx in 0..positions.len() {
                for payload in &set {
                    let mut row: Vec<String> = positions.iter().map(|(_, _, orig)| orig.clone()).collect();
                    row[pos_idx] = payload.clone();
                    all.push(row);
                }
            }
            all
        }
    };

    let total = payload_matrix.len();

    {
        let mut mgr = state.lock().await;
        mgr.attacks.insert(
            aid.clone(),
            AttackState {
                id: aid.clone(),
                status: "running".into(),
                attack_type: config.attack_type.clone(),
                request_template: config.request_template.clone(),
                results: Vec::new(),
                total_payloads: total,
                completed_payloads: 0,
                started_at: chrono_now(),
                elapsed_ms: 0,
            },
        );
    }

    let state_clone = state.clone();
    let template = config.request_template.clone();
    let grep_rules = config.grep_rules.clone();
    let throttle = config.throttle_ms;
    let follow_redirects = config.follow_redirects;
    // v0.3.10: `config.threads` is finally honored. Defaults to 10 if the
    // caller passes 0 (the JSON-default route). Previously the runner was a
    // strict sequential `for` loop — documented multi-thread feature was a
    // lie. Now: bounded concurrency via tokio::Semaphore so #threads is the
    // ceiling AND throttle still applies between dispatches.
    let concurrency = if config.threads == 0 { 10 } else { config.threads };

    tokio::spawn(async move {
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(15))
            .redirect(if follow_redirects {
                reqwest::redirect::Policy::limited(5)
            } else {
                reqwest::redirect::Policy::none()
            })
            .build()
            .unwrap_or_default();

        let start = std::time::Instant::now();
        let sem = Arc::new(Semaphore::new(concurrency));
        let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        for (i, payloads) in payload_matrix.iter().enumerate() {
            // Pause / stop check — once per dispatch. Cheap, just reads the
            // attack status from the manager.
            loop {
                let mgr = state_clone.lock().await;
                if let Some(attack) = mgr.attacks.get(&aid) {
                    if attack.status == "stopped" {
                        // Stop signal — wait for in-flight to drain, then exit.
                        drop(mgr);
                        for h in handles.drain(..) {
                            let _ = h.await;
                        }
                        let mut mgr = state_clone.lock().await;
                        if let Some(attack) = mgr.attacks.get_mut(&aid) {
                            attack.elapsed_ms = start.elapsed().as_millis() as u64;
                        }
                        return;
                    }
                    if attack.status != "paused" {
                        break;
                    }
                    drop(mgr);
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    continue;
                }
                drop(mgr);
                break;
            }

            // Acquire a permit (this throttles concurrency without coupling
            // it to dispatch timing).
            let permit = match sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };

            // Per-payload owned data for the spawned task.
            let payload_refs: Vec<String> = payloads.clone();
            let injected = {
                let refs: Vec<&str> = payload_refs.iter().map(|s| s.as_str()).collect();
                inject_payload(&template, &positions, &refs)
            };
            let (method, url, headers, body) = parse_request_template(&injected);
            let client = client.clone();
            let grep_rules = grep_rules.clone();
            let state_for_task = state_clone.clone();
            let aid_for_task = aid.clone();
            let payload_label = payloads.join(" | ");

            let handle = tokio::spawn(async move {
                let _permit = permit; // released on drop
                let req_start = std::time::Instant::now();
                let mut result = AttackResult {
                    id: i + 1,
                    position: 0,
                    payload: payload_label,
                    status: 0,
                    length: 0,
                    time_ms: 0,
                    error: String::new(),
                    grep_match: false,
                    grep_extracts: HashMap::new(),
                    response_headers: String::new(),
                    response_body_preview: String::new(),
                };

                let req = match method.as_str() {
                    "POST" => client.post(&url),
                    "PUT" => client.put(&url),
                    "DELETE" => client.delete(&url),
                    "PATCH" => client.patch(&url),
                    _ => client.get(&url),
                };

                let mut req = req;
                for (k, v) in &headers {
                    if k.to_lowercase() != "host" && k.to_lowercase() != "content-length" {
                        req = req.header(k.as_str(), v.as_str());
                    }
                }
                if let Some(ref b) = body {
                    req = req.body(b.clone());
                }

                match req.send().await {
                    Ok(resp) => {
                        result.status = resp.status().as_u16();
                        result.response_headers = resp
                            .headers()
                            .iter()
                            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                            .collect::<Vec<_>>()
                            .join("\n");
                        let resp_body = resp.text().await.unwrap_or_default();
                        result.length = resp_body.len();
                        result.response_body_preview = resp_body.chars().take(2000).collect();
                        result.time_ms = req_start.elapsed().as_millis() as u64;

                        for rule in &grep_rules {
                            match rule.rule_type.as_str() {
                                "match" => match regex::Regex::new(&rule.pattern) {
                                    Ok(re) => {
                                        if re.is_match(&resp_body) {
                                            result.grep_match = true;
                                        }
                                    }
                                    _ => {
                                        if resp_body.contains(&rule.pattern) {
                                            result.grep_match = true;
                                        }
                                    }
                                },
                                "extract" => {
                                    if let Ok(re) = regex::Regex::new(&rule.pattern) {
                                        if let Some(caps) = re.captures(&resp_body) {
                                            let group = rule.group.unwrap_or(1);
                                            if let Some(m) = caps.get(group) {
                                                let name = rule
                                                    .name
                                                    .clone()
                                                    .unwrap_or_else(|| format!("extract_{}", group));
                                                result.grep_extracts.insert(name, m.as_str().to_string());
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        result.error = e.to_string();
                        result.time_ms = req_start.elapsed().as_millis() as u64;
                    }
                }

                let mut mgr = state_for_task.lock().await;
                if let Some(attack) = mgr.attacks.get_mut(&aid_for_task) {
                    attack.results.push(result);
                    attack.completed_payloads += 1;
                    attack.elapsed_ms = start.elapsed().as_millis() as u64;
                }
            });
            handles.push(handle);

            // Inter-dispatch throttle (NOT per completion). Cheap delay so we
            // can drip-feed concurrency on rate-limited targets.
            if throttle > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(throttle)).await;
            }
        }

        // Wait for every in-flight task to finish before marking the attack
        // completed. Results may be slightly out-of-order in `attack.results`
        // (each carries its own `id`), which is fine.
        for h in handles {
            let _ = h.await;
        }

        let mut mgr = state_clone.lock().await;
        if let Some(attack) = mgr.attacks.get_mut(&aid) {
            if attack.status == "running" {
                attack.status = "completed".into();
            }
            attack.elapsed_ms = start.elapsed().as_millis() as u64;
        }
    });

    Ok(attack_id)
}

#[tauri::command]
pub async fn intruder_stop(
    state: tauri::State<'_, IntruderState>,
    attack_id: String,
) -> Result<String, String> {
    let mut mgr = state.lock().await;
    if let Some(attack) = mgr.attacks.get_mut(&attack_id) {
        attack.status = "stopped".into();
        Ok("Attack stopped".into())
    } else {
        Err("Attack not found".into())
    }
}

#[tauri::command]
pub async fn intruder_pause(
    state: tauri::State<'_, IntruderState>,
    attack_id: String,
) -> Result<String, String> {
    let mut mgr = state.lock().await;
    if let Some(attack) = mgr.attacks.get_mut(&attack_id) {
        attack.status = "paused".into();
        Ok("Attack paused".into())
    } else {
        Err("Attack not found".into())
    }
}

#[tauri::command]
pub async fn intruder_resume(
    state: tauri::State<'_, IntruderState>,
    attack_id: String,
) -> Result<String, String> {
    let mut mgr = state.lock().await;
    if let Some(attack) = mgr.attacks.get_mut(&attack_id) {
        attack.status = "running".into();
        Ok("Attack resumed".into())
    } else {
        Err("Attack not found".into())
    }
}

#[tauri::command]
pub async fn intruder_status(
    state: tauri::State<'_, IntruderState>,
    attack_id: String,
) -> Result<serde_json::Value, String> {
    let mgr = state.lock().await;
    let attack = mgr.attacks.get(&attack_id).ok_or("Attack not found")?;
    Ok(serde_json::json!({
        "id": attack.id,
        "status": attack.status,
        "attack_type": attack.attack_type,
        "total_payloads": attack.total_payloads,
        "completed_payloads": attack.completed_payloads,
        "elapsed_ms": attack.elapsed_ms,
        "result_count": attack.results.len(),
    }))
}

#[tauri::command]
pub async fn intruder_results(
    state: tauri::State<'_, IntruderState>,
    attack_id: String,
    since_id: Option<usize>,
) -> Result<serde_json::Value, String> {
    let mgr = state.lock().await;
    let attack = mgr.attacks.get(&attack_id).ok_or("Attack not found")?;
    let from = since_id.unwrap_or(0);
    let results: Vec<&AttackResult> = attack.results.iter().filter(|r| r.id > from).collect();
    Ok(serde_json::json!({
        "status": attack.status,
        "total": attack.total_payloads,
        "completed": attack.completed_payloads,
        "elapsed_ms": attack.elapsed_ms,
        "results": results,
    }))
}

#[tauri::command]
pub async fn intruder_delete(
    state: tauri::State<'_, IntruderState>,
    attack_id: String,
) -> Result<String, String> {
    let mut mgr = state.lock().await;
    mgr.attacks.remove(&attack_id);
    Ok("Attack deleted".into())
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    format!("{}Z", now.as_secs())
}
