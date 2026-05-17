// v0.3.10: MCP wrappers around the existing Intruder Tauri commands. The
// agent's previous chain ended at `send_to_intruder` (which returned an
// `intruder_config` but had nowhere to send it). Now the agent can:
//
//   send_to_intruder         → intruder_config (template + positions)
//   intruder_start           → attack_id (running)
//   intruder_status          → poll progress
//   intruder_results         → fetch finished results (filterable by grep)
//   intruder_stop            → kill an in-flight attack
//   intruder_list            → list all attacks (active + completed)
//
// The underlying engine lives in `crate::intruder`; we reach into its
// `IntruderState` global to drive it without re-implementing the runner.

use crate::mcp::types::HandlerResult;

/// Start an Intruder attack. Accepts either:
///   - an `intruder_config` object (the exact shape `send_to_intruder`
///     returns) — fastest path for chained workflows; OR
///   - explicit `request_template`, `payload_sets`, `grep_rules`,
///     `threads`, `throttle_ms`, `follow_redirects`, `attack_type`.
///
/// Returns `attack_id` for polling via `intruder_status` / `intruder_results`.
pub async fn handle_intruder_start(params: &serde_json::Value) -> HandlerResult {
    let state = crate::intruder::intruder_state()
        .ok_or_else(|| "Intruder state not initialized — cannot start attack".to_string())?;

    // Accept the `intruder_config` shape from send_to_intruder, OR explicit
    // fields. Translate to the engine's IntruderConfig.
    let cfg_val = if let Some(c) = params.get("intruder_config") { c.clone() } else { params.clone() };

    // Build the request_template from base_request if provided.
    let request_template = if let Some(tmpl) = cfg_val["request_template"].as_str() {
        tmpl.to_string()
    } else if let Some(br) = cfg_val.get("base_request") {
        build_template_from_base(br)
    } else {
        return Err(
            "Provide `request_template` (raw HTTP) or `base_request` (structured) — neither given.".into()
        );
    };

    let attack_type = cfg_val["attack_type"].as_str().unwrap_or("sniper").to_string();
    let threads =
        cfg_val["max_concurrent"].as_u64().or_else(|| cfg_val["threads"].as_u64()).unwrap_or(10) as usize;
    let throttle_ms = cfg_val["delay_ms"].as_u64().or_else(|| cfg_val["throttle_ms"].as_u64()).unwrap_or(0);
    let follow_redirects = cfg_val["follow_redirects"].as_bool().unwrap_or(false);

    // Translate `positions` (intruder_config) OR `payload_sets` (raw) into
    // PayloadSets. send_to_intruder positions carry their payload-category
    // hint, so we generate from the payload manager.
    let payload_sets = if let Some(positions) = cfg_val.get("positions").and_then(|v| v.as_array()) {
        positions
            .iter()
            .filter_map(|p| {
                let marker = p["marker"].as_str()?;
                let category = p["file_category"].as_str().unwrap_or("fuzzing");
                let limit = p["limit"].as_u64().unwrap_or(200) as usize;
                let payloads = load_payloads_for_category(category, limit);
                Some(serde_json::json!({
                    "marker": marker,
                    "payload_type": "list",
                    "payloads": payloads,
                }))
            })
            .collect::<Vec<_>>()
    } else if let Some(arr) = cfg_val.get("payload_sets").and_then(|v| v.as_array()) {
        arr.clone()
    } else {
        return Err("Provide `positions` (from send_to_intruder) or `payload_sets`.".into());
    };

    let grep_rules = cfg_val.get("grep_rules").and_then(|v| v.as_array()).cloned().unwrap_or_default();

    // Hand off to the engine via a constructed IntruderConfig JSON. We can't
    // call the #[tauri::command] directly (it wants a State<>), so we
    // replicate the engine entry point using the same internals.
    let config_json = serde_json::json!({
        "attack_type": attack_type,
        "request_template": request_template,
        "payload_sets": payload_sets,
        "grep_rules": grep_rules,
        "threads": threads,
        "throttle_ms": throttle_ms,
        "follow_redirects": follow_redirects,
    });
    let cfg: crate::intruder::IntruderConfig =
        serde_json::from_value(config_json).map_err(|e| format!("Failed to build IntruderConfig: {}", e))?;

    let attack_id = crate::intruder::start_attack_from_state(state, cfg).await?;
    Ok(serde_json::json!({
        "attack_id": attack_id,
        "status": "started",
        "next_step": format!("Poll progress with intruder_status attack_id={}", attack_id),
    }))
}

pub async fn handle_intruder_stop(params: &serde_json::Value) -> HandlerResult {
    let state =
        crate::intruder::intruder_state().ok_or_else(|| "Intruder state not initialized".to_string())?;
    let attack_id = params["attack_id"].as_str().ok_or("attack_id required")?;
    let mut mgr = state.lock().await;
    let attack = mgr.attacks.get_mut(attack_id).ok_or_else(|| format!("Attack {} not found", attack_id))?;
    attack.status = "stopped".into();
    Ok(serde_json::json!({"attack_id": attack_id, "status": "stopped"}))
}

pub async fn handle_intruder_status(params: &serde_json::Value) -> HandlerResult {
    let state =
        crate::intruder::intruder_state().ok_or_else(|| "Intruder state not initialized".to_string())?;
    let attack_id = params["attack_id"].as_str().ok_or("attack_id required")?;
    let mgr = state.lock().await;
    let attack = mgr.attacks.get(attack_id).ok_or_else(|| format!("Attack {} not found", attack_id))?;
    Ok(serde_json::json!({
        "attack_id": attack.id,
        "status": attack.status,
        "completed_payloads": attack.completed_payloads,
        "total_payloads": attack.total_payloads,
        "elapsed_ms": attack.elapsed_ms,
        "started_at": attack.started_at,
        "results_count": attack.results.len(),
        "anomaly_count": attack.results.iter().filter(|r| r.grep_match).count(),
    }))
}

pub async fn handle_intruder_results(params: &serde_json::Value) -> HandlerResult {
    let state =
        crate::intruder::intruder_state().ok_or_else(|| "Intruder state not initialized".to_string())?;
    let attack_id = params["attack_id"].as_str().ok_or("attack_id required")?;
    let only_anomalies = params["only_anomalies"].as_bool().unwrap_or(false);
    let limit = params["limit"].as_u64().unwrap_or(100) as usize;
    let offset = params["offset"].as_u64().unwrap_or(0) as usize;
    let status_filter = params["status_filter"].as_u64().map(|v| v as u16);

    let mgr = state.lock().await;
    let attack = mgr.attacks.get(attack_id).ok_or_else(|| format!("Attack {} not found", attack_id))?;

    let results: Vec<&crate::intruder::AttackResult> = attack
        .results
        .iter()
        .filter(|r| !only_anomalies || r.grep_match)
        .filter(|r| status_filter.map(|s| r.status == s).unwrap_or(true))
        .skip(offset)
        .take(limit)
        .collect();

    Ok(serde_json::json!({
        "attack_id": attack.id,
        "status": attack.status,
        "total": attack.results.len(),
        "returned": results.len(),
        "results": results,
    }))
}

pub async fn handle_intruder_list(_params: &serde_json::Value) -> HandlerResult {
    let state =
        crate::intruder::intruder_state().ok_or_else(|| "Intruder state not initialized".to_string())?;
    let mgr = state.lock().await;
    let attacks: Vec<serde_json::Value> = mgr
        .attacks
        .values()
        .map(|a| {
            serde_json::json!({
                "attack_id": a.id,
                "status": a.status,
                "attack_type": a.attack_type,
                "completed": a.completed_payloads,
                "total": a.total_payloads,
                "elapsed_ms": a.elapsed_ms,
                "started_at": a.started_at,
                "anomalies": a.results.iter().filter(|r| r.grep_match).count(),
            })
        })
        .collect();
    Ok(serde_json::json!({"count": attacks.len(), "attacks": attacks}))
}

/// Build a raw-HTTP request_template from the `base_request` shape used by
/// send_to_intruder's `intruder_config.base_request`. The engine consumes
/// raw templates (`METHOD path HTTP/1.1\r\nHeader: …\r\n\r\nbody`), so we
/// stringify the structured form here.
fn build_template_from_base(br: &serde_json::Value) -> String {
    let method = br["method"].as_str().unwrap_or("GET");
    let url = br["url"].as_str().unwrap_or("/");
    let body = br["body"].as_str().unwrap_or("");
    let headers = br["headers"].as_object();

    // Extract path + Host from the URL.
    let (host, path) = if let Ok(parsed) = url::Url::parse(url) {
        let h = parsed.host_str().unwrap_or("").to_string();
        let p = if parsed.query().is_some() {
            format!("{}?{}", parsed.path(), parsed.query().unwrap_or(""))
        } else {
            parsed.path().to_string()
        };
        (h, p)
    } else {
        (String::new(), url.to_string())
    };

    let mut out = format!("{} {} HTTP/1.1\r\n", method, path);
    if !host.is_empty() {
        out.push_str(&format!("Host: {}\r\n", host));
    }
    if let Some(map) = headers {
        for (k, v) in map {
            if k.eq_ignore_ascii_case("host") {
                continue;
            }
            if let Some(s) = v.as_str() {
                out.push_str(&format!("{}: {}\r\n", k, s));
            }
        }
    }
    out.push_str("\r\n");
    out.push_str(body);
    out
}

fn load_payloads_for_category(category: &str, limit: usize) -> Vec<String> {
    let mut mgr = crate::mcp::handlers::payloads::manager();
    mgr.load(category).unwrap_or_default().into_iter().take(limit).collect()
}
