// MCP handler for `js_library_audit` — detect-only.
//
// Inputs (one required):
//   - `url`         → fetch the URL's HTML, scan
//   - `html`        → scan HTML provided directly
//   - `traffic_id`  → pull response from proxy traffic log, scan
//   - `js`          → scan a single JS body
//
// Optional:
//   - `follow_scripts` (bool, default false) — when scanning HTML/URL, also
//     fetch each external `<script src="…">` and scan its body for inline
//     version comments. Catches minified libs whose CDN URL is generic
//     (`bundle.min.js`) but whose header comment survived.
//   - `follow_limit` (int, default 8) — max scripts to follow.
//
// Output:
//   - `detections: [{library, version, source, evidence, script_url}]`
//   - `scripts_followed: [url, …]` if follow_scripts
//   - Metadata: `library_db_size`, scan input shape
//
// The handler explicitly does NOT include CVE / vulnerability information.
// The AI agent does that research separately (web search + own knowledge).

use crate::mcp::types::HandlerResult;
use crate::proxy::state::TrafficEntry;
use crate::proxy_commands::get_global_proxy_state;

pub async fn handle_js_library_audit(params: &serde_json::Value) -> HandlerResult {
    let follow_scripts = params["follow_scripts"].as_bool().unwrap_or(false);
    let follow_limit = params["follow_limit"].as_u64().unwrap_or(8) as usize;

    let url_param = params["url"].as_str();
    let html_param = params["html"].as_str();
    let js_param = params["js"].as_str();
    let traffic_id_param = params["traffic_id"].as_u64();

    if url_param.is_none() && html_param.is_none() && js_param.is_none() && traffic_id_param.is_none() {
        return Err("Provide one of: `url`, `html`, `js`, or `traffic_id`. The tool only DETECTS \
             libraries + versions; CVE research is on the agent."
            .into());
    }

    let mut detections: Vec<crate::jslib::Detection> = Vec::new();
    let mut scripts_followed: Vec<String> = Vec::new();
    let mut input_kind = "";
    let mut input_size = 0usize;
    let mut input_url: Option<String> = None;

    // --- 1) Fetch by URL ---------------------------------------------------
    let html_owned: String = if let Some(u) = url_param {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WonderSuite/1.0")
            .build()
            .map_err(|e| format!("Client error: {}", e))?;
        let resp = client.get(u).send().await.map_err(|e| format!("Fetch failed: {}", e))?;
        let body = resp.text().await.unwrap_or_default();
        input_kind = "url";
        input_size = body.len();
        input_url = Some(u.to_string());
        body
    } else if let Some(h) = html_param {
        input_kind = "html";
        input_size = h.len();
        h.to_string()
    } else if let Some(tid) = traffic_id_param {
        let ps = get_global_proxy_state().ok_or("Proxy state not initialized")?;
        let traffic = ps.traffic.lock().await;
        let entry: &TrafficEntry =
            traffic.iter().find(|e| e.id == tid).ok_or_else(|| format!("Traffic entry {} not found", tid))?;
        input_kind = "traffic_id";
        input_size = entry.response_body.len();
        input_url = Some(entry.url.clone());
        entry.response_body.clone()
    } else {
        String::new()
    };

    // --- 2) Scan HTML / response body --------------------------------------
    if !html_owned.is_empty() {
        detections.extend(crate::jslib::detect_in_html(&html_owned));

        // --- 3) Optionally follow external script srcs ---------------------
        if follow_scripts {
            let srcs = crate::jslib::extract_script_srcs(&html_owned);
            let base = input_url.as_deref();
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::limited(3))
                .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WonderSuite/1.0")
                .build()
                .map_err(|e| format!("Client error: {}", e))?;
            for src in srcs.into_iter().take(follow_limit) {
                // Resolve relative URLs against the input URL.
                let abs = match base.and_then(|b| url::Url::parse(b).ok()) {
                    Some(base_url) => base_url.join(&src).map(|u| u.to_string()).unwrap_or(src.clone()),
                    None => src.clone(),
                };
                let Ok(resp) = client.get(&abs).send().await else {
                    continue;
                };
                let body = resp.text().await.unwrap_or_default();
                if body.is_empty() {
                    continue;
                }
                let mut more = crate::jslib::detect_in_js(&body, Some(&abs));
                detections.append(&mut more);
                scripts_followed.push(abs);
            }
        }
    }

    // --- 4) Standalone JS body input ---------------------------------------
    if let Some(js) = js_param {
        input_kind = "js";
        input_size = js.len();
        detections.extend(crate::jslib::detect_in_js(js, None));
    }

    // De-dup by (library, version) preserving first-seen evidence.
    let mut seen: std::collections::HashSet<(String, Option<String>)> = std::collections::HashSet::new();
    detections.retain(|d| seen.insert((d.library.clone(), d.version.clone())));

    // Count libraries with vs without an extracted version.
    let with_version = detections.iter().filter(|d| d.version.is_some()).count();
    let without_version = detections.len() - with_version;

    Ok(serde_json::json!({
        "input_kind": input_kind,
        "input_size_bytes": input_size,
        "input_url": input_url,
        "library_db_size": crate::jslib::library_count(),
        "detection_count": detections.len(),
        "with_version": with_version,
        "without_version": without_version,
        "scripts_followed": scripts_followed,
        "detections": detections,
        "note": "Detection only — CVE / vulnerability lookup is the agent's job. Use web search or your own knowledge to assess each (library, version) pair. Pay attention to detections marked source=script_src AND a CDN URL pinning a specific version (cdnjs / unpkg / jsDelivr) — those are highest-confidence."
    }))
}
