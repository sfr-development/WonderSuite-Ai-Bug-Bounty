// Shared request-source resolution for passive_scan and active_scan.
//
// Both scanners historically took only a `target` URL and forced GET — which
// meant any non-GET vulnerability (POST/PUT JSON APIs, GraphQL mutations,
// authenticated flows where the cookie/Authorization header lives only in the
// intercepted request) was unreachable. v0.3.8 fixes the gap: the scanner can
// now inherit the original method, headers, AND body from either:
//
//   - `intercept_id` — UUID of an on-hold intercepted item (the bridge that
//     previously didn't exist; you can attack a request WITHOUT forwarding it)
//   - `traffic_id` — numeric ID from the traffic log
//   - explicit `target` + optional `method` / `headers` / `body` overrides
//
// All three paths produce a `ResolvedSource` the scanner can `replay()` to
// issue baseline / probe requests with the correct shape.

use crate::mcp::handlers::proxy::{fetch_intercepted, ParsedRawRequest};
use crate::proxy::state::ProxyState;
use crate::proxy_commands::get_global_proxy_state;
use std::collections::HashMap;
use std::sync::Arc;

/// A scanner request template — method + url + headers + body. Built from
/// intercept_id, traffic_id, or explicit target/method/headers/body params.
#[derive(Debug, Clone)]
pub struct ResolvedSource {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    /// True iff the source was derived from intercept_id / traffic_id (so the
    /// scanner can include this in the response for the agent's audit trail).
    pub origin: &'static str,
}

impl ResolvedSource {
    /// Build a reqwest::RequestBuilder targeting `url`, preserving method,
    /// headers (with hop-by-hop / host stripped — reqwest sets those itself),
    /// and body. Headers from the scanner's own logic (e.g. CORS Origin tests)
    /// can be added by the caller after this returns.
    pub fn builder(&self, client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
        let method = reqwest::Method::from_bytes(self.method.as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut req = client.request(method, url);

        // Strip headers that reqwest manages itself or that would break the
        // request when copy-pasted across origins. host/content-length/
        // connection/transfer-encoding are computed; cookies are kept (key
        // for auth replay); origin/referer kept too (some apps require them).
        const STRIP: &[&str] =
            &["host", "content-length", "connection", "transfer-encoding", "accept-encoding"];

        for (k, v) in &self.headers {
            if STRIP.iter().any(|s| k.eq_ignore_ascii_case(s)) {
                continue;
            }
            req = req.header(k.as_str(), v.as_str());
        }

        if !self.body.is_empty() {
            req = req.body(self.body.clone());
        }
        req
    }
}

/// Resolve a scanner source from `params`. Priority:
///   1. `intercept_id` (UUID) → fetch from pending_intercepts
///   2. `traffic_id` (number) → fetch from traffic log
///   3. `target` (URL) + optional method/headers/body
///
/// `method` / `headers` / `body` in `params` always *override* whatever came
/// from intercept/traffic, so the agent can tweak just one field.
pub async fn resolve(params: &serde_json::Value) -> Result<ResolvedSource, String> {
    let intercept_id = params["intercept_id"].as_str();
    let traffic_id = params["traffic_id"].as_u64();
    let target = params["target"].as_str();

    // Common path: pull from proxy state if either intercept_id or traffic_id
    // is given. Both require the proxy to be initialized.
    let mut base: Option<(String, String, HashMap<String, String>, String, &'static str)> = None;

    if let Some(iid) = intercept_id {
        let ps = ps_or_err()?;
        let parsed = fetch_intercepted(&ps, iid).await?;
        let ParsedRawRequest { method, url, headers, body } = parsed;
        base = Some((method, url, headers, body, "intercept"));
    } else if let Some(tid) = traffic_id {
        let ps = ps_or_err()?;
        let traffic = ps.traffic.lock().await;
        let entry =
            traffic.iter().find(|e| e.id == tid).ok_or_else(|| format!("Traffic entry {} not found", tid))?;
        let headers: HashMap<String, String> = entry
            .request_headers
            .lines()
            .filter_map(|line| {
                line.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            })
            .collect();
        base =
            Some((entry.method.clone(), entry.url.clone(), headers, entry.request_body.clone(), "traffic"));
    }

    let (mut method, mut url, mut headers, mut body, origin) = match base {
        Some(b) => b,
        None => {
            let t = target.ok_or("One of `intercept_id`, `traffic_id`, or `target` is required.")?;
            ("GET".to_string(), t.to_string(), HashMap::new(), String::new(), "explicit")
        }
    };

    // Overrides. `target` swaps the URL regardless of origin (lets agents
    // attack a *modified* URL with the original request's headers/body).
    if let Some(t) = target {
        url = t.to_string();
    }
    if let Some(m) = params["method"].as_str() {
        method = m.to_string();
    }
    if let Some(b) = params["body"].as_str() {
        body = b.to_string();
    }
    if let Some(obj) = params["headers"].as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                headers.insert(k.clone(), s.to_string());
            }
        }
    }

    Ok(ResolvedSource { method, url, headers, body, origin })
}

fn ps_or_err() -> Result<Arc<ProxyState>, String> {
    get_global_proxy_state().ok_or_else(|| {
        "Proxy not initialized — start the proxy before using intercept_id / traffic_id.".to_string()
    })
}

/// Extract form-urlencoded key=value pairs from a body string. Used by
/// active_scan to inject payloads into body parameters in addition to query.
pub fn parse_form_body(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter_map(|pair| pair.split_once('=').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

/// Replace a form-urlencoded body parameter's value with a new value.
/// Returns the rebuilt body. If `param_name` is not in `body`, returns `body`
/// unchanged.
pub fn replace_form_param(body: &str, param_name: &str, new_value: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut found = false;
    for pair in body.split('&') {
        if let Some((k, _)) = pair.split_once('=') {
            if k.trim() == param_name {
                out.push(format!("{}={}", k, new_value));
                found = true;
                continue;
            }
        }
        out.push(pair.to_string());
    }
    if found {
        out.join("&")
    } else {
        body.to_string()
    }
}

/// Replace a top-level JSON-body parameter's value with a string payload.
/// Best-effort: only handles flat objects; nested keys are skipped. Returns
/// the rebuilt body, or the original body if `param_name` is not present.
pub fn replace_json_param(body: &str, param_name: &str, new_value: &str) -> String {
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(body) else {
        return body.to_string();
    };
    let Some(obj) = v.as_object_mut() else {
        return body.to_string();
    };
    if !obj.contains_key(param_name) {
        return body.to_string();
    }
    obj.insert(param_name.to_string(), serde_json::Value::String(new_value.to_string()));
    serde_json::to_string(&v).unwrap_or_else(|_| body.to_string())
}
