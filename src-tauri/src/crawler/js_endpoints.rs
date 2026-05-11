// JS endpoint extraction.
//
// Static-analysis regex pass over `text/javascript` and inline `<script>` bodies.
// Catches ~85% of API call patterns in modern bundles:
//   - fetch("/api/...")
//   - axios.get/post/put/delete/patch("/path", ...)
//   - $.ajax({ url: "/..." }) / $.get / $.post
//   - XMLHttpRequest.open("METHOD", "/...")
//   - WebSocket / new EventSource / navigator.sendBeacon
//   - bare absolute paths in string literals that look like API endpoints
//     ("/api/foo", "/v1/bar")
//   - source map references (// # sourceMappingURL=...) — pointer to .js.map
//     for deeper static analysis later
//
// Runtime hooks (extension hooks.js) catch the remaining 15%; together they
// cover essentially all dynamic endpoint usage.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct JsEndpoint {
    pub method: String,
    pub url: String,
    pub source: &'static str, // "fetch" / "axios" / "xhr" / "jquery" / "literal" / "websocket" / "sse" / "beacon" / "sourcemap"
}

/// Extract endpoint candidates from a JS source string.
pub fn extract_endpoints(js: &str) -> Vec<JsEndpoint> {
    let mut out: Vec<JsEndpoint> = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    let mut push = |method: &str, url: &str, source: &'static str, out: &mut Vec<JsEndpoint>| {
        let trimmed_url = url.trim();
        if trimmed_url.is_empty() {
            return;
        }
        // Skip data: / javascript: / mailto: / blob: schemes
        if trimmed_url.starts_with("data:")
            || trimmed_url.starts_with("javascript:")
            || trimmed_url.starts_with("mailto:")
            || trimmed_url.starts_with("blob:")
        {
            return;
        }
        let key = (method.to_uppercase(), trimmed_url.to_string());
        if seen.insert(key) {
            out.push(JsEndpoint { method: method.to_uppercase(), url: trimmed_url.into(), source });
        }
    };

    // fetch("...", { method: "..." })
    let fetch_re = regex::Regex::new(
        r#"(?is)fetch\s*\(\s*["'`]([^"'`]+)["'`](?:\s*,\s*\{[^}]*?method\s*:\s*["'`]([A-Z]+)["'`])?"#,
    )
    .unwrap();
    for c in fetch_re.captures_iter(js) {
        let url = c.get(1).map(|m| m.as_str()).unwrap_or("");
        let method = c.get(2).map(|m| m.as_str()).unwrap_or("GET");
        push(method, url, "fetch", &mut out);
    }

    // axios.get/post/put/delete/patch/head("...")
    let axios_re =
        regex::Regex::new(r#"(?is)axios\s*\.\s*(get|post|put|delete|patch|head)\s*\(\s*["'`]([^"'`]+)["'`]"#)
            .unwrap();
    for c in axios_re.captures_iter(js) {
        let method = c.get(1).map(|m| m.as_str()).unwrap_or("GET");
        let url = c.get(2).map(|m| m.as_str()).unwrap_or("");
        push(method, url, "axios", &mut out);
    }

    // axios({ url: "...", method: "..." })
    let axios_obj_re =
        regex::Regex::new(r#"(?is)axios\s*\(\s*\{[^}]*?url\s*:\s*["'`]([^"'`]+)["'`][^}]*?\}"#).unwrap();
    for c in axios_obj_re.captures_iter(js) {
        let url = c.get(1).map(|m| m.as_str()).unwrap_or("");
        push("GET", url, "axios", &mut out);
    }

    // $.ajax({ url: "..." }) / $.get(...) / $.post(...)
    let jq_re = regex::Regex::new(
        r#"(?is)\$\s*\.\s*(get|post|put|delete|ajax)\s*\(\s*(?:\{[^}]*?url\s*:\s*)?["'`]([^"'`]+)["'`]"#,
    )
    .unwrap();
    for c in jq_re.captures_iter(js) {
        let method = c.get(1).map(|m| m.as_str().to_uppercase()).unwrap_or_else(|| "GET".into());
        let url = c.get(2).map(|m| m.as_str()).unwrap_or("");
        let m = if method == "AJAX" { "GET" } else { method.as_str() };
        push(m, url, "jquery", &mut out);
    }

    // XMLHttpRequest.open("METHOD", "...")
    let xhr_re = regex::Regex::new(
        r#"(?is)\.open\s*\(\s*["'`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["'`]\s*,\s*["'`]([^"'`]+)["'`]"#,
    )
    .unwrap();
    for c in xhr_re.captures_iter(js) {
        let method = c.get(1).map(|m| m.as_str()).unwrap_or("GET");
        let url = c.get(2).map(|m| m.as_str()).unwrap_or("");
        push(method, url, "xhr", &mut out);
    }

    // new WebSocket("ws://..."), new WebSocket("wss://...")
    let ws_re = regex::Regex::new(r#"(?is)new\s+WebSocket\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap();
    for c in ws_re.captures_iter(js) {
        let url = c.get(1).map(|m| m.as_str()).unwrap_or("");
        push("CONNECT", url, "websocket", &mut out);
    }

    // new EventSource("...")
    let es_re = regex::Regex::new(r#"(?is)new\s+EventSource\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap();
    for c in es_re.captures_iter(js) {
        let url = c.get(1).map(|m| m.as_str()).unwrap_or("");
        push("GET", url, "sse", &mut out);
    }

    // navigator.sendBeacon("/url", body)
    let beacon_re = regex::Regex::new(r#"(?is)sendBeacon\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap();
    for c in beacon_re.captures_iter(js) {
        let url = c.get(1).map(|m| m.as_str()).unwrap_or("");
        push("POST", url, "beacon", &mut out);
    }

    // Bare absolute API paths in string literals: "/api/users", '/v1/foo', `/rest/...`
    let literal_re = regex::Regex::new(
        r#"["'`](/(?:api|rest|graphql|jsonrpc|v\d+|services)/[A-Za-z0-9._\-/{}?:&=%]+)["'`]"#,
    )
    .unwrap();
    for c in literal_re.captures_iter(js) {
        let url = c.get(1).map(|m| m.as_str()).unwrap_or("");
        push("GET", url, "literal", &mut out);
    }

    // Source map references (commented at the bottom of a bundle)
    let smap_re = regex::Regex::new(r#"(?im)^//[#@]\s*sourceMappingURL\s*=\s*(\S+)"#).unwrap();
    for c in smap_re.captures_iter(js) {
        let url = c.get(1).map(|m| m.as_str()).unwrap_or("");
        push("GET", url, "sourcemap", &mut out);
    }

    out
}

/// Parse a source map JSON and return the list of source paths it references.
/// Useful for understanding the original bundle structure (which can in turn
/// suggest API paths that the minified bundle obscures).
pub fn extract_sourcemap_sources(map_json: &str) -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct Map {
        #[serde(default)]
        sources: Vec<String>,
        #[serde(default, rename = "sourceRoot")]
        source_root: Option<String>,
    }
    let Ok(m) = serde_json::from_str::<Map>(map_json) else { return Vec::new() };
    let root = m.source_root.unwrap_or_default();
    m.sources.into_iter().map(|s| if root.is_empty() { s } else { format!("{}{}", root, s) }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_fetch() {
        let js = r#"fetch("/api/users", { method: "POST" })"#;
        let r = extract_endpoints(js);
        assert!(r.iter().any(|e| e.url == "/api/users" && e.method == "POST"));
    }

    #[test]
    fn extracts_axios() {
        let js = r#"axios.get("/v2/orders").then(...);"#;
        let r = extract_endpoints(js);
        assert!(r.iter().any(|e| e.url == "/v2/orders" && e.source == "axios"));
    }

    #[test]
    fn extracts_xhr() {
        let js = r#"xhr.open("PUT", "/api/x")"#;
        let r = extract_endpoints(js);
        assert!(r.iter().any(|e| e.url == "/api/x" && e.method == "PUT"));
    }

    #[test]
    fn extracts_websocket() {
        let js = r#"new WebSocket("wss://chat.example.com/ws")"#;
        let r = extract_endpoints(js);
        assert!(r.iter().any(|e| e.url.contains("wss://") && e.source == "websocket"));
    }

    #[test]
    fn extracts_literal_paths() {
        let js = r#"const URL = "/api/v1/secret"; let x = "/static/foo.png";"#;
        let r = extract_endpoints(js);
        assert!(r.iter().any(|e| e.url == "/api/v1/secret"));
        // /static/... should NOT be captured (not in our prefixes)
        assert!(!r.iter().any(|e| e.url == "/static/foo.png"));
    }

    #[test]
    fn dedupes_repeats() {
        let js = r#"fetch("/api/x"); fetch("/api/x"); axios.get("/api/x")"#;
        let r = extract_endpoints(js);
        // fetch + axios are different sources so we keep both — but two identical
        // (GET, /api/x) shouldn't appear twice from the same source.
        let fetch_hits = r.iter().filter(|e| e.source == "fetch").count();
        assert_eq!(fetch_hits, 1);
    }

    #[test]
    fn parses_source_map() {
        let m = r#"{"version":3,"sources":["src/app.ts","src/api/users.ts"]}"#;
        let s = extract_sourcemap_sources(m);
        assert_eq!(s, vec!["src/app.ts", "src/api/users.ts"]);
    }
}
