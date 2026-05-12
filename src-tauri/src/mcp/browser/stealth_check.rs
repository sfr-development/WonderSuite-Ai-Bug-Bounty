// Self-test for the human-emulation input stack.
//
// Loads an inline data: URL test page that records every event it receives,
// then drives the page via our normal browser_* CDP path. Reports back what
// the page saw: isTrusted flags, event sequences, navigator.webdriver state,
// whether our cursor overlay leaked into the page DOM.

use base64::Engine as _;
use serde_json::json;

const TEST_PAGE: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>WS stealth check</title>
<style>body{font:14px sans-serif;padding:24px}input,button{font-size:14px;padding:6px;margin:4px}</style>
</head><body>
<input id="text-input" type="text" placeholder="text">
<button id="click-btn">click me</button>
<div id="log" style="white-space:pre;font-family:monospace"></div>
<script>
window.__ws_log = [];
function rec(kind, e) {
  window.__ws_log.push({
    kind: kind,
    type: e.type,
    isTrusted: e.isTrusted,
    key: e.key || null,
    code: e.code || null,
    target: e.target ? e.target.tagName + (e.target.id?'#'+e.target.id:'') : null,
    x: e.clientX || null,
    y: e.clientY || null,
  });
}
['mousemove','mousedown','mouseup','click','keydown','keypress','keyup','input','change','focus','blur'].forEach(t => {
  document.addEventListener(t, e => rec(t, e), { capture: true });
});
window.__ws_collect = function() {
  return {
    events: window.__ws_log,
    webdriver: navigator.webdriver,
    plugins_len: navigator.plugins.length,
    has_chrome: typeof window.chrome === 'object',
    languages: navigator.languages,
    has_cdc: Object.keys(window).some(k => k.startsWith('cdc_')),
    overlay_leak: !!document.getElementById('__ws_ai_cursor') ||
                  !!document.documentElement.querySelector('div[__ws_ai_host]>*'),
    last_input: (document.getElementById('text-input') || {}).value || '',
  };
};
</script>
</body></html>"#;

pub async fn run(_p: &serde_json::Value) -> Result<serde_json::Value, String> {
    let sess = super::session().await?;
    // Load the in-memory test page via data URL (works without a local server).
    let data_url = format!(
        "data:text/html;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(TEST_PAGE.as_bytes())
    );
    sess.send("Page.navigate", json!({ "url": data_url })).await?;
    // Give the page a beat to load.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Snapshot to populate the refmap.
    let snap = super::snapshot::capture(&sess, false).await?;
    let snap_val = serde_json::to_value(&snap).unwrap_or(json!({}));
    // Find refs by attribute.
    let find_ref = |id: &str| -> Option<String> {
        let stack = vec![snap_val.clone()];
        let mut s = stack;
        while let Some(v) = s.pop() {
            if let Some(arr) = v.as_array() {
                for c in arr {
                    s.push(c.clone());
                }
            } else if let Some(obj) = v.as_object() {
                if let Some(props) = obj.get("html_props").and_then(|p| p.as_object()) {
                    if props.get("id").and_then(|x| x.as_str()) == Some(id) {
                        if let Some(r) = obj.get("ref").and_then(|x| x.as_str()) {
                            return Some(r.to_string());
                        }
                    }
                }
                for (_, val) in obj.iter() {
                    s.push(val.clone());
                }
            }
        }
        None
    };
    let profile = super::stealth_profile();

    // Click the button via CDP-native path.
    let mut click_result = "skipped".to_string();
    if let Some(rname) = find_ref("click-btn") {
        if let Some(backend) = sess.refmap.lock().await.resolve(&rname) {
            match super::input::click_element(&sess, backend, profile).await {
                Ok(_) => click_result = "ok".into(),
                Err(e) => click_result = format!("err: {}", e),
            }
        }
    }

    // Type into the text field via CDP-native path.
    let mut type_result = "skipped".to_string();
    if let Some(rname) = find_ref("text-input") {
        if let Some(backend) = sess.refmap.lock().await.resolve(&rname) {
            match super::input::type_into_element(&sess, backend, "hello", true, profile).await {
                Ok(_) => type_result = "ok".into(),
                Err(e) => type_result = format!("err: {}", e),
            }
        }
    }

    // Give the page a moment to flush events.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let collected = sess.eval("window.__ws_collect()").await.unwrap_or(json!({}));

    // Summarise: did every dispatched event arrive as isTrusted=true?
    let events_arr = collected.get("events").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut trusted = 0usize;
    let mut untrusted = 0usize;
    let mut by_type: std::collections::HashMap<String, (usize, usize)> = std::collections::HashMap::new();
    for ev in &events_arr {
        let trust = ev.get("isTrusted").and_then(|b| b.as_bool()).unwrap_or(false);
        if trust {
            trusted += 1
        } else {
            untrusted += 1
        }
        if let Some(t) = ev.get("type").and_then(|x| x.as_str()) {
            let entry = by_type.entry(t.to_string()).or_insert((0, 0));
            if trust {
                entry.0 += 1
            } else {
                entry.1 += 1
            }
        }
    }

    let webdriver = collected.get("webdriver").and_then(|x| x.as_bool()).unwrap_or(false);
    let overlay_leak = collected.get("overlay_leak").and_then(|x| x.as_bool()).unwrap_or(false);
    let has_cdc = collected.get("has_cdc").and_then(|x| x.as_bool()).unwrap_or(false);
    let last_input = collected.get("last_input").and_then(|x| x.as_str()).unwrap_or("");

    // Score: 100 = perfect, 0 = totally broken.
    let mut score = 100i32;
    if untrusted > 0 {
        score -= (untrusted as i32 * 8).min(60)
    }
    if webdriver {
        score -= 25
    }
    if overlay_leak {
        score -= 20
    }
    if has_cdc {
        score -= 15
    }
    if last_input != "hello" {
        score -= 10
    }
    score = score.max(0);
    let verdict = if score >= 90 {
        "indistinguishable"
    } else if score >= 70 {
        "good"
    } else if score >= 40 {
        "partially-detectable"
    } else {
        "detectable"
    };

    let by_type_json: serde_json::Value = by_type
        .into_iter()
        .map(|(k, (t, u))| (k, json!({ "trusted": t, "untrusted": u })))
        .collect::<serde_json::Map<_, _>>()
        .into();

    Ok(json!({
        "profile": profile.as_str(),
        "click": click_result,
        "type": type_result,
        "events_total": events_arr.len(),
        "events_trusted": trusted,
        "events_untrusted": untrusted,
        "events_by_type": by_type_json,
        "navigator_webdriver": webdriver,
        "overlay_leaked_into_page": overlay_leak,
        "cdc_globals": has_cdc,
        "last_input_value": last_input,
        "expected_input_value": "hello",
        "stealth_score": score,
        "verdict": verdict,
        "tip": "Re-run after switching `stealth_profile`. Verdict should be 'indistinguishable' on `human`/`paranoid`.",
    }))
}
