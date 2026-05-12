// All browser_* MCP tool handlers.
//
// Convention: each handler grabs an owned `Arc<BrowserSession>` via
// `super::session().await?` so the RwLock guard never spans an .await. Tools
// that take element refs resolve them against the last snapshot; missing refs
// return `code=STALE_REF` with a re-snap hint.

use std::sync::Arc;

use crate::mcp::types::HandlerResult;

use super::session::{AttachArgs, BrowserSession, LaunchArgs};

fn structured_err(code: &str, hint: &str) -> String {
    format!("code={} hint=\"{}\"", code, hint)
}

async fn resolve_ref_object(sess: &BrowserSession, r: &str) -> Result<String, String> {
    let backend_id = sess.refmap.lock().await.resolve(r).ok_or_else(|| {
        structured_err(
            "STALE_REF",
            &format!("ref {} not in current snapshot — call browser_snapshot to refresh", r),
        )
    })?;
    let resp = sess.send("DOM.resolveNode", serde_json::json!({ "backendNodeId": backend_id })).await?;
    resp.pointer("/object/objectId").and_then(|v| v.as_str()).map(String::from).ok_or_else(|| {
        structured_err(
            "STALE_REF",
            &format!("ref {} no longer resolvable — call browser_snapshot to refresh", r),
        )
    })
}

async fn maybe_snapshot(sess: &BrowserSession, p: &serde_json::Value) -> Option<serde_json::Value> {
    if p["includeSnapshot"].as_bool().unwrap_or(false) {
        super::snapshot::capture(sess, p["includeSecurity"].as_bool().unwrap_or(false))
            .await
            .ok()
            .and_then(|s| serde_json::to_value(s).ok())
    } else {
        None
    }
}

async fn call_on_ref(
    sess: &BrowserSession,
    r: &str,
    js: &str,
    args: Vec<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let obj_id = resolve_ref_object(sess, r).await?;
    let arguments: Vec<serde_json::Value> =
        args.into_iter().map(|v| serde_json::json!({ "value": v })).collect();
    let resp = sess
        .send(
            "Runtime.callFunctionOn",
            serde_json::json!({
                "objectId": obj_id,
                "functionDeclaration": js,
                "arguments": arguments,
                "returnByValue": true,
                "awaitPromise": true,
                "userGesture": true,
            }),
        )
        .await?;
    if let Some(ex) = resp.get("exceptionDetails") {
        return Err(format!("JS exception during callFunctionOn: {}", ex));
    }
    Ok(resp.pointer("/result/value").cloned().unwrap_or(serde_json::Value::Null))
}

async fn wait_for_load(sess: &BrowserSession, mode: &str, timeout_ms: u64) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);
    let probe = match mode {
        "load" => "document.readyState === 'complete'",
        "domcontentloaded" => "document.readyState === 'interactive' || document.readyState === 'complete'",
        "networkidle" => "performance.getEntriesByType('resource').slice(-5).every(e => e.responseEnd > 0)",
        _ => "true",
    };
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(structured_err(
                "WAIT_TIMEOUT",
                &format!("wait_until={} did not satisfy within {}ms", mode, timeout_ms),
            ));
        }
        if sess.eval(probe).await.ok().and_then(|v| v.as_bool()).unwrap_or(false) {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LIFECYCLE
// ─────────────────────────────────────────────────────────────────────────────

pub async fn open(p: &serde_json::Value) -> HandlerResult {
    let app = super::app_handle()
        .ok_or_else(|| structured_err("NO_APP_HANDLE", "MCP browser is not initialised — restart the app"))?;
    let state = super::state();
    if state.read().await.is_some() {
        return Err(structured_err(
            "ALREADY_OPEN",
            "browser session already exists — call browser_close first",
        ));
    }

    let proxy_port = p["proxy_port"].as_u64().unwrap_or(8080) as u16;
    let cdp_port = p["cdp_port"].as_u64().unwrap_or(9333) as u16;
    // If the agent doesn't specify, use the user's Settings preference
    // (visible by default — lets the human help on captchas etc.).
    let headless = p["headless"].as_bool().unwrap_or_else(super::default_headless);
    let url = p["url"].as_str().map(String::from);

    // The browser routes its outbound through the WonderSuite proxy for TLS
    // impersonation + traffic capture. We only need to know the proxy engine
    // is listening — we don't actually use the AppState handle here.
    let proxy_running =
        crate::proxy_commands::get_global_proxy_state().map(|ps| ps.is_running()).unwrap_or(false);
    if !proxy_running {
        return Err(structured_err(
            "PROXY_DOWN",
            "WonderSuite proxy is not running — call proxy_start (or start it via the UI), then retry",
        ));
    }

    let sess =
        BrowserSession::launch(&app, LaunchArgs { url: url.clone(), proxy_port, cdp_port, headless }).await?;

    let info = serde_json::json!({
        "success": true,
        "browser": sess.browser_label,
        "pid": sess.pid,
        "cdp_port": sess.cdp_port,
        "proxy_port": sess.proxy_port,
        "headless": sess.headless,
        "initial_url": url,
        "tip": "Call browser_snapshot to discover refs for click/type/fill_form.",
    });

    *state.write().await = Some(Arc::new(sess));
    Ok(info)
}

pub async fn attach(p: &serde_json::Value) -> HandlerResult {
    let app = super::app_handle()
        .ok_or_else(|| structured_err("NO_APP_HANDLE", "MCP browser is not initialised — restart the app"))?;
    let state = super::state();
    if state.read().await.is_some() {
        return Err(structured_err(
            "ALREADY_OPEN",
            "browser session already exists — call browser_close first",
        ));
    }
    let cdp_port = p["cdp_port"].as_u64().map(|n| n as u16);
    let proxy_port = p["proxy_port"].as_u64().unwrap_or(8080) as u16;
    let url = p["url"].as_str().map(String::from);
    let auto_launch = p["auto_launch"].as_bool().unwrap_or(false);

    let sess =
        BrowserSession::attach(&app, AttachArgs { cdp_port, proxy_port, url: url.clone(), auto_launch })
            .await?;
    let note = if sess.launched_by_us {
        "Auto-launched a fresh WonderBrowser (isolated profile, proxy-wired, stealth extension loaded). Same as browser_open.".to_string()
    } else {
        "Attached to a running WonderBrowser CDP session.".to_string()
    };
    let info = serde_json::json!({
        "success": true,
        "attached": true,
        "browser": sess.browser_label,
        "cdp_port": sess.cdp_port,
        "initial_url": url,
        "auto_launched": sess.launched_by_us,
        "note": note,
        "tip": "Call browser_snapshot to discover refs for click/type/fill_form.",
    });
    *state.write().await = Some(Arc::new(sess));
    Ok(info)
}

pub async fn close(_p: &serde_json::Value) -> HandlerResult {
    let state = super::state();
    let taken = state.write().await.take();
    if let Some(sess) = taken {
        sess.close().await;
        Ok(serde_json::json!({ "closed": true }))
    } else {
        Ok(serde_json::json!({ "closed": false, "note": "no session was open" }))
    }
}

pub async fn navigate(p: &serde_json::Value) -> HandlerResult {
    let url = p["url"].as_str().ok_or("Missing url")?.to_string();
    let wait_until = p["wait_until"].as_str().unwrap_or("load").to_string();
    let timeout_ms = p["timeout_ms"].as_u64().unwrap_or(15000);
    let s = super::session().await?;
    s.send("Page.navigate", serde_json::json!({ "url": url })).await?;
    wait_for_load(&s, &wait_until, timeout_ms).await?;
    let cur_url = s
        .eval("document.location.href")
        .await
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default();
    let cur_title =
        s.eval("document.title").await.ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
    Ok(serde_json::json!({
        "success": true, "url": cur_url, "title": cur_title, "wait_until": wait_until,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// SNAPSHOT / EXTRACT
// ─────────────────────────────────────────────────────────────────────────────

pub async fn snapshot(p: &serde_json::Value) -> HandlerResult {
    let include_security = p["include_security"].as_bool().unwrap_or(true);
    let s = super::session().await?;
    let snap = super::snapshot::capture(&s, include_security).await?;
    serde_json::to_value(snap).map_err(|e| e.to_string())
}

pub async fn get_outer_html(p: &serde_json::Value) -> HandlerResult {
    let r = p["ref"].as_str().ok_or("Missing ref")?.to_string();
    let s = super::session().await?;
    let obj_id = resolve_ref_object(&s, &r).await?;
    let resp = s
        .send(
            "Runtime.callFunctionOn",
            serde_json::json!({
                "objectId": obj_id,
                "functionDeclaration": "function() { return this.outerHTML; }",
                "returnByValue": true,
            }),
        )
        .await?;
    let html = resp.pointer("/result/value").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let len = html.len();
    let html =
        if len > 200_000 { format!("{}…(truncated, total {})", &html[..200_000], len) } else { html };
    Ok(serde_json::json!({ "ref": r, "outer_html": html, "length": len }))
}

pub async fn evaluate(p: &serde_json::Value) -> HandlerResult {
    let code = p["code"].as_str().ok_or("Missing code")?.to_string();
    let await_promise = p["await_promise"].as_bool().unwrap_or(true);
    let s = super::session().await?;
    let resp = s
        .send(
            "Runtime.evaluate",
            serde_json::json!({
                "expression": code,
                "returnByValue": true,
                "awaitPromise": await_promise,
                "userGesture": true,
            }),
        )
        .await?;
    if let Some(ex) = resp.get("exceptionDetails") {
        return Ok(serde_json::json!({
            "success": false,
            "error": ex.get("text").and_then(|v| v.as_str()).unwrap_or("JS error"),
            "exception": ex,
        }));
    }
    Ok(serde_json::json!({
        "success": true,
        "value": resp.pointer("/result/value").cloned().unwrap_or(serde_json::Value::Null),
        "type": resp.pointer("/result/type").and_then(|v| v.as_str()).unwrap_or("undefined"),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// INPUT
// ─────────────────────────────────────────────────────────────────────────────

pub async fn click(p: &serde_json::Value) -> HandlerResult {
    let r = p["ref"].as_str().ok_or("Missing ref")?.to_string();
    let s = super::session().await?;
    // Animate the AI cursor to the target, ripple, then real click. Visible to
    // the user, included in screenshots, lets you spot honeypot fields if the
    // agent walks into one.
    let js = r#"
    async function() {
        if (window.__ws_cursor_move_to) window.__ws_cursor_move_to(this, 'click');
        await new Promise(r => setTimeout(r, 340));
        if (window.__ws_cursor_click_fx) window.__ws_cursor_click_fx(this);
        this.click();
        return true;
    }"#;
    call_on_ref(&s, &r, js, vec![]).await?;
    let snap = maybe_snapshot(&s, p).await;
    Ok(serde_json::json!({ "clicked": r, "snapshot": snap }))
}

pub async fn type_text(p: &serde_json::Value) -> HandlerResult {
    let r = p["ref"].as_str().ok_or("Missing ref")?.to_string();
    let text = p["text"].as_str().ok_or("Missing text")?.to_string();
    let clear = p["clear"].as_bool().unwrap_or(true);
    let s = super::session().await?;
    let js = r#"
    async function(text, clear) {
        if (window.__ws_cursor_move_to) window.__ws_cursor_move_to(this, 'type');
        await new Promise(r => setTimeout(r, 340));
        if (window.__ws_cursor_typehint) window.__ws_cursor_typehint(this, text);
        this.focus();
        if (clear) { this.value = ''; this.dispatchEvent(new Event('input', {bubbles:true})); }
        const tag = this.tagName.toLowerCase();
        const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        const desc = Object.getOwnPropertyDescriptor(proto, 'value');
        if (desc && desc.set) desc.set.call(this, (this.value || '') + text);
        else this.value = (this.value || '') + text;
        this.dispatchEvent(new Event('input', {bubbles:true}));
        this.dispatchEvent(new Event('change', {bubbles:true}));
        return this.value;
    }"#;
    let v = call_on_ref(&s, &r, js, vec![serde_json::json!(text), serde_json::json!(clear)]).await?;
    let snap = maybe_snapshot(&s, p).await;
    Ok(serde_json::json!({ "ref": r, "value_after": v, "snapshot": snap }))
}

pub async fn fill_form(p: &serde_json::Value) -> HandlerResult {
    let values = p["values"].as_array().ok_or("Missing values: array of {ref|selector|name, value}")?.clone();
    let submit = p["submit"].as_bool().unwrap_or(false);
    let submit_ref = p["submit_ref"].as_str().map(String::from);
    let submit_selector = p["submit_selector"].as_str().map(String::from);
    let form_ref = p["form_ref"].as_str().map(String::from);
    let form_selector = p["form_selector"].as_str().map(String::from);
    let s = super::session().await?;
    let fill_native_setter = r#"
    function(text) {
        this.focus();
        const tag = this.tagName.toLowerCase();
        if (tag === 'select') {
            for (const o of this.options) o.selected = (o.value === text || o.text === text);
        } else if (this.type === 'checkbox' || this.type === 'radio') {
            this.checked = (text === 'true' || text === '1' || text === 'on' || text === this.value);
        } else {
            const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
            const desc = Object.getOwnPropertyDescriptor(proto, 'value');
            if (desc && desc.set) desc.set.call(this, text); else this.value = text;
        }
        this.dispatchEvent(new Event('input', {bubbles:true}));
        this.dispatchEvent(new Event('change', {bubbles:true}));
        return true;
    }"#;

    let mut applied = Vec::new();
    let mut errors = Vec::new();
    for v in &values {
        let val = v["value"].as_str().unwrap_or("");
        let r = v["ref"].as_str().unwrap_or("");
        let sel = v["selector"].as_str().unwrap_or("");
        let name = v["name"].as_str().unwrap_or("");
        let target_key = if !r.is_empty() {
            r.to_string()
        } else if !sel.is_empty() {
            format!("sel:{}", sel)
        } else if !name.is_empty() {
            format!("name:{}", name)
        } else {
            errors.push(serde_json::json!({ "input": v, "reason": "no ref/selector/name" }));
            continue;
        };

        let outcome = if !r.is_empty() {
            call_on_ref(&s, r, fill_native_setter, vec![serde_json::json!(val)]).await
        } else {
            // selector or name → eval a self-contained fill expression
            let lookup = if !sel.is_empty() {
                format!("document.querySelector({:?})", sel)
            } else {
                format!(
                    "(document.querySelector('[name=' + JSON.stringify({0}) + ']') || document.getElementById({0}))",
                    serde_json::Value::String(name.to_string())
                )
            };
            let js = format!(
                r#"(() => {{
                    const el = {};
                    if (!el) return {{ ok:false, reason:'not found' }};
                    ({})(val_placeholder_{});
                    return {{ ok:true, tag: el.tagName.toLowerCase(), type: el.type || null }};
                }})()"#,
                lookup,
                fill_native_setter.trim(),
                0
            );
            // Inline the value directly to avoid placeholder gymnastics.
            let js = js
                .replace("(val_placeholder_0)", &format!("({})", serde_json::Value::String(val.to_string())));
            // Embed the function: replace `(<fn body>)` with a self-applied call on the element.
            let js = format!(
                r#"(() => {{
                    const el = {lookup};
                    if (!el) return {{ ok:false, reason:'not found' }};
                    const fill = {body};
                    fill.call(el, {value});
                    return {{ ok:true, tag: el.tagName.toLowerCase(), type: el.type || null }};
                }})()"#,
                lookup = lookup,
                body = fill_native_setter.trim(),
                value = serde_json::Value::String(val.to_string()),
            );
            s.eval(&js).await.map(|v| v)
        };
        match outcome {
            Ok(v) => {
                let ok = v.get("ok").and_then(|b| b.as_bool()).unwrap_or(true);
                if ok {
                    applied.push(target_key);
                } else {
                    errors.push(
                        serde_json::json!({ "input": v, "reason": v.get("reason").cloned().unwrap_or_default() }),
                    );
                }
            }
            Err(e) => {
                errors.push(serde_json::json!({ "input": v, "reason": e }));
            }
        }
    }

    if submit {
        let _ = if let Some(sr) = submit_ref {
            call_on_ref(&s, &sr, "function() { this.click(); return true; }", vec![]).await
        } else if let Some(sel) = submit_selector {
            s.eval(&format!(
                "(() => {{ const b = document.querySelector({0}); if (b) {{ b.click(); return true; }} return false; }})()",
                serde_json::Value::String(sel),
            ))
            .await
        } else if let Some(fr) = form_ref {
            call_on_ref(
                &s,
                &fr,
                "function() { if (this.requestSubmit) this.requestSubmit(); else this.submit(); return true; }",
                vec![],
            )
            .await
        } else if let Some(fsel) = form_selector {
            s.eval(&format!(
                "(() => {{ const f = document.querySelector({0}); if (f) {{ if (f.requestSubmit) f.requestSubmit(); else f.submit(); return true; }} return false; }})()",
                serde_json::Value::String(fsel),
            ))
            .await
        } else {
            // No explicit submit target: try requestSubmit on the closest form of the last filled input
            s.eval(r#"(() => {
                const fs = document.querySelectorAll('form');
                if (fs.length === 1) { const f = fs[0]; if (f.requestSubmit) f.requestSubmit(); else f.submit(); return 'single_form_submitted'; }
                return 'no_unique_form';
            })()"#).await
        };
    }
    let snap = maybe_snapshot(&s, p).await;
    Ok(serde_json::json!({
        "applied": applied,
        "errors": errors,
        "submitted": submit,
        "snapshot": snap,
    }))
}

pub async fn press_key(p: &serde_json::Value) -> HandlerResult {
    let key = p["key"].as_str().ok_or("Missing key")?.to_string();
    let s = super::session().await?;
    for kind in ["keyDown", "keyUp"] {
        s.send(
            "Input.dispatchKeyEvent",
            serde_json::json!({
                "type": kind,
                "key": key,
                "code": key,
                "windowsVirtualKeyCode": vk_for(&key),
            }),
        )
        .await?;
    }
    let snap = maybe_snapshot(&s, p).await;
    Ok(serde_json::json!({ "pressed": key, "snapshot": snap }))
}

fn vk_for(k: &str) -> u32 {
    match k {
        "Enter" => 13,
        "Tab" => 9,
        "Escape" => 27,
        "Backspace" => 8,
        "ArrowDown" => 40,
        "ArrowUp" => 38,
        "ArrowLeft" => 37,
        "ArrowRight" => 39,
        _ => 0,
    }
}

pub async fn scroll(p: &serde_json::Value) -> HandlerResult {
    let direction = p["direction"].as_str().unwrap_or("down").to_string();
    let amount = p["amount"].as_i64().unwrap_or(500);
    let r = p["ref"].as_str().map(String::from);
    let (dx, dy) = match direction.as_str() {
        "up" => (0, -amount),
        "down" => (0, amount),
        "left" => (-amount, 0),
        "right" => (amount, 0),
        _ => (0, amount),
    };
    let s = super::session().await?;
    // Pop the banner first so the user sees the intent immediately.
    let _ = s
        .eval(&format!(
            "window.__ws_cursor_scroll_indicator && window.__ws_cursor_scroll_indicator({:?}, {})",
            direction, amount
        ))
        .await;
    if let Some(rname) = r {
        // Container scroll via custom rAF animation — guarantees visible motion
        // even when the container has scroll-behavior:auto.
        call_on_ref(
            &s,
            &rname,
            "async function(dx, dy) { if (window.__ws_cursor_animate_scroll_el) { await window.__ws_cursor_animate_scroll_el(this, dx, dy, 700); } else { this.scrollBy({left: dx, top: dy, behavior: 'smooth'}); } return true; }",
            vec![serde_json::json!(dx), serde_json::json!(dy)],
        )
        .await?;
    } else {
        // Window scroll — step through the delta over ~700ms via rAF so the
        // motion is visible regardless of CSS scroll-behavior.
        let js = format!(
            "(async () => {{ if (window.__ws_cursor_animate_scroll) {{ await window.__ws_cursor_animate_scroll({}, {}, 700); }} else {{ window.scrollBy({{ left: {}, top: {}, behavior: 'smooth' }}); }} return true; }})()",
            dx, dy, dx, dy
        );
        s.eval(&js).await?;
    }
    Ok(serde_json::json!({ "scrolled": { "dx": dx, "dy": dy } }))
}

pub async fn select_option(p: &serde_json::Value) -> HandlerResult {
    let r = p["ref"].as_str().ok_or("Missing ref")?.to_string();
    let value = p["value"].as_str().ok_or("Missing value")?.to_string();
    let s = super::session().await?;
    let js = r#"
    function(v) {
        if (this.tagName.toLowerCase() !== 'select') return false;
        for (const o of this.options) o.selected = (o.value === v || o.text === v);
        this.dispatchEvent(new Event('input', {bubbles:true}));
        this.dispatchEvent(new Event('change', {bubbles:true}));
        return this.value;
    }"#;
    let v = call_on_ref(&s, &r, js, vec![serde_json::json!(value)]).await?;
    Ok(serde_json::json!({ "ref": r, "selected": v }))
}

pub async fn set_file_input(p: &serde_json::Value) -> HandlerResult {
    let r = p["ref"].as_str().ok_or("Missing ref")?.to_string();
    let files = p["files"]
        .as_array()
        .ok_or("Missing files: array of absolute paths")?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect::<Vec<_>>();
    if files.is_empty() {
        return Err("Provide at least one file path".into());
    }
    let s = super::session().await?;
    let backend_id = s
        .refmap
        .lock()
        .await
        .resolve(&r)
        .ok_or_else(|| structured_err("STALE_REF", &format!("ref {} not in current snapshot", r)))?;
    s.send("DOM.setFileInputFiles", serde_json::json!({ "files": files, "backendNodeId": backend_id }))
        .await?;
    Ok(serde_json::json!({ "ref": r, "set_files": files }))
}

// ─────────────────────────────────────────────────────────────────────────────
// STATE / EXTRACTION
// ─────────────────────────────────────────────────────────────────────────────

pub async fn storage_full(p: &serde_json::Value) -> HandlerResult {
    let domain = p["domain"].as_str().map(String::from);
    let s = super::session().await?;
    let cookies = s.send("Network.getAllCookies", serde_json::json!({})).await?;
    let cookies = cookies["cookies"].as_array().cloned().unwrap_or_default();
    let cookies: Vec<&serde_json::Value> = if let Some(d) = &domain {
        cookies
            .iter()
            .filter(|c| {
                c["domain"]
                    .as_str()
                    .map(|cd| cd.contains(d.as_str()) || d.contains(cd.trim_start_matches('.')))
                    .unwrap_or(false)
            })
            .collect()
    } else {
        cookies.iter().collect()
    };
    let cookie_header: String = cookies
        .iter()
        .filter_map(|c| Some(format!("{}={}", c["name"].as_str()?, c["value"].as_str()?)))
        .collect::<Vec<_>>()
        .join("; ");
    let ls = s
        .eval("JSON.stringify(Object.fromEntries(Object.entries(localStorage)))")
        .await
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .unwrap_or(serde_json::json!({}));
    let ss = s
        .eval("JSON.stringify(Object.fromEntries(Object.entries(sessionStorage)))")
        .await
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .unwrap_or(serde_json::json!({}));
    let idb = s
        .eval(
            r#"new Promise(async (resolve) => {
            try {
                const dbs = await indexedDB.databases();
                resolve(dbs.map(d => ({name: d.name, version: d.version})));
            } catch (_) { resolve([]); }
        })"#,
        )
        .await
        .unwrap_or(serde_json::json!([]));
    let sw = s
        .eval(
            r#"new Promise(async (resolve) => {
            try {
                if (!navigator.serviceWorker) return resolve([]);
                const regs = await navigator.serviceWorker.getRegistrations();
                resolve(regs.map(r => ({scope: r.scope, script: r.active && r.active.scriptURL})));
            } catch (_) { resolve([]); }
        })"#,
        )
        .await
        .unwrap_or(serde_json::json!([]));
    let caches = s
        .eval(
            r#"new Promise(async (resolve) => {
            try {
                if (!caches) return resolve([]);
                const ks = await caches.keys();
                resolve(ks);
            } catch (_) { resolve([]); }
        })"#,
        )
        .await
        .unwrap_or(serde_json::json!([]));

    Ok(serde_json::json!({
        "cookies": cookies,
        "cookie_count": cookies.len(),
        "cookie_header": cookie_header,
        "local_storage": ls,
        "session_storage": ss,
        "indexed_db": idb,
        "service_workers": sw,
        "caches": caches,
        "usage": "Pass cookie_header value as `Cookie:` header when replaying outside the browser.",
    }))
}

pub async fn console(p: &serde_json::Value) -> HandlerResult {
    let action = p["action"].as_str().unwrap_or("get").to_string();
    let limit = p["limit"].as_u64().unwrap_or(200) as usize;
    let inject_code = p["code"].as_str().map(String::from);
    let s = super::session().await?;
    match action.as_str() {
        "get" => {
            let msgs = s.console.lock().await.clone();
            let start = msgs.len().saturating_sub(limit);
            Ok(serde_json::json!({
                "messages": &msgs[start..],
                "total": msgs.len(),
            }))
        }
        "clear" => {
            s.console.lock().await.clear();
            Ok(serde_json::json!({ "cleared": true }))
        }
        "inject" => {
            let code = inject_code.ok_or("Missing code for inject")?;
            let v = s.eval(&code).await?;
            Ok(serde_json::json!({ "injected": true, "result": v }))
        }
        _ => Err(format!("Unknown action: {}", action)),
    }
}

pub async fn dom_sinks(_p: &serde_json::Value) -> HandlerResult {
    let s = super::session().await?;
    let js = r#"
    (() => {
        const out = { innerHTML_calls: [], doc_write_calls: [], eval_calls: [], postmessage_listeners: [], dangerous_urls: [] };
        if (window.__ws_post_listeners) out.postmessage_listeners = window.__ws_post_listeners.map(fn => fn.toString().slice(0, 500));
        const inline = document.querySelectorAll('script:not([src])');
        inline.forEach((sc, i) => {
            const t = sc.textContent || '';
            if (/\.innerHTML\s*=/.test(t)) out.innerHTML_calls.push({source: 'inline_script_' + i, snippet: t.match(/[^;\n]*\.innerHTML\s*=[^;\n]*/)?.[0]?.slice(0, 200)});
            if (/document\.write\s*\(/.test(t)) out.doc_write_calls.push({source: 'inline_script_' + i, snippet: t.match(/document\.write\([^)]*\)/)?.[0]?.slice(0, 200)});
            if (/\beval\s*\(/.test(t)) out.eval_calls.push({source: 'inline_script_' + i, snippet: t.match(/\beval\([^)]*\)/)?.[0]?.slice(0, 200)});
        });
        document.querySelectorAll('*').forEach(el => {
            for (const attr of el.attributes) {
                if (attr.name.startsWith('on') && attr.value) {
                    if (/\.innerHTML\s*=/.test(attr.value)) out.innerHTML_calls.push({source: el.tagName + '@' + attr.name, snippet: attr.value.slice(0, 200)});
                    if (/\beval\s*\(/.test(attr.value)) out.eval_calls.push({source: el.tagName + '@' + attr.name, snippet: attr.value.slice(0, 200)});
                }
                if ((attr.name === 'href' || attr.name === 'src' || attr.name === 'action') && /^javascript:/i.test(attr.value)) {
                    out.dangerous_urls.push({tag: el.tagName, attr: attr.name, value: attr.value.slice(0, 200)});
                }
            }
        });
        return out;
    })()
    "#;
    let v = s.eval(js).await?;
    Ok(v)
}

// ─────────────────────────────────────────────────────────────────────────────
// NETWORK
// ─────────────────────────────────────────────────────────────────────────────

pub async fn network_traffic(p: &serde_json::Value) -> HandlerResult {
    let filter = p["url_contains"].as_str().map(String::from);
    let method = p["method"].as_str().map(|s| s.to_uppercase());
    let status = p["status"].as_u64().map(|s| s as u16);
    let auth_only = p["auth_only"].as_bool().unwrap_or(false);
    let limit = p["limit"].as_u64().unwrap_or(100) as usize;
    let s = super::session().await?;
    let all = s.net.snapshot();
    let total = all.len();
    let filtered: Vec<_> = all
        .into_iter()
        .filter(|e| {
            if let Some(f) = &filter {
                if !e.url.to_lowercase().contains(&f.to_lowercase()) {
                    return false;
                }
            }
            if let Some(m) = &method {
                if !e.method.eq_ignore_ascii_case(m) {
                    return false;
                }
            }
            if let Some(s) = status {
                if e.status != Some(s) {
                    return false;
                }
            }
            if auth_only && !e.is_auth_like {
                return false;
            }
            true
        })
        .rev()
        .take(limit)
        .collect();
    let count = filtered.len();
    Ok(serde_json::json!({
        "entries": filtered,
        "filtered_count": count,
        "total_captured": total,
        "hint": "Pass any `request_id` to browser_replay_to_proxy to fuzz it.",
    }))
}

pub async fn replay_to_proxy(p: &serde_json::Value) -> HandlerResult {
    let req_id = p["request_id"].as_str().ok_or("Missing request_id")?.to_string();
    let s = super::session().await?;
    let entry = s.net.find(&req_id).ok_or_else(|| {
        structured_err(
            "REQUEST_NOT_FOUND",
            "request_id not in capture buffer — call browser_network_traffic to refresh",
        )
    })?;

    let mut headers = serde_json::Map::new();
    if let Some(obj) = entry.request_headers.as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                headers.insert(k.clone(), serde_json::Value::String(s.to_string()));
            }
        }
    }
    let body = entry.request_body.unwrap_or_default();

    let mcp_params = serde_json::json!({
        "url": entry.url,
        "method": entry.method,
        "headers": headers,
        "body": body,
    });
    let resp = crate::mcp::handlers::proxy::handle_send_to_repeater(&mcp_params).await?;
    Ok(serde_json::json!({
        "from_browser_request_id": req_id,
        "proxy_response": resp,
        "hint": "The request was sent fresh and recorded in proxy traffic with source='repeater'.",
    }))
}

pub async fn resource_hints(_p: &serde_json::Value) -> HandlerResult {
    let s = super::session().await?;
    let origin = s
        .eval("location.origin")
        .await
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .ok_or("No active page (browser_navigate first)")?;
    let mut out = serde_json::Map::new();
    for path in [
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/change-password",
    ] {
        let url = format!("{}{}", origin, path);
        let js = format!(
            r#"fetch("{}", {{redirect: 'manual'}}).then(r => r.status === 200 ? r.text().then(t => ({{status: r.status, body: t.slice(0, 4000)}})) : ({{status: r.status, body: null}})).catch(e => ({{status: 0, error: String(e)}}))"#,
            url
        );
        if let Ok(v) = s.eval(&js).await {
            out.insert(path.to_string(), v);
        }
    }
    let scripts = s
        .eval(r#"Array.from(document.querySelectorAll('script[src]')).slice(0, 50).map(s => s.src)"#)
        .await
        .unwrap_or(serde_json::json!([]));
    let sourcemap_hits = s
        .eval(
            r#"(async () => {
            const out = [];
            const srcs = Array.from(document.querySelectorAll('script[src]')).slice(0, 30).map(s => s.src);
            for (const u of srcs) {
                try {
                    const r = await fetch(u);
                    const t = await r.text();
                    const m = t.match(/sourceMappingURL=([^\s'"]+)/);
                    if (m) out.push({script: u, map: m[1]});
                } catch (_) {}
            }
            return out;
        })()"#,
        )
        .await
        .unwrap_or(serde_json::json!([]));
    out.insert("scripts".into(), scripts);
    out.insert("sourcemap_hits".into(), sourcemap_hits);
    Ok(serde_json::Value::Object(out))
}

// ─────────────────────────────────────────────────────────────────────────────
// LIFECYCLE: wait_for, tabs, screenshot
// ─────────────────────────────────────────────────────────────────────────────

pub async fn wait_for(p: &serde_json::Value) -> HandlerResult {
    let action = p["action"].as_str().unwrap_or("load").to_string();
    let value = p["value"].as_str().map(String::from);
    let timeout_ms = p["timeout_ms"].as_u64().unwrap_or(10000);
    let s = super::session().await?;
    match action.as_str() {
        "selector" => {
            let sel = value.ok_or("Missing value (selector)")?;
            let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);
            loop {
                if tokio::time::Instant::now() >= deadline {
                    return Err(structured_err(
                        "WAIT_TIMEOUT",
                        &format!("selector '{}' not found within {}ms", sel, timeout_ms),
                    ));
                }
                let probe = format!("!!document.querySelector('{}')", sel.replace('\'', "\\'"));
                if s.eval(&probe).await.ok().and_then(|v| v.as_bool()).unwrap_or(false) {
                    return Ok(serde_json::json!({ "matched": "selector", "value": sel }));
                }
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
        }
        "text" => {
            let needle = value.ok_or("Missing value (text)")?;
            let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);
            loop {
                if tokio::time::Instant::now() >= deadline {
                    return Err(structured_err(
                        "WAIT_TIMEOUT",
                        &format!("text '{}' not visible within {}ms", needle, timeout_ms),
                    ));
                }
                let probe =
                    format!("(document.body && document.body.innerText || '').includes({:?})", needle);
                if s.eval(&probe).await.ok().and_then(|v| v.as_bool()).unwrap_or(false) {
                    return Ok(serde_json::json!({ "matched": "text", "value": needle }));
                }
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
        }
        _ => {
            wait_for_load(&s, &action, timeout_ms).await?;
            Ok(serde_json::json!({ "matched": action }))
        }
    }
}

pub async fn tabs(p: &serde_json::Value) -> HandlerResult {
    let action = p["action"].as_str().unwrap_or("list").to_string();
    let new_url = p["url"].as_str().unwrap_or("about:blank").to_string();
    let target_id = p["target_id"].as_str().map(String::from);
    let s = super::session().await?;
    match action.as_str() {
        "list" => {
            let r = s.send("Target.getTargets", serde_json::json!({})).await?;
            Ok(serde_json::json!({ "targets": r["targetInfos"] }))
        }
        "new" => {
            let r = s.send("Target.createTarget", serde_json::json!({ "url": new_url })).await?;
            Ok(r)
        }
        "close" => {
            let tid = target_id.ok_or("Missing target_id")?;
            s.send("Target.closeTarget", serde_json::json!({ "targetId": tid })).await?;
            Ok(serde_json::json!({ "closed": tid }))
        }
        _ => Err(format!("Unknown action: {}", action)),
    }
}

pub async fn screenshot(p: &serde_json::Value) -> HandlerResult {
    let full_page = p["full_page"].as_bool().unwrap_or(false);
    let quality = p["quality"].as_u64().unwrap_or(80) as u32;
    let r = p["ref"].as_str().map(String::from);
    let return_base64 = p["return_base64"].as_bool().unwrap_or(false);
    let s = super::session().await?;

    let (b64, scope_label) = if let Some(rname) = r.clone() {
        let obj_id = resolve_ref_object(&s, &rname).await?;
        let box_resp = s
            .send(
                "Runtime.callFunctionOn",
                serde_json::json!({
                    "objectId": obj_id,
                    "functionDeclaration": "function() { const r = this.getBoundingClientRect(); return {x:r.x, y:r.y, w:r.width, h:r.height}; }",
                    "returnByValue": true,
                }),
            )
            .await?;
        let bx = &box_resp["result"]["value"];
        let clip = serde_json::json!({
            "x": bx["x"].as_f64().unwrap_or(0.0),
            "y": bx["y"].as_f64().unwrap_or(0.0),
            "width": bx["w"].as_f64().unwrap_or(0.0),
            "height": bx["h"].as_f64().unwrap_or(0.0),
            "scale": 1
        });
        let resp = s
            .send(
                "Page.captureScreenshot",
                serde_json::json!({
                    "format": "jpeg", "quality": quality, "clip": clip,
                }),
            )
            .await?;
        (resp["data"].as_str().unwrap_or("").to_string(), format!("ref:{}", rname))
    } else {
        let resp = s
            .send(
                "Page.captureScreenshot",
                serde_json::json!({
                    "format": "jpeg",
                    "quality": quality,
                    "captureBeyondViewport": full_page,
                }),
            )
            .await?;
        let label = if full_page { "full_page" } else { "viewport" };
        (resp["data"].as_str().unwrap_or("").to_string(), label.to_string())
    };

    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| format!("base64 decode: {}", e))?;
    let size = bytes.len();

    // Persist to disk so the agent can hand the user a real path and the
    // (often massive) base64 string doesn't blow up the LLM context window.
    let home =
        std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_else(|_| ".".to_string());
    let dir = std::path::PathBuf::from(format!("{}/.wondersuite/screenshots", home));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir screenshots: {}", e))?;
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ").to_string();
    let safe_scope = scope_label.replace(':', "_").replace('/', "_");
    let file_name = format!("ws-{}-{}.jpeg", ts, safe_scope);
    let path = dir.join(&file_name);
    std::fs::write(&path, &bytes).map_err(|e| format!("write screenshot: {}", e))?;
    let path_str = path.to_string_lossy().to_string();

    let mut out = serde_json::json!({
        "format": "jpeg",
        "scope": scope_label,
        "full_page": full_page,
        "size_bytes": size,
        "path": path_str,
        "hint": "File saved to .wondersuite/screenshots. Pass return_base64:true for inline encoded data (large — usually only useful when streaming to a vision model).",
    });
    if return_base64 {
        out["base64"] = serde_json::Value::String(b64);
    }
    Ok(out)
}
