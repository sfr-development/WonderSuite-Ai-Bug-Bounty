// Human-emulation input layer.
//
// Every browser_click / browser_type / browser_scroll / browser_press_key
// goes through this module. The point is to dispatch events through Chrome's
// real input pipeline (CDP `Input.dispatchMouseEvent` / `Input.dispatchKeyEvent`
// / `Input.insertText`) so the resulting DOM events have `isTrusted: true` —
// indistinguishable from a physical keyboard/mouse and not catchable from
// any JS side-channel.
//
// On top of that the trajectory + timing are statistically humanized: Bezier
// curves with Gaussian jitter, ease-out velocity profiles, per-character
// typing cadence drawn from a normal distribution, configurable dwell time
// before and after each action.
//
// The mode is governed by a `StealthProfile`:
//   - Fast      → no humanisation, programmatic-fast (only for your own
//                 lab targets; trips most fraud SDKs)
//   - Human     → default; balanced, works against ~95% of real sites
//                 incl. FriendlyCaptcha / Cloudflare Free / Imperva
//   - Paranoid  → max stealth; longer dwell, occasional overshoot, slower
//                 typing — for banking / sophisticated bot management

use rand::Rng;
use serde_json::{json, Value};
use std::time::Duration;

use super::session::BrowserSession;

#[derive(Debug, Clone, Copy)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    pub const ORIGIN: Self = Self { x: 80.0, y: 80.0 };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StealthProfile {
    Fast,
    Human,
    Paranoid,
}

impl StealthProfile {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "fast" => Self::Fast,
            "paranoid" => Self::Paranoid,
            _ => Self::Human,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Human => "human",
            Self::Paranoid => "paranoid",
        }
    }
}

// ─── Element geometry ───────────────────────────────────────────────────

/// Viewport coordinates of an element's content-box center, via CDP
/// `DOM.getBoxModel`. Used by every input handler that targets a ref.
pub async fn element_center(sess: &BrowserSession, backend_node_id: i64) -> Result<Point, String> {
    let resp = sess.send("DOM.getBoxModel", json!({ "backendNodeId": backend_node_id })).await?;
    let quad = resp
        .pointer("/model/content")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "code=NO_BOX hint=\"element has no layout box (display:none?)\"".to_string())?;
    if quad.len() < 8 {
        return Err("code=BAD_QUAD hint=\"DOM.getBoxModel returned a malformed quad\"".into());
    }
    let mut xs = 0.0_f64;
    let mut ys = 0.0_f64;
    for i in 0..4 {
        xs += quad[i * 2].as_f64().unwrap_or(0.0);
        ys += quad[i * 2 + 1].as_f64().unwrap_or(0.0);
    }
    Ok(Point { x: xs / 4.0, y: ys / 4.0 })
}

/// Scroll the element into view so its center is hit-testable, then return
/// its post-scroll viewport coordinates. Mirrors `el.scrollIntoView`.
pub async fn scroll_into_view(sess: &BrowserSession, backend_node_id: i64) -> Result<(), String> {
    let _ = sess.send("DOM.scrollIntoViewIfNeeded", json!({ "backendNodeId": backend_node_id })).await;
    Ok(())
}

// ─── Trajectories ───────────────────────────────────────────────────────

/// Generate a list of (point, ms-since-start) pairs describing a humanlike
/// path from `from` to `to`. Quadratic Bezier with a perpendicular control
/// point offset, ease-out cubic timing, gaussian jitter peaking mid-path,
/// optional overshoot in paranoid mode.
pub fn human_path(from: Point, to: Point, profile: StealthProfile) -> Vec<(Point, u64)> {
    if profile == StealthProfile::Fast {
        return vec![(to, 0)];
    }
    let mut rng = rand::thread_rng();
    let dx = to.x - from.x;
    let dy = to.y - from.y;
    let dist = (dx * dx + dy * dy).sqrt();
    let n = ((dist / 28.0) as usize + 8).clamp(8, 18);
    let total_ms: u64 = match profile {
        StealthProfile::Paranoid => rng.gen_range(380..620),
        _ => rng.gen_range(220..440),
    };

    // Perpendicular offset for the Bezier control point (random side, magnitude
    // proportional to distance).
    let perp = if dist > 1.0 {
        let n_x = -dy / dist;
        let n_y = dx / dist;
        let mag = dist * rng.gen_range(0.10..0.30) * if rng.gen_bool(0.5) { 1.0 } else { -1.0 };
        (n_x * mag, n_y * mag)
    } else {
        (0.0, 0.0)
    };
    let cx = (from.x + to.x) / 2.0 + perp.0;
    let cy = (from.y + to.y) / 2.0 + perp.1;

    let mut path: Vec<(Point, u64)> = Vec::with_capacity(n + 2);
    for i in 0..n {
        let t_lin = (i as f64) / (n as f64 - 1.0);
        // ease-out cubic for position
        let t = 1.0 - (1.0 - t_lin).powi(3);
        let bx = (1.0 - t).powi(2) * from.x + 2.0 * (1.0 - t) * t * cx + t.powi(2) * to.x;
        let by = (1.0 - t).powi(2) * from.y + 2.0 * (1.0 - t) * t * cy + t.powi(2) * to.y;
        let jitter_peak = t_lin * (1.0 - t_lin) * 4.0; // ∈ [0,1], peaks at t=0.5
        let jitter_mag = match profile {
            StealthProfile::Paranoid => 1.8,
            _ => 1.2,
        } * jitter_peak;
        let jx = rng.gen_range(-jitter_mag..=jitter_mag);
        let jy = rng.gen_range(-jitter_mag..=jitter_mag);
        let ms = (t_lin * total_ms as f64) as u64;
        path.push((Point { x: bx + jx, y: by + jy }, ms));
    }
    // Optional overshoot near target in paranoid mode (40% chance).
    if profile == StealthProfile::Paranoid && rng.gen_bool(0.4) && dist > 60.0 {
        let over_mag = rng.gen_range(5.0..12.0);
        let dir_x = dx / dist.max(1.0);
        let dir_y = dy / dist.max(1.0);
        path.push((Point { x: to.x + dir_x * over_mag, y: to.y + dir_y * over_mag }, total_ms + 35));
        path.push((to, total_ms + 90));
    } else {
        // Ensure last point lands exactly on target.
        if let Some(last) = path.last_mut() {
            last.0 = to;
            last.1 = total_ms;
        }
    }
    path
}

// ─── Mouse ──────────────────────────────────────────────────────────────

/// Move the virtual cursor to `target` along a humanlike path. Each step is
/// a CDP `Input.dispatchMouseEvent(mouseMoved)` — the resulting DOM mousemove
/// events have `isTrusted:true` and trigger normal hover/leave bookkeeping.
///
/// In parallel we kick off a client-side rAF animation of the visible AI
/// cursor through the same waypoints. The cursor is driven explicitly from
/// here (not by the page's mousemove listeners) so a user wiggling their
/// real mouse can't drag the visual cursor off the AI's path.
pub async fn move_mouse(sess: &BrowserSession, target: Point, profile: StealthProfile) -> Result<(), String> {
    let start = sess.cursor_pos().await;
    let path = human_path(start, target, profile);

    // Kick off the client-side cursor animation through the whole path. Runs
    // in parallel with the CDP event dispatch below; both are timed off the
    // same waypoint list so they stay in sync visually.
    let path_json: Vec<[f64; 3]> = path.iter().map(|(p, ms)| [p.x, p.y, *ms as f64]).collect();
    if let Ok(serialised) = serde_json::to_string(&path_json) {
        let _ = sess
            .send(
                "Runtime.evaluate",
                json!({
                    "expression": format!("window.__ws_cursor_animate && window.__ws_cursor_animate({})", serialised),
                    "returnByValue": true,
                }),
            )
            .await;
    }

    let mut last_ms = 0u64;
    for (p, ms) in &path {
        let dt = ms.saturating_sub(last_ms);
        if dt > 0 {
            tokio::time::sleep(Duration::from_millis(dt)).await;
        }
        last_ms = *ms;
        sess.send(
            "Input.dispatchMouseEvent",
            json!({
                "type": "mouseMoved",
                "x": p.x,
                "y": p.y,
                "button": "none",
                "buttons": 0,
            }),
        )
        .await?;
    }
    sess.set_cursor_pos(target).await;
    Ok(())
}

/// Click at the cursor's current position: press → small hold → release.
/// Chrome auto-fires `click` on release if both events are over the same
/// element. Also triggers the visible ripple on the AI cursor overlay.
pub async fn click_at(sess: &BrowserSession, p: Point) -> Result<(), String> {
    let hold_ms = rand::thread_rng().gen_range(32..78);
    sess.send(
        "Input.dispatchMouseEvent",
        json!({
            "type": "mousePressed",
            "x": p.x,
            "y": p.y,
            "button": "left",
            "buttons": 1,
            "clickCount": 1,
        }),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(hold_ms)).await;
    sess.send(
        "Input.dispatchMouseEvent",
        json!({
            "type": "mouseReleased",
            "x": p.x,
            "y": p.y,
            "button": "left",
            "buttons": 0,
            "clickCount": 1,
        }),
    )
    .await?;
    // Fire the visible ripple at the click coordinates.
    let _ = sess
        .send(
            "Runtime.evaluate",
            json!({
                "expression": format!(
                    "window.__ws_cursor_ripple && window.__ws_cursor_ripple({}, {})",
                    p.x, p.y
                ),
                "returnByValue": true,
            }),
        )
        .await;
    Ok(())
}

/// Mouse wheel scroll at the cursor's current position. Fires native wheel
/// events; CSS overflow:auto / overscroll-behavior react correctly.
pub async fn wheel_scroll(sess: &BrowserSession, delta_x: f64, delta_y: f64) -> Result<(), String> {
    let p = sess.cursor_pos().await;
    sess.send(
        "Input.dispatchMouseEvent",
        json!({
            "type": "mouseWheel",
            "x": p.x,
            "y": p.y,
            "deltaX": delta_x,
            "deltaY": delta_y,
            "modifiers": 0,
        }),
    )
    .await?;
    Ok(())
}

// ─── Keyboard ───────────────────────────────────────────────────────────

/// Per-character delay for humanlike typing. Drawn from a Gaussian via
/// Central Limit Theorem approximation (avg of 4 uniforms), clamped to
/// [25, 380] ms. Adds extra time for first-in-field, spaces, and punctuation.
pub fn typing_delay(ch: char, is_first_in_field: bool, profile: StealthProfile) -> Duration {
    if profile == StealthProfile::Fast {
        return Duration::from_millis(0);
    }
    let mut rng = rand::thread_rng();
    let (mu, sigma) = match profile {
        StealthProfile::Paranoid => (115.0_f64, 38.0_f64),
        _ => (80.0_f64, 32.0_f64),
    };
    // CLT-approximate normal: sum of 4 uniforms - 2, scaled by sqrt(12/4)*sigma.
    let z: f64 = (0..4).map(|_| rng.gen::<f64>()).sum::<f64>() - 2.0;
    let mut delay = mu + z * sigma * 0.866; // 0.866 ≈ sqrt(3/4) for variance match
    if is_first_in_field {
        delay += rng.gen_range(80.0..220.0);
    }
    if ch == ' ' {
        delay += rng.gen_range(20.0..90.0);
    }
    if matches!(ch, '.' | ',' | ';' | ':' | '!' | '?') {
        delay += rng.gen_range(40.0..130.0);
    }
    Duration::from_millis(delay.clamp(25.0, 380.0) as u64)
}

/// Type a UTF-8 string into the focused element, char by char, with
/// humanised cadence. Each char goes through `Input.insertText` which
/// correctly fires beforeinput/input events with isTrusted:true and
/// handles IME / composition correctly. Also pops a typehint above the
/// focused field every few characters so the user can see what's being
/// typed.
pub async fn type_text_humanlike(
    sess: &BrowserSession,
    text: &str,
    profile: StealthProfile,
) -> Result<(), String> {
    let total = text.chars().count();
    for (i, ch) in text.chars().enumerate() {
        let d = typing_delay(ch, i == 0, profile);
        if !d.is_zero() {
            tokio::time::sleep(d).await;
        }
        sess.send("Input.insertText", json!({ "text": ch.to_string() })).await?;
        // Show a typehint above the focused field — only at start, end, and
        // every 5 chars in between to keep CDP roundtrips light.
        if i == 0 || i + 1 == total || i % 5 == 0 {
            let safe_ch = ch.to_string().replace(['\\', '"', '\''], "");
            let _ = sess
                .send(
                    "Runtime.evaluate",
                    json!({
                        "expression": format!(
                            "(() => {{ const t = document.activeElement; if (!t || !t.getBoundingClientRect) return; const r = t.getBoundingClientRect(); window.__ws_cursor_typehint && window.__ws_cursor_typehint(r.left + r.width/2, Math.max(20, r.top - 4), '{}'); }})()",
                            safe_ch
                        ),
                        "returnByValue": true,
                    }),
                )
                .await;
        }
    }
    Ok(())
}

/// Map a high-level key name to the CDP `code` / `key` / `text` triple.
/// Covers Enter, Tab, Esc, arrows, Backspace, Delete, F1-F12, Home/End,
/// PageUp/Down. Modifier-only keys (Shift/Ctrl/Alt/Meta) handled separately.
pub fn key_descriptor(name: &str) -> (String, String, Option<String>, i32) {
    // (key, code, text, native_virtual_keycode_unused)
    let n = name.trim();
    let lower = n.to_lowercase();
    match lower.as_str() {
        "enter" | "return" => ("Enter".into(), "Enter".into(), Some("\r".into()), 13),
        "tab" => ("Tab".into(), "Tab".into(), Some("\t".into()), 9),
        "escape" | "esc" => ("Escape".into(), "Escape".into(), None, 27),
        "backspace" => ("Backspace".into(), "Backspace".into(), None, 8),
        "delete" | "del" => ("Delete".into(), "Delete".into(), None, 46),
        "space" => (" ".into(), "Space".into(), Some(" ".into()), 32),
        "arrowup" | "up" => ("ArrowUp".into(), "ArrowUp".into(), None, 38),
        "arrowdown" | "down" => ("ArrowDown".into(), "ArrowDown".into(), None, 40),
        "arrowleft" | "left" => ("ArrowLeft".into(), "ArrowLeft".into(), None, 37),
        "arrowright" | "right" => ("ArrowRight".into(), "ArrowRight".into(), None, 39),
        "home" => ("Home".into(), "Home".into(), None, 36),
        "end" => ("End".into(), "End".into(), None, 35),
        "pageup" => ("PageUp".into(), "PageUp".into(), None, 33),
        "pagedown" => ("PageDown".into(), "PageDown".into(), None, 34),
        "f1" => ("F1".into(), "F1".into(), None, 112),
        "f2" => ("F2".into(), "F2".into(), None, 113),
        "f3" => ("F3".into(), "F3".into(), None, 114),
        "f4" => ("F4".into(), "F4".into(), None, 115),
        "f5" => ("F5".into(), "F5".into(), None, 116),
        "f6" => ("F6".into(), "F6".into(), None, 117),
        "f7" => ("F7".into(), "F7".into(), None, 118),
        "f8" => ("F8".into(), "F8".into(), None, 119),
        "f9" => ("F9".into(), "F9".into(), None, 120),
        "f10" => ("F10".into(), "F10".into(), None, 121),
        "f11" => ("F11".into(), "F11".into(), None, 122),
        "f12" => ("F12".into(), "F12".into(), None, 123),
        _ => {
            // Treat as a single character key.
            let ch = n.chars().next().unwrap_or(' ');
            let code = if ch.is_ascii_alphabetic() {
                format!("Key{}", ch.to_ascii_uppercase())
            } else if ch.is_ascii_digit() {
                format!("Digit{}", ch)
            } else {
                String::new()
            };
            (ch.to_string(), code, Some(ch.to_string()), ch as u32 as i32)
        }
    }
}

/// Dispatch a real keyDown→keyUp through CDP. Modifiers are CDP modifier
/// mask (1=Alt, 2=Ctrl, 4=Meta, 8=Shift).
///
/// When modifiers are set (i.e. a keyboard shortcut like Ctrl+A), we use
/// `rawKeyDown` AND omit `text`. Chromium otherwise treats `keyDown` with
/// `text` as a character insert regardless of modifier state — `Ctrl+A`
/// would actually type "a" before doing select-all (caused the famous
/// "aErnst / aGuttenbrunner" prefix bug in 0.3.3 alpha). Without text,
/// the shortcut path runs cleanly. For unmodified printable keys we keep
/// `keyDown`+`text` so `<input>` / `<textarea>` get the char correctly.
pub async fn press_key(sess: &BrowserSession, name: &str, modifiers: i32) -> Result<(), String> {
    let (key, code, text, _vk) = key_descriptor(name);
    let with_mods = modifiers != 0;
    let down_type = if with_mods { "rawKeyDown" } else { "keyDown" };

    let mut down = json!({
        "type": down_type,
        "key": key,
        "code": code,
        "modifiers": modifiers,
    });
    if !with_mods {
        if let Some(t) = &text {
            down["text"] = json!(t);
        }
    }
    sess.send("Input.dispatchKeyEvent", down).await?;
    let hold_ms = rand::thread_rng().gen_range(28..72);
    tokio::time::sleep(Duration::from_millis(hold_ms)).await;
    sess.send(
        "Input.dispatchKeyEvent",
        json!({
            "type": "keyUp",
            "key": key,
            "code": code,
            "modifiers": modifiers,
        }),
    )
    .await?;
    Ok(())
}

/// Select all + delete — used to clear a field before typing fresh content.
/// Goes through real keyDown/Up so the resulting input events are isTrusted.
pub async fn clear_field(sess: &BrowserSession) -> Result<(), String> {
    // Ctrl-A
    press_key(sess, "a", 2).await?;
    tokio::time::sleep(Duration::from_millis(35)).await;
    // Delete
    press_key(sess, "Delete", 0).await?;
    Ok(())
}

// ─── Dwell ──────────────────────────────────────────────────────────────

/// Pause before/after an action so the visible cursor settles and the
/// page's "time on field" telemetry sees a humanlike interval. Skipped in
/// Fast profile.
pub async fn dwell(profile: StealthProfile) {
    let (lo, hi) = match profile {
        StealthProfile::Fast => return,
        StealthProfile::Paranoid => (450, 1100),
        StealthProfile::Human => (220, 600),
    };
    let ms = rand::thread_rng().gen_range(lo..hi);
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

// ─── High-level orchestration ──────────────────────────────────────────

/// Move mouse to element center, dwell briefly, then press+release.
pub async fn click_element(
    sess: &BrowserSession,
    backend_node_id: i64,
    profile: StealthProfile,
) -> Result<Point, String> {
    scroll_into_view(sess, backend_node_id).await.ok();
    let p = element_center(sess, backend_node_id).await?;
    move_mouse(sess, p, profile).await?;
    dwell(profile).await;
    click_at(sess, p).await?;
    Ok(p)
}

/// Click into a field to focus it (real focus event), optionally clear,
/// then type with humanised cadence.
pub async fn type_into_element(
    sess: &BrowserSession,
    backend_node_id: i64,
    text: &str,
    clear: bool,
    profile: StealthProfile,
) -> Result<(), String> {
    scroll_into_view(sess, backend_node_id).await.ok();
    let p = element_center(sess, backend_node_id).await?;
    move_mouse(sess, p, profile).await?;
    dwell(profile).await;
    click_at(sess, p).await?;
    if clear {
        clear_field(sess).await.ok();
    }
    type_text_humanlike(sess, text, profile).await?;
    Ok(())
}

/// Convenience: dispatch a CDP raw value into the session's send pipeline,
/// useful for tools that need to bundle multiple input events. Not used
/// directly by browser_* handlers but kept for stealth_check etc.
pub async fn raw(sess: &BrowserSession, method: &str, params: Value) -> Result<Value, String> {
    sess.send(method, params).await
}
