// The killer pentest primitive: a11y tree with stable refs + form analysis +
// security block. Every input tool addresses elements by ref=eNN coming from
// the most-recent snapshot. Stale refs return STALE_REF with a re-snap hint
// so the agent recovers in one round-trip.

use serde::Serialize;
use std::collections::HashMap;

use super::session::BrowserSession;

#[derive(Default, Debug)]
pub struct RefMap {
    // ref ("e3") → CDP backendDOMNodeId (numeric), captured at snapshot time.
    by_ref: HashMap<String, i64>,
    next: u32,
}

impl RefMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.by_ref.clear();
        self.next = 0;
    }

    pub fn assign(&mut self, backend_node_id: i64) -> String {
        self.next += 1;
        let id = format!("e{}", self.next);
        self.by_ref.insert(id.clone(), backend_node_id);
        id
    }

    pub fn resolve(&self, r: &str) -> Option<i64> {
        self.by_ref.get(r).copied()
    }
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub url: String,
    pub title: String,
    pub stats: SnapStats,
    pub tree: String,
    pub forms: serde_json::Value,
    pub security: serde_json::Value,
}

#[derive(Debug, Default, Serialize)]
pub struct SnapStats {
    pub interactives: u32,
    pub forms: u32,
    pub iframes: u32,
    pub shadow_roots: u32,
    pub links: u32,
}

impl SnapStats {
    pub fn merge(&mut self, other: &SnapStats) {
        self.interactives += other.interactives;
        self.forms += other.forms;
        self.iframes += other.iframes;
        self.shadow_roots += other.shadow_roots;
        self.links += other.links;
    }
}

pub async fn capture(sess: &BrowserSession, include_security: bool) -> Result<Snapshot, String> {
    let url = sess
        .eval("document.location.href")
        .await
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default();
    let title =
        sess.eval("document.title").await.ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();

    // v0.3.17: enumerate every frame in the page so iframe descendants are
    // also captured. Previously `Accessibility.getFullAXTree({})` only
    // returned the main frame's tree — buttons inside an auth iframe (Stripe,
    // hCaptcha, OAuth pop-ups, embedded admin panels) were invisible to the
    // AI, breaking `browser_click` with "not in snapshot — re-snap".
    let frame_ids = collect_frame_ids(sess).await;

    let mut refmap = RefMap::new();
    let mut tree = String::new();
    let mut stats = SnapStats::default();

    // Main frame first — no frameId parameter so we get the page-level tree.
    if let Ok(ax) = sess.send("Accessibility.getFullAXTree", serde_json::json!({})).await {
        if let Some(nodes) = ax["nodes"].as_array() {
            let (t, s) = render_ax_tree(nodes, &mut refmap);
            tree.push_str(&t);
            stats.merge(&s);
        }
    }

    // Child frames — one CDP call per frame. Render with a banner so the
    // agent sees which subtree came from which frame.
    for frame_id in &frame_ids {
        let req = serde_json::json!({ "frameId": frame_id });
        let Ok(ax) = sess.send("Accessibility.getFullAXTree", req).await else { continue };
        let Some(nodes) = ax["nodes"].as_array() else { continue };
        if nodes.is_empty() {
            continue;
        }
        let (t, s) = render_ax_tree(nodes, &mut refmap);
        if t.trim().is_empty() {
            continue;
        }
        tree.push_str(&format!("\n--- iframe {} ---\n", frame_id));
        tree.push_str(&t);
        stats.merge(&s);
    }

    *sess.refmap.lock().await = refmap;

    let forms =
        sess.eval(FORMS_AND_LINKS_JS).await.unwrap_or(serde_json::json!({"forms": [], "links_sample": []}));

    let security = if include_security {
        sess.eval(SECURITY_JS).await.unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!(null)
    };

    Ok(Snapshot { url, title, stats, tree, forms, security })
}

/// Walk `Page.getFrameTree` and return every child frame's id. We skip the
/// root frame because `getFullAXTree({})` already covers it.
async fn collect_frame_ids(sess: &BrowserSession) -> Vec<String> {
    let Ok(tree) = sess.send("Page.getFrameTree", serde_json::json!({})).await else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    if let Some(child_frames) = tree.pointer("/frameTree/childFrames").and_then(|v| v.as_array()) {
        collect_frame_ids_rec(child_frames, &mut ids);
    }
    ids
}

fn collect_frame_ids_rec(frames: &[serde_json::Value], out: &mut Vec<String>) {
    for f in frames {
        if let Some(id) = f.pointer("/frame/id").and_then(|v| v.as_str()) {
            out.push(id.to_string());
        }
        if let Some(children) = f["childFrames"].as_array() {
            collect_frame_ids_rec(children, out);
        }
    }
}

fn render_ax_tree(nodes: &[serde_json::Value], refmap: &mut RefMap) -> (String, SnapStats) {
    use std::collections::HashMap;
    let mut by_id: HashMap<String, &serde_json::Value> = HashMap::new();
    let mut root_id: Option<String> = None;
    for n in nodes {
        if let Some(id) = n["nodeId"].as_str() {
            by_id.insert(id.to_string(), n);
            if n.get("parentId").is_none() && root_id.is_none() {
                root_id = Some(id.to_string());
            }
        }
    }

    let mut out = String::new();
    let mut stats = SnapStats::default();
    if let Some(rid) = root_id {
        walk(&by_id, &rid, 0, refmap, &mut out, &mut stats);
    }
    (out, stats)
}

fn walk(
    by_id: &std::collections::HashMap<String, &serde_json::Value>,
    id: &str,
    depth: usize,
    refmap: &mut RefMap,
    out: &mut String,
    stats: &mut SnapStats,
) {
    let Some(node) = by_id.get(id) else { return };

    let role = node.pointer("/role/value").and_then(|v| v.as_str()).unwrap_or("");
    if role == "InlineTextBox" || role == "none" || role == "presentation" {
        if let Some(children) = node["childIds"].as_array() {
            for c in children {
                if let Some(cid) = c.as_str() {
                    walk(by_id, cid, depth, refmap, out, stats);
                }
            }
        }
        return;
    }

    let name = node.pointer("/name/value").and_then(|v| v.as_str()).unwrap_or("");
    let backend_node_id = node["backendDOMNodeId"].as_i64().unwrap_or(0);

    let interesting = matches!(
        role,
        "button"
            | "link"
            | "textbox"
            | "checkbox"
            | "radio"
            | "combobox"
            | "menuitem"
            | "tab"
            | "switch"
            | "searchbox"
            | "slider"
            | "spinbutton"
            | "option"
    );
    if interesting {
        stats.interactives += 1;
    }
    if role == "link" {
        stats.links += 1;
    }
    if role == "iframe" || role == "Iframe" {
        stats.iframes += 1;
    }
    if role == "form" || role == "Form" {
        stats.forms += 1;
    }

    let need_ref = interesting || matches!(role, "form" | "iframe" | "Form" | "Iframe" | "main" | "heading");
    let mut line = String::new();
    line.push_str(&"  ".repeat(depth));
    line.push_str("- ");
    line.push_str(role);
    if !name.is_empty() {
        line.push_str(&format!(" \"{}\"", truncate(name, 80)));
    }
    if need_ref && backend_node_id != 0 {
        let r = refmap.assign(backend_node_id);
        line.push_str(&format!(" [ref={}]", r));
    }
    if let Some(props) = node["properties"].as_array() {
        for p in props {
            let pname = p["name"].as_str().unwrap_or("");
            let pval = p.pointer("/value/value").cloned().unwrap_or(serde_json::Value::Null);
            match pname {
                "level" => {
                    if let Some(n) = pval.as_i64() {
                        line.push_str(&format!(" [level={}]", n));
                    }
                }
                "checked" => {
                    if let Some(b) = pval.as_bool() {
                        if b {
                            line.push_str(" [checked]");
                        }
                    }
                }
                "expanded" => {
                    if let Some(b) = pval.as_bool() {
                        line.push_str(if b { " [expanded]" } else { " [collapsed]" });
                    }
                }
                "required" => {
                    if pval.as_bool() == Some(true) {
                        line.push_str(" [required]");
                    }
                }
                "disabled" => {
                    if pval.as_bool() == Some(true) {
                        line.push_str(" [disabled]");
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(value) = node.pointer("/value/value").and_then(|v| v.as_str()) {
        if !value.is_empty() {
            line.push_str(&format!(" [value=\"{}\"]", truncate(value, 60)));
        }
    }
    out.push_str(&line);
    out.push('\n');

    if let Some(children) = node["childIds"].as_array() {
        for c in children {
            if let Some(cid) = c.as_str() {
                walk(by_id, cid, depth + 1, refmap, out, stats);
            }
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    let trimmed = s.trim();
    if trimmed.chars().count() <= n {
        trimmed.replace('"', "\\\"")
    } else {
        let mut out: String = trimmed.chars().take(n).collect();
        out.push('…');
        out.replace('"', "\\\"")
    }
}

// Form analyser. Resolves <label for=>, aria-labelledby, parent-text labels.
// Tags hidden inputs whose name matches csrf/xsrf/token/nonce/authenticity
// as `is_token: true` so the agent doesn't have to reason about it.
const FORMS_AND_LINKS_JS: &str = r#"
(() => {
  const labelOf = (el) => {
    if (el.labels && el.labels[0]) return el.labels[0].innerText.trim();
    if (el.id) {
      const l = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
      if (l) return l.innerText.trim();
    }
    const aria = el.getAttribute('aria-labelledby');
    if (aria) {
      const n = aria.split(/\s+/).map(id => document.getElementById(id)).filter(Boolean);
      if (n.length) return n.map(x => x.innerText.trim()).join(' ');
    }
    if (el.getAttribute('aria-label')) return el.getAttribute('aria-label');
    if (el.placeholder) return el.placeholder;
    const p = el.parentElement;
    if (p && p.innerText) return p.innerText.trim().slice(0, 80);
    return null;
  };
  const isToken = (input) => {
    if (input.type !== 'hidden') return false;
    const n = (input.name || input.id || '').toLowerCase();
    if (!/csrf|xsrf|token|nonce|authenticity|_secret|antiforgery/.test(n)) return false;
    return (input.value || '').length >= 16;
  };
  // Modern sites use honeypot fields to catch bots — these are inputs invisible
  // to humans (display:none, off-screen, opacity:0) or with names like
  // `honey`/`trap`/`leave_blank`. Filling them flags the agent as a bot.
  // We return both `is_honeypot` and a `reason` so the agent knows to skip them.
  const isHoneypot = (input) => {
    if (input.type === 'hidden') return null; // hidden fields are normal, not honeypots
    let el = input;
    try {
      const cs = getComputedStyle(input);
      if (cs.display === 'none') return 'display:none';
      if (cs.visibility === 'hidden') return 'visibility:hidden';
      if (parseFloat(cs.opacity) < 0.1) return 'opacity<0.1';
    } catch (_) {}
    const r = input.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return 'zero-size box';
    if (r.left < -500 || r.top < -500) return 'positioned off-screen';
    let p = input.parentElement, depth = 0;
    while (p && depth < 6) {
      try {
        const ps = getComputedStyle(p);
        if (ps.display === 'none') return 'ancestor display:none';
        if (ps.visibility === 'hidden') return 'ancestor visibility:hidden';
        if (parseFloat(ps.opacity) < 0.05) return 'ancestor opacity:0';
        const pr = p.getBoundingClientRect();
        if (pr.left < -500 || pr.top < -500) return 'ancestor off-screen';
      } catch (_) {}
      p = p.parentElement; depth++;
    }
    const n = (input.name || input.id || '').toLowerCase();
    if (/^(honey|honeypot|hp|nobot|bot|spam|trap|leave_?blank|leaveblank|gotcha|website_url|url_for_humans)$/.test(n)) return 'suspicious name pattern';
    if (input.tabIndex === -1 && input.type !== 'submit' && input.type !== 'button' && !input.placeholder && !labelOf(input)) return 'tabindex=-1 without label';
    if (input.getAttribute('autocomplete') === 'off' && /^(email|phone|website|url|name|user)$/.test(n) && !labelOf(input)) return 'unlabelled autocomplete=off field with classic honeypot name';
    return null;
  };
  const forms = Array.from(document.forms).map(f => ({
    action: f.action || null,
    method: (f.method || 'get').toUpperCase(),
    enctype: f.enctype || null,
    name: f.name || null,
    id: f.id || null,
    inputs: Array.from(f.querySelectorAll('input, select, textarea, button')).map(i => {
      const honey = isHoneypot(i);
      return {
        tag: i.tagName.toLowerCase(),
        type: i.type || null,
        name: i.name || null,
        id: i.id || null,
        label: labelOf(i),
        value: i.type === 'password' ? '(redacted)' : (i.value || null),
        placeholder: i.placeholder || null,
        required: !!i.required,
        autocomplete: i.autocomplete || null,
        is_token: isToken(i),
        is_honeypot: !!honey,
        honeypot_reason: honey,
      };
    }),
  }));
  const links_sample = Array.from(document.querySelectorAll('a[href]'))
    .slice(0, 50)
    .map(a => ({ href: a.href, text: (a.innerText || '').trim().slice(0, 80) }));
  return { forms, links_sample, link_total: document.querySelectorAll('a[href]').length };
})()
"#;

const SECURITY_JS: &str = r#"
(() => {
  const out = { csp: null, csp_findings: [], mixed_content: false, frame_ancestors: null, cookies_set_on_page: [], iframes: [] };
  const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy" i]');
  if (cspMeta) out.csp = cspMeta.getAttribute('content');
  if (out.csp) {
    if (/unsafe-inline/i.test(out.csp)) out.csp_findings.push("unsafe-inline directive present");
    if (/unsafe-eval/i.test(out.csp)) out.csp_findings.push("unsafe-eval directive present");
    if (/\*\s*(;|$)/.test(out.csp)) out.csp_findings.push("wildcard source in directive");
    if (!/frame-ancestors/i.test(out.csp)) out.csp_findings.push("no frame-ancestors directive");
    const fa = out.csp.match(/frame-ancestors\s+([^;]+)/i);
    if (fa) out.frame_ancestors = fa[1].trim();
  }
  out.mixed_content = location.protocol === 'https:' &&
    Array.from(document.querySelectorAll('script[src], link[rel="stylesheet"], img[src], iframe[src]'))
      .some(el => /^http:/i.test(el.getAttribute('src') || el.getAttribute('href') || ''));
  try {
    out.cookies_set_on_page = document.cookie.split(/;\s*/).filter(Boolean).map(c => {
      const eq = c.indexOf('=');
      return { name: eq > 0 ? c.slice(0, eq) : c, has_value: eq > 0 };
    });
  } catch (_) { out.cookies_set_on_page = []; }
  out.iframes = Array.from(document.querySelectorAll('iframe')).slice(0, 20).map(f => ({
    src: f.src || null, sandbox: f.sandbox && f.sandbox.value || null, name: f.name || null
  }));
  out.referrer_policy = document.referrerPolicy || null;
  return out;
})()
"#;
