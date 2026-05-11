// SPA detection.
//
// Run on every HTML response. Returns a confidence score 0..1 plus the names
// of triggered heuristics; anything > 0.5 is worth a CDP JS-render pass.
//
// Heuristics (any one trips, multiple compound):
//   1. <div id="root"> / "app" / "__next" / "nuxt-app" / "svelte" with tiny preceding body
//   2. <script src> referencing a known SPA bundler signature
//   3. <noscript> "you need JavaScript enabled" message
//   4. low visible-text density + high script count
//   5. presence of __NUXT__, __APOLLO_STATE__, __INITIAL_STATE__, data-react-helmet
//   6. text/html response with no <a href> AND no <form>

use serde::Serialize;

#[derive(Debug, Default, Clone, Serialize)]
pub struct SpaReport {
    pub confidence: f32,
    pub triggers: Vec<&'static str>,
    /// True iff confidence >= 0.5 — convenience for callers.
    pub is_spa: bool,
}

const ROOT_DIVS: &[(&str, &str)] = &[
    ("root", "React"),
    ("app", "Vue/Generic"),
    ("__next", "Next.js"),
    ("__nuxt", "Nuxt"),
    ("nuxt-app", "Nuxt"),
    ("svelte", "Svelte"),
    ("__svelte", "SvelteKit"),
    ("astro-root", "Astro"),
    ("___gatsby", "Gatsby"),
    ("remix-app", "Remix"),
];

const BUNDLER_SIGNATURES: &[&str] = &[
    "_next/static",
    "_nuxt/",
    "/__webpack",
    "chunk-vendors",
    "runtime~main",
    "webpackChunk",
    "/static/js/main.",
    "/static/js/bundle.",
    "/static/js/runtime~",
    "assets/index-",
    "assets/main-",
    "vite-plugin-",
    "@vite/client",
    "vite/dist/client",
];

const STATE_GLOBALS: &[&str] = &[
    "__NUXT__",
    "__APOLLO_STATE__",
    "__INITIAL_STATE__",
    "__REDUX_STATE__",
    "__NEXT_DATA__",
    "data-react-helmet",
    "data-reactroot",
    "data-vue-meta",
    "data-server-rendered",
];

pub fn detect_spa(html: &str) -> SpaReport {
    let mut r = SpaReport::default();
    if html.is_empty() {
        return r;
    }

    // ── 1. Root divs + small body before them ────────────────────────────
    for (id, framework) in ROOT_DIVS {
        if let Some(pos) = find_root_div(html, id) {
            // Only count it as SPA-like if the body BEFORE the root div is small
            // (< 2 KB of visible text). Server-rendered pages usually have lots
            // of content above the root div.
            let before = &html[..pos];
            if visible_text_len(before) < 2048 {
                r.triggers.push(framework);
                r.confidence += 0.4;
                break;
            }
        }
    }

    // ── 2. Bundler signatures ────────────────────────────────────────────
    for sig in BUNDLER_SIGNATURES {
        if html.contains(sig) {
            r.triggers.push("bundler-signature");
            r.confidence += 0.3;
            break;
        }
    }

    // ── 3. <noscript> warning ────────────────────────────────────────────
    if has_noscript_warning(html) {
        r.triggers.push("noscript-warning");
        r.confidence += 0.3;
    }

    // ── 4. State globals ─────────────────────────────────────────────────
    for needle in STATE_GLOBALS {
        if html.contains(needle) {
            r.triggers.push("state-global");
            r.confidence += 0.3;
            break;
        }
    }

    // ── 5. Low visible-text density, many scripts ─────────────────────────
    let visible_len = visible_text_len(html);
    let script_count = count_tag(html, "script");
    if visible_len < 200 && script_count > 3 {
        r.triggers.push("low-text-many-scripts");
        r.confidence += 0.25;
    }

    // ── 6. No anchors AND no forms ───────────────────────────────────────
    let anchor_count = regex::Regex::new(r#"(?i)<a\s+[^>]*href="#).unwrap().find_iter(html).count();
    let form_count = count_tag(html, "form");
    if anchor_count == 0 && form_count == 0 && html.to_ascii_lowercase().contains("</html>") {
        r.triggers.push("no-anchors-no-forms");
        r.confidence += 0.15;
    }

    r.confidence = r.confidence.min(1.0);
    r.is_spa = r.confidence >= 0.5;
    r
}

fn find_root_div(html: &str, id: &str) -> Option<usize> {
    let pat = format!(r#"(?is)<div\s+[^>]*id\s*=\s*["']?{}["']?"#, regex::escape(id));
    let re = regex::Regex::new(&pat).ok()?;
    re.find(html).map(|m| m.start())
}

fn has_noscript_warning(html: &str) -> bool {
    let re = regex::Regex::new(r#"(?is)<noscript[^>]*>(.*?)</noscript>"#).unwrap();
    for c in re.captures_iter(html) {
        let block = c.get(1).map(|m| m.as_str().to_ascii_lowercase()).unwrap_or_default();
        if block.contains("javascript") && (block.contains("enable") || block.contains("required")) {
            return true;
        }
        if block.contains("aktivieren") || block.contains("activer") || block.contains("habilitar") {
            return true; // de / fr / es
        }
    }
    false
}

fn count_tag(html: &str, tag: &str) -> usize {
    let pat = format!(r#"(?is)<{}\b"#, regex::escape(tag));
    let re = match regex::Regex::new(&pat) {
        Ok(r) => r,
        Err(_) => return 0,
    };
    re.find_iter(html).count()
}

/// Strip tags, scripts, styles, count remaining visible characters.
/// The regex crate doesn't support backreferences, so we strip script/style
/// in two passes with named tags.
fn visible_text_len(html: &str) -> usize {
    let script_re = regex::Regex::new(r#"(?is)<script[^>]*>.*?</script>"#).unwrap();
    let style_re = regex::Regex::new(r#"(?is)<style[^>]*>.*?</style>"#).unwrap();
    let stripped = script_re.replace_all(html, "");
    let stripped = style_re.replace_all(&stripped, "");
    let no_tags = regex::Regex::new(r#"(?s)<[^>]+>"#).unwrap().replace_all(&stripped, "");
    no_tags.trim().chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_react_root() {
        let html = r#"<html><head></head><body><div id="root"></div><script src="/_next/static/runtime.js"></script></body></html>"#;
        let r = detect_spa(html);
        assert!(r.is_spa);
        assert!(r.triggers.iter().any(|t| *t == "React" || *t == "Next.js"));
    }

    #[test]
    fn detects_noscript() {
        let html = r#"<html><body><noscript>You need to enable JavaScript to run this app.</noscript></body></html>"#;
        let r = detect_spa(html);
        assert!(r.triggers.contains(&"noscript-warning"));
    }

    #[test]
    fn server_rendered_negative() {
        let html = r#"<html><body>
            <h1>Welcome</h1>
            <p>Lots of content here. About us, products, contact, etc.</p>
            <a href="/about">About</a>
            <a href="/products">Products</a>
            <form action="/search"><input name="q"></form>
        </body></html>"#;
        let r = detect_spa(html);
        assert!(!r.is_spa);
    }

    #[test]
    fn nuxt_detected_via_state_global() {
        let html = r#"<script>window.__NUXT__={data:[...]};</script>"#;
        let r = detect_spa(html);
        assert!(r.triggers.contains(&"state-global"));
    }
}
