// HTML meta-tag extraction.
//
// Pulls out everything a thorough crawler should look at:
//   - <title>, <meta name="description">, <meta name="generator">
//   - <link rel="canonical">, Link: rel=canonical header
//   - <meta http-equiv="refresh">  (treated as a redirect signal)
//   - <link rel="alternate" hreflang> (per-locale variants)
//   - <meta property="og:*"> Open Graph
//   - <meta name="twitter:*">
//   - <meta name="csrf-token"> / <meta name="anti-csrf">
//   - <meta http-equiv="content-security-policy"> (in-HTML CSP)
//
// All extraction is regex-based to avoid pulling a full DOM parser into the
// crawler hot path. The scraper crate handles deeper HTML walks in C10
// (JS-render pass).

use serde::Serialize;

#[derive(Debug, Default, Serialize, Clone)]
pub struct MetaReport {
    pub title: Option<String>,
    pub description: Option<String>,
    pub generator: Option<String>,
    pub canonical: Option<String>,
    pub meta_refresh_target: Option<String>,
    pub meta_refresh_seconds: Option<u32>,
    pub csrf_token_meta: Option<String>,
    pub csp_meta: Option<String>,
    pub robots_meta: Option<String>,
    pub open_graph: Vec<(String, String)>,
    pub twitter_card: Vec<(String, String)>,
    pub hreflang: Vec<HreflangAlt>,
    pub favicon: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct HreflangAlt {
    pub lang: String,
    pub href: String,
}

pub fn extract_meta(html: &str) -> MetaReport {
    let mut r = MetaReport::default();
    if html.is_empty() {
        return r;
    }

    // <title>...</title>
    if let Some(c) = regex::Regex::new(r#"(?is)<title[^>]*>\s*([^<]+?)\s*</title>"#).unwrap().captures(html) {
        r.title = c.get(1).map(|m| m.as_str().trim().to_string());
    }

    // <meta name="description" content="...">
    r.description = meta_content(html, "description");
    r.generator = meta_content(html, "generator");
    r.robots_meta = meta_content(html, "robots");
    r.csrf_token_meta = meta_content(html, "csrf-token")
        .or_else(|| meta_content(html, "csrf"))
        .or_else(|| meta_content(html, "_token"))
        .or_else(|| meta_content(html, "x-csrf-token"));

    // <meta http-equiv="content-security-policy" content="...">
    r.csp_meta = http_equiv_content(html, "content-security-policy");

    // <meta http-equiv="refresh" content="0;url=https://...">
    if let Some(refresh) = http_equiv_content(html, "refresh") {
        let lower = refresh.to_ascii_lowercase();
        // Format: "N;url=..." or "N; URL=..."
        if let Some(i) = lower.find("url=") {
            let url_part = refresh[i + 4..].trim().trim_matches('"').trim_matches('\'');
            r.meta_refresh_target = Some(url_part.to_string());
        }
        let seconds_str = refresh.split(';').next().unwrap_or("0").trim();
        if let Ok(s) = seconds_str.parse::<u32>() {
            r.meta_refresh_seconds = Some(s);
        }
    }

    // <link rel="canonical" href="...">
    let canon_re = regex::Regex::new(
        r#"(?is)<link\s+[^>]*rel\s*=\s*["']?\s*canonical\s*["']?[^>]*href\s*=\s*["']([^"']+)["']"#,
    )
    .unwrap();
    if let Some(c) = canon_re.captures(html) {
        r.canonical = c.get(1).map(|m| m.as_str().trim().to_string());
    } else {
        // Also try the href-then-rel ordering.
        let alt = regex::Regex::new(
            r#"(?is)<link\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*rel\s*=\s*["']?\s*canonical\s*["']?"#,
        )
        .unwrap();
        if let Some(c) = alt.captures(html) {
            r.canonical = c.get(1).map(|m| m.as_str().trim().to_string());
        }
    }

    // <link rel="alternate" hreflang="..." href="...">
    let hreflang_re = regex::Regex::new(
        r#"(?is)<link\s+[^>]*rel\s*=\s*["']alternate["'][^>]*hreflang\s*=\s*["']([^"']+)["'][^>]*href\s*=\s*["']([^"']+)["']"#,
    )
    .unwrap();
    for c in hreflang_re.captures_iter(html) {
        let lang = c.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
        let href = c.get(2).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
        if !lang.is_empty() && !href.is_empty() {
            r.hreflang.push(HreflangAlt { lang, href });
        }
    }
    // href-then-hreflang variant
    let hreflang_re2 = regex::Regex::new(
        r#"(?is)<link\s+[^>]*rel\s*=\s*["']alternate["'][^>]*href\s*=\s*["']([^"']+)["'][^>]*hreflang\s*=\s*["']([^"']+)["']"#,
    )
    .unwrap();
    for c in hreflang_re2.captures_iter(html) {
        let href = c.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
        let lang = c.get(2).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
        if !lang.is_empty()
            && !href.is_empty()
            && !r.hreflang.iter().any(|h| h.href == href && h.lang == lang)
        {
            r.hreflang.push(HreflangAlt { lang, href });
        }
    }

    // <meta property="og:..." content="...">
    let og_re = regex::Regex::new(
        r#"(?is)<meta\s+[^>]*property\s*=\s*["'](og:[^"']+)["'][^>]*content\s*=\s*["']([^"']*)["']"#,
    )
    .unwrap();
    for c in og_re.captures_iter(html) {
        let key = c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let val = c.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
        r.open_graph.push((key, val));
    }

    // <meta name="twitter:..." content="...">
    let tw_re = regex::Regex::new(
        r#"(?is)<meta\s+[^>]*name\s*=\s*["'](twitter:[^"']+)["'][^>]*content\s*=\s*["']([^"']*)["']"#,
    )
    .unwrap();
    for c in tw_re.captures_iter(html) {
        let key = c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let val = c.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
        r.twitter_card.push((key, val));
    }

    // Favicon: <link rel="icon" href="..."> or rel="shortcut icon"
    let fav_re = regex::Regex::new(
        r#"(?is)<link\s+[^>]*rel\s*=\s*["'](?:[^"']*icon[^"']*)["'][^>]*href\s*=\s*["']([^"']+)["']"#,
    )
    .unwrap();
    if let Some(c) = fav_re.captures(html) {
        r.favicon = c.get(1).map(|m| m.as_str().to_string());
    }

    r
}

fn meta_content(html: &str, name: &str) -> Option<String> {
    let pat = format!(
        r#"(?is)<meta\s+[^>]*name\s*=\s*["']{}["'][^>]*content\s*=\s*["']([^"']*)["']"#,
        regex::escape(name)
    );
    let re = regex::Regex::new(&pat).ok()?;
    re.captures(html).and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
}

fn http_equiv_content(html: &str, name: &str) -> Option<String> {
    let pat = format!(
        r#"(?is)<meta\s+[^>]*http-equiv\s*=\s*["']{}["'][^>]*content\s*=\s*["']([^"']*)["']"#,
        regex::escape(name)
    );
    let re = regex::Regex::new(&pat).ok()?;
    re.captures(html).and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_title_description() {
        let html = r#"<html><head>
            <title>  Hello  </title>
            <meta name="description" content="World">
        </head></html>"#;
        let r = extract_meta(html);
        assert_eq!(r.title.as_deref(), Some("Hello"));
        assert_eq!(r.description.as_deref(), Some("World"));
    }

    #[test]
    fn extracts_canonical() {
        let html = r#"<head><link rel="canonical" href="https://example.com/a"></head>"#;
        let r = extract_meta(html);
        assert_eq!(r.canonical.as_deref(), Some("https://example.com/a"));
    }

    #[test]
    fn extracts_meta_refresh() {
        let html = r#"<meta http-equiv="refresh" content="5;url=/login">"#;
        let r = extract_meta(html);
        assert_eq!(r.meta_refresh_target.as_deref(), Some("/login"));
        assert_eq!(r.meta_refresh_seconds, Some(5));
    }

    #[test]
    fn extracts_hreflang() {
        let html = r#"
            <link rel="alternate" hreflang="de" href="https://example.de/">
            <link rel="alternate" hreflang="fr" href="https://example.fr/">
        "#;
        let r = extract_meta(html);
        assert_eq!(r.hreflang.len(), 2);
        assert_eq!(r.hreflang[0].lang, "de");
    }

    #[test]
    fn extracts_open_graph() {
        let html = r#"
            <meta property="og:title" content="WonderSuite">
            <meta property="og:image" content="/logo.png">
        "#;
        let r = extract_meta(html);
        assert_eq!(r.open_graph.len(), 2);
    }

    #[test]
    fn extracts_csrf_token() {
        let html = r#"<meta name="csrf-token" content="abc123">"#;
        let r = extract_meta(html);
        assert_eq!(r.csrf_token_meta.as_deref(), Some("abc123"));
    }
}
