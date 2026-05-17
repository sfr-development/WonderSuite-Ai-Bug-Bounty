// JS library / framework detection engine.
//
// Philosophy: **detect what is, don't pretend to know what's vulnerable.**
//
// This module identifies frontend libraries (jQuery 1.7.2, Vue 2.6.11,
// AngularJS 1.5.0, …) by matching curated fingerprint regexes against the
// page HTML, `<script src="…">` URLs, and inline `<script>` contents. It
// returns `{name, version, evidence}` per detection.
//
// CVE / vulnerability research is explicitly NOT this module's job — the AI
// agent does that separately with up-to-date web search and its own
// knowledge. Hard-coding vulnerable-version ranges in our binary would mean
// shipping stale data the moment we release.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Compile-time-embedded fingerprint database. ~62 libraries as of v0.3.10.
const FINGERPRINTS_JSON: &str = include_str!("../../resources/jslib/fingerprints.json");

#[derive(Debug, Deserialize)]
struct RawFingerprint {
    name: String,
    #[serde(default)]
    url_patterns: Vec<String>,
    #[serde(default)]
    comment_patterns: Vec<String>,
    #[serde(default)]
    html_patterns: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawDb {
    libraries: Vec<RawFingerprint>,
}

#[derive(Debug, Clone)]
pub struct CompiledFingerprint {
    pub name: String,
    pub url_patterns: Vec<Regex>,
    pub comment_patterns: Vec<Regex>,
    pub html_patterns: Vec<Regex>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub library: String,
    /// `None` when the fingerprint matched but the matching pattern had no
    /// version capture group (e.g. SPA marker `__NEXT_DATA__`).
    pub version: Option<String>,
    /// One of: `script_src`, `inline_script_comment`, `external_script_body`,
    /// `html_pattern`. Tells the agent where the detection came from.
    pub source: &'static str,
    /// Short snippet (≤200 chars) that triggered the match. Useful for the
    /// agent to verify or correlate with raw response data.
    pub evidence: String,
    /// Source URL when source is `script_src` or `external_script_body`.
    pub script_url: Option<String>,
}

/// Compiled fingerprint DB, parsed + regex-compiled once at first use.
static FINGERPRINTS: Lazy<Vec<CompiledFingerprint>> = Lazy::new(|| {
    let raw: RawDb =
        serde_json::from_str(FINGERPRINTS_JSON).expect("fingerprints.json: parse failed at startup");
    raw.libraries
        .into_iter()
        .map(|f| CompiledFingerprint {
            name: f.name,
            url_patterns: compile_all(&f.url_patterns),
            comment_patterns: compile_all(&f.comment_patterns),
            html_patterns: compile_all(&f.html_patterns),
        })
        .collect()
});

fn compile_all(patterns: &[String]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|p| {
            Regex::new(p).map_err(|e| eprintln!("[jslib] regex compile failed for `{}`: {}", p, e)).ok()
        })
        .collect()
}

/// Return the (lazily compiled) fingerprint database.
pub fn fingerprints() -> &'static [CompiledFingerprint] {
    &FINGERPRINTS
}

/// Detect libraries from a page's HTML. Walks all `<script src="…">` URLs
/// and inline `<script>` bodies. Also runs `html_patterns` against the whole
/// HTML for marker-based detections (Next.js / Nuxt / Drupal / WP / …).
pub fn detect_in_html(html: &str) -> Vec<Detection> {
    let mut out: Vec<Detection> = Vec::new();
    let mut seen: std::collections::HashSet<(String, Option<String>)> = std::collections::HashSet::new();

    // Cheap script-tag scraping. We don't need a full HTML parser; the regex
    // covers attribute-quote variants and is bounded to the tag.
    let script_src_re = Regex::new(r#"(?is)<script[^>]+src=["']([^"']+)["'][^>]*>"#).unwrap();
    let inline_re = Regex::new(r#"(?is)<script(?:\s[^>]*)?>(.*?)</script>"#).unwrap();

    let src_urls: Vec<String> =
        script_src_re.captures_iter(html).filter_map(|c| c.get(1).map(|m| m.as_str().to_string())).collect();

    let inline_bodies: Vec<String> = inline_re
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .filter(|s| !s.trim().is_empty())
        .collect();

    for lib in fingerprints() {
        // 1. Match script src URLs against url_patterns.
        for src in &src_urls {
            for re in &lib.url_patterns {
                if let Some(caps) = re.captures(src) {
                    let version = caps.get(1).map(|m| m.as_str().to_string());
                    let key = (lib.name.clone(), version.clone());
                    if seen.insert(key) {
                        out.push(Detection {
                            library: lib.name.clone(),
                            version,
                            source: "script_src",
                            evidence: src.chars().take(200).collect(),
                            script_url: Some(src.clone()),
                        });
                    }
                }
            }
        }

        // 2. Match inline `<script>` bodies against comment_patterns.
        for body in &inline_bodies {
            for re in &lib.comment_patterns {
                if let Some(caps) = re.captures(body) {
                    let version = caps.get(1).map(|m| m.as_str().to_string());
                    let key = (lib.name.clone(), version.clone());
                    if seen.insert(key) {
                        // Trim the snippet to the matched line so we don't
                        // dump a megabyte of inline JS into the response.
                        let evidence = caps
                            .get(0)
                            .map(|m| m.as_str().to_string())
                            .unwrap_or_default()
                            .chars()
                            .take(200)
                            .collect();
                        out.push(Detection {
                            library: lib.name.clone(),
                            version,
                            source: "inline_script_comment",
                            evidence,
                            script_url: None,
                        });
                    }
                }
            }
        }

        // 3. Marker patterns against the whole HTML (`__NEXT_DATA__`,
        // `Drupal.settings`, `<meta name="generator" content="WordPress …">`).
        for re in &lib.html_patterns {
            if let Some(caps) = re.captures(html) {
                let version = caps.get(1).map(|m| m.as_str().to_string());
                let key = (lib.name.clone(), version.clone());
                if seen.insert(key) {
                    let evidence = caps
                        .get(0)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default()
                        .chars()
                        .take(200)
                        .collect();
                    out.push(Detection {
                        library: lib.name.clone(),
                        version,
                        source: "html_pattern",
                        evidence,
                        script_url: None,
                    });
                }
            }
        }
    }
    out
}

/// Detect libraries from a single JS body (e.g. an external script that the
/// caller has already fetched). Only `comment_patterns` apply — there's no
/// URL or surrounding HTML.
pub fn detect_in_js(js: &str, source_url: Option<&str>) -> Vec<Detection> {
    let mut out: Vec<Detection> = Vec::new();
    let mut seen: std::collections::HashSet<(String, Option<String>)> = std::collections::HashSet::new();

    for lib in fingerprints() {
        // Also try url_patterns against source_url if provided. A library
        // with a versioned filename (jquery-3.4.0.min.js) gets caught here
        // even if its comment header was minified out.
        if let Some(url) = source_url {
            for re in &lib.url_patterns {
                if let Some(caps) = re.captures(url) {
                    let version = caps.get(1).map(|m| m.as_str().to_string());
                    let key = (lib.name.clone(), version.clone());
                    if seen.insert(key) {
                        out.push(Detection {
                            library: lib.name.clone(),
                            version,
                            source: "script_src",
                            evidence: url.chars().take(200).collect(),
                            script_url: Some(url.to_string()),
                        });
                    }
                }
            }
        }

        for re in &lib.comment_patterns {
            if let Some(caps) = re.captures(js) {
                let version = caps.get(1).map(|m| m.as_str().to_string());
                let key = (lib.name.clone(), version.clone());
                if seen.insert(key) {
                    let evidence = caps
                        .get(0)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default()
                        .chars()
                        .take(200)
                        .collect();
                    out.push(Detection {
                        library: lib.name.clone(),
                        version,
                        source: "external_script_body",
                        evidence,
                        script_url: source_url.map(|s| s.to_string()),
                    });
                }
            }
        }
    }
    out
}

/// Extract `<script src="…">` URLs from HTML. Exposed so handlers can
/// optionally follow each external script and scan its body for inline
/// version comments (useful for minified libs whose headers survived).
pub fn extract_script_srcs(html: &str) -> Vec<String> {
    let re = Regex::new(r#"(?is)<script[^>]+src=["']([^"']+)["'][^>]*>"#).unwrap();
    re.captures_iter(html).filter_map(|c| c.get(1).map(|m| m.as_str().to_string())).collect()
}

/// Total number of libraries this module knows how to recognize. Useful for
/// `proxy_get_capabilities` and the AI skill so they don't drift.
pub fn library_count() -> usize {
    fingerprints().len()
}
