// Crawler coverage regression test.
//
// Loads the offline fixture (tests/fixtures/crawler_test_html.html) — which
// is a single HTML page containing every detection category our crawler is
// supposed to extract — and asserts each extractor produces the expected
// signal. Catches regressions in any single category without needing network.
//
// The full network-based crawler-test.com run lives in
// `scripts/run-crawler-test-com.mjs` and is not part of `cargo test`.

use wondersuite_lib::crawler::js_endpoints::extract_endpoints;
use wondersuite_lib::crawler::meta::extract_meta;
use wondersuite_lib::crawler::path::analyze;
use wondersuite_lib::crawler::robots::parse_robots;
use wondersuite_lib::crawler::sitemap::parse_sitemap;
use wondersuite_lib::crawler::soft404::Soft404Fingerprint;
use wondersuite_lib::crawler::spa::detect_spa;

const FIXTURE: &str = include_str!("fixtures/crawler_test_html.html");

#[test]
fn meta_extractor_pulls_every_field() {
    let m = extract_meta(FIXTURE);
    assert_eq!(m.title.as_deref(), Some("WonderSuite crawler-test offline fixture"));
    assert!(m.description.is_some());
    assert_eq!(m.generator.as_deref(), Some("WonderSuite Fixtures 0.2.0"));
    assert_eq!(m.canonical.as_deref(), Some("https://crawler-test.com/canonical-target"));
    assert_eq!(m.csrf_token_meta.as_deref(), Some("ABC123XYZ"));
    assert_eq!(m.robots_meta.as_deref(), Some("noindex, nofollow"));
    assert!(m.csp_meta.is_some());
    assert_eq!(m.meta_refresh_target.as_deref(), Some("/redirected"));
    assert_eq!(m.meta_refresh_seconds, Some(3));
    assert!(m.hreflang.len() >= 2);
    assert!(m.open_graph.iter().any(|(k, _)| k == "og:title"));
    assert!(m.twitter_card.iter().any(|(k, _)| k == "twitter:card"));
    assert!(m.favicon.is_some());
}

#[test]
fn spa_detector_flags_next_app() {
    let r = detect_spa(FIXTURE);
    assert!(r.is_spa, "expected SPA detection on the fixture: triggers = {:?}", r.triggers);
    assert!(r.triggers.iter().any(|t| t.contains("Next") || t.contains("React")));
}

#[test]
fn robots_parser_handles_security_disallows() {
    let robots = "
        User-agent: *
        Disallow: /admin
        Disallow: /api/internal
        Allow: /api/public
        Sitemap: https://crawler-test.com/sitemap.xml
    ";
    let r = parse_robots(robots);
    assert!(r.present);
    assert_eq!(r.disallowed.len(), 2);
    assert_eq!(r.sitemaps.len(), 1);
}

#[test]
fn sitemap_parser_handles_urlset() {
    let sm = r#"<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url><loc>https://crawler-test.com/a</loc><lastmod>2025-01-01</lastmod></url>
        <url><loc>https://crawler-test.com/b</loc></url>
    </urlset>"#;
    let r = parse_sitemap(sm);
    assert_eq!(r.variant, "urlset");
    assert_eq!(r.urls.len(), 2);
}

#[test]
fn js_endpoint_extractor_handles_modern_bundle() {
    let js = r#"
        fetch("/api/users", { method: "POST" });
        axios.get("/v2/orders").then();
        const ws = new WebSocket("wss://chat.example.com/ws");
        const xhr = new XMLHttpRequest(); xhr.open("DELETE", "/api/x/1");
        const URL = "/api/v1/secret";
    "#;
    let eps = extract_endpoints(js);
    assert!(eps.iter().any(|e| e.url == "/api/users" && e.method == "POST"));
    assert!(eps.iter().any(|e| e.url == "/v2/orders"));
    assert!(eps.iter().any(|e| e.url.contains("wss://") && e.source == "websocket"));
    assert!(eps.iter().any(|e| e.url == "/api/x/1" && e.method == "DELETE"));
    assert!(eps.iter().any(|e| e.url == "/api/v1/secret"));
}

#[test]
fn path_analyzer_flags_traversal_and_long() {
    let a = analyze("https://x/../etc/passwd");
    assert!(a.has_traversal_segments);

    let long = "https://x/".to_string() + &"a".repeat(3000);
    assert!(analyze(&long).is_too_long);

    let dbl = analyze("https://x/%252e%252e/secret");
    assert!(dbl.has_double_encoded);
}

#[test]
fn soft404_distinguishes_real_and_phantom() {
    let real_404 = Soft404Fingerprint::from_response(404, "Hard 404 response");
    let phantom = Soft404Fingerprint::from_response(200, "Sorry, this page does not exist. Not found.");
    assert!(phantom.looks_like_soft_404());
    assert!(!real_404.looks_like_soft_404());
}
