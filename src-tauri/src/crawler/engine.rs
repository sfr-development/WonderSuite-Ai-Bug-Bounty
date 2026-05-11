// Crawler engine — orchestrates queue, fetch, parsing, JS-render decision,
// and finding emission for a single host. Used by scanner_commands.rs and
// stand-alone via the `crawler_run` Tauri command.

use super::cookies::CookieJar;
use super::js_endpoints::extract_endpoints;
use super::meta::{extract_meta, MetaReport};
use super::path::{analyze, RedirectChain, UrlAnalysis};
use super::queue::CrawlQueue;
use super::robots::{parse_robots, RobotsReport};
use super::sitemap::{decompress_gzip, parse_sitemap, SitemapReport};
use super::soft404::Soft404Fingerprint;
use super::spa::{detect_spa, SpaReport};
use super::task::{CrawlTask, Tier};
use super::well_known::well_known_paths;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
pub struct CrawlerConfig {
    pub max_requests: u32,
    pub max_depth: u32,
    pub timeout_ms: u64,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub include_cross_host: bool,
    /// CDP port for the JS-render pass. None disables SPA rendering.
    pub cdp_port: Option<u16>,
    /// True ↦ also seed well-known paths.
    pub probe_well_known: bool,
    /// True ↦ also fetch + parse robots.txt and sitemap.xml.
    pub probe_robots_and_sitemap: bool,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            max_requests: 500,
            max_depth: 3,
            timeout_ms: 10_000,
            user_agent:
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 WonderSuite-Crawler/0.2"
                    .into(),
            follow_redirects: true,
            include_cross_host: false,
            cdp_port: None,
            probe_well_known: true,
            probe_robots_and_sitemap: true,
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct CrawlReport {
    pub target: String,
    pub host: String,
    pub robots: Option<RobotsReport>,
    pub sitemaps: Vec<SitemapReport>,
    pub soft_404: Option<Soft404Fingerprint>,
    pub pages_visited: Vec<PageReport>,
    pub all_endpoints: Vec<super::js_endpoints::JsEndpoint>,
    pub cookies: Vec<super::cookies::Cookie>,
    pub cookie_audit: Vec<(String, String)>,
    pub findings: Vec<CrawlFinding>,
    pub stats: CrawlStats,
}

#[derive(Debug, Default, Serialize)]
pub struct CrawlStats {
    pub requests_issued: u32,
    pub soft_404_skipped: u32,
    pub spa_renders: u32,
    pub well_known_hits: u32,
    pub redirect_loops: u32,
    pub well_known_seeded: u32,
    pub robots_disallowed_seeded: u32,
}

#[derive(Debug, Serialize)]
pub struct PageReport {
    pub url: String,
    pub final_url: String,
    pub status: u16,
    pub mime: String,
    pub length: usize,
    pub elapsed_ms: u64,
    pub tier: &'static str,
    pub spa: Option<SpaReport>,
    pub meta: Option<MetaReport>,
    pub soft_404: bool,
    pub anomalies: Vec<UrlAnomaly>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UrlAnomaly {
    pub kind: &'static str,
    pub detail: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct CrawlFinding {
    pub severity: &'static str,
    pub kind: &'static str,
    pub url: String,
    pub detail: String,
}

pub struct Crawler {
    cfg: CrawlerConfig,
    client: reqwest::Client,
    jar: Arc<CookieJar>,
}

impl Crawler {
    pub fn new(cfg: CrawlerConfig) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .redirect(if cfg.follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .user_agent(&cfg.user_agent)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { cfg, client, jar: Arc::new(CookieJar::new()) })
    }

    pub fn cookie_jar(&self) -> Arc<CookieJar> {
        self.jar.clone()
    }

    pub async fn run(&self, target: &str) -> CrawlReport {
        let mut report = CrawlReport::default();
        report.target = target.to_string();
        let base = match Url::parse(target) {
            Ok(u) => u,
            Err(e) => {
                report.findings.push(CrawlFinding {
                    severity: "info",
                    kind: "invalid-target",
                    url: target.into(),
                    detail: format!("could not parse target URL: {}", e),
                });
                return report;
            }
        };
        let host = base.host_str().unwrap_or("").to_string();
        report.host = host.clone();

        let mut queue = CrawlQueue::new();
        queue.enqueue_force(CrawlTask::get(target.to_string(), Tier::Explicit, 0));

        // 1. robots.txt + sitemap
        if self.cfg.probe_robots_and_sitemap {
            let robots = self.fetch_robots(&base).await;
            if let Some(r) = robots {
                for sm in &r.sitemaps {
                    let smr = self.fetch_sitemap(sm).await;
                    for url in smr.urls.iter().map(|u| u.loc.clone()) {
                        queue.enqueue(CrawlTask::get(url, Tier::Explicit, 1));
                    }
                    for sub in smr.sub_sitemaps.iter().cloned() {
                        // depth-1 sitemap recursion
                        let sub_r = self.fetch_sitemap(&sub).await;
                        for u in sub_r.urls.iter().map(|u| u.loc.clone()) {
                            queue.enqueue(CrawlTask::get(u, Tier::Explicit, 2));
                        }
                        report.sitemaps.push(sub_r);
                    }
                    report.sitemaps.push(smr);
                }
                for path in &r.disallowed {
                    if let Ok(joined) = base.join(path) {
                        if queue.enqueue(
                            CrawlTask::get(joined.to_string(), Tier::RobotsDisallowed, 0)
                                .with_reason("robots.txt Disallow:"),
                        ) {
                            report.stats.robots_disallowed_seeded += 1;
                        }
                    }
                }
                report.robots = Some(r);
            }
        }

        // 2. Well-known paths
        if self.cfg.probe_well_known {
            for p in well_known_paths() {
                if let Ok(joined) = base.join(p) {
                    if queue.enqueue(
                        CrawlTask::get(joined.to_string(), Tier::WellKnown, 0).with_reason("well-known path"),
                    ) {
                        report.stats.well_known_seeded += 1;
                    }
                }
            }
        }

        // 3. Soft-404 baseline
        let bogus_url =
            base.join(&super::soft404::random_bogus_path()).map(|u| u.to_string()).unwrap_or_default();
        if !bogus_url.is_empty() {
            if let Some((status, body, _hdrs, _mime, _final, _elapsed)) =
                self.fetch_text(&bogus_url, "GET", None).await
            {
                let fp = Soft404Fingerprint::from_response(status, &body);
                if fp.status == 200 && fp.canonical_phrases >= 2 {
                    report.soft_404 = Some(fp);
                }
                report.stats.requests_issued += 1;
            }
        }

        // 4. Drain the queue
        while let Some(task) = queue.pop() {
            if report.stats.requests_issued >= self.cfg.max_requests {
                break;
            }
            if task.depth > self.cfg.max_depth {
                continue;
            }
            self.visit(&task, &base, &host, &mut queue, &mut report).await;
            report.stats.requests_issued += 1;
        }

        report.cookies = self.jar.snapshot();
        report.cookie_audit = self.jar.audit().into_iter().map(|(n, f)| (n, f.to_string())).collect();
        report
    }

    async fn fetch_robots(&self, base: &Url) -> Option<RobotsReport> {
        let robots_url = base.join("/robots.txt").ok()?.to_string();
        let (status, body, _, _, _, _) = self.fetch_text(&robots_url, "GET", None).await?;
        if status != 200 || body.is_empty() {
            return None;
        }
        Some(parse_robots(&body))
    }

    async fn fetch_sitemap(&self, url: &str) -> SitemapReport {
        let lower = url.to_ascii_lowercase();
        if lower.ends_with(".gz") {
            if let Ok(resp) = self.client.get(url).send().await {
                if let Ok(bytes) = resp.bytes().await {
                    if let Ok(body) = decompress_gzip(&bytes) {
                        return parse_sitemap(&body);
                    }
                }
            }
            return SitemapReport::default();
        }
        let (_status, body, _h, _m, _f, _e) = self.fetch_text(url, "GET", None).await.unwrap_or((
            0,
            String::new(),
            String::new(),
            String::new(),
            url.to_string(),
            0,
        ));
        parse_sitemap(&body)
    }

    /// Fetch with cookie jar + redirect chain. Returns (status, body, headers, mime, final_url, elapsed_ms).
    async fn fetch_text(
        &self,
        url: &str,
        method: &str,
        body: Option<String>,
    ) -> Option<(u16, String, String, String, String, u64)> {
        let started = std::time::Instant::now();
        let parsed = Url::parse(url).ok()?;
        let host = parsed.host_str()?.to_string();
        let scheme = parsed.scheme().to_string();
        let cookie_hdr = self.jar.header_for(&host, parsed.path(), &scheme);

        let mut req = self.client.request(method.parse().unwrap_or(reqwest::Method::GET), url);
        if let Some(c) = cookie_hdr {
            req = req.header("Cookie", c);
        }
        if let Some(b) = body {
            req = req.body(b);
        }

        let resp = req.send().await.ok()?;
        let status = resp.status().as_u16();
        let final_url = resp.url().to_string();

        // Absorb Set-Cookie headers
        for v in resp.headers().get_all("set-cookie").iter() {
            if let Ok(s) = v.to_str() {
                self.jar.absorb(&host, s);
            }
        }

        let mime = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let hdr_string = resp
            .headers()
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\r\n");

        let body_str = match resp.text().await {
            Ok(b) => b,
            Err(_) => String::new(),
        };
        let elapsed = started.elapsed().as_millis() as u64;
        Some((status, body_str, hdr_string, mime, final_url, elapsed))
    }

    async fn visit(
        &self,
        task: &CrawlTask,
        base: &Url,
        host: &str,
        queue: &mut CrawlQueue,
        report: &mut CrawlReport,
    ) {
        let Some((status, body, _hdrs, mime, final_url, elapsed)) =
            self.fetch_text(&task.url, &task.method, task.body.clone()).await
        else {
            return;
        };
        let analysis = analyze(&task.url);
        let mut anomalies: Vec<UrlAnomaly> = Vec::new();
        if analysis.is_too_long {
            anomalies
                .push(UrlAnomaly { kind: "long-url", detail: format!("{} chars", analysis.original_length) });
        }
        if analysis.has_traversal_segments {
            anomalies.push(UrlAnomaly {
                kind: "traversal-segments",
                detail: "URL contains `..` or %2e%2e".into(),
            });
        }
        if analysis.has_double_encoded {
            anomalies.push(UrlAnomaly {
                kind: "double-encoded",
                detail: "URL contains double-percent-encoding".into(),
            });
        }
        if analysis.has_repeated_slashes {
            anomalies.push(UrlAnomaly {
                kind: "repeated-slashes",
                detail: "URL contains `//`, `/./`, or `/../`".into(),
            });
        }

        // Soft-404 check
        let mut soft_404 = false;
        if status == 200 {
            if let Some(fp_base) = &report.soft_404 {
                let fp_here = Soft404Fingerprint::from_response(status, &body);
                if fp_base.matches(&fp_here) {
                    soft_404 = true;
                    report.stats.soft_404_skipped += 1;
                }
            }
        }

        let mut meta: Option<MetaReport> = None;
        let mut spa: Option<SpaReport> = None;
        let is_html = mime.contains("text/html");
        if is_html && !soft_404 {
            let m = extract_meta(&body);
            // Cookie security audit for any cookie we just stored (already in jar)
            if let Some(canon) = &m.canonical {
                if !canon.is_empty() && !canon.starts_with("http") {
                    // canonical relative — resolve later
                }
            }
            // meta-refresh as a redirect signal
            if let Some(target) = &m.meta_refresh_target {
                if let Ok(joined) = Url::parse(&task.url).and_then(|u| u.join(target)) {
                    queue.enqueue(CrawlTask::get(joined.to_string(), Tier::Bfs, task.depth + 1));
                }
            }
            meta = Some(m);

            let sr = detect_spa(&body);
            if sr.is_spa && self.cfg.cdp_port.is_some() {
                // Trigger CDP render pass
                if let Some(port) = self.cfg.cdp_port {
                    let r = super::render::render_via_cdp(port, &task.url, Duration::from_secs(15)).await;
                    report.stats.spa_renders += 1;
                    for href in r.anchors.iter().chain(r.form_actions.iter()) {
                        if let Ok(u) = Url::parse(href) {
                            if same_host(host, &u) || self.cfg.include_cross_host {
                                queue.enqueue(CrawlTask::get(
                                    u.to_string(),
                                    if same_host(host, &u) { Tier::Bfs } else { Tier::CrossHost },
                                    task.depth + 1,
                                ));
                            }
                        }
                    }
                    for route in &r.spa_routes {
                        if let Ok(joined) = Url::parse(&task.url).and_then(|u| u.join(route)) {
                            queue.enqueue(CrawlTask::get(
                                joined.to_string(),
                                Tier::JsDiscovered,
                                task.depth + 1,
                            ));
                        }
                    }
                    for ep in &r.runtime_endpoints {
                        if let Ok(joined) = Url::parse(&task.url).and_then(|u| u.join(&ep.url)) {
                            let mut t =
                                CrawlTask::get(joined.to_string(), Tier::JsDiscovered, task.depth + 1);
                            t.method = ep.method.clone();
                            queue.enqueue(t);
                        }
                    }
                }
            }
            spa = Some(sr);
        }

        // Static link extraction for ANY HTML page (even SPAs)
        if is_html && !soft_404 {
            let link_re = regex::Regex::new(r#"(?is)(?:href|src|action)\s*=\s*["']([^"'#]+)["']"#).unwrap();
            for c in link_re.captures_iter(&body) {
                let Some(href) = c.get(1) else { continue };
                let href = href.as_str();
                if href.is_empty()
                    || href.starts_with("javascript:")
                    || href.starts_with("mailto:")
                    || href.starts_with("data:")
                {
                    continue;
                }
                let parsed = Url::parse(&task.url).and_then(|u| u.join(href));
                let Ok(u) = parsed else { continue };
                let same = same_host(host, &u);
                if !same && !self.cfg.include_cross_host {
                    continue;
                }
                let tier = if same { Tier::Bfs } else { Tier::CrossHost };
                queue.enqueue(CrawlTask::get(u.to_string(), tier, task.depth + 1));
            }
        }

        // JS endpoint extraction for JS bodies
        if mime.contains("javascript")
            || mime.contains("text/javascript")
            || mime.contains("application/javascript")
        {
            let eps = extract_endpoints(&body);
            for ep in &eps {
                if let Ok(joined) = Url::parse(&task.url).and_then(|u| u.join(&ep.url)) {
                    if same_host(host, &joined) || self.cfg.include_cross_host {
                        let mut t = CrawlTask::get(joined.to_string(), Tier::JsDiscovered, task.depth + 1);
                        t.method = ep.method.clone();
                        queue.enqueue(t);
                    }
                }
            }
            report.all_endpoints.extend(eps);
        }

        // Per-page finding emission
        for a in &anomalies {
            report.findings.push(CrawlFinding {
                severity: "info",
                kind: a.kind,
                url: task.url.clone(),
                detail: a.detail.clone(),
            });
        }

        report.pages_visited.push(PageReport {
            url: task.url.clone(),
            final_url,
            status,
            mime,
            length: body.len(),
            elapsed_ms: elapsed,
            tier: task.tier.label(),
            spa,
            meta,
            soft_404,
            anomalies,
        });

        // Track redirect-loop-style anomalies via task vs final_url
        if let Some(p) = report.pages_visited.last() {
            if p.url != p.final_url {
                let mut chain = RedirectChain::new();
                let _ = chain.push(&p.url);
                if let Err(e) = chain.push(&p.final_url) {
                    if e == "loop" {
                        report.stats.redirect_loops += 1;
                        report.findings.push(CrawlFinding {
                            severity: "low",
                            kind: "redirect-loop",
                            url: p.url.clone(),
                            detail: "Final URL repeats an earlier hop".into(),
                        });
                    }
                }
            }
        }

        if task.tier == Tier::WellKnown && (200..400).contains(&status) {
            report.stats.well_known_hits += 1;
            report.findings.push(CrawlFinding {
                severity: "info",
                kind: "well-known-hit",
                url: task.url.clone(),
                detail: format!("well-known path responded {}", status),
            });
        }
    }
}

fn same_host(host: &str, u: &Url) -> bool {
    u.host_str().map(|h| h.eq_ignore_ascii_case(host)).unwrap_or(false)
}
