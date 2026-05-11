// Tauri commands exposing the WonderSuite crawler.

use crate::crawler::{CrawlReport, Crawler, CrawlerConfig};
use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct CrawlerOpts {
    pub max_requests: Option<u32>,
    pub max_depth: Option<u32>,
    pub timeout_ms: Option<u64>,
    pub user_agent: Option<String>,
    pub follow_redirects: Option<bool>,
    pub include_cross_host: Option<bool>,
    pub cdp_port: Option<u16>,
    pub probe_well_known: Option<bool>,
    pub probe_robots_and_sitemap: Option<bool>,
}

fn apply(opts: CrawlerOpts) -> CrawlerConfig {
    let d = CrawlerConfig::default();
    CrawlerConfig {
        max_requests: opts.max_requests.unwrap_or(d.max_requests),
        max_depth: opts.max_depth.unwrap_or(d.max_depth),
        timeout_ms: opts.timeout_ms.unwrap_or(d.timeout_ms),
        user_agent: opts.user_agent.unwrap_or(d.user_agent),
        follow_redirects: opts.follow_redirects.unwrap_or(d.follow_redirects),
        include_cross_host: opts.include_cross_host.unwrap_or(d.include_cross_host),
        cdp_port: opts.cdp_port.or(d.cdp_port),
        probe_well_known: opts.probe_well_known.unwrap_or(d.probe_well_known),
        probe_robots_and_sitemap: opts.probe_robots_and_sitemap.unwrap_or(d.probe_robots_and_sitemap),
    }
}

#[tauri::command]
pub async fn crawler_run(target: String, options: Option<CrawlerOpts>) -> Result<CrawlReport, String> {
    let cfg = apply(options.unwrap_or_default());
    let crawler = Crawler::new(cfg)?;
    Ok(crawler.run(&target).await)
}
