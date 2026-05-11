// WonderSuite crawler — modular, security-aware web crawler.
//
// Module layout:
//   task.rs         — CrawlTask + Tier enum
//   queue.rs        — priority queue with dedupe
//   robots.rs       — robots.txt parser (treats Disallow: as high-priority targets)
//   sitemap.rs      — sitemap.xml / sitemap-index / RSS / Atom + .gz support
//   well_known.rs   — Swagger / OpenAPI / GraphQL / JSON-RPC / .well-known paths
//   js_endpoints.rs — fetch/axios/XHR/WebSocket/SSE/literal regex pass
//   meta.rs         — HTML <title>, canonical, hreflang, meta-refresh, OG, CSRF
//   path.rs         — URL canonicalization, IDNA, percent-encoding, redirect-loop tracker
//   soft404.rs      — fingerprint-based soft-404 detection
//   cookies.rs      — cookie jar with security audit
//   spa.rs          — SPA detection heuristics
//   render.rs       — CDP-driven JS-render pass via the bundled WonderBrowser
//   engine.rs       — orchestrator that ties it all together

pub mod cookies;
pub mod engine;
pub mod js_endpoints;
pub mod meta;
pub mod path;
pub mod queue;
pub mod render;
pub mod robots;
pub mod sitemap;
pub mod soft404;
pub mod spa;
pub mod task;
pub mod well_known;

pub use engine::{CrawlReport, Crawler, CrawlerConfig};
pub use task::{CrawlTask, Tier};
