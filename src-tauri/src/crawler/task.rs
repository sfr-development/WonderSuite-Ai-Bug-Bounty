use std::cmp::Ordering;

/// Priority tier for a crawl task. Lower value = higher priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tier {
    /// User-entered URL, sitemap entries, OpenAPI/Swagger spec endpoints.
    Explicit = 0,
    /// Paths listed as `Disallow:` in robots.txt — security-interesting by definition.
    RobotsDisallowed = 1,
    /// Pages with forms or query parameters (high injection-point density).
    FormsAndParams = 2,
    /// Well-known paths like `/admin`, `/login`, `/api`, `/.well-known/*`.
    WellKnown = 3,
    /// Normal same-host BFS traversal.
    Bfs = 4,
    /// Endpoints discovered from JS source / runtime hooks.
    JsDiscovered = 5,
    /// Cross-host hosts — recorded for the sitemap, not crawled by default.
    CrossHost = 6,
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::Explicit => "explicit",
            Tier::RobotsDisallowed => "robots-disallowed",
            Tier::FormsAndParams => "forms-and-params",
            Tier::WellKnown => "well-known",
            Tier::Bfs => "bfs",
            Tier::JsDiscovered => "js-discovered",
            Tier::CrossHost => "cross-host",
        }
    }
}

/// One unit of work for the crawler. Carries the URL, the tier it entered
/// the queue at, and the BFS depth (used as the secondary sort key so we
/// don't infinitely deep-dive one branch).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CrawlTask {
    pub url: String,
    pub tier: Tier,
    pub depth: u32,
    /// Optional reason string surfaced into the request log / sitemap UI.
    pub reason: Option<String>,
    /// Method to issue (default GET). POST tasks come from forms.
    pub method: String,
    /// Body for POST/PUT/PATCH.
    pub body: Option<String>,
    /// Content-Type for the body, if any.
    pub content_type: Option<String>,
}

impl CrawlTask {
    pub fn get(url: impl Into<String>, tier: Tier, depth: u32) -> Self {
        Self {
            url: url.into(),
            tier,
            depth,
            reason: None,
            method: "GET".into(),
            body: None,
            content_type: None,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

// BinaryHeap is a max-heap, so we reverse the natural ordering to make it
// pop the LOWEST tier first (= highest priority). Within tier, shallower
// depth wins so BFS doesn't run away on a single branch.
impl Ord for CrawlTask {
    fn cmp(&self, other: &Self) -> Ordering {
        (other.tier as u8).cmp(&(self.tier as u8)).then(other.depth.cmp(&self.depth))
    }
}

impl PartialOrd for CrawlTask {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BinaryHeap;

    #[test]
    fn explicit_pops_before_bfs() {
        let mut h = BinaryHeap::new();
        h.push(CrawlTask::get("a", Tier::Bfs, 0));
        h.push(CrawlTask::get("b", Tier::Explicit, 0));
        h.push(CrawlTask::get("c", Tier::JsDiscovered, 0));
        let order: Vec<_> = std::iter::from_fn(|| h.pop()).map(|t| t.tier).collect();
        assert_eq!(order, vec![Tier::Explicit, Tier::Bfs, Tier::JsDiscovered]);
    }

    #[test]
    fn shallow_depth_first_within_tier() {
        let mut h = BinaryHeap::new();
        h.push(CrawlTask::get("a", Tier::Bfs, 5));
        h.push(CrawlTask::get("b", Tier::Bfs, 1));
        h.push(CrawlTask::get("c", Tier::Bfs, 3));
        let urls: Vec<_> = std::iter::from_fn(|| h.pop()).map(|t| t.url).collect();
        assert_eq!(urls, vec!["b", "c", "a"]);
    }
}
