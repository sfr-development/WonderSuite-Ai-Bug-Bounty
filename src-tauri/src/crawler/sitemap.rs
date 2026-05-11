// Sitemap.xml / sitemap-index.xml ingestion.
//
// Handles:
// - urlset (a list of <url><loc> entries)
// - sitemapindex (a list of <sitemap><loc> pointing to sub-sitemaps)
// - gzipped sitemaps (.xml.gz)
// - Returns flat lists of URLs; recursive sitemap-index fetching is the caller's job.

use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct SitemapReport {
    /// Direct URL entries from a `<urlset>` document.
    pub urls: Vec<SitemapUrl>,
    /// Child sitemap URLs from a `<sitemapindex>` document.
    pub sub_sitemaps: Vec<String>,
    /// Best-effort detected sitemap variant ("urlset", "sitemapindex", "rss", "atom").
    pub variant: String,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct SitemapUrl {
    pub loc: String,
    pub lastmod: Option<String>,
    pub changefreq: Option<String>,
    pub priority: Option<String>,
}

/// Parse a sitemap XML body. Tolerant to namespacing and minor malformation.
pub fn parse_sitemap(body: &str) -> SitemapReport {
    let mut r = SitemapReport::default();
    if body.trim().is_empty() {
        return r;
    }

    // Cheap detection: which root element wins?
    let lower = body.to_ascii_lowercase();
    if lower.contains("<sitemapindex") {
        r.variant = "sitemapindex".into();
        r.sub_sitemaps = extract_loc(body);
    } else if lower.contains("<urlset") {
        r.variant = "urlset".into();
        r.urls = extract_urls(body);
    } else if lower.contains("<rss") {
        r.variant = "rss".into();
        // RSS feeds: <link>...</link> entries hold URLs.
        r.urls = extract_simple_links(body, "link");
    } else if lower.contains("<feed") && lower.contains("xmlns=\"http://www.w3.org/2005/atom") {
        r.variant = "atom".into();
        r.urls = extract_atom_links(body);
    } else {
        // Fallback: try `<loc>` anyway.
        let locs = extract_loc(body);
        if !locs.is_empty() {
            r.variant = "urlset".into();
            r.urls = locs.into_iter().map(|l| SitemapUrl { loc: l, ..Default::default() }).collect();
        }
    }
    r
}

fn extract_loc(body: &str) -> Vec<String> {
    let re = regex::Regex::new(r#"(?is)<loc[^>]*>\s*([^<]+?)\s*</loc>"#).unwrap();
    re.captures_iter(body)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
        .filter(|u| !u.is_empty())
        .collect()
}

fn extract_urls(body: &str) -> Vec<SitemapUrl> {
    // Pull each <url>...</url> block, then inner tags.
    let url_re = regex::Regex::new(r#"(?is)<url[^>]*>(.*?)</url>"#).unwrap();
    let inner = |body: &str, tag: &str| -> Option<String> {
        let pat = format!(r#"(?is)<{}[^>]*>\s*([^<]+?)\s*</{}>"#, tag, tag);
        let re = regex::Regex::new(&pat).ok()?;
        re.captures(body).and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
    };
    url_re
        .captures_iter(body)
        .filter_map(|c| {
            let block = c.get(1)?.as_str();
            let loc = inner(block, "loc")?;
            if loc.is_empty() {
                return None;
            }
            Some(SitemapUrl {
                loc,
                lastmod: inner(block, "lastmod"),
                changefreq: inner(block, "changefreq"),
                priority: inner(block, "priority"),
            })
        })
        .collect()
}

fn extract_simple_links(body: &str, tag: &str) -> Vec<SitemapUrl> {
    let pat = format!(r#"(?is)<{}[^>]*>\s*([^<]+?)\s*</{}>"#, tag, tag);
    let re = match regex::Regex::new(&pat) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    re.captures_iter(body)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
        .filter(|u| !u.is_empty() && (u.starts_with("http://") || u.starts_with("https://")))
        .map(|loc| SitemapUrl { loc, ..Default::default() })
        .collect()
}

fn extract_atom_links(body: &str) -> Vec<SitemapUrl> {
    // <link href="..." rel="alternate" />
    let re = regex::Regex::new(r#"(?is)<link\s+[^>]*href=["']([^"']+)["']"#).unwrap();
    re.captures_iter(body)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
        .map(|loc| SitemapUrl { loc, ..Default::default() })
        .collect()
}

/// Decompress a gzipped sitemap body.
pub fn decompress_gzip(input: &[u8]) -> Result<String, String> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut dec = GzDecoder::new(input);
    let mut out = String::new();
    dec.read_to_string(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urlset() {
        let body = r#"<?xml version="1.0"?>
            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url>
                    <loc>https://example.com/a</loc>
                    <lastmod>2025-01-01</lastmod>
                    <priority>0.8</priority>
                </url>
                <url><loc>https://example.com/b</loc></url>
            </urlset>"#;
        let r = parse_sitemap(body);
        assert_eq!(r.variant, "urlset");
        assert_eq!(r.urls.len(), 2);
        assert_eq!(r.urls[0].loc, "https://example.com/a");
        assert_eq!(r.urls[0].lastmod, Some("2025-01-01".into()));
        assert_eq!(r.urls[1].loc, "https://example.com/b");
    }

    #[test]
    fn parses_sitemapindex() {
        let body = r#"<?xml version="1.0"?>
            <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <sitemap><loc>https://example.com/sitemap-1.xml</loc></sitemap>
                <sitemap><loc>https://example.com/sitemap-2.xml</loc></sitemap>
            </sitemapindex>"#;
        let r = parse_sitemap(body);
        assert_eq!(r.variant, "sitemapindex");
        assert_eq!(r.sub_sitemaps.len(), 2);
    }

    #[test]
    fn parses_rss() {
        let body = r#"<rss><channel>
            <item><link>https://example.com/post-1</link></item>
            <item><link>https://example.com/post-2</link></item>
        </channel></rss>"#;
        let r = parse_sitemap(body);
        assert_eq!(r.variant, "rss");
        assert_eq!(r.urls.len(), 2);
    }
}
