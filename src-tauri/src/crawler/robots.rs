// robots.txt + sitemap.xml ingestion.
//
// Note: a security crawler treats `Disallow:` as a HINT FOR HIGH-PRIORITY
// TARGETS, not as a constraint. Operators put paths there because they want
// them hidden; that's exactly the surface a pentester wants to look at.
// `Allow:` is recorded but otherwise inert.

use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct RobotsReport {
    /// Paths the site asks crawlers not to index (we crawl them anyway, with priority).
    pub disallowed: Vec<String>,
    /// Paths explicitly allowed (rare, mostly informational).
    pub allowed: Vec<String>,
    /// Sitemap URLs referenced by `Sitemap:` directives.
    pub sitemaps: Vec<String>,
    /// User-Agent groups encountered (the names — useful for fingerprinting policies).
    pub user_agent_groups: Vec<String>,
    /// Crawl-delay directives (rarely useful but we log them).
    pub crawl_delays: Vec<(String, String)>,
    /// True iff a robots.txt body was present (vs 404 / 500 / network error).
    pub present: bool,
}

/// Parse a robots.txt body into a structured report. Follows the de-facto
/// rules from RFC 9309: case-insensitive directive names, comments after `#`,
/// `User-agent:` starts a new group, multi-group support.
pub fn parse_robots(body: &str) -> RobotsReport {
    let mut r = RobotsReport::default();
    if body.trim().is_empty() {
        return r;
    }
    r.present = true;

    let mut current_ua: Vec<String> = Vec::new();
    for raw_line in body.lines() {
        // Strip comments + trim
        let line = match raw_line.find('#') {
            Some(i) => &raw_line[..i],
            None => raw_line,
        }
        .trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = split_directive(line) else { continue };
        let value = value.trim().to_string();
        match key.to_ascii_lowercase().as_str() {
            "user-agent" => {
                if !r.user_agent_groups.contains(&value) {
                    r.user_agent_groups.push(value.clone());
                }
                current_ua = vec![value];
            }
            "disallow" => {
                if !value.is_empty() && !r.disallowed.contains(&value) {
                    r.disallowed.push(value);
                }
            }
            "allow" => {
                if !value.is_empty() && !r.allowed.contains(&value) {
                    r.allowed.push(value);
                }
            }
            "sitemap" => {
                if !value.is_empty() && !r.sitemaps.contains(&value) {
                    r.sitemaps.push(value);
                }
            }
            "crawl-delay" => {
                let ua_label = current_ua.last().cloned().unwrap_or_else(|| "*".into());
                r.crawl_delays.push((ua_label, value));
            }
            _ => {}
        }
    }
    r
}

fn split_directive(line: &str) -> Option<(&str, &str)> {
    let i = line.find(':')?;
    let (k, v) = line.split_at(i);
    Some((k.trim(), v[1..].trim_start()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard() {
        let body = "
            User-agent: *
            Disallow: /admin
            Disallow: /private/
            Allow: /private/public
            # comment line
            Sitemap: https://example.com/sitemap.xml
            Sitemap: https://example.com/sitemap-products.xml

            User-agent: Googlebot
            Crawl-delay: 10
        ";
        let r = parse_robots(body);
        assert!(r.present);
        assert_eq!(r.disallowed, vec!["/admin", "/private/"]);
        assert_eq!(r.allowed, vec!["/private/public"]);
        assert_eq!(r.sitemaps.len(), 2);
        assert_eq!(r.user_agent_groups, vec!["*", "Googlebot"]);
        assert_eq!(r.crawl_delays, vec![("Googlebot".into(), "10".into())]);
    }

    #[test]
    fn empty_body_means_not_present() {
        let r = parse_robots("");
        assert!(!r.present);
    }

    #[test]
    fn handles_comments_and_blanks() {
        let body = "# header\nUser-agent: *\n\nDisallow: /x  # inline\n";
        let r = parse_robots(body);
        assert_eq!(r.disallowed, vec!["/x"]);
    }
}
