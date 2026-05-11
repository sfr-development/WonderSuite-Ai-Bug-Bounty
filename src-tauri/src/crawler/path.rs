// URL canonicalization, percent-encoding normalization, IDNA, redirect-loop
// detection.
//
// Used by the queue to dedupe and to flag security-interesting URLs:
//   - long URLs (>2048 chars) -> finding "URL length / WAF bypass surface"
//   - double-encoded segments  -> finding "path normalization probe"
//   - non-ASCII hostnames      -> normalized via IDNA
//   - paths with `..` / `//`   -> finding "path traversal probe"
//   - redirect chains containing a repeat -> finding "redirect loop"

use serde::Serialize;
use url::Url;

#[derive(Debug, Default, Serialize, Clone)]
pub struct UrlAnalysis {
    pub canonical: String,
    pub host_ascii: String,
    pub host_unicode: String,
    pub is_too_long: bool,
    pub has_double_encoded: bool,
    pub has_traversal_segments: bool,
    pub has_repeated_slashes: bool,
    pub original_length: usize,
}

const URL_TOO_LONG_THRESHOLD: usize = 2048;

/// Build an analysis from a URL string. Returns a default-empty struct on
/// parse failure (the caller can still see is_too_long via fallback length).
pub fn analyze(url: &str) -> UrlAnalysis {
    let mut a = UrlAnalysis {
        original_length: url.len(),
        is_too_long: url.len() > URL_TOO_LONG_THRESHOLD,
        ..Default::default()
    };
    a.has_traversal_segments = has_traversal(url);
    a.has_repeated_slashes = has_repeated_slashes(url);
    a.has_double_encoded = has_double_encoded(url);

    if let Ok(parsed) = Url::parse(url) {
        // Strip fragment; lowercase scheme + host; preserve everything else.
        let mut clean = parsed.clone();
        clean.set_fragment(None);
        a.canonical = clean.to_string();
        if let Some(host) = clean.host_str() {
            a.host_ascii = host.to_ascii_lowercase();
            a.host_unicode = idna_to_unicode(&a.host_ascii);
        }
    } else {
        a.canonical = url.to_string();
    }
    a
}

fn has_traversal(url: &str) -> bool {
    // Catches `..`, `%2e%2e`, `%252e%252e`, `..%2f`, etc.
    let lower = url.to_ascii_lowercase();
    lower.contains("..")
        || lower.contains("%2e%2e")
        || lower.contains("%252e%252e")
        || lower.contains("..%2f")
        || lower.contains("..%5c")
}

fn has_repeated_slashes(url: &str) -> bool {
    // After the scheme://, any "//", "/./", or "/../" is suspicious.
    let after_scheme = url.find("://").map(|i| &url[i + 3..]).unwrap_or(url);
    if let Some(path_start) = after_scheme.find('/') {
        let path = &after_scheme[path_start..];
        return path.contains("//") || path.contains("/./") || path.contains("/../");
    }
    false
}

fn has_double_encoded(url: &str) -> bool {
    // `%25` is the encoding of `%`. So `%252f` decodes to `%2f` which decodes
    // to `/`. Double-encoding is a classic WAF-bypass tell.
    let lower = url.to_ascii_lowercase();
    lower.contains("%25") && (lower.contains("%252e") || lower.contains("%252f") || lower.contains("%2522"))
}

fn idna_to_unicode(ascii_host: &str) -> String {
    if !ascii_host.starts_with("xn--") && !ascii_host.contains(".xn--") {
        return ascii_host.to_string();
    }
    let cfg = idna::Config::default();
    cfg.to_unicode(ascii_host).0
}

/// Redirect-chain tracker. The crawler feeds it every Location header value
/// encountered while following a redirect; `push` returns true if a loop
/// was detected. Capped at 16 hops by default.
pub struct RedirectChain {
    seen: Vec<String>,
    max: usize,
}

impl RedirectChain {
    pub fn new() -> Self {
        Self { seen: Vec::new(), max: 16 }
    }

    pub fn with_max(max: usize) -> Self {
        Self { seen: Vec::new(), max }
    }

    /// Push the next URL in a redirect chain. Returns:
    ///   - Ok(_)           : new hop accepted
    ///   - Err("loop")     : same URL has been seen before
    ///   - Err("too long") : chain exceeded max hops
    pub fn push(&mut self, url: &str) -> Result<(), &'static str> {
        let canonical = analyze(url).canonical;
        if self.seen.iter().any(|u| u == &canonical) {
            return Err("loop");
        }
        if self.seen.len() >= self.max {
            return Err("too long");
        }
        self.seen.push(canonical);
        Ok(())
    }

    pub fn hops(&self) -> &[String] {
        &self.seen
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for RedirectChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_basic() {
        let a = analyze("https://Example.COM/foo#bar");
        assert_eq!(a.host_ascii, "example.com");
        assert!(!a.canonical.contains('#'));
    }

    #[test]
    fn flags_long_url() {
        let s = "https://x/".to_string() + &"a".repeat(3000);
        let a = analyze(&s);
        assert!(a.is_too_long);
    }

    #[test]
    fn flags_traversal() {
        assert!(analyze("https://x/../etc/passwd").has_traversal_segments);
        assert!(analyze("https://x/%2e%2e/secret").has_traversal_segments);
    }

    #[test]
    fn flags_double_encoded() {
        assert!(analyze("https://x/%252e%252e/secret").has_double_encoded);
        assert!(!analyze("https://x/normal").has_double_encoded);
    }

    #[test]
    fn idna_roundtrip() {
        // Punycode bücher.de → xn--bcher-kva.de
        let a = analyze("https://xn--bcher-kva.de/");
        assert_eq!(a.host_unicode, "bücher.de");
    }

    #[test]
    fn detects_redirect_loop() {
        let mut chain = RedirectChain::new();
        assert!(chain.push("https://x/a").is_ok());
        assert!(chain.push("https://x/b").is_ok());
        assert_eq!(chain.push("https://x/a").unwrap_err(), "loop");
    }

    #[test]
    fn detects_overlong_chain() {
        let mut chain = RedirectChain::with_max(3);
        chain.push("https://x/1").unwrap();
        chain.push("https://x/2").unwrap();
        chain.push("https://x/3").unwrap();
        assert_eq!(chain.push("https://x/4").unwrap_err(), "too long");
    }
}
