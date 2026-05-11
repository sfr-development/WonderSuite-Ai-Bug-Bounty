// Cookie jar for the crawler.
//
// reqwest::Client supports a cookie_store, but its API is hidden and we want
// our own visibility into what's set, what's been forwarded, and which
// security flags are missing per-cookie (for findings).
//
// Behavior:
//   - parse_set_cookie() takes a Set-Cookie header value, returns Cookie
//   - jar.absorb(host, set_cookie_header) reads + stores
//   - jar.header_for(host, path, scheme) returns the Cookie: header value to send
//   - jar.audit() returns a list of insecurity findings ("cookie X missing Secure", etc.)

use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>, // "Strict" | "Lax" | "None"
    pub expires: Option<String>,   // raw expires string
    pub max_age: Option<i64>,
}

impl Cookie {
    pub fn audit_findings(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.secure {
            out.push("Cookie missing Secure flag");
        }
        if !self.http_only {
            out.push("Cookie missing HttpOnly flag");
        }
        match self.same_site.as_deref() {
            None => out.push("Cookie missing SameSite attribute"),
            Some("None") if !self.secure => {
                out.push("Cookie SameSite=None without Secure (rejected by modern browsers)")
            }
            _ => {}
        }
        out
    }
}

#[derive(Default)]
pub struct CookieJar {
    /// Cookies indexed by (domain, path, name).
    inner: Mutex<HashMap<(String, String, String), Cookie>>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse + store every Set-Cookie header value. `set_cookie` can be a
    /// multi-line string (one cookie per line) — reqwest concatenates with
    /// `, ` which is ambiguous, so prefer feeding one header at a time.
    pub fn absorb(&self, request_host: &str, set_cookie: &str) -> Vec<Cookie> {
        let cookies = parse_set_cookies(set_cookie, request_host);
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        for c in &cookies {
            let key = (c.domain.clone(), c.path.clone(), c.name.clone());
            guard.insert(key, c.clone());
        }
        cookies
    }

    /// Build the `Cookie:` header value for a request. Matches by domain
    /// suffix, path prefix and secure-flag-vs-scheme.
    pub fn header_for(&self, host: &str, path: &str, scheme: &str) -> Option<String> {
        let guard = self.inner.lock().ok()?;
        let mut matches: Vec<&Cookie> = guard
            .values()
            .filter(|c| host_matches(&c.domain, host))
            .filter(|c| path_matches(&c.path, path))
            .filter(|c| !c.secure || scheme == "https")
            .collect();
        matches.sort_by(|a, b| b.path.len().cmp(&a.path.len())); // more-specific path first
        if matches.is_empty() {
            return None;
        }
        Some(matches.iter().map(|c| format!("{}={}", c.name, c.value)).collect::<Vec<_>>().join("; "))
    }

    pub fn snapshot(&self) -> Vec<Cookie> {
        self.inner.lock().map(|g| g.values().cloned().collect()).unwrap_or_default()
    }

    pub fn clear(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.clear();
        }
    }

    pub fn audit(&self) -> Vec<(String, &'static str)> {
        let mut out = Vec::new();
        if let Ok(g) = self.inner.lock() {
            for c in g.values() {
                for f in c.audit_findings() {
                    out.push((c.name.clone(), f));
                }
            }
        }
        out
    }
}

fn host_matches(domain: &str, host: &str) -> bool {
    let d = domain.trim_start_matches('.').to_ascii_lowercase();
    let h = host.to_ascii_lowercase();
    h == d || h.ends_with(&format!(".{}", d))
}

fn path_matches(cookie_path: &str, req_path: &str) -> bool {
    if cookie_path.is_empty() || cookie_path == "/" {
        return true;
    }
    req_path.starts_with(cookie_path)
}

/// Parse a single or many `Set-Cookie` header values. reqwest exposes them
/// as separate header iterations; this helper accepts a single value.
pub fn parse_set_cookies(input: &str, request_host: &str) -> Vec<Cookie> {
    // The `, ` separator is ambiguous because expires dates contain commas.
    // Heuristic: split only when ", " is followed by an `=` within ~32 chars.
    let chunks = split_safely(input);
    chunks.into_iter().filter_map(|c| parse_set_cookie(&c, request_host)).collect()
}

fn split_safely(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ',' {
            // Look ahead: is the next non-space char part of a cookie name (alnum + `=` within window)?
            let peek: String = chars.clone().take(48).collect();
            if peek
                .trim_start()
                .chars()
                .take_while(|&ch| ch != '=' && ch != ';' && ch != ',')
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == ' ' || ch == '.')
                && peek.contains('=')
            {
                out.push(buf.clone());
                buf.clear();
                continue;
            }
        }
        buf.push(c);
    }
    if !buf.trim().is_empty() {
        out.push(buf);
    }
    out
}

pub fn parse_set_cookie(input: &str, request_host: &str) -> Option<Cookie> {
    let mut parts = input.split(';').map(|s| s.trim());
    let first = parts.next()?;
    let (name, value) = first.split_once('=')?;
    let name = name.trim().to_string();
    let value = value.trim().to_string();
    if name.is_empty() {
        return None;
    }

    let mut cookie = Cookie {
        name,
        value,
        domain: request_host.to_string(),
        path: "/".into(),
        secure: false,
        http_only: false,
        same_site: None,
        expires: None,
        max_age: None,
    };

    for attr in parts {
        let lower = attr.to_ascii_lowercase();
        if lower == "secure" {
            cookie.secure = true;
        } else if lower == "httponly" {
            cookie.http_only = true;
        } else if let Some((k, v)) = attr.split_once('=') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim().to_string();
            match k.as_str() {
                "domain" => cookie.domain = v.trim_start_matches('.').to_string(),
                "path" => cookie.path = v,
                "samesite" => cookie.same_site = Some(v),
                "expires" => cookie.expires = Some(v),
                "max-age" => cookie.max_age = v.parse().ok(),
                _ => {}
            }
        }
    }
    Some(cookie)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_set_cookie() {
        let c =
            parse_set_cookie("session=abc; Path=/; Secure; HttpOnly; SameSite=Lax", "example.com").unwrap();
        assert_eq!(c.name, "session");
        assert_eq!(c.value, "abc");
        assert!(c.secure);
        assert!(c.http_only);
        assert_eq!(c.same_site.as_deref(), Some("Lax"));
    }

    #[test]
    fn audit_finds_missing_flags() {
        let c = parse_set_cookie("token=xyz; Path=/", "example.com").unwrap();
        let findings = c.audit_findings();
        assert!(findings.contains(&"Cookie missing Secure flag"));
        assert!(findings.contains(&"Cookie missing HttpOnly flag"));
        assert!(findings.contains(&"Cookie missing SameSite attribute"));
    }

    #[test]
    fn header_for_returns_cookies() {
        let jar = CookieJar::new();
        jar.absorb("example.com", "a=1; Path=/");
        jar.absorb("example.com", "b=2; Path=/api");
        let header = jar.header_for("example.com", "/api/x", "https").unwrap();
        assert!(header.contains("a=1"));
        assert!(header.contains("b=2"));
    }

    #[test]
    fn secure_only_on_https() {
        let jar = CookieJar::new();
        jar.absorb("example.com", "s=1; Secure; Path=/");
        assert!(jar.header_for("example.com", "/", "http").is_none());
        assert!(jar.header_for("example.com", "/", "https").is_some());
    }

    #[test]
    fn subdomain_matches_domain_attribute() {
        let jar = CookieJar::new();
        jar.absorb("example.com", "g=1; Domain=.example.com; Path=/");
        assert!(jar.header_for("api.example.com", "/", "https").is_some());
        assert!(jar.header_for("other.org", "/", "https").is_none());
    }
}
