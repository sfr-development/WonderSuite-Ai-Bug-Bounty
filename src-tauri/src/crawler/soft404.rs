// Soft-404 detection.
//
// Many sites return HTTP 200 with a "page not found" body for genuinely-
// missing paths. A naïve crawler chases this content forever; a security
// scanner needs to recognize that the response is functionally a 404 so it
// doesn't waste budget testing fake endpoints.
//
// Strategy:
//   1. At the start of every scan, fetch a guaranteed-bogus path
//      (`/<random-32-char>`) to capture the host's "soft-404 fingerprint":
//        - response status
//        - response length (bucketed)
//        - SHA-256 of the first 4 KB of response body
//        - the presence of common 404 strings ("not found", "page does not exist", etc.)
//   2. For every subsequent crawled URL, compare its response to the
//      fingerprint. If status matches and length is within ±10% and body
//      hash matches, mark it soft-404.
//
// Bucketing by length avoids false positives where a real 200 page just
// happens to be the same length as the 404 template.

use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Default, Clone, Serialize)]
pub struct Soft404Fingerprint {
    pub status: u16,
    pub length: usize,
    pub body_sha256: String,
    pub canonical_phrases: u8, // how many "not found"-style phrases were detected
}

impl Soft404Fingerprint {
    pub fn from_response(status: u16, body: &str) -> Self {
        let bytes = body.as_bytes();
        let prefix = &bytes[..bytes.len().min(4096)];
        let mut hasher = Sha256::new();
        hasher.update(prefix);
        let body_sha256 = format!("{:x}", hasher.finalize());

        Self { status, length: body.len(), body_sha256, canonical_phrases: count_404_phrases(body) }
    }

    /// Returns true if `other` looks like the same soft-404 response.
    pub fn matches(&self, other: &Self) -> bool {
        if self.status != other.status {
            return false;
        }
        // Length within ±10% (or ±256 bytes for tiny pages).
        let diff = self.length.abs_diff(other.length);
        let tol = (self.length / 10).max(256);
        if diff > tol {
            return false;
        }
        // Same body prefix hash OR same number of "not found" phrases AND
        // similar length is enough.
        if self.body_sha256 == other.body_sha256 {
            return true;
        }
        if self.canonical_phrases >= 2 && other.canonical_phrases >= 2 && diff < tol / 2 {
            return true;
        }
        false
    }

    /// True iff this fingerprint is itself a candidate for being treated as
    /// soft-404. A real 404 response wouldn't be cached as a baseline.
    pub fn looks_like_soft_404(&self) -> bool {
        self.status == 200 && self.canonical_phrases >= 2
    }
}

const PHRASES: &[&str] = &[
    "page not found",
    "404 not found",
    "not found",
    "page does not exist",
    "page no longer exists",
    "could not be found",
    "the page you are looking for",
    "the requested resource",
    "no such page",
    "seite nicht gefunden",   // de
    "page introuvable",       // fr
    "página no encontrada",   // es
    "pagina niet gevonden",   // nl
    "страница не найдена",    // ru
    "ページが見つかりません", // ja
    "找不到页面",             // zh
];

fn count_404_phrases(body: &str) -> u8 {
    let lower = body.to_ascii_lowercase();
    PHRASES.iter().take(8).filter(|p| lower.contains(*p)).count().min(255) as u8
}

/// Generate a random 32-char hex path. The caller appends it to the target
/// host to provoke a 404 / soft-404 baseline.
pub fn random_bogus_path() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: String = (0..32)
        .map(|_| {
            let n: u8 = rng.gen_range(0..16);
            std::char::from_digit(n as u32, 16).unwrap_or('0')
        })
        .collect();
    format!("/wondersuite-{}", chars)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_phrases() {
        let fp = Soft404Fingerprint::from_response(200, "The page you are looking for was not found.");
        assert!(fp.canonical_phrases >= 2);
    }

    #[test]
    fn matches_same_hash() {
        let a = Soft404Fingerprint::from_response(200, "Page Not Found 404");
        let b = Soft404Fingerprint::from_response(200, "Page Not Found 404");
        assert!(a.matches(&b));
    }

    #[test]
    fn different_status_no_match() {
        let a = Soft404Fingerprint::from_response(200, "Not Found");
        let b = Soft404Fingerprint::from_response(404, "Not Found");
        assert!(!a.matches(&b));
    }

    #[test]
    fn random_path_unique() {
        let p1 = random_bogus_path();
        let p2 = random_bogus_path();
        assert!(p1.starts_with("/wondersuite-"));
        assert_eq!(p1.len(), p2.len());
        // Extremely unlikely to collide
        assert_ne!(p1, p2);
    }
}
