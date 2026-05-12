// Ring buffer for captured browser requests, keyed by CDP requestId.
//
// Browser-side capture feeds this from `Network.requestWillBeSent` and
// `Network.responseReceived`. `browser_network_traffic` reads from it, and
// `browser_replay_to_proxy` fetches a single entry by its CDP requestId to
// hand to the proxy's Repeater.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;

const MAX_ENTRIES: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetEntry {
    pub request_id: String,
    pub url: String,
    pub method: String,
    pub resource_type: String,
    pub request_headers: serde_json::Value,
    pub request_body: Option<String>,
    pub status: Option<u16>,
    pub response_headers: serde_json::Value,
    pub mime_type: Option<String>,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    pub is_auth_like: bool,
}

#[derive(Default)]
pub struct NetCapture {
    entries: Mutex<VecDeque<NetEntry>>,
}

impl NetCapture {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, entry: NetEntry) {
        let mut g = self.entries.lock().unwrap();
        if g.len() >= MAX_ENTRIES {
            g.pop_front();
        }
        g.push_back(entry);
    }

    pub fn update(&self, request_id: &str, f: impl FnOnce(&mut NetEntry)) {
        let mut g = self.entries.lock().unwrap();
        if let Some(e) = g.iter_mut().rev().find(|e| e.request_id == request_id) {
            f(e);
        }
    }

    pub fn find(&self, request_id: &str) -> Option<NetEntry> {
        self.entries.lock().unwrap().iter().rev().find(|e| e.request_id == request_id).cloned()
    }

    pub fn snapshot(&self) -> Vec<NetEntry> {
        self.entries.lock().unwrap().iter().cloned().collect()
    }

    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

pub fn classify_auth_like(url: &str) -> bool {
    let u = url.to_ascii_lowercase();
    [
        "/auth",
        "/login",
        "/signin",
        "/sign-in",
        "/token",
        "/oauth",
        "/session",
        "/identity",
        "/sso",
        "/saml",
        "/openid",
        "/.well-known/openid",
        "/refresh",
        "/api/me",
        "/api/user",
        "/whoami",
        "/account",
    ]
    .iter()
    .any(|p| u.contains(p))
}
