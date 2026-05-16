// nmap-service-probes parser + match engine. The probe file is vendored at
// build time via include_str! from src-tauri/resources/portscan/. License is
// nmap-public-source-license (NPSL); we bundle unmodified.
//
// Parse semantics follow https://nmap.org/book/vscan-fileformat.html — we
// implement Probe / rarity / ports / sslports / totalwaitms / fallback /
// match / softmatch / Exclude. We do NOT implement port-version detection
// driver scripts, NSE, or service-fingerprints since none of those are
// needed for port-state + service-name + product/version output.

use once_cell::sync::Lazy;
use regex::bytes::{Regex, RegexBuilder};
use std::collections::HashMap;

const PROBES_TXT: &str = include_str!("../../resources/portscan/nmap-service-probes");

#[derive(Debug, Default, Clone)]
pub struct ServiceMatch {
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub info: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub device: Option<String>,
    pub cpe: Vec<String>,
    pub soft: bool,
    pub probe: String,
}

#[derive(Debug)]
pub struct MatchRule {
    pub service: String,
    pub re: Regex,
    pub product: Option<String>,
    pub version: Option<String>,
    pub info: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub device: Option<String>,
    pub cpe: Vec<String>,
    pub soft: bool,
}

#[derive(Debug, Default)]
pub struct Probe {
    pub proto: String,
    pub name: String,
    pub payload: Vec<u8>,
    pub rarity: u8,
    pub ports: Vec<u16>,
    pub sslports: Vec<u16>,
    pub total_wait_ms: u32,
    pub tcp_wrapped_ms: u32,
    pub fallbacks: Vec<String>,
    pub matches: Vec<MatchRule>,
}

#[derive(Debug, Default)]
pub struct ProbeDb {
    pub probes: Vec<Probe>,
    pub by_name: HashMap<String, usize>,
    pub exclude: Vec<u16>,
}

pub static PROBES: Lazy<ProbeDb> = Lazy::new(|| parse(PROBES_TXT).unwrap_or_default());

/// Look up a Probe by name; returns None if absent.
pub fn probe_by_name(name: &str) -> Option<&'static Probe> {
    let idx = *PROBES.by_name.get(name)?;
    PROBES.probes.get(idx)
}

/// Get the canonical NULL probe (banner-only).
pub fn null_probe() -> Option<&'static Probe> {
    probe_by_name("NULL")
}

/// Iterate over TCP probes whose `ports` (or `sslports`) match `port` AND
/// whose rarity <= intensity, in declaration order. Always yields NULL first
/// if present.
pub fn relevant_probes(port: u16, intensity: u8, tls: bool) -> impl Iterator<Item = &'static Probe> {
    PROBES.probes.iter().filter(move |p| {
        if p.proto != "TCP" {
            return false;
        }
        if p.rarity > intensity && p.name != "NULL" {
            return false;
        }
        if p.name == "NULL" {
            return true;
        }
        let in_ports = p.ports.contains(&port);
        let in_ssl = p.sslports.contains(&port);
        if tls {
            in_ssl || in_ports
        } else {
            in_ports
        }
    })
}

pub fn match_response_one(probe: &Probe, buf: &[u8]) -> Option<ServiceMatch> {
    if buf.is_empty() {
        return None;
    }
    let mut soft_hit: Option<ServiceMatch> = None;
    for rule in &probe.matches {
        if let Some(caps) = rule.re.captures(buf) {
            let m = ServiceMatch {
                service: rule.service.clone(),
                product: rule.product.as_ref().map(|t| interp(t, &caps)),
                version: rule.version.as_ref().map(|t| interp(t, &caps)),
                info: rule.info.as_ref().map(|t| interp(t, &caps)),
                hostname: rule.hostname.as_ref().map(|t| interp(t, &caps)),
                os: rule.os.as_ref().map(|t| interp(t, &caps)),
                device: rule.device.as_ref().map(|t| interp(t, &caps)),
                cpe: rule.cpe.iter().map(|t| interp(t, &caps)).collect(),
                soft: rule.soft,
                probe: probe.name.clone(),
            };
            if rule.soft {
                soft_hit = Some(m);
            } else {
                return Some(m);
            }
        }
    }
    // Try fallback probes for a hard match.
    for fb in &probe.fallbacks {
        if let Some(p) = probe_by_name(fb) {
            if let Some(m) = match_response_one(p, buf) {
                if !m.soft {
                    return Some(m);
                }
            }
        }
    }
    soft_hit
}

fn parse(text: &str) -> Result<ProbeDb, String> {
    let mut db = ProbeDb::default();
    let mut cur: Option<Probe> = None;
    for raw in text.lines() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("Exclude ") {
            db.exclude.extend(parse_ports(rest));
            continue;
        }
        if let Some(rest) = line.strip_prefix("Probe ") {
            if let Some(p) = cur.take() {
                db.by_name.insert(p.name.clone(), db.probes.len());
                db.probes.push(p);
            }
            let mut parts = rest.splitn(3, ' ');
            let proto = parts.next().unwrap_or("").to_string();
            let name = parts.next().unwrap_or("").to_string();
            let q = parts.next().unwrap_or("");
            let payload = decode_q(q);
            cur = Some(Probe { proto, name, payload, ..Default::default() });
            continue;
        }
        let Some(p) = cur.as_mut() else { continue };
        if let Some(r) = line.strip_prefix("rarity ") {
            p.rarity = r.trim().parse().unwrap_or(5);
        } else if let Some(r) = line.strip_prefix("ports ") {
            p.ports = parse_ports(r);
        } else if let Some(r) = line.strip_prefix("sslports ") {
            p.sslports = parse_ports(r);
        } else if let Some(r) = line.strip_prefix("totalwaitms ") {
            p.total_wait_ms = r.trim().parse().unwrap_or(6000);
        } else if let Some(r) = line.strip_prefix("tcpwrappedms ") {
            p.tcp_wrapped_ms = r.trim().parse().unwrap_or(3000);
        } else if let Some(r) = line.strip_prefix("fallback ") {
            p.fallbacks = r.split(',').map(|s| s.trim().to_string()).collect();
        } else if line.starts_with("match ") || line.starts_with("softmatch ") {
            let soft = line.starts_with("softmatch ");
            let body = &line[if soft { 10 } else { 6 }..];
            if let Some(m) = parse_match(body, soft) {
                p.matches.push(m);
            }
        }
    }
    if let Some(p) = cur.take() {
        db.by_name.insert(p.name.clone(), db.probes.len());
        db.probes.push(p);
    }
    Ok(db)
}

fn decode_q(s: &str) -> Vec<u8> {
    // "q||"  -> NULL probe, empty payload
    // "q|...payload...|" — payload uses \xHH, \r, \n, \t, \\, \0 escapes
    if !s.starts_with("q|") || s.len() < 3 {
        return Vec::new();
    }
    // Strip "q|" and trailing "|" (last char).
    let inner = &s[2..s.len() - 1];
    let bytes = inner.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'r' => {
                    out.push(b'\r');
                    i += 2;
                }
                b'n' => {
                    out.push(b'\n');
                    i += 2;
                }
                b't' => {
                    out.push(b'\t');
                    i += 2;
                }
                b'0' => {
                    out.push(0);
                    i += 2;
                }
                b'\\' => {
                    out.push(b'\\');
                    i += 2;
                }
                b'x' if i + 3 < bytes.len() => {
                    let h = std::str::from_utf8(&bytes[i + 2..i + 4]).unwrap_or("00");
                    out.push(u8::from_str_radix(h, 16).unwrap_or(0));
                    i += 4;
                }
                c => {
                    out.push(c);
                    i += 2;
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

fn parse_ports(s: &str) -> Vec<u16> {
    let mut v = Vec::new();
    for tok in s.split(',') {
        let tok = tok.trim();
        if let Some((a, b)) = tok.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.parse::<u16>(), b.parse::<u16>()) {
                v.extend(a..=b);
            }
        } else if let Ok(p) = tok.parse::<u16>() {
            v.push(p);
        }
    }
    v
}

fn parse_match(body: &str, soft: bool) -> Option<MatchRule> {
    // Format: SERVICE m<delim>REGEX<delim><flags?> [p/Prod/] [v/Ver/] [i/Info/] ...
    let (service, rest) = body.split_once(' ')?;
    let rest = rest.trim_start();
    if !rest.starts_with('m') {
        return None;
    }
    let bytes = rest.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let delim = bytes[1];
    // Find end of regex (next unescaped occurrence of delim after position 2).
    let mut i = 2usize;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == delim {
            break;
        }
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let pattern = &rest[2..i];
    // Optional flags after delim.
    let mut j = i + 1;
    let flags_end = bytes[j..].iter().position(|&b| b == b' ').map(|p| p + j).unwrap_or(bytes.len());
    let flag_str = &rest[j..flags_end];
    j = flags_end;
    let case_i = flag_str.contains('i');
    let dot_s = flag_str.contains('s');
    let re = RegexBuilder::new(pattern)
        .case_insensitive(case_i)
        .dot_matches_new_line(dot_s)
        .unicode(false)
        .size_limit(2_000_000)
        .build()
        .ok()?;
    let mut rule = MatchRule {
        service: service.to_string(),
        re,
        soft,
        product: None,
        version: None,
        info: None,
        hostname: None,
        os: None,
        device: None,
        cpe: vec![],
    };
    // Walk remaining fields:  p/.../   v/.../   i/.../   h/.../   o/.../   d/.../  cpe:/.../[a]
    while j < bytes.len() {
        while j < bytes.len() && bytes[j] == b' ' {
            j += 1;
        }
        if j >= bytes.len() {
            break;
        }
        // key is up to either '/' or ':'
        let key_start = j;
        let key_end = match bytes[j..].iter().position(|&b| b == b'/' || b == b':') {
            Some(p) => p + j,
            None => break,
        };
        let key = &rest[key_start..key_end];
        let mut k = key_end;
        if bytes[k] == b':' {
            k += 1;
        }
        if k >= bytes.len() || bytes[k] != b'/' {
            j = k.max(j + 1);
            continue;
        }
        k += 1;
        // Value runs to next unescaped delim '/'.
        let val_start = k;
        while k < bytes.len() {
            if bytes[k] == b'\\' {
                k += 2;
                continue;
            }
            if bytes[k] == b'/' {
                break;
            }
            k += 1;
        }
        if k >= bytes.len() {
            break;
        }
        let val = rest[val_start..k].to_string();
        // Possible trailing flag char like cpe:/.../a — skip into next space.
        k += 1;
        while k < bytes.len() && bytes[k] != b' ' {
            k += 1;
        }
        match key {
            "p" => rule.product = Some(val),
            "v" => rule.version = Some(val),
            "i" => rule.info = Some(val),
            "h" => rule.hostname = Some(val),
            "o" => rule.os = Some(val),
            "d" => rule.device = Some(val),
            "cpe" => rule.cpe.push(val),
            _ => {}
        }
        j = k;
    }
    Some(rule)
}

fn interp(template: &str, caps: &regex::bytes::Captures) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            let n = (bytes[i + 1] - b'0') as usize;
            if let Some(m) = caps.get(n) {
                if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                    out.push_str(s);
                }
            }
            i += 2;
        } else if bytes[i].is_ascii() {
            out.push(bytes[i] as char);
            i += 1;
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_real_file() {
        assert!(!PROBES.probes.is_empty(), "no probes parsed");
        assert!(PROBES.by_name.contains_key("NULL"), "missing NULL probe");
        assert!(PROBES.by_name.contains_key("GetRequest"), "missing GetRequest probe");
    }
}
