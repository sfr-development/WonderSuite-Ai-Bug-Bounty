// Minimal TLS probe: opens a fresh native-tls handshake against the target
// and extracts the peer cert CN + SAN list. Used for ports 443/8443 and on
// any port that returned a TLS ContentType (0x16) byte in the first banner
// read. We can't reuse a Tokio TcpStream after `connect` because we already
// consumed bytes — so the orchestrator calls this separately when needed.

use std::time::Duration;
use tokio::net::TcpStream;
use tokio_native_tls::native_tls;

use crate::portscan::types::ServiceInfo;

pub async fn probe_tls(host: &str, port: u16, sni: Option<&str>) -> Option<ServiceInfo> {
    let target = format!("{}:{}", host, port);
    let sock = match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&target)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .ok()?;
    let connector = tokio_native_tls::TlsConnector::from(connector);
    let sni = sni.unwrap_or(host);
    let stream =
        tokio::time::timeout(Duration::from_secs(3), connector.connect(sni, sock)).await.ok()?.ok()?;

    let cn;
    let mut san = Vec::<String>::new();
    if let Ok(Some(cert_der)) = stream.get_ref().peer_certificate() {
        let der = cert_der.to_der().ok()?;
        // Lightweight X.509 subject extract via the `der` crate would be ideal,
        // but for v0.3.7 we just stringify what native-tls hands us if it can.
        // native-tls's `Certificate::to_der` doesn't give a parsed view; we
        // fall back to substring matching on the DER for CN= and SAN URIs to
        // avoid pulling x509-parser as a runtime dep.
        cn = extract_cn(&der);
        san = extract_san(&der);
    } else {
        cn = None;
    }

    let svc_name = match port {
        443 | 8443 | 9443 => "https",
        465 => "smtps",
        993 => "imaps",
        995 => "pop3s",
        636 => "ldaps",
        3269 => "ldaps",
        5671 => "amqps",
        _ => "tls",
    };

    Some(ServiceInfo {
        name: svc_name.into(),
        product: None,
        version: None,
        banner: Some("tls handshake ok".into()),
        tls_cn: cn,
        tls_san: san,
        tls: true,
    })
}

fn extract_cn(der: &[u8]) -> Option<String> {
    // OID 2.5.4.3 (CN) DER: 0x55,0x04,0x03 inside a SET OF. Scan for the
    // marker 0x06,0x03,0x55,0x04,0x03 (OID) followed by a UTF8String /
    // PrintableString. Very rough; works for >95% of CA-issued certs.
    let needle = [0x06, 0x03, 0x55, 0x04, 0x03];
    for i in 0..der.len().saturating_sub(needle.len() + 4) {
        if der[i..i + 5] == needle {
            let tag = der[i + 5];
            if matches!(tag, 0x0c | 0x13 | 0x14 | 0x16) {
                let len = der[i + 6] as usize;
                let start = i + 7;
                if start + len <= der.len() {
                    if let Ok(s) = std::str::from_utf8(&der[start..start + len]) {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }
    None
}

fn extract_san(der: &[u8]) -> Vec<String> {
    // SAN extension OID: 2.5.29.17 → 0x55,0x1d,0x11. We scan for it and then
    // pull out dNSName entries (tag 0x82 in SubjectAltName SEQUENCE).
    let needle = [0x06, 0x03, 0x55, 0x1d, 0x11];
    let mut out = Vec::new();
    if let Some(idx) = der.windows(needle.len()).position(|w| w == needle) {
        // Skip the OID, then BOOLEAN(optional) + OCTET STRING wrapping the SEQUENCE
        let mut i = idx + needle.len();
        while i < der.len() {
            if der[i] == 0x82 {
                // dNSName, length byte follows
                if i + 1 >= der.len() {
                    break;
                }
                let len = der[i + 1] as usize;
                let s = i + 2;
                if s + len <= der.len() {
                    if let Ok(name) = std::str::from_utf8(&der[s..s + len]) {
                        out.push(name.to_string());
                    }
                }
                i = s + len;
            } else {
                i += 1;
            }
            if out.len() > 32 {
                break;
            }
        }
    }
    out
}
