// In-process service detection. Now powered by the **real nmap-service-probes**
// file (vendored at build time via include_str! — 187 probes, 12k+ match
// patterns). Flow:
//   1. NULL probe: read whatever the server sends on connect (banner-style
//      protocols: SSH, FTP, SMTP, POP3, IMAP, VNC, MySQL, MongoDB, …).
//   2. If no NULL match: walk probes whose `ports` (or `sslports`) cover the
//      target port, in rarity order. Send each payload, run regex matches.
//   3. Stop at first hard match. Soft-matches are retained as fallback if no
//      hard match found by the end of the probe set.
//
// Intensity (0–9) controls how many probes we try (rarity ≤ intensity).
// Identical semantics to nmap's `--version-intensity`.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::service_probes::{match_response_one, null_probe, relevant_probes};
use super::types::ServiceInfo;

mod tls;

pub async fn detect_service(mut stream: TcpStream, port: u16, intensity: u8) -> Option<ServiceInfo> {
    let intensity = intensity.min(9);

    // 1. NULL probe — read whatever the server sends on connect. Catches
    // SSH/FTP/SMTP/IMAP/MySQL/MongoDB/VNC server-first protocols. Match
    // against the 100+ NULL-probe patterns in the nmap-service-probes file.
    let mut buf = [0u8; 4096];
    let n = match timeout(Duration::from_millis(300), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => 0,
    };
    if n > 0 {
        if let Some(p) = null_probe() {
            if let Some(m) = match_response_one(p, &buf[..n]) {
                return Some(service_info_from_match(m, false));
            }
        }
        // Legacy fallback path for the few protocols where our hand-rolled
        // banner parser is more conservative (mostly mysql binary greeting).
        if let Some(svc) = match_banner(&buf[..n], port) {
            return Some(svc);
        }
    }

    if intensity == 0 {
        return None;
    }

    // 2. Active probes — only the *first* port-relevant probe gets a chance
    // on this open stream. Multi-probe scanning would need a reconnect per
    // probe, which is significant overhead for a connect-mode scan and what
    // `service_detect` MCP tool is intended for instead. Rarity ≤ intensity
    // gates which probes are eligible.
    for probe in relevant_probes(port, intensity, false) {
        if probe.payload.is_empty() {
            continue; // NULL handled above
        }
        let wait_ms = probe.total_wait_ms.clamp(200, 1200);
        let reply = run_probe_on_stream(&mut stream, &probe.payload, wait_ms).await?;
        if let Some(m) = match_response_one(probe, &reply) {
            return Some(service_info_from_match(m, false));
        }
        break; // single active probe per connection
    }

    // 3. Fallback to hand-rolled HTTP/Postgres/Redis/etc. probes — useful on
    // odd ports where nmap-service-probes doesn't list the port hint.
    if let Some(probe) = port_hint_probe(port) {
        if let Some(svc) = run_probe(&mut stream, probe).await {
            return Some(svc);
        }
    }
    if intensity >= 5 {
        if let Some(svc) = http_probe(&mut stream).await {
            return Some(svc);
        }
    }
    None
}

async fn run_probe_on_stream(stream: &mut TcpStream, payload: &[u8], wait_ms: u32) -> Option<Vec<u8>> {
    if !payload.is_empty() && stream.write_all(payload).await.is_err() {
        return None;
    }
    let mut buf = vec![0u8; 4096];
    let n = match timeout(Duration::from_millis(wait_ms as u64), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };
    buf.truncate(n);
    Some(buf)
}

fn service_info_from_match(m: super::service_probes::ServiceMatch, tls: bool) -> ServiceInfo {
    let banner = if let Some(ref info) = m.info {
        Some(info.clone())
    } else if let Some(ref p) = m.product {
        Some(format!("{}{}", p, m.version.as_deref().map(|v| format!(" {}", v)).unwrap_or_default()))
    } else {
        Some(format!("matched probe: {}", m.probe))
    };
    ServiceInfo {
        name: m.service,
        product: m.product,
        version: m.version,
        banner,
        tls_cn: None,
        tls_san: vec![],
        tls,
    }
}

#[derive(Clone, Copy)]
struct Probe {
    name: &'static str,
    payload: &'static [u8],
    expects: fn(&[u8]) -> Option<ServiceInfo>,
}

async fn run_probe(stream: &mut TcpStream, probe: Probe) -> Option<ServiceInfo> {
    if !probe.payload.is_empty() && stream.write_all(probe.payload).await.is_err() {
        return None;
    }
    let mut buf = [0u8; 2048];
    let n = match timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };
    (probe.expects)(&buf[..n])
}

fn port_hint_probe(port: u16) -> Option<Probe> {
    Some(match port {
        80 | 8080 | 8000 | 8008 | 8081 | 8888 | 5000 => HTTP_PROBE,
        443 | 8443 => return None, // handled by http_probe via TLS
        3306 => return None,       // MySQL is server-first
        5432 => POSTGRES_PROBE,
        6379 => REDIS_PROBE,
        27017 => MONGO_PROBE,
        11211 => MEMCACHED_PROBE,
        3389 => RDP_PROBE,
        10050 | 10051 => ZABBIX_PROBE,
        9100 => HTTP_PROBE, // jetdirect / printer — many also speak HTTP
        139 | 445 => SMB_PROBE,
        _ => return None,
    })
}

// ── Banner matchers (server-first protocols) ─────────────────────────────

fn match_banner(buf: &[u8], _port: u16) -> Option<ServiceInfo> {
    let text = std::str::from_utf8(buf).unwrap_or("");
    let lower = text.to_ascii_lowercase();

    if text.starts_with("SSH-") {
        // SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n
        let line = text.lines().next().unwrap_or(text).trim_end();
        let (product, version) = parse_ssh_banner(line);
        return Some(ServiceInfo {
            name: "ssh".into(),
            product,
            version,
            banner: Some(line.to_string()),
            tls_cn: None,
            tls_san: vec![],
            tls: false,
        });
    }
    if text.starts_with("220 ") || text.starts_with("220-") {
        let line = text.lines().next().unwrap_or(text).trim_end();
        let lower_line = line.to_ascii_lowercase();
        let name = if lower_line.contains("ftp") {
            "ftp"
        } else if lower_line.contains("smtp") || lower_line.contains("esmtp") {
            "smtp"
        } else {
            "ftp" // default for 220
        };
        return Some(ServiceInfo {
            name: name.into(),
            product: None,
            version: None,
            banner: Some(line.to_string()),
            tls_cn: None,
            tls_san: vec![],
            tls: false,
        });
    }
    if text.starts_with("+OK") {
        let line = text.lines().next().unwrap_or(text).trim_end();
        return Some(ServiceInfo {
            name: "pop3".into(),
            product: None,
            version: None,
            banner: Some(line.to_string()),
            tls_cn: None,
            tls_san: vec![],
            tls: false,
        });
    }
    if text.starts_with("* OK") || lower.starts_with("* ok") {
        let line = text.lines().next().unwrap_or(text).trim_end();
        return Some(ServiceInfo {
            name: "imap".into(),
            product: None,
            version: None,
            banner: Some(line.to_string()),
            tls_cn: None,
            tls_san: vec![],
            tls: false,
        });
    }
    if text.starts_with("RFB ") {
        // VNC sends "RFB 003.008\n"
        let line = text.lines().next().unwrap_or(text).trim_end();
        let version = line.strip_prefix("RFB ").map(|s| s.to_string());
        return Some(ServiceInfo {
            name: "vnc".into(),
            product: Some("VNC".into()),
            version,
            banner: Some(line.to_string()),
            tls_cn: None,
            tls_san: vec![],
            tls: false,
        });
    }
    // MySQL: server greeting is binary. Byte 4 is protocol version (10 for modern),
    // then null-terminated version string.
    if buf.len() > 6 && buf[4] == 0x0a {
        let ver_end = buf[5..].iter().position(|&b| b == 0).map(|p| p + 5).unwrap_or(buf.len());
        let version = std::str::from_utf8(&buf[5..ver_end]).ok().map(|s| s.to_string());
        return Some(ServiceInfo {
            name: "mysql".into(),
            product: Some("MySQL".into()),
            version,
            banner: Some(format!("mysql-protocol-v10")),
            tls_cn: None,
            tls_san: vec![],
            tls: false,
        });
    }
    None
}

fn parse_ssh_banner(line: &str) -> (Option<String>, Option<String>) {
    // SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5
    let after = line.trim_start_matches("SSH-2.0-").trim_start_matches("SSH-1.99-");
    if let Some((prod_version, _comment)) = after.split_once(' ') {
        if let Some((prod, ver)) = prod_version.split_once('_') {
            return (Some(prod.to_string()), Some(ver.to_string()));
        }
        return (Some(prod_version.to_string()), None);
    }
    if let Some((prod, ver)) = after.split_once('_') {
        return (Some(prod.to_string()), Some(ver.to_string()));
    }
    (Some(after.to_string()), None)
}

// ── Active probes ─────────────────────────────────────────────────────────

const HTTP_PROBE: Probe = Probe {
    name: "http",
    payload: b"GET / HTTP/1.0\r\nHost: scan.local\r\nUser-Agent: WonderSuite/0.3.7\r\nAccept: */*\r\nConnection: close\r\n\r\n",
    expects: |buf| {
        let text = std::str::from_utf8(buf).unwrap_or("");
        if !text.starts_with("HTTP/") {
            return None;
        }
        let mut product = None;
        let mut version = None;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("Server: ") {
                let rest = rest.trim();
                if let Some((p, v)) = rest.split_once('/') {
                    product = Some(p.to_string());
                    version = Some(v.split(' ').next().unwrap_or(v).to_string());
                } else {
                    product = Some(rest.to_string());
                }
                break;
            }
        }
        let status_line = text.lines().next().unwrap_or("").to_string();
        Some(ServiceInfo {
            name: "http".into(),
            product,
            version,
            banner: Some(status_line),
            tls_cn: None,
            tls_san: vec![],
            tls: false,
        })
    },
};

const POSTGRES_PROBE: Probe = Probe {
    name: "postgresql",
    payload: &[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f], // SSLRequest
    expects: |buf| {
        if buf.is_empty() {
            return None;
        }
        let detail = match buf[0] {
            b'S' => "ssl-supported",
            b'N' => "ssl-unsupported",
            b'E' => "error-response",
            _ => return None,
        };
        Some(ServiceInfo {
            name: "postgresql".into(),
            product: Some("PostgreSQL".into()),
            version: None,
            banner: Some(format!("postgres {}", detail)),
            tls_cn: None,
            tls_san: vec![],
            tls: false,
        })
    },
};

const REDIS_PROBE: Probe = Probe {
    name: "redis",
    payload: b"*1\r\n$4\r\nPING\r\n",
    expects: |buf| {
        let text = std::str::from_utf8(buf).unwrap_or("");
        if !text.starts_with("+PONG") && !text.starts_with("-NOAUTH") {
            return None;
        }
        let auth_required = text.starts_with("-NOAUTH");
        Some(ServiceInfo {
            name: "redis".into(),
            product: Some("Redis".into()),
            version: None,
            banner: Some(if auth_required {
                "redis (auth required)".into()
            } else {
                "redis (no auth)".into()
            }),
            tls_cn: None,
            tls_san: vec![],
            tls: false,
        })
    },
};

const MONGO_PROBE: Probe = Probe {
    // OP_QUERY isMaster: this is the wire format pre-3.6. Modern Mongo also
    // answers with a hello-style reply.
    name: "mongodb",
    payload: &[
        0x3a, 0, 0, 0, // messageLength = 58
        1, 0, 0, 0, // requestID
        0, 0, 0, 0, // responseTo
        0xd4, 0x07, 0, 0, // opCode = OP_QUERY (2004)
        0, 0, 0, 0, // flags
        b'a', b'd', b'm', b'i', b'n', b'.', b'$', b'c', b'm', b'd', 0, // fullCollectionName
        0, 0, 0, 0, // numberToSkip
        1, 0, 0, 0, // numberToReturn
        0x13, 0, 0, 0, // BSON doc length = 19
        0x10, b'i', b's', b'M', b'a', b's', b't', b'e', b'r', 0, 1, 0, 0, 0, 0, // {isMaster:1}
    ],
    expects: |buf| {
        if buf.len() < 16 {
            return None;
        }
        // Look for "ismaster" or "maxBsonObjectSize" / "maxWireVersion" markers in reply BSON.
        let head = std::str::from_utf8(&buf[16..buf.len().min(512)]).unwrap_or("");
        if head.contains("ismaster") || head.contains("maxBsonObjectSize") || head.contains("maxWireVersion")
        {
            return Some(ServiceInfo {
                name: "mongodb".into(),
                product: Some("MongoDB".into()),
                version: None,
                banner: Some("mongo hello reply".into()),
                tls_cn: None,
                tls_san: vec![],
                tls: false,
            });
        }
        None
    },
};

const MEMCACHED_PROBE: Probe = Probe {
    name: "memcached",
    payload: b"version\r\n",
    expects: |buf| {
        let text = std::str::from_utf8(buf).unwrap_or("");
        if !text.starts_with("VERSION ") {
            return None;
        }
        let line = text.lines().next().unwrap_or("").trim_end();
        let version = line.strip_prefix("VERSION ").map(|s| s.to_string());
        Some(ServiceInfo {
            name: "memcached".into(),
            product: Some("Memcached".into()),
            version,
            banner: Some(line.to_string()),
            tls_cn: None,
            tls_san: vec![],
            tls: false,
        })
    },
};

const RDP_PROBE: Probe = Probe {
    // Class 0 X.224 Connection Request TPDU; bare CR with no cookie. Modern
    // RDP servers reply with a Class-0 CC.
    name: "rdp",
    payload: &[0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00],
    expects: |buf| {
        if buf.len() < 4 {
            return None;
        }
        // TPKT header: 03 00 LEN_HI LEN_LO
        if buf[0] != 0x03 || buf[1] != 0x00 {
            return None;
        }
        Some(ServiceInfo {
            name: "rdp".into(),
            product: Some("Microsoft RDP".into()),
            version: None,
            banner: Some("x.224 connection confirm".into()),
            tls_cn: None,
            tls_san: vec![],
            tls: false,
        })
    },
};

const ZABBIX_PROBE: Probe = Probe {
    // Zabbix agent protocol: send ZBXD\x01 + 8-byte little-endian length + payload.
    // We send the agent.version key. Open agents respond with their version string
    // in the same framed format. Passive agents on 10050 also accept this.
    name: "zabbix",
    payload: &[
        b'Z', b'B', b'X', b'D', 0x01, // header
        0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // length = 13
        b'a', b'g', b'e', b'n', b't', b'.', b'v', b'e', b'r', b's', b'i', b'o', b'n',
    ],
    expects: |buf| {
        if buf.len() >= 5 && &buf[..5] == b"ZBXD\x01" {
            let version = if buf.len() > 13 {
                std::str::from_utf8(&buf[13..]).ok().map(|s| s.trim().to_string())
            } else {
                None
            };
            return Some(ServiceInfo {
                name: "zabbix-agent".into(),
                product: Some("Zabbix Agent".into()),
                version,
                banner: Some("zabbix agent protocol".into()),
                tls_cn: None,
                tls_san: vec![],
                tls: false,
            });
        }
        None
    },
};

const SMB_PROBE: Probe = Probe {
    // Minimal SMB2 Negotiate Protocol Request. SMB1-only servers won't respond
    // to this; that's OK for v0.3.7.
    name: "smb",
    payload: &[
        // NetBIOS session service header: type=0, flags=0, length=0xC4
        0x00, 0x00, 0x00, 0xc4, // SMB2 header
        0xfe, b'S', b'M', b'B', 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SMB2 NEGOTIATE request body
        0x24, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x10, 0x02, 0x22, 0x02, 0x24, 0x02, 0x00, 0x03, 0x02, 0x03, 0x10,
        0x03, 0x11, 0x03,
    ],
    expects: |buf| {
        // Look for the SMB2 magic in the reply: \xfeSMB
        if buf.len() >= 8 && buf[4] == 0xfe && &buf[5..8] == b"SMB" {
            return Some(ServiceInfo {
                name: "smb".into(),
                product: Some("SMB2/SMB3".into()),
                version: None,
                banner: Some("smb2 negotiate response".into()),
                tls_cn: None,
                tls_san: vec![],
                tls: false,
            });
        }
        // SMB1 reply has \xffSMB
        if buf.len() >= 8 && buf[4] == 0xff && &buf[5..8] == b"SMB" {
            return Some(ServiceInfo {
                name: "smb".into(),
                product: Some("SMB1".into()),
                version: Some("legacy".into()),
                banner: Some("smb1 negotiate response".into()),
                tls_cn: None,
                tls_san: vec![],
                tls: false,
            });
        }
        None
    },
};

async fn http_probe(stream: &mut TcpStream) -> Option<ServiceInfo> {
    // Try plaintext HTTP first; if response starts with a TLS alert / unusable,
    // we cannot upgrade in-place without re-connecting.
    if let Some(svc) = run_probe(stream, HTTP_PROBE).await {
        return Some(svc);
    }
    None
}

// TLS probe re-opens a separate connection because we don't have ALPN-aware
// peek on a Tokio TcpStream. The connect.rs caller knows the (ip, port) and
// can ask this directly for ports 443/8443.
pub use tls::probe_tls;
