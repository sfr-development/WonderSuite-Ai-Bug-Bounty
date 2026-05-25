// UDP scan engine. Sends protocol-specific UDP payloads and waits for a
// response. No raw sockets, no admin privileges needed for the SEND/RECV
// path — but without raw ICMP capture we cannot distinguish "closed"
// (ICMP type 3 code 3 received) from "open|filtered" (no response).
// Pragmatic semantics:
//   - Got a UDP datagram back   → Open + service inferred from payload
//   - No response within timeout → OpenFiltered (could be open silent, could be filtered)
//   - Connect-style error (rare on UDP) → Closed
//
// Pentesters using nmap UDP get the same ambiguity unless root + ICMP is
// available; we surface it explicitly in the pill.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tokio::time::timeout;

use crate::portscan::timing::AdaptiveTiming;
use crate::portscan::types::{PortState, ScanResult, ServiceInfo};

#[allow(clippy::too_many_arguments)]
pub async fn run_udp_scan(
    targets: Vec<(String, IpAddr)>,
    ports: Vec<u16>,
    timing: Arc<AdaptiveTiming>,
    _service_detect: bool,
    cancel: Arc<Notify>,
    result_tx: mpsc::Sender<ScanResult>,
    progress_tick: Arc<dyn Fn() + Send + Sync>,
) {
    let total = targets.len() * ports.len();
    let mut handles = Vec::with_capacity(total.min(65536));

    let cancelled = Arc::new(AtomicBool::new(false));
    {
        let flag = cancelled.clone();
        let notify = cancel.clone();
        tokio::spawn(async move {
            notify.notified().await;
            flag.store(true, Ordering::Relaxed);
        });
    }

    'outer: for &port in &ports {
        for (host, ip) in &targets {
            if cancelled.load(Ordering::Relaxed) {
                break 'outer;
            }
            let permit = match timing.permits.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let tx = result_tx.clone();
            let to = timing.timeout();
            let rtt = timing.rtt.clone();
            let tick = progress_tick.clone();
            let host = host.clone();
            let ip = *ip;
            let cancel_flag = cancelled.clone();

            let h = tokio::spawn(async move {
                let _p = permit;
                if cancel_flag.load(Ordering::Relaxed) {
                    return;
                }
                let addr = SocketAddr::new(ip, port);
                let bind = if ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
                let socket = match UdpSocket::bind(bind).await {
                    Ok(s) => s,
                    Err(_) => {
                        tick();
                        return;
                    }
                };
                if socket.connect(addr).await.is_err() {
                    tick();
                    return;
                }

                let started = Instant::now();
                let payload = probe_for_port(port);
                if socket.send(payload).await.is_err() {
                    tick();
                    return;
                }

                let mut buf = [0u8; 2048];
                let outcome = match timeout(to, socket.recv(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let rtt_ms = started.elapsed().as_millis() as u32;
                        rtt.observe(rtt_ms);
                        let service = infer_udp_service(port, &buf[..n]);
                        Some(ScanResult {
                            host: host.clone(),
                            ip,
                            port,
                            proto: "udp".into(),
                            state: PortState::Open,
                            service,
                            rtt_ms,
                            ts: now_ts(),
                        })
                    }
                    Ok(Err(e)) => {
                        // ECONNREFUSED on UDP means we got ICMP unreachable
                        // from the kernel — port is closed. (Linux/macOS only;
                        // Windows usually swallows this.)
                        let kind = e.kind();
                        if matches!(kind, std::io::ErrorKind::ConnectionRefused) {
                            Some(ScanResult {
                                host: host.clone(),
                                ip,
                                port,
                                proto: "udp".into(),
                                state: PortState::Closed,
                                service: None,
                                rtt_ms: started.elapsed().as_millis() as u32,
                                ts: now_ts(),
                            })
                        } else {
                            None
                        }
                    }
                    Ok(_) | Err(_) => {
                        // Timeout — open|filtered
                        Some(ScanResult {
                            host: host.clone(),
                            ip,
                            port,
                            proto: "udp".into(),
                            state: PortState::OpenFiltered,
                            service: None,
                            rtt_ms: started.elapsed().as_millis() as u32,
                            ts: now_ts(),
                        })
                    }
                };
                tick();
                if let Some(r) = outcome {
                    // For UDP, only emit if state is Open or Closed — drop
                    // open|filtered noise unless it's the only signal we have
                    // (we keep it because the user explicitly chose UDP mode
                    // and wants to see the candidates).
                    let _ = tx.send(r).await;
                }
            });
            handles.push(h);
        }
    }

    for h in handles {
        let _ = h.await;
    }
}

/// Protocol-specific UDP probes. Returns an empty slice if no probe is known,
/// in which case we send a single zero byte just to wake the port (some
/// services respond to anything; many don't).
fn probe_for_port(port: u16) -> &'static [u8] {
    match port {
        // DNS standard query for ".version.bind" CHAOS TXT — Bind/PowerDNS reply
        53 => &[
            0x12, 0x34, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'v',
            b'e', b'r', b's', b'i', b'o', b'n', 0x04, b'b', b'i', b'n', b'd', 0x00, 0x00, 0x10,
            0x00, 0x03,
        ],
        // SNMP v1 GET sysDescr.0 community=public
        161 | 162 => &[
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
            0x19, 0x02, 0x04, 0x12, 0x34, 0x56, 0x78, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
            0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
        ],
        // NTP v2 client mode
        123 => &[
            0x17, 0x00, 0x03, 0x2a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        // NetBIOS Name Service — Wildcard name query
        137 => &[
            0xa2, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43,
            0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01,
        ],
        // SSDP M-SEARCH discovery
        1900 => b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
        // SIP OPTIONS
        5060 | 5061 => b"OPTIONS sip:nobody@nowhere SIP/2.0\r\nVia: SIP/2.0/UDP example.com\r\nMax-Forwards: 70\r\nFrom: <sip:scan@example.com>;tag=1\r\nTo: <sip:nobody@nowhere>\r\nCall-ID: scan@example.com\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
        // mDNS query for _services._dns-sd._udp.local
        5353 => &[
            0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, b'_',
            b's', b'e', b'r', b'v', b'i', b'c', b'e', b's', 0x07, b'_', b'd', b'n', b's', b'-',
            b's', b'd', 0x04, b'_', b'u', b'd', b'p', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00,
            0x00, 0x0c, 0x00, 0x01,
        ],
        // IPMI v2 RMCP+ Get Channel Authentication Capabilities (UDP 623)
        623 => &[
            0x06, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, 0x8e, 0x04, 0xb5,
        ],
        // OpenVPN tcp/udp probe — UDP server replies to a v1 CONTROL_HARD_RESET_CLIENT
        1194 => &[
            0x38, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        // IKE / IPSec — Main mode initiator phase 1 (minimal SA proposal)
        500 | 4500 => &[
            0x5b, 0x5e, 0x64, 0xc0, 0x3e, 0x99, 0xb5, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9c,
            0x0d, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x01, 0x01, 0x00, 0x03, 0x03, 0x00, 0x00, 0x28,
        ],
        // TFTP RRQ for "wondersuite-scan"
        69 => &[
            0x00, 0x01, b'w', b'o', b'n', b'd', b'e', b'r', b's', b'u', b'i', b't', b'e', b'-',
            b's', b'c', b'a', b'n', 0x00, b'o', b'c', b't', b'e', b't', 0x00,
        ],
        // RIP request
        520 => &[
            0x01, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        // QUIC initial probe — minimal client hello + version 0x00000001
        443 => &[
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
            0x00,
        ],
        _ => &[0],
    }
}

fn infer_udp_service(port: u16, reply: &[u8]) -> Option<ServiceInfo> {
    let (name, product) = match port {
        53 => ("dns", Some("DNS")),
        67 | 68 => ("dhcp", Some("DHCP")),
        69 => ("tftp", Some("TFTP")),
        123 => ("ntp", Some("NTP")),
        137 => ("netbios-ns", Some("NetBIOS Name Service")),
        161 | 162 => ("snmp", Some("SNMP")),
        500 | 4500 => ("isakmp", Some("IKE/IPSec")),
        520 => ("rip", Some("RIP")),
        623 => ("ipmi", Some("IPMI")),
        1194 => ("openvpn", Some("OpenVPN")),
        1900 => ("ssdp", Some("SSDP/UPnP")),
        5060 | 5061 => ("sip", Some("SIP")),
        5353 => ("mdns", Some("mDNS")),
        _ => ("udp-open", None),
    };
    let banner = if reply.is_empty() {
        None
    } else if reply.iter().all(|&b| (32..=126).contains(&b) || b == 9 || b == 10 || b == 13) {
        Some(String::from_utf8_lossy(reply).chars().take(120).collect::<String>())
    } else {
        Some(format!("{} bytes binary reply", reply.len()))
    };
    Some(ServiceInfo {
        name: name.into(),
        product: product.map(String::from),
        version: None,
        banner,
        tls_cn: None,
        tls_san: vec![],
        tls: false,
    })
}

fn now_ts() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
