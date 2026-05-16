// Raw-socket SYN scan engine.
//
//   Linux:   pnet_transport L4(Ipv4(TCP)) — kernel L3 raw socket, ARP/route
//            handled by the kernel. Needs CAP_NET_RAW.
//   macOS:   same pnet path — bpf under the hood. Needs root.
//   Windows: WinDivert (kernel WFP callout) — bundled .sys + .dll, no
//            third-party download. Needs the SCM service installed (one UAC
//            prompt for life). HVCI must be disabled.
//
// On the wire we send TCP SYN packets directly. Open ports respond with
// SYN/ACK, closed with RST, filtered/no-route with nothing. RX matches
// replies to scan-id by checking dst-port (our randomized source port) and
// SipHash(src,dst,dport,secret) cookie in the seq → ack-1.

use siphasher::sip::SipHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Notify};

use crate::portscan::types::{PortState, ScanResult};

#[derive(Debug, Clone, Copy)]
enum RxState {
    Open,
    Closed,
}

fn seq_cookie(src: Ipv4Addr, dst: Ipv4Addr, dport: u16, secret: u64) -> u32 {
    let mut h = SipHasher::new_with_keys(secret, !secret);
    src.octets().hash(&mut h);
    dst.octets().hash(&mut h);
    dport.hash(&mut h);
    h.finish() as u32
}

pub fn source_ip_for(target: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect(SocketAddrV4::new(target, 80))?;
    match s.local_addr()?.ip() {
        IpAddr::V4(v) => Ok(v),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("expected IPv4 source, got {}", other),
        )),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SynCaps {
    pub available: bool,
}

pub fn check_capability() -> Result<SynCaps, String> {
    #[cfg(target_os = "linux")]
    {
        match caps::has_cap(None, caps::CapSet::Effective, caps::Capability::CAP_NET_RAW) {
            Ok(true) => Ok(SynCaps { available: true }),
            _ => Err("CAP_NET_RAW missing. Grant via:\n\
                 sudo setcap cap_net_raw,cap_net_admin=+eip <wondersuite-binary>\n\
                 …or re-run with sudo."
                .into()),
        }
    }
    #[cfg(target_os = "macos")]
    {
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            Ok(SynCaps { available: true })
        } else {
            Err("SYN scan on macOS requires root. Restart with: sudo ./WonderSuite".into())
        }
    }
    #[cfg(target_os = "windows")]
    {
        let status = crate::portscan::windriver::detect_status();
        if status.service_running {
            Ok(SynCaps { available: true })
        } else if status.hvci_enabled {
            Err("Memory Integrity (HVCI) is enabled — third-party network drivers cannot load. Falling back to TCP connect. Disable Core Isolation → Memory Integrity in Windows Security to enable raw SYN.".into())
        } else {
            Err("WonderSuite network driver is not running. Click 'Install network driver' to deploy the bundled WinDivert driver (one UAC prompt).".into())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err("SYN scan only supported on Linux, macOS, Windows".into())
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_syn_scan(
    targets: Vec<(String, IpAddr)>,
    ports: Vec<u16>,
    timing: Arc<crate::portscan::timing::AdaptiveTiming>,
    cancel: Arc<Notify>,
    result_tx: mpsc::Sender<ScanResult>,
    progress_tick: Arc<dyn Fn() + Send + Sync>,
) {
    let total_targets = targets.len();
    let v4_targets: Vec<(String, Ipv4Addr)> = targets
        .into_iter()
        .filter_map(|(h, ip)| match ip {
            IpAddr::V4(v) => Some((h, v)),
            _ => None,
        })
        .collect();
    if v4_targets.is_empty() {
        return;
    }

    // Dual-stack hostnames resolve to both A and AAAA records. The orchestrator
    // computes total_probes = targets.len() × ports.len(), but the v0.3.7 SYN
    // engine is IPv4-only. Pre-tick the counter for the skipped IPv6 entries
    // so the progress bar reaches 100% on dual-stack scans (and doesn't stall
    // at 50% on a host like scanme.nmap.org).
    let skipped_targets = total_targets.saturating_sub(v4_targets.len());
    let skipped_probes = skipped_targets * ports.len();
    for _ in 0..skipped_probes {
        progress_tick();
    }

    let cancelled = Arc::new(AtomicBool::new(false));
    {
        let flag = cancelled.clone();
        let notify = cancel.clone();
        tokio::spawn(async move {
            notify.notified().await;
            flag.store(true, Ordering::Relaxed);
        });
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix_syn_scan(v4_targets, ports, timing, cancelled, result_tx, progress_tick).await;
    }
    #[cfg(target_os = "windows")]
    {
        windows_syn_scan(v4_targets, ports, timing, cancelled, result_tx, progress_tick).await;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (v4_targets, ports, timing, cancelled, result_tx, progress_tick);
    }
}

// ── Unix (Linux + macOS) ────────────────────────────────────────────────

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn unix_syn_scan(
    v4_targets: Vec<(String, Ipv4Addr)>,
    ports: Vec<u16>,
    timing: Arc<crate::portscan::timing::AdaptiveTiming>,
    cancelled: Arc<AtomicBool>,
    result_tx: mpsc::Sender<ScanResult>,
    progress_tick: Arc<dyn Fn() + Send + Sync>,
) {
    use pnet_packet::ip::IpNextHeaderProtocols;
    use pnet_packet::ipv4::{checksum as ipv4_csum, Ipv4Flags, MutableIpv4Packet};
    use pnet_packet::tcp::{ipv4_checksum as tcp4_csum, MutableTcpPacket, TcpFlags};
    use pnet_packet::Packet;
    use pnet_transport::{tcp_packet_iter, transport_channel, TransportChannelType, TransportProtocol};

    if check_capability().is_err() {
        return;
    }

    let secret: u64 = rand::random();
    let src_port: u16 = 40000 + (rand::random::<u16>() % 20000);

    let chan_type = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut tx_chan, mut rx_chan) = match transport_channel(65536, chan_type) {
        Ok(c) => c,
        Err(_) => return,
    };

    let (rx_tx, mut rx_rx) = mpsc::channel::<(Ipv4Addr, u16, RxState)>(2048);
    let rx_cancel = cancelled.clone();
    std::thread::spawn(move || {
        let mut iter = tcp_packet_iter(&mut rx_chan);
        // Dedup duplicate SYN/ACK retransmits from the target.
        let mut seen: std::collections::HashSet<(Ipv4Addr, u16)> =
            std::collections::HashSet::with_capacity(1024);
        while !rx_cancel.load(Ordering::Relaxed) {
            match iter.next_with_timeout(Duration::from_millis(200)) {
                Ok(Some((tcp, src))) => {
                    let IpAddr::V4(src_v4) = src else { continue };
                    if tcp.get_destination() != src_port {
                        continue;
                    }
                    let our_src = match source_ip_for(src_v4) {
                        Ok(x) => x,
                        Err(_) => continue,
                    };
                    let want = seq_cookie(our_src, src_v4, tcp.get_source(), secret);
                    if tcp.get_acknowledgement().wrapping_sub(1) != want {
                        continue;
                    }
                    let flags = tcp.get_flags();
                    let state = if flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK)
                    {
                        RxState::Open
                    } else if flags & TcpFlags::RST != 0 {
                        RxState::Closed
                    } else {
                        continue;
                    };
                    let key = (src_v4, tcp.get_source());
                    if !seen.insert(key) {
                        continue;
                    }
                    let _ = rx_tx.blocking_send((src_v4, tcp.get_source(), state));
                }
                _ => continue,
            }
        }
    });

    let result_tx_rx = result_tx.clone();
    let rx_cancel2 = cancelled.clone();
    tokio::spawn(async move {
        while let Some((ip, port, st)) = rx_rx.recv().await {
            if rx_cancel2.load(Ordering::Relaxed) {
                break;
            }
            let state = match st {
                RxState::Open => PortState::Open,
                RxState::Closed => PortState::Closed,
            };
            let r = ScanResult {
                host: ip.to_string(),
                ip: IpAddr::V4(ip),
                port,
                proto: "tcp".into(),
                state,
                service: None,
                rtt_ms: 0,
                ts: now_ts(),
            };
            let _ = result_tx_rx.send(r).await;
        }
    });

    let mut buf = [0u8; 40];
    let mut sent = 0usize;
    'outer: for (_host, dst) in &v4_targets {
        let src_v4 = match source_ip_for(*dst) {
            Ok(x) => x,
            Err(_) => continue,
        };
        for &port in &ports {
            if cancelled.load(Ordering::Relaxed) {
                break 'outer;
            }
            let permit = match timing.permits.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break 'outer,
            };
            drop(permit);

            buf.fill(0);
            {
                let mut ip = MutableIpv4Packet::new(&mut buf[..20]).unwrap();
                ip.set_version(4);
                ip.set_header_length(5);
                ip.set_total_length(40);
                ip.set_ttl(64);
                ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                ip.set_source(src_v4);
                ip.set_destination(*dst);
                ip.set_identification(rand::random());
                ip.set_flags(Ipv4Flags::DontFragment);
                let c = ipv4_csum(&ip.to_immutable());
                ip.set_checksum(c);
            }
            {
                let mut tcp = MutableTcpPacket::new(&mut buf[20..]).unwrap();
                tcp.set_source(src_port);
                tcp.set_destination(port);
                tcp.set_sequence(seq_cookie(src_v4, *dst, port, secret));
                tcp.set_data_offset(5);
                tcp.set_flags(TcpFlags::SYN);
                tcp.set_window(1024);
                let c = tcp4_csum(&tcp.to_immutable(), &src_v4, dst);
                tcp.set_checksum(c);
            }
            let pkt = pnet_packet::ipv4::Ipv4Packet::new(&buf).unwrap();
            let _ = tx_chan.send_to(pkt, IpAddr::V4(*dst));
            sent += 1;
            progress_tick();
            if sent % 64 == 0 {
                tokio::task::yield_now().await;
            }
        }
    }

    let drain = timing.template.defaults().1;
    let until = Instant::now() + Duration::from_millis(drain);
    while Instant::now() < until && !cancelled.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ── Windows (WinDivert via manual libloading FFI) ───────────────────────

#[cfg(target_os = "windows")]
async fn windows_syn_scan(
    v4_targets: Vec<(String, Ipv4Addr)>,
    ports: Vec<u16>,
    timing: Arc<crate::portscan::timing::AdaptiveTiming>,
    cancelled: Arc<AtomicBool>,
    result_tx: mpsc::Sender<ScanResult>,
    progress_tick: Arc<dyn Fn() + Send + Sync>,
) {
    use pnet_packet::ip::IpNextHeaderProtocols;
    use pnet_packet::ipv4::{checksum as ipv4_csum, Ipv4Flags, MutableIpv4Packet};
    use pnet_packet::tcp::{ipv4_checksum as tcp4_csum, MutableTcpPacket, TcpFlags};
    use pnet_packet::Packet;

    if check_capability().is_err() {
        return;
    }

    // Locate WinDivert.dll inside our Tauri resource_dir. The DLL ships
    // unmodified in the installer under resources/drivers/windivert/.
    let dll_path = match crate::portscan::windriver::find_bundled_dll() {
        Some(p) => p,
        None => {
            eprintln!("[syn-windows] WinDivert.dll not found in resource_dir");
            return;
        }
    };
    let api = match crate::portscan::windivert_ffi::WinDivertApi::load(&dll_path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[syn-windows] load WinDivert.dll: {}", e);
            return;
        }
    };
    let api = std::sync::Arc::new(api);

    let first_target = v4_targets[0].1;
    let src_v4 = match source_ip_for(first_target) {
        Ok(v) => v,
        Err(_) => return,
    };

    let secret: u64 = rand::random();
    let src_port: u16 = 40000 + (rand::random::<u16>() % 20000);

    // RX handle: sniff-mode (don't actually divert packets — the kernel
    // still needs them). Filter to our scan-id's destination port + relevant
    // TCP flags. Lifetime: keep the Handle pointer alive in this task.
    let rx_filter =
        format!("inbound and ip and tcp and tcp.DstPort == {} and (tcp.Syn or tcp.Rst)", src_port);
    let rx_handle = match api.open_handle(
        &rx_filter,
        crate::portscan::windivert_ffi::LAYER_NETWORK,
        0,
        crate::portscan::windivert_ffi::FLAG_SNIFF | crate::portscan::windivert_ffi::FLAG_RECV_ONLY,
    ) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[syn-windows] RX open: {}", e);
            return;
        }
    };

    let (rx_tx, mut rx_rx) = mpsc::channel::<(Ipv4Addr, u16, RxState)>(2048);
    let rx_cancel = cancelled.clone();
    let rx_api = api.clone();
    // Raw HANDLE (*mut c_void) is !Send. Smuggle it as usize across the
    // thread boundary; convert back on the other side. Safe because the
    // RX thread is the sole owner of the handle for its lifetime.
    let rx_handle_usize = rx_handle as usize;
    std::thread::spawn(move || {
        let rx_handle = rx_handle_usize as crate::portscan::windivert_ffi::Handle;
        let mut buf = vec![0u8; 65535];
        let mut addr = crate::portscan::windivert_ffi::Address::default();
        let mut recv_len: u32 = 0;
        // Dedup: target TCP stacks retransmit SYN/ACK 3-5× when our SYN goes
        // unacked (we send raw SYN, kernel doesn't track state → no ACK back).
        // Without dedup the same port appears multiple times in results.
        let mut seen: std::collections::HashSet<(Ipv4Addr, u16)> =
            std::collections::HashSet::with_capacity(1024);
        while !rx_cancel.load(Ordering::Relaxed) {
            let ok = unsafe {
                (rx_api.recv)(
                    rx_handle,
                    buf.as_mut_ptr() as *mut _,
                    buf.len() as u32,
                    &mut recv_len,
                    &mut addr,
                )
            };
            if ok == 0 {
                continue;
            }
            let data = &buf[..recv_len as usize];
            if data.len() < 20 + 20 {
                continue;
            }
            let ip = match pnet_packet::ipv4::Ipv4Packet::new(data) {
                Some(i) => i,
                None => continue,
            };
            if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                continue;
            }
            let tcp = match pnet_packet::tcp::TcpPacket::new(ip.payload()) {
                Some(t) => t,
                None => continue,
            };
            if tcp.get_destination() != src_port {
                continue;
            }
            let src = ip.get_source();
            let want = seq_cookie(src_v4, src, tcp.get_source(), secret);
            if tcp.get_acknowledgement().wrapping_sub(1) != want {
                continue;
            }
            let flags = tcp.get_flags();
            let state = if flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                RxState::Open
            } else if flags & TcpFlags::RST != 0 {
                RxState::Closed
            } else {
                continue;
            };
            let key = (src, tcp.get_source());
            if !seen.insert(key) {
                continue; // already emitted this (ip, port) — likely a retransmit
            }
            let _ = rx_tx.blocking_send((src, tcp.get_source(), state));
        }
        // RX thread done — close the handle.
        unsafe { (rx_api.close)(rx_handle) };
    });

    let result_tx_rx = result_tx.clone();
    let rx_cancel2 = cancelled.clone();
    tokio::spawn(async move {
        while let Some((ip, port, st)) = rx_rx.recv().await {
            if rx_cancel2.load(Ordering::Relaxed) {
                break;
            }
            let state = match st {
                RxState::Open => PortState::Open,
                RxState::Closed => PortState::Closed,
            };
            let r = ScanResult {
                host: ip.to_string(),
                ip: IpAddr::V4(ip),
                port,
                proto: "tcp".into(),
                state,
                service: None,
                rtt_ms: 0,
                ts: now_ts(),
            };
            let _ = result_tx_rx.send(r).await;
        }
    });

    // TX handle: send-only, filter "false" (we never want to capture, only inject).
    // Smuggle the !Send pointer as usize so the surrounding async future stays Send.
    let tx_handle_usize = match api.open_handle(
        "false",
        crate::portscan::windivert_ffi::LAYER_NETWORK,
        0,
        crate::portscan::windivert_ffi::FLAG_SEND_ONLY,
    ) {
        Ok(h) => h as usize,
        Err(e) => {
            eprintln!("[syn-windows] TX open: {}", e);
            return;
        }
    };

    let mut buf = [0u8; 40];
    let mut sent = 0usize;
    'outer: for (_host, dst) in &v4_targets {
        for &port in &ports {
            if cancelled.load(Ordering::Relaxed) {
                break 'outer;
            }
            let permit = match timing.permits.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break 'outer,
            };
            drop(permit);

            buf.fill(0);
            {
                let mut ip = MutableIpv4Packet::new(&mut buf[..20]).unwrap();
                ip.set_version(4);
                ip.set_header_length(5);
                ip.set_total_length(40);
                ip.set_ttl(64);
                ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                ip.set_source(src_v4);
                ip.set_destination(*dst);
                ip.set_identification(rand::random());
                ip.set_flags(Ipv4Flags::DontFragment);
                let c = ipv4_csum(&ip.to_immutable());
                ip.set_checksum(c);
            }
            {
                let mut tcp = MutableTcpPacket::new(&mut buf[20..]).unwrap();
                tcp.set_source(src_port);
                tcp.set_destination(port);
                tcp.set_sequence(seq_cookie(src_v4, *dst, port, secret));
                tcp.set_data_offset(5);
                tcp.set_flags(TcpFlags::SYN);
                tcp.set_window(1024);
                let c = tcp4_csum(&tcp.to_immutable(), &src_v4, dst);
                tcp.set_checksum(c);
            }

            let addr = crate::portscan::windivert_ffi::Address::outbound_network_tcp();
            let mut send_len: u32 = 0;
            let tx_handle = tx_handle_usize as crate::portscan::windivert_ffi::Handle;
            unsafe {
                (api.send)(tx_handle, buf.as_ptr() as *const _, buf.len() as u32, &mut send_len, &addr);
            }
            sent += 1;
            progress_tick();
            if sent % 64 == 0 {
                tokio::task::yield_now().await;
            }
        }
    }

    let drain = timing.template.defaults().1;
    let until = Instant::now() + Duration::from_millis(drain);
    while Instant::now() < until && !cancelled.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let tx_handle = tx_handle_usize as crate::portscan::windivert_ffi::Handle;
    unsafe { (api.close)(tx_handle) };
}

fn now_ts() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
