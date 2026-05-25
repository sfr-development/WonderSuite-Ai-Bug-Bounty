// TLS / HTTP/2 fingerprint impersonation for the proxy's upstream requests.
//
// The MITM proxy decrypts the browser's TLS, inspects/modifies the request,
// then RE-ORIGINATES the request to the target. That re-origination uses
// Rust's TLS stack (native-tls/SChannel on Windows by default), which has
// a wildly different JA3/JA4 + HTTP/2 SETTINGS frame ordering than Chrome's.
// Cloudflare/Akamai/DataDome catch this immediately.
//
// This module wraps wreq (a reqwest-compatible client built on BoringSSL +
// h2 with browser-fingerprint profiles) to make the upstream connection look
// EXACTLY like Chrome 137, including:
//   - JA3 (TLS extension order, cipher list, supported_groups, sig algs)
//   - JA4 (newer fingerprint variant Cloudflare uses)
//   - HTTP/2 SETTINGS frame ordering + HEADERS/PRIORITY frame sequence
//   - ALPN ordering (h2 first, then http/1.1)
//   - X25519 / kyber key share preferences
//   - GREASE extensions in the right slots
//   - ECH (Encrypted Client Hello) when the target advertises it
//
// Build deps: pulls boring-sys2 which compiles BoringSSL from source.
// Requires: cmake, NASM, perl, libclang.dll. Documented in README.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use wreq::tls::CertStore;
use wreq::{redirect::Policy as WreqPolicy, Client as WreqClient, Proxy as WreqProxy};
use wreq_util::Emulation;

// Mozilla's full WebPKI root bundle, baked in at compile time. boring-sys2 has
// no platform-native trust-store loader, so without this every upstream HTTPS
// request fails with CERTIFICATE_VERIFY_FAILED. We build the CertStore once
// and share a static reference across every (re)built wreq Client.
static MOZILLA_ROOTS: std::sync::OnceLock<CertStore> = std::sync::OnceLock::new();

fn mozilla_root_store() -> &'static CertStore {
    MOZILLA_ROOTS.get_or_init(|| {
        CertStore::from_der_certs(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter())
            .expect("webpki-root-certs DER bundle is malformed (should be impossible)")
    })
}

/// Which browser to mimic. Chrome 137 is the most-recent Chrome profile that
/// wreq-util 2.x ships; our bundled Chromium is 148. JA3/JA4 shape between
/// 137 and 148 is near-identical (no major TLS extension changes in that
/// range), so this is still strong enough to defeat Cloudflare/Akamai.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpersonateProfile {
    Chrome137,
    Chrome131,
    Firefox133,
}

impl Default for ImpersonateProfile {
    fn default() -> Self {
        ImpersonateProfile::Chrome137
    }
}

impl ImpersonateProfile {
    pub fn to_emulation(self) -> Emulation {
        match self {
            ImpersonateProfile::Chrome137 => Emulation::Chrome137,
            ImpersonateProfile::Chrome131 => Emulation::Chrome131,
            ImpersonateProfile::Firefox133 => Emulation::Firefox133,
        }
    }
}

/// Upstream proxy configuration for the impersonate client. Mirrors the
/// existing `UpstreamProxyConfig` but without the runtime-poll baggage so
/// we can decide proxy use once at build time.
#[derive(Debug, Clone)]
pub struct ImpersonateUpstreamProxy {
    pub scheme: String, // "http" | "https" | "socks5"
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Holds the wreq client and tracks the currently-active config so we know
/// when to rebuild on a config change.
#[derive(Clone)]
pub struct ImpersonateClient {
    inner: Arc<RwLock<ClientCell>>,
}

#[derive(Clone)]
struct ClientCell {
    client: WreqClient,
    profile: ImpersonateProfile,
    upstream: Option<ImpersonateUpstreamProxy>,
}

impl ImpersonateClient {
    pub fn new(profile: ImpersonateProfile) -> Result<Self, String> {
        let client = build_client(profile, None)?;
        Ok(Self { inner: Arc::new(RwLock::new(ClientCell { client, profile, upstream: None })) })
    }

    /// Switch profile. Rebuilds the client only if the profile actually
    /// changes (cheap no-op otherwise).
    pub async fn set_profile(&self, profile: ImpersonateProfile) -> Result<(), String> {
        let mut g = self.inner.write().await;
        if g.profile == profile {
            return Ok(());
        }
        let client = build_client(profile, g.upstream.clone())?;
        g.client = client;
        g.profile = profile;
        Ok(())
    }

    /// Set (or clear) the upstream proxy used by the impersonate client.
    /// Rebuilds the underlying wreq Client. Idempotent on identical configs.
    pub async fn set_upstream(&self, upstream: Option<ImpersonateUpstreamProxy>) -> Result<(), String> {
        let mut g = self.inner.write().await;
        if upstream_eq(&g.upstream, &upstream) {
            return Ok(());
        }
        let client = build_client(g.profile, upstream.clone())?;
        g.client = client;
        g.upstream = upstream;
        Ok(())
    }

    pub async fn client(&self) -> WreqClient {
        self.inner.read().await.client.clone()
    }

    pub async fn profile(&self) -> ImpersonateProfile {
        self.inner.read().await.profile
    }
}

fn upstream_eq(a: &Option<ImpersonateUpstreamProxy>, b: &Option<ImpersonateUpstreamProxy>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => {
            x.scheme == y.scheme
                && x.host == y.host
                && x.port == y.port
                && x.username == y.username
                && x.password == y.password
        }
        _ => false,
    }
}

fn build_client(
    profile: ImpersonateProfile,
    upstream: Option<ImpersonateUpstreamProxy>,
) -> Result<WreqClient, String> {
    let mut builder = WreqClient::builder()
        .emulation(profile.to_emulation())
        // We're a proxy: follow redirects manually so the browser sees them.
        .redirect(WreqPolicy::none())
        // Connection pool — short-lived so we don't reuse a stale H2 socket
        // that the server GOAWAY-ed in the meantime. Cloudflare/Akamai send
        // GOAWAY at ~10-20s of idle; wreq has no `http2_keep_alive_*` PING
        // knobs (verified against wreq 5.x ClientBuilder), so the only
        // mitigation is to evict idle conns *before* they can go stale.
        // 5s is well under the typical CDN idle-GOAWAY threshold.
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(Duration::from_secs(5))
        // Built-in wreq retry on transient h2 errors (REFUSED_STREAM,
        // PROTOCOL_ERROR after GOAWAY). With a fresh pool eviction policy
        // this rarely fires, but it's the last line of defence and costs
        // nothing on the happy path.
        .http2_max_retry_count(2)
        // TCP-level keep-alive — helps detect dead intermediaries (NAT
        // timeouts, load-balancer session-table expiry) before we try to
        // reuse the socket and get hit with a RST/PROTOCOL_ERROR.
        .tcp_keepalive(Duration::from_secs(15))
        .tcp_keepalive_interval(Duration::from_secs(5))
        .tcp_keepalive_retries(3u32)
        .timeout(Duration::from_secs(60))
        // Fail fast on connect so a single dead host doesn't stall the proxy.
        .connect_timeout(Duration::from_secs(10))
        .tcp_nodelay(true)
        // CRITICAL: explicit no_proxy() so wreq does NOT pick up Windows
        // system proxy settings. Without it, wreq would route through the
        // user's configured Windows proxy (which is OUR own listener while
        // WonderBrowser is open) and loop on itself.
        .no_proxy()
        // Bundle Mozilla's WebPKI root CAs so BoringSSL can validate upstream
        // certs without the OS trust store. Same trust anchors Firefox uses.
        .cert_store(mozilla_root_store())
        // Pentest-tool semantics — DISABLE upstream cert validation. We're
        // an intercepting proxy: the user expects to be able to MITM any
        // target including self-signed certs, expired certs, hostname/SAN
        // mismatches, and direct IP-address connections (where the upstream
        // cert is for a domain, never the IP literal). Burp Suite, mitmproxy,
        // and Caido all do this by default. The reqwest fallback path
        // (engine.rs build_default_client) already does
        // `.danger_accept_invalid_certs(true)`; this aligns the wreq path.
        // Validating CAs on browser→proxy is still done by the user's OS
        // trust store via our local CA — only the proxy→origin hop is
        // affected here.
        .cert_verification(false);

    if let Some(up) = upstream {
        let url = match (&up.username, &up.password) {
            (Some(u), Some(p)) => format!(
                "{}://{}:{}@{}:{}",
                up.scheme,
                urlencoding::encode(u),
                urlencoding::encode(p),
                up.host,
                up.port
            ),
            _ => format!("{}://{}:{}", up.scheme, up.host, up.port),
        };
        let proxy = WreqProxy::all(&url).map_err(|e| format!("wreq proxy parse '{}': {}", url, e))?;
        builder = builder.proxy(proxy);
    }

    builder.build().map_err(|e| format!("wreq client build failed: {}", e))
}
