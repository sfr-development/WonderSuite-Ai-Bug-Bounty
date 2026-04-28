// ═══════════════════════════════════════════════════════════════════════
//  MCP HTTP Client Factory — Eliminates duplicated reqwest client builds
// ═══════════════════════════════════════════════════════════════════════

/// Configuration for building HTTP clients
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub timeout_ms: u64,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub user_agent: Option<String>,
    pub proxy: Option<String>,
    pub accept_invalid_certs: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 15000,
            follow_redirects: true,
            max_redirects: 10,
            user_agent: None,
            proxy: None,
            accept_invalid_certs: true,
        }
    }
}

impl ClientConfig {
    /// No-redirect client for security testing (detecting 302s, etc.)
    pub fn no_redirect() -> Self {
        Self {
            follow_redirects: false,
            ..Default::default()
        }
    }

    /// Fast client with short timeout for scanning
    pub fn scanner(timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            follow_redirects: false,
            ..Default::default()
        }
    }

    /// Client with custom timeout
    pub fn with_timeout(timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            ..Default::default()
        }
    }
}

/// Factory for building reqwest HTTP clients with common configurations.
/// Eliminates the pattern of building `reqwest::Client::builder().danger_accept_invalid_certs(true)...`
/// that was duplicated 20+ times across handler code.
pub struct HttpClientFactory;

impl HttpClientFactory {
    /// Build a pentest-grade HTTP client from config
    pub fn build(config: &ClientConfig) -> Result<reqwest::Client, String> {
        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(config.accept_invalid_certs)
            .timeout(std::time::Duration::from_millis(config.timeout_ms));

        if config.follow_redirects {
            builder = builder.redirect(reqwest::redirect::Policy::limited(config.max_redirects));
        } else {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }

        if let Some(ref ua) = config.user_agent {
            builder = builder.user_agent(ua);
        }

        if let Some(ref proxy_url) = config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url).map_err(|e| format!("Invalid proxy URL: {}", e))?;
            builder = builder.proxy(proxy);
        }

        builder.build().map_err(|e| e.to_string())
    }

    /// Quick default client — accept invalid certs, 15s timeout, follow redirects
    pub fn default_client() -> Result<reqwest::Client, String> {
        Self::build(&ClientConfig::default())
    }

    /// No-redirect client for security testing
    pub fn no_redirect_client() -> Result<reqwest::Client, String> {
        Self::build(&ClientConfig::no_redirect())
    }

    /// Scanner client with custom timeout
    pub fn scanner_client(timeout_ms: u64) -> Result<reqwest::Client, String> {
        Self::build(&ClientConfig::scanner(timeout_ms))
    }

    /// Build the reqwest Method from a string
    pub fn parse_method(method: &str) -> reqwest::Method {
        match method.to_uppercase().as_str() {
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "PATCH" => reqwest::Method::PATCH,
            "HEAD" => reqwest::Method::HEAD,
            "OPTIONS" => reqwest::Method::OPTIONS,
            _ => reqwest::Method::GET,
        }
    }
}
