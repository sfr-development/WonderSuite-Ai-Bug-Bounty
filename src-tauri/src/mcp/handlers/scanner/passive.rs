// ═══════════════════════════════════════════════════════════════════════
//  Passive Scanner — 30+ security checks without extra requests
//  Analyzes: security headers, cookies, CORS, info disclosure
// ═══════════════════════════════════════════════════════════════════════

use super::{Finding, next_finding_id};
use crate::mcp::types::HandlerResult;
use std::collections::HashMap;

// ─── MCP Handler ───────────────────────────────────────────────────

pub async fn handle_passive_scan(params: &serde_json::Value) -> HandlerResult {
    let target = params["target"].as_str()
        .ok_or("target URL is required")?;

    let check_filter: Vec<String> = params["checks"].as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_else(|| vec!["all".into()]);

    let check_all = check_filter.contains(&"all".into());

    // Fetch the target
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WonderSuite/1.0")
        .build()
        .map_err(|e| format!("Client error: {}", e))?;

    let start = std::time::Instant::now();
    let response = client.get(target).send().await
        .map_err(|e| format!("Request failed: {}", e))?;

    let status = response.status().as_u16();
    let headers: HashMap<String, String> = response.headers().iter()
        .map(|(k, v)| (k.as_str().to_lowercase(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let response_time = start.elapsed().as_millis() as u64;
    let body = response.text().await.unwrap_or_default();

    let mut findings: Vec<Finding> = Vec::new();

    // ─── Security Header Checks ────────────────────────────────────
    if check_all || check_filter.contains(&"headers".into()) {
        check_missing_header(&headers, "content-security-policy", "Content-Security-Policy",
            "medium", "Prevents XSS by controlling resource loading",
            "Add Content-Security-Policy header with strict policy", target, &mut findings);

        check_missing_header(&headers, "strict-transport-security", "Strict-Transport-Security (HSTS)",
            "medium", "Forces HTTPS connections, prevents downgrade attacks",
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains", target, &mut findings);

        check_missing_header(&headers, "x-frame-options", "X-Frame-Options",
            "medium", "Prevents clickjacking by controlling iframe embedding",
            "Add X-Frame-Options: DENY or SAMEORIGIN", target, &mut findings);

        check_missing_header(&headers, "x-content-type-options", "X-Content-Type-Options",
            "low", "Prevents MIME-type sniffing attacks",
            "Add X-Content-Type-Options: nosniff", target, &mut findings);

        check_missing_header(&headers, "referrer-policy", "Referrer-Policy",
            "low", "Controls information in the Referer header",
            "Add Referrer-Policy: strict-origin-when-cross-origin", target, &mut findings);

        check_missing_header(&headers, "permissions-policy", "Permissions-Policy",
            "info", "Restricts browser features (camera, geolocation, etc.)",
            "Add Permissions-Policy header to restrict unnecessary features", target, &mut findings);

        check_missing_header(&headers, "cross-origin-opener-policy", "Cross-Origin-Opener-Policy",
            "low", "Isolates the browsing context from cross-origin popups",
            "Add Cross-Origin-Opener-Policy: same-origin", target, &mut findings);

        // Server version disclosure
        if let Some(server) = headers.get("server") {
            if server.contains('/') || server.chars().any(|c| c.is_ascii_digit()) {
                findings.push(Finding {
                    id: next_finding_id(),
                    finding_type: "server_disclosure".into(),
                    name: "Server Version Disclosure".into(),
                    severity: "low".into(),
                    confidence: "certain".into(),
                    url: target.into(),
                    parameter: None,
                    payload: None,
                    evidence: format!("Server: {}", server),
                    detail: "The Server header reveals software version information that could help attackers identify known vulnerabilities.".into(),
                    remediation: "Remove or genericize the Server header value.".into(),
                    request_info: None,
                });
            }
        }

        // X-Powered-By disclosure
        if let Some(powered) = headers.get("x-powered-by") {
            findings.push(Finding {
                id: next_finding_id(),
                finding_type: "technology_disclosure".into(),
                name: "X-Powered-By Disclosure".into(),
                severity: "low".into(),
                confidence: "certain".into(),
                url: target.into(),
                parameter: None,
                payload: None,
                evidence: format!("X-Powered-By: {}", powered),
                detail: "The X-Powered-By header reveals the backend technology stack.".into(),
                remediation: "Remove the X-Powered-By header.".into(),
                request_info: None,
            });
        }

        // X-AspNet-Version
        for hdr_name in &["x-aspnet-version", "x-aspnetmvc-version"] {
            if let Some(val) = headers.get(*hdr_name) {
                findings.push(Finding {
                    id: next_finding_id(),
                    finding_type: "technology_disclosure".into(),
                    name: format!("{} Disclosure", hdr_name),
                    severity: "low".into(),
                    confidence: "certain".into(),
                    url: target.into(),
                    parameter: None, payload: None,
                    evidence: format!("{}: {}", hdr_name, val),
                    detail: "ASP.NET version header reveals framework version.".into(),
                    remediation: "Remove version disclosure headers in web.config.".into(),
                    request_info: None,
                });
            }
        }
    }

    // ─── Cookie Checks ─────────────────────────────────────────────
    if check_all || check_filter.contains(&"cookies".into()) {
        for (key, val) in &headers {
            if key.as_str() == "set-cookie" {
                check_cookie_flags(val, target, &mut findings);
            }
        }
    }

    // ─── CORS Checks ───────────────────────────────────────────────
    if check_all || check_filter.contains(&"cors".into()) {
        // Test with arbitrary origin
        let cors_result = client.get(target)
            .header("Origin", "https://evil-attacker.com")
            .send().await;
        
        if let Ok(cors_resp) = cors_result {
            let cors_headers: HashMap<String, String> = cors_resp.headers().iter()
                .map(|(k, v)| (k.as_str().to_lowercase(), v.to_str().unwrap_or("").to_string()))
                .collect();

            if let Some(acao) = cors_headers.get("access-control-allow-origin") {
                if acao == "https://evil-attacker.com" || acao.contains("evil-attacker") {
                    let allows_creds = cors_headers.get("access-control-allow-credentials")
                        .map(|v| v == "true").unwrap_or(false);
                    
                    findings.push(Finding {
                        id: next_finding_id(),
                        finding_type: "cors_misconfiguration".into(),
                        name: if allows_creds { "CORS: Arbitrary Origin with Credentials" } else { "CORS: Reflects Arbitrary Origin" }.into(),
                        severity: if allows_creds { "critical" } else { "high" }.into(),
                        confidence: "certain".into(),
                        url: target.into(),
                        parameter: None, payload: None,
                        evidence: format!("Access-Control-Allow-Origin: {}\nAccess-Control-Allow-Credentials: {}",
                            acao, allows_creds),
                        detail: if allows_creds {
                            "The server reflects any Origin header and allows credentials. An attacker can steal authenticated data cross-origin.".into()
                        } else {
                            "The server reflects any Origin header. This may allow cross-origin data theft.".into()
                        },
                        remediation: "Use a strict whitelist for Access-Control-Allow-Origin. Never reflect arbitrary origins.".into(),
                        request_info: None,
                    });
                } else if acao == "*" {
                    let allows_creds = cors_headers.get("access-control-allow-credentials")
                        .map(|v| v == "true").unwrap_or(false);
                    if allows_creds {
                        findings.push(Finding {
                            id: next_finding_id(),
                            finding_type: "cors_misconfiguration".into(),
                            name: "CORS: Wildcard with Credentials".into(),
                            severity: "high".into(),
                            confidence: "certain".into(),
                            url: target.into(),
                            parameter: None, payload: None,
                            evidence: "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true".into(),
                            detail: "Wildcard origin with credentials is a dangerous misconfiguration.".into(),
                            remediation: "Remove Access-Control-Allow-Credentials or use specific origins.".into(),
                            request_info: None,
                        });
                    }
                }
            }

            // Test null origin
            if let Ok(null_resp) = client.get(target).header("Origin", "null").send().await {
                if let Some(acao) = null_resp.headers().get("access-control-allow-origin") {
                    if acao.to_str().unwrap_or("") == "null" {
                        findings.push(Finding {
                            id: next_finding_id(),
                            finding_type: "cors_misconfiguration".into(),
                            name: "CORS: Allows Null Origin".into(),
                            severity: "medium".into(),
                            confidence: "certain".into(),
                            url: target.into(),
                            parameter: None, payload: None,
                            evidence: "Access-Control-Allow-Origin: null".into(),
                            detail: "The server allows the 'null' origin, which can be exploited via sandboxed iframes.".into(),
                            remediation: "Do not allow the null origin.".into(),
                            request_info: None,
                        });
                    }
                }
            }
        }
    }

    // ─── Information Disclosure Checks ──────────────────────────────
    if check_all || check_filter.contains(&"info_disclosure".into()) {
        // Internal IPs
        let ip_re = regex::Regex::new(r"(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+").unwrap();
        for cap in ip_re.find_iter(&body) {
            findings.push(Finding {
                id: next_finding_id(),
                finding_type: "internal_ip".into(),
                name: "Internal IP Address Disclosure".into(),
                severity: "medium".into(),
                confidence: "firm".into(),
                url: target.into(),
                parameter: None, payload: None,
                evidence: format!("Found: {}", cap.as_str()),
                detail: "Internal IP addresses were found in the response, potentially revealing network infrastructure.".into(),
                remediation: "Remove internal IP addresses from responses.".into(),
                request_info: None,
            });
            break; // Only report once
        }

        // Email addresses
        let email_re = regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
        let emails: Vec<String> = email_re.find_iter(&body).map(|m| m.as_str().to_string()).collect();
        if !emails.is_empty() {
            findings.push(Finding {
                id: next_finding_id(),
                finding_type: "email_disclosure".into(),
                name: "Email Address Disclosure".into(),
                severity: "info".into(),
                confidence: "certain".into(),
                url: target.into(),
                parameter: None, payload: None,
                evidence: format!("Found {} emails: {}", emails.len(), emails[..emails.len().min(5)].join(", ")),
                detail: "Email addresses found in the response could be used for social engineering.".into(),
                remediation: "Remove unnecessary email addresses from responses.".into(),
                request_info: None,
            });
        }

        // Stack traces
        let stack_patterns = [
            "Traceback (most recent",
            "at java.", "at sun.", "at org.apache",
            "Exception in thread",
            "Microsoft.AspNetCore",
            "System.NullReferenceException",
            "PHP Fatal error",
            "Parse error: syntax error",
            "Warning: mysql_", "Warning: pg_",
            "SQLSTATE[",
        ];
        for pattern in &stack_patterns {
            if body.contains(pattern) {
                findings.push(Finding {
                    id: next_finding_id(),
                    finding_type: "stack_trace".into(),
                    name: "Stack Trace / Error Message Disclosure".into(),
                    severity: "high".into(),
                    confidence: "certain".into(),
                    url: target.into(),
                    parameter: None, payload: None,
                    evidence: format!("Pattern found: {}", pattern),
                    detail: "Detailed error messages or stack traces reveal implementation details and can aid exploitation.".into(),
                    remediation: "Implement custom error pages. Disable verbose error reporting in production.".into(),
                    request_info: None,
                });
                break;
            }
        }

        // SQL error patterns (indicates misconfiguration, not necessarily injection)
        let sql_errors = [
            "You have an error in your SQL syntax",
            "mysql_fetch_array()", "pg_query()",
            "ORA-", "SQLITE_ERROR",
            "Unclosed quotation mark",
        ];
        for pattern in &sql_errors {
            if body.contains(pattern) {
                findings.push(Finding {
                    id: next_finding_id(),
                    finding_type: "sql_error".into(),
                    name: "SQL Error in Response".into(),
                    severity: "high".into(),
                    confidence: "certain".into(),
                    url: target.into(),
                    parameter: None, payload: None,
                    evidence: format!("Pattern found: {}", pattern),
                    detail: "SQL error messages in the response may indicate injection vulnerabilities or misconfiguration.".into(),
                    remediation: "Use parameterized queries. Hide database errors from users.".into(),
                    request_info: None,
                });
                break;
            }
        }
    }

    // ─── Build response ────────────────────────────────────────────

    let mut severity_counts: HashMap<String, usize> = HashMap::new();
    for f in &findings {
        *severity_counts.entry(f.severity.clone()).or_insert(0) += 1;
    }

    // Sort by severity
    let sev_order = |s: &str| -> u8 {
        match s { "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4 }
    };
    findings.sort_by(|a, b| sev_order(&a.severity).cmp(&sev_order(&b.severity)));

    Ok(serde_json::json!({
        "target": target,
        "status": status,
        "response_time_ms": response_time,
        "pages_analyzed": 1,
        "total_findings": findings.len(),
        "findings_by_severity": severity_counts,
        "findings": findings,
        "checks_performed": if check_all { vec!["headers", "cookies", "cors", "info_disclosure"] } else { check_filter.iter().map(|s| s.as_str()).collect() },
    }))
}

// ─── Helper Functions ──────────────────────────────────────────────

fn check_missing_header(
    headers: &HashMap<String, String>,
    header_name: &str,
    display_name: &str,
    severity: &str,
    detail: &str,
    remediation: &str,
    target: &str,
    findings: &mut Vec<Finding>,
) {
    if !headers.contains_key(header_name) {
        findings.push(Finding {
            id: next_finding_id(),
            finding_type: format!("missing_{}", header_name.replace('-', "_")),
            name: format!("Missing {}", display_name),
            severity: severity.into(),
            confidence: "certain".into(),
            url: target.into(),
            parameter: None,
            payload: None,
            evidence: format!("Header '{}' not present in response", display_name),
            detail: detail.into(),
            remediation: remediation.into(),
            request_info: None,
        });
    }
}

fn check_cookie_flags(set_cookie: &str, target: &str, findings: &mut Vec<Finding>) {
    let cookie_lower = set_cookie.to_lowercase();
    let cookie_name = set_cookie.split('=').next().unwrap_or("unknown").trim();
    
    if !cookie_lower.contains("httponly") {
        findings.push(Finding {
            id: next_finding_id(),
            finding_type: "cookie_no_httponly".into(),
            name: format!("Cookie '{}' Missing HttpOnly Flag", cookie_name),
            severity: "medium".into(),
            confidence: "certain".into(),
            url: target.into(),
            parameter: Some(cookie_name.into()),
            payload: None,
            evidence: format!("Set-Cookie: {}", &set_cookie[..set_cookie.len().min(100)]),
            detail: "Without HttpOnly, JavaScript can access this cookie, enabling XSS-based session theft.".into(),
            remediation: "Add the HttpOnly flag to this cookie.".into(),
            request_info: None,
        });
    }

    if !cookie_lower.contains("secure") && target.starts_with("https") {
        findings.push(Finding {
            id: next_finding_id(),
            finding_type: "cookie_no_secure".into(),
            name: format!("Cookie '{}' Missing Secure Flag", cookie_name),
            severity: "medium".into(),
            confidence: "certain".into(),
            url: target.into(),
            parameter: Some(cookie_name.into()),
            payload: None,
            evidence: format!("Set-Cookie: {}", &set_cookie[..set_cookie.len().min(100)]),
            detail: "Without Secure, this cookie can be transmitted over unencrypted HTTP.".into(),
            remediation: "Add the Secure flag to this cookie.".into(),
            request_info: None,
        });
    }

    if !cookie_lower.contains("samesite") {
        findings.push(Finding {
            id: next_finding_id(),
            finding_type: "cookie_no_samesite".into(),
            name: format!("Cookie '{}' Missing SameSite Attribute", cookie_name),
            severity: "medium".into(),
            confidence: "certain".into(),
            url: target.into(),
            parameter: Some(cookie_name.into()),
            payload: None,
            evidence: format!("Set-Cookie: {}", &set_cookie[..set_cookie.len().min(100)]),
            detail: "Without SameSite, this cookie may be sent with cross-site requests (CSRF risk).".into(),
            remediation: "Add SameSite=Lax or SameSite=Strict to this cookie.".into(),
            request_info: None,
        });
    }
}
