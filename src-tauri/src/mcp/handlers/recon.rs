use crate::mcp::types::HandlerResult;
use std::sync::Arc;

pub async fn handle_crawl_target(params: &serde_json::Value) -> HandlerResult {
    let target = params["target"].as_str().ok_or("Missing target URL")?;
    let max_depth = params["max_depth"].as_u64().unwrap_or(5) as usize;
    let max_pages = params["max_pages"].as_u64().unwrap_or(200) as usize;
    let do_extract_forms = params["extract_forms"].as_bool().unwrap_or(true);
    let extract_comments = params["extract_comments"].as_bool().unwrap_or(true);
    let extract_emails = params["extract_emails"].as_bool().unwrap_or(true);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(std::time::Duration::from_millis(params["timeout_ms"].as_u64().unwrap_or(10000)))
        .build()
        .map_err(|e| e.to_string())?;

    let base_url = url::Url::parse(target).map_err(|e| format!("Invalid URL: {}", e))?;
    let base_host = base_url.host_str().unwrap_or("").to_string();

    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<(String, usize)> = std::collections::VecDeque::new();
    let mut found_urls: Vec<serde_json::Value> = Vec::new();
    let mut found_forms: Vec<serde_json::Value> = Vec::new();
    let mut found_scripts: Vec<String> = Vec::new();
    let mut found_comments: Vec<String> = Vec::new();
    let mut found_emails: Vec<String> = Vec::new();
    let mut found_api_endpoints: Vec<String> = Vec::new();

    queue.push_back((target.to_string(), 0));

    while let Some((current_url, depth)) = queue.pop_front() {
        if visited.len() >= max_pages || depth > max_depth {
            break;
        }
        if visited.contains(&current_url) {
            continue;
        }
        visited.insert(current_url.clone());

        let resp = match client.get(&current_url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let status = resp.status().as_u16();
        let content_type =
            resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => continue,
        };

        found_urls.push(serde_json::json!({"url": current_url, "status": status, "depth": depth, "content_type": content_type, "size": body.len()}));
        if !content_type.contains("html") {
            continue;
        }

        let link_re = regex::Regex::new(r#"(?:href|src|action)\s*=\s*["']([^"']+)["']"#).unwrap();
        for cap in link_re.captures_iter(&body) {
            if let Some(m) = cap.get(1) {
                let link = m.as_str();
                let resolved = match url::Url::parse(link) {
                    Ok(u) => u.to_string(),
                    Err(_) => match base_url.join(link) {
                        Ok(u) => u.to_string(),
                        Err(_) => continue,
                    },
                };
                if let Ok(u) = url::Url::parse(&resolved) {
                    if u.host_str().unwrap_or("") == base_host && !visited.contains(&resolved) {
                        queue.push_back((resolved, depth + 1));
                    }
                }
            }
        }

        if do_extract_forms {
            let form_re = regex::Regex::new(r#"<form[^>]*>([\s\S]*?)</form>"#).unwrap();
            let input_re = regex::Regex::new(r#"<input[^>]*name\s*=\s*["']([^"']+)["'][^>]*>"#).unwrap();
            let action_re = regex::Regex::new(r#"action\s*=\s*["']([^"']+)["']"#).unwrap();
            let method_re = regex::Regex::new(r#"method\s*=\s*["']([^"']+)["']"#).unwrap();
            for form_cap in form_re.captures_iter(&body) {
                let form_html = &form_cap[0];
                let form_inner = &form_cap[1];
                let action = action_re
                    .captures(form_html)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                let method = method_re
                    .captures(form_html)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_uppercase())
                    .unwrap_or_else(|| "GET".into());
                let inputs: Vec<String> = input_re
                    .captures_iter(form_inner)
                    .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
                    .collect();
                found_forms.push(serde_json::json!({"page": current_url, "action": action, "method": method, "inputs": inputs}));
            }
        }

        let script_re = regex::Regex::new(r#"<script[^>]*src\s*=\s*["']([^"']+)["']"#).unwrap();
        for cap in script_re.captures_iter(&body) {
            if let Some(m) = cap.get(1) {
                found_scripts.push(m.as_str().to_string());
            }
        }

        if extract_comments {
            let comment_re = regex::Regex::new(r"<!--([\s\S]*?)-->").unwrap();
            for cap in comment_re.captures_iter(&body) {
                let comment = cap[1].trim().to_string();
                if comment.len() > 5 && comment.len() < 500 {
                    found_comments.push(comment);
                }
            }
        }

        if extract_emails {
            let email_re = regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
            for m in email_re.find_iter(&body) {
                let email = m.as_str().to_string();
                if !found_emails.contains(&email) {
                    found_emails.push(email);
                }
            }
        }

        let api_re = regex::Regex::new(r#"["'](/api/[^"']+)["']"#).unwrap();
        for cap in api_re.captures_iter(&body) {
            if let Some(m) = cap.get(1) {
                let ep = m.as_str().to_string();
                if !found_api_endpoints.contains(&ep) {
                    found_api_endpoints.push(ep);
                }
            }
        }
    }

    Ok(serde_json::json!({
        "target": target, "pages_crawled": visited.len(), "urls": found_urls,
        "forms": found_forms, "scripts": found_scripts, "comments": found_comments,
        "emails": found_emails, "api_endpoints": found_api_endpoints, "max_depth_reached": max_depth,
    }))
}

pub async fn handle_discover_subdomains(params: &serde_json::Value) -> HandlerResult {
    let domain = params["domain"].as_str().ok_or("Missing domain")?;
    let wordlist = params["wordlist"].as_str().unwrap_or("medium");
    let use_crt_sh = params["use_crt_sh"].as_bool().unwrap_or(true);
    let check_http = params["check_http"].as_bool().unwrap_or(true);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_millis(params["timeout_ms"].as_u64().unwrap_or(5000)))
        .build()
        .map_err(|e| e.to_string())?;

    let words: Vec<&str> = match wordlist {
        "small" => vec![
            "www", "mail", "ftp", "blog", "dev", "api", "app", "admin", "test", "staging", "cdn", "static",
            "assets", "media", "img", "images", "docs", "portal", "shop", "store", "m", "mobile",
        ],
        "large" => vec![
            "www",
            "mail",
            "ftp",
            "blog",
            "dev",
            "api",
            "app",
            "admin",
            "test",
            "staging",
            "cdn",
            "static",
            "assets",
            "media",
            "img",
            "images",
            "docs",
            "portal",
            "shop",
            "store",
            "m",
            "mobile",
            "beta",
            "alpha",
            "demo",
            "sandbox",
            "internal",
            "vpn",
            "ns1",
            "ns2",
            "ns3",
            "dns",
            "mx",
            "smtp",
            "pop",
            "imap",
            "webmail",
            "owa",
            "exchange",
            "remote",
            "gateway",
            "proxy",
            "cache",
            "lb",
            "loadbalancer",
            "waf",
            "firewall",
            "monitor",
            "grafana",
            "kibana",
            "elastic",
            "jenkins",
            "ci",
            "cd",
            "gitlab",
            "github",
            "bitbucket",
            "jira",
            "confluence",
            "wiki",
            "status",
            "health",
            "backup",
            "bak",
            "old",
            "new",
            "v2",
            "v3",
            "api-v2",
            "graphql",
            "rest",
            "ws",
            "websocket",
            "socket",
            "chat",
            "support",
            "help",
            "helpdesk",
            "ticket",
            "crm",
            "erp",
            "hr",
            "finance",
            "billing",
            "pay",
            "payment",
            "checkout",
            "cart",
            "order",
            "tracking",
            "analytics",
            "stats",
            "dashboard",
            "panel",
            "control",
            "manage",
            "management",
            "console",
            "auth",
            "login",
            "sso",
            "oauth",
            "identity",
            "id",
            "account",
            "accounts",
            "user",
            "users",
            "profile",
            "settings",
            "config",
            "configuration",
            "secure",
            "security",
            "ssl",
            "tls",
            "cert",
            "certificate",
            "key",
            "secret",
            "token",
            "vault",
            "redis",
            "mongo",
            "mysql",
            "postgres",
            "db",
            "database",
            "sql",
            "elasticsearch",
            "kafka",
            "rabbitmq",
            "queue",
            "worker",
            "cron",
            "scheduler",
            "task",
            "job",
            "batch",
            "lambda",
            "function",
            "s3",
            "storage",
            "upload",
            "download",
            "file",
            "files",
            "asset",
            "resource",
        ],
        _ => vec![
            "www",
            "mail",
            "ftp",
            "blog",
            "dev",
            "api",
            "app",
            "admin",
            "test",
            "staging",
            "cdn",
            "static",
            "assets",
            "media",
            "img",
            "images",
            "docs",
            "portal",
            "shop",
            "store",
            "m",
            "mobile",
            "beta",
            "alpha",
            "demo",
            "sandbox",
            "internal",
            "vpn",
            "ns1",
            "ns2",
            "dns",
            "mx",
            "smtp",
            "webmail",
            "remote",
            "gateway",
            "jenkins",
            "gitlab",
            "jira",
            "wiki",
            "status",
            "backup",
            "v2",
            "graphql",
            "ws",
            "chat",
            "support",
            "crm",
            "auth",
            "login",
            "sso",
            "dashboard",
            "panel",
            "console",
            "db",
            "redis",
            "s3",
            "upload",
        ],
    };

    let mut found_subdomains: Vec<serde_json::Value> = Vec::new();
    let domain_ips: Vec<String> = match tokio::net::lookup_host(format!("{}:80", domain)).await {
        Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
        Err(_) => vec![],
    };

    for word in words.iter().take(200) {
        let subdomain = format!("{}.{}", word, domain);
        if let Ok(addrs) = tokio::net::lookup_host(format!("{}:80", subdomain)).await {
            let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            let mut entry =
                serde_json::json!({"subdomain": subdomain, "ips": ips, "source": "dns_bruteforce"});
            if check_http {
                for scheme in &["https", "http"] {
                    let url = format!("{}://{}", scheme, subdomain);
                    if let Ok(resp) = client.get(&url).send().await {
                        entry["http_status"] = serde_json::json!(resp.status().as_u16());
                        entry["http_url"] = serde_json::json!(url);
                        let server = resp.headers().get("server").and_then(|v| v.to_str().ok()).unwrap_or("");
                        if !server.is_empty() {
                            entry["server"] = serde_json::json!(server);
                        }
                        break;
                    }
                }
            }
            found_subdomains.push(entry);
        }
    }

    let mut crt_sh_results: Vec<String> = Vec::new();
    if use_crt_sh {
        let crt_url = format!("https://crt.sh/?q=%.{}&output=json", domain);
        if let Ok(resp) = client.get(&crt_url).send().await {
            if let Ok(text) = resp.text().await {
                if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                    for entry in entries.iter().take(100) {
                        if let Some(name) = entry["name_value"].as_str() {
                            for line in name.lines() {
                                let clean = line.trim().replace("*.", "");
                                if clean.ends_with(domain) && !crt_sh_results.contains(&clean) {
                                    crt_sh_results.push(clean.clone());
                                    if !found_subdomains
                                        .iter()
                                        .any(|s| s["subdomain"].as_str() == Some(&clean))
                                    {
                                        found_subdomains.push(
                                            serde_json::json!({"subdomain": clean, "source": "crt.sh"}),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(
        serde_json::json!({"domain": domain, "total_found": found_subdomains.len(), "subdomains": found_subdomains, "domain_ips": domain_ips, "crt_sh_count": crt_sh_results.len()}),
    )
}

pub async fn handle_discover_content(params: &serde_json::Value) -> HandlerResult {
    let target = params["target"].as_str().ok_or("Missing target")?;
    let wordlist = params["wordlist"].as_str().unwrap_or("common");
    let follow_redirects = params["follow_redirects"].as_bool().unwrap_or(false);
    let max_concurrent = params["max_concurrent"].as_u64().unwrap_or(20) as usize;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(if follow_redirects {
            reqwest::redirect::Policy::limited(3)
        } else {
            reqwest::redirect::Policy::none()
        })
        .timeout(std::time::Duration::from_millis(params["timeout_ms"].as_u64().unwrap_or(5000)))
        .build()
        .map_err(|e| e.to_string())?;

    let words: Vec<&str> = match wordlist {
        "admin" => vec![
            "admin",
            "administrator",
            "admin-panel",
            "cpanel",
            "wp-admin",
            "phpmyadmin",
            "adminer",
            "manager",
            "control",
            "controlpanel",
            "webadmin",
            "sysadmin",
            "root",
            "superadmin",
            "moderator",
            "dashboard",
            "backend",
            "backoffice",
            "cms",
            "panel",
            "console",
            "manage",
            "management",
        ],
        "api" => vec![
            "api",
            "api/v1",
            "api/v2",
            "api/v3",
            "graphql",
            "rest",
            "swagger",
            "openapi",
            "api-docs",
            "doc",
            "docs",
            "documentation",
            "api/swagger",
            "api/health",
            "api/status",
            "api/config",
            "api/users",
            "api/auth",
            "api/login",
            "api/admin",
            "api/search",
            "api/upload",
            "api/download",
        ],
        "backup" => vec![
            ".env",
            "config.php",
            "config.bak",
            "wp-config.php",
            "database.yml",
            "config.yml",
            "secrets.yml",
            ".git/HEAD",
            ".svn/entries",
            ".DS_Store",
            "web.config",
            "robots.txt",
            "sitemap.xml",
            "crossdomain.xml",
            ".htaccess",
            ".htpasswd",
            "backup.zip",
            "backup.tar.gz",
            "dump.sql",
            "db.sql",
            "data.sql",
            "config.json",
            "package.json",
            ".npmrc",
            ".env.local",
            ".env.production",
            ".env.backup",
            ".env.old",
        ],
        "medium" => vec![
            "admin",
            "login",
            "api",
            "dashboard",
            "config",
            "backup",
            "test",
            "dev",
            "staging",
            "uploads",
            "images",
            "assets",
            "static",
            "js",
            "css",
            "fonts",
            "media",
            "files",
            "tmp",
            "temp",
            "cache",
            "log",
            "logs",
            "data",
            "db",
            "database",
            "sql",
            "download",
            "upload",
            "private",
            "secret",
            "hidden",
            "internal",
            "debug",
            "info",
            "status",
            "health",
            "version",
            "env",
            "setup",
            "install",
            "update",
            "migrate",
            "cron",
            "task",
            "queue",
            "worker",
            "webhook",
            "callback",
            "redirect",
            "return",
            "error",
            "404",
            "500",
            "maintenance",
            "beta",
            "alpha",
            "old",
            "new",
            "v1",
            "v2",
            "v3",
            "search",
            "user",
            "users",
            "profile",
            "account",
            "accounts",
            "settings",
            "preferences",
            "notification",
            "notifications",
            "message",
            "messages",
            "chat",
            "support",
            "help",
            "faq",
            "about",
            "contact",
            "terms",
            "privacy",
            "sitemap",
            "robots.txt",
            ".well-known",
            "xmlrpc.php",
            "wp-login.php",
            "wp-json",
        ],
        _ => vec![
            "admin",
            "login",
            "api",
            "dashboard",
            "config",
            "backup",
            "test",
            "dev",
            "uploads",
            "images",
            "assets",
            "js",
            "css",
            "media",
            "files",
            "tmp",
            "cache",
            "log",
            "data",
            "db",
            "download",
            "upload",
            "private",
            "secret",
            "debug",
            "status",
            "health",
            "env",
            "setup",
            "install",
            "search",
            "user",
            "users",
            "profile",
            "account",
            "settings",
            "robots.txt",
            ".well-known",
            "sitemap.xml",
            ".env",
            ".git/HEAD",
            "wp-admin",
            "wp-login.php",
            "wp-json",
            "phpmyadmin",
            "console",
            "panel",
            "swagger",
            "api-docs",
            "graphql",
        ],
    };

    let extensions: Vec<String> = params["extensions"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_else(|| vec!["".to_string()]);

    let base = target.trim_end_matches('/');
    let mut urls_to_check: Vec<String> = Vec::new();
    for word in words.iter() {
        for ext in &extensions {
            if ext.is_empty() {
                urls_to_check.push(format!("{}/{}", base, word));
            } else {
                urls_to_check.push(format!("{}/{}.{}", base, word, ext));
            }
        }
    }

    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
    let client = Arc::new(client);
    let mut handles = Vec::new();
    for url in urls_to_check.iter().take(2000) {
        let sem = semaphore.clone();
        let client = client.clone();
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await;
            match client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let size = resp.content_length().unwrap_or(0);
                    let server =
                        resp.headers().get("server").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                    let ct = resp
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let location = resp
                        .headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    Some((url, status, size, server, ct, location))
                }
                Err(_) => None,
            }
        }));
    }

    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut checked = 0usize;
    for handle in handles {
        if let Ok(Some((url, status, size, server, ct, location))) = handle.await {
            checked += 1;
            if status != 404 {
                let mut entry =
                    serde_json::json!({"url": url, "status": status, "size": size, "content_type": ct});
                if !server.is_empty() {
                    entry["server"] = serde_json::json!(server);
                }
                if !location.is_empty() {
                    entry["redirect"] = serde_json::json!(location);
                }
                results.push(entry);
            }
        }
    }
    results.sort_by(|a, b| a["status"].as_u64().cmp(&b["status"].as_u64()));
    Ok(
        serde_json::json!({"target": target, "urls_checked": checked, "results_found": results.len(), "results": results}),
    )
}

pub async fn handle_find_secrets(params: &serde_json::Value) -> HandlerResult {
    let text = if let Some(t) = params["text"].as_str() {
        t.to_string()
    } else if let Some(target) = params["target"].as_str() {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| e.to_string())?;
        client.get(target).send().await.map_err(|e| e.to_string())?.text().await.map_err(|e| e.to_string())?
    } else {
        return Err("Provide either 'text' or 'target'".into());
    };

    let secret_patterns = vec![
        ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
        ("aws_secret_key", r#"(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]"#),
        ("github_token", r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        ("google_api_key", r"AIza[0-9A-Za-z_-]{35}"),
        ("slack_token", r"xox[bpors]-[0-9]{10,13}-[0-9a-zA-Z]{10,}"),
        ("jwt_token", r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+"),
        ("private_key", r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        (
            "api_key_generic",
            r#"(?i)(?:api[_-]?key|apikey|api_secret|access_token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,})["']?"#,
        ),
        ("password_field", r#"(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*["']([^"']{4,})["']"#),
        (
            "database_url",
            r#"(?i)(?:postgres|mysql|mongodb|redis)://[^\s'"]+#),
        ("internal_ip", r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
        ("internal_url", r#"(?i)(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|internal\.|staging\.|dev\.)[^\s'"]*"#,
        ),
        ("email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        ("bearer_token", r"(?i)bearer\s+[A-Za-z0-9._~+/-]+=*"),
        ("stripe_key", r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}"),
        ("sendgrid_key", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        ("twilio_key", r"SK[0-9a-fA-F]{32}"),
        (
            "heroku_key",
            r"(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        ),
    ];

    let mut found_secrets: Vec<serde_json::Value> = Vec::new();
    for (name, pattern) in &secret_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            for m in re.find_iter(&text) {
                let value = m.as_str();
                let display =
                    if value.len() > 100 { format!("{}...", &value[..100]) } else { value.to_string() };
                found_secrets.push(serde_json::json!({
                    "type": name, "value": display, "position": m.start(),
                    "severity": match *name {
                        "aws_access_key" | "aws_secret_key" | "private_key" | "database_url" | "password_field" => "critical",
                        "github_token" | "stripe_key" | "jwt_token" | "bearer_token" => "high",
                        "api_key_generic" | "google_api_key" | "slack_token" => "medium",
                        "internal_url" | "internal_ip" | "email" => "low",
                        _ => "info"
                    }
                }));
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
    found_secrets.sort_by(|a, b| {
        severity_order(a["severity"].as_str().unwrap_or("info"))
            .cmp(&severity_order(b["severity"].as_str().unwrap_or("info")))
    });
    Ok(
        serde_json::json!({"total_secrets_found": found_secrets.len(), "secrets": found_secrets, "text_length": text.len()}),
    )
}

pub async fn handle_dns_resolve(params: &serde_json::Value) -> HandlerResult {
    let domain = params["domain"].as_str().ok_or("Missing domain")?;
    let mut results = Vec::new();
    match tokio::net::lookup_host(format!("{}:443", domain)).await {
        Ok(addrs) => {
            for addr in addrs {
                let ip = addr.ip();
                results.push(serde_json::json!({"type": if ip.is_ipv4() { "A" } else { "AAAA" }, "value": ip.to_string(), "port": addr.port()}));
            }
        }
        Err(e) => {
            results.push(serde_json::json!({"error": format!("DNS lookup failed: {}", e)}));
        }
    }
    let ips: Vec<String> =
        results.iter().filter_map(|r| r["value"].as_str().map(|s| s.to_string())).collect();
    let mut cdn_indicators = Vec::new();
    for ip in &ips {
        if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
            if let std::net::IpAddr::V4(v4) = addr {
                let octets = v4.octets();
                if [13, 52, 54, 99, 143, 204].contains(&octets[0]) {
                    cdn_indicators.push(format!("{} → likely CloudFront", ip));
                }
                if octets[0] == 104 || (octets[0] == 172 && (64..=71).contains(&octets[1])) {
                    cdn_indicators.push(format!("{} → likely Cloudflare", ip));
                }
                if octets[0] == 23 || octets[0] == 2 {
                    cdn_indicators.push(format!("{} → possibly Akamai", ip));
                }
            }
        }
    }
    let mut origin_hints = Vec::new();
    for prefix in &["origin", "direct", "backend", "real", "internal", "origin-www", "app"] {
        if let Ok(addrs) = tokio::net::lookup_host(format!("{}.{}:443", prefix, domain)).await {
            let sub_ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            if !sub_ips.is_empty() {
                origin_hints
                    .push(serde_json::json!({"subdomain": format!("{}.{}", prefix, domain), "ips": sub_ips}));
            }
        }
    }
    Ok(
        serde_json::json!({"domain": domain, "records": results, "unique_ips": ips, "cdn_indicators": cdn_indicators, "origin_subdomain_hints": origin_hints, "tip": "Use raw_tcp_send with Host header override to test direct-to-origin bypassing CDN edge"}),
    )
}
