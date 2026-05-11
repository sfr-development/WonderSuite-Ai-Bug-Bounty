use crate::mcp::types::HandlerResult;

pub async fn handle_crtsh_search(params: &serde_json::Value) -> HandlerResult {
    let domain = params["domain"].as_str().ok_or("Missing domain")?;
    let include_expired = params["include_expired"].as_bool().unwrap_or(false);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let resp = client.get(&url).send().await.map_err(|e| format!("crt.sh request failed: {}", e))?;
    let status = resp.status().as_u16();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if status != 200 {
        return Ok(serde_json::json!({"error": format!("crt.sh returned status {}", status)}));
    }
    let certs: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap_or_default();
    let mut subdomains = std::collections::BTreeSet::new();
    let mut cert_details = Vec::new();
    let now = chrono::Utc::now();
    for cert in &certs {
        let name_value = cert["name_value"].as_str().unwrap_or("");
        let not_after = cert["not_after"].as_str().unwrap_or("");
        if !include_expired {
            if let Ok(expiry) = chrono::NaiveDateTime::parse_from_str(not_after, "%Y-%m-%dT%H:%M:%S") {
                if expiry < now.naive_utc() {
                    continue;
                }
            }
        }
        for name in name_value.split('\n') {
            let name = name.trim().to_lowercase();
            if name.contains(&format!(".{}", domain.to_lowercase())) || name == domain.to_lowercase() {
                subdomains.insert(name.replace("*.", ""));
            }
        }
        if cert_details.len() < 20 {
            cert_details.push(serde_json::json!({"common_name": cert["common_name"], "name_value": name_value, "issuer": cert["issuer_name"], "not_before": cert["not_before"], "not_after": not_after}));
        }
    }
    let subdomain_list: Vec<String> = subdomains.into_iter().collect();
    Ok(
        serde_json::json!({"domain": domain, "subdomains": subdomain_list, "subdomain_count": subdomain_list.len(), "certificates_sampled": cert_details, "total_certificates": certs.len(), "source": "crt.sh (Certificate Transparency)"}),
    )
}

pub async fn handle_wayback_lookup(params: &serde_json::Value) -> HandlerResult {
    let domain = params["domain"].as_str().ok_or("Missing domain")?;
    let match_type = params["match_type"].as_str().unwrap_or("domain");
    let limit = params["limit"].as_u64().unwrap_or(500) as usize;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!("https://web.archive.org/cdx/search/cdx?url={}/*&matchType={}&output=json&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit={}", domain, match_type, limit);
    let resp = client.get(&url).send().await.map_err(|e| format!("Wayback Machine request failed: {}", e))?;
    let body = resp.text().await.map_err(|e| e.to_string())?;
    let rows: Vec<Vec<String>> = serde_json::from_str(&body).unwrap_or_default();
    let data_rows: Vec<&Vec<String>> = rows.iter().skip(1).collect();
    let interesting_patterns = [
        "/api/",
        "/v1/",
        "/v2/",
        "/graphql",
        "/admin",
        "/debug",
        ".env",
        ".git",
        ".svn",
        "config",
        "backup",
        ".sql",
        ".zip",
        ".bak",
        "swagger",
        "openapi",
        "/internal/",
        "/private/",
        "phpinfo",
        ".log",
        "wp-config",
        "robots.txt",
        "sitemap.xml",
    ];
    let mut all_urls: Vec<serde_json::Value> = Vec::new();
    let mut interesting_urls: Vec<serde_json::Value> = Vec::new();
    for row in &data_rows {
        if row.len() < 4 {
            continue;
        }
        let entry = serde_json::json!({"url": row[1], "timestamp": row[0], "status_code": row[2], "mime_type": row[3]});
        if interesting_patterns.iter().any(|p| row[1].to_lowercase().contains(p)) {
            interesting_urls.push(entry.clone());
        }
        all_urls.push(entry);
    }
    Ok(
        serde_json::json!({"domain": domain, "total_snapshots": data_rows.len(), "interesting_endpoints": interesting_urls, "interesting_count": interesting_urls.len(), "all_urls_sample": &all_urls[..all_urls.len().min(100)], "source": "Wayback Machine"}),
    )
}

pub async fn handle_whois_lookup(params: &serde_json::Value) -> HandlerResult {
    let target = params["target"].as_str().ok_or("Missing target")?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let is_ip = target.parse::<std::net::IpAddr>().is_ok();
    let rdap_url = if is_ip {
        format!("https://rdap.org/ip/{}", target)
    } else {
        format!("https://rdap.org/domain/{}", target)
    };
    let resp = client
        .get(&rdap_url)
        .header("Accept", "application/rdap+json")
        .send()
        .await
        .map_err(|e| format!("RDAP lookup failed: {}", e))?;
    let status = resp.status().as_u16();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    let data: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    if status != 200 {
        return Ok(
            serde_json::json!({"target": target, "error": format!("RDAP returned status {}", status)}),
        );
    }
    let mut result = serde_json::json!({"target": target, "type": if is_ip { "ip" } else { "domain" }, "source": "RDAP (rdap.org)"});
    if is_ip {
        result["name"] = data["name"].clone();
        result["handle"] = data["handle"].clone();
        result["start_address"] = data["startAddress"].clone();
        result["end_address"] = data["endAddress"].clone();
        result["country"] = data["country"].clone();
    } else {
        result["ldhName"] = data["ldhName"].clone();
        result["status"] = data["status"].clone();
        if let Some(ns) = data["nameservers"].as_array() {
            result["nameservers"] = serde_json::json!(ns
                .iter()
                .filter_map(|n| n["ldhName"].as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>());
        }
        if let Some(events) = data["events"].as_array() {
            for event in events {
                let action = event["eventAction"].as_str().unwrap_or("");
                let date = event["eventDate"].as_str().unwrap_or("");
                match action {
                    "registration" => {
                        result["created"] = serde_json::json!(date);
                    }
                    "expiration" => {
                        result["expires"] = serde_json::json!(date);
                    }
                    "last changed" => {
                        result["updated"] = serde_json::json!(date);
                    }
                    _ => {}
                }
            }
        }
        if let Some(entities) = data["entities"].as_array() {
            for entity in entities {
                let roles: Vec<String> = entity["roles"]
                    .as_array()
                    .map(|r| r.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                    .unwrap_or_default();
                if roles.contains(&"registrar".to_string()) {
                    if let Some(vcard) = entity["vcardArray"].as_array().and_then(|v| v.get(1)) {
                        if let Some(arr) = vcard.as_array() {
                            for prop in arr {
                                if prop[0].as_str() == Some("fn") {
                                    result["registrar"] = serde_json::json!(prop[3].as_str().unwrap_or(""));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(result)
}

pub async fn handle_asn_lookup(params: &serde_json::Value) -> HandlerResult {
    let target = params["target"].as_str().ok_or("Missing target")?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    if target.to_uppercase().starts_with("AS") {
        let asn = target.trim_start_matches("AS").trim_start_matches("as");
        let resp = client
            .get(&format!("https://rdap.org/autnum/{}", asn))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let data: serde_json::Value = serde_json::from_str(&resp.text().await.map_err(|e| e.to_string())?)
            .unwrap_or(serde_json::json!({}));
        Ok(
            serde_json::json!({"asn": format!("AS{}", asn), "name": data["name"], "handle": data["handle"], "country": data["country"], "source": "RDAP"}),
        )
    } else {
        let ip: std::net::IpAddr = target.parse().map_err(|_| "Invalid IP address")?;
        let reversed = match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
            }
            _ => return Err("IPv6 ASN lookup not yet supported".into()),
        };
        let dns_url = format!("https://dns.google/resolve?name={}&type=TXT", reversed);
        let resp = client.get(&dns_url).send().await.map_err(|e| e.to_string())?;
        let dns_data: serde_json::Value =
            serde_json::from_str(&resp.text().await.map_err(|e| e.to_string())?)
                .unwrap_or(serde_json::json!({}));
        let mut asn_info = serde_json::json!({"ip": target, "source": "Team Cymru DNS + Google DoH"});
        if let Some(answers) = dns_data["Answer"].as_array() {
            for answer in answers {
                if let Some(data) = answer["data"].as_str() {
                    let data = data.trim_matches('"');
                    let parts: Vec<&str> = data.split('|').map(|s| s.trim()).collect();
                    if parts.len() >= 3 {
                        asn_info["asn"] = serde_json::json!(format!("AS{}", parts[0].trim()));
                        asn_info["prefix"] = serde_json::json!(parts[1].trim());
                        asn_info["country"] = serde_json::json!(parts[2].trim());
                    }
                }
            }
        }
        if let Some(asn) = asn_info["asn"].as_str() {
            let asn_num = asn.trim_start_matches("AS");
            if let Ok(resp) = client.get(&format!("https://rdap.org/autnum/{}", asn_num)).send().await {
                if let Ok(body) = resp.text().await {
                    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&body) {
                        asn_info["org_name"] = data["name"].clone();
                    }
                }
            }
        }
        Ok(asn_info)
    }
}

pub async fn handle_favicon_hash(params: &serde_json::Value) -> HandlerResult {
    let target = params["target"].as_str().ok_or("Missing target")?;
    let favicon_url = if target.starts_with("http") {
        if target.ends_with("/favicon.ico") {
            target.to_string()
        } else {
            format!("{}/favicon.ico", target.trim_end_matches('/'))
        }
    } else {
        format!("https://{}/favicon.ico", target)
    };
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let resp =
        client.get(&favicon_url).send().await.map_err(|e| format!("Failed to fetch favicon: {}", e))?;
    let status = resp.status().as_u16();
    if status != 200 {
        return Ok(
            serde_json::json!({"target": target, "favicon_url": favicon_url, "error": format!("Favicon not found (HTTP {})", status)}),
        );
    }
    let favicon_bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    if favicon_bytes.is_empty() {
        return Ok(serde_json::json!({"target": target, "error": "Empty favicon response"}));
    }
    let b64 = crate::mcp::utils::base64_encode(&favicon_bytes);
    let mut b64_with_newlines = String::new();
    for (i, ch) in b64.chars().enumerate() {
        b64_with_newlines.push(ch);
        if (i + 1) % 76 == 0 {
            b64_with_newlines.push('\n');
        }
    }
    if !b64_with_newlines.ends_with('\n') {
        b64_with_newlines.push('\n');
    }
    let hash = crate::mcp::utils::murmur3_32(b64_with_newlines.as_bytes(), 0) as i32;
    Ok(serde_json::json!({
        "target": target, "favicon_url": favicon_url, "favicon_hash": hash, "favicon_size_bytes": favicon_bytes.len(),
        "search_queries": {"shodan": format!("http.favicon.hash:{}", hash), "fofa": format!("icon_hash=\"{}\"", hash), "zoomeye": format!("iconhash:\"{}\"", hash)},
    }))
}

pub async fn handle_graphql_introspect(params: &serde_json::Value) -> HandlerResult {
    let target = params["target"].as_str().ok_or("Missing target")?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let introspection_query = r#"{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields(includeDeprecated: true) { name description args { name type { name kind } } type { name kind ofType { name kind } } isDeprecated } } } }"}"#;
    let mut req =
        client.post(target).header("Content-Type", "application/json").body(introspection_query.to_string());
    if let Some(headers) = params["headers"].as_object() {
        for (key, val) in headers {
            if let Some(v) = val.as_str() {
                req = req.header(key, v);
            }
        }
    }
    let resp = req.send().await.map_err(|e| format!("GraphQL request failed: {}", e))?;
    let body = resp.text().await.map_err(|e| e.to_string())?;
    let data: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    if data["data"]["__schema"].is_null() {
        return Ok(
            serde_json::json!({"target": target, "introspectable": false, "error": "Introspection disabled"}),
        );
    }
    let schema = &data["data"]["__schema"];
    let types = schema["types"].as_array().unwrap_or(&Vec::new()).clone();
    let query_type_name = schema["queryType"]["name"].as_str().unwrap_or("Query");
    let mutation_type_name = schema["mutationType"]["name"].as_str().unwrap_or("Mutation");
    let mut queries = Vec::new();
    let mut mutations = Vec::new();
    let mut user_types = Vec::new();
    for type_def in &types {
        let name = type_def["name"].as_str().unwrap_or("");
        let kind = type_def["kind"].as_str().unwrap_or("");
        if name.starts_with("__") {
            continue;
        }
        if name == query_type_name {
            if let Some(fields) = type_def["fields"].as_array() {
                for field in fields {
                    queries.push(serde_json::json!({"name": field["name"], "args": field["args"], "return_type": field["type"]["name"]}));
                }
            }
        } else if name == mutation_type_name {
            if let Some(fields) = type_def["fields"].as_array() {
                for field in fields {
                    mutations.push(serde_json::json!({"name": field["name"], "args": field["args"]}));
                }
            }
        } else if kind == "OBJECT" || kind == "INPUT_OBJECT" {
            let fields_summary: Vec<String> = type_def["fields"]
                .as_array()
                .unwrap_or(&Vec::new())
                .iter()
                .take(10)
                .filter_map(|f| f["name"].as_str().map(|s| s.to_string()))
                .collect();
            if !fields_summary.is_empty() {
                user_types.push(serde_json::json!({"name": name, "kind": kind, "fields": fields_summary}));
            }
        }
    }
    Ok(
        serde_json::json!({"target": target, "introspectable": true, "queries": queries, "query_count": queries.len(), "mutations": mutations, "mutation_count": mutations.len(), "types": user_types, "type_count": user_types.len()}),
    )
}

pub async fn handle_js_link_finder(params: &serde_json::Value) -> HandlerResult {
    let target = params["target"].as_str().ok_or("Missing target")?;
    let max_js = params["max_js_files"].as_u64().unwrap_or(20) as usize;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(target).send().await.map_err(|e| format!("Failed to fetch target: {}", e))?;
    let html = resp.text().await.map_err(|e| e.to_string())?;
    let script_re = regex::Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)["']"#).ok();
    let base_url = url::Url::parse(target).ok();
    let js_urls: Vec<String> = script_re
        .map(|re| {
            re.captures_iter(&html)
                .filter_map(|c| {
                    let src = c.get(1)?.as_str();
                    if src.starts_with("http") {
                        return Some(src.to_string());
                    }
                    base_url.as_ref().and_then(|b| b.join(src).ok().map(|u| u.to_string()))
                })
                .take(max_js)
                .collect()
        })
        .unwrap_or_default();
    let mut all_endpoints = std::collections::BTreeSet::new();
    let mut all_secrets = Vec::new();
    let url_re = regex::Regex::new(r#"["']((?:https?://[^\s"'<>]+)|(?:/(?:api|v[0-9]|graphql|admin|internal|private|auth|oauth|user|account|payment|webhook)[^\s"'<>]*))"#).ok();
    let path_re = regex::Regex::new(r#"["'](/[a-zA-Z0-9_\-/.]+(?:\?[^"']*)?)["']"#).ok();
    let secret_re = regex::Regex::new(r#"(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key|password|bearer)\s*[:=]\s*["']([^"']{8,})["']"#).ok();
    for js_url in &js_urls {
        if let Ok(resp) = client.get(js_url).send().await {
            if let Ok(js_body) = resp.text().await {
                if let Some(ref re) = url_re {
                    for cap in re.captures_iter(&js_body) {
                        if let Some(m) = cap.get(1) {
                            all_endpoints.insert(m.as_str().to_string());
                        }
                    }
                }
                if let Some(ref re) = path_re {
                    for cap in re.captures_iter(&js_body) {
                        if let Some(m) = cap.get(1) {
                            let path = m.as_str();
                            if path.len() > 3
                                && !path.ends_with(".js")
                                && !path.ends_with(".css")
                                && !path.ends_with(".png")
                            {
                                all_endpoints.insert(path.to_string());
                            }
                        }
                    }
                }
                if let Some(ref re) = secret_re {
                    for cap in re.captures_iter(&js_body) {
                        if let Some(m) = cap.get(1) {
                            all_secrets.push(serde_json::json!({"value": m.as_str(), "source_file": js_url}));
                        }
                    }
                }
            }
        }
    }
    let endpoints: Vec<String> = all_endpoints.into_iter().collect();
    Ok(
        serde_json::json!({"target": target, "js_files_analyzed": js_urls.len(), "js_files": js_urls, "endpoints": endpoints, "endpoint_count": endpoints.len(), "secrets": all_secrets, "secret_count": all_secrets.len()}),
    )
}

pub async fn handle_reverse_ip_lookup(params: &serde_json::Value) -> HandlerResult {
    let ip = params["ip"].as_str().ok_or("Missing ip")?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let ip_addr: std::net::IpAddr = ip.parse().map_err(|_| "Invalid IP address")?;
    let ptr_name = match ip_addr {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        _ => return Err("IPv6 not yet supported".into()),
    };
    let dns_url = format!("https://dns.google/resolve?name={}&type=PTR", ptr_name);
    let resp = client.get(&dns_url).send().await.map_err(|e| e.to_string())?;
    let dns_data: serde_json::Value =
        serde_json::from_str(&resp.text().await.map_err(|e| e.to_string())?).unwrap_or(serde_json::json!({}));
    let mut hostnames = Vec::new();
    if let Some(answers) = dns_data["Answer"].as_array() {
        for answer in answers {
            if let Some(data) = answer["data"].as_str() {
                hostnames.push(data.trim_end_matches('.').to_string());
            }
        }
    }
    Ok(
        serde_json::json!({"ip": ip, "hostnames": hostnames, "hostname_count": hostnames.len(), "source": "Google DoH PTR lookup"}),
    )
}

pub async fn handle_hackertarget(params: &serde_json::Value) -> HandlerResult {
    let target = params["target"].as_str().ok_or("Missing target (domain or IP)")?;

    let tools_param = params["tools"].as_array();
    let all_tools =
        vec!["hostsearch", "reversedns", "dnslookup", "httpheaders", "pagelinks", "geoip", "aslookup"];
    let tools: Vec<&str> = if let Some(arr) = tools_param {
        arr.iter().filter_map(|v| v.as_str()).collect()
    } else {
        all_tools.clone()
    };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;

    let mut results = serde_json::json!({"target": target, "source": "api.hackertarget.com (no API key)"});
    let mut errors = Vec::new();

    for tool in &tools {
        let url = format!("https://api.hackertarget.com/{}/?q={}", tool, target);
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                if status != 200 || body.starts_with("error") || body.contains("API count exceeded") {
                    errors.push(serde_json::json!({"tool": tool, "error": body.trim().chars().take(200).collect::<String>()}));
                    continue;
                }
                match *tool {
                    "hostsearch" => {
                        let hosts: Vec<serde_json::Value> = body.lines()
                            .filter(|l| !l.is_empty() && l.contains(','))
                            .map(|l| {
                                let parts: Vec<&str> = l.splitn(2, ',').collect();
                                serde_json::json!({"hostname": parts.get(0).unwrap_or(&""), "ip": parts.get(1).unwrap_or(&"")})
                            }).collect();
                        results["hostsearch"] = serde_json::json!({"count": hosts.len(), "hosts": hosts});
                    }
                    "reversedns" => {
                        let records: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
                        results["reversedns"] =
                            serde_json::json!({"count": records.len(), "records": records});
                    }
                    "dnslookup" => {
                        results["dnslookup"] = serde_json::json!({"raw": body.trim()});
                    }
                    "httpheaders" => {
                        let mut headers = serde_json::Map::new();
                        let mut security_issues = Vec::new();
                        let security_headers = [
                            "strict-transport-security",
                            "content-security-policy",
                            "x-frame-options",
                            "x-content-type-options",
                            "x-xss-protection",
                            "referrer-policy",
                            "permissions-policy",
                        ];

                        for line in body.lines() {
                            if let Some(idx) = line.find(':') {
                                let key = line[..idx].trim().to_lowercase();
                                let val = line[idx + 1..].trim().to_string();
                                headers.insert(key.clone(), serde_json::Value::String(val));
                            }
                        }
                        for sh in &security_headers {
                            if !headers.contains_key(*sh) {
                                security_issues.push(format!("Missing: {}", sh));
                            }
                        }
                        let server = headers.get("server").and_then(|v| v.as_str()).unwrap_or("unknown");
                        let powered_by = headers.get("x-powered-by").and_then(|v| v.as_str()).unwrap_or("");
                        results["httpheaders"] = serde_json::json!({
                            "headers": headers,
                            "server": server,
                            "x_powered_by": powered_by,
                            "missing_security_headers": security_issues,
                            "security_score": format!("{}/{}", security_headers.len() - security_issues.len(), security_headers.len()),
                        });
                    }
                    "pagelinks" => {
                        let links: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
                        let internal: Vec<&&str> = links.iter().filter(|l| l.contains(target)).collect();
                        let external: Vec<&&str> =
                            links.iter().filter(|l| !l.contains(target) && l.starts_with("http")).collect();
                        let interesting_patterns = [
                            "/api/", "/v1/", "/v2/", "/admin", "/login", "/auth", "/graphql", ".json",
                            ".xml", "/swagger", "/docs",
                        ];
                        let interesting: Vec<&&str> = links
                            .iter()
                            .filter(|l| interesting_patterns.iter().any(|p| l.to_lowercase().contains(p)))
                            .collect();
                        results["pagelinks"] = serde_json::json!({
                            "total": links.len(),
                            "internal_count": internal.len(),
                            "external_count": external.len(),
                            "interesting": interesting,
                            "interesting_count": interesting.len(),
                            "all_links": links,
                        });
                    }
                    "geoip" => {
                        let mut geo = serde_json::Map::new();
                        for line in body.lines() {
                            if let Some(idx) = line.find(':') {
                                let key = line[..idx].trim().to_lowercase().replace(' ', "_");
                                let val = line[idx + 1..].trim().to_string();
                                geo.insert(key, serde_json::Value::String(val));
                            }
                        }
                        results["geoip"] = serde_json::Value::Object(geo);
                    }
                    "aslookup" => {
                        results["aslookup"] = serde_json::json!({"raw": body.trim()});
                    }
                    _ => {}
                }
            }
            Err(e) => {
                errors.push(serde_json::json!({"tool": tool, "error": e.to_string()}));
            }
        }
    }

    if !errors.is_empty() {
        results["errors"] = serde_json::json!(errors);
    }
    results["tools_executed"] = serde_json::json!(tools);
    Ok(results)
}

pub async fn handle_ip_geolocation(params: &serde_json::Value) -> HandlerResult {
    let ip = params["ip"].as_str().ok_or("Missing ip")?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let mut result = serde_json::json!({"ip": ip});

    let ip_api_url = format!("http://ip-api.com/json/{}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query", ip);
    match client.get(&ip_api_url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.text().await {
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&body) {
                    if data["status"].as_str() == Some("success") {
                        result["country"] = data["country"].clone();
                        result["country_code"] = data["countryCode"].clone();
                        result["region"] = data["regionName"].clone();
                        result["city"] = data["city"].clone();
                        result["zip"] = data["zip"].clone();
                        result["lat"] = data["lat"].clone();
                        result["lon"] = data["lon"].clone();
                        result["timezone"] = data["timezone"].clone();
                        result["isp"] = data["isp"].clone();
                        result["org"] = data["org"].clone();
                        result["as_info"] = data["as"].clone();
                        result["as_name"] = data["asname"].clone();
                        result["reverse_dns"] = data["reverse"].clone();
                        result["is_mobile"] = data["mobile"].clone();
                        result["is_proxy"] = data["proxy"].clone();
                        result["is_hosting"] = data["hosting"].clone();
                    } else {
                        result["ip_api_error"] = data["message"].clone();
                    }
                }
            }
        }
        Err(e) => {
            result["ip_api_error"] = serde_json::json!(e.to_string());
        }
    }

    match client.get(&format!("https://api.country.is/{}", ip)).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.text().await {
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&body) {
                    result["country_is"] = data["country"].clone();
                }
            }
        }
        Err(_) => {}
    }

    result["sources"] = serde_json::json!(["ip-api.com", "country.is"]);
    Ok(result)
}

pub async fn handle_tech_detect(params: &serde_json::Value) -> HandlerResult {
    let target = params["target"].as_str().ok_or("Missing target URL")?;
    let url = if target.starts_with("http") { target.to_string() } else { format!("https://{}", target) };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client.get(&url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
        .send().await.map_err(|e| format!("Request failed: {}", e))?;

    let status = resp.status().as_u16();
    let mut techs = Vec::new();
    let mut headers_map = serde_json::Map::new();

    for (key, val) in resp.headers() {
        let k = key.as_str().to_lowercase();
        let v = val.to_str().unwrap_or("").to_string();
        headers_map.insert(k.clone(), serde_json::Value::String(v.clone()));

        match k.as_str() {
            "server" => {
                techs.push(
                    serde_json::json!({"category": "web_server", "name": v, "source": "server header"}),
                );
            }
            "x-powered-by" => {
                techs.push(
                    serde_json::json!({"category": "framework", "name": v, "source": "x-powered-by header"}),
                );
            }
            "x-aspnet-version" | "x-aspnetmvc-version" => {
                techs.push(serde_json::json!({"category": "framework", "name": format!("ASP.NET {}", v), "source": k}));
            }
            "x-drupal-cache" | "x-drupal-dynamic-cache" => {
                techs.push(serde_json::json!({"category": "cms", "name": "Drupal", "source": k}));
            }
            "x-generator" => {
                techs.push(
                    serde_json::json!({"category": "generator", "name": v, "source": "x-generator header"}),
                );
            }
            "x-shopify-stage" => {
                techs.push(serde_json::json!({"category": "ecommerce", "name": "Shopify", "source": k}));
            }
            "x-amz-cf-id" | "x-amz-cf-pop" => {
                techs.push(serde_json::json!({"category": "cdn", "name": "Amazon CloudFront", "source": k}));
            }
            "cf-ray" => {
                techs.push(
                    serde_json::json!({"category": "cdn", "name": "Cloudflare", "source": "cf-ray header"}),
                );
            }
            "x-cache" => {
                if v.to_lowercase().contains("cloudfront") {
                    techs.push(
                        serde_json::json!({"category": "cdn", "name": "CloudFront", "source": "x-cache"}),
                    );
                } else if v.to_lowercase().contains("varnish") {
                    techs.push(
                        serde_json::json!({"category": "cache", "name": "Varnish", "source": "x-cache"}),
                    );
                }
            }
            "set-cookie" => {
                let v_lower = v.to_lowercase();
                if v_lower.contains("phpsessid") {
                    techs.push(serde_json::json!({"category": "language", "name": "PHP", "source": "PHPSESSID cookie"}));
                }
                if v_lower.contains("jsessionid") {
                    techs.push(serde_json::json!({"category": "language", "name": "Java", "source": "JSESSIONID cookie"}));
                }
                if v_lower.contains("asp.net") || v_lower.contains("aspnet") {
                    techs.push(serde_json::json!({"category": "framework", "name": "ASP.NET", "source": "ASP.NET cookie"}));
                }
                if v_lower.contains("laravel") {
                    techs.push(serde_json::json!({"category": "framework", "name": "Laravel", "source": "laravel_session cookie"}));
                }
                if v_lower.contains("django") || v_lower.contains("csrftoken") {
                    techs.push(serde_json::json!({"category": "framework", "name": "Django", "source": "csrf cookie"}));
                }
                if v_lower.contains("wordpress") || v_lower.contains("wp-settings") {
                    techs.push(
                        serde_json::json!({"category": "cms", "name": "WordPress", "source": "wp cookie"}),
                    );
                }
                if v_lower.contains("connect.sid") {
                    techs.push(serde_json::json!({"category": "framework", "name": "Express.js", "source": "connect.sid cookie"}));
                }
            }
            _ => {}
        }
    }

    let body = resp.text().await.unwrap_or_default();
    let body_lower = body.to_lowercase();

    if let Some(re) =
        regex::Regex::new(r#"(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']"#).ok()
    {
        for cap in re.captures_iter(&body) {
            if let Some(r#gen) = cap.get(1) {
                techs.push(serde_json::json!({"category": "generator", "name": r#gen.as_str(), "source": "meta generator"}));
            }
        }
    }

    let body_sigs: Vec<(&str, &str, &str)> = vec![
        ("wp-content/", "cms", "WordPress"),
        ("wp-includes/", "cms", "WordPress"),
        ("/sites/default/files/", "cms", "Drupal"),
        ("joomla", "cms", "Joomla"),
        ("__next", "framework", "Next.js"),
        ("__nuxt", "framework", "Nuxt.js"),
        ("ng-version", "framework", "Angular"),
        ("data-reactroot", "framework", "React"),
        ("ember-view", "framework", "Ember.js"),
        ("svelte", "framework", "Svelte"),
        ("data-turbo", "framework", "Hotwire/Turbo"),
        ("_gatsby", "framework", "Gatsby"),
        ("window.__remixContext", "framework", "Remix"),
        ("cdn.shopify.com", "ecommerce", "Shopify"),
        ("static.parastorage.com", "website_builder", "Wix"),
        ("squarespace.com", "website_builder", "Squarespace"),
        ("cdn.jsdelivr.net", "cdn", "jsDelivr"),
        ("cdnjs.cloudflare.com", "cdn", "cdnjs"),
        ("unpkg.com", "cdn", "unpkg"),
        ("jquery", "library", "jQuery"),
        ("bootstrap", "library", "Bootstrap"),
        ("tailwindcss", "library", "TailwindCSS"),
        ("font-awesome", "library", "Font Awesome"),
        ("google-analytics.com", "analytics", "Google Analytics"),
        ("googletagmanager.com", "analytics", "Google Tag Manager"),
        ("gtag(", "analytics", "Google Analytics (gtag)"),
        ("hotjar.com", "analytics", "Hotjar"),
        ("segment.com", "analytics", "Segment"),
        ("sentry", "monitoring", "Sentry"),
        ("recaptcha", "security", "reCAPTCHA"),
        ("hcaptcha", "security", "hCaptcha"),
        ("cloudflare", "cdn", "Cloudflare"),
    ];

    let mut seen = std::collections::HashSet::new();
    for (sig, cat, name) in &body_sigs {
        if body_lower.contains(*sig) && seen.insert(*name) {
            techs.push(serde_json::json!({"category": cat, "name": name, "source": format!("body contains '{}'", sig)}));
        }
    }

    let mut unique_techs: Vec<serde_json::Value> = Vec::new();
    let mut tech_names = std::collections::HashSet::new();
    for tech in &techs {
        let name = tech["name"].as_str().unwrap_or("");
        if tech_names.insert(name.to_string()) {
            unique_techs.push(tech.clone());
        }
    }

    Ok(serde_json::json!({
        "target": url,
        "status": status,
        "technologies": unique_techs,
        "technology_count": unique_techs.len(),
        "headers": headers_map,
        "source": "WonderSuite Tech Fingerprint (header + body analysis)"
    }))
}
