use serde::Serialize;
use std::time::Duration;

const UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 WonderSuite/1.0";
const TIMEOUT_LONG: Duration = Duration::from_secs(60);

fn build_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent(UA)
        .timeout(TIMEOUT_LONG)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|e| format!("HTTP client build error: {}", e))
}

fn strip_domain(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_lowercase()
}

#[derive(Serialize)]
pub struct RdapResult {
    pub ok: bool,
    pub server: String,
    pub status: u16,
    pub raw: serde_json::Value,
    pub summary: serde_json::Value,
    pub note: Option<String>,
}

async fn iana_bootstrap_for_tld(client: &reqwest::Client, tld: &str) -> Option<String> {
    let resp = client.get("https://data.iana.org/rdap/dns.json").send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    let services = body.get("services")?.as_array()?;
    for svc in services {
        let arr = svc.as_array()?;
        let tlds = arr.first()?.as_array()?;
        let urls = arr.get(1)?.as_array()?;
        for t in tlds {
            if t.as_str().map(|s| s.eq_ignore_ascii_case(tld)).unwrap_or(false) {
                for u in urls {
                    if let Some(s) = u.as_str() {
                        return Some(s.trim_end_matches('/').to_string());
                    }
                }
            }
        }
    }
    None
}

async fn try_rdap_get(client: &reqwest::Client, url: &str) -> Result<(u16, serde_json::Value), String> {
    let resp = client
        .get(url)
        .header("Accept", "application/rdap+json")
        .send()
        .await
        .map_err(|e| format!("rdap request error: {}", e))?;
    let status = resp.status().as_u16();
    let text = resp.text().await.map_err(|e| format!("rdap read error: {}", e))?;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    Ok((status, json))
}

fn summarize_domain(v: &serde_json::Value) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    if let Some(s) = v.get("ldhName").and_then(|x| x.as_str()) {
        out.insert("domain".into(), serde_json::json!(s));
    }
    if let Some(s) = v.get("status") {
        out.insert("status".into(), s.clone());
    }
    if let Some(events) = v.get("events").and_then(|e| e.as_array()) {
        for ev in events {
            let action = ev.get("eventAction").and_then(|x| x.as_str()).unwrap_or("");
            let date = ev.get("eventDate").and_then(|x| x.as_str()).unwrap_or("");
            match action {
                "registration" => {
                    out.insert("created".into(), serde_json::json!(date));
                }
                "expiration" => {
                    out.insert("expires".into(), serde_json::json!(date));
                }
                "last changed" => {
                    out.insert("updated".into(), serde_json::json!(date));
                }
                _ => {}
            }
        }
    }
    if let Some(ns) = v.get("nameservers").and_then(|n| n.as_array()) {
        let names: Vec<String> = ns
            .iter()
            .filter_map(|n| n.get("ldhName").and_then(|x| x.as_str()).map(|s| s.to_string()))
            .collect();
        out.insert("nameservers".into(), serde_json::json!(names));
    }
    if let Some(entities) = v.get("entities").and_then(|e| e.as_array()) {
        let mut found_entities = Vec::new();
        for ent in entities {
            let roles: Vec<String> = ent
                .get("roles")
                .and_then(|r| r.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            let mut name = String::new();
            let mut org = String::new();
            let mut email = String::new();
            if let Some(vcard) = ent.get("vcardArray").and_then(|v| v.get(1)).and_then(|v| v.as_array()) {
                for prop in vcard {
                    if let Some(arr) = prop.as_array() {
                        let key = arr.first().and_then(|x| x.as_str()).unwrap_or("");
                        let val = arr.get(3).and_then(|x| x.as_str()).unwrap_or("");
                        match key {
                            "fn" => name = val.into(),
                            "org" => org = val.into(),
                            "email" => email = val.into(),
                            _ => {}
                        }
                    }
                }
            }
            found_entities.push(serde_json::json!({
                "roles": roles,
                "name": name,
                "org": org,
                "email": email,
            }));
        }
        out.insert("entities".into(), serde_json::json!(found_entities));
    }
    serde_json::Value::Object(out)
}

fn summarize_ip(v: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "name": v.get("name").cloned().unwrap_or(serde_json::Value::Null),
        "handle": v.get("handle").cloned().unwrap_or(serde_json::Value::Null),
        "start_address": v.get("startAddress").cloned().unwrap_or(serde_json::Value::Null),
        "end_address": v.get("endAddress").cloned().unwrap_or(serde_json::Value::Null),
        "country": v.get("country").cloned().unwrap_or(serde_json::Value::Null),
    })
}

/// Hard-coded RDAP endpoints for ccTLDs not present in IANA's bootstrap.
/// Add new entries here when a user reports a 404 on a TLD that does publish RDAP.
#[allow(non_snake_case)]
fn ccTLD_rdap_server(tld: &str) -> Option<&'static str> {
    match tld.to_ascii_lowercase().as_str() {
        "de" => Some("https://rdap.denic.de"),
        "at" => Some("https://rdap.nic.at"),
        "ch" | "li" => Some("https://rdap.nic.ch"),
        "nl" => Some("https://rdap.sidn.nl"),
        "fr" => Some("https://rdap.nic.fr"),
        "se" => Some("https://rdap.iis.se"),
        "nu" => Some("https://rdap.iis.nu"),
        "dk" => Some("https://rdap.dk-hostmaster.dk"),
        "fi" => Some("https://rdap.fi"),
        "no" => Some("https://rdap.norid.no"),
        "is" => Some("https://rdap.isnic.is"),
        "ee" => Some("https://rdap.tld.ee"),
        "lv" => Some("https://rdap.nic.lv"),
        "lt" => Some("https://rdap.domreg.lt"),
        "pl" => Some("https://rdap.dns.pl"),
        "cz" => Some("https://rdap.nic.cz"),
        "sk" => Some("https://rdap.sk-nic.sk"),
        "hu" => Some("https://rdap.nic.hu"),
        "ro" => Some("https://rdap.rotld.ro"),
        "bg" => Some("https://rdap.register.bg"),
        "es" => Some("https://rdap.nic.es"),
        "pt" => Some("https://rdap.dns.pt"),
        "it" => Some("https://rdap.nic.it"),
        "be" => Some("https://rdap.dnsbelgium.be"),
        "lu" => Some("https://rdap.dns.lu"),
        "ie" => Some("https://rdap.weare.ie"),
        "gr" => Some("https://rdap.ics.forth.gr"),
        "uk" | "co.uk" | "org.uk" => Some("https://rdap.nominet.uk"),
        "us" => Some("https://rdap.nic.us"),
        "ca" => Some("https://rdap.ca.fury.ca"),
        "mx" => Some("https://rdap.mx"),
        "br" => Some("https://rdap.registro.br"),
        "ar" => Some("https://rdap.nic.ar"),
        "co" => Some("https://rdap.nic.co"),
        "cl" => Some("https://rdap.nic.cl"),
        "io" => Some("https://rdap.nic.io"),
        "ai" => Some("https://rdap.nic.ai"),
        "app" | "dev" | "page" => Some("https://rdap.nic.google"),
        _ => None,
    }
}

#[tauri::command]
pub async fn osint_whois(target: String) -> Result<RdapResult, String> {
    let client = build_client()?;
    let is_ip = target.parse::<std::net::IpAddr>().is_ok();
    let cleaned = if is_ip { target.clone() } else { strip_domain(&target) };
    if cleaned.is_empty() {
        return Err("empty target".into());
    }

    let mut candidates: Vec<String> = Vec::new();

    if is_ip {
        candidates.push(format!("https://rdap-bootstrap.arin.net/bootstrap/ip/{}", cleaned));
        candidates.push(format!("https://rdap.arin.net/registry/ip/{}", cleaned));
        candidates.push(format!("https://rdap.db.ripe.net/ip/{}", cleaned));
        candidates.push(format!("https://rdap.apnic.net/ip/{}", cleaned));
        candidates.push(format!("https://rdap.lacnic.net/rdap/ip/{}", cleaned));
        candidates.push(format!("https://rdap.afrinic.net/rdap/ip/{}", cleaned));
    } else {
        let tld = cleaned.rsplit('.').next().unwrap_or("").to_string();
        // Many ccTLDs publish RDAP but never registered with IANA's bootstrap (dns.json
        // doesn't list them). Hard-code the known ones so .de / .at / .nl / etc. work.
        if let Some(server) = ccTLD_rdap_server(&tld) {
            candidates.push(format!("{}/domain/{}", server, cleaned));
        }
        if let Some(server) = iana_bootstrap_for_tld(&client, &tld).await {
            candidates.push(format!("{}/domain/{}", server, cleaned));
        }
        candidates.push(format!("https://rdap-bootstrap.arin.net/bootstrap/domain/{}", cleaned));
        candidates.push(format!("https://rdap.verisign.com/com/v1/domain/{}", cleaned));
    }
    // Last-resort relay (often Cloudflare-blocked but worth one shot for unusual TLDs).
    candidates.push(format!("https://rdap.org/{}/{}", if is_ip { "ip" } else { "domain" }, cleaned));

    let mut last_status: u16 = 0;
    let mut last_server = String::new();
    let mut last_note: Option<String> = None;

    for url in &candidates {
        match try_rdap_get(&client, url).await {
            Ok((status, body)) => {
                last_status = status;
                last_server = url.clone();
                if status == 200 && body != serde_json::Value::Null {
                    let summary = if is_ip { summarize_ip(&body) } else { summarize_domain(&body) };
                    return Ok(RdapResult {
                        ok: true,
                        server: url.clone(),
                        status,
                        raw: body,
                        summary,
                        note: None,
                    });
                }
                if status == 301 || status == 302 || status == 307 || status == 308 {
                    last_note = Some(format!("redirect on {}", url));
                    continue;
                }
                last_note = Some(format!("status {} on {}", status, url));
            }
            Err(e) => {
                last_status = 0;
                last_server = url.clone();
                last_note = Some(e);
            }
        }
    }

    Ok(RdapResult {
        ok: false,
        server: last_server,
        status: last_status,
        raw: serde_json::Value::Null,
        summary: serde_json::json!({"target": cleaned}),
        note: last_note,
    })
}

#[derive(Serialize)]
pub struct CrtEntry {
    pub subdomain: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
}

#[derive(Serialize)]
pub struct CrtResult {
    pub domain: String,
    pub total_certificates: usize,
    pub subdomain_count: usize,
    pub entries: Vec<CrtEntry>,
    pub source: String,
    pub note: Option<String>,
}

#[tauri::command]
pub async fn osint_crtsh(target: String, include_expired: Option<bool>) -> Result<CrtResult, String> {
    let domain = strip_domain(&target);
    if domain.is_empty() {
        return Err("empty domain".into());
    }
    let include_expired = include_expired.unwrap_or(false);

    let client = build_client()?;
    // crt.sh is slow under load; two attempts with a short backoff.
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let mut last_err: Option<String> = None;
    let mut body_str = String::new();
    for attempt in 1..=2 {
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() {
                    last_err = Some(format!("crt.sh returned status {} (attempt {})", status, attempt));
                    continue;
                }
                match resp.text().await {
                    Ok(t) => {
                        body_str = t;
                        last_err = None;
                        break;
                    }
                    Err(e) => last_err = Some(format!("crt.sh read error: {}", e)),
                }
            }
            Err(e) => last_err = Some(format!("crt.sh request error: {}", e)),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    if let Some(e) = &last_err {
        return Ok(CrtResult {
            domain,
            total_certificates: 0,
            subdomain_count: 0,
            entries: vec![],
            source: "crt.sh".into(),
            note: Some(e.clone()),
        });
    }
    let raw_certs: Vec<serde_json::Value> = serde_json::from_str(&body_str).unwrap_or_default();
    let now = chrono::Utc::now();
    let mut seen = std::collections::BTreeMap::<String, CrtEntry>::new();

    for cert in &raw_certs {
        let name_value = cert.get("name_value").and_then(|v| v.as_str()).unwrap_or("");
        let issuer = cert.get("issuer_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let not_before = cert.get("not_before").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let not_after = cert.get("not_after").and_then(|v| v.as_str()).unwrap_or("").to_string();

        if !include_expired {
            if let Ok(expiry) = chrono::NaiveDateTime::parse_from_str(&not_after, "%Y-%m-%dT%H:%M:%S") {
                if expiry < now.naive_utc() {
                    continue;
                }
            }
        }

        for name in name_value.split('\n') {
            let n = name.trim().to_lowercase();
            if n.is_empty() {
                continue;
            }
            let clean = n.trim_start_matches("*.").to_string();
            if clean.contains(&domain) {
                seen.entry(clean.clone()).or_insert(CrtEntry {
                    subdomain: clean,
                    issuer: issuer.clone(),
                    not_before: not_before.clone(),
                    not_after: not_after.clone(),
                });
            }
        }
    }

    let entries: Vec<CrtEntry> = seen.into_values().collect();
    Ok(CrtResult {
        domain,
        total_certificates: raw_certs.len(),
        subdomain_count: entries.len(),
        entries,
        source: "crt.sh".into(),
        note: None,
    })
}
