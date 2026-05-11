use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// WonderSuite Session Handler
/// - Cookie Jar: centralized cookie storage
/// - Macros: recorded request sequences (login, CSRF token fetch)
/// - Session Rules: automated session management

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub httponly: bool,
    pub samesite: Option<String>,
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieJar {
    pub cookies: Vec<Cookie>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self { cookies: Vec::new() }
    }

    pub fn set(&mut self, cookie: Cookie) {
        self.cookies
            .retain(|c| !(c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path));
        self.cookies.push(cookie);
    }

    pub fn get(&self, domain: &str, path: &str) -> Vec<&Cookie> {
        self.cookies
            .iter()
            .filter(|c| (domain.ends_with(&c.domain) || c.domain == domain) && path.starts_with(&c.path))
            .collect()
    }

    pub fn get_header(&self, domain: &str, path: &str) -> Option<String> {
        let cookies = self.get(domain, path);
        if cookies.is_empty() {
            return None;
        }
        Some(cookies.iter().map(|c| format!("{}={}", c.name, c.value)).collect::<Vec<_>>().join("; "))
    }

    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    pub fn remove(&mut self, name: &str, domain: &str) {
        self.cookies.retain(|c| !(c.name == name && c.domain == domain));
    }

    /// Parse Set-Cookie header and add to jar
    pub fn parse_set_cookie(&mut self, header: &str, domain: &str) {
        let parts: Vec<&str> = header.split(';').collect();
        if let Some(main) = parts.first() {
            let kv: Vec<&str> = main.splitn(2, '=').collect();
            if kv.len() == 2 {
                let mut cookie = Cookie {
                    name: kv[0].trim().to_string(),
                    value: kv[1].trim().to_string(),
                    domain: domain.to_string(),
                    path: "/".to_string(),
                    secure: false,
                    httponly: false,
                    samesite: None,
                    expires: None,
                };
                for attr in &parts[1..] {
                    let attr = attr.trim().to_lowercase();
                    if attr == "secure" {
                        cookie.secure = true;
                    } else if attr == "httponly" {
                        cookie.httponly = true;
                    } else if attr.starts_with("path=") {
                        cookie.path = attr[5..].to_string();
                    } else if attr.starts_with("domain=") {
                        cookie.domain = attr[7..].to_string();
                    } else if attr.starts_with("samesite=") {
                        cookie.samesite = Some(attr[9..].to_string());
                    } else if attr.starts_with("expires=") {
                        cookie.expires = Some(attr[8..].to_string());
                    }
                }
                self.set(cookie);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroStep {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub extract: Option<MacroExtract>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroExtract {
    pub name: String,
    pub source: String, // "header", "body", "cookie"
    pub regex: String,
    pub group: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMacro {
    pub id: String,
    pub name: String,
    pub steps: Vec<MacroStep>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub scope: SessionScope,
    pub actions: Vec<SessionAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionScope {
    AllRequests,
    InScope,
    UrlContains(String),
    HostEquals(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionAction {
    UseCookieJar,
    SetCookieValue { name: String, value: String },
    RunMacro { macro_id: String },
    CheckSessionValid { check_string: String, invalid_string: Option<String> },
    AddHeader { name: String, value: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub cookie_jar: CookieJar,
    pub macros: Vec<SessionMacro>,
    pub rules: Vec<SessionRule>,
}

impl SessionState {
    pub fn new() -> Self {
        Self { cookie_jar: CookieJar::new(), macros: Vec::new(), rules: Vec::new() }
    }
}

pub type SessionHandle = Arc<Mutex<SessionState>>;

pub fn create_session_state() -> SessionHandle {
    Arc::new(Mutex::new(SessionState::new()))
}

/// Execute a macro and return extracted values
pub async fn execute_macro(session_macro: &SessionMacro) -> Result<HashMap<String, String>, String> {
    let client =
        reqwest::Client::builder().danger_accept_invalid_certs(true).build().map_err(|e| e.to_string())?;

    let mut extracted: HashMap<String, String> = HashMap::new();

    for step in &session_macro.steps {
        let req = match step.method.to_uppercase().as_str() {
            "POST" => client.post(&step.url),
            "PUT" => client.put(&step.url),
            "DELETE" => client.delete(&step.url),
            _ => client.get(&step.url),
        };

        let mut req = req;
        for (k, v) in &step.headers {
            let val = replace_variables(v, &extracted);
            req = req.header(k.as_str(), val);
        }

        if let Some(body) = &step.body {
            let body = replace_variables(body, &extracted);
            req = req.body(body);
        }

        let resp = req.send().await.map_err(|e| format!("Macro step failed: {}", e))?;

        if let Some(extract) = &step.extract {
            let source_text = match extract.source.as_str() {
                "header" => resp
                    .headers()
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                    .collect::<Vec<_>>()
                    .join("\n"),
                _ => resp.text().await.unwrap_or_default(),
            };

            if let Ok(re) = regex::Regex::new(&extract.regex) {
                if let Some(caps) = re.captures(&source_text) {
                    if let Some(m) = caps.get(extract.group) {
                        extracted.insert(extract.name.clone(), m.as_str().to_string());
                    }
                }
            }
        } else {
            let _ = resp.text().await; // consume body
        }
    }

    Ok(extracted)
}

fn replace_variables(input: &str, vars: &HashMap<String, String>) -> String {
    let mut result = input.to_string();
    for (k, v) in vars {
        result = result.replace(&format!("{{{{{}}}}}", k), v);
    }
    result
}
