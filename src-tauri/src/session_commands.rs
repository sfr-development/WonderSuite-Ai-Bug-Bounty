use crate::session::{
    self, Cookie, MacroExtract, MacroStep, SessionAction, SessionHandle, SessionMacro, SessionRule,
    SessionScope,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn normalize_samesite(s: &str) -> Option<&'static str> {
    match s.trim().to_ascii_lowercase().as_str() {
        "strict" => Some("Strict"),
        "lax" => Some("Lax"),
        "none" => Some("None"),
        _ => None,
    }
}

async fn sync_cookie_to_browser(cookie: &Cookie) -> Result<bool, String> {
    let Ok(sess) = crate::mcp::browser::session().await else {
        return Ok(false);
    };
    let mut params = serde_json::json!({
        "name":     cookie.name,
        "value":    cookie.value,
        "domain":   cookie.domain,
        "path":     cookie.path,
        "secure":   cookie.secure,
        "httpOnly": cookie.httponly,
    });
    if let Some(ss) = cookie.samesite.as_deref().and_then(normalize_samesite) {
        params["sameSite"] = serde_json::Value::String(ss.into());
    }
    sess.send("Network.setCookie", params).await.map(|_| true)
}

async fn sync_delete_cookie_from_browser(name: &str, domain: &str) -> Result<bool, String> {
    let Ok(sess) = crate::mcp::browser::session().await else {
        return Ok(false);
    };
    let params = serde_json::json!({ "name": name, "domain": domain, "path": "/" });
    sess.send("Network.deleteCookies", params).await.map(|_| true)
}

async fn sync_clear_browser_cookies() -> Result<bool, String> {
    let Ok(sess) = crate::mcp::browser::session().await else {
        return Ok(false);
    };
    sess.send("Network.clearBrowserCookies", serde_json::json!({})).await.map(|_| true)
}

#[derive(Debug, Serialize)]
pub struct CookieOpResult {
    pub msg: String,
    pub synced: bool,
    pub sync_error: Option<String>,
}

impl CookieOpResult {
    fn from_sync(msg: String, sync: Result<bool, String>) -> Self {
        match sync {
            Ok(true) => Self { msg, synced: true, sync_error: None },
            Ok(false) => Self { msg, synced: false, sync_error: None },
            Err(e) => Self { msg, synced: false, sync_error: Some(e) },
        }
    }
}

#[tauri::command]
pub async fn session_get_cookies(
    state: tauri::State<'_, SessionHandle>,
    domain: Option<String>,
) -> Result<Vec<Cookie>, String> {
    let session = state.lock().await;
    let cookies = if let Some(d) = domain {
        session.cookie_jar.cookies.iter().filter(|c| c.domain.contains(&d)).cloned().collect()
    } else {
        session.cookie_jar.cookies.clone()
    };
    Ok(cookies)
}

#[tauri::command]
pub async fn session_set_cookie(
    state: tauri::State<'_, SessionHandle>,
    name: String,
    value: String,
    domain: String,
    path: Option<String>,
    secure: Option<bool>,
    httponly: Option<bool>,
    samesite: Option<String>,
) -> Result<CookieOpResult, String> {
    let cookie = Cookie {
        name: name.clone(),
        value,
        domain: domain.clone(),
        path: path.unwrap_or_else(|| "/".into()),
        secure: secure.unwrap_or(false),
        httponly: httponly.unwrap_or(false),
        samesite,
        expires: None,
    };
    {
        let mut session = state.lock().await;
        session.cookie_jar.set(cookie.clone());
    }
    let sync = sync_cookie_to_browser(&cookie).await;
    Ok(CookieOpResult::from_sync(format!("Cookie '{}' set for {}", name, domain), sync))
}

#[tauri::command]
pub async fn session_remove_cookie(
    state: tauri::State<'_, SessionHandle>,
    name: String,
    domain: String,
) -> Result<CookieOpResult, String> {
    {
        let mut session = state.lock().await;
        session.cookie_jar.remove(&name, &domain);
    }
    let sync = sync_delete_cookie_from_browser(&name, &domain).await;
    Ok(CookieOpResult::from_sync(format!("Cookie '{}' removed from {}", name, domain), sync))
}

#[tauri::command]
pub async fn session_clear_cookies(state: tauri::State<'_, SessionHandle>) -> Result<CookieOpResult, String> {
    {
        let mut session = state.lock().await;
        session.cookie_jar.clear();
    }
    let sync = sync_clear_browser_cookies().await;
    Ok(CookieOpResult::from_sync("All cookies cleared".into(), sync))
}

#[tauri::command]
pub async fn session_import_cookies(
    state: tauri::State<'_, SessionHandle>,
    json: String,
) -> Result<CookieOpResult, String> {
    let cookies: Vec<Cookie> = serde_json::from_str(&json).map_err(|e| format!("Invalid JSON: {}", e))?;
    let count = cookies.len();
    {
        let mut session = state.lock().await;
        for c in cookies.iter().cloned() {
            session.cookie_jar.set(c);
        }
    }
    let mut any_synced = false;
    let mut errors: Vec<String> = Vec::new();
    for c in cookies.iter() {
        match sync_cookie_to_browser(c).await {
            Ok(true) => any_synced = true,
            Ok(false) => break,
            Err(e) => errors.push(format!("{}: {}", c.name, e)),
        }
    }
    let sync = if !errors.is_empty() {
        Err(errors.join("; "))
    } else if any_synced {
        Ok(true)
    } else {
        Ok(false)
    };
    Ok(CookieOpResult::from_sync(format!("Imported {} cookies", count), sync))
}

#[tauri::command]
pub async fn session_browser_sync_status() -> Result<bool, String> {
    Ok(crate::mcp::browser::session().await.is_ok())
}

#[tauri::command]
pub async fn session_export_cookies(state: tauri::State<'_, SessionHandle>) -> Result<String, String> {
    let session = state.lock().await;
    serde_json::to_string_pretty(&session.cookie_jar.cookies).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn session_get_macros(state: tauri::State<'_, SessionHandle>) -> Result<Vec<SessionMacro>, String> {
    let session = state.lock().await;
    Ok(session.macros.clone())
}

#[tauri::command]
pub async fn session_create_macro(
    state: tauri::State<'_, SessionHandle>,
    name: String,
    description: Option<String>,
    steps: Vec<serde_json::Value>,
) -> Result<String, String> {
    let macro_steps: Vec<MacroStep> = steps
        .into_iter()
        .map(|s| MacroStep {
            method: s["method"].as_str().unwrap_or("GET").to_string(),
            url: s["url"].as_str().unwrap_or("").to_string(),
            headers: s["headers"]
                .as_object()
                .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
                .unwrap_or_default(),
            body: s["body"].as_str().map(|b| b.to_string()),
            extract: s.get("extract").and_then(|e| {
                Some(MacroExtract {
                    name: e["name"].as_str()?.to_string(),
                    source: e["source"].as_str().unwrap_or("body").to_string(),
                    regex: e["regex"].as_str()?.to_string(),
                    group: e["group"].as_u64().unwrap_or(1) as usize,
                })
            }),
        })
        .collect();

    let id = uuid::Uuid::new_v4().to_string();
    let mut session = state.lock().await;
    session.macros.push(SessionMacro {
        id: id.clone(),
        name,
        steps: macro_steps,
        description: description.unwrap_or_default(),
    });
    Ok(id)
}

#[tauri::command]
pub async fn session_run_macro(
    state: tauri::State<'_, SessionHandle>,
    macro_id: String,
) -> Result<serde_json::Value, String> {
    let session = state.lock().await;
    let the_macro = session.macros.iter().find(|m| m.id == macro_id).ok_or("Macro not found")?.clone();
    drop(session); // Release lock before executing

    let extracted = session::execute_macro(&the_macro).await?;
    Ok(serde_json::json!({
        "macro_id": macro_id,
        "macro_name": the_macro.name,
        "steps_executed": the_macro.steps.len(),
        "extracted_values": extracted,
    }))
}

#[tauri::command]
pub async fn session_delete_macro(
    state: tauri::State<'_, SessionHandle>,
    macro_id: String,
) -> Result<String, String> {
    let mut session = state.lock().await;
    session.macros.retain(|m| m.id != macro_id);
    Ok("Macro deleted".into())
}

#[tauri::command]
pub async fn session_get_rules(state: tauri::State<'_, SessionHandle>) -> Result<Vec<SessionRule>, String> {
    let session = state.lock().await;
    Ok(session.rules.clone())
}

#[tauri::command]
pub async fn session_create_rule(
    state: tauri::State<'_, SessionHandle>,
    name: String,
    scope_type: String,
    scope_value: Option<String>,
    actions: Vec<serde_json::Value>,
) -> Result<String, String> {
    let scope = match scope_type.as_str() {
        "all" => SessionScope::AllRequests,
        "in_scope" => SessionScope::InScope,
        "url_contains" => SessionScope::UrlContains(scope_value.unwrap_or_default()),
        "host_equals" => SessionScope::HostEquals(scope_value.unwrap_or_default()),
        _ => return Err("Invalid scope type".into()),
    };

    let parsed_actions: Vec<SessionAction> = actions
        .into_iter()
        .filter_map(|a| {
            let action_type = a["type"].as_str()?;
            Some(match action_type {
                "use_cookie_jar" => SessionAction::UseCookieJar,
                "set_cookie" => SessionAction::SetCookieValue {
                    name: a["name"].as_str()?.to_string(),
                    value: a["value"].as_str()?.to_string(),
                },
                "run_macro" => SessionAction::RunMacro { macro_id: a["macro_id"].as_str()?.to_string() },
                "add_header" => SessionAction::AddHeader {
                    name: a["name"].as_str()?.to_string(),
                    value: a["value"].as_str()?.to_string(),
                },
                "check_session" => SessionAction::CheckSessionValid {
                    check_string: a["check_string"].as_str()?.to_string(),
                    invalid_string: a["invalid_string"].as_str().map(|s| s.to_string()),
                },
                _ => return None,
            })
        })
        .collect();

    let id = uuid::Uuid::new_v4().to_string();
    let mut session = state.lock().await;
    session.rules.push(SessionRule { id: id.clone(), name, enabled: true, scope, actions: parsed_actions });
    Ok(id)
}

#[tauri::command]
pub async fn session_toggle_rule(
    state: tauri::State<'_, SessionHandle>,
    rule_id: String,
    enabled: bool,
) -> Result<String, String> {
    let mut session = state.lock().await;
    if let Some(rule) = session.rules.iter_mut().find(|r| r.id == rule_id) {
        rule.enabled = enabled;
        Ok(format!("Rule {} {}", rule_id, if enabled { "enabled" } else { "disabled" }))
    } else {
        Err("Rule not found".into())
    }
}

#[tauri::command]
pub async fn session_delete_rule(
    state: tauri::State<'_, SessionHandle>,
    rule_id: String,
) -> Result<String, String> {
    let mut session = state.lock().await;
    session.rules.retain(|r| r.id != rule_id);
    Ok("Rule deleted".into())
}
