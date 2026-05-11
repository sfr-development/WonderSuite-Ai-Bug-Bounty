use crate::session::{
    self, Cookie, MacroExtract, MacroStep, SessionAction, SessionHandle, SessionMacro, SessionRule,
    SessionScope,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
) -> Result<String, String> {
    let mut session = state.lock().await;
    session.cookie_jar.set(Cookie {
        name: name.clone(),
        value,
        domain: domain.clone(),
        path: path.unwrap_or_else(|| "/".into()),
        secure: secure.unwrap_or(false),
        httponly: httponly.unwrap_or(false),
        samesite,
        expires: None,
    });
    Ok(format!("Cookie '{}' set for {}", name, domain))
}

#[tauri::command]
pub async fn session_remove_cookie(
    state: tauri::State<'_, SessionHandle>,
    name: String,
    domain: String,
) -> Result<String, String> {
    let mut session = state.lock().await;
    session.cookie_jar.remove(&name, &domain);
    Ok(format!("Cookie '{}' removed from {}", name, domain))
}

#[tauri::command]
pub async fn session_clear_cookies(state: tauri::State<'_, SessionHandle>) -> Result<String, String> {
    let mut session = state.lock().await;
    session.cookie_jar.clear();
    Ok("All cookies cleared".into())
}

#[tauri::command]
pub async fn session_import_cookies(
    state: tauri::State<'_, SessionHandle>,
    json: String,
) -> Result<String, String> {
    let cookies: Vec<Cookie> = serde_json::from_str(&json).map_err(|e| format!("Invalid JSON: {}", e))?;
    let count = cookies.len();
    let mut session = state.lock().await;
    for c in cookies {
        session.cookie_jar.set(c);
    }
    Ok(format!("Imported {} cookies", count))
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
