use crate::mcp::types::HandlerResult;

pub async fn handle_session_manage(params: &serde_json::Value) -> HandlerResult {
    let action = params["action"].as_str().ok_or("Missing action")?;
    use std::sync::OnceLock;
    static SESSION: OnceLock<tokio::sync::Mutex<crate::session::SessionState>> = OnceLock::new();
    let session_lock = SESSION.get_or_init(|| tokio::sync::Mutex::new(crate::session::SessionState::new()));
    let mut session = session_lock.lock().await;

    match action {
        "get_cookies" => {
            let domain = params["domain"].as_str().unwrap_or("*");
            let cookies: Vec<&crate::session::Cookie> = if domain == "*" {
                session.cookie_jar.cookies.iter().collect()
            } else {
                session.cookie_jar.get(domain, "/")
            };
            Ok(serde_json::json!({"cookies": cookies, "count": cookies.len()}))
        }
        "set_cookie" => {
            let name = params["cookie_name"].as_str().ok_or("Missing cookie_name")?;
            let value = params["cookie_value"].as_str().ok_or("Missing cookie_value")?;
            let domain = params["domain"].as_str().ok_or("Missing domain")?;
            session.cookie_jar.set(crate::session::Cookie {
                name: name.into(),
                value: value.into(),
                domain: domain.into(),
                path: params["cookie_path"].as_str().unwrap_or("/").into(),
                secure: false,
                httponly: false,
                samesite: None,
                expires: None,
            });
            Ok(serde_json::json!({"set": true, "name": name, "domain": domain}))
        }
        "clear_cookies" => {
            session.cookie_jar.clear();
            Ok(serde_json::json!({"cleared": true}))
        }
        "remove_cookie" => {
            let name = params["cookie_name"].as_str().ok_or("Missing cookie_name")?;
            let domain = params["domain"].as_str().ok_or("Missing domain")?;
            session.cookie_jar.remove(name, domain);
            Ok(serde_json::json!({"removed": true}))
        }
        "create_macro" => {
            let name = params["macro_name"].as_str().ok_or("Missing macro_name")?;
            let steps: Vec<crate::session::MacroStep> = params["macro_steps"]
                .as_array()
                .ok_or("Missing macro_steps")?
                .iter()
                .map(|s| crate::session::MacroStep {
                    method: s["method"].as_str().unwrap_or("GET").into(),
                    url: s["url"].as_str().unwrap_or("").into(),
                    headers: std::collections::HashMap::new(),
                    body: s["body"].as_str().map(String::from),
                    extract: None,
                })
                .collect();
            let id = uuid::Uuid::new_v4().to_string();
            session.macros.push(crate::session::SessionMacro {
                id: id.clone(),
                name: name.into(),
                steps,
                description: String::new(),
            });
            Ok(serde_json::json!({"created": true, "macro_id": id}))
        }
        "run_macro" => {
            let mid = params["macro_id"].as_str().ok_or("Missing macro_id")?;
            let m = session.macros.iter().find(|m| m.id == mid).ok_or("Macro not found")?.clone();
            drop(session);
            let extracted = crate::session::execute_macro(&m).await?;
            Ok(serde_json::json!({"executed": true, "extracted_values": extracted}))
        }
        "list_macros" => {
            let macros: Vec<_> = session
                .macros
                .iter()
                .map(|m| serde_json::json!({"id": m.id, "name": m.name, "steps": m.steps.len()}))
                .collect();
            Ok(serde_json::json!({"macros": macros}))
        }
        _ => Ok(serde_json::json!({"action": action})),
    }
}
