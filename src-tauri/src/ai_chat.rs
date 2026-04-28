// ─── AI Chat Proxy ──────────────────────────────────────────────────────────
// Generic HTTP proxy for AI API calls (OpenAI, Anthropic, Google).
// Runs through Tauri's Rust backend to avoid CORS restrictions.

use std::collections::HashMap;

/// Proxy an AI chat API request. The frontend constructs the provider-specific
/// body and headers; this command just forwards the raw HTTP POST.
#[tauri::command]
pub async fn ai_chat_request(
    url: String,
    headers: HashMap<String, String>,
    body: String,
) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let mut req = client
        .post(&url)
        .header("Content-Type", "application/json");

    for (key, value) in &headers {
        req = req.header(key.as_str(), value.as_str());
    }

    let resp = req
        .body(body)
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("Response read error: {}", e))?;

    if !status.is_success() {
        // Return the body so the frontend can show a meaningful error
        return Err(format!("API {} — {}", status.as_u16(), text));
    }

    Ok(text)
}
