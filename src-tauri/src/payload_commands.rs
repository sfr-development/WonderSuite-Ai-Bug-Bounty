use crate::mcp::handlers::payloads;

#[tauri::command]
pub fn payload_list_categories() -> Result<serde_json::Value, String> {
    let mgr = payloads::manager();
    let categories = mgr.list_categories();
    let total_payloads: usize = categories.iter().map(|c| c.total_payloads).sum();
    let total_files: usize = categories.iter().map(|c| c.file_count).sum();
    let downloaded: usize = categories.iter().filter(|c| c.downloaded).count();
    Ok(serde_json::json!({
        "categories": categories,
        "total_payloads": total_payloads,
        "total_files": total_files,
        "downloaded_categories": downloaded,
        "base_dir": mgr.base_dir().display().to_string(),
    }))
}

#[tauri::command]
pub async fn payload_download(category: Option<String>) -> Result<serde_json::Value, String> {
    let params = serde_json::json!({
        "action": "download",
        "category": category.unwrap_or_else(|| "all".into()),
        "source": "all",
    });
    payloads::handle_payload_manager(&params).await
}

#[tauri::command]
pub fn payload_load(
    category: String,
    offset: Option<u64>,
    limit: Option<u64>,
) -> Result<serde_json::Value, String> {
    let mut mgr = payloads::manager();
    let all = mgr.load(&category)?;
    let total = all.len();
    let off = offset.unwrap_or(0) as usize;
    let lim = limit.unwrap_or(200) as usize;
    let page: Vec<String> = all.into_iter().skip(off).take(lim).collect();
    Ok(serde_json::json!({
        "category": category,
        "total": total,
        "offset": off,
        "limit": lim,
        "payloads": page,
    }))
}

#[tauri::command]
pub fn payload_search(query: String) -> Result<serde_json::Value, String> {
    if query.trim().is_empty() {
        return Err("query is empty".into());
    }
    let mut mgr = payloads::manager();
    let results = mgr.search(&query);
    Ok(serde_json::json!({
        "query": query,
        "total_matches": results.len(),
        "results": results,
    }))
}
