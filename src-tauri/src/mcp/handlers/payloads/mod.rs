// ═══════════════════════════════════════════════════════════════════════
//  Payload Manager — Download, cache, and serve attack payloads
//  Sources: SecLists, PayloadsAllTheThings (downloaded at runtime)
// ═══════════════════════════════════════════════════════════════════════

pub mod downloader;
pub mod registry;

use std::collections::HashMap;
use std::path::PathBuf;

use crate::mcp::types::HandlerResult;

// ─── PayloadManager Global ─────────────────────────────────────────

lazy_static::lazy_static! {
    static ref PAYLOAD_MANAGER: std::sync::Mutex<PayloadManager> = std::sync::Mutex::new(PayloadManager::new());
}

pub fn manager() -> std::sync::MutexGuard<'static, PayloadManager> {
    PAYLOAD_MANAGER.lock().unwrap_or_else(|e| e.into_inner())
}

// ─── PayloadManager ────────────────────────────────────────────────

pub struct PayloadManager {
    base_dir: PathBuf,
    /// Cached payloads in memory: category → payloads
    cache: HashMap<String, Vec<String>>,
}

impl PayloadManager {
    pub fn new() -> Self {
        let base_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".wondersuite")
            .join("payloads");
        Self {
            base_dir,
            cache: HashMap::new(),
        }
    }

    pub fn base_dir(&self) -> &PathBuf {
        &self.base_dir
    }

    /// List all categories and their file counts
    pub fn list_categories(&self) -> Vec<CategoryInfo> {
        let categories = registry::all_categories();
        categories.iter().map(|cat| {
            let dir = self.base_dir.join(cat);
            let file_count = if dir.exists() {
                std::fs::read_dir(&dir)
                    .map(|rd| rd.filter(|e| e.is_ok()).count())
                    .unwrap_or(0)
            } else {
                0
            };
            let total_payloads = if dir.exists() {
                self.count_payloads_in_dir(&dir)
            } else {
                0
            };
            CategoryInfo {
                name: cat.to_string(),
                downloaded: file_count > 0,
                file_count,
                total_payloads,
                sources: registry::sources_for(cat).iter().map(|s| s.source_name.clone()).collect(),
            }
        }).collect()
    }

    /// Load all payloads for a category from disk (lazy cached)
    pub fn load(&mut self, category: &str) -> Result<Vec<String>, String> {
        // Return from cache if available
        if let Some(cached) = self.cache.get(category) {
            return Ok(cached.clone());
        }

        let dir = self.base_dir.join(category);
        if !dir.exists() {
            return Err(format!("Category '{}' not downloaded yet. Use action='download' first.", category));
        }

        let mut payloads = Vec::new();
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("Read dir: {}", e))?;
        
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("txt") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            payloads.push(trimmed.to_string());
                        }
                    }
                }
            }
        }

        // Deduplicate
        payloads.sort();
        payloads.dedup();

        self.cache.insert(category.to_string(), payloads.clone());
        Ok(payloads)
    }

    /// Search across all downloaded payloads
    pub fn search(&mut self, query: &str) -> Vec<SearchResult> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();
        
        let categories = registry::all_categories();
        for cat in &categories {
            if let Ok(payloads) = self.load(cat) {
                for payload in &payloads {
                    if payload.to_lowercase().contains(&query_lower) {
                        results.push(SearchResult {
                            category: cat.to_string(),
                            payload: payload.clone(),
                        });
                        if results.len() >= 100 {
                            return results;
                        }
                    }
                }
            }
        }
        results
    }

    /// Get info about a specific category
    pub fn category_info(&self, category: &str) -> Option<CategoryInfo> {
        self.list_categories().into_iter().find(|c| c.name == category)
    }

    /// Clear cache for a category (force reload from disk)
    pub fn invalidate_cache(&mut self, category: &str) {
        self.cache.remove(category);
    }

    fn count_payloads_in_dir(&self, dir: &PathBuf) -> usize {
        let mut count = 0;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("txt") {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        count += content.lines()
                            .filter(|l| {
                                let t = l.trim();
                                !t.is_empty() && !t.starts_with('#')
                            })
                            .count();
                    }
                }
            }
        }
        count
    }
}

// ─── Types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct CategoryInfo {
    pub name: String,
    pub downloaded: bool,
    pub file_count: usize,
    pub total_payloads: usize,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SearchResult {
    pub category: String,
    pub payload: String,
}

// ─── MCP Handler ───────────────────────────────────────────────────

pub async fn handle_payload_manager(params: &serde_json::Value) -> HandlerResult {
    let action = params["action"].as_str().unwrap_or("list");

    match action {
        "list" => {
            let mgr = manager();
            let categories = mgr.list_categories();
            let total_payloads: usize = categories.iter().map(|c| c.total_payloads).sum();
            let total_files: usize = categories.iter().map(|c| c.file_count).sum();
            Ok(serde_json::json!({
                "categories": categories,
                "total_files": total_files,
                "total_payloads": total_payloads,
                "base_dir": mgr.base_dir().display().to_string(),
            }))
        }

        "download" => {
            let category = params["category"].as_str().unwrap_or("all");
            let source = params["source"].as_str().unwrap_or("all");
            
            let categories = if category == "all" {
                registry::all_categories()
            } else {
                vec![category.to_string()]
            };

            let mut results = Vec::new();
            let base = manager().base_dir().clone();

            for cat in &categories {
                let sources = registry::sources_for(cat);
                let filtered: Vec<_> = if source == "all" {
                    sources
                } else {
                    sources.into_iter().filter(|s| s.source_name == source).collect()
                };

                for src in &filtered {
                    let target_dir = base.join(cat);
                    std::fs::create_dir_all(&target_dir).ok();

                    match downloader::download_payload_file(&src.url, &target_dir, &src.filename).await {
                        Ok(count) => {
                            results.push(serde_json::json!({
                                "category": cat,
                                "source": src.source_name,
                                "file": src.filename,
                                "payloads_downloaded": count,
                                "status": "success"
                            }));
                        }
                        Err(e) => {
                            results.push(serde_json::json!({
                                "category": cat,
                                "source": src.source_name,
                                "file": src.filename,
                                "status": "error",
                                "error": e
                            }));
                        }
                    }
                }
                
                // Invalidate cache for updated category
                manager().invalidate_cache(cat);
            }

            // Get updated stats
            let mgr = manager();
            let updated = mgr.list_categories();
            let total_payloads: usize = updated.iter().map(|c| c.total_payloads).sum();
            
            Ok(serde_json::json!({
                "action": "download",
                "results": results,
                "total_payloads_available": total_payloads,
            }))
        }

        "search" => {
            let query = params["query"].as_str().unwrap_or("");
            if query.is_empty() {
                return Err("Search query is required".into());
            }
            let results = manager().search(query);
            Ok(serde_json::json!({
                "query": query,
                "total_matches": results.len(),
                "results": results,
            }))
        }

        "info" => {
            let mgr = manager();
            if let Some(category) = params["category"].as_str() {
                // Specific category info
                match mgr.category_info(category) {
                    Some(info) => Ok(serde_json::json!(info)),
                    None => Err(format!("Unknown category: {}", category)),
                }
            } else {
                // Global info — all categories overview
                let categories = mgr.list_categories();
                let total_payloads: usize = categories.iter().map(|c| c.total_payloads).sum();
                let total_files: usize = categories.iter().map(|c| c.file_count).sum();
                let downloaded: usize = categories.iter().filter(|c| c.downloaded).count();
                Ok(serde_json::json!({
                    "total_categories": categories.len(),
                    "downloaded_categories": downloaded,
                    "total_files": total_files,
                    "total_payloads": total_payloads,
                    "base_dir": mgr.base_dir().display().to_string(),
                    "categories": categories.iter().map(|c| serde_json::json!({
                        "name": c.name,
                        "downloaded": c.downloaded,
                        "files": c.file_count,
                        "payloads": c.total_payloads,
                    })).collect::<Vec<_>>(),
                }))
            }
        }

        "load" => {
            let category = params["category"].as_str()
                .ok_or("category is required for load action")?;
            let limit = params["limit"].as_u64().unwrap_or(100) as usize;
            let offset = params["offset"].as_u64().unwrap_or(0) as usize;
            
            let payloads = manager().load(category)?;
            let total = payloads.len();
            let page: Vec<_> = payloads.into_iter().skip(offset).take(limit).collect();
            
            Ok(serde_json::json!({
                "category": category,
                "total": total,
                "offset": offset,
                "limit": limit,
                "payloads": page,
            }))
        }

        _ => Err(format!("Unknown payload_manager action: {}. Use: list, download, search, info, load", action)),
    }
}
