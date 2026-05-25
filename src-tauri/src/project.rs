use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub id: String,
    pub name: String,
    pub path: String,
    pub created_at: String,
    pub last_opened: String,
    pub description: String,
    pub target_url: String,
    pub request_count: u32,
    pub finding_count: u32,
    pub project_type: String,
    pub is_temporary: bool,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub name: String,
    pub description: String,
    pub target_url: String,
    pub proxy_port: u16,
    pub intercept_enabled: bool,
    pub project_type: String,
    pub client_name: String,
    pub tags: Vec<String>,
    pub is_temporary: bool,
    pub temp_ttl_hours: Option<u32>,
    pub auto_start_proxy: bool,
    pub auto_launch_browser: bool,
    pub initial_scope: Vec<String>,
    pub max_traffic_entries: u32,
    pub max_traffic_ram_mb: u32,
    pub auto_save_interval_s: u32,
    pub notes_template: String,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            target_url: String::new(),
            proxy_port: 8080,
            intercept_enabled: false,
            project_type: "pentest".to_string(),
            client_name: String::new(),
            tags: vec![],
            is_temporary: false,
            temp_ttl_hours: None,
            auto_start_proxy: false,
            auto_launch_browser: false,
            initial_scope: vec![],
            max_traffic_entries: 10000,
            max_traffic_ram_mb: 256,
            auto_save_interval_s: 300,
            notes_template: String::new(),
        }
    }
}

fn projects_dir() -> PathBuf {
    let home = dirs_next().unwrap_or_else(|| PathBuf::from("."));
    let dir = home.join(".wondersuite").join("projects");
    fs::create_dir_all(&dir).ok();
    dir
}

fn dirs_next() -> Option<PathBuf> {
    std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).ok().map(PathBuf::from)
}

fn registry_path() -> PathBuf {
    let home = dirs_next().unwrap_or_else(|| PathBuf::from("."));
    let dir = home.join(".wondersuite");
    fs::create_dir_all(&dir).ok();
    dir.join("projects.json")
}

fn load_registry() -> Vec<ProjectInfo> {
    let path = registry_path();
    if path.exists() {
        let data = fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        vec![]
    }
}

fn save_registry(projects: &[ProjectInfo]) {
    let path = registry_path();
    let data = serde_json::to_string_pretty(projects).unwrap_or_default();
    fs::write(path, data).ok();
}

fn generate_scope_from_url(url: &str) -> Vec<String> {
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            return vec![host.to_string(), format!("*.{}", host)];
        }
    }
    vec![]
}

fn generate_notes_template(name: &str, description: &str, target: &str, project_type: &str) -> String {
    format!(
        "# {}\n\n**Type:** {}\n**Target:** {}\n\n{}\n\n## Methodology\n\n- [ ] Reconnaissance\n- [ ] Active Scanning\n- [ ] Manual Testing\n- [ ] Exploitation\n- [ ] Reporting\n\n## Findings\n\n_No findings yet._\n\n## Notes\n\n",
        name, project_type, target, description
    )
}

#[tauri::command]
pub async fn list_projects() -> Result<Vec<ProjectInfo>, String> {
    Ok(load_registry())
}

#[tauri::command]
pub async fn create_project(
    name: String,
    description: String,
    target_url: String,
    project_type: Option<String>,
    is_temporary: Option<bool>,
    temp_ttl_hours: Option<u32>,
    proxy_port: Option<u16>,
    auto_start_proxy: Option<bool>,
    auto_launch_browser: Option<bool>,
    initial_scope: Option<Vec<String>>,
    intercept_enabled: Option<bool>,
    client_name: Option<String>,
    tags: Option<Vec<String>>,
    max_traffic_entries: Option<u32>,
    notes_template: Option<String>,
) -> Result<ProjectInfo, String> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let project_dir = projects_dir().join(&id);
    let ptype = project_type.clone().unwrap_or_else(|| "pentest".to_string());
    let is_temp = is_temporary.unwrap_or(false);

    if !is_temp {
        fs::create_dir_all(&project_dir).map_err(|e| e.to_string())?;

        let scope = initial_scope.clone().unwrap_or_else(|| generate_scope_from_url(&target_url));
        let notes = notes_template
            .clone()
            .unwrap_or_else(|| generate_notes_template(&name, &description, &target_url, &ptype));

        let config = ProjectConfig {
            name: name.clone(),
            description: description.clone(),
            target_url: target_url.clone(),
            proxy_port: proxy_port.unwrap_or(8080),
            intercept_enabled: intercept_enabled.unwrap_or(false),
            project_type: ptype.clone(),
            client_name: client_name.clone().unwrap_or_default(),
            tags: tags.clone().unwrap_or_default(),
            is_temporary: false,
            temp_ttl_hours: None,
            auto_start_proxy: auto_start_proxy.unwrap_or(false),
            auto_launch_browser: auto_launch_browser.unwrap_or(false),
            initial_scope: scope,
            max_traffic_entries: max_traffic_entries.unwrap_or(10000),
            max_traffic_ram_mb: 256,
            auto_save_interval_s: 300,
            notes_template: notes.clone(),
        };
        let config_data = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(project_dir.join("config.json"), config_data).map_err(|e| e.to_string())?;

        fs::write(project_dir.join("traffic.json"), "[]").ok();
        fs::write(project_dir.join("findings.json"), "[]").ok();
        fs::write(project_dir.join("sitemap.json"), "{}").ok();
        fs::write(project_dir.join("notes.md"), notes).ok();
    }

    let info = ProjectInfo {
        id,
        name,
        path: if is_temp { String::new() } else { project_dir.to_string_lossy().to_string() },
        created_at: now.clone(),
        last_opened: now,
        description,
        target_url,
        request_count: 0,
        finding_count: 0,
        project_type: ptype,
        is_temporary: is_temp,
        tags: tags.unwrap_or_default(),
    };

    if !is_temp {
        let mut registry = load_registry();
        registry.insert(0, info.clone());
        save_registry(&registry);
    }

    Ok(info)
}

#[tauri::command]
pub async fn open_project(id: String) -> Result<ProjectInfo, String> {
    let mut registry = load_registry();
    let project = registry.iter_mut().find(|p| p.id == id).ok_or("Project not found")?;
    project.last_opened = chrono::Utc::now().to_rfc3339();
    let info = project.clone();
    save_registry(&registry);
    Ok(info)
}

#[tauri::command]
pub async fn delete_project(id: String) -> Result<(), String> {
    let project_dir = projects_dir().join(&id);
    if project_dir.exists() {
        fs::remove_dir_all(&project_dir).map_err(|e| e.to_string())?;
    }
    let mut registry = load_registry();
    registry.retain(|p| p.id != id);
    save_registry(&registry);
    Ok(())
}

#[tauri::command]
pub async fn get_project_config(id: String) -> Result<ProjectConfig, String> {
    let config_path = projects_dir().join(&id).join("config.json");
    if !config_path.exists() {
        return Err("Config file not found".into());
    }
    let data = fs::read_to_string(&config_path).map_err(|e| e.to_string())?;
    let config: ProjectConfig = serde_json::from_str(&data).unwrap_or_default();
    Ok(config)
}

#[tauri::command]
pub async fn update_project_config(id: String, config: ProjectConfig) -> Result<(), String> {
    let config_path = projects_dir().join(&id).join("config.json");
    let data = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    fs::write(config_path, data).map_err(|e| e.to_string())?;

    let mut registry = load_registry();
    if let Some(project) = registry.iter_mut().find(|p| p.id == id) {
        project.name = config.name.clone();
        project.description = config.description.clone();
        project.target_url = config.target_url.clone();
        project.project_type = config.project_type.clone();
        project.tags = config.tags.clone();
        save_registry(&registry);
    }

    Ok(())
}

/// Snapshot proxy traffic to the project directory. Best-effort — silently
/// returns Ok if the proxy state is not initialized, since this is called
/// every 30 s by the auto-save loop and we don't want noisy errors when
/// nothing is running yet.
#[tauri::command]
pub async fn project_save_state(id: String) -> Result<(), String> {
    let project_dir = projects_dir().join(&id);
    if !project_dir.exists() {
        return Ok(());
    }
    if let Some(state) = crate::proxy_commands::get_global_proxy_state() {
        let traffic = state.traffic.lock().await;
        let data = serde_json::to_string(&*traffic).map_err(|e| e.to_string())?;
        let tmp = project_dir.join("traffic.json.tmp");
        fs::write(&tmp, data).map_err(|e| e.to_string())?;
        fs::rename(&tmp, project_dir.join("traffic.json")).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// v0.3.16: per-project UI state blob (Repeater tabs, port-scan config,
/// scope) shuttled between frontend and disk. Atomic write via tmp+rename.
/// Empty / missing blob is fine — caller treats as "fresh project".
#[tauri::command]
pub async fn project_save_state_blob(id: String, blob: String) -> Result<(), String> {
    let project_dir = projects_dir().join(&id);
    if !project_dir.exists() {
        return Ok(());
    }
    let tmp = project_dir.join("ui_state.json.tmp");
    fs::write(&tmp, blob).map_err(|e| e.to_string())?;
    fs::rename(&tmp, project_dir.join("ui_state.json")).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn project_load_state_blob(id: String) -> Result<Option<String>, String> {
    let path = projects_dir().join(&id).join("ui_state.json");
    if !path.exists() {
        return Ok(None);
    }
    match fs::read_to_string(&path) {
        Ok(s) => Ok(Some(s)),
        Err(_) => Ok(None),
    }
}

/// Restore proxy traffic from the project directory's traffic.json.
/// Replaces the in-memory traffic Vec with the persisted entries. If the
/// file is missing or malformed we leave memory untouched and return Ok —
/// a fresh project just has nothing to load.
#[tauri::command]
pub async fn project_load_state(id: String) -> Result<(), String> {
    let traffic_path = projects_dir().join(&id).join("traffic.json");
    if !traffic_path.exists() {
        return Ok(());
    }
    let data = match fs::read_to_string(&traffic_path) {
        Ok(d) => d,
        Err(_) => return Ok(()),
    };
    let entries: Vec<crate::proxy::state::TrafficEntry> = match serde_json::from_str(&data) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    if let Some(state) = crate::proxy_commands::get_global_proxy_state() {
        let mut traffic = state.traffic.lock().await;
        *traffic = entries;
    }
    Ok(())
}

#[tauri::command]
pub async fn duplicate_project(id: String) -> Result<ProjectInfo, String> {
    let registry = load_registry();
    let source = registry.iter().find(|p| p.id == id).ok_or("Project not found")?;

    let new_name = format!("{} (Copy)", source.name);

    let config_path = projects_dir().join(&id).join("config.json");
    let mut config: ProjectConfig = if config_path.exists() {
        let data = fs::read_to_string(&config_path).unwrap_or_default();
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        ProjectConfig::default()
    };
    config.name = new_name.clone();

    create_project(
        new_name,
        source.description.clone(),
        source.target_url.clone(),
        Some(source.project_type.clone()),
        Some(false),
        None,
        Some(config.proxy_port),
        Some(config.auto_start_proxy),
        Some(config.auto_launch_browser),
        Some(config.initial_scope.clone()),
        Some(config.intercept_enabled),
        Some(config.client_name.clone()),
        Some(source.tags.clone()),
        Some(config.max_traffic_entries),
        Some(config.notes_template.clone()),
    )
    .await
}

#[derive(Debug, Serialize)]
pub struct MemoryStats {
    pub process_rss_mb: f64,
    pub traffic_entries: usize,
    pub traffic_ram_mb: f64,
    pub scanner_count: usize,
    pub intruder_count: usize,
    pub cert_cache_size: usize,
    pub ws_messages: usize,
    pub mcp_activity_count: usize,
}

#[tauri::command]
pub async fn get_memory_stats() -> Result<MemoryStats, String> {
    let rss_mb = get_process_memory_mb();

    let (traffic_entries, traffic_ram, ws_messages) = match crate::proxy_commands::get_global_proxy_state() {
        Some(state) => {
            let traffic = state.traffic.lock().await;
            let count = traffic.len();
            let ram_mb = (count * 2048) as f64 / (1024.0 * 1024.0);
            drop(traffic);
            let ws = state.websocket_messages.lock().await.len();
            (count, ram_mb, ws)
        }
        None => (0, 0.0, 0),
    };

    let scanner_count = match crate::scanner_commands::scanner_state() {
        Some(s) => s.lock().await.scans.len(),
        None => 0,
    };
    let intruder_count = match crate::intruder::intruder_state() {
        Some(s) => s.lock().await.attacks.len(),
        None => 0,
    };
    let cert_cache_size = crate::proxy_commands::get_global_ca().map(|c| c.cache_size()).unwrap_or(0);
    let mcp_activity_count =
        crate::mcp::activity::get_activity_stats().get("total").and_then(|v| v.as_u64()).unwrap_or(0)
            as usize;

    Ok(MemoryStats {
        process_rss_mb: rss_mb,
        traffic_entries,
        traffic_ram_mb: traffic_ram,
        scanner_count,
        intruder_count,
        cert_cache_size,
        ws_messages,
        mcp_activity_count,
    })
}

// v0.3.17: list the files inside a project directory for the launcher's
// folder-view panel. Returns name, size, modified time, and a kind tag
// so the UI can pick an icon / open handler without re-reading the disk.
#[derive(Debug, Serialize)]
pub struct ProjectFileEntry {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub modified_unix: u64,
    pub kind: String, // "config" | "traffic" | "findings" | "sitemap" | "notes" | "ui_state" | "other"
}

fn classify_project_file(name: &str) -> &'static str {
    match name {
        "config.json" => "config",
        "traffic.json" => "traffic",
        "findings.json" => "findings",
        "sitemap.json" => "sitemap",
        "notes.md" => "notes",
        "ui_state.json" => "ui_state",
        _ => "other",
    }
}

#[tauri::command]
pub async fn list_project_files(id: String) -> Result<Vec<ProjectFileEntry>, String> {
    let dir = projects_dir().join(&id);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let read = fs::read_dir(&dir).map_err(|e| e.to_string())?;
    let mut out: Vec<ProjectFileEntry> = Vec::new();
    for entry in read.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        let name = entry.file_name().to_string_lossy().to_string();
        // Hide our atomic-write tmp files so the user doesn't see flicker.
        if name.ends_with(".tmp") {
            continue;
        }
        let modified_unix = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        out.push(ProjectFileEntry {
            path: entry.path().to_string_lossy().to_string(),
            kind: classify_project_file(&name).to_string(),
            size_bytes: meta.len(),
            modified_unix,
            name,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Reveal a path in the OS file manager (Explorer / Finder / xdg-open).
/// `select` controls whether the file itself is highlighted (Windows /
/// macOS) or just the parent folder is opened.
#[tauri::command]
pub async fn reveal_in_file_manager(path: String, select: Option<bool>) -> Result<(), String> {
    let p = PathBuf::from(&path);
    if !p.exists() {
        return Err(format!("Path does not exist: {}", path));
    }
    let select_file = select.unwrap_or(true);

    #[cfg(target_os = "windows")]
    {
        let mut cmd = std::process::Command::new("explorer");
        if select_file && p.is_file() {
            cmd.arg(format!("/select,{}", p.to_string_lossy()));
        } else {
            cmd.arg(p.as_os_str());
        }
        cmd.spawn().map_err(|e| e.to_string())?;
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let mut cmd = std::process::Command::new("open");
        if select_file && p.is_file() {
            cmd.arg("-R").arg(&p);
        } else {
            cmd.arg(&p);
        }
        cmd.spawn().map_err(|e| e.to_string())?;
        return Ok(());
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let target = if select_file && p.is_file() { p.parent().unwrap_or(&p).to_path_buf() } else { p };
        std::process::Command::new("xdg-open").arg(&target).spawn().map_err(|e| e.to_string())?;
        Ok(())
    }
}

// v0.3.17: enumerate user-visible MCP / browser outputs on disk so the
// Settings panel can list them, show paths, and let the user delete.
// Today this covers ~/.wondersuite/screenshots/. As we add more output
// dirs (downloads, exported reports), append them to the SOURCES array.
#[derive(Debug, Serialize)]
pub struct McpOutputEntry {
    pub kind: String, // "screenshot" | "download" | ...
    pub path: String,
    pub name: String,
    pub size_bytes: u64,
    pub modified_unix: u64,
}

#[derive(Debug, Serialize)]
pub struct McpOutputsListing {
    pub root: String, // absolute path to .wondersuite for the user
    pub entries: Vec<McpOutputEntry>,
    pub total_size_bytes: u64,
}

fn wondersuite_root() -> PathBuf {
    let home = dirs_next().unwrap_or_else(|| PathBuf::from("."));
    home.join(".wondersuite")
}

#[tauri::command]
pub async fn list_mcp_outputs() -> Result<McpOutputsListing, String> {
    let root = wondersuite_root();
    let mut entries: Vec<McpOutputEntry> = Vec::new();
    let mut total: u64 = 0;

    const SOURCES: &[(&str, &str)] = &[("screenshots", "screenshot")];
    for (subdir, kind) in SOURCES {
        let dir = root.join(subdir);
        let Ok(read) = fs::read_dir(&dir) else { continue };
        for entry in read.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            let modified_unix = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let size = meta.len();
            total += size;
            entries.push(McpOutputEntry {
                kind: (*kind).to_string(),
                path: entry.path().to_string_lossy().to_string(),
                name: entry.file_name().to_string_lossy().to_string(),
                size_bytes: size,
                modified_unix,
            });
        }
    }

    // Newest first — matches what the user usually wants to see.
    entries.sort_by(|a, b| b.modified_unix.cmp(&a.modified_unix));

    Ok(McpOutputsListing { root: root.to_string_lossy().to_string(), entries, total_size_bytes: total })
}

/// Delete a single output file. Path must be inside ~/.wondersuite/ —
/// we reject anything else to avoid the path-traversal risk of the
/// frontend forwarding a maliciously crafted path.
#[tauri::command]
pub async fn delete_mcp_output(path: String) -> Result<(), String> {
    let root = wondersuite_root();
    let candidate = PathBuf::from(&path);
    let canonical_root = root.canonicalize().map_err(|e| e.to_string())?;
    let canonical_target = candidate.canonicalize().map_err(|e| e.to_string())?;
    if !canonical_target.starts_with(&canonical_root) {
        return Err("Refused: path is outside ~/.wondersuite/".into());
    }
    fs::remove_file(&canonical_target).map_err(|e| e.to_string())?;
    Ok(())
}

/// Delete every file under a known output subdirectory. `kind` matches
/// the keys exposed by `list_mcp_outputs` ("screenshot"). Subdir itself
/// is kept so future writes don't have to recreate it.
#[tauri::command]
pub async fn clear_mcp_outputs(kind: String) -> Result<u32, String> {
    let subdir = match kind.as_str() {
        "screenshot" => "screenshots",
        _ => return Err(format!("Unknown output kind: {}", kind)),
    };
    let dir = wondersuite_root().join(subdir);
    let Ok(read) = fs::read_dir(&dir) else { return Ok(0) };
    let mut deleted = 0u32;
    for entry in read.flatten() {
        if entry.metadata().map(|m| m.is_file()).unwrap_or(false) {
            if fs::remove_file(entry.path()).is_ok() {
                deleted += 1;
            }
        }
    }
    Ok(deleted)
}

#[cfg(target_os = "windows")]
fn get_process_memory_mb() -> f64 {
    use std::mem::MaybeUninit;
    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(process: isize, counters: *mut ProcessMemoryCounters, cb: u32) -> i32;
    }

    unsafe {
        let mut counters = MaybeUninit::<ProcessMemoryCounters>::zeroed().assume_init();
        counters.cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
        let handle = GetCurrentProcess();
        if K32GetProcessMemoryInfo(handle, &mut counters, counters.cb) != 0 {
            counters.working_set_size as f64 / (1024.0 * 1024.0)
        } else {
            0.0
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn get_process_memory_mb() -> f64 {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<f64>() {
                        return kb / 1024.0;
                    }
                }
            }
        }
    }
    0.0
}
