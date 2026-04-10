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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub name: String,
    pub description: String,
    pub target_url: String,
    pub proxy_port: u16,
    pub intercept_enabled: bool,
}

fn projects_dir() -> PathBuf {
    let home = dirs_next().unwrap_or_else(|| PathBuf::from("."));
    let dir = home.join(".wondersuite").join("projects");
    fs::create_dir_all(&dir).ok();
    dir
}

fn dirs_next() -> Option<PathBuf> {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok()
        .map(PathBuf::from)
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

#[tauri::command]
pub async fn list_projects() -> Result<Vec<ProjectInfo>, String> {
    Ok(load_registry())
}

#[tauri::command]
pub async fn create_project(name: String, description: String, target_url: String) -> Result<ProjectInfo, String> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let project_dir = projects_dir().join(&id);
    fs::create_dir_all(&project_dir).map_err(|e| e.to_string())?;

    let config = ProjectConfig {
        name: name.clone(),
        description: description.clone(),
        target_url: target_url.clone(),
        proxy_port: 8080,
        intercept_enabled: false,
    };
    let config_data = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    fs::write(project_dir.join("config.json"), config_data).map_err(|e| e.to_string())?;

    // Create empty data files
    fs::write(project_dir.join("traffic.json"), "[]").ok();
    fs::write(project_dir.join("findings.json"), "[]").ok();
    fs::write(project_dir.join("sitemap.json"), "{}").ok();
    fs::write(project_dir.join("notes.md"), format!("# {}\n\n{}\n", name, description)).ok();

    let info = ProjectInfo {
        id,
        name,
        path: project_dir.to_string_lossy().to_string(),
        created_at: now.clone(),
        last_opened: now,
        description,
        target_url,
        request_count: 0,
        finding_count: 0,
    };

    let mut registry = load_registry();
    registry.insert(0, info.clone());
    save_registry(&registry);

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
