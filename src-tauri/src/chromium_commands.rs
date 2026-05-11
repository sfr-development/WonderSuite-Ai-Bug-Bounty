// Tauri commands exposing the ChromiumManager to the frontend.

use crate::chromium::{ChromiumError, ChromiumManager};
use serde::Serialize;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tauri::AppHandle;

#[derive(Serialize)]
pub struct ChromiumStatus {
    pub version: String,
    pub cached: bool,
    pub cache_dir: String,
    pub disk_bytes: u64,
}

#[tauri::command]
pub async fn chromium_status(app: AppHandle) -> Result<ChromiumStatus, String> {
    let mgr = ChromiumManager::new(&app).map_err(|e| e.to_string())?;
    let cached = mgr.is_cached();
    let disk_bytes =
        if cached { dir_size(mgr.cache_dir().join(mgr.pinned_version())).unwrap_or(0) } else { 0 };
    Ok(ChromiumStatus {
        version: mgr.pinned_version().into(),
        cached,
        cache_dir: mgr.cache_dir().to_string_lossy().into(),
        disk_bytes,
    })
}

/// Triggers (or re-triggers) the download. Frontend uses this when the user
/// hits the Reinstall button in Settings; normal browser launch goes through
/// `browser_launch` which calls `ChromiumManager::ensure` internally.
#[tauri::command]
pub async fn chromium_ensure(app: AppHandle) -> Result<String, String> {
    let mgr = ChromiumManager::new(&app).map_err(|e| e.to_string())?;
    let cancel = Arc::new(AtomicBool::new(false));
    let binary = mgr.ensure(cancel).await.map_err(|e| e.to_string())?;
    Ok(binary.to_string_lossy().into())
}

/// Deletes the cached install of the pinned version, forcing a fresh download
/// on next launch.
#[tauri::command]
pub fn chromium_reinstall(app: AppHandle) -> Result<bool, String> {
    let mgr = ChromiumManager::new(&app).map_err(|e| e.to_string())?;
    let dir = mgr.cache_dir().join(mgr.pinned_version());
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    Ok(true)
}

/// Open an arbitrary local directory in the system file explorer.
/// Used by Settings -> Browser -> "Open cache dir" — avoids needing a broad
/// opener-plugin path scope.
#[tauri::command]
pub fn reveal_in_explorer(path: String) -> Result<bool, String> {
    let p = std::path::PathBuf::from(&path);
    if !p.exists() {
        return Err(format!("path does not exist: {}", path));
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        Command::new("explorer.exe")
            .arg(&p)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| format!("explorer.exe failed: {}", e))?;
        Ok(true)
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(&p).spawn().map_err(|e| format!("open failed: {}", e))?;
        Ok(true)
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&p)
            .spawn()
            .map_err(|e| format!("xdg-open failed: {}", e))?;
        Ok(true)
    }
}

fn dir_size(path: std::path::PathBuf) -> Result<u64, ChromiumError> {
    let mut total = 0u64;
    if !path.exists() {
        return Ok(0);
    }
    let mut stack = vec![path];
    while let Some(p) = stack.pop() {
        for entry in std::fs::read_dir(&p)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                total += meta.len();
            }
        }
    }
    Ok(total)
}
