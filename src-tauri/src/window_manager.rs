// Multi-window support: pop individual modules into their own native window.
// Each detached window is a separate WebviewWindow that boots into the React
// app with `#detached:<module_id>` in the URL hash, so main.tsx mounts only
// that module instead of the full Shell. Backend state is shared (single
// Rust process) and cross-window UI sync rides on Tauri's emit/listen.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, LogicalPosition, LogicalSize, Manager, WebviewUrl, WebviewWindowBuilder};

#[derive(Default)]
pub struct WindowManager {
    // module_id → window label
    pub detached: DashMap<String, String>,
}

pub fn create_window_state() -> Arc<WindowManager> {
    Arc::new(WindowManager::default())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetachedInfo {
    pub module_id: String,
    pub label: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

fn label_for(module_id: &str) -> String {
    format!("detached-{}", module_id)
}

#[tauri::command]
pub async fn window_detach_module(
    app: AppHandle,
    state: tauri::State<'_, Arc<WindowManager>>,
    module_id: String,
    x: Option<f64>,
    y: Option<f64>,
    width: Option<f64>,
    height: Option<f64>,
) -> Result<String, String> {
    let label = label_for(&module_id);

    if state.detached.contains_key(&module_id) {
        if let Some(win) = app.get_webview_window(&label) {
            let _ = win.set_focus();
        }
        return Ok(label);
    }

    let url = WebviewUrl::App(format!("index.html#detached:{}", module_id).into());
    let w = width.unwrap_or(960.0).max(500.0);
    let h = height.unwrap_or(700.0).max(400.0);

    let mut builder = WebviewWindowBuilder::new(&app, &label, url)
        .title(format!("WonderSuite — {}", module_id))
        .inner_size(w, h)
        .min_inner_size(500.0, 400.0)
        .decorations(false)
        .transparent(true)
        .resizable(true);

    if let (Some(px), Some(py)) = (x, y) {
        builder = builder.position(px, py);
    } else {
        builder = builder.center();
    }

    let window = builder.build().map_err(|e| e.to_string())?;
    state.detached.insert(module_id.clone(), label.clone());

    let state_ref = state.inner().clone();
    let app_ref = app.clone();
    let module_id_ref = module_id.clone();
    window.on_window_event(move |event| {
        if matches!(event, tauri::WindowEvent::Destroyed) {
            state_ref.detached.remove(&module_id_ref);
            let _ = app_ref.emit("window:redocked", &module_id_ref);
        }
    });

    let _ = app.emit("window:detached", &module_id);
    Ok(label)
}

#[tauri::command]
pub async fn window_redock_module(
    app: AppHandle,
    state: tauri::State<'_, Arc<WindowManager>>,
    module_id: String,
) -> Result<(), String> {
    if let Some(label) = state.detached.get(&module_id).map(|r| r.clone()) {
        if let Some(win) = app.get_webview_window(&label) {
            let _ = win.close();
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn window_focus_detached(
    app: AppHandle,
    state: tauri::State<'_, Arc<WindowManager>>,
    module_id: String,
) -> Result<(), String> {
    if let Some(label) = state.detached.get(&module_id).map(|r| r.clone()) {
        if let Some(win) = app.get_webview_window(&label) {
            let _ = win.set_focus();
            let _ = win.unminimize();
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn window_list_detached(
    app: AppHandle,
    state: tauri::State<'_, Arc<WindowManager>>,
) -> Result<Vec<DetachedInfo>, String> {
    let mut out = Vec::new();
    for entry in state.detached.iter() {
        let module_id = entry.key().clone();
        let label = entry.value().clone();
        if let Some(win) = app.get_webview_window(&label) {
            let pos =
                win.outer_position().ok().map(|p| p.to_logical::<f64>(win.scale_factor().unwrap_or(1.0)));
            let size = win.inner_size().ok().map(|s| s.to_logical::<f64>(win.scale_factor().unwrap_or(1.0)));
            out.push(DetachedInfo {
                module_id,
                label,
                x: pos.map(|p| p.x as i32).unwrap_or(0),
                y: pos.map(|p| p.y as i32).unwrap_or(0),
                width: size.map(|s| s.width as u32).unwrap_or(960),
                height: size.map(|s| s.height as u32).unwrap_or(700),
            });
        }
    }
    Ok(out)
}

#[tauri::command]
pub async fn window_move_detached(
    app: AppHandle,
    state: tauri::State<'_, Arc<WindowManager>>,
    module_id: String,
    x: f64,
    y: f64,
) -> Result<(), String> {
    if let Some(label) = state.detached.get(&module_id).map(|r| r.clone()) {
        if let Some(win) = app.get_webview_window(&label) {
            win.set_position(LogicalPosition::new(x, y)).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn window_resize_detached(
    app: AppHandle,
    state: tauri::State<'_, Arc<WindowManager>>,
    module_id: String,
    width: f64,
    height: f64,
) -> Result<(), String> {
    if let Some(label) = state.detached.get(&module_id).map(|r| r.clone()) {
        if let Some(win) = app.get_webview_window(&label) {
            win.set_size(LogicalSize::new(width, height)).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
