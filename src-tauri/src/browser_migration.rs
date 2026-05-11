// One-shot migration helpers for v0.1.x users upgrading to v0.2.0.
//
// 1. Old profile lived at ~/.wondersuite/browser-profile/. New cache layout
//    puts it at <app_local_data>/browser-profiles/default/. We try to move
//    the dir over once if the new location is empty.
//
// 2. v0.1.x trusted our MITM CA via `certutil -addstore -user Root`. v0.2.0
//    uses --ignore-certificate-errors instead. Detect a stale entry and offer
//    the user a one-click cleanup.
//
// Both operations are best-effort: failures are logged and never block.

use serde::Serialize;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

#[derive(Debug, Serialize)]
pub struct MigrationReport {
    pub profile_migrated: bool,
    pub legacy_profile_path: Option<String>,
    pub new_profile_path: String,
    pub legacy_ca_present: bool,
    pub legacy_ca_subject: Option<String>,
    pub notes: Vec<String>,
}

fn legacy_profile_dir() -> Option<PathBuf> {
    let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).ok()?;
    Some(PathBuf::from(home).join(".wondersuite").join("browser-profile"))
}

fn new_profile_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let base = app.path().app_local_data_dir().map_err(|e| format!("app_local_data_dir: {}", e))?;
    Ok(base.join("browser-profiles").join("default"))
}

/// Move the legacy ~/.wondersuite/browser-profile/ into the new cache
/// location. No-op if the new location already exists or the legacy one
/// doesn't.
fn try_move_profile(app: &AppHandle, report: &mut MigrationReport) {
    let Some(legacy) = legacy_profile_dir() else { return };
    report.legacy_profile_path = Some(legacy.to_string_lossy().into());

    if !legacy.exists() {
        return;
    }

    let new_path = match new_profile_dir(app) {
        Ok(p) => p,
        Err(e) => {
            report.notes.push(format!("could not resolve new profile dir: {}", e));
            return;
        }
    };
    report.new_profile_path = new_path.to_string_lossy().into();

    if new_path.exists() {
        report.notes.push(format!(
            "new profile dir already exists; leaving legacy profile at {} for the user to delete manually",
            legacy.display()
        ));
        return;
    }

    if let Some(parent) = new_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            report.notes.push(format!("create_dir_all failed: {}", e));
            return;
        }
    }

    match std::fs::rename(&legacy, &new_path) {
        Ok(_) => {
            report.profile_migrated = true;
            report.notes.push(format!(
                "moved legacy profile from {} to {}",
                legacy.display(),
                new_path.display()
            ));
        }
        Err(e) => {
            report.notes.push(format!(
                "could not move profile dir (cross-device link?): {} — leaving legacy in place",
                e
            ));
        }
    }
}

/// Detect a WonderSuite CA cert in the user trust store (Windows only).
#[cfg(target_os = "windows")]
fn detect_legacy_ca() -> (bool, Option<String>) {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let out =
        Command::new("certutil").args(["-store", "-user", "Root"]).creation_flags(CREATE_NO_WINDOW).output();
    let Ok(out) = out else { return (false, None) };
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let lower = stdout.to_lowercase();
    let needle = "wondersuite";
    if lower.contains(needle) {
        let subject =
            stdout.lines().find(|l| l.to_lowercase().contains("wondersuite")).map(|s| s.trim().to_string());
        return (true, subject);
    }
    (false, None)
}

#[cfg(not(target_os = "windows"))]
fn detect_legacy_ca() -> (bool, Option<String>) {
    // We never installed the CA into macOS Keychain / NSS in v0.1.x, so
    // there's nothing to detect here.
    (false, None)
}

/// Remove the WonderSuite CA from the Windows user trust store. Returns true
/// if removal succeeded, false otherwise.
#[cfg(target_os = "windows")]
fn remove_legacy_ca() -> bool {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let result = Command::new("certutil")
        .args(["-delstore", "-user", "Root", "wondersuite"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    matches!(result, Ok(o) if o.status.success())
}

#[cfg(not(target_os = "windows"))]
fn remove_legacy_ca() -> bool {
    true // nothing to remove
}

#[tauri::command]
pub fn browser_migration_check(app: AppHandle) -> Result<MigrationReport, String> {
    let new_profile = new_profile_dir(&app).unwrap_or_else(|_| PathBuf::from(""));
    let mut report = MigrationReport {
        profile_migrated: false,
        legacy_profile_path: None,
        new_profile_path: new_profile.to_string_lossy().into(),
        legacy_ca_present: false,
        legacy_ca_subject: None,
        notes: vec![],
    };
    try_move_profile(&app, &mut report);
    let (ca_present, ca_subject) = detect_legacy_ca();
    report.legacy_ca_present = ca_present;
    report.legacy_ca_subject = ca_subject;
    Ok(report)
}

#[tauri::command]
pub fn browser_migration_remove_ca() -> Result<bool, String> {
    if remove_legacy_ca() {
        Ok(true)
    } else {
        Err("certutil -delstore failed (cert may already be gone, or you need admin to clear a system-wide store)".into())
    }
}
