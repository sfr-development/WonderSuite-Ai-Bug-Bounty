// WonderSuite network driver — bundled WinDivert deployment via UAC-elevated
// SCM install. WinDivert is LGPLv3 + EV-signed by Reqrypt LLC, freely
// redistributable. We ship the unmodified WinDivert64.sys + WinDivert.dll
// inside Tauri resources and register the .sys as a kernel service.
//
// Privilege model: WonderSuite itself runs unprivileged. The install flow
// uses `ShellExecuteExW` with verb "runas" on a temp `.cmd` file containing
// `sc.exe` commands → Windows pops the UAC consent dialog → cmd.exe runs
// elevated → service installed. Single UAC prompt for life; subsequent
// SYN scans need no elevation since the driver is already a SYSTEM service.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DriverStatus {
    pub installed: bool,
    pub service_running: bool,
    pub hvci_enabled: bool,
    pub bundled_version: &'static str,
    pub dll_path: Option<String>,
    pub message: String,
}

pub const BUNDLED_WINDIVERT_VERSION: &str = "2.2.2";

/// Locate `WinDivert.dll` next to the running exe's resource_dir without
/// needing a Tauri AppHandle. We compute the path manually by walking from
/// the current_exe upwards. This is needed by the SYN scan engine, which
/// runs inside a Tokio task that doesn't hold an AppHandle.
#[cfg(target_os = "windows")]
pub fn find_bundled_dll() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;
    // Tauri bundle layout: <install>/wondersuite.exe + <install>/resources/...
    let candidates = [
        exe_dir.join("resources").join("drivers").join("windivert").join("WinDivert.dll"),
        exe_dir.join("drivers").join("windivert").join("WinDivert.dll"),
        exe_dir.join("WinDivert.dll"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

/// Same as `find_bundled_dll` for the `.sys` driver file (used by the
/// SCM install command line, which needs an absolute path).
#[cfg(target_os = "windows")]
pub fn find_bundled_sys() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;
    let candidates = [
        exe_dir.join("resources").join("drivers").join("windivert").join("WinDivert64.sys"),
        exe_dir.join("drivers").join("windivert").join("WinDivert64.sys"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

#[cfg(not(target_os = "windows"))]
pub fn find_bundled_dll() -> Option<std::path::PathBuf> { None }
#[cfg(not(target_os = "windows"))]
pub fn find_bundled_sys() -> Option<std::path::PathBuf> { None }

#[cfg(target_os = "windows")]
const SERVICE_NAME: &str = "WonderSuiteNet";
#[cfg(target_os = "windows")]
const SERVICE_DISPLAY: &str = "WonderSuite Network Capture";

#[cfg(target_os = "windows")]
pub fn detect_status_with_paths(app: &tauri::AppHandle) -> DriverStatus {
    let hvci_enabled = hvci_is_enabled();
    let installed = service_query_status().is_some();
    let service_running = matches!(service_query_status(), Some(s) if s == "running");
    let dll_path = bundled_paths(app).ok().map(|(dll, _)| dll.to_string_lossy().into_owned());
    let message = if hvci_enabled {
        "HVCI / Memory Integrity is enabled — third-party drivers cannot load.".into()
    } else if service_running {
        "Driver service is running.".into()
    } else if installed {
        "Driver installed but service not running.".into()
    } else {
        "Driver not installed.".into()
    };
    DriverStatus {
        installed,
        service_running,
        hvci_enabled,
        bundled_version: BUNDLED_WINDIVERT_VERSION,
        dll_path,
        message,
    }
}

#[cfg(target_os = "windows")]
pub fn detect_status() -> DriverStatus {
    let hvci_enabled = hvci_is_enabled();
    let installed = service_query_status().is_some();
    let service_running = matches!(service_query_status(), Some(s) if s == "running");
    let message = if hvci_enabled {
        "HVCI / Memory Integrity is enabled — third-party drivers cannot load.".into()
    } else if service_running {
        "Driver service is running.".into()
    } else if installed {
        "Driver installed but service not running.".into()
    } else {
        "Driver not installed.".into()
    };
    DriverStatus {
        installed,
        service_running,
        hvci_enabled,
        bundled_version: BUNDLED_WINDIVERT_VERSION,
        dll_path: None,
        message,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn detect_status_with_paths(_app: &tauri::AppHandle) -> DriverStatus {
    detect_status()
}

#[cfg(not(target_os = "windows"))]
pub fn detect_status() -> DriverStatus {
    DriverStatus {
        installed: false,
        service_running: false,
        hvci_enabled: false,
        bundled_version: BUNDLED_WINDIVERT_VERSION,
        dll_path: None,
        message: "Driver only required on Windows.".into(),
    }
}

#[cfg(target_os = "windows")]
pub fn bundled_paths(app: &tauri::AppHandle) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
    use tauri::Manager;
    let resource = app.path().resource_dir().map_err(|e| format!("resource_dir: {}", e))?;
    let base = resource.join("drivers").join("windivert");
    let dll = base.join("WinDivert.dll");
    let sys = base.join("WinDivert64.sys");
    if !dll.exists() {
        return Err(format!("bundled WinDivert.dll missing at {}", dll.display()));
    }
    if !sys.exists() {
        return Err(format!("bundled WinDivert64.sys missing at {}", sys.display()));
    }
    Ok((dll, sys))
}

/// Install + start the kernel driver service. Uses UAC elevation via
/// `ShellExecuteExW` with verb "runas". The bundled `.sys` is registered
/// in-place from the read-only resource dir (no copy needed).
#[cfg(target_os = "windows")]
pub async fn install(app: tauri::AppHandle) -> Result<DriverStatus, String> {
    // Try the AppHandle-based bundled-paths first (correct for dev mode
    // where resource_dir is `src-tauri/resources/`), fall back to the
    // exe-relative scan (correct for installed builds where
    // resource_dir is `<install>/resources/`).
    let sys_path = bundled_paths(&app)
        .map(|(_dll, sys)| sys)
        .ok()
        .or_else(find_bundled_sys)
        .ok_or_else(|| "bundled WinDivert64.sys not found in resource dir".to_string())?;
    install_service_uac(&sys_path)?;
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    Ok(detect_status_with_paths(&app))
}

#[cfg(not(target_os = "windows"))]
pub async fn install(_app: tauri::AppHandle) -> Result<DriverStatus, String> {
    Err("Driver install only on Windows".into())
}

/// Write a tiny .cmd to %TEMP% that runs `sc.exe` to register + start the
/// service, then ShellExecuteExW it with verb "runas" — Windows shows the
/// UAC prompt + runs cmd.exe elevated. We wait for the cmd to finish before
/// re-querying status.
#[cfg(target_os = "windows")]
fn install_service_uac(sys_path: &std::path::Path) -> Result<(), String> {
    use std::iter::once;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};
    use windows::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let cmd_path = std::env::temp_dir().join("wondersuite-install-driver.cmd");
    let cmd_text = format!(
        "@echo off\r\n\
         sc.exe stop {sn} >nul 2>&1\r\n\
         sc.exe delete {sn} >nul 2>&1\r\n\
         sc.exe create {sn} type= kernel binPath= \"{sys}\" start= demand DisplayName= \"{sd}\"\r\n\
         if errorlevel 1 (echo Failed to create service & exit /b 1)\r\n\
         sc.exe start {sn}\r\n\
         if errorlevel 1 (echo Failed to start service & exit /b 1)\r\n\
         exit /b 0\r\n",
        sn = SERVICE_NAME,
        sd = SERVICE_DISPLAY,
        sys = sys_path.display(),
    );
    std::fs::write(&cmd_path, cmd_text).map_err(|e| format!("write install script: {}", e))?;

    let cmd_wide: Vec<u16> = cmd_path.as_os_str().encode_wide().chain(once(0)).collect();
    let verb_wide: Vec<u16> = "runas".encode_utf16().chain(once(0)).collect();

    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb_wide.as_ptr()),
        lpFile: PCWSTR(cmd_wide.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    unsafe {
        ShellExecuteExW(&mut info as *mut _)
            .map_err(|e| format!("ShellExecuteExW (runas) failed: {}", e))?;
        if !info.hProcess.is_invalid() {
            let _ = WaitForSingleObject(info.hProcess, INFINITE);
            let _ = CloseHandle(info.hProcess);
        }
    }

    let _ = std::fs::remove_file(&cmd_path);
    Ok(())
}

#[cfg(target_os = "windows")]
fn service_query_status() -> Option<String> {
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::System::Services::*;
    let wide_name: Vec<u16> = std::ffi::OsStr::new(SERVICE_NAME).encode_wide().chain(once(0)).collect();
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT).ok()?;
        let svc = OpenServiceW(scm, PCWSTR(wide_name.as_ptr()), SERVICE_QUERY_STATUS).ok();
        let svc = match svc {
            Some(s) => s,
            None => {
                let _ = CloseServiceHandle(scm);
                return None;
            }
        };
        let mut status: SERVICE_STATUS = std::mem::zeroed();
        let qs = QueryServiceStatus(svc, &mut status);
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        if qs.is_err() {
            return Some("installed".into());
        }
        Some(match status.dwCurrentState {
            SERVICE_RUNNING => "running".into(),
            SERVICE_STOPPED => "stopped".into(),
            SERVICE_START_PENDING => "starting".into(),
            SERVICE_STOP_PENDING => "stopping".into(),
            _ => "unknown".into(),
        })
    }
}

#[cfg(not(target_os = "windows"))]
fn service_query_status() -> Option<String> {
    None
}

#[cfg(target_os = "windows")]
fn hvci_is_enabled() -> bool {
    let key = windows_registry::LOCAL_MACHINE.open(
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
    );
    match key {
        Ok(k) => k.get_u32("Enabled").unwrap_or(0) == 1,
        Err(_) => false,
    }
}

#[cfg(not(target_os = "windows"))]
fn hvci_is_enabled() -> bool {
    false
}
