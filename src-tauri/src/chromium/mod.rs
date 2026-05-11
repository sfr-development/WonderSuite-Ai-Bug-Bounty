// WonderSuite Chromium binary manager.
//
// Responsibilities:
// - Read the pinned Chromium version from `resources/chromium_pin.json`
// - Resolve the platform-specific download URL + SHA-256
// - Download lazily to the user-data cache dir
// - Verify SHA-256
// - Extract zip
// - Garbage-collect old versions
// - Return the path to the chrome binary for spawn
//
// Used by `browser.rs::resolve_browser_binary` as the default browser source.
// System-Chrome detection is kept as a fallback (advanced setting).

pub mod download;
pub mod error;
pub mod extract;
pub mod gc;
pub mod pin;
pub mod verify;

pub use error::ChromiumError;
pub use pin::{ChromiumPin, PlatformPin};

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tauri::{AppHandle, Manager};

const VERIFIED_MARKER: &str = ".verified";

pub struct ChromiumManager {
    app: AppHandle,
    cache_dir: PathBuf,
    extension_cache_dir: PathBuf,
    pin: ChromiumPin,
}

impl ChromiumManager {
    /// Constructs the manager. Reads the pin file from app resources.
    /// Searches a small set of candidate paths to be tolerant of differences
    /// between dev mode, MSI install layout, and NSIS install layout.
    pub fn new(app: &AppHandle) -> Result<Self, ChromiumError> {
        let pin_path = resolve_resource_file(app, "chromium_pin.json")
            .ok_or_else(|| ChromiumError::Pin("chromium_pin.json not found in resource dir".into()))?;
        let pin = ChromiumPin::load_from(&pin_path)?;

        let data_dir = app
            .path()
            .app_local_data_dir()
            .map_err(|e| ChromiumError::Pin(format!("resolve app_local_data_dir: {}", e)))?;
        let cache_dir = data_dir.join("chromium");
        let extension_cache_dir = data_dir.join("extensions").join("wondersuite-extension");

        Ok(Self { app: app.clone(), cache_dir, extension_cache_dir, pin })
    }

    pub fn pinned_version(&self) -> &str {
        &self.pin.chromium_version
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    pub fn pin(&self) -> &ChromiumPin {
        &self.pin
    }

    /// Returns the absolute path to the Chromium binary. Downloads + verifies
    /// + extracts on first call. Subsequent calls are O(1) once `.verified`
    /// exists.
    pub async fn ensure(&self, cancel: Arc<AtomicBool>) -> Result<PathBuf, ChromiumError> {
        let platform = self.pin.current()?;
        let version_dir = self.cache_dir.join(&self.pin.chromium_version);
        let binary_path = version_dir.join(&platform.binary_subpath);
        let marker = version_dir.join(VERIFIED_MARKER);

        if marker.exists() && binary_path.exists() {
            return Ok(binary_path);
        }

        // Refuse to proceed against a placeholder hash — would be a silent
        // skip of integrity verification. The refresh script (or the update
        // workflow) is the only path that should produce a valid pin.
        if platform.sha256.chars().all(|c| c == '0') {
            return Err(ChromiumError::Pin(format!(
                "platform '{}' has a zero-placeholder SHA256 — run `node scripts/refresh-chromium-pin.mjs --force` to fill real hashes before launching the browser",
                ChromiumPin::current_platform_key()?
            )));
        }

        // Tear down any partial install for this version (could be from a
        // previous interrupted run).
        if version_dir.exists() {
            std::fs::remove_dir_all(&version_dir)?;
        }
        std::fs::create_dir_all(&version_dir)?;

        // Step 1: download to a temp file
        let zip_path = version_dir.join("chrome.zip");
        download::download_to_file(
            &self.app,
            &platform.url,
            &zip_path,
            &self.pin.chromium_version,
            cancel.clone(),
        )
        .await?;

        // Step 2: verify SHA-256
        download::emit(
            &self.app,
            download::DownloadProgress {
                phase: "verify",
                downloaded: 0,
                total: 0,
                version: self.pin.chromium_version.clone(),
            },
        );
        verify::verify_sha256(&zip_path, &platform.sha256)?;

        // Step 3: extract
        download::emit(
            &self.app,
            download::DownloadProgress {
                phase: "extract",
                downloaded: 0,
                total: 0,
                version: self.pin.chromium_version.clone(),
            },
        );
        extract::extract_zip(&zip_path, &version_dir)?;
        let _ = std::fs::remove_file(&zip_path);

        // Step 4: ensure binary is executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if binary_path.exists() {
                let mut perm = std::fs::metadata(&binary_path)?.permissions();
                perm.set_mode(perm.mode() | 0o111);
                std::fs::set_permissions(&binary_path, perm)?;
            }
        }

        // macOS: best-effort quarantine removal so Gatekeeper doesn't gate us
        #[cfg(target_os = "macos")]
        {
            let app_root = binary_path
                .ancestors()
                .find(|p| p.extension().and_then(|s| s.to_str()) == Some("app"))
                .unwrap_or(&version_dir);
            let _ = std::process::Command::new("xattr")
                .args(["-dr", "com.apple.quarantine"])
                .arg(app_root)
                .output();
        }

        if !binary_path.exists() {
            return Err(ChromiumError::Pin(format!(
                "binary not found after extract: {}",
                binary_path.display()
            )));
        }

        // Step 5: write the verified marker
        std::fs::write(&marker, self.pin.chromium_version.as_bytes())?;

        // Step 6: best-effort GC of old versions
        let _ = gc::gc_old_versions(&self.cache_dir, &self.pin.chromium_version);

        download::emit(
            &self.app,
            download::DownloadProgress {
                phase: "ready",
                downloaded: 0,
                total: 0,
                version: self.pin.chromium_version.clone(),
            },
        );

        Ok(binary_path)
    }

    /// Copy the bundled `wondersuite-extension/` from app resources to a
    /// stable read/write cache location. Chrome's `--load-extension` requires
    /// a regular dir, not a path inside an .msi / .deb / .app resource bundle.
    /// Subsequent calls re-sync the cache when the extension's version differs.
    pub fn extension_path(&self) -> Result<PathBuf, ChromiumError> {
        let src = resolve_resource_dir(&self.app, "wondersuite-extension").ok_or_else(|| {
            ChromiumError::Pin("bundled wondersuite-extension dir not found in resource dir".into())
        })?;

        // Cache-invalidation by full-tree hash. Previously we compared only
        // manifest.json — that meant edits to content/stealth.js shipped in a
        // new app version were SILENTLY IGNORED because the manifest hadn't
        // changed. Hash every file in the source tree; bust the cache if any
        // byte differs.
        let dst = &self.extension_cache_dir;
        let src_hash = hash_directory(&src).unwrap_or_default();
        let hash_marker = dst.join(".source_hash");
        if dst.exists() {
            if let Ok(cached) = std::fs::read_to_string(&hash_marker) {
                if cached.trim() == src_hash {
                    return Ok(dst.clone());
                }
            }
            let _ = std::fs::remove_dir_all(dst);
        }
        copy_dir_recursive(&src, dst)?;
        let _ = std::fs::write(&hash_marker, &src_hash);
        Ok(dst.clone())
    }

    /// Best-effort GC. Called from app startup.
    pub fn gc(&self) {
        let _ = gc::gc_old_versions(&self.cache_dir, &self.pin.chromium_version);
    }

    /// True iff a verified install of the pinned version already exists.
    pub fn is_cached(&self) -> bool {
        let Ok(platform) = self.pin.current() else { return false };
        let version_dir = self.cache_dir.join(&self.pin.chromium_version);
        version_dir.join(VERIFIED_MARKER).exists() && version_dir.join(&platform.binary_subpath).exists()
    }
}

/// SHA-256 of a directory's full file content, deterministic. Used for
/// extension-cache invalidation in ChromiumManager::extension_path.
fn hash_directory(path: &Path) -> Result<String, ChromiumError> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut entries: Vec<std::path::PathBuf> = walk_files(path)?;
    entries.sort();
    for p in entries {
        if let Ok(rel) = p.strip_prefix(path) {
            hasher.update(rel.to_string_lossy().as_bytes());
        }
        if let Ok(bytes) = std::fs::read(&p) {
            hasher.update(&bytes);
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn walk_files(root: &Path) -> Result<Vec<std::path::PathBuf>, ChromiumError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            out.extend(walk_files(&p)?);
        } else if p.is_file() {
            out.push(p);
        }
    }
    Ok(out)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), ChromiumError> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Tolerant resource-file lookup. Tries every reasonable place a Tauri bundle
/// might put a resource: the canonical `BaseDirectory::Resource`, plus the
/// exe-relative `_up_/<name>`, `resources/<name>`, and a dev-mode fallback to
/// `src-tauri/resources/<name>`. Returns the first existing path.
fn resolve_resource_file(app: &AppHandle, name: &str) -> Option<PathBuf> {
    let candidates = resource_candidates(app, name);
    candidates.into_iter().find(|p| p.is_file())
}

/// Same as resolve_resource_file but for directories.
fn resolve_resource_dir(app: &AppHandle, name: &str) -> Option<PathBuf> {
    let candidates = resource_candidates(app, name);
    candidates.into_iter().find(|p| p.is_dir())
}

fn resource_candidates(app: &AppHandle, name: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();

    // 1. The "official" Tauri Resource directory (works in MSI + dev + AppImage).
    if let Ok(base) = app.path().resource_dir() {
        out.push(base.join(name));
        out.push(base.join("resources").join(name));
        out.push(base.join("_up_").join(name));
        out.push(base.join("_up_").join("resources").join(name));
    }

    // 2. Next to the .exe (NSIS install layout on Windows can put resources there).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            out.push(parent.join(name));
            out.push(parent.join("resources").join(name));
        }
    }

    // 3. Dev-mode fallback: looking for src-tauri/resources/<name> when running
    //    from `cargo run` inside the workspace.
    if let Ok(cwd) = std::env::current_dir() {
        out.push(cwd.join("src-tauri").join("resources").join(name));
        out.push(cwd.join("resources").join(name));
    }

    out
}
