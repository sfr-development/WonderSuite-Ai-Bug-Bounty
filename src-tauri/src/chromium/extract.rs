use super::error::ChromiumError;
use std::fs::{self, File};
use std::io::{copy, BufReader};
use std::path::{Path, PathBuf};

/// Extract a ZIP archive into `dest_dir`. Creates `dest_dir` if missing.
///
/// - Preserves file permissions on Unix (CfT's chrome binary needs +x).
/// - Skips entries whose canonicalized path would escape `dest_dir` (zip-slip
///   protection — important when extracting an attacker-controlled archive,
///   even if we SHA-verified upstream).
pub fn extract_zip(archive: &Path, dest_dir: &Path) -> Result<(), ChromiumError> {
    fs::create_dir_all(dest_dir)?;
    let file = File::open(archive)?;
    let mut zip = zip::ZipArchive::new(BufReader::new(file))?;

    let dest_canonical = dunce_canonicalize(dest_dir)?;

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let raw_name = entry.name();
        // Defense in depth: refuse absolute paths and parent-dir traversal.
        if raw_name.starts_with('/')
            || raw_name.starts_with('\\')
            || raw_name.contains("..\\")
            || raw_name.contains("../")
        {
            return Err(ChromiumError::Pin(format!("zip entry escapes dest dir: {}", raw_name)));
        }
        let entry_path = dest_dir.join(entry.mangled_name());

        // After joining, the canonical path must still be under dest_canonical.
        let parent = entry_path.parent().unwrap_or(dest_dir);
        fs::create_dir_all(parent)?;
        if let Ok(canon) = dunce_canonicalize(parent) {
            if !canon.starts_with(&dest_canonical) {
                return Err(ChromiumError::Pin(format!(
                    "zip entry resolves outside dest: {}",
                    entry_path.display()
                )));
            }
        }

        if entry.is_dir() {
            fs::create_dir_all(&entry_path)?;
            continue;
        }

        let mut out = File::create(&entry_path)?;
        copy(&mut entry, &mut out)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = entry.unix_mode() {
                fs::set_permissions(&entry_path, fs::Permissions::from_mode(mode))?;
            }
        }
    }
    Ok(())
}

/// Like `std::fs::canonicalize` but tolerant on Windows (avoids the `\\?\`
/// UNC prefix that breaks `starts_with` comparisons against non-UNC paths).
fn dunce_canonicalize(p: &Path) -> Result<PathBuf, ChromiumError> {
    let abs = std::fs::canonicalize(p)?;
    #[cfg(windows)]
    {
        let s = abs.as_os_str().to_string_lossy().to_string();
        let stripped = s.strip_prefix(r"\\?\").unwrap_or(&s);
        return Ok(PathBuf::from(stripped));
    }
    #[allow(unreachable_code)]
    Ok(abs)
}
