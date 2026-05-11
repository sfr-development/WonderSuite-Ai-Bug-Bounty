use super::error::ChromiumError;
use std::path::Path;

/// Walk `cache_root/*` and delete every directory whose name isn't the
/// current pinned version. Used at app startup to keep disk usage bounded.
/// Errors deleting individual entries are logged but don't fail the GC.
pub fn gc_old_versions(cache_root: &Path, keep_version: &str) -> Result<usize, ChromiumError> {
    if !cache_root.exists() {
        return Ok(0);
    }
    let mut removed = 0usize;
    for entry in std::fs::read_dir(cache_root)? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == keep_version || name.is_empty() {
            continue;
        }
        // Only purge directories whose name looks like a Chromium version (a.b.c.d)
        // — defensive so we never wipe an unrelated user dir.
        if !looks_like_version(name) {
            continue;
        }
        match std::fs::remove_dir_all(&path) {
            Ok(_) => {
                removed += 1;
                println!("[Chromium] GC: removed old version {}", path.display());
            }
            Err(e) => {
                eprintln!("[Chromium] GC: failed to remove {}: {}", path.display(), e);
            }
        }
    }
    Ok(removed)
}

fn looks_like_version(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 3 {
        return false;
    }
    parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_match() {
        assert!(looks_like_version("131.0.6778.85"));
        assert!(looks_like_version("100.0.0.0"));
        assert!(looks_like_version("1.2.3"));
        assert!(!looks_like_version("foo"));
        assert!(!looks_like_version("1.2"));
        assert!(!looks_like_version(""));
        assert!(!looks_like_version("131-0-6778-85"));
    }
}
