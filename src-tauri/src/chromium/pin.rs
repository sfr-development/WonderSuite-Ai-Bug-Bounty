use super::error::ChromiumError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChromiumPin {
    pub chromium_version: String,
    pub manifest_uri: Option<String>,
    pub platforms: HashMap<String, PlatformPin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformPin {
    pub url: String,
    pub sha256: String,
    pub binary_subpath: String,
}

impl ChromiumPin {
    /// Load + parse the pin JSON from a file on disk.
    pub fn load_from(path: &Path) -> Result<Self, ChromiumError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ChromiumError::Pin(format!("read {}: {}", path.display(), e)))?;
        Self::parse(&text)
    }

    /// Parse pin JSON from a string. Validates structure but not URLs.
    pub fn parse(text: &str) -> Result<Self, ChromiumError> {
        let pin: ChromiumPin =
            serde_json::from_str(text).map_err(|e| ChromiumError::Pin(format!("invalid JSON: {}", e)))?;
        if pin.chromium_version.trim().is_empty() {
            return Err(ChromiumError::Pin("chromium_version is empty".into()));
        }
        if pin.platforms.is_empty() {
            return Err(ChromiumError::Pin("platforms map is empty".into()));
        }
        for (key, p) in &pin.platforms {
            if p.url.trim().is_empty() {
                return Err(ChromiumError::Pin(format!("{}: empty url", key)));
            }
            if p.sha256.len() != 64 {
                return Err(ChromiumError::Pin(format!(
                    "{}: sha256 must be 64 hex chars, got {}",
                    key,
                    p.sha256.len()
                )));
            }
            if p.binary_subpath.trim().is_empty() {
                return Err(ChromiumError::Pin(format!("{}: empty binary_subpath", key)));
            }
        }
        Ok(pin)
    }

    /// Resolve the current platform's key. Returns one of: "win64", "mac-arm64",
    /// "mac-x64", "linux64". Unknown platforms return an error.
    pub fn current_platform_key() -> Result<&'static str, ChromiumError> {
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            return Ok("win64");
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            return Ok("mac-arm64");
        }
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        {
            return Ok("mac-x64");
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            return Ok("linux64");
        }
        #[allow(unreachable_code)]
        Err(ChromiumError::PlatformNotSupported(format!(
            "{} / {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )))
    }

    /// Get the platform pin for the current platform.
    pub fn current(&self) -> Result<&PlatformPin, ChromiumError> {
        let key = Self::current_platform_key()?;
        self.platforms.get(key).ok_or_else(|| ChromiumError::Pin(format!("no entry for platform '{}'", key)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid() {
        let json = r#"{
            "chromium_version": "131.0.6778.85",
            "platforms": {
                "win64": {
                    "url": "https://example/chrome-win64.zip",
                    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                    "binary_subpath": "chrome-win64/chrome.exe"
                }
            }
        }"#;
        let pin = ChromiumPin::parse(json).expect("must parse");
        assert_eq!(pin.chromium_version, "131.0.6778.85");
        assert_eq!(pin.platforms.len(), 1);
    }

    #[test]
    fn rejects_short_sha() {
        let json = r#"{
            "chromium_version": "131.0.6778.85",
            "platforms": {
                "win64": {
                    "url": "https://example/x.zip",
                    "sha256": "abc",
                    "binary_subpath": "chrome.exe"
                }
            }
        }"#;
        assert!(ChromiumPin::parse(json).is_err());
    }

    #[test]
    fn rejects_empty_platforms() {
        let json = r#"{ "chromium_version": "131.0.6778.85", "platforms": {} }"#;
        assert!(ChromiumPin::parse(json).is_err());
    }
}
