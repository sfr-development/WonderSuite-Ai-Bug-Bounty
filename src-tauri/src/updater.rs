use serde::{Deserialize, Serialize};

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO: &str = "sfr-development/WonderSuite-Ai-Bug-Bounty";

#[derive(Debug, Serialize)]
pub struct UpdateInfo {
    pub current: String,
    pub latest: String,
    pub available: bool,
    pub url: String,
    pub body: String,
    pub published_at: String,
    pub assets: Vec<UpdateAsset>,
}

#[derive(Debug, Serialize)]
pub struct UpdateAsset {
    pub name: String,
    pub url: String,
    pub size: u64,
    pub platform: String,
}

#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    body: Option<String>,
    html_url: String,
    published_at: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

#[derive(Debug, Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

fn platform_for(name: &str) -> String {
    let n = name.to_lowercase();
    if n.ends_with(".msi") || n.ends_with(".exe") {
        "windows".into()
    } else if n.ends_with(".dmg") || n.contains("darwin") || n.contains("macos") {
        "macos".into()
    } else if n.ends_with(".appimage") || n.ends_with(".deb") || n.ends_with(".rpm") {
        "linux".into()
    } else {
        "other".into()
    }
}

fn version_greater(latest: &str, current: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> {
        s.trim_start_matches('v')
            .split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.parse().ok())
            .collect()
    };
    let l = parse(latest);
    let c = parse(current);
    let len = l.len().max(c.len());
    for i in 0..len {
        let li = *l.get(i).unwrap_or(&0);
        let ci = *c.get(i).unwrap_or(&0);
        if li > ci {
            return true;
        }
        if li < ci {
            return false;
        }
    }
    false
}

#[tauri::command]
pub async fn check_for_update() -> Result<UpdateInfo, String> {
    let url = format!("https://api.github.com/repos/{}/releases/latest", REPO);
    let client = reqwest::Client::builder()
        .user_agent(format!("WonderSuite/{} (updater)", CURRENT_VERSION))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("HTTP client: {}", e))?;
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("GitHub request failed: {}", e))?;
    if resp.status() == 404 {
        return Ok(UpdateInfo {
            current: CURRENT_VERSION.into(),
            latest: CURRENT_VERSION.into(),
            available: false,
            url: format!("https://github.com/{}/releases", REPO),
            body: "No releases published yet.".into(),
            published_at: String::new(),
            assets: vec![],
        });
    }
    if !resp.status().is_success() {
        return Err(format!("GitHub API returned {}", resp.status()));
    }
    let release: GhRelease = resp.json().await.map_err(|e| format!("Parse error: {}", e))?;
    let latest = release.tag_name.trim_start_matches('v').to_string();
    let available =
        !release.draft && !release.prerelease && version_greater(&release.tag_name, CURRENT_VERSION);
    Ok(UpdateInfo {
        current: CURRENT_VERSION.into(),
        latest,
        available,
        url: release.html_url,
        body: release.body.unwrap_or_default(),
        published_at: release.published_at,
        assets: release
            .assets
            .into_iter()
            .map(|a| {
                let platform = platform_for(&a.name);
                UpdateAsset { name: a.name, url: a.browser_download_url, size: a.size, platform }
            })
            .collect(),
    })
}

#[tauri::command]
pub fn current_version() -> String {
    CURRENT_VERSION.into()
}
