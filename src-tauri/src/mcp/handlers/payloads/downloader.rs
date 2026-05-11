use std::path::Path;

/// Download a single payload file from a URL to the target directory.
/// Returns the number of non-empty, non-comment lines (payload count).
pub async fn download_payload_file(url: &str, target_dir: &Path, filename: &str) -> Result<usize, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .user_agent("WonderSuite/1.0 PayloadManager")
        .build()
        .map_err(|e| format!("Client build error: {}", e))?;

    let response =
        client.get(url).send().await.map_err(|e| format!("Download failed for {}: {}", filename, e))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {} for {}: {}", response.status().as_u16(), filename, url));
    }

    let body =
        response.text().await.map_err(|e| format!("Failed to read response body for {}: {}", filename, e))?;

    let payload_count = body
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .count();

    let filepath = target_dir.join(filename);
    std::fs::write(&filepath, &body).map_err(|e| format!("Failed to write {}: {}", filepath.display(), e))?;

    Ok(payload_count)
}
