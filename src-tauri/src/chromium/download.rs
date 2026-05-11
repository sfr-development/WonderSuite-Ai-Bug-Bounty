use super::error::ChromiumError;
use futures_util::StreamExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

/// Progress event payload emitted on `chromium:progress` during download.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DownloadProgress {
    pub phase: &'static str, // "download" | "verify" | "extract" | "ready" | "error"
    pub downloaded: u64,
    pub total: u64,
    pub version: String,
}

/// Stream-download `url` to `dest`, emitting Tauri events as bytes arrive.
///
/// Behavior:
/// - Truncates `dest` if it exists.
/// - Aborts cleanly if `cancel` is set, deleting the partial file.
/// - Emits a `chromium:progress` event on the AppHandle every chunk.
pub async fn download_to_file(
    app: &AppHandle,
    url: &str,
    dest: &Path,
    version: &str,
    cancel: Arc<AtomicBool>,
) -> Result<(), ChromiumError> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(false) // CfT hosts on Google's CDN, real certs
        .timeout(std::time::Duration::from_secs(60 * 30))
        .build()?;

    let resp = client.get(url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ChromiumError::Pin(format!("GET {} returned HTTP {}", url, status)));
    }
    let total = resp.content_length().unwrap_or(0);

    let mut file = File::create(dest).await?;
    let mut downloaded: u64 = 0;
    let mut stream = resp.bytes_stream();
    let mut last_emit_ms: i64 = 0;

    emit(app, DownloadProgress { phase: "download", downloaded: 0, total, version: version.into() });

    while let Some(chunk) = stream.next().await {
        if cancel.load(Ordering::Relaxed) {
            drop(file);
            let _ = tokio::fs::remove_file(dest).await;
            return Err(ChromiumError::Cancelled);
        }
        let chunk = chunk?;
        file.write_all(&chunk).await?;
        downloaded += chunk.len() as u64;

        // Throttle event emissions to ~10/s so we don't flood the IPC channel
        let now = chrono::Utc::now().timestamp_millis();
        if now - last_emit_ms > 100 {
            last_emit_ms = now;
            emit(app, DownloadProgress { phase: "download", downloaded, total, version: version.into() });
        }
    }
    file.flush().await?;
    drop(file);

    // Final 100% emit
    emit(
        app,
        DownloadProgress {
            phase: "download",
            downloaded,
            total: total.max(downloaded),
            version: version.into(),
        },
    );

    Ok(())
}

pub fn emit(app: &AppHandle, payload: DownloadProgress) {
    if let Err(e) = app.emit("chromium:progress", payload) {
        eprintln!("[Chromium] failed to emit progress event: {}", e);
    }
}
