use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChromiumError {
    #[error("download failed: {0}")]
    Download(#[from] reqwest::Error),

    #[error("hash mismatch: expected {expected}, got {got}")]
    HashMismatch { expected: String, got: String },

    #[error("zip extract failed: {0}")]
    Extract(#[from] zip::result::ZipError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("platform not supported: {0}")]
    PlatformNotSupported(String),

    #[error("pin file missing or malformed: {0}")]
    Pin(String),

    #[error("event emit failed: {0}")]
    Emit(String),

    #[error("user cancelled")]
    Cancelled,
}
