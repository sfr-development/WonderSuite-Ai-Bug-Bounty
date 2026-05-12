// Pentest-grade browser MCP module — one persistent CDP socket per session,
// a11y snapshot with ref=eNN IDs, structured stale-ref errors, request capture
// keyed by CDP requestId so replay-to-proxy is a one-shot.

pub mod handlers;
pub mod input;
pub mod network;
pub mod session;
pub mod snapshot;
pub mod stealth_check;

use std::sync::Arc;
use tokio::sync::RwLock;

pub type BrowserSessionState = Arc<RwLock<Option<Arc<session::BrowserSession>>>>;

static SESSION: std::sync::OnceLock<BrowserSessionState> = std::sync::OnceLock::new();
static APP_HANDLE: std::sync::OnceLock<tauri::AppHandle> = std::sync::OnceLock::new();

/// User preference: should `browser_open` default to headless? Defaults to
/// `false` (visible) so the user can intervene on captchas / interactive
/// challenges. Wired to the Settings UI via Tauri commands.
static DEFAULT_HEADLESS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn default_headless() -> bool {
    DEFAULT_HEADLESS.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn set_default_headless(v: bool) {
    DEFAULT_HEADLESS.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// Default human-emulation profile applied to every browser_click / type /
/// scroll / press_key when the caller doesn't override per-call. Stored as
/// u8 (0=Fast, 1=Human, 2=Paranoid) for AtomicU8 simplicity.
static STEALTH_PROFILE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);

pub fn stealth_profile() -> input::StealthProfile {
    match STEALTH_PROFILE.load(std::sync::atomic::Ordering::Relaxed) {
        0 => input::StealthProfile::Fast,
        2 => input::StealthProfile::Paranoid,
        _ => input::StealthProfile::Human,
    }
}

pub fn set_stealth_profile(p: input::StealthProfile) {
    let v: u8 = match p {
        input::StealthProfile::Fast => 0,
        input::StealthProfile::Human => 1,
        input::StealthProfile::Paranoid => 2,
    };
    STEALTH_PROFILE.store(v, std::sync::atomic::Ordering::Relaxed);
}

pub fn state() -> BrowserSessionState {
    SESSION.get_or_init(|| Arc::new(RwLock::new(None))).clone()
}

/// Owned snapshot of the session. Handlers don't hold the RwLock guard across
/// await points — they get an Arc<BrowserSession> and the lock drops here.
pub async fn session() -> Result<Arc<session::BrowserSession>, String> {
    let st = state();
    let g = st.read().await;
    g.as_ref()
        .cloned()
        .ok_or_else(|| "code=NOT_OPEN hint=\"no browser session — call browser_open first\"".to_string())
}

pub fn set_app_handle(h: tauri::AppHandle) {
    let _ = APP_HANDLE.set(h);
}

pub fn app_handle() -> Option<tauri::AppHandle> {
    APP_HANDLE.get().cloned()
}
