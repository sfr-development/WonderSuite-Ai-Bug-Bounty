use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message as WsMessage;

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    WsMessage,
>;
type WsStream = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

/// Global CDP command ID counter (avoids borrow issues)
static CDP_CMD_ID: AtomicU64 = AtomicU64::new(100);
fn next_id() -> u64 {
    CDP_CMD_ID.fetch_add(1, Ordering::Relaxed)
}

/// Holds the CDP WebSocket halves behind their own mutexes
pub struct AgentBrowser {
    pub running: AtomicBool,
    pub pid: Mutex<Option<u32>>,
    pub cdp_port: Mutex<u16>,
    pub proxy_port: Mutex<u16>,
    pub headless: AtomicBool,
    pub sink: Mutex<Option<WsSink>>,
    pub stream: Mutex<Option<WsStream>>,
    pub current_url: Mutex<String>,
    pub current_title: Mutex<String>,
}

pub type AgentBrowserState = Arc<AgentBrowser>;

pub fn create_agent_browser_state() -> AgentBrowserState {
    Arc::new(AgentBrowser {
        running: AtomicBool::new(false),
        pid: Mutex::new(None),
        cdp_port: Mutex::new(9333),
        proxy_port: Mutex::new(8080),
        headless: AtomicBool::new(false),
        sink: Mutex::new(None),
        stream: Mutex::new(None),
        current_url: Mutex::new(String::new()),
        current_title: Mutex::new(String::new()),
    })
}

async fn cdp_send_raw(
    sink: &mut WsSink,
    stream: &mut WsStream,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let id = next_id();
    let cmd = serde_json::json!({ "id": id, "method": method, "params": params });
    sink.send(WsMessage::Text(cmd.to_string().into())).await.map_err(|e| format!("CDP send: {}", e))?;

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(15);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("CDP timeout (15s)".into());
        }
        match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(Ok(WsMessage::Text(text)))) => {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                    if json.get("id").and_then(|v| v.as_u64()) == Some(id) {
                        if let Some(err) = json.get("error") {
                            return Err(format!("CDP error: {}", err));
                        }
                        return Ok(json.get("result").cloned().unwrap_or(serde_json::json!({})));
                    }
                }
            }
            Ok(Some(Err(e))) => return Err(format!("CDP WS: {}", e)),
            Ok(None) => return Err("CDP closed".into()),
            Err(_) => return Err("CDP timeout".into()),
            _ => {}
        }
    }
}

/// Fire-and-forget CDP
async fn cdp_fire(sink: &mut WsSink, method: &str, params: serde_json::Value) -> Result<(), String> {
    let id = next_id();
    let cmd = serde_json::json!({ "id": id, "method": method, "params": params });
    sink.send(WsMessage::Text(cmd.to_string().into())).await.map_err(|e| format!("CDP send: {}", e))
}

/// Execute a CDP command using the shared state (auto-reconnects if needed)
async fn cdp(
    state: &AgentBrowserState,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    if state.sink.lock().await.is_none() && state.running.load(Ordering::Relaxed) {
        connect_cdp(state).await;
    }
    let mut sink_guard = state.sink.lock().await;
    let mut stream_guard = state.stream.lock().await;
    let sink = sink_guard
        .as_mut()
        .ok_or("CDP not connected — launch the agent browser first with agent_browser_launch")?;
    let stream = stream_guard.as_mut().ok_or("CDP not connected")?;
    cdp_send_raw(sink, stream, method, params).await
}

/// Execute JS and return the value
async fn cdp_eval(state: &AgentBrowserState, expr: &str) -> Result<serde_json::Value, String> {
    let r = cdp(
        state,
        "Runtime.evaluate",
        serde_json::json!({
            "expression": expr, "returnByValue": true, "awaitPromise": true
        }),
    )
    .await?;
    if let Some(exc) = r.get("exceptionDetails") {
        return Err(format!("JS error: {}", exc));
    }
    Ok(r.pointer("/result/value").cloned().unwrap_or(serde_json::json!(null)))
}

/// Execute JS returning string
async fn cdp_eval_str(state: &AgentBrowserState, expr: &str) -> Result<String, String> {
    let v = cdp_eval(state, expr).await?;
    Ok(v.as_str().unwrap_or("").to_string())
}

fn bezier_points(x1: f64, y1: f64, x2: f64, y2: f64, steps: usize) -> Vec<(f64, f64)> {
    let mut rng = rand::thread_rng();
    let cx1 = x1 + (x2 - x1) * rng.gen_range(0.2..0.5) + rng.gen_range(-30.0..30.0);
    let cy1 = y1 + (y2 - y1) * rng.gen_range(0.0..0.3) + rng.gen_range(-30.0..30.0);
    let cx2 = x1 + (x2 - x1) * rng.gen_range(0.5..0.8) + rng.gen_range(-20.0..20.0);
    let cy2 = y1 + (y2 - y1) * rng.gen_range(0.7..1.0) + rng.gen_range(-20.0..20.0);
    (0..=steps)
        .map(|i| {
            let t = i as f64 / steps as f64;
            let mt = 1.0 - t;
            let x =
                mt.powi(3) * x1 + 3.0 * mt.powi(2) * t * cx1 + 3.0 * mt * t.powi(2) * cx2 + t.powi(3) * x2;
            let y =
                mt.powi(3) * y1 + 3.0 * mt.powi(2) * t * cy1 + 3.0 * mt * t.powi(2) * cy2 + t.powi(3) * y2;
            (x, y)
        })
        .collect()
}

fn typing_delay() -> u64 {
    let mut rng = rand::thread_rng();
    if rng.gen_range(0..10) == 0 {
        rng.gen_range(200..500)
    } else {
        rng.gen_range(50..180)
    }
}

fn stealth_js() -> &'static str {
    r#"
Object.defineProperty(navigator,'webdriver',{get:()=>undefined});
for(const k of Object.keys(window)){if(k.startsWith('cdc_')||k.startsWith('__webdriver')||k.startsWith('$cdc_'))delete window[k]}
if(!window.chrome)window.chrome={};
if(!window.chrome.runtime)window.chrome.runtime={connect:function(){},sendMessage:function(){},id:undefined};
const _oq=window.navigator.permissions?.query;
if(_oq)window.navigator.permissions.query=function(p){if(p.name==='notifications')return Promise.resolve({state:Notification.permission});return _oq.call(this,p)};
Object.defineProperty(navigator,'plugins',{get:()=>{const a=[{name:'Chrome PDF Plugin',filename:'pdf',description:'PDF'},{name:'Chrome PDF Viewer',filename:'pdf2',description:''},{name:'Native Client',filename:'nacl',description:''}];a.length=3;a.item=i=>a[i];a.namedItem=n=>a.find(p=>p.name===n);a.refresh=()=>{};return a}});
Object.defineProperty(navigator,'languages',{get:()=>['en-US','en']});
if(!navigator.hardwareConcurrency)Object.defineProperty(navigator,'hardwareConcurrency',{get:()=>8});
const _gp=WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter=function(p){if(p===37445)return'Google Inc. (NVIDIA)';if(p===37446)return'ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11)';return _gp.call(this,p)};
if(typeof WebGL2RenderingContext!=='undefined'){const _gp2=WebGL2RenderingContext.prototype.getParameter;WebGL2RenderingContext.prototype.getParameter=function(p){if(p===37445)return'Google Inc. (NVIDIA)';if(p===37446)return'ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11)';return _gp2.call(this,p)}}
if(!navigator.connection)Object.defineProperty(navigator,'connection',{get:()=>({effectiveType:'4g',rtt:50,downlink:10,saveData:false})});
"#
}

#[tauri::command]
pub async fn agent_browser_launch(
    state: tauri::State<'_, AgentBrowserState>,
    proxy_state: tauri::State<'_, crate::proxy_commands::ProxyAppState>,
    app: tauri::AppHandle,
    proxy_port: Option<u16>,
    headless: Option<bool>,
    cdp_port: Option<u16>,
    user_agent: Option<String>,
) -> Result<serde_json::Value, String> {
    if state.running.load(Ordering::Relaxed) {
        return Err("Agent browser already running".into());
    }

    let port = proxy_port.unwrap_or(8080);
    let cdp = cdp_port.unwrap_or(9333);
    let is_headless = headless.unwrap_or(false);

    if !proxy_state.proxy_state.is_running() {
        let _ = crate::proxy_commands::proxy_start(port, proxy_state.clone(), app).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    }

    let browsers = crate::browser::detect_browsers();
    let browser = browsers.first().ok_or("No Chromium browser found")?;

    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
    let profile_dir = format!("{}/.wondersuite/agent-browser-profile", home);
    std::fs::create_dir_all(&profile_dir).map_err(|e| e.to_string())?;

    let mut args: Vec<String> = vec![
        format!("--remote-debugging-port={}", cdp),
        "--remote-allow-origins=*".into(),
        format!("--proxy-server=127.0.0.1:{}", port),
        format!("--user-data-dir={}", profile_dir),
        "--disable-blink-features=AutomationControlled".into(),
        "--disable-infobars".into(),
        "--flag-switches-begin".into(),
        "--flag-switches-end".into(),
        "--disable-features=IsolateOrigins,site-per-process,AutomationControlled,TranslateUI".into(),
        "--disable-site-isolation-trials".into(),
        "--disable-ipc-flooding-protection".into(),
        "--disable-client-side-phishing-detection".into(),
        "--disable-default-apps".into(),
        "--disable-component-update".into(),
        "--disable-background-networking".into(),
        "--disable-sync".into(),
        "--disable-translate".into(),
        "--metrics-recording-only".into(),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        "--disable-hang-monitor".into(),
        "--window-size=1920,1080".into(),
        "--start-maximized".into(),
        "--ignore-certificate-errors".into(),
        "--allow-insecure-localhost".into(),
        "--disable-extensions".into(),
    ];
    if is_headless {
        args.push("--headless=new".into());
    }
    if let Some(ref ua) = user_agent {
        args.push(format!("--user-agent={}", ua));
    }
    args.push("about:blank".into());

    #[cfg(target_os = "windows")]
    let child = {
        use std::os::windows::process::CommandExt;
        std::process::Command::new(&browser.path)
            .args(&args)
            .creation_flags(0x08000000)
            .spawn()
            .map_err(|e| format!("Launch failed: {}", e))?
    };
    #[cfg(not(target_os = "windows"))]
    let child = std::process::Command::new(&browser.path)
        .args(&args)
        .spawn()
        .map_err(|e| format!("Launch failed: {}", e))?;

    let pid = child.id();
    state.running.store(true, Ordering::Relaxed);
    state.headless.store(is_headless, Ordering::Relaxed);
    *state.pid.lock().await = Some(pid);
    *state.cdp_port.lock().await = cdp;
    *state.proxy_port.lock().await = port;

    println!("[AgentBrowser] ✓ Launched {} PID={} CDP={} Proxy={}", browser.name, pid, cdp, port);

    let sc = state.inner().clone();
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        connect_cdp(&sc).await;
    });

    Ok(serde_json::json!({
        "success": true, "pid": pid, "browser": browser.name,
        "cdp_port": cdp, "proxy_port": port, "headless": is_headless, "stealth": true,
    }))
}

async fn connect_cdp(state: &AgentBrowserState) {
    let cdp_port = *state.cdp_port.lock().await;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap();

    for attempt in 0..12 {
        let url = format!("http://127.0.0.1:{}/json", cdp_port);
        if let Ok(resp) = client.get(&url).send().await {
            if let Ok(text) = resp.text().await {
                if let Ok(pages) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                    for page in &pages {
                        if page.get("type").and_then(|v| v.as_str()) == Some("page") {
                            if let Some(ws_url) = page.get("webSocketDebuggerUrl").and_then(|v| v.as_str()) {
                                if let Ok((ws, _)) = tokio_tungstenite::connect_async(ws_url).await {
                                    let (sink, stream) = ws.split();
                                    *state.sink.lock().await = Some(sink);
                                    *state.stream.lock().await = Some(stream);

                                    {
                                        let mut s = state.sink.lock().await;
                                        let mut r = state.stream.lock().await;
                                        if let (Some(sk), Some(st)) = (s.as_mut(), r.as_mut()) {
                                            let _ =
                                                cdp_send_raw(sk, st, "Page.enable", serde_json::json!({}))
                                                    .await;
                                            let _ =
                                                cdp_send_raw(sk, st, "Network.enable", serde_json::json!({}))
                                                    .await;
                                            let _ = cdp_send_raw(sk, st, "DOM.enable", serde_json::json!({}))
                                                .await;
                                            let _ =
                                                cdp_send_raw(sk, st, "Runtime.enable", serde_json::json!({}))
                                                    .await;
                                            let _ = cdp_send_raw(
                                                sk,
                                                st,
                                                "Page.addScriptToEvaluateOnNewDocument",
                                                serde_json::json!({ "source": stealth_js() }),
                                            )
                                            .await;
                                            let _ = cdp_send_raw(sk, st, "Runtime.evaluate",
                                                serde_json::json!({ "expression": stealth_js(), "returnByValue": false })).await;
                                        }
                                    }

                                    println!("[AgentBrowser] ✓ CDP connected (attempt {})", attempt + 1);
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;
    }
    eprintln!("[AgentBrowser] CDP connection failed after 12 attempts");
}

#[tauri::command]
pub async fn agent_browser_close(state: tauri::State<'_, AgentBrowserState>) -> Result<String, String> {
    if !state.running.load(Ordering::Relaxed) {
        return Ok("Not running".into());
    }

    let _ = cdp(&state, "Browser.close", serde_json::json!({})).await;

    if let Some(pid) = *state.pid.lock().await {
        #[cfg(target_os = "windows")]
        {
            let _ = std::process::Command::new("taskkill").args(["/PID", &pid.to_string(), "/F"]).output();
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = std::process::Command::new("kill").arg(pid.to_string()).output();
        }
    }

    state.running.store(false, Ordering::Relaxed);
    *state.pid.lock().await = None;
    *state.sink.lock().await = None;
    *state.stream.lock().await = None;
    Ok("Agent browser closed".into())
}

#[tauri::command]
pub async fn agent_browser_status(
    state: tauri::State<'_, AgentBrowserState>,
) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "running": state.running.load(Ordering::Relaxed),
        "pid": *state.pid.lock().await,
        "cdp_port": *state.cdp_port.lock().await,
        "proxy_port": *state.proxy_port.lock().await,
        "headless": state.headless.load(Ordering::Relaxed),
        "current_url": *state.current_url.lock().await,
        "current_title": *state.current_title.lock().await,
        "cdp_connected": state.sink.lock().await.is_some(),
    }))
}

#[tauri::command]
pub async fn agent_browser_navigate(
    state: tauri::State<'_, AgentBrowserState>,
    url: String,
) -> Result<serde_json::Value, String> {
    if state.sink.lock().await.is_none() && state.running.load(Ordering::Relaxed) {
        connect_cdp(&state).await;
        if state.sink.lock().await.is_none() {
            return Err("CDP not connected — browser may still be starting. Wait a moment and retry.".into());
        }
    }
    let result = cdp(&state, "Page.navigate", serde_json::json!({ "url": url })).await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
    let cur_url = cdp_eval_str(&state, "document.location.href").await.unwrap_or_default();
    let cur_title = cdp_eval_str(&state, "document.title").await.unwrap_or_default();
    *state.current_url.lock().await = cur_url.clone();
    *state.current_title.lock().await = cur_title.clone();
    Ok(
        serde_json::json!({ "success": true, "url": cur_url, "title": cur_title, "frame_id": result.get("frameId") }),
    )
}

#[tauri::command]
pub async fn agent_browser_reload(state: tauri::State<'_, AgentBrowserState>) -> Result<String, String> {
    cdp(&state, "Page.reload", serde_json::json!({ "ignoreCache": true })).await?;
    Ok("Reloaded".into())
}

#[tauri::command]
pub async fn agent_browser_go_back(state: tauri::State<'_, AgentBrowserState>) -> Result<String, String> {
    let hist = cdp(&state, "Page.getNavigationHistory", serde_json::json!({})).await?;
    let idx = hist.get("currentIndex").and_then(|v| v.as_i64()).unwrap_or(0);
    if idx > 0 {
        if let Some(entries) = hist.get("entries").and_then(|v| v.as_array()) {
            if let Some(entry) = entries.get((idx - 1) as usize) {
                if let Some(eid) = entry.get("id").and_then(|v| v.as_i64()) {
                    cdp(&state, "Page.navigateToHistoryEntry", serde_json::json!({ "entryId": eid })).await?;
                }
            }
        }
    }
    Ok("Back".into())
}

#[tauri::command]
pub async fn agent_browser_go_forward(state: tauri::State<'_, AgentBrowserState>) -> Result<String, String> {
    let hist = cdp(&state, "Page.getNavigationHistory", serde_json::json!({})).await?;
    let idx = hist.get("currentIndex").and_then(|v| v.as_i64()).unwrap_or(0);
    if let Some(entries) = hist.get("entries").and_then(|v| v.as_array()) {
        if (idx + 1) < entries.len() as i64 {
            if let Some(entry) = entries.get((idx + 1) as usize) {
                if let Some(eid) = entry.get("id").and_then(|v| v.as_i64()) {
                    cdp(&state, "Page.navigateToHistoryEntry", serde_json::json!({ "entryId": eid })).await?;
                }
            }
        }
    }
    Ok("Forward".into())
}

#[tauri::command]
pub async fn agent_browser_get_url(state: tauri::State<'_, AgentBrowserState>) -> Result<String, String> {
    cdp_eval_str(&state, "document.location.href").await
}

#[tauri::command]
pub async fn agent_browser_get_title(state: tauri::State<'_, AgentBrowserState>) -> Result<String, String> {
    cdp_eval_str(&state, "document.title").await
}

#[tauri::command]
pub async fn agent_browser_get_content(state: tauri::State<'_, AgentBrowserState>) -> Result<String, String> {
    let html = cdp_eval_str(&state, "document.documentElement.outerHTML").await?;
    if html.len() > 50000 {
        Ok(format!("{}…(truncated {})", &html[..50000], html.len()))
    } else {
        Ok(html)
    }
}

#[tauri::command]
pub async fn agent_browser_get_text(state: tauri::State<'_, AgentBrowserState>) -> Result<String, String> {
    let text = cdp_eval_str(&state, "document.body?.innerText||''").await?;
    if text.len() > 30000 {
        Ok(format!("{}…(truncated)", &text[..30000]))
    } else {
        Ok(text)
    }
}

#[tauri::command]
pub async fn agent_browser_query_selector(
    state: tauri::State<'_, AgentBrowserState>,
    selector: String,
) -> Result<serde_json::Value, String> {
    let js = format!(
        r#"(()=>{{const el=document.querySelector('{}');if(!el)return null;const r=el.getBoundingClientRect();return{{tag:el.tagName.toLowerCase(),id:el.id||null,className:el.className||null,text:(el.innerText||'').slice(0,500),href:el.href||null,value:el.value||null,type:el.type||null,name:el.name||null,x:r.x+r.width/2,y:r.y+r.height/2,width:r.width,height:r.height,visible:r.width>0&&r.height>0}}}})()"#,
        selector.replace('\'', "\\'")
    );
    cdp_eval(&state, &js).await
}

#[tauri::command]
pub async fn agent_browser_query_selector_all(
    state: tauri::State<'_, AgentBrowserState>,
    selector: String,
) -> Result<serde_json::Value, String> {
    let js = format!(
        r#"(()=>{{const els=document.querySelectorAll('{}');return Array.from(els).slice(0,100).map(el=>{{const r=el.getBoundingClientRect();return{{tag:el.tagName.toLowerCase(),id:el.id||null,text:(el.innerText||'').slice(0,200),href:el.href||null,value:el.value||null,name:el.name||null,x:r.x+r.width/2,y:r.y+r.height/2}}}})}})()"#,
        selector.replace('\'', "\\'")
    );
    cdp_eval(&state, &js).await
}

#[tauri::command]
pub async fn agent_browser_get_links(
    state: tauri::State<'_, AgentBrowserState>,
) -> Result<serde_json::Value, String> {
    cdp_eval(&state, "Array.from(document.querySelectorAll('a[href]')).slice(0,200).map(a=>({href:a.href,text:(a.innerText||'').slice(0,100)}))").await
}

#[tauri::command]
pub async fn agent_browser_get_forms(
    state: tauri::State<'_, AgentBrowserState>,
) -> Result<serde_json::Value, String> {
    cdp_eval(&state, r#"Array.from(document.querySelectorAll('form')).map(f=>({action:f.action,method:f.method,id:f.id,fields:Array.from(f.querySelectorAll('input,select,textarea')).map(i=>({tag:i.tagName.toLowerCase(),name:i.name,type:i.type,id:i.id,value:i.value,placeholder:i.placeholder||null,required:i.required}))}))"#).await
}

#[tauri::command]
pub async fn agent_browser_get_inputs(
    state: tauri::State<'_, AgentBrowserState>,
) -> Result<serde_json::Value, String> {
    cdp_eval(&state, r#"Array.from(document.querySelectorAll('input,select,textarea')).slice(0,100).map(i=>{const r=i.getBoundingClientRect();return{tag:i.tagName.toLowerCase(),name:i.name,type:i.type,id:i.id,value:i.value,placeholder:i.placeholder||null,required:i.required,x:r.x+r.width/2,y:r.y+r.height/2}})"#).await
}

#[tauri::command]
pub async fn agent_browser_click(
    state: tauri::State<'_, AgentBrowserState>,
    selector: String,
) -> Result<String, String> {
    let js = format!(
        r#"(()=>{{const el=document.querySelector('{}');if(!el)return null;el.scrollIntoView({{block:'center'}});const r=el.getBoundingClientRect();return{{x:r.x+r.width/2,y:r.y+r.height/2}}}})()"#,
        selector.replace('\'', "\\'")
    );
    let pos = cdp_eval(&state, &js).await?;
    if pos.is_null() {
        return Err(format!("Element not found: {}", selector));
    }
    let x = pos.get("x").and_then(|v| v.as_f64()).ok_or("No x")?;
    let y = pos.get("y").and_then(|v| v.as_f64()).ok_or("No y")?;

    let (points, move_delays, click_delay) = {
        let mut rng = rand::thread_rng();
        let pts = bezier_points(rng.gen_range(100.0..500.0), rng.gen_range(100.0..400.0), x, y, 12);
        let delays: Vec<u64> = (0..pts.len()).map(|_| rng.gen_range(8u64..20)).collect();
        let cd: u64 = rng.gen_range(40..100);
        (pts, delays, cd)
    };

    {
        let mut sink_guard = state.sink.lock().await;
        if let Some(sink) = sink_guard.as_mut() {
            for (i, (px, py)) in points.iter().enumerate() {
                let _ = cdp_fire(
                    sink,
                    "Input.dispatchMouseEvent",
                    serde_json::json!({
                        "type": "mouseMoved", "x": *px as i64, "y": *py as i64
                    }),
                )
                .await;
                tokio::time::sleep(tokio::time::Duration::from_millis(move_delays[i])).await;
            }
        }
    }

    cdp(
        &state,
        "Input.dispatchMouseEvent",
        serde_json::json!({
            "type": "mousePressed", "x": x as i64, "y": y as i64, "button": "left", "clickCount": 1
        }),
    )
    .await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(click_delay)).await;
    cdp(
        &state,
        "Input.dispatchMouseEvent",
        serde_json::json!({
            "type": "mouseReleased", "x": x as i64, "y": y as i64, "button": "left", "clickCount": 1
        }),
    )
    .await?;

    Ok(format!("Clicked {} at ({:.0},{:.0})", selector, x, y))
}

#[tauri::command]
pub async fn agent_browser_type(
    state: tauri::State<'_, AgentBrowserState>,
    selector: String,
    text: String,
) -> Result<String, String> {
    agent_browser_click(state.clone(), selector.clone()).await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let clear_js = format!("(()=>{{const el=document.querySelector('{}');if(el){{el.value='';el.dispatchEvent(new Event('input',{{bubbles:true}}))}}}})()", selector.replace('\'', "\\'"));
    let _ = cdp_eval(&state, &clear_js).await;

    let delays: Vec<u64> = {
        let mut rng = rand::thread_rng();
        text.chars()
            .map(|_| if rng.gen_range(0..10) == 0 { rng.gen_range(200..500) } else { rng.gen_range(50..180) })
            .collect()
    };

    for (i, ch) in text.chars().enumerate() {
        let key_text = ch.to_string();
        cdp(
            &state,
            "Input.dispatchKeyEvent",
            serde_json::json!({
                "type": "keyDown", "text": key_text, "key": key_text
            }),
        )
        .await?;
        cdp(
            &state,
            "Input.dispatchKeyEvent",
            serde_json::json!({
                "type": "char", "text": key_text
            }),
        )
        .await?;
        cdp(
            &state,
            "Input.dispatchKeyEvent",
            serde_json::json!({
                "type": "keyUp", "key": key_text
            }),
        )
        .await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(delays[i])).await;
    }
    Ok(format!("Typed {} chars into {}", text.len(), selector))
}

#[tauri::command]
pub async fn agent_browser_press_key(
    state: tauri::State<'_, AgentBrowserState>,
    key: String,
) -> Result<String, String> {
    cdp(&state, "Input.dispatchKeyEvent", serde_json::json!({ "type": "keyDown", "key": key, "code": key }))
        .await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    cdp(&state, "Input.dispatchKeyEvent", serde_json::json!({ "type": "keyUp", "key": key, "code": key }))
        .await?;
    Ok(format!("Pressed {}", key))
}

#[tauri::command]
pub async fn agent_browser_scroll(
    state: tauri::State<'_, AgentBrowserState>,
    direction: String,
    amount: Option<i64>,
) -> Result<String, String> {
    let d = amount.unwrap_or(300);
    let (dx, dy) = match direction.as_str() {
        "up" => (0, -d),
        "left" => (-d, 0),
        "right" => (d, 0),
        _ => (0, d),
    };
    cdp(
        &state,
        "Input.dispatchMouseEvent",
        serde_json::json!({
            "type": "mouseWheel", "x": 400, "y": 400, "deltaX": dx, "deltaY": dy
        }),
    )
    .await?;
    Ok(format!("Scrolled {} {}", direction, d))
}

#[tauri::command]
pub async fn agent_browser_select_option(
    state: tauri::State<'_, AgentBrowserState>,
    selector: String,
    value: String,
) -> Result<String, String> {
    let js = format!(
        r#"(()=>{{const el=document.querySelector('{}');if(!el)return'not found';el.value='{}';el.dispatchEvent(new Event('change',{{bubbles:true}}));return'selected: '+el.value}})()"#,
        selector.replace('\'', "\\'"),
        value.replace('\'', "\\'")
    );
    cdp_eval_str(&state, &js).await
}

#[tauri::command]
pub async fn agent_browser_fill_form(
    state: tauri::State<'_, AgentBrowserState>,
    fields: HashMap<String, String>,
) -> Result<serde_json::Value, String> {
    let mut results = Vec::new();
    for (sel, val) in &fields {
        match agent_browser_type(state.clone(), sel.clone(), val.clone()).await {
            Ok(msg) => results.push(serde_json::json!({"field": sel, "ok": true, "msg": msg})),
            Err(e) => results.push(serde_json::json!({"field": sel, "ok": false, "msg": e})),
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
    Ok(serde_json::json!({"filled": results.len(), "results": results}))
}

#[tauri::command]
pub async fn agent_browser_clear_field(
    state: tauri::State<'_, AgentBrowserState>,
    selector: String,
) -> Result<String, String> {
    let js = format!(
        r#"(()=>{{const el=document.querySelector('{}');if(!el)return false;el.focus();el.value='';el.dispatchEvent(new Event('input',{{bubbles:true}}));return true}})()"#,
        selector.replace('\'', "\\'")
    );
    cdp_eval(&state, &js).await?;
    Ok(format!("Cleared {}", selector))
}

#[tauri::command]
pub async fn agent_browser_screenshot(
    state: tauri::State<'_, AgentBrowserState>,
    full_page: Option<bool>,
) -> Result<String, String> {
    let mut params = serde_json::json!({ "format": "png" });
    if full_page.unwrap_or(false) {
        let m = cdp(&state, "Page.getLayoutMetrics", serde_json::json!({})).await?;
        if let Some(cs) = m.get("contentSize") {
            let w = cs.get("width").and_then(|v| v.as_f64()).unwrap_or(1920.0);
            let h = cs.get("height").and_then(|v| v.as_f64()).unwrap_or(1080.0).min(16000.0);
            params["clip"] = serde_json::json!({"x":0,"y":0,"width":w,"height":h,"scale":1});
        }
    }
    let r = cdp(&state, "Page.captureScreenshot", params).await?;
    Ok(r.get("data").and_then(|v| v.as_str()).unwrap_or("").to_string())
}

#[tauri::command]
pub async fn agent_browser_screenshot_element(
    state: tauri::State<'_, AgentBrowserState>,
    selector: String,
) -> Result<String, String> {
    let js = format!(
        r#"(()=>{{const el=document.querySelector('{}');if(!el)return null;const r=el.getBoundingClientRect();return{{x:r.x,y:r.y,width:r.width,height:r.height}}}})()"#,
        selector.replace('\'', "\\'")
    );
    let rect = cdp_eval(&state, &js).await?;
    if rect.is_null() {
        return Err("Element not found".into());
    }
    let r = cdp(&state, "Page.captureScreenshot", serde_json::json!({
        "format":"png","clip":{"x":rect["x"],"y":rect["y"],"width":rect["width"],"height":rect["height"],"scale":1}
    })).await?;
    Ok(r.get("data").and_then(|v| v.as_str()).unwrap_or("").to_string())
}

#[tauri::command]
pub async fn agent_browser_set_viewport(
    state: tauri::State<'_, AgentBrowserState>,
    width: u32,
    height: u32,
    device_scale: Option<f64>,
    mobile: Option<bool>,
) -> Result<String, String> {
    cdp(&state, "Emulation.setDeviceMetricsOverride", serde_json::json!({
        "width": width, "height": height, "deviceScaleFactor": device_scale.unwrap_or(1.0), "mobile": mobile.unwrap_or(false)
    })).await?;
    Ok(format!("Viewport {}x{}", width, height))
}

#[tauri::command]
pub async fn agent_browser_evaluate(
    state: tauri::State<'_, AgentBrowserState>,
    expression: String,
) -> Result<serde_json::Value, String> {
    cdp_eval(&state, &expression).await
}

#[tauri::command]
pub async fn agent_browser_evaluate_on_new_doc(
    state: tauri::State<'_, AgentBrowserState>,
    script: String,
) -> Result<String, String> {
    let r =
        cdp(&state, "Page.addScriptToEvaluateOnNewDocument", serde_json::json!({ "source": script })).await?;
    Ok(r.get("identifier").and_then(|v| v.as_str()).unwrap_or("ok").to_string())
}

#[tauri::command]
pub async fn agent_browser_new_tab(
    state: tauri::State<'_, AgentBrowserState>,
    url: Option<String>,
) -> Result<serde_json::Value, String> {
    cdp(&state, "Target.createTarget", serde_json::json!({ "url": url.unwrap_or("about:blank".into()) }))
        .await
}

#[tauri::command]
pub async fn agent_browser_list_tabs(
    state: tauri::State<'_, AgentBrowserState>,
) -> Result<serde_json::Value, String> {
    let cdp_port = *state.cdp_port.lock().await;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|e| e.to_string())?;
    let resp =
        client.get(format!("http://127.0.0.1:{}/json", cdp_port)).send().await.map_err(|e| e.to_string())?;
    let pages: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    Ok(pages)
}

#[tauri::command]
pub async fn agent_browser_close_tab(
    state: tauri::State<'_, AgentBrowserState>,
    target_id: String,
) -> Result<String, String> {
    cdp(&state, "Target.closeTarget", serde_json::json!({ "targetId": target_id })).await?;
    Ok(format!("Closed {}", target_id))
}

#[tauri::command]
pub async fn agent_browser_switch_tab(
    state: tauri::State<'_, AgentBrowserState>,
    target_id: String,
) -> Result<String, String> {
    cdp(&state, "Target.activateTarget", serde_json::json!({ "targetId": target_id })).await?;
    Ok(format!("Switched to {}", target_id))
}

#[tauri::command]
pub async fn agent_browser_get_cookies(
    state: tauri::State<'_, AgentBrowserState>,
) -> Result<serde_json::Value, String> {
    let r = cdp(&state, "Network.getCookies", serde_json::json!({})).await?;
    Ok(r.get("cookies").cloned().unwrap_or(serde_json::json!([])))
}

#[tauri::command]
pub async fn agent_browser_set_cookie(
    state: tauri::State<'_, AgentBrowserState>,
    name: String,
    value: String,
    domain: String,
    path: Option<String>,
) -> Result<String, String> {
    cdp(&state, "Network.setCookie", serde_json::json!({ "name": name, "value": value, "domain": domain, "path": path.unwrap_or("/".into()) })).await?;
    Ok(format!("Cookie {} set", name))
}

#[tauri::command]
pub async fn agent_browser_delete_cookie(
    state: tauri::State<'_, AgentBrowserState>,
    name: String,
    domain: String,
) -> Result<String, String> {
    cdp(&state, "Network.deleteCookies", serde_json::json!({ "name": name, "domain": domain })).await?;
    Ok(format!("Cookie {} deleted", name))
}

#[tauri::command]
pub async fn agent_browser_clear_all_cookies(
    state: tauri::State<'_, AgentBrowserState>,
) -> Result<String, String> {
    cdp(&state, "Network.clearBrowserCookies", serde_json::json!({})).await?;
    Ok("All cookies cleared".into())
}

#[tauri::command]
pub async fn agent_browser_get_local_storage(
    state: tauri::State<'_, AgentBrowserState>,
) -> Result<serde_json::Value, String> {
    let s = cdp_eval_str(&state, "JSON.stringify(Object.fromEntries(Object.entries(localStorage)))").await?;
    Ok(serde_json::from_str(&s).unwrap_or(serde_json::json!({})))
}

#[tauri::command]
pub async fn agent_browser_set_local_storage(
    state: tauri::State<'_, AgentBrowserState>,
    key: String,
    value: String,
) -> Result<String, String> {
    let js = format!("localStorage.setItem('{}','{}')", key.replace('\'', "\\'"), value.replace('\'', "\\'"));
    cdp_eval(&state, &js).await?;
    Ok(format!("Set localStorage[{}]", key))
}

#[tauri::command]
pub async fn agent_browser_wait_for_element(
    state: tauri::State<'_, AgentBrowserState>,
    selector: String,
    timeout_ms: Option<u64>,
) -> Result<bool, String> {
    let deadline =
        tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms.unwrap_or(10000));
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        let r = agent_browser_query_selector(state.clone(), selector.clone()).await;
        if let Ok(v) = &r {
            if !v.is_null() {
                return Ok(true);
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    }
}

#[tauri::command]
pub async fn agent_browser_wait_for_navigation(
    state: tauri::State<'_, AgentBrowserState>,
    timeout_ms: Option<u64>,
) -> Result<String, String> {
    tokio::time::sleep(tokio::time::Duration::from_millis(timeout_ms.unwrap_or(3000).min(15000))).await;
    agent_browser_get_url(state).await
}

#[tauri::command]
pub async fn agent_browser_set_extra_headers(
    state: tauri::State<'_, AgentBrowserState>,
    headers: HashMap<String, String>,
) -> Result<String, String> {
    cdp(&state, "Network.setExtraHTTPHeaders", serde_json::json!({ "headers": headers })).await?;
    Ok(format!("{} headers set", headers.len()))
}

#[tauri::command]
pub async fn agent_browser_block_urls(
    state: tauri::State<'_, AgentBrowserState>,
    patterns: Vec<String>,
) -> Result<String, String> {
    cdp(&state, "Network.setBlockedURLs", serde_json::json!({ "urls": patterns })).await?;
    Ok(format!("Blocking {} patterns", patterns.len()))
}

#[tauri::command]
pub async fn agent_browser_set_user_agent(
    state: tauri::State<'_, AgentBrowserState>,
    user_agent: String,
) -> Result<String, String> {
    cdp(&state, "Network.setUserAgentOverride", serde_json::json!({ "userAgent": user_agent })).await?;
    Ok(format!("UA: {}", user_agent))
}

#[tauri::command]
pub async fn agent_browser_set_geolocation(
    state: tauri::State<'_, AgentBrowserState>,
    latitude: f64,
    longitude: f64,
    accuracy: Option<f64>,
) -> Result<String, String> {
    cdp(
        &state,
        "Emulation.setGeolocationOverride",
        serde_json::json!({
            "latitude": latitude, "longitude": longitude, "accuracy": accuracy.unwrap_or(100.0)
        }),
    )
    .await?;
    Ok(format!("Geo: {},{}", latitude, longitude))
}

#[tauri::command]
pub async fn agent_browser_set_timezone(
    state: tauri::State<'_, AgentBrowserState>,
    timezone_id: String,
) -> Result<String, String> {
    cdp(&state, "Emulation.setTimezoneOverride", serde_json::json!({ "timezoneId": timezone_id })).await?;
    Ok(format!("TZ: {}", timezone_id))
}

#[tauri::command]
pub async fn agent_browser_handle_dialog(
    state: tauri::State<'_, AgentBrowserState>,
    accept: bool,
    prompt_text: Option<String>,
) -> Result<String, String> {
    let mut p = serde_json::json!({ "accept": accept });
    if let Some(t) = prompt_text {
        p["promptText"] = serde_json::json!(t);
    }
    cdp(&state, "Page.handleJavaScriptDialog", p).await?;
    Ok(if accept { "Accepted" } else { "Dismissed" }.into())
}
