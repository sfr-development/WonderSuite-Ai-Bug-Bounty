mod browser;
mod browser_migration;
mod chromium;
mod chromium_commands;
mod commands;
pub mod crawler;
mod crawler_commands;
mod http2;
mod intruder;
mod mcp;
mod oast;
mod oast_commands;
mod osint_commands;
mod payload_commands;
mod port_commands;
mod project;
mod proxy;
mod proxy_commands;
mod reporting;
mod scanner;
mod scanner_commands;
mod session;
mod session_commands;
mod system;
#[cfg(not(target_os = "linux"))]
mod tls_impersonate;
mod updater;
mod websocket_commands;
mod window_manager;

use proxy_commands::ProxyAppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let sys_info = system::SystemInfo::detect();
    println!(
        "[WonderSuite] Platform: {} on {} ({})",
        sys_info.arch_display, sys_info.os, sys_info.os_version
    );
    println!("[WonderSuite] CPU cores: {}", sys_info.cpu_cores);

    let mcp_state = mcp::create_mcp_state();
    let proxy_state = ProxyAppState::new();
    let scanner_state = scanner_commands::create_scanner_state();
    let session_state = session::create_session_state();
    let intruder_state = intruder::create_intruder_state();
    let ws_state = websocket_commands::create_ws_state();
    let window_state = window_manager::create_window_state();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(mcp_state)
        .manage(proxy_state)
        .manage(scanner_state)
        .manage(session_state)
        .manage(intruder_state)
        .manage(ws_state)
        .manage(window_state)
        .invoke_handler(tauri::generate_handler![
            commands::send_http_request,
            commands::mcp_start,
            commands::mcp_stop,
            commands::mcp_status,
            commands::get_mcp_activity,
            commands::get_mcp_activity_stats,
            commands::get_mcp_traffic,
            commands::mcp_list_tools,
            project::list_projects,
            project::create_project,
            project::open_project,
            project::delete_project,
            project::get_project_config,
            project::update_project_config,
            project::duplicate_project,
            project::get_memory_stats,
            proxy_commands::proxy_start,
            proxy_commands::proxy_stop,
            proxy_commands::proxy_status,
            proxy_commands::proxy_toggle_intercept,
            proxy_commands::proxy_toggle_response_intercept,
            proxy_commands::proxy_intercept_forward,
            proxy_commands::proxy_intercept_drop,
            proxy_commands::proxy_get_traffic,
            proxy_commands::proxy_search_traffic,
            proxy_commands::proxy_clear_traffic,
            proxy_commands::proxy_get_pending,
            proxy_commands::proxy_get_ca_cert,
            proxy_commands::proxy_get_match_replace_rules,
            proxy_commands::proxy_add_match_replace_rule,
            proxy_commands::proxy_update_match_replace_rule,
            proxy_commands::proxy_remove_match_replace_rule,
            proxy_commands::proxy_get_interception_rules,
            proxy_commands::proxy_add_interception_rule,
            proxy_commands::proxy_update_interception_rule,
            proxy_commands::proxy_remove_interception_rule,
            proxy_commands::proxy_get_tls_passthrough,
            proxy_commands::proxy_add_tls_passthrough,
            proxy_commands::proxy_remove_tls_passthrough,
            proxy_commands::proxy_get_upstream,
            proxy_commands::proxy_set_upstream,
            proxy_commands::proxy_get_tls_impersonate,
            proxy_commands::proxy_set_tls_impersonate,
            proxy_commands::proxy_get_websocket_messages,
            proxy_commands::proxy_get_listeners,
            proxy_commands::proxy_add_listener,
            proxy_commands::proxy_remove_listener,
            proxy_commands::proxy_export_traffic,
            proxy_commands::proxy_import_ca_key,
            proxy_commands::proxy_get_capabilities,
            proxy_commands::proxy_get_statistics,
            scanner_commands::scanner_start_active,
            scanner_commands::scanner_status,
            scanner_commands::scanner_get_findings,
            scanner_commands::scanner_get_result,
            scanner_commands::scanner_list_scans,
            scanner_commands::scanner_delete_scan,
            scanner_commands::scanner_generate_report,
            session_commands::session_get_cookies,
            session_commands::session_set_cookie,
            session_commands::session_remove_cookie,
            session_commands::session_clear_cookies,
            session_commands::session_import_cookies,
            session_commands::session_export_cookies,
            session_commands::session_get_macros,
            session_commands::session_create_macro,
            session_commands::session_run_macro,
            session_commands::session_delete_macro,
            session_commands::session_get_rules,
            session_commands::session_create_rule,
            session_commands::session_toggle_rule,
            session_commands::session_delete_rule,
            session_commands::session_browser_sync_status,
            intruder::intruder_start,
            intruder::intruder_stop,
            intruder::intruder_pause,
            intruder::intruder_resume,
            intruder::intruder_status,
            intruder::intruder_results,
            intruder::intruder_delete,
            websocket_commands::ws_connect,
            websocket_commands::ws_send_frame,
            websocket_commands::ws_get_messages,
            websocket_commands::ws_list_connections,
            websocket_commands::ws_close_connection,
            websocket_commands::ws_add_match_replace,
            websocket_commands::ws_get_match_replace,
            websocket_commands::ws_remove_match_replace,
            window_manager::window_detach_module,
            window_manager::window_redock_module,
            window_manager::window_focus_detached,
            window_manager::window_list_detached,
            window_manager::window_move_detached,
            window_manager::window_resize_detached,
            system::get_system_info,
            browser::browser_detect,
            browser::browser_status,
            browser::browser_launch,
            commands::check_path_exists,
            commands::read_file_content,
            commands::write_mcp_config,
            commands::mcp_execute_tool,
            commands::mcp_browser_get_headless,
            commands::mcp_browser_set_headless,
            commands::mcp_browser_get_stealth_profile,
            commands::mcp_browser_set_stealth_profile,
            commands::save_file_text,
            commands::save_file_bytes,
            commands::skill_content,
            commands::install_skill,
            payload_commands::payload_list_categories,
            payload_commands::payload_download,
            payload_commands::payload_load,
            payload_commands::payload_search,
            osint_commands::osint_whois,
            osint_commands::osint_crtsh,
            port_commands::port_status,
            port_commands::kill_process,
            chromium_commands::chromium_status,
            chromium_commands::chromium_ensure,
            chromium_commands::chromium_reinstall,
            chromium_commands::reveal_in_explorer,
            browser_migration::browser_migration_check,
            browser_migration::browser_migration_remove_ca,
            crawler_commands::crawler_run,
            updater::check_for_update,
            updater::current_version,
            oast_commands::oast_start_http,
            oast_commands::oast_start_dns,
            oast_commands::oast_start_smtp,
            oast_commands::oast_stop_http,
            oast_commands::oast_stop_dns,
            oast_commands::oast_stop_smtp,
            oast_commands::oast_status,
            oast_commands::oast_generate,
            oast_commands::oast_generate_scan_payloads,
            oast_commands::oast_get_payloads,
            oast_commands::oast_poll_interactions,
            oast_commands::oast_clear,
            oast_commands::oast_collaborator_everywhere,
        ])
        .setup(|app| {
            // Stash the AppHandle so the MCP server (running on its own thread
            // with no Tauri state access) can launch the bundled browser etc.
            mcp::browser::set_app_handle(app.handle().clone());

            let mcp: mcp::McpState = app.state::<mcp::McpState>().inner().clone();
            let mut server = mcp.blocking_lock();
            match server.start_sync(3100) {
                Ok(_) => println!("[MCP] Auto-started on port {}", server.bound_port),
                Err(e) => eprintln!("[MCP] Auto-start failed: {}", e),
            }
            drop(server);

            // Best-effort GC of old Chromium versions on startup. Burp leaves
            // every previously-shipped version on disk forever; we don't.
            match chromium::ChromiumManager::new(app.handle()) {
                Ok(mgr) => mgr.gc(),
                Err(e) => eprintln!("[Chromium] startup GC skipped: {}", e),
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app, event| {
            if let tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit = event {
                browser::kill_all_launched();
            }
        });
}
