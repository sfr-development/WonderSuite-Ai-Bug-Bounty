mod agent_browser;
mod browser;
mod commands;
mod http2;
mod intruder;
mod mcp;
mod oast;
mod oast_commands;
mod payload_commands;
mod project;
mod proxy;
mod proxy_commands;
mod reporting;
mod scanner;
mod scanner_commands;
mod session;
mod session_commands;
mod system;
mod updater;
mod websocket_commands;

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
    let agent_browser_state = agent_browser::create_agent_browser_state();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(mcp_state)
        .manage(proxy_state)
        .manage(scanner_state)
        .manage(session_state)
        .manage(intruder_state)
        .manage(ws_state)
        .manage(agent_browser_state)
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
            system::get_system_info,
            browser::browser_detect,
            browser::browser_status,
            browser::browser_launch,
            commands::check_path_exists,
            commands::read_file_content,
            commands::write_mcp_config,
            commands::mcp_execute_tool,
            commands::save_file_text,
            commands::save_file_bytes,
            payload_commands::payload_list_categories,
            payload_commands::payload_download,
            payload_commands::payload_load,
            payload_commands::payload_search,
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
            agent_browser::agent_browser_launch,
            agent_browser::agent_browser_close,
            agent_browser::agent_browser_status,
            agent_browser::agent_browser_navigate,
            agent_browser::agent_browser_reload,
            agent_browser::agent_browser_go_back,
            agent_browser::agent_browser_go_forward,
            agent_browser::agent_browser_get_url,
            agent_browser::agent_browser_get_title,
            agent_browser::agent_browser_get_content,
            agent_browser::agent_browser_get_text,
            agent_browser::agent_browser_query_selector,
            agent_browser::agent_browser_query_selector_all,
            agent_browser::agent_browser_get_links,
            agent_browser::agent_browser_get_forms,
            agent_browser::agent_browser_get_inputs,
            agent_browser::agent_browser_click,
            agent_browser::agent_browser_type,
            agent_browser::agent_browser_press_key,
            agent_browser::agent_browser_scroll,
            agent_browser::agent_browser_select_option,
            agent_browser::agent_browser_fill_form,
            agent_browser::agent_browser_clear_field,
            agent_browser::agent_browser_screenshot,
            agent_browser::agent_browser_screenshot_element,
            agent_browser::agent_browser_set_viewport,
            agent_browser::agent_browser_evaluate,
            agent_browser::agent_browser_evaluate_on_new_doc,
            agent_browser::agent_browser_new_tab,
            agent_browser::agent_browser_list_tabs,
            agent_browser::agent_browser_close_tab,
            agent_browser::agent_browser_switch_tab,
            agent_browser::agent_browser_get_cookies,
            agent_browser::agent_browser_set_cookie,
            agent_browser::agent_browser_delete_cookie,
            agent_browser::agent_browser_clear_all_cookies,
            agent_browser::agent_browser_get_local_storage,
            agent_browser::agent_browser_set_local_storage,
            agent_browser::agent_browser_wait_for_element,
            agent_browser::agent_browser_wait_for_navigation,
            agent_browser::agent_browser_set_extra_headers,
            agent_browser::agent_browser_block_urls,
            agent_browser::agent_browser_set_user_agent,
            agent_browser::agent_browser_set_geolocation,
            agent_browser::agent_browser_set_timezone,
            agent_browser::agent_browser_handle_dialog,
        ])
        .setup(|app| {
            let mcp: mcp::McpState = app.state::<mcp::McpState>().inner().clone();
            let mut server = mcp.blocking_lock();
            match server.start_sync(3100) {
                Ok(_) => println!("[MCP] Auto-started on port {}", server.bound_port),
                Err(e) => eprintln!("[MCP] Auto-start failed: {}", e),
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
