pub mod advanced;
pub mod cdn_waf;
pub mod codec;
pub mod http;
pub mod intruder;
pub mod jslib;
pub mod oast;
pub mod osint;
pub mod payloads;
pub mod portscan;
pub mod proxy;
pub mod recon;
pub mod scanner;
pub mod websocket;

use crate::mcp::types::HandlerResult;

/// The central dispatcher — routes tool names to handler functions.
/// Only raw primitives. No pre-canned attacks. The AI has full freedom.
pub async fn dispatch(name: &str, params: &serde_json::Value) -> HandlerResult {
    match name {
        "send_request" => http::handle_send_request(params).await,

        "encode" => codec::handle_encode(params).await,
        "decode" => codec::handle_decode(params).await,
        "hash" => codec::handle_hash(params).await,
        "analyze_jwt" => codec::handle_analyze_jwt(params).await,
        "smart_decode" => codec::handle_smart_decode(params).await,

        "proxy_start" => proxy::handle_proxy_start(params).await,
        "proxy_stop" => proxy::handle_proxy_stop(params).await,
        "proxy_status" => proxy::handle_proxy_status(params).await,
        "proxy_toggle_intercept" => proxy::handle_proxy_toggle_intercept(params).await,
        "proxy_get_traffic" => proxy::handle_proxy_get_traffic(params).await,
        "proxy_search_traffic" => proxy::handle_proxy_search_traffic(params).await,
        "proxy_add_match_replace" => proxy::handle_proxy_add_match_replace(params).await,
        "proxy_get_match_replace" => proxy::handle_proxy_get_match_replace(params).await,
        "proxy_add_tls_passthrough" => proxy::handle_proxy_add_tls_passthrough(params).await,
        "proxy_set_upstream" => proxy::handle_proxy_set_upstream(params).await,
        "proxy_get_websocket_messages" => proxy::handle_proxy_get_websocket_messages(params).await,
        "proxy_add_interception_rule" => proxy::handle_proxy_add_interception_rule(params).await,
        "proxy_get_statistics" => proxy::handle_proxy_get_statistics(params).await,
        "proxy_clear_traffic" => proxy::handle_proxy_clear_traffic(params).await,
        "proxy_export_traffic" => proxy::handle_proxy_export_traffic(params).await,
        "send_to_repeater" => proxy::handle_send_to_repeater(params).await,
        "send_to_intruder" => proxy::handle_send_to_intruder(params).await,
        "get_intercepted" => proxy::handle_get_intercepted(params).await,
        "forward_intercepted" => proxy::handle_forward_intercepted(params).await,
        "proxy_remove_interception_rule" => proxy::handle_proxy_remove_interception_rule(params).await,
        "proxy_remove_match_replace" => proxy::handle_proxy_remove_match_replace(params).await,
        "proxy_annotate_traffic" => proxy::handle_proxy_annotate_traffic(params).await,

        // Browser MCP — pentest-grade surface (v0.4.0).
        "browser_open" => crate::mcp::browser::handlers::open(params).await,
        "browser_attach" => crate::mcp::browser::handlers::attach(params).await,
        "browser_close" => crate::mcp::browser::handlers::close(params).await,
        "browser_navigate" => crate::mcp::browser::handlers::navigate(params).await,
        "browser_snapshot" => crate::mcp::browser::handlers::snapshot(params).await,
        "browser_screenshot" => crate::mcp::browser::handlers::screenshot(params).await,
        "browser_click" => crate::mcp::browser::handlers::click(params).await,
        "browser_type" => crate::mcp::browser::handlers::type_text(params).await,
        "browser_fill_form" => crate::mcp::browser::handlers::fill_form(params).await,
        "browser_press_key" => crate::mcp::browser::handlers::press_key(params).await,
        "browser_scroll" => crate::mcp::browser::handlers::scroll(params).await,
        "browser_select_option" => crate::mcp::browser::handlers::select_option(params).await,
        "browser_set_file_input" => crate::mcp::browser::handlers::set_file_input(params).await,
        "browser_get_outer_html" => crate::mcp::browser::handlers::get_outer_html(params).await,
        "browser_evaluate" => crate::mcp::browser::handlers::evaluate(params).await,
        "browser_storage_full" => crate::mcp::browser::handlers::storage_full(params).await,
        "browser_console" => crate::mcp::browser::handlers::console(params).await,
        "browser_dom_sinks" => crate::mcp::browser::handlers::dom_sinks(params).await,
        "browser_network_traffic" => crate::mcp::browser::handlers::network_traffic(params).await,
        "browser_replay_to_proxy" => crate::mcp::browser::handlers::replay_to_proxy(params).await,
        "browser_resource_hints" => crate::mcp::browser::handlers::resource_hints(params).await,
        "browser_wait_for" => crate::mcp::browser::handlers::wait_for(params).await,
        "browser_tabs" => crate::mcp::browser::handlers::tabs(params).await,
        "browser_stealth_check" => crate::mcp::browser::stealth_check::run(params).await,

        "websocket_connect" => websocket::handle_websocket_connect(params).await,

        "crawl_target" => recon::handle_crawl_target(params).await,
        "discover_subdomains" => recon::handle_discover_subdomains(params).await,
        "discover_content" => recon::handle_discover_content(params).await,
        "find_secrets" => recon::handle_find_secrets(params).await,
        "dns_resolve" => recon::handle_dns_resolve(params).await,
        // v0.3.10: client-side library + version detection (detection only;
        // CVE research is the agent's responsibility).
        "js_library_audit" => jslib::handle_js_library_audit(params).await,

        "port_scan" => portscan::handle_port_scan(params).await,
        "port_scan_range" => portscan::handle_port_scan_range(params).await,
        "service_detect" => portscan::handle_service_detect(params).await,
        "banner_grab" => portscan::handle_banner_grab(params).await,
        "port_scan_results" => portscan::handle_port_scan_results(params).await,

        "oast_generate_payload" => oast::handle_oast_generate_payload(params).await,
        "oast_start_dns_server" => oast::handle_oast_start_dns_server(params).await,
        "oast_start_smtp_server" => oast::handle_oast_start_smtp_server(params).await,
        "oast_start_http_server" => oast::handle_oast_start_http_server(params).await,
        "oast_poll_interactions" => oast::handle_oast_poll_interactions(params).await,
        "oast_status" => oast::handle_oast_status(params).await,
        "oast_clear" => oast::handle_oast_clear(params).await,
        "oast_verify" => oast::handle_oast_verify(params).await,

        // v0.3.10: Intruder driver — previously the agent could only QUEUE
        // attacks via send_to_intruder but had no way to fire/observe them.
        "intruder_start" => intruder::handle_intruder_start(params).await,
        "intruder_stop" => intruder::handle_intruder_stop(params).await,
        "intruder_status" => intruder::handle_intruder_status(params).await,
        "intruder_results" => intruder::handle_intruder_results(params).await,
        "intruder_list" => intruder::handle_intruder_list(params).await,

        "crtsh_search" => osint::handle_crtsh_search(params).await,
        "wayback_lookup" => osint::handle_wayback_lookup(params).await,
        "whois_lookup" => osint::handle_whois_lookup(params).await,
        "asn_lookup" => osint::handle_asn_lookup(params).await,
        "favicon_hash" => osint::handle_favicon_hash(params).await,
        "reverse_ip_lookup" => osint::handle_reverse_ip_lookup(params).await,
        "js_link_finder" => osint::handle_js_link_finder(params).await,
        "graphql_introspect" => osint::handle_graphql_introspect(params).await,
        "hackertarget_lookup" => osint::handle_hackertarget(params).await,
        "ip_geolocation" => osint::handle_ip_geolocation(params).await,
        "tech_detect" => osint::handle_tech_detect(params).await,

        "raw_tcp_send" => advanced::handle_raw_tcp_send(params).await,
        "mtls_send_request" => advanced::handle_mtls_send_request(params).await,
        "race_request" => advanced::handle_race_request(params).await,
        "h2_send_request" => advanced::handle_h2_send_request(params).await,
        "bambda_filter" => advanced::handle_bambda_filter(params).await,

        "payload_manager" => payloads::handle_payload_manager(params).await,

        "analyze_cdn_waf" => cdn_waf::handle_analyze_cdn_waf(params).await,
        "get_traffic_log" => cdn_waf::handle_get_traffic_log(params).await,

        "passive_scan" => scanner::passive::handle_passive_scan(params).await,
        "fuzz_request" => scanner::fuzzer::handle_fuzz_request(params).await,
        "active_scan" => scanner::active::handle_active_scan(params).await,
        "generate_report" => scanner::reporting::handle_generate_report(params).await,

        _ => Err(format!("Unknown tool: {}", name)),
    }
}
