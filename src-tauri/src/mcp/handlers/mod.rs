// ═══════════════════════════════════════════════════════════════════════
//  MCP Handlers — Dispatch table + module declarations
//  Philosophy: Raw primitives only. The AI builds its own attack chains.
// ═══════════════════════════════════════════════════════════════════════

pub mod http;
pub mod codec;
pub mod proxy;
pub mod browser;
pub mod session;
pub mod websocket;
pub mod recon;
pub mod oast;
pub mod osint;
pub mod advanced;
pub mod payloads;
pub mod scanner;

use crate::mcp::types::HandlerResult;

/// The central dispatcher — routes tool names to handler functions.
/// Only raw primitives. No pre-canned attacks. The AI has full freedom.
pub async fn dispatch(name: &str, params: &serde_json::Value) -> HandlerResult {
    match name {
        // ─── HTTP Core ──────────────────────────────────────────────
        "send_request" => http::handle_send_request(params).await,

        // ─── Codec Primitives ───────────────────────────────────────
        "encode" => codec::handle_encode(params).await,
        "decode" => codec::handle_decode(params).await,
        "hash" => codec::handle_hash(params).await,
        "analyze_jwt" => codec::handle_analyze_jwt(params).await,
        "smart_decode" => codec::handle_smart_decode(params).await,

        // ─── Proxy IPC Bridge ───────────────────────────────────────
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
        "proxy_get_capabilities" => proxy::handle_proxy_get_capabilities(params).await,
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

        // ─── Browser CDP ────────────────────────────────────────────
        "browser_navigate" => browser::handle_browser_navigate(params).await,
        "browser_execute_js" => browser::handle_browser_execute_js(params).await,
        "session_from_browser" => browser::handle_session_from_browser(params).await,
        "browser_network_traffic" => browser::handle_browser_network_traffic(params).await,

        // ─── Session State ──────────────────────────────────────────
        "session_manage" => session::handle_session_manage(params).await,

        // ─── WebSocket ──────────────────────────────────────────────
        "websocket_connect" => websocket::handle_websocket_connect(params).await,

        // ─── Recon & Discovery ──────────────────────────────────────
        "crawl_target" => recon::handle_crawl_target(params).await,
        "discover_subdomains" => recon::handle_discover_subdomains(params).await,
        "discover_content" => recon::handle_discover_content(params).await,
        "find_secrets" => recon::handle_find_secrets(params).await,
        "dns_resolve" => recon::handle_dns_resolve(params).await,

        // ─── OAST Infrastructure ────────────────────────────────────
        "oast_generate_payload" => oast::handle_oast_generate_payload(params).await,
        "oast_poll_interactions" => oast::handle_oast_poll_interactions(params).await,
        "oast_start_server" => oast::handle_oast_start_server(params).await,
        "oast_start_dns_server" => oast::handle_oast_start_dns_server(params).await,
        "oast_start_smtp_server" => oast::handle_oast_start_smtp_server(params).await,
        "oast_verify" => oast::handle_oast_verify(params).await,

        // ─── OSINT Data Sources ─────────────────────────────────────
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

        // ─── Advanced Low-Level ─────────────────────────────────────
        "raw_tcp_send" => advanced::handle_raw_tcp_send(params).await,
        "mtls_send_request" => advanced::handle_mtls_send_request(params).await,
        "race_request" => advanced::handle_race_request(params).await,
        "h2_send_request" => advanced::handle_h2_send_request(params).await,
        "bambda_filter" => advanced::handle_bambda_filter(params).await,

        // ─── Payload Management ─────────────────────────────────────
        "payload_manager" => payloads::handle_payload_manager(params).await,

        // ─── Scanner ────────────────────────────────────────────────
        "passive_scan" => scanner::passive::handle_passive_scan(params).await,
        "fuzz_request" => scanner::fuzzer::handle_fuzz_request(params).await,
        "active_scan" => scanner::active::handle_active_scan(params).await,
        "generate_report" => scanner::reporting::handle_generate_report(params).await,

        _ => Err(format!("Unknown tool: {}", name)),
    }
}
