# MCP Tools Reference

WonderSuite exposes its full toolset over the [MCP server](page:settings-mcp) so a connected AI assistant can operate it autonomously. This is the categorized reference; the **live** list — with exact names, descriptions, and the current count — is in **Settings → MCP Server → Available Tools**.

## HTTP

`send_request` · `send_to_repeater` · `send_to_intruder` (auto-categorises payloads per parameter name) · `h2_send_request` · `mtls_send_request`

## Proxy

`proxy_start` · `proxy_stop` · `proxy_status` · `proxy_toggle_intercept` · `proxy_get_traffic` · `proxy_search_traffic` · `proxy_clear_traffic` · `proxy_export_traffic` (JSON / HAR) · `proxy_get_statistics` · `proxy_add_match_replace` · `proxy_add_interception_rule` · `proxy_add_tls_passthrough` · `proxy_set_upstream` · `proxy_annotate_traffic` · `proxy_get_websocket_messages` · `get_intercepted` · `forward_intercepted`

## Scanner

`active_scan` — SQLi, XSS, SSTI, LFI, Open Redirect, CRLF, with optional `with_oast:true` for blind command injection, blind SSRF, and Log4Shell via the bundled OAST listener · `passive_scan` — headers, cookies, CORS, information disclosure

## Intruder

`fuzz_request` — Sniper, Battering Ram, Pitchfork, Cluster Bomb

## Browser

A pentest-grade browser surface driving WonderBrowser over a persistent CDP connection. All input goes through Chrome's real input pipeline (`isTrusted: true`):

`browser_open` · `browser_attach` · `browser_close` · `browser_navigate` · `browser_snapshot` (accessibility tree + stable element refs + forms + honeypot detection) · `browser_screenshot` · `browser_click` · `browser_type` · `browser_fill_form` · `browser_press_key` · `browser_scroll` · `browser_select_option` · `browser_set_file_input` · `browser_get_outer_html` · `browser_evaluate` · `browser_storage_full` (cookies + LS + SS + IDB + SW + caches) · `browser_console` · `browser_dom_sinks` · `browser_network_traffic` · `browser_replay_to_proxy` · `browser_resource_hints` · `browser_wait_for` · `browser_tabs` · `browser_stealth_check`

## Recon

`crawl_target` · `discover_content` · `discover_subdomains` · `find_secrets` · `dns_resolve` · `js_link_finder`

## OSINT

`whois_lookup` · `asn_lookup` · `crtsh_search` · `wayback_lookup` · `hackertarget_lookup` · `ip_geolocation` · `tech_detect` · `favicon_hash` · `reverse_ip_lookup` · `graphql_introspect`

## Codec

`encode` · `decode` · `hash` · `smart_decode` · `analyze_jwt` (alg=none, kid SQLi/traversal, jku/x5u SSRF, HS/RS confusion)

## OAST

`oast_verify` · `oast_start_dns_server` · `oast_start_smtp_server` · `oast_generate_payload`

## Exploit

`race_request` · `raw_tcp_send` · `websocket_connect` · `analyze_cdn_waf`

## Reporting

`generate_report` (markdown / JSON / summary) · `bambda_filter` · `payload_manager` · `get_traffic_log`

---

> Tool names and the exact set evolve between versions. Always treat **Settings → MCP Server** as the source of truth, and install the [AI Skill](page:settings-skill) so a connected AI knows how and when to use each tool.
