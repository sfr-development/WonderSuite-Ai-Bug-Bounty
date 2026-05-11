// Well-known endpoint discovery.
//
// Three groups:
//   1. .well-known/* — RFC 8615 entries that often spill secrets / metadata
//   2. API specs   — Swagger, OpenAPI, GraphQL introspection, JSON-RPC discovery
//   3. Admin paths — /admin, /login, /api, etc. Common security-interest paths.
//
// `well_known_paths()` returns the static list. Use it to seed the crawl
// queue with Tier::WellKnown tasks at the start of every scan.

pub const WELL_KNOWN_PATHS: &[&str] = &[
    // RFC 8615 .well-known URIs
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/host-meta",
    "/.well-known/host-meta.json",
    "/.well-known/webfinger",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/change-password",
    "/.well-known/dnt-policy.txt",
    "/.well-known/keybase.txt",
    "/.well-known/matrix/client",
    "/.well-known/matrix/server",
    "/.well-known/nodeinfo",
    "/.well-known/pki-validation",
    "/.well-known/security.txt",
    "/.well-known/jwks.json",
    "/.well-known/openid_keys",
    "/.well-known/acme-challenge",
    "/.well-known/discord",
    "/.well-known/microsoft-identity-association.json",
    "/.well-known/traffic-advice",
    "/.well-known/ai-plugin.json",
];

pub const API_SPEC_PATHS: &[&str] = &[
    // OpenAPI / Swagger
    "/swagger",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/api-docs",
    "/api-docs.json",
    "/api/docs",
    "/api/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi/v3",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/redoc",
    "/api/redoc",
    // GraphQL
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/api/query",
    "/graphiql",
    "/playground",
    "/api/playground",
    // JSON-RPC
    "/jsonrpc",
    "/api/jsonrpc",
    "/api/rpc",
    "/rpc",
    // Common API roots — used as injection-point seeds
    "/api",
    "/api/",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/v1",
    "/v2",
    "/rest",
    "/rest/v1",
    "/services",
    "/services/api",
];

pub const ADMIN_LOGIN_PATHS: &[&str] = &[
    "/admin",
    "/admin/",
    "/admin/login",
    "/administrator",
    "/wp-admin",
    "/wp-login.php",
    "/wp-config.php",
    "/manager",
    "/manager/html",
    "/dashboard",
    "/console",
    "/control",
    "/cpanel",
    "/login",
    "/signin",
    "/sign-in",
    "/auth",
    "/auth/login",
    "/oauth/authorize",
    "/oauth/token",
    "/sso",
    "/account",
    "/user",
    "/users",
    "/profile",
    "/settings",
    "/config",
    "/configuration",
    "/setup",
    "/install",
    "/installer",
    "/phpmyadmin",
    "/phpinfo.php",
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/server-status",
    "/server-info",
    "/health",
    "/healthz",
    "/healthcheck",
    "/status",
    "/metrics",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/heapdump",
    "/debug",
    "/debug/pprof",
    "/backup",
    "/backups",
    "/database",
    "/db",
];

/// All well-known paths concatenated. Caller can iterate and join against a base URL.
pub fn well_known_paths() -> impl Iterator<Item = &'static str> {
    WELL_KNOWN_PATHS.iter().chain(API_SPEC_PATHS.iter()).chain(ADMIN_LOGIN_PATHS.iter()).copied()
}

/// GraphQL introspection query — used by the crawler to enumerate the schema
/// when a `/graphql` endpoint responds 200/400 (400 with a parsing error is
/// also a positive signal: it means the endpoint exists).
pub const GRAPHQL_INTROSPECTION_QUERY: &str = r#"{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind fields{name args{name type{name kind}}}}}}"}"#;

/// JSON-RPC method discovery probe — most servers respond to `rpc.discover`
/// (OpenRPC spec). Fall back to `system.listMethods` for older xmlrpc-style
/// servers that pretend to be json-rpc.
pub const JSONRPC_DISCOVERY: &str = r#"{"jsonrpc":"2.0","id":1,"method":"rpc.discover"}"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterator_covers_all_groups() {
        let n = well_known_paths().count();
        assert!(n >= 100, "expected lots of paths, got {}", n);
        assert!(well_known_paths().any(|p| p == "/.well-known/security.txt"));
        assert!(well_known_paths().any(|p| p == "/openapi.json"));
        assert!(well_known_paths().any(|p| p == "/graphql"));
        assert!(well_known_paths().any(|p| p == "/admin"));
    }
}
