//! GraphQL introspection → injection-surface enumeration (v0.3.35).
//!
//! Given a GraphQL endpoint, this:
//!   1. POSTs the standard introspection query,
//!   2. reports whether introspection is enabled (an information-disclosure
//!      finding when it is),
//!   3. parses the schema into queries/mutations and their scalar arguments,
//!   4. emits a structured list of injection points (field + argument + type)
//!      that the agent can hand to `intruder` / `active_scan` for payload tests.
//!
//! Scope note (0.3.35): this maps the attack surface. It deliberately does NOT
//! fire payloads into GraphQL arguments itself — building valid operation
//! documents for arbitrary fields is follow-up work. The returned injection
//! points are the agent's launch pad.

use crate::mcp::types::HandlerResult;
use serde_json::{json, Value};
use std::collections::HashSet;

/// Scalar types worth fuzzing for injection.
const SCALAR_TYPES: &[&str] = &["String", "ID", "Int", "Float", "Boolean"];

/// The canonical GraphQL introspection query. `ofType` is nested seven levels
/// deep so wrappers like `[String!]!` resolve all the way down to the scalar.
const INTROSPECTION_QUERY: &str = "{ __schema { queryType { name } mutationType { name } types { name kind fields(includeDeprecated: false) { name args { name type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } } } } } }";

#[derive(Debug, Clone)]
pub struct GraphQLArgument {
    pub arg_name: String,
    pub arg_type: String,
    pub is_required: bool,
    pub is_list: bool,
}

#[derive(Debug, Clone)]
pub struct GraphQLField {
    pub name: String,
    pub arguments: Vec<GraphQLArgument>,
}

#[derive(Debug, Clone)]
pub struct GraphQLSchema {
    pub queries: Vec<GraphQLField>,
    pub mutations: Vec<GraphQLField>,
}

/// One injectable GraphQL argument. Serialized into the tool response.
#[derive(Debug, Clone)]
pub struct GqlInjectionPoint {
    pub operation: String, // "query" | "mutation"
    pub field: String,
    pub arg_name: String,
    pub arg_type: String,
    pub required: bool,
    pub suggested_value: String,
}

impl GqlInjectionPoint {
    pub fn name(&self) -> String {
        format!("{}.{}", self.field, self.arg_name)
    }
    fn to_json(&self) -> Value {
        json!({
            "name": self.name(),
            "operation": self.operation,
            "field": self.field,
            "arg": self.arg_name,
            "type": self.arg_type,
            "required": self.required,
            "suggested_value": self.suggested_value,
        })
    }
}

fn is_scalar_type(t: &str) -> bool {
    SCALAR_TYPES.contains(&t)
}

fn suggested_value(arg_type: &str) -> String {
    match arg_type {
        "Int" | "Float" => "1".to_string(),
        "Boolean" => "true".to_string(),
        _ => "test".to_string(),
    }
}

/// Walk a (possibly nested) introspection type ref and return
/// `(base_scalar_name, is_required, is_list)`.
fn extract_type_info(type_obj: &Value) -> (String, bool, bool) {
    let mut current = type_obj;
    let mut is_required = false;
    let mut is_list = false;

    loop {
        match current["kind"].as_str() {
            Some("NON_NULL") | Some("NonNull") => {
                is_required = true;
                if current["ofType"].is_object() {
                    current = &current["ofType"];
                } else {
                    break;
                }
            }
            Some("LIST") | Some("List") => {
                is_list = true;
                if current["ofType"].is_object() {
                    current = &current["ofType"];
                } else {
                    break;
                }
            }
            _ => break,
        }
    }

    let base = current["name"].as_str().unwrap_or("").to_string();
    (base, is_required, is_list)
}

fn extract_argument_info(arg: &Value) -> Option<GraphQLArgument> {
    let arg_name = arg["name"].as_str()?.to_string();
    let (base_type, is_required, is_list) = extract_type_info(&arg["type"]);
    if !is_scalar_type(&base_type) {
        return None; // only scalar args are fuzzable
    }
    Some(GraphQLArgument { arg_name, arg_type: base_type, is_required, is_list })
}

fn extract_field_info(field: &Value) -> Option<GraphQLField> {
    let name = field["name"].as_str()?.to_string();
    let mut arguments = Vec::new();
    if let Some(args) = field["args"].as_array() {
        for arg in args {
            if let Some(info) = extract_argument_info(arg) {
                arguments.push(info);
            }
        }
    }
    Some(GraphQLField { name, arguments })
}

/// Parse an introspection response (`{ data: { __schema: {...} } }`) into a
/// [`GraphQLSchema`]. Returns `Err` when no `__schema` is present.
pub fn parse_graphql_schema(_endpoint: &str, data: &Value) -> Result<GraphQLSchema, String> {
    let schema = &data["data"]["__schema"];
    if schema.is_null() {
        return Err("introspection disabled or no __schema in response".into());
    }

    let query_type = schema["queryType"]["name"].as_str().unwrap_or("Query").to_string();
    let mutation_type = schema["mutationType"]["name"].as_str().unwrap_or("Mutation").to_string();

    let empty = Vec::new();
    let types = schema["types"].as_array().unwrap_or(&empty);

    let mut queries = Vec::new();
    let mut mutations = Vec::new();

    for type_def in types {
        let name = type_def["name"].as_str().unwrap_or("");
        if name.starts_with("__") {
            continue; // skip introspection meta-types
        }
        let target = if name == query_type {
            Some(&mut queries)
        } else if name == mutation_type {
            Some(&mut mutations)
        } else {
            None
        };
        if let Some(bucket) = target {
            if let Some(fields) = type_def["fields"].as_array() {
                for field in fields {
                    if let Some(f) = extract_field_info(field) {
                        // Only keep fields that actually expose scalar args.
                        if !f.arguments.is_empty() {
                            bucket.push(f);
                        }
                    }
                }
            }
        }
    }

    Ok(GraphQLSchema { queries, mutations })
}

/// Flatten a schema into a deduplicated list of injectable arguments.
pub fn schema_to_injection_points(schema: &GraphQLSchema) -> Vec<GqlInjectionPoint> {
    let mut points = Vec::new();
    let mut seen = HashSet::new();

    for (operation, fields) in [("query", &schema.queries), ("mutation", &schema.mutations)] {
        for field in fields {
            for arg in &field.arguments {
                let key = format!("{}|{}|{}", operation, field.name, arg.arg_name);
                if seen.insert(key) {
                    points.push(GqlInjectionPoint {
                        operation: operation.to_string(),
                        field: field.name.clone(),
                        arg_name: arg.arg_name.clone(),
                        arg_type: arg.arg_type.clone(),
                        required: arg.is_required,
                        suggested_value: suggested_value(&arg.arg_type),
                    });
                }
            }
        }
    }
    points
}

async fn introspect_graphql(
    endpoint: &str,
    headers: Option<&serde_json::Map<String, Value>>,
) -> Result<Value, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    let mut req = client
        .post(endpoint)
        .header("content-type", "application/json")
        .body(json!({ "query": INTROSPECTION_QUERY }).to_string());

    if let Some(obj) = headers {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                req = req.header(k.as_str(), s);
            }
        }
    }

    let resp = req.send().await.map_err(|e| format!("introspection request failed: {}", e))?;
    let body = resp.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str::<Value>(&body).map_err(|e| format!("non-JSON introspection response: {}", e))
}

/// MCP tool `graphql_scan`: introspect a GraphQL endpoint and enumerate its
/// injectable argument surface.
pub async fn handle_graphql_scan(params: &serde_json::Value) -> HandlerResult {
    let target = params["target"].as_str().ok_or("Missing target")?;
    let headers = params["headers"].as_object();

    let data = match introspect_graphql(target, headers).await {
        Ok(d) => d,
        Err(e) => {
            return Ok(json!({
                "target": target,
                "introspection_enabled": false,
                "error": e,
                "injection_points": [],
            }));
        }
    };

    let schema = match parse_graphql_schema(target, &data) {
        Ok(s) => s,
        Err(_) => {
            // A well-formed JSON response without __schema = introspection is
            // disabled. That's good security posture, not a finding.
            return Ok(json!({
                "target": target,
                "introspection_enabled": false,
                "note": "Introspection appears disabled (no __schema returned). Good posture; the argument surface can't be auto-enumerated.",
                "injection_points": [],
            }));
        }
    };

    let points = schema_to_injection_points(&schema);

    let finding = json!({
        "finding_type": "graphql_introspection_enabled",
        "name": "GraphQL introspection enabled",
        "severity": "low",
        "confidence": "certain",
        "url": target,
        "evidence": format!(
            "Introspection returned {} query field(s) and {} mutation field(s).",
            schema.queries.len(), schema.mutations.len()
        ),
        "remediation": "Disable introspection in production GraphQL deployments to avoid exposing the full schema.",
    });

    let surface = |fields: &[GraphQLField]| -> Vec<Value> {
        fields
            .iter()
            .map(|f| {
                json!({
                    "field": f.name,
                    "args": f.arguments.iter().map(|a| json!({
                        "name": a.arg_name,
                        "type": a.arg_type,
                        "required": a.is_required,
                        "list": a.is_list,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect()
    };

    Ok(json!({
        "target": target,
        "introspection_enabled": true,
        "finding": finding,
        "queries": surface(&schema.queries),
        "mutations": surface(&schema.mutations),
        "injection_point_count": points.len(),
        "injection_points": points.iter().map(|p| p.to_json()).collect::<Vec<_>>(),
        "next_step": "Feed an injection point's field+arg into intruder, or craft a GraphQL operation with SQLi/XSS/SSTI payloads in that argument.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_introspection() -> Value {
        json!({
            "data": { "__schema": {
                "queryType": { "name": "Query" },
                "mutationType": { "name": "Mutation" },
                "types": [
                    { "name": "Query", "kind": "OBJECT", "fields": [
                        { "name": "user", "args": [
                            { "name": "id", "type": { "kind": "NON_NULL", "ofType": { "kind": "SCALAR", "name": "ID" } } },
                            { "name": "email", "type": { "kind": "SCALAR", "name": "String" } }
                        ] },
                        { "name": "search", "args": [
                            { "name": "q", "type": { "kind": "NON_NULL", "ofType": { "kind": "SCALAR", "name": "String" } } },
                            { "name": "limit", "type": { "kind": "SCALAR", "name": "Int" } }
                        ] },
                        { "name": "noArgs", "args": [] }
                    ] },
                    { "name": "Mutation", "kind": "OBJECT", "fields": [
                        { "name": "createUser", "args": [
                            { "name": "name", "type": { "kind": "NON_NULL", "ofType": { "kind": "SCALAR", "name": "String" } } }
                        ] }
                    ] },
                    { "name": "__Type", "kind": "OBJECT", "fields": [] }
                ]
            } }
        })
    }

    #[test]
    fn parses_query_and_mutation_fields() {
        let schema = parse_graphql_schema("https://x/graphql", &sample_introspection()).unwrap();
        // noArgs has no scalar args, so it's dropped; user + search remain.
        assert_eq!(schema.queries.len(), 2);
        assert_eq!(schema.queries[0].name, "user");
        assert_eq!(schema.queries[0].arguments[0].arg_name, "id");
        assert_eq!(schema.queries[0].arguments[0].arg_type, "ID");
        assert!(schema.queries[0].arguments[0].is_required);
        assert!(!schema.queries[0].arguments[1].is_required);
        assert_eq!(schema.mutations.len(), 1);
        assert_eq!(schema.mutations[0].name, "createUser");
    }

    #[test]
    fn generates_one_point_per_scalar_arg() {
        let schema = parse_graphql_schema("https://x/graphql", &sample_introspection()).unwrap();
        let points = schema_to_injection_points(&schema);
        // user(id,email) + search(q,limit) + createUser(name) = 5
        assert_eq!(points.len(), 5);
        assert!(points.iter().any(|p| p.name() == "user.id" && p.operation == "query"));
        assert!(points.iter().any(|p| p.name() == "createUser.name" && p.operation == "mutation"));
        let limit = points.iter().find(|p| p.name() == "search.limit").unwrap();
        assert_eq!(limit.suggested_value, "1");
    }

    #[test]
    fn missing_schema_is_an_error() {
        let data = json!({ "data": { "__schema": null } });
        assert!(parse_graphql_schema("https://x/graphql", &data).is_err());
    }

    #[test]
    fn unwraps_nested_type_wrappers() {
        // [String!]! -> NON_NULL(LIST(NON_NULL(SCALAR String)))
        let t = json!({ "kind": "NON_NULL", "ofType": { "kind": "LIST", "ofType": {
            "kind": "NON_NULL", "ofType": { "kind": "SCALAR", "name": "String" } } } });
        let (base, req, list) = extract_type_info(&t);
        assert_eq!(base, "String");
        assert!(req);
        assert!(list);
    }

    #[test]
    fn custom_scalars_are_skipped() {
        let arg = json!({ "name": "when", "type": { "kind": "SCALAR", "name": "DateTime" } });
        assert!(extract_argument_info(&arg).is_none());
    }
}
