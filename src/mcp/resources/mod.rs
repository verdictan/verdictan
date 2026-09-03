// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP resource provider.
//!
//! Implements `resources/list` and `resources/read` for:
//! - `history://sessions` — recent sessions

pub mod context_branch;
pub mod context_recent;
pub mod context_schema;
pub mod context_team;
pub mod gateway_effective_config;
pub mod gateway_tool_servers;
pub mod history_session;
pub mod pricing_models;
pub mod regions_catalog;
pub mod regions_organization;
pub mod telemetry_providers;

use serde_json::Value;
use std::collections::BTreeSet;

use crate::api::AsyncApiClient;
use crate::error::CliError;

/// Return the list of available MCP resources.
pub fn resources_list() -> Value {
    serde_json::json!([
        {
            "uri": "history://sessions",
            "name": "Recent Sessions",
            "description": "List of recent conversation sessions.",
            "mimeType": "application/json"
        },
        history_session::descriptor(),
        gateway_effective_config::descriptor(),
        gateway_tool_servers::descriptor(),
        pricing_models::descriptor(),
        regions_catalog::descriptor(),
        regions_organization::descriptor(),
        telemetry_providers::descriptor(),
        context_team::descriptor(),
        context_branch::descriptor(),
        context_schema::descriptor(),
        context_recent::descriptor()
    ])
}

/// Return true when the allowlist entry admits the requested or advertised resource URI.
pub fn resource_matches_allow_entry(allow_entry: &str, resource_uri: &str) -> bool {
    let allow_identities = resource_identities(allow_entry);
    let resource_identities = resource_identities(resource_uri);

    allow_identities.iter().any(|allow| {
        resource_identities
            .iter()
            .any(|candidate| candidate == allow)
    })
}

/// Read a resource by URI.
pub async fn read_resource(client: &AsyncApiClient, uri: &str) -> Result<Value, CliError> {
    read_resource_for_session(client, uri, None).await
}

/// Read a resource by URI with optional active MCP session scope.
pub async fn read_resource_for_session(
    client: &AsyncApiClient,
    uri: &str,
    session_id: Option<&str>,
) -> Result<Value, CliError> {
    tracing::debug!(uri = %uri, "reading MCP resource");

    if uri == "history://sessions" {
        let response = client
            .get_json_value("/v1/history/sessions?limit=50")
            .await?;
        let items = response
            .get("sessions")
            .or_else(|| response.get("items"))
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        return Ok(serde_json::json!({
            "contents": [{
                "uri": uri,
                "mimeType": "application/json",
                "text": serde_json::to_string(&items).unwrap_or_default()
            }]
        }));
    }

    if history_session::matches_uri(uri) {
        return history_session::read_resource(client, uri).await;
    }

    if gateway_effective_config::matches_uri(uri) {
        return gateway_effective_config::read_resource(client, uri).await;
    }

    if gateway_tool_servers::matches_uri(uri) {
        return gateway_tool_servers::read_resource(client, uri).await;
    }

    if pricing_models::matches_uri(uri) {
        return pricing_models::read_resource(client, uri).await;
    }

    if regions_catalog::matches_uri(uri) {
        return regions_catalog::read_resource(client, uri).await;
    }

    if regions_organization::matches_uri(uri) {
        return regions_organization::read_resource(client, uri).await;
    }

    if telemetry_providers::matches_uri(uri) {
        return telemetry_providers::read_resource(client, uri).await;
    }

    if context_team::matches_uri(uri) {
        return context_team::read_resource_for_session(client, uri, session_id).await;
    }

    if context_branch::matches_uri(uri) {
        return context_branch::read_resource_for_session(client, uri, session_id).await;
    }

    if context_schema::matches_uri(uri) {
        return context_schema::read_resource_for_session(client, uri, session_id).await;
    }

    if context_recent::matches_uri(uri) {
        return context_recent::read_resource_for_session(client, uri, session_id).await;
    }

    Err(CliError::user(format!("Unknown resource URI: {uri}")))
}

fn resource_identities(uri: &str) -> Vec<String> {
    let mut identities = BTreeSet::new();
    let base_uri = uri.split_once('?').map_or(uri, |(value, _)| value);

    for candidate in [uri, base_uri] {
        identities.insert(candidate.to_string());
        if let Some(canonical) = canonical_resource_uri(candidate) {
            identities.insert(canonical.to_string());
            if let Some(wildcard) = template_wildcard_uri(canonical) {
                identities.insert(wildcard);
            }
        }
    }

    if let Some(canonical) = canonical_resource_uri(uri) {
        identities.insert(canonical.to_string());
        if let Some(wildcard) = template_wildcard_uri(canonical) {
            identities.insert(wildcard);
        }
    }

    identities.into_iter().collect()
}

fn canonical_resource_uri(uri: &str) -> Option<&'static str> {
    match uri {
        "history://sessions" => Some("history://sessions"),
        _ if history_session::matches_uri(uri) => Some("history://session/{id}"),
        _ if gateway_effective_config::matches_uri(uri) => Some("gateway://effective-config"),
        _ if gateway_tool_servers::matches_uri(uri) => Some("gateway://tool-servers"),
        _ if pricing_models::matches_uri(uri) => Some("pricing://models"),
        _ if regions_catalog::matches_uri(uri) => Some("regions://catalog"),
        _ if regions_organization::matches_uri(uri) => Some("regions://organization"),
        _ if telemetry_providers::matches_uri(uri) => Some("telemetry://providers"),
        _ if context_team::matches_uri(uri) => Some("context://team"),
        _ if context_branch::matches_uri(uri) => Some("context://branch/{name}"),
        _ if context_schema::matches_uri(uri) => Some("context://schema/{table}"),
        _ if context_recent::matches_uri(uri) => Some("context://recent"),
        _ => None,
    }
}

fn template_wildcard_uri(uri: &str) -> Option<String> {
    if !uri.contains('{') {
        return None;
    }

    let mut wildcard = String::with_capacity(uri.len());
    let mut chars = uri.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '{' {
            wildcard.push('*');
            for next in chars.by_ref() {
                if next == '}' {
                    break;
                }
            }
        } else {
            wildcard.push(ch);
        }
    }

    Some(wildcard)
}

#[cfg(test)]
mod tests {
    #![allow(
        dead_code,
        clippy::approx_constant,
        clippy::assertions_on_constants,
        clippy::assign_op_pattern,
        clippy::await_holding_lock,
        clippy::bool_assert_comparison,
        clippy::clone_on_copy,
        clippy::cloned_ref_to_slice_refs,
        clippy::const_is_empty,
        clippy::derivable_impls,
        clippy::err_expect,
        clippy::expect_fun_call,
        clippy::expect_used,
        clippy::field_reassign_with_default,
        clippy::large_enum_variant,
        clippy::len_zero,
        clippy::manual_contains,
        clippy::manual_range_contains,
        clippy::needless_borrow,
        clippy::needless_borrows_for_generic_args,
        clippy::panic,
        clippy::print_stderr,
        clippy::type_complexity,
        clippy::unnecessary_literal_unwrap,
        clippy::unnecessary_map_or,
        clippy::unwrap_used,
        clippy::useless_conversion,
        clippy::useless_vec,
        unused_imports,
        unused_macros,
        unused_mut,
        unused_variables,
        clippy::nonminimal_bool,
        clippy::overly_complex_bool_expr,
        clippy::needless_update,
        clippy::unnecessary_get_then_check
    )]
    use super::*;
    use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
    use std::sync::Arc;
    use tokio::{net::TcpListener, sync::Mutex};

    #[derive(Clone, Default)]
    struct ResourceApiState {
        response: Arc<Mutex<Value>>,
    }

    async fn history_sessions_handler(State(state): State<ResourceApiState>) -> impl IntoResponse {
        Json(state.response.lock().await.clone())
    }

    async fn spawn_resource_api(response: Value) -> (AsyncApiClient, tokio::task::JoinHandle<()>) {
        let state = ResourceApiState {
            response: Arc::new(Mutex::new(response)),
        };
        let app = Router::new()
            .route("/v1/history/sessions", get(history_sessions_handler))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind resource api");
        let addr = listener.local_addr().expect("resource api addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve resource api");
        });
        let client = AsyncApiClient::new(format!("http://{addr}"), "test-token")
            .expect("resource api client");
        (client, handle)
    }

    #[test]
    fn resources_list_returns_array() {
        let list = resources_list();
        assert!(list.is_array());
    }

    #[test]
    fn resources_list_contains_history_sessions() {
        let list = resources_list();
        let resources = list.as_array().unwrap();
        let uris: Vec<&str> = resources
            .iter()
            .filter_map(|r| r.get("uri").and_then(|u| u.as_str()))
            .collect();
        assert!(uris.contains(&"history://sessions"));
        assert!(uris.contains(&"history://session/{id}"));
        assert!(uris.contains(&"gateway://effective-config"));
        assert!(uris.contains(&"gateway://tool-servers"));
        assert!(uris.contains(&"pricing://models"));
        assert!(uris.contains(&"regions://catalog"));
        assert!(uris.contains(&"regions://organization"));
        assert!(uris.contains(&"telemetry://providers"));
        assert!(uris.contains(&"context://team"));
        assert!(uris.contains(&"context://branch/{name}"));
        assert!(uris.contains(&"context://schema/{table}"));
        assert!(uris.contains(&"context://recent"));
    }

    #[test]
    fn resources_list_all_have_required_fields() {
        let list = resources_list();
        let resources = list.as_array().unwrap();
        for resource in resources {
            assert!(
                resource.get("uri").and_then(|u| u.as_str()).is_some(),
                "resource missing uri"
            );
            assert!(
                resource.get("name").and_then(|n| n.as_str()).is_some(),
                "resource missing name"
            );
            assert!(
                resource
                    .get("description")
                    .and_then(|d| d.as_str())
                    .is_some(),
                "resource missing description"
            );
            assert!(
                resource.get("mimeType").and_then(|m| m.as_str()).is_some(),
                "resource missing mimeType"
            );
        }
    }

    #[test]
    fn resources_list_descriptions_use_ste_constructions() {
        let disallowed = [
            "any", "required", "require", "requires", "need", "needs", "once", "both", "either",
            "already", "still", "never", "present", "intended", "valid", "instead",
        ];
        for resource in resources_list().as_array().expect("resources array") {
            let description = resource
                .get("description")
                .and_then(Value::as_str)
                .expect("resource description");
            let lowercase = description.to_ascii_lowercase();
            assert!(
                !lowercase.contains(';'),
                "MCP resource description contains a semicolon: {description}"
            );
            for word in lowercase.split(|character: char| {
                !character.is_ascii_alphanumeric() && character != '_' && character != '-'
            }) {
                assert!(
                    !disallowed.contains(&word),
                    "MCP resource description contains a non-STE construction '{word}': {description}"
                );
            }
        }
    }

    #[test]
    fn resources_list_history_sessions_is_json_mime() {
        let list = resources_list();
        let resources = list.as_array().unwrap();
        let history = resources
            .iter()
            .find(|r| r.get("uri").and_then(|u| u.as_str()) == Some("history://sessions"))
            .expect("history://sessions resource");
        assert_eq!(
            history.get("mimeType").and_then(|m| m.as_str()),
            Some("application/json")
        );
    }

    #[test]
    fn resource_matches_allow_entry_accepts_templates_wildcards_and_legacy_aliases() {
        assert!(resource_matches_allow_entry(
            "history://session/{id}",
            "history://session/sess%2F1?include_entries=true"
        ));
        assert!(resource_matches_allow_entry(
            "context://branch/*",
            "context://branch/{name}"
        ));
        assert!(resource_matches_allow_entry(
            "gateway-tool-servers://declared",
            "gateway://tool-servers"
        ));
        assert!(resource_matches_allow_entry(
            "gateway://tool-servers",
            "gateway-tool-servers://declared?path=/tmp/policy.yaml"
        ));
        assert!(!resource_matches_allow_entry(
            "regions://catalog",
            "telemetry://providers"
        ));
    }

    #[tokio::test]
    async fn read_resource_uses_items_fallback_when_sessions_key_is_absent() {
        let (client, handle) = spawn_resource_api(serde_json::json!({
            "items": [{"id": "sess-2", "title": "Fallback"}]
        }))
        .await;

        let result = read_resource(&client, "history://sessions")
            .await
            .expect("read resource");

        assert_eq!(
            result["contents"][0]["text"],
            "[{\"id\":\"sess-2\",\"title\":\"Fallback\"}]"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn read_resource_defaults_to_empty_array_when_payload_has_no_items() {
        let (client, handle) = spawn_resource_api(serde_json::json!({
            "unexpected": true
        }))
        .await;

        let result = read_resource(&client, "history://sessions")
            .await
            .expect("read resource");

        assert_eq!(result["contents"][0]["text"], "[]");

        handle.abort();
    }

    #[tokio::test]
    async fn read_resource_rejects_unknown_uris_with_clear_error() {
        let (client, handle) = spawn_resource_api(serde_json::json!({})).await;

        let error = read_resource(&client, "history://unknown")
            .await
            .expect_err("unknown URI should fail");

        assert!(error.to_string().contains("Unknown resource URI"));

        handle.abort();
    }
}
