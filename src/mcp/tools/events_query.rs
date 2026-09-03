// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: events_query

use serde_json::{json, Value};

use super::ToolContext;
use crate::api::AsyncApiClient;
use crate::error::CliError;

struct EventsLookupFilters<'a> {
    org_id: Option<&'a str>,
    event_source: Option<&'a str>,
    event_name: Option<&'a str>,
    resource_type: Option<&'a str>,
    resource_id: Option<&'a str>,
    actor_arn: Option<&'a str>,
    start_time: Option<&'a str>,
    end_time: Option<&'a str>,
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let request_id = argument_str(arguments, &["request_id"]);
    let session_id = argument_str(arguments, &["session_id"]);
    let tool_name = argument_str(arguments, &["tool_name"]);
    let entry_kind = argument_str(arguments, &["entry_kind"]);
    let limit = argument_u32(arguments, &["limit"], 50, 1, 1000);
    let history_limit = argument_u64(arguments, &["history_limit"], 20, 1, 200);
    let events_filters = EventsLookupFilters {
        org_id: argument_str(arguments, &["org_id"]),
        event_source: argument_str(arguments, &["event_source"]),
        event_name: argument_str(arguments, &["event_name"]),
        resource_type: argument_str(arguments, &["resource_type"]),
        resource_id: argument_str(arguments, &["resource_id"]),
        actor_arn: argument_str(arguments, &["actor_arn"]),
        start_time: argument_str(arguments, &["start_time", "since"]),
        end_time: argument_str(arguments, &["end_time", "until"]),
    };

    let path = if let Some(request_id) = request_id {
        build_request_id_lookup_path(request_id)
    } else {
        build_events_lookup_path(limit, &events_filters)
    };

    tracing::debug!(
        session_id = %ctx.session_id,
        request_id = request_id.unwrap_or(""),
        query_path = %path,
        "querying governance trail via MCP"
    );

    let trail_response = ctx.client.get_json_value(&path).await?;
    let events = extract_array(&trail_response, "events");
    let event_count = events.len();
    let history = match fetch_history_correlation(
        ctx.client,
        session_id,
        request_id,
        tool_name,
        entry_kind,
        history_limit,
    )
    .await
    {
        Ok(history) => history,
        Err(error) if error.http_status() == Some(404) && session_id.is_some() => {
            return Ok(with_region_resolution_metadata(
                ctx,
                json!({
                    "ok": false,
                    "filters": filters_json(arguments, limit, history_limit),
                    "events": events,
                    "error": {
                        "code": "events_query.history_session_not_found",
                        "message": error.to_string(),
                        "remediation": "Verify the supplied session_id, or omit it to query only the trail side of the correlation.",
                    }
                }),
            ));
        }
        Err(error) => return Err(error),
    };

    let history_match_count = history
        .get("match_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    Ok(with_region_resolution_metadata(
        ctx,
        json!({
            "ok": true,
            "filters": filters_json(arguments, limit, history_limit),
            "events": events,
            "trail_metadata": {
                "result_count": trail_response.get("result_count").cloned().unwrap_or_else(|| json!(event_count)),
                "next_cursor": trail_response.get("next_cursor").cloned().unwrap_or(Value::Null),
            },
            "history": history,
            "correlation": {
                "request_id": request_id,
                "session_id": session_id,
                "tool_name": tool_name,
                "entry_kind": entry_kind,
                "event_count": event_count,
                "history_match_count": history_match_count,
            }
        }),
    ))
}

pub(crate) async fn fetch_history_correlation(
    client: &AsyncApiClient,
    session_id: Option<&str>,
    request_id: Option<&str>,
    tool_name: Option<&str>,
    entry_kind: Option<&str>,
    history_limit: u64,
) -> Result<Value, CliError> {
    if let Some(session_id) = session_id {
        let entries_value = client
            .get_json_value(&build_session_entries_path(session_id, entry_kind))
            .await?;
        let matches = extract_array(&entries_value, "entries")
            .into_iter()
            .filter(|entry| {
                request_id.is_none_or(|expected| entry_matches_request_id(entry, expected))
            })
            .filter(|entry| {
                tool_name.is_none_or(|expected| entry_matches_tool_name(entry, expected))
            })
            .take(history_limit as usize)
            .collect::<Vec<_>>();

        return Ok(json!({
            "source": "session_entries",
            "session_id": session_id,
            "query": Value::Null,
            "match_count": matches.len(),
            "matches": matches,
        }));
    }

    let Some(query) = tool_name.or(request_id) else {
        return Ok(json!({
            "source": "none",
            "session_id": Value::Null,
            "query": Value::Null,
            "match_count": 0,
            "matches": [],
        }));
    };

    let history_response = client
        .get_json_value(&build_history_search_path(query, history_limit, entry_kind))
        .await?;
    let matches = extract_array(&history_response, "results");

    Ok(json!({
        "source": "history_search",
        "session_id": Value::Null,
        "query": query,
        "match_count": matches.len(),
        "matches": matches,
    }))
}

pub(crate) fn build_request_id_lookup_path(request_id: &str) -> String {
    format!(
        "/v1/trail/events/lookup?request_id={}",
        urlencoding::encode(request_id)
    )
}

fn build_events_lookup_path(limit: u32, filters: &EventsLookupFilters<'_>) -> String {
    let mut query_params = vec![format!("limit={limit}")];

    if let Some(org_id) = filters.org_id {
        query_params.push(format!("org_id={}", urlencoding::encode(org_id)));
    }
    if let Some(event_source) = filters.event_source {
        query_params.push(format!(
            "event_source={}",
            urlencoding::encode(event_source)
        ));
    }
    if let Some(event_name) = filters.event_name {
        query_params.push(format!("event_name={}", urlencoding::encode(event_name)));
    }
    if let Some(resource_type) = filters.resource_type {
        query_params.push(format!(
            "resource_type={}",
            urlencoding::encode(resource_type)
        ));
    }
    if let Some(resource_id) = filters.resource_id {
        query_params.push(format!("resource_id={}", urlencoding::encode(resource_id)));
    }
    if let Some(actor_arn) = filters.actor_arn {
        query_params.push(format!("actor_arn={}", urlencoding::encode(actor_arn)));
    }
    if let Some(start_time) = filters.start_time {
        query_params.push(format!("start_time={}", urlencoding::encode(start_time)));
    }
    if let Some(end_time) = filters.end_time {
        query_params.push(format!("end_time={}", urlencoding::encode(end_time)));
    }

    format!("/v1/trail/events?{}", query_params.join("&"))
}

pub(crate) fn build_history_search_path(
    query: &str,
    history_limit: u64,
    entry_kind: Option<&str>,
) -> String {
    let mut params = vec![
        format!("q={}", urlencoding::encode(query)),
        format!("limit={history_limit}"),
    ];
    if let Some(entry_kind) = entry_kind {
        params.push(format!("entry_kind={}", urlencoding::encode(entry_kind)));
    }
    format!("/v1/history/search?{}", params.join("&"))
}

pub(crate) fn build_session_entries_path(session_id: &str, entry_kind: Option<&str>) -> String {
    let encoded_session_id = urlencoding::encode(session_id);
    let mut params = Vec::new();
    if let Some(entry_kind) = entry_kind {
        params.push(format!("entry_kind={}", urlencoding::encode(entry_kind)));
    }

    if params.is_empty() {
        format!("/v1/history/sessions/{encoded_session_id}/entries")
    } else {
        format!(
            "/v1/history/sessions/{encoded_session_id}/entries?{}",
            params.join("&")
        )
    }
}

pub(crate) fn entry_matches_tool_name(entry: &Value, tool_name: &str) -> bool {
    contains_tool_name(entry, tool_name, false)
}

fn contains_tool_name(value: &Value, tool_name: &str, toolish_parent: bool) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, child)| {
            let key_lower = key.to_ascii_lowercase();
            let next_toolish = toolish_parent
                || matches!(
                    key_lower.as_str(),
                    "tool" | "tools" | "tool_call" | "tool_calls" | "function" | "metadata"
                );

            ((key_lower == "tool_name" || (toolish_parent && key_lower == "name"))
                && child.as_str() == Some(tool_name))
                || contains_tool_name(child, tool_name, next_toolish)
        }),
        Value::Array(items) => items
            .iter()
            .any(|item| contains_tool_name(item, tool_name, toolish_parent)),
        _ => false,
    }
}

fn entry_matches_request_id(entry: &Value, request_id: &str) -> bool {
    contains_request_id(entry, request_id, false)
}

fn contains_request_id(value: &Value, request_id: &str, requestish_parent: bool) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, child)| {
            let key_lower = key.to_ascii_lowercase();
            let next_requestish = requestish_parent
                || key_lower.contains("request")
                || key_lower == "headers"
                || key_lower == "metadata";

            ((key_lower.contains("request_id")
                || key_lower == "x-request-id"
                || (requestish_parent && key_lower == "id"))
                && child.as_str() == Some(request_id))
                || contains_request_id(child, request_id, next_requestish)
        }),
        Value::Array(items) => items
            .iter()
            .any(|item| contains_request_id(item, request_id, requestish_parent)),
        _ => false,
    }
}

fn extract_array(value: &Value, key: &str) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

pub(crate) fn argument_str<'a>(arguments: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| {
        arguments
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

pub(crate) fn argument_u64(
    arguments: &Value,
    keys: &[&str],
    default: u64,
    min: u64,
    max: u64,
) -> u64 {
    keys.iter()
        .find_map(|key| arguments.get(*key).and_then(Value::as_u64))
        .unwrap_or(default)
        .clamp(min, max)
}

fn argument_u32(arguments: &Value, keys: &[&str], default: u32, min: u32, max: u32) -> u32 {
    keys.iter()
        .find_map(|key| arguments.get(*key).and_then(Value::as_u64))
        .map(|value| value.min(u32::MAX as u64) as u32)
        .unwrap_or(default)
        .clamp(min, max)
}

fn filters_json(arguments: &Value, limit: u32, history_limit: u64) -> Value {
    json!({
        "request_id": argument_str(arguments, &["request_id"]),
        "session_id": argument_str(arguments, &["session_id"]),
        "tool_name": argument_str(arguments, &["tool_name"]),
        "entry_kind": argument_str(arguments, &["entry_kind"]),
        "org_id": argument_str(arguments, &["org_id"]),
        "event_source": argument_str(arguments, &["event_source"]),
        "event_name": argument_str(arguments, &["event_name"]),
        "resource_type": argument_str(arguments, &["resource_type"]),
        "resource_id": argument_str(arguments, &["resource_id"]),
        "actor_arn": argument_str(arguments, &["actor_arn"]),
        "start_time": argument_str(arguments, &["start_time", "since"]),
        "end_time": argument_str(arguments, &["end_time", "until"]),
        "limit": limit,
        "history_limit": history_limit,
    })
}

fn with_region_resolution_metadata(ctx: &ToolContext<'_>, value: Value) -> Value {
    match value {
        Value::Object(mut object) => {
            object.extend(super::session_region_resolution_metadata(ctx.client));
            Value::Object(object)
        }
        other => other,
    }
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

    use axum::{
        extract::{OriginalUri, Path, State},
        routing::get,
        Json, Router,
    };
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct MockApiState {
        paths: Arc<Mutex<Vec<String>>>,
    }

    impl MockApiState {
        fn push_path(&self, value: String) {
            self.paths.lock().expect("paths lock").push(value);
        }

        fn paths(&self) -> Vec<String> {
            self.paths.lock().expect("paths lock").clone()
        }
    }

    async fn trail_lookup_handler(
        State(state): State<MockApiState>,
        uri: OriginalUri,
    ) -> Json<Value> {
        state.push_path(uri.0.to_string());
        Json(json!({
            "events": [{
                "request_id": "req-1",
                "event_name": "ToolApproved"
            }],
            "result_count": 1
        }))
    }

    async fn history_entries_handler(
        State(state): State<MockApiState>,
        Path(session_id): Path<String>,
        uri: OriginalUri,
    ) -> Json<Value> {
        state.push_path(uri.0.to_string());
        Json(json!({
            "session_id": session_id,
            "entries": [
                {
                    "entry_kind": "assistant",
                    "metadata": {
                        "tool_name": "repo_search",
                        "request_id": "req-1"
                    }
                },
                {
                    "entry_kind": "assistant",
                    "metadata": {
                        "tool_name": "other_tool",
                        "request_id": "req-2"
                    }
                }
            ]
        }))
    }

    async fn history_search_handler(
        State(state): State<MockApiState>,
        uri: OriginalUri,
    ) -> Json<Value> {
        state.push_path(uri.0.to_string());
        Json(json!({
            "results": [{
                "session_id": "sess-search",
                "session_title": "Search correlation",
                "excerpt": "repo_search",
                "entry_kind": "assistant"
            }]
        }))
    }

    async fn start_mock_api() -> (AsyncApiClient, MockApiState, tokio::task::JoinHandle<()>) {
        let state = MockApiState::default();
        let app = Router::new()
            .route("/v1/trail/events/lookup", get(trail_lookup_handler))
            .route("/v1/history/search", get(history_search_handler))
            .route(
                "/v1/history/sessions/:id/entries",
                get(history_entries_handler),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock api");
        let addr = listener.local_addr().expect("mock api addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock api");
        });
        let client =
            AsyncApiClient::new(format!("http://{addr}"), "test-token").expect("mock api client");
        (client, state, handle)
    }

    #[test]
    fn build_session_entries_path_encodes_ids_and_optional_kind() {
        assert_eq!(
            build_session_entries_path("sess/1", Some("assistant")),
            "/v1/history/sessions/sess%2F1/entries?entry_kind=assistant"
        );
        assert_eq!(
            build_session_entries_path("sess-1", None),
            "/v1/history/sessions/sess-1/entries"
        );
    }

    #[test]
    fn entry_matches_tool_name_finds_nested_tool_call_names() {
        let entry = json!({
            "response_payload": {
                "tool_calls": [{
                    "function": {
                        "name": "repo_search"
                    }
                }]
            }
        });

        assert!(entry_matches_tool_name(&entry, "repo_search"));
        assert!(!entry_matches_tool_name(&entry, "other_tool"));
    }

    #[tokio::test]
    async fn execute_correlates_trail_events_with_session_entries() {
        let (client, state, handle) = start_mock_api().await;
        let client = client.with_region(Some("eu-west".to_string()));
        let expected_api_endpoint = client.join_url("").trim_end_matches('/').to_string();
        let ctx = ToolContext {
            client: &client,
            session_id: "session-1",
        };

        let result = execute(
            &ctx,
            &json!({
                "request_id": "req-1",
                "session_id": "sess-1",
                "entry_kind": "assistant",
                "tool_name": "repo_search"
            }),
        )
        .await
        .expect("events query result");

        assert_eq!(result["ok"], true);
        assert_eq!(result["events"].as_array().unwrap().len(), 1);
        assert_eq!(result["history"]["source"], "session_entries");
        assert_eq!(result["history"]["matches"].as_array().unwrap().len(), 1);
        assert_eq!(result["resolved_region"], "eu-west");
        assert_eq!(result["resolved_region_source"], "mcp session region");
        assert_eq!(result["resolved_api_endpoint"], expected_api_endpoint);
        assert!(state
            .paths()
            .contains(&"/v1/trail/events/lookup?request_id=req-1".to_string()));

        handle.abort();
    }

    #[tokio::test]
    async fn fetch_history_correlation_falls_back_to_history_search_without_session() {
        let (client, state, handle) = start_mock_api().await;

        let history = fetch_history_correlation(
            &client,
            None,
            Some("req-1"),
            Some("repo_search"),
            Some("assistant"),
            5,
        )
        .await
        .expect("history correlation");

        assert_eq!(history["source"], "history_search");
        assert_eq!(history["match_count"], 1);
        assert!(state
            .paths()
            .iter()
            .any(|path| path.starts_with("/v1/history/search?q=repo_search")));

        handle.abort();
    }
}
