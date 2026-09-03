// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: history_search

use serde_json::Value;

use super::ToolContext;
use crate::error::CliError;

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let query = arguments
        .get("query")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::user("history_search requires 'query' parameter"))?;

    let limit = arguments.get("limit").and_then(Value::as_u64).unwrap_or(20);

    let mut params = vec![
        format!("q={}", urlencoding::encode(query)),
        format!("limit={limit}"),
    ];
    if let Some(entry_kind) = arguments.get("entry_kind").and_then(Value::as_str) {
        params.push(format!("entry_kind={}", urlencoding::encode(entry_kind)));
    }
    if let Some(agent_id) = arguments.get("agent_id").and_then(Value::as_str) {
        params.push(format!("agent_id={}", urlencoding::encode(agent_id)));
    }

    let path = format!("/v1/history/search?{}", params.join("&"));

    tracing::debug!(
        query = %query,
        limit = limit,
        session_id = %ctx.session_id,
        "searching history via MCP"
    );

    let response = ctx.client.get_json_value(&path).await?;

    let results = response
        .get("results")
        .cloned()
        .unwrap_or(Value::Array(vec![]));

    // Normalize results to expected shape
    let normalized: Vec<Value> = results
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .map(|r| {
            serde_json::json!({
                "session_id": r.get("session_id").and_then(Value::as_str).unwrap_or(""),
                "session_title": r.get("session_title").or_else(|| r.get("title")).and_then(Value::as_str).unwrap_or(""),
                "excerpt": r.get("excerpt").or_else(|| r.get("snippet")).and_then(Value::as_str).unwrap_or(""),
                "entry_kind": r.get("entry_kind").and_then(Value::as_str).unwrap_or(""),
                "captured_at": r.get("captured_at").or_else(|| r.get("created_at")).and_then(Value::as_str).unwrap_or(""),
            })
        })
        .collect();

    let mut result = serde_json::Map::new();
    result.insert("results".to_string(), Value::Array(normalized));
    result.extend(super::session_region_resolution_metadata(ctx.client));

    Ok(Value::Object(result))
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
    use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
    use serde_json::{json, Value};
    use std::sync::Arc;
    use tokio::{net::TcpListener, sync::Mutex};

    use crate::api::AsyncApiClient;

    #[test]
    fn query_param_extraction() {
        let args = json!({"query": "hello", "limit": 10});
        let query = args.get("query").and_then(Value::as_str).unwrap();
        let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(20);
        assert_eq!(query, "hello");
        assert_eq!(limit, 10);
    }

    #[test]
    fn query_param_default_limit() {
        let args = json!({"query": "search term"});
        let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(20);
        assert_eq!(limit, 20);
    }

    #[test]
    fn query_param_missing_query_detected() {
        let args = json!({});
        let query = args.get("query").and_then(Value::as_str);
        assert!(query.is_none());
    }

    #[test]
    fn path_construction() {
        let query = "test search";
        let limit = 20u64;
        let mut params = vec![
            format!("q={}", urlencoding::encode(query)),
            format!("limit={limit}"),
        ];
        params.push(format!("entry_kind={}", urlencoding::encode("request")));
        let path = format!("/v1/history/search?{}", params.join("&"));
        assert!(path.starts_with("/v1/history/search?"));
        assert!(path.contains("q=test%20search"));
        assert!(path.contains("limit=20"));
        assert!(path.contains("entry_kind=request"));
    }

    #[test]
    fn path_construction_minimal() {
        let query = "hello";
        let limit = 5u64;
        let params = vec![
            format!("q={}", urlencoding::encode(query)),
            format!("limit={limit}"),
        ];
        let path = format!("/v1/history/search?{}", params.join("&"));
        assert_eq!(path, "/v1/history/search?q=hello&limit=5");
    }

    #[test]
    fn normalize_result_entry() {
        let r = json!({
            "session_id": "s-1",
            "session_title": "Chat 1",
            "excerpt": "some text",
            "entry_kind": "request",
            "captured_at": "2025-06-01T00:00:00Z",
        });
        let normalized = json!({
            "session_id": r.get("session_id").and_then(Value::as_str).unwrap_or(""),
            "session_title": r.get("session_title").or_else(|| r.get("title")).and_then(Value::as_str).unwrap_or(""),
            "excerpt": r.get("excerpt").or_else(|| r.get("snippet")).and_then(Value::as_str).unwrap_or(""),
            "entry_kind": r.get("entry_kind").and_then(Value::as_str).unwrap_or(""),
            "captured_at": r.get("captured_at").or_else(|| r.get("created_at")).and_then(Value::as_str).unwrap_or(""),
        });
        assert_eq!(normalized["session_id"], "s-1");
        assert_eq!(normalized["session_title"], "Chat 1");
        assert_eq!(normalized["excerpt"], "some text");
    }

    #[test]
    fn normalize_result_with_fallback_fields() {
        let r = json!({
            "session_id": "s-2",
            "title": "Fallback Title",
            "snippet": "fallback text",
            "entry_kind": "response",
            "created_at": "2025-06-02T00:00:00Z",
        });
        let title = r
            .get("session_title")
            .or_else(|| r.get("title"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let excerpt = r
            .get("excerpt")
            .or_else(|| r.get("snippet"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let captured = r
            .get("captured_at")
            .or_else(|| r.get("created_at"))
            .and_then(Value::as_str)
            .unwrap_or("");
        assert_eq!(title, "Fallback Title");
        assert_eq!(excerpt, "fallback text");
        assert_eq!(captured, "2025-06-02T00:00:00Z");
    }

    #[test]
    fn normalize_result_empty_defaults() {
        let r = json!({});
        let session_id = r.get("session_id").and_then(Value::as_str).unwrap_or("");
        let title = r
            .get("session_title")
            .or_else(|| r.get("title"))
            .and_then(Value::as_str)
            .unwrap_or("");
        assert_eq!(session_id, "");
        assert_eq!(title, "");
    }

    #[derive(Clone, Default)]
    struct SearchApiState {
        requests: Arc<Mutex<Vec<String>>>,
        response: Arc<Mutex<Value>>,
    }

    async fn history_search_handler(
        State(state): State<SearchApiState>,
        uri: axum::http::Uri,
    ) -> impl IntoResponse {
        state.requests.lock().await.push(
            uri.path_and_query()
                .map(|value| value.to_string())
                .unwrap_or_default(),
        );
        Json(state.response.lock().await.clone())
    }

    async fn spawn_history_search_api(
        response: Value,
    ) -> (AsyncApiClient, SearchApiState, tokio::task::JoinHandle<()>) {
        let state = SearchApiState {
            requests: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(response)),
        };
        let app = Router::new()
            .route("/v1/history/search", get(history_search_handler))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind history search api");
        let addr = listener.local_addr().expect("history search api addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve history search api");
        });
        let client =
            AsyncApiClient::new(format!("http://{addr}"), "test-token").expect("mock api client");
        (client, state, handle)
    }

    #[tokio::test]
    async fn execute_builds_encoded_query_and_normalizes_fallback_fields() {
        let (client, state, handle) = spawn_history_search_api(json!({
            "results": [
                {
                    "session_id": "sess-1",
                    "title": "Fallback Title",
                    "snippet": "fallback excerpt",
                    "entry_kind": "assistant",
                    "created_at": "2026-06-27T12:00:00Z"
                },
                {
                    "session_id": "sess-2",
                    "session_title": "Primary Title",
                    "excerpt": "primary excerpt",
                    "entry_kind": "user",
                    "captured_at": "2026-06-27T12:01:00Z"
                }
            ]
        }))
        .await;
        let client = client.with_region(Some("eu-west".to_string()));
        let expected_api_endpoint = client.join_url("").trim_end_matches('/').to_string();
        let ctx = super::ToolContext {
            client: &client,
            session_id: "session-1",
        };

        let result = super::execute(
            &ctx,
            &json!({
                "query": "refund request",
                "limit": 5,
                "entry_kind": "assistant response",
                "agent_id": "agent/1"
            }),
        )
        .await
        .expect("history search execution");

        let requests = state.requests.lock().await.clone();
        assert_eq!(
            requests,
            vec![
                "/v1/history/search?q=refund%20request&limit=5&entry_kind=assistant%20response&agent_id=agent%2F1"
                    .to_string()
            ]
        );
        assert_eq!(result["results"][0]["session_title"], "Fallback Title");
        assert_eq!(result["results"][0]["excerpt"], "fallback excerpt");
        assert_eq!(result["results"][0]["captured_at"], "2026-06-27T12:00:00Z");
        assert_eq!(result["results"][1]["session_title"], "Primary Title");
        assert_eq!(result["results"][1]["excerpt"], "primary excerpt");
        assert_eq!(result["resolved_region"], "eu-west");
        assert_eq!(result["resolved_region_source"], "mcp session region");
        assert_eq!(result["resolved_api_endpoint"], expected_api_endpoint);

        handle.abort();
    }

    #[tokio::test]
    async fn execute_returns_empty_results_for_non_array_payloads() {
        let (client, _state, handle) =
            spawn_history_search_api(json!({ "results": { "unexpected": true } })).await;
        let ctx = super::ToolContext {
            client: &client,
            session_id: "session-2",
        };

        let result = super::execute(&ctx, &json!({ "query": "hello" }))
            .await
            .expect("history search execution");

        assert_eq!(
            result,
            json!({
                "results": [],
                "resolved_region": null,
                "resolved_region_source": null,
                "resolved_api_endpoint": client.join_url("").trim_end_matches('/'),
            })
        );

        handle.abort();
    }

    #[tokio::test]
    async fn execute_requires_query_parameter() {
        let (client, _state, handle) = spawn_history_search_api(json!({})).await;
        let ctx = super::ToolContext {
            client: &client,
            session_id: "session-3",
        };

        let error = super::execute(&ctx, &json!({ "limit": 3 }))
            .await
            .expect_err("missing query should fail");

        assert!(error
            .to_string()
            .contains("history_search requires 'query' parameter"));

        handle.abort();
    }
}
