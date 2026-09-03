// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: request_trace_get

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::events_query::{
    argument_str, argument_u64, build_request_id_lookup_path, fetch_history_correlation,
};
use super::ToolContext;
use crate::error::CliError;

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let request_id = argument_str(arguments, &["request_id"])
        .ok_or_else(|| CliError::user("request_trace_get requires 'request_id'"))?;
    let explicit_session_id = argument_str(arguments, &["session_id"]);
    let tool_name = argument_str(arguments, &["tool_name"]);
    let entry_kind = argument_str(arguments, &["entry_kind"]);
    let history_limit = argument_u64(arguments, &["history_limit"], 20, 1, 200);
    let trace_limit = argument_u64(arguments, &["trace_limit"], 5, 1, 50);

    tracing::debug!(
        session_id = %ctx.session_id,
        request_id = %request_id,
        "reading workflow trace via MCP"
    );

    let summary_response = ctx
        .client
        .get_json_value(&build_workflow_trace_lookup_path(request_id, trace_limit))
        .await?;
    let items = extract_array(&summary_response, "items");

    if items.is_empty() {
        return Ok(json!({
            "ok": false,
            "request_id": request_id,
            "error": {
                "code": "request_trace.not_found",
                "message": format!("no workflow trace matched request_id '{}'", request_id),
                "remediation": "Verify the request_id and ensure the MCP credential can read tracing data before retrying.",
            }
        }));
    }

    let trace_summary = items[0].clone();
    let Some(trace_id) = trace_summary
        .get("trace_id")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return Ok(json!({
            "ok": false,
            "request_id": request_id,
            "error": {
                "code": "request_trace.malformed_summary",
                "message": "the workflow trace summary did not include a trace_id",
                "remediation": "Inspect the underlying control-plane response and restore the admin workflow trace contract before relying on this MCP tool.",
            }
        }));
    };

    let trace = match ctx
        .client
        .get_json_value(&build_workflow_trace_detail_path(&trace_id))
        .await
    {
        Ok(trace) => trace,
        Err(error) if error.http_status() == Some(404) => {
            return Ok(json!({
                "ok": false,
                "request_id": request_id,
                "trace_id": trace_id,
                "error": {
                    "code": "request_trace.detail_not_found",
                    "message": error.to_string(),
                    "remediation": "Retry after the control plane finishes indexing the trace detail, or confirm the trace_id still exists.",
                }
            }));
        }
        Err(error) => return Err(error),
    };
    let audit_response = ctx
        .client
        .get_json_value(&build_request_id_lookup_path(request_id))
        .await?;
    let audit_events = extract_array(&audit_response, "events");

    let discovered_session_ids = extract_session_ids(&trace);
    let chosen_session_id =
        explicit_session_id.or_else(|| discovered_session_ids.first().map(String::as_str));
    let explicit_session_id_json = explicit_session_id.map(str::to_string);
    let selected_session_id_json = chosen_session_id.map(str::to_string);
    let history = match fetch_history_correlation(
        ctx.client,
        chosen_session_id,
        Some(request_id),
        tool_name,
        entry_kind,
        history_limit,
    )
    .await
    {
        Ok(history) => history,
        Err(error) if error.http_status() == Some(404) => json!({
            "source": "session_entries",
            "session_id": chosen_session_id,
            "query": Value::Null,
            "match_count": 0,
            "matches": [],
            "warning": error.to_string(),
        }),
        Err(error) => return Err(error),
    };
    let audit_event_count = audit_events.len();
    let history_match_count = history
        .get("match_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    Ok(json!({
        "ok": true,
        "request_id": request_id,
        "trace_id": trace_id,
        "trace_summary": trace_summary,
        "trace": trace,
        "audit_events": audit_events,
        "history": history,
        "resolved_session_ids": discovered_session_ids,
        "correlation": {
            "explicit_session_id": explicit_session_id_json,
            "selected_session_id": selected_session_id_json,
            "tool_name": tool_name,
            "entry_kind": entry_kind,
            "audit_event_count": audit_event_count,
            "history_match_count": history_match_count,
        }
    }))
}

fn build_workflow_trace_lookup_path(request_id: &str, limit: u64) -> String {
    format!(
        "/v1/admin/workflow-traces?request_id={}&limit={limit}",
        urlencoding::encode(request_id)
    )
}

fn build_workflow_trace_detail_path(trace_id: &str) -> String {
    format!(
        "/v1/admin/workflow-traces/{}",
        urlencoding::encode(trace_id)
    )
}

fn extract_array(value: &Value, key: &str) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn extract_session_ids(value: &Value) -> Vec<String> {
    let mut session_ids = BTreeSet::new();
    collect_session_ids(value, &mut session_ids);
    session_ids.into_iter().collect()
}

fn collect_session_ids(value: &Value, session_ids: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key.eq_ignore_ascii_case("session_id")
                    || key.eq_ignore_ascii_case("history_session_id")
                    || key.eq_ignore_ascii_case("conversation_session_id")
                {
                    if let Some(session_id) = child
                        .as_str()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                    {
                        session_ids.insert(session_id.to_string());
                    }
                }
                collect_session_ids(child, session_ids);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_session_ids(item, session_ids);
            }
        }
        _ => {}
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
        extract::{OriginalUri, State},
        routing::get,
        Json, Router,
    };
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::api::AsyncApiClient;

    #[derive(Clone, Default)]
    struct MockApiState {
        paths: Arc<Mutex<Vec<String>>>,
    }

    impl MockApiState {
        fn push_path(&self, value: String) {
            self.paths.lock().expect("paths lock").push(value);
        }
    }

    async fn workflow_traces_handler(
        State(state): State<MockApiState>,
        uri: OriginalUri,
    ) -> Json<Value> {
        state.push_path(uri.0.to_string());
        Json(json!({
            "items": [{
                "trace_id": "trace-1",
                "request_id": "req-1"
            }]
        }))
    }

    async fn workflow_trace_detail_handler(
        State(state): State<MockApiState>,
        uri: OriginalUri,
    ) -> Json<Value> {
        state.push_path(uri.0.to_string());
        Json(json!({
            "trace_id": "trace-1",
            "spans": [{
                "span_id": "span-1",
                "metadata": {
                    "session_id": "sess-1"
                }
            }]
        }))
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
            }]
        }))
    }

    async fn history_entries_handler(
        State(state): State<MockApiState>,
        uri: OriginalUri,
    ) -> Json<Value> {
        state.push_path(uri.0.to_string());
        Json(json!({
            "entries": [{
                "entry_kind": "assistant",
                "metadata": {
                    "tool_name": "repo_search",
                    "request_id": "req-1"
                }
            }]
        }))
    }

    async fn start_mock_api() -> (AsyncApiClient, tokio::task::JoinHandle<()>) {
        let state = MockApiState::default();
        let app = Router::new()
            .route("/v1/admin/workflow-traces", get(workflow_traces_handler))
            .route(
                "/v1/admin/workflow-traces/:trace_id",
                get(workflow_trace_detail_handler),
            )
            .route("/v1/trail/events/lookup", get(trail_lookup_handler))
            .route(
                "/v1/history/sessions/:id/entries",
                get(history_entries_handler),
            )
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock api");
        let addr = listener.local_addr().expect("mock api addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock api");
        });
        let client =
            AsyncApiClient::new(format!("http://{addr}"), "test-token").expect("mock api client");
        (client, handle)
    }

    #[test]
    fn extract_session_ids_finds_nested_trace_metadata() {
        let trace = json!({
            "spans": [{
                "metadata": {
                    "session_id": "sess-1"
                }
            }, {
                "input": {
                    "conversation_session_id": "sess-2"
                }
            }]
        });

        assert_eq!(
            extract_session_ids(&trace),
            vec!["sess-1".to_string(), "sess-2".to_string()]
        );
    }

    #[tokio::test]
    async fn execute_returns_structured_not_found_payload_when_trace_absent() {
        let app = Router::new().route(
            "/v1/admin/workflow-traces",
            get(|| async { Json(json!({"items": []})) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind api");
        let addr = listener.local_addr().expect("api addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve api");
        });
        let client =
            AsyncApiClient::new(format!("http://{addr}"), "test-token").expect("mock api client");
        let ctx = ToolContext {
            client: &client,
            session_id: "session-1",
        };

        let result = execute(&ctx, &json!({"request_id": "missing"}))
            .await
            .expect("trace lookup result");

        assert_eq!(result["ok"], false);
        assert_eq!(result["error"]["code"], "request_trace.not_found");

        handle.abort();
    }

    #[tokio::test]
    async fn execute_returns_trace_audit_and_history_correlation() {
        let (client, handle) = start_mock_api().await;
        let ctx = ToolContext {
            client: &client,
            session_id: "session-1",
        };

        let result = execute(
            &ctx,
            &json!({
                "request_id": "req-1",
                "tool_name": "repo_search",
                "entry_kind": "assistant"
            }),
        )
        .await
        .expect("trace lookup result");

        assert_eq!(result["ok"], true);
        assert_eq!(result["trace_id"], "trace-1");
        assert_eq!(result["audit_events"].as_array().unwrap().len(), 1);
        assert_eq!(result["history"]["source"], "session_entries");
        assert_eq!(result["history"]["match_count"], 1);

        handle.abort();
    }
}
