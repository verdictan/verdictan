// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP resource for reading a single history session.

use serde_json::{json, Value};

use crate::api::AsyncApiClient;
use crate::error::CliError;

const RESOURCE_URI_TEMPLATE: &str = "history://session/{id}";
const RESOURCE_URI_PREFIX: &str = "history://session/";

pub(crate) fn descriptor() -> Value {
    json!({
        "uri": RESOURCE_URI_TEMPLATE,
        "name": "History Session",
        "description": "Read a specified history session. Use '?include_entries=true'. Use optional '?entry_kind=...' to filter embedded entries.",
        "mimeType": "application/json"
    })
}

pub(crate) fn matches_uri(uri: &str) -> bool {
    resource_suffix(uri)
        .map(|suffix| {
            let session_id = suffix.split_once('?').map_or(suffix, |(value, _)| value);
            !session_id.trim().is_empty()
        })
        .unwrap_or(false)
}

pub(crate) async fn read_resource(client: &AsyncApiClient, uri: &str) -> Result<Value, CliError> {
    let request = parse_resource_uri(uri)?;

    tracing::debug!(
        uri = %uri,
        session_id = %request.session_id,
        include_entries = request.include_entries,
        entry_kind = request.entry_kind.as_deref().unwrap_or(""),
        "reading history session MCP resource"
    );

    let session = client
        .get_json_value(&build_session_path(&request.session_id))
        .await?;
    let entries = if request.include_entries {
        client
            .get_json_value(&build_entries_path(
                &request.session_id,
                request.entry_kind.as_deref(),
            ))
            .await?
    } else {
        Value::Null
    };

    wrap_json_contents(
        uri,
        json!({
            "session_id": request.session_id,
            "include_entries": request.include_entries,
            "entry_kind": request.entry_kind,
            "session": session,
            "entries": entries,
        }),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedResourceUri {
    session_id: String,
    include_entries: bool,
    entry_kind: Option<String>,
}

fn parse_resource_uri(uri: &str) -> Result<ParsedResourceUri, CliError> {
    let suffix = resource_suffix(uri)
        .ok_or_else(|| CliError::user(format!("Unknown history session resource URI: {uri}")))?;
    let (raw_session_id, _) = suffix.split_once('?').unwrap_or((suffix, ""));
    if raw_session_id.trim().is_empty() {
        return Err(CliError::user(format!(
            "History session resource URI must include a session id: {uri}"
        )));
    }

    let session_id = decode_component(raw_session_id);
    let include_entries = query_values(uri, &["include_entries"])
        .last()
        .is_some_and(|value| parse_bool_flag(value));
    let entry_kind = query_values(uri, &["entry_kind"])
        .into_iter()
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty());

    Ok(ParsedResourceUri {
        session_id,
        include_entries,
        entry_kind,
    })
}

fn resource_suffix(uri: &str) -> Option<&str> {
    uri.strip_prefix(RESOURCE_URI_PREFIX)
}

fn build_session_path(session_id: &str) -> String {
    format!("/v1/history/sessions/{}", urlencoding::encode(session_id))
}

fn build_entries_path(session_id: &str, entry_kind: Option<&str>) -> String {
    let base = format!(
        "/v1/history/sessions/{}/entries",
        urlencoding::encode(session_id)
    );
    match entry_kind {
        Some(entry_kind) => format!("{base}?entry_kind={}", urlencoding::encode(entry_kind)),
        None => base,
    }
}

fn query_values(uri: &str, keys: &[&str]) -> Vec<String> {
    let Some((_, query)) = uri.split_once('?') else {
        return Vec::new();
    };

    query
        .split('&')
        .filter_map(|pair| {
            let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
            keys.iter()
                .any(|candidate| raw_key.eq_ignore_ascii_case(candidate))
                .then(|| decode_component(raw_value))
        })
        .collect()
}

fn decode_component(raw_value: &str) -> String {
    match urlencoding::decode(raw_value) {
        Ok(value) => value.into_owned(),
        Err(_) => raw_value.to_string(),
    }
}

fn parse_bool_flag(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn wrap_json_contents(uri: &str, payload: Value) -> Result<Value, CliError> {
    let text = serde_json::to_string(&payload).map_err(|error| {
        CliError::internal(format!("failed to encode resource payload: {error}"))
    })?;

    Ok(json!({
        "contents": [{
            "uri": uri,
            "mimeType": "application/json",
            "text": text
        }]
    }))
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

    use std::sync::{Arc, Mutex};

    use axum::{
        extract::{OriginalUri, State},
        routing::get,
        Json, Router,
    };

    use super::*;

    #[derive(Clone, Default)]
    struct MockApiState {
        paths: Arc<Mutex<Vec<String>>>,
    }

    impl MockApiState {
        fn push_path(&self, path: String) {
            self.paths.lock().expect("paths lock").push(path);
        }

        fn paths(&self) -> Vec<String> {
            self.paths.lock().expect("paths lock").clone()
        }
    }

    async fn history_session_handler(
        State(state): State<MockApiState>,
        uri: OriginalUri,
    ) -> Json<Value> {
        state.push_path(uri.0.to_string());
        Json(json!({
            "session": {
                "session_id": "sess/1",
                "scope": "team",
                "entry_count": 2
            }
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
                "content": "matched entry"
            }]
        }))
    }

    async fn start_mock_api() -> (AsyncApiClient, MockApiState, tokio::task::JoinHandle<()>) {
        let state = MockApiState::default();
        let app = Router::new()
            .route("/v1/history/sessions/:id", get(history_session_handler))
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
    fn descriptor_uses_template_uri() {
        assert_eq!(descriptor()["uri"], RESOURCE_URI_TEMPLATE);
        assert_eq!(descriptor()["mimeType"], "application/json");
    }

    #[test]
    fn matches_uri_accepts_session_reads_with_optional_queries() {
        assert!(matches_uri("history://session/sess-1"));
        assert!(matches_uri(
            "history://session/sess%2F1?include_entries=true&entry_kind=assistant"
        ));
        assert!(!matches_uri("history://session/"));
        assert!(!matches_uri("history://sessions"));
    }

    #[test]
    fn parse_resource_uri_decodes_session_id_and_queries() {
        let parsed = parse_resource_uri(
            "history://session/sess%2F1?include_entries=yes&entry_kind=assistant",
        )
        .expect("parsed resource uri");

        assert_eq!(
            parsed,
            ParsedResourceUri {
                session_id: "sess/1".to_string(),
                include_entries: true,
                entry_kind: Some("assistant".to_string()),
            }
        );
    }

    #[tokio::test]
    async fn read_resource_fetches_session_only_by_default() {
        let (client, state, handle) = start_mock_api().await;

        let result = read_resource(&client, "history://session/sess%2F1")
            .await
            .expect("resource read");
        let payload: Value =
            serde_json::from_str(result["contents"][0]["text"].as_str().unwrap()).unwrap();

        assert_eq!(payload["session_id"], "sess/1");
        assert_eq!(payload["include_entries"], false);
        assert!(payload["entry_kind"].is_null());
        assert_eq!(payload["session"]["session"]["session_id"], "sess/1");
        assert!(payload["entries"].is_null());
        assert_eq!(state.paths(), vec!["/v1/history/sessions/sess%2F1"]);

        handle.abort();
    }

    #[tokio::test]
    async fn read_resource_embeds_entries_when_requested() {
        let (client, state, handle) = start_mock_api().await;

        let result = read_resource(
            &client,
            "history://session/sess%2F1?include_entries=true&entry_kind=assistant",
        )
        .await
        .expect("resource read");
        let payload: Value =
            serde_json::from_str(result["contents"][0]["text"].as_str().unwrap()).unwrap();

        assert_eq!(payload["include_entries"], true);
        assert_eq!(payload["entry_kind"], "assistant");
        assert_eq!(payload["entries"]["entries"][0]["content"], "matched entry");
        assert_eq!(
            state.paths(),
            vec![
                "/v1/history/sessions/sess%2F1".to_string(),
                "/v1/history/sessions/sess%2F1/entries?entry_kind=assistant".to_string(),
            ]
        );

        handle.abort();
    }
}
