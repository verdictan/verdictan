// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP resource for organization region visibility metadata.

use serde_json::Value;

use crate::api::AsyncApiClient;
use crate::error::CliError;

const RESOURCE_URI: &str = "regions://organization";
const LEGACY_RESOURCE_URI: &str = "regions-organization://visible";

pub(crate) fn descriptor() -> Value {
    serde_json::json!({
        "uri": RESOURCE_URI,
        "name": "Organization Regions",
        "description": "Authenticated organization region metadata from /v1/organization/regions.",
        "mimeType": "application/json"
    })
}

pub(crate) fn matches_uri(uri: &str) -> bool {
    uri == RESOURCE_URI || uri == LEGACY_RESOURCE_URI
}

pub(crate) async fn read_resource(client: &AsyncApiClient, uri: &str) -> Result<Value, CliError> {
    if !matches_uri(uri) {
        return Err(CliError::user(format!(
            "Unknown organization regions resource URI: {uri}"
        )));
    }

    tracing::debug!(uri = %uri, "reading organization regions MCP resource");

    let response = client.get_json_value("/v1/organization/regions").await?;
    let cells = response
        .get("cells")
        .or_else(|| response.get("regions"))
        .or_else(|| response.get("items"))
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));

    wrap_json_contents(
        uri,
        serde_json::json!({
            "cells": cells,
        }),
    )
}

fn wrap_json_contents(uri: &str, payload: Value) -> Result<Value, CliError> {
    let text = serde_json::to_string(&payload).map_err(|error| {
        CliError::internal(format!("failed to encode resource payload: {error}"))
    })?;

    Ok(serde_json::json!({
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

    use super::*;
    use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
    use std::sync::Arc;
    use tokio::{net::TcpListener, sync::Mutex};

    #[derive(Clone, Default)]
    struct RegionsApiState {
        response: Arc<Mutex<Value>>,
    }

    async fn organization_regions_handler(
        State(state): State<RegionsApiState>,
    ) -> impl IntoResponse {
        Json(state.response.lock().await.clone())
    }

    async fn spawn_regions_api(response: Value) -> (AsyncApiClient, tokio::task::JoinHandle<()>) {
        let state = RegionsApiState {
            response: Arc::new(Mutex::new(response)),
        };
        let app = Router::new()
            .route(
                "/v1/organization/regions",
                get(organization_regions_handler),
            )
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind org regions api");
        let addr = listener.local_addr().expect("org regions api addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve org regions api");
        });
        let client = AsyncApiClient::new(format!("http://{addr}"), "test-token")
            .expect("org regions client");
        (client, handle)
    }

    #[test]
    fn descriptor_exposes_stable_uri() {
        assert_eq!(descriptor()["uri"], RESOURCE_URI);
    }

    #[tokio::test]
    async fn read_resource_serializes_cells_array() {
        let (client, handle) = spawn_regions_api(serde_json::json!({
            "cells": [{
                "region_key": "us-east",
                "status": "active"
            }]
        }))
        .await;

        let result = read_resource(&client, RESOURCE_URI)
            .await
            .expect("resource read");
        let payload: Value =
            serde_json::from_str(result["contents"][0]["text"].as_str().unwrap()).unwrap();

        assert_eq!(payload["cells"][0]["region_key"], "us-east");

        handle.abort();
    }

    #[tokio::test]
    async fn read_resource_falls_back_to_empty_array() {
        let (client, handle) = spawn_regions_api(serde_json::json!({"unexpected": true})).await;

        let result = read_resource(&client, RESOURCE_URI)
            .await
            .expect("resource read");
        let payload: Value =
            serde_json::from_str(result["contents"][0]["text"].as_str().unwrap()).unwrap();

        assert_eq!(payload["cells"], serde_json::json!([]));

        handle.abort();
    }
}
