// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP resource for exact-region gateway provider telemetry snapshots.

use serde_json::Value;

use crate::api::AsyncApiClient;
use crate::error::CliError;

const RESOURCE_URI: &str = "telemetry://providers";
const LEGACY_RESOURCE_URI: &str = "telemetry-providers://configured";

pub(crate) fn descriptor() -> Value {
    serde_json::json!({
        "uri": RESOURCE_URI,
        "name": "Telemetry Providers",
        "description": "Latest gateway provider telemetry snapshot for the exact requested region. Supports ?gateway_id=... when VERDICTAN_GATEWAY_ID is unset.",
        "mimeType": "application/json"
    })
}

pub(crate) fn matches_uri(uri: &str) -> bool {
    [RESOURCE_URI, LEGACY_RESOURCE_URI]
        .into_iter()
        .any(|candidate| {
            uri == candidate
                || uri
                    .strip_prefix(candidate)
                    .is_some_and(|suffix| suffix.starts_with('?'))
        })
}

pub(crate) async fn read_resource(client: &AsyncApiClient, uri: &str) -> Result<Value, CliError> {
    if !matches_uri(uri) {
        return Err(CliError::user(format!(
            "Unknown telemetry providers resource URI: {uri}"
        )));
    }

    let requested_region = client.region().ok_or_else(|| {
        CliError::user(
            "telemetry://providers requires an exact requested region from the MCP session or API client",
        )
    })?;
    let gateway_id = gateway_id_from_uri(uri)
        .or_else(gateway_id_from_env)
        .ok_or_else(|| {
            CliError::user(
                "telemetry://providers requires ?gateway_id=<gateway-id> or VERDICTAN_GATEWAY_ID",
            )
        })?;

    tracing::debug!(
        uri = %uri,
        gateway_id = %gateway_id,
        requested_region = %requested_region,
        "reading telemetry providers MCP resource"
    );

    let path = format!(
        "/v1/gateways/{}/telemetry?limit=1",
        urlencoding::encode(&gateway_id)
    );
    let response = client.get_json_value(&path).await.map_err(|error| {
        if error.http_status() == Some(404) {
            return CliError::user(format!(
                "telemetry://providers is unavailable for gateway '{gateway_id}' in the exact requested region '{requested_region}'"
            ))
            .with_http_status(404);
        }
        error
    })?;

    let Some(snapshot) = response
        .get("snapshots")
        .and_then(Value::as_array)
        .and_then(|snapshots| snapshots.first())
    else {
        return unavailable_for_region(&gateway_id, requested_region);
    };

    let providers = provider_entries(snapshot.get("providers"));

    wrap_json_contents(
        uri,
        serde_json::json!({
            "gateway_id": gateway_id,
            "requested_region": requested_region,
            "resolved_region": requested_region,
            "resolved_region_source": "gateway_telemetry",
            "reported_at": snapshot.get("reported_at").cloned().unwrap_or(Value::Null),
            "uptime_secs": snapshot.get("uptime_secs").cloned().unwrap_or(Value::Null),
            "aggregate": snapshot.get("aggregate").cloned().unwrap_or(Value::Null),
            "rate_limiter": snapshot.get("rate_limiter").cloned().unwrap_or(Value::Null),
            "providers": providers,
        }),
    )
}

fn unavailable_for_region(gateway_id: &str, requested_region: &str) -> Result<Value, CliError> {
    Err(CliError::user(format!(
        "telemetry://providers is unavailable for gateway '{gateway_id}' in the exact requested region '{requested_region}'"
    )))
}

fn gateway_id_from_uri(uri: &str) -> Option<String> {
    query_values(uri, &["gateway_id", "id"])
        .into_iter()
        .find(|value| !value.trim().is_empty())
}

fn gateway_id_from_env() -> Option<String> {
    std::env::var("VERDICTAN_GATEWAY_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
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
                .then(|| decode_query_value(raw_value))
        })
        .collect()
}

fn decode_query_value(raw_value: &str) -> String {
    match urlencoding::decode(raw_value) {
        Ok(value) => value.into_owned(),
        Err(_) => raw_value.to_string(),
    }
}

fn provider_entries(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Object(map)) => map
            .iter()
            .map(|(provider, snapshot)| {
                let snapshot = snapshot.as_object();
                serde_json::json!({
                    "provider": provider,
                    "sample_count": snapshot
                        .and_then(|entry| entry.get("sample_count"))
                        .cloned()
                        .unwrap_or(Value::Null),
                    "p50_ttft_ms": snapshot
                        .and_then(|entry| entry.get("p50_ttft_ms"))
                        .cloned()
                        .unwrap_or(Value::Null),
                    "p50_throughput_tps": snapshot
                        .and_then(|entry| entry.get("p50_throughput_tps"))
                        .cloned()
                        .unwrap_or(Value::Null),
                    "p90_ttft_ms": snapshot
                        .and_then(|entry| entry.get("p90_ttft_ms"))
                        .cloned()
                        .unwrap_or(Value::Null),
                    "p99_ttft_ms": snapshot
                        .and_then(|entry| entry.get("p99_ttft_ms"))
                        .cloned()
                        .unwrap_or(Value::Null),
                    "health": snapshot
                        .and_then(|entry| entry.get("health"))
                        .cloned()
                        .unwrap_or(Value::Null),
                })
            })
            .collect(),
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    }
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
    use axum::{response::IntoResponse, routing::get, Json, Router};
    use std::sync::Arc;
    use tokio::{net::TcpListener, sync::Mutex};

    #[derive(Clone, Default)]
    struct TelemetryApiState {
        response: Arc<Mutex<Value>>,
    }

    async fn telemetry_handler(
        axum::extract::State(state): axum::extract::State<TelemetryApiState>,
    ) -> impl IntoResponse {
        Json(state.response.lock().await.clone())
    }

    async fn spawn_telemetry_api(response: Value) -> (AsyncApiClient, tokio::task::JoinHandle<()>) {
        let state = TelemetryApiState {
            response: Arc::new(Mutex::new(response)),
        };
        let app = Router::new()
            .route("/v1/gateways/:gateway_id/telemetry", get(telemetry_handler))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind telemetry api");
        let addr = listener.local_addr().expect("telemetry api addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve telemetry api");
        });
        let client =
            AsyncApiClient::new(format!("http://{addr}"), "test-token").expect("telemetry client");
        (client, handle)
    }

    #[test]
    fn descriptor_exposes_plan_named_uri() {
        assert_eq!(descriptor()["uri"], RESOURCE_URI);
    }

    #[test]
    fn matches_uri_accepts_query_variants() {
        assert!(matches_uri(RESOURCE_URI));
        assert!(matches_uri(LEGACY_RESOURCE_URI));
        assert!(matches_uri("telemetry://providers?gateway_id=gw-eu-1"));
        assert!(!matches_uri("telemetry://other"));
    }

    #[tokio::test]
    async fn read_resource_returns_latest_gateway_provider_snapshot() {
        let (client, handle) = spawn_telemetry_api(serde_json::json!({
            "gateway_id": "gw-eu-1",
            "snapshots": [{
                "reported_at": "2026-07-03T09:30:00Z",
                "uptime_secs": 3600,
                "providers": {
                    "openai": {
                        "sample_count": 12,
                        "p50_ttft_ms": 120.0,
                        "p50_throughput_tps": 18.5,
                        "p90_ttft_ms": 180.0,
                        "p99_ttft_ms": 240.0,
                        "health": {
                            "healthy": true,
                            "status_code": 200,
                            "latency_ms": 111
                        }
                    }
                },
                "aggregate": {
                    "requests": 42
                },
                "rate_limiter": {
                    "provider": "openai"
                }
            }]
        }))
        .await;
        let client = client.with_region(Some("eu-west".to_string()));
        let uri = "telemetry://providers?gateway_id=gw-eu-1";

        let result = read_resource(&client, uri).await.expect("resource read");
        let payload: Value =
            serde_json::from_str(result["contents"][0]["text"].as_str().unwrap()).unwrap();

        assert_eq!(payload["gateway_id"], "gw-eu-1");
        assert_eq!(payload["requested_region"], "eu-west");
        assert_eq!(payload["providers"].as_array().unwrap().len(), 1);
        assert_eq!(payload["providers"][0]["provider"], "openai");
        assert_eq!(payload["providers"][0]["health"]["healthy"], true);
        assert_eq!(payload["aggregate"]["requests"], 42);

        handle.abort();
    }

    #[tokio::test]
    async fn read_resource_requires_region_and_gateway_identity() {
        let (client, handle) = spawn_telemetry_api(serde_json::json!({ "snapshots": [] })).await;

        let no_region = read_resource(&client, "telemetry://providers?gateway_id=gw-eu-1")
            .await
            .expect_err("missing region should fail");
        assert!(no_region
            .to_string()
            .contains("telemetry://providers requires an exact requested region"));

        let client = client.with_region(Some("eu-west".to_string()));
        let no_gateway = read_resource(&client, RESOURCE_URI)
            .await
            .expect_err("missing gateway id should fail");
        assert!(no_gateway
            .to_string()
            .contains("telemetry://providers requires ?gateway_id=<gateway-id>"));

        handle.abort();
    }

    #[tokio::test]
    async fn read_resource_fails_closed_when_gateway_has_no_regional_snapshot() {
        let (client, handle) =
            spawn_telemetry_api(serde_json::json!({ "gateway_id": "gw-eu-1", "snapshots": [] }))
                .await;
        let client = client.with_region(Some("eu-west".to_string()));

        let error = read_resource(&client, "telemetry://providers?gateway_id=gw-eu-1")
            .await
            .expect_err("empty snapshots should fail");
        assert!(error
            .to_string()
            .contains("telemetry://providers is unavailable for gateway 'gw-eu-1'"));

        handle.abort();
    }
}
