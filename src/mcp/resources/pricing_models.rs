// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP resource for exact-region control-plane pricing models.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::api::AsyncApiClient;
use crate::error::CliError;
use crate::gateway::provider_catalog::normalized_provider_alias;

const RESOURCE_URI: &str = "pricing://models";
const LEGACY_RESOURCE_URI: &str = "pricing-models://catalog";
const MODELS_PATH: &str = "/v1/models?page_size=100";
const MODEL_PRICING_PATH: &str = "/v1/model-pricing";

pub(crate) fn descriptor() -> Value {
    serde_json::json!({
        "uri": RESOURCE_URI,
        "name": "Pricing Models",
        "description": "Control-plane model pricing rows available in the exact requested region.",
        "mimeType": "application/json"
    })
}

pub(crate) fn matches_uri(uri: &str) -> bool {
    uri == RESOURCE_URI || uri == LEGACY_RESOURCE_URI
}

pub(crate) async fn read_resource(client: &AsyncApiClient, uri: &str) -> Result<Value, CliError> {
    if !matches_uri(uri) {
        return Err(CliError::user(format!(
            "Unknown pricing models resource URI: {uri}"
        )));
    }

    let requested_region = client.region().ok_or_else(|| {
        CliError::user(
            "pricing://models requires an exact requested region from the MCP session or API client",
        )
    })?;

    tracing::debug!(
        uri = %uri,
        requested_region = %requested_region,
        "reading pricing models MCP resource"
    );

    let models_response = client.get_json_value(MODELS_PATH).await?;
    let model_index = build_model_index(&models_response);
    if model_index.is_empty() {
        return unavailable_for_region(requested_region);
    }

    let pricing_response = client.get_json_value(MODEL_PRICING_PATH).await?;
    let models = merge_pricing_models(&pricing_response, &model_index, requested_region);
    if models.is_empty() {
        return unavailable_for_region(requested_region);
    }

    let resolved_region = models
        .iter()
        .find_map(|model| {
            model
                .pointer("/locality/region_key")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| requested_region.to_string());

    wrap_json_contents(
        uri,
        serde_json::json!({
            "requested_region": requested_region,
            "resolved_region": resolved_region,
            "resolved_region_source": "model_catalog",
            "models": models,
        }),
    )
}

fn unavailable_for_region(requested_region: &str) -> Result<Value, CliError> {
    Err(CliError::user(format!(
        "pricing://models is unavailable in the exact requested region '{requested_region}'"
    )))
}

fn build_model_index(response: &Value) -> BTreeMap<(String, String), Value> {
    let mut index = BTreeMap::new();

    for model in response
        .get("models")
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| response.get("data").and_then(Value::as_array).cloned())
        .unwrap_or_default()
    {
        let Some(model_id) = trimmed_string(model.get("id")) else {
            continue;
        };
        let Some(provider) = trimmed_string(
            model
                .get("provider_id")
                .or_else(|| model.get("owned_by"))
                .or_else(|| model.get("provider")),
        ) else {
            continue;
        };

        index.insert((normalized_provider_alias(&provider), model_id), model);
    }

    index
}

fn merge_pricing_models(
    response: &Value,
    model_index: &BTreeMap<(String, String), Value>,
    requested_region: &str,
) -> Vec<Value> {
    response
        .get("models")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|pricing_entry| {
            let provider = trimmed_string(pricing_entry.get("provider"))?;
            let model_id = trimmed_string(pricing_entry.get("model_id"))?;
            let model =
                model_index.get(&(normalized_provider_alias(&provider), model_id.clone()))?;

            Some(serde_json::json!({
                "provider": provider,
                "model_id": model_id,
                "display_name": model.get("display_name").cloned().unwrap_or(Value::Null),
                "status": model.get("status").cloned().unwrap_or(Value::Null),
                "input_price_per_million": pricing_entry
                    .get("input_price_per_million")
                    .cloned()
                    .unwrap_or(Value::Null),
                "output_price_per_million": pricing_entry
                    .get("output_price_per_million")
                    .cloned()
                    .unwrap_or(Value::Null),
                "cached_input_price_per_million": pricing_entry
                    .get("cached_input_price_per_million")
                    .cloned()
                    .unwrap_or(Value::Null),
                "source": pricing_entry.get("source").cloned().unwrap_or(Value::Null),
                "locality": locality_from_model(model, requested_region),
            }))
        })
        .collect()
}

fn locality_from_model(model: &Value, requested_region: &str) -> Value {
    let region_key = model
        .pointer("/locality/region_key")
        .or_else(|| model.get("region_key"))
        .cloned()
        .unwrap_or(Value::Null);
    let primary_region_group_key = model
        .pointer("/locality/primary_region_group_key")
        .or_else(|| model.get("primary_region_group_key"))
        .cloned()
        .unwrap_or(Value::Null);
    let sovereignty_class = model
        .pointer("/locality/sovereignty_class")
        .or_else(|| model.get("sovereignty_class"))
        .cloned()
        .unwrap_or(Value::Null);
    let endpoint_scope = model
        .pointer("/locality/endpoint_scope")
        .or_else(|| model.get("endpoint_scope"))
        .cloned()
        .unwrap_or(Value::Null);

    serde_json::json!({
        "requested_region": requested_region,
        "region_key": region_key,
        "primary_region_group_key": primary_region_group_key,
        "sovereignty_class": sovereignty_class,
        "endpoint_scope": endpoint_scope,
    })
}

fn trimmed_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
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
    struct PricingApiState {
        models: Arc<Mutex<Value>>,
        pricing: Arc<Mutex<Value>>,
    }

    async fn models_handler(
        axum::extract::State(state): axum::extract::State<PricingApiState>,
    ) -> impl IntoResponse {
        Json(state.models.lock().await.clone())
    }

    async fn pricing_handler(
        axum::extract::State(state): axum::extract::State<PricingApiState>,
    ) -> impl IntoResponse {
        Json(state.pricing.lock().await.clone())
    }

    async fn spawn_pricing_api(
        models: Value,
        pricing: Value,
    ) -> (AsyncApiClient, tokio::task::JoinHandle<()>) {
        let state = PricingApiState {
            models: Arc::new(Mutex::new(models)),
            pricing: Arc::new(Mutex::new(pricing)),
        };
        let app = Router::new()
            .route("/v1/models", get(models_handler))
            .route("/v1/model-pricing", get(pricing_handler))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind pricing api");
        let addr = listener.local_addr().expect("pricing api addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve pricing api");
        });
        let client =
            AsyncApiClient::new(format!("http://{addr}"), "test-token").expect("pricing client");
        (client, handle)
    }

    #[test]
    fn descriptor_exposes_plan_named_uri() {
        assert_eq!(descriptor()["uri"], RESOURCE_URI);
    }

    #[test]
    fn matches_uri_accepts_canonical_and_legacy_alias() {
        assert!(matches_uri(RESOURCE_URI));
        assert!(matches_uri(LEGACY_RESOURCE_URI));
        assert!(!matches_uri("pricing://other"));
    }

    #[tokio::test]
    async fn read_resource_uses_region_scoped_control_plane_pricing() {
        let (client, handle) = spawn_pricing_api(
            serde_json::json!({
                "models": [
                    {
                        "id": "eu-fast",
                        "provider_id": "openai",
                        "display_name": "EU Fast",
                        "status": "active",
                        "region_key": "eu-west",
                        "primary_region_group_key": "eu",
                        "sovereignty_class": "eu_sovereign",
                        "endpoint_scope": "Regional"
                    },
                    {
                        "id": "us-fast",
                        "provider_id": "openai",
                        "display_name": "US Fast",
                        "status": "active",
                        "region_key": "us-east",
                        "primary_region_group_key": "us",
                        "sovereignty_class": "public",
                        "endpoint_scope": "Regional"
                    }
                ]
            }),
            serde_json::json!({
                "models": [
                    {
                        "provider": "openai",
                        "model_id": "eu-fast",
                        "input_price_per_million": 3.0,
                        "output_price_per_million": 9.0,
                        "source": "control_plane"
                    },
                    {
                        "provider": "openai",
                        "model_id": "does-not-exist",
                        "input_price_per_million": 99.0,
                        "output_price_per_million": 199.0
                    }
                ]
            }),
        )
        .await;
        let client = client.with_region(Some("eu-west".to_string()));

        let result = read_resource(&client, RESOURCE_URI)
            .await
            .expect("resource read");
        let payload: Value =
            serde_json::from_str(result["contents"][0]["text"].as_str().unwrap()).unwrap();

        assert_eq!(payload["requested_region"], "eu-west");
        assert_eq!(payload["resolved_region"], "eu-west");
        assert_eq!(payload["models"].as_array().unwrap().len(), 1);
        assert_eq!(payload["models"][0]["model_id"], "eu-fast");
        assert_eq!(
            payload["models"][0]["input_price_per_million"],
            serde_json::json!(3.0)
        );
        assert_eq!(
            payload["models"][0]["locality"]["sovereignty_class"],
            "eu_sovereign"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn read_resource_requires_requested_region() {
        let (client, handle) = spawn_pricing_api(
            serde_json::json!({ "models": [] }),
            serde_json::json!({ "models": [] }),
        )
        .await;

        let error = read_resource(&client, RESOURCE_URI)
            .await
            .expect_err("missing region should fail");
        assert!(error
            .to_string()
            .contains("pricing://models requires an exact requested region"));

        handle.abort();
    }

    #[tokio::test]
    async fn read_resource_fails_closed_when_region_has_no_available_models() {
        let (client, handle) = spawn_pricing_api(
            serde_json::json!({ "models": [] }),
            serde_json::json!({
                "models": [{
                    "provider": "openai",
                    "model_id": "eu-fast",
                    "input_price_per_million": 3.0,
                    "output_price_per_million": 9.0
                }]
            }),
        )
        .await;
        let client = client.with_region(Some("eu-west".to_string()));

        let error = read_resource(&client, RESOURCE_URI)
            .await
            .expect_err("missing regional models should fail");
        assert!(error
            .to_string()
            .contains("pricing://models is unavailable in the exact requested region 'eu-west'"));

        handle.abort();
    }
}
