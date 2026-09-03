// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

/// MCP tool: models_list
use serde_json::Value;

use super::ToolContext;
use crate::error::CliError;
use crate::gateway::provider_catalog::{capability_contract_for_provider, profile_for_provider};

const DEFAULT_PAGE_SIZE: u64 = 20;
const MAX_PAGE_SIZE: u64 = 100;

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "models_list",
        "description": "List available catalog models with optional provider, feature, and pricing filters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "description": "Filter models to one provider ID."
                },
                "model_type": {
                    "type": "string",
                    "description": "Filter by model type, for example 'chat'."
                },
                "features": {
                    "description": "Filter by one or more supported feature keys.",
                    "oneOf": [
                        { "type": "string" },
                        {
                            "type": "array",
                            "items": { "type": "string" }
                        }
                    ]
                },
                "min_context": {
                    "type": "integer",
                    "description": "Minimum context window."
                },
                "max_input_price": {
                    "type": "number",
                    "description": "Maximum input token price."
                },
                "search": {
                    "type": "string",
                    "description": "Free-text search against model and provider names."
                },
                "sort": {
                    "type": "string",
                    "description": "Sort field supported by the catalog endpoint."
                },
                "order": {
                    "type": "string",
                    "description": "Sort direction, typically 'asc' or 'desc'."
                },
                "page": {
                    "type": "integer",
                    "description": "1-based page number."
                },
                "page_size": {
                    "type": "integer",
                    "description": "Page size, max 100."
                },
                "limit": {
                    "type": "integer",
                    "description": "Alias for page_size."
                }
            }
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let path = build_path(arguments)?;

    tracing::debug!(
        session_id = %ctx.session_id,
        path = %path,
        "listing models via MCP"
    );

    let response = ctx.client.get_json_value(&path).await?;
    Ok(normalize_response(&response))
}

fn build_path(arguments: &Value) -> Result<String, CliError> {
    let mut params = Vec::new();

    if let Some(provider) = string_argument(arguments, &["provider", "provider_id"])? {
        params.push(encoded_param("provider", &provider));
    }
    if let Some(model_type) = string_argument(arguments, &["model_type", "type"])? {
        params.push(encoded_param("type", &model_type));
    }
    if let Some(features) = features_argument(arguments)? {
        params.push(encoded_param("features", &features.join(",")));
    }
    if let Some(min_context) = integer_argument(arguments, &["min_context", "context_window_min"])?
    {
        params.push(format!("min_context={min_context}"));
    }
    if let Some(max_input_price) = number_argument(arguments, &["max_input_price"])? {
        params.push(format!("max_input_price={max_input_price}"));
    }
    if let Some(search) = string_argument(arguments, &["search", "query"])? {
        params.push(encoded_param("search", &search));
    }
    if let Some(sort) = string_argument(arguments, &["sort"])? {
        params.push(encoded_param("sort", &sort));
    }
    if let Some(order) = string_argument(arguments, &["order"])? {
        params.push(encoded_param("order", &order));
    }

    if let Some(page) = integer_argument(arguments, &["page"])? {
        if page <= 0 {
            return Err(CliError::user("models_list 'page' must be greater than 0"));
        }
        params.push(format!("page={page}"));
    }

    let page_size = integer_argument(arguments, &["page_size", "limit"])?
        .map(|value| value as u64)
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .min(MAX_PAGE_SIZE);
    params.push(format!("page_size={page_size}"));

    if params.is_empty() {
        return Ok("/v1/models".to_string());
    }

    Ok(format!("/v1/models?{}", params.join("&")))
}

fn normalize_response(response: &Value) -> Value {
    let models = response
        .get("models")
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| response.get("data").and_then(Value::as_array).cloned())
        .unwrap_or_default();

    let normalized = models.iter().map(normalize_model).collect::<Vec<_>>();

    let total_count = response
        .get("total_count")
        .and_then(Value::as_u64)
        .unwrap_or(normalized.len() as u64);
    let page = response.get("page").and_then(Value::as_u64).unwrap_or(1);
    let page_size = response
        .get("page_size")
        .and_then(Value::as_u64)
        .unwrap_or(normalized.len() as u64);

    serde_json::json!({
        "models": normalized,
        "total_count": total_count,
        "page": page,
        "page_size": page_size,
    })
}

pub(crate) fn normalize_model(model: &Value) -> Value {
    let provider_id = model
        .get("provider_id")
        .or_else(|| model.get("owned_by"))
        .and_then(Value::as_str);

    serde_json::json!({
        "id": string_field(model, "id"),
        "provider_id": provider_id.unwrap_or_default(),
        "provider_name": string_field(model, "provider_name"),
        "display_name": optional_string_field(model, "display_name"),
        "model_type": string_field(model, "model_type"),
        "context_window": model.get("context_window").and_then(Value::as_i64),
        "max_output_tokens": model.get("max_output_tokens").and_then(Value::as_i64),
        "supported_features": normalize_string_array(model.get("supported_features")),
        "pricing": model.get("pricing").cloned().unwrap_or(Value::Null),
        "status": string_field(model, "status"),
        "last_verified": string_field(model, "last_verified"),
        "provider_profile": provider_id.and_then(provider_profile_value).unwrap_or(Value::Null),
        "provider_capabilities": provider_id.and_then(provider_capabilities_value).unwrap_or(Value::Null),
    })
}

pub(crate) fn normalize_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn provider_profile_value(provider: &str) -> Option<Value> {
    let profile = profile_for_provider(provider)?;
    Some(serde_json::json!({
        "provider_type": profile.provider_type.as_str(),
        "format": profile.format.as_str(),
        "api_key_header": profile.api_key_header,
        "api_key_prefix": profile.api_key_prefix,
        "path_template": profile.path_template,
    }))
}

fn provider_capabilities_value(provider: &str) -> Option<Value> {
    capability_contract_for_provider(provider)
        .and_then(|contract| serde_json::to_value(contract).ok())
}

fn encoded_param(name: &str, value: &str) -> String {
    format!("{name}={}", urlencoding::encode(value))
}

fn string_argument(arguments: &Value, keys: &[&str]) -> Result<Option<String>, CliError> {
    for key in keys {
        if let Some(value) = arguments.get(*key) {
            let text = value
                .as_str()
                .ok_or_else(|| CliError::user(format!("models_list '{key}' must be a string")))?;
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Ok(Some(trimmed.to_string()));
            }
        }
    }
    Ok(None)
}

fn integer_argument(arguments: &Value, keys: &[&str]) -> Result<Option<i64>, CliError> {
    for key in keys {
        if let Some(value) = arguments.get(*key) {
            let parsed = value
                .as_i64()
                .ok_or_else(|| CliError::user(format!("models_list '{key}' must be an integer")))?;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

fn number_argument(arguments: &Value, keys: &[&str]) -> Result<Option<f64>, CliError> {
    for key in keys {
        if let Some(value) = arguments.get(*key) {
            let parsed = value
                .as_f64()
                .ok_or_else(|| CliError::user(format!("models_list '{key}' must be a number")))?;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

fn features_argument(arguments: &Value) -> Result<Option<Vec<String>>, CliError> {
    let Some(value) = arguments
        .get("features")
        .or_else(|| arguments.get("feature"))
    else {
        return Ok(None);
    };

    if let Some(text) = value.as_str() {
        return Ok(Some(
            text.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect(),
        ));
    }

    let array = value.as_array().ok_or_else(|| {
        CliError::user("models_list 'features' must be a string or array of strings")
    })?;

    let mut features = Vec::new();
    for item in array {
        let feature = item
            .as_str()
            .ok_or_else(|| CliError::user("models_list 'features' entries must be strings"))?;
        let trimmed = feature.trim();
        if !trimmed.is_empty() {
            features.push(trimmed.to_string());
        }
    }

    Ok((!features.is_empty()).then_some(features))
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn optional_string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}
