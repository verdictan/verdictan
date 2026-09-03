// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

/// MCP tool: model_get
use serde_json::Value;

use super::models_list::normalize_string_array;
use super::ToolContext;
use crate::error::CliError;
use crate::gateway::provider_catalog::{capability_contract_for_provider, profile_for_provider};

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "model_get",
        "description": "Get one catalog model with full metadata and pricing details.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "model_id": {
                    "type": "string",
                    "description": "Exact catalog model ID."
                },
                "provider": {
                    "type": "string",
                    "description": "Optional provider ID disambiguator."
                }
            },
            "required": ["model_id"]
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let model_id = required_string_argument(arguments, &["model_id", "id"])?;
    let provider = optional_string_argument(arguments, &["provider", "provider_id"])?;

    let mut path = format!("/v1/models/{}", urlencoding::encode(&model_id));
    if let Some(provider) = provider.as_deref() {
        path.push('?');
        path.push_str(&format!("provider={}", urlencoding::encode(provider)));
    }

    tracing::debug!(
        session_id = %ctx.session_id,
        model_id = %model_id,
        provider = provider.as_deref().unwrap_or(""),
        "fetching model detail via MCP"
    );

    let response = match ctx.client.get_json_value(&path).await {
        Ok(response) => response,
        Err(error) if error.http_status() == Some(404) => {
            return Err(CliError::user(format!(
                "model_get could not find model '{model_id}'"
            )));
        }
        Err(error) => return Err(error),
    };

    Ok(normalize_model_detail(&response))
}

fn normalize_model_detail(model: &Value) -> Value {
    let provider_id = model.get("provider_id").and_then(Value::as_str);

    serde_json::json!({
        "id": string_field(model, "id"),
        "provider_id": provider_id.unwrap_or_default(),
        "provider_name": string_field(model, "provider_name"),
        "display_name": optional_string_field(model, "display_name"),
        "model_type": string_field(model, "model_type"),
        "context_window": model.get("context_window").and_then(Value::as_i64),
        "max_output_tokens": model.get("max_output_tokens").and_then(Value::as_i64),
        "supported_features": normalize_string_array(model.get("supported_features")),
        "supported_message_roles": normalize_string_array(model.get("supported_message_roles")),
        "parameter_defaults": model
            .get("parameter_defaults")
            .cloned()
            .unwrap_or_else(|| Value::Object(serde_json::Map::new())),
        "removed_params": normalize_string_array(model.get("removed_params")),
        "pricing": model.get("pricing").cloned().unwrap_or(Value::Null),
        "is_default": model.get("is_default").and_then(Value::as_bool).unwrap_or(false),
        "is_deprecated": model.get("is_deprecated").and_then(Value::as_bool).unwrap_or(false),
        "disable_playground": model
            .get("disable_playground")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "status": string_field(model, "status"),
        "last_verified": string_field(model, "last_verified"),
        "provider_profile": provider_id.and_then(provider_profile_value).unwrap_or(Value::Null),
        "provider_capabilities": provider_id.and_then(provider_capabilities_value).unwrap_or(Value::Null),
    })
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

fn required_string_argument(arguments: &Value, keys: &[&str]) -> Result<String, CliError> {
    optional_string_argument(arguments, keys)?
        .ok_or_else(|| CliError::user("model_get requires 'model_id' (or 'id')"))
}

fn optional_string_argument(arguments: &Value, keys: &[&str]) -> Result<Option<String>, CliError> {
    for key in keys {
        if let Some(value) = arguments.get(*key) {
            let text = value
                .as_str()
                .ok_or_else(|| CliError::user(format!("model_get '{key}' must be a string")))?;
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Ok(Some(trimmed.to_string()));
            }
        }
    }
    Ok(None)
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
