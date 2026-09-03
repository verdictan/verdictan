// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

/// MCP tool: providers_list
use serde_json::Value;

use super::ToolContext;
use crate::error::CliError;
use crate::gateway::provider_catalog::{capability_contract_for_provider, profile_for_provider};

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "providers_list",
        "description": "List catalog providers with model counts and known runtime capability metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "provider_type": {
                    "type": "string",
                    "description": "Filter by provider type."
                },
                "modality": {
                    "type": "string",
                    "description": "Filter by one supported modality."
                },
                "status": {
                    "type": "string",
                    "description": "Filter by provider status."
                },
                "search": {
                    "type": "string",
                    "description": "Free-text search on provider ID or display name."
                },
                "capability": {
                    "type": "string",
                    "description": "Filter providers by a capability token such as 'responses', 'tool_calls', or 'json_schema'."
                },
                "limit": {
                    "type": "integer",
                    "description": "Optional max number of providers to return after filtering."
                }
            }
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let path = build_path(arguments)?;
    let capability_filter = string_argument(arguments, &["capability", "supports"])?;
    let limit = integer_argument(arguments, &["limit"])?;

    tracing::debug!(
        session_id = %ctx.session_id,
        path = %path,
        capability = capability_filter.as_deref().unwrap_or(""),
        "listing providers via MCP"
    );

    let response = ctx.client.get_json_value(&path).await?;
    let providers = response
        .get("providers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut normalized = providers.iter().map(normalize_provider).collect::<Vec<_>>();

    if let Some(capability) = capability_filter.as_deref() {
        normalized.retain(|provider| provider_supports_capability(provider, capability));
    }

    if let Some(limit) = limit {
        normalized.truncate(limit as usize);
    }

    let total_count = normalized.len();

    Ok(serde_json::json!({
        "providers": normalized,
        "total_count": total_count,
    }))
}

fn build_path(arguments: &Value) -> Result<String, CliError> {
    let mut params = Vec::new();

    if let Some(provider_type) = string_argument(arguments, &["provider_type", "type"])? {
        params.push(encoded_param("type", &provider_type));
    }
    if let Some(modality) = string_argument(arguments, &["modality"])? {
        params.push(encoded_param("modality", &modality));
    }
    if let Some(status) = string_argument(arguments, &["status"])? {
        params.push(encoded_param("status", &status));
    }
    if let Some(search) = string_argument(arguments, &["search", "query"])? {
        params.push(encoded_param("search", &search));
    }

    if params.is_empty() {
        return Ok("/v1/providers".to_string());
    }

    Ok(format!("/v1/providers?{}", params.join("&")))
}

fn normalize_provider(provider: &Value) -> Value {
    let provider_id = string_field(provider, "id");
    let capabilities = capability_contract_for_provider(&provider_id)
        .and_then(|contract| serde_json::to_value(contract).ok())
        .unwrap_or(Value::Null);
    let provider_profile = profile_for_provider(&provider_id)
        .map(|profile| {
            serde_json::json!({
                "provider_type": profile.provider_type.as_str(),
                "format": profile.format.as_str(),
                "api_key_header": profile.api_key_header,
                "api_key_prefix": profile.api_key_prefix,
                "path_template": profile.path_template,
            })
        })
        .unwrap_or(Value::Null);

    serde_json::json!({
        "id": provider_id,
        "display_name": string_field(provider, "display_name"),
        "provider_type": string_field(provider, "provider_type"),
        "auth_pattern": string_field(provider, "auth_pattern"),
        "status": string_field(provider, "status"),
        "supported_modalities": normalize_string_array(provider.get("supported_modalities")),
        "model_count": provider.get("model_count").and_then(Value::as_i64).unwrap_or(0),
        "last_verified": string_field(provider, "last_verified"),
        "provider_profile": provider_profile,
        "capabilities": capabilities,
    })
}

fn provider_supports_capability(provider: &Value, capability: &str) -> bool {
    let capability = capability.trim().to_ascii_lowercase();
    if capability.is_empty() {
        return true;
    }

    let Some(contract) = provider.get("capabilities") else {
        return false;
    };

    match contract {
        Value::Null => false,
        Value::Object(map) => map
            .values()
            .any(|value| value_contains_token(value, &capability)),
        _ => false,
    }
}

fn value_contains_token(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(text) => text.eq_ignore_ascii_case(expected),
        Value::Array(items) => items
            .iter()
            .any(|item| value_contains_token(item, expected)),
        Value::Object(map) => map
            .values()
            .any(|item| value_contains_token(item, expected)),
        _ => false,
    }
}

fn normalize_string_array(value: Option<&Value>) -> Vec<String> {
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

fn encoded_param(name: &str, value: &str) -> String {
    format!("{name}={}", urlencoding::encode(value))
}

fn string_argument(arguments: &Value, keys: &[&str]) -> Result<Option<String>, CliError> {
    for key in keys {
        if let Some(value) = arguments.get(*key) {
            let text = value.as_str().ok_or_else(|| {
                CliError::user(format!("providers_list '{key}' must be a string"))
            })?;
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Ok(Some(trimmed.to_string()));
            }
        }
    }
    Ok(None)
}

fn integer_argument(arguments: &Value, keys: &[&str]) -> Result<Option<u64>, CliError> {
    for key in keys {
        if let Some(value) = arguments.get(*key) {
            let parsed = value.as_u64().ok_or_else(|| {
                CliError::user(format!("providers_list '{key}' must be an integer"))
            })?;
            return Ok(Some(parsed));
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
