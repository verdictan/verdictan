// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

/// MCP tool: chat_compare
use serde_json::Value;

use super::chat_test::{self, RequestFamily};
use super::ToolContext;
use crate::error::CliError;

#[derive(Clone, Debug)]
struct ModelTarget {
    model: String,
    provider: Option<String>,
}

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "chat_compare",
        "description": "Send the same prompt through multiple models. Return results when some requests fail.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "models": {
                    "type": "array",
                    "description": "Array of model IDs or objects with { model, provider }.",
                    "items": {
                        "oneOf": [
                            { "type": "string" },
                            {
                                "type": "object",
                                "properties": {
                                    "model": { "type": "string" },
                                    "provider": { "type": "string" }
                                },
                                "required": ["model"]
                            }
                        ]
                    }
                },
                "prompt": {
                    "type": "string",
                    "description": "Single user prompt to compare."
                },
                "messages": {
                    "type": "array",
                    "description": "Optional full message array shared across all models."
                },
                "request_family": {
                    "type": "string",
                    "enum": ["chat_completions", "responses"],
                    "description": "Gateway surface to use."
                },
                "max_completion_tokens": {
                    "type": "integer",
                    "description": "Optional max completion tokens shared across requests."
                },
                "max_cost_usd": {
                    "type": "number",
                    "description": "Cost ceiling for each request."
                },
                "region": {
                    "type": "string",
                    "description": "Optional exact requested region override."
                }
            },
            "required": ["models"]
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let models = model_targets(arguments)?;
    let shared_prompt = shared_prompt(arguments)?;
    let request_family = match string_argument(arguments, &["request_family"])?.as_deref() {
        Some("responses") => RequestFamily::Responses,
        Some("chat_completions") | None => RequestFamily::ChatCompletions,
        Some(other) => {
            return Err(CliError::user(format!(
                "chat_compare 'request_family' must be 'chat_completions' or 'responses' (got '{other}')"
            )))
        }
    };
    let max_cost_usd = number_argument(arguments, &["max_cost_usd"])?;
    let max_completion_tokens =
        integer_argument(arguments, &["max_completion_tokens", "max_tokens"])?
            .map(|value| value as u64);
    let requested_region = string_argument(arguments, &["region", "region_key"])?
        .or_else(|| ctx.client.region().map(ToString::to_string));

    tracing::debug!(
        session_id = %ctx.session_id,
        model_count = models.len(),
        "running MCP chat compare"
    );

    let mut results = Vec::new();
    let mut failures = Vec::new();

    for target in &models {
        let request = build_chat_test_arguments(
            target,
            &shared_prompt,
            &request_family,
            requested_region.as_deref(),
            max_completion_tokens,
            max_cost_usd,
        );

        match chat_test::execute(ctx, &request).await {
            Ok(result) => results.push(result.get("result").cloned().unwrap_or(Value::Null)),
            Err(error) => failures.push(serde_json::json!({
                "model": target.model,
                "provider": target.provider,
                "error": error.to_string(),
                "http_status": error.http_status(),
            })),
        }
    }

    if results.is_empty() {
        return Err(CliError::user(
            "chat_compare failed for every requested model",
        ));
    }

    let requested_models = models.len();
    let successful_models = results.len();
    let failed_models = failures.len();

    Ok(serde_json::json!({
        "prompt": shared_prompt,
        "request_family": match request_family {
            RequestFamily::ChatCompletions => "chat_completions",
            RequestFamily::Responses => "responses",
        },
        "requested_region": requested_region,
        "results": results,
        "failures": failures,
        "summary": {
            "requested_models": requested_models,
            "successful_models": successful_models,
            "failed_models": failed_models,
        }
    }))
}

fn model_targets(arguments: &Value) -> Result<Vec<ModelTarget>, CliError> {
    let models = arguments
        .get("models")
        .and_then(Value::as_array)
        .ok_or_else(|| CliError::user("chat_compare requires 'models' as an array"))?;

    let mut targets = Vec::with_capacity(models.len());
    for value in models {
        match value {
            Value::String(model) => {
                let trimmed = model.trim();
                if trimmed.is_empty() {
                    return Err(CliError::user(
                        "chat_compare 'models' must not contain empty strings",
                    ));
                }
                targets.push(ModelTarget {
                    model: trimmed.to_string(),
                    provider: None,
                });
            }
            Value::Object(object) => {
                let model = object
                    .get("model")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        CliError::user(
                            "chat_compare model objects require a non-empty 'model' field",
                        )
                    })?;
                let provider = object
                    .get("provider")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string);
                targets.push(ModelTarget {
                    model: model.to_string(),
                    provider,
                });
            }
            _ => {
                return Err(CliError::user(
                    "chat_compare 'models' entries must be strings or objects",
                ))
            }
        }
    }

    if targets.is_empty() {
        return Err(CliError::user("chat_compare 'models' must not be empty"));
    }

    Ok(targets)
}

fn shared_prompt(arguments: &Value) -> Result<Value, CliError> {
    if let Some(messages) = arguments.get("messages").and_then(Value::as_array) {
        return Ok(serde_json::json!({ "messages": messages }));
    }

    let prompt = arguments
        .get("prompt")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::user("chat_compare requires either 'prompt' or 'messages'"))?;

    Ok(serde_json::json!({ "prompt": prompt }))
}

fn build_chat_test_arguments(
    target: &ModelTarget,
    shared_prompt: &Value,
    request_family: &RequestFamily,
    requested_region: Option<&str>,
    max_completion_tokens: Option<u64>,
    max_cost_usd: Option<f64>,
) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("model".to_string(), Value::String(target.model.clone()));
    if let Some(provider) = target.provider.as_deref() {
        object.insert("provider".to_string(), Value::String(provider.to_string()));
    }
    if let Value::Object(shared) = shared_prompt {
        if let Some(prompt) = shared.get("prompt") {
            object.insert("prompt".to_string(), prompt.clone());
        }
        if let Some(messages) = shared.get("messages") {
            object.insert("messages".to_string(), messages.clone());
        }
    }
    object.insert(
        "request_family".to_string(),
        Value::String(match request_family {
            RequestFamily::ChatCompletions => "chat_completions".to_string(),
            RequestFamily::Responses => "responses".to_string(),
        }),
    );
    if let Some(region) = requested_region {
        object.insert("region".to_string(), Value::String(region.to_string()));
    }
    if let Some(max_completion_tokens) = max_completion_tokens {
        object.insert(
            "max_completion_tokens".to_string(),
            Value::Number(max_completion_tokens.into()),
        );
    }
    if let Some(max_cost_usd) = max_cost_usd {
        object.insert("max_cost_usd".to_string(), serde_json::json!(max_cost_usd));
    }

    Value::Object(object)
}

fn string_argument(arguments: &Value, keys: &[&str]) -> Result<Option<String>, CliError> {
    for key in keys {
        if let Some(value) = arguments.get(*key) {
            let text = value
                .as_str()
                .ok_or_else(|| CliError::user(format!("chat_compare '{key}' must be a string")))?;
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
            let parsed = value.as_i64().ok_or_else(|| {
                CliError::user(format!("chat_compare '{key}' must be an integer"))
            })?;
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
                .ok_or_else(|| CliError::user(format!("chat_compare '{key}' must be a number")))?;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}
