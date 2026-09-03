// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

/// MCP tool: chat_test
use std::time::Instant;

use reqwest::header::{HeaderName, AUTHORIZATION};
use serde_json::Value;

use super::ToolContext;
use crate::error::CliError;
use crate::gateway::provider_catalog::normalized_provider_alias;
use crate::gateway::providers::ProviderPricing;
use crate::gateway::token_estimation;

const CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
const RESPONSES_PATH: &str = "/v1/responses";
const MODEL_PRICING_PATH: &str = "/v1/model-pricing";

#[derive(Clone, Debug)]
pub(crate) enum RequestFamily {
    ChatCompletions,
    Responses,
}

#[derive(Clone, Debug)]
pub(crate) struct ModelExecutionConfig {
    pub(crate) model: String,
    pub(crate) provider: Option<String>,
    pub(crate) request_family: RequestFamily,
    pub(crate) max_cost_usd: Option<f64>,
    pub(crate) max_completion_tokens: Option<u64>,
    pub(crate) requested_region: Option<String>,
    pub(crate) resolved_region_source: Option<&'static str>,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedPrompt {
    pub(crate) label: Option<String>,
    pub(crate) request_body: Value,
}

#[derive(Clone, Debug)]
struct ModelMetadata {
    provider_id: Option<String>,
    locality: Value,
    pricing: Option<ProviderPricing>,
}

#[derive(Clone, Copy, Debug)]
struct UsageSnapshot {
    prompt_tokens: u64,
    completion_tokens: u64,
    total_tokens: u64,
    cached_input_tokens: u64,
    prompt_cost: Option<f64>,
    completion_cost: Option<f64>,
    total_cost: Option<f64>,
}

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "chat_test",
        "description": "Send one or many prompts through the gateway chat path and return text, provider, latency, usage, cost, and locality metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "model": {
                    "type": "string",
                    "description": "Exact model ID to test."
                },
                "provider": {
                    "type": "string",
                    "description": "Optional provider pin."
                },
                "prompt": {
                    "type": "string",
                    "description": "Single user prompt."
                },
                "prompts": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Multiple prompts to test against the same model."
                },
                "messages": {
                    "type": "array",
                    "description": "Full chat-completions message array."
                },
                "request_family": {
                    "type": "string",
                    "enum": ["chat_completions", "responses"],
                    "description": "Gateway surface to use."
                },
                "max_completion_tokens": {
                    "type": "integer",
                    "description": "Optional max completion tokens for the request."
                },
                "temperature": {
                    "type": "number",
                    "description": "Optional temperature override."
                },
                "max_cost_usd": {
                    "type": "number",
                    "description": "Fail closed when estimated or actual request cost exceeds this value."
                },
                "region": {
                    "type": "string",
                    "description": "Optional exact requested region override. Defaults to the MCP session region."
                }
            },
            "required": ["model"]
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let config = config_from_arguments(ctx, arguments)?;
    let prompts = prompts_from_arguments(arguments, &config)?;
    let mut results = Vec::with_capacity(prompts.len());

    tracing::debug!(
        session_id = %ctx.session_id,
        model = %config.model,
        provider = config.provider.as_deref().unwrap_or(""),
        prompt_count = prompts.len(),
        "running MCP chat test"
    );

    for prompt in &prompts {
        results.push(execute_single_prompt(ctx, &config, prompt).await?);
    }

    let result = results.first().cloned();
    let resolved_region = config
        .requested_region
        .as_deref()
        .or_else(|| ctx.client.region())
        .map(ToString::to_string);
    Ok(serde_json::json!({
        "model": config.model,
        "provider": config.provider,
        "request_family": request_family_name(&config.request_family),
        "requested_region": config.requested_region,
        "resolved_region": resolved_region,
        "resolved_region_source": config.resolved_region_source,
        "resolved_api_endpoint": super::resolved_api_endpoint(ctx.client),
        "result": result,
        "results": results,
        "total_runs": prompts.len(),
    }))
}

pub(crate) async fn execute_single_prompt(
    ctx: &ToolContext<'_>,
    config: &ModelExecutionConfig,
    prompt: &PreparedPrompt,
) -> Result<Value, CliError> {
    let metadata = resolve_model_metadata(ctx, &config.model, config.provider.as_deref()).await?;
    enforce_region_constraint(&metadata, config)?;
    enforce_estimated_cost_limit(config, &prompt.request_body, metadata.pricing.as_ref())?;

    let path = match config.request_family {
        RequestFamily::ChatCompletions => CHAT_COMPLETIONS_PATH,
        RequestFamily::Responses => RESPONSES_PATH,
    };
    let url = ctx.client.join_url(path);
    let (http_client, auth_header) = ctx.client.http_client_with_auth();
    let mut request = http_client
        .post(url)
        .header(AUTHORIZATION, auth_header)
        .json(&prompt.request_body);

    if let Some(region) = config
        .requested_region
        .as_deref()
        .or_else(|| ctx.client.region())
    {
        request = request.header(HeaderName::from_static("x-verdictan-region"), region);
    }
    if let Some(provider) = config.provider.as_deref() {
        request = request.header(HeaderName::from_static("x-verdictan-provider"), provider);
    }

    let started_at = Instant::now();
    let response = request
        .send()
        .await
        .map_err(|error| CliError::network(format!("chat_test request failed: {error}")))?;
    let measured_latency_ms = started_at.elapsed().as_millis() as u64;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .json::<Value>()
        .await
        .map_err(|error| CliError::internal(format!("chat_test received invalid JSON: {error}")))?;

    if !status.is_success() {
        let message = body
            .pointer("/error/message")
            .and_then(Value::as_str)
            .or_else(|| body.get("message").and_then(Value::as_str))
            .unwrap_or("gateway request failed");
        return Err(CliError::network(format!(
            "chat_test request returned {}: {message}",
            status.as_u16()
        ))
        .with_http_status(status.as_u16()));
    }

    let usage = extract_usage_snapshot(&body);
    let cost = compute_cost_snapshot(usage, metadata.pricing.as_ref());
    if let Some(limit) = config.max_cost_usd {
        let actual_total_cost =
            cost.get("total_cost")
                .and_then(Value::as_f64)
                .ok_or_else(|| {
                    CliError::user(
                "chat_test could not evaluate 'max_cost_usd' because cost metadata was unavailable",
            )
                })?;
        if actual_total_cost > limit {
            return Err(CliError::user(format!(
                "chat_test actual request cost ${actual_total_cost:.6} exceeded the configured limit ${limit:.6}",
            )));
        }
    }

    let provider = body
        .get("provider")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| config.provider.clone())
        .or_else(|| metadata.provider_id.clone());

    Ok(serde_json::json!({
        "status": "ok",
        "model": config.model,
        "provider": provider,
        "prompt_label": prompt.label,
        "response_id": body.get("id").cloned().unwrap_or(Value::Null),
        "response_text": extract_response_text(&body).unwrap_or_default(),
        "finish_reason": finish_reason(&body),
        "latency_ms": gateway_latency_ms(&body, &headers).unwrap_or(measured_latency_ms),
        "usage": usage_to_value(usage),
        "cost": cost,
        "locality": merge_locality(&body, &metadata, config.requested_region.as_deref().or_else(|| ctx.client.region())),
        "raw_model": body.get("model").cloned().unwrap_or(Value::Null),
    }))
}

fn config_from_arguments(
    ctx: &ToolContext<'_>,
    arguments: &Value,
) -> Result<ModelExecutionConfig, CliError> {
    let model = required_string_argument(arguments, &["model", "model_id"])?;
    let explicit_requested_region = string_argument(arguments, &["region", "region_key"])?;
    let request_family = match string_argument(arguments, &["request_family"])?.as_deref() {
        Some("responses") => RequestFamily::Responses,
        Some("chat_completions") | None => RequestFamily::ChatCompletions,
        Some(other) => {
            return Err(CliError::user(format!(
            "chat_test 'request_family' must be 'chat_completions' or 'responses' (got '{other}')"
        )))
        }
    };

    Ok(ModelExecutionConfig {
        model,
        provider: string_argument(arguments, &["provider", "provider_id"])?,
        request_family,
        max_cost_usd: number_argument(arguments, &["max_cost_usd"])?,
        max_completion_tokens: integer_argument(
            arguments,
            &["max_completion_tokens", "max_tokens"],
        )?
        .map(|value| value as u64),
        requested_region: explicit_requested_region
            .clone()
            .or_else(|| ctx.client.region().map(ToString::to_string)),
        resolved_region_source: if explicit_requested_region.is_some() {
            Some(super::TOOL_ARGUMENT_REGION_SOURCE)
        } else if ctx.client.region().is_some() {
            Some(super::MCP_SESSION_REGION_SOURCE)
        } else {
            None
        },
    })
}

fn prompts_from_arguments(
    arguments: &Value,
    config: &ModelExecutionConfig,
) -> Result<Vec<PreparedPrompt>, CliError> {
    if let Some(prompts) = arguments.get("prompts") {
        let prompts = prompts
            .as_array()
            .ok_or_else(|| CliError::user("chat_test 'prompts' must be an array of strings"))?;
        let mut prepared = Vec::with_capacity(prompts.len());
        for (index, prompt) in prompts.iter().enumerate() {
            let prompt = prompt
                .as_str()
                .ok_or_else(|| CliError::user("chat_test 'prompts' entries must be strings"))?;
            prepared.push(PreparedPrompt {
                label: Some(format!("prompt-{index}")),
                request_body: request_body_for_prompt(config, prompt, arguments),
            });
        }
        if prepared.is_empty() {
            return Err(CliError::user("chat_test 'prompts' must not be empty"));
        }
        return Ok(prepared);
    }

    if let Some(messages) = arguments.get("messages") {
        let messages = messages
            .as_array()
            .ok_or_else(|| CliError::user("chat_test 'messages' must be an array"))?;
        return Ok(vec![PreparedPrompt {
            label: None,
            request_body: request_body_for_messages(config, messages, arguments),
        }]);
    }

    let prompt = required_string_argument(arguments, &["prompt"])?;
    Ok(vec![PreparedPrompt {
        label: None,
        request_body: request_body_for_prompt(config, &prompt, arguments),
    }])
}

fn request_body_for_prompt(
    config: &ModelExecutionConfig,
    prompt: &str,
    arguments: &Value,
) -> Value {
    match config.request_family {
        RequestFamily::ChatCompletions => {
            let mut body = serde_json::json!({
                "model": config.model,
                "messages": [{
                    "role": "user",
                    "content": prompt,
                }]
            });
            attach_optional_request_fields(&mut body, arguments, config.max_completion_tokens);
            body
        }
        RequestFamily::Responses => {
            let mut body = serde_json::json!({
                "model": config.model,
                "input": prompt,
            });
            attach_optional_request_fields(&mut body, arguments, config.max_completion_tokens);
            body
        }
    }
}

fn request_body_for_messages(
    config: &ModelExecutionConfig,
    messages: &[Value],
    arguments: &Value,
) -> Value {
    let mut body = serde_json::json!({
        "model": config.model,
        "messages": messages,
    });
    attach_optional_request_fields(&mut body, arguments, config.max_completion_tokens);
    body
}

fn attach_optional_request_fields(
    body: &mut Value,
    arguments: &Value,
    max_completion_tokens: Option<u64>,
) {
    let Some(object) = body.as_object_mut() else {
        return;
    };

    if let Some(max_completion_tokens) = max_completion_tokens {
        object.insert(
            "max_tokens".to_string(),
            Value::Number(max_completion_tokens.into()),
        );
    }

    if let Some(temperature) = arguments.get("temperature").and_then(Value::as_f64) {
        object.insert("temperature".to_string(), serde_json::json!(temperature));
    }
}

async fn resolve_model_metadata(
    ctx: &ToolContext<'_>,
    model: &str,
    provider: Option<&str>,
) -> Result<ModelMetadata, CliError> {
    let mut path = format!("/v1/models/{}", urlencoding::encode(model));
    if let Some(provider) = provider {
        path.push('?');
        path.push_str(&format!("provider={}", urlencoding::encode(provider)));
    }

    let model_detail = ctx.client.get_json_value(&path).await;
    let raw_model = match model_detail {
        Ok(value) => value,
        Err(error) if error.http_status() == Some(404) && provider.is_some() => {
            return Ok(ModelMetadata {
                provider_id: provider.map(ToString::to_string),
                locality: serde_json::json!({}),
                pricing: None,
            })
        }
        Err(error) => return Err(error),
    };

    let provider_id = raw_model
        .get("provider_id")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| provider.map(ToString::to_string));
    let pricing = pricing_for_model(ctx, provider_id.as_deref(), model, &raw_model).await?;

    Ok(ModelMetadata {
        provider_id,
        locality: extract_locality(&raw_model),
        pricing,
    })
}

async fn pricing_for_model(
    ctx: &ToolContext<'_>,
    provider: Option<&str>,
    model: &str,
    raw_model: &Value,
) -> Result<Option<ProviderPricing>, CliError> {
    let Some(provider) = provider else {
        return Ok(pricing_from_model_detail(raw_model));
    };
    let provider_alias = normalized_provider_alias(provider);

    let pricing_response = ctx.client.get_json_value(MODEL_PRICING_PATH).await?;
    if let Some(models) = pricing_response.get("models").and_then(Value::as_array) {
        for entry in models {
            let Some(entry_provider) = entry.get("provider").and_then(Value::as_str) else {
                continue;
            };
            let Some(entry_model_id) = entry.get("model_id").and_then(Value::as_str) else {
                continue;
            };
            if normalized_provider_alias(entry_provider) != provider_alias
                || entry_model_id != model
            {
                continue;
            }
            let Some(input_price_per_million) =
                entry.get("input_price_per_million").and_then(Value::as_f64)
            else {
                continue;
            };
            let Some(output_price_per_million) = entry
                .get("output_price_per_million")
                .and_then(Value::as_f64)
            else {
                continue;
            };
            return Ok(Some(ProviderPricing {
                input_price_per_million,
                output_price_per_million,
                cached_input_price_per_million: entry
                    .get("cached_input_price_per_million")
                    .and_then(Value::as_f64),
                input_multiplier: None,
                cached_input_multiplier: None,
                output_multiplier: None,
            }));
        }
    }

    Ok(pricing_from_model_detail(raw_model))
}

fn pricing_from_model_detail(raw_model: &Value) -> Option<ProviderPricing> {
    let pricing = raw_model.get("pricing")?;
    let pricing = pricing.get("pay_as_you_go").unwrap_or(pricing);
    Some(ProviderPricing {
        input_price_per_million: pricing
            .get("input_price_per_million")
            .or_else(|| pricing.get("input_token_price"))
            .and_then(Value::as_f64)?,
        output_price_per_million: pricing
            .get("output_price_per_million")
            .or_else(|| pricing.get("output_token_price"))
            .and_then(Value::as_f64)?,
        cached_input_price_per_million: pricing
            .get("cached_input_price_per_million")
            .or_else(|| pricing.get("cached_input_read_price"))
            .and_then(Value::as_f64),
        input_multiplier: None,
        cached_input_multiplier: None,
        output_multiplier: None,
    })
}

fn enforce_region_constraint(
    metadata: &ModelMetadata,
    config: &ModelExecutionConfig,
) -> Result<(), CliError> {
    let Some(expected_region) = config.requested_region.as_deref() else {
        return Ok(());
    };
    let actual_region = metadata.locality.get("region_key").and_then(Value::as_str);
    if let Some(actual_region) = actual_region {
        if actual_region != expected_region {
            return Err(CliError::user(format!(
                "chat_test model '{}' is not available in exact region '{}' (resolved '{}')",
                config.model, expected_region, actual_region
            )));
        }
    }
    Ok(())
}

fn enforce_estimated_cost_limit(
    config: &ModelExecutionConfig,
    request_body: &Value,
    pricing: Option<&ProviderPricing>,
) -> Result<(), CliError> {
    let Some(limit) = config.max_cost_usd else {
        return Ok(());
    };
    let Some(pricing) = pricing else {
        return Ok(());
    };

    let prompt_tokens = token_estimation::estimate_prompt_tokens(request_body).unwrap_or(0) as u64;
    let max_completion_tokens = config.max_completion_tokens.unwrap_or(0);
    let estimate = pricing
        .compute_cost(prompt_tokens, max_completion_tokens)
        .request;
    if estimate > limit {
        return Err(CliError::user(format!(
            "chat_test estimated request cost ${estimate:.6} exceeded the configured limit ${limit:.6}",
        )));
    }

    Ok(())
}

fn extract_response_text(body: &Value) -> Option<String> {
    if let Some(choices) = body.get("choices").and_then(Value::as_array) {
        let mut parts = Vec::new();
        for choice in choices {
            let Some(text) = choice
                .get("message")
                .and_then(|value| value.get("content"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            if !text.trim().is_empty() {
                parts.push(text.to_string());
            }
        }
        if !parts.is_empty() {
            return Some(parts.join("\n"));
        }
    }

    if let Some(text) = body.get("output").and_then(Value::as_str) {
        if !text.trim().is_empty() {
            return Some(text.to_string());
        }
    }

    let outputs = body.get("output")?.as_array()?;
    let mut parts = Vec::new();
    for output in outputs {
        let Some(content) = output.get("content").and_then(Value::as_array) else {
            continue;
        };
        for item in content {
            if item.get("type").and_then(Value::as_str) != Some("output_text") {
                continue;
            }
            let Some(text) = item.get("text").and_then(Value::as_str) else {
                continue;
            };
            if !text.trim().is_empty() {
                parts.push(text.to_string());
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

fn finish_reason(body: &Value) -> Value {
    body.get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("finish_reason"))
        .cloned()
        .or_else(|| body.get("finish_reason").cloned())
        .unwrap_or(Value::Null)
}

fn gateway_latency_ms(body: &Value, headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get("x-verdictan-latency-ms")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .or_else(|| {
            body.pointer("/verdictan/decision/latency_ms")
                .and_then(Value::as_u64)
        })
}

fn extract_usage_snapshot(body: &Value) -> Option<UsageSnapshot> {
    let usage = body.get("usage")?;
    let prompt_tokens = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let completion_tokens = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let total_tokens = usage
        .get("total_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(prompt_tokens.saturating_add(completion_tokens));
    let cached_input_tokens = usage
        .pointer("/prompt_tokens_details/cached_tokens")
        .or_else(|| usage.get("cache_read_input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let prompt_cost = usage
        .get("prompt_cost")
        .or_else(|| usage.get("input_cost"))
        .and_then(Value::as_f64);
    let completion_cost = usage
        .get("completion_cost")
        .or_else(|| usage.get("output_cost"))
        .and_then(Value::as_f64);
    let total_cost = usage
        .get("total_cost")
        .or_else(|| usage.get("cost"))
        .and_then(Value::as_f64);

    if prompt_tokens == 0
        && completion_tokens == 0
        && total_tokens == 0
        && prompt_cost.is_none()
        && completion_cost.is_none()
        && total_cost.is_none()
    {
        return None;
    }

    Some(UsageSnapshot {
        prompt_tokens,
        completion_tokens,
        total_tokens,
        cached_input_tokens,
        prompt_cost,
        completion_cost,
        total_cost,
    })
}

fn compute_cost_snapshot(usage: Option<UsageSnapshot>, pricing: Option<&ProviderPricing>) -> Value {
    let Some(usage) = usage else {
        return Value::Null;
    };

    if usage.prompt_cost.is_some() || usage.completion_cost.is_some() || usage.total_cost.is_some()
    {
        let prompt_cost = usage.prompt_cost.unwrap_or(0.0);
        let completion_cost = usage
            .completion_cost
            .or_else(|| usage.total_cost.map(|total| (total - prompt_cost).max(0.0)))
            .unwrap_or(0.0);
        let total_cost = usage.total_cost.unwrap_or(prompt_cost + completion_cost);
        return serde_json::json!({
            "prompt_cost": prompt_cost,
            "completion_cost": completion_cost,
            "cached_input_cost": 0.0,
            "total_cost": total_cost,
        });
    }

    let Some(pricing) = pricing else {
        return Value::Null;
    };
    let cost = pricing.compute_cost_with_cache(
        usage.prompt_tokens,
        usage.completion_tokens,
        usage.cached_input_tokens,
    );
    serde_json::json!({
        "prompt_cost": cost.prompt,
        "completion_cost": cost.completion,
        "cached_input_cost": cost.cached_input,
        "total_cost": cost.request,
    })
}

fn usage_to_value(usage: Option<UsageSnapshot>) -> Value {
    usage
        .map(|usage| {
            serde_json::json!({
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens,
                "cached_input_tokens": usage.cached_input_tokens,
            })
        })
        .unwrap_or(Value::Null)
}

fn merge_locality(body: &Value, metadata: &ModelMetadata, requested_region: Option<&str>) -> Value {
    let response_locality = body
        .get("locality")
        .cloned()
        .or_else(|| body.pointer("/verdictan/locality").cloned())
        .unwrap_or_else(|| serde_json::json!({}));

    serde_json::json!({
        "requested_region": requested_region,
        "resolved_region": response_locality
            .get("resolved_region")
            .and_then(Value::as_str)
            .or_else(|| response_locality.get("region_key").and_then(Value::as_str))
            .or_else(|| metadata.locality.get("region_key").and_then(Value::as_str)),
        "region_key": response_locality
            .get("region_key")
            .and_then(Value::as_str)
            .or_else(|| metadata.locality.get("region_key").and_then(Value::as_str)),
        "primary_region_group_key": response_locality
            .get("primary_region_group_key")
            .and_then(Value::as_str)
            .or_else(|| metadata.locality.get("primary_region_group_key").and_then(Value::as_str)),
        "sovereignty_class": response_locality
            .get("sovereignty_class")
            .and_then(Value::as_str)
            .or_else(|| metadata.locality.get("sovereignty_class").and_then(Value::as_str)),
        "endpoint_scope": response_locality
            .get("endpoint_scope")
            .and_then(Value::as_str)
            .or_else(|| metadata.locality.get("endpoint_scope").and_then(Value::as_str)),
    })
}

fn extract_locality(raw_model: &Value) -> Value {
    let region_key = raw_model
        .pointer("/locality/region_key")
        .or_else(|| raw_model.get("region_key"))
        .or_else(|| raw_model.get("region"))
        .cloned()
        .unwrap_or(Value::Null);
    let primary_region_group_key = raw_model
        .pointer("/locality/primary_region_group_key")
        .or_else(|| raw_model.get("primary_region_group_key"))
        .cloned()
        .unwrap_or(Value::Null);
    let sovereignty_class = raw_model
        .pointer("/locality/sovereignty_class")
        .or_else(|| raw_model.get("sovereignty_class"))
        .cloned()
        .unwrap_or(Value::Null);
    let endpoint_scope = raw_model
        .pointer("/locality/endpoint_scope")
        .or_else(|| raw_model.get("endpoint_scope"))
        .cloned()
        .unwrap_or(Value::Null);

    serde_json::json!({
        "region_key": region_key,
        "primary_region_group_key": primary_region_group_key,
        "sovereignty_class": sovereignty_class,
        "endpoint_scope": endpoint_scope,
    })
}

fn request_family_name(request_family: &RequestFamily) -> &'static str {
    match request_family {
        RequestFamily::ChatCompletions => "chat_completions",
        RequestFamily::Responses => "responses",
    }
}

fn required_string_argument(arguments: &Value, keys: &[&str]) -> Result<String, CliError> {
    string_argument(arguments, keys)?
        .ok_or_else(|| CliError::user(format!("chat_test requires '{}'", keys[0])))
}

fn string_argument(arguments: &Value, keys: &[&str]) -> Result<Option<String>, CliError> {
    for key in keys {
        if let Some(value) = arguments.get(*key) {
            let text = value
                .as_str()
                .ok_or_else(|| CliError::user(format!("chat_test '{key}' must be a string")))?;
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
                .ok_or_else(|| CliError::user(format!("chat_test '{key}' must be an integer")))?;
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
                .ok_or_else(|| CliError::user(format!("chat_test '{key}' must be a number")))?;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}
