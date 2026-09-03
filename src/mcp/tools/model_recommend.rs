// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

/// MCP tool: model_recommend
use std::collections::BTreeMap;

use serde_json::Value;

use super::ToolContext;
use crate::error::CliError;
use crate::gateway::provider_catalog::{
    capability_contract_for_provider, normalized_provider_alias,
};

const MODELS_PATH: &str = "/v1/models?page_size=100";
const MODEL_PRICING_PATH: &str = "/v1/model-pricing";
const PROVIDERS_PATH: &str = "/v1/providers";

#[derive(Clone, Debug)]
struct PricingSnapshot {
    input_price_per_million: f64,
    output_price_per_million: f64,
    cached_input_price_per_million: Option<f64>,
    source: &'static str,
}

#[derive(Clone, Debug, Default)]
struct LocalityMetadata {
    region_key: Option<String>,
    primary_region_group_key: Option<String>,
    sovereignty_class: Option<String>,
    endpoint_scope: Option<String>,
}

#[derive(Clone, Debug)]
struct Candidate {
    id: String,
    provider_id: String,
    provider_name: Option<String>,
    display_name: Option<String>,
    model_type: Option<String>,
    context_window: Option<i64>,
    max_output_tokens: Option<i64>,
    supported_features: Vec<String>,
    pricing: Option<PricingSnapshot>,
    locality: LocalityMetadata,
    latency_ms: Option<f64>,
    health_status: Option<String>,
    model: Value,
    sovereignty_fit: i32,
    capability_fit: i32,
}

#[derive(Clone, Debug)]
struct Constraints {
    provider: Option<String>,
    max_input_cost: Option<f64>,
    max_output_cost: Option<f64>,
    needs_json_schema: bool,
    needs_tool_calling: bool,
    context_window_min: Option<i64>,
    region_key: String,
    sovereignty_class: Option<String>,
    latency_target_ms: Option<f64>,
    limit: usize,
}

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "model_recommend",
        "description": "Recommend the best exact-region reachable model using pricing, capability, locality, and health metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "description": "Optional provider ID filter."
                },
                "max_input_cost": {
                    "type": "number",
                    "description": "Maximum input price for each million tokens."
                },
                "max_output_cost": {
                    "type": "number",
                    "description": "Maximum output price for each million tokens."
                },
                "needs_json_schema": {
                    "type": "boolean",
                    "description": "JSON schema structured output support is mandatory."
                },
                "needs_tool_calling": {
                    "type": "boolean",
                    "description": "Tool-calling support is mandatory."
                },
                "context_window_min": {
                    "type": "integer",
                    "description": "Minimum context window."
                },
                "region": {
                    "type": "string",
                    "description": "Exact region key. Defaults to the MCP session region."
                },
                "region_key": {
                    "type": "string",
                    "description": "Alias for region."
                },
                "sovereignty_class": {
                    "type": "string",
                    "description": "Optional exact sovereignty-class requirement."
                },
                "latency_target_ms": {
                    "type": "number",
                    "description": "Optional latency target in milliseconds."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of ranked candidates to return after filtering."
                }
            }
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let constraints = constraints_from_arguments(ctx, arguments)?;

    tracing::debug!(
        session_id = %ctx.session_id,
        region_key = %constraints.region_key,
        provider = constraints.provider.as_deref().unwrap_or(""),
        "recommending model via MCP"
    );

    let models_response = ctx.client.get_json_value(MODELS_PATH).await?;
    let pricing_index = fetch_pricing_index(ctx).await?;
    let providers_index = fetch_provider_index(ctx).await;
    let provider_records = providers_index.unwrap_or_default();

    let raw_models = models_response
        .get("models")
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| {
            models_response
                .get("data")
                .and_then(Value::as_array)
                .cloned()
        })
        .unwrap_or_default();

    let mut candidates = raw_models
        .iter()
        .filter_map(|model| build_candidate(model, &provider_records, &pricing_index))
        .collect::<Vec<_>>();

    if let Some(provider) = constraints.provider.as_deref() {
        let provider = normalized_provider_alias(provider);
        candidates
            .retain(|candidate| normalized_provider_alias(&candidate.provider_id) == provider);
    }

    candidates.retain(|candidate| candidate_matches(candidate, &constraints));
    if candidates.is_empty() {
        return Err(CliError::user(format!(
            "model_recommend found no exact-region candidates for region '{}'",
            constraints.region_key
        )));
    }

    candidates.sort_by(|left, right| compare_candidates(left, right, &constraints));
    candidates.truncate(constraints.limit);

    let selected = candidates
        .first()
        .ok_or_else(|| CliError::internal("model_recommend lost every candidate after ranking"))?;

    Ok(serde_json::json!({
        "selection": candidate_to_value(selected),
        "candidates": candidates.iter().map(candidate_to_value).collect::<Vec<_>>(),
        "constraints": {
            "provider": constraints.provider,
            "max_input_cost": constraints.max_input_cost,
            "max_output_cost": constraints.max_output_cost,
            "needs_json_schema": constraints.needs_json_schema,
            "needs_tool_calling": constraints.needs_tool_calling,
            "context_window_min": constraints.context_window_min,
            "region_key": constraints.region_key,
            "sovereignty_class": constraints.sovereignty_class,
            "latency_target_ms": constraints.latency_target_ms,
        },
        "total_candidates": candidates.len(),
    }))
}

fn constraints_from_arguments(
    ctx: &ToolContext<'_>,
    arguments: &Value,
) -> Result<Constraints, CliError> {
    let region_key = string_argument(arguments, &["region", "region_key"])?
        .or_else(|| ctx.client.region().map(ToString::to_string))
        .ok_or_else(|| {
            CliError::user(
                "model_recommend requires an exact 'region' (or 'region_key') or a region-scoped MCP session",
            )
        })?;
    let limit = integer_argument(arguments, &["limit"])?.unwrap_or(5);

    Ok(Constraints {
        provider: string_argument(arguments, &["provider", "provider_id"])?,
        max_input_cost: number_argument(arguments, &["max_input_cost"])?,
        max_output_cost: number_argument(arguments, &["max_output_cost"])?,
        needs_json_schema: boolean_argument(arguments, &["needs_json_schema"])?,
        needs_tool_calling: boolean_argument(arguments, &["needs_tool_calling"])?,
        context_window_min: integer_argument(arguments, &["context_window_min"])?,
        region_key,
        sovereignty_class: string_argument(arguments, &["sovereignty_class"])?,
        latency_target_ms: number_argument(arguments, &["latency_target_ms"])?,
        limit: usize::try_from(limit.max(1)).unwrap_or(5),
    })
}

async fn fetch_pricing_index(
    ctx: &ToolContext<'_>,
) -> Result<BTreeMap<(String, String), PricingSnapshot>, CliError> {
    let response = ctx.client.get_json_value(MODEL_PRICING_PATH).await?;
    let mut index = BTreeMap::new();

    if let Some(models) = response.get("models").and_then(Value::as_array) {
        for entry in models {
            let Some(provider) = entry.get("provider").and_then(Value::as_str) else {
                continue;
            };
            let Some(model_id) = entry.get("model_id").and_then(Value::as_str) else {
                continue;
            };
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

            index.insert(
                (
                    normalized_provider_alias(provider),
                    model_id.trim().to_string(),
                ),
                PricingSnapshot {
                    input_price_per_million,
                    output_price_per_million,
                    cached_input_price_per_million: entry
                        .get("cached_input_price_per_million")
                        .and_then(Value::as_f64),
                    source: "control_plane",
                },
            );
        }
    }

    Ok(index)
}

async fn fetch_provider_index(ctx: &ToolContext<'_>) -> Result<BTreeMap<String, Value>, CliError> {
    let response = ctx.client.get_json_value(PROVIDERS_PATH).await?;
    let mut providers = BTreeMap::new();

    for provider in response
        .get("providers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        if let Some(id) = provider.get("id").and_then(Value::as_str) {
            providers.insert(normalized_provider_alias(id), provider);
        }
    }

    Ok(providers)
}

fn build_candidate(
    model: &Value,
    providers: &BTreeMap<String, Value>,
    pricing_index: &BTreeMap<(String, String), PricingSnapshot>,
) -> Option<Candidate> {
    let id = model
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_string();

    let provider_id = model
        .get("provider_id")
        .or_else(|| model.get("owned_by"))
        .or_else(|| model.get("provider"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string();
    let provider_alias = normalized_provider_alias(&provider_id);
    let provider_record = providers.get(&provider_alias);
    let locality = extract_locality(model, provider_record);
    let supported_features = string_array_from_value(model.get("supported_features"));
    let capability_contract = capability_contract_for_provider(&provider_id);
    let capability_fit = capability_fit(&supported_features, capability_contract.as_ref());
    let sovereignty_fit = sovereignty_fit(locality.sovereignty_class.as_deref());

    Some(Candidate {
        id: id.clone(),
        provider_id,
        provider_name: optional_string_field(model, "provider_name").or_else(|| {
            provider_record.and_then(|value| optional_string_field(value, "display_name"))
        }),
        display_name: optional_string_field(model, "display_name"),
        model_type: optional_string_field(model, "model_type"),
        context_window: integer_field(model, "context_window"),
        max_output_tokens: integer_field(model, "max_output_tokens"),
        supported_features,
        pricing: pricing_index
            .get(&(provider_alias, id.clone()))
            .cloned()
            .or_else(|| pricing_from_catalog(model)),
        locality,
        latency_ms: extract_latency_ms(model, provider_record),
        health_status: extract_health_status(model, provider_record),
        model: model.clone(),
        sovereignty_fit,
        capability_fit,
    })
}

fn candidate_matches(candidate: &Candidate, constraints: &Constraints) -> bool {
    if candidate.locality.region_key.as_deref() != Some(constraints.region_key.as_str()) {
        return false;
    }

    if let Some(expected) = constraints.sovereignty_class.as_deref() {
        if !candidate
            .locality
            .sovereignty_class
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(expected))
        {
            return false;
        }
    }

    if constraints.needs_json_schema && !supports_json_schema(candidate) {
        return false;
    }
    if constraints.needs_tool_calling && !supports_tool_calling(candidate) {
        return false;
    }
    if let Some(min_context) = constraints.context_window_min {
        if candidate.context_window.unwrap_or_default() < min_context {
            return false;
        }
    }
    if let Some(max_input_cost) = constraints.max_input_cost {
        if candidate
            .pricing
            .as_ref()
            .is_some_and(|pricing| pricing.input_price_per_million > max_input_cost)
        {
            return false;
        }
    }
    if let Some(max_output_cost) = constraints.max_output_cost {
        if candidate
            .pricing
            .as_ref()
            .is_some_and(|pricing| pricing.output_price_per_million > max_output_cost)
        {
            return false;
        }
    }
    if let Some(target_ms) = constraints.latency_target_ms {
        if candidate
            .latency_ms
            .is_some_and(|latency_ms| latency_ms > target_ms)
        {
            return false;
        }
    }

    true
}

fn compare_candidates(
    left: &Candidate,
    right: &Candidate,
    constraints: &Constraints,
) -> std::cmp::Ordering {
    right
        .sovereignty_fit
        .cmp(&left.sovereignty_fit)
        .then_with(|| right.capability_fit.cmp(&left.capability_fit))
        .then_with(|| {
            latency_sort_key(left, constraints).cmp(&latency_sort_key(right, constraints))
        })
        .then_with(|| cost_sort_key(left).cmp(&cost_sort_key(right)))
        .then_with(|| left.id.cmp(&right.id))
}

fn latency_sort_key(candidate: &Candidate, constraints: &Constraints) -> (i32, i64) {
    let health_penalty = match candidate
        .health_status
        .as_deref()
        .map(|value| value.to_ascii_lowercase())
    {
        Some(value) if value == "healthy" || value == "ok" || value == "ready" => 0,
        Some(_) => 1,
        None => 0,
    };
    let latency = candidate
        .latency_ms
        .unwrap_or(constraints.latency_target_ms.unwrap_or(99_999.0))
        .round() as i64;
    (health_penalty, latency)
}

fn cost_sort_key(candidate: &Candidate) -> i64 {
    candidate
        .pricing
        .as_ref()
        .map(|pricing| {
            ((pricing.input_price_per_million + pricing.output_price_per_million) * 1_000_000.0)
                .round() as i64
        })
        .unwrap_or(i64::MAX)
}

fn candidate_to_value(candidate: &Candidate) -> Value {
    serde_json::json!({
        "id": candidate.id.clone(),
        "provider_id": candidate.provider_id.clone(),
        "provider_name": candidate.provider_name.clone(),
        "display_name": candidate.display_name.clone(),
        "model_type": candidate.model_type.clone(),
        "context_window": candidate.context_window,
        "max_output_tokens": candidate.max_output_tokens,
        "supported_features": candidate.supported_features.clone(),
        "pricing": candidate.pricing.as_ref().map(|pricing| {
            serde_json::json!({
                "input_price_per_million": pricing.input_price_per_million,
                "output_price_per_million": pricing.output_price_per_million,
                "cached_input_price_per_million": pricing.cached_input_price_per_million,
                "source": pricing.source,
            })
        }),
        "locality": {
            "region_key": candidate.locality.region_key.clone(),
            "primary_region_group_key": candidate.locality.primary_region_group_key.clone(),
            "sovereignty_class": candidate.locality.sovereignty_class.clone(),
            "endpoint_scope": candidate.locality.endpoint_scope.clone(),
        },
        "latency_ms": candidate.latency_ms,
        "health_status": candidate.health_status.clone(),
        "score_breakdown": {
            "sovereignty_fit": candidate.sovereignty_fit,
            "capability_fit": candidate.capability_fit,
        },
        "status": candidate
            .model
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    })
}

fn capability_fit(
    supported_features: &[String],
    contract: Option<&crate::gateway::runtime_capabilities::RuntimeCapabilityContract>,
) -> i32 {
    let mut score = 0;
    let model_features_are_authoritative = !supported_features.is_empty();

    if feature_supported(supported_features, contract, "json_schema") {
        score += 2;
    }
    if feature_supported(supported_features, contract, "tool_calls") {
        score += 2;
    }

    if !model_features_are_authoritative
        && contract.is_some_and(|value| {
            value
                .response_format_features
                .iter()
                .any(|feature| feature.as_str() == "json_schema")
        })
    {
        score += 1;
    }
    if !model_features_are_authoritative
        && contract.is_some_and(|value| {
            value
                .interaction_features
                .iter()
                .any(|feature| feature.as_str() == "tool_calls")
        })
    {
        score += 1;
    }
    score
}

fn sovereignty_fit(sovereignty_class: Option<&str>) -> i32 {
    match sovereignty_class.map(|value| value.to_ascii_lowercase()) {
        Some(value) if value.contains("sovereign") => 2,
        Some(_) => 1,
        None => 0,
    }
}

fn supports_json_schema(candidate: &Candidate) -> bool {
    feature_supported(
        &candidate.supported_features,
        capability_contract_for_provider(&candidate.provider_id).as_ref(),
        "json_schema",
    )
}

fn supports_tool_calling(candidate: &Candidate) -> bool {
    feature_supported(
        &candidate.supported_features,
        capability_contract_for_provider(&candidate.provider_id).as_ref(),
        "tool_calls",
    )
}

fn feature_supported(
    supported_features: &[String],
    contract: Option<&crate::gateway::runtime_capabilities::RuntimeCapabilityContract>,
    feature: &str,
) -> bool {
    if !supported_features.is_empty() {
        return supported_features
            .iter()
            .any(|value| value.eq_ignore_ascii_case(feature));
    }

    match feature {
        "json_schema" => contract.is_some_and(|value| {
            value
                .response_format_features
                .iter()
                .any(|candidate| candidate.as_str() == feature)
        }),
        "tool_calls" => contract.is_some_and(|value| {
            value
                .interaction_features
                .iter()
                .any(|candidate| candidate.as_str() == feature)
        }),
        _ => false,
    }
}

fn pricing_from_catalog(model: &Value) -> Option<PricingSnapshot> {
    let pricing = model.get("pricing")?;
    let pricing = pricing.get("pay_as_you_go").unwrap_or(pricing);

    let input_price_per_million = pricing
        .get("input_price_per_million")
        .or_else(|| pricing.get("input_token_price"))
        .and_then(Value::as_f64)?;
    let output_price_per_million = pricing
        .get("output_price_per_million")
        .or_else(|| pricing.get("output_token_price"))
        .and_then(Value::as_f64)?;

    Some(PricingSnapshot {
        input_price_per_million,
        output_price_per_million,
        cached_input_price_per_million: pricing
            .get("cached_input_price_per_million")
            .or_else(|| pricing.get("cached_input_read_price"))
            .and_then(Value::as_f64),
        source: "catalog",
    })
}

fn extract_locality(model: &Value, provider: Option<&Value>) -> LocalityMetadata {
    LocalityMetadata {
        region_key: locality_string(
            model,
            provider,
            &[&["locality", "region_key"], &["region_key"], &["region"]],
        )
        .or_else(|| {
            string_array_from_value(model.get("regions"))
                .into_iter()
                .next()
        }),
        primary_region_group_key: locality_string(
            model,
            provider,
            &[
                &["locality", "primary_region_group_key"],
                &["primary_region_group_key"],
            ],
        ),
        sovereignty_class: locality_string(
            model,
            provider,
            &[&["locality", "sovereignty_class"], &["sovereignty_class"]],
        ),
        endpoint_scope: locality_string(
            model,
            provider,
            &[&["locality", "endpoint_scope"], &["endpoint_scope"]],
        ),
    }
}

fn extract_latency_ms(model: &Value, provider: Option<&Value>) -> Option<f64> {
    number_at_paths(
        model,
        &[
            &["latency_ms"],
            &["p50_latency_ms"],
            &["health", "latency_ms"],
        ],
    )
    .or_else(|| {
        provider.and_then(|value| {
            number_at_paths(
                value,
                &[
                    &["latency_ms"],
                    &["p50_latency_ms"],
                    &["health", "latency_ms"],
                ],
            )
        })
    })
}

fn extract_health_status(model: &Value, provider: Option<&Value>) -> Option<String> {
    locality_string(
        model,
        provider,
        &[&["health_status"], &["health", "status"], &["status"]],
    )
}

fn locality_string(model: &Value, provider: Option<&Value>, paths: &[&[&str]]) -> Option<String> {
    for path in paths {
        if let Some(value) = string_at_path(model, path) {
            return Some(value);
        }
        if let Some(value) = provider.and_then(|provider| string_at_path(provider, path)) {
            return Some(value);
        }
    }
    None
}

fn string_at_path(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn number_at_paths(value: &Value, paths: &[&[&str]]) -> Option<f64> {
    for path in paths {
        let mut current = value;
        let mut found = true;
        for segment in *path {
            match current.get(*segment) {
                Some(next) => current = next,
                None => {
                    found = false;
                    break;
                }
            }
        }
        if found {
            if let Some(number) = current.as_f64() {
                return Some(number);
            }
        }
    }
    None
}

fn string_array_from_value(value: Option<&Value>) -> Vec<String> {
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

fn optional_string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
        .map(ToString::to_string)
}

fn integer_field(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_i64)
}

fn string_argument(arguments: &Value, keys: &[&str]) -> Result<Option<String>, CliError> {
    for key in keys {
        if let Some(value) = arguments.get(*key) {
            let text = value.as_str().ok_or_else(|| {
                CliError::user(format!("model_recommend '{key}' must be a string"))
            })?;
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
                CliError::user(format!("model_recommend '{key}' must be an integer"))
            })?;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

fn number_argument(arguments: &Value, keys: &[&str]) -> Result<Option<f64>, CliError> {
    for key in keys {
        if let Some(value) = arguments.get(*key) {
            let parsed = value.as_f64().ok_or_else(|| {
                CliError::user(format!("model_recommend '{key}' must be a number"))
            })?;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

fn boolean_argument(arguments: &Value, keys: &[&str]) -> Result<bool, CliError> {
    for key in keys {
        if let Some(value) = arguments.get(*key) {
            return value.as_bool().ok_or_else(|| {
                CliError::user(format!("model_recommend '{key}' must be a boolean"))
            });
        }
    }
    Ok(false)
}
