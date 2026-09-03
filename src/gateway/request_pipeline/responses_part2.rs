// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Family request-pipeline module.
//! Child of `gateway::server`; parent private items remain visible.
use super::super::*;
use super::*;

pub(crate) fn apply_data_routing_policy_selection(
    registry: &crate::gateway::providers::ProviderRegistry,
    ordered: &[usize],
    data_routing: Option<&crate::gateway::providers::DataRoutingPolicy>,
    request_id: &str,
    streaming: bool,
) -> Result<Vec<usize>, ProviderOrderSelectionError> {
    let Some(data_routing) = data_routing else {
        return Ok(ordered.to_vec());
    };

    let (allowed_indices, excluded) =
        crate::gateway::providers::filter_providers_by_data_policy(data_routing, &registry.targets);

    if data_routing.log_provider_selection && !excluded.is_empty() {
        for exclusion in &excluded {
            tracing::info!(
                request_id = %request_id,
                provider_id = %exclusion.provider_id,
                reason = %exclusion.reason,
                "data-routing-policy excluded provider{}",
                if streaming { " (streaming)" } else { "" }
            );
        }
    }

    if allowed_indices.is_empty() {
        return match data_routing.on_no_compliant_provider {
            crate::gateway::providers::NoCompliantProviderAction::Block => {
                tracing::warn!(
                    request_id = %request_id,
                    "data-routing-policy: no providers meet data retention requirements, blocking{}",
                    if streaming { " (streaming)" } else { "" }
                );
                Err(ProviderOrderSelectionError::NoCompliantProvider)
            }
            crate::gateway::providers::NoCompliantProviderAction::Warn => {
                tracing::warn!(
                    request_id = %request_id,
                    "data-routing-policy: no compliant providers found, proceeding with all targets{}",
                    if streaming { " (streaming warn mode)" } else { " (warn mode)" }
                );
                Ok(ordered.to_vec())
            }
        };
    }

    Ok(ordered
        .iter()
        .copied()
        .filter(|index| allowed_indices.contains(index))
        .collect())
}

pub(crate) fn resolve_initial_provider_order(
    registry: &crate::gateway::providers::ProviderRegistry,
    state: &ActiveGatewayStateView<'_>,
    request_id: &str,
    pins: &ProviderRequestPins,
    streaming: bool,
) -> Result<Vec<usize>, ProviderOrderSelectionError> {
    let ordered = crate::gateway::provider_metrics::select_providers(
        &registry.targets,
        &registry.routing,
        state.provider_metrics,
    );
    let ordered = apply_provider_pin_selection(registry, pins.provider.as_deref(), request_id)?
        .unwrap_or(ordered);
    let ordered = apply_data_routing_policy_selection(
        registry,
        &ordered,
        data_routing_policy_for_state(state).as_ref(),
        request_id,
        streaming,
    )?;
    if let Some(pinned_id) = state
        .ua_pinned_target_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let pinned: Vec<usize> = ordered
            .iter()
            .copied()
            .filter(|index| registry.targets[*index].id == pinned_id)
            .collect();
        if pinned.is_empty() {
            return Err(ProviderOrderSelectionError::NoCompliantProvider);
        }
        return Ok(pinned);
    }
    Ok(ordered)
}

pub(crate) fn build_unknown_provider_pin_body(pin: &str) -> Bytes {
    serde_json::to_vec(&serde_json::json!({
        "error": {
            "message": format!(
                "X-Verdictan-Provider '{pin}' does not match any configured provider target"
            ),
            "type": "invalid_provider_pin",
            "code": "unknown_provider"
        }
    }))
    .unwrap_or_default()
    .into()
}

pub(crate) fn build_unknown_provider_pin_buffered_response(
    pin: &str,
) -> crate::gateway::cache::BufferedUpstreamResponse {
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    crate::gateway::cache::BufferedUpstreamResponse::new(
        StatusCode::BAD_REQUEST,
        resp_headers,
        build_unknown_provider_pin_body(pin),
        false,
    )
}

pub(crate) fn build_unknown_provider_pin_streaming_response(
    pin: &str,
) -> PreparedStreamingResponse {
    prepared_streaming_json_response(
        StatusCode::BAD_REQUEST,
        build_unknown_provider_pin_body(pin),
        HeaderValue::from_static("application/json"),
    )
}

pub(crate) fn build_no_compliant_provider_body() -> Bytes {
    serde_json::to_vec(&serde_json::json!({
        "error": {
            "message": "data-routing-policy: no providers meet data retention requirements",
            "type": "data_routing_policy_violation",
            "code": "no_compliant_provider"
        }
    }))
    .unwrap_or_default()
    .into()
}

pub(crate) fn build_no_compliant_provider_buffered_response(
) -> crate::gateway::cache::BufferedUpstreamResponse {
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    crate::gateway::cache::BufferedUpstreamResponse::new(
        StatusCode::FORBIDDEN,
        resp_headers,
        build_no_compliant_provider_body(),
        false,
    )
}

pub(crate) fn build_no_compliant_provider_streaming_response() -> PreparedStreamingResponse {
    prepared_streaming_json_response(
        StatusCode::FORBIDDEN,
        build_no_compliant_provider_body(),
        HeaderValue::from_static("application/json"),
    )
}

#[derive(Clone, Debug)]
pub(crate) struct RequestedRouteModelSelection {
    pub(crate) requested_model: String,
    pub(crate) requested_route_model: String,
    pub(crate) requested_route_model_uses_group: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ModelRoutingFailure {
    pub(crate) requested_model: String,
    pub(crate) patterns: Vec<String>,
    pub(crate) providers: Vec<String>,
}

pub(crate) fn target_model_pattern(target: &crate::gateway::providers::ProviderTarget) -> String {
    if target.model.trim() == "*" {
        return format!("{}:*", target.id);
    }

    if target.models.is_empty() {
        return format!("{}:{}", target.id, target.model);
    }

    let model_ids: Vec<&str> = target
        .models
        .iter()
        .filter(|model| model.enabled)
        .map(|model| model.model_id.as_str())
        .collect();
    format!("{}:[{}]", target.id, model_ids.join(", "))
}

pub(crate) fn build_model_routing_failure(
    registry: &crate::gateway::providers::ProviderRegistry,
    effective_ordered: &[usize],
    requested_model: &str,
) -> ModelRoutingFailure {
    let patterns = effective_ordered
        .iter()
        .map(|&index| target_model_pattern(&registry.targets[index]))
        .collect();
    let providers = effective_ordered
        .iter()
        .map(|&index| registry.targets[index].id.clone())
        .collect();
    ModelRoutingFailure {
        requested_model: requested_model.to_string(),
        patterns,
        providers,
    }
}

pub(crate) fn validate_requested_route_model(
    registry: &crate::gateway::providers::ProviderRegistry,
    base_body: &serde_json::Value,
    effective_ordered: &[usize],
    model_pin: Option<&str>,
    request_id: &str,
    streaming: bool,
) -> Result<RequestedRouteModelSelection, ModelRoutingFailure> {
    let routed_model_name = model_pin.or_else(|| base_body.get("model").and_then(|m| m.as_str()));
    if let Some(requested_model) = routed_model_name.filter(|model| !model.trim().is_empty()) {
        let any_supports = effective_ordered
            .iter()
            .any(|&index| target_supports_model(&registry.targets[index], requested_model));
        if !any_supports {
            let failure = build_model_routing_failure(registry, effective_ordered, requested_model);
            tracing::warn!(
                request_id = %request_id,
                requested_model = %requested_model,
                available_providers = ?failure.providers,
                "model routing failure: no provider matched the requested model{}",
                if streaming { " (streaming)" } else { "" }
            );
            return Err(failure);
        }
    }

    let requested_model = base_body
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    let requested_route_model = routed_model_name.unwrap_or(&requested_model).to_string();
    let requested_route_model_uses_group = !requested_route_model.trim().is_empty()
        && registry
            .resolve_model_group(&requested_route_model)
            .is_some();

    Ok(RequestedRouteModelSelection {
        requested_model,
        requested_route_model,
        requested_route_model_uses_group,
    })
}

pub(crate) fn build_model_routing_failure_message(failure: &ModelRoutingFailure) -> String {
    format!(
        "No provider matched model '{}'. \
         Attempted patterns: [{}]. Available providers: [{}]. \
         Model names in requests must exactly match a configured provider pattern. \
         See: docs.verdictan.com/docs/configurations#provider-routing",
        failure.requested_model,
        failure.patterns.join(", "),
        failure.providers.join(", "),
    )
}

pub(crate) fn build_model_routing_failure_body(failure: &ModelRoutingFailure) -> Bytes {
    Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "error": {
                "message": build_model_routing_failure_message(failure),
                "type": "model_routing_failure",
                "code": "no_matching_provider"
            }
        }))
        .unwrap_or_default(),
    )
}

pub(crate) fn build_model_routing_failure_buffered_response(
    failure: &ModelRoutingFailure,
) -> crate::gateway::cache::BufferedUpstreamResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    crate::gateway::cache::BufferedUpstreamResponse::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        headers,
        build_model_routing_failure_body(failure),
        false,
    )
}

pub(crate) fn build_model_routing_failure_streaming_response(
    failure: &ModelRoutingFailure,
) -> PreparedStreamingResponse {
    prepared_streaming_json_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        build_model_routing_failure_body(failure),
        HeaderValue::from_static("application/json"),
    )
}

/// Every provider-order stage that can eliminate candidates reports emptiness
/// through this type. A stage that narrowed a non-empty candidate set down to
/// nothing must never restore the unfiltered set: the eliminated targets were
/// eliminated for a policy, cost, capability, or routing reason, so resurrecting
/// them would dispatch to a target the request was not permitted to reach.
#[derive(Clone, Debug)]
pub(crate) enum ProviderOrderFilterError {
    CostBudgetExceeded,
    NoMatchingRegion(String),
    /// The required region emptied the candidate set while at least one
    /// candidate carried an operator-declared `data_residency` policy. Reported
    /// apart from `NoMatchingRegion` so a compliance block is not mistaken for
    /// a missing-metadata block.
    DataResidencyExcludedAllCandidates(String),
    NoMatchingQuantization,
    NoContextWindowCapacity {
        estimated_tokens: usize,
    },
    ModelGroupChainEmpty(String),
    AutoRoutingNoEligibleProvider,
    UsageAuthorizationDeniedAllCandidates,
}

pub(crate) fn apply_cost_filter_to_provider_order(
    registry: &crate::gateway::providers::ProviderRegistry,
    ordered: &[usize],
    base_body: &serde_json::Value,
    request_id: &str,
    streaming: bool,
) -> Result<Vec<usize>, ProviderOrderFilterError> {
    let Some(max_price) = registry.routing.max_price.as_ref() else {
        return Ok(ordered.to_vec());
    };

    let filtered = crate::gateway::providers::filter_by_cost(
        &registry.targets,
        ordered,
        max_price,
        None,
        extract_requested_max_tokens(base_body),
    );
    if filtered.is_empty() {
        tracing::warn!(
            request_id = %request_id,
            "cost filter: no providers within budget, blocking{}",
            if streaming { " (streaming)" } else { "" }
        );
        return Err(ProviderOrderFilterError::CostBudgetExceeded);
    }

    Ok(filtered)
}

pub(crate) fn apply_region_filter_to_provider_order(
    registry: &crate::gateway::providers::ProviderRegistry,
    ordered: &[usize],
    request_id: &str,
    streaming: bool,
) -> Result<Vec<usize>, ProviderOrderFilterError> {
    let Some(require_region) = registry.routing.require_region.as_ref() else {
        return Ok(ordered.to_vec());
    };

    let filtered =
        crate::gateway::providers::filter_by_region(&registry.targets, ordered, require_region);

    if filtered.is_empty() {
        // A residency policy on any excluded candidate means the operator pinned
        // data to a region and no endpoint can honor it. Route out of region and
        // the pin is worthless, so this stays fail-closed and is reported as the
        // compliance denial it is.
        if crate::gateway::providers::any_target_declares_data_residency(&registry.targets, ordered)
        {
            tracing::warn!(
                request_id = %request_id,
                require_region = %require_region,
                "region filter: data residency excludes every provider candidate, blocking{}",
                if streaming { " (streaming)" } else { "" }
            );
            return Err(
                ProviderOrderFilterError::DataResidencyExcludedAllCandidates(
                    require_region.to_string(),
                ),
            );
        }
        tracing::warn!(
            request_id = %request_id,
            require_region = %require_region,
            "region filter: no providers match required region, blocking{}",
            if streaming { " (streaming)" } else { "" }
        );
        return Err(ProviderOrderFilterError::NoMatchingRegion(
            require_region.to_string(),
        ));
    }

    Ok(filtered)
}

pub(crate) fn apply_quantization_filter_to_provider_order(
    registry: &crate::gateway::providers::ProviderRegistry,
    ordered: &[usize],
    request_id: &str,
    streaming: bool,
) -> Result<Vec<usize>, ProviderOrderFilterError> {
    let Some(required_quantizations) = registry.routing.require_quantizations.as_ref() else {
        return Ok(ordered.to_vec());
    };

    let filtered = crate::gateway::providers::filter_by_quantization(
        &registry.targets,
        ordered,
        required_quantizations,
    );
    if filtered.is_empty() {
        tracing::warn!(
            request_id = %request_id,
            "quantization filter: no providers match required quantizations, blocking{}",
            if streaming { " (streaming)" } else { "" }
        );
        return Err(ProviderOrderFilterError::NoMatchingQuantization);
    }

    Ok(filtered)
}

pub(crate) fn apply_pre_call_context_window_filter(
    registry: &crate::gateway::providers::ProviderRegistry,
    ordered: &[usize],
    base_body: &serde_json::Value,
    request_id: &str,
    streaming: bool,
) -> Result<Vec<usize>, ProviderOrderFilterError> {
    if !registry.routing.enable_pre_call_checks {
        return Ok(ordered.to_vec());
    }

    let Some(estimated_tokens) =
        crate::gateway::token_estimation::estimate_prompt_tokens(base_body)
    else {
        return Ok(ordered.to_vec());
    };

    let filtered: Vec<usize> = ordered
        .iter()
        .copied()
        .filter(|&index| {
            let target = &registry.targets[index];
            match target.max_context_tokens {
                Some(max_context_tokens) if estimated_tokens > max_context_tokens => {
                    tracing::debug!(
                        request_id = %request_id,
                        provider_id = %target.id,
                        estimated_tokens = estimated_tokens,
                        max_context_tokens = max_context_tokens,
                        "pre-call check: provider context window too small, skipping{}",
                        if streaming { " (streaming)" } else { "" }
                    );
                    false
                }
                _ => true,
            }
        })
        .collect();

    // The operator opted into pre-call checks, so a prompt that fits nowhere must
    // be refused. Restoring the original order here would knowingly dispatch to a
    // provider whose context window cannot hold the request.
    if filtered.is_empty() && !ordered.is_empty() {
        tracing::warn!(
            request_id = %request_id,
            estimated_tokens = estimated_tokens,
            "pre-call check: no provider context window can hold the prompt, blocking{}",
            if streaming { " (streaming)" } else { "" }
        );
        return Err(ProviderOrderFilterError::NoContextWindowCapacity { estimated_tokens });
    }

    Ok(filtered)
}

pub(crate) fn apply_model_group_provider_ordering(
    registry: &crate::gateway::providers::ProviderRegistry,
    ordered: &[usize],
    base_body: &serde_json::Value,
    request_id: &str,
    streaming: bool,
) -> Result<Vec<usize>, ProviderOrderFilterError> {
    let Some(model_name) = base_body.get("model").and_then(|value| value.as_str()) else {
        return Ok(ordered.to_vec());
    };
    let Some(group) = registry.resolve_model_group(model_name) else {
        return Ok(ordered.to_vec());
    };

    let mut chain_indices = Vec::new();
    let mut current_group = Some(group);
    let mut visited = std::collections::HashSet::new();
    while let Some(group) = current_group {
        if !visited.insert(group.name.as_str()) {
            break;
        }
        for target_id in &group.targets {
            if let Some(index) = registry
                .targets
                .iter()
                .position(|target| target.id == *target_id)
            {
                if ordered.contains(&index) && !chain_indices.contains(&index) {
                    chain_indices.push(index);
                }
            }
        }
        current_group = group.fallback_group.as_deref().and_then(|name| {
            registry
                .model_groups
                .iter()
                .find(|candidate| candidate.name == name)
        });
    }

    // The request named a model group, so only that group's chain may serve it.
    // Restoring the original order would route to a target outside the group the
    // caller asked for, silently defeating the group's routing boundary.
    if chain_indices.is_empty() && !ordered.is_empty() {
        tracing::warn!(
            request_id = %request_id,
            model_group = %group.name,
            "model group: all chain targets filtered out by prior constraints, blocking{}",
            if streaming { " (streaming)" } else { "" }
        );
        return Err(ProviderOrderFilterError::ModelGroupChainEmpty(
            group.name.clone(),
        ));
    }

    Ok(chain_indices)
}

/// Scores the auto-routing candidates and maps them back onto `ordered`,
/// optionally excluding the usage-authorization denied target ids.
pub(crate) fn auto_scored_provider_order(
    state: &ActiveGatewayStateView<'_>,
    registry: &crate::gateway::providers::ProviderRegistry,
    ordered: &[usize],
    denied_target_ids: Option<&std::collections::HashSet<String>>,
) -> Vec<usize> {
    crate::gateway::auto_provider::score_targets_with_denied(
        &registry.targets,
        &state.auto_provider.routing,
        state.provider_metrics,
        denied_target_ids,
    )
    .iter()
    .filter_map(|target| {
        registry
            .targets
            .iter()
            .position(|candidate| std::ptr::eq(candidate, *target))
    })
    .filter(|index| ordered.contains(index))
    .collect()
}

pub(crate) fn apply_auto_provider_ordering(
    state: &ActiveGatewayStateView<'_>,
    registry: &crate::gateway::providers::ProviderRegistry,
    ordered: &[usize],
    base_body: &serde_json::Value,
    request_id: &str,
    streaming: bool,
) -> Result<Vec<usize>, ProviderOrderFilterError> {
    if !state.auto_provider.enabled {
        return Ok(ordered.to_vec());
    }

    let Some(model_name) = base_body.get("model").and_then(|value| value.as_str()) else {
        return Ok(ordered.to_vec());
    };
    if model_name != state.auto_provider.name {
        return Ok(ordered.to_vec());
    }

    let auto_ordered =
        auto_scored_provider_order(state, registry, ordered, Some(&state.ua_denied_target_ids));

    if auto_ordered.is_empty() {
        if ordered.is_empty() {
            return Ok(Vec::new());
        }

        // An emptied scored set always blocks — `score_targets_with_denied`
        // documents that its caller must surface `no_eligible_provider` rather
        // than fall back. The two causes are reported separately so the caller
        // learns whether it was a usage-authorization denial or the price ceiling.
        if !state.ua_denied_target_ids.is_empty()
            && !auto_scored_provider_order(state, registry, ordered, None).is_empty()
        {
            tracing::warn!(
                request_id = %request_id,
                denied_candidates = state.ua_denied_target_ids.len(),
                "auto provider: every scored target is denied by usage authorization, blocking{}",
                if streaming { " (streaming)" } else { "" }
            );
            return Err(ProviderOrderFilterError::UsageAuthorizationDeniedAllCandidates);
        }
        tracing::warn!(
            request_id = %request_id,
            "auto provider: no target satisfies the auto-routing eligibility ceiling, blocking{}",
            if streaming { " (streaming)" } else { "" }
        );
        return Err(ProviderOrderFilterError::AutoRoutingNoEligibleProvider);
    }

    tracing::info!(
        request_id = %request_id,
        selected_provider = %registry.targets[auto_ordered[0]].id,
        candidates = auto_ordered.len(),
        "auto provider: selected target via cost+latency scoring{}",
        if streaming { " (streaming)" } else { "" }
    );
    Ok(auto_ordered)
}

pub(crate) fn resolve_prefiltered_provider_order(
    registry: &crate::gateway::providers::ProviderRegistry,
    state: &ActiveGatewayStateView<'_>,
    ordered: &[usize],
    base_body: &serde_json::Value,
    request_id: &str,
    streaming: bool,
) -> Result<Vec<usize>, ProviderOrderFilterError> {
    let ordered = apply_semantic_routing(base_body, registry, state, ordered);
    let ordered =
        apply_cost_filter_to_provider_order(registry, &ordered, base_body, request_id, streaming)?;
    let ordered = apply_region_filter_to_provider_order(registry, &ordered, request_id, streaming)?;
    let ordered =
        apply_quantization_filter_to_provider_order(registry, &ordered, request_id, streaming)?;
    let ordered =
        apply_pre_call_context_window_filter(registry, &ordered, base_body, request_id, streaming)?;
    let ordered =
        apply_model_group_provider_ordering(registry, &ordered, base_body, request_id, streaming)?;
    apply_auto_provider_ordering(state, registry, &ordered, base_body, request_id, streaming)
}

#[derive(Debug)]
pub(crate) enum ProviderDispatchPreparationError {
    Budget(BudgetFilterRejection),
    RuntimeCapability(crate::gateway::runtime_capabilities::RuntimeCapabilityError),
    RuntimeRouting(RuntimeRoutingError),
    ModelRouting(ModelRoutingFailure),
}

pub(crate) struct ProviderDispatchPlan {
    pub(crate) effective_ordered: Vec<usize>,
    pub(crate) requested_route_model_selection: RequestedRouteModelSelection,
}

pub(crate) async fn resolve_provider_dispatch_plan(
    registry: &crate::gateway::providers::ProviderRegistry,
    state: &ActiveGatewayStateView<'_>,
    path: &str,
    headers: &HeaderMap,
    base_body: &serde_json::Value,
    ordered: &[usize],
    request_id: &str,
    model_pin: Option<&str>,
    streaming: bool,
) -> Result<ProviderDispatchPlan, ProviderDispatchPreparationError> {
    let effective_ordered =
        apply_control_plane_budget_controls(base_body, registry, state, ordered, request_id)
            .await
            .map_err(ProviderDispatchPreparationError::Budget)?;
    let effective_ordered = filter_targets_by_runtime_capabilities(
        path,
        headers,
        base_body,
        &registry.targets,
        &effective_ordered,
        request_id,
    )
    .map_err(ProviderDispatchPreparationError::RuntimeCapability)?;
    let effective_ordered = filter_targets_by_model_capabilities(
        path,
        headers,
        base_body,
        &registry.targets,
        &effective_ordered,
        request_id,
        model_pin,
        Some(&state.catalog_snapshot),
    )
    .map_err(ProviderDispatchPreparationError::RuntimeCapability)?;
    let effective_ordered =
        runtime_routing_filter_targets(state, &registry.targets, &effective_ordered, request_id)
            .map_err(ProviderDispatchPreparationError::RuntimeRouting)?;
    let requested_route_model_selection = validate_requested_route_model(
        registry,
        base_body,
        &effective_ordered,
        model_pin,
        request_id,
        streaming,
    )
    .map_err(ProviderDispatchPreparationError::ModelRouting)?;

    Ok(ProviderDispatchPlan {
        effective_ordered,
        requested_route_model_selection,
    })
}

pub(crate) fn build_provider_order_filter_body(error: &ProviderOrderFilterError) -> Bytes {
    let body = match error {
        ProviderOrderFilterError::CostBudgetExceeded => serde_json::json!({
            "error": {
                "message": "no providers within cost budget",
                "type": "cost_budget_exceeded",
                "code": "no_eligible_provider"
            }
        }),
        ProviderOrderFilterError::NoMatchingRegion(require_region) => serde_json::json!({
            "error": {
                "message": format!("no providers match required region '{require_region}'"),
                "type": "region_provider_constraint",
                "code": "no_eligible_provider"
            }
        }),
        ProviderOrderFilterError::DataResidencyExcludedAllCandidates(require_region) => {
            serde_json::json!({
                "error": {
                    "message": format!(
                        "no provider endpoint satisfies data residency for region '{require_region}'"
                    ),
                    "type": "data_residency_constraint",
                    "code": "no_compliant_provider"
                }
            })
        }
        ProviderOrderFilterError::NoMatchingQuantization => serde_json::json!({
            "error": {
                "message": "no providers match required quantizations",
                "type": "quantization_constraint_violation",
                "code": "no_eligible_provider"
            }
        }),
        ProviderOrderFilterError::NoContextWindowCapacity { estimated_tokens } => {
            serde_json::json!({
                "error": {
                    "message": format!(
                        "no provider context window can hold the estimated {estimated_tokens} prompt tokens"
                    ),
                    "type": "context_window_constraint_violation",
                    "code": "no_eligible_provider"
                }
            })
        }
        ProviderOrderFilterError::ModelGroupChainEmpty(group) => serde_json::json!({
            "error": {
                "message": format!(
                    "no providers remain in model group '{group}' after routing constraints"
                ),
                "type": "model_group_constraint_violation",
                "code": "no_eligible_provider"
            }
        }),
        ProviderOrderFilterError::AutoRoutingNoEligibleProvider => serde_json::json!({
            "error": {
                "message": "no providers satisfy the auto-routing eligibility ceiling",
                "type": "auto_routing_constraint_violation",
                "code": "no_eligible_provider"
            }
        }),
        ProviderOrderFilterError::UsageAuthorizationDeniedAllCandidates => serde_json::json!({
            "error": {
                "message": "no auto-routing providers are permitted by usage-authorization policy",
                "type": "usage_authorization_denied",
                "code": "no_eligible_provider"
            }
        }),
    };
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

pub(crate) fn provider_order_filter_status(error: &ProviderOrderFilterError) -> StatusCode {
    match error {
        // A data-residency block is a legal/compliance refusal rather than a
        // capacity, budget, or capability refusal, so it keeps the dedicated 451
        // status instead of the shared 403 the other stages use.
        ProviderOrderFilterError::DataResidencyExcludedAllCandidates(_) => {
            StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
        }
        ProviderOrderFilterError::CostBudgetExceeded
        | ProviderOrderFilterError::NoMatchingRegion(_)
        | ProviderOrderFilterError::NoMatchingQuantization
        | ProviderOrderFilterError::NoContextWindowCapacity { .. }
        | ProviderOrderFilterError::ModelGroupChainEmpty(_)
        | ProviderOrderFilterError::AutoRoutingNoEligibleProvider
        | ProviderOrderFilterError::UsageAuthorizationDeniedAllCandidates => StatusCode::FORBIDDEN,
    }
}

pub(crate) fn build_provider_order_filter_buffered_response(
    error: &ProviderOrderFilterError,
) -> crate::gateway::cache::BufferedUpstreamResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    crate::gateway::cache::BufferedUpstreamResponse::new(
        provider_order_filter_status(error),
        headers,
        build_provider_order_filter_body(error),
        false,
    )
}

pub(crate) fn build_provider_order_filter_streaming_response(
    error: &ProviderOrderFilterError,
) -> PreparedStreamingResponse {
    prepared_streaming_json_response(
        provider_order_filter_status(error),
        build_provider_order_filter_body(error),
        HeaderValue::from_static("application/json"),
    )
}

pub(crate) fn build_no_accepted_candidate_body() -> Bytes {
    Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "error": {
                "message": "no policy-accepted provider candidate could serve this request",
                "type": "provider_unavailable",
                "code": "provider_candidates_exhausted"
            }
        }))
        .unwrap_or_default(),
    )
}

/// Terminal outcome when the accepted provider order was exhausted without any
/// candidate producing a response worth returning.
///
/// The accepted order is authoritative. `state.upstream_base` is not part of it
/// and is not subject to the context, model-group, price, usage-authorization,
/// region, quantization, or cost controls that produced it, so exhaustion must
/// terminate here rather than re-dispatch through the raw default upstream.
pub(crate) fn build_no_accepted_candidate_buffered_response(
) -> crate::gateway::cache::BufferedUpstreamResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    crate::gateway::cache::BufferedUpstreamResponse::new(
        StatusCode::SERVICE_UNAVAILABLE,
        headers,
        build_no_accepted_candidate_body(),
        false,
    )
}

pub(crate) fn build_no_accepted_candidate_streaming_response() -> PreparedStreamingResponse {
    prepared_streaming_json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        build_no_accepted_candidate_body(),
        HeaderValue::from_static("application/json"),
    )
}

/// Bounded, non-secret classification of a provider transport failure.
///
/// Only the kind is retained across the accepted-candidate loop. Upstream URLs,
/// credentials, and raw `reqwest` error text never reach the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportFailureKind {
    Timeout,
    Unreachable,
}

pub(crate) fn classify_transport_failure(error: &reqwest::Error) -> TransportFailureKind {
    if error.is_timeout() {
        TransportFailureKind::Timeout
    } else {
        TransportFailureKind::Unreachable
    }
}

/// Mirrors the status the streaming callers already return for an unreachable
/// upstream: `504` on timeout, `503` otherwise.
pub(crate) fn transport_failure_status(kind: TransportFailureKind) -> StatusCode {
    match kind {
        TransportFailureKind::Timeout => StatusCode::GATEWAY_TIMEOUT,
        TransportFailureKind::Unreachable => StatusCode::SERVICE_UNAVAILABLE,
    }
}

pub(crate) fn build_transport_failure_body(kind: TransportFailureKind) -> Bytes {
    let message = match kind {
        TransportFailureKind::Timeout => "every policy-accepted provider candidate timed out",
        TransportFailureKind::Unreachable => {
            "every policy-accepted provider candidate was unreachable"
        }
    };
    Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "error": {
                "message": message,
                "type": "provider_transport_error",
                "code": "provider_candidates_exhausted"
            }
        }))
        .unwrap_or_default(),
    )
}

pub(crate) fn build_transport_failure_streaming_response(
    kind: TransportFailureKind,
) -> PreparedStreamingResponse {
    prepared_streaming_json_response(
        transport_failure_status(kind),
        build_transport_failure_body(kind),
        HeaderValue::from_static("application/json"),
    )
}

pub(crate) fn is_provider_transport_exhaustion_response(status: StatusCode, body: &Bytes) -> bool {
    if !matches!(
        status,
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    ) {
        return false;
    }

    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };

    payload
        .pointer("/error/code")
        .and_then(|value| value.as_str())
        == Some("provider_candidates_exhausted")
        && payload
            .pointer("/error/type")
            .and_then(|value| value.as_str())
            == Some("provider_transport_error")
}

/// Sends a buffered request through the policy-accepted provider order.
///
/// 1. Resolves the accepted candidate set from the provider registry.
/// 2. Tries each accepted candidate in order, falling back on classified retriable errors and trigger responses.
/// 3. Records per-provider latency metrics.
/// 4. Returns the first servable response, or a terminal outcome derived from the accepted candidates themselves.
///
/// When no `provider_registry` is configured this returns a `503` instead of
/// dispatching anywhere. Once a non-empty registry is present the accepted
/// order is authoritative and exhausting it never re-dispatches through the raw
/// default upstream.
pub(crate) async fn send_with_provider_fallback(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    path: &str,
    body: Bytes,
    request_id: &str,
    traceparent: &str,
    cache_key: Option<&str>,
    correlation: &TraceCorrelation,
    request_telemetry_hints: &RequestTelemetryHints,
    session_context: Option<&crate::gateway::session::GatewaySessionContext>,
) -> (
    Result<crate::gateway::cache::BufferedUpstreamResponse, reqwest::Error>,
    Option<String>, // provider_id that served the response
) {
    let registry = match &state.provider_registry {
        Some(r) if !r.targets.is_empty() => r,
        _ => {
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            let body_bytes = serde_json::to_vec(&serde_json::json!({
                "error": missing_provider_registry_message(state.connected_mode)
            }))
            .unwrap_or_default();
            return (
                Ok(crate::gateway::cache::BufferedUpstreamResponse::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    resp_headers,
                    Bytes::from(body_bytes),
                    false,
                )),
                None,
            );
        }
    };

    let pins = extract_provider_request_pins(headers);
    let effective_ordered =
        match resolve_initial_provider_order(registry, state, request_id, &pins, false) {
            Ok(ordered) => ordered,
            Err(ProviderOrderSelectionError::UnknownProviderPin(pin)) => {
                return (Ok(build_unknown_provider_pin_buffered_response(&pin)), None);
            }
            Err(ProviderOrderSelectionError::NoCompliantProvider) => {
                return (Ok(build_no_compliant_provider_buffered_response()), None);
            }
        };
    let provider_pin = pins.provider;
    let model_pin = pins.model;

    let fallback_triggers = &registry.fallback.triggers;
    let mut last_error: Option<reqwest::Error> = None;
    // Tracks the most-recent response that matched a fallback trigger. When all
    // providers are exhausted by response-based triggers (not network errors) this
    // response is returned to the caller so the real policy/block signal is
    // preserved instead of falling through to the default upstream and surfacing a
    // misleading status (e.g. 401 from an unauthenticated default-upstream call).
    let mut last_trigger_response: Option<crate::gateway::cache::BufferedUpstreamResponse> = None;
    let mut last_inactive_response: Option<crate::gateway::cache::BufferedUpstreamResponse> = None;
    // Tracks the most-recent zero-completion response. Zero-completion insurance
    // moves to the next accepted candidate, so when every accepted candidate
    // returns a zero completion this response is what the caller receives: the
    // real provider status, headers, and body are preserved instead of leaving
    // the accepted order to dispatch through the raw default upstream.
    let mut last_zero_completion_response: Option<crate::gateway::cache::BufferedUpstreamResponse> =
        None;
    // Tracks providers that already received one auth-error retry so we don't
    // loop infinitely on a permanently-revoked credential.
    let mut auth_retried_providers: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    // Parse the request body so we can modify messages per provider.
    let base_body: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            // Unparseable body — fall through to default upstream.
            let result = send_upstream_request(
                state,
                headers,
                path,
                body,
                request_id,
                traceparent,
                cache_key,
                correlation,
                request_telemetry_hints,
            )
            .await;
            return (result, None);
        }
    };

    if let Some(model_name) = base_body.get("model").and_then(|model| model.as_str()) {
        if let Some(pipeline) = registry.resolve_pipeline(model_name) {
            if provider_pin.is_some() || model_pin.is_some() {
                return (
                    Ok(build_pipeline_error_response(
                        StatusCode::BAD_REQUEST,
                        format!(
                            "provider pipeline model '{}' cannot be combined with X-Verdictan-Provider or X-Verdictan-Model pinning",
                            model_name
                        ),
                        "invalid_pipeline_request",
                        "pipeline_pinning_unsupported",
                    )),
                    None,
                );
            }

            return execute_provider_pipeline(
                state,
                headers,
                path,
                &base_body,
                request_id,
                traceparent,
                correlation,
                request_telemetry_hints,
                session_context,
                pipeline,
            )
            .await;
        }
    }

    let effective_ordered = match resolve_prefiltered_provider_order(
        registry,
        state,
        &effective_ordered,
        &base_body,
        request_id,
        false,
    ) {
        Ok(ordered) => ordered,
        Err(error) => {
            return (
                Ok(build_provider_order_filter_buffered_response(&error)),
                None,
            )
        }
    };

    let provider_dispatch_plan = match resolve_provider_dispatch_plan(
        registry,
        state,
        path,
        headers,
        &base_body,
        &effective_ordered,
        request_id,
        model_pin.as_deref(),
        false,
    )
    .await
    {
        Ok(plan) => plan,
        Err(ProviderDispatchPreparationError::Budget(rejection)) => {
            return (Ok(build_budget_filter_buffered_response(&rejection)), None);
        }
        Err(ProviderDispatchPreparationError::RuntimeCapability(error)) => {
            return (
                Ok(build_runtime_capability_buffered_response(
                    &error, request_id,
                )),
                None,
            );
        }
        Err(ProviderDispatchPreparationError::RuntimeRouting(error)) => {
            let response = runtime_routing_error_response(&error, request_id, traceparent);
            let buffered = crate::gateway::cache::BufferedUpstreamResponse::new(
                response.status(),
                response.headers().clone(),
                axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap_or_default(),
                false,
            );
            return (Ok(buffered), None);
        }
        Err(ProviderDispatchPreparationError::ModelRouting(failure)) => {
            return (
                Ok(build_model_routing_failure_buffered_response(&failure)),
                None,
            );
        }
    };
    let effective_ordered = provider_dispatch_plan.effective_ordered;
    let requested_route_model_selection = provider_dispatch_plan.requested_route_model_selection;
    let requested_model = requested_route_model_selection.requested_model.as_str();
    let requested_route_model = requested_route_model_selection
        .requested_route_model
        .as_str();
    let requested_route_model_uses_group =
        requested_route_model_selection.requested_route_model_uses_group;

    for &idx in &effective_ordered {
        let target = &registry.targets[idx];
        if !requested_route_model_uses_group
            && !requested_route_model.trim().is_empty()
            && !target_supports_model(target, requested_route_model)
        {
            tracing::debug!(
                request_id = %request_id,
                provider_id = %target.id,
                requested_model = %requested_route_model,
                "provider target skipped because it does not support the requested model"
            );
            continue;
        }
        let target = match prepare_connected_provider_target(state, target, requested_model).await {
            Ok(ConnectedTargetResolution::Ready(target)) => target,
            Ok(ConnectedTargetResolution::Inactive {
                status,
                message,
                status_reason,
            }) => {
                tracing::warn!(
                    request_id = %request_id,
                    provider_id = %target.id,
                    status_reason = %status_reason,
                    "provider target inactive during runtime preparation"
                );
                last_inactive_response = Some(build_access_inactive_buffered_response(
                    status,
                    &message,
                    &status_reason,
                ));
                continue;
            }
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    provider_id = %target.id,
                    error = %error,
                    "connected access provider preflight failed closed"
                );
                return (
                    Ok(build_access_inactive_buffered_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Connected access preflight failed",
                        "access_preflight_failed",
                    )),
                    None,
                );
            }
        };
        let provider_start = Instant::now();

        // Circuit breaker check
        if let Some(ref cb_manager) = registry.circuit_breaker_manager {
            if !cb_manager.is_allowed(&target.id) {
                tracing::debug!(
                    request_id = %request_id,
                    provider_id = %target.id,
                    "circuit breaker: provider is open, skipping"
                );
                continue;
            }
        }

        if let Some(execution_target) = &target.execution_target {
            let resp = crate::gateway::execution_runtime::execute_target(
                execution_target,
                &target.id,
                path,
                &body,
                request_id,
            )
            .await;
            let elapsed = provider_start.elapsed();
            let trigger = crate::gateway::providers::classify_upstream_error(
                Some(resp.status().as_u16()),
                resp.body(),
                false,
            );
            if let Some(trigger) = trigger {
                if fallback_triggers.contains(&trigger) {
                    tracing::warn!(
                        request_id = %request_id,
                        provider_id = %target.id,
                        trigger = ?trigger,
                        status = resp.status().as_u16(),
                        execution_target = %execution_target.kind_label(),
                        "execution target error matches fallback trigger, trying next"
                    );
                    if let Some(ref cb_manager) = registry.circuit_breaker_manager {
                        cb_manager.record_failure(&target.id);
                    }
                    last_trigger_response = Some(resp);
                    continue;
                }
            }

            let total_tokens = serde_json::from_slice::<serde_json::Value>(resp.body())
                .ok()
                .and_then(|value| value.pointer("/usage/total_tokens")?.as_u64())
                .unwrap_or(0) as u32;
            state
                .provider_metrics
                .record(&target.id, elapsed, total_tokens, elapsed);
            if let Some(ref cb_manager) = registry.circuit_breaker_manager {
                cb_manager.record_success(&target.id);
            }
            return (Ok(resp), Some(target.id.clone()));
        }

        // --- Context compression for this provider ---
        let mut provider_body = base_body.clone();
        if let Some(max_tokens) = target.max_context_tokens {
            if let Some(messages) = provider_body.get("messages").and_then(|m| m.as_array()) {
                if let Some(compressed) = crate::gateway::context_compression::compress_messages(
                    messages,
                    max_tokens,
                    crate::gateway::context_compression::Strategy::MiddleOut,
                ) {
                    provider_body["messages"] = serde_json::Value::Array(compressed);
                    tracing::debug!(
                        request_id = %request_id,
                        provider_id = %target.id,
                        max_tokens = max_tokens,
                        "compressed context for provider"
                    );
                }
            }
        }

        // Normalize provider-prefixed request models (e.g. openai/gpt-5.4-mini)
        // to the canonical catalog model before upstream dispatch.
        let (provider_request_model, effective_target_model) =
            resolve_target_request_model(&target, requested_model, model_pin.as_deref());
        if let Some(ref model_name) = provider_request_model {
            provider_body["model"] = serde_json::Value::String(model_name.clone());
        }
        strip_runtime_contract_fields(&mut provider_body);

        // --- Resolve provider path ---
        let provider_path =
            resolve_provider_path_for_request(&target, path, &effective_target_model);

        if crate::gateway::provider_pipeline::uses_exact_provider_pipeline(&target.provider) {
            let mut exact_request_body = provider_body.clone();
            apply_target_model_request_parameter_metadata(
                &target,
                &provider_body,
                &mut exact_request_body,
                requested_model,
                model_pin.as_deref(),
                Some(&state.catalog_snapshot),
            );
            let prepared = match crate::gateway::provider_pipeline::prepare_provider_request(
                &target,
                path,
                &provider_path,
                &effective_target_model,
                &exact_request_body,
                headers,
            )
            .await
            {
                Ok(prepared) => prepared,
                Err(error) => return (Ok(error.to_buffered_response()), Some(target.id.clone())),
            };

            let provider_state = ActiveGatewayStateView {
                gateway_id: state.gateway_id.clone(),
                upstream_base: &prepared.base_url,
                upstream_auth: &prepared.upstream_auth,
                fail_mode: state.fail_mode,
                client: state.client,
                event_sink: state.event_sink,
                agent_context_service: state.agent_context_service.clone(),
                task_novelty_service: state.task_novelty_service.clone(),
                history_service: state.history_service.clone(),
                hosted_gateway_local_access: state.hosted_gateway_local_access.clone(),
                config_name: state.config_name.clone(),
                config_sha256: state.config_sha256.clone(),
                config_version: state.config_version.clone(),
                policy_chain: state.policy_chain.clone(),
                chain_entries: state.chain_entries.clone(),
                policy_blocks: state.policy_blocks.clone(),
                route_config: state.route_config.clone(),
                models_endpoint: state.models_endpoint.clone(),
                moderation: state.moderation.clone(),
                rate_limiter: state.rate_limiter,
                provider_cache: state.provider_cache,
                provider_registry: state.provider_registry.clone(),
                catalog_snapshot: state.catalog_snapshot.clone(),
                provider_metrics: state.provider_metrics,
                global_rate_limiter: state.global_rate_limiter.clone(),
                ip_rate_limiter: state.ip_rate_limiter.clone(),
                token_rate_limiter: state.token_rate_limiter.clone(),
                user_rate_limiter: state.user_rate_limiter.clone(),
                size_limit: state.size_limit.clone(),
                consumer_groups: state.consumer_groups.clone(),
                provider_extra_headers: prepared.provider_extra_headers,
                semantic_cache: state.semantic_cache.clone(),
                workflow_cache: state.workflow_cache.clone(),
                ip_allowlist: state.ip_allowlist.clone(),
                ip_allowlist_trusted_proxies: state.ip_allowlist_trusted_proxies.clone(),
                region_key: state.region_key.clone(),
                connected_mode: state.connected_mode,
                managed_public_endpoint_host: state.managed_public_endpoint_host.clone(),
                requested_region_group: state.requested_region_group.clone(),
                current_publication: state.current_publication.clone(),
                runtime_routing_settings: state.runtime_routing_settings.clone(),
                runtime_cache_ttl_override: state.runtime_cache_ttl_override,
                runtime_allow_fallbacks: state.runtime_allow_fallbacks,
                runtime_privacy_restricted: state.runtime_privacy_restricted,
                shadow_routing: state.shadow_routing.clone(),
                auto_provider: state.auto_provider.clone(),
                history_config: state.history_config.clone(),
                gateway_context_fabric: state.gateway_context_fabric.clone(),
                mcp_server_config: state.mcp_server_config.clone(),
                agent_declarations: state.agent_declarations.clone(),
                silent_engine: state.silent_engine.clone(),
                agents_runtime: state.agents_runtime.clone(),
                request_timeout: Some(target.effective_timeout(false)),
                stream_response_adapter: None,
                allow_insecure_tls: target.allow_insecure_tls,
                current_target_id: state.current_target_id.clone(),
                current_agent_id: state.current_agent_id.clone(),
                ua_pinned_target_id: state.ua_pinned_target_id.clone(),
                ua_eval_document: state.ua_eval_document.clone(),
                ua_authorization_id: state.ua_authorization_id.clone(),
                ua_dispatch_acquired: state.ua_dispatch_acquired,
                ua_denied_target_ids: state.ua_denied_target_ids.clone(),
                api_token_present: state.api_token_present,
                request_finops: state.request_finops.clone(),
                distributed_state: state.distributed_state,
                distributed_rl_params: state.distributed_rl_params,
                session_id: state.session_id.clone(),
                configuration_id: state.configuration_id.clone(),
                configuration_version_id: state.configuration_version_id.clone(),
                token_validation_cache: state.token_validation_cache,
                gateway_runtime_metrics: state.gateway_runtime_metrics,
                rollout_grade: state.rollout_grade,
                rollout_grade_required: state.rollout_grade_required,
                key_rate_limiter: state.key_rate_limiter,
                key_request_tracker: state.key_request_tracker,
                key_budget_tracker: state.key_budget_tracker,
            };

            state.provider_metrics.increment_active(&target.id);
            crate::gateway::provider_pipeline::record_upstream_attempt();
            let result = send_upstream_request(
                &provider_state,
                headers,
                &prepared.path,
                prepared.body,
                request_id,
                traceparent,
                cache_key,
                correlation,
                request_telemetry_hints,
            )
            .await;
            state.provider_metrics.decrement_active(&target.id);

            match result {
                Ok(resp) => {
                    let elapsed = provider_start.elapsed();
                    let resp = if resp.status().is_success() {
                        let resp =
                            match crate::gateway::provider_pipeline::normalize_buffered_provider_response(
                                &target.provider,
                                target.execution_target.as_ref(),
                                resp,
                            ) {
                                Ok(resp) => resp,
                                Err(error) => {
                                    return (
                                        Ok(error.to_buffered_response()),
                                        Some(target.id.clone()),
                                    )
                                }
                            };
                        match crate::gateway::provider_pipeline::translate_provider_response(
                            &target.provider,
                            path,
                            request_id,
                            crate::gateway::provider_pipeline::ProviderPipelineResponse::Buffered(resp),
                        ) {
                            Ok(crate::gateway::provider_pipeline::ProviderPipelineResponse::Buffered(
                                resp,
                            )) => resp,
                            Ok(_) => unreachable!(),
                            Err(error) => {
                                return (Ok(error.to_buffered_response()), Some(target.id.clone()))
                            }
                        }
                    } else {
                        crate::gateway::provider_pipeline::sanitize_upstream_buffered_error(
                            resp.status(),
                        )
                    };
                    let resp = if resp.status().is_success()
                        && !success_shape_valid_for_path(path, resp.body())
                    {
                        invalid_success_shape_buffered_response(path)
                    } else {
                        resp
                    };

                    let total_tokens = serde_json::from_slice::<serde_json::Value>(resp.body())
                        .ok()
                        .and_then(|v| v.pointer("/usage/total_tokens")?.as_u64())
                        .unwrap_or(0) as u32;

                    state
                        .provider_metrics
                        .record(&target.id, elapsed, total_tokens, elapsed);
                    if let Some(ref cb_manager) = registry.circuit_breaker_manager {
                        cb_manager.record_success(&target.id);
                    }
                    maybe_spawn_shadow_evaluation(
                        state,
                        registry,
                        &effective_ordered,
                        headers,
                        path,
                        &base_body,
                        &target.id,
                        request_id,
                        traceparent,
                    );

                    return (Ok(resp), Some(target.id.clone()));
                }
                Err(error) => {
                    if let Some(ref cb_manager) = registry.circuit_breaker_manager {
                        cb_manager.record_failure(&target.id);
                    }
                    return (Err(error), Some(target.id.clone()));
                }
            }
        }

        // --- Phase 15: request format translation ---
        let client_format =
            crate::gateway::format_translation::route_native_format(path, &base_body);
        let target_format = resolved_target_format(&target);
        let mut provider_request_body = if target_format != client_format {
            crate::gateway::format_translation::translate_request(
                provider_body.clone(),
                client_format,
                target_format,
            )
            .unwrap_or_else(|_| provider_body.clone())
        } else {
            provider_body.clone()
        };
        apply_target_model_request_parameter_metadata(
            &target,
            &provider_body,
            &mut provider_request_body,
            requested_model,
            model_pin.as_deref(),
            Some(&state.catalog_snapshot),
        );
        let provider_bytes = serde_json::to_vec(&provider_request_body)
            .map(Bytes::from)
            .unwrap_or_else(|_| body.clone());
        let runtime_request_config = serde_json::json!({
            "provider": target.provider,
            "model": effective_target_model,
            "base_url": target.base_url,
            "path_template": target.path_template,
            "mcp": target.mcp_bridge,
            "anthropic_version": target
                .anthropic_version
                .as_deref()
                .unwrap_or("2023-06-01"),
        });
        let provider_bytes = match serde_json::from_slice::<serde_json::Value>(&provider_bytes) {
            Ok(value) => {
                let is_mcp =
                    crate::gateway::provider_catalog::normalized_provider_alias(&target.provider)
                        == "mcp";
                let build_result = if is_mcp {
                    let meta = build_mcp_session_meta(session_context);
                    crate::gateway::runtimes::network::mcp::MCP_RUNTIME.build_request_with_session(
                        &runtime_request_config,
                        &value,
                        meta.as_ref(),
                    )
                } else {
                    crate::gateway::runtimes::build_runtime_request(
                        &target.provider,
                        target.execution_target.as_ref(),
                        &runtime_request_config,
                        &value,
                    )
                };
                match build_result {
                    Ok(value) => serde_json::to_vec(&value)
                        .ok()
                        .map(Bytes::from)
                        .unwrap_or(provider_bytes),
                    Err(error) if is_mcp => {
                        tracing::warn!(
                            request_id = %request_id,
                            provider_id = %target.id,
                            error = %error,
                            "mcp bridge rejected request before upstream dispatch"
                        );
                        let body_json = serde_json::json!({
                            "error": {
                                "message": error.to_string(),
                                "type": "invalid_request_error",
                                "code": "mcp_bridge_invalid_request"
                            }
                        });
                        let body_bytes = serde_json::to_vec(&body_json).unwrap_or_default();
                        let mut resp_headers = HeaderMap::new();
                        resp_headers.insert(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/json"),
                        );
                        return (
                            Ok(crate::gateway::cache::BufferedUpstreamResponse::new(
                                StatusCode::BAD_REQUEST,
                                resp_headers,
                                Bytes::from(body_bytes),
                                false,
                            )),
                            Some(target.id.clone()),
                        );
                    }
                    Err(_) => provider_bytes,
                }
            }
            Err(_) => provider_bytes,
        };

        // --- Phase 35: provider-native auth + endpoint override ---
        let phase35_auth = match crate::gateway::provider_auth::build_provider_auth(
            &target,
            &effective_target_model,
            &provider_path,
            &provider_bytes,
            false,
        )
        .await
        {
            Ok(auth) => auth,
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    provider_id = %target.id,
                    error = %error,
                    "provider auth resolution failed before upstream dispatch"
                );
                return (
                    Ok(build_provider_auth_buffered_response(&error.to_string())),
                    Some(target.id.clone()),
                );
            }
        };
        let resolved_base = phase35_auth
            .base_url_override
            .as_deref()
            .unwrap_or(target.base_url.as_str());
        let effective_path = phase35_auth
            .endpoint_override
            .clone()
            .unwrap_or_else(|| provider_path.clone());
        let mut phase35_extra_headers: Vec<(
            reqwest::header::HeaderName,
            reqwest::header::HeaderValue,
        )> = phase35_auth
            .extra_headers
            .iter()
            .filter_map(|(n, v)| {
                let hn = reqwest::header::HeaderName::from_bytes(n.as_bytes()).ok()?;
                let hv = reqwest::header::HeaderValue::from_str(v).ok()?;
                Some((hn, hv))
            })
            .collect();
        if crate::gateway::provider_catalog::normalized_provider_alias(&target.provider)
            == "anthropic"
        {
            let beta_headers = requested_anthropic_beta_headers(path, headers, &provider_body);
            if !beta_headers.is_empty() {
                merge_provider_extra_header(
                    &mut phase35_extra_headers,
                    "anthropic-beta",
                    &beta_headers.join(","),
                );
            }
        }
        if let Some((name, value)) = &state.upstream_auth {
            phase35_extra_headers.push((name.clone(), value.clone()));
        }

        // --- Build a temporary state view for this provider ---
        let provider_auth = match crate::gateway::providers::resolve_provider_auth(&target).await {
            Ok(auth) => auth,
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    provider_id = %target.id,
                    error = %error,
                    "provider auth header resolution failed before upstream dispatch"
                );
                return (
                    Ok(build_provider_auth_buffered_response(&error.to_string())),
                    Some(target.id.clone()),
                );
            }
        };
        let provider_base = resolved_base;

        // We create a modified state view pointing at this provider.
        let provider_state = ActiveGatewayStateView {
            gateway_id: state.gateway_id.clone(),
            upstream_base: provider_base,
            upstream_auth: &provider_auth,
            fail_mode: state.fail_mode,
            client: state.client,
            event_sink: state.event_sink,
            agent_context_service: state.agent_context_service.clone(),
            task_novelty_service: state.task_novelty_service.clone(),
            history_service: state.history_service.clone(),
            hosted_gateway_local_access: state.hosted_gateway_local_access.clone(),
            config_name: state.config_name.clone(),
            config_sha256: state.config_sha256.clone(),
            config_version: state.config_version.clone(),
            policy_chain: state.policy_chain.clone(),
            chain_entries: state.chain_entries.clone(),
            policy_blocks: state.policy_blocks.clone(),
            route_config: state.route_config.clone(),
            models_endpoint: state.models_endpoint.clone(),
            moderation: state.moderation.clone(),
            rate_limiter: state.rate_limiter,
            provider_cache: state.provider_cache,
            provider_registry: state.provider_registry.clone(),
            catalog_snapshot: state.catalog_snapshot.clone(),
            provider_metrics: state.provider_metrics,
            global_rate_limiter: state.global_rate_limiter.clone(),
            ip_rate_limiter: state.ip_rate_limiter.clone(),
            token_rate_limiter: state.token_rate_limiter.clone(),
            user_rate_limiter: state.user_rate_limiter.clone(),
            size_limit: state.size_limit.clone(),
            consumer_groups: state.consumer_groups.clone(),
            provider_extra_headers: phase35_extra_headers,
            semantic_cache: state.semantic_cache.clone(),
            workflow_cache: state.workflow_cache.clone(),
            ip_allowlist: state.ip_allowlist.clone(),
            ip_allowlist_trusted_proxies: state.ip_allowlist_trusted_proxies.clone(),
            region_key: state.region_key.clone(),
            connected_mode: state.connected_mode,
            managed_public_endpoint_host: state.managed_public_endpoint_host.clone(),
            requested_region_group: state.requested_region_group.clone(),
            current_publication: state.current_publication.clone(),
            runtime_routing_settings: state.runtime_routing_settings.clone(),
            runtime_cache_ttl_override: state.runtime_cache_ttl_override,
            runtime_allow_fallbacks: state.runtime_allow_fallbacks,
            runtime_privacy_restricted: state.runtime_privacy_restricted,
            shadow_routing: state.shadow_routing.clone(),
            auto_provider: state.auto_provider.clone(),
            history_config: state.history_config.clone(),
            gateway_context_fabric: state.gateway_context_fabric.clone(),
            mcp_server_config: state.mcp_server_config.clone(),
            agent_declarations: state.agent_declarations.clone(),
            silent_engine: state.silent_engine.clone(),
            agents_runtime: state.agents_runtime.clone(),
            request_timeout: Some(target.effective_timeout(false)),
            stream_response_adapter: None,
            allow_insecure_tls: target.allow_insecure_tls,
            current_target_id: state.current_target_id.clone(),
            current_agent_id: state.current_agent_id.clone(),
            ua_pinned_target_id: state.ua_pinned_target_id.clone(),
            ua_eval_document: state.ua_eval_document.clone(),
            ua_authorization_id: state.ua_authorization_id.clone(),
            ua_dispatch_acquired: state.ua_dispatch_acquired,
            ua_denied_target_ids: state.ua_denied_target_ids.clone(),
            api_token_present: state.api_token_present,
            request_finops: state.request_finops.clone(),
            distributed_state: state.distributed_state,
            distributed_rl_params: state.distributed_rl_params,
            session_id: state.session_id.clone(),
            configuration_id: state.configuration_id.clone(),
            configuration_version_id: state.configuration_version_id.clone(),
            token_validation_cache: state.token_validation_cache,
            gateway_runtime_metrics: state.gateway_runtime_metrics,
            rollout_grade: state.rollout_grade,
            rollout_grade_required: state.rollout_grade_required,
            key_rate_limiter: state.key_rate_limiter,
            key_request_tracker: state.key_request_tracker,
            key_budget_tracker: state.key_budget_tracker,
        };

        state.provider_metrics.increment_active(&target.id);
        let result = send_upstream_request(
            &provider_state,
            headers,
            &effective_path,
            provider_bytes,
            request_id,
            traceparent,
            cache_key,
            correlation,
            request_telemetry_hints,
        )
        .await;
        state.provider_metrics.decrement_active(&target.id);

        match result {
            Ok(resp) => {
                let elapsed = provider_start.elapsed();

                let resp = if resp.status().is_success() {
                    translate_buffered_runtime_response(
                        resp,
                        &target.provider,
                        target.execution_target.as_ref(),
                    )
                } else {
                    resp
                };

                let resp = if resp.status().is_success()
                    && target_format == client_format
                    && !success_shape_valid_for_path(&effective_path, resp.body())
                {
                    invalid_success_shape_buffered_response(&effective_path)
                } else {
                    resp
                };

                // Phase 15: back-translate provider response to client wire format.
                let resp = if target_format != client_format && resp.status().is_success() {
                    translate_buffered_response_format(resp, target_format, client_format, path)
                } else {
                    resp
                };
                let resp = if resp.status().is_success()
                    && !success_shape_valid_for_path(path, resp.body())
                {
                    invalid_success_shape_buffered_response(path)
                } else {
                    resp
                };

                // Check for zero-completion insurance.
                if path == "/v1/chat/completions" && registry.zero_completion_insurance.enabled {
                    if let Ok(body_val) = serde_json::from_slice::<serde_json::Value>(resp.body()) {
                        if let crate::gateway::zero_completion::ZeroCompletionResult::ZeroCompletion {
                            finish_reason,
                        } = crate::gateway::zero_completion::check_response(&body_val)
                        {
                            tracing::warn!(
                                request_id = %request_id,
                                provider_id = %target.id,
                                finish_reason = %finish_reason,
                                "zero-completion detected, trying next provider"
                            );
                            last_zero_completion_response = Some(resp);
                            continue;
                        }
                    }
                }

                // Classify the response for fallback triggers.
                let trigger = crate::gateway::providers::classify_upstream_error(
                    Some(resp.status().as_u16()),
                    resp.body(),
                    false,
                );

                // Credential rotation safety: on upstream auth error (401/403),
                // invalidate access preflight caches so the
                // next attempt fetches fresh credentials. This gives at most one
                // failed request per rotation event.
                if crate::gateway::providers::is_upstream_auth_error(
                    resp.status().as_u16(),
                    resp.body(),
                ) && !auth_retried_providers.contains(&target.id)
                {
                    auth_retried_providers.insert(target.id.clone());
                    if let Some(ref sink) = state.event_sink {
                        let org_id = state
                            .request_finops
                            .as_ref()
                            .and_then(|f| f.org_id.as_deref())
                            .unwrap_or("");
                        let provider_norm =
                            crate::gateway::provider_catalog::normalized_provider_alias(
                                &target.provider,
                            );
                        let preflight_key = PreflightCacheKey {
                            org_id: org_id.to_owned(),
                            provider: provider_norm,
                            model: target.model.clone(),
                        };
                        sink.access_preflight_cache.remove(&preflight_key);
                        tracing::warn!(
                            request_id = %request_id,
                            provider_id = %target.id,
                            status = resp.status().as_u16(),
                            "upstream auth error: invalidated preflight cache, \
                             will retry with fresh credentials on next fallback attempt"
                        );
                    }
                    if let Some(ref cb_manager) = registry.circuit_breaker_manager {
                        cb_manager.record_failure(&target.id);
                    }
                    last_trigger_response = Some(resp);
                    continue;
                }

                if let Some(trigger) = trigger {
                    if fallback_triggers.contains(&trigger) {
                        tracing::warn!(
                            request_id = %request_id,
                            provider_id = %target.id,
                            trigger = ?trigger,
                            status = resp.status().as_u16(),
                            "provider error matches fallback trigger, trying next"
                        );
                        if let Some(ref cb_manager) = registry.circuit_breaker_manager {
                            cb_manager.record_failure(&target.id);
                        }
                        last_trigger_response = Some(resp);
                        continue;
                    }
                }
                // Success — record metrics and return.
                let total_tokens = serde_json::from_slice::<serde_json::Value>(resp.body())
                    .ok()
                    .and_then(|v| v.pointer("/usage/total_tokens")?.as_u64())
                    .unwrap_or(0) as u32;

                state
                    .provider_metrics
                    .record(&target.id, elapsed, total_tokens, elapsed);
                if let Some(ref cb_manager) = registry.circuit_breaker_manager {
                    cb_manager.record_success(&target.id);
                }
                maybe_spawn_shadow_evaluation(
                    state,
                    registry,
                    &effective_ordered,
                    headers,
                    path,
                    &base_body,
                    &target.id,
                    request_id,
                    traceparent,
                );

                return (Ok(resp), Some(target.id.clone()));
            }
            Err(e) => {
                tracing::warn!(
                    request_id = %request_id,
                    provider_id = %target.id,
                    error = %e,
                    "provider request failed, trying next"
                );
                if let Some(ref cb_manager) = registry.circuit_breaker_manager {
                    cb_manager.record_failure(&target.id);
                }
                last_error = Some(e);
            }
        }
    }

    // The accepted provider order is exhausted. Every outcome below is derived
    // from an accepted candidate; the raw default upstream is never dispatched
    // here because it is not part of the accepted set. Resolution priority:
    //   1. Network error on the last attempt → propagate the reqwest::Error.
    //   2. A provider target was inactive → return that inactive access signal.
    //   3. Every attempt ended with a fallback-trigger response → return that
    //      response so the caller sees the real signal (e.g. ContentFilter 400).
    //   4. Every attempt returned a zero completion → return the last one so the
    //      caller receives the provider's own response rather than a synthetic
    //      status.
    //   5. No accepted candidate was ever dispatched (all skipped by model
    //      support or by an open circuit breaker) → typed 503.
    if let Some(err) = last_error {
        (Err(err), None)
    } else if let Some(resp) = last_inactive_response {
        (Ok(resp), None)
    } else if let Some(resp) = last_trigger_response {
        tracing::warn!(
            request_id = %request_id,
            status = resp.status().as_u16(),
            "all providers exhausted via response-based fallback triggers; \
             returning last trigger response to caller"
        );
        (Ok(resp), None)
    } else if let Some(resp) = last_zero_completion_response {
        tracing::warn!(
            request_id = %request_id,
            status = resp.status().as_u16(),
            "all accepted providers returned zero completions; \
             returning the last zero-completion response to caller"
        );
        (Ok(resp), None)
    } else {
        tracing::warn!(
            request_id = %request_id,
            "no accepted provider candidate was dispatched; refusing to fall back \
             to the default upstream"
        );
        (Ok(build_no_accepted_candidate_buffered_response()), None)
    }
}
