// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Family request-pipeline module.
//! Child of `gateway::server`; parent private items remain visible.
use super::super::*;
use super::*;

pub(crate) async fn send_streaming_with_provider_fallback(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    path: &str,
    body: Bytes,
    request_id: &str,
    traceparent: &str,
    correlation: &TraceCorrelation,
    request_telemetry_hints: &RequestTelemetryHints,
    session_context: Option<&crate::gateway::session::GatewaySessionContext>,
) -> (
    Result<PreparedStreamingResponse, reqwest::Error>,
    Option<String>,
) {
    let registry = match &state.provider_registry {
        Some(registry) if !registry.targets.is_empty() => registry,
        _ => {
            let body = serde_json::json!({
                "error": missing_provider_registry_message(state.connected_mode)
            });
            let body_bytes = serde_json::to_vec(&body).unwrap_or_default();
            return (
                Ok(prepared_streaming_json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    Bytes::from(body_bytes),
                    HeaderValue::from_static("application/json"),
                )),
                None,
            );
        }
    };

    let pins = extract_provider_request_pins(headers);
    let effective_ordered =
        match resolve_initial_provider_order(registry, state, request_id, &pins, true) {
            Ok(ordered) => ordered,
            Err(ProviderOrderSelectionError::UnknownProviderPin(pin)) => {
                return (
                    Ok(build_unknown_provider_pin_streaming_response(&pin)),
                    None,
                );
            }
            Err(ProviderOrderSelectionError::NoCompliantProvider) => {
                return (Ok(build_no_compliant_provider_streaming_response()), None);
            }
        };
    let provider_pin = pins.provider;
    let model_pin = pins.model;

    let base_body: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            let result = send_streaming_upstream_request(
                state,
                headers,
                path,
                body,
                request_id,
                traceparent,
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
                    Ok(prepared_streaming_json_response(
                        StatusCode::BAD_REQUEST,
                        Bytes::from(
                            serde_json::to_vec(&serde_json::json!({
                                "error": {
                                    "message": format!(
                                        "provider pipeline model '{}' cannot be combined with X-Verdictan-Provider or X-Verdictan-Model pinning",
                                        model_name
                                    ),
                                    "type": "invalid_pipeline_request",
                                    "code": "pipeline_pinning_unsupported"
                                }
                            }))
                            .unwrap_or_else(|_| b"{}".to_vec()),
                        ),
                        HeaderValue::from_static("application/json"),
                    )),
                    None,
                );
            }

            let include_usage = base_body
                .get("stream_options")
                .and_then(|value| value.get("include_usage"))
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            let (buffered_result, provider_id) = execute_provider_pipeline(
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

            return match buffered_result {
                Ok(buffered) if buffered.status().is_success() => {
                    let sse_bytes = match path {
                        "/v1/chat/completions" => crate::gateway::sse::chat_completion_json_to_sse(
                            buffered.body(),
                            include_usage,
                        ),
                        "/v1/responses" => {
                            crate::gateway::sse::responses_json_to_sse(buffered.body())
                        }
                        _ => None,
                    };

                    match sse_bytes {
                        Some(bytes) => (
                            Ok(prepared_streaming_json_response(
                                StatusCode::OK,
                                bytes,
                                HeaderValue::from_static("text/event-stream"),
                            )),
                            provider_id,
                        ),
                        None => (
                            Ok(prepared_streaming_json_response(
                                buffered.status(),
                                buffered.body().clone(),
                                buffered
                                    .headers()
                                    .get(header::CONTENT_TYPE)
                                    .cloned()
                                    .unwrap_or_else(|| {
                                        HeaderValue::from_static("application/json")
                                    }),
                            )),
                            provider_id,
                        ),
                    }
                }
                Ok(buffered) => (
                    Ok(prepared_streaming_json_response(
                        buffered.status(),
                        buffered.body().clone(),
                        buffered
                            .headers()
                            .get(header::CONTENT_TYPE)
                            .cloned()
                            .unwrap_or_else(|| HeaderValue::from_static("application/json")),
                    )),
                    provider_id,
                ),
                Err(error) => (Err(error), provider_id),
            };
        }
    }

    let effective_ordered = match resolve_prefiltered_provider_order(
        registry,
        state,
        &effective_ordered,
        &base_body,
        request_id,
        true,
    ) {
        Ok(ordered) => ordered,
        Err(error) => {
            return (
                Ok(build_provider_order_filter_streaming_response(&error)),
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
        true,
    )
    .await
    {
        Ok(plan) => plan,
        Err(ProviderDispatchPreparationError::Budget(rejection)) => {
            return (Ok(build_budget_filter_streaming_response(&rejection)), None);
        }
        Err(ProviderDispatchPreparationError::RuntimeCapability(error)) => {
            return (
                Ok(build_runtime_capability_streaming_response(
                    &error, request_id,
                )),
                None,
            );
        }
        Err(ProviderDispatchPreparationError::RuntimeRouting(error)) => {
            let response = runtime_routing_error_response(&error, request_id, traceparent);
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap_or_default();
            return (
                Ok(prepared_streaming_json_response(
                    status,
                    body,
                    HeaderValue::from_static("application/json"),
                )),
                None,
            );
        }
        Err(ProviderDispatchPreparationError::ModelRouting(failure)) => {
            return (
                Ok(build_model_routing_failure_streaming_response(&failure)),
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

    // Tracks the most-recent streaming response that matched a fallback trigger.
    // See `send_buffered_with_provider_fallback` for rationale.
    let mut last_trigger_response: Option<PreparedStreamingResponse> = None;
    let mut last_inactive_response: Option<PreparedStreamingResponse> = None;
    // Bounded, non-secret record of the most-recent provider transport failure.
    // Retaining the kind (rather than the reqwest error) keeps upstream URLs and
    // credentials out of the client-visible body while still letting the
    // accepted-order exhaustion return the contract status the streaming callers
    // already use for an unreachable upstream.
    let mut last_transport_failure: Option<TransportFailureKind> = None;
    let mut auth_retried_providers: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    for &index in &effective_ordered {
        let target = &registry.targets[index];
        if !requested_route_model_uses_group
            && !requested_route_model.trim().is_empty()
            && !target_supports_model(target, requested_route_model)
        {
            tracing::debug!(
                request_id = %request_id,
                provider_id = %target.id,
                requested_model = %requested_route_model,
                "provider target skipped because it does not support the requested model (streaming)"
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
                last_inactive_response = Some(build_access_inactive_streaming_response(
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
                    Ok(build_access_inactive_streaming_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Connected access preflight failed",
                        "access_preflight_failed",
                    )),
                    None,
                );
            }
        };

        // Circuit breaker check
        if let Some(ref cb_manager) = registry.circuit_breaker_manager {
            if !cb_manager.is_allowed(&target.id) {
                tracing::debug!(
                    request_id = %request_id,
                    provider_id = %target.id,
                    "circuit breaker: provider is open, skipping (streaming)"
                );
                continue;
            }
        }

        if let Some(execution_target) = &target.execution_target {
            let response = crate::gateway::execution_runtime::execute_target_streaming(
                execution_target,
                &target.id,
                path,
                &body,
                request_id,
            )
            .await;
            return (
                Ok(PreparedStreamingResponse {
                    status: response.status,
                    content_type: response.content_type,
                    body: response.body,
                }),
                Some(target.id.clone()),
            );
        }

        let mut provider_body = base_body.clone();

        if let Some(max_tokens) = target.max_context_tokens {
            if let Some(messages) = provider_body
                .get("messages")
                .and_then(|value| value.as_array())
            {
                if let Some(compressed) = crate::gateway::context_compression::compress_messages(
                    messages,
                    max_tokens,
                    crate::gateway::context_compression::Strategy::MiddleOut,
                ) {
                    provider_body["messages"] = serde_json::Value::Array(compressed);
                }
            }
        }

        let requested_model = base_body
            .get("model")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let (provider_request_model, effective_target_model) =
            resolve_target_request_model(&target, requested_model, model_pin.as_deref());
        if let Some(ref model_name) = provider_request_model {
            provider_body["model"] = serde_json::Value::String(model_name.clone());
        }
        strip_runtime_contract_fields(&mut provider_body);
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
            let prepared = match crate::gateway::provider_pipeline::prepare_provider_stream_request(
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
                Err(error) => return (Ok(error.to_streaming_response()), Some(target.id.clone())),
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
                request_timeout: Some(target.effective_timeout(true)),
                stream_response_adapter: prepared.stream_response_adapter,
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
            let result = send_streaming_upstream_request(
                &provider_state,
                headers,
                &prepared.path,
                prepared.body,
                request_id,
                traceparent,
                correlation,
                request_telemetry_hints,
            )
            .await;
            state.provider_metrics.decrement_active(&target.id);

            match result {
                Ok(response) => {
                    if let Some(ref cb_manager) = registry.circuit_breaker_manager {
                        cb_manager.record_success(&target.id);
                    }
                    let response = if response.status.is_success() {
                        match crate::gateway::provider_pipeline::translate_provider_response(
                            &target.provider,
                            path,
                            request_id,
                            crate::gateway::provider_pipeline::ProviderPipelineResponse::Streaming(response),
                        ) {
                            Ok(crate::gateway::provider_pipeline::ProviderPipelineResponse::Streaming(
                                resp,
                            )) => resp,
                            Ok(_) => unreachable!(),
                            Err(error) => {
                                return (Ok(error.to_streaming_response()), Some(target.id.clone()))
                            }
                        }
                    } else {
                        crate::gateway::provider_pipeline::sanitize_upstream_streaming_error(
                            response.status,
                        )
                    };
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
                    return (Ok(response), Some(target.id.clone()));
                }
                Err(error) => {
                    if let Some(ref cb_manager) = registry.circuit_breaker_manager {
                        cb_manager.record_failure(&target.id);
                    }
                    return (Err(error), Some(target.id.clone()));
                }
            }
        }
        let client_format =
            crate::gateway::format_translation::route_native_format(path, &base_body);
        let target_format = target
            .format
            .unwrap_or(crate::gateway::format_translation::ProviderFormat::OpenAI);
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
                            "mcp bridge rejected streaming request before upstream dispatch"
                        );
                        let body_json = serde_json::json!({
                            "error": {
                                "message": error.to_string(),
                                "type": "invalid_request_error",
                                "code": "mcp_bridge_invalid_request"
                            }
                        });
                        let body_bytes = serde_json::to_vec(&body_json).unwrap_or_default();
                        return (
                            Ok(PreparedStreamingResponse {
                                status: StatusCode::BAD_REQUEST,
                                content_type: HeaderValue::from_static("application/json"),
                                body: stream::once(async move {
                                    Ok::<Bytes, io::Error>(Bytes::from(body_bytes))
                                })
                                .boxed(),
                            }),
                            Some(target.id.clone()),
                        );
                    }
                    Err(_) => provider_bytes,
                }
            }
            Err(_) => provider_bytes,
        };

        // Phase 35: provider-native auth + endpoint override (streaming).
        let phase35_auth = match crate::gateway::provider_auth::build_provider_auth(
            &target,
            &effective_target_model,
            &provider_path,
            &provider_bytes,
            true,
        )
        .await
        {
            Ok(auth) => auth,
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    provider_id = %target.id,
                    error = %error,
                    "provider auth resolution failed before upstream streaming dispatch"
                );
                return (
                    Ok(build_provider_auth_streaming_response(&error.to_string())),
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

        let provider_auth = match crate::gateway::providers::resolve_provider_auth(&target).await {
            Ok(auth) => auth,
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    provider_id = %target.id,
                    error = %error,
                    "provider auth header resolution failed before upstream streaming dispatch"
                );
                return (
                    Ok(build_provider_auth_streaming_response(&error.to_string())),
                    Some(target.id.clone()),
                );
            }
        };
        let provider_state = ActiveGatewayStateView {
            gateway_id: state.gateway_id.clone(),
            upstream_base: resolved_base,
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
            request_timeout: Some(target.effective_timeout(true)),
            stream_response_adapter:
                match crate::gateway::provider_catalog::normalized_provider_alias(&target.provider)
                    .as_str()
                {
                    "ollama" => Some(StreamingResponseAdapter::OllamaChat),
                    _ => None,
                },
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
        let result = send_streaming_upstream_request(
            &provider_state,
            headers,
            &effective_path,
            provider_bytes,
            request_id,
            traceparent,
            correlation,
            request_telemetry_hints,
        )
        .await;
        state.provider_metrics.decrement_active(&target.id);

        match result {
            Ok(response) => {
                let trigger = crate::gateway::providers::classify_upstream_error(
                    Some(response.status.as_u16()),
                    b"",
                    false,
                );

                // Credential rotation safety (streaming): on upstream auth
                // error, invalidate caches and retry with fresh credentials.
                if crate::gateway::providers::is_upstream_auth_error(response.status.as_u16(), b"")
                    && !auth_retried_providers.contains(&target.id)
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
                            status = response.status.as_u16(),
                            "upstream auth error (streaming): invalidated preflight cache, \
                             will retry with fresh credentials on next fallback attempt"
                        );
                    }
                    if let Some(ref cb_manager) = registry.circuit_breaker_manager {
                        cb_manager.record_failure(&target.id);
                    }
                    last_trigger_response = Some(response);
                    continue;
                }

                if let Some(trigger) = trigger {
                    if registry.fallback.triggers.contains(&trigger) {
                        tracing::warn!(
                            request_id = %request_id,
                            provider_id = %target.id,
                            trigger = ?trigger,
                            status = response.status.as_u16(),
                            "provider streaming response matches fallback trigger, trying next"
                        );
                        if let Some(ref cb_manager) = registry.circuit_breaker_manager {
                            cb_manager.record_failure(&target.id);
                        }
                        last_trigger_response = Some(response);
                        continue;
                    }
                }

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
                let response = translate_prepared_streaming_response_format(
                    response,
                    target_format,
                    path,
                    request_id,
                );
                return (Ok(response), Some(target.id.clone()));
            }
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    provider_id = %target.id,
                    error = %error,
                    "provider streaming request failed, trying next"
                );
                if let Some(ref cb_manager) = registry.circuit_breaker_manager {
                    cb_manager.record_failure(&target.id);
                }
                last_transport_failure = Some(classify_transport_failure(&error));
            }
        }
    }

    // The accepted streaming provider order is exhausted. Resolution priority
    // mirrors the buffered path, and like the buffered path every outcome is
    // derived from an accepted candidate: the raw default upstream is never
    // dispatched here because it is not part of the accepted set.
    if let Some(resp) = last_inactive_response {
        return (Ok(resp), None);
    }
    if let Some(resp) = last_trigger_response {
        tracing::warn!(
            request_id = %request_id,
            status = resp.status.as_u16(),
            "all streaming providers exhausted via response-based fallback triggers; \
             returning last trigger response to caller"
        );
        return (Ok(resp), None);
    }
    if let Some(kind) = last_transport_failure {
        tracing::warn!(
            request_id = %request_id,
            failure_kind = ?kind,
            "all accepted streaming providers failed at the transport layer; \
             refusing to fall back to the default upstream"
        );
        return (Ok(build_transport_failure_streaming_response(kind)), None);
    }

    tracing::warn!(
        request_id = %request_id,
        "no accepted streaming provider candidate was dispatched; refusing to fall \
         back to the default upstream"
    );
    (Ok(build_no_accepted_candidate_streaming_response()), None)
}

pub(crate) async fn send_streaming_upstream_request(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    path: &str,
    body: Bytes,
    request_id: &str,
    traceparent: &str,
    correlation: &TraceCorrelation,
    _request_telemetry_hints: &RequestTelemetryHints,
) -> Result<PreparedStreamingResponse, reqwest::Error> {
    let retry_policy = state
        .provider_registry
        .as_ref()
        .map(|r| r.retry_policy.clone())
        .unwrap_or_default();
    let _model_name = extract_upstream_model_name(&body);
    // Build the upstream HTTP client once, outside the retry loop.
    // Same rationale as send_upstream_request: avoid re-allocating a new TLS
    // context and connection pool on every retry attempt.
    let request_client = if state.allow_insecure_tls {
        shared_insecure_gateway_http_client()
    } else {
        state.client.clone()
    };
    let outbound_body = strip_runtime_contract_fields_bytes(&body);

    let mut attempt = 0usize;

    loop {
        let permit = state.rate_limiter.acquire().await;
        let limiter_snapshot = state.rate_limiter.snapshot();
        let upstream_path = rewrite_upstream_path(state.upstream_base, path);
        let upstream_url = join_upstream(state.upstream_base, &upstream_path);

        let mut request = request_client
            .post(upstream_url)
            .header("X-Request-Id", request_id)
            .header("traceparent", traceparent)
            .body(outbound_body.clone());

        if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
            request = request.header(header::CONTENT_TYPE, content_type.clone());
        }
        if let Some((name, value)) = &state.upstream_auth {
            request = request.header(name.clone(), value.clone());
        }
        if is_github_models_upstream(state.upstream_base) {
            request = request.header(header::ACCEPT, "application/vnd.github+json");
            request = request.header("X-GitHub-Api-Version", github_models_api_version_header());
        }

        // Phase 35: apply provider-specific extra headers (Anthropic, Azure, Bedrock, Vertex).
        for (name, value) in &state.provider_extra_headers {
            request = request.header(name.clone(), value.clone());
        }

        // Apply per-target streaming timeout if set.
        if let Some(timeout) = state.request_timeout {
            request = request.timeout(timeout);
        }

        let span = tracing::info_span!(
            "provider_stream_evaluation",
            request_id = %request_id,
            traceparent = %traceparent,
            path = %path,
            provider = %limiter_snapshot.provider,
            attempt = attempt + 1,
            concurrency_limit = limiter_snapshot.current_concurrency,
            max_concurrency = limiter_snapshot.max_concurrency,
        );
        crate::telemetry::attach_parent_trace_context(&span, traceparent);
        annotate_trace_correlation_span(&span, correlation);

        let upstream_send_start = Instant::now();
        let result = request.send().instrument(span).await;
        record_request_stage_timing(
            RequestStageTiming::UpstreamSend,
            upstream_send_start.elapsed(),
            None,
        );
        match result {
            Ok(response) => {
                let meta =
                    crate::gateway::rate_limit::UpstreamResponseMeta::from_response(&response);

                if meta.is_transient_failure()
                    && attempt
                        < retry_policy.max_retries_for(Some(
                            &crate::gateway::providers::FallbackTrigger::ServerError,
                        ))
                {
                    let delay = retry_policy.backoff_delay(attempt);
                    drop(permit);
                    state.rate_limiter.on_transient_failure();
                    attempt += 1;
                    tokio::time::sleep(delay).await;
                    continue;
                }

                if response.status().is_success() {
                    state.rate_limiter.on_success(meta.remaining_quota_ratio);
                } else {
                    state.rate_limiter.on_transient_failure();
                }
                drop(permit);
                let content_type = match state.stream_response_adapter {
                    Some(StreamingResponseAdapter::OllamaChat)
                    | Some(StreamingResponseAdapter::BedrockAnthropicEventStream) => {
                        HeaderValue::from_static("text/event-stream")
                    }
                    None => response
                        .headers()
                        .get(header::CONTENT_TYPE)
                        .cloned()
                        .unwrap_or_else(|| HeaderValue::from_static("text/event-stream")),
                };
                let status = response.status();
                let max_response_bytes = state
                    .size_limit
                    .as_ref()
                    .and_then(|sl| sl.max_response_bytes());
                let stream_response_adapter = state.stream_response_adapter;
                let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(16);
                let request_id_for_stream = request_id.to_string();
                tokio::spawn(async move {
                    let mut response = response;
                    let mut cumulative_bytes: usize = 0;
                    let mut parser_buffer = Vec::new();
                    let created = chrono::Utc::now().timestamp();
                    loop {
                        match response.chunk().await {
                            Ok(Some(chunk)) => {
                                cumulative_bytes = cumulative_bytes.saturating_add(chunk.len());
                                if let Some(max) = max_response_bytes {
                                    if cumulative_bytes > max {
                                        tracing::warn!(
                                            cumulative_bytes = cumulative_bytes,
                                            max_response_bytes = max,
                                            "streaming response exceeds size limit, aborting stream"
                                        );
                                        let error_event = format!(
                                            "data: {}\n\n",
                                            serde_json::json!({
                                                "error": {
                                                    "message": "Streaming response exceeded size limit",
                                                    "type": "response_too_large",
                                                    "code": "response_size_exceeded"
                                                }
                                            })
                                        );
                                        let _ = tx.send(Ok(Bytes::from(error_event))).await;
                                        return;
                                    }
                                }
                                match stream_response_adapter {
                                    Some(StreamingResponseAdapter::OllamaChat) => {
                                        parser_buffer.extend_from_slice(&chunk);
                                        for payload in crate::gateway::sse::drain_json_line_frames(
                                            &mut parser_buffer,
                                        ) {
                                            if let Some(frame) =
                                                crate::gateway::sse::ollama_chat_json_to_sse(
                                                    &payload,
                                                    &format!("chatcmpl-{request_id_for_stream}"),
                                                    created,
                                                )
                                            {
                                                if tx.send(Ok(frame)).await.is_err() {
                                                    return;
                                                }
                                            }
                                        }
                                    }
                                    Some(StreamingResponseAdapter::BedrockAnthropicEventStream) => {
                                        parser_buffer.extend_from_slice(&chunk);
                                        match crate::gateway::provider_pipeline::drain_bedrock_eventstream_frames(
                                            &mut parser_buffer,
                                        ) {
                                            Ok(frames) => {
                                                for frame in frames {
                                                    if tx.send(Ok(frame)).await.is_err() {
                                                        return;
                                                    }
                                                }
                                            }
                                            Err(error) => {
                                                let _ = tx.send(Err(error)).await;
                                                return;
                                            }
                                        }
                                    }
                                    None => {
                                        if tx.send(Ok(chunk)).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                            Ok(None) => {
                                if matches!(
                                    stream_response_adapter,
                                    Some(StreamingResponseAdapter::OllamaChat)
                                ) {
                                    let trailing =
                                        String::from_utf8_lossy(&parser_buffer).trim().to_string();
                                    if !trailing.is_empty() {
                                        if let Some(frame) =
                                            crate::gateway::sse::ollama_chat_json_to_sse(
                                                &trailing,
                                                &format!("chatcmpl-{request_id_for_stream}"),
                                                created,
                                            )
                                        {
                                            let _ = tx.send(Ok(frame)).await;
                                        }
                                    }
                                }
                                if matches!(
                                    stream_response_adapter,
                                    Some(StreamingResponseAdapter::BedrockAnthropicEventStream)
                                ) {
                                    match crate::gateway::provider_pipeline::drain_bedrock_eventstream_frames(
                                        &mut parser_buffer,
                                    ) {
                                        Ok(frames) => {
                                            for frame in frames {
                                                let _ = tx.send(Ok(frame)).await;
                                            }
                                        }
                                        Err(error) => {
                                            let _ = tx.send(Err(error)).await;
                                        }
                                    }
                                }
                                return;
                            }
                            Err(error) => {
                                let _ = tx.send(Err(io::Error::other(error))).await;
                                return;
                            }
                        }
                    }
                });
                return Ok(PreparedStreamingResponse {
                    status,
                    content_type,
                    body: Box::pin(ReceiverStream::new(rx)),
                });
            }
            Err(error) => {
                drop(permit);
                state.rate_limiter.on_transient_failure();
                if attempt < retry_policy.max_retries {
                    let delay = retry_policy.backoff_delay(attempt);
                    attempt += 1;
                    tokio::time::sleep(delay).await;
                    continue;
                }
                return Err(error);
            }
        }
    }
}

pub(crate) fn prepared_streaming_json_response(
    status: StatusCode,
    body: Bytes,
    content_type: HeaderValue,
) -> PreparedStreamingResponse {
    PreparedStreamingResponse {
        status,
        content_type,
        body: Box::pin(stream::once(async move { Ok(body) })),
    }
}

pub(crate) async fn collect_prepared_stream_body(mut body: PreparedByteStream) -> Bytes {
    let mut buffered = Vec::new();
    while let Some(chunk) = body.next().await {
        match chunk {
            Ok(bytes) => buffered.extend_from_slice(&bytes),
            Err(error) => {
                buffered.extend_from_slice(error.to_string().as_bytes());
                break;
            }
        }
    }
    Bytes::from(buffered)
}

pub(crate) async fn send_upstream_request(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    path: &str,
    body: Bytes,
    request_id: &str,
    traceparent: &str,
    cache_key: Option<&str>,
    correlation: &TraceCorrelation,
    request_telemetry_hints: &RequestTelemetryHints,
) -> Result<crate::gateway::cache::BufferedUpstreamResponse, reqwest::Error> {
    let retry_policy = state
        .provider_registry
        .as_ref()
        .map(|r| r.retry_policy.clone())
        .unwrap_or_default();
    let model_name = extract_upstream_model_name(&body);
    let semantic_query_embedding = build_semantic_cache_embedding(state, &body);
    let cache_ttl_override = effective_cache_ttl_override(state);

    if let Some(key) = cache_key {
        let cached = state
            .provider_cache
            .get_with_ttl(key, cache_ttl_override)
            .instrument(proxy_phase_span(
                "provider_cache_lookup",
                request_id,
                traceparent,
                "provider.cache_lookup",
                correlation,
            ))
            .await;
        if let Some(cached) = cached {
            let provider = state.rate_limiter.snapshot().provider;
            emit_cached_provider_trace(
                request_id,
                traceparent,
                path,
                &provider,
                state.upstream_base,
                model_name.as_deref(),
                &body,
                &cached,
                correlation,
                request_telemetry_hints,
                !silent_engine(state).payload_logging_disabled(),
            )
            .await;
            tracing::debug!(
                request_id = %request_id,
                traceparent = %traceparent,
                path = %path,
                cached = cached.is_cached(),
                "served upstream provider response from cache"
            );
            return Ok(cached);
        }

        if let (Some(semantic_config), Some(query_embedding)) = (
            state.semantic_cache.as_ref(),
            semantic_query_embedding.as_ref(),
        ) {
            if semantic_config.mode == crate::gateway::cache::CacheMode::Semantic {
                let cached = async {
                    state
                        .provider_cache
                        .get_semantic_with_ttl(
                            query_embedding,
                            semantic_config.similarity_threshold,
                            cache_ttl_override,
                        )
                        .await
                }
                .instrument(proxy_phase_span(
                    "provider_semantic_cache_lookup",
                    request_id,
                    traceparent,
                    "provider.semantic_cache_lookup",
                    correlation,
                ))
                .await;

                if let Some(cached) = cached {
                    let provider = state.rate_limiter.snapshot().provider;
                    emit_cached_provider_trace(
                        request_id,
                        traceparent,
                        path,
                        &provider,
                        state.upstream_base,
                        model_name.as_deref(),
                        &body,
                        &cached,
                        correlation,
                        request_telemetry_hints,
                        !silent_engine(state).payload_logging_disabled(),
                    )
                    .await;
                    return Ok(cached);
                }
            }
        }
    }

    // Build the upstream HTTP client once, outside the retry loop.
    // When allow_insecure_tls is true a dedicated no-cert-check client is
    // required; constructing it on every attempt wastes TLS init overhead and
    // defeats connection pooling. For the standard TLS path we take a cheap
    // Arc clone of the shared gateway client.
    let request_client = if state.allow_insecure_tls {
        shared_insecure_gateway_http_client()
    } else {
        state.client.clone()
    };
    let outbound_body = strip_runtime_contract_fields_bytes(&body);

    let mut attempt = 0usize;
    loop {
        let permit = state.rate_limiter.acquire().await;
        let limiter_snapshot = state.rate_limiter.snapshot();
        let upstream_path = rewrite_upstream_path(state.upstream_base, path);
        let upstream_url = join_upstream(state.upstream_base, &upstream_path);

        let mut req = request_client
            .post(upstream_url)
            .header("X-Request-Id", request_id)
            .header("traceparent", traceparent)
            .body(outbound_body.clone());

        if let Some(ct) = headers.get(header::CONTENT_TYPE) {
            req = req.header(header::CONTENT_TYPE, ct.clone());
        }

        if let Some((name, value)) = &state.upstream_auth {
            req = req.header(name.clone(), value.clone());
        }

        if is_github_models_upstream(state.upstream_base) {
            req = req.header(header::ACCEPT, "application/vnd.github+json");
            req = req.header("X-GitHub-Api-Version", github_models_api_version_header());
        }

        // Phase 35: apply provider-specific extra headers (Anthropic, Azure, Bedrock, Vertex).
        for (name, value) in &state.provider_extra_headers {
            req = req.header(name.clone(), value.clone());
        }

        // Apply per-target non-streaming timeout if set.
        if let Some(timeout) = state.request_timeout {
            req = req.timeout(timeout);
        }

        let span = tracing::info_span!(
            "provider_evaluation",
            request_id = %request_id,
            traceparent = %traceparent,
            path = %path,
            provider = %limiter_snapshot.provider,
            attempt = attempt + 1,
            concurrency_limit = limiter_snapshot.current_concurrency,
            max_concurrency = limiter_snapshot.max_concurrency,
            verdictan_evaluation_id = tracing::field::Empty,
            verdictan_evaluation_run_id = tracing::field::Empty,
            verdictan_test_case_id = tracing::field::Empty,
            verdictan_test_run_id = tracing::field::Empty,
            gen_ai_system = tracing::field::Empty,
            gen_ai_operation_name = tracing::field::Empty,
            gen_ai_request_model = tracing::field::Empty,
            gen_ai_request_max_tokens = tracing::field::Empty,
            gen_ai_request_temperature = tracing::field::Empty,
            gen_ai_request_top_p = tracing::field::Empty,
            gen_ai_request_stop_sequences = tracing::field::Empty,
            gen_ai_response_finish_reasons = tracing::field::Empty,
            gen_ai_usage_input_tokens = tracing::field::Empty,
            gen_ai_usage_output_tokens = tracing::field::Empty,
            gen_ai_usage_total_tokens = tracing::field::Empty,
            gen_ai_usage_cached_tokens = tracing::field::Empty,
            gen_ai_usage_reasoning_tokens = tracing::field::Empty,
            verdictan_provider_id = tracing::field::Empty,
            verdictan_prompt_label = tracing::field::Empty,
            verdictan_test_index = tracing::field::Empty,
            verdictan_cache_hit = tracing::field::Empty,
            verdictan_request_body = tracing::field::Empty,
            verdictan_response_body = tracing::field::Empty,
            server_address = tracing::field::Empty,
            http_response_status_code = tracing::field::Empty
        );
        crate::telemetry::attach_parent_trace_context(&span, traceparent);
        crate::telemetry::annotate_provider_span(
            &span,
            request_id,
            &limiter_snapshot.provider,
            path,
            state.upstream_base,
            model_name.as_deref(),
        );
        let telemetry_verdictan = telemetry_verdictan_metadata(request_telemetry_hints);
        crate::telemetry::annotate_provider_request_attributes(
            &span,
            &limiter_snapshot.provider,
            path,
            &body,
            false,
            telemetry_verdictan.as_ref(),
            !silent_engine(state).payload_logging_disabled(),
        );
        annotate_trace_correlation_span(&span, correlation);

        let upstream_send_start = Instant::now();
        let result = req.send().instrument(span.clone()).await;
        record_request_stage_timing(
            RequestStageTiming::UpstreamSend,
            upstream_send_start.elapsed(),
            None,
        );
        match result {
            Ok(response) => {
                let meta =
                    crate::gateway::rate_limit::UpstreamResponseMeta::from_response(&response);

                if meta.is_rate_limited() {
                    let delay = meta
                        .retry_after
                        .unwrap_or_else(|| retry_policy.backoff_delay(attempt));
                    let snapshot = state.rate_limiter.on_rate_limited(Some(delay));
                    tracing::warn!(
                        request_id = %request_id,
                        provider = %snapshot.provider,
                        attempt = attempt + 1,
                        retry_after_ms = delay.as_millis() as u64,
                        current_concurrency = snapshot.current_concurrency,
                        "upstream provider rate limited request"
                    );
                    drop(permit);

                    if attempt
                        < retry_policy.max_retries_for(Some(
                            &crate::gateway::providers::FallbackTrigger::RateLimit,
                        ))
                    {
                        attempt += 1;
                        tokio::time::sleep(delay).await;
                        continue;
                    }

                    let buffered = crate::gateway::cache::BufferedUpstreamResponse::from_reqwest(
                        response, false,
                    )
                    .await?;
                    if let Some(key) = cache_key {
                        state
                            .provider_cache
                            .put_with_ttl(key, &buffered, cache_ttl_override)
                            .await;
                    }
                    return Ok(buffered);
                }

                if meta.is_transient_failure()
                    && attempt
                        < retry_policy.max_retries_for(Some(
                            &crate::gateway::providers::FallbackTrigger::ServerError,
                        ))
                {
                    let delay = retry_policy.backoff_delay(attempt);
                    let snapshot = state.rate_limiter.on_transient_failure();
                    tracing::warn!(
                        request_id = %request_id,
                        provider = %snapshot.provider,
                        attempt = attempt + 1,
                        retry_after_ms = delay.as_millis() as u64,
                        status = meta.status_code.unwrap_or_default(),
                        "upstream request failed transiently, retrying"
                    );
                    drop(permit);
                    attempt += 1;
                    tokio::time::sleep(delay).await;
                    continue;
                }

                let snapshot = if response.status().is_success() {
                    state.rate_limiter.on_success(meta.remaining_quota_ratio)
                } else {
                    state.rate_limiter.on_transient_failure()
                };

                tracing::debug!(
                    request_id = %request_id,
                    provider = %snapshot.provider,
                    current_concurrency = snapshot.current_concurrency,
                    remaining_quota_ratio = meta.remaining_quota_ratio,
                    status = meta.status_code.unwrap_or_default(),
                    "completed upstream provider request"
                );
                drop(permit);
                // Body-read errors are treated as transient failures and are
                // retried within the same retry budget as send-phase errors.
                // Under concurrent load an upstream may successfully send
                // response headers but then close the connection before the
                // body is fully delivered; without this retry the gateway
                // would immediately surface proxy.upstream_unreachable even
                // though the provider was reachable.
                let buffered = match crate::gateway::cache::BufferedUpstreamResponse::from_reqwest(
                    response, false,
                )
                .await
                {
                    Ok(b) => b,
                    Err(body_err) => {
                        let delay = retry_policy.backoff_delay(attempt);
                        state.rate_limiter.on_transient_failure();
                        tracing::warn!(
                            request_id = %request_id,
                            attempt = attempt + 1,
                            retry_after_ms = delay.as_millis() as u64,
                            error = %body_err,
                            "upstream response body read failed; will retry if budget remains"
                        );
                        if attempt < retry_policy.max_retries {
                            attempt += 1;
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        return Err(body_err);
                    }
                };
                crate::telemetry::annotate_provider_response_attributes(
                    &span,
                    buffered.status(),
                    buffered.body(),
                    false,
                    !silent_engine(state).payload_logging_disabled(),
                );
                if let Some(key) = cache_key {
                    state
                        .provider_cache
                        .put_with_ttl(key, &buffered, cache_ttl_override)
                        .await;
                    if let Some(query_embedding) = semantic_query_embedding.as_ref() {
                        state
                            .provider_cache
                            .store_semantic_embedding_with_ttl(
                                key,
                                query_embedding,
                                cache_ttl_override,
                            )
                            .await;
                    }
                }
                return Ok(buffered);
            }
            Err(error) => {
                let delay = retry_policy.backoff_delay(attempt);
                let snapshot = state.rate_limiter.on_transient_failure();
                tracing::warn!(
                    request_id = %request_id,
                    provider = %snapshot.provider,
                    attempt = attempt + 1,
                    retry_after_ms = delay.as_millis() as u64,
                    error = %error,
                    "upstream request errored"
                );
                drop(permit);

                if attempt < retry_policy.max_retries {
                    attempt += 1;
                    tokio::time::sleep(delay).await;
                    continue;
                }

                return Err(error);
            }
        }
    }
}

pub(crate) async fn lookup_provider_cache_only(
    state: &ActiveGatewayStateView<'_>,
    cache_key: Option<&str>,
    body: &Bytes,
    request_id: &str,
    traceparent: &str,
    correlation: &TraceCorrelation,
) -> Option<CacheLookupResult> {
    let key = cache_key?;
    let cache_ttl_override = effective_cache_ttl_override(state);

    let cached = state
        .provider_cache
        .get_with_ttl(key, cache_ttl_override)
        .instrument(proxy_phase_span(
            "provider_cache_lookup",
            request_id,
            traceparent,
            "provider.cache_lookup",
            correlation,
        ))
        .await;
    if let Some(cached) = cached {
        tracing::debug!(
            request_id = %request_id,
            traceparent = %traceparent,
            cached = cached.is_cached(),
            "served upstream provider response from cache before usage authorization"
        );
        return Some(CacheLookupResult {
            response: cached,
            outcome: CacheReplayOutcome::ExactHit,
        });
    }

    let semantic_config = state.semantic_cache.as_ref()?;
    if semantic_config.mode != crate::gateway::cache::CacheMode::Semantic {
        return None;
    }
    if semantic_config.similarity_threshold < 0.95 {
        tracing::debug!(
            request_id = %request_id,
            threshold = semantic_config.similarity_threshold,
            "semantic direct replay denied because threshold is below 0.95"
        );
        return None;
    }
    if !state
        .workflow_cache
        .as_ref()
        .map(|config| config.direct_semantic_replay_enabled)
        .unwrap_or(false)
    {
        tracing::debug!(
            request_id = %request_id,
            "semantic direct replay denied by effective workflow cache policy"
        );
        return None;
    }
    let query_embedding = build_semantic_cache_embedding(state, body)?;
    async {
        state
            .provider_cache
            .get_semantic_with_ttl(
                &query_embedding,
                semantic_config.similarity_threshold,
                cache_ttl_override,
            )
            .await
    }
    .instrument(proxy_phase_span(
        "provider_semantic_cache_lookup",
        request_id,
        traceparent,
        "provider.semantic_cache_lookup",
        correlation,
    ))
    .await
    .map(|response| CacheLookupResult {
        response,
        outcome: CacheReplayOutcome::SemanticReplayed,
    })
}

pub(crate) async fn retrieve_request_fabric_slices(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    request_value: &serde_json::Value,
    request_id: &str,
) -> Vec<crate::gateway::codebase_context::FabricArtifactSlice> {
    if !state.connected_mode {
        return Vec::new();
    }

    let finops_org_id = state
        .request_finops
        .as_ref()
        .and_then(|finops| finops.org_id.as_deref());
    let metadata = crate::gateway::codebase_context::extract_fabric_request_metadata(
        request_value,
        headers,
        finops_org_id,
    );
    if !metadata.has_lookup_scope() {
        return Vec::new();
    }

    let Some(sink) = state.event_sink.as_ref() else {
        return Vec::new();
    };
    let Ok(client) = sink.machine_client() else {
        return Vec::new();
    };
    let Some(org_id) = metadata.org_id.as_deref() else {
        return Vec::new();
    };

    match crate::gateway::codebase_context::retrieve_fabric_slices(
        client,
        sink.base_url(),
        org_id,
        metadata.repo_id.as_deref(),
        metadata.codebase_identity_id.as_deref(),
        metadata.artifact_type.as_deref(),
    )
    .await
    {
        Ok(slices) => {
            tracing::debug!(
                request_id = %request_id,
                selected_artifacts = slices.len(),
                "retrieved Codebase Context Fabric slices"
            );
            slices
        }
        Err(error) if error.is_optional_unavailable() => {
            tracing::debug!(
                request_id = %request_id,
                error = %error,
                "Codebase Context Fabric lookup unavailable; continuing without fabric slices"
            );
            Vec::new()
        }
        Err(error) => {
            tracing::warn!(
                request_id = %request_id,
                error = %error,
                "Codebase Context Fabric slice retrieval failed"
            );
            Vec::new()
        }
    }
}

pub(crate) fn annotate_cache_replay_metadata(
    event: &mut serde_json::Value,
    replay_metadata: Option<&CacheReplayMetadata>,
) {
    let Some(replay_metadata) = replay_metadata else {
        return;
    };
    if let Some(metadata) = event
        .get_mut("metadata")
        .and_then(|value| value.as_object_mut())
    {
        metadata.insert("cache_replay".to_string(), replay_metadata.to_json());
    } else if let Some(object) = event.as_object_mut() {
        object.insert(
            "metadata".to_string(),
            serde_json::json!({ "cache_replay": replay_metadata.to_json() }),
        );
    }
}

pub(crate) fn extract_upstream_model_name(body: &Bytes) -> Option<String> {
    let value = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    value
        .get("model")
        .and_then(|item| item.as_str())
        .map(|item| item.to_string())
}

pub(crate) fn extract_response_model_name(body: &Bytes) -> Option<String> {
    let value = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    value
        .get("model")
        .and_then(|item| item.as_str())
        .map(|item| item.to_string())
}

pub(crate) fn extract_pipeline_metadata(body: &Bytes) -> Option<serde_json::Value> {
    let value = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    value.get("verdictan_pipeline").cloned()
}

pub(crate) fn extract_spend_usage(body: &Bytes) -> Option<SpendUsage> {
    let value = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let usage = value.get("usage")?.as_object()?;

    let prompt_tokens = usage
        .get("prompt_tokens")
        .and_then(|value| value.as_u64())
        .or_else(|| usage.get("input_tokens").and_then(|value| value.as_u64()))
        .unwrap_or(0);
    let completion_tokens = usage
        .get("completion_tokens")
        .and_then(|value| value.as_u64())
        .or_else(|| usage.get("output_tokens").and_then(|value| value.as_u64()))
        .unwrap_or(0);
    let total_tokens = usage
        .get("total_tokens")
        .and_then(|value| value.as_u64())
        .unwrap_or(prompt_tokens.saturating_add(completion_tokens));
    // Extract cached input tokens from various provider formats
    let cached_input_tokens = usage
        .get("prompt_tokens_details")
        .and_then(|d| d.get("cached_tokens").and_then(|v| v.as_u64()))
        .or_else(|| {
            usage
                .get("input_tokens_details")
                .and_then(|d| d.get("cached_tokens").and_then(|v| v.as_u64()))
        })
        .or_else(|| {
            usage
                .get("cache_read_input_tokens")
                .and_then(|v| v.as_u64())
        })
        .or_else(|| usage.get("cached_input_tokens").and_then(|v| v.as_u64()))
        .unwrap_or(0);
    let prompt_cost = usage
        .get("prompt_cost")
        .and_then(|value| value.as_f64())
        .or_else(|| usage.get("input_cost").and_then(|value| value.as_f64()));
    let completion_cost = usage
        .get("completion_cost")
        .and_then(|value| value.as_f64())
        .or_else(|| usage.get("output_cost").and_then(|value| value.as_f64()));
    let total_cost = usage
        .get("total_cost")
        .and_then(|value| value.as_f64())
        .or_else(|| usage.get("cost").and_then(|value| value.as_f64()));

    if prompt_tokens == 0
        && completion_tokens == 0
        && total_tokens == 0
        && prompt_cost.is_none()
        && completion_cost.is_none()
        && total_cost.is_none()
    {
        return None;
    }

    Some(SpendUsage {
        prompt_tokens,
        completion_tokens,
        total_tokens,
        cached_input_tokens,
        prompt_cost,
        completion_cost,
        total_cost,
    })
}

pub fn estimate_streaming_spend_usage(
    request_body: &Bytes,
    output_text: Option<&str>,
    output_chars: usize,
) -> Option<SpendUsage> {
    let request_json = serde_json::from_slice::<serde_json::Value>(request_body).ok();
    let prompt_tokens = request_json
        .as_ref()
        .and_then(crate::gateway::token_estimation::estimate_prompt_tokens)
        .unwrap_or(0);
    let completion_tokens = output_text
        .map(crate::gateway::token_estimation::estimate_text_tokens)
        .unwrap_or_else(|| output_chars.div_ceil(4));

    if prompt_tokens == 0 && completion_tokens == 0 {
        return None;
    }

    let prompt_tokens = u64::try_from(prompt_tokens).ok()?;
    let completion_tokens = u64::try_from(completion_tokens).ok()?;

    Some(SpendUsage {
        prompt_tokens,
        completion_tokens,
        total_tokens: prompt_tokens.saturating_add(completion_tokens),
        cached_input_tokens: 0,
        prompt_cost: None,
        completion_cost: None,
        total_cost: None,
    })
}

pub(crate) fn estimate_prompt_only_spend_usage(
    request_body: &serde_json::Value,
) -> Option<SpendUsage> {
    let prompt_tokens = crate::gateway::token_estimation::estimate_prompt_tokens(request_body)?;
    if prompt_tokens == 0 {
        return None;
    }

    let prompt_tokens = u64::try_from(prompt_tokens).ok()?;
    Some(SpendUsage {
        prompt_tokens,
        completion_tokens: 0,
        total_tokens: prompt_tokens,
        cached_input_tokens: 0,
        prompt_cost: None,
        completion_cost: None,
        total_cost: None,
    })
}

pub(crate) fn resolve_buffered_post_dispatch_usage(
    request_body: &serde_json::Value,
    response: &crate::gateway::cache::BufferedUpstreamResponse,
) -> Option<ConnectedPostDispatchUsage> {
    let response_body = response.body();
    let pipeline_metadata = extract_pipeline_metadata(response_body);
    let response_model_hint = extract_response_model_name(response_body);
    let response_bytes = i64::try_from(response_body.len()).unwrap_or(0);

    extract_spend_usage(response_body)
        .map(|usage| ConnectedPostDispatchUsage {
            usage,
            source: ConnectedPostDispatchUsageSource::UpstreamReported,
            pipeline_metadata: pipeline_metadata.clone(),
            response_model_hint: response_model_hint.clone(),
            response_bytes,
        })
        .or_else(|| {
            estimate_prompt_only_spend_usage(request_body).map(|usage| ConnectedPostDispatchUsage {
                usage,
                source: ConnectedPostDispatchUsageSource::PromptOnlyFallback,
                pipeline_metadata,
                response_model_hint,
                response_bytes,
            })
        })
}

pub(crate) fn resolve_streaming_post_dispatch_usage(
    request_body: &Bytes,
    output_text: Option<&str>,
    output_chars: usize,
) -> Option<ConnectedPostDispatchUsage> {
    estimate_streaming_spend_usage(request_body, output_text, output_chars).map(|usage| {
        ConnectedPostDispatchUsage {
            usage,
            source: ConnectedPostDispatchUsageSource::StreamingEstimate,
            pipeline_metadata: None,
            response_model_hint: None,
            response_bytes: 0,
        }
    })
}

pub(crate) fn annotate_post_dispatch_usage_source(
    spend_log: &mut SpendLogPayload,
    source: ConnectedPostDispatchUsageSource,
) {
    if let Some(metadata) = spend_log.metadata.as_object_mut() {
        metadata.insert(
            "usage_source".to_string(),
            serde_json::json!(source.as_str()),
        );
        metadata.insert(
            "usage_estimated".to_string(),
            serde_json::json!(source.is_estimated()),
        );
    }
}

pub(crate) fn find_provider_target<'a>(
    provider_registry: Option<&'a crate::gateway::providers::ProviderRegistry>,
    provider_id: Option<&str>,
) -> Option<&'a crate::gateway::providers::ProviderTarget> {
    let provider_id = provider_id?;
    provider_registry?
        .targets
        .iter()
        .find(|target| target.id == provider_id)
}

pub(crate) fn spend_target_model_for_request(
    target: &crate::gateway::providers::ProviderTarget,
    requested_model: Option<&str>,
) -> Option<String> {
    if let Some(requested_model) = requested_model
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
    {
        if let Some(model) = resolve_target_request_model(target, requested_model, None).0 {
            return Some(model);
        }
    }

    let model = target.model.trim();
    (!model.is_empty() && model != "*").then(|| model.to_string())
}

pub(crate) fn spend_cost_breakdown(
    usage: SpendUsage,
    pricing: Option<&ProviderPricing>,
) -> (f64, f64, f64, f64) {
    if usage.prompt_cost.is_some() || usage.completion_cost.is_some() || usage.total_cost.is_some()
    {
        let prompt_cost = usage.prompt_cost.unwrap_or(0.0);
        let completion_cost = usage.completion_cost.unwrap_or_else(|| {
            usage
                .total_cost
                .map(|total| (total - prompt_cost).max(0.0))
                .unwrap_or(0.0)
        });
        let total_cost = usage.total_cost.unwrap_or(prompt_cost + completion_cost);
        return (prompt_cost, completion_cost, 0.0, total_cost);
    }

    if let Some(pricing) = pricing {
        let cost = pricing.compute_cost_with_cache(
            usage.prompt_tokens,
            usage.completion_tokens,
            usage.cached_input_tokens,
        );
        return (
            cost.prompt,
            cost.completion,
            cost.cached_input,
            cost.request,
        );
    }

    (0.0, 0.0, 0.0, 0.0)
}

pub(crate) fn estimated_avoided_cost_from_cached_response(response_body: &Bytes) -> f64 {
    extract_spend_usage(response_body)
        .and_then(|usage| {
            usage
                .total_cost
                .or(match (usage.prompt_cost, usage.completion_cost) {
                    (Some(prompt), Some(completion)) => Some(prompt + completion),
                    (Some(prompt), None) => Some(prompt),
                    (None, Some(completion)) => Some(completion),
                    (None, None) => None,
                })
        })
        .unwrap_or(0.0)
}

pub(crate) fn emit_cache_hit_economics(
    state: &ActiveGatewayStateView<'_>,
    request_id: &str,
    traceparent: &str,
    response_body: &Bytes,
    cache_tier: CacheTier,
    hit_type: &str,
    source_cache_key_digest: Option<&str>,
    fabric_slices: &[crate::gateway::codebase_context::FabricArtifactSlice],
) {
    if !state.connected_mode {
        return;
    }

    let Some(sink) = state.event_sink.as_ref().cloned() else {
        return;
    };
    let Ok(machine_client) = sink.machine_client().cloned() else {
        return;
    };
    let Some(finops) = state.request_finops.as_ref() else {
        return;
    };
    let Some(org_id) = finops.org_id.as_ref().filter(|value| !value.is_empty()) else {
        return;
    };

    let selected_artifact_ids =
        crate::gateway::codebase_context::selected_artifact_ids(fabric_slices);
    let selected_source_digests =
        crate::gateway::codebase_context::selected_source_digests(fabric_slices);
    let fabric_freshness = crate::gateway::codebase_context::freshness_identity(fabric_slices);

    let payload = serde_json::json!({
        "org_id": org_id,
        "team_id": finops.team_id,
        "user_id": finops.user_id,
        "agent_id": state.current_agent_id,
        "repo_id": serde_json::Value::Null,
        "monorepo_group_id": serde_json::Value::Null,
        "cache_tier": cache_tier.as_str(),
        "hit_type": hit_type,
        "estimated_avoided_cost": estimated_avoided_cost_from_cached_response(response_body),
        "source_cache_key_digest": source_cache_key_digest,
        "freshness_identity": {
            "configuration_id": state.configuration_id,
            "configuration_version_id": state.configuration_version_id,
            "config_sha256": state.config_sha256,
            "fabric": fabric_freshness,
        },
        "request_id": request_id,
        "gateway_id": spend_gateway_reference(state.gateway_id.as_ref(), state.connected_mode),
        "configuration_id": state.configuration_id,
        "configuration_version_id": state.configuration_version_id,
        "metadata": {
            "source": "gateway_cache_hit",
            "selected_fabric_artifact_ids": selected_artifact_ids,
            "selected_fabric_source_digests": selected_source_digests,
            "region_key": state.region_key,
            "requested_region_group": state.requested_region_group,
            "public_endpoint_host": state.managed_public_endpoint_host,
            "publication_key": state.current_publication.as_ref().map(|publication| publication.publication_key.clone()),
            "publication_revision_id": state.current_publication.as_ref().and_then(|publication| publication.active_revision_id.clone()),
            "publication_primary_region_group_key": state.current_publication.as_ref().and_then(|publication| publication.primary_region_group_key.clone()),
        },
    });
    let url = sink.join_url("/v1/gateway/cache/hits");
    let request_id = request_id.to_string();
    let traceparent = traceparent.to_string();

    tokio::spawn(async move {
        match machine_client
            .post(url)
            .header("X-Request-Id", request_id.clone())
            .header("traceparent", traceparent.clone())
            .json(&payload)
            .send()
            .await
        {
            Ok(response) if !response.status().is_success() => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                if is_optional_control_plane_capability_failure(status, &body) {
                    tracing::debug!(
                        request_id = %request_id,
                        status = %status,
                        "cache-hit economics ingest unavailable; continuing without cache economics telemetry"
                    );
                } else {
                    tracing::warn!(
                        request_id = %request_id,
                        status = %status,
                        response_body = %body,
                        "cache-hit economics ingest returned non-success status"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    error = %error,
                    "cache-hit economics ingest request failed"
                );
            }
            _ => {}
        }
    });
}

pub(crate) fn is_optional_control_plane_capability_failure(status: StatusCode, body: &str) -> bool {
    status == StatusCode::NOT_FOUND
        || (status == StatusCode::FORBIDDEN
            && (body.contains("\"auth.insufficient_permissions\"")
                || body.contains("\"auth.admin_surface_required\"")))
}

pub fn build_spend_log_payload_with_usage(
    context: SpendLogContext<'_>,
    request_id: &str,
    request_body: &Bytes,
    usage: SpendUsage,
    cache_hit: bool,
    provider_id: Option<&str>,
    pipeline_metadata: Option<serde_json::Value>,
    response_model_hint: Option<String>,
    response_bytes_hint: i64,
) -> Option<SpendLogPayload> {
    if cache_hit {
        return None;
    }
    if let Err(error) =
        crate::gateway::usage_authorization::validate_publication_selection_tuple_fields(
            context
                .current_publication
                .map(|publication| publication.publication_key.as_str()),
            context
                .current_publication
                .and_then(|publication| publication.active_revision_id.as_deref()),
            context
                .current_publication
                .and_then(|publication| publication.primary_region_group_key.as_deref()),
        )
    {
        tracing::warn!(
            request_id = %request_id,
            error = %error,
            "dropping spend log with incomplete publication context"
        );
        return None;
    }
    let control_plane_request_id = request_id::control_plane_request_id(request_id);

    let target = if pipeline_metadata.is_some() {
        None
    } else {
        find_provider_target(context.provider_registry, provider_id)
    };
    let requested_model = extract_upstream_model_name(request_body);
    let target_model = target
        .and_then(|target| spend_target_model_for_request(target, requested_model.as_deref()));
    let pipeline_model = pipeline_metadata.as_ref().and_then(|value| {
        value
            .get("requested_model")
            .and_then(|item| item.as_str())
            .or_else(|| value.get("name").and_then(|item| item.as_str()))
            .map(ToString::to_string)
    });
    let response_model_hint = response_model_hint
        .map(|candidate| candidate.trim().to_string())
        .filter(|candidate| !candidate.is_empty());
    let model = target_model
        .clone()
        .or_else(|| pipeline_model.clone())
        .or_else(|| response_model_hint.clone())
        .or_else(|| requested_model.clone())?;
    let resolved_route_provider = resolve_spend_log_route_provider_alias(
        target,
        provider_id,
        request_finops_provider(context.request_finops),
        Some(model.as_str()),
    );
    let provider = if pipeline_metadata.is_some() {
        "verdictan-pipeline".to_string()
    } else {
        let canonical_provider = canonical_provider_slug(target, context.upstream_base, &model);
        if is_dynamic_provider_placeholder(Some(canonical_provider.as_str())) {
            resolved_route_provider
                .clone()
                .unwrap_or(canonical_provider)
        } else {
            canonical_provider
        }
    };
    let resolved_pricing = resolve_spend_pricing(&context, target, &provider, &model, usage);
    let (prompt_cost, completion_cost, cached_input_cost, total_cost) =
        spend_cost_breakdown(usage, resolved_pricing.pricing.as_ref());
    let finops = context.request_finops;
    let gateway_execution_session_id =
        finops.and_then(|context| context.gateway_execution_session_id.clone());
    let execution_surface = canonical_runtime_execution_surface(
        finops.and_then(|context| context.execution_surface.as_deref()),
        gateway_execution_session_id.as_deref(),
    )
    .to_string();

    let mut metadata = serde_json::json!({
        "request_id": control_plane_request_id.clone(),
        "execution_id": control_plane_request_id,
        "source": "proxy-runtime",
        "cache_hit": cache_hit,
        "provider_id": provider_id,
    });
    if let Some(object) = metadata.as_object_mut() {
        if let Some(gateway_execution_session_id) = gateway_execution_session_id.as_ref() {
            object.insert(
                "gateway_execution_session_id".to_string(),
                serde_json::json!(gateway_execution_session_id),
            );
        }
        object.insert(
            "execution_surface".to_string(),
            serde_json::json!(execution_surface.clone()),
        );
        if let Some(region_key) = context.region_key {
            object.insert("region_key".to_string(), serde_json::json!(region_key));
        }
        if let Some(requested_region_group) = context.requested_region_group {
            object.insert(
                "requested_region_group".to_string(),
                serde_json::json!(requested_region_group),
            );
        }
        if let Some(public_endpoint_host) = context.managed_public_endpoint_host {
            object.insert(
                "public_endpoint_host".to_string(),
                serde_json::json!(public_endpoint_host),
            );
        }
        if let Some(publication) = context.current_publication {
            object.insert(
                "publication_key".to_string(),
                serde_json::json!(publication.publication_key),
            );
            object.insert(
                "publication_family_key".to_string(),
                serde_json::json!(publication.family_key),
            );
            object.insert(
                "publication_state".to_string(),
                serde_json::json!(publication.publication_state),
            );
            object.insert(
                "publication_locality_mode".to_string(),
                serde_json::json!(publication.locality_mode),
            );
            object.insert(
                "publication_serving_fleet_class".to_string(),
                serde_json::json!(publication.serving_fleet_class),
            );
            if let Some(active_revision_id) = publication.active_revision_id.as_deref() {
                object.insert(
                    "active_revision_id".to_string(),
                    serde_json::json!(active_revision_id),
                );
                object.insert(
                    "publication_revision_id".to_string(),
                    serde_json::json!(active_revision_id),
                );
            }
            if let Some(primary_region_group_key) = publication.primary_region_group_key.as_deref()
            {
                object.insert(
                    "selected_region_group".to_string(),
                    serde_json::json!(primary_region_group_key),
                );
                object.insert(
                    "publication_primary_region_group_key".to_string(),
                    serde_json::json!(primary_region_group_key),
                );
            }
        }
    }
    if let (Some(object), Some(pipeline_metadata)) = (metadata.as_object_mut(), pipeline_metadata) {
        object.insert("pipeline".to_string(), pipeline_metadata);
    }
    if let (Some(object), Some(context_selection)) = (
        metadata.as_object_mut(),
        finops.and_then(RequestFinopsContext::context_selection_json),
    ) {
        object.insert("context_selection".to_string(), context_selection);
    }
    if let (Some(object), Some(identity_context)) = (
        metadata.as_object_mut(),
        finops.and_then(RequestFinopsContext::identity_context_json),
    ) {
        object.insert("identity_context".to_string(), identity_context);
    }
    if let (Some(object), Some(route_provider)) =
        (metadata.as_object_mut(), resolved_route_provider.clone())
    {
        object.insert(
            "route_provider".to_string(),
            serde_json::json!(route_provider),
        );
    }

    let usage_category = derive_usage_category(
        &metadata,
        None, // workflow_id not available in spend context; derived from execution_surface
        context.current_agent_id.map(String::as_str),
    )
    .to_string();
    let model_id = target
        .and_then(|_| target_model.clone())
        .or(resolved_pricing.canonical_model_id.clone())
        .or(pipeline_model)
        .or_else(|| response_model_hint.clone())
        .or_else(|| requested_model.clone())
        .or_else(|| Some(model.clone()));

    Some(SpendLogPayload {
        provider,
        model,
        prompt_tokens: i64::try_from(usage.prompt_tokens).ok()?,
        completion_tokens: i64::try_from(usage.completion_tokens).ok()?,
        total_tokens: i64::try_from(usage.total_tokens).ok()?,
        cached_input_tokens: i64::try_from(usage.cached_input_tokens).ok()?,
        prompt_cost,
        completion_cost,
        cached_input_cost,
        total_cost,
        currency: "USD".to_string(),
        key_id: finops.and_then(|context| context.key_id.clone()),
        user_id: finops.and_then(|context| context.user_id.clone()),
        team_id: finops.and_then(|context| context.team_id.clone()),
        provider_target_id: provider_id.map(ToString::to_string),
        model_id,
        requested_model,
        requested_provider: finops
            .and_then(|context| normalize_optional_text(context.provider.as_deref())),
        pricing_source: resolved_pricing.source,
        pricing_snapshot: resolved_pricing.snapshot,
        metadata,
        gateway_id: spend_gateway_reference(context.gateway_id, context.connected_mode),
        configuration_id: context.configuration_id.cloned(),
        configuration_version_id: context.configuration_version_id.cloned(),
        agent_id: context
            .current_agent_id
            .and_then(|agent_id| normalize_optional_text(Some(agent_id))),
        gateway_execution_session_id,
        execution_surface: Some(execution_surface),
        usage_category,
        request_bytes: i64::try_from(request_body.len()).unwrap_or(0),
        response_bytes: response_bytes_hint,
        // Each policy in the chain evaluates on input and output = 2 phases.
        processing_units: i32::try_from(context.policy_count * 2).unwrap_or(0),
        conversation_id: context.conversation_id.map(ToOwned::to_owned),
        catalog_input_price: resolved_pricing.catalog_input_price,
        catalog_output_price: resolved_pricing.catalog_output_price,
        catalog_model_id: resolved_pricing.catalog_model_id,
        catalog_provider_id: resolved_pricing.catalog_provider_id,
        catalog_pricing_source: resolved_pricing.catalog_pricing_source,
    })
}

pub fn spend_gateway_reference(
    gateway_id: Option<&Arc<str>>,
    _connected_mode: bool,
) -> Option<Arc<str>> {
    gateway_id.filter(|s| !s.trim().is_empty()).cloned()
}

pub(crate) fn runtime_route_provider_alias(
    target: Option<&crate::gateway::providers::ProviderTarget>,
    fallback_provider: Option<&str>,
) -> Option<String> {
    target
        .map(|candidate| {
            crate::gateway::provider_catalog::normalized_provider_alias(&candidate.provider)
        })
        .or_else(|| normalize_optional_text(fallback_provider))
}

pub(crate) fn request_finops_provider(finops: Option<&RequestFinopsContext>) -> Option<&str> {
    finops.and_then(|context| context.provider.as_deref())
}

pub(crate) fn is_dynamic_provider_placeholder(value: Option<&str>) -> bool {
    let normalized = value
        .map(|candidate| candidate.trim().to_ascii_lowercase())
        .unwrap_or_default();
    normalized.contains("dynamic-provider.invalid")
        || normalized.contains("dynamic_provider.invalid")
        || normalized.contains("verdictan dynamic provider.invalid")
}

pub(crate) fn resolve_spend_log_route_provider_alias(
    target: Option<&crate::gateway::providers::ProviderTarget>,
    provider_id: Option<&str>,
    requested_provider: Option<&str>,
    model_hint: Option<&str>,
) -> Option<String> {
    runtime_route_provider_alias(target, None)
        .or_else(|| {
            provider_id.and_then(|provider| {
                canonical_provider_from_provider_id(provider, model_hint.unwrap_or_default())
            })
        })
        .or_else(|| {
            normalize_optional_text(requested_provider).map(|provider| {
                crate::gateway::provider_catalog::normalized_provider_alias(&provider)
            })
        })
        .or_else(|| model_hint.and_then(infer_provider_from_model))
}

pub(crate) fn runtime_resolved_provider(
    target: Option<&crate::gateway::providers::ProviderTarget>,
    upstream_base: &str,
    model_hint: Option<&str>,
) -> Option<String> {
    let resolved = canonical_provider_slug(target, upstream_base, model_hint.unwrap_or_default());
    normalize_optional_text(Some(resolved.as_str()))
}

pub(crate) fn resolve_spend_pricing(
    context: &SpendLogContext<'_>,
    target: Option<&crate::gateway::providers::ProviderTarget>,
    provider: &str,
    model: &str,
    usage: SpendUsage,
) -> ResolvedSpendPricing {
    if usage.prompt_cost.is_some() || usage.completion_cost.is_some() || usage.total_cost.is_some()
    {
        return ResolvedSpendPricing {
            source: Some(PricingSource::Upstream),
            snapshot: Some(serde_json::json!({ "source": "upstream" })),
            ..ResolvedSpendPricing::default()
        };
    }

    if let Some(pricing) = configured_target_pricing(context.provider_registry, target, model) {
        let canonical_model_id = target
            .and_then(|candidate| {
                let target_model = candidate.model.trim();
                (!target_model.is_empty() && target_model != "*").then(|| target_model.to_string())
            })
            .unwrap_or_else(|| model.to_string());
        let input_price_per_million = pricing.input_price_per_million;
        let output_price_per_million = pricing.output_price_per_million;
        let cached_input_price_per_million = pricing.cached_input_price_per_million;
        return ResolvedSpendPricing {
            pricing: Some(pricing),
            source: Some(PricingSource::ConfigDeclared),
            snapshot: Some(serde_json::json!({
                "source": "config_declared",
                "provider": provider,
                "model_id": canonical_model_id.clone(),
                "provider_target_id": target.map(|candidate| candidate.id.clone()),
                "input_price_per_million": input_price_per_million,
                "output_price_per_million": output_price_per_million,
                "cached_input_price_per_million": cached_input_price_per_million,
            })),
            canonical_model_id: Some(canonical_model_id),
            ..ResolvedSpendPricing::default()
        };
    }

    if let Some(resolved) = catalog_spend_pricing(context, provider, model, target) {
        return resolved;
    }

    ResolvedSpendPricing::default()
}

pub(crate) fn catalog_price_per_million(value: &str) -> Option<(String, f64)> {
    let exact = crate::gateway::provider_catalog::parse_exact_catalog_price(value).ok()?;
    let per_million = (exact * BigDecimal::from(10_000_i64)).normalized();
    let runtime_value = per_million.to_f64().filter(|value| value.is_finite())?;
    Some((per_million.to_string(), runtime_value))
}

pub(crate) fn catalog_spend_pricing(
    context: &SpendLogContext<'_>,
    provider: &str,
    model: &str,
    target: Option<&crate::gateway::providers::ProviderTarget>,
) -> Option<ResolvedSpendPricing> {
    let normalized_provider = crate::gateway::provider_catalog::normalized_provider_alias(provider);
    let provider_prefix = format!("{normalized_provider}/");
    let normalized_model = model
        .strip_prefix(provider_prefix.as_str())
        .unwrap_or(model)
        .trim();
    if normalized_provider.is_empty() || normalized_model.is_empty() {
        return None;
    }

    let catalog_model =
        context.catalog_snapshot.models.iter().find(|entry| {
            entry.provider_id == normalized_provider && entry.id == normalized_model
        })?;

    let input_token_price = catalog_model.input_token_price.as_deref()?;
    let output_token_price = catalog_model.output_token_price.as_deref()?;
    let (input_price_per_million_exact, input_price_per_million) =
        catalog_price_per_million(input_token_price)?;
    let (output_price_per_million_exact, output_price_per_million) =
        catalog_price_per_million(output_token_price)?;
    let cached_price = match catalog_model.cached_input_read_price.as_deref() {
        Some(value) => Some(catalog_price_per_million(value)?),
        None => None,
    };
    let cached_input_price_per_million_exact =
        cached_price.as_ref().map(|(exact, _)| exact.clone());
    let cached_input_price_per_million = cached_price.map(|(_, runtime)| runtime);
    let pricing = ProviderPricing {
        input_price_per_million,
        output_price_per_million,
        cached_input_price_per_million,
        input_multiplier: None,
        cached_input_multiplier: None,
        output_multiplier: None,
    };
    let provider_target_id = target.map(|candidate| candidate.id.clone());

    Some(ResolvedSpendPricing {
        pricing: Some(pricing),
        source: Some(PricingSource::Catalog),
        snapshot: Some(serde_json::json!({
            "source": "catalog",
            "catalog_version": context.catalog_snapshot.version,
            "provider": normalized_provider,
            "model_id": catalog_model.id.as_str(),
            "provider_target_id": provider_target_id,
            "price_unit": "cents_per_token",
            "input_token_price": input_token_price,
            "output_token_price": output_token_price,
            "cached_input_read_price": catalog_model.cached_input_read_price.as_deref(),
            "input_price_per_million": input_price_per_million_exact,
            "output_price_per_million": output_price_per_million_exact,
            "cached_input_price_per_million": cached_input_price_per_million_exact.as_deref(),
        })),
        canonical_model_id: Some(catalog_model.id.clone()),
        catalog_input_price: Some(input_token_price.to_string()),
        catalog_output_price: Some(output_token_price.to_string()),
        catalog_model_id: Some(catalog_model.id.clone()),
        catalog_provider_id: Some(catalog_model.provider_id.clone()),
        catalog_pricing_source: Some("catalog".to_string()),
    })
}

pub(crate) fn configured_target_pricing(
    provider_registry: Option<&crate::gateway::providers::ProviderRegistry>,
    target: Option<&crate::gateway::providers::ProviderTarget>,
    model: &str,
) -> Option<ProviderPricing> {
    let target = target?;
    if !target.models.is_empty() {
        return provider_registry
            .and_then(|registry| registry.resolve_model_pricing(target, model))
            .or_else(|| target.pricing.clone());
    }

    target.pricing.clone()
}

pub(crate) fn canonical_provider_slug(
    target: Option<&crate::gateway::providers::ProviderTarget>,
    upstream_base: &str,
    model: &str,
) -> String {
    target
        .and_then(|candidate| canonical_provider_from_target(candidate, model))
        .or_else(|| infer_provider_from_model(model))
        .unwrap_or_else(|| infer_provider_from_upstream(upstream_base))
}

pub(crate) fn canonical_provider_from_target(
    target: &crate::gateway::providers::ProviderTarget,
    model: &str,
) -> Option<String> {
    use crate::gateway::provider_auth::ProviderType;

    match target.provider_type {
        Some(ProviderType::AwsBedrock) => infer_provider_from_model(model)
            .or_else(|| canonical_provider_from_provider_id(&target.provider, model))
            .or_else(|| Some("aws-bedrock".to_string())),
        Some(ProviderType::GoogleAiStudio) | Some(ProviderType::GoogleVertex) => {
            Some("google".to_string())
        }
        Some(ProviderType::AzureOpenAI) => Some("azure-openai".to_string()),
        Some(ProviderType::OpenAI) => Some("openai".to_string()),
        Some(ProviderType::Anthropic) => Some("anthropic".to_string()),
        Some(ProviderType::Cohere) => Some("cohere".to_string()),
        Some(ProviderType::Generic) | None => {
            canonical_provider_from_provider_id(&target.provider, model)
                .or_else(|| infer_provider_from_model(model))
        }
        Some(other) => canonical_provider_from_provider_id(other.as_str(), model)
            .or_else(|| canonical_provider_from_provider_id(&target.provider, model)),
    }
}

pub(crate) fn canonical_provider_from_provider_id(provider: &str, model: &str) -> Option<String> {
    let base = provider.split(':').next()?.trim().to_ascii_lowercase();
    match base.as_str() {
        "openai" => Some("openai".to_string()),
        "anthropic" => Some("anthropic".to_string()),
        "cohere" => Some("cohere".to_string()),
        "google-ai-studio" | "google-vertex" => Some("google".to_string()),
        "azure-openai" => Some("azure-openai".to_string()),
        "mistral" | "mistralai" => Some("mistral".to_string()),
        "meta" | "meta-llama" => Some("meta".to_string()),
        "amazon" => Some("amazon".to_string()),
        "deepseek" => Some("deepseek".to_string()),
        "groq" => Some("groq".to_string()),
        "together" => Some("together".to_string()),
        "fireworks" => Some("fireworks".to_string()),
        "perplexity" => Some("perplexity".to_string()),
        "xai" | "x-ai" => Some("xai".to_string()),
        "aws-bedrock" => {
            infer_provider_from_model(model).or_else(|| Some("aws-bedrock".to_string()))
        }
        _ => None,
    }
}

pub(crate) fn infer_provider_from_model(model: &str) -> Option<String> {
    let normalized = model.trim().to_ascii_lowercase();
    let prefix = normalized
        .split(['.', '/', ':'])
        .next()
        .unwrap_or(normalized.as_str());

    match prefix {
        "openai" => Some("openai".to_string()),
        "anthropic" => Some("anthropic".to_string()),
        "cohere" => Some("cohere".to_string()),
        "mistral" | "mistralai" => Some("mistral".to_string()),
        "meta" | "meta-llama" => Some("meta".to_string()),
        "amazon" => Some("amazon".to_string()),
        "gemini" => Some("google".to_string()),
        "deepseek" => Some("deepseek".to_string()),
        "groq" => Some("groq".to_string()),
        _ if normalized.starts_with("gpt-")
            || normalized.starts_with("o1")
            || normalized.starts_with("o3") =>
        {
            Some("openai".to_string())
        }
        _ if normalized.starts_with("claude") => Some("anthropic".to_string()),
        _ if normalized.starts_with("deepseek") => Some("deepseek".to_string()),
        _ => None,
    }
}

pub(crate) fn infer_provider_from_upstream(upstream_base: &str) -> String {
    let host = provider_name_from_upstream(upstream_base).to_ascii_lowercase();
    if host.contains("openai") {
        return "openai".to_string();
    }
    if host.contains("anthropic") {
        return "anthropic".to_string();
    }
    if host.contains("cohere") {
        return "cohere".to_string();
    }
    if host.contains("google") || host.contains("gemini") {
        return "google".to_string();
    }
    if host.contains("mistral") {
        return "mistral".to_string();
    }
    if host.contains("azure") {
        return "azure-openai".to_string();
    }
    if host.contains("github") {
        return "github".to_string();
    }
    if host.contains("groq") {
        return "groq".to_string();
    }
    if host.contains("together") {
        return "together".to_string();
    }
    if host.contains("fireworks") {
        return "fireworks".to_string();
    }
    if host.contains("deepseek") {
        return "deepseek".to_string();
    }
    if host.contains("perplexity") {
        return "perplexity".to_string();
    }
    if host.contains("x.ai") || host == "api.x.ai" {
        return "xai".to_string();
    }
    host
}

pub(crate) fn sha256_prefixed(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Phase 15: translate a buffered upstream response body from `from_format` to `to_format`.
pub(crate) fn translate_buffered_response_format(
    resp: crate::gateway::cache::BufferedUpstreamResponse,
    from_format: crate::gateway::format_translation::ProviderFormat,
    to_format: crate::gateway::format_translation::ProviderFormat,
    path: &str,
) -> crate::gateway::cache::BufferedUpstreamResponse {
    if from_format == to_format {
        return resp;
    }
    let Ok(body_val) = serde_json::from_slice::<serde_json::Value>(resp.body()) else {
        return crate::gateway::provider_pipeline::ProviderPipelineError {
            status: StatusCode::BAD_GATEWAY,
            error_type: "server_error",
            code: "provider_response_invalid_json",
            message: "provider response was not valid JSON".to_string(),
        }
        .to_buffered_response();
    };
    let translated = if path == "/v1/responses" {
        crate::gateway::format_translation::translate_response_for_path(body_val, from_format, path)
    } else {
        crate::gateway::format_translation::translate_response(body_val, from_format, to_format)
    };
    let Ok(translated) = translated else {
        return crate::gateway::provider_pipeline::ProviderPipelineError {
            status: StatusCode::BAD_GATEWAY,
            error_type: "server_error",
            code: "provider_response_translation_failed",
            message: "provider response translation failed".to_string(),
        }
        .to_buffered_response();
    };
    let Ok(new_bytes) = serde_json::to_vec(&translated) else {
        return crate::gateway::provider_pipeline::ProviderPipelineError {
            status: StatusCode::BAD_GATEWAY,
            error_type: "server_error",
            code: "provider_response_serialization_failed",
            message: "translated provider response could not be serialized".to_string(),
        }
        .to_buffered_response();
    };
    crate::gateway::cache::BufferedUpstreamResponse::new(
        resp.status(),
        resp.headers().clone(),
        Bytes::from(new_bytes),
        resp.is_cached(),
    )
}
