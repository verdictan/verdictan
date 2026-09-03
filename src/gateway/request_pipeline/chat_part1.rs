// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Family request-pipeline module.
//! Child of `gateway::server`; parent private items remain visible.
use super::super::*;
use super::*;

pub(crate) async fn execute_chat_completions_with_state(
    mut state: ActiveGatewayStateView<'_>,
    peer_ip: std::net::IpAddr,
    mut headers: HeaderMap,
    request: Request<Body>,
    request_id: String,
    traceparent: String,
    start: Instant,
) -> Result<Response<Body>, StatusCode> {
    state.session_id = headers
        .get(
            state
                .runtime_routing_settings
                .cache_defaults
                .session_header_name
                .as_str(),
        )
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Phase 5: extract workflow lineage context from incoming headers.
    // X-Workflow-Id and X-Lineage-Id are propagated by callers that want
    // their requests correlated into a logical workflow trace.
    let workflow_lineage_ctx = crate::gateway::tracing::workflow_spans::WorkflowLineageContext {
        workflow_id: headers
            .get("x-workflow-id")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned),
        lineage_id: headers
            .get("x-lineage-id")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned),
        traceparent: traceparent.clone(),
        request_id: request_id.clone(),
        gateway_id: state.gateway_id.as_deref().map(ToString::to_string),
    };
    if workflow_lineage_ctx.has_workflow_context() {
        tracing::debug!(
            workflow_id = workflow_lineage_ctx.workflow_id.as_deref().unwrap_or(""),
            lineage_id = workflow_lineage_ctx.lineage_id.as_deref().unwrap_or(""),
            request_id = %request_id,
            "workflow lineage context attached to request"
        );
    }

    let chain_has_hipaa = state.policy_chain.iter().any(|k| k == "hipaa-phi-detector");
    let chain_has_pii = state.policy_chain.iter().any(|k| k == "pii-detector");
    let chain_has_dlp = state.policy_chain.iter().any(|k| k == "dlp-filter");
    let chain_has_student_privacy = state.policy_chain.iter().any(|k| k == "student-privacy");
    let chain_has_case_privacy = state.policy_chain.iter().any(|k| k == "case-privacy");
    let redaction_cfg = build_prompt_redaction_config(&state.policy_chain, &state.policy_blocks);

    let request_resolution = resolve_request("/v1/chat/completions", "POST", &headers, &state);
    let cg_rl_info = match enforce_consumer_group_rate_limit(
        &state,
        &request_id,
        request_resolution.consumer_group.as_ref(),
    ) {
        Ok(info) => info,
        Err(response) => return Ok(response),
    };

    let original_body_bytes = axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;

    // Phase 20: request size limit check (body, headers, URL).
    if let Some(sl) = state.size_limit.as_ref() {
        let header_len = crate::gateway::size_limit::headers_byte_len(&headers);
        let url_len = "/v1/chat/completions".len();
        if let Err(err) = sl.check(original_body_bytes.len(), header_len, url_len) {
            tracing::warn!(
                request_id = %request_id,
                kind = %err.kind,
                actual = err.actual,
                limit = err.limit,
                "request size limit exceeded"
            );
            let body = serde_json::json!({
                "error": error_json(
                    &format!("Request {} exceeds size limit ({} > {} bytes)", err.kind, err.actual, err.limit),
                    "invalid_request_error",
                    "request_too_large",
                ),
                "rejected_by": "size_limit",
                "limit_kind": err.kind.to_string(),
            });
            let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
            let response = Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Rejected-By", "size_limit")
                .header("X-Request-Id", &request_id)
                .header("traceparent", &traceparent)
                .body(Body::from(text))
                .unwrap_or_default();
            return Ok(response);
        }
    }

    let prompt_hash = sha256_prefixed(&original_body_bytes);

    let mut parsed_json: serde_json::Value = match serde_json::from_slice(&original_body_bytes) {
        Ok(v) => v,
        Err(_e) => {
            let latency_ms = start.elapsed().as_millis() as i64;
            let verdictan = verdictan_extension_json(
                "BLOCK",
                "invalid_json",
                &state.config_version,
                &request_id,
                latency_ms,
                None,
                None,
            );
            let body = serde_json::json!({
                "error": error_json(
                    "Invalid JSON body",
                    "invalid_request_error",
                    "invalid_json",
                ),
                "verdictan": verdictan,
            });
            let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
            return Ok(build_response(
                StatusCode::BAD_REQUEST,
                HeaderValue::from_static("application/json"),
                request_id,
                traceparent,
                Bytes::from(text),
                false,
                Some(verdictan_headers(
                    "BLOCK",
                    "invalid_json",
                    &state.config_version,
                    latency_ms,
                    false,
                    &[],
                    None,
                    false,
                    None,
                )),
            ));
        }
    };

    inject_identity_headers_from_finops(&mut headers, state.request_finops.as_ref());

    let conversation_id = headers
        .get("x-conversation-id")
        .and_then(|v| v.to_str().ok());
    let request_agent_id = match normalize_request_agent_id(request_agent_id_header_value(&headers))
    {
        Ok(agent_id) => agent_id,
        Err(message) => {
            let body = serde_json::json!({
                "error": error_json(message, "invalid_request_error", "invalid_agent_id")
            });
            let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
            return Ok(build_response(
                StatusCode::BAD_REQUEST,
                HeaderValue::from_static("application/json"),
                request_id,
                traceparent,
                Bytes::from(text),
                false,
                None,
            ));
        }
    };
    let git_context = git_context_from_headers(&headers);
    let (mut session_context, resolved_agent_id, applied_agent_context, reuse_outcome) =
        apply_runtime_recall(
            &state,
            &mut parsed_json,
            false,
            conversation_id,
            &request_id,
            &traceparent,
            request_agent_id.as_deref(),
            git_context,
        )
        .await;
    state.current_agent_id = resolved_agent_id;
    state.apply_agent_overrides();
    if let Some(context) = applied_agent_context.as_ref() {
        state
            .request_finops
            .get_or_insert_with(RequestFinopsContext::default)
            .apply_context_selection(&context.telemetry);
    }
    if let Some(outcome) = reuse_outcome.as_ref() {
        state
            .request_finops
            .get_or_insert_with(RequestFinopsContext::default)
            .apply_work_reuse(outcome);
    }
    let recall_attribution = applied_agent_context
        .as_ref()
        .and_then(build_recall_attribution);
    let context_fabric_policy = resolved_context_fabric_response_policy(&state);
    if let Err(response) =
        enforce_connected_deployed_agent_link(&state, &request_id, &traceparent).await
    {
        return Ok(response);
    }
    if let Err(error) = resolve_runtime_request_settings(&mut state, &headers, &mut parsed_json) {
        return Ok(runtime_routing_error_response(
            &error,
            &request_id,
            &traceparent,
        ));
    }
    if state.session_id.is_none() {
        state.session_id = session_context
            .as_ref()
            .map(|session| session.session_id.clone());
    } else if let (Some(ref override_id), Some(ref mut ctx)) =
        (state.session_id.as_ref(), session_context.as_mut())
    {
        ctx.session_id = override_id.to_string();
    }

    let trace_correlation = extract_trace_correlation(&parsed_json);
    let request_telemetry_hints = extract_request_telemetry_hints(&parsed_json);
    let stream_requested = crate::gateway::sse::stream_requested(&parsed_json);
    tracing::debug!(
        request_id = %request_id,
        connected_mode = state.connected_mode,
        streaming = stream_requested,
        "chat completions response mode resolved"
    );
    let include_usage_in_stream = parsed_json
        .get("stream_options")
        .and_then(|o| o.get("include_usage"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut body_bytes = serde_json::to_vec(&parsed_json)
        .map(Bytes::from)
        .unwrap_or_else(|_| original_body_bytes.clone());
    let mut redaction_applied = false;
    let response_redactions: Vec<crate::gateway::redaction::VerdictanRedaction> = Vec::new();
    let quality_scores_for_event: Option<serde_json::Value> = None;
    let review_result_for_event: Option<serde_json::Value> = None;

    // Run policy enforcement if chain is configured.
    // Note: we delay emitting the decision event until we know the *final* verdict
    // (some policies are evaluated after the upstream response).
    let messages_for_eval: Arc<[enforcement::ChatMessage]> =
        Arc::from(extract_messages_from_value(Some(&parsed_json)));

    // Phase 16/17: resolve route-scoped chain or fall back to global chain.
    // SEC-009: team selectors come from authenticated finops memberships;
    // X-Verdictan-Team is only a local unauthenticated profile selector.
    let request_team_slugs = resolve_request_team_slugs(
        &headers,
        state.request_finops.as_ref(),
        !state.connected_mode,
    );
    let active_chain =
        effective_chain_for_request(&state, &request_resolution, &request_team_slugs);

    let mut decision = if !active_chain.is_empty() {
        let policy_headers = policy_input_headers(&headers, state.request_finops.as_ref());
        async {
            enforcement::evaluate_chain_entries_with_identity(
                &active_chain,
                "/v1/chat/completions",
                &state.policy_blocks,
                Some(&parsed_json),
                &policy_headers,
                &messages_for_eval,
                state
                    .request_finops
                    .as_ref()
                    .and_then(|finops| finops.authenticated_identity.as_ref()),
            )
            .await
        }
        .instrument(proxy_phase_span(
            "policy_input_evaluation",
            &request_id,
            &traceparent,
            "policy.input_evaluation",
            &trace_correlation,
        ))
        .await
    } else {
        DecisionEnvelope {
            final_verdict: Verdict::Allow,
            reason_code: "ok".to_string(),
            results: Vec::new(),
        }
    };

    // Phase 5: emit enforcement lineage span for workflow-tracked requests.
    // Covers the input policy evaluation outcome. Only emitted when the
    // request carries a workflow context to avoid tracing overhead on
    // untracked traffic.
    if workflow_lineage_ctx.has_workflow_context() {
        enforcement::emit_enforcement_lineage_span(&workflow_lineage_ctx, &decision);
    }

    if decision.final_verdict == Verdict::Block {
        let latency_ms = start.elapsed().as_millis() as i64;
        if let Some(sink) = &state.event_sink {
            let mut event = decision_event_json(
                &state.config_version,
                &request_id,
                &decision,
                false,
                false,
                prompt_hash.clone(),
                None,
                state.registered_agent_id(),
                state.request_finops.as_ref(),
                state.session_id.as_deref(),
            );
            let (request_payload_for_event, response_payload_for_event) =
                silent_engine_event_payloads(
                    &state,
                    serde_json::from_slice::<serde_json::Value>(&body_bytes).ok(),
                    None,
                );
            enrich_decision_event_details(
                &mut event,
                request_payload_for_event,
                response_payload_for_event,
                "POST",
                StatusCode::BAD_REQUEST,
                decision_runtime_json(&state, "/v1/chat/completions", false),
                &trace_correlation,
            );
            apply_silent_engine_event_sanitization(&state, &mut event);
            async {
                sink.enqueue_decision(&request_id, event);
            }
            .instrument(proxy_phase_span(
                "decision_event_emit",
                &request_id,
                &traceparent,
                "event.emit",
                &trace_correlation,
            ))
            .await;
        }

        let mut verdictan = verdictan_extension_json(
            "BLOCK",
            &decision.reason_code,
            &state.config_version,
            &request_id,
            latency_ms,
            None,
            None,
        );
        inject_context_fabric_verdictan_metadata(
            &mut verdictan,
            state.request_finops.as_ref(),
            recall_attribution.as_ref(),
            &context_fabric_policy.capture_mode,
            None,
        );
        let body = serde_json::json!({
            "error": error_json(
                &format!("Request blocked by policy: {}", decision.reason_code),
                "invalid_request_error",
                "content_policy_violation",
            ),
            "verdictan": verdictan,
        });

        let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        let mut response_headers = verdictan_headers(
            "BLOCK",
            &decision.reason_code,
            &state.config_version,
            latency_ms,
            false,
            &[],
            None,
            false,
            verdictan_rbac_details(&decision),
        );
        append_context_response_headers(&mut response_headers, recall_attribution.as_ref(), None);
        return Ok(build_response(
            StatusCode::BAD_REQUEST,
            HeaderValue::from_static("application/json"),
            request_id,
            traceparent,
            Bytes::from(text),
            false,
            Some(response_headers),
        ));
    }

    if decision.final_verdict == Verdict::Escalate {
        let latency_ms = start.elapsed().as_millis() as i64;
        let mut escalation_confirmed = false;
        if let Some(sink) = &state.event_sink {
            let mut event = decision_event_json(
                &state.config_version,
                &request_id,
                &decision,
                false,
                false,
                prompt_hash.clone(),
                None,
                state.registered_agent_id(),
                state.request_finops.as_ref(),
                state.session_id.as_deref(),
            );

            // Inject escalation routing hint from the provider registry config.
            let requested_model = parsed_json.get("model").and_then(|v| v.as_str());
            if let (Some(registry), Some(model)) = (&state.provider_registry, requested_model) {
                if let Some(routing) = registry.resolve_escalation_routing_for_model(model) {
                    let hint = serde_json::json!({
                        "team_id": routing.team_id,
                        "user_id": routing.user_id,
                    });
                    if let Some(obj) = event.as_object_mut() {
                        let metadata = obj
                            .entry("metadata")
                            .or_insert_with(|| serde_json::json!({}));
                        if let Some(meta_obj) = metadata.as_object_mut() {
                            meta_obj.insert("escalation_routing".to_string(), hint);
                        }
                    }
                }
            }

            let (request_payload_for_event, response_payload_for_event) =
                silent_engine_event_payloads(
                    &state,
                    serde_json::from_slice::<serde_json::Value>(&body_bytes).ok(),
                    None,
                );
            enrich_decision_event_details(
                &mut event,
                request_payload_for_event,
                response_payload_for_event,
                "POST",
                StatusCode::OK,
                decision_runtime_json(&state, "/v1/chat/completions", false),
                &trace_correlation,
            );
            apply_silent_engine_event_sanitization(&state, &mut event);
            if async { sink.ingest_event(&request_id, &traceparent, event).await }
                .instrument(proxy_phase_span(
                    "decision_event_emit",
                    &request_id,
                    &traceparent,
                    "event.emit",
                    &trace_correlation,
                ))
                .await
                .is_ok()
            {
                escalation_confirmed = true;
            }
        }

        // The API derives escalation_id as `esc_<request_id>` on ingest.
        let escalation_id = format!("esc_{}", request_id);
        let mut verdictan = verdictan_extension_json(
            "ESCALATE",
            &decision.reason_code,
            &state.config_version,
            &request_id,
            latency_ms,
            Some(serde_json::json!({
                "id": escalation_id,
                "status": "queued",
                "created": escalation_confirmed,
            })),
            None,
        );
        inject_context_fabric_verdictan_metadata(
            &mut verdictan,
            state.request_finops.as_ref(),
            recall_attribution.as_ref(),
            &context_fabric_policy.capture_mode,
            None,
        );
        let body = serde_json::json!({
            "id": format!("chatcmpl-verdictan-{request_id}"),
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": serde_json::Value::Null },
                "finish_reason": "content_filter"
            }],
            "verdictan": verdictan,
        });

        let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        let mut response_headers = verdictan_headers(
            "ESCALATE",
            &decision.reason_code,
            &state.config_version,
            latency_ms,
            false,
            &[],
            None,
            false,
            verdictan_rbac_details(&decision),
        );
        append_context_response_headers(&mut response_headers, recall_attribution.as_ref(), None);
        return Ok(build_response(
            StatusCode::OK,
            HeaderValue::from_static("application/json"),
            request_id,
            traceparent,
            Bytes::from(text),
            false,
            Some(response_headers),
        ));
    }

    // Apply request-only redaction before forwarding, if any pre-policy requested redaction.
    // CLI-FIND-MED-002: Use route-scoped active_chain instead of global policy_chain.
    if active_chain
        .iter()
        .any(|entry| entry.kind() == "request-rewriter")
    {
        if let Some(cfg) = state.policy_blocks.get("request-rewriter") {
            let rewrite_eval = async {
                crate::gateway::request_rewrite::evaluate_request_rewriter(&parsed_json, cfg)
            }
            .instrument(proxy_phase_span(
                "policy_input_request_rewrite",
                &request_id,
                &traceparent,
                "policy.input_request_rewrite",
                &trace_correlation,
            ))
            .await;

            if let Some(rewritten) = rewrite_eval.rewritten_request {
                if let Ok(bytes) = serde_json::to_vec(&rewritten) {
                    body_bytes = Bytes::from(bytes);
                }
            }
            decision.results.push(rewrite_eval.policy_result);
        }
    }

    if decision
        .results
        .iter()
        .any(|r| r.verdict == Verdict::Redact)
    {
        async {
            let mut v = serde_json::from_slice::<serde_json::Value>(&body_bytes)
                .unwrap_or_else(|_| parsed_json.clone());
            let applied = redact_request_messages(&mut v, &redaction_cfg);
            if applied {
                if let Ok(bytes) = serde_json::to_vec(&v) {
                    body_bytes = Bytes::from(bytes);
                    redaction_applied = true;
                }
            }
        }
        .instrument(proxy_phase_span(
            "policy_input_redaction",
            &request_id,
            &traceparent,
            "policy.input_redaction",
            &trace_correlation,
        ))
        .await;
    }

    // Gateway-only request extensions must not be forwarded upstream.
    let mut upstream_body_bytes = body_bytes.clone();
    if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&upstream_body_bytes) {
        let _ = strip_verdictan_request_extension(&mut value);
        if !stream_requested {
            crate::gateway::sse::disable_stream_flag(&mut value);
        }
        if let Ok(bytes) = serde_json::to_vec(&value) {
            upstream_body_bytes = Bytes::from(bytes);
        }
    }

    let selected_fabric_slices = if stream_requested {
        Vec::new()
    } else {
        retrieve_request_fabric_slices(&state, &headers, &parsed_json, &request_id).await
    };
    if !selected_fabric_slices.is_empty() {
        if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&upstream_body_bytes) {
            if crate::gateway::codebase_context::inject_fabric_slices_into_request(
                &mut value,
                &selected_fabric_slices,
            ) {
                if let Ok(bytes) = serde_json::to_vec(&value) {
                    upstream_body_bytes = Bytes::from(bytes);
                }
            }
        }
    }

    let provider_cache_context = serde_json::from_slice::<serde_json::Value>(&upstream_body_bytes)
        .ok()
        .and_then(|value| extract_provider_cache_context(&value));
    let request_model = parsed_json
        .get("model")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let estimated_prompt_tokens =
        crate::gateway::token_estimation::estimate_prompt_tokens(&parsed_json).unwrap_or(0) as u64;
    let estimated_max_completion =
        extract_requested_max_tokens(&parsed_json).unwrap_or(4096) as u64;
    // for connected AUTO-routing requests, evaluate every
    // routing candidate READ-ONLY and record the denied ones BEFORE the sync
    // selection runs, so `resolve_auto_target` (preflight + pricing) and
    // `resolve_initial_provider_order` (send) never auto-select a provider/model
    // the subject is not allowed to use. No-op (byte-identical) for
    // explicit-model or non-connected requests; zero financial side effect.
    if state.connected_mode
        && state.auto_provider.enabled
        && request_model == state.auto_provider.name
    {
        populate_ua_denied_target_ids(
            &mut state,
            crate::gateway::usage_authorization::UsageAuthorizationRequestFamily::Chat,
            request_model,
            estimated_prompt_tokens,
            estimated_max_completion,
            &request_id,
        )
        .await;
    }
    let connected_access_status = match maybe_prime_connected_access_versions(
        &mut state,
        request_model,
        estimated_prompt_tokens,
        estimated_max_completion,
        &request_id,
    )
    .await
    {
        Ok(status) => status,
        Err(response) => return Ok(response),
    };
    let task_class = crate::gateway::task_classification::classify_request(&parsed_json, &headers);
    let cache_tier = resolve_cache_tier(
        &state,
        &headers,
        task_class,
        provider_cache_context.as_ref(),
    );
    let provider_cache_key =
        if task_class == crate::gateway::task_classification::TaskClass::ReadOnly {
            build_provider_cache_key(
                &state,
                &headers,
                "/v1/chat/completions",
                &upstream_body_bytes,
                provider_cache_context.as_ref(),
                task_class,
            )
        } else {
            None
        };
    // read-only usage-authorization policy gate. Runs after
    // trusted resolution and BEFORE the semantic-cache lookup; denies with 403
    // `usage_authorization_denied` on a restricted-denied decision without opening
    // the cache or upstream. Evaluate-only: no authorization/quota/spend/ticket.
    let ua_eval_document = match enforce_usage_authorization_evaluate_gate(
        &state,
        crate::gateway::usage_authorization::UsageAuthorizationRequestFamily::Chat,
        request_model,
        estimated_prompt_tokens,
        estimated_max_completion,
        &request_id,
        &traceparent,
    )
    .await
    {
        Ok(document) => document,
        Err(response) => return Ok(response),
    };
    state.ua_eval_document = ua_eval_document;
    let ua_financial_path_active = ua_financial_path_active(&state)
        && connected_access_status
            .admission_credential_source
            .is_some()
        && !connected_access_status.dispatch_precluded;
    let ua_admission_credential_source = connected_access_status.admission_credential_source;
    let selected_fabric_artifact_ids =
        crate::gateway::codebase_context::selected_artifact_ids(&selected_fabric_slices);
    let selected_fabric_source_digests =
        crate::gateway::codebase_context::selected_source_digests(&selected_fabric_slices);
    let mut cache_replay_metadata = (task_class
        != crate::gateway::task_classification::TaskClass::ReadOnly)
        .then(|| CacheReplayMetadata {
            outcome: CacheReplayOutcome::DeniedReplay,
            cache_tier,
            cache_key_digest: None,
            selected_fabric_artifact_ids: selected_fabric_artifact_ids.clone(),
            selected_fabric_source_digests: selected_fabric_source_digests.clone(),
        });
    let early_cached_response = if stream_requested || ua_financial_path_active {
        None
    } else {
        lookup_provider_cache_only(
            &state,
            provider_cache_key.as_deref(),
            &upstream_body_bytes,
            &request_id,
            &traceparent,
            &trace_correlation,
        )
        .await
    };
    if let Some(outcome) = early_cached_response.as_ref().map(|hit| hit.outcome) {
        cache_replay_metadata = Some(CacheReplayMetadata {
            outcome,
            cache_tier,
            cache_key_digest: provider_cache_key.clone(),
            selected_fabric_artifact_ids: selected_fabric_artifact_ids.clone(),
            selected_fabric_source_digests: selected_fabric_source_digests.clone(),
        });
    } else if provider_cache_key.is_some() && !selected_fabric_slices.is_empty() {
        cache_replay_metadata = Some(CacheReplayMetadata {
            outcome: CacheReplayOutcome::SemanticCandidate,
            cache_tier,
            cache_key_digest: provider_cache_key.clone(),
            selected_fabric_artifact_ids: selected_fabric_artifact_ids.clone(),
            selected_fabric_source_digests: selected_fabric_source_digests.clone(),
        });
    }

    let connected_access_dispatch_ctx = if ua_financial_path_active {
        ConnectedAccessDispatchContext::default()
    } else {
        match maybe_prepare_connected_access_dispatch(
            &mut state,
            &headers,
            &parsed_json,
            &request_id,
            &traceparent,
            &prompt_hash,
            extract_requested_max_tokens(&parsed_json).unwrap_or(4096) as u64,
            if early_cached_response.is_none() {
                connected_access_status.admission_credential_source
            } else {
                None
            },
            early_cached_response.is_some() || connected_access_status.dispatch_precluded,
        )
        .await
        {
            Ok(context) => context,
            Err(response) => return Ok(response),
        }
    };

    if stream_requested {
        if ua_financial_path_active {
            if let Err(response) = prepare_ua_financial_lifecycle(
                &mut state,
                &headers,
                &parsed_json,
                &upstream_body_bytes,
                &request_id,
                &traceparent,
                estimated_prompt_tokens,
                estimated_max_completion,
                ua_admission_credential_source,
                "/v1/chat/completions",
                crate::gateway::usage_authorization::UsageAuthorizationRequestFamily::Chat,
            )
            .await
            {
                return Ok(response);
            }
        }
        let ua_authorization_id_for_stream = state.ua_authorization_id.clone();
        let ua_dispatch_acquired_for_stream = state.ua_dispatch_acquired;
        let ua_financial_for_stream = ua_financial_path_active;
        if let Err(response) = persist_admitted_decision_before_dispatch(
            &state,
            &request_id,
            &traceparent,
            &decision,
            &prompt_hash,
            "/v1/chat/completions",
        ) {
            return Ok(response);
        }
        let (upstream_resp, fallback_provider_id) = send_streaming_with_provider_fallback(
            &state,
            &headers,
            "/v1/chat/completions",
            upstream_body_bytes.clone(),
            &request_id,
            &traceparent,
            &trace_correlation,
            &request_telemetry_hints,
            session_context.as_ref(),
        )
        .await;
        if let Some(ref pid) = fallback_provider_id {
            state.current_target_id = Some(pid.clone());
        }

        match upstream_resp {
            Ok(response) => {
                let status = response.status;
                let content_type = response.content_type;

                if !status.is_success() {
                    let body = collect_prepared_stream_body(response.body).await;
                    if matches!(state.fail_mode, FailMode::Allow)
                        && is_provider_transport_exhaustion_response(status, &body)
                    {
                        let latency_ms = start.elapsed().as_millis() as i64;
                        let verdictan = verdictan_extension_json(
                            "ALLOW",
                            "proxy.degraded_allow",
                            &state.config_version,
                            &request_id,
                            latency_ms,
                            None,
                            None,
                        );
                        let body = serde_json::json!({
                            "id": format!("chatcmpl_{}", request_id),
                            "object": "chat.completion",
                            "created": 0,
                            "model": "degraded",
                            "choices": [{
                                "index": 0,
                                "message": { "role": "assistant", "content": "Upstream unavailable; fail-open mode returned a degraded placeholder response." },
                                "finish_reason": "stop"
                            }],
                            "verdictan": verdictan,
                        });
                        return Ok(build_response(
                            StatusCode::OK,
                            HeaderValue::from_static("application/json"),
                            request_id,
                            traceparent,
                            Bytes::from(
                                serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
                            ),
                            true,
                            None,
                        ));
                    }
                    if ua_financial_for_stream {
                        schedule_finalize_ua_streaming_financial_lifecycle(
                            ua_authorization_id_for_stream.clone(),
                            ua_dispatch_acquired_for_stream,
                            state.event_sink.clone(),
                            upstream_body_bytes.clone(),
                            None,
                            0,
                            true,
                            state.current_agent_id.clone(),
                            ua_org_id_from_finops(state.request_finops.as_ref()),
                            &request_id,
                            &traceparent,
                        );
                    }
                    return Ok(build_response(
                        status,
                        content_type,
                        request_id,
                        traceparent,
                        body,
                        false,
                        None,
                    ));
                }

                let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(16);
                let request_id_for_task = request_id.clone();
                let traceparent_for_task = traceparent.clone();
                let config_version_for_task = state.config_version.clone();
                let parsed_request_for_task = parsed_json.clone();
                let policy_chain_for_task: Vec<String> = active_chain
                    .iter()
                    .map(|entry| entry.kind().to_string())
                    .collect();
                let policy_blocks_for_task = state.policy_blocks.clone();
                let redaction_cfg_for_task = redaction_cfg.clone();
                let prompt_hash_for_task = prompt_hash.clone();
                let event_sink_for_task = state.event_sink.clone();
                let fallback_provider_for_task = fallback_provider_id.clone();
                let trace_correlation_for_task = trace_correlation.clone();
                let body_bytes_for_task = body_bytes.clone();
                let key_budget_tracker_for_task = Arc::clone(state.key_budget_tracker);
                let connected_access_dispatch_ctx_for_task = connected_access_dispatch_ctx.clone();
                let ua_authorization_id_for_task = ua_authorization_id_for_stream.clone();
                let ua_dispatch_acquired_for_task = ua_dispatch_acquired_for_stream;
                let ua_financial_for_task = ua_financial_for_stream;
                let session_context_for_task = session_context.clone();
                let history_service_for_task = state.history_service.clone();
                let history_capture_mode_for_task = effective_history_capture_mode(&state);
                let gateway_id_for_task = state.gateway_id.clone();
                let model_for_task = parsed_request_for_task
                    .get("model")
                    .and_then(|value| value.as_str())
                    .map(ToOwned::to_owned);
                let resolved_streaming_target =
                    state.current_target_id.as_deref().and_then(|tid| {
                        state
                            .provider_registry
                            .as_ref()
                            .and_then(|reg| reg.find_target_by_id(tid))
                    });
                let streaming_gateway_ctx_for_task = StreamingGatewayContext {
                    gateway_id: spend_gateway_reference(
                        state.gateway_id.as_ref(),
                        state.connected_mode,
                    ),
                    provider: runtime_route_provider_alias(resolved_streaming_target, None),
                    resolved_provider: runtime_resolved_provider(
                        resolved_streaming_target,
                        state.upstream_base,
                        model_for_task.as_deref(),
                    ),
                    config_name: state.config_name.clone(),
                };
                let start_for_task = start;
                let mut decision_for_task = decision.clone();
                let registered_agent_id_for_task = state.current_agent_id.clone();
                let request_finops_for_task = state.request_finops.clone();
                let ua_org_id_for_task = ua_org_id_from_finops(request_finops_for_task.as_ref());
                let session_id_for_task = state.session_id.clone();
                let streaming_redaction_enabled = streaming_output_redaction_enabled(
                    &policy_chain_for_task,
                    &policy_blocks_for_task,
                );
                let streaming_requires_buffering =
                    streaming_requires_buffering(&policy_chain_for_task, &policy_blocks_for_task);
                let streaming_agent_firewall_enabled =
                    streaming_agent_firewall_enabled(&policy_chain_for_task);

                tokio::spawn(async move {
                    let mut parser_buffer = Vec::new();
                    let mut accumulated_content = String::new();
                    let mut buffered_firewall_chunks = Vec::new();
                    let mut tool_call_accumulator =
                        crate::gateway::structured_tool_calls::StreamingToolCallAccumulator::default(
                        );
                    let mut passthrough_output_chars = 0usize;
                    let mut finish_reason = None;
                    let mut chunks_forwarded = 0usize;
                    let streaming_mode = streaming_mode_label(
                        streaming_requires_buffering,
                        streaming_redaction_enabled,
                    );
                    let mut upstream_stream = response.body;

                    loop {
                        match upstream_stream.next().await {
                            Some(Ok(chunk)) => {
                                if streaming_agent_firewall_enabled {
                                    buffered_firewall_chunks.push(chunk.clone());
                                }
                                parser_buffer.extend_from_slice(&chunk);
                                for payload in
                                    crate::gateway::sse::drain_sse_data_frames(&mut parser_buffer)
                                {
                                    if streaming_agent_firewall_enabled {
                                        let _ = tool_call_accumulator.ingest_sse_payload(&payload);
                                    }
                                    if streaming_requires_buffering {
                                        crate::gateway::sse::accumulate_chat_completion_delta(
                                            &payload,
                                            &mut accumulated_content,
                                            &mut finish_reason,
                                        );
                                    } else {
                                        crate::gateway::sse::accumulate_chat_completion_delta_stats(
                                            &payload,
                                            &mut passthrough_output_chars,
                                            &mut finish_reason,
                                        );
                                    }
                                }

                                if streaming_requires_buffering {
                                    if let Some(result) = evaluate_streaming_blocking_policy(
                                        &policy_chain_for_task,
                                        &policy_blocks_for_task,
                                        &accumulated_content,
                                    ) {
                                        decision_for_task.final_verdict = Verdict::Block;
                                        decision_for_task.reason_code = result.reason_code.clone();
                                        decision_for_task.results.push(result);

                                        let latency_ms =
                                            start_for_task.elapsed().as_millis() as i64;
                                        if let Some(sink) = &event_sink_for_task {
                                            let mut event = decision_event_json(
                                                &config_version_for_task,
                                                &request_id_for_task,
                                                &decision_for_task,
                                                false,
                                                false,
                                                prompt_hash_for_task.clone(),
                                                None,
                                                registered_agent_id_for_task.as_deref(),
                                                request_finops_for_task.as_ref(),
                                                session_id_for_task.as_deref(),
                                            );
                                            enrich_decision_event_details(
                                                &mut event,
                                                Some(parsed_request_for_task.clone()),
                                                None,
                                                "POST",
                                                StatusCode::BAD_REQUEST,
                                                decision_runtime_json_streaming(
                                                    Some(accumulated_content.chars().count()),
                                                    finish_reason.as_deref(),
                                                    fallback_provider_for_task.as_deref(),
                                                    chunks_forwarded,
                                                    true,
                                                    true,
                                                    Some(&decision_for_task.reason_code),
                                                    Some("Streaming response blocked by output policy"),
                                                    Some(&streaming_gateway_ctx_for_task),
                                                ),
                                                &trace_correlation_for_task,
                                            );
                                            if let Some(metadata) = event
                                                .get_mut("metadata")
                                                .and_then(|value| value.as_object_mut())
                                            {
                                                metadata.insert(
                                                    "streaming".to_string(),
                                                    serde_json::json!(true),
                                                );
                                                metadata.insert(
                                                    "streaming_mode".to_string(),
                                                    serde_json::json!(streaming_mode),
                                                );
                                                metadata.insert(
                                                    "streaming_interrupted".to_string(),
                                                    serde_json::json!(true),
                                                );
                                            }
                                            sink.enqueue_decision(&request_id_for_task, event);
                                        }

                                        let verdictan = verdictan_extension_json(
                                            "BLOCK",
                                            &decision_for_task.reason_code,
                                            &config_version_for_task,
                                            &request_id_for_task,
                                            latency_ms,
                                            None,
                                            None,
                                        );
                                        let body = serde_json::json!({
                                            "error": error_json(
                                                &format!(
                                                    "Streaming response blocked by policy: {}",
                                                    decision_for_task.reason_code
                                                ),
                                                "invalid_request_error",
                                                "content_policy_violation",
                                            ),
                                            "verdictan": verdictan,
                                        });
                                        let _ = tx
                                            .send(Ok(Bytes::from(format!("data: {}\n\n", body))))
                                            .await;
                                        let _ = tx
                                            .send(Ok(Bytes::from_static(b"data: [DONE]\n\n")))
                                            .await;
                                        return;
                                    }
                                }

                                if !streaming_redaction_enabled && !streaming_agent_firewall_enabled
                                {
                                    chunks_forwarded += 1;
                                    if tx.send(Ok(chunk)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            None => break,
                            Some(Err(error)) => {
                                let latency_ms = start_for_task.elapsed().as_millis() as i64;
                                let failure_reason = if error.kind() == io::ErrorKind::TimedOut {
                                    "proxy.upstream_stream_timeout"
                                } else {
                                    "proxy.upstream_stream_interrupted"
                                };
                                let failure_status = if error.kind() == io::ErrorKind::TimedOut {
                                    StatusCode::GATEWAY_TIMEOUT
                                } else {
                                    StatusCode::BAD_GATEWAY
                                };
                                let failure_message =
                                    format!("Upstream streaming response interrupted: {}", error);
                                let output_chars = if streaming_requires_buffering {
                                    accumulated_content.chars().count()
                                } else {
                                    passthrough_output_chars
                                };

                                decision_for_task.reason_code = failure_reason.to_string();

                                if let Some(sink) = &event_sink_for_task {
                                    let mut event = decision_event_json(
                                        &config_version_for_task,
                                        &request_id_for_task,
                                        &decision_for_task,
                                        false,
                                        false,
                                        prompt_hash_for_task.clone(),
                                        None,
                                        registered_agent_id_for_task.as_deref(),
                                        request_finops_for_task.as_ref(),
                                        session_id_for_task.as_deref(),
                                    );
                                    enrich_decision_event_details(
                                        &mut event,
                                        Some(parsed_request_for_task.clone()),
                                        None,
                                        "POST",
                                        failure_status,
                                        decision_runtime_json_streaming(
                                            Some(output_chars),
                                            finish_reason.as_deref(),
                                            fallback_provider_for_task.as_deref(),
                                            chunks_forwarded,
                                            streaming_requires_buffering,
                                            true,
                                            Some(failure_reason),
                                            Some(&failure_message),
                                            Some(&streaming_gateway_ctx_for_task),
                                        ),
                                        &trace_correlation_for_task,
                                    );
                                    if let Some(metadata) = event
                                        .get_mut("metadata")
                                        .and_then(|value| value.as_object_mut())
                                    {
                                        metadata.insert(
                                            "streaming".to_string(),
                                            serde_json::json!(true),
                                        );
                                        metadata.insert(
                                            "streaming_mode".to_string(),
                                            serde_json::json!(streaming_mode),
                                        );
                                        metadata.insert(
                                            "streaming_redaction_buffered".to_string(),
                                            serde_json::json!(streaming_redaction_enabled),
                                        );
                                        metadata.insert(
                                            "streaming_interrupted".to_string(),
                                            serde_json::json!(true),
                                        );
                                    }
                                    sink.enqueue_decision(&request_id_for_task, event);
                                }

                                if let Some(bytes) = build_streaming_error_sse_bytes(
                                    &request_id_for_task,
                                    &config_version_for_task,
                                    &decision_for_task.final_verdict.to_string().to_uppercase(),
                                    failure_reason,
                                    &failure_message,
                                    latency_ms,
                                ) {
                                    let _ = tx.send(Ok(bytes)).await;
                                }
                                let _ = tx.send(Ok(Bytes::from_static(b"data: [DONE]\n\n"))).await;
                                return;
                            }
                        }
                    }

                    if streaming_agent_firewall_enabled {
                        if let Some(result) = evaluate_streaming_agent_firewall(
                            &policy_chain_for_task,
                            &policy_blocks_for_task,
                            tool_call_accumulator,
                            request_finops_for_task
                                .as_ref()
                                .and_then(|finops| finops.authenticated_identity.as_ref()),
                        ) {
                            decision_for_task.final_verdict = result.verdict.clone();
                            decision_for_task.reason_code = result.reason_code.clone();
                            decision_for_task.results.push(result);
                            let latency_ms = start_for_task.elapsed().as_millis() as i64;
                            if let Some(sink) = &event_sink_for_task {
                                let event = decision_event_json(
                                    &config_version_for_task,
                                    &request_id_for_task,
                                    &decision_for_task,
                                    false,
                                    false,
                                    prompt_hash_for_task.clone(),
                                    None,
                                    registered_agent_id_for_task.as_deref(),
                                    request_finops_for_task.as_ref(),
                                    session_id_for_task.as_deref(),
                                );
                                sink.enqueue_decision(&request_id_for_task, event);
                            }
                            let body = serde_json::json!({
                                "error": error_json(
                                    "Streaming tool call blocked by Agent Firewall",
                                    "invalid_request_error",
                                    "content_policy_violation",
                                ),
                                "verdictan": verdictan_extension_json(
                                    "BLOCK",
                                    &decision_for_task.reason_code,
                                    &config_version_for_task,
                                    &request_id_for_task,
                                    latency_ms,
                                    None,
                                    None,
                                ),
                            });
                            let _ = tx
                                .send(Ok(Bytes::from(format!("data: {}\n\n", body))))
                                .await;
                            let _ = tx.send(Ok(Bytes::from_static(b"data: [DONE]\n\n"))).await;
                            return;
                        }
                        if !streaming_redaction_enabled {
                            for chunk in buffered_firewall_chunks {
                                chunks_forwarded += 1;
                                if tx.send(Ok(chunk)).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }

                    if streaming_redaction_enabled {
                        let (redacted_content, redactions, targets) =
                            crate::gateway::redaction::redact_with_metadata_and_targets_with_config(
                                &accumulated_content,
                                &redaction_cfg_for_task,
                                "choices[0].message.content",
                            );

                        if !targets.is_empty() {
                            let mut entity_types: Vec<String> = targets
                                .iter()
                                .map(|target| target.entity_type.clone())
                                .collect();
                            entity_types.sort();
                            entity_types.dedup();

                            decision_for_task.results.push(enforcement::PolicyResult {
                                policy_kind: "streaming-redaction".to_string(),
                                phase: "output".to_string(),
                                verdict: Verdict::Redact,
                                reason_code: "redact.applied".to_string(),
                                details: Some(serde_json::json!({
                                    "detection_count": targets.len(),
                                    "entity_types": entity_types,
                                    "streaming": true,
                                    "streaming_mode": "buffered_redaction",
                                })),
                                redaction_targets: Some(targets),
                            });

                            if decision_for_task.final_verdict == Verdict::Allow {
                                decision_for_task.final_verdict = Verdict::Redact;
                                decision_for_task.reason_code = "redact.applied".to_string();
                            }
                        }

                        let content = if redactions.is_empty() {
                            accumulated_content.as_str()
                        } else {
                            redacted_content.as_str()
                        };

                        if let Some(bytes) = build_buffered_streaming_sse_bytes(
                            &request_id_for_task,
                            content,
                            finish_reason.as_deref(),
                        ) {
                            if tx.send(Ok(bytes)).await.is_err() {
                                return;
                            }
                        }
                    }

                    if let Some(sink) = event_sink_for_task.as_ref() {
                        let latency_ms = start_for_task.elapsed().as_millis() as i64;
                        let output_chars = if streaming_requires_buffering {
                            accumulated_content.chars().count()
                        } else {
                            passthrough_output_chars
                        };

                        decision_for_task.reason_code = if output_chars == 0 {
                            "stream.passthrough.empty".to_string()
                        } else {
                            "stream.passthrough.completed".to_string()
                        };

                        let mut event = decision_event_json(
                            &config_version_for_task,
                            &request_id_for_task,
                            &decision_for_task,
                            false,
                            false,
                            prompt_hash_for_task,
                            None,
                            registered_agent_id_for_task.as_deref(),
                            request_finops_for_task.as_ref(),
                            session_id_for_task.as_deref(),
                        );
                        enrich_decision_event_details(
                            &mut event,
                            Some(parsed_request_for_task.clone()),
                            None,
                            "POST",
                            StatusCode::OK,
                            decision_runtime_json_streaming(
                                Some(output_chars),
                                finish_reason.as_deref(),
                                fallback_provider_for_task.as_deref(),
                                chunks_forwarded,
                                streaming_requires_buffering,
                                false,
                                None,
                                None,
                                Some(&streaming_gateway_ctx_for_task),
                            ),
                            &trace_correlation_for_task,
                        );
                        annotate_streaming_decision_event_metadata(
                            &mut event,
                            streaming_mode,
                            streaming_redaction_enabled,
                            false,
                            output_chars,
                            finish_reason.as_deref(),
                            latency_ms,
                            chunks_forwarded,
                            streaming_requires_buffering,
                        );
                        sink.enqueue_decision(&request_id_for_task, event);
                    }

                    let streaming_usage = estimate_streaming_spend_usage(
                        &body_bytes_for_task,
                        if streaming_requires_buffering {
                            Some(accumulated_content.as_str())
                        } else {
                            None
                        },
                        if streaming_requires_buffering {
                            accumulated_content.chars().count()
                        } else {
                            passthrough_output_chars
                        },
                    );
                    let history_response_payload = attach_history_usage_block(
                        if streaming_requires_buffering {
                            let history_content = if streaming_redaction_enabled {
                                crate::gateway::redaction::redact_with_metadata_and_targets_with_config(
                                    &accumulated_content,
                                    &redaction_cfg_for_task,
                                    "choices[0].message.content",
                                )
                                .0
                            } else {
                                accumulated_content.clone()
                            };
                            serde_json::json!({
                                "choices": [{
                                    "index": 0,
                                    "message": { "role": "assistant", "content": history_content },
                                    "finish_reason": finish_reason,
                                }],
                                "streaming": true,
                            })
                        } else {
                            serde_json::json!({
                                "streaming": true,
                                "output_chars": passthrough_output_chars,
                                "finish_reason": finish_reason,
                            })
                        },
                        streaming_usage,
                    );
                    emit_history_writeback_detached(
                        event_sink_for_task.clone(),
                        history_service_for_task.clone(),
                        gateway_id_for_task.clone(),
                        request_finops_for_task.clone(),
                        history_capture_mode_for_task.clone(),
                        &request_id_for_task,
                        &traceparent_for_task,
                        session_context_for_task.clone(),
                        &body_bytes_for_task,
                        history_response_payload,
                        &decision_for_task.final_verdict,
                        fallback_provider_for_task.as_deref(),
                        model_for_task.as_deref(),
                        Some(start_for_task.elapsed().as_millis() as i64),
                    );
                    let upstream_duration_ms = Some(start_for_task.elapsed().as_millis() as i64);
                    if ua_financial_for_task {
                        schedule_finalize_ua_streaming_financial_lifecycle(
                            ua_authorization_id_for_task,
                            ua_dispatch_acquired_for_task,
                            event_sink_for_task.clone(),
                            body_bytes_for_task.clone(),
                            if streaming_requires_buffering {
                                Some(accumulated_content.clone())
                            } else {
                                None
                            },
                            if streaming_requires_buffering {
                                accumulated_content.chars().count()
                            } else {
                                passthrough_output_chars
                            },
                            false,
                            registered_agent_id_for_task.clone(),
                            ua_org_id_for_task.clone(),
                            &request_id_for_task,
                            &traceparent_for_task,
                        );
                    } else {
                        finalize_connected_post_dispatch_accounting(
                            event_sink_for_task.as_ref(),
                            &key_budget_tracker_for_task,
                            &body_bytes_for_task,
                            resolve_streaming_post_dispatch_usage(
                                &body_bytes_for_task,
                                if streaming_requires_buffering {
                                    Some(accumulated_content.as_str())
                                } else {
                                    None
                                },
                                if streaming_requires_buffering {
                                    accumulated_content.chars().count()
                                } else {
                                    passthrough_output_chars
                                },
                            ),
                            &connected_access_dispatch_ctx_for_task,
                            &request_id_for_task,
                            &traceparent_for_task,
                            fallback_provider_for_task.as_deref(),
                            upstream_duration_ms,
                        );
                    }
                });

                let mut streaming_headers = Vec::new();
                append_context_response_headers(
                    &mut streaming_headers,
                    recall_attribution.as_ref(),
                    None,
                );
                return Ok(build_streaming_response(
                    status,
                    content_type,
                    request_id,
                    traceparent,
                    ReceiverStream::new(rx),
                    false,
                    if streaming_headers.is_empty() {
                        None
                    } else {
                        Some(streaming_headers)
                    },
                ));
            }
            Err(error) => match state.fail_mode {
                FailMode::Block => {
                    if ua_financial_for_stream {
                        schedule_finalize_ua_streaming_financial_lifecycle(
                            ua_authorization_id_for_stream,
                            ua_dispatch_acquired_for_stream,
                            state.event_sink.clone(),
                            upstream_body_bytes.clone(),
                            None,
                            0,
                            true,
                            state.current_agent_id.clone(),
                            ua_org_id_from_finops(state.request_finops.as_ref()),
                            &request_id,
                            &traceparent,
                        );
                    }
                    let code = if error.is_timeout() {
                        StatusCode::GATEWAY_TIMEOUT
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    };
                    let latency_ms = start.elapsed().as_millis() as i64;
                    let verdictan = verdictan_extension_json(
                        "BLOCK",
                        "proxy.upstream_unreachable",
                        &state.config_version,
                        &request_id,
                        latency_ms,
                        None,
                        None,
                    );
                    let body = serde_json::json!({
                        "error": error_json(
                            &error.to_string(),
                            "invalid_request_error",
                            "proxy.upstream_unreachable",
                        ),
                        "verdictan": verdictan,
                    });
                    return Ok(build_response(
                        code,
                        HeaderValue::from_static("application/json"),
                        request_id,
                        traceparent,
                        Bytes::from(serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec())),
                        false,
                        None,
                    ));
                }
                FailMode::Allow => {
                    let latency_ms = start.elapsed().as_millis() as i64;
                    let verdictan = verdictan_extension_json(
                        "ALLOW",
                        "proxy.degraded_allow",
                        &state.config_version,
                        &request_id,
                        latency_ms,
                        None,
                        None,
                    );
                    let body = serde_json::json!({
                        "id": format!("chatcmpl_{}", request_id),
                        "object": "chat.completion",
                        "created": 0,
                        "model": "degraded",
                        "choices": [{
                            "index": 0,
                            "message": { "role": "assistant", "content": "Upstream unavailable; fail-open mode returned a degraded placeholder response." },
                            "finish_reason": "stop"
                        }],
                        "verdictan": verdictan,
                    });
                    return Ok(build_response(
                        StatusCode::OK,
                        HeaderValue::from_static("application/json"),
                        request_id,
                        traceparent,
                        Bytes::from(serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec())),
                        true,
                        None,
                    ));
                }
            },
        }
    }

    // Phase 18: pre-request token rate limit check.
    if let Some(trl) = state.token_rate_limiter.as_ref() {
        let api_key = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_start_matches("Bearer "));
        let scope_key = trl.scope_key(api_key, Some(peer_ip));
        if let Err(err) = trl.check(&scope_key) {
            tracing::warn!(
                request_id = %request_id,
                scope_key = %scope_key,
                max_tokens = err.max_tokens,
                "token rate limit exceeded"
            );
            let body = serde_json::json!({
                "error": error_json(
                    &format!(
                        "Token rate limit exceeded: {:?}/{:?} tokens in {}s window",
                        err.current_tokens, err.max_tokens, err.window_seconds
                    ),
                    "rate_limit_exceeded",
                    "token_rate_limit_exceeded",
                )
            });
            let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
            let mut builder = Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Request-Id", &request_id)
                .header("traceparent", &traceparent);
            for (name, value) in ratelimit_headers(
                err.max_tokens,
                0,
                err.window_seconds,
                Some(err.max_tokens),
                Some(0),
            ) {
                builder = builder.header(name, value);
            }
            let response = builder.body(Body::from(text)).unwrap_or_default();
            return Ok(response);
        }
    }

    let conversation_id = conversation_id.map(str::to_owned);
    finalize_chat_completions_dispatch(ChatCompletionsDispatchInput {
        state,
        peer_ip,
        headers,
        request_id,
        traceparent,
        start,
        parsed_json,
        upstream_body_bytes,
        body_bytes,
        prompt_hash,
        stream_requested,
        include_usage_in_stream,
        redaction_applied,
        ua_financial_path_active,
        ua_admission_credential_source,
        estimated_prompt_tokens,
        estimated_max_completion,
        conversation_id,
        provider_cache_key,
        chain_has_hipaa,
        chain_has_pii,
        chain_has_dlp,
        chain_has_student_privacy,
        chain_has_case_privacy,
        early_cached_response,
        cache_replay_metadata,
        cache_tier,
        decision,
        redaction_cfg,
        response_redactions,
        quality_scores_for_event,
        review_result_for_event,
        messages_for_eval,
        active_chain,
        cg_rl_info,
        trace_correlation,
        request_telemetry_hints,
        connected_access_dispatch_ctx,
        context_fabric_policy,
        selected_fabric_slices,
        session_context,
        recall_attribution,
    })
    .await
}
