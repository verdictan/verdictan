// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Family request-pipeline module.
//! Child of `gateway::server`; parent private items remain visible.
use super::super::*;
use super::*;

pub(crate) struct ResponsesDispatchInput<'a> {
    pub state: ActiveGatewayStateView<'a>,
    pub headers: HeaderMap,
    pub request_id: String,
    pub traceparent: String,
    pub start: Instant,
    pub parsed_json: serde_json::Value,
    pub upstream_body_bytes: Bytes,
    pub body_bytes: Bytes,
    pub prompt_hash: String,
    pub prompt_redaction_applied: bool,
    pub ua_financial_path_active: bool,
    pub ua_admission_credential_source: Option<ConnectedCredentialSource>,
    pub estimated_prompt_tokens: u64,
    pub estimated_max_completion: u64,
    pub conversation_id: Option<String>,
    pub provider_cache_key: Option<String>,
    pub early_cached_response: Option<CacheLookupResult>,
    pub cache_replay_metadata: Option<CacheReplayMetadata>,
    pub cache_tier: CacheTier,
    pub decision: DecisionEnvelope,
    pub redaction_cfg: crate::gateway::redaction::RedactionConfig,
    pub response_redactions: Vec<crate::gateway::redaction::VerdictanRedaction>,
    pub quality_scores_for_event: Option<serde_json::Value>,
    pub review_result_for_event: Option<serde_json::Value>,
    pub messages_for_eval: Arc<[enforcement::ChatMessage]>,
    pub active_chain: Vec<enforcement::ChainEntry>,
    pub cg_rl_info: Vec<(&'static str, String)>,
    pub trace_correlation: TraceCorrelation,
    pub request_telemetry_hints: RequestTelemetryHints,
    pub connected_access_dispatch_ctx: ConnectedAccessDispatchContext,
    pub context_fabric_policy: ResolvedContextFabricResponsePolicy,
    pub selected_fabric_slices: Vec<crate::gateway::codebase_context::FabricArtifactSlice>,
    pub session_context: Option<crate::gateway::session::GatewaySessionContext>,
    pub recall_attribution: Option<GatewayRecallAttribution>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn finalize_responses_dispatch<'a>(
    input: ResponsesDispatchInput<'a>,
) -> Result<Response<Body>, StatusCode> {
    let ResponsesDispatchInput {
        mut state,
        headers,
        request_id,
        traceparent,
        start,
        parsed_json,
        upstream_body_bytes,
        body_bytes,
        prompt_hash,
        prompt_redaction_applied,
        ua_financial_path_active,
        ua_admission_credential_source,
        estimated_prompt_tokens,
        estimated_max_completion,
        conversation_id,
        provider_cache_key,
        early_cached_response,
        cache_replay_metadata,
        cache_tier,
        mut decision,
        redaction_cfg,
        mut response_redactions,
        mut quality_scores_for_event,
        mut review_result_for_event,
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
    } = input;

    let early_cache_outcome = early_cached_response.as_ref().map(|hit| hit.outcome);
    if ua_financial_path_active && early_cached_response.is_none() {
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
            "/v1/responses",
            crate::gateway::usage_authorization::UsageAuthorizationRequestFamily::Responses,
        )
        .await
        {
            return Ok(response);
        }
    }
    let (upstream_resp, served_provider_id) = if let Some(cached) = early_cached_response {
        (Ok(cached.response), None)
    } else {
        if let Err(response) = persist_admitted_decision_before_dispatch(
            &state,
            &request_id,
            &traceparent,
            &decision,
            &prompt_hash,
            "/v1/responses",
        ) {
            return Ok(response);
        }
        send_with_provider_fallback(
            &state,
            &headers,
            "/v1/responses",
            upstream_body_bytes.clone(),
            &request_id,
            &traceparent,
            provider_cache_key.as_deref(),
            &trace_correlation,
            &request_telemetry_hints,
            session_context.as_ref(),
        )
        .await
    };
    if let Some(ref pid) = served_provider_id {
        state.current_target_id = Some(pid.clone());
    }
    match upstream_resp {
        Ok(resp) => {
            let status = resp.status();
            let content_type = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .cloned()
                .unwrap_or_else(|| HeaderValue::from_static("application/json"));

            let bytes = resp.body().clone();

            // Phase 21 / PERF-012 — response size limit check (production default 16 MiB).
            let size_exceeded = resp.response_size_exceeded().cloned();
            let effective_limit = state
                .size_limit
                .as_ref()
                .map(|sl| sl.effective_max_response_bytes())
                .unwrap_or(crate::gateway::size_limit::DEFAULT_MAX_RESPONSE_BYTES);
            let size_err = size_exceeded
                .map(|exceeded| crate::gateway::size_limit::SizeLimitExceeded {
                    kind: crate::gateway::size_limit::SizeLimitKind::Response,
                    actual: exceeded.actual,
                    limit: exceeded.limit.min(effective_limit),
                })
                .or_else(|| {
                    if bytes.len() > effective_limit {
                        Some(crate::gateway::size_limit::SizeLimitExceeded {
                            kind: crate::gateway::size_limit::SizeLimitKind::Response,
                            actual: bytes.len(),
                            limit: effective_limit,
                        })
                    } else {
                        state
                            .size_limit
                            .as_ref()
                            .and_then(|sl| sl.check_response(bytes.len()).err())
                    }
                });
            if let Some(err) = size_err {
                tracing::warn!(
                    request_id = %request_id,
                    actual = err.actual,
                    limit = err.limit,
                    "upstream response body exceeds configured size limit"
                );
                let body = serde_json::json!({
                    "error": error_json(
                        &format!("Response body exceeds configured size limit ({} > {} bytes)", err.actual, err.limit),
                        "response_too_large",
                        "response_size_exceeded",
                    )
                });
                let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("X-Request-Id", &request_id)
                    .header("traceparent", &traceparent)
                    .body(Body::from(text))
                    .unwrap_or_default());
            }

            let mut out_bytes = bytes.clone();
            let post_request_decision =
                enforcement::evaluate_chain_entries_for_stage_with_identity(
                    &active_chain,
                    enforcement::ExecutionStage::PostRequest,
                    "/v1/responses",
                    &state.policy_blocks,
                    Some(&parsed_json),
                    None,
                    &headers,
                    &messages_for_eval,
                    state
                        .request_finops
                        .as_ref()
                        .and_then(|finops| finops.authenticated_identity.as_ref()),
                )
                .await;
            merge_stage_decision(&mut decision, post_request_decision);
            let parsed_stage_output = serde_json::from_slice::<serde_json::Value>(&out_bytes).ok();
            let pre_response_messages: Arc<[enforcement::ChatMessage]> = Arc::from(
                output_messages_for_stage(parsed_stage_output.as_ref(), &out_bytes),
            );
            let pre_response_decision =
                enforcement::evaluate_chain_entries_for_stage_with_identity(
                    &active_chain,
                    enforcement::ExecutionStage::PreResponse,
                    "/v1/responses",
                    &state.policy_blocks,
                    Some(&parsed_json),
                    parsed_stage_output.as_ref(),
                    &headers,
                    &pre_response_messages,
                    state
                        .request_finops
                        .as_ref()
                        .and_then(|finops| finops.authenticated_identity.as_ref()),
                )
                .await;
            merge_stage_decision(&mut decision, pre_response_decision);
            if let Some(response) = build_stage_verdict_response(
                &decision,
                &state.config_version,
                &request_id,
                &traceparent,
                start.elapsed().as_millis() as i64,
                prompt_redaction_applied,
                &response_redactions,
                quality_scores_for_event.as_ref(),
            ) {
                return Ok(response);
            }
            let pii_action = state
                .policy_blocks
                .get("pii-detector")
                .and_then(|v| v.get("action"))
                .and_then(|v| v.as_str())
                .unwrap_or("redact");

            if state.policy_chain.iter().any(|k| k == "pii-detector") && pii_action != "off" {
                if let Ok((b, redactions, targets)) =
                    redact_openai_responses_body(&bytes, &redaction_cfg)
                {
                    if !targets.is_empty() {
                        let mut entity_types: Vec<String> =
                            targets.iter().map(|t| t.entity_type.clone()).collect();
                        entity_types.sort();
                        entity_types.dedup();

                        decision.results.push(enforcement::PolicyResult {
                            policy_kind: "pii-detector".to_string(),
                            phase: "output".to_string(),
                            verdict: Verdict::Redact,
                            reason_code: "pii.detected".to_string(),
                            details: Some(serde_json::json!({
                                "detection_count": targets.len(),
                                "entity_types": entity_types,
                            })),
                            redaction_targets: Some(targets),
                        });

                        if decision.final_verdict == Verdict::Allow {
                            decision.final_verdict = Verdict::Redact;
                            decision.reason_code = "redact.applied".to_string();
                        }
                    }

                    if !redactions.is_empty() {
                        out_bytes = b;
                        response_redactions = redactions;
                    }
                }
            }

            // Output-phase policy evaluation (Tier-2 + existing output policies), executed strictly
            // in active_chain order (CLI-FIND-MED-002: route-scoped).
            if status.is_success() {
                let mut parsed_out: Option<serde_json::Value> = None;
                let active_chain_kinds: Vec<String> =
                    active_chain.iter().map(|e| e.kind().to_string()).collect();

                for kind in &active_chain_kinds {
                    match kind.as_str() {
                        "flagged-review" => {
                            if let Some(review_result) = execute_inline_flagged_review(
                                &state,
                                &request_id,
                                &traceparent,
                                &parsed_json,
                                conversation_id.as_deref(),
                                state.session_id.as_deref(),
                                &mut parsed_out,
                                &mut out_bytes,
                                &mut decision,
                                served_provider_id.as_deref(),
                            )
                            .await
                            {
                                review_result_for_event = Some(review_result.clone());

                                if matches!(
                                    decision.final_verdict,
                                    Verdict::Block | Verdict::Escalate
                                ) {
                                    let latency_ms = start.elapsed().as_millis() as i64;
                                    if let Some(sink) = &state.event_sink {
                                        let mut event = decision_event_json(
                                            &state.config_version,
                                            &request_id,
                                            &decision,
                                            false,
                                            prompt_redaction_applied,
                                            prompt_hash.clone(),
                                            quality_scores_for_event.clone(),
                                            state.registered_agent_id(),
                                            state.request_finops.as_ref(),
                                            state.session_id.as_deref(),
                                        );
                                        inject_review_result_into_event(&mut event, &review_result);
                                        sink.enqueue_decision(&request_id, event);
                                    }

                                    let verdictan_verdict = match decision.final_verdict {
                                        Verdict::Block => "BLOCK",
                                        Verdict::Escalate => "ESCALATE",
                                        _ => "ALLOW",
                                    };
                                    let mut verdictan = verdictan_extension_json(
                                        verdictan_verdict,
                                        &decision.reason_code,
                                        &state.config_version,
                                        &request_id,
                                        latency_ms,
                                        if decision.final_verdict == Verdict::Escalate {
                                            Some(serde_json::json!({
                                                "id": format!("esc_{request_id}"),
                                                "status": "queued"
                                            }))
                                        } else {
                                            None
                                        },
                                        None,
                                    );
                                    if let Some(obj) = verdictan.as_object_mut() {
                                        obj.insert(
                                            "review_result".to_string(),
                                            review_result.clone(),
                                        );
                                    }

                                    let mut body = match decision.final_verdict {
                                        Verdict::Block => serde_json::json!({
                                            "error": error_json(
                                                &format!(
                                                    "Response blocked by policy: {}",
                                                    decision.reason_code
                                                ),
                                                "invalid_request_error",
                                                "content_policy_violation",
                                            ),
                                            "verdictan": verdictan,
                                        }),
                                        Verdict::Escalate => serde_json::json!({
                                            "id": format!("resp_verdictan_{request_id}"),
                                            "object": "response",
                                            "status": "completed",
                                            "output": [],
                                            "verdictan": verdictan,
                                        }),
                                        Verdict::Allow | Verdict::Redact => serde_json::json!({
                                            "verdictan": verdictan,
                                        }),
                                    };
                                    inject_review_result_into_payload(&mut body, &review_result);

                                    emit_history_writeback(
                                        &state,
                                        &request_id,
                                        &traceparent,
                                        session_context.clone(),
                                        &body_bytes,
                                        body.clone(),
                                        &decision.final_verdict,
                                        served_provider_id.as_deref(),
                                        parsed_json.get("model").and_then(|value| value.as_str()),
                                        Some(start.elapsed().as_millis() as i64),
                                    );

                                    let text = serde_json::to_vec(&body)
                                        .unwrap_or_else(|_| b"{}".to_vec());
                                    let status_code = if decision.final_verdict == Verdict::Block {
                                        StatusCode::BAD_REQUEST
                                    } else {
                                        StatusCode::OK
                                    };
                                    return Ok(build_response(
                                        status_code,
                                        HeaderValue::from_static("application/json"),
                                        request_id,
                                        traceparent,
                                        Bytes::from(text),
                                        false,
                                        Some(verdictan_headers(
                                            verdictan_verdict,
                                            &decision.reason_code,
                                            &state.config_version,
                                            latency_ms,
                                            prompt_redaction_applied,
                                            &response_redactions,
                                            quality_scores_for_event.as_ref(),
                                            false,
                                            verdictan_rbac_details(&decision),
                                        )),
                                    ));
                                }
                            }
                        }
                        "citation-verifier" => {
                            if let Some(cfg) = state.policy_blocks.get("citation-verifier") {
                                if let Ok(ev) =
                                    crate::gateway::citation::evaluate_citation_verifier(
                                        &parsed_json,
                                        &out_bytes,
                                        cfg,
                                    )
                                    .await
                                {
                                    decision.results.push(ev.policy_result);
                                    if ev.should_block {
                                        decision.final_verdict = Verdict::Block;
                                        decision.reason_code = decision
                                            .results
                                            .last()
                                            .map(|r| r.reason_code.clone())
                                            .unwrap_or_else(|| "citation.unverified".to_string());

                                        let latency_ms = start.elapsed().as_millis() as i64;
                                        if let Some(sink) = &state.event_sink {
                                            let event = decision_event_json(
                                                &state.config_version,
                                                &request_id,
                                                &decision,
                                                false,
                                                prompt_redaction_applied,
                                                prompt_hash.clone(),
                                                quality_scores_for_event.clone(),
                                                state.registered_agent_id(),
                                                state.request_finops.as_ref(),
                                                state.session_id.as_deref(),
                                            );
                                            sink.enqueue_decision(&request_id, event);
                                        }

                                        let verdictan = verdictan_extension_json(
                                            "BLOCK",
                                            &decision.reason_code,
                                            &state.config_version,
                                            &request_id,
                                            latency_ms,
                                            None,
                                            None,
                                        );
                                        let body = serde_json::json!({
                                            "error": error_json(
                                                &format!(
                                                    "Response blocked by policy: {}",
                                                    decision.reason_code
                                                ),
                                                "invalid_request_error",
                                                "content_policy_violation",
                                            ),
                                            "verdictan": verdictan,
                                        });

                                        let text = serde_json::to_vec(&body)
                                            .unwrap_or_else(|_| b"{}".to_vec());
                                        return Ok(build_response(
                                            StatusCode::BAD_REQUEST,
                                            HeaderValue::from_static("application/json"),
                                            request_id,
                                            traceparent,
                                            Bytes::from(text),
                                            false,
                                            Some(verdictan_headers(
                                                "BLOCK",
                                                &decision.reason_code,
                                                &state.config_version,
                                                latency_ms,
                                                prompt_redaction_applied,
                                                &response_redactions,
                                                quality_scores_for_event.as_ref(),
                                                false,
                                                verdictan_rbac_details(&decision),
                                            )),
                                        ));
                                    }
                                }
                            }
                        }
                        "response-rewriter" => {
                            if let Some(cfg) = state.policy_blocks.get("response-rewriter") {
                                let extracted_text = extract_openai_output_text_from_json(
                                    parsed_out.get_or_insert_with(|| {
                                        serde_json::from_slice::<serde_json::Value>(&out_bytes)
                                            .unwrap_or_else(|_| serde_json::json!({}))
                                    }),
                                );
                                let mut policy_result =
                                    crate::gateway::rewrite::evaluate_response_rewriter(
                                        &extracted_text,
                                        cfg,
                                    )
                                    .policy_result;
                                if let Some((rewritten_bytes, applied)) =
                                    crate::gateway::rewrite::rewrite_json_response_with_config(
                                        &out_bytes, cfg,
                                    )
                                {
                                    out_bytes = Bytes::from(rewritten_bytes);
                                    if let Some(details) = policy_result
                                        .details
                                        .as_mut()
                                        .and_then(|value| value.as_object_mut())
                                    {
                                        details.insert(
                                            "rules_applied".to_string(),
                                            serde_json::json!(applied),
                                        );
                                        details.insert(
                                            "structure_preserved".to_string(),
                                            serde_json::json!(true),
                                        );
                                    }
                                    if decision.final_verdict == Verdict::Allow {
                                        decision.reason_code = policy_result.reason_code.clone();
                                    }
                                }
                                decision.results.push(policy_result);
                            }
                        }
                        "mnpi-filter" => {
                            let cfg = state.policy_blocks.get("mnpi-filter");

                            if parsed_out.is_none() {
                                parsed_out =
                                    serde_json::from_slice::<serde_json::Value>(&out_bytes).ok();
                            }
                            if let Some(v) = parsed_out.as_ref() {
                                let text = extract_openai_output_text_from_json(v);
                                let ev =
                                    crate::gateway::compliance::evaluate_mnpi_filter(&text, cfg);
                                decision.results.push(ev.policy_result);
                                if ev.should_block {
                                    decision.final_verdict = Verdict::Block;
                                    decision.reason_code = decision
                                        .results
                                        .last()
                                        .map(|r| r.reason_code.clone())
                                        .unwrap_or_else(|| "mnpi.detected".to_string());

                                    let latency_ms = start.elapsed().as_millis() as i64;
                                    if let Some(sink) = &state.event_sink {
                                        let event = decision_event_json(
                                            &state.config_version,
                                            &request_id,
                                            &decision,
                                            false,
                                            prompt_redaction_applied,
                                            prompt_hash.clone(),
                                            quality_scores_for_event.clone(),
                                            state.registered_agent_id(),
                                            state.request_finops.as_ref(),
                                            state.session_id.as_deref(),
                                        );
                                        sink.enqueue_decision(&request_id, event);
                                    }

                                    let verdictan = verdictan_extension_json(
                                        "BLOCK",
                                        &decision.reason_code,
                                        &state.config_version,
                                        &request_id,
                                        latency_ms,
                                        None,
                                        None,
                                    );
                                    let body = serde_json::json!({
                                        "error": error_json(
                                            &format!(
                                                "Response blocked by policy: {}",
                                                decision.reason_code
                                            ),
                                            "invalid_request_error",
                                            "content_policy_violation",
                                        ),
                                        "verdictan": verdictan,
                                    });

                                    let text = serde_json::to_vec(&body)
                                        .unwrap_or_else(|_| b"{}".to_vec());
                                    return Ok(build_response(
                                        StatusCode::BAD_REQUEST,
                                        HeaderValue::from_static("application/json"),
                                        request_id,
                                        traceparent,
                                        Bytes::from(text),
                                        false,
                                        Some(verdictan_headers(
                                            "BLOCK",
                                            &decision.reason_code,
                                            &state.config_version,
                                            latency_ms,
                                            prompt_redaction_applied,
                                            &response_redactions,
                                            quality_scores_for_event.as_ref(),
                                            false,
                                            verdictan_rbac_details(&decision),
                                        )),
                                    ));
                                }
                            }
                        }
                        "financial-compliance" => {
                            let cfg = state.policy_blocks.get("financial-compliance");

                            if parsed_out.is_none() {
                                parsed_out =
                                    serde_json::from_slice::<serde_json::Value>(&out_bytes).ok();
                            }
                            if let Some(v) = parsed_out.as_ref() {
                                let text = extract_openai_output_text_from_json(v);
                                let mut ev =
                                    crate::gateway::compliance::evaluate_financial_compliance(
                                        &text, cfg,
                                    );
                                if let Some(rewrite) = ev.rewrite.take() {
                                    if let Some(vmut) = parsed_out.as_mut() {
                                        if prepend_openai_output_in_place(vmut, &rewrite.prefix) {
                                            if let Ok(out) = serde_json::to_vec(vmut) {
                                                out_bytes = Bytes::from(out);
                                            }
                                        }
                                    }
                                }
                                decision.results.push(ev.policy_result);
                                if ev.should_block {
                                    decision.final_verdict = Verdict::Block;
                                    decision.reason_code = decision
                                        .results
                                        .last()
                                        .map(|r| r.reason_code.clone())
                                        .unwrap_or_else(|| "financial.blocked".to_string());

                                    let latency_ms = start.elapsed().as_millis() as i64;
                                    if let Some(sink) = &state.event_sink {
                                        let event = decision_event_json(
                                            &state.config_version,
                                            &request_id,
                                            &decision,
                                            false,
                                            prompt_redaction_applied,
                                            prompt_hash.clone(),
                                            quality_scores_for_event.clone(),
                                            state.registered_agent_id(),
                                            state.request_finops.as_ref(),
                                            state.session_id.as_deref(),
                                        );
                                        sink.enqueue_decision(&request_id, event);
                                    }

                                    let verdictan = verdictan_extension_json(
                                        "BLOCK",
                                        &decision.reason_code,
                                        &state.config_version,
                                        &request_id,
                                        latency_ms,
                                        None,
                                        None,
                                    );
                                    let body = serde_json::json!({
                                        "error": error_json(
                                            &format!(
                                                "Response blocked by policy: {}",
                                                decision.reason_code
                                            ),
                                            "invalid_request_error",
                                            "content_policy_violation",
                                        ),
                                        "verdictan": verdictan,
                                    });

                                    let text = serde_json::to_vec(&body)
                                        .unwrap_or_else(|_| b"{}".to_vec());
                                    return Ok(build_response(
                                        StatusCode::BAD_REQUEST,
                                        HeaderValue::from_static("application/json"),
                                        request_id,
                                        traceparent,
                                        Bytes::from(text),
                                        false,
                                        Some(verdictan_headers(
                                            "BLOCK",
                                            &decision.reason_code,
                                            &state.config_version,
                                            latency_ms,
                                            prompt_redaction_applied,
                                            &response_redactions,
                                            quality_scores_for_event.as_ref(),
                                            false,
                                            verdictan_rbac_details(&decision),
                                        )),
                                    ));
                                }
                            }
                        }
                        "healthcare-compliance" => {
                            let cfg = state.policy_blocks.get("healthcare-compliance");

                            if parsed_out.is_none() {
                                parsed_out =
                                    serde_json::from_slice::<serde_json::Value>(&out_bytes).ok();
                            }
                            if let Some(v) = parsed_out.as_ref() {
                                let text = extract_openai_output_text_from_json(v);
                                let mut ev =
                                    crate::gateway::compliance::evaluate_healthcare_compliance(
                                        &text, cfg,
                                    );
                                if let Some(rewrite) = ev.rewrite.take() {
                                    if let Some(vmut) = parsed_out.as_mut() {
                                        if prepend_openai_output_in_place(vmut, &rewrite.prefix) {
                                            if let Ok(out) = serde_json::to_vec(vmut) {
                                                out_bytes = Bytes::from(out);
                                            }
                                        }
                                    }
                                }
                                decision.results.push(ev.policy_result);
                                if ev.should_block {
                                    decision.final_verdict = Verdict::Block;
                                    decision.reason_code = decision
                                        .results
                                        .last()
                                        .map(|r| r.reason_code.clone())
                                        .unwrap_or_else(|| "healthcare.blocked".to_string());

                                    let latency_ms = start.elapsed().as_millis() as i64;
                                    if let Some(sink) = &state.event_sink {
                                        let event = decision_event_json(
                                            &state.config_version,
                                            &request_id,
                                            &decision,
                                            false,
                                            prompt_redaction_applied,
                                            prompt_hash.clone(),
                                            quality_scores_for_event.clone(),
                                            state.registered_agent_id(),
                                            state.request_finops.as_ref(),
                                            state.session_id.as_deref(),
                                        );
                                        sink.enqueue_decision(&request_id, event);
                                    }

                                    let verdictan = verdictan_extension_json(
                                        "BLOCK",
                                        &decision.reason_code,
                                        &state.config_version,
                                        &request_id,
                                        latency_ms,
                                        None,
                                        None,
                                    );
                                    let body = serde_json::json!({
                                        "error": error_json(
                                            &format!(
                                                "Response blocked by policy: {}",
                                                decision.reason_code
                                            ),
                                            "invalid_request_error",
                                            "content_policy_violation",
                                        ),
                                        "verdictan": verdictan,
                                    });

                                    let text = serde_json::to_vec(&body)
                                        .unwrap_or_else(|_| b"{}".to_vec());
                                    return Ok(build_response(
                                        StatusCode::BAD_REQUEST,
                                        HeaderValue::from_static("application/json"),
                                        request_id,
                                        traceparent,
                                        Bytes::from(text),
                                        false,
                                        Some(verdictan_headers(
                                            "BLOCK",
                                            &decision.reason_code,
                                            &state.config_version,
                                            latency_ms,
                                            prompt_redaction_applied,
                                            &response_redactions,
                                            quality_scores_for_event.as_ref(),
                                            false,
                                            verdictan_rbac_details(&decision),
                                        )),
                                    ));
                                }
                            }
                        }
                        "legal-privilege" => {
                            let cfg = state.policy_blocks.get("legal-privilege");

                            if parsed_out.is_none() {
                                parsed_out =
                                    serde_json::from_slice::<serde_json::Value>(&out_bytes).ok();
                            }
                            if let Some(v) = parsed_out.as_ref() {
                                let text = extract_openai_output_text_from_json(v);
                                let ev = crate::gateway::compliance::evaluate_legal_privilege(
                                    &text, cfg,
                                );
                                decision.results.push(ev.policy_result);
                                if ev.should_block {
                                    decision.final_verdict = Verdict::Block;
                                    decision.reason_code = decision
                                        .results
                                        .last()
                                        .map(|r| r.reason_code.clone())
                                        .unwrap_or_else(|| "legal.privilege_detected".to_string());

                                    let latency_ms = start.elapsed().as_millis() as i64;
                                    if let Some(sink) = &state.event_sink {
                                        let event = decision_event_json(
                                            &state.config_version,
                                            &request_id,
                                            &decision,
                                            false,
                                            prompt_redaction_applied,
                                            prompt_hash.clone(),
                                            quality_scores_for_event.clone(),
                                            state.registered_agent_id(),
                                            state.request_finops.as_ref(),
                                            state.session_id.as_deref(),
                                        );
                                        sink.enqueue_decision(&request_id, event);
                                    }

                                    let verdictan = verdictan_extension_json(
                                        "BLOCK",
                                        &decision.reason_code,
                                        &state.config_version,
                                        &request_id,
                                        latency_ms,
                                        None,
                                        None,
                                    );
                                    let body = serde_json::json!({
                                        "error": error_json(
                                            &format!(
                                                "Response blocked by policy: {}",
                                                decision.reason_code
                                            ),
                                            "invalid_request_error",
                                            "content_policy_violation",
                                        ),
                                        "verdictan": verdictan,
                                    });

                                    let text = serde_json::to_vec(&body)
                                        .unwrap_or_else(|_| b"{}".to_vec());
                                    return Ok(build_response(
                                        StatusCode::BAD_REQUEST,
                                        HeaderValue::from_static("application/json"),
                                        request_id,
                                        traceparent,
                                        Bytes::from(text),
                                        false,
                                        Some(verdictan_headers(
                                            "BLOCK",
                                            &decision.reason_code,
                                            &state.config_version,
                                            latency_ms,
                                            prompt_redaction_applied,
                                            &response_redactions,
                                            quality_scores_for_event.as_ref(),
                                            false,
                                            verdictan_rbac_details(&decision),
                                        )),
                                    ));
                                }
                            }
                        }
                        "upl-filter" => {
                            let cfg = state.policy_blocks.get("upl-filter");

                            if parsed_out.is_none() {
                                parsed_out =
                                    serde_json::from_slice::<serde_json::Value>(&out_bytes).ok();
                            }
                            if let Some(v) = parsed_out.as_ref() {
                                let text = extract_openai_output_text_from_json(v);
                                let mut ev =
                                    crate::gateway::compliance::evaluate_upl_filter(&text, cfg);
                                if let Some(rewrite) = ev.rewrite.take() {
                                    if let Some(vmut) = parsed_out.as_mut() {
                                        if prepend_openai_output_in_place(vmut, &rewrite.prefix) {
                                            if let Ok(out) = serde_json::to_vec(vmut) {
                                                out_bytes = Bytes::from(out);
                                            }
                                        }
                                    }
                                }
                                decision.results.push(ev.policy_result);
                                if ev.should_block {
                                    decision.final_verdict = Verdict::Block;
                                    decision.reason_code = decision
                                        .results
                                        .last()
                                        .map(|r| r.reason_code.clone())
                                        .unwrap_or_else(|| "upl.blocked".to_string());

                                    let latency_ms = start.elapsed().as_millis() as i64;
                                    if let Some(sink) = &state.event_sink {
                                        let event = decision_event_json(
                                            &state.config_version,
                                            &request_id,
                                            &decision,
                                            false,
                                            prompt_redaction_applied,
                                            prompt_hash.clone(),
                                            quality_scores_for_event.clone(),
                                            state.registered_agent_id(),
                                            state.request_finops.as_ref(),
                                            state.session_id.as_deref(),
                                        );
                                        sink.enqueue_decision(&request_id, event);
                                    }

                                    let verdictan = verdictan_extension_json(
                                        "BLOCK",
                                        &decision.reason_code,
                                        &state.config_version,
                                        &request_id,
                                        latency_ms,
                                        None,
                                        None,
                                    );
                                    let body = serde_json::json!({
                                        "error": error_json(
                                            &format!(
                                                "Response blocked by policy: {}",
                                                decision.reason_code
                                            ),
                                            "invalid_request_error",
                                            "content_policy_violation",
                                        ),
                                        "verdictan": verdictan,
                                    });

                                    let text = serde_json::to_vec(&body)
                                        .unwrap_or_else(|_| b"{}".to_vec());
                                    return Ok(build_response(
                                        StatusCode::BAD_REQUEST,
                                        HeaderValue::from_static("application/json"),
                                        request_id,
                                        traceparent,
                                        Bytes::from(text),
                                        false,
                                        Some(verdictan_headers(
                                            "BLOCK",
                                            &decision.reason_code,
                                            &state.config_version,
                                            latency_ms,
                                            prompt_redaction_applied,
                                            &response_redactions,
                                            quality_scores_for_event.as_ref(),
                                            false,
                                            verdictan_rbac_details(&decision),
                                        )),
                                    ));
                                }
                            }
                        }
                        "bias-monitor" => {
                            let cfg = state.policy_blocks.get("bias-monitor");

                            if parsed_out.is_none() {
                                parsed_out =
                                    serde_json::from_slice::<serde_json::Value>(&out_bytes).ok();
                            }
                            if let Some(v) = parsed_out.as_ref() {
                                let response_text = extract_openai_output_text_from_json(v);
                                let request_text = messages_for_eval
                                    .iter()
                                    .map(|m| m.content.as_str())
                                    .collect::<Vec<_>>()
                                    .join("\n");

                                let ev = crate::gateway::compliance::evaluate_bias_monitor(
                                    &request_text,
                                    &response_text,
                                    cfg,
                                );
                                decision.results.push(ev.policy_result);
                                if ev.should_escalate {
                                    decision.final_verdict = Verdict::Escalate;
                                    decision.reason_code = decision
                                        .results
                                        .last()
                                        .map(|r| r.reason_code.clone())
                                        .unwrap_or_else(|| "bias.detected".to_string());

                                    let latency_ms = start.elapsed().as_millis() as i64;
                                    if let Some(sink) = &state.event_sink {
                                        let mut event = decision_event_json(
                                            &state.config_version,
                                            &request_id,
                                            &decision,
                                            false,
                                            prompt_redaction_applied,
                                            prompt_hash.clone(),
                                            quality_scores_for_event.clone(),
                                            state.registered_agent_id(),
                                            state.request_finops.as_ref(),
                                            state.session_id.as_deref(),
                                        );

                                        // Inject escalation routing hint from the provider registry config.
                                        let requested_model =
                                            parsed_json.get("model").and_then(|v| v.as_str());
                                        if let (Some(registry), Some(model)) =
                                            (&state.provider_registry, requested_model)
                                        {
                                            if let Some(routing) =
                                                registry.resolve_escalation_routing_for_model(model)
                                            {
                                                let hint = serde_json::json!({
                                                    "team_id": routing.team_id,
                                                    "user_id": routing.user_id,
                                                });
                                                if let Some(obj) = event.as_object_mut() {
                                                    let metadata = obj
                                                        .entry("metadata")
                                                        .or_insert_with(|| serde_json::json!({}));
                                                    if let Some(meta_obj) = metadata.as_object_mut()
                                                    {
                                                        meta_obj.insert(
                                                            "escalation_routing".to_string(),
                                                            hint,
                                                        );
                                                    }
                                                }
                                            }
                                        }

                                        sink.enqueue_decision(&request_id, event);
                                    }

                                    let escalation_id = format!("esc_{}", request_id);
                                    let verdictan = verdictan_extension_json(
                                        "ESCALATE",
                                        &decision.reason_code,
                                        &state.config_version,
                                        &request_id,
                                        latency_ms,
                                        Some(
                                            serde_json::json!({"id": escalation_id, "status": "queued"}),
                                        ),
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
                                    let text = serde_json::to_vec(&body)
                                        .unwrap_or_else(|_| b"{}".to_vec());
                                    return Ok(build_response(
                                        StatusCode::OK,
                                        HeaderValue::from_static("application/json"),
                                        request_id,
                                        traceparent,
                                        Bytes::from(text),
                                        false,
                                        Some(verdictan_headers(
                                            "ESCALATE",
                                            &decision.reason_code,
                                            &state.config_version,
                                            latency_ms,
                                            prompt_redaction_applied,
                                            &response_redactions,
                                            quality_scores_for_event.as_ref(),
                                            false,
                                            verdictan_rbac_details(&decision),
                                        )),
                                    ));
                                }
                            }
                        }
                        "quality-scorer" => {
                            if let Some(quality_cfg) = state.policy_blocks.get("quality-scorer") {
                                match crate::gateway::quality::evaluate_quality_scorer(
                                    &parsed_json,
                                    &out_bytes,
                                    quality_cfg,
                                )
                                .await
                                {
                                    Ok(qr) => {
                                        quality_scores_for_event =
                                            Some(filter_quality_scores_for_event(&qr.scores));
                                        // Phase 7: emit a typed score span when the judge produced a result.
                                        if let Some(ref judge) = qr.judge_result {
                                            let score_span = tracing::info_span!(
                                                "quality_score_evaluation",
                                                verdictan_span_type = "score",
                                            );
                                            crate::telemetry::attach_parent_trace_context(
                                                &score_span,
                                                &traceparent,
                                            );
                                            crate::telemetry::annotate_score_span_attributes(
                                                &score_span,
                                                judge,
                                                Some(start.elapsed().as_millis() as i64),
                                            );
                                            async {}.instrument(score_span).await;
                                        }
                                        let failure_action = quality_cfg
                                            .get("failure_action")
                                            .and_then(|v| v.get("action"))
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("block");

                                        if qr.block && failure_action == "fallback" {
                                            let fallback_message = quality_cfg
                                                .get("failure_action")
                                                .and_then(|v| v.get("fallback_message"))
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("I apologize, but I cannot provide a sufficiently accurate response to this query.");

                                            if parsed_out.is_none() {
                                                parsed_out =
                                                    serde_json::from_slice::<serde_json::Value>(
                                                        &out_bytes,
                                                    )
                                                    .ok();
                                            }
                                            if let Some(v) = parsed_out.as_mut() {
                                                if replace_openai_responses_output_in_place(
                                                    v,
                                                    fallback_message,
                                                ) || replace_openai_chat_output_in_place(
                                                    v,
                                                    fallback_message,
                                                ) {
                                                    if let Ok(re) = serde_json::to_vec(v) {
                                                        out_bytes = Bytes::from(re);
                                                    }
                                                }
                                            }

                                            let mut pr = qr.policy_result;
                                            pr.verdict = Verdict::Allow;
                                            pr.reason_code = "quality.fallback".to_string();
                                            pr.details = Some(serde_json::json!({
                                                "action": "fallback",
                                                "original_failure_reason": qr.reason_code,
                                                "scores": qr.scores,
                                            }));
                                            // Surface the fallback in the top-level decision so
                                            // callers can distinguish "quality passed" (ok) from
                                            // "quality failed but content was replaced" (quality.fallback).
                                            decision.reason_code = "quality.fallback".to_string();
                                            decision.results.push(pr);
                                        } else {
                                            decision.results.push(qr.policy_result);
                                        }

                                        if qr.block && failure_action != "fallback" {
                                            decision.final_verdict = Verdict::Block;
                                            decision.reason_code = qr.reason_code;

                                            let latency_ms = start.elapsed().as_millis() as i64;

                                            if let Some(sink) = &state.event_sink {
                                                let event = decision_event_json(
                                                    &state.config_version,
                                                    &request_id,
                                                    &decision,
                                                    false,
                                                    prompt_redaction_applied,
                                                    prompt_hash.clone(),
                                                    quality_scores_for_event.clone(),
                                                    state.registered_agent_id(),
                                                    state.request_finops.as_ref(),
                                                    state.session_id.as_deref(),
                                                );
                                                sink.enqueue_decision(&request_id, event);
                                            }

                                            let verdictan = verdictan_extension_json(
                                                "BLOCK",
                                                &decision.reason_code,
                                                &state.config_version,
                                                &request_id,
                                                latency_ms,
                                                None,
                                                None,
                                            );
                                            let body = serde_json::json!({
                                                "error": error_json(
                                                    &format!(
                                                        "Response blocked by policy: {}",
                                                        decision.reason_code
                                                    ),
                                                    "invalid_request_error",
                                                    "content_policy_violation",
                                                ),
                                                "verdictan": verdictan,
                                            });

                                            let text = serde_json::to_vec(&body)
                                                .unwrap_or_else(|_| b"{}".to_vec());
                                            return Ok(build_response(
                                                StatusCode::BAD_REQUEST,
                                                HeaderValue::from_static("application/json"),
                                                request_id,
                                                traceparent,
                                                Bytes::from(text),
                                                false,
                                                Some(verdictan_headers(
                                                    "BLOCK",
                                                    &decision.reason_code,
                                                    &state.config_version,
                                                    latency_ms,
                                                    prompt_redaction_applied,
                                                    &response_redactions,
                                                    quality_scores_for_event.as_ref(),
                                                    false,
                                                    verdictan_rbac_details(&decision),
                                                )),
                                            ));
                                        }
                                    }
                                    Err(_e) => {
                                        // If scoring fails, do not block; treat as allow.
                                    }
                                }
                            }
                        }
                        "human-oversight" => {
                            if let Some(oversight_cfg) = state.policy_blocks.get("human-oversight")
                            {
                                if let Some(action) =
                                    oversight_cfg.get("action").and_then(|v| v.as_str())
                                {
                                    if action == "escalate" {
                                        decision.final_verdict = Verdict::Escalate;
                                        decision.reason_code = "oversight.required".to_string();
                                        decision.results.push(enforcement::PolicyResult {
                                            policy_kind: "human-oversight".to_string(),
                                            phase: "output".to_string(),
                                            verdict: Verdict::Escalate,
                                            reason_code: "oversight.required".to_string(),
                                            details: None,
                                            redaction_targets: None,
                                        });

                                        let latency_ms = start.elapsed().as_millis() as i64;
                                        if let Some(sink) = &state.event_sink {
                                            let mut event = decision_event_json(
                                                &state.config_version,
                                                &request_id,
                                                &decision,
                                                false,
                                                prompt_redaction_applied,
                                                prompt_hash.clone(),
                                                quality_scores_for_event.clone(),
                                                state.registered_agent_id(),
                                                state.request_finops.as_ref(),
                                                state.session_id.as_deref(),
                                            );

                                            // Inject escalation routing hint from the provider registry config.
                                            let requested_model =
                                                parsed_json.get("model").and_then(|v| v.as_str());
                                            if let (Some(registry), Some(model)) =
                                                (&state.provider_registry, requested_model)
                                            {
                                                if let Some(routing) = registry
                                                    .resolve_escalation_routing_for_model(model)
                                                {
                                                    let hint = serde_json::json!({
                                                        "team_id": routing.team_id,
                                                        "user_id": routing.user_id,
                                                    });
                                                    if let Some(obj) = event.as_object_mut() {
                                                        let metadata =
                                                            obj.entry("metadata").or_insert_with(
                                                                || serde_json::json!({}),
                                                            );
                                                        if let Some(meta_obj) =
                                                            metadata.as_object_mut()
                                                        {
                                                            meta_obj.insert(
                                                                "escalation_routing".to_string(),
                                                                hint,
                                                            );
                                                        }
                                                    }
                                                }
                                            }

                                            sink.enqueue_decision(&request_id, event);
                                        }

                                        let escalation_id = format!("esc_{}", request_id);
                                        let verdictan = verdictan_extension_json(
                                            "ESCALATE",
                                            &decision.reason_code,
                                            &state.config_version,
                                            &request_id,
                                            latency_ms,
                                            Some(
                                                serde_json::json!({"id": escalation_id, "status": "queued"}),
                                            ),
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
                                        let text = serde_json::to_vec(&body)
                                            .unwrap_or_else(|_| b"{}".to_vec());
                                        return Ok(build_response(
                                            StatusCode::OK,
                                            HeaderValue::from_static("application/json"),
                                            request_id,
                                            traceparent,
                                            Bytes::from(text),
                                            false,
                                            Some(verdictan_headers(
                                                "ESCALATE",
                                                &decision.reason_code,
                                                &state.config_version,
                                                latency_ms,
                                                prompt_redaction_applied,
                                                &response_redactions,
                                                quality_scores_for_event.as_ref(),
                                                false,
                                                verdictan_rbac_details(&decision),
                                            )),
                                        ));
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            if let Some(sink) = &state.event_sink {
                let request_payload_for_event =
                    serde_json::from_slice::<serde_json::Value>(&body_bytes).ok();
                let response_payload_for_event =
                    serde_json::from_slice::<serde_json::Value>(&out_bytes).ok();
                let (request_payload_for_event, response_payload_for_event) =
                    silent_engine_event_payloads(
                        &state,
                        request_payload_for_event,
                        response_payload_for_event,
                    );
                let mut event = decision_event_json(
                    &state.config_version,
                    &request_id,
                    &decision,
                    false,
                    prompt_redaction_applied,
                    prompt_hash.clone(),
                    quality_scores_for_event.clone(),
                    state.registered_agent_id(),
                    state.request_finops.as_ref(),
                    state.session_id.as_deref(),
                );
                if let Some(review_result) = review_result_for_event.as_ref() {
                    inject_review_result_into_event(&mut event, review_result);
                }
                annotate_cache_replay_metadata(&mut event, cache_replay_metadata.as_ref());
                enrich_decision_event_details(
                    &mut event,
                    request_payload_for_event,
                    response_payload_for_event,
                    "POST",
                    status,
                    decision_runtime_json(&state, "/v1/responses", resp.is_cached()),
                    &trace_correlation,
                );
                apply_silent_engine_event_sanitization(&state, &mut event);
                sink.enqueue_decision(&request_id, event);
            }

            if resp.is_cached() {
                emit_cache_hit_economics(
                    &state,
                    &request_id,
                    &traceparent,
                    &out_bytes,
                    cache_tier,
                    early_cache_outcome
                        .unwrap_or(CacheReplayOutcome::ExactHit)
                        .hit_type(),
                    provider_cache_key.as_deref(),
                    &selected_fabric_slices,
                );
            }

            if ua_financial_path_active && !resp.is_cached() {
                finalize_ua_financial_lifecycle(
                    &state,
                    &parsed_json,
                    &resp,
                    &request_id,
                    &traceparent,
                )
                .await;
            } else {
                finalize_connected_access_after_buffered_response(
                    &state,
                    &parsed_json,
                    &body_bytes,
                    &resp,
                    &connected_access_dispatch_ctx,
                    &request_id,
                    &traceparent,
                    served_provider_id.as_deref(),
                    Some(start.elapsed().as_millis() as i64),
                );
            }

            let mut history_response_payload =
                serde_json::from_slice::<serde_json::Value>(&out_bytes)
                    .unwrap_or_else(|_| serde_json::json!({}));
            let capture_suggestion = build_capture_suggestion(
                &parsed_json,
                &history_response_payload,
                &context_fabric_policy,
            );
            maybe_auto_capture_response(
                &state,
                &headers,
                &parsed_json,
                &history_response_payload,
                session_context.as_ref(),
                &context_fabric_policy,
                &request_id,
            )
            .await;
            inject_context_fabric_verdictan_metadata(
                &mut history_response_payload,
                state.request_finops.as_ref(),
                recall_attribution.as_ref(),
                &context_fabric_policy.capture_mode,
                capture_suggestion.as_ref(),
            );
            emit_history_writeback(
                &state,
                &request_id,
                &traceparent,
                session_context.clone(),
                &body_bytes,
                history_response_payload,
                &decision.final_verdict,
                served_provider_id.as_deref(),
                parsed_json.get("model").and_then(|value| value.as_str()),
                Some(start.elapsed().as_millis() as i64),
            );

            let latency_ms = start.elapsed().as_millis() as i64;
            let verdictan_verdict = verdictan_verdict_for_success(&decision.final_verdict);
            let mut verdictan = verdictan_extension_json(
                verdictan_verdict,
                &decision.reason_code,
                &state.config_version,
                &request_id,
                latency_ms,
                None,
                if response_redactions.is_empty() {
                    None
                } else {
                    Some(
                        serde_json::to_value(&response_redactions)
                            .unwrap_or_else(|_| serde_json::json!([])),
                    )
                },
            );
            if let Some(review_result) = review_result_for_event.as_ref() {
                if let Some(obj) = verdictan.as_object_mut() {
                    obj.insert("review_result".to_string(), review_result.clone());
                }
            }

            if !response_redactions.is_empty() {
                if let Some(obj) = verdictan.as_object_mut() {
                    obj.insert(
                        "redaction_metadata".to_string(),
                        verdictan_redactions_json(&response_redactions),
                    );
                }
            }
            inject_context_fabric_verdictan_metadata(
                &mut verdictan,
                state.request_finops.as_ref(),
                recall_attribution.as_ref(),
                &context_fabric_policy.capture_mode,
                capture_suggestion.as_ref(),
            );
            let out_bytes = inject_verdictan_response_extension(out_bytes, verdictan);

            let mut response_headers = verdictan_headers(
                verdictan_verdict,
                &decision.reason_code,
                &state.config_version,
                latency_ms,
                prompt_redaction_applied,
                &response_redactions,
                quality_scores_for_event.as_ref(),
                false,
                verdictan_rbac_details(&decision),
            );
            append_cache_status_header(&mut response_headers, resp.is_cached());
            append_context_response_headers(
                &mut response_headers,
                recall_attribution.as_ref(),
                capture_suggestion.as_ref(),
            );
            Ok(inject_ratelimit_info(
                build_response(
                    status,
                    content_type,
                    request_id,
                    traceparent,
                    out_bytes,
                    false,
                    Some(response_headers),
                ),
                &cg_rl_info,
            ))
        }
        Err(upstream_err) => match state.fail_mode {
            FailMode::Block => {
                let latency_ms = start.elapsed().as_millis() as i64;
                if let Some(sink) = &state.event_sink {
                    let decision = DecisionEnvelope {
                        final_verdict: Verdict::Block,
                        reason_code: "proxy.upstream_unreachable".to_string(),
                        results: Vec::new(),
                    };
                    let event = decision_event_json(
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
                    sink.enqueue_decision(&request_id, event);
                }

                let provider_name = state.current_target_id.as_deref().unwrap_or("unknown");
                let upstream_url = state.upstream_base;
                let error_message =
                    format_upstream_unreachable_message(provider_name, upstream_url, &upstream_err);
                tracing::warn!(
                    request_id = %request_id,
                    provider = %provider_name,
                    upstream_url = %upstream_url,
                    error = %upstream_err,
                    "upstream provider unreachable"
                );
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
                        &error_message,
                        "invalid_request_error",
                        "proxy.upstream_unreachable",
                    ),
                    "verdictan": verdictan,
                });

                let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
                Ok(build_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    HeaderValue::from_static("application/json"),
                    request_id,
                    traceparent,
                    Bytes::from(text),
                    false,
                    Some(verdictan_headers(
                        "BLOCK",
                        "proxy.upstream_unreachable",
                        &state.config_version,
                        latency_ms,
                        false,
                        &[],
                        None,
                        false,
                        None,
                    )),
                ))
            }
            FailMode::Allow => {
                let latency_ms = start.elapsed().as_millis() as i64;
                if let Some(sink) = &state.event_sink {
                    let decision = DecisionEnvelope {
                        final_verdict: Verdict::Allow,
                        reason_code: "proxy.degraded_allow".to_string(),
                        results: Vec::new(),
                    };
                    let event = decision_event_json(
                        &state.config_version,
                        &request_id,
                        &decision,
                        true,
                        false,
                        prompt_hash.clone(),
                        None,
                        state.registered_agent_id(),
                        state.request_finops.as_ref(),
                        state.session_id.as_deref(),
                    );
                    sink.enqueue_decision(&request_id, event);
                }

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
                    "id": format!("resp_{}", request_id),
                    "object": "response",
                    "created_at": 0,
                    "model": "degraded",
                    "output": [
                        {
                            "id": "msg_0",
                            "type": "message",
                            "role": "assistant",
                            "content": [
                                {"type": "output_text", "text": "Upstream unavailable (degraded allow mode)."}
                            ]
                        }
                    ],
                    "verdictan": verdictan,
                });

                let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
                Ok(build_response(
                    StatusCode::OK,
                    HeaderValue::from_static("application/json"),
                    request_id,
                    traceparent,
                    Bytes::from(text),
                    true,
                    Some(verdictan_headers(
                        "ALLOW",
                        "proxy.degraded_allow",
                        &state.config_version,
                        latency_ms,
                        prompt_redaction_applied,
                        &[],
                        None,
                        true,
                        None,
                    )),
                ))
            }
        },
    }
}
