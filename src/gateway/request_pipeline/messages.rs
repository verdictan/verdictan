// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Family request-pipeline module.
//! Child of `gateway::server`; parent private items remain visible.
//! Non-streaming/SSE Messages share Chat/Responses input/tool/output/access/audit stages.
use super::super::*;
use super::*;
use uuid::Uuid;

fn messages_assistant_text(value: &serde_json::Value) -> String {
    value
        .get("content")
        .and_then(|c| c.as_array())
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| {
                    (b.get("type").and_then(|v| v.as_str()) == Some("text"))
                        .then(|| b.get("text").and_then(|v| v.as_str()).map(str::to_string))
                        .flatten()
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default()
}

fn messages_family_output_messages(
    parsed_output: Option<&serde_json::Value>,
    bytes: &Bytes,
) -> Vec<enforcement::ChatMessage> {
    if let Some(value) = parsed_output {
        let text = messages_assistant_text(value);
        if !text.trim().is_empty() {
            return vec![enforcement::ChatMessage {
                role: "assistant".into(),
                content: text,
            }];
        }
    }
    output_messages_for_stage(parsed_output, bytes)
}

fn redact_messages_request_body(
    value: &mut serde_json::Value,
    cfg: &crate::gateway::redaction::RedactionConfig,
) -> bool {
    crate::gateway::content_extraction::rewrite_request_text_segments_for_path(
        "/v1/messages",
        value,
        |segment| {
            let redacted = crate::gateway::redaction::redact_text_with_config(&segment.text, cfg);
            (redacted != segment.text).then_some(redacted)
        },
    )
}

fn redact_messages_response_body(
    bytes: &Bytes,
    cfg: &crate::gateway::redaction::RedactionConfig,
) -> Option<(Bytes, bool)> {
    let mut value = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    let mut changed = false;
    if let Some(content) = value.get_mut("content").and_then(|v| v.as_array_mut()) {
        for block in content {
            if block.get("type").and_then(|v| v.as_str()) != Some("text") {
                continue;
            }
            let Some(text) = block
                .get("text")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
            else {
                continue;
            };
            let redacted = crate::gateway::redaction::redact_text_with_config(&text, cfg);
            if redacted != text {
                block
                    .as_object_mut()?
                    .insert("text".into(), serde_json::Value::String(redacted));
                changed = true;
            }
        }
    }
    if !changed {
        return Some((bytes.clone(), false));
    }
    Some((Bytes::from(serde_json::to_vec(&value).ok()?), true))
}

fn emit_messages_decision_event(
    state: &ActiveGatewayStateView<'_>,
    request_id: &str,
    decision: &DecisionEnvelope,
    prompt_hash: String,
    body_bytes: &Bytes,
    status: StatusCode,
    prompt_redacted: bool,
    correlation: &TraceCorrelation,
) {
    let Some(sink) = state.event_sink.as_ref() else {
        return;
    };
    let mut event = decision_event_json(
        &state.config_version,
        request_id,
        decision,
        false,
        prompt_redacted,
        prompt_hash,
        None,
        state.registered_agent_id(),
        state.request_finops.as_ref(),
        state.session_id.as_deref(),
    );
    let (req_payload, resp_payload) = silent_engine_event_payloads(
        state,
        serde_json::from_slice::<serde_json::Value>(body_bytes).ok(),
        None,
    );
    enrich_decision_event_details(
        &mut event,
        req_payload,
        resp_payload,
        "POST",
        status,
        decision_runtime_json(state, "/v1/messages", false),
        correlation,
    );
    apply_silent_engine_event_sanitization(state, &mut event);
    sink.enqueue_decision(request_id, event);
}

fn evaluate_messages_tool_stage(
    active_chain: &[enforcement::ChainEntry],
    policy_blocks: &crate::gateway::PolicyBlocks,
    parsed_json: &serde_json::Value,
    authenticated_identity: Option<&crate::gateway::identity::AuthenticatedRequestIdentity>,
) -> Option<enforcement::PolicyResult> {
    if !active_chain.iter().any(|e| e.kind() == "agent-firewall") {
        return None;
    }
    // Fail closed on malformed structured tool calls; do not skip the stage.
    let calls = match crate::gateway::structured_tool_calls::canonical_tool_calls(parsed_json) {
        Ok(calls) => calls,
        Err(error) => {
            return Some(enforcement::PolicyResult {
                policy_kind: "agent-firewall".to_string(),
                phase: "tool".to_string(),
                verdict: Verdict::Block,
                reason_code: "agent_firewall.malformed_tool_call".to_string(),
                details: Some(serde_json::json!({"error": error.to_string()})),
                redaction_targets: None,
            });
        }
    };
    if calls.is_empty() {
        return None;
    }
    let result = enforcement::evaluate_agent_firewall_tool_calls(
        policy_blocks.get("agent-firewall"),
        &calls,
        authenticated_identity,
    );
    matches!(result.verdict, Verdict::Block | Verdict::Escalate).then_some(result)
}

pub(crate) async fn messages(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    mut headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let start = Instant::now();
    let x_request_id_in = headers.get("X-Request-Id").and_then(|v| v.to_str().ok());
    let request_id = match request_id::validate_or_generate_x_request_id(x_request_id_in) {
        Ok(id) => id,
        Err(err) => return Ok(reject_invalid_x_request_id(&headers, &err)),
    };
    let traceparent_in = headers.get("traceparent").and_then(|v| v.to_str().ok());
    let traceparent = request_id::normalize_or_generate_traceparent(traceparent_in);
    let mut state_view =
        match build_public_request_state(&state, &headers, peer_addr, &request_id, &traceparent)
            .await
        {
            Ok(state) => state,
            Err(response) => return Ok(response),
        };
    if let Err(response) = resolve_and_enforce_connected_endpoint_agent(
        &mut state_view,
        &headers,
        &request_id,
        &traceparent,
    )
    .await
    {
        return Ok(response);
    }

    inject_identity_headers_from_finops(&mut headers, state_view.request_finops.as_ref());

    let request_resolution = resolve_request("/v1/messages", "POST", &headers, &state_view);
    let _cg_rl_info = match enforce_consumer_group_rate_limit(
        &state_view,
        &request_id,
        request_resolution.consumer_group.as_ref(),
    ) {
        Ok(info) => info,
        Err(response) => return Ok(response),
    };

    let original_body_bytes = axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;

    let mut parsed_json = serde_json::from_slice::<serde_json::Value>(&original_body_bytes)
        .map_err(|_| {
            tracing::warn!(
                request_id = %request_id,
                "messages endpoint received invalid JSON body"
            );
            StatusCode::BAD_REQUEST
        })?;
    let stream_requested = crate::gateway::sse::stream_requested(&parsed_json);
    let prompt_hash = sha256_prefixed(&original_body_bytes);
    let redaction_cfg =
        build_prompt_redaction_config(&state_view.policy_chain, &state_view.policy_blocks);
    let mut prompt_redacted = false;
    let mut body_bytes = Bytes::from(original_body_bytes.to_vec());

    let correlation = extract_trace_correlation(&parsed_json);
    let telemetry_hints = RequestTelemetryHints::default();
    let messages_for_eval: Arc<[enforcement::ChatMessage]> =
        Arc::from(extract_messages_from_value(Some(&parsed_json)));
    // SEC-009: team selectors come from authenticated finops memberships;
    // X-Verdictan-Team is only a local unauthenticated profile selector.
    let request_team_slugs = resolve_request_team_slugs(
        &headers,
        state_view.request_finops.as_ref(),
        !state_view.connected_mode,
    );
    let active_chain =
        effective_chain_for_request(&state_view, &request_resolution, &request_team_slugs);

    let mut decision = if !active_chain.is_empty() {
        let policy_headers = policy_input_headers(&headers, state_view.request_finops.as_ref());
        enforcement::evaluate_chain_entries_with_identity(
            &active_chain,
            "/v1/messages",
            &state_view.policy_blocks,
            Some(&parsed_json),
            &policy_headers,
            &messages_for_eval,
            state_view
                .request_finops
                .as_ref()
                .and_then(|finops| finops.authenticated_identity.as_ref()),
        )
        .await
    } else {
        DecisionEnvelope {
            final_verdict: Verdict::Allow,
            reason_code: "ok".to_string(),
            results: Vec::new(),
        }
    };

    if let Some(tool_result) = evaluate_messages_tool_stage(
        &active_chain,
        &state_view.policy_blocks,
        &parsed_json,
        state_view
            .request_finops
            .as_ref()
            .and_then(|finops| finops.authenticated_identity.as_ref()),
    ) {
        decision.final_verdict = tool_result.verdict.clone();
        decision.reason_code = tool_result.reason_code.clone();
        decision.results.push(tool_result);
    }

    if matches!(decision.final_verdict, Verdict::Block | Verdict::Escalate) {
        let latency_ms = start.elapsed().as_millis() as i64;
        let status = if decision.final_verdict == Verdict::Block {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::OK
        };
        emit_messages_decision_event(
            &state_view,
            &request_id,
            &decision,
            prompt_hash.clone(),
            &body_bytes,
            status,
            prompt_redacted,
            &correlation,
        );
        if let Some(response) = build_stage_verdict_response(
            &decision,
            &state_view.config_version,
            &request_id,
            &traceparent,
            latency_ms,
            prompt_redacted,
            &[],
            None,
        ) {
            return Ok(response);
        }
    }

    if active_chain
        .iter()
        .any(|entry| entry.kind() == "request-rewriter")
    {
        if let Some(cfg) = state_view.policy_blocks.get("request-rewriter") {
            let rewrite_eval =
                crate::gateway::request_rewrite::evaluate_request_rewriter(&parsed_json, cfg);
            if let Some(rewritten) = rewrite_eval.rewritten_request {
                parsed_json = rewritten;
                if let Ok(bytes) = serde_json::to_vec(&parsed_json) {
                    body_bytes = Bytes::from(bytes);
                }
            }
            decision.results.push(rewrite_eval.policy_result);
        }
    }

    if decision
        .results
        .iter()
        .any(|result| result.verdict == Verdict::Redact)
    {
        if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            if redact_messages_request_body(&mut value, &redaction_cfg) {
                if let Ok(bytes) = serde_json::to_vec(&value) {
                    body_bytes = Bytes::from(bytes);
                    prompt_redacted = true;
                    parsed_json = value;
                }
            }
        }
    }

    let mut upstream_body_bytes = body_bytes.clone();
    if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&upstream_body_bytes) {
        if strip_verdictan_request_extension(&mut value) {
            if let Ok(bytes) = serde_json::to_vec(&value) {
                upstream_body_bytes = Bytes::from(bytes);
            }
        }
    }

    let connected_access_status = match connected_access_status_for_request(
        &mut state_view,
        &parsed_json,
        &request_id,
        extract_requested_max_tokens(&parsed_json).unwrap_or(4096) as u64,
    )
    .await
    {
        Ok(status) => status,
        Err(response) => return Ok(response),
    };
    let access_dispatch_ctx = match maybe_prepare_connected_access_dispatch(
        &mut state_view,
        &headers,
        &parsed_json,
        &request_id,
        &traceparent,
        &prompt_hash,
        extract_requested_max_tokens(&parsed_json).unwrap_or(4096) as u64,
        connected_access_status.admission_credential_source,
        connected_access_status.dispatch_precluded,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return Ok(response),
    };

    if let Err(response) = persist_admitted_decision_before_dispatch(
        &state_view,
        &request_id,
        &traceparent,
        &decision,
        &prompt_hash,
        "/v1/messages",
    ) {
        return Ok(response);
    }

    let policy_chain_kinds: Vec<String> = active_chain
        .iter()
        .map(|entry| entry.kind().to_string())
        .collect();
    let streaming_requires_buffering =
        streaming_requires_buffering(&policy_chain_kinds, &state_view.policy_blocks);
    let streaming_redaction_enabled =
        streaming_output_redaction_enabled(&policy_chain_kinds, &state_view.policy_blocks);

    if stream_requested {
        let (response, served_provider) = send_streaming_with_provider_fallback(
            &state_view,
            &headers,
            "/v1/messages",
            upstream_body_bytes.clone(),
            &request_id,
            &traceparent,
            &correlation,
            &telemetry_hints,
            None,
        )
        .await;

        return match response {
            Ok(response) if response.status.is_success() => {
                tracing::info!(
                    request_id = %request_id,
                    served_provider = ?served_provider,
                    latency_ms = start.elapsed().as_millis() as i64,
                    "messages endpoint streaming response proxied"
                );
                if streaming_requires_buffering || streaming_redaction_enabled {
                    Ok(build_messages_governed_streaming_response(
                        response,
                        &state_view,
                        upstream_body_bytes.clone(),
                        &request_id,
                        &traceparent,
                        served_provider.clone(),
                        access_dispatch_ctx.clone(),
                        decision.clone(),
                        prompt_hash.clone(),
                        policy_chain_kinds,
                        redaction_cfg.clone(),
                        streaming_redaction_enabled,
                        start,
                    ))
                } else if state_view.connected_mode {
                    Ok(build_messages_connected_streaming_response(
                        response,
                        &state_view,
                        upstream_body_bytes.clone(),
                        &request_id,
                        &traceparent,
                        served_provider.clone(),
                        access_dispatch_ctx.clone(),
                    ))
                } else {
                    Ok(prepared_streaming_response_to_http_response(
                        response,
                        &request_id,
                        &traceparent,
                    ))
                }
            }
            Ok(response) => {
                let body = collect_prepared_stream_body(response.body).await;
                Ok(build_response(
                    response.status,
                    response.content_type,
                    request_id,
                    traceparent,
                    body,
                    false,
                    None,
                ))
            }
            Err(error) => {
                tracing::error!(error = %error, "messages streaming endpoint upstream error");
                let latency_ms = start.elapsed().as_millis() as i64;
                let bytes = build_streaming_error_sse_bytes(
                    &request_id,
                    &state_view.config_version,
                    "BLOCK",
                    "proxy.upstream_stream_interrupted",
                    &format!("Upstream streaming response interrupted: {error}"),
                    latency_ms,
                )
                .unwrap_or_else(|| Bytes::from_static(b"data: [DONE]\n\n"));
                Ok(build_response(
                    StatusCode::BAD_GATEWAY,
                    HeaderValue::from_static("text/event-stream"),
                    request_id,
                    traceparent,
                    bytes,
                    true,
                    None,
                ))
            }
        };
    }

    let (upstream_resp, served_provider_id) = send_with_provider_fallback(
        &state_view,
        &headers,
        "/v1/messages",
        upstream_body_bytes.clone(),
        &request_id,
        &traceparent,
        None,
        &correlation,
        &telemetry_hints,
        None,
    )
    .await;
    match upstream_resp {
        Ok(response) => {
            let mut out_bytes = response.body().clone();
            let post_request_decision =
                enforcement::evaluate_chain_entries_for_stage_with_identity(
                    &active_chain,
                    enforcement::ExecutionStage::PostRequest,
                    "/v1/messages",
                    &state_view.policy_blocks,
                    Some(&parsed_json),
                    None,
                    &headers,
                    &messages_for_eval,
                    state_view
                        .request_finops
                        .as_ref()
                        .and_then(|finops| finops.authenticated_identity.as_ref()),
                )
                .await;
            merge_stage_decision(&mut decision, post_request_decision);

            let parsed_stage_output = serde_json::from_slice::<serde_json::Value>(&out_bytes).ok();
            let pre_response_messages: Arc<[enforcement::ChatMessage]> = Arc::from(
                messages_family_output_messages(parsed_stage_output.as_ref(), &out_bytes),
            );
            let pre_response_decision =
                enforcement::evaluate_chain_entries_for_stage_with_identity(
                    &active_chain,
                    enforcement::ExecutionStage::PreResponse,
                    "/v1/messages",
                    &state_view.policy_blocks,
                    Some(&parsed_json),
                    parsed_stage_output.as_ref(),
                    &headers,
                    &pre_response_messages,
                    state_view
                        .request_finops
                        .as_ref()
                        .and_then(|finops| finops.authenticated_identity.as_ref()),
                )
                .await;
            merge_stage_decision(&mut decision, pre_response_decision);
            if let Some(blocked) = build_stage_verdict_response(
                &decision,
                &state_view.config_version,
                &request_id,
                &traceparent,
                start.elapsed().as_millis() as i64,
                prompt_redacted,
                &[],
                None,
            ) {
                emit_messages_decision_event(
                    &state_view,
                    &request_id,
                    &decision,
                    prompt_hash.clone(),
                    &body_bytes,
                    StatusCode::BAD_REQUEST,
                    prompt_redacted,
                    &correlation,
                );
                return Ok(blocked);
            }

            let mut response_redacted = false;
            if streaming_output_redaction_enabled(&policy_chain_kinds, &state_view.policy_blocks) {
                if let Some((redacted_bytes, changed)) =
                    redact_messages_response_body(&out_bytes, &redaction_cfg)
                {
                    out_bytes = redacted_bytes;
                    response_redacted = changed;
                }
            }
            let mut response = response;
            if response_redacted {
                response.body = out_bytes;
            }

            finalize_connected_access_after_buffered_response(
                &state_view,
                &parsed_json,
                &upstream_body_bytes,
                &response,
                &access_dispatch_ctx,
                &request_id,
                &traceparent,
                served_provider_id.as_deref(),
                Some(start.elapsed().as_millis() as i64),
            );
            emit_messages_decision_event(
                &state_view,
                &request_id,
                &decision,
                prompt_hash,
                &body_bytes,
                response.status(),
                prompt_redacted || response_redacted,
                &correlation,
            );
            Ok(buffered_response_to_http_response(
                response,
                &request_id,
                &traceparent,
            ))
        }
        Err(e) => {
            tracing::error!(error = %e, "messages endpoint upstream error");
            let body = serde_json::json!({
                "error": error_json(
                    &format!("Upstream error: {e}"),
                    "server_error",
                    "upstream_error",
                )
            });
            let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
            Ok(build_response(
                StatusCode::BAD_GATEWAY,
                HeaderValue::from_static("application/json"),
                request_id,
                traceparent,
                Bytes::from(text),
                true,
                None,
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_messages_governed_streaming_response(
    response: PreparedStreamingResponse,
    state: &ActiveGatewayStateView<'_>,
    request_body_bytes: Bytes,
    request_id: &str,
    traceparent: &str,
    served_provider_id: Option<String>,
    access_dispatch_ctx: ConnectedAccessDispatchContext,
    mut decision: DecisionEnvelope,
    prompt_hash: String,
    policy_chain: Vec<String>,
    redaction_cfg: crate::gateway::redaction::RedactionConfig,
    streaming_redaction_enabled: bool,
    start: Instant,
) -> Response<Body> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(16);
    let request_id_for_task = request_id.to_string();
    let traceparent_for_task = traceparent.to_string();
    let event_sink_for_task = state.event_sink.clone();
    let key_budget_tracker_for_task = Arc::clone(state.key_budget_tracker);
    let access_dispatch_ctx_for_task = access_dispatch_ctx.clone();
    let served_provider_id_for_task = served_provider_id;
    let config_version_for_task = state.config_version.clone();
    let policy_blocks_for_task = state.policy_blocks.clone();
    let registered_agent_id_for_task = state.registered_agent_id().map(str::to_string);
    let request_finops_for_task = state.request_finops.clone();
    let session_id_for_task = state.session_id.clone();
    let PreparedStreamingResponse {
        status,
        content_type,
        body,
    } = response;

    let streaming_agent_firewall = streaming_agent_firewall_enabled(&policy_chain);

    tokio::spawn(async move {
        let stream_start = Instant::now();
        let mut parser_buffer = Vec::new();
        let mut accumulated_content = String::new();
        let mut finish_reason = None;
        let mut buffered_chunks: Vec<Bytes> = Vec::new();
        let mut tool_call_accumulator =
            crate::gateway::structured_tool_calls::StreamingToolCallAccumulator::default();
        let mut upstream_stream = body;
        let mut blocked = false;
        let mut block_message = "Streaming response blocked by output policy";

        while let Some(chunk) = upstream_stream.next().await {
            match chunk {
                Ok(chunk) => {
                    buffered_chunks.push(chunk.clone());
                    parser_buffer.extend_from_slice(&chunk);
                    for payload in crate::gateway::sse::drain_sse_data_frames(&mut parser_buffer) {
                        crate::gateway::sse::accumulate_messages_delta(
                            &payload,
                            &mut accumulated_content,
                            &mut finish_reason,
                        );
                        if streaming_agent_firewall {
                            let _ = tool_call_accumulator.ingest_sse_payload(&payload);
                        }
                    }
                    if let Some(result) = evaluate_streaming_blocking_policy(
                        &policy_chain,
                        &policy_blocks_for_task,
                        &accumulated_content,
                    ) {
                        decision.final_verdict = Verdict::Block;
                        decision.reason_code = result.reason_code.clone();
                        decision.results.push(result);
                        blocked = true;
                        break;
                    }
                }
                Err(error) => {
                    let _ = tx.send(Err(error)).await;
                    return;
                }
            }
        }

        // SEC-026: authorize assembled structured tool calls before any buffered
        // frames reach auto-executing Anthropic/Messages clients.
        if !blocked && streaming_agent_firewall {
            if let Some(result) = evaluate_streaming_agent_firewall(
                &policy_chain,
                &policy_blocks_for_task,
                tool_call_accumulator,
                request_finops_for_task
                    .as_ref()
                    .and_then(|finops| finops.authenticated_identity.as_ref()),
            ) {
                decision.final_verdict = result.verdict.clone();
                decision.reason_code = result.reason_code.clone();
                decision.results.push(result);
                blocked = true;
                block_message = "Streaming tool call blocked by Agent Firewall";
            }
        }

        if blocked {
            let latency_ms = start.elapsed().as_millis() as i64;
            if let Some(sink) = event_sink_for_task.as_ref() {
                let mut event = decision_event_json(
                    &config_version_for_task,
                    &request_id_for_task,
                    &decision,
                    false,
                    false,
                    prompt_hash.clone(),
                    None,
                    registered_agent_id_for_task.as_deref(),
                    request_finops_for_task.as_ref(),
                    session_id_for_task.as_deref(),
                );
                enrich_decision_event_details(
                    &mut event,
                    serde_json::from_slice(&request_body_bytes).ok(),
                    None,
                    "POST",
                    StatusCode::BAD_REQUEST,
                    decision_runtime_json_streaming(
                        Some(accumulated_content.chars().count()),
                        finish_reason.as_deref(),
                        served_provider_id_for_task.as_deref(),
                        0,
                        true,
                        true,
                        Some(&decision.reason_code),
                        Some(block_message),
                        None,
                    ),
                    &TraceCorrelation::default(),
                );
                sink.enqueue_decision(&request_id_for_task, event);
            }
            let bytes = build_streaming_error_sse_bytes(
                &request_id_for_task,
                &config_version_for_task,
                "BLOCK",
                &decision.reason_code,
                &format!("Request blocked by policy: {}", decision.reason_code),
                latency_ms,
            )
            .unwrap_or_else(|| Bytes::from_static(b"data: [DONE]\n\n"));
            let _ = tx.send(Ok(bytes)).await;
            return;
        }

        if streaming_redaction_enabled {
            let redacted = crate::gateway::redaction::redact_text_with_config(
                &accumulated_content,
                &redaction_cfg,
            );
            let stop_reason = match finish_reason.as_deref() {
                Some("tool_calls") => "tool_use",
                Some(other) => other,
                None => "end_turn",
            };
            let rebuilt = crate::gateway::sse::messages_text_to_sse(
                &format!("msg_verdictan_{request_id_for_task}"),
                &redacted,
                stop_reason,
            );
            let _ = tx.send(Ok(rebuilt)).await;
        } else {
            for chunk in buffered_chunks {
                if tx.send(Ok(chunk)).await.is_err() {
                    return;
                }
            }
        }

        finalize_connected_post_dispatch_accounting(
            event_sink_for_task.as_ref(),
            &key_budget_tracker_for_task,
            &request_body_bytes,
            resolve_streaming_post_dispatch_usage(
                &request_body_bytes,
                Some(accumulated_content.as_str()),
                accumulated_content.chars().count(),
            ),
            &access_dispatch_ctx_for_task,
            &request_id_for_task,
            &traceparent_for_task,
            served_provider_id_for_task.as_deref(),
            Some(stream_start.elapsed().as_millis() as i64),
        );
    });

    build_streaming_response(
        status,
        content_type,
        request_id.to_string(),
        traceparent.to_string(),
        ReceiverStream::new(rx),
        false,
        None,
    )
}

/// Resolve the auto virtual provider target for a model name.
pub(crate) fn resolve_auto_target<'a>(
    model_name: &str,
    state: &'a ActiveGatewayStateView<'_>,
) -> Option<&'a crate::gateway::providers::ProviderTarget> {
    if !state.auto_provider.enabled {
        return None;
    }
    if model_name != state.auto_provider.name {
        return None;
    }
    let registry = state.provider_registry.as_ref()?;
    let ranked = crate::gateway::auto_provider::score_targets_with_denied(
        &registry.targets,
        &state.auto_provider.routing,
        state.provider_metrics,
        Some(&state.ua_denied_target_ids),
    );
    ranked.into_iter().next()
}

pub(crate) fn split_provider_prefixed_model_reference(model_name: &str) -> Option<(&str, &str)> {
    let trimmed = model_name.trim();
    let (provider_hint, model_id) = trimmed.split_once('/')?;
    let provider_hint = provider_hint.trim();
    let model_id = model_id.trim();
    if provider_hint.is_empty()
        || model_id.is_empty()
        || !provider_hint
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    {
        return None;
    }
    Some((provider_hint, model_id))
}

pub(crate) fn provider_prefixed_model_name_for_target<'a>(
    target: &crate::gateway::providers::ProviderTarget,
    requested_model: &'a str,
) -> Option<&'a str> {
    let (provider_hint, model_name) = split_provider_prefixed_model_reference(requested_model)?;
    let provider_hint = crate::gateway::provider_catalog::normalized_provider_alias(provider_hint);
    let target_provider =
        crate::gateway::provider_catalog::normalized_provider_alias(&target.provider);
    (provider_hint == target_provider).then_some(model_name)
}

pub(crate) fn target_supports_model(
    target: &crate::gateway::providers::ProviderTarget,
    model_name: &str,
) -> bool {
    let model_name = model_name.trim();
    if model_name.is_empty() {
        return false;
    }
    let provider_scoped_model = provider_prefixed_model_name_for_target(target, model_name);
    if split_provider_prefixed_model_reference(model_name).is_some()
        && provider_scoped_model.is_none()
    {
        return false;
    }

    let matches_target = |candidate: &str| {
        target.model.trim() == "*"
            || target.model == candidate
            || target.models.iter().any(|entry| {
                entry.enabled
                    && (entry.model_id == candidate
                        || entry.aliases.iter().any(|alias| alias == candidate))
            })
    };

    matches_target(model_name) || provider_scoped_model.is_some_and(matches_target)
}

pub(crate) fn resolve_target_model_name(
    target: &crate::gateway::providers::ProviderTarget,
) -> Option<&str> {
    let model = target.model.trim();
    if !model.is_empty() && model != "*" {
        return Some(model);
    }

    target
        .models
        .iter()
        .find(|entry| entry.enabled)
        .map(|entry| entry.model_id.as_str())
}

pub(crate) fn resolve_catalog_model_name_for_request<'a>(
    target: &'a crate::gateway::providers::ProviderTarget,
    requested_model: &str,
) -> Option<&'a str> {
    let requested_model = requested_model.trim();
    if requested_model.is_empty() {
        return resolve_target_model_name(target);
    }

    let direct_match = |candidate: &str| {
        let target_model = target.model.trim();
        if !target_model.is_empty() && target_model != "*" {
            return (target_model == candidate).then_some(target_model);
        }

        target.models.iter().find_map(|entry| {
            (entry.enabled
                && (entry.model_id == candidate
                    || entry.aliases.iter().any(|alias| alias == candidate)))
            .then_some(entry.model_id.as_str())
        })
    };

    direct_match(requested_model).or_else(|| {
        provider_prefixed_model_name_for_target(target, requested_model).and_then(direct_match)
    })
}

pub(crate) fn find_enabled_target_model_entry<'a>(
    target: &'a crate::gateway::providers::ProviderTarget,
    candidate: &str,
) -> Option<&'a crate::gateway::providers::ProviderModelEntry> {
    let candidate = candidate.trim();
    if candidate.is_empty() {
        return None;
    }
    target.models.iter().find(|entry| {
        entry.enabled
            && (entry.model_id == candidate || entry.aliases.iter().any(|alias| alias == candidate))
    })
}

pub(crate) fn resolve_target_model_entry_for_request<'a>(
    target: &'a crate::gateway::providers::ProviderTarget,
    requested_model: &str,
    model_pin: Option<&str>,
) -> Option<&'a crate::gateway::providers::ProviderModelEntry> {
    if let Some(model_name) = model_pin
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| find_enabled_target_model_entry(target, value))
    {
        return Some(model_name);
    }

    let requested_model = requested_model.trim();
    if requested_model.is_empty() {
        return None;
    }

    resolve_catalog_model_name_for_request(target, requested_model)
        .and_then(|model_name| find_enabled_target_model_entry(target, model_name))
        .or_else(|| find_enabled_target_model_entry(target, requested_model))
}

pub(crate) fn supported_features_contain(supported_features: &[String], feature: &str) -> bool {
    supported_features
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(feature))
}

pub(crate) fn resolve_request_capability_metadata(
    target: &crate::gateway::providers::ProviderTarget,
    requested_model: &str,
    model_pin: Option<&str>,
    catalog_snapshot: Option<&crate::gateway::provider_catalog::CatalogSnapshot>,
) -> Option<(String, Vec<String>, Option<u32>)> {
    let catalog_model = catalog_snapshot.and_then(|snapshot| {
        resolve_cached_catalog_model_for_request(target, requested_model, model_pin, snapshot)
    });
    let model_entry = resolve_target_model_entry_for_request(target, requested_model, model_pin);
    let model_id = model_entry
        .map(|entry| entry.model_id.clone())
        .or_else(|| catalog_model.map(|model| model.id.clone()))
        .or_else(|| resolve_target_request_model(target, requested_model, model_pin).0)
        .or_else(|| resolve_target_model_name(target).map(ToOwned::to_owned))
        .or_else(|| {
            let requested_model = requested_model.trim();
            (!requested_model.is_empty()).then(|| requested_model.to_string())
        })?;

    let mut supported_features = catalog_model
        .map(|model| model.supported_features.clone())
        .unwrap_or_default();
    let mut max_output_tokens = catalog_model.and_then(|model| {
        model
            .max_output_tokens
            .and_then(|value| u32::try_from(value).ok())
    });

    if let Some(model_entry) = model_entry {
        if !model_entry.supported_features.is_empty() {
            supported_features = model_entry.supported_features.clone();
        }
        if model_entry.max_output_tokens.is_some() {
            max_output_tokens = model_entry.max_output_tokens;
        }
    }

    Some((model_id, supported_features, max_output_tokens))
}

pub(crate) fn validate_target_model_capabilities(
    target: &crate::gateway::providers::ProviderTarget,
    request_body: &serde_json::Value,
    request_contract: &crate::gateway::runtime_capabilities::RuntimeCapabilityRequest,
    requested_model: &str,
    model_pin: Option<&str>,
    catalog_snapshot: Option<&crate::gateway::provider_catalog::CatalogSnapshot>,
) -> Result<(), crate::gateway::runtime_capabilities::RuntimeCapabilityError> {
    let Some((model_id, supported_features, max_output_tokens)) =
        resolve_request_capability_metadata(target, requested_model, model_pin, catalog_snapshot)
    else {
        return Ok(());
    };

    if !supported_features.is_empty() {
        if request_uses_tooling_shape(request_body, request_contract)
            && !supported_features_contain(&supported_features, "tools")
        {
            return Err(
                crate::gateway::runtime_capabilities::RuntimeCapabilityError::UnsupportedModelTooling {
                    model: model_id.clone(),
                },
            );
        }

        if let Some(feature) = request_contract.response_format_feature {
            let feature_name = feature.as_str();
            if !supported_features_contain(&supported_features, feature_name) {
                return Err(
                    crate::gateway::runtime_capabilities::RuntimeCapabilityError::UnsupportedModelResponseFormat {
                        model: model_id.clone(),
                        feature: feature_name.to_string(),
                    },
                );
            }
        }
    }

    if let Some(max_output_tokens) = max_output_tokens {
        if let Some(requested_max_tokens) = extract_requested_max_tokens(request_body) {
            if requested_max_tokens > max_output_tokens {
                return Err(
                    crate::gateway::runtime_capabilities::RuntimeCapabilityError::MaxOutputTokensExceeded {
                        model: model_id,
                        requested: requested_max_tokens,
                        max_output_tokens,
                    },
                );
            }
        }
    }

    Ok(())
}
pub(crate) fn resolve_parameter_override_value(
    source_body: &serde_json::Value,
    override_value: &serde_json::Value,
) -> Option<serde_json::Value> {
    let copy_from = override_value
        .get("copy_from")
        .and_then(serde_json::Value::as_str);
    if let Some(copy_from) = copy_from {
        let copied = if copy_from.starts_with('/') {
            source_body.pointer(copy_from).cloned()
        } else {
            source_body.get(copy_from).cloned()
        };
        return copied.or_else(|| override_value.get("default").cloned());
    }

    Some(override_value.clone())
}

pub(crate) fn resolve_cached_catalog_model_for_request<'a>(
    target: &crate::gateway::providers::ProviderTarget,
    requested_model: &str,
    model_pin: Option<&str>,
    catalog_snapshot: &'a crate::gateway::provider_catalog::CatalogSnapshot,
) -> Option<&'a crate::gateway::provider_catalog::CatalogModel> {
    let provider_id = crate::gateway::provider_catalog::normalized_provider_alias(&target.provider);
    let resolved_model = model_pin
        .and_then(|value| {
            resolve_catalog_model_name_for_request(target, value).map(ToOwned::to_owned)
        })
        .or_else(|| {
            resolve_catalog_model_name_for_request(target, requested_model).map(ToOwned::to_owned)
        })
        .or_else(|| resolve_target_request_model(target, requested_model, model_pin).0)
        .or_else(|| resolve_target_model_name(target).map(ToOwned::to_owned))
        .or_else(|| {
            let requested_model = requested_model.trim();
            (!requested_model.is_empty()).then(|| requested_model.to_string())
        })?;
    let normalized_model = if let Some((prefix, model_id)) = resolved_model.split_once('/') {
        let normalized_prefix = crate::gateway::provider_catalog::normalized_provider_alias(prefix);
        let model_id = model_id.trim();
        if normalized_prefix == provider_id && !model_id.is_empty() {
            model_id
        } else {
            resolved_model.as_str()
        }
    } else {
        resolved_model.as_str()
    };

    catalog_snapshot.models.iter().find(|model| {
        crate::gateway::provider_catalog::normalized_provider_alias(&model.provider_id)
            == provider_id
            && model.id == normalized_model
    })
}

pub(crate) fn resolve_request_parameter_metadata(
    target: &crate::gateway::providers::ProviderTarget,
    requested_model: &str,
    model_pin: Option<&str>,
    catalog_snapshot: Option<&crate::gateway::provider_catalog::CatalogSnapshot>,
) -> (serde_json::Map<String, serde_json::Value>, Vec<String>) {
    let catalog_model = catalog_snapshot.and_then(|snapshot| {
        resolve_cached_catalog_model_for_request(target, requested_model, model_pin, snapshot)
    });
    let mut parameter_overrides = catalog_model
        .map(|model| model.parameter_overrides.clone())
        .unwrap_or_default();
    let mut removed_params = catalog_model
        .map(|model| model.removed_params.clone())
        .unwrap_or_default();

    if let Some(model_entry) =
        resolve_target_model_entry_for_request(target, requested_model, model_pin)
    {
        if !model_entry.parameter_overrides.is_empty() {
            parameter_overrides = model_entry.parameter_overrides.clone();
        }
        if !model_entry.removed_params.is_empty() {
            removed_params = model_entry.removed_params.clone();
        }
    }

    (parameter_overrides, removed_params)
}

pub(crate) fn apply_target_model_request_parameter_metadata(
    target: &crate::gateway::providers::ProviderTarget,
    source_body: &serde_json::Value,
    provider_body: &mut serde_json::Value,
    requested_model: &str,
    model_pin: Option<&str>,
    catalog_snapshot: Option<&crate::gateway::provider_catalog::CatalogSnapshot>,
) {
    let Some(object) = provider_body.as_object_mut() else {
        return;
    };

    let (parameter_overrides, removed_params) =
        resolve_request_parameter_metadata(target, requested_model, model_pin, catalog_snapshot);
    if parameter_overrides.is_empty() && removed_params.is_empty() {
        return;
    }

    for (key, override_value) in &parameter_overrides {
        if let Some(value) = resolve_parameter_override_value(source_body, override_value) {
            object.insert(key.clone(), value);
        }
    }

    for key in &removed_params {
        object.remove(key);
    }
}

pub(crate) fn resolve_target_request_model(
    target: &crate::gateway::providers::ProviderTarget,
    requested_model: &str,
    model_pin: Option<&str>,
) -> (Option<String>, String) {
    let requested_model = requested_model.trim();
    let pinned_model = model_pin
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let catalog_model =
        resolve_catalog_model_name_for_request(target, requested_model).map(ToOwned::to_owned);
    let explicit_target_model = target
        .model
        .trim()
        .chars()
        .next()
        .is_some()
        .then(|| target.model.trim())
        .filter(|value| *value != "*")
        .map(ToOwned::to_owned);
    let provider_request_model = pinned_model
        .clone()
        .or_else(|| catalog_model.clone())
        .or(explicit_target_model);
    let effective_target_model = provider_request_model
        .clone()
        .or_else(|| (!requested_model.is_empty()).then(|| requested_model.to_string()))
        .unwrap_or_default();
    (provider_request_model, effective_target_model)
}

pub(crate) fn resolve_provider_path_for_request(
    target: &crate::gateway::providers::ProviderTarget,
    default_path: &str,
    effective_target_model: &str,
) -> String {
    let model_name = if !effective_target_model.trim().is_empty() {
        effective_target_model
    } else {
        target.model.as_str()
    };
    if let Some(template) = target.path_template.as_deref() {
        return template.replace("{model}", model_name);
    }

    if let Some(template) = crate::gateway::provider_catalog::provider_path_template_for_public_path(
        &target.provider,
        default_path,
    ) {
        return template.replace("{model}", model_name);
    }

    let target_format = target.format.or_else(|| {
        crate::gateway::provider_catalog::profile_for_provider(&target.provider)
            .map(|profile| profile.format)
    });
    match (default_path, target_format) {
        ("/v1/messages", Some(crate::gateway::format_translation::ProviderFormat::OpenAI)) => {
            return "/v1/chat/completions".to_string();
        }
        (
            "/v1/chat/completions" | "/v1/responses",
            Some(crate::gateway::format_translation::ProviderFormat::Anthropic),
        ) => {
            return "/v1/messages".to_string();
        }
        _ => {}
    }

    let runtime_path = crate::gateway::runtimes::resolve_runtime_path(
        &target.provider,
        target.execution_target.as_ref(),
        model_name,
        None,
        default_path,
    );
    if runtime_path != default_path {
        return runtime_path;
    }

    if let Some(template) = crate::gateway::provider_catalog::profile_for_provider(&target.provider)
        .and_then(|profile| profile.path_template)
    {
        return template.replace("{model}", model_name);
    }

    runtime_path
}

pub(crate) fn resolved_target_format(
    target: &crate::gateway::providers::ProviderTarget,
) -> crate::gateway::format_translation::ProviderFormat {
    target
        .format
        .or_else(|| {
            crate::gateway::provider_catalog::profile_for_provider(&target.provider)
                .map(|profile| profile.format)
        })
        .unwrap_or(crate::gateway::format_translation::ProviderFormat::OpenAI)
}

/// Read-only usage-authorization policy gate.
///
/// Calls `POST /v1/gateway/usage-authorizations/evaluate` via the authenticated
/// gateway machine client after trusted subject/project/configuration/agent/
/// provider/model resolution and BEFORE the semantic-cache lookup, and denies
/// the request with HTTP 403 `usage_authorization_denied` when the returned
/// document is a restricted-denied decision. Evaluation is read-only: it creates no
/// authorization, quota, allocation, spend, or ticket. The decision is
/// served from a non-sliding, absolute-expiry policy cache; a cache hit reuses
/// the decision without re-calling the control plane, and policy caching never
/// bypasses the commit/dispatch that lands in a later increment.
///
/// The gate is only reachable for connected requests with a fully resolved
/// control-plane identity (gateway machine client + organization + UUID subject
/// token). When it cannot run it returns `Ok` and leaves the existing path
/// unchanged — it never authorizes, only denies. When the authoritative policy
/// is unavailable it fails closed with HTTP 503.
pub(crate) async fn enforce_usage_authorization_evaluate_gate(
    state: &ActiveGatewayStateView<'_>,
    request_family: crate::gateway::usage_authorization::UsageAuthorizationRequestFamily,
    requested_model: &str,
    estimated_prompt_tokens: u64,
    estimated_max_completion_tokens: u64,
    request_id: &str,
    traceparent: &str,
) -> Result<Option<crate::gateway::usage_authorization::UsageAuthorizationDocument>, Response<Body>>
{
    if !state.connected_mode {
        return Ok(None);
    }
    let Some(sink) = state.event_sink.as_ref() else {
        return Ok(None);
    };
    let Ok(machine_client) = sink.machine_client() else {
        return Ok(None);
    };
    let Some(finops) = state.request_finops.as_ref() else {
        return Ok(None);
    };
    let Some(org_id) = finops
        .org_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    // subject_token_id is a required UA binding UUID (increment 1). When it does
    // not resolve to a UUID the read-only gate is not reachable; authoritative
    // fail-closed enforcement lands with the increment-3 reservation.
    let Some(subject_token_id) =
        crate::gateway::usage_authorization::normalize_binding_uuid(finops.key_id.as_deref())
    else {
        return Ok(None);
    };

    let usage_pricing = resolve_usage_pricing_context_with_estimate(
        requested_model,
        state,
        estimated_prompt_tokens,
        estimated_max_completion_tokens,
    );
    let provider = usage_pricing.provider.clone();
    let model = usage_pricing.model.clone();
    if provider.trim().is_empty() || model.trim().is_empty() {
        return Ok(None);
    }

    let project_id = crate::gateway::usage_authorization::normalize_binding_uuid(None);
    let configuration_id = crate::gateway::usage_authorization::normalize_binding_uuid(
        state.configuration_id.as_deref(),
    );
    let agent_id = crate::gateway::usage_authorization::normalize_binding_uuid(
        state.current_agent_id.as_deref(),
    );

    let cache_key =
        crate::gateway::usage_authorization_pipeline::UsageAuthorizationPolicyCacheKey {
            organization_id: org_id.to_string(),
            gateway_id: state.gateway_id.as_deref().unwrap_or("").to_string(),
            subject_token_id: subject_token_id.clone(),
            project_id: project_id.clone(),
            configuration_id: configuration_id.clone(),
            agent_id: agent_id.clone(),
            provider: provider.clone(),
            model: model.clone(),
            request_family,
        };

    let now = Utc::now();
    let document = if let Some(cached) = sink.ua_policy_cache.get(&cache_key, now) {
        cached
    } else {
        let request = crate::gateway::usage_authorization::UsageAuthorizationEvaluateRequest {
            subject_token_id,
            project_id,
            configuration_id,
            agent_id,
            provider: provider.clone(),
            model: model.clone(),
            request_family,
            usage: crate::gateway::usage_authorization::UsageAuthorizationUsage {
                input_tokens: estimated_prompt_tokens,
                max_output_tokens: estimated_max_completion_tokens,
                request_units: 1,
                pricing_snapshot_id: None,
                asserted_estimate_usd: Some(
                    crate::gateway::usage_authorization::canonical_estimate_usd(
                        usage_pricing.estimated_cost_usd,
                    ),
                ),
            },
        };
        match crate::gateway::usage_authorization::evaluate_usage_authorization(
            machine_client,
            sink.base_url(),
            &request,
        )
        .await
        {
            Ok(document) => {
                sink.ua_policy_cache
                    .insert(cache_key, document.clone(), now);
                document
            }
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    provider = %provider,
                    model = %model,
                    error = %error,
                    "usage-authorization evaluate failed; denying request (fail closed)"
                );
                return Err(build_request_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    request_id,
                    traceparent,
                    "Usage-authorization policy is temporarily unavailable",
                    "service_unavailable",
                    "usage_authorization_policy_unavailable",
                ));
            }
        }
    };

    if let Err(code) =
        crate::gateway::usage_authorization_pipeline::require_fresh_usage_authorization_document(
            &document, &now,
        )
    {
        tracing::warn!(
            request_id = %request_id,
            error_code = %code,
            "usage-authorization policy document rejected as stale or unavailable"
        );
        let error_code = if code
            == crate::gateway::usage_authorization_pipeline::USAGE_AUTHORIZATION_POLICY_STALE
        {
            crate::gateway::usage_authorization_pipeline::USAGE_AUTHORIZATION_POLICY_STALE
        } else {
            crate::gateway::usage_authorization_pipeline::USAGE_AUTHORIZATION_POLICY_UNAVAILABLE
        };
        return Err(build_request_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            traceparent,
            "Usage-authorization policy is temporarily unavailable",
            "service_unavailable",
            error_code,
        ));
    }

    if !document.is_allowed() {
        let denial_reason = document
            .denial_reason()
            .unwrap_or("Request denied by usage-authorization policy");
        tracing::info!(
            request_id = %request_id,
            policy_sha256 = %document.policy_sha256,
            provider = %provider,
            model = %model,
            "usage-authorization evaluate denied request"
        );
        return Err(build_request_error_response(
            StatusCode::FORBIDDEN,
            request_id,
            traceparent,
            denial_reason,
            "access_denied",
            "usage_authorization_denied",
        ));
    }

    Ok(Some(document))
}

pub(crate) fn ua_financial_path_active(state: &ActiveGatewayStateView<'_>) -> bool {
    state.connected_mode && state.ua_eval_document.is_some() && !state.shadow_routing.enabled
}

pub(crate) async fn resolve_ua_pinned_target_id(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    path: &str,
    body: &Bytes,
    request_id: &str,
) -> Result<Option<String>, Response<Body>> {
    let registry = match state.provider_registry.as_ref() {
        Some(registry) if !registry.targets.is_empty() => registry,
        _ => return Ok(None),
    };
    let base_body: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let pins = extract_provider_request_pins(headers);
    let effective_ordered =
        match resolve_initial_provider_order(registry, state, request_id, &pins, false) {
            Ok(ordered) => ordered,
            Err(ProviderOrderSelectionError::UnknownProviderPin(_)) => return Ok(None),
            Err(ProviderOrderSelectionError::NoCompliantProvider) => return Ok(None),
        };
    let effective_ordered = match resolve_prefiltered_provider_order(
        registry,
        state,
        &effective_ordered,
        &base_body,
        request_id,
        false,
    ) {
        Ok(ordered) => ordered,
        Err(_) => return Ok(None),
    };
    let provider_dispatch_plan = match resolve_provider_dispatch_plan(
        registry,
        state,
        path,
        headers,
        &base_body,
        &effective_ordered,
        request_id,
        pins.model.as_deref(),
        false,
    )
    .await
    {
        Ok(plan) => plan,
        Err(_) => return Ok(None),
    };
    let requested_model = base_body
        .get("model")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let idx = provider_dispatch_plan
        .effective_ordered
        .iter()
        .copied()
        .find(|index| target_supports_model(&registry.targets[*index], requested_model))
        .or_else(|| provider_dispatch_plan.effective_ordered.first().copied())
        .or_else(|| effective_ordered.first().copied());
    Ok(idx.map(|index| registry.targets[index].id.clone()))
}

pub(crate) async fn prepare_ua_financial_lifecycle(
    state: &mut ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    parsed_json: &serde_json::Value,
    upstream_body_bytes: &Bytes,
    request_id: &str,
    traceparent: &str,
    estimated_prompt_tokens: u64,
    estimated_max_completion_tokens: u64,
    admission_credential_source: Option<ConnectedCredentialSource>,
    proxy_path: &str,
    request_family: crate::gateway::usage_authorization::UsageAuthorizationRequestFamily,
) -> Result<(), Response<Body>> {
    let eval_document = state
        .ua_eval_document
        .as_ref()
        .ok_or_else(|| {
            build_request_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                traceparent,
                "Usage-authorization policy document is unavailable",
                "service_unavailable",
                "usage_authorization_policy_unavailable",
            )
        })?
        .clone();

    let pinned_target_id =
        resolve_ua_pinned_target_id(state, headers, proxy_path, upstream_body_bytes, request_id)
            .await?
            .ok_or_else(|| {
                build_request_error_response(
                    StatusCode::FORBIDDEN,
                    request_id,
                    traceparent,
                    "no auto-routing providers are permitted by usage-authorization policy",
                    "access_denied",
                    "no_eligible_provider",
                )
            })?;
    state.ua_pinned_target_id = Some(pinned_target_id.clone());

    let _ = state.provider_registry.as_ref().ok_or_else(|| {
        build_request_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            traceparent,
            "Provider registry is unavailable",
            "service_unavailable",
            "provider_registry_unavailable",
        )
    })?;

    let usage_pricing = resolve_usage_pricing_context_with_estimate(
        parsed_json
            .get("model")
            .and_then(|value| value.as_str())
            .unwrap_or(""),
        state,
        estimated_prompt_tokens,
        estimated_max_completion_tokens,
    );
    let provider = usage_pricing.provider.clone();
    let model = usage_pricing.model.clone();
    // The control plane derives the credential origin from the organization
    // configuration, so the authorization body carries no credential source.
    // A request without a resolved customer-owned key is still rejected here.
    if !matches!(
        admission_credential_source,
        Some(ConnectedCredentialSource::Byok)
    ) {
        return Err(build_request_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            traceparent,
            "Connected token admission is unavailable",
            "service_unavailable",
            "token_admission_unavailable",
        ));
    }

    let finops = state.request_finops.as_ref().ok_or_else(|| {
        build_request_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            traceparent,
            "Connected token admission identity is unavailable",
            "service_unavailable",
            "token_admission_identity_unavailable",
        )
    })?;
    let subject_token_id =
        crate::gateway::usage_authorization::normalize_binding_uuid(finops.key_id.as_deref())
            .ok_or_else(|| {
                build_request_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    request_id,
                    traceparent,
                    "Connected token admission identity is unavailable",
                    "service_unavailable",
                    "token_admission_identity_unavailable",
                )
            })?;
    let project_id = crate::gateway::usage_authorization::normalize_binding_uuid(None);
    let configuration_id = crate::gateway::usage_authorization::normalize_binding_uuid(
        state.configuration_id.as_deref(),
    );
    let agent_id = crate::gateway::usage_authorization::normalize_binding_uuid(
        state.current_agent_id.as_deref(),
    );

    let binding = crate::gateway::usage_authorization::UsageAuthorizationBinding {
        subject_token_id: subject_token_id.clone(),
        project_id,
        configuration_id,
        agent_id,
        provider: provider.clone(),
        model: model.clone(),
        request_family,
    };
    let usage = crate::gateway::usage_authorization::UsageAuthorizationUsage {
        input_tokens: estimated_prompt_tokens,
        max_output_tokens: estimated_max_completion_tokens,
        request_units: 1,
        pricing_snapshot_id: None,
        asserted_estimate_usd: Some(crate::gateway::usage_authorization::canonical_estimate_usd(
            usage_pricing.estimated_cost_usd,
        )),
    };

    let sink = state.event_sink.as_ref().ok_or_else(|| {
        build_request_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            traceparent,
            "Connected admission client is unavailable",
            "service_unavailable",
            "token_admission_client_unavailable",
        )
    })?;
    let machine_client = sink.machine_client().map_err(|error| {
        tracing::error!(
            request_id = %request_id,
            error = %error,
            "connected UA machine client initialization failed"
        );
        build_request_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            traceparent,
            "Connected admission client is unavailable",
            "service_unavailable",
            "token_admission_client_unavailable",
        )
    })?;
    let api_base_url = sink.base_url();

    let authorize_request = crate::gateway::usage_authorization::UsageAuthorizationCreateRequest {
        request_id: request_id.to_string(),
        delivery_kind:
            crate::gateway::usage_authorization::UsageAuthorizationDeliveryKind::Upstream,
        binding,
        usage,
        accepted_policy_version: eval_document.policy_version.clone(),
        accepted_policy_sha256: eval_document.policy_sha256.clone(),
    };
    let authorization = match crate::gateway::usage_authorization::create_usage_authorization(
        machine_client,
        api_base_url,
        &authorize_request,
    )
    .await
    {
        Ok(authorization) => authorization,
        Err(error) => {
            use crate::gateway::usage_authorization::UsageAuthorizationErrorCode;

            match error.error_code() {
                Some(UsageAuthorizationErrorCode::BudgetExceeded) => {
                    return Err(build_request_error_response(
                        StatusCode::PAYMENT_REQUIRED,
                        request_id,
                        traceparent,
                        "Usage-authorization budget exhausted",
                        "payment_required",
                        "usage_authorization_budget_exceeded",
                    ));
                }
                Some(UsageAuthorizationErrorCode::RateLimitExceeded) => {
                    return Err(build_request_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        request_id,
                        traceparent,
                        "Usage-authorization admission limit exceeded",
                        "service_unavailable",
                        "usage_authorization_rate_limited",
                    ));
                }
                _ => {
                    tracing::warn!(
                        request_id = %request_id,
                        error = %error,
                        "usage-authorization creation failed; denying request (fail closed)"
                    );
                    return Err(build_request_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        request_id,
                        traceparent,
                        "Usage authorization failed",
                        "service_unavailable",
                        "usage_authorization_create_failed",
                    ));
                }
            }
        }
    };

    let attempt_id = Uuid::new_v4().to_string();
    let dispatch_request = crate::gateway::usage_authorization::UsageAuthorizationDispatchRequest {
        attempt_id: attempt_id.clone(),
        provider_idempotency:
            crate::gateway::usage_authorization::UsageAuthorizationProviderIdempotency::Unsupported,
        provider_idempotency_key: None,
    };
    crate::gateway::usage_authorization::dispatch_usage_authorization(
        machine_client,
        api_base_url,
        &authorization.gateway_usage_authorization_id,
        &dispatch_request,
    )
    .await
    .map_err(|error| {
        tracing::warn!(
            request_id = %request_id,
            gateway_usage_authorization_id = %authorization.gateway_usage_authorization_id,
            error = %error,
            "usage-authorization dispatch failed; denying request (fail closed)"
        );
        build_request_error_response(
            StatusCode::CONFLICT,
            request_id,
            traceparent,
            "Usage-authorization dispatch is indeterminate",
            "conflict",
            "gateway_dispatch_outcome_indeterminate",
        )
    })?;

    state.ua_authorization_id = Some(authorization.gateway_usage_authorization_id);
    state.ua_dispatch_acquired = true;
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UaAgentUsageTokens {
    pub(crate) prompt_tokens: u64,
    pub(crate) completion_tokens: u64,
    pub(crate) cached_input_tokens: u64,
}

pub(crate) fn ua_org_id_from_finops(finops: Option<&RequestFinopsContext>) -> Option<String> {
    finops
        .and_then(|finops| finops.org_id.as_deref())
        .map(str::trim)
        .filter(|org_id| !org_id.is_empty())
        .map(str::to_owned)
}

pub(crate) async fn maybe_increment_ua_agent_usage(
    event_sink: &EventSink,
    machine_client: &reqwest::Client,
    current_agent_id: Option<&str>,
    org_id: Option<&str>,
    request_body_bytes: &Bytes,
    usage: Option<UaAgentUsageTokens>,
    request_id: &str,
) {
    let Some(agent_id) = current_agent_id
        .map(str::trim)
        .filter(|agent_id| !agent_id.is_empty())
    else {
        return;
    };
    let org_id = org_id.map(str::trim).filter(|org_id| !org_id.is_empty());
    let Some(org_id) = org_id else {
        return;
    };

    let increment_model = extract_upstream_model_name(request_body_bytes).unwrap_or_default();
    let increment_provider = infer_provider_from_model(&increment_model).unwrap_or_default();
    let actual_input = usage.map(|usage| usage.prompt_tokens).unwrap_or(0);
    let actual_completion = usage.map(|usage| usage.completion_tokens).unwrap_or(0);
    let actual_cached = usage.map(|usage| usage.cached_input_tokens).unwrap_or(0);

    if let Err(error) = crate::gateway::usage_constraints::increment_agent_usage(
        machine_client,
        event_sink.base_url(),
        "",
        agent_id,
        org_id,
        &increment_provider,
        &increment_model,
        actual_input,
        actual_cached,
        actual_completion,
        1,
        Some(request_id),
    )
    .await
    {
        tracing::warn!(
            agent_id = %agent_id,
            request_id = %request_id,
            error = %error,
            "usage authorization agent usage increment failed"
        );
    }
}

/// Build the neutral completion body for a usage authorization.
///
/// The control plane accepts `completed` and `released` only. A gateway that
/// cannot report provider usage releases the authorization with a reason
/// instead of reporting token counts that the provider never returned.
pub(crate) fn usage_authorization_completion_body(
    usage: Option<UaAgentUsageTokens>,
    release_reason: &str,
) -> crate::gateway::usage_authorization::UsageAuthorizationCompleteRequest {
    use crate::gateway::usage_authorization::UsageAuthorizationCompleteRequest;

    match usage {
        Some(usage) => UsageAuthorizationCompleteRequest::Completed {
            input_tokens: usage.prompt_tokens,
            output_tokens: usage.completion_tokens,
            cached_input_tokens: Some(usage.cached_input_tokens),
            pricing_snapshot_id: None,
        },
        None => UsageAuthorizationCompleteRequest::Released {
            reason: release_reason.to_string(),
        },
    }
}

pub(crate) async fn finalize_ua_financial_lifecycle(
    state: &ActiveGatewayStateView<'_>,
    request_body: &serde_json::Value,
    response: &crate::gateway::cache::BufferedUpstreamResponse,
    request_id: &str,
    _traceparent: &str,
) {
    let Some(authorization_id) = state.ua_authorization_id.clone() else {
        return;
    };
    let Some(sink) = state.event_sink.clone() else {
        return;
    };
    finalize_ua_financial_lifecycle_inner(
        sink,
        authorization_id,
        state.ua_dispatch_acquired,
        state.current_agent_id.clone(),
        ua_org_id_from_finops(state.request_finops.as_ref()),
        request_body.clone(),
        response.clone(),
        request_id.to_string(),
    )
    .await;
}

async fn finalize_ua_financial_lifecycle_inner(
    sink: EventSink,
    authorization_id: String,
    dispatch_acquired: bool,
    current_agent_id: Option<String>,
    org_id: Option<String>,
    request_body: serde_json::Value,
    response: crate::gateway::cache::BufferedUpstreamResponse,
    request_id: String,
) {
    let Ok(machine_client) = sink.machine_client() else {
        return;
    };
    let machine_client = machine_client.clone();
    let request_body_bytes =
        Bytes::from(serde_json::to_vec(&request_body).unwrap_or_else(|_| b"{}".to_vec()));
    let should_increment = dispatch_acquired && response.status().is_success();
    let complete_event_id = uuid::Uuid::new_v4().to_string();

    let usage_tokens = if response.status().is_success() {
        resolve_buffered_post_dispatch_usage(&request_body, &response).map(|usage_ctx| {
            let usage = usage_ctx.usage;
            UaAgentUsageTokens {
                prompt_tokens: usage.prompt_tokens,
                completion_tokens: usage.completion_tokens,
                cached_input_tokens: usage.cached_input_tokens,
            }
        })
    } else {
        None
    };
    let complete_request = if response.status().is_success() {
        usage_authorization_completion_body(usage_tokens, "provider_usage_unavailable")
    } else if dispatch_acquired {
        usage_authorization_completion_body(
            None,
            &format!("upstream_http_{}", response.status().as_u16()),
        )
    } else {
        return;
    };

    if let Err(error) = sink
        .persist_and_deliver_ua_complete(
            &request_id,
            &authorization_id,
            &complete_request,
            &complete_event_id,
        )
        .await
    {
        tracing::error!(
            request_id = %request_id,
            gateway_usage_authorization_id = %authorization_id,
            error = %error,
            "usage-authorization completion closeout failed"
        );
        return;
    }

    if should_increment {
        maybe_increment_ua_agent_usage(
            &sink,
            &machine_client,
            current_agent_id.as_deref(),
            org_id.as_deref(),
            &request_body_bytes,
            usage_tokens,
            &request_id,
        )
        .await;
    }
}

/// Schedule buffered UA settlement on the sink join set (sync call sites only).
pub(crate) fn schedule_finalize_ua_financial_lifecycle(
    state: &ActiveGatewayStateView<'_>,
    request_body: &serde_json::Value,
    response: &crate::gateway::cache::BufferedUpstreamResponse,
    request_id: &str,
    _traceparent: &str,
) {
    let Some(sink) = state.event_sink.clone() else {
        return;
    };
    let authorization_id = state.ua_authorization_id.clone();
    let dispatch_acquired = state.ua_dispatch_acquired;
    let current_agent_id = state.current_agent_id.clone();
    let org_id = ua_org_id_from_finops(state.request_finops.as_ref());
    let request_body = request_body.clone();
    let response = response.clone();
    let request_id = request_id.to_string();
    let forward_join_set = std::sync::Arc::clone(&sink.forward_join_set);
    let task = async move {
        if let Some(authorization_id) = authorization_id {
            finalize_ua_financial_lifecycle_inner(
                sink,
                authorization_id,
                dispatch_acquired,
                current_agent_id,
                org_id,
                request_body,
                response,
                request_id,
            )
            .await;
        }
    };
    {
        let mut join_set = match forward_join_set.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        join_set.spawn(task);
    }
}

pub(crate) async fn finalize_ua_streaming_financial_lifecycle(
    authorization_id: Option<String>,
    dispatch_acquired: bool,
    event_sink: Option<EventSink>,
    request_body: Bytes,
    output_text: Option<String>,
    output_chars: usize,
    released_upstream_error: bool,
    current_agent_id: Option<String>,
    org_id: Option<String>,
    request_id: &str,
    _traceparent: &str,
) {
    let Some(authorization_id) = authorization_id else {
        return;
    };
    let Some(sink) = event_sink else {
        return;
    };
    let Ok(machine_client) = sink.machine_client() else {
        return;
    };
    let request_id = request_id.to_string();
    let machine_client = machine_client.clone();
    let should_increment = dispatch_acquired && !released_upstream_error;
    let complete_event_id = uuid::Uuid::new_v4().to_string();

    let usage_tokens = if released_upstream_error {
        None
    } else {
        estimate_streaming_spend_usage(&request_body, output_text.as_deref(), output_chars).map(
            |usage| UaAgentUsageTokens {
                prompt_tokens: usage.prompt_tokens,
                completion_tokens: usage.completion_tokens,
                cached_input_tokens: usage.cached_input_tokens,
            },
        )
    };
    let complete_request = if !released_upstream_error {
        usage_authorization_completion_body(usage_tokens, "provider_usage_unavailable")
    } else if dispatch_acquired {
        usage_authorization_completion_body(None, "upstream_transport_failure")
    } else {
        return;
    };

    if let Err(error) = sink
        .persist_and_deliver_ua_complete(
            &request_id,
            &authorization_id,
            &complete_request,
            &complete_event_id,
        )
        .await
    {
        tracing::error!(
            request_id = %request_id,
            gateway_usage_authorization_id = %authorization_id,
            error = %error,
            "usage-authorization streaming completion closeout failed"
        );
        return;
    }

    if should_increment {
        maybe_increment_ua_agent_usage(
            &sink,
            &machine_client,
            current_agent_id.as_deref(),
            org_id.as_deref(),
            &request_body,
            usage_tokens,
            &request_id,
        )
        .await;
    }
}

/// Schedule streaming UA settlement on the sink join set (sync call sites only).
pub(crate) fn schedule_finalize_ua_streaming_financial_lifecycle(
    authorization_id: Option<String>,
    dispatch_acquired: bool,
    event_sink: Option<EventSink>,
    request_body: Bytes,
    output_text: Option<String>,
    output_chars: usize,
    released_upstream_error: bool,
    current_agent_id: Option<String>,
    org_id: Option<String>,
    request_id: &str,
    traceparent: &str,
) {
    let Some(sink) = event_sink else {
        return;
    };
    let request_id = request_id.to_string();
    let traceparent = traceparent.to_string();
    let forward_join_set = std::sync::Arc::clone(&sink.forward_join_set);
    let task = async move {
        finalize_ua_streaming_financial_lifecycle(
            authorization_id,
            dispatch_acquired,
            Some(sink),
            request_body,
            output_text,
            output_chars,
            released_upstream_error,
            current_agent_id,
            org_id,
            &request_id,
            &traceparent,
        )
        .await;
    };
    {
        let mut join_set = match forward_join_set.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        join_set.spawn(task);
    }
}

// increment 3c: READ-ONLY usage-authorization evaluation of every
/// auto-routing candidate. Returns the set of provider-target ids the subject
/// is NOT allowed to use (document `{mode:"restricted", allowed:false}`), so the
/// synchronous selection chain can exclude them without an async refactor.
///
/// This has ZERO financial side effects — evaluate only, no reservation, quota,
/// usage authorization, or spend mutation. It reuses the same authenticated machine client,
/// binding normalization, and non-sliding `UsageAuthorizationPolicyCache` as the request-path
/// gate, and derives each candidate's provider/model exactly like
/// `resolve_usage_pricing_context_with_estimate`, so a subsequently selected
/// candidate hits the cache instead of re-evaluating.
///
/// Fail-closed parity with the request-path gate: on an evaluate transport /
/// non-2xx error a candidate is neither marked allowed nor falsely denied — it
/// is skipped, and the request-path gate still fails closed (503) for the model
/// that is ultimately selected. Only hashes are emitted.
pub(crate) async fn compute_ua_denied_target_ids(
    state: &ActiveGatewayStateView<'_>,
    request_family: crate::gateway::usage_authorization::UsageAuthorizationRequestFamily,
    requested_model: &str,
    estimated_prompt_tokens: u64,
    estimated_max_completion_tokens: u64,
    request_id: &str,
) -> std::collections::HashSet<String> {
    let mut denied: std::collections::HashSet<String> = std::collections::HashSet::new();
    if !state.connected_mode {
        return denied;
    }
    let Some(sink) = state.event_sink.as_ref() else {
        return denied;
    };
    let Ok(machine_client) = sink.machine_client() else {
        return denied;
    };
    let Some(finops) = state.request_finops.as_ref() else {
        return denied;
    };
    let Some(org_id) = finops
        .org_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return denied;
    };
    let Some(subject_token_id) =
        crate::gateway::usage_authorization::normalize_binding_uuid(finops.key_id.as_deref())
    else {
        return denied;
    };
    let Some(registry) = state.provider_registry.as_ref() else {
        return denied;
    };
    if registry.targets.is_empty() {
        return denied;
    }

    let gateway_id = state.gateway_id.as_deref().unwrap_or("").to_string();
    let project_id = crate::gateway::usage_authorization::normalize_binding_uuid(None);
    let configuration_id = crate::gateway::usage_authorization::normalize_binding_uuid(
        state.configuration_id.as_deref(),
    );
    let agent_id = crate::gateway::usage_authorization::normalize_binding_uuid(
        state.current_agent_id.as_deref(),
    );
    let now = Utc::now();

    for target in &registry.targets {
        let provider =
            crate::gateway::provider_catalog::normalized_provider_alias(&target.provider);
        let model = resolve_target_request_model(target, requested_model, None)
            .0
            .or_else(|| resolve_target_model_name(target).map(ToOwned::to_owned))
            .unwrap_or_else(|| requested_model.to_string());
        if provider.trim().is_empty() || model.trim().is_empty() {
            continue;
        }

        let cache_key =
            crate::gateway::usage_authorization_pipeline::UsageAuthorizationPolicyCacheKey {
                organization_id: org_id.to_string(),
                gateway_id: gateway_id.clone(),
                subject_token_id: subject_token_id.clone(),
                project_id: project_id.clone(),
                configuration_id: configuration_id.clone(),
                agent_id: agent_id.clone(),
                provider: provider.clone(),
                model: model.clone(),
                request_family,
            };

        let document = if let Some(cached) = sink.ua_policy_cache.get(&cache_key, now) {
            cached
        } else {
            let estimated_cost_usd = estimate_declared_request_cost(
                state,
                target,
                &model,
                estimated_prompt_tokens,
                estimated_max_completion_tokens,
            );
            let request = crate::gateway::usage_authorization::UsageAuthorizationEvaluateRequest {
                subject_token_id: subject_token_id.clone(),
                project_id: project_id.clone(),
                configuration_id: configuration_id.clone(),
                agent_id: agent_id.clone(),
                provider: provider.clone(),
                model: model.clone(),
                request_family,
                usage: crate::gateway::usage_authorization::UsageAuthorizationUsage {
                    input_tokens: estimated_prompt_tokens,
                    max_output_tokens: estimated_max_completion_tokens,
                    request_units: 1,
                    pricing_snapshot_id: None,
                    asserted_estimate_usd: Some(
                        crate::gateway::usage_authorization::canonical_estimate_usd(
                            estimated_cost_usd,
                        ),
                    ),
                },
            };
            match crate::gateway::usage_authorization::evaluate_usage_authorization(
                machine_client,
                sink.base_url(),
                &request,
            )
            .await
            {
                Ok(document) => {
                    sink.ua_policy_cache
                        .insert(cache_key, document.clone(), now);
                    document
                }
                Err(error) => {
                    // Read-only, fail-closed posture: do NOT mark this candidate
                    // allowed and do NOT falsely deny it. Skip; the request-path
                    // evaluate gate still fails closed (503) for the model that is
                    // ultimately selected.
                    tracing::debug!(
                        request_id = %request_id,
                        provider = %provider,
                        model = %model,
                        error = %error,
                        "usage-authorization candidate evaluate failed; leaving candidate to the request-path gate"
                    );
                    continue;
                }
            }
        };

        if crate::gateway::usage_authorization_pipeline::require_fresh_usage_authorization_document(
            &document, &now,
        )
        .is_err()
        {
            continue;
        }

        if !document.is_allowed() {
            tracing::info!(
                request_id = %request_id,
                policy_sha256 = %document.policy_sha256,
                provider = %provider,
                model = %model,
                "usage authorization excluded auto-routing candidate (restricted, not allowed)"
            );
            denied.insert(target.id.clone());
        }
    }

    denied
}

/// Fill `state.ua_denied_target_ids` from a READ-ONLY per-candidate evaluate so
/// the synchronous auto-routing selection (`resolve_auto_target` /
/// `resolve_initial_provider_order` -> `score_targets`) excludes providers/models
/// the subject is not allowed to use. Only reachable for connected auto-routing
/// requests; a no-op (empty set) everywhere else keeps selection byte-identical.
pub(crate) async fn populate_ua_denied_target_ids(
    state: &mut ActiveGatewayStateView<'_>,
    request_family: crate::gateway::usage_authorization::UsageAuthorizationRequestFamily,
    requested_model: &str,
    estimated_prompt_tokens: u64,
    estimated_max_completion_tokens: u64,
    request_id: &str,
) {
    let denied = compute_ua_denied_target_ids(
        state,
        request_family,
        requested_model,
        estimated_prompt_tokens,
        estimated_max_completion_tokens,
        request_id,
    )
    .await;
    state.ua_denied_target_ids = denied;
}

pub(crate) async fn maybe_prime_connected_access_versions(
    state: &mut ActiveGatewayStateView<'_>,
    requested_model: &str,
    prompt_tokens: u64,
    max_completion_tokens: u64,
    request_id: &str,
) -> Result<ConnectedAccessRequestStatus, Response<Body>> {
    if !state.connected_mode {
        return Ok(ConnectedAccessRequestStatus::default());
    }

    let Some(org_id) = state
        .request_finops
        .as_ref()
        .and_then(|finops| finops.org_id.clone())
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(ConnectedAccessRequestStatus::default());
    };
    let Some(target) = resolve_auto_target(requested_model, state).or_else(|| {
        state.provider_registry.as_ref().and_then(|registry| {
            registry
                .targets
                .iter()
                .find(|candidate| target_supports_model(candidate, requested_model))
        })
    }) else {
        tracing::debug!(
            request_id = %request_id,
            requested_model = %requested_model,
            "skipping connected access preflight because no deployed target matched the request"
        );
        return Ok(ConnectedAccessRequestStatus {
            admission_credential_source: None,
            dispatch_precluded: true,
        });
    };
    if !crate::gateway::provider_auth::uses_organization_stored_provider_secret(target) {
        return Ok(ConnectedAccessRequestStatus {
            admission_credential_source: Some(ConnectedCredentialSource::Byok),
            dispatch_precluded: false,
        });
    }
    if resolve_catalog_model_name_for_request(target, requested_model).is_none() {
        tracing::debug!(
            request_id = %request_id,
            provider_id = %target.id,
            requested_model = %requested_model,
            "skipping connected access preflight because the requested model is not proven active in target catalog metadata"
        );
        return Ok(ConnectedAccessRequestStatus {
            admission_credential_source: None,
            dispatch_precluded: true,
        });
    }

    // The control plane evaluates the organization provider-key policy for one
    // agent. Without a resolved agent there is no BYOK policy to evaluate, so
    // the gateway denies dispatch.
    let Some(request_agent_id) = resolved_request_agent_id(state) else {
        tracing::warn!(
            request_id = %request_id,
            "skipping connected access preflight because no deployed request agent resolved"
        );
        return Ok(ConnectedAccessRequestStatus {
            admission_credential_source: None,
            dispatch_precluded: true,
        });
    };

    let Some(sink) = state.event_sink.as_ref() else {
        return Err(build_request_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            request_id,
            "Connected access preflight is unavailable",
            "service_unavailable",
            "access_preflight_unavailable",
        ));
    };
    let machine_client = sink.machine_client().map_err(|error| {
        tracing::warn!(
            request_id = %request_id,
            error = %error,
            "connected access preflight unavailable"
        );
        build_request_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            request_id,
            "Connected access preflight is unavailable",
            "service_unavailable",
            "access_preflight_unavailable",
        )
    })?;
    let usage_pricing = resolve_usage_pricing_context_with_estimate(
        requested_model,
        state,
        prompt_tokens,
        max_completion_tokens,
    );
    let preflight_req = crate::gateway::access_preflight::AccessPreflightRequest {
        org_id: org_id.clone(),
        agent_id: request_agent_id,
        provider: usage_pricing.provider.clone(),
        model: usage_pricing.model.clone(),
    };
    let mut outcome = run_connected_access_preflight(machine_client, sink, preflight_req.clone())
        .await
        .map_err(|error| {
            tracing::warn!(
                request_id = %request_id,
                error = %error,
                "connected access preflight failed"
            );
            build_request_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                request_id,
                "Connected access preflight failed",
                "service_unavailable",
                "access_preflight_failed",
            )
        })?;

    // fail closed on required distributed-state loss before any
    // process-local budget reservation. LocalOnly remains an explicit
    // one-node development contract and never materializes from Required outage.
    if let Some(distributed) = state.distributed_state.as_ref() {
        let decision = budget_admission::admit_budget_for_distributed_state(distributed);
        if !decision.allows_dispatch() {
            tracing::warn!(
                request_id = %request_id,
                requirement = %distributed.requirement().as_str(),
                decision = %decision.as_str(),
                "budget admission denied; required distributed backend unavailable"
            );
            return Err(build_request_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                request_id,
                "Distributed state unavailable for budget admission",
                "service_unavailable",
                crate::gateway::distributed_state::DISTRIBUTED_STATE_UNAVAILABLE_REASON,
            ));
        }
    }

    // Local budget enforcement: if the cached outcome has a budget tracker,
    // attempt to reserve estimated cost. If exhausted, invalidate and re-fetch.
    if !try_local_budget_reservation(&outcome, prompt_tokens, max_completion_tokens) {
        tracing::info!(
            request_id = %request_id,
            provider = %usage_pricing.provider,
            model = %usage_pricing.model,
            "local budget exhausted, invalidating preflight cache"
        );
        let cache_key = PreflightCacheKey {
            org_id: org_id.clone(),
            provider: usage_pricing.provider.clone(),
            model: usage_pricing.model.clone(),
        };
        sink.access_preflight_cache.remove(&cache_key);

        outcome = run_connected_access_preflight(machine_client, sink, preflight_req)
            .await
            .map_err(|error| {
                tracing::warn!(
                    request_id = %request_id,
                    error = %error,
                    "connected access preflight re-fetch after budget exhaustion failed"
                );
                build_request_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    request_id,
                    request_id,
                    "Connected access preflight failed",
                    "service_unavailable",
                    "access_preflight_failed",
                )
            })?;
    }

    if let Some(finops) = state.request_finops.as_mut() {
        finops.org_authz_version = outcome
            .primary
            .org_authz_version
            .or(finops.org_authz_version);
    }

    // `ready_byok` is the only ready state. Every other readiness value keeps
    // dispatch precluded so the gateway never resolves a platform credential.
    let admission_credential_source = if outcome.primary.status == "ready_byok" {
        Some(ConnectedCredentialSource::Byok)
    } else {
        None
    };
    Ok(ConnectedAccessRequestStatus {
        admission_credential_source,
        dispatch_precluded: admission_credential_source.is_none(),
    })
}

#[derive(Clone, Copy)]
pub(crate) struct ConnectedDispatchUsageContext<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) traceparent: &'a str,
    pub(crate) org_id: &'a str,
    pub(crate) agent_id: Option<&'a str>,
    pub(crate) provider: &'a str,
    pub(crate) model: &'a str,
    pub(crate) estimated_prompt_tokens: u64,
    pub(crate) estimated_max_completion_tokens: u64,
}

pub(crate) async fn enforce_connected_agent_usage_constraints(
    machine_client: &reqwest::Client,
    api_base_url: &str,
    ctx: ConnectedDispatchUsageContext<'_>,
) -> Result<(), Response<Body>> {
    let Some(agent_id) = ctx.agent_id else {
        return Ok(());
    };

    match crate::gateway::usage_constraints::check_agent_usage(
        machine_client,
        api_base_url,
        "",
        agent_id,
        ctx.org_id,
        ctx.provider,
        ctx.model,
        ctx.estimated_prompt_tokens,
        ctx.estimated_max_completion_tokens,
    )
    .await
    {
        Ok(crate::gateway::usage_constraints::UsageCheckResult::Allowed) => Ok(()),
        Ok(crate::gateway::usage_constraints::UsageCheckResult::Rejected {
            constraint_type,
            interval,
            enforcement_mode,
            resets_at,
            retry_after_secs,
        }) => {
            tracing::warn!(
                request_id = %ctx.request_id,
                agent_id = %agent_id,
                constraint_type = %constraint_type,
                enforcement_mode = %enforcement_mode,
                "agent usage constraint exceeded"
            );
            let body = serde_json::json!({
                "error": error_json(
                    &format!(
                        "Usage constraint exceeded: {} ({})",
                        constraint_type, interval
                    ),
                    "rate_limit_exceeded",
                    "usage_constraint_exceeded",
                ),
                "constraint_type": constraint_type,
                "interval": interval,
                "enforcement_mode": enforcement_mode,
                "resets_at": resets_at,
                "retry_after_secs": retry_after_secs,
            });
            let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
            let mut builder = Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Request-Id", ctx.request_id)
                .header("traceparent", ctx.traceparent);
            if let Some(secs) = retry_after_secs {
                builder = builder.header("Retry-After", secs.to_string());
            }
            Err(builder.body(Body::from(text)).unwrap_or_default())
        }
        Err(err) => {
            tracing::error!(
                request_id = %ctx.request_id,
                error = %err,
                "usage constraint check failed; rejecting request in connected mode"
            );
            Err(build_request_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                ctx.request_id,
                ctx.traceparent,
                "Usage constraint check failed",
                "service_unavailable",
                "usage_constraint_check_failed",
            ))
        }
    }
}

pub(crate) async fn maybe_prepare_connected_access_dispatch(
    state: &mut ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    parsed_json: &serde_json::Value,
    request_id: &str,
    traceparent: &str,
    prompt_hash: &str,
    estimated_max_completion_tokens: u64,
    admission_credential_source: Option<ConnectedCredentialSource>,
    skip_authoritative_admission: bool,
) -> Result<ConnectedAccessDispatchContext, Response<Body>> {
    let request_model = parsed_json
        .get("model")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let estimated_prompt_tokens =
        crate::gateway::token_estimation::estimate_prompt_tokens(parsed_json).unwrap_or(0) as u64;

    let frozen_usage_attribution = usage_execution_attribution(state, request_id);

    if state.connected_mode && !skip_authoritative_admission {
        let sink = state.event_sink.as_ref().ok_or_else(|| {
            build_request_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                traceparent,
                "Connected admission client is unavailable",
                "service_unavailable",
                "token_admission_client_unavailable",
            )
        })?;
        let machine_client = sink.machine_client().map_err(|error| {
            tracing::error!(
                request_id = %request_id,
                error = %error,
                "connected admission client initialization failed"
            );
            build_request_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                traceparent,
                "Connected admission client is unavailable",
                "service_unavailable",
                "token_admission_client_unavailable",
            )
        })?;
        let api_base_url = sink.base_url();
        let usage_pricing = resolve_usage_pricing_context_with_estimate(
            request_model,
            state,
            estimated_prompt_tokens,
            estimated_max_completion_tokens,
        );
        let est_provider = usage_pricing.provider.clone();
        let reserve_model = usage_pricing.model.clone();
        let finops = state.request_finops.as_ref();
        let org_id = finops.and_then(|f| f.org_id.as_deref()).unwrap_or("");
        let agent_id = state.current_agent_id.as_deref();
        let usage_ctx = ConnectedDispatchUsageContext {
            request_id,
            traceparent,
            org_id,
            agent_id,
            provider: &est_provider,
            model: &reserve_model,
            estimated_prompt_tokens,
            estimated_max_completion_tokens,
        };
        enforce_connected_agent_usage_constraints(machine_client, api_base_url, usage_ctx).await?;

        if let Err(error) = frozen_usage_attribution.validate_publication_selection_tuple() {
            tracing::error!(
                request_id = %request_id,
                error = %error,
                "connected access publication context invalid; rejecting request"
            );
            return Err(build_request_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                traceparent,
                "Connected access publication context invalid",
                "service_unavailable",
                "access_publication_context_invalid",
            ));
        }

        let _ = admission_credential_source;
        let _ = prompt_hash;
        let _ = headers;
    }

    let dispatch_conversation_id = headers
        .get("x-conversation-id")
        .and_then(|v| v.to_str().ok());
    Ok(ConnectedAccessDispatchContext {
        gateway_usage_authorization_id: None,
        frozen_usage_attribution,
        frozen_spend_log_context: OwnedSpendLogContext::from_state(state)
            .with_conversation_id(dispatch_conversation_id),
    })
}

pub(crate) async fn connected_access_status_for_request(
    state: &mut ActiveGatewayStateView<'_>,
    parsed_json: &serde_json::Value,
    request_id: &str,
    estimated_max_completion_tokens: u64,
) -> Result<ConnectedAccessRequestStatus, Response<Body>> {
    let request_model = parsed_json
        .get("model")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let estimated_prompt_tokens =
        crate::gateway::token_estimation::estimate_prompt_tokens(parsed_json).unwrap_or(0) as u64;
    maybe_prime_connected_access_versions(
        state,
        request_model,
        estimated_prompt_tokens,
        estimated_max_completion_tokens,
        request_id,
    )
    .await
}

pub(crate) fn finalize_connected_post_dispatch_accounting(
    event_sink: Option<&EventSink>,
    key_budget_tracker: &Arc<crate::gateway::token_rate_limit::TokenBudgetTracker>,
    request_body_bytes: &Bytes,
    usage: Option<ConnectedPostDispatchUsage>,
    access_dispatch_ctx: &ConnectedAccessDispatchContext,
    request_id: &str,
    _traceparent: &str,
    served_provider_id: Option<&str>,
    upstream_duration_ms: Option<i64>,
) {
    let request_finops = access_dispatch_ctx
        .frozen_spend_log_context
        .request_finops
        .as_ref();
    let mut increment_model = extract_upstream_model_name(request_body_bytes).unwrap_or_default();
    let mut increment_provider = infer_provider_from_model(&increment_model).unwrap_or_default();

    if let Some(sink) = event_sink {
        if let Some(usage_context) = usage.as_ref() {
            if usage_context.source.is_estimated() {
                tracing::debug!(
                    request_id = %request_id,
                    usage_source = %usage_context.source.as_str(),
                    "using estimated post-dispatch usage for accounting closeout"
                );
            }
            if let Some(mut spend_log) = build_spend_log_payload_with_usage(
                access_dispatch_ctx.frozen_spend_log_context.as_ref(),
                request_id,
                request_body_bytes,
                usage_context.usage,
                false,
                served_provider_id,
                usage_context.pipeline_metadata.clone(),
                usage_context.response_model_hint.clone(),
                usage_context.response_bytes,
            ) {
                annotate_post_dispatch_usage_source(&mut spend_log, usage_context.source);
                if let Some(duration_ms) = upstream_duration_ms {
                    if let Some(object) = spend_log.metadata.as_object_mut() {
                        object.insert("latency_ms".to_string(), serde_json::json!(duration_ms));
                    }
                }
                if !spend_log.model.trim().is_empty() {
                    increment_model = spend_log.model.clone();
                }
                if !spend_log.provider.trim().is_empty() {
                    increment_provider = spend_log.provider.clone();
                }
                record_successful_token_spend_with_context(
                    key_budget_tracker,
                    request_finops,
                    &spend_log,
                );
                // CLI duplicate-writer correction:
                // reservation-linked requests are settled authoritatively
                // through the API below (single reservation-linked write, with
                // replay deduplicated server-side). Emitting the legacy
                // fire-and-forget spend writer here as well would double-write
                // the same logical unit of work. Only emit the legacy writer
                // when no usage authorization exists (e.g. local/unauthorized
                // gateway requests). Local usage tracking above is retained for
                // all requests.
                sink.enqueue_spend_log(request_id, spend_log);
            }
        }
    }

    if !access_dispatch_ctx.frozen_spend_log_context.connected_mode {
        return;
    }

    if access_dispatch_ctx
        .frozen_spend_log_context
        .current_agent_id
        .is_none()
    {
        return;
    }

    let Some(sink) = event_sink else {
        return;
    };
    let Ok(machine_client) = sink.machine_client() else {
        return;
    };

    let actual_input = usage
        .as_ref()
        .map(|usage| usage.usage.prompt_tokens)
        .unwrap_or(0);
    let actual_completion = usage
        .as_ref()
        .map(|usage| usage.usage.completion_tokens)
        .unwrap_or(0);
    let actual_cached = usage
        .as_ref()
        .map(|usage| usage.usage.cached_input_tokens)
        .unwrap_or(0);
    let current_agent_id = access_dispatch_ctx
        .frozen_spend_log_context
        .current_agent_id
        .clone();
    let org_id = request_finops
        .and_then(|finops| finops.org_id.as_deref())
        .unwrap_or("")
        .to_string();
    let usage_increment_idempotency_key = request_id.to_string();
    let client = machine_client.clone();
    let base_url = sink.base_url().to_string();
    let forward_join_set = std::sync::Arc::clone(&sink.forward_join_set);
    let task = async move {
        if let Some(agent_id) = current_agent_id.as_deref() {
            if let Err(err) = crate::gateway::usage_constraints::increment_agent_usage(
                &client,
                &base_url,
                "",
                agent_id,
                &org_id,
                &increment_provider,
                &increment_model,
                actual_input,
                actual_cached,
                actual_completion,
                1,
                Some(&usage_increment_idempotency_key),
            )
            .await
            {
                tracing::warn!(
                    agent_id = %agent_id,
                    error = %err,
                    "usage increment failed"
                );
            }
        }
    };
    {
        let mut join_set = match forward_join_set.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        join_set.spawn(task);
    }
}

pub(crate) fn finalize_connected_access_after_buffered_response(
    state: &ActiveGatewayStateView<'_>,
    request_body: &serde_json::Value,
    request_body_bytes: &Bytes,
    response: &crate::gateway::cache::BufferedUpstreamResponse,
    access_dispatch_ctx: &ConnectedAccessDispatchContext,
    request_id: &str,
    traceparent: &str,
    served_provider_id: Option<&str>,
    upstream_duration_ms: Option<i64>,
) {
    if response.is_cached() {
        return;
    }

    finalize_connected_post_dispatch_accounting(
        state.event_sink.as_ref(),
        state.key_budget_tracker,
        request_body_bytes,
        resolve_buffered_post_dispatch_usage(request_body, response),
        access_dispatch_ctx,
        request_id,
        traceparent,
        served_provider_id,
        upstream_duration_ms,
    );
}
