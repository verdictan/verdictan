// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Server section module.
//! Child of `gateway::server`; parent private items remain visible via `use crate::gateway::*`.
// Parent `server.rs` still owns private request-resolution types used by
// `pub(crate)` helpers here until ownership is fully moved.
#![allow(private_interfaces)]
use super::super::*;
use super::part1::*;

pub(crate) fn inject_context_fabric_verdictan_metadata(
    verdictan: &mut serde_json::Value,
    finops: Option<&RequestFinopsContext>,
    recall_attribution: Option<&GatewayRecallAttribution>,
    capture_mode: &str,
    capture_suggestion: Option<&GatewayCaptureSuggestion>,
) {
    if recall_attribution.is_none()
        && capture_suggestion.is_none()
        && finops
            .and_then(RequestFinopsContext::work_reuse_json)
            .is_none()
        && finops
            .and_then(|value| value.novelty_class.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
    {
        return;
    }

    let Some(root) = verdictan.as_object_mut() else {
        return;
    };

    let context_fabric = root
        .entry("context_fabric".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let Some(context_fabric_object) = context_fabric.as_object_mut() else {
        return;
    };

    context_fabric_object.insert("capture_mode".to_string(), serde_json::json!(capture_mode));
    if let Some(novelty_class) = finops
        .and_then(|value| value.novelty_class.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        context_fabric_object.insert(
            "novelty_class".to_string(),
            serde_json::json!(novelty_class),
        );
    }

    if let Some(recall_attribution) = recall_attribution {
        context_fabric_object.insert("recall_applied".to_string(), serde_json::Value::Bool(true));
        context_fabric_object.insert(
            "recall_summary".to_string(),
            serde_json::json!(recall_attribution.summary),
        );
        context_fabric_object.insert(
            "recalled_entries".to_string(),
            serde_json::to_value(&recall_attribution.recalled_entries)
                .unwrap_or_else(|_| serde_json::json!([])),
        );
    }

    if let Some(capture_suggestion) = capture_suggestion {
        context_fabric_object.insert(
            "capture_suggestion".to_string(),
            serde_json::to_value(capture_suggestion).unwrap_or_else(|_| serde_json::json!({})),
        );
    }

    if let Some(work_reuse) = finops.and_then(RequestFinopsContext::work_reuse_json) {
        root.insert("work_reuse".to_string(), work_reuse);
    }
}

pub async fn apply_runtime_recall(
    state: &ActiveGatewayStateView<'_>,
    parsed_json: &mut serde_json::Value,
    responses_api: bool,
    conversation_id: Option<&str>,
    request_id: &str,
    traceparent: &str,
    request_agent_id: Option<&str>,
    git_context: Option<crate::gateway::session::GatewayGitContext>,
) -> (
    Option<crate::gateway::session::GatewaySessionContext>,
    Option<String>,
    Option<crate::gateway::agent_context::AppliedAgentContext>,
    Option<crate::gateway::work_reuse::RuntimeReuseOutcome>,
) {
    let agent_id = match request_agent_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(agent_id) => Some(agent_id.to_string()),
        None => resolve_runtime_agent_id(state).await,
    };
    let session_user_id = state
        .request_finops
        .as_ref()
        .and_then(|context| context.user_id.as_deref())
        .or_else(|| {
            state
                .request_finops
                .as_ref()
                .and_then(|context| context.created_by.as_deref())
        });
    let session_context = crate::gateway::session::derive_session_context_with_git_context(
        state
            .request_finops
            .as_ref()
            .and_then(|context| context.org_id.as_deref()),
        session_user_id,
        state
            .request_finops
            .as_ref()
            .and_then(|context| context.team_id.as_deref()),
        state
            .request_finops
            .as_ref()
            .and_then(|context| context.key_id.as_deref()),
        state.gateway_id.as_deref(),
        agent_id.as_deref(),
        conversation_id,
        state
            .request_finops
            .as_ref()
            .and_then(|context| context.gateway_execution_session_id.as_deref()),
        git_context,
    );

    let needs_runtime = state.agent_context_service.is_some()
        || state.history_service.is_some()
        || state.task_novelty_service.is_some();
    if !needs_runtime {
        return (session_context, agent_id, None, None);
    };
    let Some(session_context_ref) = session_context.as_ref() else {
        return (session_context, agent_id, None, None);
    };
    // Skip recall for one-shot sessions without a conversation_id — there is
    // no prior conversation history to recall (IMP-004).
    if session_context_ref.conversation_id.is_none() {
        return (session_context, agent_id, None, None);
    }
    let fail_open = true;
    let request_text = if responses_api {
        extract_messages_for_responses(Some(parsed_json))
            .into_iter()
            .map(|message| message.content)
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        extract_messages_from_value(Some(parsed_json))
            .into_iter()
            .map(|message| message.content)
            .collect::<Vec<_>>()
            .join("\n")
    };

    let novelty_request = crate::gateway::task_novelty::build_task_novelty_request(
        session_context_ref,
        Some(request_text.as_str()),
        parsed_json,
    );
    let novelty_assessment = if let (Some(service), Some(request)) = (
        state.task_novelty_service.as_ref(),
        novelty_request.as_ref(),
    ) {
        match tokio::time::timeout(
            Duration::from_millis(service.timeout_ms()),
            service.classify_task_novelty(session_context_ref, request),
        )
        .await
        {
            Ok(Ok(assessment)) => Some(assessment),
            Ok(Err(error)) => {
                tracing::warn!(error = %error, "task novelty classification failed");
                None
            }
            Err(_) => {
                tracing::warn!("task novelty classification timed out");
                None
            }
        }
    } else {
        None
    };
    let tool_chain_match = if let (Some(request), Some(_assessment)) =
        (novelty_request.as_ref(), novelty_assessment.as_ref())
    {
        lookup_agent_tool_chain_match(state.event_sink.as_ref(), session_context_ref, request).await
    } else {
        None
    };
    let tool_chain_hit = tool_chain_match.is_some();
    let tool_names = tool_chain_match
        .as_ref()
        .map(|candidate| {
            let mut names = candidate
                .tool_calls
                .iter()
                .map(|tool_call| tool_call.tool_name.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();
            names.sort();
            names.dedup();
            names
        })
        .unwrap_or_default();
    let mut reuse_outcome = novelty_assessment.as_ref().and_then(|assessment| {
        let decision = crate::gateway::work_reuse::select_reuse_mode(
            Some(assessment),
            tool_chain_match.as_ref(),
            state
                .hosted_gateway_local_access
                .as_ref()
                .is_some_and(|config| config.enabled),
        )?;
        let requested_mode = decision.mode.as_str().to_string();
        Some(crate::gateway::work_reuse::RuntimeReuseOutcome {
            novelty_class: Some(assessment.novelty_class.as_str().to_string()),
            matched_receipt_id: assessment
                .matched_receipt
                .as_ref()
                .map(|receipt| receipt.receipt_id.clone()),
            decision: Some(decision),
            requested_mode: Some(requested_mode),
            policy_decision: None,
            verifier: None,
            tool_chain_hit,
            tool_names: tool_names.clone(),
            avoided_tool_executions: None,
            avoided_model_calls: None,
            reuse_applied: None,
            replay_success: None,
            policy_denied: None,
            block_injected: false,
        })
    });
    if let (Some(assessment), Some(outcome)) = (novelty_assessment.as_ref(), reuse_outcome.as_mut())
    {
        if let Some(decision) = outcome.decision.as_mut() {
            if decision.mode != crate::gateway::work_reuse::ReuseMode::OpenFreshInvestigation {
                let policy_decision =
                    crate::gateway::work_reuse_policy::evaluate_work_reuse_policy(
                        state.event_sink.as_ref(),
                        session_context_ref,
                        state
                            .hosted_gateway_local_access
                            .as_ref()
                            .filter(|config| config.enabled),
                        assessment.request.working_directory.as_deref(),
                        decision,
                        assessment
                            .matched_receipt
                            .as_ref()
                            .map(|receipt| receipt.confidence_score),
                        tool_chain_match.as_ref(),
                    )
                    .await;
                crate::gateway::work_reuse_policy::emit_policy_decision_event(
                    state.event_sink.as_ref(),
                    request_id,
                    traceparent,
                    session_context_ref,
                    &policy_decision,
                )
                .await;
                let policy_allows_reuse = policy_decision.decision == "allow";
                outcome.policy_decision = Some(policy_decision.clone());
                if !policy_allows_reuse {
                    decision.mode = crate::gateway::work_reuse::ReuseMode::OpenFreshInvestigation;
                    decision.reason = format!(
                        "autonomous reuse blocked by policy: {}",
                        policy_decision.reason_code
                    );
                    decision.verifier_commands.clear();
                } else if matches!(
                    decision.mode,
                    crate::gateway::work_reuse::ReuseMode::ReplayCommands
                        | crate::gateway::work_reuse::ReuseMode::AdaptPreviousPatch
                ) {
                    decision.mode = crate::gateway::work_reuse::ReuseMode::OpenFreshInvestigation;
                    decision.reason =
                        "autonomous replay and patch adaptation require an execution path before reuse can be applied"
                            .to_string();
                    decision.verifier_commands.clear();
                }
            }
            if decision.mode == crate::gateway::work_reuse::ReuseMode::RunKnownVerifier {
                if let Some(config) = state.hosted_gateway_local_access.as_ref() {
                    crate::gateway::work_reuse_policy::emit_verifier_event(
                        state.event_sink.as_ref(),
                        request_id,
                        traceparent,
                        session_context_ref,
                        "start",
                        "pending",
                        "work_reuse.verifier_started",
                        &decision.verifier_commands,
                        None,
                    )
                    .await;
                    match crate::gateway::work_reuse_verifier::execute_reuse_verifier(
                        config,
                        assessment.request.working_directory.as_deref(),
                        assessment.request.git_repo.as_str(),
                        &decision.verifier_commands,
                    )
                    .await
                    {
                        Ok(summary) => {
                            let verdict = if summary.succeeded { "allow" } else { "deny" };
                            let reason_code = if summary.succeeded {
                                "work_reuse.verifier_succeeded"
                            } else {
                                "work_reuse.verifier_failed"
                            };
                            outcome.verifier = Some(summary);
                            crate::gateway::work_reuse_policy::emit_verifier_event(
                                state.event_sink.as_ref(),
                                request_id,
                                traceparent,
                                session_context_ref,
                                if verdict == "allow" {
                                    "success"
                                } else {
                                    "failure"
                                },
                                verdict,
                                reason_code,
                                &decision.verifier_commands,
                                outcome.verifier.as_ref(),
                            )
                            .await;
                        }
                        Err(error) => {
                            tracing::warn!(error = %error, "work reuse verifier failed");
                            crate::gateway::work_reuse_policy::emit_verifier_event(
                                state.event_sink.as_ref(),
                                request_id,
                                traceparent,
                                session_context_ref,
                                "failure",
                                "deny",
                                "work_reuse.verifier_failed",
                                &decision.verifier_commands,
                                None,
                            )
                            .await;
                        }
                    }
                }
            }
            if let Some(block) = crate::gateway::work_reuse::build_reuse_context_block(
                assessment,
                decision,
                outcome.verifier.as_ref(),
            ) {
                outcome.block_injected = if responses_api {
                    crate::gateway::work_reuse::inject_reuse_block_into_responses_request(
                        parsed_json,
                        &block,
                    )
                } else {
                    crate::gateway::work_reuse::inject_reuse_block_into_chat_request(
                        parsed_json,
                        &block,
                    )
                };
            }
        }
    }
    if let Some(outcome) = reuse_outcome.as_mut() {
        let final_mode = outcome
            .decision
            .as_ref()
            .map(|decision| decision.mode)
            .unwrap_or(crate::gateway::work_reuse::ReuseMode::OpenFreshInvestigation);
        let policy_denied = outcome
            .policy_decision
            .as_ref()
            .is_some_and(|policy| policy.decision != "allow");
        let reuse_applied = final_mode
            != crate::gateway::work_reuse::ReuseMode::OpenFreshInvestigation
            && outcome.block_injected;
        let replay_success =
            if final_mode == crate::gateway::work_reuse::ReuseMode::RunKnownVerifier {
                Some(
                    outcome
                        .verifier
                        .as_ref()
                        .is_some_and(|summary| summary.succeeded),
                )
            } else if outcome.tool_chain_hit || outcome.matched_receipt_id.is_some() {
                Some(reuse_applied)
            } else {
                None
            };
        let avoided_tool_executions = if reuse_applied && !outcome.tool_names.is_empty() {
            Some(outcome.tool_names.len() as u32)
        } else if outcome.tool_chain_hit {
            Some(0)
        } else {
            None
        };
        let avoided_model_calls = if outcome.matched_receipt_id.is_some() {
            Some(u32::from(reuse_applied))
        } else {
            None
        };

        outcome.avoided_tool_executions = avoided_tool_executions;
        outcome.avoided_model_calls = avoided_model_calls;
        outcome.reuse_applied = Some(reuse_applied);
        outcome.replay_success = replay_success;
        outcome.policy_denied = Some(policy_denied);
    }

    let Some(agent_context_service) = state.agent_context_service.as_ref() else {
        return (session_context, agent_id, None, reuse_outcome);
    };
    let recall = tokio::time::timeout(
        Duration::from_millis(agent_context_service.timeout_ms()),
        agent_context_service.resolve_context(
            session_context_ref,
            state.gateway_id.as_deref(),
            Some(request_text.as_str()),
            crate::gateway::agent_context::RuntimeContextConfig {
                allow_working_context: state.history_service.is_some(),
            },
            novelty_request.as_ref(),
        ),
    )
    .await;

    let applied = match recall {
        Ok(Ok(Some(applied))) => applied,
        Ok(Ok(None)) => return (session_context, agent_id, None, reuse_outcome),
        Ok(Err(error)) => {
            if fail_open {
                tracing::warn!(error = %error, "agent context resolution failed");
            } else {
                tracing::error!(error = %error, "agent context resolution failed");
            }
            return (session_context, agent_id, None, reuse_outcome);
        }
        Err(_) => {
            if fail_open {
                tracing::warn!("agent context resolution timed out");
            } else {
                tracing::error!("agent context resolution timed out");
            }
            return (session_context, agent_id, None, reuse_outcome);
        }
    };

    tracing::debug!(
        session_id = %session_context_ref.session_id,
        plan_hash = %applied.telemetry.plan_hash,
        pack_hash = ?applied.telemetry.pack_hash,
        selected_item_count = applied.telemetry.selected_item_ids.len(),
        estimated_context_tokens = applied.telemetry.tokens.estimated_tokens,
        injected_context_tokens = applied.telemetry.tokens.injected_tokens,
        working_context_tokens = applied.telemetry.tokens.working_context_tokens,
        "agent context selected for request"
    );

    let injected = if responses_api {
        crate::gateway::agent_context::AgentContextService::inject_into_responses_request(
            parsed_json,
            &applied,
        )
    } else {
        crate::gateway::agent_context::AgentContextService::inject_into_chat_request(
            parsed_json,
            &applied,
        )
    };

    if injected {
        (session_context, agent_id, Some(applied), reuse_outcome)
    } else {
        (session_context, agent_id, None, reuse_outcome)
    }
}

pub(crate) fn extract_history_token_usage(
    value: &serde_json::Value,
    finops: Option<&RequestFinopsContext>,
) -> serde_json::Value {
    let prompt_tokens = value
        .pointer("/usage/prompt_tokens")
        .and_then(|candidate| candidate.as_i64())
        .or_else(|| {
            value
                .pointer("/usage/input_tokens")
                .and_then(|candidate| candidate.as_i64())
        })
        .unwrap_or(0);
    let completion_tokens = value
        .pointer("/usage/completion_tokens")
        .and_then(|candidate| candidate.as_i64())
        .or_else(|| {
            value
                .pointer("/usage/output_tokens")
                .and_then(|candidate| candidate.as_i64())
        })
        .unwrap_or(0);
    let total_tokens = value
        .pointer("/usage/total_tokens")
        .and_then(|candidate| candidate.as_i64())
        .unwrap_or(prompt_tokens + completion_tokens);
    let mut usage = serde_json::json!({
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
    });
    if let (Some(object), Some(finops)) = (usage.as_object_mut(), finops) {
        let working_context_tokens = finops.working_context_tokens.unwrap_or_default();
        let user_prompt_tokens = prompt_tokens.saturating_sub(working_context_tokens as i64);

        if let Some(context_plan_hash) = finops
            .context_plan_hash
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            object.insert(
                "context_plan_hash".to_string(),
                serde_json::json!(context_plan_hash),
            );
        }
        object.insert(
            "user_prompt_tokens".to_string(),
            serde_json::json!(user_prompt_tokens.max(0)),
        );
        if working_context_tokens > 0 {
            object.insert(
                "working_context_tokens".to_string(),
                serde_json::json!(working_context_tokens),
            );
        }

        if let Some(context_selection) = finops.context_selection_json() {
            object.insert("context_selection".to_string(), context_selection);
        }
    }
    usage
}

pub fn attach_history_usage_block(
    mut response_payload: serde_json::Value,
    usage: Option<SpendUsage>,
) -> serde_json::Value {
    let Some(usage) = usage.filter(|usage| usage.total_tokens > 0) else {
        return response_payload;
    };

    let Some(object) = response_payload.as_object_mut() else {
        return response_payload;
    };

    object.entry("usage".to_string()).or_insert_with(|| {
        serde_json::json!({
            "prompt_tokens": usage.prompt_tokens,
            "completion_tokens": usage.completion_tokens,
            "total_tokens": usage.total_tokens,
            "cached_input_tokens": usage.cached_input_tokens,
        })
    });

    response_payload
}

pub(crate) fn build_metadata_only_history_request(
    request_payload: &serde_json::Value,
    request_id: &str,
    finops: Option<&RequestFinopsContext>,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "request_id": request_id,
        "message_count": extract_messages_from_value(Some(request_payload)).len(),
        "has_verdictan": request_payload.get("verdictan").is_some(),
    });
    // Extract the last user message as a title seed so the API can derive a
    // conversation title even in metadata_only mode (privacy-preserving: only
    // the first user turn, truncated to 120 chars, is kept).
    if let Some(title_seed) = extract_title_seed_from_request(request_payload) {
        if let Some(object) = payload.as_object_mut() {
            object.insert(
                "title_seed".to_string(),
                serde_json::Value::String(title_seed),
            );
        }
    }
    if let (Some(object), Some(context_selection)) = (
        payload.as_object_mut(),
        finops.and_then(RequestFinopsContext::context_selection_json),
    ) {
        object.insert("context_selection".to_string(), context_selection);
    }
    payload
}

/// Extract a truncated last-user-turn string suitable for title generation.
/// Returns at most 120 characters of the last user message content.
pub(crate) fn extract_title_seed_from_request(
    request_payload: &serde_json::Value,
) -> Option<String> {
    let messages = extract_messages_from_value(Some(request_payload));
    let last_user = messages.iter().rev().find(|m| m.role == "user")?;
    let text: String = last_user
        .content
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if text.is_empty() {
        return None;
    }
    const MAX_CHARS: usize = 120;
    if text.chars().count() <= MAX_CHARS {
        Some(text)
    } else {
        let end = text
            .char_indices()
            .nth(MAX_CHARS)
            .map(|(idx, _)| idx)
            .unwrap_or(text.len());
        Some(format!("{}…", text[..end].trim_end()))
    }
}

pub(crate) fn build_metadata_only_history_response(
    response_payload: &serde_json::Value,
    finops: Option<&RequestFinopsContext>,
) -> serde_json::Value {
    serde_json::json!({
        "usage": extract_history_token_usage(response_payload, finops),
        "has_output": extract_openai_chat_output(response_payload)
            .or_else(|| extract_openai_responses_output(response_payload))
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false),
    })
}

pub(crate) fn append_history_writeback_metadata(
    mut response_payload: serde_json::Value,
    latency_ms: Option<i64>,
    background_requested: bool,
) -> serde_json::Value {
    let Some(root) = response_payload.as_object_mut() else {
        return response_payload;
    };

    let verdictan = root
        .entry("verdictan".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let Some(verdictan_object) = verdictan.as_object_mut() else {
        return response_payload;
    };

    verdictan_object.insert(
        "history".to_string(),
        serde_json::json!({
            "latency_ms": latency_ms,
            "background_requested": background_requested,
        }),
    );

    response_payload
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RuntimeToolCallContext {
    pub(crate) tool_name: String,
    pub(crate) arguments: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RuntimeToolResultContext {
    pub(crate) tool_name: String,
    pub(crate) arguments: serde_json::Value,
    pub(crate) output: serde_json::Value,
}

pub(crate) fn parse_runtime_tool_payload_string(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|_| serde_json::Value::String(text.to_string()))
}

pub(crate) fn normalize_runtime_tool_payload(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => parse_runtime_tool_payload_string(text),
        serde_json::Value::Array(items) => {
            let mut text_fragments = Vec::new();
            for item in items {
                match item {
                    serde_json::Value::String(text) => text_fragments.push(text.clone()),
                    serde_json::Value::Object(map)
                        if map.get("type").and_then(serde_json::Value::as_str) == Some("text") =>
                    {
                        let Some(text) = map.get("text").and_then(serde_json::Value::as_str) else {
                            return value.clone();
                        };
                        text_fragments.push(text.to_string());
                    }
                    _ => return value.clone(),
                }
            }

            if text_fragments.is_empty() {
                value.clone()
            } else {
                parse_runtime_tool_payload_string(&text_fragments.join("\n"))
            }
        }
        serde_json::Value::Object(map)
            if map.get("type").and_then(serde_json::Value::as_str) == Some("text") =>
        {
            map.get("text")
                .and_then(serde_json::Value::as_str)
                .map(parse_runtime_tool_payload_string)
                .unwrap_or_else(|| value.clone())
        }
        _ => value.clone(),
    }
}

pub(crate) fn register_openai_tool_calls(
    tool_calls: &[serde_json::Value],
    pending: &mut BTreeMap<String, RuntimeToolCallContext>,
) {
    for tool_call in tool_calls {
        let Some(call_id) = tool_call
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let function = tool_call.get("function").unwrap_or(tool_call);
        let Some(tool_name) = function
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        pending.insert(
            call_id.to_string(),
            RuntimeToolCallContext {
                tool_name: tool_name.to_string(),
                arguments: function
                    .get("arguments")
                    .map(normalize_runtime_tool_payload)
                    .unwrap_or_else(|| serde_json::json!({})),
            },
        );
    }
}

pub(crate) fn register_anthropic_tool_use_blocks(
    blocks: &[serde_json::Value],
    pending: &mut BTreeMap<String, RuntimeToolCallContext>,
) {
    for block in blocks {
        if block.get("type").and_then(serde_json::Value::as_str) != Some("tool_use") {
            continue;
        }
        let Some(call_id) = block
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(tool_name) = block
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        pending.insert(
            call_id.to_string(),
            RuntimeToolCallContext {
                tool_name: tool_name.to_string(),
                arguments: block
                    .get("input")
                    .map(normalize_runtime_tool_payload)
                    .unwrap_or_else(|| serde_json::json!({})),
            },
        );
    }
}

pub(crate) fn collect_anthropic_tool_result_blocks(
    blocks: &[serde_json::Value],
    pending: &BTreeMap<String, RuntimeToolCallContext>,
    results: &mut Vec<RuntimeToolResultContext>,
) {
    for block in blocks {
        if block.get("type").and_then(serde_json::Value::as_str) != Some("tool_result") {
            continue;
        }
        let Some(call_id) = block
            .get("tool_use_id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(tool_context) = pending.get(call_id) else {
            continue;
        };
        let Some(output) = block.get("content") else {
            continue;
        };

        results.push(RuntimeToolResultContext {
            tool_name: tool_context.tool_name.clone(),
            arguments: tool_context.arguments.clone(),
            output: normalize_runtime_tool_payload(output),
        });
    }
}

pub(crate) fn collect_openai_tool_result_message(
    message: &serde_json::Value,
    pending: &BTreeMap<String, RuntimeToolCallContext>,
    results: &mut Vec<RuntimeToolResultContext>,
) {
    if message.get("role").and_then(serde_json::Value::as_str) != Some("tool") {
        return;
    }
    let Some(call_id) = message
        .get("tool_call_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };
    let Some(tool_context) = pending.get(call_id) else {
        return;
    };
    let Some(output) = message.get("content") else {
        return;
    };

    results.push(RuntimeToolResultContext {
        tool_name: tool_context.tool_name.clone(),
        arguments: tool_context.arguments.clone(),
        output: normalize_runtime_tool_payload(output),
    });
}

pub(crate) fn extract_runtime_tool_results_from_messages(
    messages: &[serde_json::Value],
) -> Vec<RuntimeToolResultContext> {
    let mut pending = BTreeMap::new();
    let mut results = Vec::new();

    for message in messages {
        if let Some(tool_calls) = message
            .get("tool_calls")
            .and_then(serde_json::Value::as_array)
        {
            register_openai_tool_calls(tool_calls, &mut pending);
        }

        if let Some(content_blocks) = message.get("content").and_then(serde_json::Value::as_array) {
            register_anthropic_tool_use_blocks(content_blocks, &mut pending);
            collect_anthropic_tool_result_blocks(content_blocks, &pending, &mut results);
        }

        collect_openai_tool_result_message(message, &pending, &mut results);
    }

    results
}

pub(crate) fn extract_runtime_tool_results_from_responses_input(
    request_payload: &serde_json::Value,
) -> Vec<RuntimeToolResultContext> {
    let mut pending = BTreeMap::new();
    let mut results = Vec::new();

    let Some(input) = request_payload.get("input") else {
        return results;
    };
    let items = if let Some(array) = input.as_array() {
        array.as_slice()
    } else {
        std::slice::from_ref(input)
    };

    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };
        match object.get("type").and_then(serde_json::Value::as_str) {
            Some("function_call") => {
                let Some(call_id) = object
                    .get("call_id")
                    .or_else(|| object.get("id"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };
                let Some(tool_name) = object
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };
                pending.insert(
                    call_id.to_string(),
                    RuntimeToolCallContext {
                        tool_name: tool_name.to_string(),
                        arguments: object
                            .get("arguments")
                            .map(normalize_runtime_tool_payload)
                            .unwrap_or_else(|| serde_json::json!({})),
                    },
                );
            }
            Some("function_call_output") => {
                let Some(call_id) = object
                    .get("call_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };
                let Some(tool_context) = pending.get(call_id) else {
                    continue;
                };
                let Some(output) = object.get("output").or_else(|| object.get("content")) else {
                    continue;
                };
                results.push(RuntimeToolResultContext {
                    tool_name: tool_context.tool_name.clone(),
                    arguments: tool_context.arguments.clone(),
                    output: normalize_runtime_tool_payload(output),
                });
            }
            _ => {
                let item_value = serde_json::Value::Object(object.clone());
                results.extend(extract_runtime_tool_results_from_messages(
                    std::slice::from_ref(&item_value),
                ));
            }
        }
    }

    results
}

pub(crate) fn extract_runtime_tool_results(
    request_payload: &serde_json::Value,
) -> Vec<RuntimeToolResultContext> {
    let mut unique = Vec::new();
    let mut seen = BTreeSet::new();

    for result in extract_runtime_tool_results_from_messages(
        request_payload
            .get("messages")
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
    )
    .into_iter()
    .chain(extract_runtime_tool_results_from_responses_input(
        request_payload,
    )) {
        let Ok(arguments) = serde_json::to_string(&result.arguments) else {
            continue;
        };
        let Ok(output) = serde_json::to_string(&result.output) else {
            continue;
        };
        let dedup_key = format!("{}|{arguments}|{output}", result.tool_name);
        if seen.insert(dedup_key) {
            unique.push(result);
        }
    }

    unique
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct GatewayCreateAgentCallTracePayload {
    pub(crate) org_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) agent_id: Option<String>,
    pub(crate) session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) conversation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) model: Option<String>,
    pub(crate) prompt_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) response_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) request_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) response_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) input_tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) output_tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) estimated_cost_micros: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) latency_ms: Option<i64>,
    pub(crate) git_repo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) git_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) git_commit: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub(crate) struct GatewayCreateAgentCallTraceResponse {
    pub(crate) agent_call_trace_id: String,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingAgentToolCallTracePayload {
    pub(crate) tool_name: String,
    pub(crate) arguments: serde_json::Value,
    pub(crate) result: serde_json::Value,
    pub(crate) tool_status: String,
    pub(crate) duration_ms: Option<i64>,
    pub(crate) policy_decision: String,
    pub(crate) provenance: serde_json::Value,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct GatewayCreateAgentToolCallTracePayload {
    pub(crate) org_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) agent_id: Option<String>,
    pub(crate) agent_call_trace_id: String,
    pub(crate) session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) conversation_id: Option<String>,
    pub(crate) tool_name: String,
    pub(crate) arguments: serde_json::Value,
    pub(crate) result: serde_json::Value,
    pub(crate) tool_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) duration_ms: Option<i64>,
    pub(crate) policy_decision: String,
    pub(crate) provenance: serde_json::Value,
    pub(crate) git_repo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) git_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) git_commit: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct GatewayAgentToolChainSearchPayload {
    pub(crate) org_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) agent_id: Option<String>,
    pub(crate) git_repo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) git_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) git_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) normalized_prompt_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) task_fingerprint_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) error_signature_hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) file_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) symbols: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) tool_names: Vec<String>,
    pub(crate) limit: u32,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub(crate) struct GatewayAgentToolChainSearchResponse {
    #[serde(default)]
    pub(crate) matches: Vec<crate::gateway::work_reuse::AgentToolChainMatch>,
}

pub fn build_agent_call_trace_machine_payload(
    request_finops: Option<&RequestFinopsContext>,
    session_context: &crate::gateway::session::GatewaySessionContext,
    request_payload: &serde_json::Value,
    response_payload: &serde_json::Value,
    provider_id: Option<&str>,
    model: Option<&str>,
    latency_ms: Option<i64>,
) -> Option<serde_json::Value> {
    serde_json::to_value(build_agent_call_trace_payload(
        request_finops,
        session_context,
        request_payload,
        response_payload,
        provider_id,
        model,
        latency_ms,
    )?)
    .ok()
}

pub fn build_agent_tool_call_trace_machine_payloads(
    session_context: &crate::gateway::session::GatewaySessionContext,
    request_payload: &serde_json::Value,
    agent_call_trace_id: &str,
) -> Vec<serde_json::Value> {
    let Some(org_id) = normalize_agent_trace_scalar(session_context._org_id.as_deref()) else {
        return Vec::new();
    };
    build_pending_agent_tool_call_trace_payloads(request_payload)
        .into_iter()
        .filter_map(|payload| {
            serde_json::to_value(serialize_pending_agent_tool_call_trace_payload(
                session_context,
                org_id.as_str(),
                agent_call_trace_id,
                payload,
            ))
            .ok()
        })
        .collect()
}

#[doc(hidden)]
pub fn build_agent_tool_call_trace_machine_payload(
    session_context: &crate::gateway::session::GatewaySessionContext,
    agent_call_trace_id: &str,
    tool_name: &str,
    arguments: &serde_json::Value,
    result: &serde_json::Value,
    tool_status: &str,
    duration_ms: Option<i64>,
) -> Option<serde_json::Value> {
    let org_id = normalize_agent_trace_scalar(session_context._org_id.as_deref())?;
    serde_json::to_value(serialize_pending_agent_tool_call_trace_payload(
        session_context,
        org_id.as_str(),
        agent_call_trace_id,
        build_pending_agent_tool_call_trace_payload(
            tool_name.to_string(),
            arguments.clone(),
            result.clone(),
            tool_status.to_string(),
            duration_ms,
        ),
    ))
    .ok()
}

pub(crate) fn build_agent_call_trace_payload(
    request_finops: Option<&RequestFinopsContext>,
    session_context: &crate::gateway::session::GatewaySessionContext,
    request_payload: &serde_json::Value,
    response_payload: &serde_json::Value,
    provider_id: Option<&str>,
    model: Option<&str>,
    latency_ms: Option<i64>,
) -> Option<GatewayCreateAgentCallTracePayload> {
    let org_id = normalize_agent_trace_scalar(session_context._org_id.as_deref())?;
    let git_context = session_context.git_context.as_ref()?;
    let git_repo = normalize_agent_trace_scalar(git_context.repo.as_deref())?;
    let git_branch = normalize_agent_trace_scalar(git_context.branch.as_deref());
    let git_commit = normalize_agent_trace_scalar(git_context.commit.as_deref());
    let request_bytes = serde_json::to_vec(request_payload).ok()?;
    let response_bytes = serde_json::to_vec(response_payload).ok()?;
    let (input_tokens, output_tokens) = response_usage_counts(response_payload);

    Some(GatewayCreateAgentCallTracePayload {
        org_id,
        team_id: normalize_agent_trace_scalar(session_context.team_id.as_deref()),
        agent_id: normalize_agent_trace_scalar(session_context.agent_id.as_deref()),
        session_id: session_context.session_id.clone(),
        conversation_id: normalize_agent_trace_scalar(session_context.conversation_id.as_deref()),
        provider: provider_id
            .and_then(|value| normalize_agent_trace_scalar(Some(value)))
            .or_else(|| request_finops.and_then(|finops| finops.provider.clone())),
        model: model
            .and_then(|value| normalize_agent_trace_scalar(Some(value)))
            .or_else(|| request_finops.and_then(|finops| finops.model_filter.clone())),
        prompt_hash: sha256_prefixed(&request_bytes),
        response_hash: Some(sha256_prefixed(&response_bytes)),
        request_preview: json_preview(request_payload),
        response_preview: json_preview(response_payload),
        input_tokens,
        output_tokens,
        estimated_cost_micros: None,
        latency_ms,
        git_repo,
        git_branch,
        git_commit,
    })
}

pub(crate) fn build_pending_agent_tool_call_trace_payloads(
    request_payload: &serde_json::Value,
) -> Vec<PendingAgentToolCallTracePayload> {
    extract_runtime_tool_results(request_payload)
        .into_iter()
        .map(|tool_result| {
            build_pending_agent_tool_call_trace_payload(
                tool_result.tool_name,
                tool_result.arguments,
                tool_result.output,
                "succeeded".to_string(),
                None,
            )
        })
        .collect()
}

pub(crate) fn build_pending_agent_tool_call_trace_payload(
    tool_name: String,
    arguments: serde_json::Value,
    result: serde_json::Value,
    tool_status: String,
    duration_ms: Option<i64>,
) -> PendingAgentToolCallTracePayload {
    let risk_policy = crate::gateway::tool_risk_policy::DestructiveActionPolicy {
        enabled: true,
        ..Default::default()
    };
    let resource_locator = serde_json::to_string(&arguments).unwrap_or_else(|_| "{}".to_string());
    let classification = crate::gateway::tool_risk_policy::classify_tool_action(
        &risk_policy,
        tool_name.as_str(),
        resource_locator.as_str(),
    );
    let side_effect = !matches!(
        classification.risk_level,
        crate::gateway::tool_risk_policy::ToolRiskLevel::Safe
    );
    let external_write = classification.resource_kind == "url" && side_effect;
    let policy_decision = if side_effect || classification.requires_approval {
        "deny".to_string()
    } else {
        "allow".to_string()
    };
    let mutability_class = if side_effect { "mutating" } else { "read_only" };
    let provenance = serde_json::json!({
        "side_effect": side_effect,
        "external_write": external_write,
        "mutability_class": mutability_class,
        "risk_level": tool_risk_level_label(classification.risk_level),
        "resource_kind": classification.resource_kind,
        "resource_locator": classification.resource_locator,
        "policy_match_reason": classification.policy_match_reason,
    });

    PendingAgentToolCallTracePayload {
        tool_name,
        arguments,
        result,
        tool_status,
        duration_ms,
        policy_decision,
        provenance,
    }
}

pub(crate) fn serialize_pending_agent_tool_call_trace_payload(
    session_context: &crate::gateway::session::GatewaySessionContext,
    org_id: &str,
    agent_call_trace_id: &str,
    payload: PendingAgentToolCallTracePayload,
) -> GatewayCreateAgentToolCallTracePayload {
    let git_context = session_context.git_context.as_ref();
    GatewayCreateAgentToolCallTracePayload {
        org_id: org_id.to_string(),
        team_id: normalize_agent_trace_scalar(session_context.team_id.as_deref()),
        agent_id: normalize_agent_trace_scalar(session_context.agent_id.as_deref()),
        agent_call_trace_id: agent_call_trace_id.to_string(),
        session_id: session_context.session_id.clone(),
        conversation_id: normalize_agent_trace_scalar(session_context.conversation_id.as_deref()),
        tool_name: payload.tool_name,
        arguments: payload.arguments,
        result: payload.result,
        tool_status: payload.tool_status,
        duration_ms: payload.duration_ms,
        policy_decision: payload.policy_decision,
        provenance: payload.provenance,
        git_repo: normalize_agent_trace_scalar(
            git_context.and_then(|context| context.repo.as_deref()),
        )
        .unwrap_or_default(),
        git_branch: normalize_agent_trace_scalar(
            git_context.and_then(|context| context.branch.as_deref()),
        ),
        git_commit: normalize_agent_trace_scalar(
            git_context.and_then(|context| context.commit.as_deref()),
        ),
    }
}

pub(crate) fn normalize_agent_trace_scalar(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn response_usage_counts(
    response_payload: &serde_json::Value,
) -> (Option<i64>, Option<i64>) {
    let input_tokens = response_payload
        .pointer("/usage/prompt_tokens")
        .and_then(serde_json::Value::as_i64)
        .or_else(|| {
            response_payload
                .pointer("/usage/input_tokens")
                .and_then(serde_json::Value::as_i64)
        });
    let output_tokens = response_payload
        .pointer("/usage/completion_tokens")
        .and_then(serde_json::Value::as_i64)
        .or_else(|| {
            response_payload
                .pointer("/usage/output_tokens")
                .and_then(serde_json::Value::as_i64)
        });
    (input_tokens, output_tokens)
}

pub(crate) fn json_preview(value: &serde_json::Value) -> Option<String> {
    let serialized = serde_json::to_string(value).ok()?;
    let pii_redacted = crate::gateway::redaction::redact_text(&serialized);
    let secret_redacted =
        redact_agent_trace_preview_text(&crate::mcp::audit::sanitize_for_audit(&pii_redacted));
    let truncated = truncate_agent_trace_preview(&secret_redacted);
    (!truncated.is_empty()).then_some(truncated)
}

pub(crate) fn redact_agent_trace_preview_text(input: &str) -> String {
    let private_key_redacted = static_regex!(
        r"(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
    )
    .replace_all(input, "[REDACTED]")
    .to_string();
    let assignment_redacted = static_regex!(
        r"(?i)((?:api[_-]?key|client_secret|private_key|password|secret|token|x-api-key)[=:\s]+)\S+"
    )
    .replace_all(&private_key_redacted, "${1}[REDACTED]")
    .to_string();
    let bearer_redacted = static_regex!(r"(?i)(authorization:\s*bearer\s+)\S+")
        .replace_all(&assignment_redacted, "${1}[REDACTED]")
        .to_string();
    static_regex!(
        r"\b(?:sk-[A-Za-z0-9_\-]+|sk_live_[A-Za-z0-9_\-]+|sk_test_[A-Za-z0-9_\-]+|ghp_[A-Za-z0-9]+|gho_[A-Za-z0-9]+|glpat-[A-Za-z0-9_\-]+|xox[baprs]-[A-Za-z0-9\-]+|AKIA[0-9A-Z]{16}|vdt_[A-Za-z0-9_\-]+)\b"
    )
    .replace_all(&bearer_redacted, "[REDACTED]")
    .to_string()
}

pub(crate) fn truncate_agent_trace_preview(value: &str) -> String {
    const MAX_PREVIEW_CHARS: usize = 512;
    let mut truncated = value.chars().take(MAX_PREVIEW_CHARS).collect::<String>();
    if value.chars().count() > MAX_PREVIEW_CHARS {
        truncated.push_str("...");
    }
    truncated
}

pub(crate) fn tool_risk_level_label(
    level: crate::gateway::tool_risk_policy::ToolRiskLevel,
) -> &'static str {
    match level {
        crate::gateway::tool_risk_policy::ToolRiskLevel::Safe => "safe",
        crate::gateway::tool_risk_policy::ToolRiskLevel::Moderate => "moderate",
        crate::gateway::tool_risk_policy::ToolRiskLevel::Destructive => "destructive",
        crate::gateway::tool_risk_policy::ToolRiskLevel::Critical => "critical",
    }
}

pub(crate) fn emit_agent_trace_bundle_detached(
    event_sink: Option<EventSink>,
    request_finops: Option<&RequestFinopsContext>,
    session_context: Option<&crate::gateway::session::GatewaySessionContext>,
    request_payload: &serde_json::Value,
    response_payload: &serde_json::Value,
    request_id: &str,
    traceparent: &str,
    provider_id: Option<&str>,
    model: Option<&str>,
    latency_ms: Option<i64>,
) {
    let Some(event_sink) = event_sink else {
        return;
    };
    let Some(session_context) = session_context.cloned() else {
        return;
    };
    let Some(agent_call_payload) = build_agent_call_trace_payload(
        request_finops,
        &session_context,
        request_payload,
        response_payload,
        provider_id,
        model,
        latency_ms,
    ) else {
        return;
    };
    let pending_tool_payloads = build_pending_agent_tool_call_trace_payloads(request_payload);
    let Ok(machine_client) = event_sink.machine_client().cloned() else {
        return;
    };
    let agent_call_url = event_sink.join_url("/v1/gateway/agent-calls");
    let agent_tool_url = event_sink.join_url("/v1/gateway/agent-tool-calls");
    let request_id = request_id.to_string();
    let traceparent = traceparent.to_string();

    tokio::spawn(async move {
        let response = match machine_client
            .post(agent_call_url)
            .header("X-Request-Id", request_id.clone())
            .header("traceparent", traceparent.clone())
            .json(&agent_call_payload)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    error = %error,
                    "agent call trace emission failed"
                );
                return;
            }
        };
        if !response.status().is_success() {
            let status = response.status();
            let response_body = response.text().await.unwrap_or_default();
            if is_optional_control_plane_capability_failure(status, &response_body) {
                tracing::debug!(
                    request_id = %request_id,
                    status = %status,
                    "agent call trace emission unavailable; continuing without trace persistence"
                );
            } else {
                tracing::warn!(
                    request_id = %request_id,
                    status = %status,
                    response_body = %response_body,
                    "agent call trace emission returned non-success status"
                );
            }
            return;
        }
        let created = match response.json::<GatewayCreateAgentCallTraceResponse>().await {
            Ok(created) => created,
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    error = %error,
                    "agent call trace emission returned an unreadable body"
                );
                return;
            }
        };
        if pending_tool_payloads.is_empty() {
            return;
        }
        for payload in pending_tool_payloads {
            let body = serialize_pending_agent_tool_call_trace_payload(
                &session_context,
                agent_call_payload.org_id.as_str(),
                created.agent_call_trace_id.as_str(),
                payload,
            );
            match machine_client
                .post(agent_tool_url.clone())
                .header("X-Request-Id", request_id.clone())
                .header("traceparent", traceparent.clone())
                .json(&body)
                .send()
                .await
            {
                Ok(response) if !response.status().is_success() => {
                    let status = response.status();
                    let response_body = response.text().await.unwrap_or_default();
                    tracing::warn!(
                        request_id = %request_id,
                        status = %status,
                        response_body = %response_body,
                        "agent tool call trace emission returned non-success status"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        request_id = %request_id,
                        error = %error,
                        "agent tool call trace emission failed"
                    );
                }
                Ok(_) => {}
            }
        }
    });
}

pub(crate) async fn lookup_agent_tool_chain_match(
    event_sink: Option<&EventSink>,
    session_context: &crate::gateway::session::GatewaySessionContext,
    novelty_request: &crate::gateway::task_novelty::TaskNoveltyRequest,
) -> Option<crate::gateway::work_reuse::AgentToolChainMatch> {
    let sink = event_sink?;
    let org_id = normalize_agent_trace_scalar(session_context._org_id.as_deref())?;
    let git_commit = session_context
        .git_context
        .as_ref()
        .and_then(|context| normalize_agent_trace_scalar(context.commit.as_deref()));
    let request = GatewayAgentToolChainSearchPayload {
        org_id,
        team_id: novelty_request.team_id.clone(),
        agent_id: novelty_request.agent_id.clone(),
        git_repo: novelty_request.git_repo.clone(),
        git_branch: novelty_request.git_branch.clone(),
        git_commit,
        normalized_prompt_hash: novelty_request.normalized_prompt_hash.clone(),
        task_fingerprint_hash: novelty_request.task_fingerprint_hash.clone(),
        error_signature_hashes: novelty_request.error_signature_hashes.clone(),
        file_paths: novelty_request.file_paths.clone(),
        symbols: novelty_request.symbols.clone(),
        tool_names: novelty_request.command_names.clone(),
        limit: 1,
    };
    let client = sink.machine_client().ok()?;
    let response = client
        .post(sink.join_url("/v1/gateway/agent-tool-chains/search"))
        .json(&request)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::warn!(
            status = %status,
            body = %body,
            "agent tool chain search failed"
        );
        return None;
    }
    response
        .json::<GatewayAgentToolChainSearchResponse>()
        .await
        .ok()?
        .matches
        .into_iter()
        .next()
}

pub(crate) fn emit_tool_result_graph_upsert_detached(
    event_sink: Option<EventSink>,
    request_finops: Option<&RequestFinopsContext>,
    session_context: Option<&crate::gateway::session::GatewaySessionContext>,
    request_payload: &serde_json::Value,
    request_id: &str,
    traceparent: &str,
) {
    let Some(event_sink) = event_sink else {
        return;
    };
    let Some(git_context) = session_context.and_then(|context| context.git_context.as_ref()) else {
        tracing::debug!(
            request_id = %request_id,
            traceparent = %traceparent,
            "tool-result graph upsert skipped: no git context"
        );
        return;
    };
    let Some(repo) = git_context
        .repo
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        tracing::debug!(
            request_id = %request_id,
            traceparent = %traceparent,
            "tool-result graph upsert skipped: no git repo"
        );
        return;
    };
    let Some(branch) = git_context
        .branch
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        tracing::debug!(
            request_id = %request_id,
            traceparent = %traceparent,
            "tool-result graph upsert skipped: no git branch"
        );
        return;
    };

    let tool_results = extract_runtime_tool_results(request_payload);
    if tool_results.is_empty() {
        return;
    }

    let captured_at = Utc::now();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut warnings = Vec::new();
    for tool_result in tool_results {
        let payload = graph_populator::prepare_tool_result_upsert_payload(&ToolResultGraphInput {
            repo: Some(repo.to_string()),
            branch: Some(branch.to_string()),
            tool_name: tool_result.tool_name,
            arguments: tool_result.arguments,
            output: tool_result.output,
            captured_at,
        });
        nodes.extend(payload.nodes);
        edges.extend(payload.edges);
        warnings.extend(payload.warnings);
    }

    if nodes.is_empty() && edges.is_empty() {
        return;
    }

    let mut body = match serde_json::to_value(GraphUpsertPayload {
        repo: Some(repo.to_string()),
        branch: Some(branch.to_string()),
        nodes,
        edges,
        warnings,
    }) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                request_id = %request_id,
                traceparent = %traceparent,
                error = %error,
                "tool-result graph upsert serialization failed"
            );
            return;
        }
    };
    let Some(body_object) = body.as_object_mut() else {
        tracing::warn!(
            request_id = %request_id,
            traceparent = %traceparent,
            "tool-result graph upsert skipped: payload was not an object"
        );
        return;
    };
    if let Some(team_id) = request_finops
        .and_then(|finops| finops.team_id.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        body_object.insert(
            "team_id".to_string(),
            serde_json::Value::String(team_id.to_string()),
        );
    }

    let client = event_sink.client().clone();
    let url = event_sink.join_url("/v1/context/graph/upsert");
    let request_id = request_id.to_string();
    let traceparent = traceparent.to_string();

    tokio::spawn(async move {
        match client
            .post(url)
            .header("X-Request-Id", request_id.clone())
            .header("traceparent", traceparent.clone())
            .json(&body)
            .send()
            .await
        {
            Ok(response) if !response.status().is_success() => {
                let status = response.status();
                let response_body = response.text().await.unwrap_or_default();
                if is_optional_control_plane_capability_failure(status, &response_body) {
                    tracing::debug!(
                        request_id = %request_id,
                        status = %status,
                        "tool-result graph upsert unavailable; continuing without graph ingestion"
                    );
                } else {
                    tracing::warn!(
                        request_id = %request_id,
                        status = %status,
                        response_body = %response_body,
                        "tool-result graph upsert returned non-success status"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    error = %error,
                    "tool-result graph upsert request failed"
                );
            }
            Ok(_) => {}
        }
    });
}

pub(crate) fn emit_work_reuse_outcome_event(
    event_sink: Option<&EventSink>,
    request_finops: Option<&RequestFinopsContext>,
    session_context: &crate::gateway::session::GatewaySessionContext,
    request_id: &str,
    traceparent: &str,
    gateway_id: Option<&str>,
    provider_id: Option<&str>,
    model: Option<&str>,
) {
    let Some(event_sink) = event_sink else {
        return;
    };
    let Some(finops) = request_finops else {
        return;
    };
    let Some(novelty_class) = finops
        .novelty_class
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };

    let final_mode = finops
        .work_reuse_mode
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("open_fresh_investigation");
    let requested_mode = finops
        .work_reuse_requested_mode
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(final_mode);
    let matched_receipt_id = finops
        .novelty_receipt_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let tool_names = finops
        .work_reuse_tool_names
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let policy_denied = finops.work_reuse_policy_denied.unwrap_or(false);
    let reuse_applied = finops.work_reuse_reuse_applied.unwrap_or(false);
    let replay_success = finops.work_reuse_replay_success;
    let verdict = if policy_denied
        || (matched_receipt_id.is_some() && replay_success == Some(false) && !reuse_applied)
    {
        "deny"
    } else {
        "allow"
    };
    let reason_code = if policy_denied {
        finops
            .work_reuse_policy_reason_code
            .clone()
            .unwrap_or_else(|| "work_reuse.policy_denied".to_string())
    } else if reuse_applied {
        "work_reuse.applied".to_string()
    } else if matched_receipt_id.is_some() {
        "work_reuse.fallback_open_fresh".to_string()
    } else {
        "work_reuse.no_match".to_string()
    };

    event_sink.enqueue_decision(request_id, serde_json::json!({
            "event_type": "gateway.work_reuse.outcome",
            "request_id": request_id,
            "traceparent": traceparent,
            "verdict": verdict,
            "reason_code": reason_code,
            "config_version": "gateway-runtime",
            "environment": "gateway",
            "agent_id": session_context.agent_id.clone(),
            "session_id": session_context.session_id.clone(),
            "details": {
                "runtime": {
                    "provider": provider_id,
                    "model": model,
                    "gateway_id": gateway_id,
                }
            },
            "metadata": {
                "gateway_id": gateway_id,
                "git_repo": session_context.git_context.as_ref().and_then(|value| value.repo.clone()),
                "git_branch": session_context.git_context.as_ref().and_then(|value| value.branch.clone()),
                "git_commit": session_context.git_context.as_ref().and_then(|value| value.commit.clone()),
                "team_id": session_context.team_id.clone(),
                "provider": provider_id,
                "model": model,
                "novelty_class": novelty_class,
                "matched_receipt_id": matched_receipt_id,
                "requested_mode": requested_mode,
                "final_mode": final_mode,
                "tool_chain_hit": finops.work_reuse_tool_chain_hit.unwrap_or(false),
                "tool_names": tool_names,
                "avoided_model_calls": finops.work_reuse_avoided_model_calls.unwrap_or(0),
                "avoided_tool_executions": finops.work_reuse_avoided_tool_executions.unwrap_or(0),
                "reuse_applied": reuse_applied,
                "replay_success": replay_success,
                "policy_decision": finops.work_reuse_policy_decision.clone(),
                "policy_id": finops.work_reuse_policy_id.clone(),
                "policy_reason_code": finops.work_reuse_policy_reason_code.clone(),
                "policy_denied": policy_denied,
            }
        }),
    );
}

pub(crate) fn emit_history_writeback(
    state: &ActiveGatewayStateView<'_>,
    request_id: &str,
    traceparent: &str,
    session_context: Option<crate::gateway::session::GatewaySessionContext>,
    request_body: &Bytes,
    response_payload: serde_json::Value,
    verdict: &Verdict,
    provider_id: Option<&str>,
    model: Option<&str>,
    latency_ms: Option<i64>,
) {
    let effective_provider_id = provider_id.or_else(|| {
        crate::gateway::provider_catalog::infer_provider_from_base_url(state.upstream_base)
    });
    emit_history_writeback_detached(
        state.event_sink.clone(),
        state.history_service.clone(),
        state.gateway_id.clone(),
        state.request_finops.clone(),
        effective_history_capture_mode(state),
        request_id,
        traceparent,
        session_context,
        request_body,
        response_payload,
        verdict,
        effective_provider_id,
        model,
        latency_ms,
    );
}

pub(crate) fn emit_history_writeback_detached(
    event_sink: Option<EventSink>,
    history_service: Option<Arc<crate::gateway::history::HistoryService>>,
    gateway_id: Option<Arc<str>>,
    request_finops: Option<RequestFinopsContext>,
    capture_mode: Option<String>,
    request_id: &str,
    traceparent: &str,
    session_context: Option<crate::gateway::session::GatewaySessionContext>,
    request_body: &Bytes,
    response_payload: serde_json::Value,
    verdict: &Verdict,
    provider_id: Option<&str>,
    model: Option<&str>,
    latency_ms: Option<i64>,
) {
    let Some(session_context) = session_context else {
        tracing::debug!(
            request_id = %request_id,
            traceparent = %traceparent,
            capture_mode = ?capture_mode,
            "history writeback skipped: no session context"
        );
        return;
    };

    let mut request_payload = serde_json::from_slice::<serde_json::Value>(request_body)
        .unwrap_or_else(|_| serde_json::json!({}));
    let _ = strip_verdictan_request_extension(&mut request_payload);
    emit_agent_trace_bundle_detached(
        event_sink.clone(),
        request_finops.as_ref(),
        Some(&session_context),
        &request_payload,
        &response_payload,
        request_id,
        traceparent,
        provider_id,
        model,
        latency_ms,
    );
    emit_tool_result_graph_upsert_detached(
        event_sink.clone(),
        request_finops.as_ref(),
        Some(&session_context),
        &request_payload,
        request_id,
        traceparent,
    );
    emit_work_reuse_outcome_event(
        event_sink.as_ref(),
        request_finops.as_ref(),
        &session_context,
        request_id,
        traceparent,
        gateway_id.as_deref(),
        provider_id,
        model,
    );

    let capture_mode = capture_mode.unwrap_or_else(|| "metadata_only".to_string());
    if capture_mode == "disabled" {
        return;
    }

    let Some(history_service) = history_service else {
        tracing::warn!(
            request_id = %request_id,
            traceparent = %traceparent,
            capture_mode = ?capture_mode,
            "history writeback skipped: no history service"
        );
        return;
    };

    let decision = match verdict {
        Verdict::Block => "blocked",
        Verdict::Escalate => "escalated",
        _ => "allowed",
    }
    .to_string();

    if decision != "allowed" && !history_service.include_blocked() {
        return;
    }

    let background_requested = request_payload
        .get("background")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let is_streaming_completion = request_payload
        .get("stream")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    // Classify MCP tools/call requests as "tool_call" entries; everything else is "chat".
    let entry_kind = if request_payload
        .get("jsonrpc")
        .and_then(serde_json::Value::as_str)
        == Some("2.0")
        && request_payload
            .get("method")
            .and_then(serde_json::Value::as_str)
            == Some("tools/call")
    {
        "tool_call"
    } else {
        "chat"
    };

    let token_usage = extract_history_token_usage(&response_payload, request_finops.as_ref());
    let request_payload = if capture_mode == "metadata_only" {
        build_metadata_only_history_request(&request_payload, request_id, request_finops.as_ref())
    } else {
        request_payload
    };
    let response_payload = if capture_mode == "metadata_only" {
        build_metadata_only_history_response(&response_payload, request_finops.as_ref())
    } else {
        response_payload
    };
    let response_payload =
        append_history_writeback_metadata(response_payload, latency_ms, background_requested);

    history_service.enqueue_history_entry(
        request_id,
        traceparent,
        session_context.clone(),
        crate::gateway::history::HistoryEntryPayload {
            gateway_id: gateway_id.as_deref().unwrap_or("").to_string(),
            provider_id: provider_id.map(ToOwned::to_owned),
            model: model.map(ToOwned::to_owned),
            decision,
            request_payload,
            response_payload,
            agent_id: session_context.agent_id.clone(),
            token_usage,
            entry_kind: entry_kind.to_string(),
            is_streaming_completion,
        },
    );
}

pub(crate) fn record_successful_token_spend_with_context(
    key_budget_tracker: &Arc<crate::gateway::token_rate_limit::TokenBudgetTracker>,
    request_finops: Option<&RequestFinopsContext>,
    spend_log: &SpendLogPayload,
) {
    let Some(finops) = request_finops else {
        return;
    };
    let Some(key_id) = finops.key_id.as_deref() else {
        return;
    };
    key_budget_tracker.add_spend(
        key_id,
        finops.current_key_spend,
        spend_log.total_cost.max(0.0),
    );
}

pub(crate) fn record_successful_token_spend(
    state: &ActiveGatewayStateView<'_>,
    spend_log: &SpendLogPayload,
) {
    record_successful_token_spend_with_context(
        state.key_budget_tracker,
        state.request_finops.as_ref(),
        spend_log,
    );
}

pub(crate) async fn load_remaining_scope_budget(
    sink: &EventSink,
    finops: Option<&RequestFinopsContext>,
    connected_mode: bool,
) -> Result<Option<f64>, anyhow::Error> {
    // Connected mode no longer probes the unimplemented `/v1/gateway/budgets`
    // machine route. It relies on the validated key headroom already carried in
    // `RequestFinopsContext` plus the supported per-provider machine budget
    // checks performed later in `apply_control_plane_budget_controls`.
    if connected_mode {
        return Ok(None);
    }

    let mut remaining =
        remaining_budget_from_records(&sink.list_budgets("organization", None).await?);

    if let Some(finops) = finops {
        if let Some(key_id) = finops.key_id.as_deref() {
            let records = sink.list_budgets("key", Some(key_id)).await?;
            remaining =
                tighter_remaining_budget(remaining, remaining_budget_from_records(&records));
        }
        if let Some(team_id) = finops.team_id.as_deref() {
            let records = sink.list_budgets("team", Some(team_id)).await?;
            remaining =
                tighter_remaining_budget(remaining, remaining_budget_from_records(&records));
        }
        if let Some(user_id) = finops.user_id.as_deref() {
            let records = sink.list_budgets("user", Some(user_id)).await?;
            remaining =
                tighter_remaining_budget(remaining, remaining_budget_from_records(&records));
        }
    }

    Ok(remaining)
}

pub(crate) async fn provider_has_budget_headroom(
    sink: &EventSink,
    finops: Option<&RequestFinopsContext>,
    connected_mode: bool,
    target: &crate::gateway::providers::ProviderTarget,
    requested_model: Option<&str>,
    prompt_tokens: Option<u32>,
    max_completion_tokens: Option<u32>,
) -> Result<bool, anyhow::Error> {
    let provider = crate::gateway::provider_catalog::normalized_provider_alias(&target.provider);
    let target_model = if target.model.trim().is_empty() {
        requested_model
    } else {
        Some(target.model.as_str())
    };
    let budget = if connected_mode {
        let org_id = finops
            .and_then(|context| context.org_id.as_deref())
            .ok_or_else(|| {
                anyhow::anyhow!("control-plane provider budget lookup missing org_id")
            })?;
        sink.check_control_plane_provider_budget(
            org_id,
            &provider,
            target_model,
            finops.and_then(|context| context.team_id.as_deref()),
            finops.and_then(|context| context.user_id.as_deref()),
            finops.and_then(|context| context.key_id.as_deref()),
        )
        .await?
    } else {
        sink.check_provider_budget(&provider, target_model).await?
    };

    if !budget.allowed {
        return Ok(false);
    }

    let Some(remaining_budget) = budget.remaining_budget else {
        return Ok(true);
    };

    let Some(cost) = crate::gateway::providers::estimate_request_cost(
        target,
        prompt_tokens,
        max_completion_tokens,
    ) else {
        return Ok(true);
    };

    Ok(cost.request <= remaining_budget)
}

pub async fn apply_control_plane_budget_controls(
    request_body: &serde_json::Value,
    registry: &crate::gateway::providers::ProviderRegistry,
    state: &ActiveGatewayStateView<'_>,
    ordered: &[usize],
    request_id: &str,
) -> Result<Vec<usize>, BudgetFilterRejection> {
    let mut effective_ordered = ordered.to_vec();
    let requested_model = request_body
        .get("model")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);

    if let Some(finops) = state.request_finops.as_ref() {
        if !finops.allowed_providers.is_empty() {
            effective_ordered.retain(|&idx| {
                let provider = crate::gateway::provider_catalog::normalized_provider_alias(
                    &registry.targets[idx].provider,
                );
                finops
                    .allowed_providers
                    .iter()
                    .any(|value| value == &provider)
            });
            if effective_ordered.is_empty() {
                return Err(BudgetFilterRejection::access_denied(
                    "The supplied API token is not authorized for the requested provider scope",
                    "tokens.scope_not_allowed",
                ));
            }
        }

        if !finops.allowed_models.is_empty() {
            let model_name = requested_model.as_deref().or_else(|| {
                effective_ordered.first().and_then(|idx| {
                    let model = registry.targets[*idx].model.trim();
                    if model.is_empty() || model == "*" {
                        None
                    } else {
                        Some(model)
                    }
                })
            });
            if !matches!(
                model_name,
                Some(model) if finops
                    .allowed_models
                    .iter()
                    .any(|pattern| crate::policy::evaluator::glob_match(pattern, model))
            ) {
                return Err(BudgetFilterRejection::access_denied(
                    "The supplied API token is not authorized for the requested model scope",
                    "tokens.scope_not_allowed",
                ));
            }
        }
    }

    let prompt_tokens = crate::gateway::token_estimation::estimate_prompt_tokens(request_body)
        .and_then(|value| u32::try_from(value).ok());
    let max_completion_tokens = extract_requested_max_tokens(request_body);

    let mut remaining_budget = state
        .request_finops
        .as_ref()
        .and_then(|finops| finops.remaining_key_budget);
    if let Some(sink) = state.event_sink.as_ref() {
        match load_remaining_scope_budget(sink, state.request_finops.as_ref(), state.connected_mode)
            .await
        {
            Ok(scope_budget) => {
                remaining_budget = tighter_remaining_budget(remaining_budget, scope_budget);
            }
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    error = %error,
                    "scope budget lookup failed; continuing without control-plane scope budget filtering"
                );
            }
        }
    }

    if let Some(remaining_budget) = remaining_budget {
        let filtered = crate::gateway::providers::filter_by_remaining_budget(
            &registry.targets,
            &effective_ordered,
            remaining_budget,
            prompt_tokens,
            max_completion_tokens,
        );
        for &idx in &effective_ordered {
            if !filtered.contains(&idx) && registry.targets[idx].pricing.is_none() {
                tracing::info!(
                    request_id = %request_id,
                    provider = %registry.targets[idx].id,
                    "Provider excluded from budget-filtered routing: \
                     no pricing metadata available. To include this provider, \
                     add pricing via admin model-pricing or contact your platform admin."
                );
            }
        }
        if filtered.is_empty() {
            return Err(BudgetFilterRejection::forbidden(
                "No providers fit within the remaining budget headroom",
                "no_eligible_provider",
            ));
        }
        if filtered.first() != effective_ordered.first() {
            tracing::info!(
                request_id = %request_id,
                remaining_budget,
                previous_provider = ?effective_ordered
                    .first()
                    .map(|idx| registry.targets[*idx].id.as_str()),
                selected_provider = %registry.targets[filtered[0]].id,
                "budget steering demoted the request to an affordable provider"
            );
        }
        effective_ordered = filtered;
    }

    if let Some(sink) = state.event_sink.as_ref() {
        let fail_closed_on_lookup_error = state
            .request_finops
            .as_ref()
            .and_then(RequestFinopsContext::identity_context_json)
            .is_some()
            || state.api_token_present;
        let mut filtered = Vec::with_capacity(effective_ordered.len());
        for idx in &effective_ordered {
            let target = &registry.targets[*idx];
            match provider_has_budget_headroom(
                sink,
                state.request_finops.as_ref(),
                state.connected_mode,
                target,
                requested_model.as_deref(),
                prompt_tokens,
                max_completion_tokens,
            )
            .await
            {
                Ok(true) => filtered.push(*idx),
                Ok(false) => {
                    tracing::info!(
                        request_id = %request_id,
                        provider_id = %target.id,
                        "provider budget filter excluded provider"
                    );
                }
                Err(error) => {
                    if fail_closed_on_lookup_error {
                        tracing::warn!(
                            request_id = %request_id,
                            provider_id = %target.id,
                            error = %error,
                            "provider budget lookup failed for API token traffic; rejecting request"
                        );
                        return Err(BudgetFilterRejection::service_unavailable(
                            "Provider budget validation is temporarily unavailable for API token traffic",
                            "provider_budget_check_unavailable",
                        ));
                    }
                    tracing::warn!(
                        request_id = %request_id,
                        provider_id = %target.id,
                        error = %error,
                        "provider budget lookup failed; keeping provider eligible"
                    );
                    filtered.push(*idx);
                }
            }
        }

        if filtered.is_empty() {
            return Err(BudgetFilterRejection::forbidden(
                "No providers have remaining provider budget headroom",
                "no_eligible_provider",
            ));
        }
        if filtered.first() != effective_ordered.first() {
            tracing::info!(
                request_id = %request_id,
                previous_provider = ?effective_ordered
                    .first()
                    .map(|idx| registry.targets[*idx].id.as_str()),
                selected_provider = %registry.targets[filtered[0]].id,
                "provider budget constraints demoted the request to an eligible provider"
            );
        }
        effective_ordered = filtered;
    }

    Ok(effective_ordered)
}

pub(crate) fn effective_chain_for_request(
    state: &ActiveGatewayStateView<'_>,
    request_resolution: &RequestResolution,
    request_team_slugs: &[String],
) -> Vec<crate::gateway::enforcement::ChainEntry> {
    let raw_chain = if let Some(chain) = request_resolution
        .consumer_group
        .as_ref()
        .and_then(|group| group.chain.clone())
    {
        chain
    } else if let Some(chain) = request_resolution
        .matched_route
        .as_ref()
        .and_then(|route| route.chain.clone())
    {
        chain
    } else {
        state.chain_entries.clone()
    };

    // Filter chain entries by targeting applicability.
    let gateway_id = state.gateway_id.as_deref();
    raw_chain
        .into_iter()
        .filter(|entry| {
            let applicable = entry.is_applicable_for(gateway_id, request_team_slugs);
            if !applicable {
                tracing::debug!(
                    policy = entry.kind(),
                    gateway_id = gateway_id.unwrap_or("<none>"),
                    "policy skipped by targeting selector"
                );
            }
            applicable
        })
        .collect()
}

pub(crate) fn merge_stage_decision(
    decision: &mut enforcement::DecisionEnvelope,
    stage_decision: enforcement::DecisionEnvelope,
) {
    for result in stage_decision.results {
        decision.results.push(result);
    }

    match stage_decision.final_verdict {
        Verdict::Block => {
            decision.final_verdict = Verdict::Block;
            decision.reason_code = stage_decision.reason_code;
        }
        Verdict::Escalate if decision.final_verdict != Verdict::Block => {
            decision.final_verdict = Verdict::Escalate;
            decision.reason_code = stage_decision.reason_code;
        }
        Verdict::Redact if decision.final_verdict == Verdict::Allow => {
            decision.final_verdict = Verdict::Redact;
            decision.reason_code = stage_decision.reason_code;
        }
        _ => {}
    }
}

pub(crate) fn output_messages_for_stage(
    parsed_output: Option<&serde_json::Value>,
    bytes: &Bytes,
) -> Vec<enforcement::ChatMessage> {
    let text = parsed_output
        .and_then(|value| {
            extract_openai_chat_output(value).or_else(|| extract_openai_responses_output(value))
        })
        .unwrap_or_else(|| String::from_utf8_lossy(bytes).to_string());
    if text.trim().is_empty() {
        Vec::new()
    } else {
        vec![enforcement::ChatMessage {
            role: "assistant".to_string(),
            content: text,
        }]
    }
}

pub(crate) fn build_stage_verdict_response(
    decision: &enforcement::DecisionEnvelope,
    config_version: &str,
    request_id: &str,
    traceparent: &str,
    latency_ms: i64,
    redaction_applied: bool,
    response_redactions: &[crate::gateway::redaction::VerdictanRedaction],
    quality_scores: Option<&serde_json::Value>,
) -> Option<Response<Body>> {
    let (status, verdict_label, message) = match decision.final_verdict {
        Verdict::Block => (
            StatusCode::BAD_REQUEST,
            "BLOCK",
            format!("Request blocked by policy: {}", decision.reason_code),
        ),
        Verdict::Escalate => (
            StatusCode::OK,
            "ESCALATE",
            format!("Request escalated by policy: {}", decision.reason_code),
        ),
        _ => return None,
    };

    let verdictan = verdictan_extension_json(
        verdict_label,
        &decision.reason_code,
        config_version,
        request_id,
        latency_ms,
        None,
        None,
    );
    let body = match decision.final_verdict {
        Verdict::Escalate => serde_json::json!({
            "id": format!("chatcmpl-verdictan-{request_id}"),
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": serde_json::Value::Null },
                "finish_reason": "content_filter"
            }],
            "verdictan": verdictan,
        }),
        _ => serde_json::json!({
            "error": error_json(
                &message,
                "invalid_request_error",
                "content_policy_violation",
            ),
            "verdictan": verdictan,
        }),
    };
    let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Some(build_response(
        status,
        HeaderValue::from_static("application/json"),
        request_id.to_string(),
        traceparent.to_string(),
        Bytes::from(text),
        false,
        Some(verdictan_headers(
            verdict_label,
            &decision.reason_code,
            config_version,
            latency_ms,
            redaction_applied,
            response_redactions,
            quality_scores,
            false,
            verdictan_rbac_details(decision),
        )),
    ))
}
