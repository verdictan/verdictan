// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Family request-pipeline module.
//! Child of `gateway::server`; parent private items remain visible.
use super::super::*;
use super::*;

pub(crate) fn build_prompt_redaction_config(
    policy_chain: &[String],
    policy_blocks: &crate::gateway::PolicyBlocks,
) -> crate::gateway::redaction::RedactionConfig {
    let chain_has_hipaa = policy_chain.iter().any(|kind| kind == "hipaa-phi-detector");
    let chain_has_dlp = policy_chain.iter().any(|kind| kind == "dlp-filter");
    let chain_has_student_privacy = policy_chain.iter().any(|kind| kind == "student-privacy");
    let chain_has_case_privacy = policy_chain.iter().any(|kind| kind == "case-privacy");

    let mut redaction_cfg = crate::gateway::redaction::RedactionConfig::from_policy_block(
        policy_blocks.get("pii-detector"),
    );

    if chain_has_hipaa {
        redaction_cfg.healthcare_mode = true;
        redaction_cfg.pci_mode = false;
    }

    if chain_has_dlp {
        if let Some(dlp_cfg) = policy_blocks.get("dlp-filter") {
            let action = dlp_cfg
                .get("action")
                .and_then(|value| value.as_str())
                .unwrap_or("redact");
            if action == "redact" {
                if let Some(patterns) = dlp_cfg
                    .get("detect_patterns")
                    .and_then(|value| value.as_array())
                {
                    for pattern in patterns.iter().filter_map(|value| value.as_str()) {
                        redaction_cfg.detect_patterns.push(pattern.to_string());
                    }
                }
                if let Some(terms) = dlp_cfg
                    .get("blocked_terms")
                    .and_then(|value| value.as_array())
                {
                    for term in terms.iter().filter_map(|value| value.as_str()) {
                        let escaped = regex_escape_literal(term);
                        if !escaped.is_empty() {
                            redaction_cfg.detect_patterns.push(format!("(?i){escaped}"));
                        }
                    }
                }
            }
        }
    }

    if chain_has_student_privacy {
        if let Some(cfg) = policy_blocks.get("student-privacy") {
            let action = cfg
                .get("action")
                .and_then(|value| value.as_str())
                .unwrap_or("redact");
            if action == "redact" {
                redaction_cfg.detect_patterns.push(
                    r"(?i)\bstudent\s*(id|identifier|number)\s*[:#-]?\s*[A-Z0-9-]{4,}\b"
                        .to_string(),
                );
            }
        }
    }

    if chain_has_case_privacy {
        redaction_cfg.detect_patterns.push(
            r"(?i)\b(case|incident|report)\s*(no\.?|number|#)\s*[:\-]?\s*[A-Z0-9][A-Z0-9\-]{3,}\b"
                .to_string(),
        );
    }

    redaction_cfg
}

pub(crate) fn extract_messages_for_responses(
    value: Option<&serde_json::Value>,
) -> Vec<ChatMessage> {
    let Some(value) = value else {
        return Vec::new();
    };

    crate::gateway::content_extraction::extract_responses_messages(value)
        .into_iter()
        .map(|message| ChatMessage {
            role: message.role,
            content: message.content,
        })
        .collect()
}

pub(crate) fn redact_responses_input(
    value: &mut serde_json::Value,
    cfg: &crate::gateway::redaction::RedactionConfig,
) -> bool {
    crate::gateway::content_extraction::rewrite_request_text_segments_for_path(
        "/v1/responses",
        value,
        |segment| {
            let redacted = crate::gateway::redaction::redact_text_with_config(&segment.text, cfg);
            (redacted != segment.text).then_some(redacted)
        },
    )
}

pub(crate) fn verdictan_rbac_details(decision: &DecisionEnvelope) -> Option<&serde_json::Value> {
    decision
        .results
        .iter()
        .find(|r| r.policy_kind == "rbac")
        .and_then(|r| r.details.as_ref())
}

pub(crate) fn append_cache_status_header(
    headers: &mut Vec<(axum::http::HeaderName, HeaderValue)>,
    is_cached: bool,
) {
    headers.retain(|(name, _)| name.as_str() != "x-cache-status");
    headers.push((
        axum::http::HeaderName::from_static("x-cache-status"),
        HeaderValue::from_static(if is_cached { "hit" } else { "miss" }),
    ));
}

pub fn verdictan_headers(
    verdict: &str,
    reason_code: &str,
    config_version: &str,
    latency_ms: i64,
    prompt_redacted: bool,
    response_redactions: &[crate::gateway::redaction::VerdictanRedaction],
    quality_scores: Option<&serde_json::Value>,
    degraded: bool,
    rbac_details: Option<&serde_json::Value>,
) -> Vec<(axum::http::HeaderName, HeaderValue)> {
    let mut headers: Vec<(axum::http::HeaderName, HeaderValue)> = Vec::new();

    headers.push((
        axum::http::HeaderName::from_static("x-verdictan-verdict"),
        HeaderValue::from_str(verdict).unwrap_or_else(|_| HeaderValue::from_static("ALLOW")),
    ));
    headers.push((
        axum::http::HeaderName::from_static("x-verdictan-reason-code"),
        HeaderValue::from_str(reason_code).unwrap_or_else(|_| HeaderValue::from_static("ok")),
    ));
    headers.push((
        axum::http::HeaderName::from_static("x-verdictan-config-version"),
        HeaderValue::from_str(config_version).unwrap_or_else(|_| HeaderValue::from_static("0.0.0")),
    ));
    headers.push((
        axum::http::HeaderName::from_static("x-verdictan-latency-ms"),
        HeaderValue::from_str(&latency_ms.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    ));
    headers.push((
        axum::http::HeaderName::from_static("x-verdictan-prompt-redacted"),
        HeaderValue::from_static(if prompt_redacted { "true" } else { "false" }),
    ));

    if degraded {
        headers.push((
            axum::http::HeaderName::from_static("x-verdictan-degraded"),
            HeaderValue::from_static("true"),
        ));
    }

    if !response_redactions.is_empty() {
        headers.push((
            axum::http::HeaderName::from_static("x-verdictan-response-redacted"),
            HeaderValue::from_static("true"),
        ));
        headers.push((
            axum::http::HeaderName::from_static("x-verdictan-redaction-count"),
            HeaderValue::from_str(&response_redactions.len().to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("0")),
        ));

        let mut kinds: Vec<String> = response_redactions.iter().map(|r| r.kind.clone()).collect();
        kinds.sort();
        kinds.dedup();
        let kinds_joined = kinds.join(",");
        if let Ok(v) = HeaderValue::from_str(&kinds_joined) {
            headers.push((
                axum::http::HeaderName::from_static("x-verdictan-redacted-entities"),
                v,
            ));
        }
    } else {
        headers.push((
            axum::http::HeaderName::from_static("x-verdictan-response-redacted"),
            HeaderValue::from_static("false"),
        ));
    }

    if let Some(q) = quality_scores {
        // Keep headers compact and stable.
        if let Some(aggregate) = q
            .get("aggregate")
            .and_then(|v| v.as_f64())
            .map(crate::gateway::quality::scale_public_quality_percent)
            .map(|x| {
                let mut text = format!("{x:.2}");
                while text.ends_with('0') {
                    text.pop();
                }
                if text.ends_with('.') {
                    text.pop();
                }
                format!("{text}%")
            })
        {
            if let Ok(v) = HeaderValue::from_str(&aggregate) {
                headers.push((
                    axum::http::HeaderName::from_static("x-verdictan-quality-aggregate"),
                    v,
                ));
            }
        }
    }

    if let Some(rbac) = rbac_details {
        if let Some(missing) = rbac.get("missing_headers").and_then(|v| v.as_array()) {
            let names: Vec<String> = missing
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect();
            let joined = names.join(",");
            if let Ok(v) = HeaderValue::from_str(&joined) {
                headers.push((
                    axum::http::HeaderName::from_static("x-verdictan-rbac-missing"),
                    v,
                ));
            }
        }
    }

    headers
}

pub(crate) fn extract_messages_from_value(value: Option<&serde_json::Value>) -> Vec<ChatMessage> {
    let Some(value) = value else {
        return Vec::new();
    };

    crate::gateway::content_extraction::extract_request_messages(value)
        .into_iter()
        .map(|message| ChatMessage {
            role: message.role,
            content: message.content,
        })
        .collect()
}

pub(crate) fn redact_request_messages(
    value: &mut serde_json::Value,
    cfg: &crate::gateway::redaction::RedactionConfig,
) -> bool {
    crate::gateway::content_extraction::rewrite_request_text_segments_for_path(
        "/v1/chat/completions",
        value,
        |segment| {
            let redacted = crate::gateway::redaction::redact_text_with_config(&segment.text, cfg);
            (redacted != segment.text).then_some(redacted)
        },
    )
}

pub fn decision_event_json(
    config_version: &str,
    request_id: &str,
    decision: &DecisionEnvelope,
    degraded_mode: bool,
    prompt_redacted: bool,
    prompt_hash: String,
    quality: Option<serde_json::Value>,
    agent_id: Option<&str>,
    finops: Option<&RequestFinopsContext>,
    session_id: Option<&str>,
) -> serde_json::Value {
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let control_plane_request_id = request_id::control_plane_request_id(request_id);

    let policy_results: Vec<serde_json::Value> = decision
        .results
        .iter()
        .map(|r| {
            let mut v = serde_json::json!({
                "policy_kind": r.policy_kind,
                "phase": r.phase,
                "verdict": r.verdict.to_string(),
                "reason_code": r.reason_code,
                "latency_ms": 0
            });
            if let Some(details) = &r.details {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("details".to_string(), details.clone());
                }
            }
            if let Some(targets) = &r.redaction_targets {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("redaction_targets".to_string(), serde_json::json!(targets));
                }
            }
            v
        })
        .collect();

    let mut details = serde_json::json!({
        "degraded_mode": degraded_mode,
        "policy_results": policy_results,
    });
    if let Some(q) = quality {
        if let Some(obj) = details.as_object_mut() {
            obj.insert("scores".to_string(), q);
        }
    }

    serde_json::json!({
        "event_id": decision_event_id(&control_plane_request_id),
        "event_type": "decision",
        "request_id": control_plane_request_id,
        "timestamp": timestamp,
        "verdict": decision.final_verdict.to_string(),
        "reason_code": decision.reason_code,
        "config_version": config_version,
        "details": details,
        "prompt_redacted": prompt_redacted,
        "prompt_hash": prompt_hash,
        "agent_id": agent_id,
        "identity_proof_method": finops
            .filter(|context| context.has_token_identity())
            .map(|_| crate::gateway::identity::IdentityProofMethod::ApiToken.as_str())
            .unwrap_or(crate::gateway::identity::IdentityProofMethod::HeaderSoft.as_str()),
        "identity_context": finops.and_then(RequestFinopsContext::identity_context_json),
        "context_selection": finops.and_then(RequestFinopsContext::context_selection_json),
        "session_id": session_id,
    })
}

pub(crate) fn inject_review_result_into_event(
    event: &mut serde_json::Value,
    review_result: &serde_json::Value,
) {
    let Some(root) = event.as_object_mut() else {
        return;
    };

    let details = root
        .entry("details".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if let Some(details_obj) = details.as_object_mut() {
        details_obj.insert("review_result".to_string(), review_result.clone());
    }
}

pub(crate) fn inject_review_result_into_payload(
    payload: &mut serde_json::Value,
    review_result: &serde_json::Value,
) {
    let Some(root) = payload.as_object_mut() else {
        return;
    };

    root.insert("review_result".to_string(), review_result.clone());
    if let Some(verdictan) = root
        .get_mut("verdictan")
        .and_then(|value| value.as_object_mut())
    {
        verdictan.insert("review_result".to_string(), review_result.clone());
    }
}

pub(crate) fn flagged_review_effective_verdict(
    execution: &crate::gateway::quality::FlaggedReviewExecution,
) -> Verdict {
    if execution.mode == "audit_only" {
        return Verdict::Allow;
    }

    match execution.verdict.as_str() {
        "block" => Verdict::Block,
        "escalate" => Verdict::Escalate,
        _ => Verdict::Allow,
    }
}

pub(crate) async fn execute_inline_flagged_review(
    state: &ActiveGatewayStateView<'_>,
    request_id: &str,
    traceparent: &str,
    request_json: &serde_json::Value,
    conversation_id: Option<&str>,
    history_session_id: Option<&str>,
    parsed_out: &mut Option<serde_json::Value>,
    out_bytes: &mut Bytes,
    decision: &mut DecisionEnvelope,
    primary_provider: Option<&str>,
) -> Option<serde_json::Value> {
    let policy_cfg = state.policy_blocks.get("flagged-review")?;
    let agent_id = match state.registered_agent_id() {
        Some(agent_id) if !agent_id.trim().is_empty() => agent_id,
        _ => {
            tracing::warn!(request_id, "flagged-review skipped: no resolved agent_id");
            return None;
        }
    };

    if parsed_out.is_none() {
        *parsed_out = serde_json::from_slice::<serde_json::Value>(out_bytes).ok();
    }
    let output_text = parsed_out
        .as_ref()
        .map(extract_openai_output_text_from_json)
        .unwrap_or_default();
    if output_text.trim().is_empty() {
        return None;
    }

    let request_text = extract_messages_from_value(Some(request_json))
        .into_iter()
        .map(|message| message.content)
        .collect::<Vec<_>>()
        .join("\n");

    let execution = crate::gateway::quality::execute_flagged_review(
        request_json,
        &request_text,
        &output_text,
        &decision.reason_code,
        primary_provider,
        Some(state.upstream_base),
        Some(policy_cfg),
    )
    .await?;

    let persisted = match state.event_sink.as_ref() {
        Some(sink) => match sink
            .create_agent_review_execution(
                request_id,
                traceparent,
                agent_id,
                &execution.api_request_json(
                    conversation_id,
                    history_session_id,
                    &decision_event_id(request_id),
                ),
            )
            .await
        {
            Ok(payload) => Some(payload),
            Err(error) => {
                tracing::warn!(
                    request_id,
                    agent_id,
                    error = %error,
                    "flagged-review persistence failed"
                );
                None
            }
        },
        None => None,
    };

    let review_execution_id = persisted
        .as_ref()
        .and_then(|payload| payload.get("id"))
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let review_result = execution.review_result_json(&review_execution_id, agent_id);
    let effective_verdict = flagged_review_effective_verdict(&execution);
    decision.results.push(enforcement::PolicyResult {
        policy_kind: "flagged-review".to_string(),
        phase: "output".to_string(),
        verdict: effective_verdict.clone(),
        reason_code: execution.reason_code.clone(),
        details: Some(serde_json::json!({ "review_result": review_result.clone() })),
        redaction_targets: None,
    });

    if execution.mode == "review_and_return"
        && matches!(execution.verdict.as_str(), "allow" | "warn")
    {
        if let Some(reviewed_response) = execution.reviewed_response.as_deref() {
            if let Some(value) = parsed_out.as_mut() {
                if replace_openai_chat_output_in_place(value, reviewed_response)
                    || replace_openai_responses_output_in_place(value, reviewed_response)
                {
                    inject_review_result_into_payload(value, &review_result);
                    if let Ok(serialized) = serde_json::to_vec(value) {
                        *out_bytes = Bytes::from(serialized);
                    }
                }
            }
            decision.final_verdict = Verdict::Allow;
            decision.reason_code = "ok".to_string();
            return Some(review_result);
        }
    }

    if let Some(value) = parsed_out.as_mut() {
        inject_review_result_into_payload(value, &review_result);
        if let Ok(serialized) = serde_json::to_vec(value) {
            *out_bytes = Bytes::from(serialized);
        }
    }

    match effective_verdict {
        Verdict::Block | Verdict::Escalate => {
            decision.final_verdict = effective_verdict;
            decision.reason_code = execution.reason_code;
        }
        Verdict::Allow | Verdict::Redact => {}
    }

    Some(review_result)
}

pub fn decision_event_id(request_id: &str) -> String {
    format!("vdt_decision_{request_id}")
}

pub(crate) fn error_json(message: &str, error_type: &str, code: &str) -> serde_json::Value {
    serde_json::json!({
        "message": message,
        "type": error_type,
        "param": serde_json::Value::Null,
        "code": code,
    })
}

pub(crate) fn format_upstream_unreachable_message(
    provider_name: &str,
    url: &str,
    error: &dyn std::fmt::Display,
) -> String {
    let status_url = crate::gateway::provider_catalog::provider_status_page_url(provider_name);
    format!(
        "Provider '{provider_name}' at '{url}' is unreachable (error: {error}). \
         Check: 1) Provider URL is correct in your configuration, \
         2) Network/firewall allows outbound to the provider, \
         3) Provider API key is valid and not expired, \
         4) Provider service status at {status_url}"
    )
}

/// Centralised rate-limit header builder. Returns the standard `x-ratelimit-*`
/// header names used by all major LLM providers and SDKs.
pub(crate) fn ratelimit_headers(
    limit_requests: u64,
    remaining_requests: u64,
    retry_after_secs: u64,
    limit_tokens: Option<u64>,
    remaining_tokens: Option<u64>,
) -> Vec<(&'static str, String)> {
    let mut hdrs = vec![
        ("x-ratelimit-limit-requests", limit_requests.to_string()),
        (
            "x-ratelimit-remaining-requests",
            remaining_requests.to_string(),
        ),
        ("Retry-After", retry_after_secs.to_string()),
    ];
    if let Some(lt) = limit_tokens {
        hdrs.push(("x-ratelimit-limit-tokens", lt.to_string()));
    }
    if let Some(rt) = remaining_tokens {
        hdrs.push(("x-ratelimit-remaining-tokens", rt.to_string()));
    }
    hdrs
}

pub(crate) fn extract_openai_chat_output(v: &serde_json::Value) -> Option<String> {
    let choices = v.get("choices")?.as_array()?;
    let mut parts = Vec::new();
    for c in choices {
        if let Some(s) = c
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|x| x.as_str())
        {
            if !s.trim().is_empty() {
                parts.push(s);
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

pub(crate) fn extract_openai_responses_output(v: &serde_json::Value) -> Option<String> {
    if let Some(text) = v.get("output").and_then(|value| value.as_str()) {
        if !text.trim().is_empty() {
            return Some(text.to_string());
        }
    }

    let outputs = v.get("output")?.as_array()?;
    let mut parts = Vec::new();
    for out in outputs {
        let content = match out.get("content").and_then(|x| x.as_array()) {
            Some(c) => c,
            None => continue,
        };
        for item in content {
            let typ = item.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if typ != "output_text" {
                continue;
            }
            if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                if !text.trim().is_empty() {
                    parts.push(text);
                }
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

pub(crate) fn regex_escape_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out.trim().to_string()
}

pub(crate) fn verdictan_redactions_json(
    items: &[crate::gateway::redaction::VerdictanRedaction],
) -> serde_json::Value {
    use std::collections::BTreeMap;

    let applied = !items.is_empty();
    let mut entity_types: Vec<String> = items.iter().map(|r| r.kind.clone()).collect();
    entity_types.sort();
    entity_types.dedup();

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for r in items {
        *counts.entry(r.kind.clone()).or_insert(0) += 1;
    }

    serde_json::json!({
        "applied": applied,
        "entities": entity_types,
        "count_by_type": counts,
        "items": items,
    })
}

pub(crate) fn verdictan_extension_json(
    verdict: &str,
    reason_code: &str,
    config_version: &str,
    request_id: &str,
    latency_ms: i64,
    escalation: Option<serde_json::Value>,
    redactions: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut verdictan = serde_json::json!({
        "decision": {
            "verdict": verdict,
            "reason_code": reason_code,
            "config_version": config_version,
            "request_id": request_id,
            "latency_ms": latency_ms,
        }
    });

    if let Some(escalation) = escalation {
        if let Some(obj) = verdictan.as_object_mut() {
            obj.insert("escalation".to_string(), escalation);
        }
    }

    if let Some(redactions) = redactions {
        if let Some(obj) = verdictan.as_object_mut() {
            obj.insert("redactions".to_string(), redactions);
        }
    }
    verdictan
}

pub(crate) fn redact_openai_response_body(
    upstream_response_bytes: &[u8],
    cfg: &crate::gateway::redaction::RedactionConfig,
) -> Result<
    (
        Bytes,
        Vec<crate::gateway::redaction::VerdictanRedaction>,
        Vec<crate::gateway::enforcement::RedactionTarget>,
    ),
    anyhow::Error,
> {
    let mut v: serde_json::Value = serde_json::from_slice(upstream_response_bytes)?;

    let Some(choices) = v.get_mut("choices").and_then(|x| x.as_array_mut()) else {
        return Ok((
            Bytes::from(upstream_response_bytes.to_vec()),
            Vec::new(),
            Vec::new(),
        ));
    };

    let mut all_redactions = Vec::new();
    let mut all_targets = Vec::new();
    for choice in choices {
        let choice_idx = choice.get("index").and_then(|v| v.as_i64()).unwrap_or(0);
        let Some(msg) = choice.get_mut("message") else {
            continue;
        };
        let Some(content) = msg.get_mut("content") else {
            continue;
        };
        let Some(s) = content.as_str() else {
            continue;
        };

        let loc = format!("choices[{choice_idx}].message.content");
        let (redacted, redactions, targets) =
            crate::gateway::redaction::redact_with_metadata_and_targets_with_config(s, cfg, &loc);
        if redacted != s {
            *content = serde_json::Value::String(redacted);
            all_redactions.extend(redactions);
            all_targets.extend(targets);
        }
    }

    let out = serde_json::to_vec(&v)?;
    Ok((Bytes::from(out), all_redactions, all_targets))
}

pub(crate) fn redact_openai_responses_body(
    upstream_response_bytes: &[u8],
    cfg: &crate::gateway::redaction::RedactionConfig,
) -> Result<
    (
        Bytes,
        Vec<crate::gateway::redaction::VerdictanRedaction>,
        Vec<crate::gateway::enforcement::RedactionTarget>,
    ),
    anyhow::Error,
> {
    let mut v: serde_json::Value = serde_json::from_slice(upstream_response_bytes)?;

    let Some(outputs) = v.get_mut("output").and_then(|x| x.as_array_mut()) else {
        return Ok((
            Bytes::from(upstream_response_bytes.to_vec()),
            Vec::new(),
            Vec::new(),
        ));
    };

    let mut all_redactions = Vec::new();
    let mut all_targets = Vec::new();
    for out in outputs {
        let out_idx = out.get("index").and_then(|v| v.as_i64()).unwrap_or(0);
        let Some(content_arr) = out.get_mut("content").and_then(|x| x.as_array_mut()) else {
            continue;
        };

        for (content_idx, item) in content_arr.iter_mut().enumerate() {
            let typ = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if typ != "output_text" {
                continue;
            }

            let Some(text) = item.get_mut("text") else {
                continue;
            };
            let Some(s) = text.as_str() else {
                continue;
            };

            let loc = format!("output[{out_idx}].content[{content_idx}].text");
            let (redacted, redactions, targets) =
                crate::gateway::redaction::redact_with_metadata_and_targets_with_config(
                    s, cfg, &loc,
                );
            if redacted != s {
                *text = serde_json::Value::String(redacted);
                all_redactions.extend(redactions);
                all_targets.extend(targets);
            }
        }
    }

    let out = serde_json::to_vec(&v)?;
    Ok((Bytes::from(out), all_redactions, all_targets))
}

pub(crate) fn replace_openai_chat_output_in_place(
    v: &mut serde_json::Value,
    fallback: &str,
) -> bool {
    let Some(choices) = v.get_mut("choices").and_then(|x| x.as_array_mut()) else {
        return false;
    };

    let mut changed = false;
    for choice in choices {
        let Some(msg) = choice.get_mut("message") else {
            continue;
        };
        let Some(content) = msg.get_mut("content") else {
            continue;
        };

        if content.is_string() {
            *content = serde_json::Value::String(fallback.to_string());
            changed = true;
        }
    }
    changed
}

pub(crate) fn replace_openai_responses_output_in_place(
    v: &mut serde_json::Value,
    fallback: &str,
) -> bool {
    let Some(outputs) = v.get_mut("output").and_then(|x| x.as_array_mut()) else {
        return false;
    };

    let mut changed = false;
    for out in outputs {
        let Some(content_arr) = out.get_mut("content").and_then(|x| x.as_array_mut()) else {
            continue;
        };

        for item in content_arr.iter_mut() {
            let typ = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if typ != "output_text" {
                continue;
            }

            let Some(text) = item.get_mut("text") else {
                continue;
            };
            if text.is_string() {
                *text = serde_json::Value::String(fallback.to_string());
                changed = true;
            }
        }
    }

    changed
}

pub(crate) fn extract_openai_output_text_from_json(v: &serde_json::Value) -> String {
    if let Some(choices) = v.get("choices").and_then(|x| x.as_array()) {
        let mut parts = Vec::new();
        for choice in choices {
            if let Some(content) = choice
                .get("message")
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_str())
            {
                parts.push(content);
            }
        }
        return parts.join("\n");
    }

    if let Some(output) = v.get("output").and_then(|value| value.as_str()) {
        return output.to_string();
    }

    if let Some(outputs) = v.get("output").and_then(|x| x.as_array()) {
        let mut parts = Vec::new();
        for out in outputs {
            let Some(content_arr) = out.get("content").and_then(|x| x.as_array()) else {
                continue;
            };
            for item in content_arr {
                let typ = item.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if typ != "output_text" {
                    continue;
                }
                if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                    parts.push(text);
                }
            }
        }
        return parts.join("\n");
    }

    String::new()
}

pub(crate) fn prepend_openai_output_in_place(v: &mut serde_json::Value, prefix: &str) -> bool {
    if let Some(choices) = v.get_mut("choices").and_then(|x| x.as_array_mut()) {
        let mut changed = false;
        for choice in choices {
            let Some(msg) = choice.get_mut("message") else {
                continue;
            };
            let Some(content) = msg.get_mut("content") else {
                continue;
            };
            if let Some(s) = content.as_str() {
                *content = serde_json::Value::String(format!("{}{}", prefix, s));
                changed = true;
            }
        }
        return changed;
    }

    if let Some(outputs) = v.get_mut("output").and_then(|x| x.as_array_mut()) {
        let mut changed = false;
        for out in outputs {
            let Some(content_arr) = out.get_mut("content").and_then(|x| x.as_array_mut()) else {
                continue;
            };
            for item in content_arr.iter_mut() {
                let typ = item.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if typ != "output_text" {
                    continue;
                }
                let Some(text) = item.get_mut("text") else {
                    continue;
                };
                if let Some(s) = text.as_str() {
                    *text = serde_json::Value::String(format!("{}{}", prefix, s));
                    changed = true;
                }
            }
        }
        return changed;
    }

    false
}

pub(crate) fn verdictan_verdict_for_success(v: &Verdict) -> &'static str {
    match v {
        Verdict::Allow => "ALLOW",
        Verdict::Redact => "REDACT",
        Verdict::Block => "BLOCK",
        Verdict::Escalate => "ESCALATE",
    }
}

pub(crate) fn inject_verdictan_response_extension(
    mut body: Bytes,
    verdictan: serde_json::Value,
) -> Bytes {
    let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return body;
    };
    let Some(obj) = v.as_object_mut() else {
        return body;
    };
    obj.insert("verdictan".to_string(), verdictan);
    if let Ok(out) = serde_json::to_vec(&v) {
        body = Bytes::from(out);
    }
    body
}

pub(crate) fn strip_verdictan_request_extension(v: &mut serde_json::Value) -> bool {
    let Some(obj) = v.as_object_mut() else {
        return false;
    };
    obj.remove("verdictan").is_some()
}

pub fn filter_quality_scores_for_event(scores: &serde_json::Value) -> serde_json::Value {
    let mut map = serde_json::Map::new();

    // Output statistics — always include (may be 0 / null).
    for key in [
        "output_chars",
        "sentence_count",
        "min_output_chars",
        "min_sentences",
    ] {
        map.insert(
            key.to_string(),
            scores.get(key).cloned().unwrap_or(serde_json::Value::Null),
        );
    }

    // Quality metric scores — only include when the value is non-null so the
    // API payload stays clean and the frontend can distinguish "not computed"
    // from "computed zero".
    let metrics = scores.get("metrics");
    let get_metric = |key: &str| {
        metrics
            .and_then(|m| m.get(key))
            .filter(|v| !v.is_null())
            .cloned()
    };

    if let Some(v) = get_metric("aggregate") {
        map.insert("aggregate".to_string(), v);
    }
    if let Some(v) = get_metric("faithfulness") {
        map.insert("faithfulness".to_string(), v);
    }
    if let Some(v) = get_metric("relevancy") {
        map.insert("relevancy".to_string(), v);
    }
    if let Some(v) = get_metric("coherence") {
        map.insert("coherence".to_string(), v);
    }
    if let Some(v) = get_metric("completeness") {
        map.insert("completeness".to_string(), v);
    }
    // nli_entailment is the CLI-internal name; the API + frontend call it "accuracy".
    if let Some(v) = get_metric("nli_entailment") {
        map.insert("accuracy".to_string(), v);
    }

    // Phase 6: forward judge metadata when present so the API event record can
    // surface scorer identity and rationale in the console.
    if let Some(judge) = scores.get("judge").filter(|v| !v.is_null()) {
        map.insert("judge".to_string(), judge.clone());
    }

    serde_json::Value::Object(map)
}

pub(crate) async fn emit_cached_provider_trace(
    request_id: &str,
    traceparent: &str,
    path: &str,
    provider: &str,
    upstream_base: &str,
    model: Option<&str>,
    request_body: &Bytes,
    response: &crate::gateway::cache::BufferedUpstreamResponse,
    correlation: &TraceCorrelation,
    request_telemetry_hints: &RequestTelemetryHints,
    capture_payloads: bool,
) {
    let span = tracing::info_span!(
        "provider_evaluation",
        request_id = %request_id,
        traceparent = %traceparent,
        path = %path,
        provider = %provider,
        attempt = 1,
        concurrency_limit = 0,
        max_concurrency = 0,
        cache_hit = true,
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
        provider,
        path,
        upstream_base,
        model,
    );
    let telemetry_verdictan = telemetry_verdictan_metadata(request_telemetry_hints);
    crate::telemetry::annotate_provider_request_attributes(
        &span,
        provider,
        path,
        request_body,
        true,
        telemetry_verdictan.as_ref(),
        capture_payloads,
    );
    annotate_trace_correlation_span(&span, correlation);
    crate::telemetry::annotate_provider_response_attributes(
        &span,
        response.status(),
        response.body(),
        true,
        capture_payloads,
    );

    async {}.instrument(span).await;
}

pub fn enrich_decision_event_details(
    event: &mut serde_json::Value,
    request_payload: Option<serde_json::Value>,
    response_payload: Option<serde_json::Value>,
    request_method: &str,
    response_status: StatusCode,
    runtime: serde_json::Value,
    correlation: &TraceCorrelation,
) {
    let Some(details) = event
        .get_mut("details")
        .and_then(|value| value.as_object_mut())
    else {
        return;
    };

    details.insert(
        "request_method".to_string(),
        serde_json::Value::String(request_method.to_string()),
    );
    details.insert(
        "response_status".to_string(),
        serde_json::Value::Number(serde_json::Number::from(u64::from(
            response_status.as_u16(),
        ))),
    );
    // Merge runtime fields into any existing runtime object so streaming
    // enrichment preserves the gateway_id / provider / config fields that
    // decision_runtime_json wrote earlier.
    if let Some(existing_runtime) = details
        .get_mut("runtime")
        .and_then(|value| value.as_object_mut())
    {
        if let Some(new_fields) = runtime.as_object() {
            for (key, value) in new_fields {
                existing_runtime.insert(key.clone(), value.clone());
            }
        }
    } else {
        details.insert("runtime".to_string(), runtime);
    }

    if let Some(correlation) = correlation.as_event_json() {
        details.insert("correlation".to_string(), correlation);
    }

    if let Some(request_payload) = request_payload {
        details.insert("request".to_string(), request_payload);
    }

    if let Some(response_payload) = response_payload {
        details.insert("response".to_string(), response_payload);
    }
}

pub fn annotate_streaming_decision_event_metadata(
    event: &mut serde_json::Value,
    streaming_mode: &str,
    streaming_redaction_buffered: bool,
    interrupted: bool,
    output_chars: usize,
    finish_reason: Option<&str>,
    latency_ms: i64,
    chunks_forwarded: usize,
    buffered: bool,
) {
    let Some(event_obj) = event.as_object_mut() else {
        return;
    };

    let metadata = event_obj
        .entry("metadata".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let Some(metadata_obj) = metadata.as_object_mut() else {
        return;
    };

    metadata_obj.insert("streaming".to_string(), serde_json::json!(true));
    metadata_obj.insert(
        "streaming_mode".to_string(),
        serde_json::json!(streaming_mode),
    );
    metadata_obj.insert(
        "streaming_redaction_buffered".to_string(),
        serde_json::json!(streaming_redaction_buffered),
    );
    metadata_obj.insert(
        "streaming_interrupted".to_string(),
        serde_json::json!(interrupted),
    );
    metadata_obj.insert(
        "streaming_summary".to_string(),
        serde_json::json!({
            "mode": streaming_mode,
            "output_chars": output_chars,
            "finish_reason": finish_reason,
            "latency_ms": latency_ms,
            "chunks_forwarded": chunks_forwarded,
            "buffered": buffered,
            "interrupted": interrupted,
        }),
    );
}

/// Phase 9: redact message bodies from a decision event payload in-place.
/// Replaces `details.request.messages[].content` and `details.response.choices[].message.content`
/// with `"[REDACTED]"`.
pub fn redact_event_message_bodies(event: &mut serde_json::Value) {
    let Some(details) = event.get_mut("details").and_then(|v| v.as_object_mut()) else {
        return;
    };
    // Redact request messages.
    if let Some(messages) = details
        .get_mut("request")
        .and_then(|r| r.get_mut("messages"))
        .and_then(|m| m.as_array_mut())
    {
        for msg in messages.iter_mut() {
            if let Some(content) = msg.get_mut("content") {
                *content = serde_json::Value::String("[REDACTED]".to_string());
            }
        }
    }
    // Redact response choices.
    if let Some(choices) = details
        .get_mut("response")
        .and_then(|r| r.get_mut("choices"))
        .and_then(|c| c.as_array_mut())
    {
        for choice in choices.iter_mut() {
            if let Some(content) = choice.get_mut("message").and_then(|m| m.get_mut("content")) {
                *content = serde_json::Value::String("[REDACTED]".to_string());
            }
            // Also redact streaming delta content if present.
            if let Some(content) = choice.get_mut("delta").and_then(|d| d.get_mut("content")) {
                *content = serde_json::Value::String("[REDACTED]".to_string());
            }
        }
    }
    // Redact single input string (Responses API).
    if let Some(input) = details.get_mut("request").and_then(|r| r.get_mut("input")) {
        if input.is_string() {
            *input = serde_json::Value::String("[REDACTED]".to_string());
        }
    }
}

pub(crate) fn silent_engine_event_payloads(
    state: &ActiveGatewayStateView<'_>,
    request_payload: Option<serde_json::Value>,
    response_payload: Option<serde_json::Value>,
) -> (Option<serde_json::Value>, Option<serde_json::Value>) {
    if silent_engine(state).payload_logging_disabled() {
        (None, None)
    } else {
        (request_payload, response_payload)
    }
}

pub(crate) fn apply_silent_engine_event_sanitization(
    state: &ActiveGatewayStateView<'_>,
    event: &mut serde_json::Value,
) {
    let engine = silent_engine(state);

    if engine.citation_writeback_disabled() {
        if let Some(root) = event.as_object_mut() {
            root.remove("citations");
            root.remove("citation_results");
        }
    }

    if !engine.privacy_enforcement_only() {
        return;
    }

    let Some(root) = event.as_object_mut() else {
        return;
    };
    root.remove("identity_context");
    root.remove("session_id");
    root.remove("context_selection");
    if let Some(details) = root
        .get_mut("details")
        .and_then(|value| value.as_object_mut())
    {
        details.remove("request");
        details.remove("response");
    }
}

pub fn decision_runtime_json(
    state: &ActiveGatewayStateView<'_>,
    path: &str,
    cache_hit: bool,
) -> serde_json::Value {
    let snapshot = state.rate_limiter.snapshot();
    let resolved_target = state.current_target_id.as_deref().and_then(|target_id| {
        state
            .provider_registry
            .as_ref()
            .and_then(|registry| registry.find_target_by_id(target_id))
    });
    let route_provider = runtime_route_provider_alias(resolved_target, Some(&snapshot.provider));
    let resolved_provider = runtime_resolved_provider(
        resolved_target,
        state.upstream_base,
        resolved_target.and_then(resolve_target_model_name),
    );
    serde_json::json!({
        "cache_hit": cache_hit,
        "gateway_id": spend_gateway_reference(state.gateway_id.as_ref(), state.connected_mode),
        "provider": route_provider,
        "resolved_provider": resolved_provider,
        "upstream_base_url": resolved_target
            .map(|target| target.base_url.as_str())
            .unwrap_or(state.upstream_base),
        "upstream_path": path,
        "config_name": state.config_name,
        "config_sha256": state.config_sha256,
        "agent_id": state.current_target_id,
    })
}

pub fn decision_runtime_json_streaming(
    output_chars: Option<usize>,
    finish_reason: Option<&str>,
    fallback_provider_id: Option<&str>,
    chunks_forwarded: usize,
    buffered: bool,
    interrupted: bool,
    failure_reason: Option<&str>,
    failure_message: Option<&str>,
    gateway_context: Option<&StreamingGatewayContext>,
) -> serde_json::Value {
    let mut val = serde_json::json!({
        "streaming": true,
        "output_chars": output_chars,
        "finish_reason": finish_reason,
        "fallback_provider_id": fallback_provider_id,
        "chunks_forwarded": chunks_forwarded,
        "buffered": buffered,
        "interrupted": interrupted,
        "failure_reason": failure_reason,
        "failure_message": failure_message,
    });
    if let Some(ctx) = gateway_context {
        if let Some(obj) = val.as_object_mut() {
            obj.insert("gateway_id".to_string(), serde_json::json!(ctx.gateway_id));
            obj.insert("provider".to_string(), serde_json::json!(ctx.provider));
            obj.insert(
                "resolved_provider".to_string(),
                serde_json::json!(ctx.resolved_provider),
            );
            obj.insert(
                "config_name".to_string(),
                serde_json::json!(ctx.config_name),
            );
        }
    }
    val
}

/// Gateway context fields cloned into streaming tasks so that
/// `decision_runtime_json_streaming` can include them alongside the
/// streaming-specific fields.
#[derive(Clone)]
pub struct StreamingGatewayContext {
    pub(crate) gateway_id: Option<Arc<str>>,
    pub(crate) provider: Option<String>,
    pub(crate) resolved_provider: Option<String>,
    pub(crate) config_name: Option<String>,
}

pub(crate) fn streaming_mode_label(
    requires_buffering: bool,
    redaction_buffered: bool,
) -> &'static str {
    if redaction_buffered {
        "buffered_redaction"
    } else if requires_buffering {
        "buffered_policy"
    } else {
        "passthrough"
    }
}

pub(crate) fn streaming_requires_buffering(
    policy_chain: &[String],
    policy_blocks: &crate::gateway::PolicyBlocks,
) -> bool {
    if streaming_output_redaction_enabled(policy_chain, policy_blocks) {
        return true;
    }

    policy_chain.iter().any(|kind| {
        matches!(
            kind.as_str(),
            "citation-verifier"
                | "mnpi-filter"
                | "financial-compliance"
                | "healthcare-compliance"
                | "legal-privilege"
                | "upl-filter"
                | "bias-monitor"
                | "quality-scorer"
                | "human-oversight"
                | "safety-filter"
                | "itar-ear-filter"
                | "entity-list-filter"
                | "dual-use-filter"
                | "response-rewriter"
                | "agent-firewall"
        )
    })
}

pub(crate) fn streaming_agent_firewall_enabled(policy_chain: &[String]) -> bool {
    policy_chain.iter().any(|kind| kind == "agent-firewall")
}

pub(crate) fn evaluate_streaming_agent_firewall(
    policy_chain: &[String],
    policy_blocks: &crate::gateway::PolicyBlocks,
    accumulator: crate::gateway::structured_tool_calls::StreamingToolCallAccumulator,
    authenticated_identity: Option<&crate::gateway::identity::AuthenticatedRequestIdentity>,
) -> Option<enforcement::PolicyResult> {
    if !streaming_agent_firewall_enabled(policy_chain) {
        return None;
    }
    let calls = match accumulator.finish() {
        Ok(calls) => calls,
        Err(error) => {
            return Some(enforcement::PolicyResult {
                policy_kind: "agent-firewall".to_string(),
                phase: "tool".to_string(),
                verdict: Verdict::Block,
                reason_code: "agent_firewall.malformed_tool_call".to_string(),
                details: Some(serde_json::json!({"error": error.to_string(), "streaming": true})),
                redaction_targets: None,
            });
        }
    };
    let result = enforcement::evaluate_agent_firewall_tool_calls(
        policy_blocks.get("agent-firewall"),
        &calls,
        authenticated_identity,
    );
    matches!(result.verdict, Verdict::Block | Verdict::Escalate).then_some(result)
}

pub(crate) fn evaluate_streaming_blocking_policy(
    policy_chain: &[String],
    policy_blocks: &crate::gateway::PolicyBlocks,
    output_text: &str,
) -> Option<enforcement::PolicyResult> {
    let lower = output_text.to_ascii_lowercase();

    for kind in policy_chain {
        match kind.as_str() {
            "safety-filter" => {
                let Some(cfg) = policy_blocks.get("safety-filter") else {
                    continue;
                };
                let mode = cfg
                    .get("mode")
                    .and_then(|value| value.as_str())
                    .unwrap_or("critical_infrastructure");
                let action = cfg
                    .get("action")
                    .and_then(|value| value.as_str())
                    .unwrap_or("block");
                if action == "escalate" {
                    continue;
                }

                let mut block_if: Vec<String> = cfg
                    .get("block_if")
                    .and_then(|value| value.as_array())
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|item| item.as_str().map(|text| text.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                if block_if.is_empty() {
                    block_if = match mode {
                        "automotive" => vec![
                            "disable airbags".to_string(),
                            "bypass brakes".to_string(),
                            "tamper".to_string(),
                        ],
                        "education" => vec!["self-harm".to_string(), "suicide".to_string()],
                        "law_enforcement" => vec!["doxx".to_string(), "target".to_string()],
                        _ => vec![
                            "explosive".to_string(),
                            "weapon".to_string(),
                            "attack".to_string(),
                        ],
                    };
                }

                if let Some(matched) = block_if.iter().find(|term| {
                    let trimmed = term.trim().to_ascii_lowercase();
                    if trimmed.is_empty() {
                        return false;
                    }
                    let pattern = format!(r"(?i)\b{}\b", regex_lite::escape(&trimmed));
                    regex_lite::Regex::new(&pattern)
                        .map(|re| re.is_match(&lower))
                        .unwrap_or_else(|_| lower.contains(&trimmed))
                }) {
                    return Some(enforcement::PolicyResult {
                        policy_kind: "safety-filter".to_string(),
                        phase: "output".to_string(),
                        verdict: Verdict::Block,
                        reason_code: format!("safety.triggered.{mode}"),
                        details: Some(serde_json::json!({
                            "mode": mode,
                            "action": action,
                            "matched": matched,
                            "streaming": true,
                        })),
                        redaction_targets: None,
                    });
                }
            }
            "itar-ear-filter" | "entity-list-filter" | "dual-use-filter" => {
                let Some(cfg) = policy_blocks.get(kind) else {
                    continue;
                };
                let (terms_key, reason_prefix) = match kind.as_str() {
                    "entity-list-filter" => ("blocked_entities", "entity_list"),
                    _ => (
                        "blocked_terms",
                        if kind == "itar-ear-filter" {
                            "export_controls"
                        } else {
                            "dual_use"
                        },
                    ),
                };

                let mut terms: Vec<String> = cfg
                    .get(terms_key)
                    .and_then(|value| value.as_array())
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|item| item.as_str().map(|text| text.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                if terms.is_empty() && kind == "itar-ear-filter" {
                    terms = vec![
                        "itar".to_string(),
                        "ear".to_string(),
                        "usml".to_string(),
                        "eccn".to_string(),
                    ];
                }
                if terms.is_empty() && kind == "dual-use-filter" {
                    terms = vec![
                        "weapon".to_string(),
                        "explosive".to_string(),
                        "bioweapon".to_string(),
                        "nerve agent".to_string(),
                    ];
                }

                let action = cfg
                    .get("action")
                    .and_then(|value| value.as_str())
                    .unwrap_or("block");
                if kind == "dual-use-filter" && action == "redact" {
                    continue;
                }

                if let Some(matched) = terms.iter().find(|term| {
                    let needle = term.trim().to_ascii_lowercase();
                    if needle.is_empty() {
                        return false;
                    }
                    // Use word-boundary matching to avoid substring false
                    // positives (e.g. "itar" inside "military").
                    let pattern = format!(r"(?i)\b{}\b", regex_lite::escape(&needle));
                    regex_lite::Regex::new(&pattern)
                        .map(|re| re.is_match(&lower))
                        .unwrap_or_else(|_| lower.contains(&needle))
                }) {
                    return Some(enforcement::PolicyResult {
                        policy_kind: kind.to_string(),
                        phase: "output".to_string(),
                        verdict: Verdict::Block,
                        reason_code: format!("{reason_prefix}.triggered"),
                        details: Some(serde_json::json!({
                            "action": action,
                            "matched": matched,
                            "streaming": true,
                        })),
                        redaction_targets: None,
                    });
                }
            }
            _ => {}
        }
    }

    None
}

pub(crate) fn streaming_output_redaction_enabled(
    policy_chain: &[String],
    policy_blocks: &crate::gateway::PolicyBlocks,
) -> bool {
    policy_chain.iter().any(|kind| match kind.as_str() {
        "pii-detector" => {
            policy_blocks
                .get("pii-detector")
                .and_then(|value| value.get("action"))
                .and_then(|value| value.as_str())
                .unwrap_or("redact")
                != "off"
        }
        "hipaa-phi-detector" => {
            policy_blocks
                .get("hipaa-phi-detector")
                .and_then(|value| value.get("action"))
                .and_then(|value| value.as_str())
                .unwrap_or("redact")
                != "off"
        }
        "dlp-filter" => {
            policy_blocks
                .get("dlp-filter")
                .and_then(|value| value.get("action"))
                .and_then(|value| value.as_str())
                .unwrap_or("redact")
                == "redact"
        }
        "student-privacy" => {
            policy_blocks
                .get("student-privacy")
                .and_then(|value| value.get("action"))
                .and_then(|value| value.as_str())
                .unwrap_or("redact")
                == "redact"
        }
        "case-privacy" => true,
        "dual-use-filter" => {
            policy_blocks
                .get("dual-use-filter")
                .and_then(|value| value.get("action"))
                .and_then(|value| value.as_str())
                .unwrap_or("block")
                == "redact"
        }
        _ => false,
    })
}

pub(crate) fn build_buffered_streaming_sse_bytes(
    request_id: &str,
    content: &str,
    finish_reason: Option<&str>,
) -> Option<Bytes> {
    let response = serde_json::json!({
        "id": format!("chatcmpl_verdictan_{request_id}"),
        "created": chrono::Utc::now().timestamp(),
        "model": "verdictan-buffered-stream",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content,
            },
            "finish_reason": finish_reason.unwrap_or("stop"),
        }],
    });

    crate::gateway::sse::chat_completion_json_to_sse(&serde_json::to_vec(&response).ok()?, false)
}

pub(crate) fn build_buffered_responses_sse_bytes(
    request_id: &str,
    content: &str,
    finish_reason: Option<&str>,
) -> Option<Bytes> {
    let response = serde_json::json!({
        "id": format!("resp_verdictan_{request_id}"),
        "object": "response",
        "status": finish_reason.unwrap_or("completed"),
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{
                "type": "output_text",
                "text": content,
            }],
        }],
    });

    crate::gateway::sse::responses_json_to_sse(&serde_json::to_vec(&response).ok()?)
}

#[derive(Clone, Debug)]
pub(crate) struct PipelineStepResult {
    pub(crate) label: String,
    pub(crate) target_id: String,
    pub(crate) provider: String,
    pub(crate) model: String,
    pub(crate) status: StatusCode,
    pub(crate) output_text: String,
    pub(crate) usage: Option<SpendUsage>,
    pub(crate) prompt_cost: f64,
    pub(crate) completion_cost: f64,
    pub(crate) cached_input_cost: f64,
    pub(crate) total_cost: f64,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PipelineUsageTotals {
    pub(crate) prompt_tokens: u64,
    pub(crate) completion_tokens: u64,
    pub(crate) total_tokens: u64,
    pub(crate) cached_input_tokens: u64,
    pub(crate) prompt_cost: f64,
    pub(crate) completion_cost: f64,
    pub(crate) cached_input_cost: f64,
    pub(crate) total_cost: f64,
    pub(crate) has_usage: bool,
}

impl PipelineUsageTotals {
    pub(crate) fn record_step(
        &mut self,
        usage: SpendUsage,
        prompt_cost: f64,
        completion_cost: f64,
        cached_input_cost: f64,
        total_cost: f64,
    ) {
        self.prompt_tokens = self.prompt_tokens.saturating_add(usage.prompt_tokens);
        self.completion_tokens = self
            .completion_tokens
            .saturating_add(usage.completion_tokens);
        self.total_tokens = self.total_tokens.saturating_add(usage.total_tokens);
        self.cached_input_tokens = self
            .cached_input_tokens
            .saturating_add(usage.cached_input_tokens);
        self.prompt_cost += prompt_cost;
        self.completion_cost += completion_cost;
        self.cached_input_cost += cached_input_cost;
        self.total_cost += total_cost;
        self.has_usage = true;
    }

    pub(crate) fn into_json(self) -> Option<serde_json::Value> {
        if !self.has_usage {
            return None;
        }

        Some(serde_json::json!({
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "prompt_cost": self.prompt_cost,
            "completion_cost": self.completion_cost,
            "cached_input_cost": self.cached_input_cost,
            "total_cost": self.total_cost,
        }))
    }
}

pub(crate) fn pipeline_supported_path(path: &str) -> bool {
    matches!(path, "/v1/chat/completions" | "/v1/responses")
}

pub(crate) fn build_pipeline_json_response(
    status: StatusCode,
    body: serde_json::Value,
) -> crate::gateway::cache::BufferedUpstreamResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    crate::gateway::cache::BufferedUpstreamResponse::new(
        status,
        headers,
        Bytes::from(serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec())),
        false,
    )
}

pub(crate) fn build_pipeline_error_response(
    status: StatusCode,
    message: impl Into<String>,
    error_type: &str,
    code: &str,
) -> crate::gateway::cache::BufferedUpstreamResponse {
    build_pipeline_json_response(
        status,
        serde_json::json!({
            "error": {
                "message": message.into(),
                "type": error_type,
                "code": code,
            }
        }),
    )
}

pub(crate) fn pipeline_step_label(
    step: &crate::gateway::providers::ProviderPipelineStep,
) -> String {
    step.name.clone().unwrap_or_else(|| step.target.clone())
}

pub(crate) fn build_pipeline_chat_messages(
    original_body: &serde_json::Value,
    step: &crate::gateway::providers::ProviderPipelineStep,
    previous_output: Option<&str>,
) -> Result<Vec<serde_json::Value>, CliError> {
    let original_messages = original_body
        .get("messages")
        .and_then(|value| value.as_array())
        .cloned()
        .ok_or_else(|| {
            CliError::user(
                "provider pipelines for /v1/chat/completions require a top-level 'messages' array",
            )
        })?;

    let mut messages = if previous_output.is_some()
        && step.input_mode == crate::gateway::providers::ProviderPipelineInputMode::Replace
    {
        Vec::new()
    } else {
        original_messages
    };

    if let Some(instruction) = step.instruction.as_deref().map(str::trim) {
        if !instruction.is_empty() {
            messages.insert(
                0,
                serde_json::json!({
                    "role": "system",
                    "content": instruction,
                }),
            );
        }
    }

    if let Some(output) = previous_output
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        messages.push(serde_json::json!({
            "role": step.inject_as.as_str(),
            "content": output,
        }));
    }

    Ok(messages)
}

pub(crate) fn build_pipeline_responses_input(
    original_body: &serde_json::Value,
    step: &crate::gateway::providers::ProviderPipelineStep,
    previous_output: Option<&str>,
) -> Result<Vec<serde_json::Value>, CliError> {
    let original_input = if let Some(messages) = original_body
        .get("messages")
        .and_then(|value| value.as_array())
    {
        messages.clone()
    } else if let Some(input) = original_body.get("input") {
        if let Some(text) = input.as_str() {
            vec![serde_json::Value::String(text.to_string())]
        } else if let Some(items) = input.as_array() {
            items.clone()
        } else {
            return Err(CliError::user(
                "provider pipelines for /v1/responses require 'input' to be a string or array",
            ));
        }
    } else {
        return Err(CliError::user(
            "provider pipelines for /v1/responses require a top-level 'input' string or array",
        ));
    };

    let mut input = if previous_output.is_some()
        && step.input_mode == crate::gateway::providers::ProviderPipelineInputMode::Replace
    {
        Vec::new()
    } else {
        original_input
    };

    if let Some(instruction) = step.instruction.as_deref().map(str::trim) {
        if !instruction.is_empty() {
            input.insert(
                0,
                serde_json::json!({
                    "role": "system",
                    "content": instruction,
                }),
            );
        }
    }

    if let Some(output) = previous_output
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        input.push(serde_json::json!({
            "role": step.inject_as.as_str(),
            "content": output,
        }));
    }

    Ok(input)
}

pub(crate) fn build_pipeline_step_request(
    path: &str,
    original_body: &serde_json::Value,
    step: &crate::gateway::providers::ProviderPipelineStep,
    previous_output: Option<&str>,
    step_index: usize,
) -> Result<serde_json::Value, CliError> {
    let mut request = original_body.clone();
    crate::gateway::sse::disable_stream_flag(&mut request);
    let Some(object) = request.as_object_mut() else {
        return Err(CliError::user(
            "provider pipelines require a JSON object request body",
        ));
    };
    object.remove("stream_options");
    object.insert(
        "model".to_string(),
        serde_json::Value::String(format!("__verdictan_pipeline_step_{step_index}__")),
    );

    match path {
        "/v1/chat/completions" => {
            let messages = build_pipeline_chat_messages(original_body, step, previous_output)?;
            object.insert("messages".to_string(), serde_json::Value::Array(messages));
        }
        "/v1/responses" => {
            let input = build_pipeline_responses_input(original_body, step, previous_output)?;
            object.remove("messages");
            object.insert("input".to_string(), serde_json::Value::Array(input));
        }
        _ => {
            return Err(CliError::user(
                "provider pipelines currently support only /v1/chat/completions and /v1/responses",
            ));
        }
    }

    Ok(request)
}

pub(crate) fn build_pipeline_headers(
    headers: &HeaderMap,
    target: &crate::gateway::providers::ProviderTarget,
) -> Result<HeaderMap, CliError> {
    let mut pipeline_headers = headers.clone();
    pipeline_headers.remove("x-verdictan-provider");
    pipeline_headers.remove("x-verdictan-model");
    pipeline_headers.insert(
        "x-verdictan-provider",
        HeaderValue::from_str(&target.id).map_err(|error| {
            CliError::user(format!(
                "provider pipeline target '{}' cannot be used as a provider pin header: {error}",
                target.id
            ))
        })?,
    );
    // A wildcard model ("*") means "use whatever model the request already carries",
    // so we skip the model pin header to let the original model pass through.
    if !target.model.is_empty() && target.model.trim() != "*" {
        pipeline_headers.insert(
            "x-verdictan-model",
            HeaderValue::from_str(&target.model).map_err(|error| {
                CliError::user(format!(
                    "provider pipeline target '{}' model '{}' cannot be used as a model pin header: {error}",
                    target.id, target.model
                ))
            })?,
        );
    }
    Ok(pipeline_headers)
}

pub(crate) fn pipeline_step_usage_json(usage: SpendUsage) -> serde_json::Value {
    serde_json::json!({
        "prompt_tokens": usage.prompt_tokens,
        "completion_tokens": usage.completion_tokens,
        "total_tokens": usage.total_tokens,
        "cached_input_tokens": usage.cached_input_tokens,
    })
}

pub(crate) fn build_pipeline_metadata_json(
    requested_model: &str,
    pipeline: &crate::gateway::providers::ProviderPipeline,
    step_results: &[PipelineStepResult],
) -> serde_json::Value {
    serde_json::json!({
        "name": pipeline.name.clone(),
        "requested_model": requested_model,
        "mode": pipeline.mode.as_str(),
        "aggregation": pipeline.aggregation.as_str(),
        "steps": step_results
            .iter()
            .map(|result| {
                let mut value = serde_json::json!({
                    "name": result.label.clone(),
                    "target": result.target_id.clone(),
                    "provider": result.provider.clone(),
                    "model": result.model.clone(),
                    "status": result.status.as_u16(),
                    "output_chars": result.output_text.chars().count(),
                    "cost": {
                        "prompt_cost": result.prompt_cost,
                        "completion_cost": result.completion_cost,
                        "cached_input_cost": result.cached_input_cost,
                        "total_cost": result.total_cost,
                    }
                });
                if let Some(usage) = result.usage {
                    if let Some(object) = value.as_object_mut() {
                        object.insert("usage".to_string(), pipeline_step_usage_json(usage));
                    }
                }
                value
            })
            .collect::<Vec<_>>(),
    })
}

pub(crate) fn decorate_pipeline_response(
    response: crate::gateway::cache::BufferedUpstreamResponse,
    requested_model: &str,
    pipeline_metadata: serde_json::Value,
    usage: Option<serde_json::Value>,
) -> crate::gateway::cache::BufferedUpstreamResponse {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(response.body()) else {
        return response;
    };
    let Some(object) = value.as_object_mut() else {
        return response;
    };
    object.insert(
        "model".to_string(),
        serde_json::Value::String(requested_model.to_string()),
    );
    if let Some(usage) = usage {
        object.insert("usage".to_string(), usage);
    }
    object.insert("verdictan_pipeline".to_string(), pipeline_metadata);

    let Ok(body) = serde_json::to_vec(&value) else {
        return response;
    };
    let mut headers = response.headers().clone();
    headers.remove(header::CONTENT_LENGTH);
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    crate::gateway::cache::BufferedUpstreamResponse::new(
        response.status(),
        headers,
        Bytes::from(body),
        response.is_cached(),
    )
}

pub(crate) fn build_pipeline_synthetic_response(
    path: &str,
    request_id: &str,
    requested_model: &str,
    output_text: &str,
    pipeline_metadata: serde_json::Value,
    usage: Option<serde_json::Value>,
) -> crate::gateway::cache::BufferedUpstreamResponse {
    let now = chrono::Utc::now();
    let mut body = match path {
        "/v1/chat/completions" => serde_json::json!({
            "id": format!("chatcmpl_verdictan_pipeline_{request_id}"),
            "object": "chat.completion",
            "created": now.timestamp(),
            "model": requested_model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": output_text,
                },
                "finish_reason": "stop",
            }],
        }),
        "/v1/responses" => serde_json::json!({
            "id": format!("resp_verdictan_pipeline_{request_id}"),
            "created_at": now.to_rfc3339(),
            "model": requested_model,
            "output": output_text,
            "status": "succeeded",
        }),
        _ => serde_json::json!({}),
    };

    if let Some(object) = body.as_object_mut() {
        if let Some(usage) = usage {
            object.insert("usage".to_string(), usage);
        }
        object.insert("verdictan_pipeline".to_string(), pipeline_metadata);
    }

    build_pipeline_json_response(StatusCode::OK, body)
}

pub(crate) fn pipeline_requested_model_name(
    original_body: &serde_json::Value,
    pipeline: &crate::gateway::providers::ProviderPipeline,
) -> String {
    original_body
        .get("model")
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| pipeline.name.clone())
}

pub(crate) async fn execute_provider_pipeline(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    path: &str,
    original_body: &serde_json::Value,
    request_id: &str,
    traceparent: &str,
    correlation: &TraceCorrelation,
    request_telemetry_hints: &RequestTelemetryHints,
    session_context: Option<&crate::gateway::session::GatewaySessionContext>,
    pipeline: &crate::gateway::providers::ProviderPipeline,
) -> (
    Result<crate::gateway::cache::BufferedUpstreamResponse, reqwest::Error>,
    Option<String>,
) {
    if !pipeline_supported_path(path) {
        return (
            Ok(build_pipeline_error_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "provider pipeline model '{}' only supports /v1/chat/completions and /v1/responses",
                    pipeline.name
                ),
                "invalid_pipeline_endpoint",
                "pipeline_endpoint_unsupported",
            )),
            None,
        );
    }

    let Some(registry) = state.provider_registry.as_ref() else {
        return (
            Ok(build_pipeline_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                missing_provider_registry_message(state.connected_mode),
                "pipeline_registry_missing",
                "pipeline_registry_missing",
            )),
            None,
        );
    };

    let requested_model = pipeline_requested_model_name(original_body, pipeline);

    match pipeline.mode {
        crate::gateway::providers::ProviderPipelineMode::Sequence => {
            let mut previous_output: Option<String> = None;
            let mut totals = PipelineUsageTotals::default();
            let mut step_results = Vec::with_capacity(pipeline.steps.len());

            for (step_index, step) in pipeline.steps.iter().enumerate() {
                let Some(target) = registry.find_target_by_id(&step.target) else {
                    return (
                        Ok(build_pipeline_error_response(
                            StatusCode::BAD_REQUEST,
                            format!(
                                "provider pipeline '{}' references unknown target '{}'",
                                pipeline.name, step.target
                            ),
                            "invalid_pipeline_target",
                            "pipeline_target_unknown",
                        )),
                        None,
                    );
                };

                let step_request = match build_pipeline_step_request(
                    path,
                    original_body,
                    step,
                    previous_output.as_deref(),
                    step_index,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        return (
                            Ok(build_pipeline_error_response(
                                StatusCode::BAD_REQUEST,
                                error.to_string(),
                                "invalid_pipeline_request",
                                "pipeline_request_invalid",
                            )),
                            None,
                        )
                    }
                };
                let step_headers = match build_pipeline_headers(headers, target) {
                    Ok(value) => value,
                    Err(error) => {
                        return (
                            Ok(build_pipeline_error_response(
                                StatusCode::BAD_REQUEST,
                                error.to_string(),
                                "invalid_pipeline_header",
                                "pipeline_header_invalid",
                            )),
                            None,
                        )
                    }
                };
                let step_bytes = match serde_json::to_vec(&step_request) {
                    Ok(value) => Bytes::from(value),
                    Err(error) => {
                        return (
                            Ok(build_pipeline_error_response(
                                StatusCode::BAD_REQUEST,
                                format!("failed to serialize pipeline step request: {error}"),
                                "invalid_pipeline_request",
                                "pipeline_request_invalid",
                            )),
                            None,
                        )
                    }
                };

                let (step_response, _) = Box::pin(send_with_provider_fallback(
                    state,
                    &step_headers,
                    path,
                    step_bytes,
                    request_id,
                    traceparent,
                    None,
                    correlation,
                    request_telemetry_hints,
                    session_context,
                ))
                .await;

                let response = match step_response {
                    Ok(response) => response,
                    Err(error) => return (Err(error), Some(target.id.clone())),
                };
                if !response.status().is_success() {
                    return (Ok(response), Some(target.id.clone()));
                }

                let output_text = serde_json::from_slice::<serde_json::Value>(response.body())
                    .ok()
                    .map(|value| extract_openai_output_text_from_json(&value))
                    .unwrap_or_default();
                let usage = extract_spend_usage(response.body());
                let model = extract_response_model_name(response.body())
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| target.model.clone());
                let provider = canonical_provider_slug(Some(target), state.upstream_base, &model);
                let (prompt_cost, completion_cost, cached_input_cost, total_cost) = usage
                    .map(|usage_value| {
                        let pricing = resolve_spend_pricing(
                            &spend_log_context(state),
                            Some(target),
                            &provider,
                            &model,
                            usage_value,
                        );
                        spend_cost_breakdown(usage_value, pricing.pricing.as_ref())
                    })
                    .unwrap_or((0.0, 0.0, 0.0, 0.0));
                if let Some(usage) = usage {
                    totals.record_step(
                        usage,
                        prompt_cost,
                        completion_cost,
                        cached_input_cost,
                        total_cost,
                    );
                }

                step_results.push(PipelineStepResult {
                    label: pipeline_step_label(step),
                    target_id: target.id.clone(),
                    provider,
                    model,
                    status: response.status(),
                    output_text: output_text.clone(),
                    usage,
                    prompt_cost,
                    completion_cost,
                    cached_input_cost,
                    total_cost,
                });
                previous_output = (!output_text.trim().is_empty()).then_some(output_text);

                if step_index + 1 == pipeline.steps.len() {
                    let metadata =
                        build_pipeline_metadata_json(&requested_model, pipeline, &step_results);
                    let decorated = decorate_pipeline_response(
                        response,
                        &requested_model,
                        metadata,
                        totals.into_json(),
                    );
                    return (Ok(decorated), None);
                }
            }

            (
                Ok(build_pipeline_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "provider pipeline '{}' did not execute any steps",
                        pipeline.name
                    ),
                    "pipeline_execution_error",
                    "pipeline_no_steps_executed",
                )),
                None,
            )
        }
        crate::gateway::providers::ProviderPipelineMode::FanOut => {
            let mut prepared_steps = Vec::with_capacity(pipeline.steps.len());
            for (step_index, step) in pipeline.steps.iter().enumerate() {
                let Some(target) = registry.find_target_by_id(&step.target) else {
                    return (
                        Ok(build_pipeline_error_response(
                            StatusCode::BAD_REQUEST,
                            format!(
                                "provider pipeline '{}' references unknown target '{}'",
                                pipeline.name, step.target
                            ),
                            "invalid_pipeline_target",
                            "pipeline_target_unknown",
                        )),
                        None,
                    );
                };
                let step_request = match build_pipeline_step_request(
                    path,
                    original_body,
                    step,
                    None,
                    step_index,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        return (
                            Ok(build_pipeline_error_response(
                                StatusCode::BAD_REQUEST,
                                error.to_string(),
                                "invalid_pipeline_request",
                                "pipeline_request_invalid",
                            )),
                            None,
                        )
                    }
                };
                let step_headers = match build_pipeline_headers(headers, target) {
                    Ok(value) => value,
                    Err(error) => {
                        return (
                            Ok(build_pipeline_error_response(
                                StatusCode::BAD_REQUEST,
                                error.to_string(),
                                "invalid_pipeline_header",
                                "pipeline_header_invalid",
                            )),
                            None,
                        )
                    }
                };
                let step_bytes = match serde_json::to_vec(&step_request) {
                    Ok(value) => Bytes::from(value),
                    Err(error) => {
                        return (
                            Ok(build_pipeline_error_response(
                                StatusCode::BAD_REQUEST,
                                format!("failed to serialize pipeline step request: {error}"),
                                "invalid_pipeline_request",
                                "pipeline_request_invalid",
                            )),
                            None,
                        )
                    }
                };
                prepared_steps.push((step.clone(), target.clone(), step_headers, step_bytes));
            }

            let outcomes = futures_util::future::join_all(prepared_steps.into_iter().map(
                |(step, target, step_headers, step_bytes)| async move {
                    let result = Box::pin(send_with_provider_fallback(
                        state,
                        &step_headers,
                        path,
                        step_bytes,
                        request_id,
                        traceparent,
                        None,
                        correlation,
                        request_telemetry_hints,
                        session_context,
                    ))
                    .await;
                    (step, target, result)
                },
            ))
            .await;

            let mut totals = PipelineUsageTotals::default();
            let mut step_results = Vec::new();
            let mut first_success_response: Option<
                crate::gateway::cache::BufferedUpstreamResponse,
            > = None;
            let mut first_error_response: Option<(
                crate::gateway::cache::BufferedUpstreamResponse,
                String,
            )> = None;
            let mut first_network_error: Option<(reqwest::Error, String)> = None;

            for (step, target, (result, _served_provider)) in outcomes {
                match result {
                    Ok(response) => {
                        if !response.status().is_success() {
                            if first_error_response.is_none() {
                                first_error_response = Some((response, target.id.clone()));
                            }
                            continue;
                        }

                        if first_success_response.is_none() {
                            first_success_response = Some(response.clone());
                        }

                        let output_text =
                            serde_json::from_slice::<serde_json::Value>(response.body())
                                .ok()
                                .map(|value| extract_openai_output_text_from_json(&value))
                                .unwrap_or_default();
                        let usage = extract_spend_usage(response.body());
                        let model = extract_response_model_name(response.body())
                            .filter(|value| !value.trim().is_empty())
                            .unwrap_or_else(|| target.model.clone());
                        let provider =
                            canonical_provider_slug(Some(&target), state.upstream_base, &model);
                        let (prompt_cost, completion_cost, cached_input_cost, total_cost) = usage
                            .map(|usage_value| {
                                let pricing = resolve_spend_pricing(
                                    &spend_log_context(state),
                                    Some(&target),
                                    &provider,
                                    &model,
                                    usage_value,
                                );
                                spend_cost_breakdown(usage_value, pricing.pricing.as_ref())
                            })
                            .unwrap_or((0.0, 0.0, 0.0, 0.0));
                        if let Some(usage) = usage {
                            totals.record_step(
                                usage,
                                prompt_cost,
                                completion_cost,
                                cached_input_cost,
                                total_cost,
                            );
                        }

                        step_results.push(PipelineStepResult {
                            label: pipeline_step_label(&step),
                            target_id: target.id,
                            provider,
                            model,
                            status: response.status(),
                            output_text,
                            usage,
                            prompt_cost,
                            completion_cost,
                            cached_input_cost,
                            total_cost,
                        });
                    }
                    Err(error) => {
                        if first_network_error.is_none() {
                            first_network_error = Some((error, target.id.clone()));
                        }
                    }
                }
            }

            if step_results.is_empty() {
                if let Some((response, target_id)) = first_error_response {
                    return (Ok(response), Some(target_id));
                }
                if let Some((error, target_id)) = first_network_error {
                    return (Err(error), Some(target_id));
                }
                return (
                    Ok(build_pipeline_error_response(
                        StatusCode::BAD_GATEWAY,
                        format!(
                            "provider pipeline '{}' did not receive any successful fan-out responses",
                            pipeline.name
                        ),
                        "pipeline_execution_error",
                        "pipeline_no_successful_steps",
                    )),
                    None,
                );
            }

            let metadata = build_pipeline_metadata_json(&requested_model, pipeline, &step_results);
            let usage = totals.into_json();
            match pipeline.aggregation {
                crate::gateway::providers::ProviderPipelineAggregation::FirstSuccess => {
                    let Some(response) = first_success_response else {
                        return (
                            Ok(build_pipeline_error_response(
                                StatusCode::BAD_GATEWAY,
                                format!(
                                    "provider pipeline '{}' could not determine a successful fan-out response",
                                    pipeline.name
                                ),
                                "pipeline_execution_error",
                                "pipeline_first_success_missing",
                            )),
                            None,
                        );
                    };
                    (
                        Ok(decorate_pipeline_response(
                            response,
                            &requested_model,
                            metadata,
                            usage,
                        )),
                        None,
                    )
                }
                crate::gateway::providers::ProviderPipelineAggregation::Concat => {
                    let combined_output = step_results
                        .iter()
                        .filter(|result| !result.output_text.trim().is_empty())
                        .map(|result| {
                            if step_results.len() == 1 {
                                result.output_text.clone()
                            } else {
                                format!("## {}\n{}", result.label, result.output_text)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n\n");
                    (
                        Ok(build_pipeline_synthetic_response(
                            path,
                            request_id,
                            &requested_model,
                            &combined_output,
                            metadata,
                            usage,
                        )),
                        None,
                    )
                }
            }
        }
    }
}

pub(crate) fn build_streaming_error_sse_bytes(
    request_id: &str,
    config_version: &str,
    verdict: &str,
    reason_code: &str,
    message: &str,
    latency_ms: i64,
) -> Option<Bytes> {
    let verdictan = verdictan_extension_json(
        verdict,
        reason_code,
        config_version,
        request_id,
        latency_ms,
        None,
        None,
    );
    let body = serde_json::json!({
        "error": error_json(message, "upstream_stream_error", reason_code),
        "verdictan": verdictan,
    });

    Some(Bytes::from(format!("data: {}\n\n", body)))
}

pub(crate) async fn provider_metrics_endpoint(
    State(state): State<GatewayState>,
) -> Result<Response<Body>, StatusCode> {
    let json = state.provider_metrics.snapshot_json();
    let body = serde_json::to_vec(&json).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Standard Prometheus text exposition endpoint for scraping.
///
/// Always returns output from the global prometheus registry (which includes
/// all `verdictan_gateway_*` metrics defined in `metrics.rs`). When a
/// `prometheus_sink` is also configured via callbacks, its output is appended
/// after the global registry output.
///
/// This endpoint MUST NOT require authentication.
pub(crate) async fn prometheus_metrics_handler(
    State(state): State<GatewayState>,
) -> Result<Response<Body>, StatusCode> {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = String::new();
    if let Err(e) = { encoder.encode_utf8(&metric_families, &mut buffer) } {
        tracing::warn!(error = %e, "failed to encode prometheus metrics");
    }

    // Append callback-configured sink metrics when present.
    if let Some(sink) = &state.prometheus_sink {
        let sink_text = sink.render();
        if !sink_text.trim().is_empty() {
            buffer.push('\n');
            buffer.push_str(&sink_text);
        }
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(Body::from(buffer))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// EU AI Act compliance report endpoint — generates an on-demand compliance
/// report based on the active policy chain. Requires proxy-admin authentication
/// with `gateways:read` permission.
pub(crate) async fn compliance_report_handler(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Result<Response<Body>, StatusCode> {
    enforce_proxy_admin_auth(
        &state,
        &headers,
        peer_addr,
        "compliance_report",
        "gateways:read",
    )
    .await?;

    let config = state.active_config.snapshot();
    let report = crate::gateway::eu_ai_act::generate_compliance_report(&config);
    let body = serde_json::to_vec(&report).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Multi-provider fallback wrapper around `send_upstream_request`.
///
/// When a `provider_registry` is present in the active config, this function:
/// 1. Selects provider ordering based on the configured routing strategy and live metrics.
/// 2. Optionally compresses the context to fit each provider's token limit.
pub(crate) fn build_mcp_session_meta(
    session: Option<&crate::gateway::session::GatewaySessionContext>,
) -> Option<crate::gateway::runtimes::network::mcp::McpSessionMeta> {
    let session = session?;
    let authenticated_actor = session
        .agent_id
        .clone()
        .or_else(|| Some(format!("mcp:session:{}", session.session_id)));
    Some(crate::gateway::runtimes::network::mcp::McpSessionMeta {
        session_id: Some(session.session_id.clone()),
        conversation_id: session.conversation_id.clone(),
        agent_id: session.agent_id.clone(),
        authenticated_actor,
        target_server: Some("mcp:published".to_string()),
        ..Default::default()
    })
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ProviderRequestPins {
    pub(crate) provider: Option<String>,
    pub(crate) model: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum ProviderOrderSelectionError {
    UnknownProviderPin(String),
    NoCompliantProvider,
}

pub(crate) fn extract_provider_request_pins(headers: &HeaderMap) -> ProviderRequestPins {
    ProviderRequestPins {
        provider: headers
            .get("x-verdictan-provider")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        model: headers
            .get("x-verdictan-model")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
    }
}

pub(crate) fn data_routing_policy_for_state(
    state: &ActiveGatewayStateView<'_>,
) -> Option<crate::gateway::providers::DataRoutingPolicy> {
    if state
        .policy_chain
        .contains(&"data-routing-policy".to_string())
    {
        return crate::gateway::providers::parse_data_routing_policy(
            state.policy_blocks.get("data-routing-policy"),
        );
    }
    None
}

pub(crate) fn apply_provider_pin_selection(
    registry: &crate::gateway::providers::ProviderRegistry,
    provider_pin: Option<&str>,
    request_id: &str,
) -> Result<Option<Vec<usize>>, ProviderOrderSelectionError> {
    let Some(provider_pin) = provider_pin else {
        return Ok(None);
    };

    let pinned = registry.resolve_provider_pin(provider_pin);
    if pinned.is_empty() {
        tracing::warn!(
            request_id = %request_id,
            provider_pin = %provider_pin,
            "X-Verdictan-Provider: unknown provider target, rejecting"
        );
        return Err(ProviderOrderSelectionError::UnknownProviderPin(
            provider_pin.to_string(),
        ));
    }

    Ok(Some(pinned))
}
