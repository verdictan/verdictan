// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Streaming output governance.
//!
//! Buffers only the minimum complete semantic unit each output policy needs,
//! enforces redaction/block decisions before any client emission, records a
//! stable termination reason, and rejects startup/config when a policy cannot
//! enforce the selected streaming mode.

use super::super::*;
use crate::gateway::sse::{
    self, encode_sse_data_frame, extract_sse_semantic_unit, messages_text_to_sse,
    rewrite_messages_delta_text, SseSemanticUnit, StreamingFamily,
};

use super::*;

/// Selected streaming emission mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamingOutputMode {
    /// Emit complete SSE frames as soon as they arrive (no output policy).
    Passthrough,
    /// Buffer to the policy's minimum semantic unit, then allow or block.
    BufferedPolicy,
    /// Buffer the complete response text, redact, then emit.
    BufferedRedaction,
}

impl StreamingOutputMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passthrough => "passthrough",
            Self::BufferedPolicy => "buffered_policy",
            Self::BufferedRedaction => "buffered_redaction",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "passthrough" => Some(Self::Passthrough),
            "buffered_policy" => Some(Self::BufferedPolicy),
            "buffered_redaction" => Some(Self::BufferedRedaction),
            _ => None,
        }
    }
}

impl std::fmt::Display for StreamingOutputMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Minimum complete semantic unit required before emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamingSemanticUnitKind {
    /// One finished SSE data frame / event.
    SseEvent,
    /// Full assistant text for the stream (required by spanning redaction).
    CompleteResponse,
}

impl StreamingSemanticUnitKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SseEvent => "sse_event",
            Self::CompleteResponse => "complete_response",
        }
    }
}

/// Stable stream termination reason recorded for evidence / settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamTerminationReason {
    Completed,
    PolicyBlock { reason_code: String },
    PolicyRedactApplied { reason_code: String },
    UpstreamInterrupted { reason_code: String },
    ClientDisconnected,
    StartupRejected { reason_code: String },
}

impl StreamTerminationReason {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Completed => "stream.completed",
            Self::PolicyBlock { reason_code } => reason_code.as_str(),
            Self::PolicyRedactApplied { reason_code } => reason_code.as_str(),
            Self::UpstreamInterrupted { reason_code } => reason_code.as_str(),
            Self::ClientDisconnected => "stream.client_disconnected",
            Self::StartupRejected { reason_code } => reason_code.as_str(),
        }
    }

    pub fn is_policy_terminal(&self) -> bool {
        matches!(
            self,
            Self::PolicyBlock { .. }
                | Self::PolicyRedactApplied { .. }
                | Self::StartupRejected { .. }
        )
    }
}

/// Startup / configuration rejection when streaming cannot be enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingStartupError {
    pub reason_code: String,
    pub message: String,
    pub policy_kind: Option<String>,
}

impl std::fmt::Display for StreamingStartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason_code, self.message)
    }
}

impl std::error::Error for StreamingStartupError {}

/// Planned streaming enforcement derived from the active output policy set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingEnforcementPlan {
    pub mode: StreamingOutputMode,
    pub semantic_unit: StreamingSemanticUnitKind,
    pub requires_block_check: bool,
    pub requires_redaction: bool,
    pub driving_policies: Vec<String>,
}

/// Decision produced for one evaluable semantic unit before emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamingUnitDecision {
    Allow {
        emit_payload: String,
    },
    Redact {
        emit_payload: String,
        reason_code: String,
    },
    Block {
        reason_code: String,
        message: String,
    },
    Hold,
}

/// What the governor is allowed to send to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamingEmission {
    Frame(Bytes),
    TerminalError { reason_code: String, body: Bytes },
}

const STREAMING_UNENFORCEABLE_OUTPUT_POLICIES: &[&str] = &[
    // Output-phase language validation has no streaming evaluator.
    "language-validator",
    // Review queues have no streaming decision path.
    "flagged-review",
];

fn policy_requires_redaction(kind: &str, policy_blocks: &crate::gateway::PolicyBlocks) -> bool {
    match kind {
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
    }
}

fn policy_requires_block_buffering(kind: &str) -> bool {
    matches!(
        kind,
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
}

fn language_validator_requires_output(policy_blocks: &crate::gateway::PolicyBlocks) -> bool {
    policy_blocks
        .get("language-validator")
        .and_then(|value| value.get("apply_to"))
        .and_then(|value| value.as_str())
        .is_some_and(|apply_to| apply_to == "output" || apply_to == "both")
}

fn unenforceable_streaming_policy<'a>(
    policy_chain: &'a [String],
    policy_blocks: &crate::gateway::PolicyBlocks,
) -> Option<&'a str> {
    for kind in policy_chain {
        if kind == "language-validator" && language_validator_requires_output(policy_blocks) {
            return Some(kind.as_str());
        }
        if STREAMING_UNENFORCEABLE_OUTPUT_POLICIES.contains(&kind.as_str())
            && kind != "language-validator"
        {
            return Some(kind.as_str());
        }
    }
    None
}

/// Derive the enforcement plan required by the active output policy chain.
pub fn plan_streaming_enforcement(
    policy_chain: &[String],
    policy_blocks: &crate::gateway::PolicyBlocks,
) -> Result<StreamingEnforcementPlan, StreamingStartupError> {
    if let Some(kind) = unenforceable_streaming_policy(policy_chain, policy_blocks) {
        return Err(StreamingStartupError {
            reason_code: "streaming.policy_cannot_enforce".to_string(),
            message: format!(
                "policy '{kind}' cannot enforce output decisions for streaming responses"
            ),
            policy_kind: Some(kind.to_string()),
        });
    }

    let mut driving_policies = Vec::new();
    let mut requires_redaction = false;
    let mut requires_block_check = false;

    for kind in policy_chain {
        if policy_requires_redaction(kind, policy_blocks) {
            requires_redaction = true;
            driving_policies.push(kind.clone());
        } else if policy_requires_block_buffering(kind) {
            requires_block_check = true;
            driving_policies.push(kind.clone());
        }
    }

    let (mode, semantic_unit) = if requires_redaction {
        (
            StreamingOutputMode::BufferedRedaction,
            StreamingSemanticUnitKind::CompleteResponse,
        )
    } else if requires_block_check {
        (
            StreamingOutputMode::BufferedPolicy,
            StreamingSemanticUnitKind::SseEvent,
        )
    } else {
        (
            StreamingOutputMode::Passthrough,
            StreamingSemanticUnitKind::SseEvent,
        )
    };

    Ok(StreamingEnforcementPlan {
        mode,
        semantic_unit,
        requires_block_check,
        requires_redaction,
        driving_policies,
    })
}

/// Reject startup/config when the selected streaming mode cannot be enforced.
fn validate_streaming_mode_startup(
    policy_chain: &[String],
    policy_blocks: &crate::gateway::PolicyBlocks,
    selected_mode: StreamingOutputMode,
) -> Result<StreamingEnforcementPlan, StreamingStartupError> {
    let required = plan_streaming_enforcement(policy_chain, policy_blocks)?;

    let compatible = match selected_mode {
        StreamingOutputMode::Passthrough => required.mode == StreamingOutputMode::Passthrough,
        StreamingOutputMode::BufferedPolicy => {
            matches!(
                required.mode,
                StreamingOutputMode::Passthrough | StreamingOutputMode::BufferedPolicy
            )
        }
        StreamingOutputMode::BufferedRedaction => true,
    };

    if !compatible {
        return Err(StreamingStartupError {
            reason_code: "streaming.mode_unenforceable".to_string(),
            message: format!(
                "selected streaming mode '{}' cannot enforce required mode '{}' for policies [{}]",
                selected_mode.as_str(),
                required.mode.as_str(),
                required.driving_policies.join(", ")
            ),
            policy_kind: required.driving_policies.first().cloned(),
        });
    }

    Ok(StreamingEnforcementPlan {
        mode: selected_mode,
        semantic_unit: match selected_mode {
            StreamingOutputMode::BufferedRedaction => StreamingSemanticUnitKind::CompleteResponse,
            StreamingOutputMode::BufferedPolicy | StreamingOutputMode::Passthrough => {
                if required.semantic_unit == StreamingSemanticUnitKind::CompleteResponse {
                    StreamingSemanticUnitKind::CompleteResponse
                } else {
                    StreamingSemanticUnitKind::SseEvent
                }
            }
        },
        requires_block_check: required.requires_block_check
            || selected_mode != StreamingOutputMode::Passthrough,
        requires_redaction: required.requires_redaction
            || selected_mode == StreamingOutputMode::BufferedRedaction,
        driving_policies: required.driving_policies,
    })
}

/// Evaluate one complete semantic unit before emission.
pub fn decide_streaming_unit(
    plan: &StreamingEnforcementPlan,
    policy_chain: &[String],
    policy_blocks: &crate::gateway::PolicyBlocks,
    family: StreamingFamily,
    unit: &SseSemanticUnit,
    accumulated_text: &str,
    stream_finished: bool,
) -> StreamingUnitDecision {
    if plan.requires_block_check || plan.mode == StreamingOutputMode::BufferedPolicy {
        if let Some(result) =
            evaluate_streaming_blocking_policy(policy_chain, policy_blocks, accumulated_text)
        {
            return StreamingUnitDecision::Block {
                reason_code: result.reason_code,
                message: "Streaming response blocked by output policy".to_string(),
            };
        }
    }

    match plan.mode {
        StreamingOutputMode::Passthrough => StreamingUnitDecision::Allow {
            emit_payload: unit.payload.clone(),
        },
        StreamingOutputMode::BufferedPolicy => {
            // Emit only after the minimum SSE semantic unit is complete. Hold
            // terminal control until stream end so a late block can still win.
            if unit.is_terminal && !stream_finished {
                StreamingUnitDecision::Hold
            } else {
                StreamingUnitDecision::Allow {
                    emit_payload: unit.payload.clone(),
                }
            }
        }
        StreamingOutputMode::BufferedRedaction => {
            if !stream_finished {
                return StreamingUnitDecision::Hold;
            }
            let redaction_cfg = crate::gateway::redaction::RedactionConfig::from_policy_block(
                policy_blocks.get("pii-detector"),
            );
            let (redacted, _meta, targets) =
                crate::gateway::redaction::redact_with_metadata_and_targets_with_config(
                    accumulated_text,
                    &redaction_cfg,
                    "streaming.output",
                );
            let emit_payload = match family {
                StreamingFamily::Messages => {
                    let stop = unit.finish_reason.as_deref().unwrap_or("end_turn");
                    // Represent the fully evaluated text as Messages SSE.
                    let bytes = messages_text_to_sse("msg_verdictan_buffered", &redacted, stop);
                    String::from_utf8_lossy(&bytes).into_owned()
                }
                StreamingFamily::ChatCompletions | StreamingFamily::Responses => {
                    if let Some(rewritten) = rewrite_unit_text(family, &unit.payload, &redacted)
                        .or_else(|| {
                            // Fall back to a synthetic chat frame when the terminal
                            // unit has no rewriteable text field.
                            Some(redacted.clone())
                        })
                    {
                        rewritten
                    } else {
                        redacted.clone()
                    }
                }
            };
            if targets.is_empty() {
                StreamingUnitDecision::Allow { emit_payload }
            } else {
                StreamingUnitDecision::Redact {
                    emit_payload,
                    reason_code: "redact.applied".to_string(),
                }
            }
        }
    }
}

fn rewrite_unit_text(family: StreamingFamily, payload: &str, replacement: &str) -> Option<String> {
    match family {
        StreamingFamily::ChatCompletions => {
            sse::rewrite_chat_completion_delta_text(payload, replacement)
        }
        StreamingFamily::Responses => sse::rewrite_responses_delta_text(payload, replacement),
        StreamingFamily::Messages => rewrite_messages_delta_text(payload, replacement),
    }
}

fn emission_from_payload(payload: &str) -> StreamingEmission {
    if payload.contains("\n\ndata:") || payload.starts_with("data:") {
        StreamingEmission::Frame(Bytes::from(payload.to_string()))
    } else {
        StreamingEmission::Frame(encode_sse_data_frame(payload))
    }
}

/// Stateful governor that buffers semantic units and emits only after decisions.
#[derive(Debug)]
pub struct StreamingOutputGovernor {
    pub family: StreamingFamily,
    pub plan: StreamingEnforcementPlan,
    pub policy_chain: Vec<String>,
    pub policy_blocks: crate::gateway::PolicyBlocks,
    parser_buffer: Vec<u8>,
    accumulated_text: String,
    finish_reason: Option<String>,
    held_units: Vec<SseSemanticUnit>,
    termination: Option<StreamTerminationReason>,
    units_emitted: usize,
}

impl StreamingOutputGovernor {
    pub fn new(
        family: StreamingFamily,
        plan: StreamingEnforcementPlan,
        policy_chain: Vec<String>,
        policy_blocks: crate::gateway::PolicyBlocks,
    ) -> Self {
        Self {
            family,
            plan,
            policy_chain,
            policy_blocks,
            parser_buffer: Vec::new(),
            accumulated_text: String::new(),
            finish_reason: None,
            held_units: Vec::new(),
            termination: None,
            units_emitted: 0,
        }
    }

    pub fn termination_reason(&self) -> Option<&StreamTerminationReason> {
        self.termination.as_ref()
    }

    pub fn accumulated_text(&self) -> &str {
        &self.accumulated_text
    }

    pub fn finish_reason(&self) -> Option<&str> {
        self.finish_reason.as_deref()
    }

    pub fn units_emitted(&self) -> usize {
        self.units_emitted
    }

    /// Ingest upstream bytes. Returns emissions that are safe to send now.
    pub fn ingest_chunk(&mut self, chunk: &[u8]) -> Vec<StreamingEmission> {
        if self.termination.is_some() {
            return Vec::new();
        }

        self.parser_buffer.extend_from_slice(chunk);
        let payloads = sse::drain_sse_data_frames(&mut self.parser_buffer);
        let mut emissions = Vec::new();

        for payload in payloads {
            let Some(unit) = extract_sse_semantic_unit(self.family, &payload) else {
                if self.plan.mode == StreamingOutputMode::Passthrough {
                    emissions.push(StreamingEmission::Frame(encode_sse_data_frame(&payload)));
                    self.units_emitted += 1;
                }
                continue;
            };

            if !unit.text_delta.is_empty() {
                self.accumulated_text.push_str(&unit.text_delta);
            }
            if let Some(reason) = unit.finish_reason.clone() {
                self.finish_reason = Some(reason);
            }

            match decide_streaming_unit(
                &self.plan,
                &self.policy_chain,
                &self.policy_blocks,
                self.family,
                &unit,
                &self.accumulated_text,
                false,
            ) {
                StreamingUnitDecision::Allow { emit_payload } => {
                    emissions.push(emission_from_payload(&emit_payload));
                    self.units_emitted += 1;
                }
                StreamingUnitDecision::Redact {
                    emit_payload,
                    reason_code,
                } => {
                    emissions.push(emission_from_payload(&emit_payload));
                    self.units_emitted += 1;
                    self.termination =
                        Some(StreamTerminationReason::PolicyRedactApplied { reason_code });
                }
                StreamingUnitDecision::Block {
                    reason_code,
                    message,
                } => {
                    let body = Bytes::from(format!(
                        "data: {}\n\n",
                        serde_json::json!({
                            "error": {
                                "message": message,
                                "type": "invalid_request_error",
                                "code": "content_policy_violation",
                            },
                            "verdictan": {
                                "verdict": "BLOCK",
                                "reason_code": reason_code,
                                "streaming_termination_reason": reason_code,
                            }
                        })
                    ));
                    emissions.push(StreamingEmission::TerminalError {
                        reason_code: reason_code.clone(),
                        body,
                    });
                    self.termination = Some(StreamTerminationReason::PolicyBlock { reason_code });
                    return emissions;
                }
                StreamingUnitDecision::Hold => {
                    self.held_units.push(unit);
                }
            }
        }

        emissions
    }

    /// Finish the stream: flush held units / apply complete-response policies.
    pub fn finish(&mut self) -> Vec<StreamingEmission> {
        if self.termination.is_some() {
            return Vec::new();
        }

        let mut emissions = Vec::new();
        let terminal_unit = SseSemanticUnit {
            family: self.family,
            payload: "[DONE]".to_string(),
            text_delta: String::new(),
            is_terminal: true,
            finish_reason: self.finish_reason.clone(),
        };

        match decide_streaming_unit(
            &self.plan,
            &self.policy_chain,
            &self.policy_blocks,
            self.family,
            &terminal_unit,
            &self.accumulated_text,
            true,
        ) {
            StreamingUnitDecision::Allow { emit_payload } => {
                if self.plan.mode == StreamingOutputMode::BufferedRedaction {
                    emissions.push(emission_from_payload(&emit_payload));
                    self.units_emitted += 1;
                } else {
                    for unit in self.held_units.drain(..) {
                        emissions.push(emission_from_payload(&unit.payload));
                        self.units_emitted += 1;
                    }
                }
                self.termination = Some(StreamTerminationReason::Completed);
            }
            StreamingUnitDecision::Redact {
                emit_payload,
                reason_code,
            } => {
                emissions.push(emission_from_payload(&emit_payload));
                self.units_emitted += 1;
                self.termination =
                    Some(StreamTerminationReason::PolicyRedactApplied { reason_code });
            }
            StreamingUnitDecision::Block {
                reason_code,
                message,
            } => {
                let body = Bytes::from(format!(
                    "data: {}\n\n",
                    serde_json::json!({
                        "error": {
                            "message": message,
                            "type": "invalid_request_error",
                            "code": "content_policy_violation",
                        },
                        "verdictan": {
                            "verdict": "BLOCK",
                            "reason_code": reason_code,
                            "streaming_termination_reason": reason_code,
                        }
                    })
                ));
                emissions.push(StreamingEmission::TerminalError {
                    reason_code: reason_code.clone(),
                    body,
                });
                self.termination = Some(StreamTerminationReason::PolicyBlock { reason_code });
            }
            StreamingUnitDecision::Hold => {
                for unit in self.held_units.drain(..) {
                    emissions.push(emission_from_payload(&unit.payload));
                    self.units_emitted += 1;
                }
                self.termination = Some(StreamTerminationReason::Completed);
            }
        }

        emissions
    }

    pub fn mark_upstream_interrupted(&mut self, reason_code: &str) {
        if self.termination.is_none() {
            self.termination = Some(StreamTerminationReason::UpstreamInterrupted {
                reason_code: reason_code.to_string(),
            });
        }
    }

    pub fn mark_client_disconnected(&mut self) {
        if self.termination.is_none() {
            self.termination = Some(StreamTerminationReason::ClientDisconnected);
        }
    }
}

pub(crate) fn build_messages_connected_streaming_response(
    response: PreparedStreamingResponse,
    state: &ActiveGatewayStateView<'_>,
    request_body_bytes: Bytes,
    request_id: &str,
    traceparent: &str,
    served_provider_id: Option<String>,
    access_dispatch_ctx: ConnectedAccessDispatchContext,
) -> Response<Body> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(16);
    let request_id_for_task = request_id.to_string();
    let traceparent_for_task = traceparent.to_string();
    let event_sink_for_task = state.event_sink.clone();
    let key_budget_tracker_for_task = Arc::clone(state.key_budget_tracker);
    let access_dispatch_ctx_for_task = access_dispatch_ctx.clone();
    let served_provider_id_for_task = served_provider_id;
    let policy_chain = state.policy_chain.clone();
    let policy_blocks = state.policy_blocks.clone();
    let PreparedStreamingResponse {
        status,
        content_type,
        body,
    } = response;

    tokio::spawn(async move {
        let stream_start = Instant::now();
        let plan = match plan_streaming_enforcement(&policy_chain, &policy_blocks) {
            Ok(plan) => plan,
            Err(error) => {
                let body = Bytes::from(format!(
                    "data: {}\n\n",
                    serde_json::json!({
                        "error": {
                            "message": error.message,
                            "type": "invalid_request_error",
                            "code": error.reason_code,
                        }
                    })
                ));
                let _ = tx.send(Ok(body)).await;
                let _ = tx.send(Ok(Bytes::from_static(b"data: [DONE]\n\n"))).await;
                return;
            }
        };

        let mut governor = StreamingOutputGovernor::new(
            StreamingFamily::Messages,
            plan,
            policy_chain,
            policy_blocks,
        );
        let mut upstream_stream = body;

        while let Some(chunk) = upstream_stream.next().await {
            match chunk {
                Ok(chunk) => {
                    // Always emit through the governor so incomplete SSE frames
                    // never leave before a complete semantic unit is decided.
                    for emission in governor.ingest_chunk(&chunk) {
                        match emission {
                            StreamingEmission::Frame(bytes) => {
                                if tx.send(Ok(bytes)).await.is_err() {
                                    governor.mark_client_disconnected();
                                    return;
                                }
                            }
                            StreamingEmission::TerminalError { body, .. } => {
                                let _ = tx.send(Ok(body)).await;
                                let _ = tx.send(Ok(Bytes::from_static(b"data: [DONE]\n\n"))).await;
                                finalize_connected_post_dispatch_accounting(
                                    event_sink_for_task.as_ref(),
                                    &key_budget_tracker_for_task,
                                    &request_body_bytes,
                                    resolve_streaming_post_dispatch_usage(
                                        &request_body_bytes,
                                        Some(governor.accumulated_text()),
                                        governor.accumulated_text().chars().count(),
                                    ),
                                    &access_dispatch_ctx_for_task,
                                    &request_id_for_task,
                                    &traceparent_for_task,
                                    served_provider_id_for_task.as_deref(),
                                    Some(stream_start.elapsed().as_millis() as i64),
                                );
                                return;
                            }
                        }
                    }
                }
                Err(error) => {
                    let reason = if error.kind() == io::ErrorKind::TimedOut {
                        "proxy.upstream_stream_timeout"
                    } else {
                        "proxy.upstream_stream_interrupted"
                    };
                    governor.mark_upstream_interrupted(reason);
                    let _ = tx.send(Err(error)).await;
                    finalize_connected_post_dispatch_accounting(
                        event_sink_for_task.as_ref(),
                        &key_budget_tracker_for_task,
                        &request_body_bytes,
                        resolve_streaming_post_dispatch_usage(
                            &request_body_bytes,
                            Some(governor.accumulated_text()),
                            governor.accumulated_text().chars().count(),
                        ),
                        &access_dispatch_ctx_for_task,
                        &request_id_for_task,
                        &traceparent_for_task,
                        served_provider_id_for_task.as_deref(),
                        Some(stream_start.elapsed().as_millis() as i64),
                    );
                    return;
                }
            }
        }

        for emission in governor.finish() {
            match emission {
                StreamingEmission::Frame(bytes) => {
                    if tx.send(Ok(bytes)).await.is_err() {
                        governor.mark_client_disconnected();
                        break;
                    }
                }
                StreamingEmission::TerminalError { body, .. } => {
                    let _ = tx.send(Ok(body)).await;
                    let _ = tx.send(Ok(Bytes::from_static(b"data: [DONE]\n\n"))).await;
                    break;
                }
            }
        }

        let _ = governor.termination_reason();

        finalize_connected_post_dispatch_accounting(
            event_sink_for_task.as_ref(),
            &key_budget_tracker_for_task,
            &request_body_bytes,
            resolve_streaming_post_dispatch_usage(
                &request_body_bytes,
                Some(governor.accumulated_text()),
                governor.accumulated_text().chars().count(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn blocks_with(entries: &[(&str, serde_json::Value)]) -> crate::gateway::PolicyBlocks {
        let mut blocks = crate::gateway::PolicyBlocks::new();
        for (kind, value) in entries {
            blocks.insert((*kind).to_string(), value.clone());
        }
        blocks
    }

    #[test]
    fn plan_buffers_minimum_unit_for_block_and_redaction_policies() {
        let blocks = blocks_with(&[]);
        let block_plan =
            plan_streaming_enforcement(&["safety-filter".to_string()], &blocks).expect("plan");
        assert_eq!(block_plan.mode, StreamingOutputMode::BufferedPolicy);
        assert_eq!(
            block_plan.semantic_unit,
            StreamingSemanticUnitKind::SseEvent
        );

        let redact_plan = plan_streaming_enforcement(
            &["pii-detector".to_string()],
            &blocks_with(&[("pii-detector", json!({ "action": "redact" }))]),
        )
        .expect("plan");
        assert_eq!(redact_plan.mode, StreamingOutputMode::BufferedRedaction);
        assert_eq!(
            redact_plan.semantic_unit,
            StreamingSemanticUnitKind::CompleteResponse
        );

        let passthrough =
            plan_streaming_enforcement(&["audit-logger".to_string()], &blocks).expect("plan");
        assert_eq!(passthrough.mode, StreamingOutputMode::Passthrough);
    }

    #[test]
    fn startup_rejects_when_policy_cannot_enforce_selected_mode() {
        let err = validate_streaming_mode_startup(
            &["pii-detector".to_string()],
            &blocks_with(&[("pii-detector", json!({ "action": "redact" }))]),
            StreamingOutputMode::Passthrough,
        )
        .expect_err("passthrough cannot enforce redaction");
        assert_eq!(err.reason_code, "streaming.mode_unenforceable");

        let err = plan_streaming_enforcement(
            &["language-validator".to_string()],
            &blocks_with(&[("language-validator", json!({ "apply_to": "output" }))]),
        )
        .expect_err("language-validator output cannot stream");
        assert_eq!(err.reason_code, "streaming.policy_cannot_enforce");
        assert_eq!(err.policy_kind.as_deref(), Some("language-validator"));

        let err = plan_streaming_enforcement(&["flagged-review".to_string()], &blocks_with(&[]))
            .expect_err("flagged-review cannot stream");
        assert_eq!(err.reason_code, "streaming.policy_cannot_enforce");
    }

    #[test]
    fn governor_blocks_before_emission_and_records_termination_reason() {
        let plan = plan_streaming_enforcement(
            &["safety-filter".to_string()],
            &blocks_with(&[(
                "safety-filter",
                json!({
                    "mode": "critical_infrastructure",
                    "action": "block",
                    "block_if": ["weapon"]
                }),
            )]),
        )
        .expect("plan");
        let mut governor = StreamingOutputGovernor::new(
            StreamingFamily::Messages,
            plan,
            vec!["safety-filter".to_string()],
            blocks_with(&[(
                "safety-filter",
                json!({
                    "mode": "critical_infrastructure",
                    "action": "block",
                    "block_if": ["weapon"]
                }),
            )]),
        );

        let safe = governor.ingest_chunk(
            br#"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello "}}

"#,
        );
        assert_eq!(safe.len(), 1);
        assert!(matches!(safe[0], StreamingEmission::Frame(_)));
        assert!(governor.termination_reason().is_none());

        let blocked = governor.ingest_chunk(
            br#"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"weapon plans"}}

"#,
        );
        assert_eq!(blocked.len(), 1);
        match &blocked[0] {
            StreamingEmission::TerminalError { reason_code, body } => {
                assert!(reason_code.starts_with("safety.triggered"));
                let text = String::from_utf8_lossy(body);
                assert!(text.contains("content_policy_violation"));
                assert!(!text.contains("weapon plans"));
            }
            StreamingEmission::Frame(_) => panic!("expected terminal block before emission"),
        }
        assert!(matches!(
            governor.termination_reason(),
            Some(StreamTerminationReason::PolicyBlock { .. })
        ));
    }

    #[test]
    fn governor_redacts_complete_response_before_emission() {
        let blocks = blocks_with(&[("pii-detector", json!({ "action": "redact" }))]);
        let plan =
            plan_streaming_enforcement(&["pii-detector".to_string()], &blocks).expect("plan");
        let mut governor = StreamingOutputGovernor::new(
            StreamingFamily::Messages,
            plan,
            vec!["pii-detector".to_string()],
            blocks,
        );

        let held = governor.ingest_chunk(
            br#"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Contact alice@example.com"}}

"#,
        );
        assert!(held.is_empty(), "redaction must not emit partial units");
        assert!(governor.termination_reason().is_none());

        let finished = governor.finish();
        assert_eq!(finished.len(), 1);
        match &finished[0] {
            StreamingEmission::Frame(bytes) => {
                let text = String::from_utf8_lossy(bytes);
                assert!(text.contains("[REDACTED:EMAIL]") || text.contains("REDACTED"));
                assert!(!text.contains("alice@example.com"));
            }
            StreamingEmission::TerminalError { .. } => panic!("expected redacted frame"),
        }
        assert!(matches!(
            governor.termination_reason(),
            Some(StreamTerminationReason::PolicyRedactApplied { .. })
                | Some(StreamTerminationReason::Completed)
        ));
    }

    #[test]
    fn partial_sse_bytes_are_not_treated_as_semantic_units() {
        let plan = plan_streaming_enforcement(&[], &blocks_with(&[])).expect("plan");
        let mut governor = StreamingOutputGovernor::new(
            StreamingFamily::ChatCompletions,
            plan,
            Vec::new(),
            blocks_with(&[]),
        );
        let partial = governor.ingest_chunk(
            br#"data: {"choices":[{"delta":{"content":"hel"},"finish_reason":null}]}"#,
        );
        assert!(partial.is_empty());
        let complete = governor.ingest_chunk(b"\n\n");
        assert_eq!(complete.len(), 1);
    }
}
