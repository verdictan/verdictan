// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! WebSocket family handlers with authenticate-once frame governance.
//!
//! Handshake authentication runs exactly once via `build_public_request_state`.
//! Each complete text frame is evaluated before upstream forward / client emission;
//! binary frames are rejected with `policy.unsupported_transport`.

use super::super::*;
use crate::gateway::websocket_proxy::{
    self, classify_text_frame, FrameDecisionEvidence, FrameDirection, FrameGovernDecision,
    FrameKind, WebSocketFrameGovernor, CLOSE_POLICY_VIOLATION, POLICY_UNSUPPORTED_TRANSPORT,
};

use super::*;

/// Session governor built after handshake auth; never re-authenticates.
struct PolicySessionFrameGovernor {
    authenticated_once: bool,
    path: &'static str,
    request_id: String,
    config_version: String,
    chain_entries: Vec<enforcement::ChainEntry>,
    policy_blocks: crate::gateway::PolicyBlocks,
    policy_headers: HeaderMap,
    authenticated_identity: Option<crate::gateway::identity::AuthenticatedRequestIdentity>,
    request_finops: Option<RequestFinopsContext>,
    event_sink: Option<EventSink>,
    agent_id: Option<String>,
    session_id: Option<String>,
    evidence_log: Vec<FrameDecisionEvidence>,
}

impl PolicySessionFrameGovernor {
    fn from_handshake(
        state: &ActiveGatewayStateView<'_>,
        headers: &HeaderMap,
        path: &'static str,
        request_id: &str,
    ) -> Self {
        // Authenticate-once: identity/finops already resolved at handshake.
        let request_resolution = resolve_request(path, "GET", headers, state);
        // SEC-009: team selectors come from authenticated finops memberships;
        // X-Verdictan-Team is only a local unauthenticated profile selector.
        let request_team_slugs = resolve_request_team_slugs(
            headers,
            state.request_finops.as_ref(),
            !state.connected_mode,
        );
        let chain_entries =
            effective_chain_for_request(state, &request_resolution, &request_team_slugs);
        let policy_headers = policy_input_headers(headers, state.request_finops.as_ref());
        let authenticated_identity = state
            .request_finops
            .as_ref()
            .and_then(|finops| finops.authenticated_identity.clone());
        Self {
            authenticated_once: true,
            path,
            request_id: request_id.to_string(),
            config_version: state.config_version.clone(),
            chain_entries,
            policy_blocks: state.policy_blocks.clone(),
            policy_headers,
            authenticated_identity,
            request_finops: state.request_finops.clone(),
            event_sink: state.event_sink.clone(),
            agent_id: state.registered_agent_id().map(str::to_string),
            session_id: state.session_id.clone(),
            evidence_log: Vec::new(),
        }
    }

    async fn evaluate_text(
        &self,
        frame_seq: u64,
        direction: FrameDirection,
        text: &str,
    ) -> FrameGovernDecision {
        let stage = match direction {
            FrameDirection::ClientToUpstream => enforcement::ExecutionStage::PreRequest,
            FrameDirection::UpstreamToClient => enforcement::ExecutionStage::PreResponse,
        };

        let (kind, request_json, messages) = match classify_text_frame(text) {
            websocket_proxy::TextFrameClass::CompleteJson(value) => {
                let messages = messages_for_path(self.path, Some(&value), text.as_bytes());
                (FrameKind::TextJson, Some(value), messages)
            }
            websocket_proxy::TextFrameClass::IncompleteJson => {
                return FrameGovernDecision::Block {
                    close_code: CLOSE_POLICY_VIOLATION,
                    evidence: FrameDecisionEvidence {
                        frame_seq,
                        direction,
                        kind: FrameKind::IncompleteJson,
                        decision: "block".into(),
                        reason_code: "request.validation_failed".into(),
                        authenticated_once: self.authenticated_once,
                        details: serde_json::json!({
                            "path": self.path,
                            "note": "incomplete_or_malformed_json_frame",
                            "stage": stage.as_str(),
                        }),
                    },
                };
            }
            websocket_proxy::TextFrameClass::NonJson => {
                let synthetic = serde_json::json!({ "content": text });
                let messages = messages_for_path(self.path, Some(&synthetic), text.as_bytes());
                (FrameKind::TextNonJson, Some(synthetic), messages)
            }
        };

        let decision = if self.chain_entries.is_empty() {
            DecisionEnvelope {
                final_verdict: Verdict::Allow,
                reason_code: "ok".to_string(),
                results: Vec::new(),
            }
        } else {
            let response_json = match direction {
                FrameDirection::UpstreamToClient => request_json.as_ref(),
                FrameDirection::ClientToUpstream => None,
            };
            enforcement::evaluate_chain_entries_for_stage_with_identity(
                &self.chain_entries,
                stage,
                self.path,
                &self.policy_blocks,
                request_json.as_ref(),
                response_json,
                &self.policy_headers,
                &messages,
                self.authenticated_identity.as_ref(),
            )
            .await
        };

        let evidence = FrameDecisionEvidence {
            frame_seq,
            direction,
            kind,
            decision: decision.final_verdict.to_string(),
            reason_code: decision.reason_code.clone(),
            authenticated_once: self.authenticated_once,
            details: serde_json::json!({
                "path": self.path,
                "stage": stage.as_str(),
                "policy_results": decision.results.iter().map(|r| {
                    serde_json::json!({
                        "policy_kind": r.policy_kind,
                        "phase": r.phase,
                        "verdict": r.verdict.to_string(),
                        "reason_code": r.reason_code,
                    })
                }).collect::<Vec<_>>(),
            }),
        };

        match decision.final_verdict {
            Verdict::Block => FrameGovernDecision::Block {
                close_code: CLOSE_POLICY_VIOLATION,
                evidence,
            },
            Verdict::Allow | Verdict::Redact | Verdict::Escalate => FrameGovernDecision::Allow {
                forward_text: text.to_string(),
                evidence,
            },
        }
    }

    fn emit_frame_evidence(&self, evidence: &FrameDecisionEvidence) {
        let Some(sink) = self.event_sink.as_ref() else {
            return;
        };
        let mut envelope = DecisionEnvelope {
            final_verdict: match evidence.decision.as_str() {
                "block" => Verdict::Block,
                "redact" => Verdict::Redact,
                "escalate" => Verdict::Escalate,
                _ => Verdict::Allow,
            },
            reason_code: evidence.reason_code.clone(),
            results: vec![enforcement::PolicyResult {
                policy_kind: "websocket-frame-policy".into(),
                phase: evidence.direction.as_str().into(),
                verdict: match evidence.decision.as_str() {
                    "block" | "unsupported_transport" => Verdict::Block,
                    "redact" => Verdict::Redact,
                    "escalate" => Verdict::Escalate,
                    _ => Verdict::Allow,
                },
                reason_code: evidence.reason_code.clone(),
                details: Some(evidence.to_json()),
                redaction_targets: None,
            }],
        };
        if evidence.reason_code == POLICY_UNSUPPORTED_TRANSPORT {
            envelope.final_verdict = Verdict::Block;
            envelope.reason_code = POLICY_UNSUPPORTED_TRANSPORT.into();
        }
        let mut event = decision_event_json(
            &self.config_version,
            &self.request_id,
            &envelope,
            false,
            false,
            String::new(),
            None,
            self.agent_id.as_deref(),
            self.request_finops.as_ref(),
            self.session_id.as_deref(),
        );
        if let Some(details) = event.get_mut("details").and_then(|v| v.as_object_mut()) {
            details.insert("websocket_frame".to_string(), evidence.to_json());
        }
        sink.enqueue_decision(&self.request_id, event);
    }
}

impl WebSocketFrameGovernor for PolicySessionFrameGovernor {
    fn authenticated_once(&self) -> bool {
        self.authenticated_once
    }

    async fn evaluate_client_text(&mut self, frame_seq: u64, text: &str) -> FrameGovernDecision {
        self.evaluate_text(frame_seq, FrameDirection::ClientToUpstream, text)
            .await
    }

    async fn evaluate_upstream_text(&mut self, frame_seq: u64, text: &str) -> FrameGovernDecision {
        self.evaluate_text(frame_seq, FrameDirection::UpstreamToClient, text)
            .await
    }

    fn reject_binary(&mut self, frame_seq: u64, direction: FrameDirection) -> FrameGovernDecision {
        let evidence = FrameDecisionEvidence {
            frame_seq,
            direction,
            kind: FrameKind::Binary,
            decision: "unsupported_transport".into(),
            reason_code: POLICY_UNSUPPORTED_TRANSPORT.into(),
            authenticated_once: self.authenticated_once,
            details: serde_json::json!({
                "path": self.path,
                "transport": "websocket",
                "frame": "binary",
            }),
        };
        FrameGovernDecision::UnsupportedTransport { evidence }
    }

    fn append_evidence(&mut self, evidence: FrameDecisionEvidence) {
        self.emit_frame_evidence(&evidence);
        self.evidence_log.push(evidence);
    }
}

fn messages_for_path(
    path: &str,
    json: Option<&serde_json::Value>,
    raw: &[u8],
) -> Vec<enforcement::ChatMessage> {
    if path.contains("/responses") {
        let messages = extract_messages_for_responses(json);
        if !messages.is_empty() {
            return messages;
        }
    }
    let from_value = extract_messages_from_value(json);
    if !from_value.is_empty() {
        return from_value;
    }
    output_messages_for_stage(json, &Bytes::copy_from_slice(raw))
}

pub(crate) async fn chat_completions_ws(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    let x_request_id_in = headers.get("X-Request-Id").and_then(|v| v.to_str().ok());
    let request_id = match request_id::validate_or_generate_x_request_id(x_request_id_in) {
        Ok(id) => id,
        Err(err) => return reject_invalid_x_request_id(&headers, &err),
    };
    let traceparent_in = headers.get("traceparent").and_then(|v| v.to_str().ok());
    let traceparent = request_id::normalize_or_generate_traceparent(traceparent_in);

    let permit = match state
        .admission_controller
        .try_admit("ws", "chat_completions")
    {
        Ok(p) => p,
        Err(denied) => {
            return build_request_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                &request_id,
                &traceparent,
                &denied.to_string(),
                "rate_limit_error",
                "admission_denied",
            );
        }
    };

    // Authenticate once at handshake; frame governor never re-authenticates.
    let mut state_view =
        match build_public_request_state(&state, &headers, peer_addr, &request_id, &traceparent)
            .await
        {
            Ok(state_view) => state_view,
            Err(response) => return response,
        };
    let synthetic_body = match prepare_connected_websocket_ua_lifecycle(
        &mut state_view,
        &headers,
        "/v1/chat/completions",
        &request_id,
        &traceparent,
    )
    .await
    {
        Ok(body) => body,
        Err(response) => return response,
    };
    let ua_financial_path_active = ua_financial_path_active(&state_view);
    let ua_authorization_id = state_view.ua_authorization_id.clone();
    let ua_dispatch_acquired = state_view.ua_dispatch_acquired;
    let event_sink = state_view.event_sink.clone();
    let current_agent_id = state_view.current_agent_id.clone();
    let org_id = ua_org_id_from_finops(state_view.request_finops.as_ref());
    let frame_governor = PolicySessionFrameGovernor::from_handshake(
        &state_view,
        &headers,
        "/v1/chat/completions",
        &request_id,
    );
    let upstream = match resolve_websocket_upstream_target(
        &state_view,
        &headers,
        "/v1/chat/completions",
        &request_id,
        &traceparent,
    )
    .await
    {
        Ok(upstream) => upstream,
        Err(response) => return response,
    };
    let on_session_close = build_websocket_ua_session_closeout(
        ua_financial_path_active,
        ua_authorization_id,
        ua_dispatch_acquired,
        event_sink,
        synthetic_body.unwrap_or_default(),
        current_agent_id,
        org_id,
        request_id,
        traceparent,
    );

    websocket_proxy::proxy_upgrade_with_permit(
        ws,
        headers,
        upstream,
        "/v1/chat/completions",
        Some(permit),
        on_session_close,
        frame_governor,
    )
    .await
}

pub(crate) async fn responses_ws(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    let x_request_id_in = headers.get("X-Request-Id").and_then(|v| v.to_str().ok());
    let request_id = match request_id::validate_or_generate_x_request_id(x_request_id_in) {
        Ok(id) => id,
        Err(err) => return reject_invalid_x_request_id(&headers, &err),
    };
    let traceparent_in = headers.get("traceparent").and_then(|v| v.to_str().ok());
    let traceparent = request_id::normalize_or_generate_traceparent(traceparent_in);

    let permit = match state.admission_controller.try_admit("ws", "responses") {
        Ok(p) => p,
        Err(denied) => {
            return build_request_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                &request_id,
                &traceparent,
                &denied.to_string(),
                "rate_limit_error",
                "admission_denied",
            );
        }
    };

    // Authenticate once at handshake; frame governor never re-authenticates.
    let mut state_view =
        match build_public_request_state(&state, &headers, peer_addr, &request_id, &traceparent)
            .await
        {
            Ok(state_view) => state_view,
            Err(response) => return response,
        };
    let synthetic_body = match prepare_connected_websocket_ua_lifecycle(
        &mut state_view,
        &headers,
        "/v1/responses",
        &request_id,
        &traceparent,
    )
    .await
    {
        Ok(body) => body,
        Err(response) => return response,
    };
    let ua_financial_path_active = ua_financial_path_active(&state_view);
    let ua_authorization_id = state_view.ua_authorization_id.clone();
    let ua_dispatch_acquired = state_view.ua_dispatch_acquired;
    let event_sink = state_view.event_sink.clone();
    let current_agent_id = state_view.current_agent_id.clone();
    let org_id = ua_org_id_from_finops(state_view.request_finops.as_ref());
    let frame_governor = PolicySessionFrameGovernor::from_handshake(
        &state_view,
        &headers,
        "/v1/responses",
        &request_id,
    );
    let upstream = match resolve_websocket_upstream_target(
        &state_view,
        &headers,
        "/v1/responses",
        &request_id,
        &traceparent,
    )
    .await
    {
        Ok(upstream) => upstream,
        Err(response) => return response,
    };
    let on_session_close = build_websocket_ua_session_closeout(
        ua_financial_path_active,
        ua_authorization_id,
        ua_dispatch_acquired,
        event_sink,
        synthetic_body.unwrap_or_default(),
        current_agent_id,
        org_id,
        request_id,
        traceparent,
    );

    websocket_proxy::proxy_upgrade_with_permit(
        ws,
        headers,
        upstream,
        "/v1/responses",
        Some(permit),
        on_session_close,
        frame_governor,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::websocket_proxy::{DefaultFrameGovernor, POLICY_UNSUPPORTED_TRANSPORT};

    #[test]
    fn binary_rejection_uses_policy_unsupported_transport() {
        let mut governor = DefaultFrameGovernor::authenticated();
        let decision = WebSocketFrameGovernor::reject_binary(
            &mut governor,
            1,
            FrameDirection::ClientToUpstream,
        );
        match decision {
            FrameGovernDecision::UnsupportedTransport { evidence } => {
                assert_eq!(evidence.reason_code, POLICY_UNSUPPORTED_TRANSPORT);
                assert!(evidence.authenticated_once);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
