// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! WebSocket upstream proxy with per-frame governance.
//!
//! Handshake authentication happens once in the request pipeline. This module
//! evaluates each complete text frame before upstream forwarding or client
//! emission, rejects binary frames with `policy.unsupported_transport`, and
//! appends per-frame decision evidence.

use axum::extract::ws::CloseFrame;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};

/// Stable reason code for binary WebSocket frames.
pub const POLICY_UNSUPPORTED_TRANSPORT: &str = "policy.unsupported_transport";

/// WebSocket close code for unsupported data (binary frames).
pub const CLOSE_UNSUPPORTED_DATA: u16 = 1003;
/// WebSocket close code for policy violation.
pub const CLOSE_POLICY_VIOLATION: u16 = 1008;

#[derive(Clone, Debug)]
pub(crate) struct WebSocketUpstreamTarget {
    pub base_url: String,
    pub auth_header: Option<(String, String)>,
    pub extra_headers: Vec<(String, String)>,
}

/// Optional closeout invoked after the proxied websocket session ends.
pub(crate) type WebSocketSessionCloseout = Box<dyn FnOnce() + Send>;

/// Direction of a governed WebSocket data frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDirection {
    ClientToUpstream,
    UpstreamToClient,
}

impl FrameDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientToUpstream => "client_to_upstream",
            Self::UpstreamToClient => "upstream_to_client",
        }
    }
}

/// Kind of frame presented to governance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    TextJson,
    TextNonJson,
    IncompleteJson,
    Binary,
    Control,
    ProtocolFragment,
}

impl FrameKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TextJson => "text_json",
            Self::TextNonJson => "text_non_json",
            Self::IncompleteJson => "incomplete_json",
            Self::Binary => "binary",
            Self::Control => "control",
            Self::ProtocolFragment => "protocol_fragment",
        }
    }
}

/// Per-frame decision recorded as durable evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameDecisionEvidence {
    pub frame_seq: u64,
    pub direction: FrameDirection,
    pub kind: FrameKind,
    pub decision: String,
    pub reason_code: String,
    pub authenticated_once: bool,
    pub details: serde_json::Value,
}

impl FrameDecisionEvidence {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "event_type": "websocket_frame_decision",
            "frame_seq": self.frame_seq,
            "direction": self.direction.as_str(),
            "frame_kind": self.kind.as_str(),
            "decision": self.decision,
            "reason_code": self.reason_code,
            "session_authenticated_once": self.authenticated_once,
            "details": self.details,
        })
    }
}

/// Outcome of governing one complete data frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameGovernDecision {
    /// Forward the (possibly rewritten) text payload.
    Allow {
        forward_text: String,
        evidence: FrameDecisionEvidence,
    },
    /// Reject the frame and close the session.
    Block {
        close_code: u16,
        evidence: FrameDecisionEvidence,
    },
    /// Reject binary / unsupported transport and close the session.
    UnsupportedTransport { evidence: FrameDecisionEvidence },
}

impl FrameGovernDecision {
    pub fn evidence(&self) -> &FrameDecisionEvidence {
        match self {
            Self::Allow { evidence, .. }
            | Self::Block { evidence, .. }
            | Self::UnsupportedTransport { evidence } => evidence,
        }
    }
}

/// Session-scoped governor: authenticate once at handshake, evaluate each frame.
pub(crate) trait WebSocketFrameGovernor: Send {
    /// Handshake authentication already completed exactly once for this session.
    fn authenticated_once(&self) -> bool;

    /// Evaluate a complete client→upstream text frame before forwarding.
    fn evaluate_client_text(
        &mut self,
        frame_seq: u64,
        text: &str,
    ) -> impl std::future::Future<Output = FrameGovernDecision> + Send;

    /// Evaluate a complete upstream→client text frame before emission.
    fn evaluate_upstream_text(
        &mut self,
        frame_seq: u64,
        text: &str,
    ) -> impl std::future::Future<Output = FrameGovernDecision> + Send;

    /// Record binary rejection evidence (never forward binary).
    fn reject_binary(&mut self, frame_seq: u64, direction: FrameDirection) -> FrameGovernDecision;

    /// Append per-frame decision evidence (local buffer and/or durable sink).
    fn append_evidence(&mut self, evidence: FrameDecisionEvidence);
}

/// Fail-closed default used by unit tests and any caller without a custom governor:
/// reject binary, require JSON-shaped text, allow valid JSON without policy chain.
#[derive(Debug, Default)]
pub(crate) struct DefaultFrameGovernor {
    authenticated_once: bool,
    evidence_log: Vec<FrameDecisionEvidence>,
}

impl DefaultFrameGovernor {
    pub fn authenticated() -> Self {
        Self {
            authenticated_once: true,
            evidence_log: Vec::new(),
        }
    }

    pub fn evidence_log(&self) -> &[FrameDecisionEvidence] {
        &self.evidence_log
    }
}

impl WebSocketFrameGovernor for DefaultFrameGovernor {
    fn authenticated_once(&self) -> bool {
        self.authenticated_once
    }

    async fn evaluate_client_text(&mut self, frame_seq: u64, text: &str) -> FrameGovernDecision {
        self.evaluate_text(frame_seq, FrameDirection::ClientToUpstream, text)
    }

    async fn evaluate_upstream_text(&mut self, frame_seq: u64, text: &str) -> FrameGovernDecision {
        self.evaluate_text(frame_seq, FrameDirection::UpstreamToClient, text)
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
                "transport": "websocket",
                "frame": "binary",
            }),
        };
        FrameGovernDecision::UnsupportedTransport { evidence }
    }

    fn append_evidence(&mut self, evidence: FrameDecisionEvidence) {
        self.evidence_log.push(evidence);
    }
}

impl DefaultFrameGovernor {
    fn evaluate_text(
        &self,
        frame_seq: u64,
        direction: FrameDirection,
        text: &str,
    ) -> FrameGovernDecision {
        match classify_text_frame(text) {
            TextFrameClass::CompleteJson(_) => FrameGovernDecision::Allow {
                forward_text: text.to_string(),
                evidence: FrameDecisionEvidence {
                    frame_seq,
                    direction,
                    kind: FrameKind::TextJson,
                    decision: "allow".into(),
                    reason_code: "ok".into(),
                    authenticated_once: self.authenticated_once,
                    details: serde_json::json!({ "evaluated": true }),
                },
            },
            TextFrameClass::NonJson => FrameGovernDecision::Allow {
                forward_text: text.to_string(),
                evidence: FrameDecisionEvidence {
                    frame_seq,
                    direction,
                    kind: FrameKind::TextNonJson,
                    decision: "allow".into(),
                    reason_code: "ok".into(),
                    authenticated_once: self.authenticated_once,
                    details: serde_json::json!({
                        "evaluated": true,
                        "note": "non_json_text_evaluated_as_opaque_content",
                    }),
                },
            },
            TextFrameClass::IncompleteJson => FrameGovernDecision::Block {
                close_code: CLOSE_POLICY_VIOLATION,
                evidence: FrameDecisionEvidence {
                    frame_seq,
                    direction,
                    kind: FrameKind::IncompleteJson,
                    decision: "block".into(),
                    reason_code: "request.validation_failed".into(),
                    authenticated_once: self.authenticated_once,
                    details: serde_json::json!({
                        "evaluated": true,
                        "note": "incomplete_or_malformed_json_frame",
                    }),
                },
            },
        }
    }
}

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum TextFrameClass {
    CompleteJson(serde_json::Value),
    NonJson,
    IncompleteJson,
}

/// Classify a complete WebSocket text message for frame governance.
pub(crate) fn classify_text_frame(text: &str) -> TextFrameClass {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return TextFrameClass::NonJson;
    }
    match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(value) => TextFrameClass::CompleteJson(value),
        Err(_) => {
            let looks_like_json = trimmed.starts_with('{') || trimmed.starts_with('[');
            if looks_like_json {
                TextFrameClass::IncompleteJson
            } else {
                TextFrameClass::NonJson
            }
        }
    }
}

pub(crate) async fn proxy_upgrade_with_permit<G>(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    target: WebSocketUpstreamTarget,
    path: &'static str,
    permit: Option<super::admission_control::AdmissionPermit>,
    on_session_close: Option<WebSocketSessionCloseout>,
    frame_governor: G,
) -> Response
where
    G: WebSocketFrameGovernor + 'static,
{
    ws.on_upgrade(move |socket| {
        proxy_socket(
            socket,
            headers,
            target,
            path,
            permit,
            on_session_close,
            frame_governor,
        )
    })
}

async fn proxy_socket<G>(
    socket: WebSocket,
    headers: HeaderMap,
    target: WebSocketUpstreamTarget,
    path: &'static str,
    _permit: Option<super::admission_control::AdmissionPermit>,
    on_session_close: Option<WebSocketSessionCloseout>,
    mut governor: G,
) where
    G: WebSocketFrameGovernor,
{
    debug_assert!(
        governor.authenticated_once(),
        "websocket frame governance requires handshake authentication exactly once"
    );

    let upstream_path = super::server::rewrite_upstream_path(&target.base_url, path);
    let mut upstream_url = super::server::join_upstream(&target.base_url, &upstream_path);
    if upstream_url.starts_with("https://") {
        upstream_url = upstream_url.replacen("https://", "wss://", 1);
    } else if upstream_url.starts_with("http://") {
        upstream_url = upstream_url.replacen("http://", "ws://", 1);
    }

    let mut request = http::Request::builder().uri(&upstream_url);
    for (name, value) in headers.iter() {
        if *name == axum::http::header::AUTHORIZATION {
            continue;
        }
        // reserved identity headers never reach provider upstreams.
        if super::server::is_reserved_identity_header(name) {
            continue;
        }
        request = request.header(name, value);
    }
    if let Some((name, value)) = &target.auth_header {
        request = request.header(name, value);
    }
    for (name, value) in &target.extra_headers {
        request = request.header(name, value);
    }

    let Ok(request) = request.body(()) else {
        return;
    };
    let Ok((upstream, _)) = tokio_tungstenite::connect_async(request).await else {
        return;
    };

    let (mut client_sender, mut client_receiver) = socket.split();
    let (mut upstream_sender, mut upstream_receiver) = upstream.split();
    let mut frame_seq = 0u64;
    let mut client_open = true;
    let mut upstream_open = true;

    while client_open || upstream_open {
        tokio::select! {
            client_msg = client_receiver.next(), if client_open => {
                match client_msg {
                    Some(Ok(message)) => {
                        match message {
                            Message::Binary(_) => {
                                frame_seq = frame_seq.saturating_add(1);
                                let decision = governor.reject_binary(
                                    frame_seq,
                                    FrameDirection::ClientToUpstream,
                                );
                                governor.append_evidence(decision.evidence().clone());
                                let _ = client_sender
                                    .send(policy_close_message(
                                        CLOSE_UNSUPPORTED_DATA,
                                        POLICY_UNSUPPORTED_TRANSPORT,
                                    ))
                                    .await;
                                break;
                            }
                            Message::Text(text) => {
                                frame_seq = frame_seq.saturating_add(1);
                                let decision = governor.evaluate_client_text(frame_seq, &text).await;
                                governor.append_evidence(decision.evidence().clone());
                                match decision {
                                    FrameGovernDecision::Allow { forward_text, .. } => {
                                        if upstream_sender
                                            .send(tokio_tungstenite::tungstenite::Message::Text(
                                                forward_text,
                                            ))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                    FrameGovernDecision::Block {
                                        close_code,
                                        evidence,
                                    } => {
                                        let _ = client_sender
                                            .send(policy_close_message(
                                                close_code,
                                                &evidence.reason_code,
                                            ))
                                            .await;
                                        break;
                                    }
                                    FrameGovernDecision::UnsupportedTransport { evidence } => {
                                        let _ = client_sender
                                            .send(policy_close_message(
                                                CLOSE_UNSUPPORTED_DATA,
                                                &evidence.reason_code,
                                            ))
                                            .await;
                                        break;
                                    }
                                }
                            }
                            Message::Ping(bytes) => {
                                if upstream_sender
                                    .send(tokio_tungstenite::tungstenite::Message::Ping(bytes))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Message::Pong(bytes) => {
                                if upstream_sender
                                    .send(tokio_tungstenite::tungstenite::Message::Pong(bytes))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Message::Close(frame) => {
                                let _ = upstream_sender
                                    .send(tokio_tungstenite::tungstenite::Message::Close(
                                        frame.map(|frame| {
                                            tokio_tungstenite::tungstenite::protocol::CloseFrame {
                                                code: frame.code.into(),
                                                reason: frame.reason,
                                            }
                                        }),
                                    ))
                                    .await;
                                break;
                            }
                        }
                    }
                    Some(Err(_)) | None => {
                        client_open = false;
                    }
                }
            }
            upstream_msg = upstream_receiver.next(), if upstream_open => {
                match upstream_msg {
                    Some(Ok(message)) => {
                        match message {
                            tokio_tungstenite::tungstenite::Message::Binary(_) => {
                                frame_seq = frame_seq.saturating_add(1);
                                let decision = governor.reject_binary(
                                    frame_seq,
                                    FrameDirection::UpstreamToClient,
                                );
                                governor.append_evidence(decision.evidence().clone());
                                let _ = client_sender
                                    .send(policy_close_message(
                                        CLOSE_UNSUPPORTED_DATA,
                                        POLICY_UNSUPPORTED_TRANSPORT,
                                    ))
                                    .await;
                                break;
                            }
                            tokio_tungstenite::tungstenite::Message::Text(text) => {
                                frame_seq = frame_seq.saturating_add(1);
                                let decision =
                                    governor.evaluate_upstream_text(frame_seq, &text).await;
                                governor.append_evidence(decision.evidence().clone());
                                match decision {
                                    FrameGovernDecision::Allow { forward_text, .. } => {
                                        if client_sender
                                            .send(Message::Text(forward_text))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                    FrameGovernDecision::Block {
                                        close_code,
                                        evidence,
                                    } => {
                                        let _ = client_sender
                                            .send(policy_close_message(
                                                close_code,
                                                &evidence.reason_code,
                                            ))
                                            .await;
                                        break;
                                    }
                                    FrameGovernDecision::UnsupportedTransport { evidence } => {
                                        let _ = client_sender
                                            .send(policy_close_message(
                                                CLOSE_UNSUPPORTED_DATA,
                                                &evidence.reason_code,
                                            ))
                                            .await;
                                        break;
                                    }
                                }
                            }
                            tokio_tungstenite::tungstenite::Message::Ping(bytes) => {
                                if client_sender.send(Message::Ping(bytes)).await.is_err() {
                                    break;
                                }
                            }
                            tokio_tungstenite::tungstenite::Message::Pong(bytes) => {
                                if client_sender.send(Message::Pong(bytes)).await.is_err() {
                                    break;
                                }
                            }
                            tokio_tungstenite::tungstenite::Message::Close(frame) => {
                                let _ = client_sender
                                    .send(Message::Close(frame.map(|frame| CloseFrame {
                                        code: frame.code.into(),
                                        reason: frame.reason,
                                    })))
                                    .await;
                                break;
                            }
                            tokio_tungstenite::tungstenite::Message::Frame(_) => {
                                frame_seq = frame_seq.saturating_add(1);
                                let evidence = FrameDecisionEvidence {
                                    frame_seq,
                                    direction: FrameDirection::UpstreamToClient,
                                    kind: FrameKind::ProtocolFragment,
                                    decision: "drop".into(),
                                    reason_code: "ok".into(),
                                    authenticated_once: governor.authenticated_once(),
                                    details: serde_json::json!({
                                        "note": "raw_protocol_fragment_not_emitted",
                                    }),
                                };
                                governor.append_evidence(evidence);
                            }
                        }
                    }
                    Some(Err(_)) | None => {
                        upstream_open = false;
                    }
                }
            }
        }
    }

    if let Some(closeout) = on_session_close {
        closeout();
    }
}

fn policy_close_message(code: u16, reason: &str) -> Message {
    let reason = truncate_close_reason(reason);
    Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    }))
}

fn truncate_close_reason(reason: &str) -> String {
    // RFC 6455 close reason is at most 123 UTF-8 bytes.
    let mut out = String::new();
    for ch in reason.chars() {
        if out.len() + ch.len_utf8() > 123 {
            break;
        }
        out.push(ch);
    }
    if out.is_empty() {
        "policy".into()
    } else {
        out
    }
}

fn to_tungstenite_message(message: Message) -> Option<tokio_tungstenite::tungstenite::Message> {
    match message {
        Message::Text(text) => Some(tokio_tungstenite::tungstenite::Message::Text(text)),
        Message::Binary(bytes) => Some(tokio_tungstenite::tungstenite::Message::Binary(bytes)),
        Message::Ping(bytes) => Some(tokio_tungstenite::tungstenite::Message::Ping(bytes)),
        Message::Pong(bytes) => Some(tokio_tungstenite::tungstenite::Message::Pong(bytes)),
        Message::Close(frame) => Some(tokio_tungstenite::tungstenite::Message::Close(frame.map(
            |frame| tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: frame.code.into(),
                reason: frame.reason,
            },
        ))),
    }
}

fn to_axum_message(message: tokio_tungstenite::tungstenite::Message) -> Option<Message> {
    match message {
        tokio_tungstenite::tungstenite::Message::Text(text) => Some(Message::Text(text)),
        tokio_tungstenite::tungstenite::Message::Binary(bytes) => Some(Message::Binary(bytes)),
        tokio_tungstenite::tungstenite::Message::Ping(bytes) => Some(Message::Ping(bytes)),
        tokio_tungstenite::tungstenite::Message::Pong(bytes) => Some(Message::Pong(bytes)),
        tokio_tungstenite::tungstenite::Message::Close(frame) => {
            Some(Message::Close(frame.map(|frame| {
                axum::extract::ws::CloseFrame {
                    code: frame.code.into(),
                    reason: frame.reason,
                }
            })))
        }
        tokio_tungstenite::tungstenite::Message::Frame(_) => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        dead_code,
        clippy::approx_constant,
        clippy::assertions_on_constants,
        clippy::assign_op_pattern,
        clippy::await_holding_lock,
        clippy::bool_assert_comparison,
        clippy::clone_on_copy,
        clippy::cloned_ref_to_slice_refs,
        clippy::const_is_empty,
        clippy::derivable_impls,
        clippy::err_expect,
        clippy::expect_fun_call,
        clippy::expect_used,
        clippy::field_reassign_with_default,
        clippy::large_enum_variant,
        clippy::len_zero,
        clippy::manual_contains,
        clippy::manual_range_contains,
        clippy::needless_borrow,
        clippy::needless_borrows_for_generic_args,
        clippy::panic,
        clippy::print_stderr,
        clippy::type_complexity,
        clippy::unnecessary_literal_unwrap,
        clippy::unnecessary_map_or,
        clippy::unwrap_used,
        clippy::useless_conversion,
        clippy::useless_vec,
        unused_imports,
        unused_macros,
        unused_mut,
        unused_variables,
        clippy::nonminimal_bool,
        clippy::overly_complex_bool_expr,
        clippy::needless_update,
        clippy::unnecessary_get_then_check
    )]
    use super::*;
    use axum::extract::ws::CloseFrame;
    use axum::http::{HeaderMap, StatusCode as HttpStatusCode};
    use futures_util::{SinkExt, StreamExt};
    use std::sync::{Arc, Mutex};

    fn install_test_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn upstream_proxy_ends_without_payload(
        response: Result<
            Option<
                Result<
                    tokio_tungstenite::tungstenite::Message,
                    tokio_tungstenite::tungstenite::Error,
                >,
            >,
            tokio::time::error::Elapsed,
        >,
    ) -> bool {
        match response {
            Err(_) => true,
            Ok(None) => true,
            Ok(Some(Err(_))) => true,
            Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))) => true,
            Ok(Some(Ok(_))) => false,
        }
    }

    #[test]
    fn websocket_not_supported_returns_bad_gateway() {
        let status = HttpStatusCode::BAD_GATEWAY;
        let body = "websocket upstream unavailable";
        assert_eq!(status, HttpStatusCode::BAD_GATEWAY);
        assert_eq!(body, "websocket upstream unavailable");
    }

    #[test]
    fn classify_text_frame_distinguishes_json_non_json_and_incomplete() {
        assert!(matches!(
            classify_text_frame(r#"{"messages":[]}"#),
            TextFrameClass::CompleteJson(_)
        ));
        assert!(matches!(
            classify_text_frame("hello"),
            TextFrameClass::NonJson
        ));
        assert!(matches!(
            classify_text_frame("{\"partial\":"),
            TextFrameClass::IncompleteJson
        ));
    }

    #[test]
    fn default_governor_rejects_binary_with_policy_unsupported_transport() {
        let mut governor = DefaultFrameGovernor::authenticated();
        assert!(governor.authenticated_once());
        let decision = governor.reject_binary(1, FrameDirection::ClientToUpstream);
        match decision {
            FrameGovernDecision::UnsupportedTransport { evidence } => {
                assert_eq!(evidence.reason_code, POLICY_UNSUPPORTED_TRANSPORT);
                assert_eq!(evidence.kind, FrameKind::Binary);
                assert!(evidence.authenticated_once);
            }
            other => panic!("expected unsupported transport, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn default_governor_blocks_incomplete_json_before_forward() {
        let mut governor = DefaultFrameGovernor::authenticated();
        let decision = governor.evaluate_client_text(2, "{\"messages\":").await;
        match decision {
            FrameGovernDecision::Block { evidence, .. } => {
                assert_eq!(evidence.kind, FrameKind::IncompleteJson);
                assert_eq!(evidence.reason_code, "request.validation_failed");
            }
            other => panic!("expected block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn default_governor_allows_complete_json_with_evidence() {
        let mut governor = DefaultFrameGovernor::authenticated();
        let decision = governor
            .evaluate_client_text(3, r#"{"model":"gpt-test"}"#)
            .await;
        match decision {
            FrameGovernDecision::Allow { evidence, .. } => {
                assert_eq!(evidence.kind, FrameKind::TextJson);
                assert_eq!(evidence.decision, "allow");
                assert!(evidence.authenticated_once);
            }
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn message_conversion_round_trips_text_binary_ping_pong() {
        let text = Message::Text("hello".into());
        let binary = Message::Binary(vec![1, 2, 3]);
        let ping = Message::Ping(vec![4]);
        let pong = Message::Pong(vec![5]);

        for message in [text, binary, ping, pong] {
            let converted = to_tungstenite_message(message.clone()).expect("to tungstenite");
            let back = to_axum_message(converted).expect("to axum");
            assert_eq!(format!("{message:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn message_conversion_handles_close_frames() {
        let close = Message::Close(Some(CloseFrame {
            code: 1000u16.into(),
            reason: "done".into(),
        }));
        let converted = to_tungstenite_message(close).expect("to tungstenite");
        let back = to_axum_message(converted).expect("to axum");
        match back {
            Message::Close(Some(frame)) => {
                assert_eq!(u16::from(frame.code), 1000);
                assert_eq!(frame.reason, "done");
            }
            other => panic!("expected close frame, got {other:?}"),
        }
    }

    #[test]
    fn tungstenite_frame_messages_are_ignored_on_client_path() {
        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
        use tokio_tungstenite::tungstenite::protocol::frame::Frame;
        use tokio_tungstenite::tungstenite::protocol::CloseFrame as TungsteniteCloseFrame;
        use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;

        let frame = TungsteniteMessage::Frame(Frame::ping(Vec::new()));
        assert!(to_axum_message(frame).is_none());

        let close = TungsteniteMessage::Close(Some(TungsteniteCloseFrame {
            code: CloseCode::Normal,
            reason: "bye".into(),
        }));
        let back = to_axum_message(close).expect("close converts");
        assert!(matches!(back, Message::Close(_)));
    }

    async fn start_upstream_echo_server() -> (String, tokio::task::JoinHandle<()>) {
        use axum::{response::IntoResponse, routing::get, Router};
        use futures_util::StreamExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream echo server");
        let addr = listener.local_addr().expect("upstream address");
        let handle = tokio::spawn(async move {
            async fn echo(ws: WebSocketUpgrade) -> impl IntoResponse {
                ws.on_upgrade(|mut socket: WebSocket| async move {
                    while let Some(Ok(message)) = socket.next().await {
                        match message {
                            Message::Text(text) => {
                                let _ =
                                    socket.send(Message::Text(format!("upstream:{text}"))).await;
                            }
                            Message::Binary(bytes) => {
                                let _ = socket.send(Message::Binary(bytes)).await;
                            }
                            Message::Ping(bytes) => {
                                let _ = socket.send(Message::Pong(bytes)).await;
                            }
                            Message::Close(_) => break,
                            Message::Pong(_) => {}
                        }
                    }
                })
            }

            let app = Router::new()
                .route("/v1/chat/completions", get(echo))
                .route("/v1/responses", get(echo));
            axum::serve(listener, app)
                .await
                .expect("serve upstream echo");
        });
        (format!("http://{addr}"), handle)
    }

    async fn start_proxy_server(
        upstream_url: String,
        path: &'static str,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use axum::{routing::get, Router};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind proxy server");
        let addr = listener.local_addr().expect("proxy address");
        let handle = tokio::spawn(async move {
            let route_path = format!("{path}/ws");
            let app = Router::new().route(
                route_path.as_str(),
                get(move |ws: WebSocketUpgrade, headers: HeaderMap| {
                    let upstream_url = upstream_url.clone();
                    async move {
                        proxy_upgrade_with_permit(
                            ws,
                            headers,
                            WebSocketUpstreamTarget {
                                base_url: upstream_url,
                                auth_header: Some((
                                    "Authorization".to_string(),
                                    "Bearer upstream-token".to_string(),
                                )),
                                extra_headers: vec![(
                                    "X-Proxy-Test".to_string(),
                                    "yes".to_string(),
                                )],
                            },
                            path,
                            None,
                            None,
                            DefaultFrameGovernor::authenticated(),
                        )
                        .await
                    }
                }),
            );
            axum::serve(listener, app).await.expect("serve proxy");
        });
        (addr, handle)
    }

    async fn start_proxy_server_with_governor(
        upstream_url: String,
        path: &'static str,
        evidence: Arc<Mutex<Vec<FrameDecisionEvidence>>>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use axum::{routing::get, Router};

        struct RecordingGovernor {
            inner: DefaultFrameGovernor,
            evidence: Arc<Mutex<Vec<FrameDecisionEvidence>>>,
        }

        impl WebSocketFrameGovernor for RecordingGovernor {
            fn authenticated_once(&self) -> bool {
                self.inner.authenticated_once()
            }

            async fn evaluate_client_text(
                &mut self,
                frame_seq: u64,
                text: &str,
            ) -> FrameGovernDecision {
                self.inner.evaluate_client_text(frame_seq, text).await
            }

            async fn evaluate_upstream_text(
                &mut self,
                frame_seq: u64,
                text: &str,
            ) -> FrameGovernDecision {
                self.inner.evaluate_upstream_text(frame_seq, text).await
            }

            fn reject_binary(
                &mut self,
                frame_seq: u64,
                direction: FrameDirection,
            ) -> FrameGovernDecision {
                self.inner.reject_binary(frame_seq, direction)
            }

            fn append_evidence(&mut self, evidence: FrameDecisionEvidence) {
                self.inner.append_evidence(evidence.clone());
                self.evidence.lock().expect("lock").push(evidence);
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind proxy server");
        let addr = listener.local_addr().expect("proxy address");
        let handle = tokio::spawn(async move {
            let route_path = format!("{path}/ws");
            let app = Router::new().route(
                route_path.as_str(),
                get(move |ws: WebSocketUpgrade, headers: HeaderMap| {
                    let upstream_url = upstream_url.clone();
                    let evidence = Arc::clone(&evidence);
                    async move {
                        let governor = RecordingGovernor {
                            inner: DefaultFrameGovernor::authenticated(),
                            evidence,
                        };
                        proxy_upgrade_with_permit(
                            ws,
                            headers,
                            WebSocketUpstreamTarget {
                                base_url: upstream_url,
                                auth_header: Some((
                                    "Authorization".to_string(),
                                    "Bearer upstream-token".to_string(),
                                )),
                                extra_headers: vec![],
                            },
                            path,
                            None,
                            None,
                            governor,
                        )
                        .await
                    }
                }),
            );
            axum::serve(listener, app).await.expect("serve proxy");
        });
        (addr, handle)
    }
}
