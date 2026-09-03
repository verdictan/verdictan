// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Streamable HTTP transport helpers for the hosted gateway MCP surface.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;

use axum::http::{
    header::{HeaderName, CONTENT_TYPE},
    HeaderMap, HeaderValue, StatusCode,
};
use axum::response::{
    sse::{Event, KeepAlive, Sse},
    IntoResponse, Response,
};
use axum::Json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use crate::api::AsyncApiClient;
use crate::error::CliError;
use crate::mcp::server::{self, MCP_PROTOCOL_VERSION};

const DEFAULT_SESSION_IDLE_TIMEOUT_SECS: u64 = 30 * 60;
const MAX_STREAMS_PER_SESSION: usize = 4;

const MCP_SESSION_ID_HEADER: &str = "mcp-session-id";
const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
const PRIME_EVENT_SUFFIX: &str = ":0";

#[derive(Clone)]
pub struct StreamableHttpState {
    sessions: Arc<RwLock<HashMap<String, SessionEntry>>>,
    cleanup_started: Arc<AtomicBool>,
}

impl Default for StreamableHttpState {
    fn default() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            cleanup_started: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[derive(Clone)]
struct SessionEntry {
    protocol_version: String,
    auth_fingerprint: String,
    session_policy: crate::mcp::server::McpSessionPolicy,
    streams: HashMap<String, mpsc::Sender<OutboundEvent>>,
    last_active: Instant,
}

#[derive(Clone)]
struct OutboundEvent {
    event_id: String,
    payload: Option<Value>,
}

struct StreamDropGuard {
    state: StreamableHttpState,
    session_id: String,
    stream_id: String,
}

impl Drop for StreamDropGuard {
    fn drop(&mut self) {
        let state = self.state.clone();
        let session_id = self.session_id.clone();
        let stream_id = self.stream_id.clone();
        tokio::spawn(async move {
            state.detach_stream(&session_id, &stream_id).await;
        });
    }
}

impl StreamableHttpState {
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    pub async fn session_policy(
        &self,
        session_id: &str,
    ) -> Option<crate::mcp::server::McpSessionPolicy> {
        let sessions = self.sessions.read().await;
        sessions
            .get(session_id)
            .map(|session| session.session_policy.clone())
    }

    async fn send_notification(&self, session_id: &str, message: Value) -> Result<(), CliError> {
        let sender = {
            let sessions = self.sessions.read().await;
            let session = sessions
                .get(session_id)
                .ok_or_else(|| CliError::user(format!("Unknown MCP session: {session_id}")))?;
            session
                .streams
                .values()
                .next()
                .cloned()
                .ok_or_else(|| CliError::user("No active MCP event stream for session"))?
        };

        sender
            .send(OutboundEvent {
                event_id: Uuid::new_v4().to_string(),
                payload: Some(message),
            })
            .await
            .map_err(|_| CliError::internal("Failed to deliver MCP server notification"))
    }

    async fn admit_session(
        &self,
        protocol_version: &str,
        auth_fingerprint: &str,
        session_policy: crate::mcp::server::McpSessionPolicy,
    ) -> Option<String> {
        let mut sessions = self.sessions.write().await;
        let active_session_count = sessions
            .values()
            .filter(|session| session.auth_fingerprint == auth_fingerprint)
            .count();
        if active_session_count >= session_policy.max_concurrent_sessions as usize {
            return None;
        }

        let session_id = Uuid::new_v4().to_string();
        sessions.insert(
            session_id.clone(),
            SessionEntry {
                protocol_version: protocol_version.to_string(),
                auth_fingerprint: auth_fingerprint.to_string(),
                session_policy,
                streams: HashMap::new(),
                last_active: Instant::now(),
            },
        );
        Some(session_id)
    }

    async fn protocol_version_for_session(&self, session_id: &str) -> Option<String> {
        let sessions = self.sessions.read().await;
        sessions
            .get(session_id)
            .map(|session| session.protocol_version.clone())
    }

    async fn auth_matches(&self, session_id: &str, auth_fingerprint: &str) -> Option<bool> {
        let sessions = self.sessions.read().await;
        sessions
            .get(session_id)
            .map(|session| session.auth_fingerprint == auth_fingerprint)
    }

    async fn attach_stream(
        &self,
        session_id: &str,
    ) -> Result<(String, mpsc::Receiver<OutboundEvent>), CliError> {
        let (sender, receiver) = mpsc::channel(32);
        let stream_id = Uuid::new_v4().to_string();

        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| CliError::user(format!("Unknown MCP session: {session_id}")))?;

        session.streams.retain(|_, tx| !tx.is_closed());

        if session.streams.len() >= MAX_STREAMS_PER_SESSION {
            if let Some(oldest_key) = session.streams.keys().next().cloned() {
                tracing::info!(
                    session_id = %session_id, evicted_stream = %oldest_key,
                    "evicting oldest MCP GET stream to stay within per-session limit"
                );
                session.streams.remove(&oldest_key);
            }
        }

        session.streams.insert(stream_id.clone(), sender);

        Ok((stream_id, receiver))
    }

    async fn detach_stream(&self, session_id: &str, stream_id: &str) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.streams.remove(stream_id);
        }
    }

    async fn touch_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_active = Instant::now();
        }
    }

    pub async fn evict_idle_sessions(&self, idle_timeout_secs: Option<u64>) -> usize {
        let timeout = std::time::Duration::from_secs(
            idle_timeout_secs.unwrap_or(DEFAULT_SESSION_IDLE_TIMEOUT_SECS),
        );
        let now = Instant::now();
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|session_id, entry| {
            let idle = now.duration_since(entry.last_active) < timeout;
            if !idle {
                tracing::info!(
                    session_id = %session_id,
                    idle_secs = now.duration_since(entry.last_active).as_secs(),
                    "evicting idle MCP session"
                );
            }
            idle
        });
        before - sessions.len()
    }

    pub fn spawn_background_session_cleanup(&self) {
        if self.cleanup_started.swap(true, Ordering::AcqRel) {
            return;
        }

        let state = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let evicted = state.evict_idle_sessions(None).await;
                if evicted > 0 {
                    tracing::info!(evicted_count = evicted, "periodic MCP session cleanup");
                }
            }
        });
    }
}

pub fn mcp_session_id(headers: &HeaderMap) -> Option<String> {
    header_value(headers, MCP_SESSION_ID_HEADER).map(ToOwned::to_owned)
}

pub fn auth_fingerprint(raw_token: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(raw_token.as_bytes());
    let hex = format!("{:x}", digest.finalize());
    hex[..16].to_string()
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_post(
    state: StreamableHttpState,
    mcp_outbox: &crate::mcp::audit::McpOutboxHandle,
    client: &AsyncApiClient,
    auth_fingerprint: &str,
    request_id: Option<&str>,
    session_id: Option<&str>,
    request: Value,
    session_policy: Option<crate::mcp::server::McpSessionPolicy>,
    trace_context: Option<&crate::mcp::server::McpToolTraceContext>,
) -> Response {
    state.evict_idle_sessions(None).await;

    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let session_policy = session_policy.unwrap_or_default();

    if is_jsonrpc_response(&request) {
        return StatusCode::ACCEPTED.into_response();
    }

    if request.to_string().len() as u64 > session_policy.max_prompt_bytes {
        return transport_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            id,
            -32004,
            "MCP request exceeds the configured session prompt limit",
        );
    }

    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    if method.is_empty() {
        return transport_error_response(
            StatusCode::BAD_REQUEST,
            id,
            -32600,
            "MCP POST requests must include a JSON-RPC method",
        );
    }

    if method == "initialize" {
        if request.get("id").is_none() {
            return transport_error_response(
                StatusCode::BAD_REQUEST,
                Value::Null,
                -32600,
                "initialize must be sent as a JSON-RPC request with an id",
            );
        }

        let response = server::handle_jsonrpc_request_with_context(
            mcp_outbox,
            client,
            "",
            request_id,
            &request,
            Some(&session_policy),
            trace_context,
        )
        .await;
        let Some(session_id) = state
            .admit_session(MCP_PROTOCOL_VERSION, auth_fingerprint, session_policy)
            .await
        else {
            return transport_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                id,
                -32005,
                "MCP session concurrency limit reached for this bearer token",
            );
        };
        return json_response_with_session(response, &session_id, MCP_PROTOCOL_VERSION);
    }

    let Some(session_id) = session_id else {
        return transport_error_response(
            StatusCode::BAD_REQUEST,
            id,
            -32600,
            "MCP-Session-Id is required after initialize",
        );
    };

    match state.auth_matches(session_id, auth_fingerprint).await {
        Some(true) => {}
        Some(false) => {
            return transport_error_response(
                StatusCode::FORBIDDEN,
                id,
                -32003,
                "MCP session auth does not match the original bearer token",
            )
        }
        None => {
            return transport_error_response(
                StatusCode::NOT_FOUND,
                id,
                -32001,
                "Unknown or expired MCP session",
            )
        }
    }

    if state
        .protocol_version_for_session(session_id)
        .await
        .is_none()
    {
        return transport_error_response(
            StatusCode::NOT_FOUND,
            id,
            -32001,
            "Unknown or expired MCP session",
        );
    }

    let Some(stored_policy) = state.session_policy(session_id).await else {
        return transport_error_response(
            StatusCode::NOT_FOUND,
            id,
            -32001,
            "Unknown or expired MCP session",
        );
    };

    state.touch_session(session_id).await;

    if request.get("id").is_none() {
        let _ = server::handle_jsonrpc_request_with_context(
            mcp_outbox,
            client,
            session_id,
            request_id,
            &request,
            Some(&stored_policy),
            trace_context,
        )
        .await;
        return StatusCode::ACCEPTED.into_response();
    }

    let response = server::handle_jsonrpc_request_with_context(
        mcp_outbox,
        client,
        session_id,
        request_id,
        &request,
        Some(&stored_policy),
        trace_context,
    )
    .await;
    Json(response).into_response()
}

pub async fn handle_get(
    state: StreamableHttpState,
    auth_fingerprint: &str,
    session_id: Option<&str>,
) -> Response {
    state.evict_idle_sessions(None).await;

    let Some(session_id) = session_id else {
        return transport_error_response(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32600,
            "MCP-Session-Id is required for GET /mcp",
        );
    };

    match state.auth_matches(session_id, auth_fingerprint).await {
        Some(true) => {}
        Some(false) => {
            return transport_error_response(
                StatusCode::FORBIDDEN,
                Value::Null,
                -32003,
                "MCP session auth does not match the original bearer token",
            )
        }
        None => {
            return transport_error_response(
                StatusCode::NOT_FOUND,
                Value::Null,
                -32001,
                "Unknown or expired MCP session",
            )
        }
    }

    state.touch_session(session_id).await;

    let (stream_id, mut receiver) = match state.attach_stream(session_id).await {
        Ok(value) => value,
        Err(error) => {
            return transport_error_response(
                StatusCode::NOT_FOUND,
                Value::Null,
                -32001,
                &error.to_string(),
            )
        }
    };

    let drop_guard = StreamDropGuard {
        state: state.clone(),
        session_id: session_id.to_string(),
        stream_id: stream_id.clone(),
    };

    let stream = async_stream::stream! {
        let _cleanup = drop_guard;
        yield Ok::<Event, Infallible>(Event::default()
            .id(format!("{stream_id}{PRIME_EVENT_SUFFIX}"))
            .data(""));

        while let Some(event) = receiver.recv().await {
            yield Ok(event.into_sse());
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

impl OutboundEvent {
    fn into_sse(self) -> Event {
        let mut event = Event::default().id(self.event_id);
        if let Some(payload) = self.payload {
            event = event.data(payload.to_string());
        } else {
            event = event.data("");
        }
        event
    }
}

fn is_jsonrpc_response(request: &Value) -> bool {
    request.get("method").is_none()
        && request.get("id").is_some()
        && (request.get("result").is_some() || request.get("error").is_some())
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn json_response_with_session(
    response: Value,
    session_id: &str,
    protocol_version: &str,
) -> Response {
    let mut http_response = Json(response).into_response();
    http_response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    http_response.headers_mut().insert(
        HeaderName::from_static(MCP_SESSION_ID_HEADER),
        HeaderValue::from_str(session_id).unwrap_or_else(|_| HeaderValue::from_static("invalid")),
    );
    if let Ok(value) = HeaderValue::from_str(protocol_version) {
        http_response
            .headers_mut()
            .insert(HeaderName::from_static(MCP_PROTOCOL_VERSION_HEADER), value);
    }
    http_response
}

fn transport_error_response(status: StatusCode, id: Value, code: i32, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message,
            }
        })),
    )
        .into_response()
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
    use axum::{
        routing::{get, post},
        Router,
    };
    use futures_util::StreamExt;
    use serde_json::json;
    use std::{sync::Arc, time::Duration};
    use tokio::net::TcpListener;
    async fn start_mock_api() -> (AsyncApiClient, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        let app = Router::new()
            .route(
                "/v1/history/search",
                get(|| async {
                    Json(json!({
                        "results": [{
                            "session_id": "sess-1",
                            "session_title": "Recent",
                            "excerpt": "match",
                            "entry_kind": "assistant",
                            "captured_at": "2026-07-03T00:00:00Z"
                        }]
                    }))
                }),
            )
            .route(
                "/v1/history/sessions",
                get(|| async {
                    Json(json!({
                        "sessions": [{"id": "sess-1", "title": "Recent"}]
                    }))
                }),
            )
            .route("/v1/events", post(|| async { Json(json!({ "ok": true })) }));

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock api");
        });

        (
            AsyncApiClient::new(format!("http://{addr}"), "test-token").expect("api client"),
            handle,
        )
    }

    struct SseEventReader<S> {
        stream: S,
        pending: String,
    }

    impl<S> SseEventReader<S>
    where
        S: futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
    {
        fn new(stream: S) -> Self {
            Self {
                stream,
                pending: String::new(),
            }
        }

        async fn next_event(&mut self) -> (Option<String>, Option<String>) {
            loop {
                if let Some(frame_end) = self.pending.find("\n\n") {
                    let frame = self.pending[..frame_end].to_string();
                    self.pending = self.pending[(frame_end + 2)..].to_string();

                    let event_id = frame
                        .lines()
                        .find_map(|line| line.strip_prefix("id: ").map(str::to_string));
                    let data = frame
                        .lines()
                        .find_map(|line| line.strip_prefix("data: ").map(str::to_string));
                    return (event_id, data);
                }

                let chunk = tokio::time::timeout(Duration::from_secs(2), self.stream.next())
                    .await
                    .expect("timed out waiting for SSE event")
                    .expect("SSE stream ended unexpectedly")
                    .expect("SSE chunk");
                self.pending
                    .push_str(std::str::from_utf8(&chunk).expect("SSE chunk should be utf8"));
            }
        }
    }

    fn test_mcp_outbox() -> crate::mcp::audit::McpOutboxHandle {
        crate::mcp::audit::McpOutboxHandle::from_env()
    }

    #[test]
    fn auth_fingerprint_is_stable() {
        assert_eq!(auth_fingerprint("token-1"), auth_fingerprint("token-1"));
        assert_ne!(auth_fingerprint("token-1"), auth_fingerprint("token-2"));
    }

    #[test]
    fn mcp_session_id_reads_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            MCP_SESSION_ID_HEADER,
            HeaderValue::from_static("session-123"),
        );
        assert_eq!(mcp_session_id(&headers).as_deref(), Some("session-123"));
    }

    #[tokio::test]
    async fn initialize_returns_session_header() {
        let (client, handle) = start_mock_api().await;
        let state = StreamableHttpState::default();

        let outbox = test_mcp_outbox();
        let response = handle_post(
            state,
            &outbox,
            &client,
            &auth_fingerprint("vdt_test"),
            None,
            None,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
            None,
            None,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(MCP_SESSION_ID_HEADER));
        assert_eq!(
            response
                .headers()
                .get(MCP_PROTOCOL_VERSION_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(MCP_PROTOCOL_VERSION),
        );

        handle.abort();
    }

    #[tokio::test]
    async fn initialize_followed_by_get_opens_sse_stream() {
        let (client, handle) = start_mock_api().await;
        let state = StreamableHttpState::default();
        let fingerprint = auth_fingerprint("vdt_test");

        let outbox = test_mcp_outbox();
        let init_response = handle_post(
            state.clone(),
            &outbox,
            &client,
            &fingerprint,
            None,
            None,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
            None,
            None,
        )
        .await;
        let session_id = init_response
            .headers()
            .get(MCP_SESSION_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .expect("session header")
            .to_string();

        let app = Router::new()
            .route(
                "/mcp",
                get({
                    let state = state.clone();
                    let fingerprint = fingerprint.clone();
                    move || {
                        let state = state.clone();
                        let fingerprint = fingerprint.clone();
                        async move { handle_get(state, &fingerprint, Some(&session_id)).await }
                    }
                }),
            )
            .with_state(());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind sse listener");
        let addr = listener.local_addr().expect("sse addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve sse app");
        });

        let response = reqwest::Client::new()
            .get(format!("http://{addr}/mcp"))
            .send()
            .await
            .expect("SSE GET");
        assert_eq!(response.status(), StatusCode::OK);

        let mut reader = SseEventReader::new(response.bytes_stream());
        let (event_id, data) = reader.next_event().await;
        assert!(event_id.is_some());
        assert_eq!(data.as_deref(), Some(""));

        server.abort();
        handle.abort();
    }

    #[tokio::test]
    async fn initialize_followed_by_notification_delivers_payload() {
        let (client, handle) = start_mock_api().await;
        let state = StreamableHttpState::default();
        let fingerprint = auth_fingerprint("vdt_test");

        let outbox = test_mcp_outbox();
        let init_response = handle_post(
            state.clone(),
            &outbox,
            &client,
            &fingerprint,
            None,
            None,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
            None,
            None,
        )
        .await;
        let session_id = init_response
            .headers()
            .get(MCP_SESSION_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .expect("session header")
            .to_string();

        let app = Router::new()
            .route(
                "/mcp",
                get({
                    let state = state.clone();
                    let fingerprint = fingerprint.clone();
                    let session_id = session_id.clone();
                    move || {
                        let state = state.clone();
                        let fingerprint = fingerprint.clone();
                        let session_id = session_id.clone();
                        async move { handle_get(state, &fingerprint, Some(&session_id)).await }
                    }
                }),
            )
            .with_state(());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind sse listener");
        let addr = listener.local_addr().expect("sse addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve sse app");
        });

        let response = reqwest::Client::new()
            .get(format!("http://{addr}/mcp"))
            .send()
            .await
            .expect("SSE GET");
        assert_eq!(response.status(), StatusCode::OK);

        let mut reader = SseEventReader::new(response.bytes_stream());
        let _ = reader.next_event().await;

        state
            .send_notification(
                &session_id,
                json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/test",
                    "params": {
                        "ok": true
                    }
                }),
            )
            .await
            .expect("send notification");

        let (_event_id, data) = reader.next_event().await;
        let payload: Value =
            serde_json::from_str(&data.expect("notification data")).expect("notification payload");
        assert_eq!(payload["method"], "notifications/test");
        assert_eq!(payload["params"]["ok"], true);

        server.abort();
        handle.abort();
    }

    #[tokio::test]
    async fn initialize_rejects_when_concurrent_session_limit_is_reached() {
        let (client, handle) = start_mock_api().await;
        let state = StreamableHttpState::default();
        let fingerprint = auth_fingerprint("vdt_test");
        let policy = crate::mcp::server::McpSessionPolicy {
            max_concurrent_sessions: 1,
            ..crate::mcp::server::McpSessionPolicy::default()
        };

        let outbox = test_mcp_outbox();
        let first = handle_post(
            state.clone(),
            &outbox,
            &client,
            &fingerprint,
            None,
            None,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
            Some(policy.clone()),
            None,
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);

        let second = handle_post(
            state,
            &outbox,
            &client,
            &fingerprint,
            None,
            None,
            json!({"jsonrpc":"2.0","id":2,"method":"initialize"}),
            Some(policy),
            None,
        )
        .await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

        handle.abort();
    }
}
