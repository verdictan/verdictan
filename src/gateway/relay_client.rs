// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

#![allow(clippy::result_large_err)]
//! Reverse-tunnel relay client for external gateways behind NAT/firewalls.
//!
//! When the gateway is in connected mode with a `runtime_registration_id` and
//! `VERDICTAN_API_URL` is set, a background task connects to the platform's
//! relay WebSocket endpoint. The platform dispatches inbound API traffic
//! through this tunnel, and the relay client forwards each request to the
//! local gateway HTTP server.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{Sink, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite;
use tracing::{debug, info, warn};

const MAX_BACKOFF: Duration = Duration::from_secs(30);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const LOCAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CLIENT_PING_INTERVAL: Duration = Duration::from_secs(20);
const IDLE_TIMEOUT: Duration = Duration::from_secs(45);

/// Indicates how a relay session ended, distinguishing failures that occurred
/// before vs after successful registration with the platform.
enum SessionOutcome {
    /// Server sent a close frame after the session was fully established.
    CleanClose,
    /// An error occurred after registration succeeded (the connection was
    /// previously working).
    DisconnectedAfterRegistration(anyhow::Error),
    /// Connection or registration itself failed (never reached a working state).
    ConnectionFailed(anyhow::Error),
}

// ── Envelope types (mirror the API's types) ─────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequestEnvelope {
    request_id: String,
    method: String,
    path: String,
    headers: HashMap<String, String>,
    #[serde(default)]
    body: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ResponseEnvelope {
    request_id: String,
    #[serde(default)]
    status: u16,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body: String,
    #[serde(default)]
    streaming: bool,
}

#[derive(Debug, Deserialize)]
struct RegistrationAck {
    #[serde(rename = "type")]
    kind: String,
    runtime_registration_id: String,
}

// ── Configuration ───────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub(crate) struct RelayClientConfig {
    pub api_base_url: String,
    pub api_token: String,
    pub runtime_registration_id: String,
    pub local_gateway_port: u16,
}

// ── Spawn ───────────────────────────────────────────────────────────────────

pub(crate) fn spawn_relay_client(config: RelayClientConfig) {
    std::mem::drop(spawn_relay_client_task(config));
}

fn spawn_relay_client_task(config: RelayClientConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        relay_client_loop(config).await;
    })
}

async fn relay_client_loop(config: RelayClientConfig) {
    let mut backoff = INITIAL_BACKOFF;
    let mut first_connect = true;

    loop {
        info!(
            api_base_url = %config.api_base_url,
            runtime_registration_id = %config.runtime_registration_id,
            "relay client: connecting to platform relay"
        );

        match run_relay_session(&config, first_connect).await {
            SessionOutcome::CleanClose => {
                warn!(
                    backoff_secs = INITIAL_BACKOFF.as_secs(),
                    "relay client: connection closed, reconnecting in {}s",
                    INITIAL_BACKOFF.as_secs()
                );
                backoff = INITIAL_BACKOFF;
            }
            SessionOutcome::DisconnectedAfterRegistration(e) => {
                warn!(
                    error = %e,
                    backoff_secs = INITIAL_BACKOFF.as_secs(),
                    "relay client: connection lost, reconnecting in {}s",
                    INITIAL_BACKOFF.as_secs()
                );
                backoff = INITIAL_BACKOFF;
            }
            SessionOutcome::ConnectionFailed(e) => {
                warn!(
                    error = %e,
                    backoff_secs = backoff.as_secs(),
                    "relay client: connection failed, reconnecting in {}s",
                    backoff.as_secs()
                );
            }
        }

        first_connect = false;
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn run_relay_session(config: &RelayClientConfig, first_connect: bool) -> SessionOutcome {
    let ws_url = build_ws_url(&config.api_base_url);

    let request = match tungstenite::http::Request::builder()
        .uri(&ws_url)
        .header("Authorization", format!("Bearer {}", config.api_token))
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .header("Sec-WebSocket-Version", "13")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Host", extract_host(&ws_url))
        .body(())
    {
        Ok(r) => r,
        Err(e) => return SessionOutcome::ConnectionFailed(e.into()),
    };

    let (ws_stream, _response) = match tokio_tungstenite::connect_async(request).await {
        Ok(s) => s,
        Err(e) => return SessionOutcome::ConnectionFailed(e.into()),
    };
    let (mut ws_sink, mut ws_stream_rx) = ws_stream.split();

    info!(
        runtime_registration_id = %config.runtime_registration_id,
        "relay client: WebSocket connected, sending registration"
    );

    let registration = serde_json::json!({
        "runtime_registration_id": config.runtime_registration_id,
    });
    if let Err(e) = ws_sink
        .send(tungstenite::Message::Text(registration.to_string()))
        .await
    {
        return SessionOutcome::ConnectionFailed(e.into());
    }
    let ws_sink = Arc::new(tokio::sync::Mutex::new(ws_sink));

    // Wait for registration ack
    if let Some(Ok(msg)) = ws_stream_rx.next().await {
        match msg {
            tungstenite::Message::Text(text) => {
                let ack: RegistrationAck = match serde_json::from_str(&text) {
                    Ok(ack) => ack,
                    Err(e) => {
                        return SessionOutcome::ConnectionFailed(anyhow::anyhow!(
                            "invalid registration ack: {e}"
                        ));
                    }
                };
                if ack.kind != "registered" {
                    return SessionOutcome::ConnectionFailed(anyhow::anyhow!(
                        "unexpected registration ack type: {}",
                        ack.kind
                    ));
                }
                if ack.runtime_registration_id != config.runtime_registration_id {
                    return SessionOutcome::ConnectionFailed(anyhow::anyhow!(
                        "registration ack runtime_registration_id mismatch"
                    ));
                }
                debug!(ack = %text, "relay client: received registration ack");
            }
            tungstenite::Message::Close(_) => {
                return SessionOutcome::ConnectionFailed(anyhow::anyhow!(
                    "server closed connection during registration"
                ));
            }
            _ => {
                return SessionOutcome::ConnectionFailed(anyhow::anyhow!(
                    "unexpected non-text registration ack"
                ));
            }
        }
    } else {
        return SessionOutcome::ConnectionFailed(anyhow::anyhow!(
            "connection closed before registration ack"
        ));
    }

    // --- Registration succeeded ---
    if first_connect {
        info!(
            runtime_registration_id = %config.runtime_registration_id,
            "relay client: registered, listening for requests"
        );
    } else {
        info!(
            runtime_registration_id = %config.runtime_registration_id,
            "relay client: reconnected"
        );
    }

    let local_base = format!("http://127.0.0.1:{}", config.local_gateway_port);
    let http_client = match reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => return SessionOutcome::DisconnectedAfterRegistration(e.into()),
    };

    let mut ping_interval = tokio::time::interval(CLIENT_PING_INTERVAL);
    ping_interval.tick().await;
    let idle_deadline = tokio::time::Instant::now() + IDLE_TIMEOUT;
    let idle_timer = tokio::time::sleep_until(idle_deadline);
    tokio::pin!(idle_timer);

    loop {
        tokio::select! {
            msg_opt = ws_stream_rx.next() => {
                idle_timer.as_mut().reset(tokio::time::Instant::now() + IDLE_TIMEOUT);

                let msg = match msg_opt {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => return SessionOutcome::DisconnectedAfterRegistration(e.into()),
                    None => return SessionOutcome::CleanClose,
                };

                match msg {
                    tungstenite::Message::Text(text) => {
                        let envelope: RequestEnvelope = match serde_json::from_str(&text) {
                            Ok(e) => e,
                            Err(e) => {
                                warn!(error = %e, "relay client: invalid request envelope");
                                continue;
                            }
                        };

                        info!(
                            request_id = %envelope.request_id,
                            method = %envelope.method,
                            path = %envelope.path,
                            "relay client: received request, forwarding to local gateway"
                        );

                        let http_client = http_client.clone();
                        let local_base = local_base.clone();
                        let ws_sink = Arc::clone(&ws_sink);
                        tokio::spawn(async move {
                            relay_local_request(&http_client, &local_base, envelope, ws_sink).await;
                        });
                    }
                    tungstenite::Message::Close(_) => {
                        info!("relay client: server sent close frame");
                        return SessionOutcome::CleanClose;
                    }
                    tungstenite::Message::Ping(data) => {
                        if let Err(e) =
                            send_ws_message(&ws_sink, tungstenite::Message::Pong(data)).await
                        {
                            return SessionOutcome::DisconnectedAfterRegistration(e.into());
                        }
                    }
                    tungstenite::Message::Pong(_) => {
                        debug!("relay client: received pong");
                    }
                    _ => {}
                }
            }
            _ = ping_interval.tick() => {
                debug!("relay client: sending heartbeat ping");
                if let Err(e) =
                    send_ws_message(&ws_sink, tungstenite::Message::Ping(vec![])).await
                {
                    return SessionOutcome::DisconnectedAfterRegistration(e.into());
                }
            }
            _ = &mut idle_timer => {
                warn!(
                    timeout_secs = IDLE_TIMEOUT.as_secs(),
                    "relay client: idle timeout, no messages received"
                );
                return SessionOutcome::DisconnectedAfterRegistration(
                    anyhow::anyhow!("idle timeout: no messages received in {}s", IDLE_TIMEOUT.as_secs()),
                );
            }
        }
    }
}

async fn send_ws_message<S>(
    ws_sink: &Arc<tokio::sync::Mutex<S>>,
    message: tungstenite::Message,
) -> Result<(), tungstenite::Error>
where
    S: Sink<tungstenite::Message, Error = tungstenite::Error> + Unpin,
{
    let mut guard = ws_sink.lock().await;
    guard.send(message).await
}

fn build_local_gateway_request(
    client: &reqwest::Client,
    local_base: &str,
    envelope: &RequestEnvelope,
) -> reqwest::RequestBuilder {
    let url = format!("{}{}", local_base, envelope.path);

    let method = match envelope.method.as_str() {
        "GET" => reqwest::Method::GET,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        _ => reqwest::Method::POST,
    };

    let mut request = client.request(method, &url);

    for (key, value) in &envelope.headers {
        if key.eq_ignore_ascii_case("host") {
            continue;
        }
        request = request.header(key.as_str(), value.as_str());
    }

    if !envelope.body.is_empty() {
        request = request.body(envelope.body.clone());
    }

    request
}

fn relay_local_gateway_error_response(request_id: &str, message: String) -> ResponseEnvelope {
    ResponseEnvelope {
        request_id: request_id.to_string(),
        status: 502,
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        body: serde_json::json!({
            "error": {
                "message": message,
                "type": "relay_error",
                "code": "relay_local_gateway_error",
            }
        })
        .to_string(),
        streaming: false,
    }
}

fn response_headers_to_hash_map(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for (key, value) in headers {
        if let Ok(parsed) = value.to_str() {
            values.insert(key.as_str().to_string(), parsed.to_string());
        }
    }
    values
}

fn response_is_event_stream(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase().starts_with("text/event-stream"))
        .unwrap_or(false)
}

fn drain_utf8_chunk(buffer: &mut Vec<u8>) -> Option<String> {
    if buffer.is_empty() {
        return None;
    }

    match std::str::from_utf8(buffer) {
        Ok(text) => {
            let out = text.to_string();
            buffer.clear();
            (!out.is_empty()).then_some(out)
        }
        Err(error) if error.error_len().is_none() => {
            let valid_up_to = error.valid_up_to();
            if valid_up_to == 0 {
                None
            } else {
                let out = String::from_utf8_lossy(&buffer[..valid_up_to]).to_string();
                buffer.drain(..valid_up_to);
                (!out.is_empty()).then_some(out)
            }
        }
        Err(_) => {
            let out = String::from_utf8_lossy(buffer).to_string();
            buffer.clear();
            (!out.is_empty()).then_some(out)
        }
    }
}

async fn buffer_local_gateway_response(
    response: reqwest::Response,
    request_id: &str,
) -> ResponseEnvelope {
    let status = response.status().as_u16();
    let headers = response_headers_to_hash_map(response.headers());
    let body = match tokio::time::timeout(LOCAL_REQUEST_TIMEOUT, response.text()).await {
        Ok(Ok(body)) => body,
        Ok(Err(error)) => {
            return relay_local_gateway_error_response(
                request_id,
                format!("Local gateway response read failed: {error}"),
            );
        }
        Err(_) => {
            return relay_local_gateway_error_response(
                request_id,
                format!(
                    "Local gateway response timed out after {}s",
                    LOCAL_REQUEST_TIMEOUT.as_secs()
                ),
            );
        }
    };

    ResponseEnvelope {
        request_id: request_id.to_string(),
        status,
        headers,
        body,
        streaming: false,
    }
}

async fn send_response_envelope<S>(
    ws_sink: &Arc<tokio::sync::Mutex<S>>,
    response: ResponseEnvelope,
) -> Result<(), tungstenite::Error>
where
    S: Sink<tungstenite::Message, Error = tungstenite::Error> + Unpin,
{
    let response_json = serde_json::to_string(&response).map_err(|error| {
        tungstenite::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to serialize relay response: {error}"),
        ))
    })?;
    send_ws_message(ws_sink, tungstenite::Message::Text(response_json)).await
}

async fn send_streaming_local_gateway_response<S>(
    response: reqwest::Response,
    request_id: &str,
    ws_sink: &Arc<tokio::sync::Mutex<S>>,
) -> Result<(), tungstenite::Error>
where
    S: Sink<tungstenite::Message, Error = tungstenite::Error> + Unpin,
{
    let status = response.status().as_u16();
    let headers = response_headers_to_hash_map(response.headers());
    send_response_envelope(
        ws_sink,
        ResponseEnvelope {
            request_id: request_id.to_string(),
            status,
            headers,
            body: String::new(),
            streaming: true,
        },
    )
    .await?;

    let mut stream = response.bytes_stream();
    let mut utf8_buffer = Vec::new();
    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(chunk) => {
                utf8_buffer.extend_from_slice(&chunk);
                if let Some(body) = drain_utf8_chunk(&mut utf8_buffer) {
                    send_response_envelope(
                        ws_sink,
                        ResponseEnvelope {
                            request_id: request_id.to_string(),
                            status: 0,
                            headers: HashMap::new(),
                            body,
                            streaming: true,
                        },
                    )
                    .await?;
                }
            }
            Err(error) => {
                warn!(
                    request_id = %request_id,
                    error = %error,
                    "relay client: local gateway streaming response failed"
                );
                let body = format!(
                    "data: {{\"error\":{{\"message\":\"Local gateway streaming response failed: {}\",\"type\":\"relay_error\",\"code\":\"relay_local_gateway_error\"}}}}\n\n",
                    error
                );
                send_response_envelope(
                    ws_sink,
                    ResponseEnvelope {
                        request_id: request_id.to_string(),
                        status: 0,
                        headers: HashMap::new(),
                        body,
                        streaming: true,
                    },
                )
                .await?;
                send_response_envelope(
                    ws_sink,
                    ResponseEnvelope {
                        request_id: request_id.to_string(),
                        status: 0,
                        headers: HashMap::new(),
                        body: "data: [DONE]\n\n".to_string(),
                        streaming: true,
                    },
                )
                .await?;
                send_response_envelope(
                    ws_sink,
                    ResponseEnvelope {
                        request_id: request_id.to_string(),
                        status: 0,
                        headers: HashMap::new(),
                        body: String::new(),
                        streaming: false,
                    },
                )
                .await?;
                return Ok(());
            }
        }
    }

    if let Some(body) = drain_utf8_chunk(&mut utf8_buffer) {
        send_response_envelope(
            ws_sink,
            ResponseEnvelope {
                request_id: request_id.to_string(),
                status: 0,
                headers: HashMap::new(),
                body,
                streaming: true,
            },
        )
        .await?;
    }

    send_response_envelope(
        ws_sink,
        ResponseEnvelope {
            request_id: request_id.to_string(),
            status: 0,
            headers: HashMap::new(),
            body: String::new(),
            streaming: false,
        },
    )
    .await
}

async fn relay_local_request<S>(
    client: &reqwest::Client,
    local_base: &str,
    envelope: RequestEnvelope,
    ws_sink: Arc<tokio::sync::Mutex<S>>,
) where
    S: Sink<tungstenite::Message, Error = tungstenite::Error> + Unpin + Send + 'static,
{
    let request_id = envelope.request_id.clone();
    let response = match tokio::time::timeout(
        LOCAL_REQUEST_TIMEOUT,
        build_local_gateway_request(client, local_base, &envelope).send(),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            warn!(
                request_id = %request_id,
                error = %error,
                "relay client: local gateway request failed"
            );
            let _ = send_response_envelope(
                &ws_sink,
                relay_local_gateway_error_response(
                    &request_id,
                    format!("Local gateway request failed: {error}"),
                ),
            )
            .await;
            return;
        }
        Err(_) => {
            warn!(
                request_id = %request_id,
                timeout_secs = LOCAL_REQUEST_TIMEOUT.as_secs(),
                "relay client: local gateway request timed out"
            );
            let _ = send_response_envelope(
                &ws_sink,
                relay_local_gateway_error_response(
                    &request_id,
                    format!(
                        "Local gateway request timed out after {}s",
                        LOCAL_REQUEST_TIMEOUT.as_secs()
                    ),
                ),
            )
            .await;
            return;
        }
    };

    if response.status().is_success() && response_is_event_stream(&response) {
        info!(
            request_id = %request_id,
            status = response.status().as_u16(),
            "relay client: streaming response established"
        );
        if let Err(error) =
            send_streaming_local_gateway_response(response, &request_id, &ws_sink).await
        {
            warn!(
                request_id = %request_id,
                error = %error,
                "relay client: failed to forward streaming response over relay"
            );
        } else {
            info!(request_id = %request_id, "relay client: streaming response completed");
        }
        return;
    }

    let buffered = buffer_local_gateway_response(response, &request_id).await;
    info!(
        request_id = %request_id,
        status = buffered.status,
        "relay client: sending response back through relay"
    );
    if let Err(error) = send_response_envelope(&ws_sink, buffered).await {
        warn!(
            request_id = %request_id,
            error = %error,
            "relay client: failed to forward buffered response over relay"
        );
    }
}

#[cfg(test)]
async fn forward_to_local_gateway(
    client: &reqwest::Client,
    local_base: &str,
    envelope: &RequestEnvelope,
) -> ResponseEnvelope {
    let request_id = envelope.request_id.clone();
    let response = match tokio::time::timeout(
        LOCAL_REQUEST_TIMEOUT,
        build_local_gateway_request(client, local_base, envelope).send(),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            warn!(
                request_id = %request_id,
                error = %error,
                "relay client: local gateway request failed"
            );
            return relay_local_gateway_error_response(
                &request_id,
                format!("Local gateway request failed: {error}"),
            );
        }
        Err(_) => {
            warn!(
                request_id = %request_id,
                timeout_secs = LOCAL_REQUEST_TIMEOUT.as_secs(),
                "relay client: local gateway request timed out"
            );
            return relay_local_gateway_error_response(
                &request_id,
                format!(
                    "Local gateway request timed out after {}s",
                    LOCAL_REQUEST_TIMEOUT.as_secs()
                ),
            );
        }
    };

    buffer_local_gateway_response(response, &request_id).await
}

fn build_ws_url(api_base_url: &str) -> String {
    // Internal-only override for development and testing. Not documented as
    // a customer-facing env var — the normal path derives the relay URL
    // automatically from VERDICTAN_API_URL.
    if let Ok(relay_url) = std::env::var("VERDICTAN_RELAY_URL") {
        let url = relay_url.trim_end_matches('/');
        let ws_base = if url.starts_with("https://") {
            url.replacen("https://", "wss://", 1)
        } else if url.starts_with("http://") {
            url.replacen("http://", "ws://", 1)
        } else if url.starts_with("wss://") || url.starts_with("ws://") {
            url.to_string()
        } else {
            format!("ws://{url}")
        };
        return format!("{ws_base}/v1/gateway/relay");
    }

    let base = api_base_url.trim_end_matches('/');

    let (scheme, host_and_path) = if let Some(rest) = base.strip_prefix("https://") {
        ("wss://", rest)
    } else if let Some(rest) = base.strip_prefix("http://") {
        ("ws://", rest)
    } else {
        ("ws://", base)
    };

    let host = host_and_path.split('/').next().unwrap_or(host_and_path);

    // Derive the relay hostname: replace the leading `api.` with `relay.`.
    // If the hostname has no `api.` prefix (e.g. localhost or a bare IP),
    // fall back to using the API host directly.
    let relay_host = if let Some(rest) = host.strip_prefix("api.") {
        format!("relay.{rest}")
    } else {
        host.to_string()
    };

    format!("{scheme}{relay_host}/v1/gateway/relay")
}

fn extract_host(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("localhost")
        .to_string()
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
        body::Body,
        extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        extract::State,
        http::{HeaderMap, HeaderValue, Method, StatusCode},
        response::IntoResponse,
        routing::{any, get},
        Router,
    };
    use serde_json::Value;
    use std::sync::{Arc, Mutex};
    use tokio::sync::oneshot;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CapturedLocalRequest {
        method: String,
        host: Option<String>,
        custom_header: Option<String>,
        body: String,
    }

    async fn capture_local_request(
        State(captured): State<Arc<Mutex<Option<CapturedLocalRequest>>>>,
        method: Method,
        headers: HeaderMap,
        body: String,
    ) -> impl IntoResponse {
        *captured.lock().expect("captured request lock") = Some(CapturedLocalRequest {
            method: method.as_str().to_string(),
            host: headers
                .get("host")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            custom_header: headers
                .get("x-custom-header")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            body,
        });

        ([("x-relay-client-test", "ok")], Body::from("forwarded"))
    }

    async fn capture_streaming_local_request(
        State(captured): State<Arc<Mutex<Option<CapturedLocalRequest>>>>,
        method: Method,
        headers: HeaderMap,
        body: String,
    ) -> impl IntoResponse {
        *captured.lock().expect("captured request lock") = Some(CapturedLocalRequest {
            method: method.as_str().to_string(),
            host: headers
                .get("host")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            custom_header: headers
                .get("x-custom-header")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            body,
        });

        let body_stream = tokio_stream::iter(vec![
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(
                b"data: {\"delta\":\"hello\"}\n\n",
            )),
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"data: [DONE]\n\n")),
        ]);

        (
            [
                ("content-type", "text/event-stream"),
                ("cache-control", "no-cache"),
                ("server-timing", "gateway_upstream;dur=12.5"),
            ],
            Body::from_stream(body_stream),
        )
    }

    #[derive(Clone, Debug, Default)]
    struct RelaySessionObservation {
        registration: Option<Value>,
        response: Option<ResponseEnvelope>,
        pong: Option<Vec<u8>>,
    }

    async fn spawn_local_gateway(
        captured: Arc<Mutex<Option<CapturedLocalRequest>>>,
    ) -> std::net::SocketAddr {
        let app = Router::new()
            .route("/relay", any(capture_local_request))
            .route("/stream", any(capture_streaming_local_request))
            .with_state(captured);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local gateway");
        let addr = listener.local_addr().expect("local gateway addr");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve local gateway");
        });
        addr
    }

    async fn spawn_relay_server<F, Fut>(handler: F) -> std::net::SocketAddr
    where
        F: Fn(WebSocket) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let app = Router::new().route(
            "/v1/gateway/relay",
            get(move |ws: WebSocketUpgrade| {
                let handler = handler.clone();
                async move { ws.on_upgrade(handler) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind relay server");
        let addr = listener.local_addr().expect("relay server addr");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve relay server");
        });
        addr
    }

    #[test]
    fn build_ws_url_derives_relay_hostname() {
        assert_eq!(
            build_ws_url("https://api.eu.verdictan.com"),
            "wss://relay.eu.verdictan.com/v1/gateway/relay"
        );
    }

    #[test]
    fn build_ws_url_derives_relay_us() {
        assert_eq!(
            build_ws_url("https://api.us.verdictan.com"),
            "wss://relay.us.verdictan.com/v1/gateway/relay"
        );
    }

    #[test]
    fn build_ws_url_derives_relay_bare_api() {
        assert_eq!(
            build_ws_url("https://api.verdictan.com"),
            "wss://relay.verdictan.com/v1/gateway/relay"
        );
    }

    #[test]
    fn build_ws_url_localhost_fallback() {
        assert_eq!(
            build_ws_url("http://localhost:8080"),
            "ws://localhost:8080/v1/gateway/relay"
        );
    }

    #[test]
    fn build_ws_url_no_api_prefix_preserves_host() {
        assert_eq!(
            build_ws_url("https://custom.example.com"),
            "wss://custom.example.com/v1/gateway/relay"
        );
    }

    #[test]
    fn build_ws_url_strips_trailing_slash() {
        assert_eq!(
            build_ws_url("https://api.eu.verdictan.com/"),
            "wss://relay.eu.verdictan.com/v1/gateway/relay"
        );
    }

    #[test]
    fn build_ws_url_preserves_port() {
        assert_eq!(
            build_ws_url("http://api.local:9090"),
            "ws://relay.local:9090/v1/gateway/relay"
        );
    }

    #[test]
    fn build_ws_url_uses_explicit_relay_override() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        crate::test_support::set_var("VERDICTAN_RELAY_URL", "https://relay.internal:9443/");
        assert_eq!(
            build_ws_url("https://api.verdictan.com"),
            "wss://relay.internal:9443/v1/gateway/relay"
        );
        crate::test_support::unset_var("VERDICTAN_RELAY_URL");
    }

    #[test]
    fn build_ws_url_uses_explicit_relay_override_without_scheme() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        crate::test_support::set_var("VERDICTAN_RELAY_URL", "relay.internal:9443/");
        assert_eq!(
            build_ws_url("https://api.verdictan.com"),
            "ws://relay.internal:9443/v1/gateway/relay"
        );
        crate::test_support::unset_var("VERDICTAN_RELAY_URL");
    }

    #[test]
    fn extract_host_from_wss_url() {
        assert_eq!(
            extract_host("wss://relay.eu.verdictan.com/v1/gateway/relay"),
            "relay.eu.verdictan.com"
        );
    }

    #[test]
    fn extract_host_with_port() {
        assert_eq!(
            extract_host("ws://localhost:8080/v1/gateway/relay"),
            "localhost:8080"
        );
    }

    #[test]
    fn extract_host_without_scheme_returns_bare_host() {
        assert_eq!(
            extract_host("relay.internal:8080/path"),
            "relay.internal:8080"
        );
    }

    #[test]
    fn request_envelope_roundtrip() {
        let envelope = RequestEnvelope {
            request_id: "req-1".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::new(),
            body: String::new(),
        };
        let json = serde_json::to_string(&envelope).expect("serialize");
        let _: RequestEnvelope = serde_json::from_str(&json).expect("deserialize");
    }

    #[test]
    fn response_envelope_error_construction() {
        let resp = ResponseEnvelope {
            request_id: "req-1".to_string(),
            status: 502,
            headers: HashMap::new(),
            body: "error".to_string(),
            streaming: false,
        };
        assert_eq!(resp.status, 502);
    }

    #[tokio::test]
    async fn forward_to_local_gateway_forwards_headers_body_and_overrides_caller_host() {
        let captured = Arc::new(Mutex::new(None::<CapturedLocalRequest>));
        let app = Router::new()
            .route("/relay", any(capture_local_request))
            .with_state(Arc::clone(&captured));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("listener addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test server");
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("http client");
        let response = forward_to_local_gateway(
            &client,
            &format!("http://{addr}"),
            &RequestEnvelope {
                request_id: "req-success".to_string(),
                method: "POST".to_string(),
                path: "/relay".to_string(),
                headers: HashMap::from([
                    ("host".to_string(), "ignored.example.com".to_string()),
                    ("x-custom-header".to_string(), "present".to_string()),
                ]),
                body: "payload".to_string(),
            },
        )
        .await;

        assert_eq!(response.request_id, "req-success");
        assert_eq!(response.status, StatusCode::OK.as_u16());
        assert_eq!(response.body, "forwarded");
        assert_eq!(
            response
                .headers
                .get("x-relay-client-test")
                .map(String::as_str),
            Some("ok")
        );

        let captured = captured
            .lock()
            .expect("captured request lock")
            .clone()
            .expect("captured request");
        assert_eq!(
            captured,
            CapturedLocalRequest {
                method: "POST".to_string(),
                host: Some(addr.to_string()),
                custom_header: Some("present".to_string()),
                body: "payload".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn forward_to_local_gateway_returns_structured_502_for_connection_failures() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral listener");
        let addr = listener.local_addr().expect("listener addr");
        drop(listener);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .expect("http client");
        let response = forward_to_local_gateway(
            &client,
            &format!("http://{addr}"),
            &RequestEnvelope {
                request_id: "req-failure".to_string(),
                method: "GET".to_string(),
                path: "/relay".to_string(),
                headers: HashMap::from([(
                    "x-custom-header".to_string(),
                    HeaderValue::from_static("present")
                        .to_str()
                        .expect("header value")
                        .to_string(),
                )]),
                body: String::new(),
            },
        )
        .await;

        assert_eq!(response.request_id, "req-failure");
        assert_eq!(response.status, 502);
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert!(response.body.contains("relay_local_gateway_error"));
        assert!(!response.streaming);
    }

    #[tokio::test]
    async fn run_relay_session_forwards_requests_and_handles_ping_after_registration() {
        let captured = Arc::new(Mutex::new(None::<CapturedLocalRequest>));
        let local_addr = spawn_local_gateway(Arc::clone(&captured)).await;

        let observation = Arc::new(Mutex::new(RelaySessionObservation::default()));
        let (done_tx, done_rx) = oneshot::channel();
        let done_tx = Arc::new(Mutex::new(Some(done_tx)));
        let observation_for_handler = Arc::clone(&observation);
        let done_tx_for_handler = Arc::clone(&done_tx);

        let relay_addr = spawn_relay_server(move |socket| {
            let observation = Arc::clone(&observation_for_handler);
            let done_tx = Arc::clone(&done_tx_for_handler);
            async move {
                let (mut ws_sink, mut ws_stream) = socket.split();

                let registration_text = match ws_stream.next().await {
                    Some(Ok(WsMessage::Text(text))) => text,
                    other => panic!("expected registration text, got {other:?}"),
                };
                let registration: Value =
                    serde_json::from_str(&registration_text).expect("parse registration");
                observation
                    .lock()
                    .expect("relay observation lock")
                    .registration = Some(registration);

                let ack = serde_json::json!({
                    "type": "registered",
                    "runtime_registration_id": "runtime-123",
                });
                ws_sink
                    .send(WsMessage::Text(ack.to_string().into()))
                    .await
                    .expect("send registration ack");
                ws_sink
                    .send(WsMessage::Ping(vec![1, 2, 3].into()))
                    .await
                    .expect("send ping");

                let pong = match ws_stream.next().await {
                    Some(Ok(WsMessage::Pong(bytes))) => bytes.to_vec(),
                    other => panic!("expected pong from relay client, got {other:?}"),
                };
                observation.lock().expect("relay observation lock").pong = Some(pong);

                let envelope = RequestEnvelope {
                    request_id: "req-relay".to_string(),
                    method: "POST".to_string(),
                    path: "/relay".to_string(),
                    headers: HashMap::from([
                        ("host".to_string(), "ignored.example.com".to_string()),
                        ("x-custom-header".to_string(), "present".to_string()),
                    ]),
                    body: "payload".to_string(),
                };
                ws_sink
                    .send(WsMessage::Text(
                        serde_json::to_string(&envelope)
                            .expect("serialize request envelope")
                            .into(),
                    ))
                    .await
                    .expect("send request envelope");

                let response_text = match ws_stream.next().await {
                    Some(Ok(WsMessage::Text(text))) => text,
                    other => panic!("expected response text, got {other:?}"),
                };
                let response: ResponseEnvelope =
                    serde_json::from_str(&response_text).expect("parse response envelope");
                observation.lock().expect("relay observation lock").response = Some(response);

                ws_sink
                    .send(WsMessage::Close(None))
                    .await
                    .expect("send close");

                if let Some(done_tx) = done_tx.lock().expect("done tx lock").take() {
                    done_tx.send(()).expect("signal relay completion");
                }
            }
        })
        .await;
        drop(done_tx);

        let outcome = run_relay_session(
            &RelayClientConfig {
                api_base_url: format!("http://{relay_addr}"),
                api_token: "token-123".to_string(),
                runtime_registration_id: "runtime-123".to_string(),
                local_gateway_port: local_addr.port(),
            },
            true,
        )
        .await;

        assert!(matches!(outcome, SessionOutcome::CleanClose));
        tokio::time::timeout(Duration::from_secs(1), done_rx)
            .await
            .expect("relay server completion timed out")
            .expect("relay server completed");

        let observation = observation.lock().expect("relay observation lock").clone();
        assert_eq!(
            observation.registration,
            Some(serde_json::json!({
                "runtime_registration_id": "runtime-123",
            }))
        );
        assert_eq!(observation.pong, Some(vec![1, 2, 3]));
        let response = observation.response.expect("relay response");
        assert_eq!(response.request_id, "req-relay");
        assert_eq!(response.status, StatusCode::OK.as_u16());
        assert_eq!(response.body, "forwarded");
        assert!(!response.streaming);
        assert_eq!(
            response
                .headers
                .get("x-relay-client-test")
                .map(String::as_str),
            Some("ok")
        );

        let captured = captured
            .lock()
            .expect("captured request lock")
            .clone()
            .expect("captured request");
        assert_eq!(
            captured,
            CapturedLocalRequest {
                method: "POST".to_string(),
                host: Some(local_addr.to_string()),
                custom_header: Some("present".to_string()),
                body: "payload".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn run_relay_session_streams_event_stream_frames_after_registration() {
        let captured = Arc::new(Mutex::new(None::<CapturedLocalRequest>));
        let local_addr = spawn_local_gateway(Arc::clone(&captured)).await;

        let streamed_frames = Arc::new(Mutex::new(Vec::<ResponseEnvelope>::new()));
        let (done_tx, done_rx) = oneshot::channel();
        let done_tx = Arc::new(Mutex::new(Some(done_tx)));
        let streamed_frames_for_handler = Arc::clone(&streamed_frames);
        let done_tx_for_handler = Arc::clone(&done_tx);

        let relay_addr = spawn_relay_server(move |socket| {
            let streamed_frames = Arc::clone(&streamed_frames_for_handler);
            let done_tx = Arc::clone(&done_tx_for_handler);
            async move {
                let (mut ws_sink, mut ws_stream) = socket.split();

                match ws_stream.next().await {
                    Some(Ok(WsMessage::Text(_))) => {}
                    other => panic!("expected registration text, got {other:?}"),
                }

                let ack = serde_json::json!({
                    "type": "registered",
                    "runtime_registration_id": "runtime-stream",
                });
                ws_sink
                    .send(WsMessage::Text(ack.to_string().into()))
                    .await
                    .expect("send registration ack");

                let envelope = RequestEnvelope {
                    request_id: "req-stream".to_string(),
                    method: "POST".to_string(),
                    path: "/stream".to_string(),
                    headers: HashMap::from([
                        ("host".to_string(), "ignored.example.com".to_string()),
                        ("x-custom-header".to_string(), "present".to_string()),
                    ]),
                    body: "payload".to_string(),
                };
                ws_sink
                    .send(WsMessage::Text(
                        serde_json::to_string(&envelope)
                            .expect("serialize request envelope")
                            .into(),
                    ))
                    .await
                    .expect("send request envelope");

                loop {
                    let message = tokio::time::timeout(Duration::from_secs(2), ws_stream.next())
                        .await
                        .expect("timed out waiting for streamed frame");
                    let message = match message {
                        Some(Ok(message)) => message,
                        other => panic!("expected streamed relay frame, got {other:?}"),
                    };

                    match message {
                        WsMessage::Text(text) => {
                            let frame: ResponseEnvelope =
                                serde_json::from_str(&text).expect("parse streamed frame");
                            let done = !frame.streaming;
                            streamed_frames
                                .lock()
                                .expect("streamed frames lock")
                                .push(frame);
                            if done {
                                break;
                            }
                        }
                        WsMessage::Ping(data) => {
                            ws_sink
                                .send(WsMessage::Pong(data))
                                .await
                                .expect("reply to ping");
                        }
                        other => panic!("unexpected relay message during stream: {other:?}"),
                    }
                }

                ws_sink
                    .send(WsMessage::Close(None))
                    .await
                    .expect("send close");

                if let Some(done_tx) = done_tx.lock().expect("done tx lock").take() {
                    done_tx.send(()).expect("signal relay completion");
                }
            }
        })
        .await;
        drop(done_tx);

        let outcome = run_relay_session(
            &RelayClientConfig {
                api_base_url: format!("http://{relay_addr}"),
                api_token: "token-123".to_string(),
                runtime_registration_id: "runtime-stream".to_string(),
                local_gateway_port: local_addr.port(),
            },
            true,
        )
        .await;

        assert!(matches!(outcome, SessionOutcome::CleanClose));
        tokio::time::timeout(Duration::from_secs(1), done_rx)
            .await
            .expect("relay server completion timed out")
            .expect("relay server completed");

        let frames = streamed_frames
            .lock()
            .expect("streamed frames lock")
            .clone();
        assert!(
            frames.len() >= 3,
            "expected initial headers frame, data frame, and final completion frame"
        );

        let first = frames.first().expect("initial streamed frame");
        assert_eq!(first.request_id, "req-stream");
        assert_eq!(first.status, StatusCode::OK.as_u16());
        assert!(first.streaming);
        assert!(first.body.is_empty());
        assert_eq!(
            first.headers.get("content-type").map(String::as_str),
            Some("text/event-stream")
        );
        assert_eq!(
            first.headers.get("server-timing").map(String::as_str),
            Some("gateway_upstream;dur=12.5")
        );

        let last = frames.last().expect("final streamed frame");
        assert!(!last.streaming);
        assert!(last.body.is_empty());

        let streamed_body = frames
            .iter()
            .skip(1)
            .take(frames.len().saturating_sub(2))
            .map(|frame| frame.body.as_str())
            .collect::<Vec<_>>()
            .join("");
        assert!(streamed_body.contains("data: {\"delta\":\"hello\"}"));
        assert!(streamed_body.contains("data: [DONE]"));

        let captured = captured
            .lock()
            .expect("captured request lock")
            .clone()
            .expect("captured request");
        assert_eq!(
            captured,
            CapturedLocalRequest {
                method: "POST".to_string(),
                host: Some(local_addr.to_string()),
                custom_header: Some("present".to_string()),
                body: "payload".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn run_relay_session_rejects_mismatched_registration_ack() {
        let relay_addr = spawn_relay_server(|socket| async move {
            let (mut ws_sink, mut ws_stream) = socket.split();
            match ws_stream.next().await {
                Some(Ok(WsMessage::Text(_))) => {}
                other => panic!("expected registration text, got {other:?}"),
            }

            let ack = serde_json::json!({
                "type": "registered",
                "runtime_registration_id": "runtime-other",
            });
            ws_sink
                .send(WsMessage::Text(ack.to_string().into()))
                .await
                .expect("send mismatched ack");
        })
        .await;

        let outcome = run_relay_session(
            &RelayClientConfig {
                api_base_url: format!("http://{relay_addr}"),
                api_token: "token-123".to_string(),
                runtime_registration_id: "runtime-123".to_string(),
                local_gateway_port: 9,
            },
            true,
        )
        .await;

        match outcome {
            SessionOutcome::ConnectionFailed(error) => {
                assert!(
                    error
                        .to_string()
                        .contains("runtime_registration_id mismatch"),
                    "unexpected error: {error}"
                );
            }
            _ => panic!("expected registration failure"),
        }
    }

    #[tokio::test]
    async fn run_relay_session_rejects_invalid_json_registration_ack() {
        let relay_addr = spawn_relay_server(|socket| async move {
            let (mut ws_sink, mut ws_stream) = socket.split();
            match ws_stream.next().await {
                Some(Ok(WsMessage::Text(_))) => {}
                other => panic!("expected registration text, got {other:?}"),
            }

            ws_sink
                .send(WsMessage::Text("not-json".into()))
                .await
                .expect("send invalid ack");
        })
        .await;

        let outcome = run_relay_session(
            &RelayClientConfig {
                api_base_url: format!("http://{relay_addr}"),
                api_token: "token-123".to_string(),
                runtime_registration_id: "runtime-123".to_string(),
                local_gateway_port: 9,
            },
            true,
        )
        .await;

        match outcome {
            SessionOutcome::ConnectionFailed(error) => {
                assert!(
                    error.to_string().contains("invalid registration ack"),
                    "unexpected error: {error}"
                );
            }
            _ => panic!("expected registration failure"),
        }
    }

    #[tokio::test]
    async fn run_relay_session_rejects_unexpected_registration_ack_type() {
        let relay_addr = spawn_relay_server(|socket| async move {
            let (mut ws_sink, mut ws_stream) = socket.split();
            match ws_stream.next().await {
                Some(Ok(WsMessage::Text(_))) => {}
                other => panic!("expected registration text, got {other:?}"),
            }

            let ack = serde_json::json!({
                "type": "accepted",
                "runtime_registration_id": "runtime-123",
            });
            ws_sink
                .send(WsMessage::Text(ack.to_string().into()))
                .await
                .expect("send unexpected ack type");
        })
        .await;

        let outcome = run_relay_session(
            &RelayClientConfig {
                api_base_url: format!("http://{relay_addr}"),
                api_token: "token-123".to_string(),
                runtime_registration_id: "runtime-123".to_string(),
                local_gateway_port: 9,
            },
            true,
        )
        .await;

        match outcome {
            SessionOutcome::ConnectionFailed(error) => {
                assert!(
                    error
                        .to_string()
                        .contains("unexpected registration ack type"),
                    "unexpected error: {error}"
                );
            }
            _ => panic!("expected registration failure"),
        }
    }

    #[tokio::test]
    async fn run_relay_session_rejects_non_text_registration_ack() {
        let relay_addr = spawn_relay_server(|socket| async move {
            let (mut ws_sink, mut ws_stream) = socket.split();
            match ws_stream.next().await {
                Some(Ok(WsMessage::Text(_))) => {}
                other => panic!("expected registration text, got {other:?}"),
            }

            ws_sink
                .send(WsMessage::Binary(vec![1, 2, 3].into()))
                .await
                .expect("send binary ack");
        })
        .await;

        let outcome = run_relay_session(
            &RelayClientConfig {
                api_base_url: format!("http://{relay_addr}"),
                api_token: "token-123".to_string(),
                runtime_registration_id: "runtime-123".to_string(),
                local_gateway_port: 9,
            },
            true,
        )
        .await;

        match outcome {
            SessionOutcome::ConnectionFailed(error) => {
                assert!(
                    error
                        .to_string()
                        .contains("unexpected non-text registration ack"),
                    "unexpected error: {error}"
                );
            }
            _ => panic!("expected registration failure"),
        }
    }

    #[tokio::test]
    async fn run_relay_session_rejects_close_frame_during_registration() {
        let relay_addr = spawn_relay_server(|socket| async move {
            let (mut ws_sink, mut ws_stream) = socket.split();
            match ws_stream.next().await {
                Some(Ok(WsMessage::Text(_))) => {}
                other => panic!("expected registration text, got {other:?}"),
            }

            ws_sink
                .send(WsMessage::Close(None))
                .await
                .expect("send close during registration");
        })
        .await;

        let outcome = run_relay_session(
            &RelayClientConfig {
                api_base_url: format!("http://{relay_addr}"),
                api_token: "token-123".to_string(),
                runtime_registration_id: "runtime-123".to_string(),
                local_gateway_port: 9,
            },
            true,
        )
        .await;

        match outcome {
            SessionOutcome::ConnectionFailed(error) => {
                assert!(
                    error
                        .to_string()
                        .contains("server closed connection during registration"),
                    "unexpected error: {error}"
                );
            }
            _ => panic!("expected registration failure"),
        }
    }

    #[tokio::test]
    async fn run_relay_session_rejects_connection_drop_before_registration_ack() {
        let relay_addr = spawn_relay_server(|socket| async move {
            let (_ws_sink, mut ws_stream) = socket.split();
            match ws_stream.next().await {
                Some(Ok(WsMessage::Text(_))) => {}
                other => panic!("expected registration text, got {other:?}"),
            }
        })
        .await;

        let outcome = run_relay_session(
            &RelayClientConfig {
                api_base_url: format!("http://{relay_addr}"),
                api_token: "token-123".to_string(),
                runtime_registration_id: "runtime-123".to_string(),
                local_gateway_port: 9,
            },
            true,
        )
        .await;

        match outcome {
            SessionOutcome::ConnectionFailed(error) => {
                assert!(
                    error
                        .to_string()
                        .contains("connection closed before registration ack"),
                    "unexpected error: {error}"
                );
            }
            _ => panic!("expected registration failure"),
        }
    }

    #[tokio::test]
    async fn run_relay_session_allows_reconnected_branch_after_registration() {
        let relay_addr = spawn_relay_server(|socket| async move {
            let (mut ws_sink, mut ws_stream) = socket.split();
            match ws_stream.next().await {
                Some(Ok(WsMessage::Text(_))) => {}
                other => panic!("expected registration text, got {other:?}"),
            }

            let ack = serde_json::json!({
                "type": "registered",
                "runtime_registration_id": "runtime-123",
            });
            ws_sink
                .send(WsMessage::Text(ack.to_string().into()))
                .await
                .expect("send registration ack");
            ws_sink
                .send(WsMessage::Close(None))
                .await
                .expect("send close");
        })
        .await;

        let outcome = run_relay_session(
            &RelayClientConfig {
                api_base_url: format!("http://{relay_addr}"),
                api_token: "token-123".to_string(),
                runtime_registration_id: "runtime-123".to_string(),
                local_gateway_port: 9,
            },
            false,
        )
        .await;

        assert!(matches!(outcome, SessionOutcome::CleanClose));
    }

    #[test]
    fn request_envelope_serde_roundtrip() {
        let envelope = RequestEnvelope {
            request_id: "req-1".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
            body: "test body".to_string(),
        };
        let json = serde_json::to_string(&envelope).unwrap();
        let recovered: RequestEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.request_id, "req-1");
        assert_eq!(recovered.method, "POST");
        assert_eq!(recovered.body, "test body");
    }

    #[test]
    fn request_envelope_default_body() {
        let json = r#"{"request_id":"r","method":"GET","path":"/","headers":{}}"#;
        let env: RequestEnvelope = serde_json::from_str(json).unwrap();
        assert!(env.body.is_empty());
    }

    // ── ResponseEnvelope serde ──────────────────────────────────────────

    #[test]
    fn response_envelope_serde_roundtrip() {
        let envelope = ResponseEnvelope {
            request_id: "req-1".to_string(),
            status: 200,
            headers: HashMap::from([("x-test".to_string(), "value".to_string())]),
            body: "response body".to_string(),
            streaming: false,
        };
        let json = serde_json::to_string(&envelope).unwrap();
        let recovered: ResponseEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.status, 200);
        assert!(!recovered.streaming);
    }

    #[test]
    fn response_envelope_defaults() {
        let json = r#"{"request_id":"r"}"#;
        let env: ResponseEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(env.status, 0);
        assert!(env.headers.is_empty());
        assert!(env.body.is_empty());
        assert!(!env.streaming);
    }

    // ── Constants ───────────────────────────────────────────────────────

    #[test]
    fn relay_client_constants() {
        assert_eq!(MAX_BACKOFF, Duration::from_secs(30));
        assert_eq!(INITIAL_BACKOFF, Duration::from_secs(1));
        assert_eq!(LOCAL_REQUEST_TIMEOUT, Duration::from_secs(30));
        assert_eq!(CLIENT_PING_INTERVAL, Duration::from_secs(20));
        assert_eq!(IDLE_TIMEOUT, Duration::from_secs(45));
    }

    // ── RelayClientConfig ───────────────────────────────────────────────

    #[test]
    fn relay_client_config_clone() {
        let config = RelayClientConfig {
            api_base_url: "https://api.example.com".to_string(),
            api_token: "tok".to_string(),
            runtime_registration_id: "reg-1".to_string(),
            local_gateway_port: 8080,
        };
        let cloned = config.clone();
        assert_eq!(cloned.api_base_url, "https://api.example.com");
        assert_eq!(cloned.local_gateway_port, 8080);
    }

    // ── RelayClientConfig debug ──────────────────────────────────────

    #[test]
    fn relay_client_config_debug_format() {
        let config = RelayClientConfig {
            api_base_url: "https://api.example.com".to_string(),
            api_token: "secret".to_string(),
            runtime_registration_id: "reg-1".to_string(),
            local_gateway_port: 8080,
        };
        let debug = format!("{:?}", config);
        assert!(debug.contains("api_base_url"));
    }

    // ── RequestEnvelope edge cases ──────────────────────────────────

    #[test]
    fn request_envelope_with_headers() {
        let envelope = RequestEnvelope {
            request_id: "req-h".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: HashMap::from([
                ("authorization".to_string(), "Bearer tok".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
            ]),
            body: "{}".to_string(),
        };
        assert_eq!(envelope.headers.len(), 2);
    }

    // ── ResponseEnvelope streaming ──────────────────────────────────

    #[test]
    fn response_envelope_streaming_flag() {
        let env = ResponseEnvelope {
            request_id: "req-s".to_string(),
            status: 200,
            headers: HashMap::new(),
            body: "data: test\n\n".to_string(),
            streaming: true,
        };
        assert!(env.streaming);
    }
}
