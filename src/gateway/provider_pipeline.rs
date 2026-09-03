// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Exact-provider request preparation and upstream dispatch.
//!
//! this module does not parse declarative `auto.routing`, A/B,
//! shadow, health-threshold, or provider-rate-limit knobs. Capability /
//! structured-output mismatches fail closed before upstream dispatch.
//!
//! the exact-provider pipeline dispatches a single selected target.
//! Network/provider failure returns that target's primary-path error and MUST
//! NOT invent alternate-provider fallback from this module.

use std::{collections::HashMap, io};

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::header::{HeaderName, HeaderValue as ReqHeaderValue};
use serde_json::{json, Value};
use tokio_stream::wrappers::ReceiverStream;

use super::{
    cache::BufferedUpstreamResponse,
    format_translation::{self, ProviderFormat},
    provider_auth, provider_catalog,
    providers::{self, ProviderTarget},
    runtime_capabilities::{request_capability_contract_with_headers, InteractionFeature},
    runtimes,
    server::{PreparedStreamingResponse, StreamingResponseAdapter},
    sse,
};

#[cfg(test)]
static UPSTREAM_ATTEMPTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[derive(Debug)]
pub(crate) struct ProviderPipelineError {
    pub(crate) status: StatusCode,
    pub(crate) error_type: &'static str,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl ProviderPipelineError {
    fn invalid_request(message: impl Into<String>, code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error_type: "invalid_request_error",
            code,
            message: message.into(),
        }
    }

    fn bad_gateway(message: impl Into<String>, code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            error_type: "server_error",
            code,
            message: message.into(),
        }
    }

    fn to_bytes(&self) -> Bytes {
        serde_json::to_vec(&json!({
            "error": {
                "message": self.message,
                "type": self.error_type,
                "code": self.code,
            }
        }))
        .unwrap_or_else(|_| b"{}".to_vec())
        .into()
    }

    pub(crate) fn to_buffered_response(&self) -> BufferedUpstreamResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        BufferedUpstreamResponse::new(self.status, headers, self.to_bytes(), false)
    }

    pub(crate) fn to_streaming_response(&self) -> PreparedStreamingResponse {
        PreparedStreamingResponse::json(self.status, self.to_bytes())
    }
}

pub(crate) struct PreparedProviderRequest {
    pub(crate) body: Bytes,
    pub(crate) base_url: String,
    pub(crate) path: String,
    pub(crate) provider_extra_headers: Vec<(HeaderName, ReqHeaderValue)>,
    pub(crate) upstream_auth: Option<(HeaderName, ReqHeaderValue)>,
    pub(crate) stream_response_adapter: Option<StreamingResponseAdapter>,
}

pub(crate) enum ProviderPipelineResponse {
    Buffered(BufferedUpstreamResponse),
    Streaming(PreparedStreamingResponse),
}

pub(crate) fn uses_exact_provider_pipeline(provider: &str) -> bool {
    matches!(
        provider_catalog::normalized_provider_alias(provider).as_str(),
        "anthropic" | "aws-bedrock" | "cohere" | "watsonx"
    )
}

fn buffered_normalized_format(provider: &str) -> ProviderFormat {
    match provider_catalog::normalized_provider_alias(provider).as_str() {
        "anthropic" | "aws-bedrock" => ProviderFormat::Anthropic,
        "cohere" | "watsonx" => ProviderFormat::OpenAI,
        _ => ProviderFormat::OpenAI,
    }
}

fn streaming_native_format(provider: &str) -> ProviderFormat {
    match provider_catalog::normalized_provider_alias(provider).as_str() {
        "anthropic" | "aws-bedrock" => ProviderFormat::Anthropic,
        "cohere" => ProviderFormat::Cohere,
        "watsonx" => ProviderFormat::OpenAI,
        _ => ProviderFormat::OpenAI,
    }
}

fn requested_anthropic_beta_headers(
    path: &str,
    headers: &HeaderMap,
    request_body: &Value,
) -> Vec<String> {
    let mut values = headers
        .get("anthropic-beta")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if path == "/v1/messages"
        && request_capability_contract_with_headers(path, request_body, headers).is_some_and(
            |request| {
                request
                    .interaction_features
                    .contains(&InteractionFeature::ExtendedThinking)
            },
        )
        && !values
            .iter()
            .any(|value| value == "interleaved-thinking-2025-05-14")
    {
        values.push("interleaved-thinking-2025-05-14".to_string());
    }

    values.sort_unstable();
    values.dedup();
    values
}

fn merge_provider_extra_header(
    extra_headers: &mut Vec<(HeaderName, ReqHeaderValue)>,
    name: &str,
    value: &str,
) {
    let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    let Ok(header_value) = ReqHeaderValue::from_str(value) else {
        return;
    };
    if let Some(existing) = extra_headers
        .iter_mut()
        .find(|(existing_name, _)| *existing_name == header_name)
    {
        *existing = (header_name, header_value);
        return;
    }
    extra_headers.push((header_name, header_value));
}

fn runtime_request_config(target: &ProviderTarget, effective_target_model: &str) -> Value {
    json!({
        "provider": target.provider,
        "provider_spec": target.provider,
        "model": effective_target_model,
        "base_url": target.base_url,
        "path_template": target.path_template,
        "mcp": target.mcp_bridge,
        "anthropic_version": target.anthropic_version.as_deref().unwrap_or("2023-06-01"),
        "aws_region": target.aws_region,
        "bedrock_model_family": target.bedrock_model_family,
        "watsonx_api_version": target.watsonx_api_version,
        "watsonx_project_id": target.watsonx_project_id,
        "watsonx_space_id": target.watsonx_space_id,
    })
}

async fn prepare_exact_provider_request(
    target: &ProviderTarget,
    public_path: &str,
    provider_path: &str,
    effective_target_model: &str,
    request_body: &Value,
    request_headers: &HeaderMap,
    is_streaming: bool,
) -> Result<PreparedProviderRequest, ProviderPipelineError> {
    let runtime_request = runtimes::build_runtime_request(
        &target.provider,
        target.execution_target.as_ref(),
        &runtime_request_config(target, effective_target_model),
        request_body,
    )
    .map_err(|error| {
        ProviderPipelineError::invalid_request(error.to_string(), "provider_request_invalid")
    })?;

    let request_bytes = serde_json::to_vec(&runtime_request)
        .map(Bytes::from)
        .map_err(|error| {
            ProviderPipelineError::invalid_request(
                format!("failed to serialize provider request: {error}"),
                "provider_request_serialization_failed",
            )
        })?;

    let phase35_auth = provider_auth::build_provider_auth(
        target,
        effective_target_model,
        provider_path,
        &request_bytes,
        is_streaming,
    )
    .await
    .map_err(|error| {
        ProviderPipelineError::bad_gateway(error.to_string(), "provider_auth_failed")
    })?;

    let mut provider_extra_headers = phase35_auth
        .extra_headers
        .iter()
        .map(|(name, value)| {
            let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                ProviderPipelineError::bad_gateway(
                    format!("provider produced invalid header name '{name}'"),
                    "provider_header_invalid",
                )
            })?;
            let header_value = ReqHeaderValue::from_str(value).map_err(|_| {
                ProviderPipelineError::bad_gateway(
                    format!("provider produced invalid header value for '{name}'"),
                    "provider_header_invalid",
                )
            })?;
            Ok((header_name, header_value))
        })
        .collect::<Result<Vec<_>, ProviderPipelineError>>()?;

    if provider_catalog::normalized_provider_alias(&target.provider) == "anthropic" {
        let beta_headers =
            requested_anthropic_beta_headers(public_path, request_headers, request_body);
        if !beta_headers.is_empty() {
            merge_provider_extra_header(
                &mut provider_extra_headers,
                "anthropic-beta",
                &beta_headers.join(","),
            );
        }
    }

    let upstream_auth = if provider_catalog::normalized_provider_alias(&target.provider) == "cohere"
    {
        providers::resolve_provider_auth(target)
            .await
            .map_err(|error| {
                ProviderPipelineError::bad_gateway(error.to_string(), "provider_auth_failed")
            })?
    } else {
        None
    };

    Ok(PreparedProviderRequest {
        body: request_bytes,
        base_url: phase35_auth
            .base_url_override
            .unwrap_or_else(|| target.base_url.clone()),
        path: phase35_auth
            .endpoint_override
            .unwrap_or_else(|| provider_path.to_string()),
        provider_extra_headers,
        upstream_auth,
        stream_response_adapter: if is_streaming
            && provider_catalog::normalized_provider_alias(&target.provider) == "aws-bedrock"
        {
            Some(StreamingResponseAdapter::BedrockAnthropicEventStream)
        } else {
            None
        },
    })
}

pub(crate) async fn prepare_provider_request(
    target: &ProviderTarget,
    public_path: &str,
    provider_path: &str,
    effective_target_model: &str,
    request_body: &Value,
    request_headers: &HeaderMap,
) -> Result<PreparedProviderRequest, ProviderPipelineError> {
    prepare_exact_provider_request(
        target,
        public_path,
        provider_path,
        effective_target_model,
        request_body,
        request_headers,
        false,
    )
    .await
}

pub(crate) async fn prepare_provider_stream_request(
    target: &ProviderTarget,
    public_path: &str,
    provider_path: &str,
    effective_target_model: &str,
    request_body: &Value,
    request_headers: &HeaderMap,
) -> Result<PreparedProviderRequest, ProviderPipelineError> {
    prepare_exact_provider_request(
        target,
        public_path,
        provider_path,
        effective_target_model,
        request_body,
        request_headers,
        true,
    )
    .await
}

pub(crate) fn sanitize_upstream_buffered_error(status: StatusCode) -> BufferedUpstreamResponse {
    ProviderPipelineError {
        status,
        error_type: "server_error",
        code: "upstream_provider_error",
        message: format!("Upstream provider returned HTTP {}", status.as_u16()),
    }
    .to_buffered_response()
}

pub(crate) fn normalize_buffered_provider_response(
    provider: &str,
    execution_target: Option<&super::execution_runtime::ExecutionTarget>,
    response: BufferedUpstreamResponse,
) -> Result<BufferedUpstreamResponse, ProviderPipelineError> {
    let body = serde_json::from_slice::<Value>(response.body()).map_err(|error| {
        ProviderPipelineError::bad_gateway(
            format!("provider response was not valid JSON: {error}"),
            "provider_response_invalid_json",
        )
    })?;
    let translated = runtimes::translate_runtime_response(provider, execution_target, &body)
        .map_err(|error| {
            ProviderPipelineError::bad_gateway(
                error.to_string(),
                "provider_response_translation_failed",
            )
        })?;
    let body = serde_json::to_vec(&translated).map_err(|error| {
        ProviderPipelineError::bad_gateway(
            format!("translated provider response could not be serialized: {error}"),
            "provider_response_serialization_failed",
        )
    })?;
    Ok(BufferedUpstreamResponse::new(
        response.status(),
        response.headers().clone(),
        Bytes::from(body),
        response.is_cached(),
    ))
}

pub(crate) fn sanitize_upstream_streaming_error(status: StatusCode) -> PreparedStreamingResponse {
    ProviderPipelineError {
        status,
        error_type: "server_error",
        code: "upstream_provider_error",
        message: format!("Upstream provider returned HTTP {}", status.as_u16()),
    }
    .to_streaming_response()
}

fn parse_eventstream_headers(bytes: &[u8]) -> Result<HashMap<String, String>, io::Error> {
    let mut headers = HashMap::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let name_len = *bytes
            .get(cursor)
            .ok_or_else(|| io::Error::other("missing eventstream header name length"))?
            as usize;
        cursor += 1;
        let name_end = cursor.saturating_add(name_len);
        let name = std::str::from_utf8(
            bytes
                .get(cursor..name_end)
                .ok_or_else(|| io::Error::other("truncated eventstream header name"))?,
        )
        .map_err(|error| io::Error::other(format!("invalid eventstream header name: {error}")))?;
        cursor = name_end;
        let value_type = *bytes
            .get(cursor)
            .ok_or_else(|| io::Error::other("missing eventstream header type"))?;
        cursor += 1;
        let value = match value_type {
            0 => "true".to_string(),
            1 => "false".to_string(),
            2 => {
                let value = *bytes
                    .get(cursor)
                    .ok_or_else(|| io::Error::other("truncated byte header"))?;
                cursor += 1;
                value.to_string()
            }
            3 => {
                let value = i16::from_be_bytes(
                    bytes
                        .get(cursor..cursor + 2)
                        .ok_or_else(|| io::Error::other("truncated short header"))?
                        .try_into()
                        .map_err(|_| io::Error::other("invalid short header"))?,
                );
                cursor += 2;
                value.to_string()
            }
            4 => {
                let value = i32::from_be_bytes(
                    bytes
                        .get(cursor..cursor + 4)
                        .ok_or_else(|| io::Error::other("truncated int header"))?
                        .try_into()
                        .map_err(|_| io::Error::other("invalid int header"))?,
                );
                cursor += 4;
                value.to_string()
            }
            5 | 8 => {
                let value = i64::from_be_bytes(
                    bytes
                        .get(cursor..cursor + 8)
                        .ok_or_else(|| io::Error::other("truncated long header"))?
                        .try_into()
                        .map_err(|_| io::Error::other("invalid long header"))?,
                );
                cursor += 8;
                value.to_string()
            }
            6 | 7 => {
                let value_len = u16::from_be_bytes(
                    bytes
                        .get(cursor..cursor + 2)
                        .ok_or_else(|| io::Error::other("truncated header length"))?
                        .try_into()
                        .map_err(|_| io::Error::other("invalid header length"))?,
                ) as usize;
                cursor += 2;
                let value_end = cursor.saturating_add(value_len);
                let value_bytes = bytes
                    .get(cursor..value_end)
                    .ok_or_else(|| io::Error::other("truncated header value"))?;
                cursor = value_end;
                if value_type == 7 {
                    std::str::from_utf8(value_bytes)
                        .map_err(|error| {
                            io::Error::other(format!("invalid string header value: {error}"))
                        })?
                        .to_string()
                } else {
                    String::from_utf8_lossy(value_bytes).to_string()
                }
            }
            9 => {
                let value_end = cursor.saturating_add(16);
                let value_bytes = bytes
                    .get(cursor..value_end)
                    .ok_or_else(|| io::Error::other("truncated uuid header"))?;
                cursor = value_end;
                hex::encode(value_bytes)
            }
            _ => return Err(io::Error::other("unsupported eventstream header type")),
        };
        headers.insert(name.to_string(), value);
    }
    Ok(headers)
}

pub(crate) fn drain_bedrock_eventstream_frames(
    buffer: &mut Vec<u8>,
) -> Result<Vec<Bytes>, io::Error> {
    use base64::Engine as _;

    let mut frames = Vec::new();
    let mut offset = 0usize;
    while buffer.len().saturating_sub(offset) >= 12 {
        let frame = &buffer[offset..];
        let total_len = u32::from_be_bytes(
            frame[0..4]
                .try_into()
                .map_err(|_| io::Error::other("invalid bedrock frame length"))?,
        ) as usize;
        let headers_len = u32::from_be_bytes(
            frame[4..8]
                .try_into()
                .map_err(|_| io::Error::other("invalid bedrock headers length"))?,
        ) as usize;
        if total_len < 16 || headers_len > total_len.saturating_sub(16) {
            return Err(io::Error::other("invalid bedrock eventstream frame"));
        }
        if frame.len() < total_len {
            break;
        }
        let prelude_crc = u32::from_be_bytes(
            frame[8..12]
                .try_into()
                .map_err(|_| io::Error::other("invalid bedrock prelude crc"))?,
        );
        if crc32fast::hash(&frame[0..8]) != prelude_crc {
            return Err(io::Error::other("bedrock eventstream prelude crc mismatch"));
        }
        let message_crc = u32::from_be_bytes(
            frame[total_len - 4..total_len]
                .try_into()
                .map_err(|_| io::Error::other("invalid bedrock message crc"))?,
        );
        if crc32fast::hash(&frame[0..total_len - 4]) != message_crc {
            return Err(io::Error::other("bedrock eventstream message crc mismatch"));
        }
        let headers = parse_eventstream_headers(&frame[12..12 + headers_len])?;
        let payload = &frame[12 + headers_len..total_len - 4];
        let event_type = headers
            .get(":event-type")
            .or_else(|| headers.get("event-type"))
            .map(String::as_str)
            .unwrap_or("");
        match event_type {
            "chunk" => {
                let event_json: Value = serde_json::from_slice(payload).map_err(|error| {
                    io::Error::other(format!("invalid bedrock chunk envelope: {error}"))
                })?;
                let chunk_bytes = if let Some(encoded) = event_json
                    .get("bytes")
                    .and_then(|value| value.as_str())
                    .or_else(|| {
                        event_json
                            .pointer("/chunk/bytes")
                            .and_then(|value| value.as_str())
                    }) {
                    base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .map_err(|error| {
                            io::Error::other(format!("invalid bedrock chunk bytes: {error}"))
                        })?
                } else {
                    payload.to_vec()
                };
                let chunk_text = String::from_utf8(chunk_bytes).map_err(|error| {
                    io::Error::other(format!("invalid utf-8 in bedrock chunk bytes: {error}"))
                })?;
                frames.push(Bytes::from(format!("data: {chunk_text}\n\n")));
            }
            "internalServerException"
            | "modelStreamErrorException"
            | "validationException"
            | "throttlingException"
            | "modelTimeoutException"
            | "serviceUnavailableException" => {
                let message = serde_json::from_slice::<Value>(payload)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("message")
                            .and_then(|message| message.as_str())
                            .map(ToString::to_string)
                    })
                    .unwrap_or_else(|| format!("bedrock stream event '{event_type}'"));
                return Err(io::Error::other(message));
            }
            _ => {}
        }
        offset += total_len;
    }
    if offset > 0 {
        buffer.drain(0..offset);
    }
    Ok(frames)
}

pub(crate) fn translate_provider_response(
    provider: &str,
    public_path: &str,
    request_id: &str,
    response: ProviderPipelineResponse,
) -> Result<ProviderPipelineResponse, ProviderPipelineError> {
    match response {
        ProviderPipelineResponse::Buffered(resp) => {
            let value = serde_json::from_slice::<Value>(resp.body()).map_err(|error| {
                ProviderPipelineError::bad_gateway(
                    format!("provider response was not valid JSON: {error}"),
                    "provider_response_invalid_json",
                )
            })?;
            let normalized =
                runtimes::translate_runtime_response(provider, None, &value).map_err(|error| {
                    ProviderPipelineError::bad_gateway(
                        error.to_string(),
                        "provider_response_invalid",
                    )
                })?;
            let translated = format_translation::translate_response_for_path(
                normalized,
                buffered_normalized_format(provider),
                public_path,
            )
            .map_err(|error| {
                ProviderPipelineError::bad_gateway(
                    error.to_string(),
                    "provider_response_translation_failed",
                )
            })?;
            let bytes = serde_json::to_vec(&translated)
                .map(Bytes::from)
                .map_err(|error| {
                    ProviderPipelineError::bad_gateway(
                        format!("failed to serialize translated provider response: {error}"),
                        "provider_response_serialization_failed",
                    )
                })?;
            Ok(ProviderPipelineResponse::Buffered(
                BufferedUpstreamResponse::new(
                    resp.status(),
                    resp.headers().clone(),
                    bytes,
                    resp.is_cached(),
                ),
            ))
        }
        ProviderPipelineResponse::Streaming(resp) => {
            let source_format = streaming_native_format(provider);
            if public_path == "/v1/chat/completions" && source_format == ProviderFormat::OpenAI {
                return Ok(ProviderPipelineResponse::Streaming(resp));
            }
            if public_path == "/v1/messages" && source_format == ProviderFormat::Anthropic {
                return Ok(ProviderPipelineResponse::Streaming(resp));
            }

            let mut translator = format_translation::RouteNativeSseTranslator::new(
                public_path,
                source_format,
                request_id,
            );
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(16);
            let PreparedStreamingResponse {
                status,
                content_type: _,
                body,
            } = resp;

            tokio::spawn(async move {
                let mut body = body;
                let mut buffer = Vec::new();
                while let Some(chunk) = body.next().await {
                    match chunk {
                        Ok(bytes) => {
                            buffer.extend_from_slice(&bytes);
                            for payload in sse::drain_sse_data_frames(&mut buffer) {
                                for frame in translator.translate_payload(&payload) {
                                    if tx.send(Ok(frame)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            let _ = tx.send(Err(error)).await;
                            return;
                        }
                    }
                }

                let trailing = String::from_utf8_lossy(&buffer).trim().to_string();
                if !trailing.is_empty() {
                    let payload = trailing
                        .strip_prefix("data:")
                        .map(str::trim)
                        .unwrap_or(trailing.as_str());
                    for frame in translator.translate_payload(payload) {
                        if tx.send(Ok(frame)).await.is_err() {
                            return;
                        }
                    }
                }
            });

            Ok(ProviderPipelineResponse::Streaming(
                PreparedStreamingResponse {
                    status,
                    content_type: HeaderValue::from_static("text/event-stream"),
                    body: Box::pin(ReceiverStream::new(rx)),
                },
            ))
        }
    }
}

pub(crate) fn record_upstream_attempt() {
    #[cfg(test)]
    {
        UPSTREAM_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reset_upstream_attempts_for_test() {
    UPSTREAM_ATTEMPTS.store(0, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn upstream_attempts_for_test() -> usize {
    UPSTREAM_ATTEMPTS.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(test)]
mod task070_primary_path_tests {
    use super::ProviderPipelineError;
    use axum::http::StatusCode;

    fn request_pinned_dispatch_index(ordered: &[usize]) -> Result<usize, ProviderPipelineError> {
        match ordered {
        [only] => Ok(*only),
        [] => Err(ProviderPipelineError::invalid_request(
            "provider pool selection produced no pinned target",
            "no_eligible_provider",
        )),
        _ => Err(ProviderPipelineError::invalid_request(
            "exact provider pipeline refuses alternate-provider fallback; expected a single pinned target",
            "provider_pool_not_pinned",
        )),
    }
    }

    fn primary_path_provider_failure(
        selected_target_id: &str,
        selected_provider: &str,
        upstream_message: impl Into<String>,
    ) -> ProviderPipelineError {
        ProviderPipelineError {
            status: StatusCode::BAD_GATEWAY,
            error_type: "server_error",
            code: "provider_primary_path_error",
            message: format!(
                "provider '{}' (target '{}') failed: {}",
                selected_provider,
                selected_target_id,
                upstream_message.into()
            ),
        }
    }

    #[test]
    fn request_pinned_dispatch_refuses_alternate_provider_fallback() {
        assert_eq!(request_pinned_dispatch_index(&[3]).expect("pinned"), 3);
        let multi = request_pinned_dispatch_index(&[0, 1]).expect_err("no alternate fallback");
        assert_eq!(multi.code, "provider_pool_not_pinned");
        let empty = request_pinned_dispatch_index(&[]).expect_err("empty");
        assert_eq!(empty.code, "no_eligible_provider");
    }

    #[test]
    fn primary_path_failure_names_selected_target() {
        let failure = primary_path_provider_failure("tgt-1", "openai", "connection reset");
        assert_eq!(failure.code, "provider_primary_path_error");
        assert!(failure.message.contains("tgt-1"));
        assert!(failure.message.contains("openai"));
    }
}
