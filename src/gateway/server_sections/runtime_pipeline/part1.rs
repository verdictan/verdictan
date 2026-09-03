// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Server section module.
//! Child of `gateway::server`; parent private items remain visible via `use crate::gateway::*`.
use super::super::*;

pub(crate) fn should_run_shadow_evaluation(
    shadow_routing: &EffectiveShadowRouting,
    mirror: &crate::gateway::providers::TrafficMirrorConfig,
) -> bool {
    shadow_routing.enabled
        && mirror.enabled
        && mirror.mirror_target.is_some()
        && mirror.sample_rate > 0.0
        && mirror
            .sample_rate
            .partial_cmp(&0.0)
            .is_some_and(|ordering| ordering.is_gt())
}

pub(crate) fn shadow_sampled(sample_rate: f64) -> bool {
    if sample_rate >= 1.0 {
        return true;
    }
    if sample_rate <= 0.0 {
        return false;
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as f64
        / 1_000_000_000.0;
    nanos < sample_rate
}

pub(crate) async fn execute_shadow_provider_request(
    client: reqwest::Client,
    target: crate::gateway::providers::ProviderTarget,
    path: String,
    request_id: String,
    traceparent: String,
    content_type: Option<HeaderValue>,
    request_json: serde_json::Value,
) -> Result<StatusCode, anyhow::Error> {
    let mut provider_body = request_json;
    if !target.model.is_empty() && target.model.trim() != "*" {
        provider_body["model"] = serde_json::Value::String(target.model.clone());
    }
    strip_runtime_contract_fields(&mut provider_body);
    let provider_path = crate::gateway::providers::resolve_provider_path(&target, &path);
    let provider_bytes = serde_json::to_vec(&provider_body)
        .map(Bytes::from)
        .map_err(|error| anyhow::anyhow!("shadow request serialization failed: {error}"))?;
    let phase35_auth = crate::gateway::provider_auth::build_provider_auth(
        &target,
        &target.model,
        &provider_path,
        &provider_bytes,
        false,
    )
    .await
    .map_err(|error| anyhow::anyhow!("shadow auth resolution failed: {error}"))?;
    let resolved_base = phase35_auth
        .base_url_override
        .unwrap_or_else(|| target.base_url.clone());
    let effective_path = phase35_auth.endpoint_override.unwrap_or(provider_path);
    let upstream_url = join_upstream(
        &resolved_base,
        &rewrite_upstream_path(&resolved_base, &effective_path),
    );

    let request_client = if target.allow_insecure_tls {
        shared_insecure_gateway_http_client()
    } else {
        client
    };

    let mut request = request_client
        .post(upstream_url)
        .header("X-Request-Id", request_id)
        .header("traceparent", traceparent)
        .body(provider_bytes);
    if let Some(content_type) = content_type {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    if let Some((name, value)) = crate::gateway::providers::resolve_provider_auth(&target).await? {
        request = request.header(name, value);
    }
    for (name, value) in phase35_auth.extra_headers {
        request = request.header(name, value);
    }

    let response = request.send().await?;
    Ok(response.status())
}

/// Why a configured shadow mirror did not receive egress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShadowSkipReason {
    MirrorsPrimaryTarget,
    TargetNotConfigured,
    UsageAuthorizationDenied,
    NotInAcceptedProviderOrder,
}

impl ShadowSkipReason {
    pub(crate) fn reason_code(self) -> &'static str {
        match self {
            Self::MirrorsPrimaryTarget => "shadow_skip.mirrors_primary_target",
            Self::TargetNotConfigured => "shadow_skip.target_not_configured",
            Self::UsageAuthorizationDenied => "shadow_skip.usage_authorization_denied",
            Self::NotInAcceptedProviderOrder => "shadow_skip.not_in_accepted_provider_order",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShadowEgressDecision {
    Dispatch { target_index: usize },
    Skip(ShadowSkipReason),
}

/// Decides whether a configured shadow mirror may receive egress.
///
/// The mirror must be a target the primary request pipeline already accepted:
/// present in the final accepted provider order and absent from the
/// usage-authorization denied set. A target dropped by the context, model-group,
/// price, usage-authorization, region, quantization, cost, capability, or `routing.only`
/// controls is therefore unreachable from the shadow path too, so no excluded
/// target can receive request-derived egress on any dispatch path.
///
/// The gate applies to every capture mode. `metadata_only` does not forward the
/// request body, but which mirror is contacted and that a request occurred are
/// themselves request-derived, so both modes share the single invariant rather
/// than splitting it.
pub(crate) fn shadow_egress_decision(
    registry: &crate::gateway::providers::ProviderRegistry,
    accepted_order: &[usize],
    ua_denied_target_ids: &std::collections::HashSet<String>,
    shadow_target_id: &str,
    primary_provider_id: &str,
) -> ShadowEgressDecision {
    if shadow_target_id == primary_provider_id {
        return ShadowEgressDecision::Skip(ShadowSkipReason::MirrorsPrimaryTarget);
    }
    let Some(target_index) = registry
        .targets
        .iter()
        .position(|target| target.id == shadow_target_id)
    else {
        return ShadowEgressDecision::Skip(ShadowSkipReason::TargetNotConfigured);
    };
    if ua_denied_target_ids.contains(shadow_target_id) {
        return ShadowEgressDecision::Skip(ShadowSkipReason::UsageAuthorizationDenied);
    }
    if !accepted_order.contains(&target_index) {
        return ShadowEgressDecision::Skip(ShadowSkipReason::NotInAcceptedProviderOrder);
    }
    ShadowEgressDecision::Dispatch { target_index }
}

pub fn maybe_spawn_shadow_evaluation(
    state: &ActiveGatewayStateView<'_>,
    registry: &crate::gateway::providers::ProviderRegistry,
    accepted_order: &[usize],
    headers: &HeaderMap,
    path: &str,
    request_json: &serde_json::Value,
    primary_provider_id: &str,
    request_id: &str,
    traceparent: &str,
) {
    let mirror = &registry.traffic_mirror;
    if !should_run_shadow_evaluation(&state.shadow_routing, mirror)
        || !shadow_sampled(mirror.sample_rate)
    {
        return;
    }
    let Some(shadow_target_id) = mirror.mirror_target.as_deref() else {
        return;
    };
    let target_index = match shadow_egress_decision(
        registry,
        accepted_order,
        &state.ua_denied_target_ids,
        shadow_target_id,
        primary_provider_id,
    ) {
        ShadowEgressDecision::Dispatch { target_index } => target_index,
        ShadowEgressDecision::Skip(reason) => {
            // Shadow evaluation is optional observability: record bounded,
            // non-secret evidence and leave the primary request untouched.
            tracing::warn!(
                request_id = %request_id,
                shadow_target_id = %shadow_target_id,
                reason_code = reason.reason_code(),
                "shadow evaluation skipped: mirror target is not an accepted provider candidate"
            );
            return;
        }
    };
    let target = registry.targets[target_index].clone();
    let decision_id = format!("shadow-{}", uuid::Uuid::new_v4().simple());
    let capture_mode = if state.runtime_privacy_restricted {
        "metadata_only".to_string()
    } else {
        state.shadow_routing.capture_mode.clone()
    };
    let event_sink = state.event_sink.clone();
    let request_id_owned = request_id.to_string();
    let traceparent_owned = traceparent.to_string();
    let primary_provider_id = primary_provider_id.to_string();
    let path_owned = path.to_string();
    let request_family = path.trim_start_matches("/v1/").replace('/', "_");
    let content_type = headers.get(header::CONTENT_TYPE).cloned();
    let request_json = request_json.clone();
    let client = state.client.clone();
    let payload_bytes = ShadowEvaluationJob::estimate_payload_bytes(
        &path_owned,
        &request_id_owned,
        &traceparent_owned,
        &request_json,
        &capture_mode,
        &primary_provider_id,
        &request_family,
        &decision_id,
        &target.id,
    );
    let job = ShadowEvaluationJob {
        client,
        target,
        path: path_owned,
        request_id: request_id_owned.clone(),
        traceparent: traceparent_owned,
        content_type,
        request_json,
        capture_mode,
        event_sink,
        primary_provider_id,
        request_family,
        decision_id,
        payload_bytes,
    };

    // PERF-016: admit into the bounded shadow worker queue instead of an
    // unbounded per-request tokio::spawn.
    match ShadowEvaluationQueue::shared().try_enqueue(job) {
        Ok(()) => {}
        Err(reason) => {
            tracing::warn!(
                request_id = %request_id_owned,
                drop_reason = ?reason,
                "shadow evaluation dropped: bounded queue admission rejected job"
            );
        }
    }
}

/// Enable shadow routing on a state view for PERF-016 fixtures.
#[doc(hidden)]
pub fn enable_shadow_routing_for_test(state: &mut ActiveGatewayStateView<'_>, capture_mode: &str) {
    state.shadow_routing = EffectiveShadowRouting {
        enabled: true,
        capture_mode: capture_mode.to_string(),
    };
}

pub(crate) fn distributed_tenant_scope(state: &ActiveGatewayStateView<'_>) -> String {
    let locality_scope = locality_scope_fragment(
        state.requested_region_group.as_deref(),
        state.managed_public_endpoint_host.as_deref(),
    );

    if state.connected_mode {
        if let Some(org_id) = state
            .request_finops
            .as_ref()
            .and_then(|context| context.org_id.as_deref())
        {
            return locality_scope
                .as_ref()
                .map(|scope| format!("org:{org_id}:{scope}"))
                .unwrap_or_else(|| format!("org:{org_id}"));
        }
        return locality_scope
            .as_ref()
            .map(|scope| format!("org:unknown:{scope}"))
            .unwrap_or_else(|| "org:unknown".to_string());
    }

    let base = state
        .gateway_id
        .as_ref()
        .map(|gateway_id| format!("gateway:{gateway_id}"))
        .unwrap_or_else(|| "gateway:global".to_string());

    locality_scope
        .as_ref()
        .map(|scope| format!("{base}:{scope}"))
        .unwrap_or(base)
}

pub(crate) fn buffered_response_to_http_response(
    response: crate::gateway::cache::BufferedUpstreamResponse,
    request_id: &str,
    traceparent: &str,
) -> Response<Body> {
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/json"));
    let mut extra_headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            if name == header::CONTENT_TYPE
                || name == header::CONTENT_LENGTH
                || *name == header::HeaderName::from_static("x-request-id")
                || *name == header::HeaderName::from_static("traceparent")
            {
                return None;
            }
            Some((name.clone(), value.clone()))
        })
        .collect::<Vec<_>>();
    append_cache_status_header(&mut extra_headers, response.is_cached());

    build_response(
        response.status(),
        content_type,
        request_id.to_string(),
        traceparent.to_string(),
        response.body().clone(),
        false,
        Some(extra_headers),
    )
}

pub(crate) fn prepared_streaming_response_to_http_response(
    response: PreparedStreamingResponse,
    request_id: &str,
    traceparent: &str,
) -> Response<Body> {
    let mut resp = Response::new(Body::from_stream(response.body));
    *resp.status_mut() = response.status;

    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, response.content_type);
    if let Ok(value) = HeaderValue::from_str(request_id) {
        headers.insert(header::HeaderName::from_static("x-request-id"), value);
    }
    if let Ok(value) = HeaderValue::from_str(traceparent) {
        headers.insert(header::HeaderName::from_static("traceparent"), value);
    }
    maybe_insert_server_timing_header(headers);

    resp
}

pub(crate) async fn resolve_websocket_upstream_target(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    path: &'static str,
    request_id: &str,
    traceparent: &str,
) -> Result<crate::gateway::websocket_proxy::WebSocketUpstreamTarget, Response<Body>> {
    if let Some(registry) = &state.provider_registry {
        if !registry.targets.is_empty() {
            let provider_pin = headers
                .get("x-verdictan-provider")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());

            let ordered = if let Some(ref provider_pin) = provider_pin {
                let pinned = registry.resolve_provider_pin(provider_pin);
                if pinned.is_empty() {
                    return Err(build_request_error_response(
                        StatusCode::BAD_REQUEST,
                        request_id,
                        traceparent,
                        &format!(
                            "X-Verdictan-Provider '{}' does not match any configured provider target",
                            provider_pin
                        ),
                        "invalid_provider_pin",
                        "unknown_provider",
                    ));
                }
                pinned
            } else {
                crate::gateway::provider_metrics::select_providers(
                    &registry.targets,
                    &registry.routing,
                    state.provider_metrics,
                )
            };

            let ordered = if let Some(pinned_id) = state
                .ua_pinned_target_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                let pinned: Vec<usize> = ordered
                    .iter()
                    .copied()
                    .filter(|index| registry.targets[*index].id == pinned_id)
                    .collect();
                if pinned.is_empty() {
                    return Err(build_request_error_response(
                        StatusCode::FORBIDDEN,
                        request_id,
                        traceparent,
                        "No eligible upstream provider is available for websocket traffic",
                        "access_denied",
                        "no_eligible_provider",
                    ));
                }
                pinned
            } else {
                ordered
            };

            let mut last_inactive: Option<Response<Body>> = None;
            for index in ordered {
                let target = &registry.targets[index];
                let target =
                    match prepare_connected_provider_target(state, target, &target.model).await {
                        Ok(ConnectedTargetResolution::Ready(target)) => target,
                        Ok(ConnectedTargetResolution::Inactive {
                            status,
                            message,
                            status_reason,
                        }) => {
                            tracing::warn!(
                                request_id = %request_id,
                                provider_id = %target.id,
                                status_reason = %status_reason,
                                "provider target inactive during websocket preparation"
                            );
                            last_inactive = Some(build_request_error_response(
                                status,
                                request_id,
                                traceparent,
                                &message,
                                "server_error",
                                "provider_target_inactive",
                            ));
                            continue;
                        }
                        Err(error) => {
                            return Err(build_request_error_response(
                                StatusCode::SERVICE_UNAVAILABLE,
                                request_id,
                                traceparent,
                                &format!("Connected access preflight failed: {error}"),
                                "server_error",
                                "access_preflight_failed",
                            ));
                        }
                    };

                if target.execution_target.is_some() {
                    last_inactive = Some(build_request_error_response(
                        StatusCode::BAD_GATEWAY,
                        request_id,
                        traceparent,
                        "The selected provider target does not support websocket proxying",
                        "server_error",
                        "websocket_upstream_unavailable",
                    ));
                    continue;
                }

                let provider_path = crate::gateway::providers::resolve_provider_path(&target, path);
                let phase35_auth = crate::gateway::provider_auth::build_provider_auth(
                    &target,
                    &target.model,
                    &provider_path,
                    b"{}",
                    true,
                )
                .await
                .map_err(|error| {
                    build_request_error_response(
                        StatusCode::BAD_GATEWAY,
                        request_id,
                        traceparent,
                        &error.to_string(),
                        "server_error",
                        "provider_auth_failed",
                    )
                })?;
                let base_url = phase35_auth
                    .base_url_override
                    .clone()
                    .unwrap_or_else(|| target.base_url.clone());
                let mut auth_header = crate::gateway::providers::resolve_provider_auth(&target)
                    .await
                    .map_err(|error| {
                        build_request_error_response(
                            StatusCode::BAD_GATEWAY,
                            request_id,
                            traceparent,
                            &error.to_string(),
                            "server_error",
                            "provider_auth_failed",
                        )
                    })?
                    .and_then(|(name, value)| {
                        value
                            .to_str()
                            .ok()
                            .map(|value| (name.to_string(), value.to_string()))
                    });
                let mut extra_headers = phase35_auth.extra_headers;

                if auth_header.is_none() {
                    if let Some(index) = extra_headers
                        .iter()
                        .position(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                    {
                        let (name, value) = extra_headers.remove(index);
                        auth_header = Some((name, value));
                    }
                } else if let Some((auth_name, _)) = auth_header.as_ref() {
                    extra_headers.retain(|(name, _)| !name.eq_ignore_ascii_case(auth_name));
                }

                return Ok(crate::gateway::websocket_proxy::WebSocketUpstreamTarget {
                    base_url,
                    auth_header,
                    extra_headers,
                });
            }

            if let Some(response) = last_inactive {
                return Err(response);
            }

            return Err(build_request_error_response(
                StatusCode::BAD_GATEWAY,
                request_id,
                traceparent,
                "No eligible upstream provider is available for websocket traffic",
                "server_error",
                "websocket_upstream_unavailable",
            ));
        }
    }

    if state.connected_mode {
        return Err(build_request_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            traceparent,
            missing_provider_registry_message(true),
            "server_error",
            "provider_registry_missing",
        ));
    }

    Ok(crate::gateway::websocket_proxy::WebSocketUpstreamTarget {
        base_url: state.upstream_base.to_string(),
        auth_header: state.upstream_auth.as_ref().and_then(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        }),
        extra_headers: state
            .provider_extra_headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.to_string(), value.to_string()))
            })
            .collect(),
    })
}

pub(crate) fn resolve_request(
    path: &str,
    method: &str,
    headers: &HeaderMap,
    state: &ActiveGatewayStateView<'_>,
) -> RequestResolution {
    let matched_route = state.route_config.resolve(path, method, headers).cloned();
    let consumer_group = state
        .consumer_groups
        .as_ref()
        .and_then(|config| config.resolve(headers));

    RequestResolution {
        matched_route,
        consumer_group,
    }
}

/// API token prefix for all token-backed access/API tokens.
pub(crate) const API_TOKEN_KEY_PREFIX: &str = "vdt_";

/// Returns `true` if the raw bearer value looks like a Verdictan token-backed
/// credential we should route to the token validation endpoint. Gateway Keys
/// share the `vdt_` token system prefix and are validated by the API.
#[inline]
pub fn is_api_token(raw: &str) -> bool {
    raw.starts_with(API_TOKEN_KEY_PREFIX)
}

pub(crate) fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn build_request_error_response(
    status: StatusCode,
    request_id: &str,
    traceparent: &str,
    message: &str,
    error_type: &'static str,
    code: &'static str,
) -> Response<Body> {
    let body = serde_json::json!({
        "error": error_json(message, error_type, code),
    });
    let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    build_response(
        status,
        HeaderValue::from_static("application/json"),
        request_id.to_string(),
        traceparent.to_string(),
        Bytes::from(text),
        false,
        None,
    )
}

/// Build an HTTP 400 response for a caller-supplied `X-Request-Id` that violates
/// the usage-authorization request-id grammar. The gateway rejects the
/// request outright rather than truncating or replacing the caller's identifier;
/// the response echoes a freshly generated valid id so downstream correlation
/// still works, and never reflects the rejected input back to the caller.
pub(crate) fn reject_invalid_x_request_id(
    headers: &HeaderMap,
    error: &request_id::InvalidRequestId,
) -> Response<Body> {
    let traceparent_in = headers.get("traceparent").and_then(|v| v.to_str().ok());
    let traceparent = request_id::normalize_or_generate_traceparent(traceparent_in);
    let fallback_request_id = uuid::Uuid::new_v4().to_string();
    build_request_error_response(
        StatusCode::BAD_REQUEST,
        &fallback_request_id,
        &traceparent,
        error.reason,
        "invalid_request_error",
        "invalid_request_id",
    )
}

pub(crate) const AUDIO_TRANSCRIPTION_DECODED_MAX_BYTES: usize = 26_214_400;
pub(crate) const AUDIO_TRANSCRIPTION_ENCODED_MAX_BYTES: usize = 34_952_536;
pub(crate) const AUDIO_SPEECH_INPUT_MAX_BYTES: usize = 16_384;
pub(crate) const AUDIO_REQUEST_JSON_OVERHEAD_BYTES: usize = 65_536;
pub(crate) const AUDIO_TRANSCRIPTION_ALLOWED_FORMATS: &[&str] =
    &["wav", "mp3", "mp4", "mpeg", "mpga", "m4a", "webm", "ogg"];
pub(crate) const AUDIO_SPEECH_ALLOWED_OUTPUT_FORMATS: &[&str] =
    &["mp3", "wav", "opus", "aac", "flac", "pcm"];
pub(crate) const OPENAI_AUDIO_SPEECH_VOICES: &[&str] = &[
    "alloy", "ash", "ballad", "coral", "echo", "fable", "nova", "onyx", "sage", "shimmer", "verse",
];

#[derive(Debug, Clone)]
pub(crate) struct RuntimePreflightError {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
    pub(crate) details: serde_json::Value,
}

impl RuntimePreflightError {
    pub(crate) fn validation_failed(message: &'static str, details: serde_json::Value) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "request.validation_failed",
            message,
            details,
        }
    }

    pub(crate) fn new(
        status: StatusCode,
        code: &'static str,
        message: &'static str,
        details: serde_json::Value,
    ) -> Self {
        Self {
            status,
            code,
            message,
            details,
        }
    }
}

pub(crate) fn runtime_error_id(request_id: &str) -> String {
    format!("err_{}", request_id.trim_start_matches("req_"))
}

pub(crate) fn runtime_error_envelope(
    status: StatusCode,
    request_id: &str,
    code: &str,
    message: &str,
    details: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "error": {
            "status": status.as_u16(),
            "code": code,
            "message": message,
            "details": details,
            "error_id": runtime_error_id(request_id),
            "request_id": request_id,
        }
    })
}

pub(crate) fn build_runtime_json_response(
    status: StatusCode,
    request_id: &str,
    traceparent: &str,
    code: &str,
    message: &str,
    details: serde_json::Value,
) -> Response<Body> {
    let body = runtime_error_envelope(status, request_id, code, message, details);
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    build_response(
        status,
        HeaderValue::from_static("application/json"),
        request_id.to_string(),
        traceparent.to_string(),
        Bytes::from(bytes),
        false,
        None,
    )
}

pub(crate) fn runtime_error_body_bytes(
    status: StatusCode,
    request_id: &str,
    code: &str,
    message: &str,
    details: serde_json::Value,
) -> Bytes {
    let body = runtime_error_envelope(status, request_id, code, message, details);
    Bytes::from(serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()))
}

pub(crate) fn build_runtime_preflight_response(
    request_id: &str,
    traceparent: &str,
    error: &RuntimePreflightError,
) -> Response<Body> {
    build_runtime_json_response(
        error.status,
        request_id,
        traceparent,
        error.code,
        error.message,
        error.details.clone(),
    )
}

pub(crate) fn build_runtime_capability_buffered_response(
    error: &crate::gateway::runtime_capabilities::RuntimeCapabilityError,
    request_id: &str,
) -> crate::gateway::cache::BufferedUpstreamResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let bytes = runtime_error_body_bytes(
        StatusCode::UNPROCESSABLE_ENTITY,
        request_id,
        error.code(),
        &error.browser_safe_message(),
        error.details(),
    );
    crate::gateway::cache::BufferedUpstreamResponse::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        headers,
        bytes,
        false,
    )
}

pub(crate) fn build_runtime_capability_streaming_response(
    error: &crate::gateway::runtime_capabilities::RuntimeCapabilityError,
    request_id: &str,
) -> PreparedStreamingResponse {
    prepared_streaming_json_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        runtime_error_body_bytes(
            StatusCode::UNPROCESSABLE_ENTITY,
            request_id,
            error.code(),
            &error.browser_safe_message(),
            error.details(),
        ),
        HeaderValue::from_static("application/json"),
    )
}

pub(crate) fn filter_targets_by_runtime_capabilities(
    path: &str,
    headers: &HeaderMap,
    request_body: &serde_json::Value,
    targets: &[crate::gateway::providers::ProviderTarget],
    ordered: &[usize],
    request_id: &str,
) -> Result<Vec<usize>, crate::gateway::runtime_capabilities::RuntimeCapabilityError> {
    let Some(request_contract) =
        crate::gateway::runtime_capabilities::request_capability_contract_with_headers(
            path,
            request_body,
            headers,
        )
    else {
        return Ok(ordered.to_vec());
    };
    let mut eligible = Vec::with_capacity(ordered.len());
    let mut first_error = None;

    for &index in ordered {
        let target = &targets[index];
        let contract =
            crate::gateway::provider_catalog::capability_contract_for_provider(&target.provider);
        let allow_missing_contract = crate::gateway::runtimes::resolve_runtime_for_target(
            &target.provider,
            target.execution_target.as_ref(),
        )
        .is_some()
            || !matches!(
                crate::gateway::execution_runtime::classify_capability(&target.provider),
                crate::gateway::execution_runtime::ExecutionCapability::UnsupportedAtConfigTime
            );
        match crate::gateway::runtime_capabilities::validate_runtime_capability_contract(
            contract.as_ref(),
            &request_contract,
            allow_missing_contract,
        ) {
            Ok(()) => eligible.push(index),
            Err(error) => {
                tracing::debug!(
                    request_id = %request_id,
                    provider_id = %target.id,
                    provider = %target.provider,
                    capability_error = %error,
                    capability_code = error.code(),
                    "runtime capability contract rejected provider candidate"
                );
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }

    if eligible.is_empty() {
        return Err(first_error.unwrap_or(
            crate::gateway::runtime_capabilities::RuntimeCapabilityError::MissingContract,
        ));
    }

    Ok(eligible)
}

pub(crate) fn filter_targets_by_model_capabilities(
    path: &str,
    headers: &HeaderMap,
    request_body: &serde_json::Value,
    targets: &[crate::gateway::providers::ProviderTarget],
    ordered: &[usize],
    request_id: &str,
    model_pin: Option<&str>,
    catalog_snapshot: Option<&crate::gateway::provider_catalog::CatalogSnapshot>,
) -> Result<Vec<usize>, crate::gateway::runtime_capabilities::RuntimeCapabilityError> {
    let Some(request_contract) =
        crate::gateway::runtime_capabilities::request_capability_contract_with_headers(
            path,
            request_body,
            headers,
        )
    else {
        return Ok(ordered.to_vec());
    };
    let requested_model = request_body
        .get("model")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let mut eligible = Vec::with_capacity(ordered.len());
    let mut first_error = None;

    for &index in ordered {
        let target = &targets[index];
        match validate_target_model_capabilities(
            target,
            request_body,
            &request_contract,
            requested_model,
            model_pin,
            catalog_snapshot,
        ) {
            Ok(()) => eligible.push(index),
            Err(error) => {
                tracing::debug!(
                    request_id = %request_id,
                    provider_id = %target.id,
                    provider = %target.provider,
                    capability_error = %error,
                    capability_code = error.code(),
                    "resolved model capability metadata rejected provider candidate"
                );
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }

    if eligible.is_empty() {
        return Err(first_error.unwrap_or(
            crate::gateway::runtime_capabilities::RuntimeCapabilityError::MissingContract,
        ));
    }

    Ok(eligible)
}

pub(crate) fn parse_runtime_json_body(
    body: &Bytes,
) -> Result<serde_json::Value, RuntimePreflightError> {
    serde_json::from_slice(body).map_err(|_| {
        RuntimePreflightError::validation_failed(
            "The runtime request body must be valid JSON.",
            serde_json::json!({ "field": "body" }),
        )
    })
}

pub(crate) fn required_string_field<'a>(
    body: &'a serde_json::Value,
    pointer: &str,
) -> Result<&'a str, RuntimePreflightError> {
    body.pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            RuntimePreflightError::validation_failed(
                "The runtime request is missing a required string field.",
                serde_json::json!({ "field": pointer.trim_start_matches('/') }),
            )
        })
}

pub(crate) fn normalized_audio_transcription_format(
    body: &serde_json::Value,
) -> Result<&str, RuntimePreflightError> {
    let format = required_string_field(body, "/input_audio/format")?;
    let normalized = format.trim().to_ascii_lowercase();
    if AUDIO_TRANSCRIPTION_ALLOWED_FORMATS.contains(&normalized.as_str()) {
        return Ok(body
            .pointer("/input_audio/format")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(format));
    }

    Err(RuntimePreflightError::new(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "runtime.audio.unsupported_input_format",
        "Audio input format is not supported for transcriptions.",
        serde_json::json!({
            "field": "input_audio.format",
            "allowed_formats": AUDIO_TRANSCRIPTION_ALLOWED_FORMATS,
            "provided_format": normalized,
        }),
    ))
}

pub(crate) fn normalized_audio_speech_output_format(
    body: &serde_json::Value,
) -> Result<String, RuntimePreflightError> {
    let format = body
        .get("response_format")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("mp3")
        .trim()
        .to_ascii_lowercase();
    if AUDIO_SPEECH_ALLOWED_OUTPUT_FORMATS.contains(&format.as_str()) {
        return Ok(format);
    }

    Err(RuntimePreflightError::new(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "runtime.audio.unsupported_output_format",
        "Speech output format is not supported.",
        serde_json::json!({
            "field": "response_format",
            "allowed_formats": AUDIO_SPEECH_ALLOWED_OUTPUT_FORMATS,
            "provided_format": format,
        }),
    ))
}

pub(crate) fn validate_audio_transcription_request(
    body: &serde_json::Value,
) -> Result<(), RuntimePreflightError> {
    let _model = required_string_field(body, "/model")?;
    let _format = normalized_audio_transcription_format(body)?;
    let encoded_audio = required_string_field(body, "/input_audio/data")?;

    if let Some(language) = body.get("language") {
        if language
            .as_str()
            .map(str::trim)
            .is_none_or(|value| value.is_empty())
        {
            return Err(RuntimePreflightError::validation_failed(
                "The optional language field must be a non-empty string when provided.",
                serde_json::json!({ "field": "language" }),
            ));
        }
    }

    if encoded_audio.len() > AUDIO_TRANSCRIPTION_ENCODED_MAX_BYTES {
        return Err(RuntimePreflightError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "runtime.audio.encoded_size_exceeded",
            "Base64 audio input exceeds the runtime contract size limit.",
            serde_json::json!({
                "field": "input_audio.data",
                "max_bytes": AUDIO_TRANSCRIPTION_ENCODED_MAX_BYTES,
            }),
        ));
    }

    let decoded = BASE64_STANDARD.decode(encoded_audio).map_err(|_| {
        RuntimePreflightError::validation_failed(
            "Audio input must be valid base64.",
            serde_json::json!({ "field": "input_audio.data" }),
        )
    })?;

    if decoded.len() > AUDIO_TRANSCRIPTION_DECODED_MAX_BYTES {
        return Err(RuntimePreflightError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "runtime.audio.decoded_size_exceeded",
            "Decoded audio exceeds the runtime contract size limit.",
            serde_json::json!({
                "field": "input_audio.data",
                "max_bytes": AUDIO_TRANSCRIPTION_DECODED_MAX_BYTES,
            }),
        ));
    }

    Ok(())
}

pub(crate) fn voice_is_safe_identifier(voice: &str) -> bool {
    let trimmed = voice.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 64
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

pub(crate) fn speech_voice_supported_by_registry(
    state: &ActiveGatewayStateView<'_>,
    voice: &str,
) -> bool {
    let Some(registry) = state.provider_registry.as_ref() else {
        return true;
    };

    let mut saw_speech_target = false;
    let mut saw_generic_voice_target = false;
    for target in &registry.targets {
        let Some(contract) =
            crate::gateway::provider_catalog::capability_contract_for_provider(&target.provider)
        else {
            continue;
        };
        if !contract
            .request_families
            .contains(&crate::gateway::runtime_capabilities::RequestFamily::AudioSpeech)
        {
            continue;
        }
        saw_speech_target = true;
        let alias = crate::gateway::provider_catalog::normalized_provider_alias(&target.provider);
        if matches!(
            alias.as_str(),
            "openai" | "openai-chat" | "openai-responses" | "openrouter" | "azure" | "azure-openai"
        ) && OPENAI_AUDIO_SPEECH_VOICES.contains(&voice)
        {
            return true;
        }
        if matches!(alias.as_str(), "elevenlabs" | "eleven-labs") {
            saw_generic_voice_target = true;
        }
    }

    if saw_generic_voice_target {
        return voice_is_safe_identifier(voice);
    }

    if !saw_speech_target {
        return true;
    }

    OPENAI_AUDIO_SPEECH_VOICES.contains(&voice)
}

pub(crate) fn validate_audio_speech_request(
    state: &ActiveGatewayStateView<'_>,
    body: &serde_json::Value,
) -> Result<(), RuntimePreflightError> {
    let _model = required_string_field(body, "/model")?;
    let input = required_string_field(body, "/input")?;
    let voice = required_string_field(body, "/voice")?;
    let _response_format = normalized_audio_speech_output_format(body)?;

    if input.len() > AUDIO_SPEECH_INPUT_MAX_BYTES {
        return Err(RuntimePreflightError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "runtime.audio.speech_input_too_large",
            "Speech input exceeds the runtime contract size limit.",
            serde_json::json!({
                "field": "input",
                "max_bytes": AUDIO_SPEECH_INPUT_MAX_BYTES,
            }),
        ));
    }

    if !voice_is_safe_identifier(voice) {
        return Err(RuntimePreflightError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "runtime.audio.preflight_failed",
            "Speech voice is invalid for this request.",
            serde_json::json!({
                "field": "voice",
                "constraint": "voice must use only ASCII letters, digits, hyphens, or underscores",
            }),
        ));
    }

    if !speech_voice_supported_by_registry(state, voice) {
        return Err(RuntimePreflightError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "runtime.audio.preflight_failed",
            "Speech voice is not supported by the eligible runtime providers.",
            serde_json::json!({
                "field": "voice",
                "allowed_voices": OPENAI_AUDIO_SPEECH_VOICES,
            }),
        ));
    }

    if let Some(speed) = body.get("speed") {
        let Some(speed) = speed.as_f64() else {
            return Err(RuntimePreflightError::validation_failed(
                "Speech speed must be a number when provided.",
                serde_json::json!({ "field": "speed" }),
            ));
        };
        if !speed.is_finite() || !(0.25..=4.0).contains(&speed) {
            return Err(RuntimePreflightError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "runtime.audio.preflight_failed",
                "Speech speed must stay within the supported runtime range.",
                serde_json::json!({
                    "field": "speed",
                    "min": 0.25,
                    "max": 4.0,
                }),
            ));
        }
    }

    Ok(())
}

pub(crate) fn build_token_validation_error_response(
    request_id: &str,
    traceparent: &str,
    error: &TokenValidationError,
) -> Response<Body> {
    let message = match error {
        TokenValidationError::Unauthorized { .. }
        | TokenValidationError::Forbidden { .. } => {
            "API token validation is misconfigured: set VERDICTAN_API_TOKEN so the runtime can reach the control plane"
        }
        TokenValidationError::Request(_)
        | TokenValidationError::UnexpectedStatus { .. } => {
            "API token validation is temporarily unavailable"
        }
    };

    build_request_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        request_id,
        traceparent,
        message,
        "service_unavailable",
        "token_validation_unavailable",
    )
}

pub fn build_budget_filter_body(rejection: &BudgetFilterRejection) -> Bytes {
    Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "error": error_json(&rejection.message, rejection.error_type, rejection.code),
        }))
        .unwrap_or_else(|_| b"{}".to_vec()),
    )
}

pub(crate) fn build_budget_filter_buffered_response(
    rejection: &BudgetFilterRejection,
) -> crate::gateway::cache::BufferedUpstreamResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    crate::gateway::cache::BufferedUpstreamResponse::new(
        rejection.status,
        headers,
        build_budget_filter_body(rejection),
        false,
    )
}

pub(crate) fn build_budget_filter_streaming_response(
    rejection: &BudgetFilterRejection,
) -> PreparedStreamingResponse {
    prepared_streaming_json_response(
        rejection.status,
        build_budget_filter_body(rejection),
        HeaderValue::from_static("application/json"),
    )
}

pub(crate) fn build_provider_auth_body(message: &str) -> Bytes {
    serde_json::to_vec(&serde_json::json!({
        "error": error_json(message, "server_error", "provider_auth_failed"),
    }))
    .unwrap_or_else(|_| b"{}".to_vec())
    .into()
}

pub(crate) fn build_provider_auth_buffered_response(
    message: &str,
) -> crate::gateway::cache::BufferedUpstreamResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    crate::gateway::cache::BufferedUpstreamResponse::new(
        StatusCode::BAD_GATEWAY,
        headers,
        build_provider_auth_body(message),
        false,
    )
}

pub(crate) fn build_provider_auth_streaming_response(message: &str) -> PreparedStreamingResponse {
    prepared_streaming_json_response(
        StatusCode::BAD_GATEWAY,
        build_provider_auth_body(message),
        HeaderValue::from_static("application/json"),
    )
}

pub(crate) fn requested_anthropic_beta_headers(
    path: &str,
    headers: &HeaderMap,
    request_body: &serde_json::Value,
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
        && crate::gateway::runtime_capabilities::request_capability_contract_with_headers(
            path,
            request_body,
            headers,
        )
        .is_some_and(|request| {
            request.interaction_features.contains(
                &crate::gateway::runtime_capabilities::InteractionFeature::ExtendedThinking,
            )
        })
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

pub(crate) fn merge_provider_extra_header(
    extra_headers: &mut Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
    name: &str,
    value: &str,
) {
    let Ok(header_name) = reqwest::header::HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    let Ok(header_value) = reqwest::header::HeaderValue::from_str(value) else {
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

pub(crate) fn success_shape_valid_for_path(path: &str, body: &[u8]) -> bool {
    if path == "/v1/audio/speech" {
        return true;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };

    match path {
        "/v1/chat/completions" => value.get("choices").is_some(),
        "/v1/responses" => value.get("output").is_some(),
        "/v1/messages" => {
            value.get("content").is_some()
                && value.get("type").and_then(|value| value.as_str()) == Some("message")
        }
        _ => true,
    }
}

pub(crate) fn invalid_success_shape_buffered_response(
    path: &str,
) -> crate::gateway::cache::BufferedUpstreamResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let body = serde_json::json!({
        "error": error_json(
            &format!("Upstream returned a success payload that does not match the {} contract", path),
            "server_error",
            "invalid_upstream_success_shape",
        ),
    });
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    crate::gateway::cache::BufferedUpstreamResponse::new(
        StatusCode::BAD_GATEWAY,
        headers,
        Bytes::from(bytes),
        false,
    )
}

pub(crate) fn build_access_inactive_body(message: &str, status_reason: &str) -> Bytes {
    serde_json::to_vec(&serde_json::json!({
        "error": error_json(message, "access_inactive", status_reason),
    }))
    .unwrap_or_else(|_| b"{}".to_vec())
    .into()
}

pub(crate) fn build_access_inactive_buffered_response(
    status: StatusCode,
    message: &str,
    status_reason: &str,
) -> crate::gateway::cache::BufferedUpstreamResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    crate::gateway::cache::BufferedUpstreamResponse::new(
        status,
        headers,
        build_access_inactive_body(message, status_reason),
        false,
    )
}

pub(crate) fn build_access_inactive_streaming_response(
    status: StatusCode,
    message: &str,
    status_reason: &str,
) -> PreparedStreamingResponse {
    prepared_streaming_json_response(
        status,
        build_access_inactive_body(message, status_reason),
        HeaderValue::from_static("application/json"),
    )
}

pub(crate) fn access_inactive_status(status_reason: &str) -> StatusCode {
    match status_reason {
        "provider_key_policy_denied" | "provider_key_no_policy_binding" => StatusCode::FORBIDDEN,
        "unsupported_provider" => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

pub(crate) fn access_inactive_message(status_reason: &str, provider_id: &str) -> String {
    match status_reason {
        "provider_key_policy_denied" => {
            format!("Provider target '{provider_id}' is inactive: provider key access denied")
        }
        "provider_key_no_policy_binding" => {
            format!("Provider target '{provider_id}' is inactive: no provider-key policy binding")
        }
        "provider_key_not_configured" => {
            format!("Provider target '{provider_id}' is inactive: provider key is not configured")
        }
        "provider_key_seeded_default_deleted" => {
            format!("Provider target '{provider_id}' is inactive: seeded provider key was deleted")
        }
        "unsupported_provider" => {
            format!("Provider target '{provider_id}' is inactive: provider is unsupported")
        }
        other => format!("Provider target '{provider_id}' is inactive: {other}"),
    }
}

pub(crate) fn missing_provider_registry_message(connected_mode: bool) -> &'static str {
    if connected_mode {
        "no configuration is currently deployed to this gateway; connect it to the API and deploy an agent configuration first"
    } else {
        "no provider registry configured; a providers section with at least one target is required"
    }
}

pub(crate) fn optional_local_api_key_fallback(
    target: &crate::gateway::providers::ProviderTarget,
    allow_store_ref: bool,
) -> Option<(String, String)> {
    if target.required
        || !target.requires_provider_auth_material()
        || !target.api_key.trim().is_empty()
    {
        return None;
    }

    let secret_ref = target.secret_key_ref.as_ref()?;
    if let Some(env_name) = secret_ref.env_name() {
        let api_key = std::env::var(env_name).ok()?.trim().to_string();
        if api_key.is_empty() {
            return None;
        }

        return Some((env_name.to_string(), api_key));
    }

    if !allow_store_ref {
        return None;
    }

    let store_name = secret_ref.store_name()?;
    let mut candidates = Vec::with_capacity(2);
    if !store_name.starts_with("VERDICTAN_") {
        candidates.push(format!("VERDICTAN_{store_name}"));
    }
    candidates.push(store_name.to_string());

    for env_name in candidates {
        let api_key = match std::env::var(&env_name) {
            Ok(value) => value.trim().to_string(),
            Err(_) => continue,
        };
        if api_key.is_empty() {
            continue;
        }

        return Some((env_name, api_key));
    }

    None
}

pub(crate) fn missing_local_provider_key_message(
    target: &crate::gateway::providers::ProviderTarget,
    connected_mode: bool,
) -> String {
    if let Some(secret_ref) = target.secret_key_ref.as_ref() {
        if let Some(env_name) = secret_ref.env_name() {
            return format!(
                "Provider target '{}' is inactive: environment variable '{}' is not set",
                target.id, env_name
            );
        }
        if let Some(store_name) = secret_ref.store_name() {
            if connected_mode {
                return format!(
                    "Provider target '{}' is inactive: provider key '{}' is not configured in the control plane",
                    target.id, store_name
                );
            }
            return format!(
                "Provider target '{}' is inactive: store-backed secret '{}' requires a connected gateway or a matching local env fallback",
                target.id, store_name
            );
        }
    }

    format!(
        "Provider target '{}' is inactive: provider key is not configured",
        target.id
    )
}

pub(crate) fn resolve_local_provider_target(
    target: &crate::gateway::providers::ProviderTarget,
    connected_mode: bool,
    allow_store_ref: bool,
) -> ConnectedTargetResolution<crate::gateway::providers::ProviderTarget> {
    if crate::gateway::provider_catalog::is_unavailable_provider(&target.provider) {
        return ConnectedTargetResolution::Inactive {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: crate::gateway::provider_catalog::unavailable_provider_message(
                &target.provider,
            ),
            status_reason: "provider_unavailable".to_string(),
        };
    }

    let mut prepared = target.clone();
    if !prepared.api_key.trim().is_empty() {
        return ConnectedTargetResolution::Ready(prepared);
    }

    if let Some((_, api_key)) = optional_local_api_key_fallback(target, allow_store_ref) {
        prepared.api_key = api_key;
        return ConnectedTargetResolution::Ready(prepared);
    }

    if prepared.requires_provider_auth_material() {
        return ConnectedTargetResolution::Inactive {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: missing_local_provider_key_message(target, connected_mode),
            status_reason: "provider_key_not_configured".to_string(),
        };
    }

    ConnectedTargetResolution::Ready(prepared)
}

pub(crate) fn connected_provider_key_status_allows_local_fallback(status_reason: &str) -> bool {
    matches!(
        status_reason,
        "provider_key_not_configured" | "provider_key_seeded_default_deleted"
    )
}

pub(crate) fn provider_target_startup_status(
    connected_mode: bool,
    target: &crate::gateway::providers::ProviderTarget,
) -> (&'static str, String) {
    if crate::gateway::provider_catalog::is_unavailable_provider(&target.provider) {
        return (
            "rejected",
            crate::gateway::provider_catalog::unavailable_provider_message(&target.provider),
        );
    }

    if target.execution_target.is_some() {
        return if connected_mode {
            (
                "inactive",
                "connected gateways do not execute local or self-hosted targets".to_string(),
            )
        } else {
            (
                "ready",
                "local or self-hosted execution target is available".to_string(),
            )
        };
    }

    if connected_mode
        && crate::gateway::provider_auth::uses_organization_stored_provider_secret(target)
    {
        let local_env_available = optional_local_api_key_fallback(target, true).is_some();
        let store_name = target
            .secret_key_ref
            .as_ref()
            .and_then(|reference| reference.store_name())
            .unwrap_or("unknown");
        let reason = if local_env_available {
            format!(
                "waiting for connected provider-key resolution for '{}' (local env fallback available)",
                store_name
            )
        } else {
            format!(
                "waiting for connected provider-key resolution for '{}'",
                store_name
            )
        };
        return ("pending", reason);
    }

    if !target.requires_provider_auth_material() {
        return (
            "ready",
            "provider uses optional or self-managed credentials".to_string(),
        );
    }

    if !target.api_key.trim().is_empty() {
        return (
            "ready",
            "environment-backed credential resolved".to_string(),
        );
    }

    if let Some((env_name, _)) = optional_local_api_key_fallback(target, true) {
        return (
            "ready",
            format!("local environment fallback '{}' is available", env_name),
        );
    }

    (
        "inactive",
        missing_local_provider_key_message(target, connected_mode),
    )
}

pub(crate) fn log_provider_target_startup_statuses(
    connected_mode: bool,
    loaded_config: &LoadedDeclarativeConfig,
) {
    let Some(registry) = loaded_config.provider_registry.as_ref() else {
        return;
    };

    for target in &registry.targets {
        let (status, reason) = provider_target_startup_status(connected_mode, target);
        tracing::info!(
            provider_id = %target.id,
            provider = %target.provider,
            model = %target.model,
            required = target.required,
            status,
            reason = %reason,
            "gateway provider target status"
        );
    }
}

pub(crate) fn resolved_request_agent_id(state: &ActiveGatewayStateView<'_>) -> Option<String> {
    state.current_agent_id.clone().or_else(|| {
        state
            .request_finops
            .as_ref()
            .and_then(|finops| finops.agent_id.clone())
    })
}

pub(crate) fn extract_requested_max_tokens(request_body: &serde_json::Value) -> Option<u32> {
    request_body
        .get("max_tokens")
        .or_else(|| request_body.get("max_completion_tokens"))
        .or_else(|| request_body.get("max_output_tokens"))
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
}

pub(crate) fn tighter_remaining_budget(
    current: Option<f64>,
    candidate: Option<f64>,
) -> Option<f64> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.min(candidate)),
        (Some(current), None) => Some(current),
        (None, Some(candidate)) => Some(candidate),
        (None, None) => None,
    }
}

pub(crate) fn remaining_budget_from_records(records: &[GatewayBudgetRecord]) -> Option<f64> {
    records
        .iter()
        .map(|budget| (budget.max_budget - budget.current_spend).max(0.0))
        .reduce(f64::min)
}

#[derive(Clone, Debug, serde::Deserialize)]
pub(crate) struct GatewayAgentSummary {
    pub(crate) id: String,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct GatewayAgentListResponse {
    pub(crate) agents: Vec<GatewayAgentSummary>,
}

pub async fn resolve_runtime_agent_id(state: &ActiveGatewayStateView<'_>) -> Option<String> {
    if let Some(agent_id) =
        optional_env("VERDICTAN_AGENT_ID").filter(|value| !value.trim().is_empty())
    {
        return Some(agent_id);
    }

    if let Some(agent_id) = state
        .agents_runtime
        .as_ref()
        .and_then(|config| config.default_agent_id.clone())
        .filter(|value| !value.trim().is_empty())
    {
        return Some(agent_id);
    }

    match fetch_bound_gateway_agent(state).await {
        Ok(Some(agent)) => Some(agent.id),
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(error = %error, "gateway agent lookup failed");
            None
        }
    }
}

/// Fetch the single agent bound to this gateway (single-agent-per-gateway
/// constraint). Returns `None` when the gateway has no agent binding.
pub(crate) async fn fetch_bound_gateway_agent(
    state: &ActiveGatewayStateView<'_>,
) -> Result<Option<GatewayAgentSummary>, String> {
    let gateway_id = state
        .gateway_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "gateway id is unavailable".to_string())?
        .to_string();
    let sink = state
        .event_sink
        .as_ref()
        .ok_or_else(|| "control-plane event sink is unavailable".to_string())?;
    sink.fetch_bound_gateway_agent_binding(&gateway_id).await
}

pub(crate) async fn enforce_connected_deployed_agent_link(
    state: &ActiveGatewayStateView<'_>,
    request_id: &str,
    traceparent: &str,
) -> Result<(), Response<Body>> {
    if !state.connected_mode {
        return Ok(());
    }

    let Some(agent_id) = resolved_request_agent_id(state)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        tracing::warn!(
            request_id = %request_id,
            gateway_id = ?state.gateway_id,
            "connected gateway request rejected because no deployed gateway agent resolved"
        );
        return Err(build_request_error_response(
            StatusCode::FORBIDDEN,
            request_id,
            traceparent,
            "Connected gateway requests require a deployed agent linked to this gateway",
            "access_denied",
            "gateway_agent_required",
        ));
    };

    let bound_agent = match fetch_bound_gateway_agent(state).await {
        Ok(agent) => agent,
        Err(error) => {
            tracing::warn!(
                request_id = %request_id,
                gateway_id = ?state.gateway_id,
                error = %error,
                "connected gateway request rejected because agent linkage could not be verified"
            );
            return Err(build_request_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                traceparent,
                "Connected gateway agent linkage could not be verified",
                "service_unavailable",
                "gateway_agent_lookup_unavailable",
            ));
        }
    };

    let Some(bound) = bound_agent else {
        tracing::warn!(
            request_id = %request_id,
            gateway_id = ?state.gateway_id,
            "connected gateway request rejected because no agent is bound to this gateway"
        );
        return Err(build_request_error_response(
            StatusCode::FORBIDDEN,
            request_id,
            traceparent,
            "Connected gateway requests require a deployed agent bound to this gateway",
            "access_denied",
            "gateway_agent_required",
        ));
    };

    if bound.id == agent_id {
        return Ok(());
    }

    tracing::warn!(
        request_id = %request_id,
        gateway_id = ?state.gateway_id,
        agent_id = %agent_id,
        bound_agent_id = %bound.id,
        "connected gateway request rejected because the resolved agent is not the bound agent"
    );
    Err(build_request_error_response(
        StatusCode::FORBIDDEN,
        request_id,
        traceparent,
        "The resolved agent is not the agent bound to this gateway",
        "access_denied",
        "gateway_agent_not_linked",
    ))
}

pub(crate) async fn resolve_and_enforce_connected_endpoint_agent(
    state: &mut ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    request_id: &str,
    traceparent: &str,
) -> Result<(), Response<Body>> {
    if !state.connected_mode {
        return Ok(());
    }

    let request_agent_id = match normalize_request_agent_id(request_agent_id_header_value(headers))
    {
        Ok(agent_id) => agent_id,
        Err(message) => {
            return Err(build_request_error_response(
                StatusCode::BAD_REQUEST,
                request_id,
                traceparent,
                message,
                "invalid_request_error",
                "invalid_agent_id",
            ));
        }
    };

    if let Some(agent_id) = request_agent_id {
        state.current_agent_id = Some(agent_id);
    } else if state.current_agent_id.is_none() {
        state.current_agent_id = resolve_runtime_agent_id(state).await;
    }

    state.apply_agent_overrides();

    enforce_connected_deployed_agent_link(state, request_id, traceparent).await
}

pub(crate) fn effective_history_capture_mode(state: &ActiveGatewayStateView<'_>) -> Option<String> {
    if silent_engine(state).history_disabled() {
        return Some("disabled".to_string());
    }
    state
        .history_config
        .as_ref()
        .map(|config| config.mode.clone())
        .or_else(|| {
            state
                .request_finops
                .as_ref()
                .and_then(|context| context.history_capture_mode.clone())
        })
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct GatewayRecallEntryAttribution {
    pub(crate) title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) age: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) confidence_tier: Option<String>,
    pub(crate) item_id: String,
    pub(crate) item_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source_history_session_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GatewayRecallAttribution {
    pub(crate) summary: String,
    pub(crate) recalled_entries: Vec<GatewayRecallEntryAttribution>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct GatewayCaptureSuggestion {
    pub(crate) hint: String,
    pub(crate) mode: String,
    pub(crate) suggested_title: String,
    pub(crate) detected_topic: String,
    pub(crate) prompt_text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GatewayCaptureCandidate {
    pub(crate) suggested_title: String,
    pub(crate) detected_topic: String,
    pub(crate) response_text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedContextFabricResponsePolicy {
    pub(crate) enabled: bool,
    pub(crate) capture_mode: String,
    pub(crate) capture_exclude_patterns: Vec<String>,
}

pub(crate) fn resolved_context_fabric_response_policy(
    state: &ActiveGatewayStateView<'_>,
) -> ResolvedContextFabricResponsePolicy {
    let default_capture_mode = state
        .mcp_server_config
        .as_ref()
        .and_then(|config| config.default_capture_mode.as_deref())
        .unwrap_or("nudge")
        .to_string();
    let gateway_enabled = state
        .gateway_context_fabric
        .as_ref()
        .and_then(|config| config.enabled)
        .unwrap_or(true);
    let gateway_capture_mode = state
        .gateway_context_fabric
        .as_ref()
        .and_then(|config| config.capture_mode.clone())
        .unwrap_or_else(|| default_capture_mode.clone());

    let resolved_agent = state
        .current_agent_id
        .as_deref()
        .and_then(|agent_id| {
            state
                .agent_declarations
                .iter()
                .find(|candidate| candidate.id == agent_id)
        })
        .or_else(|| {
            state
                .agents_runtime
                .as_ref()
                .and_then(|runtime| runtime.default_agent_id.as_deref())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .and_then(|agent_id| {
                    state
                        .agent_declarations
                        .iter()
                        .find(|candidate| candidate.id == agent_id)
                })
        })
        .or_else(|| {
            if state.agent_declarations.len() == 1 {
                state.agent_declarations.first()
            } else {
                None
            }
        });

    if let Some(agent) = resolved_agent {
        let resolved = crate::gateway::declarative_config::agent_config_resolution::resolve_declared_agent_config(
            agent,
            state.gateway_context_fabric.as_ref(),
            state.mcp_server_config.as_ref(),
        );
        return ResolvedContextFabricResponsePolicy {
            enabled: resolved.context_fabric.enabled,
            capture_mode: resolved.context_fabric.capture_mode,
            capture_exclude_patterns: resolved.context_fabric.capture_exclude_patterns,
        };
    }

    ResolvedContextFabricResponsePolicy {
        enabled: gateway_enabled,
        capture_mode: gateway_capture_mode,
        capture_exclude_patterns: state
            .gateway_context_fabric
            .as_ref()
            .and_then(|config| config.capture_exclude_patterns.clone())
            .unwrap_or_default(),
    }
}

pub(crate) fn truncate_inline_text(value: &str, max_chars: usize) -> String {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.chars().count() <= max_chars {
        return normalized;
    }

    let end = normalized
        .char_indices()
        .nth(max_chars)
        .map(|(idx, _)| idx)
        .unwrap_or(normalized.len());
    format!("{}...", normalized[..end].trim_end())
}

pub(crate) fn recalled_context_entry_contents(block: &str) -> Vec<String> {
    block
        .split("\n\n")
        .skip(1)
        .filter_map(|segment| {
            segment
                .split_once("] ")
                .map(|(_, content)| content.trim())
                .filter(|content| !content.is_empty())
                .map(ToOwned::to_owned)
        })
        .collect()
}

pub(crate) fn build_recall_attribution(
    applied: &crate::gateway::agent_context::AppliedAgentContext,
) -> Option<GatewayRecallAttribution> {
    if applied.telemetry.selected_items.is_empty() {
        return None;
    }

    let contents = recalled_context_entry_contents(&applied.block);
    let recalled_entries = applied
        .telemetry
        .selected_items
        .iter()
        .enumerate()
        .map(|(index, item)| GatewayRecallEntryAttribution {
            title: contents
                .get(index)
                .map(|content| truncate_inline_text(content, 72))
                .filter(|title| !title.is_empty())
                .unwrap_or_else(|| item.item_id.clone()),
            author: None,
            age: None,
            branch: None,
            confidence_tier: None,
            item_id: item.item_id.clone(),
            item_type: item.item_type.clone(),
            source_history_session_id: item.source_history_session_id.clone(),
        })
        .collect::<Vec<_>>();

    if recalled_entries.is_empty() {
        return None;
    }

    let summary = if recalled_entries.len() == 1 {
        format!(
            "Team context applied: \"{}\"",
            truncate_inline_text(&recalled_entries[0].title, 72)
        )
    } else {
        format!(
            "Team context applied: \"{}\" (+{} more)",
            truncate_inline_text(&recalled_entries[0].title, 56),
            recalled_entries.len().saturating_sub(1)
        )
    };

    Some(GatewayRecallAttribution {
        summary: truncate_inline_text(&summary, 180),
        recalled_entries,
    })
}

pub(crate) fn extract_request_text_for_capture(request_json: &serde_json::Value) -> String {
    let messages = extract_messages_for_responses(Some(request_json));
    let user_messages = messages
        .iter()
        .filter(|message| message.role.eq_ignore_ascii_case("user"))
        .map(|message| message.content.as_str())
        .collect::<Vec<_>>();
    if !user_messages.is_empty() {
        return user_messages.join("\n");
    }

    messages
        .into_iter()
        .filter(|message| {
            !message.role.eq_ignore_ascii_case("system")
                && !message.role.eq_ignore_ascii_case("developer")
        })
        .map(|message| message.content)
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn detect_high_value_response_topic(
    request_text: &str,
    response_text: &str,
) -> Option<&'static str> {
    let response_len = response_text.chars().count();
    if response_len < 120 {
        return None;
    }

    let combined = format!(
        "{}\n{}",
        request_text.to_ascii_lowercase(),
        truncate_inline_text(response_text, 500).to_ascii_lowercase()
    );
    let looks_structured = response_text.contains('\n') && response_len >= 200;
    let has_code_fence = response_text.contains("```");

    let topics: [(&str, &[&str]); 5] = [
        (
            "schema",
            &[
                "schema",
                "table",
                "column",
                "migration",
                "index",
                "constraint",
                "create table",
            ],
        ),
        (
            "query",
            &[
                "sql", "query", "select ", "join ", "where ", "explain", "cte",
            ],
        ),
        (
            "architecture",
            &[
                "architecture",
                "design",
                "service",
                "component",
                "boundary",
                "workflow",
                "system",
            ],
        ),
        (
            "debug",
            &[
                "debug",
                "error",
                "stack trace",
                "traceback",
                "panic",
                "exception",
                "fix",
            ],
        ),
        (
            "explanation",
            &[
                "explain",
                "because",
                "walkthrough",
                "step-by-step",
                "how it works",
                "why",
            ],
        ),
    ];

    let mut best_topic = None;
    let mut best_score = 0usize;
    for (topic, keywords) in topics {
        let score = keywords
            .iter()
            .filter(|keyword| combined.contains(*keyword))
            .count();
        if score > best_score {
            best_score = score;
            best_topic = Some(topic);
        }
    }

    if best_score >= 2
        || (best_score >= 1 && (looks_structured || has_code_fence || response_len >= 320))
    {
        return best_topic;
    }

    if has_code_fence && response_len >= 180 {
        return Some("debug");
    }

    None
}

pub(crate) fn detect_capture_candidate(
    request_json: &serde_json::Value,
    response_json: &serde_json::Value,
) -> Option<GatewayCaptureCandidate> {
    let request_text = extract_request_text_for_capture(request_json);
    let response_text = extract_openai_chat_output(response_json)
        .or_else(|| extract_openai_responses_output(response_json))?;
    let topic = detect_high_value_response_topic(&request_text, &response_text)?;
    let suggested_title = if !request_text.trim().is_empty() {
        truncate_inline_text(&request_text, 72)
    } else {
        truncate_inline_text(&response_text, 72)
    };

    Some(GatewayCaptureCandidate {
        suggested_title: if suggested_title.is_empty() {
            format!("{topic} insight")
        } else {
            suggested_title
        },
        detected_topic: topic.to_string(),
        response_text,
    })
}

pub(crate) fn capture_matches_exclude_patterns(content: &str, patterns: &[String]) -> bool {
    let lower = content.to_ascii_lowercase();
    patterns
        .iter()
        .map(|pattern| pattern.trim())
        .filter(|pattern| !pattern.is_empty())
        .any(|pattern| {
            regex_lite::Regex::new(pattern)
                .map(|regex| regex.is_match(content))
                .unwrap_or_else(|_| lower.contains(&pattern.to_ascii_lowercase()))
        })
}

pub(crate) fn build_request_scoped_api_client(
    state: &ActiveGatewayStateView<'_>,
    raw_token: &str,
) -> Result<crate::api::AsyncApiClient, CliError> {
    let api_base_url = state
        .event_sink
        .as_ref()
        .map(|sink| sink.base_url())
        .ok_or_else(|| CliError::internal("gateway API base URL is not configured".to_string()))?;

    crate::api::AsyncApiClient::new(api_base_url, raw_token)
        .map(|client| client.with_region(mcp_resolved_region(state)))
}

pub(crate) async fn maybe_auto_capture_response(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    request_json: &serde_json::Value,
    response_json: &serde_json::Value,
    session_context: Option<&crate::gateway::session::GatewaySessionContext>,
    policy: &ResolvedContextFabricResponsePolicy,
    request_id: &str,
) {
    if !policy.enabled {
        return;
    }
    if matches!(
        policy.capture_mode.as_str(),
        "off" | "metadata_only" | "disabled"
    ) {
        tracing::debug!(
            request_id = %request_id,
            capture_mode = %policy.capture_mode,
            "skipping content capture: privacy-preserving capture mode"
        );
        return;
    }
    if policy.capture_mode != "auto" {
        return;
    }

    let Some(session_context) = session_context else {
        return;
    };
    let Some(raw_token) = extract_bearer_token(headers).filter(|token| is_api_token(token)) else {
        return;
    };
    let Some(candidate) = detect_capture_candidate(request_json, response_json) else {
        return;
    };
    if capture_matches_exclude_patterns(&candidate.response_text, &policy.capture_exclude_patterns)
    {
        tracing::debug!(
            request_id = %request_id,
            "skipping context auto-capture because content matched an exclude pattern"
        );
        return;
    }

    let client = match build_request_scoped_api_client(state, &raw_token) {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(
                request_id = %request_id,
                error = %error,
                "failed to build request-scoped API client for context auto-capture"
            );
            return;
        }
    };

    let git_context = session_context.git_context.as_ref();
    let body = serde_json::json!({
        "content": candidate.response_text,
        "session_id": session_context.session_id,
        "team_id": session_context.team_id,
        "repo": git_context.and_then(|context| context.repo.clone()),
        "branch": git_context.and_then(|context| context.branch.clone()),
        "commit": git_context.and_then(|context| context.commit.clone()),
        "tags": [
            "source:response_capture",
            format!("topic:{}", candidate.detected_topic),
        ],
        "source_kind": "response_capture",
        "source_ref": {
            "capture_surface": "gateway_response",
            "request_id": request_id,
            "detected_topic": candidate.detected_topic,
            "suggested_title": candidate.suggested_title,
        },
    });

    match client.post_json_value("/v1/context/share", &body).await {
        Ok(response) => {
            tracing::debug!(
                request_id = %request_id,
                status = response
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("created"),
                "gateway context auto-capture completed"
            );
        }
        Err(error) => {
            tracing::warn!(
                request_id = %request_id,
                error = %error,
                "gateway context auto-capture failed"
            );
        }
    }
}

pub(crate) fn build_capture_suggestion(
    request_json: &serde_json::Value,
    response_json: &serde_json::Value,
    policy: &ResolvedContextFabricResponsePolicy,
) -> Option<GatewayCaptureSuggestion> {
    if !policy.enabled {
        return None;
    }
    if matches!(
        policy.capture_mode.as_str(),
        "off" | "metadata_only" | "disabled"
    ) {
        return None;
    }
    if policy.capture_mode != "nudge" {
        return None;
    }

    let candidate = detect_capture_candidate(request_json, response_json)?;

    Some(GatewayCaptureSuggestion {
        hint: "save-for-team".to_string(),
        mode: "nudge".to_string(),
        suggested_title: candidate.suggested_title,
        detected_topic: candidate.detected_topic,
        prompt_text: "This looks useful for your team. Say 'save for team' to share it."
            .to_string(),
    })
}

pub(crate) fn upsert_response_header(
    headers: &mut Vec<(axum::http::HeaderName, HeaderValue)>,
    name: &'static str,
    value: &str,
) {
    if value.trim().is_empty() {
        return;
    }

    let header_name = axum::http::HeaderName::from_static(name);
    let Ok(header_value) = HeaderValue::from_str(value) else {
        return;
    };

    if let Some(existing) = headers
        .iter_mut()
        .find(|(existing_name, _)| *existing_name == header_name)
    {
        *existing = (header_name, header_value);
        return;
    }

    headers.push((header_name, header_value));
}

pub(crate) fn append_context_response_headers(
    headers: &mut Vec<(axum::http::HeaderName, HeaderValue)>,
    recall_attribution: Option<&GatewayRecallAttribution>,
    capture_suggestion: Option<&GatewayCaptureSuggestion>,
) {
    if let Some(recall_attribution) = recall_attribution {
        upsert_response_header(
            headers,
            "x-verdictan-context-applied",
            &recall_attribution.summary,
        );
    }
    if let Some(capture_suggestion) = capture_suggestion {
        upsert_response_header(
            headers,
            "x-verdictan-context-hint",
            &capture_suggestion.hint,
        );
    }
}
