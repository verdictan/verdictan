// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Family request-pipeline module.
//! Child of `gateway::server`; parent private items remain visible.
use super::super::*;
use super::*;

pub(crate) fn translate_prepared_streaming_response_format(
    resp: PreparedStreamingResponse,
    source_format: crate::gateway::format_translation::ProviderFormat,
    path: &str,
    request_id: &str,
) -> PreparedStreamingResponse {
    let route_format =
        crate::gateway::format_translation::route_native_format(path, &serde_json::Value::Null);
    if source_format == route_format {
        return resp;
    }

    let mut translator = crate::gateway::format_translation::RouteNativeSseTranslator::new(
        path,
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
                    for payload in crate::gateway::sse::drain_sse_data_frames(&mut buffer) {
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

    PreparedStreamingResponse {
        status,
        content_type: HeaderValue::from_static("text/event-stream"),
        body: Box::pin(ReceiverStream::new(rx)),
    }
}

pub(crate) fn translate_buffered_runtime_response(
    resp: crate::gateway::cache::BufferedUpstreamResponse,
    provider: &str,
    execution_target: Option<&crate::gateway::execution_runtime::ExecutionTarget>,
) -> crate::gateway::cache::BufferedUpstreamResponse {
    let Ok(body_val) = serde_json::from_slice::<serde_json::Value>(resp.body()) else {
        return resp;
    };
    let Ok(translated) =
        crate::gateway::runtimes::translate_runtime_response(provider, execution_target, &body_val)
    else {
        return resp;
    };
    let Ok(new_bytes) = serde_json::to_vec(&translated) else {
        return resp;
    };
    crate::gateway::cache::BufferedUpstreamResponse::new(
        resp.status(),
        resp.headers().clone(),
        Bytes::from(new_bytes),
        resp.is_cached(),
    )
}

pub(crate) fn resolve_cache_tier(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    task_class: crate::gateway::task_classification::TaskClass,
    context_variables: Option<&serde_json::Value>,
) -> CacheTier {
    if headers
        .get("x-verdictan-cache-scope")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "private" | "private_edge_cache" | "key" | "user"
            )
        })
        .unwrap_or(false)
    {
        return CacheTier::PrivateEdge;
    }

    if let Some(config) = state.workflow_cache.as_ref() {
        if !config.enabled {
            return CacheTier::PrivateEdge;
        }
        if config.physical_gateway_private_cache_only {
            return CacheTier::PrivateEdge;
        }
        match config.default_tier.as_str() {
            "private_edge_cache" => return CacheTier::PrivateEdge,
            "org_shared_cache" if !config.org_shared_enabled => return CacheTier::PrivateEdge,
            _ => {}
        }
    }

    if !state.connected_mode {
        return CacheTier::PrivateEdge;
    }

    let code_aware = context_variables.is_some()
        || git_scope_from_headers(headers).is_some()
        || headers.get("x-verdictan-repo-id").is_some()
        || headers.get("x-repo-id").is_some()
        || headers.get("x-verdictan-codebase-identity-id").is_some();
    let read_only = task_class == crate::gateway::task_classification::TaskClass::ReadOnly;
    let has_compatible_entitlements = state
        .request_finops
        .as_ref()
        .and_then(|finops| finops.entitlement_digest.as_deref())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);

    if read_only && has_compatible_entitlements && (code_aware || state.workflow_cache.is_none()) {
        CacheTier::OrgShared
    } else {
        CacheTier::PrivateEdge
    }
}

pub fn build_provider_cache_key(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    path: &str,
    body: &Bytes,
    context_variables: Option<&serde_json::Value>,
    task_class: crate::gateway::task_classification::TaskClass,
) -> Option<String> {
    if !state.provider_cache.is_enabled() {
        return None;
    }

    // Declarative cache controls can disable cache usage entirely or require an
    // explicit opt-in header per request.
    if let Some(sc) = &state.semantic_cache {
        if !sc.enabled {
            return None;
        }
        if !sc.default_on {
            let opted_in = headers
                .get("x-verdictan-cache")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("on"))
                .unwrap_or(false);
            if !opted_in {
                return None;
            }
        }
    }

    let provider = provider_name_from_upstream(state.upstream_base);
    let provider_scope = provider_scope_key(
        state.upstream_base,
        state
            .upstream_auth
            .as_ref()
            .map(|(_, value)| value.as_bytes()),
    );
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let request_body = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .map(|value| canonicalize_json_value(&value))
        .unwrap_or_else(|| serde_json::json!({ "sha256": sha256_prefixed(body) }));

    let cache_tier = resolve_cache_tier(state, headers, task_class, context_variables);
    let resolved_agent_id = state.current_agent_id.clone().or_else(|| {
        state
            .request_finops
            .as_ref()
            .and_then(|finops| finops.agent_id.clone())
    });
    let resolved_agent_gateway_group_id = state
        .request_finops
        .as_ref()
        .and_then(|finops| finops.agent_gateway_group_id.as_deref())
        .map(ToOwned::to_owned)
        .or_else(|| {
            state
                .workflow_cache
                .as_ref()
                .and_then(|config| config.agent_gateway_group_id.clone())
        });

    // Connected-mode org-shared cache keys isolate by org, team, entitlements,
    // and config identity while intentionally omitting key_id so compatible
    // API tokens can share entries. Private cache keys retain key_id/user
    // isolation.
    let tenant_scope = if state.connected_mode {
        Some(state.request_finops.as_ref().map_or_else(
            || serde_json::json!({ "_scope": "control_plane_unscoped" }),
            |finops| match cache_tier {
                CacheTier::OrgShared => {
                    serde_json::json!({
                        "org_id": finops.org_id,
                        "team_id": finops.team_id,
                        "agent_id": resolved_agent_id,
                        "agent_gateway_group_id": resolved_agent_gateway_group_id,
                        "requested_region_group": state.requested_region_group,
                        "public_endpoint_host": state.managed_public_endpoint_host,
                        "entitlement_digest": finops.entitlement_digest,
                                                "org_authz_version": finops.org_authz_version,
                    })
                }
                CacheTier::PrivateEdge => {
                    serde_json::json!({
                        "org_id": finops.org_id,
                        "team_id": finops.team_id,
                        "user_id": finops.user_id,
                        "key_id": finops.key_id,
                        "agent_id": resolved_agent_id,
                        "agent_gateway_group_id": resolved_agent_gateway_group_id,
                        "gateway_id": state.gateway_id,
                        "requested_region_group": state.requested_region_group,
                        "public_endpoint_host": state.managed_public_endpoint_host,
                        "entitlement_digest": finops.entitlement_digest,
                                                "org_authz_version": finops.org_authz_version,
                    })
                }
            },
        ))
    } else {
        None
    };
    let config_identity = if state.connected_mode {
        Some(serde_json::json!({
            "configuration_version_id": state.configuration_version_id,
            "config_sha256": state.config_sha256,
        }))
    } else {
        None
    };
    let git_scope = git_scope_from_headers(headers);

    let request_family = path
        .trim_start_matches("/v1/")
        .split('/')
        .next()
        .unwrap_or(path);
    let explicit_model = request_body
        .get("model")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);

    let key_material = serde_json::json!({
        "provider": provider,
        "provider_scope": provider_scope,
        "upstream_base": state.upstream_base,
        "path": path,
        "request_family": request_family,
        "model": explicit_model,
        "policy_sha256": &state.config_sha256,
        "content_type": content_type,
        "request": request_body,
        "context_variables": context_variables.map(canonicalize_json_value),
        "cache_buster": state.provider_cache.cache_buster(),
        "cache_tier": cache_tier.as_str(),
        "session_id": state.session_id,
        "runtime_cache_ttl_seconds": effective_cache_ttl_override(state).map(|ttl| ttl.as_secs()),
        "tenant": tenant_scope,
        "config_identity": config_identity,
        "git_scope": git_scope,
    });

    serde_json::to_vec(&canonicalize_json_value(&key_material))
        .ok()
        .map(|serialized| sha256_prefixed(&serialized))
}

pub(crate) fn git_scope_from_headers(headers: &HeaderMap) -> Option<serde_json::Value> {
    let git_context = git_context_from_headers(headers)?;

    Some(serde_json::json!({
        "git_repo": git_context.repo,
        "git_branch": git_context.branch,
        "git_commit": git_context.commit,
    }))
}

pub(crate) fn git_context_from_headers(
    headers: &HeaderMap,
) -> Option<crate::gateway::session::GatewayGitContext> {
    crate::gateway::session::GatewayGitContext::new(
        header_string(headers, "x-verdictan-git-repo")
            .or_else(|| header_string(headers, "x-git-repo"))
            .as_deref(),
        header_string(headers, "x-verdictan-git-branch")
            .or_else(|| header_string(headers, "x-git-branch"))
            .as_deref(),
        header_string(headers, "x-verdictan-git-commit")
            .or_else(|| header_string(headers, "x-git-commit"))
            .as_deref(),
    )
}

pub(crate) fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

/// Check the per-token RPM limit, if any is configured on the finops context.
///
/// Returns `None` when the request is allowed. Returns `Some(response)` with
/// HTTP 429 and standard rate-limit headers when the per-key ceiling is
/// exceeded. The check is a no-op when the finops context carries no
/// `rate_limit_rpm` or no `key_id`.
pub fn enforce_token_rate_limit(
    state: &ActiveGatewayStateView<'_>,
    finops: &RequestFinopsContext,
    request_id: &str,
    traceparent: &str,
) -> Option<Response<Body>> {
    let (key_id, limit_rpm) = match (finops.key_id.as_deref(), finops.rate_limit_rpm) {
        (Some(kid), Some(rpm)) => (kid, rpm),
        _ => return None,
    };

    if let Err(err) = state
        .key_rate_limiter
        .check_and_increment(key_id, limit_rpm)
    {
        tracing::warn!(
            request_id = %request_id,
            key_id = %key_id,
            limit_rpm = %limit_rpm,
            "API token rate limit exceeded"
        );
        let body = serde_json::json!({
            "error": error_json(
                "Rate limit exceeded for this API token",
                "rate_limit_exceeded",
                "token_rate_limit_exceeded",
            )
        });
        let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        let mut builder = Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header(header::CONTENT_TYPE, "application/json")
            .header("X-Request-Id", request_id)
            .header("traceparent", traceparent);
        for (name, value) in ratelimit_headers(err.limit, 0, err.retry_after_seconds, None, None) {
            builder = builder.header(name, value);
        }
        return Some(builder.body(Body::from(text)).unwrap_or_default());
    }

    None
}

pub(crate) fn enforce_request_network_controls(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    peer_ip: IpAddr,
    request_id: &str,
    traceparent: &str,
) -> Option<Response<Body>> {
    if let Some(cidrs) = state
        .request_finops
        .as_ref()
        .and_then(|finops| finops.ip_restrictions.as_ref())
        .filter(|values| !values.is_empty())
    {
        let nets: Vec<ipnet::IpNet> = cidrs
            .iter()
            .filter_map(|cidr| {
                cidr.parse::<ipnet::IpNet>()
                    .or_else(|_| cidr.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                    .ok()
            })
            .collect();
        if !nets.is_empty() {
            let client_ip = crate::gateway::rate_limit::extract_client_ip(
                headers,
                state.ip_allowlist_trusted_proxies.as_ref(),
                peer_ip,
            );
            if !crate::gateway::network::ip_is_allowlisted(client_ip, &nets) {
                let body = serde_json::json!({
                    "error": error_json(
                        "Source IP is not in the allowed list for this API token",
                        "access_denied",
                        "ip_restrictions_denied",
                    )
                });
                let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
                return Some(
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header(header::CONTENT_TYPE, "application/json")
                        .header("X-Request-Id", request_id)
                        .header("traceparent", traceparent)
                        .body(Body::from(text))
                        .unwrap_or_default(),
                );
            }
        }
    }

    if let Some(allowlist) = state.ip_allowlist.as_ref() {
        let client_ip = crate::gateway::rate_limit::extract_client_ip(
            headers,
            state.ip_allowlist_trusted_proxies.as_ref(),
            peer_ip,
        );
        if !crate::gateway::network::ip_is_allowlisted(client_ip, allowlist) {
            let body = serde_json::json!({
                "error": error_json(
                    "Source IP is not allowed",
                    "access_denied",
                    "ip_allowlist_denied",
                )
            });
            let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
            return Some(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("X-Request-Id", request_id)
                    .header("traceparent", traceparent)
                    .body(Body::from(text))
                    .unwrap_or_default(),
            );
        }
    }

    if let Some(grl) = state.global_rate_limiter.as_ref() {
        if let Err(err) = grl.check_and_increment() {
            let body = serde_json::json!({
                "error": error_json(
                    "Global rate limit exceeded",
                    "rate_limit_exceeded",
                    "global_rate_limit_exceeded",
                )
            });
            let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
            let mut builder = Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Request-Id", request_id)
                .header("traceparent", traceparent);
            for (name, value) in
                ratelimit_headers(err.limit, 0, err.retry_after_seconds, None, None)
            {
                builder = builder.header(name, value);
            }
            return Some(builder.body(Body::from(text)).unwrap_or_default());
        }
    }

    if let Some(iprl) = state.ip_rate_limiter.as_ref() {
        let client_ip =
            crate::gateway::rate_limit::extract_client_ip(headers, iprl.trusted_proxies(), peer_ip);
        if let Err(err) = iprl.check_and_increment(client_ip) {
            let body = serde_json::json!({
                "error": error_json(
                    "Rate limit exceeded for client IP",
                    "rate_limit_exceeded",
                    "ip_rate_limit_exceeded",
                )
            });
            let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
            let mut builder = Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Request-Id", request_id)
                .header("traceparent", traceparent);
            for (name, value) in
                ratelimit_headers(err.limit, 0, err.retry_after_seconds, None, None)
            {
                builder = builder.header(name, value);
            }
            return Some(builder.body(Body::from(text)).unwrap_or_default());
        }
    }

    if let Some(url) = state.user_rate_limiter.as_ref() {
        if let Some(user_id) =
            crate::gateway::network::extract_user_id(headers, &url.config().header_names)
        {
            if let Err(err) = url.check_and_increment(&user_id) {
                let body = serde_json::json!({
                    "error": error_json(
                        "Rate limit exceeded for user",
                        "rate_limit_exceeded",
                        "user_rate_limit_exceeded",
                    )
                });
                let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
                let mut builder = Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("X-Request-Id", request_id)
                    .header("traceparent", traceparent);
                for (name, value) in
                    ratelimit_headers(err.limit, 0, err.retry_after_seconds, None, None)
                {
                    builder = builder.header(name, value);
                }
                return Some(builder.body(Body::from(text)).unwrap_or_default());
            }
        }
    }

    None
}

pub(crate) fn enforce_distributed_request_rate_limit(
    state: &ActiveGatewayStateView<'_>,
    request_id: &str,
    traceparent: &str,
) -> Option<Response<Body>> {
    if let (Some(ds), Some((limit, window_secs))) =
        (state.distributed_state, state.distributed_rl_params)
    {
        let tenant_scope = distributed_tenant_scope(state);
        match crate::gateway::distributed_rate_limit::check_rate_limit(
            ds,
            &tenant_scope,
            limit,
            window_secs,
        ) {
            Ok(result) if !result.allowed => {
                tracing::warn!(
                    request_id = %request_id,
                    tenant_scope = %tenant_scope,
                    limit = %limit,
                    "distributed rate limit exceeded"
                );
                let body = serde_json::json!({
                    "error": error_json(
                        "Distributed rate limit exceeded",
                        "rate_limit_exceeded",
                        "distributed_rate_limit_exceeded",
                    )
                });
                let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
                let mut builder = Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("X-Request-Id", request_id)
                    .header("traceparent", traceparent);
                for (name, value) in ratelimit_headers(
                    limit,
                    result.remaining,
                    result.reset_at.saturating_sub(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    ),
                    None,
                    None,
                ) {
                    builder = builder.header(name, value);
                }
                return Some(builder.body(Body::from(text)).unwrap_or_default());
            }
            Ok(_) => {}
            Err(e) => {
                if state.connected_mode && state.rollout_grade_required {
                    tracing::error!(
                        request_id = %request_id,
                        tenant_scope = %tenant_scope,
                        error = %e,
                        "distributed rate limit check failed for rollout-grade connected traffic"
                    );
                    let body = serde_json::json!({
                        "error": error_json(
                            "Distributed rate limiting is temporarily unavailable",
                            "service_unavailable",
                            "distributed_rate_limit_unavailable",
                        )
                    });
                    let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
                    return Some(
                        Response::builder()
                            .status(StatusCode::SERVICE_UNAVAILABLE)
                            .header(header::CONTENT_TYPE, "application/json")
                            .header("X-Request-Id", request_id)
                            .header("traceparent", traceparent)
                            .body(Body::from(text))
                            .unwrap_or_default(),
                    );
                }
                tracing::warn!(
                    request_id = %request_id,
                    tenant_scope = %tenant_scope,
                    error = %e,
                    "distributed rate limit check failed, allowing request (fail-open)"
                );
            }
        }
    }

    None
}

pub(crate) fn build_semantic_cache_embedding(
    state: &ActiveGatewayStateView<'_>,
    body: &Bytes,
) -> Option<Vec<f64>> {
    let config = state.semantic_cache.as_ref()?;
    if !config.enabled {
        return None;
    }
    if config.mode != crate::gateway::cache::CacheMode::Semantic {
        return None;
    }

    let provider_id = config.embedding_provider.as_deref()?;
    let registry = state.provider_registry.as_ref()?;
    let body_json = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let text = semantic_cache_text_from_body(&body_json)?;
    crate::policy::embeddings::embed_text_with_provider(provider_id, &text, registry).ok()
}

pub(crate) fn semantic_cache_text_from_body(value: &serde_json::Value) -> Option<String> {
    if let Some(messages) = value.get("messages").and_then(|item| item.as_array()) {
        let text = messages
            .iter()
            .filter_map(|message| message.get("content").and_then(|item| item.as_str()))
            .collect::<Vec<_>>()
            .join("\n");
        if !text.trim().is_empty() {
            return Some(text);
        }
    }

    if let Some(input) = value.get("input") {
        if let Some(text) = input.as_str() {
            if !text.trim().is_empty() {
                return Some(text.to_string());
            }
        }
        if let Some(items) = input.as_array() {
            let text = items
                .iter()
                .filter_map(|item| item.get("content").and_then(|content| content.as_str()))
                .collect::<Vec<_>>()
                .join("\n");
            if !text.trim().is_empty() {
                return Some(text);
            }
        }
    }

    value
        .get("prompt")
        .and_then(|item| item.as_str())
        .map(ToString::to_string)
}

pub(crate) fn apply_semantic_routing(
    request_body: &serde_json::Value,
    registry: &crate::gateway::providers::ProviderRegistry,
    state: &ActiveGatewayStateView<'_>,
    ordered: &[usize],
) -> Vec<usize> {
    if registry.routing.strategy != crate::gateway::providers::RoutingStrategy::Semantic {
        return ordered.to_vec();
    }

    let provider_id = registry
        .routing
        .semantic_embedding_provider
        .as_deref()
        .or_else(|| {
            state
                .semantic_cache
                .as_ref()
                .and_then(|config| config.embedding_provider.as_deref())
        });
    let Some(provider_id) = provider_id else {
        return ordered.to_vec();
    };

    let Some(query_text) = semantic_cache_text_from_body(request_body) else {
        return ordered.to_vec();
    };

    let mut described_indices = Vec::new();
    let mut texts = vec![query_text.as_str()];
    for &idx in ordered {
        if let Some(description) = registry.targets[idx].description.as_deref() {
            described_indices.push(idx);
            texts.push(description);
        }
    }

    if described_indices.is_empty() {
        return ordered.to_vec();
    }

    let threshold = registry.routing.semantic_similarity_threshold;
    let embed_result =
        crate::policy::embeddings::embed_texts_with_provider(provider_id, &texts, registry);

    let mut scored = match embed_result {
        Ok(embeddings) if embeddings.len() == texts.len() => {
            let query_embedding = &embeddings[0];
            described_indices
                .iter()
                .enumerate()
                .map(|(position, idx)| {
                    (
                        *idx,
                        crate::gateway::cache::cosine_similarity(
                            query_embedding,
                            &embeddings[position + 1],
                        ),
                    )
                })
                .filter(|(_, score)| *score >= threshold)
                .collect::<Vec<_>>()
        }
        Ok(_) | Err(_) => {
            tracing::warn!(
                provider_id = provider_id,
                "semantic routing: configured provider failed or returned mismatched embeddings; failing closed to original order"
            );
            return ordered.to_vec();
        }
    };

    if scored.is_empty() {
        return ordered.to_vec();
    }

    scored.sort_by(|left, right| {
        right
            .1
            .partial_cmp(&left.1)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut reordered = scored.iter().map(|(idx, _)| *idx).collect::<Vec<_>>();
    for &idx in ordered {
        if !reordered.contains(&idx) {
            reordered.push(idx);
        }
    }

    reordered
}

pub(crate) fn local_semantic_similarity(left: &str, right: &str) -> f64 {
    let left_tokens = tokenize_semantic_text(left);
    let right_tokens = tokenize_semantic_text(right);
    if left_tokens.is_empty() || right_tokens.is_empty() {
        return 0.0;
    }

    let overlap = left_tokens
        .iter()
        .filter(|token| right_tokens.contains(*token))
        .count() as f64;
    overlap / ((left_tokens.len() as f64).sqrt() * (right_tokens.len() as f64).sqrt())
}

pub(crate) fn tokenize_semantic_text(input: &str) -> std::collections::BTreeSet<String> {
    input
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

pub(crate) fn extract_provider_cache_context(
    value: &serde_json::Value,
) -> Option<serde_json::Value> {
    let mut context = serde_json::Map::new();

    for (label, candidate) in [
        (
            "verdictan.context_variables",
            value.pointer("/verdictan/context_variables"),
        ),
        ("verdictan.variables", value.pointer("/verdictan/variables")),
        (
            "verdictan.context_variables",
            value.pointer("/verdictan/context_variables"),
        ),
        ("verdictan.variables", value.pointer("/verdictan/variables")),
        ("variables", value.get("variables")),
    ] {
        if let Some(found) = candidate {
            context.insert(label.to_string(), canonicalize_json_value(found));
        }
    }

    if let Some(fabric_scope) = extract_provider_cache_context_fabric_scope(value) {
        context.insert("context_fabric".to_string(), fabric_scope);
    }

    if context.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(context))
    }
}

pub(crate) fn extract_provider_cache_context_fabric_scope(
    value: &serde_json::Value,
) -> Option<serde_json::Value> {
    let fabric = value
        .pointer("/verdictan/context_fabric")
        .or_else(|| value.get("context_fabric"))?;
    let mut scope = serde_json::Map::new();

    for key in [
        "selected_artifact_ids",
        "source_digests",
        "repo_id",
        "codebase_identity_id",
        "artifact_type",
        "git_repo",
        "git_branch",
        "git_commit",
    ] {
        if let Some(found) = fabric.get(key) {
            scope.insert(key.to_string(), canonicalize_json_value(found));
        }
    }

    (!scope.is_empty()).then_some(serde_json::Value::Object(scope))
}

pub(crate) fn canonicalize_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let ordered: BTreeMap<String, serde_json::Value> = map
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize_json_value(value)))
                .collect();
            let mut normalized = serde_json::Map::new();
            for (key, value) in ordered {
                normalized.insert(key, value);
            }
            serde_json::Value::Object(normalized)
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                .map(canonicalize_json_value)
                .collect::<Vec<_>>(),
        ),
        _ => value.clone(),
    }
}

pub(crate) fn provider_name_from_upstream(upstream_base: &str) -> String {
    let trimmed = upstream_base
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    trimmed.split('/').next().unwrap_or(trimmed).to_string()
}

pub(crate) fn provider_scope_key(upstream_base: &str, auth_value: Option<&[u8]>) -> String {
    use sha2::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(upstream_base.as_bytes());
    if let Some(value) = auth_value {
        hasher.update(value);
    }
    let digest = hex::encode(hasher.finalize());
    format!("scope:{}", &digest[..16])
}

/// Injects informational rate-limit headers into a successful (2xx) response.
pub(crate) fn inject_ratelimit_info(
    mut resp: Response<Body>,
    info: &[(&str, String)],
) -> Response<Body> {
    if !resp.status().is_success() || info.is_empty() {
        return resp;
    }
    let hdrs = resp.headers_mut();
    for (name, value) in info {
        if let (Ok(hn), Ok(hv)) = (
            axum::http::HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            hdrs.insert(hn, hv);
        }
    }
    resp
}

pub(crate) fn build_response(
    status: StatusCode,
    content_type: HeaderValue,
    request_id: String,
    traceparent: String,
    body: Bytes,
    degraded: bool,
    extra_headers: Option<Vec<(axum::http::HeaderName, HeaderValue)>>,
) -> Response<Body> {
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;

    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, content_type);
    headers.insert(
        header::HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&request_id).unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );

    headers.insert(
        header::HeaderName::from_static("traceparent"),
        HeaderValue::from_str(&traceparent).unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );

    if degraded {
        headers.insert(
            header::HeaderName::from_static("x-verdictan-degraded"),
            HeaderValue::from_static("true"),
        );
    }

    if let Some(extra) = extra_headers {
        for (k, v) in extra {
            headers.insert(k, v);
        }
    }
    maybe_insert_server_timing_header(headers);

    resp
}

pub(crate) fn build_streaming_response(
    status: StatusCode,
    content_type: HeaderValue,
    request_id: String,
    traceparent: String,
    stream: ReceiverStream<Result<Bytes, io::Error>>,
    degraded: bool,
    extra_headers: Option<Vec<(axum::http::HeaderName, HeaderValue)>>,
) -> Response<Body> {
    let mut resp = Response::new(Body::from_stream(stream));
    *resp.status_mut() = status;

    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, content_type);
    headers.insert(
        header::HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&request_id).unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );
    headers.insert(
        header::HeaderName::from_static("traceparent"),
        HeaderValue::from_str(&traceparent).unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );

    if degraded {
        headers.insert(
            header::HeaderName::from_static("x-verdictan-degraded"),
            HeaderValue::from_static("true"),
        );
    }

    if let Some(extra) = extra_headers {
        for (name, value) in extra {
            headers.insert(name, value);
        }
    }
    maybe_insert_server_timing_header(headers);

    resp
}

pub fn join_upstream(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{base}/{path}")
}

pub fn rewrite_upstream_path(upstream_base: &str, path: &str) -> String {
    if !is_github_models_upstream(upstream_base) {
        return path.to_string();
    }

    match path {
        "/v1/chat/completions" => "/inference/chat/completions".to_string(),
        "/v1/responses" => "/inference/responses".to_string(),
        "/v1/embeddings" => "/inference/embeddings".to_string(),
        _ => path.to_string(),
    }
}

pub(crate) fn is_github_models_upstream(upstream_base: &str) -> bool {
    GITHUB_MODELS_HOSTS
        .iter()
        .any(|host| upstream_base.contains(host))
}

pub(crate) fn github_models_api_version_header() -> String {
    std::env::var("VERDICTAN_GITHUB_MODELS_API_VERSION")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| GITHUB_MODELS_DEFAULT_API_VERSION.to_string())
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /v1/models — list available models
// ═══════════════════════════════════════════════════════════════════════════

pub(crate) async fn list_models(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Result<Response<Body>, StatusCode> {
    let x_request_id_in = headers.get("X-Request-Id").and_then(|v| v.to_str().ok());
    let request_id = match request_id::validate_or_generate_x_request_id(x_request_id_in) {
        Ok(id) => id,
        Err(err) => return Ok(reject_invalid_x_request_id(&headers, &err)),
    };
    let traceparent_in = headers.get("traceparent").and_then(|v| v.to_str().ok());
    let traceparent = request_id::normalize_or_generate_traceparent(traceparent_in);

    let state_view =
        match build_public_request_state(&state, &headers, peer_addr, &request_id, &traceparent)
            .await
        {
            Ok(state_view) => state_view,
            Err(response) => return Ok(response),
        };

    execute_list_models_with_state(state_view, request_id, traceparent).await
}

pub(crate) async fn execute_list_models_with_state(
    state_view: ActiveGatewayStateView<'_>,
    request_id: String,
    traceparent: String,
) -> Result<Response<Body>, StatusCode> {
    if state_view.models_endpoint.disabled {
        let body = serde_json::json!({
            "error": error_json("Models endpoint is disabled", "invalid_request_error", "models_disabled")
        });
        let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        return Ok(build_response(
            StatusCode::NOT_FOUND,
            HeaderValue::from_static("application/json"),
            request_id.clone(),
            traceparent.clone(),
            Bytes::from(text),
            false,
            None,
        ));
    }

    let body = crate::gateway::models_endpoint::build_models_response(
        state_view.provider_registry.as_ref(),
        &state_view.auto_provider,
        &state_view.models_endpoint,
    );
    let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Ok(build_response(
        StatusCode::OK,
        HeaderValue::from_static("application/json"),
        request_id.clone(),
        traceparent.clone(),
        Bytes::from(text),
        false,
        None,
    ))
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /v1/models/:model_id — retrieve a single model
// ═══════════════════════════════════════════════════════════════════════════

pub(crate) async fn get_model(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    axum::extract::Path(model_id): axum::extract::Path<String>,
) -> Result<Response<Body>, StatusCode> {
    let x_request_id_in = headers.get("X-Request-Id").and_then(|v| v.to_str().ok());
    let request_id = match request_id::validate_or_generate_x_request_id(x_request_id_in) {
        Ok(id) => id,
        Err(err) => return Ok(reject_invalid_x_request_id(&headers, &err)),
    };
    let traceparent_in = headers.get("traceparent").and_then(|v| v.to_str().ok());
    let traceparent = request_id::normalize_or_generate_traceparent(traceparent_in);

    let state_view =
        match build_public_request_state(&state, &headers, peer_addr, &request_id, &traceparent)
            .await
        {
            Ok(state_view) => state_view,
            Err(response) => return Ok(response),
        };

    if state_view.models_endpoint.disabled {
        let body = serde_json::json!({
            "error": error_json("Models endpoint is disabled", "invalid_request_error", "models_disabled")
        });
        let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        return Ok(build_response(
            StatusCode::NOT_FOUND,
            HeaderValue::from_static("application/json"),
            request_id.clone(),
            traceparent.clone(),
            Bytes::from(text),
            false,
            None,
        ));
    }

    let all = crate::gateway::models_endpoint::build_models_response(
        state_view.provider_registry.as_ref(),
        &state_view.auto_provider,
        &state_view.models_endpoint,
    );

    let found = all.get("data").and_then(|d| d.as_array()).and_then(|arr| {
        arr.iter()
            .find(|m| m.get("id").and_then(|v| v.as_str()) == Some(&model_id))
    });

    match found {
        Some(model) => {
            let text = serde_json::to_vec(model).unwrap_or_else(|_| b"{}".to_vec());
            Ok(build_response(
                StatusCode::OK,
                HeaderValue::from_static("application/json"),
                request_id.clone(),
                traceparent.clone(),
                Bytes::from(text),
                false,
                None,
            ))
        }
        None => {
            let body = serde_json::json!({
                "error": error_json(
                    &format!("The model '{}' does not exist", model_id),
                    "invalid_request_error",
                    "model_not_found",
                )
            });
            let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
            Ok(build_response(
                StatusCode::NOT_FOUND,
                HeaderValue::from_static("application/json"),
                request_id,
                traceparent,
                Bytes::from(text),
                false,
                None,
            ))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// POST /v1/embeddings — proxy to upstream embeddings endpoint
// ═══════════════════════════════════════════════════════════════════════════

pub(crate) async fn embeddings(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
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

    let mut state =
        match build_public_request_state(&state, &headers, peer_addr, &request_id, &traceparent)
            .await
        {
            Ok(state) => state,
            Err(response) => return Ok(response),
        };
    if let Err(response) = resolve_and_enforce_connected_endpoint_agent(
        &mut state,
        &headers,
        &request_id,
        &traceparent,
    )
    .await
    {
        return Ok(response);
    }

    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let request_body = match parse_runtime_json_body(&body_bytes) {
        Ok(body) => body,
        Err(error) => {
            return Ok(build_runtime_preflight_response(
                &request_id,
                &traceparent,
                &error,
            ))
        }
    };
    let prompt_hash = sha256_prefixed(&body_bytes);

    let correlation = TraceCorrelation::default();
    let telemetry_hints = RequestTelemetryHints::default();
    let connected_access_status = match connected_access_status_for_request(
        &mut state,
        &request_body,
        &request_id,
        0,
    )
    .await
    {
        Ok(status) => status,
        Err(response) => return Ok(response),
    };
    let access_dispatch_ctx = match maybe_prepare_connected_access_dispatch(
        &mut state,
        &headers,
        &request_body,
        &request_id,
        &traceparent,
        &prompt_hash,
        0,
        connected_access_status.admission_credential_source,
        connected_access_status.dispatch_precluded,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return Ok(response),
    };

    let (upstream_resp, served_provider_id) = send_with_provider_fallback(
        &state,
        &headers,
        "/v1/embeddings",
        body_bytes.clone(),
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
            let latency_ms = start.elapsed().as_millis() as i64;
            finalize_connected_access_after_buffered_response(
                &state,
                &request_body,
                &body_bytes,
                &response,
                &access_dispatch_ctx,
                &request_id,
                &traceparent,
                served_provider_id.as_deref(),
                Some(latency_ms),
            );
            tracing::info!(
                request_id = %request_id,
                latency_ms,
                upstream_status = %response.status(),
                "embeddings proxied"
            );
            Ok(buffered_response_to_http_response(
                response,
                &request_id,
                &traceparent,
            ))
        }
        Err(e) => {
            tracing::error!(error = %e, "embeddings upstream error");
            let body = serde_json::json!({
                "error": error_json(
                    "Upstream embeddings service unavailable",
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

// ═══════════════════════════════════════════════════════════════════════════
// POST /v1/audio/transcriptions — proxy to upstream transcription endpoint
// ═══════════════════════════════════════════════════════════════════════════

pub(crate) async fn audio_transcriptions(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
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

    let mut state =
        match build_public_request_state(&state, &headers, peer_addr, &request_id, &traceparent)
            .await
        {
            Ok(state) => state,
            Err(response) => return Ok(response),
        };
    if let Err(response) = resolve_and_enforce_connected_endpoint_agent(
        &mut state,
        &headers,
        &request_id,
        &traceparent,
    )
    .await
    {
        return Ok(response);
    }

    let body_limit = AUDIO_TRANSCRIPTION_ENCODED_MAX_BYTES + AUDIO_REQUEST_JSON_OVERHEAD_BYTES;
    let body_bytes = match axum::body::to_bytes(request.into_body(), body_limit).await {
        Ok(b) => b,
        Err(_) => {
            return Ok(build_runtime_json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &request_id,
                &traceparent,
                "runtime.audio.encoded_size_exceeded",
                "Base64 audio input exceeds the runtime contract size limit.",
                serde_json::json!({
                    "field": "input_audio.data",
                    "max_bytes": AUDIO_TRANSCRIPTION_ENCODED_MAX_BYTES,
                }),
            ))
        }
    };

    let request_body = match parse_runtime_json_body(&body_bytes) {
        Ok(body) => body,
        Err(error) => {
            return Ok(build_runtime_preflight_response(
                &request_id,
                &traceparent,
                &error,
            ))
        }
    };
    if let Err(error) = validate_audio_transcription_request(&request_body) {
        return Ok(build_runtime_preflight_response(
            &request_id,
            &traceparent,
            &error,
        ));
    }
    let prompt_hash = sha256_prefixed(&body_bytes);

    let correlation = TraceCorrelation::default();
    let telemetry_hints = RequestTelemetryHints::default();
    let connected_access_status = match connected_access_status_for_request(
        &mut state,
        &request_body,
        &request_id,
        0,
    )
    .await
    {
        Ok(status) => status,
        Err(response) => return Ok(response),
    };
    let access_dispatch_ctx = match maybe_prepare_connected_access_dispatch(
        &mut state,
        &headers,
        &request_body,
        &request_id,
        &traceparent,
        &prompt_hash,
        0,
        connected_access_status.admission_credential_source,
        connected_access_status.dispatch_precluded,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return Ok(response),
    };

    let (upstream_resp, served_provider_id) = send_with_provider_fallback(
        &state,
        &headers,
        "/v1/audio/transcriptions",
        body_bytes.clone(),
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
            let latency_ms = start.elapsed().as_millis() as i64;
            finalize_connected_access_after_buffered_response(
                &state,
                &request_body,
                &body_bytes,
                &response,
                &access_dispatch_ctx,
                &request_id,
                &traceparent,
                served_provider_id.as_deref(),
                Some(latency_ms),
            );
            tracing::info!(
                request_id = %request_id,
                latency_ms,
                upstream_status = %response.status(),
                "audio transcription proxied"
            );
            Ok(buffered_response_to_http_response(
                response,
                &request_id,
                &traceparent,
            ))
        }
        Err(error) => {
            tracing::error!(request_id = %request_id, error = %error, "audio transcription upstream error");
            Ok(build_runtime_json_response(
                StatusCode::BAD_GATEWAY,
                &request_id,
                &traceparent,
                "upstream_error",
                "Upstream audio transcription service unavailable.",
                serde_json::json!({}),
            ))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// POST /v1/audio/speech — proxy to upstream speech endpoint
// ═══════════════════════════════════════════════════════════════════════════

pub(crate) async fn audio_speech(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
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

    let mut state =
        match build_public_request_state(&state, &headers, peer_addr, &request_id, &traceparent)
            .await
        {
            Ok(state) => state,
            Err(response) => return Ok(response),
        };
    if let Err(response) = resolve_and_enforce_connected_endpoint_agent(
        &mut state,
        &headers,
        &request_id,
        &traceparent,
    )
    .await
    {
        return Ok(response);
    }

    let body_limit = AUDIO_SPEECH_INPUT_MAX_BYTES + AUDIO_REQUEST_JSON_OVERHEAD_BYTES;
    let body_bytes = match axum::body::to_bytes(request.into_body(), body_limit).await {
        Ok(b) => b,
        Err(_) => {
            return Ok(build_runtime_json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &request_id,
                &traceparent,
                "runtime.audio.speech_input_too_large",
                "Speech input exceeds the runtime contract size limit.",
                serde_json::json!({
                    "field": "input",
                    "max_bytes": AUDIO_SPEECH_INPUT_MAX_BYTES,
                }),
            ))
        }
    };

    let request_body = match parse_runtime_json_body(&body_bytes) {
        Ok(body) => body,
        Err(error) => {
            return Ok(build_runtime_preflight_response(
                &request_id,
                &traceparent,
                &error,
            ))
        }
    };
    if let Err(error) = validate_audio_speech_request(&state, &request_body) {
        return Ok(build_runtime_preflight_response(
            &request_id,
            &traceparent,
            &error,
        ));
    }
    let prompt_hash = sha256_prefixed(&body_bytes);

    let correlation = TraceCorrelation::default();
    let telemetry_hints = RequestTelemetryHints::default();
    let connected_access_status = match connected_access_status_for_request(
        &mut state,
        &request_body,
        &request_id,
        0,
    )
    .await
    {
        Ok(status) => status,
        Err(response) => return Ok(response),
    };
    let access_dispatch_ctx = match maybe_prepare_connected_access_dispatch(
        &mut state,
        &headers,
        &request_body,
        &request_id,
        &traceparent,
        &prompt_hash,
        0,
        connected_access_status.admission_credential_source,
        connected_access_status.dispatch_precluded,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return Ok(response),
    };

    let (upstream_resp, served_provider_id) = send_with_provider_fallback(
        &state,
        &headers,
        "/v1/audio/speech",
        body_bytes.clone(),
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
            let latency_ms = start.elapsed().as_millis() as i64;
            finalize_connected_access_after_buffered_response(
                &state,
                &request_body,
                &body_bytes,
                &response,
                &access_dispatch_ctx,
                &request_id,
                &traceparent,
                served_provider_id.as_deref(),
                Some(latency_ms),
            );
            tracing::info!(
                request_id = %request_id,
                latency_ms,
                upstream_status = %response.status(),
                "audio speech proxied"
            );
            Ok(buffered_response_to_http_response(
                response,
                &request_id,
                &traceparent,
            ))
        }
        Err(error) => {
            tracing::error!(request_id = %request_id, error = %error, "audio speech upstream error");
            Ok(build_runtime_json_response(
                StatusCode::BAD_GATEWAY,
                &request_id,
                &traceparent,
                "upstream_error",
                "Upstream audio speech service unavailable.",
                serde_json::json!({}),
            ))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// POST /v1/completions — proxy to upstream completions endpoint
// ═══════════════════════════════════════════════════════════════════════════

pub(crate) async fn completions(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
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

    let mut state =
        match build_public_request_state(&state, &headers, peer_addr, &request_id, &traceparent)
            .await
        {
            Ok(state) => state,
            Err(response) => return Ok(response),
        };
    if let Err(response) = resolve_and_enforce_connected_endpoint_agent(
        &mut state,
        &headers,
        &request_id,
        &traceparent,
    )
    .await
    {
        return Ok(response);
    }

    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let request_body = match parse_runtime_json_body(&body_bytes) {
        Ok(body) => body,
        Err(error) => {
            return Ok(build_runtime_preflight_response(
                &request_id,
                &traceparent,
                &error,
            ))
        }
    };
    let prompt_hash = sha256_prefixed(&body_bytes);

    let correlation = TraceCorrelation::default();
    let telemetry_hints = RequestTelemetryHints::default();
    let request_model = request_body
        .get("model")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let estimated_prompt_tokens =
        crate::gateway::token_estimation::estimate_prompt_tokens(&request_body).unwrap_or(0) as u64;
    let estimated_max_completion =
        extract_requested_max_tokens(&request_body).unwrap_or(4096) as u64;
    let connected_access_status = match connected_access_status_for_request(
        &mut state,
        &request_body,
        &request_id,
        estimated_max_completion,
    )
    .await
    {
        Ok(status) => status,
        Err(response) => return Ok(response),
    };
    let ua_eval_document = match enforce_usage_authorization_evaluate_gate(
        &state,
        crate::gateway::usage_authorization::UsageAuthorizationRequestFamily::Completions,
        request_model,
        estimated_prompt_tokens,
        estimated_max_completion,
        &request_id,
        &traceparent,
    )
    .await
    {
        Ok(document) => document,
        Err(response) => return Ok(response),
    };
    state.ua_eval_document = ua_eval_document;
    let ua_financial_path_active = ua_financial_path_active(&state)
        && connected_access_status
            .admission_credential_source
            .is_some()
        && !connected_access_status.dispatch_precluded;
    let ua_admission_credential_source = connected_access_status.admission_credential_source;
    let access_dispatch_ctx = if ua_financial_path_active {
        ConnectedAccessDispatchContext::default()
    } else {
        match maybe_prepare_connected_access_dispatch(
            &mut state,
            &headers,
            &request_body,
            &request_id,
            &traceparent,
            &prompt_hash,
            extract_requested_max_tokens(&request_body).unwrap_or(4096) as u64,
            connected_access_status.admission_credential_source,
            connected_access_status.dispatch_precluded,
        )
        .await
        {
            Ok(context) => context,
            Err(response) => return Ok(response),
        }
    };

    if ua_financial_path_active {
        if let Err(response) = prepare_ua_financial_lifecycle(
            &mut state,
            &headers,
            &request_body,
            &body_bytes,
            &request_id,
            &traceparent,
            estimated_prompt_tokens,
            estimated_max_completion,
            ua_admission_credential_source,
            "/v1/completions",
            crate::gateway::usage_authorization::UsageAuthorizationRequestFamily::Completions,
        )
        .await
        {
            return Ok(response);
        }
    }

    let (upstream_resp, served_provider_id) = send_with_provider_fallback(
        &state,
        &headers,
        "/v1/completions",
        body_bytes.clone(),
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
            let latency_ms = start.elapsed().as_millis() as i64;
            if ua_financial_path_active && !response.is_cached() {
                schedule_finalize_ua_financial_lifecycle(
                    &state,
                    &request_body,
                    &response,
                    &request_id,
                    &traceparent,
                );
            } else {
                finalize_connected_access_after_buffered_response(
                    &state,
                    &request_body,
                    &body_bytes,
                    &response,
                    &access_dispatch_ctx,
                    &request_id,
                    &traceparent,
                    served_provider_id.as_deref(),
                    Some(latency_ms),
                );
            }
            tracing::info!(
                request_id = %request_id,
                latency_ms,
                upstream_status = %response.status(),
                "completions proxied"
            );
            Ok(buffered_response_to_http_response(
                response,
                &request_id,
                &traceparent,
            ))
        }
        Err(e) => {
            tracing::error!(error = %e, "completions upstream error");
            let body = serde_json::json!({
                "error": error_json(
                    "Upstream completions service unavailable",
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

// ═══════════════════════════════════════════════════════════════════════════
// POST /v1/moderations — content moderation endpoint
// ═══════════════════════════════════════════════════════════════════════════

pub(crate) async fn moderations(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
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
            Ok(state_view) => state_view,
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

    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::PAYLOAD_TOO_LARGE),
    };

    let parsed: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            let body = serde_json::json!({
                "error": error_json("Invalid JSON body", "invalid_request_error", "invalid_json")
            });
            let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
            return Ok(build_response(
                StatusCode::BAD_REQUEST,
                HeaderValue::from_static("application/json"),
                request_id,
                traceparent,
                Bytes::from(text),
                false,
                None,
            ));
        }
    };
    let prompt_hash = sha256_prefixed(&body_bytes);
    let correlation = TraceCorrelation::default();
    let telemetry_hints = RequestTelemetryHints::default();
    let connected_access_status =
        match connected_access_status_for_request(&mut state_view, &parsed, &request_id, 0).await {
            Ok(status) => status,
            Err(response) => return Ok(response),
        };
    let access_dispatch_ctx = match maybe_prepare_connected_access_dispatch(
        &mut state_view,
        &headers,
        &parsed,
        &request_id,
        &traceparent,
        &prompt_hash,
        0,
        connected_access_status.admission_credential_source,
        connected_access_status.dispatch_precluded,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return Ok(response),
    };

    let input_segments = crate::gateway::content_extraction::collect_request_text_segments_for_path(
        "/v1/moderations",
        &parsed,
    );
    let input_text = input_segments
        .iter()
        .map(|segment| segment.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if input_text.trim().is_empty() {
        let body = serde_json::json!({
            "error": error_json("Missing or invalid 'input' field", "invalid_request_error", "missing_input")
        });
        let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        return Ok(build_response(
            StatusCode::BAD_REQUEST,
            HeaderValue::from_static("application/json"),
            request_id,
            traceparent,
            Bytes::from(text),
            false,
            None,
        ));
    }

    // Check if moderation config is available; if not, proxy to upstream
    if let Some(ref mod_cfg) = state_view.moderation {
        // Build an ExternalModerationConfig from the lightweight ModerationConfig
        let ext_cfg = crate::gateway::external_moderation::ExternalModerationConfig {
            provider: mod_cfg.provider.clone(),
            secret_key_env: mod_cfg.secret_key_env.clone(),
            endpoint: mod_cfg.endpoint.clone(),
            categories: mod_cfg.categories.clone(),
            threshold: mod_cfg.threshold,
            ..Default::default()
        };

        let result = crate::gateway::external_moderation::check(&input_text, &ext_cfg).await;

        // Build OpenAI-compatible moderation response
        let body = serde_json::json!({
            "id": format!("modr-verdictan-{request_id}"),
            "model": "verdictan-moderation",
            "results": [{
                "flagged": result.flagged,
                "categories": result.scores.keys().map(|k| (k.clone(), result.flagged)).collect::<std::collections::HashMap<String, bool>>(),
                "category_scores": result.scores,
            }]
        });
        let text = Bytes::from(serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()));
        let response = crate::gateway::cache::BufferedUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            text.clone(),
            false,
        );
        finalize_connected_access_after_buffered_response(
            &state_view,
            &parsed,
            &body_bytes,
            &response,
            &access_dispatch_ctx,
            &request_id,
            &traceparent,
            None,
            Some(start.elapsed().as_millis() as i64),
        );
        Ok(build_response(
            StatusCode::OK,
            HeaderValue::from_static("application/json"),
            request_id,
            traceparent,
            text,
            false,
            None,
        ))
    } else {
        let (upstream_resp, served_provider_id) = send_with_provider_fallback(
            &state_view,
            &headers,
            "/v1/moderations",
            body_bytes.clone(),
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
                finalize_connected_access_after_buffered_response(
                    &state_view,
                    &parsed,
                    &body_bytes,
                    &response,
                    &access_dispatch_ctx,
                    &request_id,
                    &traceparent,
                    served_provider_id.as_deref(),
                    Some(start.elapsed().as_millis() as i64),
                );
                Ok(buffered_response_to_http_response(
                    response,
                    &request_id,
                    &traceparent,
                ))
            }
            Err(e) => {
                tracing::error!(error = %e, "moderations upstream error");
                let body = serde_json::json!({
                    "error": error_json(
                        "Upstream moderation service unavailable",
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
}
