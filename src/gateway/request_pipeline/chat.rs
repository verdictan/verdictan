// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Family request-pipeline module.
//! Child of `gateway::server`; parent private items remain visible.
use super::super::*;
use super::*;

pub(crate) async fn chat_completions(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let request_stage_timings = Arc::new(RequestStageTimings::default());
    REQUEST_STAGE_TIMINGS
        .scope(Arc::clone(&request_stage_timings), async move {
            let start = Instant::now();
            let x_request_id_in = headers.get("X-Request-Id").and_then(|v| v.to_str().ok());
            let request_id = match request_id::validate_or_generate_x_request_id(x_request_id_in) {
                Ok(id) => id,
                Err(err) => return Ok(reject_invalid_x_request_id(&headers, &err)),
            };
            let traceparent_in = headers.get("traceparent").and_then(|v| v.to_str().ok());
            let traceparent = request_id::normalize_or_generate_traceparent(traceparent_in);
            let (parts, body) = request.into_parts();
            let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
                .await
                .unwrap_or_default();
            let state_view = match build_public_request_state(
                &state,
                &headers,
                peer_addr,
                &request_id,
                &traceparent,
            )
            .await
            {
                Ok(state_view) => state_view,
                Err(response) => {
                    if let Some(relay_response) = try_outbound_relay(
                        &state,
                        &headers,
                        &body_bytes,
                        "/v1/chat/completions",
                        "POST",
                    )
                    .await
                    {
                        return Ok(relay_response);
                    }
                    return Ok(response);
                }
            };
            let request = Request::from_parts(parts, Body::from(body_bytes));
            execute_chat_completions_with_state(
                state_view,
                peer_addr.ip(),
                headers,
                request,
                request_id,
                traceparent,
                start,
            )
            .await
        })
        .await
        .map(|response| apply_request_stage_headers(response, request_stage_timings.as_ref()))
}
