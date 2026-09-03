// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Response, StatusCode};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use bytes::Bytes;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tracing::{debug, info, warn};

type HmacSha256 = Hmac<Sha256>;

pub(crate) const RELAY_TTL_INITIAL: u8 = 2;
pub(crate) const RELAY_LATENCY_SLO_P99_MS: u64 = 250;

static RELAY_ROUND_ROBIN: AtomicUsize = AtomicUsize::new(0);

// ── Relay envelope ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct RelayEnvelope {
    pub relay_ttl: u8,
    pub agent_id: String,
    pub publication_key: String,
    pub original_uri: String,
    pub method: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub body_base64: String,
    #[serde(default)]
    pub hop_records: Vec<RelayHopRecord>,
    pub signature: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct RelayHopRecord {
    pub gateway_id: String,
    pub timestamp: String,
    pub reason: String,
}

// ── mTLS configuration ──────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub(crate) struct RelayTlsConfig {
    pub cert_pem: Option<Vec<u8>>,
    pub key_pem: Option<Vec<u8>>,
    pub ca_cert_pem: Option<Vec<u8>>,
}

impl RelayTlsConfig {
    pub fn from_env() -> Self {
        Self {
            cert_pem: read_optional_file_from_env("VERDICTAN_RELAY_TLS_CERT"),
            key_pem: read_optional_file_from_env("VERDICTAN_RELAY_TLS_KEY"),
            ca_cert_pem: read_optional_file_from_env("VERDICTAN_RELAY_TLS_CA_CERT"),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.cert_pem.is_some() && self.key_pem.is_some() && self.ca_cert_pem.is_some()
    }

    pub fn build_mtls_client(&self) -> Option<reqwest::Client> {
        let cert_pem = self.cert_pem.as_ref()?;
        let key_pem = self.key_pem.as_ref()?;
        let ca_cert_pem = self.ca_cert_pem.as_ref()?;
        let identity =
            reqwest::Identity::from_pem(&[cert_pem.as_slice(), key_pem.as_slice()].concat())
                .ok()?;
        let ca_cert = reqwest::Certificate::from_pem(ca_cert_pem).ok()?;
        reqwest::Client::builder()
            .identity(identity)
            .add_root_certificate(ca_cert)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .ok()
    }
}

fn read_optional_file_from_env(env_key: &str) -> Option<Vec<u8>> {
    let path = std::env::var(env_key).ok()?;
    std::fs::read(path.trim()).ok()
}

pub(crate) fn verify_relay_mtls(headers: &HeaderMap, tls_config: &RelayTlsConfig) -> bool {
    if !tls_config.is_configured() {
        return false;
    }
    headers
        .get("x-verdictan-relay-client-cert-verified")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "true")
}

/// Authenticated proxy provenance for managed-public ingress headers.
///
/// Reuses the relay client-cert verification mark that a TLS-terminating proxy
/// sets only after mutual TLS succeeds. The same proxy must also prove the
/// authenticated relay transport secret so trusted-proxy CIDR membership alone
/// cannot authorize a spoofed header set.
pub(crate) fn verify_ingress_proxy_mtls(
    headers: &HeaderMap,
    tls_config: &RelayTlsConfig,
    relay_hmac_secret: Option<&str>,
) -> bool {
    verify_relay_mtls(headers, tls_config) && validate_relay_token(headers, relay_hmac_secret)
}

// ── Envelope HMAC signing ───────────────────────────────────────────────────

pub(crate) fn sign_envelope(envelope: &RelayEnvelope, hmac_secret: &str) -> String {
    let payload = build_signing_payload(envelope);
    compute_hmac(&payload, hmac_secret)
}

pub(crate) fn verify_envelope_signature(envelope: &RelayEnvelope, hmac_secret: &str) -> bool {
    let payload = build_signing_payload(envelope);
    constant_time_eq(
        compute_hmac(&payload, hmac_secret).as_bytes(),
        envelope.signature.as_bytes(),
    )
}

fn build_signing_payload(envelope: &RelayEnvelope) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct SigningHop<'a> {
        gateway_id: &'a str,
        timestamp: &'a str,
        reason: &'a str,
    }

    #[derive(serde::Serialize)]
    struct SigningPayload<'a> {
        relay_ttl: u8,
        agent_id: &'a str,
        publication_key: &'a str,
        original_uri: &'a str,
        method: &'a str,
        headers: Vec<(&'a str, &'a str)>,
        body_base64: &'a str,
        hop_records: Vec<SigningHop<'a>>,
    }

    let mut headers = envelope
        .headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    headers.sort_unstable_by(|(left_name, left_value), (right_name, right_value)| {
        left_name
            .cmp(right_name)
            .then_with(|| left_value.cmp(right_value))
    });

    let hop_records = envelope
        .hop_records
        .iter()
        .map(|hop| SigningHop {
            gateway_id: &hop.gateway_id,
            timestamp: &hop.timestamp,
            reason: &hop.reason,
        })
        .collect::<Vec<_>>();

    #[allow(clippy::expect_used)] // relay signing payload only contains serializable primitives
    serde_json::to_vec(&SigningPayload {
        relay_ttl: envelope.relay_ttl,
        agent_id: &envelope.agent_id,
        publication_key: &envelope.publication_key,
        original_uri: &envelope.original_uri,
        method: &envelope.method,
        headers,
        body_base64: &envelope.body_base64,
        hop_records,
    })
    .expect("relay signing payload should serialize")
}

#[allow(clippy::expect_used)] // HMAC-SHA256 accepts any key length; this cannot fail
fn compute_hmac(payload: &[u8], secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ── Request detection and token validation ──────────────────────────────────

pub(crate) fn is_relayed_request(headers: &HeaderMap) -> bool {
    headers
        .get("x-verdictan-relay")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "true")
}

pub(crate) fn validate_relay_token(headers: &HeaderMap, relay_hmac_secret: Option<&str>) -> bool {
    let Some(secret) = relay_hmac_secret else {
        return false;
    };
    let Some(token) = headers
        .get("x-verdictan-relay-token")
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    constant_time_eq(token.as_bytes(), secret.as_bytes())
}

// ── Cell-local peer filtering ────────────────────────────────────────────────

pub(crate) fn filter_cell_local_peers(
    peers: &[crate::runtime::PeerGatewayDescriptor],
    agent_id: &str,
    local_region_key: Option<&str>,
) -> Vec<String> {
    let Some(region_key) = local_region_key else {
        warn!("relay: no region key; cross-region relay forbidden");
        return Vec::new();
    };
    peers
        .iter()
        .filter(|p| {
            p.agent_id == agent_id
                && p.relay_endpoint.is_some()
                && p.readiness == "ready"
                && p.region.as_deref() == Some(region_key)
        })
        .filter_map(|p| p.relay_endpoint.clone())
        .collect()
}

pub(crate) fn select_relay_peer(endpoints: &[String]) -> Option<&str> {
    if endpoints.is_empty() {
        return None;
    }
    let index = RELAY_ROUND_ROBIN.fetch_add(1, Ordering::Relaxed) % endpoints.len();
    Some(&endpoints[index])
}

// ── Relay authorization ──────────────────────────────────────────────────────

pub(crate) fn authorize_relay_agent(
    publication_catalog: &[crate::runtime::ConnectedGatewayPublicationCatalogDescriptor],
    agent_id: &str,
) -> bool {
    publication_catalog.iter().any(|entry| {
        entry.agent_id.as_deref() == Some(agent_id) && entry.publication_state == "published"
    })
}

// ── Outbound: build envelope ─────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_relay_envelope(
    agent_id: &str,
    publication_key: &str,
    original_uri: &str,
    method: &str,
    headers: &HeaderMap,
    body: &Bytes,
    gateway_id: &str,
    hmac_secret: &str,
) -> RelayEnvelope {
    let header_map: HashMap<String, String> = headers
        .iter()
        .filter_map(|(name, value)| {
            let n = name.as_str().to_string();
            let v = value.to_str().ok()?.to_string();
            Some((n, v))
        })
        .collect();

    let hop = RelayHopRecord {
        gateway_id: gateway_id.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        reason: "agent_not_local".to_string(),
    };

    let mut envelope = RelayEnvelope {
        relay_ttl: RELAY_TTL_INITIAL,
        agent_id: agent_id.to_string(),
        publication_key: publication_key.to_string(),
        original_uri: original_uri.to_string(),
        method: method.to_string(),
        headers: header_map,
        body_base64: BASE64_STANDARD.encode(body),
        hop_records: vec![hop],
        signature: String::new(),
    };

    envelope.signature = sign_envelope(&envelope, hmac_secret);
    envelope
}

// ── Outbound: forward to peer ───────────────────────────────────────────────

#[allow(clippy::result_large_err)]
pub(crate) async fn forward_relay_to_peer(
    client: &reqwest::Client,
    peer_endpoint: &str,
    envelope: &RelayEnvelope,
    relay_hmac_secret: &str,
) -> Result<Response<Body>, Response<Body>> {
    let target_url = relay_target_url(peer_endpoint);

    debug!(
        peer_endpoint,
        agent_id = %envelope.agent_id,
        relay_ttl = envelope.relay_ttl,
        "forwarding relay envelope to peer gateway"
    );

    let body = serde_json::to_vec(envelope)
        .map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "relay_serialize_failed"))?;

    let request = client
        .post(&target_url)
        .header("content-type", "application/json")
        .header("x-verdictan-relay", "true")
        .header("x-verdictan-relay-token", relay_hmac_secret)
        .body(body);

    match request.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut builder = Response::builder().status(status);
            for (key, value) in resp.headers() {
                if let Ok(name) = axum::http::header::HeaderName::from_bytes(key.as_ref()) {
                    if let Ok(val) = axum::http::header::HeaderValue::from_bytes(value.as_ref()) {
                        builder = builder.header(name, val);
                    }
                }
            }
            let body_bytes = resp.bytes().await.unwrap_or_default();
            builder
                .body(Body::from(body_bytes))
                .map_err(|_| error_response(StatusCode::BAD_GATEWAY, "relay_response_build_failed"))
        }
        Err(e) => {
            warn!(error = %e, peer_endpoint, "relay request to peer failed");
            Err(error_response(
                StatusCode::BAD_GATEWAY,
                "relay_peer_unavailable",
            ))
        }
    }
}

// ── Inbound relay handler ────────────────────────────────────────────────────

pub(crate) async fn handle_relay_request(
    State(state): State<super::server::GatewayState>,
    req_headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    let start = Instant::now();
    let gateway_id = state.gateway_id.clone().unwrap_or_default();
    let read_model = state.connected_read_model.snapshot();

    // ── Verify relay token (pre-shared HMAC secret) ──────────────────────
    let Some(ref hmac_secret) = read_model.relay_hmac_secret else {
        warn!("relay: no HMAC secret configured");
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "relay_not_configured");
    };

    if !validate_relay_token(&req_headers, Some(hmac_secret)) {
        warn!("relay: invalid relay token");
        return error_response(StatusCode::UNAUTHORIZED, "relay_token_invalid");
    }

    // ── mTLS verification ────────────────────────────────────────────────
    let tls_config = RelayTlsConfig::from_env();
    if tls_config.is_configured() && !verify_relay_mtls(&req_headers, &tls_config) {
        warn!("relay: mTLS verification failed");
        return error_response(StatusCode::UNAUTHORIZED, "relay_mtls_failed");
    }

    // ── Parse relay envelope ─────────────────────────────────────────────
    let envelope: RelayEnvelope = match serde_json::from_slice(&body) {
        Ok(env) => env,
        Err(e) => {
            warn!(error = %e, "relay: invalid envelope");
            return error_response(StatusCode::BAD_REQUEST, "relay_envelope_invalid");
        }
    };

    // ── Verify envelope HMAC signature ───────────────────────────────────
    if !verify_envelope_signature(&envelope, hmac_secret) {
        warn!(agent_id = %envelope.agent_id, "relay: envelope signature verification failed");
        return error_response(StatusCode::FORBIDDEN, "relay_signature_invalid");
    }

    // ── Check relay TTL ──────────────────────────────────────────────────
    if envelope.relay_ttl == 0 {
        warn!(agent_id = %envelope.agent_id, "relay: TTL exhausted");
        let latency_ms = start.elapsed().as_millis() as u64;
        emit_relay_audit(&state, &envelope, &gateway_id, "ttl_exhausted", latency_ms);
        return error_response(StatusCode::BAD_GATEWAY, "relay_ttl_exhausted");
    }

    // ── Authorize agent on this gateway ──────────────────────────────────
    if !authorize_relay_agent(&read_model.publication_catalog, &envelope.agent_id) {
        warn!(
            agent_id = %envelope.agent_id,
            gateway_id = %gateway_id,
            "relay: agent not authorized on this gateway"
        );
        let latency_ms = start.elapsed().as_millis() as u64;
        emit_relay_audit(&state, &envelope, &gateway_id, "forbidden", latency_ms);
        return error_response(StatusCode::FORBIDDEN, "relay_agent_not_authorized");
    }

    // ── Enforce cell-local constraint ────────────────────────────────────
    if let Some(last_hop) = envelope.hop_records.last() {
        let sender_cell = read_model
            .peer_gateways
            .iter()
            .find(|p| p.gateway_id == last_hop.gateway_id)
            .and_then(|p| p.region.as_deref());
        if let (Some(local_cell), Some(remote_cell)) =
            (read_model.region_key.as_deref(), sender_cell)
        {
            if local_cell != remote_cell {
                warn!(
                    local_cell,
                    remote_cell,
                    agent_id = %envelope.agent_id,
                    "relay: cross-cell relay forbidden"
                );
                return error_response(StatusCode::FORBIDDEN, "relay_cross_cell_forbidden");
            }
        }
    }

    // ── Decode original request body ─────────────────────────────────────
    let original_body = match BASE64_STANDARD.decode(&envelope.body_base64) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "relay: body decode failed");
            return error_response(StatusCode::BAD_REQUEST, "relay_body_decode_failed");
        }
    };

    // ── Forward to upstream provider ─────────────────────────────────────
    let upstream_url = format!(
        "{}{}",
        state.upstream_base.trim_end_matches('/'),
        envelope.original_uri,
    );

    let method = relay_method(&envelope.method);
    let upstream_headers = build_upstream_headers(&envelope.headers, state.upstream_auth.as_ref());

    let response = state
        .client
        .request(method, &upstream_url)
        .headers(upstream_headers)
        .body(original_body)
        .send()
        .await;

    let latency_ms = start.elapsed().as_millis() as u64;
    super::metrics::record_relay_request(latency_ms);

    match response {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut builder = Response::builder().status(status);
            for (key, value) in resp.headers() {
                if let Ok(name) = axum::http::header::HeaderName::from_bytes(key.as_ref()) {
                    if let Ok(val) = axum::http::header::HeaderValue::from_bytes(value.as_ref()) {
                        builder = builder.header(name, val);
                    }
                }
            }
            let resp_bytes = resp.bytes().await.unwrap_or_default();

            emit_relay_audit(&state, &envelope, &gateway_id, "success", latency_ms);

            info!(
                agent_id = %envelope.agent_id,
                relay_ttl = envelope.relay_ttl,
                latency_ms,
                slo_exceeded = latency_ms > RELAY_LATENCY_SLO_P99_MS,
                "relay request completed"
            );

            builder.body(Body::from(resp_bytes)).unwrap_or_else(|_| {
                error_response(StatusCode::BAD_GATEWAY, "relay_response_build_failed")
            })
        }
        Err(e) => {
            warn!(error = %e, "relay: upstream request failed");
            emit_relay_audit(
                &state,
                &envelope,
                &gateway_id,
                "upstream_failed",
                latency_ms,
            );
            error_response(StatusCode::BAD_GATEWAY, "relay_upstream_failed")
        }
    }
}

// ── Audit event emission ─────────────────────────────────────────────────────

fn relay_target_url(peer_endpoint: &str) -> String {
    format!("{}/verdictan/relay", peer_endpoint.trim_end_matches('/'))
}

fn relay_method(method: &str) -> reqwest::Method {
    match method {
        "GET" => reqwest::Method::GET,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        _ => reqwest::Method::POST,
    }
}

fn build_upstream_headers(
    envelope_headers: &HashMap<String, String>,
    upstream_auth: Option<&(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
) -> reqwest::header::HeaderMap {
    let mut upstream_headers = reqwest::header::HeaderMap::new();
    for (name, value) in envelope_headers {
        if matches!(
            name.as_str(),
            "host" | "x-verdictan-relay" | "x-verdictan-relay-token"
        ) {
            continue;
        }
        if let (Ok(rname), Ok(rvalue)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            upstream_headers.insert(rname, rvalue);
        }
    }

    if let Some((auth_name, auth_value)) = upstream_auth {
        if let Ok(rname) = reqwest::header::HeaderName::from_bytes(auth_name.as_ref()) {
            if let Ok(rvalue) = reqwest::header::HeaderValue::from_bytes(auth_value.as_ref()) {
                upstream_headers.insert(rname, rvalue);
            }
        }
    }

    upstream_headers
}

fn emit_relay_audit(
    state: &super::server::GatewayState,
    envelope: &RelayEnvelope,
    gateway_id: &str,
    outcome: &str,
    latency_ms: u64,
) {
    let Some(ref sink) = state.event_sink else {
        return;
    };
    let peer_gateway = envelope
        .hop_records
        .last()
        .map(|hop| hop.gateway_id.as_str());
    let event = serde_json::json!({
        "verdict": "relay",
        "reason_code": format!("relay.inbound.{outcome}"),
        "details": {
            "relay": {
                "direction": "inbound",
                "agent_id": envelope.agent_id,
                "publication_key": envelope.publication_key,
                "gateway_id": gateway_id,
                "peer_gateway": peer_gateway,
                "outcome": outcome,
                "latency_ms": latency_ms,
                "relay_ttl": envelope.relay_ttl,
                "hop_count": envelope.hop_records.len(),
                "slo_p99_ms": RELAY_LATENCY_SLO_P99_MS,
                "slo_exceeded": latency_ms > RELAY_LATENCY_SLO_P99_MS,
            }
        }
    });
    let request_id = format!("relay-{}", uuid::Uuid::new_v4());
    let _traceparent = format!(
        "00-{}-0000000000000001-01",
        uuid::Uuid::new_v4().as_simple()
    );
    sink.enqueue_decision(&request_id, event);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_outbound_relay_audit(
    sink: &super::server::EventSink,
    agent_id: &str,
    publication_key: &str,
    gateway_id: &str,
    peer_endpoint: &str,
    outcome: &str,
    latency_ms: u64,
    relay_ttl: u8,
) {
    let event = serde_json::json!({
        "verdict": "relay",
        "reason_code": format!("relay.outbound.{outcome}"),
        "details": {
            "relay": {
                "direction": "outbound",
                "agent_id": agent_id,
                "publication_key": publication_key,
                "gateway_id": gateway_id,
                "peer_endpoint": peer_endpoint,
                "outcome": outcome,
                "latency_ms": latency_ms,
                "relay_ttl": relay_ttl,
                "slo_p99_ms": RELAY_LATENCY_SLO_P99_MS,
                "slo_exceeded": latency_ms > RELAY_LATENCY_SLO_P99_MS,
            }
        }
    });
    let request_id = format!("relay-{}", uuid::Uuid::new_v4());
    let _traceparent = format!(
        "00-{}-0000000000000001-01",
        uuid::Uuid::new_v4().as_simple()
    );
    sink.enqueue_decision(&request_id, event);
}

// ── Error responses ─────────────────────────────────────────────────────────

fn error_response(status: StatusCode, code: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "error": {
                    "message": format!("Relay request failed: {code}"),
                    "type": "relay_error",
                    "code": code,
                }
            }))
            .unwrap_or_else(|_| b"{}".to_vec()),
        ))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(status)
                .body(Body::empty())
                .unwrap_or_default()
        })
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
    use axum::http::HeaderValue;
    use axum::routing::post;
    use axum::Router;
    use reqwest::header::{HeaderName as ReqwestHeaderName, HeaderValue as ReqwestHeaderValue};
    use std::sync::{Arc, LazyLock, Mutex};
    use tempfile::tempdir;

    static ROUND_ROBIN_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[derive(Clone, Debug)]
    struct CapturedRelayRequest {
        headers: HeaderMap,
        body: Bytes,
    }

    #[test]
    fn relay_detection_identifies_relayed_requests() {
        let mut headers = HeaderMap::new();
        assert!(!is_relayed_request(&headers));

        headers.insert("x-verdictan-relay", HeaderValue::from_static("true"));
        assert!(is_relayed_request(&headers));

        headers.insert("x-verdictan-relay", HeaderValue::from_static("false"));
        assert!(!is_relayed_request(&headers));
    }

    #[test]
    fn relay_detection_rejects_non_utf8_marker_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-verdictan-relay",
            HeaderValue::from_bytes(&[0xFF]).expect("opaque relay marker"),
        );
        assert!(!is_relayed_request(&headers));
    }

    #[test]
    fn relay_token_validation_uses_constant_time_comparison() {
        assert!(!validate_relay_token(&HeaderMap::new(), Some("secret123")));

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-verdictan-relay-token",
            HeaderValue::from_static("secret123"),
        );
        assert!(validate_relay_token(&headers, Some("secret123")));
        assert!(!validate_relay_token(&headers, Some("wrong")));
        assert!(!validate_relay_token(&headers, None));
    }

    #[test]
    fn relay_token_validation_rejects_non_utf8_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-verdictan-relay-token",
            HeaderValue::from_bytes(&[0xFF]).expect("opaque relay token"),
        );

        assert!(!validate_relay_token(&headers, Some("secret123")));
    }

    #[test]
    fn select_relay_peer_round_robins() {
        let _guard = ROUND_ROBIN_TEST_LOCK.lock().expect("round robin lock");
        RELAY_ROUND_ROBIN.store(0, Ordering::Relaxed);

        let endpoints = vec![
            "https://gw1.example.com".to_string(),
            "https://gw2.example.com".to_string(),
        ];
        assert_eq!(
            select_relay_peer(&endpoints),
            Some("https://gw1.example.com")
        );
        assert_eq!(
            select_relay_peer(&endpoints),
            Some("https://gw2.example.com")
        );
        assert_eq!(
            select_relay_peer(&endpoints),
            Some("https://gw1.example.com")
        );
    }

    #[test]
    fn select_relay_peer_returns_none_for_empty() {
        let endpoints: Vec<String> = vec![];
        assert!(select_relay_peer(&endpoints).is_none());
    }

    #[test]
    fn filter_cell_local_peers_rejects_cross_cell() {
        let peers = vec![crate::runtime::PeerGatewayDescriptor {
            agent_id: "agent-1".to_string(),
            gateway_id: "gw-1".to_string(),
            relay_endpoint: Some("https://gw1.example.com".to_string()),
            readiness: "ready".to_string(),
            region: Some("us-east".to_string()),
        }];
        let result = filter_cell_local_peers(&peers, "agent-1", Some("eu-west"));
        assert!(result.is_empty());
    }

    #[test]
    fn filter_cell_local_peers_accepts_same_cell() {
        let peers = vec![crate::runtime::PeerGatewayDescriptor {
            agent_id: "agent-1".to_string(),
            gateway_id: "gw-1".to_string(),
            relay_endpoint: Some("https://gw1.example.com".to_string()),
            readiness: "ready".to_string(),
            region: Some("us-east".to_string()),
        }];
        let result = filter_cell_local_peers(&peers, "agent-1", Some("us-east"));
        assert_eq!(result, vec!["https://gw1.example.com"]);
    }

    #[test]
    fn filter_cell_local_peers_rejects_when_no_local_cell() {
        let peers = vec![crate::runtime::PeerGatewayDescriptor {
            agent_id: "agent-1".to_string(),
            gateway_id: "gw-1".to_string(),
            relay_endpoint: Some("https://gw1.example.com".to_string()),
            readiness: "ready".to_string(),
            region: Some("us-east".to_string()),
        }];
        let result = filter_cell_local_peers(&peers, "agent-1", None);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_cell_local_peers_only_keeps_ready_same_region_matches() {
        let peers = vec![
            crate::runtime::PeerGatewayDescriptor {
                agent_id: "agent-1".to_string(),
                gateway_id: "gw-ready".to_string(),
                relay_endpoint: Some("https://gw-ready.example.com".to_string()),
                readiness: "ready".to_string(),
                region: Some("us-east".to_string()),
            },
            crate::runtime::PeerGatewayDescriptor {
                agent_id: "agent-2".to_string(),
                gateway_id: "gw-other-agent".to_string(),
                relay_endpoint: Some("https://gw-other-agent.example.com".to_string()),
                readiness: "ready".to_string(),
                region: Some("us-east".to_string()),
            },
            crate::runtime::PeerGatewayDescriptor {
                agent_id: "agent-1".to_string(),
                gateway_id: "gw-no-endpoint".to_string(),
                relay_endpoint: None,
                readiness: "ready".to_string(),
                region: Some("us-east".to_string()),
            },
            crate::runtime::PeerGatewayDescriptor {
                agent_id: "agent-1".to_string(),
                gateway_id: "gw-not-ready".to_string(),
                relay_endpoint: Some("https://gw-not-ready.example.com".to_string()),
                readiness: "warming".to_string(),
                region: Some("us-east".to_string()),
            },
            crate::runtime::PeerGatewayDescriptor {
                agent_id: "agent-1".to_string(),
                gateway_id: "gw-other-region".to_string(),
                relay_endpoint: Some("https://gw-other-region.example.com".to_string()),
                readiness: "ready".to_string(),
                region: Some("eu-west".to_string()),
            },
        ];

        let result = filter_cell_local_peers(&peers, "agent-1", Some("us-east"));
        assert_eq!(result, vec!["https://gw-ready.example.com"]);
    }

    #[test]
    fn authorize_relay_agent_allows_published() {
        let catalog = vec![
            crate::runtime::ConnectedGatewayPublicationCatalogDescriptor {
                family_key: "global".to_string(),
                publication_key: "pub-1".to_string(),
                published_hostname: None,
                publication_state: "published".to_string(),
                active_revision_id: None,
                locality_mode: "global".to_string(),
                serving_fleet_class: "managed".to_string(),
                agent_id: Some("agent-1".to_string()),
            },
        ];
        assert!(authorize_relay_agent(&catalog, "agent-1"));
        assert!(!authorize_relay_agent(&catalog, "agent-2"));
    }

    #[test]
    fn authorize_relay_agent_rejects_unpublished() {
        let catalog = vec![
            crate::runtime::ConnectedGatewayPublicationCatalogDescriptor {
                family_key: "global".to_string(),
                publication_key: "pub-1".to_string(),
                published_hostname: None,
                publication_state: "draining".to_string(),
                active_revision_id: None,
                locality_mode: "global".to_string(),
                serving_fleet_class: "managed".to_string(),
                agent_id: Some("agent-1".to_string()),
            },
        ];
        assert!(!authorize_relay_agent(&catalog, "agent-1"));
    }

    #[test]
    fn envelope_signature_roundtrip() {
        let headers = HeaderMap::new();
        let body = Bytes::from(r#"{"model":"gpt-4","messages":[]}"#);
        let envelope = build_relay_envelope(
            "agent-1",
            "pub-1",
            "/v1/chat/completions",
            "POST",
            &headers,
            &body,
            "gw-origin",
            "test-secret",
        );

        assert_eq!(envelope.relay_ttl, RELAY_TTL_INITIAL);
        assert_eq!(envelope.agent_id, "agent-1");
        assert_eq!(envelope.hop_records.len(), 1);
        assert_eq!(envelope.hop_records[0].gateway_id, "gw-origin");
        assert!(!envelope.signature.is_empty());
        assert!(verify_envelope_signature(&envelope, "test-secret"));
        assert!(!verify_envelope_signature(&envelope, "wrong-secret"));
    }

    #[test]
    fn envelope_signature_rejects_tampered_payload_fields() {
        let envelope = RelayEnvelope {
            relay_ttl: 2,
            agent_id: "agent-1".to_string(),
            publication_key: "pub-1".to_string(),
            original_uri: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body_base64: "dGVzdA==".to_string(),
            hop_records: vec![RelayHopRecord {
                gateway_id: "gw-origin".to_string(),
                timestamp: "2026-06-23T12:00:00Z".to_string(),
                reason: "agent_not_local".to_string(),
            }],
            signature: String::new(),
        };
        let signature = sign_envelope(&envelope, "secret");

        let mut tampered_body = envelope.clone();
        tampered_body.signature = signature.clone();
        tampered_body.body_base64 = "b3RoZXI=".to_string();
        assert!(!verify_envelope_signature(&tampered_body, "secret"));

        let mut tampered_hop = envelope;
        tampered_hop.signature = signature;
        tampered_hop.hop_records[0].gateway_id = "gw-other".to_string();
        assert!(!verify_envelope_signature(&tampered_hop, "secret"));
    }

    #[test]
    fn envelope_signature_rejects_tampered_method_and_headers() {
        let mut envelope = RelayEnvelope {
            relay_ttl: 2,
            agent_id: "agent-1".to_string(),
            publication_key: "pub-1".to_string(),
            original_uri: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::from([("x-trace-id".to_string(), "trace-1".to_string())]),
            body_base64: "dGVzdA==".to_string(),
            hop_records: vec![],
            signature: String::new(),
        };
        envelope.signature = sign_envelope(&envelope, "secret");

        let mut tampered_method = envelope.clone();
        tampered_method.method = "PATCH".to_string();
        assert!(!verify_envelope_signature(&tampered_method, "secret"));

        let mut tampered_headers = envelope;
        tampered_headers
            .headers
            .insert("x-trace-id".to_string(), "trace-2".to_string());
        assert!(!verify_envelope_signature(&tampered_headers, "secret"));
    }

    #[test]
    fn envelope_signature_is_deterministic() {
        let sig1 = sign_envelope(
            &RelayEnvelope {
                relay_ttl: 2,
                agent_id: "a".to_string(),
                publication_key: "p".to_string(),
                original_uri: "/v1/chat/completions".to_string(),
                method: "POST".to_string(),
                headers: HashMap::new(),
                body_base64: "dGVzdA==".to_string(),
                hop_records: vec![],
                signature: String::new(),
            },
            "secret",
        );
        let sig2 = sign_envelope(
            &RelayEnvelope {
                relay_ttl: 2,
                agent_id: "a".to_string(),
                publication_key: "p".to_string(),
                original_uri: "/v1/chat/completions".to_string(),
                method: "POST".to_string(),
                headers: HashMap::new(),
                body_base64: "dGVzdA==".to_string(),
                hop_records: vec![],
                signature: String::new(),
            },
            "secret",
        );
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn build_signing_payload_serializes_expected_fields_and_hops() {
        let envelope = RelayEnvelope {
            relay_ttl: 7,
            agent_id: "agent-1".to_string(),
            publication_key: "pub-1".to_string(),
            original_uri: "/v1/responses".to_string(),
            method: "POST".to_string(),
            headers: HashMap::from([
                ("x-request-id".to_string(), "req-1".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
            ]),
            body_base64: "cGF5bG9hZA==".to_string(),
            hop_records: vec![
                RelayHopRecord {
                    gateway_id: "gw-a".to_string(),
                    timestamp: "2026-06-23T12:00:00Z".to_string(),
                    reason: "agent_not_local".to_string(),
                },
                RelayHopRecord {
                    gateway_id: "gw-b".to_string(),
                    timestamp: "2026-06-23T12:01:00Z".to_string(),
                    reason: "agent_not_local".to_string(),
                },
            ],
            signature: String::new(),
        };

        let payload: serde_json::Value =
            serde_json::from_slice(&build_signing_payload(&envelope)).expect("payload json");

        assert_eq!(
            payload,
            serde_json::json!({
                "relay_ttl": 7,
                "agent_id": "agent-1",
                "publication_key": "pub-1",
                "original_uri": "/v1/responses",
                "method": "POST",
                "headers": [
                    ["content-type", "application/json"],
                    ["x-request-id", "req-1"]
                ],
                "body_base64": "cGF5bG9hZA==",
                "hop_records": [
                    {
                        "gateway_id": "gw-a",
                        "timestamp": "2026-06-23T12:00:00Z",
                        "reason": "agent_not_local"
                    },
                    {
                        "gateway_id": "gw-b",
                        "timestamp": "2026-06-23T12:01:00Z",
                        "reason": "agent_not_local"
                    }
                ]
            })
        );
    }

    #[test]
    fn compute_hmac_is_hex_and_changes_with_inputs() {
        let baseline = compute_hmac(b"relay-payload", "relay-secret");
        assert_eq!(baseline.len(), 64);
        assert!(baseline.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(baseline, compute_hmac(b"relay-payload-2", "relay-secret"));
        assert_ne!(baseline, compute_hmac(b"relay-payload", "relay-secret-2"));
    }

    #[test]
    fn constant_time_eq_rejects_length_and_content_mismatches() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"same-but-longer"));
        assert!(!constant_time_eq(b"same", b"lame"));
    }

    #[test]
    fn mtls_config_not_configured_by_default() {
        let config = RelayTlsConfig::default();
        assert!(!config.is_configured());
        assert!(config.build_mtls_client().is_none());
    }

    #[test]
    fn mtls_config_returns_none_for_invalid_pem_material() {
        let config = RelayTlsConfig {
            cert_pem: Some(b"not-a-cert".to_vec()),
            key_pem: Some(b"not-a-key".to_vec()),
            ca_cert_pem: Some(b"not-a-ca".to_vec()),
        };

        assert!(config.is_configured());
        assert!(config.build_mtls_client().is_none());
    }

    #[test]
    fn relay_ttl_initial_is_two() {
        assert_eq!(RELAY_TTL_INITIAL, 2);
    }

    #[test]
    fn body_base64_roundtrip_in_envelope() {
        let original = b"hello world";
        let encoded = BASE64_STANDARD.encode(original);
        let decoded = BASE64_STANDARD.decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn verify_relay_mtls_requires_verified_header_when_tls_is_configured() {
        let tls_config = RelayTlsConfig {
            cert_pem: Some(vec![1]),
            key_pem: Some(vec![2]),
            ca_cert_pem: Some(vec![3]),
        };
        let mut headers = HeaderMap::new();

        assert!(!verify_relay_mtls(&headers, &tls_config));

        headers.insert(
            "x-verdictan-relay-client-cert-verified",
            HeaderValue::from_static("true"),
        );
        assert!(verify_relay_mtls(&headers, &tls_config));

        headers.insert(
            "x-verdictan-relay-client-cert-verified",
            HeaderValue::from_static("false"),
        );
        assert!(!verify_relay_mtls(&headers, &tls_config));
    }

    #[test]
    fn verify_ingress_proxy_mtls_requires_verified_header_and_relay_token() {
        let tls_config = RelayTlsConfig {
            cert_pem: Some(vec![1]),
            key_pem: Some(vec![2]),
            ca_cert_pem: Some(vec![3]),
        };
        let mut headers = HeaderMap::new();
        assert!(!verify_ingress_proxy_mtls(
            &headers,
            &tls_config,
            Some("relay-secret"),
        ));
        headers.insert(
            "x-verdictan-relay-client-cert-verified",
            HeaderValue::from_static("true"),
        );
        assert!(!verify_ingress_proxy_mtls(
            &headers,
            &tls_config,
            Some("relay-secret"),
        ));
        headers.insert(
            "x-verdictan-relay-token",
            HeaderValue::from_static("relay-secret"),
        );
        assert!(verify_ingress_proxy_mtls(
            &headers,
            &tls_config,
            Some("relay-secret"),
        ));
        assert!(!verify_ingress_proxy_mtls(
            &headers,
            &tls_config,
            Some("wrong-secret"),
        ));
    }

    #[test]
    fn verify_relay_mtls_fails_when_tls_is_incomplete() {
        let tls_config = RelayTlsConfig {
            cert_pem: Some(vec![1]),
            key_pem: Some(vec![2]),
            ca_cert_pem: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-verdictan-relay-client-cert-verified",
            HeaderValue::from_static("true"),
        );

        assert!(!verify_relay_mtls(&headers, &tls_config));
    }

    #[test]
    fn relay_tls_config_from_env_reads_all_pem_files() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("relay.crt");
        let key_path = dir.path().join("relay.key");
        let ca_path = dir.path().join("relay-ca.crt");
        std::fs::write(&cert_path, b"cert").expect("write cert");
        std::fs::write(&key_path, b"key").expect("write key");
        std::fs::write(&ca_path, b"ca").expect("write ca");

        crate::test_support::set_var(
            "VERDICTAN_RELAY_TLS_CERT",
            format!("  {}  ", cert_path.display()),
        );
        crate::test_support::set_var(
            "VERDICTAN_RELAY_TLS_KEY",
            format!("  {}  ", key_path.display()),
        );
        crate::test_support::set_var(
            "VERDICTAN_RELAY_TLS_CA_CERT",
            format!("  {}  ", ca_path.display()),
        );

        let config = RelayTlsConfig::from_env();
        assert_eq!(config.cert_pem.as_deref(), Some(b"cert".as_slice()));
        assert_eq!(config.key_pem.as_deref(), Some(b"key".as_slice()));
        assert_eq!(config.ca_cert_pem.as_deref(), Some(b"ca".as_slice()));
        assert!(config.is_configured());

        crate::test_support::unset_var("VERDICTAN_RELAY_TLS_CERT");
        crate::test_support::unset_var("VERDICTAN_RELAY_TLS_KEY");
        crate::test_support::unset_var("VERDICTAN_RELAY_TLS_CA_CERT");
    }

    #[test]
    fn read_optional_file_from_env_returns_none_for_missing_env_and_missing_file() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        crate::test_support::unset_var("VERDICTAN_RELAY_TLS_CERT");
        assert!(read_optional_file_from_env("VERDICTAN_RELAY_TLS_CERT").is_none());

        crate::test_support::set_var("VERDICTAN_RELAY_TLS_CERT", "/path/that/does/not/exist.pem");
        assert!(read_optional_file_from_env("VERDICTAN_RELAY_TLS_CERT").is_none());
        crate::test_support::unset_var("VERDICTAN_RELAY_TLS_CERT");
    }

    #[test]
    fn build_relay_envelope_skips_non_utf8_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-valid", HeaderValue::from_static("value"));
        headers.insert(
            "x-binary",
            HeaderValue::from_bytes(&[0xFF]).expect("opaque header value"),
        );

        let envelope = build_relay_envelope(
            "agent-2",
            "pub-2",
            "/v1/responses",
            "POST",
            &headers,
            &Bytes::from_static(b"payload"),
            "gw-1",
            "secret",
        );

        assert_eq!(
            envelope.headers.get("x-valid").map(String::as_str),
            Some("value")
        );
        assert!(!envelope.headers.contains_key("x-binary"));
        assert!(verify_envelope_signature(&envelope, "secret"));
    }

    #[tokio::test]
    async fn build_relay_envelope_preserves_method_and_encodes_body() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("req-123"));
        let envelope = build_relay_envelope(
            "agent-3",
            "pub-3",
            "/v1/files",
            "PATCH",
            &headers,
            &Bytes::from_static(b"relay-body"),
            "gw-origin",
            "secret",
        );

        assert_eq!(envelope.method, "PATCH");
        assert_eq!(envelope.original_uri, "/v1/files");
        assert_eq!(envelope.body_base64, BASE64_STANDARD.encode(b"relay-body"));
        assert_eq!(
            envelope.headers.get("x-request-id").map(String::as_str),
            Some("req-123")
        );
        assert_eq!(envelope.hop_records[0].reason, "agent_not_local");
        assert!(chrono::DateTime::parse_from_rfc3339(&envelope.hop_records[0].timestamp).is_ok());
    }

    #[test]
    fn relay_target_url_trims_trailing_slashes() {
        assert_eq!(
            relay_target_url("https://gw.example.com///"),
            "https://gw.example.com/verdictan/relay"
        );
        assert_eq!(
            relay_target_url("https://gw.example.com"),
            "https://gw.example.com/verdictan/relay"
        );
    }

    #[test]
    fn relay_method_maps_known_verbs_and_falls_back_to_post() {
        assert_eq!(relay_method("GET"), reqwest::Method::GET);
        assert_eq!(relay_method("PUT"), reqwest::Method::PUT);
        assert_eq!(relay_method("DELETE"), reqwest::Method::DELETE);
        assert_eq!(relay_method("PATCH"), reqwest::Method::PATCH);
        assert_eq!(relay_method("POST"), reqwest::Method::POST);
        assert_eq!(relay_method("unknown"), reqwest::Method::POST);
    }

    #[test]
    fn build_upstream_headers_filters_relay_headers_and_injects_auth() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("host".to_string(), "relay.example.com".to_string());
        headers.insert("x-verdictan-relay".to_string(), "true".to_string());
        headers.insert(
            "x-verdictan-relay-token".to_string(),
            "relay-secret".to_string(),
        );
        headers.insert("bad header".to_string(), "ignored".to_string());
        headers.insert("x-invalid-value".to_string(), "\nnot-allowed".to_string());

        let auth_name = ReqwestHeaderName::from_static("authorization");
        let auth_value = ReqwestHeaderValue::from_static("Bearer upstream");
        let upstream_headers = build_upstream_headers(&headers, Some(&(auth_name, auth_value)));

        assert_eq!(
            upstream_headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert!(upstream_headers.get("host").is_none());
        assert!(upstream_headers.get("x-verdictan-relay").is_none());
        assert!(upstream_headers.get("x-verdictan-relay-token").is_none());
        assert!(upstream_headers.get("x-invalid-value").is_none());
        assert_eq!(
            upstream_headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer upstream")
        );
        assert_eq!(upstream_headers.len(), 2);
    }

    #[test]
    fn build_upstream_headers_without_auth_leaves_existing_headers_only() {
        let mut headers = HashMap::new();
        headers.insert("accept".to_string(), "application/json".to_string());

        let upstream_headers = build_upstream_headers(&headers, None);
        assert_eq!(
            upstream_headers
                .get("accept")
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(upstream_headers.len(), 1);
    }

    #[tokio::test]
    async fn error_response_returns_structured_json_payload() {
        let response = error_response(StatusCode::FORBIDDEN, "relay_signature_invalid");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("parse relay error body");
        assert_eq!(json["error"]["type"], "relay_error");
        assert_eq!(json["error"]["code"], "relay_signature_invalid");
    }

    #[tokio::test]
    async fn forward_relay_to_peer_proxies_request_and_response() {
        let captured = Arc::new(tokio::sync::Mutex::new(None::<CapturedRelayRequest>));
        let app = {
            let captured = Arc::clone(&captured);
            Router::new().route(
                "/verdictan/relay",
                post(move |headers: HeaderMap, body: Bytes| {
                    let captured = Arc::clone(&captured);
                    async move {
                        *captured.lock().await = Some(CapturedRelayRequest { headers, body });
                        Response::builder()
                            .status(StatusCode::CREATED)
                            .header("x-peer-status", "ok")
                            .body(Body::from("peer-ok"))
                            .expect("peer response")
                    }
                }),
            )
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind relay peer");
        let address = listener.local_addr().expect("peer address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve relay peer");
        });
        tokio::task::yield_now().await;

        let envelope = RelayEnvelope {
            relay_ttl: RELAY_TTL_INITIAL,
            agent_id: "agent-1".to_string(),
            publication_key: "pub-1".to_string(),
            original_uri: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body_base64: BASE64_STANDARD.encode(br#"{"hello":"world"}"#),
            hop_records: vec![RelayHopRecord {
                gateway_id: "gw-origin".to_string(),
                timestamp: "2026-06-23T12:00:00Z".to_string(),
                reason: "agent_not_local".to_string(),
            }],
            signature: "signed".to_string(),
        };

        let response = forward_relay_to_peer(
            &reqwest::Client::new(),
            &format!("http://{address}/"),
            &envelope,
            "relay-secret",
        )
        .await
        .expect("forwarded relay response");

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response
                .headers()
                .get("x-peer-status")
                .and_then(|value| value.to_str().ok()),
            Some("ok")
        );
        let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("relay response body");
        assert_eq!(response_body, Bytes::from_static(b"peer-ok"));

        let captured = captured
            .lock()
            .await
            .clone()
            .expect("captured relay request");
        assert_eq!(
            captured
                .headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            captured
                .headers
                .get("x-verdictan-relay")
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            captured
                .headers
                .get("x-verdictan-relay-token")
                .and_then(|value| value.to_str().ok()),
            Some("relay-secret")
        );

        let forwarded: RelayEnvelope =
            serde_json::from_slice(&captured.body).expect("forwarded relay envelope");
        assert_eq!(forwarded.agent_id, envelope.agent_id);
        assert_eq!(forwarded.publication_key, envelope.publication_key);
        assert_eq!(forwarded.original_uri, envelope.original_uri);
        assert_eq!(forwarded.signature, envelope.signature);

        server.abort();
    }

    #[tokio::test]
    async fn forward_relay_to_peer_returns_bad_gateway_on_request_failure() {
        let envelope = RelayEnvelope {
            relay_ttl: RELAY_TTL_INITIAL,
            agent_id: "agent-1".to_string(),
            publication_key: "pub-1".to_string(),
            original_uri: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body_base64: BASE64_STANDARD.encode(b"payload"),
            hop_records: vec![],
            signature: "signed".to_string(),
        };

        let response = forward_relay_to_peer(
            &reqwest::Client::new(),
            "http://[::1",
            &envelope,
            "relay-secret",
        )
        .await
        .expect_err("request failure should return relay error response");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("relay failure body");
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("parse relay failure body");
        assert_eq!(json["error"]["code"], "relay_peer_unavailable");
    }

    // ── relay_target_url ────────────────────────────────────────────────

    #[test]
    fn relay_target_url_strips_trailing_slash() {
        assert_eq!(
            relay_target_url("https://peer.example.com/"),
            "https://peer.example.com/verdictan/relay"
        );
        assert_eq!(
            relay_target_url("https://peer.example.com"),
            "https://peer.example.com/verdictan/relay"
        );
    }

    // ── relay_method ────────────────────────────────────────────────────

    #[test]
    fn relay_method_maps_known_methods() {
        assert_eq!(relay_method("GET"), reqwest::Method::GET);
        assert_eq!(relay_method("PUT"), reqwest::Method::PUT);
        assert_eq!(relay_method("DELETE"), reqwest::Method::DELETE);
        assert_eq!(relay_method("PATCH"), reqwest::Method::PATCH);
    }

    #[test]
    fn relay_method_defaults_to_post() {
        assert_eq!(relay_method("POST"), reqwest::Method::POST);
        assert_eq!(relay_method("UNKNOWN"), reqwest::Method::POST);
    }

    // ── build_upstream_headers ───────────────────────────────────────────

    #[test]
    fn build_upstream_headers_skips_relay_headers() {
        let mut envelope_headers = HashMap::new();
        envelope_headers.insert("content-type".to_string(), "application/json".to_string());
        envelope_headers.insert("host".to_string(), "original.example.com".to_string());
        envelope_headers.insert("x-verdictan-relay".to_string(), "true".to_string());
        envelope_headers.insert("x-verdictan-relay-token".to_string(), "secret".to_string());

        let headers = build_upstream_headers(&envelope_headers, None);
        assert!(headers.get("content-type").is_some());
        assert!(headers.get("host").is_none());
        assert!(headers.get("x-verdictan-relay").is_none());
        assert!(headers.get("x-verdictan-relay-token").is_none());
    }

    #[test]
    fn build_upstream_headers_inserts_auth() {
        let envelope_headers = HashMap::new();
        let auth_name = reqwest::header::HeaderName::from_static("authorization");
        let auth_value = reqwest::header::HeaderValue::from_static("Bearer tok");
        let headers = build_upstream_headers(&envelope_headers, Some(&(auth_name, auth_value)));
        assert_eq!(
            headers.get("authorization").unwrap().to_str().unwrap(),
            "Bearer tok"
        );
    }

    // ── verify_relay_mtls ───────────────────────────────────────────────

    #[test]
    fn verify_relay_mtls_returns_false_when_not_configured() {
        let headers = HeaderMap::new();
        let config = RelayTlsConfig::default();
        assert!(!verify_relay_mtls(&headers, &config));
    }

    #[test]
    fn verify_relay_mtls_returns_false_when_header_missing() {
        let headers = HeaderMap::new();
        let config = RelayTlsConfig {
            cert_pem: Some(b"cert".to_vec()),
            key_pem: Some(b"key".to_vec()),
            ca_cert_pem: Some(b"ca".to_vec()),
        };
        assert!(!verify_relay_mtls(&headers, &config));
    }

    #[test]
    fn verify_relay_mtls_returns_true_when_verified() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-verdictan-relay-client-cert-verified",
            HeaderValue::from_static("true"),
        );
        let config = RelayTlsConfig {
            cert_pem: Some(b"cert".to_vec()),
            key_pem: Some(b"key".to_vec()),
            ca_cert_pem: Some(b"ca".to_vec()),
        };
        assert!(verify_relay_mtls(&headers, &config));
    }

    // ── RelayTlsConfig ──────────────────────────────────────────────────

    #[test]
    fn relay_tls_config_not_configured_when_partial() {
        let config = RelayTlsConfig {
            cert_pem: Some(b"cert".to_vec()),
            key_pem: None,
            ca_cert_pem: None,
        };
        assert!(!config.is_configured());
    }

    #[test]
    fn relay_tls_config_configured_when_all_present() {
        let config = RelayTlsConfig {
            cert_pem: Some(b"cert".to_vec()),
            key_pem: Some(b"key".to_vec()),
            ca_cert_pem: Some(b"ca".to_vec()),
        };
        assert!(config.is_configured());
    }

    // ── constant_time_eq ────────────────────────────────────────────────

    #[test]
    fn constant_time_eq_identical() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    // ── select_relay_peer ───────────────────────────────────────────────

    #[test]
    fn select_relay_peer_empty_returns_none() {
        assert!(select_relay_peer(&[]).is_none());
    }

    #[test]
    fn select_relay_peer_single() {
        let endpoints = vec!["https://peer1.example.com".to_string()];
        assert_eq!(
            select_relay_peer(&endpoints),
            Some("https://peer1.example.com")
        );
    }

    #[test]
    fn select_relay_peer_round_robin() {
        let endpoints = vec![
            "https://peer1.example.com".to_string(),
            "https://peer2.example.com".to_string(),
        ];
        let first = select_relay_peer(&endpoints).unwrap().to_string();
        let second = select_relay_peer(&endpoints).unwrap().to_string();
        assert_ne!(first, second);
    }

    // ── authorize_relay_agent ───────────────────────────────────────────

    #[test]
    fn authorize_relay_agent_published() {
        let catalog = vec![
            crate::runtime::ConnectedGatewayPublicationCatalogDescriptor {
                agent_id: Some("agent-1".to_string()),
                publication_state: "published".to_string(),
                publication_key: "pk-1".to_string(),
                active_revision_id: None,
                family_key: "fk-1".to_string(),
                published_hostname: None,
                locality_mode: "any".to_string(),
                serving_fleet_class: "default".to_string(),
            },
        ];
        assert!(authorize_relay_agent(&catalog, "agent-1"));
    }

    #[test]
    fn authorize_relay_agent_not_published() {
        let catalog = vec![
            crate::runtime::ConnectedGatewayPublicationCatalogDescriptor {
                agent_id: Some("agent-1".to_string()),
                publication_state: "draft".to_string(),
                publication_key: "pk-1".to_string(),
                active_revision_id: None,
                family_key: "fk-1".to_string(),
                published_hostname: None,
                locality_mode: "any".to_string(),
                serving_fleet_class: "default".to_string(),
            },
        ];
        assert!(!authorize_relay_agent(&catalog, "agent-1"));
    }

    #[test]
    fn authorize_relay_agent_wrong_agent() {
        let catalog = vec![
            crate::runtime::ConnectedGatewayPublicationCatalogDescriptor {
                agent_id: Some("agent-1".to_string()),
                publication_state: "published".to_string(),
                publication_key: "pk-1".to_string(),
                active_revision_id: None,
                family_key: "fk-1".to_string(),
                published_hostname: None,
                locality_mode: "any".to_string(),
                serving_fleet_class: "default".to_string(),
            },
        ];
        assert!(!authorize_relay_agent(&catalog, "agent-2"));
    }

    // ── sign_envelope and verify_envelope_signature ─────────────────────

    #[test]
    fn sign_and_verify_envelope_roundtrip() {
        let mut envelope = RelayEnvelope {
            relay_ttl: RELAY_TTL_INITIAL,
            agent_id: "agent-1".to_string(),
            publication_key: "pub-1".to_string(),
            original_uri: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body_base64: BASE64_STANDARD.encode(b"test body"),
            hop_records: vec![],
            signature: String::new(),
        };
        envelope.signature = sign_envelope(&envelope, "secret-key");
        assert!(verify_envelope_signature(&envelope, "secret-key"));
        assert!(!verify_envelope_signature(&envelope, "wrong-key"));
    }

    // ── RelayEnvelope serde roundtrip ───────────────────────────────────

    #[test]
    fn relay_envelope_serde_roundtrip() {
        let envelope = RelayEnvelope {
            relay_ttl: 2,
            agent_id: "agent-x".to_string(),
            publication_key: "pub-y".to_string(),
            original_uri: "/v1/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
            body_base64: BASE64_STANDARD.encode(b"payload"),
            hop_records: vec![RelayHopRecord {
                gateway_id: "gw-1".to_string(),
                timestamp: "2025-01-01T00:00:00Z".to_string(),
                reason: "agent_not_local".to_string(),
            }],
            signature: "sig".to_string(),
        };
        let json = serde_json::to_string(&envelope).unwrap();
        let recovered: RelayEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.agent_id, "agent-x");
        assert_eq!(recovered.relay_ttl, 2);
        assert_eq!(recovered.hop_records.len(), 1);
    }

    // ── RELAY_TTL_INITIAL ───────────────────────────────────────────────

    #[test]
    fn relay_ttl_initial_value() {
        assert_eq!(RELAY_TTL_INITIAL, 2);
    }

    // ── RELAY_LATENCY_SLO_P99_MS ────────────────────────────────────────

    #[test]
    fn relay_latency_slo_value() {
        assert_eq!(RELAY_LATENCY_SLO_P99_MS, 250);
    }

    #[tokio::test]
    async fn emit_outbound_relay_audit_records_without_panicking() {
        let sink =
            super::super::server::EventSink::from_config(super::super::server::EventSinkConfig {
                base_url: "http://127.0.0.1:9".to_string(),
                api_token: "relay-audit-token".to_string(),
                gateway_service_token: None,
            })
            .expect("event sink");

        emit_outbound_relay_audit(
            &sink,
            "agent-relay",
            "pub-relay",
            "gw-relay",
            "https://peer.example.com",
            "success",
            42,
            RELAY_TTL_INITIAL,
        );
    }

    // ── RelayHopRecord serde ──────────────────────────────────────────

    #[test]
    fn relay_hop_record_serde_roundtrip_extra() {
        let hop = RelayHopRecord {
            gateway_id: "gw-hop-2".to_string(),
            timestamp: "2025-06-01T00:00:00Z".to_string(),
            reason: "forwarded".to_string(),
        };
        let json = serde_json::to_string(&hop).unwrap();
        let recovered: RelayHopRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.gateway_id, "gw-hop-2");
        assert_eq!(recovered.reason, "forwarded");
    }

    // ── sign_envelope is deterministic ──────────────────────────────

    #[test]
    fn sign_envelope_is_deterministic() {
        let envelope = RelayEnvelope {
            relay_ttl: RELAY_TTL_INITIAL,
            agent_id: "agent-det".to_string(),
            publication_key: "pub-det".to_string(),
            original_uri: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body_base64: BASE64_STANDARD.encode(b"det body"),
            hop_records: vec![],
            signature: String::new(),
        };
        let sig1 = sign_envelope(&envelope, "key");
        let sig2 = sign_envelope(&envelope, "key");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn sign_envelope_normalizes_header_insertion_order() {
        let envelope_a = RelayEnvelope {
            relay_ttl: RELAY_TTL_INITIAL,
            agent_id: "agent-order".to_string(),
            publication_key: "pub-order".to_string(),
            original_uri: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::from([
                ("x-b".to_string(), "2".to_string()),
                ("x-a".to_string(), "1".to_string()),
            ]),
            body_base64: BASE64_STANDARD.encode(b"det body"),
            hop_records: vec![],
            signature: String::new(),
        };
        let envelope_b = RelayEnvelope {
            headers: HashMap::from([
                ("x-a".to_string(), "1".to_string()),
                ("x-b".to_string(), "2".to_string()),
            ]),
            ..envelope_a.clone()
        };

        assert_eq!(
            sign_envelope(&envelope_a, "key"),
            sign_envelope(&envelope_b, "key")
        );
    }

    #[test]
    fn sign_envelope_varies_by_key() {
        let envelope = RelayEnvelope {
            relay_ttl: 1,
            agent_id: "a".to_string(),
            publication_key: "p".to_string(),
            original_uri: "/".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body_base64: String::new(),
            hop_records: vec![],
            signature: String::new(),
        };
        let sig1 = sign_envelope(&envelope, "key-a");
        let sig2 = sign_envelope(&envelope, "key-b");
        assert_ne!(sig1, sig2);
    }
}

#[cfg(test)]
mod coverage_expansion_relay_tests {
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
    use axum::http::HeaderValue;

    // ── HMAC signing and verification ───────────────────────────────────

    #[test]
    fn sign_and_verify_envelope_round_trip() {
        let envelope = RelayEnvelope {
            relay_ttl: 2,
            agent_id: "agent-1".to_string(),
            publication_key: "pub-key".to_string(),
            original_uri: "/v1/chat/completions".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body_base64: BASE64_STANDARD.encode(b"hello"),
            hop_records: vec![RelayHopRecord {
                gateway_id: "gw-1".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                reason: "routing".to_string(),
            }],
            signature: String::new(),
        };
        let mut signed = envelope.clone();
        signed.signature = sign_envelope(&signed, "test-secret");
        assert!(verify_envelope_signature(&signed, "test-secret"));
        assert!(!verify_envelope_signature(&signed, "wrong-secret"));
    }

    #[test]
    fn verify_envelope_empty_signature_fails() {
        let envelope = RelayEnvelope {
            relay_ttl: 1,
            agent_id: "a".to_string(),
            publication_key: "p".to_string(),
            original_uri: "/".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body_base64: String::new(),
            hop_records: vec![],
            signature: String::new(),
        };
        assert!(!verify_envelope_signature(&envelope, "secret"));
    }

    // ── constant_time_eq ────────────────────────────────────────────────

    #[test]
    fn constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer string"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    // ── is_relayed_request ──────────────────────────────────────────────

    #[test]
    fn is_relayed_request_true() {
        let mut headers = HeaderMap::new();
        headers.insert("x-verdictan-relay", HeaderValue::from_static("true"));
        assert!(is_relayed_request(&headers));
    }

    #[test]
    fn is_relayed_request_false_missing() {
        let headers = HeaderMap::new();
        assert!(!is_relayed_request(&headers));
    }

    #[test]
    fn is_relayed_request_false_wrong_value() {
        let mut headers = HeaderMap::new();
        headers.insert("x-verdictan-relay", HeaderValue::from_static("false"));
        assert!(!is_relayed_request(&headers));
    }

    // ── validate_relay_token ────────────────────────────────────────────

    #[test]
    fn validate_relay_token_no_secret() {
        let headers = HeaderMap::new();
        assert!(!validate_relay_token(&headers, None));
    }

    #[test]
    fn validate_relay_token_correct() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-verdictan-relay-token",
            HeaderValue::from_static("my-secret"),
        );
        assert!(validate_relay_token(&headers, Some("my-secret")));
    }

    #[test]
    fn validate_relay_token_incorrect() {
        let mut headers = HeaderMap::new();
        headers.insert("x-verdictan-relay-token", HeaderValue::from_static("wrong"));
        assert!(!validate_relay_token(&headers, Some("my-secret")));
    }

    #[test]
    fn validate_relay_token_missing_header() {
        let headers = HeaderMap::new();
        assert!(!validate_relay_token(&headers, Some("my-secret")));
    }

    // ── verify_relay_mtls ───────────────────────────────────────────────

    #[test]
    fn verify_relay_mtls_not_configured() {
        let headers = HeaderMap::new();
        let config = RelayTlsConfig::default();
        assert!(!verify_relay_mtls(&headers, &config));
    }

    // ── select_relay_peer ───────────────────────────────────────────────

    #[test]
    fn select_relay_peer_empty() {
        assert!(select_relay_peer(&[]).is_none());
    }

    #[test]
    fn select_relay_peer_single() {
        let peers = vec!["https://peer1.example.com".to_string()];
        assert_eq!(select_relay_peer(&peers), Some("https://peer1.example.com"));
    }

    #[test]
    fn select_relay_peer_round_robin() {
        let peers = vec![
            "https://peer1.example.com".to_string(),
            "https://peer2.example.com".to_string(),
        ];
        let first = select_relay_peer(&peers).unwrap().to_string();
        let second = select_relay_peer(&peers).unwrap().to_string();
        assert_ne!(first, second);
    }

    // ── RelayTlsConfig ──────────────────────────────────────────────────

    #[test]
    fn relay_tls_config_not_configured() {
        let config = RelayTlsConfig::default();
        assert!(!config.is_configured());
        assert!(config.build_mtls_client().is_none());
    }

    // ── RelayEnvelope serialization ─────────────────────────────────────

    #[test]
    fn relay_envelope_serde_round_trip() {
        let envelope = RelayEnvelope {
            relay_ttl: 2,
            agent_id: "agent-1".to_string(),
            publication_key: "pub-1".to_string(),
            original_uri: "/v1/chat".to_string(),
            method: "POST".to_string(),
            headers: HashMap::from([("x-custom".to_string(), "value".to_string())]),
            body_base64: BASE64_STANDARD.encode(b"body"),
            hop_records: vec![RelayHopRecord {
                gateway_id: "gw-1".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                reason: "routing".to_string(),
            }],
            signature: "sig".to_string(),
        };
        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: RelayEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.relay_ttl, 2);
        assert_eq!(deserialized.agent_id, "agent-1");
        assert_eq!(deserialized.hop_records.len(), 1);
    }

    // ── build_relay_envelope ────────────────────────────────────────────

    #[test]
    fn build_relay_envelope_constructs_valid_signed() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let body = Bytes::from(b"test body".to_vec());
        let envelope = build_relay_envelope(
            "agent-x",
            "pub-key-1",
            "/v1/completions",
            "POST",
            &headers,
            &body,
            "gw-origin",
            "hmac-secret-123",
        );
        assert_eq!(envelope.agent_id, "agent-x");
        assert_eq!(envelope.publication_key, "pub-key-1");
        assert_eq!(envelope.relay_ttl, RELAY_TTL_INITIAL);
        assert_eq!(envelope.method, "POST");
        assert_eq!(envelope.hop_records.len(), 1);
        assert_eq!(envelope.hop_records[0].gateway_id, "gw-origin");
        assert!(!envelope.signature.is_empty());
        assert!(verify_envelope_signature(&envelope, "hmac-secret-123"));
    }

    // ── relay_method ────────────────────────────────────────────────────

    #[test]
    fn relay_method_maps_known_methods() {
        assert_eq!(relay_method("GET"), reqwest::Method::GET);
        assert_eq!(relay_method("PUT"), reqwest::Method::PUT);
        assert_eq!(relay_method("DELETE"), reqwest::Method::DELETE);
        assert_eq!(relay_method("PATCH"), reqwest::Method::PATCH);
        assert_eq!(relay_method("POST"), reqwest::Method::POST);
    }

    #[test]
    fn relay_method_unknown_defaults_to_post() {
        assert_eq!(relay_method("OPTIONS"), reqwest::Method::POST);
        assert_eq!(relay_method("HEAD"), reqwest::Method::POST);
        assert_eq!(relay_method(""), reqwest::Method::POST);
    }

    // ── relay_target_url ────────────────────────────────────────────────

    #[test]
    fn relay_target_url_appends_path() {
        assert_eq!(
            relay_target_url("https://gw.example.com"),
            "https://gw.example.com/verdictan/relay"
        );
    }

    #[test]
    fn relay_target_url_trims_trailing_slash() {
        assert_eq!(
            relay_target_url("https://gw.example.com/"),
            "https://gw.example.com/verdictan/relay"
        );
    }

    // ── build_upstream_headers ───────────────────────────────────────────

    #[test]
    fn build_upstream_headers_filters_relay_headers() {
        let envelope_headers = HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("x-verdictan-relay".to_string(), "true".to_string()),
            ("x-verdictan-relay-token".to_string(), "secret".to_string()),
            ("host".to_string(), "example.com".to_string()),
            ("x-custom".to_string(), "value".to_string()),
        ]);
        let result = build_upstream_headers(&envelope_headers, None);
        assert!(result.get("content-type").is_some());
        assert!(result.get("x-custom").is_some());
        assert!(result.get("x-verdictan-relay").is_none());
        assert!(result.get("x-verdictan-relay-token").is_none());
        assert!(result.get("host").is_none());
    }

    #[test]
    fn build_upstream_headers_injects_auth() {
        let envelope_headers =
            HashMap::from([("content-type".to_string(), "application/json".to_string())]);
        let auth_name = reqwest::header::HeaderName::from_static("authorization");
        let auth_value =
            reqwest::header::HeaderValue::from_str("Bearer sk-test").expect("valid auth value");
        let result = build_upstream_headers(&envelope_headers, Some(&(auth_name, auth_value)));
        assert_eq!(
            result.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer sk-test")
        );
    }

    #[test]
    fn build_upstream_headers_empty_input() {
        let envelope_headers = HashMap::new();
        let result = build_upstream_headers(&envelope_headers, None);
        assert!(result.is_empty());
    }

    // ── error_response ──────────────────────────────────────────────────

    #[test]
    fn error_response_produces_json_body() {
        let resp = error_response(StatusCode::BAD_GATEWAY, "relay_peer_unavailable");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    // ── RelayTlsConfig ──────────────────────────────────────────────────

    #[test]
    fn relay_tls_config_is_configured_requires_all_three() {
        let partial = RelayTlsConfig {
            cert_pem: Some(b"cert".to_vec()),
            key_pem: Some(b"key".to_vec()),
            ca_cert_pem: None,
        };
        assert!(!partial.is_configured());

        let full = RelayTlsConfig {
            cert_pem: Some(b"cert".to_vec()),
            key_pem: Some(b"key".to_vec()),
            ca_cert_pem: Some(b"ca".to_vec()),
        };
        assert!(full.is_configured());
    }

    // ── verify_relay_mtls ───────────────────────────────────────────────

    #[test]
    fn verify_relay_mtls_requires_configured_and_header() {
        let config = RelayTlsConfig {
            cert_pem: Some(b"cert".to_vec()),
            key_pem: Some(b"key".to_vec()),
            ca_cert_pem: Some(b"ca".to_vec()),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-verdictan-relay-client-cert-verified",
            HeaderValue::from_static("true"),
        );
        assert!(verify_relay_mtls(&headers, &config));
    }

    #[test]
    fn verify_relay_mtls_rejects_false_header() {
        let config = RelayTlsConfig {
            cert_pem: Some(b"cert".to_vec()),
            key_pem: Some(b"key".to_vec()),
            ca_cert_pem: Some(b"ca".to_vec()),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-verdictan-relay-client-cert-verified",
            HeaderValue::from_static("false"),
        );
        assert!(!verify_relay_mtls(&headers, &config));
    }

    #[test]
    fn verify_relay_mtls_rejects_missing_header() {
        let config = RelayTlsConfig {
            cert_pem: Some(b"cert".to_vec()),
            key_pem: Some(b"key".to_vec()),
            ca_cert_pem: Some(b"ca".to_vec()),
        };
        let headers = HeaderMap::new();
        assert!(!verify_relay_mtls(&headers, &config));
    }

    // ── RELAY_TTL_INITIAL and RELAY_LATENCY_SLO_P99_MS constants ────────

    #[test]
    fn relay_constants_are_sensible() {
        assert!(RELAY_TTL_INITIAL > 0);
        assert!(RELAY_LATENCY_SLO_P99_MS > 0);
    }
}
