// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

#![allow(dead_code, clippy::result_large_err, clippy::too_many_arguments)]
pub use axum::http::header;
pub use axum::{body::Body, Router};
use axum::{
    extract::{ws::WebSocketUpgrade, ConnectInfo, Query, State},
    http::{HeaderValue, Request, Response},
    response::IntoResponse,
    routing::{get, post},
};
pub use axum::{
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use bigdecimal::{BigDecimal, ToPrimitive};

pub use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::{stream, StreamExt};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{LazyLock, RwLock};
use std::time::Instant;
pub use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio_stream::wrappers::ReceiverStream;
use tracing::Instrument;

use crate::error::CliError;

macro_rules! static_regex {
    ($pattern:expr) => {{
        static RE: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| {
            #[allow(clippy::expect_used)]
            regex_lite::Regex::new($pattern).expect("static regex pattern")
        })
    }};
}

/// Identifies how the pricing for a spend log entry was resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingSource {
    Upstream,
    ConfigDeclared,
    Catalog,
}

fn default_usage_category_cli() -> String {
    "gateway_llm".to_string()
}

/// Derive the usage category from request context using the priority order:
/// 1. metadata.source == "export" → exports
/// 2. metadata.source == "policy_processing" → policy_processing
/// 3. workflow_id present → workflows
/// 4. agent_id present → agents
/// 5. Everything else → gateway_llm
fn derive_usage_category(
    metadata: &serde_json::Value,
    workflow_id: Option<&str>,
    agent_id: Option<&str>,
) -> &'static str {
    if let Some(source) = metadata
        .as_object()
        .and_then(|obj| obj.get("source"))
        .and_then(serde_json::Value::as_str)
    {
        match source {
            "export" => return "exports",
            "policy_processing" => return "policy_processing",
            _ => {}
        }
    }
    if workflow_id.map(|s| !s.is_empty()).unwrap_or(false) {
        return "workflows";
    }
    if let Some(aid) = agent_id {
        if !aid.is_empty() {
            return "agents";
        }
    }
    "gateway_llm"
}

fn request_agent_id_header_value(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-verdictan-agent-id")
        .or_else(|| headers.get("x-agent-id"))
        .and_then(|value| value.to_str().ok())
}

fn normalize_request_agent_id(header_value: Option<&str>) -> Result<Option<String>, &'static str> {
    let Some(agent_id) = header_value
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };

    if agent_id.len() > 128 {
        return Err("x-verdictan-agent-id must be at most 128 characters");
    }

    if !agent_id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    {
        return Err("x-verdictan-agent-id must contain only ASCII letters, digits, or hyphens");
    }

    Ok(Some(agent_id.to_string()))
}

use super::{
    bounded_ttl_cache::BoundedTtlCache,
    enforcement::{self, ChatMessage},
    graph_populator::{self, GraphUpsertPayload, ToolResultGraphInput},
    providers::ProviderPricing,
    request_id,
};
pub use super::{
    declarative_config::LoadedDeclarativeConfig,
    enforcement::{DecisionEnvelope, Verdict},
    fail_mode::FailMode,
};

#[derive(Clone, Debug)]
pub struct UpstreamAuthConfig {
    pub header_name: String,
    pub header_value: String,
}

#[path = "event_delivery.rs"]
pub mod event_delivery;
#[path = "identity_context.rs"]
mod identity_context;
#[path = "readiness.rs"]
mod readiness;
#[path = "request_pipeline/mod.rs"]
mod request_pipeline;

pub use event_delivery::{
    drain_forwarding_tasks_on_shutdown, spawn_wal_delivery_worker, EventSink, EventSinkConfig,
    GatewayHandle,
};
// Identity-context seams live in `identity_context.rs`.
// Adversarial integration tests consume the reserved-header and
// team-binding helpers through these public re-exports.
use identity_context::{
    inject_identity_headers_from_finops, policy_input_headers, require_connected_public_auth,
    resolve_request_finops_context,
};
pub use identity_context::{is_reserved_identity_header, RequestFinopsContext};
#[cfg(test)]
use readiness::first_managed_public_endpoint_health_issue;
use readiness::{
    initialize_distributed_state_and_rollout, proxy_health, proxy_liveness, proxy_readiness,
    DistributedReadinessBootstrap,
};
// Family handlers and shared orchestration helpers.
#[allow(unused_imports)]
use request_pipeline::*;
// Re-export helpers previously defined as `pub` in this module for crate tests and
// gateway siblings (characterization suites import `gateway::server::*`).
pub use request_pipeline::{
    decision_event_json, enforce_token_rate_limit, join_upstream, redact_event_message_bodies,
    rewrite_upstream_path, verdictan_headers,
};

fn persist_admitted_decision_before_dispatch(
    state: &ActiveGatewayStateView<'_>,
    request_id: &str,
    traceparent: &str,
    decision: &DecisionEnvelope,
    prompt_hash: &str,
    request_path: &str,
) -> Result<(), Response<Body>> {
    let Some(sink) = state.event_sink.as_ref() else {
        return Ok(());
    };

    let mut event = decision_event_json(
        &state.config_version,
        request_id,
        decision,
        false,
        decision
            .results
            .iter()
            .any(|result| result.verdict == Verdict::Redact),
        prompt_hash.to_string(),
        None,
        state.registered_agent_id(),
        state.request_finops.as_ref(),
        state.session_id.as_deref(),
    );
    if let Some(details) = event
        .get_mut("details")
        .and_then(serde_json::Value::as_object_mut)
    {
        details.insert(
            "durability_stage".to_string(),
            serde_json::Value::String("pre_dispatch_fsync".to_string()),
        );
        details.insert(
            "request_path".to_string(),
            serde_json::Value::String(request_path.to_string()),
        );
    }

    sink.persist_admitted_decision(request_id, event)
        .map(|_| ())
        .map_err(|error| {
            tracing::error!(
                request_id = %request_id,
                request_path = %request_path,
                error = %error,
                "provider dispatch rejected because decision WAL fsync failed"
            );
            build_request_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                traceparent,
                "Durable decision evidence could not be persisted",
                "service_unavailable",
                "audit.wal_unavailable",
            )
        })
}

const RUNTIME_ROUTING_CACHE_TTL: Duration = Duration::from_secs(30);
const BOUND_GATEWAY_AGENT_CACHE_TTL: Duration = Duration::from_secs(30);
const ACCESS_PREFLIGHT_CACHE_TTL: Duration = Duration::from_secs(30);
const ACCESS_PREFLIGHT_CACHE_TTL_MIN: Duration = Duration::from_secs(15);
const ACCESS_PREFLIGHT_CACHE_TTL_MAX: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
enum RequestStageTiming {
    RuntimeRoutingLookup,
    BoundGatewayAgentLookup,
    TokenValidation,
    AccessPreflight,
    UpstreamSend,
}

impl RequestStageTiming {
    const COUNT: usize = 5;
    const ALL: [Self; Self::COUNT] = [
        Self::RuntimeRoutingLookup,
        Self::BoundGatewayAgentLookup,
        Self::TokenValidation,
        Self::AccessPreflight,
        Self::UpstreamSend,
    ];

    fn index(self) -> usize {
        match self {
            Self::RuntimeRoutingLookup => 0,
            Self::BoundGatewayAgentLookup => 1,
            Self::TokenValidation => 2,
            Self::AccessPreflight => 3,
            Self::UpstreamSend => 4,
        }
    }

    fn server_timing_name(self) -> &'static str {
        match self {
            Self::RuntimeRoutingLookup => "runtime-routing",
            Self::BoundGatewayAgentLookup => "bound-agent",
            Self::TokenValidation => "token-validation",
            Self::AccessPreflight => "access-preflight",
            Self::UpstreamSend => "upstream-send",
        }
    }
}

#[derive(Default)]
struct RequestStageTimings {
    totals_micros: std::sync::Mutex<[u64; RequestStageTiming::COUNT]>,
}

impl RequestStageTimings {
    fn record(&self, stage: RequestStageTiming, elapsed: Duration) {
        let elapsed_micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        let mut guard = self
            .totals_micros
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        guard[stage.index()] = guard[stage.index()].saturating_add(elapsed_micros);
    }

    fn server_timing_value(&self) -> Option<String> {
        let totals = *self
            .totals_micros
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let metrics: Vec<String> = RequestStageTiming::ALL
            .into_iter()
            .filter_map(|stage| {
                let micros = totals[stage.index()];
                (micros > 0).then(|| {
                    format!(
                        "{};dur={:.1}",
                        stage.server_timing_name(),
                        micros as f64 / 1000.0
                    )
                })
            })
            .collect();
        (!metrics.is_empty()).then(|| metrics.join(", "))
    }
}

tokio::task_local! {
    static REQUEST_STAGE_TIMINGS: Arc<RequestStageTimings>;
}

fn record_request_stage_timing(
    stage: RequestStageTiming,
    elapsed: Duration,
    cache_hit: Option<bool>,
) {
    let _ = REQUEST_STAGE_TIMINGS.try_with(|collector| collector.record(stage, elapsed));
    tracing::trace!(
        stage = stage.server_timing_name(),
        elapsed_ms = elapsed.as_secs_f64() * 1000.0,
        cache_hit = cache_hit,
        "gateway request stage completed"
    );
}

fn maybe_insert_server_timing_header(headers: &mut HeaderMap) {
    let header_value = REQUEST_STAGE_TIMINGS
        .try_with(|collector| collector.server_timing_value())
        .ok()
        .flatten();
    let Some(header_value) = header_value else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(&header_value) {
        headers.insert(header::HeaderName::from_static("server-timing"), value);
    }
}

fn apply_request_stage_headers(
    mut response: Response<Body>,
    collector: &RequestStageTimings,
) -> Response<Body> {
    if let Some(header_value) = collector.server_timing_value() {
        if let Ok(value) = HeaderValue::from_str(&header_value) {
            response
                .headers_mut()
                .insert(header::HeaderName::from_static("server-timing"), value);
        }
    }
    response
}

fn shared_insecure_gateway_http_client() -> reqwest::Client {
    static SHARED_INSECURE_GATEWAY_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
        #[allow(clippy::expect_used)]
        // BOOT: the shared insecure client uses only constant builder settings.
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(90))
            .user_agent(concat!("verdictan-gateway/", env!("CARGO_PKG_VERSION")))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("shared insecure gateway client")
    });
    SHARED_INSECURE_GATEWAY_HTTP_CLIENT.clone()
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SpendLogPayload {
    pub provider: String,
    pub model: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub cached_input_tokens: i64,
    pub prompt_cost: f64,
    pub completion_cost: f64,
    pub cached_input_cost: f64,
    pub total_cost: f64,
    pub currency: String,
    pub key_id: Option<String>,
    pub user_id: Option<String>,
    pub team_id: Option<String>,
    /// Canonical provider target ID from the active config.
    pub provider_target_id: Option<String>,
    /// Canonical model ID resolved from the target config.
    pub model_id: Option<String>,
    /// The model the client originally requested.
    pub requested_model: Option<String>,
    /// The provider the client pinned via X-Verdictan-Provider.
    pub requested_provider: Option<String>,
    pub pricing_source: Option<PricingSource>,
    pub pricing_snapshot: Option<serde_json::Value>,
    pub metadata: serde_json::Value,
    /// The gateway's registered ID, forwarded for configuration linkage.
    pub gateway_id: Option<Arc<str>>,
    /// The API-assigned configuration UUID associated with this gateway, if known.
    pub configuration_id: Option<Arc<str>>,
    /// The API-assigned configuration version UUID active at request time, if known.
    pub configuration_version_id: Option<Arc<str>>,
    /// The resolved agent UUID associated with this governed request, if known.
    pub agent_id: Option<String>,
    // ── Spend attribution ────────────────────────────────────────────────────
    /// Gateway execution session ID when this request was initiated inside a gateway execution session.
    pub gateway_execution_session_id: Option<String>,
    /// Execution surface: "gateway" or "gateway_execution_session".
    pub execution_surface: Option<String>,
    // ── Usage category tagging (Phase 2 / Lane B) ──────────────────────────
    /// Derived usage category for cost attribution.
    #[serde(default = "default_usage_category_cli")]
    pub usage_category: String,
    /// Size of the serialized request body sent upstream (bytes).
    #[serde(default)]
    pub request_bytes: i64,
    /// Size of the raw response body from upstream (bytes).
    #[serde(default)]
    pub response_bytes: i64,
    /// Number of policy evaluation units consumed (input + output phase count).
    #[serde(default)]
    pub processing_units: i32,
    /// Conversation UUID for per-conversation cost attribution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    // ── Catalog-backed pricing enrichment ────────────────────────────────────
    /// Exact catalog-resolved input token price, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_input_price: Option<String>,
    /// Exact catalog-resolved output token price, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_output_price: Option<String>,
    /// Canonical model ID from the catalog.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_model_id: Option<String>,
    /// Canonical provider ID from the catalog.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_provider_id: Option<String>,
    /// How the final spend pricing was resolved: "catalog", "config_declared",
    /// "upstream", or "default_fallback".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_pricing_source: Option<String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SpendUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub cached_input_tokens: u64,
    pub prompt_cost: Option<f64>,
    pub completion_cost: Option<f64>,
    pub total_cost: Option<f64>,
}

#[derive(Clone, Debug, Default)]
struct ResolvedSpendPricing {
    pricing: Option<ProviderPricing>,
    source: Option<PricingSource>,
    snapshot: Option<serde_json::Value>,
    canonical_model_id: Option<String>,
    catalog_input_price: Option<String>,
    catalog_output_price: Option<String>,
    catalog_model_id: Option<String>,
    catalog_provider_id: Option<String>,
    catalog_pricing_source: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct UsagePricingContext {
    pub provider: String,
    pub model: String,
    pub estimated_cost_usd: Option<f64>,
}

/// Credential origin proven by connected admission. Verdictan resolves upstream
/// provider access from customer-owned sources only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectedCredentialSource {
    Byok,
}

impl ConnectedCredentialSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Byok => "byok",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ConnectedAccessRequestStatus {
    admission_credential_source: Option<ConnectedCredentialSource>,
    dispatch_precluded: bool,
}

#[derive(Clone, Debug, Default)]
struct ConnectedAccessDispatchContext {
    gateway_usage_authorization_id: Option<String>,
    frozen_usage_attribution: super::usage_authorization::UsageExecutionAttribution,
    frozen_spend_log_context: OwnedSpendLogContext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectedPostDispatchUsageSource {
    UpstreamReported,
    PromptOnlyFallback,
    StreamingEstimate,
}

impl ConnectedPostDispatchUsageSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::UpstreamReported => "provider_reported",
            Self::PromptOnlyFallback => "prompt_only_fallback",
            Self::StreamingEstimate => "streaming_estimate",
        }
    }

    fn is_estimated(self) -> bool {
        !matches!(self, Self::UpstreamReported)
    }
}

#[derive(Clone, Debug)]
struct ConnectedPostDispatchUsage {
    usage: SpendUsage,
    source: ConnectedPostDispatchUsageSource,
    pipeline_metadata: Option<serde_json::Value>,
    response_model_hint: Option<String>,
    response_bytes: i64,
}

#[derive(Clone, Debug)]
struct ConnectedAccessPreflightOutcome {
    primary: super::access_preflight::AccessPreflightResponse,
    /// Snapshot of org authz version at cache-insertion time.
    org_authz_version: Option<i64>,
    /// Local budget enforcement: tracks remaining budget across concurrent
    /// requests within the cache TTL window. Decremented optimistically on
    /// each request; if exhausted, the cache entry is invalidated to force a
    /// fresh server-side check.
    local_budget_tracker: Option<Arc<LocalBudgetTracker>>,
}

/// Thread-safe local budget tracker for the preflight cache window.
/// Uses a Mutex to support atomic read-decrement-check operations.
#[derive(Debug)]
struct LocalBudgetTracker {
    remaining: std::sync::Mutex<f64>,
    cost_per_1k_input_tokens: Option<f64>,
    cost_per_1k_output_tokens: Option<f64>,
    budget_limit: Option<f64>,
    budget_period: Option<String>,
}

impl LocalBudgetTracker {
    fn new(
        remaining_budget: f64,
        cost_per_1k_input: Option<f64>,
        cost_per_1k_output: Option<f64>,
        budget_limit: Option<f64>,
        budget_period: Option<String>,
    ) -> Self {
        Self {
            remaining: std::sync::Mutex::new(remaining_budget),
            cost_per_1k_input_tokens: cost_per_1k_input,
            cost_per_1k_output_tokens: cost_per_1k_output,
            budget_limit,
            budget_period,
        }
    }

    /// Estimate cost and attempt to reserve budget. Returns Ok(estimated_cost)
    /// if budget was available, or Err if budget is exhausted.
    fn try_reserve(&self, input_tokens: u64, max_output_tokens: u64) -> Result<f64, ()> {
        let input_cost = self
            .cost_per_1k_input_tokens
            .map(|c| c * input_tokens as f64 / 1000.0)
            .unwrap_or(0.0);
        let output_cost = self
            .cost_per_1k_output_tokens
            .map(|c| c * max_output_tokens as f64 / 1000.0)
            .unwrap_or(0.0);
        let estimated_cost = input_cost + output_cost;

        if estimated_cost <= 0.0 {
            return Ok(0.0);
        }

        let mut remaining = self.remaining.lock().unwrap_or_else(|e| e.into_inner());
        if *remaining < estimated_cost {
            return Err(());
        }
        *remaining -= estimated_cost;
        Ok(estimated_cost)
    }

    /// Credit back unused budget when actual usage is less than the
    /// conservative estimate.
    fn credit_back(&self, amount: f64) {
        if amount <= 0.0 {
            return;
        }
        let mut remaining = self.remaining.lock().unwrap_or_else(|e| e.into_inner());
        *remaining += amount;
    }

    /// Returns true if pricing data is available for local enforcement.
    fn has_pricing(&self) -> bool {
        self.cost_per_1k_input_tokens.is_some() || self.cost_per_1k_output_tokens.is_some()
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct PreflightCacheKey {
    org_id: String,
    provider: String,
    model: String,
}

#[derive(Clone, Debug)]
pub struct SpendLogContext<'a> {
    pub provider_registry: Option<&'a super::providers::ProviderRegistry>,
    pub catalog_snapshot: super::provider_catalog::CatalogSnapshot,
    pub upstream_base: &'a str,
    pub gateway_id: Option<&'a Arc<str>>,
    pub connected_mode: bool,
    pub region_key: Option<&'a str>,
    pub managed_public_endpoint_host: Option<&'a str>,
    pub requested_region_group: Option<&'a str>,
    pub current_publication: Option<&'a crate::runtime::ConnectedGatewayPublicationDescriptor>,
    pub configuration_id: Option<&'a Arc<str>>,
    pub configuration_version_id: Option<&'a Arc<str>>,
    pub current_agent_id: Option<&'a String>,
    pub request_finops: Option<&'a RequestFinopsContext>,
    /// Number of policies in the active chain (input + output = 2× this value).
    pub policy_count: usize,
    /// Conversation UUID for per-conversation cost attribution.
    pub conversation_id: Option<&'a str>,
}

#[derive(Clone, Debug, Default)]
struct OwnedSpendLogContext {
    provider_registry: Option<super::providers::ProviderRegistry>,
    catalog_snapshot: super::provider_catalog::CatalogSnapshot,
    upstream_base: String,
    gateway_id: Option<Arc<str>>,
    connected_mode: bool,
    region_key: Option<String>,
    managed_public_endpoint_host: Option<String>,
    requested_region_group: Option<String>,
    current_publication: Option<crate::runtime::ConnectedGatewayPublicationDescriptor>,
    configuration_id: Option<Arc<str>>,
    configuration_version_id: Option<Arc<str>>,
    current_agent_id: Option<String>,
    request_finops: Option<RequestFinopsContext>,
    policy_count: usize,
    conversation_id: Option<String>,
}

impl OwnedSpendLogContext {
    pub fn from_state(state: &ActiveGatewayStateView<'_>) -> Self {
        Self {
            provider_registry: state.provider_registry.clone(),
            catalog_snapshot: state.catalog_snapshot.clone(),
            upstream_base: state.upstream_base.to_string(),
            gateway_id: state.gateway_id.clone(),
            connected_mode: state.connected_mode,
            region_key: state.region_key.clone(),
            managed_public_endpoint_host: state.managed_public_endpoint_host.clone(),
            requested_region_group: state.requested_region_group.clone(),
            current_publication: state.current_publication.clone(),
            configuration_id: state.configuration_id.clone(),
            configuration_version_id: state.configuration_version_id.clone(),
            current_agent_id: state.current_agent_id.clone(),
            request_finops: state.request_finops.clone(),
            policy_count: state.policy_chain.len(),
            conversation_id: None,
        }
    }

    fn with_conversation_id(mut self, conversation_id: Option<&str>) -> Self {
        self.conversation_id = conversation_id.map(ToOwned::to_owned);
        self
    }

    fn as_ref(&self) -> SpendLogContext<'_> {
        SpendLogContext {
            provider_registry: self.provider_registry.as_ref(),
            catalog_snapshot: self.catalog_snapshot.clone(),
            upstream_base: &self.upstream_base,
            gateway_id: self.gateway_id.as_ref(),
            connected_mode: self.connected_mode,
            region_key: self.region_key.as_deref(),
            managed_public_endpoint_host: self.managed_public_endpoint_host.as_deref(),
            requested_region_group: self.requested_region_group.as_deref(),
            current_publication: self.current_publication.as_ref(),
            configuration_id: self.configuration_id.as_ref(),
            configuration_version_id: self.configuration_version_id.as_ref(),
            current_agent_id: self.current_agent_id.as_ref(),
            request_finops: self.request_finops.as_ref(),
            policy_count: self.policy_count,
            conversation_id: self.conversation_id.as_deref(),
        }
    }
}

pub fn spend_log_context<'a>(state: &'a ActiveGatewayStateView<'a>) -> SpendLogContext<'a> {
    SpendLogContext {
        provider_registry: state.provider_registry.as_ref(),
        catalog_snapshot: state.catalog_snapshot.clone(),
        upstream_base: state.upstream_base,
        gateway_id: state.gateway_id.as_ref(),
        connected_mode: state.connected_mode,
        region_key: state.region_key.as_deref(),
        managed_public_endpoint_host: state.managed_public_endpoint_host.as_deref(),
        conversation_id: None,
        requested_region_group: state.requested_region_group.as_deref(),
        current_publication: state.current_publication.as_ref(),
        configuration_id: state.configuration_id.as_ref(),
        configuration_version_id: state.configuration_version_id.as_ref(),
        current_agent_id: state.current_agent_id.as_ref(),
        request_finops: state.request_finops.as_ref(),
        policy_count: state.policy_chain.len(),
    }
}

fn canonical_runtime_execution_surface(
    execution_surface: Option<&str>,
    gateway_execution_session_id: Option<&str>,
) -> &'static str {
    match execution_surface
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
    {
        Some("runner_session") | Some("gateway_execution_session") => "runner_session",
        Some("interactive_chat") | Some("gateway") => "interactive_chat",
        Some(_) | None if gateway_execution_session_id.is_some() => "runner_session",
        _ => "interactive_chat",
    }
}

fn usage_execution_attribution(
    state: &ActiveGatewayStateView<'_>,
    request_id: &str,
) -> super::usage_authorization::UsageExecutionAttribution {
    let gateway_execution_session_id = state
        .request_finops
        .as_ref()
        .and_then(|context| context.gateway_execution_session_id.clone());
    let current_publication = state.current_publication.as_ref();

    super::usage_authorization::UsageExecutionAttribution {
        request_id: Some(request_id::control_plane_request_id(request_id)),
        execution_surface: Some(
            canonical_runtime_execution_surface(
                state
                    .request_finops
                    .as_ref()
                    .and_then(|context| context.execution_surface.as_deref()),
                gateway_execution_session_id.as_deref(),
            )
            .to_string(),
        ),
        gateway_execution_session_id,
        region_key: state.region_key.clone(),
        publication_key: current_publication.map(|publication| publication.publication_key.clone()),
        active_revision_id: current_publication
            .and_then(|publication| publication.active_revision_id.clone()),
        requested_region_group: state.requested_region_group.clone(),
        selected_region_group: current_publication
            .and_then(|publication| publication.primary_region_group_key.clone()),
        conversation_id: None,
    }
}

fn usage_execution_attribution_with_conversation(
    state: &ActiveGatewayStateView<'_>,
    request_id: &str,
    conversation_id: Option<&str>,
) -> super::usage_authorization::UsageExecutionAttribution {
    let mut attribution = usage_execution_attribution(state, request_id);
    attribution.conversation_id = conversation_id.map(ToOwned::to_owned);
    attribution
}

/// Effective IP allow-list CIDRs from the key\u2019s org security settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheTier {
    PrivateEdge,
    OrgShared,
}

impl CacheTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateEdge => "private_edge_cache",
            Self::OrgShared => "org_shared_cache",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheReplayOutcome {
    ExactHit,
    SemanticCandidate,
    SemanticRevalidated,
    SemanticReplayed,
    StaleMiss,
    DeniedReplay,
}

impl CacheReplayOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExactHit => "exact_hit",
            Self::SemanticCandidate => "semantic_candidate",
            Self::SemanticRevalidated => "semantic_revalidated",
            Self::SemanticReplayed => "semantic_replayed",
            Self::StaleMiss => "stale_miss",
            Self::DeniedReplay => "denied_replay",
        }
    }

    fn hit_type(self) -> &'static str {
        match self {
            Self::ExactHit => "exact",
            Self::SemanticCandidate => "semantic_candidate",
            Self::SemanticRevalidated => "semantic_revalidated",
            Self::SemanticReplayed => "semantic_replayed",
            Self::StaleMiss | Self::DeniedReplay => "exact",
        }
    }
}

#[derive(Clone, Debug)]
struct CacheReplayMetadata {
    outcome: CacheReplayOutcome,
    cache_tier: CacheTier,
    cache_key_digest: Option<String>,
    selected_fabric_artifact_ids: Vec<String>,
    selected_fabric_source_digests: Vec<String>,
}

impl CacheReplayMetadata {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "outcome": self.outcome.as_str(),
            "cache_tier": self.cache_tier.as_str(),
            "cache_key_digest": self.cache_key_digest,
            "selected_fabric_artifact_ids": self.selected_fabric_artifact_ids,
            "selected_fabric_source_digests": self.selected_fabric_source_digests,
        })
    }
}

struct CacheLookupResult {
    response: super::cache::BufferedUpstreamResponse,
    outcome: CacheReplayOutcome,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct GatewayBudgetRecord {
    pub max_budget: f64,
    pub current_spend: f64,
}

#[derive(Debug, serde::Deserialize)]
struct GatewayBudgetListResponse {
    budgets: Vec<GatewayBudgetRecord>,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct TokenRecord {
    id: String,
    #[serde(default)]
    gateway_id: Option<String>,
    provider: Option<String>,
    #[serde(default, deserialize_with = "deserialize_token_model_filters")]
    model_filter: Vec<String>,
    team_id: Option<String>,
    user_id: Option<String>,
    max_budget: Option<f64>,
    current_spend: f64,
    #[serde(default)]
    key_class: Option<String>,
    #[serde(default)]
    resource_id: Option<String>,
    #[serde(default)]
    resource_vrn: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    metadata: serde_json::Value,
    #[serde(default)]
    rate_limit_rpm: Option<i32>,
}

fn validated_key_gateway_binding(metadata: &serde_json::Value) -> Option<&str> {
    metadata
        .get("personal_gateway_id")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            metadata
                .get("gateway_id")
                .and_then(serde_json::Value::as_str)
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn validated_key_agent_binding(metadata: &serde_json::Value) -> Option<&str> {
    metadata
        .get("agent_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

#[derive(Clone, Debug, serde::Deserialize)]
struct TokenHistoryDefaults {
    capture_mode: String,
    previous_sessions_max: i32,
    previous_allowed_requests_max: i32,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct GatewayIpRestrictions {
    cidrs: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct GatewayControlsPayload {
    #[serde(default)]
    fail_closed: bool,
    #[serde(default)]
    allowed_providers: Vec<String>,
    #[serde(default)]
    allowed_models: Vec<String>,
    #[serde(default)]
    allowed_gateways: Vec<String>,
    #[serde(default)]
    disabled_providers: Vec<String>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
struct TokenDepletionState {
    #[serde(default)]
    max_budget: Option<f64>,
    #[serde(default)]
    current_spend: Option<f64>,
    #[serde(default)]
    remaining_budget: Option<f64>,
    #[serde(default)]
    max_requests: Option<u64>,
    #[serde(default)]
    current_requests: Option<u64>,
    #[serde(default)]
    remaining_requests: Option<u64>,
}

#[derive(Debug, serde::Deserialize, Clone)]
pub struct TokenValidationResponse {
    valid: bool,
    #[serde(default)]
    authenticated_identity: Option<crate::gateway::identity::AuthenticatedIdentityClaims>,
    reason: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    token_id: Option<String>,
    org_id: Option<String>,
    key_id: Option<String>,
    #[serde(default)]
    key_class: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    team_id: Option<String>,
    user_id: Option<String>,
    agent_id: Option<String>,
    agent_gateway_group_id: Option<String>,
    #[serde(default)]
    attached_policy_ids: Vec<String>,
    #[serde(default)]
    depletion: Option<TokenDepletionState>,
    ip_restrictions: Option<GatewayIpRestrictions>,
    #[serde(default)]
    entitlements: Vec<String>,
    history: Option<TokenHistoryDefaults>,
    #[serde(default)]
    created_by: Option<String>,
    key: Option<TokenRecord>,
    #[serde(default)]
    gateway_controls: Option<GatewayControlsPayload>,
    #[serde(default)]
    org_authz_version: Option<i64>,
}

#[derive(Debug)]
pub(crate) enum TokenValidationError {
    Request(reqwest::Error),
    Unauthorized { body: String },
    Forbidden { body: String },
    UnexpectedStatus { status: StatusCode, body: String },
}

impl std::fmt::Display for TokenValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(error) => write!(f, "{error}"),
            Self::Unauthorized { body } => {
                write!(f, "API token validation unauthorized: {body}")
            }
            Self::Forbidden { body } => {
                write!(f, "API token validation forbidden: {body}")
            }
            Self::UnexpectedStatus { status, body } => {
                write!(
                    f,
                    "API token validation failed: status={status} body={body}"
                )
            }
        }
    }
}

impl std::error::Error for TokenValidationError {}

#[derive(Default)]
pub struct GatewayRuntimeMetrics {
    pub token_validation_cache_hits: std::sync::atomic::AtomicU64,
    pub token_validation_cache_misses: std::sync::atomic::AtomicU64,
    pub runtime_controls_cache_hits: std::sync::atomic::AtomicU64,
    pub runtime_controls_cache_misses: std::sync::atomic::AtomicU64,
    pub manifest_fetches: std::sync::atomic::AtomicU64,
    pub yaml_fetches: std::sync::atomic::AtomicU64,
    pub runtime_build_failures: std::sync::atomic::AtomicU64,
}

impl GatewayRuntimeMetrics {
    fn record_token_validation_cache_hit(&self) {
        self.token_validation_cache_hits
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_token_validation_cache_miss(&self) {
        self.token_validation_cache_misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_runtime_controls_cache_hit(&self) {
        self.runtime_controls_cache_hits
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_runtime_controls_cache_miss(&self) {
        self.runtime_controls_cache_misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_manifest_fetch(&self) {
        self.manifest_fetches
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_yaml_fetch(&self) {
        self.yaml_fetches
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_runtime_build_failure(&self) {
        self.runtime_build_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn as_json(&self) -> serde_json::Value {
        serde_json::json!({
            "token_validation_cache_hits": self.token_validation_cache_hits.load(std::sync::atomic::Ordering::Relaxed),
            "token_validation_cache_misses": self.token_validation_cache_misses.load(std::sync::atomic::Ordering::Relaxed),
            "runtime_controls_cache_hits": self.runtime_controls_cache_hits.load(std::sync::atomic::Ordering::Relaxed),
            "runtime_controls_cache_misses": self.runtime_controls_cache_misses.load(std::sync::atomic::Ordering::Relaxed),
            "manifest_fetches": self.manifest_fetches.load(std::sync::atomic::Ordering::Relaxed),
            "yaml_fetches": self.yaml_fetches.load(std::sync::atomic::Ordering::Relaxed),
            "runtime_build_failures": self.runtime_build_failures.load(std::sync::atomic::Ordering::Relaxed),
        })
    }
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct GatewayProviderBudgetCheckResponse {
    pub allowed: bool,
    pub remaining_budget: Option<f64>,
}

#[derive(Debug)]
pub struct BudgetFilterRejection {
    pub status: StatusCode,
    pub error_type: &'static str,
    pub code: &'static str,
    pub message: String,
}

fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
        .map(ToOwned::to_owned)
}

fn deserialize_token_model_filters<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum StringOrMany {
        One(String),
        Many(Vec<String>),
    }

    let value = <Option<StringOrMany> as serde::Deserialize>::deserialize(deserializer)?;
    Ok(match value {
        Some(StringOrMany::One(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Vec::new()
            } else {
                vec![trimmed.to_string()]
            }
        }
        Some(StringOrMany::Many(values)) => values
            .into_iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect(),
        None => Vec::new(),
    })
}

fn normalize_text_scope_values(values: &[String]) -> Vec<String> {
    let mut normalized = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn normalize_provider_scope_values(values: &[String]) -> Vec<String> {
    let mut normalized = values
        .iter()
        .map(|value| crate::gateway::provider_catalog::normalized_provider_alias(value))
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct EffectiveTokenScopes {
    allowed_providers: Vec<String>,
    allowed_models: Vec<String>,
    allowed_gateways: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenScopeMergeError {
    PolicyResolutionFailed,
    GovernedScopeConflict,
}

fn intersect_scope_values(
    binding_values: &[String],
    policy_values: &[String],
    normalizer: impl Fn(&[String]) -> Vec<String>,
) -> Vec<String> {
    let binding_values = normalizer(binding_values);
    let policy_values = normalizer(policy_values);
    match (binding_values.is_empty(), policy_values.is_empty()) {
        (true, true) => Vec::new(),
        (false, true) => binding_values,
        (true, false) => policy_values,
        (false, false) => binding_values
            .into_iter()
            .filter(|value| policy_values.contains(value))
            .collect(),
    }
}

fn merge_scope_values(
    binding_values: &[String],
    policy_values: &[String],
    normalizer: impl Fn(&[String]) -> Vec<String>,
) -> Result<Vec<String>, TokenScopeMergeError> {
    let merged = intersect_scope_values(binding_values, policy_values, normalizer);
    if !binding_values.is_empty() && !policy_values.is_empty() && merged.is_empty() {
        Err(TokenScopeMergeError::GovernedScopeConflict)
    } else {
        Ok(merged)
    }
}

fn merged_token_scopes(
    key: &TokenRecord,
    gateway_controls: Option<&GatewayControlsPayload>,
    attached_policy_ids: &[String],
) -> Result<EffectiveTokenScopes, TokenScopeMergeError> {
    if !attached_policy_ids.is_empty() && gateway_controls.is_none() {
        return Err(TokenScopeMergeError::PolicyResolutionFailed);
    }

    let binding_gateways = key
        .gateway_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| vec![value.to_string()])
        .or_else(|| {
            validated_key_gateway_binding(&key.metadata).map(|value| vec![value.to_string()])
        })
        .unwrap_or_default();
    let binding_providers = key
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| vec![value.to_string()])
        .unwrap_or_default();
    let binding_models = key.model_filter.clone();

    let policy_providers = gateway_controls
        .map(|value| value.allowed_providers.clone())
        .unwrap_or_default();
    let policy_models = gateway_controls
        .map(|value| value.allowed_models.clone())
        .unwrap_or_default();
    let policy_gateways = gateway_controls
        .map(|value| value.allowed_gateways.clone())
        .unwrap_or_default();

    let allowed_providers = merge_scope_values(
        &binding_providers,
        &policy_providers,
        normalize_provider_scope_values,
    )?;
    let allowed_models =
        merge_scope_values(&binding_models, &policy_models, normalize_text_scope_values)?;
    let allowed_gateways = merge_scope_values(
        &binding_gateways,
        &policy_gateways,
        normalize_text_scope_values,
    )?;

    Ok(EffectiveTokenScopes {
        allowed_providers,
        allowed_models,
        allowed_gateways,
    })
}

fn token_current_spend(key: &TokenRecord, validation: &TokenValidationResponse) -> f64 {
    validation
        .depletion
        .as_ref()
        .and_then(|value| value.current_spend)
        .unwrap_or(key.current_spend)
}

fn token_max_budget(key: &TokenRecord, validation: &TokenValidationResponse) -> Option<f64> {
    validation
        .depletion
        .as_ref()
        .and_then(|value| value.max_budget)
        .or(key.max_budget)
}

fn token_current_requests(validation: &TokenValidationResponse) -> u64 {
    validation
        .depletion
        .as_ref()
        .and_then(|value| value.current_requests)
        .unwrap_or(0)
}

fn token_max_requests(validation: &TokenValidationResponse) -> Option<u64> {
    validation
        .depletion
        .as_ref()
        .and_then(|value| value.max_requests)
}

fn parse_expiry_timestamp(value: Option<&str>) -> Option<DateTime<Utc>> {
    value
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

fn silent_engine(
    state: &ActiveGatewayStateView<'_>,
) -> super::declarative_config::SilentEngineConfig {
    state.silent_engine.clone().unwrap_or_default().effective()
}

impl BudgetFilterRejection {
    fn forbidden(message: impl Into<String>, code: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error_type: "cost_budget_exceeded",
            code,
            message: message.into(),
        }
    }

    fn access_denied(message: impl Into<String>, code: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error_type: "access_denied",
            code,
            message: message.into(),
        }
    }

    fn service_unavailable(message: impl Into<String>, code: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            error_type: "service_unavailable",
            code,
            message: message.into(),
        }
    }
}

type PreparedByteStream = futures_util::stream::BoxStream<'static, Result<Bytes, io::Error>>;

pub(crate) struct PreparedStreamingResponse {
    pub(crate) status: StatusCode,
    pub(crate) content_type: HeaderValue,
    pub(crate) body: PreparedByteStream,
}

impl PreparedStreamingResponse {
    pub(crate) fn json(status: StatusCode, body: Bytes) -> Self {
        Self {
            status,
            content_type: HeaderValue::from_static("application/json"),
            body: stream::once(async move { Ok::<Bytes, io::Error>(body) }).boxed(),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ControlPlaneBudgetQueryCacheKey {
    org_id: String,
    target_type: String,
    target_id: Option<String>,
    team_id: Option<String>,
    user_id: Option<String>,
    key_id: Option<String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ControlPlaneProviderBudgetQueryCacheKey {
    org_id: String,
    provider: String,
    model: Option<String>,
    team_id: Option<String>,
    user_id: Option<String>,
    key_id: Option<String>,
}

#[derive(Clone, Copy)]
pub(crate) enum StreamingResponseAdapter {
    OllamaChat,
    BedrockAnthropicEventStream,
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Generate a short local gateway label when the operator did not provide one.
///
/// Connected mode still prefers the control-plane registered gateway identity
/// when it can resolve it. This fallback is used only when startup lacks an
/// explicit or control-plane-provided gateway label.
pub(crate) fn auto_generate_gateway_id() -> String {
    uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(12)
        .collect()
}

fn normalize_provider_alias_list(values: &[String]) -> Vec<String> {
    let mut aliases = values
        .iter()
        .map(|value| crate::gateway::provider_catalog::normalized_provider_alias(value))
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<_>>();
    aliases.sort();
    aliases.dedup();
    aliases
}

#[derive(Clone, Debug, Default)]
pub struct TraceCorrelation {
    pub evaluation_id: Option<String>,
    pub evaluation_run_id: Option<String>,
    pub test_case_id: Option<String>,
    pub test_run_id: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct RequestTelemetryHints {
    prompt_label: Option<String>,
    test_index: Option<i64>,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct RuntimeRoutingSettings {
    #[serde(default = "default_runtime_provider_policy")]
    default_provider_policy: RuntimeProviderPolicySettings,
    #[serde(default = "default_runtime_cache_defaults")]
    cache_defaults: RuntimeCacheDefaults,
    #[serde(default = "default_runtime_plugin_governance")]
    plugin_governance: RuntimePluginGovernance,
    #[serde(default = "default_runtime_shadow_routing")]
    shadow_routing: RuntimeShadowRoutingSettings,
}

impl Default for RuntimeRoutingSettings {
    fn default() -> Self {
        Self {
            default_provider_policy: default_runtime_provider_policy(),
            cache_defaults: default_runtime_cache_defaults(),
            plugin_governance: default_runtime_plugin_governance(),
            shadow_routing: default_runtime_shadow_routing(),
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize)]
struct RuntimeProviderPolicySettings {
    #[serde(default = "default_true")]
    allow_fallbacks: bool,
    #[serde(default = "default_true")]
    require_parameters: bool,
    #[serde(default = "default_data_collection_allow")]
    data_collection: String,
    #[serde(default)]
    zdr: bool,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct RuntimeCacheDefaults {
    #[serde(default = "default_true")]
    allow_cache_control: bool,
    #[serde(default = "default_true")]
    sticky_routing: bool,
    #[serde(default = "default_true")]
    allow_session_id: bool,
    #[serde(default = "default_session_header_name")]
    session_header_name: String,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
struct RuntimePluginGovernance {
    #[serde(default)]
    defaults: Vec<RuntimePluginSetting>,
    #[serde(default)]
    forced_on: Vec<RuntimePluginSetting>,
    #[serde(default)]
    prevent_overrides: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct RuntimePluginSetting {
    id: String,
    enabled: bool,
    #[serde(default)]
    options: Option<serde_json::Value>,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct RuntimeShadowRoutingSettings {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_shadow_evaluation_mode")]
    evaluation_mode: String,
    #[serde(default = "default_shadow_capture_mode")]
    capture_mode: String,
}

#[derive(Clone, Debug)]
struct RuntimeCacheControl {
    cache_type: String,
    ttl_override: Option<Duration>,
}

#[derive(Clone, Debug)]
pub(crate) struct EffectiveShadowRouting {
    enabled: bool,
    capture_mode: String,
}

impl Default for EffectiveShadowRouting {
    fn default() -> Self {
        Self {
            enabled: false,
            capture_mode: default_shadow_capture_mode(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_data_collection_allow() -> String {
    "allow".to_string()
}

fn default_session_header_name() -> String {
    "x-session-id".to_string()
}

fn default_shadow_evaluation_mode() -> String {
    "asynchronous".to_string()
}

fn default_shadow_capture_mode() -> String {
    "metadata_only".to_string()
}

fn default_runtime_provider_policy() -> RuntimeProviderPolicySettings {
    RuntimeProviderPolicySettings {
        allow_fallbacks: true,
        require_parameters: true,
        data_collection: default_data_collection_allow(),
        zdr: false,
    }
}

fn default_runtime_cache_defaults() -> RuntimeCacheDefaults {
    RuntimeCacheDefaults {
        allow_cache_control: true,
        sticky_routing: true,
        allow_session_id: true,
        session_header_name: default_session_header_name(),
    }
}

fn default_runtime_plugin_governance() -> RuntimePluginGovernance {
    RuntimePluginGovernance::default()
}

fn default_runtime_shadow_routing() -> RuntimeShadowRoutingSettings {
    RuntimeShadowRoutingSettings {
        enabled: false,
        evaluation_mode: default_shadow_evaluation_mode(),
        capture_mode: default_shadow_capture_mode(),
    }
}

fn runtime_routing_from_declarative(
    cfg: Option<super::declarative_config::RuntimeRoutingConfig>,
) -> RuntimeRoutingSettings {
    let Some(cfg) = cfg else {
        return RuntimeRoutingSettings::default();
    };
    RuntimeRoutingSettings {
        default_provider_policy: RuntimeProviderPolicySettings {
            allow_fallbacks: cfg.default_provider_policy.allow_fallbacks,
            require_parameters: cfg.default_provider_policy.require_parameters,
            data_collection: cfg.default_provider_policy.data_collection,
            zdr: cfg.default_provider_policy.zdr,
        },
        cache_defaults: RuntimeCacheDefaults {
            allow_cache_control: cfg.cache_defaults.allow_cache_control,
            sticky_routing: cfg.cache_defaults.sticky_routing,
            allow_session_id: cfg.cache_defaults.allow_session_id,
            session_header_name: cfg.cache_defaults.session_header_name,
        },
        plugin_governance: RuntimePluginGovernance {
            defaults: cfg
                .plugin_governance
                .defaults
                .into_iter()
                .map(|p| RuntimePluginSetting {
                    id: p.id,
                    enabled: p.enabled,
                    options: p.options,
                })
                .collect(),
            forced_on: cfg
                .plugin_governance
                .forced_on
                .into_iter()
                .map(|p| RuntimePluginSetting {
                    id: p.id,
                    enabled: p.enabled,
                    options: p.options,
                })
                .collect(),
            prevent_overrides: cfg.plugin_governance.prevent_overrides,
        },
        shadow_routing: RuntimeShadowRoutingSettings {
            enabled: cfg.shadow_routing.enabled,
            evaluation_mode: cfg.shadow_routing.evaluation_mode,
            capture_mode: cfg.shadow_routing.capture_mode,
        },
    }
}

#[derive(Debug, thiserror::Error)]
enum RuntimeRoutingError {
    #[error("{message}")]
    InvalidRequest {
        status: StatusCode,
        code: &'static str,
        message: String,
    },
}

impl RuntimeRoutingError {
    fn invalid_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidRequest {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code,
            message: message.into(),
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest { status, .. } => *status,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest { code, .. } => code,
        }
    }

    fn browser_safe_message(&self) -> &str {
        match self {
            Self::InvalidRequest { message, .. } => message.as_str(),
        }
    }
}

impl TraceCorrelation {
    fn is_empty(&self) -> bool {
        self.evaluation_id.is_none()
            && self.evaluation_run_id.is_none()
            && self.test_case_id.is_none()
            && self.test_run_id.is_none()
    }

    fn as_event_json(&self) -> Option<serde_json::Value> {
        if self.is_empty() {
            return None;
        }

        Some(serde_json::json!({
            "evaluation_id": self.evaluation_id,
            "evaluation_run_id": self.evaluation_run_id,
            "test_case_id": self.test_case_id,
            "test_run_id": self.test_run_id,
        }))
    }
}

fn normalize_optional_string_value(value: Option<&serde_json::Value>) -> Option<String> {
    value
        .and_then(|candidate| candidate.as_str())
        .map(|candidate| candidate.trim().to_string())
        .filter(|candidate| !candidate.is_empty())
}

fn extract_trace_correlation(value: &serde_json::Value) -> TraceCorrelation {
    let verdictan = value
        .get("verdictan")
        .and_then(|candidate| candidate.as_object());
    let correlation = verdictan
        .and_then(|candidate| candidate.get("trace"))
        .and_then(|candidate| candidate.as_object())
        .or_else(|| {
            verdictan
                .and_then(|candidate| candidate.get("correlation"))
                .and_then(|candidate| candidate.as_object())
        })
        .or(verdictan);

    let Some(correlation) = correlation else {
        return TraceCorrelation::default();
    };

    TraceCorrelation {
        evaluation_id: normalize_optional_string_value(correlation.get("evaluation_id")),
        evaluation_run_id: normalize_optional_string_value(correlation.get("evaluation_run_id")),
        test_case_id: normalize_optional_string_value(correlation.get("test_case_id")),
        test_run_id: normalize_optional_string_value(correlation.get("test_run_id")),
    }
}

fn extract_request_telemetry_hints(value: &serde_json::Value) -> RequestTelemetryHints {
    let Some(verdictan) = value
        .get("verdictan")
        .and_then(|candidate| candidate.as_object())
    else {
        return RequestTelemetryHints::default();
    };

    RequestTelemetryHints {
        prompt_label: verdictan
            .get("prompt")
            .and_then(|candidate| candidate.as_object())
            .and_then(|candidate| candidate.get("label"))
            .and_then(|candidate| candidate.as_str())
            .or_else(|| {
                verdictan
                    .get("prompt_label")
                    .and_then(|candidate| candidate.as_str())
            })
            .map(ToOwned::to_owned),
        test_index: verdictan
            .get("test")
            .and_then(|candidate| candidate.as_object())
            .and_then(|candidate| candidate.get("index"))
            .and_then(|candidate| candidate.as_i64())
            .or_else(|| {
                verdictan
                    .get("test_index")
                    .and_then(|candidate| candidate.as_i64())
            }),
    }
}

fn telemetry_verdictan_metadata(
    hints: &RequestTelemetryHints,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    if hints.prompt_label.is_none() && hints.test_index.is_none() {
        return None;
    }

    let mut verdictan = serde_json::Map::new();

    if let Some(prompt_label) = &hints.prompt_label {
        verdictan.insert(
            "prompt_label".to_string(),
            serde_json::Value::String(prompt_label.clone()),
        );
    }

    if let Some(test_index) = hints.test_index {
        verdictan.insert(
            "test_index".to_string(),
            serde_json::Value::Number(test_index.into()),
        );
    }

    Some(verdictan)
}

fn annotate_trace_correlation_span(span: &tracing::Span, correlation: &TraceCorrelation) {
    if correlation.is_empty() {
        return;
    }

    if let Some(value) = &correlation.evaluation_id {
        span.record("verdictan_evaluation_id", tracing::field::display(value));
    }
    if let Some(value) = &correlation.evaluation_run_id {
        span.record(
            "verdictan_evaluation_run_id",
            tracing::field::display(value),
        );
    }
    if let Some(value) = &correlation.test_case_id {
        span.record("verdictan_test_case_id", tracing::field::display(value));
    }
    if let Some(value) = &correlation.test_run_id {
        span.record("verdictan_test_run_id", tracing::field::display(value));
    }

    #[cfg(feature = "otlp")]
    {
        use opentelemetry::trace::TraceContextExt;
        use opentelemetry::KeyValue;
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let context = span.context();
        let otel_span = context.span();

        if let Some(value) = &correlation.evaluation_id {
            otel_span.set_attribute(KeyValue::new("verdictan.evaluation_id", value.clone()));
        }
        if let Some(value) = &correlation.evaluation_run_id {
            otel_span.set_attribute(KeyValue::new("verdictan.evaluation_run_id", value.clone()));
        }
        if let Some(value) = &correlation.test_case_id {
            otel_span.set_attribute(KeyValue::new("verdictan.test_case_id", value.clone()));
        }
        if let Some(value) = &correlation.test_run_id {
            otel_span.set_attribute(KeyValue::new("verdictan.test_run_id", value.clone()));
        }
    }
}

fn proxy_phase_span(
    name: &'static str,
    request_id: &str,
    traceparent: &str,
    phase: &'static str,
    correlation: &TraceCorrelation,
) -> tracing::Span {
    let span = tracing::info_span!(
        "proxy_phase",
        request_id = %request_id,
        traceparent = %traceparent,
        span_name = %name,
        phase = %phase,
        verdictan_evaluation_id = tracing::field::Empty,
        verdictan_evaluation_run_id = tracing::field::Empty,
        verdictan_test_case_id = tracing::field::Empty,
        verdictan_test_run_id = tracing::field::Empty
    );
    crate::telemetry::attach_parent_trace_context(&span, traceparent);
    annotate_trace_correlation_span(&span, correlation);
    crate::telemetry::annotate_workflow_phase_span(&span, name, phase);
    span
}

#[derive(Clone)]
pub struct GatewayState {
    pub gateway_id: Option<Arc<str>>,
    pub crdt_replica_id: Arc<str>,
    pub crdt_auth_client: Option<Arc<super::jwt_auth::GatewayAuthClient>>,
    pub crdt_auth_shutdown: Option<Arc<tokio::sync::watch::Sender<bool>>>,
    pub runtime_registration_id: Option<String>,
    /// Connected-mode publication/locality cache with freshness tracking used
    /// to fail closed when the control-plane read model goes stale.
    pub connected_read_model: SharedConnectedGatewayReadModel,
    pub catalog_resolver: super::provider_catalog::CatalogBackedProviderResolver,
    pub source_config_path: Option<String>,
    pub upstream_base: String,
    pub upstream_auth: Option<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
    pub fail_mode: FailMode,
    pub client: reqwest::Client,
    pub api_base_url: Option<String>,
    pub admin_bearer_token: Option<String>,
    pub event_sink: Option<EventSink>,
    pub mcp_sessions: crate::mcp::transport::streamable_http::StreamableHttpState,
    pub crdt_sync_runtime: SharedCrdtSyncRuntime,
    pub agent_context_service: Option<Arc<super::agent_context::AgentContextService>>,
    pub history_service: Option<Arc<super::history::HistoryService>>,
    pub admin_local_only: bool,
    pub active_config: SharedGatewayConfig,
    pub rate_limiter: Arc<super::rate_limit::AdaptiveConcurrencyLimiter>,
    pub provider_cache: Arc<super::cache::ProviderResponseCache>,
    pub provider_metrics: Arc<super::provider_metrics::ProviderMetrics>,
    /// Phase 19 — global request-count rate limiter (optional).
    pub global_rate_limiter: Option<Arc<super::rate_limit::GlobalRateLimiter>>,
    /// Phase 19 — per-client-IP rate limiter (optional).
    pub ip_rate_limiter: Option<Arc<super::rate_limit::IpRateLimiter>>,
    /// Phase 18 — token-consumption rate limiter (optional).
    pub token_rate_limiter: Option<Arc<super::token_rate_limit::TokenRateLimiter>>,
    /// Phase 20 — request size limit middleware (optional).
    pub size_limit: Option<Arc<super::size_limit::SizeLimitMiddleware>>,
    /// Per-user request-count rate limiter (optional).
    pub user_rate_limiter: Option<Arc<super::rate_limit::UserRateLimiter>>,
    /// Per-token RPM limiter (always present; enforces `rate_limit_rpm`
    /// from validated API tokens when the control-plane client is active).
    pub key_rate_limiter: Arc<super::rate_limit::TokenRateLimiter>,
    /// Legacy local request-count telemetry state. Authoritative admission and
    /// lifetime request consumption are owned by the control-plane reservation.
    pub key_request_tracker: Arc<super::token_rate_limit::TokenRequestTracker>,
    /// Local post-dispatch spend telemetry; never an admission authority.
    pub key_budget_tracker: Arc<super::token_rate_limit::TokenBudgetTracker>,
    /// Optional source-IP allowlist parsed from declarative config.
    pub ip_allowlist: Option<Arc<Vec<ipnet::IpNet>>>,
    /// Proxy networks authorized to supply the client-address chain.
    pub ip_allowlist_trusted_proxies: Arc<Vec<ipnet::IpNet>>,
    /// When `true` the gateway runs with a validated control-plane client: every
    /// incoming request must present a valid API token and IP
    /// restrictions from the key\u2019s org are enforced at authentication time.
    pub connected_mode: bool,
    /// Shared Prometheus callback sink for `/metrics` scrape endpoint.
    pub prometheus_sink: Option<Arc<super::callbacks::PrometheusCallback>>,
    /// Callback router for dispatching events to all configured sinks.
    pub callback_router: Option<Arc<super::callbacks::CallbackRouter>>,
    /// Phase 25 — centralized distributed state for multi-instance coordination.
    pub distributed_state: Option<Arc<super::distributed_state::DistributedState>>,
    /// Instance-scoped sealed MCP outbox location for connected tool-call audit.
    pub mcp_outbox: Arc<crate::mcp::audit::McpOutboxHandle>,
    /// Connected-mode: bounded TTL cache for API token validation results.
    pub token_validation_cache:
        Arc<super::token_validation_cache::TokenValidationCache<TokenValidationResponse>>,
    /// Connected-mode diagnostics for auth/runtime-state cache behavior.
    pub gateway_runtime_metrics: Arc<GatewayRuntimeMetrics>,
    pub rollout_grade: bool,
    pub rollout_grade_required: bool,
    pub rollout_grade_reasons: Arc<Vec<String>>,
    /// CLI-FIND-LOW-004 + CLI-FIND-RACE-001: Serialize reload operations so that
    /// concurrent reload requests do not interleave config publication and
    /// circuit-breaker state restoration.
    pub reload_guard: Arc<tokio::sync::Mutex<()>>,
    /// CLI-FIND-RACE-004: Counter of in-flight background tasks (event forwarding,
    /// spend-log forwarding). Incremented before spawn, decremented on completion.
    /// Shutdown waits up to 5 seconds for this to reach zero.
    pub in_flight_tasks: Arc<std::sync::atomic::AtomicUsize>,
    pub admission_controller: super::admission_control::AdmissionController,
    pub health_monitor: Arc<super::health_monitor::ProviderHealthMonitor>,
    ///007: AI usage streaming capture config from policy stanza.
    pub ai_usage_capture_config: super::ai_usage_capture::CaptureConfig,
}

#[derive(Clone, Default)]
pub struct SharedCrdtSyncRuntime {
    inner: Arc<RwLock<Option<Arc<super::crdt_sync::CrdtSyncDriver>>>>,
}

impl SharedCrdtSyncRuntime {
    pub fn replace(
        &self,
        replica_id: &str,
        context_fabric: Option<&super::declarative_config::ContextFabricConfig>,
        auth_client: Option<Arc<super::jwt_auth::GatewayAuthClient>>,
        read_model: Option<SharedConnectedGatewayReadModel>,
    ) -> Result<(), CliError> {
        let runtime = build_crdt_sync_driver(replica_id, context_fabric, auth_client, read_model)?
            .map(Arc::new);
        #[allow(clippy::expect_used)]
        let mut guard = self.inner.write().expect("crdt sync runtime lock");
        *guard = runtime;
        Ok(())
    }

    pub fn current(&self) -> Option<Arc<super::crdt_sync::CrdtSyncDriver>> {
        #[allow(clippy::expect_used)]
        self.inner.read().expect("crdt sync runtime lock").clone()
    }
}

fn build_crdt_sync_driver(
    replica_id: &str,
    context_fabric: Option<&super::declarative_config::ContextFabricConfig>,
    auth_client: Option<Arc<super::jwt_auth::GatewayAuthClient>>,
    read_model: Option<SharedConnectedGatewayReadModel>,
) -> Result<Option<super::crdt_sync::CrdtSyncDriver>, CliError> {
    let multi_gateway = context_fabric.and_then(|cfg| cfg.multi_gateway.as_ref());
    if !multi_gateway.and_then(|cfg| cfg.enabled).unwrap_or(false) {
        return Ok(None);
    }

    if auth_client.is_none() {
        return Err(CliError::user(
            "context_fabric.multi_gateway requires CRDT peer authentication material, which is \
             bootstrapped only when the gateway starts. Restart the gateway with \
             context_fabric.multi_gateway enabled instead of enabling it through a config reload."
                .to_string(),
        ));
    }

    let mut config = super::crdt_sync::PeerSyncConfig::default();
    if let Some(peers) = multi_gateway.and_then(|cfg| cfg.peers.as_ref()) {
        config.peers = peers
            .iter()
            .map(|peer| super::crdt_sync::PeerSyncPeer {
                gateway_id: peer.gateway_id.clone(),
                endpoint: peer.endpoint.clone(),
            })
            .collect();
    }
    if let Some(sync_interval_ms) = multi_gateway.and_then(|cfg| cfg.sync_interval_ms) {
        config.sync_interval_ms = sync_interval_ms;
    }
    if let Some(max_partition_buffer_age) =
        multi_gateway.and_then(|cfg| cfg.max_partition_buffer_age.as_deref())
    {
        config.max_partition_buffer_age = parse_duration_literal(max_partition_buffer_age)?;
    }
    config.enabled = true;

    let state = Arc::new(tokio::sync::RwLock::new(
        super::crdt::ContextCrdt::new(replica_id.to_string()).map_err(|error| {
            CliError::internal(format!(
                "failed to initialize context CRDT replica: {error}"
            ))
        })?,
    ));

    super::crdt_sync::CrdtSyncDriver::new_authenticated(
        state,
        config,
        reqwest::Client::builder()
            .timeout(Duration::from_millis(750))
            .build()
            .map_err(|error| {
                CliError::internal(format!("failed to initialize CRDT HTTP client: {error}"))
            })?,
        auth_client,
        read_model,
    )
    .map(Some)
    .map_err(|error| CliError::internal(format!("failed to initialize CRDT sync driver: {error}")))
}

async fn build_crdt_auth_client(
    api_base_url: Option<&str>,
    event_sink: Option<&EventSinkConfig>,
    runtime_registration_id: Option<&str>,
    multi_gateway_enabled: bool,
) -> Result<Option<Arc<super::jwt_auth::GatewayAuthClient>>, CliError> {
    if !multi_gateway_enabled {
        return Ok(None);
    }

    let base_url = api_base_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::user(
                "context_fabric.multi_gateway requires VERDICTAN_API_URL to bootstrap CRDT auth"
                    .to_string(),
            )
        })?;
    let sink = event_sink.ok_or_else(|| {
        CliError::user(
            "context_fabric.multi_gateway requires VERDICTAN_API_TOKEN to bootstrap CRDT auth"
                .to_string(),
        )
    })?;
    let runtime_registration_id = runtime_registration_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::user(
                "context_fabric.multi_gateway requires a runtime_registration_id UUID".to_string(),
            )
        })?;
    let gateway_id = uuid::Uuid::parse_str(runtime_registration_id)
        .map(|parsed| parsed.hyphenated().to_string())
        .map_err(|_| {
            CliError::user(
                "context_fabric.multi_gateway requires runtime_registration_id to be a UUID"
                    .to_string(),
            )
        })?;
    let whoami = crate::auth::token::whoami_async(base_url, &sink.api_token)
        .await
        .map_err(|error| {
            CliError::user(format!("failed to verify gateway auth context: {error}"))
        })?;
    let client = Arc::new(super::jwt_auth::GatewayAuthClient::new(
        sink.api_token.clone(),
        base_url.to_string(),
        whoami.org_id,
        gateway_id,
    ));
    client.bootstrap().await.map_err(|error| {
        CliError::user(format!("failed to bootstrap CRDT gateway auth: {error}"))
    })?;
    Ok(Some(client))
}

fn parse_duration_literal(value: &str) -> Result<Duration, CliError> {
    let raw = value.trim();
    let (number, multiplier_ms) = if let Some(number) = raw.strip_suffix("ms") {
        (number, 1u64)
    } else if let Some(number) = raw.strip_suffix('s') {
        (number, 1_000u64)
    } else if let Some(number) = raw.strip_suffix('m') {
        (number, 60_000u64)
    } else if let Some(number) = raw.strip_suffix('h') {
        (number, 3_600_000u64)
    } else if let Some(number) = raw.strip_suffix('d') {
        (number, 86_400_000u64)
    } else {
        return Err(CliError::internal(format!(
            "unsupported duration literal for context_fabric.multi_gateway.max_partition_buffer_age: {raw}"
        )));
    };

    let base = number.parse::<u64>().map_err(|error| {
        CliError::internal(format!(
            "invalid duration literal for context_fabric.multi_gateway.max_partition_buffer_age: {raw} ({error})"
        ))
    })?;
    let total_ms = base.checked_mul(multiplier_ms).ok_or_else(|| {
        CliError::internal(format!(
            "duration literal overflow for context_fabric.multi_gateway.max_partition_buffer_age: {raw}"
        ))
    })?;
    Ok(Duration::from_millis(total_ms))
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RequestResolution {
    matched_route: Option<super::routes::Route>,
    consumer_group: Option<super::consumer::ResolvedConsumerGroup>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct ActiveGatewayConfig {
    mode: &'static str,
    config_version: String,
    config_sha256: String,
    config_content: String,
    policy_chain: Vec<String>,
    policy_count: usize,
    targeting: Vec<serde_json::Value>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct GatewayConfigQuery {
    source_path: Option<String>,
    org_id: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct SourceGatewayConfig {
    path: Option<String>,
    exists: bool,
    config_version: Option<String>,
    config_sha256: Option<String>,
    bytes: Option<u64>,
    updated_at: Option<String>,
    content: Option<String>,
    read_error: Option<String>,
}

#[derive(Clone)]
pub struct SharedGatewayConfig {
    pub inner: Arc<RwLock<LoadedDeclarativeConfig>>,
}

impl SharedGatewayConfig {
    pub fn new(config: LoadedDeclarativeConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(config)),
        }
    }

    pub fn snapshot(&self) -> LoadedDeclarativeConfig {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let snapshot = self.inner.read().expect("gateway config lock").clone();
        snapshot
    }

    pub fn replace(&self, config: LoadedDeclarativeConfig) {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut guard = self.inner.write().expect("gateway config lock");
        *guard = config;
    }
}

fn spawn_connected_read_model_refresh_loop(
    sink: EventSink,
    runtime_registration_id: String,
    local_hosted_gateway: Option<super::declarative_config::HostedGatewayRuntimeConfig>,
    active_config: SharedGatewayConfig,
    connected_read_model: SharedConnectedGatewayReadModel,
    catalog_resolver: super::provider_catalog::CatalogBackedProviderResolver,
    reload_guard: Arc<tokio::sync::Mutex<()>>,
    gateway_id: Option<String>,
) {
    tokio::spawn(async move {
        if let Err(error) = sink.fetch_runtime_routing_settings(None).await {
            tracing::debug!(
                gateway_id = ?gateway_id,
                runtime_registration_id = %runtime_registration_id,
                error = %error,
                "connected gateway runtime routing cache prewarm skipped"
            );
        }
        if let Some(bound_gateway_id) = gateway_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if let Err(error) = sink
                .fetch_bound_gateway_agent_binding(bound_gateway_id)
                .await
            {
                tracing::debug!(
                    gateway_id = %bound_gateway_id,
                    runtime_registration_id = %runtime_registration_id,
                    error = %error,
                    "connected gateway agent binding cache prewarm skipped"
                );
            }
        }
        // Prewarm: if the read model has no successful refresh yet, fetch
        // immediately instead of waiting for the first interval tick.
        let needs_prewarm = {
            let snapshot = connected_read_model.snapshot();
            snapshot
                .publication_catalog_last_successful_refresh_at
                .is_none()
                && snapshot
                    .routing_compatibility_last_successful_refresh_at
                    .is_none()
        };
        if needs_prewarm {
            tracing::info!(
                gateway_id = ?gateway_id,
                runtime_registration_id = %runtime_registration_id,
                "connected gateway read model: prewarming on startup"
            );
            if let Err(error) = refresh_connected_read_model_once(
                &sink,
                &runtime_registration_id,
                &local_hosted_gateway,
                &active_config,
                &connected_read_model,
                &catalog_resolver,
                &reload_guard,
            )
            .await
            {
                tracing::warn!(
                    gateway_id = ?gateway_id,
                    runtime_registration_id = %runtime_registration_id,
                    error = %error,
                    "connected gateway read model prewarm failed"
                );
            }
        }

        let mut interval = tokio::time::interval(Duration::from_secs(
            CONNECTED_READ_MODEL_REFRESH_INTERVAL_SECS,
        ));
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(error) = refresh_connected_read_model_once(
                &sink,
                &runtime_registration_id,
                &local_hosted_gateway,
                &active_config,
                &connected_read_model,
                &catalog_resolver,
                &reload_guard,
            )
            .await
            {
                let snapshot = connected_read_model.snapshot();
                tracing::warn!(
                    gateway_id = ?gateway_id,
                    runtime_registration_id = %runtime_registration_id,
                    error = %error,
                    publication_catalog_last_successful_refresh_at =
                        ?snapshot.publication_catalog_last_successful_refresh_at,
                    publication_catalog_last_refresh_error =
                        ?snapshot.publication_catalog_last_refresh_error,
                    routing_compatibility_last_successful_refresh_at =
                        ?snapshot.routing_compatibility_last_successful_refresh_at,
                    routing_compatibility_last_refresh_error =
                        ?snapshot.routing_compatibility_last_refresh_error,
                    auth_verification_material_last_refresh_error =
                        ?snapshot.auth_verification_material_last_refresh_error,
                    registry_metadata_last_refresh_error =
                        ?snapshot.registry_metadata_last_refresh_error,
                    capacity_health_last_refresh_error =
                        ?snapshot.capacity_health_last_refresh_error,
                    "connected gateway read model refresh failed"
                );
            }
        }
    });
}

#[path = "server_sections/state_and_routing.rs"]
mod state_and_routing;
pub use state_and_routing::*;

#[path = "server_sections/runtime_pipeline/mod.rs"]
mod runtime_pipeline;
pub use runtime_pipeline::*;

#[path = "server_sections/bootstrap_and_runtime.rs"]
mod bootstrap_and_runtime;
pub use bootstrap_and_runtime::*;

fn enforce_consumer_group_rate_limit(
    state: &ActiveGatewayStateView<'_>,
    request_id: &str,
    consumer_group: Option<&super::consumer::ResolvedConsumerGroup>,
) -> Result<Vec<(&'static str, String)>, Response<Body>> {
    let Some(config) = state.consumer_groups.as_ref() else {
        return Ok(vec![]);
    };
    let Some(consumer_group) = consumer_group else {
        return Ok(vec![]);
    };

    match config.check_request_limit(consumer_group) {
        Ok(remaining_opt) => {
            let Some(remaining) = remaining_opt else {
                return Ok(vec![]);
            };
            let limit = consumer_group
                .rate_limit
                .as_ref()
                .and_then(|rl| rl.max_requests)
                .unwrap_or(0);
            Ok(vec![
                ("x-ratelimit-limit-requests", limit.to_string()),
                ("x-ratelimit-remaining-requests", remaining.to_string()),
            ])
        }
        Err(err) => {
            tracing::warn!(
                request_id = %request_id,
                consumer_group = %err.group_name,
                limit = err.limit,
                "consumer group rate limit exceeded"
            );
            let body = serde_json::json!({
                "error": error_json(
                    "Rate limit exceeded for consumer group",
                    "rate_limit_exceeded",
                    "consumer_group_rate_limit_exceeded",
                )
            });
            let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
            let mut builder = Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Verdictan-Consumer-Group", &err.group_name)
                .header("X-Request-Id", request_id);
            for (name, value) in ratelimit_headers(
                err.limit,
                err.remaining,
                err.retry_after_seconds,
                None,
                None,
            ) {
                builder = builder.header(name, value);
            }
            Err(builder.body(Body::from(text)).unwrap_or_default())
        }
    }
}

fn resolve_websocket_ua_request_context(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
) -> Option<(String, Bytes)> {
    let registry = state.provider_registry.as_ref()?;
    if registry.targets.is_empty() {
        return None;
    }

    let provider_pin = headers
        .get("x-verdictan-provider")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let ordered = if let Some(ref provider_pin) = provider_pin {
        registry.resolve_provider_pin(provider_pin)
    } else {
        super::provider_metrics::select_providers(
            &registry.targets,
            &registry.routing,
            state.provider_metrics,
        )
    };
    if ordered.is_empty() {
        return None;
    }

    for index in ordered {
        let target = &registry.targets[index];
        if target.execution_target.is_some() {
            continue;
        }
        let model = resolve_target_request_model(target, &target.model, None)
            .0
            .or_else(|| resolve_target_model_name(target).map(ToOwned::to_owned))
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| target.model.clone());
        let body = serde_json::to_vec(&serde_json::json!({ "model": model }))
            .ok()?
            .into();
        return Some((model, body));
    }
    None
}

async fn prepare_connected_websocket_ua_lifecycle(
    state: &mut ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    proxy_path: &'static str,
    request_id: &str,
    traceparent: &str,
) -> Result<Option<Bytes>, Response<Body>> {
    let Some((requested_model, synthetic_body)) =
        resolve_websocket_ua_request_context(state, headers)
    else {
        return Ok(None);
    };
    let parsed_json: serde_json::Value =
        serde_json::from_slice(&synthetic_body).unwrap_or(serde_json::Value::Null);
    let estimated_prompt_tokens = 0u64;
    let estimated_max_completion = 4096u64;

    let connected_access_status = maybe_prime_connected_access_versions(
        state,
        &requested_model,
        estimated_prompt_tokens,
        estimated_max_completion,
        request_id,
    )
    .await?;

    let ua_eval_document = enforce_usage_authorization_evaluate_gate(
        state,
        super::usage_authorization::UsageAuthorizationRequestFamily::Websocket,
        &requested_model,
        estimated_prompt_tokens,
        estimated_max_completion,
        request_id,
        traceparent,
    )
    .await?;
    state.ua_eval_document = ua_eval_document;

    let ua_financial_path_active = ua_financial_path_active(state)
        && connected_access_status
            .admission_credential_source
            .is_some()
        && !connected_access_status.dispatch_precluded;
    if !ua_financial_path_active {
        return Ok(Some(synthetic_body));
    }

    prepare_ua_financial_lifecycle(
        state,
        headers,
        &parsed_json,
        &synthetic_body,
        request_id,
        traceparent,
        estimated_prompt_tokens,
        estimated_max_completion,
        connected_access_status.admission_credential_source,
        proxy_path,
        super::usage_authorization::UsageAuthorizationRequestFamily::Websocket,
    )
    .await?;
    Ok(Some(synthetic_body))
}

fn build_websocket_ua_session_closeout(
    ua_financial_path_active: bool,
    gateway_usage_authorization_id: Option<String>,
    dispatch_acquired: bool,
    event_sink: Option<EventSink>,
    request_body: Bytes,
    current_agent_id: Option<String>,
    org_id: Option<String>,
    request_id: String,
    traceparent: String,
) -> Option<super::websocket_proxy::WebSocketSessionCloseout> {
    if !ua_financial_path_active {
        return None;
    }
    let gateway_usage_authorization_id = gateway_usage_authorization_id?;
    Some(Box::new(move || {
        schedule_finalize_ua_streaming_financial_lifecycle(
            Some(gateway_usage_authorization_id),
            dispatch_acquired,
            event_sink,
            request_body,
            None,
            0,
            false,
            current_agent_id,
            org_id,
            &request_id,
            &traceparent,
        );
    }))
}

async fn mcp_get(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Result<Response<Body>, StatusCode> {
    let settings = gateway_mcp_route_settings(&state);
    let x_request_id_in = headers
        .get("X-Request-Id")
        .and_then(|value| value.to_str().ok());
    let request_id = match request_id::validate_or_generate_x_request_id(x_request_id_in) {
        Ok(id) => id,
        Err(err) => return Ok(reject_invalid_x_request_id(&headers, &err)),
    };
    let traceparent_in = headers
        .get("traceparent")
        .and_then(|value| value.to_str().ok());
    let traceparent = request_id::normalize_or_generate_traceparent(traceparent_in);

    if !settings.enabled {
        return Ok(build_request_error_response(
            StatusCode::NOT_FOUND,
            &request_id,
            &traceparent,
            "The MCP endpoint is disabled on this gateway",
            "invalid_request_error",
            "mcp_disabled",
        ));
    }

    if let Some(response) =
        reject_unpublished_mcp_without_ingress(&state, &headers, &request_id, &traceparent)
    {
        return Ok(response);
    }

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
    if let Err(response) = require_mcp_publication_context(&state_view, &request_id, &traceparent) {
        return Ok(response);
    }

    let raw_token = match require_mcp_api_token(&headers, &request_id, &traceparent) {
        Ok(raw_token) => raw_token,
        Err(response) => return Ok(response),
    };
    let auth_fingerprint = crate::mcp::transport::streamable_http::auth_fingerprint(&raw_token);
    let session_id = crate::mcp::transport::streamable_http::mcp_session_id(&headers);
    Ok(crate::mcp::transport::streamable_http::handle_get(
        state.mcp_sessions.clone(),
        &auth_fingerprint,
        session_id.as_deref(),
    )
    .await)
}

async fn mcp_post(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let settings = gateway_mcp_route_settings(&state);
    let x_request_id_in = headers
        .get("X-Request-Id")
        .and_then(|value| value.to_str().ok());
    let request_id = match request_id::validate_or_generate_x_request_id(x_request_id_in) {
        Ok(id) => id,
        Err(err) => return Ok(reject_invalid_x_request_id(&headers, &err)),
    };
    let traceparent_in = headers
        .get("traceparent")
        .and_then(|value| value.to_str().ok());
    let traceparent = request_id::normalize_or_generate_traceparent(traceparent_in);

    if !settings.enabled {
        return Ok(build_request_error_response(
            StatusCode::NOT_FOUND,
            &request_id,
            &traceparent,
            "The MCP endpoint is disabled on this gateway",
            "invalid_request_error",
            "mcp_disabled",
        ));
    }

    if let Some(response) =
        reject_unpublished_mcp_without_ingress(&state, &headers, &request_id, &traceparent)
    {
        return Ok(response);
    }

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
    if let Err(response) = require_mcp_publication_context(&state_view, &request_id, &traceparent) {
        return Ok(response);
    }

    let raw_token = match require_mcp_api_token(&headers, &request_id, &traceparent) {
        Ok(raw_token) => raw_token,
        Err(response) => return Ok(response),
    };
    let session_id = crate::mcp::transport::streamable_http::mcp_session_id(&headers);
    if let Some(ref session_id) = session_id {
        crate::mcp::local_context_runtime::shared_local_context_runtime_registry()
            .session(session_id.clone())
            .bind_crdt_sync_driver(
                state
                    .crdt_sync_runtime
                    .current()
                    .map(|driver| (*driver).clone()),
            );
    }
    let session_policy = if let Some(ref session_id) = session_id {
        state
            .mcp_sessions
            .session_policy(session_id)
            .await
            .unwrap_or_else(|| default_mcp_session_policy(&initial_public_route_config(&state)))
    } else {
        match resolve_gateway_mcp_session_policy(&state, &state_view, &request_id, &traceparent) {
            Ok(policy) => policy,
            Err(response) => return Ok(response),
        }
    };
    let client = match build_gateway_mcp_client(
        &state,
        &state_view,
        &raw_token,
        &request_id,
        &traceparent,
    ) {
        Ok(client) => client,
        Err(response) => return Ok(response),
    };
    let session_request_limit = session_policy.max_prompt_bytes.min(usize::MAX as u64) as usize;
    let request_body_limit = settings.max_request_body_bytes.min(session_request_limit);
    let body_bytes = match axum::body::to_bytes(request.into_body(), request_body_limit).await {
        Ok(body_bytes) => body_bytes,
        Err(_) => {
            return Ok(build_request_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &request_id,
                &traceparent,
                "The MCP request body exceeds the configured size limit",
                "invalid_request_error",
                "mcp_request_too_large",
            ))
        }
    };
    let request_json = match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
        Ok(request_json) => request_json,
        Err(_) => {
            return Ok(build_request_error_response(
                StatusCode::BAD_REQUEST,
                &request_id,
                &traceparent,
                "Invalid JSON body",
                "invalid_request_error",
                "invalid_json",
            ))
        }
    };
    let auth_fingerprint = crate::mcp::transport::streamable_http::auth_fingerprint(&raw_token);
    let conversation_id = headers
        .get("x-conversation-id")
        .and_then(|value| value.to_str().ok());
    let git_context = git_context_from_headers(&headers);
    let mcp_trace_context = build_gateway_mcp_trace_context(
        &state,
        &state_view,
        session_id.as_deref(),
        conversation_id,
        git_context,
        Some(traceparent.as_str()),
    );

    Ok(crate::mcp::transport::streamable_http::handle_post(
        state.mcp_sessions.clone(),
        state.mcp_outbox.as_ref(),
        &client,
        &auth_fingerprint,
        Some(request_id.as_str()),
        session_id.as_deref(),
        request_json,
        Some(session_policy),
        mcp_trace_context.as_ref(),
    )
    .await)
}

async fn crdt_sync_post(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    let Some(driver) = state.crdt_sync_runtime.current() else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": "error",
                "code": "crdt_sync_disabled",
                "message": "CRDT sync is not enabled on this gateway",
            })),
        )
            .into_response();
    };

    if body.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "code": "crdt_sync_empty_body",
                "message": "CRDT sync requests must include an application/octet-stream body",
            })),
        )
            .into_response();
    }

    let bearer_token = extract_bearer_token(&headers);
    match driver
        .receive_http_request(bearer_token.as_deref(), &body)
        .await
    {
        Ok(report) => {
            let merge = &report.merge;
            Json(serde_json::json!({
                "status": "ok",
                "replica_id": state.crdt_replica_id,
                "duplicate": report.duplicate,
                "ignored_self_origin": report.ignored_self_origin,
                "state_changed": merge.state_changed(),
                "merge_summary": {
                    "added_tags": merge.membership.added_tags,
                    "added_tombstones": merge.membership.added_tombstones,
                    "updated_tombstones": merge.membership.updated_tombstones,
                    "changed_fields": merge.changed_fields,
                    "inserted_fields": merge.inserted_fields,
                }
            }))
            .into_response()
        }
        Err(super::crdt_sync::SyncError::PayloadTooLarge(_)) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "status": "error",
                "code": "crdt_sync_payload_too_large",
                "message": format!("CRDT sync requests must not exceed {} bytes", 1_048_576),
            })),
        )
            .into_response(),
        Err(super::crdt_sync::SyncError::MissingPeerAuthenticator) => {
            tracing::error!(
                replica_id = %state.crdt_replica_id,
                "refused CRDT sync ingress because peer authentication material is not configured. \
                 Restart the gateway to bootstrap multi-gateway CRDT auth."
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "status": "error",
                    "code": "crdt_sync_authenticator_unavailable",
                    "message": "CRDT sync is enabled without peer authentication material and cannot accept peer state",
                })),
            )
                .into_response()
        }
        Err(super::crdt_sync::SyncError::MissingPeerAuthorization) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "status": "error",
                "code": "crdt_sync_unauthorized",
                "message": "CRDT sync requests require a gateway peer bearer token",
            })),
        )
            .into_response(),
        Err(
            error @ (super::crdt_sync::SyncError::PeerAuthorization(_)
            | super::crdt_sync::SyncError::InactivePeer(_)),
        ) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "status": "error",
                "code": "crdt_sync_forbidden",
                "message": error.to_string(),
            })),
        )
            .into_response(),
        Err(super::crdt_sync::SyncError::ReplayConflict) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "status": "error",
                "code": "crdt_sync_replay_conflict",
                "message": "CRDT sync replay conflict detected for sync_id",
            })),
        )
            .into_response(),
        Err(
            error @ (super::crdt_sync::SyncError::ReplayCacheFull
            | super::crdt_sync::SyncError::PeerMaterialStale
            | super::crdt_sync::SyncError::NoActivePeer),
        ) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "error",
                "code": "crdt_sync_temporarily_unavailable",
                "message": error.to_string(),
            })),
        )
            .into_response(),
        Err(
            error @ (super::crdt_sync::SyncError::Crdt(_)
            | super::crdt_sync::SyncError::Serialize(_)
            | super::crdt_sync::SyncError::PayloadDigestMismatch),
        ) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "code": "crdt_sync_invalid_payload",
                "message": error.to_string(),
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "status": "error",
                "code": "crdt_sync_failed",
                "message": error.to_string(),
            })),
        )
            .into_response(),
    }
}

fn spawn_provider_health_probe_loop(state: GatewayState) {
    use std::collections::HashMap;
    use tokio::time::Instant;

    tokio::spawn(async move {
        let mut next_due: HashMap<String, Instant> = HashMap::new();
        let tick_interval = Duration::from_secs(1);

        loop {
            let snapshot = state.active_config.snapshot();
            let Some(registry) = snapshot.provider_registry else {
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            };

            let now = Instant::now();
            let mut probed_any = false;

            for target in &registry.targets {
                let Some(health_probe) = &target.health_probe else {
                    continue;
                };

                let interval_secs = health_probe.interval_seconds.max(5);
                let due = next_due.entry(target.id.clone()).or_insert(now);

                if now < *due {
                    continue;
                }

                let endpoint = health_probe
                    .endpoint
                    .clone()
                    .unwrap_or_else(|| format!("{}/health", target.base_url.trim_end_matches('/')));
                let result =
                    super::health_probe::probe_endpoint(&endpoint, health_probe.timeout_ms).await;
                state.provider_metrics.record_health(
                    &target.id,
                    result.healthy,
                    result.status_code,
                    result.latency_ms,
                    result.checked_at_unix,
                );

                *due = now + Duration::from_secs(interval_secs);
                probed_any = true;
            }

            // Remove entries for targets no longer in config.
            let active_ids: std::collections::HashSet<&str> = registry
                .targets
                .iter()
                .filter(|t| t.health_probe.is_some())
                .map(|t| t.id.as_str())
                .collect();
            next_due.retain(|id, _| active_ids.contains(id.as_str()));

            if !probed_any {
                let sleep_until = next_due
                    .values()
                    .min()
                    .copied()
                    .unwrap_or(now + Duration::from_secs(30));
                let sleep_dur = sleep_until
                    .saturating_duration_since(now)
                    .max(tick_interval);
                tokio::time::sleep(sleep_dur).await;
            } else {
                tokio::time::sleep(tick_interval).await;
            }
        }
    });
}

pub async fn run_until_ctrl_c_with_policy(
    listen: std::net::SocketAddr,
    upstream_base: String,
    upstream_auth: Option<UpstreamAuthConfig>,
    fail_mode: FailMode,
    event_sink: Option<EventSinkConfig>,
    loaded_config: LoadedDeclarativeConfig,
    max_concurrency: usize,
) -> Result<(), CliError> {
    run_instance_until_ctrl_c(crate::runtime::RuntimeInstanceConfig::new(
        None,
        listen,
        upstream_base,
        upstream_auth,
        fail_mode,
        loaded_config,
        max_concurrency,
        true,
        event_sink,
    ))
    .await
}

pub async fn run_instance_until_ctrl_c(
    config: crate::runtime::RuntimeInstanceConfig,
) -> Result<(), CliError> {
    let handle = spawn_instance(config).await?;

    eprintln!("gateway listening on http://{}", handle.addr);

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| CliError::internal(format!("failed to listen for ctrl-c: {e}")))?;

    handle.shutdown();
    Ok(())
}

/// Readiness probe — checks that the gateway config is loaded.
async fn proxy_config(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<GatewayConfigQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    enforce_proxy_admin_auth(
        &state,
        &headers,
        peer_addr,
        "inspect_config",
        "gateways:read",
    )
    .await?;
    tracing::info!(
        action = "inspect_config",
        peer_addr = %peer_addr,
        local_only = state.admin_local_only,
        gateway_id = ?state.gateway_id,
        "gateway admin inspection granted"
    );
    if query
        .source_path
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
    {
        tracing::warn!(
            requested_source_path = ?query.source_path,
            configured_source_path = ?state.source_config_path,
            "gateway admin ignored caller-supplied source_path override"
        );
    }

    let bootstrap_config = state.active_config.snapshot();
    let source = read_source_gateway_config(state.source_config_path.as_deref()).await;
    let requested_org_id = query
        .org_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let (config, inspection_scope, inspection_note) = if state.connected_mode {
        (
            Some(active_gateway_config(&bootstrap_config)),
            "connected_active",
            requested_org_id.map(|org_id| {
                serde_json::json!({
                    "org_id": org_id,
                    "message": "Connected gateways expose only the active runtime config; org-specific runtime inspection is no longer available",
                })
            }),
        )
    } else {
        (
            Some(active_gateway_config(&bootstrap_config)),
            "hosted_active",
            None,
        )
    };

    Ok(Json(serde_json::json!({
        "config": config,
        "inspection_scope": inspection_scope,
        "inspection": inspection_note,
        "bootstrap": {
            "config_version": bootstrap_config.config_version,
            "config_sha256": bootstrap_config.config_sha256,
            "policy_count": bootstrap_config.chain_entries.len(),
            "has_provider_registry": bootstrap_config.provider_registry.is_some(),
        },
        "source": source,
        "upstream": {
            "base_url": state.upstream_base,
            "rate_limit": state.rate_limiter.snapshot(),
        },
        "runtime": {
            "rate_control": "aimd",
            "automatic_retry": "exponential_backoff",
            "max_retries": 3,
            "provider_cache": state.provider_cache.runtime_json().await,
        }
    })))
}

async fn reload_proxy_config(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<ReloadGatewayConfigRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    enforce_proxy_admin_auth(
        &state,
        &headers,
        peer_addr,
        "reload_config",
        "gateways:deploy",
    )
    .await?;

    let mut loaded_config = if payload.clear_active.unwrap_or(false) {
        LoadedDeclarativeConfig::empty()
    } else if let Some(config_yaml) = payload
        .config_yaml
        .as_ref()
        .filter(|value| !value.trim().is_empty())
    {
        LoadedDeclarativeConfig::from_bytes(config_yaml.as_bytes())
            .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?
    } else if let Some(config_path) = payload
        .config_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        // SECURITY: Restrict config_path to prevent arbitrary file reads.
        // Reject absolute paths and parent traversal.
        let path = Path::new(config_path);
        if path.is_absolute() || config_path.contains("..") {
            tracing::warn!(
                config_path = %config_path,
                "reload_proxy_config: rejected path (absolute or traversal)"
            );
            return Err(StatusCode::FORBIDDEN);
        }
        LoadedDeclarativeConfig::from_path(path).map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?
    } else {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    };

    super::secret_resolver::resolve_hosted_secret_key_refs(&state.event_sink, &mut loaded_config)
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "gateway config resolution failed during reload");
            StatusCode::BAD_GATEWAY
        })?;

    // CLI-FIND-LOW-004 + CLI-FIND-RACE-001: Serialize reload operations to prevent
    // interleaved config publication and circuit-breaker state restoration.
    let _reload_lock = state.reload_guard.lock().await;

    // Snapshot circuit breaker state before replacing the config so that degraded
    // providers are not re-flooded after a hot reload.
    let cb_snapshot = state
        .active_config
        .snapshot()
        .provider_registry
        .as_ref()
        .and_then(|reg| reg.circuit_breaker_manager.as_ref())
        .map(|cbm| cbm.snapshot());

    // CLI-FIND-RACE-001: Restore CB state into the new loaded config's provider
    // registry BEFORE publication so concurrent requests never observe reset breakers.
    if let Some(ref snapshot) = cb_snapshot {
        if let Some(cbm) = loaded_config
            .provider_registry
            .as_ref()
            .and_then(|reg| reg.circuit_breaker_manager.as_ref())
        {
            cbm.restore(snapshot);
        }
    }

    // Note (TOCTOU-006): In-flight requests continue to report the config_version active at
    // request start, not at event emission time. This is expected behavior.
    // Requests that already passed input-phase policy evaluation keep using their captured
    // config snapshot, so events from those requests may carry the prior config_version even
    // after the gateway's active version has advanced.
    state.active_config.replace(loaded_config.clone());
    state
        .crdt_sync_runtime
        .replace(
            state.crdt_replica_id.as_ref(),
            loaded_config.context_fabric.as_ref(),
            state.crdt_auth_client.clone(),
            Some(state.connected_read_model.clone()),
        )
        .map_err(|error| {
            tracing::warn!(error = %error, "failed to refresh CRDT sync runtime during reload");
            StatusCode::UNPROCESSABLE_ENTITY
        })?;

    tracing::info!(
        action = "reload_config",
        peer_addr = %peer_addr,
        local_only = state.admin_local_only,
        gateway_id = ?state.gateway_id,
        config_version = %loaded_config.config_version,
        config_sha256 = %loaded_config.config_sha256,
        "gateway admin reload applied"
    );

    Ok(Json(serde_json::json!({
        "ok": true,
        "config": active_gateway_config(&loaded_config),
        "message": "Declarative config applied to gateway runtime",
    })))
}

#[derive(Debug, serde::Deserialize)]
struct InvalidateGatewayCacheRequest {
    org_id: Option<String>,
}

async fn invalidate_gateway_cache(
    State(state): State<GatewayState>,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<InvalidateGatewayCacheRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    enforce_proxy_admin_auth(
        &state,
        &headers,
        peer_addr,
        "invalidate_cache",
        "gateways:deploy",
    )
    .await?;

    state.token_validation_cache.clear();

    if let Some(org_id) = payload
        .org_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        tracing::info!(org_id = %org_id, "token validation cache invalidated on demand");
    } else {
        tracing::info!("token validation cache fully invalidated");
    }

    Ok(Json(serde_json::json!({
        "ok": true,
        "message": "API token validation cache invalidated",
    })))
}

#[derive(Debug, serde::Deserialize)]
struct CheckPermissionResult {
    allowed: bool,
    #[serde(default)]
    reason: Option<String>,
}

pub async fn enforce_proxy_admin_auth(
    state: &GatewayState,
    headers: &HeaderMap,
    peer_addr: std::net::SocketAddr,
    action: &str,
    required_permission: &str,
) -> Result<(), StatusCode> {
    // CLI-SEC-002: Even in local-only mode, require the admin bearer token.
    // The bypass for unauthenticated local access is only permitted when no
    // admin_bearer_token has been configured AND no remote API is available
    // (pure-local dev mode). In all other cases the secret is required.
    let has_authorization_header = headers.contains_key(header::AUTHORIZATION);
    if state.admin_local_only
        && peer_addr.ip().is_loopback()
        && !has_authorization_header
        && state.api_base_url.is_none()
        && state.admin_bearer_token.is_none()
    {
        return Ok(());
    }

    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        tracing::warn!(
            action = action,
            peer_addr = %peer_addr,
            gateway_id = ?state.gateway_id,
            "rejected gateway admin request without a valid bearer token"
        );
        return Err(StatusCode::UNAUTHORIZED);
    };

    if state.admin_bearer_token.as_deref() == Some(token) {
        return Ok(());
    }

    let Some(api_base_url) = state.api_base_url.as_deref() else {
        tracing::warn!(
            action = action,
            peer_addr = %peer_addr,
            gateway_id = ?state.gateway_id,
            "rejected gateway admin request because VERDICTAN_API_URL is not configured"
        );
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };

    let resource = state
        .gateway_id
        .as_deref()
        .map(|gateway_id| format!("proxy/{gateway_id}"))
        .unwrap_or_else(|| "proxy".to_string());

    let response = state
        .client
        .post(format!(
            "{}/v1/auth/check-permission",
            api_base_url.trim_end_matches('/')
        ))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .json(&serde_json::json!({
            "action": required_permission,
            "resource": resource,
        }))
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(
                action = action,
                peer_addr = %peer_addr,
                gateway_id = ?state.gateway_id,
                error = %error,
                "failed to validate gateway admin bearer token"
            );
            StatusCode::BAD_GATEWAY
        })?;

    if response.status() == StatusCode::UNAUTHORIZED {
        tracing::warn!(
            action = action,
            peer_addr = %peer_addr,
            gateway_id = ?state.gateway_id,
            "rejected gateway admin request with invalid bearer token"
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !response.status().is_success() {
        tracing::warn!(
            action = action,
            peer_addr = %peer_addr,
            gateway_id = ?state.gateway_id,
            status = %response.status(),
            "gateway admin bearer token validation returned a non-success status"
        );
        return Err(StatusCode::BAD_GATEWAY);
    }

    let payload = response
        .json::<CheckPermissionResult>()
        .await
        .map_err(|error| {
            tracing::warn!(
                action = action,
                peer_addr = %peer_addr,
                gateway_id = ?state.gateway_id,
                error = %error,
                "failed to decode gateway admin permission response"
            );
            StatusCode::BAD_GATEWAY
        })?;

    if payload.allowed {
        Ok(())
    } else {
        tracing::warn!(
            action = action,
            peer_addr = %peer_addr,
            gateway_id = ?state.gateway_id,
            reason = ?payload.reason,
            required_permission = required_permission,
            "rejected gateway admin request without the required permission"
        );
        Err(StatusCode::FORBIDDEN)
    }
}

async fn try_outbound_relay(
    state: &GatewayState,
    headers: &HeaderMap,
    body: &Bytes,
    original_uri: &str,
    method: &str,
) -> Option<Response<Body>> {
    if !state.connected_mode || super::relay::is_relayed_request(headers) {
        return None;
    }
    let read_model = state.connected_read_model.snapshot();
    let hmac_secret = read_model.relay_hmac_secret.as_ref()?;
    let agent_id = request_agent_id_header_value(headers)?;
    let peers = read_model.peer_relay_endpoints_for_agent(agent_id);
    let peer = super::relay::select_relay_peer(&peers)?;
    let gateway_id = state.gateway_id.as_deref().unwrap_or("");
    let publication_key = read_model
        .publication_catalog
        .iter()
        .find(|p| p.agent_id.as_deref() == Some(agent_id))
        .map(|p| p.publication_key.as_str())
        .unwrap_or("");

    let envelope = super::relay::build_relay_envelope(
        agent_id,
        publication_key,
        original_uri,
        method,
        headers,
        body,
        gateway_id,
        hmac_secret,
    );

    let tls_config = super::relay::RelayTlsConfig::from_env();
    let client = tls_config
        .build_mtls_client()
        .unwrap_or_else(|| state.client.clone());

    let start = Instant::now();
    let result = super::relay::forward_relay_to_peer(&client, peer, &envelope, hmac_secret).await;
    let latency_ms = start.elapsed().as_millis() as u64;

    let outcome = if result.is_ok() { "success" } else { "failed" };
    super::metrics::record_outbound_relay(latency_ms, outcome);
    if let Some(ref sink) = state.event_sink {
        super::relay::emit_outbound_relay_audit(
            sink,
            agent_id,
            publication_key,
            gateway_id,
            peer,
            outcome,
            latency_ms,
            envelope.relay_ttl,
        );
    }

    Some(result.unwrap_or_else(|e| e))
}

/// Attempt local budget reservation on a cached preflight outcome.
/// Returns `true` if the request is allowed to proceed, or `false` if
/// the local budget is exhausted and the cache entry should be evicted.
fn try_local_budget_reservation(
    outcome: &ConnectedAccessPreflightOutcome,
    input_tokens: u64,
    max_output_tokens: u64,
) -> bool {
    let Some(tracker) = outcome.local_budget_tracker.as_ref() else {
        return true;
    };
    if !tracker.has_pricing() {
        return true;
    }
    tracker.try_reserve(input_tokens, max_output_tokens).is_ok()
}

async fn run_connected_access_preflight(
    machine_client: &reqwest::Client,
    sink: &EventSink,
    request: super::access_preflight::AccessPreflightRequest,
) -> Result<ConnectedAccessPreflightOutcome, anyhow::Error> {
    let cache_key = PreflightCacheKey {
        org_id: request.org_id.clone(),
        provider: request.provider.clone(),
        model: request.model.clone(),
    };
    let preflight_start = Instant::now();
    if let Some(cached) = sink.access_preflight_cache.get(&cache_key) {
        if cached.primary.status == "ready_byok" {
            tracing::debug!(
                org_id = %cache_key.org_id,
                provider = %cache_key.provider,
                model = %cache_key.model,
                "access preflight ready_byok outcome bypasses cache reuse"
            );
            sink.access_preflight_cache.remove(&cache_key);
        } else {
            tracing::debug!(
                org_id = %cache_key.org_id,
                provider = %cache_key.provider,
                model = %cache_key.model,
                "access preflight cache hit"
            );
            sink.access_preflight_cache.insert_with_jitter(
                cache_key.clone(),
                cached.clone(),
                ACCESS_PREFLIGHT_CACHE_TTL_MIN,
                ACCESS_PREFLIGHT_CACHE_TTL_MAX,
            );
            record_request_stage_timing(
                RequestStageTiming::AccessPreflight,
                preflight_start.elapsed(),
                Some(true),
            );
            return Ok(cached);
        }
    }

    let primary =
        match super::access_preflight::access_preflight(machine_client, sink.base_url(), &request)
            .await
        {
            Ok(primary) => primary,
            Err(error) => {
                record_request_stage_timing(
                    RequestStageTiming::AccessPreflight,
                    preflight_start.elapsed(),
                    Some(false),
                );
                return Err(anyhow::anyhow!(error.to_string()));
            }
        };
    let org_authz_version = primary.org_authz_version;

    invalidate_preflight_cache_on_version_change(sink, &cache_key.org_id, org_authz_version);

    let local_budget_tracker = primary.remaining_budget.map(|remaining| {
        Arc::new(LocalBudgetTracker::new(
            remaining,
            primary.cost_per_1k_input_tokens_usd(),
            primary.cost_per_1k_output_tokens_usd(),
            primary.budget_limit,
            primary.budget_period.clone(),
        ))
    });

    let outcome = ConnectedAccessPreflightOutcome {
        primary,
        org_authz_version,
        local_budget_tracker,
    };

    // Jittered TTL: 15–30s to prevent credential-pool pinning and spread
    // cache expiration across requests.
    if outcome.primary.status != "ready_byok" {
        sink.access_preflight_cache.insert_with_jitter(
            cache_key,
            outcome.clone(),
            ACCESS_PREFLIGHT_CACHE_TTL_MIN,
            ACCESS_PREFLIGHT_CACHE_TTL_MAX,
        );
    }
    record_request_stage_timing(
        RequestStageTiming::AccessPreflight,
        preflight_start.elapsed(),
        Some(false),
    );
    Ok(outcome)
}

/// Evicts cached access-preflight entries when org authz version changes.
fn invalidate_preflight_cache_on_version_change(
    sink: &EventSink,
    org_id: &str,
    new_org_authz_version: Option<i64>,
) {
    let org_id_owned = org_id.to_owned();
    let authz_v = new_org_authz_version;
    sink.access_preflight_cache.remove_where_kv(|key, cached| {
        if key.org_id != org_id_owned {
            return false;
        }
        let authz_mismatch = match (cached.org_authz_version, authz_v) {
            (Some(old), Some(new)) => old != new,
            _ => false,
        };
        if authz_mismatch {
            tracing::info!(
                org_id = %org_id_owned,
                provider = %key.provider,
                model = %key.model,
                old_org_authz_version = ?cached.org_authz_version,
                new_org_authz_version = ?authz_v,
                "evicting stale access preflight entry due to authz version change"
            );
            true
        } else {
            false
        }
    });
}

pub(crate) enum ConnectedTargetResolution<T> {
    Ready(T),
    Inactive {
        status: StatusCode,
        message: String,
        status_reason: String,
    },
}

async fn prepare_connected_provider_target(
    state: &ActiveGatewayStateView<'_>,
    target: &super::providers::ProviderTarget,
    request_model: &str,
) -> Result<ConnectedTargetResolution<super::providers::ProviderTarget>, anyhow::Error> {
    if !state.connected_mode {
        return Ok(resolve_local_provider_target(target, false, true));
    }

    if target.execution_target.is_some() {
        return Ok(ConnectedTargetResolution::Inactive {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: format!(
                "Provider target '{}' is inactive: connected gateways do not execute local or self-hosted targets",
                target.id
            ),
            status_reason: "connected_gateway_required".to_string(),
        });
    }

    if !super::provider_auth::uses_organization_stored_provider_secret(target) {
        return Ok(resolve_local_provider_target(target, true, true));
    }

    let finops = state
        .request_finops
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("connected access preflight missing request finops"))?;
    let org_id = finops
        .org_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("connected access preflight missing org_id"))?;
    let sink = state
        .event_sink
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("connected access preflight missing event sink"))?;
    let request_agent_id = match resolved_request_agent_id(state) {
        Some(agent_id) => agent_id,
        None => {
            tracing::warn!(
                provider_id = %target.id,
                "connected provider-key resolution rejected because no deployed request agent resolved"
            );
            return Ok(ConnectedTargetResolution::Inactive {
                status: StatusCode::FORBIDDEN,
                message: format!(
                    "Provider target '{}' is inactive: connected gateway requests require a deployed agent linked to this gateway",
                    target.id
                ),
                status_reason: "gateway_agent_required".to_string(),
            });
        }
    };
    let machine_client = sink.machine_client()?;
    let provider = crate::gateway::provider_catalog::normalized_provider_alias(&target.provider);
    let Some(model) = resolve_catalog_model_name_for_request(target, request_model) else {
        tracing::warn!(
            provider_id = %target.id,
            requested_model = %request_model,
            "connected provider-key resolution rejected because the requested model is not active in target catalog metadata"
        );
        return Ok(ConnectedTargetResolution::Inactive {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            message: format!(
                "Provider target '{}' is inactive: requested model is not active in the platform catalog",
                target.id
            ),
            status_reason: "catalog_model_not_active".to_string(),
        });
    };
    let model = model.to_string();
    let outcome = run_connected_access_preflight(
        machine_client,
        sink,
        super::access_preflight::AccessPreflightRequest {
            org_id: org_id.to_string(),
            agent_id: request_agent_id,
            provider,
            model,
        },
    )
    .await?;
    if outcome.primary.status == "ready_byok" {
        let mut prepared = target.clone();
        prepared.api_key = outcome
            .primary
            .resolved_api_key
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("access preflight did not return a provider key"))?;
        return Ok(ConnectedTargetResolution::Ready(prepared));
    }

    let status_reason = outcome.primary.status_reason;
    if connected_provider_key_status_allows_local_fallback(&status_reason) {
        if let Some((env_name, api_key)) = optional_local_api_key_fallback(target, true) {
            tracing::warn!(
                provider_id = %target.id,
                env_name = %env_name,
                status_reason = %status_reason,
                "connected provider-key resolution fell back to local environment key"
            );
            let mut prepared = target.clone();
            prepared.api_key = api_key;
            return Ok(ConnectedTargetResolution::Ready(prepared));
        }
    }

    Ok(ConnectedTargetResolution::Inactive {
        status: access_inactive_status(&status_reason),
        message: access_inactive_message(&status_reason, &target.id),
        status_reason,
    })
}

fn estimate_declared_request_cost(
    state: &ActiveGatewayStateView<'_>,
    target: &super::providers::ProviderTarget,
    model_name: &str,
    prompt_tokens: u64,
    max_completion_tokens: u64,
) -> Option<f64> {
    state
        .provider_registry
        .as_ref()
        .and_then(|registry| registry.resolve_model_pricing(target, model_name))
        .map(|pricing| {
            pricing
                .compute_cost(prompt_tokens, max_completion_tokens)
                .request
        })
}

pub fn resolve_usage_pricing_context_with_estimate(
    requested_model: &str,
    state: &ActiveGatewayStateView<'_>,
    prompt_tokens: u64,
    max_completion_tokens: u64,
) -> UsagePricingContext {
    let requested_model = requested_model.trim();
    if let Some(target) = resolve_auto_target(requested_model, state) {
        let provider =
            crate::gateway::provider_catalog::normalized_provider_alias(&target.provider);
        let model = resolve_target_request_model(target, requested_model, None)
            .0
            .or_else(|| resolve_target_model_name(target).map(ToOwned::to_owned))
            .unwrap_or_else(|| requested_model.to_string());
        if !provider.is_empty() && !model.is_empty() {
            return UsagePricingContext {
                provider,
                model: model.clone(),
                estimated_cost_usd: estimate_declared_request_cost(
                    state,
                    target,
                    &model,
                    prompt_tokens,
                    max_completion_tokens,
                ),
            };
        }
    }

    let provider = infer_provider_from_model(requested_model)
        .unwrap_or_else(|| infer_provider_from_upstream(state.upstream_base));
    let model = requested_model.to_string();
    let estimated_cost_usd = state.provider_registry.as_ref().and_then(|registry| {
        registry
            .targets
            .iter()
            .find(|target| {
                crate::gateway::provider_catalog::normalized_provider_alias(&target.provider)
                    == provider
                    && target_supports_model(target, &model)
            })
            .and_then(|target| {
                estimate_declared_request_cost(
                    state,
                    target,
                    &model,
                    prompt_tokens,
                    max_completion_tokens,
                )
            })
    });

    UsagePricingContext {
        provider,
        model,
        estimated_cost_usd,
    }
}

#[cfg(test)]
#[path = "server_tests/audio_preflight_validation_tests.rs"]
mod audio_preflight_validation_tests;
#[cfg(test)]
#[path = "server_tests/comprehensive_server_tests.rs"]
mod comprehensive_server_tests;
#[cfg(test)]
#[path = "server_tests/connected_mode_pull_tests.rs"]
mod connected_mode_pull_tests;
#[cfg(test)]
#[path = "server_tests/coverage_expansion_server_tests.rs"]
mod coverage_expansion_server_tests;
#[cfg(test)]
#[path = "server_tests/coverage_gap_server_tests.rs"]
mod coverage_gap_server_tests;
#[cfg(test)]
#[path = "server_tests/coverage_server_helpers_tests.rs"]
mod coverage_server_helpers_tests;
#[cfg(test)]
#[path = "server_tests/deep_coverage_phase2_tests.rs"]
mod deep_coverage_phase2_tests;
#[cfg(test)]
#[path = "server_tests/deep_coverage_tests.rs"]
mod deep_coverage_tests;
#[cfg(test)]
#[path = "server_tests/direct_function_coverage_tests.rs"]
mod direct_function_coverage_tests;
#[cfg(test)]
#[path = "server_tests/line_level_coverage_tests.rs"]
mod line_level_coverage_tests;
#[cfg(test)]
#[path = "server_tests/managed_public_endpoint_tests.rs"]
mod managed_public_endpoint_tests;
#[cfg(test)]
#[path = "server_tests/optional_control_plane_failure_tests.rs"]
mod optional_control_plane_failure_tests;
#[cfg(test)]
#[path = "server_tests/provider_runtime_resolution_tests.rs"]
mod provider_runtime_resolution_tests;
#[cfg(test)]
#[path = "server_tests/pure_helper_tests.rs"]
mod pure_helper_tests;
#[cfg(test)]
#[cfg(test)]
#[path = "server_tests/wildcard_model_tests.rs"]
mod wildcard_model_tests;
