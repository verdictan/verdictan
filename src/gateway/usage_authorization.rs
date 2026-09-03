// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Gateway-side usage-authorization contract and attribution.
//!
//! This module owns the neutral usage-authorization wire contract that the
//! gateway shares with the control plane, the client calls for the four
//! `/v1/gateway/usage-authorizations` routes, and execution-context validation.
//!
//! The organization owns every upstream provider credential, so the contract
//! has no caller-controlled credential source. The control plane derives the
//! credential origin from the resolved organization configuration.

use chrono::{DateTime, Utc};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct UsageExecutionAttribution {
    /// Stable execution identity shared across authorize, spend ingest, and complete.
    pub request_id: Option<String>,
    /// Runner-session identity when the request is part of a gateway execution.
    pub gateway_execution_session_id: Option<String>,
    /// Canonical execution surface persisted by the control plane.
    pub execution_surface: Option<String>,
    pub region_key: Option<String>,
    pub publication_key: Option<String>,
    pub active_revision_id: Option<String>,
    pub requested_region_group: Option<String>,
    pub selected_region_group: Option<String>,
    /// Conversation UUID for per-conversation cost attribution.
    pub conversation_id: Option<String>,
}

pub(crate) fn validate_publication_selection_tuple_fields(
    publication_key: Option<&str>,
    active_revision_id: Option<&str>,
    selected_region_group: Option<&str>,
) -> Result<(), anyhow::Error> {
    let publication_key = publication_key
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let active_revision_id = active_revision_id
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let selected_region_group = selected_region_group
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if active_revision_id.is_some() && publication_key.is_none() {
        anyhow::bail!("publication_key is required when active_revision_id is provided");
    }

    if selected_region_group.is_some() && publication_key.is_none() {
        anyhow::bail!("publication_key is required when selected_region_group is provided");
    }

    if selected_region_group.is_some() && active_revision_id.is_none() {
        anyhow::bail!("active_revision_id is required when selected_region_group is provided");
    }

    Ok(())
}

impl UsageExecutionAttribution {
    pub(crate) fn validate_publication_selection_tuple(&self) -> Result<(), anyhow::Error> {
        validate_publication_selection_tuple_fields(
            self.publication_key.as_deref(),
            self.active_revision_id.as_deref(),
            self.selected_region_group.as_deref(),
        )
    }
}

// ─── Usage-authorization wire contract ───────────────────────────────────────

/// Schema identifier of the neutral usage-authorization document.
pub(crate) const USAGE_AUTHORIZATION_SCHEMA_VERSION: &str = "usage-authorization/v1";

const USAGE_AUTHORIZATION_EVALUATE_PATH: &str = "v1/gateway/usage-authorizations/evaluate";
const USAGE_AUTHORIZATION_PATH: &str = "v1/gateway/usage-authorizations";

/// Request family accepted by the control-plane usage-authorization routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageAuthorizationRequestFamily {
    Chat,
    Completions,
    Responses,
    Messages,
    Embeddings,
    Audio,
    Moderation,
    Websocket,
}

impl UsageAuthorizationRequestFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Completions => "completions",
            Self::Responses => "responses",
            Self::Messages => "messages",
            Self::Embeddings => "embeddings",
            Self::Audio => "audio",
            Self::Moderation => "moderation",
            Self::Websocket => "websocket",
        }
    }
}

impl std::fmt::Display for UsageAuthorizationRequestFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle state of one usage authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageAuthorizationState {
    Authorized,
    Dispatched,
    Completed,
    Released,
}

impl UsageAuthorizationState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Dispatched => "dispatched",
            Self::Completed => "completed",
            Self::Released => "released",
        }
    }

    /// Returns `true` when the authorization reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Released)
    }
}

impl std::fmt::Display for UsageAuthorizationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Delivery path that the gateway uses for the authorized request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageAuthorizationDeliveryKind {
    Upstream,
    SemanticCache,
}

/// Provider idempotency capability for one dispatch attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageAuthorizationProviderIdempotency {
    Supported,
    Unsupported,
}

/// Declared usage of one request. The control plane prices this declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageAuthorizationUsage {
    pub input_tokens: u64,
    pub max_output_tokens: u64,
    pub request_units: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pricing_snapshot_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asserted_estimate_usd: Option<String>,
}

/// Access decision that the control-plane policy evaluation returns.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode")]
pub enum UsageAuthorizationAccessDecision {
    #[serde(rename = "unrestricted")]
    Unrestricted,
    #[serde(rename = "restricted")]
    Restricted {
        allowed: bool,
        matched_policy_ids: Vec<String>,
        denial_reason: Option<String>,
        limits: UsageAuthorizationAccessLimits,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct UsageAuthorizationAccessLimits {
    pub requests_per_minute: Option<u64>,
    pub tokens_per_minute: Option<u64>,
    pub max_context_tokens: Option<u64>,
}

/// One budget window that applies to the evaluated request.
#[derive(Debug, Clone, Deserialize)]
pub struct UsageAuthorizationBudgetEntry {
    pub kind: String,
    pub source_kind: String,
    pub source_policy_id: String,
    pub scope_type: String,
    pub scope_id: Option<String>,
    pub currency: String,
    pub limit: String,
    pub spent: String,
    pub outstanding_reservations: String,
    pub remaining: String,
    pub timezone: String,
    pub week_starts_on: String,
    pub month_anchor_day: i16,
    pub starts_at: String,
    pub ends_at: String,
}

/// Signed policy document that the evaluate route returns.
#[derive(Debug, Clone, Deserialize)]
pub struct UsageAuthorizationDocument {
    pub schema_version: String,
    pub policy_version: String,
    pub policy_sha256: String,
    pub document_sha256: String,
    pub issued_at: String,
    pub expires_at: String,
    pub binding: UsageAuthorizationDocumentBinding,
    pub access: UsageAuthorizationAccessDecision,
    pub budgets: Vec<UsageAuthorizationBudgetEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UsageAuthorizationDocumentBinding {
    pub organization_id: String,
    pub gateway_id: String,
    pub subject_token_id: String,
    pub project_id: Option<String>,
    pub configuration_id: Option<String>,
    pub agent_id: Option<String>,
    pub provider: String,
    pub model: String,
    pub request_family: UsageAuthorizationRequestFamily,
    pub usage_category: String,
}

impl UsageAuthorizationDocument {
    /// Returns `true` when the document lets the request continue.
    pub fn is_allowed(&self) -> bool {
        match &self.access {
            UsageAuthorizationAccessDecision::Unrestricted => true,
            UsageAuthorizationAccessDecision::Restricted { allowed, .. } => *allowed,
        }
    }

    /// Returns the denial reason when the document denies the request.
    pub fn denial_reason(&self) -> Option<&str> {
        match &self.access {
            UsageAuthorizationAccessDecision::Restricted {
                allowed: false,
                denial_reason,
                ..
            } => denial_reason.as_deref(),
            _ => None,
        }
    }

    /// Returns `true` when any budget window has no remaining amount.
    pub fn has_exhausted_budget(&self) -> bool {
        self.budgets.iter().any(|budget| {
            budget
                .remaining
                .parse::<f64>()
                .map(|value| value <= 0.0)
                .unwrap_or(false)
        })
    }

    /// Returns `true` when the document keeps policy identity and is not expired.
    pub fn is_fresh(&self, now: DateTime<Utc>) -> bool {
        if self.policy_version.trim().is_empty() || self.policy_sha256.trim().is_empty() {
            return false;
        }
        DateTime::parse_from_rfc3339(&self.expires_at)
            .map(|expires| now < expires.with_timezone(&Utc))
            .unwrap_or(false)
    }
}

/// Normalize an optional binding id to a canonical lowercase-hyphenated UUID
/// string, or `None` when the value is absent, blank, or not a UUID.
///
/// The evaluate and authorization wire contract requires every binding id to be
/// a lowercase hyphenated UUID string. The nullable binding fields
/// (`project_id`, `configuration_id`, `agent_id`) must therefore be sent as
/// `null` rather than as a non-UUID runtime label, and the required
/// `subject_token_id` must resolve to a UUID — callers treat `None` as
/// fail-closed and must not open an authorization call without it. A valid but
/// non-canonical UUID (for example uppercase, simple, or braced form) is
/// normalized to its canonical lowercase-hyphenated representation so the
/// emitted value always matches the wire grammar.
pub fn normalize_binding_uuid(value: Option<&str>) -> Option<String> {
    let raw = value
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())?;
    uuid::Uuid::parse_str(raw)
        .ok()
        .map(|parsed| parsed.hyphenated().to_string())
}

/// Format an optional USD estimate as a canonical nonnegative decimal string for
/// the `asserted_estimate_usd` wire field: no sign, no exponent, no trailing
/// fractional zeros; zero (or an absent, negative, or non-finite input) renders
/// as `"0"`. Matches the API's `canonical_decimal` output shape.
pub fn canonical_estimate_usd(value: Option<f64>) -> String {
    // `from_f64_retain` preserves the exact (imprecise) f64 expansion, so round to
    // a bounded precision before normalizing to produce a stable canonical string.
    let decimal = value
        .filter(|candidate| candidate.is_finite() && *candidate > 0.0)
        .and_then(rust_decimal::Decimal::from_f64_retain)
        .map(|parsed| parsed.round_dp(12).normalize())
        .unwrap_or(rust_decimal::Decimal::ZERO);
    if decimal.is_zero() {
        return "0".to_string();
    }
    let rendered = decimal.to_string();
    rendered
        .strip_prefix('+')
        .map(str::to_string)
        .unwrap_or(rendered)
}

/// Body of `POST /v1/gateway/usage-authorizations/evaluate`.
#[derive(Debug, Clone, Serialize)]
pub struct UsageAuthorizationEvaluateRequest {
    pub subject_token_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    pub provider: String,
    pub model: String,
    pub request_family: UsageAuthorizationRequestFamily,
    pub usage: UsageAuthorizationUsage,
}

/// Request binding that identifies the authorized execution context.
#[derive(Debug, Clone, Serialize)]
pub struct UsageAuthorizationBinding {
    pub subject_token_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    pub provider: String,
    pub model: String,
    pub request_family: UsageAuthorizationRequestFamily,
}

/// Body of `POST /v1/gateway/usage-authorizations`.
///
/// The body has no credential-source field. The control plane derives the
/// credential origin from the organization configuration.
#[derive(Debug, Clone, Serialize)]
pub struct UsageAuthorizationCreateRequest {
    pub request_id: String,
    pub delivery_kind: UsageAuthorizationDeliveryKind,
    pub binding: UsageAuthorizationBinding,
    pub usage: UsageAuthorizationUsage,
    pub accepted_policy_version: String,
    pub accepted_policy_sha256: String,
}

/// Authoritative price estimate that the control plane froze for the request.
#[derive(Debug, Clone, Deserialize)]
pub struct UsageAuthorizationCostEstimate {
    pub pricing_snapshot_id: String,
    pub authoritative_estimate_usd: String,
    #[serde(default)]
    pub unit_prices: BTreeMap<String, String>,
}

/// Response of `POST /v1/gateway/usage-authorizations`.
#[derive(Debug, Clone, Deserialize)]
pub struct UsageAuthorizationRecord {
    pub gateway_usage_authorization_id: String,
    pub state: UsageAuthorizationState,
    pub usage_at: String,
    pub cost_estimate: UsageAuthorizationCostEstimate,
    pub document: UsageAuthorizationDocument,
}

/// Body of `POST /v1/gateway/usage-authorizations/{id}/dispatch`.
#[derive(Debug, Clone, Serialize)]
pub struct UsageAuthorizationDispatchRequest {
    pub attempt_id: String,
    pub provider_idempotency: UsageAuthorizationProviderIdempotency,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_idempotency_key: Option<String>,
}

/// Response of `POST /v1/gateway/usage-authorizations/{id}/dispatch`.
#[derive(Debug, Clone, Deserialize)]
pub struct UsageAuthorizationDispatchResponse {
    pub gateway_usage_authorization_id: String,
    pub state: UsageAuthorizationState,
    pub attempt_id: String,
}

/// Body of `POST /v1/gateway/usage-authorizations/{id}/complete`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome")]
pub enum UsageAuthorizationCompleteRequest {
    /// The provider returned usage for the authorized request.
    #[serde(rename = "completed")]
    Completed {
        input_tokens: u64,
        output_tokens: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        cached_input_tokens: Option<u64>,
        // The gateway holds no pricing authority. The control plane settles
        // from the snapshot that it froze on the authorization and only
        // cross-checks a supplied identifier. Never invent an identifier.
        #[serde(skip_serializing_if = "Option::is_none")]
        pricing_snapshot_id: Option<String>,
    },
    /// The authorized request did not reach the provider.
    #[serde(rename = "released")]
    Released { reason: String },
}

/// Response of `POST /v1/gateway/usage-authorizations/{id}/complete`.
#[derive(Debug, Clone, Deserialize)]
pub struct UsageAuthorizationCompletion {
    pub gateway_usage_authorization_id: String,
    pub state: UsageAuthorizationState,
    #[serde(default)]
    pub spend_id: Option<String>,
    #[serde(default)]
    pub input_tokens: u64,
    #[serde(default)]
    pub output_tokens: u64,
    #[serde(default)]
    pub cached_input_tokens: u64,
    pub actual_cost_usd: String,
    #[serde(default)]
    pub pricing_snapshot_id: Option<String>,
    #[serde(default)]
    pub release_reason: Option<String>,
    pub usage_at: String,
}

/// Control-plane error code of the usage-authorization contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageAuthorizationErrorCode {
    AccessDenied,
    AuthorizationNotFound,
    BudgetExceeded,
    CompletionConflict,
    IdempotencyKeyForbidden,
    IdempotencyKeyRequired,
    PolicyDrift,
    RateLimitExceeded,
    Other(String),
}

impl UsageAuthorizationErrorCode {
    /// Map one control-plane error value to the usage-authorization contract.
    pub fn from_wire(code: &str) -> Self {
        match code.trim() {
            "usage_authorization.access_denied" => Self::AccessDenied,
            "usage_authorization.authorization_not_found" => Self::AuthorizationNotFound,
            "usage_authorization.budget_exceeded" => Self::BudgetExceeded,
            "usage_authorization.completion_conflict" => Self::CompletionConflict,
            "usage_authorization.idempotency_key_forbidden" => Self::IdempotencyKeyForbidden,
            "usage_authorization.idempotency_key_required" => Self::IdempotencyKeyRequired,
            "usage_authorization.policy_drift" => Self::PolicyDrift,
            "usage_authorization.rate_limit_exceeded" => Self::RateLimitExceeded,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::AccessDenied => "usage_authorization.access_denied",
            Self::AuthorizationNotFound => "usage_authorization.authorization_not_found",
            Self::BudgetExceeded => "usage_authorization.budget_exceeded",
            Self::CompletionConflict => "usage_authorization.completion_conflict",
            Self::IdempotencyKeyForbidden => "usage_authorization.idempotency_key_forbidden",
            Self::IdempotencyKeyRequired => "usage_authorization.idempotency_key_required",
            Self::PolicyDrift => "usage_authorization.policy_drift",
            Self::RateLimitExceeded => "usage_authorization.rate_limit_exceeded",
            Self::Other(code) => code.as_str(),
        }
    }
}

impl std::fmt::Display for UsageAuthorizationErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Failure of one usage-authorization control-plane call.
#[derive(Debug, thiserror::Error)]
pub enum UsageAuthorizationError {
    #[error("invalid control-plane endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("usage-authorization transport failure: {0}")]
    Transport(String),
    #[error("invalid usage-authorization response: {0}")]
    InvalidResponse(String),
    #[error("usage-authorization rejected: status={status} code={code} message={message}")]
    Rejected {
        status: u16,
        code: UsageAuthorizationErrorCode,
        message: String,
    },
}

impl UsageAuthorizationError {
    /// Return the control-plane error code when the control plane rejected the call.
    pub fn error_code(&self) -> Option<&UsageAuthorizationErrorCode> {
        match self {
            Self::Rejected { code, .. } => Some(code),
            _ => None,
        }
    }

    /// Return the HTTP status when the control plane rejected the call.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Rejected { status, .. } => Some(*status),
            _ => None,
        }
    }
}

fn usage_authorization_url(api_base_url: &str, path: &str) -> Result<Url, UsageAuthorizationError> {
    let base = api_base_url.trim();
    if base.is_empty() {
        return Err(UsageAuthorizationError::InvalidEndpoint(
            "api_base_url must not be empty".to_string(),
        ));
    }
    let base = format!("{}/", base.trim_end_matches('/'));
    let base = Url::parse(&base).map_err(|error| {
        UsageAuthorizationError::InvalidEndpoint(format!("invalid api_base_url: {error}"))
    })?;
    base.join(path.trim_start_matches('/')).map_err(|error| {
        UsageAuthorizationError::InvalidEndpoint(format!("invalid control-plane path: {error}"))
    })
}

/// Build the rejection error from the standard control-plane error envelope.
fn rejected_error(status: u16, body: &str) -> UsageAuthorizationError {
    let envelope: Option<serde_json::Value> = serde_json::from_str(body).ok();
    let error = envelope.as_ref().and_then(|value| value.get("error"));
    let code = error
        .and_then(|error| error.get("code"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("usage_authorization.unknown_error");
    let message = error
        .and_then(|error| error.get("message"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or(body)
        .to_string();
    UsageAuthorizationError::Rejected {
        status,
        code: UsageAuthorizationErrorCode::from_wire(code),
        message,
    }
}

fn record_usage_authorization_metric(operation: &str, outcome: &str) {
    super::metrics::record_usage_authorization_control_plane(operation, outcome);
}

fn usage_authorization_retry_policy() -> crate::retry::RetryPolicy {
    crate::retry::RetryPolicy {
        max_retries: 2,
        base_delay: Duration::from_millis(100),
        multiplier: 2.0,
        max_delay: Duration::from_millis(500),
        jitter: 0.2,
    }
}

/// Call `POST /v1/gateway/usage-authorizations/evaluate`.
///
/// Evaluates access policy, rate ceilings, and budget state for one request
/// context and returns the signed usage-authorization document.
pub async fn evaluate_usage_authorization(
    client: &reqwest::Client,
    api_base_url: &str,
    request: &UsageAuthorizationEvaluateRequest,
) -> Result<UsageAuthorizationDocument, UsageAuthorizationError> {
    let url = usage_authorization_url(api_base_url, USAGE_AUTHORIZATION_EVALUATE_PATH)?;

    let response = client
        .post(url)
        .json(request)
        .send()
        .await
        .map_err(|error| {
            record_usage_authorization_metric("usage_authorization_evaluate", "transport_error");
            UsageAuthorizationError::Transport(format!("evaluate request failed: {error}"))
        })?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        record_usage_authorization_metric("usage_authorization_evaluate", "error");
        return Err(rejected_error(status.as_u16(), &body));
    }

    let document: UsageAuthorizationDocument = response.json().await.map_err(|error| {
        record_usage_authorization_metric("usage_authorization_evaluate", "parse_error");
        UsageAuthorizationError::InvalidResponse(format!("evaluate response invalid: {error}"))
    })?;

    record_usage_authorization_metric("usage_authorization_evaluate", "success");
    tracing::debug!(
        policy_version = %document.policy_version,
        allowed = document.is_allowed(),
        budgets = document.budgets.len(),
        "usage-authorization evaluate completed"
    );
    Ok(document)
}

/// Call `POST /v1/gateway/usage-authorizations`.
///
/// Creates the authorization that holds the estimated cost. The caller must
/// send the `policy_version` and `policy_sha256` of an accepted evaluate
/// document. Transient transport and server failures use a bounded retry.
pub async fn create_usage_authorization(
    client: &reqwest::Client,
    api_base_url: &str,
    request: &UsageAuthorizationCreateRequest,
) -> Result<UsageAuthorizationRecord, UsageAuthorizationError> {
    let url = usage_authorization_url(api_base_url, USAGE_AUTHORIZATION_PATH)?;
    let policy = usage_authorization_retry_policy();

    let mut last_error: Option<UsageAuthorizationError> = None;
    for attempt in 0..=policy.max_retries {
        let response = match client.post(url.clone()).json(request).send().await {
            Ok(response) => response,
            Err(error) => {
                let retryable =
                    (error.is_timeout() || error.is_connect()) && attempt < policy.max_retries;
                last_error = Some(UsageAuthorizationError::Transport(format!(
                    "authorize request failed: {error}"
                )));
                if retryable {
                    let delay = crate::retry::compute_delay(&policy, attempt + 1);
                    tracing::warn!(
                        attempt = attempt + 1,
                        delay_ms = delay.as_millis() as u64,
                        "usage-authorization authorize transport error; retrying"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                record_usage_authorization_metric(
                    "usage_authorization_authorize",
                    "transport_error",
                );
                return Err(last_error.unwrap_or_else(|| {
                    UsageAuthorizationError::Transport(
                        "authorize retry ended without a captured error".to_string(),
                    )
                }));
            }
        };

        let status = response.status();
        if status.is_success() {
            let record: UsageAuthorizationRecord = response.json().await.map_err(|error| {
                record_usage_authorization_metric("usage_authorization_authorize", "parse_error");
                UsageAuthorizationError::InvalidResponse(format!(
                    "authorize response invalid: {error}"
                ))
            })?;
            record_usage_authorization_metric("usage_authorization_authorize", "success");
            tracing::debug!(
                gateway_usage_authorization_id = %record.gateway_usage_authorization_id,
                state = %record.state,
                estimated_cost_usd = %record.cost_estimate.authoritative_estimate_usd,
                "usage authorization created"
            );
            return Ok(record);
        }

        let retryable = crate::retry::classify_status(status.as_u16())
            == crate::retry::RetryClassification::Transient
            && attempt < policy.max_retries;
        let body = response.text().await.unwrap_or_default();
        last_error = Some(rejected_error(status.as_u16(), &body));
        if retryable {
            let delay = crate::retry::compute_delay(&policy, attempt + 1);
            tracing::warn!(
                attempt = attempt + 1,
                status = %status,
                delay_ms = delay.as_millis() as u64,
                "usage-authorization authorize server error; retrying"
            );
            tokio::time::sleep(delay).await;
            continue;
        }
        record_usage_authorization_metric("usage_authorization_authorize", "error");
        return Err(last_error.unwrap_or_else(|| {
            UsageAuthorizationError::Transport(
                "authorize retry ended without a captured error".to_string(),
            )
        }));
    }

    record_usage_authorization_metric("usage_authorization_authorize", "exhausted");
    Err(last_error.unwrap_or_else(|| {
        UsageAuthorizationError::Transport("authorize exhausted retries".to_string())
    }))
}

/// Call `POST /v1/gateway/usage-authorizations/{id}/dispatch`.
///
/// Tells the control plane that the gateway starts one upstream attempt.
pub async fn dispatch_usage_authorization(
    client: &reqwest::Client,
    api_base_url: &str,
    gateway_usage_authorization_id: &str,
    request: &UsageAuthorizationDispatchRequest,
) -> Result<UsageAuthorizationDispatchResponse, UsageAuthorizationError> {
    let path = format!("{USAGE_AUTHORIZATION_PATH}/{gateway_usage_authorization_id}/dispatch");
    let url = usage_authorization_url(api_base_url, &path)?;

    let response = client
        .post(url)
        .json(request)
        .send()
        .await
        .map_err(|error| {
            record_usage_authorization_metric("usage_authorization_dispatch", "transport_error");
            UsageAuthorizationError::Transport(format!("dispatch request failed: {error}"))
        })?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        record_usage_authorization_metric("usage_authorization_dispatch", "error");
        return Err(rejected_error(status.as_u16(), &body));
    }

    let dispatch: UsageAuthorizationDispatchResponse = response.json().await.map_err(|error| {
        record_usage_authorization_metric("usage_authorization_dispatch", "parse_error");
        UsageAuthorizationError::InvalidResponse(format!("dispatch response invalid: {error}"))
    })?;

    record_usage_authorization_metric("usage_authorization_dispatch", "success");
    tracing::debug!(
        gateway_usage_authorization_id = %gateway_usage_authorization_id,
        attempt_id = %dispatch.attempt_id,
        state = %dispatch.state,
        "usage-authorization dispatch confirmed"
    );
    Ok(dispatch)
}

/// Call `POST /v1/gateway/usage-authorizations/{id}/complete`.
///
/// Reports the final outcome of one authorization. The control plane treats
/// completion as idempotent, so transient failures use a bounded retry.
pub async fn complete_usage_authorization(
    client: &reqwest::Client,
    api_base_url: &str,
    gateway_usage_authorization_id: &str,
    request: &UsageAuthorizationCompleteRequest,
) -> Result<UsageAuthorizationCompletion, UsageAuthorizationError> {
    let path = format!("{USAGE_AUTHORIZATION_PATH}/{gateway_usage_authorization_id}/complete");
    let url = usage_authorization_url(api_base_url, &path)?;
    let policy = usage_authorization_retry_policy();

    let mut last_error: Option<UsageAuthorizationError> = None;
    for attempt in 0..=policy.max_retries {
        let response = match client.post(url.clone()).json(request).send().await {
            Ok(response) => response,
            Err(error) => {
                let retryable =
                    (error.is_timeout() || error.is_connect()) && attempt < policy.max_retries;
                last_error = Some(UsageAuthorizationError::Transport(format!(
                    "complete request failed: {error}"
                )));
                if retryable {
                    let delay = crate::retry::compute_delay(&policy, attempt + 1);
                    tracing::warn!(
                        gateway_usage_authorization_id = %gateway_usage_authorization_id,
                        attempt = attempt + 1,
                        delay_ms = delay.as_millis() as u64,
                        "usage-authorization complete transport error; retrying"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                record_usage_authorization_metric(
                    "usage_authorization_complete",
                    "transport_error",
                );
                return Err(last_error.unwrap_or_else(|| {
                    UsageAuthorizationError::Transport(
                        "complete retry ended without a captured error".to_string(),
                    )
                }));
            }
        };

        let status = response.status();
        if status.is_success() {
            let completion: UsageAuthorizationCompletion =
                response.json().await.map_err(|error| {
                    record_usage_authorization_metric(
                        "usage_authorization_complete",
                        "parse_error",
                    );
                    UsageAuthorizationError::InvalidResponse(format!(
                        "complete response invalid: {error}"
                    ))
                })?;
            record_usage_authorization_metric("usage_authorization_complete", "success");
            tracing::debug!(
                gateway_usage_authorization_id = %gateway_usage_authorization_id,
                state = %completion.state,
                spend_id = ?completion.spend_id,
                "usage-authorization complete finished"
            );
            return Ok(completion);
        }

        let retryable = crate::retry::classify_status(status.as_u16())
            == crate::retry::RetryClassification::Transient
            && attempt < policy.max_retries;
        let body = response.text().await.unwrap_or_default();
        last_error = Some(rejected_error(status.as_u16(), &body));
        if retryable {
            let delay = crate::retry::compute_delay(&policy, attempt + 1);
            tracing::warn!(
                gateway_usage_authorization_id = %gateway_usage_authorization_id,
                attempt = attempt + 1,
                status = %status,
                delay_ms = delay.as_millis() as u64,
                "usage-authorization complete server error; retrying"
            );
            tokio::time::sleep(delay).await;
            continue;
        }
        record_usage_authorization_metric("usage_authorization_complete", "error");
        return Err(last_error.unwrap_or_else(|| {
            UsageAuthorizationError::Transport(
                "complete retry ended without a captured error".to_string(),
            )
        }));
    }

    record_usage_authorization_metric("usage_authorization_complete", "exhausted");
    Err(last_error.unwrap_or_else(|| {
        UsageAuthorizationError::Transport("complete exhausted retries".to_string())
    }))
}

/// Release one authorization that never reached the provider.
async fn release_usage_authorization(
    client: &reqwest::Client,
    api_base_url: &str,
    gateway_usage_authorization_id: &str,
    reason: &str,
) -> Result<UsageAuthorizationCompletion, UsageAuthorizationError> {
    complete_usage_authorization(
        client,
        api_base_url,
        gateway_usage_authorization_id,
        &UsageAuthorizationCompleteRequest::Released {
            reason: reason.to_string(),
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn normalize_binding_uuid_accepts_canonical_uuid() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            normalize_binding_uuid(Some(uuid)),
            Some(uuid.to_string()),
            "a canonical lowercase-hyphenated UUID must pass through unchanged"
        );
    }

    #[test]
    fn normalize_binding_uuid_normalizes_uppercase_and_simple_forms() {
        let canonical = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            normalize_binding_uuid(Some("550E8400-E29B-41D4-A716-446655440000")),
            Some(canonical.to_string()),
            "uppercase UUID must be normalized to lowercase-hyphenated"
        );
        assert_eq!(
            normalize_binding_uuid(Some("550e8400e29b41d4a716446655440000")),
            Some(canonical.to_string()),
            "simple (unhyphenated) UUID must be normalized to hyphenated"
        );
    }

    #[test]
    fn normalize_binding_uuid_rejects_non_uuid_runtime_labels() {
        assert_eq!(normalize_binding_uuid(Some("vk-billing-test")), None);
        assert_eq!(normalize_binding_uuid(Some("cfg-connected-billing")), None);
        assert_eq!(normalize_binding_uuid(Some("agent-abc")), None);
    }

    #[test]
    fn normalize_binding_uuid_treats_absent_and_blank_as_none() {
        assert_eq!(normalize_binding_uuid(None), None);
        assert_eq!(normalize_binding_uuid(Some("")), None);
        assert_eq!(normalize_binding_uuid(Some("   ")), None);
    }

    #[test]
    fn normalize_binding_uuid_trims_surrounding_whitespace() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            normalize_binding_uuid(Some("  550e8400-e29b-41d4-a716-446655440000  ")),
            Some(uuid.to_string())
        );
    }

    #[test]
    fn canonical_estimate_usd_formats_and_trims() {
        assert_eq!(canonical_estimate_usd(None), "0");
        assert_eq!(canonical_estimate_usd(Some(0.0)), "0");
        assert_eq!(canonical_estimate_usd(Some(-1.0)), "0");
        assert_eq!(canonical_estimate_usd(Some(f64::NAN)), "0");
        assert_eq!(canonical_estimate_usd(Some(2.5)), "2.5");
        assert_eq!(canonical_estimate_usd(Some(0.0025)), "0.0025");
        let rendered = canonical_estimate_usd(Some(1.2500));
        assert_eq!(rendered, "1.25");
        assert!(!rendered.starts_with('+'));
    }

    #[test]
    fn validate_tuple_all_none_ok() {
        assert!(validate_publication_selection_tuple_fields(None, None, None).is_ok());
    }

    #[test]
    fn validate_tuple_revision_without_pub_fails() {
        assert!(validate_publication_selection_tuple_fields(None, Some("rev-1"), None).is_err());
    }

    #[test]
    fn attribution_validate_delegates_to_fields() {
        let attr = UsageExecutionAttribution {
            active_revision_id: Some("rev-1".into()),
            publication_key: None,
            ..Default::default()
        };
        assert!(attr.validate_publication_selection_tuple().is_err());
    }

    // ── Usage-authorization contract ─────────────────────────────────────

    use axum::{extract::Path, http::StatusCode, response::IntoResponse, routing::post, Router};
    use serde_json::{json, Value};

    async fn start_server(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("test server addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve test server");
        });
        (format!("http://{addr}"), handle)
    }

    fn sample_usage() -> UsageAuthorizationUsage {
        UsageAuthorizationUsage {
            input_tokens: 100,
            max_output_tokens: 200,
            request_units: 1,
            pricing_snapshot_id: None,
            asserted_estimate_usd: None,
        }
    }

    fn sample_binding() -> UsageAuthorizationBinding {
        UsageAuthorizationBinding {
            subject_token_id: "tok-1".to_string(),
            project_id: None,
            configuration_id: None,
            agent_id: None,
            provider: "openai".to_string(),
            model: "gpt-5.4".to_string(),
            request_family: UsageAuthorizationRequestFamily::Chat,
        }
    }

    fn sample_document_json() -> Value {
        json!({
            "schema_version": USAGE_AUTHORIZATION_SCHEMA_VERSION,
            "policy_version": "a".repeat(64),
            "policy_sha256": "b".repeat(64),
            "document_sha256": "c".repeat(64),
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T01:00:00Z",
            "binding": {
                "organization_id": "org-1",
                "gateway_id": "gw-1",
                "subject_token_id": "tok-1",
                "provider": "openai",
                "model": "gpt-5.4",
                "request_family": "chat",
                "usage_category": "gateway_llm"
            },
            "access": { "mode": "unrestricted" },
            "budgets": []
        })
    }

    fn parse_document() -> UsageAuthorizationDocument {
        serde_json::from_value(sample_document_json()).unwrap()
    }

    #[test]
    fn evaluate_request_omits_credential_source() {
        let request = UsageAuthorizationEvaluateRequest {
            subject_token_id: "tok-1".to_string(),
            project_id: None,
            configuration_id: None,
            agent_id: Some("agent-1".to_string()),
            provider: "openai".to_string(),
            model: "gpt-5.4".to_string(),
            request_family: UsageAuthorizationRequestFamily::Chat,
            usage: sample_usage(),
        };
        let body = serde_json::to_value(&request).unwrap();
        assert_eq!(body["request_family"], "chat");
        assert_eq!(body["agent_id"], "agent-1");
        assert!(body.get("project_id").is_none());
        assert!(body.get("credential_source").is_none());
    }

    #[test]
    fn create_request_omits_credential_source() {
        let request = UsageAuthorizationCreateRequest {
            request_id: "req-1".to_string(),
            delivery_kind: UsageAuthorizationDeliveryKind::Upstream,
            binding: sample_binding(),
            usage: sample_usage(),
            accepted_policy_version: "a".repeat(64),
            accepted_policy_sha256: "b".repeat(64),
        };
        let body = serde_json::to_value(&request).unwrap();
        assert_eq!(body["delivery_kind"], "upstream");
        assert!(body.get("credential_source").is_none());
        assert!(body["binding"].get("credential_source").is_none());
    }

    #[test]
    fn complete_request_serializes_neutral_outcomes() {
        let completed = serde_json::to_value(UsageAuthorizationCompleteRequest::Completed {
            input_tokens: 100,
            output_tokens: 20,
            cached_input_tokens: Some(4),
            pricing_snapshot_id: None,
        })
        .unwrap();
        assert_eq!(completed["outcome"], "completed");
        assert_eq!(completed["cached_input_tokens"], 4);
        assert!(completed.get("pricing_snapshot_id").is_none());
        assert!(completed.get("source_cost").is_none());
        assert!(completed.get("fx_snapshot_id").is_none());

        let released = serde_json::to_value(UsageAuthorizationCompleteRequest::Released {
            reason: "upstream_unavailable".to_string(),
        })
        .unwrap();
        assert_eq!(released["outcome"], "released");
        assert_eq!(released["reason"], "upstream_unavailable");
    }

    #[test]
    fn document_freshness_requires_identity_and_expiry() {
        let document = parse_document();
        let inside = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let after = chrono::DateTime::parse_from_rfc3339("2026-01-01T01:00:01Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(document.is_fresh(inside));
        assert!(!document.is_fresh(after));

        let mut without_digest = parse_document();
        without_digest.policy_sha256.clear();
        assert!(!without_digest.is_fresh(inside));
    }

    #[test]
    fn document_reports_access_and_budget_state() {
        let allowed = parse_document();
        assert!(allowed.is_allowed());
        assert!(allowed.denial_reason().is_none());
        assert!(!allowed.has_exhausted_budget());

        let mut denied_json = sample_document_json();
        denied_json["access"] = json!({
            "mode": "restricted",
            "allowed": false,
            "matched_policy_ids": ["pol-1"],
            "denial_reason": "model not in allowlist",
            "limits": {}
        });
        let denied: UsageAuthorizationDocument = serde_json::from_value(denied_json).unwrap();
        assert!(!denied.is_allowed());
        assert_eq!(denied.denial_reason(), Some("model not in allowlist"));
    }

    #[test]
    fn state_values_map_to_the_contract() {
        let state: UsageAuthorizationState = serde_json::from_value(json!("dispatched")).unwrap();
        assert_eq!(state, UsageAuthorizationState::Dispatched);
        assert!(!state.is_terminal());
        assert!(UsageAuthorizationState::Completed.is_terminal());
        assert!(UsageAuthorizationState::Released.is_terminal());
        assert_eq!(UsageAuthorizationState::Authorized.as_str(), "authorized");
        assert!(serde_json::from_value::<UsageAuthorizationState>(json!("settled")).is_err());
    }

    #[test]
    fn error_codes_map_to_the_contract() {
        assert_eq!(
            UsageAuthorizationErrorCode::from_wire("usage_authorization.budget_exceeded"),
            UsageAuthorizationErrorCode::BudgetExceeded
        );
        assert_eq!(
            UsageAuthorizationErrorCode::from_wire("usage_authorization.rate_limit_exceeded"),
            UsageAuthorizationErrorCode::RateLimitExceeded
        );
        assert_eq!(
            UsageAuthorizationErrorCode::from_wire("usage_authorization.policy_drift"),
            UsageAuthorizationErrorCode::PolicyDrift
        );
        assert_eq!(
            UsageAuthorizationErrorCode::from_wire("unrecognized_namespace.policy_drift"),
            UsageAuthorizationErrorCode::Other("unrecognized_namespace.policy_drift".to_string())
        );
    }

    #[test]
    fn rejected_error_reads_the_control_plane_envelope() {
        let body = json!({
            "error": {
                "status": 429,
                "code": "usage_authorization.budget_exceeded",
                "message": "daily budget exceeded"
            }
        })
        .to_string();
        let error = rejected_error(429, &body);
        assert_eq!(error.status(), Some(429));
        assert_eq!(
            error.error_code(),
            Some(&UsageAuthorizationErrorCode::BudgetExceeded)
        );
        assert!(error.to_string().contains("daily budget exceeded"));

        let unparsed = rejected_error(500, "not-json");
        assert_eq!(
            unparsed.error_code(),
            Some(&UsageAuthorizationErrorCode::Other(
                "usage_authorization.unknown_error".to_string()
            ))
        );
    }

    #[test]
    fn url_builder_rejects_an_empty_base() {
        assert!(matches!(
            usage_authorization_url("", USAGE_AUTHORIZATION_PATH),
            Err(UsageAuthorizationError::InvalidEndpoint(_))
        ));
        let url = usage_authorization_url("http://127.0.0.1:9/", USAGE_AUTHORIZATION_PATH).unwrap();
        assert_eq!(url.path(), "/v1/gateway/usage-authorizations");
    }

    #[tokio::test]
    async fn evaluate_calls_the_usage_authorization_route() {
        let app = Router::new().route(
            "/v1/gateway/usage-authorizations/evaluate",
            post(|| async { (StatusCode::OK, axum::Json(sample_document_json())).into_response() }),
        );
        let (base_url, handle) = start_server(app).await;
        let client = reqwest::Client::new();
        let request = UsageAuthorizationEvaluateRequest {
            subject_token_id: "tok-1".to_string(),
            project_id: None,
            configuration_id: None,
            agent_id: None,
            provider: "openai".to_string(),
            model: "gpt-5.4".to_string(),
            request_family: UsageAuthorizationRequestFamily::Chat,
            usage: sample_usage(),
        };

        let document = evaluate_usage_authorization(&client, &format!("{base_url}/"), &request)
            .await
            .expect("evaluate succeeds");
        assert_eq!(
            document.schema_version,
            USAGE_AUTHORIZATION_SCHEMA_VERSION.to_string()
        );
        assert!(document.is_allowed());

        handle.abort();
    }

    #[tokio::test]
    async fn create_calls_the_usage_authorization_route() {
        let app = Router::new().route(
            "/v1/gateway/usage-authorizations",
            post(|| async {
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "gateway_usage_authorization_id": "auth-1",
                        "state": "authorized",
                        "usage_at": "2026-01-01T00:00:00Z",
                        "cost_estimate": {
                            "pricing_snapshot_id": "snap-1",
                            "authoritative_estimate_usd": "0.0025",
                            "unit_prices": { "input_per_1k": "0.003" }
                        },
                        "document": sample_document_json(),
                    })),
                )
                    .into_response()
            }),
        );
        let (base_url, handle) = start_server(app).await;
        let client = reqwest::Client::new();
        let request = UsageAuthorizationCreateRequest {
            request_id: "req-1".to_string(),
            delivery_kind: UsageAuthorizationDeliveryKind::Upstream,
            binding: sample_binding(),
            usage: sample_usage(),
            accepted_policy_version: "a".repeat(64),
            accepted_policy_sha256: "b".repeat(64),
        };

        let record = create_usage_authorization(&client, &base_url, &request)
            .await
            .expect("authorize succeeds");
        assert_eq!(record.gateway_usage_authorization_id, "auth-1");
        assert_eq!(record.state, UsageAuthorizationState::Authorized);
        assert_eq!(record.cost_estimate.authoritative_estimate_usd, "0.0025");
        assert_eq!(
            record.cost_estimate.unit_prices.get("input_per_1k"),
            Some(&"0.003".to_string())
        );

        handle.abort();
    }

    #[tokio::test]
    async fn dispatch_calls_the_usage_authorization_route() {
        let app = Router::new().route(
            "/v1/gateway/usage-authorizations/:id/dispatch",
            post(|Path(id): Path<String>| async move {
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "gateway_usage_authorization_id": id,
                        "state": "dispatched",
                        "attempt_id": "auth-1-attempt-1",
                    })),
                )
                    .into_response()
            }),
        );
        let (base_url, handle) = start_server(app).await;
        let client = reqwest::Client::new();
        let request = UsageAuthorizationDispatchRequest {
            attempt_id: "auth-1-attempt-1".to_string(),
            provider_idempotency: UsageAuthorizationProviderIdempotency::Supported,
            provider_idempotency_key: Some("idem-1".to_string()),
        };

        let dispatch = dispatch_usage_authorization(&client, &base_url, "auth-1", &request)
            .await
            .expect("dispatch succeeds");
        assert_eq!(dispatch.gateway_usage_authorization_id, "auth-1");
        assert_eq!(dispatch.state, UsageAuthorizationState::Dispatched);
        assert_eq!(dispatch.attempt_id, "auth-1-attempt-1");

        handle.abort();
    }

    #[tokio::test]
    async fn complete_and_release_call_the_usage_authorization_route() {
        let app = Router::new().route(
            "/v1/gateway/usage-authorizations/:id/complete",
            post(
                |Path(id): Path<String>, axum::Json(body): axum::Json<Value>| async move {
                    let released = body["outcome"] == "released";
                    (
                        StatusCode::OK,
                        axum::Json(json!({
                            "gateway_usage_authorization_id": id,
                            "state": if released { "released" } else { "completed" },
                            "spend_id": if released { Value::Null } else { json!("spend-1") },
                            "input_tokens": body["input_tokens"].as_u64().unwrap_or(0),
                            "output_tokens": body["output_tokens"].as_u64().unwrap_or(0),
                            "actual_cost_usd": if released { "0" } else { "0.0020" },
                            "pricing_snapshot_id": "snap-1",
                            "release_reason": body.get("reason").cloned().unwrap_or(Value::Null),
                            "usage_at": "2026-01-01T00:00:05Z",
                        })),
                    )
                        .into_response()
                },
            ),
        );
        let (base_url, handle) = start_server(app).await;
        let client = reqwest::Client::new();

        let completion = complete_usage_authorization(
            &client,
            &base_url,
            "auth-1",
            &UsageAuthorizationCompleteRequest::Completed {
                input_tokens: 100,
                output_tokens: 20,
                cached_input_tokens: None,
                pricing_snapshot_id: None,
            },
        )
        .await
        .expect("complete succeeds");
        assert_eq!(completion.state, UsageAuthorizationState::Completed);
        assert_eq!(completion.spend_id.as_deref(), Some("spend-1"));
        assert_eq!(completion.actual_cost_usd, "0.0020");
        assert_eq!(completion.input_tokens, 100);
        assert_eq!(completion.cached_input_tokens, 0);

        let released = release_usage_authorization(&client, &base_url, "auth-1", "policy_denied")
            .await
            .expect("release succeeds");
        assert_eq!(released.state, UsageAuthorizationState::Released);
        assert_eq!(released.release_reason.as_deref(), Some("policy_denied"));

        handle.abort();
    }

    #[tokio::test]
    async fn control_plane_rejection_maps_to_a_contract_error() {
        let app = Router::new().route(
            "/v1/gateway/usage-authorizations",
            post(|| async {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    axum::Json(json!({
                        "error": {
                            "status": 429,
                            "code": "usage_authorization.budget_exceeded",
                            "message": "daily budget exceeded"
                        }
                    })),
                )
                    .into_response()
            }),
        );
        let (base_url, handle) = start_server(app).await;
        let client = reqwest::Client::new();
        let request = UsageAuthorizationCreateRequest {
            request_id: "req-1".to_string(),
            delivery_kind: UsageAuthorizationDeliveryKind::Upstream,
            binding: sample_binding(),
            usage: sample_usage(),
            accepted_policy_version: "a".repeat(64),
            accepted_policy_sha256: "b".repeat(64),
        };

        let error = create_usage_authorization(&client, &base_url, &request)
            .await
            .expect_err("authorize is rejected");
        assert_eq!(error.status(), Some(429));
        assert_eq!(
            error.error_code(),
            Some(&UsageAuthorizationErrorCode::BudgetExceeded)
        );

        handle.abort();
    }
}
