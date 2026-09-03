// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Usage-authorization integration for the gateway request lifecycle.
//!
//! This module wires the four lifecycle stages (evaluate → authorize →
//! dispatch → complete) into the gateway's policy enforcement, streaming,
//! moderation, circuit breaker, retry, telemetry, and event pipeline.
//!
//! It is the single integration point between the usage-authorization client
//! calls in [`super::usage_authorization`] and the rest of the gateway runtime.
//!
//! The organization owns every upstream provider credential, so the pipeline
//! carries no credential-source choice and no platform financial outcome.
//! Pre-dispatch denials stay stable before any provider call: budget and rate
//! ceilings both return HTTP 429. See [`classify_authorize_denial`].

use std::time::{Duration, Instant};

use serde::Serialize;

use super::circuit_breaker::CircuitBreakerManager;
use super::usage_authorization::{
    UsageAuthorizationAccessDecision, UsageAuthorizationCompletion,
    UsageAuthorizationDispatchRequest, UsageAuthorizationDocument,
    UsageAuthorizationProviderIdempotency, UsageAuthorizationRequestFamily,
};

/// Error code returned when a policy document has no version or digest identity.
pub const USAGE_AUTHORIZATION_POLICY_UNAVAILABLE: &str = "usage_authorization_policy_unavailable";
/// Error code returned when a policy document is expired.
pub const USAGE_AUTHORIZATION_POLICY_STALE: &str = "usage_authorization_policy_stale";

/// Stable classification of control-plane authorization denials before provider calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeDenialKind {
    /// Hourly, daily, weekly, monthly, or lifetime spend ceiling exceeded.
    BudgetCeiling,
    /// RPM, TPM, or request-count ceiling exceeded.
    RateLimited,
}

/// Classify an authorization HTTP denial using status plus optional API error code.
///
/// Budget codes (`budget.*`, `*budget_exceeded*`) map to
/// [`AuthorizeDenialKind::BudgetCeiling`] even though they share HTTP 429 with
/// rate limits.
pub fn classify_authorize_denial(
    status: u16,
    error_code: Option<&str>,
) -> Option<AuthorizeDenialKind> {
    match status {
        429 => {
            let code = error_code.unwrap_or("");
            if code.starts_with("budget.") || code.contains("budget_exceeded") {
                Some(AuthorizeDenialKind::BudgetCeiling)
            } else {
                Some(AuthorizeDenialKind::RateLimited)
            }
        }
        _ => None,
    }
}

// ── Policy disposition ───────────────────────────────────────────────────────

/// Policy disposition from a usage-authorization evaluation. The gateway uses
/// it to decide how to continue with a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageAuthorizationDisposition {
    /// Request is allowed to proceed.
    Allow,
    /// Request is denied by policy.
    Deny { reason: String },
    /// Request must be audited but is allowed.
    Audit { policy_ids: Vec<String> },
    /// Request requires human escalation.
    Escalate { policy_ids: Vec<String> },
}

impl UsageAuthorizationDisposition {
    /// Derive the disposition from an evaluation document.
    pub fn from_document(document: &UsageAuthorizationDocument) -> Self {
        match &document.access {
            UsageAuthorizationAccessDecision::Unrestricted => Self::Allow,
            UsageAuthorizationAccessDecision::Restricted {
                allowed: true,
                matched_policy_ids,
                ..
            } if !matched_policy_ids.is_empty() => Self::Audit {
                policy_ids: matched_policy_ids.clone(),
            },
            UsageAuthorizationAccessDecision::Restricted { allowed: true, .. } => Self::Allow,
            UsageAuthorizationAccessDecision::Restricted {
                allowed: false,
                denial_reason,
                matched_policy_ids,
                ..
            } => Self::Deny {
                reason: denial_reason.clone().unwrap_or_else(|| {
                    format!("denied by policies: {}", matched_policy_ids.join(", "))
                }),
            },
        }
    }

    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow | Self::Audit { .. })
    }
}

/// Enforcement context that carries the evaluation result through the gateway
/// request pipeline.
#[derive(Debug, Clone)]
pub struct UsageAuthorizationEnforcementContext {
    pub document: UsageAuthorizationDocument,
    pub disposition: UsageAuthorizationDisposition,
    pub evaluated_at: Instant,
}

impl UsageAuthorizationEnforcementContext {
    pub fn new(document: UsageAuthorizationDocument) -> Self {
        let disposition = UsageAuthorizationDisposition::from_document(&document);
        Self {
            document,
            disposition,
            evaluated_at: Instant::now(),
        }
    }

    /// Check if the evaluation expired, based on the document's `expires_at`.
    fn is_expired(&self, now: &chrono::DateTime<chrono::Utc>) -> bool {
        chrono::DateTime::parse_from_rfc3339(&self.document.expires_at)
            .map(|expires| *now >= expires)
            .unwrap_or(true)
    }

    /// Fail closed when the required policy document is stale or has no
    /// version and digest identity.
    fn reject_if_stale_or_unavailable(
        &self,
        now: &chrono::DateTime<chrono::Utc>,
    ) -> Result<(), String> {
        require_fresh_usage_authorization_document(&self.document, now)
    }
}

/// Reject documents that are expired or have no version and digest identity.
pub fn require_fresh_usage_authorization_document(
    document: &UsageAuthorizationDocument,
    now: &chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    if document.policy_version.trim().is_empty() || document.policy_sha256.trim().is_empty() {
        return Err(USAGE_AUTHORIZATION_POLICY_UNAVAILABLE.to_string());
    }
    if !document.is_fresh(*now) {
        return Err(USAGE_AUTHORIZATION_POLICY_STALE.to_string());
    }
    Ok(())
}

// ── Streaming context ────────────────────────────────────────────────────────

/// Tracks the lifecycle state of a streaming (SSE or WebSocket) request. The
/// authorization stays open until the stream completes. The gateway then
/// settles the final token usage.
#[derive(Debug)]
pub struct UsageAuthorizationStreamingContext {
    pub gateway_usage_authorization_id: String,
    pub attempt_id: String,
    pub started_at: Instant,
    /// Accumulated input tokens (set at start).
    pub input_tokens: u64,
    /// Accumulated output tokens (updated as stream chunks arrive).
    pub output_tokens: std::sync::atomic::AtomicU64,
    /// Whether the stream completed normally.
    completed: std::sync::atomic::AtomicBool,
}

impl UsageAuthorizationStreamingContext {
    pub fn new(
        gateway_usage_authorization_id: String,
        attempt_id: String,
        input_tokens: u64,
    ) -> Self {
        Self {
            gateway_usage_authorization_id,
            attempt_id,
            started_at: Instant::now(),
            input_tokens,
            output_tokens: std::sync::atomic::AtomicU64::new(0),
            completed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Add output tokens from a streaming chunk.
    fn add_output_tokens(&self, tokens: u64) {
        self.output_tokens
            .fetch_add(tokens, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get the current output token count.
    fn current_output_tokens(&self) -> u64 {
        self.output_tokens
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Mark the stream as completed.
    pub fn mark_completed(&self) {
        self.completed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Check if the stream is marked completed.
    fn is_completed(&self) -> bool {
        self.completed.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Elapsed time since the stream started.
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }
}

// ── Moderation integration ───────────────────────────────────────────────────

/// Moderation outcome after the access decision applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageAuthorizationModerationOutcome {
    /// Content passes moderation within the authorization constraints.
    Passed,
    /// Moderation flagged the content. Policy determines the action.
    Flagged { reason: String, policy_allows: bool },
    /// Moderation was skipped because policy denied the request.
    AuthorizationDenied,
}

/// Apply the access decision to moderation. When policy denies a request,
/// moderation is skipped because the request does not reach the provider.
fn apply_moderation_gate(
    enforcement: &UsageAuthorizationEnforcementContext,
    moderation_passed: bool,
    moderation_reason: Option<&str>,
) -> UsageAuthorizationModerationOutcome {
    if !enforcement.disposition.is_allowed() {
        return UsageAuthorizationModerationOutcome::AuthorizationDenied;
    }

    if moderation_passed {
        UsageAuthorizationModerationOutcome::Passed
    } else {
        UsageAuthorizationModerationOutcome::Flagged {
            reason: moderation_reason.unwrap_or("content_flagged").to_string(),
            policy_allows: enforcement.disposition.is_allowed(),
        }
    }
}

// ── Circuit breaker integration ──────────────────────────────────────────────

/// Check circuit breaker state with budget-aware health context. When the
/// provider circuit is open and the evaluation shows budget pressure, the
/// error carries that context.
fn check_circuit_breaker(
    circuit_breaker: &CircuitBreakerManager,
    provider_id: &str,
    enforcement: &UsageAuthorizationEnforcementContext,
) -> Result<(), UsageAuthorizationCircuitBreakerError> {
    if !circuit_breaker.is_allowed(provider_id) {
        let budget_pressure = enforcement.document.has_exhausted_budget();
        return Err(UsageAuthorizationCircuitBreakerError::CircuitOpen {
            provider_id: provider_id.to_string(),
            budget_pressure,
        });
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum UsageAuthorizationCircuitBreakerError {
    #[error("circuit open for provider {provider_id} (budget_pressure={budget_pressure})")]
    CircuitOpen {
        provider_id: String,
        budget_pressure: bool,
    },
}

// ── Retry context ────────────────────────────────────────────────────────────

/// Retry context that respects the authorization constraints. A retry uses the
/// same authorization through a new dispatch attempt and must not exceed the
/// authorized budget.
#[derive(Debug, Clone)]
pub struct UsageAuthorizationRetryContext {
    pub gateway_usage_authorization_id: String,
    pub max_attempts: u32,
    pub current_attempt: u32,
}

impl UsageAuthorizationRetryContext {
    pub fn new(gateway_usage_authorization_id: String, max_attempts: u32) -> Self {
        Self {
            gateway_usage_authorization_id,
            max_attempts,
            current_attempt: 0,
        }
    }

    /// Check if another retry attempt is allowed.
    fn can_retry(&self) -> bool {
        self.current_attempt < self.max_attempts
    }

    /// Record an attempt.
    fn record_attempt(&mut self) {
        self.current_attempt += 1;
    }

    /// Generate a unique attempt identifier for the next dispatch.
    pub fn next_attempt_id(&self) -> String {
        format!(
            "{}-attempt-{}",
            self.gateway_usage_authorization_id,
            self.current_attempt + 1
        )
    }

    /// Build a dispatch request for the next retry attempt.
    fn build_dispatch_request(
        &self,
        provider_supports_idempotency: bool,
        idempotency_key: Option<String>,
    ) -> UsageAuthorizationDispatchRequest {
        UsageAuthorizationDispatchRequest {
            attempt_id: self.next_attempt_id(),
            provider_idempotency: if provider_supports_idempotency {
                UsageAuthorizationProviderIdempotency::Supported
            } else {
                UsageAuthorizationProviderIdempotency::Unsupported
            },
            provider_idempotency_key: idempotency_key,
        }
    }
}

// ── Telemetry ────────────────────────────────────────────────────────────────

/// Structured telemetry event for the usage-authorization lifecycle.
#[derive(Debug, Clone, Serialize)]
pub struct UsageAuthorizationLifecycleEvent {
    pub event_type: UsageAuthorizationEventType,
    pub gateway_usage_authorization_id: Option<String>,
    pub organization_id: String,
    pub gateway_id: String,
    pub provider: String,
    pub model: String,
    pub request_family: String,
    pub disposition: String,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_remaining: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageAuthorizationEventType {
    Evaluate,
    Authorize,
    Dispatch,
    Complete,
    Release,
    BudgetExceeded,
    AccessDenied,
}

impl UsageAuthorizationEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Evaluate => "usage_authorization.evaluate",
            Self::Authorize => "usage_authorization.authorize",
            Self::Dispatch => "usage_authorization.dispatch",
            Self::Complete => "usage_authorization.complete",
            Self::Release => "usage_authorization.release",
            Self::BudgetExceeded => "usage_authorization.budget_exceeded",
            Self::AccessDenied => "usage_authorization.access_denied",
        }
    }
}

impl std::fmt::Display for UsageAuthorizationEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Emit a structured telemetry event for one lifecycle stage.
pub fn emit_usage_authorization_telemetry(event: &UsageAuthorizationLifecycleEvent) {
    tracing::info!(
        usage_authorization.event_type = %event.event_type,
        usage_authorization.gateway_usage_authorization_id = ?event.gateway_usage_authorization_id,
        usage_authorization.organization_id = %event.organization_id,
        usage_authorization.gateway_id = %event.gateway_id,
        usage_authorization.provider = %event.provider,
        usage_authorization.model = %event.model,
        usage_authorization.request_family = %event.request_family,
        usage_authorization.disposition = %event.disposition,
        usage_authorization.duration_ms = event.duration_ms,
        usage_authorization.error = ?event.error,
        usage_authorization.budget_remaining = ?event.budget_remaining,
        usage_authorization.cost_usd = ?event.cost_usd,
        "usage_authorization_lifecycle"
    );
}

fn min_budget_remaining(document: &UsageAuthorizationDocument) -> Option<String> {
    document
        .budgets
        .iter()
        .filter_map(|budget| budget.remaining.parse::<f64>().ok())
        .fold(None, |accumulator: Option<f64>, value| {
            Some(accumulator.map_or(value, |current| current.min(value)))
        })
        .map(|value| format!("{value}"))
}

/// Build a telemetry event from an evaluate result.
fn telemetry_from_evaluate(
    document: &UsageAuthorizationDocument,
    duration: Duration,
    error: Option<&str>,
) -> UsageAuthorizationLifecycleEvent {
    UsageAuthorizationLifecycleEvent {
        event_type: UsageAuthorizationEventType::Evaluate,
        gateway_usage_authorization_id: None,
        organization_id: document.binding.organization_id.clone(),
        gateway_id: document.binding.gateway_id.clone(),
        provider: document.binding.provider.clone(),
        model: document.binding.model.clone(),
        request_family: document.binding.request_family.as_str().to_string(),
        disposition: if document.is_allowed() {
            "allowed".to_string()
        } else {
            "denied".to_string()
        },
        duration_ms: duration.as_millis() as u64,
        error: error.map(ToString::to_string),
        budget_remaining: min_budget_remaining(document),
        cost_usd: None,
    }
}

/// Build a telemetry event from a completion result.
fn telemetry_from_complete(
    gateway_usage_authorization_id: &str,
    organization_id: &str,
    gateway_id: &str,
    provider: &str,
    model: &str,
    request_family: &str,
    completion: &UsageAuthorizationCompletion,
    duration: Duration,
) -> UsageAuthorizationLifecycleEvent {
    UsageAuthorizationLifecycleEvent {
        event_type: UsageAuthorizationEventType::Complete,
        gateway_usage_authorization_id: Some(gateway_usage_authorization_id.to_string()),
        organization_id: organization_id.to_string(),
        gateway_id: gateway_id.to_string(),
        provider: provider.to_string(),
        model: model.to_string(),
        request_family: request_family.to_string(),
        disposition: completion.state.as_str().to_string(),
        duration_ms: duration.as_millis() as u64,
        error: None,
        budget_remaining: None,
        cost_usd: Some(completion.actual_cost_usd.clone()),
    }
}

// ── Event pipeline ───────────────────────────────────────────────────────────

/// Audit record for the usage-authorization lifecycle. The gateway emits it to
/// the event pipeline and forwards it to the control-plane audit trail.
#[derive(Debug, Clone, Serialize)]
pub struct UsageAuthorizationAuditRecord {
    pub record_type: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_usage_authorization_id: Option<String>,
    pub organization_id: String,
    pub gateway_id: String,
    pub subject_token_id: String,
    pub provider: String,
    pub model: String,
    pub request_family: String,
    pub policy_version: String,
    pub policy_sha256: String,
    pub disposition: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_cost_usd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_cost_usd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spend_id: Option<String>,
    pub budget_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_budget_remaining: Option<String>,
}

/// Build an audit record from an evaluation result.
fn audit_record_from_evaluate(
    document: &UsageAuthorizationDocument,
) -> UsageAuthorizationAuditRecord {
    UsageAuthorizationAuditRecord {
        record_type: UsageAuthorizationEventType::Evaluate.as_str().to_string(),
        timestamp: document.issued_at.clone(),
        gateway_usage_authorization_id: None,
        organization_id: document.binding.organization_id.clone(),
        gateway_id: document.binding.gateway_id.clone(),
        subject_token_id: document.binding.subject_token_id.clone(),
        provider: document.binding.provider.clone(),
        model: document.binding.model.clone(),
        request_family: document.binding.request_family.as_str().to_string(),
        policy_version: document.policy_version.clone(),
        policy_sha256: document.policy_sha256.clone(),
        disposition: if document.is_allowed() {
            "allowed".to_string()
        } else {
            "denied".to_string()
        },
        denial_reason: document.denial_reason().map(ToString::to_string),
        estimated_cost_usd: None,
        actual_cost_usd: None,
        spend_id: None,
        budget_count: document.budgets.len(),
        min_budget_remaining: min_budget_remaining(document),
    }
}

/// Build an audit record from an authorization plus its completion.
fn audit_record_from_complete(
    document: &UsageAuthorizationDocument,
    gateway_usage_authorization_id: &str,
    completion: &UsageAuthorizationCompletion,
    estimated_cost_usd: &str,
) -> UsageAuthorizationAuditRecord {
    UsageAuthorizationAuditRecord {
        record_type: UsageAuthorizationEventType::Complete.as_str().to_string(),
        timestamp: completion.usage_at.clone(),
        gateway_usage_authorization_id: Some(gateway_usage_authorization_id.to_string()),
        organization_id: document.binding.organization_id.clone(),
        gateway_id: document.binding.gateway_id.clone(),
        subject_token_id: document.binding.subject_token_id.clone(),
        provider: document.binding.provider.clone(),
        model: document.binding.model.clone(),
        request_family: document.binding.request_family.as_str().to_string(),
        policy_version: document.policy_version.clone(),
        policy_sha256: document.policy_sha256.clone(),
        disposition: completion.state.as_str().to_string(),
        denial_reason: completion.release_reason.clone(),
        estimated_cost_usd: Some(estimated_cost_usd.to_string()),
        actual_cost_usd: Some(completion.actual_cost_usd.clone()),
        spend_id: completion.spend_id.clone(),
        budget_count: document.budgets.len(),
        min_budget_remaining: min_budget_remaining(document),
    }
}

// ── Non-sliding policy cache (version/digest keyed) ──────────────────────────

/// Request-context tip used to recover the version/digest key for a prior
/// evaluate. Documents themselves are stored only under
/// [`UsageAuthorizationPolicyDigestKey`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UsageAuthorizationPolicyCacheKey {
    pub organization_id: String,
    pub gateway_id: String,
    pub subject_token_id: String,
    pub project_id: Option<String>,
    pub configuration_id: Option<String>,
    pub agent_id: Option<String>,
    pub provider: String,
    pub model: String,
    pub request_family: UsageAuthorizationRequestFamily,
}

/// Canonical cache identity: policy version plus policy digest only.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UsageAuthorizationPolicyDigestKey {
    pub policy_version: String,
    pub policy_sha256: String,
}

#[derive(Debug, Clone)]
struct CachedPolicyDocument {
    document: UsageAuthorizationDocument,
    /// Absolute expiry parsed from the document's `expires_at` (never extended).
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// Bounded, non-sliding cache of usage-authorization evaluate documents.
///
/// Documents are stored **only** under `(policy_version, policy_sha256)`. A thin
/// context-to-digest tip map recovers that key for later identical request
/// contexts. Entries expire at the document's absolute `expires_at` and are
/// never refreshed on access. Documents that have no version or digest identity
/// are refused (not cached).
#[derive(Debug)]
pub struct UsageAuthorizationPolicyCache {
    by_digest: std::sync::Mutex<
        std::collections::HashMap<UsageAuthorizationPolicyDigestKey, CachedPolicyDocument>,
    >,
    tip_by_context: std::sync::Mutex<
        std::collections::HashMap<
            UsageAuthorizationPolicyCacheKey,
            UsageAuthorizationPolicyDigestKey,
        >,
    >,
    capacity: usize,
}

impl UsageAuthorizationPolicyCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            by_digest: std::sync::Mutex::new(std::collections::HashMap::new()),
            tip_by_context: std::sync::Mutex::new(std::collections::HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Reject documents that are expired or have no required version or digest.
    pub fn document_is_fresh(
        document: &UsageAuthorizationDocument,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        document.is_fresh(now)
    }

    /// Return the cached document for a request context tip when its
    /// version/digest entry is still within absolute expiry.
    pub fn get(
        &self,
        key: &UsageAuthorizationPolicyCacheKey,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<UsageAuthorizationDocument> {
        let digest = {
            let tips = self
                .tip_by_context
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            tips.get(key).cloned()
        }?;
        self.get_by_digest(&digest, now)
    }

    /// Lookup solely by version/digest identity.
    pub fn get_by_digest(
        &self,
        key: &UsageAuthorizationPolicyDigestKey,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<UsageAuthorizationDocument> {
        let mut entries = self
            .by_digest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match entries.get(key) {
            Some(entry)
                if now < entry.expires_at && Self::document_is_fresh(&entry.document, now) =>
            {
                Some(entry.document.clone())
            }
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    /// Insert a document keyed only by its version/digest. A missing version or
    /// digest refuses the insert. An unparseable expiry is stored as `now` so
    /// the entry is never served (fail-safe).
    pub fn insert(
        &self,
        context: UsageAuthorizationPolicyCacheKey,
        document: UsageAuthorizationDocument,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        if document.policy_version.trim().is_empty() || document.policy_sha256.trim().is_empty() {
            return;
        }
        let digest = UsageAuthorizationPolicyDigestKey {
            policy_version: document.policy_version.clone(),
            policy_sha256: document.policy_sha256.clone(),
        };
        let expires_at = chrono::DateTime::parse_from_rfc3339(&document.expires_at)
            .map(|parsed| parsed.with_timezone(&chrono::Utc))
            .unwrap_or(now);

        {
            let mut entries = self
                .by_digest
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if entries.len() >= self.capacity && !entries.contains_key(&digest) {
                entries.retain(|_, value| now < value.expires_at);
                if entries.len() >= self.capacity {
                    if let Some(evict) = entries.keys().next().cloned() {
                        entries.remove(&evict);
                    }
                }
            }
            entries.insert(
                digest.clone(),
                CachedPolicyDocument {
                    document,
                    expires_at,
                },
            );
        }

        let mut tips = self
            .tip_by_context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tips.insert(context, digest);
    }

    /// Number of stored digest entries.
    pub fn len(&self) -> usize {
        self.by_digest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn policy_doc_with_expiry(expires_at: &str) -> UsageAuthorizationDocument {
        serde_json::from_value(serde_json::json!({
            "schema_version": super::super::usage_authorization::USAGE_AUTHORIZATION_SCHEMA_VERSION,
            "policy_version": "a".repeat(64),
            "policy_sha256": "b".repeat(64),
            "document_sha256": "c".repeat(64),
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": expires_at,
            "binding": {
                "organization_id": "11111111-1111-1111-1111-111111111111",
                "gateway_id": "gw-1",
                "subject_token_id": "33333333-3333-3333-3333-333333333333",
                "provider": "openai",
                "model": "gpt-5.4-mini",
                "request_family": "chat",
                "usage_category": "gateway_llm"
            },
            "access": { "mode": "unrestricted" },
            "budgets": []
        }))
        .unwrap()
    }

    fn sample_policy_key() -> UsageAuthorizationPolicyCacheKey {
        UsageAuthorizationPolicyCacheKey {
            organization_id: "11111111-1111-1111-1111-111111111111".to_string(),
            gateway_id: "gw-1".to_string(),
            subject_token_id: "33333333-3333-3333-3333-333333333333".to_string(),
            project_id: None,
            configuration_id: None,
            agent_id: None,
            provider: "openai".to_string(),
            model: "gpt-5.4-mini".to_string(),
            request_family: UsageAuthorizationRequestFamily::Chat,
        }
    }

    #[test]
    fn policy_cache_serves_within_absolute_expiry_and_is_non_sliding() {
        let cache = UsageAuthorizationPolicyCache::new(16);
        let key = sample_policy_key();
        let document = policy_doc_with_expiry("2026-01-01T01:00:00Z");
        let inserted_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        cache.insert(key.clone(), document, inserted_at);

        let mid = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:59:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(cache.get(&key, mid).is_some());

        // Reading past the absolute expiry is a miss: access never extends it.
        let after = chrono::DateTime::parse_from_rfc3339("2026-01-01T01:00:01Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(cache.get(&key, after).is_none());
        assert!(cache.is_empty(), "an expired entry is evicted on the miss");
    }

    #[test]
    fn policy_cache_miss_on_unparseable_expiry() {
        let cache = UsageAuthorizationPolicyCache::new(4);
        let key = sample_policy_key();
        let document = policy_doc_with_expiry("not-a-timestamp");
        let now = chrono::Utc::now();
        cache.insert(key.clone(), document, now);
        assert!(cache.get(&key, now).is_none());
    }

    #[test]
    fn policy_cache_respects_capacity() {
        let cache = UsageAuthorizationPolicyCache::new(1);
        let now = chrono::Utc::now();
        let future = "2999-01-01T00:00:00Z";
        let mut key_a = sample_policy_key();
        key_a.provider = "openai".to_string();
        let mut key_b = sample_policy_key();
        key_b.provider = "anthropic".to_string();
        let mut document_a = policy_doc_with_expiry(future);
        document_a.policy_sha256 = "c".repeat(64);
        let mut document_b = policy_doc_with_expiry(future);
        document_b.policy_sha256 = "d".repeat(64);
        cache.insert(key_a, document_a, now);
        cache.insert(key_b, document_b, now);
        assert!(cache.len() <= 1, "bounded capacity must be enforced");
    }

    #[test]
    fn policy_cache_keys_only_by_version_and_digest() {
        let cache = UsageAuthorizationPolicyCache::new(8);
        let now = chrono::Utc::now();
        let future = "2999-01-01T00:00:00Z";
        let mut context_a = sample_policy_key();
        context_a.provider = "openai".to_string();
        let mut context_b = sample_policy_key();
        context_b.provider = "anthropic".to_string();
        let document = policy_doc_with_expiry(future);
        cache.insert(context_a.clone(), document.clone(), now);

        let digest = UsageAuthorizationPolicyDigestKey {
            policy_version: document.policy_version.clone(),
            policy_sha256: document.policy_sha256.clone(),
        };
        assert!(cache.get_by_digest(&digest, now).is_some());
        assert!(cache.get(&context_a, now).is_some());

        // A context tip that was never inserted misses even though the digest
        // entry exists.
        assert!(cache.get(&context_b, now).is_none());

        // A document without version identity is refused.
        let mut unidentified = policy_doc_with_expiry(future);
        unidentified.policy_version.clear();
        cache.insert(context_b, unidentified, now);
        assert_eq!(cache.len(), 1);
    }
    use crate::gateway::usage_authorization::{
        UsageAuthorizationState, USAGE_AUTHORIZATION_SCHEMA_VERSION,
    };
    use serde_json::json;

    fn make_unrestricted_document() -> UsageAuthorizationDocument {
        serde_json::from_value(json!({
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
        }))
        .unwrap()
    }

    fn make_denied_document() -> UsageAuthorizationDocument {
        serde_json::from_value(json!({
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
            "access": {
                "mode": "restricted",
                "allowed": false,
                "matched_policy_ids": ["pol-deny-1"],
                "denial_reason": "model not in allowlist",
                "limits": {}
            },
            "budgets": []
        }))
        .unwrap()
    }

    fn make_completion(state: &str) -> UsageAuthorizationCompletion {
        serde_json::from_value(json!({
            "gateway_usage_authorization_id": "auth-1",
            "state": state,
            "spend_id": "spend-1",
            "input_tokens": 100,
            "output_tokens": 20,
            "actual_cost_usd": "0.0020",
            "pricing_snapshot_id": "snap-1",
            "usage_at": "2026-01-01T00:00:05Z"
        }))
        .unwrap()
    }

    // ── Disposition ──────────────────────────────────────────────────────

    #[test]
    fn disposition_from_unrestricted_is_allow() {
        let disposition =
            UsageAuthorizationDisposition::from_document(&make_unrestricted_document());
        assert_eq!(disposition, UsageAuthorizationDisposition::Allow);
        assert!(disposition.is_allowed());
    }

    #[test]
    fn disposition_from_denied_is_deny() {
        let disposition = UsageAuthorizationDisposition::from_document(&make_denied_document());
        assert!(matches!(
            disposition,
            UsageAuthorizationDisposition::Deny { .. }
        ));
        assert!(!disposition.is_allowed());
    }

    #[test]
    fn disposition_from_restricted_allowed_with_policies_is_audit() {
        let document: UsageAuthorizationDocument = serde_json::from_value(json!({
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
            "access": {
                "mode": "restricted",
                "allowed": true,
                "matched_policy_ids": ["pol-audit-1"],
                "limits": {}
            },
            "budgets": []
        }))
        .unwrap();
        let disposition = UsageAuthorizationDisposition::from_document(&document);
        assert!(matches!(
            disposition,
            UsageAuthorizationDisposition::Audit { .. }
        ));
        assert!(disposition.is_allowed());
    }

    #[test]
    fn enforcement_context_new_sets_disposition() {
        let context = UsageAuthorizationEnforcementContext::new(make_unrestricted_document());
        assert!(context.disposition.is_allowed());
    }

    #[test]
    fn enforcement_context_expiry_check() {
        let context = UsageAuthorizationEnforcementContext::new(make_unrestricted_document());
        let future = chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(context.is_expired(&future));
        assert!(context.reject_if_stale_or_unavailable(&future).is_err());

        let before = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(!context.is_expired(&before));
        assert!(context.reject_if_stale_or_unavailable(&before).is_ok());
    }

    #[test]
    fn require_fresh_document_rejects_missing_digest_and_stale_expiry() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let fresh = make_unrestricted_document();
        assert!(require_fresh_usage_authorization_document(&fresh, &now).is_ok());

        let mut missing = make_unrestricted_document();
        missing.policy_sha256.clear();
        assert_eq!(
            require_fresh_usage_authorization_document(&missing, &now).unwrap_err(),
            USAGE_AUTHORIZATION_POLICY_UNAVAILABLE
        );

        let after = chrono::DateTime::parse_from_rfc3339("2026-01-01T01:00:01Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(
            require_fresh_usage_authorization_document(&fresh, &after).unwrap_err(),
            USAGE_AUTHORIZATION_POLICY_STALE
        );
    }

    // ── Streaming context ────────────────────────────────────────────────

    #[test]
    fn streaming_context_tracks_output_tokens() {
        let context =
            UsageAuthorizationStreamingContext::new("auth-1".to_string(), "att-1".to_string(), 100);
        assert_eq!(context.current_output_tokens(), 0);
        context.add_output_tokens(50);
        context.add_output_tokens(30);
        assert_eq!(context.current_output_tokens(), 80);
        assert_eq!(context.input_tokens, 100);
    }

    #[test]
    fn streaming_context_completion_flag() {
        let context =
            UsageAuthorizationStreamingContext::new("auth-2".to_string(), "att-2".to_string(), 200);
        assert!(!context.is_completed());
        context.mark_completed();
        assert!(context.is_completed());
    }

    // ── Moderation ───────────────────────────────────────────────────────

    #[test]
    fn moderation_gate_passes_when_allowed_and_clean() {
        let context = UsageAuthorizationEnforcementContext::new(make_unrestricted_document());
        assert_eq!(
            apply_moderation_gate(&context, true, None),
            UsageAuthorizationModerationOutcome::Passed
        );
    }

    #[test]
    fn moderation_gate_flags_when_allowed_but_flagged() {
        let context = UsageAuthorizationEnforcementContext::new(make_unrestricted_document());
        assert!(matches!(
            apply_moderation_gate(&context, false, Some("hate_speech")),
            UsageAuthorizationModerationOutcome::Flagged {
                policy_allows: true,
                ..
            }
        ));
    }

    #[test]
    fn moderation_gate_skips_when_authorization_denied() {
        let context = UsageAuthorizationEnforcementContext::new(make_denied_document());
        assert_eq!(
            apply_moderation_gate(&context, true, None),
            UsageAuthorizationModerationOutcome::AuthorizationDenied
        );
    }

    // ── Circuit breaker ──────────────────────────────────────────────────

    #[test]
    fn circuit_breaker_allows_when_closed() {
        let breaker = CircuitBreakerManager::new(Default::default());
        let context = UsageAuthorizationEnforcementContext::new(make_unrestricted_document());
        assert!(check_circuit_breaker(&breaker, "openai", &context).is_ok());
    }

    #[test]
    fn circuit_breaker_rejects_when_open() {
        let config = super::super::circuit_breaker::CircuitBreakerConfig {
            enabled: true,
            consecutive_failure_threshold: 1,
            cooldown: Duration::from_secs(300),
            half_open_successes: 1,
        };
        let breaker = CircuitBreakerManager::new(config);
        breaker.record_failure("openai");
        let context = UsageAuthorizationEnforcementContext::new(make_unrestricted_document());
        assert!(check_circuit_breaker(&breaker, "openai", &context).is_err());
    }

    // ── Retry context ────────────────────────────────────────────────────

    #[test]
    fn retry_context_allows_within_limits() {
        let mut context = UsageAuthorizationRetryContext::new("auth-1".to_string(), 3);
        assert!(context.can_retry());
        context.record_attempt();
        context.record_attempt();
        assert!(context.can_retry());
        context.record_attempt();
        assert!(!context.can_retry());
    }

    #[test]
    fn retry_context_builds_dispatch_request() {
        let context = UsageAuthorizationRetryContext::new("auth-1".to_string(), 3);
        assert_eq!(context.next_attempt_id(), "auth-1-attempt-1");

        let request = context.build_dispatch_request(true, Some("idem-key-1".to_string()));
        assert_eq!(request.attempt_id, "auth-1-attempt-1");
        assert_eq!(
            request.provider_idempotency,
            UsageAuthorizationProviderIdempotency::Supported
        );
        assert_eq!(
            request.provider_idempotency_key,
            Some("idem-key-1".to_string())
        );

        let unsupported = context.build_dispatch_request(false, None);
        assert_eq!(
            unsupported.provider_idempotency,
            UsageAuthorizationProviderIdempotency::Unsupported
        );
    }

    // ── Denial classification ────────────────────────────────────────────

    #[test]
    fn classify_authorize_denial_separates_budget_and_rate() {
        assert_eq!(
            classify_authorize_denial(429, Some("budget.daily_exceeded")),
            Some(AuthorizeDenialKind::BudgetCeiling)
        );
        assert_eq!(
            classify_authorize_denial(429, Some("usage_authorization.budget_exceeded")),
            Some(AuthorizeDenialKind::BudgetCeiling)
        );
        assert_eq!(
            classify_authorize_denial(429, Some("usage_authorization.rate_limit_exceeded")),
            Some(AuthorizeDenialKind::RateLimited)
        );
        assert_eq!(
            classify_authorize_denial(429, None),
            Some(AuthorizeDenialKind::RateLimited)
        );
    }

    #[test]
    fn classify_authorize_denial_has_no_platform_financial_outcome() {
        assert_eq!(classify_authorize_denial(402, None), None);
        assert_eq!(classify_authorize_denial(500, None), None);
    }

    // ── Telemetry ────────────────────────────────────────────────────────

    #[test]
    fn telemetry_from_evaluate_captures_document_fields() {
        let document = make_unrestricted_document();
        let event = telemetry_from_evaluate(&document, Duration::from_millis(42), None);
        assert_eq!(event.event_type, UsageAuthorizationEventType::Evaluate);
        assert_eq!(event.organization_id, "org-1");
        assert_eq!(event.gateway_id, "gw-1");
        assert_eq!(event.provider, "openai");
        assert_eq!(event.model, "gpt-5.4");
        assert_eq!(event.request_family, "chat");
        assert_eq!(event.disposition, "allowed");
        assert_eq!(event.duration_ms, 42);
        assert!(event.error.is_none());
    }

    #[test]
    fn telemetry_from_complete_uses_the_completion_state() {
        let completion = make_completion("completed");
        let event = telemetry_from_complete(
            "auth-1",
            "org-1",
            "gw-1",
            "openai",
            "gpt-5.4",
            "chat",
            &completion,
            Duration::from_millis(7),
        );
        assert_eq!(event.event_type, UsageAuthorizationEventType::Complete);
        assert_eq!(
            event.disposition,
            UsageAuthorizationState::Completed.as_str()
        );
        assert_eq!(event.cost_usd, Some("0.0020".to_string()));
    }

    #[test]
    fn event_type_names_are_neutral() {
        assert_eq!(
            UsageAuthorizationEventType::Evaluate.as_str(),
            "usage_authorization.evaluate"
        );
        assert_eq!(
            UsageAuthorizationEventType::Authorize.as_str(),
            "usage_authorization.authorize"
        );
        assert_eq!(
            UsageAuthorizationEventType::Dispatch.as_str(),
            "usage_authorization.dispatch"
        );
        assert_eq!(
            UsageAuthorizationEventType::Complete.as_str(),
            "usage_authorization.complete"
        );
        assert_eq!(
            UsageAuthorizationEventType::Release.as_str(),
            "usage_authorization.release"
        );
        assert_eq!(
            UsageAuthorizationEventType::BudgetExceeded.as_str(),
            "usage_authorization.budget_exceeded"
        );
        assert_eq!(
            UsageAuthorizationEventType::AccessDenied.as_str(),
            "usage_authorization.access_denied"
        );
    }

    #[test]
    fn telemetry_serializes_to_json() {
        let document = make_unrestricted_document();
        let event = telemetry_from_evaluate(&document, Duration::from_millis(10), None);
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["event_type"], "evaluate");
        assert_eq!(value["organization_id"], "org-1");
    }

    // ── Audit records ────────────────────────────────────────────────────

    #[test]
    fn audit_record_from_evaluate_unrestricted() {
        let record = audit_record_from_evaluate(&make_unrestricted_document());
        assert_eq!(record.record_type, "usage_authorization.evaluate");
        assert_eq!(record.organization_id, "org-1");
        assert_eq!(record.disposition, "allowed");
        assert!(record.denial_reason.is_none());
        assert!(record.gateway_usage_authorization_id.is_none());
    }

    #[test]
    fn audit_record_from_evaluate_denied() {
        let record = audit_record_from_evaluate(&make_denied_document());
        assert_eq!(record.disposition, "denied");
        assert_eq!(
            record.denial_reason.as_deref(),
            Some("model not in allowlist")
        );
    }

    #[test]
    fn audit_record_from_complete_has_costs() {
        let document = make_unrestricted_document();
        let completion = make_completion("completed");
        let record = audit_record_from_complete(&document, "auth-1", &completion, "0.0025");
        assert_eq!(record.record_type, "usage_authorization.complete");
        assert_eq!(
            record.gateway_usage_authorization_id,
            Some("auth-1".to_string())
        );
        assert_eq!(record.estimated_cost_usd, Some("0.0025".to_string()));
        assert_eq!(record.actual_cost_usd, Some("0.0020".to_string()));
        assert_eq!(record.spend_id, Some("spend-1".to_string()));
        assert_eq!(record.disposition, "completed");
    }

    #[test]
    fn audit_record_serializes_without_absent_fields() {
        let record = audit_record_from_evaluate(&make_unrestricted_document());
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["record_type"], "usage_authorization.evaluate");
        assert!(value.get("denial_reason").is_none());
        assert!(value.get("estimated_cost_usd").is_none());
        assert!(value.get("credential_source").is_none());
    }
}
