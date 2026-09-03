// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Gateway identity and finops request context.
//!
//! This module owns request finops/identity construction and the header
//! reconstruction helpers used before policy evaluation:
//! - [`RequestFinopsContext`] and [`RequestFinopsContext::has_authoritative_identity`]
//! - [`inject_identity_headers_from_finops`] / [`policy_input_headers`]
//! - [`resolve_request_finops_context`] / [`require_connected_public_auth`]
//!
//! Authenticated typed identity is populated only from API `validate_token` /
//! machine-token validation claims (or a verified signed assertion upstream of
//! this module), then projected to [`identity::PolicyIdentityContext`] for
//! policy consumers.
//!
//! Reserved identity headers are stripped and reconstructed only from
//! [`identity::AuthenticatedRequestIdentity`]. Policy-chain team targeting uses
//! authenticated [`RequestFinopsContext::selected_team_ids`] / memberships /
//! `team_id` (see `resolve_request_team_slugs`). Caller `X-Verdictan-Team` is
//! stripped/rejected for selection on authenticated and connected profiles and
//! is allowed as a selector only on an explicit local unauthenticated profile.
//! Forged out-of-set selectors on authenticated token validation fail closed
//! with `403 auth.team_binding_mismatch`. Reserved headers must never reach
//! provider upstreams (`strip_reserved_identity_headers` /
//! [`is_reserved_identity_header`]).

use super::*;
use crate::gateway::{
    agent_context, canonicalization, identity, network, rate_limit, token_validation_cache,
    work_reuse, work_reuse_verifier,
};

/// Reserved identity headers that callers must not control and that must never
/// be forwarded to provider upstreams.
pub const RESERVED_IDENTITY_HEADERS: &[&str] = &[
    "x-key-id",
    "x-org-id",
    "x-team-id",
    "x-verdictan-team",
    "x-user-id",
    "x-user-role",
];

/// Returns true when `name` is a reserved identity header (case-insensitive).
pub fn is_reserved_identity_header(name: &axum::http::HeaderName) -> bool {
    let lower = name.as_str();
    RESERVED_IDENTITY_HEADERS
        .iter()
        .any(|reserved| lower.eq_ignore_ascii_case(reserved))
}

/// Remove every reserved identity header from `headers`.
pub fn strip_reserved_identity_headers(headers: &mut HeaderMap) {
    for name in RESERVED_IDENTITY_HEADERS {
        headers.remove(*name);
    }
}

fn parse_csv_header_values(headers: &HeaderMap, name: &str) -> Vec<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Caller-requested team selectors from reserved team headers (pre-strip).
pub fn parse_requested_team_selectors(headers: &HeaderMap) -> Vec<String> {
    let mut requested = parse_csv_header_values(headers, "x-verdictan-team");
    requested.extend(parse_csv_header_values(headers, "x-team-id"));
    requested
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Bind requested team selectors to the authenticated team set.
///
/// - Empty request → use the authenticated team set (org-wide when empty).
/// - Non-empty request → every requested team must be in the authenticated set;
///   otherwise fail closed.
///
/// `Err` is intentional: callers map the unit error to
/// `403 auth.team_binding_mismatch` without leaking selector details.
#[allow(clippy::result_unit_err)]
pub fn bind_selected_team_ids(
    authenticated_team_ids: &[String],
    requested_team_ids: &[String],
) -> Result<Vec<String>, ()> {
    if requested_team_ids.is_empty() {
        return Ok(authenticated_team_ids.to_vec());
    }

    let allowed: std::collections::BTreeSet<&str> =
        authenticated_team_ids.iter().map(String::as_str).collect();
    if requested_team_ids
        .iter()
        .any(|team| !allowed.contains(team.as_str()))
    {
        return Err(());
    }

    Ok(requested_team_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn insert_identity_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    if let Ok(header_value) = axum::http::HeaderValue::from_str(value) {
        headers.insert(name, header_value);
    }
}

fn reconstruct_identity_headers_from_authenticated(
    headers: &mut HeaderMap,
    identity: &identity::AuthenticatedRequestIdentity,
    selected_team_ids: &[String],
    key_id: Option<&str>,
) {
    strip_reserved_identity_headers(headers);
    insert_identity_header(headers, "X-Org-ID", identity.org_id());
    insert_identity_header(headers, "X-User-ID", identity.subject());
    insert_identity_header(
        headers,
        "X-Key-ID",
        key_id.unwrap_or_else(|| identity.credential_id()),
    );
    if let Some(primary_team) = selected_team_ids.first() {
        insert_identity_header(headers, "X-Team-ID", primary_team);
    } else if let Some(primary_team) = identity.team_ids().first() {
        insert_identity_header(headers, "X-Team-ID", primary_team);
    }
    if !selected_team_ids.is_empty() {
        insert_identity_header(headers, "X-Verdictan-Team", &selected_team_ids.join(","));
    } else if !identity.team_ids().is_empty() {
        insert_identity_header(headers, "X-Verdictan-Team", &identity.team_ids().join(","));
    }
    if !identity.roles().is_empty() {
        insert_identity_header(headers, "X-User-Role", &identity.roles().join(","));
    }
}

fn reconstruct_identity_headers_from_finops_fields(
    headers: &mut HeaderMap,
    ctx: &RequestFinopsContext,
) {
    strip_reserved_identity_headers(headers);
    if let Some(org_id) = ctx.org_id.as_deref() {
        insert_identity_header(headers, "X-Org-ID", org_id);
    }
    if let Some(user_id) = ctx.user_id.as_deref() {
        insert_identity_header(headers, "X-User-ID", user_id);
    }
    if let Some(team_id) = ctx.team_id.as_deref() {
        insert_identity_header(headers, "X-Team-ID", team_id);
        insert_identity_header(headers, "X-Verdictan-Team", team_id);
    }
    if !ctx.selected_team_ids.is_empty() {
        insert_identity_header(
            headers,
            "X-Verdictan-Team",
            &ctx.selected_team_ids.join(","),
        );
        if let Some(primary_team) = ctx.selected_team_ids.first() {
            insert_identity_header(headers, "X-Team-ID", primary_team);
        }
    }
    if let Some(key_id) = ctx.key_id.as_deref() {
        insert_identity_header(headers, "X-Key-ID", key_id);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdentityClaimBinding {
    org_matches: bool,
    subject_matches: bool,
    credential_matches: bool,
    team_matches: bool,
}

impl IdentityClaimBinding {
    fn is_valid(self) -> bool {
        self.org_matches && self.subject_matches && self.credential_matches && self.team_matches
    }
}

fn bind_authenticated_identity(
    identity: &identity::AuthenticatedRequestIdentity,
    validation_org_id: Option<&str>,
    key: &TokenRecord,
) -> IdentityClaimBinding {
    let expected_subject = key.user_id.as_deref().unwrap_or(key.id.as_str());
    IdentityClaimBinding {
        org_matches: validation_org_id == Some(identity.org_id()),
        subject_matches: identity.subject() == expected_subject,
        credential_matches: identity.credential_id() == key.id,
        team_matches: key
            .team_id
            .as_ref()
            .is_none_or(|team_id| identity.team_ids().iter().any(|claim| claim == team_id)),
    }
}

#[derive(Clone, Debug, Default)]
pub struct RequestFinopsContext {
    pub authenticated_identity: Option<identity::AuthenticatedRequestIdentity>,
    /// Team selectors bound from authenticated claims (and optional request
    /// subset). Empty means org-wide / no team targeting.
    pub selected_team_ids: Vec<String>,
    pub key_id: Option<String>,
    pub user_id: Option<String>,
    pub team_id: Option<String>,
    pub org_id: Option<String>,
    pub created_by: Option<String>,
    pub provider: Option<String>,
    pub model_filter: Option<String>,
    pub remaining_key_budget: Option<f64>,
    pub max_key_budget: Option<f64>,
    pub current_key_spend: f64,
    pub max_requests: Option<u64>,
    pub current_requests: u64,
    pub remaining_requests: Option<u64>,
    pub allowed_providers: Vec<String>,
    pub allowed_models: Vec<String>,
    pub allowed_gateways: Vec<String>,
    pub history_capture_mode: Option<String>,
    pub history_previous_sessions_max: Option<i32>,
    pub history_previous_allowed_requests_max: Option<i32>,
    /// Effective IP allow-list CIDRs from the key's org security settings.
    /// `None` means the org has no IP restrictions; an empty vec is treated the same.
    pub ip_restrictions: Option<Vec<String>>,
    /// Resolved API token entitlements used for org-shared cache replay gates.
    pub entitlements: Vec<String>,
    pub entitlement_digest: Option<String>,
    pub org_authz_version: Option<i64>,
    pub agent_id: Option<String>,
    pub agent_gateway_group_id: Option<String>,
    /// Per-key requests-per-minute ceiling. Only set when the validated key
    /// carries a positive `rate_limit_rpm` value.
    pub rate_limit_rpm: Option<u32>,
    // Gateway-execution attribution.
    pub gateway_execution_session_id: Option<String>,
    pub execution_surface: Option<String>,
    /// Agent-context selection telemetry for the current request.
    pub context_plan_hash: Option<String>,
    pub context_pack_hash: Option<String>,
    pub context_policy_version: Option<i64>,
    pub context_selected_item_ids: Vec<String>,
    pub context_selected_items: Vec<agent_context::SelectedContextItemTelemetry>,
    pub context_selected_hierarchy_lanes: Vec<String>,
    pub context_selected_receipt_ids: Vec<String>,
    pub context_citation_required_count: Option<u32>,
    pub context_max_tokens: Option<u32>,
    pub context_estimated_tokens: Option<u32>,
    pub context_injected_tokens: Option<u32>,
    pub working_context_tokens: Option<u32>,
    pub novelty_class: Option<String>,
    pub novelty_receipt_id: Option<String>,
    pub work_reuse_mode: Option<String>,
    pub work_reuse_reason: Option<String>,
    pub work_reuse_policy_decision: Option<String>,
    pub work_reuse_policy_id: Option<String>,
    pub work_reuse_policy_reason_code: Option<String>,
    pub work_reuse_verifier_commands: Vec<String>,
    pub work_reuse_verifier: Option<work_reuse_verifier::ReuseVerifierSummary>,
    pub work_reuse_requested_mode: Option<String>,
    pub work_reuse_tool_chain_hit: Option<bool>,
    pub work_reuse_tool_names: Vec<String>,
    pub work_reuse_avoided_tool_executions: Option<u32>,
    pub work_reuse_avoided_model_calls: Option<u32>,
    pub work_reuse_reuse_applied: Option<bool>,
    pub work_reuse_replay_success: Option<bool>,
    pub work_reuse_policy_denied: Option<bool>,
}

impl RequestFinopsContext {
    /// Project verified authenticated identity into the policy-facing context.
    ///
    /// Returns `None` when the request was not authenticated through an
    /// authoritative token/assertion proof.
    fn policy_identity_context(&self) -> Option<identity::PolicyIdentityContext> {
        self.authenticated_identity
            .as_ref()
            .map(identity::PolicyIdentityContext::from)
    }

    pub(super) fn has_token_identity(&self) -> bool {
        self.key_id
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
    }

    pub(super) fn has_authoritative_identity(&self) -> bool {
        self.authenticated_identity.is_some()
            || self
                .org_id
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty())
            || self
                .user_id
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty())
            || self
                .team_id
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty())
            || self.has_token_identity()
    }

    pub(super) fn identity_context_json(&self) -> Option<serde_json::Value> {
        if !self.has_authoritative_identity() {
            return None;
        }

        Some(serde_json::json!({
            "key_id": self.key_id,
            "org_id": self.org_id,
            "user_id": self.user_id,
            "team_id": self.team_id,
        }))
    }

    pub(super) fn context_selection_json(&self) -> Option<serde_json::Value> {
        let plan_hash = self
            .context_plan_hash
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())?;

        Some(serde_json::json!({
            "plan_hash": plan_hash,
            "pack_hash": self.context_pack_hash,
            "context_policy_version": self.context_policy_version,
            "selected_item_ids": self.context_selected_item_ids,
            "selected_items": self.context_selected_items,
            "selected_hierarchy_lanes": self.context_selected_hierarchy_lanes,
            "selected_receipt_ids": self.context_selected_receipt_ids,
            "citation_required_count": self.context_citation_required_count,
            "max_context_tokens": self.context_max_tokens,
            "estimated_context_tokens": self.context_estimated_tokens,
            "injected_context_tokens": self.context_injected_tokens,
            "working_context_tokens": self.working_context_tokens,
        }))
    }

    pub(super) fn apply_context_selection(
        &mut self,
        selection: &agent_context::ContextSelectionTelemetry,
    ) {
        self.context_plan_hash = Some(selection.plan_hash.clone());
        self.context_pack_hash = selection.pack_hash.clone();
        self.context_policy_version = Some(selection.context_policy_version);
        self.context_selected_item_ids = selection.selected_item_ids.clone();
        self.context_selected_items = selection.selected_items.clone();
        self.context_selected_hierarchy_lanes = selection.selected_hierarchy_lanes.clone();
        self.context_selected_receipt_ids = selection.selected_receipt_ids.clone();
        self.context_citation_required_count = Some(selection.citation_required_count);
        self.context_max_tokens = Some(selection.tokens.max_context_tokens);
        self.context_estimated_tokens = Some(selection.tokens.estimated_tokens);
        self.context_injected_tokens = Some(selection.tokens.injected_tokens);
        self.working_context_tokens = Some(selection.tokens.working_context_tokens);
    }

    pub(super) fn work_reuse_json(&self) -> Option<serde_json::Value> {
        let mode = self
            .work_reuse_mode
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let novelty = self
            .novelty_class
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if mode.is_none() && novelty.is_none() {
            return None;
        }
        Some(serde_json::json!({
            "novelty_class": novelty,
            "matched_receipt_id": self.novelty_receipt_id,
            "requested_mode": self.work_reuse_requested_mode,
            "mode": mode,
            "reason": self.work_reuse_reason,
            "policy_decision": self.work_reuse_policy_decision,
            "policy_id": self.work_reuse_policy_id,
            "reason_code": self.work_reuse_policy_reason_code,
            "verifier_commands": self.work_reuse_verifier_commands,
            "verifier": self.work_reuse_verifier,
            "tool_chain_hit": self.work_reuse_tool_chain_hit,
            "tool_names": self.work_reuse_tool_names,
            "avoided_tool_executions": self.work_reuse_avoided_tool_executions,
            "avoided_model_calls": self.work_reuse_avoided_model_calls,
            "reuse_applied": self.work_reuse_reuse_applied,
            "replay_success": self.work_reuse_replay_success,
            "policy_denied": self.work_reuse_policy_denied,
        }))
    }

    pub(super) fn apply_work_reuse(&mut self, outcome: &work_reuse::RuntimeReuseOutcome) {
        self.novelty_class = outcome.novelty_class.clone();
        self.novelty_receipt_id = outcome.matched_receipt_id.clone();
        self.work_reuse_requested_mode = outcome.requested_mode.clone();
        if let Some(decision) = outcome.decision.as_ref() {
            self.work_reuse_mode = Some(decision.mode.as_str().to_string());
            self.work_reuse_reason = Some(decision.reason.clone());
            self.work_reuse_verifier_commands = decision.verifier_commands.clone();
        }
        if let Some(policy) = outcome.policy_decision.as_ref() {
            self.work_reuse_policy_decision = Some(policy.decision.clone());
            self.work_reuse_policy_id = policy.policy_id.clone();
            self.work_reuse_policy_reason_code = Some(policy.reason_code.clone());
        }
        self.work_reuse_verifier = outcome.verifier.clone();
        self.work_reuse_tool_chain_hit = Some(outcome.tool_chain_hit);
        self.work_reuse_tool_names = outcome.tool_names.clone();
        self.work_reuse_avoided_tool_executions = outcome.avoided_tool_executions;
        self.work_reuse_avoided_model_calls = outcome.avoided_model_calls;
        self.work_reuse_reuse_applied = outcome.reuse_applied;
        self.work_reuse_replay_success = outcome.replay_success;
        self.work_reuse_policy_denied = outcome.policy_denied;
    }
}

pub(super) fn inject_identity_headers_from_finops(
    headers: &mut HeaderMap,
    finops: Option<&RequestFinopsContext>,
) {
    let Some(ctx) = finops else { return };

    // Authoritative authenticated identity always wins: strip reserved headers
    // and rebuild exclusively from AuthenticatedRequestIdentity.
    if let Some(identity) = ctx.authenticated_identity.as_ref() {
        reconstruct_identity_headers_from_authenticated(
            headers,
            identity,
            &ctx.selected_team_ids,
            ctx.key_id.as_deref(),
        );
        return;
    }

    // Legacy authoritative finops fields (no typed identity yet): strip and
    // rebuild so spoofed caller values cannot stick.
    if ctx.has_authoritative_identity() {
        reconstruct_identity_headers_from_finops_fields(headers, ctx);
        return;
    }

    // Telemetry-only / header-soft path: never invent key identity from the
    // caller, but leave soft org/user/role headers alone for local RBAC.
    headers.remove("X-Key-ID");
}

pub(super) fn policy_input_headers(
    request_headers: &HeaderMap,
    request_finops: Option<&RequestFinopsContext>,
) -> HeaderMap {
    let mut headers = request_headers.clone();

    // Public callers must never supply their own authoritative identity.
    // Strip reserved headers and rebuild from AuthenticatedRequestIdentity (or
    // legacy authoritative finops fields). Telemetry-only finops must not erase
    // header-soft identity before RBAC, aside from always dropping X-Key-ID.
    if request_finops
        .is_some_and(|ctx| ctx.authenticated_identity.is_some() || ctx.has_authoritative_identity())
    {
        strip_reserved_identity_headers(&mut headers);
    } else {
        headers.remove("X-Key-ID");
    }

    if let Some(ctx) = request_finops {
        inject_identity_headers_from_finops(&mut headers, Some(ctx));
    }

    headers
}

/// Build a header map safe for provider upstreams: clone then strip every
/// reserved identity header so caller-spoofed identity material never leaks.
fn upstream_safe_headers(request_headers: &HeaderMap) -> HeaderMap {
    let mut headers = request_headers.clone();
    strip_reserved_identity_headers(&mut headers);
    headers
}

pub(super) async fn require_connected_public_auth(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    peer_ip: std::net::IpAddr,
    request_id: &str,
    traceparent: &str,
) -> Result<Option<RequestFinopsContext>, Response<Body>> {
    if !state.connected_mode {
        return Ok(None);
    }

    match resolve_request_finops_context(state, headers, peer_ip, request_id, traceparent).await {
        Ok(Some(finops)) => {
            if let Some(rejection) =
                enforce_token_rate_limit(state, &finops, request_id, traceparent)
            {
                return Err(rejection);
            }
            Ok(Some(finops))
        }
        Ok(None) => Err(build_request_error_response(
            StatusCode::UNAUTHORIZED,
            request_id,
            traceparent,
            "Authentication required: provide a valid Verdictan API token",
            "authentication_error",
            "missing_api_key",
        )),
        Err(response) => Err(response),
    }
}

pub(super) async fn resolve_request_finops_context(
    state: &ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    peer_ip: std::net::IpAddr,
    request_id: &str,
    traceparent: &str,
) -> Result<Option<RequestFinopsContext>, Response<Body>> {
    let Some(raw_key) = extract_bearer_token(headers) else {
        if state.connected_mode {
            return Err(build_request_error_response(
                StatusCode::UNAUTHORIZED,
                request_id,
                traceparent,
                "Authentication required: provide a valid API token",
                "authentication_error",
                "missing_api_key",
            ));
        }
        return Ok(None);
    };
    if !is_api_token(&raw_key) {
        if state.connected_mode {
            return Err(build_request_error_response(
                StatusCode::UNAUTHORIZED,
                request_id,
                traceparent,
                "Authentication required: provide a valid Verdictan API token",
                "authentication_error",
                "missing_api_key",
            ));
        }
        return Ok(None);
    }

    let Some(sink) = state.event_sink.as_ref() else {
        return Err(build_request_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            traceparent,
            "API token validation requires a configured Verdictan API connection",
            "service_unavailable",
            "token_validation_unavailable",
        ));
    };

    let cache_key =
        token_validation_cache::TokenValidationCacheKey::for_runtime_validation(&raw_key);
    let token_validation_start = Instant::now();
    let mut token_validation_cache_hit = false;
    let validation = if let Some(cached) = state.token_validation_cache.get_negative(&cache_key) {
        token_validation_cache_hit = true;
        state
            .gateway_runtime_metrics
            .record_token_validation_cache_hit();
        cached
    } else {
        state
            .gateway_runtime_metrics
            .record_token_validation_cache_miss();
        let validation = match sink.validate_token(&raw_key).await {
            Ok(validation) => validation,
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    error = %error,
                    "API token validation failed"
                );
                record_request_stage_timing(
                    RequestStageTiming::TokenValidation,
                    token_validation_start.elapsed(),
                    Some(false),
                );
                return Err(build_token_validation_error_response(
                    request_id,
                    traceparent,
                    &error,
                ));
            }
        };

        if !validation.valid {
            state
                .token_validation_cache
                .insert_negative(cache_key, validation.clone());
        }

        validation
    };
    record_request_stage_timing(
        RequestStageTiming::TokenValidation,
        token_validation_start.elapsed(),
        Some(token_validation_cache_hit),
    );

    if !validation.valid {
        let reason = validation.reason.as_deref().unwrap_or("inactive");
        let (status, error_type, code, message) = match reason {
            "expired" => (
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                "tokens.expired",
                "The supplied API token has expired".to_string(),
            ),
            "budget_exhausted" => (
                StatusCode::PAYMENT_REQUIRED,
                "cost_budget_exceeded",
                "tokens.budget_exhausted",
                "The supplied API token has exhausted its budget".to_string(),
            ),
            "request_limit_exhausted" => (
                StatusCode::FORBIDDEN,
                "access_denied",
                "tokens.request_limit_exhausted",
                "The supplied API token has exhausted its request limit".to_string(),
            ),
            _ => (
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                "invalid_api_token",
                format!("API token is not valid: {reason}"),
            ),
        };
        return Err(build_request_error_response(
            status,
            request_id,
            traceparent,
            &message,
            error_type,
            code,
        ));
    }

    if state.connected_mode {
        let org_present = validation
            .org_id
            .as_ref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
        if !org_present {
            return Err(build_request_error_response(
                StatusCode::UNAUTHORIZED,
                request_id,
                traceparent,
                "API token is missing an organization scope required for connected gateways",
                "authentication_error",
                "token_missing_org",
            ));
        }
    }

    let Some(key) = validation.key.clone() else {
        return Err(build_request_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            traceparent,
            "API token validation did not return key details",
            "service_unavailable",
            "token_validation_unavailable",
        ));
    };

    let effective_scopes = match merged_token_scopes(
        &key,
        validation.gateway_controls.as_ref(),
        &validation.attached_policy_ids,
    ) {
        Ok(value) => value,
        Err(TokenScopeMergeError::PolicyResolutionFailed) => {
            return Err(build_request_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                traceparent,
                "API token scope governance could not be resolved deterministically",
                "service_unavailable",
                "token_scope_resolution_failed",
            ));
        }
        Err(TokenScopeMergeError::GovernedScopeConflict) => {
            return Err(build_request_error_response(
                StatusCode::FORBIDDEN,
                request_id,
                traceparent,
                "The supplied API token is not authorized for the configured gateway scope",
                "access_denied",
                "tokens.scope_not_allowed",
            ));
        }
    };

    let current_key_spend = token_current_spend(&key, &validation);
    let max_key_budget = token_max_budget(&key, &validation);
    let current_requests = token_current_requests(&validation);
    let max_requests = token_max_requests(&validation);

    if !state.connected_mode {
        if let (Some(bound_gateway_id), Some(runtime_gateway_id)) = (
            validated_key_gateway_binding(&key.metadata),
            state.gateway_id.as_deref(),
        ) {
            if runtime_gateway_id != bound_gateway_id {
                return Err(build_request_error_response(
                    StatusCode::FORBIDDEN,
                    request_id,
                    traceparent,
                    "This API token is not valid for the current gateway instance",
                    "access_denied",
                    "token_scope_mismatch",
                ));
            }
        }
    }

    if !effective_scopes.allowed_gateways.is_empty() {
        let runtime_gateway_id = state
            .gateway_id
            .as_deref()
            .map(str::trim)
            .unwrap_or_default();
        if runtime_gateway_id.is_empty()
            || !effective_scopes
                .allowed_gateways
                .iter()
                .any(|value| value == runtime_gateway_id)
        {
            return Err(build_request_error_response(
                StatusCode::FORBIDDEN,
                request_id,
                traceparent,
                "The supplied API token is not authorized for this gateway instance",
                "access_denied",
                "tokens.scope_not_allowed",
            ));
        }
    }

    if let Some(bound_agent_id) = validated_key_agent_binding(&key.metadata) {
        let configured_agent_id = optional_env("VERDICTAN_AGENT_ID")
            .or_else(|| {
                state
                    .agents_runtime
                    .as_ref()
                    .and_then(|config| config.default_agent_id.clone())
            })
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        if let Some(configured_agent_id) = configured_agent_id {
            if configured_agent_id != bound_agent_id {
                return Err(build_request_error_response(
                    StatusCode::FORBIDDEN,
                    request_id,
                    traceparent,
                    "This API token is not valid for the configured agent binding",
                    "access_denied",
                    "token_agent_mismatch",
                ));
            }
        }
    }

    let ip_restriction_cidrs: Option<Vec<String>> = validation
        .ip_restrictions
        .as_ref()
        .map(|r| r.cidrs.clone())
        .filter(|cidrs| !cidrs.is_empty());

    if let Some(ref cidrs) = ip_restriction_cidrs {
        let nets: Vec<ipnet::IpNet> = cidrs
            .iter()
            .filter_map(|cidr| {
                cidr.parse::<ipnet::IpNet>()
                    .or_else(|_| cidr.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                    .ok()
            })
            .collect();
        if !nets.is_empty() {
            let client_ip = rate_limit::extract_client_ip(
                headers,
                state.ip_allowlist_trusted_proxies.as_ref(),
                peer_ip,
            );
            if !network::ip_is_allowlisted(client_ip, &nets) {
                tracing::warn!(
                    request_id = %request_id,
                    client_ip = %client_ip,
                    org_id = ?validation.org_id,
                    "ip restrictions denied: client IP not in org allowlist"
                );
                return Err(build_request_error_response(
                    StatusCode::FORBIDDEN,
                    request_id,
                    traceparent,
                    "Source IP is not in the allowed list for this API token",
                    "access_denied",
                    "ip_restrictions_denied",
                ));
            }
        }
    }

    let entitlement_digest = if validation.entitlements.is_empty() {
        None
    } else {
        Some(canonicalization::compute_entitlement_digest(
            &validation.entitlements,
        ))
    };

    let key_id = validation
        .key_id
        .clone()
        .or_else(|| validation.token_id.clone())
        .or_else(|| Some(key.id.clone()));
    if matches!(max_requests, Some(limit) if current_requests >= limit) {
        return Err(build_request_error_response(
            StatusCode::FORBIDDEN,
            request_id,
            traceparent,
            "The supplied API token has exhausted its request limit",
            "access_denied",
            "tokens.request_limit_exhausted",
        ));
    }
    let remaining_key_budget = match max_key_budget {
        Some(max_budget) if current_key_spend < max_budget => {
            Some((max_budget - current_key_spend).max(0.0))
        }
        Some(_) => {
            return Err(build_request_error_response(
                StatusCode::PAYMENT_REQUIRED,
                request_id,
                traceparent,
                "The supplied API token has exhausted its budget",
                "cost_budget_exceeded",
                "tokens.budget_exhausted",
            ));
        }
        None => None,
    };

    if let Some(expires_at) = parse_expiry_timestamp(
        validation
            .expires_at
            .as_deref()
            .or(key.expires_at.as_deref()),
    ) {
        if expires_at <= Utc::now() {
            return Err(build_request_error_response(
                StatusCode::UNAUTHORIZED,
                request_id,
                traceparent,
                "The supplied API token has expired",
                "authentication_error",
                "tokens.expired",
            ));
        }
    }

    let authenticated_identity_claims =
        validation.authenticated_identity.clone().ok_or_else(|| {
            build_request_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                traceparent,
                "API token validation did not return authenticated identity claims",
                "service_unavailable",
                "token_identity_claims_unavailable",
            )
        })?;
    let authenticated_identity = identity::AuthenticatedRequestIdentity::from_validated_claims(
        authenticated_identity_claims,
    )
    .map_err(|error| {
        tracing::error!(
            request_id = %request_id,
            error = %error,
            "API token validation returned invalid authenticated identity claims"
        );
        build_request_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            traceparent,
            "API token validation returned invalid authenticated identity claims",
            "service_unavailable",
            "token_identity_claims_invalid",
        )
    })?;
    let claim_binding =
        bind_authenticated_identity(&authenticated_identity, validation.org_id.as_deref(), &key);
    if !claim_binding.is_valid() {
        tracing::error!(
            request_id = %request_id,
            org_claim_matches = claim_binding.org_matches,
            subject_claim_matches = claim_binding.subject_matches,
            credential_claim_matches = claim_binding.credential_matches,
            team_claim_matches = claim_binding.team_matches,
            "API token identity claims did not match validated token bindings"
        );
        return Err(build_request_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            traceparent,
            "API token identity claims did not match validated token bindings",
            "service_unavailable",
            "token_identity_claims_mismatch",
        ));
    }

    // SEC-009: authenticated memberships / team_id own chain selection.
    // Caller X-Verdictan-Team is not a selector on authenticated profiles.
    // Out-of-set header values are rejected; in-set values are stripped from
    // selection so a forged subset cannot weaken team-scoped policy.
    let requested_teams = parse_requested_team_selectors(headers);
    if !requested_teams.is_empty()
        && bind_selected_team_ids(authenticated_identity.team_ids(), &requested_teams).is_err()
    {
        return Err(build_request_error_response(
            StatusCode::FORBIDDEN,
            request_id,
            traceparent,
            "Requested team is outside the authenticated team set",
            "access_denied",
            "auth.team_binding_mismatch",
        ));
    }
    let selected_team_ids = authenticated_identity.team_ids().to_vec();

    let primary_team_id = selected_team_ids
        .first()
        .cloned()
        .or_else(|| key.team_id.clone());

    Ok(Some(RequestFinopsContext {
        authenticated_identity: Some(authenticated_identity),
        selected_team_ids,
        key_id,
        user_id: key.user_id.clone(),
        team_id: primary_team_id,
        org_id: validation.org_id.clone(),
        created_by: validation.created_by.clone(),
        provider: normalize_optional_text(key.provider.as_deref()),
        model_filter: key.model_filter.first().cloned(),
        remaining_key_budget,
        max_key_budget,
        current_key_spend,
        max_requests,
        current_requests,
        remaining_requests: max_requests.map(|limit| limit.saturating_sub(current_requests)),
        allowed_providers: effective_scopes.allowed_providers,
        allowed_models: effective_scopes.allowed_models,
        allowed_gateways: effective_scopes.allowed_gateways,
        history_capture_mode: validation
            .history
            .as_ref()
            .map(|history| history.capture_mode.clone()),
        history_previous_sessions_max: validation
            .history
            .as_ref()
            .map(|history| history.previous_sessions_max),
        history_previous_allowed_requests_max: validation
            .history
            .as_ref()
            .map(|history| history.previous_allowed_requests_max),
        ip_restrictions: ip_restriction_cidrs,
        entitlements: validation.entitlements.clone(),
        entitlement_digest,
        org_authz_version: validation.org_authz_version,
        agent_id: validation.agent_id.clone(),
        agent_gateway_group_id: validation.agent_gateway_group_id.clone(),
        rate_limit_rpm: key
            .rate_limit_rpm
            .and_then(|rpm| u32::try_from(rpm).ok())
            .filter(|&rpm| rpm > 0),
        gateway_execution_session_id: None,
        execution_surface: None,
        ..Default::default()
    }))
}

#[cfg(test)]
mod authenticated_identity_tests {
    use super::*;

    fn authenticated_identity() -> identity::AuthenticatedRequestIdentity {
        identity::AuthenticatedRequestIdentity::from_validated_claims(
            identity::AuthenticatedIdentityClaims {
                proof_method: identity::IdentityProofMethod::ApiToken,
                issuer: "verdictan-api".to_string(),
                subject: "user-1".to_string(),
                credential_id: "token-1".to_string(),
                org_id: "org-1".to_string(),
                team_ids: vec!["team-b".to_string(), "team-a".to_string()],
                roles: vec!["member".to_string()],
                scopes: vec!["events:read".to_string()],
                assurance_level: identity::IdentityAssuranceLevel::Token,
                expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            },
        )
        .expect("authenticated identity")
    }

    fn token_record(user_id: Option<&str>, team_id: Option<&str>) -> TokenRecord {
        TokenRecord {
            id: "token-1".to_string(),
            gateway_id: None,
            provider: None,
            model_filter: Vec::new(),
            team_id: team_id.map(str::to_string),
            user_id: user_id.map(str::to_string),
            max_budget: None,
            current_spend: 0.0,
            key_class: None,
            resource_id: None,
            resource_vrn: None,
            expires_at: None,
            metadata: serde_json::json!({}),
            rate_limit_rpm: None,
        }
    }

    #[test]
    fn policy_identity_preserves_authenticated_claims() {
        let identity = authenticated_identity();
        let mut finops = RequestFinopsContext {
            authenticated_identity: Some(identity.clone()),
            ..Default::default()
        };
        let policy = finops
            .policy_identity_context()
            .expect("policy identity context");

        assert_eq!(policy.proof_method, identity::IdentityProofMethod::ApiToken);
        assert_eq!(policy.issuer, "verdictan-api");
        assert_eq!(policy.subject, "user-1");
        assert_eq!(policy.credential_id, "token-1");
        assert_eq!(policy.org_id, "org-1");
        assert_eq!(policy.team_ids, ["team-a", "team-b"]);
        assert_eq!(policy.roles, ["member"]);
        assert_eq!(policy.scopes, ["events:read"]);
        assert_eq!(
            policy.assurance_level,
            identity::IdentityAssuranceLevel::Token
        );
        assert!(policy.expires_at.is_some());

        finops.authenticated_identity = None;
        assert!(finops.policy_identity_context().is_none());
    }

    #[test]
    fn token_claim_binding_rejects_every_authoritative_mismatch() {
        let identity = authenticated_identity();
        let matching = token_record(Some("user-1"), Some("team-a"));
        assert!(bind_authenticated_identity(&identity, Some("org-1"), &matching).is_valid());

        let org_mismatch = bind_authenticated_identity(&identity, Some("org-other"), &matching);
        assert!(!org_mismatch.org_matches);
        assert!(!org_mismatch.is_valid());

        let subject_mismatch = bind_authenticated_identity(
            &identity,
            Some("org-1"),
            &token_record(Some("user-other"), Some("team-a")),
        );
        assert!(!subject_mismatch.subject_matches);
        assert!(!subject_mismatch.is_valid());

        let credential_mismatch = bind_authenticated_identity(
            &identity,
            Some("org-1"),
            &TokenRecord {
                id: "token-other".to_string(),
                ..token_record(Some("user-1"), Some("team-a"))
            },
        );
        assert!(!credential_mismatch.credential_matches);
        assert!(!credential_mismatch.is_valid());

        let team_mismatch = bind_authenticated_identity(
            &identity,
            Some("org-1"),
            &token_record(Some("user-1"), Some("team-missing")),
        );
        assert!(!team_mismatch.team_matches);
        assert!(!team_mismatch.is_valid());
    }

    #[test]
    fn team_binding_rejects_requested_team_outside_authenticated_set() {
        let authenticated = vec!["team-a".to_string(), "team-b".to_string()];
        assert!(bind_selected_team_ids(&authenticated, &["team-missing".into()]).is_err());
        assert_eq!(
            bind_selected_team_ids(&authenticated, &["team-a".into()]).expect("subset"),
            vec!["team-a".to_string()]
        );
        assert_eq!(
            bind_selected_team_ids(&authenticated, &[]).expect("default"),
            authenticated
        );
    }

    #[test]
    fn policy_input_headers_reconstruct_from_authenticated_identity() {
        let identity = authenticated_identity();
        let ctx = RequestFinopsContext {
            authenticated_identity: Some(identity),
            selected_team_ids: vec!["team-a".to_string()],
            key_id: Some("token-1".to_string()),
            ..Default::default()
        };
        let mut h = HeaderMap::new();
        h.insert("X-Key-ID", "spoofed-key".parse().unwrap());
        h.insert("X-Org-ID", "spoofed-org".parse().unwrap());
        h.insert("X-Team-ID", "spoofed-team".parse().unwrap());
        h.insert("X-Verdictan-Team", "spoofed-team".parse().unwrap());
        h.insert("X-User-ID", "spoofed-user".parse().unwrap());
        h.insert("X-User-Role", "spoofed-role".parse().unwrap());
        h.insert("X-Custom", "kept".parse().unwrap());

        let result = policy_input_headers(&h, Some(&ctx));
        assert_eq!(result.get("X-Key-ID").unwrap().to_str().unwrap(), "token-1");
        assert_eq!(result.get("X-Org-ID").unwrap().to_str().unwrap(), "org-1");
        assert_eq!(result.get("X-User-ID").unwrap().to_str().unwrap(), "user-1");
        assert_eq!(result.get("X-Team-ID").unwrap().to_str().unwrap(), "team-a");
        assert_eq!(
            result.get("X-Verdictan-Team").unwrap().to_str().unwrap(),
            "team-a"
        );
        assert_eq!(
            result.get("X-User-Role").unwrap().to_str().unwrap(),
            "member"
        );
        assert_eq!(result.get("X-Custom").unwrap().to_str().unwrap(), "kept");
    }

    #[test]
    fn upstream_safe_headers_strip_all_reserved_identity_headers() {
        let mut h = HeaderMap::new();
        h.insert("X-Key-ID", "k".parse().unwrap());
        h.insert("X-Org-ID", "o".parse().unwrap());
        h.insert("X-Team-ID", "t".parse().unwrap());
        h.insert("X-Verdictan-Team", "t".parse().unwrap());
        h.insert("X-User-ID", "u".parse().unwrap());
        h.insert("X-User-Role", "r".parse().unwrap());
        h.insert("Content-Type", "application/json".parse().unwrap());

        let safe = upstream_safe_headers(&h);
        for name in RESERVED_IDENTITY_HEADERS {
            assert!(
                safe.get(*name).is_none(),
                "reserved header {name} must not reach upstream"
            );
        }
        assert_eq!(
            safe.get("Content-Type").unwrap().to_str().unwrap(),
            "application/json"
        );
    }

    #[test]
    fn inject_overwrites_spoofed_headers_from_authenticated_identity() {
        let identity = authenticated_identity();
        let ctx = RequestFinopsContext {
            authenticated_identity: Some(identity),
            selected_team_ids: vec!["team-b".to_string()],
            key_id: Some("token-1".to_string()),
            ..Default::default()
        };
        let mut headers = HeaderMap::new();
        headers.insert("X-Org-ID", "spoofed".parse().unwrap());
        inject_identity_headers_from_finops(&mut headers, Some(&ctx));
        assert_eq!(headers.get("X-Org-ID").unwrap().to_str().unwrap(), "org-1");
        assert_eq!(
            headers.get("X-Verdictan-Team").unwrap().to_str().unwrap(),
            "team-b"
        );
    }

    #[test]
    fn parse_requested_team_selectors_dedupes_team_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Verdictan-Team", "team-a, team-b".parse().unwrap());
        headers.insert("X-Team-ID", "team-b".parse().unwrap());
        assert_eq!(
            parse_requested_team_selectors(&headers),
            vec!["team-a".to_string(), "team-b".to_string()]
        );
    }
}
