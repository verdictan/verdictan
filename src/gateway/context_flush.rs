// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::agent_context::{AgentContextService, AppliedAgentContext, RuntimeContextConfig};
use super::session::GatewaySessionContext;

/// Flush state machine as described in the architecture plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlushState {
    NotRequired,
    FlushRequested,
    Flushed,
    ReResolved,
    FallbackToLossy,
    FailedClosed,
}

/// Policy governing what happens when flush fails or times out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushFailurePolicy {
    FallbackToLossy,
    FailClosed,
}

impl FlushFailurePolicy {
    pub fn parse(s: &str) -> Self {
        match s {
            "fail_closed" => Self::FailClosed,
            _ => Self::FallbackToLossy,
        }
    }
}

/// Configuration for the context flush step, sourced from agent policy.
#[derive(Debug, Clone)]
pub struct FlushConfig {
    pub enabled: bool,
    pub timeout_ms: u64,
    pub failure_policy: FlushFailurePolicy,
}

impl Default for FlushConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_ms: 5000,
            failure_policy: FlushFailurePolicy::FallbackToLossy,
        }
    }
}

/// Telemetry emitted by the flush orchestrator.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FlushTelemetry {
    pub state: String,
    pub flush_duration_ms: u64,
    pub condensation_id: Option<String>,
    pub re_resolved: bool,
    pub fallback_to_lossy: bool,
}

/// Request sent to the API flush endpoint.
#[derive(Debug, Serialize)]
struct FlushRequest {
    org_id: String,
    agent_id: String,
    history_session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    conversation_id: Option<String>,
    context_plan_hash: String,
    provider_token_budget: u32,
    estimated_tokens: u32,
}

/// Response from the API flush endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct FlushResponse {
    pub condensation_id: Option<String>,
    pub recall_document_id: Option<String>,
    #[serde(default)]
    pub condensed_tokens: u32,
}

/// Orchestrates the pre-compression context flush step.
///
/// This runs after normal context assembly when the estimated prompt exceeds
/// the provider token budget. The state machine:
/// 1. Check if flush is needed (estimated > budget) and enabled
/// 2. Call the API flush endpoint to persist a condensation
/// 3. Re-resolve context once to pick up the flush artifact
/// 4. If still oversized, fall back to lossy compression (or fail closed)
#[allow(clippy::too_many_arguments)]
pub async fn run_pre_compression_flush(
    agent_context_service: &AgentContextService,
    session: &GatewaySessionContext,
    gateway_id: Option<&str>,
    request_text: Option<&str>,
    runtime_config: RuntimeContextConfig,
    applied: &AppliedAgentContext,
    provider_token_budget: u32,
    flush_config: &FlushConfig,
) -> (FlushState, Option<AppliedAgentContext>, FlushTelemetry) {
    let mut telemetry = FlushTelemetry::default();

    if !flush_config.enabled {
        telemetry.state = FlushState::NotRequired.to_string();
        return (FlushState::NotRequired, None, telemetry);
    }

    let estimated = applied.telemetry.tokens.estimated_tokens;
    if estimated <= provider_token_budget {
        telemetry.state = FlushState::NotRequired.to_string();
        return (FlushState::NotRequired, None, telemetry);
    }

    tracing::info!(
        session_id = %session.session_id,
        estimated_tokens = estimated,
        provider_budget = provider_token_budget,
        "context flush requested: prompt exceeds provider budget"
    );

    let start = Instant::now();
    let timeout = Duration::from_millis(flush_config.timeout_ms);

    let flush_result = tokio::time::timeout(
        timeout,
        execute_flush(
            agent_context_service,
            session,
            &applied.telemetry.plan_hash,
            provider_token_budget,
            estimated,
        ),
    )
    .await;

    telemetry.flush_duration_ms = start.elapsed().as_millis() as u64;

    let flush_response = match flush_result {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "context flush execution failed");
            return handle_flush_failure(flush_config.failure_policy, &mut telemetry);
        }
        Err(_) => {
            tracing::warn!(
                timeout_ms = flush_config.timeout_ms,
                "context flush timed out"
            );
            return handle_flush_failure(flush_config.failure_policy, &mut telemetry);
        }
    };

    telemetry.condensation_id = flush_response.condensation_id.clone();
    telemetry.state = FlushState::Flushed.to_string();

    // Re-resolve context once to incorporate the flush artifact.
    let re_resolve_result = agent_context_service
        .resolve_context(session, gateway_id, request_text, runtime_config, None)
        .await;

    match re_resolve_result {
        Ok(Some(new_applied)) => {
            telemetry.re_resolved = true;
            if new_applied.telemetry.tokens.estimated_tokens <= provider_token_budget {
                telemetry.state = FlushState::ReResolved.to_string();
                tracing::info!(
                    session_id = %session.session_id,
                    new_tokens = new_applied.telemetry.tokens.estimated_tokens,
                    "context flush successful: re-resolved fits budget"
                );
                (FlushState::ReResolved, Some(new_applied), telemetry)
            } else {
                telemetry.fallback_to_lossy = true;
                telemetry.state = FlushState::FallbackToLossy.to_string();
                tracing::info!(
                    session_id = %session.session_id,
                    new_tokens = new_applied.telemetry.tokens.estimated_tokens,
                    "context flush: re-resolved still oversized, falling back to lossy"
                );
                (FlushState::FallbackToLossy, Some(new_applied), telemetry)
            }
        }
        Ok(None) => {
            telemetry.fallback_to_lossy = true;
            telemetry.state = FlushState::FallbackToLossy.to_string();
            (FlushState::FallbackToLossy, None, telemetry)
        }
        Err(e) => {
            tracing::warn!(error = %e, "re-resolve after flush failed");
            handle_flush_failure(flush_config.failure_policy, &mut telemetry)
        }
    }
}

/// Execute the flush by calling the API's context_flush endpoint.
async fn execute_flush(
    service: &AgentContextService,
    session: &GatewaySessionContext,
    plan_hash: &str,
    provider_budget: u32,
    estimated_tokens: u32,
) -> anyhow::Result<FlushResponse> {
    let Some(agent_id) = session.agent_id.as_deref() else {
        anyhow::bail!("context flush requires agent_id");
    };

    let request = FlushRequest {
        org_id: session._org_id.clone().unwrap_or_default(),
        agent_id: agent_id.to_string(),
        history_session_id: session.session_id.clone(),
        conversation_id: session.conversation_id.clone(),
        context_plan_hash: plan_hash.to_string(),
        provider_token_budget: provider_budget,
        estimated_tokens,
    };

    service.execute_context_flush(&request).await
}

pub fn handle_flush_failure(
    policy: FlushFailurePolicy,
    telemetry: &mut FlushTelemetry,
) -> (FlushState, Option<AppliedAgentContext>, FlushTelemetry) {
    match policy {
        FlushFailurePolicy::FallbackToLossy => {
            telemetry.fallback_to_lossy = true;
            telemetry.state = FlushState::FallbackToLossy.to_string();
            (FlushState::FallbackToLossy, None, telemetry.clone())
        }
        FlushFailurePolicy::FailClosed => {
            telemetry.state = FlushState::FailedClosed.to_string();
            (FlushState::FailedClosed, None, telemetry.clone())
        }
    }
}

impl FlushState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::FlushRequested => "flush_requested",
            Self::Flushed => "flushed",
            Self::ReResolved => "re_resolved",
            Self::FallbackToLossy => "fallback_to_lossy",
            Self::FailedClosed => "failed_closed",
        }
    }
}

impl std::fmt::Display for FlushState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
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

    #[test]
    fn flush_failure_policy_parse_fail_closed() {
        assert_eq!(
            FlushFailurePolicy::parse("fail_closed"),
            FlushFailurePolicy::FailClosed
        );
    }

    #[test]
    fn flush_failure_policy_parse_fallback() {
        assert_eq!(
            FlushFailurePolicy::parse("fallback_to_lossy"),
            FlushFailurePolicy::FallbackToLossy
        );
    }

    #[test]
    fn flush_failure_policy_parse_unknown_defaults_to_fallback() {
        assert_eq!(
            FlushFailurePolicy::parse(""),
            FlushFailurePolicy::FallbackToLossy
        );
        assert_eq!(
            FlushFailurePolicy::parse("anything"),
            FlushFailurePolicy::FallbackToLossy
        );
    }

    #[test]
    fn flush_config_defaults() {
        let config = FlushConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.failure_policy, FlushFailurePolicy::FallbackToLossy);
    }

    #[test]
    fn flush_state_as_str() {
        assert_eq!(FlushState::NotRequired.as_str(), "not_required");
        assert_eq!(FlushState::FlushRequested.as_str(), "flush_requested");
        assert_eq!(FlushState::Flushed.as_str(), "flushed");
        assert_eq!(FlushState::ReResolved.as_str(), "re_resolved");
        assert_eq!(FlushState::FallbackToLossy.as_str(), "fallback_to_lossy");
        assert_eq!(FlushState::FailedClosed.as_str(), "failed_closed");
    }

    #[test]
    fn flush_state_display() {
        assert_eq!(format!("{}", FlushState::Flushed), "flushed");
        assert_eq!(format!("{}", FlushState::FailedClosed), "failed_closed");
    }

    #[test]
    fn flush_state_serde_serialization() {
        let json = serde_json::to_string(&FlushState::FlushRequested).unwrap();
        assert_eq!(json, "\"flush_requested\"");
    }

    #[test]
    fn flush_telemetry_defaults() {
        let t = FlushTelemetry::default();
        assert_eq!(t.state, "");
        assert_eq!(t.flush_duration_ms, 0);
        assert!(t.condensation_id.is_none());
        assert!(!t.re_resolved);
        assert!(!t.fallback_to_lossy);
    }

    #[test]
    fn handle_flush_failure_fallback_to_lossy() {
        let mut telemetry = FlushTelemetry::default();
        let (state, applied, result_telemetry) =
            handle_flush_failure(FlushFailurePolicy::FallbackToLossy, &mut telemetry);
        assert_eq!(state, FlushState::FallbackToLossy);
        assert!(applied.is_none());
        assert!(result_telemetry.fallback_to_lossy);
        assert_eq!(result_telemetry.state, "fallback_to_lossy");
    }

    #[test]
    fn handle_flush_failure_fail_closed() {
        let mut telemetry = FlushTelemetry::default();
        let (state, applied, result_telemetry) =
            handle_flush_failure(FlushFailurePolicy::FailClosed, &mut telemetry);
        assert_eq!(state, FlushState::FailedClosed);
        assert!(applied.is_none());
        assert!(!result_telemetry.fallback_to_lossy);
        assert_eq!(result_telemetry.state, "failed_closed");
    }

    #[test]
    fn handle_flush_failure_preserves_existing_telemetry() {
        let mut telemetry = FlushTelemetry {
            flush_duration_ms: 42,
            condensation_id: Some("cond-1".to_string()),
            ..Default::default()
        };
        let (_, _, result_telemetry) =
            handle_flush_failure(FlushFailurePolicy::FallbackToLossy, &mut telemetry);
        assert_eq!(result_telemetry.flush_duration_ms, 42);
        assert_eq!(result_telemetry.condensation_id.as_deref(), Some("cond-1"));
    }

    #[test]
    fn flush_state_serde_all_variants() {
        let expected = [
            (FlushState::NotRequired, "\"not_required\""),
            (FlushState::FlushRequested, "\"flush_requested\""),
            (FlushState::Flushed, "\"flushed\""),
            (FlushState::ReResolved, "\"re_resolved\""),
            (FlushState::FallbackToLossy, "\"fallback_to_lossy\""),
            (FlushState::FailedClosed, "\"failed_closed\""),
        ];
        for (variant, json_str) in expected {
            assert_eq!(serde_json::to_string(&variant).unwrap(), json_str);
        }
    }

    #[test]
    fn flush_state_display_all_variants() {
        assert_eq!(format!("{}", FlushState::NotRequired), "not_required");
        assert_eq!(format!("{}", FlushState::FlushRequested), "flush_requested");
        assert_eq!(format!("{}", FlushState::ReResolved), "re_resolved");
        assert_eq!(
            format!("{}", FlushState::FallbackToLossy),
            "fallback_to_lossy"
        );
    }

    #[test]
    fn flush_failure_policy_parse_case_sensitive() {
        assert_eq!(
            FlushFailurePolicy::parse("Fail_Closed"),
            FlushFailurePolicy::FallbackToLossy
        );
    }

    #[test]
    fn flush_config_custom_values() {
        let config = FlushConfig {
            enabled: true,
            timeout_ms: 10000,
            failure_policy: FlushFailurePolicy::FailClosed,
        };
        assert!(config.enabled);
        assert_eq!(config.timeout_ms, 10000);
        assert_eq!(config.failure_policy, FlushFailurePolicy::FailClosed);
    }

    #[test]
    fn flush_telemetry_serialization() {
        let t = FlushTelemetry {
            state: "flushed".to_string(),
            flush_duration_ms: 150,
            condensation_id: Some("abc".to_string()),
            re_resolved: true,
            fallback_to_lossy: false,
        };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["state"], "flushed");
        assert_eq!(json["flush_duration_ms"], 150);
        assert_eq!(json["condensation_id"], "abc");
        assert_eq!(json["re_resolved"], true);
        assert_eq!(json["fallback_to_lossy"], false);
    }

    #[test]
    fn flush_response_deserialization() {
        let json = serde_json::json!({
            "condensation_id": "cond-abc",
            "recall_document_id": "doc-1",
            "condensed_tokens": 500
        });
        let resp: FlushResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.condensation_id.as_deref(), Some("cond-abc"));
        assert_eq!(resp.recall_document_id.as_deref(), Some("doc-1"));
        assert_eq!(resp.condensed_tokens, 500);
    }

    #[test]
    fn flush_response_deserialization_minimal() {
        let json = serde_json::json!({});
        let resp: FlushResponse = serde_json::from_value(json).unwrap();
        assert!(resp.condensation_id.is_none());
        assert!(resp.recall_document_id.is_none());
        assert_eq!(resp.condensed_tokens, 0);
    }
}
