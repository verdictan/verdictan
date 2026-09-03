// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Tool-shape detection and pre-dispatch MCP/tool-action governance.
//!
//! Family handlers use [`request_uses_tooling_shape`] for capability checks.
//! Actual tool dispatch must call
//! [`crate::gateway::tool_validation::evaluate_tool_action_before_dispatch`]
//! immediately before invocation so validation, security, and budget run on the
//! real tool name, JSON arguments, actor, target server, risk class, approval
//! state, and remaining action budget.

use crate::gateway::runtime_capabilities;
use crate::gateway::tool_budget::ToolBudgetConfig;
use crate::gateway::tool_security::ToolSecurityConfig;
use crate::gateway::tool_validation::{
    evaluate_tool_action_before_dispatch, ToolActionContext, ToolActionPreDispatchDecision,
    ToolValidationConfig,
};

pub(crate) fn request_uses_tooling_shape(
    request_body: &serde_json::Value,
    request_contract: &runtime_capabilities::RuntimeCapabilityRequest,
) -> bool {
    request_body
        .get("tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| !tools.is_empty())
        || request_body.get("tool_choice").is_some()
        || request_body.get("parallel_tool_calls").is_some()
        || request_contract.interaction_features.iter().any(|feature| {
            matches!(
                feature,
                runtime_capabilities::InteractionFeature::ToolCalls
                    | runtime_capabilities::InteractionFeature::ToolResults
                    | runtime_capabilities::InteractionFeature::ParallelToolCalls
                    | runtime_capabilities::InteractionFeature::FineGrainedToolStreaming
            )
        })
}

/// Evaluate one actual tool action immediately before dispatch.
///
/// Pipeline and MCP bridge callers must invoke this on the concrete tool name
/// and JSON arguments rather than on a request-level `tools` declaration list.
async fn govern_tool_action_before_dispatch(
    validation_config: &ToolValidationConfig,
    security_config: &ToolSecurityConfig,
    budget_config: &ToolBudgetConfig,
    ctx: &ToolActionContext,
) -> ToolActionPreDispatchDecision {
    evaluate_tool_action_before_dispatch(validation_config, security_config, budget_config, ctx)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::tool_budget::ToolBudgetLimit;
    use crate::gateway::tool_validation::{canonical_argument_digest, ToolValidationConfig};
    use serde_json::json;
    use std::collections::HashMap;

    fn base_ctx(tool_name: &str, arguments: serde_json::Value) -> ToolActionContext {
        ToolActionContext {
            tool_name: tool_name.to_string(),
            arguments,
            authenticated_actor: "actor:user-1".to_string(),
            target_server: "tool-server:docs".to_string(),
            remaining_action_budget: 3,
        }
    }

    #[tokio::test]
    async fn pipeline_gate_allows_declared_safe_action() {
        let validation = ToolValidationConfig {
            declared_tools: vec!["search".to_string()],
            allow_undeclared: false,
            ..Default::default()
        };
        let decision = govern_tool_action_before_dispatch(
            &validation,
            &ToolSecurityConfig::default(),
            &ToolBudgetConfig::default(),
            &base_ctx("search", json!({"q": "rust"})),
        )
        .await;
        assert!(decision.allowed);
        assert!(decision.reason.is_none());
        assert!(decision.argument_digest.starts_with("sha256:"));
        assert_eq!(
            decision.evidence["argument_digest"],
            decision.argument_digest
        );
        assert!(decision.evidence.get("arguments").is_none());
    }

    #[tokio::test]
    async fn pipeline_gate_blocks_budget_bypass_when_remaining_is_zero() {
        let mut budgets = HashMap::new();
        budgets.insert(
            "search".to_string(),
            ToolBudgetLimit {
                max_tokens: None,
                max_calls: Some(5),
            },
        );
        let budget = ToolBudgetConfig { budgets };
        let mut ctx = base_ctx("search", json!({"q": "rust"}));
        ctx.remaining_action_budget = 0;
        let validation = ToolValidationConfig {
            declared_tools: vec!["search".to_string()],
            ..Default::default()
        };
        let decision = govern_tool_action_before_dispatch(
            &validation,
            &ToolSecurityConfig::default(),
            &budget,
            &ctx,
        )
        .await;
        assert!(!decision.allowed);
        assert!(decision
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("action_budget_exhausted"));
    }

    #[tokio::test]
    async fn pipeline_gate_blocks_undeclared_tool_action() {
        let validation = ToolValidationConfig {
            declared_tools: vec!["search".to_string()],
            allow_undeclared: false,
            ..Default::default()
        };
        let decision = govern_tool_action_before_dispatch(
            &validation,
            &ToolSecurityConfig::default(),
            &ToolBudgetConfig::default(),
            &base_ctx("delete_file", json!({"path": "/tmp/demo"})),
        )
        .await;
        assert!(!decision.allowed);
        assert!(decision
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("undeclared_tools:delete_file"));
    }

    #[tokio::test]
    async fn argument_digest_omits_configured_secrets_from_evidence() {
        let args = json!({
            "path": "/tmp/demo",
            "api_key": "sk-live-super-secret",
            "authorization": "Bearer firewall-secret",
            "nested": {"password": "hunter2", "q": "ok"}
        });
        let digest = canonical_argument_digest(&args);
        let validation = ToolValidationConfig {
            declared_tools: vec!["upload".to_string()],
            ..Default::default()
        };
        let decision = govern_tool_action_before_dispatch(
            &validation,
            &ToolSecurityConfig::default(),
            &ToolBudgetConfig::default(),
            &base_ctx("upload", args),
        )
        .await;
        assert_eq!(decision.argument_digest, digest);
        let evidence = decision.evidence.to_string();
        assert!(!evidence.contains("sk-live-super-secret"));
        assert!(!evidence.contains("firewall-secret"));
        assert!(!evidence.contains("hunter2"));
        assert!(evidence.contains(&digest));
    }

    #[test]
    fn tooling_shape_detects_tools_array_without_contract_features() {
        let body = json!({"tools": [{"name": "search"}]});
        let contract = runtime_capabilities::RuntimeCapabilityRequest {
            family: runtime_capabilities::RequestFamily::ChatCompletions,
            input_modalities: Vec::new(),
            output_modalities: Vec::new(),
            interaction_features: Vec::new(),
            transport_mode: runtime_capabilities::TransportMode::Json,
            response_format_feature: None,
            routing_policy_features: Vec::new(),
            caching_features: Vec::new(),
            plugin_features: Vec::new(),
            beta_headers: Vec::new(),
            requires_strict_mode: false,
        };
        assert!(request_uses_tooling_shape(&body, &contract));
    }
}
