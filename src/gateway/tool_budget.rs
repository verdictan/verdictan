// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::HashMap;

use serde_json::Value;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct ToolBudgetLimit {
    pub max_tokens: Option<u64>,
    /// Maximum tool actions allowed for this tool under the action-budget gate.
    #[serde(default)]
    pub max_calls: Option<u64>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct ToolBudgetConfig {
    #[serde(default)]
    pub budgets: HashMap<String, ToolBudgetLimit>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ToolBudgetDecision {
    pub flagged: bool,
    pub exceeded_tools: Vec<String>,
}

pub fn evaluate_budget(
    config: &ToolBudgetConfig,
    request_json: Option<&Value>,
) -> ToolBudgetDecision {
    let max_tokens = request_json
        .and_then(|json| json.get("max_tokens"))
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let requested_tools = crate::gateway::tool_validation::extract_requested_tools(request_json);
    let exceeded_tools = requested_tools
        .into_iter()
        .filter(|tool| {
            config
                .budgets
                .get(tool)
                .and_then(|limit| limit.max_tokens)
                .map(|limit| max_tokens > limit)
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();

    ToolBudgetDecision {
        flagged: !exceeded_tools.is_empty(),
        exceeded_tools,
    }
}

/// Evaluate remaining action budget for one actual tool invocation.
///
/// When the tool has a configured `max_calls` budget, dispatch is blocked if
/// `remaining_action_budget` is zero. A remaining count above `max_calls` is
/// also treated as inconsistent configuration input and blocked fail-closed.
pub fn evaluate_action_budget(
    config: &ToolBudgetConfig,
    tool_name: &str,
    remaining_action_budget: u64,
) -> ToolBudgetDecision {
    let Some(limit) = config.budgets.get(tool_name) else {
        return ToolBudgetDecision {
            flagged: false,
            exceeded_tools: Vec::new(),
        };
    };

    let Some(max_calls) = limit.max_calls else {
        return ToolBudgetDecision {
            flagged: false,
            exceeded_tools: Vec::new(),
        };
    };

    let exhausted = remaining_action_budget == 0 || remaining_action_budget > max_calls;
    ToolBudgetDecision {
        flagged: exhausted,
        exceeded_tools: if exhausted {
            vec![tool_name.to_string()]
        } else {
            Vec::new()
        },
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
    use serde_json::json;

    #[test]
    fn evaluate_budget_no_config_not_flagged() {
        let config = ToolBudgetConfig::default();
        let body = json!({
            "max_tokens": 1000,
            "tools": [{"function": {"name": "search"}}]
        });
        let result = evaluate_budget(&config, Some(&body));
        assert!(!result.flagged);
        assert!(result.exceeded_tools.is_empty());
    }

    #[test]
    fn evaluate_budget_within_limit_not_flagged() {
        let mut budgets = HashMap::new();
        budgets.insert(
            "search".to_string(),
            ToolBudgetLimit {
                max_tokens: Some(2000),
                max_calls: None,
            },
        );
        let config = ToolBudgetConfig { budgets };
        let body = json!({
            "max_tokens": 1000,
            "tools": [{"function": {"name": "search"}}]
        });
        let result = evaluate_budget(&config, Some(&body));
        assert!(!result.flagged);
        assert!(result.exceeded_tools.is_empty());
    }

    #[test]
    fn evaluate_budget_exceeds_limit_flagged() {
        let mut budgets = HashMap::new();
        budgets.insert(
            "search".to_string(),
            ToolBudgetLimit {
                max_tokens: Some(500),
                max_calls: None,
            },
        );
        let config = ToolBudgetConfig { budgets };
        let body = json!({
            "max_tokens": 1000,
            "tools": [{"function": {"name": "search"}}]
        });
        let result = evaluate_budget(&config, Some(&body));
        assert!(result.flagged);
        assert_eq!(result.exceeded_tools, vec!["search".to_string()]);
    }

    #[test]
    fn evaluate_budget_multiple_tools_partial_exceed() {
        let mut budgets = HashMap::new();
        budgets.insert(
            "expensive".to_string(),
            ToolBudgetLimit {
                max_tokens: Some(100),
                max_calls: None,
            },
        );
        budgets.insert(
            "cheap".to_string(),
            ToolBudgetLimit {
                max_tokens: Some(5000),
                max_calls: None,
            },
        );
        let config = ToolBudgetConfig { budgets };
        let body = json!({
            "max_tokens": 1000,
            "tools": [
                {"function": {"name": "expensive"}},
                {"function": {"name": "cheap"}}
            ]
        });
        let result = evaluate_budget(&config, Some(&body));
        assert!(result.flagged);
        assert_eq!(result.exceeded_tools, vec!["expensive".to_string()]);
    }

    #[test]
    fn evaluate_budget_no_max_tokens_in_request() {
        let mut budgets = HashMap::new();
        budgets.insert(
            "search".to_string(),
            ToolBudgetLimit {
                max_tokens: Some(500),
                max_calls: None,
            },
        );
        let config = ToolBudgetConfig { budgets };
        let body = json!({
            "tools": [{"function": {"name": "search"}}]
        });
        let result = evaluate_budget(&config, Some(&body));
        assert!(!result.flagged);
    }

    #[test]
    fn evaluate_budget_none_request() {
        let config = ToolBudgetConfig::default();
        let result = evaluate_budget(&config, None);
        assert!(!result.flagged);
        assert!(result.exceeded_tools.is_empty());
    }

    #[test]
    fn evaluate_budget_tool_without_budget_not_flagged() {
        let config = ToolBudgetConfig::default();
        let body = json!({
            "max_tokens": 99999,
            "tools": [{"function": {"name": "unconfigured"}}]
        });
        let result = evaluate_budget(&config, Some(&body));
        assert!(!result.flagged);
    }

    #[test]
    fn tool_budget_limit_no_max_tokens_not_flagged() {
        let mut budgets = HashMap::new();
        budgets.insert(
            "tool".to_string(),
            ToolBudgetLimit {
                max_tokens: None,
                max_calls: None,
            },
        );
        let config = ToolBudgetConfig { budgets };
        let body = json!({
            "max_tokens": 999999,
            "tools": [{"function": {"name": "tool"}}]
        });
        let result = evaluate_budget(&config, Some(&body));
        assert!(!result.flagged);
    }

    #[test]
    fn evaluate_action_budget_blocks_when_remaining_is_zero() {
        let mut budgets = HashMap::new();
        budgets.insert(
            "search".to_string(),
            ToolBudgetLimit {
                max_tokens: None,
                max_calls: Some(4),
            },
        );
        let config = ToolBudgetConfig { budgets };
        let decision = evaluate_action_budget(&config, "search", 0);
        assert!(decision.flagged);
        assert_eq!(decision.exceeded_tools, vec!["search".to_string()]);
    }

    #[test]
    fn evaluate_action_budget_allows_positive_remaining_within_max_calls() {
        let mut budgets = HashMap::new();
        budgets.insert(
            "search".to_string(),
            ToolBudgetLimit {
                max_tokens: None,
                max_calls: Some(4),
            },
        );
        let config = ToolBudgetConfig { budgets };
        let decision = evaluate_action_budget(&config, "search", 2);
        assert!(!decision.flagged);
    }

    #[test]
    fn evaluate_action_budget_ignores_tools_without_max_calls() {
        let mut budgets = HashMap::new();
        budgets.insert(
            "search".to_string(),
            ToolBudgetLimit {
                max_tokens: Some(10),
                max_calls: None,
            },
        );
        let config = ToolBudgetConfig { budgets };
        let decision = evaluate_action_budget(&config, "search", 0);
        assert!(!decision.flagged);
    }
}
