// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Context-management configuration parsed from declarative gateway config.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OverflowStrategy {
    RouteToLarger,
    Summarize,
    Truncate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextManagementConfig {
    pub strategy: OverflowStrategy,
    pub max_summarization_ratio: f64,
    pub preserve_system_prompt: bool,
    pub preserve_last_n_messages: Option<usize>,
}

impl Default for ContextManagementConfig {
    fn default() -> Self {
        Self {
            strategy: OverflowStrategy::Truncate,
            max_summarization_ratio: 0.5,
            preserve_system_prompt: true,
            preserve_last_n_messages: Some(4),
        }
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
    fn default_config_values() {
        let cfg = ContextManagementConfig::default();
        assert!(matches!(cfg.strategy, OverflowStrategy::Truncate));
        assert_eq!(cfg.max_summarization_ratio, 0.5);
        assert!(cfg.preserve_system_prompt);
        assert_eq!(cfg.preserve_last_n_messages, Some(4));
    }

    #[test]
    fn config_serializes_to_json() {
        let cfg = ContextManagementConfig::default();
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["preserve_system_prompt"], true);
        assert_eq!(json["max_summarization_ratio"], 0.5);
        assert_eq!(json["preserve_last_n_messages"], 4);
    }

    #[test]
    fn config_deserializes_from_json() {
        let json = serde_json::json!({
            "strategy": "RouteToLarger",
            "max_summarization_ratio": 0.75,
            "preserve_system_prompt": false,
            "preserve_last_n_messages": 2
        });
        let cfg: ContextManagementConfig = serde_json::from_value(json).unwrap();
        assert!(matches!(cfg.strategy, OverflowStrategy::RouteToLarger));
        assert_eq!(cfg.max_summarization_ratio, 0.75);
        assert!(!cfg.preserve_system_prompt);
        assert_eq!(cfg.preserve_last_n_messages, Some(2));
    }

    #[test]
    fn config_deserializes_null_preserve_last_n() {
        let json = serde_json::json!({
            "strategy": "Summarize",
            "max_summarization_ratio": 0.3,
            "preserve_system_prompt": true,
            "preserve_last_n_messages": null
        });
        let cfg: ContextManagementConfig = serde_json::from_value(json).unwrap();
        assert!(matches!(cfg.strategy, OverflowStrategy::Summarize));
        assert_eq!(cfg.preserve_last_n_messages, None);
    }

    #[test]
    fn overflow_strategy_all_variants_serialize() {
        let variants = [
            OverflowStrategy::RouteToLarger,
            OverflowStrategy::Summarize,
            OverflowStrategy::Truncate,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            assert!(!json.is_empty());
            let roundtrip: OverflowStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(
                std::mem::discriminant(variant),
                std::mem::discriminant(&roundtrip)
            );
        }
    }
}
