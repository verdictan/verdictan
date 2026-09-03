// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Tool-risk classification and enforcement.
//!
//! Classifies tool invocations by risk level and determines whether operator
//! approval is required before execution. The module is gated behind the
//! `destructive_action_approval_enforcement` runtime flag and is **disabled by
//! default** until Phase 14 routes are live.
//!
//! ## Risk levels
//!
//! | Level | Meaning |
//! |--------------|-------------------------------------------------------------|
//! | `Safe` | Read-only or idempotent; no approval required. |
//! | `Moderate` | Write with bounded blast radius; approval optional per policy. |
//! | `Destructive`| Irreversible or wide-blast-radius write; approval required. |
//! | `Critical` | System-level or cross-boundary; always requires approval. |

use serde::{Deserialize, Serialize};

// ── Risk level ────────────────────────────────────────────────────────────────

/// Coarse classification of a tool action's risk to data and system integrity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolRiskLevel {
    /// Read-only or idempotent; no approval needed.
    Safe,
    /// Bounded write; approval optional based on policy.
    Moderate,
    /// Irreversible or wide-blast-radius write; approval required.
    Destructive,
    /// Cross-boundary or system-level; always requires approval.
    Critical,
}

// ── Action type ───────────────────────────────────────────────────────────────

/// Semantic category of the action a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolActionType {
    FilesystemDelete,
    FilesystemWrite,
    FilesystemExecute,
    NotificationSend,
    ToolExecute,
    NetworkEgress,
}

// ── Rule ──────────────────────────────────────────────────────────────────────

/// A single risk-classification rule.
///
/// The `pattern` is matched as a case-insensitive substring of the combined
/// `"{action} {resource}"` string so it can match command names, resource
/// paths, or URL patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRiskRule {
    /// Substring pattern to match against the `"{action} {resource}"` string.
    pub pattern: String,
    /// Semantic action type for structured logging and policy decisions.
    pub action_type: ToolActionType,
    /// Risk classification assigned when this rule matches.
    pub risk_level: ToolRiskLevel,
    /// Whether an explicit operator approval grant is required.
    pub requires_approval: bool,
}

// ── Policy ────────────────────────────────────────────────────────────────────

/// Destructive-action approval policy loaded from gateway configuration.
///
/// The policy is **disabled by default** (`enabled: false`). Set
/// `destructive_action_approval_enforcement: true` in the gateway config
/// to activate enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestructiveActionPolicy {
    /// Runtime flag: `false` means the module is a no-op.
    #[serde(default)]
    pub enabled: bool,
    /// Ordered list of classification rules. First match wins.
    #[serde(default = "default_risk_rules")]
    pub risk_rules: Vec<ToolRiskRule>,
}

impl Default for DestructiveActionPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            risk_rules: default_risk_rules(),
        }
    }
}

// ── Classification result ─────────────────────────────────────────────────────

/// The result of classifying a tool invocation against the policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRiskClassification {
    /// The action string that was classified.
    pub action: String,
    /// The resource string that was classified.
    pub resource_kind: String,
    /// The full resource locator (path, URL, etc.).
    pub resource_locator: String,
    /// Assigned risk level.
    pub risk_level: ToolRiskLevel,
    /// Whether this invocation requires an explicit approval grant.
    pub requires_approval: bool,
    /// Human-readable explanation of why this rule matched.
    pub policy_match_reason: String,
}

// ── Default rules ─────────────────────────────────────────────────────────────

/// Seed the default rule table covering the highest-risk action patterns.
///
/// Rules are evaluated in order; the first match wins.
fn default_risk_rules() -> Vec<ToolRiskRule> {
    vec![
        // ── Critical: hard-reset and force-push git operations ────────────────
        ToolRiskRule {
            pattern: "git reset".to_string(),
            action_type: ToolActionType::FilesystemWrite,
            risk_level: ToolRiskLevel::Critical,
            requires_approval: true,
        },
        ToolRiskRule {
            pattern: "git push --force".to_string(),
            action_type: ToolActionType::FilesystemWrite,
            risk_level: ToolRiskLevel::Critical,
            requires_approval: true,
        },
        ToolRiskRule {
            pattern: "git push -f".to_string(),
            action_type: ToolActionType::FilesystemWrite,
            risk_level: ToolRiskLevel::Critical,
            requires_approval: true,
        },
        // ── Destructive: normal git writes ────────────────────────────────────
        ToolRiskRule {
            pattern: "git commit".to_string(),
            action_type: ToolActionType::FilesystemWrite,
            risk_level: ToolRiskLevel::Destructive,
            requires_approval: true,
        },
        ToolRiskRule {
            pattern: "git push".to_string(),
            action_type: ToolActionType::NetworkEgress,
            risk_level: ToolRiskLevel::Destructive,
            requires_approval: true,
        },
        // ── Critical: recursive file deletion ─────────────────────────────────
        ToolRiskRule {
            pattern: "rm -rf".to_string(),
            action_type: ToolActionType::FilesystemDelete,
            risk_level: ToolRiskLevel::Critical,
            requires_approval: true,
        },
        ToolRiskRule {
            pattern: "rm -r".to_string(),
            action_type: ToolActionType::FilesystemDelete,
            risk_level: ToolRiskLevel::Critical,
            requires_approval: true,
        },
        // ── Destructive: privileged filesystem execution ───────────────────────
        ToolRiskRule {
            pattern: "chmod +x".to_string(),
            action_type: ToolActionType::FilesystemExecute,
            risk_level: ToolRiskLevel::Destructive,
            requires_approval: true,
        },
        ToolRiskRule {
            pattern: "sudo ".to_string(),
            action_type: ToolActionType::FilesystemExecute,
            risk_level: ToolRiskLevel::Critical,
            requires_approval: true,
        },
        // ── Moderate: external notification sends ─────────────────────────────
        ToolRiskRule {
            pattern: "notify.send".to_string(),
            action_type: ToolActionType::NotificationSend,
            risk_level: ToolRiskLevel::Moderate,
            requires_approval: false,
        },
        ToolRiskRule {
            pattern: "notification.send".to_string(),
            action_type: ToolActionType::NotificationSend,
            risk_level: ToolRiskLevel::Moderate,
            requires_approval: false,
        },
        // ── Critical: privileged network egress ────────────────────────────────
        ToolRiskRule {
            pattern: "curl http://".to_string(),
            action_type: ToolActionType::NetworkEgress,
            risk_level: ToolRiskLevel::Critical,
            requires_approval: true,
        },
        ToolRiskRule {
            pattern: "wget ".to_string(),
            action_type: ToolActionType::NetworkEgress,
            risk_level: ToolRiskLevel::Destructive,
            requires_approval: true,
        },
        // ── Moderate: filesystem writes ───────────────────────────────────────
        ToolRiskRule {
            pattern: "write_file".to_string(),
            action_type: ToolActionType::FilesystemWrite,
            risk_level: ToolRiskLevel::Moderate,
            requires_approval: false,
        },
        ToolRiskRule {
            pattern: "create_file".to_string(),
            action_type: ToolActionType::FilesystemWrite,
            risk_level: ToolRiskLevel::Moderate,
            requires_approval: false,
        },
    ]
}

// ── Classification function ───────────────────────────────────────────────────

/// Classify a tool invocation against the policy.
///
/// When the policy is disabled (`enabled: false`) every invocation is returned
/// as `Safe` with `requires_approval: false` so existing behaviour is
/// unchanged until Phase 14 routes are live.
///
/// When enabled, rules are evaluated in insertion order; the first match wins.
/// If no rule matches, the invocation is classified as `Safe`.
pub fn classify_tool_action(
    policy: &DestructiveActionPolicy,
    action: &str,
    resource: &str,
) -> ToolRiskClassification {
    if !policy.enabled {
        return ToolRiskClassification {
            action: action.to_string(),
            resource_kind: infer_resource_kind(resource),
            resource_locator: resource.to_string(),
            risk_level: ToolRiskLevel::Safe,
            requires_approval: false,
            policy_match_reason: "policy_disabled".to_string(),
        };
    }

    let haystack = format!("{action} {resource}").to_ascii_lowercase();

    for rule in &policy.risk_rules {
        let needle = rule.pattern.to_ascii_lowercase();
        if !needle.is_empty() && haystack.contains(needle.as_str()) {
            return ToolRiskClassification {
                action: action.to_string(),
                resource_kind: infer_resource_kind(resource),
                resource_locator: resource.to_string(),
                risk_level: rule.risk_level,
                requires_approval: rule.requires_approval,
                policy_match_reason: format!("matched_rule:{}", rule.pattern),
            };
        }
    }

    // No rule matched: safe by default.
    ToolRiskClassification {
        action: action.to_string(),
        resource_kind: infer_resource_kind(resource),
        resource_locator: resource.to_string(),
        risk_level: ToolRiskLevel::Safe,
        requires_approval: false,
        policy_match_reason: "no_rule_matched".to_string(),
    }
}

/// Derive a coarse resource kind label from the resource locator string.
fn infer_resource_kind(resource: &str) -> String {
    let r = resource.to_ascii_lowercase();
    if r.starts_with("http://") || r.starts_with("https://") {
        "url".to_string()
    } else if r.starts_with('/') || r.contains('\\') {
        "filesystem_path".to_string()
    } else if r.is_empty() {
        "unspecified".to_string()
    } else {
        "tool_argument".to_string()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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
    fn disabled_policy_returns_safe() {
        let policy = DestructiveActionPolicy::default();
        assert!(!policy.enabled);
        let result = classify_tool_action(&policy, "rm -rf", "/tmp/data");
        assert_eq!(result.risk_level, ToolRiskLevel::Safe);
        assert!(!result.requires_approval);
        assert_eq!(result.policy_match_reason, "policy_disabled");
    }

    #[test]
    fn enabled_policy_matches_git_reset_as_critical() {
        let policy = DestructiveActionPolicy {
            enabled: true,
            ..Default::default()
        };
        let result = classify_tool_action(&policy, "git reset", "--hard HEAD");
        assert_eq!(result.risk_level, ToolRiskLevel::Critical);
        assert!(result.requires_approval);
        assert!(result.policy_match_reason.contains("git reset"));
    }

    #[test]
    fn enabled_policy_matches_force_push() {
        let policy = DestructiveActionPolicy {
            enabled: true,
            ..Default::default()
        };
        let result = classify_tool_action(&policy, "git push --force", "origin main");
        assert_eq!(result.risk_level, ToolRiskLevel::Critical);
        assert!(result.requires_approval);
    }

    #[test]
    fn enabled_policy_matches_rm_rf() {
        let policy = DestructiveActionPolicy {
            enabled: true,
            ..Default::default()
        };
        let result = classify_tool_action(&policy, "rm -rf", "/important/data");
        assert_eq!(result.risk_level, ToolRiskLevel::Critical);
        assert!(result.requires_approval);
    }

    #[test]
    fn enabled_policy_matches_sudo() {
        let policy = DestructiveActionPolicy {
            enabled: true,
            ..Default::default()
        };
        let result = classify_tool_action(&policy, "sudo ", "apt install foo");
        assert_eq!(result.risk_level, ToolRiskLevel::Critical);
        assert!(result.requires_approval);
    }

    #[test]
    fn enabled_policy_matches_git_commit_as_destructive() {
        let policy = DestructiveActionPolicy {
            enabled: true,
            ..Default::default()
        };
        let result = classify_tool_action(&policy, "git commit", "-m fix");
        assert_eq!(result.risk_level, ToolRiskLevel::Destructive);
        assert!(result.requires_approval);
    }

    #[test]
    fn enabled_policy_matches_git_push_as_destructive() {
        let policy = DestructiveActionPolicy {
            enabled: true,
            ..Default::default()
        };
        let result = classify_tool_action(&policy, "git push", "origin feature");
        assert_eq!(result.risk_level, ToolRiskLevel::Destructive);
        assert!(result.requires_approval);
    }

    #[test]
    fn enabled_policy_matches_wget_as_destructive() {
        let policy = DestructiveActionPolicy {
            enabled: true,
            ..Default::default()
        };
        let result = classify_tool_action(&policy, "wget ", "http://example.com/file");
        assert_eq!(result.risk_level, ToolRiskLevel::Destructive);
        assert!(result.requires_approval);
    }

    #[test]
    fn enabled_policy_matches_write_file_as_moderate() {
        let policy = DestructiveActionPolicy {
            enabled: true,
            ..Default::default()
        };
        let result = classify_tool_action(&policy, "write_file", "/tmp/output.txt");
        assert_eq!(result.risk_level, ToolRiskLevel::Moderate);
        assert!(!result.requires_approval);
    }

    #[test]
    fn enabled_policy_matches_notification_as_moderate() {
        let policy = DestructiveActionPolicy {
            enabled: true,
            ..Default::default()
        };
        let result = classify_tool_action(&policy, "notify.send", "channel");
        assert_eq!(result.risk_level, ToolRiskLevel::Moderate);
        assert!(!result.requires_approval);
    }

    #[test]
    fn enabled_policy_no_match_returns_safe() {
        let policy = DestructiveActionPolicy {
            enabled: true,
            ..Default::default()
        };
        let result = classify_tool_action(&policy, "read_file", "/tmp/data.txt");
        assert_eq!(result.risk_level, ToolRiskLevel::Safe);
        assert!(!result.requires_approval);
        assert_eq!(result.policy_match_reason, "no_rule_matched");
    }

    #[test]
    fn classify_is_case_insensitive() {
        let policy = DestructiveActionPolicy {
            enabled: true,
            ..Default::default()
        };
        let result = classify_tool_action(&policy, "GIT RESET", "--hard");
        assert_eq!(result.risk_level, ToolRiskLevel::Critical);
    }

    #[test]
    fn first_matching_rule_wins() {
        let policy = DestructiveActionPolicy {
            enabled: true,
            ..Default::default()
        };
        // "git push --force" matches both "git push --force" (Critical) and "git push" (Destructive)
        // First match should be Critical since --force rule comes first.
        let result = classify_tool_action(&policy, "git push --force", "origin main");
        assert_eq!(result.risk_level, ToolRiskLevel::Critical);
    }

    #[test]
    fn infer_resource_kind_url() {
        assert_eq!(infer_resource_kind("http://example.com"), "url");
        assert_eq!(infer_resource_kind("https://api.test.io/v1"), "url");
    }

    #[test]
    fn infer_resource_kind_filesystem() {
        assert_eq!(infer_resource_kind("/tmp/data.txt"), "filesystem_path");
        assert_eq!(infer_resource_kind("C:\\Users\\file"), "filesystem_path");
    }

    #[test]
    fn infer_resource_kind_empty() {
        assert_eq!(infer_resource_kind(""), "unspecified");
    }

    #[test]
    fn infer_resource_kind_tool_argument() {
        assert_eq!(infer_resource_kind("some-argument"), "tool_argument");
    }

    #[test]
    fn tool_risk_level_ordering() {
        assert!(ToolRiskLevel::Safe < ToolRiskLevel::Moderate);
        assert!(ToolRiskLevel::Moderate < ToolRiskLevel::Destructive);
        assert!(ToolRiskLevel::Destructive < ToolRiskLevel::Critical);
    }

    #[test]
    fn default_risk_rules_are_non_empty() {
        let rules = default_risk_rules();
        assert!(!rules.is_empty());
    }

    #[test]
    fn tool_risk_level_serde_roundtrip() {
        let json = serde_json::to_string(&ToolRiskLevel::Critical).unwrap();
        let parsed: ToolRiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ToolRiskLevel::Critical);
    }

    #[test]
    fn tool_action_type_serde_roundtrip() {
        let json = serde_json::to_string(&ToolActionType::FilesystemDelete).unwrap();
        let parsed: ToolActionType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ToolActionType::FilesystemDelete);
    }

    #[test]
    fn classification_populates_all_fields() {
        let policy = DestructiveActionPolicy {
            enabled: true,
            ..Default::default()
        };
        let result = classify_tool_action(&policy, "rm -rf", "/var/data");
        assert_eq!(result.action, "rm -rf");
        assert_eq!(result.resource_locator, "/var/data");
        assert_eq!(result.resource_kind, "filesystem_path");
        assert!(result.policy_match_reason.starts_with("matched_rule:"));
    }
}
