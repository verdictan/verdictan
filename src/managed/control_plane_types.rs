// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Typed API response structs for control-plane endpoints.
//!
//! These types model the JSON shapes returned by the control-plane API and
//! replace ad-hoc `serde_json::Value` access patterns with compile-time
//! checked deserialization. Used by `control_export` and `control_reconcile`.

use serde::Deserialize;

use crate::managed::control_manifest::{AgentContextFabricSpec, AgentMcpSpec, ResourceTagSpec};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Deserialize an array of items from a JSON wrapper object.
///
/// Extracts `value[key]` as a JSON array and deserializes each element into `T`.
/// Items that fail deserialization are silently dropped (matching the previous
/// `filter_map` semantics). Returns an empty `Vec` if the key is missing.
pub(crate) fn extract_typed_list<T: serde::de::DeserializeOwned>(
    value: &serde_json::Value,
    key: &str,
) -> Vec<T> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Convert typed resource-tag items into [`ResourceTagSpec`].
pub(crate) fn resource_tags_to_specs(resource_tags: &[ResourceTagItem]) -> Vec<ResourceTagSpec> {
    resource_tags
        .iter()
        .filter_map(|tag| {
            Some(ResourceTagSpec {
                key: tag.key.clone()?,
                value: tag.value.clone()?,
                source: tag.source.clone(),
            })
        })
        .collect()
}

// ── Generic named-resource for fetch_remote_list ──────────────────────────────

/// A named API resource with a polymorphic ID field.
///
/// Different API endpoints return the resource ID under different field names
/// (`id`, `policy_id`, `role_id`, etc.). This struct captures all known ID
/// field names so `fetch_remote_list` can resolve them uniformly.
#[derive(Debug, Deserialize)]
pub(crate) struct NamedResource {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub role_id: Option<String>,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
}

impl NamedResource {
    /// Resolve the resource ID trying each known field name in priority order.
    pub fn resolved_id(&self) -> Option<&str> {
        self.id
            .as_deref()
            .or(self.policy_id.as_deref())
            .or(self.role_id.as_deref())
            .or(self.team_id.as_deref())
            .or(self.agent_id.as_deref())
    }
}

/// A user resource keyed by email.
#[derive(Debug, Deserialize)]
pub(crate) struct UserResource {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
}

impl UserResource {
    pub fn resolved_id(&self) -> Option<&str> {
        self.id.as_deref().or(self.user_id.as_deref())
    }
}

/// ID extracted from a create/update API response.
#[derive(Debug, Deserialize)]
pub(crate) struct ResourceIdResponse {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub role_id: Option<String>,
    #[serde(default)]
    pub policy_id: Option<String>,
}

impl ResourceIdResponse {
    pub fn resolved_id(&self) -> String {
        self.id
            .as_deref()
            .or(self.role_id.as_deref())
            .or(self.policy_id.as_deref())
            .unwrap_or("")
            .to_string()
    }
}

// ── Secrets ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct SecretItem {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub env_var: Option<String>,
}

// ── IAM ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct PolicyItem {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub statements: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RolePolicyRef {
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RoleItem {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub policies: Vec<RolePolicyRef>,
}

// ── Teams ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct TeamItem {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

impl TeamItem {
    pub fn resolved_id(&self) -> Option<&str> {
        self.id.as_deref().or(self.team_id.as_deref())
    }
}

// ── Users ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct UserItem {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

impl UserItem {
    pub fn resolved_id(&self) -> Option<&str> {
        self.id.as_deref().or(self.user_id.as_deref())
    }
}

// ── Agents ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct AgentItem {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub team_name: Option<String>,
    #[serde(default)]
    pub team: Option<String>,
    #[serde(default)]
    pub gateway_ids: Vec<String>,
    #[serde(default)]
    pub scope_kind: Option<String>,
    #[serde(default)]
    pub configuration_id: Option<String>,
    #[serde(default)]
    pub active_configuration_version_id: Option<String>,
    #[serde(default)]
    pub configuration_version_id: Option<String>,
    #[serde(default)]
    pub resource_name: Option<String>,
    #[serde(default)]
    pub resource_tags: Vec<ResourceTagItem>,
    #[serde(default)]
    pub context_fabric: Option<AgentContextFabricSpec>,
    #[serde(default)]
    pub mcp: Option<AgentMcpSpec>,
}

impl AgentItem {
    pub fn resolved_id(&self) -> Option<&str> {
        self.id.as_deref().or(self.agent_id.as_deref())
    }
}

// ── Platform provider bundles ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct PlatformProviderBundleItem {
    #[serde(default)]
    pub bundle_key: Option<String>,
    #[serde(default)]
    pub provider_registry: Option<serde_json::Value>,
    #[serde(default)]
    pub status: Option<String>,
}

// ── Regulated execution profiles ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct RegulatedExecutionProfileItem {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub deployment_profile: Option<String>,
    #[serde(default)]
    pub default: Option<bool>,
    #[serde(default)]
    pub residency_region: Option<String>,
    #[serde(default)]
    pub data_residency_tag: Option<String>,
    #[serde(default)]
    pub cross_border_policy: Option<String>,
    #[serde(default)]
    pub tokenization_enabled: Option<bool>,
    #[serde(default)]
    pub require_in_memory_only: Option<bool>,
    #[serde(default)]
    pub allow_internet_egress: Option<bool>,
    #[serde(default)]
    pub workload_class: Option<String>,
    #[serde(default)]
    pub deletion_attestation_enabled: Option<bool>,
    #[serde(default)]
    pub fail_mode: Option<String>,
}

// ── Approval policies ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct ApprovalPolicyItem {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub simulation_mode: Option<bool>,
    #[serde(default)]
    pub break_glass_enabled: Option<bool>,
    #[serde(default)]
    pub break_glass_post_review_required: Option<bool>,
    #[serde(default)]
    pub thresholds: Vec<ApprovalThresholdItem>,
    #[serde(default)]
    pub approver_chains: Vec<ApproverChainItem>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApprovalThresholdItem {
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub data_class: Option<String>,
    #[serde(default)]
    pub destination_pattern: Option<String>,
    #[serde(default)]
    pub approval_mode: Option<String>,
    #[serde(default)]
    pub required_approvals: Option<u32>,
    #[serde(default)]
    pub decision_ttl_minutes: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApproverChainItem {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub approvers: Vec<String>,
    #[serde(default)]
    pub backup_approvers: Vec<String>,
    #[serde(default)]
    pub escalation_after_minutes: Option<u32>,
}

// ── Billing budgets ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct BudgetItem {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub amount: Option<String>,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub period_type: Option<String>,
    #[serde(default)]
    pub alert_thresholds: Vec<i32>,
    #[serde(default)]
    pub hard_limit_enabled: Option<bool>,
    #[serde(default)]
    pub hard_limit_amount: Option<String>,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub week_starts_on: Option<String>,
    #[serde(default)]
    pub month_anchor_day: Option<i16>,
    #[serde(default)]
    pub billing_categories: Vec<String>,
}

// ── Prompt evaluation suites ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct PromptSuiteItem {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub resource_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub suite_id: Option<String>,
    #[serde(default)]
    pub resource_tags: Vec<ResourceTagItem>,
}

impl PromptSuiteItem {
    pub fn resolved_id(&self) -> Option<&str> {
        self.id.as_deref().or(self.suite_id.as_deref())
    }
}

// ── Gateways ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct GatewayItem {
    #[serde(default)]
    pub id: Option<String>,
}

// ── Agent binding ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct AgentBindingResponse {
    #[serde(default)]
    pub binding_mode: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
}

// ── Hosted gateway policy ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct HostedGatewayPolicyResponse {
    #[serde(default, alias = "default_agent")]
    pub default_agent_id: Option<String>,
    #[serde(default)]
    pub default_agent_fallback_enabled: Option<bool>,
    #[serde(default)]
    pub fail_closed_on_missing_binding: Option<bool>,
}

// ── Resource tags ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct ResourceTagItem {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
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
    fn command_helper_coverage_extract_typed_list_deserializes_valid_items() {
        let value = json!({
            "policies": [
                {"name": "allow-read", "policy_id": "pol-1"},
                {"name": "broken"},
                "not-an-object"
            ]
        });

        let policies: Vec<NamedResource> = extract_typed_list(&value, "policies");
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].resolved_id(), Some("pol-1"));
        assert_eq!(policies[1].resolved_id(), None);
    }

    #[test]
    fn command_helper_coverage_resource_tags_to_specs_skips_incomplete_tags() {
        let specs = resource_tags_to_specs(&[
            ResourceTagItem {
                key: Some("env".to_string()),
                value: Some("prod".to_string()),
                source: Some("manifest".to_string()),
            },
            ResourceTagItem {
                key: None,
                value: Some("ignored".to_string()),
                source: None,
            },
        ]);

        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].key, "env");
        assert_eq!(specs[0].value, "prod");
        assert_eq!(specs[0].source.as_deref(), Some("manifest"));
    }

    #[test]
    fn command_helper_coverage_named_resource_resolved_id_checks_fields() {
        let policy = NamedResource {
            name: Some("policy".to_string()),
            id: None,
            policy_id: Some("pol-99".to_string()),
            role_id: None,
            team_id: None,
            agent_id: None,
        };
        assert_eq!(policy.resolved_id(), Some("pol-99"));
    }

    #[test]
    fn command_helper_coverage_user_resource_and_id_response_resolve_ids() {
        let user = UserResource {
            email: Some("ops@example.com".to_string()),
            id: None,
            user_id: Some("user-42".to_string()),
        };
        assert_eq!(user.resolved_id(), Some("user-42"));

        let response = ResourceIdResponse {
            id: None,
            role_id: Some("role-1".to_string()),
            policy_id: None,
        };
        assert_eq!(response.resolved_id(), "role-1");
    }

    #[test]
    fn extract_typed_list_returns_empty_for_missing_key() {
        let value = json!({"other": []});
        let result: Vec<NamedResource> = extract_typed_list(&value, "policies");
        assert!(result.is_empty());
    }

    #[test]
    fn extract_typed_list_returns_empty_for_non_array() {
        let value = json!({"policies": "not-an-array"});
        let result: Vec<NamedResource> = extract_typed_list(&value, "policies");
        assert!(result.is_empty());
    }

    #[test]
    fn extract_typed_list_skips_malformed_items() {
        let value = json!({"items": [42, null, {"name": "valid"}]});
        let result: Vec<NamedResource> = extract_typed_list(&value, "items");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name.as_deref(), Some("valid"));
    }

    #[test]
    fn named_resource_resolved_id_prefers_id_over_others() {
        let resource = NamedResource {
            name: Some("test".to_string()),
            id: Some("id-1".to_string()),
            policy_id: Some("pol-2".to_string()),
            role_id: Some("role-3".to_string()),
            team_id: Some("team-4".to_string()),
            agent_id: Some("agent-5".to_string()),
        };
        assert_eq!(resource.resolved_id(), Some("id-1"));
    }

    #[test]
    fn named_resource_resolved_id_falls_through_to_role_id() {
        let resource = NamedResource {
            name: None,
            id: None,
            policy_id: None,
            role_id: Some("role-3".to_string()),
            team_id: None,
            agent_id: None,
        };
        assert_eq!(resource.resolved_id(), Some("role-3"));
    }

    #[test]
    fn named_resource_resolved_id_falls_through_to_team_id() {
        let resource = NamedResource {
            name: None,
            id: None,
            policy_id: None,
            role_id: None,
            team_id: Some("team-4".to_string()),
            agent_id: None,
        };
        assert_eq!(resource.resolved_id(), Some("team-4"));
    }

    #[test]
    fn named_resource_resolved_id_falls_through_to_agent_id() {
        let resource = NamedResource {
            name: None,
            id: None,
            policy_id: None,
            role_id: None,
            team_id: None,
            agent_id: Some("agent-5".to_string()),
        };
        assert_eq!(resource.resolved_id(), Some("agent-5"));
    }

    #[test]
    fn named_resource_resolved_id_returns_none_when_all_empty() {
        let resource = NamedResource {
            name: Some("name-only".to_string()),
            id: None,
            policy_id: None,
            role_id: None,
            team_id: None,
            agent_id: None,
        };
        assert_eq!(resource.resolved_id(), None);
    }

    #[test]
    fn user_resource_resolved_id_prefers_id() {
        let user = UserResource {
            email: None,
            id: Some("id-1".to_string()),
            user_id: Some("user-2".to_string()),
        };
        assert_eq!(user.resolved_id(), Some("id-1"));
    }

    #[test]
    fn user_resource_resolved_id_returns_none() {
        let user = UserResource {
            email: Some("test@example.com".to_string()),
            id: None,
            user_id: None,
        };
        assert_eq!(user.resolved_id(), None);
    }

    #[test]
    fn resource_id_response_resolved_id_prefers_id() {
        let response = ResourceIdResponse {
            id: Some("id-1".to_string()),
            role_id: Some("role-2".to_string()),
            policy_id: Some("pol-3".to_string()),
        };
        assert_eq!(response.resolved_id(), "id-1");
    }

    #[test]
    fn resource_id_response_resolved_id_falls_to_policy_id() {
        let response = ResourceIdResponse {
            id: None,
            role_id: None,
            policy_id: Some("pol-3".to_string()),
        };
        assert_eq!(response.resolved_id(), "pol-3");
    }

    #[test]
    fn resource_id_response_resolved_id_returns_empty_when_none() {
        let response = ResourceIdResponse {
            id: None,
            role_id: None,
            policy_id: None,
        };
        assert_eq!(response.resolved_id(), "");
    }

    #[test]
    fn team_item_resolved_id_prefers_id() {
        let team = TeamItem {
            id: Some("id-1".to_string()),
            team_id: Some("team-2".to_string()),
            name: None,
            description: None,
        };
        assert_eq!(team.resolved_id(), Some("id-1"));
    }

    #[test]
    fn team_item_resolved_id_falls_to_team_id() {
        let team = TeamItem {
            id: None,
            team_id: Some("team-2".to_string()),
            name: None,
            description: None,
        };
        assert_eq!(team.resolved_id(), Some("team-2"));
    }

    #[test]
    fn team_item_resolved_id_returns_none() {
        let team = TeamItem {
            id: None,
            team_id: None,
            name: Some("test".to_string()),
            description: None,
        };
        assert_eq!(team.resolved_id(), None);
    }

    #[test]
    fn user_item_resolved_id_prefers_id() {
        let user = UserItem {
            id: Some("id-1".to_string()),
            user_id: Some("user-2".to_string()),
            email: None,
        };
        assert_eq!(user.resolved_id(), Some("id-1"));
    }

    #[test]
    fn user_item_resolved_id_falls_to_user_id() {
        let user = UserItem {
            id: None,
            user_id: Some("user-2".to_string()),
            email: None,
        };
        assert_eq!(user.resolved_id(), Some("user-2"));
    }

    #[test]
    fn user_item_resolved_id_returns_none() {
        let user = UserItem {
            id: None,
            user_id: None,
            email: Some("test@example.com".to_string()),
        };
        assert_eq!(user.resolved_id(), None);
    }

    #[test]
    fn agent_item_resolved_id_prefers_id() {
        let agent: AgentItem = serde_json::from_value(json!({
            "id": "id-1",
            "agent_id": "agent-2",
            "name": "test"
        }))
        .unwrap();
        assert_eq!(agent.resolved_id(), Some("id-1"));
    }

    #[test]
    fn agent_item_resolved_id_falls_to_agent_id() {
        let agent: AgentItem = serde_json::from_value(json!({
            "agent_id": "agent-2",
            "name": "test"
        }))
        .unwrap();
        assert_eq!(agent.resolved_id(), Some("agent-2"));
    }

    #[test]
    fn agent_item_resolved_id_returns_none() {
        let agent: AgentItem = serde_json::from_value(json!({"name": "test"})).unwrap();
        assert_eq!(agent.resolved_id(), None);
    }

    #[test]
    fn prompt_suite_item_resolved_id_prefers_id() {
        let suite: PromptSuiteItem = serde_json::from_value(json!({
            "id": "id-1",
            "suite_id": "suite-2",
            "name": "test"
        }))
        .unwrap();
        assert_eq!(suite.resolved_id(), Some("id-1"));
    }

    #[test]
    fn prompt_suite_item_resolved_id_falls_to_suite_id() {
        let suite: PromptSuiteItem = serde_json::from_value(json!({
            "suite_id": "suite-2",
            "name": "test"
        }))
        .unwrap();
        assert_eq!(suite.resolved_id(), Some("suite-2"));
    }

    #[test]
    fn prompt_suite_item_resolved_id_returns_none() {
        let suite: PromptSuiteItem = serde_json::from_value(json!({"name": "test"})).unwrap();
        assert_eq!(suite.resolved_id(), None);
    }

    #[test]
    fn resource_tags_to_specs_handles_all_none() {
        let specs = resource_tags_to_specs(&[ResourceTagItem {
            key: None,
            value: None,
            source: None,
        }]);
        assert!(specs.is_empty());
    }

    #[test]
    fn resource_tags_to_specs_skips_missing_value() {
        let specs = resource_tags_to_specs(&[ResourceTagItem {
            key: Some("env".to_string()),
            value: None,
            source: None,
        }]);
        assert!(specs.is_empty());
    }

    #[test]
    fn resource_tags_to_specs_preserves_source_none() {
        let specs = resource_tags_to_specs(&[ResourceTagItem {
            key: Some("env".to_string()),
            value: Some("prod".to_string()),
            source: None,
        }]);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].key, "env");
        assert_eq!(specs[0].value, "prod");
        assert!(specs[0].source.is_none());
    }

    #[test]
    fn budget_item_deserializes_with_defaults() {
        let item: BudgetItem = serde_json::from_value(json!({"name": "test"})).unwrap();
        assert_eq!(item.name.as_deref(), Some("test"));
        assert!(item.id.is_none());
        assert!(item.alert_thresholds.is_empty());
        assert!(item.billing_categories.is_empty());
    }

    #[test]
    fn platform_provider_bundle_item_deserializes() {
        let item: PlatformProviderBundleItem = serde_json::from_value(json!({
            "bundle_key": "test-bundle",
            "provider_registry": {"providers": []},
            "status": "active"
        }))
        .unwrap();
        assert_eq!(item.bundle_key.as_deref(), Some("test-bundle"));
        assert_eq!(item.status.as_deref(), Some("active"));
    }

    #[test]
    fn gateway_item_deserializes() {
        let item: GatewayItem = serde_json::from_value(json!({"id": "gw-1"})).unwrap();
        assert_eq!(item.id.as_deref(), Some("gw-1"));
    }

    #[test]
    fn agent_binding_response_deserializes() {
        let item: AgentBindingResponse = serde_json::from_value(json!({
            "binding_mode": "explicit",
            "agent_id": "ag-1"
        }))
        .unwrap();
        assert_eq!(item.binding_mode.as_deref(), Some("explicit"));
        assert_eq!(item.agent_id.as_deref(), Some("ag-1"));
    }

    #[test]
    fn hosted_gateway_policy_response_deserializes() {
        let item: HostedGatewayPolicyResponse = serde_json::from_value(json!({
            "default_agent": "ag-default",
            "default_agent_fallback_enabled": true,
            "fail_closed_on_missing_binding": false
        }))
        .unwrap();
        assert_eq!(item.default_agent_id.as_deref(), Some("ag-default"));
        assert_eq!(item.default_agent_fallback_enabled, Some(true));
        assert_eq!(item.fail_closed_on_missing_binding, Some(false));
    }

    #[test]
    fn secret_item_deserializes() {
        let item: SecretItem = serde_json::from_value(json!({
            "name": "api-key",
            "description": "Main API key",
            "env_var": "API_KEY"
        }))
        .unwrap();
        assert_eq!(item.name.as_deref(), Some("api-key"));
        assert_eq!(item.description.as_deref(), Some("Main API key"));
        assert_eq!(item.env_var.as_deref(), Some("API_KEY"));
    }

    #[test]
    fn policy_item_deserializes() {
        let item: PolicyItem = serde_json::from_value(json!({
            "name": "read-only",
            "description": "Read-only access",
            "statements": [{"effect": "allow"}]
        }))
        .unwrap();
        assert_eq!(item.name.as_deref(), Some("read-only"));
        assert!(item.statements.is_some());
    }

    #[test]
    fn role_item_deserializes_with_policies() {
        let item: RoleItem = serde_json::from_value(json!({
            "name": "viewer",
            "policies": [{"name": "read-only"}]
        }))
        .unwrap();
        assert_eq!(item.name.as_deref(), Some("viewer"));
        assert_eq!(item.policies.len(), 1);
        assert_eq!(item.policies[0].name.as_deref(), Some("read-only"));
    }

    #[test]
    fn approval_policy_item_deserializes() {
        let item: ApprovalPolicyItem = serde_json::from_value(json!({
            "name": "dual-approval",
            "enabled": true,
            "simulation_mode": false,
            "break_glass_enabled": true,
            "thresholds": [{"risk_level": "critical", "approval_mode": "dual", "required_approvals": 2}],
            "approver_chains": [{"name": "chain-1", "mode": "dual", "approvers": ["alice"]}]
        }))
        .unwrap();
        assert_eq!(item.name.as_deref(), Some("dual-approval"));
        assert_eq!(item.enabled, Some(true));
        assert_eq!(item.thresholds.len(), 1);
        assert_eq!(item.approver_chains.len(), 1);
    }

    #[test]
    fn regulated_execution_profile_item_deserializes() {
        let item: RegulatedExecutionProfileItem = serde_json::from_value(json!({
            "name": "sovereign",
            "deployment_profile": "sovereign_region",
            "default": false,
            "cross_border_policy": "deny_by_default",
            "fail_mode": "fail_closed"
        }))
        .unwrap();
        assert_eq!(item.name.as_deref(), Some("sovereign"));
        assert_eq!(item.deployment_profile.as_deref(), Some("sovereign_region"));
        assert_eq!(item.default, Some(false));
    }
}
