// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Typed control-plane manifest structs and YAML/JSON parsing for the
//! `verdictan control` resource structure.
//!
//! This is a **separate surface** from the gateway runtime policy document and
//! MUST NOT contain or import gateway runtime policy fields such as
//! `loads.runtime` or `history.capture`.
//!
//! Reconcile ordering (dependencies):
//!   secrets → iam.policies → iam.roles → teams → users → memberships
//!   → platform_provider_bundles → agents → agent.gateway_links
//!   → budgets

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;

use crate::error::CliError;

const SUPPORTED_VERSION: &str = "1";

// ── Top-level manifest ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlManifest {
    pub version: String,
    pub resources: Resources,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iam: Option<IamSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub teams: Vec<TeamSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<UserSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platform_provider_bundles: Vec<PlatformProviderBundleSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<AgentSpec>,
    /// Billing budgets and spend guardrails scoped to the org, a team,
    /// a user, or an agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub budgets: Vec<BudgetSpec>,
    /// Organisation-level regulated execution profiles.
    /// Reconciled via the regulated execution settings API.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regulated_execution_profiles: Vec<RegulatedExecutionProfileSpec>,
    /// Workflow approval policies governing destructive-action gating,
    /// dual-approval chains, break-glass access, and delegated approver chains.
    /// Reconciled via the approval policy API.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_policies: Vec<ApprovalPolicySpec>,
    /// Prompt and workflow evaluation suite definitions.
    /// Reconciled via the prompt evaluation API.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompt_evaluation_suites: Vec<PromptEvaluationSuiteSpec>,
    /// Organisation defaults for conversation and task collaboration
    /// visibility and sharing. Reconciled via the collaboration settings API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collaboration_defaults: Option<CollaborationDefaultsSpec>,
    /// Organisation-level hosted gateway default-agent binding policy.
    /// Reconciled via the hosted gateway API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosted_gateway_policy: Option<HostedGatewayPolicySpec>,
    /// Explicit per-hosted-gateway agent bindings.
    /// Each entry maps one hosted gateway to one agent and is reconciled via
    /// PUT /v1/gateways/:id/agent-binding.
    //: explicit bindings take precedence over the org default-agent
    /// policy and are idempotent (safe to re-apply).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosted_gateway_bindings: Vec<HostedGatewayBindingSpec>,
    /// Organisation browser-auth and SSO discovery policy for the shared
    /// auth platform. Reconciled via the auth-platform org policy API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_org_policy: Option<AuthOrgPolicySpec>,
}

impl Resources {
    /// Returns `true` when no resource was populated by the export.
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
            && self.iam.is_none()
            && self.teams.is_empty()
            && self.users.is_empty()
            && self.platform_provider_bundles.is_empty()
            && self.agents.is_empty()
            && self.budgets.is_empty()
            && self.regulated_execution_profiles.is_empty()
            && self.approval_policies.is_empty()
            && self.prompt_evaluation_suites.is_empty()
            && self.collaboration_defaults.is_none()
            && self.hosted_gateway_policy.is_none()
            && self.hosted_gateway_bindings.is_empty()
            && self.auth_org_policy.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretSpec {
    pub name: String,
    /// Environment variable that holds the secret value at apply time.
    //: raw `--value` is intentionally absent — use env or keychain.
    pub env: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ── IAM ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IamSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<IamPolicySpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<IamRoleSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamPolicySpec {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statements: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamRoleSpec {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
}

// ── Teams ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamSpec {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<TeamMemberSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMemberSpec {
    pub email: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}

// ── Users ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSpec {
    pub email: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub teams: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceTagSpec {
    pub key: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum MatchListOrWildcardSpec {
    Wildcard(String),
    Explicit(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContextFabricTtlSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_captured_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContextFabricConfidenceSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub votes_for_verified: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_flag_stale_after_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentContextFabricSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_exclude_patterns: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_max_entries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<ContextFabricTtlSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_similarity_threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compaction_similarity_threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pii_detection: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dlp_filter: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<ContextFabricConfidenceSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_inheritance: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_answer_threshold: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpSessionLimitsSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_prompt_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_test_inference_cost_usd: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_sessions: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolServerPolicySpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_unapproved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentMcpSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<MatchListOrWildcardSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_resources: Option<MatchListOrWildcardSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_limits: Option<McpSessionLimitsSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_servers: Option<McpToolServerPolicySpec>,
}

// ── Agents ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_tags: Vec<ResourceTagSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateways: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_fabric: Option<AgentContextFabricSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<AgentMcpSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<AgentDeploymentSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDeploymentSpec {
    pub configuration_id: String,
    pub configuration_version_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rollout_gateways: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollout_reason: Option<String>,
}

// ── Platform provider bundles ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformProviderBundleSpec {
    pub bundle_key: String,
    pub provider_registry: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

// ── Regulated execution profiles ──────────────────────────────────────────────

/// Organisation-level regulated execution profile.
///
/// Maps to a named deployment preset and its derived control-plane and runtime
/// defaults. Set `default: true` on at most one profile to designate the
/// org-wide default for new workloads that do not declare an explicit profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatedExecutionProfileSpec {
    pub name: String,
    /// Named preset: "regulated_saas", "private_cloud", "sovereign_region",
    /// "clinical_zero_retention", or
    /// "financial_shared_cache_disabled".
    pub deployment_profile: String,
    /// At most one profile per org should have `default: true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residency_region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_residency_tag: Option<String>,
    /// Must be "deny_by_default", "eu_only", "us_gov_only", or
    /// "allow_with_logging". SEC-014: routing is denied rather than silently
    /// downgraded when the request cannot be proven compliant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_border_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenization_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_in_memory_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_internet_egress: Option<bool>,
    /// Must be "regulated", "standard", or "experimental".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_class: Option<String>,
    /// When true, regulated executions emit DSSE-wrapped deletion receipts,
    /// signed execution manifests, and retention-policy attestations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_attestation_enabled: Option<bool>,
    /// Must be "fail_closed" or "fail_open". fail_closed is required for
    /// sovereign_region and clinical_zero_retention profiles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_mode: Option<String>,
}

// ── Approval policies ─────────────────────────────────────────────────────────

/// Workflow approval policy governing destructive-action gating.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalPolicySpec {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// When true, gates are evaluated and logged but not enforced. Used for
    /// pre-production policy validation only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulation_mode: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub break_glass_enabled: Option<bool>,
    /// When true, every break-glass approval creates a mandatory post-review
    /// workflow that must be completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub break_glass_post_review_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thresholds: Vec<ApprovalThresholdSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approver_chains: Vec<ApproverChainSpec>,
}

/// Per-risk-level approval threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalThresholdSpec {
    /// Must be "low", "medium", "high", or "critical".
    pub risk_level: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_pattern: Option<String>,
    /// Must be "single", "dual", or "delegated_chain". `dual` requires
    /// exactly two distinct human approvers; any deny is terminal.
    pub approval_mode: String,
    /// Must equal 1 for single, 2 for dual, and equal the number of ordered
    /// chain steps for delegated_chain.
    pub required_approvals: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_ttl_minutes: Option<u32>,
}

/// Named approver chain used in approval policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverChainSpec {
    pub name: String,
    /// Must be "single", "dual", or "delegated_chain".
    pub mode: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backup_approvers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalation_after_minutes: Option<u32>,
}

// ── Billing budgets ──────────────────────────────────────────────────────────

/// Declarative billing budget and spend guardrail.
///
/// Budgets may scope to the organisation (`org`, the default), a named team,
/// a user email, or an agent name. At most one scope target may be set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSpec {
    pub name: String,
    /// Decimal string amount, e.g. `"500.00"`.
    pub amount: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// Must be `hourly`, `daily`, `weekly`, or `monthly`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alert_thresholds: Vec<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_limit_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_limit_amount: Option<String>,
    /// Team name for a team-scoped budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    /// User email for a user-scoped budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Agent name for an agent-scoped budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub week_starts_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub month_anchor_day: Option<i16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub billing_categories: Vec<String>,
}

// ── Prompt evaluation suites ──────────────────────────────────────────────────

/// Prompt and workflow evaluation suite definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptEvaluationSuiteSpec {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_tags: Vec<ResourceTagSpec>,
}

// ── Collaboration defaults ────────────────────────────────────────────────────

/// Organisation defaults for conversation and task collaboration visibility.
///
/// SEC-018: Existing conversations and task threads remain owner-only until
/// explicitly shared, regardless of these defaults.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollaborationDefaultsSpec {
    /// Must be "owner_only" or "team".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_conversation_visibility: Option<String>,
    /// Must be "owner_only" or "team".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_task_visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_user_sharing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_team_sharing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_membership_changes: Option<bool>,
}

// ── Hosted gateway policy ─────────────────────────────────────────────────────

/// Organisation-level hosted gateway default-agent binding policy.
///
//: when `default_agent_fallback_enabled` is false, hosted gateways
/// without an explicit agent binding fail closed and cannot accept work.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostedGatewayPolicySpec {
    /// Name of the agent used as the org default when a hosted gateway has no
    /// explicit binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_agent: Option<String>,
    /// When false, unbound hosted gateways fail closed instead of falling
    /// back to the default agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_agent_fallback_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_closed_on_missing_binding: Option<bool>,
}

// ── Hosted-gateway explicit agent bindings ────────────────────────────────────

/// Explicit per-hosted-gateway agent binding.
///
//: When set, this gateway resolves to the named agent at
/// bootstrap and overrides the org default-agent fallback. The gateway must be
/// a hosted gateway and the named agent must be active.
///
/// Reconciled via PUT /v1/gateways/:gateway_id/agent-binding.
/// Each `gateway_id` may appear at most once in `hosted_gateway_bindings`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedGatewayBindingSpec {
    /// ID of the hosted gateway to bind. Must be a non-empty gateway
    /// identifier; org-scoped uniqueness is enforced at the API layer.
    pub gateway_id: String,
    /// Name of the agent to bind this gateway to. Resolved to an agent ID at
    /// apply time by looking up the agent by name in the org's agent list.
    pub agent: String,
}

// ── Auth org policy ───────────────────────────────────────────────────────────

/// Organisation browser-auth and SSO discovery policy.
///
/// SEC-011/SEC-019: raw credentials and session material must not be stored
/// here. SSO-002/SSO-005: verified domains drive deterministic SSO discovery
/// routing.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthOrgPolicySpec {
    /// Verified email domains owned by this organisation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_domains: Vec<String>,
    /// When true, all users must authenticate through an approved SSO
    /// provider; local auth is denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_sso: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_auth_allowed: Option<bool>,
    /// When true, verified SSO users can be provisioned on first login
    /// without an explicit invite. Fails closed when `invite_only` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jit_provisioning_enabled: Option<bool>,
    /// When true, new accounts require an explicit invite. Overrides
    /// `jit_provisioning_enabled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_only: Option<bool>,
    /// Allowed origins for popup auth return postMessage completion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub popup_return_origins: Vec<String>,
}

// ── Parsing ───────────────────────────────────────────────────────────────────

/// Parse and validate a manifest from a YAML or JSON file on disk.
pub fn load_from_path(path: &std::path::Path) -> Result<ControlManifest, CliError> {
    let bytes = std::fs::read(path)
        .map_err(|e| CliError::user(format!("cannot read manifest {}: {e}", path.display())))?;

    let manifest: ControlManifest = if path.extension().and_then(|e| e.to_str()) == Some("json") {
        serde_json::from_slice(&bytes)
            .map_err(|e| CliError::user(format!("invalid manifest JSON {}: {e}", path.display())))?
    } else {
        serde_yaml::from_slice(&bytes)
            .map_err(|e| CliError::user(format!("invalid manifest YAML {}: {e}", path.display())))?
    };

    validate(&manifest)?;
    Ok(manifest)
}

fn validate_resource_name(resource_type: &str, name: Option<&str>) -> Result<(), CliError> {
    if let Some(value) = name {
        if value.trim().is_empty() {
            return Err(CliError::user(format!(
                "{resource_type}: resource_name must not be empty"
            )));
        }
    }
    Ok(())
}

fn validate_resource_tags(
    resource_type: &str,
    resource_tags: &[ResourceTagSpec],
) -> Result<(), CliError> {
    for tag in resource_tags {
        if tag.key.trim().is_empty() {
            return Err(CliError::user(format!(
                "{resource_type}: resource tag key must not be empty"
            )));
        }
        if tag.value.trim().is_empty() {
            return Err(CliError::user(format!(
                "{resource_type}: resource tag value must not be empty for key {:?}",
                tag.key
            )));
        }
        if let Some(source) = &tag.source {
            if !matches!(source.as_str(), "user" | "system" | "inherited") {
                return Err(CliError::user(format!(
                    "{resource_type}: resource tag source must be 'user', 'system', or 'inherited', got {:?}",
                    source
                )));
            }
        }
    }
    Ok(())
}

fn validate_optional_unit_interval_f64(
    resource_type: &str,
    field: &str,
    value: Option<f64>,
) -> Result<(), CliError> {
    if let Some(value) = value {
        if !(0.0..=1.0).contains(&value) {
            return Err(CliError::user(format!(
                "{resource_type}: {field} must be between 0.0 and 1.0, got {value}"
            )));
        }
    }
    Ok(())
}

fn validate_optional_nonnegative_f64(
    resource_type: &str,
    field: &str,
    value: Option<f64>,
) -> Result<(), CliError> {
    if let Some(value) = value {
        if value < 0.0 {
            return Err(CliError::user(format!(
                "{resource_type}: {field} must be greater than or equal to 0.0, got {value}"
            )));
        }
    }
    Ok(())
}

fn validate_optional_positive_u32(
    resource_type: &str,
    field: &str,
    value: Option<u32>,
) -> Result<(), CliError> {
    if let Some(value) = value {
        if value == 0 {
            return Err(CliError::user(format!(
                "{resource_type}: {field} must be greater than 0"
            )));
        }
    }
    Ok(())
}

fn validate_optional_positive_u64(
    resource_type: &str,
    field: &str,
    value: Option<u64>,
) -> Result<(), CliError> {
    if let Some(value) = value {
        if value == 0 {
            return Err(CliError::user(format!(
                "{resource_type}: {field} must be greater than 0"
            )));
        }
    }
    Ok(())
}

fn validate_non_empty_strings(
    resource_type: &str,
    field: &str,
    values: &[String],
) -> Result<(), CliError> {
    for value in values {
        if value.trim().is_empty() {
            return Err(CliError::user(format!(
                "{resource_type}: {field} entries must not be empty"
            )));
        }
    }
    Ok(())
}

fn validate_match_list_or_wildcard(
    resource_type: &str,
    field: &str,
    value: &MatchListOrWildcardSpec,
) -> Result<(), CliError> {
    match value {
        MatchListOrWildcardSpec::Wildcard(wildcard) => {
            if wildcard.trim() != "*" {
                return Err(CliError::user(format!(
                    "{resource_type}: {field} must be '*' or a non-empty string array"
                )));
            }
        }
        MatchListOrWildcardSpec::Explicit(values) => {
            if values.is_empty() {
                return Err(CliError::user(format!(
                    "{resource_type}: {field} must not be an empty array"
                )));
            }
            validate_non_empty_strings(resource_type, field, values)?;
        }
    }

    Ok(())
}

fn validate_context_fabric_spec(
    agent_name: &str,
    spec: &AgentContextFabricSpec,
) -> Result<(), CliError> {
    let resource_type = format!("agent {:?}", agent_name);
    if let Some(capture_mode) = &spec.capture_mode {
        if !matches!(capture_mode.as_str(), "nudge" | "auto" | "off") {
            return Err(CliError::user(format!(
                "{resource_type}: context_fabric.capture_mode must be 'nudge', 'auto', or 'off', got {:?}",
                capture_mode
            )));
        }
    }
    if let Some(patterns) = &spec.capture_exclude_patterns {
        validate_non_empty_strings(
            &resource_type,
            "context_fabric.capture_exclude_patterns",
            patterns,
        )?;
    }
    validate_optional_positive_u32(
        &resource_type,
        "context_fabric.pool_max_entries",
        spec.pool_max_entries,
    )?;
    if let Some(ttl) = &spec.ttl {
        validate_optional_positive_u32(
            &resource_type,
            "context_fabric.ttl.auto_captured_days",
            ttl.auto_captured_days,
        )?;
        validate_optional_positive_u32(
            &resource_type,
            "context_fabric.ttl.manual_days",
            ttl.manual_days,
        )?;
        validate_optional_positive_u32(
            &resource_type,
            "context_fabric.ttl.verified_days",
            ttl.verified_days,
        )?;
    }
    validate_optional_unit_interval_f64(
        &resource_type,
        "context_fabric.dedup_similarity_threshold",
        spec.dedup_similarity_threshold,
    )?;
    validate_optional_unit_interval_f64(
        &resource_type,
        "context_fabric.compaction_similarity_threshold",
        spec.compaction_similarity_threshold,
    )?;
    validate_optional_unit_interval_f64(
        &resource_type,
        "context_fabric.direct_answer_threshold",
        spec.direct_answer_threshold,
    )?;
    if let Some(confidence) = &spec.confidence {
        validate_optional_positive_u32(
            &resource_type,
            "context_fabric.confidence.votes_for_verified",
            confidence.votes_for_verified,
        )?;
        validate_optional_positive_u32(
            &resource_type,
            "context_fabric.confidence.auto_flag_stale_after_days",
            confidence.auto_flag_stale_after_days,
        )?;
    }
    Ok(())
}

fn validate_agent_mcp_spec(agent_name: &str, spec: &AgentMcpSpec) -> Result<(), CliError> {
    let resource_type = format!("agent {:?}", agent_name);
    if let Some(allowed_tools) = &spec.allowed_tools {
        validate_match_list_or_wildcard(&resource_type, "mcp.allowed_tools", allowed_tools)?;
    }
    if let Some(allowed_resources) = &spec.allowed_resources {
        validate_match_list_or_wildcard(
            &resource_type,
            "mcp.allowed_resources",
            allowed_resources,
        )?;
    }
    if let Some(tool_servers) = &spec.tool_servers {
        if let Some(allowed_ids) = &tool_servers.allowed_ids {
            validate_non_empty_strings(
                &resource_type,
                "mcp.tool_servers.allowed_ids",
                allowed_ids,
            )?;
        }
    }
    if let Some(session_limits) = &spec.session_limits {
        validate_optional_positive_u64(
            &resource_type,
            "mcp.session_limits.max_prompt_bytes",
            session_limits.max_prompt_bytes,
        )?;
        validate_optional_nonnegative_f64(
            &resource_type,
            "mcp.session_limits.max_test_inference_cost_usd",
            session_limits.max_test_inference_cost_usd,
        )?;
        validate_optional_positive_u32(
            &resource_type,
            "mcp.session_limits.max_concurrent_sessions",
            session_limits.max_concurrent_sessions,
        )?;
    }
    Ok(())
}

fn parse_decimal_field(resource_type: &str, field: &str, value: &str) -> Result<Decimal, CliError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CliError::user(format!(
            "{resource_type}: {field} must not be empty"
        )));
    }

    Decimal::from_str_exact(trimmed)
        .or_else(|_| Decimal::from_str(trimmed))
        .map_err(|_| {
            CliError::user(format!(
                "{resource_type}: {field} must be a valid decimal string, got {:?}",
                value
            ))
        })
}

/// Validate the parsed manifest against the supported schema constraints.
pub fn validate(manifest: &ControlManifest) -> Result<(), CliError> {
    if manifest.version != SUPPORTED_VERSION {
        return Err(CliError::user(format!(
            "unsupported manifest version {:?} (expected {:?})",
            manifest.version, SUPPORTED_VERSION
        )));
    }

    for secret in &manifest.resources.secrets {
        if secret.name.is_empty() {
            return Err(CliError::user("secret name must not be empty"));
        }
        if secret.env.is_empty() {
            return Err(CliError::user(format!(
                "secret {:?}: env must not be empty",
                secret.name
            )));
        }
    }

    if let Some(iam) = &manifest.resources.iam {
        for policy in &iam.policies {
            if policy.name.is_empty() {
                return Err(CliError::user("iam.policies: name must not be empty"));
            }
        }
        let policy_names: std::collections::HashSet<&str> =
            iam.policies.iter().map(|p| p.name.as_str()).collect();
        for role in &iam.roles {
            if role.name.is_empty() {
                return Err(CliError::user("iam.roles: name must not be empty"));
            }
            for pol_ref in &role.policies {
                if !policy_names.contains(pol_ref.as_str()) {
                    return Err(CliError::user(format!(
                        "iam.roles.{:?}: references unknown policy {:?}",
                        role.name, pol_ref
                    )));
                }
            }
        }
    }

    for team in &manifest.resources.teams {
        if team.name.is_empty() {
            return Err(CliError::user("team name must not be empty"));
        }
        for member in &team.members {
            if member.email.is_empty() {
                return Err(CliError::user(format!(
                    "team {:?}: member email must not be empty",
                    team.name
                )));
            }
        }
    }

    for user in &manifest.resources.users {
        if user.email.is_empty() {
            return Err(CliError::user("user email must not be empty"));
        }
    }

    for bundle in &manifest.resources.platform_provider_bundles {
        if bundle.bundle_key.trim().is_empty() {
            return Err(CliError::user(
                "platform_provider_bundles: bundle_key must not be empty",
            ));
        }
        if !bundle.provider_registry.is_object() {
            return Err(CliError::user(format!(
                "platform_provider_bundles.{:?}: provider_registry must be a JSON object",
                bundle.bundle_key
            )));
        }
        if let Some(status) = &bundle.status {
            if !matches!(status.as_str(), "active" | "deprecated" | "archived") {
                return Err(CliError::user(format!(
                    "platform_provider_bundles.{:?}: status must be 'active', 'deprecated', or 'archived', got {:?}",
                    bundle.bundle_key, status
                )));
            }
        }
    }

    for agent in &manifest.resources.agents {
        if agent.name.is_empty() {
            return Err(CliError::user("agent name must not be empty"));
        }
        validate_resource_name("agent", agent.resource_name.as_deref())?;
        validate_resource_tags("agent", &agent.resource_tags)?;
        if let Some(scope_kind) = &agent.scope_kind {
            if !matches!(scope_kind.as_str(), "personal" | "agent_wide") {
                return Err(CliError::user(format!(
                    "agent {:?}: scope_kind must be 'personal' or 'agent_wide', got {:?}",
                    agent.name, scope_kind
                )));
            }
        }
        if let Some(context_fabric) = &agent.context_fabric {
            validate_context_fabric_spec(&agent.name, context_fabric)?;
        }
        if let Some(mcp) = &agent.mcp {
            validate_agent_mcp_spec(&agent.name, mcp)?;
        }
        if let Some(deployment) = &agent.deployment {
            if deployment.configuration_id.trim().is_empty() {
                return Err(CliError::user(format!(
                    "agent {:?}: deployment.configuration_id must not be empty",
                    agent.name
                )));
            }
            if deployment.configuration_version_id.trim().is_empty() {
                return Err(CliError::user(format!(
                    "agent {:?}: deployment.configuration_version_id must not be empty",
                    agent.name
                )));
            }
        }
    }

    // ── Regulated execution profiles ──────────────────────────────────────────

    const VALID_DEPLOYMENT_PROFILES: &[&str] = &[
        "regulated_saas",
        "private_cloud",
        "sovereign_region",
        "clinical_zero_retention",
        "financial_shared_cache_disabled",
    ];

    const FAIL_CLOSED_REQUIRED_PROFILES: &[&str] = &["sovereign_region", "clinical_zero_retention"];

    let mut default_profile_count = 0u32;
    for profile in &manifest.resources.regulated_execution_profiles {
        if profile.name.trim().is_empty() {
            return Err(CliError::user(
                "regulated_execution_profiles: name must not be empty",
            ));
        }
        if !VALID_DEPLOYMENT_PROFILES.contains(&profile.deployment_profile.as_str()) {
            return Err(CliError::user(format!(
                "regulated_execution_profiles.{:?}: deployment_profile must be one of {:?}, got {:?}",
                profile.name,
                VALID_DEPLOYMENT_PROFILES,
                profile.deployment_profile
            )));
        }
        if let Some(cp) = &profile.cross_border_policy {
            if !matches!(
                cp.as_str(),
                "deny_by_default" | "eu_only" | "us_gov_only" | "allow_with_logging"
            ) {
                return Err(CliError::user(format!(
                    "regulated_execution_profiles.{:?}: cross_border_policy must be 'deny_by_default', 'eu_only', 'us_gov_only', or 'allow_with_logging', got {:?}",
                    profile.name, cp
                )));
            }
        }
        if let Some(wc) = &profile.workload_class {
            if !matches!(wc.as_str(), "regulated" | "standard" | "experimental") {
                return Err(CliError::user(format!(
                    "regulated_execution_profiles.{:?}: workload_class must be 'regulated', 'standard', or 'experimental', got {:?}",
                    profile.name, wc
                )));
            }
        }
        if let Some(fm) = &profile.fail_mode {
            if !matches!(fm.as_str(), "fail_closed" | "fail_open") {
                return Err(CliError::user(format!(
                    "regulated_execution_profiles.{:?}: fail_mode must be 'fail_closed' or 'fail_open', got {:?}",
                    profile.name, fm
                )));
            }
        }
        // Sovereign and clinical profiles require fail_closed.
        if FAIL_CLOSED_REQUIRED_PROFILES.contains(&profile.deployment_profile.as_str()) {
            if let Some(fm) = &profile.fail_mode {
                if fm != "fail_closed" {
                    return Err(CliError::user(format!(
                        "regulated_execution_profiles.{:?}: deployment_profile '{}' requires fail_mode 'fail_closed'",
                        profile.name, profile.deployment_profile
                    )));
                }
            }
        }
        if profile.default == Some(true) {
            default_profile_count += 1;
        }
    }
    if default_profile_count > 1 {
        return Err(CliError::user(
            "regulated_execution_profiles: at most one profile may have default: true",
        ));
    }

    // ── Approval policies ─────────────────────────────────────────────────────

    for policy in &manifest.resources.approval_policies {
        if policy.name.trim().is_empty() {
            return Err(CliError::user("approval_policies: name must not be empty"));
        }
        for threshold in &policy.thresholds {
            if !matches!(
                threshold.risk_level.as_str(),
                "low" | "medium" | "high" | "critical"
            ) {
                return Err(CliError::user(format!(
                    "approval_policies.{:?}: threshold risk_level must be 'low', 'medium', 'high', or 'critical', got {:?}",
                    policy.name, threshold.risk_level
                )));
            }
            if !matches!(
                threshold.approval_mode.as_str(),
                "single" | "dual" | "delegated_chain"
            ) {
                return Err(CliError::user(format!(
                    "approval_policies.{:?}: threshold approval_mode must be 'single', 'dual', or 'delegated_chain', got {:?}",
                    policy.name, threshold.approval_mode
                )));
            }
            // Validate required_approvals vs approval_mode.
            let expected = match threshold.approval_mode.as_str() {
                "single" => Some(1u32),
                "dual" => Some(2u32),
                _ => None, // delegated_chain length is not statically known
            };
            if let Some(exp) = expected {
                if threshold.required_approvals != exp {
                    return Err(CliError::user(format!(
                        "approval_policies.{:?}: threshold approval_mode '{}' requires required_approvals={}, got {}",
                        policy.name,
                        threshold.approval_mode,
                        exp,
                        threshold.required_approvals
                    )));
                }
            }
            if threshold.required_approvals == 0 {
                return Err(CliError::user(format!(
                    "approval_policies.{:?}: threshold required_approvals must be at least 1",
                    policy.name
                )));
            }
        }
        for chain in &policy.approver_chains {
            if chain.name.trim().is_empty() {
                return Err(CliError::user(format!(
                    "approval_policies.{:?}: approver_chain name must not be empty",
                    policy.name
                )));
            }
            if !matches!(chain.mode.as_str(), "single" | "dual" | "delegated_chain") {
                return Err(CliError::user(format!(
                    "approval_policies.{:?}: approver_chain {:?} mode must be 'single', 'dual', or 'delegated_chain', got {:?}",
                    policy.name, chain.name, chain.mode
                )));
            }
        }
    }

    // ── Billing budgets ──────────────────────────────────────────────────────

    const VALID_BUDGET_PERIOD_TYPES: &[&str] = &["hourly", "daily", "weekly", "monthly"];
    const VALID_WEEK_STARTS: &[&str] = &[
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
    ];
    const VALID_BILLING_CATEGORIES: &[&str] = &[
        "gateway_llm",
        "agents",
        "workflows",
        "exports",
        "storage",
        "data_transfer",
        "policy_processing",
    ];

    {
        let mut seen_budget_names = std::collections::HashSet::new();
        for budget in &manifest.resources.budgets {
            if budget.name.trim().is_empty() {
                return Err(CliError::user("budgets: name must not be empty"));
            }
            if !seen_budget_names.insert(budget.name.as_str()) {
                return Err(CliError::user(format!(
                    "budgets: duplicate name {:?} — each budget name must be unique in the manifest",
                    budget.name
                )));
            }

            let resource_type = format!("budgets.{:?}", budget.name);
            let amount = parse_decimal_field(&resource_type, "amount", &budget.amount)?;
            if amount <= Decimal::ZERO {
                return Err(CliError::user(format!(
                    "{resource_type}: amount must be greater than zero"
                )));
            }

            if let Some(currency) = &budget.currency {
                if currency.trim().is_empty() {
                    return Err(CliError::user(format!(
                        "{resource_type}: currency must not be empty"
                    )));
                }
            }

            if let Some(period_type) = &budget.period_type {
                if !VALID_BUDGET_PERIOD_TYPES.contains(&period_type.as_str()) {
                    return Err(CliError::user(format!(
                        "{resource_type}: period_type must be one of {:?}, got {:?}",
                        VALID_BUDGET_PERIOD_TYPES, period_type
                    )));
                }
            }

            if !budget.alert_thresholds.is_empty()
                && budget
                    .alert_thresholds
                    .iter()
                    .any(|value| !(1..=100).contains(value))
            {
                return Err(CliError::user(format!(
                    "{resource_type}: alert_thresholds must contain integers between 1 and 100"
                )));
            }

            if budget.hard_limit_enabled.unwrap_or(false) && budget.hard_limit_amount.is_none() {
                return Err(CliError::user(format!(
                    "{resource_type}: hard_limit_amount is required when hard_limit_enabled is true"
                )));
            }

            if let Some(hard_limit_amount) = &budget.hard_limit_amount {
                let parsed_hard_limit =
                    parse_decimal_field(&resource_type, "hard_limit_amount", hard_limit_amount)?;
                if parsed_hard_limit < amount {
                    return Err(CliError::user(format!(
                        "{resource_type}: hard_limit_amount must be greater than or equal to amount"
                    )));
                }
            }

            let scope_count = usize::from(budget.team.is_some())
                + usize::from(budget.user.is_some())
                + usize::from(budget.agent.is_some());
            if scope_count > 1 {
                return Err(CliError::user(format!(
                    "{resource_type}: set at most one of team, user, or agent"
                )));
            }

            for (field, value) in [
                ("team", budget.team.as_deref()),
                ("user", budget.user.as_deref()),
                ("agent", budget.agent.as_deref()),
            ] {
                if let Some(scope_value) = value {
                    if scope_value.trim().is_empty() {
                        return Err(CliError::user(format!(
                            "{resource_type}: {field} must not be empty"
                        )));
                    }
                }
            }

            if let Some(timezone) = &budget.timezone {
                if timezone.trim().is_empty() {
                    return Err(CliError::user(format!(
                        "{resource_type}: timezone must not be empty"
                    )));
                }
            }

            if let Some(week_starts_on) = &budget.week_starts_on {
                if !VALID_WEEK_STARTS.contains(&week_starts_on.as_str()) {
                    return Err(CliError::user(format!(
                        "{resource_type}: week_starts_on must be one of {:?}, got {:?}",
                        VALID_WEEK_STARTS, week_starts_on
                    )));
                }
            }

            if let Some(month_anchor_day) = budget.month_anchor_day {
                if !(1..=31).contains(&month_anchor_day) {
                    return Err(CliError::user(format!(
                        "{resource_type}: month_anchor_day must be between 1 and 31"
                    )));
                }
            }

            if let Some(invalid_category) = budget
                .billing_categories
                .iter()
                .find(|value| !VALID_BILLING_CATEGORIES.contains(&value.as_str()))
            {
                return Err(CliError::user(format!(
                    "{resource_type}: unsupported billing category {:?}; valid values are {:?}",
                    invalid_category, VALID_BILLING_CATEGORIES
                )));
            }
        }
    }

    // ── Prompt evaluation suites ──────────────────────────────────────────────

    for suite in &manifest.resources.prompt_evaluation_suites {
        if suite.name.trim().is_empty() {
            return Err(CliError::user(
                "prompt_evaluation_suites: name must not be empty",
            ));
        }
        validate_resource_name(
            &format!("prompt_evaluation_suites.{:?}", suite.name),
            suite.resource_name.as_deref(),
        )?;
        validate_resource_tags(
            &format!("prompt_evaluation_suites.{:?}", suite.name),
            &suite.resource_tags,
        )?;
    }

    // ── Collaboration defaults ────────────────────────────────────────────────

    if let Some(collab) = &manifest.resources.collaboration_defaults {
        for (field, value) in [
            (
                "default_conversation_visibility",
                &collab.default_conversation_visibility,
            ),
            ("default_task_visibility", &collab.default_task_visibility),
        ] {
            if let Some(v) = value {
                if !matches!(v.as_str(), "owner_only" | "team") {
                    return Err(CliError::user(format!(
                        "collaboration_defaults.{field}: must be 'owner_only' or 'team', got {:?}",
                        v
                    )));
                }
            }
        }
    }

    // ── Hosted gateway bindings ───────────────────────────────────────────────

    {
        let mut seen_gateways = std::collections::HashSet::new();
        for binding in &manifest.resources.hosted_gateway_bindings {
            if binding.gateway_id.trim().is_empty() {
                return Err(CliError::user(
                    "hosted_gateway_bindings: gateway_id must not be empty",
                ));
            }
            if binding.agent.trim().is_empty() {
                return Err(CliError::user(format!(
                    "hosted_gateway_bindings.{:?}: agent must not be empty",
                    binding.gateway_id
                )));
            }
            if !seen_gateways.insert(binding.gateway_id.as_str()) {
                return Err(CliError::user(format!(
                    "hosted_gateway_bindings: duplicate gateway_id {:?} — each gateway may appear at most once",
                    binding.gateway_id
                )));
            }
        }
    }

    Ok(())
}

// ── Export scaffold ───────────────────────────────────────────────────────────

/// Build an empty manifest scaffold with the correct version.
#[allow(dead_code)]
pub(crate) fn empty_manifest() -> ControlManifest {
    ControlManifest {
        version: SUPPORTED_VERSION.to_string(),
        resources: Resources::default(),
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
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn minimal_manifest() -> ControlManifest {
        empty_manifest()
    }

    fn unique_temp_path(ext: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock drift")
            .as_nanos();
        path.push(format!(
            "verdictan-control-manifest-{}-{nanos}.{ext}",
            std::process::id()
        ));
        path
    }

    #[test]
    fn empty_manifest_uses_supported_version() {
        let manifest = empty_manifest();
        assert_eq!(manifest.version, "1");
        assert!(manifest.resources.is_empty());
    }

    #[test]
    fn resources_is_empty_tracks_populated_sections() {
        let mut resources = Resources::default();
        assert!(resources.is_empty());

        resources.auth_org_policy = Some(AuthOrgPolicySpec::default());
        assert!(!resources.is_empty());
    }

    #[test]
    fn parse_decimal_field_accepts_trimmed_decimal() {
        let parsed = parse_decimal_field("budgets.\"monthly\"", "amount", " 10.50 ").unwrap();
        assert_eq!(parsed, Decimal::from_str("10.50").unwrap());
    }

    #[test]
    fn parse_decimal_field_rejects_empty_value() {
        let error = parse_decimal_field("budgets.\"monthly\"", "amount", "   ").unwrap_err();
        assert!(error.to_string().contains("must not be empty"));
    }

    #[test]
    fn load_from_path_supports_json_and_yaml() {
        let json_path = unique_temp_path("json");
        let yaml_path = unique_temp_path("yaml");

        fs::write(&json_path, r#"{"version":"1","resources":{}}"#).unwrap();
        fs::write(&yaml_path, "version: \"1\"\nresources: {}\n").unwrap();

        let json_manifest = load_from_path(&json_path).unwrap();
        let yaml_manifest = load_from_path(&yaml_path).unwrap();

        assert_eq!(json_manifest.version, "1");
        assert!(json_manifest.resources.is_empty());
        assert_eq!(yaml_manifest.version, "1");
        assert!(yaml_manifest.resources.is_empty());

        let _ = fs::remove_file(json_path);
        let _ = fs::remove_file(yaml_path);
    }

    #[test]
    fn validate_rejects_invalid_agent_resource_tag_source() {
        let mut manifest = minimal_manifest();
        manifest.resources.agents.push(AgentSpec {
            name: "finance-bot".to_string(),
            resource_name: None,
            resource_tags: vec![ResourceTagSpec {
                key: "env".to_string(),
                value: "prod".to_string(),
                source: Some("bad-source".to_string()),
            }],
            team: None,
            scope_kind: None,
            gateways: vec![],
            context_fabric: None,
            mcp: None,
            deployment: None,
        });

        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("resource tag source"));
    }

    #[test]
    fn validate_rejects_budget_with_multiple_scope_selectors() {
        let mut manifest = minimal_manifest();
        manifest.resources.budgets.push(BudgetSpec {
            name: "team-and-user".to_string(),
            amount: "100.00".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: Some("finance".to_string()),
            user: Some("alice@example.com".to_string()),
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        });

        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("set at most one of team, user, or agent"));
    }

    #[test]
    fn validate_rejects_budget_hard_limit_without_amount() {
        let mut manifest = minimal_manifest();
        manifest.resources.budgets.push(BudgetSpec {
            name: "hard-limit".to_string(),
            amount: "100.00".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: Some(true),
            hard_limit_amount: None,
            team: None,
            user: None,
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        });

        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("hard_limit_amount is required"));
    }

    #[test]
    fn validate_rejects_dual_threshold_with_wrong_required_approvals() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .approval_policies
            .push(ApprovalPolicySpec {
                name: "dual-approval".to_string(),
                description: None,
                enabled: Some(true),
                simulation_mode: None,
                break_glass_enabled: None,
                break_glass_post_review_required: None,
                thresholds: vec![ApprovalThresholdSpec {
                    risk_level: "critical".to_string(),
                    data_class: None,
                    destination_pattern: None,
                    approval_mode: "dual".to_string(),
                    required_approvals: 1,
                    decision_ttl_minutes: None,
                }],
                approver_chains: vec![],
            });

        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("requires required_approvals=2"));
    }

    #[test]
    fn validate_rejects_duplicate_hosted_gateway_bindings() {
        let mut manifest = minimal_manifest();
        manifest.resources.hosted_gateway_bindings = vec![
            HostedGatewayBindingSpec {
                gateway_id: "gw-prod".to_string(),
                agent: "finance-bot".to_string(),
            },
            HostedGatewayBindingSpec {
                gateway_id: "gw-prod".to_string(),
                agent: "ops-bot".to_string(),
            },
        ];

        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("duplicate gateway_id"));
    }

    #[test]
    fn validate_accepts_prompt_suite_tags_and_collaboration_defaults() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .prompt_evaluation_suites
            .push(PromptEvaluationSuiteSpec {
                name: "nightly-suite".to_string(),
                resource_name: Some("nightly-suite-prod".to_string()),
                description: Some("Nightly quality checks".to_string()),
                enabled: Some(true),
                resource_tags: vec![ResourceTagSpec {
                    key: "env".to_string(),
                    value: "prod".to_string(),
                    source: Some("system".to_string()),
                }],
            });
        manifest.resources.collaboration_defaults = Some(CollaborationDefaultsSpec {
            default_conversation_visibility: Some("team".to_string()),
            default_task_visibility: Some("owner_only".to_string()),
            allow_user_sharing: Some(true),
            allow_team_sharing: Some(false),
            audit_membership_changes: Some(true),
        });

        assert!(validate(&manifest).is_ok());
    }

    // ── Version validation ────────────────────────────────────────────────

    #[test]
    fn validate_rejects_unsupported_version() {
        let mut manifest = minimal_manifest();
        manifest.version = "99".to_string();
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("unsupported manifest version"));
    }

    // ── Secret validation ─────────────────────────────────────────────────

    #[test]
    fn validate_rejects_empty_secret_name() {
        let mut manifest = minimal_manifest();
        manifest.resources.secrets.push(SecretSpec {
            name: "".to_string(),
            env: "MY_SECRET".to_string(),
            description: None,
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("secret name must not be empty"));
    }

    #[test]
    fn validate_rejects_empty_secret_env() {
        let mut manifest = minimal_manifest();
        manifest.resources.secrets.push(SecretSpec {
            name: "api-key".to_string(),
            env: "".to_string(),
            description: None,
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("env must not be empty"));
    }

    #[test]
    fn validate_accepts_valid_secret() {
        let mut manifest = minimal_manifest();
        manifest.resources.secrets.push(SecretSpec {
            name: "api-key".to_string(),
            env: "API_KEY".to_string(),
            description: Some("Main API key".to_string()),
        });
        assert!(validate(&manifest).is_ok());
    }

    // ── IAM validation ────────────────────────────────────────────────────

    #[test]
    fn validate_rejects_empty_policy_name() {
        let mut manifest = minimal_manifest();
        manifest.resources.iam = Some(IamSpec {
            policies: vec![IamPolicySpec {
                name: "".to_string(),
                description: None,
                statements: None,
            }],
            roles: vec![],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("iam.policies: name must not be empty"));
    }

    #[test]
    fn validate_rejects_empty_role_name() {
        let mut manifest = minimal_manifest();
        manifest.resources.iam = Some(IamSpec {
            policies: vec![],
            roles: vec![IamRoleSpec {
                name: "".to_string(),
                policies: vec![],
            }],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("iam.roles: name must not be empty"));
    }

    #[test]
    fn validate_rejects_role_referencing_unknown_policy() {
        let mut manifest = minimal_manifest();
        manifest.resources.iam = Some(IamSpec {
            policies: vec![IamPolicySpec {
                name: "read-only".to_string(),
                description: None,
                statements: None,
            }],
            roles: vec![IamRoleSpec {
                name: "viewer".to_string(),
                policies: vec!["nonexistent".to_string()],
            }],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("references unknown policy"));
    }

    #[test]
    fn validate_accepts_valid_iam() {
        let mut manifest = minimal_manifest();
        manifest.resources.iam = Some(IamSpec {
            policies: vec![IamPolicySpec {
                name: "read-only".to_string(),
                description: None,
                statements: None,
            }],
            roles: vec![IamRoleSpec {
                name: "viewer".to_string(),
                policies: vec!["read-only".to_string()],
            }],
        });
        assert!(validate(&manifest).is_ok());
    }

    // ── Team validation ───────────────────────────────────────────────────

    #[test]
    fn validate_rejects_empty_team_name() {
        let mut manifest = minimal_manifest();
        manifest.resources.teams.push(TeamSpec {
            name: "".to_string(),
            description: None,
            members: vec![],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("team name must not be empty"));
    }

    #[test]
    fn validate_rejects_empty_team_member_email() {
        let mut manifest = minimal_manifest();
        manifest.resources.teams.push(TeamSpec {
            name: "engineering".to_string(),
            description: None,
            members: vec![TeamMemberSpec {
                email: "".to_string(),
                roles: vec![],
            }],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("member email must not be empty"));
    }

    // ── User validation ───────────────────────────────────────────────────

    #[test]
    fn validate_rejects_empty_user_email() {
        let mut manifest = minimal_manifest();
        manifest.resources.users.push(UserSpec {
            email: "".to_string(),
            teams: vec![],
            roles: vec![],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("user email must not be empty"));
    }

    // ── Agent validation ──────────────────────────────────────────────────

    #[test]
    fn validate_rejects_empty_agent_name() {
        let mut manifest = minimal_manifest();
        manifest.resources.agents.push(AgentSpec {
            name: "".to_string(),
            resource_name: None,
            resource_tags: vec![],
            team: None,
            scope_kind: None,
            gateways: vec![],
            context_fabric: None,
            mcp: None,
            deployment: None,
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("agent name must not be empty"));
    }

    #[test]
    fn validate_rejects_invalid_agent_scope_kind() {
        let mut manifest = minimal_manifest();
        manifest.resources.agents.push(AgentSpec {
            name: "bot".to_string(),
            resource_name: None,
            resource_tags: vec![],
            team: None,
            scope_kind: Some("invalid".to_string()),
            gateways: vec![],
            context_fabric: None,
            mcp: None,
            deployment: None,
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("scope_kind must be"));
    }

    #[test]
    fn validate_accepts_personal_scope_kind() {
        let mut manifest = minimal_manifest();
        manifest.resources.agents.push(AgentSpec {
            name: "bot".to_string(),
            resource_name: None,
            resource_tags: vec![],
            team: None,
            scope_kind: Some("personal".to_string()),
            gateways: vec![],
            context_fabric: None,
            mcp: None,
            deployment: None,
        });
        assert!(validate(&manifest).is_ok());
    }

    #[test]
    fn load_from_path_round_trips_agent_context_fabric_and_mcp_sections() {
        let yaml_path = unique_temp_path("yaml");
        fs::write(
            &yaml_path,
            r#"version: "1"
resources:
  agents:
    - name: bot
      context_fabric:
        capture_mode: auto
        pool_max_entries: 500
        direct_answer_threshold: 0.85
      mcp:
        enabled: true
        allowed_tools:
          - context_search
        allowed_resources: "*"
        session_limits:
          max_prompt_bytes: 64000
        tool_servers:
          allowed_ids:
            - approved-db-tool
"#,
        )
        .unwrap();

        let manifest = load_from_path(&yaml_path).unwrap();
        let agent = &manifest.resources.agents[0];
        assert_eq!(
            agent
                .context_fabric
                .as_ref()
                .and_then(|spec| spec.capture_mode.as_deref()),
            Some("auto")
        );
        assert_eq!(
            agent
                .context_fabric
                .as_ref()
                .and_then(|spec| spec.pool_max_entries),
            Some(500)
        );
        assert_eq!(agent.mcp.as_ref().and_then(|spec| spec.enabled), Some(true));
        assert_eq!(
            agent
                .mcp
                .as_ref()
                .and_then(|spec| spec.allowed_resources.as_ref()),
            Some(&MatchListOrWildcardSpec::Wildcard("*".to_string()))
        );

        let rendered = serde_yaml::to_string(&manifest).unwrap();
        assert!(rendered.contains("context_fabric:"));
        assert!(rendered.contains("mcp:"));

        let _ = fs::remove_file(yaml_path);
    }

    #[test]
    fn validate_rejects_invalid_agent_context_fabric_capture_mode() {
        let mut manifest = minimal_manifest();
        manifest.resources.agents.push(AgentSpec {
            name: "bot".to_string(),
            resource_name: None,
            resource_tags: vec![],
            team: None,
            scope_kind: None,
            gateways: vec![],
            context_fabric: Some(AgentContextFabricSpec {
                capture_mode: Some("manual".to_string()),
                ..AgentContextFabricSpec::default()
            }),
            mcp: None,
            deployment: None,
        });

        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("context_fabric.capture_mode"));
    }

    #[test]
    fn validate_rejects_empty_agent_mcp_allowed_tools() {
        let mut manifest = minimal_manifest();
        manifest.resources.agents.push(AgentSpec {
            name: "bot".to_string(),
            resource_name: None,
            resource_tags: vec![],
            team: None,
            scope_kind: None,
            gateways: vec![],
            context_fabric: None,
            mcp: Some(AgentMcpSpec {
                allowed_tools: Some(MatchListOrWildcardSpec::Explicit(vec![])),
                ..AgentMcpSpec::default()
            }),
            deployment: None,
        });

        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("mcp.allowed_tools"));
    }

    #[test]
    fn validate_rejects_empty_deployment_configuration_id() {
        let mut manifest = minimal_manifest();
        manifest.resources.agents.push(AgentSpec {
            name: "bot".to_string(),
            resource_name: None,
            resource_tags: vec![],
            team: None,
            scope_kind: None,
            gateways: vec![],
            context_fabric: None,
            mcp: None,
            deployment: Some(AgentDeploymentSpec {
                configuration_id: "  ".to_string(),
                configuration_version_id: "v1".to_string(),
                rollout_gateways: vec![],
                rollout_reason: None,
            }),
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("configuration_id must not be empty"));
    }

    #[test]
    fn validate_rejects_empty_deployment_version_id() {
        let mut manifest = minimal_manifest();
        manifest.resources.agents.push(AgentSpec {
            name: "bot".to_string(),
            resource_name: None,
            resource_tags: vec![],
            team: None,
            scope_kind: None,
            gateways: vec![],
            context_fabric: None,
            mcp: None,
            deployment: Some(AgentDeploymentSpec {
                configuration_id: "cfg-1".to_string(),
                configuration_version_id: " ".to_string(),
                rollout_gateways: vec![],
                rollout_reason: None,
            }),
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("configuration_version_id must not be empty"));
    }

    #[test]
    fn validate_rejects_empty_resource_name() {
        let mut manifest = minimal_manifest();
        manifest.resources.agents.push(AgentSpec {
            name: "bot".to_string(),
            resource_name: Some("  ".to_string()),
            resource_tags: vec![],
            team: None,
            scope_kind: None,
            gateways: vec![],
            context_fabric: None,
            mcp: None,
            deployment: None,
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("resource_name must not be empty"));
    }

    #[test]
    fn validate_rejects_empty_resource_tag_key() {
        let mut manifest = minimal_manifest();
        manifest.resources.agents.push(AgentSpec {
            name: "bot".to_string(),
            resource_name: None,
            resource_tags: vec![ResourceTagSpec {
                key: " ".to_string(),
                value: "prod".to_string(),
                source: None,
            }],
            team: None,
            scope_kind: None,
            gateways: vec![],
            context_fabric: None,
            mcp: None,
            deployment: None,
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("resource tag key must not be empty"));
    }

    #[test]
    fn validate_rejects_empty_resource_tag_value() {
        let mut manifest = minimal_manifest();
        manifest.resources.agents.push(AgentSpec {
            name: "bot".to_string(),
            resource_name: None,
            resource_tags: vec![ResourceTagSpec {
                key: "env".to_string(),
                value: "  ".to_string(),
                source: None,
            }],
            team: None,
            scope_kind: None,
            gateways: vec![],
            context_fabric: None,
            mcp: None,
            deployment: None,
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("resource tag value must not be empty"));
    }

    // ── Platform provider bundle validation ───────────────────────────────

    #[test]
    fn validate_rejects_empty_bundle_key() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .platform_provider_bundles
            .push(PlatformProviderBundleSpec {
                bundle_key: "  ".to_string(),
                provider_registry: serde_json::json!({}),
                status: None,
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("bundle_key must not be empty"));
    }

    #[test]
    fn validate_rejects_non_object_provider_registry() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .platform_provider_bundles
            .push(PlatformProviderBundleSpec {
                bundle_key: "test-bundle".to_string(),
                provider_registry: serde_json::json!("not-an-object"),
                status: None,
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("provider_registry must be a JSON object"));
    }

    #[test]
    fn validate_rejects_invalid_bundle_status() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .platform_provider_bundles
            .push(PlatformProviderBundleSpec {
                bundle_key: "test-bundle".to_string(),
                provider_registry: serde_json::json!({}),
                status: Some("invalid".to_string()),
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("status must be"));
    }

    #[test]
    fn validate_accepts_valid_bundle() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .platform_provider_bundles
            .push(PlatformProviderBundleSpec {
                bundle_key: "test-bundle".to_string(),
                provider_registry: serde_json::json!({"providers": []}),
                status: Some("active".to_string()),
            });
        assert!(validate(&manifest).is_ok());
    }

    // ── Regulated execution profile validation ────────────────────────────

    #[test]
    fn validate_rejects_empty_profile_name() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .regulated_execution_profiles
            .push(RegulatedExecutionProfileSpec {
                name: "  ".to_string(),
                deployment_profile: "regulated_saas".to_string(),
                default: None,
                residency_region: None,
                data_residency_tag: None,
                cross_border_policy: None,
                tokenization_enabled: None,
                require_in_memory_only: None,
                allow_internet_egress: None,
                workload_class: None,
                deletion_attestation_enabled: None,
                fail_mode: None,
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("regulated_execution_profiles: name must not be empty"));
    }

    #[test]
    fn validate_rejects_invalid_deployment_profile() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .regulated_execution_profiles
            .push(RegulatedExecutionProfileSpec {
                name: "test".to_string(),
                deployment_profile: "unknown_profile".to_string(),
                default: None,
                residency_region: None,
                data_residency_tag: None,
                cross_border_policy: None,
                tokenization_enabled: None,
                require_in_memory_only: None,
                allow_internet_egress: None,
                workload_class: None,
                deletion_attestation_enabled: None,
                fail_mode: None,
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("deployment_profile must be one of"));
    }

    #[test]
    fn validate_rejects_invalid_cross_border_policy() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .regulated_execution_profiles
            .push(RegulatedExecutionProfileSpec {
                name: "test".to_string(),
                deployment_profile: "regulated_saas".to_string(),
                default: None,
                residency_region: None,
                data_residency_tag: None,
                cross_border_policy: Some("invalid".to_string()),
                tokenization_enabled: None,
                require_in_memory_only: None,
                allow_internet_egress: None,
                workload_class: None,
                deletion_attestation_enabled: None,
                fail_mode: None,
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("cross_border_policy must be"));
    }

    #[test]
    fn validate_rejects_invalid_workload_class() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .regulated_execution_profiles
            .push(RegulatedExecutionProfileSpec {
                name: "test".to_string(),
                deployment_profile: "regulated_saas".to_string(),
                default: None,
                residency_region: None,
                data_residency_tag: None,
                cross_border_policy: None,
                tokenization_enabled: None,
                require_in_memory_only: None,
                allow_internet_egress: None,
                workload_class: Some("invalid".to_string()),
                deletion_attestation_enabled: None,
                fail_mode: None,
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("workload_class must be"));
    }

    #[test]
    fn validate_rejects_invalid_fail_mode() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .regulated_execution_profiles
            .push(RegulatedExecutionProfileSpec {
                name: "test".to_string(),
                deployment_profile: "regulated_saas".to_string(),
                default: None,
                residency_region: None,
                data_residency_tag: None,
                cross_border_policy: None,
                tokenization_enabled: None,
                require_in_memory_only: None,
                allow_internet_egress: None,
                workload_class: None,
                deletion_attestation_enabled: None,
                fail_mode: Some("invalid".to_string()),
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("fail_mode must be"));
    }

    #[test]
    fn validate_rejects_sovereign_profile_without_fail_closed() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .regulated_execution_profiles
            .push(RegulatedExecutionProfileSpec {
                name: "sov".to_string(),
                deployment_profile: "sovereign_region".to_string(),
                default: None,
                residency_region: None,
                data_residency_tag: None,
                cross_border_policy: None,
                tokenization_enabled: None,
                require_in_memory_only: None,
                allow_internet_egress: None,
                workload_class: None,
                deletion_attestation_enabled: None,
                fail_mode: Some("fail_open".to_string()),
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("requires fail_mode 'fail_closed'"));
    }

    #[test]
    fn validate_rejects_multiple_default_profiles() {
        let mut manifest = minimal_manifest();
        for i in 0..2 {
            manifest
                .resources
                .regulated_execution_profiles
                .push(RegulatedExecutionProfileSpec {
                    name: format!("profile-{i}"),
                    deployment_profile: "regulated_saas".to_string(),
                    default: Some(true),
                    residency_region: None,
                    data_residency_tag: None,
                    cross_border_policy: None,
                    tokenization_enabled: None,
                    require_in_memory_only: None,
                    allow_internet_egress: None,
                    workload_class: None,
                    deletion_attestation_enabled: None,
                    fail_mode: None,
                });
        }
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("at most one profile may have default: true"));
    }

    // ── Approval policy validation ────────────────────────────────────────

    #[test]
    fn validate_rejects_empty_approval_policy_name() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .approval_policies
            .push(ApprovalPolicySpec {
                name: "  ".to_string(),
                description: None,
                enabled: None,
                simulation_mode: None,
                break_glass_enabled: None,
                break_glass_post_review_required: None,
                thresholds: vec![],
                approver_chains: vec![],
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("approval_policies: name must not be empty"));
    }

    #[test]
    fn validate_rejects_invalid_threshold_risk_level() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .approval_policies
            .push(ApprovalPolicySpec {
                name: "test".to_string(),
                description: None,
                enabled: None,
                simulation_mode: None,
                break_glass_enabled: None,
                break_glass_post_review_required: None,
                thresholds: vec![ApprovalThresholdSpec {
                    risk_level: "invalid".to_string(),
                    data_class: None,
                    destination_pattern: None,
                    approval_mode: "single".to_string(),
                    required_approvals: 1,
                    decision_ttl_minutes: None,
                }],
                approver_chains: vec![],
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("threshold risk_level must be"));
    }

    #[test]
    fn validate_rejects_invalid_threshold_approval_mode() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .approval_policies
            .push(ApprovalPolicySpec {
                name: "test".to_string(),
                description: None,
                enabled: None,
                simulation_mode: None,
                break_glass_enabled: None,
                break_glass_post_review_required: None,
                thresholds: vec![ApprovalThresholdSpec {
                    risk_level: "high".to_string(),
                    data_class: None,
                    destination_pattern: None,
                    approval_mode: "invalid".to_string(),
                    required_approvals: 1,
                    decision_ttl_minutes: None,
                }],
                approver_chains: vec![],
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("threshold approval_mode must be"));
    }

    #[test]
    fn validate_rejects_single_mode_with_wrong_required_approvals() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .approval_policies
            .push(ApprovalPolicySpec {
                name: "test".to_string(),
                description: None,
                enabled: None,
                simulation_mode: None,
                break_glass_enabled: None,
                break_glass_post_review_required: None,
                thresholds: vec![ApprovalThresholdSpec {
                    risk_level: "low".to_string(),
                    data_class: None,
                    destination_pattern: None,
                    approval_mode: "single".to_string(),
                    required_approvals: 3,
                    decision_ttl_minutes: None,
                }],
                approver_chains: vec![],
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("requires required_approvals=1"));
    }

    #[test]
    fn validate_rejects_zero_required_approvals_delegated_chain() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .approval_policies
            .push(ApprovalPolicySpec {
                name: "test".to_string(),
                description: None,
                enabled: None,
                simulation_mode: None,
                break_glass_enabled: None,
                break_glass_post_review_required: None,
                thresholds: vec![ApprovalThresholdSpec {
                    risk_level: "medium".to_string(),
                    data_class: None,
                    destination_pattern: None,
                    approval_mode: "delegated_chain".to_string(),
                    required_approvals: 0,
                    decision_ttl_minutes: None,
                }],
                approver_chains: vec![],
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("required_approvals must be at least 1"));
    }

    #[test]
    fn validate_rejects_empty_approver_chain_name() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .approval_policies
            .push(ApprovalPolicySpec {
                name: "test".to_string(),
                description: None,
                enabled: None,
                simulation_mode: None,
                break_glass_enabled: None,
                break_glass_post_review_required: None,
                thresholds: vec![],
                approver_chains: vec![ApproverChainSpec {
                    name: " ".to_string(),
                    mode: "single".to_string(),
                    approvers: vec![],
                    backup_approvers: vec![],
                    escalation_after_minutes: None,
                }],
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("approver_chain name must not be empty"));
    }

    #[test]
    fn validate_rejects_invalid_approver_chain_mode() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .approval_policies
            .push(ApprovalPolicySpec {
                name: "test".to_string(),
                description: None,
                enabled: None,
                simulation_mode: None,
                break_glass_enabled: None,
                break_glass_post_review_required: None,
                thresholds: vec![],
                approver_chains: vec![ApproverChainSpec {
                    name: "chain-1".to_string(),
                    mode: "invalid".to_string(),
                    approvers: vec![],
                    backup_approvers: vec![],
                    escalation_after_minutes: None,
                }],
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("approver_chain"));
        assert!(error.to_string().contains("mode must be"));
    }

    // ── Budget validation ─────────────────────────────────────────────────

    #[test]
    fn validate_rejects_empty_budget_name() {
        let mut manifest = minimal_manifest();
        manifest.resources.budgets.push(BudgetSpec {
            name: " ".to_string(),
            amount: "100.00".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: None,
            user: None,
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("budgets: name must not be empty"));
    }

    #[test]
    fn validate_rejects_duplicate_budget_names() {
        let mut manifest = minimal_manifest();
        for _ in 0..2 {
            manifest.resources.budgets.push(BudgetSpec {
                name: "dup-budget".to_string(),
                amount: "100.00".to_string(),
                currency: None,
                period_type: None,
                alert_thresholds: vec![],
                hard_limit_enabled: None,
                hard_limit_amount: None,
                team: None,
                user: None,
                agent: None,
                timezone: None,
                week_starts_on: None,
                month_anchor_day: None,
                billing_categories: vec![],
            });
        }
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("duplicate name"));
    }

    #[test]
    fn validate_rejects_zero_budget_amount() {
        let mut manifest = minimal_manifest();
        manifest.resources.budgets.push(BudgetSpec {
            name: "zero".to_string(),
            amount: "0".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: None,
            user: None,
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("amount must be greater than zero"));
    }

    #[test]
    fn validate_rejects_invalid_budget_amount() {
        let mut manifest = minimal_manifest();
        manifest.resources.budgets.push(BudgetSpec {
            name: "bad".to_string(),
            amount: "abc".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: None,
            user: None,
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("must be a valid decimal string"));
    }

    #[test]
    fn validate_rejects_invalid_period_type() {
        let mut manifest = minimal_manifest();
        manifest.resources.budgets.push(BudgetSpec {
            name: "test".to_string(),
            amount: "100.00".to_string(),
            currency: None,
            period_type: Some("biweekly".to_string()),
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: None,
            user: None,
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("period_type must be one of"));
    }

    #[test]
    fn validate_rejects_out_of_range_alert_thresholds() {
        let mut manifest = minimal_manifest();
        manifest.resources.budgets.push(BudgetSpec {
            name: "test".to_string(),
            amount: "100.00".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![0, 50, 101],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: None,
            user: None,
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("alert_thresholds must contain integers between 1 and 100"));
    }

    #[test]
    fn validate_rejects_hard_limit_below_amount() {
        let mut manifest = minimal_manifest();
        manifest.resources.budgets.push(BudgetSpec {
            name: "test".to_string(),
            amount: "100.00".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: Some(true),
            hard_limit_amount: Some("50.00".to_string()),
            team: None,
            user: None,
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("hard_limit_amount must be greater than or equal to amount"));
    }

    #[test]
    fn validate_rejects_empty_budget_scope_value() {
        let mut manifest = minimal_manifest();
        manifest.resources.budgets.push(BudgetSpec {
            name: "test".to_string(),
            amount: "100.00".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: Some("  ".to_string()),
            user: None,
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("team must not be empty"));
    }

    #[test]
    fn validate_rejects_empty_budget_currency() {
        let mut manifest = minimal_manifest();
        manifest.resources.budgets.push(BudgetSpec {
            name: "test".to_string(),
            amount: "100.00".to_string(),
            currency: Some(" ".to_string()),
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: None,
            user: None,
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("currency must not be empty"));
    }

    #[test]
    fn validate_rejects_empty_budget_timezone() {
        let mut manifest = minimal_manifest();
        manifest.resources.budgets.push(BudgetSpec {
            name: "test".to_string(),
            amount: "100.00".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: None,
            user: None,
            agent: None,
            timezone: Some(" ".to_string()),
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("timezone must not be empty"));
    }

    #[test]
    fn validate_rejects_invalid_week_starts_on() {
        let mut manifest = minimal_manifest();
        manifest.resources.budgets.push(BudgetSpec {
            name: "test".to_string(),
            amount: "100.00".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: None,
            user: None,
            agent: None,
            timezone: None,
            week_starts_on: Some("funday".to_string()),
            month_anchor_day: None,
            billing_categories: vec![],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("week_starts_on must be one of"));
    }

    #[test]
    fn validate_rejects_out_of_range_month_anchor_day() {
        let mut manifest = minimal_manifest();
        manifest.resources.budgets.push(BudgetSpec {
            name: "test".to_string(),
            amount: "100.00".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: None,
            user: None,
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: Some(32),
            billing_categories: vec![],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("month_anchor_day must be between 1 and 31"));
    }

    #[test]
    fn validate_rejects_invalid_usage_category() {
        let mut manifest = minimal_manifest();
        manifest.resources.budgets.push(BudgetSpec {
            name: "test".to_string(),
            amount: "100.00".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: None,
            user: None,
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec!["unknown_category".to_string()],
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("unsupported billing category"));
    }

    // ── Prompt evaluation suite validation ────────────────────────────────

    #[test]
    fn validate_rejects_empty_prompt_suite_name() {
        let mut manifest = minimal_manifest();
        manifest
            .resources
            .prompt_evaluation_suites
            .push(PromptEvaluationSuiteSpec {
                name: " ".to_string(),
                resource_name: None,
                description: None,
                enabled: None,
                resource_tags: vec![],
            });
        let error = validate(&manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("prompt_evaluation_suites: name must not be empty"));
    }

    // ── Collaboration defaults validation ─────────────────────────────────

    #[test]
    fn validate_rejects_invalid_conversation_visibility() {
        let mut manifest = minimal_manifest();
        manifest.resources.collaboration_defaults = Some(CollaborationDefaultsSpec {
            default_conversation_visibility: Some("public".to_string()),
            default_task_visibility: None,
            allow_user_sharing: None,
            allow_team_sharing: None,
            audit_membership_changes: None,
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("must be 'owner_only' or 'team'"));
    }

    #[test]
    fn validate_rejects_invalid_task_visibility() {
        let mut manifest = minimal_manifest();
        manifest.resources.collaboration_defaults = Some(CollaborationDefaultsSpec {
            default_conversation_visibility: None,
            default_task_visibility: Some("global".to_string()),
            allow_user_sharing: None,
            allow_team_sharing: None,
            audit_membership_changes: None,
        });
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("must be 'owner_only' or 'team'"));
    }

    // ── Hosted gateway binding validation ─────────────────────────────────

    #[test]
    fn validate_rejects_empty_gateway_binding_id() {
        let mut manifest = minimal_manifest();
        manifest.resources.hosted_gateway_bindings = vec![HostedGatewayBindingSpec {
            gateway_id: "  ".to_string(),
            agent: "bot".to_string(),
        }];
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("gateway_id must not be empty"));
    }

    #[test]
    fn validate_rejects_empty_gateway_binding_agent() {
        let mut manifest = minimal_manifest();
        manifest.resources.hosted_gateway_bindings = vec![HostedGatewayBindingSpec {
            gateway_id: "gw-1".to_string(),
            agent: " ".to_string(),
        }];
        let error = validate(&manifest).unwrap_err();
        assert!(error.to_string().contains("agent must not be empty"));
    }

    // ── Resources.is_empty exhaustive ─────────────────────────────────────

    #[test]
    fn resources_is_empty_false_with_secrets() {
        let mut resources = Resources::default();
        resources.secrets = vec![SecretSpec {
            name: "x".to_string(),
            env: "X".to_string(),
            description: None,
        }];
        assert!(!resources.is_empty());
    }

    #[test]
    fn resources_is_empty_false_with_iam() {
        let mut resources = Resources::default();
        resources.iam = Some(IamSpec::default());
        assert!(!resources.is_empty());
    }

    #[test]
    fn resources_is_empty_false_with_hosted_gateway_policy() {
        let mut resources = Resources::default();
        resources.hosted_gateway_policy = Some(HostedGatewayPolicySpec::default());
        assert!(!resources.is_empty());
    }

    #[test]
    fn resources_is_empty_false_with_collaboration_defaults() {
        let mut resources = Resources::default();
        resources.collaboration_defaults = Some(CollaborationDefaultsSpec::default());
        assert!(!resources.is_empty());
    }

    // ── load_from_path error paths ────────────────────────────────────────

    #[test]
    fn load_from_path_rejects_missing_file() {
        let error = load_from_path(std::path::Path::new("/nonexistent/manifest.yaml")).unwrap_err();
        assert!(error.to_string().contains("cannot read manifest"));
    }

    #[test]
    fn load_from_path_rejects_invalid_json() {
        let path = unique_temp_path("json");
        fs::write(&path, "{{not json}}").unwrap();
        let error = load_from_path(&path).unwrap_err();
        assert!(error.to_string().contains("invalid manifest JSON"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_from_path_rejects_invalid_yaml() {
        let path = unique_temp_path("yaml");
        fs::write(&path, ":\n  - :\n  bad: [").unwrap();
        let error = load_from_path(&path).unwrap_err();
        assert!(error.to_string().contains("invalid manifest YAML"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn parse_decimal_field_accepts_exact_decimal() {
        let parsed = parse_decimal_field("test", "field", "123.456").unwrap();
        assert_eq!(parsed, Decimal::from_str("123.456").unwrap());
    }

    #[test]
    fn parse_decimal_field_rejects_non_numeric() {
        let error = parse_decimal_field("test", "field", "abc").unwrap_err();
        assert!(error.to_string().contains("must be a valid decimal string"));
    }
}

#[cfg(test)]
mod coverage_expansion_manifest_tests {
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

    // ── ControlManifest parsing ─────────────────────────────────────────

    #[test]
    fn control_manifest_minimal() {
        let manifest: ControlManifest = serde_json::from_value(serde_json::json!({
            "version": "1",
            "resources": {}
        }))
        .unwrap();
        assert_eq!(manifest.version, "1");
        assert!(manifest.resources.is_empty());
    }

    #[test]
    fn control_manifest_with_secrets() {
        let manifest: ControlManifest = serde_json::from_value(serde_json::json!({
            "version": "1",
            "resources": {
                "secrets": [
                    {"name": "openai-key", "env": "OPENAI_API_KEY"}
                ]
            }
        }))
        .unwrap();
        assert_eq!(manifest.resources.secrets.len(), 1);
        assert_eq!(manifest.resources.secrets[0].name, "openai-key");
    }

    // ── Resources::is_empty ─────────────────────────────────────────────

    #[test]
    fn resources_is_empty_default() {
        let resources = Resources::default();
        assert!(resources.is_empty());
    }

    #[test]
    fn resources_is_empty_with_secrets() {
        let resources = Resources {
            secrets: vec![SecretSpec {
                name: "s1".to_string(),
                env: "VAR".to_string(),
                description: None,
            }],
            ..Default::default()
        };
        assert!(!resources.is_empty());
    }

    #[test]
    fn resources_is_empty_with_teams() {
        let resources = Resources {
            teams: vec![TeamSpec {
                name: "team-1".to_string(),
                description: None,
                members: vec![],
            }],
            ..Default::default()
        };
        assert!(!resources.is_empty());
    }

    // ── SecretSpec ──────────────────────────────────────────────────────

    #[test]
    fn secret_spec_serde() {
        let spec = SecretSpec {
            name: "my-secret".to_string(),
            env: "MY_SECRET_VAR".to_string(),
            description: None,
        };
        let j = serde_json::to_value(&spec).unwrap();
        assert_eq!(j["name"], "my-secret");
        assert_eq!(j["env"], "MY_SECRET_VAR");
    }

    // ── SUPPORTED_VERSION ───────────────────────────────────────────────

    #[test]
    fn supported_version_is_one() {
        assert_eq!(SUPPORTED_VERSION, "1");
    }
}
