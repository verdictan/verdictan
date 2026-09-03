// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Reconcile engine for the control-plane manifest.
//!
//! Implements **ordered** drift detection and idempotent reconciliation for:
//!   1. secrets
//!   2. iam.policies
//!   3. iam.roles (and role-policy attachments)
//!   4. teams (and team members)
//!   5. users
//!   6. platform provider bundles
//!   7. agents (and gateway links)
//!   8. billing budgets
//!   9. regulated_execution_profiles
//!  12. approval_policies
//!  13. prompt_evaluation_suites
//!  15. collaboration_defaults (singleton)
//!  16. hosted_gateway_policy (singleton)
//!  17. hosted_gateway_bindings (per-gateway explicit agent binding)
//!  18. auth_org_policy (singleton)
//!
//! **Prune** (deletion of remote resources absent from the manifest) is guarded
//! behind an explicit caller-supplied `prune` flag and MUST NOT happen
//! implicitly.
//!
//! This module is strictly a control-plane reconciler. It MUST NOT reference
//! gateway runtime policy files, `declarative_config.rs`, or any gateway
//! runtime types. Runtime defaults for `loads.runtime` and
//! `history.capture` remain in the gateway runtime policy document.
use crate::api::AsyncApiClient;
use crate::error::CliError;
use crate::managed::control_manifest::{
    AgentSpec, ApprovalPolicySpec, AuthOrgPolicySpec, BudgetSpec, CollaborationDefaultsSpec,
    ControlManifest, HostedGatewayBindingSpec, HostedGatewayPolicySpec, IamPolicySpec, IamRoleSpec,
    PlatformProviderBundleSpec, PromptEvaluationSuiteSpec, RegulatedExecutionProfileSpec,
    ResourceTagSpec, SecretSpec, TeamSpec, UserSpec,
};
use crate::managed::control_plane_types::{
    extract_typed_list, resource_tags_to_specs, AgentItem, BudgetItem, NamedResource,
    PlatformProviderBundleItem, PolicyItem, PromptSuiteItem, ResourceIdResponse, UserResource,
};
use rust_decimal::Decimal;
use serde_json::Value;
use std::{collections::HashMap, str::FromStr};

// ── Operation types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReconcileAction {
    Create,
    Update,
    Delete,
    #[serde(rename = "no-op")]
    NoOp,
}

impl std::fmt::Display for ReconcileAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconcileAction::Create => write!(f, "create"),
            ReconcileAction::Update => write!(f, "update"),
            ReconcileAction::Delete => write!(f, "delete"),
            ReconcileAction::NoOp => write!(f, "no-op"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReconcileOp {
    pub resource_type: String,
    pub name: String,
    pub action: ReconcileAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct ReconcilePlan {
    pub ops: Vec<ReconcileOp>,
}

impl ReconcilePlan {
    pub fn has_changes(&self) -> bool {
        self.ops.iter().any(|op| op.action != ReconcileAction::NoOp)
    }

    pub fn creates(&self) -> usize {
        self.ops
            .iter()
            .filter(|op| op.action == ReconcileAction::Create)
            .count()
    }

    pub fn updates(&self) -> usize {
        self.ops
            .iter()
            .filter(|op| op.action == ReconcileAction::Update)
            .count()
    }

    pub fn deletions(&self) -> usize {
        self.ops
            .iter()
            .filter(|op| op.action == ReconcileAction::Delete)
            .count()
    }

    pub fn no_ops(&self) -> usize {
        self.ops
            .iter()
            .filter(|op| op.action == ReconcileAction::NoOp)
            .count()
    }
}

// ── Reconcile results ─────────────────────────────────────────────────────────

#[derive(Debug, Default, serde::Serialize)]
pub struct ReconcileResult {
    pub successful: Vec<ReconcileOp>,
    pub failed: Vec<ReconcileOpError>,
}

#[derive(Debug, serde::Serialize)]
pub struct ReconcileOpError {
    pub op: ReconcileOp,
    pub error: String,
}

impl ReconcileResult {
    pub fn has_failures(&self) -> bool {
        !self.failed.is_empty()
    }
}

#[derive(Debug, Clone)]
struct RemotePlatformProviderBundle {
    bundle_key: String,
    provider_registry: Value,
    status: String,
}

#[derive(Debug, Clone)]
struct RemotePromptEvaluationSuite {
    id: String,
    name: String,
    description: Option<String>,
    enabled: Option<bool>,
}

#[derive(Debug, Clone)]
struct RemoteIamPolicy {
    id: String,
    name: String,
    description: Option<String>,
    statements: Option<Value>,
}

#[derive(Debug, Clone)]
struct RemoteBillingBudget {
    id: String,
    name: String,
    amount: String,
    currency: String,
    period_type: String,
    alert_thresholds: Vec<i32>,
    hard_limit_enabled: bool,
    hard_limit_amount: Option<String>,
    team_id: Option<String>,
    user_id: Option<String>,
    agent_id: Option<String>,
    timezone: String,
    week_starts_on: String,
    month_anchor_day: i16,
    billing_categories: Vec<String>,
}

#[derive(Debug, Default)]
struct ResolvedBudgetScopeIds {
    team_id: Option<String>,
    user_id: Option<String>,
    agent_id: Option<String>,
}

// ── Plan computation ──────────────────────────────────────────────────────────

/// Compute a diff plan between `manifest` desired state and current remote
/// state fetched from `client`.
///
/// Returns a [`ReconcilePlan`] that can be displayed dry-run by `control plan`
/// or executed by `control apply`. Operations appear in dependency order so
/// execution is safe when applied sequentially.
///
/// When `prune` is `false`, remote resources absent from the manifest are
/// never scheduled for deletion.
pub async fn compute_plan(
    client: &AsyncApiClient,
    manifest: &ControlManifest,
    prune: bool,
) -> Result<ReconcilePlan, CliError> {
    let mut plan = ReconcilePlan::default();

    // Ordering: secrets → iam policies → iam roles → teams → users
    //         → platform provider bundles → agents → billing budgets
    //         → regulated_execution_profiles → approval_policies
    //         → prompt_evaluation_suites → collaboration_defaults
    //         → hosted_gateway_policy → hosted_gateway_bindings
    //         → auth_org_policy
    plan_secrets(client, &manifest.resources.secrets, prune, &mut plan).await?;
    plan_iam(client, manifest, prune, &mut plan).await?;
    plan_teams(client, &manifest.resources.teams, prune, &mut plan).await?;
    plan_users(client, &manifest.resources.users, prune, &mut plan).await?;
    plan_platform_provider_bundles(
        client,
        &manifest.resources.platform_provider_bundles,
        prune,
        &mut plan,
    )
    .await?;
    plan_agents(client, &manifest.resources.agents, prune, &mut plan).await?;
    plan_budgets(client, &manifest.resources.budgets, prune, &mut plan).await?;
    plan_regulated_execution_profiles(
        client,
        &manifest.resources.regulated_execution_profiles,
        prune,
        &mut plan,
    )
    .await?;
    plan_approval_policies(
        client,
        &manifest.resources.approval_policies,
        prune,
        &mut plan,
    )
    .await?;
    plan_prompt_evaluation_suites(
        client,
        &manifest.resources.prompt_evaluation_suites,
        prune,
        &mut plan,
    )
    .await?;
    plan_collaboration_defaults(client, manifest, &mut plan).await?;
    plan_hosted_gateway_policy(client, manifest, &mut plan).await?;
    plan_hosted_gateway_bindings(
        client,
        &manifest.resources.hosted_gateway_bindings,
        &mut plan,
    )
    .await?;
    plan_auth_org_policy(client, manifest, &mut plan).await?;

    Ok(plan)
}

/// Compute a diff plan for IAM policies only.
///
/// This is the narrowest reusable plan surface for `verdictan policy diff/apply`.
pub async fn compute_iam_policy_plan(
    client: &AsyncApiClient,
    desired: &[IamPolicySpec],
    prune: bool,
) -> Result<ReconcilePlan, CliError> {
    let mut plan = ReconcilePlan::default();
    plan_iam_policies(client, desired, prune, &mut plan).await?;
    Ok(plan)
}

// ── Secrets ───────────────────────────────────────────────────────────────────

async fn plan_secrets(
    client: &AsyncApiClient,
    desired: &[SecretSpec],
    prune: bool,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    let remote = fetch_remote_list(client, "/v1/secrets", "secrets").await?;

    for spec in desired {
        let existing = find_by_name(&remote, &spec.name);
        // Secrets are always reconciled as an upsert because the env var value
        // may have rotated since the last apply.
        let action = if existing.is_some() {
            ReconcileAction::Update
        } else {
            ReconcileAction::Create
        };
        plan.ops.push(ReconcileOp {
            resource_type: "secret".to_string(),
            name: spec.name.clone(),
            action,
            remote_id: existing,
            detail: Some(format!("env={}", spec.env)),
        });
    }

    if prune {
        let desired_names: std::collections::HashSet<&str> =
            desired.iter().map(|s| s.name.as_str()).collect();
        for (name, id) in &remote {
            if !desired_names.contains(name.as_str()) {
                plan.ops.push(ReconcileOp {
                    resource_type: "secret".to_string(),
                    name: name.clone(),
                    action: ReconcileAction::Delete,
                    remote_id: Some(id.clone()),
                    detail: None,
                });
            }
        }
    }
    Ok(())
}

// ── IAM ───────────────────────────────────────────────────────────────────────

async fn plan_iam(
    client: &AsyncApiClient,
    manifest: &ControlManifest,
    prune: bool,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    let Some(iam) = &manifest.resources.iam else {
        return Ok(());
    };
    plan_iam_policies(client, &iam.policies, prune, plan).await?;
    plan_iam_roles(client, &iam.roles, prune, plan).await?;
    Ok(())
}

async fn plan_iam_policies(
    client: &AsyncApiClient,
    desired: &[IamPolicySpec],
    prune: bool,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    let remote = fetch_remote_policies(client).await?;

    for spec in desired {
        let existing = remote.iter().find(|policy| policy.name == spec.name);
        let (action, remote_id, detail) = match existing {
            Some(policy) if iam_policy_needs_update(spec, policy) => (
                ReconcileAction::Update,
                Some(policy.id.clone()),
                iam_policy_diff_detail(spec, policy),
            ),
            Some(policy) => (
                ReconcileAction::NoOp,
                Some(policy.id.clone()),
                spec.description.clone(),
            ),
            None => (ReconcileAction::Create, None, spec.description.clone()),
        };
        plan.ops.push(ReconcileOp {
            resource_type: "iam.policy".to_string(),
            name: spec.name.clone(),
            action,
            remote_id,
            detail,
        });
    }

    if prune {
        let desired_names: std::collections::HashSet<&str> =
            desired.iter().map(|p| p.name.as_str()).collect();
        for policy in &remote {
            if !desired_names.contains(policy.name.as_str()) {
                plan.ops.push(ReconcileOp {
                    resource_type: "iam.policy".to_string(),
                    name: policy.name.clone(),
                    action: ReconcileAction::Delete,
                    remote_id: Some(policy.id.clone()),
                    detail: None,
                });
            }
        }
    }
    Ok(())
}

async fn plan_iam_roles(
    client: &AsyncApiClient,
    desired: &[IamRoleSpec],
    prune: bool,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    let remote = fetch_remote_list(client, "/v1/roles", "roles").await?;

    for spec in desired {
        let existing = find_by_name(&remote, &spec.name);
        let action = if existing.is_some() {
            ReconcileAction::NoOp
        } else {
            ReconcileAction::Create
        };
        let detail = if spec.policies.is_empty() {
            None
        } else {
            Some(format!("policies=[{}]", spec.policies.join(",")))
        };
        plan.ops.push(ReconcileOp {
            resource_type: "iam.role".to_string(),
            name: spec.name.clone(),
            action,
            remote_id: existing,
            detail,
        });
    }

    if prune {
        let desired_names: std::collections::HashSet<&str> =
            desired.iter().map(|r| r.name.as_str()).collect();
        for (name, id) in &remote {
            if !desired_names.contains(name.as_str()) {
                plan.ops.push(ReconcileOp {
                    resource_type: "iam.role".to_string(),
                    name: name.clone(),
                    action: ReconcileAction::Delete,
                    remote_id: Some(id.clone()),
                    detail: None,
                });
            }
        }
    }
    Ok(())
}

// ── Teams ─────────────────────────────────────────────────────────────────────

async fn plan_teams(
    client: &AsyncApiClient,
    desired: &[TeamSpec],
    prune: bool,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    let remote = fetch_remote_list(client, "/v1/teams", "teams").await?;

    for spec in desired {
        let existing = find_by_name(&remote, &spec.name);
        let action = if existing.is_some() {
            ReconcileAction::NoOp
        } else {
            ReconcileAction::Create
        };
        plan.ops.push(ReconcileOp {
            resource_type: "team".to_string(),
            name: spec.name.clone(),
            action,
            remote_id: existing,
            detail: spec.description.clone(),
        });
        // Membership upsert (always idempotent — API ignores duplicates).
        for member in &spec.members {
            let detail = if member.roles.is_empty() {
                None
            } else {
                Some(format!("roles=[{}]", member.roles.join(",")))
            };
            plan.ops.push(ReconcileOp {
                resource_type: "team.member".to_string(),
                name: format!("{}/{}", spec.name, member.email),
                action: ReconcileAction::Create,
                remote_id: None,
                detail,
            });
        }
    }

    if prune {
        let desired_names: std::collections::HashSet<&str> =
            desired.iter().map(|t| t.name.as_str()).collect();
        for (name, id) in &remote {
            if !desired_names.contains(name.as_str()) {
                plan.ops.push(ReconcileOp {
                    resource_type: "team".to_string(),
                    name: name.clone(),
                    action: ReconcileAction::Delete,
                    remote_id: Some(id.clone()),
                    detail: None,
                });
            }
        }
    }
    Ok(())
}

// ── Users ─────────────────────────────────────────────────────────────────────

async fn plan_users(
    client: &AsyncApiClient,
    desired: &[UserSpec],
    prune: bool,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    let remote = fetch_remote_list_by_email(client, "/v1/users").await?;

    for spec in desired {
        let existing = find_by_key(&remote, &spec.email);
        let action = if existing.is_some() {
            ReconcileAction::NoOp
        } else {
            ReconcileAction::Create
        };
        plan.ops.push(ReconcileOp {
            resource_type: "user".to_string(),
            name: spec.email.clone(),
            action,
            remote_id: existing,
            detail: None,
        });
    }

    if prune {
        let desired_emails: std::collections::HashSet<&str> =
            desired.iter().map(|u| u.email.as_str()).collect();
        for (email, id) in &remote {
            if !desired_emails.contains(email.as_str()) {
                plan.ops.push(ReconcileOp {
                    resource_type: "user".to_string(),
                    name: email.clone(),
                    action: ReconcileAction::Delete,
                    remote_id: Some(id.clone()),
                    detail: None,
                });
            }
        }
    }
    Ok(())
}

// ── Platform provider bundles ──────────────────────────────────────────────────

async fn plan_platform_provider_bundles(
    client: &AsyncApiClient,
    desired: &[PlatformProviderBundleSpec],
    prune: bool,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    let remote = fetch_remote_platform_provider_bundles(client).await?;

    for spec in desired {
        let existing = remote
            .iter()
            .find(|bundle| bundle.bundle_key == spec.bundle_key);
        let action = match existing {
            Some(bundle) if platform_provider_bundle_needs_update(spec, bundle) => {
                ReconcileAction::Update
            }
            Some(_) => ReconcileAction::NoOp,
            None => ReconcileAction::Create,
        };
        plan.ops.push(ReconcileOp {
            resource_type: "platform_provider_bundle".to_string(),
            name: spec.bundle_key.clone(),
            action,
            remote_id: existing.map(|bundle| bundle.bundle_key.clone()),
            detail: Some(format!("status={}", platform_provider_bundle_status(spec))),
        });
    }

    if prune {
        let desired_keys: std::collections::HashSet<&str> = desired
            .iter()
            .map(|bundle| bundle.bundle_key.as_str())
            .collect();
        for bundle in &remote {
            if !desired_keys.contains(bundle.bundle_key.as_str()) && bundle.status != "archived" {
                plan.ops.push(ReconcileOp {
                    resource_type: "platform_provider_bundle".to_string(),
                    name: bundle.bundle_key.clone(),
                    action: ReconcileAction::Delete,
                    remote_id: Some(bundle.bundle_key.clone()),
                    detail: Some("archive".to_string()),
                });
            }
        }
    }

    Ok(())
}

// ── Regulated execution profiles ──────────────────────────────────────────────

async fn plan_regulated_execution_profiles(
    client: &AsyncApiClient,
    desired: &[RegulatedExecutionProfileSpec],
    prune: bool,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    let remote = fetch_remote_list(
        client,
        "/v1/settings/regulated-execution-profiles",
        "profiles",
    )
    .await?;

    for spec in desired {
        let existing = find_by_name(&remote, &spec.name);
        // Always upsert: profile fields may have changed.
        let action = if existing.is_some() {
            ReconcileAction::Update
        } else {
            ReconcileAction::Create
        };
        plan.ops.push(ReconcileOp {
            resource_type: "regulated_execution_profile".to_string(),
            name: spec.name.clone(),
            action,
            remote_id: existing,
            detail: Some(format!("profile={}", spec.deployment_profile)),
        });
    }

    if prune {
        let desired_names: std::collections::HashSet<&str> =
            desired.iter().map(|p| p.name.as_str()).collect();
        for (name, id) in &remote {
            if !desired_names.contains(name.as_str()) {
                plan.ops.push(ReconcileOp {
                    resource_type: "regulated_execution_profile".to_string(),
                    name: name.clone(),
                    action: ReconcileAction::Delete,
                    remote_id: Some(id.clone()),
                    detail: None,
                });
            }
        }
    }

    Ok(())
}

// ── Approval policies ─────────────────────────────────────────────────────────

async fn plan_approval_policies(
    client: &AsyncApiClient,
    desired: &[ApprovalPolicySpec],
    prune: bool,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    let remote = fetch_remote_list(client, "/v1/approval-policies", "policies").await?;

    for spec in desired {
        let existing = find_by_name(&remote, &spec.name);
        // Always upsert: thresholds and chains may have changed.
        let action = if existing.is_some() {
            ReconcileAction::Update
        } else {
            ReconcileAction::Create
        };
        plan.ops.push(ReconcileOp {
            resource_type: "approval_policy".to_string(),
            name: spec.name.clone(),
            action,
            remote_id: existing,
            detail: spec.description.clone(),
        });
    }

    if prune {
        let desired_names: std::collections::HashSet<&str> =
            desired.iter().map(|p| p.name.as_str()).collect();
        for (name, id) in &remote {
            if !desired_names.contains(name.as_str()) {
                plan.ops.push(ReconcileOp {
                    resource_type: "approval_policy".to_string(),
                    name: name.clone(),
                    action: ReconcileAction::Delete,
                    remote_id: Some(id.clone()),
                    detail: None,
                });
            }
        }
    }

    Ok(())
}

// ── Prompt evaluation suites ──────────────────────────────────────────────────

async fn plan_prompt_evaluation_suites(
    client: &AsyncApiClient,
    desired: &[PromptEvaluationSuiteSpec],
    prune: bool,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    let remote = fetch_remote_prompt_evaluation_suites(client).await?;

    for spec in desired {
        let existing = find_remote_prompt_evaluation_suite(&remote, spec);
        let action = match existing {
            Some(remote_suite) if prompt_evaluation_suite_needs_update(spec, remote_suite) => {
                ReconcileAction::Update
            }
            Some(_) => ReconcileAction::NoOp,
            None => ReconcileAction::Create,
        };
        plan.ops.push(ReconcileOp {
            resource_type: "prompt_evaluation_suite".to_string(),
            name: spec.name.clone(),
            action,
            remote_id: existing.map(|suite| suite.id.clone()),
            detail: spec
                .resource_name
                .clone()
                .or_else(|| spec.description.clone()),
        });
    }

    if prune {
        let desired_names: std::collections::HashSet<String> = desired
            .iter()
            .map(prompt_evaluation_suite_resource_name)
            .collect();
        for suite in &remote {
            if !desired_names.contains(suite.name.as_str()) {
                plan.ops.push(ReconcileOp {
                    resource_type: "prompt_evaluation_suite".to_string(),
                    name: suite.name.clone(),
                    action: ReconcileAction::Delete,
                    remote_id: Some(suite.id.clone()),
                    detail: None,
                });
            }
        }
    }

    Ok(())
}

// ── Collaboration defaults (singleton) ────────────────────────────────────────

async fn plan_collaboration_defaults(
    client: &AsyncApiClient,
    manifest: &ControlManifest,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    if manifest.resources.collaboration_defaults.is_none() {
        return Ok(());
    }
    // Determine whether a remote record already exists by probing GET.
    let action = match client.get_json_value("/v1/settings/collaboration").await {
        Ok(_) => ReconcileAction::Update,
        Err(_) => ReconcileAction::Create,
    };
    plan.ops.push(ReconcileOp {
        resource_type: "collaboration_defaults".to_string(),
        name: "org".to_string(),
        action,
        remote_id: None,
        detail: None,
    });
    Ok(())
}

// ── Hosted gateway policy (singleton) ────────────────────────────────────────

async fn plan_hosted_gateway_policy(
    client: &AsyncApiClient,
    manifest: &ControlManifest,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    if manifest.resources.hosted_gateway_policy.is_none() {
        return Ok(());
    }
    let action = match client
        .get_json_value("/v1/settings/hosted-gateway-policy")
        .await
    {
        Ok(_) => ReconcileAction::Update,
        Err(_) => ReconcileAction::Create,
    };
    plan.ops.push(ReconcileOp {
        resource_type: "hosted_gateway_policy".to_string(),
        name: "org".to_string(),
        action,
        remote_id: None,
        detail: manifest
            .resources
            .hosted_gateway_policy
            .as_ref()
            .and_then(|p| p.default_agent.clone()),
    });
    Ok(())
}

// ── Auth org policy (singleton) ───────────────────────────────────────────────

async fn plan_auth_org_policy(
    client: &AsyncApiClient,
    manifest: &ControlManifest,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    if manifest.resources.auth_org_policy.is_none() {
        return Ok(());
    }
    let action = match client.get_json_value("/v1/settings/auth-org-policy").await {
        Ok(_) => ReconcileAction::Update,
        Err(_) => ReconcileAction::Create,
    };
    plan.ops.push(ReconcileOp {
        resource_type: "auth_org_policy".to_string(),
        name: "org".to_string(),
        action,
        remote_id: None,
        detail: None,
    });
    Ok(())
}

// ── Hosted-gateway explicit agent bindings ────────────────────────────────────

/// Plan ops for per-gateway explicit agent bindings.
///
//: Each declared binding is always emitted as an Update
/// (PUT upsert) because there is no stable remote state to diff against without
/// fetching every gateway individually. This is safe: the API endpoint is
/// idempotent. Prune is intentionally NOT supported for hosted-gateway
/// bindings — removing an explicit binding reverts the gateway to the org
/// default-agent fallback, which is a privileged destructive action that must
/// be performed explicitly via the API or by removing the binding entry from
/// the manifest.
async fn plan_hosted_gateway_bindings(
    client: &AsyncApiClient,
    desired: &[HostedGatewayBindingSpec],
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    // Verify that each named agent exists so the plan surface is actionable.
    // A missing agent is surfaced as an Update op with a detail annotation;
    // the error is deferred to execute time so plan remains non-blocking.
    let remote_agents = fetch_remote_list(client, "/v1/agents", "agents").await?;

    for spec in desired {
        let agent_exists = find_by_name(&remote_agents, &spec.agent).is_some();
        let detail = if agent_exists {
            Some(format!("agent={}", spec.agent))
        } else {
            Some(format!(
                "agent={} (not yet resolved — will retry at apply)",
                spec.agent
            ))
        };
        plan.ops.push(ReconcileOp {
            resource_type: "hosted_gateway_binding".to_string(),
            name: spec.gateway_id.clone(),
            // Always upsert: the API PUT is idempotent.
            action: ReconcileAction::Update,
            remote_id: None,
            detail,
        });
    }

    Ok(())
}

// ── Agents ────────────────────────────────────────────────────────────────────

/// Compute reconcile ops for a single [`AgentSpec`] given its current remote
/// state. Extracted as a pure (sync) function for unit-testability — the
/// async `plan_agents` fetches remote state and calls this per spec.
pub fn agent_ops_for_spec(spec: &AgentSpec, existing: Option<String>) -> Vec<ReconcileOp> {
    let mut ops = Vec::new();

    let agent_action = if existing.is_some() {
        if spec
            .resource_name
            .as_deref()
            .is_some_and(|resource_name| resource_name != spec.name)
        {
            let new_name = agent_resource_name(spec);
            tracing::warn!(
                manifest_name = %spec.name,
                old_name = %spec.name,
                new_name = %new_name,
                "Agent resource_name changed from '{}' to '{}'. \
                 This will create a new agent rather than renaming the existing one. \
                 Update the manifest 'name' field to match the remote name \
                 if you intended a rename.",
                spec.name,
                new_name,
            );
            ReconcileAction::Update
        } else {
            ReconcileAction::NoOp
        }
    } else {
        ReconcileAction::Create
    };
    ops.push(ReconcileOp {
        resource_type: "agent".to_string(),
        name: spec.name.clone(),
        action: agent_action,
        remote_id: existing.clone(),
        detail: spec.team.clone(),
    });

    if spec.deployment.is_some() {
        ops.push(ReconcileOp {
            resource_type: "agent.deployment".to_string(),
            name: spec.name.clone(),
            action: if existing.is_some() {
                ReconcileAction::Update
            } else {
                ReconcileAction::Create
            },
            remote_id: existing.clone(),
            detail: spec
                .deployment
                .as_ref()
                .map(|d| d.configuration_version_id.clone()),
        });
    }

    // Gateway link upsert (idempotent — link endpoint ignores duplicates).
    for gw in &spec.gateways {
        ops.push(ReconcileOp {
            resource_type: "agent.gateway_link".to_string(),
            name: format!("{}/{}", spec.name, gw),
            action: ReconcileAction::Create,
            remote_id: None,
            detail: None,
        });
    }

    ops
}

fn find_remote_agent<'a>(remote: &'a [AgentItem], spec: &AgentSpec) -> Option<&'a AgentItem> {
    let desired_resource_name = agent_resource_name(spec);
    remote.iter().find(|item| {
        item.name.as_deref() == Some(spec.name.as_str())
            || item.name.as_deref() == Some(desired_resource_name.as_str())
            || item.resource_name.as_deref() == Some(desired_resource_name.as_str())
    })
}

fn remote_agent_resource_name(item: &AgentItem) -> Option<&str> {
    item.resource_name.as_deref().or(item.name.as_deref())
}

fn agent_control_config_diff_lines(spec: &AgentSpec, remote: &AgentItem) -> Vec<String> {
    let mut lines = Vec::new();
    push_agent_control_config_diff_lines(
        "context_fabric",
        &remote.context_fabric,
        &spec.context_fabric,
        &mut lines,
    );
    push_agent_control_config_diff_lines("mcp", &remote.mcp, &spec.mcp, &mut lines);
    lines
}

fn push_agent_control_config_diff_lines<T: serde::Serialize>(
    section: &str,
    remote: &Option<T>,
    desired: &Option<T>,
    lines: &mut Vec<String>,
) {
    let remote_value = serde_json::to_value(remote).unwrap_or(serde_json::Value::Null);
    let desired_value = serde_json::to_value(desired).unwrap_or(serde_json::Value::Null);
    push_agent_control_value_diff_lines(&remote_value, &desired_value, section.to_string(), lines);
}

fn push_agent_control_value_diff_lines(
    remote: &serde_json::Value,
    desired: &serde_json::Value,
    path: String,
    lines: &mut Vec<String>,
) {
    match (remote, desired) {
        (serde_json::Value::Object(remote_obj), serde_json::Value::Object(desired_obj)) => {
            for (key, remote_value) in remote_obj {
                let nested_path = format!("{path}.{key}");
                match desired_obj.get(key) {
                    Some(desired_value) => push_agent_control_value_diff_lines(
                        remote_value,
                        desired_value,
                        nested_path,
                        lines,
                    ),
                    None => {
                        push_agent_control_removed_value_lines(remote_value, nested_path, lines);
                    }
                }
            }

            for (key, desired_value) in desired_obj {
                if !remote_obj.contains_key(key) {
                    push_agent_control_added_value_lines(
                        desired_value,
                        format!("{path}.{key}"),
                        lines,
                    );
                }
            }
        }
        (serde_json::Value::Null, serde_json::Value::Object(desired_obj)) => {
            for (key, desired_value) in desired_obj {
                push_agent_control_added_value_lines(desired_value, format!("{path}.{key}"), lines);
            }
        }
        (serde_json::Value::Object(remote_obj), serde_json::Value::Null) => {
            for (key, remote_value) in remote_obj {
                push_agent_control_removed_value_lines(
                    remote_value,
                    format!("{path}.{key}"),
                    lines,
                );
            }
        }
        (remote_value, desired_value) if remote_value != desired_value => {
            lines.push(format!(
                "~ {path}: {} -> {}",
                format_control_diff_value(remote_value),
                format_control_diff_value(desired_value),
            ));
        }
        _ => {}
    }
}

fn push_agent_control_added_value_lines(
    value: &serde_json::Value,
    path: String,
    lines: &mut Vec<String>,
) {
    match value {
        serde_json::Value::Object(entries) => {
            for (key, nested_value) in entries {
                push_agent_control_added_value_lines(nested_value, format!("{path}.{key}"), lines);
            }
        }
        other => lines.push(format!("+ {path}: {}", format_control_diff_value(other))),
    }
}

fn push_agent_control_removed_value_lines(
    value: &serde_json::Value,
    path: String,
    lines: &mut Vec<String>,
) {
    match value {
        serde_json::Value::Object(entries) => {
            for (key, nested_value) in entries {
                push_agent_control_removed_value_lines(
                    nested_value,
                    format!("{path}.{key}"),
                    lines,
                );
            }
        }
        other => lines.push(format!("- {path}: {}", format_control_diff_value(other))),
    }
}

fn format_control_diff_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "<absent>".to_string(),
        serde_json::Value::String(inner) => format!("\"{inner}\""),
        other => other.to_string(),
    }
}

fn agent_needs_update(spec: &AgentSpec, remote: &AgentItem) -> bool {
    remote_agent_resource_name(remote) != Some(agent_resource_name(spec).as_str())
        || resource_tags_to_specs(&remote.resource_tags) != spec.resource_tags
        || remote.context_fabric != spec.context_fabric
        || remote.mcp != spec.mcp
}

async fn fetch_remote_agents(client: &AsyncApiClient) -> Result<Vec<AgentItem>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/agents").await? {
        Some(v) => v,
        None => return Ok(vec![]),
    };

    Ok(extract_typed_list(&value, "agents"))
}

async fn plan_agents(
    client: &AsyncApiClient,
    desired: &[AgentSpec],
    prune: bool,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    let remote = fetch_remote_agents(client).await?;

    for spec in desired {
        let existing = find_remote_agent(&remote, spec);
        let control_diff_lines = existing
            .map(|item| agent_control_config_diff_lines(spec, item))
            .unwrap_or_default();
        let needs_update = existing.is_some_and(|item| agent_needs_update(spec, item));
        let mut ops = agent_ops_for_spec(
            spec,
            existing.and_then(|item| item.resolved_id().map(str::to_string)),
        );
        if needs_update {
            if let Some(agent_op) = ops.first_mut() {
                agent_op.action = ReconcileAction::Update;
                if !control_diff_lines.is_empty() {
                    agent_op.detail = Some(control_diff_lines.join("\n"));
                }
            }
        }
        plan.ops.extend(ops);
    }

    if prune {
        let desired_names: std::collections::HashSet<String> = desired
            .iter()
            .flat_map(|spec| [spec.name.clone(), agent_resource_name(spec)])
            .collect();
        for item in &remote {
            let Some(id) = item.resolved_id() else {
                continue;
            };
            let matches_desired = item
                .name
                .as_deref()
                .is_some_and(|name| desired_names.contains(name))
                || item
                    .resource_name
                    .as_deref()
                    .is_some_and(|name| desired_names.contains(name));
            if !matches_desired {
                plan.ops.push(ReconcileOp {
                    resource_type: "agent".to_string(),
                    name: item
                        .name
                        .clone()
                        .or_else(|| item.resource_name.clone())
                        .unwrap_or_else(|| id.to_string()),
                    action: ReconcileAction::Delete,
                    remote_id: Some(id.to_string()),
                    detail: None,
                });
            }
        }
    }
    Ok(())
}

// ── Billing budgets ──────────────────────────────────────────────────────────

fn budget_scope_identity(spec: &BudgetSpec) -> String {
    if let Some(team) = &spec.team {
        format!("team/{team}")
    } else if let Some(user) = &spec.user {
        format!("user/{user}")
    } else if let Some(agent) = &spec.agent {
        format!("agent/{agent}")
    } else {
        "org".to_string()
    }
}

fn budget_effective_currency(spec: &BudgetSpec) -> String {
    spec.currency.clone().unwrap_or_else(|| "USD".to_string())
}

fn budget_effective_period_type(spec: &BudgetSpec) -> String {
    spec.period_type
        .clone()
        .unwrap_or_else(|| "monthly".to_string())
}

fn budget_effective_alert_thresholds(spec: &BudgetSpec) -> Vec<i32> {
    if spec.alert_thresholds.is_empty() {
        vec![50, 75, 90]
    } else {
        spec.alert_thresholds.clone()
    }
}

fn budget_effective_hard_limit_enabled(spec: &BudgetSpec) -> bool {
    spec.hard_limit_enabled.unwrap_or(false)
}

fn budget_effective_timezone(spec: &BudgetSpec) -> String {
    spec.timezone.clone().unwrap_or_else(|| "UTC".to_string())
}

fn budget_effective_week_starts_on(spec: &BudgetSpec) -> String {
    spec.week_starts_on
        .clone()
        .unwrap_or_else(|| "monday".to_string())
}

fn budget_effective_month_anchor_day(spec: &BudgetSpec) -> i16 {
    spec.month_anchor_day.unwrap_or(1)
}

fn budget_effective_billing_categories(spec: &BudgetSpec) -> Vec<String> {
    if spec.billing_categories.is_empty() {
        vec!["gateway_llm".to_string()]
    } else {
        spec.billing_categories.clone()
    }
}

fn parse_decimal(value: &str) -> Option<Decimal> {
    Decimal::from_str_exact(value)
        .ok()
        .or_else(|| Decimal::from_str(value).ok())
}

fn same_decimal_value(left: &str, right: &str) -> bool {
    match (parse_decimal(left), parse_decimal(right)) {
        (Some(lhs), Some(rhs)) => lhs == rhs,
        _ => left.trim() == right.trim(),
    }
}

fn invert_pairs(pairs: Vec<(String, String)>) -> HashMap<String, String> {
    pairs.into_iter().collect()
}

fn budget_needs_update(
    spec: &BudgetSpec,
    remote: &RemoteBillingBudget,
    team_name_to_id: &HashMap<String, String>,
    user_email_to_id: &HashMap<String, String>,
    agent_name_to_id: &HashMap<String, String>,
) -> bool {
    let desired_currency = budget_effective_currency(spec);
    let desired_period_type = budget_effective_period_type(spec);
    let desired_alert_thresholds = budget_effective_alert_thresholds(spec);
    let desired_hard_limit_enabled = budget_effective_hard_limit_enabled(spec);
    let desired_timezone = budget_effective_timezone(spec);
    let desired_week_starts_on = budget_effective_week_starts_on(spec);
    let desired_month_anchor_day = budget_effective_month_anchor_day(spec);
    let desired_billing_categories = budget_effective_billing_categories(spec);

    if !same_decimal_value(&spec.amount, &remote.amount) {
        return true;
    }
    if desired_currency != remote.currency.as_str() {
        return true;
    }
    if desired_period_type != remote.period_type.as_str() {
        return true;
    }
    if desired_alert_thresholds.as_slice() != remote.alert_thresholds.as_slice() {
        return true;
    }
    if desired_hard_limit_enabled != remote.hard_limit_enabled {
        return true;
    }
    if spec
        .hard_limit_amount
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            !remote
                .hard_limit_amount
                .as_deref()
                .is_some_and(|remote_value| same_decimal_value(value, remote_value))
        })
        .unwrap_or_else(|| remote.hard_limit_amount.is_some())
    {
        return true;
    }

    let desired_team_id = spec
        .team
        .as_ref()
        .and_then(|name| team_name_to_id.get(name));
    if spec.team.is_some() && desired_team_id.is_none() {
        return true;
    }
    if desired_team_id.map(|value| value.as_str()) != remote.team_id.as_deref() {
        return true;
    }

    let desired_user_id = spec
        .user
        .as_ref()
        .and_then(|email| user_email_to_id.get(email));
    if spec.user.is_some() && desired_user_id.is_none() {
        return true;
    }
    if desired_user_id.map(|value| value.as_str()) != remote.user_id.as_deref() {
        return true;
    }

    let desired_agent_id = spec
        .agent
        .as_ref()
        .and_then(|name| agent_name_to_id.get(name));
    if spec.agent.is_some() && desired_agent_id.is_none() {
        return true;
    }
    if desired_agent_id.map(|value| value.as_str()) != remote.agent_id.as_deref() {
        return true;
    }

    if desired_timezone != remote.timezone.as_str() {
        return true;
    }
    if desired_week_starts_on != remote.week_starts_on.as_str() {
        return true;
    }
    if desired_month_anchor_day != remote.month_anchor_day {
        return true;
    }
    if desired_billing_categories.as_slice() != remote.billing_categories.as_slice() {
        return true;
    }

    false
}

async fn plan_budgets(
    client: &AsyncApiClient,
    desired: &[BudgetSpec],
    prune: bool,
    plan: &mut ReconcilePlan,
) -> Result<(), CliError> {
    let remote = fetch_remote_budgets(client).await?;
    let team_name_to_id = invert_pairs(fetch_remote_list(client, "/v1/teams", "teams").await?);
    let user_email_to_id = invert_pairs(fetch_remote_list_by_email(client, "/v1/users").await?);
    let agent_name_to_id = invert_pairs(fetch_remote_list(client, "/v1/agents", "agents").await?);

    for spec in desired {
        let existing = remote.iter().find(|budget| budget.name == spec.name);
        let action = match existing {
            Some(remote_budget)
                if budget_needs_update(
                    spec,
                    remote_budget,
                    &team_name_to_id,
                    &user_email_to_id,
                    &agent_name_to_id,
                ) =>
            {
                ReconcileAction::Update
            }
            Some(_) => ReconcileAction::NoOp,
            None => ReconcileAction::Create,
        };
        plan.ops.push(ReconcileOp {
            resource_type: "billing_budget".to_string(),
            name: spec.name.clone(),
            action,
            remote_id: existing.map(|budget| budget.id.clone()),
            detail: Some(format!(
                "period={} scope={}",
                budget_effective_period_type(spec),
                budget_scope_identity(spec)
            )),
        });
    }

    if prune {
        let desired_names: std::collections::HashSet<&str> =
            desired.iter().map(|budget| budget.name.as_str()).collect();
        for budget in &remote {
            if !desired_names.contains(budget.name.as_str()) {
                plan.ops.push(ReconcileOp {
                    resource_type: "billing_budget".to_string(),
                    name: budget.name.clone(),
                    action: ReconcileAction::Delete,
                    remote_id: Some(budget.id.clone()),
                    detail: Some(format!(
                        "period={} scope={}",
                        budget.period_type.as_str(),
                        if budget.user_id.is_some() {
                            "user"
                        } else if budget.team_id.is_some() {
                            "team"
                        } else if budget.agent_id.is_some() {
                            "agent"
                        } else {
                            "org"
                        }
                    )),
                });
            }
        }
    }

    Ok(())
}

// ── Execution ─────────────────────────────────────────────────────────────────

/// Execute a reconcile plan against the API.
///
/// Create and update operations are applied in the order they appear in the
/// plan, which preserves the dependency ordering established by
/// [`compute_plan`]. Delete operations run afterwards in reverse plan order so
/// dependent resources are pruned before their parents. Execution halts at the
/// first failure to avoid partial-state drift further down the dependency
/// chain.
pub async fn execute_plan(
    client: &AsyncApiClient,
    plan: &ReconcilePlan,
    manifest: &ControlManifest,
) -> Result<ReconcileResult, CliError> {
    let mut result = ReconcileResult::default();
    let mut ordered_ops: Vec<&ReconcileOp> = plan
        .ops
        .iter()
        .filter(|op| op.action != ReconcileAction::Delete)
        .collect();
    let mut delete_ops: Vec<&ReconcileOp> = plan
        .ops
        .iter()
        .filter(|op| op.action == ReconcileAction::Delete)
        .collect();
    delete_ops.reverse();
    ordered_ops.extend(delete_ops);

    for op in ordered_ops {
        if op.action == ReconcileAction::NoOp {
            result.successful.push(op.clone());
            continue;
        }

        match execute_op(client, op, manifest).await {
            Ok(()) => result.successful.push(op.clone()),
            Err(err) => {
                result.failed.push(ReconcileOpError {
                    op: op.clone(),
                    error: err.to_string(),
                });
                // Abort on first failure to prevent partial state.
                return Ok(result);
            }
        }
    }

    Ok(result)
}

async fn execute_op(
    client: &AsyncApiClient,
    op: &ReconcileOp,
    manifest: &ControlManifest,
) -> Result<(), CliError> {
    match (op.resource_type.as_str(), &op.action) {
        // ── Secrets ──
        ("secret", ReconcileAction::Create) => {
            let spec = find_secret_spec(manifest, &op.name)?;
            apply_secret_create(client, spec).await
        }
        ("secret", ReconcileAction::Update) => {
            let spec = find_secret_spec(manifest, &op.name)?;
            let id = op
                .remote_id
                .as_deref()
                .ok_or_else(|| CliError::internal("secret update missing remote_id"))?;
            apply_secret_update(client, id, spec).await
        }
        ("secret", ReconcileAction::Delete) => {
            let id = require_remote_id(op)?;
            client
                .delete_json_value(&format!("/v1/secrets/{id}"))
                .await?;
            Ok(())
        }

        // ── IAM policies ──
        ("iam.policy", ReconcileAction::Create) => {
            let iam = manifest
                .resources
                .iam
                .as_ref()
                .ok_or_else(|| CliError::internal("iam section missing"))?;
            let spec = iam
                .policies
                .iter()
                .find(|p| p.name == op.name)
                .ok_or_else(|| CliError::internal("iam.policy spec missing from manifest"))?;
            let body = build_iam_policy_body(spec)?;
            client.post_json_value("/v1/policies", &body).await?;
            Ok(())
        }
        ("iam.policy", ReconcileAction::Update) => {
            let iam = manifest
                .resources
                .iam
                .as_ref()
                .ok_or_else(|| CliError::internal("iam section missing"))?;
            let spec = iam
                .policies
                .iter()
                .find(|p| p.name == op.name)
                .ok_or_else(|| CliError::internal("iam.policy spec missing from manifest"))?;
            let id = require_remote_id(op)?;
            let body = build_iam_policy_body(spec)?;
            client
                .put_json_value(&format!("/v1/policies/{id}"), &body)
                .await?;
            Ok(())
        }
        ("iam.policy", ReconcileAction::Delete) => {
            let id = require_remote_id(op)?;
            client
                .delete_json_value(&format!("/v1/policies/{id}"))
                .await?;
            Ok(())
        }

        // ── IAM roles ──
        ("iam.role", ReconcileAction::Create) => {
            let iam = manifest
                .resources
                .iam
                .as_ref()
                .ok_or_else(|| CliError::internal("iam section missing"))?;
            let spec = iam
                .roles
                .iter()
                .find(|r| r.name == op.name)
                .ok_or_else(|| CliError::internal("iam.role spec missing from manifest"))?;
            let result = client
                .post_json_value("/v1/roles", &serde_json::json!({ "name": spec.name }))
                .await?;
            let role_id = extract_id(&result);
            // Attach policies after creation.
            if !spec.policies.is_empty() {
                let remote_policies = fetch_remote_list(client, "/v1/policies", "policies").await?;
                for pol_name in &spec.policies {
                    if let Some(pol_id) = find_by_name(&remote_policies, pol_name) {
                        let path = format!("/v1/roles/{role_id}/policies/{pol_id}");
                        let _ = client.post_json_value(&path, &serde_json::json!({})).await;
                    }
                }
            }
            Ok(())
        }
        ("iam.role", ReconcileAction::Delete) => {
            let id = require_remote_id(op)?;
            client.delete_json_value(&format!("/v1/roles/{id}")).await?;
            Ok(())
        }

        // ── Teams ──
        ("team", ReconcileAction::Create) => {
            let spec = manifest
                .resources
                .teams
                .iter()
                .find(|t| t.name == op.name)
                .ok_or_else(|| CliError::internal("team spec missing from manifest"))?;
            let mut body = serde_json::json!({ "name": spec.name });
            if let Some(desc) = &spec.description {
                body["description"] = serde_json::Value::String(desc.clone());
            }
            client.post_json_value("/v1/teams", &body).await?;
            Ok(())
        }
        ("team", ReconcileAction::Delete) => {
            let id = require_remote_id(op)?;
            client.delete_json_value(&format!("/v1/teams/{id}")).await?;
            Ok(())
        }

        // ── Team members ──
        // name is "teamname/email"
        ("team.member", ReconcileAction::Create) => {
            let (team_name, email) = split2(&op.name, '/')
                .ok_or_else(|| CliError::internal("team.member name format invalid"))?;
            let teams = fetch_remote_list(client, "/v1/teams", "teams").await?;
            let team_id = find_by_name(&teams, team_name).ok_or_else(|| {
                CliError::user(format!("team {team_name:?} not found (was it created?)",))
            })?;
            client
                .post_json_value(
                    &format!("/v1/teams/{team_id}/members"),
                    &serde_json::json!({ "email": email }),
                )
                .await?;
            Ok(())
        }

        // ── Users ──
        ("user", ReconcileAction::Create) => {
            client
                .post_json_value("/v1/users/invite", &serde_json::json!({ "email": op.name }))
                .await?;
            Ok(())
        }
        ("user", ReconcileAction::Delete) => {
            let id = require_remote_id(op)?;
            client.delete_json_value(&format!("/v1/users/{id}")).await?;
            Ok(())
        }

        // ── Platform provider bundles ──
        ("platform_provider_bundle", ReconcileAction::Create) => {
            let spec = find_platform_provider_bundle_spec(manifest, &op.name)?;
            let mut body = serde_json::json!({
                "bundle_key": spec.bundle_key,
                "provider_registry": spec.provider_registry,
            });
            if let Some(status) = &spec.status {
                body["status"] = serde_json::Value::String(status.clone());
            }
            client
                .post_json_value("/v1/admin/platform-provider-bundles", &body)
                .await?;
            Ok(())
        }
        ("platform_provider_bundle", ReconcileAction::Update) => {
            let spec = find_platform_provider_bundle_spec(manifest, &op.name)?;
            client
                .put_json_value(
                    &format!("/v1/admin/platform-provider-bundles/{}", spec.bundle_key),
                    &serde_json::json!({
                        "provider_registry": spec.provider_registry,
                        "status": platform_provider_bundle_status(spec),
                    }),
                )
                .await?;
            Ok(())
        }
        ("platform_provider_bundle", ReconcileAction::Delete) => {
            let bundle_key = require_remote_id(op)?;
            client
                .put_json_value(
                    &format!("/v1/admin/platform-provider-bundles/{bundle_key}"),
                    &serde_json::json!({ "status": "archived" }),
                )
                .await?;
            Ok(())
        }

        // ── Agents ──
        ("agent", ReconcileAction::Create) => {
            let spec = manifest
                .resources
                .agents
                .iter()
                .find(|agent| agent.name == op.name)
                .ok_or_else(|| CliError::internal("agent spec missing from manifest"))?;
            client
                .post_json_value("/v1/agents", &build_agent_body(spec))
                .await?;
            Ok(())
        }
        ("agent", ReconcileAction::Update) => {
            let spec = manifest
                .resources
                .agents
                .iter()
                .find(|agent| agent.name == op.name)
                .ok_or_else(|| CliError::internal("agent spec missing from manifest"))?;
            let id = require_remote_id(op)?;
            client
                .put_json_value(&format!("/v1/agents/{id}"), &build_agent_body(spec))
                .await?;
            Ok(())
        }
        ("agent", ReconcileAction::Delete) => {
            let id = require_remote_id(op)?;
            client
                .delete_json_value(&format!("/v1/agents/{id}"))
                .await?;
            Ok(())
        }

        ("agent.deployment", ReconcileAction::Create | ReconcileAction::Update) => {
            let spec = manifest
                .resources
                .agents
                .iter()
                .find(|agent| agent.name == op.name)
                .ok_or_else(|| CliError::internal("agent spec missing from manifest"))?;
            let deployment = spec
                .deployment
                .as_ref()
                .ok_or_else(|| CliError::internal("agent deployment spec missing from manifest"))?;
            let agents = fetch_remote_list(client, "/v1/agents", "agents").await?;
            let agent_id = find_by_name(&agents, &spec.name).ok_or_else(|| {
                CliError::user(format!("agent {:?} not found (was it created?)", spec.name))
            })?;
            client
                .put_json_value(
                    &format!("/v1/agents/{agent_id}/deployment"),
                    &serde_json::json!({
                        "configuration_id": deployment.configuration_id,
                        "configuration_version_id": deployment.configuration_version_id,
                        "rollout_gateway_ids": deployment.rollout_gateways,
                        "rollout_reason": deployment.rollout_reason,
                    }),
                )
                .await?;
            Ok(())
        }

        // ── Agent gateway links ──
        // name is "agentname/gatewayname"
        ("agent.gateway_link", ReconcileAction::Create) => {
            let (agent_name, gateway_name) = split2(&op.name, '/')
                .ok_or_else(|| CliError::internal("agent.gateway_link name format invalid"))?;
            let agents = fetch_remote_list(client, "/v1/agents", "agents").await?;
            let agent_id = find_by_name(&agents, agent_name).ok_or_else(|| {
                CliError::user(format!("agent {agent_name:?} not found (was it created?)"))
            })?;
            client
                .post_json_value(
                    &format!("/v1/agents/{agent_id}/gateways"),
                    &serde_json::json!({ "gateway_id": gateway_name }),
                )
                .await?;
            Ok(())
        }

        // ── Billing budgets ──
        ("billing_budget", ReconcileAction::Create) => {
            let spec = find_budget_spec(manifest, &op.name)?;
            let scope_ids = resolve_budget_scope_ids(client, spec).await?;
            let body = build_budget_body(spec, &scope_ids);
            client.post_json_value("/v1/usage/budgets", &body).await?;
            Ok(())
        }
        ("billing_budget", ReconcileAction::Update) => {
            let spec = find_budget_spec(manifest, &op.name)?;
            let scope_ids = resolve_budget_scope_ids(client, spec).await?;
            let body = build_budget_body(spec, &scope_ids);
            let id = require_remote_id(op)?;
            client
                .put_json_value(&format!("/v1/usage/budgets/{id}"), &body)
                .await?;
            Ok(())
        }
        ("billing_budget", ReconcileAction::Delete) => {
            let id = require_remote_id(op)?;
            client
                .delete_json_value(&format!("/v1/usage/budgets/{id}"))
                .await?;
            Ok(())
        }

        // ── Regulated execution profiles ──
        ("regulated_execution_profile", ReconcileAction::Create) => {
            let spec = find_regulated_execution_profile_spec(manifest, &op.name)?;
            let body = build_regulated_execution_profile_body(spec);
            client
                .post_json_value("/v1/settings/regulated-execution-profiles", &body)
                .await?;
            Ok(())
        }
        ("regulated_execution_profile", ReconcileAction::Update) => {
            let spec = find_regulated_execution_profile_spec(manifest, &op.name)?;
            let body = build_regulated_execution_profile_body(spec);
            client
                .put_json_value(
                    &format!("/v1/settings/regulated-execution-profiles/{}", spec.name),
                    &body,
                )
                .await?;
            Ok(())
        }
        ("regulated_execution_profile", ReconcileAction::Delete) => {
            client
                .delete_json_value(&format!(
                    "/v1/settings/regulated-execution-profiles/{}",
                    op.name
                ))
                .await?;
            Ok(())
        }

        // ── Approval policies ──
        ("approval_policy", ReconcileAction::Create) => {
            let spec = find_approval_policy_spec(manifest, &op.name)?;
            let body = build_approval_policy_body(spec);
            client
                .post_json_value("/v1/approval-policies", &body)
                .await?;
            Ok(())
        }
        ("approval_policy", ReconcileAction::Update) => {
            let spec = find_approval_policy_spec(manifest, &op.name)?;
            let body = build_approval_policy_body(spec);
            let id = op
                .remote_id
                .as_deref()
                .ok_or_else(|| CliError::internal("approval_policy update missing remote_id"))?;
            client
                .put_json_value(&format!("/v1/approval-policies/{id}"), &body)
                .await?;
            Ok(())
        }
        ("approval_policy", ReconcileAction::Delete) => {
            let id = require_remote_id(op)?;
            client
                .delete_json_value(&format!("/v1/approval-policies/{id}"))
                .await?;
            Ok(())
        }

        // ── Prompt evaluation suites ──
        ("prompt_evaluation_suite", ReconcileAction::Create) => {
            let spec = find_prompt_evaluation_suite_spec(manifest, &op.name)?;
            let mut body = serde_json::json!({
                "name": prompt_evaluation_suite_resource_name(spec),
                "resource_name": prompt_evaluation_suite_resource_name(spec),
            });
            if let Some(desc) = &spec.description {
                body["description"] = serde_json::Value::String(desc.clone());
            }
            if let Some(enabled) = spec.enabled {
                body["enabled"] = serde_json::Value::Bool(enabled);
            }
            let resource_tags = build_resource_tags_value(&spec.resource_tags);
            if !resource_tags.as_array().is_none_or(|tags| tags.is_empty()) {
                body["resource_tags"] = resource_tags;
            }
            client.post_json_value("/v1/prompt-suites", &body).await?;
            Ok(())
        }
        ("prompt_evaluation_suite", ReconcileAction::Update) => {
            let spec = find_prompt_evaluation_suite_spec(manifest, &op.name)?;
            let id = require_remote_id(op)?;
            let mut body = serde_json::json!({
                "name": prompt_evaluation_suite_resource_name(spec),
                "description": spec.description,
                "resource_name": prompt_evaluation_suite_resource_name(spec),
                "resource_tags": build_resource_tags_value(&spec.resource_tags),
            });
            if let Some(enabled) = spec.enabled {
                body["enabled"] = serde_json::Value::Bool(enabled);
            }
            client
                .patch_json_value(&format!("/v1/prompt-suites/{id}"), &body)
                .await?;
            Ok(())
        }
        ("prompt_evaluation_suite", ReconcileAction::Delete) => {
            let id = require_remote_id(op)?;
            client
                .delete_json_value(&format!("/v1/prompt-suites/{id}"))
                .await?;
            Ok(())
        }

        // ── Collaboration defaults (singleton PUT) ──
        ("collaboration_defaults", ReconcileAction::Create | ReconcileAction::Update) => {
            let spec = manifest
                .resources
                .collaboration_defaults
                .as_ref()
                .ok_or_else(|| {
                    CliError::internal("collaboration_defaults spec missing from manifest")
                })?;
            let body = build_collaboration_defaults_body(spec);
            client
                .put_json_value("/v1/settings/collaboration", &body)
                .await?;
            Ok(())
        }

        // ── Hosted gateway policy (singleton PUT) ──
        ("hosted_gateway_policy", ReconcileAction::Create | ReconcileAction::Update) => {
            let spec = manifest
                .resources
                .hosted_gateway_policy
                .as_ref()
                .ok_or_else(|| {
                    CliError::internal("hosted_gateway_policy spec missing from manifest")
                })?;
            let body = build_hosted_gateway_policy_body(spec);
            client
                .put_json_value("/v1/settings/hosted-gateway-policy", &body)
                .await?;
            Ok(())
        }

        // ── Auth org policy (singleton PUT) ──
        ("auth_org_policy", ReconcileAction::Create | ReconcileAction::Update) => {
            let spec =
                manifest.resources.auth_org_policy.as_ref().ok_or_else(|| {
                    CliError::internal("auth_org_policy spec missing from manifest")
                })?;
            let body = build_auth_org_policy_body(spec);
            client
                .put_json_value("/v1/settings/auth-org-policy", &body)
                .await?;
            Ok(())
        }

        // ── Hosted-gateway explicit agent bindings (PUT upsert per gateway) ──
        ("hosted_gateway_binding", ReconcileAction::Update) => {
            let spec = find_hosted_gateway_binding_spec(manifest, &op.name)?;
            // Resolve agent name → agent ID at apply time.
            let agents = fetch_remote_list(client, "/v1/agents", "agents").await?;
            let agent_id = find_by_name(&agents, &spec.agent).ok_or_else(|| {
                CliError::user(format!(
                    "hosted_gateway_binding {:?}: agent {:?} not found — was it created?",
                    spec.gateway_id, spec.agent
                ))
            })?;
            client
                .put_json_value(
                    &format!("/v1/gateways/{}/agent-binding", spec.gateway_id),
                    &serde_json::json!({ "agent_id": agent_id }),
                )
                .await?;
            Ok(())
        }

        // ── NoOp ──
        (_, ReconcileAction::NoOp) => Ok(()),

        (rt, action) => Err(CliError::internal(format!(
            "unhandled reconcile op: {rt} {action}"
        ))),
    }
}

fn find_budget_spec<'m>(
    manifest: &'m ControlManifest,
    name: &str,
) -> Result<&'m BudgetSpec, CliError> {
    manifest
        .resources
        .budgets
        .iter()
        .find(|budget| budget.name == name)
        .ok_or_else(|| {
            CliError::internal(format!(
                "billing_budget spec {name:?} missing from manifest"
            ))
        })
}

async fn resolve_budget_scope_ids(
    client: &AsyncApiClient,
    spec: &BudgetSpec,
) -> Result<ResolvedBudgetScopeIds, CliError> {
    let mut resolved = ResolvedBudgetScopeIds::default();

    if let Some(team_name) = &spec.team {
        let teams = fetch_remote_list(client, "/v1/teams", "teams").await?;
        resolved.team_id = Some(find_by_name(&teams, team_name).ok_or_else(|| {
            CliError::user(format!(
                "billing budget {:?}: team {:?} not found — was it created?",
                spec.name, team_name
            ))
        })?);
    }

    if let Some(user_email) = &spec.user {
        let users = fetch_remote_list_by_email(client, "/v1/users").await?;
        resolved.user_id = Some(find_by_key(&users, user_email).ok_or_else(|| {
            CliError::user(format!(
                "billing budget {:?}: user {:?} not found — was it invited?",
                spec.name, user_email
            ))
        })?);
    }

    if let Some(agent_name) = &spec.agent {
        let agents = fetch_remote_list(client, "/v1/agents", "agents").await?;
        resolved.agent_id = Some(find_by_name(&agents, agent_name).ok_or_else(|| {
            CliError::user(format!(
                "billing budget {:?}: agent {:?} not found — was it created?",
                spec.name, agent_name
            ))
        })?);
    }

    Ok(resolved)
}

fn build_budget_body(spec: &BudgetSpec, scope_ids: &ResolvedBudgetScopeIds) -> serde_json::Value {
    serde_json::json!({
        "name": spec.name,
        "amount": spec.amount,
        "currency": budget_effective_currency(spec),
        "period_type": budget_effective_period_type(spec),
        "alert_thresholds": budget_effective_alert_thresholds(spec),
        "hard_limit_enabled": budget_effective_hard_limit_enabled(spec),
        "hard_limit_amount": spec.hard_limit_amount,
        "team_id": scope_ids.team_id,
        "user_id": scope_ids.user_id,
        "agent_id": scope_ids.agent_id,
        "timezone": budget_effective_timezone(spec),
        "week_starts_on": budget_effective_week_starts_on(spec),
        "month_anchor_day": budget_effective_month_anchor_day(spec),
        "billing_categories": budget_effective_billing_categories(spec),
    })
}

// ── Wave-2 spec finders and body builders ─────────────────────────────────────

fn find_regulated_execution_profile_spec<'m>(
    manifest: &'m ControlManifest,
    name: &str,
) -> Result<&'m RegulatedExecutionProfileSpec, CliError> {
    manifest
        .resources
        .regulated_execution_profiles
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| {
            CliError::internal(format!(
                "regulated_execution_profile spec {name:?} missing from manifest"
            ))
        })
}

pub fn build_regulated_execution_profile_body(
    spec: &RegulatedExecutionProfileSpec,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "name": spec.name,
        "deployment_profile": spec.deployment_profile,
    });
    if let Some(v) = spec.default {
        body["default"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = &spec.residency_region {
        body["residency_region"] = serde_json::Value::String(v.clone());
    }
    if let Some(v) = &spec.data_residency_tag {
        body["data_residency_tag"] = serde_json::Value::String(v.clone());
    }
    if let Some(v) = &spec.cross_border_policy {
        body["cross_border_policy"] = serde_json::Value::String(v.clone());
    }
    if let Some(v) = spec.tokenization_enabled {
        body["tokenization_enabled"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = spec.require_in_memory_only {
        body["require_in_memory_only"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = spec.allow_internet_egress {
        body["allow_internet_egress"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = &spec.workload_class {
        body["workload_class"] = serde_json::Value::String(v.clone());
    }
    if let Some(v) = spec.deletion_attestation_enabled {
        body["deletion_attestation_enabled"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = &spec.fail_mode {
        body["fail_mode"] = serde_json::Value::String(v.clone());
    }
    body
}

fn find_approval_policy_spec<'m>(
    manifest: &'m ControlManifest,
    name: &str,
) -> Result<&'m ApprovalPolicySpec, CliError> {
    manifest
        .resources
        .approval_policies
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| {
            CliError::internal(format!(
                "approval_policy spec {name:?} missing from manifest"
            ))
        })
}

pub fn build_approval_policy_body(spec: &ApprovalPolicySpec) -> serde_json::Value {
    let mut body = serde_json::json!({ "name": spec.name });
    if let Some(desc) = &spec.description {
        body["description"] = serde_json::Value::String(desc.clone());
    }
    if let Some(v) = spec.enabled {
        body["enabled"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = spec.simulation_mode {
        body["simulation_mode"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = spec.break_glass_enabled {
        body["break_glass_enabled"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = spec.break_glass_post_review_required {
        body["break_glass_post_review_required"] = serde_json::Value::Bool(v);
    }
    if !spec.thresholds.is_empty() {
        body["thresholds"] = serde_json::Value::Array(
            spec.thresholds
                .iter()
                .map(|t| {
                    let mut entry = serde_json::json!({
                        "risk_level": t.risk_level,
                        "approval_mode": t.approval_mode,
                        "required_approvals": t.required_approvals,
                    });
                    if let Some(v) = &t.data_class {
                        entry["data_class"] = serde_json::Value::String(v.clone());
                    }
                    if let Some(v) = &t.destination_pattern {
                        entry["destination_pattern"] = serde_json::Value::String(v.clone());
                    }
                    if let Some(v) = t.decision_ttl_minutes {
                        entry["decision_ttl_minutes"] = serde_json::Value::Number(v.into());
                    }
                    entry
                })
                .collect(),
        );
    }
    if !spec.approver_chains.is_empty() {
        body["approver_chains"] = serde_json::Value::Array(
            spec.approver_chains
                .iter()
                .map(|c| {
                    let mut entry = serde_json::json!({
                        "name": c.name,
                        "mode": c.mode,
                    });
                    if !c.approvers.is_empty() {
                        entry["approvers"] = serde_json::Value::Array(
                            c.approvers
                                .iter()
                                .cloned()
                                .map(serde_json::Value::String)
                                .collect(),
                        );
                    }
                    if !c.backup_approvers.is_empty() {
                        entry["backup_approvers"] = serde_json::Value::Array(
                            c.backup_approvers
                                .iter()
                                .cloned()
                                .map(serde_json::Value::String)
                                .collect(),
                        );
                    }
                    if let Some(v) = c.escalation_after_minutes {
                        entry["escalation_after_minutes"] = serde_json::Value::Number(v.into());
                    }
                    entry
                })
                .collect(),
        );
    }
    body
}

fn find_prompt_evaluation_suite_spec<'m>(
    manifest: &'m ControlManifest,
    name: &str,
) -> Result<&'m PromptEvaluationSuiteSpec, CliError> {
    manifest
        .resources
        .prompt_evaluation_suites
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| {
            CliError::internal(format!(
                "prompt_evaluation_suite spec {name:?} missing from manifest"
            ))
        })
}

pub fn find_hosted_gateway_binding_spec<'m>(
    manifest: &'m ControlManifest,
    gateway_id: &str,
) -> Result<&'m HostedGatewayBindingSpec, CliError> {
    manifest
        .resources
        .hosted_gateway_bindings
        .iter()
        .find(|b| b.gateway_id == gateway_id)
        .ok_or_else(|| {
            CliError::internal(format!(
                "hosted_gateway_binding spec for gateway {gateway_id:?} missing from manifest"
            ))
        })
}

pub fn build_collaboration_defaults_body(spec: &CollaborationDefaultsSpec) -> serde_json::Value {
    let mut body = serde_json::json!({});
    if let Some(v) = &spec.default_conversation_visibility {
        body["default_conversation_visibility"] = serde_json::Value::String(v.clone());
    }
    if let Some(v) = &spec.default_task_visibility {
        body["default_task_visibility"] = serde_json::Value::String(v.clone());
    }
    if let Some(v) = spec.allow_user_sharing {
        body["allow_user_sharing"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = spec.allow_team_sharing {
        body["allow_team_sharing"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = spec.audit_membership_changes {
        body["audit_membership_changes"] = serde_json::Value::Bool(v);
    }
    body
}

pub fn build_hosted_gateway_policy_body(spec: &HostedGatewayPolicySpec) -> serde_json::Value {
    let mut body = serde_json::json!({});
    if let Some(v) = &spec.default_agent {
        body["default_agent"] = serde_json::Value::String(v.clone());
    }
    if let Some(v) = spec.default_agent_fallback_enabled {
        body["default_agent_fallback_enabled"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = spec.fail_closed_on_missing_binding {
        body["fail_closed_on_missing_binding"] = serde_json::Value::Bool(v);
    }
    body
}

pub fn build_auth_org_policy_body(spec: &AuthOrgPolicySpec) -> serde_json::Value {
    let mut body = serde_json::json!({});
    if !spec.verified_domains.is_empty() {
        body["verified_domains"] = serde_json::Value::Array(
            spec.verified_domains
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    if let Some(v) = spec.required_sso {
        body["required_sso"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = spec.local_auth_allowed {
        body["local_auth_allowed"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = spec.jit_provisioning_enabled {
        body["jit_provisioning_enabled"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = spec.invite_only {
        body["invite_only"] = serde_json::Value::Bool(v);
    }
    if !spec.popup_return_origins.is_empty() {
        body["popup_return_origins"] = serde_json::Value::Array(
            spec.popup_return_origins
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    body
}

// ── Secret apply helpers ──────────────────────────────────────────────────────

async fn apply_secret_create(client: &AsyncApiClient, spec: &SecretSpec) -> Result<(), CliError> {
    let env_val = std::env::var(&spec.env).map_err(|_| {
        CliError::user(format!(
            "secret {:?}: env var {:?} is not set — cannot apply",
            spec.name, spec.env
        ))
    })?;
    let mut body = serde_json::json!({
        "name": spec.name,
        "value": env_val,
        "source_kind": "env",
        "env_var": spec.env,
    });
    if let Some(desc) = &spec.description {
        body["description"] = serde_json::Value::String(desc.clone());
    }
    client.post_json_value("/v1/secrets", &body).await?;
    Ok(())
}

async fn apply_secret_update(
    client: &AsyncApiClient,
    id: &str,
    spec: &SecretSpec,
) -> Result<(), CliError> {
    let env_val = std::env::var(&spec.env).map_err(|_| {
        CliError::user(format!(
            "secret {:?}: env var {:?} is not set — cannot apply update",
            spec.name, spec.env
        ))
    })?;
    client
        .put_json_value(
            &format!("/v1/secrets/{id}"),
            &serde_json::json!({
                "value": env_val,
                "source_kind": "env",
                "env_var": spec.env,
            }),
        )
        .await?;
    Ok(())
}

// ── Remote fetch helpers ──────────────────────────────────────────────────────

/// Fetch a JSON value from the API with retry on transient 502/503 errors.
///
/// Returns `Ok(Some(value))` on success, `Ok(None)` on 404 (resource type
/// not yet provisioned), and `Err` on auth errors or permanent failures.
/// Transient 502/503 responses are retried with exponential backoff
/// (1 s → 2 s → 4 s) before failing with a descriptive crash-loop message.
pub(crate) async fn fetch_json_value_with_retry(
    client: &AsyncApiClient,
    path: &str,
) -> Result<Option<serde_json::Value>, CliError> {
    const BACKOFF_SECS: [u64; 3] = [1, 2, 4];

    fetch_json_value_with_retry_using_backoff(client, path, &BACKOFF_SECS).await
}

async fn fetch_json_value_with_retry_using_backoff(
    client: &AsyncApiClient,
    path: &str,
    backoff_secs: &[u64],
) -> Result<Option<serde_json::Value>, CliError> {
    debug_assert!(
        !backoff_secs.is_empty(),
        "fetch_json_value_with_retry_using_backoff requires at least one retry slot"
    );

    let max_retries = backoff_secs.len();

    for (attempt, backoff) in backoff_secs.iter().copied().enumerate() {
        match client.get_json_value_once(path).await {
            Ok(value) => return Ok(Some(value)),
            Err(e) if e.is_auth() => return Err(e),
            Err(e) => {
                let status = e.http_status.unwrap_or(0);

                if status == 404 {
                    return Ok(None);
                }

                let is_transient = status == 502 || status == 503;

                if is_transient && attempt < max_retries - 1 {
                    tracing::warn!(
                        path,
                        status,
                        attempt = attempt + 1,
                        max_retries,
                        backoff_secs = backoff,
                        "Transient API error, retrying with backoff"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                    continue;
                }

                if is_transient {
                    return Err(CliError::network(format!(
                        "API returned {status} after {max_retries} retries. \
                         The API may be in a crash-loop. Check API logs and health."
                    )));
                }

                return Err(e);
            }
        }
    }

    unreachable!("retry loop always returns before completing")
}

fn agent_resource_name(spec: &AgentSpec) -> String {
    spec.resource_name
        .clone()
        .unwrap_or_else(|| spec.name.clone())
}

fn prompt_evaluation_suite_resource_name(spec: &PromptEvaluationSuiteSpec) -> String {
    spec.resource_name
        .clone()
        .unwrap_or_else(|| spec.name.clone())
}

fn build_resource_tags_value(resource_tags: &[ResourceTagSpec]) -> serde_json::Value {
    serde_json::Value::Array(
        resource_tags
            .iter()
            .map(|tag| {
                let mut value = serde_json::json!({
                    "key": tag.key,
                    "value": tag.value,
                });
                if let Some(source) = &tag.source {
                    value["source"] = serde_json::Value::String(source.clone());
                }
                value
            })
            .collect(),
    )
}

fn build_agent_body(spec: &AgentSpec) -> serde_json::Value {
    serde_json::json!({
        "name": agent_resource_name(spec),
        "resource_name": agent_resource_name(spec),
        "resource_tags": build_resource_tags_value(&spec.resource_tags),
        "context_fabric": spec.context_fabric,
        "mcp": spec.mcp,
    })
}

fn find_remote_prompt_evaluation_suite<'a>(
    remote: &'a [RemotePromptEvaluationSuite],
    spec: &PromptEvaluationSuiteSpec,
) -> Option<&'a RemotePromptEvaluationSuite> {
    let desired_name = prompt_evaluation_suite_resource_name(spec);
    remote
        .iter()
        .find(|suite| suite.name == spec.name || suite.name == desired_name)
}

fn prompt_evaluation_suite_needs_update(
    spec: &PromptEvaluationSuiteSpec,
    remote: &RemotePromptEvaluationSuite,
) -> bool {
    prompt_evaluation_suite_resource_name(spec) != remote.name
        || spec.description != remote.description
        || spec.enabled != remote.enabled
}

async fn fetch_remote_prompt_evaluation_suites(
    client: &AsyncApiClient,
) -> Result<Vec<RemotePromptEvaluationSuite>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/prompt-suites").await? {
        Some(v) => v,
        None => return Ok(vec![]),
    };

    let items: Vec<PromptSuiteItem> = extract_typed_list(&value, "items");

    Ok(items
        .into_iter()
        .filter_map(|item| {
            let id = item.resolved_id()?.to_string();
            let name = item.name?;
            Some(RemotePromptEvaluationSuite {
                id,
                name,
                description: item.description,
                enabled: item.enabled,
            })
        })
        .collect())
}

async fn fetch_remote_budgets(
    client: &AsyncApiClient,
) -> Result<Vec<RemoteBillingBudget>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/usage/budgets").await? {
        Some(v) => v,
        None => return Ok(vec![]),
    };

    let items: Vec<BudgetItem> = extract_typed_list(&value, "budgets");

    Ok(items
        .into_iter()
        .filter_map(|item| {
            Some(RemoteBillingBudget {
                id: item.id?,
                name: item.name?,
                amount: item.amount?,
                currency: item.currency.unwrap_or_else(|| "USD".to_string()),
                period_type: item.period_type.unwrap_or_else(|| "monthly".to_string()),
                alert_thresholds: if item.alert_thresholds.is_empty() {
                    vec![50, 75, 90]
                } else {
                    item.alert_thresholds
                },
                hard_limit_enabled: item.hard_limit_enabled.unwrap_or(false),
                hard_limit_amount: item.hard_limit_amount,
                team_id: item.team_id,
                user_id: item.user_id,
                agent_id: item.agent_id,
                timezone: item.timezone.unwrap_or_else(|| "UTC".to_string()),
                week_starts_on: item.week_starts_on.unwrap_or_else(|| "monday".to_string()),
                month_anchor_day: item.month_anchor_day.unwrap_or(1),
                billing_categories: if item.billing_categories.is_empty() {
                    vec!["gateway_llm".to_string()]
                } else {
                    item.billing_categories
                },
            })
        })
        .collect())
}

/// Fetch a paginated remote list and return `(name, id)` pairs.
///
/// Returns an empty list when the endpoint returns 404 (resource type not
/// yet provisioned). Auth errors (401/403) propagate immediately.
/// Transient 502/503 errors are retried with exponential backoff; other
/// non-success statuses propagate as hard failures.
async fn fetch_remote_list(
    client: &AsyncApiClient,
    path: &str,
    array_key: &str,
) -> Result<Vec<(String, String)>, CliError> {
    let value = match fetch_json_value_with_retry(client, path).await? {
        Some(v) => v,
        None => return Ok(vec![]),
    };

    let items: Vec<NamedResource> = extract_typed_list(&value, array_key);

    Ok(items
        .into_iter()
        .filter_map(|item| {
            let id = item.resolved_id()?.to_string();
            let name = item.name?;
            Some((name, id))
        })
        .collect())
}

/// Fetch users list indexed by email (rather than name).
/// Auth errors (401/403) propagate immediately. Transient 502/503 errors
/// are retried with exponential backoff.
async fn fetch_remote_list_by_email(
    client: &AsyncApiClient,
    path: &str,
) -> Result<Vec<(String, String)>, CliError> {
    let value = match fetch_json_value_with_retry(client, path).await? {
        Some(v) => v,
        None => return Ok(vec![]),
    };

    let items: Vec<UserResource> = extract_typed_list(&value, "users");

    Ok(items
        .into_iter()
        .filter_map(|item| {
            let id = item.resolved_id()?.to_string();
            let email = item.email?;
            Some((email, id))
        })
        .collect())
}

async fn fetch_remote_platform_provider_bundles(
    client: &AsyncApiClient,
) -> Result<Vec<RemotePlatformProviderBundle>, CliError> {
    let value = match fetch_json_value_with_retry(
        client,
        "/v1/admin/platform-provider-bundles?include_archived=true",
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(vec![]),
    };

    let items: Vec<PlatformProviderBundleItem> = extract_typed_list(&value, "bundles");

    Ok(items
        .into_iter()
        .filter_map(|item| {
            Some(RemotePlatformProviderBundle {
                bundle_key: item.bundle_key?,
                provider_registry: item.provider_registry?,
                status: item.status?,
            })
        })
        .collect())
}

async fn fetch_remote_policies(client: &AsyncApiClient) -> Result<Vec<RemoteIamPolicy>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/policies").await? {
        Some(v) => v,
        None => return Ok(vec![]),
    };

    let items: Vec<PolicyItem> = extract_typed_list(&value, "policies");
    let named: Vec<NamedResource> = extract_typed_list(&value, "policies");

    Ok(items
        .into_iter()
        .zip(named)
        .filter_map(|(item, named)| {
            Some(RemoteIamPolicy {
                id: named.resolved_id()?.to_string(),
                name: item.name?,
                description: item.description,
                statements: item.statements,
            })
        })
        .collect())
}

pub fn platform_provider_bundle_status(spec: &PlatformProviderBundleSpec) -> &str {
    spec.status.as_deref().unwrap_or("active")
}

fn platform_provider_bundle_needs_update(
    spec: &PlatformProviderBundleSpec,
    remote: &RemotePlatformProviderBundle,
) -> bool {
    remote.provider_registry != spec.provider_registry
        || remote.status != platform_provider_bundle_status(spec)
}

pub fn find_by_name(list: &[(String, String)], name: &str) -> Option<String> {
    list.iter()
        .find(|(n, _)| n == name)
        .map(|(_, id)| id.clone())
}

fn find_by_key(list: &[(String, String)], key: &str) -> Option<String> {
    list.iter()
        .find(|(k, _)| k == key)
        .map(|(_, id)| id.clone())
}

fn normalized_policy_description(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn normalized_policy_statements(value: Option<&Value>) -> Value {
    match value {
        Some(value) => value
            .get("Statement")
            .or_else(|| value.get("statements"))
            .cloned()
            .unwrap_or_else(|| value.clone()),
        None => Value::Null,
    }
}

fn iam_policy_needs_update(spec: &IamPolicySpec, remote: &RemoteIamPolicy) -> bool {
    normalized_policy_description(spec.description.as_deref())
        != normalized_policy_description(remote.description.as_deref())
        || normalized_policy_statements(spec.statements.as_ref())
            != normalized_policy_statements(remote.statements.as_ref())
}

fn iam_policy_diff_detail(spec: &IamPolicySpec, remote: &RemoteIamPolicy) -> Option<String> {
    let mut lines = Vec::new();

    if normalized_policy_description(spec.description.as_deref())
        != normalized_policy_description(remote.description.as_deref())
    {
        lines.push("~ description".to_string());
    }
    if normalized_policy_statements(spec.statements.as_ref())
        != normalized_policy_statements(remote.statements.as_ref())
    {
        lines.push("~ statements".to_string());
    }

    (!lines.is_empty()).then(|| lines.join("\n"))
}

fn build_iam_policy_body(spec: &IamPolicySpec) -> Result<serde_json::Value, CliError> {
    let statements = spec.statements.clone().ok_or_else(|| {
        CliError::user(format!(
            "IAM policy {:?} is missing statements; supply an ABAC policy document",
            spec.name
        ))
    })?;
    let mut body = serde_json::json!({
        "name": spec.name.clone(),
        "statements": statements,
    });
    if let Some(desc) = &spec.description {
        body["description"] = serde_json::Value::String(desc.clone());
    }
    Ok(body)
}

// ── Internal small helpers ────────────────────────────────────────────────────

fn find_secret_spec<'m>(
    manifest: &'m ControlManifest,
    name: &str,
) -> Result<&'m SecretSpec, CliError> {
    manifest
        .resources
        .secrets
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| CliError::internal(format!("secret spec {name:?} missing from manifest")))
}

fn find_platform_provider_bundle_spec<'m>(
    manifest: &'m ControlManifest,
    bundle_key: &str,
) -> Result<&'m PlatformProviderBundleSpec, CliError> {
    manifest
        .resources
        .platform_provider_bundles
        .iter()
        .find(|bundle| bundle.bundle_key == bundle_key)
        .ok_or_else(|| {
            CliError::internal(format!(
                "platform provider bundle spec {bundle_key:?} missing from manifest"
            ))
        })
}

fn require_remote_id(op: &ReconcileOp) -> Result<&str, CliError> {
    op.remote_id
        .as_deref()
        .ok_or_else(|| CliError::internal(format!("{} delete missing remote_id", op.name)))
}

/// Extract the resource `id` from a JSON response, trying multiple field names.
fn extract_id(value: &serde_json::Value) -> String {
    let result: Result<ResourceIdResponse, _> = serde_json::from_value(value.clone());
    result.map(|r| r.resolved_id()).unwrap_or_default()
}

/// Split `s` on the first occurrence of `sep` and return `(left, right)`.
pub fn split2(s: &str, sep: char) -> Option<(&str, &str)> {
    let idx = s.find(sep)?;
    Some((&s[..idx], &s[idx + sep.len_utf8()..]))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

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
    use crate::managed::control_manifest::{
        AgentDeploymentSpec, ApprovalThresholdSpec, ApproverChainSpec, AuthOrgPolicySpec,
        CollaborationDefaultsSpec, HostedGatewayPolicySpec, IamSpec, Resources, TeamMemberSpec,
    };
    use axum::{
        body::Bytes,
        extract::State,
        http::{Method, StatusCode, Uri},
        Json, Router,
    };
    use std::{
        collections::{HashMap, VecDeque},
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Debug)]
    struct MockApiResponse {
        status: StatusCode,
        body: serde_json::Value,
    }

    #[derive(Clone, Debug, PartialEq)]
    struct RecordedRequest {
        method: String,
        path: String,
        body: serde_json::Value,
    }

    #[derive(Clone, Default)]
    struct MockApiState {
        responses: Arc<Mutex<HashMap<String, VecDeque<MockApiResponse>>>>,
        request_counts: Arc<Mutex<HashMap<String, usize>>>,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
    }

    impl MockApiState {
        fn request_count(&self, path: &str) -> usize {
            self.request_counts
                .lock()
                .expect("lock request counts")
                .get(path)
                .copied()
                .unwrap_or(0)
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.requests.lock().expect("lock requests").clone()
        }

        fn request_summaries(&self) -> Vec<String> {
            self.requests()
                .into_iter()
                .map(|request| format!("{} {}", request.method, request.path))
                .collect()
        }
    }

    fn mock_response(status: StatusCode, body: serde_json::Value) -> MockApiResponse {
        MockApiResponse { status, body }
    }

    async fn scripted_api_handler(
        State(state): State<MockApiState>,
        method: Method,
        uri: Uri,
        body: Bytes,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let path = uri
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| uri.path().to_string());

        {
            let mut counts = state.request_counts.lock().expect("lock request counts");
            *counts.entry(path.clone()).or_default() += 1;
        }

        state
            .requests
            .lock()
            .expect("lock requests")
            .push(RecordedRequest {
                method: method.to_string(),
                path: path.clone(),
                body: if body.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_slice(body.as_ref()).unwrap_or_else(|_| {
                        serde_json::Value::String(
                            String::from_utf8_lossy(body.as_ref()).into_owned(),
                        )
                    })
                },
            });

        let response = {
            let mut responses = state.responses.lock().expect("lock responses");
            match responses.get_mut(&path) {
                Some(queue) if queue.len() > 1 => queue.pop_front().expect("scripted response"),
                Some(queue) => queue.front().cloned().expect("scripted response"),
                None => mock_response(
                    StatusCode::NOT_FOUND,
                    serde_json::json!({"error": "not found"}),
                ),
            }
        };

        (response.status, Json(response.body))
    }

    async fn spawn_mock_api(
        responses: Vec<(String, Vec<MockApiResponse>)>,
    ) -> (AsyncApiClient, MockApiState, tokio::task::JoinHandle<()>) {
        let state = MockApiState {
            responses: Arc::new(Mutex::new(
                responses
                    .into_iter()
                    .map(|(path, items)| (path, VecDeque::from(items)))
                    .collect(),
            )),
            request_counts: Arc::new(Mutex::new(HashMap::new())),
            requests: Arc::new(Mutex::new(Vec::new())),
        };

        let app = Router::new()
            .fallback(scripted_api_handler)
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock api");
        let addr = listener.local_addr().expect("mock api addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock api server");
        });

        let client =
            AsyncApiClient::new(format!("http://{}", addr), "test-token").expect("mock client");
        (client, state, handle)
    }

    fn sample_budget_spec() -> BudgetSpec {
        BudgetSpec {
            name: "monthly-budget".to_string(),
            amount: "10.00".to_string(),
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
        }
    }

    fn sample_remote_budget() -> RemoteBillingBudget {
        RemoteBillingBudget {
            id: "budget-1".to_string(),
            name: "monthly-budget".to_string(),
            amount: "10.0".to_string(),
            currency: "USD".to_string(),
            period_type: "monthly".to_string(),
            alert_thresholds: vec![50, 75, 90],
            hard_limit_enabled: false,
            hard_limit_amount: None,
            team_id: None,
            user_id: None,
            agent_id: None,
            timezone: "UTC".to_string(),
            week_starts_on: "monday".to_string(),
            month_anchor_day: 1,
            billing_categories: vec!["gateway_llm".to_string()],
        }
    }

    fn sample_prompt_suite_spec() -> PromptEvaluationSuiteSpec {
        PromptEvaluationSuiteSpec {
            name: "nightly".to_string(),
            resource_name: Some("nightly-prod".to_string()),
            description: Some("Nightly checks".to_string()),
            enabled: Some(true),
            resource_tags: vec![],
        }
    }

    fn sample_remote_prompt_suite() -> RemotePromptEvaluationSuite {
        RemotePromptEvaluationSuite {
            id: "suite-1".to_string(),
            name: "nightly-prod".to_string(),
            description: Some("Nightly checks".to_string()),
            enabled: Some(true),
        }
    }

    fn sample_provider_bundle_spec() -> PlatformProviderBundleSpec {
        PlatformProviderBundleSpec {
            bundle_key: "shared-openai".to_string(),
            provider_registry: serde_json::json!({"targets": ["gpt-5.4"]}),
            status: None,
        }
    }

    fn sample_remote_provider_bundle() -> RemotePlatformProviderBundle {
        RemotePlatformProviderBundle {
            bundle_key: "shared-openai".to_string(),
            provider_registry: serde_json::json!({"targets": ["gpt-5.4"]}),
            status: "active".to_string(),
        }
    }

    fn sample_regulated_execution_profile_spec() -> RegulatedExecutionProfileSpec {
        RegulatedExecutionProfileSpec {
            name: "regulated".to_string(),
            deployment_profile: "regulated_saas".to_string(),
            default: Some(true),
            residency_region: Some("eu-west-1".to_string()),
            data_residency_tag: None,
            cross_border_policy: Some("deny_by_default".to_string()),
            tokenization_enabled: Some(true),
            require_in_memory_only: Some(true),
            allow_internet_egress: Some(false),
            workload_class: Some("regulated".to_string()),
            deletion_attestation_enabled: Some(true),
            fail_mode: Some("fail_closed".to_string()),
        }
    }

    fn sample_approval_policy_spec() -> ApprovalPolicySpec {
        ApprovalPolicySpec {
            name: "dual".to_string(),
            description: Some("Dual approval policy".to_string()),
            enabled: Some(true),
            simulation_mode: Some(false),
            break_glass_enabled: Some(true),
            break_glass_post_review_required: Some(true),
            thresholds: vec![ApprovalThresholdSpec {
                risk_level: "high".to_string(),
                data_class: Some("phi".to_string()),
                destination_pattern: Some("s3://exports/*".to_string()),
                approval_mode: "dual".to_string(),
                required_approvals: 2,
                decision_ttl_minutes: Some(30),
            }],
            approver_chains: vec![ApproverChainSpec {
                name: "security".to_string(),
                mode: "delegated_chain".to_string(),
                approvers: vec!["alice".to_string(), "bob".to_string()],
                backup_approvers: vec!["charlie".to_string()],
                escalation_after_minutes: Some(15),
            }],
        }
    }

    fn sample_collaboration_defaults_spec() -> CollaborationDefaultsSpec {
        CollaborationDefaultsSpec {
            default_conversation_visibility: Some("team".to_string()),
            default_task_visibility: Some("owner_only".to_string()),
            allow_user_sharing: Some(true),
            allow_team_sharing: Some(false),
            audit_membership_changes: Some(true),
        }
    }

    fn sample_hosted_gateway_policy_spec() -> HostedGatewayPolicySpec {
        HostedGatewayPolicySpec {
            default_agent: Some("nightly-bot".to_string()),
            default_agent_fallback_enabled: Some(true),
            fail_closed_on_missing_binding: Some(false),
        }
    }

    fn sample_auth_org_policy_spec() -> AuthOrgPolicySpec {
        AuthOrgPolicySpec {
            verified_domains: vec!["verdictan.com".to_string()],
            required_sso: Some(true),
            local_auth_allowed: Some(false),
            jit_provisioning_enabled: Some(true),
            invite_only: Some(false),
            popup_return_origins: vec!["https://console.verdictan.com".to_string()],
        }
    }

    fn sample_agent_spec() -> AgentSpec {
        AgentSpec {
            name: "nightly-bot".to_string(),
            resource_name: None,
            resource_tags: vec![],
            team: Some("platform".to_string()),
            scope_kind: None,
            gateways: vec!["gw-eu".to_string(), "gw-us".to_string()],
            context_fabric: None,
            mcp: None,
            deployment: Some(AgentDeploymentSpec {
                configuration_id: "cfg-1".to_string(),
                configuration_version_id: "cfgv-1".to_string(),
                rollout_gateways: vec!["gw-eu".to_string()],
                rollout_reason: Some("initial rollout".to_string()),
            }),
        }
    }

    fn execution_manifest() -> ControlManifest {
        let mut prompt_suite = sample_prompt_suite_spec();
        prompt_suite.resource_tags = vec![crate::managed::control_manifest::ResourceTagSpec {
            key: "env".to_string(),
            value: "prod".to_string(),
            source: Some("user".to_string()),
        }];

        ControlManifest {
            version: "1".to_string(),
            resources: Resources {
                secrets: vec![],
                iam: Some(IamSpec {
                    policies: vec![IamPolicySpec {
                        name: "read-events".to_string(),
                        description: Some("Read event history".to_string()),
                        statements: Some(
                            serde_json::json!([{ "effect": "allow", "action": ["events:read"] }]),
                        ),
                    }],
                    roles: vec![IamRoleSpec {
                        name: "analyst".to_string(),
                        policies: vec!["read-events".to_string()],
                    }],
                }),
                teams: vec![TeamSpec {
                    name: "platform".to_string(),
                    description: Some("Platform team".to_string()),
                    members: vec![TeamMemberSpec {
                        email: "alice@example.com".to_string(),
                        roles: vec!["admin".to_string()],
                    }],
                }],
                users: vec![UserSpec {
                    email: "alice@example.com".to_string(),
                    teams: vec![],
                    roles: vec![],
                }],
                platform_provider_bundles: vec![PlatformProviderBundleSpec {
                    bundle_key: "shared-openai".to_string(),
                    provider_registry: serde_json::json!({"targets": ["gpt-5.4"]}),
                    status: Some("active".to_string()),
                }],
                agents: vec![AgentSpec {
                    name: "nightly-bot".to_string(),
                    resource_name: Some("nightly-bot-resource".to_string()),
                    resource_tags: vec![crate::managed::control_manifest::ResourceTagSpec {
                        key: "env".to_string(),
                        value: "prod".to_string(),
                        source: Some("user".to_string()),
                    }],
                    team: Some("platform".to_string()),
                    scope_kind: None,
                    gateways: vec!["gw-eu".to_string()],
                    context_fabric: Some(
                        crate::managed::control_manifest::AgentContextFabricSpec {
                            capture_mode: Some("auto".to_string()),
                            ..crate::managed::control_manifest::AgentContextFabricSpec::default()
                        },
                    ),
                    mcp: Some(crate::managed::control_manifest::AgentMcpSpec {
                        enabled: Some(true),
                        ..crate::managed::control_manifest::AgentMcpSpec::default()
                    }),
                    deployment: Some(AgentDeploymentSpec {
                        configuration_id: "cfg-1".to_string(),
                        configuration_version_id: "cfgv-1".to_string(),
                        rollout_gateways: vec!["gw-eu".to_string()],
                        rollout_reason: Some("initial rollout".to_string()),
                    }),
                }],
                budgets: vec![BudgetSpec {
                    name: "ops-budget".to_string(),
                    amount: "42.00".to_string(),
                    currency: Some("EUR".to_string()),
                    period_type: Some("weekly".to_string()),
                    alert_thresholds: vec![25, 75],
                    hard_limit_enabled: Some(true),
                    hard_limit_amount: Some("84.00".to_string()),
                    team: Some("platform".to_string()),
                    user: Some("alice@example.com".to_string()),
                    agent: Some("nightly-bot".to_string()),
                    timezone: Some("Europe/Madrid".to_string()),
                    week_starts_on: Some("sunday".to_string()),
                    month_anchor_day: Some(14),
                    billing_categories: vec!["agents".to_string()],
                }],
                regulated_execution_profiles: vec![sample_regulated_execution_profile_spec()],
                approval_policies: vec![sample_approval_policy_spec()],
                prompt_evaluation_suites: vec![prompt_suite],
                collaboration_defaults: Some(sample_collaboration_defaults_spec()),
                hosted_gateway_policy: Some(sample_hosted_gateway_policy_spec()),
                hosted_gateway_bindings: vec![HostedGatewayBindingSpec {
                    gateway_id: "gw-prod".to_string(),
                    agent: "nightly-bot".to_string(),
                }],
                auth_org_policy: Some(sample_auth_org_policy_spec()),
            },
        }
    }

    fn lookup_manifest() -> ControlManifest {
        ControlManifest {
            version: "1".to_string(),
            resources: Resources {
                secrets: vec![SecretSpec {
                    name: "openai-key".to_string(),
                    env: "VERDICTAN_OPENAI_API_KEY".to_string(),
                    description: None,
                }],
                iam: None,
                teams: vec![],
                users: vec![],
                platform_provider_bundles: vec![PlatformProviderBundleSpec {
                    bundle_key: "shared-openai".to_string(),
                    provider_registry: serde_json::json!({"targets": []}),
                    status: Some("active".to_string()),
                }],
                agents: vec![],
                budgets: vec![sample_budget_spec()],
                regulated_execution_profiles: vec![RegulatedExecutionProfileSpec {
                    name: "regulated".to_string(),
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
                }],
                approval_policies: vec![ApprovalPolicySpec {
                    name: "dual".to_string(),
                    description: None,
                    enabled: Some(true),
                    simulation_mode: None,
                    break_glass_enabled: None,
                    break_glass_post_review_required: None,
                    thresholds: vec![],
                    approver_chains: vec![],
                }],
                prompt_evaluation_suites: vec![PromptEvaluationSuiteSpec {
                    name: "nightly".to_string(),
                    resource_name: Some("nightly-prod".to_string()),
                    description: Some("Nightly checks".to_string()),
                    enabled: Some(true),
                    resource_tags: vec![],
                }],
                collaboration_defaults: None,
                hosted_gateway_policy: None,
                hosted_gateway_bindings: vec![HostedGatewayBindingSpec {
                    gateway_id: "gw-prod".to_string(),
                    agent: "nightly-bot".to_string(),
                }],
                auth_org_policy: None,
            },
        }
    }

    fn empty_manifest() -> ControlManifest {
        ControlManifest {
            version: "1".to_string(),
            resources: Resources::default(),
        }
    }

    fn plan_summaries(plan: &ReconcilePlan) -> Vec<String> {
        plan.ops
            .iter()
            .map(|op| format!("{}:{}:{}", op.resource_type, op.name, op.action))
            .collect()
    }

    fn find_request<'a>(
        requests: &'a [RecordedRequest],
        method: &str,
        path: &str,
    ) -> &'a RecordedRequest {
        requests
            .iter()
            .find(|request| request.method == method && request.path == path)
            .unwrap_or_else(|| panic!("missing request {method} {path}"))
    }

    #[test]
    fn reconcile_result_reports_failures() {
        let mut result = ReconcileResult::default();
        assert!(!result.has_failures());

        result.failed.push(ReconcileOpError {
            op: ReconcileOp {
                resource_type: "secret".to_string(),
                name: "bad".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            error: "boom".to_string(),
        });
        assert!(result.has_failures());
    }

    #[test]
    fn reconcile_action_display_uses_cli_strings() {
        assert_eq!(ReconcileAction::Create.to_string(), "create");
        assert_eq!(ReconcileAction::Update.to_string(), "update");
        assert_eq!(ReconcileAction::Delete.to_string(), "delete");
        assert_eq!(ReconcileAction::NoOp.to_string(), "no-op");
    }

    #[test]
    fn reconcile_plan_counts_and_has_changes_track_actions() {
        let empty = ReconcilePlan::default();
        assert!(!empty.has_changes());
        assert_eq!(empty.creates(), 0);
        assert_eq!(empty.updates(), 0);
        assert_eq!(empty.deletions(), 0);
        assert_eq!(empty.no_ops(), 0);

        let plan = ReconcilePlan {
            ops: vec![
                ReconcileOp {
                    resource_type: "secret".to_string(),
                    name: "create-me".to_string(),
                    action: ReconcileAction::Create,
                    remote_id: None,
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "budget".to_string(),
                    name: "update-me".to_string(),
                    action: ReconcileAction::Update,
                    remote_id: Some("budget-1".to_string()),
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "agent".to_string(),
                    name: "delete-me".to_string(),
                    action: ReconcileAction::Delete,
                    remote_id: Some("agent-1".to_string()),
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "team".to_string(),
                    name: "noop".to_string(),
                    action: ReconcileAction::NoOp,
                    remote_id: Some("team-1".to_string()),
                    detail: None,
                },
            ],
        };

        assert!(plan.has_changes());
        assert_eq!(plan.creates(), 1);
        assert_eq!(plan.updates(), 1);
        assert_eq!(plan.deletions(), 1);
        assert_eq!(plan.no_ops(), 1);
    }

    #[test]
    fn agent_ops_for_spec_creates_agent_deployment_and_gateway_links_for_new_agent() {
        let spec = sample_agent_spec();

        let ops = agent_ops_for_spec(&spec, None);

        assert_eq!(ops.len(), 4);
        assert_eq!(ops[0].resource_type.as_str(), "agent");
        assert_eq!(ops[0].name.as_str(), "nightly-bot");
        assert_eq!(&ops[0].action, &ReconcileAction::Create);
        assert!(ops[0].remote_id.is_none());
        assert_eq!(ops[0].detail.as_deref(), Some("platform"));

        assert_eq!(ops[1].resource_type.as_str(), "agent.deployment");
        assert_eq!(&ops[1].action, &ReconcileAction::Create);
        assert!(ops[1].remote_id.is_none());
        assert_eq!(ops[1].detail.as_deref(), Some("cfgv-1"));

        assert_eq!(ops[2].resource_type.as_str(), "agent.gateway_link");
        assert_eq!(ops[2].name.as_str(), "nightly-bot/gw-eu");
        assert_eq!(&ops[2].action, &ReconcileAction::Create);
        assert!(ops[2].remote_id.is_none());

        assert_eq!(ops[3].resource_type.as_str(), "agent.gateway_link");
        assert_eq!(ops[3].name.as_str(), "nightly-bot/gw-us");
        assert_eq!(&ops[3].action, &ReconcileAction::Create);
        assert!(ops[3].remote_id.is_none());
    }

    #[test]
    fn agent_ops_for_spec_keeps_existing_agent_noop_and_updates_deployment() {
        let mut spec = sample_agent_spec();
        spec.resource_name = Some(spec.name.clone());

        let ops = agent_ops_for_spec(&spec, Some("agent-1".to_string()));

        assert_eq!(ops.len(), 4);
        assert_eq!(ops[0].resource_type.as_str(), "agent");
        assert_eq!(&ops[0].action, &ReconcileAction::NoOp);
        assert_eq!(ops[0].remote_id.as_deref(), Some("agent-1"));
        assert_eq!(ops[0].detail.as_deref(), Some("platform"));

        assert_eq!(ops[1].resource_type.as_str(), "agent.deployment");
        assert_eq!(&ops[1].action, &ReconcileAction::Update);
        assert_eq!(ops[1].remote_id.as_deref(), Some("agent-1"));
        assert_eq!(ops[1].detail.as_deref(), Some("cfgv-1"));
    }

    #[test]
    fn agent_ops_for_spec_marks_existing_agent_for_update_when_resource_name_changes() {
        let mut spec = sample_agent_spec();
        spec.resource_name = Some("nightly-bot-v2".to_string());
        spec.deployment = None;
        spec.gateways.clear();

        let ops = agent_ops_for_spec(&spec, Some("agent-1".to_string()));

        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].resource_type.as_str(), "agent");
        assert_eq!(&ops[0].action, &ReconcileAction::Update);
        assert_eq!(ops[0].remote_id.as_deref(), Some("agent-1"));
        assert_eq!(ops[0].detail.as_deref(), Some("platform"));
    }

    #[test]
    fn agent_needs_update_detects_context_fabric_and_mcp_drift() {
        let mut spec = sample_agent_spec();
        spec.resource_name = Some(spec.name.clone());
        spec.context_fabric = Some(crate::managed::control_manifest::AgentContextFabricSpec {
            capture_mode: Some("auto".to_string()),
            ..crate::managed::control_manifest::AgentContextFabricSpec::default()
        });
        spec.mcp = Some(crate::managed::control_manifest::AgentMcpSpec {
            enabled: Some(true),
            ..crate::managed::control_manifest::AgentMcpSpec::default()
        });

        let remote = AgentItem {
            name: Some("nightly-bot".to_string()),
            id: Some("agent-1".to_string()),
            agent_id: None,
            team_name: Some("platform".to_string()),
            team: None,
            gateway_ids: vec!["gw-eu".to_string(), "gw-us".to_string()],
            scope_kind: None,
            configuration_id: Some("cfg-1".to_string()),
            active_configuration_version_id: Some("cfgv-1".to_string()),
            configuration_version_id: None,
            resource_name: Some("nightly-bot".to_string()),
            resource_tags: vec![],
            context_fabric: None,
            mcp: None,
        };

        assert!(agent_needs_update(&spec, &remote));
    }

    #[test]
    fn agent_control_config_diff_lines_report_added_removed_and_changed_fields() {
        let mut spec = sample_agent_spec();
        spec.resource_name = Some(spec.name.clone());
        spec.context_fabric = Some(crate::managed::control_manifest::AgentContextFabricSpec {
            capture_mode: Some("auto".to_string()),
            pool_max_entries: Some(500),
            direct_answer_threshold: Some(0.85),
            ..crate::managed::control_manifest::AgentContextFabricSpec::default()
        });
        spec.mcp = Some(crate::managed::control_manifest::AgentMcpSpec {
            enabled: Some(true),
            allowed_tools: Some(
                crate::managed::control_manifest::MatchListOrWildcardSpec::Explicit(vec![
                    "context_search".to_string(),
                ]),
            ),
            allowed_resources: Some(
                crate::managed::control_manifest::MatchListOrWildcardSpec::Wildcard(
                    "*".to_string(),
                ),
            ),
            session_limits: Some(crate::managed::control_manifest::McpSessionLimitsSpec {
                max_prompt_bytes: Some(64_000),
                ..crate::managed::control_manifest::McpSessionLimitsSpec::default()
            }),
            tool_servers: Some(crate::managed::control_manifest::McpToolServerPolicySpec {
                allowed_ids: Some(vec!["approved-db-tool".to_string()]),
                ..crate::managed::control_manifest::McpToolServerPolicySpec::default()
            }),
        });

        let remote = AgentItem {
            name: Some("nightly-bot".to_string()),
            id: Some("agent-1".to_string()),
            agent_id: None,
            team_name: Some("platform".to_string()),
            team: None,
            gateway_ids: vec!["gw-eu".to_string(), "gw-us".to_string()],
            scope_kind: None,
            configuration_id: Some("cfg-1".to_string()),
            active_configuration_version_id: Some("cfgv-1".to_string()),
            configuration_version_id: None,
            resource_name: Some("nightly-bot".to_string()),
            resource_tags: vec![],
            context_fabric: Some(crate::managed::control_manifest::AgentContextFabricSpec {
                capture_mode: Some("off".to_string()),
                branch_inheritance: Some(true),
                ..crate::managed::control_manifest::AgentContextFabricSpec::default()
            }),
            mcp: Some(crate::managed::control_manifest::AgentMcpSpec {
                enabled: Some(false),
                session_limits: Some(crate::managed::control_manifest::McpSessionLimitsSpec {
                    max_concurrent_sessions: Some(2),
                    ..crate::managed::control_manifest::McpSessionLimitsSpec::default()
                }),
                tool_servers: Some(crate::managed::control_manifest::McpToolServerPolicySpec {
                    allowed_ids: Some(vec!["legacy-db-tool".to_string()]),
                    ..crate::managed::control_manifest::McpToolServerPolicySpec::default()
                }),
                ..crate::managed::control_manifest::AgentMcpSpec::default()
            }),
        };

        let diff_lines = agent_control_config_diff_lines(&spec, &remote);

        assert_eq!(
            diff_lines,
            vec![
                "- context_fabric.branch_inheritance: true".to_string(),
                "~ context_fabric.capture_mode: \"off\" -> \"auto\"".to_string(),
                "+ context_fabric.direct_answer_threshold: 0.85".to_string(),
                "+ context_fabric.pool_max_entries: 500".to_string(),
                "~ mcp.enabled: false -> true".to_string(),
                "- mcp.session_limits.max_concurrent_sessions: 2".to_string(),
                "+ mcp.session_limits.max_prompt_bytes: 64000".to_string(),
                "~ mcp.tool_servers.allowed_ids: [\"legacy-db-tool\"] -> [\"approved-db-tool\"]"
                    .to_string(),
                "+ mcp.allowed_resources: \"*\"".to_string(),
                "+ mcp.allowed_tools: [\"context_search\"]".to_string(),
            ]
        );
    }

    #[test]
    fn build_agent_body_includes_context_fabric_and_mcp_sections() {
        let mut spec = sample_agent_spec();
        spec.context_fabric = Some(crate::managed::control_manifest::AgentContextFabricSpec {
            capture_mode: Some("off".to_string()),
            pool_max_entries: Some(900),
            ..crate::managed::control_manifest::AgentContextFabricSpec::default()
        });
        spec.mcp = Some(crate::managed::control_manifest::AgentMcpSpec {
            allowed_tools: Some(
                crate::managed::control_manifest::MatchListOrWildcardSpec::Explicit(vec![
                    "context_search".to_string(),
                ]),
            ),
            ..crate::managed::control_manifest::AgentMcpSpec::default()
        });

        let body = build_agent_body(&spec);

        assert_eq!(body["name"], serde_json::json!("nightly-bot"));
        assert_eq!(
            body["context_fabric"]["capture_mode"],
            serde_json::json!("off")
        );
        assert_eq!(
            body["mcp"]["allowed_tools"],
            serde_json::json!(["context_search"])
        );
    }

    #[test]
    fn budget_default_helpers_cover_org_and_named_scopes() {
        let mut spec = sample_budget_spec();
        assert_eq!(budget_scope_identity(&spec), "org");
        assert_eq!(budget_effective_currency(&spec), "USD");
        assert_eq!(budget_effective_period_type(&spec), "monthly");
        assert_eq!(budget_effective_alert_thresholds(&spec), vec![50, 75, 90]);
        assert!(!budget_effective_hard_limit_enabled(&spec));
        assert_eq!(budget_effective_timezone(&spec), "UTC");
        assert_eq!(budget_effective_week_starts_on(&spec), "monday");
        assert_eq!(budget_effective_month_anchor_day(&spec), 1);
        assert_eq!(
            budget_effective_billing_categories(&spec),
            vec!["gateway_llm".to_string()]
        );

        spec.team = Some("finance".to_string());
        assert_eq!(budget_scope_identity(&spec), "team/finance");
        spec.team = None;
        spec.user = Some("alice@example.com".to_string());
        assert_eq!(budget_scope_identity(&spec), "user/alice@example.com");
        spec.user = None;
        spec.agent = Some("triage-bot".to_string());
        assert_eq!(budget_scope_identity(&spec), "agent/triage-bot");
    }

    #[test]
    fn same_decimal_value_handles_numeric_and_string_fallbacks() {
        assert!(same_decimal_value("10.0", "10.00"));
        assert!(same_decimal_value(" region-eu ", "region-eu"));
        assert!(!same_decimal_value("10.0", "11.0"));
        assert_eq!(parse_decimal("not-a-decimal"), None);
    }

    #[test]
    fn budget_needs_update_accepts_equivalent_defaults() {
        let spec = sample_budget_spec();
        let remote = sample_remote_budget();

        assert!(!budget_needs_update(
            &spec,
            &remote,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        ));
    }

    #[test]
    fn budget_needs_update_detects_scope_and_remote_limit_drift() {
        let mut spec = sample_budget_spec();
        spec.team = Some("finance".to_string());
        spec.hard_limit_enabled = Some(true);
        spec.hard_limit_amount = Some("20.00".to_string());

        let mut remote = sample_remote_budget();
        remote.hard_limit_enabled = true;
        remote.hard_limit_amount = Some("20.0".to_string());
        remote.team_id = Some("team-1".to_string());

        let empty_map = HashMap::new();
        assert!(budget_needs_update(
            &spec,
            &remote,
            &empty_map,
            &HashMap::new(),
            &HashMap::new(),
        ));

        let team_map = HashMap::from([("finance".to_string(), "team-1".to_string())]);
        assert!(!budget_needs_update(
            &spec,
            &remote,
            &team_map,
            &HashMap::new(),
            &HashMap::new(),
        ));

        remote.billing_categories = vec!["agents".to_string()];
        assert!(budget_needs_update(
            &spec,
            &remote,
            &team_map,
            &HashMap::new(),
            &HashMap::new(),
        ));
    }

    #[test]
    fn budget_needs_update_detects_scope_resolution_and_orphaned_limit_drift() {
        let mut spec = sample_budget_spec();
        spec.user = Some("alice@example.com".to_string());

        let mut remote = sample_remote_budget();
        remote.user_id = Some("user-1".to_string());

        assert!(budget_needs_update(
            &spec,
            &remote,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        ));

        let user_map = HashMap::from([("alice@example.com".to_string(), "user-1".to_string())]);
        assert!(!budget_needs_update(
            &spec,
            &remote,
            &HashMap::new(),
            &user_map,
            &HashMap::new(),
        ));

        remote.hard_limit_amount = Some("25.00".to_string());
        assert!(budget_needs_update(
            &spec,
            &remote,
            &HashMap::new(),
            &user_map,
            &HashMap::new(),
        ));
    }

    #[test]
    fn budget_needs_update_detects_agent_scope_map_drift() {
        let mut spec = sample_budget_spec();
        spec.agent = Some("triage-bot".to_string());

        let mut remote = sample_remote_budget();
        remote.agent_id = Some("agent-1".to_string());

        assert!(budget_needs_update(
            &spec,
            &remote,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        ));

        let agent_map = HashMap::from([("triage-bot".to_string(), "agent-1".to_string())]);
        assert!(!budget_needs_update(
            &spec,
            &remote,
            &HashMap::new(),
            &HashMap::new(),
            &agent_map,
        ));
    }

    #[test]
    fn build_budget_body_uses_defaults_and_scope_ids() {
        let spec = sample_budget_spec();
        let scope_ids = ResolvedBudgetScopeIds {
            team_id: Some("team-1".to_string()),
            user_id: None,
            agent_id: Some("agent-1".to_string()),
        };

        let body = build_budget_body(&spec, &scope_ids);
        assert_eq!(body["currency"], serde_json::json!("USD"));
        assert_eq!(body["period_type"], serde_json::json!("monthly"));
        assert_eq!(body["team_id"], serde_json::json!("team-1"));
        assert_eq!(body["agent_id"], serde_json::json!("agent-1"));
        assert_eq!(
            body["billing_categories"],
            serde_json::json!(["gateway_llm"])
        );
    }

    #[test]
    fn build_budget_body_preserves_custom_values_and_null_scope_fields() {
        let mut spec = sample_budget_spec();
        spec.currency = Some("EUR".to_string());
        spec.period_type = Some("weekly".to_string());
        spec.alert_thresholds = vec![40, 80];
        spec.hard_limit_enabled = Some(true);
        spec.hard_limit_amount = Some("9.50".to_string());
        spec.timezone = Some("Europe/Madrid".to_string());
        spec.week_starts_on = Some("sunday".to_string());
        spec.month_anchor_day = Some(14);
        spec.billing_categories = vec!["agents".to_string()];

        let body = build_budget_body(
            &spec,
            &ResolvedBudgetScopeIds {
                team_id: None,
                user_id: Some("user-1".to_string()),
                agent_id: None,
            },
        );

        assert_eq!(body["currency"], serde_json::json!("EUR"));
        assert_eq!(body["period_type"], serde_json::json!("weekly"));
        assert_eq!(body["alert_thresholds"], serde_json::json!([40, 80]));
        assert_eq!(body["hard_limit_enabled"], serde_json::json!(true));
        assert_eq!(body["hard_limit_amount"], serde_json::json!("9.50"));
        assert_eq!(body["user_id"], serde_json::json!("user-1"));
        assert!(body["team_id"].is_null());
        assert!(body["agent_id"].is_null());
        assert_eq!(body["timezone"], serde_json::json!("Europe/Madrid"));
        assert_eq!(body["week_starts_on"], serde_json::json!("sunday"));
        assert_eq!(body["month_anchor_day"], serde_json::json!(14));
        assert_eq!(body["billing_categories"], serde_json::json!(["agents"]));
    }

    #[test]
    fn prompt_suite_and_bundle_update_helpers_detect_drift() {
        let spec = sample_prompt_suite_spec();
        let remote_suite = sample_remote_prompt_suite();
        assert!(!prompt_evaluation_suite_needs_update(&spec, &remote_suite));

        let renamed_remote = RemotePromptEvaluationSuite {
            name: "nightly-dev".to_string(),
            ..remote_suite.clone()
        };
        assert!(prompt_evaluation_suite_needs_update(&spec, &renamed_remote));

        let description_remote = RemotePromptEvaluationSuite {
            description: Some("Nightly prod checks".to_string()),
            ..remote_suite.clone()
        };
        assert!(prompt_evaluation_suite_needs_update(
            &spec,
            &description_remote
        ));

        let enabled_remote = RemotePromptEvaluationSuite {
            enabled: Some(false),
            ..remote_suite.clone()
        };
        assert!(prompt_evaluation_suite_needs_update(&spec, &enabled_remote));

        let bundle_spec = sample_provider_bundle_spec();
        let remote_bundle = sample_remote_provider_bundle();
        assert_eq!(platform_provider_bundle_status(&bundle_spec), "active");
        assert!(!platform_provider_bundle_needs_update(
            &bundle_spec,
            &remote_bundle
        ));
        let registry_remote = RemotePlatformProviderBundle {
            provider_registry: serde_json::json!({"targets": ["gpt-5.5"]}),
            ..remote_bundle.clone()
        };
        assert!(platform_provider_bundle_needs_update(
            &bundle_spec,
            &registry_remote
        ));
        let changed_remote = RemotePlatformProviderBundle {
            status: "archived".to_string(),
            ..remote_bundle
        };
        assert!(platform_provider_bundle_needs_update(
            &bundle_spec,
            &changed_remote
        ));
    }

    #[test]
    fn prompt_suite_lookup_and_resource_name_helpers_cover_fallback_paths() {
        let named_only = vec![RemotePromptEvaluationSuite {
            id: "suite-2".to_string(),
            name: "nightly".to_string(),
            description: None,
            enabled: None,
        }];
        let resource_only = vec![sample_remote_prompt_suite()];

        let spec = sample_prompt_suite_spec();
        assert_eq!(prompt_evaluation_suite_resource_name(&spec), "nightly-prod");
        assert_eq!(
            find_remote_prompt_evaluation_suite(&named_only, &spec)
                .unwrap()
                .id,
            "suite-2"
        );
        assert_eq!(
            find_remote_prompt_evaluation_suite(&resource_only, &spec)
                .unwrap()
                .id,
            "suite-1"
        );

        let fallback_spec = PromptEvaluationSuiteSpec {
            resource_name: None,
            ..sample_prompt_suite_spec()
        };
        assert_eq!(
            prompt_evaluation_suite_resource_name(&fallback_spec),
            "nightly"
        );
        assert!(find_remote_prompt_evaluation_suite(&[], &fallback_spec).is_none());
    }

    #[test]
    fn singleton_and_policy_body_builders_include_only_populated_fields() {
        let regulated_body =
            build_regulated_execution_profile_body(&sample_regulated_execution_profile_spec());
        assert_eq!(regulated_body["name"], serde_json::json!("regulated"));
        assert_eq!(
            regulated_body["deployment_profile"],
            serde_json::json!("regulated_saas")
        );
        assert_eq!(regulated_body["default"], serde_json::json!(true));
        assert_eq!(
            regulated_body["residency_region"],
            serde_json::json!("eu-west-1")
        );
        assert!(regulated_body.get("data_residency_tag").is_none());
        assert_eq!(
            regulated_body["cross_border_policy"],
            serde_json::json!("deny_by_default")
        );
        assert_eq!(
            regulated_body["tokenization_enabled"],
            serde_json::json!(true)
        );
        assert_eq!(
            regulated_body["require_in_memory_only"],
            serde_json::json!(true)
        );
        assert_eq!(
            regulated_body["allow_internet_egress"],
            serde_json::json!(false)
        );
        assert_eq!(
            regulated_body["workload_class"],
            serde_json::json!("regulated")
        );
        assert_eq!(
            regulated_body["deletion_attestation_enabled"],
            serde_json::json!(true)
        );
        assert_eq!(
            regulated_body["fail_mode"],
            serde_json::json!("fail_closed")
        );

        let approval_body = build_approval_policy_body(&sample_approval_policy_spec());
        assert_eq!(approval_body["name"], serde_json::json!("dual"));
        assert_eq!(
            approval_body["description"],
            serde_json::json!("Dual approval policy")
        );
        assert_eq!(approval_body["enabled"], serde_json::json!(true));
        assert_eq!(approval_body["simulation_mode"], serde_json::json!(false));
        assert_eq!(
            approval_body["break_glass_enabled"],
            serde_json::json!(true)
        );
        assert_eq!(
            approval_body["break_glass_post_review_required"],
            serde_json::json!(true)
        );
        assert_eq!(
            approval_body["thresholds"],
            serde_json::json!([{
                "risk_level": "high",
                "data_class": "phi",
                "destination_pattern": "s3://exports/*",
                "approval_mode": "dual",
                "required_approvals": 2,
                "decision_ttl_minutes": 30,
            }])
        );
        assert_eq!(
            approval_body["approver_chains"],
            serde_json::json!([{
                "name": "security",
                "mode": "delegated_chain",
                "approvers": ["alice", "bob"],
                "backup_approvers": ["charlie"],
                "escalation_after_minutes": 15,
            }])
        );

        let collaboration_body =
            build_collaboration_defaults_body(&sample_collaboration_defaults_spec());
        assert_eq!(
            collaboration_body["default_conversation_visibility"],
            serde_json::json!("team")
        );
        assert_eq!(
            collaboration_body["default_task_visibility"],
            serde_json::json!("owner_only")
        );
        assert_eq!(
            collaboration_body["allow_user_sharing"],
            serde_json::json!(true)
        );
        assert_eq!(
            collaboration_body["allow_team_sharing"],
            serde_json::json!(false)
        );
        assert_eq!(
            collaboration_body["audit_membership_changes"],
            serde_json::json!(true)
        );
        assert_eq!(
            build_collaboration_defaults_body(&CollaborationDefaultsSpec::default()),
            serde_json::json!({})
        );

        let hosted_gateway_body =
            build_hosted_gateway_policy_body(&sample_hosted_gateway_policy_spec());
        assert_eq!(
            hosted_gateway_body["default_agent"],
            serde_json::json!("nightly-bot")
        );
        assert_eq!(
            hosted_gateway_body["default_agent_fallback_enabled"],
            serde_json::json!(true)
        );
        assert_eq!(
            hosted_gateway_body["fail_closed_on_missing_binding"],
            serde_json::json!(false)
        );
        assert_eq!(
            build_hosted_gateway_policy_body(&HostedGatewayPolicySpec::default()),
            serde_json::json!({})
        );

        let auth_org_body = build_auth_org_policy_body(&sample_auth_org_policy_spec());
        assert_eq!(
            auth_org_body["verified_domains"],
            serde_json::json!(["verdictan.com"])
        );
        assert_eq!(auth_org_body["required_sso"], serde_json::json!(true));
        assert_eq!(
            auth_org_body["local_auth_allowed"],
            serde_json::json!(false)
        );
        assert_eq!(
            auth_org_body["jit_provisioning_enabled"],
            serde_json::json!(true)
        );
        assert_eq!(auth_org_body["invite_only"], serde_json::json!(false));
        assert_eq!(
            auth_org_body["popup_return_origins"],
            serde_json::json!(["https://console.verdictan.com"])
        );
        assert_eq!(
            build_auth_org_policy_body(&AuthOrgPolicySpec::default()),
            serde_json::json!({})
        );
    }

    #[test]
    fn spec_finders_and_small_helpers_cover_success_and_error_paths() {
        let manifest = lookup_manifest();

        assert_eq!(
            find_secret_spec(&manifest, "openai-key").unwrap().env,
            "VERDICTAN_OPENAI_API_KEY"
        );
        assert_eq!(
            find_platform_provider_bundle_spec(&manifest, "shared-openai")
                .unwrap()
                .bundle_key,
            "shared-openai"
        );
        assert_eq!(
            find_regulated_execution_profile_spec(&manifest, "regulated")
                .unwrap()
                .deployment_profile,
            "regulated_saas"
        );
        assert_eq!(
            find_approval_policy_spec(&manifest, "dual").unwrap().name,
            "dual"
        );
        assert_eq!(
            find_prompt_evaluation_suite_spec(&manifest, "nightly")
                .unwrap()
                .resource_name
                .as_deref(),
            Some("nightly-prod")
        );
        assert_eq!(
            find_budget_spec(&manifest, "monthly-budget")
                .unwrap()
                .amount,
            "10.00"
        );
        assert_eq!(
            find_hosted_gateway_binding_spec(&manifest, "gw-prod")
                .unwrap()
                .agent,
            "nightly-bot"
        );

        assert!(find_secret_spec(&manifest, "missing").is_err());
        assert!(find_platform_provider_bundle_spec(&manifest, "missing").is_err());
        assert!(find_budget_spec(&manifest, "missing").is_err());
    }

    #[test]
    fn build_resource_tags_lookup_and_id_helpers_cover_optional_fields() {
        assert_eq!(build_resource_tags_value(&[]), serde_json::json!([]));

        let tags = build_resource_tags_value(&[
            ResourceTagSpec {
                key: "env".to_string(),
                value: "prod".to_string(),
                source: None,
            },
            ResourceTagSpec {
                key: "owner".to_string(),
                value: "platform".to_string(),
                source: Some("system".to_string()),
            },
        ]);
        let items = tags.as_array().unwrap();
        assert!(items[0].get("source").is_none());
        assert_eq!(items[1]["source"], serde_json::json!("system"));

        let list = vec![
            ("shared-openai".to_string(), "bundle-1".to_string()),
            ("shared-anthropic".to_string(), "bundle-2".to_string()),
        ];
        assert_eq!(
            find_by_name(&list, "shared-openai"),
            Some("bundle-1".to_string())
        );
        assert_eq!(
            find_by_key(&list, "shared-anthropic"),
            Some("bundle-2".to_string())
        );
        assert_eq!(find_by_key(&list, "missing"), None);

        let inverted = invert_pairs(vec![
            ("finance".to_string(), "team-1".to_string()),
            ("finance".to_string(), "team-2".to_string()),
            ("ops".to_string(), "team-3".to_string()),
        ]);
        assert_eq!(inverted.get("finance"), Some(&"team-2".to_string()));
        assert_eq!(inverted.get("ops"), Some(&"team-3".to_string()));

        let op = ReconcileOp {
            resource_type: "secret".to_string(),
            name: "delete-me".to_string(),
            action: ReconcileAction::Delete,
            remote_id: Some("secret-1".to_string()),
            detail: None,
        };
        assert_eq!(require_remote_id(&op).unwrap(), "secret-1");
        assert!(require_remote_id(&ReconcileOp {
            remote_id: None,
            ..op
        })
        .is_err());

        assert_eq!(
            extract_id(&serde_json::json!({"id": "plain-id"})),
            "plain-id"
        );
        assert_eq!(
            extract_id(&serde_json::json!({"policy_id": "policy-1"})),
            "policy-1"
        );
        assert_eq!(
            extract_id(&serde_json::json!({"role_id": "role-1"})),
            "role-1"
        );
        assert_eq!(extract_id(&serde_json::json!({"status": "ok"})), "");
    }

    #[test]
    fn split2_handles_edge_cases_and_multibyte_separator() {
        assert_eq!(split2("missing", ':'), None);
        assert_eq!(split2(":leading", ':'), Some(("", "leading")));
        assert_eq!(split2("trailing:", ':'), Some(("trailing", "")));
        assert_eq!(split2("a:b:c", ':'), Some(("a", "b:c")));

        let (left, right) = split2("ops•incident", '•').unwrap();
        assert_eq!(left, "ops");
        assert_eq!(right, "incident");
    }

    #[tokio::test]
    async fn fetch_json_value_with_retry_covers_success_404_auth_and_permanent_failures() {
        let (client, state, handle) = spawn_mock_api(vec![
            (
                "/ok".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({"ok": true}),
                )],
            ),
            (
                "/missing".to_string(),
                vec![mock_response(
                    StatusCode::NOT_FOUND,
                    serde_json::json!({"error": "missing"}),
                )],
            ),
            (
                "/auth".to_string(),
                vec![mock_response(
                    StatusCode::UNAUTHORIZED,
                    serde_json::json!({"error": "unauthorized"}),
                )],
            ),
            (
                "/boom".to_string(),
                vec![mock_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::json!({"error": "boom"}),
                )],
            ),
        ])
        .await;

        assert_eq!(
            fetch_json_value_with_retry(&client, "/ok").await.unwrap(),
            Some(serde_json::json!({"ok": true}))
        );
        assert_eq!(
            fetch_json_value_with_retry(&client, "/missing")
                .await
                .unwrap(),
            None
        );

        let auth_err = fetch_json_value_with_retry(&client, "/auth")
            .await
            .expect_err("auth failure");
        assert!(auth_err.is_auth());
        assert_eq!(auth_err.http_status, Some(401));

        let network_err = fetch_json_value_with_retry(&client, "/boom")
            .await
            .expect_err("network failure");
        assert_eq!(network_err.error_code(), "cli.network_error");
        assert_eq!(network_err.http_status, Some(500));

        assert_eq!(state.request_count("/ok"), 1);
        assert_eq!(state.request_count("/missing"), 1);
        assert_eq!(state.request_count("/auth"), 1);
        assert_eq!(state.request_count("/boom"), 1);

        handle.abort();
    }

    #[tokio::test]
    async fn fetch_json_value_with_retry_retries_transient_errors_until_success() {
        let (client, state, handle) = spawn_mock_api(vec![(
            "/retry".to_string(),
            vec![
                mock_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({"error": "warming up"}),
                ),
                mock_response(
                    StatusCode::BAD_GATEWAY,
                    serde_json::json!({"error": "upstream restart"}),
                ),
                mock_response(StatusCode::OK, serde_json::json!({"ready": true})),
            ],
        )])
        .await;

        assert_eq!(
            fetch_json_value_with_retry_using_backoff(&client, "/retry", &[0, 0, 0])
                .await
                .unwrap(),
            Some(serde_json::json!({"ready": true}))
        );
        assert_eq!(state.request_count("/retry"), 3);

        handle.abort();
    }

    #[tokio::test]
    async fn fetch_json_value_with_retry_reports_crash_loop_after_transient_exhaustion() {
        let (client, state, handle) = spawn_mock_api(vec![(
            "/crash-loop".to_string(),
            vec![
                mock_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({"error": "booting"}),
                ),
                mock_response(
                    StatusCode::BAD_GATEWAY,
                    serde_json::json!({"error": "proxy mismatch"}),
                ),
                mock_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({"error": "still booting"}),
                ),
            ],
        )])
        .await;

        let err = fetch_json_value_with_retry_using_backoff(&client, "/crash-loop", &[0, 0, 0])
            .await
            .expect_err("retry exhaustion");
        assert_eq!(err.error_code(), "cli.network_error");
        assert!(err.to_string().contains("API returned 503 after 3 retries"));
        assert_eq!(state.request_count("/crash-loop"), 3);

        handle.abort();
    }

    #[tokio::test]
    async fn remote_fetch_helpers_apply_defaults_and_skip_incomplete_items() {
        let (client, _state, handle) = spawn_mock_api(vec![
            (
                "/named".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "items": [
                            {"name": "secret-a", "id": "id-1"},
                            {"name": "policy-a", "policy_id": "policy-1"},
                            {"name": "role-a", "role_id": "role-1"},
                            {"name": "team-a", "team_id": "team-1"},
                            {"name": "agent-a", "agent_id": "agent-1"},
                            {"id": "missing-name"},
                            {"name": "missing-id"}
                        ]
                    }),
                )],
            ),
            (
                "/v1/users".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "users": [
                            {"email": "alice@example.com", "user_id": "user-1"},
                            {"id": "missing-email"}
                        ]
                    }),
                )],
            ),
            (
                "/v1/usage/budgets".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "budgets": [
                            {"id": "budget-1", "name": "ops", "amount": "25.00"},
                            {"name": "missing-id", "amount": "10.00"},
                            {"id": "missing-amount", "name": "bad"}
                        ]
                    }),
                )],
            ),
            (
                "/v1/prompt-suites".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "items": [
                            {
                                "suite_id": "suite-1",
                                "name": "nightly",
                                "description": "Nightly checks",
                                "enabled": true
                            },
                            {
                                "id": "suite-2",
                                "description": "missing name"
                            }
                        ]
                    }),
                )],
            ),
            (
                "/v1/admin/platform-provider-bundles?include_archived=true".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "bundles": [
                            {
                                "bundle_key": "shared-openai",
                                "provider_registry": {"targets": ["gpt-5.4"]},
                                "status": "active"
                            },
                            {
                                "bundle_key": "missing-status",
                                "provider_registry": {}
                            }
                        ]
                    }),
                )],
            ),
        ])
        .await;

        assert_eq!(
            fetch_remote_list(&client, "/named", "items").await.unwrap(),
            vec![
                ("secret-a".to_string(), "id-1".to_string()),
                ("policy-a".to_string(), "policy-1".to_string()),
                ("role-a".to_string(), "role-1".to_string()),
                ("team-a".to_string(), "team-1".to_string()),
                ("agent-a".to_string(), "agent-1".to_string()),
            ]
        );
        assert_eq!(
            fetch_remote_list_by_email(&client, "/v1/users")
                .await
                .unwrap(),
            vec![("alice@example.com".to_string(), "user-1".to_string())]
        );

        let budgets = fetch_remote_budgets(&client).await.unwrap();
        assert_eq!(budgets.len(), 1);
        assert_eq!(budgets[0].id, "budget-1");
        assert_eq!(budgets[0].currency, "USD");
        assert_eq!(budgets[0].period_type, "monthly");
        assert_eq!(budgets[0].alert_thresholds, vec![50, 75, 90]);
        assert!(!budgets[0].hard_limit_enabled);
        assert_eq!(budgets[0].timezone, "UTC");
        assert_eq!(budgets[0].week_starts_on, "monday");
        assert_eq!(budgets[0].month_anchor_day, 1);
        assert_eq!(
            budgets[0].billing_categories,
            vec!["gateway_llm".to_string()]
        );

        let suites = fetch_remote_prompt_evaluation_suites(&client)
            .await
            .unwrap();
        assert_eq!(suites.len(), 1);
        assert_eq!(suites[0].id, "suite-1");
        assert_eq!(suites[0].name, "nightly");
        assert_eq!(suites[0].description.as_deref(), Some("Nightly checks"));
        assert_eq!(suites[0].enabled, Some(true));

        let bundles = fetch_remote_platform_provider_bundles(&client)
            .await
            .unwrap();
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0].bundle_key, "shared-openai");
        assert_eq!(bundles[0].status, "active");

        handle.abort();
    }

    #[tokio::test]
    async fn resolve_budget_scope_ids_resolves_known_resources_and_surfaces_missing_scopes() {
        let (client, _state, handle) = spawn_mock_api(vec![
            (
                "/v1/teams".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({"teams": [{"name": "finance", "team_id": "team-1"}]}),
                )],
            ),
            (
                "/v1/users".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({"users": [{"email": "alice@example.com", "id": "user-1"}]}),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({"agents": [{"name": "triage-bot", "agent_id": "agent-1"}]}),
                )],
            ),
        ])
        .await;

        let mut scoped_spec = sample_budget_spec();
        scoped_spec.team = Some("finance".to_string());
        scoped_spec.user = Some("alice@example.com".to_string());
        scoped_spec.agent = Some("triage-bot".to_string());

        let resolved = resolve_budget_scope_ids(&client, &scoped_spec)
            .await
            .unwrap();
        assert_eq!(resolved.team_id.as_deref(), Some("team-1"));
        assert_eq!(resolved.user_id.as_deref(), Some("user-1"));
        assert_eq!(resolved.agent_id.as_deref(), Some("agent-1"));

        handle.abort();

        let (client, _state, handle) = spawn_mock_api(vec![(
            "/v1/teams".to_string(),
            vec![mock_response(
                StatusCode::OK,
                serde_json::json!({"teams": []}),
            )],
        )])
        .await;

        let mut missing_team = sample_budget_spec();
        missing_team.team = Some("finance".to_string());

        let err = resolve_budget_scope_ids(&client, &missing_team)
            .await
            .expect_err("missing team");
        assert_eq!(err.error_code(), "cli.config_invalid");
        assert!(err.to_string().contains("team \"finance\" not found"));

        handle.abort();
    }

    #[tokio::test]
    async fn plan_hosted_gateway_bindings_marks_missing_agents_in_detail() {
        let (client, _state, handle) = spawn_mock_api(vec![(
            "/v1/agents".to_string(),
            vec![mock_response(
                StatusCode::OK,
                serde_json::json!({"agents": [{"name": "nightly-bot", "id": "agent-1"}]}),
            )],
        )])
        .await;

        let desired = vec![
            HostedGatewayBindingSpec {
                gateway_id: "gw-eu".to_string(),
                agent: "nightly-bot".to_string(),
            },
            HostedGatewayBindingSpec {
                gateway_id: "gw-us".to_string(),
                agent: "missing-bot".to_string(),
            },
        ];
        let mut plan = ReconcilePlan::default();

        plan_hosted_gateway_bindings(&client, &desired, &mut plan)
            .await
            .unwrap();

        assert_eq!(plan.ops.len(), 2);
        assert_eq!(plan.ops[0].action, ReconcileAction::Update);
        assert_eq!(plan.ops[0].detail.as_deref(), Some("agent=nightly-bot"));
        assert_eq!(plan.ops[1].action, ReconcileAction::Update);
        assert_eq!(
            plan.ops[1].detail.as_deref(),
            Some("agent=missing-bot (not yet resolved — will retry at apply)")
        );

        handle.abort();
    }

    #[tokio::test]
    async fn plan_prompt_suites_and_platform_bundles_cover_prune_and_update_behavior() {
        let (client, _state, handle) = spawn_mock_api(vec![
            (
                "/v1/prompt-suites".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "items": [
                            {
                                "id": "suite-1",
                                "name": "nightly-prod",
                                "description": "Nightly checks",
                                "enabled": true
                            },
                            {
                                "id": "suite-2",
                                "name": "orphan-suite",
                                "description": null,
                                "enabled": null
                            }
                        ]
                    }),
                )],
            ),
            (
                "/v1/admin/platform-provider-bundles?include_archived=true".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "bundles": [
                            {
                                "bundle_key": "shared-openai",
                                "provider_registry": {"targets": ["gpt-5.4"]},
                                "status": "archived"
                            },
                            {
                                "bundle_key": "extra-active",
                                "provider_registry": {"targets": ["gpt-4.1"]},
                                "status": "active"
                            },
                            {
                                "bundle_key": "extra-archived",
                                "provider_registry": {"targets": ["gpt-4o"]},
                                "status": "archived"
                            }
                        ]
                    }),
                )],
            ),
        ])
        .await;

        let mut prompt_plan = ReconcilePlan::default();
        plan_prompt_evaluation_suites(
            &client,
            &[sample_prompt_suite_spec()],
            true,
            &mut prompt_plan,
        )
        .await
        .unwrap();

        assert_eq!(prompt_plan.ops.len(), 2);
        assert_eq!(prompt_plan.ops[0].action, ReconcileAction::NoOp);
        assert_eq!(prompt_plan.ops[0].remote_id.as_deref(), Some("suite-1"));
        assert_eq!(prompt_plan.ops[0].detail.as_deref(), Some("nightly-prod"));
        assert_eq!(prompt_plan.ops[1].action, ReconcileAction::Delete);
        assert_eq!(prompt_plan.ops[1].name, "orphan-suite");
        assert_eq!(prompt_plan.ops[1].remote_id.as_deref(), Some("suite-2"));

        let mut bundle_plan = ReconcilePlan::default();
        plan_platform_provider_bundles(
            &client,
            &[sample_provider_bundle_spec()],
            true,
            &mut bundle_plan,
        )
        .await
        .unwrap();

        assert_eq!(bundle_plan.ops.len(), 2);
        assert_eq!(bundle_plan.ops[0].action, ReconcileAction::Update);
        assert_eq!(bundle_plan.ops[0].name, "shared-openai");
        assert_eq!(bundle_plan.ops[0].detail.as_deref(), Some("status=active"));
        assert_eq!(bundle_plan.ops[1].action, ReconcileAction::Delete);
        assert_eq!(bundle_plan.ops[1].name, "extra-active");
        assert_eq!(bundle_plan.ops[1].detail.as_deref(), Some("archive"));

        handle.abort();
    }

    #[tokio::test]
    async fn compute_plan_orders_sections_and_classifies_core_reconcile_actions() {
        let mut drift_budget = sample_budget_spec();
        drift_budget.name = "team-drift".to_string();
        drift_budget.amount = "15.00".to_string();
        drift_budget.team = Some("platform".to_string());

        let mut new_budget = sample_budget_spec();
        new_budget.name = "new-budget".to_string();
        new_budget.amount = "5.00".to_string();
        new_budget.user = Some("bob@example.com".to_string());

        let manifest = ControlManifest {
            version: "1".to_string(),
            resources: Resources {
                secrets: vec![
                    SecretSpec {
                        name: "openai-key".to_string(),
                        env: "VERDICTAN_CONTROL_RECONCILE_EXISTING_SECRET".to_string(),
                        description: Some("primary".to_string()),
                    },
                    SecretSpec {
                        name: "anthropic-key".to_string(),
                        env: "VERDICTAN_CONTROL_RECONCILE_NEW_SECRET".to_string(),
                        description: None,
                    },
                ],
                iam: Some(IamSpec {
                    policies: vec![
                        IamPolicySpec {
                            name: "existing-policy".to_string(),
                            description: None,
                            statements: None,
                        },
                        IamPolicySpec {
                            name: "new-policy".to_string(),
                            description: Some("created".to_string()),
                            statements: None,
                        },
                    ],
                    roles: vec![
                        IamRoleSpec {
                            name: "existing-role".to_string(),
                            policies: vec![],
                        },
                        IamRoleSpec {
                            name: "new-role".to_string(),
                            policies: vec!["existing-policy".to_string()],
                        },
                    ],
                }),
                teams: vec![
                    TeamSpec {
                        name: "platform".to_string(),
                        description: Some("Platform".to_string()),
                        members: vec![TeamMemberSpec {
                            email: "alice@example.com".to_string(),
                            roles: vec!["owner".to_string()],
                        }],
                    },
                    TeamSpec {
                        name: "finance".to_string(),
                        description: None,
                        members: vec![],
                    },
                ],
                users: vec![
                    UserSpec {
                        email: "alice@example.com".to_string(),
                        teams: vec![],
                        roles: vec![],
                    },
                    UserSpec {
                        email: "bob@example.com".to_string(),
                        teams: vec![],
                        roles: vec![],
                    },
                ],
                platform_provider_bundles: vec![sample_provider_bundle_spec()],
                agents: vec![sample_agent_spec()],
                budgets: vec![sample_budget_spec(), drift_budget, new_budget],
                regulated_execution_profiles: vec![sample_regulated_execution_profile_spec()],
                approval_policies: vec![sample_approval_policy_spec()],
                prompt_evaluation_suites: vec![sample_prompt_suite_spec()],
                collaboration_defaults: Some(sample_collaboration_defaults_spec()),
                hosted_gateway_policy: Some(sample_hosted_gateway_policy_spec()),
                hosted_gateway_bindings: vec![HostedGatewayBindingSpec {
                    gateway_id: "gw-prod".to_string(),
                    agent: "nightly-bot".to_string(),
                }],
                auth_org_policy: Some(sample_auth_org_policy_spec()),
            },
        };

        let (client, _state, handle) = spawn_mock_api(vec![
            (
                "/v1/secrets".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "secrets": [
                            {"name": "openai-key", "id": "secret-1"},
                            {"name": "orphan-secret", "id": "secret-2"}
                        ]
                    }),
                )],
            ),
            (
                "/v1/policies".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "policies": [
                            {"name": "existing-policy", "policy_id": "policy-1"},
                            {"name": "orphan-policy", "policy_id": "policy-2"}
                        ]
                    }),
                )],
            ),
            (
                "/v1/roles".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "roles": [
                            {"name": "existing-role", "role_id": "role-1"},
                            {"name": "orphan-role", "role_id": "role-2"}
                        ]
                    }),
                )],
            ),
            (
                "/v1/teams".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "teams": [
                            {"name": "platform", "team_id": "team-1"},
                            {"name": "orphan-team", "team_id": "team-2"}
                        ]
                    }),
                )],
            ),
            (
                "/v1/users".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "users": [
                            {"email": "alice@example.com", "user_id": "user-1"},
                            {"email": "orphan@example.com", "user_id": "user-2"}
                        ]
                    }),
                )],
            ),
            (
                "/v1/admin/platform-provider-bundles?include_archived=true".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "bundles": [
                            {
                                "bundle_key": "shared-openai",
                                "provider_registry": {"targets": ["gpt-5.4"]},
                                "status": "archived"
                            },
                            {
                                "bundle_key": "orphan-active",
                                "provider_registry": {"targets": ["gpt-4.1"]},
                                "status": "active"
                            }
                        ]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [
                            {"name": "nightly-bot", "agent_id": "agent-1"},
                            {"name": "orphan-bot", "agent_id": "agent-2"}
                        ]
                    }),
                )],
            ),
            (
                "/v1/usage/budgets".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "budgets": [
                            {"id": "budget-1", "name": "monthly-budget", "amount": "10.0"},
                            {
                                "id": "budget-2",
                                "name": "team-drift",
                                "amount": "12.00",
                                "team_id": "team-1"
                            },
                            {
                                "id": "budget-3",
                                "name": "orphan-budget",
                                "amount": "9.00",
                                "period_type": "weekly",
                                "agent_id": "agent-1"
                            }
                        ]
                    }),
                )],
            ),
            (
                "/v1/settings/regulated-execution-profiles".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "profiles": [
                            {"name": "regulated", "id": "profile-1"},
                            {"name": "orphan-profile", "id": "profile-2"}
                        ]
                    }),
                )],
            ),
            (
                "/v1/approval-policies".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "policies": [
                            {"name": "dual", "id": "approval-1"},
                            {"name": "orphan-approval", "id": "approval-2"}
                        ]
                    }),
                )],
            ),
            (
                "/v1/prompt-suites".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "items": [
                            {
                                "id": "suite-1",
                                "name": "nightly-prod",
                                "description": "Nightly checks",
                                "enabled": true
                            },
                            {
                                "id": "suite-2",
                                "name": "orphan-suite",
                                "description": null,
                                "enabled": null
                            }
                        ]
                    }),
                )],
            ),
            (
                "/v1/settings/collaboration".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({"ok": true}),
                )],
            ),
            (
                "/v1/settings/hosted-gateway-policy".to_string(),
                vec![mock_response(
                    StatusCode::NOT_FOUND,
                    serde_json::json!({"error": "missing"}),
                )],
            ),
            (
                "/v1/settings/auth-org-policy".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({"ok": true}),
                )],
            ),
        ])
        .await;

        let plan = compute_plan(&client, &manifest, true).await.unwrap();

        assert_eq!(plan.creates(), 10);
        assert_eq!(plan.updates(), 9);
        assert_eq!(plan.deletions(), 11);
        assert_eq!(plan.no_ops(), 7);
        assert!(plan.has_changes());
        assert_eq!(
            plan_summaries(&plan),
            vec![
                "secret:openai-key:update".to_string(),
                "secret:anthropic-key:create".to_string(),
                "secret:orphan-secret:delete".to_string(),
                "iam.policy:existing-policy:no-op".to_string(),
                "iam.policy:new-policy:create".to_string(),
                "iam.policy:orphan-policy:delete".to_string(),
                "iam.role:existing-role:no-op".to_string(),
                "iam.role:new-role:create".to_string(),
                "iam.role:orphan-role:delete".to_string(),
                "team:platform:no-op".to_string(),
                "team.member:platform/alice@example.com:create".to_string(),
                "team:finance:create".to_string(),
                "team:orphan-team:delete".to_string(),
                "user:alice@example.com:no-op".to_string(),
                "user:bob@example.com:create".to_string(),
                "user:orphan@example.com:delete".to_string(),
                "platform_provider_bundle:shared-openai:update".to_string(),
                "platform_provider_bundle:orphan-active:delete".to_string(),
                "agent:nightly-bot:no-op".to_string(),
                "agent.deployment:nightly-bot:update".to_string(),
                "agent.gateway_link:nightly-bot/gw-eu:create".to_string(),
                "agent.gateway_link:nightly-bot/gw-us:create".to_string(),
                "agent:orphan-bot:delete".to_string(),
                "billing_budget:monthly-budget:no-op".to_string(),
                "billing_budget:team-drift:update".to_string(),
                "billing_budget:new-budget:create".to_string(),
                "billing_budget:orphan-budget:delete".to_string(),
                "regulated_execution_profile:regulated:update".to_string(),
                "regulated_execution_profile:orphan-profile:delete".to_string(),
                "approval_policy:dual:update".to_string(),
                "approval_policy:orphan-approval:delete".to_string(),
                "prompt_evaluation_suite:nightly:no-op".to_string(),
                "prompt_evaluation_suite:orphan-suite:delete".to_string(),
                "collaboration_defaults:org:update".to_string(),
                "hosted_gateway_policy:org:create".to_string(),
                "hosted_gateway_binding:gw-prod:update".to_string(),
                "auth_org_policy:org:update".to_string(),
            ]
        );

        handle.abort();
    }

    #[tokio::test]
    async fn compute_plan_with_prune_disabled_skips_all_remote_only_deletions() {
        let mut manifest = empty_manifest();
        manifest.resources.iam = Some(IamSpec::default());
        let (client, state, handle) = spawn_mock_api(vec![
            (
                "/v1/secrets".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "secrets": [{"name": "orphan-secret", "id": "secret-1"}]
                    }),
                )],
            ),
            (
                "/v1/policies".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "policies": [{"name": "orphan-policy", "policy_id": "policy-1"}]
                    }),
                )],
            ),
            (
                "/v1/roles".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "roles": [{"name": "orphan-role", "role_id": "role-1"}]
                    }),
                )],
            ),
            (
                "/v1/teams".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "teams": [{"name": "orphan-team", "team_id": "team-1"}]
                    }),
                )],
            ),
            (
                "/v1/users".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "users": [{"email": "orphan@example.com", "user_id": "user-1"}]
                    }),
                )],
            ),
            (
                "/v1/admin/platform-provider-bundles?include_archived=true".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "bundles": [{
                            "bundle_key": "orphan-active",
                            "provider_registry": {"targets": ["gpt-4.1"]},
                            "status": "active"
                        }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{"name": "orphan-bot", "agent_id": "agent-1"}]
                    }),
                )],
            ),
            (
                "/v1/usage/budgets".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "budgets": [{
                            "id": "budget-1",
                            "name": "orphan-budget",
                            "amount": "9.00",
                            "currency": "USD",
                            "period_type": "weekly",
                            "alert_thresholds": [50, 75, 90],
                            "hard_limit_enabled": false,
                            "hard_limit_amount": null,
                            "team_id": null,
                            "user_id": null,
                            "agent_id": "agent-1",
                            "timezone": "UTC",
                            "week_starts_on": "monday",
                            "month_anchor_day": 1,
                            "billing_categories": ["gateway_llm"]
                        }]
                    }),
                )],
            ),
            (
                "/v1/settings/regulated-execution-profiles".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "profiles": [{"name": "orphan-profile", "id": "profile-1"}]
                    }),
                )],
            ),
            (
                "/v1/approval-policies".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "policies": [{"name": "orphan-approval", "id": "approval-1"}]
                    }),
                )],
            ),
            (
                "/v1/prompt-suites".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "items": [{
                            "id": "suite-1",
                            "name": "orphan-suite",
                            "description": null,
                            "enabled": null
                        }]
                    }),
                )],
            ),
        ])
        .await;

        let plan = compute_plan(&client, &manifest, false).await.unwrap();

        assert!(
            plan.ops.is_empty(),
            "prune=false should suppress all remote-only delete operations: {:?}",
            plan_summaries(&plan)
        );
        assert!(
            state.request_count("/v1/secrets") >= 1,
            "prune=false should still fetch remote secrets for comparison"
        );
        assert!(
            state.request_count("/v1/policies") >= 1,
            "prune=false should still fetch remote policies for comparison"
        );
        assert!(
            state.request_count("/v1/roles") >= 1,
            "prune=false should still fetch remote roles for comparison"
        );
        assert!(
            state.request_count("/v1/teams") >= 1,
            "prune=false should still fetch remote teams for comparison"
        );
        assert!(
            state.request_count("/v1/users") >= 1,
            "prune=false should still fetch remote users for comparison"
        );
        assert_eq!(
            state.request_count("/v1/admin/platform-provider-bundles?include_archived=true"),
            1
        );
        assert!(
            state.request_count("/v1/agents") >= 1,
            "prune=false should still fetch remote agents for comparison"
        );
        assert!(
            state.request_count("/v1/usage/budgets") >= 1,
            "prune=false should still fetch remote budgets for comparison"
        );
        assert_eq!(
            state.request_count("/v1/settings/regulated-execution-profiles"),
            1
        );
        assert_eq!(state.request_count("/v1/approval-policies"), 1);
        assert_eq!(state.request_count("/v1/prompt-suites"), 1);

        handle.abort();
    }

    #[tokio::test]
    async fn execute_plan_runs_non_delete_ops_before_reverse_prune_ops() {
        let plan = ReconcilePlan {
            ops: vec![
                ReconcileOp {
                    resource_type: "team".to_string(),
                    name: "platform".to_string(),
                    action: ReconcileAction::Delete,
                    remote_id: Some("team-1".to_string()),
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "user".to_string(),
                    name: "alice@example.com".to_string(),
                    action: ReconcileAction::Create,
                    remote_id: None,
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "secret".to_string(),
                    name: "openai-key".to_string(),
                    action: ReconcileAction::Delete,
                    remote_id: Some("secret-1".to_string()),
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "agent".to_string(),
                    name: "nightly-bot".to_string(),
                    action: ReconcileAction::NoOp,
                    remote_id: Some("agent-1".to_string()),
                    detail: None,
                },
            ],
        };
        let (client, state, handle) = spawn_mock_api(vec![
            (
                "/v1/users/invite".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/secrets/secret-1".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/teams/team-1".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
        ])
        .await;

        let result = execute_plan(&client, &plan, &empty_manifest())
            .await
            .unwrap();

        assert!(!result.has_failures());
        assert_eq!(result.successful.len(), 4);
        assert_eq!(result.failed.len(), 0);
        assert_eq!(
            state.request_summaries(),
            vec![
                "POST /v1/users/invite".to_string(),
                "DELETE /v1/secrets/secret-1".to_string(),
                "DELETE /v1/teams/team-1".to_string(),
            ]
        );

        handle.abort();
    }

    #[tokio::test]
    async fn execute_plan_stops_after_first_failed_operation() {
        let plan = ReconcilePlan {
            ops: vec![
                ReconcileOp {
                    resource_type: "user".to_string(),
                    name: "alice@example.com".to_string(),
                    action: ReconcileAction::Create,
                    remote_id: None,
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "mystery".to_string(),
                    name: "broken".to_string(),
                    action: ReconcileAction::Create,
                    remote_id: None,
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "team".to_string(),
                    name: "platform".to_string(),
                    action: ReconcileAction::Delete,
                    remote_id: Some("team-1".to_string()),
                    detail: None,
                },
            ],
        };
        let (client, state, handle) = spawn_mock_api(vec![(
            "/v1/users/invite".to_string(),
            vec![mock_response(StatusCode::OK, serde_json::json!({}))],
        )])
        .await;

        let result = execute_plan(&client, &plan, &empty_manifest())
            .await
            .unwrap();

        assert_eq!(result.successful.len(), 1);
        assert_eq!(result.failed.len(), 1);
        assert_eq!(result.successful[0].name, "alice@example.com");
        assert_eq!(result.failed[0].op.name, "broken");
        assert!(result.failed[0]
            .error
            .contains("unhandled reconcile op: mystery create"));
        assert_eq!(
            state.request_summaries(),
            vec!["POST /v1/users/invite".to_string()]
        );

        handle.abort();
    }

    #[tokio::test]
    async fn execute_op_covers_non_secret_resource_mutation_paths() {
        let manifest = execution_manifest();
        let (client, state, handle) = spawn_mock_api(vec![
            (
                "/v1/policies".to_string(),
                vec![
                    mock_response(StatusCode::OK, serde_json::json!({"id": "policy-created"})),
                    mock_response(
                        StatusCode::OK,
                        serde_json::json!({
                            "policies": [{ "name": "read-events", "policy_id": "policy-1" }]
                        }),
                    ),
                ],
            ),
            (
                "/v1/roles".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({"id": "role-1"}),
                )],
            ),
            (
                "/v1/roles/role-1/policies/policy-1".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/teams".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "teams": [{ "name": "platform", "team_id": "team-1" }]
                    }),
                )],
            ),
            (
                "/v1/users".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "users": [{ "email": "alice@example.com", "user_id": "user-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/policies/policy-9".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/roles/role-9".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/teams".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "teams": [{ "name": "platform", "team_id": "team-1" }]
                    }),
                )],
            ),
            (
                "/v1/teams/team-1/members".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/teams/team-9".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/users/invite".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/users/user-9".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/admin/platform-provider-bundles".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/admin/platform-provider-bundles/shared-openai".to_string(),
                vec![
                    mock_response(StatusCode::OK, serde_json::json!({})),
                    mock_response(StatusCode::OK, serde_json::json!({})),
                ],
            ),
            (
                "/v1/admin/platform-provider-bundles/shared-legacy".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents/agent-1/deployment".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/agents/agent-1/gateways".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/agents/agent-9".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/agents/agent-10".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/usage/budgets".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/usage/budgets/budget-1".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/usage/budgets/budget-2".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/settings/regulated-execution-profiles".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/settings/regulated-execution-profiles/regulated".to_string(),
                vec![
                    mock_response(StatusCode::OK, serde_json::json!({})),
                    mock_response(StatusCode::OK, serde_json::json!({})),
                ],
            ),
            (
                "/v1/approval-policies".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/approval-policies/appr-1".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/approval-policies/appr-2".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/prompt-suites".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/prompt-suites/suite-1".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/prompt-suites/suite-2".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/settings/collaboration".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/settings/hosted-gateway-policy".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/settings/auth-org-policy".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/gateways/gw-prod/agent-binding".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "agents": [{ "name": "nightly-bot", "agent_id": "agent-1" }]
                    }),
                )],
            ),
            (
                "/v1/teams/team-1/members".to_string(),
                vec![mock_response(StatusCode::OK, serde_json::json!({}))],
            ),
        ])
        .await;

        let ops = vec![
            ReconcileOp {
                resource_type: "iam.policy".to_string(),
                name: "read-events".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "iam.policy".to_string(),
                name: "read-events".to_string(),
                action: ReconcileAction::Delete,
                remote_id: Some("policy-9".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "iam.role".to_string(),
                name: "analyst".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "iam.role".to_string(),
                name: "analyst".to_string(),
                action: ReconcileAction::Delete,
                remote_id: Some("role-9".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "team".to_string(),
                name: "platform".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "team".to_string(),
                name: "platform".to_string(),
                action: ReconcileAction::Delete,
                remote_id: Some("team-9".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "team.member".to_string(),
                name: "platform/alice@example.com".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "user".to_string(),
                name: "alice@example.com".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "user".to_string(),
                name: "alice@example.com".to_string(),
                action: ReconcileAction::Delete,
                remote_id: Some("user-9".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "platform_provider_bundle".to_string(),
                name: "shared-openai".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "platform_provider_bundle".to_string(),
                name: "shared-openai".to_string(),
                action: ReconcileAction::Update,
                remote_id: Some("shared-openai".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "platform_provider_bundle".to_string(),
                name: "shared-legacy".to_string(),
                action: ReconcileAction::Delete,
                remote_id: Some("shared-legacy".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "agent".to_string(),
                name: "nightly-bot".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "agent".to_string(),
                name: "nightly-bot".to_string(),
                action: ReconcileAction::Update,
                remote_id: Some("agent-9".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "agent".to_string(),
                name: "nightly-bot".to_string(),
                action: ReconcileAction::Delete,
                remote_id: Some("agent-10".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "agent.deployment".to_string(),
                name: "nightly-bot".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "agent.gateway_link".to_string(),
                name: "nightly-bot/gw-eu".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "billing_budget".to_string(),
                name: "ops-budget".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "billing_budget".to_string(),
                name: "ops-budget".to_string(),
                action: ReconcileAction::Update,
                remote_id: Some("budget-1".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "billing_budget".to_string(),
                name: "ops-budget".to_string(),
                action: ReconcileAction::Delete,
                remote_id: Some("budget-2".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "regulated_execution_profile".to_string(),
                name: "regulated".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "regulated_execution_profile".to_string(),
                name: "regulated".to_string(),
                action: ReconcileAction::Update,
                remote_id: Some("regulated".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "regulated_execution_profile".to_string(),
                name: "regulated".to_string(),
                action: ReconcileAction::Delete,
                remote_id: Some("regulated".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "approval_policy".to_string(),
                name: "dual".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "approval_policy".to_string(),
                name: "dual".to_string(),
                action: ReconcileAction::Update,
                remote_id: Some("appr-1".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "approval_policy".to_string(),
                name: "dual".to_string(),
                action: ReconcileAction::Delete,
                remote_id: Some("appr-2".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "prompt_evaluation_suite".to_string(),
                name: "nightly".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "prompt_evaluation_suite".to_string(),
                name: "nightly".to_string(),
                action: ReconcileAction::Update,
                remote_id: Some("suite-1".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "prompt_evaluation_suite".to_string(),
                name: "nightly".to_string(),
                action: ReconcileAction::Delete,
                remote_id: Some("suite-2".to_string()),
                detail: None,
            },
            ReconcileOp {
                resource_type: "collaboration_defaults".to_string(),
                name: "singleton".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "hosted_gateway_policy".to_string(),
                name: "singleton".to_string(),
                action: ReconcileAction::Update,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "auth_org_policy".to_string(),
                name: "singleton".to_string(),
                action: ReconcileAction::Update,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "hosted_gateway_binding".to_string(),
                name: "gw-prod".to_string(),
                action: ReconcileAction::Update,
                remote_id: None,
                detail: None,
            },
            ReconcileOp {
                resource_type: "noop".to_string(),
                name: "ignored".to_string(),
                action: ReconcileAction::NoOp,
                remote_id: None,
                detail: None,
            },
        ];

        for op in &ops {
            execute_op(&client, op, &manifest).await.unwrap();
        }

        let requests = state.requests();
        assert_eq!(requests.len(), 45);
        assert_eq!(state.request_count("/v1/agents"), 6);
        assert_eq!(state.request_count("/v1/teams"), 4);
        assert_eq!(state.request_count("/v1/users"), 2);
        assert_eq!(state.request_count("/v1/policies"), 2);

        let policy_create = find_request(&requests, "POST", "/v1/policies");
        assert_eq!(
            policy_create.body,
            serde_json::json!({
                "name": "read-events",
                "description": "Read event history",
                "statements": [{ "effect": "allow", "action": ["events:read"] }]
            })
        );
        assert_eq!(
            find_request(&requests, "POST", "/v1/roles/role-1/policies/policy-1").body,
            serde_json::json!({})
        );
        assert_eq!(
            find_request(&requests, "POST", "/v1/teams/team-1/members").body,
            serde_json::json!({ "email": "alice@example.com" })
        );
        assert_eq!(
            find_request(&requests, "POST", "/v1/admin/platform-provider-bundles").body,
            serde_json::json!({
                "bundle_key": "shared-openai",
                "provider_registry": { "targets": ["gpt-5.4"] },
                "status": "active",
            })
        );
        assert_eq!(
            find_request(
                &requests,
                "PUT",
                "/v1/admin/platform-provider-bundles/shared-legacy"
            )
            .body,
            serde_json::json!({ "status": "archived" })
        );
        assert_eq!(
            find_request(&requests, "POST", "/v1/agents").body,
            serde_json::json!({
                "name": "nightly-bot-resource",
                "resource_name": "nightly-bot-resource",
                "resource_tags": [{ "key": "env", "value": "prod", "source": "user" }],
                "context_fabric": {
                    "capture_mode": "auto"
                },
                "mcp": {
                    "enabled": true
                }
            })
        );
        assert_eq!(
            find_request(&requests, "PUT", "/v1/agents/agent-1/deployment").body,
            serde_json::json!({
                "configuration_id": "cfg-1",
                "configuration_version_id": "cfgv-1",
                "rollout_gateway_ids": ["gw-eu"],
                "rollout_reason": "initial rollout",
            })
        );
        assert_eq!(
            find_request(&requests, "POST", "/v1/agents/agent-1/gateways").body,
            serde_json::json!({ "gateway_id": "gw-eu" })
        );
        assert_eq!(
            find_request(&requests, "POST", "/v1/usage/budgets").body,
            serde_json::json!({
                "name": "ops-budget",
                "amount": "42.00",
                "currency": "EUR",
                "period_type": "weekly",
                "alert_thresholds": [25, 75],
                "hard_limit_enabled": true,
                "hard_limit_amount": "84.00",
                "team_id": "team-1",
                "user_id": "user-1",
                "agent_id": "agent-1",
                "timezone": "Europe/Madrid",
                "week_starts_on": "sunday",
                "month_anchor_day": 14,
                "billing_categories": ["agents"],
            })
        );
        assert_eq!(
            find_request(&requests, "POST", "/v1/prompt-suites").body,
            serde_json::json!({
                "name": "nightly-prod",
                "resource_name": "nightly-prod",
                "description": "Nightly checks",
                "enabled": true,
                "resource_tags": [{ "key": "env", "value": "prod", "source": "user" }],
            })
        );
        assert_eq!(
            find_request(&requests, "PUT", "/v1/gateways/gw-prod/agent-binding").body,
            serde_json::json!({ "agent_id": "agent-1" })
        );

        handle.abort();
    }

    #[tokio::test]
    async fn execute_op_covers_non_secret_error_paths() {
        let manifest = execution_manifest();
        let (client, state, handle) = spawn_mock_api(vec![(
            "/v1/agents".to_string(),
            vec![mock_response(
                StatusCode::OK,
                serde_json::json!({"agents": []}),
            )],
        )])
        .await;

        let invalid_team_member = ReconcileOp {
            resource_type: "team.member".to_string(),
            name: "platform-only".to_string(),
            action: ReconcileAction::Create,
            remote_id: None,
            detail: None,
        };
        let team_err = execute_op(&client, &invalid_team_member, &manifest)
            .await
            .expect_err("invalid team member name");
        assert!(team_err
            .to_string()
            .contains("team.member name format invalid"));
        assert!(state.requests().is_empty());

        let invalid_gateway_link = ReconcileOp {
            resource_type: "agent.gateway_link".to_string(),
            name: "nightly-bot-only".to_string(),
            action: ReconcileAction::Create,
            remote_id: None,
            detail: None,
        };
        let gateway_err = execute_op(&client, &invalid_gateway_link, &manifest)
            .await
            .expect_err("invalid gateway link name");
        assert!(gateway_err
            .to_string()
            .contains("agent.gateway_link name format invalid"));
        assert!(state.requests().is_empty());

        let missing_approval_id = ReconcileOp {
            resource_type: "approval_policy".to_string(),
            name: "dual".to_string(),
            action: ReconcileAction::Update,
            remote_id: None,
            detail: None,
        };
        let approval_err = execute_op(&client, &missing_approval_id, &manifest)
            .await
            .expect_err("approval update missing remote id");
        assert!(approval_err
            .to_string()
            .contains("approval_policy update missing remote_id"));
        assert!(state.requests().is_empty());

        let missing_binding_agent = ReconcileOp {
            resource_type: "hosted_gateway_binding".to_string(),
            name: "gw-prod".to_string(),
            action: ReconcileAction::Update,
            remote_id: None,
            detail: None,
        };
        let binding_err = execute_op(&client, &missing_binding_agent, &manifest)
            .await
            .expect_err("binding agent should be missing");
        assert!(binding_err
            .to_string()
            .contains("agent \"nightly-bot\" not found"));
        assert_eq!(state.request_count("/v1/agents"), 1);

        let unsupported = ReconcileOp {
            resource_type: "mystery".to_string(),
            name: "broken".to_string(),
            action: ReconcileAction::Create,
            remote_id: None,
            detail: None,
        };
        let unsupported_err = execute_op(&client, &unsupported, &manifest)
            .await
            .expect_err("unsupported op should fail");
        assert!(unsupported_err
            .to_string()
            .contains("unhandled reconcile op: mystery create"));
        assert_eq!(state.request_count("/v1/agents"), 1);

        handle.abort();
    }

    #[test]
    fn build_regulated_execution_profile_body_minimal() {
        let spec = RegulatedExecutionProfileSpec {
            name: "default".to_string(),
            deployment_profile: "standard".to_string(),
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
        };
        let body = build_regulated_execution_profile_body(&spec);
        assert_eq!(body["name"], "default");
        assert_eq!(body["deployment_profile"], "standard");
        assert!(body.get("default").is_none());
        assert!(body.get("residency_region").is_none());
    }

    #[test]
    fn build_regulated_execution_profile_body_all_fields() {
        let spec = RegulatedExecutionProfileSpec {
            name: "sovereign".to_string(),
            deployment_profile: "sovereign_region".to_string(),
            default: Some(true),
            residency_region: Some("eu-central-1".to_string()),
            data_residency_tag: Some("gdpr".to_string()),
            cross_border_policy: Some("deny".to_string()),
            tokenization_enabled: Some(true),
            require_in_memory_only: Some(false),
            allow_internet_egress: Some(true),
            workload_class: Some("batch".to_string()),
            deletion_attestation_enabled: Some(true),
            fail_mode: Some("fail_closed".to_string()),
        };
        let body = build_regulated_execution_profile_body(&spec);
        assert_eq!(body["name"], "sovereign");
        assert_eq!(body["deployment_profile"], "sovereign_region");
        assert_eq!(body["default"], true);
        assert_eq!(body["residency_region"], "eu-central-1");
        assert_eq!(body["data_residency_tag"], "gdpr");
        assert_eq!(body["cross_border_policy"], "deny");
        assert_eq!(body["tokenization_enabled"], true);
        assert_eq!(body["require_in_memory_only"], false);
        assert_eq!(body["allow_internet_egress"], true);
        assert_eq!(body["workload_class"], "batch");
        assert_eq!(body["deletion_attestation_enabled"], true);
        assert_eq!(body["fail_mode"], "fail_closed");
    }

    #[test]
    fn build_approval_policy_body_minimal() {
        let spec = ApprovalPolicySpec {
            name: "minimal".to_string(),
            description: None,
            enabled: None,
            simulation_mode: None,
            break_glass_enabled: None,
            break_glass_post_review_required: None,
            thresholds: vec![],
            approver_chains: vec![],
        };
        let body = build_approval_policy_body(&spec);
        assert_eq!(body["name"], "minimal");
        assert!(body.get("description").is_none());
        assert!(body.get("enabled").is_none());
        assert!(body.get("thresholds").is_none());
        assert!(body.get("approver_chains").is_none());
    }

    #[test]
    fn build_approval_policy_body_full() {
        let spec = ApprovalPolicySpec {
            name: "strict".to_string(),
            description: Some("Strict policy".to_string()),
            enabled: Some(true),
            simulation_mode: Some(false),
            break_glass_enabled: Some(true),
            break_glass_post_review_required: Some(true),
            thresholds: vec![ApprovalThresholdSpec {
                risk_level: "high".to_string(),
                approval_mode: "dual".to_string(),
                required_approvals: 2,
                data_class: Some("pii".to_string()),
                destination_pattern: Some("*.prod".to_string()),
                decision_ttl_minutes: Some(30),
            }],
            approver_chains: vec![ApproverChainSpec {
                name: "security-chain".to_string(),
                mode: "sequential".to_string(),
                approvers: vec!["alice@example.com".to_string()],
                backup_approvers: vec!["bob@example.com".to_string()],
                escalation_after_minutes: Some(60),
            }],
        };
        let body = build_approval_policy_body(&spec);
        assert_eq!(body["name"], "strict");
        assert_eq!(body["description"], "Strict policy");
        assert_eq!(body["enabled"], true);
        assert_eq!(body["simulation_mode"], false);
        assert_eq!(body["break_glass_enabled"], true);
        assert_eq!(body["break_glass_post_review_required"], true);

        let thresholds = body["thresholds"].as_array().unwrap();
        assert_eq!(thresholds.len(), 1);
        assert_eq!(thresholds[0]["risk_level"], "high");
        assert_eq!(thresholds[0]["approval_mode"], "dual");
        assert_eq!(thresholds[0]["required_approvals"], 2);
        assert_eq!(thresholds[0]["data_class"], "pii");
        assert_eq!(thresholds[0]["destination_pattern"], "*.prod");
        assert_eq!(thresholds[0]["decision_ttl_minutes"], 30);

        let chains = body["approver_chains"].as_array().unwrap();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0]["name"], "security-chain");
        assert_eq!(chains[0]["mode"], "sequential");
        assert_eq!(chains[0]["approvers"][0], "alice@example.com");
        assert_eq!(chains[0]["backup_approvers"][0], "bob@example.com");
        assert_eq!(chains[0]["escalation_after_minutes"], 60);
    }

    #[test]
    fn build_collaboration_defaults_body_empty() {
        let spec = CollaborationDefaultsSpec {
            default_conversation_visibility: None,
            default_task_visibility: None,
            allow_user_sharing: None,
            allow_team_sharing: None,
            audit_membership_changes: None,
        };
        let body = build_collaboration_defaults_body(&spec);
        assert_eq!(body, serde_json::json!({}));
    }

    #[test]
    fn build_collaboration_defaults_body_all_fields() {
        let spec = CollaborationDefaultsSpec {
            default_conversation_visibility: Some("team".to_string()),
            default_task_visibility: Some("private".to_string()),
            allow_user_sharing: Some(true),
            allow_team_sharing: Some(false),
            audit_membership_changes: Some(true),
        };
        let body = build_collaboration_defaults_body(&spec);
        assert_eq!(body["default_conversation_visibility"], "team");
        assert_eq!(body["default_task_visibility"], "private");
        assert_eq!(body["allow_user_sharing"], true);
        assert_eq!(body["allow_team_sharing"], false);
        assert_eq!(body["audit_membership_changes"], true);
    }

    #[test]
    fn build_hosted_gateway_policy_body_empty() {
        let spec = HostedGatewayPolicySpec {
            default_agent: None,
            default_agent_fallback_enabled: None,
            fail_closed_on_missing_binding: None,
        };
        let body = build_hosted_gateway_policy_body(&spec);
        assert_eq!(body, serde_json::json!({}));
    }

    #[test]
    fn build_hosted_gateway_policy_body_all_fields() {
        let spec = HostedGatewayPolicySpec {
            default_agent: Some("my-agent".to_string()),
            default_agent_fallback_enabled: Some(true),
            fail_closed_on_missing_binding: Some(false),
        };
        let body = build_hosted_gateway_policy_body(&spec);
        assert_eq!(body["default_agent"], "my-agent");
        assert_eq!(body["default_agent_fallback_enabled"], true);
        assert_eq!(body["fail_closed_on_missing_binding"], false);
    }

    #[test]
    fn build_auth_org_policy_body_empty() {
        let spec = AuthOrgPolicySpec {
            verified_domains: vec![],
            required_sso: None,
            local_auth_allowed: None,
            jit_provisioning_enabled: None,
            invite_only: None,
            popup_return_origins: vec![],
        };
        let body = build_auth_org_policy_body(&spec);
        assert_eq!(body, serde_json::json!({}));
    }

    #[test]
    fn build_auth_org_policy_body_all_fields() {
        let spec = AuthOrgPolicySpec {
            verified_domains: vec!["example.com".to_string(), "corp.io".to_string()],
            required_sso: Some(true),
            local_auth_allowed: Some(false),
            jit_provisioning_enabled: Some(true),
            invite_only: Some(false),
            popup_return_origins: vec!["https://app.example.com".to_string()],
        };
        let body = build_auth_org_policy_body(&spec);
        let domains = body["verified_domains"].as_array().unwrap();
        assert_eq!(domains.len(), 2);
        assert_eq!(domains[0], "example.com");
        assert_eq!(domains[1], "corp.io");
        assert_eq!(body["required_sso"], true);
        assert_eq!(body["local_auth_allowed"], false);
        assert_eq!(body["jit_provisioning_enabled"], true);
        assert_eq!(body["invite_only"], false);
        let origins = body["popup_return_origins"].as_array().unwrap();
        assert_eq!(origins.len(), 1);
        assert_eq!(origins[0], "https://app.example.com");
    }

    #[test]
    fn find_hosted_gateway_binding_spec_found() {
        let manifest = ControlManifest {
            version: "1".to_string(),
            resources: Resources {
                hosted_gateway_bindings: vec![
                    HostedGatewayBindingSpec {
                        gateway_id: "gw-1".to_string(),
                        agent: "agent-a".to_string(),
                    },
                    HostedGatewayBindingSpec {
                        gateway_id: "gw-2".to_string(),
                        agent: "agent-b".to_string(),
                    },
                ],
                ..Resources::default()
            },
        };
        let binding = find_hosted_gateway_binding_spec(&manifest, "gw-2").unwrap();
        assert_eq!(binding.agent, "agent-b");
    }

    #[test]
    fn find_hosted_gateway_binding_spec_not_found() {
        let manifest = ControlManifest {
            version: "1".to_string(),
            resources: Resources::default(),
        };
        let err = find_hosted_gateway_binding_spec(&manifest, "gw-missing").unwrap_err();
        assert!(err.to_string().contains("gw-missing"));
    }

    #[test]
    fn find_by_name_found_and_missing() {
        let list = vec![
            ("alpha".to_string(), "id-a".to_string()),
            ("beta".to_string(), "id-b".to_string()),
        ];
        assert_eq!(find_by_name(&list, "alpha"), Some("id-a".to_string()));
        assert_eq!(find_by_name(&list, "beta"), Some("id-b".to_string()));
        assert_eq!(find_by_name(&list, "gamma"), None);
    }

    #[test]
    fn find_by_name_empty_list() {
        let list: Vec<(String, String)> = vec![];
        assert_eq!(find_by_name(&list, "anything"), None);
    }

    #[test]
    fn platform_provider_bundle_status_defaults_to_active() {
        let spec = PlatformProviderBundleSpec {
            bundle_key: "k".to_string(),
            provider_registry: serde_json::json!({}),
            status: None,
        };
        assert_eq!(platform_provider_bundle_status(&spec), "active");
    }

    #[test]
    fn platform_provider_bundle_status_uses_explicit_value() {
        let spec = PlatformProviderBundleSpec {
            bundle_key: "k".to_string(),
            provider_registry: serde_json::json!({}),
            status: Some("disabled".to_string()),
        };
        assert_eq!(platform_provider_bundle_status(&spec), "disabled");
    }

    #[test]
    fn reconcile_op_serialization() {
        let op = ReconcileOp {
            resource_type: "secret".to_string(),
            name: "my-secret".to_string(),
            action: ReconcileAction::Create,
            remote_id: None,
            detail: Some("env".to_string()),
        };
        let json = serde_json::to_string(&op).unwrap();
        assert!(json.contains("\"resource_type\":\"secret\""));
        assert!(json.contains("\"action\":\"create\""));
        assert!(!json.contains("remote_id"));
        assert!(json.contains("\"detail\":\"env\""));
    }

    #[test]
    fn reconcile_op_serialization_skips_none_detail() {
        let op = ReconcileOp {
            resource_type: "agent".to_string(),
            name: "bot".to_string(),
            action: ReconcileAction::NoOp,
            remote_id: Some("id-1".to_string()),
            detail: None,
        };
        let json = serde_json::to_string(&op).unwrap();
        assert!(json.contains("\"remote_id\":\"id-1\""));
        assert!(!json.contains("detail"));
    }

    #[test]
    fn reconcile_result_has_failures_reflects_failed_ops() {
        let success_only = ReconcileResult {
            successful: vec![ReconcileOp {
                resource_type: "secret".to_string(),
                name: "shared-key".to_string(),
                action: ReconcileAction::Create,
                remote_id: Some("sec-1".to_string()),
                detail: None,
            }],
            failed: Vec::new(),
        };
        assert!(!success_only.has_failures());

        let with_failure = ReconcileResult {
            successful: Vec::new(),
            failed: vec![ReconcileOpError {
                op: ReconcileOp {
                    resource_type: "team".to_string(),
                    name: "ops".to_string(),
                    action: ReconcileAction::Update,
                    remote_id: Some("team-1".to_string()),
                    detail: Some("member sync".to_string()),
                },
                error: "boom".to_string(),
            }],
        };
        assert!(with_failure.has_failures());
    }

    #[test]
    fn reconcile_plan_all_no_ops_reports_no_changes() {
        let plan = ReconcilePlan {
            ops: vec![
                ReconcileOp {
                    resource_type: "secret".to_string(),
                    name: "s1".to_string(),
                    action: ReconcileAction::NoOp,
                    remote_id: Some("id-1".to_string()),
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "team".to_string(),
                    name: "t1".to_string(),
                    action: ReconcileAction::NoOp,
                    remote_id: Some("id-2".to_string()),
                    detail: None,
                },
            ],
        };
        assert!(!plan.has_changes());
        assert_eq!(plan.no_ops(), 2);
        assert_eq!(plan.creates(), 0);
        assert_eq!(plan.updates(), 0);
        assert_eq!(plan.deletions(), 0);
    }

    // ── ReconcileAction Display ─────────────────────────────────────────

    #[test]
    fn reconcile_action_display() {
        assert_eq!(ReconcileAction::Create.to_string(), "create");
        assert_eq!(ReconcileAction::Update.to_string(), "update");
        assert_eq!(ReconcileAction::Delete.to_string(), "delete");
        assert_eq!(ReconcileAction::NoOp.to_string(), "no-op");
    }

    // ── ReconcileAction serde ───────────────────────────────────────────

    #[test]
    fn reconcile_action_serializes_expected_names() {
        assert_eq!(
            serde_json::to_string(&ReconcileAction::Create).unwrap(),
            "\"create\""
        );
        assert_eq!(
            serde_json::to_string(&ReconcileAction::Update).unwrap(),
            "\"update\""
        );
        assert_eq!(
            serde_json::to_string(&ReconcileAction::Delete).unwrap(),
            "\"delete\""
        );
        assert_eq!(
            serde_json::to_string(&ReconcileAction::NoOp).unwrap(),
            "\"no-op\""
        );
    }

    // ── ReconcilePlan counters ──────────────────────────────────────────

    #[test]
    fn reconcile_plan_empty() {
        let plan = ReconcilePlan::default();
        assert!(!plan.has_changes());
        assert_eq!(plan.creates(), 0);
        assert_eq!(plan.updates(), 0);
        assert_eq!(plan.deletions(), 0);
        assert_eq!(plan.no_ops(), 0);
    }

    #[test]
    fn reconcile_plan_with_changes() {
        let plan = ReconcilePlan {
            ops: vec![
                ReconcileOp {
                    resource_type: "secret".to_string(),
                    name: "s1".to_string(),
                    action: ReconcileAction::Create,
                    remote_id: None,
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "team".to_string(),
                    name: "t1".to_string(),
                    action: ReconcileAction::Update,
                    remote_id: Some("id-1".to_string()),
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "user".to_string(),
                    name: "u1".to_string(),
                    action: ReconcileAction::Delete,
                    remote_id: Some("id-2".to_string()),
                    detail: None,
                },
            ],
        };
        assert!(plan.has_changes());
        assert_eq!(plan.creates(), 1);
        assert_eq!(plan.updates(), 1);
        assert_eq!(plan.deletions(), 1);
        assert_eq!(plan.no_ops(), 0);
    }

    // ── ReconcileOp with all fields ─────────────────────────────────────

    #[test]
    fn reconcile_op_all_fields_serialization() {
        let op = ReconcileOp {
            resource_type: "iam_policy".to_string(),
            name: "admin-policy".to_string(),
            action: ReconcileAction::Update,
            remote_id: Some("pol-123".to_string()),
            detail: Some("permission change".to_string()),
        };
        let json = serde_json::to_value(&op).unwrap();
        assert_eq!(json["resource_type"], "iam_policy");
        assert_eq!(json["action"], "update");
        assert_eq!(json["remote_id"], "pol-123");
        assert_eq!(json["detail"], "permission change");
    }

    // ── ReconcileOp Debug format ───────────────────────────────────

    #[test]
    fn reconcile_op_debug_includes_action() {
        let op = ReconcileOp {
            resource_type: "team".to_string(),
            name: "t1".to_string(),
            action: ReconcileAction::Create,
            remote_id: None,
            detail: None,
        };
        let debug = format!("{:?}", op);
        assert!(debug.contains("Create"));
    }

    // ── ReconcilePlan mixed actions ──────────────────────────────────

    #[test]
    fn reconcile_plan_mixed_actions_has_changes() {
        let plan = ReconcilePlan {
            ops: vec![
                ReconcileOp {
                    resource_type: "team".to_string(),
                    name: "t1".to_string(),
                    action: ReconcileAction::NoOp,
                    remote_id: Some("id-1".to_string()),
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "team".to_string(),
                    name: "t2".to_string(),
                    action: ReconcileAction::Create,
                    remote_id: None,
                    detail: Some("new team".to_string()),
                },
            ],
        };
        assert!(plan.has_changes());
        assert_eq!(plan.creates(), 1);
        assert_eq!(plan.no_ops(), 1);
    }
}

#[cfg(test)]
mod coverage_expansion_reconcile_tests {
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

    // ── ReconcileAction ─────────────────────────────────────────────────

    #[test]
    fn reconcile_action_display() {
        assert_eq!(ReconcileAction::Create.to_string(), "create");
        assert_eq!(ReconcileAction::Update.to_string(), "update");
        assert_eq!(ReconcileAction::Delete.to_string(), "delete");
        assert_eq!(ReconcileAction::NoOp.to_string(), "no-op");
    }

    #[test]
    fn reconcile_action_eq() {
        assert_eq!(ReconcileAction::Create, ReconcileAction::Create);
        assert_ne!(ReconcileAction::Create, ReconcileAction::Update);
    }

    #[test]
    fn reconcile_action_serialize() {
        let j = serde_json::to_value(ReconcileAction::Create).unwrap();
        assert_eq!(j, json!("create"));
        let j = serde_json::to_value(ReconcileAction::NoOp).unwrap();
        assert_eq!(j, json!("no-op"));
    }

    // ── ReconcilePlan ───────────────────────────────────────────────────

    #[test]
    fn reconcile_plan_empty_has_no_changes() {
        let plan = ReconcilePlan { ops: vec![] };
        assert!(!plan.has_changes());
        assert_eq!(plan.creates(), 0);
        assert_eq!(plan.updates(), 0);
    }

    #[test]
    fn reconcile_plan_noop_only_has_no_changes() {
        let plan = ReconcilePlan {
            ops: vec![ReconcileOp {
                resource_type: "secret".to_string(),
                name: "s1".to_string(),
                action: ReconcileAction::NoOp,
                remote_id: None,
                detail: None,
            }],
        };
        assert!(!plan.has_changes());
    }

    #[test]
    fn reconcile_plan_with_create_has_changes() {
        let plan = ReconcilePlan {
            ops: vec![ReconcileOp {
                resource_type: "secret".to_string(),
                name: "s1".to_string(),
                action: ReconcileAction::Create,
                remote_id: None,
                detail: Some("new secret".to_string()),
            }],
        };
        assert!(plan.has_changes());
        assert_eq!(plan.creates(), 1);
        assert_eq!(plan.updates(), 0);
    }

    #[test]
    fn reconcile_plan_with_update_has_changes() {
        let plan = ReconcilePlan {
            ops: vec![ReconcileOp {
                resource_type: "role".to_string(),
                name: "r1".to_string(),
                action: ReconcileAction::Update,
                remote_id: Some("uuid-123".to_string()),
                detail: Some("permissions changed".to_string()),
            }],
        };
        assert!(plan.has_changes());
        assert_eq!(plan.updates(), 1);
    }

    #[test]
    fn reconcile_plan_mixed_ops() {
        let plan = ReconcilePlan {
            ops: vec![
                ReconcileOp {
                    resource_type: "secret".to_string(),
                    name: "s1".to_string(),
                    action: ReconcileAction::Create,
                    remote_id: None,
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "secret".to_string(),
                    name: "s2".to_string(),
                    action: ReconcileAction::NoOp,
                    remote_id: Some("id-2".to_string()),
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "role".to_string(),
                    name: "r1".to_string(),
                    action: ReconcileAction::Update,
                    remote_id: Some("id-r1".to_string()),
                    detail: None,
                },
                ReconcileOp {
                    resource_type: "team".to_string(),
                    name: "t1".to_string(),
                    action: ReconcileAction::Delete,
                    remote_id: Some("id-t1".to_string()),
                    detail: None,
                },
            ],
        };
        assert!(plan.has_changes());
        assert_eq!(plan.creates(), 1);
        assert_eq!(plan.updates(), 1);
    }

    // ── ReconcileOp serialization ───────────────────────────────────────

    #[test]
    fn reconcile_op_serialization() {
        let op = ReconcileOp {
            resource_type: "secret".to_string(),
            name: "my-secret".to_string(),
            action: ReconcileAction::Create,
            remote_id: None,
            detail: Some("added new secret".to_string()),
        };
        let j = serde_json::to_value(&op).unwrap();
        assert_eq!(j["resource_type"], "secret");
        assert_eq!(j["name"], "my-secret");
        assert_eq!(j["action"], "create");
        assert!(j.get("remote_id").is_none() || j["remote_id"].is_null());
        assert_eq!(j["detail"], "added new secret");
    }

    #[test]
    fn reconcile_op_skip_serializing_none() {
        let op = ReconcileOp {
            resource_type: "policy".to_string(),
            name: "p1".to_string(),
            action: ReconcileAction::NoOp,
            remote_id: None,
            detail: None,
        };
        let j = serde_json::to_string(&op).unwrap();
        assert!(!j.contains("remote_id"));
        assert!(!j.contains("detail"));
    }
}
