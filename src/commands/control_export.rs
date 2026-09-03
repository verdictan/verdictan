// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan control export` — scaffold a control-plane manifest from current state.
//!
//! Queries the remote control-plane API and writes (or prints) a manifest YAML
//! that represents the current state of secrets, IAM policies, roles, teams,
//! users, platform provider bundles, and agents.
//!
//! # Usage
//!
//! ```text
//! verdictan control export [--file control-manifest.yaml] [--include-secret-stubs] [--json] [--allow-partial]
//! ```
//!
//! # Flag behaviour
//!
//! - `--include-secret-stubs`: include secret entries with a placeholder `env`
//!   value (`<SET_ENV_VAR>`) so the manifest is importable. Without this flag
//!   the secrets section is omitted because the actual env var names are not
//!   stored server-side.
//! - `--file`: write the YAML to a file rather than printing to stdout.
//! - `--json`: emit JSON instead of YAML.
//! - `--allow-partial`: emit the partial manifest even when one or more
//!   resource types fail to export. Without this flag the command fails before
//!   writing or printing a partial manifest.
//!
//! # Module wiring
//! Add `pub(crate) mod control_export;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;
use std::collections::HashMap;
use std::path::Path;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::managed::control_manifest::{
    AgentDeploymentSpec, AgentSpec, ApprovalPolicySpec, ApprovalThresholdSpec, ApproverChainSpec,
    AuthOrgPolicySpec, BudgetSpec, CollaborationDefaultsSpec, ControlManifest,
    HostedGatewayBindingSpec, HostedGatewayPolicySpec, IamPolicySpec, IamRoleSpec, IamSpec,
    PlatformProviderBundleSpec, PromptEvaluationSuiteSpec, RegulatedExecutionProfileSpec,
    Resources, SecretSpec, TeamSpec, UserSpec,
};
use crate::managed::control_plane_types::{
    extract_typed_list, resource_tags_to_specs, AgentBindingResponse, AgentItem,
    ApprovalPolicyItem, ApprovalThresholdItem, ApproverChainItem, BudgetItem, GatewayItem,
    HostedGatewayPolicyResponse, PlatformProviderBundleItem, PolicyItem, PromptSuiteItem,
    RegulatedExecutionProfileItem, RoleItem, SecretItem, TeamItem, UserItem,
};
use crate::managed::control_reconcile::fetch_json_value_with_retry;
use crate::output::json::print_json;
use crate::persistence::atomic_write;

// ── Export error tracking ─────────────────────────────────────────────────────

struct ResourceExportError {
    resource_type: String,
    http_status: Option<u16>,
    message: String,
}

impl ResourceExportError {
    fn display_detail(&self) -> String {
        match self.http_status {
            Some(status) => format!("{}: HTTP {}", self.resource_type, status),
            None => format!("{}: {}", self.resource_type, self.message),
        }
    }
}

struct ExportOutcome {
    manifest: ControlManifest,
    errors: Vec<ResourceExportError>,
    total_attempted: usize,
}

struct BudgetScopeMaps {
    agent_id_to_name: HashMap<String, String>,
    team_id_to_name: HashMap<String, String>,
    user_id_to_email: HashMap<String, String>,
}

#[derive(Debug, Args)]
pub(crate) struct ControlExportArgs {
    /// Write the exported manifest to this file path. If not set, print to stdout.
    #[arg(long)]
    pub(crate) file: Option<std::path::PathBuf>,

    /// Include secret stub entries with placeholder env values.
    #[arg(long)]
    pub(crate) include_secret_stubs: bool,

    /// Emit JSON, not YAML.
    #[arg(long)]
    pub(crate) json: bool,

    /// Emit the manifest when one or more resource types fail.
    #[arg(long)]
    pub(crate) allow_partial: bool,

    /// Optional config file path (YAML).
    #[arg(long)]
    pub(crate) config: Option<std::path::PathBuf>,

    /// Override API URL.
    #[arg(long)]
    pub(crate) api_url: Option<String>,

    /// Override API token.
    #[arg(long)]
    pub(crate) api_token: Option<String>,

    /// Profile name (default: "default").
    #[arg(long, default_value = "default")]
    pub(crate) profile: String,

    /// Target region for this API call.
    #[arg(long)]
    pub(crate) region: Option<String>,
}
pub(crate) async fn run_async(args: ControlExportArgs) -> Result<(), CliError> {
    let inputs = ConfigInputs {
        api_url_flag: args.api_url,
        api_token_flag: args.api_token,
        config_path: args.config,
        profile_flag: Some(args.profile),
        region_flag: args.region,
    };
    let config = Config::resolve(inputs)?;
    let api_token = config.api_token.ok_or_else(|| {
        CliError::auth("missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)")
    })?;
    let client = AsyncApiClient::new(config.api_url, api_token)?.with_region(config.region.clone());

    let outcome = build_export_manifest(&client, args.include_secret_stubs).await?;

    // Surface a helpful message when the export is completely empty.
    if outcome.manifest.resources.is_empty() && outcome.errors.is_empty() {
        eprintln!(
            "\nWarning: exported manifest contains no resources.\n\
             Common causes:\n  \
             • API token has expired — run `verdictan auth login` to refresh\n  \
             • Token lacks required permissions for the target org\n  \
             • The organisation has no configured resources yet\n\
             Check warnings above for per-resource details.\n"
        );
    }

    let total = outcome.total_attempted;
    let failed = outcome.errors.len();
    let succeeded = total - failed;

    if !outcome.errors.is_empty() && !args.allow_partial {
        eprintln!(
            "{}",
            format_export_summary(&outcome.errors, succeeded, total, false)
        );
        return Err(CliError::network(format!(
            "{failed} resource type(s) failed to export; rerun with --allow-partial to emit a partial manifest"
        )));
    }

    emit_manifest(&outcome.manifest, args.file.as_deref(), args.json)?;

    if outcome.errors.is_empty() {
        eprintln!("Export summary: {succeeded}/{total} resources exported successfully.");
    } else {
        eprintln!(
            "{}",
            format_export_summary(&outcome.errors, succeeded, total, true)
        );
    }

    Ok(())
}

fn emit_manifest(
    manifest: &ControlManifest,
    path: Option<&Path>,
    as_json: bool,
) -> Result<(), CliError> {
    if let Some(path) = path {
        let rendered = render_manifest(manifest, as_json)?;
        write_manifest_atomically(path, &rendered)?;
        println!("exported to {}", path.display());
        return Ok(());
    }

    if as_json {
        print_json(manifest)?;
    } else {
        let yaml = render_manifest(manifest, false)?;
        print!("{yaml}");
    }

    Ok(())
}

fn render_manifest(manifest: &ControlManifest, as_json: bool) -> Result<String, CliError> {
    if as_json {
        serde_json::to_string_pretty(manifest)
            .map_err(|e| CliError::internal(format!("json serialization failed: {e}")))
    } else {
        serde_yaml::to_string(manifest)
            .map_err(|e| CliError::internal(format!("yaml serialization failed: {e}")))
    }
}

fn write_manifest_atomically(path: &Path, contents: &str) -> Result<(), CliError> {
    if path.file_name().is_none() {
        return Err(CliError::user(format!(
            "cannot write {}: missing file name",
            path.display()
        )));
    }

    atomic_write(path, contents.as_bytes())
        .map_err(|error| CliError::user(format!("cannot write {}: {error}", path.display())))
}

fn format_export_summary(
    errors: &[ResourceExportError],
    succeeded: usize,
    total: usize,
    partial_allowed: bool,
) -> String {
    let failed_details = errors
        .iter()
        .map(ResourceExportError::display_detail)
        .collect::<Vec<_>>()
        .join(", ");

    if partial_allowed {
        format!(
            "Export summary: {succeeded}/{total} resources exported successfully. \
             Partial manifest emitted because --allow-partial was set. Failed: [{failed_details}]"
        )
    } else {
        format!(
            "Export summary: {succeeded}/{total} resources exported successfully. \
             Failed: [{failed_details}]"
        )
    }
}

async fn build_export_manifest(
    client: &AsyncApiClient,
    include_secret_stubs: bool,
) -> Result<ExportOutcome, CliError> {
    let mut resources = Resources::default();
    let mut errors: Vec<ResourceExportError> = Vec::new();
    let mut total_attempted: usize = 0;

    macro_rules! try_export {
        ($resource_type:expr, $call:expr, $target:expr) => {{
            total_attempted += 1;
            match $call.await {
                Ok(v) => $target = v,
                Err(e) => {
                    errors.push(ResourceExportError {
                        resource_type: $resource_type.to_string(),
                        http_status: e.http_status,
                        message: e.to_string(),
                    });
                }
            }
        }};
    }

    // Secrets
    if include_secret_stubs {
        try_export!("secrets", export_secrets(client), resources.secrets);
    }

    // IAM policies and roles
    total_attempted += 1;
    match export_iam(client).await {
        Ok(iam) => {
            if !iam.policies.is_empty() || !iam.roles.is_empty() {
                resources.iam = Some(iam);
            }
        }
        Err(e) => {
            errors.push(ResourceExportError {
                resource_type: "iam".to_string(),
                http_status: e.http_status,
                message: e.to_string(),
            });
        }
    }

    // Teams
    try_export!("teams", export_teams(client), resources.teams);

    // Users
    try_export!("users", export_users(client), resources.users);

    // Platform provider bundles
    try_export!(
        "platform_provider_bundles",
        export_platform_provider_bundles(client),
        resources.platform_provider_bundles
    );

    // Agents
    try_export!("agents", export_agents(client), resources.agents);

    // Agent ID→name map (helper for hosted gateway exports).
    // Hosted gateway exports can still fall back to raw IDs, but billing
    // budget exports must not silently downgrade scoped names to opaque IDs.
    let agent_id_to_name = build_agent_id_to_name_map(client).await.unwrap_or_default();

    // Billing budgets
    total_attempted += 1;
    match build_budget_scope_maps(client).await {
        Ok(scope_maps) => match export_budgets(
            client,
            &scope_maps.team_id_to_name,
            &scope_maps.user_id_to_email,
            &scope_maps.agent_id_to_name,
        )
        .await
        {
            Ok(v) => resources.budgets = v,
            Err(e) => {
                errors.push(ResourceExportError {
                    resource_type: "billing_budgets".to_string(),
                    http_status: e.http_status,
                    message: e.to_string(),
                });
            }
        },
        Err(e) => {
            errors.push(ResourceExportError {
                resource_type: "billing_budgets".to_string(),
                http_status: e.http_status,
                message: e.to_string(),
            });
        }
    }

    // Regulated execution profiles
    try_export!(
        "regulated_execution_profiles",
        export_regulated_execution_profiles(client),
        resources.regulated_execution_profiles
    );

    // Approval policies
    try_export!(
        "approval_policies",
        export_approval_policies(client),
        resources.approval_policies
    );

    // Prompt evaluation suites
    try_export!(
        "prompt_evaluation_suites",
        export_prompt_evaluation_suites(client),
        resources.prompt_evaluation_suites
    );

    // Collaboration defaults (singleton)
    total_attempted += 1;
    match export_collaboration_defaults(client).await {
        Ok(v) => resources.collaboration_defaults = v,
        Err(e) => {
            errors.push(ResourceExportError {
                resource_type: "collaboration_defaults".to_string(),
                http_status: e.http_status,
                message: e.to_string(),
            });
        }
    }

    // Hosted gateway policy (singleton)
    total_attempted += 1;
    match export_hosted_gateway_policy(client, &agent_id_to_name).await {
        Ok(v) => resources.hosted_gateway_policy = v,
        Err(e) => {
            errors.push(ResourceExportError {
                resource_type: "hosted_gateway_policy".to_string(),
                http_status: e.http_status,
                message: e.to_string(),
            });
        }
    }

    // Hosted gateway bindings (explicit only)
    try_export!(
        "hosted_gateway_bindings",
        export_hosted_gateway_bindings(client, &agent_id_to_name),
        resources.hosted_gateway_bindings
    );

    // Auth org policy (singleton)
    total_attempted += 1;
    match export_auth_org_policy(client).await {
        Ok(v) => resources.auth_org_policy = v,
        Err(e) => {
            errors.push(ResourceExportError {
                resource_type: "auth_org_policy".to_string(),
                http_status: e.http_status,
                message: e.to_string(),
            });
        }
    }

    Ok(ExportOutcome {
        manifest: ControlManifest {
            version: "1".to_string(),
            resources,
        },
        errors,
        total_attempted,
    })
}

// ── Per-resource exporters ────────────────────────────────────────────────────

async fn export_secrets(client: &AsyncApiClient) -> Result<Vec<SecretSpec>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/secrets").await? {
        Some(v) => v,
        None => return Ok(vec![]),
    };
    let items: Vec<SecretItem> = extract_typed_list(&value, "secrets");
    let specs = items.iter().filter_map(build_secret_spec).collect();
    Ok(specs)
}

async fn export_iam(client: &AsyncApiClient) -> Result<IamSpec, CliError> {
    let mut spec = IamSpec::default();

    // Policies
    if let Some(value) = fetch_json_value_with_retry(client, "/v1/policies").await? {
        let items: Vec<PolicyItem> = extract_typed_list(&value, "policies");
        spec.policies = items.iter().filter_map(build_iam_policy_spec).collect();
    }

    // Roles
    if let Some(value) = fetch_json_value_with_retry(client, "/v1/roles").await? {
        let items: Vec<RoleItem> = extract_typed_list(&value, "roles");
        spec.roles = items.iter().filter_map(build_iam_role_spec).collect();
    }

    Ok(spec)
}

async fn export_teams(client: &AsyncApiClient) -> Result<Vec<TeamSpec>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/teams").await? {
        Some(v) => v,
        None => return Ok(vec![]),
    };
    let items: Vec<TeamItem> = extract_typed_list(&value, "teams");
    let specs = items.iter().filter_map(build_team_spec).collect();
    Ok(specs)
}

async fn export_users(client: &AsyncApiClient) -> Result<Vec<UserSpec>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/users").await? {
        Some(v) => v,
        None => return Ok(vec![]),
    };
    let items: Vec<UserItem> = extract_typed_list(&value, "users");
    let specs = items.iter().filter_map(build_user_spec).collect();
    Ok(specs)
}

async fn export_agents(client: &AsyncApiClient) -> Result<Vec<AgentSpec>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/agents").await? {
        Some(v) => v,
        None => return Ok(vec![]),
    };
    let items: Vec<AgentItem> = extract_typed_list(&value, "agents");
    Ok(items.iter().filter_map(build_agent_spec).collect())
}

async fn export_platform_provider_bundles(
    client: &AsyncApiClient,
) -> Result<Vec<PlatformProviderBundleSpec>, CliError> {
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
        .filter_map(build_platform_provider_bundle_spec)
        .collect())
}

fn build_secret_spec(item: &SecretItem) -> Option<SecretSpec> {
    let name = item.name.clone()?;
    Some(SecretSpec {
        name,
        env: item
            .env_var
            .clone()
            .unwrap_or_else(|| "<SET_ENV_VAR>".to_string()),
        description: item.description.clone(),
    })
}

fn build_iam_policy_spec(item: &PolicyItem) -> Option<IamPolicySpec> {
    let name = item.name.clone()?;
    Some(IamPolicySpec {
        name,
        description: item.description.clone(),
        statements: item.statements.clone(),
    })
}

fn build_iam_role_spec(item: &RoleItem) -> Option<IamRoleSpec> {
    let name = item.name.clone()?;
    let policies = item
        .policies
        .iter()
        .filter_map(|policy| policy.name.clone())
        .collect();
    Some(IamRoleSpec { name, policies })
}

fn build_team_spec(item: &TeamItem) -> Option<TeamSpec> {
    let name = item.name.clone()?;
    Some(TeamSpec {
        name,
        description: item.description.clone(),
        members: vec![],
    })
}

fn build_user_spec(item: &UserItem) -> Option<UserSpec> {
    let email = item.email.clone()?;
    Some(UserSpec {
        email,
        teams: vec![],
        roles: vec![],
    })
}

fn build_platform_provider_bundle_spec(
    item: PlatformProviderBundleItem,
) -> Option<PlatformProviderBundleSpec> {
    Some(PlatformProviderBundleSpec {
        bundle_key: item.bundle_key?,
        provider_registry: item.provider_registry?,
        status: item.status,
    })
}

fn build_agent_spec(item: &AgentItem) -> Option<AgentSpec> {
    let name = item.name.as_ref()?;
    let team = item.team_name.clone().or_else(|| item.team.clone());
    let gateways = item.gateway_ids.clone();
    let scope_kind = item.scope_kind.clone();
    let configuration_id = item.configuration_id.clone();
    let configuration_version_id = item
        .active_configuration_version_id
        .clone()
        .or_else(|| item.configuration_version_id.clone());
    let deployment = match (configuration_id, configuration_version_id) {
        (Some(configuration_id), Some(configuration_version_id)) => Some(AgentDeploymentSpec {
            configuration_id,
            configuration_version_id,
            rollout_gateways: gateways.clone(),
            rollout_reason: None,
        }),
        _ => None,
    };

    Some(AgentSpec {
        name: name.to_string(),
        resource_name: item.resource_name.clone(),
        resource_tags: resource_tags_to_specs(&item.resource_tags),
        team,
        scope_kind,
        gateways,
        context_fabric: item.context_fabric.clone(),
        mcp: item.mcp.clone(),
        deployment,
    })
}

// ── Agent ID → name map (for hosted gateway export) ───────────────────────────

async fn build_agent_id_to_name_map(
    client: &AsyncApiClient,
) -> Result<HashMap<String, String>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/agents").await? {
        Some(v) => v,
        None => return Ok(HashMap::new()),
    };
    let items: Vec<AgentItem> = extract_typed_list(&value, "agents");
    Ok(items
        .into_iter()
        .filter_map(|item| {
            let id = item.resolved_id()?.to_string();
            let name = item.name?;
            Some((id, name))
        })
        .collect())
}

async fn build_team_id_to_name_map(
    client: &AsyncApiClient,
) -> Result<HashMap<String, String>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/teams").await? {
        Some(v) => v,
        None => return Ok(HashMap::new()),
    };
    let items: Vec<TeamItem> = extract_typed_list(&value, "teams");
    Ok(items
        .into_iter()
        .filter_map(|item| Some((item.resolved_id()?.to_string(), item.name?)))
        .collect())
}

async fn build_user_id_to_email_map(
    client: &AsyncApiClient,
) -> Result<HashMap<String, String>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/users").await? {
        Some(v) => v,
        None => return Ok(HashMap::new()),
    };
    let items: Vec<UserItem> = extract_typed_list(&value, "users");
    Ok(items
        .into_iter()
        .filter_map(|item| Some((item.resolved_id()?.to_string(), item.email?)))
        .collect())
}

async fn build_budget_scope_maps(client: &AsyncApiClient) -> Result<BudgetScopeMaps, CliError> {
    Ok(BudgetScopeMaps {
        agent_id_to_name: build_agent_id_to_name_map(client).await?,
        team_id_to_name: build_team_id_to_name_map(client).await?,
        user_id_to_email: build_user_id_to_email_map(client).await?,
    })
}

fn resolve_budget_scope_name(
    id: Option<String>,
    names_by_id: &HashMap<String, String>,
) -> Option<String> {
    id.and_then(|raw_id| names_by_id.get(&raw_id).cloned().or(Some(raw_id)))
}

fn build_budget_spec(
    item: BudgetItem,
    team_id_to_name: &HashMap<String, String>,
    user_id_to_email: &HashMap<String, String>,
    agent_id_to_name: &HashMap<String, String>,
) -> Option<BudgetSpec> {
    let name = item.name?;
    let amount = item.amount?;

    Some(BudgetSpec {
        name,
        amount,
        currency: item.currency,
        period_type: item.period_type,
        alert_thresholds: item.alert_thresholds,
        hard_limit_enabled: item.hard_limit_enabled,
        hard_limit_amount: item.hard_limit_amount,
        team: resolve_budget_scope_name(item.team_id, team_id_to_name),
        user: resolve_budget_scope_name(item.user_id, user_id_to_email),
        agent: resolve_budget_scope_name(item.agent_id, agent_id_to_name),
        timezone: item.timezone,
        week_starts_on: item.week_starts_on,
        month_anchor_day: item.month_anchor_day,
        billing_categories: item.billing_categories,
    })
}

fn budget_scope_sort_key(spec: &BudgetSpec) -> String {
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

// ── Billing budgets ──────────────────────────────────────────────────────────

async fn export_budgets(
    client: &AsyncApiClient,
    team_id_to_name: &HashMap<String, String>,
    user_id_to_email: &HashMap<String, String>,
    agent_id_to_name: &HashMap<String, String>,
) -> Result<Vec<BudgetSpec>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/usage/budgets").await? {
        Some(v) => v,
        None => return Ok(vec![]),
    };
    let items: Vec<BudgetItem> = extract_typed_list(&value, "budgets");
    let mut specs: Vec<BudgetSpec> = items
        .into_iter()
        .filter_map(|item| {
            build_budget_spec(item, team_id_to_name, user_id_to_email, agent_id_to_name)
        })
        .collect();
    specs.sort_by(|a, b| {
        budget_scope_sort_key(a)
            .cmp(&budget_scope_sort_key(b))
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(specs)
}

// ── MCP catalog entries ───────────────────────────────────────────────────────

// ── Regulated execution profiles ──────────────────────────────────────────────

async fn export_regulated_execution_profiles(
    client: &AsyncApiClient,
) -> Result<Vec<RegulatedExecutionProfileSpec>, CliError> {
    let value =
        match fetch_json_value_with_retry(client, "/v1/settings/regulated-execution-profiles")
            .await?
        {
            Some(v) => v,
            None => return Ok(vec![]),
        };
    let items: Vec<RegulatedExecutionProfileItem> = extract_typed_list(&value, "profiles");
    let mut specs: Vec<RegulatedExecutionProfileSpec> = items
        .into_iter()
        .filter_map(build_regulated_execution_profile_spec)
        .collect();
    specs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(specs)
}

fn build_regulated_execution_profile_spec(
    item: RegulatedExecutionProfileItem,
) -> Option<RegulatedExecutionProfileSpec> {
    let name = item.name?;
    let deployment_profile = item.deployment_profile?;
    Some(RegulatedExecutionProfileSpec {
        name,
        deployment_profile,
        default: item.default,
        residency_region: item.residency_region,
        data_residency_tag: item.data_residency_tag,
        cross_border_policy: item.cross_border_policy,
        tokenization_enabled: item.tokenization_enabled,
        require_in_memory_only: item.require_in_memory_only,
        allow_internet_egress: item.allow_internet_egress,
        workload_class: item.workload_class,
        deletion_attestation_enabled: item.deletion_attestation_enabled,
        fail_mode: item.fail_mode,
    })
}

// ── Approval policies ─────────────────────────────────────────────────────────

async fn export_approval_policies(
    client: &AsyncApiClient,
) -> Result<Vec<ApprovalPolicySpec>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/approval-policies").await? {
        Some(v) => v,
        None => return Ok(vec![]),
    };
    let items: Vec<ApprovalPolicyItem> = extract_typed_list(&value, "policies");
    let mut specs: Vec<ApprovalPolicySpec> = items
        .into_iter()
        .filter_map(build_approval_policy_spec)
        .collect();
    specs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(specs)
}

fn build_approval_threshold_spec(item: ApprovalThresholdItem) -> Option<ApprovalThresholdSpec> {
    Some(ApprovalThresholdSpec {
        risk_level: item.risk_level?,
        data_class: item.data_class,
        destination_pattern: item.destination_pattern,
        approval_mode: item.approval_mode.unwrap_or_else(|| "single".to_string()),
        required_approvals: item.required_approvals.unwrap_or(1),
        decision_ttl_minutes: item.decision_ttl_minutes,
    })
}

fn build_approver_chain_spec(item: ApproverChainItem) -> Option<ApproverChainSpec> {
    Some(ApproverChainSpec {
        name: item.name?,
        mode: item.mode.unwrap_or_else(|| "single".to_string()),
        approvers: item.approvers,
        backup_approvers: item.backup_approvers,
        escalation_after_minutes: item.escalation_after_minutes,
    })
}

fn build_approval_policy_spec(item: ApprovalPolicyItem) -> Option<ApprovalPolicySpec> {
    let name = item.name?;
    let thresholds = item
        .thresholds
        .into_iter()
        .filter_map(build_approval_threshold_spec)
        .collect();
    let approver_chains = item
        .approver_chains
        .into_iter()
        .filter_map(build_approver_chain_spec)
        .collect();
    Some(ApprovalPolicySpec {
        name,
        description: item.description,
        enabled: item.enabled,
        simulation_mode: item.simulation_mode,
        break_glass_enabled: item.break_glass_enabled,
        break_glass_post_review_required: item.break_glass_post_review_required,
        thresholds,
        approver_chains,
    })
}

// ── Prompt evaluation suites ──────────────────────────────────────────────────

async fn export_prompt_evaluation_suites(
    client: &AsyncApiClient,
) -> Result<Vec<PromptEvaluationSuiteSpec>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/prompt-suites").await? {
        Some(v) => v,
        None => return Ok(vec![]),
    };
    let items: Vec<PromptSuiteItem> = extract_typed_list(&value, "items");
    let mut specs: Vec<PromptEvaluationSuiteSpec> = items
        .iter()
        .filter_map(build_prompt_evaluation_suite_spec)
        .collect();
    specs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(specs)
}

fn build_prompt_evaluation_suite_spec(item: &PromptSuiteItem) -> Option<PromptEvaluationSuiteSpec> {
    let name = item.name.clone()?;
    Some(PromptEvaluationSuiteSpec {
        name: name.clone(),
        resource_name: item.resource_name.clone().or(Some(name)),
        description: item.description.clone(),
        enabled: item.enabled,
        resource_tags: resource_tags_to_specs(&item.resource_tags),
    })
}

// ── Collaboration defaults (singleton) ────────────────────────────────────────

async fn export_collaboration_defaults(
    client: &AsyncApiClient,
) -> Result<Option<CollaborationDefaultsSpec>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/settings/collaboration").await? {
        Some(v) => v,
        None => return Ok(None),
    };
    serde_json::from_value(value)
        .map(Some)
        .map_err(|e| CliError::internal(format!("failed to decode collaboration defaults: {e}")))
}

// ── Hosted gateway policy (singleton) ─────────────────────────────────────────

async fn export_hosted_gateway_policy(
    client: &AsyncApiClient,
    agent_id_to_name: &HashMap<String, String>,
) -> Result<Option<HostedGatewayPolicySpec>, CliError> {
    let value =
        match fetch_json_value_with_retry(client, "/v1/settings/hosted-gateway-policy").await? {
            Some(v) => v,
            None => return Ok(None),
        };
    let response: HostedGatewayPolicyResponse = serde_json::from_value(value)
        .map_err(|e| CliError::internal(format!("failed to decode hosted gateway policy: {e}")))?;
    Ok(Some(build_hosted_gateway_policy_spec(
        response,
        agent_id_to_name,
    )))
}

fn build_hosted_gateway_policy_spec(
    response: HostedGatewayPolicyResponse,
    agent_id_to_name: &HashMap<String, String>,
) -> HostedGatewayPolicySpec {
    let default_agent = response
        .default_agent_id
        .and_then(|id| agent_id_to_name.get(&id).cloned().or(Some(id)));
    HostedGatewayPolicySpec {
        default_agent,
        default_agent_fallback_enabled: response.default_agent_fallback_enabled,
        fail_closed_on_missing_binding: response.fail_closed_on_missing_binding,
    }
}

// ── Hosted gateway bindings (explicit only) ───────────────────────────────────

async fn export_hosted_gateway_bindings(
    client: &AsyncApiClient,
    agent_id_to_name: &HashMap<String, String>,
) -> Result<Vec<HostedGatewayBindingSpec>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/gateways").await? {
        Some(v) => v,
        None => return Ok(vec![]),
    };
    let gateways: Vec<GatewayItem> = extract_typed_list(&value, "gateways");

    let mut specs = Vec::new();
    for gw in &gateways {
        let gw_id = match gw.id.as_deref() {
            Some(id) => id,
            None => continue,
        };
        // Probe per-gateway binding; only export explicit bindings.
        let binding: AgentBindingResponse = match client
            .get_json(&format!("/v1/gateways/{gw_id}/agent-binding"))
            .await
        {
            Ok(v) => v,
            Err(_) => continue,
        };
        if binding.binding_mode.as_deref() != Some("explicit") {
            continue;
        }
        if let Some(spec) = build_hosted_gateway_binding_spec(gw_id, binding, agent_id_to_name) {
            specs.push(spec);
        }
    }
    specs.sort_by(|a, b| a.gateway_id.cmp(&b.gateway_id));
    Ok(specs)
}

fn build_hosted_gateway_binding_spec(
    gateway_id: &str,
    binding: AgentBindingResponse,
    agent_id_to_name: &HashMap<String, String>,
) -> Option<HostedGatewayBindingSpec> {
    let agent_id = binding.agent_id?;
    let agent = agent_id_to_name.get(&agent_id).cloned().unwrap_or(agent_id);
    Some(HostedGatewayBindingSpec {
        gateway_id: gateway_id.to_string(),
        agent,
    })
}

// ── Auth org policy (singleton) ───────────────────────────────────────────────

async fn export_auth_org_policy(
    client: &AsyncApiClient,
) -> Result<Option<AuthOrgPolicySpec>, CliError> {
    let value = match fetch_json_value_with_retry(client, "/v1/settings/auth-org-policy").await? {
        Some(v) => v,
        None => return Ok(None),
    };
    serde_json::from_value(value)
        .map(Some)
        .map_err(|e| CliError::internal(format!("failed to decode auth org policy: {e}")))
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

    #[derive(Clone, Default)]
    struct MockApiState {
        responses: Arc<Mutex<HashMap<String, VecDeque<MockApiResponse>>>>,
        request_counts: Arc<Mutex<HashMap<String, usize>>>,
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

        let _ = method;
        let _ = body;

        {
            let mut counts = state.request_counts.lock().expect("lock request counts");
            *counts.entry(path.clone()).or_default() += 1;
        }

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

    #[test]
    fn resource_export_error_display_with_http_status() {
        let err = ResourceExportError {
            resource_type: "secrets".to_string(),
            http_status: Some(403),
            message: "forbidden".to_string(),
        };
        assert_eq!(err.display_detail(), "secrets: HTTP 403");
    }

    #[test]
    fn resource_export_error_display_without_http_status() {
        let err = ResourceExportError {
            resource_type: "teams".to_string(),
            http_status: None,
            message: "connection refused".to_string(),
        };
        assert_eq!(err.display_detail(), "teams: connection refused");
    }

    #[test]
    fn format_export_summary_partial_allowed() {
        let errors = vec![
            ResourceExportError {
                resource_type: "secrets".to_string(),
                http_status: Some(500),
                message: "internal error".to_string(),
            },
            ResourceExportError {
                resource_type: "teams".to_string(),
                http_status: None,
                message: "timeout".to_string(),
            },
        ];
        let summary = format_export_summary(&errors, 8, 10, true);
        assert!(summary.contains("8/10"));
        assert!(summary.contains("--allow-partial"));
        assert!(summary.contains("secrets: HTTP 500"));
        assert!(summary.contains("teams: timeout"));
    }

    #[test]
    fn format_export_summary_partial_not_allowed() {
        let errors = vec![ResourceExportError {
            resource_type: "iam".to_string(),
            http_status: Some(401),
            message: "unauthorized".to_string(),
        }];
        let summary = format_export_summary(&errors, 9, 10, false);
        assert!(summary.contains("9/10"));
        assert!(!summary.contains("--allow-partial"));
        assert!(summary.contains("iam: HTTP 401"));
    }

    #[test]
    fn render_manifest_json_produces_valid_json() {
        let manifest = ControlManifest {
            version: "1".to_string(),
            resources: Resources::default(),
        };
        let output = render_manifest(&manifest, true).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["version"], "1");
    }

    #[test]
    fn render_manifest_yaml_produces_valid_yaml() {
        let manifest = ControlManifest {
            version: "1".to_string(),
            resources: Resources::default(),
        };
        let output = render_manifest(&manifest, false).unwrap();
        assert!(output.contains("version"));
    }

    #[test]
    fn write_manifest_atomically_rejects_missing_filename() {
        let path = Path::new("/");
        let err = write_manifest_atomically(path, "data").unwrap_err();
        assert!(err.to_string().contains("missing file name"));
    }

    #[test]
    fn write_manifest_atomically_succeeds_with_valid_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.yaml");
        write_manifest_atomically(&path, "version: 1\n").unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "version: 1\n");
    }

    #[test]
    fn command_helper_coverage_write_manifest_atomically_maps_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("occupied");
        std::fs::create_dir(&path).unwrap();
        let err = write_manifest_atomically(&path, "version: 1\n").unwrap_err();
        assert!(err.to_string().contains("cannot write"));
        assert!(err.to_string().contains("occupied"));
    }

    #[test]
    fn emit_manifest_writes_to_file_in_json_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");
        let manifest = ControlManifest {
            version: "1".to_string(),
            resources: Resources::default(),
        };
        emit_manifest(&manifest, Some(&path), true).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed["version"], "1");
    }

    #[test]
    fn emit_manifest_writes_to_file_in_yaml_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.yaml");
        let manifest = ControlManifest {
            version: "1".to_string(),
            resources: Resources::default(),
        };
        emit_manifest(&manifest, Some(&path), false).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("version"));
    }

    #[test]
    fn export_outcome_empty_manifest_has_no_resources() {
        let outcome = ExportOutcome {
            manifest: ControlManifest {
                version: "1".to_string(),
                resources: Resources::default(),
            },
            errors: vec![],
            total_attempted: 5,
        };
        assert!(outcome.manifest.resources.is_empty());
        assert_eq!(outcome.errors.len(), 0);
    }

    #[test]
    fn partial_export_errors_block_without_allow_partial_flag() {
        let errors = vec![ResourceExportError {
            resource_type: "agents".to_string(),
            http_status: Some(502),
            message: "bad gateway".to_string(),
        }];
        let total = 10;
        let succeeded = total - errors.len();
        let summary = format_export_summary(&errors, succeeded, total, false);
        assert!(summary.contains("9/10"));
        assert!(summary.contains("agents: HTTP 502"));
    }

    #[test]
    fn build_agent_spec_prefers_team_name_and_active_configuration_version() {
        let item = AgentItem {
            name: Some("Analyst".to_string()),
            id: Some("agent-1".to_string()),
            agent_id: None,
            team_name: Some("Security".to_string()),
            team: Some("security-fallback".to_string()),
            gateway_ids: vec!["gw-1".to_string(), "gw-2".to_string()],
            scope_kind: Some("personal".to_string()),
            configuration_id: Some("cfg-1".to_string()),
            active_configuration_version_id: Some("cfgv-active".to_string()),
            configuration_version_id: Some("cfgv-legacy".to_string()),
            resource_name: Some("agent.analyst".to_string()),
            resource_tags: vec![
                crate::managed::control_plane_types::ResourceTagItem {
                    key: Some("department".to_string()),
                    value: Some("security".to_string()),
                    source: Some("user".to_string()),
                },
                crate::managed::control_plane_types::ResourceTagItem {
                    key: Some("ignored".to_string()),
                    value: None,
                    source: Some("user".to_string()),
                },
            ],
            context_fabric: Some(crate::managed::control_manifest::AgentContextFabricSpec {
                capture_mode: Some("auto".to_string()),
                pool_max_entries: Some(500),
                ..crate::managed::control_manifest::AgentContextFabricSpec::default()
            }),
            mcp: Some(crate::managed::control_manifest::AgentMcpSpec {
                allowed_resources: Some(
                    crate::managed::control_manifest::MatchListOrWildcardSpec::Wildcard(
                        "*".to_string(),
                    ),
                ),
                ..crate::managed::control_manifest::AgentMcpSpec::default()
            }),
        };

        let spec = build_agent_spec(&item).unwrap();
        assert_eq!(spec.name, "Analyst");
        assert_eq!(spec.team.as_deref(), Some("Security"));
        assert_eq!(spec.scope_kind.as_deref(), Some("personal"));
        assert_eq!(spec.resource_name.as_deref(), Some("agent.analyst"));
        assert_eq!(spec.gateways, vec!["gw-1", "gw-2"]);
        assert_eq!(spec.resource_tags.len(), 1);
        assert_eq!(spec.resource_tags[0].key, "department");
        assert_eq!(spec.resource_tags[0].value, "security");
        assert_eq!(spec.resource_tags[0].source.as_deref(), Some("user"));
        assert_eq!(
            spec.context_fabric
                .as_ref()
                .and_then(|cfg| cfg.capture_mode.as_deref()),
            Some("auto")
        );
        assert_eq!(
            spec.mcp
                .as_ref()
                .and_then(|cfg| cfg.allowed_resources.as_ref()),
            Some(
                &crate::managed::control_manifest::MatchListOrWildcardSpec::Wildcard(
                    "*".to_string(),
                )
            )
        );

        let deployment = spec.deployment.unwrap();
        assert_eq!(deployment.configuration_id, "cfg-1");
        assert_eq!(deployment.configuration_version_id, "cfgv-active");
        assert_eq!(deployment.rollout_gateways, vec!["gw-1", "gw-2"]);
        assert_eq!(deployment.rollout_reason, None);
    }

    #[test]
    fn build_agent_spec_falls_back_to_team_and_legacy_configuration_version() {
        let item = AgentItem {
            name: Some("Responder".to_string()),
            id: None,
            agent_id: Some("agent-2".to_string()),
            team_name: None,
            team: Some("Incident Response".to_string()),
            gateway_ids: vec![],
            scope_kind: Some("agent_wide".to_string()),
            configuration_id: Some("cfg-2".to_string()),
            active_configuration_version_id: None,
            configuration_version_id: Some("cfgv-legacy".to_string()),
            resource_name: None,
            resource_tags: vec![],
            context_fabric: None,
            mcp: None,
        };

        let spec = build_agent_spec(&item).unwrap();
        assert_eq!(spec.team.as_deref(), Some("Incident Response"));
        assert_eq!(spec.scope_kind.as_deref(), Some("agent_wide"));
        let deployment = spec.deployment.unwrap();
        assert_eq!(deployment.configuration_id, "cfg-2");
        assert_eq!(deployment.configuration_version_id, "cfgv-legacy");
    }

    #[test]
    fn build_agent_spec_skips_missing_name_and_omits_incomplete_deployment() {
        let missing_name = AgentItem {
            name: None,
            id: Some("agent-3".to_string()),
            agent_id: None,
            team_name: None,
            team: None,
            gateway_ids: vec![],
            scope_kind: None,
            configuration_id: None,
            active_configuration_version_id: None,
            configuration_version_id: None,
            resource_name: None,
            resource_tags: vec![],
            context_fabric: None,
            mcp: None,
        };
        assert!(build_agent_spec(&missing_name).is_none());

        let missing_version = AgentItem {
            name: Some("Reviewer".to_string()),
            id: Some("agent-4".to_string()),
            agent_id: None,
            team_name: None,
            team: None,
            gateway_ids: vec!["gw-9".to_string()],
            scope_kind: None,
            configuration_id: Some("cfg-4".to_string()),
            active_configuration_version_id: None,
            configuration_version_id: None,
            resource_name: None,
            resource_tags: vec![],
            context_fabric: None,
            mcp: None,
        };

        let spec = build_agent_spec(&missing_version).unwrap();
        assert!(spec.deployment.is_none());
        assert_eq!(spec.gateways, vec!["gw-9"]);
    }

    #[test]
    fn build_budget_spec_resolves_scope_names_and_preserves_unmapped_ids() {
        let item = BudgetItem {
            id: Some("budget-1".to_string()),
            name: Some("Quarterly".to_string()),
            amount: Some("500.00".to_string()),
            currency: Some("USD".to_string()),
            period_type: Some("monthly".to_string()),
            alert_thresholds: vec![50, 90],
            hard_limit_enabled: Some(true),
            hard_limit_amount: Some("750.00".to_string()),
            team_id: Some("team-1".to_string()),
            user_id: Some("user-42".to_string()),
            agent_id: Some("agent-7".to_string()),
            timezone: Some("UTC".to_string()),
            week_starts_on: Some("monday".to_string()),
            month_anchor_day: Some(1),
            billing_categories: vec!["inference".to_string()],
        };

        let team_names = HashMap::from([("team-1".to_string(), "Operations".to_string())]);
        let user_emails = HashMap::new();
        let agent_names = HashMap::from([("agent-7".to_string(), "Copilot".to_string())]);

        let spec = build_budget_spec(item, &team_names, &user_emails, &agent_names).unwrap();
        assert_eq!(spec.name, "Quarterly");
        assert_eq!(spec.amount, "500.00");
        assert_eq!(spec.team.as_deref(), Some("Operations"));
        assert_eq!(spec.user.as_deref(), Some("user-42"));
        assert_eq!(spec.agent.as_deref(), Some("Copilot"));
        assert_eq!(spec.currency.as_deref(), Some("USD"));
        assert_eq!(spec.period_type.as_deref(), Some("monthly"));
        assert_eq!(spec.alert_thresholds, vec![50, 90]);
        assert_eq!(spec.billing_categories, vec!["inference"]);
    }

    #[test]
    fn build_budget_spec_requires_name_and_amount() {
        let missing_name = BudgetItem {
            id: None,
            name: None,
            amount: Some("100.00".to_string()),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team_id: None,
            user_id: None,
            agent_id: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        };
        let missing_amount = BudgetItem {
            id: None,
            name: Some("No Amount".to_string()),
            amount: None,
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team_id: None,
            user_id: None,
            agent_id: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        };

        let empty = HashMap::new();
        assert!(build_budget_spec(missing_name, &empty, &empty, &empty).is_none());
        assert!(build_budget_spec(missing_amount, &empty, &empty, &empty).is_none());
    }

    #[test]
    fn build_secret_spec_uses_placeholder_env_and_preserves_description() {
        let item = SecretItem {
            name: Some("openai".to_string()),
            description: Some("Primary provider key".to_string()),
            env_var: None,
        };

        let spec = build_secret_spec(&item).unwrap();
        assert_eq!(spec.name, "openai");
        assert_eq!(spec.env, "<SET_ENV_VAR>");
        assert_eq!(spec.description.as_deref(), Some("Primary provider key"));
    }

    #[test]
    fn build_secret_spec_requires_name() {
        let item = SecretItem {
            name: None,
            description: Some("Missing name".to_string()),
            env_var: Some("VERDICTAN_OPENAI_API_KEY".to_string()),
        };
        assert!(build_secret_spec(&item).is_none());
    }

    #[test]
    fn build_iam_policy_spec_preserves_description_and_statements() {
        let statements = serde_json::json!([{ "effect": "allow", "action": ["events:read"] }]);
        let item = PolicyItem {
            name: Some("read-events".to_string()),
            description: Some("Read-only events access".to_string()),
            statements: Some(statements.clone()),
        };

        let spec = build_iam_policy_spec(&item).unwrap();
        assert_eq!(spec.name, "read-events");
        assert_eq!(spec.description.as_deref(), Some("Read-only events access"));
        assert_eq!(spec.statements, Some(statements));
    }

    #[test]
    fn build_iam_role_spec_filters_policy_refs_without_names() {
        let item = RoleItem {
            name: Some("auditor".to_string()),
            policies: vec![
                crate::managed::control_plane_types::RolePolicyRef {
                    name: Some("read-events".to_string()),
                },
                crate::managed::control_plane_types::RolePolicyRef { name: None },
                crate::managed::control_plane_types::RolePolicyRef {
                    name: Some("read-history".to_string()),
                },
            ],
        };

        let spec = build_iam_role_spec(&item).unwrap();
        assert_eq!(spec.name, "auditor");
        assert_eq!(spec.policies, vec!["read-events", "read-history"]);
    }

    #[test]
    fn build_team_spec_preserves_description_and_uses_empty_members() {
        let item = TeamItem {
            id: Some("team-1".to_string()),
            team_id: None,
            name: Some("Operations".to_string()),
            description: Some("Core operators".to_string()),
        };

        let spec = build_team_spec(&item).unwrap();
        assert_eq!(spec.name, "Operations");
        assert_eq!(spec.description.as_deref(), Some("Core operators"));
        assert!(spec.members.is_empty());
    }

    #[test]
    fn build_user_spec_requires_email_and_initializes_empty_memberships() {
        let missing_email = UserItem {
            id: Some("user-1".to_string()),
            user_id: None,
            email: None,
        };
        assert!(build_user_spec(&missing_email).is_none());

        let item = UserItem {
            id: Some("user-2".to_string()),
            user_id: None,
            email: Some("analyst@example.com".to_string()),
        };
        let spec = build_user_spec(&item).unwrap();
        assert_eq!(spec.email, "analyst@example.com");
        assert!(spec.teams.is_empty());
        assert!(spec.roles.is_empty());
    }

    #[test]
    fn build_platform_provider_bundle_spec_requires_key_and_registry() {
        let valid = PlatformProviderBundleItem {
            bundle_key: Some("openai".to_string()),
            provider_registry: Some(serde_json::json!({ "providers": ["openai"] })),
            status: Some("active".to_string()),
        };
        let spec = build_platform_provider_bundle_spec(valid).unwrap();
        assert_eq!(spec.bundle_key, "openai");
        assert_eq!(spec.status.as_deref(), Some("active"));

        let missing_registry = PlatformProviderBundleItem {
            bundle_key: Some("anthropic".to_string()),
            provider_registry: None,
            status: None,
        };
        assert!(build_platform_provider_bundle_spec(missing_registry).is_none());
    }

    #[test]
    fn build_regulated_execution_profile_spec_requires_name_and_deployment_profile() {
        let valid = RegulatedExecutionProfileItem {
            name: Some("Sovereign".to_string()),
            deployment_profile: Some("sovereign_region".to_string()),
            default: Some(true),
            residency_region: Some("eu-west-1".to_string()),
            data_residency_tag: Some("eu".to_string()),
            cross_border_policy: Some("deny_by_default".to_string()),
            tokenization_enabled: Some(true),
            require_in_memory_only: Some(true),
            allow_internet_egress: Some(false),
            workload_class: Some("regulated".to_string()),
            deletion_attestation_enabled: Some(true),
            fail_mode: Some("fail_closed".to_string()),
        };

        let spec = build_regulated_execution_profile_spec(valid).unwrap();
        assert_eq!(spec.name, "Sovereign");
        assert_eq!(spec.deployment_profile, "sovereign_region");
        assert_eq!(spec.default, Some(true));
        assert_eq!(spec.fail_mode.as_deref(), Some("fail_closed"));

        let missing_name = RegulatedExecutionProfileItem {
            name: None,
            deployment_profile: Some("private_cloud".to_string()),
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
        assert!(build_regulated_execution_profile_spec(missing_name).is_none());
    }

    #[test]
    fn build_approval_threshold_spec_defaults_mode_and_required_approvals() {
        let item = ApprovalThresholdItem {
            risk_level: Some("high".to_string()),
            data_class: Some("pii".to_string()),
            destination_pattern: Some("*.prod".to_string()),
            approval_mode: None,
            required_approvals: None,
            decision_ttl_minutes: Some(60),
        };

        let spec = build_approval_threshold_spec(item).unwrap();
        assert_eq!(spec.risk_level, "high");
        assert_eq!(spec.data_class.as_deref(), Some("pii"));
        assert_eq!(spec.approval_mode, "single");
        assert_eq!(spec.required_approvals, 1);
        assert_eq!(spec.decision_ttl_minutes, Some(60));
    }

    #[test]
    fn build_approval_threshold_spec_requires_risk_level() {
        let item = ApprovalThresholdItem {
            risk_level: None,
            data_class: None,
            destination_pattern: None,
            approval_mode: Some("dual".to_string()),
            required_approvals: Some(2),
            decision_ttl_minutes: None,
        };
        assert!(build_approval_threshold_spec(item).is_none());
    }

    #[test]
    fn build_approver_chain_spec_defaults_mode_and_requires_name() {
        let valid = ApproverChainItem {
            name: Some("security-chain".to_string()),
            mode: None,
            approvers: vec!["alice@example.com".to_string()],
            backup_approvers: vec!["bob@example.com".to_string()],
            escalation_after_minutes: Some(30),
        };

        let spec = build_approver_chain_spec(valid).unwrap();
        assert_eq!(spec.name, "security-chain");
        assert_eq!(spec.mode, "single");
        assert_eq!(spec.approvers, vec!["alice@example.com"]);
        assert_eq!(spec.backup_approvers, vec!["bob@example.com"]);
        assert_eq!(spec.escalation_after_minutes, Some(30));

        let missing_name = ApproverChainItem {
            name: None,
            mode: Some("dual".to_string()),
            approvers: vec![],
            backup_approvers: vec![],
            escalation_after_minutes: None,
        };
        assert!(build_approver_chain_spec(missing_name).is_none());
    }

    #[test]
    fn build_approval_policy_spec_filters_invalid_thresholds_and_chains() {
        let item = ApprovalPolicyItem {
            name: Some("production-changes".to_string()),
            description: Some("Protects production mutations".to_string()),
            enabled: Some(true),
            simulation_mode: Some(false),
            break_glass_enabled: Some(true),
            break_glass_post_review_required: Some(true),
            thresholds: vec![
                ApprovalThresholdItem {
                    risk_level: Some("critical".to_string()),
                    data_class: Some("regulated".to_string()),
                    destination_pattern: Some("prod/*".to_string()),
                    approval_mode: Some("dual".to_string()),
                    required_approvals: Some(2),
                    decision_ttl_minutes: Some(15),
                },
                ApprovalThresholdItem {
                    risk_level: None,
                    data_class: None,
                    destination_pattern: None,
                    approval_mode: None,
                    required_approvals: None,
                    decision_ttl_minutes: None,
                },
            ],
            approver_chains: vec![
                ApproverChainItem {
                    name: Some("ops-chain".to_string()),
                    mode: Some("delegated_chain".to_string()),
                    approvers: vec!["ops@example.com".to_string()],
                    backup_approvers: vec![],
                    escalation_after_minutes: Some(10),
                },
                ApproverChainItem {
                    name: None,
                    mode: None,
                    approvers: vec![],
                    backup_approvers: vec![],
                    escalation_after_minutes: None,
                },
            ],
        };

        let spec = build_approval_policy_spec(item).unwrap();
        assert_eq!(spec.name, "production-changes");
        assert_eq!(spec.thresholds.len(), 1);
        assert_eq!(spec.thresholds[0].approval_mode, "dual");
        assert_eq!(spec.approver_chains.len(), 1);
        assert_eq!(spec.approver_chains[0].name, "ops-chain");
    }

    #[test]
    fn build_approval_policy_spec_requires_name() {
        let item = ApprovalPolicyItem {
            name: None,
            description: None,
            enabled: None,
            simulation_mode: None,
            break_glass_enabled: None,
            break_glass_post_review_required: None,
            thresholds: vec![],
            approver_chains: vec![],
        };
        assert!(build_approval_policy_spec(item).is_none());
    }

    #[test]
    fn build_prompt_evaluation_suite_spec_falls_back_to_name_and_filters_tags() {
        let item = PromptSuiteItem {
            name: Some("release-readiness".to_string()),
            resource_name: None,
            description: Some("Regression suite".to_string()),
            enabled: Some(true),
            id: Some("suite-1".to_string()),
            suite_id: None,
            resource_tags: vec![
                crate::managed::control_plane_types::ResourceTagItem {
                    key: Some("env".to_string()),
                    value: Some("prod".to_string()),
                    source: Some("user".to_string()),
                },
                crate::managed::control_plane_types::ResourceTagItem {
                    key: Some("ignored".to_string()),
                    value: None,
                    source: Some("user".to_string()),
                },
            ],
        };

        let spec = build_prompt_evaluation_suite_spec(&item).unwrap();
        assert_eq!(spec.name, "release-readiness");
        assert_eq!(spec.resource_name.as_deref(), Some("release-readiness"));
        assert_eq!(spec.description.as_deref(), Some("Regression suite"));
        assert_eq!(spec.enabled, Some(true));
        assert_eq!(spec.resource_tags.len(), 1);
        assert_eq!(spec.resource_tags[0].key, "env");
    }

    #[test]
    fn resolve_budget_scope_name_prefers_mapped_name_and_falls_back_to_id() {
        let names = HashMap::from([("team-1".to_string(), "Operations".to_string())]);

        assert_eq!(
            resolve_budget_scope_name(Some("team-1".to_string()), &names).as_deref(),
            Some("Operations")
        );
        assert_eq!(
            resolve_budget_scope_name(Some("team-9".to_string()), &names).as_deref(),
            Some("team-9")
        );
        assert_eq!(resolve_budget_scope_name(None, &names), None);
    }

    #[test]
    fn build_hosted_gateway_policy_spec_resolves_agent_name_and_preserves_flags() {
        let response = HostedGatewayPolicyResponse {
            default_agent_id: Some("agent-1".to_string()),
            default_agent_fallback_enabled: Some(true),
            fail_closed_on_missing_binding: Some(false),
        };
        let agent_names = HashMap::from([("agent-1".to_string(), "Copilot".to_string())]);

        let spec = build_hosted_gateway_policy_spec(response, &agent_names);
        assert_eq!(spec.default_agent.as_deref(), Some("Copilot"));
        assert_eq!(spec.default_agent_fallback_enabled, Some(true));
        assert_eq!(spec.fail_closed_on_missing_binding, Some(false));
    }

    #[test]
    fn build_hosted_gateway_binding_spec_resolves_agent_name_or_preserves_id() {
        let names = HashMap::from([("agent-1".to_string(), "Copilot".to_string())]);
        let mapped = AgentBindingResponse {
            binding_mode: Some("explicit".to_string()),
            agent_id: Some("agent-1".to_string()),
        };
        let fallback = AgentBindingResponse {
            binding_mode: Some("explicit".to_string()),
            agent_id: Some("agent-9".to_string()),
        };
        let missing_agent = AgentBindingResponse {
            binding_mode: Some("explicit".to_string()),
            agent_id: None,
        };

        let mapped_spec = build_hosted_gateway_binding_spec("gw-1", mapped, &names).unwrap();
        assert_eq!(mapped_spec.gateway_id, "gw-1");
        assert_eq!(mapped_spec.agent, "Copilot");

        let fallback_spec = build_hosted_gateway_binding_spec("gw-2", fallback, &names).unwrap();
        assert_eq!(fallback_spec.agent, "agent-9");

        assert!(build_hosted_gateway_binding_spec("gw-3", missing_agent, &names).is_none());
    }

    #[test]
    fn budget_scope_sort_key_covers_all_scope_branches() {
        let team = BudgetSpec {
            name: "Team Budget".to_string(),
            amount: "10.00".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: Some("Security".to_string()),
            user: None,
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        };
        let user = BudgetSpec {
            name: "User Budget".to_string(),
            amount: "10.00".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: None,
            user: Some("user@example.com".to_string()),
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        };
        let agent = BudgetSpec {
            name: "Agent Budget".to_string(),
            amount: "10.00".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: None,
            user: None,
            agent: Some("Responder".to_string()),
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        };
        let org = BudgetSpec {
            name: "Org Budget".to_string(),
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
        };

        assert_eq!(budget_scope_sort_key(&team), "team/Security");
        assert_eq!(budget_scope_sort_key(&user), "user/user@example.com");
        assert_eq!(budget_scope_sort_key(&agent), "agent/Responder");
        assert_eq!(budget_scope_sort_key(&org), "org");
    }

    #[test]
    fn budget_sort_uses_scope_key_then_name() {
        let mut specs = vec![
            BudgetSpec {
                name: "Zulu".to_string(),
                amount: "10.00".to_string(),
                currency: None,
                period_type: None,
                alert_thresholds: vec![],
                hard_limit_enabled: None,
                hard_limit_amount: None,
                team: Some("Alpha".to_string()),
                user: None,
                agent: None,
                timezone: None,
                week_starts_on: None,
                month_anchor_day: None,
                billing_categories: vec![],
            },
            BudgetSpec {
                name: "Alpha".to_string(),
                amount: "10.00".to_string(),
                currency: None,
                period_type: None,
                alert_thresholds: vec![],
                hard_limit_enabled: None,
                hard_limit_amount: None,
                team: Some("Alpha".to_string()),
                user: None,
                agent: None,
                timezone: None,
                week_starts_on: None,
                month_anchor_day: None,
                billing_categories: vec![],
            },
            BudgetSpec {
                name: "Org Budget".to_string(),
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
            },
            BudgetSpec {
                name: "User Budget".to_string(),
                amount: "10.00".to_string(),
                currency: None,
                period_type: None,
                alert_thresholds: vec![],
                hard_limit_enabled: None,
                hard_limit_amount: None,
                team: None,
                user: Some("user@example.com".to_string()),
                agent: None,
                timezone: None,
                week_starts_on: None,
                month_anchor_day: None,
                billing_categories: vec![],
            },
            BudgetSpec {
                name: "Agent Budget".to_string(),
                amount: "10.00".to_string(),
                currency: None,
                period_type: None,
                alert_thresholds: vec![],
                hard_limit_enabled: None,
                hard_limit_amount: None,
                team: None,
                user: None,
                agent: Some("Responder".to_string()),
                timezone: None,
                week_starts_on: None,
                month_anchor_day: None,
                billing_categories: vec![],
            },
        ];

        specs.sort_by(|a, b| {
            budget_scope_sort_key(a)
                .cmp(&budget_scope_sort_key(b))
                .then_with(|| a.name.cmp(&b.name))
        });

        let names = specs.into_iter().map(|spec| spec.name).collect::<Vec<_>>();
        assert_eq!(
            names,
            vec!["Agent Budget", "Org Budget", "Alpha", "Zulu", "User Budget",]
        );
    }

    #[tokio::test]
    async fn build_export_manifest_covers_successful_async_exporters() {
        let (client, state, handle) = spawn_mock_api(vec![
            (
                "/v1/secrets".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "secrets": [
                            {
                                "name": "openai",
                                "env_var": "VERDICTAN_OPENAI_API_KEY",
                                "description": "Primary provider key"
                            },
                            {
                                "description": "missing name"
                            }
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
                            {
                                "name": "read-events",
                                "description": "Read event history",
                                "statements": [{ "effect": "allow", "action": ["events:read"] }]
                            },
                            {
                                "description": "missing name"
                            }
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
                            {
                                "name": "analyst",
                                "policies": [{ "name": "read-events" }, { "name": null }]
                            },
                            {
                                "policies": []
                            }
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
                            {
                                "id": "team-1",
                                "name": "Security",
                                "description": "Core operators"
                            },
                            {
                                "id": "team-2"
                            }
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
                            {
                                "id": "user-1",
                                "email": "alice@example.com"
                            },
                            {
                                "id": "user-2"
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
                                "provider_registry": { "targets": ["gpt-5.4"] },
                                "status": "active"
                            },
                            {
                                "bundle_key": "broken-bundle"
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
                            {
                                "id": "agent-1",
                                "name": "Copilot",
                                "team_name": "Security",
                                "gateway_ids": ["gw-eu"],
                                "configuration_id": "cfg-1",
                                "active_configuration_version_id": "cfgv-1",
                                "resource_name": "agent.copilot",
                                "resource_tags": [
                                    { "key": "env", "value": "prod", "source": "user" },
                                    { "key": "ignored", "source": "user" }
                                ]
                            },
                            {
                                "agent_id": "agent-2"
                            }
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
                            {
                                "id": "budget-1",
                                "name": "User Spend",
                                "amount": "25.00",
                                "user_id": "user-1"
                            },
                            {
                                "id": "budget-2",
                                "name": "Team Spend",
                                "amount": "50.00",
                                "team_id": "team-1"
                            },
                            {
                                "id": "budget-3",
                                "amount": "5.00"
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
                            {
                                "name": "zeta",
                                "deployment_profile": "private_cloud"
                            },
                            {
                                "name": "alpha",
                                "deployment_profile": "regulated_saas",
                                "default": true
                            },
                            {
                                "deployment_profile": "missing-name"
                            }
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
                            {
                                "name": "zeta",
                                "thresholds": [{ "risk_level": "high" }],
                                "approver_chains": []
                            },
                            {
                                "name": "alpha",
                                "thresholds": [],
                                "approver_chains": []
                            },
                            {
                                "enabled": true
                            }
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
                                "suite_id": "suite-2",
                                "name": "zeta",
                                "enabled": false
                            },
                            {
                                "id": "suite-1",
                                "name": "alpha",
                                "resource_name": "alpha-prod",
                                "description": "Alpha suite",
                                "enabled": true,
                                "resource_tags": [
                                    { "key": "env", "value": "prod", "source": "user" },
                                    { "key": "ignored", "source": "user" }
                                ]
                            },
                            {
                                "id": "suite-3",
                                "description": "missing name"
                            }
                        ]
                    }),
                )],
            ),
            (
                "/v1/settings/collaboration".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "default_conversation_visibility": "team",
                        "allow_user_sharing": true
                    }),
                )],
            ),
            (
                "/v1/settings/hosted-gateway-policy".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "default_agent": "agent-1",
                        "default_agent_fallback_enabled": true,
                        "fail_closed_on_missing_binding": false
                    }),
                )],
            ),
            (
                "/v1/gateways".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "gateways": [
                            { "id": "gw-us" },
                            { "id": "gw-eu" },
                            {}
                        ]
                    }),
                )],
            ),
            (
                "/v1/gateways/gw-us/agent-binding".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "binding_mode": "implicit",
                        "agent_id": "agent-1"
                    }),
                )],
            ),
            (
                "/v1/gateways/gw-eu/agent-binding".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "binding_mode": "explicit",
                        "agent_id": "agent-1"
                    }),
                )],
            ),
            (
                "/v1/settings/auth-org-policy".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "verified_domains": ["verdictan.com"],
                        "required_sso": true
                    }),
                )],
            ),
        ])
        .await;

        let outcome = build_export_manifest(&client, true).await.unwrap();

        assert!(outcome.errors.is_empty());
        assert_eq!(outcome.total_attempted, 14);
        assert_eq!(state.request_count("/v1/secrets"), 1);
        assert_eq!(state.request_count("/v1/agents"), 3);
        assert_eq!(state.request_count("/v1/teams"), 2);
        assert_eq!(state.request_count("/v1/users"), 2);

        let resources = outcome.manifest.resources;
        assert_eq!(resources.secrets.len(), 1);
        assert_eq!(resources.secrets[0].env, "VERDICTAN_OPENAI_API_KEY");

        let iam = resources.iam.expect("iam export");
        assert_eq!(iam.policies.len(), 1);
        assert_eq!(iam.roles.len(), 1);
        assert_eq!(iam.roles[0].policies, vec!["read-events"]);

        assert_eq!(resources.teams.len(), 1);
        assert_eq!(resources.users.len(), 1);
        assert_eq!(resources.platform_provider_bundles.len(), 1);
        assert_eq!(
            resources.platform_provider_bundles[0].bundle_key,
            "shared-openai"
        );

        assert_eq!(resources.agents.len(), 1);
        assert_eq!(resources.agents[0].name, "Copilot");
        assert_eq!(
            resources.agents[0]
                .deployment
                .as_ref()
                .map(|spec| spec.configuration_version_id.as_str()),
            Some("cfgv-1")
        );

        let budget_names = resources
            .budgets
            .iter()
            .map(|budget| budget.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(budget_names, vec!["Team Spend", "User Spend"]);
        assert_eq!(resources.budgets[0].team.as_deref(), Some("Security"));
        assert_eq!(
            resources.budgets[1].user.as_deref(),
            Some("alice@example.com")
        );

        let regulated_names = resources
            .regulated_execution_profiles
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(regulated_names, vec!["alpha", "zeta"]);

        let approval_names = resources
            .approval_policies
            .iter()
            .map(|policy| policy.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(approval_names, vec!["alpha", "zeta"]);

        let suite_names = resources
            .prompt_evaluation_suites
            .iter()
            .map(|suite| suite.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(suite_names, vec!["alpha", "zeta"]);
        assert_eq!(
            resources.prompt_evaluation_suites[0]
                .resource_name
                .as_deref(),
            Some("alpha-prod")
        );
        assert_eq!(resources.prompt_evaluation_suites[0].resource_tags.len(), 1);

        assert_eq!(
            resources
                .collaboration_defaults
                .as_ref()
                .and_then(|spec| spec.default_conversation_visibility.as_deref()),
            Some("team")
        );
        assert_eq!(
            resources
                .hosted_gateway_policy
                .as_ref()
                .and_then(|spec| spec.default_agent.as_deref()),
            Some("Copilot")
        );
        assert_eq!(resources.hosted_gateway_bindings.len(), 1);
        assert_eq!(resources.hosted_gateway_bindings[0].gateway_id, "gw-eu");
        assert_eq!(resources.hosted_gateway_bindings[0].agent, "Copilot");
        assert_eq!(
            resources
                .auth_org_policy
                .as_ref()
                .map(|spec| spec.verified_domains.clone()),
            Some(vec!["verdictan.com".to_string()])
        );

        handle.abort();
    }

    #[tokio::test]
    async fn build_export_manifest_covers_partial_errors_and_mapping_fallbacks() {
        let (client, state, handle) = spawn_mock_api(vec![
            (
                "/v1/policies".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({"policies": []}),
                )],
            ),
            (
                "/v1/roles".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({"roles": []}),
                )],
            ),
            (
                "/v1/teams".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "teams": [{ "id": "team-1", "name": "Security" }]
                    }),
                )],
            ),
            (
                "/v1/users".to_string(),
                vec![
                    mock_response(
                        StatusCode::OK,
                        serde_json::json!({
                            "users": [{ "id": "user-1", "email": "alice@example.com" }]
                        }),
                    ),
                    mock_response(
                        StatusCode::UNAUTHORIZED,
                        serde_json::json!({"error": "expired token"}),
                    ),
                ],
            ),
            (
                "/v1/admin/platform-provider-bundles?include_archived=true".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({"bundles": []}),
                )],
            ),
            (
                "/v1/agents".to_string(),
                vec![
                    mock_response(
                        StatusCode::OK,
                        serde_json::json!({
                            "agents": [{ "id": "agent-9", "name": "Copilot" }]
                        }),
                    ),
                    mock_response(
                        StatusCode::UNAUTHORIZED,
                        serde_json::json!({"error": "token expired"}),
                    ),
                    mock_response(
                        StatusCode::OK,
                        serde_json::json!({
                            "agents": [{ "id": "agent-9", "name": "Copilot" }]
                        }),
                    ),
                ],
            ),
            (
                "/v1/usage/budgets".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "budgets": [{ "id": "budget-1", "name": "Ops", "amount": "10.00" }]
                    }),
                )],
            ),
            (
                "/v1/settings/regulated-execution-profiles".to_string(),
                vec![mock_response(
                    StatusCode::NOT_FOUND,
                    serde_json::json!({"error": "missing"}),
                )],
            ),
            (
                "/v1/approval-policies".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({"policies": []}),
                )],
            ),
            (
                "/v1/prompt-suites".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "items": [{ "id": "suite-1", "name": "nightly" }]
                    }),
                )],
            ),
            (
                "/v1/settings/collaboration".to_string(),
                vec![mock_response(
                    StatusCode::NOT_FOUND,
                    serde_json::json!({"error": "missing"}),
                )],
            ),
            (
                "/v1/settings/hosted-gateway-policy".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "default_agent": "agent-9",
                        "default_agent_fallback_enabled": false
                    }),
                )],
            ),
            (
                "/v1/gateways".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "gateways": [{ "id": "gw-a" }, { "id": "gw-b" }]
                    }),
                )],
            ),
            (
                "/v1/gateways/gw-a/agent-binding".to_string(),
                vec![mock_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "binding_mode": "explicit",
                        "agent_id": "agent-9"
                    }),
                )],
            ),
            (
                "/v1/gateways/gw-b/agent-binding".to_string(),
                vec![mock_response(
                    StatusCode::NOT_FOUND,
                    serde_json::json!({"error": "missing"}),
                )],
            ),
            (
                "/v1/settings/auth-org-policy".to_string(),
                vec![mock_response(
                    StatusCode::UNAUTHORIZED,
                    serde_json::json!({"error": "expired token"}),
                )],
            ),
        ])
        .await;

        let outcome = build_export_manifest(&client, false).await.unwrap();
        let error_types = outcome
            .errors
            .iter()
            .map(|error| error.resource_type.as_str())
            .collect::<Vec<_>>();

        assert_eq!(outcome.total_attempted, 13);
        assert_eq!(state.request_count("/v1/secrets"), 0);
        assert_eq!(state.request_count("/v1/agents"), 3);
        assert_eq!(error_types, vec!["billing_budgets", "auth_org_policy"]);
        assert!(outcome.manifest.resources.secrets.is_empty());
        assert!(outcome.manifest.resources.budgets.is_empty());
        assert_eq!(
            outcome
                .manifest
                .resources
                .hosted_gateway_policy
                .as_ref()
                .and_then(|spec| spec.default_agent.as_deref()),
            Some("agent-9")
        );
        assert_eq!(outcome.manifest.resources.hosted_gateway_bindings.len(), 1);
        assert_eq!(
            outcome.manifest.resources.hosted_gateway_bindings[0].agent,
            "agent-9"
        );
        assert!(outcome.manifest.resources.auth_org_policy.is_none());

        handle.abort();
    }
}

#[cfg(test)]
mod coverage_expansion_control_export_tests {
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
    use crate::managed::control_plane_types::{AgentItem, PlatformProviderBundleItem, SecretItem};
    use serde_json::json;

    // ── ResourceExportError ─────────────────────────────────────────────

    #[test]
    fn resource_export_error_display_with_status() {
        let err = ResourceExportError {
            resource_type: "secrets".to_string(),
            http_status: Some(403),
            message: "forbidden".to_string(),
        };
        let detail = err.display_detail();
        assert_eq!(detail, "secrets: HTTP 403");
    }

    #[test]
    fn resource_export_error_display_without_status() {
        let err = ResourceExportError {
            resource_type: "agents".to_string(),
            http_status: None,
            message: "network timeout".to_string(),
        };
        let detail = err.display_detail();
        assert_eq!(detail, "agents: network timeout");
    }

    // ── ControlExportArgs defaults ──────────────────────────────────────

    #[test]
    fn control_export_args_default_state() {
        let args = ControlExportArgs {
            file: None,
            include_secret_stubs: false,
            json: false,
            allow_partial: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        assert!(args.file.is_none());
        assert!(!args.include_secret_stubs);
        assert!(!args.json);
        assert!(!args.allow_partial);
        assert_eq!(args.profile, "default");
    }

    // ── BudgetScopeMaps ─────────────────────────────────────────────────

    #[test]
    fn budget_scope_maps_empty() {
        let maps = BudgetScopeMaps {
            agent_id_to_name: HashMap::new(),
            team_id_to_name: HashMap::new(),
            user_id_to_email: HashMap::new(),
        };
        assert!(maps.agent_id_to_name.is_empty());
        assert!(maps.team_id_to_name.is_empty());
        assert!(maps.user_id_to_email.is_empty());
    }

    #[test]
    fn worker6_control_export_summary_formats_partial_and_full_modes() {
        let errors = vec![ResourceExportError {
            resource_type: "users".to_string(),
            http_status: Some(500),
            message: "failed".to_string(),
        }];

        let full = format_export_summary(&errors, 3, 4, false);
        assert!(full.contains("3/4 resources exported successfully"));
        assert!(!full.contains("Partial manifest emitted"));
        assert!(full.contains("users: HTTP 500"));

        let partial = format_export_summary(&errors, 3, 4, true);
        assert!(partial.contains("Partial manifest emitted because --allow-partial was set."));
        assert!(partial.contains("users: HTTP 500"));
    }

    #[cfg(unix)]
    #[test]
    fn worker6_control_export_write_manifest_atomically_rejects_paths_without_filenames() {
        let err = write_manifest_atomically(std::path::Path::new("/"), "payload")
            .expect_err("root path should not be writable as a file");
        assert!(err.to_string().contains("missing file name"));
    }

    #[test]
    fn worker6_control_export_build_secret_and_bundle_specs_cover_fallbacks() {
        let secret = build_secret_spec(&SecretItem {
            name: Some("openai".to_string()),
            description: Some("provider secret".to_string()),
            env_var: None,
        })
        .expect("secret spec");
        assert_eq!(secret.name, "openai");
        assert_eq!(secret.env, "<SET_ENV_VAR>");
        assert_eq!(secret.description.as_deref(), Some("provider secret"));

        let bundle = build_platform_provider_bundle_spec(PlatformProviderBundleItem {
            bundle_key: Some("default".to_string()),
            provider_registry: Some(json!({"openai": {"models": ["gpt-5.4"]}})),
            status: Some("active".to_string()),
        })
        .expect("bundle spec");
        assert_eq!(bundle.bundle_key, "default");
        assert_eq!(bundle.status.as_deref(), Some("active"));

        assert!(
            build_platform_provider_bundle_spec(PlatformProviderBundleItem {
                bundle_key: None,
                provider_registry: Some(json!({})),
                status: None,
            })
            .is_none()
        );
    }

    #[test]
    fn worker6_control_export_build_agent_spec_handles_partial_and_full_deployments() {
        let partial = build_agent_spec(&AgentItem {
            name: Some("partial-agent".to_string()),
            id: Some("agent-1".to_string()),
            agent_id: None,
            team_name: None,
            team: Some("ops".to_string()),
            gateway_ids: vec!["gw-a".to_string()],
            scope_kind: Some("team".to_string()),
            configuration_id: Some("cfg-1".to_string()),
            active_configuration_version_id: None,
            configuration_version_id: None,
            resource_name: None,
            resource_tags: vec![],
            context_fabric: None,
            mcp: None,
        })
        .expect("partial spec");
        assert_eq!(partial.team.as_deref(), Some("ops"));
        assert!(partial.deployment.is_none());

        let full = build_agent_spec(&AgentItem {
            name: Some("full-agent".to_string()),
            id: Some("agent-2".to_string()),
            agent_id: None,
            team_name: Some("platform".to_string()),
            team: Some("fallback".to_string()),
            gateway_ids: vec!["gw-b".to_string()],
            scope_kind: Some("org".to_string()),
            configuration_id: Some("cfg-2".to_string()),
            active_configuration_version_id: Some("cfgv-2".to_string()),
            configuration_version_id: None,
            resource_name: Some("agents/full-agent".to_string()),
            resource_tags: vec![],
            context_fabric: Some(crate::managed::control_manifest::AgentContextFabricSpec {
                enabled: Some(true),
                ..crate::managed::control_manifest::AgentContextFabricSpec::default()
            }),
            mcp: Some(crate::managed::control_manifest::AgentMcpSpec {
                enabled: Some(true),
                ..crate::managed::control_manifest::AgentMcpSpec::default()
            }),
        })
        .expect("full spec");
        assert_eq!(full.team.as_deref(), Some("platform"));
        let deployment = full.deployment.expect("deployment");
        assert_eq!(deployment.configuration_id, "cfg-2");
        assert_eq!(deployment.configuration_version_id, "cfgv-2");
        assert_eq!(deployment.rollout_gateways, vec!["gw-b".to_string()]);
        assert_eq!(
            full.context_fabric.as_ref().and_then(|cfg| cfg.enabled),
            Some(true)
        );
        assert_eq!(full.mcp.as_ref().and_then(|cfg| cfg.enabled), Some(true));
    }

    #[test]
    fn worker6_control_export_budget_scope_helpers_resolve_names_and_sort_keys() {
        let resolved = resolve_budget_scope_name(
            Some("team-1".to_string()),
            &HashMap::from([("team-1".to_string(), "Team One".to_string())]),
        );
        assert_eq!(resolved.as_deref(), Some("Team One"));

        let fallback = resolve_budget_scope_name(Some("user-9".to_string()), &HashMap::new());
        assert_eq!(fallback.as_deref(), Some("user-9"));

        let team_budget = BudgetSpec {
            name: "Team Budget".to_string(),
            amount: "10".to_string(),
            currency: None,
            period_type: None,
            alert_thresholds: vec![],
            hard_limit_enabled: None,
            hard_limit_amount: None,
            team: Some("Team One".to_string()),
            user: None,
            agent: None,
            timezone: None,
            week_starts_on: None,
            month_anchor_day: None,
            billing_categories: vec![],
        };
        let user_budget = BudgetSpec {
            team: None,
            user: Some("alice@example.com".to_string()),
            ..team_budget.clone()
        };
        let agent_budget = BudgetSpec {
            team: None,
            user: None,
            agent: Some("Gateway Agent".to_string()),
            ..team_budget.clone()
        };
        let org_budget = BudgetSpec {
            team: None,
            user: None,
            agent: None,
            ..team_budget.clone()
        };

        assert_eq!(budget_scope_sort_key(&team_budget), "team/Team One");
        assert_eq!(
            budget_scope_sort_key(&user_budget),
            "user/alice@example.com"
        );
        assert_eq!(budget_scope_sort_key(&agent_budget), "agent/Gateway Agent");
        assert_eq!(budget_scope_sort_key(&org_budget), "org");
    }
}
