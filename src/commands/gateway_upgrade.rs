// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use chrono::Utc;
use clap::{Args, Subcommand, ValueEnum};
use tokio::process::Command as TokioCommand;

use crate::supervisor::state_store::InstanceRecord;
use crate::{
    commands::gateway_service::{
        current_platform, install_service, service_file_exists, GatewayServiceInstallSpec,
    },
    error::CliError,
    gateway::runtime_upgrade::{
        RuntimeRollbackRecord, RuntimeServiceManager, RuntimeUpgradeHealthCheck,
        RuntimeUpgradePhase, RuntimeUpgradePlan, RuntimeUpgradeStatus,
    },
    instances::GatewayInstanceStatus,
    output::json::print_json,
    supervisor::{
        default_state_dir, OperationAction, OperationHistoryEntry, OperationOutcome,
        SupervisorStateStore,
    },
};

#[derive(Debug, Args)]
pub struct GatewayUpgradeArgs {
    #[command(subcommand)]
    pub command: GatewayUpgradeCommand,
}

#[derive(Debug, Subcommand)]
pub enum GatewayUpgradeCommand {
    Plan(GatewayUpgradePlanArgs),
    Apply(GatewayUpgradeApplyArgs),
    Status(GatewayUpgradeStatusArgs),
    Rollback(GatewayUpgradeRollbackArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ServiceManagerArg {
    Manual,
    Launchd,
    SystemdUser,
}

impl From<ServiceManagerArg> for RuntimeServiceManager {
    fn from(value: ServiceManagerArg) -> Self {
        match value {
            ServiceManagerArg::Manual => RuntimeServiceManager::Manual,
            ServiceManagerArg::Launchd => RuntimeServiceManager::Launchd,
            ServiceManagerArg::SystemdUser => RuntimeServiceManager::SystemdUser,
        }
    }
}

#[derive(Debug, Args)]
pub struct GatewayUpgradePlanArgs {
    #[arg(long, default_value = "verdictan-proxy")]
    pub name: String,
    #[arg(long)]
    pub target_version: String,
    #[arg(long)]
    pub binary_path: PathBuf,
    #[arg(long)]
    pub config_sha256: Option<String>,
    #[arg(long)]
    pub health_command: Option<String>,
    #[arg(long, default_value_t = 30)]
    pub health_timeout_secs: u64,
    #[arg(long)]
    pub rollback_version: Option<String>,
    #[arg(long)]
    pub rollback_binary_path: Option<PathBuf>,
    #[arg(long, value_enum)]
    pub service_manager: Option<ServiceManagerArg>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long = "yes", default_value_t = false)]
    pub assume_yes: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct GatewayUpgradeApplyArgs {
    #[arg(long, default_value = "verdictan-proxy")]
    pub name: String,
    #[arg(long)]
    pub target_version: Option<String>,
    #[arg(long)]
    pub binary_path: Option<PathBuf>,
    #[arg(long)]
    pub config_sha256: Option<String>,
    #[arg(long)]
    pub health_command: Option<String>,
    #[arg(long, default_value_t = 30)]
    pub health_timeout_secs: u64,
    #[arg(long)]
    pub rollback_version: Option<String>,
    #[arg(long)]
    pub rollback_binary_path: Option<PathBuf>,
    #[arg(long, value_enum)]
    pub service_manager: Option<ServiceManagerArg>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long = "yes", default_value_t = false)]
    pub assume_yes: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct GatewayUpgradeStatusArgs {
    #[arg(long, default_value = "verdictan-proxy")]
    pub name: String,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct GatewayUpgradeRollbackArgs {
    #[arg(long, default_value = "verdictan-proxy")]
    pub name: String,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long = "yes", default_value_t = false)]
    pub assume_yes: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, serde::Serialize)]
struct GatewayUpgradeOutput {
    instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan: Option<RuntimeUpgradePlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<RuntimeUpgradeStatus>,
}

pub async fn run_async(args: GatewayUpgradeArgs) -> Result<(), CliError> {
    match args.command {
        GatewayUpgradeCommand::Plan(args) => run_plan(args).await,
        GatewayUpgradeCommand::Apply(args) => run_apply(args).await,
        GatewayUpgradeCommand::Status(args) => run_status(args),
        GatewayUpgradeCommand::Rollback(args) => run_rollback(args).await,
    }
}

async fn run_plan(args: GatewayUpgradePlanArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.clone().unwrap_or(default_state_dir()?);
    let mut store = SupervisorStateStore::load(&state_dir)?;
    let record = load_record(&store, &args.name)?;
    let plan = build_plan_from_args(
        &record,
        &args.name,
        args.target_version,
        args.binary_path,
        args.config_sha256,
        args.health_command,
        args.health_timeout_secs,
        args.rollback_version,
        args.rollback_binary_path,
        args.service_manager,
    )?;

    let mut status = record.status.clone();
    status.runtime_upgrade_plan = Some(plan.clone());
    status.runtime_upgrade_status = Some(RuntimeUpgradeStatus::from_plan(
        &plan,
        current_active_version(&record.status),
        current_active_binary_path(&record.status)?,
    ));
    status.updated_at = Utc::now().to_rfc3339();
    store.set_status(&args.name, status.clone())?;
    store.append_operation_history(
        &args.name,
        upgrade_history_entry(
            OperationAction::UpgradePlan,
            OperationOutcome::Succeeded,
            Some("runtime upgrade plan recorded".to_string()),
            &record.status,
            Some(plan.target_version.clone()),
            status.runtime_upgrade_status.as_ref(),
        ),
    )?;

    emit_output(
        GatewayUpgradeOutput {
            instance_id: record.spec.instance_id.as_str().to_string(),
            plan: Some(plan),
            status: status.runtime_upgrade_status,
        },
        args.json,
        "planned runtime upgrade",
    )
}

async fn run_apply(args: GatewayUpgradeApplyArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.clone().unwrap_or(default_state_dir()?);
    let mut store = SupervisorStateStore::load(&state_dir)?;
    let record = load_record(&store, &args.name)?;
    let plan = build_plan_from_optional_args(
        &record,
        &args.name,
        args.target_version,
        args.binary_path,
        args.config_sha256,
        args.health_command,
        args.health_timeout_secs,
        args.rollback_version,
        args.rollback_binary_path,
        args.service_manager,
    )?;

    let mut status = record.status.clone();
    status.runtime_upgrade_plan = Some(plan.clone());
    let mut upgrade_status = RuntimeUpgradeStatus::from_plan(
        &plan,
        current_active_version(&record.status),
        current_active_binary_path(&record.status)?,
    );
    upgrade_status.phase = RuntimeUpgradePhase::Applying;
    upgrade_status.updated_at = Some(Utc::now().to_rfc3339());
    status.runtime_upgrade_status = Some(upgrade_status.clone());
    status.last_error = None;
    status.updated_at = Utc::now().to_rfc3339();
    store.set_status(&args.name, status.clone())?;

    apply_service_upgrade(&record, &state_dir, &plan).await?;

    let mut health_check = plan.health_check.clone();
    let mut failure_reason = None;
    if let Some(check) = health_check.as_mut() {
        let result = run_health_check(check).await?;
        *check = result;
        if check.passed != Some(true) {
            failure_reason = Some("runtime upgrade health check failed".to_string());
        }
    }

    let now = Utc::now().to_rfc3339();
    let mut store = SupervisorStateStore::load(&state_dir)?;
    let latest = load_record(&store, &args.name)?;
    let mut latest_status = latest.status.clone();
    let mut applied_status = latest_status
        .runtime_upgrade_status
        .clone()
        .unwrap_or_else(|| RuntimeUpgradeStatus::from_plan(&plan, None, None));
    applied_status.target_version = Some(plan.target_version.clone());
    applied_status.target_binary_path = Some(plan.target_binary_path.clone());
    applied_status.config_sha256 = plan.config_sha256.clone();
    applied_status.service_manager = plan.service_manager;
    applied_status.health_check = health_check.clone();
    applied_status.rollback = Some(plan.rollback.clone());
    applied_status.last_restart_at = Some(now.clone());
    applied_status.updated_at = Some(now.clone());

    let history_outcome = if let Some(reason) = failure_reason.clone() {
        applied_status.phase = RuntimeUpgradePhase::Failed;
        applied_status.last_error = Some(reason.clone());
        latest_status.last_error = Some(reason);
        OperationOutcome::Failed
    } else {
        applied_status.phase = RuntimeUpgradePhase::Succeeded;
        applied_status.active_version = Some(plan.target_version.clone());
        applied_status.active_binary_path = Some(plan.target_binary_path.clone());
        applied_status.last_error = None;
        latest_status.last_error = None;
        OperationOutcome::Succeeded
    };

    latest_status.runtime_upgrade_plan = Some(plan.clone());
    latest_status.runtime_upgrade_status = Some(applied_status.clone());
    latest_status.last_healthcheck_at = Some(now.clone());
    latest_status.last_observed_healthy = Some(history_outcome == OperationOutcome::Succeeded);
    latest_status.updated_at = now.clone();
    store.set_status(&args.name, latest_status.clone())?;
    store.append_operation_history(
        &args.name,
        upgrade_history_entry(
            OperationAction::UpgradeApply,
            history_outcome,
            failure_reason
                .clone()
                .or_else(|| Some("runtime upgrade applied".to_string())),
            &latest.status,
            Some(plan.target_version.clone()),
            latest_status.runtime_upgrade_status.as_ref(),
        ),
    )?;

    if history_outcome == OperationOutcome::Failed {
        return Err(CliError::user(
            failure_reason.unwrap_or_else(|| "runtime upgrade failed".to_string()),
        ));
    }

    emit_output(
        GatewayUpgradeOutput {
            instance_id: latest.spec.instance_id.as_str().to_string(),
            plan: Some(plan),
            status: latest_status.runtime_upgrade_status,
        },
        args.json,
        "applied runtime upgrade",
    )
}

fn run_status(args: GatewayUpgradeStatusArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.clone().unwrap_or(default_state_dir()?);
    let store = SupervisorStateStore::load(&state_dir)?;
    let record = load_record(&store, &args.name)?;
    emit_output(
        GatewayUpgradeOutput {
            instance_id: record.spec.instance_id.as_str().to_string(),
            plan: record.status.runtime_upgrade_plan.clone(),
            status: record.status.runtime_upgrade_status.clone(),
        },
        args.json,
        "runtime upgrade status",
    )
}

async fn run_rollback(args: GatewayUpgradeRollbackArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.clone().unwrap_or(default_state_dir()?);
    let mut store = SupervisorStateStore::load(&state_dir)?;
    let record = load_record(&store, &args.name)?;
    let rollback = rollback_record(&record.status)?;
    let inferred_service_manager = infer_service_manager(&args.name, None)?;

    apply_service_rollback(&record, &state_dir, &rollback).await?;

    let mut status = record.status.clone();
    let mut upgrade_status =
        status
            .runtime_upgrade_status
            .clone()
            .unwrap_or_else(|| RuntimeUpgradeStatus {
                service_manager: inferred_service_manager,
                ..RuntimeUpgradeStatus::default()
            });
    let now = Utc::now().to_rfc3339();
    upgrade_status.phase = RuntimeUpgradePhase::RolledBack;
    upgrade_status.active_version = Some(rollback.version.clone());
    upgrade_status.active_binary_path = Some(rollback.binary_path.clone());
    upgrade_status.target_version = None;
    upgrade_status.target_binary_path = None;
    upgrade_status.last_restart_at = Some(now.clone());
    upgrade_status.last_error = None;
    upgrade_status.rollback = Some(rollback.clone());
    upgrade_status.updated_at = Some(now.clone());

    status.runtime_upgrade_plan = None;
    status.runtime_upgrade_status = Some(upgrade_status.clone());
    status.last_error = None;
    status.last_healthcheck_at = Some(now.clone());
    status.last_observed_healthy = Some(true);
    status.updated_at = now.clone();
    store.set_status(&args.name, status.clone())?;
    store.append_operation_history(
        &args.name,
        upgrade_history_entry(
            OperationAction::UpgradeRollback,
            OperationOutcome::RolledBack,
            Some("runtime rollback applied".to_string()),
            &record.status,
            Some(rollback.version.clone()),
            status.runtime_upgrade_status.as_ref(),
        ),
    )?;

    emit_output(
        GatewayUpgradeOutput {
            instance_id: record.spec.instance_id.as_str().to_string(),
            plan: None,
            status: status.runtime_upgrade_status,
        },
        args.json,
        "rolled back runtime upgrade",
    )
}

fn emit_output(value: GatewayUpgradeOutput, json: bool, label: &str) -> Result<(), CliError> {
    if json {
        return print_json(&value);
    }

    println!("{label}: {}", value.instance_id);
    if let Some(plan) = value.plan.as_ref() {
        println!(
            "plan: target={} binary={} service_manager={}",
            plan.target_version,
            plan.target_binary_path,
            plan.service_manager.as_str()
        );
    }
    if let Some(status) = value.status.as_ref() {
        println!("phase: {}", runtime_phase_label(status.phase));
        if let Some(active_version) = status.active_version.as_deref() {
            println!("active version: {active_version}");
        }
        if let Some(active_binary) = status.active_binary_path.as_deref() {
            println!("active binary: {active_binary}");
        }
        if let Some(target_version) = status.target_version.as_deref() {
            println!("target version: {target_version}");
        }
        if let Some(target_binary) = status.target_binary_path.as_deref() {
            println!("target binary: {target_binary}");
        }
        if let Some(last_restart_at) = status.last_restart_at.as_deref() {
            println!("last restart at: {last_restart_at}");
        }
        if let Some(last_error) = status.last_error.as_deref() {
            println!("last error: {last_error}");
        }
    }
    Ok(())
}

fn load_record(store: &SupervisorStateStore, name: &str) -> Result<InstanceRecord, CliError> {
    store
        .get_instance(name)
        .cloned()
        .ok_or_else(|| CliError::user(format!("instance {name} does not exist")))
}

#[allow(clippy::too_many_arguments)]
fn build_plan_from_args(
    record: &InstanceRecord,
    name: &str,
    target_version: String,
    binary_path: PathBuf,
    config_sha256: Option<String>,
    health_command: Option<String>,
    health_timeout_secs: u64,
    rollback_version: Option<String>,
    rollback_binary_path: Option<PathBuf>,
    service_manager: Option<ServiceManagerArg>,
) -> Result<RuntimeUpgradePlan, CliError> {
    let target_binary_path = validate_binary_path(&binary_path)?;
    let service_manager = infer_service_manager(name, service_manager)?;
    let rollback_binary_path = if let Some(path) = rollback_binary_path {
        validate_binary_path(&path)?
    } else {
        current_active_binary_path(&record.status)?.ok_or_else(|| {
            CliError::user("unable to infer rollback binary path; pass --rollback-binary-path")
        })?
    };
    let rollback_version = rollback_version
        .or_else(|| current_active_version(&record.status))
        .ok_or_else(|| {
            CliError::user("unable to infer rollback version; pass --rollback-version")
        })?;
    let created_at = Utc::now().to_rfc3339();

    Ok(RuntimeUpgradePlan {
        target_version,
        target_binary_path,
        service_manager,
        config_sha256: config_sha256.or_else(|| record.status.observed_config_sha256.clone()),
        health_check: health_command
            .as_deref()
            .map(|command| RuntimeUpgradeHealthCheck {
                command: command.trim().to_string(),
                timeout_secs: health_timeout_secs.max(1),
                working_directory: std::env::current_dir()
                    .ok()
                    .map(|path| path.display().to_string()),
                ..RuntimeUpgradeHealthCheck::default()
            }),
        rollback: RuntimeRollbackRecord {
            version: rollback_version,
            binary_path: rollback_binary_path,
            config_sha256: record.status.observed_config_sha256.clone(),
            recorded_at: created_at.clone(),
            reason: Some("pre-upgrade rollback checkpoint".to_string()),
        },
        created_at,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_plan_from_optional_args(
    record: &InstanceRecord,
    name: &str,
    target_version: Option<String>,
    binary_path: Option<PathBuf>,
    config_sha256: Option<String>,
    health_command: Option<String>,
    health_timeout_secs: u64,
    rollback_version: Option<String>,
    rollback_binary_path: Option<PathBuf>,
    service_manager: Option<ServiceManagerArg>,
) -> Result<RuntimeUpgradePlan, CliError> {
    if target_version.is_none()
        && binary_path.is_none()
        && config_sha256.is_none()
        && health_command.is_none()
        && rollback_version.is_none()
        && rollback_binary_path.is_none()
        && service_manager.is_none()
    {
        return record.status.runtime_upgrade_plan.clone().ok_or_else(|| {
            CliError::user(
                "no runtime upgrade plan found; run `verdictan gateway upgrade plan` first",
            )
        });
    }

    build_plan_from_args(
        record,
        name,
        target_version.ok_or_else(|| CliError::user("--target-version is required"))?,
        binary_path.ok_or_else(|| CliError::user("--binary-path is required"))?,
        config_sha256,
        health_command,
        health_timeout_secs,
        rollback_version,
        rollback_binary_path,
        service_manager,
    )
}

fn validate_binary_path(path: &Path) -> Result<String, CliError> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        CliError::user(format!(
            "runtime binary path {} is not readable: {e}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(CliError::user(format!(
            "runtime binary path {} must point to a file",
            path.display()
        )));
    }
    Ok(path.display().to_string())
}

fn current_binary_path() -> Result<String, CliError> {
    let exe = std::env::current_exe()
        .map_err(|e| CliError::internal(format!("failed to resolve current executable: {e}")))?;
    Ok(exe.display().to_string())
}

fn current_active_version(status: &GatewayInstanceStatus) -> Option<String> {
    status
        .runtime_upgrade_status
        .as_ref()
        .and_then(|value| value.active_version.clone())
        .or_else(|| status.observed_config_version.clone())
}

fn current_active_binary_path(status: &GatewayInstanceStatus) -> Result<Option<String>, CliError> {
    if let Some(value) = status
        .runtime_upgrade_status
        .as_ref()
        .and_then(|value| value.active_binary_path.clone())
    {
        return Ok(Some(value));
    }
    current_binary_path().map(Some)
}

fn infer_service_manager(
    name: &str,
    requested: Option<ServiceManagerArg>,
) -> Result<RuntimeServiceManager, CliError> {
    if let Some(requested) = requested {
        return Ok(requested.into());
    }
    if service_file_exists(name)? {
        return current_platform().map(RuntimeServiceManager::from);
    }
    Ok(RuntimeServiceManager::Manual)
}

async fn apply_service_upgrade(
    record: &InstanceRecord,
    state_dir: &Path,
    plan: &RuntimeUpgradePlan,
) -> Result<(), CliError> {
    if plan.service_manager == RuntimeServiceManager::Manual
        || !service_file_exists(&record.spec.name)?
    {
        return Ok(());
    }
    let spec = build_service_spec(record, state_dir, PathBuf::from(&plan.target_binary_path))?;
    install_service(&spec)?;
    Ok(())
}

async fn apply_service_rollback(
    record: &InstanceRecord,
    state_dir: &Path,
    rollback: &RuntimeRollbackRecord,
) -> Result<(), CliError> {
    if !service_file_exists(&record.spec.name)? {
        return Ok(());
    }
    let spec = build_service_spec(record, state_dir, PathBuf::from(&rollback.binary_path))?;
    install_service(&spec)?;
    Ok(())
}

fn build_service_spec(
    record: &InstanceRecord,
    state_dir: &Path,
    binary_path: PathBuf,
) -> Result<GatewayServiceInstallSpec, CliError> {
    let connected_mode = connected_mode_from_env();
    let mut env = BTreeMap::new();
    env.insert(
        "VERDICTAN_SUPERVISOR_SERVICE_MODE".to_string(),
        "1".to_string(),
    );
    if let Some(secret_ref) = &record.spec.upstream_api_key {
        if let Some(value) = secret_ref.resolve() {
            env.insert("VERDICTAN_UPSTREAM_API_KEY".to_string(), value);
        }
        if let crate::instances::SecretReference::EnvVar { name } = secret_ref {
            env.insert(
                "VERDICTAN_UPSTREAM_API_KEY_SOURCE".to_string(),
                name.clone(),
            );
        }
    }
    if let Some(secret_ref) = &record.spec.admin_token {
        if let Some(value) = secret_ref.resolve() {
            env.insert("VERDICTAN_API_TOKEN".to_string(), value);
        }
        if let crate::instances::SecretReference::EnvVar { name } = secret_ref {
            env.insert("VERDICTAN_API_TOKEN_SOURCE".to_string(), name.clone());
        }
    }
    if let Some(header) = record.spec.upstream_api_key_header.as_ref() {
        env.insert(
            "VERDICTAN_UPSTREAM_API_KEY_HEADER".to_string(),
            header.clone(),
        );
    }
    if let Some(prefix) = record.spec.upstream_api_key_prefix.as_ref() {
        env.insert(
            "VERDICTAN_UPSTREAM_API_KEY_PREFIX".to_string(),
            prefix.clone(),
        );
    }
    populate_service_runtime_env(&mut env);
    if std::env::var("VERDICTAN_AGENT_ID").ok().is_none() {
        if let Some(agent_name) = resolve_agent_name_arg() {
            env.insert("VERDICTAN_AGENT_NAME".to_string(), agent_name);
        }
    }

    Ok(GatewayServiceInstallSpec {
        name: record.spec.name.clone(),
        listen: record.spec.listen_addr.clone(),
        upstream: Some(record.spec.upstream_base_url.clone()),
        policy_configs: record
            .spec
            .policy_config_source
            .path_values()
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        fail_mode: record.spec.fail_mode.clone(),
        max_concurrency: Some(record.spec.max_concurrency),
        connected_mode,
        api_token: std::env::var("VERDICTAN_API_TOKEN").ok(),
        agent_id: std::env::var("VERDICTAN_AGENT_ID")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        env,
        command_override: Some(vec![
            "gateway".to_string(),
            "start".to_string(),
            "--name".to_string(),
            record.spec.instance_id.as_str().to_string(),
            "--state-dir".to_string(),
            state_dir.display().to_string(),
        ]),
        binary_path_override: Some(binary_path),
    })
}

fn connected_mode_from_env() -> bool {
    crate::gateway::gateway_env::gateway_control_plane_connected()
}

fn populate_service_runtime_env(env: &mut BTreeMap<String, String>) {
    if !env.contains_key("VERDICTAN_API_URL") {
        env.insert(
            "VERDICTAN_API_URL".to_string(),
            std::env::var("VERDICTAN_API_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| crate::config::DEFAULT_API_URL.to_string()),
        );
    }
    copy_nonempty_env(env, "VERDICTAN_API_TOKEN");
    copy_nonempty_env(env, "VERDICTAN_OTLP_ENDPOINT");
}

fn copy_nonempty_env(env: &mut BTreeMap<String, String>, key: &str) {
    if env.contains_key(key) {
        return;
    }
    if let Ok(value) = std::env::var(key) {
        if !value.trim().is_empty() {
            env.insert(key.to_string(), value);
        }
    }
}

fn resolve_agent_name_arg() -> Option<String> {
    std::env::var("VERDICTAN_AGENT_NAME")
        .ok()
        .or_else(|| std::env::var("VERDICTAN_AGENT_NAME").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

async fn run_health_check(
    check: &RuntimeUpgradeHealthCheck,
) -> Result<RuntimeUpgradeHealthCheck, CliError> {
    let mut command = TokioCommand::new("/bin/sh");
    command.arg("-c").arg(&check.command);
    if let Some(working_directory) = check.working_directory.as_deref() {
        command.current_dir(working_directory);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = tokio::time::timeout(
        Duration::from_secs(check.timeout_secs.max(1)),
        command.output(),
    )
    .await;

    match output {
        Ok(Ok(output)) => Ok(RuntimeUpgradeHealthCheck {
            command: check.command.clone(),
            timeout_secs: check.timeout_secs,
            working_directory: check.working_directory.clone(),
            last_exit_code: output.status.code(),
            last_stdout_preview: preview_bytes(&output.stdout),
            last_stderr_preview: preview_bytes(&output.stderr),
            passed: Some(output.status.success()),
            checked_at: Some(Utc::now().to_rfc3339()),
        }),
        Ok(Err(error)) => Err(CliError::internal(format!(
            "failed to run upgrade health check: {error}"
        ))),
        Err(_) => Ok(RuntimeUpgradeHealthCheck {
            command: check.command.clone(),
            timeout_secs: check.timeout_secs,
            working_directory: check.working_directory.clone(),
            last_exit_code: None,
            last_stdout_preview: None,
            last_stderr_preview: Some("health check timed out".to_string()),
            passed: Some(false),
            checked_at: Some(Utc::now().to_rfc3339()),
        }),
    }
}

fn preview_bytes(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes).trim().to_string();
    if text.is_empty() {
        return None;
    }
    if text.len() > 240 {
        return Some(format!("{}...", &text[..240]));
    }
    Some(text)
}

fn rollback_record(status: &GatewayInstanceStatus) -> Result<RuntimeRollbackRecord, CliError> {
    status
        .runtime_upgrade_status
        .as_ref()
        .and_then(|value| value.rollback.clone())
        .or_else(|| {
            status
                .runtime_upgrade_plan
                .as_ref()
                .map(|plan| plan.rollback.clone())
        })
        .ok_or_else(|| CliError::user("instance has no runtime rollback checkpoint"))
}

fn upgrade_history_entry(
    action: OperationAction,
    outcome: OperationOutcome,
    reason: Option<String>,
    previous_status: &GatewayInstanceStatus,
    target_version: Option<String>,
    upgrade_status: Option<&RuntimeUpgradeStatus>,
) -> OperationHistoryEntry {
    OperationHistoryEntry {
        action,
        outcome,
        reason,
        previous_version: current_active_version(previous_status),
        previous_sha256: previous_status.observed_config_sha256.clone(),
        target_version,
        target_sha256: upgrade_status.and_then(|value| value.config_sha256.clone()),
        active_version: upgrade_status.and_then(|value| value.active_version.clone()),
        active_sha256: previous_status.observed_config_sha256.clone(),
        recorded_at: Utc::now().to_rfc3339(),
    }
}

fn runtime_phase_label(phase: RuntimeUpgradePhase) -> &'static str {
    match phase {
        RuntimeUpgradePhase::Planned => "planned",
        RuntimeUpgradePhase::Applying => "applying",
        RuntimeUpgradePhase::Succeeded => "succeeded",
        RuntimeUpgradePhase::Failed => "failed",
        RuntimeUpgradePhase::RolledBack => "rolled_back",
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
    use crate::instances::{GatewayInstanceId, GatewayInstanceSpec, PolicyConfigSource};

    fn instance_record(temp_dir: &Path) -> InstanceRecord {
        let spec = GatewayInstanceSpec::new(
            GatewayInstanceId::new("finance_main").expect("instance id"),
            "gateway-finance",
            "finance-main",
            "127.0.0.1:41002",
            "https://api.example.com",
            None,
            None,
            None,
            "block",
            PolicyConfigSource::path(temp_dir.join("policy.yaml").display().to_string()),
            8,
            None,
            true,
        )
        .expect("spec");
        InstanceRecord {
            spec,
            status: GatewayInstanceStatus {
                observed_config_version: Some("2.0.0".to_string()),
                observed_config_sha256: Some("sha-observed".to_string()),
                runtime_upgrade_status: Some(RuntimeUpgradeStatus {
                    phase: RuntimeUpgradePhase::Succeeded,
                    active_version: Some("2.0.0".to_string()),
                    active_binary_path: Some("/opt/verdictan/bin/verdictan-prev".to_string()),
                    target_version: Some("2.0.0".to_string()),
                    target_binary_path: Some("/opt/verdictan/bin/verdictan-prev".to_string()),
                    service_manager: RuntimeServiceManager::SystemdUser,
                    config_sha256: Some("sha-observed".to_string()),
                    last_restart_at: None,
                    last_error: None,
                    health_check: None,
                    rollback: None,
                    updated_at: Some("2026-07-05T00:00:00Z".to_string()),
                }),
                ..GatewayInstanceStatus::default()
            },
            operations_history: Vec::new(),
            rollout_plan: None,
        }
    }

    #[test]
    fn build_plan_uses_existing_runtime_as_rollback_checkpoint() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp.path().join("policy.yaml"), "version: 1\n").expect("policy");
        let target = temp.path().join("verdictan-new");
        std::fs::write(&target, "binary").expect("binary");
        let record = instance_record(temp.path());

        let plan = build_plan_from_args(
            &record,
            "finance-main",
            "2.1.0".to_string(),
            target,
            None,
            Some("true".to_string()),
            15,
            None,
            None,
            Some(ServiceManagerArg::SystemdUser),
        )
        .expect("plan");

        assert_eq!(plan.target_version, "2.1.0");
        assert_eq!(plan.rollback.version, "2.0.0");
        assert_eq!(
            plan.rollback.binary_path,
            "/opt/verdictan/bin/verdictan-prev"
        );
        assert_eq!(plan.service_manager, RuntimeServiceManager::SystemdUser);
    }
}
