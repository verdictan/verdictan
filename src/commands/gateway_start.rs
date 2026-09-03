// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use chrono::Utc;
use clap::Args;

use crate::commands::gateway_history::build_operation_entry;
use crate::commands::gateway_service::{
    current_platform, service_file_exists, start_service, ServicePlatform,
};
use crate::error::CliError;
use crate::gateway::runtime_upgrade::RuntimeServiceManager;
use crate::instances::status::{ConfigVerificationState, GatewayInstanceLifecycle};
use crate::supervisor::{
    default_state_dir, OperationAction, OperationOutcome, SupervisorStateStore,
};

#[derive(Debug, Args)]
pub(crate) struct GatewayStartArgs {
    #[arg(long)]
    pub(crate) name: String,

    #[arg(long)]
    pub(crate) state_dir: Option<std::path::PathBuf>,
}

pub(crate) fn run(args: GatewayStartArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.unwrap_or(default_state_dir()?);
    let mut store = SupervisorStateStore::load(&state_dir)?;
    let record = store
        .get_instance(&args.name)
        .cloned()
        .ok_or_else(|| CliError::user(format!("instance {} does not exist", args.name)))?;

    let mut starting_status = record.status.clone();
    starting_status.lifecycle = GatewayInstanceLifecycle::Starting;
    starting_status.last_error = None;
    starting_status.verification_state = ConfigVerificationState::Pending;
    starting_status.updated_at = Utc::now().to_rfc3339();
    store.set_status(&args.name, starting_status)?;

    let runtime_config =
        match crate::runtime::RuntimeInstanceConfig::from_instance_spec(&record.spec) {
            Ok(runtime_config) => runtime_config,
            Err(err) => {
                let mut failed_status = record.status.clone();
                failed_status.lifecycle = GatewayInstanceLifecycle::Failed;
                failed_status.last_error = Some(err.to_string());
                failed_status.updated_at = Utc::now().to_rfc3339();
                store.set_status(&args.name, failed_status)?;
                return Err(err);
            }
        };

    let invoked_by_service = std::env::var("VERDICTAN_SUPERVISOR_SERVICE_MODE")
        .ok()
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !invoked_by_service && service_file_exists(&args.name)? {
        let (platform, path) = match start_service(&args.name) {
            Ok(result) => result,
            Err(err) => {
                let _ = store.append_operation_history(
                    &args.name,
                    build_operation_entry(
                        OperationAction::Start,
                        OperationOutcome::Failed,
                        Some(err.to_string()),
                        &record,
                    ),
                );
                return Err(err);
            }
        };
        let mut running_status = record.status.clone();
        running_status.lifecycle = GatewayInstanceLifecycle::Running;
        running_status.observed_config_version =
            Some(runtime_config.loaded_config.config_version.clone());
        running_status.observed_config_sha256 =
            Some(runtime_config.loaded_config.config_sha256.clone());
        running_status.desired_config_version = running_status.observed_config_version.clone();
        running_status.desired_config_sha256 = running_status.observed_config_sha256.clone();
        running_status.last_known_good_version = running_status.observed_config_version.clone();
        running_status.last_known_good_sha256 = running_status.observed_config_sha256.clone();
        running_status.verification_state = ConfigVerificationState::Verified;
        running_status.last_verified_at = Some(Utc::now().to_rfc3339());
        running_status.last_healthcheck_at = Some(Utc::now().to_rfc3339());
        running_status.last_observed_healthy = Some(true);
        running_status.last_seen_at = Some(Utc::now().to_rfc3339());
        running_status.updated_at = Utc::now().to_rfc3339();
        store.set_status(&args.name, running_status)?;
        store.append_operation_history(
            &args.name,
            build_operation_entry(
                OperationAction::Start,
                OperationOutcome::Succeeded,
                Some(format!("started via {}", platform_name(&platform))),
                &record,
            ),
        )?;
        println!("started {} service {}", platform.display_name(), args.name);
        println!("service file: {}", path.display());
        return Ok(());
    }

    let mut running_status = record.status.clone();
    running_status.lifecycle = GatewayInstanceLifecycle::Running;
    running_status.observed_config_version =
        Some(runtime_config.loaded_config.config_version.clone());
    running_status.observed_config_sha256 =
        Some(runtime_config.loaded_config.config_sha256.clone());
    running_status.desired_config_version = running_status.observed_config_version.clone();
    running_status.desired_config_sha256 = running_status.observed_config_sha256.clone();
    running_status.last_known_good_version = running_status.observed_config_version.clone();
    running_status.last_known_good_sha256 = running_status.observed_config_sha256.clone();
    running_status.verification_state = ConfigVerificationState::Verified;
    running_status.last_verified_at = Some(Utc::now().to_rfc3339());
    running_status.last_healthcheck_at = Some(Utc::now().to_rfc3339());
    running_status.last_observed_healthy = Some(true);
    running_status.last_seen_at = Some(Utc::now().to_rfc3339());
    running_status.updated_at = Utc::now().to_rfc3339();
    store.set_status(&args.name, running_status)?;
    apply_runtime_upgrade_env(&record.status);

    let result = run_gateway_runtime(runtime_config);

    let mut store = SupervisorStateStore::load(&state_dir)?;

    match result {
        Ok(()) => {
            let record = store
                .get_instance(&args.name)
                .cloned()
                .ok_or_else(|| CliError::user(format!("instance {} does not exist", args.name)))?;
            let mut stopped_status = record.status;
            stopped_status.lifecycle = GatewayInstanceLifecycle::Stopped;
            stopped_status.verification_state = ConfigVerificationState::Verified;
            stopped_status.last_seen_at = Some(Utc::now().to_rfc3339());
            stopped_status.updated_at = Utc::now().to_rfc3339();
            store.set_status(&args.name, stopped_status)?;
            Ok(())
        }
        Err(err) => {
            let record = store
                .get_instance(&args.name)
                .cloned()
                .ok_or_else(|| CliError::user(format!("instance {} does not exist", args.name)))?;
            let mut failed_status = record.status;
            failed_status.lifecycle = GatewayInstanceLifecycle::Failed;
            failed_status.last_error = Some(err.to_string());
            failed_status.verification_state = ConfigVerificationState::Failed;
            failed_status.last_healthcheck_at = Some(Utc::now().to_rfc3339());
            failed_status.last_observed_healthy = Some(false);
            failed_status.last_seen_at = Some(Utc::now().to_rfc3339());
            failed_status.updated_at = Utc::now().to_rfc3339();
            store.set_status(&args.name, failed_status)?;
            Err(err)
        }
    }
}

fn apply_runtime_upgrade_env(status: &crate::instances::status::GatewayInstanceStatus) {
    let runtime_status = status.runtime_upgrade_status.as_ref();
    let active_binary_path = runtime_status
        .and_then(|value| value.active_binary_path.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .map(|path| path.display().to_string())
        });
    let active_version = runtime_status
        .and_then(|value| value.active_version.clone())
        .or_else(|| status.observed_config_version.clone());
    let service_manager = runtime_status
        .map(|value| value.service_manager)
        .unwrap_or_else(infer_runtime_service_manager);
    set_optional_env(
        "VERDICTAN_RUNTIME_ACTIVE_VERSION",
        active_version.as_deref(),
    );
    set_optional_env(
        "VERDICTAN_RUNTIME_ACTIVE_BINARY_PATH",
        active_binary_path.as_deref(),
    );
    set_optional_env(
        "VERDICTAN_RUNTIME_TARGET_VERSION",
        runtime_status.and_then(|value| value.target_version.as_deref()),
    );
    set_optional_env(
        "VERDICTAN_RUNTIME_TARGET_BINARY_PATH",
        runtime_status.and_then(|value| value.target_binary_path.as_deref()),
    );
    set_optional_env(
        "VERDICTAN_RUNTIME_LAST_RESTART_AT",
        runtime_status.and_then(|value| value.last_restart_at.as_deref()),
    );
    set_optional_env(
        "VERDICTAN_RUNTIME_UPGRADE_PHASE",
        runtime_status.map(|value| value.phase.as_str()),
    );
    std::env::set_var(
        "VERDICTAN_RUNTIME_SERVICE_MANAGER",
        service_manager.as_str(),
    );
}

fn infer_runtime_service_manager() -> RuntimeServiceManager {
    match current_platform() {
        Ok(platform) => RuntimeServiceManager::from(platform),
        Err(_) => RuntimeServiceManager::Manual,
    }
}

fn set_optional_env(name: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        std::env::set_var(name, value);
    } else {
        std::env::remove_var(name);
    }
}

fn run_gateway_runtime(
    runtime_config: crate::runtime::RuntimeInstanceConfig,
) -> Result<(), CliError> {
    #[cfg(test)]
    if let Some(result) = test_runtime_result_from_env() {
        let _ = runtime_config;
        return result;
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::internal(format!("failed to build tokio runtime: {e}")))?;
    rt.block_on(async move {
        crate::telemetry::init(true)?;
        runtime_config.run_until_ctrl_c().await
    })
}

#[cfg(test)]
fn test_runtime_result_from_env() -> Option<Result<(), CliError>> {
    match std::env::var("VERDICTAN_TEST_GATEWAY_START_RUNTIME_RESULT").ok() {
        Some(value) if value == "ok" => Some(Ok(())),
        Some(value) if value.starts_with("err:") => Some(Err(CliError::internal(
            value.trim_start_matches("err:").to_string(),
        ))),
        Some(value) => Some(Err(CliError::internal(format!(
            "unsupported VERDICTAN_TEST_GATEWAY_START_RUNTIME_RESULT={value}"
        )))),
        None => None,
    }
}

fn platform_name(platform: &ServicePlatform) -> &'static str {
    platform.display_name()
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
    use super::{run, GatewayStartArgs};
    use crate::commands::gateway_service::{install_service, GatewayServiceInstallSpec};
    use crate::instances::status::{ConfigVerificationState, GatewayInstanceLifecycle};
    use crate::instances::{
        GatewayInstanceId, GatewayInstanceSpec, GatewayInstanceStatus, PolicyConfigSource,
    };
    use crate::supervisor::{OperationAction, OperationOutcome, SupervisorStateStore};
    use std::{collections::BTreeMap, path::PathBuf};

    struct TestEnvGuard {
        keys: Vec<&'static str>,
    }

    impl TestEnvGuard {
        fn new(pairs: &[(&'static str, String)]) -> Self {
            for (key, value) in pairs {
                crate::test_support::set_var(key, value);
            }
            Self {
                keys: pairs.iter().map(|(key, _)| *key).collect(),
            }
        }
    }

    impl Drop for TestEnvGuard {
        fn drop(&mut self) {
            for key in &self.keys {
                crate::test_support::unset_var(key);
            }
        }
    }

    fn write_policy(dir: &std::path::Path, name: &str, version: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(
            &path,
            format!(
                "pack:\n  version: \"{version}\"\npolicies:\n  chain:\n    - quality-scorer: {{}}\n"
            ),
        )
        .expect("write policy");
        path
    }

    fn instance_spec(name: &str, policy_source: PolicyConfigSource) -> GatewayInstanceSpec {
        GatewayInstanceSpec::new(
            GatewayInstanceId::new(name).expect("instance id"),
            format!("{name}_gw"),
            name,
            "127.0.0.1:41002",
            "https://api.example.com",
            None,
            None,
            None,
            "block",
            policy_source,
            8,
            None,
            true,
        )
        .expect("instance spec")
    }

    fn create_instance(state_dir: &std::path::Path, spec: GatewayInstanceSpec) {
        let mut store = SupervisorStateStore::load(state_dir).expect("load store");
        store.create_instance(spec).expect("create instance");
    }

    fn load_status(
        state_dir: &std::path::Path,
        name: &str,
    ) -> (
        GatewayInstanceStatus,
        crate::supervisor::state_store::InstanceRecord,
    ) {
        let store = SupervisorStateStore::load(state_dir).expect("reload store");
        let record = store.get_instance(name).cloned().expect("instance");
        (record.status.clone(), record)
    }

    fn service_spec(name: &str) -> GatewayServiceInstallSpec {
        GatewayServiceInstallSpec {
            name: name.to_string(),
            listen: "127.0.0.1:41002".to_string(),
            upstream: Some("https://api.example.com".to_string()),
            policy_configs: Vec::new(),
            fail_mode: "block".to_string(),
            max_concurrency: Some(8),
            connected_mode: false,
            api_token: None,
            agent_id: None,
            env: BTreeMap::new(),
            command_override: None,
            binary_path_override: None,
        }
    }

    #[test]
    fn run_starts_managed_service_and_records_success() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        let policy_path = write_policy(temp.path(), "policy.yaml", "1.2.3");
        create_instance(
            &state_dir,
            instance_spec(
                "finance_main",
                PolicyConfigSource::path(policy_path.display().to_string()),
            ),
        );

        let _env = TestEnvGuard::new(&[
            (
                "VERDICTAN_TEST_HOME",
                temp.path().to_string_lossy().to_string(),
            ),
            ("VERDICTAN_TEST_SERVICE_PLATFORM", "launchd".to_string()),
            (
                "VERDICTAN_TEST_SERVICE_COMMAND_LOG",
                temp.path()
                    .join("commands.log")
                    .to_string_lossy()
                    .to_string(),
            ),
        ]);
        install_service(&service_spec("finance_main")).expect("install service");

        run(GatewayStartArgs {
            name: "finance_main".to_string(),
            state_dir: Some(state_dir.clone()),
        })
        .expect("start service");

        let (status, record) = load_status(&state_dir, "finance_main");
        assert_eq!(status.lifecycle, GatewayInstanceLifecycle::Running);
        assert_eq!(status.verification_state, ConfigVerificationState::Verified);
        assert_eq!(status.observed_config_version.as_deref(), Some("1.2.3"));
        assert_eq!(
            status.desired_config_version,
            status.observed_config_version
        );
        let history = record.operations_history.last().expect("history");
        assert_eq!(history.action, OperationAction::Start);
        assert_eq!(history.outcome, OperationOutcome::Succeeded);
        assert!(history
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("launchd"));
    }

    #[test]
    fn run_marks_instance_stopped_after_runtime_exits_cleanly() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        let policy_path = write_policy(temp.path(), "runtime.yaml", "2.0.0");
        create_instance(
            &state_dir,
            instance_spec(
                "runtime_main",
                PolicyConfigSource::path(policy_path.display().to_string()),
            ),
        );

        let _env = TestEnvGuard::new(&[
            ("VERDICTAN_SUPERVISOR_SERVICE_MODE", "true".to_string()),
            (
                "VERDICTAN_TEST_GATEWAY_START_RUNTIME_RESULT",
                "ok".to_string(),
            ),
        ]);

        run(GatewayStartArgs {
            name: "runtime_main".to_string(),
            state_dir: Some(state_dir.clone()),
        })
        .expect("runtime run");

        let (status, record) = load_status(&state_dir, "runtime_main");
        assert_eq!(status.lifecycle, GatewayInstanceLifecycle::Stopped);
        assert_eq!(status.verification_state, ConfigVerificationState::Verified);
        assert_eq!(status.observed_config_version.as_deref(), Some("2.0.0"));
        assert!(record.operations_history.is_empty());
    }

    #[test]
    fn run_marks_instance_failed_when_runtime_returns_error() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        let policy_path = write_policy(temp.path(), "runtime-fail.yaml", "3.0.0");
        create_instance(
            &state_dir,
            instance_spec(
                "runtime_fail",
                PolicyConfigSource::path(policy_path.display().to_string()),
            ),
        );

        let _env = TestEnvGuard::new(&[
            ("VERDICTAN_SUPERVISOR_SERVICE_MODE", "1".to_string()),
            (
                "VERDICTAN_TEST_GATEWAY_START_RUNTIME_RESULT",
                "err:runtime exploded".to_string(),
            ),
        ]);

        let error = run(GatewayStartArgs {
            name: "runtime_fail".to_string(),
            state_dir: Some(state_dir.clone()),
        })
        .expect_err("runtime failure");

        assert!(error.to_string().contains("runtime exploded"));
        let (status, _) = load_status(&state_dir, "runtime_fail");
        assert_eq!(status.lifecycle, GatewayInstanceLifecycle::Failed);
        assert_eq!(status.verification_state, ConfigVerificationState::Failed);
        assert!(status
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("runtime exploded"));
        assert_eq!(status.last_observed_healthy, Some(false));
    }

    #[test]
    fn run_marks_instance_failed_when_runtime_config_cannot_load() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        create_instance(
            &state_dir,
            instance_spec(
                "broken_runtime",
                PolicyConfigSource::path(temp.path().join("missing.yaml").display().to_string()),
            ),
        );

        let error = run(GatewayStartArgs {
            name: "broken_runtime".to_string(),
            state_dir: Some(state_dir.clone()),
        })
        .expect_err("missing config");

        assert!(error.to_string().contains("failed to read"));
        let (status, _) = load_status(&state_dir, "broken_runtime");
        assert_eq!(status.lifecycle, GatewayInstanceLifecycle::Failed);
        assert!(status
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("failed to read"));
    }

    #[test]
    fn run_fails_for_nonexistent_instance() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        std::fs::create_dir_all(&state_dir).expect("create state dir");

        let error = run(GatewayStartArgs {
            name: "nonexistent".to_string(),
            state_dir: Some(state_dir),
        })
        .expect_err("instance should not exist");
        assert!(error.to_string().contains("does not exist"));
    }

    #[test]
    fn args_debug_impl() {
        let args = GatewayStartArgs {
            name: "prod-gw".to_string(),
            state_dir: Some(std::path::PathBuf::from("/var/lib/verdictan")),
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("prod-gw"));
        assert!(debug.contains("/var/lib/verdictan"));
    }
}
