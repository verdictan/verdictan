// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use chrono::Utc;
use clap::Args;

use crate::commands::gateway_history::build_operation_entry;
use crate::commands::gateway_service::stop_service;
use crate::error::CliError;
use crate::instances::status::GatewayInstanceLifecycle;
use crate::supervisor::{
    default_state_dir, OperationAction, OperationOutcome, SupervisorStateStore,
};

#[derive(Debug, Args)]
pub(crate) struct GatewayStopArgs {
    #[arg(long)]
    pub(crate) name: String,

    #[arg(long)]
    pub(crate) state_dir: Option<std::path::PathBuf>,
}

pub(crate) fn run(args: GatewayStopArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.unwrap_or(default_state_dir()?);
    let mut store = SupervisorStateStore::load(&state_dir)?;

    if store.get_instance(&args.name).is_some() {
        let record = store
            .get_instance(&args.name)
            .cloned()
            .ok_or_else(|| CliError::user(format!("instance {} does not exist", args.name)))?;
        if let Err(err) = stop_service(&args.name) {
            let _ = store.append_operation_history(
                &args.name,
                build_operation_entry(
                    OperationAction::Stop,
                    OperationOutcome::Failed,
                    Some(err.to_string()),
                    &record,
                ),
            );
            return Err(err);
        }
        let mut status = record.status.clone();
        status.lifecycle = GatewayInstanceLifecycle::Stopped;
        status.last_seen_at = Some(Utc::now().to_rfc3339());
        status.updated_at = Utc::now().to_rfc3339();
        store.set_status(&args.name, status)?;
        store.append_operation_history(
            &args.name,
            build_operation_entry(
                OperationAction::Stop,
                OperationOutcome::Succeeded,
                Some("service stop requested".to_string()),
                &record,
            ),
        )?;
        println!("stopped {}", args.name);
        return Ok(());
    }

    stop_service(&args.name)?;
    println!("stopped {}", args.name);
    Ok(())
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
    use super::{run, GatewayStopArgs};
    use crate::commands::gateway_service::{install_service, GatewayServiceInstallSpec};
    use crate::instances::status::GatewayInstanceLifecycle;
    use crate::instances::{GatewayInstanceId, GatewayInstanceSpec, PolicyConfigSource};
    use crate::supervisor::{OperationAction, OperationOutcome, SupervisorStateStore};
    use std::collections::BTreeMap;

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

    fn create_instance(state_dir: &std::path::Path, name: &str) {
        let mut store = SupervisorStateStore::load(state_dir).expect("load store");
        let spec = GatewayInstanceSpec::new(
            GatewayInstanceId::new(name).expect("instance id"),
            format!("{name}_gw"),
            name,
            "127.0.0.1:41002",
            "https://api.example.com",
            None,
            None,
            None,
            "block",
            PolicyConfigSource::Empty,
            8,
            None,
            true,
        )
        .expect("spec");
        store.create_instance(spec).expect("create instance");
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
    fn run_updates_supervisor_state_and_history_on_success() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        create_instance(&state_dir, "finance_main");

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

        run(GatewayStopArgs {
            name: "finance_main".to_string(),
            state_dir: Some(state_dir.clone()),
        })
        .expect("stop instance");

        let store = SupervisorStateStore::load(&state_dir).expect("reload store");
        let record = store.get_instance("finance_main").expect("instance");
        assert_eq!(record.status.lifecycle, GatewayInstanceLifecycle::Stopped);
        let history = record.operations_history.last().expect("history");
        assert_eq!(history.action, OperationAction::Stop);
        assert_eq!(history.outcome, OperationOutcome::Succeeded);
        assert_eq!(history.reason.as_deref(), Some("service stop requested"));
    }

    #[test]
    fn run_records_failed_stop_when_service_manager_errors() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        create_instance(&state_dir, "missing_service");

        let _env = TestEnvGuard::new(&[
            (
                "VERDICTAN_TEST_HOME",
                temp.path().to_string_lossy().to_string(),
            ),
            ("VERDICTAN_TEST_SERVICE_PLATFORM", "launchd".to_string()),
        ]);

        let error = run(GatewayStopArgs {
            name: "missing_service".to_string(),
            state_dir: Some(state_dir.clone()),
        })
        .expect_err("missing service");

        assert!(error.to_string().contains("is not installed"));
        let store = SupervisorStateStore::load(&state_dir).expect("reload store");
        let record = store.get_instance("missing_service").expect("instance");
        let history = record.operations_history.last().expect("history");
        assert_eq!(history.action, OperationAction::Stop);
        assert_eq!(history.outcome, OperationOutcome::Failed);
    }

    #[test]
    fn run_stops_service_even_without_supervisor_record() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");

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
        install_service(&service_spec("orphaned")).expect("install service");

        run(GatewayStopArgs {
            name: "orphaned".to_string(),
            state_dir: Some(state_dir),
        })
        .expect("stop orphaned service");
    }

    #[test]
    fn args_debug_impl() {
        let args = GatewayStopArgs {
            name: "finance-gw".to_string(),
            state_dir: Some(std::path::PathBuf::from("/tmp/state")),
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("finance-gw"));
        assert!(debug.contains("/tmp/state"));
    }

    #[test]
    fn args_default_state_dir_is_none() {
        let args = GatewayStopArgs {
            name: "test-gw".to_string(),
            state_dir: None,
        };
        assert!(args.state_dir.is_none());
        assert_eq!(args.name, "test-gw");
    }
}
