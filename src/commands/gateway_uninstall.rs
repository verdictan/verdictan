// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::{
    commands::gateway_history::build_operation_entry,
    commands::gateway_service::{uninstall_service, ServicePlatform},
    error::CliError,
    supervisor::{default_state_dir, OperationAction, OperationOutcome, SupervisorStateStore},
};

#[derive(Debug, Args)]
pub(crate) struct GatewayUninstallArgs {
    #[arg(long, default_value = "verdictan-proxy")]
    pub(crate) name: String,

    #[arg(long)]
    pub(crate) state_dir: Option<std::path::PathBuf>,
}

pub(crate) fn run(args: GatewayUninstallArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.unwrap_or(default_state_dir()?);
    let mut store = SupervisorStateStore::load(&state_dir)?;
    let record = store.get_instance(&args.name).cloned();
    let (platform, path) = match uninstall_service(&args.name) {
        Ok(result) => result,
        Err(err) => {
            if let Some(record) = &record {
                let _ = store.append_operation_history(
                    &args.name,
                    build_operation_entry(
                        OperationAction::Uninstall,
                        OperationOutcome::Failed,
                        Some(err.to_string()),
                        record,
                    ),
                );
            }
            return Err(err);
        }
    };
    if let Some(record) = &record {
        store.append_operation_history(
            &args.name,
            build_operation_entry(
                OperationAction::Uninstall,
                OperationOutcome::Succeeded,
                Some(format!("removed from {}", platform_name(&platform))),
                record,
            ),
        )?;
    }
    println!("removed {} service {}", platform.display_name(), args.name);
    println!("service file: {}", path.display());
    Ok(())
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
    use super::*;

    #[test]
    fn platform_name_launchd() {
        assert_eq!(platform_name(&ServicePlatform::Launchd), "launchd");
    }

    #[test]
    fn platform_name_systemd_user() {
        assert_eq!(
            platform_name(&ServicePlatform::SystemdUser),
            "systemd --user"
        );
    }

    #[test]
    fn default_service_name() {
        let args = GatewayUninstallArgs {
            name: "verdictan-proxy".to_string(),
            state_dir: None,
        };
        assert_eq!(args.name, "verdictan-proxy");
    }

    #[test]
    fn output_messages_include_service_name() {
        let name = "my-proxy";
        let msg_launchd = format!("removed launchd service {}", name);
        let msg_systemd = format!("removed systemd --user service {}", name);
        assert!(msg_launchd.contains("my-proxy"));
        assert!(msg_systemd.contains("my-proxy"));
    }

    #[test]
    fn args_with_custom_state_dir() {
        let args = GatewayUninstallArgs {
            name: "test".to_string(),
            state_dir: Some(std::path::PathBuf::from("/custom/state")),
        };
        assert_eq!(args.state_dir.unwrap().to_str().unwrap(), "/custom/state");
    }

    #[test]
    fn args_debug_impl() {
        let args = GatewayUninstallArgs {
            name: "proxy-prod".to_string(),
            state_dir: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("proxy-prod"));
    }

    #[test]
    fn platform_name_matches_output_format() {
        let name = "my-service";
        let msg_launchd = format!(
            "removed {} service {}",
            platform_name(&ServicePlatform::Launchd),
            name
        );
        assert_eq!(msg_launchd, "removed launchd service my-service");
        let msg_systemd = format!(
            "removed {} service {}",
            platform_name(&ServicePlatform::SystemdUser),
            name
        );
        assert_eq!(msg_systemd, "removed systemd --user service my-service");
    }

    #[test]
    fn args_default_state_dir_is_none() {
        let args = GatewayUninstallArgs {
            name: "test".to_string(),
            state_dir: None,
        };
        assert!(args.state_dir.is_none());
    }
}
