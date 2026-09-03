// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::BTreeMap;

use clap::Args;

use crate::{
    commands::gateway_history::build_operation_entry,
    commands::gateway_service::{install_service, GatewayServiceInstallSpec, ServicePlatform},
    error::CliError,
    supervisor::{default_state_dir, OperationAction, OperationOutcome, SupervisorStateStore},
};

fn connected_mode_from_env() -> bool {
    crate::gateway::gateway_env::gateway_control_plane_connected()
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

fn populate_service_runtime_env(env: &mut BTreeMap<String, String>, _connected_mode: bool) {
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

#[derive(Debug, Args)]
pub(crate) struct GatewayInstallArgs {
    #[arg(long, default_value = "verdictan-proxy")]
    pub(crate) name: String,

    #[arg(long)]
    pub(crate) listen: Option<String>,

    #[arg(long)]
    pub(crate) upstream: Option<String>,

    #[arg(long)]
    pub(crate) upstream_api_key_header: Option<String>,

    #[arg(long)]
    pub(crate) upstream_api_key_prefix: Option<String>,

    #[arg(long, default_value = "block", value_parser = ["allow", "block"])]
    pub(crate) fail_mode: String,

    #[arg(long)]
    pub(crate) policy_config: Vec<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) max_concurrency: Option<usize>,

    #[arg(long)]
    pub(crate) agent_id: Option<String>,

    #[arg(long)]
    pub(crate) agent_name: Option<String>,

    #[arg(long)]
    pub(crate) state_dir: Option<std::path::PathBuf>,
}

fn resolve_agent_id_arg(value: Option<String>) -> Option<String> {
    value
        .or_else(|| std::env::var("VERDICTAN_AGENT_ID").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn resolve_agent_name_arg(value: Option<String>) -> Option<String> {
    value
        .or_else(|| std::env::var("VERDICTAN_AGENT_NAME").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn run(args: GatewayInstallArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.clone().unwrap_or(default_state_dir()?);
    let mut store = SupervisorStateStore::load(&state_dir)?;
    let connected_mode = connected_mode_from_env();
    if let Some(record) = store.get_instance(&args.name) {
        let record = record.clone();
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
        populate_service_runtime_env(&mut env, connected_mode);

        let agent_id = resolve_agent_id_arg(args.agent_id.clone());
        if agent_id.is_none() {
            if let Some(agent_name) = resolve_agent_name_arg(args.agent_name.clone()) {
                env.insert("VERDICTAN_AGENT_NAME".to_string(), agent_name);
            }
        }

        let spec = GatewayServiceInstallSpec {
            name: args.name.clone(),
            listen: record.spec.listen_addr.clone(),
            upstream: Some(record.spec.upstream_base_url.clone()),
            policy_configs: record
                .spec
                .policy_config_source
                .path_values()
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect(),
            fail_mode: record.spec.fail_mode.clone(),
            max_concurrency: Some(record.spec.max_concurrency),
            connected_mode,
            api_token: None,
            agent_id,
            env,
            command_override: Some(vec![
                "gateway".to_string(),
                "start".to_string(),
                "--name".to_string(),
                record.spec.instance_id.as_str().to_string(),
                "--state-dir".to_string(),
                state_dir.display().to_string(),
            ]),
            binary_path_override: None,
        };

        let (platform, path) = match install_service(&spec) {
            Ok(result) => result,
            Err(err) => {
                let _ = store.append_operation_history(
                    &args.name,
                    build_operation_entry(
                        OperationAction::Install,
                        OperationOutcome::Failed,
                        Some(err.to_string()),
                        &record,
                    ),
                );
                return Err(err);
            }
        };
        store.append_operation_history(
            &args.name,
            build_operation_entry(
                OperationAction::Install,
                OperationOutcome::Succeeded,
                Some(format!("installed via {}", platform_name(&platform))),
                &record,
            ),
        )?;
        println!(
            "installed {} service {}",
            platform.display_name(),
            args.name
        );
        println!("service file: {}", path.display());
        return Ok(());
    }

    let upstream = args
        .upstream
        .or_else(|| std::env::var("VERDICTAN_UPSTREAM_URL").ok())
        .or_else(|| {
            if !connected_mode {
                Some(super::gateway_run::DEFAULT_HOSTED_UPSTREAM_URL.to_string())
            } else {
                None
            }
        });

    let mut env = BTreeMap::new();
    if let Ok(value) = std::env::var("VERDICTAN_UPSTREAM_API_KEY") {
        env.insert("VERDICTAN_UPSTREAM_API_KEY".to_string(), value);
    }
    if let Some(value) = args
        .upstream_api_key_header
        .or_else(|| std::env::var("VERDICTAN_UPSTREAM_API_KEY_HEADER").ok())
    {
        env.insert("VERDICTAN_UPSTREAM_API_KEY_HEADER".to_string(), value);
    }
    if let Some(value) = args
        .upstream_api_key_prefix
        .or_else(|| std::env::var("VERDICTAN_UPSTREAM_API_KEY_PREFIX").ok())
    {
        env.insert("VERDICTAN_UPSTREAM_API_KEY_PREFIX".to_string(), value);
    }
    if let Ok(value) = std::env::var("VERDICTAN_API_TOKEN") {
        env.insert("VERDICTAN_API_TOKEN".to_string(), value);
    }
    populate_service_runtime_env(&mut env, connected_mode);

    let agent_id = resolve_agent_id_arg(args.agent_id);
    if agent_id.is_none() {
        if let Some(agent_name) = resolve_agent_name_arg(args.agent_name) {
            env.insert("VERDICTAN_AGENT_NAME".to_string(), agent_name);
        }
    }

    let spec = GatewayServiceInstallSpec {
        name: args.name.clone(),
        listen: args
            .listen
            .unwrap_or_else(|| super::gateway_run::DEFAULT_LISTEN_ADDR.to_string()),
        upstream,
        policy_configs: args.policy_config,
        fail_mode: args.fail_mode,
        max_concurrency: args.max_concurrency,
        connected_mode,
        api_token: None,
        agent_id,
        env,
        command_override: None,
        binary_path_override: None,
    };

    let (platform, path) = install_service(&spec)?;
    println!(
        "installed {} service {}",
        platform.display_name(),
        args.name
    );
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
    use crate::config::test_env_lock;

    #[test]
    fn command_helper_coverage_resolve_agent_id_arg_prefers_flag_then_env() {
        let _env_lock = test_env_lock().lock().expect("env lock");
        assert_eq!(
            resolve_agent_id_arg(Some("  agent-flag  ".to_string())),
            Some("agent-flag".to_string())
        );

        let env_name = "VERDICTAN_AGENT_ID";
        std::env::set_var(env_name, "  agent-env  ");
        assert_eq!(resolve_agent_id_arg(None), Some("agent-env".to_string()));
        std::env::remove_var(env_name);

        assert_eq!(resolve_agent_id_arg(Some("   ".to_string())), None);
    }

    #[test]
    fn command_helper_coverage_resolve_agent_name_arg_checks_aliases() {
        let _env_lock = test_env_lock().lock().expect("env lock");
        assert_eq!(
            resolve_agent_name_arg(Some("  display-name  ".to_string())),
            Some("display-name".to_string())
        );

        std::env::set_var("VERDICTAN_AGENT_NAME", "env-agent");
        assert_eq!(resolve_agent_name_arg(None), Some("env-agent".to_string()));
        std::env::remove_var("VERDICTAN_AGENT_NAME");

        std::env::set_var("VERDICTAN_AGENT_NAME", "verdictan-agent");
        assert_eq!(
            resolve_agent_name_arg(None),
            Some("verdictan-agent".to_string())
        );
        std::env::remove_var("VERDICTAN_AGENT_NAME");
    }

    #[test]
    fn command_helper_coverage_copy_nonempty_env_skips_existing_and_blank_values() {
        let _env_lock = test_env_lock().lock().expect("env lock");
        let mut env = BTreeMap::from([("VERDICTAN_API_TOKEN".to_string(), "preset".to_string())]);
        std::env::set_var("VERDICTAN_API_TOKEN", "from-env");
        copy_nonempty_env(&mut env, "VERDICTAN_API_TOKEN");
        assert_eq!(
            env.get("VERDICTAN_API_TOKEN").map(String::as_str),
            Some("preset")
        );

        std::env::set_var("VERDICTAN_OTLP_ENDPOINT", "   ");
        copy_nonempty_env(&mut env, "VERDICTAN_OTLP_ENDPOINT");
        assert!(!env.contains_key("VERDICTAN_OTLP_ENDPOINT"));

        std::env::set_var("VERDICTAN_OTLP_ENDPOINT", "http://otel:4317");
        copy_nonempty_env(&mut env, "VERDICTAN_OTLP_ENDPOINT");
        assert_eq!(
            env.get("VERDICTAN_OTLP_ENDPOINT").map(String::as_str),
            Some("http://otel:4317")
        );
        std::env::remove_var("VERDICTAN_API_TOKEN");
        std::env::remove_var("VERDICTAN_OTLP_ENDPOINT");
    }

    #[test]
    fn command_helper_coverage_populate_service_runtime_env_uses_defaults_and_copies() {
        let _env_lock = test_env_lock().lock().expect("env lock");
        let mut env = BTreeMap::new();
        std::env::remove_var("VERDICTAN_API_URL");
        std::env::set_var("VERDICTAN_API_TOKEN", "runtime-token");

        populate_service_runtime_env(&mut env, false);

        assert_eq!(
            env.get("VERDICTAN_API_URL").map(String::as_str),
            Some(crate::config::DEFAULT_API_URL)
        );
        assert_eq!(
            env.get("VERDICTAN_API_TOKEN").map(String::as_str),
            Some("runtime-token")
        );

        std::env::remove_var("VERDICTAN_API_TOKEN");
    }

    #[test]
    fn resolve_agent_id_arg_returns_none_for_all_blank() {
        let _env_lock = test_env_lock().lock().expect("env lock");
        std::env::remove_var("VERDICTAN_AGENT_ID");
        assert_eq!(resolve_agent_id_arg(None), None);
    }

    #[test]
    fn resolve_agent_name_arg_returns_none_when_all_unset() {
        let _env_lock = test_env_lock().lock().expect("env lock");
        std::env::remove_var("VERDICTAN_AGENT_NAME");
        std::env::remove_var("VERDICTAN_AGENT_NAME");
        assert_eq!(resolve_agent_name_arg(None), None);
    }

    #[test]
    fn connected_mode_from_env_always_true() {
        assert!(connected_mode_from_env());
    }

    #[test]
    fn platform_name_returns_expected_strings() {
        assert_eq!(platform_name(&ServicePlatform::Launchd), "launchd");
        assert_eq!(
            platform_name(&ServicePlatform::SystemdUser),
            "systemd --user"
        );
    }
}
