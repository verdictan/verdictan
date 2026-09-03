// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::error::CliError;
use crate::instances::{
    GatewayInstanceId, GatewayInstanceSpec, PolicyConfigSource, SecretReference,
};
use crate::output::json::print_json;
use crate::supervisor::{default_state_dir, SupervisorStateStore};

#[derive(Debug, Args)]
pub(crate) struct GatewayCreateArgs {
    /// Human-readable display name for the gateway instance.
    /// If you do not set the name, the CLI uses `$HOSTNAME`. If `$HOSTNAME` is
    /// not available, it uses the system hostname.
    #[arg(long)]
    pub(crate) name: Option<String>,

    #[arg(long)]
    pub(crate) gateway_id: Option<String>,

    #[arg(long)]
    pub(crate) listen: String,

    #[arg(long)]
    pub(crate) upstream: String,

    #[arg(long)]
    pub(crate) upstream_api_key_env: Option<String>,

    #[arg(long)]
    pub(crate) upstream_api_key_keychain_service: Option<String>,

    #[arg(long)]
    pub(crate) upstream_api_key_keychain_account: Option<String>,

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

    #[arg(long = "api-token-env")]
    pub(crate) admin_token_env: Option<String>,

    #[arg(long = "api-token-keychain-service")]
    pub(crate) admin_token_keychain_service: Option<String>,

    #[arg(long = "api-token-keychain-account")]
    pub(crate) admin_token_keychain_account: Option<String>,

    #[arg(long, default_value_t = true)]
    pub(crate) admin_local_only: bool,

    #[arg(long)]
    pub(crate) state_dir: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) json: bool,
}

/// Resolve the gateway display name with this sequence:
/// 1. `--name` CLI flag (explicit)
/// 2. `$HOSTNAME` environment variable
/// 3. System hostname with `gethostname` or the `hostname` command
/// 4. Static fallback `"gateway-default"`
fn resolve_gateway_name(arg: Option<String>) -> String {
    resolve_gateway_name_with(arg, std::env::var("HOSTNAME").ok(), system_hostname())
}

/// Pure resolution logic for the gateway display name. Accepts pre-resolved
/// hostname sources so tests can call this without changing the host process
/// environment or spawning subprocesses.
pub(crate) fn resolve_gateway_name_with(
    arg: Option<String>,
    env_hostname: Option<String>,
    sys_hostname: Option<String>,
) -> String {
    if let Some(name) = arg.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        return name.to_string();
    }
    if let Some(hostname) = env_hostname
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return hostname.to_string();
    }
    if let Some(hostname) = sys_hostname
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return hostname.to_string();
    }
    "gateway-default".to_string()
}

fn system_hostname() -> Option<String> {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|h| !h.is_empty())
}

pub(crate) fn run(args: GatewayCreateArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.unwrap_or(default_state_dir()?);
    let mut store = SupervisorStateStore::load(state_dir)?;
    let resolved_name = resolve_gateway_name(args.name);
    let instance_id = GatewayInstanceId::new(resolved_name.clone())?;
    let upstream_api_key = secret_reference(
        args.upstream_api_key_env,
        args.upstream_api_key_keychain_service,
        args.upstream_api_key_keychain_account,
        "upstream api key",
    )?;
    let admin_token = secret_reference(
        args.admin_token_env,
        args.admin_token_keychain_service,
        args.admin_token_keychain_account,
        "proxy api token",
    )?;
    let policy_config_source = PolicyConfigSource::from_paths(
        args.policy_config
            .iter()
            .map(|path| path.display().to_string()),
    );
    let spec = GatewayInstanceSpec::new(
        instance_id,
        args.gateway_id.unwrap_or_else(|| resolved_name.clone()),
        resolved_name,
        args.listen,
        args.upstream,
        upstream_api_key,
        args.upstream_api_key_header,
        args.upstream_api_key_prefix,
        args.fail_mode,
        policy_config_source,
        args.max_concurrency.unwrap_or(16),
        admin_token,
        args.admin_local_only,
    )?;
    store.create_instance(spec.clone())?;

    if args.json {
        return print_json(&serde_json::json!({
            "ok": true,
            "instance": spec,
            "state_dir": store.state_dir(),
        }));
    }

    println!("created proxy instance {}", spec.instance_id);
    println!("gateway id: {}", spec.gateway_id);
    println!("listen: {}", spec.listen_addr);
    println!("upstream: {}", spec.upstream_base_url);
    Ok(())
}

fn secret_reference(
    env_var: Option<String>,
    keychain_service: Option<String>,
    keychain_account: Option<String>,
    label: &str,
) -> Result<Option<SecretReference>, CliError> {
    match (env_var, keychain_service, keychain_account) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => Err(CliError::user(format!(
            "{label} must use either an env var reference or a keychain reference, not both"
        ))),
        (Some(name), None, None) => Ok(Some(SecretReference::env_var(name))),
        (None, Some(service), Some(account)) => {
            Ok(Some(SecretReference::keychain(service, account)))
        }
        (None, None, None) => Ok(None),
        _ => Err(CliError::user(format!(
            "{label} keychain references require both service and account"
        ))),
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
    use crate::instances::SecretReference;

    #[test]
    fn command_helper_coverage_resolve_gateway_name_with_priority_chain() {
        assert_eq!(
            resolve_gateway_name_with(
                Some("cli-name".to_string()),
                Some("env-host".to_string()),
                Some("sys-host".to_string()),
            ),
            "cli-name"
        );
        assert_eq!(
            resolve_gateway_name_with(
                None,
                Some("env-host".to_string()),
                Some("sys-host".to_string())
            ),
            "env-host"
        );
        assert_eq!(
            resolve_gateway_name_with(None, None, Some("sys-host".to_string())),
            "sys-host"
        );
        assert_eq!(
            resolve_gateway_name_with(None, Some("   ".to_string()), None),
            "gateway-default"
        );
    }

    #[test]
    fn command_helper_coverage_secret_reference_rejects_mixed_sources() {
        let error = secret_reference(
            Some("TOKEN_ENV".to_string()),
            Some("service".to_string()),
            Some("account".to_string()),
            "proxy api token",
        )
        .expect_err("env and keychain should conflict");
        assert!(error.to_string().contains("not both"));

        let env_only =
            secret_reference(Some("TOKEN_ENV".to_string()), None, None, "proxy api token")
                .expect("env reference");
        assert_eq!(env_only, Some(SecretReference::env_var("TOKEN_ENV")));

        let keychain = secret_reference(
            None,
            Some("svc".to_string()),
            Some("acct".to_string()),
            "upstream api key",
        )
        .expect("keychain reference");
        assert_eq!(
            keychain,
            Some(SecretReference::keychain(
                "svc".to_string(),
                "acct".to_string()
            ))
        );
    }

    #[test]
    fn resolve_gateway_name_with_all_none_returns_default() {
        assert_eq!(
            resolve_gateway_name_with(None, None, None),
            "gateway-default"
        );
    }

    #[test]
    fn resolve_gateway_name_with_empty_cli_name_falls_through() {
        assert_eq!(
            resolve_gateway_name_with(Some("".to_string()), Some("env-host".to_string()), None,),
            "env-host"
        );
    }

    #[test]
    fn resolve_gateway_name_with_whitespace_env_falls_to_system() {
        assert_eq!(
            resolve_gateway_name_with(None, Some("   ".to_string()), Some("sys-host".to_string())),
            "sys-host"
        );
    }

    #[test]
    fn secret_reference_none_when_all_empty() {
        let result =
            secret_reference(None, None, None, "api key").expect("all-none should succeed");
        assert_eq!(result, None);
    }

    #[test]
    fn secret_reference_keychain_requires_both_service_and_account() {
        let error = secret_reference(None, Some("svc".to_string()), None, "test key")
            .expect_err("keychain needs both");
        assert!(error.to_string().contains("both"));
    }
}
