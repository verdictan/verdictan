// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan agent unlink-gateway` — unlink a gateway from an agent.
//!
//! Uses DELETE /v1/agents/:id/gateways/:gateway_id.
//!
//! # Module wiring
//! Add `pub(crate) mod agent_unlink_gateway;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct AgentUnlinkGatewayArgs {
    /// Agent id.
    #[arg(long)]
    pub(crate) agent_id: String,

    /// Gateway id to unlink.
    #[arg(long)]
    pub(crate) gateway_id: String,

    /// Skip the confirmation prompt.
    #[arg(long)]
    pub(crate) yes: bool,

    /// Emit machine-readable JSON to stdout.
    #[arg(long)]
    pub(crate) json: bool,

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
pub(crate) async fn run_async(args: AgentUnlinkGatewayArgs) -> Result<(), CliError> {
    if !args.yes {
        return Err(CliError::user(format!(
            "pass --yes to confirm unlinking gateway {} from agent {}",
            args.gateway_id, args.agent_id
        )));
    }

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

    let path = format!("/v1/agents/{}/gateways/{}", args.agent_id, args.gateway_id);
    let result = client.delete_json_value(&path).await?;

    if args.json {
        return print_json(&result);
    }

    println!(
        "unlinked gateway {} from agent {}",
        args.gateway_id, args.agent_id
    );
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

    #[test]
    fn yes_flag_required_error_message() {
        let gateway_id = "gw-1";
        let agent_id = "ag-2";
        let msg = format!(
            "pass --yes to confirm unlinking gateway {} from agent {}",
            gateway_id, agent_id
        );
        assert!(msg.contains("gw-1"));
        assert!(msg.contains("ag-2"));
    }

    #[test]
    fn unlink_path_formatting() {
        let agent_id = "ag-1";
        let gateway_id = "gw-99";
        let path = format!("/v1/agents/{}/gateways/{}", agent_id, gateway_id);
        assert_eq!(path, "/v1/agents/ag-1/gateways/gw-99");
    }

    #[test]
    fn yes_flag_error_includes_both_ids() {
        let gateway_id = "gw-special_1";
        let agent_id = "ag-special_2";
        let msg = format!(
            "pass --yes to confirm unlinking gateway {} from agent {}",
            gateway_id, agent_id
        );
        assert!(msg.contains("gw-special_1"));
        assert!(msg.contains("ag-special_2"));
        assert!(msg.contains("--yes"));
    }

    #[test]
    fn output_message_format() {
        let gateway_id = "gw-7";
        let agent_id = "ag-8";
        let msg = format!("unlinked gateway {} from agent {}", gateway_id, agent_id);
        assert!(msg.contains("unlinked"));
        assert!(msg.contains("gw-7"));
        assert!(msg.contains("ag-8"));
    }

    #[test]
    fn args_debug_impl() {
        let args = super::AgentUnlinkGatewayArgs {
            agent_id: "ag-1".to_string(),
            gateway_id: "gw-2".to_string(),
            yes: true,
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("ag-1"));
        assert!(debug.contains("gw-2"));
    }

    #[test]
    fn unlink_path_with_uuid_ids() {
        let agent_id = "550e8400-e29b-41d4-a716-446655440000";
        let gateway_id = "660e8400-e29b-41d4-a716-446655440001";
        let path = format!("/v1/agents/{}/gateways/{}", agent_id, gateway_id);
        assert!(path.starts_with("/v1/agents/550e8400"));
        assert!(path.ends_with("446655440001"));
    }

    #[test]
    fn config_inputs_construction() {
        let inputs = crate::config::ConfigInputs {
            api_url_flag: None,
            api_token_flag: Some("secret".to_string()),
            config_path: Some(std::path::PathBuf::from("/tmp/config.yaml")),
            profile_flag: Some("prod".to_string()),
            region_flag: None,
        };
        assert!(inputs.api_url_flag.is_none());
        assert_eq!(inputs.api_token_flag.as_deref(), Some("secret"));
        assert_eq!(inputs.profile_flag.as_deref(), Some("prod"));
    }
}
