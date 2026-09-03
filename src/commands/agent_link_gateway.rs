// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan agent link-gateway` — link a gateway to an agent.
//!
//! Uses POST /v1/agents/:id/gateways to attach a proxy/gateway instance.
//! A subsequent call with the same gateway_id is idempotent (the API will
//! update an existing link via PUT if needed).
//!
//! # Module wiring
//! Add `pub(crate) mod agent_link_gateway;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct AgentLinkGatewayArgs {
    /// Agent id.
    #[arg(long)]
    pub(crate) agent_id: String,

    /// Gateway / proxy id to link.
    #[arg(long)]
    pub(crate) gateway_id: String,

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
pub(crate) async fn run_async(args: AgentLinkGatewayArgs) -> Result<(), CliError> {
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

    let path = format!("/v1/agents/{}/gateways", args.agent_id);
    let body = serde_json::json!({ "gateway_id": args.gateway_id });
    let result = client.post_json_value(&path, &body).await?;

    if args.json {
        return print_json(&result);
    }

    println!(
        "linked gateway {} to agent {}",
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
    use serde_json::json;

    #[test]
    fn link_path_formatting() {
        let agent_id = "ag-1";
        let path = format!("/v1/agents/{}/gateways", agent_id);
        assert_eq!(path, "/v1/agents/ag-1/gateways");
    }

    #[test]
    fn link_body_construction() {
        let gateway_id = "gw-42";
        let body = json!({ "gateway_id": gateway_id });
        assert_eq!(body["gateway_id"], "gw-42");
    }

    #[test]
    fn link_output_message() {
        let gateway_id = "gw-100";
        let agent_id = "ag-200";
        let msg = format!("linked gateway {} to agent {}", gateway_id, agent_id);
        assert!(msg.contains("gw-100"));
        assert!(msg.contains("ag-200"));
    }

    #[test]
    fn link_path_with_special_chars() {
        let agent_id = "ag-uuid-550e8400-e29b";
        let path = format!("/v1/agents/{}/gateways", agent_id);
        assert_eq!(path, "/v1/agents/ag-uuid-550e8400-e29b/gateways");
    }

    #[test]
    fn link_body_preserves_gateway_id_exactly() {
        let gateway_id = "gw-with-dashes_and_underscores";
        let body = json!({ "gateway_id": gateway_id });
        assert_eq!(body["gateway_id"], "gw-with-dashes_and_underscores");
    }

    #[test]
    fn args_debug_impl() {
        let args = super::AgentLinkGatewayArgs {
            agent_id: "ag-1".to_string(),
            gateway_id: "gw-2".to_string(),
            json: false,
            config: None,
            api_url: Some("https://api.test".to_string()),
            api_token: None,
            profile: "default".to_string(),
            region: Some("us-east-1".to_string()),
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("ag-1"));
        assert!(debug.contains("gw-2"));
        assert!(debug.contains("us-east-1"));
    }

    #[test]
    fn config_inputs_construction() {
        let inputs = crate::config::ConfigInputs {
            api_url_flag: Some("https://api.example.com".to_string()),
            api_token_flag: Some("tok".to_string()),
            config_path: None,
            profile_flag: Some("default".to_string()),
            region_flag: Some("eu-west-1".to_string()),
        };
        assert_eq!(
            inputs.api_url_flag.as_deref(),
            Some("https://api.example.com")
        );
        assert_eq!(inputs.region_flag.as_deref(), Some("eu-west-1"));
    }
}
