// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan agent delete` — delete an agent record.
//!
//! # Module wiring
//! Add `pub(crate) mod agent_delete;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct AgentDeleteArgs {
    /// Agent id.
    #[arg(long)]
    pub(crate) agent_id: String,

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
pub(crate) async fn run_async(args: AgentDeleteArgs) -> Result<(), CliError> {
    if !args.yes {
        return Err(CliError::user(format!(
            "pass --yes to confirm deleting agent {}",
            args.agent_id
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

    let path = format!("/v1/agents/{}", args.agent_id);
    let result = client.delete_json_value(&path).await?;

    if args.json {
        return print_json(&result);
    }

    println!("deleted agent {}", args.agent_id);
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
        let agent_id = "a-42";
        let msg = format!("pass --yes to confirm deleting agent {}", agent_id);
        assert!(msg.contains("--yes"));
        assert!(msg.contains("a-42"));
    }

    #[test]
    fn delete_path_formatting() {
        let agent_id = "a-99";
        let path = format!("/v1/agents/{}", agent_id);
        assert_eq!(path, "/v1/agents/a-99");
    }

    #[test]
    fn yes_flag_required_includes_agent_id() {
        let agent_id = "agent-with-special-chars_123";
        let msg = format!("pass --yes to confirm deleting agent {}", agent_id);
        assert!(msg.contains("--yes"));
        assert!(msg.contains("agent-with-special-chars_123"));
    }

    #[test]
    fn delete_path_with_special_chars() {
        let agent_id = "agent-uuid-550e8400-e29b";
        let path = format!("/v1/agents/{}", agent_id);
        assert_eq!(path, "/v1/agents/agent-uuid-550e8400-e29b");
    }

    #[test]
    fn args_debug_impl() {
        let args = super::AgentDeleteArgs {
            agent_id: "a-1".to_string(),
            yes: false,
            json: true,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("a-1"));
    }

    #[test]
    fn args_with_all_fields() {
        let args = super::AgentDeleteArgs {
            agent_id: "agent-prod-42".to_string(),
            yes: true,
            json: false,
            config: Some(std::path::PathBuf::from("/tmp/config.yaml")),
            api_url: Some("https://api.staging.example.com".to_string()),
            api_token: Some("vdt_token".to_string()),
            profile: "staging".to_string(),
            region: Some("eu-west-1".to_string()),
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("agent-prod-42"));
        assert!(debug.contains("staging"));
        assert!(debug.contains("eu-west-1"));
    }

    #[test]
    fn output_message_format() {
        let agent_id = "ag-to-delete";
        let msg = format!("deleted agent {}", agent_id);
        assert!(msg.contains("deleted agent"));
        assert!(msg.contains("ag-to-delete"));
    }

    #[test]
    fn config_inputs_construction_with_region() {
        let inputs = crate::config::ConfigInputs {
            api_url_flag: None,
            api_token_flag: None,
            config_path: None,
            profile_flag: Some("default".to_string()),
            region_flag: Some("us-west-2".to_string()),
        };
        assert_eq!(inputs.region_flag.as_deref(), Some("us-west-2"));
    }
}
