// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan role show-actions` — display the effective actions granted or denied by a role.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct RoleShowActionsArgs {
    /// Role id.
    #[arg(long)]
    pub(crate) role_id: String,

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
pub(crate) async fn run_async(args: RoleShowActionsArgs) -> Result<(), CliError> {
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

    let path = format!("/v1/roles/{}/effective-actions", args.role_id);
    let value = client.get_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    let actions = value
        .get("effective_actions")
        .and_then(|actions| actions.as_array())
        .cloned()
        .unwrap_or_default();

    if actions.is_empty() {
        println!("no effective actions");
        return Ok(());
    }

    for action in actions {
        let effect = action
            .get("effect")
            .and_then(|value| value.as_str())
            .unwrap_or("-");
        let action_name = action
            .get("action")
            .and_then(|value| value.as_str())
            .unwrap_or("-");
        let resource = action
            .get("resource")
            .and_then(|value| value.as_str())
            .unwrap_or("-");
        let source_policy = action
            .get("source_policy")
            .and_then(|value| value.as_str())
            .unwrap_or("-");
        println!("{effect}\t{action_name}\t{resource}\t{source_policy}");
    }

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
    fn effective_actions_path_formatting() {
        let role_id = "r-42";
        let path = format!("/v1/roles/{}/effective-actions", role_id);
        assert_eq!(path, "/v1/roles/r-42/effective-actions");
    }

    #[test]
    fn parse_effective_actions_response() {
        let value = json!({"effective_actions": [
            {"effect": "allow", "action": "read", "resource": "*", "source_policy": "pol-1"},
            {"effect": "deny", "action": "delete", "resource": "secrets:*", "source_policy": "pol-2"}
        ]});
        let actions = value
            .get("effective_actions")
            .and_then(|a| a.as_array())
            .unwrap();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0]["effect"], "allow");
        assert_eq!(actions[1]["effect"], "deny");
    }

    #[test]
    fn parse_effective_actions_empty() {
        let value = json!({"effective_actions": []});
        let actions = value
            .get("effective_actions")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(actions.is_empty());
    }

    #[test]
    fn parse_action_field_defaults() {
        let action = json!({});
        assert_eq!(
            action.get("effect").and_then(|v| v.as_str()).unwrap_or("-"),
            "-"
        );
        assert_eq!(
            action.get("action").and_then(|v| v.as_str()).unwrap_or("-"),
            "-"
        );
        assert_eq!(
            action
                .get("resource")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
            "-"
        );
        assert_eq!(
            action
                .get("source_policy")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
            "-"
        );
    }
}
