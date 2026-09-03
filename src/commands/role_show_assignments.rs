// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan role show-assignments` — display users, teams, and tokens assigned to a role.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct RoleShowAssignmentsArgs {
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
pub(crate) async fn run_async(args: RoleShowAssignmentsArgs) -> Result<(), CliError> {
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

    let path = format!("/v1/roles/{}/assignments", args.role_id);
    let value = client.get_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    println!("users:");
    for user in value
        .get("users")
        .and_then(|users| users.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let user_id = user
            .get("user_id")
            .and_then(|value| value.as_str())
            .unwrap_or("-");
        let email = user
            .get("email")
            .and_then(|value| value.as_str())
            .unwrap_or("-");
        let assignment_level = user
            .get("assignment_level")
            .and_then(|value| value.as_str())
            .unwrap_or("-");
        println!("  {user_id}\t{email}\t{assignment_level}");
    }

    println!("teams:");
    for team in value
        .get("teams")
        .and_then(|teams| teams.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let team_id = team
            .get("team_id")
            .and_then(|value| value.as_str())
            .unwrap_or("-");
        let name = team
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or("-");
        println!("  {team_id}\t{name}");
    }

    println!("tokens:");
    for token in value
        .get("tokens")
        .and_then(|tokens| tokens.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let token_id = token
            .get("token_id")
            .and_then(|value| value.as_str())
            .unwrap_or("-");
        let label = token
            .get("label")
            .and_then(|value| value.as_str())
            .unwrap_or("-");
        println!("  {token_id}\t{label}");
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
    fn assignments_path_formatting() {
        let role_id = "r-42";
        let path = format!("/v1/roles/{}/assignments", role_id);
        assert_eq!(path, "/v1/roles/r-42/assignments");
    }

    #[test]
    fn parse_users_from_response() {
        let value = json!({"users": [
            {"user_id": "u-1", "email": "a@b.com", "assignment_level": "org"}
        ]});
        let users = value.get("users").and_then(|u| u.as_array()).unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0]["user_id"], "u-1");
    }

    #[test]
    fn parse_teams_from_response() {
        let value = json!({"teams": [
            {"team_id": "t-1", "name": "eng"}
        ]});
        let teams = value.get("teams").and_then(|t| t.as_array()).unwrap();
        assert_eq!(teams.len(), 1);
        assert_eq!(teams[0]["team_id"], "t-1");
    }

    #[test]
    fn parse_tokens_from_response() {
        let value = json!({"tokens": [
            {"token_id": "tok-1", "label": "CI key"}
        ]});
        let tokens = value.get("tokens").and_then(|t| t.as_array()).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0]["label"], "CI key");
    }

    #[test]
    fn parse_empty_assignments() {
        let value = json!({});
        let users = value
            .get("users")
            .and_then(|u| u.as_array())
            .cloned()
            .unwrap_or_default();
        let teams = value
            .get("teams")
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();
        let tokens = value
            .get("tokens")
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(users.is_empty());
        assert!(teams.is_empty());
        assert!(tokens.is_empty());
    }
}
