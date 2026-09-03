// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan team list-members` — list members of a team.
//!
//! # Module wiring
//! Add `pub(crate) mod team_list_members;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct TeamListMembersArgs {
    /// Team id.
    #[arg(long)]
    pub(crate) team_id: String,

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
pub(crate) async fn run_async(args: TeamListMembersArgs) -> Result<(), CliError> {
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

    let path = format!("/v1/teams/{}", args.team_id);
    let value = client.get_json_value(&path).await?;

    if args.json {
        let team = value.get("team").unwrap_or(&value);
        return print_json(&serde_json::json!({
            "members": team.get("members").cloned().unwrap_or(serde_json::Value::Array(vec![]))
        }));
    }

    let members = value
        .get("team")
        .or(Some(&value))
        .and_then(|team| team.get("members"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if members.is_empty() {
        println!("no members");
        return Ok(());
    }

    for m in &members {
        let id = m.get("user_id").and_then(|v| v.as_str()).unwrap_or("-");
        let email = m.get("email").and_then(|v| v.as_str()).unwrap_or("-");
        let name = m.get("name").and_then(|v| v.as_str()).unwrap_or("-");
        println!("{id}  {email}  {name}");
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
    fn list_members_path_formatting() {
        let team_id = "t-42";
        let path = format!("/v1/teams/{}", team_id);
        assert_eq!(path, "/v1/teams/t-42");
    }

    #[test]
    fn parse_members_with_team_wrapper() {
        let value = json!({"team": {"members": [
            {"user_id": "u-1", "email": "a@b.com", "name": "Alice"},
            {"user_id": "u-2", "email": "b@c.com", "name": "Bob"}
        ]}});
        let members = value
            .get("team")
            .and_then(|t| t.get("members"))
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0]["user_id"], "u-1");
    }

    #[test]
    fn parse_members_empty() {
        let value = json!({"team": {"members": []}});
        let members = value
            .get("team")
            .and_then(|t| t.get("members"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(members.is_empty());
    }

    #[test]
    fn parse_member_field_defaults() {
        let m = json!({});
        assert_eq!(
            m.get("user_id").and_then(|v| v.as_str()).unwrap_or("-"),
            "-"
        );
        assert_eq!(m.get("email").and_then(|v| v.as_str()).unwrap_or("-"), "-");
        assert_eq!(m.get("name").and_then(|v| v.as_str()).unwrap_or("-"), "-");
    }

    #[test]
    fn json_mode_extracts_members_array() {
        let value = json!({"team": {"members": [{"user_id": "u-1"}]}});
        let team = value.get("team").unwrap_or(&value);
        let members = team
            .get("members")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]));
        let output = json!({"members": members});
        assert_eq!(output["members"][0]["user_id"], "u-1");
    }
}
