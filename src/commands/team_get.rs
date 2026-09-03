// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan team get` — fetch a single team by id.
//!
//! # Module wiring
//! Add `pub(crate) mod team_get;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct TeamGetArgs {
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
pub(crate) async fn run_async(args: TeamGetArgs) -> Result<(), CliError> {
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
        return print_json(&value);
    }

    let t = value.get("team").unwrap_or(&value);
    let id = t.get("team_id").and_then(|v| v.as_str()).unwrap_or("-");
    let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("-");
    let slug = t.get("slug").and_then(|v| v.as_str()).unwrap_or("-");
    let desc = t.get("description").and_then(|v| v.as_str()).unwrap_or("-");
    let member_count = t
        .get("members")
        .and_then(|v| v.as_array())
        .map(|members| members.len())
        .unwrap_or(0);
    let role_count = t
        .get("inherited_roles")
        .and_then(|v| v.as_array())
        .map(|roles| roles.len())
        .unwrap_or(0);

    println!("id:          {id}");
    println!("name:        {name}");
    println!("slug:        {slug}");
    println!("description: {desc}");
    println!("members:     {member_count}");
    println!("roles:       {role_count}");

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
    fn get_path_formatting() {
        let team_id = "t-42";
        let path = format!("/v1/teams/{}", team_id);
        assert_eq!(path, "/v1/teams/t-42");
    }

    #[test]
    fn parse_team_with_wrapper() {
        let value = json!({"team": {
            "team_id": "t-1", "name": "eng", "slug": "engineering",
            "description": "Engineering team",
            "members": [{"user_id": "u-1"}],
            "inherited_roles": [{"role_id": "r-1"}]
        }});
        let t = value.get("team").unwrap_or(&value);
        assert_eq!(t["team_id"], "t-1");
        let member_count = t
            .get("members")
            .and_then(|v| v.as_array())
            .map(|m| m.len())
            .unwrap_or(0);
        assert_eq!(member_count, 1);
        let role_count = t
            .get("inherited_roles")
            .and_then(|v| v.as_array())
            .map(|r| r.len())
            .unwrap_or(0);
        assert_eq!(role_count, 1);
    }

    #[test]
    fn parse_team_without_wrapper() {
        let value = json!({"team_id": "t-2", "name": "ops"});
        let t = value.get("team").unwrap_or(&value);
        assert_eq!(t["team_id"], "t-2");
    }

    #[test]
    fn parse_team_defaults() {
        let t = json!({});
        assert_eq!(
            t.get("team_id").and_then(|v| v.as_str()).unwrap_or("-"),
            "-"
        );
        assert_eq!(t.get("name").and_then(|v| v.as_str()).unwrap_or("-"), "-");
        assert_eq!(t.get("slug").and_then(|v| v.as_str()).unwrap_or("-"), "-");
        let members = t
            .get("members")
            .and_then(|v| v.as_array())
            .map(|m| m.len())
            .unwrap_or(0);
        assert_eq!(members, 0);
    }
}
