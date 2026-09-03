// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan team add-member` — add a user to a team.
//!
//! # Module wiring
//! Add `pub(crate) mod team_add_member;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct TeamAddMemberArgs {
    /// Team id.
    #[arg(long)]
    pub(crate) team_id: String,

    /// Email address of a member who is in the organization.
    #[arg(long)]
    pub(crate) email: String,

    /// Team role to assign on membership.
    #[arg(long)]
    pub(crate) role: Option<String>,

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
pub(crate) async fn run_async(args: TeamAddMemberArgs) -> Result<(), CliError> {
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

    let path = format!("/v1/teams/{}/members", args.team_id);
    let mut body = serde_json::json!({ "email": args.email });
    if let Some(role) = args.role {
        body["role"] = serde_json::Value::String(role);
    }
    let result = client.post_json_value(&path, &body).await?;

    if args.json {
        return print_json(&result);
    }

    let member = result.get("member").unwrap_or(&result);
    let email = member
        .get("email")
        .and_then(|value| value.as_str())
        .unwrap_or("-");
    println!("added {email} to team {}", args.team_id);
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
    fn add_member_body_email_only() {
        let body = json!({ "email": "alice@example.com" });
        assert_eq!(body["email"], "alice@example.com");
        assert!(body.get("role").is_none());
    }

    #[test]
    fn add_member_body_with_role() {
        let mut body = json!({ "email": "bob@example.com" });
        let role = Some("lead".to_string());
        if let Some(r) = role {
            body["role"] = serde_json::Value::String(r);
        }
        assert_eq!(body["role"], "lead");
    }

    #[test]
    fn add_member_path_formatting() {
        let team_id = "t-1";
        let path = format!("/v1/teams/{}/members", team_id);
        assert_eq!(path, "/v1/teams/t-1/members");
    }

    #[test]
    fn parse_member_response_with_wrapper() {
        let result = json!({"member": {"email": "x@y.com"}});
        let member = result.get("member").unwrap_or(&result);
        let email = member.get("email").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(email, "x@y.com");
    }

    #[test]
    fn parse_member_response_without_wrapper() {
        let result = json!({"email": "z@y.com"});
        let member = result.get("member").unwrap_or(&result);
        let email = member.get("email").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(email, "z@y.com");
    }
}
