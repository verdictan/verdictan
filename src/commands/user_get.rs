// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan user get` — fetch a single org member by id.
//!
//! # Module wiring
//! Add `pub(crate) mod user_get;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct UserGetArgs {
    /// User id.
    #[arg(long)]
    pub(crate) user_id: String,

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
pub(crate) async fn run_async(args: UserGetArgs) -> Result<(), CliError> {
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

    let path = format!("/v1/users/{}", args.user_id);
    let value = client.get_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    let u = value.get("user").unwrap_or(&value);
    let id = u.get("user_id").and_then(|v| v.as_str()).unwrap_or("-");
    let email = u.get("email").and_then(|v| v.as_str()).unwrap_or("-");
    let name = u
        .get("display_name")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let status = u.get("status").and_then(|v| v.as_str()).unwrap_or("-");
    let org_role = u.get("org_role").and_then(|v| v.as_str()).unwrap_or("-");
    let created = u.get("created_at").and_then(|v| v.as_str()).unwrap_or("-");

    println!("id:         {id}");
    println!("email:      {email}");
    println!("name:       {name}");
    println!("status:     {status}");
    println!("org_role:   {org_role}");
    println!("created_at: {created}");

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
        let user_id = "u-42";
        let path = format!("/v1/users/{}", user_id);
        assert_eq!(path, "/v1/users/u-42");
    }

    #[test]
    fn parse_user_with_wrapper() {
        let value = json!({"user": {
            "user_id": "u-1", "email": "a@b.com", "display_name": "Alice",
            "status": "active", "org_role": "admin", "created_at": "2025-01-01"
        }});
        let u = value.get("user").unwrap_or(&value);
        assert_eq!(u["user_id"], "u-1");
        assert_eq!(u["email"], "a@b.com");
        assert_eq!(u["display_name"], "Alice");
    }

    #[test]
    fn parse_user_without_wrapper() {
        let value = json!({"user_id": "u-2", "email": "b@c.com"});
        let u = value.get("user").unwrap_or(&value);
        assert_eq!(u["user_id"], "u-2");
    }

    #[test]
    fn parse_user_defaults() {
        let u = json!({});
        assert_eq!(
            u.get("user_id").and_then(|v| v.as_str()).unwrap_or("-"),
            "-"
        );
        assert_eq!(u.get("email").and_then(|v| v.as_str()).unwrap_or("-"), "-");
        assert_eq!(
            u.get("display_name")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
            "-"
        );
        assert_eq!(u.get("status").and_then(|v| v.as_str()).unwrap_or("-"), "-");
        assert_eq!(
            u.get("org_role").and_then(|v| v.as_str()).unwrap_or("-"),
            "-"
        );
    }
}
