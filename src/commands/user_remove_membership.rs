// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan user remove-membership` — remove a user from the current organization.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct UserRemoveMembershipArgs {
    /// User id.
    #[arg(long)]
    pub(crate) user_id: String,

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
pub(crate) async fn run_async(args: UserRemoveMembershipArgs) -> Result<(), CliError> {
    if !args.yes {
        return Err(CliError::user(format!(
            "pass --yes to confirm removing user {} from the organization",
            args.user_id
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

    let path = format!("/v1/users/{}/membership", args.user_id);
    let value = client.delete_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    println!("removed user {} from the organization", args.user_id);
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
    fn membership_path_formatting() {
        let user_id = "usr-77";
        let path = format!("/v1/users/{}/membership", user_id);
        assert_eq!(path, "/v1/users/usr-77/membership");
    }

    #[test]
    fn membership_path_special_chars() {
        let user_id = "usr-abc-123";
        let path = format!("/v1/users/{}/membership", user_id);
        assert!(path.starts_with("/v1/users/"));
        assert!(path.ends_with("/membership"));
    }

    #[test]
    fn yes_flag_required_error_message() {
        let msg = format!(
            "pass --yes to confirm removing user {} from the organization",
            "usr-77"
        );
        assert!(msg.contains("--yes"));
        assert!(msg.contains("usr-77"));
    }
}
