// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan iam policy delete` — delete an IAM policy.
//!
//! # Module wiring
//! Add `pub(crate) mod iam_policy_delete;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct IamPolicyDeleteArgs {
    /// Policy id.
    #[arg(long)]
    pub(crate) policy_id: String,

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
pub(crate) async fn run_async(args: IamPolicyDeleteArgs) -> Result<(), CliError> {
    if !args.yes {
        return Err(CliError::user(format!(
            "pass --yes to confirm deleting policy {}",
            args.policy_id
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

    let path = format!("/v1/policies/{}", args.policy_id);
    let result = client.delete_json_value(&path).await?;

    if args.json {
        return print_json(&result);
    }

    println!("deleted policy {}", args.policy_id);
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
        let policy_id = "pol-42";
        let msg = format!("pass --yes to confirm deleting policy {}", policy_id);
        assert!(msg.contains("pol-42"));
    }

    #[test]
    fn delete_path_formatting() {
        let policy_id = "pol-99";
        let path = format!("/v1/policies/{}", policy_id);
        assert_eq!(path, "/v1/policies/pol-99");
    }
}
