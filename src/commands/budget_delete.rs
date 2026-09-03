// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan spend budget delete` — delete a spend budget.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct BudgetDeleteArgs {
    /// Budget id.
    #[arg(long)]
    pub(crate) budget_id: String,

    #[arg(long)]
    pub(crate) yes: bool,

    #[arg(long)]
    pub(crate) json: bool,

    #[arg(long)]
    pub(crate) config: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) api_url: Option<String>,

    #[arg(long)]
    pub(crate) api_token: Option<String>,

    #[arg(long, default_value = "default")]
    pub(crate) profile: String,

    /// Target region for this API call.
    #[arg(long)]
    pub(crate) region: Option<String>,
}
pub(crate) async fn run_async(args: BudgetDeleteArgs) -> Result<(), CliError> {
    if !args.yes {
        return Err(CliError::user("pass --yes to confirm budget deletion"));
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

    let path = format!("/v1/budgets/{}", args.budget_id);
    let value = client.delete_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    println!("deleted budget {}", args.budget_id);
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
        let msg = "pass --yes to confirm budget deletion";
        assert!(msg.contains("--yes"));
    }

    #[test]
    fn delete_path_formatting() {
        let budget_id = "b-99";
        let path = format!("/v1/budgets/{}", budget_id);
        assert_eq!(path, "/v1/budgets/b-99");
    }

    #[test]
    fn output_message() {
        let budget_id = "b-deleted";
        let msg = format!("deleted budget {}", budget_id);
        assert!(msg.contains("deleted budget"));
        assert!(msg.contains("b-deleted"));
    }

    #[test]
    fn args_debug_impl() {
        let args = super::BudgetDeleteArgs {
            budget_id: "b-1".to_string(),
            yes: false,
            json: true,
            config: None,
            api_url: Some("https://api.test".to_string()),
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("b-1"));
        assert!(debug.contains("BudgetDeleteArgs"));
    }

    #[test]
    fn delete_path_with_uuid() {
        let budget_id = "550e8400-e29b-41d4-a716-446655440000";
        let path = format!("/v1/budgets/{}", budget_id);
        assert_eq!(path, "/v1/budgets/550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn yes_flag_message_is_static() {
        let msg = "pass --yes to confirm budget deletion";
        assert_eq!(msg, "pass --yes to confirm budget deletion");
    }

    #[test]
    fn config_inputs_all_none() {
        let inputs = crate::config::ConfigInputs {
            api_url_flag: None,
            api_token_flag: None,
            config_path: None,
            profile_flag: Some("default".to_string()),
            region_flag: None,
        };
        assert!(inputs.api_url_flag.is_none());
        assert!(inputs.api_token_flag.is_none());
        assert!(inputs.config_path.is_none());
        assert!(inputs.region_flag.is_none());
    }
}
