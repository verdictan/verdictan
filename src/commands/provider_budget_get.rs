// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan spend provider-budget get` — fetch a provider budget by id.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct ProviderBudgetGetArgs {
    /// Provider budget id.
    #[arg(long)]
    pub(crate) budget_id: String,

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
pub(crate) async fn run_async(args: ProviderBudgetGetArgs) -> Result<(), CliError> {
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

    let path = format!("/v1/provider-budgets/{}", args.budget_id);
    let value = client.get_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    let b = value.get("provider_budget").unwrap_or(&value);
    println!(
        "id:        {}",
        b.get("id").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "provider:  {}",
        b.get("provider").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "limit_usd: {}",
        b.get("limit_usd").and_then(|v| v.as_f64()).unwrap_or(0.0)
    );
    println!(
        "period:    {}",
        b.get("period").and_then(|v| v.as_str()).unwrap_or("-")
    );

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
        let budget_id = "pb-42";
        let path = format!("/v1/provider-budgets/{}", budget_id);
        assert_eq!(path, "/v1/provider-budgets/pb-42");
    }

    #[test]
    fn parse_response_with_wrapper() {
        let value = json!({"provider_budget": {
            "id": "pb-1",
            "provider": "openai",
            "limit_usd": 100.0,
            "period": "monthly"
        }});
        let b = value.get("provider_budget").unwrap_or(&value);
        assert_eq!(b.get("id").and_then(|v| v.as_str()).unwrap(), "pb-1");
        assert_eq!(
            b.get("provider").and_then(|v| v.as_str()).unwrap(),
            "openai"
        );
        assert_eq!(b.get("limit_usd").and_then(|v| v.as_f64()).unwrap(), 100.0);
    }

    #[test]
    fn parse_response_field_defaults() {
        let b = json!({});
        assert_eq!(b.get("id").and_then(|v| v.as_str()).unwrap_or("-"), "-");
        assert_eq!(
            b.get("provider").and_then(|v| v.as_str()).unwrap_or("-"),
            "-"
        );
        assert_eq!(
            b.get("limit_usd").and_then(|v| v.as_f64()).unwrap_or(0.0),
            0.0
        );
        assert_eq!(b.get("period").and_then(|v| v.as_str()).unwrap_or("-"), "-");
    }
}
