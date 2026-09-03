// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan spend provider-budget list` — list provider budgets.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct ProviderBudgetListArgs {
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
pub(crate) async fn run_async(args: ProviderBudgetListArgs) -> Result<(), CliError> {
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

    let value = client.get_json_value("/v1/provider-budgets").await?;

    if args.json {
        return print_json(&value);
    }

    let items = value
        .get("provider_budgets")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if items.is_empty() {
        println!("no provider budgets");
        return Ok(());
    }

    for b in &items {
        let id = b.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        let provider = b.get("provider").and_then(|v| v.as_str()).unwrap_or("-");
        let limit = b.get("limit_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
        println!("{id}  {provider}  limit=${limit:.4}");
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
    fn parse_budgets_from_response() {
        let value = json!({"provider_budgets": [
            {"id": "pb-1", "provider": "openai", "limit_usd": 50.0},
            {"id": "pb-2", "provider": "anthropic", "limit_usd": 100.0}
        ]});
        let items = value
            .get("provider_budgets")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn parse_budgets_empty() {
        let value = json!({"provider_budgets": []});
        let items = value
            .get("provider_budgets")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(items.is_empty());
    }

    #[test]
    fn budget_limit_formatting() {
        let limit: f64 = 99.5;
        let formatted = format!("limit=${limit:.4}");
        assert_eq!(formatted, "limit=$99.5000");
    }

    #[test]
    fn budget_row_defaults() {
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
    }
}
