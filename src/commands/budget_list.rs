// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan spend budget list` — list spend budgets.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::currency::format_currency;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct BudgetListArgs {
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
pub(crate) async fn run_async(args: BudgetListArgs) -> Result<(), CliError> {
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

    let value = client.get_json_value("/v1/budgets").await?;

    if args.json {
        return print_json(&value);
    }

    if let Some(ref region) = client.region() {
        println!("[region: {region}]");
    }

    let items = value
        .get("budgets")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    render_budget_list(&items);

    Ok(())
}

fn render_budget_list(items: &[serde_json::Value]) {
    if items.is_empty() {
        println!("no budgets");
        return;
    }

    for budget in items {
        println!("{}", format_budget_line(budget));
    }
}

fn format_budget_line(budget: &serde_json::Value) -> String {
    let id = budget.get("id").and_then(|v| v.as_str()).unwrap_or("-");
    let name = budget.get("name").and_then(|v| v.as_str()).unwrap_or("-");
    let currency = budget
        .get("currency")
        .and_then(|v| v.as_str())
        .unwrap_or("USD");
    let limit = budget
        .get("max_budget")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    format!("{id}  {name}  limit={}", format_currency(limit, currency))
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
    use super::*;
    use serde_json::json;

    #[test]
    fn command_helper_coverage_format_budget_line_uses_currency_and_fallbacks() {
        let line = format_budget_line(&json!({
            "id": "budget-1",
            "name": "Monthly",
            "currency": "EUR",
            "max_budget": 42.5
        }));

        assert_eq!(line, "budget-1  Monthly  limit=€42.50");
        assert_eq!(format_budget_line(&json!({})), "-  -  limit=$0.00");
    }

    #[test]
    fn command_helper_coverage_render_budget_list_prints_rows_or_empty_message() {
        let budgets = vec![json!({
            "id": "budget-2",
            "name": "Ops",
            "max_budget": 10.0
        })];

        render_budget_list(&budgets);
        render_budget_list(&[]);
    }

    #[test]
    fn format_budget_line_with_non_usd_currency() {
        let line = format_budget_line(&json!({
            "id": "b-1",
            "name": "Euro Budget",
            "currency": "EUR",
            "max_budget": 1000.0
        }));
        assert!(line.contains("b-1"));
        assert!(line.contains("Euro Budget"));
        assert!(line.contains("€"));
    }

    #[test]
    fn format_budget_line_missing_currency_defaults_usd() {
        let line = format_budget_line(&json!({
            "id": "b-2",
            "name": "Default",
            "max_budget": 25.0
        }));
        assert!(line.contains("$25.00"));
    }

    #[test]
    fn format_budget_line_zero_limit() {
        let line = format_budget_line(&json!({
            "id": "b-3",
            "name": "Zero",
            "max_budget": 0.0
        }));
        assert!(line.contains("$0.00"));
    }

    #[test]
    fn args_debug_impl() {
        let args = BudgetListArgs {
            json: true,
            config: None,
            api_url: Some("https://api.test".to_string()),
            api_token: None,
            profile: "default".to_string(),
            region: Some("us-east-1".to_string()),
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("BudgetListArgs"));
        assert!(debug.contains("us-east-1"));
    }

    #[test]
    fn parse_budgets_missing_key() {
        let value = json!({});
        let items = value
            .get("budgets")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(items.is_empty());
    }

    #[test]
    fn parse_budgets_non_array_value() {
        let value = json!({"budgets": "not-array"});
        let items = value
            .get("budgets")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(items.is_empty());
    }
}
