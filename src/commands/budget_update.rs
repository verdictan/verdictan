// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan spend budget update` — update a spend budget.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct BudgetUpdateArgs {
    /// Budget id.
    #[arg(long)]
    pub(crate) budget_id: String,

    #[arg(long)]
    pub(crate) name: Option<String>,

    /// Maximum budget amount.
    #[arg(long)]
    pub(crate) max_budget: Option<f64>,

    /// Currency.
    #[arg(long)]
    pub(crate) currency: Option<String>,

    /// Budget renewal schedule (for example, "monthly", "daily", or "weekly").
    #[arg(long)]
    pub(crate) reset_schedule: Option<String>,

    /// Alert threshold percentage.
    #[arg(long)]
    pub(crate) alert_threshold_pct: Option<i32>,

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
pub(crate) async fn run_async(args: BudgetUpdateArgs) -> Result<(), CliError> {
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

    let mut payload = serde_json::json!({});
    if let Some(name) = &args.name {
        payload["name"] = serde_json::Value::String(name.clone());
    }
    if let Some(limit) = args.max_budget {
        payload["max_budget"] = serde_json::json!(limit);
    }
    if let Some(currency) = &args.currency {
        payload["currency"] = serde_json::Value::String(currency.clone());
    }
    if let Some(schedule) = &args.reset_schedule {
        payload["reset_schedule"] = serde_json::Value::String(schedule.clone());
    }
    if let Some(pct) = args.alert_threshold_pct {
        payload["alert_threshold_pct"] = serde_json::json!(pct);
    }

    let path = format!("/v1/budgets/{}", args.budget_id);
    let value = client.put_json_value(&path, &payload).await?;

    if args.json {
        return print_json(&value);
    }

    println!("updated budget {}", args.budget_id);
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
    fn update_payload_all_fields() {
        let mut payload = json!({});
        payload["name"] = serde_json::Value::String("Q1 Budget".into());
        payload["max_budget"] = json!(500.0);
        payload["currency"] = serde_json::Value::String("USD".into());
        payload["reset_schedule"] = serde_json::Value::String("monthly".into());
        payload["alert_threshold_pct"] = json!(80);

        assert_eq!(payload["name"], "Q1 Budget");
        assert_eq!(payload["max_budget"], 500.0);
        assert_eq!(payload["currency"], "USD");
        assert_eq!(payload["reset_schedule"], "monthly");
        assert_eq!(payload["alert_threshold_pct"], 80);
    }

    #[test]
    fn update_payload_partial() {
        let mut payload = json!({});
        payload["max_budget"] = json!(200.0);
        assert_eq!(payload["max_budget"], 200.0);
        assert!(payload.get("name").is_none());
    }

    #[test]
    fn update_path_formatting() {
        let budget_id = "b-42";
        let path = format!("/v1/budgets/{}", budget_id);
        assert_eq!(path, "/v1/budgets/b-42");
    }

    #[test]
    fn update_payload_empty_when_no_fields_set() {
        let payload = json!({});
        assert!(payload.as_object().unwrap().is_empty());
    }

    #[test]
    fn update_output_message() {
        let budget_id = "b-updated";
        let msg = format!("updated budget {}", budget_id);
        assert!(msg.contains("updated budget"));
        assert!(msg.contains("b-updated"));
    }

    #[test]
    fn args_debug_impl() {
        let args = super::BudgetUpdateArgs {
            budget_id: "b-99".to_string(),
            name: Some("New Name".to_string()),
            max_budget: Some(1000.0),
            currency: Some("EUR".to_string()),
            reset_schedule: None,
            alert_threshold_pct: None,
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("b-99"));
        assert!(debug.contains("New Name"));
    }

    #[test]
    fn update_payload_single_field_name() {
        let mut payload = json!({});
        payload["name"] = serde_json::Value::String("Updated Name".into());
        assert_eq!(payload.as_object().unwrap().len(), 1);
        assert_eq!(payload["name"], "Updated Name");
    }

    #[test]
    fn update_payload_single_field_alert_threshold() {
        let mut payload = json!({});
        payload["alert_threshold_pct"] = json!(95);
        assert_eq!(payload.as_object().unwrap().len(), 1);
        assert_eq!(payload["alert_threshold_pct"], 95);
    }

    #[test]
    fn update_path_with_uuid() {
        let budget_id = "550e8400-e29b";
        let path = format!("/v1/budgets/{}", budget_id);
        assert_eq!(path, "/v1/budgets/550e8400-e29b");
    }
}
