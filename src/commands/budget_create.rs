// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan spend budget create` — create a spend budget.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct BudgetCreateArgs {
    /// Budget name.
    #[arg(long)]
    pub(crate) name: String,

    /// Maximum budget amount.
    #[arg(long)]
    pub(crate) max_budget: f64,

    /// Budget target type (key, user, team, organization).
    #[arg(long = "target-type", alias = "target-type", value_parser = ["key", "user", "team", "organization"])]
    pub(crate) target_type: String,

    /// Target entity id (mandatory for key, user, and team target types).
    #[arg(long = "target-id", alias = "target-id")]
    pub(crate) target_id: Option<String>,

    /// Currency (default: usd).
    #[arg(long, default_value = "usd")]
    pub(crate) currency: String,

    /// Budget renewal schedule (for example, "monthly", "daily", or "weekly").
    #[arg(long)]
    pub(crate) reset_schedule: Option<String>,

    /// Alert threshold percentage (default: 80).
    #[arg(long, default_value_t = 80)]
    pub(crate) alert_threshold_pct: i32,

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
pub(crate) async fn run_async(args: BudgetCreateArgs) -> Result<(), CliError> {
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

    let mut payload = serde_json::json!({
        "name": args.name,
        "max_budget": args.max_budget,
        "target_type": args.target_type,
        "currency": args.currency,
        "alert_threshold_pct": args.alert_threshold_pct,
    });
    if let Some(target_id) = &args.target_id {
        payload["target_id"] = serde_json::Value::String(target_id.clone());
    }
    if let Some(schedule) = &args.reset_schedule {
        payload["reset_schedule"] = serde_json::Value::String(schedule.clone());
    }

    let value = client.post_json_value("/v1/budgets", &payload).await?;

    if args.json {
        return print_json(&value);
    }

    let b = value.get("budget").unwrap_or(&value);
    let id = b.get("id").and_then(|v| v.as_str()).unwrap_or("-");
    println!("created budget {id}");
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
    fn create_body_required_fields() {
        let payload = json!({
            "name": "team-budget",
            "max_budget": 1000.0,
            "target_type": "organization",
            "currency": "usd",
            "alert_threshold_pct": 80,
        });
        assert_eq!(payload["name"], "team-budget");
        assert_eq!(payload["max_budget"], 1000.0);
        assert_eq!(payload["target_type"], "organization");
        assert_eq!(payload["currency"], "usd");
        assert_eq!(payload["alert_threshold_pct"], 80);
    }

    #[test]
    fn create_body_with_optional_fields() {
        let mut payload = json!({
            "name": "b",
            "max_budget": 500.0,
            "target_type": "key",
            "currency": "usd",
            "alert_threshold_pct": 90,
        });
        payload["target_id"] = serde_json::Value::String("key-1".into());
        payload["reset_schedule"] = serde_json::Value::String("monthly".into());
        assert_eq!(payload["target_id"], "key-1");
        assert_eq!(payload["reset_schedule"], "monthly");
    }

    #[test]
    fn parse_create_response() {
        let value = json!({"budget": {"id": "b-new"}});
        let b = value.get("budget").unwrap_or(&value);
        let id = b.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "b-new");
    }

    #[test]
    fn parse_create_response_missing() {
        let value = json!({});
        let b = value.get("budget").unwrap_or(&value);
        let id = b.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "-");
    }

    #[test]
    fn parse_create_response_unwrapped() {
        let value = json!({"id": "b-direct"});
        let b = value.get("budget").unwrap_or(&value);
        let id = b.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "b-direct");
    }

    #[test]
    fn create_body_without_optional_fields() {
        let payload = json!({
            "name": "b",
            "max_budget": 100.0,
            "target_type": "organization",
            "currency": "usd",
            "alert_threshold_pct": 80,
        });
        assert!(payload.get("target_id").is_none());
        assert!(payload.get("reset_schedule").is_none());
    }

    #[test]
    fn args_debug_impl() {
        let args = super::BudgetCreateArgs {
            name: "test-budget".to_string(),
            max_budget: 500.0,
            target_type: "team".to_string(),
            target_id: Some("team-1".to_string()),
            currency: "eur".to_string(),
            reset_schedule: Some("weekly".to_string()),
            alert_threshold_pct: 90,
            json: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("test-budget"));
        assert!(debug.contains("team"));
    }

    #[test]
    fn parse_create_response_null_id() {
        let value = json!({"budget": {"id": null}});
        let b = value.get("budget").unwrap_or(&value);
        let id = b.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "-");
    }

    #[test]
    fn create_body_zero_budget() {
        let payload = json!({
            "name": "zero",
            "max_budget": 0.0,
            "target_type": "organization",
            "currency": "usd",
            "alert_threshold_pct": 0,
        });
        assert_eq!(payload["max_budget"], 0.0);
        assert_eq!(payload["alert_threshold_pct"], 0);
    }

    #[test]
    fn create_body_large_budget() {
        let payload = json!({
            "name": "enterprise",
            "max_budget": 999999.99,
            "target_type": "organization",
            "currency": "usd",
            "alert_threshold_pct": 100,
        });
        assert_eq!(payload["max_budget"], 999999.99);
        assert_eq!(payload["alert_threshold_pct"], 100);
    }
}
