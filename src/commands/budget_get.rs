// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan spend budget get` — fetch a budget by id.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::currency::format_currency;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct BudgetGetArgs {
    /// Budget id.
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
pub(crate) async fn run_async(args: BudgetGetArgs) -> Result<(), CliError> {
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
    let value = client.get_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    let b = value.get("budget").unwrap_or(&value);
    render_budget_details(b);

    Ok(())
}

fn render_budget_details(b: &serde_json::Value) {
    let currency = b.get("currency").and_then(|v| v.as_str()).unwrap_or("USD");
    let max_budget = b.get("max_budget").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let current_spend = b
        .get("current_spend")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    println!(
        "id:        {}",
        b.get("id").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "name:      {}",
        b.get("name").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!("limit:     {}", format_currency(max_budget, currency));
    println!("spend:     {}", format_currency(current_spend, currency));
    println!("currency:  {}", currency);
    println!(
        "schedule:  {}",
        b.get("reset_schedule")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
    );
    println!(
        "created:   {}",
        b.get("created_at").and_then(|v| v.as_str()).unwrap_or("-")
    );
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
    use crate::test_support;
    use axum::{routing::get, Json, Router};
    use serde_json::json;
    use tokio::net::TcpListener;

    #[test]
    fn command_helper_coverage_render_budget_details_formats_currency_fields() {
        render_budget_details(&json!({
            "id": "budget-1",
            "name": "Monthly",
            "currency": "EUR",
            "max_budget": 100.0,
            "current_spend": 12.5,
            "reset_schedule": "monthly",
            "created_at": "2025-01-01T00:00:00Z"
        }));
        render_budget_details(&json!({}));
    }

    async fn spawn_budget_api(budget_id: &str) -> String {
        let path = format!("/v1/budgets/{budget_id}");
        let budget_id = budget_id.to_string();
        let app = Router::new().route(
            &path,
            get(move || {
                let budget_id = budget_id.clone();
                async move {
                    Json(json!({
                        "budget": {
                            "id": budget_id,
                            "name": "Shard Budget",
                            "currency": "USD",
                            "max_budget": 250.0,
                            "current_spend": 40.0,
                            "reset_schedule": "monthly",
                            "created_at": "2025-01-01T00:00:00Z"
                        }
                    }))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind budget api");
        let addr = listener.local_addr().expect("budget addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve budget api");
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn run_async_prints_human_budget_details() {
        let api_url = spawn_budget_api("budget-shard-1").await;
        let args = BudgetGetArgs {
            budget_id: "budget-shard-1".to_string(),
            json: false,
            config: None,
            api_url: Some(api_url),
            api_token: Some("test-token".to_string()),
            profile: "default".to_string(),
            region: None,
        };
        run_async(args)
            .await
            .expect("budget get human output succeeds");
    }

    #[tokio::test]
    async fn run_async_requires_api_token() {
        let _guard = test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        test_support::set_var("HOME", dir.path());
        test_support::set_var(
            "VERDICTAN_TEST_HOME",
            dir.path().to_string_lossy().to_string(),
        );
        std::env::remove_var("VERDICTAN_API_TOKEN");
        std::env::remove_var("VERDICTAN_CONFIG");

        let args = BudgetGetArgs {
            budget_id: "budget-shard-1".to_string(),
            json: false,
            config: None,
            api_url: Some("http://127.0.0.1:9".to_string()),
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let err = run_async(args)
            .await
            .expect_err("missing token should fail");
        assert!(err.to_string().contains("missing api token"));
    }

    #[test]
    fn render_budget_details_null_fields() {
        render_budget_details(&json!({
            "id": null,
            "name": null,
            "currency": null,
            "max_budget": null,
            "current_spend": null,
            "reset_schedule": null,
            "created_at": null
        }));
    }

    #[test]
    fn render_budget_details_with_all_fields() {
        render_budget_details(&json!({
            "id": "budget-full",
            "name": "Full Budget",
            "currency": "GBP",
            "max_budget": 999.99,
            "current_spend": 500.50,
            "reset_schedule": "weekly",
            "created_at": "2026-01-01T00:00:00Z"
        }));
    }

    #[test]
    fn get_path_formatting() {
        let budget_id = "b-uuid-123";
        let path = format!("/v1/budgets/{}", budget_id);
        assert_eq!(path, "/v1/budgets/b-uuid-123");
    }

    #[test]
    fn args_debug_impl() {
        let args = BudgetGetArgs {
            budget_id: "b-42".to_string(),
            json: true,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("b-42"));
        assert!(debug.contains("BudgetGetArgs"));
    }

    #[test]
    fn parse_response_unwrapped() {
        let value = json!({"id": "b-direct", "currency": "USD", "max_budget": 100.0});
        let b = value.get("budget").unwrap_or(&value);
        let id = b.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "b-direct");
    }
}
