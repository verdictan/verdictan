// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan spend summary` — get spend summary for the organisation.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::currency::format_currency;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct SpendSummaryArgs {
    /// Since (RFC3339 UTC or a relative duration, for example 30d).
    #[arg(long)]
    pub(crate) since: Option<String>,

    /// Group results by dimension (for example, "region").
    #[arg(long)]
    pub(crate) group_by: Option<String>,

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
pub(crate) async fn run_async(args: SpendSummaryArgs) -> Result<(), CliError> {
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

    let path = build_spend_summary_path(args.since.as_deref(), args.group_by.as_deref());

    let value = client.get_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    render_spend_summary(&value, client.region());
    Ok(())
}

fn render_spend_summary(value: &serde_json::Value, region: Option<&str>) {
    if let Some(region) = region {
        println!("[region: {region}]");
    }

    let s = value.get("summary").unwrap_or(value);
    let currency = s.get("currency").and_then(|v| v.as_str()).unwrap_or("USD");
    let total_cost = s.get("total_cost").and_then(|v| v.as_f64()).unwrap_or(0.0);
    println!("total_cost:    {}", format_currency(total_cost, currency));
    println!(
        "total_tokens:  {}",
        s.get("total_tokens").and_then(|v| v.as_i64()).unwrap_or(0)
    );
    println!("currency:      {}", currency);

    if let Some(by_region) = s.get("by_region").and_then(|v| v.as_array()) {
        render_region_breakdown(by_region, currency);
    }
}

fn render_region_breakdown(by_region: &[serde_json::Value], default_currency: &str) {
    println!("\nby region:");

    if by_region.is_empty() {
        print_region_row("-", 0.0, default_currency);
        return;
    }

    for entry in by_region {
        let region = entry
            .get("region_key")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let cost = entry
            .get("total_cost")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let currency = entry
            .get("currency")
            .and_then(|v| v.as_str())
            .unwrap_or(default_currency);
        print_region_row(region, cost, currency);
    }
}

fn print_region_row(region: &str, cost: f64, currency: &str) {
    println!("  {region:<12} {}", format_currency(cost, currency));
}

fn build_spend_summary_path(since: Option<&str>, group_by: Option<&str>) -> String {
    let mut query = Vec::new();
    if let Some(since) = since {
        query.push(format!("since={}", urlencoding::encode(since)));
    }
    if let Some(group_by) = group_by {
        query.push(format!("group_by={}", urlencoding::encode(group_by)));
    }

    if query.is_empty() {
        "/v1/spend/summary".to_string()
    } else {
        format!("/v1/spend/summary?{}", query.join("&"))
    }
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
    fn command_helper_coverage_build_spend_summary_path_encodes_query_params() {
        assert_eq!(build_spend_summary_path(None, None), "/v1/spend/summary");
        assert_eq!(
            build_spend_summary_path(Some("30d"), Some("region")),
            "/v1/spend/summary?since=30d&group_by=region"
        );
        assert_eq!(
            build_spend_summary_path(Some("2025-01-01T00:00:00Z"), None),
            "/v1/spend/summary?since=2025-01-01T00%3A00%3A00Z"
        );
    }

    #[test]
    fn command_helper_coverage_render_spend_summary_prints_region_breakdown() {
        use serde_json::json;

        let value = json!({
            "summary": {
                "currency": "USD",
                "total_cost": 12.5,
                "total_tokens": 900,
                "by_region": [
                    {"region_key": "us-east", "total_cost": 7.5, "currency": "USD"},
                    {"region_key": "eu-west", "total_cost": 5.0, "currency": "EUR"}
                ]
            }
        });

        render_spend_summary(&value, Some("us-east"));
    }

    async fn spawn_spend_summary_api() -> String {
        let app = Router::new().route(
            "/v1/spend/summary",
            get(
                |axum::extract::Query(query): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| async move {
                    assert_eq!(query.get("since").map(String::as_str), Some("7d"));
                    assert_eq!(query.get("group_by").map(String::as_str), Some("region"));
                    Json(json!({
                        "summary": {
                            "currency": "USD",
                            "total_cost": 10.0,
                            "total_tokens": 100,
                            "by_region": [
                                {"region_key": "us-east", "total_cost": 10.0, "currency": "USD"}
                            ]
                        }
                    }))
                },
            ),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind spend summary api");
        let addr = listener.local_addr().expect("spend summary addr");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve spend summary api");
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn run_async_prints_human_spend_summary() {
        let api_url = spawn_spend_summary_api().await;
        let args = SpendSummaryArgs {
            json: false,
            since: Some("7d".to_string()),
            group_by: Some("region".to_string()),
            config: None,
            api_url: Some(api_url),
            api_token: Some("test-token".to_string()),
            profile: "default".to_string(),
            region: Some("us-east".to_string()),
        };
        run_async(args)
            .await
            .expect("spend summary human output succeeds");
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

        let args = SpendSummaryArgs {
            json: false,
            since: Some("7d".to_string()),
            group_by: None,
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
    fn render_spend_summary_without_region_header() {
        let value = json!({
            "summary": {
                "currency": "EUR",
                "total_cost": 5.25,
                "total_tokens": 1200
            }
        });
        render_spend_summary(&value, None);
    }

    #[test]
    fn render_spend_summary_no_summary_wrapper() {
        let value = json!({
            "currency": "USD",
            "total_cost": 0.0,
            "total_tokens": 0
        });
        render_spend_summary(&value, None);
    }

    #[test]
    fn render_spend_summary_missing_fields_uses_defaults() {
        let value = json!({});
        render_spend_summary(&value, Some("global"));
    }

    #[test]
    fn build_spend_summary_path_since_only() {
        assert_eq!(
            build_spend_summary_path(Some("7d"), None),
            "/v1/spend/summary?since=7d"
        );
    }

    #[test]
    fn build_spend_summary_path_group_by_only() {
        assert_eq!(
            build_spend_summary_path(None, Some("team")),
            "/v1/spend/summary?group_by=team"
        );
    }
}
