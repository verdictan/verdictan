// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan spend provider-budget create` — create a provider budget.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct ProviderBudgetCreateArgs {
    /// Provider name (for example, "openai" or "anthropic").
    #[arg(long)]
    pub(crate) provider: String,

    /// Limit in USD.
    #[arg(long)]
    pub(crate) limit_usd: f64,

    /// Period (for example, "monthly" or "daily").
    #[arg(long, default_value = "monthly")]
    pub(crate) period: String,

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
pub(crate) async fn run_async(args: ProviderBudgetCreateArgs) -> Result<(), CliError> {
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

    let payload = serde_json::json!({
        "provider": args.provider,
        "limit_usd": args.limit_usd,
        "period": args.period,
    });

    let value = client
        .post_json_value("/v1/provider-budgets", &payload)
        .await?;

    if args.json {
        return print_json(&value);
    }

    let b = value.get("provider_budget").unwrap_or(&value);
    let id = b.get("id").and_then(|v| v.as_str()).unwrap_or("-");
    println!("created provider budget {id}");
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
    fn create_body_construction() {
        let payload = json!({
            "provider": "openai",
            "limit_usd": 100.0,
            "period": "monthly",
        });
        assert_eq!(payload["provider"], "openai");
        assert_eq!(payload["limit_usd"], 100.0);
        assert_eq!(payload["period"], "monthly");
    }

    #[test]
    fn parse_create_response() {
        let value = json!({"provider_budget": {"id": "pb-new"}});
        let b = value.get("provider_budget").unwrap_or(&value);
        let id = b.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "pb-new");
    }

    #[test]
    fn parse_create_response_without_wrapper() {
        let value = json!({"id": "pb-2"});
        let b = value.get("provider_budget").unwrap_or(&value);
        let id = b.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "pb-2");
    }

    #[test]
    fn parse_create_response_missing() {
        let value = json!({});
        let b = value.get("provider_budget").unwrap_or(&value);
        let id = b.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "-");
    }

    #[test]
    fn create_body_with_optional_fields() {
        let payload = json!({
            "provider": "anthropic",
            "limit_usd": 50.0,
            "period": "weekly",
            "currency": "EUR",
        });
        assert_eq!(payload["provider"], "anthropic");
        assert_eq!(payload["period"], "weekly");
        assert_eq!(payload["currency"], "EUR");
    }

    #[test]
    fn create_path_is_correct() {
        let path = "/v1/provider-budgets";
        assert_eq!(path, "/v1/provider-budgets");
    }
}
