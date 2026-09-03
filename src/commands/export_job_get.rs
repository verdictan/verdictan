// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan export-jobs get` — fetch the lifecycle status of an export job.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::commands::export_job_common::find_job;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct ExportJobGetArgs {
    /// Export job id.
    #[arg(long)]
    pub(crate) job_id: String,

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
pub(crate) async fn run_async(args: ExportJobGetArgs) -> Result<(), CliError> {
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

    let value = client.get_json_value("/v1/exports/jobs").await?;
    let job = find_job(&value, &args.job_id)?
        .ok_or_else(|| CliError::user(format!("export job {} not found", args.job_id)))?;

    if args.json {
        return print_json(job);
    }

    println!(
        "id:      {}",
        job.get("job_id").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "status:  {}",
        job.get("status").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "format:  {}",
        job.get("format").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "requested: {}",
        job.get("requested_at")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
    );
    println!(
        "window:  {} to {}",
        job.get("start_date")
            .and_then(|v| v.as_str())
            .unwrap_or("-"),
        job.get("end_date").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "rows:    {}",
        job.get("event_count")
            .and_then(|v| v.as_i64())
            .map(|count| count.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    if let Some(message) = job
        .get("failure_message")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|message| !message.is_empty())
    {
        println!("failure: {message}");
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
    fn current_job_shape_has_expected_lifecycle_fields() {
        for status in ["queued", "processing", "completed", "failed", "expired"] {
            let job = json!({
                "job_id": "j-1",
                "status": status,
                "format": "csv",
                "requested_at": "2025-01-01T00:00:00Z"
            });
            assert_eq!(
                job.get("job_id").and_then(|value| value.as_str()),
                Some("j-1")
            );
            assert_eq!(
                job.get("status").and_then(|value| value.as_str()),
                Some(status)
            );
        }
    }

    #[test]
    fn args_debug_impl() {
        let args = super::ExportJobGetArgs {
            job_id: "j-42".to_string(),
            json: true,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("j-42"));
    }
}
