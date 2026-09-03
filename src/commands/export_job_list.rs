// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan export-jobs list` — list async export jobs.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::commands::export_job_common::{job_id, jobs};
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct ExportJobListArgs {
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
pub(crate) async fn run_async(args: ExportJobListArgs) -> Result<(), CliError> {
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

    if args.json {
        return print_json(&value);
    }

    let items = jobs(&value)?;

    if items.is_empty() {
        println!("no export jobs");
        return Ok(());
    }

    for j in items {
        let id = job_id(j).unwrap_or("-");
        let status = j.get("status").and_then(|v| v.as_str()).unwrap_or("-");
        let format = j.get("format").and_then(|v| v.as_str()).unwrap_or("-");
        let requested = j
            .get("requested_at")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        println!("{id}  {status}  {format}  {requested}");
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
    fn parse_jobs_from_response() {
        let value = json!({"jobs": [
            {"job_id": "j-1", "status": "completed", "format": "csv", "requested_at": "2025-01-01"},
            {"job_id": "j-2", "status": "queued", "format": "json", "requested_at": "2025-01-02"}
        ]});
        let items = super::jobs(&value).unwrap();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn parse_jobs_empty() {
        let value = json!({"jobs": []});
        let items = super::jobs(&value).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn parse_jobs_missing_key_is_contract_error() {
        let value = json!({});
        assert!(super::jobs(&value).is_err());
    }

    #[test]
    fn job_row_defaults() {
        let j = json!({});
        assert_eq!(super::job_id(&j).unwrap_or("-"), "-");
        assert_eq!(j.get("status").and_then(|v| v.as_str()).unwrap_or("-"), "-");
        assert_eq!(j.get("format").and_then(|v| v.as_str()).unwrap_or("-"), "-");
    }

    #[test]
    fn job_row_all_fields() {
        let j = json!({
            "job_id": "j-1",
            "status": "completed",
            "format": "csv",
            "requested_at": "2025-06-01T00:00:00Z"
        });
        assert_eq!(super::job_id(&j), Some("j-1"));
        assert_eq!(
            j.get("status").and_then(|v| v.as_str()).unwrap(),
            "completed"
        );
        assert_eq!(j.get("format").and_then(|v| v.as_str()).unwrap(), "csv");
        assert_eq!(
            j.get("requested_at").and_then(|v| v.as_str()).unwrap(),
            "2025-06-01T00:00:00Z"
        );
    }

    #[test]
    fn output_no_jobs_message() {
        let msg = "no export jobs";
        assert!(msg.contains("no export jobs"));
    }

    #[test]
    fn parse_jobs_null_values_in_array() {
        let value = json!({"jobs": [
            {"job_id": null, "status": null, "format": null, "requested_at": null}
        ]});
        let items = super::jobs(&value).unwrap();
        assert_eq!(items.len(), 1);
        let j = &items[0];
        assert_eq!(super::job_id(j).unwrap_or("-"), "-");
        assert_eq!(j.get("status").and_then(|v| v.as_str()).unwrap_or("-"), "-");
    }

    #[test]
    fn job_row_formatting() {
        let j = json!({"job_id": "j-1", "status": "completed", "format": "csv", "requested_at": "2025-01-01"});
        let id = super::job_id(&j).unwrap_or("-");
        let status = j.get("status").and_then(|v| v.as_str()).unwrap_or("-");
        let format = j.get("format").and_then(|v| v.as_str()).unwrap_or("-");
        let requested = j
            .get("requested_at")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let row = format!("{id}  {status}  {format}  {requested}");
        assert!(row.contains("j-1"));
        assert!(row.contains("completed"));
        assert!(row.contains("csv"));
        assert!(row.contains("2025-01-01"));
    }

    #[test]
    fn parse_jobs_non_array_type_is_contract_error() {
        let value = json!({"jobs": "not-an-array"});
        assert!(super::jobs(&value).is_err());
    }

    #[test]
    fn args_debug_impl() {
        let args = super::ExportJobListArgs {
            json: true,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("ExportJobListArgs"));
    }
}
