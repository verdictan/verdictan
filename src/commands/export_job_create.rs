// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan export-jobs create` — create an async export job.

use chrono::{DateTime, NaiveDate, Utc};
use clap::Args;

use crate::api::AsyncApiClient;
use crate::commands::export_job_common::{
    created_job, find_job, job_failure_message, required_job_id, required_job_status,
};
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct ExportJobCreateArgs {
    /// Relative duration for the export window (for example, 24h, 7d, or 30d).
    /// Sets start_date to the call time minus the duration. Sets end_date to the call time.
    /// The CLI ignores this value if --start-date and --end-date are set.
    #[arg(long)]
    pub(crate) since: Option<String>,

    /// Explicit start date (YYYY-MM-DD). Overrides --since.
    #[arg(long)]
    pub(crate) start_date: Option<String>,

    /// Explicit end date (YYYY-MM-DD). Overrides --since.
    #[arg(long)]
    pub(crate) end_date: Option<String>,

    /// Export format.
    #[arg(
        long,
        value_parser = [
            "csv",
            "json",
            "compliance-aesia",
            "compliance-aepd",
            "compliance-ens",
            "compliance-all"
        ]
    )]
    pub(crate) format: String,

    /// Wait for the job to complete before returning.
    #[arg(long)]
    pub(crate) wait: bool,

    /// Maximum seconds to wait when --wait is set (default 120).
    #[arg(long, default_value_t = 120)]
    pub(crate) wait_timeout_secs: u64,

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

/// Parse a relative duration string (for example, "7d", "24h", or "30d") into a
/// `chrono::Duration`. Supports `h` (hours) and `d` (days) suffixes.
fn parse_relative_duration(s: &str) -> Result<chrono::Duration, CliError> {
    let s = s.trim();
    let duration = if let Some(hours) = s.strip_suffix('h') {
        let n: i64 = hours
            .parse()
            .map_err(|_| CliError::user(format!("invalid duration: {s}")))?;
        chrono::Duration::try_hours(n)
    } else if let Some(days) = s.strip_suffix('d') {
        let n: i64 = days
            .parse()
            .map_err(|_| CliError::user(format!("invalid duration: {s}")))?;
        chrono::Duration::try_days(n)
    } else {
        return Err(CliError::user(format!(
            "invalid duration '{s}': use a suffix like '7d' or '24h'"
        )));
    }
    .ok_or_else(|| CliError::user(format!("invalid duration: {s}")))?;

    if duration <= chrono::Duration::zero() {
        return Err(CliError::user("--since duration must be greater than zero"));
    }

    Ok(duration)
}

fn resolve_export_dates(
    start_date: Option<&str>,
    end_date: Option<&str>,
    since: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(String, String), CliError> {
    match (start_date, end_date) {
        (Some(start), Some(end)) => {
            let parsed_start = NaiveDate::parse_from_str(start, "%Y-%m-%d")
                .map_err(|_| CliError::user("invalid --start-date: expected YYYY-MM-DD"))?;
            let parsed_end = NaiveDate::parse_from_str(end, "%Y-%m-%d")
                .map_err(|_| CliError::user("invalid --end-date: expected YYYY-MM-DD"))?;
            if parsed_start > parsed_end {
                return Err(CliError::user(
                    "--start-date must be on or before --end-date",
                ));
            }
            Ok((start.to_string(), end.to_string()))
        }
        (Some(_), None) | (None, Some(_)) => Err(CliError::user(
            "--start-date and --end-date must be provided together",
        )),
        (None, None) => {
            let since = since.ok_or_else(|| {
                CliError::user("provide --since (e.g. '7d') or both --start-date and --end-date")
            })?;
            let duration = parse_relative_duration(since)?;
            let start = now.checked_sub_signed(duration).ok_or_else(|| {
                CliError::user("--since duration is outside the supported date range")
            })?;
            Ok((
                start.format("%Y-%m-%d").to_string(),
                now.format("%Y-%m-%d").to_string(),
            ))
        }
    }
}

fn export_job_failed_error(job_id: &str, job: &serde_json::Value) -> CliError {
    if let Some(message) = job_failure_message(job) {
        return CliError::user(format!("export job {job_id} failed: {message}"));
    }

    CliError::user(format!("export job {job_id} failed"))
}

fn export_job_expired_error(job_id: &str) -> CliError {
    CliError::user(format!(
        "export job {job_id} expired before it became downloadable"
    ))
}

pub(crate) async fn run_async(args: ExportJobCreateArgs) -> Result<(), CliError> {
    let inputs = ConfigInputs {
        api_url_flag: args.api_url.clone(),
        api_token_flag: args.api_token.clone(),
        config_path: args.config.clone(),
        profile_flag: Some(args.profile.clone()),
        region_flag: args.region,
    };
    let config = Config::resolve(inputs)?;
    let api_token = config.api_token.ok_or_else(|| {
        CliError::auth("missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)")
    })?;
    let client = AsyncApiClient::new(config.api_url, api_token)?.with_region(config.region.clone());

    let (start_date, end_date) = resolve_export_dates(
        args.start_date.as_deref(),
        args.end_date.as_deref(),
        args.since.as_deref(),
        Utc::now(),
    )?;

    let payload = serde_json::json!({
        "start_date": start_date,
        "end_date": end_date,
        "format": args.format,
    });

    let value = client.post_json_value("/v1/exports/jobs", &payload).await?;

    let job_id = required_job_id(created_job(&value)?)?.to_string();

    if args.wait {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(args.wait_timeout_secs);
        let poll_interval = std::time::Duration::from_secs(2);

        loop {
            let list_response = client.get_json_value("/v1/exports/jobs").await?;
            if let Some(job) = find_job(&list_response, &job_id)? {
                match required_job_status(job)? {
                    "completed" => {
                        if args.json {
                            return print_json(job);
                        }
                        println!("job {job_id} completed");
                        return Ok(());
                    }
                    "failed" => return Err(export_job_failed_error(&job_id, job)),
                    "expired" => return Err(export_job_expired_error(&job_id)),
                    "queued" | "processing" => {}
                    status => {
                        return Err(CliError::internal(format!(
                            "api response contains unknown export job status '{status}'"
                        )));
                    }
                }
            }

            let sleep_for = deadline
                .saturating_duration_since(std::time::Instant::now())
                .min(poll_interval);
            if sleep_for.is_zero() {
                return Err(CliError::user(format!(
                    "export job {job_id} did not complete within {} seconds",
                    args.wait_timeout_secs
                )));
            }

            tokio::time::sleep(sleep_for).await;

            if std::time::Instant::now() >= deadline {
                return Err(CliError::user(format!(
                    "export job {job_id} did not complete within {} seconds",
                    args.wait_timeout_secs
                )));
            }
        }
    }

    if args.json {
        return print_json(&value);
    }

    println!("created export job {job_id}");
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

    use super::*;
    use serde_json::json;

    #[test]
    fn parse_relative_duration_hours() {
        let d = parse_relative_duration("24h").unwrap();
        assert_eq!(d.num_hours(), 24);
    }

    #[test]
    fn parse_relative_duration_days() {
        let d = parse_relative_duration("7d").unwrap();
        assert_eq!(d.num_days(), 7);
    }

    #[test]
    fn parse_relative_duration_single_day() {
        let d = parse_relative_duration("1d").unwrap();
        assert_eq!(d.num_days(), 1);
    }

    #[test]
    fn parse_relative_duration_invalid_suffix() {
        let result = parse_relative_duration("30m");
        assert!(result.is_err());
    }

    #[test]
    fn parse_relative_duration_invalid_number() {
        let result = parse_relative_duration("abch");
        assert!(result.is_err());
    }

    #[test]
    fn parse_relative_duration_no_suffix() {
        let result = parse_relative_duration("123");
        assert!(result.is_err());
    }

    #[test]
    fn parse_relative_duration_whitespace_trimmed() {
        let d = parse_relative_duration("  12h  ").unwrap();
        assert_eq!(d.num_hours(), 12);
    }

    #[test]
    fn export_job_failed_error_with_message() {
        let m = json!({"failure_message": "quota exceeded"});
        let err = export_job_failed_error("j-1", &m);
        let msg = err.to_string();
        assert!(msg.contains("j-1"));
        assert!(msg.contains("quota exceeded"));
    }

    #[test]
    fn export_job_failed_error_without_message() {
        let m = json!({});
        let err = export_job_failed_error("j-2", &m);
        let msg = err.to_string();
        assert!(msg.contains("j-2"));
        assert!(msg.contains("failed"));
    }

    #[test]
    fn create_payload_construction() {
        let payload = json!({
            "start_date": "2025-01-01",
            "end_date": "2025-01-31",
            "format": "csv",
        });
        assert_eq!(payload["start_date"], "2025-01-01");
        assert_eq!(payload["end_date"], "2025-01-31");
        assert_eq!(payload["format"], "csv");
    }

    #[test]
    fn parse_relative_duration_large_numbers() {
        let d = parse_relative_duration("365d").unwrap();
        assert_eq!(d.num_days(), 365);
    }

    #[test]
    fn export_job_failed_error_uses_current_failure_field() {
        let m = json!({"failure_message": "disk quota exceeded"});
        let err = export_job_failed_error("j-3", &m);
        assert!(err.to_string().contains("disk quota exceeded"));
    }

    #[test]
    fn parse_relative_duration_minutes_not_supported() {
        assert!(parse_relative_duration("45m").is_err());
    }

    #[test]
    fn parse_relative_duration_zero_hours() {
        assert!(parse_relative_duration("0h").is_err());
    }

    #[test]
    fn parse_relative_duration_zero_days() {
        assert!(parse_relative_duration("0d").is_err());
    }

    #[test]
    fn parse_relative_duration_with_leading_whitespace() {
        let d = parse_relative_duration("  24h  ").unwrap();
        assert_eq!(d.num_hours(), 24);
    }

    #[test]
    fn create_payload_with_all_formats() {
        for fmt in [
            "csv",
            "json",
            "compliance-aesia",
            "compliance-aepd",
            "compliance-ens",
            "compliance-all",
        ] {
            let payload = json!({"format": fmt});
            assert_eq!(payload["format"].as_str().unwrap(), fmt);
        }
    }

    #[test]
    fn export_job_expired_error_is_actionable() {
        let err = export_job_expired_error("j-expired");
        let message = err.to_string();
        assert!(message.contains("j-expired"));
        assert!(message.contains("expired"));
    }

    #[test]
    fn export_job_failed_error_empty_failure_message() {
        let m = json!({"failure_message": ""});
        let err = export_job_failed_error("j-empty", &m);
        let msg = err.to_string();
        assert!(msg.contains("j-empty"));
    }

    #[test]
    fn resolve_export_dates_rejects_partial_or_reversed_explicit_window() {
        let now = DateTime::parse_from_rfc3339("2026-07-17T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(resolve_export_dates(Some("2026-07-01"), None, Some("7d"), now).is_err());
        assert!(resolve_export_dates(None, Some("2026-07-17"), Some("7d"), now).is_err());
        assert!(resolve_export_dates(Some("2026-07-18"), Some("2026-07-17"), None, now,).is_err());
    }

    #[test]
    fn resolve_export_dates_uses_positive_since_when_explicit_dates_are_absent() {
        let now = DateTime::parse_from_rfc3339("2026-07-17T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            resolve_export_dates(None, None, Some("7d"), now).unwrap(),
            ("2026-07-10".to_string(), "2026-07-17".to_string())
        );
    }
}
