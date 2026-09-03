// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Trail commands for immutable audit trail operations.
//!
//! This module provides CLI commands for querying, verifying, and exporting
//! trail events from the CloudTrail-style immutable audit system.

pub(crate) mod anchor_verify;
pub(crate) mod export;
pub(crate) mod lookup;
pub(crate) mod verify;

use chrono::{DateTime, Duration, Utc};
use clap::Subcommand;
use uuid::Uuid;

use crate::api::AsyncApiClient;
use crate::error::CliError;

#[derive(Debug, Subcommand)]
pub(crate) enum TrailCommands {
    /// Verify hash chain integrity for trail events.
    Verify(verify::VerifyArgs),
    /// Query and display trail events.
    Lookup(lookup::LookupArgs),
    /// Export trail events to a file.
    Export(export::ExportArgs),
}

/// Verify that an optional CLI organization assertion matches the organization
/// selected by the authenticated API token.
///
/// Trail endpoints are authorization-scoped and do not accept an organization
/// selector. This client-side check keeps `--org-id` as an automation guardrail.
/// It does not make the option look like a routing control.
pub(crate) async fn assert_authenticated_org(
    client: &AsyncApiClient,
    expected_org_id: Option<&str>,
) -> Result<Option<String>, CliError> {
    let Some(expected_org_id) = expected_org_id else {
        return Ok(None);
    };
    let expected_org_uuid = Uuid::parse_str(expected_org_id).map_err(|_| {
        CliError::user(format!(
            "invalid --org-id '{expected_org_id}': expected a UUID"
        ))
    })?;

    let whoami = client.get_json_value("/v1/whoami").await?;
    let authenticated_org_id = whoami
        .get("org_id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::internal("whoami response missing org_id"))?;
    let authenticated_org_uuid = Uuid::parse_str(authenticated_org_id)
        .map_err(|_| CliError::internal("whoami response contains an invalid org_id"))?;

    if authenticated_org_uuid != expected_org_uuid {
        return Err(CliError::user(format!(
            "authenticated organization is {authenticated_org_id}, not {expected_org_id}"
        )));
    }

    Ok(Some(authenticated_org_uuid.to_string()))
}

pub(crate) fn parse_rfc3339_arg(
    value: &str,
    argument_name: &str,
) -> Result<DateTime<Utc>, CliError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| {
            CliError::user(format!(
                "invalid {argument_name} '{value}': expected an RFC 3339 timestamp"
            ))
        })
}

pub(crate) fn validate_bounded_query_window(
    start_time: Option<&str>,
    end_time: Option<&str>,
    max_days: i64,
) -> Result<(), CliError> {
    let start = start_time
        .map(|value| parse_rfc3339_arg(value, "--start-time"))
        .transpose()?;
    let end = end_time
        .map(|value| parse_rfc3339_arg(value, "--end-time"))
        .transpose()?;

    if let (Some(start), Some(end)) = (start, end) {
        if start >= end {
            return Err(CliError::user(
                "--start-time must be earlier than --end-time",
            ));
        }
        if end.signed_duration_since(start) > Duration::days(max_days) {
            return Err(CliError::user(format!(
                "trail query window must not exceed {max_days} days"
            )));
        }
    }

    Ok(())
}

pub(crate) fn resolve_verify_window(
    start_time: Option<&str>,
    end_time: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(String, String), CliError> {
    let start = match start_time {
        Some(value) => parse_verify_start(value, &now)?,
        None => now
            .checked_sub_signed(Duration::days(7))
            .ok_or_else(|| CliError::user("default verification window is out of range"))?,
    };
    let end = match end_time {
        Some(value) => parse_rfc3339_arg(value, "--end-time")?,
        None => now,
    };

    if start >= end {
        return Err(CliError::user(
            "--start-time must be earlier than --end-time",
        ));
    }

    Ok((
        start.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        end.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
    ))
}

fn parse_verify_start(value: &str, now: &DateTime<Utc>) -> Result<DateTime<Utc>, CliError> {
    if let Ok(timestamp) = DateTime::parse_from_rfc3339(value) {
        return Ok(timestamp.with_timezone(&Utc));
    }

    let (amount, unit) = if let Some(amount) = value.strip_suffix('h') {
        (amount, "h")
    } else if let Some(amount) = value.strip_suffix('d') {
        (amount, "d")
    } else {
        return Err(CliError::user(format!(
            "invalid --start-time '{value}': expected RFC 3339 or a positive duration such as 24h or 7d"
        )));
    };
    let amount = amount.parse::<i64>().map_err(|_| {
        CliError::user(format!(
            "invalid --start-time '{value}': expected RFC 3339 or a positive duration such as 24h or 7d"
        ))
    })?;
    if amount <= 0 {
        return Err(CliError::user(
            "relative --start-time duration must be greater than zero",
        ));
    }
    let duration = match unit {
        "h" => Duration::try_hours(amount),
        "d" => Duration::try_days(amount),
        _ => None,
    }
    .ok_or_else(|| {
        CliError::user(format!(
            "invalid --start-time '{value}': expected RFC 3339 or a positive duration such as 24h or 7d"
        ))
    })?;

    now.checked_sub_signed(duration)
        .ok_or_else(|| CliError::user("relative --start-time is outside the supported date range"))
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

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-17T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn resolve_verify_window_converts_relative_hours_and_days() {
        let (start, end) = resolve_verify_window(Some("24h"), None, fixed_now()).unwrap();
        assert_eq!(start, "2026-07-16T12:00:00Z");
        assert_eq!(end, "2026-07-17T12:00:00Z");

        let (start, _) = resolve_verify_window(Some("7d"), None, fixed_now()).unwrap();
        assert_eq!(start, "2026-07-10T12:00:00Z");
    }

    #[test]
    fn resolve_verify_window_rejects_invalid_or_reversed_ranges() {
        assert!(resolve_verify_window(Some("0h"), None, fixed_now()).is_err());
        assert!(resolve_verify_window(Some("-1d"), None, fixed_now()).is_err());
        assert!(resolve_verify_window(Some("7w"), None, fixed_now()).is_err());
        assert!(resolve_verify_window(Some("é"), None, fixed_now()).is_err());
        assert!(resolve_verify_window(
            Some("2026-07-18T00:00:00Z"),
            Some("2026-07-17T00:00:00Z"),
            fixed_now(),
        )
        .is_err());
    }

    #[test]
    fn validate_bounded_query_window_enforces_rfc3339_order_and_limit() {
        assert!(validate_bounded_query_window(
            Some("2026-07-10T00:00:00Z"),
            Some("2026-07-17T00:00:00Z"),
            7,
        )
        .is_ok());
        assert!(validate_bounded_query_window(
            Some("2026-07-17T00:00:00Z"),
            Some("2026-07-17T00:00:00Z"),
            7,
        )
        .is_err());
        assert!(validate_bounded_query_window(
            Some("2026-07-09T23:59:59Z"),
            Some("2026-07-17T00:00:00Z"),
            7,
        )
        .is_err());
    }
}
