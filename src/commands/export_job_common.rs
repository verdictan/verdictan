// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Shared parsing for the current asynchronous export-job API contract.

use serde_json::Value;

use crate::error::CliError;

pub(crate) fn created_job(response: &Value) -> Result<&Value, CliError> {
    response
        .get("job")
        .filter(|job| job.is_object())
        .ok_or_else(|| CliError::internal("api response missing export job"))
}

pub(crate) fn jobs(response: &Value) -> Result<&[Value], CliError> {
    response
        .get("jobs")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| CliError::internal("api response missing export jobs"))
}

pub(crate) fn find_job<'a>(
    response: &'a Value,
    expected_job_id: &str,
) -> Result<Option<&'a Value>, CliError> {
    Ok(jobs(response)?
        .iter()
        .find(|job| job_id(job) == Some(expected_job_id)))
}

pub(crate) fn job_id(job: &Value) -> Option<&str> {
    job.get("job_id").and_then(Value::as_str)
}

pub(crate) fn job_status(job: &Value) -> Option<&str> {
    job.get("status").and_then(Value::as_str)
}

pub(crate) fn job_failure_message(job: &Value) -> Option<&str> {
    job.get("failure_message")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|message| !message.is_empty())
}

pub(crate) fn required_job_id(job: &Value) -> Result<&str, CliError> {
    job_id(job).ok_or_else(|| CliError::internal("api response missing export job id"))
}

pub(crate) fn required_job_status(job: &Value) -> Result<&str, CliError> {
    job_status(job).ok_or_else(|| CliError::internal("api response missing export job status"))
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

    use super::*;

    #[test]
    fn parses_current_create_response_shape() {
        let response = json!({
            "job": {
                "job_id": "exp_123",
                "status": "queued",
                "format": "csv"
            },
            "queue_topic": "org.exports"
        });

        let job = created_job(&response).unwrap();
        assert_eq!(required_job_id(job).unwrap(), "exp_123");
        assert_eq!(required_job_status(job).unwrap(), "queued");
    }

    #[test]
    fn finds_job_by_current_job_id_field() {
        let response = json!({
            "jobs": [
                {"job_id": "exp_queued", "status": "queued"},
                {"job_id": "exp_ready", "status": "completed"}
            ]
        });

        let job = find_job(&response, "exp_ready").unwrap().unwrap();
        assert_eq!(required_job_status(job).unwrap(), "completed");
    }

    #[test]
    fn rejects_legacy_id_field() {
        let response = json!({"job": {"id": "legacy-id", "status": "queued"}});
        let job = created_job(&response).unwrap();
        assert!(required_job_id(job).is_err());
    }

    #[test]
    fn trims_failure_message() {
        let job = json!({"failure_message": "  worker failed  "});
        assert_eq!(job_failure_message(&job), Some("worker failed"));
    }

    #[test]
    fn empty_failure_message_is_absent() {
        let job = json!({"failure_message": "   "});
        assert_eq!(job_failure_message(&job), None);
    }

    #[test]
    fn jobs_requires_array() {
        assert!(jobs(&json!({"jobs": {}})).is_err());
        assert!(jobs(&json!({})).is_err());
    }
}
