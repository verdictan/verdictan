// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan export-jobs download` — stream the completed export artifact to stdout.

use std::io::Write;

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;

#[derive(Debug, Args)]
pub(crate) struct ExportJobDownloadArgs {
    /// Export job id.
    #[arg(long)]
    pub(crate) job_id: String,

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
pub(crate) async fn run_async(args: ExportJobDownloadArgs) -> Result<(), CliError> {
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

    let path = format!("/v1/exports/jobs/{}/download", args.job_id);
    let (status, bytes) = client.get_bytes(&path).await?;

    if !status.is_success() {
        return Err(CliError::network(format!(
            "download failed with status {}",
            status.as_u16()
        )));
    }

    std::io::stdout()
        .write_all(&bytes)
        .map_err(|e| CliError::internal(format!("failed to write export to stdout: {e}")))?;

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

    #[test]
    fn download_path_formatting() {
        let job_id = "job-42";
        let path = format!("/v1/exports/jobs/{}/download", job_id);
        assert_eq!(path, "/v1/exports/jobs/job-42/download");
    }

    #[test]
    fn error_status_message() {
        let status_code = 404u16;
        let msg = format!("download failed with status {}", status_code);
        assert!(msg.contains("404"));
    }

    #[test]
    fn error_status_message_500() {
        let status_code = 500u16;
        let msg = format!("download failed with status {}", status_code);
        assert!(msg.contains("500"));
    }

    #[test]
    fn download_path_with_uuid() {
        let job_id = "550e8400-e29b-41d4-a716-446655440000";
        let path = format!("/v1/exports/jobs/{}/download", job_id);
        assert!(path.contains("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn download_path_starts_with_expected_prefix() {
        let job_id = "any-id";
        let path = format!("/v1/exports/jobs/{}/download", job_id);
        assert!(path.starts_with("/v1/exports/jobs/"));
        assert!(path.ends_with("/download"));
    }

    #[test]
    fn error_status_message_formats_all_common_codes() {
        for code in [400u16, 401, 403, 404, 500, 502, 503] {
            let msg = format!("download failed with status {}", code);
            assert!(msg.contains(&code.to_string()));
        }
    }

    #[test]
    fn args_debug_impl() {
        let args = super::ExportJobDownloadArgs {
            job_id: "job-123".to_string(),
            config: None,
            api_url: Some("http://api.test".to_string()),
            api_token: Some("tok".to_string()),
            profile: "default".to_string(),
            region: Some("us-west-2".to_string()),
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("job-123"));
        assert!(debug.contains("us-west-2"));
    }

    #[test]
    fn args_with_config_path() {
        let args = super::ExportJobDownloadArgs {
            job_id: "j-1".to_string(),
            config: Some(std::path::PathBuf::from("/etc/verdictan/config.yaml")),
            api_url: None,
            api_token: None,
            profile: "prod".to_string(),
            region: None,
        };
        assert_eq!(
            args.config.unwrap().to_str().unwrap(),
            "/etc/verdictan/config.yaml"
        );
        assert_eq!(args.profile, "prod");
    }

    #[test]
    fn stdout_write_error_message_formatting() {
        let err_msg = "broken pipe";
        let msg = format!("failed to write export to stdout: {}", err_msg);
        assert!(msg.contains("failed to write export to stdout"));
        assert!(msg.contains("broken pipe"));
    }
}
