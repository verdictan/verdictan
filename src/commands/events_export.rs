// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;
use std::io::Write;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;

#[derive(Debug, Args)]
pub(crate) struct EventsExportArgs {
    /// Since (RFC3339 UTC or a relative duration, for example 10m, 2h, 7d, or 1w).
    #[arg(long)]
    pub(crate) since: String,

    /// Export format: csv or json.
    #[arg(long, value_parser = ["csv", "json"])]
    pub(crate) format: String,

    /// Optional config file path (YAML).
    #[arg(long)]
    pub(crate) config: Option<std::path::PathBuf>,

    /// Override API URL.
    #[arg(long)]
    pub(crate) api_url: Option<String>,

    /// Profile name (default: "default").
    #[arg(long, default_value = "default")]
    pub(crate) profile: String,

    /// Target region for this API call.
    #[arg(long)]
    pub(crate) region: Option<String>,
}
pub(crate) async fn run_async(args: EventsExportArgs) -> Result<(), CliError> {
    let inputs = ConfigInputs {
        api_url_flag: args.api_url,
        api_token_flag: None,
        config_path: args.config,
        profile_flag: Some(args.profile),
        region_flag: args.region,
    };

    let config = Config::resolve(inputs)?;
    let api_token = config.api_token.ok_or_else(|| {
        CliError::auth("missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)")
    })?;

    let client = AsyncApiClient::new(config.api_url, api_token)?.with_region(config.region.clone());

    let path = build_export_path(&args.since, &args.format);

    let (status, bytes) = client.get_bytes(&path).await?;
    if !status.is_success() {
        return Err(classify_export_error(status));
    }

    std::io::stdout()
        .write_all(&bytes)
        .map_err(|e| CliError::internal(format!("failed to write export to stdout: {e}")))?;

    Ok(())
}

fn classify_export_error(status: reqwest::StatusCode) -> CliError {
    let code = status.as_u16();
    match code {
        401 | 403 => CliError::auth(format!(
            "authorization failed for events export (HTTP {code})"
        ))
        .with_http_status(code),
        400 | 409 | 422 => {
            CliError::user(format!("validation error for events export (HTTP {code})"))
                .with_http_status(code)
        }
        500..=599 => CliError::network(format!(
            "remote service error for events export (HTTP {code})"
        ))
        .with_http_status(code),
        _ => CliError::network(format!("api request failed with status {code}"))
            .with_http_status(code),
    }
}

fn build_export_path(since: &str, format: &str) -> String {
    let since = urlencoding::encode(since);
    let format = urlencoding::encode(format);
    format!("/v1/events/export?since={since}&format={format}")
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
    use axum::{routing::get, Router};
    use serde::Deserialize;
    use tokio::net::TcpListener;

    #[test]
    fn command_helper_coverage_build_export_path_encodes_query_params() {
        assert_eq!(
            build_export_path("1h", "csv"),
            "/v1/events/export?since=1h&format=csv"
        );
        assert_eq!(
            build_export_path("2025-01-01T00:00:00Z", "json"),
            "/v1/events/export?since=2025-01-01T00%3A00%3A00Z&format=json"
        );
    }

    #[test]
    fn build_export_path_with_plus_in_since() {
        let path = build_export_path("2025-01-01T00:00:00+05:30", "csv");
        assert!(path.contains("since=2025-01-01T00%3A00%3A00%2B05%3A30"));
    }

    #[derive(Debug, Deserialize)]
    struct ExportQuery {
        since: Option<String>,
        format: Option<String>,
    }

    async fn spawn_export_api() -> String {
        let app = Router::new().route(
            "/v1/events/export",
            get(
                |axum::extract::Query(query): axum::extract::Query<ExportQuery>| async move {
                    assert_eq!(query.since.as_deref(), Some("30m"));
                    assert_eq!(query.format.as_deref(), Some("csv"));
                    "event_id,timestamp\n"
                },
            ),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind export api");
        let addr = listener.local_addr().expect("export addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve export api");
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn run_async_writes_export_bytes_to_stdout() {
        let api_url = spawn_export_api().await;
        std::env::set_var("VERDICTAN_API_TOKEN", "test-token");
        let args = EventsExportArgs {
            since: "30m".to_string(),
            format: "csv".to_string(),
            config: None,
            api_url: Some(api_url),
            profile: "default".to_string(),
            region: None,
        };
        run_async(args).await.expect("export succeeds");
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

        let args = EventsExportArgs {
            since: "30m".to_string(),
            format: "csv".to_string(),
            config: None,
            api_url: Some("http://127.0.0.1:9".to_string()),
            profile: "default".to_string(),
            region: None,
        };
        let err = run_async(args)
            .await
            .expect_err("missing token should fail");
        assert!(err.to_string().contains("missing api token"));
    }

    #[tokio::test]
    async fn run_async_maps_5xx_to_network_error() {
        let app = Router::new().route(
            "/v1/events/export",
            get(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind export api");
        let api_url = format!(
            "http://{}",
            listener.local_addr().expect("export error addr")
        );
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve export error api");
        });

        let args = EventsExportArgs {
            since: "1h".to_string(),
            format: "json".to_string(),
            config: None,
            api_url: Some(api_url),
            profile: "default".to_string(),
            region: None,
        };
        std::env::set_var("VERDICTAN_API_TOKEN", "test-token");
        let err = run_async(args)
            .await
            .expect_err("export status should fail");
        assert!(err.to_string().contains("remote service error"));
        assert_eq!(err.exit_code(), crate::error::EXIT_NETWORK);
    }

    #[tokio::test]
    async fn run_async_maps_403_to_auth_error() {
        let app = Router::new().route(
            "/v1/events/export",
            get(|| async { axum::http::StatusCode::FORBIDDEN }),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind export api");
        let api_url = format!(
            "http://{}",
            listener.local_addr().expect("export auth addr")
        );
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve export auth api");
        });

        std::env::set_var("VERDICTAN_API_TOKEN", "test-token");
        let args = EventsExportArgs {
            since: "1h".to_string(),
            format: "json".to_string(),
            config: None,
            api_url: Some(api_url),
            profile: "default".to_string(),
            region: None,
        };
        let err = run_async(args).await.expect_err("403 should fail");
        assert!(err.to_string().contains("authorization failed"));
        assert_eq!(err.exit_code(), crate::error::EXIT_AUTH);
    }

    #[tokio::test]
    async fn run_async_maps_422_to_validation_error() {
        let app = Router::new().route(
            "/v1/events/export",
            get(|| async { axum::http::StatusCode::UNPROCESSABLE_ENTITY }),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind export api");
        let api_url = format!(
            "http://{}",
            listener.local_addr().expect("export validation addr")
        );
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve export validation api");
        });

        std::env::set_var("VERDICTAN_API_TOKEN", "test-token");
        let args = EventsExportArgs {
            since: "1h".to_string(),
            format: "json".to_string(),
            config: None,
            api_url: Some(api_url),
            profile: "default".to_string(),
            region: None,
        };
        let err = run_async(args).await.expect_err("422 should fail");
        assert!(err.to_string().contains("validation error"));
        assert_eq!(err.exit_code(), crate::error::EXIT_USER);
    }

    #[test]
    fn build_export_path_encodes_ampersand_in_since() {
        let path = build_export_path("a&b", "csv");
        assert!(path.contains("since=a%26b"));
    }

    #[test]
    fn args_debug_impl() {
        let args = EventsExportArgs {
            since: "1h".to_string(),
            format: "csv".to_string(),
            config: None,
            api_url: Some("http://localhost".to_string()),
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("csv"));
        assert!(debug.contains("1h"));
    }

    #[test]
    fn build_export_path_empty_since() {
        let path = build_export_path("", "csv");
        assert_eq!(path, "/v1/events/export?since=&format=csv");
    }
}
