// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;
use crate::supervisor::{default_state_dir, SupervisorStateStore};

#[derive(Debug, Args)]
pub(crate) struct GatewayListArgs {
    #[arg(long)]
    pub(crate) state_dir: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) json: bool,

    /// List gateways registered in the remote API (uses /v1/gateways).
    #[arg(long)]
    pub(crate) remote: bool,

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
pub(crate) async fn run_async(args: GatewayListArgs) -> Result<(), CliError> {
    if args.remote {
        return run_remote_async(args).await;
    }
    run_local(args)
}

fn run_local(args: GatewayListArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.unwrap_or(default_state_dir()?);
    let store = SupervisorStateStore::load(state_dir)?;
    let instances = store.list_instances();
    let supervisor = store.metadata();

    if args.json {
        return print_json(&serde_json::json!({
            "supervisor": supervisor,
            "items": instances
        }));
    }

    if let Some(message) = supervisor.recovery_message {
        eprintln!("warning: {}", message);
    }

    if instances.is_empty() {
        println!("no gateway instances defined");
        return Ok(());
    }

    for instance in instances {
        println!(
            "{}\t{}\t{}\t{}",
            instance.instance_id, instance.lifecycle, instance.listen_addr, instance.gateway_id
        );
    }
    Ok(())
}

pub(crate) async fn run_remote_async(args: GatewayListArgs) -> Result<(), CliError> {
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

    let value = client.get_json_value("/v1/gateways").await?;

    if args.json {
        return print_json(&value);
    }

    let items = value
        .get("gateways")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if items.is_empty() {
        println!("no remote gateways");
        return Ok(());
    }

    for gw in &items {
        let id = gw.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        let name = gw.get("name").and_then(|v| v.as_str()).unwrap_or("-");
        let status = gw.get("status").and_then(|v| v.as_str()).unwrap_or("-");
        println!("{id}\t{name}\t{status}");
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

    use super::*;
    use crate::instances::status::GatewayInstanceLifecycle;
    use crate::instances::{
        GatewayInstanceId, GatewayInstanceSpec, GatewayInstanceStatus, PolicyConfigSource,
    };
    use crate::supervisor::SupervisorStateStore;
    use crate::test_support;
    use tempfile::tempdir;

    fn with_test_home<F: FnOnce() -> R, R>(run: F) -> R {
        let _guard = test_support::env_lock().lock().expect("env lock");
        let dir = tempdir().expect("tempdir");
        test_support::set_var("HOME", dir.path());
        test_support::set_var(
            "VERDICTAN_TEST_HOME",
            dir.path().to_string_lossy().to_string(),
        );
        run()
    }

    fn list_args(state_dir: std::path::PathBuf) -> GatewayListArgs {
        GatewayListArgs {
            state_dir: Some(state_dir),
            json: false,
            remote: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        }
    }

    fn write_instance(state_dir: &std::path::Path, instance_id: &str) {
        let mut store = SupervisorStateStore::load(state_dir.to_path_buf()).expect("load store");
        store
            .create_instance(
                GatewayInstanceSpec::new(
                    GatewayInstanceId::new(instance_id).expect("instance id"),
                    format!("gateway_{instance_id}"),
                    format!("instance_{instance_id}"),
                    "127.0.0.1:8080",
                    "https://example.com",
                    None,
                    None,
                    None,
                    "allow",
                    PolicyConfigSource::path("policy-config.yaml"),
                    1,
                    None,
                    true,
                )
                .expect("instance spec"),
            )
            .expect("create instance");
        store
            .set_status(
                instance_id,
                GatewayInstanceStatus::default().with_lifecycle(GatewayInstanceLifecycle::Running),
            )
            .expect("set status");
    }

    #[test]
    fn command_helper_coverage_run_local_reports_empty_supervisor_state() {
        with_test_home(|| {
            let dir = tempdir().expect("tempdir");
            run_local(list_args(dir.path().to_path_buf())).expect("empty list");
        });
    }

    #[test]
    fn command_helper_coverage_run_local_json_includes_instances() {
        with_test_home(|| {
            let dir = tempdir().expect("tempdir");
            write_instance(dir.path(), "inst-a");

            let mut args = list_args(dir.path().to_path_buf());
            args.json = true;
            run_local(args).expect("json list");
        });
    }

    #[test]
    fn command_helper_coverage_run_local_prints_instance_rows() {
        with_test_home(|| {
            let dir = tempdir().expect("tempdir");
            write_instance(dir.path(), "inst-b");

            run_local(list_args(dir.path().to_path_buf())).expect("human list");
        });
    }

    use axum::{routing::get, Json, Router};
    use serde_json::json;
    use tokio::net::TcpListener;

    async fn spawn_gateways_server(empty: bool) -> String {
        let app = Router::new().route(
            "/v1/gateways",
            get(move || async move {
                if empty {
                    Json(json!({ "gateways": [] }))
                } else {
                    Json(json!({
                        "gateways": [
                            { "id": "gw-1", "name": "prod", "status": "active" },
                            { "id": "gw-2", "name": "staging", "status": "inactive" }
                        ]
                    }))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve gateways stub");
        });
        base_url
    }

    fn remote_args(api_url: String, json: bool) -> GatewayListArgs {
        GatewayListArgs {
            state_dir: None,
            json,
            remote: true,
            config: None,
            api_url: Some(api_url),
            api_token: Some("test-token".to_string()),
            profile: "default".to_string(),
            region: None,
        }
    }

    #[tokio::test]
    async fn command_helper_coverage_run_remote_async_prints_human_rows() {
        let api_url = spawn_gateways_server(false).await;
        run_remote_async(remote_args(api_url, false))
            .await
            .expect("remote human list");
    }

    #[tokio::test]
    async fn command_helper_coverage_run_remote_async_reports_empty_remote_gateways() {
        let api_url = spawn_gateways_server(true).await;
        run_remote_async(remote_args(api_url, false))
            .await
            .expect("empty remote list");
    }

    #[tokio::test]
    async fn command_helper_coverage_run_remote_async_json_returns_payload() {
        let api_url = spawn_gateways_server(false).await;
        run_remote_async(remote_args(api_url, true))
            .await
            .expect("remote json list");
    }

    #[tokio::test]
    async fn command_helper_coverage_run_async_dispatches_remote_list() {
        let api_url = spawn_gateways_server(false).await;
        let args = remote_args(api_url, true);
        run_async(args).await.expect("run_async remote dispatch");
    }

    #[tokio::test]
    async fn command_helper_coverage_run_remote_async_requires_api_token() {
        let _guard = test_support::env_lock().lock().expect("env lock");
        let dir = tempdir().expect("tempdir");
        test_support::set_var("HOME", dir.path());
        test_support::set_var(
            "VERDICTAN_TEST_HOME",
            dir.path().to_string_lossy().to_string(),
        );
        std::env::remove_var("VERDICTAN_API_TOKEN");
        std::env::remove_var("VERDICTAN_CONFIG");

        let mut args = remote_args("http://127.0.0.1:9".to_string(), false);
        args.api_token = None;
        let err = run_remote_async(args)
            .await
            .expect_err("missing token should fail");
        assert!(err.to_string().contains("missing api token"));
    }

    #[test]
    fn command_helper_coverage_run_local_multiple_instances() {
        with_test_home(|| {
            let dir = tempdir().expect("tempdir");
            write_instance(dir.path(), "inst-1");
            write_instance(dir.path(), "inst-2");
            write_instance(dir.path(), "inst-3");

            run_local(list_args(dir.path().to_path_buf())).expect("multi list");
        });
    }

    #[test]
    fn args_debug_impl() {
        let args = GatewayListArgs {
            state_dir: None,
            json: false,
            remote: false,
            config: None,
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            region: None,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("GatewayListArgs"));
    }

    #[test]
    fn args_remote_mode_flag() {
        let args = GatewayListArgs {
            state_dir: None,
            json: true,
            remote: true,
            config: None,
            api_url: Some("http://api.test".to_string()),
            api_token: Some("tok".to_string()),
            profile: "default".to_string(),
            region: Some("us-east-1".to_string()),
        };
        assert!(args.remote);
        assert!(args.json);
        assert_eq!(args.region.as_deref(), Some("us-east-1"));
    }
}
