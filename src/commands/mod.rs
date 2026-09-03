// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

pub(crate) mod agent_create;
pub(crate) mod agent_delete;
pub(crate) mod agent_get;
pub(crate) mod agent_link_gateway;
pub(crate) mod agent_list;
pub(crate) mod agent_unlink_gateway;
pub(crate) mod agent_update;
pub mod auth_login;
pub(crate) mod auth_logout;
pub(crate) mod auth_token;
pub(crate) mod auth_whoami;
pub(crate) mod budget_create;
pub(crate) mod budget_delete;
pub(crate) mod budget_get;
pub(crate) mod budget_list;
pub(crate) mod budget_update;
pub(crate) mod cache;
pub(crate) mod config_validate;
pub(crate) mod configure;
pub(crate) mod control_apply;
pub(crate) mod control_export;
pub(crate) mod control_plan;
pub(crate) mod doctor;
pub(crate) mod escalation_claim;
pub(crate) mod escalation_get;
pub(crate) mod escalation_list;
pub(crate) mod escalation_resolve;
pub(crate) mod escalation_unclaim;
pub(crate) mod events_export;
pub(crate) mod events_tail;
pub(crate) mod export_job_common;
pub(crate) mod export_job_create;
pub(crate) mod export_job_download;
pub(crate) mod export_job_get;
pub(crate) mod export_job_list;
pub(crate) mod gateway_check;
pub(crate) mod gateway_config;
pub(crate) mod gateway_create;
pub(crate) mod gateway_diff;
pub mod gateway_history;
pub(crate) mod gateway_inspect;
pub(crate) mod gateway_install;
pub(crate) mod gateway_list;
pub(crate) mod gateway_reconcile;
pub(crate) mod gateway_reload;
pub(crate) mod gateway_revert;
pub mod gateway_run;
pub mod gateway_service;
pub(crate) mod gateway_start;
pub(crate) mod gateway_status;
pub(crate) mod gateway_stop;
pub(crate) mod gateway_uninstall;
pub mod gateway_upgrade;
pub(crate) mod history_condense;
pub(crate) mod history_export;
pub(crate) mod history_get_session;
pub(crate) mod history_learn;
pub(crate) mod history_list_sessions;
pub(crate) mod history_replay;
pub(crate) mod history_search;
pub(crate) mod history_share;
pub(crate) mod history_stats;
pub(crate) mod history_tag;
pub(crate) mod iam_policy_create;
pub(crate) mod iam_policy_delete;
pub(crate) mod iam_policy_get;
pub(crate) mod iam_policy_list;
pub(crate) mod iam_policy_update;
pub mod init;
pub(crate) mod policy_apply;
pub(crate) mod policy_common;
pub(crate) mod policy_diff;
pub(crate) mod policy_evaluate;
pub(crate) mod policy_export;
pub(crate) mod policy_lint;
pub(crate) mod policy_test;
pub(crate) mod provider_budget_create;
pub(crate) mod provider_budget_delete;
pub(crate) mod provider_budget_get;
pub(crate) mod provider_budget_list;
pub mod regions;
pub(crate) mod role_attach_policy;
pub(crate) mod role_create;
pub(crate) mod role_delete;
pub(crate) mod role_detach_policy;
pub(crate) mod role_get;
pub(crate) mod role_list;
pub(crate) mod role_show_actions;
pub(crate) mod role_show_assignments;
pub(crate) mod role_update;
pub(crate) mod secret_create;
pub(crate) mod secret_delete;
pub(crate) mod secret_get;
pub(crate) mod secret_list;
pub(crate) mod secret_update;
pub(crate) mod secrets_add;
pub(crate) mod secrets_status;
pub(crate) mod spend_summary;
pub(crate) mod team_add_member;
pub(crate) mod team_assign_role;
pub(crate) mod team_create;
pub(crate) mod team_delete;
pub(crate) mod team_detach_role;
pub(crate) mod team_get;
pub(crate) mod team_list;
pub(crate) mod team_list_members;
pub(crate) mod team_remove_member;
pub(crate) mod team_update;
pub(crate) mod token;
pub mod token_exchange_code;
pub(crate) mod trail;
pub(crate) mod user_assign_role;
pub(crate) mod user_detach_role;
pub(crate) mod user_get;
pub(crate) mod user_invite;
pub(crate) mod user_list;
pub(crate) mod user_reactivate;
pub(crate) mod user_remove_membership;
pub(crate) mod user_suspend;
pub(crate) mod user_update;
pub mod policy_push {
    use clap::Args;

    use crate::api::AsyncApiClient;
    use crate::config::{Config, ConfigInputs};
    use crate::error::CliError;
    use crate::output::json::print_json;

    #[derive(Debug, Args)]
    pub struct PolicyPushArgs {
        #[arg(long, default_value = "policy-config.yaml")]
        pub file: std::path::PathBuf,

        #[arg(long)]
        pub gateway_id: String,

        #[arg(long)]
        pub change_detail: Option<String>,

        #[arg(long)]
        pub json: bool,

        #[arg(long)]
        pub config: Option<std::path::PathBuf>,

        #[arg(long)]
        pub api_url: Option<String>,

        #[arg(long)]
        pub api_token: Option<String>,

        #[arg(long, default_value = "default")]
        pub profile: String,
    }

    pub fn run(args: PolicyPushArgs) -> Result<(), CliError> {
        tokio::runtime::Runtime::new()
            .map_err(|e| CliError::internal(format!("failed to create async runtime: {e}")))?
            .block_on(run_async(args))
    }

    pub(crate) async fn run_async(args: PolicyPushArgs) -> Result<(), CliError> {
        let yaml = std::fs::read_to_string(&args.file)
            .map_err(|e| CliError::user(format!("failed to read {}: {e}", args.file.display())))?;

        let inputs = ConfigInputs {
            api_url_flag: args.api_url,
            api_token_flag: args.api_token,
            config_path: args.config,
            profile_flag: Some(args.profile),
            region_flag: None,
        };

        let config = Config::resolve(inputs)?;
        let api_token = config.api_token.ok_or_else(|| {
            CliError::auth(
                "missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)",
            )
        })?;

        let client = AsyncApiClient::new(config.api_url, api_token)?;
        let path = format!(
            "/v1/admin/configurations/gateways/{}/versions",
            urlencoding::encode(args.gateway_id.trim())
        );
        let payload = serde_json::json!({
            "yaml": yaml,
            "source": "manual",
            "change_detail": args.change_detail.unwrap_or_else(|| "CLI policy push".to_string()),
            "set_current": true
        });

        let response = client.post_json_value(&path, &payload).await?;
        if args.json {
            return print_json(&response);
        }

        let version = response
            .get("version")
            .and_then(|value| value.as_object())
            .ok_or_else(|| CliError::internal("api response missing version object"))?;
        let id = version
            .get("id")
            .and_then(|value| value.as_str())
            .ok_or_else(|| CliError::internal("api response missing version.id"))?;

        println!("pushed policy version {id}");
        if let Some(value) = version.get("version").and_then(|item| item.as_str()) {
            println!("version: {value}");
        }
        if let Some(value) = version.get("sha256").and_then(|item| item.as_str()) {
            println!("sha256: {value}");
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
        use std::sync::{Arc, Mutex};

        use axum::{
            extract::{Path, State},
            routing::post,
            Json, Router,
        };
        use tempfile::tempdir;

        async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind listener");
            let addr = listener.local_addr().expect("listener addr");
            let handle = tokio::spawn(async move {
                axum::serve(listener, router).await.expect("serve test api");
            });
            (format!("http://{addr}"), handle)
        }

        fn write_policy_file(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
            let dir = tempdir().expect("tempdir");
            let path = dir.path().join("policy-config.yaml");
            std::fs::write(&path, contents).expect("write policy config");
            (dir, path)
        }

        #[tokio::test]
        async fn run_async_posts_expected_version_body() {
            let _env_guard = crate::test_support::env_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            crate::test_support::unset_var("VERDICTAN_API_URL");
            crate::test_support::unset_var("VERDICTAN_API_TOKEN");

            let (_dir, policy_file) = write_policy_file("mode: enforce\n");
            let payloads = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));

            async fn push_handler(
                Path(gateway_id): Path<String>,
                State(payloads): State<Arc<Mutex<Vec<serde_json::Value>>>>,
                Json(body): Json<serde_json::Value>,
            ) -> Json<serde_json::Value> {
                assert_eq!(gateway_id, "gw-test");
                payloads.lock().expect("payload lock").push(body);
                Json(serde_json::json!({
                    "version": {
                        "id": "ver_123",
                        "version": "2026-06-23T00:00:00Z",
                        "sha256": "abc123"
                    }
                }))
            }

            let router = Router::new()
                .route(
                    "/v1/admin/configurations/gateways/:gateway_id/versions",
                    post(push_handler),
                )
                .with_state(payloads.clone());
            let (base_url, handle) = serve(router).await;

            let result = run_async(PolicyPushArgs {
                file: policy_file,
                gateway_id: "gw-test".into(),
                change_detail: Some("manual detail".into()),
                json: false,
                config: None,
                api_url: Some(base_url),
                api_token: Some("token".into()),
                profile: "default".into(),
            })
            .await;

            handle.abort();
            result.expect("policy push should succeed");

            let payloads = payloads.lock().expect("payload lock");
            assert_eq!(payloads.len(), 1);
            assert_eq!(payloads[0]["yaml"], "mode: enforce\n");
            assert_eq!(payloads[0]["source"], "manual");
            assert_eq!(payloads[0]["change_detail"], "manual detail");
            assert_eq!(payloads[0]["set_current"], true);
        }

        #[tokio::test]
        async fn run_async_requires_version_id_in_response() {
            let _env_guard = crate::test_support::env_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            crate::test_support::unset_var("VERDICTAN_API_URL");
            crate::test_support::unset_var("VERDICTAN_API_TOKEN");

            let (_dir, policy_file) = write_policy_file("mode: audit\n");

            async fn push_handler() -> Json<serde_json::Value> {
                Json(serde_json::json!({
                    "version": {
                        "version": "missing-id"
                    }
                }))
            }

            let router = Router::new().route(
                "/v1/admin/configurations/gateways/:gateway_id/versions",
                post(push_handler),
            );
            let (base_url, handle) = serve(router).await;

            let error = run_async(PolicyPushArgs {
                file: policy_file,
                gateway_id: "gw-test".into(),
                change_detail: None,
                json: false,
                config: None,
                api_url: Some(base_url),
                api_token: Some("token".into()),
                profile: "default".into(),
            })
            .await
            .expect_err("missing version id should fail");

            handle.abort();
            assert_eq!(error.exit_code(), crate::error::EXIT_INTERNAL);
        }
    }
}

pub mod policy_deploy {
    use clap::Args;

    use crate::api::AsyncApiClient;
    use crate::config::{Config, ConfigInputs};
    use crate::error::CliError;
    use crate::output::json::print_json;

    #[derive(Debug, Args)]
    pub struct PolicyDeployArgs {
        #[arg(long, default_value = "policy-config.yaml")]
        pub file: std::path::PathBuf,

        #[arg(long)]
        pub source_gateway_id: String,

        #[arg(long = "target-gateway-id", required = true)]
        pub target_gateway_ids: Vec<String>,

        #[arg(long)]
        pub change_detail: Option<String>,

        #[arg(long)]
        pub json: bool,

        #[arg(long)]
        pub config: Option<std::path::PathBuf>,

        #[arg(long)]
        pub api_url: Option<String>,

        #[arg(long)]
        pub api_token: Option<String>,

        #[arg(long, default_value = "default")]
        pub profile: String,

        #[arg(long, default_value_t = 60)]
        pub timeout_secs: u64,

        #[arg(long, default_value_t = 1000)]
        pub poll_interval_ms: u64,
    }

    pub fn run(args: PolicyDeployArgs) -> Result<(), CliError> {
        tokio::runtime::Runtime::new()
            .map_err(|e| CliError::internal(format!("failed to create async runtime: {e}")))?
            .block_on(run_async(args))
    }

    pub(crate) async fn run_async(args: PolicyDeployArgs) -> Result<(), CliError> {
        let yaml = std::fs::read_to_string(&args.file)
            .map_err(|e| CliError::user(format!("failed to read {}: {e}", args.file.display())))?;

        let inputs = ConfigInputs {
            api_url_flag: args.api_url,
            api_token_flag: args.api_token,
            config_path: args.config,
            profile_flag: Some(args.profile),
            region_flag: None,
        };

        let config = Config::resolve(inputs)?;
        let api_token = config.api_token.ok_or_else(|| {
            CliError::auth(
                "missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)",
            )
        })?;

        let client = AsyncApiClient::new(config.api_url, api_token)?;
        let payload = serde_json::json!({
            "source_gateway_id": args.source_gateway_id,
            "target_gateway_ids": args.target_gateway_ids,
            "yaml": yaml,
            "change_detail": args.change_detail.unwrap_or_else(|| "CLI policy deploy".to_string())
        });

        let response = client
            .post_json_value("/v1/admin/configurations/rollout", &payload)
            .await?;
        if args.json {
            return print_json(&response);
        }

        let source_version_id = response
            .get("source_version_id")
            .and_then(|value| value.as_str())
            .ok_or_else(|| CliError::internal("api response missing source_version_id"))?;
        println!("rolled out policy from source version {source_version_id}");

        let targets = response
            .get("targets")
            .and_then(|value| value.as_array())
            .ok_or_else(|| CliError::internal("api response missing targets array"))?;
        for target in targets {
            let gateway_id = target
                .get("gateway_id")
                .and_then(|value| value.as_str())
                .ok_or_else(|| CliError::internal("api response missing targets[].gateway_id"))?;
            match target.get("version").and_then(|value| value.as_str()) {
                Some(version) => println!("- {gateway_id}: {version}"),
                None => println!("- {gateway_id}"),
            }
        }

        wait_for_rollout(
            &client,
            &args.target_gateway_ids,
            source_version_id,
            args.timeout_secs,
            args.poll_interval_ms,
        )
        .await?;
        println!("rollout verified");

        Ok(())
    }

    async fn wait_for_rollout(
        client: &AsyncApiClient,
        target_gateway_ids: &[String],
        source_version_id: &str,
        timeout_secs: u64,
        poll_interval_ms: u64,
    ) -> Result<(), CliError> {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs.max(1));
        loop {
            let response = client.get_json_value("/v1/admin/configurations").await?;
            if rollout_applied(&response, target_gateway_ids, source_version_id)? {
                return Ok(());
            }

            if std::time::Instant::now() >= deadline {
                return Err(CliError::network(format!(
                    "timed out waiting for rollout to apply source version {source_version_id}"
                )));
            }

            tokio::time::sleep(std::time::Duration::from_millis(poll_interval_ms.max(100))).await;
        }
    }

    fn rollout_applied(
        response: &serde_json::Value,
        target_gateway_ids: &[String],
        source_version_id: &str,
    ) -> Result<bool, CliError> {
        let gateways = response
            .get("gateways")
            .and_then(|value| value.as_array())
            .ok_or_else(|| CliError::internal("api response missing gateways array"))?;

        for target_gateway_id in target_gateway_ids {
            let Some(gateway) = gateways.iter().find(|gateway| {
                gateway.get("gateway_id").and_then(|value| value.as_str())
                    == Some(target_gateway_id.as_str())
            }) else {
                return Err(CliError::internal(format!(
                    "api response missing gateway {target_gateway_id}"
                )));
            };

            let current_version_id = gateway
                .get("current_version_id")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            if current_version_id != source_version_id {
                return Ok(false);
            }
        }

        Ok(true)
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
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        };

        use axum::{
            routing::{get, post},
            Json, Router,
        };
        use tempfile::tempdir;

        async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind listener");
            let addr = listener.local_addr().expect("listener addr");
            let handle = tokio::spawn(async move {
                axum::serve(listener, router).await.expect("serve test api");
            });
            (format!("http://{addr}"), handle)
        }

        fn write_policy_file(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
            let dir = tempdir().expect("tempdir");
            let path = dir.path().join("policy-config.yaml");
            std::fs::write(&path, contents).expect("write policy config");
            (dir, path)
        }

        #[test]
        fn rollout_applied_returns_true_only_when_all_targets_match() {
            let response = serde_json::json!({
                "gateways": [
                    {"gateway_id": "gw-a", "current_version_id": "ver_1"},
                    {"gateway_id": "gw-b", "current_version_id": "ver_1"}
                ]
            });
            assert!(
                rollout_applied(&response, &["gw-a".into(), "gw-b".into()], "ver_1")
                    .expect("rollout applied")
            );
            assert!(
                !rollout_applied(&response, &["gw-a".into(), "gw-b".into()], "ver_2")
                    .expect("rollout not yet applied")
            );
        }

        #[test]
        fn rollout_applied_errors_when_gateway_is_missing() {
            let response = serde_json::json!({
                "gateways": [{"gateway_id": "gw-a", "current_version_id": "ver_1"}]
            });
            let error = rollout_applied(&response, &["gw-b".into()], "ver_1")
                .expect_err("missing gateway should fail");
            assert!(error.to_string().contains("missing gateway gw-b"));
        }

        #[tokio::test]
        async fn run_async_posts_rollout_and_verifies_targets() {
            let _env_guard = crate::test_support::env_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            crate::test_support::unset_var("VERDICTAN_API_URL");
            crate::test_support::unset_var("VERDICTAN_API_TOKEN");

            let (_dir, policy_file) = write_policy_file("routes: []\n");
            let rollout_payloads = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
            let config_polls = Arc::new(AtomicUsize::new(0));

            let router = Router::new()
                .route(
                    "/v1/admin/configurations/rollout",
                    post({
                        let rollout_payloads = rollout_payloads.clone();
                        move |Json(body): Json<serde_json::Value>| {
                            let rollout_payloads = rollout_payloads.clone();
                            async move {
                                rollout_payloads.lock().expect("payload lock").push(body);
                                Json(serde_json::json!({
                                    "source_version_id": "ver_live",
                                    "targets": [
                                        {"gateway_id": "gw-a", "version": "v1"},
                                        {"gateway_id": "gw-b", "version": "v1"}
                                    ]
                                }))
                            }
                        }
                    }),
                )
                .route(
                    "/v1/admin/configurations",
                    get({
                        let config_polls = config_polls.clone();
                        move || {
                            let config_polls = config_polls.clone();
                            async move {
                                config_polls.fetch_add(1, Ordering::SeqCst);
                                Json(serde_json::json!({
                                    "gateways": [
                                        {"gateway_id": "gw-a", "current_version_id": "ver_live"},
                                        {"gateway_id": "gw-b", "current_version_id": "ver_live"}
                                    ]
                                }))
                            }
                        }
                    }),
                );
            let (base_url, handle) = serve(router).await;

            let result = run_async(PolicyDeployArgs {
                file: policy_file,
                source_gateway_id: "gw-source".into(),
                target_gateway_ids: vec!["gw-a".into(), "gw-b".into()],
                change_detail: Some("deploy detail".into()),
                json: false,
                config: None,
                api_url: Some(base_url),
                api_token: Some("token".into()),
                profile: "default".into(),
                timeout_secs: 1,
                poll_interval_ms: 0,
            })
            .await;

            handle.abort();
            result.expect("policy deploy should succeed");

            let rollout_payloads = rollout_payloads.lock().expect("payload lock");
            assert_eq!(rollout_payloads.len(), 1);
            assert_eq!(rollout_payloads[0]["source_gateway_id"], "gw-source");
            assert_eq!(
                rollout_payloads[0]["target_gateway_ids"],
                serde_json::json!(["gw-a", "gw-b"])
            );
            assert_eq!(rollout_payloads[0]["yaml"], "routes: []\n");
            assert_eq!(rollout_payloads[0]["change_detail"], "deploy detail");
            assert!(config_polls.load(Ordering::SeqCst) >= 1);
        }
    }
}
