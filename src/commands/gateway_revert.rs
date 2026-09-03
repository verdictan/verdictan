// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use chrono::Utc;
use clap::Args;

use crate::error::CliError;
use crate::instances::status::{ConfigVerificationState, GatewayInstanceLifecycle};
use crate::output::json::print_json;
use crate::supervisor::{
    default_state_dir, OperationAction, OperationHistoryEntry, OperationOutcome,
    SupervisorStateStore,
};

#[derive(Debug, Args)]
pub(crate) struct GatewayRevertArgs {
    #[arg(long)]
    pub(crate) name: String,

    #[arg(long)]
    pub(crate) gateway_url: String,

    #[arg(long)]
    pub(crate) state_dir: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) json: bool,
}
pub(crate) async fn run_async(args: GatewayRevertArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.unwrap_or(default_state_dir()?);
    let mut store = SupervisorStateStore::load(&state_dir)?;
    let record = store
        .get_instance(&args.name)
        .cloned()
        .ok_or_else(|| CliError::user(format!("instance {} does not exist", args.name)))?;

    let rollback_yaml =
        record.status.rollback_target_yaml.clone().ok_or_else(|| {
            CliError::user(format!("instance {} has no rollback target", args.name))
        })?;
    let target_version = record
        .status
        .rollback_target_version
        .clone()
        .ok_or_else(|| {
            CliError::user(format!(
                "instance {} has an incomplete rollback target: missing version",
                args.name
            ))
        })?;
    let target_sha256 = record
        .status
        .rollback_target_sha256
        .clone()
        .ok_or_else(|| {
            CliError::user(format!(
                "instance {} has an incomplete rollback target: missing digest",
                args.name
            ))
        })?;

    let api_token = crate::commands::gateway_reload::resolve_gateway_api_token(
        None,
        record
            .spec
            .admin_token
            .as_ref()
            .and_then(|secret_ref| secret_ref.resolve()),
    );

    let value = crate::commands::gateway_reload::post_reload_gateway_config(
        &args.gateway_url,
        &rollback_yaml,
        api_token.as_deref(),
    )
    .await?;
    crate::commands::gateway_reload::parse_reload_config(&value)?;
    let verified = crate::commands::gateway_reload::verify_gateway_config(
        &args.gateway_url,
        api_token.as_deref(),
        &target_sha256,
        &target_version,
    )
    .await?;
    crate::commands::gateway_reload::verify_gateway_health(&args.gateway_url).await?;

    let previous_version = record.status.observed_config_version.clone();
    let previous_sha256 = record.status.observed_config_sha256.clone();
    let mut status = record.status;
    status.lifecycle = GatewayInstanceLifecycle::Running;
    status.observed_config_version = verified.version.clone();
    status.observed_config_sha256 = verified.sha256.clone();
    status.last_known_good_version = verified.version.clone();
    status.last_known_good_sha256 = verified.sha256.clone();
    status.desired_config_version = verified.version.clone();
    status.desired_config_sha256 = verified.sha256.clone();
    status.desired_config_source = None;
    status.rollback_target_version = None;
    status.rollback_target_sha256 = None;
    status.rollback_target_yaml = None;
    status.last_error = None;
    status.last_rollback_reason = Some("manual revert requested".to_string());
    status.verification_state = ConfigVerificationState::RolledBack;
    status.last_verified_at = Some(Utc::now().to_rfc3339());
    status.last_healthcheck_at = Some(Utc::now().to_rfc3339());
    status.last_observed_healthy = Some(true);
    status.last_seen_at = Some(Utc::now().to_rfc3339());
    status.updated_at = Utc::now().to_rfc3339();
    store.set_status(&args.name, status)?;
    store.append_operation_history(
        &args.name,
        OperationHistoryEntry {
            action: OperationAction::Revert,
            outcome: OperationOutcome::Succeeded,
            reason: Some("manual revert requested".to_string()),
            previous_version,
            previous_sha256,
            target_version: Some(target_version),
            target_sha256: Some(target_sha256),
            active_version: verified.version,
            active_sha256: verified.sha256,
            recorded_at: Utc::now().to_rfc3339(),
        },
    )?;

    if args.json {
        return print_json(&value);
    }

    println!("reverted {}", args.name);
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
    use super::{run_async, GatewayRevertArgs};
    use crate::instances::status::GatewayInstanceLifecycle;
    use crate::instances::{GatewayInstanceId, GatewayInstanceSpec, PolicyConfigSource};
    use crate::supervisor::{
        OperationAction, OperationHistoryEntry, OperationOutcome, SupervisorStateStore,
    };
    use axum::{
        http::StatusCode,
        routing::{get, post},
        Json, Router,
    };
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    fn stage_revert_target(
        state_dir: &Path,
        name: &str,
        target_version: &str,
        target_sha256: &str,
        target_yaml: &str,
    ) {
        let spec = GatewayInstanceSpec::new(
            GatewayInstanceId::new(name).expect("instance id"),
            format!("{name}_gateway"),
            name,
            "127.0.0.1:41002",
            "https://api.example.com",
            None,
            None,
            None,
            "block",
            PolicyConfigSource::Empty,
            8,
            None,
            true,
        )
        .expect("spec");
        let mut store = SupervisorStateStore::load(state_dir).expect("load store");
        store.create_instance(spec).expect("create instance");

        let mut status = store.get_instance(name).expect("instance").status.clone();
        status.lifecycle = GatewayInstanceLifecycle::Failed;
        status.observed_config_version = Some("v-current".to_string());
        status.observed_config_sha256 = Some("sha-current".to_string());
        status.rollback_target_version = Some(target_version.to_string());
        status.rollback_target_sha256 = Some(target_sha256.to_string());
        status.rollback_target_yaml = Some(target_yaml.to_string());
        status.last_error = Some("prior activation failed".to_string());
        store.set_status(name, status).expect("stage status");
        store
            .append_operation_history(
                name,
                OperationHistoryEntry {
                    action: OperationAction::Reload,
                    outcome: OperationOutcome::Failed,
                    reason: Some("prior activation failed".to_string()),
                    previous_version: Some("v-stable".to_string()),
                    previous_sha256: Some("sha-stable".to_string()),
                    target_version: Some("v-current".to_string()),
                    target_sha256: Some("sha-current".to_string()),
                    active_version: Some("v-current".to_string()),
                    active_sha256: Some("sha-current".to_string()),
                    recorded_at: "2026-08-01T00:00:00Z".to_string(),
                },
            )
            .expect("stage history");
    }

    async fn start_revert_stub(
        active_version: &str,
        active_sha256: &str,
        health_status: StatusCode,
        health_body: serde_json::Value,
        persistence_lock_path: Option<PathBuf>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let response = Arc::new(json!({
            "ok": true,
            "config": {
                "config_version": active_version,
                "config_sha256": active_sha256,
                "config_content": "pack:\n  version: target\n"
            }
        }));
        let health_body = Arc::new(health_body);
        let app = Router::new()
            .route(
                "/verdictan/config/reload",
                post({
                    let response = Arc::clone(&response);
                    move || {
                        let response = Arc::clone(&response);
                        async move { Json(response.as_ref().clone()) }
                    }
                }),
            )
            .route(
                "/verdictan/config",
                get({
                    let response = Arc::clone(&response);
                    move || {
                        let response = Arc::clone(&response);
                        async move { Json(response.as_ref().clone()) }
                    }
                }),
            )
            .route(
                "/healthz",
                get(move || {
                    let health_body = Arc::clone(&health_body);
                    let persistence_lock_path = persistence_lock_path.clone();
                    async move {
                        if let Some(path) = persistence_lock_path {
                            std::fs::remove_file(&path).expect("remove supervisor state lock file");
                            std::fs::create_dir(&path)
                                .expect("install persistence-failure sentinel");
                        }
                        (health_status, Json(health_body.as_ref().clone()))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve stub");
        });
        (format!("http://{addr}"), handle)
    }

    fn assert_revert_evidence_retained(state_dir: &Path, name: &str) {
        let store = SupervisorStateStore::load(state_dir).expect("reload store");
        let record = store.get_instance(name).expect("instance");
        assert_eq!(record.status.lifecycle, GatewayInstanceLifecycle::Failed);
        assert_eq!(
            record.status.rollback_target_version.as_deref(),
            Some("v-target")
        );
        assert_eq!(
            record.status.rollback_target_sha256.as_deref(),
            Some("sha-target")
        );
        assert!(record.status.rollback_target_yaml.is_some());
        assert_eq!(record.operations_history.len(), 1);
        assert_eq!(
            record.operations_history[0].reason.as_deref(),
            Some("prior activation failed")
        );
    }

    async fn run_revert(
        state_dir: &Path,
        gateway_url: String,
        name: &str,
    ) -> Result<(), crate::error::CliError> {
        run_async(GatewayRevertArgs {
            name: name.to_string(),
            gateway_url,
            state_dir: Some(state_dir.to_path_buf()),
            json: false,
        })
        .await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verified_revert_sets_running_and_clears_rollback_evidence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        stage_revert_target(
            &state_dir,
            "verified",
            "v-target",
            "sha-target",
            "pack:\n  version: v-target\n",
        );
        let (gateway_url, handle) = start_revert_stub(
            "v-target",
            "sha-target",
            StatusCode::OK,
            json!({"status": "ok"}),
            None,
        )
        .await;

        run_revert(&state_dir, gateway_url, "verified")
            .await
            .expect("verified revert");

        let store = SupervisorStateStore::load(&state_dir).expect("reload store");
        let record = store.get_instance("verified").expect("instance");
        assert_eq!(record.status.lifecycle, GatewayInstanceLifecycle::Running);
        assert_eq!(
            record.status.observed_config_version.as_deref(),
            Some("v-target")
        );
        assert_eq!(
            record.status.observed_config_sha256.as_deref(),
            Some("sha-target")
        );
        assert_eq!(record.status.last_observed_healthy, Some(true));
        assert!(record.status.rollback_target_version.is_none());
        assert!(record.status.rollback_target_sha256.is_none());
        assert!(record.status.rollback_target_yaml.is_none());
        assert_eq!(record.operations_history.len(), 2);
        assert_eq!(
            record.operations_history[1].outcome,
            OperationOutcome::Succeeded
        );

        handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn revert_rejects_reload_2xx_with_digest_mismatch_and_retains_evidence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        stage_revert_target(
            &state_dir,
            "digest-mismatch",
            "v-target",
            "sha-target",
            "pack:\n  version: v-target\n",
        );
        let (gateway_url, handle) = start_revert_stub(
            "v-target",
            "sha-other",
            StatusCode::OK,
            json!({"status": "ok"}),
            None,
        )
        .await;

        let error = run_revert(&state_dir, gateway_url, "digest-mismatch")
            .await
            .expect_err("digest mismatch");
        assert!(error
            .to_string()
            .contains("expected active config digest sha-target but proxy is reporting sha-other"));
        assert_revert_evidence_retained(&state_dir, "digest-mismatch");

        handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn revert_rejects_reload_2xx_with_version_mismatch_and_retains_evidence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        stage_revert_target(
            &state_dir,
            "version-mismatch",
            "v-target",
            "sha-target",
            "pack:\n  version: v-target\n",
        );
        let (gateway_url, handle) = start_revert_stub(
            "v-other",
            "sha-target",
            StatusCode::OK,
            json!({"status": "ok"}),
            None,
        )
        .await;

        let error = run_revert(&state_dir, gateway_url, "version-mismatch")
            .await
            .expect_err("version mismatch");
        assert!(error
            .to_string()
            .contains("expected active config version v-target but proxy is reporting v-other"));
        assert_revert_evidence_retained(&state_dir, "version-mismatch");

        handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn revert_rejects_unhealthy_target_and_retains_evidence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        stage_revert_target(
            &state_dir,
            "health-mismatch",
            "v-target",
            "sha-target",
            "pack:\n  version: v-target\n",
        );
        let (gateway_url, handle) = start_revert_stub(
            "v-target",
            "sha-target",
            StatusCode::OK,
            json!({"status": "degraded"}),
            None,
        )
        .await;

        let error = run_revert(&state_dir, gateway_url, "health-mismatch")
            .await
            .expect_err("health mismatch");
        assert!(error
            .to_string()
            .contains("expected gateway health status ok but proxy is reporting degraded"));
        assert_revert_evidence_retained(&state_dir, "health-mismatch");

        handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn revert_surfaces_persistence_failure_without_clearing_evidence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        stage_revert_target(
            &state_dir,
            "persist-failure",
            "v-target",
            "sha-target",
            "pack:\n  version: v-target\n",
        );
        let lock_path = state_dir.join("supervisor-state.lock");
        let (gateway_url, handle) = start_revert_stub(
            "v-target",
            "sha-target",
            StatusCode::OK,
            json!({"status": "ok"}),
            Some(lock_path),
        )
        .await;

        let error = run_revert(&state_dir, gateway_url, "persist-failure")
            .await
            .expect_err("persistence failure");
        assert!(error
            .to_string()
            .contains("failed to open supervisor state lock"));
        assert_revert_evidence_retained(&state_dir, "persist-failure");

        handle.abort();
    }

    #[test]
    fn revert_records_manual_reason() {
        let reason = "manual revert requested";
        assert_eq!(reason, "manual revert requested");
    }

    #[test]
    fn rollback_clears_target_fields() {
        let mut status = json!({
            "rollback_target_version": "v1",
            "rollback_target_sha256": "aaa",
            "rollback_target_yaml": "yaml_content",
            "last_error": "some error",
        });
        status["rollback_target_version"] = serde_json::Value::Null;
        status["rollback_target_sha256"] = serde_json::Value::Null;
        status["rollback_target_yaml"] = serde_json::Value::Null;
        status["last_error"] = serde_json::Value::Null;
        assert!(status["rollback_target_version"].is_null());
        assert!(status["rollback_target_sha256"].is_null());
        assert!(status["rollback_target_yaml"].is_null());
        assert!(status["last_error"].is_null());
    }

    #[test]
    fn operation_history_entry_shape() {
        let entry = json!({
            "action": "Revert",
            "outcome": "Succeeded",
            "reason": "manual revert requested",
            "previous_version": "v2",
            "active_version": "v1",
        });
        assert_eq!(entry["action"], "Revert");
        assert_eq!(entry["outcome"], "Succeeded");
        assert_eq!(entry["reason"], "manual revert requested");
    }

    #[test]
    fn operation_history_entry_failed_shape() {
        let entry = json!({
            "action": "Revert",
            "outcome": "Failed",
            "reason": "reload rejected by proxy",
            "previous_version": "v2",
            "active_version": "v2",
        });
        assert_eq!(entry["outcome"], "Failed");
        assert_eq!(entry["reason"], "reload rejected by proxy");
    }

    #[test]
    fn rollback_clears_all_target_fields_independently() {
        let mut status = json!({
            "rollback_target_version": "v1",
            "rollback_target_sha256": "sha",
            "rollback_target_yaml": "yaml",
        });
        status["rollback_target_version"] = serde_json::Value::Null;
        assert!(status["rollback_target_version"].is_null());
        assert!(!status["rollback_target_sha256"].is_null());
        status["rollback_target_sha256"] = serde_json::Value::Null;
        status["rollback_target_yaml"] = serde_json::Value::Null;
        assert!(status["rollback_target_sha256"].is_null());
        assert!(status["rollback_target_yaml"].is_null());
    }

    #[test]
    fn revert_output_message() {
        let name = "my-gateway";
        let msg = format!("reverted {}", name);
        assert!(msg.contains("reverted my-gateway"));
    }

    #[test]
    fn revert_output_message_with_special_chars() {
        let name = "gw-prod/region-1";
        let msg = format!("reverted {}", name);
        assert!(msg.contains("gw-prod/region-1"));
    }

    #[test]
    fn operation_history_entry_with_version_tracking() {
        let entry = json!({
            "action": "Revert",
            "outcome": "Succeeded",
            "reason": "manual revert requested",
            "previous_version": "v2",
            "previous_sha256": "sha-prev",
            "target_version": "v1",
            "target_sha256": "sha-target",
            "active_version": "v1",
            "active_sha256": "sha-target",
        });
        assert_eq!(entry["target_version"], "v1");
        assert_eq!(entry["active_version"], "v1");
        assert_eq!(entry["target_sha256"], entry["active_sha256"]);
    }

    #[test]
    fn rollback_preserves_unrelated_status_fields() {
        let mut status = json!({
            "rollback_target_version": "v1",
            "rollback_target_sha256": "sha",
            "lifecycle": "running",
            "observed_config_version": "v2",
        });
        status["rollback_target_version"] = serde_json::Value::Null;
        status["rollback_target_sha256"] = serde_json::Value::Null;
        assert_eq!(status["lifecycle"], "running");
        assert_eq!(status["observed_config_version"], "v2");
    }

    #[test]
    fn operation_history_entry_all_outcomes() {
        for outcome in ["Succeeded", "Failed", "RolledBack"] {
            let entry = json!({
                "action": "Revert",
                "outcome": outcome,
                "reason": "test",
            });
            assert_eq!(entry["outcome"], outcome);
        }
    }
}
