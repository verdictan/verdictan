// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use chrono::Utc;
use clap::Args;

use crate::commands::gateway_reload::{
    fetch_gateway_config, post_reload_gateway_config, verify_gateway_config,
};
use crate::error::CliError;
use crate::instances::status::{ConfigVerificationState, GatewayInstanceLifecycle};
use crate::output::json::print_json;
use crate::supervisor::{
    default_state_dir, OperationAction, OperationHistoryEntry, OperationOutcome,
    SupervisorStateStore,
};

#[derive(Debug, Args)]
pub(crate) struct GatewayReconcileArgs {
    #[arg(long)]
    pub(crate) name: Option<String>,

    #[arg(long)]
    pub(crate) all: bool,

    #[arg(long)]
    pub(crate) state_dir: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) apply_rollback: bool,

    #[arg(long)]
    pub(crate) cancel: bool,

    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(serde::Serialize)]
struct ReconcileInstanceResult {
    instance_id: String,
    gateway_url: String,
    healthy: bool,
    outcome: String,
    message: String,
    observed_version: Option<String>,
    observed_sha256: Option<String>,
    rollback_applied: bool,
}
pub(crate) async fn run_async(args: GatewayReconcileArgs) -> Result<(), CliError> {
    if !args.all && args.name.is_none() {
        return Err(CliError::user("pass --name <instance> or --all"));
    }

    let state_dir = args.state_dir.unwrap_or(default_state_dir()?);
    let mut store = SupervisorStateStore::load(&state_dir)?;
    let instance_ids = if args.all {
        let items = store.list_instances();
        if items.is_empty() {
            return Err(CliError::user("no proxy instances registered"));
        }
        items
            .into_iter()
            .map(|item| item.instance_id)
            .collect::<Vec<_>>()
    } else {
        vec![args
            .name
            .ok_or_else(|| CliError::user("missing instance name"))?]
    };

    let mut results = Vec::new();
    for instance_id in instance_ids {
        results.push(
            reconcile_instance(&mut store, &instance_id, args.apply_rollback, args.cancel).await?,
        );
    }

    if args.json {
        return print_json(&serde_json::json!({ "results": results }));
    }

    for result in &results {
        println!(
            "{} [{}] {} - {}",
            result.instance_id,
            result.outcome,
            if result.healthy {
                "healthy"
            } else {
                "attention"
            },
            result.message,
        );
    }

    let failed = results.iter().filter(|item| !item.healthy).count();
    if failed > 0 {
        return Err(CliError::network(format!(
            "{failed} instance(s) failed reconciliation",
        )));
    }

    Ok(())
}

async fn reconcile_instance(
    store: &mut SupervisorStateStore,
    instance_id: &str,
    apply_rollback: bool,
    cancel: bool,
) -> Result<ReconcileInstanceResult, CliError> {
    let record = store
        .get_instance(instance_id)
        .cloned()
        .ok_or_else(|| CliError::user(format!("instance {} does not exist", instance_id)))?;
    let gateway_url = derive_gateway_url(&record.spec.listen_addr)?;
    let api_token = resolve_admin_token(&record);
    let now = Utc::now().to_rfc3339();

    if cancel {
        let mut status = record.status.clone();
        status.last_reconciled_at = Some(now.clone());
        status.last_reconciliation_outcome = Some("cancelled".to_string());
        status.last_reconciliation_error = None;
        status.updated_at = now.clone();
        store.set_rollout_plan(instance_id, None)?;
        store.set_status(instance_id, status.clone())?;
        store.append_operation_history(
            instance_id,
            OperationHistoryEntry {
                action: OperationAction::CancelReconcile,
                outcome: OperationOutcome::Succeeded,
                reason: Some("operator cancelled reconciliation".to_string()),
                previous_version: record.status.observed_config_version.clone(),
                previous_sha256: record.status.observed_config_sha256.clone(),
                target_version: record.status.desired_config_version.clone(),
                target_sha256: record.status.desired_config_sha256.clone(),
                active_version: record.status.observed_config_version.clone(),
                active_sha256: record.status.observed_config_sha256.clone(),
                recorded_at: now,
            },
        )?;
        return Ok(ReconcileInstanceResult {
            instance_id: instance_id.to_string(),
            gateway_url,
            healthy: true,
            outcome: "cancelled".to_string(),
            message: "reconciliation plan cleared".to_string(),
            observed_version: status.observed_config_version,
            observed_sha256: status.observed_config_sha256,
            rollback_applied: false,
        });
    }

    match reconcile_live_state(&gateway_url, api_token.as_deref(), &record, apply_rollback).await {
        Ok(mut result) => {
            let mut status = record.status.clone();
            status.lifecycle = if result.healthy {
                GatewayInstanceLifecycle::Running
            } else {
                GatewayInstanceLifecycle::Failed
            };
            status.observed_config_version = result.observed_version.clone();
            status.observed_config_sha256 = result.observed_sha256.clone();
            status.last_reconciled_at = Some(Utc::now().to_rfc3339());
            status.last_reconciliation_outcome = Some(result.outcome.clone());
            status.last_reconciliation_error = if result.healthy {
                None
            } else {
                Some(result.message.clone())
            };
            status.last_healthcheck_at = Some(Utc::now().to_rfc3339());
            status.last_observed_healthy = Some(result.healthy);
            status.last_seen_at = Some(Utc::now().to_rfc3339());
            status.verification_state =
                if result.rollback_applied || result.outcome == "rollback_verified" {
                    ConfigVerificationState::RolledBack
                } else if result.healthy {
                    ConfigVerificationState::Verified
                } else {
                    ConfigVerificationState::Failed
                };
            status.updated_at = Utc::now().to_rfc3339();
            store.set_status(instance_id, status.clone())?;
            store.append_operation_history(
                instance_id,
                OperationHistoryEntry {
                    action: OperationAction::Reconcile,
                    outcome: if result.rollback_applied {
                        OperationOutcome::RolledBack
                    } else if result.healthy {
                        OperationOutcome::Succeeded
                    } else {
                        OperationOutcome::Failed
                    },
                    reason: Some(result.message.clone()),
                    previous_version: record.status.observed_config_version.clone(),
                    previous_sha256: record.status.observed_config_sha256.clone(),
                    target_version: record.status.desired_config_version.clone(),
                    target_sha256: record.status.desired_config_sha256.clone(),
                    active_version: status.observed_config_version.clone(),
                    active_sha256: status.observed_config_sha256.clone(),
                    recorded_at: Utc::now().to_rfc3339(),
                },
            )?;
            result.instance_id = instance_id.to_string();
            result.gateway_url = gateway_url;
            Ok(result)
        }
        Err(error) => {
            let mut status = record.status.clone();
            status.lifecycle = GatewayInstanceLifecycle::Failed;
            status.last_reconciled_at = Some(Utc::now().to_rfc3339());
            status.last_reconciliation_outcome = Some("unreachable".to_string());
            status.last_reconciliation_error = Some(error.to_string());
            status.last_healthcheck_at = Some(Utc::now().to_rfc3339());
            status.last_observed_healthy = Some(false);
            status.last_seen_at = Some(Utc::now().to_rfc3339());
            status.verification_state = ConfigVerificationState::Failed;
            status.updated_at = Utc::now().to_rfc3339();
            store.set_status(instance_id, status)?;
            store.append_operation_history(
                instance_id,
                OperationHistoryEntry {
                    action: OperationAction::Reconcile,
                    outcome: OperationOutcome::Failed,
                    reason: Some(error.to_string()),
                    previous_version: record.status.observed_config_version.clone(),
                    previous_sha256: record.status.observed_config_sha256.clone(),
                    target_version: record.status.desired_config_version.clone(),
                    target_sha256: record.status.desired_config_sha256.clone(),
                    active_version: None,
                    active_sha256: None,
                    recorded_at: Utc::now().to_rfc3339(),
                },
            )?;
            Ok(ReconcileInstanceResult {
                instance_id: instance_id.to_string(),
                gateway_url,
                healthy: false,
                outcome: "unreachable".to_string(),
                message: error.to_string(),
                observed_version: None,
                observed_sha256: None,
                rollback_applied: false,
            })
        }
    }
}

async fn reconcile_live_state(
    gateway_url: &str,
    admin_token: Option<&str>,
    record: &crate::supervisor::state_store::InstanceRecord,
    apply_rollback: bool,
) -> Result<ReconcileInstanceResult, CliError> {
    let live = fetch_gateway_config(gateway_url, admin_token).await?;
    let desired_version = record
        .status
        .desired_config_version
        .as_deref()
        .or(record.status.observed_config_version.as_deref());
    let desired_sha = record
        .status
        .desired_config_sha256
        .as_deref()
        .or(record.status.observed_config_sha256.as_deref());

    if let (Some(expected_version), Some(expected_sha)) = (desired_version, desired_sha) {
        if verify_gateway_config(gateway_url, admin_token, expected_sha, expected_version)
            .await
            .is_ok()
        {
            return Ok(ReconcileInstanceResult {
                instance_id: String::new(),
                gateway_url: String::new(),
                healthy: true,
                outcome: "healthy".to_string(),
                message: format!("live proxy is serving expected config {}", expected_version),
                observed_version: live.version,
                observed_sha256: live.sha256,
                rollback_applied: false,
            });
        }
    }

    if let (Some(rollback_version), Some(rollback_sha)) = (
        record.status.rollback_target_version.as_deref(),
        record.status.rollback_target_sha256.as_deref(),
    ) {
        if verify_gateway_config(gateway_url, admin_token, rollback_sha, rollback_version)
            .await
            .is_ok()
        {
            return Ok(ReconcileInstanceResult {
                instance_id: String::new(),
                gateway_url: String::new(),
                healthy: true,
                outcome: "rollback_verified".to_string(),
                message: format!(
                    "live proxy already matches rollback target {}",
                    rollback_version
                ),
                observed_version: live.version,
                observed_sha256: live.sha256,
                rollback_applied: false,
            });
        }
    }

    if apply_rollback {
        if let (Some(rollback_yaml), Some(rollback_version), Some(rollback_sha)) = (
            record.status.rollback_target_yaml.as_deref(),
            record.status.rollback_target_version.as_deref(),
            record.status.rollback_target_sha256.as_deref(),
        ) {
            post_reload_gateway_config(gateway_url, rollback_yaml, admin_token).await?;
            let verified =
                verify_gateway_config(gateway_url, admin_token, rollback_sha, rollback_version)
                    .await?;
            return Ok(ReconcileInstanceResult {
                instance_id: String::new(),
                gateway_url: String::new(),
                healthy: true,
                outcome: "rollback_applied".to_string(),
                message: format!(
                    "rollback target {} reapplied and verified",
                    rollback_version
                ),
                observed_version: verified.version,
                observed_sha256: verified.sha256,
                rollback_applied: true,
            });
        }
    }

    Ok(ReconcileInstanceResult {
        instance_id: String::new(),
        gateway_url: String::new(),
        healthy: false,
        outcome: "drift_detected".to_string(),
        message: "live proxy configuration does not match desired or rollback target".to_string(),
        observed_version: live.version,
        observed_sha256: live.sha256,
        rollback_applied: false,
    })
}

fn resolve_admin_token(record: &crate::supervisor::state_store::InstanceRecord) -> Option<String> {
    crate::commands::gateway_reload::resolve_gateway_api_token(
        None,
        record
            .spec
            .admin_token
            .as_ref()
            .and_then(|secret_ref| secret_ref.resolve()),
    )
}

fn derive_gateway_url(listen_addr: &str) -> Result<String, CliError> {
    let addr: SocketAddr = listen_addr.parse().map_err(|error| {
        CliError::user(format!("invalid listen address {}: {error}", listen_addr))
    })?;
    let host = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    Ok(format!("http://{}:{}", host, addr.port()))
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

    #[test]
    fn command_helper_coverage_derive_gateway_url_maps_unspecified_bind_to_localhost() {
        assert_eq!(
            derive_gateway_url("0.0.0.0:8080").expect("ipv4 unspecified"),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            derive_gateway_url("[::]:9090").expect("ipv6 unspecified"),
            "http://::1:9090"
        );
        assert_eq!(
            derive_gateway_url("10.0.0.5:41002").expect("explicit host"),
            "http://10.0.0.5:41002"
        );
    }

    #[test]
    fn command_helper_coverage_derive_gateway_url_rejects_invalid_listen_address() {
        let error = derive_gateway_url("not-a-socket").expect_err("invalid listen addr");
        assert!(error.to_string().contains("invalid listen address"));
    }

    #[test]
    fn derive_gateway_url_localhost_passthrough() {
        assert_eq!(
            derive_gateway_url("127.0.0.1:3000").expect("localhost v4"),
            "http://127.0.0.1:3000"
        );
    }

    #[test]
    fn derive_gateway_url_ipv6_localhost_passthrough() {
        assert_eq!(
            derive_gateway_url("[::1]:4000").expect("localhost v6"),
            "http://::1:4000"
        );
    }

    #[test]
    fn derive_gateway_url_high_port() {
        assert_eq!(
            derive_gateway_url("192.168.1.1:65535").expect("high port"),
            "http://192.168.1.1:65535"
        );
    }

    #[test]
    fn derive_gateway_url_port_zero_is_valid() {
        assert_eq!(
            derive_gateway_url("10.0.0.1:0").expect("port zero"),
            "http://10.0.0.1:0"
        );
    }

    #[test]
    fn derive_gateway_url_rejects_empty_string() {
        let error = derive_gateway_url("").expect_err("empty addr");
        assert!(error.to_string().contains("invalid listen address"));
    }

    #[test]
    fn derive_gateway_url_rejects_missing_port() {
        let error = derive_gateway_url("127.0.0.1").expect_err("no port");
        assert!(error.to_string().contains("invalid listen address"));
    }

    #[test]
    fn reconcile_instance_result_serializes_to_json() {
        let result = ReconcileInstanceResult {
            instance_id: "gw-test".to_string(),
            gateway_url: "http://127.0.0.1:8080".to_string(),
            healthy: true,
            outcome: "healthy".to_string(),
            message: "live proxy is serving expected config v1".to_string(),
            observed_version: Some("v1".to_string()),
            observed_sha256: Some("abc123".to_string()),
            rollback_applied: false,
        };
        let json = serde_json::to_value(&result).expect("serialize");
        assert_eq!(json["instance_id"], "gw-test");
        assert_eq!(json["healthy"], true);
        assert_eq!(json["rollback_applied"], false);
        assert_eq!(json["observed_version"], "v1");
    }

    #[test]
    fn reconcile_instance_result_with_rollback() {
        let result = ReconcileInstanceResult {
            instance_id: "gw-rb".to_string(),
            gateway_url: "http://10.0.0.1:9090".to_string(),
            healthy: true,
            outcome: "rollback_applied".to_string(),
            message: "rollback target v0.9 reapplied".to_string(),
            observed_version: Some("v0.9".to_string()),
            observed_sha256: Some("def456".to_string()),
            rollback_applied: true,
        };
        let json = serde_json::to_value(&result).expect("serialize");
        assert_eq!(json["rollback_applied"], true);
        assert_eq!(json["outcome"], "rollback_applied");
    }

    #[test]
    fn reconcile_instance_result_unhealthy_with_none_versions() {
        let result = ReconcileInstanceResult {
            instance_id: "gw-fail".to_string(),
            gateway_url: "http://127.0.0.1:8080".to_string(),
            healthy: false,
            outcome: "unreachable".to_string(),
            message: "connection refused".to_string(),
            observed_version: None,
            observed_sha256: None,
            rollback_applied: false,
        };
        let json = serde_json::to_value(&result).expect("serialize");
        assert_eq!(json["healthy"], false);
        assert!(json["observed_version"].is_null());
        assert!(json["observed_sha256"].is_null());
    }

    #[test]
    fn derive_gateway_url_ipv4_private_range() {
        assert_eq!(
            derive_gateway_url("172.16.0.1:8443").expect("private"),
            "http://172.16.0.1:8443"
        );
    }
}
