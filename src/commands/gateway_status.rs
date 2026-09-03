// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::supervisor::state_store::{InstanceRecord, SupervisorStateMetadata};
use crate::{
    commands::gateway_history::{
        action_label, filter_history, history_filter_label, HistoryActionFilter,
    },
    commands::gateway_service::service_status,
    error::CliError,
    output::json::print_json,
    supervisor::{default_state_dir, OperationHistoryEntry, SupervisorStateStore},
};

#[derive(Debug, Args)]
pub(crate) struct GatewayStatusArgs {
    #[arg(long, default_value = "verdictan-proxy")]
    pub(crate) name: String,

    #[arg(long)]
    pub(crate) state_dir: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) json: bool,

    #[arg(long, default_value_t = 5)]
    pub(crate) history_limit: usize,

    #[arg(long, value_enum)]
    pub(crate) history_action: Option<HistoryActionFilter>,

    #[arg(long, conflicts_with = "json")]
    pub(crate) history_json: bool,
}

pub(crate) fn run(args: GatewayStatusArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.clone().unwrap_or(default_state_dir()?);
    let store = SupervisorStateStore::load(state_dir)?;
    if let Some(record) = store.get_instance(&args.name) {
        let supervisor = store.metadata();
        let operations_history = filter_history(
            record.operations_history.as_slice(),
            args.history_limit,
            args.history_action,
        );
        let value = serde_json::json!({
            "source": "supervisor",
            "supervisor": supervisor,
            "spec": record.spec,
            "status": record.status,
            "history_limit": args.history_limit,
            "history_action": args.history_action.map(|item| history_filter_label(item).to_string()),
            "operations_history": operations_history,
        });

        if args.history_json {
            return print_json(&serde_json::json!({
                "instance_id": record.spec.instance_id.as_str(),
                "history_limit": args.history_limit,
                "history_action": args.history_action.map(|item| history_filter_label(item).to_string()),
                "operations_history": operations_history,
            }));
        }

        if args.json {
            return print_json(&value);
        }

        let rendered =
            render_supervisor_record(&supervisor, record, args.history_limit, args.history_action);
        println!("{}", rendered);
        return Ok(());
    }

    let status = service_status(&args.name)?;
    if !status.service_file.exists() {
        return Err(CliError::user(format!(
            "gateway instance '{}' not found in supervisor state and is not installed as a service",
            args.name
        )));
    }
    if args.json {
        return print_json(&serde_json::json!({
            "source": "service_manager",
            "label": status.label,
            "state": status.state,
            "pid": status.pid,
            "service_file": status.service_file,
        }));
    }

    println!("label: {}", status.label);
    println!("state: {}", status.state);
    if let Some(pid) = status.pid {
        println!("pid: {pid}");
    }
    println!("service file: {}", status.service_file.display());
    Ok(())
}

pub(crate) fn render_supervisor_record(
    supervisor: &SupervisorStateMetadata,
    record: &InstanceRecord,
    history_limit: usize,
    history_action: Option<HistoryActionFilter>,
) -> String {
    let effective_region = std::env::var("VERDICTAN_REGION")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let mut lines = vec![
        format!("instance: {}", record.spec.instance_id.as_str()),
        format!("gateway id: {}", record.spec.gateway_id),
        format!("name: {}", record.spec.name),
        format!(
            "region: {}",
            effective_region.as_deref().unwrap_or("(not set)")
        ),
        format!("listen: {}", record.spec.listen_addr),
        format!("lifecycle: {:?}", record.status.lifecycle).to_ascii_lowercase(),
    ];

    if let Some(version) = &record.status.observed_config_version {
        let digest = record
            .status
            .observed_config_sha256
            .as_deref()
            .unwrap_or("unknown");
        lines.push(format!("observed config: {} ({})", version, digest));
    }

    if let Some(last_error) = &record.status.last_error {
        lines.push(format!("last error: {}", last_error));
    }
    if let Some(last_reconciled_at) = &record.status.last_reconciled_at {
        lines.push(format!("last reconciled at: {}", last_reconciled_at));
    }
    if let Some(outcome) = &record.status.last_reconciliation_outcome {
        lines.push(format!("last reconciliation outcome: {}", outcome));
    }
    if let Some(error) = &record.status.last_reconciliation_error {
        lines.push(format!("last reconciliation error: {}", error));
    }

    lines.push(format!("state dir: {}", supervisor.state_dir));
    if supervisor.recovered_from_backup {
        lines.push("recovered from backup: true".to_string());
    }
    if let Some(message) = &supervisor.recovery_message {
        lines.push(format!("recovery message: {}", message));
    }

    lines.push(match history_action {
        Some(filter) => format!("recent history (action={}):", history_filter_label(filter)),
        None => "recent history:".to_string(),
    });
    if record.operations_history.is_empty() {
        lines.push("- none".to_string());
    } else {
        let entries = filter_history(
            record.operations_history.as_slice(),
            history_limit,
            history_action,
        );
        if entries.is_empty() {
            lines.push("- none".to_string());
        }
        for entry in entries {
            lines.push(format!("- {}", format_history_entry(entry)));
        }
    }

    lines.join("\n")
}

fn format_history_entry(entry: &OperationHistoryEntry) -> String {
    let action = action_label(entry.action);

    let mut parts = vec![
        entry.recorded_at.clone(),
        action.to_string(),
        format!("{:?}", entry.outcome).to_ascii_lowercase(),
    ];

    if let Some(target) = &entry.target_version {
        parts.push(format!("target={}", target));
    }
    if let Some(active) = &entry.active_version {
        parts.push(format!("active={}", active));
    }
    if let Some(reason) = &entry.reason {
        parts.push(format!("reason={}", reason));
    }

    parts.join(" | ")
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
    use super::{format_history_entry, render_supervisor_record};
    use crate::commands::gateway_history::HistoryActionFilter;
    use crate::instances::status::GatewayInstanceLifecycle;
    use crate::instances::{
        GatewayInstanceId, GatewayInstanceSpec, GatewayInstanceStatus, PolicyConfigSource,
    };
    use crate::supervisor::state_store::SupervisorStateMetadata;
    use crate::supervisor::{OperationAction, OperationHistoryEntry, OperationOutcome};

    struct TestEnvGuard {
        keys: Vec<&'static str>,
    }

    impl TestEnvGuard {
        fn new(pairs: &[(&'static str, String)]) -> Self {
            for (key, value) in pairs {
                crate::test_support::set_var(key, value);
            }
            Self {
                keys: pairs.iter().map(|(key, _)| *key).collect(),
            }
        }
    }

    impl Drop for TestEnvGuard {
        fn drop(&mut self) {
            for key in &self.keys {
                crate::test_support::unset_var(key);
            }
        }
    }

    fn sample_record() -> crate::supervisor::state_store::InstanceRecord {
        let spec = GatewayInstanceSpec::new(
            GatewayInstanceId::new("finance_main").expect("instance id"),
            "finance_main_gw",
            "finance_main",
            "127.0.0.1:41002",
            "https://api.example.com",
            None,
            None,
            None,
            "block",
            PolicyConfigSource::path("/tmp/policy.yaml"),
            8,
            None,
            true,
        )
        .expect("spec");
        let status = GatewayInstanceStatus {
            lifecycle: GatewayInstanceLifecycle::Running,
            observed_config_version: Some("2.0.0".to_string()),
            observed_config_sha256: Some("sha-256".to_string()),
            last_error: Some("last failure".to_string()),
            last_reconciled_at: Some("2026-06-23T10:00:00Z".to_string()),
            last_reconciliation_outcome: Some("rollback_verified".to_string()),
            last_reconciliation_error: Some("transient upstream drift".to_string()),
            ..GatewayInstanceStatus::default()
        };
        crate::supervisor::state_store::InstanceRecord {
            spec,
            status,
            operations_history: vec![
                OperationHistoryEntry {
                    action: OperationAction::Reload,
                    outcome: OperationOutcome::Succeeded,
                    reason: Some("rolled config forward".to_string()),
                    previous_version: Some("1.0.0".to_string()),
                    previous_sha256: Some("sha-old".to_string()),
                    target_version: Some("2.0.0".to_string()),
                    target_sha256: Some("sha-256".to_string()),
                    active_version: Some("2.0.0".to_string()),
                    active_sha256: Some("sha-256".to_string()),
                    recorded_at: "2026-06-23T10:01:00Z".to_string(),
                },
                OperationHistoryEntry {
                    action: OperationAction::Stop,
                    outcome: OperationOutcome::Failed,
                    reason: Some("service manager unavailable".to_string()),
                    previous_version: None,
                    previous_sha256: None,
                    target_version: None,
                    target_sha256: None,
                    active_version: None,
                    active_sha256: None,
                    recorded_at: "2026-06-23T10:02:00Z".to_string(),
                },
            ],
            rollout_plan: None,
        }
    }

    #[test]
    fn render_supervisor_record_uses_region_override_and_filtered_history() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let _env = TestEnvGuard::new(&[("VERDICTAN_REGION", "eu-central".to_string())]);

        let output = render_supervisor_record(
            &SupervisorStateMetadata {
                state_dir: "/tmp/verdictan".to_string(),
                recovered_from_backup: true,
                recovery_message: Some("recovered successfully".to_string()),
                wal_recovered: false,
                state_checksum: Some("checksum".to_string()),
            },
            &sample_record(),
            5,
            Some(HistoryActionFilter::Reload),
        );

        assert!(output.contains("region: eu-central"));
        assert!(output.contains("observed config: 2.0.0 (sha-256)"));
        assert!(output.contains("last error: last failure"));
        assert!(output.contains("recovered from backup: true"));
        assert!(output.contains("recovery message: recovered successfully"));
        assert!(output.contains("recent history (action=reload):"));
        assert!(output.contains("reload | succeeded"));
        assert!(!output.contains("stop | failed"));
    }

    #[test]
    fn render_supervisor_record_reports_no_history_after_filtering() {
        let output = render_supervisor_record(
            &SupervisorStateMetadata {
                state_dir: "/tmp/verdictan".to_string(),
                recovered_from_backup: false,
                recovery_message: None,
                wal_recovered: false,
                state_checksum: None,
            },
            &sample_record(),
            5,
            Some(HistoryActionFilter::Install),
        );

        assert!(output.contains("region: (not set)"));
        assert!(output.contains("recent history (action=install):"));
        assert!(output.contains("- none"));
    }

    #[test]
    fn format_history_entry_includes_target_active_and_reason() {
        let rendered = format_history_entry(&OperationHistoryEntry {
            action: OperationAction::Reconcile,
            outcome: OperationOutcome::RolledBack,
            reason: Some("verification drift".to_string()),
            previous_version: Some("1.0.0".to_string()),
            previous_sha256: Some("old".to_string()),
            target_version: Some("2.0.0".to_string()),
            target_sha256: Some("new".to_string()),
            active_version: Some("1.0.0".to_string()),
            active_sha256: Some("old".to_string()),
            recorded_at: "2026-06-23T11:00:00Z".to_string(),
        });

        assert_eq!(
            rendered,
            "2026-06-23T11:00:00Z | reconcile | rolledback | target=2.0.0 | active=1.0.0 | reason=verification drift"
        );
    }

    #[test]
    fn format_history_entry_no_target_no_active_no_reason() {
        let rendered = format_history_entry(&OperationHistoryEntry {
            action: OperationAction::Install,
            outcome: OperationOutcome::Succeeded,
            reason: None,
            previous_version: None,
            previous_sha256: None,
            target_version: None,
            target_sha256: None,
            active_version: None,
            active_sha256: None,
            recorded_at: "2026-06-23T12:00:00Z".to_string(),
        });
        assert!(rendered.contains("install"));
        assert!(rendered.contains("succeeded"));
        assert!(rendered.contains("2026-06-23T12:00:00Z"));
    }

    #[test]
    fn format_history_entry_with_only_reason() {
        let rendered = format_history_entry(&OperationHistoryEntry {
            action: OperationAction::Stop,
            outcome: OperationOutcome::Failed,
            reason: Some("timeout".to_string()),
            previous_version: None,
            previous_sha256: None,
            target_version: None,
            target_sha256: None,
            active_version: None,
            active_sha256: None,
            recorded_at: "2026-06-23T13:00:00Z".to_string(),
        });
        assert!(rendered.contains("stop"));
        assert!(rendered.contains("failed"));
        assert!(rendered.contains("reason=timeout"));
    }

    #[test]
    fn render_supervisor_record_no_recovery_message() {
        let output = render_supervisor_record(
            &SupervisorStateMetadata {
                state_dir: "/tmp/verdictan".to_string(),
                recovered_from_backup: false,
                recovery_message: None,
                wal_recovered: false,
                state_checksum: None,
            },
            &sample_record(),
            10,
            None,
        );
        assert!(!output.contains("recovered from backup: true"));
        assert!(!output.contains("recovery message:"));
    }

    #[test]
    fn render_supervisor_record_no_observed_config() {
        let mut record = sample_record();
        record.status.observed_config_version = None;
        record.status.observed_config_sha256 = None;
        record.status.last_error = None;
        record.status.last_reconciled_at = None;
        record.status.last_reconciliation_outcome = None;
        record.status.last_reconciliation_error = None;
        let output = render_supervisor_record(
            &SupervisorStateMetadata {
                state_dir: "/tmp".to_string(),
                recovered_from_backup: false,
                recovery_message: None,
                wal_recovered: false,
                state_checksum: None,
            },
            &record,
            5,
            None,
        );
        assert!(!output.contains("observed config:"));
        assert!(!output.contains("last error:"));
        assert!(!output.contains("last reconciled at:"));
    }

    #[test]
    fn render_supervisor_record_empty_history() {
        let mut record = sample_record();
        record.operations_history.clear();
        let output = render_supervisor_record(
            &SupervisorStateMetadata {
                state_dir: "/tmp".to_string(),
                recovered_from_backup: false,
                recovery_message: None,
                wal_recovered: false,
                state_checksum: None,
            },
            &record,
            5,
            None,
        );
        assert!(output.contains("- none"));
    }

    #[test]
    fn render_supervisor_record_all_history_unfiltered() {
        let output = render_supervisor_record(
            &SupervisorStateMetadata {
                state_dir: "/tmp".to_string(),
                recovered_from_backup: false,
                recovery_message: None,
                wal_recovered: false,
                state_checksum: None,
            },
            &sample_record(),
            10,
            None,
        );
        assert!(output.contains("recent history:"));
        assert!(output.contains("reload | succeeded"));
        assert!(output.contains("stop | failed"));
    }

    #[test]
    fn format_history_entry_with_target_and_active_versions() {
        let rendered = format_history_entry(&OperationHistoryEntry {
            action: OperationAction::Reload,
            outcome: OperationOutcome::Succeeded,
            reason: None,
            previous_version: Some("v1".to_string()),
            previous_sha256: Some("old-sha".to_string()),
            target_version: Some("v2".to_string()),
            target_sha256: Some("new-sha".to_string()),
            active_version: Some("v2".to_string()),
            active_sha256: Some("new-sha".to_string()),
            recorded_at: "2026-06-25T00:00:00Z".to_string(),
        });
        assert!(rendered.contains("target=v2"));
        assert!(rendered.contains("active=v2"));
        assert!(!rendered.contains("reason="));
    }
}
