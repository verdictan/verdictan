// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use chrono::Utc;
use clap::ValueEnum;

use crate::supervisor::{OperationAction, OperationHistoryEntry, OperationOutcome};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum HistoryActionFilter {
    Reload,
    Reconcile,
    Revert,
    Install,
    Start,
    Stop,
    Uninstall,
    Upgrade,
}

pub fn build_operation_entry(
    action: OperationAction,
    outcome: OperationOutcome,
    reason: Option<String>,
    record: &crate::supervisor::state_store::InstanceRecord,
) -> OperationHistoryEntry {
    OperationHistoryEntry {
        action,
        outcome,
        reason,
        previous_version: record.status.observed_config_version.clone(),
        previous_sha256: record.status.observed_config_sha256.clone(),
        target_version: record.status.observed_config_version.clone(),
        target_sha256: record.status.observed_config_sha256.clone(),
        active_version: record.status.observed_config_version.clone(),
        active_sha256: record.status.observed_config_sha256.clone(),
        recorded_at: Utc::now().to_rfc3339(),
    }
}

pub fn action_label(action: OperationAction) -> &'static str {
    match action {
        OperationAction::Reload => "reload",
        OperationAction::Reconcile => "reconcile",
        OperationAction::CancelReconcile => "cancel_reconcile",
        OperationAction::Revert => "revert",
        OperationAction::Install => "install",
        OperationAction::Start => "start",
        OperationAction::Stop => "stop",
        OperationAction::Uninstall => "uninstall",
        OperationAction::UpgradePlan => "upgrade_plan",
        OperationAction::UpgradeApply => "upgrade_apply",
        OperationAction::UpgradeRollback => "upgrade_rollback",
    }
}

pub fn history_filter_label(filter: HistoryActionFilter) -> &'static str {
    match filter {
        HistoryActionFilter::Reload => "reload",
        HistoryActionFilter::Reconcile => "reconcile",
        HistoryActionFilter::Revert => "revert",
        HistoryActionFilter::Install => "install",
        HistoryActionFilter::Start => "start",
        HistoryActionFilter::Stop => "stop",
        HistoryActionFilter::Uninstall => "uninstall",
        HistoryActionFilter::Upgrade => "upgrade",
    }
}

pub fn filter_history(
    operations_history: &[OperationHistoryEntry],
    history_limit: usize,
    action_filter: Option<HistoryActionFilter>,
) -> Vec<&OperationHistoryEntry> {
    let limit = history_limit.max(1);
    operations_history
        .iter()
        .rev()
        .filter(|entry| action_filter.is_none_or(|filter| matches_filter(entry.action, filter)))
        .take(limit)
        .collect()
}

fn matches_filter(action: OperationAction, filter: HistoryActionFilter) -> bool {
    matches!(
        (action, filter),
        (OperationAction::Reload, HistoryActionFilter::Reload)
            | (OperationAction::Reconcile, HistoryActionFilter::Reconcile)
            | (
                OperationAction::CancelReconcile,
                HistoryActionFilter::Reconcile
            )
            | (OperationAction::Revert, HistoryActionFilter::Revert)
            | (OperationAction::Install, HistoryActionFilter::Install)
            | (OperationAction::Start, HistoryActionFilter::Start)
            | (OperationAction::Stop, HistoryActionFilter::Stop)
            | (OperationAction::Uninstall, HistoryActionFilter::Uninstall)
            | (OperationAction::UpgradePlan, HistoryActionFilter::Upgrade)
            | (OperationAction::UpgradeApply, HistoryActionFilter::Upgrade)
            | (
                OperationAction::UpgradeRollback,
                HistoryActionFilter::Upgrade
            )
    )
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

    fn make_entry(action: OperationAction) -> OperationHistoryEntry {
        OperationHistoryEntry {
            action,
            outcome: OperationOutcome::Succeeded,
            reason: None,
            previous_version: None,
            previous_sha256: None,
            target_version: None,
            target_sha256: None,
            active_version: None,
            active_sha256: None,
            recorded_at: "2025-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn action_label_all_variants() {
        assert_eq!(action_label(OperationAction::Reload), "reload");
        assert_eq!(action_label(OperationAction::Reconcile), "reconcile");
        assert_eq!(
            action_label(OperationAction::CancelReconcile),
            "cancel_reconcile"
        );
        assert_eq!(action_label(OperationAction::Revert), "revert");
        assert_eq!(action_label(OperationAction::Install), "install");
        assert_eq!(action_label(OperationAction::Start), "start");
        assert_eq!(action_label(OperationAction::Stop), "stop");
        assert_eq!(action_label(OperationAction::Uninstall), "uninstall");
    }

    #[test]
    fn history_filter_label_all_variants() {
        assert_eq!(history_filter_label(HistoryActionFilter::Reload), "reload");
        assert_eq!(
            history_filter_label(HistoryActionFilter::Reconcile),
            "reconcile"
        );
        assert_eq!(history_filter_label(HistoryActionFilter::Revert), "revert");
        assert_eq!(
            history_filter_label(HistoryActionFilter::Install),
            "install"
        );
        assert_eq!(history_filter_label(HistoryActionFilter::Start), "start");
        assert_eq!(history_filter_label(HistoryActionFilter::Stop), "stop");
        assert_eq!(
            history_filter_label(HistoryActionFilter::Uninstall),
            "uninstall"
        );
    }

    #[test]
    fn matches_filter_reload() {
        assert!(matches_filter(
            OperationAction::Reload,
            HistoryActionFilter::Reload
        ));
        assert!(!matches_filter(
            OperationAction::Reload,
            HistoryActionFilter::Stop
        ));
    }

    #[test]
    fn matches_filter_reconcile_includes_cancel() {
        assert!(matches_filter(
            OperationAction::Reconcile,
            HistoryActionFilter::Reconcile
        ));
        assert!(matches_filter(
            OperationAction::CancelReconcile,
            HistoryActionFilter::Reconcile
        ));
    }

    #[test]
    fn matches_filter_negative_cases() {
        assert!(!matches_filter(
            OperationAction::Revert,
            HistoryActionFilter::Install
        ));
        assert!(!matches_filter(
            OperationAction::Start,
            HistoryActionFilter::Stop
        ));
        assert!(!matches_filter(
            OperationAction::Install,
            HistoryActionFilter::Uninstall
        ));
    }

    #[test]
    fn filter_history_empty() {
        let entries: Vec<OperationHistoryEntry> = vec![];
        let result = filter_history(&entries, 10, None);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_history_no_filter_respects_limit() {
        let entries = vec![
            make_entry(OperationAction::Reload),
            make_entry(OperationAction::Start),
            make_entry(OperationAction::Stop),
        ];
        let result = filter_history(&entries, 2, None);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn filter_history_returns_most_recent_first() {
        let entries = vec![
            make_entry(OperationAction::Install),
            make_entry(OperationAction::Reload),
            make_entry(OperationAction::Stop),
        ];
        let result = filter_history(&entries, 10, None);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].action, OperationAction::Stop);
    }

    #[test]
    fn filter_history_with_action_filter() {
        let entries = vec![
            make_entry(OperationAction::Reload),
            make_entry(OperationAction::Start),
            make_entry(OperationAction::Reload),
        ];
        let result = filter_history(&entries, 10, Some(HistoryActionFilter::Reload));
        assert_eq!(result.len(), 2);
        for entry in &result {
            assert_eq!(entry.action, OperationAction::Reload);
        }
    }

    #[test]
    fn filter_history_limit_zero_treated_as_one() {
        let entries = vec![
            make_entry(OperationAction::Reload),
            make_entry(OperationAction::Start),
        ];
        let result = filter_history(&entries, 0, None);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn filter_history_limit_exceeds_entries() {
        let entries = vec![make_entry(OperationAction::Reload)];
        let result = filter_history(&entries, 100, None);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn filter_history_with_action_filter_no_match() {
        let entries = vec![
            make_entry(OperationAction::Reload),
            make_entry(OperationAction::Start),
        ];
        let result = filter_history(&entries, 10, Some(HistoryActionFilter::Uninstall));
        assert!(result.is_empty());
    }

    #[test]
    fn matches_filter_all_action_filter_combinations() {
        assert!(matches_filter(
            OperationAction::Revert,
            HistoryActionFilter::Revert
        ));
        assert!(matches_filter(
            OperationAction::Install,
            HistoryActionFilter::Install
        ));
        assert!(matches_filter(
            OperationAction::Start,
            HistoryActionFilter::Start
        ));
        assert!(matches_filter(
            OperationAction::Stop,
            HistoryActionFilter::Stop
        ));
        assert!(matches_filter(
            OperationAction::Uninstall,
            HistoryActionFilter::Uninstall
        ));
    }

    #[test]
    fn action_label_cancel_reconcile() {
        assert_eq!(
            action_label(OperationAction::CancelReconcile),
            "cancel_reconcile"
        );
    }

    #[test]
    fn operation_history_entry_manual_construction() {
        let entry = OperationHistoryEntry {
            action: OperationAction::Reload,
            outcome: OperationOutcome::Succeeded,
            reason: Some("test reason".to_string()),
            previous_version: None,
            previous_sha256: None,
            target_version: None,
            target_sha256: None,
            active_version: None,
            active_sha256: None,
            recorded_at: "2025-01-01T00:00:00Z".into(),
        };
        assert_eq!(entry.action, OperationAction::Reload);
        assert_eq!(entry.outcome, OperationOutcome::Succeeded);
        assert_eq!(entry.reason.as_deref(), Some("test reason"));
        assert!(!entry.recorded_at.is_empty());
    }

    #[test]
    fn operation_history_entry_with_all_version_fields() {
        let entry = OperationHistoryEntry {
            action: OperationAction::Reconcile,
            outcome: OperationOutcome::RolledBack,
            reason: Some("drift detected".to_string()),
            previous_version: Some("1.0.0".to_string()),
            previous_sha256: Some("sha-prev".to_string()),
            target_version: Some("2.0.0".to_string()),
            target_sha256: Some("sha-target".to_string()),
            active_version: Some("1.0.0".to_string()),
            active_sha256: Some("sha-prev".to_string()),
            recorded_at: "2025-06-01T00:00:00Z".into(),
        };
        assert_eq!(entry.previous_version.as_deref(), Some("1.0.0"));
        assert_eq!(entry.previous_sha256.as_deref(), Some("sha-prev"));
        assert_eq!(entry.target_version.as_deref(), Some("2.0.0"));
        assert_eq!(entry.target_sha256.as_deref(), Some("sha-target"));
        assert_eq!(entry.active_version.as_deref(), Some("1.0.0"));
        assert_eq!(entry.active_sha256.as_deref(), Some("sha-prev"));
    }
}
