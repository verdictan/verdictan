// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use chrono::Utc;

use crate::gateway::runtime_upgrade::{RuntimeUpgradePlan, RuntimeUpgradeStatus};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigVerificationState {
    Unknown,
    Pending,
    Verified,
    Failed,
    RolledBack,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayInstanceLifecycle {
    Stopped,
    Starting,
    Running,
    Failed,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct GatewayInstanceStatus {
    pub lifecycle: GatewayInstanceLifecycle,
    pub desired_config_version: Option<String>,
    pub desired_config_sha256: Option<String>,
    pub desired_config_source: Option<String>,
    pub observed_config_version: Option<String>,
    pub observed_config_sha256: Option<String>,
    pub last_known_good_version: Option<String>,
    pub last_known_good_sha256: Option<String>,
    pub rollback_target_version: Option<String>,
    pub rollback_target_sha256: Option<String>,
    pub rollback_target_yaml: Option<String>,
    pub last_reload_reason: Option<String>,
    pub last_rollback_reason: Option<String>,
    pub last_error: Option<String>,
    pub verification_state: ConfigVerificationState,
    pub last_verified_at: Option<String>,
    pub last_checkpoint_at: Option<String>,
    pub last_reconciled_at: Option<String>,
    pub last_reconciliation_outcome: Option<String>,
    pub last_reconciliation_error: Option<String>,
    pub last_healthcheck_at: Option<String>,
    pub last_observed_healthy: Option<bool>,
    pub last_seen_at: Option<String>,
    pub runtime_upgrade_plan: Option<RuntimeUpgradePlan>,
    pub runtime_upgrade_status: Option<RuntimeUpgradeStatus>,
    pub updated_at: String,
}

impl Default for GatewayInstanceStatus {
    fn default() -> Self {
        Self {
            lifecycle: GatewayInstanceLifecycle::Stopped,
            desired_config_version: None,
            desired_config_sha256: None,
            desired_config_source: None,
            observed_config_version: None,
            observed_config_sha256: None,
            last_known_good_version: None,
            last_known_good_sha256: None,
            rollback_target_version: None,
            rollback_target_sha256: None,
            rollback_target_yaml: None,
            last_reload_reason: None,
            last_rollback_reason: None,
            last_error: None,
            verification_state: ConfigVerificationState::Unknown,
            last_verified_at: None,
            last_checkpoint_at: None,
            last_reconciled_at: None,
            last_reconciliation_outcome: None,
            last_reconciliation_error: None,
            last_healthcheck_at: None,
            last_observed_healthy: None,
            last_seen_at: None,
            runtime_upgrade_plan: None,
            runtime_upgrade_status: None,
            updated_at: Utc::now().to_rfc3339(),
        }
    }
}

impl GatewayInstanceStatus {
    #[allow(dead_code)]
    pub fn with_lifecycle(mut self, lifecycle: GatewayInstanceLifecycle) -> Self {
        self.lifecycle = lifecycle;
        self.updated_at = Utc::now().to_rfc3339();
        self
    }
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
    fn default_status_is_stopped() {
        let status = GatewayInstanceStatus::default();
        assert_eq!(status.lifecycle, GatewayInstanceLifecycle::Stopped);
        assert_eq!(status.verification_state, ConfigVerificationState::Unknown);
        assert!(status.desired_config_version.is_none());
        assert!(status.observed_config_version.is_none());
        assert!(status.last_error.is_none());
        assert!(status.last_known_good_version.is_none());
    }

    #[test]
    fn lifecycle_serde_roundtrip_stopped() {
        let lifecycle = GatewayInstanceLifecycle::Stopped;
        let json = serde_json::to_string(&lifecycle).unwrap();
        assert_eq!(json, r#""stopped""#);
        let recovered: GatewayInstanceLifecycle = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, GatewayInstanceLifecycle::Stopped);
    }

    #[test]
    fn lifecycle_serde_roundtrip_starting() {
        let lifecycle = GatewayInstanceLifecycle::Starting;
        let json = serde_json::to_string(&lifecycle).unwrap();
        assert_eq!(json, r#""starting""#);
        let recovered: GatewayInstanceLifecycle = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, GatewayInstanceLifecycle::Starting);
    }

    #[test]
    fn lifecycle_serde_roundtrip_running() {
        let lifecycle = GatewayInstanceLifecycle::Running;
        let json = serde_json::to_string(&lifecycle).unwrap();
        assert_eq!(json, r#""running""#);
        let recovered: GatewayInstanceLifecycle = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, GatewayInstanceLifecycle::Running);
    }

    #[test]
    fn lifecycle_serde_roundtrip_failed() {
        let lifecycle = GatewayInstanceLifecycle::Failed;
        let json = serde_json::to_string(&lifecycle).unwrap();
        assert_eq!(json, r#""failed""#);
        let recovered: GatewayInstanceLifecycle = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, GatewayInstanceLifecycle::Failed);
    }

    #[test]
    fn verification_state_serde_unknown() {
        let state = ConfigVerificationState::Unknown;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#""unknown""#);
        let recovered: ConfigVerificationState = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, ConfigVerificationState::Unknown);
    }

    #[test]
    fn verification_state_serde_pending() {
        let state = ConfigVerificationState::Pending;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#""pending""#);
    }

    #[test]
    fn verification_state_serde_verified() {
        let state = ConfigVerificationState::Verified;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#""verified""#);
    }

    #[test]
    fn verification_state_serde_failed() {
        let state = ConfigVerificationState::Failed;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#""failed""#);
    }

    #[test]
    fn verification_state_serde_rolled_back() {
        let state = ConfigVerificationState::RolledBack;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#""rolled_back""#);
    }

    #[test]
    fn full_status_serde_roundtrip() {
        let status = GatewayInstanceStatus {
            lifecycle: GatewayInstanceLifecycle::Running,
            desired_config_version: Some("v2".to_string()),
            desired_config_sha256: Some("sha-desired".to_string()),
            desired_config_source: Some("file".to_string()),
            observed_config_version: Some("v1".to_string()),
            observed_config_sha256: Some("sha-observed".to_string()),
            last_known_good_version: Some("v1".to_string()),
            last_known_good_sha256: Some("sha-good".to_string()),
            rollback_target_version: Some("v0".to_string()),
            rollback_target_sha256: Some("sha-rollback".to_string()),
            rollback_target_yaml: Some("yaml-content".to_string()),
            last_reload_reason: Some("config change".to_string()),
            last_rollback_reason: None,
            last_error: None,
            verification_state: ConfigVerificationState::Verified,
            last_verified_at: Some("2025-01-01T00:00:00Z".to_string()),
            last_checkpoint_at: Some("2025-01-01T00:00:00Z".to_string()),
            last_reconciled_at: Some("2025-01-01T00:00:00Z".to_string()),
            last_reconciliation_outcome: Some("success".to_string()),
            last_reconciliation_error: None,
            last_healthcheck_at: Some("2025-01-01T00:00:00Z".to_string()),
            last_observed_healthy: Some(true),
            last_seen_at: Some("2025-01-01T00:00:00Z".to_string()),
            runtime_upgrade_plan: None,
            runtime_upgrade_status: None,
            updated_at: Utc::now().to_rfc3339(),
        };
        let json = serde_json::to_string(&status).unwrap();
        let recovered: GatewayInstanceStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.lifecycle, GatewayInstanceLifecycle::Running);
        assert_eq!(recovered.desired_config_version.as_deref(), Some("v2"));
        assert_eq!(
            recovered.verification_state,
            ConfigVerificationState::Verified
        );
        assert_eq!(recovered.last_observed_healthy, Some(true));
    }
}
