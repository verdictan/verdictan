// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde::{Deserialize, Serialize};

use crate::commands::gateway_service::ServicePlatform;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeServiceManager {
    #[default]
    Manual,
    Launchd,
    LaunchDaemon,
    SystemdUser,
    SystemdSystem,
    WindowsService,
}

impl RuntimeServiceManager {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Launchd => "launchd",
            Self::LaunchDaemon => "launch_daemon",
            Self::SystemdUser => "systemd_user",
            Self::SystemdSystem => "systemd_system",
            Self::WindowsService => "windows_service",
        }
    }
}

impl From<ServicePlatform> for RuntimeServiceManager {
    fn from(value: ServicePlatform) -> Self {
        match value {
            ServicePlatform::Launchd => Self::Launchd,
            ServicePlatform::LaunchDaemon => Self::LaunchDaemon,
            ServicePlatform::SystemdUser => Self::SystemdUser,
            ServicePlatform::SystemdSystem => Self::SystemdSystem,
            ServicePlatform::WindowsService => Self::WindowsService,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeUpgradePhase {
    #[default]
    Planned,
    Applying,
    Succeeded,
    Failed,
    RolledBack,
}

impl RuntimeUpgradePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Applying => "applying",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeUpgradeHealthCheck {
    pub command: String,
    pub timeout_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_stdout_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_stderr_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeRollbackRecord {
    pub version: String,
    pub binary_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_sha256: Option<String>,
    pub recorded_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeUpgradePlan {
    pub target_version: String,
    pub target_binary_path: String,
    pub service_manager: RuntimeServiceManager,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_check: Option<RuntimeUpgradeHealthCheck>,
    pub rollback: RuntimeRollbackRecord,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeUpgradeStatus {
    pub phase: RuntimeUpgradePhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_binary_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_binary_path: Option<String>,
    pub service_manager: RuntimeServiceManager,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_restart_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_check: Option<RuntimeUpgradeHealthCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback: Option<RuntimeRollbackRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

impl RuntimeUpgradeStatus {
    pub fn from_plan(
        plan: &RuntimeUpgradePlan,
        active_version: Option<String>,
        active_binary_path: Option<String>,
    ) -> Self {
        Self {
            phase: RuntimeUpgradePhase::Planned,
            active_version,
            active_binary_path,
            target_version: Some(plan.target_version.clone()),
            target_binary_path: Some(plan.target_binary_path.clone()),
            service_manager: plan.service_manager,
            config_sha256: plan.config_sha256.clone(),
            last_restart_at: None,
            last_error: None,
            health_check: plan.health_check.clone(),
            rollback: Some(plan.rollback.clone()),
            updated_at: Some(plan.created_at.clone()),
        }
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
    fn runtime_upgrade_status_copies_plan_fields() {
        let plan = RuntimeUpgradePlan {
            target_version: "2.1.0".to_string(),
            target_binary_path: "/opt/verdictan/bin/verdictan".to_string(),
            service_manager: RuntimeServiceManager::SystemdUser,
            config_sha256: Some("sha-config".to_string()),
            health_check: Some(RuntimeUpgradeHealthCheck {
                command: "verdictan gateway status --json".to_string(),
                timeout_secs: 30,
                ..RuntimeUpgradeHealthCheck::default()
            }),
            rollback: RuntimeRollbackRecord {
                version: "2.0.0".to_string(),
                binary_path: "/opt/verdictan/bin/verdictan-prev".to_string(),
                config_sha256: Some("sha-prev".to_string()),
                recorded_at: "2026-07-05T00:00:00Z".to_string(),
                reason: Some("previous stable runtime".to_string()),
            },
            created_at: "2026-07-05T00:00:00Z".to_string(),
        };

        let status = RuntimeUpgradeStatus::from_plan(
            &plan,
            Some("2.0.0".to_string()),
            Some("/opt/verdictan/bin/verdictan-prev".to_string()),
        );

        assert_eq!(status.phase, RuntimeUpgradePhase::Planned);
        assert_eq!(status.active_version.as_deref(), Some("2.0.0"));
        assert_eq!(status.target_version.as_deref(), Some("2.1.0"));
        assert_eq!(
            status.target_binary_path.as_deref(),
            Some("/opt/verdictan/bin/verdictan")
        );
        assert_eq!(status.service_manager, RuntimeServiceManager::SystemdUser);
        assert!(status.rollback.is_some());
    }
}
