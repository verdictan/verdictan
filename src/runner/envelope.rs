// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! RUNNER-010: Gateway execution session envelope — signed dispatch package delivered by
//! the control plane to a gateway.
//!
//! The envelope carries everything a gateway needs to begin executing a session:
//! - targeting information (which gateway)
//! - merged profile configuration
//! - active permission grants (filesystem, network, tool)
//! - identity context (org, user, service account)
//! - whether custom harness overrides are permitted
//! - an optional custom harness override (only when `allows_custom_harness` is true)
use serde::{Deserialize, Serialize};

// ── Identity context ──────────────────────────────────────────────────────────

/// The identity under which the gateway execution session executes.
///
/// Carried in the session envelope so the harness can tag telemetry, enforce
/// data-residency policies, and self-report to the control plane with the
/// correct tenant context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerIdentityContext {
    /// Tenant organisation UUID.
    pub org_id: String,
    /// UUID of the user who dispatched the session, if applicable.
    pub user_id: Option<String>,
    /// UUID of the service account used for dispatch, if applicable.
    pub service_account_id: Option<String>,
    /// Opaque bearer token for the execution runtime to call back to the control plane.
    /// Scoped to `gateway_execution:write` on `org/*` only.
    pub session_api_token: Option<String>,
}

// ── Permission grant ──────────────────────────────────────────────────────────

/// A fine-grained permission grant active for this gateway execution session.
///
/// Mirrors the `runner_permission_grants` table row delivered to the gateway
/// so the execution sandbox can enforce the constraints locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerPermissionGrant {
    pub id: String,
    /// One of: `filesystem`, `network`, `tool`.
    pub grant_type: String,
    /// Grant-type-specific scope definition.
    ///
    /// | `grant_type` | Expected shape |
    /// |---------------|----------------|
    /// | `filesystem` | `{"paths": ["/home/user/project"], "mode": "read_write"}` |
    /// | `network` | `{"hosts": ["api.example.com"], "ports": [443]}` |
    /// | `tool` | `{"tool_names": ["bash", "python"]}` |
    pub scope: serde_json::Value,
    /// ISO-8601 expiry timestamp. `None` means the grant lives for the
    /// duration of the session.
    pub expires_at: Option<String>,
}

// ── Harness specification ─────────────────────────────────────────────────────

/// An optional custom harness override.
///
/// Only accepted when `allows_custom_harness` is `true` (RUNNER-012).
/// The source and version are recorded in the audit event log when accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessSpec {
    /// Path to the harness executable, or an inline script identifier.
    pub source: String,
    /// Version tag for audit metadata (e.g. `"v1.2.3"` or a git SHA).
    pub version: String,
    /// Optional BLAKE3 checksum of the harness binary/script for integrity
    /// verification before execution.
    pub checksum: Option<String>,
}

// ── Session envelope ──────────────────────────────────────────────────────────

/// A gateway execution session envelope delivered by the control plane (RUNNER-010).
///
/// The gateway validates this envelope via
/// [`crate::runner::harness::validate_harness`] and the targeting
/// checks before accepting and executing the session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerSessionEnvelope {
    /// Control-plane session UUID (maps to `runner_sessions.id`).
    pub session_id: String,
    /// Identity context for tenant isolation and API call-back.
    pub identity: RunnerIdentityContext,
    /// Whether this session permits custom harness overrides.
    /// When `false`, only the managed Verdictan harness is used.
    pub allows_custom_harness: bool,
    /// Specific gateway UUID this session is targeted at.
    ///
    /// `None` means any gateway may accept it.
    pub target_gateway_id: Option<String>,
    /// Merged profile configuration (profile defaults + caller overrides).
    ///
    /// Well-known keys used by the default harness driver:
    /// - `command` (string) — harness executable + args.
    /// - `working_dir` (string) — working directory.
    /// - `env` (object) — extra environment variables (string→string).
    /// - `timeout_seconds` (u64) — session timeout; defaults to `3600`.
    pub profile_config: serde_json::Value,
    /// Active permission grants scoped to this session.
    #[serde(default)]
    pub permission_grants: Vec<RunnerPermissionGrant>,
    /// Optional prompt text forwarded to the harness.
    pub prompt: Option<String>,
    /// Optional custom harness override.
    ///
    /// Only permitted when `allows_custom_harness` is `true`
    /// (validated by [`crate::runner::harness::validate_harness`]).
    pub harness: Option<HarnessSpec>,
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

    fn sample_identity() -> RunnerIdentityContext {
        RunnerIdentityContext {
            org_id: "org-123".to_string(),
            user_id: Some("user-456".to_string()),
            service_account_id: None,
            session_api_token: Some("tok-abc".to_string()),
        }
    }

    fn sample_permission_grant() -> RunnerPermissionGrant {
        RunnerPermissionGrant {
            id: "grant-1".to_string(),
            grant_type: "filesystem".to_string(),
            scope: serde_json::json!({"paths": ["/home/user"], "mode": "read_write"}),
            expires_at: Some("2025-12-31T23:59:59Z".to_string()),
        }
    }

    fn sample_harness() -> HarnessSpec {
        HarnessSpec {
            source: "/usr/local/bin/custom-harness".to_string(),
            version: "v1.2.3".to_string(),
            checksum: Some("abc123def456".to_string()),
        }
    }

    fn sample_envelope() -> RunnerSessionEnvelope {
        RunnerSessionEnvelope {
            session_id: "sess-789".to_string(),
            identity: sample_identity(),
            allows_custom_harness: true,
            target_gateway_id: Some("gw-prod-01".to_string()),
            profile_config: serde_json::json!({
                "command": "python run.py",
                "working_dir": "/workspace",
                "timeout_seconds": 3600
            }),
            permission_grants: vec![sample_permission_grant()],
            prompt: Some("Analyze the data".to_string()),
            harness: Some(sample_harness()),
        }
    }

    #[test]
    fn envelope_serde_round_trip() {
        let envelope = sample_envelope();
        let json = serde_json::to_string(&envelope).unwrap();
        let recovered: RunnerSessionEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.session_id, "sess-789");
        assert_eq!(recovered.identity.org_id, "org-123");
        assert!(recovered.allows_custom_harness);
        assert_eq!(recovered.target_gateway_id.as_deref(), Some("gw-prod-01"));
        assert_eq!(recovered.permission_grants.len(), 1);
        assert_eq!(recovered.prompt.as_deref(), Some("Analyze the data"));
        assert!(recovered.harness.is_some());
    }

    #[test]
    fn identity_context_serde_round_trip() {
        let identity = sample_identity();
        let json = serde_json::to_string(&identity).unwrap();
        let recovered: RunnerIdentityContext = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.org_id, "org-123");
        assert_eq!(recovered.user_id.as_deref(), Some("user-456"));
        assert!(recovered.service_account_id.is_none());
        assert_eq!(recovered.session_api_token.as_deref(), Some("tok-abc"));
    }

    #[test]
    fn permission_grant_serde_round_trip() {
        let grant = sample_permission_grant();
        let json = serde_json::to_string(&grant).unwrap();
        let recovered: RunnerPermissionGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.id, "grant-1");
        assert_eq!(recovered.grant_type, "filesystem");
        assert!(recovered.expires_at.is_some());
    }

    #[test]
    fn harness_spec_serde_round_trip() {
        let harness = sample_harness();
        let json = serde_json::to_string(&harness).unwrap();
        let recovered: HarnessSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.source, "/usr/local/bin/custom-harness");
        assert_eq!(recovered.version, "v1.2.3");
        assert_eq!(recovered.checksum.as_deref(), Some("abc123def456"));
    }

    #[test]
    fn harness_spec_without_checksum() {
        let harness = HarnessSpec {
            source: "inline.sh".to_string(),
            version: "v0.1.0".to_string(),
            checksum: None,
        };
        let json = serde_json::to_string(&harness).unwrap();
        let recovered: HarnessSpec = serde_json::from_str(&json).unwrap();
        assert!(recovered.checksum.is_none());
    }

    #[test]
    fn envelope_minimal_without_optional_fields() {
        let envelope = RunnerSessionEnvelope {
            session_id: "sess-min".to_string(),
            identity: RunnerIdentityContext {
                org_id: "org-1".to_string(),
                user_id: None,
                service_account_id: None,
                session_api_token: None,
            },
            allows_custom_harness: false,
            target_gateway_id: None,
            profile_config: serde_json::json!({}),
            permission_grants: vec![],
            prompt: None,
            harness: None,
        };
        let json = serde_json::to_string(&envelope).unwrap();
        let recovered: RunnerSessionEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.session_id, "sess-min");
        assert!(!recovered.allows_custom_harness);
        assert!(recovered.target_gateway_id.is_none());
        assert!(recovered.permission_grants.is_empty());
        assert!(recovered.prompt.is_none());
        assert!(recovered.harness.is_none());
    }

    #[test]
    fn permission_grant_network_type() {
        let grant = RunnerPermissionGrant {
            id: "grant-net".to_string(),
            grant_type: "network".to_string(),
            scope: serde_json::json!({"hosts": ["api.example.com"], "ports": [443]}),
            expires_at: None,
        };
        let json = serde_json::to_string(&grant).unwrap();
        let recovered: RunnerPermissionGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.grant_type, "network");
        assert!(recovered.expires_at.is_none());
    }

    #[test]
    fn permission_grant_tool_type() {
        let grant = RunnerPermissionGrant {
            id: "grant-tool".to_string(),
            grant_type: "tool".to_string(),
            scope: serde_json::json!({"tool_names": ["bash", "python"]}),
            expires_at: None,
        };
        let json = serde_json::to_string(&grant).unwrap();
        let recovered: RunnerPermissionGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.grant_type, "tool");
    }
}
