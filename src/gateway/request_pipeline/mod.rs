// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Request-family pipeline modules.
//!
//! Family handlers and shared orchestration helpers live here as real Rust
//! modules. Provider translation remains in `provider_adapters.rs`.
//!
//! [`governance::RequestGovernancePipeline`] owns the family-neutral ordered
//! stage sequence; adapters under `governance` perform typed extraction and
//! reconstruction only.

// Shared orchestration parts (re-exported so siblings can `use super::*`).
pub(super) mod chat_part1;
pub(super) mod chat_part2;
pub(super) mod messages;
pub(super) mod responses_part1;
pub(super) mod responses_part2;
pub(super) mod responses_part3;
pub(super) mod responses_part4;
pub(super) mod responses_part5;

pub(super) use chat_part1::*;
pub(super) use chat_part2::*;
pub(super) use messages::*;
pub(super) use responses_part1::*;
pub(super) use responses_part2::*;
pub(super) use responses_part3::*;
pub(super) use responses_part4::*;
pub(super) use responses_part5::*;

// Previously `pub` in the server module; keep crate/tests and gateway siblings callable.
pub use responses_part1::{
    annotate_streaming_decision_event_metadata, decision_event_json, decision_runtime_json,
    decision_runtime_json_streaming, enrich_decision_event_details,
    filter_quality_scores_for_event, redact_event_message_bodies, verdictan_headers,
};
pub use responses_part3::{
    build_spend_log_payload_with_usage, estimate_streaming_spend_usage, spend_gateway_reference,
};
pub use responses_part4::{
    build_provider_cache_key, enforce_token_rate_limit, join_upstream, rewrite_upstream_path,
};

// Family handler modules
pub(super) mod chat;
pub(super) mod responses;
pub(super) mod streaming;
pub(super) mod tools;
pub(super) mod websocket;

pub(super) use chat::chat_completions;
pub(super) use responses::responses;
pub(super) use streaming::build_messages_connected_streaming_response;
pub(super) use tools::request_uses_tooling_shape;
pub(super) use websocket::{chat_completions_ws, responses_ws};

/// Family-neutral ordered governance pipeline.
///
/// Import via `request_pipeline::governance::{RequestGovernancePipeline,...}`.
/// Keep the surface module-scoped so server's `use request_pipeline::*` does not
/// pull unused governance symbols into the parent namespace.
pub mod governance;

/// Minimal distributed budget admission gate.
///
/// Budget reservation is admitted only when the immutable distributed
/// requirement and backend health allow it. [`DistributedRequirement::Required`]
/// fail-closes while the shared backend is unhealthy;
/// [`DistributedRequirement::LocalOnly`] admits process-local budget tracking
/// only for the explicit one-node self-hosted development contract.
pub mod budget_admission {
    use crate::gateway::distributed_rate_limit::{
        BackendHealthSnapshot, BackendHealthTracker, DistributedFailurePolicy,
    };
    use crate::gateway::distributed_state::DistributedRequirement;

    /// Decision returned by [`admit_budget_reservation`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BudgetAdmissionDecision {
        /// Shared backend is healthy; proceed with distributed budget reservation.
        AdmitDistributed,
        /// Explicit LocalOnly contract; process-local budget tracking is permitted.
        AdmitLocalOnly,
        /// No shared-state consumers; admission is unconstrained here.
        AdmitUnrestricted,
        /// Required backend is unhealthy; deny before provider dispatch.
        DenyFailClosed,
    }

    impl BudgetAdmissionDecision {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::AdmitDistributed => "admit_distributed",
                Self::AdmitLocalOnly => "admit_local_only",
                Self::AdmitUnrestricted => "admit_unrestricted",
                Self::DenyFailClosed => "deny_fail_closed",
            }
        }

        pub fn allows_dispatch(self) -> bool {
            !matches!(self, Self::DenyFailClosed)
        }
    }

    /// Evaluate budget admission against the immutable requirement and health.
    ///
    /// Never rematerializes LocalOnly from a Required outage — callers must
    /// pass the startup-derived requirement unchanged.
    pub fn admit_budget_reservation(
        requirement: DistributedRequirement,
        health: &BackendHealthTracker,
    ) -> BudgetAdmissionDecision {
        // Preserve the fixed contract: Required stays Required after failure.
        let requirement = requirement.after_backend_failure();
        let policy = DistributedFailurePolicy::for_requirement(requirement);
        let snapshot = health.snapshot();
        match requirement {
            DistributedRequirement::Disabled => BudgetAdmissionDecision::AdmitUnrestricted,
            DistributedRequirement::LocalOnly => BudgetAdmissionDecision::AdmitLocalOnly,
            DistributedRequirement::Required => {
                if policy.is_fail_closed() && !snapshot.admits_traffic() {
                    BudgetAdmissionDecision::DenyFailClosed
                } else {
                    BudgetAdmissionDecision::AdmitDistributed
                }
            }
        }
    }

    /// Gate budget reservation using the gateway's distributed-state contract.
    ///
    /// Uses the immutable requirement plus live backend availability (which
    /// already applies two-success recovery in `DistributedState`). Required
    /// deployments fail closed while the backend is unavailable; LocalOnly
    /// remains the explicit one-node development contract only.
    pub fn admit_budget_for_distributed_state(
        state: &crate::gateway::distributed_state::DistributedState,
    ) -> BudgetAdmissionDecision {
        let requirement = state.requirement().after_backend_failure();
        match requirement {
            DistributedRequirement::Disabled => BudgetAdmissionDecision::AdmitUnrestricted,
            DistributedRequirement::LocalOnly => BudgetAdmissionDecision::AdmitLocalOnly,
            DistributedRequirement::Required => {
                if state.backend_available() {
                    BudgetAdmissionDecision::AdmitDistributed
                } else {
                    BudgetAdmissionDecision::DenyFailClosed
                }
            }
        }
    }

    /// Convenience wrapper when only a health snapshot is available.
    pub fn admit_budget_reservation_with_snapshot(
        requirement: DistributedRequirement,
        snapshot: BackendHealthSnapshot,
    ) -> BudgetAdmissionDecision {
        let tracker = BackendHealthTracker::new();
        if !snapshot.healthy {
            tracker.record_failure();
        }
        admit_budget_reservation(requirement, &tracker)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn required_fail_closes_when_unhealthy() {
            let health = BackendHealthTracker::new();
            health.record_failure();
            assert_eq!(
                admit_budget_reservation(DistributedRequirement::Required, &health),
                BudgetAdmissionDecision::DenyFailClosed
            );
        }

        #[test]
        fn required_admits_when_healthy() {
            let health = BackendHealthTracker::new();
            assert_eq!(
                admit_budget_reservation(DistributedRequirement::Required, &health),
                BudgetAdmissionDecision::AdmitDistributed
            );
        }

        #[test]
        fn local_only_admits_process_local_budget() {
            let health = BackendHealthTracker::new();
            health.record_failure();
            assert_eq!(
                admit_budget_reservation(DistributedRequirement::LocalOnly, &health),
                BudgetAdmissionDecision::AdmitLocalOnly
            );
            // Required outage must not become LocalOnly.
            assert_ne!(
                DistributedRequirement::Required.after_backend_failure(),
                DistributedRequirement::LocalOnly
            );
        }

        #[test]
        fn disabled_is_unrestricted() {
            let health = BackendHealthTracker::new();
            assert_eq!(
                admit_budget_reservation(DistributedRequirement::Disabled, &health),
                BudgetAdmissionDecision::AdmitUnrestricted
            );
        }

        #[test]
        fn required_needs_two_successes_after_outage() {
            use crate::gateway::distributed_rate_limit::{
                local_only_guarantee_boundary, RECOVERY_SUCCESS_THRESHOLD,
            };
            let health = BackendHealthTracker::new();
            health.record_failure();
            assert_eq!(
                admit_budget_reservation(DistributedRequirement::Required, &health),
                BudgetAdmissionDecision::DenyFailClosed
            );
            let first = health.record_success();
            assert!(!first.healthy);
            assert_eq!(
                admit_budget_reservation(DistributedRequirement::Required, &health),
                BudgetAdmissionDecision::DenyFailClosed
            );
            let second = health.record_success();
            assert!(second.healthy);
            assert_eq!(second.consecutive_successes, RECOVERY_SUCCESS_THRESHOLD);
            assert_eq!(
                admit_budget_reservation(DistributedRequirement::Required, &health),
                BudgetAdmissionDecision::AdmitDistributed
            );
            let boundary = local_only_guarantee_boundary(DistributedRequirement::LocalOnly);
            assert_eq!(
                boundary["runtime_transition_into_local_only_prohibited"],
                true
            );
        }

        #[test]
        fn distributed_state_required_tracks_backend_availability() {
            // Local-only DistributedState construction (no live Redis).
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let local = rt.block_on(async {
                crate::gateway::distributed_state::DistributedState::initialize(
                    None,
                    "redis",
                    DistributedRequirement::LocalOnly,
                )
                .await
                .expect("local-only state")
            });
            assert_eq!(
                admit_budget_for_distributed_state(&local),
                BudgetAdmissionDecision::AdmitLocalOnly
            );
        }
    }
}
