// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Ordered governance stages for [`super::RequestGovernancePipeline`].

/// One stage in the family-neutral request governance pipeline.
///
/// Stages run exactly in [`GOVERNANCE_STAGE_ORDER`]. Downstream family handlers
/// must not reorder, skip, or insert product stages ahead of this contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GovernanceStage {
    Authenticate,
    BindIdentity,
    ResolveFamily,
    EnforceDistributedState,
    ReserveDurableAuditCapacity,
    EvaluateAccessPolicy,
    RunInputPolicy,
    ReserveBudgetFunding,
    DispatchUpstreamOrTool,
    RunOutputPolicy,
    SettleUsage,
    AppendFinalDurableEvidence,
}

impl GovernanceStage {
    /// Stable wire / evidence id for this stage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authenticate => "authenticate",
            Self::BindIdentity => "bind_identity",
            Self::ResolveFamily => "resolve_family",
            Self::EnforceDistributedState => "enforce_required_distributed_state",
            Self::ReserveDurableAuditCapacity => "reserve_durable_audit_capacity",
            Self::EvaluateAccessPolicy => "evaluate_access_policy",
            Self::RunInputPolicy => "run_input_policy",
            Self::ReserveBudgetFunding => "reserve_budget_funding",
            Self::DispatchUpstreamOrTool => "dispatch_upstream_or_tool",
            Self::RunOutputPolicy => "run_output_policy",
            Self::SettleUsage => "settle_usage",
            Self::AppendFinalDurableEvidence => "append_final_durable_evidence",
        }
    }
}

impl std::fmt::Display for GovernanceStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Canonical stage order for every governed proxy request.
pub const GOVERNANCE_STAGE_ORDER: &[GovernanceStage] = &[
    GovernanceStage::Authenticate,
    GovernanceStage::BindIdentity,
    GovernanceStage::ResolveFamily,
    GovernanceStage::EnforceDistributedState,
    GovernanceStage::ReserveDurableAuditCapacity,
    GovernanceStage::EvaluateAccessPolicy,
    GovernanceStage::RunInputPolicy,
    GovernanceStage::ReserveBudgetFunding,
    GovernanceStage::DispatchUpstreamOrTool,
    GovernanceStage::RunOutputPolicy,
    GovernanceStage::SettleUsage,
    GovernanceStage::AppendFinalDurableEvidence,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_stage_order_matches_task_038_contract() {
        assert_eq!(
            GOVERNANCE_STAGE_ORDER
                .iter()
                .map(|stage| stage.as_str())
                .collect::<Vec<_>>(),
            vec![
                "authenticate",
                "bind_identity",
                "resolve_family",
                "enforce_required_distributed_state",
                "reserve_durable_audit_capacity",
                "evaluate_access_policy",
                "run_input_policy",
                "reserve_budget_funding",
                "dispatch_upstream_or_tool",
                "run_output_policy",
                "settle_usage",
                "append_final_durable_evidence",
            ]
        );
    }
}
