// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Family-neutral ordered request governance pipeline.

use crate::gateway::request_family_registry::{resolve_entry, RequestFamily};

use super::adapter::FamilyRequestAdapter;
use super::error::{GovernanceError, GovernanceResult};
use super::guards::{AuditCapacityGuard, FundingReservationGuard};
use super::host::{
    AccessPolicyDecision, GovernanceContext, GovernanceHost, GovernanceRequest, GovernanceSuccess,
    InputPolicyDecision, OutputPolicyDecision,
};
use super::stages::{GovernanceStage, GOVERNANCE_STAGE_ORDER};

/// Runs the ordered governance stages for one proxy request.
///
/// Adapters perform typed extraction/reconstruction only. All side-effecting
/// stages go through [`GovernanceHost`]. Unused audit capacity and funding
/// reservations are released on every terminal path via Drop guards.
pub struct RequestGovernancePipeline;

impl RequestGovernancePipeline {
    /// Execute the full ordered stage sequence for `request`.
    pub async fn execute<H, A>(
        host: &mut H,
        adapter: &A,
        request: GovernanceRequest,
    ) -> GovernanceResult<GovernanceSuccess>
    where
        H: GovernanceHost,
        A: FamilyRequestAdapter,
    {
        let mut ctx = GovernanceContext::new(request);
        let mut audit_guard: Option<AuditCapacityGuard> = None;
        let mut funding_guard: Option<FundingReservationGuard> = None;

        let result = Self::run_stages(
            host,
            adapter,
            &mut ctx,
            &mut audit_guard,
            &mut funding_guard,
        )
        .await;

        // Terminal release: Drop releases unused capacity/funding even when the
        // caller discards these Options after an early Err return.
        drop(funding_guard);
        drop(audit_guard);

        result
    }

    async fn run_stages<H, A>(
        host: &mut H,
        adapter: &A,
        ctx: &mut GovernanceContext,
        audit_guard: &mut Option<AuditCapacityGuard>,
        funding_guard: &mut Option<FundingReservationGuard>,
    ) -> GovernanceResult<GovernanceSuccess>
    where
        H: GovernanceHost,
        A: FamilyRequestAdapter,
    {
        debug_assert_eq!(
            GOVERNANCE_STAGE_ORDER.first().copied(),
            Some(GovernanceStage::Authenticate)
        );

        // 1. authenticate
        let identity = host
            .authenticate(ctx)
            .await
            .map_err(|error| annotate_stage(GovernanceStage::Authenticate, error))?;
        ctx.identity = Some(identity.clone());
        ctx.mark_completed(GovernanceStage::Authenticate);

        // 2. bind identity
        let policy_identity = host
            .bind_identity(ctx, &identity)
            .await
            .map_err(|error| annotate_stage(GovernanceStage::BindIdentity, error))?;
        ctx.policy_identity = Some(policy_identity);
        ctx.mark_completed(GovernanceStage::BindIdentity);

        // 3. resolve family (registry authority; not adapter-owned)
        let entry = resolve_entry(&ctx.request.method, &ctx.request.path).ok_or_else(|| {
            GovernanceError::at_stage(
                GovernanceStage::ResolveFamily,
                "governance.unknown_family",
                format!(
                    "no registry entry for {} {}",
                    ctx.request.method, ctx.request.path
                ),
            )
        })?;
        if entry.family != adapter.family() {
            return Err(GovernanceError::at_stage(
                GovernanceStage::ResolveFamily,
                "governance.family_adapter_mismatch",
                format!(
                    "adapter family {} does not match registry family {}",
                    adapter.family().as_str(),
                    entry.family.as_str()
                ),
            ));
        }
        ctx.family = Some(entry.family);
        ctx.registry_entry = Some(entry);
        ctx.mark_completed(GovernanceStage::ResolveFamily);

        // Adapter typed extraction only (no policy / side effects).
        let raw = ctx.raw_family_request();
        let extracted = adapter
            .extract(&raw)
            .map_err(|error| annotate_stage(GovernanceStage::ResolveFamily, error))?;

        // 4. enforce required distributed state
        host.enforce_required_distributed_state(ctx)
            .await
            .map_err(|error| annotate_stage(GovernanceStage::EnforceDistributedState, error))?;
        ctx.mark_completed(GovernanceStage::EnforceDistributedState);

        // 5. reserve durable audit capacity
        let audit = host
            .reserve_durable_audit_capacity(ctx)
            .await
            .map_err(|error| annotate_stage(GovernanceStage::ReserveDurableAuditCapacity, error))?;
        *audit_guard = Some(audit);
        ctx.mark_completed(GovernanceStage::ReserveDurableAuditCapacity);

        // 6. evaluate access policy
        match host
            .evaluate_access_policy(ctx)
            .await
            .map_err(|error| annotate_stage(GovernanceStage::EvaluateAccessPolicy, error))?
        {
            AccessPolicyDecision::Allow => {}
            AccessPolicyDecision::Deny { reason } => {
                return Err(GovernanceError::at_stage(
                    GovernanceStage::EvaluateAccessPolicy,
                    "governance.access_denied",
                    reason,
                ));
            }
        }
        ctx.mark_completed(GovernanceStage::EvaluateAccessPolicy);

        // 7. run input policy
        match host
            .run_input_policy(ctx)
            .await
            .map_err(|error| annotate_stage(GovernanceStage::RunInputPolicy, error))?
        {
            InputPolicyDecision::Allow | InputPolicyDecision::Transform => {}
            InputPolicyDecision::Block { reason } => {
                return Err(GovernanceError::at_stage(
                    GovernanceStage::RunInputPolicy,
                    "governance.input_blocked",
                    reason,
                ));
            }
        }
        ctx.mark_completed(GovernanceStage::RunInputPolicy);

        // 8. reserve budget/funding
        let funding = host
            .reserve_budget_funding(ctx)
            .await
            .map_err(|error| annotate_stage(GovernanceStage::ReserveBudgetFunding, error))?;
        *funding_guard = Some(funding);
        ctx.mark_completed(GovernanceStage::ReserveBudgetFunding);

        // Adapter typed reconstruction only, immediately before dispatch.
        let reconstructed = adapter
            .reconstruct(&extracted, &raw)
            .map_err(|error| annotate_stage(GovernanceStage::DispatchUpstreamOrTool, error))?;
        ctx.reconstructed = Some(reconstructed.clone());

        // 9. dispatch upstream/tool
        let dispatch = host
            .dispatch_upstream_or_tool(ctx, &reconstructed)
            .await
            .map_err(|error| annotate_stage(GovernanceStage::DispatchUpstreamOrTool, error))?;
        ctx.dispatch_outcome = Some(dispatch.clone());
        ctx.mark_completed(GovernanceStage::DispatchUpstreamOrTool);

        // 10. run output policy
        match host
            .run_output_policy(ctx, &dispatch)
            .await
            .map_err(|error| annotate_stage(GovernanceStage::RunOutputPolicy, error))?
        {
            OutputPolicyDecision::Allow | OutputPolicyDecision::Redact => {}
            OutputPolicyDecision::Block { reason } => {
                return Err(GovernanceError::at_stage(
                    GovernanceStage::RunOutputPolicy,
                    "governance.output_blocked",
                    reason,
                ));
            }
        }
        ctx.mark_completed(GovernanceStage::RunOutputPolicy);

        // 11. settle usage
        let Some(funding_ref) = funding_guard.as_ref() else {
            return Err(annotate_stage(
                GovernanceStage::SettleUsage,
                GovernanceError::at_stage(
                    GovernanceStage::SettleUsage,
                    "governance.internal",
                    "funding reservation missing before settle",
                ),
            ));
        };
        let usage = host
            .settle_usage(ctx, funding_ref, &dispatch)
            .await
            .map_err(|error| annotate_stage(GovernanceStage::SettleUsage, error))?;
        if let Some(funding) = funding_guard.as_ref() {
            funding.mark_settled();
        }
        ctx.usage = Some(usage.clone());
        ctx.mark_completed(GovernanceStage::SettleUsage);

        // 12. append final durable evidence
        let Some(audit_mut) = audit_guard.as_mut() else {
            return Err(annotate_stage(
                GovernanceStage::AppendFinalDurableEvidence,
                GovernanceError::at_stage(
                    GovernanceStage::AppendFinalDurableEvidence,
                    "governance.internal",
                    "audit capacity missing before final evidence",
                ),
            ));
        };
        host.append_final_durable_evidence(ctx, audit_mut)
            .await
            .map_err(|error| annotate_stage(GovernanceStage::AppendFinalDurableEvidence, error))?;
        ctx.mark_completed(GovernanceStage::AppendFinalDurableEvidence);

        let family = ctx.family.unwrap_or(RequestFamily::ChatCompletions);
        Ok(GovernanceSuccess {
            family,
            stages_completed: ctx.stages_completed.clone(),
            dispatch,
            usage,
        })
    }
}

fn annotate_stage(stage: GovernanceStage, mut error: GovernanceError) -> GovernanceError {
    if error.stage.is_none() {
        error.stage = Some(stage);
    }
    error
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use crate::gateway::identity::{
        AuthenticatedIdentityClaims, AuthenticatedRequestIdentity, IdentityAssuranceLevel,
        IdentityProofMethod, PolicyIdentityContext,
    };
    use crate::gateway::request_family_registry::RequestFamily;

    use super::super::adapter::JsonBodyAdapter;
    use super::super::guards::{AuditCapacityGuard, FundingReservationGuard};
    use super::super::host::{DispatchOutcome, SettlementUsage};
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FailAt {
        None,
        Authenticate,
        BindIdentity,
        DistributedState,
        ReserveAudit,
        AccessPolicy,
        InputPolicy,
        ReserveFunding,
        Dispatch,
        OutputPolicy,
        Settle,
        FinalEvidence,
    }

    struct RecordingHost {
        fail_at: FailAt,
        observed: Arc<std::sync::Mutex<Vec<&'static str>>>,
        audit_releases: Arc<AtomicUsize>,
        funding_releases: Arc<AtomicUsize>,
    }

    impl RecordingHost {
        fn new(fail_at: FailAt) -> Self {
            Self {
                fail_at,
                observed: Arc::new(std::sync::Mutex::new(Vec::new())),
                audit_releases: Arc::new(AtomicUsize::new(0)),
                funding_releases: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn record(&self, stage: &'static str) {
            self.observed.lock().expect("lock").push(stage);
        }

        fn stages(&self) -> Vec<&'static str> {
            self.observed.lock().expect("lock").clone()
        }
    }

    fn test_identity() -> AuthenticatedRequestIdentity {
        AuthenticatedRequestIdentity::from_validated_claims(AuthenticatedIdentityClaims {
            proof_method: IdentityProofMethod::ApiToken,
            issuer: "https://issuer.test".into(),
            subject: "user-1".into(),
            credential_id: "cred-1".into(),
            org_id: "org-1".into(),
            team_ids: vec!["team-1".into()],
            roles: vec!["operator".into()],
            scopes: vec!["gateway:invoke".into()],
            assurance_level: IdentityAssuranceLevel::SingleFactor,
            expires_at: None,
        })
        .expect("identity")
    }

    impl GovernanceHost for RecordingHost {
        async fn authenticate(
            &mut self,
            _ctx: &mut GovernanceContext,
        ) -> GovernanceResult<AuthenticatedRequestIdentity> {
            self.record("authenticate");
            if self.fail_at == FailAt::Authenticate {
                return Err(GovernanceError::at_stage(
                    GovernanceStage::Authenticate,
                    "test.auth_failed",
                    "forced authenticate failure",
                ));
            }
            Ok(test_identity())
        }

        async fn bind_identity(
            &mut self,
            _ctx: &mut GovernanceContext,
            identity: &AuthenticatedRequestIdentity,
        ) -> GovernanceResult<PolicyIdentityContext> {
            self.record("bind_identity");
            if self.fail_at == FailAt::BindIdentity {
                return Err(GovernanceError::at_stage(
                    GovernanceStage::BindIdentity,
                    "test.bind_failed",
                    "forced bind failure",
                ));
            }
            Ok(PolicyIdentityContext::from(identity))
        }

        async fn enforce_required_distributed_state(
            &mut self,
            _ctx: &mut GovernanceContext,
        ) -> GovernanceResult<()> {
            self.record("enforce_required_distributed_state");
            if self.fail_at == FailAt::DistributedState {
                return Err(GovernanceError::at_stage(
                    GovernanceStage::EnforceDistributedState,
                    "test.distributed_failed",
                    "forced distributed-state failure",
                ));
            }
            Ok(())
        }

        async fn reserve_durable_audit_capacity(
            &mut self,
            _ctx: &mut GovernanceContext,
        ) -> GovernanceResult<AuditCapacityGuard> {
            self.record("reserve_durable_audit_capacity");
            if self.fail_at == FailAt::ReserveAudit {
                return Err(GovernanceError::at_stage(
                    GovernanceStage::ReserveDurableAuditCapacity,
                    "test.audit_reserve_failed",
                    "forced audit reserve failure",
                ));
            }
            Ok(AuditCapacityGuard::with_counter(
                Arc::clone(&self.audit_releases),
                || {},
            ))
        }

        async fn evaluate_access_policy(
            &mut self,
            _ctx: &mut GovernanceContext,
        ) -> GovernanceResult<AccessPolicyDecision> {
            self.record("evaluate_access_policy");
            if self.fail_at == FailAt::AccessPolicy {
                return Ok(AccessPolicyDecision::Deny {
                    reason: "forced access deny".into(),
                });
            }
            Ok(AccessPolicyDecision::Allow)
        }

        async fn run_input_policy(
            &mut self,
            _ctx: &mut GovernanceContext,
        ) -> GovernanceResult<InputPolicyDecision> {
            self.record("run_input_policy");
            if self.fail_at == FailAt::InputPolicy {
                return Ok(InputPolicyDecision::Block {
                    reason: "forced input block".into(),
                });
            }
            Ok(InputPolicyDecision::Allow)
        }

        async fn reserve_budget_funding(
            &mut self,
            _ctx: &mut GovernanceContext,
        ) -> GovernanceResult<FundingReservationGuard> {
            self.record("reserve_budget_funding");
            if self.fail_at == FailAt::ReserveFunding {
                return Err(GovernanceError::at_stage(
                    GovernanceStage::ReserveBudgetFunding,
                    "test.funding_reserve_failed",
                    "forced funding reserve failure",
                ));
            }
            Ok(FundingReservationGuard::with_counter(
                Arc::clone(&self.funding_releases),
                || {},
            ))
        }

        async fn dispatch_upstream_or_tool(
            &mut self,
            _ctx: &mut GovernanceContext,
            _request: &super::super::adapter::ReconstructedFamilyRequest,
        ) -> GovernanceResult<DispatchOutcome> {
            self.record("dispatch_upstream_or_tool");
            if self.fail_at == FailAt::Dispatch {
                return Err(GovernanceError::at_stage(
                    GovernanceStage::DispatchUpstreamOrTool,
                    "test.dispatch_failed",
                    "forced dispatch failure",
                ));
            }
            Ok(DispatchOutcome {
                status: 200,
                body: br#"{"ok":true}"#.to_vec(),
                upstream_called: true,
            })
        }

        async fn run_output_policy(
            &mut self,
            _ctx: &mut GovernanceContext,
            _dispatch: &DispatchOutcome,
        ) -> GovernanceResult<OutputPolicyDecision> {
            self.record("run_output_policy");
            if self.fail_at == FailAt::OutputPolicy {
                return Ok(OutputPolicyDecision::Block {
                    reason: "forced output block".into(),
                });
            }
            Ok(OutputPolicyDecision::Allow)
        }

        async fn settle_usage(
            &mut self,
            _ctx: &mut GovernanceContext,
            _funding: &FundingReservationGuard,
            _dispatch: &DispatchOutcome,
        ) -> GovernanceResult<SettlementUsage> {
            self.record("settle_usage");
            if self.fail_at == FailAt::Settle {
                return Err(GovernanceError::at_stage(
                    GovernanceStage::SettleUsage,
                    "test.settle_failed",
                    "forced settle failure",
                ));
            }
            Ok(SettlementUsage {
                input_tokens: 3,
                output_tokens: 5,
                cost_micros: 42,
            })
        }

        async fn append_final_durable_evidence(
            &mut self,
            _ctx: &mut GovernanceContext,
            _audit: &mut AuditCapacityGuard,
        ) -> GovernanceResult<()> {
            self.record("append_final_durable_evidence");
            if self.fail_at == FailAt::FinalEvidence {
                return Err(GovernanceError::at_stage(
                    GovernanceStage::AppendFinalDurableEvidence,
                    "test.evidence_failed",
                    "forced evidence failure",
                ));
            }
            Ok(())
        }
    }

    fn sample_request() -> GovernanceRequest {
        GovernanceRequest {
            request_id: "req-test-1".into(),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"model":"gpt-test","messages":[]}"#.to_vec(),
        }
    }

    #[tokio::test]
    async fn ordered_stages_run_to_completion() {
        let mut host = RecordingHost::new(FailAt::None);
        let adapter = JsonBodyAdapter::new(RequestFamily::ChatCompletions);
        let success = RequestGovernancePipeline::execute(&mut host, &adapter, sample_request())
            .await
            .expect("pipeline success");

        assert_eq!(
            host.stages(),
            vec![
                "authenticate",
                "bind_identity",
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
        assert_eq!(
            success
                .stages_completed
                .iter()
                .map(|stage| stage.as_str())
                .collect::<Vec<_>>(),
            GOVERNANCE_STAGE_ORDER
                .iter()
                .map(|stage| stage.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(success.family, RequestFamily::ChatCompletions);
        assert!(success.dispatch.upstream_called);
        // Successful settle consumes funding; unused audit capacity still releases once.
        assert_eq!(host.funding_releases.load(Ordering::SeqCst), 0);
        assert_eq!(host.audit_releases.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn terminal_release_after_access_deny_releases_audit_only() {
        let mut host = RecordingHost::new(FailAt::AccessPolicy);
        let adapter = JsonBodyAdapter::new(RequestFamily::ChatCompletions);
        let err = RequestGovernancePipeline::execute(&mut host, &adapter, sample_request())
            .await
            .expect_err("access deny");
        assert_eq!(err.code, "governance.access_denied");
        assert_eq!(host.audit_releases.load(Ordering::SeqCst), 1);
        assert_eq!(host.funding_releases.load(Ordering::SeqCst), 0);
        assert!(!host.stages().contains(&"dispatch_upstream_or_tool"));
    }

    #[tokio::test]
    async fn terminal_release_after_dispatch_failure_releases_audit_and_funding() {
        let mut host = RecordingHost::new(FailAt::Dispatch);
        let adapter = JsonBodyAdapter::new(RequestFamily::ChatCompletions);
        let err = RequestGovernancePipeline::execute(&mut host, &adapter, sample_request())
            .await
            .expect_err("dispatch fail");
        assert_eq!(err.code, "test.dispatch_failed");
        assert_eq!(host.audit_releases.load(Ordering::SeqCst), 1);
        assert_eq!(host.funding_releases.load(Ordering::SeqCst), 1);
        assert!(!host.stages().contains(&"settle_usage"));
    }

    #[tokio::test]
    async fn terminal_release_after_output_block_releases_funding() {
        let mut host = RecordingHost::new(FailAt::OutputPolicy);
        let adapter = JsonBodyAdapter::new(RequestFamily::ChatCompletions);
        let err = RequestGovernancePipeline::execute(&mut host, &adapter, sample_request())
            .await
            .expect_err("output block");
        assert_eq!(err.code, "governance.output_blocked");
        assert_eq!(host.audit_releases.load(Ordering::SeqCst), 1);
        assert_eq!(host.funding_releases.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pre_audit_failure_releases_neither_guard() {
        let mut host = RecordingHost::new(FailAt::DistributedState);
        let adapter = JsonBodyAdapter::new(RequestFamily::ChatCompletions);
        let err = RequestGovernancePipeline::execute(&mut host, &adapter, sample_request())
            .await
            .expect_err("distributed fail");
        assert_eq!(err.code, "test.distributed_failed");
        assert_eq!(host.audit_releases.load(Ordering::SeqCst), 0);
        assert_eq!(host.funding_releases.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unknown_family_fails_before_distributed_and_dispatch() {
        let mut host = RecordingHost::new(FailAt::None);
        let adapter = JsonBodyAdapter::new(RequestFamily::ChatCompletions);
        let mut request = sample_request();
        request.path = "/v1/not-a-family".into();
        let err = RequestGovernancePipeline::execute(&mut host, &adapter, request)
            .await
            .expect_err("unknown family");
        assert_eq!(err.code, "governance.unknown_family");
        assert_eq!(host.stages(), vec!["authenticate", "bind_identity"]);
        assert_eq!(host.audit_releases.load(Ordering::SeqCst), 0);
        assert_eq!(host.funding_releases.load(Ordering::SeqCst), 0);
    }
}
