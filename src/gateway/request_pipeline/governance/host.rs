// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Host seams invoked by [`super::RequestGovernancePipeline`].
//!
//! The pipeline owns stage ordering and terminal release. Hosts own the real
//! authenticate / policy / dispatch / settle / evidence implementations.

use crate::gateway::identity::{AuthenticatedRequestIdentity, PolicyIdentityContext};
use crate::gateway::request_family_registry::{RegistryEntry, RequestFamily};

use super::adapter::{RawFamilyRequest, ReconstructedFamilyRequest};
use super::error::GovernanceResult;
use super::guards::{AuditCapacityGuard, FundingReservationGuard};
use super::stages::GovernanceStage;

/// Ingress view consumed before family resolution.
#[derive(Debug, Clone)]
pub struct GovernanceRequest {
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Mutable per-request state accumulated across ordered stages.
#[derive(Debug)]
pub struct GovernanceContext {
    pub request: GovernanceRequest,
    pub identity: Option<AuthenticatedRequestIdentity>,
    pub policy_identity: Option<PolicyIdentityContext>,
    pub family: Option<RequestFamily>,
    pub registry_entry: Option<&'static RegistryEntry>,
    pub reconstructed: Option<ReconstructedFamilyRequest>,
    pub dispatch_outcome: Option<DispatchOutcome>,
    pub usage: Option<SettlementUsage>,
    pub stages_completed: Vec<GovernanceStage>,
}

impl GovernanceContext {
    pub fn new(request: GovernanceRequest) -> Self {
        Self {
            request,
            identity: None,
            policy_identity: None,
            family: None,
            registry_entry: None,
            reconstructed: None,
            dispatch_outcome: None,
            usage: None,
            stages_completed: Vec::new(),
        }
    }

    pub fn mark_completed(&mut self, stage: GovernanceStage) {
        self.stages_completed.push(stage);
    }

    pub fn raw_family_request(&self) -> RawFamilyRequest {
        RawFamilyRequest {
            method: self.request.method.clone(),
            path: self.request.path.clone(),
            headers: self.request.headers.clone(),
            body: self.request.body.clone(),
        }
    }
}

/// Access-policy evaluation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessPolicyDecision {
    Allow,
    Deny { reason: String },
}

/// Input-policy evaluation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputPolicyDecision {
    Allow,
    Transform,
    Block { reason: String },
}

/// Output-policy evaluation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputPolicyDecision {
    Allow,
    Redact,
    Block { reason: String },
}

/// Upstream or tool dispatch result carried into post-policy stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchOutcome {
    pub status: u16,
    pub body: Vec<u8>,
    pub upstream_called: bool,
}

/// Normalized usage settled against a funding reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_micros: u64,
}

/// Successful pipeline completion payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceSuccess {
    pub family: RequestFamily,
    pub stages_completed: Vec<GovernanceStage>,
    pub dispatch: DispatchOutcome,
    pub usage: SettlementUsage,
}

/// Host callbacks for each mutable/side-effecting governance stage.
///
/// `resolve_family` is owned by the pipeline (registry authority) and is not a
/// host method. Adapters remain limited to typed extraction/reconstruction.
pub trait GovernanceHost: Send {
    async fn authenticate(
        &mut self,
        ctx: &mut GovernanceContext,
    ) -> GovernanceResult<AuthenticatedRequestIdentity>;

    async fn bind_identity(
        &mut self,
        ctx: &mut GovernanceContext,
        identity: &AuthenticatedRequestIdentity,
    ) -> GovernanceResult<PolicyIdentityContext>;

    async fn enforce_required_distributed_state(
        &mut self,
        ctx: &mut GovernanceContext,
    ) -> GovernanceResult<()>;

    async fn reserve_durable_audit_capacity(
        &mut self,
        ctx: &mut GovernanceContext,
    ) -> GovernanceResult<AuditCapacityGuard>;

    async fn evaluate_access_policy(
        &mut self,
        ctx: &mut GovernanceContext,
    ) -> GovernanceResult<AccessPolicyDecision>;

    async fn run_input_policy(
        &mut self,
        ctx: &mut GovernanceContext,
    ) -> GovernanceResult<InputPolicyDecision>;

    async fn reserve_budget_funding(
        &mut self,
        ctx: &mut GovernanceContext,
    ) -> GovernanceResult<FundingReservationGuard>;

    async fn dispatch_upstream_or_tool(
        &mut self,
        ctx: &mut GovernanceContext,
        request: &ReconstructedFamilyRequest,
    ) -> GovernanceResult<DispatchOutcome>;

    async fn run_output_policy(
        &mut self,
        ctx: &mut GovernanceContext,
        dispatch: &DispatchOutcome,
    ) -> GovernanceResult<OutputPolicyDecision>;

    async fn settle_usage(
        &mut self,
        ctx: &mut GovernanceContext,
        funding: &FundingReservationGuard,
        dispatch: &DispatchOutcome,
    ) -> GovernanceResult<SettlementUsage>;

    async fn append_final_durable_evidence(
        &mut self,
        ctx: &mut GovernanceContext,
        audit: &mut AuditCapacityGuard,
    ) -> GovernanceResult<()>;
}
