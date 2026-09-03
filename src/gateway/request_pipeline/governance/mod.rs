// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Family-neutral request governance pipeline.
//!
//! [`RequestGovernancePipeline`] runs ordered stages shared by every registered
//! request family. Family adapters implement typed extraction and
//! reconstruction only; side-effecting stages go through [`GovernanceHost`].
//! Unused durable-audit capacity and funding reservations release on every
//! terminal path via Drop guards.

mod adapter;
mod error;
mod guards;
mod host;
mod pipeline;
mod stages;

// Re-exports are the stable surface. The parent `request_pipeline`
// module is private under `server`, so these symbols may not yet have crate
// consumers until later lanes wire handlers; keep them public intentionally.
#[allow(unused_imports)]
pub use adapter::{
    FamilyRequestAdapter, JsonBodyAdapter, RawFamilyRequest, ReconstructedFamilyRequest,
};
#[allow(unused_imports)]
pub use error::{GovernanceError, GovernanceResult};
#[allow(unused_imports)]
pub use guards::{AuditCapacityGuard, FundingReservationGuard};
#[allow(unused_imports)]
pub use host::{
    AccessPolicyDecision, DispatchOutcome, GovernanceContext, GovernanceHost, GovernanceRequest,
    GovernanceSuccess, InputPolicyDecision, OutputPolicyDecision, SettlementUsage,
};
#[allow(unused_imports)]
pub use pipeline::RequestGovernancePipeline;
#[allow(unused_imports)]
pub use stages::{GovernanceStage, GOVERNANCE_STAGE_ORDER};
