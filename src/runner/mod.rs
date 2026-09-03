// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Gateway execution domain types for `verdictan` gateway deployments.
//!
//! This module provides the canonical, well-typed DTOs for all gateway-execution-related
//! gateway↔control-plane communication, organised by RUNNER implementation item:
//!
//! | Sub-module | RUNNER item | Responsibility |
//! |------------|-------------|----------------|
//! | [`envelope`] | RUNNER-010 | Session dispatch envelope: targeting, permission grants, identity context, harness spec |
//! | [`harness`] | RUNNER-012 | Custom harness validation: only sessions with `allows_custom_harness = true` may supply a custom harness |
//!
//! ## Usage
//!
//! The gateway execution executor in [`crate::gateway::runner`] implements the
//! full execution lifecycle using these types. The `runner/` module provides
//! the public-facing surface; `gateway/runner.rs` provides the HTTP transport
//! and Tokio task management.
//!
//! ```rust,ignore
//! use crate::runner::{
//!     envelope::RunnerSessionEnvelope,
//!     harness::validate_harness,
//! };
//!
//! // Validate a custom harness before accepting the session (RUNNER-012).
//! validate_harness(envelope.allows_custom_harness, envelope.harness.is_some)?;
//! ```

pub mod envelope;
pub mod harness;

// ── Convenience re-exports ────────────────────────────────────────────────────

// RUNNER-010
pub(crate) use envelope::RunnerPermissionGrant;

// RUNNER-012
pub(crate) use harness::HarnessValidationError;
