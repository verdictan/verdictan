// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Contract-absence guard and retired-name inventory for the removed
//! provider-access surface.
//!
//! Provider access is BYOK only. The gateway resolves a customer-owned
//! credential and never accepts a platform-supplied one.
//!
//! This module names the removed material, so it holds retired literals on
//! purpose. Keep every other active module free of those literals. A validator
//! or an absence test that must name a retired field reads the inventory from
//! this module instead of repeating the literal.

/// Provider-bundle fields that an older control plane can send to request
/// platform-managed provider access. The gateway rejects the same fields that
/// the API rejects.
pub(crate) const REMOVED_MANAGED_ACCESS_FIELDS: [&str; 2] = ["use_byok", "allow_managed_fallback"];

/// Access-preflight request fields that let a caller ask for a platform
/// credential. The BYOK contract carries none of them.
#[cfg(test)]
pub(crate) const REMOVED_PREFLIGHT_REQUEST_FIELDS: [&str; 2] =
    ["prefer_byok", "allow_managed_fallback"];

/// The retired ready state. `ready_byok` is the only ready state that access
/// preflight returns, so a client must reject this value.
#[cfg(test)]
pub(crate) const REMOVED_PREFLIGHT_READY_STATE: &str = "ready_managed";

/// Completion-envelope fields that reported platform credential-vault reuse.
#[cfg(test)]
pub(crate) const REMOVED_COMPLETION_FIELDS: [&str; 1] = ["credential_vault_cache_record"];
