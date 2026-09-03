// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! RUNNER-012: Custom harness validation.
//!
//! Custom harnesses supplied in a gateway execution session envelope
//! are controlled by the `allows_custom_harness` boolean flag on the envelope.
//! All execution runs on the customer gateway; the flag determines whether
//! the session may supply a custom harness override or must use the managed
//! Verdictan harness.
//!
//! This module provides:
//! - [`validate_harness`] — the canonical validation entry-point used by both
//!   the gateway executor and the dispatch-time API check.

use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors that can arise from harness validation (RUNNER-012).
#[derive(Debug, Error)]
pub enum HarnessValidationError {
    #[error(
        "custom harness rejected: session does not have allows_custom_harness enabled (RUNNER-012)"
    )]
    CustomHarnessRejected,
}

// ── Validation entry-point ────────────────────────────────────────────────────

/// Validate that a custom harness (if present) is permitted by the session's
/// `allows_custom_harness` flag (RUNNER-012).
///
/// # Arguments
/// * `allows_custom_harness` — whether the session permits custom harness overrides.
/// * `has_custom_harness` — `true` when the envelope carries a
///   [`crate::runner::HarnessSpec`].
///
/// # Errors
/// Returns [`HarnessValidationError::CustomHarnessRejected`] when a custom
/// harness is present but `allows_custom_harness` is `false`.
pub fn validate_harness(
    allows_custom_harness: bool,
    has_custom_harness: bool,
) -> Result<(), HarnessValidationError> {
    if !has_custom_harness {
        return Ok(());
    }

    if allows_custom_harness {
        Ok(())
    } else {
        Err(HarnessValidationError::CustomHarnessRejected)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

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
    fn validate_harness_allows_no_custom_harness() {
        assert!(validate_harness(false, false).is_ok());
    }

    #[test]
    fn validate_harness_allows_no_custom_harness_when_permitted() {
        assert!(validate_harness(true, false).is_ok());
    }

    #[test]
    fn validate_harness_allows_custom_harness_when_permitted() {
        assert!(validate_harness(true, true).is_ok());
    }

    #[test]
    fn validate_harness_rejects_custom_harness_when_not_permitted() {
        let err = validate_harness(false, true).unwrap_err();
        assert!(matches!(err, HarnessValidationError::CustomHarnessRejected));
        assert!(err.to_string().contains("RUNNER-012"));
    }

    #[test]
    fn harness_validation_error_display() {
        let err = HarnessValidationError::CustomHarnessRejected;
        let msg = err.to_string();
        assert!(msg.contains("custom harness rejected"));
        assert!(msg.contains("allows_custom_harness"));
    }
}
