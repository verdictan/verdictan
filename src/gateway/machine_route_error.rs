// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Error classification for gateway machine route responses.
//!
//! Implements the CLI caller contract from ADR-007: service-token authentication,
//! tenant binding, and structured diagnostics for machine route failures.
//!
//! Contract requirements:
//! - 401 → report gateway service-token authentication/configuration failure.
//! - 403 or tenant-safe 404 → report authorization or tenant-binding failure.
//! - The CLI MUST NOT retry a rejected machine call with a different `org_id`.

use reqwest::StatusCode;

/// Classification of a machine route error response per ADR-007.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MachineRouteFailure {
    /// 401: service token is missing, blank, malformed, expired, or revoked.
    ServiceTokenAuthFailure,
    /// 403/404: valid token but org mismatch, missing gateway authorization,
    /// or tenant-safe not-found.
    TenantBindingFailure,
    /// Any other non-2xx status.
    Other,
}

impl MachineRouteFailure {
    /// Classify a non-success HTTP status code from a machine route response.
    pub(crate) fn from_status(status: StatusCode) -> Self {
        match status.as_u16() {
            401 => Self::ServiceTokenAuthFailure,
            403 | 404 => Self::TenantBindingFailure,
            _ => Self::Other,
        }
    }

    /// A human-readable diagnostic string suitable for tracing and error messages.
    pub(crate) fn diagnostic(self) -> &'static str {
        match self {
            Self::ServiceTokenAuthFailure => {
                "gateway service-token authentication/configuration failure (401)"
            }
            Self::TenantBindingFailure => {
                "gateway authorization or tenant-binding failure (403/404)"
            }
            Self::Other => "gateway machine route request failed",
        }
    }
}

/// Log a structured machine route error and return a formatted error string.
///
/// This helper centralizes the ADR-007 contract error reporting so that all
/// machine route callers produce consistent diagnostics.
pub(crate) fn classify_and_format(route_family: &str, status: StatusCode, body: &str) -> String {
    let failure = MachineRouteFailure::from_status(status);
    let diagnostic = failure.diagnostic();

    match failure {
        MachineRouteFailure::ServiceTokenAuthFailure => {
            tracing::error!(
                route_family = %route_family,
                status = %status,
                diagnostic = %diagnostic,
                "machine route auth failure: check VERDICTAN_API_TOKEN configuration"
            );
        }
        MachineRouteFailure::TenantBindingFailure => {
            tracing::error!(
                route_family = %route_family,
                status = %status,
                diagnostic = %diagnostic,
                "machine route tenant/authz failure: org_id may not match token owner"
            );
        }
        MachineRouteFailure::Other => {
            tracing::warn!(
                route_family = %route_family,
                status = %status,
                "machine route non-2xx response"
            );
        }
    }

    format!("{route_family}: {diagnostic} — status={status} body={body}")
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
    fn classify_401_as_service_token_failure() {
        let f = MachineRouteFailure::from_status(StatusCode::UNAUTHORIZED);
        assert_eq!(f, MachineRouteFailure::ServiceTokenAuthFailure);
        assert!(f.diagnostic().contains("service-token"));
        assert!(f.diagnostic().contains("401"));
    }

    #[test]
    fn classify_403_as_tenant_binding_failure() {
        let f = MachineRouteFailure::from_status(StatusCode::FORBIDDEN);
        assert_eq!(f, MachineRouteFailure::TenantBindingFailure);
        assert!(f.diagnostic().contains("tenant-binding"));
    }

    #[test]
    fn classify_404_as_tenant_binding_failure() {
        let f = MachineRouteFailure::from_status(StatusCode::NOT_FOUND);
        assert_eq!(f, MachineRouteFailure::TenantBindingFailure);
        assert!(f.diagnostic().contains("403/404"));
    }

    #[test]
    fn classify_500_as_other() {
        let f = MachineRouteFailure::from_status(StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(f, MachineRouteFailure::Other);
    }

    #[test]
    fn format_includes_route_family_and_status() {
        let msg = classify_and_format(
            "agent-context/resolve",
            StatusCode::UNAUTHORIZED,
            r#"{"error":"unauthorized"}"#,
        );
        assert!(msg.contains("agent-context/resolve"));
        assert!(msg.contains("401"));
        assert!(msg.contains("service-token"));
    }

    #[test]
    fn format_403_includes_tenant_diagnostic() {
        let msg = classify_and_format(
            "citations/memory",
            StatusCode::FORBIDDEN,
            r#"{"error":"forbidden"}"#,
        );
        assert!(msg.contains("tenant-binding"));
        assert!(msg.contains("403"));
    }
}
