// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

#![allow(clippy::items_after_test_module)]

use std::fmt;

use crate::i18n;

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_USER: i32 = 2;
pub const EXIT_AUTH: i32 = 3;
pub const EXIT_NETWORK: i32 = 4;
pub const EXIT_INTERNAL: i32 = 5;
pub const EXIT_GATEWAY: i32 = 6;

#[derive(Debug)]
pub struct CliError {
    kind: CliErrorKind,
    message: String,
    /// Optional correlation ID from an upstream API error response.
    /// Logged at DEBUG level; never shown in user-facing output.
    pub(crate) correlation_id: Option<String>,
    /// HTTP status code from the upstream API, when available.
    /// Used by retry logic to distinguish transient (502/503) from permanent errors.
    pub(crate) http_status: Option<u16>,
}

#[derive(Debug)]
enum CliErrorKind {
    User,
    Auth,
    Network,
    Internal,
    /// Gateway-specific failures (key validation, config reload, policy enforcement).
    Gateway,
}

impl CliError {
    pub fn user(message: impl Into<String>) -> Self {
        Self {
            kind: CliErrorKind::User,
            message: message.into(),
            correlation_id: None,
            http_status: None,
        }
    }

    pub fn auth(message: impl Into<String>) -> Self {
        Self {
            kind: CliErrorKind::Auth,
            message: message.into(),
            correlation_id: None,
            http_status: None,
        }
    }

    pub fn network(message: impl Into<String>) -> Self {
        Self {
            kind: CliErrorKind::Network,
            message: message.into(),
            correlation_id: None,
            http_status: None,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: CliErrorKind::Internal,
            message: message.into(),
            correlation_id: None,
            http_status: None,
        }
    }

    pub fn gateway(message: impl Into<String>) -> Self {
        Self {
            kind: CliErrorKind::Gateway,
            message: message.into(),
            correlation_id: None,
            http_status: None,
        }
    }

    /// Attach an upstream correlation ID to this error.
    ///
    /// The ID is logged at DEBUG level when the error is displayed; it is never
    /// included in user-facing output to avoid leaking internal identifiers.
    fn with_correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Attach the HTTP status code that caused this error.
    pub fn with_http_status(mut self, status: u16) -> Self {
        self.http_status = Some(status);
        self
    }

    pub fn http_status(&self) -> Option<u16> {
        self.http_status
    }

    pub fn is_auth(&self) -> bool {
        matches!(self.kind, CliErrorKind::Auth)
    }

    pub fn exit_code(&self) -> i32 {
        match self.kind {
            CliErrorKind::User => EXIT_USER,
            CliErrorKind::Auth => EXIT_AUTH,
            CliErrorKind::Network => EXIT_NETWORK,
            CliErrorKind::Internal => EXIT_INTERNAL,
            CliErrorKind::Gateway => EXIT_GATEWAY,
        }
    }

    /// Stable dot-separated error code for this error variant.
    ///
    /// These codes are machine-readable and stable across releases. Use them
    /// for automated error handling, metrics, and structured logging.
    pub fn error_code(&self) -> &'static str {
        match self.kind {
            CliErrorKind::User => "cli.config_invalid",
            CliErrorKind::Auth => "cli.auth_failed",
            CliErrorKind::Network => "cli.network_error",
            CliErrorKind::Internal => "cli.internal",
            CliErrorKind::Gateway => "cli.gateway_error",
        }
    }

    /// Localised prefix for this error kind using the active global locale.
    fn kind_prefix(&self) -> &'static str {
        let locale = i18n::global();
        match self.kind {
            CliErrorKind::User => i18n::t(locale, "error.user"),
            CliErrorKind::Auth => i18n::t(locale, "error.auth"),
            CliErrorKind::Network => i18n::t(locale, "error.network"),
            CliErrorKind::Internal => i18n::t(locale, "error.internal"),
            CliErrorKind::Gateway => i18n::t(locale, "error.gateway"),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref cid) = self.correlation_id {
            tracing::debug!(correlation_id = %cid, error_code = %self.error_code(), "command failure detail");
        }
        let prefix = self.kind_prefix();
        if prefix.is_empty() {
            write!(f, "{}", self.message)
        } else {
            write!(f, "{} {}", prefix, self.message)
        }
    }
}

impl std::error::Error for CliError {}

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

    // ── Constructor tests ───────────────────────────────────────────────

    #[test]
    fn user_error_stores_message() {
        let err = CliError::user("bad input");
        assert_eq!(format!("{err}").contains("bad input"), true);
    }

    #[test]
    fn auth_error_stores_message() {
        let err = CliError::auth("token expired");
        assert_eq!(format!("{err}").contains("token expired"), true);
    }

    #[test]
    fn network_error_stores_message() {
        let err = CliError::network("connection refused");
        assert_eq!(format!("{err}").contains("connection refused"), true);
    }

    #[test]
    fn internal_error_stores_message() {
        let err = CliError::internal("something broke");
        assert_eq!(format!("{err}").contains("something broke"), true);
    }

    #[test]
    fn gateway_error_stores_message() {
        let err = CliError::gateway("key invalid");
        assert_eq!(format!("{err}").contains("key invalid"), true);
    }

    // ── exit_code ──────────────────────────────────────────────────────

    #[test]
    fn exit_code_user() {
        assert_eq!(CliError::user("x").exit_code(), EXIT_USER);
    }

    #[test]
    fn exit_code_auth() {
        assert_eq!(CliError::auth("x").exit_code(), EXIT_AUTH);
    }

    #[test]
    fn exit_code_network() {
        assert_eq!(CliError::network("x").exit_code(), EXIT_NETWORK);
    }

    #[test]
    fn exit_code_internal() {
        assert_eq!(CliError::internal("x").exit_code(), EXIT_INTERNAL);
    }

    #[test]
    fn exit_code_gateway() {
        assert_eq!(CliError::gateway("x").exit_code(), EXIT_GATEWAY);
    }

    // ── error_code ─────────────────────────────────────────────────────

    #[test]
    fn error_code_user() {
        assert_eq!(CliError::user("x").error_code(), "cli.config_invalid");
    }

    #[test]
    fn error_code_auth() {
        assert_eq!(CliError::auth("x").error_code(), "cli.auth_failed");
    }

    #[test]
    fn error_code_network() {
        assert_eq!(CliError::network("x").error_code(), "cli.network_error");
    }

    #[test]
    fn error_code_internal() {
        assert_eq!(CliError::internal("x").error_code(), "cli.internal");
    }

    #[test]
    fn error_code_gateway() {
        assert_eq!(CliError::gateway("x").error_code(), "cli.gateway_error");
    }

    // ── is_auth ────────────────────────────────────────────────────────

    #[test]
    fn is_auth_true_for_auth_error() {
        assert!(CliError::auth("fail").is_auth());
    }

    #[test]
    fn is_auth_false_for_other_kinds() {
        assert!(!CliError::user("x").is_auth());
        assert!(!CliError::network("x").is_auth());
        assert!(!CliError::internal("x").is_auth());
        assert!(!CliError::gateway("x").is_auth());
    }

    // ── builder methods ────────────────────────────────────────────────

    #[test]
    fn with_correlation_id_sets_value() {
        let err = CliError::network("fail").with_correlation_id("abc-123");
        assert_eq!(err.correlation_id.as_deref(), Some("abc-123"));
    }

    #[test]
    fn with_http_status_sets_value() {
        let err = CliError::network("fail").with_http_status(502);
        assert_eq!(err.http_status, Some(502));
    }

    #[test]
    fn builder_methods_chain() {
        let err = CliError::auth("x")
            .with_correlation_id("cid")
            .with_http_status(401);
        assert_eq!(err.correlation_id.as_deref(), Some("cid"));
        assert_eq!(err.http_status, Some(401));
        assert!(err.is_auth());
    }

    #[test]
    fn default_correlation_id_is_none() {
        let err = CliError::user("x");
        assert!(err.correlation_id.is_none());
    }

    #[test]
    fn default_http_status_is_none() {
        let err = CliError::user("x");
        assert!(err.http_status.is_none());
    }

    // ── Display impl ───────────────────────────────────────────────────

    #[test]
    fn display_contains_message() {
        let err = CliError::user("something went wrong");
        let text = format!("{err}");
        assert!(text.contains("something went wrong"));
    }

    #[test]
    fn display_each_kind_contains_message() {
        let cases: [(fn(String) -> CliError, &str); 5] = [
            (|m| CliError::user(m), "user msg"),
            (|m| CliError::auth(m), "auth msg"),
            (|m| CliError::network(m), "net msg"),
            (|m| CliError::internal(m), "int msg"),
            (|m| CliError::gateway(m), "gw msg"),
        ];
        for (kind_fn, msg) in cases {
            let err = kind_fn(msg.to_string());
            assert!(
                format!("{err}").contains(msg),
                "Display for error did not contain '{msg}'"
            );
        }
    }

    // ── std::error::Error trait ─────────────────────────────────────────

    #[test]
    fn implements_std_error() {
        let err = CliError::user("test");
        let _: &dyn std::error::Error = &err;
    }

    // ── Debug impl ─────────────────────────────────────────────────────

    #[test]
    fn debug_is_not_empty() {
        let err = CliError::internal("debug test");
        let debug = format!("{err:?}");
        assert!(!debug.is_empty());
    }

    // ── exit code constants ─────────────────────────────────────────────

    #[test]
    fn exit_code_constants_are_distinct() {
        let codes = [
            EXIT_SUCCESS,
            EXIT_USER,
            EXIT_AUTH,
            EXIT_NETWORK,
            EXIT_INTERNAL,
            EXIT_GATEWAY,
        ];
        for (i, a) in codes.iter().enumerate() {
            for (j, b) in codes.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "exit codes at index {i} and {j} collide");
                }
            }
        }
    }

    #[test]
    fn exit_success_is_zero() {
        assert_eq!(EXIT_SUCCESS, 0);
    }

    // ── From<anyhow::Error> ─────────────────────────────────────────────

    #[test]
    fn from_anyhow_produces_internal_error() {
        let anyhow_err = anyhow::anyhow!("unexpected failure");
        let cli_err: CliError = anyhow_err.into();
        assert_eq!(cli_err.exit_code(), EXIT_INTERNAL);
        assert_eq!(cli_err.error_code(), "cli.internal");
    }

    #[test]
    fn from_anyhow_sanitizes_reqwest_message() {
        let anyhow_err = anyhow::anyhow!("error sending request for url");
        let cli_err: CliError = anyhow_err.into();
        let text = format!("{cli_err}");
        assert!(
            text.contains("network request failed"),
            "expected sanitized message, got: {text}"
        );
        assert!(!text.contains("error sending request"));
    }

    #[test]
    fn from_anyhow_sanitizes_hyper_message() {
        let anyhow_err = anyhow::anyhow!("hyper::Error(...)");
        let cli_err: CliError = anyhow_err.into();
        let text = format!("{cli_err}");
        assert!(text.contains("network request failed"));
    }

    #[test]
    fn from_anyhow_sanitizes_connection_refused() {
        let anyhow_err = anyhow::anyhow!("connection refused");
        let cli_err: CliError = anyhow_err.into();
        let text = format!("{cli_err}");
        assert!(text.contains("network request failed"));
    }

    #[test]
    fn from_anyhow_sanitizes_timed_out() {
        let anyhow_err = anyhow::anyhow!("operation timed out");
        let cli_err: CliError = anyhow_err.into();
        let text = format!("{cli_err}");
        assert!(text.contains("network request failed"));
    }

    #[test]
    fn from_anyhow_preserves_non_network_message() {
        let anyhow_err = anyhow::anyhow!("config file not found");
        let cli_err: CliError = anyhow_err.into();
        let text = format!("{cli_err}");
        assert!(text.contains("config file not found"));
    }
}

impl From<anyhow::Error> for CliError {
    fn from(err: anyhow::Error) -> Self {
        // Log the full error chain at DEBUG so operators can diagnose with
        // RUST_LOG=debug without exposing internal paths or raw library errors
        // to normal user output.
        tracing::debug!(error = %err, "internal error detail");

        let message = err.to_string();

        // Sanitize: replace raw network/library error strings with stable,
        // user-friendly messages that do not expose internal URLs, Rust types,
        // or implementation details.
        let sanitized = if message.contains("error sending request")
            || message.contains("reqwest::")
            || message.contains("hyper::")
            || message.contains("connection refused")
            || message.contains("connection reset")
            || message.contains("timed out")
        {
            "network request failed; check connectivity and API URL".to_string()
        } else {
            message
        };

        CliError::internal(sanitized)
    }
}
