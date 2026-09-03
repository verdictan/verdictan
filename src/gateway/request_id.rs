// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use crate::error::CliError;
use sha2::{Digest, Sha256};

/// Maximum length, in bytes, of a valid request identifier after trimming.
pub const MAX_REQUEST_ID_LEN: usize = 128;

/// Error returned when a caller-supplied `X-Request-Id` is present but does not
/// satisfy the usage-authorization request-id grammar. Callers translate this
/// into an HTTP 400 rather than silently truncating or replacing the caller's
/// value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidRequestId {
    pub reason: &'static str,
}

impl std::fmt::Display for InvalidRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason)
    }
}

impl std::error::Error for InvalidRequestId {}

/// Returns `true` when `s` matches the usage-authorization request-id grammar:
/// 1-128 ASCII letters or digits, or the punctuation `-`, `_`, `.`, `:`. This
/// mirrors the authoritative API validator
/// (`api/src/domains/gateway/usage_authorization_contract.rs`) so a locally
/// accepted id is never rejected by the control-plane authorization contract's
/// `deny_unknown_fields` body.
pub fn is_valid_request_id(s: &str) -> bool {
    let len = s.len();
    (1..=MAX_REQUEST_ID_LEN).contains(&len)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b':')
}

/// Validates a caller-supplied `X-Request-Id` header value.
///
/// - An absent header, or one that is only ASCII whitespace, yields a freshly
///   generated valid identifier. This is the only case that mints a new id.
/// - A present, non-empty value is trimmed of surrounding ASCII whitespace and
///   accepted only when it satisfies [`is_valid_request_id`]; otherwise an
///   [`InvalidRequestId`] error is returned so the caller can reject the request
///   with HTTP 400 instead of truncating or replacing the caller's identifier.
pub fn validate_or_generate_x_request_id(
    header_value: Option<&str>,
) -> Result<String, InvalidRequestId> {
    let Some(raw) = header_value else {
        return Ok(uuid::Uuid::new_v4().to_string());
    };
    let trimmed = raw.trim_matches(|c: char| c.is_ascii_whitespace());
    if trimmed.is_empty() {
        return Ok(uuid::Uuid::new_v4().to_string());
    }
    if !is_valid_request_id(trimmed) {
        return Err(InvalidRequestId {
            reason: "X-Request-Id must be 1-128 ASCII letters, digits, or -_.: characters",
        });
    }
    Ok(trimmed.to_string())
}

pub fn normalize_traceparent(header_value: Option<&str>) -> Option<String> {
    header_value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub fn control_plane_request_id(request_id: &str) -> String {
    let trimmed = request_id.trim();
    if trimmed.is_empty() {
        return generate_32_hex();
    }
    if is_valid_32_hex_lower(trimmed) {
        return trimmed.to_string();
    }
    if let Ok(parsed) = uuid::Uuid::parse_str(trimmed) {
        return parsed.simple().to_string();
    }

    let digest = Sha256::digest(trimmed.as_bytes());
    hex::encode(&digest[..16])
}

pub fn normalize_or_generate_traceparent(input: Option<&str>) -> String {
    normalize_traceparent(input).unwrap_or_else(|| {
        // Minimal W3C Trace Context header.
        // version(2)-trace_id(32)-parent_id(16)-flags(2)
        let trace_id = generate_32_hex();
        let parent_id = generate_16_hex();
        format!("00-{trace_id}-{parent_id}-01")
    })
}

pub fn is_valid_32_hex_lower(s: &str) -> bool {
    if s.len() != 32 {
        return false;
    }
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn generate_32_hex() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

pub fn generate_16_hex() -> String {
    let id = uuid::Uuid::new_v4().as_bytes().to_owned();
    hex::encode(&id[..8])
}

pub fn parse_listen_addr(s: &str) -> Result<std::net::SocketAddr, CliError> {
    s.parse::<std::net::SocketAddr>()
        .map_err(|e| CliError::user(format!("invalid listen address: {e}")))
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
    fn validate_request_id_uses_header_when_present() {
        let id = validate_or_generate_x_request_id(Some("req-123")).unwrap();
        assert_eq!(id, "req-123");
    }

    #[test]
    fn validate_request_id_trims_whitespace() {
        let id = validate_or_generate_x_request_id(Some("  req-456  ")).unwrap();
        assert_eq!(id, "req-456");
    }

    #[test]
    fn validate_request_id_rejects_too_long_instead_of_truncating() {
        let long = "x".repeat(MAX_REQUEST_ID_LEN + 1);
        let err = validate_or_generate_x_request_id(Some(&long)).unwrap_err();
        assert!(err.reason.contains("1-128"));
    }

    #[test]
    fn validate_request_id_accepts_max_length() {
        let exact = "a".repeat(MAX_REQUEST_ID_LEN);
        let id = validate_or_generate_x_request_id(Some(&exact)).unwrap();
        assert_eq!(id.len(), MAX_REQUEST_ID_LEN);
    }

    #[test]
    fn validate_request_id_rejects_invalid_characters() {
        assert!(validate_or_generate_x_request_id(Some("req id with space")).is_err());
        assert!(validate_or_generate_x_request_id(Some("req/id")).is_err());
        assert!(validate_or_generate_x_request_id(Some("req\nid")).is_err());
        assert!(validate_or_generate_x_request_id(Some("réq")).is_err());
    }

    #[test]
    fn validate_request_id_accepts_full_grammar() {
        let id = validate_or_generate_x_request_id(Some("Req-123_test.abc:xyz")).unwrap();
        assert_eq!(id, "Req-123_test.abc:xyz");
    }

    #[test]
    fn is_valid_request_id_matches_grammar() {
        assert!(is_valid_request_id("a"));
        assert!(is_valid_request_id("A-b_c.d:0"));
        assert!(!is_valid_request_id(""));
        assert!(!is_valid_request_id("has space"));
        assert!(!is_valid_request_id(&"x".repeat(MAX_REQUEST_ID_LEN + 1)));
    }

    #[test]
    fn normalize_traceparent_preserves_value() {
        let tp = normalize_traceparent(Some("00-abc-def-01"));
        assert_eq!(tp.as_deref(), Some("00-abc-def-01"));
    }

    #[test]
    fn normalize_traceparent_returns_none_for_empty() {
        assert!(normalize_traceparent(Some("")).is_none());
        assert!(normalize_traceparent(None).is_none());
    }

    #[test]
    fn normalize_traceparent_trims_whitespace() {
        let tp = normalize_traceparent(Some("  00-abc-def-01  "));
        assert_eq!(tp.as_deref(), Some("00-abc-def-01"));
    }

    #[test]
    fn validate_request_id_invalid_error_is_displayable() {
        let err = validate_or_generate_x_request_id(Some("bad id")).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn is_valid_32_hex_lower_accepts_valid() {
        assert!(is_valid_32_hex_lower("0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn is_valid_32_hex_lower_rejects_uppercase() {
        assert!(!is_valid_32_hex_lower("0123456789ABCDEF0123456789abcdef"));
    }

    #[test]
    fn is_valid_32_hex_lower_rejects_wrong_length() {
        assert!(!is_valid_32_hex_lower("0123456789abcdef"));
        assert!(!is_valid_32_hex_lower("0123456789abcdef0123456789abcdef0"));
    }

    #[test]
    fn is_valid_32_hex_lower_rejects_non_hex() {
        assert!(!is_valid_32_hex_lower("0123456789abcdefghijklmnopqrstuv"));
    }

    #[test]
    fn control_plane_request_id_passes_through_valid_32_hex() {
        let input = "0123456789abcdef0123456789abcdef";
        assert_eq!(control_plane_request_id(input), input);
    }

    #[test]
    fn control_plane_request_id_converts_uuid_to_simple() {
        let uuid_str = "01234567-89ab-cdef-0123-456789abcdef";
        let result = control_plane_request_id(uuid_str);
        assert_eq!(result, "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn control_plane_request_id_hashes_arbitrary_string() {
        let result = control_plane_request_id("some-arbitrary-value");
        assert_eq!(result.len(), 32);
        assert!(is_valid_32_hex_lower(&result));
    }

    #[test]
    fn control_plane_request_id_hash_is_deterministic() {
        let a = control_plane_request_id("deterministic-input");
        let b = control_plane_request_id("deterministic-input");
        assert_eq!(a, b);
    }

    #[test]
    fn normalize_or_generate_traceparent_preserves_input() {
        let tp = normalize_or_generate_traceparent(Some("00-abc-def-01"));
        assert_eq!(tp, "00-abc-def-01");
    }

    #[test]
    fn parse_listen_addr_accepts_valid_socket_addr() {
        let addr = parse_listen_addr("127.0.0.1:8080").unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn parse_listen_addr_accepts_ipv6() {
        let addr = parse_listen_addr("[::1]:9090").unwrap();
        assert_eq!(addr.port(), 9090);
    }

    #[test]
    fn parse_listen_addr_rejects_invalid() {
        assert!(parse_listen_addr("not-an-address").is_err());
        assert!(parse_listen_addr("127.0.0.1").is_err());
    }
}
