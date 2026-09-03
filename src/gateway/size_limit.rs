// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Phase 20 — Request Size Limiting.
//!
//! Enforces byte-level limits on the request body, header block, and URL.
//! Exceeding any limit produces a `SizeLimitExceeded` error that the caller
//! converts into an HTTP 413 Payload Too Large.
//!
//! PERF-012: response bodies always enforce a production hard cap of 16 MiB
//! via [`bounded_chunk_reader`]. `max_response_bytes: None` means "use the
//! production default", not "unlimited".

#[path = "bounded_chunk_reader.rs"]
pub mod bounded_chunk_reader;

pub use bounded_chunk_reader::{
    effective_response_limit, overflow_stop_bytes, reject_oversized_content_length,
    DEFAULT_MAX_RESPONSE_BYTES, MAX_IN_FLIGHT_RESPONSE_BUFFER_BYTES,
};

// ─── Config ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
pub struct SizeLimitConfig {
    /// Maximum request body size in bytes.
    pub max_body_bytes: Option<usize>,
    /// Maximum total header block size in bytes (sum of name+value lengths).
    pub max_header_bytes: Option<usize>,
    /// Maximum URL length in bytes.
    pub max_url_bytes: Option<usize>,
    /// Maximum response body size in bytes.
    ///
    /// `None` applies the production default ([`DEFAULT_MAX_RESPONSE_BYTES`]).
    /// Configured values are tightened to that hard cap.
    pub max_response_bytes: Option<usize>,
}

/// Per-key / per-route overrides expressed in megabytes (matching LiteLLM
/// token config surface).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
pub struct SizeLimitOverride {
    /// Per-key maximum request body size in megabytes.
    pub max_request_size_mb: Option<f64>,
    /// Per-key maximum response body size in megabytes.
    pub max_response_size_mb: Option<f64>,
}

impl SizeLimitConfig {
    /// Return a new config with per-key overrides applied. The override
    /// tightens the limit (uses the stricter of the two when both are set).
    fn with_override(&self, ov: &SizeLimitOverride) -> Self {
        let mb_to_bytes = |mb: f64| (mb * 1_048_576.0) as usize;
        let tighten = |base: Option<usize>, ov_mb: Option<f64>| -> Option<usize> {
            match (base, ov_mb.map(mb_to_bytes)) {
                (Some(b), Some(o)) => Some(b.min(o)),
                (Some(b), None) => Some(b),
                (None, Some(o)) => Some(o),
                (None, None) => None,
            }
        };

        SizeLimitConfig {
            max_body_bytes: tighten(self.max_body_bytes, ov.max_request_size_mb),
            max_header_bytes: self.max_header_bytes,
            max_url_bytes: self.max_url_bytes,
            max_response_bytes: tighten(self.max_response_bytes, ov.max_response_size_mb),
        }
    }
}

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SizeLimitKind {
    Body,
    Headers,
    Url,
    Response,
}

impl std::fmt::Display for SizeLimitKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SizeLimitKind::Body => write!(f, "body"),
            SizeLimitKind::Headers => write!(f, "headers"),
            SizeLimitKind::Url => write!(f, "url"),
            SizeLimitKind::Response => write!(f, "response"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SizeLimitExceeded {
    pub kind: SizeLimitKind,
    pub actual: usize,
    pub limit: usize,
}

impl std::fmt::Display for SizeLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} size {} bytes exceeds limit of {} bytes",
            self.kind, self.actual, self.limit
        )
    }
}

// ─── Middleware ───────────────────────────────────────────────────────────────

pub struct SizeLimitMiddleware {
    config: SizeLimitConfig,
}

impl SizeLimitMiddleware {
    pub fn new(config: SizeLimitConfig) -> Self {
        Self { config }
    }

    /// Returns the configured maximum response body size, if any.
    pub fn max_response_bytes(&self) -> Option<usize> {
        self.config.max_response_bytes
    }

    /// Production-effective response limit (configured value, capped at 16 MiB).
    pub fn effective_max_response_bytes(&self) -> usize {
        effective_response_limit(self.config.max_response_bytes)
    }

    /// Check only the upstream response body size.
    ///
    /// Always enforces the production-effective limit (default 16 MiB).
    /// Returns `Err(SizeLimitExceeded { kind: Response,.. })` when exceeded.
    pub fn check_response(&self, body_len: usize) -> Result<(), SizeLimitExceeded> {
        let max = self.effective_max_response_bytes();
        if body_len > max {
            return Err(SizeLimitExceeded {
                kind: SizeLimitKind::Response,
                actual: body_len,
                limit: max,
            });
        }
        Ok(())
    }

    /// Check body, header block, and URL sizes in one pass.
    ///
    /// Returns `Ok` when all configured limits pass; `Err(SizeLimitExceeded)`
    /// for the first limit that fires (evaluated in body → headers → url order).
    pub fn check(
        &self,
        body_len: usize,
        headers_len: usize,
        url_len: usize,
    ) -> Result<(), SizeLimitExceeded> {
        if let Some(max) = self.config.max_body_bytes {
            if body_len > max {
                return Err(SizeLimitExceeded {
                    kind: SizeLimitKind::Body,
                    actual: body_len,
                    limit: max,
                });
            }
        }
        if let Some(max) = self.config.max_header_bytes {
            if headers_len > max {
                return Err(SizeLimitExceeded {
                    kind: SizeLimitKind::Headers,
                    actual: headers_len,
                    limit: max,
                });
            }
        }
        if let Some(max) = self.config.max_url_bytes {
            if url_len > max {
                return Err(SizeLimitExceeded {
                    kind: SizeLimitKind::Url,
                    actual: url_len,
                    limit: max,
                });
            }
        }
        Ok(())
    }
}

/// Calculate the total byte size of an HTTP header block from an Axum
/// `HeaderMap`. Counts both name and value octets for every header.
pub fn headers_byte_len(headers: &axum::http::HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len())
        .sum()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

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
    use axum::http::HeaderMap;

    #[test]
    fn size_limit_config_default_is_no_limits() {
        let config = SizeLimitConfig::default();
        assert!(config.max_body_bytes.is_none());
        assert!(config.max_header_bytes.is_none());
        assert!(config.max_url_bytes.is_none());
        assert!(config.max_response_bytes.is_none());
    }

    #[test]
    fn check_all_within_limits() {
        let mw = SizeLimitMiddleware::new(SizeLimitConfig {
            max_body_bytes: Some(1024),
            max_header_bytes: Some(512),
            max_url_bytes: Some(256),
            max_response_bytes: None,
        });
        assert!(mw.check(100, 100, 50).is_ok());
    }

    #[test]
    fn check_body_exceeds_limit() {
        let mw = SizeLimitMiddleware::new(SizeLimitConfig {
            max_body_bytes: Some(100),
            max_header_bytes: None,
            max_url_bytes: None,
            max_response_bytes: None,
        });
        let err = mw.check(200, 50, 50).unwrap_err();
        assert_eq!(err.kind, SizeLimitKind::Body);
        assert_eq!(err.actual, 200);
        assert_eq!(err.limit, 100);
    }

    #[test]
    fn check_headers_exceeds_limit() {
        let mw = SizeLimitMiddleware::new(SizeLimitConfig {
            max_body_bytes: Some(1000),
            max_header_bytes: Some(50),
            max_url_bytes: None,
            max_response_bytes: None,
        });
        let err = mw.check(100, 100, 50).unwrap_err();
        assert_eq!(err.kind, SizeLimitKind::Headers);
        assert_eq!(err.actual, 100);
        assert_eq!(err.limit, 50);
    }

    #[test]
    fn check_url_exceeds_limit() {
        let mw = SizeLimitMiddleware::new(SizeLimitConfig {
            max_body_bytes: Some(1000),
            max_header_bytes: Some(1000),
            max_url_bytes: Some(10),
            max_response_bytes: None,
        });
        let err = mw.check(100, 100, 50).unwrap_err();
        assert_eq!(err.kind, SizeLimitKind::Url);
        assert_eq!(err.actual, 50);
        assert_eq!(err.limit, 10);
    }

    #[test]
    fn check_no_limits_always_passes() {
        let mw = SizeLimitMiddleware::new(SizeLimitConfig::default());
        assert!(mw.check(999_999, 999_999, 999_999).is_ok());
    }

    #[test]
    fn check_body_exact_boundary() {
        let mw = SizeLimitMiddleware::new(SizeLimitConfig {
            max_body_bytes: Some(100),
            ..Default::default()
        });
        assert!(mw.check(100, 0, 0).is_ok());
        assert!(mw.check(101, 0, 0).is_err());
    }

    #[test]
    fn check_response_within_limit() {
        let mw = SizeLimitMiddleware::new(SizeLimitConfig {
            max_response_bytes: Some(1000),
            ..Default::default()
        });
        assert!(mw.check_response(500).is_ok());
        assert!(mw.check_response(1000).is_ok());
    }

    #[test]
    fn check_response_exceeds_limit() {
        let mw = SizeLimitMiddleware::new(SizeLimitConfig {
            max_response_bytes: Some(1000),
            ..Default::default()
        });
        let err = mw.check_response(1001).unwrap_err();
        assert_eq!(err.kind, SizeLimitKind::Response);
        assert_eq!(err.actual, 1001);
        assert_eq!(err.limit, 1000);
    }

    #[test]
    fn check_response_no_limit_uses_production_default() {
        let mw = SizeLimitMiddleware::new(SizeLimitConfig::default());
        assert!(mw.check_response(1_000_000).is_ok());
        let err = mw
            .check_response(DEFAULT_MAX_RESPONSE_BYTES + 1)
            .unwrap_err();
        assert_eq!(err.kind, SizeLimitKind::Response);
        assert_eq!(err.limit, DEFAULT_MAX_RESPONSE_BYTES);
    }

    #[test]
    fn effective_max_response_bytes_defaults_to_sixteen_mib() {
        let mw = SizeLimitMiddleware::new(SizeLimitConfig::default());
        assert_eq!(
            mw.effective_max_response_bytes(),
            DEFAULT_MAX_RESPONSE_BYTES
        );
    }

    #[test]
    fn effective_max_response_bytes_tightens_above_hard_cap() {
        let mw = SizeLimitMiddleware::new(SizeLimitConfig {
            max_response_bytes: Some(DEFAULT_MAX_RESPONSE_BYTES * 4),
            ..Default::default()
        });
        assert_eq!(
            mw.effective_max_response_bytes(),
            DEFAULT_MAX_RESPONSE_BYTES
        );
    }

    #[test]
    fn max_response_bytes_accessor() {
        let mw = SizeLimitMiddleware::new(SizeLimitConfig {
            max_response_bytes: Some(42),
            ..Default::default()
        });
        assert_eq!(mw.max_response_bytes(), Some(42));
    }

    #[test]
    fn with_override_tightens_body_limit() {
        let config = SizeLimitConfig {
            max_body_bytes: Some(10_000_000),
            ..Default::default()
        };
        let ov = SizeLimitOverride {
            max_request_size_mb: Some(1.0),
            max_response_size_mb: None,
        };
        let result = config.with_override(&ov);
        assert_eq!(result.max_body_bytes, Some(1_048_576));
    }

    #[test]
    fn with_override_does_not_loosen_limit() {
        let config = SizeLimitConfig {
            max_body_bytes: Some(500_000),
            ..Default::default()
        };
        let ov = SizeLimitOverride {
            max_request_size_mb: Some(10.0),
            max_response_size_mb: None,
        };
        let result = config.with_override(&ov);
        assert_eq!(result.max_body_bytes, Some(500_000));
    }

    #[test]
    fn with_override_applies_response_limit() {
        let config = SizeLimitConfig::default();
        let ov = SizeLimitOverride {
            max_request_size_mb: None,
            max_response_size_mb: Some(2.0),
        };
        let result = config.with_override(&ov);
        assert_eq!(result.max_response_bytes, Some(2_097_152));
    }

    #[test]
    fn with_override_preserves_header_and_url() {
        let config = SizeLimitConfig {
            max_header_bytes: Some(100),
            max_url_bytes: Some(200),
            ..Default::default()
        };
        let ov = SizeLimitOverride {
            max_request_size_mb: Some(1.0),
            max_response_size_mb: Some(1.0),
        };
        let result = config.with_override(&ov);
        assert_eq!(result.max_header_bytes, Some(100));
        assert_eq!(result.max_url_bytes, Some(200));
    }

    #[test]
    fn headers_byte_len_empty() {
        let headers = HeaderMap::new();
        assert_eq!(headers_byte_len(&headers), 0);
    }

    #[test]
    fn headers_byte_len_counts_name_and_value() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        let expected = "content-type".len() + "application/json".len();
        assert_eq!(headers_byte_len(&headers), expected);
    }

    #[test]
    fn headers_byte_len_multiple_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("a", "1".parse().unwrap());
        headers.insert("bb", "22".parse().unwrap());
        let expected = 1 + 1 + 2 + 2;
        assert_eq!(headers_byte_len(&headers), expected);
    }

    #[test]
    fn size_limit_kind_display() {
        assert_eq!(format!("{}", SizeLimitKind::Body), "body");
        assert_eq!(format!("{}", SizeLimitKind::Headers), "headers");
        assert_eq!(format!("{}", SizeLimitKind::Url), "url");
        assert_eq!(format!("{}", SizeLimitKind::Response), "response");
    }

    #[test]
    fn size_limit_exceeded_display() {
        let err = SizeLimitExceeded {
            kind: SizeLimitKind::Body,
            actual: 2000,
            limit: 1000,
        };
        assert_eq!(
            format!("{err}"),
            "body size 2000 bytes exceeds limit of 1000 bytes"
        );
    }
}
