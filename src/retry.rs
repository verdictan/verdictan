// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Bounded retry helper with exponential backoff and jitter.
//!
//! Provides a single retry policy for the CLI that classifies transient vs
//! permanent failures and logs each attempt with correlation metadata.
use std::time::Duration;

fn cheap_jitter_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as f64
        / 1_000_000_000.0
}

/// Retry configuration.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (excludes the initial attempt).
    pub max_retries: u32,
    /// Base delay before the first retry.
    pub base_delay: Duration,
    /// Multiplier applied to delay on each subsequent attempt.
    pub multiplier: f64,
    /// Maximum delay cap.
    pub max_delay: Duration,
    /// Jitter factor (0.0–1.0). Applied as ± percentage of computed delay.
    pub jitter: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(200),
            multiplier: 2.0,
            max_delay: Duration::from_secs(5),
            jitter: 0.25,
        }
    }
}

/// Classification of a failure for retry purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryClassification {
    /// Transient failure — safe to retry (5xx, timeout, connection refused).
    Transient,
    /// Permanent failure — do NOT retry (4xx, auth errors, validation).
    Permanent,
}

/// Classify an HTTP status code for retry purposes.
pub fn classify_status(status: u16) -> RetryClassification {
    match status {
        // CLI-LOGIC-002: Include 500 as transient — upstream internal errors are
        // typically recoverable on retry (e.g. overloaded backends, transient bugs).
        429 | 500 | 502 | 503 | 504 => RetryClassification::Transient,
        _ if status >= 500 => RetryClassification::Permanent, // Non-transient 5xx (501, 505, etc.)
        _ => RetryClassification::Permanent,
    }
}

/// Execute an async operation with retry.
///
/// The `classify` closure receives the error and returns whether to retry.
/// Each retry is logged at `WARN` level with attempt count and delay.
pub async fn with_retry<F, Fut, T, E>(
    policy: &RetryPolicy,
    operation_name: &str,
    execute: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    with_retry_classified(
        policy,
        operation_name,
        |_| RetryClassification::Transient,
        execute,
    )
    .await
}

/// Execute an async operation with classification-based retry.
///
/// Callers MUST ensure the retried operation is idempotent. Non-idempotent
/// operations should not use this helper.
/// Only retries when `classify(&err)` returns `RetryClassification::Transient`.
/// Permanent errors are returned immediately without retry.
/// Each retry is logged at `WARN` level with attempt count and delay.
pub(crate) async fn with_retry_classified<F, Fut, T, E, C>(
    policy: &RetryPolicy,
    operation_name: &str,
    classify: C,
    mut execute: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
    C: Fn(&E) -> RetryClassification,
{
    let mut attempt = 0u32;

    loop {
        match execute().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                attempt += 1;

                if classify(&err) == RetryClassification::Permanent {
                    tracing::debug!(
                        operation = operation_name,
                        attempt = attempt,
                        error = %err,
                        "permanent failure — not retrying"
                    );
                    return Err(err);
                }

                if attempt > policy.max_retries {
                    tracing::error!(
                        operation = operation_name,
                        attempt = attempt,
                        error = %err,
                        "retry exhausted — returning final error"
                    );
                    return Err(err);
                }

                let delay = compute_delay(policy, attempt);
                tracing::warn!(
                    operation = operation_name,
                    attempt = attempt,
                    max_retries = policy.max_retries,
                    delay_ms = delay.as_millis() as u64,
                    error = %err,
                    "retrying after transient failure"
                );

                tokio::time::sleep(delay).await;
            }
        }
    }
}

pub fn compute_delay(policy: &RetryPolicy, attempt: u32) -> Duration {
    compute_delay_with_sample(policy, attempt, cheap_jitter_f64())
}

#[doc(hidden)]
pub fn compute_delay_with_sample(
    policy: &RetryPolicy,
    attempt: u32,
    jitter_sample: f64,
) -> Duration {
    let base_ms = policy.base_delay.as_millis() as f64;
    let delay_ms = base_ms * policy.multiplier.powi(attempt.saturating_sub(1) as i32);
    let capped_ms = delay_ms.min(policy.max_delay.as_millis() as f64);

    let clamped_sample = jitter_sample.clamp(0.0, 1.0 - f64::EPSILON);
    // Apply jitter: ± jitter_factor of the computed delay
    let jitter_range = capped_ms * policy.jitter;
    // Map the jitter sample from [0,1) to [-jitter_range, +jitter_range).
    let jitter_offset = jitter_range * (2.0 * clamped_sample - 1.0);
    let final_ms = (capped_ms + jitter_offset).max(0.0);

    Duration::from_millis(final_ms as u64)
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
    fn classify_status_transient_codes() {
        assert_eq!(classify_status(429), RetryClassification::Transient);
        assert_eq!(classify_status(500), RetryClassification::Transient);
        assert_eq!(classify_status(502), RetryClassification::Transient);
        assert_eq!(classify_status(503), RetryClassification::Transient);
        assert_eq!(classify_status(504), RetryClassification::Transient);
    }

    #[test]
    fn classify_status_permanent_codes() {
        assert_eq!(classify_status(400), RetryClassification::Permanent);
        assert_eq!(classify_status(401), RetryClassification::Permanent);
        assert_eq!(classify_status(403), RetryClassification::Permanent);
        assert_eq!(classify_status(404), RetryClassification::Permanent);
        assert_eq!(classify_status(422), RetryClassification::Permanent);
        assert_eq!(classify_status(200), RetryClassification::Permanent);
        assert_eq!(classify_status(201), RetryClassification::Permanent);
        assert_eq!(classify_status(301), RetryClassification::Permanent);
    }

    #[test]
    fn classify_status_non_transient_5xx() {
        assert_eq!(classify_status(501), RetryClassification::Permanent);
        assert_eq!(classify_status(505), RetryClassification::Permanent);
        assert_eq!(classify_status(507), RetryClassification::Permanent);
        assert_eq!(classify_status(511), RetryClassification::Permanent);
    }

    #[test]
    fn default_policy_values() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.base_delay, Duration::from_millis(200));
        assert_eq!(policy.multiplier, 2.0);
        assert_eq!(policy.max_delay, Duration::from_secs(5));
        assert_eq!(policy.jitter, 0.25);
    }

    #[test]
    fn compute_delay_first_attempt_zero_jitter() {
        let policy = RetryPolicy {
            base_delay: Duration::from_millis(100),
            multiplier: 2.0,
            max_delay: Duration::from_secs(10),
            jitter: 0.0,
            ..Default::default()
        };
        let delay = compute_delay_with_sample(&policy, 1, 0.5);
        assert_eq!(delay, Duration::from_millis(100));
    }

    #[test]
    fn compute_delay_exponential_growth() {
        let policy = RetryPolicy {
            base_delay: Duration::from_millis(100),
            multiplier: 2.0,
            max_delay: Duration::from_secs(10),
            jitter: 0.0,
            ..Default::default()
        };
        assert_eq!(
            compute_delay_with_sample(&policy, 1, 0.5),
            Duration::from_millis(100)
        );
        assert_eq!(
            compute_delay_with_sample(&policy, 2, 0.5),
            Duration::from_millis(200)
        );
        assert_eq!(
            compute_delay_with_sample(&policy, 3, 0.5),
            Duration::from_millis(400)
        );
        assert_eq!(
            compute_delay_with_sample(&policy, 4, 0.5),
            Duration::from_millis(800)
        );
    }

    #[test]
    fn compute_delay_respects_max_delay_cap() {
        let policy = RetryPolicy {
            base_delay: Duration::from_millis(1000),
            multiplier: 10.0,
            max_delay: Duration::from_secs(5),
            jitter: 0.0,
            ..Default::default()
        };
        let delay = compute_delay_with_sample(&policy, 5, 0.5);
        assert_eq!(delay, Duration::from_secs(5));
    }

    #[test]
    fn compute_delay_jitter_minimum_sample() {
        let policy = RetryPolicy {
            base_delay: Duration::from_millis(200),
            multiplier: 2.0,
            max_delay: Duration::from_secs(10),
            jitter: 0.25,
            ..Default::default()
        };
        let delay = compute_delay_with_sample(&policy, 1, 0.0);
        assert_eq!(delay, Duration::from_millis(150));
    }

    #[test]
    fn compute_delay_jitter_maximum_sample() {
        let policy = RetryPolicy {
            base_delay: Duration::from_millis(200),
            multiplier: 2.0,
            max_delay: Duration::from_secs(10),
            jitter: 0.25,
            ..Default::default()
        };
        let delay = compute_delay_with_sample(&policy, 1, 0.999);
        assert!(delay.as_millis() >= 249 && delay.as_millis() <= 250);
    }

    #[test]
    fn compute_delay_clamps_negative_jitter_sample() {
        let policy = RetryPolicy {
            base_delay: Duration::from_millis(200),
            multiplier: 2.0,
            max_delay: Duration::from_secs(10),
            jitter: 0.25,
            ..Default::default()
        };
        let delay = compute_delay_with_sample(&policy, 1, -1.0);
        assert_eq!(delay, Duration::from_millis(150));
    }

    #[test]
    fn compute_delay_clamps_above_one_jitter_sample() {
        let policy = RetryPolicy {
            base_delay: Duration::from_millis(200),
            multiplier: 2.0,
            max_delay: Duration::from_secs(10),
            jitter: 0.25,
            ..Default::default()
        };
        let delay = compute_delay_with_sample(&policy, 1, 5.0);
        assert!(delay.as_millis() >= 249 && delay.as_millis() <= 250);
    }

    #[test]
    fn compute_delay_saturating_sub_on_attempt_zero() {
        let policy = RetryPolicy {
            base_delay: Duration::from_millis(100),
            multiplier: 3.0,
            max_delay: Duration::from_secs(10),
            jitter: 0.0,
            ..Default::default()
        };
        let delay = compute_delay_with_sample(&policy, 0, 0.5);
        assert_eq!(delay, Duration::from_millis(100));
    }

    #[test]
    fn compute_delay_with_zero_base_delay() {
        let policy = RetryPolicy {
            base_delay: Duration::from_millis(0),
            multiplier: 2.0,
            max_delay: Duration::from_secs(10),
            jitter: 0.25,
            ..Default::default()
        };
        let delay = compute_delay_with_sample(&policy, 3, 0.5);
        assert_eq!(delay, Duration::from_millis(0));
    }
}
