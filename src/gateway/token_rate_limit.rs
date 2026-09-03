// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Phase 18 — Token-Consumption Rate Limiting.
//!
//! Implements a sliding-window token counter with three scopes:
//! `global`, `per_key`, and `per_ip`. After each upstream response the proxy
//! records the token usage; before the *next* request the `check` guard is
//! evaluated. Exceeding the ceiling produces a `RateLimitExceeded` error that
//! the caller converts into an HTTP 429.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Number of sub-windows used to approximate a sliding window.
const SUB_WINDOWS: usize = 6;

// ─── Config ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenScope {
    Global,
    PerKey,
    PerIp,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TokenRateLimitConfig {
    /// Maximum cumulative tokens allowed within the rolling window.
    pub max_tokens: u64,
    /// Window length in seconds.
    pub window_seconds: u64,
    /// Scope at which the limiter is keyed.
    pub scope: TokenScope,
}

// ─── Sliding-window bucket ───────────────────────────────────────────────────

struct SubWindow {
    tokens: u64,
    started_at: Instant,
}

struct TokenBucket {
    sub_windows: Vec<SubWindow>,
    window_seconds: u64,
}

impl TokenBucket {
    fn new(window_seconds: u64) -> Self {
        Self {
            sub_windows: Vec::new(),
            window_seconds,
        }
    }

    /// Evict sub-windows that have fully expired.
    fn prune(&mut self, now: Instant) {
        let full = Duration::from_secs(self.window_seconds);
        self.sub_windows
            .retain(|sw| now.duration_since(sw.started_at) < full);
    }

    /// Sum tokens across all active sub-windows.
    fn sum(&self) -> u64 {
        self.sub_windows.iter().map(|sw| sw.tokens).sum()
    }

    /// Add `tokens` to the current sub-window, creating one if needed.
    fn record(&mut self, tokens: u64, now: Instant) {
        // Each sub-window spans `window / SUB_WINDOWS` seconds.
        let sub_duration = Duration::from_secs((self.window_seconds / SUB_WINDOWS as u64).max(1));

        if let Some(last) = self.sub_windows.last_mut() {
            if now.duration_since(last.started_at) < sub_duration {
                last.tokens += tokens;
                return;
            }
        }
        self.sub_windows.push(SubWindow {
            tokens,
            started_at: now,
        });
    }
}

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RateLimitExceeded {
    pub window_seconds: u64,
    pub max_tokens: u64,
    pub current_tokens: u64,
}

impl std::fmt::Display for RateLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "token rate limit exceeded: {}/{} tokens in {}s window",
            self.current_tokens, self.max_tokens, self.window_seconds
        )
    }
}

// ─── Limiter ─────────────────────────────────────────────────────────────────

pub struct TokenRateLimiter {
    config: TokenRateLimitConfig,
    buckets: Mutex<HashMap<String, TokenBucket>>,
}

impl TokenRateLimiter {
    pub fn new(config: TokenRateLimitConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the scope key for the given request context.
    pub fn scope_key(&self, api_key: Option<&str>, client_ip: Option<IpAddr>) -> String {
        match self.config.scope {
            TokenScope::Global => "__global__".to_string(),
            TokenScope::PerKey => api_key.unwrap_or("__no_key__").to_string(),
            TokenScope::PerIp => client_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "__no_ip__".to_string()),
        }
    }

    /// Check whether the scope key is currently below the token ceiling.
    ///
    /// Returns `Ok(remaining)` when under the ceiling; `Err(RateLimitExceeded)`
    /// when the ceiling has already been reached.
    pub fn check(&self, scope_key: &str) -> Result<u64, RateLimitExceeded> {
        let now = Instant::now();
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut buckets = self.buckets.lock().expect("token rate limiter lock");
        let bucket = buckets
            .entry(scope_key.to_string())
            .or_insert_with(|| TokenBucket::new(self.config.window_seconds));
        bucket.prune(now);
        let current = bucket.sum();
        if current >= self.config.max_tokens {
            Err(RateLimitExceeded {
                window_seconds: self.config.window_seconds,
                max_tokens: self.config.max_tokens,
                current_tokens: current,
            })
        } else {
            Ok(self.config.max_tokens.saturating_sub(current))
        }
    }

    /// Record consumed tokens for this scope key (called after upstream responds).
    pub fn record(&self, scope_key: &str, tokens: u64) {
        let now = Instant::now();
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut buckets = self.buckets.lock().expect("token rate limiter lock");
        let bucket = buckets
            .entry(scope_key.to_string())
            .or_insert_with(|| TokenBucket::new(self.config.window_seconds));
        bucket.prune(now);
        bucket.record(tokens, now);
    }

    #[allow(dead_code)]
    pub fn config(&self) -> &TokenRateLimitConfig {
        &self.config
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TokenRequestLimitExceeded {
    pub max_requests: u64,
    pub current_requests: u64,
}

#[derive(Default)]
pub struct TokenRequestTracker {
    counts: Mutex<HashMap<String, u64>>,
}

impl TokenRequestTracker {
    pub fn sync(&self, key_id: &str, observed_current_requests: u64) -> u64 {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut guard = self.counts.lock().expect("token request tracker lock");
        let entry = guard
            .entry(key_id.to_string())
            .or_insert(observed_current_requests);
        if *entry < observed_current_requests {
            *entry = observed_current_requests;
        }
        *entry
    }

    pub fn check_and_increment(
        &self,
        key_id: &str,
        observed_current_requests: u64,
        max_requests: u64,
    ) -> Result<u64, TokenRequestLimitExceeded> {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut guard = self.counts.lock().expect("token request tracker lock");
        let entry = guard
            .entry(key_id.to_string())
            .or_insert(observed_current_requests);
        if *entry < observed_current_requests {
            *entry = observed_current_requests;
        }
        if *entry >= max_requests {
            return Err(TokenRequestLimitExceeded {
                max_requests,
                current_requests: *entry,
            });
        }
        *entry = entry.saturating_add(1);
        Ok(max_requests.saturating_sub(*entry))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TokenBudgetExceeded {
    pub max_budget: f64,
    pub current_spend: f64,
}

#[derive(Default)]
pub struct TokenBudgetTracker {
    spends: Mutex<HashMap<String, f64>>,
}

impl TokenBudgetTracker {
    pub fn sync(&self, key_id: &str, observed_current_spend: f64) -> f64 {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut guard = self.spends.lock().expect("token budget tracker lock");
        let entry = guard
            .entry(key_id.to_string())
            .or_insert(observed_current_spend);
        if *entry < observed_current_spend {
            *entry = observed_current_spend;
        }
        *entry
    }

    pub fn add_spend(&self, key_id: &str, observed_current_spend: f64, spend_delta: f64) -> f64 {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut guard = self.spends.lock().expect("token budget tracker lock");
        let entry = guard
            .entry(key_id.to_string())
            .or_insert(observed_current_spend);
        if *entry < observed_current_spend {
            *entry = observed_current_spend;
        }
        if spend_delta.is_finite() && spend_delta > 0.0 {
            *entry += spend_delta;
        }
        *entry
    }

    fn ensure_within_budget(
        &self,
        key_id: &str,
        observed_current_spend: f64,
        max_budget: f64,
    ) -> Result<f64, TokenBudgetExceeded> {
        let current_spend = self.sync(key_id, observed_current_spend);
        if current_spend >= max_budget {
            return Err(TokenBudgetExceeded {
                max_budget,
                current_spend,
            });
        }
        Ok((max_budget - current_spend).max(0.0))
    }
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn request_tracker_fails_closed_after_local_increment() {
        let tracker = TokenRequestTracker::default();
        assert_eq!(
            tracker
                .check_and_increment("key-1", 0, 1)
                .expect("first request allowed"),
            0
        );
        assert!(tracker.check_and_increment("key-1", 0, 1).is_err());
    }

    #[test]
    fn request_tracker_syncs_forward_to_new_observed_count() {
        let tracker = TokenRequestTracker::default();
        tracker
            .check_and_increment("key-1", 0, 10)
            .expect("first request allowed");
        assert_eq!(tracker.sync("key-1", 5), 5);
        assert_eq!(
            tracker
                .check_and_increment("key-1", 5, 10)
                .expect("next request allowed"),
            4
        );
    }

    #[test]
    fn budget_tracker_uses_local_spend_before_next_validation_refresh() {
        let tracker = TokenBudgetTracker::default();
        assert_eq!(
            tracker
                .ensure_within_budget("key-1", 0.0, 1.0)
                .expect("budget available"),
            1.0
        );
        assert_eq!(tracker.add_spend("key-1", 0.0, 0.75), 0.75);
        assert_eq!(
            tracker
                .ensure_within_budget("key-1", 0.0, 1.0)
                .expect("budget still available"),
            0.25
        );
        assert!(tracker.ensure_within_budget("key-1", 0.0, 0.5).is_err());
    }

    // ── TokenRateLimiter ──────────────────────────────────────────────────

    #[test]
    fn token_rate_limiter_allows_under_ceiling_and_rejects_above() {
        let limiter = TokenRateLimiter::new(TokenRateLimitConfig {
            max_tokens: 100,
            window_seconds: 60,
            scope: TokenScope::Global,
        });
        let key = limiter.scope_key(None, None);
        assert_eq!(limiter.check(&key).expect("under ceiling"), 100);

        limiter.record(&key, 80);
        assert_eq!(limiter.check(&key).expect("still under"), 20);

        limiter.record(&key, 25);
        let err = limiter.check(&key).expect_err("over ceiling");
        assert_eq!(err.max_tokens, 100);
        assert!(err.current_tokens >= 100);
        assert_eq!(err.window_seconds, 60);
    }

    #[test]
    fn token_rate_limiter_scope_key_global() {
        let limiter = TokenRateLimiter::new(TokenRateLimitConfig {
            max_tokens: 10,
            window_seconds: 60,
            scope: TokenScope::Global,
        });
        assert_eq!(
            limiter.scope_key(Some("my-key"), Some(IpAddr::V4(Ipv4Addr::LOCALHOST))),
            "__global__"
        );
    }

    #[test]
    fn token_rate_limiter_scope_key_per_key() {
        let limiter = TokenRateLimiter::new(TokenRateLimitConfig {
            max_tokens: 10,
            window_seconds: 60,
            scope: TokenScope::PerKey,
        });
        assert_eq!(limiter.scope_key(Some("api-key-1"), None), "api-key-1");
        assert_eq!(limiter.scope_key(None, None), "__no_key__");
    }

    #[test]
    fn token_rate_limiter_scope_key_per_ip() {
        let limiter = TokenRateLimiter::new(TokenRateLimitConfig {
            max_tokens: 10,
            window_seconds: 60,
            scope: TokenScope::PerIp,
        });
        assert_eq!(
            limiter.scope_key(None, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))),
            "10.0.0.1"
        );
        assert_eq!(
            limiter.scope_key(None, Some(IpAddr::V6(Ipv6Addr::LOCALHOST))),
            "::1"
        );
        assert_eq!(limiter.scope_key(None, None), "__no_ip__");
    }

    #[test]
    fn token_rate_limiter_config_accessor() {
        let config = TokenRateLimitConfig {
            max_tokens: 42,
            window_seconds: 120,
            scope: TokenScope::PerKey,
        };
        let limiter = TokenRateLimiter::new(config);
        assert_eq!(limiter.config().max_tokens, 42);
        assert_eq!(limiter.config().window_seconds, 120);
    }

    #[test]
    fn token_rate_limiter_independent_scopes() {
        let limiter = TokenRateLimiter::new(TokenRateLimitConfig {
            max_tokens: 50,
            window_seconds: 60,
            scope: TokenScope::PerKey,
        });
        limiter.record("key-a", 50);
        assert!(limiter.check("key-a").is_err());
        assert_eq!(limiter.check("key-b").expect("different scope"), 50);
    }

    // ── RateLimitExceeded Display ─────────────────────────────────────────

    #[test]
    fn rate_limit_exceeded_display() {
        let err = RateLimitExceeded {
            window_seconds: 60,
            max_tokens: 100,
            current_tokens: 150,
        };
        let display = err.to_string();
        assert!(display.contains("150/100"));
        assert!(display.contains("60s"));
    }

    // ── TokenRequestTracker edge cases ────────────────────────────────────

    #[test]
    fn request_tracker_does_not_sync_backwards() {
        let tracker = TokenRequestTracker::default();
        tracker.sync("key-1", 10);
        assert_eq!(tracker.sync("key-1", 5), 10);
    }

    #[test]
    fn request_tracker_independent_keys() {
        let tracker = TokenRequestTracker::default();
        tracker.check_and_increment("key-a", 0, 1).expect("a ok");
        assert!(tracker.check_and_increment("key-a", 0, 1).is_err());
        tracker.check_and_increment("key-b", 0, 1).expect("b ok");
    }

    #[test]
    fn request_tracker_limit_exceeded_fields() {
        let tracker = TokenRequestTracker::default();
        tracker.check_and_increment("key-1", 0, 2).unwrap();
        tracker.check_and_increment("key-1", 0, 2).unwrap();
        let err = tracker.check_and_increment("key-1", 0, 2).unwrap_err();
        assert_eq!(err.max_requests, 2);
        assert_eq!(err.current_requests, 2);
    }

    // ── TokenBudgetTracker edge cases ─────────────────────────────────────

    #[test]
    fn budget_tracker_add_spend_ignores_nan_and_negative() {
        let tracker = TokenBudgetTracker::default();
        tracker.sync("key-1", 1.0);
        assert_eq!(tracker.add_spend("key-1", 1.0, f64::NAN), 1.0);
        assert_eq!(tracker.add_spend("key-1", 1.0, -5.0), 1.0);
        assert_eq!(tracker.add_spend("key-1", 1.0, 0.0), 1.0);
    }

    #[test]
    fn budget_tracker_sync_does_not_regress() {
        let tracker = TokenBudgetTracker::default();
        tracker.sync("key-1", 10.0);
        assert_eq!(tracker.sync("key-1", 5.0), 10.0);
    }

    #[test]
    fn budget_exceeded_fields() {
        let tracker = TokenBudgetTracker::default();
        tracker.add_spend("key-1", 0.0, 5.0);
        let err = tracker.ensure_within_budget("key-1", 0.0, 3.0).unwrap_err();
        assert_eq!(err.max_budget, 3.0);
        assert_eq!(err.current_spend, 5.0);
    }
}
