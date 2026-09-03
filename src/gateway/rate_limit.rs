// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use reqwest::header::HeaderMap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AdaptiveConcurrencySnapshot {
    pub provider: String,
    pub scope_key: String,
    pub max_concurrency: usize,
    pub current_concurrency: usize,
    pub in_flight: usize,
    pub cooldown_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct UpstreamResponseMeta {
    pub status_code: Option<u16>,
    pub retry_after: Option<Duration>,
    pub remaining_quota_ratio: Option<f64>,
}

impl UpstreamResponseMeta {
    pub fn from_response(response: &reqwest::Response) -> Self {
        Self {
            status_code: Some(response.status().as_u16()),
            retry_after: parse_retry_after(response.headers()),
            remaining_quota_ratio: parse_remaining_quota_ratio(response.headers()),
        }
    }

    pub fn is_rate_limited(&self) -> bool {
        self.status_code == Some(429)
    }

    pub fn is_transient_failure(&self) -> bool {
        matches!(self.status_code, Some(408 | 500 | 502 | 503 | 504))
    }
}

#[derive(Debug)]
struct LimiterState {
    max_concurrency: usize,
    current_concurrency: usize,
    in_flight: usize,
    consecutive_successes: usize,
    cooldown_until: Option<Instant>,
}

pub struct AdaptiveConcurrencyLimiter {
    provider: String,
    scope_key: String,
    state: Mutex<LimiterState>,
    notify: Notify,
}

pub struct AdaptivePermit<'a> {
    limiter: &'a AdaptiveConcurrencyLimiter,
}

enum AcquireDecision {
    Granted,
    Busy,
    Cooldown(Duration),
}

impl AdaptiveConcurrencyLimiter {
    pub fn new(provider: String, scope_key: String, max_concurrency: usize) -> Self {
        let max_concurrency = max_concurrency.max(1);
        Self {
            provider,
            scope_key,
            state: Mutex::new(LimiterState {
                max_concurrency,
                current_concurrency: max_concurrency,
                in_flight: 0,
                consecutive_successes: 0,
                cooldown_until: None,
            }),
            notify: Notify::new(),
        }
    }

    pub async fn acquire(&self) -> AdaptivePermit<'_> {
        loop {
            let notified = self.notify.notified();
            let decision = {
                // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
                #[allow(clippy::expect_used)]
                let mut state = self.state.lock().expect("rate limiter lock");
                let now = Instant::now();
                if let Some(until) = state.cooldown_until {
                    if until > now {
                        AcquireDecision::Cooldown(until.duration_since(now))
                    } else {
                        state.cooldown_until = None;
                        if state.in_flight < state.current_concurrency {
                            state.in_flight += 1;
                            AcquireDecision::Granted
                        } else {
                            AcquireDecision::Busy
                        }
                    }
                } else if state.in_flight < state.current_concurrency {
                    state.in_flight += 1;
                    AcquireDecision::Granted
                } else {
                    AcquireDecision::Busy
                }
            };

            match decision {
                AcquireDecision::Granted => return AdaptivePermit { limiter: self },
                AcquireDecision::Busy => notified.await,
                AcquireDecision::Cooldown(delay) => tokio::time::sleep(delay).await,
            }
        }
    }

    pub fn on_success(&self, remaining_quota_ratio: Option<f64>) -> AdaptiveConcurrencySnapshot {
        let snapshot = {
            // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
            #[allow(clippy::expect_used)]
            let mut state = self.state.lock().expect("rate limiter lock");

            if remaining_quota_ratio.is_some_and(|ratio| ratio < 0.10) {
                state.current_concurrency = halve_concurrency(state.current_concurrency);
                state.consecutive_successes = 0;
            } else {
                state.consecutive_successes += 1;
                let threshold = state.current_concurrency.max(1);
                if state.consecutive_successes >= threshold
                    && state.current_concurrency < state.max_concurrency
                {
                    state.current_concurrency += 1;
                    state.consecutive_successes = 0;
                }
            }

            snapshot_from_state(&self.provider, &self.scope_key, &state)
        };

        self.notify.notify_waiters();
        snapshot
    }

    pub fn on_rate_limited(&self, retry_after: Option<Duration>) -> AdaptiveConcurrencySnapshot {
        let snapshot = {
            // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
            #[allow(clippy::expect_used)]
            let mut state = self.state.lock().expect("rate limiter lock");
            state.current_concurrency = halve_concurrency(state.current_concurrency);
            state.consecutive_successes = 0;
            if let Some(delay) = retry_after {
                state.cooldown_until = Some(Instant::now() + delay);
            }
            snapshot_from_state(&self.provider, &self.scope_key, &state)
        };

        self.notify.notify_waiters();
        snapshot
    }

    pub fn on_transient_failure(&self) -> AdaptiveConcurrencySnapshot {
        let snapshot = {
            // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
            #[allow(clippy::expect_used)]
            let mut state = self.state.lock().expect("rate limiter lock");
            state.consecutive_successes = 0;
            snapshot_from_state(&self.provider, &self.scope_key, &state)
        };

        self.notify.notify_waiters();
        snapshot
    }

    pub fn snapshot(&self) -> AdaptiveConcurrencySnapshot {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let state = self.state.lock().expect("rate limiter lock");
        snapshot_from_state(&self.provider, &self.scope_key, &state)
    }
}

impl Drop for AdaptivePermit<'_> {
    fn drop(&mut self) {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut state = self.limiter.state.lock().expect("rate limiter lock");
        if state.in_flight > 0 {
            state.in_flight -= 1;
        }
        drop(state);
        self.limiter.notify.notify_waiters();
    }
}

fn snapshot_from_state(
    provider: &str,
    scope_key: &str,
    state: &LimiterState,
) -> AdaptiveConcurrencySnapshot {
    let cooldown_ms = state
        .cooldown_until
        .and_then(|until| until.checked_duration_since(Instant::now()))
        .map(|delay| delay.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0);

    AdaptiveConcurrencySnapshot {
        provider: provider.to_string(),
        scope_key: scope_key.to_string(),
        max_concurrency: state.max_concurrency,
        current_concurrency: state.current_concurrency,
        in_flight: state.in_flight,
        cooldown_ms,
    }
}

fn halve_concurrency(value: usize) -> usize {
    value.div_ceil(2).max(1)
}

fn parse_remaining_quota_ratio(headers: &HeaderMap) -> Option<f64> {
    let remaining = parse_header_u64(
        headers,
        &[
            "x-ratelimit-remaining-requests",
            "x-ratelimit-remaining",
            "ratelimit-remaining",
        ],
    )?;
    let limit = parse_header_u64(
        headers,
        &[
            "x-ratelimit-limit-requests",
            "x-ratelimit-limit",
            "ratelimit-limit",
        ],
    )?;

    if limit == 0 {
        return None;
    }

    Some(remaining as f64 / limit as f64)
}

fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get("retry-after")?.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }

    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    if let Ok(date) = chrono::DateTime::parse_from_rfc2822(value) {
        let now = chrono::Utc::now();
        let seconds = (date.with_timezone(&chrono::Utc) - now).num_seconds();
        if seconds > 0 {
            return Some(Duration::from_secs(seconds as u64));
        }
    }

    if let Ok(date) = chrono::NaiveDateTime::parse_from_str(value, "%a, %d %b %Y %H:%M:%S GMT") {
        let now = chrono::Utc::now().naive_utc();
        let seconds = (date - now).num_seconds();
        if seconds > 0 {
            return Some(Duration::from_secs(seconds as u64));
        }
    }

    None
}

fn parse_header_u64(headers: &HeaderMap, names: &[&str]) -> Option<u64> {
    for name in names {
        let Some(value) = headers.get(*name) else {
            continue;
        };
        let Ok(value) = value.to_str() else {
            continue;
        };
        let value = value.trim();
        if let Ok(parsed) = value.parse::<u64>() {
            return Some(parsed);
        }
    }
    None
}

// ─── Phase 19: Global & IP Rate Limiting ────────────────────────────────────

/// Configuration for the global request-count ceiling.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct GlobalRateLimitConfig {
    /// Maximum requests allowed within the window.
    pub max_requests: u64,
    /// Window length in seconds.
    pub window_seconds: u64,
}

/// Configuration for per-client-IP rate limiting.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct IpRateLimitConfig {
    /// Maximum requests per IP within the window.
    pub max_requests: u64,
    /// Window length in seconds.
    pub window_seconds: u64,
    /// Proxy networks authorized to append `X-Forwarded-For`.
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
}

/// Configuration for per-user request-count rate limiting.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct UserRateLimiterConfig {
    /// Maximum requests per user within the window.
    pub max_requests: u64,
    /// Window length in seconds.
    pub window_seconds: u64,
    /// Header names used to resolve the effective user id.
    #[serde(default = "default_user_header_names")]
    pub header_names: Vec<String>,
}

fn default_user_header_names() -> Vec<String> {
    vec!["x-user-id".to_string()]
}

/// Error returned when either global or IP rate limit is exceeded.
#[derive(Debug, Clone)]
pub struct RequestRateLimitExceeded {
    pub retry_after_seconds: u64,
    pub limit: u64,
    pub remaining: u64,
}

impl std::fmt::Display for RequestRateLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rate limit exceeded: limit={} retry_after={}s",
            self.limit, self.retry_after_seconds
        )
    }
}

/// Global fixed-window request-count limiter (atomic counter + epoch reset).
pub struct GlobalRateLimiter {
    config: GlobalRateLimitConfig,
    counter: AtomicU64,
    window_start: Mutex<Instant>,
}

impl GlobalRateLimiter {
    pub fn new(config: GlobalRateLimitConfig) -> Self {
        Self {
            config,
            counter: AtomicU64::new(0),
            window_start: Mutex::new(Instant::now()),
        }
    }

    /// Attempt to count one request; returns `Ok(remaining)` or `Err` when over ceiling.
    pub fn check_and_increment(&self) -> Result<u64, RequestRateLimitExceeded> {
        let now = Instant::now();
        {
            // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
            #[allow(clippy::expect_used)]
            let mut ws = self.window_start.lock().expect("global rl window lock");
            if now.duration_since(*ws) >= Duration::from_secs(self.config.window_seconds) {
                *ws = now;
                self.counter.store(0, Ordering::SeqCst);
            }
        }
        let count = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        if count > self.config.max_requests {
            Err(RequestRateLimitExceeded {
                retry_after_seconds: self.config.window_seconds,
                limit: self.config.max_requests,
                remaining: 0,
            })
        } else {
            Ok(self.config.max_requests.saturating_sub(count))
        }
    }

    pub fn config(&self) -> &GlobalRateLimitConfig {
        &self.config
    }
}

/// Per-IP fixed-window request-count limiter.
pub struct IpRateLimiter {
    config: IpRateLimitConfig,
    trusted_proxies: Vec<ipnet::IpNet>,
    /// Map from client IP → (count, window_start).
    buckets: Mutex<HashMap<IpAddr, (u64, Instant)>>,
}

/// Per-user fixed-window request-count limiter.
pub struct UserRateLimiter {
    config: UserRateLimiterConfig,
    buckets: Mutex<HashMap<String, (u64, Instant)>>,
}

impl IpRateLimiter {
    pub fn new(config: IpRateLimitConfig) -> Result<Self, String> {
        let trusted_proxies =
            super::network::parse_trusted_proxy_cidrs(&config.trusted_proxy_cidrs)?;
        Ok(Self {
            config,
            trusted_proxies,
            buckets: Mutex::new(HashMap::new()),
        })
    }

    /// Attempt to count one request for `ip`.
    pub fn check_and_increment(&self, ip: IpAddr) -> Result<u64, RequestRateLimitExceeded> {
        let now = Instant::now();
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut buckets = self.buckets.lock().expect("ip rl lock");
        let window_duration = Duration::from_secs(self.config.window_seconds);

        let entry = buckets.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= window_duration {
            *entry = (0, now);
        }
        entry.0 += 1;
        if entry.0 > self.config.max_requests {
            Err(RequestRateLimitExceeded {
                retry_after_seconds: self.config.window_seconds,
                limit: self.config.max_requests,
                remaining: 0,
            })
        } else {
            Ok(self.config.max_requests.saturating_sub(entry.0))
        }
    }

    pub fn config(&self) -> &IpRateLimitConfig {
        &self.config
    }

    pub fn trusted_proxies(&self) -> &[ipnet::IpNet] {
        &self.trusted_proxies
    }
}

impl UserRateLimiter {
    pub fn new(config: UserRateLimiterConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_and_increment(&self, user_id: &str) -> Result<u64, RequestRateLimitExceeded> {
        let now = Instant::now();
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut buckets = self.buckets.lock().expect("user rl lock");
        let window_duration = Duration::from_secs(self.config.window_seconds);

        let entry = buckets.entry(user_id.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) >= window_duration {
            *entry = (0, now);
        }

        entry.0 += 1;
        if entry.0 > self.config.max_requests {
            Err(RequestRateLimitExceeded {
                retry_after_seconds: self.config.window_seconds,
                limit: self.config.max_requests,
                remaining: 0,
            })
        } else {
            Ok(self.config.max_requests.saturating_sub(entry.0))
        }
    }

    pub fn config(&self) -> &UserRateLimiterConfig {
        &self.config
    }
}

// ─── Per-token RPM limiter ───────────────────────────────────────────────────

/// Per-token fixed-window requests-per-minute limiter.
///
/// Each API token that carries a positive `rate_limit_rpm` is tracked
/// in an in-memory per-key bucket. Keys without a configured RPM limit
/// always pass through. The window is always exactly 60 seconds.
pub struct TokenRateLimiter {
    /// key_id → (count, window_start)
    buckets: Mutex<HashMap<String, (u64, Instant)>>,
}

impl TokenRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Attempt to count one request for `key_id` against `limit_rpm`.
    ///
    /// Returns `Ok(remaining)` when allowed, or `Err` when the per-minute
    /// ceiling has been reached. A `limit_rpm` of `0` is treated as
    /// "no limit" and always returns `Ok`.
    pub fn check_and_increment(
        &self,
        key_id: &str,
        limit_rpm: u32,
    ) -> Result<u64, RequestRateLimitExceeded> {
        if limit_rpm == 0 {
            return Ok(u64::MAX);
        }
        let limit = u64::from(limit_rpm);
        let window_duration = Duration::from_secs(60);
        let now = Instant::now();
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut buckets = self.buckets.lock().expect("key rl lock");
        let entry = buckets.entry(key_id.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) >= window_duration {
            *entry = (0, now);
        }
        entry.0 += 1;
        if entry.0 > limit {
            Err(RequestRateLimitExceeded {
                retry_after_seconds: 60,
                limit,
                remaining: 0,
            })
        } else {
            Ok(limit.saturating_sub(entry.0))
        }
    }
}

impl Default for TokenRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve `[X-Forwarded-For..., peer]` from right to left.
///
/// The resolver moves left only while the current hop belongs to a configured
/// trusted-proxy network. An untrusted direct peer therefore cannot influence
/// the result by supplying `X-Forwarded-For`.
pub fn extract_client_ip(
    headers: &axum::http::HeaderMap,
    trusted_proxies: &[ipnet::IpNet],
    peer_ip: IpAddr,
) -> IpAddr {
    if !super::network::ip_is_allowlisted(peer_ip, trusted_proxies) {
        return peer_ip;
    }

    let forwarded_values = headers.get_all("x-forwarded-for");
    if forwarded_values.iter().next().is_none() {
        return peer_ip;
    }

    let mut forwarded = Vec::new();
    for value in forwarded_values {
        let Ok(value) = value.to_str() else {
            return peer_ip;
        };
        for candidate in value.split(',') {
            let Ok(candidate) = candidate.trim().parse::<IpAddr>() else {
                return peer_ip;
            };
            forwarded.push(candidate);
        }
    }

    let mut current = peer_ip;
    for candidate in forwarded.into_iter().rev() {
        if !super::network::ip_is_allowlisted(current, trusted_proxies) {
            break;
        }
        current = candidate;
    }
    current
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
    use std::net::{IpAddr, Ipv4Addr};

    fn trusted_proxies(cidrs: &[&str]) -> Vec<ipnet::IpNet> {
        cidrs
            .iter()
            .map(|cidr| cidr.parse::<ipnet::IpNet>().unwrap())
            .collect()
    }

    #[test]
    fn upstream_response_meta_default_fields() {
        let meta = UpstreamResponseMeta::default();
        assert_eq!(meta.status_code, None);
        assert_eq!(meta.retry_after, None);
        assert_eq!(meta.remaining_quota_ratio, None);
    }

    #[test]
    fn is_rate_limited_only_for_429() {
        let meta = UpstreamResponseMeta {
            status_code: Some(429),
            ..Default::default()
        };
        assert!(meta.is_rate_limited());

        let meta_200 = UpstreamResponseMeta {
            status_code: Some(200),
            ..Default::default()
        };
        assert!(!meta_200.is_rate_limited());
    }

    #[test]
    fn is_transient_failure_codes() {
        for code in [408, 500, 502, 503, 504] {
            let meta = UpstreamResponseMeta {
                status_code: Some(code),
                ..Default::default()
            };
            assert!(
                meta.is_transient_failure(),
                "expected {code} to be transient"
            );
        }
        let meta = UpstreamResponseMeta {
            status_code: Some(400),
            ..Default::default()
        };
        assert!(!meta.is_transient_failure());
    }

    #[test]
    fn halve_concurrency_values() {
        assert_eq!(halve_concurrency(10), 5);
        assert_eq!(halve_concurrency(1), 1);
        assert_eq!(halve_concurrency(0), 1);
        assert_eq!(halve_concurrency(3), 2);
        assert_eq!(halve_concurrency(7), 4);
    }

    #[test]
    fn parse_retry_after_numeric() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", "30".parse().unwrap());
        let result = parse_retry_after(&headers).unwrap();
        assert_eq!(result, Duration::from_secs(30));
    }

    #[test]
    fn parse_retry_after_empty() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", "".parse().unwrap());
        assert!(parse_retry_after(&headers).is_none());
    }

    #[test]
    fn parse_retry_after_missing() {
        let headers = HeaderMap::new();
        assert!(parse_retry_after(&headers).is_none());
    }

    #[test]
    fn parse_remaining_quota_ratio_valid() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-remaining-requests", "50".parse().unwrap());
        headers.insert("x-ratelimit-limit-requests", "100".parse().unwrap());
        let ratio = parse_remaining_quota_ratio(&headers).unwrap();
        assert!((ratio - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_remaining_quota_ratio_zero_limit() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-remaining", "5".parse().unwrap());
        headers.insert("x-ratelimit-limit", "0".parse().unwrap());
        assert!(parse_remaining_quota_ratio(&headers).is_none());
    }

    #[test]
    fn parse_remaining_quota_ratio_missing_headers() {
        let headers = HeaderMap::new();
        assert!(parse_remaining_quota_ratio(&headers).is_none());
    }

    #[test]
    fn parse_header_u64_picks_first_match() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-remaining", "42".parse().unwrap());
        let result = parse_header_u64(&headers, &["x-ratelimit-remaining", "ratelimit-remaining"]);
        assert_eq!(result, Some(42));
    }

    #[test]
    fn parse_header_u64_uses_secondary_name_when_primary_missing() {
        let mut headers = HeaderMap::new();
        headers.insert("ratelimit-remaining", "17".parse().unwrap());
        let result = parse_header_u64(&headers, &["x-ratelimit-remaining", "ratelimit-remaining"]);
        assert_eq!(result, Some(17));
    }

    #[test]
    fn global_rate_limiter_within_limit() {
        let limiter = GlobalRateLimiter::new(GlobalRateLimitConfig {
            max_requests: 5,
            window_seconds: 60,
        });
        for _ in 0..5 {
            assert!(limiter.check_and_increment().is_ok());
        }
        assert!(limiter.check_and_increment().is_err());
    }

    #[test]
    fn global_rate_limiter_config_accessor() {
        let limiter = GlobalRateLimiter::new(GlobalRateLimitConfig {
            max_requests: 10,
            window_seconds: 30,
        });
        assert_eq!(limiter.config().max_requests, 10);
        assert_eq!(limiter.config().window_seconds, 30);
    }

    #[test]
    fn global_rate_limiter_returns_remaining() {
        let limiter = GlobalRateLimiter::new(GlobalRateLimitConfig {
            max_requests: 3,
            window_seconds: 60,
        });
        assert_eq!(limiter.check_and_increment().unwrap(), 2);
        assert_eq!(limiter.check_and_increment().unwrap(), 1);
        assert_eq!(limiter.check_and_increment().unwrap(), 0);
    }

    #[test]
    fn global_rate_limiter_resets_after_window_expires() {
        let limiter = GlobalRateLimiter::new(GlobalRateLimitConfig {
            max_requests: 1,
            window_seconds: 1,
        });
        assert_eq!(limiter.check_and_increment().unwrap(), 0);
        assert!(limiter.check_and_increment().is_err());

        #[allow(clippy::expect_used)]
        {
            let mut window_start = limiter.window_start.lock().expect("window lock");
            *window_start = Instant::now() - Duration::from_secs(2);
        }

        assert_eq!(limiter.check_and_increment().unwrap(), 0);
    }

    #[test]
    fn ip_rate_limiter_within_limit() {
        let limiter = IpRateLimiter::new(IpRateLimitConfig {
            max_requests: 3,
            window_seconds: 60,
            trusted_proxy_cidrs: Vec::new(),
        })
        .unwrap();
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        for _ in 0..3 {
            assert!(limiter.check_and_increment(ip).is_ok());
        }
        assert!(limiter.check_and_increment(ip).is_err());
    }

    #[test]
    fn ip_rate_limiter_different_ips_independent() {
        let limiter = IpRateLimiter::new(IpRateLimitConfig {
            max_requests: 1,
            window_seconds: 60,
            trusted_proxy_cidrs: Vec::new(),
        })
        .unwrap();
        let ip1: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
        assert!(limiter.check_and_increment(ip1).is_ok());
        assert!(limiter.check_and_increment(ip2).is_ok());
        assert!(limiter.check_and_increment(ip1).is_err());
    }

    #[test]
    fn ip_rate_limiter_resets_bucket_after_window_expires() {
        let limiter = IpRateLimiter::new(IpRateLimitConfig {
            max_requests: 1,
            window_seconds: 1,
            trusted_proxy_cidrs: Vec::new(),
        })
        .unwrap();
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();
        assert_eq!(limiter.check_and_increment(ip).unwrap(), 0);
        assert!(limiter.check_and_increment(ip).is_err());

        #[allow(clippy::expect_used)]
        {
            let mut buckets = limiter.buckets.lock().expect("ip buckets");
            buckets.get_mut(&ip).expect("bucket").1 = Instant::now() - Duration::from_secs(2);
        }

        assert_eq!(limiter.check_and_increment(ip).unwrap(), 0);
    }

    #[test]
    fn ip_rate_limiter_rejects_invalid_trusted_proxy_cidr() {
        let result = IpRateLimiter::new(IpRateLimitConfig {
            max_requests: 1,
            window_seconds: 60,
            trusted_proxy_cidrs: vec!["not-a-cidr".to_string()],
        });
        assert!(result.is_err());
    }

    #[test]
    fn user_rate_limiter_within_limit() {
        let limiter = UserRateLimiter::new(UserRateLimiterConfig {
            max_requests: 2,
            window_seconds: 60,
            header_names: vec!["x-user-id".to_string()],
        });
        assert!(limiter.check_and_increment("user-a").is_ok());
        assert!(limiter.check_and_increment("user-a").is_ok());
        assert!(limiter.check_and_increment("user-a").is_err());
    }

    #[test]
    fn user_rate_limiter_different_users_independent() {
        let limiter = UserRateLimiter::new(UserRateLimiterConfig {
            max_requests: 1,
            window_seconds: 60,
            header_names: vec!["x-user-id".to_string()],
        });
        assert!(limiter.check_and_increment("user-a").is_ok());
        assert!(limiter.check_and_increment("user-b").is_ok());
    }

    #[test]
    fn user_rate_limiter_resets_bucket_after_window_expires() {
        let limiter = UserRateLimiter::new(UserRateLimiterConfig {
            max_requests: 1,
            window_seconds: 1,
            header_names: vec!["x-user-id".to_string()],
        });
        assert_eq!(limiter.check_and_increment("user-a").unwrap(), 0);
        assert!(limiter.check_and_increment("user-a").is_err());

        #[allow(clippy::expect_used)]
        {
            let mut buckets = limiter.buckets.lock().expect("user buckets");
            buckets.get_mut("user-a").expect("bucket").1 = Instant::now() - Duration::from_secs(2);
        }

        assert_eq!(limiter.check_and_increment("user-a").unwrap(), 0);
    }

    #[test]
    fn token_rate_limiter_zero_limit_always_passes() {
        let limiter = TokenRateLimiter::new();
        for _ in 0..100 {
            assert!(limiter.check_and_increment("key", 0).is_ok());
        }
    }

    #[test]
    fn token_rate_limiter_enforces_limit() {
        let limiter = TokenRateLimiter::new();
        assert!(limiter.check_and_increment("key", 2).is_ok());
        assert!(limiter.check_and_increment("key", 2).is_ok());
        assert!(limiter.check_and_increment("key", 2).is_err());
    }

    #[test]
    fn token_rate_limiter_different_keys_independent() {
        let limiter = TokenRateLimiter::new();
        assert!(limiter.check_and_increment("key-a", 1).is_ok());
        assert!(limiter.check_and_increment("key-b", 1).is_ok());
        assert!(limiter.check_and_increment("key-a", 1).is_err());
    }

    #[test]
    fn token_rate_limiter_default_impl() {
        let limiter = TokenRateLimiter::default();
        assert!(limiter.check_and_increment("k", 1).is_ok());
    }

    #[test]
    fn token_rate_limiter_resets_bucket_after_window_expires() {
        let limiter = TokenRateLimiter::new();
        assert_eq!(limiter.check_and_increment("key", 1).unwrap(), 0);
        assert!(limiter.check_and_increment("key", 1).is_err());

        #[allow(clippy::expect_used)]
        {
            let mut buckets = limiter.buckets.lock().expect("token buckets");
            buckets.get_mut("key").expect("bucket").1 = Instant::now() - Duration::from_secs(61);
        }

        assert_eq!(limiter.check_and_increment("key", 1).unwrap(), 0);
    }

    #[test]
    fn extract_client_ip_direct_spoof_returns_untrusted_peer() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.99".parse().unwrap());
        let peer: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        let proxies = trusted_proxies(&["10.0.0.0/8"]);
        assert_eq!(extract_client_ip(&headers, &proxies, peer), peer);
    }

    #[test]
    fn extract_client_ip_no_xff_returns_peer() {
        let headers = axum::http::HeaderMap::new();
        let peer: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        let proxies = trusted_proxies(&["192.168.1.0/24"]);
        assert_eq!(extract_client_ip(&headers, &proxies, peer), peer);
    }

    #[test]
    fn extract_client_ip_trusted_peer_uses_single_xff_entry() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.5".parse().unwrap());
        let peer: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        let proxies = trusted_proxies(&["192.168.1.0/24"]);
        let result = extract_client_ip(&headers, &proxies, peer);
        assert_eq!(result, "10.0.0.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn extract_client_ip_stops_at_first_untrusted_hop_from_right() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.99, 198.51.100.7, 10.0.0.2".parse().unwrap(),
        );
        let peer: IpAddr = Ipv4Addr::new(10, 0, 0, 3).into();
        let proxies = trusted_proxies(&["10.0.0.0/8"]);
        let result = extract_client_ip(&headers, &proxies, peer);
        assert_eq!(result, "198.51.100.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn extract_client_ip_invalid_trusted_chain_returns_peer() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.7, invalid".parse().unwrap());
        let peer: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        let proxies = trusted_proxies(&["192.168.1.0/24"]);
        assert_eq!(extract_client_ip(&headers, &proxies, peer), peer);
    }

    #[test]
    fn request_rate_limit_exceeded_display() {
        let err = RequestRateLimitExceeded {
            retry_after_seconds: 60,
            limit: 100,
            remaining: 0,
        };
        let display = format!("{err}");
        assert!(display.contains("rate limit exceeded"));
        assert!(display.contains("100"));
        assert!(display.contains("60s"));
    }

    #[test]
    fn default_user_header_names_value() {
        let names = default_user_header_names();
        assert_eq!(names, vec!["x-user-id".to_string()]);
    }

    #[test]
    fn adaptive_concurrency_limiter_snapshot() {
        let limiter = AdaptiveConcurrencyLimiter::new("openai".into(), "default".into(), 10);
        let snap = limiter.snapshot();
        assert_eq!(snap.provider, "openai");
        assert_eq!(snap.scope_key, "default");
        assert_eq!(snap.max_concurrency, 10);
        assert_eq!(snap.current_concurrency, 10);
        assert_eq!(snap.in_flight, 0);
    }

    #[test]
    fn adaptive_concurrency_limiter_min_max_is_one() {
        let limiter = AdaptiveConcurrencyLimiter::new("p".into(), "s".into(), 0);
        let snap = limiter.snapshot();
        assert_eq!(snap.max_concurrency, 1);
    }

    #[test]
    fn on_success_grows_concurrency_after_threshold() {
        let limiter = AdaptiveConcurrencyLimiter::new("p".into(), "s".into(), 5);
        {
            #[allow(clippy::expect_used)]
            let mut state = limiter.state.lock().expect("lock");
            state.current_concurrency = 2;
        }
        for _ in 0..2 {
            limiter.on_success(None);
        }
        let snap = limiter.snapshot();
        assert_eq!(snap.current_concurrency, 3);
    }

    #[test]
    fn on_success_halves_on_low_quota() {
        let limiter = AdaptiveConcurrencyLimiter::new("p".into(), "s".into(), 10);
        let snap = limiter.on_success(Some(0.05));
        assert_eq!(snap.current_concurrency, 5);
    }

    #[test]
    fn on_rate_limited_halves_concurrency() {
        let limiter = AdaptiveConcurrencyLimiter::new("p".into(), "s".into(), 10);
        let snap = limiter.on_rate_limited(None);
        assert_eq!(snap.current_concurrency, 5);
    }

    #[test]
    fn on_rate_limited_with_retry_after() {
        let limiter = AdaptiveConcurrencyLimiter::new("p".into(), "s".into(), 10);
        let snap = limiter.on_rate_limited(Some(Duration::from_secs(5)));
        assert!(snap.cooldown_ms > 0);
    }

    #[test]
    fn on_transient_failure_resets_consecutive_successes() {
        let limiter = AdaptiveConcurrencyLimiter::new("p".into(), "s".into(), 10);
        limiter.on_success(None);
        limiter.on_transient_failure();
        let snap = limiter.snapshot();
        assert_eq!(snap.current_concurrency, 10);
    }

    #[test]
    fn adaptive_concurrency_snapshot_serializes() {
        let snap = AdaptiveConcurrencySnapshot {
            provider: "test".into(),
            scope_key: "k".into(),
            max_concurrency: 10,
            current_concurrency: 5,
            in_flight: 2,
            cooldown_ms: 0,
        };
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["provider"], "test");
        assert_eq!(json["max_concurrency"], 10);
    }

    #[test]
    fn global_rate_limit_config_deserializes() {
        let json = serde_json::json!({"max_requests": 100, "window_seconds": 60});
        let config: GlobalRateLimitConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.max_requests, 100);
        assert_eq!(config.window_seconds, 60);
    }

    #[test]
    fn ip_rate_limit_config_deserializes_with_defaults() {
        let json = serde_json::json!({"max_requests": 50, "window_seconds": 30});
        let config: IpRateLimitConfig = serde_json::from_value(json).unwrap();
        assert!(config.trusted_proxy_cidrs.is_empty());
    }

    #[test]
    fn user_rate_limiter_config_default_header_names() {
        let json = serde_json::json!({"max_requests": 10, "window_seconds": 60});
        let config: UserRateLimiterConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.header_names, vec!["x-user-id".to_string()]);
    }
}
