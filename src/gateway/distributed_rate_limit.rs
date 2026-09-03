// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Phase 21 — Distributed Rate Limiting (feature-gated).
//!
//! When compiled with `--features distributed` this module exposes a
//! `DistributedRateLimiter` that uses a Redis sorted-set sliding-window pattern
//! over async pooled connections with bounded connect/command timeouts and an
//! atomic admission script. Backend outages apply an explicit policy:
//! [`DistributedFailurePolicy::FailClosed`] (required / multi-node) or
//! [`DistributedFailurePolicy::LocalEnforcement`] (explicit one-node
//! self-hosted development only). Recovery after a failure requires two
//! consecutive successful backend probes before traffic is admitted again.
//!
//! **No live Redis instance is required for hard-lane tests.** Deterministic
//! injected backends cover degraded behavior.
//!
//! ### Stateless function-based API (Phase 25)
//!
//! [`check_rate_limit`] provides a stateless alternative that accepts a
//! [`super::distributed_state::DistributedState`] reference and performs a
//! sliding-window check against Redis when available, falling back to an
//! in-process counter otherwise.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing;

use super::distributed_state::DistributedRequirement;
use super::rate_limit::{GlobalRateLimitConfig, RequestRateLimitExceeded};

/// Bounded connect timeout for async Redis/Valkey pool acquisition.
pub const DISTRIBUTED_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Bounded command/response timeout for atomic scripts and probes.
pub const DISTRIBUTED_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
/// Consecutive successful probes required before an unhealthy backend recovers.
pub const RECOVERY_SUCCESS_THRESHOLD: u32 = 2;

// ─── Phase 25: stateless function-based API ───────────────────────────────────

/// Result of a distributed rate limit check.
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed (not rate limited).
    pub allowed: bool,
    /// Remaining requests in the current window.
    pub remaining: u64,
    /// Unix timestamp (seconds) when the current window resets.
    pub reset_at: u64,
}

/// Explicit degraded-mode behavior when a distributed backend fails after the
/// limiter has already been configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributedFailurePolicy {
    /// Use the process-local limiter so requests remain bounded.
    ///
    /// Admissible only for the explicit [`DistributedRequirement::LocalOnly`]
    /// one-node self-hosted development contract. Must never be selected as a
    /// runtime transition after a required-backend failure.
    LocalEnforcement,
    /// Deny requests when distributed coordination cannot be trusted.
    FailClosed,
}

impl DistributedFailurePolicy {
    /// Derive the failure policy from the immutable distributed requirement.
    ///
    /// [`DistributedRequirement::Required`] always fail-closes.
    /// [`DistributedRequirement::LocalOnly`] is the only contract that may use
    /// process-local enforcement. Backend health never influences this choice.
    pub fn for_requirement(requirement: DistributedRequirement) -> Self {
        match requirement {
            DistributedRequirement::Required => Self::FailClosed,
            DistributedRequirement::LocalOnly | DistributedRequirement::Disabled => {
                Self::LocalEnforcement
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalEnforcement => "local_enforcement",
            Self::FailClosed => "fail_closed",
        }
    }

    pub fn is_fail_closed(self) -> bool {
        matches!(self, Self::FailClosed)
    }

    /// Compatibility alias for [`Self::FailClosed`].
    ///
    /// Kept so out-of-module callers that still construct `Deny` continue to
    /// compile while matching the explicit FailClosed semantics.
    #[allow(non_upper_case_globals)]
    pub const Deny: Self = Self::FailClosed;
}

/// Point-in-time health observation for a distributed backend consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendHealthSnapshot {
    pub healthy: bool,
    pub consecutive_successes: u32,
    /// Unix seconds of the last successful backend operation, when any.
    pub last_success_unix: Option<u64>,
    /// Unix seconds of the last failed backend operation, when any.
    pub last_failure_unix: Option<u64>,
}

impl BackendHealthSnapshot {
    /// True when the backend is fully recovered (healthy after two successes).
    pub fn admits_traffic(self) -> bool {
        self.healthy
    }
}

#[derive(Debug)]
struct BackendHealthInner {
    healthy: bool,
    consecutive_successes: u32,
    last_success_at: Option<Instant>,
    last_failure_at: Option<Instant>,
    last_success_unix: Option<u64>,
    last_failure_unix: Option<u64>,
}

/// Tracks last-success / last-failure timestamps and two-success recovery.
///
/// After any failure the backend is unhealthy. Traffic under
/// [`DistributedFailurePolicy::FailClosed`] stays denied until
/// [`RECOVERY_SUCCESS_THRESHOLD`] consecutive successes are observed.
#[derive(Debug)]
pub struct BackendHealthTracker {
    inner: Mutex<BackendHealthInner>,
}

impl Default for BackendHealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendHealthTracker {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(BackendHealthInner {
                healthy: true,
                consecutive_successes: RECOVERY_SUCCESS_THRESHOLD,
                last_success_at: None,
                last_failure_at: None,
                last_success_unix: None,
                last_failure_unix: None,
            }),
        }
    }

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn snapshot_locked(inner: &BackendHealthInner) -> BackendHealthSnapshot {
        BackendHealthSnapshot {
            healthy: inner.healthy,
            consecutive_successes: inner.consecutive_successes,
            last_success_unix: inner.last_success_unix,
            last_failure_unix: inner.last_failure_unix,
        }
    }

    pub fn snapshot(&self) -> BackendHealthSnapshot {
        #[allow(clippy::expect_used)]
        let inner = self.inner.lock().expect("backend health lock");
        Self::snapshot_locked(&inner)
    }

    pub fn is_healthy(&self) -> bool {
        self.snapshot().healthy
    }

    /// Record a successful backend probe/command. Returns the post-update snapshot.
    pub fn record_success(&self) -> BackendHealthSnapshot {
        #[allow(clippy::expect_used)]
        let mut inner = self.inner.lock().expect("backend health lock");
        let now = Instant::now();
        inner.last_success_at = Some(now);
        inner.last_success_unix = Some(Self::now_unix());
        if inner.healthy {
            inner.consecutive_successes = RECOVERY_SUCCESS_THRESHOLD;
        } else {
            inner.consecutive_successes = inner
                .consecutive_successes
                .saturating_add(1)
                .min(RECOVERY_SUCCESS_THRESHOLD);
            if inner.consecutive_successes >= RECOVERY_SUCCESS_THRESHOLD {
                inner.healthy = true;
            }
        }
        Self::snapshot_locked(&inner)
    }

    /// Record a backend failure. Immediately marks the backend unhealthy.
    pub fn record_failure(&self) -> BackendHealthSnapshot {
        #[allow(clippy::expect_used)]
        let mut inner = self.inner.lock().expect("backend health lock");
        let now = Instant::now();
        inner.last_failure_at = Some(now);
        inner.last_failure_unix = Some(Self::now_unix());
        inner.healthy = false;
        inner.consecutive_successes = 0;
        Self::snapshot_locked(&inner)
    }

    pub fn last_success_at(&self) -> Option<Instant> {
        #[allow(clippy::expect_used)]
        self.inner
            .lock()
            .expect("backend health lock")
            .last_success_at
    }

    pub fn last_failure_at(&self) -> Option<Instant> {
        #[allow(clippy::expect_used)]
        self.inner
            .lock()
            .expect("backend health lock")
            .last_failure_at
    }
}

/// Readiness display for the LocalOnly guarantee boundary.
///
/// Additive JSON fragment for `/readyz`. Documents that LocalOnly is only the
/// explicit one-node self-hosted development contract and cannot be entered at
/// runtime after a distributed backend failure. Readiness display wiring is
/// owned by; this helper is the consumer-owned fragment.
pub fn local_only_guarantee_boundary(requirement: DistributedRequirement) -> serde_json::Value {
    let active = matches!(requirement, DistributedRequirement::LocalOnly);
    serde_json::json!({
        "requirement": requirement.as_str(),
        "local_only_active": active,
        "local_only_admissible_only_for": "single_node_self_hosted_development",
        "runtime_transition_into_local_only_prohibited": true,
        "guarantee_boundary": if active {
            "process_local_state_only"
        } else if matches!(requirement, DistributedRequirement::Required) {
            "shared_distributed_backend_required"
        } else {
            "distributed_state_unused"
        },
        "failure_policy": DistributedFailurePolicy::for_requirement(requirement).as_str(),
    })
}

/// Classification for distributed backend failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributedBackendFailureKind {
    Unavailable,
    Command,
}

impl DistributedBackendFailureKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Command => "command",
        }
    }
}

/// Error reported by the distributed backend before degraded policy handling.
#[derive(Debug, Clone)]
pub struct DistributedBackendError {
    backend_name: &'static str,
    kind: DistributedBackendFailureKind,
    message: String,
}

impl DistributedBackendError {
    pub fn unavailable(backend_name: &'static str, message: impl Into<String>) -> Self {
        Self {
            backend_name,
            kind: DistributedBackendFailureKind::Unavailable,
            message: message.into(),
        }
    }

    pub fn command(backend_name: &'static str, message: impl Into<String>) -> Self {
        Self {
            backend_name,
            kind: DistributedBackendFailureKind::Command,
            message: message.into(),
        }
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend_name
    }

    pub fn kind(&self) -> DistributedBackendFailureKind {
        self.kind
    }
}

impl std::fmt::Display for DistributedBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} backend {} failure: {}",
            self.backend_name,
            self.kind.as_str(),
            self.message
        )
    }
}

impl std::error::Error for DistributedBackendError {}

/// Backend outcome before the caller's degraded policy is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributedCheckOutcome {
    Allowed { remaining: u64 },
    Denied,
}

#[cfg_attr(not(any(test, feature = "distributed")), allow(dead_code))]
fn distributed_reset_at(now_secs: u64, window_secs: u64, oldest_score_us: Option<f64>) -> u64 {
    let window_secs = window_secs.max(1);
    match oldest_score_us {
        Some(oldest_score_us) if oldest_score_us.is_finite() && oldest_score_us >= 0.0 => {
            let reset_at = ((oldest_score_us + (window_secs as f64 * 1_000_000.0)) / 1_000_000.0)
                .ceil() as u64;
            reset_at.max(now_secs)
        }
        _ => now_secs + window_secs,
    }
}

#[cfg(feature = "distributed")]
const REDIS_ATOMIC_RATE_LIMIT_SCRIPT: &str = r#"
-- verdictan_distributed_rate_limit_atomic_v1
local key = KEYS[1]
local min_score = tonumber(ARGV[1])
local now_score = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local ttl_secs = tonumber(ARGV[4])
local member = ARGV[5]

redis.call('ZREMRANGEBYSCORE', key, '-inf', min_score)
redis.call('ZADD', key, now_score, member)
local count = redis.call('ZCARD', key)

if count > limit then
  redis.call('ZREM', key, member)
  count = count - 1
  redis.call('EXPIRE', key, ttl_secs)
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local oldest_score = -1
  if oldest[2] ~= nil then
    oldest_score = tonumber(oldest[2])
  end
  return {0, count, oldest_score}
end

redis.call('EXPIRE', key, ttl_secs)

local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local oldest_score = -1
if oldest[2] ~= nil then
  oldest_score = tonumber(oldest[2])
end

return {1, count, oldest_score}
"#;

#[cfg(feature = "distributed")]
#[derive(Debug, Clone, Copy)]
struct AtomicRedisCheckResult {
    allowed: bool,
    count: u64,
    oldest_score_us: Option<f64>,
}

#[cfg(feature = "distributed")]
fn parse_atomic_redis_check_result(
    raw: (i64, i64, i64),
) -> Result<AtomicRedisCheckResult, &'static str> {
    let allowed = match raw.0 {
        0 => false,
        1 => true,
        _ => return Err("unexpected allowed flag"),
    };
    let count = u64::try_from(raw.1).map_err(|_| "negative count")?;
    let oldest_score_us = if raw.2 >= 0 { Some(raw.2 as f64) } else { None };
    Ok(AtomicRedisCheckResult {
        allowed,
        count,
        oldest_score_us,
    })
}

#[cfg(feature = "distributed")]
fn redis_i64_from_u64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

#[cfg(feature = "distributed")]
fn redis_i64_from_micros(value: u128) -> i64 {
    value.min(i64::MAX as u128) as i64
}

type DistributedBackendFuture<'a> = Pin<
    Box<dyn Future<Output = Result<DistributedCheckOutcome, DistributedBackendError>> + Send + 'a>,
>;

/// Injectable backend seam for deterministic tests.
#[doc(hidden)]
pub trait DistributedRateLimitBackend: Send + Sync {
    fn check_and_increment<'a>(&'a self, scope_key: &'a str) -> DistributedBackendFuture<'a>;
}

struct ScopedLocalWindow {
    count: u64,
    window_start: Instant,
}

struct ScopedLocalRateLimiter {
    config: GlobalRateLimitConfig,
    counters: Mutex<HashMap<String, ScopedLocalWindow>>,
}

impl ScopedLocalRateLimiter {
    fn new(config: GlobalRateLimitConfig) -> Self {
        Self {
            config,
            counters: Mutex::new(HashMap::new()),
        }
    }

    fn check_and_increment(&self, scope_key: &str) -> Result<u64, RequestRateLimitExceeded> {
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.config.window_seconds);
        #[allow(clippy::expect_used)]
        let mut counters = self.counters.lock().expect("scoped local rl lock");
        let entry = counters
            .entry(scope_key.to_string())
            .or_insert_with(|| ScopedLocalWindow {
                count: 0,
                window_start: now,
            });

        if now.duration_since(entry.window_start) >= window_duration {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;
        if entry.count > self.config.max_requests {
            Err(RequestRateLimitExceeded {
                retry_after_seconds: self.config.window_seconds,
                limit: self.config.max_requests,
                remaining: 0,
            })
        } else {
            Ok(self.config.max_requests.saturating_sub(entry.count))
        }
    }

    fn config(&self) -> &GlobalRateLimitConfig {
        &self.config
    }
}

/// In-process sliding-window counter used when distributed mode is off.
mod local_counter {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    struct WindowEntry {
        count: u64,
        window_start: u64,
    }

    static COUNTERS: OnceLock<Mutex<HashMap<String, WindowEntry>>> = OnceLock::new();

    fn counters() -> &'static Mutex<HashMap<String, WindowEntry>> {
        COUNTERS.get_or_init(Default::default)
    }

    /// Returns `(allowed, remaining, reset_at_unix_secs)` at an injected wall clock.
    pub fn check_and_increment_at(
        key: &str,
        limit: u64,
        window_secs: u64,
        now: u64,
    ) -> (bool, u64, u64) {
        let window_secs = window_secs.max(1);
        let window_start = (now / window_secs) * window_secs;
        let window_end = window_start + window_secs;

        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut guard = counters().lock().expect("local rate limit counter lock");
        let entry = guard.entry(key.to_string()).or_insert(WindowEntry {
            count: 0,
            window_start,
        });
        // New window: reset counter.
        if entry.window_start != window_start {
            entry.count = 0;
            entry.window_start = window_start;
        }
        if entry.count >= limit {
            (false, 0, window_end)
        } else {
            entry.count += 1;
            let remaining = limit.saturating_sub(entry.count);
            (true, remaining, window_end)
        }
    }
}

/// Check and (if allowed) record a rate limit hit against `DistributedState`.
///
/// - `tenant_id`: stable scope key; typically the gateway ID to preserve
///   tenant isolation across Redis keys.
/// - `limit`: maximum requests allowed in the window.
/// - `window_secs`: sliding-window duration in seconds.
///
/// When `state.is_distributed` is `true`, the check uses a Redis sorted-set
/// sliding window keyed by [`super::distributed_state::rate_limit_key`]. If
/// the Redis backend is unreachable the function returns a backend error and
/// leaves the admission policy to the caller. Central rollout-grade request
/// paths fail closed on that error; local-only/dev paths may still fail open.
///
/// When `state.is_distributed` is `false` (feature absent or no Redis
/// configured), falls back to an in-process fixed-window counter.
pub fn check_rate_limit(
    state: &super::distributed_state::DistributedState,
    tenant_id: &str,
    limit: u64,
    window_secs: u64,
) -> anyhow::Result<RateLimitResult> {
    // Suppress unused-variable warnings in the non-distributed compilation path.
    let _ = state;

    #[cfg(feature = "distributed")]
    let now_secs = state.now_unix_seconds();

    #[cfg(feature = "distributed")]
    if state.is_distributed() {
        let now_us = redis_i64_from_micros(state.now_unix_micros());
        let window_us = redis_i64_from_u64(window_secs).saturating_mul(1_000_000);
        let min_score = now_us.saturating_sub(window_us);
        let redis_key = super::distributed_state::rate_limit_key(tenant_id, "sliding");

        let Some(conn_result) = state.connection() else {
            tracing::warn!(
                tenant_id = %tenant_id,
                backend = %state.backend_name(),
                "distributed rate limit: no backend connection"
            );
            anyhow::bail!(
                "distributed rate limit backend connection unavailable for {}",
                state.backend_name()
            );
        };
        let mut conn = match conn_result {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    backend = %state.backend_name(),
                    error = %e,
                    "distributed rate limit: backend connection error"
                );
                return Err(anyhow::anyhow!(
                    "distributed rate limit backend connection error for {}: {e}",
                    state.backend_name()
                ));
            }
        };
        // Bound synchronous command latency for the atomic script path.
        let _ = conn.set_read_timeout(Some(DISTRIBUTED_COMMAND_TIMEOUT));
        let _ = conn.set_write_timeout(Some(DISTRIBUTED_COMMAND_TIMEOUT));

        let member = uuid::Uuid::new_v4().to_string();
        let raw: (i64, i64, i64) = redis::cmd("EVAL")
            .arg(REDIS_ATOMIC_RATE_LIMIT_SCRIPT)
            .arg(1)
            .arg(&redis_key)
            .arg(min_score)
            .arg(now_us)
            .arg(redis_i64_from_u64(limit))
            .arg(redis_i64_from_u64(window_secs.saturating_add(1)))
            .arg(&member)
            .query(&mut conn)
            .map_err(|error| {
                anyhow::anyhow!(
                    "distributed rate limit atomic check failed for {}: {error}",
                    state.backend_name()
                )
            })?;
        let outcome = parse_atomic_redis_check_result(raw).map_err(|error| {
            anyhow::anyhow!(
                "distributed rate limit backend returned invalid atomic result for {}: {error}",
                state.backend_name()
            )
        })?;

        if !outcome.allowed {
            return Ok(RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_at: distributed_reset_at(now_secs, window_secs, outcome.oldest_score_us),
            });
        }

        return Ok(RateLimitResult {
            allowed: true,
            remaining: limit.saturating_sub(outcome.count),
            reset_at: distributed_reset_at(now_secs, window_secs, outcome.oldest_score_us),
        });
    }

    // Local-only path (feature absent or no Redis configured).
    let (allowed, remaining, reset_at) = local_counter::check_and_increment_at(
        tenant_id,
        limit,
        window_secs,
        state.now_unix_seconds(),
    );
    Ok(RateLimitResult {
        allowed,
        remaining,
        reset_at,
    })
}

// ─── Config ──────────────────────────────────────────────────────────────────

/// The backing store for distributed coordination.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "backend")]
pub enum DistributedBackend {
    /// Redis sorted-set based sliding window.
    Redis {
        /// Name of the environment variable that holds the Redis connection URL.
        url_env: String,
    },
    /// Valkey sorted-set based sliding window using the Redis protocol.
    Valkey {
        /// Name of the environment variable that holds the Valkey connection URL.
        url_env: String,
    },
}

impl DistributedBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Redis { .. } => "redis",
            Self::Valkey { .. } => "valkey",
        }
    }

    pub fn url_env(&self) -> &str {
        match self {
            Self::Redis { url_env } | Self::Valkey { url_env } => url_env,
        }
    }
}

/// Optional distributed extension for any request-count or token-count limiter.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DistributedConfig {
    /// Which backend to use. Currently `redis` and `valkey` map to the same
    /// Redis protocol-backed implementation.
    #[serde(flatten)]
    pub backend: DistributedBackend,
}

// ─── Redis sliding-window limiter (only compiled in with `distributed`) ──────

#[cfg(feature = "distributed")]
mod redis_impl {
    use super::*;
    use std::collections::HashMap;
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::Mutex as AsyncMutex;

    /// Process-wide async pools shared by rate-limit and fingerprint consumers.
    fn shared_pools() -> &'static Mutex<HashMap<&'static str, Arc<AsyncRedisPool>>> {
        static POOLS: OnceLock<Mutex<HashMap<&'static str, Arc<AsyncRedisPool>>>> = OnceLock::new();
        POOLS.get_or_init(Default::default)
    }

    /// Register an async pool for sibling distributed consumers (fingerprint).
    pub fn register_async_redis_pool(backend_name: &'static str, pool: Arc<AsyncRedisPool>) {
        #[allow(clippy::expect_used)]
        let mut guard = shared_pools().lock().expect("async redis pool registry");
        guard.insert(backend_name, pool);
    }

    /// Lookup a previously registered async pool by backend name.
    pub fn shared_async_redis_pool(backend_name: &str) -> Option<Arc<AsyncRedisPool>> {
        #[allow(clippy::expect_used)]
        let guard = shared_pools().lock().expect("async redis pool registry");
        guard.get(backend_name).cloned()
    }

    /// Open (or reuse) an async pool from an explicit Redis/Valkey URL.
    pub fn async_redis_pool_from_url(
        redis_url: &str,
        backend_name: &'static str,
    ) -> Result<Arc<AsyncRedisPool>, redis::RedisError> {
        if let Some(existing) = shared_async_redis_pool(backend_name) {
            return Ok(existing);
        }
        let client = redis::Client::open(redis_url)?;
        let pool = Arc::new(AsyncRedisPool::new(
            client,
            backend_name,
            DISTRIBUTED_CONNECT_TIMEOUT,
            DISTRIBUTED_COMMAND_TIMEOUT,
        ));
        register_async_redis_pool(backend_name, Arc::clone(&pool));
        Ok(pool)
    }

    /// Async multiplexed connection pool with bounded connect/command timeouts.
    ///
    /// Multiplexed connections are cloneable and share one TCP session; we keep
    /// a single pooled handle and recreate it after transport failures.
    pub struct AsyncRedisPool {
        client: redis::Client,
        backend_name: &'static str,
        connect_timeout: Duration,
        command_timeout: Duration,
        pooled: AsyncMutex<Option<redis::aio::MultiplexedConnection>>,
    }

    impl AsyncRedisPool {
        pub fn new(
            client: redis::Client,
            backend_name: &'static str,
            connect_timeout: Duration,
            command_timeout: Duration,
        ) -> Self {
            Self {
                client,
                backend_name,
                connect_timeout,
                command_timeout,
                pooled: AsyncMutex::new(None),
            }
        }

        pub fn backend_name(&self) -> &'static str {
            self.backend_name
        }

        pub fn command_timeout(&self) -> Duration {
            self.command_timeout
        }

        pub async fn acquire(
            &self,
        ) -> Result<redis::aio::MultiplexedConnection, DistributedBackendError> {
            let mut guard = self.pooled.lock().await;
            if let Some(existing) = guard.as_ref() {
                return Ok(existing.clone());
            }
            let conn = tokio::time::timeout(
                self.connect_timeout,
                self.client.get_multiplexed_async_connection_with_timeouts(
                    self.command_timeout,
                    self.connect_timeout,
                ),
            )
            .await
            .map_err(|_| {
                DistributedBackendError::unavailable(
                    self.backend_name,
                    format!(
                        "connect timed out after {}ms",
                        self.connect_timeout.as_millis()
                    ),
                )
            })?
            .map_err(|error| {
                DistributedBackendError::unavailable(
                    self.backend_name,
                    format!("connection failed: {error}"),
                )
            })?;
            *guard = Some(conn.clone());
            Ok(conn)
        }

        pub async fn invalidate(&self) {
            let mut guard = self.pooled.lock().await;
            *guard = None;
        }

        pub async fn ping(&self) -> Result<(), DistributedBackendError> {
            let mut conn = self.acquire().await?;
            let result = tokio::time::timeout(
                self.command_timeout,
                redis::cmd("PING").query_async::<_, String>(&mut conn),
            )
            .await
            .map_err(|_| {
                DistributedBackendError::unavailable(
                    self.backend_name,
                    format!(
                        "PING timed out after {}ms",
                        self.command_timeout.as_millis()
                    ),
                )
            })?;
            match result {
                Ok(_) => Ok(()),
                Err(error) => {
                    self.invalidate().await;
                    Err(DistributedBackendError::command(
                        self.backend_name,
                        format!("PING failed: {error}"),
                    ))
                }
            }
        }

        /// Run an atomic EVAL script returning `(i64, String)` with command timeout.
        pub async fn eval_i64_string(
            &self,
            script: &str,
            key: &str,
            value: &str,
            ttl_ms: i64,
        ) -> Result<(i64, String), DistributedBackendError> {
            let mut conn = self.acquire().await?;
            let raw_result = tokio::time::timeout(
                self.command_timeout,
                redis::cmd("EVAL")
                    .arg(script)
                    .arg(1)
                    .arg(key)
                    .arg(value)
                    .arg(ttl_ms)
                    .query_async::<_, (i64, String)>(&mut conn),
            )
            .await
            .map_err(|_| {
                DistributedBackendError::command(
                    self.backend_name,
                    format!(
                        "atomic script timed out after {}ms",
                        self.command_timeout.as_millis()
                    ),
                )
            })?;
            match raw_result {
                Ok(value) => Ok(value),
                Err(error) => {
                    self.invalidate().await;
                    Err(DistributedBackendError::command(
                        self.backend_name,
                        format!("atomic script failed: {error}"),
                    ))
                }
            }
        }
    }

    /// A Redis-backed sliding-window rate limiter using sorted sets.
    ///
    /// Each distinct `scope_key` maps to a sorted-set key in Redis. Members
    /// are request UUIDs; scores are microsecond Unix timestamps. A single
    /// atomic Redis script performs cleanup, admission, rollback-on-overflow,
    /// and expiry updates so concurrent workers cannot overshoot the ceiling.
    pub struct RedisRateLimiter {
        pub config: crate::gateway::rate_limit::GlobalRateLimitConfig,
        pub pool: Arc<AsyncRedisPool>,
        pub backend_name: &'static str,
    }

    impl RedisRateLimiter {
        pub fn new(
            config: crate::gateway::rate_limit::GlobalRateLimitConfig,
            backend_name: &'static str,
            redis_url: &str,
        ) -> Result<Self, redis::RedisError> {
            let client = redis::Client::open(redis_url)?;
            let pool = Arc::new(AsyncRedisPool::new(
                client,
                backend_name,
                DISTRIBUTED_CONNECT_TIMEOUT,
                DISTRIBUTED_COMMAND_TIMEOUT,
            ));
            register_async_redis_pool(backend_name, Arc::clone(&pool));
            Ok(Self {
                config,
                pool,
                backend_name,
            })
        }

        pub async fn probe(&self) -> Result<(), DistributedBackendError> {
            self.pool.ping().await
        }
    }

    impl DistributedRateLimitBackend for RedisRateLimiter {
        fn check_and_increment<'a>(&'a self, scope_key: &'a str) -> DistributedBackendFuture<'a> {
            Box::pin(async move {
                let mut conn = self.pool.acquire().await?;

                let now_us = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros();
                let now_us = redis_i64_from_micros(now_us);
                let window_us =
                    redis_i64_from_u64(self.config.window_seconds).saturating_mul(1_000_000);
                let min_score = now_us.saturating_sub(window_us);
                let redis_key = format!("vt:rl:{}", scope_key);
                let member = uuid::Uuid::new_v4().to_string();
                let raw_result = tokio::time::timeout(
                    self.pool.command_timeout(),
                    redis::cmd("EVAL")
                        .arg(REDIS_ATOMIC_RATE_LIMIT_SCRIPT)
                        .arg(1)
                        .arg(&redis_key)
                        .arg(min_score)
                        .arg(now_us)
                        .arg(redis_i64_from_u64(self.config.max_requests))
                        .arg(redis_i64_from_u64(
                            self.config.window_seconds.saturating_add(1),
                        ))
                        .arg(&member)
                        .query_async::<_, (i64, i64, i64)>(&mut conn),
                )
                .await
                .map_err(|_| {
                    DistributedBackendError::command(
                        self.backend_name,
                        format!(
                            "atomic check timed out after {}ms",
                            self.pool.command_timeout().as_millis()
                        ),
                    )
                })?;
                let raw = raw_result.map_err(|error| {
                    // Drop the pooled handle so the next call reconnects.
                    // Best-effort; ignore join errors from the async invalidate.
                    DistributedBackendError::command(
                        self.backend_name,
                        format!("atomic check failed: {error}"),
                    )
                });
                let raw = match raw {
                    Ok(value) => value,
                    Err(error) => {
                        self.pool.invalidate().await;
                        return Err(error);
                    }
                };
                let outcome = parse_atomic_redis_check_result(raw).map_err(|error| {
                    DistributedBackendError::command(
                        self.backend_name,
                        format!("invalid atomic result: {error}"),
                    )
                })?;

                if outcome.allowed {
                    Ok(DistributedCheckOutcome::Allowed {
                        remaining: self.config.max_requests.saturating_sub(outcome.count),
                    })
                } else {
                    Ok(DistributedCheckOutcome::Denied)
                }
            })
        }
    }
}

/// Shared async Redis/Valkey pool helpers used by fingerprint and other
/// distributed consumers.
#[cfg(feature = "distributed")]
pub use redis_impl::{async_redis_pool_from_url, shared_async_redis_pool, AsyncRedisPool};

// ─── Unified distributed limiter with local fallback ─────────────────────────

/// A rate limiter that prefers the distributed back-end when compiled in and
/// reachable, and applies an explicit degraded policy on backend failure.
pub struct DistributedRateLimiter {
    local: Arc<ScopedLocalRateLimiter>,
    failure_policy: DistributedFailurePolicy,
    backend: Option<Arc<dyn DistributedRateLimitBackend>>,
    health: Arc<BackendHealthTracker>,
    /// Optional probe used for two-success recovery without mutating counters.
    #[cfg(feature = "distributed")]
    recovery_probe: Option<Arc<redis_impl::RedisRateLimiter>>,
    #[cfg(not(feature = "distributed"))]
    recovery_probe: Option<()>,
}

impl DistributedRateLimiter {
    /// Build with a local fallback only (used when `distributed` feature is off
    /// or when no `DistributedConfig` is provided).
    pub fn local_only(config: GlobalRateLimitConfig) -> Self {
        Self::local_only_with_policy(config, DistributedFailurePolicy::LocalEnforcement)
    }

    fn local_only_with_policy(
        config: GlobalRateLimitConfig,
        failure_policy: DistributedFailurePolicy,
    ) -> Self {
        Self {
            local: Arc::new(ScopedLocalRateLimiter::new(config)),
            failure_policy,
            backend: None,
            health: Arc::new(BackendHealthTracker::new()),
            recovery_probe: None,
        }
    }

    /// Build with an optional Redis back-end. If the Redis URL resolves but
    /// the client fails to initialise, a warning is logged and the limiter
    /// operates in local-only mode.
    pub fn from_config(
        config: GlobalRateLimitConfig,
        distributed: Option<&DistributedConfig>,
    ) -> Self {
        Self::from_config_with_policy(
            config,
            distributed,
            DistributedFailurePolicy::LocalEnforcement,
        )
    }

    /// Build using the immutable distributed requirement to select FailClosed
    /// vs LocalEnforcement. Requirement is never inferred from backend health.
    pub fn from_config_for_requirement(
        config: GlobalRateLimitConfig,
        distributed: Option<&DistributedConfig>,
        requirement: DistributedRequirement,
    ) -> Self {
        Self::from_config_with_policy(
            config,
            distributed,
            DistributedFailurePolicy::for_requirement(requirement),
        )
    }

    pub fn from_config_with_policy(
        config: GlobalRateLimitConfig,
        distributed: Option<&DistributedConfig>,
        failure_policy: DistributedFailurePolicy,
    ) -> Self {
        #[cfg(feature = "distributed")]
        {
            if let Some(dist) = distributed {
                let url_env = dist.backend.url_env();
                let redis_url = std::env::var(url_env).unwrap_or_default();
                if !redis_url.is_empty() {
                    match redis_impl::RedisRateLimiter::new(
                        config.clone(),
                        dist.backend.as_str(),
                        &redis_url,
                    ) {
                        Ok(redis) => {
                            tracing::info!(
                                backend = %dist.backend.as_str(),
                                url_env = %url_env,
                                failure_policy = %failure_policy.as_str(),
                                "distributed rate limiter initialised"
                            );
                            let redis = Arc::new(redis);
                            return Self {
                                local: Arc::new(ScopedLocalRateLimiter::new(config)),
                                failure_policy,
                                backend: Some(redis.clone() as Arc<dyn DistributedRateLimitBackend>),
                                health: Arc::new(BackendHealthTracker::new()),
                                recovery_probe: Some(redis),
                            };
                        }
                        Err(e) => {
                            tracing::warn!(
                                backend = %dist.backend.as_str(),
                                error = %e,
                                url_env = %url_env,
                                "failed to initialise distributed rate limiter backend, using local"
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        backend = %dist.backend.as_str(),
                        url_env = %url_env,
                        "distributed rate limit configured but backend URL env var is empty, using local"
                    );
                }
            }
            Self::local_only_with_policy(config, failure_policy)
        }

        #[cfg(not(feature = "distributed"))]
        {
            if distributed.is_some() {
                tracing::warn!(
                    "distributed rate limit configured but 'distributed' feature is not compiled in; \
                     using local in-memory fallback"
                );
            }
            Self::local_only_with_policy(config, failure_policy)
        }
    }

    #[doc(hidden)]
    fn with_backend_for_tests(
        config: GlobalRateLimitConfig,
        failure_policy: DistributedFailurePolicy,
        backend: Arc<dyn DistributedRateLimitBackend>,
    ) -> Self {
        Self {
            local: Arc::new(ScopedLocalRateLimiter::new(config)),
            failure_policy,
            backend: Some(backend),
            health: Arc::new(BackendHealthTracker::new()),
            recovery_probe: None,
        }
    }

    #[doc(hidden)]
    fn with_backend_and_health_for_tests(
        config: GlobalRateLimitConfig,
        failure_policy: DistributedFailurePolicy,
        backend: Arc<dyn DistributedRateLimitBackend>,
        health: Arc<BackendHealthTracker>,
    ) -> Self {
        Self {
            local: Arc::new(ScopedLocalRateLimiter::new(config)),
            failure_policy,
            backend: Some(backend),
            health,
            recovery_probe: None,
        }
    }

    pub fn failure_policy(&self) -> DistributedFailurePolicy {
        self.failure_policy
    }

    pub fn health(&self) -> &BackendHealthTracker {
        &self.health
    }

    pub fn health_snapshot(&self) -> BackendHealthSnapshot {
        self.health.snapshot()
    }

    fn limit_exceeded(&self) -> RequestRateLimitExceeded {
        RequestRateLimitExceeded {
            retry_after_seconds: self.local.config().window_seconds,
            limit: self.local.config().max_requests,
            remaining: 0,
        }
    }

    fn apply_backend_failure(
        &self,
        scope_key: &str,
        error: &DistributedBackendError,
    ) -> Result<u64, RequestRateLimitExceeded> {
        let snapshot = self.health.record_failure();
        tracing::warn!(
            scope_key = %scope_key,
            backend = %error.backend_name(),
            failure_kind = %error.kind().as_str(),
            degraded_policy = %self.failure_policy.as_str(),
            last_failure_unix = ?snapshot.last_failure_unix,
            consecutive_successes = snapshot.consecutive_successes,
            error = %error,
            "distributed rate limit backend failed"
        );

        match self.failure_policy {
            DistributedFailurePolicy::LocalEnforcement => self.local.check_and_increment(scope_key),
            DistributedFailurePolicy::FailClosed => Err(self.limit_exceeded()),
        }
    }

    /// When unhealthy under FailClosed, probe without mutating counters until
    /// two consecutive successes restore health.
    async fn recover_if_needed(&self) -> Result<(), RequestRateLimitExceeded> {
        if self.health.is_healthy() {
            return Ok(());
        }

        match self.failure_policy {
            DistributedFailurePolicy::LocalEnforcement => Ok(()),
            DistributedFailurePolicy::FailClosed => {
                #[cfg(feature = "distributed")]
                if let Some(probe) = &self.recovery_probe {
                    match probe.probe().await {
                        Ok(()) => {
                            let snapshot = self.health.record_success();
                            tracing::info!(
                                consecutive_successes = snapshot.consecutive_successes,
                                healthy = snapshot.healthy,
                                last_success_unix = ?snapshot.last_success_unix,
                                "distributed rate limit recovery probe succeeded"
                            );
                            if snapshot.healthy {
                                return Ok(());
                            }
                            return Err(self.limit_exceeded());
                        }
                        Err(error) => {
                            self.health.record_failure();
                            tracing::warn!(
                                error = %error,
                                "distributed rate limit recovery probe failed"
                            );
                            return Err(self.limit_exceeded());
                        }
                    }
                }
                // Injected backends: treat the next real check as the recovery probe.
                Ok(())
            }
        }
    }

    /// Check and increment, preferring the distributed back-end when available.
    pub async fn check_and_increment(
        &self,
        scope_key: &str,
    ) -> Result<u64, RequestRateLimitExceeded> {
        if let Some(backend) = &self.backend {
            if !self.health.is_healthy() {
                self.recover_if_needed().await?;
                if !self.health.is_healthy()
                    && self.failure_policy == DistributedFailurePolicy::FailClosed
                    && self.recovery_probe.is_some()
                {
                    return Err(self.limit_exceeded());
                }
                if !self.health.is_healthy()
                    && self.failure_policy == DistributedFailurePolicy::LocalEnforcement
                {
                    return self.local.check_and_increment(scope_key);
                }
            }

            return match backend.check_and_increment(scope_key).await {
                Ok(DistributedCheckOutcome::Allowed { remaining }) => {
                    let snapshot = self.health.record_success();
                    if self.failure_policy == DistributedFailurePolicy::FailClosed
                        && !snapshot.healthy
                    {
                        // First success during recovery does not admit traffic.
                        return Err(self.limit_exceeded());
                    }
                    Ok(remaining)
                }
                Ok(DistributedCheckOutcome::Denied) => {
                    self.health.record_success();
                    Err(self.limit_exceeded())
                }
                Err(error) => self.apply_backend_failure(scope_key, &error),
            };
        }

        // Local-only path (sync, so we block briefly — acceptable for the proxy).
        self.local.check_and_increment(scope_key)
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
    use std::sync::Mutex;

    #[test]
    fn distributed_reset_at_falls_back_to_now_plus_window_without_history() {
        assert_eq!(distributed_reset_at(100, 60, None), 160);
    }

    #[test]
    fn distributed_reset_at_uses_oldest_surviving_score() {
        let oldest_score_us = 150_250_000.0;
        assert_eq!(distributed_reset_at(200, 60, Some(oldest_score_us)), 211);
    }

    #[test]
    fn distributed_reset_at_never_reports_a_past_boundary() {
        let stale_score_us = 50_000_000.0;
        assert_eq!(distributed_reset_at(200, 60, Some(stale_score_us)), 200);
    }

    #[test]
    fn distributed_reset_at_clamps_zero_window_to_one() {
        assert_eq!(distributed_reset_at(100, 0, None), 101);
    }

    // ── Mock backend ─────────────────────────────────────────────────────

    struct MockBackend {
        outcome: Mutex<Result<DistributedCheckOutcome, DistributedBackendError>>,
    }

    impl MockBackend {
        fn allowed(remaining: u64) -> Arc<Self> {
            Arc::new(Self {
                outcome: Mutex::new(Ok(DistributedCheckOutcome::Allowed { remaining })),
            })
        }

        fn denied() -> Arc<Self> {
            Arc::new(Self {
                outcome: Mutex::new(Ok(DistributedCheckOutcome::Denied)),
            })
        }

        fn unavailable() -> Arc<Self> {
            Arc::new(Self {
                outcome: Mutex::new(Err(DistributedBackendError::unavailable(
                    "mock",
                    "simulated outage",
                ))),
            })
        }

        fn command_error() -> Arc<Self> {
            Arc::new(Self {
                outcome: Mutex::new(Err(DistributedBackendError::command(
                    "mock",
                    "simulated command error",
                ))),
            })
        }
    }

    impl DistributedRateLimitBackend for MockBackend {
        fn check_and_increment<'a>(&'a self, _scope_key: &'a str) -> DistributedBackendFuture<'a> {
            #[allow(clippy::expect_used)]
            let result = self.outcome.lock().expect("mock lock").clone();
            Box::pin(async move { result })
        }
    }

    fn test_config() -> GlobalRateLimitConfig {
        GlobalRateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
        }
    }

    // ── DistributedRateLimiter with mock backend ─────────────────────────

    #[tokio::test]
    async fn backend_allowed_passes_through() {
        let limiter = DistributedRateLimiter::with_backend_for_tests(
            test_config(),
            DistributedFailurePolicy::FailClosed,
            MockBackend::allowed(9),
        );
        let result = limiter.check_and_increment("tenant-1").await;
        assert_eq!(result.unwrap(), 9);
    }

    #[tokio::test]
    async fn backend_denied_returns_exceeded() {
        let limiter = DistributedRateLimiter::with_backend_for_tests(
            test_config(),
            DistributedFailurePolicy::LocalEnforcement,
            MockBackend::denied(),
        );
        let result = limiter.check_and_increment("tenant-1").await;
        let err = result.unwrap_err();
        assert_eq!(err.limit, 10);
        assert_eq!(err.remaining, 0);
    }

    #[tokio::test]
    async fn backend_unavailable_local_enforcement_falls_back() {
        let limiter = DistributedRateLimiter::with_backend_for_tests(
            test_config(),
            DistributedFailurePolicy::LocalEnforcement,
            MockBackend::unavailable(),
        );
        let result = limiter.check_and_increment("tenant-fallback").await;
        assert!(
            result.is_ok(),
            "local enforcement should allow the first request"
        );
        assert_eq!(result.unwrap(), 9);
    }

    #[tokio::test]
    async fn backend_unavailable_fail_closed_policy_rejects() {
        let limiter = DistributedRateLimiter::with_backend_for_tests(
            test_config(),
            DistributedFailurePolicy::FailClosed,
            MockBackend::unavailable(),
        );
        let result = limiter.check_and_increment("tenant-deny").await;
        assert!(
            result.is_err(),
            "fail-closed policy should reject on backend failure"
        );
        assert!(!limiter.health().is_healthy());
        assert!(limiter.health_snapshot().last_failure_unix.is_some());
    }

    #[tokio::test]
    async fn backend_command_error_triggers_degraded_policy() {
        let limiter = DistributedRateLimiter::with_backend_for_tests(
            test_config(),
            DistributedFailurePolicy::FailClosed,
            MockBackend::command_error(),
        );
        let result = limiter.check_and_increment("tenant-cmd-err").await;
        assert!(
            result.is_err(),
            "fail-closed policy should reject on command error"
        );
    }

    // ── Local-only limiter ───────────────────────────────────────────────

    #[tokio::test]
    async fn local_only_limiter_enforces_ceiling() {
        let config = GlobalRateLimitConfig {
            max_requests: 3,
            window_seconds: 60,
        };
        let limiter = DistributedRateLimiter::local_only(config);
        assert!(limiter.check_and_increment("local-test").await.is_ok());
        assert!(limiter.check_and_increment("local-test").await.is_ok());
        assert!(limiter.check_and_increment("local-test").await.is_ok());
        let fourth = limiter.check_and_increment("local-test").await;
        assert!(fourth.is_err(), "should reject after max_requests");
    }

    #[tokio::test]
    async fn local_only_scopes_are_independent() {
        let config = GlobalRateLimitConfig {
            max_requests: 1,
            window_seconds: 60,
        };
        let limiter = DistributedRateLimiter::local_only(config);
        assert!(limiter.check_and_increment("scope-a").await.is_ok());
        assert!(limiter.check_and_increment("scope-b").await.is_ok());
        assert!(limiter.check_and_increment("scope-a").await.is_err());
    }

    // ── DistributedBackendError display ──────────────────────────────────

    #[test]
    fn backend_error_display_includes_kind_and_message() {
        let err = DistributedBackendError::unavailable("redis", "connection refused");
        let display = err.to_string();
        assert!(display.contains("redis"));
        assert!(display.contains("unavailable"));
        assert!(display.contains("connection refused"));
    }

    #[test]
    fn backend_error_command_kind_is_correct() {
        let err = DistributedBackendError::command("valkey", "EVAL failed");
        assert_eq!(err.kind(), DistributedBackendFailureKind::Command);
        assert_eq!(err.backend_name(), "valkey");
    }

    // ── DistributedFailurePolicy ─────────────────────────────────────────

    #[test]
    fn failure_policy_as_str_values() {
        assert_eq!(
            DistributedFailurePolicy::LocalEnforcement.as_str(),
            "local_enforcement"
        );
        assert_eq!(DistributedFailurePolicy::FailClosed.as_str(), "fail_closed");
        assert_eq!(
            DistributedFailurePolicy::Deny,
            DistributedFailurePolicy::FailClosed
        );
    }

    #[test]
    fn failure_policy_for_requirement_matrix() {
        assert_eq!(
            DistributedFailurePolicy::for_requirement(DistributedRequirement::Required),
            DistributedFailurePolicy::FailClosed
        );
        assert_eq!(
            DistributedFailurePolicy::for_requirement(DistributedRequirement::LocalOnly),
            DistributedFailurePolicy::LocalEnforcement
        );
        assert_eq!(
            DistributedFailurePolicy::for_requirement(DistributedRequirement::Disabled),
            DistributedFailurePolicy::LocalEnforcement
        );
    }

    #[test]
    fn local_only_guarantee_boundary_documents_contract() {
        let local = local_only_guarantee_boundary(DistributedRequirement::LocalOnly);
        assert_eq!(local["local_only_active"], true);
        assert_eq!(
            local["local_only_admissible_only_for"],
            "single_node_self_hosted_development"
        );
        assert_eq!(local["runtime_transition_into_local_only_prohibited"], true);
        assert_eq!(local["guarantee_boundary"], "process_local_state_only");

        let required = local_only_guarantee_boundary(DistributedRequirement::Required);
        assert_eq!(required["local_only_active"], false);
        assert_eq!(
            required["guarantee_boundary"],
            "shared_distributed_backend_required"
        );
        assert_eq!(required["failure_policy"], "fail_closed");
    }

    #[test]
    fn backend_health_requires_two_successes_to_recover() {
        let health = BackendHealthTracker::new();
        assert!(health.is_healthy());
        health.record_failure();
        assert!(!health.is_healthy());
        assert_eq!(health.snapshot().consecutive_successes, 0);
        assert!(health.snapshot().last_failure_unix.is_some());

        let first = health.record_success();
        assert!(!first.healthy, "one success must not restore health");
        assert_eq!(first.consecutive_successes, 1);
        assert!(first.last_success_unix.is_some());

        let second = health.record_success();
        assert!(second.healthy, "two successes restore health");
        assert_eq!(second.consecutive_successes, RECOVERY_SUCCESS_THRESHOLD);
    }

    #[tokio::test]
    async fn fail_closed_requires_two_successes_before_admission() {
        let health = Arc::new(BackendHealthTracker::new());
        health.record_failure();
        let backend = MockBackend::allowed(9);
        let limiter = DistributedRateLimiter::with_backend_and_health_for_tests(
            test_config(),
            DistributedFailurePolicy::FailClosed,
            backend.clone(),
            Arc::clone(&health),
        );

        let first = limiter.check_and_increment("recover-1").await;
        assert!(first.is_err(), "first recovery success must not admit");
        assert!(!health.is_healthy());

        let second = limiter.check_and_increment("recover-1").await;
        assert_eq!(second.unwrap(), 9);
        assert!(health.is_healthy());
    }

    // ── DistributedBackendFailureKind ─────────────────────────────────────

    #[test]
    fn backend_failure_kind_as_str() {
        assert_eq!(
            DistributedBackendFailureKind::Unavailable.as_str(),
            "unavailable"
        );
        assert_eq!(DistributedBackendFailureKind::Command.as_str(), "command");
    }

    // ── DistributedBackend config ─────────────────────────────────────────

    #[test]
    fn distributed_backend_redis_as_str_and_url_env() {
        let backend = DistributedBackend::Redis {
            url_env: "MY_REDIS_URL".to_string(),
        };
        assert_eq!(backend.as_str(), "redis");
        assert_eq!(backend.url_env(), "MY_REDIS_URL");
    }

    #[test]
    fn distributed_backend_valkey_as_str_and_url_env() {
        let backend = DistributedBackend::Valkey {
            url_env: "MY_VALKEY_URL".to_string(),
        };
        assert_eq!(backend.as_str(), "valkey");
        assert_eq!(backend.url_env(), "MY_VALKEY_URL");
    }

    #[test]
    fn distributed_backend_serde_round_trips() {
        let config = DistributedConfig {
            backend: DistributedBackend::Redis {
                url_env: "REDIS_URL".to_string(),
            },
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let deserialized: DistributedConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.backend.as_str(), "redis");
        assert_eq!(deserialized.backend.url_env(), "REDIS_URL");
    }

    #[test]
    fn distributed_backend_valkey_serde_round_trips() {
        let config = DistributedConfig {
            backend: DistributedBackend::Valkey {
                url_env: "VALKEY_URL".to_string(),
            },
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let deserialized: DistributedConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.backend.as_str(), "valkey");
        assert_eq!(deserialized.backend.url_env(), "VALKEY_URL");
    }

    // ── DistributedBackendError ───────────────────────────────────────────

    #[test]
    fn backend_error_is_std_error() {
        let err = DistributedBackendError::unavailable("redis", "down");
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.to_string().contains("redis"));
    }

    // ── DistributedCheckOutcome variants ──────────────────────────────────

    #[test]
    fn distributed_check_outcome_variants_are_correct() {
        let allowed = DistributedCheckOutcome::Allowed { remaining: 5 };
        assert_eq!(allowed, DistributedCheckOutcome::Allowed { remaining: 5 });
        let denied = DistributedCheckOutcome::Denied;
        assert_eq!(denied, DistributedCheckOutcome::Denied);
    }

    // ── local_counter ─────────────────────────────────────────────────────

    #[test]
    fn local_counter_enforces_limit_within_window() {
        let key = format!("local-counter-test-{}", uuid::Uuid::new_v4());
        let (allowed, remaining, _) = local_counter::check_and_increment_at(&key, 2, 60, 120);
        assert!(allowed);
        assert_eq!(remaining, 1);

        let (allowed, remaining, _) = local_counter::check_and_increment_at(&key, 2, 60, 121);
        assert!(allowed);
        assert_eq!(remaining, 0);

        let (allowed, remaining, _) = local_counter::check_and_increment_at(&key, 2, 60, 122);
        assert!(!allowed);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn local_counter_zero_window_treated_as_one() {
        let key = format!("local-counter-zero-window-{}", uuid::Uuid::new_v4());
        let (_, _, reset_at) = local_counter::check_and_increment_at(&key, 10, 0, 42);
        assert_eq!(reset_at, 43);
    }

    // ── from_config without distributed ───────────────────────────────────

    #[tokio::test]
    async fn from_config_none_creates_local_only() {
        let limiter = DistributedRateLimiter::from_config(
            GlobalRateLimitConfig {
                max_requests: 2,
                window_seconds: 60,
            },
            None,
        );
        let scope = format!("local-only-{}", uuid::Uuid::new_v4());
        assert!(limiter.check_and_increment(&scope).await.is_ok());
        assert!(limiter.check_and_increment(&scope).await.is_ok());
        assert!(limiter.check_and_increment(&scope).await.is_err());
    }

    #[test]
    fn rate_limit_result_fields() {
        let result = RateLimitResult {
            allowed: true,
            remaining: 42,
            reset_at: 1700000000,
        };
        assert!(result.allowed);
        assert_eq!(result.remaining, 42);
        assert_eq!(result.reset_at, 1700000000);
    }

    // ── check_rate_limit non-distributed path ─────────────────────────────

    #[tokio::test]
    async fn check_rate_limit_local_only_enforces_limit() {
        let state = super::super::distributed_state::DistributedState::new(None, "redis")
            .await
            .expect("local state");
        let tenant = format!("check-rl-local-{}", uuid::Uuid::new_v4());
        let first = check_rate_limit(&state, &tenant, 1, 60).expect("first");
        assert!(first.allowed);
        assert_eq!(first.remaining, 0);

        let second = check_rate_limit(&state, &tenant, 1, 60).expect("second");
        assert!(!second.allowed);
        assert_eq!(second.remaining, 0);
    }

    // ── distributed_reset_at edge cases ───────────────────────────────────

    #[test]
    fn distributed_reset_at_infinite_score_uses_fallback() {
        assert_eq!(distributed_reset_at(100, 60, Some(f64::INFINITY)), 160);
        assert_eq!(distributed_reset_at(100, 60, Some(f64::NEG_INFINITY)), 160);
        assert_eq!(distributed_reset_at(100, 60, Some(f64::NAN)), 160);
    }

    #[test]
    fn distributed_reset_at_negative_score_uses_fallback() {
        assert_eq!(distributed_reset_at(100, 60, Some(-1.0)), 160);
    }

    // ── parse_atomic_redis_check_result ───────────────────────────────────

    #[cfg(feature = "distributed")]
    #[test]
    fn parse_atomic_redis_allowed_result() {
        let result = parse_atomic_redis_check_result((1, 3, 150_000_000)).unwrap();
        assert!(result.allowed);
        assert_eq!(result.count, 3);
        assert_eq!(result.oldest_score_us, Some(150_000_000.0));
    }

    #[cfg(feature = "distributed")]
    #[test]
    fn parse_atomic_redis_denied_result() {
        let result = parse_atomic_redis_check_result((0, 10, -1)).unwrap();
        assert!(!result.allowed);
        assert_eq!(result.count, 10);
        assert_eq!(result.oldest_score_us, None);
    }

    #[cfg(feature = "distributed")]
    #[test]
    fn parse_atomic_redis_unexpected_flag_errors() {
        let err = parse_atomic_redis_check_result((2, 0, 0));
        assert!(err.is_err());
    }

    #[cfg(feature = "distributed")]
    #[test]
    fn parse_atomic_redis_negative_count_errors() {
        let err = parse_atomic_redis_check_result((1, -1, 0));
        assert!(err.is_err());
    }

    #[cfg(feature = "distributed")]
    #[test]
    fn redis_i64_from_u64_clamps_large_values() {
        assert_eq!(redis_i64_from_u64(0), 0);
        assert_eq!(redis_i64_from_u64(100), 100);
        assert_eq!(redis_i64_from_u64(u64::MAX), i64::MAX);
    }

    #[cfg(feature = "distributed")]
    #[test]
    fn redis_i64_from_micros_clamps_large_values() {
        assert_eq!(redis_i64_from_micros(0), 0);
        assert_eq!(redis_i64_from_micros(1_000_000), 1_000_000);
        assert_eq!(redis_i64_from_micros(u128::MAX), i64::MAX);
    }
}
