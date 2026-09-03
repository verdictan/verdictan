// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Centralized distributed state for multi-instance gateway coordination.
//!
//! When compiled with `--features distributed` this module exposes a
//! [`DistributedState`] that holds a Redis connection pool and provides
//! shared key-naming helpers used by both rate limiting and fingerprint
//! deduplication. Without the feature flag the struct is always a local-only
//! no-op so callers never need to `#[cfg(…)]` at the call site.
//!
//! [`DistributedRequirement`] is the immutable deployment/policy contract for
//! whether shared state is unused ([`DistributedRequirement::Disabled`]),
//! confined to an explicit single-node development profile
//! ([`DistributedRequirement::LocalOnly`]), or mandatory
//! ([`DistributedRequirement::Required`]). Derivation uses only deployment
//! profile and enabled policy capabilities — never backend health. `LocalOnly`
//! is never selected after a distributed backend failure.
//!
//! [`DistributedRequirement::Required`] fails startup on missing URL
//! or init failure. Runtime backend loss marks the state unavailable so
//! dependent requests and `/readyz` return
//! [`DISTRIBUTED_STATE_UNAVAILABLE_REASON`] (`503`). Connected-mode must not
//! silently fall back to process-local admission.

#![cfg_attr(not(feature = "distributed"), allow(dead_code, unused_imports))]

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use super::clock::{Clock, SystemClock};

/// Stable reason code for required distributed-state loss.
pub const DISTRIBUTED_STATE_UNAVAILABLE_REASON: &str = "dependency.distributed_state_unavailable";

/// Consecutive successful probes required before an unhealthy required backend
/// recovers for dependent-request admission and `/readyz`.
pub const RUNTIME_RECOVERY_SUCCESS_THRESHOLD: u32 = 2;

// ─── TTL constants ────────────────────────────────────────────────────────────

/// Default window for distributed rate limiting (seconds).
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Default TTL for fingerprint deduplication (seconds).
const FINGERPRINT_DEDUP_TTL_SECS: u64 = 300;

// ─── Key-naming helpers ───────────────────────────────────────────────────────

/// Redis key for a tenant-scoped rate limit sorted set.
///
/// `window` is a stable bucket identifier, e.g. `"sliding"` for a sliding-
/// window sorted set or a numeric epoch bucket for a fixed-window counter.
pub fn rate_limit_key(tenant_id: &str, window: &str) -> String {
    format!("vt:rl:{tenant_id}:{window}")
}

/// Redis key for a tenant-scoped request fingerprint entry.
pub fn fingerprint_key(tenant_id: &str, fingerprint: &str) -> String {
    format!("vt:fp:{tenant_id}:{fingerprint}")
}

// ─── Distributed requirement contract ──────────────────────────────

/// Policy features that consume shared distributed state when enabled.
///
/// These are the only required-state consumers recognized by the gateway
/// requirement matrix. Enumeration is exhaustive and intentional.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequiredStateConsumer {
    /// Cross-instance request rate limiting.
    RateLimits,
    /// Budget / funding reservation admission.
    Budgets,
    /// Request fingerprint coordination.
    Fingerprints,
    /// Org-shared cache admission and coordination.
    SharedCacheAdmission,
    /// Replay protection / idempotent request deduplication.
    ReplayProtection,
}

impl RequiredStateConsumer {
    /// Stable snake_case identifier for readiness and evidence surfaces.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RateLimits => "rate_limits",
            Self::Budgets => "budgets",
            Self::Fingerprints => "fingerprints",
            Self::SharedCacheAdmission => "shared_cache_admission",
            Self::ReplayProtection => "replay_protection",
        }
    }
}

/// Complete set of required-state consumers in stable declaration order.
pub const REQUIRED_STATE_CONSUMERS: &[RequiredStateConsumer] = &[
    RequiredStateConsumer::RateLimits,
    RequiredStateConsumer::Budgets,
    RequiredStateConsumer::Fingerprints,
    RequiredStateConsumer::SharedCacheAdmission,
    RequiredStateConsumer::ReplayProtection,
];

/// Enabled policy capabilities that may require shared distributed state.
///
/// Built from declarative / runtime policy configuration. Must never be
/// inferred from Redis/Valkey health or connectivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DistributedPolicyCapabilities {
    pub rate_limits: bool,
    pub budgets: bool,
    pub fingerprints: bool,
    pub shared_cache_admission: bool,
    pub replay_protection: bool,
}

impl DistributedPolicyCapabilities {
    /// Construct from explicit per-consumer enablement flags.
    pub fn from_enabled_flags(
        rate_limits: bool,
        budgets: bool,
        fingerprints: bool,
        shared_cache_admission: bool,
        replay_protection: bool,
    ) -> Self {
        Self {
            rate_limits,
            budgets,
            fingerprints,
            shared_cache_admission,
            replay_protection,
        }
    }

    /// True when at least one required-state consumer is enabled.
    pub fn requires_shared_state(self) -> bool {
        self.rate_limits
            || self.budgets
            || self.fingerprints
            || self.shared_cache_admission
            || self.replay_protection
    }

    /// Enabled consumers in [`REQUIRED_STATE_CONSUMERS`] declaration order.
    fn enabled_consumers(self) -> Vec<RequiredStateConsumer> {
        REQUIRED_STATE_CONSUMERS
            .iter()
            .copied()
            .filter(|consumer| match consumer {
                RequiredStateConsumer::RateLimits => self.rate_limits,
                RequiredStateConsumer::Budgets => self.budgets,
                RequiredStateConsumer::Fingerprints => self.fingerprints,
                RequiredStateConsumer::SharedCacheAdmission => self.shared_cache_admission,
                RequiredStateConsumer::ReplayProtection => self.replay_protection,
            })
            .collect()
    }
}

/// Deployment topology contract used to derive [`DistributedRequirement`].
///
/// Independent of backend health. `LocalOnly` is admissible only for the
/// explicit single-node self-hosted development profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DistributedDeploymentProfile {
    /// Explicit one-node self-hosted development contract.
    ///
    /// Process-local state is the accepted guarantee boundary. This profile
    /// must be selected at startup from deployment inputs, never after a
    /// distributed backend failure.
    SingleNodeSelfHostedDevelopment,
    /// Connected, multi-node, hosted, SaaS, CJIS, release, or any non-dev
    /// self-hosted topology where shared consumers require a live backend.
    MultiNodeOrConnected,
}

impl DistributedDeploymentProfile {
    /// Resolve the topology contract from runtime deployment inputs.
    ///
    /// Does not consult backend health, Redis URLs, or connection status.
    ///
    /// `SingleNodeSelfHostedDevelopment` requires all of:
    /// - not connected to the control plane
    /// - `VERDICTAN_ENV=development`
    /// - deployment mode `self-hosted` / `self_hosted`
    pub fn resolve(connected_mode: bool, verdictan_env: &str, deployment_mode: &str) -> Self {
        let env_is_development = verdictan_env.trim().eq_ignore_ascii_case("development");
        let mode = deployment_mode.trim().to_ascii_lowercase();
        let mode_is_self_hosted = matches!(mode.as_str(), "self-hosted" | "self_hosted");
        if !connected_mode && env_is_development && mode_is_self_hosted {
            Self::SingleNodeSelfHostedDevelopment
        } else {
            Self::MultiNodeOrConnected
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleNodeSelfHostedDevelopment => "single_node_self_hosted_development",
            Self::MultiNodeOrConnected => "multi_node_or_connected",
        }
    }
}

/// Immutable distributed-state requirement for a gateway process.
///
/// Derived solely from [`DistributedDeploymentProfile`] and
/// [`DistributedPolicyCapabilities`]. Backend health must never influence
/// this value. In particular, [`Self::LocalOnly`] is a fixed single-node
/// deployment contract and must not be selected after a distributed backend
/// failure (see [`Self::after_backend_failure`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DistributedRequirement {
    /// No required-state consumers are enabled; shared state is unused.
    Disabled,
    /// Explicit single-node self-hosted development contract with at least
    /// one consumer enabled. Process-local state is the guarantee boundary.
    LocalOnly,
    /// Shared distributed state is mandatory for the enabled consumers.
    Required,
}

impl DistributedRequirement {
    /// Derive the immutable requirement from deployment profile and enabled
    /// policy capabilities.
    ///
    /// The function signature intentionally excludes backend health so callers
    /// cannot accidentally couple requirement selection to Redis/Valkey state.
    pub fn derive(
        profile: DistributedDeploymentProfile,
        capabilities: DistributedPolicyCapabilities,
    ) -> Self {
        if !capabilities.requires_shared_state() {
            return Self::Disabled;
        }
        match profile {
            DistributedDeploymentProfile::SingleNodeSelfHostedDevelopment => Self::LocalOnly,
            DistributedDeploymentProfile::MultiNodeOrConnected => Self::Required,
        }
    }

    /// Resolve profile inputs then derive the requirement.
    ///
    /// Still never consults backend health.
    pub fn derive_from_runtime(
        connected_mode: bool,
        verdictan_env: &str,
        deployment_mode: &str,
        capabilities: DistributedPolicyCapabilities,
    ) -> Self {
        let profile =
            DistributedDeploymentProfile::resolve(connected_mode, verdictan_env, deployment_mode);
        Self::derive(profile, capabilities)
    }

    /// Backend failure / outage must not rematerialize [`Self::LocalOnly`]
    /// from [`Self::Required`] (or otherwise change the contract).
    ///
    /// `LocalOnly` remains only when it was the fixed startup contract.
    pub fn after_backend_failure(self) -> Self {
        self
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::LocalOnly => "local_only",
            Self::Required => "required",
        }
    }

    /// True when dependent requests must have a live shared backend.
    pub fn requires_live_backend(self) -> bool {
        matches!(self, Self::Required)
    }
}

// ─── Runtime unavailable error ─────────────────────────────────────

/// Required distributed backend is missing or unhealthy.
///
/// Dependent request paths and `/readyz` MUST map this to HTTP 503 with
/// [`DISTRIBUTED_STATE_UNAVAILABLE_REASON`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedStateUnavailable {
    backend_name: &'static str,
    detail: String,
}

impl DistributedStateUnavailable {
    pub fn new(backend_name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            backend_name,
            detail: detail.into(),
        }
    }

    pub fn reason_code(&self) -> &'static str {
        DISTRIBUTED_STATE_UNAVAILABLE_REASON
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend_name
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// HTTP status for dependent-request and readiness rejection.
    pub fn status_code(&self) -> u16 {
        503
    }

    /// Alias used by request-path helpers.
    pub fn http_status(&self) -> u16 {
        self.status_code()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "error": {
                "code": self.reason_code(),
                "message": format!(
                    "required distributed state ({}) unavailable: {}",
                    self.backend_name, self.detail
                ),
                "backend": self.backend_name,
            }
        })
    }

    /// Status plus JSON body for dependent-request rejection (HTTP 503).
    pub fn to_http_parts(&self) -> (u16, serde_json::Value) {
        (self.status_code(), self.to_json())
    }
}

impl std::fmt::Display for DistributedStateUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} backend unavailable ({})",
            self.reason_code(),
            self.backend_name,
            self.detail
        )
    }
}

impl std::error::Error for DistributedStateUnavailable {}

// ─── DistributedState ────────────────────────────────────────────────────────

/// Centralized distributed state for multi-instance gateway coordination.
///
/// Holds an optional Redis client when compiled with `--features distributed`
/// and a non-empty Redis URL is supplied.
///
/// Under [`DistributedRequirement::Required`], missing URL or initialization
/// failure is fatal at startup, and runtime backend loss fails closed via
/// [`Self::ensure_available_for_dependent_request`]. Local in-process fallback
/// is admissible only for [`DistributedRequirement::LocalOnly`] /
/// [`DistributedRequirement::Disabled`].
pub struct DistributedState {
    #[cfg(feature = "distributed")]
    redis: Option<redis::Client>,
    backend_name: &'static str,
    clock: Arc<dyn Clock>,
    requirement: DistributedRequirement,
    /// Process-local observation of backend liveness. Starts `true` when a
    /// live backend was established at init; flipped `false` on runtime errors.
    backend_available: AtomicBool,
    /// Consecutive successful probes while recovering from failure.
    consecutive_successes: AtomicU32,
}

impl std::fmt::Debug for DistributedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("DistributedState");
        #[cfg(feature = "distributed")]
        {
            debug.field("redis_configured", &self.redis.is_some());
        }
        debug
            .field("backend_name", &self.backend_name)
            .field("requirement", &self.requirement)
            .field(
                "backend_available",
                &self
                    .backend_available
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .field(
                "consecutive_successes",
                &self
                    .consecutive_successes
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl DistributedState {
    /// Create a new `DistributedState` with [`DistributedRequirement::Disabled`].
    ///
    /// Prefer [`Self::initialize`] at gateway startup so the immutable
    /// requirement contract is attached. This soft constructor remains for
    /// fixture and unit-test call sites that do not enforce Required semantics.
    ///
    /// - When `redis_url` is `Some` and non-empty, connects to Redis and
    ///   verifies connectivity with a PING at startup. Returns an error if
    ///   the connection or PING fails.
    /// - When `redis_url` is `None`, empty, or whitespace-only, returns a
    ///   local-only variant (`is_distributed` returns `false`).
    /// - Without the `distributed` feature flag this always returns a local-
    ///   only variant, regardless of `redis_url`.
    pub async fn new(redis_url: Option<&str>, backend_name: &'static str) -> anyhow::Result<Self> {
        Self::new_with_clock(redis_url, backend_name, Arc::new(SystemClock)).await
    }

    /// Create a new `DistributedState` using an explicit clock (Disabled contract).
    pub async fn new_with_clock(
        redis_url: Option<&str>,
        backend_name: &'static str,
        clock: Arc<dyn Clock>,
    ) -> anyhow::Result<Self> {
        Self::initialize_with_clock(
            redis_url,
            backend_name,
            DistributedRequirement::Disabled,
            clock,
        )
        .await
    }

    /// Initialize distributed state under an immutable requirement contract.
    ///
    /// When `requirement` is [`DistributedRequirement::Required`]:
    /// - missing / empty URL fails startup
    /// - connection or PING failure fails startup
    /// - without the `distributed` feature, a configured URL fails startup
    ///   (no silent local fallback)
    pub async fn initialize(
        redis_url: Option<&str>,
        backend_name: &'static str,
        requirement: DistributedRequirement,
    ) -> anyhow::Result<Self> {
        Self::initialize_with_clock(redis_url, backend_name, requirement, Arc::new(SystemClock))
            .await
    }

    /// Initialize with an explicit clock (test seam).
    pub async fn initialize_with_clock(
        redis_url: Option<&str>,
        backend_name: &'static str,
        requirement: DistributedRequirement,
        clock: Arc<dyn Clock>,
    ) -> anyhow::Result<Self> {
        let normalized_redis_url = redis_url.and_then(|url| {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });

        if requirement.requires_live_backend() && normalized_redis_url.is_none() {
            anyhow::bail!(
                "distributed state is required ({}) but {} URL is missing or empty",
                requirement.as_str(),
                backend_display_name(backend_name)
            );
        }

        #[cfg(not(feature = "distributed"))]
        {
            if requirement.requires_live_backend() {
                anyhow::bail!(
                    "distributed state is required ({}) but the 'distributed' feature is not \
                     compiled in; rebuild with --features distributed",
                    requirement.as_str()
                );
            }
            if normalized_redis_url.is_some() {
                tracing::warn!(
                    backend = backend_name,
                    requirement = requirement.as_str(),
                    "distributed state configured but the 'distributed' feature is not \
                     compiled in; operating in local-only mode"
                );
            }
            Ok(Self {
                backend_name,
                clock,
                requirement,
                backend_available: AtomicBool::new(false),
                consecutive_successes: AtomicU32::new(0),
            })
        }

        #[cfg(feature = "distributed")]
        {
            let redis = if let Some(url) = normalized_redis_url {
                let client = redis::Client::open(url).map_err(|e| {
                    anyhow::anyhow!(
                        "invalid {} URL for distributed state: {e}",
                        backend_display_name(backend_name)
                    )
                })?;
                // Verify connectivity synchronously at startup so misconfigured
                // Redis is rejected early rather than at first request.
                let mut conn = client.get_connection().map_err(|e| {
                    anyhow::anyhow!(
                        "failed to connect to {} for distributed state: {e}",
                        backend_display_name(backend_name)
                    )
                })?;
                let _: String = redis::cmd("PING").query(&mut conn).map_err(|e| {
                    anyhow::anyhow!(
                        "failed to ping {} for distributed state: {e}",
                        backend_display_name(backend_name)
                    )
                })?;
                tracing::info!(
                    backend = backend_name,
                    requirement = requirement.as_str(),
                    "distributed state connection established"
                );
                Some(client)
            } else {
                None
            };
            let backend_available = redis.is_some();
            Ok(Self {
                redis,
                backend_name,
                clock,
                requirement,
                backend_available: AtomicBool::new(backend_available),
                consecutive_successes: AtomicU32::new(if backend_available {
                    RUNTIME_RECOVERY_SUCCESS_THRESHOLD
                } else {
                    0
                }),
            })
        }
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend_name
    }

    pub fn requirement(&self) -> DistributedRequirement {
        self.requirement
    }

    pub fn now_unix_seconds(&self) -> u64 {
        self.clock.unix_seconds()
    }

    pub fn now_unix_micros(&self) -> u128 {
        self.clock.unix_micros()
    }

    /// Returns `true` when a Redis backend client is configured and the
    /// `distributed` feature is compiled in.
    pub fn is_distributed(&self) -> bool {
        #[cfg(feature = "distributed")]
        {
            self.redis.is_some()
        }
        #[cfg(not(feature = "distributed"))]
        {
            false
        }
    }

    /// Last observed backend liveness (updated by probes and connection use).
    pub fn backend_available(&self) -> bool {
        self.backend_available.load(Ordering::Acquire)
    }

    /// Record a successful backend operation / probe.
    ///
    /// After a failure under Required, availability is restored only after
    /// [`RUNTIME_RECOVERY_SUCCESS_THRESHOLD`] consecutive successes.
    pub fn mark_backend_success(&self) {
        if self.backend_available.load(Ordering::Acquire) {
            self.consecutive_successes
                .store(RUNTIME_RECOVERY_SUCCESS_THRESHOLD, Ordering::Release);
            return;
        }
        let next = self
            .consecutive_successes
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1)
            .min(RUNTIME_RECOVERY_SUCCESS_THRESHOLD);
        self.consecutive_successes.store(next, Ordering::Release);
        if next >= RUNTIME_RECOVERY_SUCCESS_THRESHOLD {
            self.backend_available.store(true, Ordering::Release);
        }
    }

    /// Record a backend failure. Required consumers must fail closed immediately.
    pub fn mark_backend_failure(&self) {
        self.backend_available.store(false, Ordering::Release);
        self.consecutive_successes.store(0, Ordering::Release);
    }

    /// Probe the live backend (PING). Updates availability. No-op success when
    /// the requirement does not need a live backend and no client is configured.
    pub fn probe_backend(&self) -> Result<(), DistributedStateUnavailable> {
        if !self.requirement.requires_live_backend() {
            if self.is_distributed() {
                return self.ping_backend();
            }
            return Ok(());
        }
        if !self.is_distributed() {
            self.mark_backend_failure();
            return Err(DistributedStateUnavailable::new(
                self.backend_name,
                "required backend client is not configured",
            ));
        }
        self.ping_backend()
    }

    fn ping_backend(&self) -> Result<(), DistributedStateUnavailable> {
        #[cfg(feature = "distributed")]
        {
            let Some(client) = self.redis.as_ref() else {
                self.mark_backend_failure();
                return Err(DistributedStateUnavailable::new(
                    self.backend_name,
                    "required backend client is not configured",
                ));
            };
            let mut conn = client.get_connection().map_err(|e| {
                self.mark_backend_failure();
                DistributedStateUnavailable::new(
                    self.backend_name,
                    format!("connection failed during readiness probe: {e}"),
                )
            })?;
            let _: String = redis::cmd("PING").query(&mut conn).map_err(|e| {
                self.mark_backend_failure();
                DistributedStateUnavailable::new(
                    self.backend_name,
                    format!("ping failed during readiness probe: {e}"),
                )
            })?;
            self.mark_backend_success();
            if self.requirement.requires_live_backend() && !self.backend_available() {
                return Err(DistributedStateUnavailable::new(
                    self.backend_name,
                    format!(
                        "backend probe succeeded but recovery requires \
                         {RUNTIME_RECOVERY_SUCCESS_THRESHOLD} consecutive successes"
                    ),
                ));
            }
            Ok(())
        }
        #[cfg(not(feature = "distributed"))]
        {
            if self.requirement.requires_live_backend() {
                self.mark_backend_failure();
                Err(DistributedStateUnavailable::new(
                    self.backend_name,
                    "distributed feature not compiled in",
                ))
            } else {
                Ok(())
            }
        }
    }

    /// Fail closed for dependent requests when the immutable contract requires
    /// a live backend that is currently unavailable.
    pub fn ensure_available_for_dependent_request(
        &self,
    ) -> Result<(), DistributedStateUnavailable> {
        if !self.requirement.requires_live_backend() {
            return Ok(());
        }
        if self.is_distributed() && self.backend_available() {
            return Ok(());
        }
        Err(DistributedStateUnavailable::new(
            self.backend_name,
            if !self.is_distributed() {
                "required backend is not configured"
            } else {
                "required backend is unhealthy"
            },
        ))
    }

    /// Obtain a synchronous Redis connection from the pool, if available.
    ///
    /// Returns `None` when the `distributed` feature is absent or no Redis URL
    /// was configured. Returns `Some(Err(_))` when the pool exists but
    /// acquiring a connection fails (marks the backend unavailable).
    #[cfg(feature = "distributed")]
    pub fn connection(&self) -> Option<Result<redis::Connection, redis::RedisError>> {
        self.redis.as_ref().map(|c| match c.get_connection() {
            Ok(conn) => {
                self.mark_backend_success();
                Ok(conn)
            }
            Err(err) => {
                self.mark_backend_failure();
                Err(err)
            }
        })
    }

    #[cfg(all(test, feature = "distributed"))]
    fn from_redis_client_for_tests(
        redis: Option<redis::Client>,
        backend_name: &'static str,
    ) -> Self {
        Self::from_redis_client_for_tests_with_requirement(
            redis,
            backend_name,
            DistributedRequirement::Disabled,
        )
    }

    #[cfg(all(test, feature = "distributed"))]
    pub(crate) fn from_redis_client_for_tests_with_requirement(
        redis: Option<redis::Client>,
        backend_name: &'static str,
        requirement: DistributedRequirement,
    ) -> Self {
        let available = redis.is_some();
        Self {
            redis,
            backend_name,
            clock: Arc::new(SystemClock),
            requirement,
            backend_available: AtomicBool::new(available),
            consecutive_successes: AtomicU32::new(if available {
                RUNTIME_RECOVERY_SUCCESS_THRESHOLD
            } else {
                0
            }),
        }
    }
}

fn backend_display_name(backend_name: &str) -> &'static str {
    match backend_name {
        "valkey" => "Valkey",
        _ => "Redis",
    }
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

    fn caps_none() -> DistributedPolicyCapabilities {
        DistributedPolicyCapabilities::default()
    }

    fn caps_rate_limits() -> DistributedPolicyCapabilities {
        DistributedPolicyCapabilities::from_enabled_flags(true, false, false, false, false)
    }

    fn caps_all() -> DistributedPolicyCapabilities {
        DistributedPolicyCapabilities::from_enabled_flags(true, true, true, true, true)
    }

    // ── Key-naming helpers ───────────────────────────────────────────────

    #[test]
    fn rate_limit_key_format() {
        assert_eq!(
            rate_limit_key("tenant-1", "sliding"),
            "vt:rl:tenant-1:sliding"
        );
    }

    #[test]
    fn rate_limit_key_with_numeric_bucket() {
        assert_eq!(
            rate_limit_key("org-42", "1700000000"),
            "vt:rl:org-42:1700000000"
        );
    }

    #[test]
    fn fingerprint_key_format() {
        assert_eq!(
            fingerprint_key("tenant-1", "abc123"),
            "vt:fp:tenant-1:abc123"
        );
    }

    #[test]
    fn fingerprint_key_with_long_hash() {
        let hash = "a".repeat(64);
        let key = fingerprint_key("t", &hash);
        assert!(key.starts_with("vt:fp:t:"));
        assert_eq!(key.len(), "vt:fp:t:".len() + 64);
    }

    // ── backend_display_name ─────────────────────────────────────────────

    #[test]
    fn backend_display_name_valkey() {
        assert_eq!(backend_display_name("valkey"), "Valkey");
    }

    #[test]
    fn backend_display_name_redis() {
        assert_eq!(backend_display_name("redis"), "Redis");
    }

    #[test]
    fn backend_display_name_unknown_defaults_to_redis() {
        assert_eq!(backend_display_name("unknown"), "Redis");
    }

    // ── TTL constants ────────────────────────────────────────────────────

    #[test]
    fn ttl_constants_are_reasonable() {
        assert_eq!(RATE_LIMIT_WINDOW_SECS, 60);
        assert_eq!(FINGERPRINT_DEDUP_TTL_SECS, 300);
    }

    // ── DistributedState non-distributed mode ────────────────────────────

    #[tokio::test]
    async fn local_only_state_is_not_distributed() {
        let state = DistributedState::new(None, "redis").await.unwrap();
        assert!(!state.is_distributed());
        assert_eq!(state.backend_name(), "redis");
    }

    #[tokio::test]
    async fn empty_url_state_is_not_distributed() {
        let state = DistributedState::new(Some(""), "valkey").await.unwrap();
        assert!(!state.is_distributed());
        assert_eq!(state.backend_name(), "valkey");
    }

    #[tokio::test]
    async fn whitespace_only_url_is_not_distributed() {
        let state = DistributedState::new(Some("   "), "redis").await.unwrap();
        assert!(!state.is_distributed());
    }

    #[cfg(feature = "distributed")]
    #[tokio::test]
    async fn invalid_redis_url_returns_error() {
        let result = DistributedState::new(Some("not-a-valid-url"), "redis").await;
        let err = match result {
            Ok(_) => panic!("expected invalid redis url to return an error"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(msg.contains("invalid") || msg.contains("Redis"));
    }

    #[cfg(feature = "distributed")]
    #[test]
    fn from_redis_client_none_is_not_distributed() {
        let state = DistributedState::from_redis_client_for_tests(None, "redis");
        assert!(!state.is_distributed());
        assert_eq!(state.backend_name(), "redis");
    }

    #[cfg(feature = "distributed")]
    #[test]
    fn from_redis_client_some_is_distributed() {
        let client = redis::Client::open("redis://127.0.0.1:1/").expect("redis client");
        let state = DistributedState::from_redis_client_for_tests(Some(client), "valkey");
        assert!(state.is_distributed());
        assert_eq!(state.backend_name(), "valkey");
    }

    #[cfg(feature = "distributed")]
    #[test]
    fn connection_returns_none_without_redis() {
        let state = DistributedState::from_redis_client_for_tests(None, "redis");
        assert!(state.connection().is_none());
    }

    #[test]
    fn required_state_consumers_are_enumerated_exhaustively() {
        assert_eq!(
            REQUIRED_STATE_CONSUMERS,
            &[
                RequiredStateConsumer::RateLimits,
                RequiredStateConsumer::Budgets,
                RequiredStateConsumer::Fingerprints,
                RequiredStateConsumer::SharedCacheAdmission,
                RequiredStateConsumer::ReplayProtection,
            ]
        );
        assert_eq!(RequiredStateConsumer::RateLimits.as_str(), "rate_limits");
        assert_eq!(RequiredStateConsumer::Budgets.as_str(), "budgets");
        assert_eq!(RequiredStateConsumer::Fingerprints.as_str(), "fingerprints");
        assert_eq!(
            RequiredStateConsumer::SharedCacheAdmission.as_str(),
            "shared_cache_admission"
        );
        assert_eq!(
            RequiredStateConsumer::ReplayProtection.as_str(),
            "replay_protection"
        );
    }

    #[test]
    fn capabilities_enabled_consumers_follow_declaration_order() {
        let caps =
            DistributedPolicyCapabilities::from_enabled_flags(false, true, false, true, true);
        assert_eq!(
            caps.enabled_consumers(),
            vec![
                RequiredStateConsumer::Budgets,
                RequiredStateConsumer::SharedCacheAdmission,
                RequiredStateConsumer::ReplayProtection,
            ]
        );
        assert!(caps.requires_shared_state());
        assert!(!caps_none().requires_shared_state());
    }

    #[test]
    fn derive_disabled_when_no_consumers_regardless_of_profile() {
        assert_eq!(
            DistributedRequirement::derive(
                DistributedDeploymentProfile::SingleNodeSelfHostedDevelopment,
                caps_none()
            ),
            DistributedRequirement::Disabled
        );
        assert_eq!(
            DistributedRequirement::derive(
                DistributedDeploymentProfile::MultiNodeOrConnected,
                caps_none()
            ),
            DistributedRequirement::Disabled
        );
    }

    #[test]
    fn derive_local_only_for_explicit_single_node_with_consumers() {
        assert_eq!(
            DistributedRequirement::derive(
                DistributedDeploymentProfile::SingleNodeSelfHostedDevelopment,
                caps_rate_limits()
            ),
            DistributedRequirement::LocalOnly
        );
        assert_eq!(
            DistributedRequirement::derive(
                DistributedDeploymentProfile::SingleNodeSelfHostedDevelopment,
                caps_all()
            ),
            DistributedRequirement::LocalOnly
        );
    }

    #[test]
    fn derive_required_for_multi_node_or_connected_with_consumers() {
        assert_eq!(
            DistributedRequirement::derive(
                DistributedDeploymentProfile::MultiNodeOrConnected,
                caps_rate_limits()
            ),
            DistributedRequirement::Required
        );
        for consumer_caps in [
            DistributedPolicyCapabilities::from_enabled_flags(true, false, false, false, false),
            DistributedPolicyCapabilities::from_enabled_flags(false, true, false, false, false),
            DistributedPolicyCapabilities::from_enabled_flags(false, false, true, false, false),
            DistributedPolicyCapabilities::from_enabled_flags(false, false, false, true, false),
            DistributedPolicyCapabilities::from_enabled_flags(false, false, false, false, true),
        ] {
            assert_eq!(
                DistributedRequirement::derive(
                    DistributedDeploymentProfile::MultiNodeOrConnected,
                    consumer_caps
                ),
                DistributedRequirement::Required,
                "each required-state consumer must force Required on multi-node/connected"
            );
        }
    }

    #[test]
    fn deployment_profile_resolve_single_node_only_for_dev_self_hosted() {
        assert_eq!(
            DistributedDeploymentProfile::resolve(false, "development", "self-hosted"),
            DistributedDeploymentProfile::SingleNodeSelfHostedDevelopment
        );
        assert_eq!(
            DistributedDeploymentProfile::resolve(false, "Development", "self_hosted"),
            DistributedDeploymentProfile::SingleNodeSelfHostedDevelopment
        );
    }

    #[test]
    fn deployment_profile_resolve_multi_node_for_connected_or_non_dev() {
        let cases = [
            (true, "development", "self-hosted"),
            (false, "production", "self-hosted"),
            (false, "development", "hosted"),
            (false, "development", "saas"),
            (false, "development", "connected"),
            (false, "development", "cjis"),
            (false, "development", "release"),
            (true, "production", "saas"),
        ];
        for (connected, env, mode) in cases {
            assert_eq!(
                DistributedDeploymentProfile::resolve(connected, env, mode),
                DistributedDeploymentProfile::MultiNodeOrConnected,
                "connected={connected} env={env} mode={mode}"
            );
        }
    }

    #[test]
    fn derive_from_runtime_matrix() {
        assert_eq!(
            DistributedRequirement::derive_from_runtime(
                false,
                "development",
                "self-hosted",
                caps_none()
            ),
            DistributedRequirement::Disabled
        );
        assert_eq!(
            DistributedRequirement::derive_from_runtime(
                false,
                "development",
                "self-hosted",
                caps_rate_limits()
            ),
            DistributedRequirement::LocalOnly
        );
        assert_eq!(
            DistributedRequirement::derive_from_runtime(
                true,
                "development",
                "self-hosted",
                caps_rate_limits()
            ),
            DistributedRequirement::Required
        );
        assert_eq!(
            DistributedRequirement::derive_from_runtime(
                false,
                "production",
                "self-hosted",
                caps_all()
            ),
            DistributedRequirement::Required
        );
    }

    #[test]
    fn local_only_never_selected_after_backend_failure_from_required() {
        let required = DistributedRequirement::Required;
        // Simulating an outage must preserve Required — never rematerialize LocalOnly.
        assert_eq!(
            required.after_backend_failure(),
            DistributedRequirement::Required
        );
        assert_ne!(
            required.after_backend_failure(),
            DistributedRequirement::LocalOnly
        );
        assert!(required.requires_live_backend());

        let local = DistributedRequirement::LocalOnly;
        assert_eq!(
            local.after_backend_failure(),
            DistributedRequirement::LocalOnly
        );
        assert!(!local.requires_live_backend());
    }

    #[test]
    fn requirement_as_str_labels() {
        assert_eq!(DistributedRequirement::Disabled.as_str(), "disabled");
        assert_eq!(DistributedRequirement::LocalOnly.as_str(), "local_only");
        assert_eq!(DistributedRequirement::Required.as_str(), "required");
        assert_eq!(
            DistributedDeploymentProfile::SingleNodeSelfHostedDevelopment.as_str(),
            "single_node_self_hosted_development"
        );
        assert_eq!(
            DistributedDeploymentProfile::MultiNodeOrConnected.as_str(),
            "multi_node_or_connected"
        );
    }

    #[test]
    fn derivation_ignores_distributed_backend_presence() {
        // Requirement derivation has no health/URL parameter. A process that
        // later loses Redis must still report the same startup-derived value.
        let before = DistributedRequirement::derive(
            DistributedDeploymentProfile::MultiNodeOrConnected,
            caps_all(),
        );
        let after_outage = before.after_backend_failure();
        assert_eq!(before, DistributedRequirement::Required);
        assert_eq!(after_outage, DistributedRequirement::Required);
        // LocalOnly remains a fixed single-node contract only.
        let local = DistributedRequirement::derive(
            DistributedDeploymentProfile::SingleNodeSelfHostedDevelopment,
            caps_all(),
        );
        assert_eq!(local, DistributedRequirement::LocalOnly);
        assert_eq!(
            local.after_backend_failure(),
            DistributedRequirement::LocalOnly
        );
    }

    // ── Required distributed-state init / runtime unavailable ─────────────────────

    #[tokio::test]
    async fn required_initialize_without_url_fails_startup() {
        let err = DistributedState::initialize(None, "redis", DistributedRequirement::Required)
            .await
            .expect_err("Required must reject missing URL");
        let msg = err.to_string();
        assert!(msg.contains("required") || msg.contains("missing") || msg.contains("empty"));
    }

    #[tokio::test]
    async fn required_initialize_with_empty_url_fails_startup() {
        let err =
            DistributedState::initialize(Some("   "), "valkey", DistributedRequirement::Required)
                .await
                .expect_err("Required must reject empty URL");
        assert!(err.to_string().contains("Valkey") || err.to_string().contains("empty"));
    }

    #[tokio::test]
    async fn local_only_initialize_without_url_succeeds() {
        let state = DistributedState::initialize(None, "redis", DistributedRequirement::LocalOnly)
            .await
            .expect("LocalOnly may start without a URL");
        assert!(!state.is_distributed());
        assert_eq!(state.requirement(), DistributedRequirement::LocalOnly);
        assert!(state.ensure_available_for_dependent_request().is_ok());
    }

    #[cfg(feature = "distributed")]
    #[test]
    fn required_runtime_failure_blocks_dependent_requests() {
        let client = redis::Client::open("redis://127.0.0.1:1/").expect("redis client");
        let state = DistributedState::from_redis_client_for_tests_with_requirement(
            Some(client),
            "redis",
            DistributedRequirement::Required,
        );
        assert!(state.is_distributed());
        assert!(state.ensure_available_for_dependent_request().is_ok());
        state.mark_backend_failure();
        let err = state
            .ensure_available_for_dependent_request()
            .expect_err("Required must fail closed after runtime backend loss");
        assert_eq!(err.reason_code(), DISTRIBUTED_STATE_UNAVAILABLE_REASON);
        assert_eq!(err.status_code(), 503);
        assert!(err
            .to_string()
            .contains(DISTRIBUTED_STATE_UNAVAILABLE_REASON));
    }

    #[cfg(feature = "distributed")]
    #[test]
    fn required_recovery_needs_two_consecutive_successes() {
        let client = redis::Client::open("redis://127.0.0.1:1/").expect("redis client");
        let state = DistributedState::from_redis_client_for_tests_with_requirement(
            Some(client),
            "redis",
            DistributedRequirement::Required,
        );
        state.mark_backend_failure();
        assert!(!state.backend_available());
        state.mark_backend_success();
        assert!(
            !state.backend_available(),
            "single success must not restore Required availability"
        );
        assert!(state.ensure_available_for_dependent_request().is_err());
        state.mark_backend_success();
        assert!(state.backend_available());
        assert!(state.ensure_available_for_dependent_request().is_ok());
    }

    #[test]
    fn unavailable_reason_code_is_stable() {
        let err = DistributedStateUnavailable::new("redis", "probe failed");
        assert_eq!(
            err.reason_code(),
            "dependency.distributed_state_unavailable"
        );
        assert_eq!(err.status_code(), 503);
        assert_eq!(
            err.to_json()["error"]["code"],
            "dependency.distributed_state_unavailable"
        );
        let (status, body) = err.to_http_parts();
        assert_eq!(status, 503);
        assert_eq!(
            body["error"]["code"],
            "dependency.distributed_state_unavailable"
        );
    }

    #[cfg(not(feature = "distributed"))]
    #[tokio::test]
    async fn required_initialize_without_distributed_feature_fails_startup() {
        let err = DistributedState::initialize(
            Some("redis://127.0.0.1:6379/"),
            "redis",
            DistributedRequirement::Required,
        )
        .await
        .expect_err("Required must fail when distributed feature is absent");
        let msg = err.to_string();
        assert!(
            msg.contains("distributed") && msg.contains("feature"),
            "unexpected error: {msg}"
        );
    }
}
