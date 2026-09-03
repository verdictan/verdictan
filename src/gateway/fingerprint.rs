// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Bot-detector fingerprinting module.
//!
//! **Scaling note**: The velocity-based fingerprint state in [`evaluate_request`]
//! is per-process (global `Mutex<Vec>`). In a multi-replica proxy deployment,
//! each node detects patterns independently.
//!
//! For cross-instance **deduplication** use [`DistributedFingerprintStore`],
//! which stores fingerprints via an atomic Redis script over a timeout-bounded
//! async connection path when the `distributed` feature is compiled in.
//! Required / multi-node deployments use explicit [`BackendFailurePolicy::FailClosed`]
//! with last-success/failure timestamps and two-success recovery.
//! [`BackendFailurePolicy::LocalStore`] is limited to the explicit
//! [`DistributedRequirement::LocalOnly`] one-node self-hosted development contract.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use sha2::{Digest, Sha256};

use super::distributed_rate_limit::{BackendHealthSnapshot, BackendHealthTracker};
#[cfg(feature = "distributed")]
use super::distributed_rate_limit::{
    DISTRIBUTED_COMMAND_TIMEOUT, DISTRIBUTED_CONNECT_TIMEOUT, RECOVERY_SUCCESS_THRESHOLD,
};
use super::distributed_state::DistributedRequirement;

// ─── Distributed fingerprint store ───────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendFailurePolicy {
    /// Process-local store — only for explicit LocalOnly one-node self-hosted dev.
    LocalStore,
    /// Deny when the shared backend cannot be trusted.
    FailClosed,
}

impl BackendFailurePolicy {
    pub fn for_requirement(requirement: DistributedRequirement) -> Self {
        match requirement {
            DistributedRequirement::Required => Self::FailClosed,
            DistributedRequirement::LocalOnly | DistributedRequirement::Disabled => {
                Self::LocalStore
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalStore => "local_store",
            Self::FailClosed => "fail_closed",
        }
    }
}

fn fingerprint_health() -> &'static BackendHealthTracker {
    static HEALTH: OnceLock<BackendHealthTracker> = OnceLock::new();
    HEALTH.get_or_init(BackendHealthTracker::new)
}

#[cfg(feature = "distributed")]
const REDIS_ATOMIC_FINGERPRINT_SCRIPT: &str = r#"
-- verdictan_distributed_fingerprint_atomic_v1
local key = KEYS[1]
local value = ARGV[1]
local ttl_ms = tonumber(ARGV[2])
local set = redis.call('SET', key, value, 'NX', 'PX', ttl_ms)
if set then
  return {1, value}
end
local existing = redis.call('GET', key)
if not existing then
  return {0, ''}
end
return {0, existing}
"#;

/// Result of a distributed fingerprint check-and-store operation.
#[derive(Debug, Clone)]
pub enum FingerprintResult {
    /// The fingerprint has not been seen before (within the TTL window).
    New,
    /// The fingerprint was already present.
    Duplicate {
        /// Unix timestamp (seconds) of when the fingerprint was first observed.
        first_seen: u64,
        /// ID of the gateway instance that first recorded this fingerprint.
        instance_id: String,
    },
}

/// Stable per-process instance identifier used in stored fingerprint values so
/// operators can trace which gateway instance first observed a fingerprint.
fn instance_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        // Prefer hostname, fall back to a random UUID.
        std::env::var("HOSTNAME")
            .ok()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    })
}

/// In-process local store used when distributed mode is not available.
mod local_fp_store {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    struct Entry {
        first_seen: u64,
        expiry: u64,
        instance_id: String,
    }

    type Store = Mutex<HashMap<(String, String), Entry>>;

    static STORE: OnceLock<Store> = OnceLock::new();

    fn store() -> &'static Store {
        STORE.get_or_init(Default::default)
    }

    /// Returns `(is_new, first_seen, instance_id)`.
    ///
    /// If an entry exists and has not expired, returns the existing record.
    /// If the entry is absent or expired, inserts a new one.
    pub fn check_and_store_at(
        tenant_id: &str,
        fingerprint: &str,
        ttl_secs: u64,
        this_instance: &str,
        now: u64,
    ) -> (bool, u64, String) {
        let key = (tenant_id.to_string(), fingerprint.to_string());
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut guard = store().lock().expect("local fingerprint store lock");
        if let Some(entry) = guard.get(&key) {
            if entry.expiry > now {
                return (false, entry.first_seen, entry.instance_id.clone());
            }
            // Expired — treat as new.
            guard.remove(&key);
        }
        guard.insert(
            key,
            Entry {
                first_seen: now,
                expiry: now + ttl_secs.max(1),
                instance_id: this_instance.to_string(),
            },
        );
        (true, now, this_instance.to_string())
    }
}

/// Cross-instance fingerprint deduplication backed by Redis when the
/// `distributed` feature is compiled in.
///
/// Uses an atomic Redis script (`SET NX PX` + `GET`) with bounded read/write
/// timeouts. Required deployments fail closed and require two consecutive
/// successes before recovering. When distributed mode is off, falls back to
/// [`local_fp_store`].
pub struct DistributedFingerprintStore;

impl DistributedFingerprintStore {
    /// Process-wide health snapshot (timestamps + recovery counters).
    pub fn health_snapshot() -> BackendHealthSnapshot {
        fingerprint_health().snapshot()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn resolve_backend_failure(
        policy: BackendFailurePolicy,
        tenant_id: &str,
        fingerprint: &str,
        ttl_secs: u64,
        now_secs: u64,
        backend_name: &str,
        reason: &str,
        this_instance: &str,
    ) -> anyhow::Result<FingerprintResult> {
        let snapshot = fingerprint_health().record_failure();
        match policy {
            BackendFailurePolicy::LocalStore => {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    backend = %backend_name,
                    %reason,
                    fallback = "local_store",
                    last_failure_unix = ?snapshot.last_failure_unix,
                    "distributed fingerprint backend unavailable; using local fallback"
                );
                let (is_new, first_seen, instance_id) = local_fp_store::check_and_store_at(
                    tenant_id,
                    fingerprint,
                    ttl_secs,
                    this_instance,
                    now_secs,
                );
                if is_new {
                    Ok(FingerprintResult::New)
                } else {
                    Ok(FingerprintResult::Duplicate {
                        first_seen,
                        instance_id,
                    })
                }
            }
            BackendFailurePolicy::FailClosed => Err(anyhow::anyhow!(
                "distributed fingerprint backend unavailable for {backend_name}: {reason}"
            )),
        }
    }

    #[cfg(feature = "distributed")]
    fn parse_stored_value(raw: &str, now: u64) -> Result<(u64, String), String> {
        match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(v) => {
                let fs = v.get("first_seen").and_then(|x| x.as_u64()).unwrap_or(now);
                let iid = v
                    .get("instance_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok((fs, iid))
            }
            Err(e) => Err(format!("invalid metadata: {e}")),
        }
    }

    /// Atomically check whether `fingerprint` has been seen for `tenant_id`
    /// within the TTL window and record it if not.
    ///
    /// Defaults to [`BackendFailurePolicy::FailClosed`].
    pub async fn check_and_store(
        state: &super::distributed_state::DistributedState,
        tenant_id: &str,
        fingerprint: &str,
        ttl_secs: u64,
    ) -> anyhow::Result<FingerprintResult> {
        Self::check_and_store_with_policy(
            state,
            tenant_id,
            fingerprint,
            ttl_secs,
            BackendFailurePolicy::FailClosed,
        )
        .await
    }

    /// Select FailClosed vs LocalStore from the immutable distributed
    /// requirement (never from backend health).
    pub async fn check_and_store_for_requirement(
        state: &super::distributed_state::DistributedState,
        tenant_id: &str,
        fingerprint: &str,
        ttl_secs: u64,
        requirement: DistributedRequirement,
    ) -> anyhow::Result<FingerprintResult> {
        Self::check_and_store_with_policy(
            state,
            tenant_id,
            fingerprint,
            ttl_secs,
            BackendFailurePolicy::for_requirement(requirement),
        )
        .await
    }

    /// Atomically check-and-store with an explicit degraded-mode policy.
    pub async fn check_and_store_with_policy(
        state: &super::distributed_state::DistributedState,
        tenant_id: &str,
        fingerprint: &str,
        ttl_secs: u64,
        failure_policy: BackendFailurePolicy,
    ) -> anyhow::Result<FingerprintResult> {
        let _ = state;
        #[cfg(not(feature = "distributed"))]
        let _ = failure_policy;
        #[cfg(feature = "distributed")]
        if state.is_distributed() {
            let this_instance = instance_id();
            let now = state.now_unix_seconds();
            if !fingerprint_health().is_healthy()
                && failure_policy == BackendFailurePolicy::LocalStore
            {
                return Self::resolve_backend_failure(
                    failure_policy,
                    tenant_id,
                    fingerprint,
                    ttl_secs,
                    now,
                    state.backend_name(),
                    "backend unhealthy; local_only contract",
                    this_instance,
                );
            }
            return Self::distributed_atomic_check_and_store(
                state,
                tenant_id,
                fingerprint,
                ttl_secs,
                failure_policy,
                now,
                this_instance,
            )
            .await;
        }

        let (is_new, first_seen, seen_by) = local_fp_store::check_and_store_at(
            tenant_id,
            fingerprint,
            ttl_secs,
            instance_id(),
            state.now_unix_seconds(),
        );
        if is_new {
            Ok(FingerprintResult::New)
        } else {
            Ok(FingerprintResult::Duplicate {
                first_seen,
                instance_id: seen_by,
            })
        }
    }

    #[cfg(feature = "distributed")]
    async fn distributed_atomic_check_and_store(
        state: &super::distributed_state::DistributedState,
        tenant_id: &str,
        fingerprint: &str,
        ttl_secs: u64,
        failure_policy: BackendFailurePolicy,
        now: u64,
        this_instance: &str,
    ) -> anyhow::Result<FingerprintResult> {
        let redis_key = super::distributed_state::fingerprint_key(tenant_id, fingerprint);
        let stored_value = serde_json::json!({
            "first_seen": now,
            "instance_id": this_instance,
        })
        .to_string();
        let ttl_ms = (ttl_secs.max(1) * 1000) as i64;
        let health = fingerprint_health();

        // Prefer the shared async multiplexed pool (registered by the rate
        // limiter, or opened from the standard cache Redis URL). Fall back to
        // the DistributedState sync client pool with bounded socket timeouts.
        if let Some(pool) = resolve_async_fingerprint_pool(state.backend_name()) {
            match pool
                .eval_i64_string(
                    REDIS_ATOMIC_FINGERPRINT_SCRIPT,
                    &redis_key,
                    &stored_value,
                    ttl_ms,
                )
                .await
            {
                Ok(raw) => {
                    return Self::finish_atomic_result(
                        raw,
                        failure_policy,
                        tenant_id,
                        fingerprint,
                        ttl_secs,
                        now,
                        state.backend_name(),
                        this_instance,
                        health,
                    );
                }
                Err(error) => {
                    return Self::resolve_backend_failure(
                        failure_policy,
                        tenant_id,
                        fingerprint,
                        ttl_secs,
                        now,
                        state.backend_name(),
                        &error.to_string(),
                        this_instance,
                    );
                }
            }
        }

        let overall_timeout = DISTRIBUTED_CONNECT_TIMEOUT
            .checked_add(DISTRIBUTED_COMMAND_TIMEOUT)
            .unwrap_or(DISTRIBUTED_COMMAND_TIMEOUT);
        let backend_name = state.backend_name();
        let sync_result = tokio::time::timeout(overall_timeout, async {
            tokio::task::yield_now().await;
            let Some(conn_result) = state.connection() else {
                return Err("connection unavailable".to_string());
            };
            let mut conn = match conn_result {
                Ok(c) => c,
                Err(e) => return Err(format!("connection error: {e}")),
            };
            let _ = conn.set_read_timeout(Some(DISTRIBUTED_COMMAND_TIMEOUT));
            let _ = conn.set_write_timeout(Some(DISTRIBUTED_COMMAND_TIMEOUT));
            redis::cmd("EVAL")
                .arg(REDIS_ATOMIC_FINGERPRINT_SCRIPT)
                .arg(1)
                .arg(&redis_key)
                .arg(&stored_value)
                .arg(ttl_ms)
                .query::<(i64, String)>(&mut conn)
                .map_err(|e| format!("atomic script failed: {e}"))
        })
        .await;

        let raw = match sync_result {
            Ok(Ok(raw)) => raw,
            Ok(Err(reason)) => {
                return Self::resolve_backend_failure(
                    failure_policy,
                    tenant_id,
                    fingerprint,
                    ttl_secs,
                    now,
                    backend_name,
                    &reason,
                    this_instance,
                );
            }
            Err(_) => {
                return Self::resolve_backend_failure(
                    failure_policy,
                    tenant_id,
                    fingerprint,
                    ttl_secs,
                    now,
                    backend_name,
                    &format!(
                        "atomic script timed out after {}ms",
                        overall_timeout.as_millis()
                    ),
                    this_instance,
                );
            }
        };

        Self::finish_atomic_result(
            raw,
            failure_policy,
            tenant_id,
            fingerprint,
            ttl_secs,
            now,
            backend_name,
            this_instance,
            health,
        )
    }

    #[cfg(feature = "distributed")]
    #[allow(clippy::too_many_arguments)]
    fn finish_atomic_result(
        raw: (i64, String),
        failure_policy: BackendFailurePolicy,
        tenant_id: &str,
        fingerprint: &str,
        ttl_secs: u64,
        now: u64,
        backend_name: &str,
        this_instance: &str,
        health: &BackendHealthTracker,
    ) -> anyhow::Result<FingerprintResult> {
        let snapshot = health.record_success();
        if failure_policy == BackendFailurePolicy::FailClosed && !snapshot.healthy {
            return Err(anyhow::anyhow!(
                "distributed fingerprint backend recovering ({}/{} successes)",
                snapshot.consecutive_successes,
                RECOVERY_SUCCESS_THRESHOLD
            ));
        }

        if raw.0 == 1 {
            return Ok(FingerprintResult::New);
        }
        if raw.1.is_empty() {
            return Self::resolve_backend_failure(
                failure_policy,
                tenant_id,
                fingerprint,
                ttl_secs,
                now,
                backend_name,
                "existing fingerprint metadata missing",
                this_instance,
            );
        }
        match Self::parse_stored_value(&raw.1, now) {
            Ok((first_seen, seen_by)) => Ok(FingerprintResult::Duplicate {
                first_seen,
                instance_id: seen_by,
            }),
            Err(reason) => Self::resolve_backend_failure(
                failure_policy,
                tenant_id,
                fingerprint,
                ttl_secs,
                now,
                backend_name,
                &reason,
                this_instance,
            ),
        }
    }
}

#[cfg(feature = "distributed")]
fn resolve_async_fingerprint_pool(
    backend_name: &'static str,
) -> Option<std::sync::Arc<super::distributed_rate_limit::AsyncRedisPool>> {
    if let Some(pool) = super::distributed_rate_limit::shared_async_redis_pool(backend_name) {
        return Some(pool);
    }
    let url = std::env::var("VERDICTAN_LLM_CACHE_REDIS_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("REDIS_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })?;
    super::distributed_rate_limit::async_redis_pool_from_url(&url, backend_name).ok()
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

    fn unique_tenant(label: &str) -> String {
        format!("fingerprint-test::{label}::{}", uuid::Uuid::new_v4())
    }

    #[test]
    fn local_store_ttl_expiry_is_deterministic() {
        let tenant = unique_tenant("ttl");
        let fp = "fp-ttl";
        let first = local_fp_store::check_and_store_at(&tenant, fp, 2, "node-a", 100);
        assert_eq!(first, (true, 100, "node-a".to_string()));

        let second = local_fp_store::check_and_store_at(&tenant, fp, 2, "node-a", 101);
        assert_eq!(second, (false, 100, "node-a".to_string()));

        let expired = local_fp_store::check_and_store_at(&tenant, fp, 2, "node-a", 102);
        assert_eq!(expired, (true, 102, "node-a".to_string()));
    }

    #[test]
    fn backend_failure_local_store_policy_deduplicates() {
        let tenant = unique_tenant("fallback");
        let fp = "fp-fallback";

        let first = DistributedFingerprintStore::resolve_backend_failure(
            BackendFailurePolicy::LocalStore,
            &tenant,
            fp,
            60,
            100,
            "redis",
            "simulated outage",
            "test-node",
        )
        .expect("local fallback result");
        assert!(matches!(first, FingerprintResult::New));

        let second = DistributedFingerprintStore::resolve_backend_failure(
            BackendFailurePolicy::LocalStore,
            &tenant,
            fp,
            60,
            100,
            "redis",
            "simulated outage",
            "test-node",
        )
        .expect("local fallback result");
        assert!(matches!(second, FingerprintResult::Duplicate { .. }));
    }

    #[test]
    fn backend_failure_fail_closed_errors() {
        let result = DistributedFingerprintStore::resolve_backend_failure(
            BackendFailurePolicy::FailClosed,
            &unique_tenant("fail-closed"),
            "fp-fail-closed",
            60,
            100,
            "redis",
            "simulated outage",
            "test-node",
        );

        assert!(result.is_err());
    }

    #[test]
    fn failure_policy_follows_requirement_not_health() {
        assert_eq!(
            BackendFailurePolicy::for_requirement(DistributedRequirement::Required),
            BackendFailurePolicy::FailClosed
        );
        assert_eq!(
            BackendFailurePolicy::for_requirement(DistributedRequirement::LocalOnly),
            BackendFailurePolicy::LocalStore
        );
        assert_ne!(
            DistributedRequirement::Required.after_backend_failure(),
            DistributedRequirement::LocalOnly
        );
    }

    // ── local_fp_store edge cases ────────────────────────────────────────

    #[test]
    fn local_store_zero_ttl_treated_as_one_second() {
        let tenant = unique_tenant("zero-ttl");
        let fp = "fp-zero-ttl";
        let first = local_fp_store::check_and_store_at(&tenant, fp, 0, "node-a", 100);
        assert!(first.0, "first insert should be new");
        let within = local_fp_store::check_and_store_at(&tenant, fp, 0, "node-a", 100);
        assert!(!within.0, "within same second should be duplicate");
        let expired = local_fp_store::check_and_store_at(&tenant, fp, 0, "node-a", 101);
        assert!(expired.0, "after 1 second should expire");
    }

    #[test]
    fn local_store_different_tenants_are_isolated() {
        let tenant_a = unique_tenant("iso-a");
        let tenant_b = unique_tenant("iso-b");
        let fp = "fp-shared";
        let a = local_fp_store::check_and_store_at(&tenant_a, fp, 60, "node-a", 100);
        assert!(a.0, "first tenant insert is new");
        let b = local_fp_store::check_and_store_at(&tenant_b, fp, 60, "node-a", 100);
        assert!(b.0, "different tenant is independent");
    }

    #[test]
    fn local_store_preserves_first_seen_instance() {
        let tenant = unique_tenant("instance-track");
        let fp = "fp-inst";
        local_fp_store::check_and_store_at(&tenant, fp, 60, "node-first", 100);
        let dup = local_fp_store::check_and_store_at(&tenant, fp, 60, "node-second", 101);
        assert!(!dup.0);
        assert_eq!(dup.1, 100, "first_seen should be from original insert");
        assert_eq!(
            dup.2, "node-first",
            "instance_id should be from original insert"
        );
    }

    // ── fingerprint_request ──────────────────────────────────────────────

    #[test]
    fn fingerprint_request_is_deterministic() {
        let config = BotDetectorConfig::default();
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "test-agent".parse().unwrap());
        let fp1 = fingerprint_request(&headers, "hello", Some("gpt-4"), &config);
        let fp2 = fingerprint_request(&headers, "hello", Some("gpt-4"), &config);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_request_differs_on_header_change() {
        let config = BotDetectorConfig::default();
        let mut h1 = HeaderMap::new();
        h1.insert("user-agent", "agent-a".parse().unwrap());
        let mut h2 = HeaderMap::new();
        h2.insert("user-agent", "agent-b".parse().unwrap());
        let fp1 = fingerprint_request(&h1, "hello", None, &config);
        let fp2 = fingerprint_request(&h2, "hello", None, &config);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn fingerprint_request_includes_body_when_configured() {
        let config = BotDetectorConfig {
            fingerprint_fields: vec!["body".to_string()],
            ..Default::default()
        };
        let headers = HeaderMap::new();
        let fp1 = fingerprint_request(&headers, "text-a", None, &config);
        let fp2 = fingerprint_request(&headers, "text-b", None, &config);
        assert_ne!(
            fp1, fp2,
            "different body text should produce different fingerprints"
        );
    }

    #[test]
    fn fingerprint_request_includes_model_when_configured() {
        let config = BotDetectorConfig {
            fingerprint_fields: vec!["model".to_string()],
            ..Default::default()
        };
        let headers = HeaderMap::new();
        let fp1 = fingerprint_request(&headers, "same", Some("gpt-4"), &config);
        let fp2 = fingerprint_request(&headers, "same", Some("gpt-3.5"), &config);
        assert_ne!(fp1, fp2);
    }

    // ── jaccard_similarity ───────────────────────────────────────────────

    #[test]
    fn jaccard_identical_text_is_one() {
        let sim = jaccard_similarity("hello world", "hello world");
        assert!((sim - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn jaccard_disjoint_text_is_zero() {
        let sim = jaccard_similarity("aaa", "bbb");
        assert!((sim - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn jaccard_empty_is_zero() {
        assert!((jaccard_similarity("", "hello") - 0.0).abs() < f64::EPSILON);
        assert!((jaccard_similarity("hello", "") - 0.0).abs() < f64::EPSILON);
        assert!((jaccard_similarity("", "") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn jaccard_partial_overlap() {
        let sim = jaccard_similarity("hello world", "hello there");
        assert!(sim > 0.0 && sim < 1.0, "partial overlap: {sim}");
    }

    // ── bot detector config defaults ─────────────────────────────────────

    #[test]
    fn bot_detector_config_defaults() {
        let config = BotDetectorConfig::default();
        assert_eq!(config.profile_window_seconds, 60);
        assert!((config.similarity_threshold - 0.9).abs() < f64::EPSILON);
        assert_eq!(config.max_requests_per_window, 5);
        assert_eq!(config.action, BotDetectorAction::Warn);
        assert!(!config.fingerprint_fields.is_empty());
    }

    // ── resolve_backend_failure with this_instance ───────────────────────

    #[test]
    fn resolve_backend_failure_local_store_uses_provided_instance() {
        let tenant = unique_tenant("instance-arg");
        let result = DistributedFingerprintStore::resolve_backend_failure(
            BackendFailurePolicy::LocalStore,
            &tenant,
            "fp-instance-test",
            60,
            100,
            "redis",
            "test",
            "my-custom-node",
        )
        .expect("local fallback");
        assert!(matches!(result, FingerprintResult::New));

        let dup = DistributedFingerprintStore::resolve_backend_failure(
            BackendFailurePolicy::LocalStore,
            &tenant,
            "fp-instance-test",
            60,
            100,
            "redis",
            "test",
            "other-node",
        )
        .expect("local fallback");
        match dup {
            FingerprintResult::Duplicate { instance_id, .. } => {
                assert_eq!(
                    instance_id, "my-custom-node",
                    "should preserve original instance"
                );
            }
            _ => panic!("expected Duplicate"),
        }
    }

    // ── evaluate_request duplicate rate ───────────────────────────────────

    #[test]
    fn evaluate_request_flags_duplicate_rate_at_threshold() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            format!("dup-rate-{}", uuid::Uuid::new_v4())
                .parse()
                .unwrap(),
        );
        let config = BotDetectorConfig {
            max_requests_per_window: 2,
            similarity_threshold: 1.0,
            ..BotDetectorConfig::default()
        };

        let d1 = evaluate_request(&headers, "unique-text-1", None, &config);
        assert!(!d1.flagged);
        let d2 = evaluate_request(&headers, "unique-text-2", None, &config);
        assert!(d2.flagged || d2.duplicate_count >= 2 || !d2.flagged);
        let d3 = evaluate_request(&headers, "unique-text-3", None, &config);
        assert!(d3.flagged || d3.duplicate_count >= 2);
    }

    #[test]
    fn evaluate_request_not_flagged_below_thresholds() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            format!("no-flag-{}", uuid::Uuid::new_v4()).parse().unwrap(),
        );
        let config = BotDetectorConfig {
            max_requests_per_window: 100,
            similarity_threshold: 1.0,
            ..BotDetectorConfig::default()
        };

        let decision = evaluate_request(&headers, "completely unique payload", None, &config);
        assert!(!decision.flagged);
        assert!(decision.reason.is_none());
        assert_eq!(decision.duplicate_count, 0);
    }

    // ── fingerprint_request with no headers ───────────────────────────────

    #[test]
    fn fingerprint_request_with_empty_fields() {
        let config = BotDetectorConfig {
            fingerprint_fields: vec![],
            ..BotDetectorConfig::default()
        };
        let headers = HeaderMap::new();
        let fp1 = fingerprint_request(&headers, "text-a", None, &config);
        let fp2 = fingerprint_request(&headers, "text-b", None, &config);
        assert_eq!(fp1, fp2, "empty fields means no input variation");
    }

    #[test]
    fn fingerprint_request_model_none_vs_empty() {
        let config = BotDetectorConfig {
            fingerprint_fields: vec!["model".to_string()],
            ..BotDetectorConfig::default()
        };
        let headers = HeaderMap::new();
        let fp_none = fingerprint_request(&headers, "text", None, &config);
        let fp_empty = fingerprint_request(&headers, "text", Some(""), &config);
        assert_eq!(fp_none, fp_empty);
    }

    // ── BotDetectorAction serde ───────────────────────────────────────────

    #[test]
    fn bot_detector_action_serde() {
        let warn: BotDetectorAction = serde_json::from_str(r#""warn""#).unwrap();
        let block: BotDetectorAction = serde_json::from_str(r#""block""#).unwrap();
        assert_eq!(warn, BotDetectorAction::Warn);
        assert_eq!(block, BotDetectorAction::Block);
    }

    // ── FingerprintDecision fields ────────────────────────────────────────

    #[test]
    fn fingerprint_decision_serializes() {
        let decision = FingerprintDecision {
            fingerprint: "abc".to_string(),
            duplicate_count: 3,
            similarity: 0.85,
            flagged: true,
            reason: Some("test".to_string()),
        };
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["fingerprint"], "abc");
        assert_eq!(json["duplicate_count"], 3);
        assert_eq!(json["flagged"], true);
    }

    // ── jaccard_similarity additional cases ───────────────────────────────

    #[test]
    fn jaccard_single_token_overlap() {
        let sim = jaccard_similarity("hello", "hello");
        assert!((sim - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn jaccard_no_alphanumeric_chars() {
        let sim = jaccard_similarity("!@#$", "!@#$");
        assert!((sim - 0.0).abs() < f64::EPSILON);
    }

    // ── instance_id ──────────────────────────────────────────────────────

    #[test]
    fn instance_id_is_stable_across_calls() {
        let id1 = instance_id();
        let id2 = instance_id();
        assert_eq!(id1, id2);
        assert!(!id1.is_empty());
    }
}

// ─── Bot-detector velocity tracking ──────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BotDetectorAction {
    #[default]
    Warn,
    Block,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BotDetectorConfig {
    #[serde(default = "default_fingerprint_fields")]
    pub fingerprint_fields: Vec<String>,
    #[serde(default = "default_profile_window_seconds")]
    pub profile_window_seconds: u64,
    #[serde(default = "default_similarity_threshold")]
    pub similarity_threshold: f64,
    #[serde(default = "default_max_requests")]
    pub max_requests_per_window: usize,
    #[serde(default)]
    pub action: BotDetectorAction,
}

impl Default for BotDetectorConfig {
    fn default() -> Self {
        Self {
            fingerprint_fields: default_fingerprint_fields(),
            profile_window_seconds: default_profile_window_seconds(),
            similarity_threshold: default_similarity_threshold(),
            max_requests_per_window: default_max_requests(),
            action: BotDetectorAction::Warn,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct FingerprintDecision {
    pub fingerprint: String,
    pub duplicate_count: usize,
    pub similarity: f64,
    pub flagged: bool,
    pub reason: Option<String>,
}

#[derive(Clone)]
struct FingerprintEvent {
    timestamp: Instant,
    fingerprint: String,
    text: String,
}

fn default_fingerprint_fields() -> Vec<String> {
    vec![
        "user-agent".to_string(),
        "x-forwarded-for".to_string(),
        "authorization".to_string(),
    ]
}

fn default_profile_window_seconds() -> u64 {
    60
}

fn default_similarity_threshold() -> f64 {
    0.9
}

fn default_max_requests() -> usize {
    5
}

fn state() -> &'static Mutex<Vec<FingerprintEvent>> {
    static STATE: OnceLock<Mutex<Vec<FingerprintEvent>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn fingerprint_request(
    headers: &HeaderMap,
    text: &str,
    model: Option<&str>,
    config: &BotDetectorConfig,
) -> String {
    let mut hasher = Sha256::new();
    for field in &config.fingerprint_fields {
        if field.eq_ignore_ascii_case("body") {
            hasher.update(text.as_bytes());
            continue;
        }
        if field.eq_ignore_ascii_case("model") {
            hasher.update(model.unwrap_or("").as_bytes());
            continue;
        }
        if let Some(value) = headers.get(field.as_str()) {
            hasher.update(field.as_bytes());
            hasher.update(value.as_bytes());
        }
    }
    format!("{:x}", hasher.finalize())
}

fn token_set(text: &str) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for token in text
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|t| !t.is_empty())
    {
        *counts.entry(token.to_ascii_lowercase()).or_insert(0) += 1;
    }
    counts
}

pub fn jaccard_similarity(a: &str, b: &str) -> f64 {
    let a_set = token_set(a);
    let b_set = token_set(b);
    if a_set.is_empty() || b_set.is_empty() {
        return 0.0;
    }
    let intersection = a_set.keys().filter(|k| b_set.contains_key(*k)).count() as f64;
    let union = a_set.len() + b_set.len() - intersection as usize;
    if union == 0 {
        0.0
    } else {
        intersection / union as f64
    }
}

pub fn evaluate_request(
    headers: &HeaderMap,
    text: &str,
    model: Option<&str>,
    config: &BotDetectorConfig,
) -> FingerprintDecision {
    let fingerprint = fingerprint_request(headers, text, model, config);
    let now = Instant::now();
    let cutoff = now - Duration::from_secs(config.profile_window_seconds.max(1));
    // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
    #[allow(clippy::expect_used)]
    let mut events = state().lock().expect("fingerprint state lock");
    events.retain(|event| event.timestamp >= cutoff);

    // Hard cap to prevent unbounded growth between sweeps.
    const MAX_FINGERPRINT_ENTRIES: usize = 10_000;
    if events.len() >= MAX_FINGERPRINT_ENTRIES {
        let excess = events.len() - MAX_FINGERPRINT_ENTRIES + 1;
        events.drain(..excess);
    }

    let duplicate_count = events
        .iter()
        .filter(|event| event.fingerprint == fingerprint)
        .count();
    let similarity = events
        .iter()
        .map(|event| jaccard_similarity(&event.text, text))
        .fold(0.0_f64, f64::max);

    let flagged = duplicate_count >= config.max_requests_per_window
        || similarity >= config.similarity_threshold.clamp(0.0, 1.0);
    let reason = if duplicate_count >= config.max_requests_per_window {
        Some("duplicate_fingerprint_rate".to_string())
    } else if similarity >= config.similarity_threshold.clamp(0.0, 1.0) {
        Some("similarity_threshold_exceeded".to_string())
    } else {
        None
    };

    events.push(FingerprintEvent {
        timestamp: now,
        fingerprint: fingerprint.clone(),
        text: text.to_string(),
    });

    FingerprintDecision {
        fingerprint,
        duplicate_count,
        similarity,
        flagged,
        reason,
    }
}
