// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Phase 47 P2 — Provider health monitoring and automatic failover.
//!
//! `ProviderHealthMonitor` tracks per-credential rolling metrics and applies
//! circuit-breaker logic to classify credentials as `Healthy`, `Degraded`, or
//! `Unhealthy`. The routing layer consumes these states to exclude or
//! deprioritize unhealthy credentials.
//!
//! A background Tokio task probes each active credential at a configurable
//! interval (default 30 s, env `VERDICTAN_HEALTH_PROBE_INTERVAL_SECS`).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
    #[default]
    Unknown,
}

/// Shared thread-safe health state map, keyed by credential ID.
#[cfg_attr(test, allow(dead_code))]
pub type SharedHealthState = Arc<RwLock<HashMap<String, HealthState>>>;

// ── Declarative config parsing ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMonitorProviderEntry {
    pub name: String,
    pub endpoint: String,
    #[serde(default = "default_interval_seconds")]
    pub interval_seconds: u64,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_interval_seconds() -> u64 {
    30
}
fn default_timeout_ms() -> u64 {
    5000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMonitorConfig {
    #[serde(default)]
    pub providers: Vec<HealthMonitorProviderEntry>,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    #[serde(default)]
    pub alert_callback_urls: Vec<String>,
}

fn default_unhealthy_threshold() -> u32 {
    3
}

impl Default for HealthMonitorConfig {
    fn default() -> Self {
        Self {
            providers: Vec::new(),
            unhealthy_threshold: default_unhealthy_threshold(),
            alert_callback_urls: Vec::new(),
        }
    }
}

/// Parse a `HealthMonitorConfig` from a JSON root that may contain a
/// `"health_monitor"` key.
pub fn parse_health_monitor_config(root: &serde_json::Value) -> HealthMonitorConfig {
    root.get("health_monitor")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

// ── Configuration ────────────────────────────────────────────────────────────

const DEFAULT_PROBE_INTERVAL_SECS: u64 = 30;
const WINDOW_DURATION_SECS: u64 = 60;
const DEGRADED_ERROR_RATE_PCT: f64 = 50.0;
const UNHEALTHY_ERROR_RATE_PCT: f64 = 90.0;
const UNHEALTHY_SILENCE_SECS: u64 = 300;
const RECOVERY_CONSECUTIVE_PROBES: u32 = 3;
const DEGRADED_TRAFFIC_FRACTION: f64 = 0.10;

fn probe_interval() -> Duration {
    let secs = std::env::var("VERDICTAN_HEALTH_PROBE_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_PROBE_INTERVAL_SECS)
        .clamp(10, 300);
    Duration::from_secs(secs)
}

// ── Timestamped event for sliding window ─────────────────────────────────────

#[derive(Debug, Clone)]
struct TimestampedEvent {
    at: Instant,
    is_error: bool,
    latency_ms: u64,
}

// ── Per-credential rolling metrics ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct CredentialHealthMetrics {
    pub credential_id: String,
    pub provider_id: String,
    pub error_count_60s: u64,
    pub request_count_60s: u64,
    pub error_rate_pct: f64,
    pub latency_p50_ms: Option<u64>,
    pub latency_p95_ms: Option<u64>,
    pub rate_limit_remaining: Option<u64>,
    #[serde(skip)]
    pub last_success_at: Option<Instant>,
    #[serde(skip)]
    pub last_error_at: Option<Instant>,
    pub state: HealthState,
    pub consecutive_recovery_probes: u32,
}

impl CredentialHealthMetrics {
    fn new(credential_id: String, provider_id: String) -> Self {
        Self {
            credential_id,
            provider_id,
            error_count_60s: 0,
            request_count_60s: 0,
            error_rate_pct: 0.0,
            latency_p50_ms: None,
            latency_p95_ms: None,
            rate_limit_remaining: None,
            last_success_at: None,
            last_error_at: None,
            state: HealthState::Healthy,
            consecutive_recovery_probes: 0,
        }
    }
}

// ── Trail event for state transitions ────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct HealthStateChangedEvent {
    pub credential_id_redacted: String,
    pub provider_id: String,
    pub previous_state: HealthState,
    pub new_state: HealthState,
    pub error_rate_pct: f64,
    pub request_count_60s: u64,
    pub trigger: String,
}

// ── Credential entry for probing ─────────────────────────────────────────────

#[derive(Debug, Clone)]
#[cfg_attr(test, allow(dead_code))]
pub struct MonitoredCredential {
    pub id: String,
    pub provider_id: String,
    pub endpoint_url: String,
}

// ── Internal per-credential state (not shared directly) ──────────────────────

#[derive(Clone)]
struct CredentialInternalState {
    events: VecDeque<TimestampedEvent>,
    metrics: CredentialHealthMetrics,
}

impl CredentialInternalState {
    fn new(credential_id: String, provider_id: String) -> Self {
        Self {
            events: VecDeque::new(),
            metrics: CredentialHealthMetrics::new(credential_id, provider_id),
        }
    }

    fn record_event(&mut self, is_error: bool, latency_ms: u64) {
        let now = Instant::now();
        self.events.push_back(TimestampedEvent {
            at: now,
            is_error,
            latency_ms,
        });

        if is_error {
            self.metrics.last_error_at = Some(now);
        } else {
            self.metrics.last_success_at = Some(now);
        }

        self.expire_old_events(now);
        self.recompute_metrics(now);
    }

    fn expire_old_events(&mut self, now: Instant) {
        let cutoff = now - Duration::from_secs(WINDOW_DURATION_SECS);
        while self.events.front().is_some_and(|e| e.at < cutoff) {
            self.events.pop_front();
        }
    }

    fn recompute_metrics(&mut self, now: Instant) {
        let cutoff = now - Duration::from_secs(WINDOW_DURATION_SECS);

        let mut total = 0u64;
        let mut errors = 0u64;
        let mut latencies: Vec<u64> = Vec::new();

        for event in &self.events {
            if event.at >= cutoff {
                total += 1;
                if event.is_error {
                    errors += 1;
                }
                latencies.push(event.latency_ms);
            }
        }

        self.metrics.request_count_60s = total;
        self.metrics.error_count_60s = errors;
        self.metrics.error_rate_pct = if total > 0 {
            (errors as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        latencies.sort_unstable();
        self.metrics.latency_p50_ms = percentile(&latencies, 50);
        self.metrics.latency_p95_ms = percentile(&latencies, 95);
    }

    fn evaluate_circuit_breaker(&mut self, now: Instant) -> Option<HealthStateChangedEvent> {
        let previous_state = self.metrics.state;

        let silence_exceeded = self
            .metrics
            .last_success_at
            .map(|t| now.duration_since(t).as_secs() > UNHEALTHY_SILENCE_SECS)
            .unwrap_or(false);

        let new_state =
            if self.metrics.error_rate_pct > UNHEALTHY_ERROR_RATE_PCT || silence_exceeded {
                self.metrics.consecutive_recovery_probes = 0;
                HealthState::Unhealthy
            } else if self.metrics.error_rate_pct > DEGRADED_ERROR_RATE_PCT {
                self.metrics.consecutive_recovery_probes = 0;
                HealthState::Degraded
            } else if previous_state == HealthState::Unhealthy
                || previous_state == HealthState::Degraded
            {
                if self.metrics.consecutive_recovery_probes >= RECOVERY_CONSECUTIVE_PROBES {
                    HealthState::Healthy
                } else {
                    previous_state
                }
            } else {
                HealthState::Healthy
            };

        self.metrics.state = new_state;

        if new_state != previous_state {
            let trigger = match new_state {
                HealthState::Unhealthy if silence_exceeded => "no_success_5min".to_string(),
                HealthState::Unhealthy => {
                    format!("error_rate_{:.0}pct", self.metrics.error_rate_pct)
                }
                HealthState::Degraded => {
                    format!("error_rate_{:.0}pct", self.metrics.error_rate_pct)
                }
                HealthState::Healthy => format!(
                    "recovery_after_{}_probes",
                    self.metrics.consecutive_recovery_probes
                ),
                HealthState::Unknown => "initial".to_string(),
            };

            Some(HealthStateChangedEvent {
                credential_id_redacted: redact_id(&self.metrics.credential_id),
                provider_id: self.metrics.provider_id.clone(),
                previous_state,
                new_state,
                error_rate_pct: self.metrics.error_rate_pct,
                request_count_60s: self.metrics.request_count_60s,
                trigger,
            })
        } else {
            None
        }
    }
}

// ── Provider Health Monitor ──────────────────────────────────────────────────

pub struct ProviderHealthMonitor {
    states: Arc<DashMap<String, CredentialHealthMetrics>>,
    internal_states: Arc<DashMap<String, CredentialInternalState>>,
}

impl Default for ProviderHealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderHealthMonitor {
    pub fn new() -> Self {
        Self {
            states: Arc::new(DashMap::new()),
            internal_states: Arc::new(DashMap::new()),
        }
    }

    /// Shared reference to the credential health map, for routing integration.
    #[cfg_attr(test, allow(dead_code))]
    pub fn states(&self) -> Arc<DashMap<String, CredentialHealthMetrics>> {
        Arc::clone(&self.states)
    }

    /// Query the health state for a specific credential.
    pub fn credential_state(&self, credential_id: &str) -> HealthState {
        self.states
            .get(credential_id)
            .map(|r| r.state)
            .unwrap_or(HealthState::Unknown)
    }

    /// Traffic multiplier for a credential (1.0 for healthy, 0.10 for degraded,
    /// 0.0 for unhealthy).
    fn traffic_multiplier(&self, credential_id: &str) -> f64 {
        match self.credential_state(credential_id) {
            HealthState::Healthy => 1.0,
            HealthState::Degraded => DEGRADED_TRAFFIC_FRACTION,
            HealthState::Unhealthy => 0.0,
            HealthState::Unknown => 0.7,
        }
    }

    /// Record a request outcome from the live traffic path.
    pub fn record_request(
        &self,
        credential_id: &str,
        provider_id: &str,
        is_error: bool,
        latency_ms: u64,
        rate_limit_remaining: Option<u64>,
    ) -> Option<HealthStateChangedEvent> {
        let now = Instant::now();
        let mut internal = self
            .internal_states
            .get(credential_id)
            .map(|existing| existing.value().clone())
            .unwrap_or_else(|| {
                CredentialInternalState::new(credential_id.to_string(), provider_id.to_string())
            });
        internal.metrics.credential_id = credential_id.to_string();
        internal.metrics.provider_id = provider_id.to_string();

        internal.record_event(is_error, latency_ms);

        if let Some(remaining) = rate_limit_remaining {
            internal.metrics.rate_limit_remaining = Some(remaining);
        }

        if !is_error
            && (internal.metrics.state == HealthState::Unhealthy
                || internal.metrics.state == HealthState::Degraded)
        {
            internal.metrics.consecutive_recovery_probes += 1;
        }

        let event = internal.evaluate_circuit_breaker(now);

        if let Some(ref ev) = event {
            info!(
                credential = %ev.credential_id_redacted,
                provider = %ev.provider_id,
                previous = ?ev.previous_state,
                new = ?ev.new_state,
                error_rate = ev.error_rate_pct,
                trigger = %ev.trigger,
                "provider.health_state_changed"
            );
        }

        self.states
            .insert(credential_id.to_string(), internal.metrics.clone());
        self.internal_states
            .insert(credential_id.to_string(), internal);

        event
    }

    /// Record a health probe result (background task path).
    #[cfg_attr(test, allow(dead_code))]
    pub fn record_probe(
        &self,
        credential_id: &str,
        provider_id: &str,
        success: bool,
        latency_ms: u64,
    ) -> Option<HealthStateChangedEvent> {
        self.record_request(credential_id, provider_id, !success, latency_ms, None)
    }

    /// Spawn background health probing for a set of credentials.
    #[cfg_attr(test, allow(dead_code))]
    pub fn spawn_probe_tasks(self: &Arc<Self>, credentials: Vec<MonitoredCredential>) {
        let interval = probe_interval();
        for cred in credentials {
            let monitor = Arc::clone(self);
            let cred = cred.clone();
            tokio::spawn(async move {
                debug!(
                    credential_id = %redact_id(&cred.id),
                    provider = %cred.provider_id,
                    interval_secs = interval.as_secs(),
                    "starting health probe loop"
                );
                loop {
                    tokio::time::sleep(interval).await;
                    let start = Instant::now();
                    let success = probe_credential(&cred.endpoint_url).await;
                    let latency_ms = start.elapsed().as_millis() as u64;

                    if let Some(event) =
                        monitor.record_probe(&cred.id, &cred.provider_id, success, latency_ms)
                    {
                        warn!(
                            provider = %event.provider_id,
                            state = ?event.new_state,
                            trigger = %event.trigger,
                            "provider.health_state_changed (probe)"
                        );
                    }
                }
            });
        }
    }

    /// Snapshot current health states for all tracked credentials.
    pub fn snapshot(&self) -> Vec<CredentialHealthMetrics> {
        self.states.iter().map(|r| r.value().clone()).collect()
    }

    /// Check if a credential should be excluded from routing.
    fn is_routable(&self, credential_id: &str) -> bool {
        self.credential_state(credential_id) != HealthState::Unhealthy
    }
}

// ── Background probe ─────────────────────────────────────────────────────────

/// Minimal probe: send a tiny request to detect basic endpoint reachability.
async fn probe_credential(endpoint_url: &str) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    match client.get(endpoint_url).send().await {
        Ok(resp) => resp.status().is_success() || resp.status().as_u16() == 401,
        Err(_) => false,
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn percentile(sorted: &[u64], pct: u8) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let index = (pct as usize * (sorted.len() - 1)) / 100;
    sorted.get(index).copied()
}

fn redact_id(id: &str) -> String {
    if id.len() <= 8 {
        return "***".to_string();
    }
    format!("{}...{}", &id[..4], &id[id.len() - 4..])
}

// ── Tests ────────────────────────────────────────────────────────────────────

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
    use axum::{http::StatusCode, routing::get, Router};

    async fn start_probe_server(status: StatusCode) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route("/healthz", get(move || async move { status }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        (format!("http://{addr}/healthz"), handle)
    }

    #[test]
    fn new_monitor_returns_unknown_for_missing_credential() {
        let monitor = ProviderHealthMonitor::new();
        assert_eq!(
            monitor.credential_state("nonexistent"),
            HealthState::Unknown
        );
    }

    #[test]
    fn traffic_multiplier_defaults() {
        let monitor = ProviderHealthMonitor::new();
        assert!((monitor.traffic_multiplier("missing") - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn record_successful_request_stays_healthy() {
        let monitor = ProviderHealthMonitor::new();
        let event = monitor.record_request("cred-1", "openai", false, 120, None);
        assert!(event.is_none());
        assert_eq!(monitor.credential_state("cred-1"), HealthState::Healthy);
    }

    #[test]
    fn record_many_errors_transitions_to_degraded() {
        let monitor = ProviderHealthMonitor::new();

        for _ in 0..3 {
            monitor.record_request("cred-1", "openai", false, 100, None);
        }
        for _ in 0..5 {
            monitor.record_request("cred-1", "openai", true, 5000, None);
        }

        let state = monitor.credential_state("cred-1");
        assert!(
            state == HealthState::Degraded || state == HealthState::Unhealthy,
            "expected degraded or unhealthy after many errors, got {:?}",
            state
        );
    }

    #[test]
    fn record_overwhelming_errors_transitions_to_unhealthy() {
        let monitor = ProviderHealthMonitor::new();

        monitor.record_request("cred-1", "openai", false, 100, None);
        for _ in 0..20 {
            monitor.record_request("cred-1", "openai", true, 5000, None);
        }

        assert_eq!(monitor.credential_state("cred-1"), HealthState::Unhealthy);
        assert!(!monitor.is_routable("cred-1"));
    }

    #[test]
    fn recovery_after_consecutive_successes() {
        let monitor = ProviderHealthMonitor::new();

        monitor.record_request("cred-1", "openai", false, 100, None);
        for _ in 0..20 {
            monitor.record_request("cred-1", "openai", true, 5000, None);
        }
        assert_eq!(monitor.credential_state("cred-1"), HealthState::Unhealthy);

        for _ in 0..60 {
            monitor.record_request("cred-1", "openai", false, 80, None);
        }

        assert_eq!(monitor.credential_state("cred-1"), HealthState::Healthy);
    }

    #[test]
    fn exact_degraded_threshold_stays_healthy() {
        let monitor = ProviderHealthMonitor::new();
        monitor.record_request("cred-1", "openai", false, 100, None);
        monitor.record_request("cred-1", "openai", true, 500, None);

        assert_eq!(monitor.credential_state("cred-1"), HealthState::Healthy);
    }

    #[test]
    fn exact_unhealthy_threshold_stays_degraded() {
        let monitor = ProviderHealthMonitor::new();
        monitor.record_request("cred-1", "openai", false, 100, None);
        for _ in 0..9 {
            monitor.record_request("cred-1", "openai", true, 500, None);
        }

        assert_eq!(monitor.credential_state("cred-1"), HealthState::Degraded);
        assert!(monitor.is_routable("cred-1"));
    }

    #[test]
    fn snapshot_returns_all_tracked_credentials() {
        let monitor = ProviderHealthMonitor::new();
        monitor.record_request("cred-1", "openai", false, 100, None);
        monitor.record_request("cred-2", "anthropic", false, 80, None);

        let snap = monitor.snapshot();
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn rate_limit_remaining_recorded() {
        let monitor = ProviderHealthMonitor::new();
        monitor.record_request("cred-1", "openai", false, 100, Some(42));

        let metrics = monitor.states.get("cred-1").map(|r| r.clone());
        assert!(metrics.is_some());
        assert_eq!(
            metrics.as_ref().and_then(|m| m.rate_limit_remaining),
            Some(42)
        );
    }

    #[test]
    fn healthy_credential_is_routable() {
        let monitor = ProviderHealthMonitor::new();
        monitor.record_request("cred-1", "openai", false, 100, None);
        assert!(monitor.is_routable("cred-1"));
    }

    #[test]
    fn health_state_changed_event_on_transition() {
        let monitor = ProviderHealthMonitor::new();

        monitor.record_request("cred-1", "openai", false, 100, None);

        let mut transition_event = None;
        for _ in 0..30 {
            if let Some(ev) = monitor.record_request("cred-1", "openai", true, 5000, None) {
                transition_event = Some(ev);
            }
        }

        assert!(
            transition_event.is_some(),
            "expected a state transition event"
        );
        let event = transition_event.as_ref().unwrap_or_else(|| {
            std::process::abort();
        });
        assert_eq!(event.provider_id, "openai");
        assert!(
            event.new_state == HealthState::Degraded || event.new_state == HealthState::Unhealthy
        );
    }

    #[test]
    fn rolling_window_metrics_preserve_prior_events() {
        let monitor = ProviderHealthMonitor::new();
        monitor.record_request("cred-1", "openai", false, 100, None);
        monitor.record_request("cred-1", "openai", true, 500, None);

        let metrics = monitor
            .states
            .get("cred-1")
            .map(|entry| entry.value().clone())
            .expect("metrics");
        assert_eq!(metrics.request_count_60s, 2);
        assert_eq!(metrics.error_count_60s, 1);
        assert!((metrics.error_rate_pct - 50.0).abs() < f64::EPSILON);
        assert_eq!(metrics.latency_p50_ms, Some(100));
        assert_eq!(metrics.latency_p95_ms, Some(100));
    }

    #[test]
    fn percentile_empty() {
        assert_eq!(percentile(&[], 50), None);
    }

    #[test]
    fn percentile_single() {
        assert_eq!(percentile(&[100], 50), Some(100));
        assert_eq!(percentile(&[100], 95), Some(100));
    }

    #[test]
    fn percentile_multiple() {
        let data: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&data, 50), Some(50));
        assert_eq!(percentile(&data, 95), Some(95));
    }

    #[test]
    fn redact_short_id() {
        assert_eq!(redact_id("abc"), "***");
    }

    #[test]
    fn redact_long_id() {
        assert_eq!(redact_id("sk-abcdefghij"), "sk-a...ghij");
    }

    #[test]
    fn probe_interval_default() {
        let _guard = crate::test_support::env_lock().lock().unwrap();
        crate::test_support::unset_var("VERDICTAN_HEALTH_PROBE_INTERVAL_SECS");
        let interval = probe_interval();
        assert!(interval.as_secs() >= 10);
    }

    #[test]
    fn degraded_traffic_fraction_is_ten_percent() {
        assert!((DEGRADED_TRAFFIC_FRACTION - 0.10).abs() < f64::EPSILON);
    }

    #[test]
    fn traffic_multiplier_for_healthy_is_full() {
        let monitor = ProviderHealthMonitor::new();
        monitor.record_request("cred-1", "openai", false, 50, None);
        assert!((monitor.traffic_multiplier("cred-1") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn traffic_multiplier_for_degraded_and_unhealthy_states() {
        let monitor = ProviderHealthMonitor::new();
        monitor.record_request("cred-degraded", "openai", false, 100, None);
        for _ in 0..2 {
            monitor.record_request("cred-degraded", "openai", true, 500, None);
        }

        monitor.record_request("cred-unhealthy", "openai", false, 100, None);
        for _ in 0..20 {
            monitor.record_request("cred-unhealthy", "openai", true, 500, None);
        }

        assert!((monitor.traffic_multiplier("cred-degraded") - 0.10).abs() < f64::EPSILON);
        assert!((monitor.traffic_multiplier("cred-unhealthy") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn states_accessor_returns_live_shared_map() {
        let monitor = ProviderHealthMonitor::new();
        assert!(monitor.states().is_empty());

        monitor.record_request("cred-1", "openai", false, 100, None);
        let states = monitor.states();
        let metrics = states.get("cred-1").expect("credential metrics");
        assert_eq!(metrics.provider_id, "openai");
        assert_eq!(metrics.request_count_60s, 1);
    }

    #[test]
    fn record_probe_treats_failure_as_error_request() {
        let monitor = ProviderHealthMonitor::new();
        let event = monitor.record_probe("cred-1", "openai", false, 250);

        let event = event.expect("failed probe should trip the breaker from an empty history");
        assert_eq!(event.new_state, HealthState::Unhealthy);
        let states = monitor.states();
        let metrics = states
            .get("cred-1")
            .expect("credential metrics after probe");
        assert_eq!(metrics.error_count_60s, 1);
        assert_eq!(metrics.request_count_60s, 1);
        assert_eq!(metrics.state, HealthState::Unhealthy);
    }

    #[test]
    fn evaluate_circuit_breaker_marks_unhealthy_after_long_silence() {
        let mut state =
            CredentialInternalState::new("cred-silence".to_string(), "openai".to_string());
        let now = Instant::now();
        state.metrics.state = HealthState::Healthy;
        state.metrics.last_success_at = Some(now - Duration::from_secs(UNHEALTHY_SILENCE_SECS + 1));

        let event = state
            .evaluate_circuit_breaker(now)
            .expect("silence transition");

        assert_eq!(state.metrics.state, HealthState::Unhealthy);
        assert_eq!(event.previous_state, HealthState::Healthy);
        assert_eq!(event.new_state, HealthState::Unhealthy);
        assert_eq!(event.trigger, "no_success_5min");
        assert_eq!(event.credential_id_redacted, "cred...ence");
    }

    #[test]
    fn evaluate_circuit_breaker_recovers_after_required_probes() {
        let mut state =
            CredentialInternalState::new("cred-recovery".to_string(), "openai".to_string());
        let now = Instant::now();
        state.metrics.state = HealthState::Degraded;
        state.metrics.error_rate_pct = 0.0;
        state.metrics.request_count_60s = 3;
        state.metrics.consecutive_recovery_probes = RECOVERY_CONSECUTIVE_PROBES;

        let event = state
            .evaluate_circuit_breaker(now)
            .expect("recovery transition");

        assert_eq!(state.metrics.state, HealthState::Healthy);
        assert_eq!(event.previous_state, HealthState::Degraded);
        assert_eq!(event.new_state, HealthState::Healthy);
        assert_eq!(event.trigger, "recovery_after_3_probes");
    }

    #[test]
    fn probe_interval_respects_env_and_clamps() {
        let _guard = crate::test_support::env_lock().lock().unwrap();
        crate::test_support::unset_var("VERDICTAN_HEALTH_PROBE_INTERVAL_SECS");

        crate::test_support::set_var("VERDICTAN_HEALTH_PROBE_INTERVAL_SECS", "2");
        assert_eq!(probe_interval(), Duration::from_secs(10));

        crate::test_support::set_var("VERDICTAN_HEALTH_PROBE_INTERVAL_SECS", "301");
        assert_eq!(probe_interval(), Duration::from_secs(300));

        crate::test_support::unset_var("VERDICTAN_HEALTH_PROBE_INTERVAL_SECS");
    }

    #[test]
    fn probe_interval_invalid_value_falls_back_to_default() {
        let _guard = crate::test_support::env_lock().lock().unwrap();
        crate::test_support::set_var("VERDICTAN_HEALTH_PROBE_INTERVAL_SECS", "not-a-number");
        assert_eq!(
            probe_interval(),
            Duration::from_secs(DEFAULT_PROBE_INTERVAL_SECS)
        );
        crate::test_support::unset_var("VERDICTAN_HEALTH_PROBE_INTERVAL_SECS");
    }

    #[tokio::test]
    async fn spawn_probe_tasks_accepts_empty_credential_lists() {
        let monitor = Arc::new(ProviderHealthMonitor::new());
        monitor.spawn_probe_tasks(Vec::new());
        tokio::task::yield_now().await;
        assert!(monitor.states().is_empty());
    }

    // ── parse_health_monitor_config ──────────────────────────────────────

    #[test]
    fn parse_config_absent() {
        let root = serde_json::json!({});
        let cfg = parse_health_monitor_config(&root);
        assert!(cfg.providers.is_empty());
        assert_eq!(cfg.unhealthy_threshold, 3);
    }

    #[test]
    fn parse_config_with_providers() {
        let root = serde_json::json!({
            "health_monitor": {
                "providers": [
                    { "name": "openai", "endpoint": "https://api.openai.com/healthz" }
                ],
                "unhealthy_threshold": 5
            }
        });
        let cfg = parse_health_monitor_config(&root);
        assert_eq!(cfg.providers.len(), 1);
        assert_eq!(cfg.providers[0].interval_seconds, 30);
        assert_eq!(cfg.providers[0].timeout_ms, 5000);
        assert_eq!(cfg.unhealthy_threshold, 5);
    }

    #[test]
    fn parse_config_invalid_section_falls_back_to_default() {
        let root = serde_json::json!({
            "health_monitor": {
                "providers": "not-a-list"
            }
        });
        let cfg = parse_health_monitor_config(&root);
        assert!(cfg.providers.is_empty());
        assert_eq!(cfg.unhealthy_threshold, default_unhealthy_threshold());
    }

    // ── HealthState serde ────────────────────────────────────────────────

    #[test]
    fn health_state_serde_roundtrip() {
        for state in [
            HealthState::Healthy,
            HealthState::Degraded,
            HealthState::Unhealthy,
            HealthState::Unknown,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let recovered: HealthState = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, state);
        }
    }

    #[test]
    fn health_state_default_is_unknown() {
        assert_eq!(HealthState::default(), HealthState::Unknown);
    }

    // ── HealthMonitorProviderEntry defaults ──────────────────────────────

    #[test]
    fn provider_entry_defaults() {
        let entry: HealthMonitorProviderEntry =
            serde_json::from_str(r#"{"name":"test","endpoint":"http://localhost"}"#).unwrap();
        assert_eq!(entry.interval_seconds, 30);
        assert_eq!(entry.timeout_ms, 5000);
    }

    // ── CredentialHealthMetrics serialization ────────────────────────────

    #[test]
    fn credential_metrics_serialize() {
        let metrics = CredentialHealthMetrics::new("cred-1".to_string(), "openai".to_string());
        let json = serde_json::to_value(&metrics).unwrap();
        assert_eq!(json["credential_id"], "cred-1");
        assert_eq!(json["provider_id"], "openai");
        assert_eq!(json["state"], "healthy");
    }

    // ── multiple providers tracked independently ─────────────────────────

    #[test]
    fn independent_provider_tracking() {
        let monitor = ProviderHealthMonitor::new();
        for _ in 0..20 {
            monitor.record_request("cred-1", "openai", true, 5000, None);
        }
        monitor.record_request("cred-2", "anthropic", false, 100, None);

        assert_eq!(monitor.credential_state("cred-1"), HealthState::Unhealthy);
        assert_eq!(monitor.credential_state("cred-2"), HealthState::Healthy);
    }

    #[tokio::test]
    async fn probe_credential_treats_success_and_unauthorized_as_reachable() {
        let (ok_url, ok_handle) = start_probe_server(StatusCode::OK).await;
        let (unauthorized_url, unauthorized_handle) =
            start_probe_server(StatusCode::UNAUTHORIZED).await;

        let ok = probe_credential(&ok_url).await;
        let unauthorized = probe_credential(&unauthorized_url).await;

        ok_handle.abort();
        unauthorized_handle.abort();

        assert!(ok);
        assert!(unauthorized);
    }
}
