// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Circuit breaker implementation.
//! Note: State is per-process only. In distributed deployments, each process
//! maintains independent breaker state. For shared state, a Redis-backed
//! backend could be introduced behind a feature flag.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Circuit breaker state for a single provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Declarative circuit breaker configuration.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Kill-switch: when false, the circuit breaker is disabled.
    pub enabled: bool,
    /// Number of consecutive failures before opening the circuit.
    pub consecutive_failure_threshold: u32,
    /// Duration of the open state before transitioning to half-open.
    pub cooldown: Duration,
    /// Number of successes required in half-open to close the circuit.
    pub half_open_successes: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            consecutive_failure_threshold: 5,
            cooldown: Duration::from_secs(30),
            half_open_successes: 1,
        }
    }
}

/// Internal mutable state for one provider's circuit breaker.
#[derive(Debug)]
struct ProviderCircuitState {
    state: CircuitState,
    consecutive_failures: u32,
    last_failure_at: Option<Instant>,
    half_open_successes: u32,
}

impl Default for ProviderCircuitState {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            last_failure_at: None,
            half_open_successes: 0,
        }
    }
}

/// Thread-safe circuit breaker manager for all providers.
#[derive(Debug, Clone)]
pub struct CircuitBreakerManager {
    config: CircuitBreakerConfig,
    states: Arc<Mutex<HashMap<String, ProviderCircuitState>>>,
}

impl CircuitBreakerManager {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            states: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns true if the provider is allowed to receive traffic.
    pub fn is_allowed(&self, provider_id: &str) -> bool {
        if !self.config.enabled {
            return true;
        }
        let mut states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        let entry = states.entry(provider_id.to_string()).or_default();
        match entry.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if cooldown has elapsed → transition to HalfOpen
                if let Some(last) = entry.last_failure_at {
                    if last.elapsed() >= self.config.cooldown {
                        tracing::info!(
                            provider_id = provider_id,
                            "circuit breaker: cooldown elapsed, transitioning to half-open"
                        );
                        entry.state = CircuitState::HalfOpen;
                        entry.half_open_successes = 0;
                        true
                    } else {
                        false
                    }
                } else {
                    // No recorded failure time — shouldn't happen, but allow
                    true
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful request for a provider.
    pub fn record_success(&self, provider_id: &str) {
        if !self.config.enabled {
            return;
        }
        let mut states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        let entry = states.entry(provider_id.to_string()).or_default();
        match entry.state {
            CircuitState::Closed => {
                entry.consecutive_failures = 0;
            }
            CircuitState::HalfOpen => {
                entry.half_open_successes += 1;
                if entry.half_open_successes >= self.config.half_open_successes {
                    tracing::info!(
                        provider_id = provider_id,
                        "circuit breaker: half-open probe succeeded, closing circuit"
                    );
                    entry.state = CircuitState::Closed;
                    entry.consecutive_failures = 0;
                    entry.half_open_successes = 0;
                }
            }
            CircuitState::Open => {
                // Shouldn't happen (we don't send to open providers)
            }
        }
    }

    /// Record a failed request for a provider.
    pub fn record_failure(&self, provider_id: &str) {
        if !self.config.enabled {
            return;
        }
        let mut states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        let entry = states.entry(provider_id.to_string()).or_default();
        entry.consecutive_failures += 1;
        entry.last_failure_at = Some(Instant::now());
        match entry.state {
            CircuitState::Closed => {
                if entry.consecutive_failures >= self.config.consecutive_failure_threshold {
                    tracing::warn!(
                        provider_id = provider_id,
                        failures = entry.consecutive_failures,
                        cooldown_secs = self.config.cooldown.as_secs(),
                        "circuit breaker: opening circuit"
                    );
                    entry.state = CircuitState::Open;
                }
            }
            CircuitState::HalfOpen => {
                tracing::warn!(
                    provider_id = provider_id,
                    "circuit breaker: half-open probe failed, reopening circuit"
                );
                entry.state = CircuitState::Open;
                entry.half_open_successes = 0;
            }
            CircuitState::Open => {}
        }
    }

    /// Get the current circuit state for a provider (for testing/metrics).
    #[cfg_attr(not(test), allow(dead_code))]
    fn get_state(&self, provider_id: &str) -> CircuitState {
        let states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        states
            .get(provider_id)
            .map(|s| s.state)
            .unwrap_or(CircuitState::Closed)
    }

    /// Snapshot current circuit states for all tracked providers.
    pub fn snapshot(&self) -> HashMap<String, CircuitStateSnapshot> {
        let states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        states
            .iter()
            .map(|(id, state)| {
                (
                    id.clone(),
                    CircuitStateSnapshot {
                        state: state.state,
                        consecutive_failures: state.consecutive_failures,
                        half_open_successes: state.half_open_successes,
                    },
                )
            })
            .collect()
    }

    /// Restore circuit states from a snapshot, only for providers present in this manager.
    ///
    /// Open circuits have their `last_failure_at` reset to now so the cooldown
    /// timer restarts from the moment of reload rather than from the original failure.
    pub fn restore(&self, snapshot: &HashMap<String, CircuitStateSnapshot>) {
        let mut states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        for (id, snap) in snapshot {
            let entry = states.entry(id.clone()).or_default();
            entry.state = snap.state;
            entry.consecutive_failures = snap.consecutive_failures;
            entry.half_open_successes = snap.half_open_successes;
            // Reset the cooldown timer for Open circuits so the new config gets
            // a fresh window rather than an already-elapsed one.
            if snap.state == CircuitState::Open {
                entry.last_failure_at = Some(Instant::now());
            }
        }
    }
}

/// Lightweight snapshot of a single provider's circuit state, used for
/// preserving health across config reloads.
#[derive(Debug, Clone)]
pub struct CircuitStateSnapshot {
    pub state: CircuitState,
    pub consecutive_failures: u32,
    pub half_open_successes: u32,
}

/// Parse circuit breaker config from the `providers` section.
pub fn parse_circuit_breaker_config(section: &serde_json::Value) -> CircuitBreakerConfig {
    let Some(cb) = section.get("circuit_breaker") else {
        return CircuitBreakerConfig::default();
    };
    CircuitBreakerConfig {
        enabled: cb.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
        consecutive_failure_threshold: cb
            .get("consecutive_failure_threshold")
            .and_then(|v| v.as_u64())
            .unwrap_or(5) as u32,
        cooldown: Duration::from_secs(
            cb.get("cooldown_seconds")
                .and_then(|v| v.as_u64())
                .unwrap_or(30),
        ),
        half_open_successes: cb
            .get("half_open_successes")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32,
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
    use serde_json::json;

    fn test_config(threshold: u32) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            enabled: true,
            consecutive_failure_threshold: threshold,
            cooldown: Duration::from_millis(50),
            half_open_successes: 1,
        }
    }

    #[test]
    fn default_config_values() {
        let config = CircuitBreakerConfig::default();
        assert!(config.enabled);
        assert_eq!(config.consecutive_failure_threshold, 5);
        assert_eq!(config.cooldown, Duration::from_secs(30));
        assert_eq!(config.half_open_successes, 1);
    }

    #[test]
    fn new_provider_starts_closed() {
        let manager = CircuitBreakerManager::new(test_config(3));
        assert_eq!(manager.get_state("provider-a"), CircuitState::Closed);
    }

    #[test]
    fn closed_circuit_allows_traffic() {
        let manager = CircuitBreakerManager::new(test_config(3));
        assert!(manager.is_allowed("provider-a"));
    }

    #[test]
    fn failures_below_threshold_stay_closed() {
        let manager = CircuitBreakerManager::new(test_config(3));
        manager.record_failure("p1");
        manager.record_failure("p1");
        assert_eq!(manager.get_state("p1"), CircuitState::Closed);
        assert!(manager.is_allowed("p1"));
    }

    #[test]
    fn failures_at_threshold_open_circuit() {
        let manager = CircuitBreakerManager::new(test_config(3));
        manager.record_failure("p1");
        manager.record_failure("p1");
        manager.record_failure("p1");
        assert_eq!(manager.get_state("p1"), CircuitState::Open);
    }

    #[test]
    fn open_circuit_blocks_traffic() {
        let manager = CircuitBreakerManager::new(test_config(3));
        for _ in 0..3 {
            manager.record_failure("p1");
        }
        assert!(!manager.is_allowed("p1"));
    }

    #[test]
    fn success_resets_failure_counter_in_closed() {
        let manager = CircuitBreakerManager::new(test_config(3));
        manager.record_failure("p1");
        manager.record_failure("p1");
        manager.record_success("p1");
        manager.record_failure("p1");
        manager.record_failure("p1");
        assert_eq!(manager.get_state("p1"), CircuitState::Closed);
    }

    #[test]
    fn disabled_circuit_breaker_always_allows() {
        let config = CircuitBreakerConfig {
            enabled: false,
            ..CircuitBreakerConfig::default()
        };
        let manager = CircuitBreakerManager::new(config);
        for _ in 0..100 {
            manager.record_failure("p1");
        }
        assert!(manager.is_allowed("p1"));
    }

    #[test]
    fn disabled_record_success_is_noop() {
        let config = CircuitBreakerConfig {
            enabled: false,
            ..CircuitBreakerConfig::default()
        };
        let manager = CircuitBreakerManager::new(config);
        manager.record_success("p1");
        assert_eq!(manager.get_state("p1"), CircuitState::Closed);
    }

    #[test]
    fn disabled_record_failure_is_noop() {
        let config = CircuitBreakerConfig {
            enabled: false,
            ..CircuitBreakerConfig::default()
        };
        let manager = CircuitBreakerManager::new(config);
        manager.record_failure("p1");
        assert_eq!(manager.get_state("p1"), CircuitState::Closed);
    }

    #[test]
    fn providers_are_independent() {
        let manager = CircuitBreakerManager::new(test_config(2));
        manager.record_failure("p1");
        manager.record_failure("p1");
        assert_eq!(manager.get_state("p1"), CircuitState::Open);
        assert_eq!(manager.get_state("p2"), CircuitState::Closed);
        assert!(manager.is_allowed("p2"));
    }

    #[test]
    fn snapshot_captures_state() {
        let manager = CircuitBreakerManager::new(test_config(2));
        manager.record_failure("p1");
        manager.record_failure("p1");
        let snap = manager.snapshot();
        assert_eq!(snap["p1"].state, CircuitState::Open);
        assert_eq!(snap["p1"].consecutive_failures, 2);
    }

    #[test]
    fn restore_applies_snapshot() {
        let manager = CircuitBreakerManager::new(test_config(2));
        let mut snap = HashMap::new();
        snap.insert(
            "p1".to_string(),
            CircuitStateSnapshot {
                state: CircuitState::Open,
                consecutive_failures: 5,
                half_open_successes: 0,
            },
        );
        manager.restore(&snap);
        assert_eq!(manager.get_state("p1"), CircuitState::Open);
        assert!(!manager.is_allowed("p1"));
    }

    #[test]
    fn parse_circuit_breaker_config_defaults_without_section() {
        let section = json!({});
        let config = parse_circuit_breaker_config(&section);
        assert!(config.enabled);
        assert_eq!(config.consecutive_failure_threshold, 5);
        assert_eq!(config.cooldown, Duration::from_secs(30));
        assert_eq!(config.half_open_successes, 1);
    }

    #[test]
    fn parse_circuit_breaker_config_custom_values() {
        let section = json!({
            "circuit_breaker": {
                "enabled": false,
                "consecutive_failure_threshold": 10,
                "cooldown_seconds": 60,
                "half_open_successes": 3
            }
        });
        let config = parse_circuit_breaker_config(&section);
        assert!(!config.enabled);
        assert_eq!(config.consecutive_failure_threshold, 10);
        assert_eq!(config.cooldown, Duration::from_secs(60));
        assert_eq!(config.half_open_successes, 3);
    }

    #[test]
    fn parse_circuit_breaker_config_partial_values() {
        let section = json!({
            "circuit_breaker": {
                "cooldown_seconds": 120
            }
        });
        let config = parse_circuit_breaker_config(&section);
        assert!(config.enabled);
        assert_eq!(config.consecutive_failure_threshold, 5);
        assert_eq!(config.cooldown, Duration::from_secs(120));
        assert_eq!(config.half_open_successes, 1);
    }
}
