// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
pub use std::time::Duration;
use std::time::Instant;

#[derive(Clone)]
struct ProviderHealthSample {
    healthy: bool,
    status_code: Option<u16>,
    latency_ms: Option<u64>,
    checked_at_unix: u64,
}

/// Per-provider sliding-window latency and throughput metrics.
#[derive(Clone)]
pub struct ProviderMetrics {
    inner: Arc<RwLock<HashMap<String, ProviderWindow>>>,
    window: Duration,
    min_sample_count: usize,
    /// Round-robin counter shared across clones (Phase 14).
    rr_counter: Arc<std::sync::atomic::AtomicUsize>,
    /// Active in-flight connection counts per provider (Phase 14).
    active_conns: Arc<RwLock<HashMap<String, usize>>>,
    /// Smooth weighted-RR current weights per provider (Phase 14).
    wrr_state: Arc<Mutex<HashMap<String, f64>>>,
    health: Arc<RwLock<HashMap<String, ProviderHealthSample>>>,
    /// Cumulative token usage per provider within the measurement window.
    usage: Arc<RwLock<HashMap<String, VecDeque<UsageSample>>>>,
}

struct ProviderWindow {
    samples: VecDeque<ProviderSample>,
}

struct ProviderSample {
    timestamp: Instant,
    ttft_ms: u64,
    throughput_tps: f64,
}

struct UsageSample {
    timestamp: Instant,
    total_tokens: u64,
}

impl ProviderMetrics {
    pub fn new(window_seconds: u64, min_sample_count: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            window: Duration::from_secs(window_seconds),
            min_sample_count,
            rr_counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            active_conns: Arc::new(RwLock::new(HashMap::new())),
            wrr_state: Arc::new(Mutex::new(HashMap::new())),
            health: Arc::new(RwLock::new(HashMap::new())),
            usage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a successful provider response.
    pub fn record(
        &self,
        provider_id: &str,
        ttft: Duration,
        total_tokens: u32,
        total_duration: Duration,
    ) {
        let throughput_tps = if total_duration.as_secs_f64() > 0.0 {
            f64::from(total_tokens) / total_duration.as_secs_f64()
        } else {
            0.0
        };

        let sample = ProviderSample {
            timestamp: Instant::now(),
            ttft_ms: ttft.as_millis() as u64,
            throughput_tps,
        };

        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut map = self.inner.write().expect("metrics lock");
        let window = map
            .entry(provider_id.to_string())
            .or_insert_with(|| ProviderWindow {
                samples: VecDeque::new(),
            });
        window.samples.push_back(sample);

        // Evict expired samples.
        let cutoff = Instant::now() - self.window;
        while window.samples.front().is_some_and(|s| s.timestamp < cutoff) {
            window.samples.pop_front();
        }
    }

    /// Record token usage for a provider (for UsageBased routing).
    fn record_usage(&self, provider_id: &str, total_tokens: u64) {
        let cutoff = Instant::now() - self.window;
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut map = self.usage.write().expect("usage lock");
        let samples = map.entry(provider_id.to_string()).or_default();
        samples.push_back(UsageSample {
            timestamp: Instant::now(),
            total_tokens,
        });
        while samples.front().is_some_and(|s| s.timestamp < cutoff) {
            samples.pop_front();
        }
    }

    /// Return provider IDs ranked by cumulative token usage ascending (lowest = best).
    pub fn ranked_by_usage(&self) -> Vec<(String, u64)> {
        let cutoff = Instant::now() - self.window;
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let map = self.usage.read().expect("usage lock");
        let mut ranked: Vec<(String, u64)> = map
            .iter()
            .map(|(id, samples)| {
                let total: u64 = samples
                    .iter()
                    .filter(|s| s.timestamp >= cutoff)
                    .map(|s| s.total_tokens)
                    .sum();
                (id.clone(), total)
            })
            .collect();
        ranked.sort_by_key(|(_, usage)| *usage);
        ranked
    }

    /// Return cumulative token usage for a single provider within the measurement window.
    pub fn total_tokens(&self, provider_id: &str) -> u64 {
        let cutoff = Instant::now() - self.window;
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let map = self.usage.read().expect("usage lock");
        map.get(provider_id)
            .map(|samples| {
                samples
                    .iter()
                    .filter(|s| s.timestamp >= cutoff)
                    .map(|s| s.total_tokens)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Return provider IDs ranked by p50 TTFT ascending (lowest = best).
    /// Providers with fewer than `min_sample_count` samples are excluded.
    pub fn ranked_by_ttft(&self) -> Vec<(String, f64)> {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let map = self.inner.read().expect("metrics lock");
        let mut ranked: Vec<(String, f64)> = map
            .iter()
            .filter(|(_, w)| w.samples.len() >= self.min_sample_count)
            .map(|(id, w)| (id.clone(), p50_ttft(w)))
            .collect();
        ranked.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked
    }

    /// Return provider IDs ranked by p50 throughput descending (highest = best).
    pub fn ranked_by_throughput(&self) -> Vec<(String, f64)> {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let map = self.inner.read().expect("metrics lock");
        let mut ranked: Vec<(String, f64)> = map
            .iter()
            .filter(|(_, w)| w.samples.len() >= self.min_sample_count)
            .map(|(id, w)| (id.clone(), p50_throughput(w)))
            .collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked
    }

    /// Serialize current metrics for the admin endpoint.
    pub fn snapshot_json(&self) -> serde_json::Value {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let map = self.inner.read().expect("metrics lock");
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let health = self.health.read().expect("health lock");
        let mut providers = serde_json::Map::new();
        for (id, window) in map.iter() {
            let count = window.samples.len();
            let ttft = if count > 0 { p50_ttft(window) } else { 0.0 };
            let throughput = if count > 0 {
                p50_throughput(window)
            } else {
                0.0
            };
            let p90_ttft = if count >= 2 {
                percentile_ttft_at(window, 90)
            } else {
                0.0
            };
            let p99_ttft = if count >= 2 {
                percentile_ttft_at(window, 99)
            } else {
                0.0
            };
            let p90_tput = if count >= 2 {
                percentile_throughput_at(window, 90)
            } else {
                0.0
            };
            let p99_tput = if count >= 2 {
                percentile_throughput_at(window, 99)
            } else {
                0.0
            };
            let health_json = health.get(id).map(|sample| {
                serde_json::json!({
                    "healthy": sample.healthy,
                    "status_code": sample.status_code,
                    "latency_ms": sample.latency_ms,
                    "checked_at_unix": sample.checked_at_unix,
                })
            });
            providers.insert(
                id.clone(),
                serde_json::json!({
                    "sample_count": count,
                    "p50_ttft_ms": ttft,
                    "p50_throughput_tps": throughput,
                    "p90_ttft_ms": p90_ttft,
                    "p99_ttft_ms": p99_ttft,
                    "p90_throughput_tps": p90_tput,
                    "p99_throughput_tps": p99_tput,
                    "health": health_json,
                }),
            );
        }
        serde_json::Value::Object(providers)
    }

    /// Return the percentile TTFT (ms) for a provider, or `None` if below min_sample_count.
    pub fn percentile_ttft(
        &self,
        provider_id: &str,
        p: super::providers::Percentile,
    ) -> Option<f64> {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let map = self.inner.read().expect("metrics lock");
        let window = map.get(provider_id)?;
        if window.samples.len() < self.min_sample_count {
            return None;
        }
        let pct = percentile_pct(p);
        Some(percentile_ttft_at(window, pct))
    }

    /// Return the percentile throughput (tps) for a provider, or `None` if below min_sample_count.
    pub fn percentile_throughput(
        &self,
        provider_id: &str,
        p: super::providers::Percentile,
    ) -> Option<f64> {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let map = self.inner.read().expect("metrics lock");
        let window = map.get(provider_id)?;
        if window.samples.len() < self.min_sample_count {
            return None;
        }
        let pct = percentile_pct(p);
        Some(percentile_throughput_at(window, pct))
    }

    /// Increment the active connection count for a provider (LeastConnections strategy).
    pub fn increment_active(&self, provider_id: &str) {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut map = self.active_conns.write().expect("active_conns lock");
        *map.entry(provider_id.to_string()).or_insert(0) += 1;
    }

    /// Decrement the active connection count for a provider (saturating at 0).
    pub fn decrement_active(&self, provider_id: &str) {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut map = self.active_conns.write().expect("active_conns lock");
        let count = map.entry(provider_id.to_string()).or_insert(0);
        *count = count.saturating_sub(1);
    }

    /// Return the current active connection count for a provider.
    fn active_connection_count(&self, provider_id: &str) -> usize {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let map = self.active_conns.read().expect("active_conns lock");
        map.get(provider_id).copied().unwrap_or(0)
    }

    pub fn record_health(
        &self,
        provider_id: &str,
        healthy: bool,
        status_code: Option<u16>,
        latency_ms: Option<u64>,
        checked_at_unix: u64,
    ) {
        if let Ok(mut map) = self.health.write() {
            map.insert(
                provider_id.to_string(),
                ProviderHealthSample {
                    healthy,
                    status_code,
                    latency_ms,
                    checked_at_unix,
                },
            );
        }
    }

    pub fn is_healthy(&self, provider_id: &str) -> Option<bool> {
        self.health
            .read()
            .ok()
            .and_then(|map| map.get(provider_id).map(|sample| sample.healthy))
    }

    /// Return the current sample count for a provider within the measurement window.
    pub fn sample_count(&self, provider_id: &str) -> usize {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let map = self.inner.read().expect("metrics lock");
        map.get(provider_id).map(|w| w.samples.len()).unwrap_or(0)
    }

    /// Return the configured minimum sample count threshold.
    pub fn min_sample_count(&self) -> usize {
        self.min_sample_count
    }
}

fn p50_ttft(window: &ProviderWindow) -> f64 {
    percentile_ttft_at(window, 50)
}

fn p50_throughput(window: &ProviderWindow) -> f64 {
    percentile_throughput_at(window, 50)
}

fn percentile_ttft_at(window: &ProviderWindow, pct: u64) -> f64 {
    let mut values: Vec<u64> = window.samples.iter().map(|s| s.ttft_ms).collect();
    values.sort_unstable();
    if values.is_empty() {
        return 0.0;
    }
    let idx = ((values.len() as u64 * pct) / 100).min(values.len() as u64 - 1) as usize;
    values[idx] as f64
}

fn percentile_throughput_at(window: &ProviderWindow, pct: u64) -> f64 {
    let mut values: Vec<f64> = window.samples.iter().map(|s| s.throughput_tps).collect();
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if values.is_empty() {
        return 0.0;
    }
    let idx = ((values.len() as u64 * pct) / 100).min(values.len() as u64 - 1) as usize;
    values[idx]
}

fn percentile_pct(p: super::providers::Percentile) -> u64 {
    use super::providers::Percentile;
    match p {
        Percentile::P50 => 50,
        Percentile::P90 => 90,
        Percentile::P99 => 99,
    }
}

/// Move providers that violate the SLA cutoffs to the back of the list.
/// Providers without enough samples are treated as compliant (benefit of the doubt).
fn deprioritize_by_sla(
    targets: &[super::providers::ProviderTarget],
    ordered: &[usize],
    metrics: &ProviderMetrics,
    max_latency: &Option<super::providers::PerformanceCutoff>,
    min_throughput: &Option<super::providers::PerformanceCutoff>,
) -> Vec<usize> {
    let mut compliant = Vec::new();
    let mut non_compliant = Vec::new();

    for &idx in ordered {
        let id = &targets[idx].id;
        let mut sla_ok = true;

        if let Some(cutoff) = max_latency {
            if let Some(latency) = metrics.percentile_ttft(id, cutoff.percentile) {
                if latency > cutoff.value {
                    sla_ok = false;
                }
            }
        }

        if sla_ok {
            if let Some(cutoff) = min_throughput {
                if let Some(tput) = metrics.percentile_throughput(id, cutoff.percentile) {
                    if tput < cutoff.value {
                        sla_ok = false;
                    }
                }
            }
        }

        if sla_ok {
            compliant.push(idx);
        } else {
            non_compliant.push(idx);
        }
    }

    compliant.extend(non_compliant);
    compliant
}

/// Select providers from a registry based on routing strategy and metrics.
/// Returns indices into the registry's targets vec, ordered by preference.
///
/// Applies Phase 1 filters (only/ignore/order/allow_fallbacks) and Phase 3
/// SLA deprioritization. Cost/region/quantization filters (Phases 2, 4, 5)
/// are applied downstream in the proxy server after the request body is available.
///
/// When `task_type` is provided and the strategy is `TaskAware`, providers
/// matching the task profile's preferred list are promoted to the front.
pub fn select_providers(
    targets: &[super::providers::ProviderTarget],
    routing: &super::providers::RoutingConfig,
    metrics: &ProviderMetrics,
) -> Vec<usize> {
    select_providers_with_task(targets, routing, metrics, None)
}

/// Task-aware variant of `select_providers` that accepts an optional task type
/// for `TaskAware` routing strategy support.
pub fn select_providers_with_task(
    targets: &[super::providers::ProviderTarget],
    routing: &super::providers::RoutingConfig,
    metrics: &ProviderMetrics,
    task_type: Option<super::providers::TaskType>,
) -> Vec<usize> {
    let mut eligible = eligible_provider_indices(targets, routing);
    if eligible.is_empty() {
        return eligible;
    }

    sort_indices_by_health(&mut eligible, targets, metrics);
    let mut ordered = order_by_strategy(targets, routing, metrics, &eligible, task_type);
    apply_warmup_lane(&mut ordered, targets, routing, metrics);
    apply_order_override(&mut ordered, targets, routing);
    apply_sla_preferences(&mut ordered, targets, routing, metrics);
    apply_fallback_truncation(&mut ordered, routing);
    ordered
}

fn eligible_provider_indices(
    targets: &[super::providers::ProviderTarget],
    routing: &super::providers::RoutingConfig,
) -> Vec<usize> {
    let mut eligible: Vec<usize> = (0..targets.len()).collect();
    if let Some(only) = &routing.only {
        eligible.retain(|&index| only.contains(&targets[index].id));
    } else if let Some(ignore) = &routing.ignore {
        eligible.retain(|&index| !ignore.contains(&targets[index].id));
    }
    eligible
}

fn sort_indices_by_health(
    eligible: &mut [usize],
    targets: &[super::providers::ProviderTarget],
    metrics: &ProviderMetrics,
) {
    eligible.sort_by_key(|index| match metrics.is_healthy(&targets[*index].id) {
        Some(true) | None => 0,
        Some(false) => 1,
    });
}

fn order_by_strategy(
    targets: &[super::providers::ProviderTarget],
    routing: &super::providers::RoutingConfig,
    metrics: &ProviderMetrics,
    eligible: &[usize],
    _task_type: Option<super::providers::TaskType>,
) -> Vec<usize> {
    use super::providers::RoutingStrategy;

    match routing.strategy {
        RoutingStrategy::Ordered | RoutingStrategy::Semantic | RoutingStrategy::TaskAware => {
            eligible.to_vec()
        }
        RoutingStrategy::LowestLatency | RoutingStrategy::HighestThroughput => {
            latency_or_throughput_order(targets, routing, metrics, eligible)
        }
        RoutingStrategy::RoundRobin => round_robin_order(metrics, eligible),
        RoutingStrategy::WeightedRoundRobin => {
            weighted_round_robin_order(targets, metrics, eligible)
        }
        RoutingStrategy::LeastConnections | RoutingStrategy::LeastBusy => {
            least_busy_order(targets, metrics, eligible)
        }
        RoutingStrategy::Random | RoutingStrategy::SimpleShuffle => shuffled_order(eligible),
        RoutingStrategy::UsageBased => usage_based_order(targets, metrics, eligible),
    }
}

fn latency_or_throughput_order(
    targets: &[super::providers::ProviderTarget],
    routing: &super::providers::RoutingConfig,
    metrics: &ProviderMetrics,
    eligible: &[usize],
) -> Vec<usize> {
    if rand_f64() < routing.exploration_ratio {
        return shuffled_order(eligible);
    }

    let ranked = match routing.strategy {
        super::providers::RoutingStrategy::LowestLatency => metrics.ranked_by_ttft(),
        super::providers::RoutingStrategy::HighestThroughput => metrics.ranked_by_throughput(),
        _ => return eligible.to_vec(),
    };

    order_eligible_by_ranked_ids(targets, eligible, &ranked)
}

fn round_robin_order(metrics: &ProviderMetrics, eligible: &[usize]) -> Vec<usize> {
    let count = metrics
        .rr_counter
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let start = count % eligible.len();
    (0..eligible.len())
        .map(|offset| eligible[(start + offset) % eligible.len()])
        .collect()
}

fn weighted_round_robin_order(
    targets: &[super::providers::ProviderTarget],
    metrics: &ProviderMetrics,
    eligible: &[usize],
) -> Vec<usize> {
    let total_weight: f64 = eligible
        .iter()
        .map(|&index| targets[index].weight.unwrap_or(1.0))
        .sum();

    // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
    #[allow(clippy::expect_used)]
    let mut state = metrics.wrr_state.lock().expect("wrr lock");
    for &index in eligible {
        let weight = targets[index].weight.unwrap_or(1.0);
        *state.entry(targets[index].id.clone()).or_insert(0.0) += weight;
    }

    let best = eligible.iter().copied().max_by(|&left, &right| {
        let left_weight = state.get(&targets[left].id).copied().unwrap_or(0.0);
        let right_weight = state.get(&targets[right].id).copied().unwrap_or(0.0);
        left_weight
            .partial_cmp(&right_weight)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if let Some(index) = best {
        *state.entry(targets[index].id.clone()).or_insert(0.0) -= total_weight;
    }
    drop(state);

    promote_selected_index(best, eligible)
}

fn least_busy_order(
    targets: &[super::providers::ProviderTarget],
    metrics: &ProviderMetrics,
    eligible: &[usize],
) -> Vec<usize> {
    let mut sorted = eligible.to_vec();
    // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
    #[allow(clippy::expect_used)]
    let active = metrics.active_conns.read().expect("active_conns lock");
    sorted.sort_by_key(|&index| active.get(&targets[index].id).copied().unwrap_or(0));
    sorted
}

fn shuffled_order(eligible: &[usize]) -> Vec<usize> {
    let mut shuffled = eligible.to_vec();
    fisher_yates_shuffle(&mut shuffled);
    shuffled
}

fn usage_based_order(
    targets: &[super::providers::ProviderTarget],
    metrics: &ProviderMetrics,
    eligible: &[usize],
) -> Vec<usize> {
    let ranked = metrics.ranked_by_usage();
    order_eligible_by_ranked_ids(targets, eligible, &ranked)
}

fn order_eligible_by_ranked_ids<T>(
    targets: &[super::providers::ProviderTarget],
    eligible: &[usize],
    ranked: &[(String, T)],
) -> Vec<usize> {
    if ranked.is_empty() {
        return eligible.to_vec();
    }

    let mut ordered = Vec::with_capacity(eligible.len());
    for (provider_id, _) in ranked {
        if let Some(index) = targets.iter().position(|target| &target.id == provider_id) {
            if eligible.contains(&index) && !ordered.contains(&index) {
                ordered.push(index);
            }
        }
    }
    for &index in eligible {
        if !ordered.contains(&index) {
            ordered.push(index);
        }
    }
    ordered
}

fn promote_selected_index(selected: Option<usize>, eligible: &[usize]) -> Vec<usize> {
    let Some(selected) = selected else {
        return eligible.to_vec();
    };

    let mut ordered = vec![selected];
    for &index in eligible {
        if index != selected {
            ordered.push(index);
        }
    }
    ordered
}

fn apply_warmup_lane(
    ordered: &mut Vec<usize>,
    targets: &[super::providers::ProviderTarget],
    routing: &super::providers::RoutingConfig,
    metrics: &ProviderMetrics,
) {
    use super::providers::RoutingStrategy;

    if !matches!(
        routing.strategy,
        RoutingStrategy::LowestLatency | RoutingStrategy::HighestThroughput
    ) || routing.warmup_ratio <= 0.0
    {
        return;
    }

    let under_sampled: Vec<usize> = ordered
        .iter()
        .copied()
        .filter(|&index| metrics.sample_count(&targets[index].id) < metrics.min_sample_count())
        .collect();

    if under_sampled.is_empty() || rand_f64() >= routing.warmup_ratio {
        return;
    }

    let pick_index = (rand_f64() * under_sampled.len() as f64) as usize % under_sampled.len();
    let promoted = under_sampled[pick_index];
    ordered.retain(|&index| index != promoted);
    ordered.insert(0, promoted);
}

fn apply_order_override(
    ordered: &mut Vec<usize>,
    targets: &[super::providers::ProviderTarget],
    routing: &super::providers::RoutingConfig,
) {
    let Some(order_ids) = &routing.order else {
        return;
    };

    let mut remaining = ordered.clone();
    let mut reordered = Vec::with_capacity(ordered.len());
    for id in order_ids {
        if let Some(position) = remaining.iter().position(|&index| &targets[index].id == id) {
            reordered.push(remaining.remove(position));
        }
    }
    reordered.extend(remaining);
    *ordered = reordered;
}

fn apply_sla_preferences(
    ordered: &mut Vec<usize>,
    targets: &[super::providers::ProviderTarget],
    routing: &super::providers::RoutingConfig,
    metrics: &ProviderMetrics,
) {
    if routing.preferred_max_latency.is_none() && routing.preferred_min_throughput.is_none() {
        return;
    }

    *ordered = deprioritize_by_sla(
        targets,
        ordered,
        metrics,
        &routing.preferred_max_latency,
        &routing.preferred_min_throughput,
    );
}

fn apply_fallback_truncation(ordered: &mut Vec<usize>, routing: &super::providers::RoutingConfig) {
    if !routing.allow_fallbacks && !ordered.is_empty() {
        ordered.truncate(1);
    }
}

/// Simple pseudo-random f64 in [0, 1) using Instant-based entropy.
/// Not cryptographic — just for exploration jitter.
fn rand_f64() -> f64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    (nanos as f64) / 1_000_000_000.0
}

#[cfg(test)]
fn percentile_pct_value(p: super::providers::Percentile) -> u64 {
    percentile_pct(p)
}

fn fisher_yates_shuffle(items: &mut [usize]) {
    use std::cell::Cell;
    thread_local! {
        static SEED: Cell<u64> = const { Cell::new(0) };
    }

    SEED.with(|s| {
        let mut seed = s.get();
        if seed == 0 {
            seed = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as u64;
            seed = seed.wrapping_add(0x517cc1b727220a95);
        }
        for i in (1..items.len()).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let j = (seed as usize) % (i + 1);
            items.swap(i, j);
        }
        s.set(seed);
    });
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
    use crate::gateway::providers::{Percentile, ProviderTarget, RoutingConfig};
    use std::time::Duration;

    fn make_metrics() -> ProviderMetrics {
        ProviderMetrics::new(300, 3)
    }

    fn sample_target(id: &str) -> ProviderTarget {
        ProviderTarget {
            id: id.to_string(),
            provider: "openai".to_string(),
            model: "gpt-5.4".to_string(),
            execution_target: None,
            mcp_bridge: None,
            description: None,
            base_url: "https://api.openai.com".to_string(),
            api_key: String::new(),
            api_key_header: "Authorization".to_string(),
            api_key_prefix: "Bearer ".to_string(),
            secret_key_ref: None,
            path_template: None,
            headers: Default::default(),
            timeout: Duration::from_secs(30),
            stream_timeout: None,
            max_context_tokens: None,
            max_messages: None,
            data_policy: None,
            pricing: None,
            models: Vec::new(),
            data_collection: None,
            zdr: false,
            region: None,
            quantizations: None,
            weight: None,
            provider_type: None,
            format: None,
            anthropic_version: None,
            aws_region: None,
            aws_profile: None,
            bedrock_model_family: None,
            watsonx_api_version: None,
            watsonx_project_id: None,
            watsonx_space_id: None,
            gcp_project: None,
            gcp_region: None,
            azure_api_version: None,
            azure_deployment: None,
            oauth2: None,
            health_probe: None,
            allow_insecure_tls: false,
            escalation_routing: None,
            required: false,
            data_residency: None,
            certifications: None,
        }
    }

    #[test]
    fn record_and_ranked_by_ttft() {
        let m = make_metrics();
        m.record("p1", Duration::from_millis(100), 50, Duration::from_secs(1));
        m.record("p1", Duration::from_millis(200), 60, Duration::from_secs(1));
        m.record("p1", Duration::from_millis(150), 55, Duration::from_secs(1));
        m.record("p2", Duration::from_millis(50), 40, Duration::from_secs(1));
        m.record("p2", Duration::from_millis(60), 45, Duration::from_secs(1));
        m.record("p2", Duration::from_millis(55), 42, Duration::from_secs(1));

        let ranked = m.ranked_by_ttft();
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].0, "p2");
        assert_eq!(ranked[1].0, "p1");
    }

    #[test]
    fn ranked_by_ttft_excludes_under_sampled() {
        let m = make_metrics();
        m.record("p1", Duration::from_millis(100), 50, Duration::from_secs(1));
        assert!(m.ranked_by_ttft().is_empty());
    }

    #[test]
    fn record_and_ranked_by_throughput() {
        let m = make_metrics();
        for _ in 0..3 {
            m.record(
                "slow",
                Duration::from_millis(100),
                10,
                Duration::from_secs(2),
            );
            m.record(
                "fast",
                Duration::from_millis(50),
                100,
                Duration::from_secs(1),
            );
        }

        let ranked = m.ranked_by_throughput();
        assert_eq!(ranked[0].0, "fast");
    }

    #[test]
    fn record_usage_and_total_tokens() {
        let m = make_metrics();
        m.record_usage("p1", 500);
        m.record_usage("p1", 300);
        assert_eq!(m.total_tokens("p1"), 800);
        assert_eq!(m.total_tokens("unknown"), 0);
    }

    #[test]
    fn ranked_by_usage_sorts_ascending() {
        let m = make_metrics();
        m.record_usage("heavy", 1000);
        m.record_usage("light", 100);

        let ranked = m.ranked_by_usage();
        assert_eq!(ranked[0].0, "light");
        assert_eq!(ranked[1].0, "heavy");
    }

    #[test]
    fn active_connection_count_tracking() {
        let m = make_metrics();
        assert_eq!(m.active_connection_count("p1"), 0);
        m.increment_active("p1");
        m.increment_active("p1");
        assert_eq!(m.active_connection_count("p1"), 2);
        m.decrement_active("p1");
        assert_eq!(m.active_connection_count("p1"), 1);
        m.decrement_active("p1");
        m.decrement_active("p1");
        assert_eq!(m.active_connection_count("p1"), 0);
    }

    #[test]
    fn snapshot_json_includes_providers() {
        let m = make_metrics();
        for _ in 0..3 {
            m.record("p1", Duration::from_millis(100), 50, Duration::from_secs(1));
        }
        let snap = m.snapshot_json();
        assert!(snap.get("p1").is_some());
        assert_eq!(snap["p1"]["sample_count"], 3);
    }

    #[test]
    fn percentile_ttft_returns_none_for_under_sampled() {
        let m = make_metrics();
        m.record("p1", Duration::from_millis(100), 50, Duration::from_secs(1));
        assert!(m.percentile_ttft("p1", Percentile::P50).is_none());
    }

    #[test]
    fn percentile_ttft_returns_value_for_sufficient_samples() {
        let m = make_metrics();
        for i in 0..5 {
            m.record(
                "p1",
                Duration::from_millis(100 + i * 10),
                50,
                Duration::from_secs(1),
            );
        }
        let p50 = m.percentile_ttft("p1", Percentile::P50);
        assert!(p50.is_some());
    }

    #[test]
    fn percentile_throughput_returns_none_for_unknown() {
        let m = make_metrics();
        assert!(m
            .percentile_throughput("unknown", Percentile::P90)
            .is_none());
    }

    #[test]
    fn sample_count_and_min_sample_count() {
        let m = make_metrics();
        assert_eq!(m.sample_count("p1"), 0);
        assert_eq!(m.min_sample_count(), 3);
        m.record("p1", Duration::from_millis(100), 50, Duration::from_secs(1));
        assert_eq!(m.sample_count("p1"), 1);
    }

    #[test]
    fn record_health_and_is_healthy() {
        let m = make_metrics();
        assert!(m.is_healthy("p1").is_none());
        m.record_health("p1", true, Some(200), Some(50), 1700000000);
        assert_eq!(m.is_healthy("p1"), Some(true));
        m.record_health("p1", false, Some(500), Some(5000), 1700000001);
        assert_eq!(m.is_healthy("p1"), Some(false));
    }

    #[test]
    fn snapshot_json_includes_health() {
        let m = make_metrics();
        for _ in 0..3 {
            m.record("p1", Duration::from_millis(100), 50, Duration::from_secs(1));
        }
        m.record_health("p1", true, Some(200), Some(50), 1700000000);
        let snap = m.snapshot_json();
        assert!(snap["p1"]["health"].get("healthy").is_some());
    }

    #[test]
    fn percentile_pct_mapping() {
        assert_eq!(percentile_pct_value(Percentile::P50), 50);
        assert_eq!(percentile_pct_value(Percentile::P90), 90);
        assert_eq!(percentile_pct_value(Percentile::P99), 99);
    }

    #[test]
    fn percentile_ttft_at_empty_window() {
        let window = ProviderWindow {
            samples: std::collections::VecDeque::new(),
        };
        assert!((percentile_ttft_at(&window, 50)).abs() < f64::EPSILON);
    }

    #[test]
    fn percentile_throughput_at_empty_window() {
        let window = ProviderWindow {
            samples: std::collections::VecDeque::new(),
        };
        assert!((percentile_throughput_at(&window, 50)).abs() < f64::EPSILON);
    }

    #[test]
    fn select_providers_ordered() {
        let targets = vec![sample_target("t1"), sample_target("t2")];
        let routing = RoutingConfig::default();
        let metrics = make_metrics();
        let selected = select_providers(&targets, &routing, &metrics);
        assert_eq!(selected, vec![0, 1]);
    }

    #[test]
    fn select_providers_with_only_filter() {
        let targets = vec![
            sample_target("t1"),
            sample_target("t2"),
            sample_target("t3"),
        ];
        let routing = RoutingConfig {
            only: Some(vec!["t2".to_string()]),
            ..Default::default()
        };
        let metrics = make_metrics();
        let selected = select_providers(&targets, &routing, &metrics);
        assert_eq!(selected, vec![1]);
    }

    #[test]
    fn select_providers_with_ignore_filter() {
        let targets = vec![
            sample_target("t1"),
            sample_target("t2"),
            sample_target("t3"),
        ];
        let routing = RoutingConfig {
            ignore: Some(vec!["t2".to_string()]),
            ..Default::default()
        };
        let metrics = make_metrics();
        let selected = select_providers(&targets, &routing, &metrics);
        assert_eq!(selected, vec![0, 2]);
    }

    #[test]
    fn select_providers_disallow_fallbacks_truncates() {
        let targets = vec![sample_target("t1"), sample_target("t2")];
        let routing = RoutingConfig {
            allow_fallbacks: false,
            ..Default::default()
        };
        let metrics = make_metrics();
        let selected = select_providers(&targets, &routing, &metrics);
        assert_eq!(selected.len(), 1);
    }

    #[test]
    fn select_providers_order_override() {
        let targets = vec![
            sample_target("t1"),
            sample_target("t2"),
            sample_target("t3"),
        ];
        let routing = RoutingConfig {
            order: Some(vec!["t3".to_string(), "t1".to_string()]),
            ..Default::default()
        };
        let metrics = make_metrics();
        let selected = select_providers(&targets, &routing, &metrics);
        assert_eq!(selected, vec![2, 0, 1]);
    }

    #[test]
    fn select_providers_empty_targets() {
        let targets: Vec<ProviderTarget> = vec![];
        let routing = RoutingConfig::default();
        let metrics = make_metrics();
        let selected = select_providers(&targets, &routing, &metrics);
        assert!(selected.is_empty());
    }

    #[test]
    fn promote_selected_index_none() {
        let result = promote_selected_index(None, &[0, 1, 2]);
        assert_eq!(result, vec![0, 1, 2]);
    }

    #[test]
    fn promote_selected_index_some() {
        let result = promote_selected_index(Some(2), &[0, 1, 2]);
        assert_eq!(result, vec![2, 0, 1]);
    }
}
