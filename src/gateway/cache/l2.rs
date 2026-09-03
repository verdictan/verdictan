// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    LazyLock, RwLock,
};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CliError;

use super::l1::{unix_now_secs, ContextPlan, ContextPoolMutation};

type ContextPlanL2PartitionKey = (String, String);

static SHARED_L2_CACHE: LazyLock<ContextPlanL2Cache> = LazyLock::new(|| {
    ContextPlanL2Cache::new(
        None,
        DEFAULT_L2_REDIS_KEY_PREFIX,
        Duration::from_secs(3600),
        DEFAULT_EXPECTED_TOPICS_PER_PARTITION,
        DEFAULT_L2_BLOOM_FALSE_POSITIVE_RATE,
    )
    .unwrap_or_else(|_| ContextPlanL2Cache::passthrough())
});

pub fn shared_l2_cache() -> &'static ContextPlanL2Cache {
    &SHARED_L2_CACHE
}

const DEFAULT_L2_REDIS_KEY_PREFIX: &str = "vt:context-cache";
pub const DEFAULT_L2_BLOOM_FALSE_POSITIVE_RATE: f64 = 0.05;
const DEFAULT_EXPECTED_TOPICS_PER_PARTITION: usize = 256;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicClusterContext {
    pub repo: String,
    pub branch: String,
    pub topic: String,
    #[serde(default)]
    pub stored_at_unix_secs: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plans: Vec<ContextPlan>,
}

impl TopicClusterContext {
    pub fn new(
        repo: impl Into<String>,
        branch: impl Into<String>,
        topic: impl Into<String>,
        plans: Vec<ContextPlan>,
    ) -> Self {
        Self {
            repo: repo.into(),
            branch: branch.into(),
            topic: topic.into(),
            stored_at_unix_secs: unix_now_secs(),
            plans,
        }
    }

    pub fn partition_key(&self) -> ContextPlanL2PartitionKey {
        (self.repo.clone(), self.branch.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BloomFilter {
    bit_count: usize,
    hash_count: u32,
    bits: Vec<u64>,
}

impl BloomFilter {
    fn new(expected_items: usize, false_positive_rate: f64) -> Result<Self, CliError> {
        if expected_items == 0 {
            return Err(CliError::user(
                "context_fabric.cache.expected_topics_per_partition must be > 0",
            ));
        }
        if !(0.0..1.0).contains(&false_positive_rate) {
            return Err(CliError::user(
                "context_fabric.cache.l2_bloom_false_positive_rate must be between 0 and 1",
            ));
        }

        let expected_items = expected_items as f64;
        let bit_count = (-(expected_items * false_positive_rate.ln())
            / std::f64::consts::LN_2.powi(2))
        .ceil()
        .max(64.0) as usize;
        let hash_count = ((bit_count as f64 / expected_items) * std::f64::consts::LN_2)
            .ceil()
            .max(1.0) as u32;
        let words = bit_count.div_ceil(64);

        Ok(Self {
            bit_count,
            hash_count,
            bits: vec![0; words],
        })
    }

    fn insert(&mut self, value: &str) {
        let positions = self.positions(value).collect::<Vec<_>>();
        for position in positions {
            let word = position / 64;
            let bit = position % 64;
            self.bits[word] |= 1u64 << bit;
        }
    }

    fn contains(&self, value: &str) -> bool {
        self.positions(value).all(|position| {
            let word = position / 64;
            let bit = position % 64;
            (self.bits[word] & (1u64 << bit)) != 0
        })
    }

    #[allow(dead_code)] // Pending cache reset flows use explicit Bloom filter clearing.
    fn clear(&mut self) {
        self.bits.fill(0);
    }

    fn positions<'a>(&'a self, value: &'a str) -> impl Iterator<Item = usize> + 'a {
        let digest = Sha256::digest(value.as_bytes());
        let mut first = [0u8; 8];
        let mut second = [0u8; 8];
        first.copy_from_slice(&digest[..8]);
        second.copy_from_slice(&digest[8..16]);
        let hash_one = u64::from_le_bytes(first);
        let mut hash_two = u64::from_le_bytes(second);
        if hash_two == 0 {
            hash_two = 0x9E37_79B9_7F4A_7C15;
        }
        let bit_count = self.bit_count as u64;
        (0..self.hash_count).map(move |index| {
            let position = hash_one.wrapping_add((index as u64).wrapping_mul(hash_two)) % bit_count;
            position as usize
        })
    }
}

#[derive(Clone, Debug)]
struct BloomPartitionState {
    filter: BloomFilter,
    topic_count: usize,
    stale: bool,
}

#[cfg_attr(not(feature = "distributed"), allow(dead_code))] // Reachable when `--features distributed` is enabled.
#[derive(Clone)]
struct RedisTopicClusterStore {
    #[cfg(feature = "distributed")]
    client: redis::Client,
    key_prefix: String,
    operator_backend: &'static str,
}

#[cfg_attr(not(feature = "distributed"), allow(dead_code))] // Reachable when `--features distributed` is enabled.
impl RedisTopicClusterStore {
    fn try_new(
        redis_url: &str,
        key_prefix: &str,
        operator_backend: &'static str,
    ) -> Result<Self, CliError> {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = redis_url;
            let _ = key_prefix;
            let _ = operator_backend;
            Err(CliError::user(format!(
                "context fabric L2 cache requested {operator_backend}, but this CLI build does not include --features distributed"
            )))
        }

        #[cfg(feature = "distributed")]
        {
            let normalized_prefix = normalize_key_prefix(key_prefix);
            let backend_display_name = backend_display_name(operator_backend);
            let client = redis::Client::open(redis_url).map_err(|error| {
                CliError::user(format!(
                    "invalid {backend_display_name} URL for context_fabric.cache.redis_url: {error}"
                ))
            })?;
            let mut connection = client.get_connection().map_err(|error| {
                CliError::network(format!(
                    "failed to connect to {backend_display_name} for context_fabric.cache.redis_url: {error}"
                ))
            })?;
            let _: String = redis::cmd("PING").query(&mut connection).map_err(|error| {
                CliError::network(format!(
                    "failed to ping {backend_display_name} for context_fabric.cache.redis_url: {error}"
                ))
            })?;

            Ok(Self {
                client,
                key_prefix: normalized_prefix,
                operator_backend,
            })
        }
    }

    fn get(&self, repo: &str, branch: &str, topic: &str) -> Option<TopicClusterContext> {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = repo;
            let _ = branch;
            let _ = topic;
            None
        }

        #[cfg(feature = "distributed")]
        {
            let mut connection = self.connection().ok()?;
            let payload: Option<Vec<u8>> = redis::cmd("GET")
                .arg(self.topic_key(repo, branch, topic))
                .query(&mut connection)
                .ok()?;
            serde_json::from_slice(&payload?).ok()
        }
    }

    fn put(&self, cluster: &TopicClusterContext, ttl: &Duration) {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = cluster;
            let _ = ttl;
        }

        #[cfg(feature = "distributed")]
        {
            let Ok(mut connection) = self.connection() else {
                return;
            };
            let Ok(payload) = serde_json::to_vec(cluster) else {
                return;
            };
            let ttl_secs = ttl.as_secs().max(1);
            if let Err(error) = redis::cmd("SETEX")
                .arg(self.topic_key(&cluster.repo, &cluster.branch, &cluster.topic))
                .arg(ttl_secs)
                .arg(payload)
                .query::<()>(&mut connection)
            {
                tracing::warn!(
                    error = %error,
                    backend = self.operator_backend,
                    repo = %cluster.repo,
                    branch = %cluster.branch,
                    topic = %cluster.topic,
                    "context L2 redis put failed"
                );
            }
        }
    }

    fn remove_topic(&self, repo: &str, branch: &str, topic: &str) {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = repo;
            let _ = branch;
            let _ = topic;
        }

        #[cfg(feature = "distributed")]
        {
            let Ok(mut connection) = self.connection() else {
                return;
            };
            if let Err(error) = redis::cmd("DEL")
                .arg(self.topic_key(repo, branch, topic))
                .query::<()>(&mut connection)
            {
                tracing::warn!(
                    error = %error,
                    backend = self.operator_backend,
                    repo = %repo,
                    branch = %branch,
                    topic = %topic,
                    "context L2 redis topic delete failed"
                );
            }
        }
    }

    fn remove_partition(&self, repo: &str, branch: &str) {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = repo;
            let _ = branch;
        }

        #[cfg(feature = "distributed")]
        {
            let Ok(mut connection) = self.connection() else {
                return;
            };
            let keys = self.keys_matching(&mut connection, &self.partition_pattern(repo, branch));
            if keys.is_empty() {
                return;
            }
            if let Err(error) = redis::cmd("DEL").arg(keys).query::<()>(&mut connection) {
                tracing::warn!(
                    error = %error,
                    backend = self.operator_backend,
                    repo = %repo,
                    branch = %branch,
                    "context L2 redis partition delete failed"
                );
            }
        }
    }

    fn clear(&self) {
        #[cfg(not(feature = "distributed"))]
        {}

        #[cfg(feature = "distributed")]
        {
            let Ok(mut connection) = self.connection() else {
                return;
            };
            let keys = self.keys_matching(&mut connection, &format!("{}:*", self.key_prefix));
            if keys.is_empty() {
                return;
            }
            let _ = redis::cmd("DEL").arg(keys).query::<()>(&mut connection);
        }
    }

    #[cfg(feature = "distributed")]
    fn connection(&self) -> Result<redis::Connection, redis::RedisError> {
        self.client.get_connection()
    }

    #[cfg(feature = "distributed")]
    fn keys_matching(&self, connection: &mut redis::Connection, pattern: &str) -> Vec<String> {
        redis::cmd("KEYS")
            .arg(pattern)
            .query::<Vec<String>>(connection)
            .unwrap_or_default()
    }

    fn topic_key(&self, repo: &str, branch: &str, topic: &str) -> String {
        format!(
            "{}:topic:{}:{}:{}",
            self.key_prefix,
            encode_component(repo),
            encode_component(branch),
            encode_component(topic)
        )
    }

    fn partition_pattern(&self, repo: &str, branch: &str) -> String {
        format!(
            "{}:topic:{}:{}:*",
            self.key_prefix,
            encode_component(repo),
            encode_component(branch)
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPlanL2Stats {
    pub partition_count: u64,
    pub ready_partition_count: u64,
    pub stale_partition_count: u64,
    pub topic_count: u64,
    pub hit_count: u64,
    pub miss_count: u64,
    pub negative_short_circuit_count: u64,
    pub degraded_lookup_count: u64,
    pub redis_enabled: bool,
}

pub struct ContextPlanL2Cache {
    false_positive_rate: f64,
    expected_topics_per_partition: usize,
    ttl: Duration,
    partitions: RwLock<HashMap<ContextPlanL2PartitionKey, BloomPartitionState>>,
    backend: Option<RedisTopicClusterStore>,
    hit_count: AtomicU64,
    miss_count: AtomicU64,
    negative_short_circuit_count: AtomicU64,
    degraded_lookup_count: AtomicU64,
}

impl ContextPlanL2Cache {
    pub fn new(
        redis_url: Option<&str>,
        key_prefix: &str,
        ttl: Duration,
        expected_topics_per_partition: usize,
        false_positive_rate: f64,
    ) -> Result<Self, CliError> {
        Self::with_operator_backend(
            redis_url,
            key_prefix,
            ttl,
            expected_topics_per_partition,
            false_positive_rate,
            "redis",
        )
    }

    pub fn with_operator_backend(
        redis_url: Option<&str>,
        key_prefix: &str,
        ttl: Duration,
        expected_topics_per_partition: usize,
        false_positive_rate: f64,
        operator_backend: &'static str,
    ) -> Result<Self, CliError> {
        validate_false_positive_rate(false_positive_rate)?;
        let expected_topics_per_partition = expected_topics_per_partition.max(1);

        let backend = redis_url
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(|value| match RedisTopicClusterStore::try_new(value, key_prefix, operator_backend) {
                Ok(store) => Some(store),
                Err(error) => {
                    tracing::warn!(error = %error, backend = operator_backend, "context L2 redis backend unavailable; falling back to pass-through");
                    None
                }
            });

        Ok(Self {
            false_positive_rate,
            expected_topics_per_partition,
            ttl,
            partitions: RwLock::new(HashMap::new()),
            backend,
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
            negative_short_circuit_count: AtomicU64::new(0),
            degraded_lookup_count: AtomicU64::new(0),
        })
    }

    pub fn passthrough() -> Self {
        Self {
            false_positive_rate: DEFAULT_L2_BLOOM_FALSE_POSITIVE_RATE,
            expected_topics_per_partition: DEFAULT_EXPECTED_TOPICS_PER_PARTITION,
            ttl: Duration::from_secs(3600),
            partitions: RwLock::new(HashMap::new()),
            backend: None,
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
            negative_short_circuit_count: AtomicU64::new(0),
            degraded_lookup_count: AtomicU64::new(0),
        }
    }

    pub fn backend_available(&self) -> bool {
        self.backend.is_some()
    }

    pub fn topic_might_exist(&self, repo: &str, branch: &str, topic: &str) -> bool {
        let partitions = self
            .partitions
            .read()
            .unwrap_or_else(|error| error.into_inner());
        let Some(state) = partitions.get(&(repo.to_string(), branch.to_string())) else {
            return true;
        };
        if state.stale {
            return true;
        }
        let contains = state.filter.contains(topic);
        if !contains {
            self.negative_short_circuit_count
                .fetch_add(1, Ordering::Relaxed);
        }
        contains
    }

    pub fn record_topic(&self, repo: &str, branch: &str, topic: &str) {
        let key = (repo.to_string(), branch.to_string());
        let mut partitions = self
            .partitions
            .write()
            .unwrap_or_else(|error| error.into_inner());
        let state = partitions
            .entry(key)
            .or_insert_with(|| BloomPartitionState {
                filter: fallback_bloom_filter(),
                topic_count: 0,
                stale: false,
            });
        state.filter.insert(topic);
        state.topic_count = state.topic_count.saturating_add(1);
        state.stale = false;
    }

    pub fn replace_partition_topics(&self, repo: &str, branch: &str, topics: Vec<String>) {
        let mut filter = BloomFilter::new(
            self.expected_topics_per_partition.max(topics.len().max(1)),
            self.false_positive_rate,
        )
        .unwrap_or_else(|_| fallback_bloom_filter());
        for topic in &topics {
            filter.insert(topic);
        }

        let mut partitions = self
            .partitions
            .write()
            .unwrap_or_else(|error| error.into_inner());
        partitions.insert(
            (repo.to_string(), branch.to_string()),
            BloomPartitionState {
                filter,
                topic_count: topics.len(),
                stale: false,
            },
        );
    }

    pub fn store_topic_cluster(&self, cluster: TopicClusterContext) {
        self.record_topic(&cluster.repo, &cluster.branch, &cluster.topic);
        if let Some(backend) = &self.backend {
            backend.put(&cluster, &self.ttl);
        }
    }

    fn get_topic_cluster(
        &self,
        repo: &str,
        branch: &str,
        topic: &str,
    ) -> Option<TopicClusterContext> {
        if !self.topic_might_exist(repo, branch, topic) {
            self.miss_count.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let Some(backend) = &self.backend else {
            self.degraded_lookup_count.fetch_add(1, Ordering::Relaxed);
            return None;
        };

        let result = backend.get(repo, branch, topic);
        if result.is_some() {
            self.hit_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.miss_count.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    pub fn apply_mutation(&self, mutation: &ContextPoolMutation) {
        self.invalidate_partition(&mutation.repo, &mutation.branch);
        if let (Some(topic), Some(backend)) = (mutation.topic.as_deref(), &self.backend) {
            backend.remove_topic(&mutation.repo, &mutation.branch, topic);
        }
    }

    pub fn invalidate_partition(&self, repo: &str, branch: &str) {
        let key = (repo.to_string(), branch.to_string());
        if let Some(state) = self
            .partitions
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut(&key)
        {
            state.stale = true;
        }
        if let Some(backend) = &self.backend {
            backend.remove_partition(repo, branch);
        }
    }

    pub fn clear(&self) {
        self.partitions
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        self.hit_count.store(0, Ordering::Relaxed);
        self.miss_count.store(0, Ordering::Relaxed);
        self.negative_short_circuit_count
            .store(0, Ordering::Relaxed);
        self.degraded_lookup_count.store(0, Ordering::Relaxed);
        if let Some(backend) = &self.backend {
            backend.clear();
        }
    }

    pub fn stats(&self) -> ContextPlanL2Stats {
        let partitions = self
            .partitions
            .read()
            .unwrap_or_else(|error| error.into_inner());
        let ready_partition_count = partitions.values().filter(|state| !state.stale).count() as u64;
        let stale_partition_count = partitions.values().filter(|state| state.stale).count() as u64;
        let topic_count = partitions
            .values()
            .map(|state| state.topic_count as u64)
            .sum();

        ContextPlanL2Stats {
            partition_count: partitions.len() as u64,
            ready_partition_count,
            stale_partition_count,
            topic_count,
            hit_count: self.hit_count.load(Ordering::Relaxed),
            miss_count: self.miss_count.load(Ordering::Relaxed),
            negative_short_circuit_count: self.negative_short_circuit_count.load(Ordering::Relaxed),
            degraded_lookup_count: self.degraded_lookup_count.load(Ordering::Relaxed),
            redis_enabled: self.backend.is_some(),
        }
    }

    pub fn pressure_json(&self) -> serde_json::Value {
        let stats = self.stats();
        let level = if stats.stale_partition_count > 0 {
            "elevated"
        } else {
            "nominal"
        };
        serde_json::json!({
            "level": level,
            "partition_count": stats.partition_count,
            "ready_partition_count": stats.ready_partition_count,
            "stale_partition_count": stats.stale_partition_count,
            "topic_count": stats.topic_count,
            "hit_count": stats.hit_count,
            "miss_count": stats.miss_count,
            "negative_short_circuit_count": stats.negative_short_circuit_count,
            "degraded_lookup_count": stats.degraded_lookup_count,
            "redis_enabled": stats.redis_enabled,
        })
    }
}

fn validate_false_positive_rate(false_positive_rate: f64) -> Result<(), CliError> {
    if (0.0..1.0).contains(&false_positive_rate) {
        Ok(())
    } else {
        Err(CliError::user(
            "context_fabric.cache.l2_bloom_false_positive_rate must be between 0 and 1",
        ))
    }
}

#[cfg_attr(not(feature = "distributed"), allow(dead_code))] // Reachable when `--features distributed` is enabled.
fn normalize_key_prefix(key_prefix: &str) -> String {
    let trimmed = key_prefix.trim().trim_matches(':');
    if trimmed.is_empty() {
        DEFAULT_L2_REDIS_KEY_PREFIX.to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg_attr(not(feature = "distributed"), allow(dead_code))] // Reachable when `--features distributed` is enabled.
fn backend_display_name(operator_backend: &str) -> &'static str {
    match operator_backend {
        "valkey" => "Valkey",
        _ => "Redis",
    }
}

#[cfg_attr(not(feature = "distributed"), allow(dead_code))] // Reachable when `--features distributed` is enabled.
fn encode_component(value: &str) -> String {
    urlencoding::encode(value).into_owned()
}

fn fallback_bloom_filter() -> BloomFilter {
    BloomFilter {
        bit_count: 64,
        hash_count: 1,
        bits: vec![0; 1],
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

    fn authorization() -> super::super::l1::ContextCacheAuthorization {
        super::super::l1::ContextCacheAuthorization::new(
            "org-test",
            Some("team-test".to_string()),
            "authz-v1",
        )
    }

    fn cluster(repo: &str, branch: &str, topic: &str) -> TopicClusterContext {
        TopicClusterContext::new(
            repo,
            branch,
            topic,
            vec![ContextPlan::new(
                authorization(),
                repo,
                branch,
                format!("plan for {topic}"),
                vec![],
            )],
        )
    }

    #[test]
    fn bloom_filter_has_no_false_negatives_for_inserted_values() {
        let mut filter = BloomFilter::new(32, 0.05).expect("filter");
        filter.insert("schema");
        filter.insert("routing");
        filter.insert("billing");

        assert!(filter.contains("schema"));
        assert!(filter.contains("routing"));
        assert!(filter.contains("billing"));
    }

    #[test]
    fn invalid_false_positive_rate_is_rejected() {
        let error = match ContextPlanL2Cache::new(None, "cache", Duration::from_secs(60), 16, 1.0) {
            Ok(_) => panic!("rate should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("l2_bloom_false_positive_rate"));
    }

    #[test]
    fn missing_partition_falls_through_without_negative_short_circuit() {
        let cache = ContextPlanL2Cache::new(None, "cache", Duration::from_secs(60), 16, 0.05)
            .expect("cache");
        assert!(cache.topic_might_exist("repo", "branch", "schema"));
        assert_eq!(cache.stats().negative_short_circuit_count, 0);
    }

    #[test]
    fn absent_topic_short_circuits_when_partition_is_ready() {
        let cache = ContextPlanL2Cache::new(None, "cache", Duration::from_secs(60), 16, 0.05)
            .expect("cache");
        cache.replace_partition_topics(
            "repo",
            "branch",
            vec!["schema".to_string(), "routing".to_string()],
        );

        assert!(!cache.topic_might_exist("repo", "branch", "billing"));
        assert_eq!(cache.stats().negative_short_circuit_count, 1);
    }

    #[test]
    fn stale_partition_falls_through_to_avoid_false_negatives() {
        let cache = ContextPlanL2Cache::new(None, "cache", Duration::from_secs(60), 16, 0.05)
            .expect("cache");
        cache.replace_partition_topics("repo", "branch", vec!["schema".to_string()]);
        cache.invalidate_partition("repo", "branch");

        assert!(cache.topic_might_exist("repo", "branch", "billing"));
        assert_eq!(cache.stats().stale_partition_count, 1);
    }

    #[test]
    fn storing_cluster_records_topic_even_without_redis() {
        let cache = ContextPlanL2Cache::new(None, "cache", Duration::from_secs(60), 16, 0.05)
            .expect("cache");
        cache.store_topic_cluster(cluster("repo", "branch", "schema"));

        assert!(cache.topic_might_exist("repo", "branch", "schema"));
        assert!(cache
            .get_topic_cluster("repo", "branch", "schema")
            .is_none());
        assert_eq!(cache.stats().degraded_lookup_count, 1);
    }

    #[test]
    fn apply_mutation_marks_partition_stale() {
        let cache = ContextPlanL2Cache::new(None, "cache", Duration::from_secs(60), 16, 0.05)
            .expect("cache");
        cache.replace_partition_topics("repo", "branch", vec!["schema".to_string()]);
        cache.apply_mutation(&ContextPoolMutation::new(
            authorization(),
            "repo",
            "branch",
            super::super::l1::ContextPoolMutationKind::Share,
        ));

        let stats = cache.stats();
        assert_eq!(stats.stale_partition_count, 1);
    }

    #[test]
    fn normalize_key_prefix_defaults_and_trims() {
        assert_eq!(normalize_key_prefix("::team-cache::"), "team-cache");
        assert_eq!(
            normalize_key_prefix("   "),
            DEFAULT_L2_REDIS_KEY_PREFIX.to_string()
        );
    }

    #[test]
    fn backend_display_name_maps_known_backends() {
        assert_eq!(backend_display_name("redis"), "Redis");
        assert_eq!(backend_display_name("valkey"), "Valkey");
    }

    #[test]
    fn pressure_json_has_expected_schema() {
        let cache = ContextPlanL2Cache::new(None, "cache", Duration::from_secs(60), 16, 0.05)
            .expect("cache");
        let pressure = cache.pressure_json();
        assert!(pressure.get("level").is_some());
        assert!(pressure.get("partition_count").is_some());
        assert!(pressure.get("redis_enabled").is_some());
    }
}
