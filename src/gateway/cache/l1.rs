// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    LazyLock, RwLock,
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

const DEFAULT_SHARED_CAPACITY_PER_PARTITION: usize = 100;
const DEFAULT_SHARED_MAX_BYTES: u64 = 8 * 1024 * 1024;

static SHARED_L1_CACHE: LazyLock<ContextPlanL1Cache> = LazyLock::new(|| {
    ContextPlanL1Cache::new(
        DEFAULT_SHARED_CAPACITY_PER_PARTITION,
        DEFAULT_SHARED_MAX_BYTES,
    )
});

pub fn shared_l1_cache() -> &'static ContextPlanL1Cache {
    &SHARED_L1_CACHE
}

pub type ContextPlanQueryHash = u64;
pub type ContextPlanPartitionKey = (ContextCacheAuthorization, String, String);
pub type ContextPlanCacheKey = (
    ContextCacheAuthorization,
    String,
    String,
    ContextPlanQueryHash,
);

const DEFAULT_INVALIDATION_CHANNEL_CAPACITY: usize = 128;

pub fn hash_context_query(query: &str) -> ContextPlanQueryHash {
    let digest = Sha256::digest(query.trim().as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContextCacheAuthorization {
    pub organization_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    pub authorization_version: String,
}

impl ContextCacheAuthorization {
    pub fn new(
        organization_id: impl Into<String>,
        team_id: Option<String>,
        authorization_version: impl Into<String>,
    ) -> Self {
        Self {
            organization_id: organization_id.into().trim().to_string(),
            team_id: team_id
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            authorization_version: authorization_version.into().trim().to_string(),
        }
    }

    pub fn is_complete(&self) -> bool {
        !self.organization_id.is_empty() && !self.authorization_version.is_empty()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPlanItem {
    pub organization_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    pub authorization_version: String,
    pub item_id: String,
    pub content: String,
    #[serde(default)]
    pub token_estimate: u32,
    #[serde(default)]
    pub citation_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPlan {
    pub organization_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    pub authorization_version: String,
    pub repo: String,
    pub branch: String,
    pub query_text: String,
    pub query_hash: ContextPlanQueryHash,
    #[serde(default)]
    pub recall_count: u64,
    #[serde(default)]
    pub generated_at_unix_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic_cluster: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<ContextPlanItem>,
}

impl ContextPlan {
    pub fn new(
        authorization: ContextCacheAuthorization,
        repo: impl Into<String>,
        branch: impl Into<String>,
        query_text: impl Into<String>,
        mut items: Vec<ContextPlanItem>,
    ) -> Self {
        let query_text = query_text.into();
        for item in &mut items {
            item.organization_id = authorization.organization_id.clone();
            item.team_id = authorization.team_id.clone();
            item.authorization_version = authorization.authorization_version.clone();
        }
        Self {
            organization_id: authorization.organization_id,
            team_id: authorization.team_id,
            authorization_version: authorization.authorization_version,
            repo: repo.into(),
            branch: branch.into(),
            query_hash: hash_context_query(&query_text),
            query_text,
            recall_count: 0,
            generated_at_unix_secs: unix_now_secs(),
            plan_hash: None,
            topic_cluster: None,
            items,
        }
    }

    pub fn authorization(&self) -> ContextCacheAuthorization {
        ContextCacheAuthorization {
            organization_id: self.organization_id.clone(),
            team_id: self.team_id.clone(),
            authorization_version: self.authorization_version.clone(),
        }
    }

    pub fn cache_key(&self) -> ContextPlanCacheKey {
        (
            self.authorization(),
            self.repo.clone(),
            self.branch.clone(),
            self.query_hash,
        )
    }

    pub fn partition_key(&self) -> ContextPlanPartitionKey {
        (self.authorization(), self.repo.clone(), self.branch.clone())
    }

    pub fn approx_size_bytes(&self) -> u64 {
        match serde_json::to_vec(self) {
            Ok(bytes) => bytes.len() as u64,
            Err(_) => {
                let items_len = self
                    .items
                    .iter()
                    .map(|item| item.item_id.len() + item.content.len())
                    .sum::<usize>();
                (self.organization_id.len()
                    + self.team_id.as_deref().map(str::len).unwrap_or(0)
                    + self.authorization_version.len()
                    + self.repo.len()
                    + self.branch.len()
                    + self.query_text.len()
                    + items_len
                    + self.plan_hash.as_deref().map(str::len).unwrap_or(0)
                    + self.topic_cluster.as_deref().map(str::len).unwrap_or(0)
                    + 64) as u64
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextPoolMutationKind {
    Share,
    Capture,
    Flag,
    Eviction,
    #[default]
    Other,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPoolMutation {
    pub authorization: ContextCacheAuthorization,
    pub repo: String,
    pub branch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_hash: Option<ContextPlanQueryHash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(default)]
    pub kind: ContextPoolMutationKind,
}

impl ContextPoolMutation {
    pub fn new(
        authorization: ContextCacheAuthorization,
        repo: impl Into<String>,
        branch: impl Into<String>,
        kind: ContextPoolMutationKind,
    ) -> Self {
        Self {
            authorization,
            repo: repo.into(),
            branch: branch.into(),
            query_hash: None,
            topic: None,
            kind,
        }
    }

    pub fn partition_key(&self) -> ContextPlanPartitionKey {
        (
            self.authorization.clone(),
            self.repo.clone(),
            self.branch.clone(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPlanL1Stats {
    pub partition_count: u64,
    pub entry_count: u64,
    pub total_size_bytes: u64,
    pub max_bytes: u64,
    pub capacity_per_partition: u64,
    pub hit_count: u64,
    pub miss_count: u64,
    pub eviction_count: u64,
    pub invalidation_count: u64,
}

impl ContextPlanL1Stats {
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hit_count.saturating_add(self.miss_count);
        if total == 0 {
            0.0
        } else {
            self.hit_count as f64 / total as f64
        }
    }
}

#[derive(Clone)]
struct ContextPlanEntry {
    plan: ContextPlan,
    size_bytes: u64,
    last_accessed: Instant,
}

#[derive(Default)]
struct PartitionCache {
    entries: IndexMap<ContextPlanQueryHash, ContextPlanEntry>,
    total_size_bytes: u64,
}

pub struct ContextPlanL1Cache {
    capacity_per_partition: usize,
    max_bytes: u64,
    partitions: RwLock<HashMap<ContextPlanPartitionKey, PartitionCache>>,
    total_size_bytes: AtomicU64,
    hit_count: AtomicU64,
    miss_count: AtomicU64,
    eviction_count: AtomicU64,
    invalidation_count: AtomicU64,
    invalidation_tx: broadcast::Sender<ContextPoolMutation>,
}

impl ContextPlanL1Cache {
    pub fn new(capacity_per_partition: usize, max_bytes: u64) -> Self {
        let (invalidation_tx, _) =
            broadcast::channel(DEFAULT_INVALIDATION_CHANNEL_CAPACITY.max(capacity_per_partition));
        Self {
            capacity_per_partition,
            max_bytes,
            partitions: RwLock::new(HashMap::new()),
            total_size_bytes: AtomicU64::new(0),
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
            eviction_count: AtomicU64::new(0),
            invalidation_count: AtomicU64::new(0),
            invalidation_tx,
        }
    }

    pub fn capacity_per_partition(&self) -> usize {
        self.capacity_per_partition
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ContextPoolMutation> {
        self.invalidation_tx.subscribe()
    }

    pub fn get(
        &self,
        authorization: &ContextCacheAuthorization,
        repo: &str,
        branch: &str,
        query_hash: ContextPlanQueryHash,
    ) -> Option<ContextPlan> {
        if !authorization.is_complete() {
            self.miss_count.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let key = (authorization.clone(), repo.to_string(), branch.to_string());
        let mut partitions = self
            .partitions
            .write()
            .unwrap_or_else(|error| error.into_inner());
        let Some(partition) = partitions.get_mut(&key) else {
            self.miss_count.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let Some(plan) = ({
            match partition.entries.get_mut(&query_hash) {
                Some(entry) => {
                    entry.last_accessed = Instant::now();
                    Some(entry.plan.clone())
                }
                None => None,
            }
        }) else {
            self.miss_count.fetch_add(1, Ordering::Relaxed);
            return None;
        };

        let from = partition.entries.get_index_of(&query_hash).unwrap_or(0);
        let to = partition.entries.len().saturating_sub(1);
        partition.entries.move_index(from, to);
        self.hit_count.fetch_add(1, Ordering::Relaxed);
        Some(plan)
    }

    pub fn insert(&self, mut plan: ContextPlan) -> bool {
        if self.capacity_per_partition == 0 || self.max_bytes == 0 {
            return false;
        }
        let authorization = plan.authorization();
        if !authorization.is_complete() {
            return false;
        }
        if plan.items.iter().any(|item| {
            item.organization_id != authorization.organization_id
                || item.team_id != authorization.team_id
                || item.authorization_version != authorization.authorization_version
        }) {
            return false;
        }
        if plan.query_hash == 0 {
            plan.query_hash = hash_context_query(&plan.query_text);
        }

        let partition_key = plan.partition_key();
        let query_hash = plan.query_hash;
        let size_bytes = plan.approx_size_bytes();
        // PERF-012: validate before cache insertion — never admit a single entry
        // larger than the production response hard cap (16 MiB).
        if size_bytes > crate::gateway::size_limit::DEFAULT_MAX_RESPONSE_BYTES as u64 {
            return false;
        }
        let mut partitions = self
            .partitions
            .write()
            .unwrap_or_else(|error| error.into_inner());

        let remove_partition = {
            let partition = partitions.entry(partition_key.clone()).or_default();
            if let Some(existing) = partition.entries.shift_remove(&query_hash) {
                partition.total_size_bytes = partition
                    .total_size_bytes
                    .saturating_sub(existing.size_bytes);
                self.total_size_bytes
                    .fetch_sub(existing.size_bytes, Ordering::Relaxed);
            }
            partition.entries.insert(
                query_hash,
                ContextPlanEntry {
                    plan,
                    size_bytes,
                    last_accessed: Instant::now(),
                },
            );
            partition.total_size_bytes = partition.total_size_bytes.saturating_add(size_bytes);
            self.total_size_bytes
                .fetch_add(size_bytes, Ordering::Relaxed);
            self.evict_partition_entries_locked(partition);
            partition.entries.is_empty()
        };

        if remove_partition {
            partitions.remove(&partition_key);
        }
        self.evict_global_entries_locked(&mut partitions);
        true
    }

    pub fn replace_partition_plans(
        &self,
        authorization: &ContextCacheAuthorization,
        repo: &str,
        branch: &str,
        mut plans: Vec<ContextPlan>,
    ) {
        self.remove_partition(authorization, repo, branch);
        if self.capacity_per_partition == 0 || self.max_bytes == 0 {
            return;
        }

        plans.sort_by(|left, right| {
            right
                .recall_count
                .cmp(&left.recall_count)
                .then_with(|| left.query_text.cmp(&right.query_text))
        });
        plans.truncate(self.capacity_per_partition);

        for mut plan in plans.into_iter().rev() {
            if plan.authorization() != *authorization {
                continue;
            }
            plan.repo = repo.to_string();
            plan.branch = branch.to_string();
            if plan.query_hash == 0 {
                plan.query_hash = hash_context_query(&plan.query_text);
            }
            let _ = self.insert(plan);
        }
    }

    pub fn remove_partition(
        &self,
        authorization: &ContextCacheAuthorization,
        repo: &str,
        branch: &str,
    ) -> bool {
        if !authorization.is_complete() {
            return false;
        }
        let key = (authorization.clone(), repo.to_string(), branch.to_string());
        let mut partitions = self
            .partitions
            .write()
            .unwrap_or_else(|error| error.into_inner());
        let Some(partition) = partitions.remove(&key) else {
            return false;
        };
        self.total_size_bytes
            .fetch_sub(partition.total_size_bytes, Ordering::Relaxed);
        true
    }

    pub fn clear(&self) {
        self.partitions
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        self.total_size_bytes.store(0, Ordering::Relaxed);
        self.hit_count.store(0, Ordering::Relaxed);
        self.miss_count.store(0, Ordering::Relaxed);
        self.eviction_count.store(0, Ordering::Relaxed);
        self.invalidation_count.store(0, Ordering::Relaxed);
    }

    pub fn apply_invalidation(&self, mutation: &ContextPoolMutation) -> bool {
        if !mutation.authorization.is_complete() {
            return false;
        }
        let mut removed = false;
        let partition_key = mutation.partition_key();
        let mut partitions = self
            .partitions
            .write()
            .unwrap_or_else(|error| error.into_inner());

        if let Some(query_hash) = mutation.query_hash {
            let mut remove_partition = false;
            if let Some(partition) = partitions.get_mut(&partition_key) {
                if let Some(entry) = partition.entries.shift_remove(&query_hash) {
                    partition.total_size_bytes =
                        partition.total_size_bytes.saturating_sub(entry.size_bytes);
                    self.total_size_bytes
                        .fetch_sub(entry.size_bytes, Ordering::Relaxed);
                    removed = true;
                }
                remove_partition = partition.entries.is_empty();
            }
            if remove_partition {
                partitions.remove(&partition_key);
            }
        } else if let Some(partition) = partitions.remove(&partition_key) {
            self.total_size_bytes
                .fetch_sub(partition.total_size_bytes, Ordering::Relaxed);
            removed = true;
        }

        self.invalidation_count.fetch_add(1, Ordering::Relaxed);
        removed
    }

    pub fn publish_invalidation(&self, mutation: ContextPoolMutation) -> bool {
        if !mutation.authorization.is_complete() {
            return false;
        }
        let removed = self.apply_invalidation(&mutation);
        let _ = self.invalidation_tx.send(mutation);
        removed
    }

    pub fn stats(&self) -> ContextPlanL1Stats {
        let partitions = self
            .partitions
            .read()
            .unwrap_or_else(|error| error.into_inner());
        let entry_count = partitions
            .values()
            .map(|partition| partition.entries.len() as u64)
            .sum();
        ContextPlanL1Stats {
            partition_count: partitions.len() as u64,
            entry_count,
            total_size_bytes: self.total_size_bytes.load(Ordering::Relaxed),
            max_bytes: self.max_bytes,
            capacity_per_partition: self.capacity_per_partition as u64,
            hit_count: self.hit_count.load(Ordering::Relaxed),
            miss_count: self.miss_count.load(Ordering::Relaxed),
            eviction_count: self.eviction_count.load(Ordering::Relaxed),
            invalidation_count: self.invalidation_count.load(Ordering::Relaxed),
        }
    }

    pub fn pressure_json(&self) -> serde_json::Value {
        let total = self.total_size_bytes.load(Ordering::Relaxed);
        let percent = if self.max_bytes == 0 {
            0
        } else {
            ((total as f64 / self.max_bytes as f64) * 100.0).round() as u64
        };
        let level = match percent {
            0..=49 => "nominal",
            50..=79 => "elevated",
            _ => "high",
        };
        let stats = self.stats();
        serde_json::json!({
            "level": level,
            "estimated_entry_count": stats.entry_count,
            "partition_count": stats.partition_count,
            "total_size_bytes": total,
            "max_bytes": self.max_bytes,
            "percent_used": percent,
            "hit_count": stats.hit_count,
            "miss_count": stats.miss_count,
            "eviction_count": stats.eviction_count,
            "invalidation_count": stats.invalidation_count,
        })
    }

    fn evict_partition_entries_locked(&self, partition: &mut PartitionCache) {
        while partition.entries.len() > self.capacity_per_partition {
            let Some((_, entry)) = partition.entries.shift_remove_index(0) else {
                break;
            };
            partition.total_size_bytes =
                partition.total_size_bytes.saturating_sub(entry.size_bytes);
            self.total_size_bytes
                .fetch_sub(entry.size_bytes, Ordering::Relaxed);
            self.eviction_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn evict_global_entries_locked(
        &self,
        partitions: &mut HashMap<ContextPlanPartitionKey, PartitionCache>,
    ) {
        while self.total_size_bytes.load(Ordering::Relaxed) > self.max_bytes {
            let mut victim_partition: Option<ContextPlanPartitionKey> = None;
            let mut victim_accessed: Option<Instant> = None;

            for (partition_key, partition) in partitions.iter() {
                let Some((_, entry)) = partition.entries.first() else {
                    continue;
                };
                let should_replace = victim_accessed
                    .map(|current| entry.last_accessed < current)
                    .unwrap_or(true);
                if should_replace {
                    victim_accessed = Some(entry.last_accessed);
                    victim_partition = Some(partition_key.clone());
                }
            }

            let Some(victim_partition) = victim_partition else {
                break;
            };

            let mut remove_partition = false;
            if let Some(partition) = partitions.get_mut(&victim_partition) {
                if let Some((_, entry)) = partition.entries.shift_remove_index(0) {
                    partition.total_size_bytes =
                        partition.total_size_bytes.saturating_sub(entry.size_bytes);
                    self.total_size_bytes
                        .fetch_sub(entry.size_bytes, Ordering::Relaxed);
                    self.eviction_count.fetch_add(1, Ordering::Relaxed);
                }
                remove_partition = partition.entries.is_empty();
            }

            if remove_partition {
                partitions.remove(&victim_partition);
            }
        }
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

    fn authorization(org: &str, team: &str, version: &str) -> ContextCacheAuthorization {
        ContextCacheAuthorization::new(org, Some(team.to_string()), version)
    }

    fn plan(
        authorization: ContextCacheAuthorization,
        repo: &str,
        branch: &str,
        query: &str,
        recall_count: u64,
    ) -> ContextPlan {
        let mut plan = ContextPlan::new(
            authorization,
            repo,
            branch,
            query,
            vec![ContextPlanItem {
                organization_id: String::new(),
                team_id: None,
                authorization_version: String::new(),
                item_id: format!("{query}-1"),
                content: format!("content for {query}"),
                token_estimate: 5,
                citation_required: false,
                source_kind: Some("manual".to_string()),
            }],
        );
        plan.recall_count = recall_count;
        plan
    }

    #[test]
    fn query_hash_is_deterministic() {
        assert_eq!(
            hash_context_query("same query"),
            hash_context_query("same query")
        );
        assert_ne!(
            hash_context_query("same query"),
            hash_context_query("different query")
        );
    }

    #[test]
    fn insert_rejects_entries_larger_than_production_response_cap() {
        let cache = ContextPlanL1Cache::new(10, 32 * 1024 * 1024);
        let auth = authorization("org", "team", "v1");
        let mut oversized = plan(auth.clone(), "repo", "branch", "huge", 1);
        oversized.items[0].content =
            "X".repeat(crate::gateway::size_limit::DEFAULT_MAX_RESPONSE_BYTES + 64);
        assert!(
            oversized.approx_size_bytes()
                > crate::gateway::size_limit::DEFAULT_MAX_RESPONSE_BYTES as u64
        );
        assert!(!cache.insert(oversized));
        assert_eq!(cache.stats().total_size_bytes, 0);
    }

    #[test]
    fn get_moves_entry_to_mru_position_before_eviction() {
        let cache = ContextPlanL1Cache::new(2, 4096);
        let auth = authorization("org", "team", "v1");
        let plan_a = plan(auth.clone(), "repo", "branch", "alpha", 1);
        let plan_b = plan(auth.clone(), "repo", "branch", "beta", 2);
        let plan_c = plan(auth.clone(), "repo", "branch", "gamma", 3);

        cache.insert(plan_a.clone());
        cache.insert(plan_b.clone());
        assert!(cache
            .get(&auth, "repo", "branch", plan_a.query_hash)
            .is_some());
        cache.insert(plan_c.clone());

        assert!(cache
            .get(&auth, "repo", "branch", plan_a.query_hash)
            .is_some());
        assert!(cache
            .get(&auth, "repo", "branch", plan_b.query_hash)
            .is_none());
        assert!(cache
            .get(&auth, "repo", "branch", plan_c.query_hash)
            .is_some());
    }

    #[test]
    fn global_budget_evicts_oldest_lru_entry_across_partitions() {
        let auth = authorization("org", "team", "v1");
        let plan_a = plan(auth.clone(), "repo-a", "branch-a", "alpha", 1);
        let plan_b = plan(auth.clone(), "repo-b", "branch-b", "beta", 1);
        let cache = ContextPlanL1Cache::new(
            4,
            plan_a
                .approx_size_bytes()
                .saturating_add(plan_b.approx_size_bytes())
                .saturating_sub(1),
        );

        cache.insert(plan_a.clone());
        cache.insert(plan_b.clone());

        assert!(cache
            .get(&auth, "repo-a", "branch-a", plan_a.query_hash)
            .is_none());
        assert!(cache
            .get(&auth, "repo-b", "branch-b", plan_b.query_hash)
            .is_some());
        assert_eq!(cache.stats().eviction_count, 1);
    }

    #[test]
    fn replace_partition_keeps_most_recalled_plans() {
        let cache = ContextPlanL1Cache::new(2, 4096);
        let auth = authorization("org", "team", "v1");
        cache.replace_partition_plans(
            &auth,
            "repo",
            "branch",
            vec![
                plan(auth.clone(), "repo", "branch", "low", 1),
                plan(auth.clone(), "repo", "branch", "high", 10),
                plan(auth.clone(), "repo", "branch", "mid", 5),
            ],
        );

        let stats = cache.stats();
        assert_eq!(stats.entry_count, 2);
        assert!(cache
            .get(&auth, "repo", "branch", hash_context_query("high"))
            .is_some());
        assert!(cache
            .get(&auth, "repo", "branch", hash_context_query("mid"))
            .is_some());
        assert!(cache
            .get(&auth, "repo", "branch", hash_context_query("low"))
            .is_none());
    }

    #[tokio::test]
    async fn invalidation_broadcasts_and_removes_matching_entry() {
        let cache = ContextPlanL1Cache::new(4, 4096);
        let auth = authorization("org", "team", "v1");
        let plan = plan(auth.clone(), "repo", "branch", "alpha", 1);
        let mut receiver = cache.subscribe();

        cache.insert(plan.clone());
        let removed = cache.publish_invalidation(ContextPoolMutation {
            authorization: auth.clone(),
            repo: "repo".to_string(),
            branch: "branch".to_string(),
            query_hash: Some(plan.query_hash),
            topic: None,
            kind: ContextPoolMutationKind::Share,
        });

        assert!(removed);
        assert!(cache
            .get(&auth, "repo", "branch", plan.query_hash)
            .is_none());
        let received = receiver.recv().await.expect("receive invalidation");
        assert_eq!(received.query_hash, Some(plan.query_hash));
        assert_eq!(received.kind, ContextPoolMutationKind::Share);
    }

    #[test]
    fn identical_queries_are_isolated_across_orgs_teams_and_authorization_versions() {
        let cache = ContextPlanL1Cache::new(8, 16 * 1024);
        let org_a_team_a = authorization("org-a", "team-a", "v1");
        let org_a_team_b = authorization("org-a", "team-b", "v1");
        let org_b_team_a = authorization("org-b", "team-a", "v1");
        let org_a_team_a_v2 = authorization("org-a", "team-a", "v2");
        let scopes = [
            (org_a_team_a.clone(), "org-a/team-a/v1"),
            (org_a_team_b.clone(), "org-a/team-b/v1"),
            (org_b_team_a.clone(), "org-b/team-a/v1"),
            (org_a_team_a_v2.clone(), "org-a/team-a/v2"),
        ];

        for (authorization, content) in &scopes {
            let mut plan = plan(
                authorization.clone(),
                "same/repo",
                "same-branch",
                "same query",
                1,
            );
            plan.items[0].content = (*content).to_string();
            assert!(cache.insert(plan));
        }

        let query_hash = hash_context_query("same query");
        for (authorization, content) in &scopes {
            let hit = cache
                .get(authorization, "same/repo", "same-branch", query_hash)
                .expect("authorized partition must contain its own plan");
            assert_eq!(hit.items[0].content, *content);
            assert_eq!(hit.items[0].organization_id, authorization.organization_id);
            assert_eq!(hit.items[0].team_id, authorization.team_id);
            assert_eq!(
                hit.items[0].authorization_version,
                authorization.authorization_version
            );
        }
    }

    #[test]
    fn tenant_scoped_invalidation_does_not_remove_other_org_or_team_entries() {
        let cache = ContextPlanL1Cache::new(8, 16 * 1024);
        let org_a_team_a = authorization("org-a", "team-a", "v1");
        let org_a_team_b = authorization("org-a", "team-b", "v1");
        let org_b_team_a = authorization("org-b", "team-a", "v1");
        let query_hash = hash_context_query("same query");

        for authorization in [&org_a_team_a, &org_a_team_b, &org_b_team_a] {
            assert!(cache.insert(plan(
                authorization.clone(),
                "same/repo",
                "same-branch",
                "same query",
                1,
            )));
        }

        assert!(cache.publish_invalidation(ContextPoolMutation {
            authorization: org_a_team_a.clone(),
            repo: "same/repo".to_string(),
            branch: "same-branch".to_string(),
            query_hash: Some(query_hash),
            topic: None,
            kind: ContextPoolMutationKind::Share,
        }));

        assert!(cache
            .get(&org_a_team_a, "same/repo", "same-branch", query_hash,)
            .is_none());
        assert!(cache
            .get(&org_a_team_b, "same/repo", "same-branch", query_hash,)
            .is_some());
        assert!(cache
            .get(&org_b_team_a, "same/repo", "same-branch", query_hash,)
            .is_some());
    }

    #[test]
    fn partition_recompute_rejects_plans_from_another_authorization_scope() {
        let cache = ContextPlanL1Cache::new(8, 16 * 1024);
        let requested_scope = authorization("org-a", "team-a", "v1");
        let foreign_scope = authorization("org-b", "team-b", "v1");

        cache.replace_partition_plans(
            &requested_scope,
            "same/repo",
            "same-branch",
            vec![plan(
                foreign_scope,
                "same/repo",
                "same-branch",
                "same query",
                1,
            )],
        );

        assert!(cache
            .get(
                &requested_scope,
                "same/repo",
                "same-branch",
                hash_context_query("same query"),
            )
            .is_none());
        assert_eq!(cache.stats().entry_count, 0);
    }

    #[tokio::test]
    async fn incomplete_authorization_cannot_publish_invalidation() {
        let cache = ContextPlanL1Cache::new(8, 16 * 1024);
        let mut receiver = cache.subscribe();

        assert!(!cache.publish_invalidation(ContextPoolMutation::new(
            ContextCacheAuthorization::default(),
            "same/repo",
            "same-branch",
            ContextPoolMutationKind::Share,
        )));
        assert!(receiver.try_recv().is_err());
        assert_eq!(cache.stats().invalidation_count, 0);
    }

    #[test]
    fn pressure_json_reports_expected_shape() {
        let cache = ContextPlanL1Cache::new(4, 4096);
        cache.insert(plan(
            authorization("org", "team", "v1"),
            "repo",
            "branch",
            "alpha",
            1,
        ));
        let pressure = cache.pressure_json();
        assert!(pressure.get("level").is_some());
        assert!(pressure.get("estimated_entry_count").is_some());
        assert!(pressure.get("percent_used").is_some());
    }
}
