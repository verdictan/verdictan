// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use dashmap::DashMap;
use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::hash::Hash;
use std::sync::{
    atomic::{AtomicU64, Ordering as AtomicOrdering},
    Mutex,
};
use std::time::{Duration, Instant};

const METADATA_REBUILD_FACTOR: usize = 4;
const MIN_METADATA_REBUILD_RECORDS: usize = 16;

#[derive(Clone)]
struct CacheEntry<V> {
    value: V,
    expires_at: Instant,
    generation: u64,
}

#[derive(Clone)]
struct ExpirationRecord<K> {
    key: K,
    expires_at: Instant,
    generation: u64,
}

impl<K> PartialEq for ExpirationRecord<K> {
    fn eq(&self, other: &Self) -> bool {
        self.expires_at == other.expires_at && self.generation == other.generation
    }
}

impl<K> Eq for ExpirationRecord<K> {}

impl<K> PartialOrd for ExpirationRecord<K> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K> Ord for ExpirationRecord<K> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.expires_at
            .cmp(&other.expires_at)
            .then_with(|| self.generation.cmp(&other.generation))
    }
}

#[derive(Clone)]
struct InsertionRecord<K> {
    key: K,
    generation: u64,
}

impl<K> PartialEq for InsertionRecord<K> {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation
    }
}

impl<K> Eq for InsertionRecord<K> {}

impl<K> PartialOrd for InsertionRecord<K> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K> Ord for InsertionRecord<K> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.generation.cmp(&other.generation)
    }
}

pub struct BoundedTtlCache<K, V> {
    max_entries: usize,
    ttl: Duration,
    entries: DashMap<K, CacheEntry<V>>,
    expirations: Mutex<BinaryHeap<Reverse<ExpirationRecord<K>>>>,
    insertions: Mutex<BinaryHeap<Reverse<InsertionRecord<K>>>>,
    maintenance: Mutex<()>,
    next_generation: AtomicU64,
}

impl<K, V> BoundedTtlCache<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            max_entries,
            ttl,
            entries: DashMap::new(),
            expirations: Mutex::new(BinaryHeap::new()),
            insertions: Mutex::new(BinaryHeap::new()),
            maintenance: Mutex::new(()),
            next_generation: AtomicU64::new(0),
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.get_at(key, Instant::now())
    }

    pub fn insert(&self, key: K, value: V) {
        self.insert_inner_at(key, value, None, Instant::now());
    }

    pub fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        self.insert_inner_at(key, value, Some(ttl), Instant::now());
    }

    /// Insert with a jittered TTL uniformly distributed in `[min_ttl, max_ttl]`.
    /// Uses system time nanos as a lightweight entropy source to avoid adding a
    /// `rand` dependency to the runtime path.
    pub fn insert_with_jitter(&self, key: K, value: V, min_ttl: Duration, max_ttl: Duration) {
        let ttl = Self::ttl_from_sample(min_ttl, max_ttl, Self::cheap_jitter_f64());
        self.insert_inner_at(key, value, Some(ttl), Instant::now());
    }

    pub fn remove(&self, key: &K) {
        let _guard = self
            .maintenance
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.entries.remove(key);
        self.maybe_compact_metadata_locked();
    }

    pub fn clear(&self) {
        let _guard = self
            .maintenance
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.entries.clear();
        self.expirations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        self.insertions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
    }

    pub fn reap_expired(&self) {
        let _guard = self
            .maintenance
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.prune_expired_locked(Instant::now());
        self.maybe_compact_metadata_locked();
    }

    /// Remove all entries whose key satisfies the given predicate.
    fn remove_where(&self, predicate: impl Fn(&K) -> bool) {
        let _guard = self
            .maintenance
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let keys: Vec<K> = self
            .entries
            .iter()
            .filter(|entry| predicate(entry.key()))
            .map(|entry| entry.key().clone())
            .collect();
        for key in keys {
            self.entries.remove(&key);
        }
        self.maybe_compact_metadata_locked();
    }

    /// Remove entries where the predicate over (key, value) returns true.
    pub fn remove_where_kv(&self, predicate: impl Fn(&K, &V) -> bool) {
        let _guard = self
            .maintenance
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let keys: Vec<K> = self
            .entries
            .iter()
            .filter(|entry| predicate(entry.key(), &entry.value().value))
            .map(|entry| entry.key().clone())
            .collect();
        for key in keys {
            self.entries.remove(&key);
        }
        self.maybe_compact_metadata_locked();
    }

    fn get_at(&self, key: &K, now: Instant) -> Option<V> {
        {
            let entry = self.entries.get(key)?;
            if entry.expires_at > now {
                return Some(entry.value.clone());
            }
        }

        let _guard = self
            .maintenance
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.prune_expired_locked(now);
        self.entries
            .get(key)
            .filter(|entry| entry.expires_at > now)
            .map(|entry| entry.value.clone())
    }

    fn insert_inner_at(&self, key: K, value: V, custom_ttl: Option<Duration>, now: Instant) {
        if self.max_entries == 0 {
            return;
        }

        let _guard = self
            .maintenance
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.prune_expired_locked(now);

        if !self.entries.contains_key(&key) {
            self.evict_excess_locked();
        }

        let generation = self
            .next_generation
            .fetch_add(1, AtomicOrdering::Relaxed)
            .saturating_add(1);
        let expires_at = now + custom_ttl.unwrap_or(self.ttl);
        self.entries.insert(
            key.clone(),
            CacheEntry {
                value,
                expires_at,
                generation,
            },
        );
        self.expirations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(Reverse(ExpirationRecord {
                key: key.clone(),
                expires_at,
                generation,
            }));
        self.insertions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(Reverse(InsertionRecord { key, generation }));
        self.maybe_compact_metadata_locked();
    }

    fn evict_excess_locked(&self) {
        let mut insertions = self
            .insertions
            .lock()
            .unwrap_or_else(|error| error.into_inner());

        while self.entries.len() >= self.max_entries {
            let Some(Reverse(record)) = insertions.pop() else {
                break;
            };
            let should_remove = self
                .entries
                .get(&record.key)
                .is_some_and(|entry| entry.generation == record.generation);
            if should_remove {
                self.entries.remove(&record.key);
            }
        }
    }

    fn prune_expired_locked(&self, now: Instant) {
        let mut expirations = self
            .expirations
            .lock()
            .unwrap_or_else(|error| error.into_inner());

        while let Some(Reverse(record)) = expirations.peek() {
            if record.expires_at > now {
                break;
            }

            let Some(record) = expirations.pop().map(|e| e.0) else {
                break;
            };
            let should_remove = self.entries.get(&record.key).is_some_and(|entry| {
                entry.generation == record.generation && entry.expires_at <= now
            });
            if should_remove {
                self.entries.remove(&record.key);
            }
        }
    }

    fn cheap_jitter_f64() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(1))
            .subsec_nanos() as f64
            / 1_000_000_000.0
    }

    fn ttl_from_sample(min_ttl: Duration, max_ttl: Duration, sample: f64) -> Duration {
        if max_ttl <= min_ttl {
            return min_ttl;
        }

        let range_ms = max_ttl.as_millis().saturating_sub(min_ttl.as_millis()) as f64;
        let clamped_sample = sample.clamp(0.0, 1.0 - f64::EPSILON);
        let jitter_ms = (range_ms * clamped_sample) as u64;
        min_ttl + Duration::from_millis(jitter_ms)
    }

    fn maybe_compact_metadata_locked(&self) {
        let live_entries = self.entries.len();
        let mut expirations = self
            .expirations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut insertions = self
            .insertions
            .lock()
            .unwrap_or_else(|error| error.into_inner());

        if live_entries == 0 {
            expirations.clear();
            insertions.clear();
            return;
        }

        let threshold = live_entries
            .saturating_mul(METADATA_REBUILD_FACTOR)
            .max(self.max_entries.saturating_mul(2))
            .max(MIN_METADATA_REBUILD_RECORDS);
        if expirations.len() <= threshold && insertions.len() <= threshold {
            return;
        }

        expirations.clear();
        insertions.clear();
        for entry in self.entries.iter() {
            let cache_entry = entry.value();
            expirations.push(Reverse(ExpirationRecord {
                key: entry.key().clone(),
                expires_at: cache_entry.expires_at,
                generation: cache_entry.generation,
            }));
            insertions.push(Reverse(InsertionRecord {
                key: entry.key().clone(),
                generation: cache_entry.generation,
            }));
        }
    }

    #[cfg(test)]
    pub(crate) fn get_at_for_test(&self, key: &K, now: Instant) -> Option<V> {
        self.get_at(key, now)
    }

    #[cfg(test)]
    pub(crate) fn insert_with_ttl_at_for_test(
        &self,
        key: K,
        value: V,
        ttl: Duration,
        now: Instant,
    ) {
        self.insert_inner_at(key, value, Some(ttl), now);
    }

    #[cfg(test)]
    fn metadata_record_counts_for_test(&self) -> (usize, usize, usize) {
        (
            self.entries.len(),
            self.expirations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            self.insertions
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
        )
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
    use super::BoundedTtlCache;
    use std::time::{Duration, Instant};

    #[test]
    fn insert_and_get() {
        let cache = BoundedTtlCache::new(10, Duration::from_secs(60));
        let now = Instant::now();

        cache.insert_inner_at("k1".to_string(), "v1".to_string(), None, now);

        assert_eq!(cache.get_at(&"k1".to_string(), now), Some("v1".to_string()));
        assert_eq!(cache.get_at(&"k2".to_string(), now), None);
    }

    #[test]
    fn evicts_oldest_live_entry_at_capacity() {
        let cache = BoundedTtlCache::new(2, Duration::from_secs(60));
        let now = Instant::now();

        cache.insert_inner_at("k1".to_string(), 1, None, now);
        cache.insert_inner_at("k2".to_string(), 2, None, now + Duration::from_millis(1));
        cache.insert_inner_at("k3".to_string(), 3, None, now + Duration::from_millis(2));

        assert_eq!(
            cache.get_at(&"k1".to_string(), now + Duration::from_millis(2)),
            None
        );
        assert_eq!(
            cache.get_at(&"k2".to_string(), now + Duration::from_millis(2)),
            Some(2)
        );
        assert_eq!(
            cache.get_at(&"k3".to_string(), now + Duration::from_millis(2)),
            Some(3)
        );
    }

    #[test]
    fn prunes_expired_entries_before_capacity_eviction() {
        let cache = BoundedTtlCache::new(2, Duration::from_millis(5));
        let now = Instant::now();

        cache.insert_inner_at("k1".to_string(), 1, None, now);
        cache.insert_inner_at("k2".to_string(), 2, None, now + Duration::from_millis(10));
        cache.insert_inner_at("k3".to_string(), 3, None, now + Duration::from_millis(11));

        assert_eq!(
            cache.get_at(&"k1".to_string(), now + Duration::from_millis(11)),
            None
        );
        assert_eq!(
            cache.get_at(&"k2".to_string(), now + Duration::from_millis(11)),
            Some(2)
        );
        assert_eq!(
            cache.get_at(&"k3".to_string(), now + Duration::from_millis(11)),
            Some(3)
        );
    }

    #[test]
    fn get_returns_none_after_expiry_without_sleep() {
        let cache = BoundedTtlCache::new(10, Duration::from_millis(5));
        let now = Instant::now();

        cache.insert_inner_at("k1".to_string(), "v1".to_string(), None, now);

        assert_eq!(
            cache.get_at(&"k1".to_string(), now + Duration::from_millis(6)),
            None
        );
    }

    #[test]
    fn remove_key() {
        let cache = BoundedTtlCache::new(10, Duration::from_secs(60));
        let now = Instant::now();

        cache.insert_inner_at("k1".to_string(), 42, None, now);
        cache.remove(&"k1".to_string());

        assert_eq!(cache.get_at(&"k1".to_string(), now), None);
    }

    #[test]
    fn removing_last_entry_clears_stale_metadata() {
        let cache = BoundedTtlCache::new(10, Duration::from_secs(60));
        let now = Instant::now();
        let key = "solo".to_string();

        cache.insert_inner_at(key.clone(), 1, None, now);
        cache.insert_inner_at(key.clone(), 2, None, now + Duration::from_millis(1));

        cache.remove(&key);

        assert_eq!(cache.get_at(&key, now + Duration::from_millis(1)), None);
        assert_eq!(cache.metadata_record_counts_for_test(), (0, 0, 0));
    }

    #[test]
    fn remove_where_clears_matching_keys() {
        let cache = BoundedTtlCache::new(10, Duration::from_secs(60));
        let now = Instant::now();

        cache.insert_inner_at("keep".to_string(), 1, None, now);
        cache.insert_inner_at("drop-a".to_string(), 2, None, now);
        cache.insert_inner_at("drop-b".to_string(), 3, None, now);
        cache.remove_where(|key| key.starts_with("drop"));

        assert_eq!(cache.get_at(&"keep".to_string(), now), Some(1));
        assert_eq!(cache.get_at(&"drop-a".to_string(), now), None);
        assert_eq!(cache.get_at(&"drop-b".to_string(), now), None);
    }

    #[test]
    fn remove_where_kv_clears_matching_values() {
        let cache = BoundedTtlCache::new(10, Duration::from_secs(60));
        let now = Instant::now();

        cache.insert_inner_at("keep".to_string(), 1, None, now);
        cache.insert_inner_at("drop".to_string(), 2, None, now);
        cache.remove_where_kv(|_, value| *value == 2);

        assert_eq!(cache.get_at(&"keep".to_string(), now), Some(1));
        assert_eq!(cache.get_at(&"drop".to_string(), now), None);
    }

    #[test]
    fn refreshed_entry_survives_stale_expiration_record() {
        let cache = BoundedTtlCache::new(10, Duration::from_secs(60));
        let now = Instant::now();
        let key = "refresh".to_string();

        cache.insert_inner_at(
            key.clone(),
            "old".to_string(),
            Some(Duration::from_millis(5)),
            now,
        );
        cache.insert_inner_at(
            key.clone(),
            "new".to_string(),
            Some(Duration::from_secs(60)),
            now + Duration::from_millis(1),
        );

        assert_eq!(
            cache.get_at(&key, now + Duration::from_millis(6)),
            Some("new".to_string())
        );
    }

    #[test]
    fn updating_existing_key_at_capacity_preserves_other_live_entries() {
        let cache = BoundedTtlCache::new(2, Duration::from_secs(60));
        let now = Instant::now();
        let first_key = "first".to_string();
        let second_key = "second".to_string();

        cache.insert_inner_at(first_key.clone(), 1, None, now);
        cache.insert_inner_at(second_key.clone(), 2, None, now + Duration::from_millis(1));
        cache.insert_inner_at(first_key.clone(), 10, None, now + Duration::from_millis(2));

        assert_eq!(
            cache.get_at(&first_key, now + Duration::from_millis(2)),
            Some(10)
        );
        assert_eq!(
            cache.get_at(&second_key, now + Duration::from_millis(2)),
            Some(2)
        );
        assert_eq!(cache.metadata_record_counts_for_test().0, 2);
    }

    #[test]
    fn refreshed_entry_is_not_evicted_by_stale_insertion_record() {
        let cache = BoundedTtlCache::new(2, Duration::from_secs(60));
        let now = Instant::now();
        let key1 = "k1".to_string();
        let key2 = "k2".to_string();
        let key3 = "k3".to_string();

        cache.insert_inner_at(key1.clone(), 1, None, now);
        cache.insert_inner_at(key2.clone(), 2, None, now + Duration::from_millis(1));
        cache.insert_inner_at(key1.clone(), 10, None, now + Duration::from_millis(2));
        cache.insert_inner_at(key3.clone(), 3, None, now + Duration::from_millis(3));

        assert_eq!(
            cache.get_at(&key1, now + Duration::from_millis(3)),
            Some(10)
        );
        assert_eq!(cache.get_at(&key2, now + Duration::from_millis(3)), None);
        assert_eq!(cache.get_at(&key3, now + Duration::from_millis(3)), Some(3));
    }

    #[test]
    fn removed_entry_stale_insertion_record_is_skipped_during_eviction() {
        let cache = BoundedTtlCache::new(2, Duration::from_secs(60));
        let now = Instant::now();
        let removed_key = "removed".to_string();
        let evicted_key = "evicted".to_string();
        let retained_key = "retained".to_string();
        let new_key = "new".to_string();

        cache.insert_inner_at(removed_key.clone(), 1, None, now);
        cache.insert_inner_at(evicted_key.clone(), 2, None, now + Duration::from_millis(1));
        cache.remove(&removed_key);
        cache.insert_inner_at(
            retained_key.clone(),
            3,
            None,
            now + Duration::from_millis(2),
        );
        cache.insert_inner_at(new_key.clone(), 4, None, now + Duration::from_millis(3));

        assert_eq!(
            cache.get_at(&removed_key, now + Duration::from_millis(3)),
            None
        );
        assert_eq!(
            cache.get_at(&evicted_key, now + Duration::from_millis(3)),
            None
        );
        assert_eq!(
            cache.get_at(&retained_key, now + Duration::from_millis(3)),
            Some(3)
        );
        assert_eq!(
            cache.get_at(&new_key, now + Duration::from_millis(3)),
            Some(4)
        );
    }

    #[test]
    fn removed_entry_stale_expiration_record_is_ignored_during_reap() {
        let cache = BoundedTtlCache::new(2, Duration::from_secs(60));
        let expired_inserted_at = Instant::now() - Duration::from_secs(2);
        let expired_key = "expired".to_string();
        let live_key = "live".to_string();

        cache.insert_inner_at(
            expired_key.clone(),
            "old".to_string(),
            Some(Duration::from_millis(1)),
            expired_inserted_at,
        );
        cache.insert_inner_at(live_key.clone(), "fresh".to_string(), None, Instant::now());
        cache.remove(&expired_key);

        cache.reap_expired();

        assert_eq!(cache.get(&expired_key), None);
        assert_eq!(cache.get(&live_key), Some("fresh".to_string()));
    }

    #[test]
    fn compacts_stale_metadata_records_after_repeated_refresh() {
        let cache = BoundedTtlCache::new(10, Duration::from_secs(60));
        let now = Instant::now();
        let key = "hot".to_string();

        for generation in 0..80u64 {
            cache.insert_inner_at(
                key.clone(),
                generation,
                None,
                now + Duration::from_millis(generation),
            );
        }

        let (live_entries, expiration_records, insertion_records) =
            cache.metadata_record_counts_for_test();
        assert_eq!(live_entries, 1);
        assert!(expiration_records <= 20);
        assert!(insertion_records <= 20);
        assert_eq!(
            cache.get_at(&key, now + Duration::from_millis(79)),
            Some(79)
        );
    }

    #[test]
    fn jitter_ttl_uses_requested_range() {
        let min_ttl = Duration::from_millis(5);
        let max_ttl = Duration::from_millis(15);

        assert_eq!(
            BoundedTtlCache::<String, String>::ttl_from_sample(min_ttl, max_ttl, 0.0),
            min_ttl
        );
        assert_eq!(
            BoundedTtlCache::<String, String>::ttl_from_sample(min_ttl, max_ttl, 0.5),
            Duration::from_millis(10)
        );
        assert_eq!(
            BoundedTtlCache::<String, String>::ttl_from_sample(min_ttl, max_ttl, 0.999),
            Duration::from_millis(14)
        );
        assert_eq!(
            BoundedTtlCache::<String, String>::ttl_from_sample(min_ttl, min_ttl, 0.5),
            min_ttl
        );
    }

    #[test]
    fn jitter_ttl_clamps_out_of_range_samples_and_inverted_bounds() {
        let min_ttl = Duration::from_millis(5);
        let max_ttl = Duration::from_millis(15);

        assert_eq!(
            BoundedTtlCache::<String, String>::ttl_from_sample(min_ttl, max_ttl, -3.0),
            min_ttl
        );
        assert_eq!(
            BoundedTtlCache::<String, String>::ttl_from_sample(min_ttl, max_ttl, 1.0),
            Duration::from_millis(14)
        );
        assert_eq!(
            BoundedTtlCache::<String, String>::ttl_from_sample(max_ttl, min_ttl, 0.5),
            max_ttl
        );
    }

    #[test]
    fn public_insert_and_get_use_default_ttl() {
        let cache = BoundedTtlCache::new(4, Duration::from_secs(60));
        cache.insert("key".to_string(), "value".to_string());

        assert_eq!(cache.get(&"key".to_string()), Some("value".to_string()));
    }

    #[test]
    fn public_insert_with_ttl_allows_immediate_expiration() {
        let cache = BoundedTtlCache::new(4, Duration::from_secs(60));
        cache.insert_with_ttl("key".to_string(), "value".to_string(), Duration::ZERO);

        assert_eq!(cache.get(&"key".to_string()), None);
    }

    #[test]
    fn zero_capacity_cache_drops_insertions() {
        let cache = BoundedTtlCache::new(0, Duration::from_secs(60));
        cache.insert("key".to_string(), "value".to_string());

        assert_eq!(cache.get(&"key".to_string()), None);
    }

    #[test]
    fn clear_removes_all_entries_and_metadata() {
        let cache = BoundedTtlCache::new(4, Duration::from_secs(60));
        cache.insert("a".to_string(), "1".to_string());
        cache.insert("b".to_string(), "2".to_string());

        cache.clear();

        assert_eq!(cache.get(&"a".to_string()), None);
        assert_eq!(cache.get(&"b".to_string()), None);
        assert_eq!(cache.metadata_record_counts_for_test(), (0, 0, 0));
    }

    #[test]
    fn reap_expired_removes_stale_entries() {
        let cache = BoundedTtlCache::new(4, Duration::from_secs(60));
        let inserted_at = Instant::now() - Duration::from_secs(2);

        cache.insert_with_ttl_at_for_test(
            "expired".to_string(),
            "value".to_string(),
            Duration::from_millis(1),
            inserted_at,
        );

        assert_eq!(
            cache.get_at_for_test(&"expired".to_string(), Instant::now()),
            None
        );

        cache.reap_expired();
        let (entries, _, _) = cache.metadata_record_counts_for_test();
        assert_eq!(entries, 0);
    }

    #[test]
    fn insert_with_jitter_accepts_equal_bounds_without_randomness() {
        let cache = BoundedTtlCache::new(4, Duration::from_secs(60));
        cache.insert_with_jitter(
            "key".to_string(),
            "value".to_string(),
            Duration::from_secs(5),
            Duration::from_secs(5),
        );

        assert_eq!(cache.get(&"key".to_string()), Some("value".to_string()));
    }
}
