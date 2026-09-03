// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Bounded TTL cache for denied token validations (connected control plane).

use std::time::Duration;

use sha2::{Digest, Sha256};

use super::bounded_ttl_cache::BoundedTtlCache;

#[cfg(test)]
use std::time::Instant;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TokenValidationCacheKey {
    pub key_sha256: String,
    pub shape: String,
}

impl TokenValidationCacheKey {
    pub fn for_runtime_validation(raw_key: &str) -> Self {
        Self {
            key_sha256: hex::encode(Sha256::digest(raw_key.as_bytes())),
            shape: "token_runtime_v1".to_string(),
        }
    }
}

pub struct TokenValidationCache<V: Clone> {
    negative_ttl: Duration,
    inner: BoundedTtlCache<TokenValidationCacheKey, V>,
}

impl<V: Clone> TokenValidationCache<V> {
    pub fn new(max_entries: usize, negative_ttl: Duration) -> Self {
        Self {
            negative_ttl,
            inner: BoundedTtlCache::new(max_entries, negative_ttl),
        }
    }

    pub fn get_negative(&self, key: &TokenValidationCacheKey) -> Option<V> {
        self.inner.get(key)
    }

    pub fn insert_negative(&self, key: TokenValidationCacheKey, value: V) {
        self.inner.insert_with_ttl(key, value, self.negative_ttl);
    }

    pub fn clear(&self) {
        self.inner.clear();
    }

    pub fn reap_expired(&self) {
        self.inner.reap_expired();
    }

    #[cfg(test)]
    fn insert_negative_at(&self, key: TokenValidationCacheKey, value: V, now: Instant) {
        self.inner
            .insert_with_ttl_at_for_test(key, value, self.negative_ttl, now);
    }

    #[cfg(test)]
    fn get_negative_at(&self, key: &TokenValidationCacheKey, now: Instant) -> Option<V> {
        self.inner.get_at_for_test(key, now)
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
    use super::{TokenValidationCache, TokenValidationCacheKey};
    use std::time::{Duration, Instant};

    fn key(raw: &str) -> TokenValidationCacheKey {
        TokenValidationCacheKey::for_runtime_validation(raw)
    }

    #[test]
    fn returns_negative_entries() {
        let cache = TokenValidationCache::new(4, Duration::from_secs(5));
        let now = Instant::now();
        let key = key("runtime-token");

        cache.insert_negative_at(key.clone(), "deny".to_string(), now);

        assert_eq!(cache.get_negative_at(&key, now), Some("deny".to_string()));
    }

    #[test]
    fn evicts_oldest_denial_at_capacity() {
        let cache = TokenValidationCache::new(2, Duration::from_secs(5));
        let now = Instant::now();
        let key1 = key("runtime-token-1");
        let key2 = key("runtime-token-2");
        let key3 = key("runtime-token-3");

        cache.insert_negative_at(key1.clone(), "deny-1".to_string(), now);
        cache.insert_negative_at(
            key2.clone(),
            "deny-2".to_string(),
            now + Duration::from_millis(1),
        );
        cache.insert_negative_at(
            key3.clone(),
            "deny-3".to_string(),
            now + Duration::from_millis(2),
        );

        assert_eq!(
            cache.get_negative_at(&key1, now + Duration::from_millis(2)),
            None
        );
        assert_eq!(
            cache.get_negative_at(&key2, now + Duration::from_millis(2)),
            Some("deny-2".to_string())
        );
        assert_eq!(
            cache.get_negative_at(&key3, now + Duration::from_millis(2)),
            Some("deny-3".to_string())
        );
    }

    #[test]
    fn expires_denials_by_ttl() {
        let cache = TokenValidationCache::new(4, Duration::from_millis(5));
        let now = Instant::now();
        let negative_key = key("runtime-negative");

        cache.insert_negative_at(negative_key.clone(), "deny".to_string(), now);

        assert_eq!(
            cache.get_negative_at(&negative_key, now + Duration::from_millis(6)),
            None
        );
    }

    #[test]
    fn clear_removes_cached_entries() {
        let cache = TokenValidationCache::new(4, Duration::from_secs(5));
        let key = key("runtime-token");

        cache.insert_negative(key.clone(), "deny".to_string());
        assert_eq!(cache.get_negative(&key), Some("deny".to_string()));

        cache.clear();

        assert_eq!(cache.get_negative(&key), None);
    }

    #[test]
    fn runtime_validation_key_hash_is_deterministic() {
        let key = TokenValidationCacheKey::for_runtime_validation("runtime-token");

        assert_eq!(
            key.key_sha256,
            "f8e1f3c257c8d1a3d07a68280431f02cde33742cfa77724b270598eb1d3a51b6"
        );
        assert_eq!(key.shape, "token_runtime_v1");
    }
}
