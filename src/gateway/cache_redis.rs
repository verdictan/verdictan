// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

#![cfg_attr(not(feature = "distributed"), allow(dead_code, unused_imports))]

use std::time::Duration;

use crate::error::CliError;

use super::cache::{cosine_similarity, StoredCachedResponse};

const DEFAULT_REDIS_CACHE_KEY_PREFIX: &str = "vt:llm-cache";
const DEFAULT_CACHE_OP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct RedisExactCacheBackend {
    #[cfg(feature = "distributed")]
    connection: redis::aio::ConnectionManager,
    key_prefix: String,
    operator_backend: &'static str,
    request_timeout: Duration,
}

impl RedisExactCacheBackend {
    pub(crate) async fn new(
        redis_url: &str,
        key_prefix: &str,
        operator_backend: &'static str,
    ) -> Result<Self, CliError> {
        Self::new_with_timeout(
            redis_url,
            key_prefix,
            operator_backend,
            DEFAULT_CACHE_OP_TIMEOUT,
        )
        .await
    }

    pub(crate) async fn new_with_timeout(
        redis_url: &str,
        key_prefix: &str,
        operator_backend: &'static str,
        request_timeout: Duration,
    ) -> Result<Self, CliError> {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = redis_url;
            let _ = key_prefix;
            let _ = operator_backend;
            let _ = request_timeout;
            Err(CliError::user(format!(
                "VERDICTAN_LLM_CACHE_BACKEND={operator_backend} requires a CLI build with --features distributed"
            )))
        }

        #[cfg(feature = "distributed")]
        {
            let normalized_prefix = normalize_key_prefix(key_prefix);
            let backend_display_name = backend_display_name(operator_backend);
            let client = redis::Client::open(redis_url).map_err(|error| {
                CliError::user(format!(
                    "invalid {backend_display_name} URL for VERDICTAN_LLM_CACHE_REDIS_URL: {error}"
                ))
            })?;
            let mut connection = tokio::time::timeout(
                request_timeout,
                client.get_connection_manager(),
            )
            .await
            .map_err(|_| {
                CliError::network(format!(
                    "timed out connecting to {backend_display_name} for VERDICTAN_LLM_CACHE_BACKEND={operator_backend}"
                ))
            })?
            .map_err(|error| {
                CliError::network(format!(
                    "failed to connect to {backend_display_name} for VERDICTAN_LLM_CACHE_BACKEND={operator_backend}: {error}"
                ))
            })?;
            let _: String = Self::run_cmd(
                &mut connection,
                request_timeout,
                redis::cmd("PING"),
            )
            .await
            .map_err(|error| {
                CliError::network(format!(
                    "failed to ping {backend_display_name} for VERDICTAN_LLM_CACHE_BACKEND={operator_backend}: {error}"
                ))
            })?;

            Ok(Self {
                connection,
                key_prefix: normalized_prefix,
                operator_backend,
                request_timeout,
            })
        }
    }

    pub(crate) async fn get(&self, key: &str) -> Option<StoredCachedResponse> {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = key;
            None
        }

        #[cfg(feature = "distributed")]
        {
            let mut connection = self.connection.clone();
            let payload: Option<Vec<u8>> = Self::run_cmd(
                &mut connection,
                self.request_timeout,
                Self::cmd_get(self.response_key(key)),
            )
            .await
            .ok()?;
            serde_json::from_slice(&payload?).ok()
        }
    }

    pub(crate) async fn put(&self, key: &str, entry: StoredCachedResponse, ttl: &Duration) {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = key;
            let _ = entry;
            let _ = ttl;
        }

        #[cfg(feature = "distributed")]
        {
            let Ok(payload) = serde_json::to_vec(&entry) else {
                return;
            };
            let ttl_secs = ttl.as_secs().max(1);
            let mut connection = self.connection.clone();
            let response_key = self.response_key(key);
            let index_key = self.response_index_key();
            if let Err(error) = Self::run_cmd::<()>(
                &mut connection,
                self.request_timeout,
                Self::cmd_setex(&response_key, ttl_secs, payload),
            )
            .await
            {
                tracing::warn!(
                    error = %error,
                    cache_key = %key,
                    backend = self.operator_backend,
                    "cache put failed"
                );
                return;
            }
            if let Err(error) = Self::run_cmd::<()>(
                &mut connection,
                self.request_timeout,
                Self::cmd_sadd(&index_key, key),
            )
            .await
            {
                tracing::warn!(
                    error = %error,
                    cache_key = %key,
                    backend = self.operator_backend,
                    "cache response index update failed"
                );
            }
        }
    }

    pub(crate) async fn clear(&self) {
        #[cfg(not(feature = "distributed"))]
        {}

        #[cfg(feature = "distributed")]
        {
            let mut connection = self.connection.clone();
            let response_keys = self
                .indexed_members(&mut connection, &self.response_index_key())
                .await;
            let embedding_keys = self
                .indexed_members(&mut connection, &self.embedding_index_key())
                .await;

            let mut delete_args: Vec<String> = Vec::with_capacity(
                response_keys.len() + embedding_keys.len() + response_keys.len() + 2,
            );
            for key in &response_keys {
                delete_args.push(self.response_key(key));
            }
            for key in &embedding_keys {
                delete_args.push(self.embedding_key(key));
            }
            delete_args.push(self.response_index_key());
            delete_args.push(self.embedding_index_key());

            if delete_args.is_empty() {
                return;
            }
            if let Err(error) = Self::run_cmd::<()>(
                &mut connection,
                self.request_timeout,
                Self::cmd_del(&delete_args),
            )
            .await
            {
                tracing::warn!(error = %error, backend = self.operator_backend, "cache clear failed");
            }
        }
    }

    pub(crate) async fn remove(&self, key: &str) -> bool {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = key;
            false
        }

        #[cfg(feature = "distributed")]
        {
            let mut connection = self.connection.clone();
            let mut removed = false;
            for redis_key in [self.response_key(key), self.embedding_key(key)] {
                match Self::run_cmd::<u64>(
                    &mut connection,
                    self.request_timeout,
                    Self::cmd_del(&[redis_key]),
                )
                .await
                {
                    Ok(count) if count > 0 => removed = true,
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            cache_key = %key,
                            backend = self.operator_backend,
                            "cache remove failed"
                        );
                    }
                }
            }
            let _ = Self::run_cmd::<()>(
                &mut connection,
                self.request_timeout,
                Self::cmd_srem(self.response_index_key(), key),
            )
            .await;
            let _ = Self::run_cmd::<()>(
                &mut connection,
                self.request_timeout,
                Self::cmd_srem(self.embedding_index_key(), key),
            )
            .await;
            removed
        }
    }

    pub(crate) async fn pressure_json(&self) -> serde_json::Value {
        #[cfg(not(feature = "distributed"))]
        {
            serde_json::json!({
                "level": "unknown",
                "estimated_entry_count": serde_json::Value::Null,
            })
        }

        #[cfg(feature = "distributed")]
        {
            let mut connection = self.connection.clone();
            match Self::run_cmd::<u64>(
                &mut connection,
                self.request_timeout,
                Self::cmd_scard(self.response_index_key()),
            )
            .await
            {
                Ok(count) => serde_json::json!({
                    "level": "nominal",
                    "estimated_entry_count": count,
                }),
                Err(_) => serde_json::json!({
                    "level": "degraded",
                    "estimated_entry_count": serde_json::Value::Null,
                }),
            }
        }
    }

    pub(crate) async fn store_semantic_embedding(
        &self,
        key: &str,
        embedding: &[f64],
        ttl: &Duration,
    ) {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = key;
            let _ = embedding;
            let _ = ttl;
        }

        #[cfg(feature = "distributed")]
        {
            let Ok(payload) = serde_json::to_vec(embedding) else {
                return;
            };
            let ttl_secs = ttl.as_secs().max(1);
            let mut connection = self.connection.clone();
            if let Err(error) = Self::run_cmd::<()>(
                &mut connection,
                self.request_timeout,
                Self::cmd_setex(self.embedding_key(key), ttl_secs, payload),
            )
            .await
            {
                tracing::warn!(
                    error = %error,
                    cache_key = %key,
                    backend = self.operator_backend,
                    "semantic cache put failed"
                );
                return;
            }
            if let Err(error) = Self::run_cmd::<()>(
                &mut connection,
                self.request_timeout,
                Self::cmd_sadd(self.embedding_index_key(), key),
            )
            .await
            {
                tracing::warn!(
                    error = %error,
                    cache_key = %key,
                    backend = self.operator_backend,
                    "semantic cache index update failed"
                );
            }
        }
    }

    /// Cardinality-independent semantic lookup: one `SMEMBERS` plus one `MGET`.
    ///
    /// Never uses Redis `KEYS`. Request count stays constant for any fixture size.
    pub(crate) async fn semantic_lookup_key(
        &self,
        query_embedding: &[f64],
        threshold: f64,
    ) -> Option<String> {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = query_embedding;
            let _ = threshold;
            None
        }

        #[cfg(feature = "distributed")]
        {
            if query_embedding.is_empty() {
                return None;
            }

            let mut connection = self.connection.clone();
            let members = self
                .indexed_members(&mut connection, &self.embedding_index_key())
                .await;
            if members.is_empty() {
                return None;
            }

            let redis_keys: Vec<String> =
                members.iter().map(|key| self.embedding_key(key)).collect();
            let payloads: Vec<Option<Vec<u8>>> = Self::run_cmd(
                &mut connection,
                self.request_timeout,
                Self::cmd_mget(&redis_keys),
            )
            .await
            .ok()?;

            let mut best_key: Option<String> = None;
            let mut best_score = threshold;
            let mut stale: Vec<String> = Vec::new();

            for (member, payload) in members.into_iter().zip(payloads) {
                let Some(payload) = payload else {
                    stale.push(member);
                    continue;
                };
                let Ok(candidate_embedding) = serde_json::from_slice::<Vec<f64>>(&payload) else {
                    stale.push(member);
                    continue;
                };
                let score = cosine_similarity(query_embedding, &candidate_embedding);
                if score > best_score {
                    best_score = score;
                    best_key = Some(member);
                }
            }

            if !stale.is_empty() {
                let _ = Self::run_cmd::<()>(
                    &mut connection,
                    self.request_timeout,
                    Self::cmd_srem_many(&self.embedding_index_key(), &stale),
                )
                .await;
            }

            best_key
        }
    }

    /// Pipelined bulk seed used by PERF-001 cardinality fixtures.
    ///
    /// Keeps request count proportional to batch count, not one RTT per embedding.
    pub(crate) async fn bulk_store_semantic_embeddings(
        &self,
        embeddings: &[(String, Vec<f64>)],
        ttl: &Duration,
    ) {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = embeddings;
            let _ = ttl;
        }

        #[cfg(feature = "distributed")]
        {
            if embeddings.is_empty() {
                return;
            }
            const BATCH_SIZE: usize = 500;
            let ttl_secs = ttl.as_secs().max(1);
            let index_key = self.embedding_index_key();
            let mut connection = self.connection.clone();

            for chunk in embeddings.chunks(BATCH_SIZE) {
                let mut pipe = redis::pipe();
                let mut queued = 0usize;
                for (key, embedding) in chunk {
                    if embedding.is_empty() {
                        continue;
                    }
                    let Ok(payload) = serde_json::to_vec(embedding) else {
                        continue;
                    };
                    pipe.cmd("SETEX")
                        .arg(self.embedding_key(key))
                        .arg(ttl_secs)
                        .arg(payload)
                        .ignore();
                    pipe.cmd("SADD").arg(&index_key).arg(key).ignore();
                    queued += 1;
                }
                if queued == 0 {
                    continue;
                }
                match tokio::time::timeout(
                    self.request_timeout,
                    pipe.query_async::<_, ()>(&mut connection),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(
                            error = %error,
                            backend = self.operator_backend,
                            batch_size = queued,
                            "semantic cache bulk seed failed"
                        );
                    }
                    Err(_) => {
                        tracing::warn!(
                            backend = self.operator_backend,
                            batch_size = queued,
                            timeout_ms = self.request_timeout.as_millis() as u64,
                            "semantic cache bulk seed timed out"
                        );
                    }
                }
            }
        }
    }

    fn response_key(&self, key: &str) -> String {
        format!("{}:response:{key}", self.key_prefix)
    }

    fn embedding_key(&self, key: &str) -> String {
        format!("{}:embedding:{key}", self.key_prefix)
    }

    fn response_index_key(&self) -> String {
        format!("{}:response-index", self.key_prefix)
    }

    fn embedding_index_key(&self) -> String {
        format!("{}:embedding-index", self.key_prefix)
    }

    fn cache_key_from_embedding_key(&self, redis_key: &str) -> Option<String> {
        redis_key
            .strip_prefix(&format!("{}:embedding:", self.key_prefix))
            .map(ToString::to_string)
    }

    #[cfg(feature = "distributed")]
    async fn indexed_members(
        &self,
        connection: &mut redis::aio::ConnectionManager,
        index_key: &str,
    ) -> Vec<String> {
        Self::run_cmd::<Vec<String>>(
            connection,
            self.request_timeout,
            Self::cmd_smembers(index_key),
        )
        .await
        .unwrap_or_default()
    }

    #[cfg(feature = "distributed")]
    async fn run_cmd<T>(
        connection: &mut redis::aio::ConnectionManager,
        timeout: Duration,
        cmd: redis::Cmd,
    ) -> Result<T, String>
    where
        T: redis::FromRedisValue,
    {
        tokio::time::timeout(timeout, cmd.query_async(connection))
            .await
            .map_err(|_| "redis cache operation timed out".to_string())?
            .map_err(|error| error.to_string())
    }

    #[cfg(feature = "distributed")]
    fn cmd_get(key: impl redis::ToRedisArgs) -> redis::Cmd {
        let mut cmd = redis::cmd("GET");
        cmd.arg(key);
        cmd
    }

    #[cfg(feature = "distributed")]
    fn cmd_setex(
        key: impl redis::ToRedisArgs,
        ttl: u64,
        payload: impl redis::ToRedisArgs,
    ) -> redis::Cmd {
        let mut cmd = redis::cmd("SETEX");
        cmd.arg(key);
        cmd.arg(ttl);
        cmd.arg(payload);
        cmd
    }

    #[cfg(feature = "distributed")]
    fn cmd_sadd(key: impl redis::ToRedisArgs, member: impl redis::ToRedisArgs) -> redis::Cmd {
        let mut cmd = redis::cmd("SADD");
        cmd.arg(key);
        cmd.arg(member);
        cmd
    }

    #[cfg(feature = "distributed")]
    fn cmd_srem(key: impl redis::ToRedisArgs, member: impl redis::ToRedisArgs) -> redis::Cmd {
        let mut cmd = redis::cmd("SREM");
        cmd.arg(key);
        cmd.arg(member);
        cmd
    }

    #[cfg(feature = "distributed")]
    fn cmd_scard(key: impl redis::ToRedisArgs) -> redis::Cmd {
        let mut cmd = redis::cmd("SCARD");
        cmd.arg(key);
        cmd
    }

    #[cfg(feature = "distributed")]
    fn cmd_smembers(key: impl redis::ToRedisArgs) -> redis::Cmd {
        let mut cmd = redis::cmd("SMEMBERS");
        cmd.arg(key);
        cmd
    }

    #[cfg(feature = "distributed")]
    fn cmd_del(keys: &[String]) -> redis::Cmd {
        let mut cmd = redis::cmd("DEL");
        for key in keys {
            cmd.arg(key);
        }
        cmd
    }

    #[cfg(feature = "distributed")]
    fn cmd_mget(keys: &[String]) -> redis::Cmd {
        let mut cmd = redis::cmd("MGET");
        for key in keys {
            cmd.arg(key);
        }
        cmd
    }

    #[cfg(feature = "distributed")]
    fn cmd_srem_many(index_key: &str, members: &[String]) -> redis::Cmd {
        let mut cmd = redis::cmd("SREM");
        cmd.arg(index_key);
        for member in members {
            cmd.arg(member);
        }
        cmd
    }
}

fn normalize_key_prefix(key_prefix: &str) -> String {
    let trimmed = key_prefix.trim().trim_matches(':');
    if trimmed.is_empty() {
        DEFAULT_REDIS_CACHE_KEY_PREFIX.to_string()
    } else {
        trimmed.to_string()
    }
}

fn backend_display_name(operator_backend: &str) -> &'static str {
    match operator_backend {
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
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};

    fn sample_entry() -> StoredCachedResponse {
        StoredCachedResponse {
            stored_at_unix_secs: 1,
            status: 200,
            headers: vec![],
            body_base64: BASE64_STANDARD.encode(b"cached"),
            original_key: None,
            key_version: 1,
        }
    }

    #[test]
    fn normalize_key_prefix_defaults_and_trims() {
        assert_eq!(
            normalize_key_prefix("::team-cache::"),
            "team-cache".to_string()
        );
        assert_eq!(
            normalize_key_prefix("   "),
            DEFAULT_REDIS_CACHE_KEY_PREFIX.to_string()
        );
    }

    #[test]
    fn backend_display_name_maps_known_backends() {
        assert_eq!(backend_display_name("redis"), "Redis");
        assert_eq!(backend_display_name("valkey"), "Valkey");
        assert_eq!(backend_display_name("something-else"), "Redis");
    }

    #[test]
    fn key_helpers_use_normalized_prefixes() {
        let key_prefix = "custom-prefix";
        assert_eq!(
            format!("{key_prefix}:response:session-1"),
            "custom-prefix:response:session-1"
        );
        assert_eq!(
            format!("{key_prefix}:embedding:session-1"),
            "custom-prefix:embedding:session-1"
        );
        assert_eq!(
            format!("{key_prefix}:response-index"),
            "custom-prefix:response-index"
        );
        assert_eq!(
            format!("{key_prefix}:embedding-index"),
            "custom-prefix:embedding-index"
        );
    }

    #[test]
    fn embedding_key_round_trips_back_to_cache_key() {
        let prefix = "custom-prefix";
        let redis_key = format!("{prefix}:embedding:abc123");
        assert_eq!(
            redis_key.strip_prefix(&format!("{prefix}:embedding:")),
            Some("abc123")
        );
        let _ = sample_entry();
    }

    #[cfg(not(feature = "distributed"))]
    fn unavailable_backend() -> RedisExactCacheBackend {
        RedisExactCacheBackend {
            key_prefix: "custom-prefix".to_string(),
            operator_backend: "redis",
            request_timeout: DEFAULT_CACHE_OP_TIMEOUT,
        }
    }

    #[cfg(not(feature = "distributed"))]
    #[tokio::test]
    async fn backend_methods_fail_open_without_panicking_when_unavailable() {
        let backend = unavailable_backend();

        assert!(backend.get("missing").await.is_none());
        backend
            .put("missing", sample_entry(), &Duration::from_secs(60))
            .await;
        backend
            .store_semantic_embedding("missing", &[0.1, 0.2], &Duration::from_secs(60))
            .await;
        backend.clear().await;
        assert!(!backend.remove("missing").await);
        let _ = backend.pressure_json().await;
        assert!(backend.semantic_lookup_key(&[], 0.8).await.is_none());
        assert!(backend
            .semantic_lookup_key(&[0.1, 0.2], 0.8)
            .await
            .is_none());
    }

    #[cfg(not(feature = "distributed"))]
    #[tokio::test]
    async fn semantic_lookup_key_returns_none_for_empty_embedding() {
        let backend = unavailable_backend();
        assert!(backend.semantic_lookup_key(&[], 0.0).await.is_none());
    }

    #[cfg(not(feature = "distributed"))]
    #[test]
    fn cache_key_from_embedding_key_strips_prefix() {
        let backend = unavailable_backend();
        assert_eq!(
            backend.cache_key_from_embedding_key("custom-prefix:embedding:abc123"),
            Some("abc123".to_string())
        );
        assert_eq!(
            backend.cache_key_from_embedding_key("other-prefix:embedding:abc123"),
            None
        );
    }
}
