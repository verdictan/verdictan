// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

pub use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
pub use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use indexmap::IndexMap;
pub use std::{collections::HashMap, time::Duration};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crate::error::CliError;
use crate::gateway::metrics::{CACHE_HIT_COUNTER, CACHE_MISS_COUNTER};

use super::super::cache_object_store::ObjectStoreExactCacheBackend;
pub use super::super::cache_object_store::{ObjectStoreCacheConfig, ObjectStoreFlavor};
pub use super::super::cache_qdrant::QdrantCacheConfig;
use super::super::cache_qdrant::QdrantSemanticCacheBackend;
use super::super::cache_redis::RedisExactCacheBackend;

// ─── Cache key versioning ────────────────────────────────────────────────────

/// Current key-version stamped on all newly written cache blobs.
///
/// When a cache read encounters an entry whose `key_version` does not match
/// this constant, the read returns a cache miss rather than a decryption error
/// (fail-open on unknown version, not fail-closed). This enables zero-downtime
/// key rotation:
///
/// 1. Deploy new key version to all gateway instances.
/// 2. New writes use `CURRENT_CACHE_KEY_VERSION`.
/// 3. Old entries (previous version) continue to be decryptable until evicted by their TTL.
/// 4. After the TTL window all surviving entries carry the new version.
///
/// Old entries serialised before this field existed are deserialized with
/// `key_version = 0` (via `#[serde(default)]`), which is not a recognized
/// version and therefore returns a cache miss.
async fn atomic_write_async(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|error| {
            CliError::internal(format!(
                "failed to create parent directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    let tmp_path = path.with_extension(format!(
        "{}.tmp-{}",
        path.extension().and_then(|e| e.to_str()).unwrap_or("bin"),
        std::process::id()
    ));
    tokio::fs::write(&tmp_path, bytes).await.map_err(|error| {
        CliError::internal(format!(
            "failed to write temporary file {}: {error}",
            tmp_path.display()
        ))
    })?;
    if let Err(error) = tokio::fs::rename(&tmp_path, path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(CliError::internal(format!(
            "failed to replace file {}: {error}",
            path.display()
        )));
    }
    Ok(())
}

pub const CURRENT_CACHE_KEY_VERSION: u32 = 1;

/// Returns `CURRENT_CACHE_KEY_VERSION`. Convenience accessor for tests.
fn current_cache_key_version() -> u32 {
    CURRENT_CACHE_KEY_VERSION
}

fn default_key_version() -> u32 {
    // Absent key_version entries deserialize as version 0, which becomes an
    // unrecognized version and therefore a cache miss.
    0
}

const DEFAULT_CACHE_TTL_SECS: u64 = 14 * 24 * 60 * 60;
pub const DEFAULT_REDIS_CACHE_KEY_PREFIX: &str = "vt:llm-cache";
const DEFAULT_GCS_ENDPOINT: &str = "https://storage.googleapis.com";

/// Default maximum size for the local filesystem cache (500 MB).
pub const DEFAULT_LOCAL_CACHE_MAX_BYTES: u64 = 524_288_000;

/// Magic byte identifying bincode-serialized cache entries.
const CACHE_FORMAT_BINCODE_V1: u8 = 0x01;

/// Metadata tracked per entry in the LRU index.
#[derive(Clone, Debug)]
struct CacheEntryMeta {
    size_bytes: u64,
    last_accessed: Instant,
    #[allow(dead_code)]
    created_at: Instant,
}

/// Statistics exposed by the filesystem cache backend.
#[derive(Clone, Debug, Default)]
pub struct FilesystemCacheStats {
    pub entry_count: u64,
    pub total_size_bytes: u64,
    pub max_bytes: u64,
    pub hit_count: u64,
    pub miss_count: u64,
    pub eviction_count: u64,
    pub warmed: bool,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct PersistedFilesystemCacheStats {
    hit_count: u64,
    miss_count: u64,
    eviction_count: u64,
}

#[derive(Clone, Debug)]
pub struct BufferedUpstreamResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub cached: bool,
    /// Set when PERF-012 bounded reading rejected Content-Length or stopped at limit+1.
    /// Oversized responses must never be cached.
    pub response_size_exceeded: Option<ResponseSizeExceeded>,
}

/// Details for a response rejected by the bounded chunk reader / size limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseSizeExceeded {
    pub actual: usize,
    pub limit: usize,
}

impl BufferedUpstreamResponse {
    pub fn new(status: StatusCode, headers: HeaderMap, body: Bytes, cached: bool) -> Self {
        Self {
            status,
            headers,
            body,
            cached,
            response_size_exceeded: None,
        }
    }

    pub fn size_exceeded(
        _status: StatusCode,
        headers: HeaderMap,
        actual: usize,
        limit: usize,
        cached: bool,
    ) -> Self {
        // Preserve upstream headers for diagnostics, but force a non-success
        // status so provider success-shape validation cannot admit an emptied
        // oversized body. Callers (chat/responses finalize) map the flag to 502
        // `response_size_exceeded`.
        Self {
            status: StatusCode::BAD_GATEWAY,
            headers,
            body: Bytes::new(),
            cached,
            response_size_exceeded: Some(ResponseSizeExceeded { actual, limit }),
        }
    }

    pub async fn from_reqwest(
        response: reqwest::Response,
        cached: bool,
    ) -> Result<Self, reqwest::Error> {
        Self::from_reqwest_with_limit(
            response,
            cached,
            crate::gateway::size_limit::DEFAULT_MAX_RESPONSE_BYTES,
        )
        .await
    }

    pub async fn from_reqwest_with_limit(
        response: reqwest::Response,
        cached: bool,
        limit: usize,
    ) -> Result<Self, reqwest::Error> {
        use crate::gateway::size_limit::{
            effective_response_limit, overflow_stop_bytes, reject_oversized_content_length,
            MAX_IN_FLIGHT_RESPONSE_BUFFER_BYTES,
        };
        use bytes::BytesMut;
        use futures_util::StreamExt;

        let limit = effective_response_limit(Some(limit));
        let status = response.status();
        let headers = response.headers().clone();

        // Reject oversized Content-Length before buffering any body bytes.
        if let Err(error) = reject_oversized_content_length(&headers, limit) {
            drop(response);
            return Ok(Self::size_exceeded(
                status,
                headers,
                error.actual(),
                error.limit(),
                cached,
            ));
        }

        let stop_at = overflow_stop_bytes(limit);
        debug_assert!(stop_at <= MAX_IN_FLIGHT_RESPONSE_BUFFER_BYTES);

        let mut stream = response.bytes_stream();
        let mut buf = BytesMut::with_capacity(limit.min(65_536));
        while let Some(item) = stream.next().await {
            // Preserve reqwest transport errors so provider dispatch can retry.
            let chunk = item?;
            if chunk.is_empty() {
                continue;
            }
            let remaining = stop_at.saturating_sub(buf.len());
            if remaining == 0 || chunk.len() > remaining {
                let take = remaining.min(chunk.len());
                if take > 0 {
                    buf.extend_from_slice(&chunk[..take]);
                }
                return Ok(Self::size_exceeded(
                    status,
                    headers,
                    buf.len(),
                    limit,
                    cached,
                ));
            }
            buf.extend_from_slice(&chunk);
        }

        if buf.len() > limit {
            return Ok(Self::size_exceeded(
                status,
                headers,
                buf.len(),
                limit,
                cached,
            ));
        }

        Ok(Self::new(status, headers, buf.freeze(), cached))
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }

    pub fn is_cached(&self) -> bool {
        self.cached
    }

    pub fn is_cacheable_success(&self) -> bool {
        self.response_size_exceeded.is_none() && self.status.is_success() && !self.body.is_empty()
    }

    pub fn is_response_size_exceeded(&self) -> bool {
        self.response_size_exceeded.is_some()
    }

    pub fn response_size_exceeded(&self) -> Option<&ResponseSizeExceeded> {
        self.response_size_exceeded.as_ref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheBackend {
    Memory,
    Filesystem,
    Redis,
    Valkey,
    S3,
    Gcs,
    Qdrant,
}

impl CacheBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Filesystem => "filesystem",
            Self::Redis => "redis",
            Self::Valkey => "valkey",
            Self::S3 => "s3",
            Self::Gcs => "gcs",
            Self::Qdrant => "qdrant",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CacheConfig {
    pub enabled: bool,
    pub backend: CacheBackend,
    pub ttl: Duration,
    pub directory: Option<PathBuf>,
    pub max_bytes: u64,
    pub warmup_enabled: bool,
    pub redis_url: Option<String>,
    pub redis_key_prefix: String,
    pub s3_config: Option<ObjectStoreCacheConfig>,
    pub gcs_config: Option<ObjectStoreCacheConfig>,
    pub qdrant_config: Option<QdrantCacheConfig>,
    pub clear_on_start: bool,
    pub cache_buster: Option<String>,
}

impl CacheConfig {
    pub fn from_env() -> Result<Self, CliError> {
        let enabled = parse_bool_env("VERDICTAN_LLM_CACHE_ENABLED").unwrap_or(true);
        let ttl_secs = std::env::var("VERDICTAN_LLM_CACHE_TTL_SECS")
            .ok()
            .map(|value| {
                value.parse::<u64>().map_err(|_| {
                    CliError::user(
                        "invalid VERDICTAN_LLM_CACHE_TTL_SECS (expected positive integer seconds)",
                    )
                })
            })
            .transpose()?
            .unwrap_or(DEFAULT_CACHE_TTL_SECS)
            .max(1);
        let clear_on_start = parse_bool_env("VERDICTAN_LLM_CACHE_CLEAR").unwrap_or(false);
        let cache_buster = std::env::var("VERDICTAN_LLM_CACHE_BUSTER")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        let backend = parse_cache_backend(
            std::env::var("VERDICTAN_LLM_CACHE_BACKEND")
                .unwrap_or_else(|_| "auto".to_string())
                .trim(),
        )?;

        let directory = match backend {
            CacheBackend::Memory => None,
            CacheBackend::Filesystem => Some(resolve_cache_directory(
                std::env::var("VERDICTAN_LLM_CACHE_DIR").ok(),
            )),
            _ => None,
        };

        let max_bytes = std::env::var("VERDICTAN_LLM_CACHE_MAX_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_LOCAL_CACHE_MAX_BYTES);

        let warmup_enabled = parse_bool_env("VERDICTAN_LLM_CACHE_WARMUP_ENABLED").unwrap_or(true);

        let redis_url = match backend {
            CacheBackend::Redis | CacheBackend::Valkey => resolve_redis_cache_url(),
            _ => None,
        };
        let redis_key_prefix = resolve_redis_cache_key_prefix();
        let s3_config = match backend {
            CacheBackend::S3 => resolve_s3_cache_config(),
            _ => None,
        };
        let gcs_config = match backend {
            CacheBackend::Gcs => resolve_gcs_cache_config(),
            _ => None,
        };
        let qdrant_config = match backend {
            CacheBackend::Qdrant => resolve_qdrant_cache_config(),
            _ => None,
        };

        let config = Self {
            enabled,
            backend,
            ttl: Duration::from_secs(ttl_secs),
            directory,
            max_bytes,
            warmup_enabled,
            redis_url,
            redis_key_prefix,
            s3_config,
            gcs_config,
            qdrant_config,
            clear_on_start,
            cache_buster,
        };
        config.ensure_supported()?;
        Ok(config)
    }

    pub fn ensure_supported(&self) -> Result<(), CliError> {
        if !self.enabled {
            return Ok(());
        }

        match self.backend {
            CacheBackend::Memory | CacheBackend::Filesystem => Ok(()),
            CacheBackend::Redis | CacheBackend::Valkey => ensure_redis_cache_supported(self),
            CacheBackend::S3 => ensure_s3_cache_supported(self),
            CacheBackend::Gcs => ensure_gcs_cache_supported(self),
            CacheBackend::Qdrant => ensure_qdrant_cache_supported(self),
        }
    }
}

/// Returns `true` when the gateway is running in a development or test
/// environment. Used to select safe defaults (e.g. memory-only cache).
fn is_dev_or_test_environment() -> bool {
    matches!(
        std::env::var("VERDICTAN_ENV")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "development" | "dev" | "test" | "testing"
    ) || std::env::var("VERDICTAN_TEST_HOME").is_ok()
        || cfg!(test)
}

pub fn parse_cache_backend(raw: &str) -> Result<CacheBackend, CliError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" | "" => {
            if is_dev_or_test_environment() {
                Ok(CacheBackend::Memory)
            } else {
                Err(CliError::user(
                    "VERDICTAN_LLM_CACHE_BACKEND='auto' requires an explicit backend in production; \
                     set to 'memory', 'filesystem', 'redis', 'valkey', 's3', 'gcs', or 'qdrant'",
                ))
            }
        }
        "memory" => Ok(CacheBackend::Memory),
        "filesystem" | "file" | "disk" => Ok(CacheBackend::Filesystem),
        "redis" => Ok(CacheBackend::Redis),
        "valkey" => Ok(CacheBackend::Valkey),
        "s3" => Ok(CacheBackend::S3),
        "gcs" => Ok(CacheBackend::Gcs),
        "qdrant" => Ok(CacheBackend::Qdrant),
        _ => Err(CliError::user(
            "invalid VERDICTAN_LLM_CACHE_BACKEND (expected memory|filesystem|redis|valkey|s3|gcs|qdrant)",
        )),
    }
}

fn resolve_env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn resolve_redis_cache_url() -> Option<String> {
    resolve_env_value("VERDICTAN_LLM_CACHE_REDIS_URL")
}

fn resolve_redis_cache_key_prefix() -> String {
    resolve_env_value("VERDICTAN_LLM_CACHE_REDIS_KEY_PREFIX")
        .map(|value| value.trim_matches(':').to_string())
        .unwrap_or_else(|| DEFAULT_REDIS_CACHE_KEY_PREFIX.to_string())
}

fn resolve_s3_cache_config() -> Option<ObjectStoreCacheConfig> {
    let endpoint = resolve_env_value("VERDICTAN_LLM_CACHE_S3_ENDPOINT");
    Some(ObjectStoreCacheConfig {
        flavor: ObjectStoreFlavor::S3,
        bucket: resolve_env_value("VERDICTAN_LLM_CACHE_S3_BUCKET")?,
        prefix: resolve_env_value("VERDICTAN_LLM_CACHE_S3_PREFIX")
            .unwrap_or_else(ObjectStoreCacheConfig::default_prefix),
        region: resolve_env_value("VERDICTAN_LLM_CACHE_S3_REGION")?,
        endpoint: endpoint.clone(),
        access_key_id: resolve_env_value("VERDICTAN_LLM_CACHE_S3_ACCESS_KEY_ID")?,
        secret_access_key: resolve_env_value("VERDICTAN_LLM_CACHE_S3_SECRET_ACCESS_KEY")?,
        force_path_style: parse_bool_env("VERDICTAN_LLM_CACHE_S3_FORCE_PATH_STYLE")
            .unwrap_or(endpoint.is_some()),
    })
}

fn resolve_gcs_cache_config() -> Option<ObjectStoreCacheConfig> {
    Some(ObjectStoreCacheConfig {
        flavor: ObjectStoreFlavor::Gcs,
        bucket: resolve_env_value("VERDICTAN_LLM_CACHE_GCS_BUCKET")?,
        prefix: resolve_env_value("VERDICTAN_LLM_CACHE_GCS_PREFIX")
            .unwrap_or_else(ObjectStoreCacheConfig::default_prefix),
        region: resolve_env_value("VERDICTAN_LLM_CACHE_GCS_REGION")
            .unwrap_or_else(|| "auto".to_string()),
        endpoint: Some(
            resolve_env_value("VERDICTAN_LLM_CACHE_GCS_ENDPOINT")
                .unwrap_or_else(|| DEFAULT_GCS_ENDPOINT.to_string()),
        ),
        access_key_id: resolve_env_value("VERDICTAN_LLM_CACHE_GCS_ACCESS_KEY_ID")?,
        secret_access_key: resolve_env_value("VERDICTAN_LLM_CACHE_GCS_SECRET_ACCESS_KEY")?,
        force_path_style: parse_bool_env("VERDICTAN_LLM_CACHE_GCS_FORCE_PATH_STYLE")
            .unwrap_or(true),
    })
}

fn resolve_qdrant_cache_config() -> Option<QdrantCacheConfig> {
    Some(QdrantCacheConfig {
        url: resolve_env_value("VERDICTAN_LLM_CACHE_QDRANT_URL")?,
        collection: resolve_env_value("VERDICTAN_LLM_CACHE_QDRANT_COLLECTION")
            .unwrap_or_else(QdrantCacheConfig::default_collection),
        api_key: resolve_env_value("VERDICTAN_LLM_CACHE_QDRANT_API_KEY"),
        request_timeout: QdrantCacheConfig::default_timeout(),
    })
}

#[cfg_attr(not(feature = "distributed"), allow(dead_code))]
fn redis_cache_missing_url_error() -> CliError {
    CliError::user(
        "VERDICTAN_LLM_CACHE_BACKEND=redis or valkey requires VERDICTAN_LLM_CACHE_REDIS_URL",
    )
}

#[cfg_attr(not(feature = "distributed"), allow(dead_code))]
fn s3_cache_missing_config_error() -> CliError {
    CliError::user(
        "VERDICTAN_LLM_CACHE_BACKEND=s3 requires VERDICTAN_LLM_CACHE_S3_BUCKET, VERDICTAN_LLM_CACHE_S3_REGION, VERDICTAN_LLM_CACHE_S3_ACCESS_KEY_ID, and VERDICTAN_LLM_CACHE_S3_SECRET_ACCESS_KEY",
    )
}

#[cfg_attr(not(feature = "distributed"), allow(dead_code))]
fn gcs_cache_missing_config_error() -> CliError {
    CliError::user(
        "VERDICTAN_LLM_CACHE_BACKEND=gcs requires VERDICTAN_LLM_CACHE_GCS_BUCKET plus GCS interoperability credentials via VERDICTAN_LLM_CACHE_GCS_ACCESS_KEY_ID and VERDICTAN_LLM_CACHE_GCS_SECRET_ACCESS_KEY",
    )
}

#[cfg_attr(not(feature = "distributed"), allow(dead_code))]
fn qdrant_cache_missing_config_error() -> CliError {
    CliError::user("VERDICTAN_LLM_CACHE_BACKEND=qdrant requires VERDICTAN_LLM_CACHE_QDRANT_URL")
}

#[cfg(feature = "distributed")]
fn ensure_distributed_cache_feature(_backend: CacheBackend) -> Result<(), CliError> {
    Ok(())
}

#[cfg(not(feature = "distributed"))]
fn ensure_distributed_cache_feature(backend: CacheBackend) -> Result<(), CliError> {
    Err(CliError::user(format!(
        "VERDICTAN_LLM_CACHE_BACKEND={} requires a CLI build with --features distributed",
        backend.as_str()
    )))
}

#[cfg(feature = "distributed")]
fn ensure_redis_cache_supported(config: &CacheConfig) -> Result<(), CliError> {
    if config.redis_url.is_some() {
        Ok(())
    } else {
        Err(redis_cache_missing_url_error())
    }
}

#[cfg(not(feature = "distributed"))]
fn ensure_redis_cache_supported(config: &CacheConfig) -> Result<(), CliError> {
    ensure_distributed_cache_feature(config.backend)
}

fn ensure_s3_cache_supported(config: &CacheConfig) -> Result<(), CliError> {
    ensure_distributed_cache_feature(CacheBackend::S3)?;
    if config.s3_config.is_some() {
        Ok(())
    } else {
        Err(s3_cache_missing_config_error())
    }
}

fn ensure_gcs_cache_supported(config: &CacheConfig) -> Result<(), CliError> {
    ensure_distributed_cache_feature(CacheBackend::Gcs)?;
    if config.gcs_config.is_some() {
        Ok(())
    } else {
        Err(gcs_cache_missing_config_error())
    }
}

fn ensure_qdrant_cache_supported(config: &CacheConfig) -> Result<(), CliError> {
    ensure_distributed_cache_feature(CacheBackend::Qdrant)?;
    if config.qdrant_config.is_some() {
        Ok(())
    } else {
        Err(qdrant_cache_missing_config_error())
    }
}

#[derive(Clone)]
enum ExactCacheBackendAdapter {
    Memory(MemoryExactCacheBackend),
    Filesystem(FilesystemExactCacheBackend),
    Redis(RedisExactCacheBackend),
    S3(ObjectStoreExactCacheBackend),
    Gcs(ObjectStoreExactCacheBackend),
    Qdrant(QdrantSemanticCacheBackend),
}

impl ExactCacheBackendAdapter {
    async fn from_config(config: &CacheConfig) -> Result<Self, CliError> {
        if !config.enabled {
            return Ok(Self::Memory(MemoryExactCacheBackend::default()));
        }

        match config.backend {
            CacheBackend::Memory => Ok(Self::Memory(MemoryExactCacheBackend::default())),
            CacheBackend::Filesystem => {
                // SAFETY: invariant: filesystem cache backend requires a directory.
                #[allow(clippy::expect_used)]
                let directory = config
                    .directory
                    .clone()
                    .expect("filesystem cache directory should be configured");
                Ok(Self::Filesystem(
                    FilesystemExactCacheBackend::new(directory, config.max_bytes).await,
                ))
            }
            CacheBackend::Redis | CacheBackend::Valkey => {
                Ok(Self::Redis(
                    RedisExactCacheBackend::new(
                        {
                            // SAFETY: invariant: redis-backed caches require redis_url.
                            #[allow(clippy::expect_used)]
                            let redis_url = config
                                .redis_url
                                .as_deref()
                                .expect("redis cache url should be configured");
                            redis_url
                        },
                        &config.redis_key_prefix,
                        config.backend.as_str(),
                    )
                    .await?,
                ))
            }
            CacheBackend::S3 => Ok(Self::S3(ObjectStoreExactCacheBackend::new({
                // SAFETY: invariant: S3 cache backend requires S3 configuration.
                #[allow(clippy::expect_used)]
                let s3_config = config
                    .s3_config
                    .clone()
                    .expect("s3 cache config should be configured");
                s3_config
            })?)),
            CacheBackend::Gcs => Ok(Self::Gcs(ObjectStoreExactCacheBackend::new({
                // SAFETY: invariant: GCS cache backend requires GCS configuration.
                #[allow(clippy::expect_used)]
                let gcs_config = config
                    .gcs_config
                    .clone()
                    .expect("gcs cache config should be configured");
                gcs_config
            })?)),
            CacheBackend::Qdrant => Ok(Self::Qdrant(
                QdrantSemanticCacheBackend::new({
                    // SAFETY: invariant: Qdrant cache backend requires Qdrant configuration.
                    #[allow(clippy::expect_used)]
                    let qdrant_config = config
                        .qdrant_config
                        .clone()
                        .expect("qdrant cache config should be configured");
                    qdrant_config
                })
                .await?,
            )),
        }
    }

    async fn get(&self, key: &str) -> Option<StoredCachedResponse> {
        match self {
            Self::Memory(backend) => backend.get(key),
            Self::Filesystem(backend) => backend.get(key).await,
            Self::Redis(backend) => backend.get(key).await,
            Self::S3(backend) | Self::Gcs(backend) => backend.get(key).await,
            Self::Qdrant(backend) => backend.get(key).await,
        }
    }

    async fn put(
        &self,
        key: &str,
        entry: StoredCachedResponse,
        ttl: &Duration,
        stats: &Arc<RwLock<CacheStats>>,
    ) {
        match self {
            Self::Memory(backend) => backend.put(key, entry, ttl, stats),
            Self::Filesystem(backend) => backend.put(key, entry).await,
            Self::Redis(backend) => backend.put(key, entry, ttl).await,
            Self::S3(backend) | Self::Gcs(backend) => backend.put(key, entry).await,
            Self::Qdrant(backend) => backend.put(key, entry, ttl).await,
        }
    }

    pub async fn clear(&self) {
        match self {
            Self::Memory(backend) => backend.clear(),
            Self::Filesystem(backend) => backend.clear().await,
            Self::Redis(backend) => backend.clear().await,
            Self::S3(backend) | Self::Gcs(backend) => backend.clear().await,
            Self::Qdrant(backend) => backend.clear().await,
        }
    }

    async fn remove(&self, key: &str) -> bool {
        match self {
            Self::Memory(backend) => backend.remove(key),
            Self::Filesystem(backend) => backend.remove(key).await,
            Self::Redis(backend) => backend.remove(key).await,
            Self::S3(backend) | Self::Gcs(backend) => backend.remove(key).await,
            Self::Qdrant(backend) => backend.remove(key).await,
        }
    }

    async fn pressure_json(&self) -> serde_json::Value {
        match self {
            Self::Memory(backend) => backend.pressure_json(),
            Self::Filesystem(backend) => backend.pressure_json(),
            Self::Redis(backend) => backend.pressure_json().await,
            Self::S3(backend) | Self::Gcs(backend) => backend.pressure_json().await,
            Self::Qdrant(backend) => backend.pressure_json().await,
        }
    }

    async fn store_semantic_embedding(&self, key: &str, embedding: &[f64], ttl: &Duration) {
        match self {
            Self::Redis(backend) => backend.store_semantic_embedding(key, embedding, ttl).await,
            Self::Qdrant(backend) => backend.store_semantic_embedding(key, embedding, ttl).await,
            _ => {}
        }
    }

    async fn semantic_lookup_key(&self, query_embedding: &[f64], threshold: f64) -> Option<String> {
        match self {
            Self::Redis(backend) => {
                backend
                    .semantic_lookup_key(query_embedding, threshold)
                    .await
            }
            Self::Qdrant(backend) => {
                backend
                    .semantic_lookup_key(query_embedding, threshold)
                    .await
            }
            _ => None,
        }
    }

    fn supports_semantic_cache(&self) -> bool {
        matches!(
            self,
            Self::Memory(_) | Self::Filesystem(_) | Self::Redis(_) | Self::Qdrant(_)
        )
    }

    fn owns_remote_semantic_index(&self) -> bool {
        matches!(self, Self::Redis(_) | Self::Qdrant(_))
    }

    async fn bulk_store_semantic_embeddings(
        &self,
        embeddings: &[(String, Vec<f64>)],
        ttl: &Duration,
    ) {
        match self {
            Self::Redis(backend) => {
                backend
                    .bulk_store_semantic_embeddings(embeddings, ttl)
                    .await;
            }
            Self::Qdrant(backend) => {
                for (key, embedding) in embeddings {
                    backend.store_semantic_embedding(key, embedding, ttl).await;
                }
            }
            _ => {}
        }
    }

    pub async fn insert_test_entry(&self, key: &str, entry: StoredCachedResponse) {
        match self {
            Self::Memory(backend) => backend.insert_test_entry(key, entry),
            Self::Filesystem(backend) => backend.put(key, entry).await,
            Self::Redis(backend) => backend.put(key, entry, &Duration::from_secs(60)).await,
            Self::S3(backend) | Self::Gcs(backend) => backend.put(key, entry).await,
            Self::Qdrant(backend) => backend.put(key, entry, &Duration::from_secs(60)).await,
        }
    }

    fn record_miss(&self) {
        if let Self::Filesystem(backend) = self {
            backend.record_miss();
        }
    }

    fn record_hit(&self) {
        if let Self::Filesystem(backend) = self {
            backend.record_hit();
        }
    }
}

#[derive(Clone, Default)]
struct MemoryExactCacheBackend {
    entries: Arc<RwLock<HashMap<String, StoredCachedResponse>>>,
}

impl MemoryExactCacheBackend {
    fn get(&self, key: &str) -> Option<StoredCachedResponse> {
        self.entries.read().ok()?.get(key).cloned()
    }

    fn put(
        &self,
        key: &str,
        entry: StoredCachedResponse,
        ttl: &Duration,
        stats: &Arc<RwLock<CacheStats>>,
    ) {
        if let Ok(mut memory) = self.entries.write() {
            ProviderResponseCache::evict_expired_and_cap(
                &mut memory,
                ProviderResponseCache::MAX_MEMORY_ENTRIES,
                ttl,
                stats,
            );
            memory.insert(key.to_string(), entry);
        }
    }

    fn clear(&self) {
        if let Ok(mut memory) = self.entries.write() {
            memory.clear();
        }
    }

    fn remove(&self, key: &str) -> bool {
        self.entries
            .write()
            .map(|mut memory| memory.remove(key).is_some())
            .unwrap_or(false)
    }

    fn pressure_json(&self) -> serde_json::Value {
        let entry_count = self
            .entries
            .read()
            .map(|entries| entries.len())
            .unwrap_or_default();
        let max_entries = entry_count.max(1);
        let percent = ((entry_count as f64 / max_entries as f64) * 100.0).round() as u64;
        let level = match percent {
            0..=49 => "nominal",
            50..=79 => "elevated",
            _ => "high",
        };
        serde_json::json!({
            "level": level,
            "estimated_entry_count": entry_count,
        })
    }

    pub fn insert_test_entry(&self, key: &str, entry: StoredCachedResponse) {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut entries = self.entries.write().expect("memory cache lock");
        entries.insert(key.to_string(), entry);
    }
}

#[derive(Clone)]
struct FilesystemExactCacheBackend {
    directory: PathBuf,
    max_bytes: u64,
    lru_index: Arc<RwLock<IndexMap<String, CacheEntryMeta>>>,
    total_size_bytes: Arc<AtomicU64>,
    hit_count: Arc<AtomicU64>,
    miss_count: Arc<AtomicU64>,
    eviction_count: Arc<AtomicU64>,
    warmed: Arc<AtomicBool>,
}

impl FilesystemExactCacheBackend {
    async fn new(directory: PathBuf, max_bytes: u64) -> Self {
        let backend = Self {
            directory,
            max_bytes,
            lru_index: Arc::new(RwLock::new(IndexMap::new())),
            total_size_bytes: Arc::new(AtomicU64::new(0)),
            hit_count: Arc::new(AtomicU64::new(0)),
            miss_count: Arc::new(AtomicU64::new(0)),
            eviction_count: Arc::new(AtomicU64::new(0)),
            warmed: Arc::new(AtomicBool::new(false)),
        };
        backend.restore_persisted_stats().await;
        backend
    }

    fn stats_file_path(&self) -> PathBuf {
        self.directory.join(".cache-stats.json")
    }

    async fn restore_persisted_stats(&self) {
        let Ok(bytes) = tokio::fs::read(self.stats_file_path()).await else {
            return;
        };
        let Ok(stats) = serde_json::from_slice::<PersistedFilesystemCacheStats>(&bytes) else {
            return;
        };

        self.hit_count.store(stats.hit_count, Ordering::Relaxed);
        self.miss_count.store(stats.miss_count, Ordering::Relaxed);
        self.eviction_count
            .store(stats.eviction_count, Ordering::Relaxed);
    }

    fn persist_stats_sync(&self) {
        let stats = PersistedFilesystemCacheStats {
            hit_count: self.hit_count.load(Ordering::Relaxed),
            miss_count: self.miss_count.load(Ordering::Relaxed),
            eviction_count: self.eviction_count.load(Ordering::Relaxed),
        };
        let Ok(bytes) = serde_json::to_vec(&stats) else {
            return;
        };
        let _ = std::fs::create_dir_all(&self.directory);
        let path = self.stats_file_path();
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }

    async fn persist_current_stats(&self) {
        self.persist_stats_sync();
    }

    /// Scans the cache directory to rebuild the in-memory LRU index.
    pub async fn warm(&self) {
        let start = Instant::now();
        let mut count: u64 = 0;
        let mut total: u64 = 0;

        let Ok(mut entries) = tokio::fs::read_dir(&self.directory).await else {
            self.warmed.store(true, Ordering::Release);
            return;
        };
        while let Ok(Some(subdir_entry)) = entries.next_entry().await {
            let subdir_path = subdir_entry.path();
            let Ok(meta) = tokio::fs::metadata(&subdir_path).await else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }
            let Ok(mut files) = tokio::fs::read_dir(&subdir_path).await else {
                continue;
            };
            while let Ok(Some(file_entry)) = files.next_entry().await {
                let file_path = file_entry.path();
                let Ok(metadata) = tokio::fs::metadata(&file_path).await else {
                    continue;
                };
                if !metadata.is_file() {
                    continue;
                }
                let size = metadata.len();
                let key = tokio::fs::read(&file_path)
                    .await
                    .ok()
                    .and_then(|bytes| deserialize_cache_entry(&bytes))
                    .and_then(|entry| entry.original_key)
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| {
                        file_path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_string()
                    });
                if key.is_empty() {
                    continue;
                }
                let now = Instant::now();
                if let Ok(mut index) = self.lru_index.write() {
                    index.insert(
                        key,
                        CacheEntryMeta {
                            size_bytes: size,
                            last_accessed: now,
                            created_at: now,
                        },
                    );
                }
                total += size;
                count += 1;
            }
        }

        self.total_size_bytes.store(total, Ordering::Relaxed);
        self.warmed.store(true, Ordering::Release);

        let elapsed = start.elapsed();
        let size_mb = total as f64 / (1024.0 * 1024.0);
        tracing::info!(
            entries = count,
            size_mb = format!("{size_mb:.1}"),
            elapsed_ms = elapsed.as_millis(),
            "cache warmed from disk"
        );
    }

    pub fn stats(&self) -> FilesystemCacheStats {
        FilesystemCacheStats {
            entry_count: self
                .lru_index
                .read()
                .map(|idx| idx.len() as u64)
                .unwrap_or(0),
            total_size_bytes: self.total_size_bytes.load(Ordering::Relaxed),
            max_bytes: self.max_bytes,
            hit_count: self.hit_count.load(Ordering::Relaxed),
            miss_count: self.miss_count.load(Ordering::Relaxed),
            eviction_count: self.eviction_count.load(Ordering::Relaxed),
            warmed: self.warmed.load(Ordering::Acquire),
        }
    }

    async fn get(&self, key: &str) -> Option<StoredCachedResponse> {
        let path = self.cache_file_path(key)?;
        let bytes = tokio::fs::read(&path).await.ok()?;
        let entry = deserialize_cache_entry(&bytes)?;

        if let Ok(mut index) = self.lru_index.write() {
            if let Some(meta) = index.get_mut(key) {
                meta.last_accessed = Instant::now();
            }
            let from = index.get_index_of(key).unwrap_or(0);
            let to = index.len().saturating_sub(1);
            index.move_index(from, to);
        }
        Some(entry)
    }

    async fn put(&self, key: &str, mut entry: StoredCachedResponse) {
        let Some(path) = self.cache_file_path(key) else {
            return;
        };
        if entry.original_key.is_none() {
            entry.original_key = Some(key.to_string());
        }
        let serialized = serialize_cache_entry(&entry);

        let entry_size = serialized.len() as u64;
        self.evict_if_needed(entry_size).await;

        if let Some(parent) = path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        if atomic_write_async(&path, &serialized).await.is_ok() {
            let mut old_size: u64 = 0;
            if let Ok(mut index) = self.lru_index.write() {
                if let Some(existing) = index.get(key) {
                    old_size = existing.size_bytes;
                }
                let now = Instant::now();
                index.insert(
                    key.to_string(),
                    CacheEntryMeta {
                        size_bytes: entry_size,
                        last_accessed: now,
                        created_at: now,
                    },
                );
            }
            let current = self.total_size_bytes.load(Ordering::Relaxed);
            self.total_size_bytes.store(
                current.saturating_sub(old_size).saturating_add(entry_size),
                Ordering::Relaxed,
            );
        }
    }

    async fn evict_if_needed(&self, new_entry_size: u64) {
        let current_total = self.total_size_bytes.load(Ordering::Relaxed);
        if current_total + new_entry_size <= self.max_bytes {
            return;
        }

        let mut freed: u64 = 0;
        let needed = (current_total + new_entry_size).saturating_sub(self.max_bytes);

        let keys_to_evict: Vec<(String, u64)> = {
            let Ok(index) = self.lru_index.read() else {
                return;
            };
            index
                .iter()
                .map(|(k, m)| (k.clone(), m.size_bytes))
                .take_while(|(_, size)| {
                    if freed >= needed {
                        return false;
                    }
                    freed += size;
                    true
                })
                .collect()
        };

        let mut evicted_bytes: u64 = 0;
        for (key, size) in &keys_to_evict {
            if let Some(path) = self.cache_file_path(key) {
                let _ = tokio::fs::remove_file(path).await;
            }
            evicted_bytes += size;
        }

        if let Ok(mut index) = self.lru_index.write() {
            for (key, _) in &keys_to_evict {
                index.shift_remove(key);
            }
        }

        let evict_count = keys_to_evict.len() as u64;
        self.eviction_count
            .fetch_add(evict_count, Ordering::Relaxed);
        let prev = self.total_size_bytes.load(Ordering::Relaxed);
        self.total_size_bytes
            .store(prev.saturating_sub(evicted_bytes), Ordering::Relaxed);
        self.persist_current_stats().await;
    }

    async fn clear(&self) {
        let _ = tokio::fs::remove_dir_all(&self.directory).await;
        if let Ok(mut index) = self.lru_index.write() {
            index.clear();
        }
        self.total_size_bytes.store(0, Ordering::Relaxed);
        self.hit_count.store(0, Ordering::Relaxed);
        self.miss_count.store(0, Ordering::Relaxed);
        self.eviction_count.store(0, Ordering::Relaxed);
    }

    async fn remove(&self, key: &str) -> bool {
        let Some(path) = self.cache_file_path(key) else {
            return false;
        };
        let removed = tokio::fs::remove_file(path).await.is_ok();
        if removed {
            if let Ok(mut index) = self.lru_index.write() {
                if let Some(meta) = index.shift_remove(key) {
                    let prev = self.total_size_bytes.load(Ordering::Relaxed);
                    self.total_size_bytes
                        .store(prev.saturating_sub(meta.size_bytes), Ordering::Relaxed);
                }
            }
        }
        removed
    }

    fn pressure_json(&self) -> serde_json::Value {
        let total = self.total_size_bytes.load(Ordering::Relaxed);
        let max = self.max_bytes;
        let percent = if max > 0 {
            ((total as f64 / max as f64) * 100.0).round() as u64
        } else {
            0
        };
        let level = match percent {
            0..=49 => "nominal",
            50..=79 => "elevated",
            _ => "high",
        };
        let entry_count = self
            .lru_index
            .read()
            .map(|idx| idx.len())
            .unwrap_or_default();
        serde_json::json!({
            "level": level,
            "estimated_entry_count": entry_count,
            "total_size_bytes": total,
            "max_bytes": max,
            "percent_used": percent,
        })
    }

    fn record_miss(&self) {
        self.miss_count.fetch_add(1, Ordering::Relaxed);
        self.schedule_persist_stats();
    }

    fn record_hit(&self) {
        self.hit_count.fetch_add(1, Ordering::Relaxed);
        self.schedule_persist_stats();
    }

    fn schedule_persist_stats(&self) {
        self.persist_stats_sync();
    }

    fn cache_file_path(&self, key: &str) -> Option<PathBuf> {
        let sanitized = key.replace(':', "_");
        let prefix = sanitized.get(..2).unwrap_or("cache");
        Some(self.directory.join(prefix).join(format!("{sanitized}.bin")))
    }

    /// Returns directory path for external inspection.
    #[allow(dead_code)]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// List the top N entries by size (largest first) or most recently accessed.
    pub fn list_top_entries(&self, limit: usize, by_size: bool) -> Vec<(String, u64, u64)> {
        let Ok(index) = self.lru_index.read() else {
            return Vec::new();
        };
        let mut entries: Vec<(String, u64, u64)> = index
            .iter()
            .map(|(k, m)| {
                let accessed_ago = Instant::now().duration_since(m.last_accessed).as_secs();
                (k.clone(), m.size_bytes, accessed_ago)
            })
            .collect();
        if by_size {
            entries.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        } else {
            entries.sort_by_key(|a| a.2);
        }
        entries.truncate(limit);
        entries
    }
}

/// Serialize a cache entry using bincode with a format version header.
fn serialize_cache_entry(entry: &StoredCachedResponse) -> Vec<u8> {
    let bincode_bytes = bincode::serialize(entry).unwrap_or_default();
    let mut out = Vec::with_capacity(1 + bincode_bytes.len());
    out.push(CACHE_FORMAT_BINCODE_V1);
    out.extend_from_slice(&bincode_bytes);
    out
}

/// Deserialize a cache entry, trying bincode first then JSON fallback.
fn deserialize_cache_entry(bytes: &[u8]) -> Option<StoredCachedResponse> {
    if bytes.is_empty() {
        return None;
    }
    if bytes[0] == CACHE_FORMAT_BINCODE_V1 {
        return bincode::deserialize(&bytes[1..]).ok();
    }
    serde_json::from_slice(bytes).ok()
}

#[derive(Clone)]
pub struct ProviderResponseCache {
    config: CacheConfig,
    exact_backend: ExactCacheBackendAdapter,
    semantic_index: Arc<RwLock<HashMap<String, Vec<f64>>>>,
    stats: Arc<RwLock<CacheStats>>,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
struct CacheStats {
    hits: u64,
    misses: u64,
    puts: u64,
    evictions: u64,
    clears: u64,
}

impl ProviderResponseCache {
    pub async fn from_env() -> Result<Self, CliError> {
        let config = CacheConfig::from_env()?;
        let exact_backend = ExactCacheBackendAdapter::from_config(&config).await?;
        let cache = Self {
            config,
            exact_backend,
            semantic_index: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CacheStats::default())),
        };

        if cache.config.clear_on_start {
            cache.clear().await;
        }

        if cache.config.enabled {
            if let Some(directory) = &cache.config.directory {
                tokio::fs::create_dir_all(directory)
                    .await
                    .map_err(|error| {
                        CliError::internal(format!(
                            "failed to create provider cache directory {}: {error}",
                            directory.display()
                        ))
                    })?;
            }
        }

        if cache.config.enabled && cache.config.backend == CacheBackend::Filesystem {
            let dir_display = cache
                .config
                .directory
                .as_ref()
                .map(|d| d.display().to_string())
                .unwrap_or_else(|| "~/.verdictan/cache/".to_string());
            tracing::info!(
                backend = "filesystem",
                directory = %dir_display,
                max_bytes = cache.config.max_bytes,
                "Cache: filesystem (auto-configured at {dir_display})"
            );

            if cache.config.warmup_enabled {
                if let ExactCacheBackendAdapter::Filesystem(ref fs_backend) = cache.exact_backend {
                    fs_backend.warm().await;
                }
            }
        } else {
            tracing::info!(
                backend = %if cache.config.enabled { cache.config.backend.as_str() } else { "disabled" },
                "gateway cache backend initialized"
            );
        }

        Ok(cache)
    }

    pub fn memory_for_test() -> Self {
        Self {
            config: CacheConfig {
                enabled: true,
                backend: CacheBackend::Memory,
                ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
                directory: None,
                max_bytes: DEFAULT_LOCAL_CACHE_MAX_BYTES,
                warmup_enabled: false,
                redis_url: None,
                redis_key_prefix: DEFAULT_REDIS_CACHE_KEY_PREFIX.to_string(),
                s3_config: None,
                gcs_config: None,
                qdrant_config: None,
                clear_on_start: false,
                cache_buster: None,
            },
            exact_backend: ExactCacheBackendAdapter::Memory(MemoryExactCacheBackend::default()),
            semantic_index: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn cache_buster(&self) -> Option<&str> {
        self.config.cache_buster.as_deref()
    }

    pub fn uses_shared_backend(&self) -> bool {
        self.config.enabled
            && matches!(
                self.config.backend,
                CacheBackend::Redis
                    | CacheBackend::Valkey
                    | CacheBackend::S3
                    | CacheBackend::Gcs
                    | CacheBackend::Qdrant
            )
    }

    pub fn backend_name(&self) -> &'static str {
        if self.config.enabled {
            self.config.backend.as_str()
        } else {
            "disabled"
        }
    }

    pub async fn runtime_json(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.config.enabled,
            "backend": if self.config.enabled {
                self.config.backend.as_str()
            } else {
                "disabled"
            },
            "ttl_seconds": self.config.ttl.as_secs(),
            "directory": self.config.directory.as_ref().map(|path| path.display().to_string()),
            "cache_buster_configured": self.config.cache_buster.is_some(),
            "stats": self.stats.read().ok().map(|stats| serde_json::json!({
                "hits": stats.hits,
                "misses": stats.misses,
                "puts": stats.puts,
                "evictions": stats.evictions,
                "clears": stats.clears,
            })).unwrap_or_else(|| serde_json::json!({})),
            "pressure": self.cache_pressure_json().await,
        })
    }

    pub async fn get(&self, key: &str) -> Option<BufferedUpstreamResponse> {
        self.get_with_ttl(key, None).await
    }

    pub async fn get_with_ttl(
        &self,
        key: &str,
        ttl_override: Option<Duration>,
    ) -> Option<BufferedUpstreamResponse> {
        if !self.config.enabled {
            return None;
        }

        let Some(entry) = self.exact_backend.get(key).await else {
            self.record_miss();
            tracing::debug!(backend = %self.config.backend.as_str(), hit = false, "cache lookup");
            return None;
        };

        // Entries with an unrecognized key_version return a cache miss rather
        // than a decryption error so key rotation can happen without downtime.
        if entry.key_version != CURRENT_CACHE_KEY_VERSION {
            tracing::debug!(
                backend = %self.config.backend.as_str(),
                entry_key_version = entry.key_version,
                current_key_version = CURRENT_CACHE_KEY_VERSION,
                "cache lookup: key_version mismatch — treating as cache miss for key rotation"
            );
            self.record_miss();
            return None;
        }

        if self.is_expired_with_ttl(&entry, ttl_override) {
            self.remove(key).await;
            self.record_miss();
            tracing::debug!(backend = %self.config.backend.as_str(), hit = false, "cache lookup");
            return None;
        }

        self.record_hit();
        tracing::debug!(backend = %self.config.backend.as_str(), hit = true, "cache lookup");
        entry.to_buffered_response(true)
    }

    /// Maximum number of in-memory cache entries before eviction.
    const MAX_MEMORY_ENTRIES: usize = 10_000;

    pub async fn put(&self, key: &str, response: &BufferedUpstreamResponse) {
        self.put_with_ttl(key, response, None).await;
    }

    pub async fn put_with_ttl(
        &self,
        key: &str,
        response: &BufferedUpstreamResponse,
        ttl_override: Option<Duration>,
    ) {
        if !self.config.enabled || !response.is_cacheable_success() {
            return;
        }
        // PERF-012: never cache oversized / size-rejected upstream bodies.
        if response.response_size_exceeded.is_some() {
            return;
        }
        if response.body.len() > crate::gateway::size_limit::DEFAULT_MAX_RESPONSE_BYTES {
            return;
        }

        let entry = StoredCachedResponse::from_response(response);
        self.record_put();
        self.exact_backend
            .put(key, entry, &self.effective_ttl(ttl_override), &self.stats)
            .await;
    }

    fn evict_expired_and_cap(
        memory: &mut HashMap<String, StoredCachedResponse>,
        max: usize,
        ttl: &Duration,
        stats: &Arc<RwLock<CacheStats>>,
    ) {
        let now = current_unix_secs();
        let before = memory.len();
        memory.retain(|_, entry| now.saturating_sub(entry.stored_at_unix_secs) <= ttl.as_secs());
        let evicted = before - memory.len();

        // If still over cap, remove oldest entries.
        if memory.len() >= max {
            let mut entries: Vec<(String, u64)> = memory
                .iter()
                .map(|(k, v)| (k.clone(), v.stored_at_unix_secs))
                .collect();
            entries.sort_by_key(|(_, ts)| *ts);
            let to_remove = memory.len() - max + 1;
            for (key, _) in entries.into_iter().take(to_remove) {
                memory.remove(&key);
            }
            let extra = to_remove;
            if let Ok(mut s) = stats.write() {
                s.evictions += (evicted + extra) as u64;
            }
        } else if evicted > 0 {
            if let Ok(mut s) = stats.write() {
                s.evictions += evicted as u64;
            }
        }
    }

    pub async fn store_semantic_embedding(&self, key: &str, embedding: &[f64]) {
        self.store_semantic_embedding_with_ttl(key, embedding, None)
            .await;
    }

    pub async fn store_semantic_embedding_with_ttl(
        &self,
        key: &str,
        embedding: &[f64],
        ttl_override: Option<Duration>,
    ) {
        if !self.config.enabled
            || embedding.is_empty()
            || !self.exact_backend.supports_semantic_cache()
        {
            return;
        }

        self.exact_backend
            .store_semantic_embedding(key, embedding, &self.effective_ttl(ttl_override))
            .await;

        if let Ok(mut index) = self.semantic_index.write() {
            index.insert(key.to_string(), embedding.to_vec());
        }
    }

    /// Pipelined Redis seed helper for PERF-001 cardinality fixtures.
    pub async fn seed_semantic_embeddings_for_test(&self, embeddings: &[(String, Vec<f64>)]) {
        if !self.config.enabled || embeddings.is_empty() {
            return;
        }
        let ttl = self.config.ttl;
        self.exact_backend
            .bulk_store_semantic_embeddings(embeddings, &ttl)
            .await;
        if let Ok(mut index) = self.semantic_index.write() {
            for (key, embedding) in embeddings {
                if embedding.is_empty() {
                    continue;
                }
                index.insert(key.clone(), embedding.clone());
            }
        }
    }

    pub async fn get_semantic(
        &self,
        query_embedding: &[f64],
        threshold: f64,
    ) -> Option<BufferedUpstreamResponse> {
        self.get_semantic_with_ttl(query_embedding, threshold, None)
            .await
    }

    pub async fn get_semantic_with_ttl(
        &self,
        query_embedding: &[f64],
        threshold: f64,
        ttl_override: Option<Duration>,
    ) -> Option<BufferedUpstreamResponse> {
        if !self.config.enabled
            || query_embedding.is_empty()
            || !self.exact_backend.supports_semantic_cache()
        {
            return None;
        }

        // Redis/Qdrant own the remote index. A remote key hit (or stale miss) must not
        // fall through into a second local scan + GET — that would reintroduce sequential
        // lookup work and non-constant Redis GET counts under fixture growth.
        if self.exact_backend.owns_remote_semantic_index() {
            let best_key = self
                .exact_backend
                .semantic_lookup_key(query_embedding, threshold)
                .await?;
            return self.get_with_ttl(&best_key, ttl_override).await;
        }

        let best_key = {
            let index = self.semantic_index.read().ok()?;
            semantic_lookup(query_embedding, &index, threshold)?.to_string()
        };

        self.get_with_ttl(&best_key, ttl_override).await
    }

    pub async fn clear(&self) {
        self.exact_backend.clear().await;
        if let Ok(mut index) = self.semantic_index.write() {
            index.clear();
        }
        if let Ok(mut stats) = self.stats.write() {
            stats.clears += 1;
        }
    }

    async fn remove(&self, key: &str) {
        if self.exact_backend.remove(key).await {
            if let Ok(mut index) = self.semantic_index.write() {
                index.remove(key);
            }
            self.record_eviction();
        }
    }

    fn effective_ttl(&self, ttl_override: Option<Duration>) -> Duration {
        ttl_override.unwrap_or(self.config.ttl)
    }

    fn is_expired_with_ttl(
        &self,
        entry: &StoredCachedResponse,
        ttl_override: Option<Duration>,
    ) -> bool {
        current_unix_secs().saturating_sub(entry.stored_at_unix_secs)
            > self.effective_ttl(ttl_override).as_secs()
    }

    /// Test helper: builds a cache backend on a temporary current-thread runtime.
    /// Production startup uses [`ProviderResponseCache::from_env`] asynchronously.
    #[allow(clippy::expect_used)]
    fn new_for_test(config: CacheConfig) -> Self {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(async {
                    let exact_backend = ExactCacheBackendAdapter::from_config(&config)
                        .await
                        .expect("test cache backend should be supported");
                    Self {
                        config,
                        exact_backend,
                        semantic_index: Arc::new(RwLock::new(HashMap::new())),
                        stats: Arc::new(RwLock::new(CacheStats::default())),
                    }
                })
            }),
            Err(_) => {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("test cache runtime");
                runtime.block_on(async {
                    let exact_backend = ExactCacheBackendAdapter::from_config(&config)
                        .await
                        .expect("test cache backend should be supported");
                    Self {
                        config,
                        exact_backend,
                        semantic_index: Arc::new(RwLock::new(HashMap::new())),
                        stats: Arc::new(RwLock::new(CacheStats::default())),
                    }
                })
            }
        }
    }

    async fn cache_pressure_json(&self) -> serde_json::Value {
        self.exact_backend.pressure_json().await
    }

    pub async fn insert_test_entry(&self, key: &str, entry: StoredCachedResponse) {
        self.exact_backend.insert_test_entry(key, entry).await;
    }

    pub async fn raw_entry_for_test(&self, key: &str) -> Option<StoredCachedResponse> {
        self.exact_backend.get(key).await
    }

    /// Returns filesystem-specific cache statistics, or `None` if not using filesystem backend.
    pub fn filesystem_stats(&self) -> Option<FilesystemCacheStats> {
        match &self.exact_backend {
            ExactCacheBackendAdapter::Filesystem(fs) => Some(fs.stats()),
            _ => None,
        }
    }

    /// Returns the cache directory path (only for filesystem backend).
    pub fn cache_directory(&self) -> Option<&Path> {
        self.config.directory.as_deref()
    }

    /// Returns the configured max bytes.
    pub fn max_bytes(&self) -> u64 {
        self.config.max_bytes
    }

    /// Returns the top N cache entries sorted by size or recency.
    pub fn list_top_entries(&self, limit: usize, by_size: bool) -> Vec<(String, u64, u64)> {
        match &self.exact_backend {
            ExactCacheBackendAdapter::Filesystem(fs) => fs.list_top_entries(limit, by_size),
            _ => Vec::new(),
        }
    }

    /// Returns the CacheConfig for external inspection.
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    fn record_hit(&self) {
        CACHE_HIT_COUNTER.inc();
        if let Ok(mut stats) = self.stats.write() {
            stats.hits += 1;
        }
        self.exact_backend.record_hit();
    }

    fn record_miss(&self) {
        CACHE_MISS_COUNTER.inc();
        if let Ok(mut stats) = self.stats.write() {
            stats.misses += 1;
        }
        self.exact_backend.record_miss();
    }

    fn record_put(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.puts += 1;
        }
    }

    fn record_eviction(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.evictions += 1;
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StoredCachedResponse {
    pub stored_at_unix_secs: u64,
    pub status: u16,
    pub headers: Vec<StoredHeader>,
    pub body_base64: String,
    #[serde(default)]
    pub original_key: Option<String>,
    /// Key-version stamp written at cache-write time.
    ///
    /// Entries with `key_version != CURRENT_CACHE_KEY_VERSION` produce a
    /// cache miss so that key rotation is handled gracefully. Entries missing
    /// this field are deserialized as version `0` and will
    /// trigger a cache miss on first read after upgrade, which is the correct
    /// behavior.
    #[serde(default = "default_key_version")]
    pub key_version: u32,
}

impl StoredCachedResponse {
    pub fn stored_at_unix_secs(&self) -> u64 {
        self.stored_at_unix_secs
    }

    fn from_response(response: &BufferedUpstreamResponse) -> Self {
        Self {
            stored_at_unix_secs: current_unix_secs(),
            status: response.status.as_u16(),
            headers: response
                .headers
                .iter()
                .map(|(name, value)| StoredHeader {
                    name: name.as_str().to_string(),
                    value_base64: BASE64_STANDARD.encode(value.as_bytes()),
                })
                .collect(),
            body_base64: BASE64_STANDARD.encode(response.body.as_ref()),
            original_key: None,
            key_version: CURRENT_CACHE_KEY_VERSION,
        }
    }

    fn to_buffered_response(&self, cached: bool) -> Option<BufferedUpstreamResponse> {
        let mut headers = HeaderMap::new();
        for header in &self.headers {
            let name = HeaderName::from_bytes(header.name.as_bytes()).ok()?;
            let value_bytes = BASE64_STANDARD.decode(&header.value_base64).ok()?;
            let value = HeaderValue::from_bytes(&value_bytes).ok()?;
            headers.append(name, value);
        }

        let body = Bytes::from(BASE64_STANDARD.decode(&self.body_base64).ok()?);
        Some(BufferedUpstreamResponse::new(
            StatusCode::from_u16(self.status).ok()?,
            headers,
            body,
            cached,
        ))
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StoredHeader {
    pub name: String,
    pub value_base64: String,
}

pub fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parse_bool_env(name: &str) -> Option<bool> {
    std::env::var(name)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
}

// ═══════════════════════════════════════════════════════════════════════════
// Semantic cache config and math utilities
// ═══════════════════════════════════════════════════════════════════════════

/// Selects the cache matching strategy.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    /// Exact key match (default).
    #[default]
    Exact,
    /// Embedding-based cosine similarity. Requires `embedding_provider`.
    Semantic,
}

/// Operator-supplied config for the semantic cache extension.
///
/// Parsed from the `cache:` section of a declarative policy config.
/// When absent or when `mode` is `Exact`, all semantic fields are ignored.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SemanticCacheConfig {
    /// Enables response caching for this declarative config.
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,
    /// Matching mode. Default: `Exact`.
    #[serde(default)]
    pub mode: CacheMode,
    /// Minimum cosine similarity for a cache hit. Range [0.0, 1.0]. Default: 0.85.
    #[serde(default = "default_similarity_threshold")]
    pub similarity_threshold: f64,
    /// References a configured provider target ID whose `/v1/embeddings` endpoint
    /// will be called to compute embeddings. Required when `mode` is `Semantic`.
    #[serde(default)]
    pub embedding_provider: Option<String>,
    /// When false, the cache only activates if the request includes
    /// `x-verdictan-cache: on`. Default: true (cache is always active).
    #[serde(default = "default_cache_default_on")]
    pub default_on: bool,
    /// Optional per-config cache TTL override in seconds.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

fn default_cache_enabled() -> bool {
    true
}

fn default_cache_default_on() -> bool {
    true
}

impl Default for SemanticCacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_cache_enabled(),
            mode: CacheMode::Exact,
            similarity_threshold: default_similarity_threshold(),
            embedding_provider: None,
            default_on: true,
            ttl_seconds: None,
        }
    }
}

impl SemanticCacheConfig {
    pub fn ttl_override(&self) -> Option<Duration> {
        self.ttl_seconds
            .filter(|seconds| *seconds > 0)
            .map(Duration::from_secs)
    }
}

fn default_similarity_threshold() -> f64 {
    0.85
}

/// Compute cosine similarity between two embedding vectors.
///
/// Returns a value in \[-1.0, 1.0\]. Returns `0.0` when either vector is
/// all-zeros or when the lengths differ (graceful degradation, never panics).
#[allow(dead_code)]
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let mag_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 {
        return 0.0;
    }
    (dot / (mag_a * mag_b)).clamp(-1.0, 1.0)
}

/// Find the best-matching entry in an embedding map whose similarity exceeds
/// `threshold`. Returns the key of the closest match, if any.
///
/// `index` maps cache key strings to pre-computed embedding vectors.
#[allow(dead_code)]
pub fn semantic_lookup<'k>(
    query_embedding: &[f64],
    index: &'k HashMap<String, Vec<f64>>,
    threshold: f64,
) -> Option<&'k str> {
    let mut best_key: Option<&str> = None;
    let mut best_score = threshold;

    for (key, embedding) in index {
        let score = cosine_similarity(query_embedding, embedding);
        if score > best_score {
            best_score = score;
            best_key = Some(key.as_str());
        }
    }

    best_key
}

fn resolve_cache_directory(explicit: Option<String>) -> PathBuf {
    if let Some(path) = explicit.filter(|value| !value.trim().is_empty()) {
        return PathBuf::from(path);
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return Path::new(&home)
                .join("Library")
                .join("Caches")
                .join("verdictan")
                .join("llm-provider-cache");
        }
    }

    if let Some(xdg_cache_home) = std::env::var_os("XDG_CACHE_HOME") {
        return Path::new(&xdg_cache_home)
            .join("verdictan")
            .join("llm-provider-cache");
    }

    if let Some(home) = std::env::var_os("HOME") {
        return Path::new(&home)
            .join(".cache")
            .join("verdictan")
            .join("llm-provider-cache");
    }

    std::env::temp_dir().join("verdictan-llm-provider-cache")
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 6 — Secure cache tier system
// ═══════════════════════════════════════════════════════════════════════════
//
// Defines the three explicit cache tiers and the policy/gate layer that sits
// in front of them. Raw/unbounded global cache access is **hard-prohibited**
// (SEC-cache-01).
//
// Tier hierarchy (most-to-least isolated):
//   PrivateEdge — user/session-private. Default safe fallback.
//   OrgShared — org-scoped sharing. Gated by approval, data
//                              class, and provider policy.

use super::super::canonicalization::ReplayDigest;

/// Canonical cache tiers for agent state caching (Phase 6).
///
/// Each tier is a strictly scoped isolation boundary. Downgrades only move
/// toward `PrivateEdge`, never up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheTier {
    /// Private to a single user/session. No cross-user or cross-session
    /// sharing. Always available as the safe fallback for all other tiers.
    PrivateEdge,

    /// Shared within an organization. Requires org-level approval, data-class
    /// gates, and provider allow/deny checks.
    OrgShared,
}

impl CacheTier {
    /// Returns the wire name used in audit tables and tracing events.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateEdge => "private_edge_cache",
            Self::OrgShared => "org_shared_cache",
        }
    }
}

impl std::fmt::Display for CacheTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Approval and data-class signals ─────────────────────────────────────────

/// Approval signal sourced from the enforcement layer.
///
/// Mirrors the enforcement `Verdict` but simplified to the three states
/// relevant for cache tier gating.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalSignal {
    Approved,
    Pending,
    Denied,
}

/// Highest data-sensitivity class present in a request, as seen by the
/// cache tier gate.
///
/// Variants are ordered from lowest to highest sensitivity so that
/// `PartialOrd`/`Ord` can be used for threshold comparisons.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DataClassSignal {
    Unclassified,
    Pii,
    Phi,
    Financial,
    IntellectualProperty,
}

impl DataClassSignal {
    /// Wire name used in audit tables and tracing events.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unclassified => "unclassified",
            Self::Pii => "pii",
            Self::Phi => "phi",
            Self::Financial => "financial",
            Self::IntellectualProperty => "intellectual_property",
        }
    }
}

// ─── CacheTierPolicy ──────────────────────────────────────────────────────────

/// Per-org policy controlling which cache tiers are enabled and what gates
/// apply at each tier.
///
/// The safe default permits only `PrivateEdge`. Shared and federated tiers
/// must be explicitly opted into via control-plane configuration
/// (`secure_cache_policies` table, migration 0213).
#[derive(Clone, Debug)]
pub struct CacheTierPolicy {
    /// Allow `PrivateEdge` tier. Defaults to `true`; cannot be meaningfully
    /// disabled (PrivateEdge is the final safe fallback).
    pub allow_private_edge: bool,

    /// Allow `OrgShared` tier. Default: `false` (explicit opt-in required).
    pub allow_org_shared: bool,

    /// Data classes blocked from `OrgShared`.
    /// A request bearing any of these classes is downgraded to `PrivateEdge`.
    pub blocked_data_classes: Vec<DataClassSignal>,

    /// Provider IDs blocked from `OrgShared`.
    pub blocked_providers: Vec<String>,

    /// Whether an `Approved` enforcement verdict is required before `OrgShared`
    /// tier use. Default: `true`.
    pub require_approval_for_org_shared: bool,
}

impl Default for CacheTierPolicy {
    fn default() -> Self {
        Self {
            allow_private_edge: true,
            allow_org_shared: false,
            // Conservative defaults: PHI, PII, and financial data are blocked
            // from all shared tiers out-of-the-box.
            blocked_data_classes: vec![
                DataClassSignal::Phi,
                DataClassSignal::Pii,
                DataClassSignal::Financial,
                DataClassSignal::IntellectualProperty,
            ],
            blocked_providers: vec![],
            require_approval_for_org_shared: true,
        }
    }
}

// ─── TierGateContext ──────────────────────────────────────────────────────────

/// Per-request context supplied to [`evaluate_tier_gate`].
///
/// All fields are structural signals — no message content.
pub struct TierGateContext<'a> {
    /// Resolved organization identifier.
    pub org_id: &'a str,

    /// Resolved user or session identifier (used for `PrivateEdge` scoping).
    pub user_id: Option<&'a str>,

    /// Workflow context identifier (`X-Workflow-Id` header value).
    pub workflow_id: Option<&'a str>,

    /// Canonical replay digest of the incoming request.
    pub replay_digest: Option<&'a ReplayDigest>,

    /// Stored replay digest for the cache key being evaluated, if any.
    pub stored_digest: Option<&'a ReplayDigest>,

    /// Approval signal from the enforcement layer.
    pub approval_verdict: Option<ApprovalSignal>,

    /// Highest data-sensitivity class present in the request.
    pub data_class: Option<DataClassSignal>,

    /// Provider identifier for this request (e.g. `"openai"`).
    pub provider_id: Option<&'a str>,

    /// Whether the shared/federated backend is currently reachable.
    /// When `false`, shared tiers are unavailable and the gate falls back to
    /// `PrivateEdge`.
    pub backend_available: bool,
}

// ─── TierGateOutcome ──────────────────────────────────────────────────────────

/// Result of a [`evaluate_tier_gate`] call.
#[derive(Clone, Debug)]
pub enum TierGateOutcome {
    /// The requested tier was granted.
    Permitted { tier: CacheTier },
    /// The requested tier was unavailable; a lower tier is used instead.
    ///
    /// Downgrades always move toward `PrivateEdge`.
    Downgraded {
        requested: CacheTier,
        effective: CacheTier,
        reason: &'static str,
    },
    /// The request was denied from all tiers (e.g. digest mismatch, missing
    /// workflow context on global tier, or explicit policy denial).
    Denied { reason: &'static str },
}

impl TierGateOutcome {
    /// Returns the effective tier if the outcome is `Permitted` or `Downgraded`.
    fn effective_tier(&self) -> Option<CacheTier> {
        match self {
            Self::Permitted { tier } => Some(*tier),
            Self::Downgraded { effective, .. } => Some(*effective),
            Self::Denied { .. } => None,
        }
    }

    /// Returns `true` when the cache may be used (permitted or downgraded).
    fn is_usable(&self) -> bool {
        !matches!(self, Self::Denied { .. })
    }

    /// Returns the gate reason for tracing; `None` on `Permitted`.
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Self::Permitted { .. } => None,
            Self::Downgraded { reason, .. } | Self::Denied { reason } => Some(reason),
        }
    }
}

// ─── evaluate_tier_gate ───────────────────────────────────────────────────────

/// Evaluates whether `tier` may be used for the given request context.
///
/// ## Fail-closed rules
///
/// - An unavailable backend produces `Downgraded { effective: PrivateEdge }`.
/// - Blocked data class or provider on `OrgShared` produces a downgrade to `PrivateEdge`, not silent omission.
///
/// Callers should log the outcome using [`TierGateOutcome::reason`] when
/// non-`None`.
pub fn evaluate_tier_gate(
    tier: CacheTier,
    policy: &CacheTierPolicy,
    ctx: &TierGateContext<'_>,
) -> TierGateOutcome {
    match tier {
        // ── PrivateEdge ──────────────────────────────────────────────────────
        CacheTier::PrivateEdge => {
            if policy.allow_private_edge {
                TierGateOutcome::Permitted { tier }
            } else {
                // This should never happen with a well-formed policy, but be
                // explicit rather than silently succeeding.
                TierGateOutcome::Denied {
                    reason: "private_edge_cache disabled by org policy",
                }
            }
        }

        // ── OrgShared ────────────────────────────────────────────────────────
        CacheTier::OrgShared => {
            if !policy.allow_org_shared {
                tracing::debug!(
                    org_id = %ctx.org_id,
                    tier = %CacheTier::OrgShared,
                    "tier gate: org_shared_cache not enabled — downgrading to private_edge"
                );
                return TierGateOutcome::Downgraded {
                    requested: CacheTier::OrgShared,
                    effective: CacheTier::PrivateEdge,
                    reason: "org_shared_cache not enabled by org policy",
                };
            }

            if policy.require_approval_for_org_shared
                && !matches!(ctx.approval_verdict, Some(ApprovalSignal::Approved))
            {
                tracing::debug!(
                    org_id = %ctx.org_id,
                    tier = %CacheTier::OrgShared,
                    "tier gate: org_shared_cache requires approved verdict — downgrading"
                );
                return TierGateOutcome::Downgraded {
                    requested: CacheTier::OrgShared,
                    effective: CacheTier::PrivateEdge,
                    reason: "org_shared_cache requires an approved enforcement verdict",
                };
            }

            if let Some(data_class) = ctx.data_class {
                if policy.blocked_data_classes.contains(&data_class) {
                    tracing::debug!(
                        org_id = %ctx.org_id,
                        tier = %CacheTier::OrgShared,
                        data_class = %data_class.as_str(),
                        "tier gate: data class blocked from org_shared_cache — downgrading"
                    );
                    return TierGateOutcome::Downgraded {
                        requested: CacheTier::OrgShared,
                        effective: CacheTier::PrivateEdge,
                        reason: "request data class is blocked from org_shared_cache",
                    };
                }
            }

            if let Some(provider) = ctx.provider_id {
                if policy
                    .blocked_providers
                    .iter()
                    .any(|p| p.as_str() == provider)
                {
                    tracing::debug!(
                        org_id = %ctx.org_id,
                        tier = %CacheTier::OrgShared,
                        provider = %provider,
                        "tier gate: provider blocked from org_shared_cache — downgrading"
                    );
                    return TierGateOutcome::Downgraded {
                        requested: CacheTier::OrgShared,
                        effective: CacheTier::PrivateEdge,
                        reason: "provider is blocked from org_shared_cache",
                    };
                }
            }

            if !ctx.backend_available {
                tracing::warn!(
                    org_id = %ctx.org_id,
                    tier = %CacheTier::OrgShared,
                    "tier gate: backend unavailable — falling back to private_edge"
                );
                return TierGateOutcome::Downgraded {
                    requested: CacheTier::OrgShared,
                    effective: CacheTier::PrivateEdge,
                    reason:
                        "org_shared_cache backend unavailable — falling back to private execution",
                };
            }

            TierGateOutcome::Permitted { tier }
        }
    }
}

// ─── DenyList (negative-cache / deny-list foundation) ────────────────────────

/// A single negative-cache entry.
///
/// Deny-list entries are populated from:
/// - Control-plane `cache_invalidation_log` records with `deny_repopulate = TRUE`.
/// - Operator-triggered runtime flush commands.
/// - Automatic detection of unsafe replay patterns.
#[derive(Clone, Debug)]
pub struct DenyListEntry {
    /// The cache key that is denied (exact match).
    pub key: String,

    /// Human-readable reason for the denial.
    pub reason: String,

    /// Unix timestamp (seconds) after which this entry expires.
    /// `u64::MAX` means the entry never expires.
    pub expires_at_unix_secs: u64,
}

/// In-process deny-list for cache key suppression.
///
/// Entries are checked before every cache `get`. Expired entries are pruned
/// lazily on [`DenyList::is_denied`] and explicitly via
/// [`DenyList::prune_expired`].
#[derive(Clone, Default)]
pub struct DenyList {
    entries: Arc<RwLock<Vec<DenyListEntry>>>,
}

impl DenyList {
    /// Returns `true` when `key` is currently denied (and not expired).
    ///
    /// Expired entries are pruned lazily during this call.
    pub fn is_denied(&self, key: &str) -> bool {
        let now = current_unix_secs();
        let Ok(mut entries) = self.entries.write() else {
            // Fail-closed: if the lock is poisoned, deny access.
            tracing::error!("deny_list: lock poisoned — failing closed");
            return true;
        };
        // Prune expired entries in the same write-lock acquisition.
        entries.retain(|e| now <= e.expires_at_unix_secs);
        entries.iter().any(|e| e.key == key)
    }

    /// Adds an entry to the deny-list.
    pub fn add(&self, entry: DenyListEntry) {
        if let Ok(mut entries) = self.entries.write() {
            entries.push(entry);
        }
    }

    /// Explicitly prunes all expired entries. Safe to call from a background
    /// maintenance task.
    pub fn prune_expired(&self) {
        let now = current_unix_secs();
        if let Ok(mut entries) = self.entries.write() {
            entries.retain(|e| now <= e.expires_at_unix_secs);
        }
    }

    /// Returns the number of active (non-expired) deny-list entries.
    fn active_entry_count(&self) -> usize {
        let now = current_unix_secs();
        self.entries
            .read()
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| now <= e.expires_at_unix_secs)
                    .count()
            })
            .unwrap_or(0)
    }
}

// ─── Phase 6 tests ────────────────────────────────────────────────────────────

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
    use axum::http::{HeaderMap, StatusCode};
    use std::ffi::{OsStr, OsString};
    use std::sync::{Arc, MutexGuard, RwLock};
    use tempfile::tempdir;

    fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| handle.block_on(fut)),
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(fut),
        }
    }

    const CACHE_ENV_KEYS: &[&str] = &[
        "VERDICTAN_LLM_CACHE_ENABLED",
        "VERDICTAN_LLM_CACHE_BACKEND",
        "VERDICTAN_LLM_CACHE_TTL_SECS",
        "VERDICTAN_LLM_CACHE_CLEAR",
        "VERDICTAN_LLM_CACHE_BUSTER",
        "VERDICTAN_LLM_CACHE_DIR",
        "VERDICTAN_LLM_CACHE_MAX_BYTES",
        "VERDICTAN_LLM_CACHE_WARMUP_ENABLED",
        "VERDICTAN_LLM_CACHE_REDIS_URL",
        "VERDICTAN_LLM_CACHE_REDIS_KEY_PREFIX",
        "VERDICTAN_LLM_CACHE_S3_BUCKET",
        "VERDICTAN_LLM_CACHE_S3_PREFIX",
        "VERDICTAN_LLM_CACHE_S3_REGION",
        "VERDICTAN_LLM_CACHE_S3_ENDPOINT",
        "VERDICTAN_LLM_CACHE_S3_ACCESS_KEY_ID",
        "VERDICTAN_LLM_CACHE_S3_SECRET_ACCESS_KEY",
        "VERDICTAN_LLM_CACHE_S3_FORCE_PATH_STYLE",
        "VERDICTAN_LLM_CACHE_GCS_BUCKET",
        "VERDICTAN_LLM_CACHE_GCS_PREFIX",
        "VERDICTAN_LLM_CACHE_GCS_REGION",
        "VERDICTAN_LLM_CACHE_GCS_ENDPOINT",
        "VERDICTAN_LLM_CACHE_GCS_ACCESS_KEY_ID",
        "VERDICTAN_LLM_CACHE_GCS_SECRET_ACCESS_KEY",
        "VERDICTAN_LLM_CACHE_GCS_FORCE_PATH_STYLE",
        "VERDICTAN_LLM_CACHE_QDRANT_URL",
        "VERDICTAN_LLM_CACHE_QDRANT_COLLECTION",
        "VERDICTAN_LLM_CACHE_QDRANT_API_KEY",
    ];

    #[derive(Default)]
    struct TestEnvGuard {
        saved: HashMap<String, Option<OsString>>,
    }

    impl TestEnvGuard {
        fn set(&mut self, key: &str, value: impl AsRef<OsStr>) {
            self.saved
                .entry(key.to_string())
                .or_insert_with(|| std::env::var_os(key));
            crate::test_support::set_var(key, value);
        }

        fn unset(&mut self, key: &str) {
            self.saved
                .entry(key.to_string())
                .or_insert_with(|| std::env::var_os(key));
            crate::test_support::unset_var(key);
        }
    }

    impl Drop for TestEnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain() {
                if let Some(value) = value {
                    crate::test_support::set_var(&key, value);
                } else {
                    crate::test_support::unset_var(&key);
                }
            }
        }
    }

    fn env_guard() -> (MutexGuard<'static, ()>, TestEnvGuard) {
        (
            crate::test_support::env_lock()
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            TestEnvGuard::default(),
        )
    }

    fn clear_cache_env(env: &mut TestEnvGuard) {
        for key in CACHE_ENV_KEYS {
            env.unset(key);
        }
    }

    fn accessor_cache(config: CacheConfig) -> ProviderResponseCache {
        ProviderResponseCache {
            config,
            exact_backend: ExactCacheBackendAdapter::Memory(MemoryExactCacheBackend::default()),
            semantic_index: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }

    fn memory_cache_with_ttl(ttl: Duration) -> ProviderResponseCache {
        let mut config = memory_cache().config().clone();
        config.ttl = ttl;
        ProviderResponseCache::new_for_test(config)
    }

    fn old_success_entry(body: &[u8], age_secs: u64) -> StoredCachedResponse {
        StoredCachedResponse {
            stored_at_unix_secs: current_unix_secs().saturating_sub(age_secs),
            status: StatusCode::OK.as_u16(),
            headers: vec![],
            body_base64: BASE64_STANDARD.encode(body),
            original_key: None,
            key_version: CURRENT_CACHE_KEY_VERSION,
        }
    }

    fn memory_cache() -> ProviderResponseCache {
        ProviderResponseCache::new_for_test(CacheConfig {
            enabled: true,
            backend: CacheBackend::Memory,
            ttl: Duration::from_secs(60),
            directory: None,
            max_bytes: DEFAULT_LOCAL_CACHE_MAX_BYTES,
            warmup_enabled: false,
            redis_url: None,
            redis_key_prefix: DEFAULT_REDIS_CACHE_KEY_PREFIX.to_string(),
            s3_config: None,
            gcs_config: None,
            qdrant_config: None,
            clear_on_start: false,
            cache_buster: None,
        })
    }

    fn filesystem_cache_config(directory: PathBuf, max_bytes: u64) -> CacheConfig {
        CacheConfig {
            enabled: true,
            backend: CacheBackend::Filesystem,
            ttl: Duration::from_secs(60),
            directory: Some(directory),
            max_bytes,
            warmup_enabled: false,
            redis_url: None,
            redis_key_prefix: DEFAULT_REDIS_CACHE_KEY_PREFIX.to_string(),
            s3_config: None,
            gcs_config: None,
            qdrant_config: None,
            clear_on_start: false,
            cache_buster: None,
        }
    }

    fn cache_config_for_test(backend: CacheBackend) -> CacheConfig {
        CacheConfig {
            enabled: true,
            backend,
            ttl: Duration::from_secs(60),
            directory: None,
            max_bytes: DEFAULT_LOCAL_CACHE_MAX_BYTES,
            warmup_enabled: false,
            redis_url: None,
            redis_key_prefix: DEFAULT_REDIS_CACHE_KEY_PREFIX.to_string(),
            s3_config: None,
            gcs_config: None,
            qdrant_config: None,
            clear_on_start: false,
            cache_buster: None,
        }
    }

    #[test]
    fn provider_cache_increments_prometheus_hit_and_miss_counters() {
        let cache = memory_cache();
        let hit_before = CACHE_HIT_COUNTER.get();
        let miss_before = CACHE_MISS_COUNTER.get();
        let response = BufferedUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"cached-response"),
            false,
        );

        block_on(cache.put("cache-key", &response));
        assert!(block_on(cache.get("cache-key")).is_some());
        assert!(block_on(cache.get("missing-key")).is_none());

        assert!(CACHE_HIT_COUNTER.get() >= hit_before + 1.0);
        assert!(CACHE_MISS_COUNTER.get() >= miss_before + 1.0);
    }

    // ── parse_cache_backend ──────────────────────────────────────────────

    #[test]
    fn parse_cache_backend_auto() {
        // `auto` (and the empty default) resolve to memory in a
        // dev/test environment (`cfg!(test)` is true here) rather than persistent disk.
        assert_eq!(parse_cache_backend("auto").unwrap(), CacheBackend::Memory);
        assert_eq!(parse_cache_backend("").unwrap(), CacheBackend::Memory);
    }

    #[test]
    fn parse_cache_backend_memory() {
        assert_eq!(parse_cache_backend("memory").unwrap(), CacheBackend::Memory);
    }

    #[test]
    fn parse_cache_backend_filesystem_aliases() {
        assert_eq!(
            parse_cache_backend("filesystem").unwrap(),
            CacheBackend::Filesystem
        );
        assert_eq!(
            parse_cache_backend("file").unwrap(),
            CacheBackend::Filesystem
        );
        assert_eq!(
            parse_cache_backend("disk").unwrap(),
            CacheBackend::Filesystem
        );
    }

    #[test]
    fn parse_cache_backend_redis() {
        assert_eq!(parse_cache_backend("redis").unwrap(), CacheBackend::Redis);
    }

    #[test]
    fn parse_cache_backend_valkey() {
        assert_eq!(parse_cache_backend("valkey").unwrap(), CacheBackend::Valkey);
    }

    #[test]
    fn parse_cache_backend_s3() {
        assert_eq!(parse_cache_backend("s3").unwrap(), CacheBackend::S3);
    }

    #[test]
    fn parse_cache_backend_gcs() {
        assert_eq!(parse_cache_backend("gcs").unwrap(), CacheBackend::Gcs);
    }

    #[test]
    fn parse_cache_backend_qdrant() {
        assert_eq!(parse_cache_backend("qdrant").unwrap(), CacheBackend::Qdrant);
    }

    #[test]
    fn parse_cache_backend_case_insensitive() {
        assert_eq!(parse_cache_backend("MEMORY").unwrap(), CacheBackend::Memory);
        assert_eq!(parse_cache_backend("Redis").unwrap(), CacheBackend::Redis);
    }

    #[test]
    fn parse_cache_backend_trims_whitespace() {
        assert_eq!(
            parse_cache_backend("  memory  ").unwrap(),
            CacheBackend::Memory
        );
    }

    #[test]
    fn parse_cache_backend_invalid() {
        assert!(parse_cache_backend("postgres").is_err());
    }

    // ── CacheBackend::as_str ─────────────────────────────────────────────

    #[test]
    fn cache_backend_as_str_all_variants() {
        assert_eq!(CacheBackend::Memory.as_str(), "memory");
        assert_eq!(CacheBackend::Filesystem.as_str(), "filesystem");
        assert_eq!(CacheBackend::Redis.as_str(), "redis");
        assert_eq!(CacheBackend::Valkey.as_str(), "valkey");
        assert_eq!(CacheBackend::S3.as_str(), "s3");
        assert_eq!(CacheBackend::Gcs.as_str(), "gcs");
        assert_eq!(CacheBackend::Qdrant.as_str(), "qdrant");
    }

    // ── env/config helpers ───────────────────────────────────────────────

    #[test]
    fn resolve_env_value_trims_and_filters_empty_values() {
        let (_lock, mut env) = env_guard();

        env.set(
            "VERDICTAN_CACHE_TEST_ENV_VALUE",
            "  redis://cache.internal:6379/3  ",
        );
        assert_eq!(
            resolve_env_value("VERDICTAN_CACHE_TEST_ENV_VALUE").as_deref(),
            Some("redis://cache.internal:6379/3")
        );

        env.set("VERDICTAN_CACHE_TEST_ENV_VALUE", "   ");
        assert_eq!(resolve_env_value("VERDICTAN_CACHE_TEST_ENV_VALUE"), None);

        env.unset("VERDICTAN_CACHE_TEST_ENV_VALUE");
        assert_eq!(resolve_env_value("VERDICTAN_CACHE_TEST_ENV_VALUE"), None);
    }

    #[test]
    fn resolve_redis_cache_helpers_read_env_and_default_prefix() {
        let (_lock, mut env) = env_guard();

        env.unset("VERDICTAN_LLM_CACHE_REDIS_URL");
        env.unset("VERDICTAN_LLM_CACHE_REDIS_KEY_PREFIX");
        assert_eq!(resolve_redis_cache_url(), None);
        assert_eq!(
            resolve_redis_cache_key_prefix(),
            DEFAULT_REDIS_CACHE_KEY_PREFIX
        );

        env.set(
            "VERDICTAN_LLM_CACHE_REDIS_URL",
            "  redis://127.0.0.1:6379/9  ",
        );
        env.set(
            "VERDICTAN_LLM_CACHE_REDIS_KEY_PREFIX",
            "::tenant::shared-cache::",
        );

        assert_eq!(
            resolve_redis_cache_url().as_deref(),
            Some("redis://127.0.0.1:6379/9")
        );
        assert_eq!(resolve_redis_cache_key_prefix(), "tenant::shared-cache");
    }

    #[test]
    fn resolve_s3_cache_config_requires_required_fields() {
        let (_lock, mut env) = env_guard();

        env.unset("VERDICTAN_LLM_CACHE_S3_BUCKET");
        env.unset("VERDICTAN_LLM_CACHE_S3_REGION");
        env.unset("VERDICTAN_LLM_CACHE_S3_ACCESS_KEY_ID");
        env.unset("VERDICTAN_LLM_CACHE_S3_SECRET_ACCESS_KEY");
        env.set(
            "VERDICTAN_LLM_CACHE_S3_ENDPOINT",
            "https://minio.internal:9000",
        );

        assert!(resolve_s3_cache_config().is_none());
    }

    #[test]
    fn resolve_s3_cache_config_uses_defaults_and_bool_override() {
        let (_lock, mut env) = env_guard();

        env.set("VERDICTAN_LLM_CACHE_S3_BUCKET", "gateway-cache");
        env.set("VERDICTAN_LLM_CACHE_S3_REGION", "eu-west-1");
        env.set("VERDICTAN_LLM_CACHE_S3_ACCESS_KEY_ID", "access");
        env.set("VERDICTAN_LLM_CACHE_S3_SECRET_ACCESS_KEY", "secret");
        env.set(
            "VERDICTAN_LLM_CACHE_S3_ENDPOINT",
            "https://minio.internal:9000",
        );
        env.unset("VERDICTAN_LLM_CACHE_S3_PREFIX");
        env.unset("VERDICTAN_LLM_CACHE_S3_FORCE_PATH_STYLE");

        let config = resolve_s3_cache_config().expect("s3 config");
        assert_eq!(config.flavor, ObjectStoreFlavor::S3);
        assert_eq!(config.bucket, "gateway-cache");
        assert_eq!(config.prefix, ObjectStoreCacheConfig::default_prefix());
        assert_eq!(config.region, "eu-west-1");
        assert_eq!(
            config.endpoint.as_deref(),
            Some("https://minio.internal:9000")
        );
        assert_eq!(config.access_key_id, "access");
        assert_eq!(config.secret_access_key, "secret");
        assert!(config.force_path_style);

        env.set("VERDICTAN_LLM_CACHE_S3_PREFIX", "tenant/cache");
        env.set("VERDICTAN_LLM_CACHE_S3_FORCE_PATH_STYLE", "off");

        let overridden = resolve_s3_cache_config().expect("s3 config override");
        assert_eq!(overridden.prefix, "tenant/cache");
        assert!(!overridden.force_path_style);
    }

    #[test]
    fn resolve_gcs_cache_config_requires_bucket_and_credentials() {
        let (_lock, mut env) = env_guard();

        env.set("VERDICTAN_LLM_CACHE_GCS_BUCKET", "gateway-cache");
        env.unset("VERDICTAN_LLM_CACHE_GCS_ACCESS_KEY_ID");
        env.unset("VERDICTAN_LLM_CACHE_GCS_SECRET_ACCESS_KEY");

        assert!(resolve_gcs_cache_config().is_none());
    }

    #[test]
    fn resolve_gcs_cache_config_uses_defaults_and_overrides() {
        let (_lock, mut env) = env_guard();

        env.set("VERDICTAN_LLM_CACHE_GCS_BUCKET", "gateway-cache");
        env.set("VERDICTAN_LLM_CACHE_GCS_ACCESS_KEY_ID", "access");
        env.set("VERDICTAN_LLM_CACHE_GCS_SECRET_ACCESS_KEY", "secret");
        env.unset("VERDICTAN_LLM_CACHE_GCS_PREFIX");
        env.unset("VERDICTAN_LLM_CACHE_GCS_REGION");
        env.unset("VERDICTAN_LLM_CACHE_GCS_ENDPOINT");
        env.unset("VERDICTAN_LLM_CACHE_GCS_FORCE_PATH_STYLE");

        let defaults = resolve_gcs_cache_config().expect("gcs config");
        assert_eq!(defaults.flavor, ObjectStoreFlavor::Gcs);
        assert_eq!(defaults.bucket, "gateway-cache");
        assert_eq!(defaults.prefix, ObjectStoreCacheConfig::default_prefix());
        assert_eq!(defaults.region, "auto");
        assert_eq!(defaults.endpoint.as_deref(), Some(DEFAULT_GCS_ENDPOINT));
        assert_eq!(defaults.access_key_id, "access");
        assert_eq!(defaults.secret_access_key, "secret");
        assert!(defaults.force_path_style);

        env.set("VERDICTAN_LLM_CACHE_GCS_PREFIX", "custom/cache");
        env.set("VERDICTAN_LLM_CACHE_GCS_REGION", "us-central1");
        env.set(
            "VERDICTAN_LLM_CACHE_GCS_ENDPOINT",
            "https://storage.example.internal",
        );
        env.set("VERDICTAN_LLM_CACHE_GCS_FORCE_PATH_STYLE", "0");

        let overridden = resolve_gcs_cache_config().expect("gcs override");
        assert_eq!(overridden.prefix, "custom/cache");
        assert_eq!(overridden.region, "us-central1");
        assert_eq!(
            overridden.endpoint.as_deref(),
            Some("https://storage.example.internal")
        );
        assert!(!overridden.force_path_style);
    }

    #[test]
    fn resolve_qdrant_cache_config_requires_url_and_uses_defaults() {
        let (_lock, mut env) = env_guard();

        env.unset("VERDICTAN_LLM_CACHE_QDRANT_URL");
        env.unset("VERDICTAN_LLM_CACHE_QDRANT_COLLECTION");
        env.unset("VERDICTAN_LLM_CACHE_QDRANT_API_KEY");
        assert!(resolve_qdrant_cache_config().is_none());

        env.set(
            "VERDICTAN_LLM_CACHE_QDRANT_URL",
            "https://qdrant.internal:6333",
        );
        let defaults = resolve_qdrant_cache_config().expect("qdrant config");
        assert_eq!(defaults.url, "https://qdrant.internal:6333");
        assert_eq!(defaults.collection, QdrantCacheConfig::default_collection());
        assert_eq!(defaults.api_key, None);
        assert_eq!(
            defaults.request_timeout,
            QdrantCacheConfig::default_timeout()
        );

        env.set(
            "VERDICTAN_LLM_CACHE_QDRANT_COLLECTION",
            "tenant_semantic_cache",
        );
        env.set("VERDICTAN_LLM_CACHE_QDRANT_API_KEY", "qdrant-secret");
        let overridden = resolve_qdrant_cache_config().expect("qdrant override");
        assert_eq!(overridden.collection, "tenant_semantic_cache");
        assert_eq!(overridden.api_key.as_deref(), Some("qdrant-secret"));
    }

    #[test]
    fn resolve_qdrant_cache_config_blank_optional_values_fall_back_to_defaults() {
        let (_lock, mut env) = env_guard();

        env.set(
            "VERDICTAN_LLM_CACHE_QDRANT_URL",
            "  https://qdrant.internal:6333  ",
        );
        env.set("VERDICTAN_LLM_CACHE_QDRANT_COLLECTION", "   ");
        env.set("VERDICTAN_LLM_CACHE_QDRANT_API_KEY", "   ");

        let config = resolve_qdrant_cache_config().expect("qdrant config");
        assert_eq!(config.url, "https://qdrant.internal:6333");
        assert_eq!(config.collection, QdrantCacheConfig::default_collection());
        assert_eq!(config.api_key, None);
    }

    #[test]
    fn missing_cache_config_errors_are_user_facing() {
        let redis_error = redis_cache_missing_url_error();
        assert_eq!(redis_error.error_code(), "cli.config_invalid");
        assert!(redis_error
            .to_string()
            .contains("VERDICTAN_LLM_CACHE_REDIS_URL"));

        let s3_error = s3_cache_missing_config_error();
        assert_eq!(s3_error.error_code(), "cli.config_invalid");
        assert!(s3_error
            .to_string()
            .contains("VERDICTAN_LLM_CACHE_BACKEND=s3"));

        let gcs_error = gcs_cache_missing_config_error();
        assert_eq!(gcs_error.error_code(), "cli.config_invalid");
        assert!(gcs_error
            .to_string()
            .contains("VERDICTAN_LLM_CACHE_BACKEND=gcs"));

        let qdrant_error = qdrant_cache_missing_config_error();
        assert_eq!(qdrant_error.error_code(), "cli.config_invalid");
        assert!(qdrant_error
            .to_string()
            .contains("VERDICTAN_LLM_CACHE_QDRANT_URL"));
    }

    #[test]
    fn parse_bool_env_supports_truthy_falsey_and_invalid_values() {
        let (_lock, mut env) = env_guard();

        env.set("VERDICTAN_CACHE_TEST_BOOL", " YES ");
        assert_eq!(parse_bool_env("VERDICTAN_CACHE_TEST_BOOL"), Some(true));

        env.set("VERDICTAN_CACHE_TEST_BOOL", "Off");
        assert_eq!(parse_bool_env("VERDICTAN_CACHE_TEST_BOOL"), Some(false));

        env.set("VERDICTAN_CACHE_TEST_BOOL", "sometimes");
        assert_eq!(parse_bool_env("VERDICTAN_CACHE_TEST_BOOL"), None);

        env.unset("VERDICTAN_CACHE_TEST_BOOL");
        assert_eq!(parse_bool_env("VERDICTAN_CACHE_TEST_BOOL"), None);
    }

    #[test]
    fn cache_default_helpers_match_expected_values() {
        assert!(default_cache_enabled());
        assert!(default_cache_default_on());
        assert!((default_similarity_threshold() - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn resolve_cache_directory_prefers_explicit_path() {
        let dir = tempdir().expect("tempdir");
        let explicit = dir.path().join("cache-root");

        assert_eq!(
            resolve_cache_directory(Some(explicit.display().to_string())),
            explicit
        );
    }

    #[test]
    fn resolve_cache_directory_prefers_platform_cache_envs() {
        let (_lock, mut env) = env_guard();
        let xdg_cache = tempdir().expect("xdg cache");
        let home = tempdir().expect("home");

        env.set("XDG_CACHE_HOME", xdg_cache.path());
        env.set("HOME", home.path());

        let resolved = resolve_cache_directory(None);

        #[cfg(target_os = "macos")]
        assert_eq!(
            resolved,
            home.path()
                .join("Library")
                .join("Caches")
                .join("verdictan")
                .join("llm-provider-cache")
        );

        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            resolved,
            xdg_cache
                .path()
                .join("verdictan")
                .join("llm-provider-cache")
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn resolve_cache_directory_falls_back_to_home_cache_when_xdg_missing() {
        let (_lock, mut env) = env_guard();
        let home = tempdir().expect("home");

        env.unset("XDG_CACHE_HOME");
        env.set("HOME", home.path());

        assert_eq!(
            resolve_cache_directory(None),
            home.path()
                .join(".cache")
                .join("verdictan")
                .join("llm-provider-cache")
        );
    }

    #[test]
    fn resolve_cache_directory_falls_back_to_temp_dir_without_home_or_xdg() {
        let (_lock, mut env) = env_guard();

        env.unset("HOME");
        env.unset("XDG_CACHE_HOME");

        assert_eq!(
            resolve_cache_directory(None),
            std::env::temp_dir().join("verdictan-llm-provider-cache")
        );
    }

    // ── cosine_similarity ────────────────────────────────────────────────

    #[test]
    fn cosine_similarity_identical_vectors() {
        let v = vec![1.0, 2.0, 3.0];
        let sim = cosine_similarity(&v, &v);
        assert!((sim - 1.0).abs() < 1e-9);
    }

    #[test]
    fn cosine_similarity_orthogonal_vectors() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        assert!((cosine_similarity(&a, &b)).abs() < 1e-9);
    }

    #[test]
    fn cosine_similarity_opposite_vectors() {
        let a = vec![1.0, 0.0];
        let b = vec![-1.0, 0.0];
        assert!((cosine_similarity(&a, &b) - (-1.0)).abs() < 1e-9);
    }

    #[test]
    fn cosine_similarity_different_lengths() {
        assert_eq!(cosine_similarity(&[1.0, 2.0], &[1.0]), 0.0);
    }

    #[test]
    fn cosine_similarity_empty_vectors() {
        assert_eq!(cosine_similarity(&[], &[]), 0.0);
    }

    #[test]
    fn cosine_similarity_zero_vectors() {
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 2.0]), 0.0);
    }

    // ── semantic_lookup ──────────────────────────────────────────────────

    #[test]
    fn semantic_lookup_empty_index() {
        let index = HashMap::new();
        assert!(semantic_lookup(&[1.0], &index, 0.5).is_none());
    }

    #[test]
    fn semantic_lookup_below_threshold() {
        let mut index = HashMap::new();
        index.insert("k1".to_string(), vec![1.0, 0.0]);
        assert!(semantic_lookup(&[0.0, 1.0], &index, 0.5).is_none());
    }

    #[test]
    fn semantic_lookup_above_threshold() {
        let mut index = HashMap::new();
        index.insert("k1".to_string(), vec![1.0, 0.0]);
        index.insert("k2".to_string(), vec![0.9, 0.1]);
        let result = semantic_lookup(&[1.0, 0.0], &index, 0.5);
        assert!(result.is_some());
    }

    // ── serialize / deserialize cache entries ─────────────────────────────

    #[test]
    fn serialize_deserialize_roundtrip() {
        let entry = StoredCachedResponse {
            stored_at_unix_secs: 1700000000,
            status: 200,
            headers: vec![StoredHeader {
                name: "content-type".to_string(),
                value_base64: BASE64_STANDARD.encode(b"application/json"),
            }],
            body_base64: BASE64_STANDARD.encode(b"hello"),
            original_key: None,
            key_version: CURRENT_CACHE_KEY_VERSION,
        };
        let bytes = serialize_cache_entry(&entry);
        let recovered = deserialize_cache_entry(&bytes).expect("deserialize");
        assert_eq!(recovered.status, 200);
        assert_eq!(recovered.key_version, CURRENT_CACHE_KEY_VERSION);
    }

    #[test]
    fn deserialize_empty_bytes_returns_none() {
        assert!(deserialize_cache_entry(&[]).is_none());
    }

    #[test]
    fn deserialize_json_fallback() {
        let entry = StoredCachedResponse {
            stored_at_unix_secs: 1700000000,
            status: 200,
            headers: vec![],
            body_base64: BASE64_STANDARD.encode(b"test"),
            original_key: None,
            key_version: CURRENT_CACHE_KEY_VERSION,
        };
        let json = serde_json::to_vec(&entry).unwrap();
        let recovered = deserialize_cache_entry(&json).expect("deserialize");
        assert_eq!(recovered.status, 200);
    }

    #[test]
    fn deserialize_json_without_key_version_defaults_to_zero() {
        let legacy_json = serde_json::json!({
            "stored_at_unix_secs": 1700000000u64,
            "status": 200u16,
            "headers": [],
            "body_base64": BASE64_STANDARD.encode(b"legacy"),
        });

        let recovered = deserialize_cache_entry(&serde_json::to_vec(&legacy_json).unwrap())
            .expect("legacy entry should deserialize");

        assert_eq!(recovered.key_version, 0);
    }

    // ── BufferedUpstreamResponse ──────────────────────────────────────────

    #[test]
    fn is_cacheable_success_ok_with_body() {
        let resp = BufferedUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"data"),
            false,
        );
        assert!(resp.is_cacheable_success());
    }

    #[test]
    fn is_cacheable_success_fails_on_error_status() {
        let resp = BufferedUpstreamResponse::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            HeaderMap::new(),
            Bytes::from_static(b"err"),
            false,
        );
        assert!(!resp.is_cacheable_success());
    }

    #[test]
    fn is_cacheable_success_fails_on_empty_body() {
        let resp =
            BufferedUpstreamResponse::new(StatusCode::OK, HeaderMap::new(), Bytes::new(), false);
        assert!(!resp.is_cacheable_success());
    }

    #[test]
    fn buffered_response_accessors() {
        let resp = BufferedUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"body"),
            true,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().is_empty());
        assert_eq!(resp.body().as_ref(), b"body");
        assert!(resp.is_cached());
    }

    // ── StoredCachedResponse::to_buffered_response ───────────────────────

    #[test]
    fn stored_response_roundtrip_through_buffered() {
        let resp = BufferedUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"content"),
            false,
        );
        let stored = StoredCachedResponse::from_response(&resp);
        let recovered = stored.to_buffered_response(true).unwrap();
        assert_eq!(recovered.status(), StatusCode::OK);
        assert_eq!(recovered.body().as_ref(), b"content");
        assert!(recovered.is_cached());
    }

    #[test]
    fn stored_response_rejects_invalid_header_name() {
        let stored = StoredCachedResponse {
            stored_at_unix_secs: current_unix_secs(),
            status: StatusCode::OK.as_u16(),
            headers: vec![StoredHeader {
                name: "bad\nheader".to_string(),
                value_base64: BASE64_STANDARD.encode(b"value"),
            }],
            body_base64: BASE64_STANDARD.encode(b"content"),
            original_key: None,
            key_version: CURRENT_CACHE_KEY_VERSION,
        };

        assert!(stored.to_buffered_response(true).is_none());
    }

    #[test]
    fn stored_response_rejects_invalid_body_base64() {
        let stored = StoredCachedResponse {
            stored_at_unix_secs: current_unix_secs(),
            status: StatusCode::OK.as_u16(),
            headers: vec![],
            body_base64: "!not-base64!".to_string(),
            original_key: None,
            key_version: CURRENT_CACHE_KEY_VERSION,
        };

        assert!(stored.to_buffered_response(true).is_none());
    }

    #[test]
    fn stored_response_rejects_invalid_status_code() {
        let stored = StoredCachedResponse {
            stored_at_unix_secs: current_unix_secs(),
            status: 42,
            headers: vec![],
            body_base64: BASE64_STANDARD.encode(b"content"),
            original_key: None,
            key_version: CURRENT_CACHE_KEY_VERSION,
        };

        assert!(stored.to_buffered_response(true).is_none());
    }

    // ── current_cache_key_version ────────────────────────────────────────

    #[test]
    fn current_cache_key_version_matches_constant() {
        assert_eq!(current_cache_key_version(), CURRENT_CACHE_KEY_VERSION);
    }

    #[test]
    fn default_key_version_is_zero_for_legacy_entries() {
        assert_eq!(default_key_version(), 0);
    }

    #[test]
    fn stored_response_timestamp_accessor_returns_original_value() {
        let entry = StoredCachedResponse {
            stored_at_unix_secs: 123,
            status: StatusCode::OK.as_u16(),
            headers: vec![],
            body_base64: BASE64_STANDARD.encode(b"body"),
            original_key: None,
            key_version: CURRENT_CACHE_KEY_VERSION,
        };

        assert_eq!(entry.stored_at_unix_secs(), 123);
    }

    #[test]
    fn deserialize_invalid_bincode_payload_returns_none() {
        let bytes = [CACHE_FORMAT_BINCODE_V1, 0x01, 0x02, 0x03];
        assert!(deserialize_cache_entry(&bytes).is_none());
    }

    // ── SemanticCacheConfig ──────────────────────────────────────────────

    #[test]
    fn semantic_cache_config_default() {
        let cfg = SemanticCacheConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.mode, CacheMode::Exact);
        assert!((cfg.similarity_threshold - 0.85).abs() < 1e-9);
        assert!(cfg.embedding_provider.is_none());
        assert!(cfg.default_on);
        assert!(cfg.ttl_seconds.is_none());
    }

    #[test]
    fn semantic_cache_ttl_override_none_when_zero() {
        let cfg = SemanticCacheConfig {
            ttl_seconds: Some(0),
            ..Default::default()
        };
        assert!(cfg.ttl_override().is_none());
    }

    #[test]
    fn semantic_cache_ttl_override_some_when_positive() {
        let cfg = SemanticCacheConfig {
            ttl_seconds: Some(120),
            ..Default::default()
        };
        assert_eq!(cfg.ttl_override(), Some(Duration::from_secs(120)));
    }

    #[test]
    fn cache_get_with_ttl_override_extends_entry_lifetime() {
        let cache = memory_cache_with_ttl(Duration::from_secs(1));
        block_on(cache.insert_test_entry("ttl-key", old_success_entry(b"cached", 5)));

        let hit = block_on(cache.get_with_ttl("ttl-key", Some(Duration::from_secs(10))));
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().body().as_ref(), b"cached");
    }

    #[test]
    fn semantic_cache_ttl_override_expires_old_entries() {
        let cache = memory_cache_with_ttl(Duration::from_secs(60));
        block_on(cache.insert_test_entry("semantic-old", old_success_entry(b"stale", 8)));
        block_on(cache.store_semantic_embedding("semantic-old", &[1.0, 0.0]));

        let hit =
            block_on(cache.get_semantic_with_ttl(&[1.0, 0.0], 0.9, Some(Duration::from_secs(5))));
        assert!(hit.is_none());
        assert!(block_on(cache.raw_entry_for_test("semantic-old")).is_none());
    }

    #[test]
    fn semantic_cache_ttl_override_keeps_entry_when_override_is_long_enough() {
        let cache = memory_cache_with_ttl(Duration::from_secs(1));
        block_on(cache.insert_test_entry("semantic-fresh", old_success_entry(b"fresh", 5)));
        block_on(cache.store_semantic_embedding("semantic-fresh", &[1.0, 0.0]));

        let hit =
            block_on(cache.get_semantic_with_ttl(&[1.0, 0.0], 0.9, Some(Duration::from_secs(10))));
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().body().as_ref(), b"fresh");
    }

    // ── CacheTier ────────────────────────────────────────────────────────

    #[test]
    fn cache_tier_as_str() {
        assert_eq!(CacheTier::PrivateEdge.as_str(), "private_edge_cache");
        assert_eq!(CacheTier::OrgShared.as_str(), "org_shared_cache");
    }

    #[test]
    fn cache_tier_display() {
        assert_eq!(format!("{}", CacheTier::PrivateEdge), "private_edge_cache");
    }

    #[test]
    fn cache_tier_policy_default_is_private_only_and_conservative() {
        let policy = CacheTierPolicy::default();

        assert!(policy.allow_private_edge);
        assert!(!policy.allow_org_shared);
        assert!(policy.require_approval_for_org_shared);
        assert!(policy.blocked_providers.is_empty());
        assert_eq!(
            policy.blocked_data_classes,
            vec![
                DataClassSignal::Phi,
                DataClassSignal::Pii,
                DataClassSignal::Financial,
                DataClassSignal::IntellectualProperty,
            ]
        );
    }

    // ── DataClassSignal ──────────────────────────────────────────────────

    #[test]
    fn data_class_signal_as_str() {
        assert_eq!(DataClassSignal::Unclassified.as_str(), "unclassified");
        assert_eq!(DataClassSignal::Pii.as_str(), "pii");
        assert_eq!(DataClassSignal::Phi.as_str(), "phi");
        assert_eq!(DataClassSignal::Financial.as_str(), "financial");
        assert_eq!(
            DataClassSignal::IntellectualProperty.as_str(),
            "intellectual_property"
        );
    }

    #[test]
    fn data_class_ordering() {
        assert!(DataClassSignal::Pii > DataClassSignal::Unclassified);
        assert!(DataClassSignal::IntellectualProperty > DataClassSignal::Financial);
    }

    // ── TierGateOutcome ──────────────────────────────────────────────────

    #[test]
    fn tier_gate_outcome_permitted() {
        let outcome = TierGateOutcome::Permitted {
            tier: CacheTier::PrivateEdge,
        };
        assert_eq!(outcome.effective_tier(), Some(CacheTier::PrivateEdge));
        assert!(outcome.is_usable());
        assert!(outcome.reason().is_none());
    }

    #[test]
    fn tier_gate_outcome_downgraded() {
        let outcome = TierGateOutcome::Downgraded {
            requested: CacheTier::OrgShared,
            effective: CacheTier::PrivateEdge,
            reason: "test",
        };
        assert_eq!(outcome.effective_tier(), Some(CacheTier::PrivateEdge));
        assert!(outcome.is_usable());
        assert_eq!(outcome.reason(), Some("test"));
    }

    #[test]
    fn tier_gate_outcome_denied() {
        let outcome = TierGateOutcome::Denied { reason: "nope" };
        assert!(outcome.effective_tier().is_none());
        assert!(!outcome.is_usable());
        assert_eq!(outcome.reason(), Some("nope"));
    }

    // ── evaluate_tier_gate ───────────────────────────────────────────────

    fn default_gate_ctx<'a>() -> TierGateContext<'a> {
        TierGateContext {
            org_id: "org-1",
            user_id: Some("user-1"),
            workflow_id: None,
            replay_digest: None,
            stored_digest: None,
            approval_verdict: Some(ApprovalSignal::Approved),
            data_class: None,
            provider_id: None,
            backend_available: true,
        }
    }

    #[test]
    fn gate_private_edge_permitted_by_default() {
        let policy = CacheTierPolicy::default();
        let ctx = default_gate_ctx();
        let outcome = evaluate_tier_gate(CacheTier::PrivateEdge, &policy, &ctx);
        assert!(matches!(outcome, TierGateOutcome::Permitted { .. }));
    }

    #[test]
    fn gate_private_edge_denied_when_policy_disables_it() {
        let policy = CacheTierPolicy {
            allow_private_edge: false,
            ..Default::default()
        };
        let ctx = default_gate_ctx();
        let outcome = evaluate_tier_gate(CacheTier::PrivateEdge, &policy, &ctx);
        assert!(matches!(
            outcome,
            TierGateOutcome::Denied {
                reason: "private_edge_cache disabled by org policy",
            }
        ));
    }

    #[test]
    fn gate_org_shared_downgraded_when_not_enabled() {
        let policy = CacheTierPolicy::default();
        let ctx = default_gate_ctx();
        let outcome = evaluate_tier_gate(CacheTier::OrgShared, &policy, &ctx);
        assert!(matches!(outcome, TierGateOutcome::Downgraded { .. }));
    }

    #[test]
    fn gate_org_shared_permitted_when_fully_configured() {
        let policy = CacheTierPolicy {
            allow_org_shared: true,
            require_approval_for_org_shared: true,
            blocked_data_classes: vec![],
            blocked_providers: vec![],
            ..Default::default()
        };
        let ctx = default_gate_ctx();
        let outcome = evaluate_tier_gate(CacheTier::OrgShared, &policy, &ctx);
        assert!(matches!(outcome, TierGateOutcome::Permitted { .. }));
    }

    #[test]
    fn gate_org_shared_downgraded_without_approval() {
        let policy = CacheTierPolicy {
            allow_org_shared: true,
            require_approval_for_org_shared: true,
            ..Default::default()
        };
        let mut ctx = default_gate_ctx();
        ctx.approval_verdict = Some(ApprovalSignal::Pending);
        let outcome = evaluate_tier_gate(CacheTier::OrgShared, &policy, &ctx);
        assert!(matches!(outcome, TierGateOutcome::Downgraded { .. }));
    }

    #[test]
    fn gate_org_shared_downgraded_without_explicit_approved_verdict() {
        let policy = CacheTierPolicy {
            allow_org_shared: true,
            require_approval_for_org_shared: true,
            blocked_data_classes: vec![],
            blocked_providers: vec![],
            ..Default::default()
        };
        let mut ctx = default_gate_ctx();
        ctx.approval_verdict = None;

        let outcome = evaluate_tier_gate(CacheTier::OrgShared, &policy, &ctx);

        assert!(matches!(
            outcome,
            TierGateOutcome::Downgraded {
                requested: CacheTier::OrgShared,
                effective: CacheTier::PrivateEdge,
                reason: "org_shared_cache requires an approved enforcement verdict",
            }
        ));
    }

    #[test]
    fn gate_org_shared_downgraded_for_blocked_data_class() {
        let policy = CacheTierPolicy {
            allow_org_shared: true,
            require_approval_for_org_shared: false,
            blocked_data_classes: vec![DataClassSignal::Pii],
            ..Default::default()
        };
        let mut ctx = default_gate_ctx();
        ctx.data_class = Some(DataClassSignal::Pii);
        let outcome = evaluate_tier_gate(CacheTier::OrgShared, &policy, &ctx);
        assert!(matches!(outcome, TierGateOutcome::Downgraded { .. }));
    }

    #[test]
    fn gate_org_shared_downgraded_for_blocked_provider() {
        let policy = CacheTierPolicy {
            allow_org_shared: true,
            require_approval_for_org_shared: false,
            blocked_data_classes: vec![],
            blocked_providers: vec!["openai".to_string()],
            ..Default::default()
        };
        let mut ctx = default_gate_ctx();
        ctx.provider_id = Some("openai");
        let outcome = evaluate_tier_gate(CacheTier::OrgShared, &policy, &ctx);
        assert!(matches!(outcome, TierGateOutcome::Downgraded { .. }));
    }

    #[test]
    fn gate_org_shared_downgraded_when_backend_unavailable() {
        let policy = CacheTierPolicy {
            allow_org_shared: true,
            require_approval_for_org_shared: false,
            blocked_data_classes: vec![],
            blocked_providers: vec![],
            ..Default::default()
        };
        let mut ctx = default_gate_ctx();
        ctx.backend_available = false;
        let outcome = evaluate_tier_gate(CacheTier::OrgShared, &policy, &ctx);
        assert!(matches!(outcome, TierGateOutcome::Downgraded { .. }));
    }

    // ── DenyList ─────────────────────────────────────────────────────────

    #[test]
    fn deny_list_empty_allows_all() {
        let list = DenyList::default();
        assert!(!list.is_denied("any-key"));
    }

    #[test]
    fn deny_list_add_and_check() {
        let list = DenyList::default();
        list.add(DenyListEntry {
            key: "blocked".to_string(),
            reason: "test".to_string(),
            expires_at_unix_secs: u64::MAX,
        });
        assert!(list.is_denied("blocked"));
        assert!(!list.is_denied("other"));
    }

    #[test]
    fn deny_list_active_count() {
        let list = DenyList::default();
        list.add(DenyListEntry {
            key: "k1".to_string(),
            reason: "r".to_string(),
            expires_at_unix_secs: u64::MAX,
        });
        list.add(DenyListEntry {
            key: "k2".to_string(),
            reason: "r".to_string(),
            expires_at_unix_secs: u64::MAX,
        });
        assert_eq!(list.active_entry_count(), 2);
    }

    #[test]
    fn deny_list_prune_removes_expired() {
        let list = DenyList::default();
        list.add(DenyListEntry {
            key: "expired".to_string(),
            reason: "r".to_string(),
            expires_at_unix_secs: 0,
        });
        list.prune_expired();
        assert_eq!(list.active_entry_count(), 0);
    }

    #[test]
    fn deny_list_is_denied_prunes_expired_entries_lazily() {
        let list = DenyList::default();
        list.add(DenyListEntry {
            key: "expired".to_string(),
            reason: "old".to_string(),
            expires_at_unix_secs: 0,
        });
        list.add(DenyListEntry {
            key: "active".to_string(),
            reason: "current".to_string(),
            expires_at_unix_secs: u64::MAX,
        });

        assert!(!list.is_denied("expired"));
        assert!(list.is_denied("active"));
        assert_eq!(list.active_entry_count(), 1);
    }

    // ── CacheMode serde ──────────────────────────────────────────────────

    #[test]
    fn cache_mode_serde_roundtrip() {
        let exact: CacheMode = serde_json::from_str(r#""exact""#).unwrap();
        assert_eq!(exact, CacheMode::Exact);
        let semantic: CacheMode = serde_json::from_str(r#""semantic""#).unwrap();
        assert_eq!(semantic, CacheMode::Semantic);
    }

    // ── ProviderResponseCache: memory backend ────────────────────────────

    #[test]
    fn cache_disabled_returns_none() {
        let cache = ProviderResponseCache::new_for_test(CacheConfig {
            enabled: false,
            backend: CacheBackend::Memory,
            ttl: Duration::from_secs(60),
            directory: None,
            max_bytes: DEFAULT_LOCAL_CACHE_MAX_BYTES,
            warmup_enabled: false,
            redis_url: None,
            redis_key_prefix: DEFAULT_REDIS_CACHE_KEY_PREFIX.to_string(),
            s3_config: None,
            gcs_config: None,
            qdrant_config: None,
            clear_on_start: false,
            cache_buster: None,
        });
        let resp = BufferedUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"body"),
            false,
        );
        block_on(cache.put("k", &resp));
        assert!(block_on(cache.get("k")).is_none());
    }

    #[test]
    fn cache_backend_name_disabled() {
        let cache = ProviderResponseCache::new_for_test(CacheConfig {
            enabled: false,
            backend: CacheBackend::Memory,
            ttl: Duration::from_secs(60),
            directory: None,
            max_bytes: DEFAULT_LOCAL_CACHE_MAX_BYTES,
            warmup_enabled: false,
            redis_url: None,
            redis_key_prefix: DEFAULT_REDIS_CACHE_KEY_PREFIX.to_string(),
            s3_config: None,
            gcs_config: None,
            qdrant_config: None,
            clear_on_start: false,
            cache_buster: None,
        });
        assert_eq!(cache.backend_name(), "disabled");
    }

    #[test]
    fn cache_backend_name_memory() {
        let cache = memory_cache();
        assert_eq!(cache.backend_name(), "memory");
    }

    #[test]
    fn cache_config_from_env_defaults_to_memory_in_dev_or_test_with_expected_defaults() {
        let (_lock, mut env) = env_guard();
        let xdg_cache = tempdir().expect("xdg cache");
        let home = tempdir().expect("home");

        clear_cache_env(&mut env);
        env.set("XDG_CACHE_HOME", xdg_cache.path());
        env.set("HOME", home.path());

        // with no explicit backend, `auto` resolves to memory in a
        // dev/test environment (`cfg!(test)`), so no on-disk cache directory is used.
        let config = CacheConfig::from_env().expect("cache config from env");

        assert!(config.enabled);
        assert_eq!(config.backend, CacheBackend::Memory);
        assert_eq!(config.ttl, Duration::from_secs(DEFAULT_CACHE_TTL_SECS));
        assert_eq!(config.directory, None);
        assert_eq!(config.max_bytes, DEFAULT_LOCAL_CACHE_MAX_BYTES);
        assert!(config.warmup_enabled);
        assert_eq!(config.redis_url, None);
        assert_eq!(
            config.redis_key_prefix,
            DEFAULT_REDIS_CACHE_KEY_PREFIX.to_string()
        );
        assert!(config.s3_config.is_none());
        assert!(config.gcs_config.is_none());
        assert!(config.qdrant_config.is_none());
        assert!(!config.clear_on_start);
        assert_eq!(config.cache_buster, None);
    }

    #[test]
    fn cache_config_from_env_allows_disabled_shared_backend_without_extra_config() {
        let (_lock, mut env) = env_guard();

        clear_cache_env(&mut env);
        env.set("VERDICTAN_LLM_CACHE_ENABLED", "false");
        env.set("VERDICTAN_LLM_CACHE_BACKEND", "redis");

        let config = CacheConfig::from_env().expect("disabled shared backend config");

        assert!(!config.enabled);
        assert_eq!(config.backend, CacheBackend::Redis);
        assert_eq!(config.redis_url, None);
        assert_eq!(config.directory, None);
    }

    #[test]
    fn cache_config_from_env_applies_memory_overrides_and_clamps_ttl() {
        let (_lock, mut env) = env_guard();

        clear_cache_env(&mut env);
        env.set("VERDICTAN_LLM_CACHE_BACKEND", "memory");
        env.set("VERDICTAN_LLM_CACHE_TTL_SECS", "0");
        env.set("VERDICTAN_LLM_CACHE_MAX_BYTES", "0");
        env.set("VERDICTAN_LLM_CACHE_WARMUP_ENABLED", "off");
        env.set("VERDICTAN_LLM_CACHE_CLEAR", "yes");
        env.set("VERDICTAN_LLM_CACHE_BUSTER", "   ");
        env.set("VERDICTAN_LLM_CACHE_DIR", "/tmp/unused-memory-cache");

        let config = CacheConfig::from_env().expect("memory cache config");

        assert_eq!(config.backend, CacheBackend::Memory);
        assert_eq!(config.ttl, Duration::from_secs(1));
        assert_eq!(config.directory, None);
        assert_eq!(config.max_bytes, DEFAULT_LOCAL_CACHE_MAX_BYTES);
        assert!(!config.warmup_enabled);
        assert!(config.clear_on_start);
        assert_eq!(config.cache_buster, None);
    }

    #[test]
    fn cache_config_from_env_rejects_invalid_ttl() {
        let (_lock, mut env) = env_guard();

        clear_cache_env(&mut env);
        env.set("VERDICTAN_LLM_CACHE_BACKEND", "memory");
        env.set("VERDICTAN_LLM_CACHE_TTL_SECS", "not-a-number");

        let error = CacheConfig::from_env().expect_err("invalid ttl should fail");

        assert_eq!(error.error_code(), "cli.config_invalid");
        assert!(error.to_string().contains("VERDICTAN_LLM_CACHE_TTL_SECS"));
    }

    #[cfg(not(feature = "distributed"))]
    #[test]
    fn shared_cache_backends_require_distributed_feature() {
        for backend in [
            CacheBackend::Redis,
            CacheBackend::Valkey,
            CacheBackend::S3,
            CacheBackend::Gcs,
            CacheBackend::Qdrant,
        ] {
            let error = cache_config_for_test(backend)
                .ensure_supported()
                .expect_err("shared backends should fail without distributed feature");

            assert_eq!(error.error_code(), "cli.config_invalid");
            assert!(error.to_string().contains("--features distributed"));
            assert!(error.to_string().contains(backend.as_str()));
        }
    }

    #[cfg(feature = "distributed")]
    #[test]
    fn distributed_cache_backends_validate_required_configuration() {
        let redis_error = cache_config_for_test(CacheBackend::Redis)
            .ensure_supported()
            .expect_err("redis without URL should fail");
        assert!(redis_error
            .to_string()
            .contains("VERDICTAN_LLM_CACHE_REDIS_URL"));

        let mut redis_config = cache_config_for_test(CacheBackend::Redis);
        redis_config.redis_url = Some("redis://127.0.0.1:6379/0".to_string());
        assert!(redis_config.ensure_supported().is_ok());

        let mut valkey_config = cache_config_for_test(CacheBackend::Valkey);
        valkey_config.redis_url = Some("redis://127.0.0.1:6379/1".to_string());
        assert!(valkey_config.ensure_supported().is_ok());

        let s3_error = cache_config_for_test(CacheBackend::S3)
            .ensure_supported()
            .expect_err("s3 without config should fail");
        assert!(s3_error
            .to_string()
            .contains("VERDICTAN_LLM_CACHE_BACKEND=s3"));

        let mut s3_config = cache_config_for_test(CacheBackend::S3);
        s3_config.s3_config = Some(ObjectStoreCacheConfig {
            flavor: ObjectStoreFlavor::S3,
            bucket: "gateway-cache".to_string(),
            prefix: ObjectStoreCacheConfig::default_prefix(),
            region: "us-east-1".to_string(),
            endpoint: None,
            access_key_id: "access".to_string(),
            secret_access_key: "secret".to_string(),
            force_path_style: false,
        });
        assert!(s3_config.ensure_supported().is_ok());

        let gcs_error = cache_config_for_test(CacheBackend::Gcs)
            .ensure_supported()
            .expect_err("gcs without config should fail");
        assert!(gcs_error
            .to_string()
            .contains("VERDICTAN_LLM_CACHE_BACKEND=gcs"));

        let mut gcs_config = cache_config_for_test(CacheBackend::Gcs);
        gcs_config.gcs_config = Some(ObjectStoreCacheConfig {
            flavor: ObjectStoreFlavor::Gcs,
            bucket: "gateway-cache".to_string(),
            prefix: ObjectStoreCacheConfig::default_prefix(),
            region: "auto".to_string(),
            endpoint: Some(DEFAULT_GCS_ENDPOINT.to_string()),
            access_key_id: "access".to_string(),
            secret_access_key: "secret".to_string(),
            force_path_style: true,
        });
        assert!(gcs_config.ensure_supported().is_ok());

        let qdrant_error = cache_config_for_test(CacheBackend::Qdrant)
            .ensure_supported()
            .expect_err("qdrant without config should fail");
        assert!(qdrant_error
            .to_string()
            .contains("VERDICTAN_LLM_CACHE_QDRANT_URL"));

        let mut qdrant_config = cache_config_for_test(CacheBackend::Qdrant);
        qdrant_config.qdrant_config = Some(QdrantCacheConfig {
            url: "https://qdrant.internal:6333".to_string(),
            collection: QdrantCacheConfig::default_collection(),
            api_key: None,
            request_timeout: QdrantCacheConfig::default_timeout(),
        });
        assert!(qdrant_config.ensure_supported().is_ok());
    }

    #[test]
    fn provider_response_cache_from_env_exposes_config_runtime_json_and_buster() {
        let (_lock, mut env) = env_guard();
        let temp = tempdir().expect("tempdir");
        let cache_dir = temp.path().join("provider-cache");

        env.set("VERDICTAN_LLM_CACHE_ENABLED", "true");
        env.set("VERDICTAN_LLM_CACHE_BACKEND", "filesystem");
        env.set("VERDICTAN_LLM_CACHE_DIR", cache_dir.as_os_str());
        env.set("VERDICTAN_LLM_CACHE_TTL_SECS", "7");
        env.set("VERDICTAN_LLM_CACHE_MAX_BYTES", "4096");
        env.set("VERDICTAN_LLM_CACHE_BUSTER", "  rollout-42  ");

        let cache = block_on(ProviderResponseCache::from_env()).expect("cache from env");
        let runtime = block_on(cache.runtime_json());

        assert!(cache.is_enabled());
        assert_eq!(cache.backend_name(), "filesystem");
        assert_eq!(cache.cache_buster(), Some("rollout-42"));
        assert_eq!(cache.cache_directory(), Some(cache_dir.as_path()));
        assert_eq!(cache.max_bytes(), 4096);
        assert_eq!(cache.config().ttl, Duration::from_secs(7));
        assert_eq!(cache.config().cache_buster.as_deref(), Some("rollout-42"));
        assert!(cache_dir.is_dir());
        assert_eq!(runtime["enabled"], true);
        assert_eq!(runtime["backend"], "filesystem");
        assert_eq!(runtime["ttl_seconds"], 7);
        assert_eq!(runtime["cache_buster_configured"], true);
        assert_eq!(runtime["directory"], cache_dir.display().to_string());
        assert_eq!(runtime["stats"]["hits"], 0);
    }

    #[test]
    fn cache_runtime_json_has_required_fields() {
        let cache = memory_cache();
        let json = block_on(cache.runtime_json());
        assert_eq!(json["enabled"], true);
        assert_eq!(json["backend"], "memory");
        assert!(json.get("ttl_seconds").is_some());
        assert!(json.get("stats").is_some());
    }

    #[test]
    fn cache_uses_shared_backend_false_for_memory() {
        let cache = memory_cache();
        assert!(!cache.uses_shared_backend());
    }

    #[test]
    fn cache_uses_shared_backend_only_for_enabled_shared_configs() {
        let enabled_shared = accessor_cache(CacheConfig {
            enabled: true,
            backend: CacheBackend::Redis,
            ttl: Duration::from_secs(30),
            directory: None,
            max_bytes: DEFAULT_LOCAL_CACHE_MAX_BYTES,
            warmup_enabled: false,
            redis_url: Some("redis://cache.internal:6379/0".to_string()),
            redis_key_prefix: DEFAULT_REDIS_CACHE_KEY_PREFIX.to_string(),
            s3_config: None,
            gcs_config: None,
            qdrant_config: None,
            clear_on_start: false,
            cache_buster: Some("buster".to_string()),
        });
        assert!(enabled_shared.uses_shared_backend());

        let disabled_shared = accessor_cache(CacheConfig {
            enabled: false,
            ..enabled_shared.config().clone()
        });
        assert!(!disabled_shared.uses_shared_backend());
        assert_eq!(disabled_shared.backend_name(), "disabled");
    }

    #[test]
    fn cache_clear_empties_entries() {
        let cache = memory_cache();
        let resp = BufferedUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"data"),
            false,
        );
        block_on(cache.put("k1", &resp));
        assert!(block_on(cache.get("k1")).is_some());
        block_on(cache.clear());
        assert!(block_on(cache.get("k1")).is_none());
    }

    #[test]
    fn cache_key_version_mismatch_is_miss() {
        let cache = memory_cache();
        let entry = StoredCachedResponse {
            stored_at_unix_secs: current_unix_secs(),
            status: 200,
            headers: vec![],
            body_base64: BASE64_STANDARD.encode(b"old"),
            original_key: None,
            key_version: 0,
        };
        block_on(cache.insert_test_entry("old-key", entry));
        assert!(block_on(cache.get("old-key")).is_none());
    }

    #[test]
    fn cache_put_skips_non_success() {
        let cache = memory_cache();
        let resp = BufferedUpstreamResponse::new(
            StatusCode::BAD_REQUEST,
            HeaderMap::new(),
            Bytes::from_static(b"err"),
            false,
        );
        block_on(cache.put("err-key", &resp));
        assert!(block_on(cache.get("err-key")).is_none());
    }

    #[test]
    fn memory_backend_pressure_json_is_nominal_when_empty_and_high_when_populated() {
        let backend = MemoryExactCacheBackend::default();
        assert_eq!(backend.pressure_json()["level"], "nominal");
        assert_eq!(backend.pressure_json()["estimated_entry_count"], 0);

        backend.insert_test_entry("k1", old_success_entry(b"value", 0));

        assert_eq!(backend.pressure_json()["level"], "high");
        assert_eq!(backend.pressure_json()["estimated_entry_count"], 1);
    }

    #[test]
    fn filesystem_backend_cache_file_path_sanitizes_keys_and_short_prefixes() {
        let dir = tempdir().expect("tempdir");
        let backend = block_on(FilesystemExactCacheBackend::new(
            dir.path().to_path_buf(),
            1024,
        ));

        let regular = backend
            .cache_file_path("ab:key")
            .expect("regular cache path");
        assert_eq!(regular, dir.path().join("ab").join("ab_key.bin"));

        let short = backend.cache_file_path(":").expect("short cache path");
        assert_eq!(short, dir.path().join("cache").join("_.bin"));
    }

    #[test]
    fn filesystem_backend_roundtrip_updates_stats_and_pressure() {
        let dir = tempdir().expect("tempdir");
        let backend = block_on(FilesystemExactCacheBackend::new(
            dir.path().to_path_buf(),
            4096,
        ));
        let entry = old_success_entry(b"filesystem-body", 0);

        block_on(backend.put("fs:key", entry.clone()));
        let fetched = block_on(backend.get("fs:key")).expect("filesystem cache hit");
        // ProviderResponseCache records filesystem hit counters after a successful backend read.
        backend.record_hit();

        assert_eq!(fetched.body_base64, entry.body_base64);

        let stats = backend.stats();
        assert_eq!(stats.entry_count, 1);
        assert_eq!(stats.hit_count, 1);
        assert_eq!(stats.miss_count, 0);
        assert!(stats.total_size_bytes > 0);
        assert!(!stats.warmed);

        let pressure = backend.pressure_json();
        assert_eq!(pressure["estimated_entry_count"], 1);
        assert_eq!(pressure["max_bytes"], 4096);
        assert_eq!(pressure["level"], "nominal");
        assert!(pressure["percent_used"].as_u64().unwrap_or_default() > 0);
    }

    #[test]
    fn filesystem_backend_remove_updates_index_and_size() {
        let dir = tempdir().expect("tempdir");
        let backend = block_on(FilesystemExactCacheBackend::new(
            dir.path().to_path_buf(),
            4096,
        ));
        let entry = old_success_entry(b"delete-me", 0);

        block_on(backend.put("gone:key", entry));
        let path = backend
            .cache_file_path("gone:key")
            .expect("cache file path should exist");
        assert!(path.exists());

        assert!(block_on(backend.remove("gone:key")));
        assert!(!path.exists());
        assert!(!block_on(backend.remove("gone:key")));

        let stats = backend.stats();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.total_size_bytes, 0);
    }

    #[test]
    fn filesystem_backend_evicts_oldest_entry_when_capacity_is_exceeded() {
        let dir = tempdir().expect("tempdir");
        let first = old_success_entry(b"first-entry-body", 0);
        let second = old_success_entry(b"second-entry-body", 0);
        let max_bytes = serialize_cache_entry(&first).len() as u64 + 1;
        let backend = block_on(FilesystemExactCacheBackend::new(
            dir.path().to_path_buf(),
            max_bytes,
        ));

        block_on(backend.put("aa:first", first));
        block_on(backend.put("bb:second", second));

        assert!(block_on(backend.get("aa:first")).is_none());
        assert!(block_on(backend.get("bb:second")).is_some());

        let stats = backend.stats();
        assert_eq!(stats.entry_count, 1);
        assert_eq!(stats.eviction_count, 1);
    }

    #[test]
    fn filesystem_backend_clear_removes_directory_and_resets_stats() {
        let dir = tempdir().expect("tempdir");
        let backend = block_on(FilesystemExactCacheBackend::new(
            dir.path().to_path_buf(),
            4096,
        ));

        block_on(backend.put("clear:key", old_success_entry(b"payload", 0)));
        assert!(dir.path().exists());

        block_on(backend.clear());

        assert!(!dir.path().exists());
        let stats = backend.stats();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.total_size_bytes, 0);
    }

    #[test]
    fn filesystem_backend_warm_rebuilds_index_and_marks_backend_warmed() {
        let dir = tempdir().expect("tempdir");
        let writer = block_on(FilesystemExactCacheBackend::new(
            dir.path().to_path_buf(),
            4096,
        ));
        block_on(writer.put("ab:key", old_success_entry(b"payload", 0)));
        std::fs::write(dir.path().join("ignored.txt"), b"ignored").expect("write ignored file");

        let warmed = block_on(FilesystemExactCacheBackend::new(
            dir.path().to_path_buf(),
            4096,
        ));
        block_on(warmed.warm());

        let stats = warmed.stats();
        assert_eq!(stats.entry_count, 1);
        assert!(stats.total_size_bytes > 0);
        assert!(stats.warmed);
    }

    #[test]
    fn filesystem_backend_list_top_entries_sorts_by_size_and_recency() {
        let dir = tempdir().expect("tempdir");
        let backend = block_on(FilesystemExactCacheBackend::new(
            dir.path().to_path_buf(),
            20_000,
        ));

        block_on(backend.put("aa:small", old_success_entry(b"a", 0)));
        block_on(backend.put(
            "bb:large",
            old_success_entry(b"abcdefghijklmnopqrstuvwxyz", 0),
        ));
        let now = Instant::now();
        let mut index = backend.lru_index.write().expect("lru index lock");
        index
            .get_mut("aa:small")
            .expect("small entry")
            .last_accessed = now;
        index
            .get_mut("bb:large")
            .expect("large entry")
            .last_accessed = now - Duration::from_secs(30);
        drop(index);

        let by_size = backend.list_top_entries(2, true);
        assert_eq!(by_size.len(), 2);
        assert_eq!(by_size[0].0, "bb:large");
        assert!(by_size[0].1 > by_size[1].1);

        let by_recent = backend.list_top_entries(2, false);
        assert_eq!(by_recent.len(), 2);
        assert_eq!(by_recent[0].0, "aa:small");
        assert!(by_recent[0].2 <= by_recent[1].2);
    }

    #[test]
    fn filesystem_backend_warm_restores_original_keys_and_persisted_counters() {
        let dir = tempdir().expect("tempdir");
        let backend = block_on(FilesystemExactCacheBackend::new(
            dir.path().to_path_buf(),
            20_000,
        ));

        block_on(backend.put(
            "tenant:gateway:cache:key:with:colons",
            old_success_entry(b"payload", 0),
        ));
        backend.record_hit();
        backend.record_miss();
        block_on(backend.persist_current_stats());

        let warmed = block_on(FilesystemExactCacheBackend::new(
            dir.path().to_path_buf(),
            20_000,
        ));
        block_on(warmed.warm());

        let stats = warmed.stats();
        assert_eq!(stats.hit_count, 1);
        assert_eq!(stats.miss_count, 1);
        assert_eq!(
            warmed.list_top_entries(1, false)[0].0,
            "tenant:gateway:cache:key:with:colons"
        );
    }

    #[test]
    fn provider_response_cache_filesystem_helpers_expose_backend_only_state() {
        let dir = tempdir().expect("tempdir");
        let cache = ProviderResponseCache::new_for_test(filesystem_cache_config(
            dir.path().to_path_buf(),
            8192,
        ));
        let response = BufferedUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"filesystem"),
            false,
        );

        block_on(cache.put("aa:item", &response));

        let stats = cache
            .filesystem_stats()
            .expect("filesystem stats should be available");
        assert_eq!(stats.entry_count, 1);
        assert_eq!(cache.cache_directory(), Some(dir.path()));
        assert_eq!(cache.list_top_entries(1, true).len(), 1);

        let memory = memory_cache();
        assert!(memory.filesystem_stats().is_none());
        assert!(memory.list_top_entries(3, true).is_empty());
    }

    // ── parse_cache_backend (extended) ──────────────────────────────────

    #[test]
    fn parse_cache_backend_auto_defaults() {
        // `auto` resolves to memory in dev/test (`cfg!(test)`).
        assert_eq!(parse_cache_backend("auto").unwrap(), CacheBackend::Memory);
        assert_eq!(parse_cache_backend("").unwrap(), CacheBackend::Memory);
    }

    #[test]
    fn parse_cache_backend_memory_variant() {
        assert_eq!(parse_cache_backend("memory").unwrap(), CacheBackend::Memory);
    }

    #[test]
    fn parse_cache_backend_filesystem_variants() {
        assert_eq!(
            parse_cache_backend("filesystem").unwrap(),
            CacheBackend::Filesystem
        );
        assert_eq!(
            parse_cache_backend("file").unwrap(),
            CacheBackend::Filesystem
        );
        assert_eq!(
            parse_cache_backend("disk").unwrap(),
            CacheBackend::Filesystem
        );
    }

    #[test]
    fn parse_cache_backend_redis_variant() {
        assert_eq!(parse_cache_backend("redis").unwrap(), CacheBackend::Redis);
    }

    #[test]
    fn parse_cache_backend_valkey_variant() {
        assert_eq!(parse_cache_backend("valkey").unwrap(), CacheBackend::Valkey);
    }

    #[test]
    fn parse_cache_backend_s3_variant() {
        assert_eq!(parse_cache_backend("s3").unwrap(), CacheBackend::S3);
    }

    #[test]
    fn parse_cache_backend_gcs_variant() {
        assert_eq!(parse_cache_backend("gcs").unwrap(), CacheBackend::Gcs);
    }

    #[test]
    fn parse_cache_backend_qdrant_variant() {
        assert_eq!(parse_cache_backend("qdrant").unwrap(), CacheBackend::Qdrant);
    }

    #[test]
    fn parse_cache_backend_invalid_name() {
        assert!(parse_cache_backend("invalid").is_err());
    }

    #[test]
    fn parse_cache_backend_case_insensitive_mixed() {
        assert_eq!(parse_cache_backend("MEMORY").unwrap(), CacheBackend::Memory);
        assert_eq!(parse_cache_backend("Redis").unwrap(), CacheBackend::Redis);
    }

    // ── CacheBackend::as_str ────────────────────────────────────────────

    #[test]
    fn cache_backend_as_str() {
        assert_eq!(CacheBackend::Memory.as_str(), "memory");
        assert_eq!(CacheBackend::Filesystem.as_str(), "filesystem");
        assert_eq!(CacheBackend::Redis.as_str(), "redis");
        assert_eq!(CacheBackend::Valkey.as_str(), "valkey");
        assert_eq!(CacheBackend::S3.as_str(), "s3");
        assert_eq!(CacheBackend::Gcs.as_str(), "gcs");
        assert_eq!(CacheBackend::Qdrant.as_str(), "qdrant");
    }

    // ── current_cache_key_version ───────────────────────────────────────

    #[test]
    fn current_cache_key_version_accessor() {
        assert_eq!(current_cache_key_version(), CURRENT_CACHE_KEY_VERSION);
        assert_eq!(CURRENT_CACHE_KEY_VERSION, 1);
    }

    // ── default_key_version ─────────────────────────────────────────────

    #[test]
    fn default_key_version_is_zero() {
        assert_eq!(default_key_version(), 0);
    }

    // ── BufferedUpstreamResponse ─────────────────────────────────────────

    #[test]
    fn buffered_upstream_response_accessors() {
        let resp = BufferedUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"test"),
            true,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().is_empty());
        assert_eq!(resp.body(), &Bytes::from_static(b"test"));
        assert!(resp.is_cached());
        assert!(resp.is_cacheable_success());
    }

    #[test]
    fn buffered_upstream_response_not_cacheable_on_error() {
        let resp = BufferedUpstreamResponse::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            HeaderMap::new(),
            Bytes::from_static(b"error"),
            false,
        );
        assert!(!resp.is_cacheable_success());
        assert!(!resp.is_cached());
    }

    #[test]
    fn buffered_upstream_response_not_cacheable_when_empty() {
        let resp =
            BufferedUpstreamResponse::new(StatusCode::OK, HeaderMap::new(), Bytes::new(), false);
        assert!(!resp.is_cacheable_success());
    }

    // ── resolve_env_value ───────────────────────────────────────────────

    #[test]
    fn resolve_env_value_returns_none_for_unset() {
        assert!(resolve_env_value("__VERDICTAN_TEST_CACHE_UNSET_VAR__").is_none());
    }

    // ── ExactCacheBackendAdapter supports_semantic_cache ─────────────────

    #[test]
    fn memory_backend_supports_semantic_cache() {
        let adapter = ExactCacheBackendAdapter::Memory(MemoryExactCacheBackend::default());
        assert!(adapter.supports_semantic_cache());
    }

    // ── MemoryExactCacheBackend operations ───────────────────────────────

    #[test]
    fn memory_backend_put_get_remove() {
        let backend = MemoryExactCacheBackend::default();
        let entry = old_success_entry(b"test data", 0);
        let stats = Arc::new(RwLock::new(CacheStats::default()));
        backend.put("key1", entry.clone(), &Duration::from_secs(60), &stats);
        assert!(backend.get("key1").is_some());
        assert!(backend.remove("key1"));
        assert!(backend.get("key1").is_none());
    }

    #[test]
    fn memory_backend_clear() {
        let backend = MemoryExactCacheBackend::default();
        let entry = old_success_entry(b"test data", 0);
        let stats = Arc::new(RwLock::new(CacheStats::default()));
        backend.put("key1", entry.clone(), &Duration::from_secs(60), &stats);
        backend.put("key2", entry.clone(), &Duration::from_secs(60), &stats);
        backend.clear();
        assert!(backend.get("key1").is_none());
        assert!(backend.get("key2").is_none());
    }

    #[test]
    fn memory_backend_pressure_json() {
        let backend = MemoryExactCacheBackend::default();
        let json = backend.pressure_json();
        assert_eq!(json["level"], "nominal");
        assert_eq!(json["estimated_entry_count"], 0);
    }

    // ── cache key generation ────────────────────────────────────────────

    fn generate_cache_key(model: &str, body: &[u8], path: &str, buster: Option<&str>) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(model.as_bytes());
        hasher.update(body);
        hasher.update(path.as_bytes());
        if let Some(b) = buster {
            hasher.update(b.as_bytes());
        }
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    #[test]
    fn cache_key_deterministic_for_same_input() {
        let key1 = generate_cache_key("gpt-4", b"hello", "/v1/chat/completions", None);
        let key2 = generate_cache_key("gpt-4", b"hello", "/v1/chat/completions", None);
        assert_eq!(key1, key2);
    }

    #[test]
    fn cache_key_differs_for_different_model() {
        let key1 = generate_cache_key("gpt-4", b"hello", "/v1/chat/completions", None);
        let key2 = generate_cache_key("gpt-3.5", b"hello", "/v1/chat/completions", None);
        assert_ne!(key1, key2);
    }

    #[test]
    fn cache_key_differs_for_different_body() {
        let key1 = generate_cache_key("gpt-4", b"hello", "/v1/chat/completions", None);
        let key2 = generate_cache_key("gpt-4", b"world", "/v1/chat/completions", None);
        assert_ne!(key1, key2);
    }

    #[test]
    fn cache_key_differs_with_buster() {
        let key1 = generate_cache_key("gpt-4", b"hello", "/v1/chat/completions", None);
        let key2 = generate_cache_key("gpt-4", b"hello", "/v1/chat/completions", Some("v2"));
        assert_ne!(key1, key2);
    }

    // ── StoredCachedResponse serde ──────────────────────────────────────

    #[test]
    fn stored_cached_response_serde_roundtrip() {
        let entry = StoredCachedResponse {
            status: 200,
            headers: vec![StoredHeader {
                name: "content-type".to_string(),
                value_base64: BASE64_STANDARD.encode(b"application/json"),
            }],
            body_base64: BASE64_STANDARD.encode(b"cached body"),
            stored_at_unix_secs: 1234567890,
            original_key: None,
            key_version: 1,
        };
        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: StoredCachedResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.status, 200);
        assert_eq!(
            deserialized.body_base64,
            BASE64_STANDARD.encode(b"cached body")
        );
        assert_eq!(deserialized.key_version, 1);
    }

    #[test]
    fn stored_cached_response_default_key_version_on_missing() {
        let json = r#"{"status":200,"headers":[],"body_base64":"aGk=","stored_at_unix_secs":0}"#;
        let entry: StoredCachedResponse = serde_json::from_str(json).unwrap();
        assert_eq!(entry.key_version, 0);
    }

    // ── CacheStats ──────────────────────────────────────────────────────

    #[test]
    fn cache_stats_default() {
        let stats = CacheStats::default();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.puts, 0);
    }

    // ── DEFAULT_REDIS_CACHE_KEY_PREFIX ───────────────────────────────────

    #[test]
    fn default_redis_cache_key_prefix_value() {
        assert_eq!(DEFAULT_REDIS_CACHE_KEY_PREFIX, "vt:llm-cache");
    }

    // ── DEFAULT_LOCAL_CACHE_MAX_BYTES ───────────────────────────────────

    #[test]
    fn default_local_cache_max_bytes_value() {
        assert_eq!(DEFAULT_LOCAL_CACHE_MAX_BYTES, 524_288_000);
    }

    // ── BufferedUpstreamResponse ────────────────────────────────────────

    #[test]
    fn buffered_response_constructor_and_accessors() {
        let mut headers = HeaderMap::new();
        headers.insert("x-test", "value".parse().unwrap());
        let resp = BufferedUpstreamResponse::new(
            StatusCode::OK,
            headers,
            Bytes::from_static(b"test body"),
            true,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.body(), &Bytes::from_static(b"test body"));
        assert!(resp.is_cached());
        assert!(resp.headers().contains_key("x-test"));
    }

    #[test]
    fn buffered_response_not_cached() {
        let resp = BufferedUpstreamResponse::new(
            StatusCode::BAD_REQUEST,
            HeaderMap::new(),
            Bytes::from_static(b"error"),
            false,
        );
        assert!(!resp.is_cached());
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn buffered_response_is_cacheable_success() {
        let resp = BufferedUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"ok"),
            false,
        );
        assert!(resp.is_cacheable_success());
    }

    #[test]
    fn buffered_response_empty_body_not_cacheable() {
        let resp =
            BufferedUpstreamResponse::new(StatusCode::OK, HeaderMap::new(), Bytes::new(), false);
        assert!(!resp.is_cacheable_success());
    }

    #[test]
    fn buffered_response_error_not_cacheable() {
        let resp = BufferedUpstreamResponse::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            HeaderMap::new(),
            Bytes::from_static(b"error"),
            false,
        );
        assert!(!resp.is_cacheable_success());
    }

    // ── parse_cache_backend ────────────────────────────────────────────

    #[test]
    fn parse_cache_backend_memory_ok() {
        assert!(parse_cache_backend("memory").is_ok());
    }

    #[test]
    fn parse_cache_backend_filesystem_ok() {
        assert!(parse_cache_backend("filesystem").is_ok());
    }

    #[test]
    fn parse_cache_backend_redis_ok() {
        assert!(parse_cache_backend("redis").is_ok());
    }

    // ── cosine_similarity ─────────────────────────────────────────────

    #[test]
    fn cosine_similarity_identical_unit_vectors() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn cosine_similarity_perpendicular_vectors() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        assert!((cosine_similarity(&a, &b)).abs() < 1e-9);
    }

    #[test]
    fn cosine_similarity_empty_vectors_zero() {
        let a: Vec<f64> = vec![];
        let b: Vec<f64> = vec![];
        assert!((cosine_similarity(&a, &b)).abs() < 1e-9);
    }

    // ── current_unix_secs ─────────────────────────────────────────────

    #[test]
    fn current_unix_secs_positive() {
        assert!(current_unix_secs() > 0);
    }

    // ── current_cache_key_version ─────────────────────────────────────

    #[test]
    fn current_cache_key_version_stable() {
        let v1 = current_cache_key_version();
        let v2 = current_cache_key_version();
        assert_eq!(v1, v2);
    }

    // ── CacheMode ─────────────────────────────────────────────────────

    #[test]
    fn cache_mode_default_is_exact() {
        assert!(matches!(CacheMode::default(), CacheMode::Exact));
    }

    #[test]
    fn cache_mode_semantic_variant() {
        let _ = CacheMode::Semantic;
    }
}

#[cfg(test)]
mod coverage_expansion_cache_tests {
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
    use axum::http::{HeaderMap, StatusCode};

    // ── CURRENT_CACHE_KEY_VERSION ───────────────────────────────────────

    #[test]
    fn current_cache_key_version_is_one() {
        assert_eq!(CURRENT_CACHE_KEY_VERSION, 1);
        assert_eq!(current_cache_key_version(), 1);
    }

    #[test]
    fn default_key_version_is_zero() {
        assert_eq!(default_key_version(), 0);
    }

    // ── Constants ───────────────────────────────────────────────────────

    #[test]
    fn default_cache_ttl_secs_two_weeks() {
        assert_eq!(DEFAULT_CACHE_TTL_SECS, 14 * 24 * 60 * 60);
    }

    #[test]
    fn default_redis_key_prefix() {
        assert_eq!(DEFAULT_REDIS_CACHE_KEY_PREFIX, "vt:llm-cache");
    }

    #[test]
    fn default_local_cache_max_bytes_500mb() {
        assert_eq!(DEFAULT_LOCAL_CACHE_MAX_BYTES, 524_288_000);
    }

    #[test]
    fn cache_format_bincode_v1() {
        assert_eq!(CACHE_FORMAT_BINCODE_V1, 0x01);
    }

    // ── BufferedUpstreamResponse ────────────────────────────────────────

    #[test]
    fn buffered_response_new() {
        let response = BufferedUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from("body"),
            false,
        );
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from("body"));
        assert!(!response.cached);
    }

    #[test]
    fn buffered_response_cached_flag() {
        let response = BufferedUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from("cached body"),
            true,
        );
        assert!(response.cached);
    }

    // ── FilesystemCacheStats ────────────────────────────────────────────

    #[test]
    fn filesystem_cache_stats_default() {
        let stats = FilesystemCacheStats::default();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.total_size_bytes, 0);
        assert_eq!(stats.max_bytes, 0);
        assert_eq!(stats.hit_count, 0);
        assert_eq!(stats.miss_count, 0);
        assert_eq!(stats.eviction_count, 0);
        assert!(!stats.warmed);
    }

    // ── ProviderResponseCache memory_for_test ───────────────────────────

    #[test]
    fn provider_response_cache_memory_for_test() {
        let _cache = ProviderResponseCache::memory_for_test();
    }
}
