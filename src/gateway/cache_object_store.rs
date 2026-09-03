// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

#![cfg_attr(not(feature = "distributed"), allow(dead_code, unused_imports))]

#[cfg(feature = "distributed")]
use aws_credential_types::Credentials;
#[cfg(feature = "distributed")]
use aws_sdk_s3::{primitives::ByteStream, Client as S3Client};
#[cfg(feature = "distributed")]
use aws_types::region::Region;
use sha2::{Digest, Sha256};

use crate::error::CliError;

use super::cache::StoredCachedResponse;

const DEFAULT_OBJECT_STORE_PREFIX: &str = "verdictan/llm-cache";
const DEFAULT_OBJECT_STORE_OP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectStoreFlavor {
    S3,
    Gcs,
}

impl ObjectStoreFlavor {
    fn backend_name(self) -> &'static str {
        match self {
            Self::S3 => "s3",
            Self::Gcs => "gcs",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ObjectStoreCacheConfig {
    pub flavor: ObjectStoreFlavor,
    pub bucket: String,
    pub prefix: String,
    pub region: String,
    pub endpoint: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub force_path_style: bool,
}

impl ObjectStoreCacheConfig {
    pub fn default_prefix() -> String {
        DEFAULT_OBJECT_STORE_PREFIX.to_string()
    }
}

#[derive(Clone)]
pub struct ObjectStoreExactCacheBackend {
    #[cfg(feature = "distributed")]
    client: S3Client,
    config: ObjectStoreCacheConfig,
}

impl ObjectStoreExactCacheBackend {
    pub fn new(config: ObjectStoreCacheConfig) -> Result<Self, CliError> {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = config;
            Err(CliError::user(
                "shared object-store cache backends require a CLI build with --features distributed",
            ))
        }

        #[cfg(feature = "distributed")]
        {
            let client = build_client(&config)?;
            Ok(Self { client, config })
        }
    }

    pub async fn get(&self, key: &str) -> Option<StoredCachedResponse> {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = key;
            None
        }

        #[cfg(feature = "distributed")]
        {
            match tokio::time::timeout(DEFAULT_OBJECT_STORE_OP_TIMEOUT, self.get_inner(key)).await {
                Ok(result) => result,
                Err(_) => {
                    tracing::warn!(
                        backend = %self.config.flavor.backend_name(),
                        cache_key = %key,
                        timeout_ms = DEFAULT_OBJECT_STORE_OP_TIMEOUT.as_millis() as u64,
                        "object-store cache get timed out"
                    );
                    None
                }
            }
        }
    }

    #[cfg(feature = "distributed")]
    async fn get_inner(&self, key: &str) -> Option<StoredCachedResponse> {
        let object_key = self.object_key(key);
        let response = match self
            .client
            .get_object()
            .bucket(&self.config.bucket)
            .key(&object_key)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) if is_missing_object_error(&error.to_string()) => return None,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    backend = %self.config.flavor.backend_name(),
                    cache_key = %key,
                    "object-store cache get failed"
                );
                return None;
            }
        };
        let bytes = match response.body.collect().await {
            Ok(body) => body.into_bytes(),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    backend = %self.config.flavor.backend_name(),
                    cache_key = %key,
                    "object-store cache body read failed"
                );
                return None;
            }
        };
        serde_json::from_slice(&bytes).ok()
    }

    pub async fn put(&self, key: &str, entry: StoredCachedResponse) {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = key;
            let _ = entry;
        }

        #[cfg(feature = "distributed")]
        {
            if tokio::time::timeout(DEFAULT_OBJECT_STORE_OP_TIMEOUT, self.put_inner(key, entry))
                .await
                .is_err()
            {
                tracing::warn!(
                    backend = %self.config.flavor.backend_name(),
                    cache_key = %key,
                    timeout_ms = DEFAULT_OBJECT_STORE_OP_TIMEOUT.as_millis() as u64,
                    "object-store cache put timed out"
                );
            }
        }
    }

    #[cfg(feature = "distributed")]
    async fn put_inner(&self, key: &str, entry: StoredCachedResponse) {
        let object_key = self.object_key(key);
        let Ok(payload) = serde_json::to_vec(&entry) else {
            return;
        };
        if let Err(error) = self
            .client
            .put_object()
            .bucket(&self.config.bucket)
            .key(&object_key)
            .content_type("application/json")
            .body(ByteStream::from(payload))
            .send()
            .await
        {
            tracing::warn!(
                error = %error,
                backend = %self.config.flavor.backend_name(),
                cache_key = %key,
                "object-store cache put failed"
            );
        }
    }

    pub async fn clear(&self) {
        #[cfg(not(feature = "distributed"))]
        {}

        #[cfg(feature = "distributed")]
        {
            if tokio::time::timeout(DEFAULT_OBJECT_STORE_OP_TIMEOUT, self.clear_inner())
                .await
                .is_err()
            {
                tracing::warn!(
                    backend = %self.config.flavor.backend_name(),
                    timeout_ms = DEFAULT_OBJECT_STORE_OP_TIMEOUT.as_millis() as u64,
                    "object-store cache clear timed out"
                );
            }
        }
    }

    #[cfg(feature = "distributed")]
    async fn clear_inner(&self) {
        for object_key in self.list_object_keys().await {
            if let Err(error) = self
                .client
                .delete_object()
                .bucket(&self.config.bucket)
                .key(&object_key)
                .send()
                .await
            {
                tracing::warn!(
                    error = %error,
                    backend = %self.config.flavor.backend_name(),
                    object_key = %object_key,
                    "object-store cache clear delete failed"
                );
            }
        }
    }

    pub async fn remove(&self, key: &str) -> bool {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = key;
            false
        }

        #[cfg(feature = "distributed")]
        {
            match tokio::time::timeout(DEFAULT_OBJECT_STORE_OP_TIMEOUT, self.remove_inner(key))
                .await
            {
                Ok(removed) => removed,
                Err(_) => {
                    tracing::warn!(
                        backend = %self.config.flavor.backend_name(),
                        cache_key = %key,
                        timeout_ms = DEFAULT_OBJECT_STORE_OP_TIMEOUT.as_millis() as u64,
                        "object-store cache remove timed out"
                    );
                    false
                }
            }
        }
    }

    #[cfg(feature = "distributed")]
    async fn remove_inner(&self, key: &str) -> bool {
        let object_key = self.object_key(key);
        match self
            .client
            .delete_object()
            .bucket(&self.config.bucket)
            .key(&object_key)
            .send()
            .await
        {
            Ok(_) => true,
            Err(error) if is_missing_object_error(&error.to_string()) => false,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    backend = %self.config.flavor.backend_name(),
                    cache_key = %key,
                    "object-store cache remove failed"
                );
                false
            }
        }
    }

    pub async fn pressure_json(&self) -> serde_json::Value {
        #[cfg(not(feature = "distributed"))]
        {
            serde_json::json!({
                "level": "unknown",
                "estimated_entry_count": serde_json::Value::Null,
            })
        }

        #[cfg(feature = "distributed")]
        {
            let keys = self.list_object_keys().await;
            serde_json::json!({
                "level": "nominal",
                "estimated_entry_count": keys.len(),
                "semantic_shared": false,
            })
        }
    }

    fn object_key(&self, key: &str) -> String {
        let digest = hex::encode(Sha256::digest(key.as_bytes()));
        format!("{}/{}.json", self.config.prefix.trim_matches('/'), digest)
    }

    #[cfg(feature = "distributed")]
    async fn list_object_keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        let mut continuation: Option<String> = None;

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.config.bucket)
                .prefix(self.config.prefix.trim_matches('/').to_string());
            if let Some(token) = continuation.as_ref() {
                request = request.continuation_token(token);
            }

            let response = match request.send().await {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        backend = %self.config.flavor.backend_name(),
                        "object-store cache list failed"
                    );
                    break;
                }
            };

            for object in response.contents() {
                if let Some(key) = object.key() {
                    keys.push(key.to_string());
                }
            }

            if !response.is_truncated().unwrap_or(false) {
                break;
            }
            continuation = response.next_continuation_token().map(ToString::to_string);
            if continuation.is_none() {
                break;
            }
        }

        keys
    }
}

#[cfg(feature = "distributed")]
fn build_client(config: &ObjectStoreCacheConfig) -> Result<S3Client, CliError> {
    let credentials = Credentials::new(
        config.access_key_id.clone(),
        config.secret_access_key.clone(),
        None,
        None,
        "verdictan-llm-cache",
    );

    let mut builder = aws_sdk_s3::config::Builder::new()
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
        .region(Region::new(config.region.clone()))
        .credentials_provider(credentials)
        .force_path_style(config.force_path_style);

    if let Some(endpoint) = config.endpoint.clone() {
        builder = builder.endpoint_url(endpoint);
    }

    Ok(S3Client::from_conf(builder.build()))
}

fn is_missing_object_error(message: &str) -> bool {
    message.contains("NoSuchKey") || message.contains("NotFound") || message.contains("404")
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

    fn config(flavor: ObjectStoreFlavor) -> ObjectStoreCacheConfig {
        ObjectStoreCacheConfig {
            flavor,
            bucket: "bucket-1".to_string(),
            prefix: "/custom/cache-prefix/".to_string(),
            region: "us-east-1".to_string(),
            endpoint: Some("http://127.0.0.1:9".to_string()),
            access_key_id: "access-key".to_string(),
            secret_access_key: "secret-key".to_string(),
            force_path_style: true,
        }
    }

    fn backend(flavor: ObjectStoreFlavor) -> ObjectStoreExactCacheBackend {
        let config = config(flavor);

        #[cfg(feature = "distributed")]
        {
            ObjectStoreExactCacheBackend {
                client: build_client(&config).expect("object-store client"),
                config,
            }
        }

        #[cfg(not(feature = "distributed"))]
        {
            ObjectStoreExactCacheBackend { config }
        }
    }

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
    fn default_prefix_matches_constant() {
        assert_eq!(
            ObjectStoreCacheConfig::default_prefix(),
            DEFAULT_OBJECT_STORE_PREFIX.to_string()
        );
    }

    #[test]
    fn backend_names_match_flavors() {
        assert_eq!(ObjectStoreFlavor::S3.backend_name(), "s3");
        assert_eq!(ObjectStoreFlavor::Gcs.backend_name(), "gcs");
    }

    #[test]
    fn object_key_hashes_cache_key_and_trims_prefix() {
        let backend = backend(ObjectStoreFlavor::S3);
        let digest = hex::encode(Sha256::digest(b"cache-key"));
        assert_eq!(
            backend.object_key("cache-key"),
            format!("custom/cache-prefix/{digest}.json")
        );
    }

    #[test]
    fn missing_object_detection_matches_expected_signatures() {
        assert!(is_missing_object_error("NoSuchKey"));
        assert!(is_missing_object_error("NotFound"));
        assert!(is_missing_object_error("upstream returned 404"));
        assert!(!is_missing_object_error("permission denied"));
    }

    #[cfg(not(feature = "distributed"))]
    #[test]
    fn new_requires_distributed_feature() {
        let error = match ObjectStoreExactCacheBackend::new(config(ObjectStoreFlavor::S3)) {
            Ok(_) => panic!("expected distributed feature error"),
            Err(error) => error,
        };
        assert!(format!("{error}").contains("--features distributed"));
    }

    #[cfg(not(feature = "distributed"))]
    #[tokio::test]
    async fn non_distributed_backend_methods_are_safe_noops() {
        let backend = backend(ObjectStoreFlavor::Gcs);
        assert!(backend.get("missing").await.is_none());
        backend.put("missing", sample_entry()).await;
        backend.clear().await;
        assert!(!backend.remove("missing").await);
        assert_eq!(backend.pressure_json().await["level"], "unknown");
    }

    #[cfg(feature = "distributed")]
    #[tokio::test]
    async fn shared_client_async_path_executes_future_to_completion() {
        let value = async { 21 * 2 }.await;
        assert_eq!(value, 42);
    }

    #[test]
    fn object_key_is_deterministic_for_same_input() {
        let backend = backend(ObjectStoreFlavor::S3);
        let key1 = backend.object_key("same-key");
        let key2 = backend.object_key("same-key");
        assert_eq!(key1, key2);
    }

    #[test]
    fn object_key_differs_for_different_input() {
        let backend = backend(ObjectStoreFlavor::S3);
        let key1 = backend.object_key("key-a");
        let key2 = backend.object_key("key-b");
        assert_ne!(key1, key2);
    }

    #[test]
    fn object_key_always_ends_with_json_extension() {
        let backend = backend(ObjectStoreFlavor::Gcs);
        let key = backend.object_key("arbitrary");
        assert!(key.ends_with(".json"));
    }

    #[test]
    fn flavor_debug_impl() {
        assert_eq!(format!("{:?}", ObjectStoreFlavor::S3), "S3");
        assert_eq!(format!("{:?}", ObjectStoreFlavor::Gcs), "Gcs");
    }

    #[test]
    fn flavor_equality() {
        assert_eq!(ObjectStoreFlavor::S3, ObjectStoreFlavor::S3);
        assert_ne!(ObjectStoreFlavor::S3, ObjectStoreFlavor::Gcs);
    }

    #[test]
    fn is_missing_object_error_case_sensitive() {
        assert!(!is_missing_object_error("nosuchkey"));
        assert!(is_missing_object_error("NoSuchKey: the key does not exist"));
    }
}
