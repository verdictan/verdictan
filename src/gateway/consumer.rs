// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use axum::http::HeaderMap;
use sha2::Digest;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::CliError;

use super::enforcement::ChainEntry;

#[derive(Debug, Clone)]
pub struct ConsumerGroupConfig {
    pub key_header: String,
    pub groups: Vec<ConsumerGroup>,
    api_key_index: HashMap<String, usize>,
    request_limiter: Arc<GroupRequestLimiter>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConsumerGroup {
    pub name: String,
    #[serde(default)]
    pub api_keys: Vec<String>,
    #[serde(default)]
    pub rate_limit: Option<GroupRateLimit>,
    #[serde(default)]
    pub chain: Option<Vec<ChainEntry>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupRateLimit {
    #[serde(default)]
    pub max_requests: Option<u64>,
    pub window_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct ResolvedConsumerGroup {
    pub name: String,
    pub chain: Option<Vec<ChainEntry>>,
    pub rate_limit: Option<GroupRateLimit>,
}

#[derive(Debug, Clone)]
pub struct GroupRequestRateLimitExceeded {
    pub group_name: String,
    pub retry_after_seconds: u64,
    pub limit: u64,
    pub remaining: u64,
}

#[derive(Debug, serde::Deserialize)]
struct RawConsumerGroupConfig {
    #[serde(default = "default_key_header")]
    key_header: String,
    #[serde(default)]
    groups: Vec<ConsumerGroup>,
}

#[derive(Debug, Default)]
struct GroupRequestLimiter {
    buckets: Mutex<HashMap<String, (u64, Instant)>>,
}

fn default_key_header() -> String {
    "Authorization".to_string()
}

impl ConsumerGroupConfig {
    pub fn from_json(root: &serde_json::Value) -> Result<Option<Self>, CliError> {
        let Some(value) = root.get("consumer_groups") else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }

        let raw: RawConsumerGroupConfig =
            serde_json::from_value(value.clone()).map_err(|error| {
                CliError::user(format!("failed to parse consumer_groups section: {error}"))
            })?;

        let mut api_key_index = HashMap::new();
        for (group_index, group) in raw.groups.iter().enumerate() {
            for api_key_hash in &group.api_keys {
                api_key_index
                    .entry(api_key_hash.trim().to_ascii_lowercase())
                    .or_insert(group_index);
            }
        }

        Ok(Some(Self {
            key_header: raw.key_header,
            groups: raw.groups,
            api_key_index,
            request_limiter: Arc::new(GroupRequestLimiter::default()),
        }))
    }

    pub fn resolve(&self, headers: &HeaderMap) -> Option<ResolvedConsumerGroup> {
        let presented_key = self.extract_presented_key(headers)?;
        let key_hash = sha256_hex(presented_key.as_bytes());
        let group_index = *self.api_key_index.get(&key_hash)?;
        let group = self.groups.get(group_index)?;

        Some(ResolvedConsumerGroup {
            name: group.name.clone(),
            chain: group.chain.clone(),
            rate_limit: group.rate_limit.clone(),
        })
    }

    pub fn check_request_limit(
        &self,
        group: &ResolvedConsumerGroup,
    ) -> Result<Option<u64>, GroupRequestRateLimitExceeded> {
        let Some(rate_limit) = group.rate_limit.as_ref() else {
            return Ok(None);
        };
        let Some(max_requests) = rate_limit.max_requests else {
            return Ok(None);
        };

        self.request_limiter
            .check_and_increment(&group.name, max_requests, rate_limit.window_seconds)
            .map(Some)
    }

    fn extract_presented_key(&self, headers: &HeaderMap) -> Option<String> {
        let value = headers
            .get(self.key_header.as_str())
            .and_then(|header| header.to_str().ok())?
            .trim();
        if value.is_empty() {
            return None;
        }

        if self.key_header.eq_ignore_ascii_case("authorization") {
            if let Some(bearer) = value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
            {
                let bearer = bearer.trim();
                if !bearer.is_empty() {
                    return Some(bearer.to_string());
                }
            }
        }

        Some(value.to_string())
    }
}

impl GroupRequestLimiter {
    fn check_and_increment(
        &self,
        group_name: &str,
        max_requests: u64,
        window_seconds: u64,
    ) -> Result<u64, GroupRequestRateLimitExceeded> {
        let now = Instant::now();
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut buckets = self
            .buckets
            .lock()
            .expect("consumer group rate limiter lock");
        let window = Duration::from_secs(window_seconds);

        let entry = buckets.entry(group_name.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) >= window {
            *entry = (0, now);
        }
        entry.0 += 1;

        if entry.0 > max_requests {
            Err(GroupRequestRateLimitExceeded {
                group_name: group_name.to_string(),
                retry_after_seconds: window_seconds,
                limit: max_requests,
                remaining: 0,
            })
        } else {
            Ok(max_requests.saturating_sub(entry.0))
        }
    }
}

pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
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
    use axum::http::{header::AUTHORIZATION, HeaderValue};
    use serde_json::json;

    fn hashed(value: &str) -> String {
        sha256_hex(value.as_bytes())
    }

    #[test]
    fn from_json_returns_none_when_section_is_missing_or_null() {
        assert!(ConsumerGroupConfig::from_json(&json!({}))
            .expect("missing section")
            .is_none());
        assert!(
            ConsumerGroupConfig::from_json(&json!({ "consumer_groups": null }))
                .expect("null section")
                .is_none()
        );
    }

    #[test]
    fn from_json_rejects_invalid_consumer_groups_shape() {
        let error = ConsumerGroupConfig::from_json(&json!({
            "consumer_groups": {
                "groups": "not-an-array"
            }
        }))
        .expect_err("invalid consumer_groups shape should fail");

        assert!(
            error
                .to_string()
                .contains("failed to parse consumer_groups section"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn resolve_prefers_first_group_for_duplicate_key_hashes() {
        let config = ConsumerGroupConfig::from_json(&json!({
            "consumer_groups": {
                "groups": [
                    {
                        "name": "primary",
                        "api_keys": [hashed("token-a")]
                    },
                    {
                        "name": "shadow",
                        "api_keys": [hashed("token-a")]
                    }
                ]
            }
        }))
        .expect("config")
        .expect("consumer groups");

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token-a"));

        let resolved = config.resolve(&headers).expect("resolved group");
        assert_eq!(resolved.name, "primary");
    }

    #[test]
    fn resolve_supports_custom_key_headers_and_trimmed_values() {
        let config = ConsumerGroupConfig::from_json(&json!({
            "consumer_groups": {
                "key_header": "x-verdictan-consumer-key",
                "groups": [
                    {
                        "name": "tenant-a",
                        "api_keys": [hashed("raw-key")]
                    }
                ]
            }
        }))
        .expect("config")
        .expect("consumer groups");

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-verdictan-consumer-key",
            HeaderValue::from_static("  raw-key  "),
        );

        let resolved = config.resolve(&headers).expect("resolved group");
        assert_eq!(resolved.name, "tenant-a");
    }

    #[test]
    fn resolve_rejects_blank_or_missing_authorization_values() {
        let config = ConsumerGroupConfig::from_json(&json!({
            "consumer_groups": {
                "groups": [
                    {
                        "name": "tenant-a",
                        "api_keys": [hashed("token-a")]
                    }
                ]
            }
        }))
        .expect("config")
        .expect("consumer groups");

        let mut blank = HeaderMap::new();
        blank.insert(AUTHORIZATION, HeaderValue::from_static("Bearer    "));
        assert!(config.resolve(&blank).is_none());

        assert!(config.resolve(&HeaderMap::new()).is_none());
    }

    #[test]
    fn check_request_limit_counts_down_and_then_reports_exhaustion() {
        let config = ConsumerGroupConfig::from_json(&json!({
            "consumer_groups": {
                "groups": [
                    { "name": "tenant-a", "api_keys": [] }
                ]
            }
        }))
        .expect("config")
        .expect("consumer groups");

        let group = ResolvedConsumerGroup {
            name: "tenant-a".to_string(),
            chain: None,
            rate_limit: Some(GroupRateLimit {
                max_requests: Some(2),
                window_seconds: 60,
            }),
        };

        assert_eq!(config.check_request_limit(&group).expect("first"), Some(1));
        assert_eq!(config.check_request_limit(&group).expect("second"), Some(0));

        let exceeded = config
            .check_request_limit(&group)
            .expect_err("third request should exceed the limit");
        assert_eq!(exceeded.group_name, "tenant-a");
        assert_eq!(exceeded.retry_after_seconds, 60);
        assert_eq!(exceeded.limit, 2);
        assert_eq!(exceeded.remaining, 0);
    }

    #[test]
    fn check_request_limit_skips_groups_without_request_caps() {
        let config = ConsumerGroupConfig::from_json(&json!({
            "consumer_groups": {
                "groups": [
                    { "name": "tenant-a", "api_keys": [] }
                ]
            }
        }))
        .expect("config")
        .expect("consumer groups");

        let unlimited = ResolvedConsumerGroup {
            name: "tenant-a".to_string(),
            chain: None,
            rate_limit: Some(GroupRateLimit {
                max_requests: None,
                window_seconds: 60,
            }),
        };

        let no_limit = ResolvedConsumerGroup {
            name: "tenant-b".to_string(),
            chain: None,
            rate_limit: None,
        };

        assert_eq!(
            config.check_request_limit(&unlimited).expect("unlimited"),
            None
        );
        assert_eq!(
            config.check_request_limit(&no_limit).expect("no limit"),
            None
        );
    }

    #[test]
    fn sha256_helpers_validate_expected_hex_shapes() {
        let digest = sha256_hex(b"hello");
        assert_eq!(digest.len(), 64);
        assert!(is_sha256_hex(&digest));
        assert!(!is_sha256_hex("xyz"));
        assert!(!is_sha256_hex(
            "g000000000000000000000000000000000000000000000000000000000000000"
        ));
    }
}
