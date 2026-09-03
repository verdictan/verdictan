// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CachedOAuthToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix timestamp seconds; used for serde transport to/from the API.
    pub expires_at_unix: u64,
    pub token_type: String,
    /// In-process instant for fast freshness checks (not serialized).
    #[serde(skip)]
    pub(crate) expires_at: Option<Instant>,
}

impl CachedOAuthToken {
    /// Construct a token from an `expires_in` duration (as returned by the OAuth server).
    pub fn from_expires_in(
        access_token: String,
        refresh_token: Option<String>,
        token_type: String,
        expires_in: Duration,
    ) -> Self {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires_at_unix = now_unix + expires_in.as_secs();
        let expires_at = Some(Instant::now() + expires_in);
        Self {
            access_token,
            refresh_token,
            expires_at_unix,
            token_type,
            expires_at,
        }
    }

    /// Reconstruct the `expires_at` Instant from the unix timestamp after deserializing.
    fn with_instant(mut self) -> Self {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let remaining = self.expires_at_unix.saturating_sub(now_unix);
        self.expires_at = Some(Instant::now() + Duration::from_secs(remaining));
        self
    }

    pub fn bearer_value(&self) -> String {
        format!("{} {}", self.token_type, self.access_token)
    }

    pub fn is_fresh(&self) -> bool {
        self.expires_at
            .map(|t| t > Instant::now() + Duration::from_secs(30))
            .unwrap_or(false)
    }
}

#[derive(Debug)]
struct PersistenceConfig {
    api_base_url: String,
    api_token: String,
    client: reqwest::Client,
}

#[derive(Default)]
pub struct OAuthTokenStore {
    inner: Mutex<HashMap<String, CachedOAuthToken>>,
    persistence: Mutex<Option<PersistenceConfig>>,
}

impl OAuthTokenStore {
    pub fn global() -> &'static Self {
        static STORE: OnceLock<OAuthTokenStore> = OnceLock::new();
        STORE.get_or_init(Self::default)
    }

    /// Create a fresh, isolated instance for use in tests.
    pub fn new_isolated() -> Self {
        Self::default()
    }

    /// Configure the store to persist tokens to the control-plane API.
    /// Call once at gateway startup when `VERDICTAN_API_URL` and token are available.
    pub fn configure_api_persistence(&self, base_url: String, api_token: String) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        if let Ok(mut guard) = self.persistence.lock() {
            *guard = Some(PersistenceConfig {
                api_base_url: base_url,
                api_token,
                client,
            });
        }
    }

    pub fn get(&self, key: &str) -> Option<CachedOAuthToken> {
        let stale_in_memory = self.inner.lock().ok()?.get(key).cloned();

        // Fast path: in-memory cache.
        if let Some(token) = stale_in_memory.clone() {
            tracing::debug!(
                provider_key = key,
                fresh = token.is_fresh(),
                "oauth token cache lookup"
            );
            if token.is_fresh() {
                return Some(token);
            }
        }

        // Cold/stale path: try API persistence.
        let config = self.persistence.lock().ok()?.as_ref().map(|c| {
            (
                c.api_base_url.clone(),
                c.api_token.clone(),
                c.client.clone(),
            )
        });

        let Some((base_url, api_token, client)) = config else {
            return stale_in_memory;
        };

        let url = format!("{}/v1/oauth-tokens/{}", base_url.trim_end_matches('/'), key);

        let response = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                client
                    .get(&url)
                    .header("Authorization", format!("Bearer {}", api_token))
                    .send()
                    .await
            })
        });

        match response {
            Ok(resp) if resp.status().is_success() => {
                let token_result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(async { resp.json::<CachedOAuthToken>().await })
                });
                match token_result {
                    Ok(token) => {
                        let token = token.with_instant();
                        tracing::info!(
                            provider_key = key,
                            source = "api",
                            "oauth token loaded from API persistence"
                        );
                        if let Ok(mut guard) = self.inner.lock() {
                            guard.insert(key.to_string(), token.clone());
                        }
                        Some(token)
                    }
                    Err(e) => {
                        tracing::warn!(provider_key = key, error = %e, "failed to deserialize oauth token from API");
                        None
                    }
                }
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => stale_in_memory,
            Ok(resp) => {
                tracing::warn!(
                    provider_key = key,
                    status = %resp.status(),
                    "unexpected status reading oauth token from API"
                );
                stale_in_memory
            }
            Err(e) => {
                tracing::warn!(provider_key = key, error = %e, "oauth token API read failed");
                stale_in_memory
            }
        }
    }

    pub fn put(&self, key: String, token: CachedOAuthToken) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(key.clone(), token.clone());
        }

        // Best-effort persistence to the API; do not block the caller.
        let config = match self.persistence.lock().ok().and_then(|guard| {
            guard.as_ref().map(|c| {
                (
                    c.api_base_url.clone(),
                    c.api_token.clone(),
                    c.client.clone(),
                )
            })
        }) {
            Some(c) => c,
            None => return,
        };

        let (base_url, api_token, client) = config;
        let url = format!("{}/v1/oauth-tokens/{}", base_url.trim_end_matches('/'), key);

        tokio::spawn(async move {
            match client
                .put(&url)
                .header("Authorization", format!("Bearer {}", api_token))
                .json(&token)
                .send()
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(provider_key = %key, error = %e, "oauth token API persistence write failed");
                }
            }
        });
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

    #[test]
    fn from_expires_in_sets_fields_and_expiry() {
        let token = CachedOAuthToken::from_expires_in(
            "access-123".to_string(),
            Some("refresh-456".to_string()),
            "Bearer".to_string(),
            Duration::from_secs(3600),
        );
        assert_eq!(token.access_token, "access-123");
        assert_eq!(token.refresh_token.as_deref(), Some("refresh-456"));
        assert_eq!(token.token_type, "Bearer");
        assert!(token.expires_at.is_some());
        assert!(token.expires_at_unix > 0);
    }

    #[test]
    fn bearer_value_formats_type_and_token() {
        let token = CachedOAuthToken {
            access_token: "my-token".to_string(),
            refresh_token: None,
            expires_at_unix: u64::MAX,
            token_type: "Bearer".to_string(),
            expires_at: Some(Instant::now() + Duration::from_secs(3600)),
        };
        assert_eq!(token.bearer_value(), "Bearer my-token");
    }

    #[test]
    fn is_fresh_returns_true_when_more_than_30s_remain() {
        let fresh = CachedOAuthToken {
            access_token: "t".to_string(),
            refresh_token: None,
            expires_at_unix: u64::MAX,
            token_type: "Bearer".to_string(),
            expires_at: Some(Instant::now() + Duration::from_secs(60)),
        };
        assert!(fresh.is_fresh());
    }

    #[test]
    fn is_fresh_returns_false_when_less_than_30s_remain() {
        let stale = CachedOAuthToken {
            access_token: "t".to_string(),
            refresh_token: None,
            expires_at_unix: 0,
            token_type: "Bearer".to_string(),
            expires_at: Some(Instant::now() + Duration::from_secs(10)),
        };
        assert!(!stale.is_fresh());
    }

    #[test]
    fn is_fresh_returns_false_when_no_instant() {
        let no_instant = CachedOAuthToken {
            access_token: "t".to_string(),
            refresh_token: None,
            expires_at_unix: u64::MAX,
            token_type: "Bearer".to_string(),
            expires_at: None,
        };
        assert!(!no_instant.is_fresh());
    }

    #[test]
    fn with_instant_reconstructs_expiry_from_unix() {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = CachedOAuthToken {
            access_token: "t".to_string(),
            refresh_token: None,
            expires_at_unix: now_unix + 3600,
            token_type: "Bearer".to_string(),
            expires_at: None,
        };
        let restored = token.with_instant();
        assert!(restored.expires_at.is_some());
        assert!(restored.is_fresh());
    }

    #[test]
    fn with_instant_handles_already_expired_token() {
        let token = CachedOAuthToken {
            access_token: "t".to_string(),
            refresh_token: None,
            expires_at_unix: 0,
            token_type: "Bearer".to_string(),
            expires_at: None,
        };
        let restored = token.with_instant();
        assert!(!restored.is_fresh());
    }

    #[test]
    fn isolated_store_put_and_get_in_memory() {
        let store = OAuthTokenStore::new_isolated();
        let token = CachedOAuthToken::from_expires_in(
            "access".to_string(),
            None,
            "Bearer".to_string(),
            Duration::from_secs(3600),
        );
        store.put("provider-1".to_string(), token.clone());

        let retrieved = store.get("provider-1").expect("token should be cached");
        assert_eq!(retrieved.access_token, "access");
        assert!(retrieved.is_fresh());
    }

    #[test]
    fn isolated_store_get_returns_none_for_missing_key() {
        let store = OAuthTokenStore::new_isolated();
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn isolated_store_returns_stale_token_without_api_persistence() {
        let store = OAuthTokenStore::new_isolated();
        let stale = CachedOAuthToken {
            access_token: "stale".to_string(),
            refresh_token: None,
            expires_at_unix: 0,
            token_type: "Bearer".to_string(),
            expires_at: Some(Instant::now() + Duration::from_secs(5)),
        };
        store.put("provider-stale".to_string(), stale);

        let result = store.get("provider-stale");
        assert!(result.is_some());
        assert!(!result.unwrap().is_fresh());
    }

    #[test]
    fn configure_api_persistence_does_not_panic() {
        let store = OAuthTokenStore::new_isolated();
        store
            .configure_api_persistence("http://127.0.0.1:9/".to_string(), "test-token".to_string());
    }

    mod persistence_api {
        use super::*;
        use crate::testing::oauth_mock_api::{start_mock_oauth_api, start_override_get_oauth_api};
        use axum::http::StatusCode;

        fn fresh_token(expires_in_secs: u64) -> CachedOAuthToken {
            CachedOAuthToken::from_expires_in(
                "test-access-token".to_string(),
                Some("test-refresh-token".to_string()),
                "Bearer".to_string(),
                Duration::from_secs(expires_in_secs),
            )
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn put_sends_to_api() {
            let (base_url, mock_state, _server) = start_mock_oauth_api().await;
            let store = OAuthTokenStore::new_isolated();
            store.configure_api_persistence(base_url, "test-token".to_string());

            store.put("provider:test".to_string(), fresh_token(3600));
            mock_state.wait_for_puts(1).await;

            let calls = mock_state.put_calls_snapshot();
            assert_eq!(calls.len(), 1, "expected one PUT call to mock API");
            assert_eq!(calls[0].0, "provider:test");
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn get_cold_cache_fetches_from_api() {
            let (base_url, mock_state, _server) = start_mock_oauth_api().await;
            {
                let token = fresh_token(3600);
                let serialized = serde_json::to_value(&token).expect("serialise token");
                mock_state
                    .store
                    .lock()
                    .expect("store lock")
                    .insert("provider:cold".to_string(), serialized);
            }

            let store = OAuthTokenStore::new_isolated();
            store.configure_api_persistence(base_url, "test-token".to_string());

            let result = store.get("provider:cold");
            assert!(result.is_some(), "expected token from API");
            assert_eq!(result.unwrap().access_token, "test-access-token");
            assert_eq!(mock_state.get_call_count(), 1);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn get_warm_cache_skips_api() {
            let (base_url, mock_state, _server) = start_mock_oauth_api().await;
            let store = OAuthTokenStore::new_isolated();
            store.configure_api_persistence(base_url, "test-token".to_string());

            store.put("provider:warm".to_string(), fresh_token(3600));
            mock_state.wait_for_puts(1).await;
            mock_state.get_calls.lock().expect("get_calls lock").clear();

            let result = store.get("provider:warm");
            assert!(result.is_some(), "expected cached token");
            assert_eq!(mock_state.get_call_count(), 0);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn get_expired_in_memory_fetches_from_api() {
            let (base_url, mock_state, _server) = start_mock_oauth_api().await;
            let store = OAuthTokenStore::new_isolated();
            store.configure_api_persistence(base_url, "test-token".to_string());

            store.put("provider:expired".to_string(), fresh_token(0));
            mock_state.wait_for_puts(1).await;

            {
                let token = CachedOAuthToken::from_expires_in(
                    "fresh-from-api".to_string(),
                    Some("fresh-refresh-token".to_string()),
                    "Bearer".to_string(),
                    Duration::from_secs(7200),
                );
                let serialized = serde_json::to_value(&token).expect("serialise token");
                mock_state
                    .store
                    .lock()
                    .expect("store lock")
                    .insert("provider:expired".to_string(), serialized);
            }
            mock_state.get_calls.lock().expect("get_calls lock").clear();

            let result = store
                .get("provider:expired")
                .expect("expected fresh token from API on stale eviction");
            assert_eq!(result.access_token, "fresh-from-api");
            assert_eq!(mock_state.get_call_count(), 1);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn get_stale_cache_returns_stale_token_when_api_reports_not_found() {
            let (base_url, mock_state, _server) = start_mock_oauth_api().await;
            let store = OAuthTokenStore::new_isolated();
            store.put("provider:stale-miss".to_string(), fresh_token(0));
            store.configure_api_persistence(base_url, "test-token".to_string());

            let result = store
                .get("provider:stale-miss")
                .expect("stale token should be returned when persisted token is missing");

            assert_eq!(result.access_token, "test-access-token");
            assert!(!result.is_fresh());
            assert_eq!(mock_state.get_call_count(), 1);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn get_cold_cache_returns_none_when_api_returns_invalid_json() {
            let (base_url, get_calls, _server) =
                start_override_get_oauth_api(StatusCode::OK, "not-json").await;
            let store = OAuthTokenStore::new_isolated();
            store.configure_api_persistence(base_url, "test-token".to_string());

            let result = store.get("provider:invalid-json");
            assert!(
                result.is_none(),
                "invalid API payload should not populate cache"
            );
            assert_eq!(get_calls.lock().expect("get_calls lock").len(), 1);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn get_stale_cache_returns_stale_token_when_api_errors() {
            let (base_url, get_calls, _server) = start_override_get_oauth_api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "{\"error\":\"boom\"}",
            )
            .await;
            let store = OAuthTokenStore::new_isolated();
            store.put("provider:stale-error".to_string(), fresh_token(0));
            store.configure_api_persistence(base_url, "test-token".to_string());

            let result = store
                .get("provider:stale-error")
                .expect("stale token should be returned when API read fails");

            assert_eq!(result.access_token, "test-access-token");
            assert!(!result.is_fresh());
            assert_eq!(get_calls.lock().expect("get_calls lock").len(), 1);
        }
    }
}
