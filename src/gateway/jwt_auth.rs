// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Gateway JWT authentication client.
//!
//! Bootstraps a machine JWT from the control-plane API via opaque-token exchange,
//! caches JWKS for verifying incoming machine JWTs, and polls revocations.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{decode_header, errors::ErrorKind, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::{watch, RwLock};
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single JWK entry from the JWKS endpoint.
#[derive(Clone, Debug, Deserialize)]
pub struct JwkEntry {
    pub kty: String,
    pub kid: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: Option<String>,
    pub n: String,
    pub e: String,
}

/// Response from `GET /v1/jwt/jwks`.
#[derive(Clone, Debug, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkEntry>,
}

/// Response from `POST /v1/jwt/exchange`.
#[derive(Clone, Debug, Deserialize)]
pub struct ExchangeResponse {
    pub access_token: String,
    #[serde(default)]
    pub token_type: Option<String>,
    pub expires_in: u32,
    pub scope: String,
}

/// Response from `GET /v1/jwt/revocations`.
#[derive(Clone, Debug, Deserialize)]
pub struct RevocationsResponse {
    pub revoked_jtis: Vec<String>,
    pub server_time: i64,
}

/// Claims contained in a verified machine JWT.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MachineClaims {
    pub iss: String,
    pub sub: String,
    pub aud: OneOrMany,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub org_id: String,
    pub principal_type: String,
    pub actor_class: String,
    pub scope: String,
    #[serde(default)]
    pub gateway_id: Option<String>,
    pub azp: String,
    #[serde(default)]
    pub rev_check: Option<String>,
    /// Region this token was issued for. Mandatory since Phase 15.
    #[serde(default)]
    pub region: Option<String>,
}

/// `aud` may be a single string or an array of strings.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Self::One(s) => s == value,
            Self::Many(v) => v.iter().any(|s| s == value),
        }
    }

    pub fn is_exactly(&self, value: &str) -> bool {
        match self {
            Self::One(s) => s == value,
            Self::Many(v) => v.len() == 1 && v[0] == value,
        }
    }
}

/// Errors produced by the auth client.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("JWT exchange failed: {0}")]
    Exchange(String),
    #[error("JWKS fetch failed: {0}")]
    JwksFetch(String),
    #[error("Revocations fetch failed: {0}")]
    RevocationsFetch(String),
    #[error("JWT verification failed: {0}")]
    Verification(String),
    #[error("Token expired")]
    Expired,
    #[error("Unknown kid: {0}")]
    UnknownKid(String),
    #[error("Org mismatch: expected {expected}, got {actual}")]
    OrgMismatch { expected: String, actual: String },
    #[error("Audience mismatch")]
    AudienceMismatch,
    #[error("Token revoked: {0}")]
    Revoked(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

struct CachedJwt {
    token: String,
    expires_at: Instant,
}

struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    last_refresh: Instant,
    min_refresh_interval: Duration,
    /// Kids that were requested but not found — prevents repeated JWKS fetches.
    unknown_kids: HashSet<String>,
}

impl JwksCache {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
            last_refresh: Instant::now() - Duration::from_secs(300),
            min_refresh_interval: Duration::from_secs(30),
            unknown_kids: HashSet::new(),
        }
    }

    fn should_refresh(&self) -> bool {
        self.last_refresh.elapsed() >= self.min_refresh_interval
    }
}

// ---------------------------------------------------------------------------
// GatewayAuthClient
// ---------------------------------------------------------------------------

/// Client that manages the gateway's own machine JWT and verifies incoming JWTs.
pub struct GatewayAuthClient {
    opaque_token: String,
    api_url: String,
    org_id: String,
    gateway_id: String,
    jwt: Arc<RwLock<Option<CachedJwt>>>,
    peer_jwts: Arc<RwLock<HashMap<String, CachedJwt>>>,
    jwks: Arc<RwLock<JwksCache>>,
    revoked_jtis: Arc<RwLock<HashSet<String>>>,
    last_revocation_poll: Arc<RwLock<i64>>,
    last_material_refresh: Arc<RwLock<Instant>>,
    client: Client,
}

/// Audience URI for this gateway instance.
pub(crate) fn gateway_audience(gateway_id: &str) -> String {
    format!("https://gateway-{gateway_id}.verdictan.io")
}

/// Expected issuer for machine JWTs.
pub(crate) const EXPECTED_ISSUER: &str = "https://api.verdictan.com";
const CRDT_SYNC_SCOPE: &str = "gateway:crdt:sync";

/// Buffer before expiry at which we proactively refresh.
const REFRESH_BUFFER: Duration = Duration::from_secs(60);
const PEER_REFRESH_BUFFER: Duration = Duration::from_secs(150);
const MATERIAL_MAX_AGE: Duration = Duration::from_secs(300);

fn map_verification_error(error: jsonwebtoken::errors::Error) -> AuthError {
    match error.kind() {
        ErrorKind::ExpiredSignature => AuthError::Expired,
        ErrorKind::InvalidAudience => AuthError::AudienceMismatch,
        _ => AuthError::Verification(format!("decode failed: {error}")),
    }
}

impl GatewayAuthClient {
    /// Create a new auth client. Does NOT perform bootstrap — call [`bootstrap`] next.
    pub fn new(opaque_token: String, api_url: String, org_id: String, gateway_id: String) -> Self {
        Self {
            opaque_token,
            api_url,
            org_id,
            gateway_id,
            jwt: Arc::new(RwLock::new(None)),
            peer_jwts: Arc::new(RwLock::new(HashMap::new())),
            jwks: Arc::new(RwLock::new(JwksCache::new())),
            revoked_jtis: Arc::new(RwLock::new(HashSet::new())),
            last_revocation_poll: Arc::new(RwLock::new(0)),
            last_material_refresh: Arc::new(RwLock::new(Instant::now())),
            client: Client::new(),
        }
    }

    /// Fail-closed bootstrap: exchange token, fetch JWKS, poll revocations.
    /// Returns an error if any step fails — the gateway MUST NOT start without auth.
    pub async fn bootstrap(&self) -> Result<(), AuthError> {
        info!("Bootstrapping gateway JWT auth client");

        self.refresh_jwt().await?;
        self.refresh_jwks().await?;
        self.refresh_revocations().await?;

        info!("Gateway JWT auth client bootstrapped successfully");
        Ok(())
    }

    /// Returns a valid bearer token, refreshing proactively if within the buffer window.
    pub async fn get_bearer_token(&self) -> Result<String, AuthError> {
        {
            let guard = self.jwt.read().await;
            if let Some(cached) = guard.as_ref() {
                if cached.expires_at > Instant::now() + REFRESH_BUFFER {
                    return Ok(cached.token.clone());
                }
            }
        }
        // Token missing or about to expire — refresh.
        self.refresh_jwt().await?;
        let guard = self.jwt.read().await;
        guard
            .as_ref()
            .map(|c| c.token.clone())
            .ok_or_else(|| AuthError::Exchange("token missing after refresh".into()))
    }

    /// Returns a valid CRDT peer bearer token scoped to the target gateway.
    pub async fn get_peer_bearer_token(
        &self,
        target_gateway_id: &str,
    ) -> Result<String, AuthError> {
        {
            let guard = self.peer_jwts.read().await;
            if let Some(cached) = guard.get(target_gateway_id) {
                if cached.expires_at > Instant::now() + PEER_REFRESH_BUFFER {
                    return Ok(cached.token.clone());
                }
            }
        }

        self.refresh_peer_jwt(target_gateway_id).await?;
        let guard = self.peer_jwts.read().await;
        guard
            .get(target_gateway_id)
            .map(|cached| cached.token.clone())
            .ok_or_else(|| AuthError::Exchange("peer token missing after refresh".into()))
    }

    pub async fn material_is_fresh(&self) -> bool {
        self.last_material_refresh.read().await.elapsed() <= MATERIAL_MAX_AGE
    }

    /// Exchange the opaque API token for a short-lived machine JWT.
    pub async fn refresh_jwt(&self) -> Result<(), AuthError> {
        debug!("Refreshing gateway machine JWT via exchange");

        let url = format!("{}/v1/jwt/exchange", self.api_url);
        let body = serde_json::json!({
            "audience": gateway_audience(&self.gateway_id),
            "ttl": 300
        });

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.opaque_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| AuthError::Exchange(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AuthError::Exchange(format!("{status}: {text}")));
        }

        let exchange: ExchangeResponse = resp
            .json()
            .await
            .map_err(|e| AuthError::Exchange(e.to_string()))?;

        let expires_at = Instant::now() + Duration::from_secs(u64::from(exchange.expires_in));

        let mut guard = self.jwt.write().await;
        *guard = Some(CachedJwt {
            token: exchange.access_token,
            expires_at,
        });
        drop(guard);
        self.mark_material_refresh().await;

        debug!("Machine JWT refreshed, expires in {}s", exchange.expires_in);
        Ok(())
    }

    pub async fn refresh_peer_jwt(&self, target_gateway_id: &str) -> Result<(), AuthError> {
        debug!(target_gateway_id, "Refreshing CRDT peer JWT");

        let url = format!("{}/v1/gateway/crdt/peer-token", self.api_url);
        let body = serde_json::json!({
            "target_gateway_id": target_gateway_id,
        });

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.opaque_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| AuthError::Exchange(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AuthError::Exchange(format!("{status}: {text}")));
        }

        let exchange: ExchangeResponse = resp
            .json()
            .await
            .map_err(|e| AuthError::Exchange(e.to_string()))?;
        if exchange.token_type.as_deref() != Some("Bearer") {
            return Err(AuthError::Exchange(format!(
                "unexpected CRDT peer token type: {}",
                exchange.token_type.as_deref().unwrap_or("<missing>")
            )));
        }
        if exchange.scope.trim() != CRDT_SYNC_SCOPE {
            return Err(AuthError::Exchange(format!(
                "unexpected CRDT peer token scope: {}",
                exchange.scope.trim()
            )));
        }
        let expected_audience = gateway_audience(target_gateway_id);
        let claims = self
            .verify_jwt_for_audience(&exchange.access_token, &expected_audience)
            .await?;
        if claims.scope.trim() != CRDT_SYNC_SCOPE {
            return Err(AuthError::Verification(format!(
                "expected exact scope {CRDT_SYNC_SCOPE}"
            )));
        }
        if claims.gateway_id.as_deref() != Some(self.gateway_id.as_str()) {
            return Err(AuthError::Verification(
                "peer token gateway_id does not match source gateway".to_string(),
            ));
        }
        let expires_at = Instant::now() + Duration::from_secs(u64::from(exchange.expires_in));

        let mut guard = self.peer_jwts.write().await;
        guard.insert(
            target_gateway_id.to_string(),
            CachedJwt {
                token: exchange.access_token,
                expires_at,
            },
        );
        drop(guard);
        self.mark_material_refresh().await;
        Ok(())
    }

    /// Fetch the JWKS from the API and update the local cache.
    pub async fn refresh_jwks(&self) -> Result<(), AuthError> {
        debug!("Refreshing JWKS cache");

        let url = format!("{}/v1/jwt/jwks", self.api_url);

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.opaque_token)
            .send()
            .await
            .map_err(|e| AuthError::JwksFetch(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AuthError::JwksFetch(format!("{status}: {text}")));
        }

        let jwks: JwksResponse = resp
            .json()
            .await
            .map_err(|e| AuthError::JwksFetch(e.to_string()))?;

        let mut keys: HashMap<String, DecodingKey> = HashMap::with_capacity(jwks.keys.len());
        for entry in &jwks.keys {
            let jwk_value = serde_json::json!({
                "kty": entry.kty,
                "kid": entry.kid,
                "alg": entry.alg,
                "use": entry.use_,
                "n": entry.n,
                "e": entry.e,
            });
            let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk_value)
                .map_err(|e| AuthError::JwksFetch(format!("invalid JWK: {e}")))?;
            let dk = DecodingKey::from_jwk(&jwk)
                .map_err(|e| AuthError::JwksFetch(format!("decoding key: {e}")))?;
            keys.insert(entry.kid.clone(), dk);
        }

        let mut guard = self.jwks.write().await;
        guard.keys = keys;
        guard.last_refresh = Instant::now();
        guard.unknown_kids.clear();
        drop(guard);
        self.mark_material_refresh().await;

        debug!("JWKS cache refreshed with {} keys", jwks.keys.len());
        Ok(())
    }

    /// Poll revocations since last known server time.
    pub async fn refresh_revocations(&self) -> Result<(), AuthError> {
        let since = { *self.last_revocation_poll.read().await };

        debug!(since, "Polling revocations");

        let url = format!("{}/v1/jwt/revocations?since={}", self.api_url, since);

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.opaque_token)
            .send()
            .await
            .map_err(|e| AuthError::RevocationsFetch(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AuthError::RevocationsFetch(format!("{status}: {text}")));
        }

        let revocations: RevocationsResponse = resp
            .json()
            .await
            .map_err(|e| AuthError::RevocationsFetch(e.to_string()))?;

        if !revocations.revoked_jtis.is_empty() {
            let mut guard = self.revoked_jtis.write().await;
            for jti in &revocations.revoked_jtis {
                guard.insert(jti.clone());
            }
            debug!(count = revocations.revoked_jtis.len(), "Added revoked JTIs");
        }

        let mut ts = self.last_revocation_poll.write().await;
        *ts = revocations.server_time;
        drop(ts);
        self.mark_material_refresh().await;

        Ok(())
    }

    /// Verify an incoming JWT presented by a client to the gateway.
    ///
    /// Enforces:
    /// - Valid signature (RS256 via cached JWKS)
    /// - Token not expired
    /// - Issuer == `https://api.verdictan.com`
    /// - Audience includes this gateway's audience URI
    /// - `org_id` matches gateway's org
    /// - `jti` not revoked
    pub async fn verify_incoming_jwt(&self, token: &str) -> Result<MachineClaims, AuthError> {
        let expected_aud = gateway_audience(&self.gateway_id);
        self.verify_jwt_for_audience(token, &expected_aud).await
    }

    async fn verify_jwt_for_audience(
        &self,
        token: &str,
        expected_aud: &str,
    ) -> Result<MachineClaims, AuthError> {
        let header = decode_header(token)
            .map_err(|e| AuthError::Verification(format!("invalid header: {e}")))?;

        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| AuthError::Verification("missing kid in header".into()))?;

        // Try to find the key in cache.
        let decoding_key = self.resolve_decoding_key(kid).await?;

        // Build validation.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&expected_aud]);
        validation.set_issuer(&[EXPECTED_ISSUER]);
        validation.validate_exp = true;

        let token_data = jsonwebtoken::decode::<MachineClaims>(token, &decoding_key, &validation)
            .map_err(map_verification_error)?;

        let claims = token_data.claims;

        // Org binding check.
        if claims.org_id != self.org_id {
            return Err(AuthError::OrgMismatch {
                expected: self.org_id.clone(),
                actual: claims.org_id,
            });
        }

        // Audience check (redundant with validation but explicit for clarity).
        if !claims.aud.is_exactly(expected_aud) {
            return Err(AuthError::AudienceMismatch);
        }

        // Revocation check.
        {
            let guard = self.revoked_jtis.read().await;
            if guard.contains(&claims.jti) {
                return Err(AuthError::Revoked(claims.jti));
            }
        }

        Ok(claims)
    }

    /// Spawn the background refresh loop. Returns a `JoinHandle` that runs until dropped.
    pub fn spawn_refresh_loop(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        self.spawn_refresh_loop_until(None)
    }

    pub fn spawn_refresh_loop_with_shutdown(
        self: &Arc<Self>,
        shutdown: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        self.spawn_refresh_loop_until(Some(shutdown))
    }

    fn spawn_refresh_loop_until(
        self: &Arc<Self>,
        shutdown: Option<watch::Receiver<bool>>,
    ) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut revocation_interval = tokio::time::interval(Duration::from_secs(30));
            let mut jwks_interval = tokio::time::interval(Duration::from_secs(300));
            let mut jwt_interval = tokio::time::interval(Duration::from_secs(60));
            let mut shutdown = shutdown;

            // Consume the first immediate tick.
            revocation_interval.tick().await;
            jwks_interval.tick().await;
            jwt_interval.tick().await;

            loop {
                if let Some(receiver) = shutdown.as_mut() {
                    tokio::select! {
                        changed = receiver.changed() => {
                            if changed.is_err() || *receiver.borrow() {
                                break;
                            }
                        }
                        _ = revocation_interval.tick() => {
                            if let Err(e) = this.refresh_revocations().await {
                                warn!(error = %e, "Revocation poll failed");
                            }
                        }
                        _ = jwks_interval.tick() => {
                            if let Err(e) = this.refresh_jwks().await {
                                warn!(error = %e, "JWKS refresh failed");
                            }
                        }
                        _ = jwt_interval.tick() => {
                            if let Err(e) = this.get_bearer_token().await {
                                warn!(error = %e, "Gateway JWT refresh failed");
                            }
                            let peer_ids = {
                                let guard = this.peer_jwts.read().await;
                                guard.keys().cloned().collect::<Vec<_>>()
                            };
                            for peer_id in peer_ids {
                                if let Err(e) = this.get_peer_bearer_token(&peer_id).await {
                                    warn!(error = %e, peer_gateway_id = %peer_id, "CRDT peer JWT refresh failed");
                                }
                            }
                        }
                    }
                } else {
                    tokio::select! {
                        _ = revocation_interval.tick() => {
                            if let Err(e) = this.refresh_revocations().await {
                                warn!(error = %e, "Revocation poll failed");
                            }
                        }
                        _ = jwks_interval.tick() => {
                            if let Err(e) = this.refresh_jwks().await {
                                warn!(error = %e, "JWKS refresh failed");
                            }
                        }
                        _ = jwt_interval.tick() => {
                            if let Err(e) = this.get_bearer_token().await {
                                warn!(error = %e, "Gateway JWT refresh failed");
                            }
                            let peer_ids = {
                                let guard = this.peer_jwts.read().await;
                                guard.keys().cloned().collect::<Vec<_>>()
                            };
                            for peer_id in peer_ids {
                                if let Err(e) = this.get_peer_bearer_token(&peer_id).await {
                                    warn!(error = %e, peer_gateway_id = %peer_id, "CRDT peer JWT refresh failed");
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    /// Resolve a `DecodingKey` for the given kid, refreshing JWKS if needed.
    async fn resolve_decoding_key(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        // Fast path: key already in cache.
        {
            let guard = self.jwks.read().await;
            if let Some(key) = guard.keys.get(kid) {
                return Ok(key.clone());
            }
            // If we already tried and failed for this kid, don't spam JWKS.
            if guard.unknown_kids.contains(kid) && !guard.should_refresh() {
                return Err(AuthError::UnknownKid(kid.to_owned()));
            }
        }

        // Attempt a JWKS refresh (rate-limited).
        {
            let guard = self.jwks.read().await;
            if !guard.should_refresh() {
                // Already refreshed recently and kid still not present.
                return Err(AuthError::UnknownKid(kid.to_owned()));
            }
        }

        // Perform refresh.
        if let Err(e) = self.refresh_jwks().await {
            error!(error = %e, "JWKS refresh failed during key resolution");
            return Err(AuthError::UnknownKid(kid.to_owned()));
        }

        // Re-check after refresh.
        let guard = self.jwks.read().await;
        if let Some(key) = guard.keys.get(kid) {
            Ok(key.clone())
        } else {
            // Negative-cache this kid.
            drop(guard);
            let mut guard = self.jwks.write().await;
            guard.unknown_kids.insert(kid.to_owned());
            Err(AuthError::UnknownKid(kid.to_owned()))
        }
    }

    async fn mark_material_refresh(&self) {
        let mut guard = self.last_material_refresh.write().await;
        *guard = Instant::now();
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
    use crate::testing::gateway_jwt::{
        machine_claims_for_test, sign_machine_token, test_jwks_payload, unix_now, TEST_RSA_KID,
    };
    use axum::{
        http::StatusCode,
        routing::{get, post},
        Json, Router,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[derive(Clone)]
    struct CallCounters {
        exchange: Arc<AtomicUsize>,
        jwks: Arc<AtomicUsize>,
        revocations: Arc<AtomicUsize>,
    }

    async fn start_auth_server(
        counters: CallCounters,
        jwks: serde_json::Value,
        revocations: serde_json::Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let exchange_counts = counters.exchange.clone();
        let jwks_counts = counters.jwks.clone();
        let revocation_counts = counters.revocations.clone();

        let app = Router::new()
            .route(
                "/v1/jwt/exchange",
                post(move || {
                    let exchange_counts = exchange_counts.clone();
                    async move {
                        exchange_counts.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({
                            "access_token": "machine-jwt-token",
                            "expires_in": 300,
                            "scope": "gateway"
                        }))
                    }
                }),
            )
            .route(
                "/v1/jwt/jwks",
                get(move || {
                    let jwks_counts = jwks_counts.clone();
                    let jwks = jwks.clone();
                    async move {
                        jwks_counts.fetch_add(1, Ordering::SeqCst);
                        Json(jwks)
                    }
                }),
            )
            .route(
                "/v1/jwt/revocations",
                get(move || {
                    let revocation_counts = revocation_counts.clone();
                    let revocations = revocations.clone();
                    async move {
                        revocation_counts.fetch_add(1, Ordering::SeqCst);
                        Json(revocations)
                    }
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        (format!("http://{addr}"), handle)
    }

    async fn start_error_server(
        route: &'static str,
        method: &'static str,
        status: StatusCode,
        body: &'static str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app = match method {
            "POST" => Router::new().route(route, post(move || async move { (status, body) })),
            _ => Router::new().route(route, get(move || async move { (status, body) })),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        (format!("http://{addr}"), handle)
    }

    #[test]
    fn gateway_audience_format() {
        assert_eq!(
            gateway_audience("abc-123"),
            "https://gateway-abc-123.verdictan.io"
        );
    }

    #[test]
    fn one_or_many_contains() {
        let one = OneOrMany::One("a".into());
        assert!(one.contains("a"));
        assert!(!one.contains("b"));

        let many = OneOrMany::Many(vec!["x".into(), "y".into()]);
        assert!(many.contains("x"));
        assert!(many.contains("y"));
        assert!(!many.contains("z"));
    }

    #[test]
    fn jwks_cache_refresh_policy_respects_interval() {
        let mut cache = JwksCache::new();
        assert!(cache.should_refresh());

        cache.last_refresh = Instant::now();
        assert!(!cache.should_refresh());
    }

    #[tokio::test]
    async fn bootstrap_populates_cached_token_and_revocation_state() {
        let counters = CallCounters {
            exchange: Arc::new(AtomicUsize::new(0)),
            jwks: Arc::new(AtomicUsize::new(0)),
            revocations: Arc::new(AtomicUsize::new(0)),
        };
        let (api_url, handle) = start_auth_server(
            counters.clone(),
            serde_json::json!({ "keys": [] }),
            serde_json::json!({
                "revoked_jtis": ["revoked-1"],
                "server_time": 4242
            }),
        )
        .await;

        let client = GatewayAuthClient::new(
            "opaque-token".to_string(),
            api_url,
            "org-1".to_string(),
            "gateway-1".to_string(),
        );

        client.bootstrap().await.expect("bootstrap");
        let token = client.get_bearer_token().await.expect("cached bearer");

        handle.abort();

        assert_eq!(token, "machine-jwt-token");
        assert_eq!(counters.exchange.load(Ordering::SeqCst), 1);
        assert_eq!(counters.jwks.load(Ordering::SeqCst), 1);
        assert_eq!(counters.revocations.load(Ordering::SeqCst), 1);
        assert!(client.revoked_jtis.read().await.contains("revoked-1"));
        assert_eq!(*client.last_revocation_poll.read().await, 4242);
    }

    #[tokio::test]
    async fn resolve_decoding_key_negative_caches_unknown_kid_after_refresh() {
        let counters = CallCounters {
            exchange: Arc::new(AtomicUsize::new(0)),
            jwks: Arc::new(AtomicUsize::new(0)),
            revocations: Arc::new(AtomicUsize::new(0)),
        };
        let (api_url, handle) = start_auth_server(
            counters.clone(),
            serde_json::json!({ "keys": [] }),
            serde_json::json!({
                "revoked_jtis": [],
                "server_time": 0
            }),
        )
        .await;

        let client = GatewayAuthClient::new(
            "opaque-token".to_string(),
            api_url,
            "org-1".to_string(),
            "gateway-1".to_string(),
        );
        {
            let mut jwks = client.jwks.write().await;
            jwks.last_refresh = Instant::now() - Duration::from_secs(301);
        }

        let first = client.resolve_decoding_key("missing-kid").await;
        let second = client.resolve_decoding_key("missing-kid").await;

        handle.abort();

        assert!(matches!(first, Err(AuthError::UnknownKid(ref kid)) if kid == "missing-kid"));
        assert!(matches!(second, Err(AuthError::UnknownKid(ref kid)) if kid == "missing-kid"));
        assert_eq!(counters.jwks.load(Ordering::SeqCst), 1);
        assert!(client
            .jwks
            .read()
            .await
            .unknown_kids
            .contains("missing-kid"));
    }

    #[tokio::test]
    async fn get_bearer_token_returns_cached_token_without_refresh() {
        let client = GatewayAuthClient::new(
            "opaque-token".to_string(),
            "http://127.0.0.1:1".to_string(),
            "org-1".to_string(),
            "gateway-1".to_string(),
        );
        {
            let mut guard = client.jwt.write().await;
            *guard = Some(CachedJwt {
                token: "cached-token".to_string(),
                expires_at: Instant::now() + REFRESH_BUFFER + Duration::from_secs(30),
            });
        }

        let token = client.get_bearer_token().await.expect("cached token");
        assert_eq!(token, "cached-token");
    }

    #[tokio::test]
    async fn get_bearer_token_refreshes_expiring_token() {
        let counters = CallCounters {
            exchange: Arc::new(AtomicUsize::new(0)),
            jwks: Arc::new(AtomicUsize::new(0)),
            revocations: Arc::new(AtomicUsize::new(0)),
        };
        let (api_url, handle) = start_auth_server(
            counters.clone(),
            serde_json::json!({ "keys": [] }),
            serde_json::json!({
                "revoked_jtis": [],
                "server_time": 0
            }),
        )
        .await;

        let client = GatewayAuthClient::new(
            "opaque-token".to_string(),
            api_url,
            "org-1".to_string(),
            "gateway-1".to_string(),
        );
        {
            let mut guard = client.jwt.write().await;
            *guard = Some(CachedJwt {
                token: "stale-token".to_string(),
                expires_at: Instant::now() + REFRESH_BUFFER - Duration::from_secs(1),
            });
        }

        let token = client.get_bearer_token().await.expect("refreshed token");
        handle.abort();

        assert_eq!(token, "machine-jwt-token");
        assert_eq!(counters.exchange.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refresh_jwt_includes_status_and_body_on_failure() {
        let (api_url, handle) = start_error_server(
            "/v1/jwt/exchange",
            "POST",
            StatusCode::UNAUTHORIZED,
            "denied",
        )
        .await;

        let client = GatewayAuthClient::new(
            "opaque-token".to_string(),
            api_url,
            "org-1".to_string(),
            "gateway-1".to_string(),
        );

        let error = client.refresh_jwt().await.expect_err("exchange failure");
        handle.abort();

        assert!(
            matches!(error, AuthError::Exchange(message) if message.contains("401 Unauthorized: denied"))
        );
    }

    #[tokio::test]
    async fn refresh_jwks_includes_status_and_body_on_failure() {
        let (api_url, handle) = start_error_server(
            "/v1/jwt/jwks",
            "GET",
            StatusCode::BAD_GATEWAY,
            "upstream-down",
        )
        .await;

        let client = GatewayAuthClient::new(
            "opaque-token".to_string(),
            api_url,
            "org-1".to_string(),
            "gateway-1".to_string(),
        );

        let error = client.refresh_jwks().await.expect_err("jwks failure");
        handle.abort();

        assert!(
            matches!(error, AuthError::JwksFetch(message) if message.contains("502 Bad Gateway: upstream-down"))
        );
    }

    #[tokio::test]
    async fn refresh_revocations_includes_status_and_body_on_failure() {
        let (api_url, handle) = start_error_server(
            "/v1/jwt/revocations",
            "GET",
            StatusCode::SERVICE_UNAVAILABLE,
            "try-later",
        )
        .await;

        let client = GatewayAuthClient::new(
            "opaque-token".to_string(),
            api_url,
            "org-1".to_string(),
            "gateway-1".to_string(),
        );

        let error = client
            .refresh_revocations()
            .await
            .expect_err("revocation failure");
        handle.abort();

        assert!(
            matches!(error, AuthError::RevocationsFetch(message) if message.contains("503 Service Unavailable: try-later"))
        );
    }

    #[tokio::test]
    async fn resolve_decoding_key_uses_cached_key_without_refreshing() {
        let client = GatewayAuthClient::new(
            "opaque-token".to_string(),
            "http://127.0.0.1:1".to_string(),
            "org-1".to_string(),
            "gateway-1".to_string(),
        );
        {
            let mut guard = client.jwks.write().await;
            guard.keys.insert(
                "cached-kid".to_string(),
                DecodingKey::from_secret(b"cached"),
            );
        }

        let key = client
            .resolve_decoding_key("cached-kid")
            .await
            .expect("cached key");

        let _ = key;
    }

    #[tokio::test]
    async fn verify_incoming_jwt_accepts_valid_rs256_token() {
        let counters = CallCounters {
            exchange: Arc::new(AtomicUsize::new(0)),
            jwks: Arc::new(AtomicUsize::new(0)),
            revocations: Arc::new(AtomicUsize::new(0)),
        };
        let (api_url, handle) = start_auth_server(
            counters.clone(),
            test_jwks_payload(),
            serde_json::json!({
                "revoked_jtis": [],
                "server_time": 0
            }),
        )
        .await;

        let client = GatewayAuthClient::new(
            "opaque-token".to_string(),
            api_url,
            "org-1".to_string(),
            "gateway-1".to_string(),
        );
        client.refresh_jwks().await.expect("jwks");

        let claims = machine_claims_for_test(
            OneOrMany::One(gateway_audience("gateway-1")),
            unix_now() + 300,
            "org-1",
            "jti-valid",
        );
        let token = sign_machine_token(&claims, Some(TEST_RSA_KID));

        let verified = client.verify_incoming_jwt(&token).await.expect("verified");
        handle.abort();

        assert_eq!(verified.org_id, "org-1");
        assert_eq!(verified.jti, "jti-valid");
        assert_eq!(counters.jwks.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn verify_incoming_jwt_rejects_missing_kid_header() {
        let client = GatewayAuthClient::new(
            "opaque-token".to_string(),
            "http://127.0.0.1:1".to_string(),
            "org-1".to_string(),
            "gateway-1".to_string(),
        );
        let claims = machine_claims_for_test(
            OneOrMany::One(gateway_audience("gateway-1")),
            unix_now() + 300,
            "org-1",
            "jti-no-kid",
        );
        let token = sign_machine_token(&claims, None);

        let error = client
            .verify_incoming_jwt(&token)
            .await
            .expect_err("missing kid");

        assert!(
            matches!(error, AuthError::Verification(message) if message == "missing kid in header")
        );
    }

    #[tokio::test]
    async fn verify_incoming_jwt_maps_org_mismatch() {
        let counters = CallCounters {
            exchange: Arc::new(AtomicUsize::new(0)),
            jwks: Arc::new(AtomicUsize::new(0)),
            revocations: Arc::new(AtomicUsize::new(0)),
        };
        let (api_url, handle) = start_auth_server(
            counters,
            test_jwks_payload(),
            serde_json::json!({
                "revoked_jtis": [],
                "server_time": 0
            }),
        )
        .await;

        let client = GatewayAuthClient::new(
            "opaque-token".to_string(),
            api_url,
            "org-1".to_string(),
            "gateway-1".to_string(),
        );
        client.refresh_jwks().await.expect("jwks");

        let claims = machine_claims_for_test(
            OneOrMany::One(gateway_audience("gateway-1")),
            unix_now() + 300,
            "org-2",
            "jti-org-mismatch",
        );
        let token = sign_machine_token(&claims, Some(TEST_RSA_KID));

        let error = client
            .verify_incoming_jwt(&token)
            .await
            .expect_err("org mismatch");
        handle.abort();

        assert!(
            matches!(error, AuthError::OrgMismatch { expected, actual } if expected == "org-1" && actual == "org-2")
        );
    }

    #[tokio::test]
    async fn verify_incoming_jwt_maps_revoked_jti() {
        let counters = CallCounters {
            exchange: Arc::new(AtomicUsize::new(0)),
            jwks: Arc::new(AtomicUsize::new(0)),
            revocations: Arc::new(AtomicUsize::new(0)),
        };
        let (api_url, handle) = start_auth_server(
            counters,
            test_jwks_payload(),
            serde_json::json!({
                "revoked_jtis": [],
                "server_time": 0
            }),
        )
        .await;

        let client = GatewayAuthClient::new(
            "opaque-token".to_string(),
            api_url,
            "org-1".to_string(),
            "gateway-1".to_string(),
        );
        client.refresh_jwks().await.expect("jwks");
        client
            .revoked_jtis
            .write()
            .await
            .insert("jti-revoked".to_string());

        let claims = machine_claims_for_test(
            OneOrMany::One(gateway_audience("gateway-1")),
            unix_now() + 300,
            "org-1",
            "jti-revoked",
        );
        let token = sign_machine_token(&claims, Some(TEST_RSA_KID));

        let error = client
            .verify_incoming_jwt(&token)
            .await
            .expect_err("revoked jti");
        handle.abort();

        assert!(matches!(error, AuthError::Revoked(jti) if jti == "jti-revoked"));
    }

    #[tokio::test]
    async fn verify_incoming_jwt_maps_expired_signature() {
        let counters = CallCounters {
            exchange: Arc::new(AtomicUsize::new(0)),
            jwks: Arc::new(AtomicUsize::new(0)),
            revocations: Arc::new(AtomicUsize::new(0)),
        };
        let (api_url, handle) = start_auth_server(
            counters,
            test_jwks_payload(),
            serde_json::json!({
                "revoked_jtis": [],
                "server_time": 0
            }),
        )
        .await;

        let client = GatewayAuthClient::new(
            "opaque-token".to_string(),
            api_url,
            "org-1".to_string(),
            "gateway-1".to_string(),
        );
        client.refresh_jwks().await.expect("jwks");

        let claims = machine_claims_for_test(
            OneOrMany::One(gateway_audience("gateway-1")),
            unix_now() - 120,
            "org-1",
            "jti-expired",
        );
        let token = sign_machine_token(&claims, Some(TEST_RSA_KID));

        let error = client
            .verify_incoming_jwt(&token)
            .await
            .expect_err("expired token");
        handle.abort();

        assert!(matches!(error, AuthError::Expired));
    }

    #[tokio::test]
    async fn verify_incoming_jwt_maps_invalid_audience() {
        let counters = CallCounters {
            exchange: Arc::new(AtomicUsize::new(0)),
            jwks: Arc::new(AtomicUsize::new(0)),
            revocations: Arc::new(AtomicUsize::new(0)),
        };
        let (api_url, handle) = start_auth_server(
            counters,
            test_jwks_payload(),
            serde_json::json!({
                "revoked_jtis": [],
                "server_time": 0
            }),
        )
        .await;

        let client = GatewayAuthClient::new(
            "opaque-token".to_string(),
            api_url,
            "org-1".to_string(),
            "gateway-1".to_string(),
        );
        client.refresh_jwks().await.expect("jwks");

        let claims = machine_claims_for_test(
            OneOrMany::One("https://gateway-other.verdictan.io".to_string()),
            unix_now() + 300,
            "org-1",
            "jti-wrong-aud",
        );
        let token = sign_machine_token(&claims, Some(TEST_RSA_KID));

        let error = client
            .verify_incoming_jwt(&token)
            .await
            .expect_err("audience mismatch");
        handle.abort();

        assert!(matches!(error, AuthError::AudienceMismatch));
    }

    // ── OneOrMany ───────────────────────────────────────────────────────

    #[test]
    fn one_or_many_one_contains() {
        let v = OneOrMany::One("aud-1".into());
        assert!(v.contains("aud-1"));
        assert!(!v.contains("aud-2"));
    }

    #[test]
    fn one_or_many_many_contains() {
        let v = OneOrMany::Many(vec!["aud-1".into(), "aud-2".into()]);
        assert!(v.contains("aud-1"));
        assert!(v.contains("aud-2"));
        assert!(!v.contains("aud-3"));
    }

    #[test]
    fn one_or_many_serde_roundtrip_one() {
        let v: OneOrMany = serde_json::from_str("\"single\"").unwrap();
        assert!(v.contains("single"));
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"single\"");
    }

    #[test]
    fn one_or_many_serde_roundtrip_many() {
        let v: OneOrMany = serde_json::from_str("[\"a\",\"b\"]").unwrap();
        assert!(v.contains("a"));
        assert!(v.contains("b"));
    }

    // ── gateway_audience ────────────────────────────────────────────────

    #[test]
    fn gateway_audience_format_url() {
        assert_eq!(
            gateway_audience("gw-1"),
            "https://gateway-gw-1.verdictan.io"
        );
        assert_eq!(gateway_audience("abc"), "https://gateway-abc.verdictan.io");
    }

    // ── AuthError Display ──────────────────────────────────────────────

    #[test]
    fn auth_error_display_variants() {
        let e = AuthError::Exchange("bad token".into());
        assert!(e.to_string().contains("bad token"));

        let e = AuthError::JwksFetch("timeout".into());
        assert!(e.to_string().contains("timeout"));

        let e = AuthError::RevocationsFetch("network".into());
        assert!(e.to_string().contains("network"));

        let e = AuthError::Verification("invalid sig".into());
        assert!(e.to_string().contains("invalid sig"));

        let e = AuthError::Expired;
        assert!(e.to_string().contains("expired"));

        let e = AuthError::UnknownKid("kid-1".into());
        assert!(e.to_string().contains("kid-1"));

        let e = AuthError::OrgMismatch {
            expected: "org-1".into(),
            actual: "org-2".into(),
        };
        assert!(e.to_string().contains("org-1"));
        assert!(e.to_string().contains("org-2"));

        let e = AuthError::AudienceMismatch;
        assert!(e.to_string().contains("Audience"));

        let e = AuthError::Revoked("jti-1".into());
        assert!(e.to_string().contains("jti-1"));
    }

    // ── JwksCache ──────────────────────────────────────────────────────

    #[test]
    fn jwks_cache_should_refresh_initially() {
        let cache = JwksCache::new();
        assert!(cache.should_refresh());
    }

    #[test]
    fn jwks_cache_should_not_refresh_too_soon() {
        let mut cache = JwksCache::new();
        cache.last_refresh = Instant::now();
        assert!(!cache.should_refresh());
    }

    // ── ExchangeResponse / RevocationsResponse / JwkEntry deser ────────

    #[test]
    fn exchange_response_deser() {
        let j = serde_json::json!({"access_token":"tok","expires_in":3600,"scope":"gateway"});
        let r: ExchangeResponse = serde_json::from_value(j).unwrap();
        assert_eq!(r.access_token, "tok");
        assert_eq!(r.expires_in, 3600);
        assert_eq!(r.scope, "gateway");
    }

    #[test]
    fn revocations_response_deser() {
        let j = serde_json::json!({"revoked_jtis":["jti-1","jti-2"],"server_time":12345});
        let r: RevocationsResponse = serde_json::from_value(j).unwrap();
        assert_eq!(r.revoked_jtis.len(), 2);
        assert_eq!(r.server_time, 12345);
    }

    #[test]
    fn jwk_entry_deser() {
        let j = serde_json::json!({"kty":"RSA","kid":"kid-1","alg":"RS256","use":"sig","n":"abc","e":"AQAB"});
        let entry: JwkEntry = serde_json::from_value(j).unwrap();
        assert_eq!(entry.kty, "RSA");
        assert_eq!(entry.kid, "kid-1");
        assert_eq!(entry.alg, "RS256");
        assert_eq!(entry.use_.as_deref(), Some("sig"));
    }

    #[test]
    fn jwks_response_deser() {
        let j =
            serde_json::json!({"keys":[{"kty":"RSA","kid":"k1","alg":"RS256","n":"n","e":"e"}]});
        let r: JwksResponse = serde_json::from_value(j).unwrap();
        assert_eq!(r.keys.len(), 1);
    }

    // ── MachineClaims deser ─────────────────────────────────────────────

    #[test]
    fn machine_claims_deser_minimal() {
        let j = serde_json::json!({
            "iss": "https://api.verdictan.com",
            "sub": "sub-1",
            "aud": "aud-1",
            "exp": 9999999999i64,
            "iat": 1000000000i64,
            "jti": "jti-1",
            "org_id": "org-1",
            "principal_type": "gateway",
            "actor_class": "machine",
            "scope": "gateway",
            "azp": "azp-1"
        });
        let c: MachineClaims = serde_json::from_value(j).unwrap();
        assert_eq!(c.iss, "https://api.verdictan.com");
        assert_eq!(c.sub, "sub-1");
        assert!(c.aud.contains("aud-1"));
        assert!(c.gateway_id.is_none());
        assert!(c.rev_check.is_none());
        assert!(c.region.is_none());
    }

    #[test]
    fn machine_claims_deser_full() {
        let j = serde_json::json!({
            "iss": "https://api.verdictan.com",
            "sub": "sub-1",
            "aud": ["aud-1", "aud-2"],
            "exp": 9999999999i64,
            "iat": 1000000000i64,
            "jti": "jti-1",
            "org_id": "org-1",
            "principal_type": "gateway",
            "actor_class": "machine",
            "scope": "gateway",
            "azp": "azp-1",
            "gateway_id": "gw-1",
            "rev_check": "online",
            "region": "eu-west-1"
        });
        let c: MachineClaims = serde_json::from_value(j).unwrap();
        assert!(c.aud.contains("aud-1"));
        assert!(c.aud.contains("aud-2"));
        assert_eq!(c.gateway_id.as_deref(), Some("gw-1"));
        assert_eq!(c.region.as_deref(), Some("eu-west-1"));
    }

    // ── EXPECTED_ISSUER / REFRESH_BUFFER constants ─────────────────────

    #[test]
    fn expected_issuer_constant() {
        assert_eq!(EXPECTED_ISSUER, "https://api.verdictan.com");
    }

    #[test]
    fn refresh_buffer_constant() {
        assert_eq!(REFRESH_BUFFER, Duration::from_secs(60));
    }

    // ── GatewayAuthClient construction ─────────────────────────────────

    #[tokio::test]
    async fn auth_client_initial_state() {
        let client = GatewayAuthClient::new(
            "token".into(),
            "https://api.test".into(),
            "org-1".into(),
            "gw-1".into(),
        );
        assert!(client.jwt.read().await.is_none());
        assert!(client.jwks.read().await.keys.is_empty());
        assert!(client.revoked_jtis.read().await.is_empty());
        assert_eq!(*client.last_revocation_poll.read().await, 0);
    }

    // ── OneOrMany ────────────────────────────────────────────────────────

    #[test]
    fn one_or_many_one_does_not_contain_other() {
        let v = OneOrMany::One("aud-1".to_string());
        assert!(v.contains("aud-1"));
        assert!(!v.contains("aud-2"));
    }

    #[test]
    fn one_or_many_many_contains_all() {
        let v = OneOrMany::Many(vec!["a".to_string(), "b".to_string()]);
        assert!(v.contains("a"));
        assert!(v.contains("b"));
        assert!(!v.contains("c"));
    }

    // ── AuthError ────────────────────────────────────────────────────

    #[test]
    fn auth_error_display() {
        let err = AuthError::Exchange("connection refused".to_string());
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn auth_error_jwks_display() {
        let err = AuthError::JwksFetch("timeout".to_string());
        assert!(err.to_string().contains("timeout"));
    }

    // ── GatewayAuthClient update_revoked_jtis ──────────────────────────

    #[tokio::test]
    async fn auth_client_add_revoked_jti() {
        let client = GatewayAuthClient::new(
            "token".into(),
            "https://api.test".into(),
            "org-1".into(),
            "gw-1".into(),
        );
        client
            .revoked_jtis
            .write()
            .await
            .insert("jti-revoked".to_string());
        assert!(client.revoked_jtis.read().await.contains("jti-revoked"));
    }
}
