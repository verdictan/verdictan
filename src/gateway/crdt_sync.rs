// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bincode::Options;
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, Notify, RwLock};

use sha2::{Digest, Sha256};

use super::crdt::{
    unix_timestamp_millis, ContextCrdt, ContextCrdtState, CrdtError, CrdtMutation, HlcTimestamp,
    MergeSummary,
};
use super::jwt_auth::GatewayAuthClient;

fn compute_payload_digest(payload: &[u8]) -> String {
    let hash = Sha256::digest(payload);
    hex::encode(hash)
}

const DEFAULT_SYNC_INTERVAL_MS: u64 = 100;
const DEFAULT_MAX_PARTITION_BUFFER_AGE_SECS: u64 = 24 * 60 * 60;
const DEFAULT_HTTP_TIMEOUT_MS: u64 = 750;
const MAX_SYNC_BODY_BYTES: usize = 1_048_576;
const MAX_SYNC_STATE_BYTES: u64 = 4_194_304;
const DEDUPE_WINDOW: Duration = Duration::from_secs(300);
const MAX_DEDUPE_ENTRIES: usize = 10_000;
const PEER_METADATA_MAX_AGE_SECS: i64 = 300;
const CRDT_SYNC_SCOPE: &str = "gateway:crdt:sync";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerSyncConfig {
    pub enabled: bool,
    pub peers: Vec<PeerSyncPeer>,
    pub sync_interval_ms: u64,
    pub max_partition_buffer_age: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerSyncPeer {
    pub gateway_id: String,
    pub endpoint: String,
}

impl Default for PeerSyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            peers: Vec::new(),
            sync_interval_ms: DEFAULT_SYNC_INTERVAL_MS,
            max_partition_buffer_age: Duration::from_secs(DEFAULT_MAX_PARTITION_BUFFER_AGE_SECS),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncEnvelope {
    pub sync_id: String,
    pub origin_replica_id: String,
    pub emitted_at: HlcTimestamp,
    pub payload_digest_sha256: String,
    pub encoded_state: Vec<u8>,
}

impl SyncEnvelope {
    pub fn from_state(
        origin_replica_id: impl Into<String>,
        emitted_at: HlcTimestamp,
        state: &ContextCrdtState,
    ) -> Result<Self, SyncError> {
        let encoded_state = bincode::DefaultOptions::new()
            .with_limit(MAX_SYNC_STATE_BYTES)
            .serialize(state)
            .map_err(SyncError::Serialize)?;
        Ok(Self {
            sync_id: uuid::Uuid::new_v4().to_string(),
            origin_replica_id: origin_replica_id.into(),
            emitted_at,
            payload_digest_sha256: compute_payload_digest(&encoded_state),
            encoded_state,
        })
    }

    pub fn decode_state(&self) -> Result<ContextCrdtState, SyncError> {
        if self.encoded_state.len() > MAX_SYNC_BODY_BYTES {
            return Err(SyncError::PayloadTooLarge(self.encoded_state.len()));
        }
        let actual_digest = compute_payload_digest(&self.encoded_state);
        if actual_digest != self.payload_digest_sha256 {
            return Err(SyncError::PayloadDigestMismatch);
        }
        bincode::DefaultOptions::new()
            .with_limit(MAX_SYNC_STATE_BYTES)
            .deserialize(&self.encoded_state)
            .map_err(SyncError::Serialize)
    }

    pub fn encode(&self) -> Result<Vec<u8>, SyncError> {
        bincode::DefaultOptions::new()
            .with_limit(MAX_SYNC_BODY_BYTES as u64)
            .serialize(self)
            .map_err(SyncError::Serialize)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        if bytes.len() > MAX_SYNC_BODY_BYTES {
            return Err(SyncError::PayloadTooLarge(bytes.len()));
        }
        bincode::DefaultOptions::new()
            .with_limit(MAX_SYNC_BODY_BYTES as u64)
            .deserialize(bytes)
            .map_err(SyncError::Serialize)
    }
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error(transparent)]
    Crdt(#[from] CrdtError),
    #[error("failed to build sync client: {0}")]
    HttpClient(String),
    #[error("failed to broadcast sync envelope: {0}")]
    Http(#[from] reqwest::Error),
    #[error("peer rejected sync envelope with status {0}")]
    PeerStatus(reqwest::StatusCode),
    #[error("peer sync requires a bearer token")]
    MissingPeerAuthorization,
    #[error("peer sync requires configured CRDT peer authentication material")]
    MissingPeerAuthenticator,
    #[error("peer token verification failed: {0}")]
    PeerAuthorization(String),
    #[error("peer sync material is stale")]
    PeerMaterialStale,
    #[error("configured peer {0} is not active")]
    InactivePeer(String),
    #[error("no active configured CRDT peer is available")]
    NoActivePeer,
    #[error("encoded CRDT sync body exceeds {0} bytes")]
    PayloadTooLarge(usize),
    #[error("CRDT sync payload digest does not match the encoded state bytes")]
    PayloadDigestMismatch,
    #[error("CRDT sync replay conflict detected for sync_id")]
    ReplayConflict,
    #[error("CRDT sync dedupe cache is at capacity")]
    ReplayCacheFull,
    #[error("failed to serialize sync envelope: {0}")]
    Serialize(#[from] Box<bincode::ErrorKind>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BroadcastReport {
    pub attempted_peers: usize,
    pub successful_peers: usize,
    pub failed_peers: Vec<String>,
}

impl BroadcastReport {
    pub fn all_succeeded(&self) -> bool {
        self.attempted_peers == self.successful_peers && self.failed_peers.is_empty()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReceiveReport {
    pub duplicate: bool,
    pub ignored_self_origin: bool,
    pub merge: MergeSummary,
}

#[derive(Clone)]
pub struct CrdtSyncDriver {
    inner: Arc<CrdtSyncDriverInner>,
}

struct CrdtSyncDriverInner {
    state: Arc<RwLock<ContextCrdt>>,
    config: PeerSyncConfig,
    client: Client,
    auth_client: Option<Arc<GatewayAuthClient>>,
    read_model: Option<super::server::SharedConnectedGatewayReadModel>,
    pending_envelope: Mutex<Option<SyncEnvelope>>,
    seen_syncs: Mutex<HashMap<(String, String), CachedSyncDigest>>,
    round_robin: AtomicUsize,
    notify: Notify,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CachedSyncDigest {
    digest: String,
    cached_at: Instant,
}

impl CrdtSyncDriver {
    pub fn new(state: Arc<RwLock<ContextCrdt>>, config: PeerSyncConfig) -> Result<Self, SyncError> {
        let client = Client::builder()
            .timeout(Duration::from_millis(DEFAULT_HTTP_TIMEOUT_MS))
            .build()
            .map_err(|error| SyncError::HttpClient(error.to_string()))?;
        Self::new_with_client(state, config, client)
    }

    pub fn new_with_client(
        state: Arc<RwLock<ContextCrdt>>,
        config: PeerSyncConfig,
        client: Client,
    ) -> Result<Self, SyncError> {
        Self::new_authenticated(state, config, client, None, None)
    }

    pub fn new_authenticated(
        state: Arc<RwLock<ContextCrdt>>,
        config: PeerSyncConfig,
        client: Client,
        auth_client: Option<Arc<GatewayAuthClient>>,
        read_model: Option<super::server::SharedConnectedGatewayReadModel>,
    ) -> Result<Self, SyncError> {
        let inner = Arc::new(CrdtSyncDriverInner {
            state,
            config,
            client,
            auth_client,
            read_model,
            pending_envelope: Mutex::new(None),
            seen_syncs: Mutex::new(HashMap::new()),
            round_robin: AtomicUsize::new(0),
            notify: Notify::new(),
        });
        let driver = Self { inner };
        driver.spawn_retry_worker();
        Ok(driver)
    }

    pub fn state(&self) -> Arc<RwLock<ContextCrdt>> {
        self.inner.state.clone()
    }

    pub async fn apply_local_mutation(
        &self,
        mutation: CrdtMutation,
    ) -> Result<Option<SyncEnvelope>, SyncError> {
        let mut replica = self.inner.state.write().await;
        let result = replica.apply_mutation(mutation);
        if !result.changed {
            return Ok(None);
        }

        replica.compact_now(self.inner.config.max_partition_buffer_age);
        let timestamp = match result.timestamp {
            Some(timestamp) => timestamp,
            None => return Ok(None),
        };
        let envelope =
            SyncEnvelope::from_state(replica.replica_id().to_string(), timestamp, replica.state())?;
        drop(replica);

        if self.inner.config.enabled && !self.inner.config.peers.is_empty() {
            let mut pending = self.inner.pending_envelope.lock().await;
            *pending = Some(envelope.clone());
            drop(pending);
            self.inner.notify.notify_one();
        }

        Ok(Some(envelope))
    }

    pub async fn broadcast_snapshot(&self) -> Result<Option<BroadcastReport>, SyncError> {
        if !self.inner.config.enabled || self.inner.config.peers.is_empty() {
            return Ok(None);
        }

        let envelope = {
            let replica = self.inner.state.read().await;
            let emitted_at = replica
                .state()
                .max_timestamp()
                .unwrap_or_else(|| HlcTimestamp::zero(replica.replica_id().to_string()));
            SyncEnvelope::from_state(
                replica.replica_id().to_string(),
                emitted_at,
                replica.state(),
            )?
        };

        let report = self.broadcast_envelope(&envelope).await?;
        if report.all_succeeded() {
            let mut pending = self.inner.pending_envelope.lock().await;
            *pending = None;
        }
        Ok(Some(report))
    }

    pub async fn receive_envelope(
        &self,
        envelope: SyncEnvelope,
    ) -> Result<ReceiveReport, SyncError> {
        let mut replica = self.inner.state.write().await;
        if envelope.origin_replica_id == replica.replica_id() {
            return Ok(ReceiveReport {
                duplicate: false,
                ignored_self_origin: true,
                merge: MergeSummary::default(),
            });
        }

        let remote_state = envelope.decode_state()?;
        let merge = replica.merge_state_at(&remote_state, unix_timestamp_millis());
        replica.compact_now(self.inner.config.max_partition_buffer_age);
        Ok(ReceiveReport {
            duplicate: false,
            ignored_self_origin: false,
            merge,
        })
    }

    pub async fn receive_http_bytes(&self, bytes: &[u8]) -> Result<ReceiveReport, SyncError> {
        let envelope = SyncEnvelope::decode(bytes)?;
        self.receive_envelope(envelope).await
    }

    pub async fn receive_http_request(
        &self,
        bearer_token: Option<&str>,
        bytes: &[u8],
    ) -> Result<ReceiveReport, SyncError> {
        if bytes.len() > MAX_SYNC_BODY_BYTES {
            return Err(SyncError::PayloadTooLarge(bytes.len()));
        }

        // Remote ingress is fail-closed: without peer authentication material there is no
        // way to bind an envelope to an authorized peer, so the merge must not happen.
        let Some(auth_client) = self.inner.auth_client.as_ref() else {
            return Err(SyncError::MissingPeerAuthenticator);
        };
        if !auth_client.material_is_fresh().await {
            return Err(SyncError::PeerMaterialStale);
        }

        let raw_token = bearer_token
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .ok_or(SyncError::MissingPeerAuthorization)?;
        let claims = auth_client
            .verify_incoming_jwt(raw_token)
            .await
            .map_err(|error| SyncError::PeerAuthorization(error.to_string()))?;
        if claims.scope.trim() != CRDT_SYNC_SCOPE {
            return Err(SyncError::PeerAuthorization(format!(
                "expected exact scope {CRDT_SYNC_SCOPE}"
            )));
        }

        let envelope = SyncEnvelope::decode(bytes)?;
        if claims.gateway_id.as_deref() != Some(envelope.origin_replica_id.as_str()) {
            return Err(SyncError::PeerAuthorization(
                "token gateway_id does not match envelope origin_replica_id".to_string(),
            ));
        }

        let source_gateway_id = claims.gateway_id.clone().ok_or_else(|| {
            SyncError::PeerAuthorization("token gateway_id is missing".to_string())
        })?;
        self.ensure_active_configured_peer(&source_gateway_id)?;

        if self
            .is_duplicate_digest(
                &source_gateway_id,
                &envelope.sync_id,
                &envelope.payload_digest_sha256,
            )
            .await?
        {
            return Ok(ReceiveReport {
                duplicate: true,
                ignored_self_origin: false,
                merge: MergeSummary::default(),
            });
        }

        let report = self.receive_envelope(envelope.clone()).await?;
        self.record_digest(
            &source_gateway_id,
            &envelope.sync_id,
            &envelope.payload_digest_sha256,
        )
        .await?;
        Ok(report)
    }

    fn ensure_active_configured_peer(&self, gateway_id: &str) -> Result<(), SyncError> {
        let read_model = self
            .inner
            .read_model
            .as_ref()
            .ok_or(SyncError::PeerMaterialStale)?;
        let snapshot = read_model.snapshot();
        let age_secs = snapshot
            .publication_catalog_age_seconds(Utc::now())
            .unwrap_or(i64::MAX);
        if age_secs > PEER_METADATA_MAX_AGE_SECS {
            return Err(SyncError::PeerMaterialStale);
        }

        let configured = self
            .inner
            .config
            .peers
            .iter()
            .any(|peer| peer.gateway_id == gateway_id);
        if !configured {
            return Err(SyncError::InactivePeer(gateway_id.to_string()));
        }

        let active = snapshot
            .peer_gateways
            .iter()
            .any(|peer| peer.gateway_id == gateway_id && peer.readiness == "ready");
        if !active {
            return Err(SyncError::InactivePeer(gateway_id.to_string()));
        }
        Ok(())
    }

    async fn is_duplicate_digest(
        &self,
        source_gateway_id: &str,
        sync_id: &str,
        digest: &str,
    ) -> Result<bool, SyncError> {
        let mut cache = self.inner.seen_syncs.lock().await;
        let now = Instant::now();
        cache.retain(|_, entry| now.duration_since(entry.cached_at) <= DEDUPE_WINDOW);
        let key = (source_gateway_id.to_string(), sync_id.to_string());
        if let Some(entry) = cache.get(&key) {
            return if entry.digest == digest {
                Ok(true)
            } else {
                Err(SyncError::ReplayConflict)
            };
        }
        Ok(false)
    }

    async fn record_digest(
        &self,
        source_gateway_id: &str,
        sync_id: &str,
        digest: &str,
    ) -> Result<(), SyncError> {
        let mut cache = self.inner.seen_syncs.lock().await;
        let now = Instant::now();
        cache.retain(|_, entry| now.duration_since(entry.cached_at) <= DEDUPE_WINDOW);
        let key = (source_gateway_id.to_string(), sync_id.to_string());
        if let Some(entry) = cache.get(&key) {
            return if entry.digest == digest {
                Ok(())
            } else {
                Err(SyncError::ReplayConflict)
            };
        }
        if cache.len() >= MAX_DEDUPE_ENTRIES {
            return Err(SyncError::ReplayCacheFull);
        }
        cache.insert(
            key,
            CachedSyncDigest {
                digest: digest.to_string(),
                cached_at: now,
            },
        );
        Ok(())
    }

    fn spawn_retry_worker(&self) {
        if !self.inner.config.enabled || self.inner.config.peers.is_empty() {
            return;
        }

        let inner = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            loop {
                let Some(inner) = inner.upgrade() else {
                    break;
                };
                if Arc::strong_count(&inner) == 1 {
                    break;
                }

                let interval_ms = inner.config.sync_interval_ms.max(1);
                tokio::select! {
                    _ = inner.notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_millis(interval_ms)) => {}
                }

                let pending = {
                    let pending = inner.pending_envelope.lock().await;
                    pending.clone()
                };
                let Some(envelope) = pending else {
                    continue;
                };

                let report = Self::broadcast_with_inner(&inner, &envelope).await;
                match report {
                    Ok(report) if report.all_succeeded() => {
                        let mut pending = inner.pending_envelope.lock().await;
                        if pending.as_ref() == Some(&envelope) {
                            *pending = None;
                        }
                    }
                    Ok(_) | Err(_) => {}
                }
            }
        });
    }

    async fn broadcast_envelope(
        &self,
        envelope: &SyncEnvelope,
    ) -> Result<BroadcastReport, SyncError> {
        Self::broadcast_with_inner(&self.inner, envelope).await
    }

    async fn broadcast_with_inner(
        inner: &Arc<CrdtSyncDriverInner>,
        envelope: &SyncEnvelope,
    ) -> Result<BroadcastReport, SyncError> {
        if !inner.config.enabled || inner.config.peers.is_empty() {
            return Ok(BroadcastReport::default());
        }

        let payload = envelope.encode()?;
        let peer = select_outbound_peer(inner)?;
        let bearer = if let Some(auth_client) = inner.auth_client.as_ref() {
            if !auth_client.material_is_fresh().await {
                return Err(SyncError::PeerMaterialStale);
            }
            Some(
                auth_client
                    .get_peer_bearer_token(&peer.gateway_id)
                    .await
                    .map_err(|error| SyncError::PeerAuthorization(error.to_string()))?,
            )
        } else {
            None
        };

        let mut request = inner
            .client
            .post(&peer.endpoint)
            .header("content-type", "application/octet-stream");
        if let Some(token) = bearer.as_deref() {
            request = request.bearer_auth(token);
        }
        let response = request.body(payload).send().await;

        let mut report = BroadcastReport {
            attempted_peers: 1,
            ..BroadcastReport::default()
        };
        match response {
            Ok(response) if response.status().is_success() => {
                report.successful_peers = 1;
                Ok(report)
            }
            Ok(response) => {
                report
                    .failed_peers
                    .push(format!("{} ({})", peer.endpoint, response.status()));
                Err(SyncError::PeerStatus(response.status()))
            }
            Err(error) => {
                report.failed_peers.push(peer.endpoint.clone());
                Err(SyncError::Http(error))
            }
        }
    }
}

fn select_outbound_peer(inner: &Arc<CrdtSyncDriverInner>) -> Result<PeerSyncPeer, SyncError> {
    let Some(read_model) = inner.read_model.as_ref() else {
        return inner
            .config
            .peers
            .first()
            .cloned()
            .ok_or(SyncError::NoActivePeer);
    };
    let snapshot = read_model.snapshot();
    let age_secs = snapshot
        .publication_catalog_age_seconds(Utc::now())
        .unwrap_or(i64::MAX);
    if age_secs > PEER_METADATA_MAX_AGE_SECS {
        return Err(SyncError::PeerMaterialStale);
    }

    let active_peers: Vec<PeerSyncPeer> = inner
        .config
        .peers
        .iter()
        .filter(|peer| {
            snapshot
                .peer_gateways
                .iter()
                .any(|active| active.gateway_id == peer.gateway_id && active.readiness == "ready")
        })
        .cloned()
        .collect();
    if active_peers.is_empty() {
        return Err(SyncError::NoActivePeer);
    }

    let index = inner.round_robin.fetch_add(1, Ordering::Relaxed) % active_peers.len();
    Ok(active_peers[index].clone())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::collections::BTreeMap;

    use super::*;
    use crate::gateway::crdt::CrdtMutation;

    fn entry_fields(content: &str) -> BTreeMap<String, serde_json::Value> {
        BTreeMap::from([
            ("content".to_string(), serde_json::json!(content)),
            ("repo".to_string(), serde_json::json!("verdictan")),
            ("branch".to_string(), serde_json::json!("feature/a")),
            ("topic".to_string(), serde_json::json!("schema")),
        ])
    }

    async fn peer_envelope_bytes(entry_id: &str, content: &str) -> Vec<u8> {
        let peer_replica = Arc::new(RwLock::new(
            ContextCrdt::new("peer-gateway").expect("peer replica"),
        ));
        let peer_driver =
            CrdtSyncDriver::new(peer_replica, PeerSyncConfig::default()).expect("peer driver");
        peer_driver
            .apply_local_mutation(CrdtMutation::UpsertEntry {
                entry_id: entry_id.to_string(),
                fields: entry_fields(content),
                now_ms: Some(10_000),
            })
            .await
            .expect("peer mutation")
            .expect("peer envelope")
            .encode()
            .expect("encoded envelope")
    }

    #[tokio::test]
    async fn receive_http_request_refuses_ingress_without_peer_authenticator() {
        let envelope = peer_envelope_bytes("schema-users", "users schema").await;
        let local_replica = Arc::new(RwLock::new(
            ContextCrdt::new("local-gateway").expect("local replica"),
        ));
        let driver = CrdtSyncDriver::new_authenticated(
            local_replica.clone(),
            PeerSyncConfig {
                enabled: true,
                ..PeerSyncConfig::default()
            },
            Client::new(),
            None,
            None,
        )
        .expect("local driver");

        for bearer_token in [None, Some("peer-supplied-token")] {
            let error = driver
                .receive_http_request(bearer_token, &envelope)
                .await
                .expect_err("ingress must be refused without peer authentication material");
            assert!(
                matches!(error, SyncError::MissingPeerAuthenticator),
                "unexpected error: {error}"
            );
        }

        let replica = local_replica.read().await;
        assert_eq!(replica.state().visible_len(), 0);
        assert!(replica.state().visible_entry_ids().is_empty());
        assert!(replica.state().max_timestamp().is_none());
    }
}
